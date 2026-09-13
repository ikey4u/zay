//! SOCKS5 TCP inbound integrated with the native router and outbound manager.

use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, copy_bidirectional},
    net::{TcpListener, UdpSocket},
    sync::Mutex,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{PacketConnection, PacketFuture, PacketStream, Stream},
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::{Network, SocksAddr},
    },
    inbound::{
        PacketDestinationNat, PacketSniffSessions, TcpInboundContext,
        TcpInboundInjector, TcpInjectFuture, hijack_dns_packet_with_context,
        inherited_tcp_metadata, prepare_tcp_inbound_detour,
        serve_hijacked_dns_stream_with_context, sniff_and_route_stream,
        with_tcp_inbound_context,
    },
    option::SocksInboundOptions,
    outbound::OutboundManager,
    protocol::socks::{
        SocksCommand, SocksVersion, decode_udp_packet, encode_udp_packet,
        server_request, write_reply_for_version,
    },
    protocol::uot,
    route::{Action, Metadata, Router},
};

pub struct SocksInbound {
    name: String,
    tag: String,
    options: SocksInboundOptions,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

#[derive(Clone)]
pub struct SocksTcpInjector {
    tag: String,
    users: Vec<crate::option::User>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
}

impl SocksTcpInjector {
    pub fn new(
        tag: impl Into<String>,
        options: SocksInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Self {
        let udp_timeout = options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        Self {
            tag: tag.into(),
            users: options.users,
            router,
            outbounds,
            udp_timeout,
        }
    }
}

impl TcpInboundInjector for SocksTcpInjector {
    fn inject<'a>(
        &'a self,
        stream: Stream,
        context: TcpInboundContext,
    ) -> TcpInjectFuture<'a> {
        let source = context.source;
        Box::pin(with_tcp_inbound_context(context, async move {
            let local_ip = if source.is_ipv4() {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            };
            handle_connection(
                stream,
                local_ip,
                source,
                &self.tag,
                &self.users,
                &self.router,
                &self.outbounds,
                self.udp_timeout,
            )
            .await
        }))
    }
}

impl SocksInbound {
    pub fn new(
        tag: impl Into<String>,
        options: SocksInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Self {
        let tag = tag.into();
        Self {
            name: format!("inbound/socks[{tag}]"),
            tag,
            options,
            router,
            outbounds,
            cancellation: CancellationToken::new(),
            task: None,
            local_addr: None,
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    async fn bind(&mut self) -> io::Result<()> {
        let ip = self
            .options
            .listen
            .listen
            .map(|address| address.0)
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        let listener = crate::common::socket::bind_tcp_listener(
            SocketAddr::new(ip, self.options.listen.listen_port),
            &self.options.listen,
        )
        .await?;
        self.local_addr = Some(listener.local_addr()?);
        let cancellation = self.cancellation.clone();
        let tag = self.tag.clone();
        let users = self.options.users.clone();
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        let udp_timeout = self
            .options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        self.task = Some(tokio::spawn(async move {
            accept_loop(
                listener,
                cancellation,
                tag,
                users,
                router,
                outbounds,
                udp_timeout,
            )
            .await
        }));
        Ok(())
    }
}

impl Lifecycle for SocksInbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start {
                return Ok(());
            }
            self.bind().await.map_err(|error| LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: error.to_string(),
            })
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            if let Some(task) = self.task.take() {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        return Err(LifecycleError::Close {
                            component: self.name.clone(),
                            message: error.to_string(),
                        });
                    }
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => {
                        return Err(LifecycleError::Close {
                            component: self.name.clone(),
                            message: error.to_string(),
                        });
                    }
                }
            }
            Ok(())
        })
    }
}

async fn accept_loop(
    listener: TcpListener,
    cancellation: CancellationToken,
    tag: String,
    users: Vec<crate::option::User>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            result = listener.accept() => {
                let (stream, source) = result?;
                let local_ip = stream.local_addr()?.ip();
                let tag = tag.clone();
                let users = users.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                connections.spawn(async move {
                    let _ = handle_connection(
                        stream, local_ip, source, &tag, &users, &router, &outbounds, udp_timeout,
                    ).await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_connection<S>(
    mut client: S,
    local_ip: IpAddr,
    source: SocketAddr,
    tag: &str,
    users: &[crate::option::User],
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request = server_request(&mut client, users).await?;
    match request.command {
        SocksCommand::Connect => {
            if let Some(uot_version) =
                uot::destination_version(&request.destination)
            {
                write_reply_for_version(&mut client, request.version, 0, None)
                    .await?;
                let packet_connection = uot::accept(
                    Box::new(client) as crate::adapter::Stream,
                    uot_version,
                )
                .await?;
                return proxy_packet_connection(
                    Box::new(packet_connection),
                    source,
                    tag,
                    request.user,
                    router,
                    outbounds,
                    udp_timeout,
                )
                .await;
            }
            handle_tcp(
                client,
                source,
                tag,
                request.version,
                request.destination,
                request.user,
                router,
                outbounds,
            )
            .await
        }
        SocksCommand::UdpAssociate => {
            if request.version != SocksVersion::V5 {
                write_reply_for_version(&mut client, request.version, 7, None)
                    .await?;
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "SOCKS4 UDP is not supported",
                ));
            }
            handle_udp_association(
                client,
                local_ip,
                source,
                tag,
                request.destination,
                request.user,
                router,
                outbounds,
                udp_timeout,
            )
            .await
        }
        SocksCommand::Bind => {
            write_reply_for_version(&mut client, request.version, 7, None)
                .await?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SOCKS BIND is not supported",
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_packet_connection(
    incoming: crate::adapter::PacketStream,
    source: SocketAddr,
    tag: &str,
    user: Option<String>,
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let mut packet = vec![0_u8; 65_535];
    let mut sniff_sessions = PacketSniffSessions::<SocksAddr>::new(udp_timeout);
    let (size, original_destination) =
        timeout(udp_timeout, incoming.recv_from(&mut packet))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SOCKS UDP session timed out",
                )
            })??;
    let first_payload = packet[..size].to_vec();
    let (destination, origin_destination) =
        restore_fake_ip(original_destination.clone(), outbounds)?;
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination.clone()),
        origin_destination: origin_destination.clone(),
        fake_ip: origin_destination.is_some(),
        network: Some(Network::Udp),
        user: user.unwrap_or_default(),
        ..Metadata::default()
    };
    let decision = sniff_sessions
        .route(
            original_destination.clone(),
            &first_payload,
            &mut metadata,
            router,
            outbounds,
        )
        .await?;
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        return Ok(());
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        let mut pending = Some((first_payload, original_destination));
        loop {
            if let Some((payload, original_destination)) = pending.take() {
                let (destination, origin_destination) =
                    restore_fake_ip(original_destination.clone(), outbounds)?;
                metadata.destination = Some(destination);
                metadata.origin_destination = origin_destination.clone();
                metadata.fake_ip = origin_destination.is_some();
                let response = hijack_dns_packet_with_context(
                    &payload, outbounds, &metadata,
                )
                .await?;
                incoming.send_to(&response, &original_destination).await?;
            }
            let (size, destination) =
                timeout(udp_timeout, incoming.recv_from(&mut packet))
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "SOCKS UDP session timed out",
                        )
                    })??;
            pending = Some((packet[..size].to_vec(), destination));
        }
    }
    let routed_destination = decision.destination(&destination);
    let connection_options = decision.connection_options();
    let udp_timeout = connection_options.udp_timeout.unwrap_or(udp_timeout);
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })?
    };
    let outgoing = dialer
        .listen_udp_with_options(
            &routed_destination,
            &connection_options.network,
        )
        .await?;
    let mut destination_nat = PacketDestinationNat::new(
        destination.clone(),
        routed_destination.clone(),
    );
    let first_routed_destination = destination_nat
        .translate_destination(destination, original_destination);
    outgoing
        .send_to(&first_payload, &first_routed_destination)
        .await?;
    let mut response = vec![0_u8; 65_535];
    loop {
        enum Event {
            Incoming(io::Result<(usize, SocksAddr)>),
            Response(io::Result<(usize, SocksAddr)>),
        }
        let event = timeout(udp_timeout, async {
            tokio::select! {
                result = incoming.recv_from(&mut packet) => Event::Incoming(result),
                result = outgoing.recv_from(&mut response) => Event::Response(result),
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "SOCKS UDP session timed out",
            )
        })?;
        match event {
            Event::Incoming(result) => {
                let (size, original_destination) = result?;
                let (destination, _origin_destination) =
                    restore_fake_ip(original_destination.clone(), outbounds)?;
                let destination = destination_nat
                    .translate_destination(destination, original_destination);
                outgoing.send_to(&packet[..size], &destination).await?;
            }
            Event::Response(result) => {
                let (size, response_source) = result?;
                let response_source =
                    destination_nat.translate_source(response_source);
                incoming
                    .send_to(&response[..size], &response_source)
                    .await?;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp<S>(
    mut client: S,
    source: SocketAddr,
    tag: &str,
    version: SocksVersion,
    destination: crate::common::network::SocksAddr,
    user: Option<String>,
    router: &Router,
    outbounds: &OutboundManager,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (destination, origin_destination) =
        restore_fake_ip(destination, outbounds)?;
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination.clone()),
        origin_destination: origin_destination.clone(),
        fake_ip: origin_destination.is_some(),
        network: Some(Network::Tcp),
        user: user.unwrap_or_default(),
        ..inherited_tcp_metadata(source, tag)
    };
    if let Some(injector) =
        prepare_tcp_inbound_detour(&mut metadata, outbounds)?
    {
        write_reply_for_version(&mut client, version, 0, None).await?;
        return injector
            .inject(Box::new(client), TcpInboundContext { source, metadata })
            .await;
    }
    let sniff_before_dial =
        matches!(router.route(&metadata).action(), Some(Action::Sniff(_)));
    if sniff_before_dial {
        // SOCKS clients wait for a successful command reply before emitting
        // the application payload that the route action needs to inspect.
        write_reply_for_version(&mut client, version, 0, None).await?;
    }
    let (mut client, decision) = sniff_and_route_stream(
        Box::new(client) as Stream,
        &mut metadata,
        router,
        outbounds,
    )
    .await?;
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        if !sniff_before_dial {
            write_reply_for_version(&mut client, version, 2, None).await?;
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection rejected by route rule",
        ));
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        if !sniff_before_dial {
            write_reply_for_version(&mut client, version, 0, None).await?;
        }
        return serve_hijacked_dns_stream_with_context(
            client, outbounds, &metadata,
        )
        .await;
    }
    let routed_destination = decision.destination(&destination);
    let connection_options = decision.connection_options();
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "outbound not found: {}",
                    decision.outbound().unwrap_or_default()
                ),
            )
        })?
    };
    let mut remote = match dialer
        .dial_tcp_with_options(&routed_destination, &connection_options.network)
        .await
    {
        Ok(stream) => stream,
        Err(error) => {
            if !sniff_before_dial {
                let _ = write_reply_for_version(
                    &mut client,
                    version,
                    error_reply(&error),
                    None,
                )
                .await;
            }
            return Err(error);
        }
    };
    remote = match super::apply_routed_tcp_options(remote, &connection_options)
    {
        Ok(stream) => stream,
        Err(error) => {
            if !sniff_before_dial {
                let _ = write_reply_for_version(
                    &mut client,
                    version,
                    error_reply(&error),
                    None,
                )
                .await;
            }
            return Err(error);
        }
    };
    if !sniff_before_dial {
        write_reply_for_version(&mut client, version, 0, None).await?;
    }
    copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_udp_association<S>(
    mut control: S,
    local_ip: IpAddr,
    source: SocketAddr,
    tag: &str,
    requested_client: crate::common::network::SocksAddr,
    user: Option<String>,
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
    let bound = socket.local_addr()?;
    write_reply_for_version(
        &mut control,
        SocksVersion::V5,
        0,
        Some(&bound.into()),
    )
    .await?;
    let client_address = match requested_client {
        crate::common::network::SocksAddr::Ip(address)
            if !address.ip().is_unspecified() && address.port() != 0 =>
        {
            Some(address)
        }
        _ => None,
    };
    let incoming: PacketStream = Box::new(SocksUdpAssociation {
        socket,
        source_ip: source.ip(),
        client: Mutex::new(client_address),
    });
    tokio::select! {
        result = proxy_packet_connection(
            incoming, source, tag, user, router, outbounds, udp_timeout,
        ) => result,
        result = wait_for_control_close(&mut control) => result,
    }
}

async fn wait_for_control_close<S>(control: &mut S) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    loop {
        match control.read_u8().await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
}

struct SocksUdpAssociation {
    socket: UdpSocket,
    source_ip: IpAddr,
    client: Mutex<Option<SocketAddr>>,
}

impl PacketConnection for SocksUdpAssociation {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let client = self.client.lock().await.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "SOCKS UDP client is not known",
                )
            })?;
            let packet = encode_udp_packet(destination, data)?;
            self.socket.send_to(&packet, client).await
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut packet = vec![0_u8; 65_535];
            loop {
                let (size, sender) = self.socket.recv_from(&mut packet).await?;
                if sender.ip() != self.source_ip {
                    continue;
                }
                let mut client = self.client.lock().await;
                if client.is_some_and(|expected| expected != sender) {
                    continue;
                }
                client.get_or_insert(sender);
                drop(client);
                let (destination, payload) =
                    decode_udp_packet(&packet[..size])?;
                if payload.len() > data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "SOCKS UDP receive buffer is too small",
                    ));
                }
                data[..payload.len()].copy_from_slice(payload);
                return Ok((payload.len(), destination));
            }
        })
    }
}

pub(crate) fn restore_fake_ip(
    destination: crate::common::network::SocksAddr,
    outbounds: &OutboundManager,
) -> io::Result<(
    crate::common::network::SocksAddr,
    Option<crate::common::network::SocksAddr>,
)> {
    let crate::common::network::SocksAddr::Ip(address) = &destination else {
        return Ok((destination, None));
    };
    if !outbounds.dns().is_fake_ip(address.ip()) {
        return Ok((destination, None));
    }
    let domain = outbounds
        .dns()
        .fake_ip_domain(address.ip())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "missing fakeip record, enable a persistent cache when clients retain DNS results",
            )
        })?;
    let restored =
        crate::common::network::SocksAddr::new(domain, address.port());
    Ok((restored, Some(destination)))
}

fn error_reply(error: &io::Error) -> u8 {
    match error.kind() {
        io::ErrorKind::PermissionDenied => 2,
        io::ErrorKind::NetworkUnreachable => 3,
        io::ErrorKind::HostUnreachable | io::ErrorKind::NotFound => 4,
        io::ErrorKind::ConnectionRefused => 5,
        io::ErrorKind::TimedOut => 6,
        io::ErrorKind::Unsupported => 7,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
    };

    use super::SocksInbound;
    use crate::{
        common::{
            lifecycle::{Lifecycle, StartStage},
            network::SocksAddr,
        },
        inbound::http::HttpTcpInjector,
        option::{HttpMixedInboundOptions, Options, SocksInboundOptions},
        outbound::OutboundManager,
        protocol::socks::{
            client_handshake, client_handshake4, client_udp_associate,
            decode_udp_packet, encode_udp_packet,
        },
        route::Router,
    };

    #[tokio::test]
    async fn proxies_a_tcp_connection_end_to_end() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let options: SocksInboundOptions = serde_json::from_value(json!({
            "listen": "127.0.0.1",
            "listen_port": 0
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound = SocksInbound::new("test", options, router, outbounds);
        inbound.start(StartStage::Initialize).await.unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let mut client = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        client_handshake(&mut client, &target_address.into(), None)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut data = [0_u8; 4];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"ping");
        inbound.close().await.unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn proxies_a_socks4a_domain_connection_end_to_end() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let runtime_options: Options = serde_json::from_value(json!({
            "dns": {
                "servers": [{
                    "type":"hosts",
                    "tag":"hosts",
                    "predefined":{"echo.test":"127.0.0.1"}
                }],
                "final":"hosts"
            },
            "outbounds":[{"type":"direct","tag":"direct"}]
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&runtime_options, "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let options: SocksInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0
        }))
        .unwrap();
        let mut inbound = SocksInbound::new("test", options, router, outbounds);
        inbound.start(StartStage::Start).await.unwrap();

        let mut client = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        client_handshake4(
            &mut client,
            &crate::common::network::SocksAddr::new("echo.test", target_port),
            "",
        )
        .await
        .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut data = [0_u8; 4];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"ping");
        inbound.close().await.unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn proxies_a_udp_association_end_to_end() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut data = [0_u8; 32];
            let mut first_source = None;
            for _ in 0..2 {
                let (size, source) = target.recv_from(&mut data).await.unwrap();
                if let Some(first_source) = first_source {
                    assert_eq!(source, first_source);
                } else {
                    first_source = Some(source);
                }
                target.send_to(&data[..size], source).await.unwrap();
            }
        });
        let options: SocksInboundOptions = serde_json::from_value(json!({
            "listen": "127.0.0.1",
            "listen_port": 0,
            "udp_timeout": "5s"
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound = SocksInbound::new("test", options, router, outbounds);
        inbound.start(StartStage::Initialize).await.unwrap();
        inbound.start(StartStage::Start).await.unwrap();

        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut control = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        let relay = client_udp_associate(
            &mut control,
            &udp_client.local_addr().unwrap().into(),
            None,
        )
        .await
        .unwrap();
        let relay = relay.resolve().await.unwrap()[0];
        let request =
            encode_udp_packet(&target_address.into(), b"datagram").unwrap();
        udp_client.send_to(&request, relay).await.unwrap();
        let mut response = [0_u8; 512];
        let (size, _) = udp_client.recv_from(&mut response).await.unwrap();
        let (source, payload) = decode_udp_packet(&response[..size]).unwrap();
        assert_eq!(source, target_address.into());
        assert_eq!(payload, b"datagram");
        let request =
            encode_udp_packet(&target_address.into(), b"again").unwrap();
        udp_client.send_to(&request, relay).await.unwrap();
        let (size, _) = udp_client.recv_from(&mut response).await.unwrap();
        let (source, payload) = decode_udp_packet(&response[..size]).unwrap();
        assert_eq!(source, target_address.into());
        assert_eq!(payload, b"again");

        drop(control);
        inbound.close().await.unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn proxies_udp_over_tcp_versions_one_and_two_end_to_end() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            for _ in 0..2 {
                let mut data = [0_u8; 32];
                let (size, source) = target.recv_from(&mut data).await.unwrap();
                target.send_to(&data[..size], source).await.unwrap();
            }
        });
        let inbound_options: SocksInboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "udp_timeout":"5s"
            }))
            .unwrap();
        let direct = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound =
            SocksInbound::new("uot", inbound_options, router, direct);
        inbound.start(StartStage::Start).await.unwrap();
        let proxy = inbound.local_addr().unwrap();

        for version in [1, 2] {
            let options: Options = serde_json::from_value(json!({
                "outbounds":[{
                    "type":"socks",
                    "tag":"proxy",
                    "server":proxy.ip().to_string(),
                    "server_port":proxy.port(),
                    "udp_over_tcp":{"enabled":true,"version":version}
                }]
            }))
            .unwrap();
            let outbounds =
                OutboundManager::from_options(&options, "").unwrap();
            let connection = outbounds
                .default()
                .listen_udp(&target_address.into())
                .await
                .unwrap();
            connection
                .send_to(b"uot", &target_address.into())
                .await
                .unwrap();
            let mut data = [0_u8; 32];
            let (size, source) = connection.recv_from(&mut data).await.unwrap();
            assert_eq!(source, target_address.into());
            assert_eq!(&data[..size], b"uot");
        }
        inbound.close().await.unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn restores_fake_ip_before_routing_tcp() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let options: Options = serde_json::from_value(json!({
            "dns": {
                "servers": [
                    {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"},
                    {"type":"hosts","tag":"real","predefined":{"echo.test":"127.0.0.1"}}
                ],
                "final": "real"
            },
            "outbounds": [
                {"type":"direct","tag":"direct","domain_resolver":"real"},
                {"type":"block","tag":"block"}
            ]
        }))
        .unwrap();
        let outbounds =
            Arc::new(OutboundManager::from_options(&options, "block").unwrap());
        let fake_address = outbounds
            .dns()
            .resolver("fake")
            .unwrap()
            .lookup("echo.test", crate::option::DomainStrategy::Ipv4Only)
            .await
            .unwrap()[0];
        let router = Arc::new(
            Router::from_json(
                &[json!({"domain":"echo.test","outbound":"direct"})],
                "block",
            )
            .unwrap(),
        );
        let inbound_options: SocksInboundOptions = serde_json::from_value(
            json!({"listen":"127.0.0.1","listen_port":0}),
        )
        .unwrap();
        let mut inbound =
            SocksInbound::new("test", inbound_options, router, outbounds);
        inbound.start(StartStage::Start).await.unwrap();
        let mut client = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        client_handshake(
            &mut client,
            &std::net::SocketAddr::new(fake_address, target_port).into(),
            None,
        )
        .await
        .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut data = [0_u8; 4];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"ping");
        inbound.close().await.unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn listener_detour_injects_socks_payload_into_http() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let options: Options = serde_json::from_value(json!({
            "outbounds": [{"type":"direct","tag":"direct"}]
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&options, "direct").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "direct").unwrap());
        let injector = Arc::new(
            HttpTcpInjector::new(
                "inner-http",
                HttpMixedInboundOptions::default(),
                router.clone(),
                outbounds.clone(),
            )
            .unwrap(),
        );
        outbounds.register_inbound_tcp_detour(
            "outer-socks",
            "inner-http",
            true,
            Some(injector),
        );
        let inbound_options: SocksInboundOptions = serde_json::from_value(
            json!({"listen":"127.0.0.1","listen_port":0}),
        )
        .unwrap();
        let mut inbound = SocksInbound::new(
            "outer-socks",
            inbound_options,
            router,
            outbounds,
        );
        inbound.start(StartStage::Start).await.unwrap();

        let mut client = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        client_handshake(
            &mut client,
            &"192.0.2.1:9"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
            None,
        )
        .await
        .unwrap();
        client
            .write_all(
                format!(
                    "CONNECT {target_address} HTTP/1.1\r\nHost: {target_address}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            client.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
        }
        assert!(response.starts_with(b"HTTP/1.1 200"));
        client.write_all(b"ping").await.unwrap();
        let mut data = [0_u8; 4];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"ping");

        inbound.close().await.unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn restores_fake_ip_and_rewrites_udp_response_source() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let mut data = [0_u8; 32];
            let (size, source) = target.recv_from(&mut data).await.unwrap();
            target.send_to(&data[..size], source).await.unwrap();
        });
        let options: Options = serde_json::from_value(json!({
            "dns": {"servers": [
                {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"},
                {"type":"hosts","tag":"real","predefined":{"echo.test":"127.0.0.1"}}
            ], "final":"real"},
            "outbounds": [
                {"type":"direct","tag":"direct","domain_resolver":"real"},
                {"type":"block","tag":"block"}
            ]
        }))
        .unwrap();
        let outbounds =
            Arc::new(OutboundManager::from_options(&options, "block").unwrap());
        let fake_address = outbounds
            .dns()
            .resolver("fake")
            .unwrap()
            .lookup("echo.test", crate::option::DomainStrategy::Ipv4Only)
            .await
            .unwrap()[0];
        let fake_destination =
            std::net::SocketAddr::new(fake_address, target_port).into();
        let router = Arc::new(
            Router::from_json(
                &[json!({"domain":"echo.test","outbound":"direct"})],
                "block",
            )
            .unwrap(),
        );
        let inbound_options: SocksInboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "udp_timeout":"5s"
            }))
            .unwrap();
        let mut inbound =
            SocksInbound::new("test", inbound_options, router, outbounds);
        inbound.start(StartStage::Start).await.unwrap();
        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut control = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        let relay = client_udp_associate(
            &mut control,
            &udp_client.local_addr().unwrap().into(),
            None,
        )
        .await
        .unwrap()
        .resolve()
        .await
        .unwrap()[0];
        let request = encode_udp_packet(&fake_destination, b"fake").unwrap();
        udp_client.send_to(&request, relay).await.unwrap();
        let mut response = [0_u8; 512];
        let (size, _) = udp_client.recv_from(&mut response).await.unwrap();
        let (source, payload) = decode_udp_packet(&response[..size]).unwrap();
        assert_eq!(source, fake_destination);
        assert_eq!(payload, b"fake");
        drop(control);
        inbound.close().await.unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn route_override_rewrites_udp_response_source() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let mut data = [0_u8; 32];
            let (size, source) = target.recv_from(&mut data).await.unwrap();
            target.send_to(&data[..size], source).await.unwrap();
        });
        let options: Options = serde_json::from_value(json!({
            "outbounds": [{"type":"direct","tag":"direct"}]
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&options, "direct").unwrap(),
        );
        let original_destination = SocksAddr::new("192.0.2.77", 5353);
        let router = Arc::new(
            Router::from_json(
                &[json!({
                    "action":"route",
                    "outbound":"direct",
                    "override_address":"127.0.0.1",
                    "override_port":target_port
                })],
                "direct",
            )
            .unwrap(),
        );
        let inbound_options: SocksInboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "udp_timeout":"5s"
            }))
            .unwrap();
        let mut inbound =
            SocksInbound::new("test", inbound_options, router, outbounds);
        inbound.start(StartStage::Start).await.unwrap();
        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut control = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        let relay = client_udp_associate(
            &mut control,
            &udp_client.local_addr().unwrap().into(),
            None,
        )
        .await
        .unwrap()
        .resolve()
        .await
        .unwrap()[0];
        let request =
            encode_udp_packet(&original_destination, b"override").unwrap();
        udp_client.send_to(&request, relay).await.unwrap();
        let mut response = [0_u8; 512];
        let (size, _) = udp_client.recv_from(&mut response).await.unwrap();
        let (source, payload) = decode_udp_packet(&response[..size]).unwrap();
        assert_eq!(source, original_destination);
        assert_eq!(payload, b"override");
        drop(control);
        inbound.close().await.unwrap();
        echo.await.unwrap();
    }
}
