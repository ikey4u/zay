//! Fixed-destination TCP/UDP tunnel inbound.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{PacketStream, Stream},
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::{Network, SocksAddr},
    },
    inbound::{
        PacketSniffSessions, TcpInboundContext, hijack_dns_packet_with_context,
        prepare_tcp_inbound_detour, serve_hijacked_dns_stream_with_context,
        sniff_and_route_stream,
    },
    option::{DirectInboundOptions, Network as OptionNetwork},
    outbound::OutboundManager,
    route::{Action, Metadata, Router},
};

pub struct DirectInbound {
    name: String,
    tag: String,
    options: DirectInboundOptions,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    tasks: Vec<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

impl DirectInbound {
    pub fn new(
        tag: impl Into<String>,
        options: DirectInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Self {
        let tag = tag.into();
        Self {
            name: format!("inbound/direct[{tag}]"),
            tag,
            options,
            router,
            outbounds,
            cancellation: CancellationToken::new(),
            tasks: Vec::new(),
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
        let networks = self.options.network.build();
        let tcp_enabled = networks.contains(&OptionNetwork::Tcp);
        let udp_enabled = networks.contains(&OptionNetwork::Udp);
        let mut port = self.options.listen.listen_port;

        if tcp_enabled {
            let listener = crate::common::socket::bind_tcp_listener(
                SocketAddr::new(ip, port),
                &self.options.listen,
            )
            .await?;
            let local_addr = listener.local_addr()?;
            port = local_addr.port();
            self.local_addr = Some(local_addr);
            let cancellation = self.cancellation.clone();
            let tag = self.tag.clone();
            let options = self.options.clone();
            let router = self.router.clone();
            let outbounds = self.outbounds.clone();
            self.tasks.push(tokio::spawn(async move {
                tcp_loop(
                    listener,
                    cancellation,
                    tag,
                    options,
                    router,
                    outbounds,
                )
                .await
            }));
        }
        if udp_enabled {
            let socket =
                Arc::new(UdpSocket::bind(SocketAddr::new(ip, port)).await?);
            self.local_addr.get_or_insert(socket.local_addr()?);
            let cancellation = self.cancellation.clone();
            let tag = self.tag.clone();
            let options = self.options.clone();
            let router = self.router.clone();
            let outbounds = self.outbounds.clone();
            self.tasks.push(tokio::spawn(async move {
                udp_loop(socket, cancellation, tag, options, router, outbounds)
                    .await
            }));
        }
        Ok(())
    }
}

impl Lifecycle for DirectInbound {
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
            for task in self.tasks.drain(..) {
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

async fn tcp_loop(
    listener: TcpListener,
    cancellation: CancellationToken,
    tag: String,
    options: DirectInboundOptions,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            result = listener.accept() => {
                let (stream, source) = result?;
                let destination = override_destination(stream.local_addr()?.into(), &options);
                let tag = tag.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                connections.spawn(async move {
                    let _ = handle_tcp(stream, source, destination, &tag, &router, &outbounds).await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn handle_tcp(
    client: TcpStream,
    source: SocketAddr,
    destination: SocksAddr,
    tag: &str,
    router: &Router,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let mut metadata =
        route_metadata(Network::Tcp, source, destination.clone(), tag);
    if let Some(injector) =
        prepare_tcp_inbound_detour(&mut metadata, outbounds)?
    {
        return injector
            .inject(Box::new(client), TcpInboundContext { source, metadata })
            .await;
    }
    let (mut client, decision) = sniff_and_route_stream(
        Box::new(client) as Stream,
        &mut metadata,
        router,
        outbounds,
    )
    .await?;
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection rejected by route rule",
        ));
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        return serve_hijacked_dns_stream_with_context(
            client, outbounds, &metadata,
        )
        .await;
    }
    let destination = metadata.destination.as_ref().unwrap_or(&destination);
    let routed_destination = decision.destination(destination);
    let connection_options = decision.connection_options();
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })?
    };
    let mut remote = dialer
        .dial_tcp_with_options(&routed_destination, &connection_options.network)
        .await?;
    remote = super::apply_routed_tcp_options(remote, &connection_options)?;
    copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

async fn udp_loop(
    socket: Arc<UdpSocket>,
    cancellation: CancellationToken,
    tag: String,
    options: DirectInboundOptions,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> io::Result<()> {
    let local = socket.local_addr()?;
    let destination = override_destination(local.into(), &options);
    let udp_timeout = options
        .listen
        .udp_timeout
        .0
        .as_std()
        .filter(|duration| !duration.is_zero())
        .unwrap_or(crate::constant::UDP_TIMEOUT);
    let mut packet = vec![0_u8; 65_535];
    let mut sniff_sessions =
        PacketSniffSessions::<SocketAddr>::new(udp_timeout);
    let mut sessions = HashMap::<SocketAddr, mpsc::Sender<Vec<u8>>>::new();
    let (closed_sender, mut closed_receiver) = mpsc::unbounded_channel();
    let mut tasks = JoinSet::new();
    loop {
        let received = tokio::select! {
            _ = cancellation.cancelled() => break,
            Some(source) = closed_receiver.recv() => {
                sessions.remove(&source);
                continue;
            }
            received = socket.recv_from(&mut packet) => received?,
        };
        let (size, source) = received;
        let mut payload = packet[..size].to_vec();
        if let Some(sender) = sessions.get(&source) {
            match sender.try_send(payload) {
                Ok(()) => continue,
                Err(mpsc::error::TrySendError::Full(_)) => continue,
                Err(mpsc::error::TrySendError::Closed(error)) => {
                    payload = error;
                    sessions.remove(&source);
                }
            }
        }
        let mut metadata =
            route_metadata(Network::Udp, source, destination.clone(), &tag);
        let Ok(decision) = sniff_sessions
            .route(source, &payload, &mut metadata, &router, &outbounds)
            .await
        else {
            continue;
        };
        if matches!(decision.action(), Some(Action::Reject { .. })) {
            continue;
        }
        if matches!(decision.action(), Some(Action::HijackDns)) {
            let Ok(response) =
                hijack_dns_packet_with_context(&payload, &outbounds, &metadata)
                    .await
            else {
                continue;
            };
            socket.send_to(&response, source).await?;
            continue;
        }
        let destination = metadata.destination.as_ref().unwrap_or(&destination);
        let routed_destination = decision.destination(destination);
        let connection_options = decision.connection_options();
        let udp_timeout = connection_options.udp_timeout.unwrap_or(udp_timeout);
        let dialer = if matches!(decision.action(), Some(Action::Direct)) {
            outbounds.direct()
        } else if let Some(dialer) = outbounds.select(decision.outbound()) {
            dialer
        } else {
            continue;
        };
        let outgoing = match dialer
            .listen_udp_with_options(
                &routed_destination,
                &connection_options.network,
            )
            .await
        {
            Ok(connection) => connection,
            Err(_) => continue,
        };
        let (sender, receiver) = mpsc::channel(64);
        sessions.insert(source, sender);
        let socket = socket.clone();
        let closed_sender = closed_sender.clone();
        tasks.spawn(async move {
            let _ = proxy_udp_session(
                socket,
                source,
                outgoing,
                routed_destination,
                payload,
                receiver,
                udp_timeout,
            )
            .await;
            let _ = closed_sender.send(source);
        });
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn proxy_udp_session(
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    outgoing: PacketStream,
    destination: SocksAddr,
    first: Vec<u8>,
    mut receiver: mpsc::Receiver<Vec<u8>>,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let mut pending = Some(first);
    let mut response = vec![0_u8; 65_535];
    loop {
        if let Some(payload) = pending.take() {
            outgoing.send_to(&payload, &destination).await?;
        }
        enum Event {
            Incoming(Option<Vec<u8>>),
            Response(io::Result<(usize, SocksAddr)>),
        }
        let event = timeout(udp_timeout, async {
            tokio::select! {
                payload = receiver.recv() => Event::Incoming(payload),
                result = outgoing.recv_from(&mut response) => Event::Response(result),
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "direct UDP session timed out",
            )
        })?;
        match event {
            Event::Incoming(Some(payload)) => pending = Some(payload),
            Event::Incoming(None) => return Ok(()),
            Event::Response(result) => {
                let (size, _) = result?;
                socket.send_to(&response[..size], source).await?;
            }
        }
    }
}

fn route_metadata(
    network: Network,
    source: SocketAddr,
    destination: SocksAddr,
    tag: &str,
) -> Metadata {
    Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination),
        network: Some(network),
        ..Metadata::default()
    }
}

fn override_destination(
    original: SocksAddr,
    options: &DirectInboundOptions,
) -> SocksAddr {
    let host = if options.override_address.is_empty() {
        original.host()
    } else {
        options.override_address.clone()
    };
    let port = if options.override_port == 0 {
        original.port()
    } else {
        options.override_port
    };
    SocksAddr::new(host, port)
}

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, RecordType},
        serialize::binary::{BinDecodable, BinEncodable, BinEncoder},
    };
    use std::sync::Arc;

    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
    };

    use super::DirectInbound;
    use crate::{
        common::lifecycle::{Lifecycle, StartStage},
        option::{DirectInboundOptions, Options},
        outbound::OutboundManager,
        route::Router,
    };

    #[tokio::test]
    async fn fixed_destination_tunnels_tcp_and_udp() {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut bytes = [0_u8; 3];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let tcp_options: DirectInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0,
            "network":"tcp",
            "override_address":"127.0.0.1",
            "override_port":tcp_address.port()
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut tcp_inbound = DirectInbound::new(
            "tcp",
            tcp_options,
            router.clone(),
            outbounds.clone(),
        );
        tcp_inbound.start(StartStage::Start).await.unwrap();
        let mut client = TcpStream::connect(tcp_inbound.local_addr().unwrap())
            .await
            .unwrap();
        client.write_all(b"tcp").await.unwrap();
        let mut bytes = [0_u8; 3];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"tcp");
        tcp_inbound.close().await.unwrap();
        tcp_echo.await.unwrap();

        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut bytes = [0_u8; 16];
            let mut first_source = None;
            for _ in 0..2 {
                let (size, source) =
                    udp_target.recv_from(&mut bytes).await.unwrap();
                if let Some(first_source) = first_source {
                    assert_eq!(source, first_source);
                } else {
                    first_source = Some(source);
                }
                udp_target.send_to(&bytes[..size], source).await.unwrap();
            }
        });
        let udp_options: DirectInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0,
            "network":"udp",
            "override_address":"127.0.0.1",
            "override_port":udp_address.port(),
            "udp_timeout":"5s"
        }))
        .unwrap();
        let mut udp_inbound =
            DirectInbound::new("udp", udp_options, router, outbounds);
        udp_inbound.start(StartStage::Start).await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(b"udp", udp_inbound.local_addr().unwrap())
            .await
            .unwrap();
        let mut bytes = [0_u8; 16];
        let (size, _) = client.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..size], b"udp");
        client
            .send_to(b"again", udp_inbound.local_addr().unwrap())
            .await
            .unwrap();
        let (size, _) = client.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..size], b"again");
        udp_inbound.close().await.unwrap();
        udp_echo.await.unwrap();
    }

    #[tokio::test]
    async fn fixed_fake_ip_destination_is_restored_for_tcp_and_udp() {
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
        let router = Arc::new(
            Router::from_json(
                &[json!({"domain":"echo.test","outbound":"direct"})],
                "block",
            )
            .unwrap(),
        );

        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_target.local_addr().unwrap().port();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let tcp_options: DirectInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0,
            "network":"tcp",
            "override_address":fake_address.to_string(),
            "override_port":tcp_port
        }))
        .unwrap();
        let mut tcp_inbound = DirectInbound::new(
            "fake-tcp",
            tcp_options,
            router.clone(),
            outbounds.clone(),
        );
        tcp_inbound.start(StartStage::Start).await.unwrap();
        let mut tcp_client =
            TcpStream::connect(tcp_inbound.local_addr().unwrap())
                .await
                .unwrap();
        tcp_client.write_all(b"ping").await.unwrap();
        let mut payload = [0_u8; 4];
        tcp_client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        tcp_inbound.close().await.unwrap();
        tcp_echo.await.unwrap();

        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = udp_target.local_addr().unwrap().port();
        let udp_echo = tokio::spawn(async move {
            let mut payload = [0_u8; 32];
            let (size, source) =
                udp_target.recv_from(&mut payload).await.unwrap();
            udp_target.send_to(&payload[..size], source).await.unwrap();
        });
        let udp_options: DirectInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0,
            "network":"udp",
            "override_address":fake_address.to_string(),
            "override_port":udp_port,
            "udp_timeout":"5s"
        }))
        .unwrap();
        let mut udp_inbound =
            DirectInbound::new("fake-udp", udp_options, router, outbounds);
        udp_inbound.start(StartStage::Start).await.unwrap();
        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp_client
            .send_to(b"fake", udp_inbound.local_addr().unwrap())
            .await
            .unwrap();
        let mut response = [0_u8; 32];
        let (size, _) = udp_client.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"fake");
        udp_inbound.close().await.unwrap();
        udp_echo.await.unwrap();
    }

    #[tokio::test]
    async fn sniff_action_routes_by_http_host_without_consuming_request() {
        let fallback = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_address = fallback.local_addr().unwrap();
        let selected = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let selected_port = selected.local_addr().unwrap().port();
        let request = b"GET /check HTTP/1.1\r\nHost: route.example\r\n\r\n";
        let selected_task = tokio::spawn(async move {
            let (mut stream, _) = selected.accept().await.unwrap();
            let mut received = vec![0_u8; request.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, request);
            stream.write_all(b"selected").await.unwrap();
        });
        let options: DirectInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0,
            "network":"tcp",
            "override_address":"127.0.0.1",
            "override_port":fallback_address.port()
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(
            Router::from_json(
                &[
                    json!({"action":"sniff", "sniffer":"http"}),
                    json!({
                        "protocol":"http",
                        "domain":"route.example",
                        "override_port":selected_port
                    }),
                ],
                "",
            )
            .unwrap(),
        );
        let mut inbound =
            DirectInbound::new("sniff", options, router, outbounds);
        inbound.start(StartStage::Start).await.unwrap();
        let mut client = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        client.write_all(request).await.unwrap();
        let mut response = [0_u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"selected");
        inbound.close().await.unwrap();
        selected_task.await.unwrap();
        drop(fallback);
    }

    #[tokio::test]
    async fn udp_dns_sniff_and_hijack_uses_internal_resolver() {
        let options: Options = serde_json::from_value(json!({
            "dns": {"servers": [{
                "type": "hosts",
                "tag": "hosts",
                "predefined": {"hijack.example": "198.51.100.23"}
            }]}
        }))
        .unwrap();
        let outbounds =
            Arc::new(OutboundManager::from_options(&options, "").unwrap());
        let router = Arc::new(
            Router::from_json(
                &[
                    json!({"action":"sniff", "sniffer":"dns"}),
                    json!({"protocol":"dns", "action":"hijack-dns"}),
                ],
                "",
            )
            .unwrap(),
        );
        let inbound_options: DirectInboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "network":"udp",
                "override_address":"127.0.0.1",
                "override_port":53
            }))
            .unwrap();
        let mut inbound = DirectInbound::new(
            "dns-hijack",
            inbound_options,
            router,
            outbounds,
        );
        inbound.start(StartStage::Start).await.unwrap();

        let mut query = Message::new(0x3344, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("hijack.example.").unwrap(),
            RecordType::A,
        ));
        let mut wire = Vec::new();
        query.emit(&mut BinEncoder::new(&mut wire)).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&wire, inbound.local_addr().unwrap())
            .await
            .unwrap();
        let mut response = [0_u8; 1024];
        let (size, _) = client.recv_from(&mut response).await.unwrap();
        let response = Message::from_bytes(&response[..size]).unwrap();
        assert_eq!(response.id, 0x3344);
        assert!(matches!(
            &response.answers[0].data,
            RData::A(address) if address.0.to_string() == "198.51.100.23"
        ));
        inbound.close().await.unwrap();
    }
}
