//! TUIC v5 QUIC inbound.

use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};

use tokio::{
    io::copy_bidirectional,
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    adapter::Stream,
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::{Network, SocksAddr},
        tls::{TlsError, build_server_config_with_default_alpn},
    },
    inbound::{
        PacketDestinationNat, TcpInboundContext,
        hijack_dns_packet_with_context, prepare_tcp_inbound_detour,
        serve_hijacked_dns_stream_with_context, sniff_and_route_packet,
        sniff_and_route_stream, socks::restore_fake_ip,
    },
    option::TuicInboundOptions,
    outbound::OutboundManager,
    protocol::{
        hysteria2::Hysteria2QuicOptions,
        tuic::{
            DEFAULT_ALPN, ServerSession, ServerUdpEvent, UdpDefragmenter,
            UdpMessage, server_endpoint,
        },
    },
    route::{Action, Metadata, Router},
};

#[derive(Debug, thiserror::Error)]
pub enum TuicInboundError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("invalid TUIC inbound configuration: {0}")]
    Config(String),
}

pub struct TuicInbound {
    name: String,
    tag: String,
    options: TuicInboundOptions,
    users: Arc<HashMap<Uuid, (String, String)>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

impl TuicInbound {
    pub fn new(
        tag: impl Into<String>,
        options: TuicInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, TuicInboundError> {
        if options.users.is_empty() {
            return Err(TuicInboundError::Config("missing users".into()));
        }
        if options.tls.as_ref().is_none_or(|tls| !tls.enabled) {
            return Err(TuicInboundError::Config("TLS is required".into()));
        }
        if !matches!(
            options.congestion_control.as_str(),
            "" | "cubic" | "new_reno" | "bbr"
        ) {
            return Err(TuicInboundError::Config(format!(
                "unsupported congestion control {:?}",
                options.congestion_control
            )));
        }
        let mut users = HashMap::new();
        for (index, user) in options.users.iter().enumerate() {
            if user.uuid.is_empty() {
                return Err(TuicInboundError::Config(format!(
                    "missing uuid for user {index}"
                )));
            }
            let uuid = Uuid::parse_str(&user.uuid).map_err(|error| {
                TuicInboundError::Config(format!(
                    "invalid uuid for user {index}: {error}"
                ))
            })?;
            users.insert(uuid, (user.name.clone(), user.password.clone()));
        }
        let tag = tag.into();
        Ok(Self {
            name: format!("inbound/tuic[{tag}]"),
            tag,
            options,
            users: Arc::new(users),
            router,
            outbounds,
            cancellation: CancellationToken::new(),
            task: None,
            local_addr: None,
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    async fn bind(&mut self) -> io::Result<()> {
        let mut tls = build_server_config_with_default_alpn(
            self.options.tls.as_ref().expect("validated TLS"),
            &[DEFAULT_ALPN],
        )
        .map_err(io::Error::other)?;
        if self.options.zero_rtt_handshake {
            Arc::make_mut(&mut tls.config).max_early_data_size = u32::MAX;
        }
        let address = SocketAddr::new(
            self.options
                .listen
                .listen
                .map(|address| address.0)
                .unwrap_or(std::net::Ipv6Addr::UNSPECIFIED.into()),
            self.options.listen.listen_port,
        );
        let mut transport = Hysteria2QuicOptions {
            idle_timeout: self.options.quic.idle_timeout.as_std(),
            keep_alive_period: self.options.quic.keep_alive_period.as_std(),
            stream_receive_window: self.options.quic.stream_receive_window.0,
            connection_receive_window: self
                .options
                .quic
                .connection_receive_window
                .0,
            max_concurrent_streams: u64::try_from(
                self.options.quic.max_concurrent_streams,
            )
            .map_err(|_| io::Error::other("negative max_concurrent_streams"))?,
            initial_packet_size: u64::try_from(
                self.options.quic.initial_packet_size,
            )
            .map_err(|_| io::Error::other("negative initial_packet_size"))?,
            disable_path_mtu_discovery: self
                .options
                .quic
                .disable_path_mtu_discovery,
        }
        .build()?;
        match self.options.congestion_control.as_str() {
            "new_reno" => {
                transport.congestion_controller_factory(Arc::new(
                    quinn::congestion::NewRenoConfig::default(),
                ));
            }
            "bbr" => {
                transport.congestion_controller_factory(Arc::new(
                    quinn::congestion::BbrConfig::default(),
                ));
            }
            "" | "cubic" => {}
            _ => unreachable!("congestion control validated in constructor"),
        }
        let endpoint = server_endpoint(address, tls, Arc::new(transport))?;
        self.local_addr = Some(endpoint.local_addr()?);
        let auth_timeout = self
            .options
            .auth_timeout
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(std::time::Duration::from_secs(3));
        let udp_timeout = self
            .options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        let heartbeat = self
            .options
            .heartbeat
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(std::time::Duration::from_secs(10));
        let cancellation = self.cancellation.clone();
        let users = self.users.clone();
        let tag = self.tag.clone();
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        self.task = Some(tokio::spawn(async move {
            accept_loop(
                endpoint,
                cancellation,
                users,
                auth_timeout,
                tag,
                router,
                outbounds,
                udp_timeout,
                heartbeat,
            )
            .await
        }));
        Ok(())
    }
}

impl Lifecycle for TuicInbound {
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
                task.await
                    .map_err(|error| LifecycleError::Close {
                        component: self.name.clone(),
                        message: error.to_string(),
                    })?
                    .map_err(|error| LifecycleError::Close {
                        component: self.name.clone(),
                        message: error.to_string(),
                    })?;
            }
            Ok(())
        })
    }
}

struct UdpState {
    sender: mpsc::Sender<UdpMessage>,
    defragmenter: UdpDefragmenter,
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    endpoint: quinn::Endpoint,
    cancellation: CancellationToken,
    users: Arc<HashMap<Uuid, (String, String)>>,
    auth_timeout: std::time::Duration,
    tag: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    heartbeat: std::time::Duration,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let users = users.clone();
                let tag = tag.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                connections.spawn(async move {
                    let connection = incoming.await.map_err(io::Error::other)?;
                    let source = connection.remote_address();
                    let session = ServerSession::authenticate(connection, &users, auth_timeout).await?;
                    let user = session.user.clone();
                    let mut udp_sessions = HashMap::<u16, UdpState>::new();
                    let (udp_closed_sender, mut udp_closed_receiver) =
                        mpsc::unbounded_channel();
                    let mut tasks = JoinSet::new();
                    let mut heartbeat_timer = tokio::time::interval(heartbeat);
                    heartbeat_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    heartbeat_timer.tick().await;
                    loop {
                        tokio::select! {
                            _ = heartbeat_timer.tick() => {
                                if session.send_heartbeat().is_err() {
                                    break;
                                }
                            }
                            result = session.accept_tcp() => {
                                let (stream, destination) = match result {
                                    Ok(value) => value,
                                    Err(_) if session.connection().close_reason().is_some() => break,
                                    Err(error) => return Err(error),
                                };
                                let tag = tag.clone();
                                let user = user.clone();
                                let router = router.clone();
                                let outbounds = outbounds.clone();
                                tasks.spawn(async move {
                                    let _ = proxy_tcp(Box::new(stream), source, &tag, destination, user, &router, &outbounds).await;
                                });
                            }
                            result = session.read_udp() => {
                                let event = match result {
                                    Ok(value) => value,
                                    Err(_) if session.connection().close_reason().is_some() => break,
                                    Err(error) => return Err(error),
                                };
                                let (message, stream_mode) = match event {
                                    ServerUdpEvent::Packet(message, stream_mode) => (message, stream_mode),
                                    ServerUdpEvent::Dissociate(session_id) => {
                                        udp_sessions.remove(&session_id);
                                        continue;
                                    }
                                    ServerUdpEvent::Heartbeat => continue,
                                };
                                let session_id = message.session_id;
                                if udp_sessions.get(&session_id).is_none_or(|state| state.sender.is_closed()) {
                                    udp_sessions.remove(&session_id);
                                    let (sender, receiver) = mpsc::channel(64);
                                    udp_sessions.insert(session_id, UdpState {
                                        sender,
                                        defragmenter: UdpDefragmenter::default(),
                                    });
                                    let connection = session.connection().clone();
                                    let tag = tag.clone();
                                    let user = user.clone();
                                    let router = router.clone();
                                    let outbounds = outbounds.clone();
                                    let udp_closed_sender = udp_closed_sender.clone();
                                    tasks.spawn(async move {
                                        let result = proxy_udp_session(
                                            connection, receiver, session_id,
                                            stream_mode, source, &tag, user,
                                            &router, &outbounds, udp_timeout,
                                        ).await;
                                        let _ = udp_closed_sender.send(session_id);
                                        let _ = result;
                                    });
                                }
                                let state = udp_sessions.get_mut(&session_id).expect("UDP session inserted");
                                let Some(message) = state.defragmenter.feed(message) else { continue };
                                let _ = state.sender.try_send(message);
                            }
                            Some(session_id) = udp_closed_receiver.recv() => {
                                if udp_sessions.get(&session_id).is_some_and(|state| state.sender.is_closed()) {
                                    udp_sessions.remove(&session_id);
                                }
                            }
                        }
                    }
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    Ok::<_, io::Error>(())
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    endpoint.close(0_u32.into(), b"");
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn proxy_udp_session(
    connection: quinn::Connection,
    mut receiver: mpsc::Receiver<UdpMessage>,
    session_id: u16,
    stream_mode: bool,
    source: SocketAddr,
    tag: &str,
    user: String,
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let first = timeout(udp_timeout, receiver.recv())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "TUIC UDP session timed out",
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "TUIC UDP session closed",
            )
        })?;
    let client_destination = first.destination.clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing TUIC UDP destination",
        )
    })?;
    let (destination, origin_destination) =
        restore_fake_ip(client_destination, outbounds)?;
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination.clone()),
        origin_destination: origin_destination.clone(),
        fake_ip: origin_destination.is_some(),
        network: Some(Network::Udp),
        user,
        ..Metadata::default()
    };
    let decision =
        sniff_and_route_packet(&first.data, &mut metadata, router, outbounds)
            .await?;
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        return Ok(());
    }
    let mut response_packet_id = 0_u16;
    if matches!(decision.action(), Some(Action::HijackDns)) {
        let mut pending = Some(first);
        loop {
            if let Some(message) = pending.take() {
                let response_source = message.destination.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "missing TUIC UDP destination",
                    )
                })?;
                let response = hijack_dns_packet_with_context(
                    &message.data,
                    outbounds,
                    &metadata,
                )
                .await?;
                send_udp_response(
                    &connection,
                    stream_mode,
                    session_id,
                    &mut response_packet_id,
                    response_source,
                    response,
                )
                .await?;
            }
            pending = Some(
                timeout(udp_timeout, receiver.recv())
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "TUIC UDP session timed out",
                        )
                    })?
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "TUIC UDP session closed",
                        )
                    })?,
            );
        }
    }

    let routed = decision.destination(&destination);
    let mut destination_nat =
        PacketDestinationNat::new(destination.clone(), routed);
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
            destination_nat.route_destination(),
            &connection_options.network,
        )
        .await?;
    let mut pending = Some(first);
    let mut response = vec![0_u8; 65_535];
    loop {
        if let Some(message) = pending.take() {
            let client_destination = message.destination.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing TUIC UDP destination",
                )
            })?;
            let (destination, _origin_destination) =
                restore_fake_ip(client_destination.clone(), outbounds)?;
            let destination = destination_nat
                .translate_destination(destination, client_destination);
            outgoing.send_to(&message.data, &destination).await?;
        }
        enum Event {
            Incoming(Option<UdpMessage>),
            Response(io::Result<(usize, SocksAddr)>),
        }
        let event = timeout(udp_timeout, async {
            tokio::select! {
                message = receiver.recv() => Event::Incoming(message),
                result = outgoing.recv_from(&mut response) => Event::Response(result),
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "TUIC UDP session timed out",
            )
        })?;
        match event {
            Event::Incoming(Some(message)) => pending = Some(message),
            Event::Incoming(None) => return Ok(()),
            Event::Response(result) => {
                let (size, response_source) = result?;
                let response_source =
                    destination_nat.translate_source(response_source);
                send_udp_response(
                    &connection,
                    stream_mode,
                    session_id,
                    &mut response_packet_id,
                    response_source,
                    response[..size].to_vec(),
                )
                .await?;
            }
        }
    }
}

async fn send_udp_response(
    connection: &quinn::Connection,
    stream_mode: bool,
    session_id: u16,
    packet_id: &mut u16,
    response_source: SocksAddr,
    data: Vec<u8>,
) -> io::Result<()> {
    *packet_id = packet_id.wrapping_add(1);
    let response = UdpMessage {
        session_id,
        packet_id: *packet_id,
        fragment_total: 1,
        fragment_id: 0,
        destination: Some(response_source),
        data,
    };
    if stream_mode {
        let mut stream =
            connection.open_uni().await.map_err(io::Error::other)?;
        stream
            .write_all(&response.encode()?)
            .await
            .map_err(io::Error::other)?;
        stream.finish().map_err(io::Error::other)?;
    } else {
        let mtu = connection.max_datagram_size().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "QUIC datagrams unavailable",
            )
        })?;
        for fragment in
            crate::protocol::tuic::fragment_udp_message(response, mtu)?
        {
            connection
                .send_datagram(bytes::Bytes::from(fragment.encode()?))
                .map_err(io::Error::other)?;
        }
    }
    Ok(())
}

async fn proxy_tcp(
    client: Stream,
    source: SocketAddr,
    tag: &str,
    destination: SocksAddr,
    user: String,
    router: &Router,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let (destination, origin_destination) =
        restore_fake_ip(destination, outbounds)?;
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination.clone()),
        origin_destination: origin_destination.clone(),
        fake_ip: origin_destination.is_some(),
        network: Some(Network::Tcp),
        user,
        ..Metadata::default()
    };
    if let Some(injector) =
        prepare_tcp_inbound_detour(&mut metadata, outbounds)?
    {
        return injector
            .inject(client, TcpInboundContext { source, metadata })
            .await;
    }
    let (mut client, decision) =
        sniff_and_route_stream(client, &mut metadata, router, outbounds)
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
    let destination = decision.destination(&destination);
    let connection_options = decision.connection_options();
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })?
    };
    let mut remote = dialer
        .dial_tcp_with_options(&destination, &connection_options.network)
        .await?;
    remote = super::apply_routed_tcp_options(remote, &connection_options)?;
    copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };
    use uuid::Uuid;

    use super::TuicInbound;
    use crate::{
        adapter::Dialer,
        common::{
            lifecycle::{Lifecycle, StartStage},
            network::SocksAddr,
            tls::build_client_config,
        },
        option::{
            DirectOutboundOptions, Options, OutboundTlsOptions,
            TuicInboundOptions,
        },
        outbound::OutboundManager,
        protocol::{
            direct::DirectOutbound,
            hysteria2::Hysteria2QuicOptions,
            tuic::{DEFAULT_ALPN, TuicOutbound},
        },
        route::Router,
    };

    #[tokio::test]
    async fn proxies_authenticated_tcp_and_fragmented_udp_end_to_end() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut payload = [0_u8; 4];
                stream.read_exact(&mut payload).await.unwrap();
                stream.write_all(&payload).await.unwrap();
            }
        });
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut payload = [0_u8; 4096];
            let mut first_source = None;
            for _ in 0..2 {
                let (size, source) =
                    udp_target.recv_from(&mut payload).await.unwrap();
                if let Some(first_source) = first_source {
                    assert_eq!(source, first_source);
                } else {
                    first_source = Some(source);
                }
                udp_target.send_to(&payload[..size], source).await.unwrap();
            }
        });
        let uuid =
            Uuid::parse_str("059032a9-7d40-4a96-9bb1-36823d848068").unwrap();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let options: TuicInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1", "listen_port":0,
            "users":[{
                "name":"alice", "uuid":uuid.to_string(),
                "password":"secret"
            }],
            "auth_timeout":"3s", "heartbeat":"10s",
            "congestion_control":"bbr",
            "tls":{
                "enabled":true,
                "certificate":cert.pem(),
                "key":key_pair.serialize_pem()
            }
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound =
            TuicInbound::new("tuic-in", options, router, outbounds).unwrap();
        inbound.start(StartStage::Start).await.unwrap();

        let server = inbound.local_addr().unwrap();
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &[DEFAULT_ALPN],
        )
        .unwrap();
        let mut transport = Hysteria2QuicOptions::default().build().unwrap();
        transport.congestion_controller_factory(Arc::new(
            quinn::congestion::BbrConfig::default(),
        ));
        let outbound = TuicOutbound::new_with_packet_dialer(
            server.into(),
            "localhost",
            uuid,
            "secret",
            tls,
            Arc::new(transport),
            false,
            std::time::Duration::from_secs(10),
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            false,
        );
        let mut stream = outbound
            .dial_tcp(&SocksAddr::from(destination))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        drop(stream);

        let udp_destination = SocksAddr::from(udp_destination);
        let udp = outbound.listen_udp(&udp_destination).await.unwrap();
        let packet: Vec<u8> =
            (0..3000).map(|index| (index % 251) as u8).collect();
        udp.send_to(&packet, &udp_destination).await.unwrap();
        let mut response = [0_u8; 4096];
        let (size, source) = udp.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], packet);
        assert_eq!(source, udp_destination);
        udp.send_to(b"second", &udp_destination).await.unwrap();
        let (size, source) = udp.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"second");
        assert_eq!(source, udp_destination);
        drop(udp);

        outbound.reset().await;
        let mut stream = outbound
            .dial_tcp(&SocksAddr::from(destination))
            .await
            .unwrap();
        stream.write_all(b"next").await.unwrap();
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"next");

        inbound.close().await.unwrap();
        echo.await.unwrap();
        udp_echo.await.unwrap();
    }
}
