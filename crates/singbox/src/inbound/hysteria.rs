//! Hysteria v1 QUIC inbound.

use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::common::sniff::{SniffError, sniff_stream};
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
        resolve_metadata, serve_hijacked_dns_stream_with_context,
        sniff_and_route_packet, socks::restore_fake_ip,
    },
    option::HysteriaInboundOptions,
    outbound::OutboundManager,
    protocol::{
        hysteria::{
            DEFAULT_ALPN, HysteriaBrutalServerConfig, HysteriaStream,
            MBPS_TO_BPS, ServerResponse, ServerSession, UdpDefragmenter,
            UdpMessage, server_endpoint, write_server_response,
        },
        hysteria2::Hysteria2QuicOptions,
    },
    route::{Action, Metadata, Router},
};

#[derive(Debug, thiserror::Error)]
pub enum HysteriaInboundError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("invalid Hysteria inbound configuration: {0}")]
    Config(String),
}

pub struct HysteriaInbound {
    name: String,
    tag: String,
    options: HysteriaInboundOptions,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

impl HysteriaInbound {
    pub fn new(
        tag: impl Into<String>,
        options: HysteriaInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, HysteriaInboundError> {
        if options.users.is_empty() {
            return Err(HysteriaInboundError::Config("missing users".into()));
        }
        if options.tls.as_ref().is_none_or(|tls| !tls.enabled) {
            return Err(HysteriaInboundError::Config("TLS is required".into()));
        }
        let (send_bps, receive_bps) = bandwidth(&options);
        if send_bps == 0 || receive_bps == 0 {
            return Err(HysteriaInboundError::Config(
                "upload/download speed is required".into(),
            ));
        }
        let tag = tag.into();
        Ok(Self {
            name: format!("inbound/hysteria[{tag}]"),
            tag,
            options,
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
        let tls = build_server_config_with_default_alpn(
            self.options.tls.as_ref().expect("validated TLS"),
            &[DEFAULT_ALPN],
        )
        .map_err(io::Error::other)?;
        let address = SocketAddr::new(
            self.options
                .listen
                .listen
                .map(|address| address.0)
                .unwrap_or(std::net::Ipv6Addr::UNSPECIFIED.into()),
            self.options.listen.listen_port,
        );
        let stream_window = if self.options.quic.stream_receive_window.0 == 0 {
            self.options.recv_window_client
        } else {
            self.options.quic.stream_receive_window.0
        };
        let connection_window =
            if self.options.quic.connection_receive_window.0 == 0 {
                self.options.recv_window_conn
            } else {
                self.options.quic.connection_receive_window.0
            };
        let max_concurrent_streams =
            if self.options.quic.max_concurrent_streams == 0 {
                self.options.max_conn_client
            } else {
                self.options.quic.max_concurrent_streams
            };
        let (send_bps, receive_bps) = bandwidth(&self.options);
        let server_brutal = Arc::new(HysteriaBrutalServerConfig::new(send_bps));
        let mut transport = Hysteria2QuicOptions {
            idle_timeout: self
                .options
                .quic
                .idle_timeout
                .as_std()
                .or(Some(std::time::Duration::from_secs(30))),
            keep_alive_period: self
                .options
                .quic
                .keep_alive_period
                .as_std()
                .or(Some(std::time::Duration::from_secs(10))),
            stream_receive_window: if stream_window == 0 {
                8 * 1024 * 1024
            } else {
                stream_window
            },
            connection_receive_window: if connection_window == 0 {
                20 * 1024 * 1024
            } else {
                connection_window
            },
            max_concurrent_streams: u64::try_from(max_concurrent_streams)
                .map_err(|_| {
                    io::Error::other("negative max_concurrent_streams")
                })?,
            initial_packet_size: u64::try_from(
                self.options.quic.initial_packet_size,
            )
            .map_err(|_| io::Error::other("negative initial_packet_size"))?,
            disable_path_mtu_discovery: self
                .options
                .quic
                .disable_path_mtu_discovery
                || self.options.disable_mtu_discovery,
        }
        .build()?;
        transport.congestion_controller_factory(server_brutal.clone());
        let endpoint = server_endpoint(
            address,
            tls,
            Arc::new(transport),
            (!self.options.obfs.is_empty())
                .then(|| self.options.obfs.as_bytes().to_vec()),
        )?;
        self.local_addr = Some(endpoint.local_addr()?);
        let users = Arc::new(
            self.options
                .users
                .iter()
                .map(|user| (user.password(), user.name.clone()))
                .collect(),
        );
        let udp_timeout = self
            .options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        let cancellation = self.cancellation.clone();
        let tag = self.tag.clone();
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        self.task = Some(tokio::spawn(async move {
            accept_loop(
                endpoint,
                server_brutal,
                cancellation,
                users,
                send_bps,
                receive_bps,
                tag,
                router,
                outbounds,
                udp_timeout,
            )
            .await
        }));
        Ok(())
    }
}

fn bandwidth(options: &HysteriaInboundOptions) -> (u64, u64) {
    let up = options
        .up
        .map(|value| value.value())
        .filter(|value| *value != 0)
        .unwrap_or_else(|| {
            u64::try_from(options.up_mbps.max(0)).unwrap() * MBPS_TO_BPS
        });
    let down = options
        .down
        .map(|value| value.value())
        .filter(|value| *value != 0)
        .unwrap_or_else(|| {
            u64::try_from(options.down_mbps.max(0)).unwrap() * MBPS_TO_BPS
        });
    (up, down)
}

impl Lifecycle for HysteriaInbound {
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
    server_brutal: Arc<HysteriaBrutalServerConfig>,
    cancellation: CancellationToken,
    users: Arc<HashMap<String, String>>,
    send_bps: u64,
    receive_bps: u64,
    tag: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
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
                let connecting = incoming.accept().map_err(io::Error::other)?;
                let brutal = server_brutal.take_pending().ok_or_else(|| {
                    io::Error::other("Hysteria Brutal controller was not constructed")
                })?;
                connections.spawn(async move {
                    let connection = connecting.await.map_err(io::Error::other)?;
                    let source = connection.remote_address();
                    let session = ServerSession::authenticate(connection, &users, send_bps, receive_bps).await?;
                    brutal.set_bps(session.negotiated_send_bps);
                    let user = session.user.clone();
                    let mut udp_sessions = HashMap::<u32, UdpState>::new();
                    let mut next_session_id = 0_u32;
                    let mut streams = JoinSet::new();
                    loop {
                        tokio::select! {
                            result = session.accept_request() => {
                                let (mut stream, request) = match result {
                                    Ok(value) => value,
                                    Err(_) if session.connection().close_reason().is_some() => break,
                                    Err(error) => return Err(error),
                                };
                                if request.udp {
                                    next_session_id = next_session_id.wrapping_add(1);
                                    write_server_response(&mut stream.send, &ServerResponse { ok: true, udp_session_id: next_session_id, message: String::new() }).await?;
                                    let destination = SocksAddr::new(request.host, request.port);
                                    let (sender, receiver) = mpsc::channel(64);
                                    udp_sessions.insert(next_session_id, UdpState { sender, defragmenter: UdpDefragmenter::default() });
                                    let connection = session.connection().clone();
                                    let tag = tag.clone(); let user = user.clone(); let router = router.clone(); let outbounds = outbounds.clone();
                                    streams.spawn(async move { let _ = proxy_udp_session(connection, stream, receiver, next_session_id, source, &tag, destination, user, &router, &outbounds, udp_timeout).await; });
                                } else {
                                    let destination = SocksAddr::new(request.host, request.port);
                                    let tag = tag.clone(); let user = user.clone(); let router = router.clone(); let outbounds = outbounds.clone();
                                    streams.spawn(async move { let _ = proxy_tcp(stream, source, &tag, destination, user, &router, &outbounds).await; });
                                }
                            }
                            result = session.read_udp(), if !udp_sessions.is_empty() => {
                                let message = match result {
                                    Ok(value) => value,
                                    Err(_) if session.connection().close_reason().is_some() => break,
                                    Err(error) => return Err(error),
                                };
                                let Some(state) = udp_sessions.get_mut(&message.session_id) else { continue; };
                                let Some(message) = state.defragmenter.feed(message) else { continue; };
                                let session_id = message.session_id;
                                if matches!(
                                    state.sender.try_send(message),
                                    Err(mpsc::error::TrySendError::Closed(_))
                                ) {
                                    udp_sessions.remove(&session_id);
                                }
                            }
                        }
                    }
                    streams.abort_all();
                    while streams.join_next().await.is_some() {}
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
    mut control: HysteriaStream,
    mut receiver: mpsc::Receiver<UdpMessage>,
    session_id: u32,
    source: SocketAddr,
    tag: &str,
    destination: SocksAddr,
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
                "Hysteria UDP session timed out",
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Hysteria UDP session closed",
            )
        })?;
    let (destination, origin_destination) =
        restore_fake_ip(destination, outbounds)?;
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
    let mut response_packet_id = 0_u32;
    if matches!(decision.action(), Some(Action::HijackDns)) {
        let mut pending = Some(first);
        let mut hold = [0_u8; 1024];
        loop {
            if let Some(message) = pending.take() {
                let response = hijack_dns_packet_with_context(
                    &message.data,
                    outbounds,
                    &metadata,
                )
                .await?;
                let response_source =
                    SocksAddr::new(message.host, message.port);
                send_udp_response(
                    &connection,
                    session_id,
                    &mut response_packet_id,
                    response_source,
                    response,
                )?;
            }
            let event = timeout(udp_timeout, async {
                tokio::select! {
                    message = receiver.recv() => Ok(message),
                    result = control.recv.read(&mut hold) => match result {
                        Ok(None) => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "Hysteria UDP control stream closed")),
                        Ok(Some(_)) => Ok(None),
                        Err(error) => Err(io::Error::other(error)),
                    },
                }
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Hysteria UDP session timed out",
                )
            })??;
            if let Some(message) = event {
                pending = Some(message);
            }
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
    let mut hold = [0_u8; 1024];
    loop {
        if let Some(message) = pending.take() {
            let client_destination = SocksAddr::new(message.host, message.port);
            let (destination, _origin_destination) =
                restore_fake_ip(client_destination.clone(), outbounds)?;
            let destination = destination_nat
                .translate_destination(destination, client_destination);
            outgoing.send_to(&message.data, &destination).await?;
        }
        enum Event {
            Incoming(Option<UdpMessage>),
            Response(io::Result<(usize, SocksAddr)>),
            Control(Result<Option<usize>, quinn::ReadError>),
        }
        let event = timeout(udp_timeout, async {
            tokio::select! {
                message = receiver.recv() => Event::Incoming(message),
                result = outgoing.recv_from(&mut response) => Event::Response(result),
                result = control.recv.read(&mut hold) => Event::Control(result),
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Hysteria UDP session timed out",
            )
        })?;
        match event {
            Event::Incoming(Some(message)) => pending = Some(message),
            Event::Incoming(None) => return Ok(()),
            Event::Response(result) => {
                let (size, source) = result?;
                let source = destination_nat.translate_source(source);
                send_udp_response(
                    &connection,
                    session_id,
                    &mut response_packet_id,
                    source,
                    response[..size].to_vec(),
                )?;
            }
            Event::Control(Ok(None)) => return Ok(()),
            Event::Control(Ok(Some(_))) => {}
            Event::Control(Err(error)) => {
                return Err(io::Error::other(error));
            }
        }
    }
}

fn send_udp_response(
    connection: &quinn::Connection,
    session_id: u32,
    packet_id: &mut u32,
    source: SocksAddr,
    data: Vec<u8>,
) -> io::Result<()> {
    *packet_id = packet_id.wrapping_add(1);
    let response = UdpMessage {
        session_id,
        packet_id: (*packet_id % u32::from(u16::MAX)) as u16,
        fragment_id: 0,
        fragment_count: 1,
        host: source.host(),
        port: source.port(),
        data,
    };
    let mtu = connection.max_datagram_size().ok_or_else(|| {
        io::Error::new(io::ErrorKind::Unsupported, "QUIC datagrams unavailable")
    })?;
    for fragment in
        crate::protocol::hysteria::fragment_udp_message(response, mtu)?
    {
        connection
            .send_datagram(bytes::Bytes::from(fragment.encode()?))
            .map_err(io::Error::other)?;
    }
    Ok(())
}

async fn proxy_tcp(
    mut client: HysteriaStream,
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
        send_tcp_success(&mut client).await?;
        return injector
            .inject(Box::new(client), TcpInboundContext { source, metadata })
            .await;
    }
    let mut route_state = router.route_state();
    let mut inspected = Vec::new();
    let decision = loop {
        let decision = router.route_next(&metadata, &mut route_state);
        match decision.action().cloned() {
            Some(Action::Sniff(options)) => {
                let server_first = matches!(
                    destination.port(),
                    25 | 110 | 143 | 465 | 587 | 993 | 995
                );
                if server_first || !metadata.protocol.is_empty() {
                    continue;
                }
                let deadline = tokio::time::Instant::now() + options.timeout;
                while inspected.len() < 64 * 1024 {
                    let mut chunk = [0_u8; 8192];
                    let limit = chunk.len().min(64 * 1024 - inspected.len());
                    let size = match tokio::time::timeout_at(
                        deadline,
                        client.read(&mut chunk[..limit]),
                    )
                    .await
                    {
                        Ok(Ok(size)) => size,
                        Ok(Err(error)) => {
                            send_tcp_failure(&mut client, &error).await;
                            return Err(error);
                        }
                        Err(_) => break,
                    };
                    if size == 0 {
                        break;
                    }
                    inspected.extend_from_slice(&chunk[..size]);
                    match sniff_stream(&inspected, &options.stream_sniffers) {
                        Ok(result) => {
                            metadata.protocol = result.protocol;
                            metadata.domain = result.domain;
                            metadata.client = result.client;
                            break;
                        }
                        Err(SniffError::NeedMoreData) => {}
                        Err(SniffError::Invalid(_)) => break,
                    }
                }
            }
            Some(Action::Resolve(options)) => {
                let routed = metadata
                    .destination
                    .as_ref()
                    .map(|destination| decision.destination(destination));
                if let Err(error) = resolve_metadata(
                    &mut metadata,
                    routed.as_ref(),
                    &options,
                    outbounds,
                )
                .await
                {
                    send_tcp_failure(&mut client, &error).await;
                    return Err(error);
                }
            }
            _ => break decision,
        }
    };
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        let error = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection rejected by route rule",
        );
        send_tcp_failure(&mut client, &error).await;
        return Err(error);
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        send_tcp_success(&mut client).await?;
        let client: Stream =
            crate::adapter::replay_stream(Box::new(client), inspected);
        return serve_hijacked_dns_stream_with_context(
            client, outbounds, &metadata,
        )
        .await;
    }
    let destination = decision.destination(&destination);
    let connection_options = decision.connection_options();
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        Ok(outbounds.direct())
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })
    };
    let dialer = match dialer {
        Ok(dialer) => dialer,
        Err(error) => {
            send_tcp_failure(&mut client, &error).await;
            return Err(error);
        }
    };
    let mut remote = match dialer
        .dial_tcp_with_options(&destination, &connection_options.network)
        .await
    {
        Ok(remote) => remote,
        Err(error) => {
            send_tcp_failure(&mut client, &error).await;
            return Err(error);
        }
    };
    remote = match super::apply_routed_tcp_options(remote, &connection_options)
    {
        Ok(stream) => stream,
        Err(error) => {
            send_tcp_failure(&mut client, &error).await;
            return Err(error);
        }
    };
    send_tcp_success(&mut client).await?;
    if !inspected.is_empty() {
        remote.write_all(&inspected).await?;
    }
    copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

async fn send_tcp_success(client: &mut HysteriaStream) -> io::Result<()> {
    write_server_response(
        &mut client.send,
        &ServerResponse {
            ok: true,
            udp_session_id: 0,
            message: String::new(),
        },
    )
    .await
}

async fn send_tcp_failure(client: &mut HysteriaStream, error: &io::Error) {
    let _ = write_server_response(
        &mut client.send,
        &ServerResponse {
            ok: false,
            udp_session_id: 0,
            message: error.to_string(),
        },
    )
    .await;
    let _ = client.send.finish();
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

    use super::HysteriaInbound;
    use crate::{
        adapter::Dialer,
        common::{
            lifecycle::{Lifecycle, StartStage},
            network::SocksAddr,
            tls::build_client_config,
        },
        option::{
            DirectOutboundOptions, HysteriaInboundOptions, Options,
            OutboundTlsOptions,
        },
        outbound::OutboundManager,
        protocol::{
            direct::DirectOutbound,
            hysteria::{HysteriaOutbound, MBPS_TO_BPS},
            hysteria2::Hysteria2QuicOptions,
        },
        route::Router,
    };

    #[tokio::test]
    async fn proxies_authenticated_xplus_tcp_and_udp_end_to_end() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
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

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let options: HysteriaInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1", "listen_port":0,
            "users":[{"name":"alice","auth_str":"secret"}],
            "up":"20 Mbps", "down":"40 Mbps", "obfs":"cover-secret",
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
        let router = Arc::new(
            Router::from_json(
                &[json!({
                    "network":"udp",
                    "action":"route-options",
                    "override_address":"127.0.0.1",
                    "override_port":udp_destination.port()
                })],
                "",
            )
            .unwrap(),
        );
        let mut inbound =
            HysteriaInbound::new("hy-in", options, router, outbounds).unwrap();
        inbound.start(StartStage::Start).await.unwrap();

        let server = inbound.local_addr().unwrap();
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &[crate::protocol::hysteria::DEFAULT_ALPN],
        )
        .unwrap();
        let transport = Hysteria2QuicOptions::default().build().unwrap();
        let outbound = HysteriaOutbound::new_with_packet_dialer(
            server.into(),
            "localhost",
            "secret",
            20 * MBPS_TO_BPS,
            40 * MBPS_TO_BPS,
            tls,
            transport,
            Some(b"cover-secret".to_vec()),
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
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

        let udp_destination = SocksAddr::new("192.0.2.77", 5353);
        let udp = outbound.listen_udp(&udp_destination).await.unwrap();
        let packet: Vec<u8> =
            (0..3000).map(|index| (index % 251) as u8).collect();
        udp.send_to(&packet, &udp_destination).await.unwrap();
        let mut response = [0_u8; 4096];
        let (size, source) = udp.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], packet);
        assert_eq!(source, udp_destination);
        udp.send_to(b"pong", &udp_destination).await.unwrap();
        let (size, source) = udp.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"pong");
        assert_eq!(source, udp_destination);

        let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable_destination = unavailable.local_addr().unwrap();
        drop(unavailable);
        let error = match outbound
            .dial_tcp(&SocksAddr::from(unavailable_destination))
            .await
        {
            Ok(_) => panic!("unavailable target unexpectedly connected"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("Hysteria remote error"),
            "unexpected error: {error}"
        );

        inbound.close().await.unwrap();
        echo.await.unwrap();
        udp_echo.await.unwrap();
    }
}
