//! VMess AEAD-header inbound with framed body security.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use quinn::Endpoint;
use tokio::{
    io::copy_bidirectional,
    net::TcpListener,
    sync::Mutex,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{PacketStream, Stream},
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::{Network, SocksAddr},
        ntp::NtpClock,
        tls::{
            ServerTlsConfig, TlsError,
            build_server_config_with_default_alpn_and_reality_dialer,
        },
    },
    inbound::{
        TcpInboundContext, TcpInboundInjector, TcpInjectFuture,
        inherited_tcp_metadata, prepare_tcp_inbound_detour, resolve_metadata,
        serve_hijacked_dns_stream_with_context, sniff_and_route_stream_from,
        socks::{proxy_packet_connection, restore_fake_ip},
        with_tcp_inbound_context,
    },
    option::{V2RayTransportOptions, VMessInboundOptions},
    outbound::OutboundManager,
    protocol::vmess::{
        Command, OPTION_CHUNK_STREAM, RequestHeader, Security,
        VmessPacketConnection, alter_id_key, command_key,
        read_request_with_clock, user_id, wrap_body_stream, write_response,
    },
    route::{Action, Metadata, Router},
    transport::{
        quic::{
            boxed_stream as boxed_quic_stream,
            server_config as quic_server_config,
        },
        v2ray::{
            accept_transport_streams, tls_alpn, validate_server_transport,
        },
    },
};

#[derive(Debug, thiserror::Error)]
pub enum VmessInboundError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("invalid VMess inbound configuration: {0}")]
    Config(String),
    #[error("unsupported VMess inbound functionality: {0}")]
    Unsupported(String),
}

pub struct VmessInbound {
    name: String,
    tag: String,
    options: VMessInboundOptions,
    keys: Vec<[u8; 16]>,
    alter_ids: Vec<Vec<[u8; 16]>>,
    names: Vec<String>,
    tls: Option<ServerTlsConfig>,
    transport: Option<V2RayTransportOptions>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    replay: Arc<Mutex<HashMap<[u8; 16], Instant>>>,
    clock: Option<NtpClock>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

#[derive(Clone)]
pub struct VmessTcpInjector {
    tag: String,
    keys: Vec<[u8; 16]>,
    alter_ids: Vec<Vec<[u8; 16]>>,
    names: Vec<String>,
    tls: Option<ServerTlsConfig>,
    transport: Option<V2RayTransportOptions>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    replay: Arc<Mutex<HashMap<[u8; 16], Instant>>>,
    clock: Option<NtpClock>,
    udp_timeout: Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
}

impl VmessTcpInjector {
    pub fn new(
        tag: impl Into<String>,
        options: VMessInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, VmessInboundError> {
        Self::new_with_clock(tag, options, router, outbounds, None)
    }

    pub fn new_with_clock(
        tag: impl Into<String>,
        options: VMessInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        clock: Option<NtpClock>,
    ) -> Result<Self, VmessInboundError> {
        let inbound = VmessInbound::new_with_clock(
            tag, options, router, outbounds, clock,
        )?;
        let multiplex_brutal = crate::protocol::mux::server_brutal_options(
            inbound
                .options
                .multiplex
                .as_ref()
                .filter(|multiplex| multiplex.enabled)
                .and_then(|multiplex| multiplex.brutal.as_ref()),
        )
        .map_err(|error| VmessInboundError::Unsupported(error.to_string()))?;
        Ok(Self {
            tag: inbound.tag,
            keys: inbound.keys,
            alter_ids: inbound.alter_ids,
            names: inbound.names,
            tls: inbound.tls,
            transport: inbound.transport,
            router: inbound.router,
            outbounds: inbound.outbounds,
            replay: inbound.replay,
            clock: inbound.clock,
            udp_timeout: inbound
                .options
                .listen
                .udp_timeout
                .0
                .as_std()
                .filter(|duration| !duration.is_zero())
                .unwrap_or(crate::constant::UDP_TIMEOUT),
            multiplex_enabled: inbound
                .options
                .multiplex
                .as_ref()
                .is_some_and(|multiplex| multiplex.enabled),
            multiplex_padding: inbound.options.multiplex.as_ref().is_some_and(
                |multiplex| multiplex.enabled && multiplex.padding,
            ),
            multiplex_brutal,
        })
    }
}

impl TcpInboundInjector for VmessTcpInjector {
    fn inject<'a>(
        &'a self,
        stream: Stream,
        context: TcpInboundContext,
    ) -> TcpInjectFuture<'a> {
        let source = context.source;
        Box::pin(with_tcp_inbound_context(context, async move {
            let stream = match self.tls.clone() {
                Some(tls) if self.transport.is_none() => {
                    Box::new(tls.accept_stream(stream).await?)
                }
                _ => stream,
            };
            serve_stream(
                stream,
                source,
                &self.tag,
                &self.keys,
                &self.alter_ids,
                &self.names,
                &self.router,
                &self.outbounds,
                &self.replay,
                self.clock.as_ref(),
                self.udp_timeout,
                self.multiplex_enabled,
                self.multiplex_padding,
                self.multiplex_brutal,
            )
            .await
        }))
    }
}

impl VmessInbound {
    pub fn new(
        tag: impl Into<String>,
        options: VMessInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, VmessInboundError> {
        Self::new_with_clock(tag, options, router, outbounds, None)
    }

    pub fn new_with_clock(
        tag: impl Into<String>,
        options: VMessInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        clock: Option<NtpClock>,
    ) -> Result<Self, VmessInboundError> {
        let transport = options.transport.clone();
        if let Some(transport) = transport.as_ref() {
            validate_server_transport(transport).map_err(|error| {
                VmessInboundError::Unsupported(error.to_string())
            })?;
        }
        if matches!(transport, Some(V2RayTransportOptions::Quic))
            && !options.tls.as_ref().is_some_and(|tls| tls.enabled)
        {
            return Err(VmessInboundError::Config(
                "V2Ray QUIC transport requires TLS".into(),
            ));
        }
        crate::protocol::mux::server_brutal_options(
            options
                .multiplex
                .as_ref()
                .filter(|multiplex| multiplex.enabled)
                .and_then(|multiplex| multiplex.brutal.as_ref()),
        )
        .map_err(|error| VmessInboundError::Unsupported(error.to_string()))?;
        let mut seen = HashMap::new();
        let mut keys = Vec::with_capacity(options.users.len());
        let mut names = Vec::with_capacity(options.users.len());
        let mut alter_ids = Vec::with_capacity(options.users.len());
        for (index, user) in options.users.iter().enumerate() {
            let id = user_id(&user.uuid);
            if let Some(first) = seen.insert(id, index) {
                return Err(VmessInboundError::Config(format!(
                    "duplicate VMess UUID for users {first} and {index}"
                )));
            }
            keys.push(command_key(id));
            if user.alter_id < 0 {
                return Err(VmessInboundError::Config(format!(
                    "VMess user {index} alterId cannot be negative"
                )));
            }
            alter_ids.push(
                (1..=user.alter_id as usize)
                    .map(|alter_index| alter_id_key(id, alter_index))
                    .collect(),
            );
            names.push(if user.name.is_empty() {
                index.to_string()
            } else {
                user.name.clone()
            });
        }
        if keys.is_empty() {
            return Err(VmessInboundError::Config(
                "at least one VMess user is required".into(),
            ));
        }
        let reality_dialer = options
            .tls
            .as_ref()
            .and_then(|tls| tls.reality.as_ref())
            .filter(|reality| reality.enabled)
            .map(|reality| {
                outbounds.endpoint_dialer(
                    "inbound/vmess/reality",
                    &reality.handshake.dialer,
                )
            })
            .transpose()
            .map_err(|error| {
                VmessInboundError::Tls(TlsError::Unsupported(error.to_string()))
            })?;
        let tls = options
            .tls
            .as_ref()
            .filter(|tls| tls.enabled)
            .map(|tls| {
                build_server_config_with_default_alpn_and_reality_dialer(
                    tls,
                    tls_alpn(options.transport.as_ref()),
                    reality_dialer.clone(),
                )
            })
            .transpose()?;
        let tag = tag.into();
        Ok(Self {
            name: format!("inbound/vmess[{tag}]"),
            tag,
            options,
            keys,
            alter_ids,
            names,
            tls,
            transport,
            router,
            outbounds,
            replay: Arc::new(Mutex::new(HashMap::new())),
            clock,
            cancellation: CancellationToken::new(),
            task: None,
            local_addr: None,
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    async fn bind(&mut self) -> io::Result<()> {
        let multiplex_enabled = self
            .options
            .multiplex
            .as_ref()
            .is_some_and(|multiplex| multiplex.enabled);
        let multiplex_padding =
            self.options.multiplex.as_ref().is_some_and(|multiplex| {
                multiplex.enabled && multiplex.padding
            });
        let multiplex_brutal = crate::protocol::mux::server_brutal_options(
            self.options
                .multiplex
                .as_ref()
                .filter(|multiplex| multiplex.enabled)
                .and_then(|multiplex| multiplex.brutal.as_ref()),
        )?;
        let ip = self
            .options
            .listen
            .listen
            .map(|value| value.0)
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        let bind_address = SocketAddr::new(ip, self.options.listen.listen_port);
        let udp_timeout = self
            .options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|value| !value.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        if matches!(self.transport, Some(V2RayTransportOptions::Quic)) {
            let tls = self.tls.clone().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "QUIC requires TLS")
            })?;
            let endpoint =
                Endpoint::server(quic_server_config(tls)?, bind_address)?;
            self.local_addr = Some(endpoint.local_addr()?);
            self.task = Some(tokio::spawn(quic_accept_loop(
                endpoint,
                self.cancellation.clone(),
                self.tag.clone(),
                self.keys.clone(),
                self.alter_ids.clone(),
                self.names.clone(),
                self.router.clone(),
                self.outbounds.clone(),
                self.replay.clone(),
                self.clock.clone(),
                udp_timeout,
                multiplex_enabled,
                multiplex_padding,
                multiplex_brutal,
            )));
        } else {
            let listener = crate::common::socket::bind_tcp_listener(
                bind_address,
                &self.options.listen,
            )
            .await?;
            self.local_addr = Some(listener.local_addr()?);
            self.task = Some(tokio::spawn(accept_loop(
                listener,
                self.cancellation.clone(),
                self.tag.clone(),
                self.keys.clone(),
                self.alter_ids.clone(),
                self.names.clone(),
                self.tls.clone(),
                self.transport.clone(),
                self.router.clone(),
                self.outbounds.clone(),
                self.replay.clone(),
                self.clock.clone(),
                udp_timeout,
                multiplex_enabled,
                multiplex_padding,
                multiplex_brutal,
            )));
        }
        Ok(())
    }
}

impl Lifecycle for VmessInbound {
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

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    cancellation: CancellationToken,
    tag: String,
    keys: Vec<[u8; 16]>,
    alter_ids: Vec<Vec<[u8; 16]>>,
    names: Vec<String>,
    tls: Option<ServerTlsConfig>,
    transport: Option<V2RayTransportOptions>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    replay: Arc<Mutex<HashMap<[u8; 16], Instant>>>,
    clock: Option<NtpClock>,
    udp_timeout: Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            result = listener.accept() => {
                let (stream, source) = result?;
                let tag = tag.clone(); let keys = keys.clone(); let alter_ids = alter_ids.clone(); let names = names.clone();
                let tls = tls.clone(); let transport = transport.clone(); let router = router.clone(); let outbounds = outbounds.clone();
                let replay = replay.clone(); let clock = clock.clone();
                connections.spawn(async move {
                    let socket = crate::adapter::tcp_stream_socket(&stream);
                    let tls_enabled = tls.is_some();
                    let stream: io::Result<Stream> = if let Some(tls) = tls {
                        let stream = tls.accept_stream(Box::new(stream)).await?;
                        Ok(Box::new(stream))
                    } else { Ok(Box::new(stream)) };
                    let stream = stream?;
                    let mut accepted = accept_transport_streams(
                        stream,
                        transport.as_ref(),
                        tls_enabled,
                    ).await?;
                    let mut logical_streams = JoinSet::new();
                    while let Some(stream) = accepted.recv().await {
                        let stream = crate::adapter::preserve_stream_socket(stream?, socket);
                        let tag = tag.clone(); let keys = keys.clone(); let alter_ids = alter_ids.clone(); let names = names.clone();
                        let router = router.clone(); let outbounds = outbounds.clone(); let replay = replay.clone(); let clock = clock.clone();
                        logical_streams.spawn(async move {
                            serve_stream(stream, source, &tag, &keys, &alter_ids, &names, &router, &outbounds, &replay, clock.as_ref(), udp_timeout, multiplex_enabled, multiplex_padding, multiplex_brutal).await
                        });
                    }
                    while logical_streams.join_next().await.is_some() {}
                    Ok::<_, io::Error>(())
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
async fn quic_accept_loop(
    endpoint: Endpoint,
    cancellation: CancellationToken,
    tag: String,
    keys: Vec<[u8; 16]>,
    alter_ids: Vec<Vec<[u8; 16]>>,
    names: Vec<String>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    replay: Arc<Mutex<HashMap<[u8; 16], Instant>>>,
    clock: Option<NtpClock>,
    udp_timeout: Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let tag = tag.clone(); let keys = keys.clone(); let alter_ids = alter_ids.clone(); let names = names.clone();
                let router = router.clone(); let outbounds = outbounds.clone(); let replay = replay.clone(); let clock = clock.clone();
                connections.spawn(async move {
                    let connection = incoming.await.map_err(io::Error::other)?;
                    let source = connection.remote_address();
                    let mut streams = JoinSet::new();
                    loop {
                        let (send, recv) = match connection.accept_bi().await {
                            Ok(stream) => stream,
                            Err(_) => break,
                        };
                        let stream = boxed_quic_stream(connection.clone(), send, recv);
                        let tag = tag.clone(); let keys = keys.clone(); let alter_ids = alter_ids.clone(); let names = names.clone();
                        let router = router.clone(); let outbounds = outbounds.clone(); let replay = replay.clone(); let clock = clock.clone();
                        streams.spawn(async move {
                            serve_stream(stream, source, &tag, &keys, &alter_ids, &names, &router, &outbounds, &replay, clock.as_ref(), udp_timeout, multiplex_enabled, multiplex_padding, multiplex_brutal).await
                        });
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
async fn serve_stream(
    mut stream: Stream,
    source: SocketAddr,
    tag: &str,
    keys: &[[u8; 16]],
    alter_ids: &[Vec<[u8; 16]>],
    names: &[String],
    router: &Arc<Router>,
    outbounds: &Arc<OutboundManager>,
    replay: &Mutex<HashMap<[u8; 16], Instant>>,
    clock: Option<&NtpClock>,
    udp_timeout: Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
) -> io::Result<()> {
    let socket = crate::adapter::stream_socket(&stream);
    let (request, user, auth) =
        read_request_with_clock(&mut stream, keys, alter_ids, clock).await?;
    if !request.legacy_header {
        check_replay(replay, auth).await?;
    }
    validate_request(&request)?;
    handle_connection(
        stream,
        source,
        tag,
        request,
        names[user].clone(),
        router,
        outbounds,
        udp_timeout,
        multiplex_enabled,
        multiplex_padding,
        multiplex_brutal,
        socket,
    )
    .await
}

async fn check_replay(
    replay: &Mutex<HashMap<[u8; 16], Instant>>,
    auth: [u8; 16],
) -> io::Result<()> {
    let mut replay = replay.lock().await;
    replay.retain(|_, seen| seen.elapsed() <= Duration::from_secs(120));
    if replay.insert(auth, Instant::now()).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "replayed VMess request",
        ));
    }
    Ok(())
}

fn validate_request(request: &RequestHeader) -> io::Result<()> {
    if !matches!(
        request.security,
        value if value == Security::None.wire()
            || value == Security::Legacy.wire()
            || value == Security::Aes128Gcm.wire()
            || value == Security::Chacha20Poly1305.wire()
    ) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this VMess body security is not ported yet",
        ));
    }
    let supported_options = OPTION_CHUNK_STREAM
        | crate::protocol::vmess::OPTION_CHUNK_MASKING
        | crate::protocol::vmess::OPTION_GLOBAL_PADDING
        | crate::protocol::vmess::OPTION_AUTHENTICATED_LENGTH;
    if request.option & !supported_options != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VMess request uses unsupported body options",
        ));
    }
    if request.security == Security::None.wire() {
        let expected_option = if request.command == Command::Udp {
            OPTION_CHUNK_STREAM
        } else {
            0
        };
        if request.option != expected_option {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported VMess none-security body framing",
            ));
        }
    } else if request.security == Security::Legacy.wire() {
        if request.option != OPTION_CHUNK_STREAM {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported VMess legacy body framing",
            ));
        }
    } else if request.option & OPTION_CHUNK_STREAM == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encrypted VMess body requires chunk stream framing",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut client: Stream,
    source: SocketAddr,
    tag: &str,
    request: RequestHeader,
    user: String,
    router: &Arc<Router>,
    outbounds: &Arc<OutboundManager>,
    udp_timeout: Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
    socket: Option<crate::adapter::StreamSocket>,
) -> io::Result<()> {
    match request.command {
        Command::Tcp => {
            let destination = request.destination.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VMess TCP request has no destination",
                )
            })?;
            if multiplex_enabled
                && crate::protocol::mux::is_destination(&destination)
            {
                write_response(&mut client, &request).await?;
                let client = wrap_body_stream(client, &request, true)?;
                let client =
                    crate::adapter::preserve_stream_socket(client, socket);
                return crate::protocol::mux::serve_routed_h2mux(
                    client,
                    source,
                    tag.to_owned(),
                    user,
                    router.clone(),
                    outbounds.clone(),
                    udp_timeout,
                    multiplex_padding,
                    multiplex_brutal,
                )
                .await;
            }
            proxy_tcp(
                client,
                source,
                tag,
                destination,
                user,
                request,
                router,
                outbounds,
            )
            .await
        }
        Command::Udp => {
            let destination = request.destination.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VMess UDP request has no destination",
                )
            })?;
            let packet: PacketStream = Box::new(VmessPacketConnection::new(
                client,
                request,
                destination.clone(),
                true,
            ));
            let packet = if crate::protocol::packetaddr::is_magic(&destination)
            {
                Box::new(
                    crate::protocol::packetaddr::PacketAddrConnection::new(
                        packet,
                    ),
                ) as PacketStream
            } else {
                packet
            };
            proxy_packet_connection(
                packet,
                source,
                tag,
                Some(user),
                router,
                outbounds,
                udp_timeout,
            )
            .await
        }
        Command::Mux => {
            write_response(&mut client, &request).await?;
            let client = wrap_body_stream(client, &request, true)?;
            crate::protocol::vmess_mux::serve_routed(
                client,
                None,
                source,
                tag.to_owned(),
                user,
                router.clone(),
                outbounds.clone(),
                udp_timeout,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn proxy_tcp(
    mut client: Stream,
    source: SocketAddr,
    tag: &str,
    destination: SocksAddr,
    user: String,
    request: RequestHeader,
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
        ..inherited_tcp_metadata(source, tag)
    };
    if let Some(injector) =
        prepare_tcp_inbound_detour(&mut metadata, outbounds)?
    {
        write_response(&mut client, &request).await?;
        let client = wrap_body_stream(client, &request, true)?;
        return injector
            .inject(client, TcpInboundContext { source, metadata })
            .await;
    }
    let mut route_state = router.route_state();
    let (decision, sniff_before_dial) = loop {
        let decision = router.route_next(&metadata, &mut route_state);
        match decision.action().cloned() {
            Some(Action::Resolve(options)) => {
                let effective_destination = metadata
                    .destination
                    .as_ref()
                    .map(|value| decision.destination(value));
                resolve_metadata(
                    &mut metadata,
                    effective_destination.as_ref(),
                    &options,
                    outbounds,
                )
                .await?;
            }
            Some(Action::Sniff(_)) => {
                // VMess clients wait for the authenticated response header
                // before accepting response data. Send it only when route
                // evaluation actually needs to inspect decoded payload.
                write_response(&mut client, &request).await?;
                let decoded = wrap_body_stream(client, &request, true)?;
                let (decoded, decision) = sniff_and_route_stream_from(
                    decoded,
                    &mut metadata,
                    router,
                    outbounds,
                    route_state,
                    Some(decision),
                )
                .await?;
                client = decoded;
                break (decision, true);
            }
            _ => break (decision, false),
        }
    };
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection rejected by route rule",
        ));
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        if !sniff_before_dial {
            write_response(&mut client, &request).await?;
            client = wrap_body_stream(client, &request, true)?;
        }
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
    if !sniff_before_dial {
        write_response(&mut client, &request).await?;
        client = wrap_body_stream(client, &request, true)?;
    }
    copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::VmessInbound;
    use crate::{
        adapter::Dialer,
        common::{
            lifecycle::{Lifecycle, StartStage},
            network::SocksAddr,
            tls::{ClientTlsDialer, build_client_config},
        },
        option::{Options, OutboundTlsOptions, VMessInboundOptions},
        outbound::OutboundManager,
        protocol::{
            direct::DirectOutbound,
            vmess::{VmessClientConfig, VmessOutbound},
        },
        route::Router,
        transport::v2ray::{
            GrpcDialer, HttpDialer, HttpUpgradeDialer, WebsocketDialer,
        },
    };
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    #[tokio::test]
    async fn proxies_none_security_tcp_and_udp_end_to_end() {
        proxies_security_tcp_and_udp_end_to_end("none", 0, false, false, "")
            .await;
    }

    #[tokio::test]
    async fn proxies_aes_security_tcp_and_udp_end_to_end() {
        proxies_security_tcp_and_udp_end_to_end(
            "aes-128-gcm",
            0,
            false,
            false,
            "",
        )
        .await;
    }

    #[tokio::test]
    async fn proxies_chacha_security_tcp_and_udp_end_to_end() {
        proxies_security_tcp_and_udp_end_to_end(
            "chacha20-poly1305",
            0,
            false,
            false,
            "",
        )
        .await;
    }

    #[tokio::test]
    async fn proxies_legacy_cfb_security_tcp_and_udp_end_to_end() {
        proxies_security_tcp_and_udp_end_to_end(
            "aes-128-cfb",
            0,
            false,
            false,
            "",
        )
        .await;
    }

    #[tokio::test]
    async fn proxies_global_padding_and_authenticated_length_end_to_end() {
        proxies_security_tcp_and_udp_end_to_end(
            "aes-128-gcm",
            0,
            true,
            true,
            "",
        )
        .await;
    }

    #[tokio::test]
    async fn proxies_legacy_alter_id_header_end_to_end() {
        proxies_security_tcp_and_udp_end_to_end("auto", 1, false, false, "")
            .await;
    }

    #[tokio::test]
    async fn proxies_packetaddr_udp_end_to_end() {
        proxies_security_tcp_and_udp_end_to_end(
            "auto",
            0,
            false,
            false,
            "packetaddr",
        )
        .await;
    }

    #[tokio::test]
    async fn proxies_xudp_end_to_end() {
        proxies_security_tcp_and_udp_end_to_end(
            "auto", 0, false, false, "xudp",
        )
        .await;
    }

    #[tokio::test]
    async fn proxies_websocket_transport_end_to_end() {
        proxies_security_with_transport_tcp_and_udp_end_to_end(
            "auto",
            0,
            false,
            false,
            "",
            Some("ws"),
        )
        .await;
    }

    #[tokio::test]
    async fn proxies_websocket_early_data_end_to_end() {
        proxies_security_with_transport_tcp_and_udp_end_to_end(
            "auto",
            0,
            false,
            false,
            "",
            Some("ws-early"),
        )
        .await;
    }

    #[tokio::test]
    async fn proxies_http_upgrade_transport_end_to_end() {
        proxies_security_with_transport_tcp_and_udp_end_to_end(
            "auto",
            0,
            false,
            false,
            "",
            Some("httpupgrade"),
        )
        .await;
    }

    #[tokio::test]
    async fn proxies_http_transport_end_to_end() {
        proxies_security_with_transport_tcp_and_udp_end_to_end(
            "auto",
            0,
            false,
            false,
            "",
            Some("http"),
        )
        .await;
    }

    #[tokio::test]
    async fn proxies_http2_tls_transport_end_to_end() {
        proxies_security_with_transport_tcp_and_udp_end_to_end(
            "auto",
            0,
            false,
            false,
            "",
            Some("http2"),
        )
        .await;
    }

    #[tokio::test]
    async fn proxies_grpc_transport_end_to_end() {
        proxies_security_with_transport_tcp_and_udp_end_to_end(
            "auto",
            0,
            false,
            false,
            "",
            Some("grpc"),
        )
        .await;
    }

    #[tokio::test]
    async fn proxies_quic_transport_end_to_end() {
        proxies_security_with_transport_tcp_and_udp_end_to_end(
            "auto",
            0,
            false,
            false,
            "",
            Some("quic"),
        )
        .await;
    }

    async fn proxies_security_tcp_and_udp_end_to_end(
        security: &str,
        alter_id: i32,
        global_padding: bool,
        authenticated_length: bool,
        packet_encoding: &str,
    ) {
        proxies_security_with_transport_tcp_and_udp_end_to_end(
            security,
            alter_id,
            global_padding,
            authenticated_length,
            packet_encoding,
            None,
        )
        .await;
    }

    async fn proxies_security_with_transport_tcp_and_udp_end_to_end(
        security: &str,
        alter_id: i32,
        global_padding: bool,
        authenticated_length: bool,
        packet_encoding: &str,
        transport: Option<&str>,
    ) {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_destination = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut data = [0; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut data = [0; 16];
            let (size, source) = udp_target.recv_from(&mut data).await.unwrap();
            udp_target.send_to(&data[..size], source).await.unwrap();
        });
        let user = "00112233-4455-6677-8899-aabbccddeeff";
        let tls = if matches!(transport, Some("http2" | "quic")) {
            let CertifiedKey { cert, key_pair } =
                generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            Some(json!({
                "enabled":true,
                "certificate":cert.pem(),
                "key":key_pair.serialize_pem(),
                "alpn":[if transport == Some("quic") { "h3" } else { "h2" }]
            }))
        } else {
            None
        };
        let options: VMessInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1", "listen_port":0, "udp_timeout":"5s",
            "users":[{"name":"alice", "uuid":user, "alterId":alter_id}],
            "tls":tls,
            "transport": transport.map(|transport| match transport {
                "ws-early" => json!({
                    "type":"ws",
                    "path":"/vmess",
                    "max_early_data":2048,
                    "early_data_header_name":"Sec-WebSocket-Protocol"
                }),
                "grpc" => json!({
                    "type":"grpc",
                    "service_name":"VMessService"
                }),
                "http2" => json!({"type":"http","path":"/vmess"}),
                "quic" => json!({"type":"quic"}),
                transport => json!({"type":transport,"path":"/vmess"}),
            })
        }))
        .unwrap();
        let runtime_options: Options = serde_json::from_value(json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds":[{"type":"direct","tag":"direct"}]
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&runtime_options, "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound =
            VmessInbound::new("vmess", options, router, outbounds).unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let server_address = inbound.local_addr().unwrap();
        let server = SocksAddr::from(server_address);
        let direct: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(Default::default()));
        let upstream: Arc<dyn Dialer> = match transport {
            Some("ws") => Arc::new(
                WebsocketDialer::new(
                    direct,
                    server.clone(),
                    serde_json::from_value(json!({"path":"/vmess"})).unwrap(),
                )
                .unwrap(),
            ),
            Some("ws-early") => Arc::new(
                WebsocketDialer::new(
                    direct,
                    server.clone(),
                    serde_json::from_value(json!({
                        "path":"/vmess",
                        "max_early_data":2048,
                        "early_data_header_name":"Sec-WebSocket-Protocol"
                    }))
                    .unwrap(),
                )
                .unwrap(),
            ),
            Some("httpupgrade") => Arc::new(
                HttpUpgradeDialer::new(
                    direct,
                    server.clone(),
                    serde_json::from_value(json!({"path":"/vmess"})).unwrap(),
                )
                .unwrap(),
            ),
            Some("http") => Arc::new(
                HttpDialer::new(
                    direct,
                    server.clone(),
                    serde_json::from_value(json!({"path":"/vmess"})).unwrap(),
                )
                .unwrap(),
            ),
            Some("http2") => {
                let tls = build_client_config(
                    "localhost",
                    &OutboundTlsOptions {
                        enabled: true,
                        insecure: true,
                        ..Default::default()
                    },
                    &["h2"],
                )
                .unwrap();
                let tls: Arc<dyn Dialer> =
                    Arc::new(ClientTlsDialer::new(direct, tls));
                Arc::new(
                    HttpDialer::new_http2(
                        tls,
                        server.clone(),
                        serde_json::from_value(json!({"path":"/vmess"}))
                            .unwrap(),
                    )
                    .unwrap(),
                )
            }
            Some("grpc") => Arc::new(
                GrpcDialer::new(
                    direct,
                    server.clone(),
                    serde_json::from_value(json!({
                        "service_name":"VMessService"
                    }))
                    .unwrap(),
                )
                .unwrap(),
            ),
            Some("quic") => direct,
            None => direct,
            Some(transport) => {
                panic!("unsupported test transport: {transport}")
            }
        };
        let client: Arc<dyn Dialer> = if transport == Some("quic") {
            let client_options: Options = serde_json::from_value(json!({
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "outbounds":[
                    {"type":"direct","tag":"quic-underlay","connect_timeout":"5s"},
                    {
                        "type":"vmess",
                        "tag":"vmess-client",
                        "server":server_address.ip().to_string(),
                        "server_port":server_address.port(),
                        "uuid":user,
                        "security":security,
                        "detour":"quic-underlay",
                        "tls":{
                            "enabled":true,
                            "server_name":"localhost",
                            "insecure":true
                        },
                        "transport":{"type":"quic"}
                    }
                ]
            }))
            .unwrap();
            OutboundManager::from_options(&client_options, "vmess-client")
                .unwrap()
                .select(Some("vmess-client"))
                .unwrap()
        } else {
            Arc::new(
                VmessOutbound::new(
                    upstream,
                    server,
                    user,
                    VmessClientConfig {
                        security,
                        alter_id,
                        global_padding,
                        authenticated_length,
                        packet_encoding,
                    },
                )
                .unwrap(),
            )
        };
        let mut tcp = client.dial_tcp(&tcp_destination.into()).await.unwrap();
        tcp.write_all(b"ping").await.unwrap();
        let mut response = [0; 16];
        tcp.read_exact(&mut response[..4]).await.unwrap();
        assert_eq!(&response[..4], b"ping");
        let packet = client.listen_udp(&udp_destination.into()).await.unwrap();
        packet
            .send_to(b"datagram", &SocksAddr::from(udp_destination))
            .await
            .unwrap();
        let (size, source) = packet.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"datagram");
        assert_eq!(source, SocksAddr::from(udp_destination));
        inbound.close().await.unwrap();
        tcp_echo.await.unwrap();
        udp_echo.await.unwrap();
    }
}
