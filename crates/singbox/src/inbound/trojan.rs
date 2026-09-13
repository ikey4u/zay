//! Trojan TCP inbound with optional TLS and native TCP/UDP routing.

use std::{
    collections::HashMap,
    io::{self, Cursor},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf, copy_bidirectional},
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{PacketStream, Stream},
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::{Network, SocksAddr},
        tls::{
            ServerTlsConfig, TlsError,
            build_server_config_with_default_alpn_and_reality_dialer,
        },
    },
    inbound::{
        TcpInboundContext, TcpInboundInjector, TcpInjectFuture,
        inherited_tcp_metadata, prepare_tcp_inbound_detour,
        serve_hijacked_dns_stream_with_context, sniff_and_route_stream,
        socks::{proxy_packet_connection, restore_fake_ip},
        with_tcp_inbound_context,
    },
    option::{TrojanInboundOptions, V2RayTransportOptions},
    outbound::OutboundManager,
    protocol::trojan::{
        COMMAND_TCP, COMMAND_UDP, Command, RequestError,
        TrojanPacketConnection, key, read_request_with_fallback,
    },
    route::{Action, Metadata, Router},
    transport::{
        quic::{
            StreamHandler as QuicStreamHandler,
            accept_loop as quic_accept_loop, server_endpoint,
        },
        v2ray::{
            accept_transport_streams, tls_alpn, validate_server_transport,
        },
    },
};

#[derive(Debug, thiserror::Error)]
pub enum TrojanInboundError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("unsupported Trojan inbound functionality: {0}")]
    Unsupported(String),
    #[error("duplicate Trojan password for users {first} and {second}")]
    DuplicatePassword { first: usize, second: usize },
}

pub struct TrojanInbound {
    name: String,
    tag: String,
    options: TrojanInboundOptions,
    keys: Vec<[u8; 56]>,
    tls: Option<ServerTlsConfig>,
    transport: Option<V2RayTransportOptions>,
    fallback: Option<SocksAddr>,
    fallback_for_alpn: HashMap<String, SocksAddr>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

#[derive(Clone)]
pub struct TrojanTcpInjector {
    tag: String,
    keys: Vec<[u8; 56]>,
    users: Vec<crate::option::TrojanUser>,
    fallback: Option<SocksAddr>,
    fallback_for_alpn: HashMap<String, SocksAddr>,
    tls: Option<ServerTlsConfig>,
    transport: Option<V2RayTransportOptions>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
}

impl TrojanTcpInjector {
    pub fn new(
        tag: impl Into<String>,
        options: TrojanInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, TrojanInboundError> {
        let inbound = TrojanInbound::new(tag, options, router, outbounds)?;
        let multiplex_brutal = crate::protocol::mux::server_brutal_options(
            inbound
                .options
                .multiplex
                .as_ref()
                .filter(|multiplex| multiplex.enabled)
                .and_then(|multiplex| multiplex.brutal.as_ref()),
        )
        .map_err(|error| TrojanInboundError::Unsupported(error.to_string()))?;
        Ok(Self {
            tag: inbound.tag,
            keys: inbound.keys,
            users: inbound.options.users,
            fallback: inbound.fallback,
            fallback_for_alpn: inbound.fallback_for_alpn,
            tls: inbound.tls,
            transport: inbound.transport,
            router: inbound.router,
            outbounds: inbound.outbounds,
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

impl TcpInboundInjector for TrojanTcpInjector {
    fn inject<'a>(
        &'a self,
        stream: Stream,
        context: TcpInboundContext,
    ) -> TcpInjectFuture<'a> {
        let source = context.source;
        Box::pin(with_tcp_inbound_context(context, async move {
            let mut negotiated_alpn = None;
            let stream = match self.tls.clone() {
                Some(tls) if self.transport.is_none() => {
                    let stream = tls.accept_stream(stream).await?;
                    negotiated_alpn = stream.alpn_protocol().map(|value| {
                        String::from_utf8_lossy(value).into_owned()
                    });
                    Box::new(stream)
                }
                _ => stream,
            };
            handle_connection(
                stream,
                source,
                &self.tag,
                &self.keys,
                &self.users,
                &self.router,
                &self.outbounds,
                self.udp_timeout,
                self.multiplex_enabled,
                self.multiplex_padding,
                self.multiplex_brutal,
                self.fallback.clone(),
                self.fallback_for_alpn.clone(),
                negotiated_alpn.as_deref(),
            )
            .await
        }))
    }
}

fn build_fallback(
    options: &crate::option::ServerOptions,
) -> Result<SocksAddr, TrojanInboundError> {
    if options.server.is_empty() || options.server_port == 0 {
        return Err(TrojanInboundError::Unsupported(
            "fallback requires a non-empty server and port".into(),
        ));
    }
    Ok(SocksAddr::new(options.server.clone(), options.server_port))
}

struct ReplayStream {
    prefix: Cursor<Vec<u8>>,
    inner: Stream,
}

/// `smux` unnecessarily requires the transport itself to be `Sync` even
/// though it splits all I/O into one reader and one writer task. Serializing
/// individual poll calls lets every singbox `Stream` satisfy that bound while
/// retaining concurrent read/write progress.
struct SyncStream(StdMutex<Stream>);

impl SyncStream {
    fn new(stream: Stream) -> Self {
        Self(StdMutex::new(stream))
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, Stream>> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("smux transport lock poisoned"))
    }
}

impl AsyncRead for SyncStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut stream = match self.lock() {
            Ok(stream) => stream,
            Err(error) => return Poll::Ready(Err(error)),
        };
        Pin::new(&mut **stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for SyncStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut stream = match self.lock() {
            Ok(stream) => stream,
            Err(error) => return Poll::Ready(Err(error)),
        };
        Pin::new(&mut **stream).poll_write(context, data)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let mut stream = match self.lock() {
            Ok(stream) => stream,
            Err(error) => return Poll::Ready(Err(error)),
        };
        Pin::new(&mut **stream).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let mut stream = match self.lock() {
            Ok(stream) => stream,
            Err(error) => return Poll::Ready(Err(error)),
        };
        Pin::new(&mut **stream).poll_shutdown(context)
    }
}

impl AsyncRead for ReplayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            return Pin::new(&mut self.prefix).poll_read(context, buffer);
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for ReplayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, data)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl TrojanInbound {
    pub fn new(
        tag: impl Into<String>,
        options: TrojanInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, TrojanInboundError> {
        let transport = options.transport.clone();
        if let Some(transport) = transport.as_ref() {
            validate_server_transport(transport).map_err(|error| {
                TrojanInboundError::Unsupported(error.to_string())
            })?;
        }
        if matches!(transport, Some(V2RayTransportOptions::Quic))
            && !options.tls.as_ref().is_some_and(|tls| tls.enabled)
        {
            return Err(TrojanInboundError::Unsupported(
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
        .map_err(|error| TrojanInboundError::Unsupported(error.to_string()))?;
        let fallback = options
            .fallback
            .as_ref()
            .filter(|fallback| !fallback.server.is_empty())
            .map(build_fallback)
            .transpose()?;
        if !options.fallback_for_alpn.is_empty()
            && !options.tls.as_ref().is_some_and(|tls| tls.enabled)
        {
            return Err(TrojanInboundError::Unsupported(
                "fallback_for_alpn requires TLS".into(),
            ));
        }
        let fallback_for_alpn = options
            .fallback_for_alpn
            .iter()
            .map(|(alpn, fallback)| {
                Ok((alpn.clone(), build_fallback(fallback)?))
            })
            .collect::<Result<_, TrojanInboundError>>()?;
        let keys: Vec<_> = options
            .users
            .iter()
            .map(|user| key(&user.password))
            .collect();
        for second in 0..keys.len() {
            if let Some(first) = keys[..second]
                .iter()
                .position(|candidate| candidate == &keys[second])
            {
                return Err(TrojanInboundError::DuplicatePassword {
                    first,
                    second,
                });
            }
        }
        let reality_dialer = options
            .tls
            .as_ref()
            .and_then(|tls| tls.reality.as_ref())
            .filter(|reality| reality.enabled)
            .map(|reality| {
                outbounds.endpoint_dialer(
                    "inbound/trojan/reality",
                    &reality.handshake.dialer,
                )
            })
            .transpose()
            .map_err(|error| {
                TrojanInboundError::Tls(TlsError::Unsupported(
                    error.to_string(),
                ))
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
            name: format!("inbound/trojan[{tag}]"),
            tag,
            options,
            keys,
            tls,
            transport,
            fallback,
            fallback_for_alpn,
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
        let ip = self
            .options
            .listen
            .listen
            .map(|address| address.0)
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        let bind_address = SocketAddr::new(ip, self.options.listen.listen_port);
        let cancellation = self.cancellation.clone();
        let tag = self.tag.clone();
        let keys = self.keys.clone();
        let users = self.options.users.clone();
        let tls = self.tls.clone();
        let transport = self.transport.clone();
        let fallback = self.fallback.clone();
        let fallback_for_alpn = self.fallback_for_alpn.clone();
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
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
        let udp_timeout = self
            .options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        if matches!(transport, Some(V2RayTransportOptions::Quic)) {
            let endpoint = server_endpoint(
                tls.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "QUIC requires TLS",
                    )
                })?,
                bind_address,
            )?;
            self.local_addr = Some(endpoint.local_addr()?);
            let handler: QuicStreamHandler = Arc::new(move |stream, source| {
                let tag = tag.clone();
                let keys = keys.clone();
                let users = users.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                let fallback = fallback.clone();
                let fallback_for_alpn = fallback_for_alpn.clone();
                Box::pin(async move {
                    let _ = handle_connection(
                        stream,
                        source,
                        &tag,
                        &keys,
                        &users,
                        &router,
                        &outbounds,
                        udp_timeout,
                        multiplex_enabled,
                        multiplex_padding,
                        multiplex_brutal,
                        fallback,
                        fallback_for_alpn,
                        None,
                    )
                    .await;
                })
            });
            self.task = Some(tokio::spawn(quic_accept_loop(
                endpoint,
                cancellation,
                handler,
            )));
        } else {
            let listener = crate::common::socket::bind_tcp_listener(
                bind_address,
                &self.options.listen,
            )
            .await?;
            self.local_addr = Some(listener.local_addr()?);
            self.task = Some(tokio::spawn(async move {
                accept_loop(
                    listener,
                    cancellation,
                    tag,
                    keys,
                    users,
                    tls,
                    transport,
                    router,
                    outbounds,
                    udp_timeout,
                    multiplex_enabled,
                    multiplex_padding,
                    multiplex_brutal,
                    fallback,
                    fallback_for_alpn,
                )
                .await
            }));
        }
        Ok(())
    }
}

impl Lifecycle for TrojanInbound {
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
    keys: Vec<[u8; 56]>,
    users: Vec<crate::option::TrojanUser>,
    tls: Option<ServerTlsConfig>,
    transport: Option<V2RayTransportOptions>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
    fallback: Option<SocksAddr>,
    fallback_for_alpn: HashMap<String, SocksAddr>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            result = listener.accept() => {
                let (stream, source) = result?;
                let tag = tag.clone();
                let keys = keys.clone();
                let users = users.clone();
                let tls = tls.clone();
                let transport = transport.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                let fallback = fallback.clone();
                let fallback_for_alpn = fallback_for_alpn.clone();
                connections.spawn(async move {
                    let socket = crate::adapter::tcp_stream_socket(&stream);
                    let tls_enabled = tls.is_some();
                    let mut negotiated_alpn = None;
                    let stream: io::Result<Stream> = if let Some(tls) = tls {
                        let stream = tls.accept_stream(Box::new(stream)).await?;
                        negotiated_alpn = stream
                            .alpn_protocol()
                            .map(|value| String::from_utf8_lossy(value).into_owned());
                        Ok(Box::new(stream))
                    } else {
                        Ok(Box::new(stream))
                    };
                    if let Ok(stream) = stream {
                        let mut accepted = accept_transport_streams(
                            stream,
                            transport.as_ref(),
                            tls_enabled,
                        ).await?;
                        let mut logical_streams = JoinSet::new();
                        while let Some(stream) = accepted.recv().await {
                            let stream = crate::adapter::preserve_stream_socket(stream?, socket);
                            let tag = tag.clone(); let keys = keys.clone(); let users = users.clone();
                            let router = router.clone(); let outbounds = outbounds.clone();
                            let fallback = fallback.clone(); let fallback_for_alpn = fallback_for_alpn.clone();
                            let negotiated_alpn = negotiated_alpn.clone();
                            logical_streams.spawn(async move {
                                let _ = handle_connection(
                                    stream,
                                    source,
                                    &tag,
                                    &keys,
                                    &users,
                                    &router,
                                    &outbounds,
                                    udp_timeout,
                                    multiplex_enabled,
                                    multiplex_padding,
                                    multiplex_brutal,
                                    fallback,
                                    fallback_for_alpn,
                                    negotiated_alpn.as_deref(),
                                )
                                .await;
                            });
                        }
                        while logical_streams.join_next().await.is_some() {}
                    }
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
async fn handle_connection(
    mut client: Stream,
    source: SocketAddr,
    tag: &str,
    keys: &[[u8; 56]],
    users: &[crate::option::TrojanUser],
    router: &Arc<Router>,
    outbounds: &Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
    fallback: Option<SocksAddr>,
    fallback_for_alpn: HashMap<String, SocksAddr>,
    negotiated_alpn: Option<&str>,
) -> io::Result<()> {
    let socket = crate::adapter::stream_socket(&client);
    let request = match read_request_with_fallback(&mut client, keys).await {
        Ok(request) => request,
        Err(RequestError::Io(error)) => return Err(error),
        Err(RequestError::InvalidPassword(presented)) => {
            let destination = if !fallback_for_alpn.is_empty()
                && negotiated_alpn.is_some_and(|alpn| !alpn.is_empty())
            {
                negotiated_alpn
                    .and_then(|alpn| fallback_for_alpn.get(alpn))
                    .cloned()
            } else {
                fallback
            }
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "invalid Trojan password and fallback is disabled",
                )
            })?;
            let replay: Stream = Box::new(ReplayStream {
                prefix: Cursor::new(presented),
                inner: client,
            });
            return proxy_tcp(
                replay,
                source,
                tag,
                destination,
                String::new(),
                router,
                outbounds,
            )
            .await;
        }
    };
    let user = users
        .get(request.user)
        .map(|user| user.name.clone())
        .unwrap_or_default();
    match request.command {
        Command::Tcp => {
            if multiplex_enabled
                && crate::protocol::mux::is_destination(&request.destination)
            {
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
                request.destination,
                user,
                router,
                outbounds,
            )
            .await
        }
        Command::Udp => {
            let packet: PacketStream =
                Box::new(TrojanPacketConnection::new(client));
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
            serve_trojan_mux(
                client,
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

async fn serve_trojan_mux(
    client: Stream,
    source: SocketAddr,
    tag: String,
    user: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    // Go's MaxFrameSize counts payload bytes while this crate counts the
    // complete frame, including the eight-byte wire header.
    let config = smux::Config {
        enable_keep_alive: false,
        max_frame_size: 32 * 1024 + 8,
        ..Default::default()
    };
    let session = smux::Session::server(SyncStream::new(client), config)
        .await
        .map_err(io::Error::other)?;
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            result = session.accept_stream() => {
                let stream = result.map_err(io::Error::other)?;
                let tag = tag.clone();
                let user = user.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                connections.spawn(async move {
                    let _ = handle_trojan_mux_stream(
                        stream,
                        source,
                        tag,
                        user,
                        router,
                        outbounds,
                        udp_timeout,
                    )
                    .await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn handle_trojan_mux_stream(
    mut client: smux::Stream,
    source: SocketAddr,
    tag: String,
    user: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let command = client.read_u8().await?;
    let destination = crate::protocol::socks::read_address(&mut client).await?;
    match command {
        COMMAND_TCP => {
            proxy_tcp(
                Box::new(client),
                source,
                &tag,
                destination,
                user,
                &router,
                &outbounds,
            )
            .await
        }
        COMMAND_UDP => {
            let packet: PacketStream =
                Box::new(TrojanPacketConnection::new(Box::new(client)));
            proxy_packet_connection(
                packet,
                source,
                &tag,
                Some(user),
                &router,
                &outbounds,
                udp_timeout,
            )
            .await
        }
        command => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown Trojan-Go mux command: {command}"),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn proxy_tcp(
    client: Stream,
    source: SocketAddr,
    tag: &str,
    destination: crate::common::network::SocksAddr,
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
        ..inherited_tcp_metadata(source, tag)
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
        net::{TcpListener, TcpStream, UdpSocket},
        time::{Duration, timeout},
    };
    use tokio_rustls::TlsConnector;

    use super::TrojanInbound;
    use crate::{
        adapter::{Dialer, PacketConnection, Stream},
        common::{
            lifecycle::{Lifecycle, StartStage},
            network::SocksAddr,
            tls::build_client_config,
        },
        option::{Options, OutboundTlsOptions, TrojanInboundOptions},
        outbound::OutboundManager,
        protocol::{
            direct::DirectOutbound,
            socks::write_address,
            trojan::{
                COMMAND_TCP, COMMAND_UDP, Command, TrojanOutbound,
                TrojanPacketConnection, key, write_request,
            },
        },
        route::Router,
        transport::quic::QuicDialer,
    };

    #[tokio::test]
    async fn replays_invalid_authentication_bytes_to_fallback() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback = target.local_addr().unwrap();
        let payload = b"GET / HTTP/1.0\r\n\r\n";
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut received = vec![0_u8; payload.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, payload);
            stream.write_all(b"fallback-ok").await.unwrap();
        });
        let options: crate::option::TrojanInboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "users":[{"name":"","password":"valid-password"}],
                "fallback":{
                    "server":fallback.ip().to_string(),
                    "server_port":fallback.port()
                }
            }))
            .unwrap();
        let runtime_options: crate::option::Options =
            serde_json::from_value(json!({
                "outbounds":[{"type":"direct","tag":"direct"}]
            }))
            .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&runtime_options, "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "direct").unwrap());
        let mut inbound =
            TrojanInbound::new("trojan", options, router, outbounds).unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let mut stream = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        stream.write_all(payload).await.unwrap();
        let mut response = [0_u8; 11];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"fallback-ok");
        inbound.close().await.unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn selects_tls_fallback_by_negotiated_alpn() {
        let default_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let default_fallback = default_target.local_addr().unwrap();
        let h2_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let h2_fallback = h2_target.local_addr().unwrap();
        let payload = b"GET / HTTP/1.0\r\n\r\n";
        let h2_echo = tokio::spawn(async move {
            let (mut stream, _) = h2_target.accept().await.unwrap();
            let mut received = vec![0_u8; payload.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, payload);
            stream.write_all(b"h2-fallback").await.unwrap();
        });
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let options: TrojanInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0,
            "users":[{"name":"","password":"valid-password"}],
            "tls":{
                "enabled":true,
                "certificate":cert.pem(),
                "key":key_pair.serialize_pem(),
                "alpn":["h2","http/1.1"]
            },
            "fallback":{
                "server":default_fallback.ip().to_string(),
                "server_port":default_fallback.port()
            },
            "fallback_for_alpn":{
                "h2":{
                    "server":h2_fallback.ip().to_string(),
                    "server_port":h2_fallback.port()
                }
            }
        }))
        .unwrap();
        let runtime_options: Options = serde_json::from_value(json!({
            "outbounds":[{"type":"direct","tag":"direct"}]
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&runtime_options, "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "direct").unwrap());
        let mut inbound =
            TrojanInbound::new("trojan", options, router, outbounds).unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let server = inbound.local_addr().unwrap();

        let tcp = TcpStream::connect(server).await.unwrap();
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &["h2"],
        )
        .unwrap();
        let mut client = TlsConnector::from(tls.config)
            .connect(tls.server_name, tcp)
            .await
            .unwrap();
        client.write_all(payload).await.unwrap();
        let mut response = [0_u8; 11];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"h2-fallback");
        h2_echo.await.unwrap();

        let tcp = TcpStream::connect(server).await.unwrap();
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &["http/1.1"],
        )
        .unwrap();
        let mut client = TlsConnector::from(tls.config)
            .connect(tls.server_name, tcp)
            .await
            .unwrap();
        client.write_all(payload).await.unwrap();
        let mut byte = [0_u8; 1];
        let closed = timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("unmapped ALPN connection did not close");
        assert!(matches!(closed, Err(_) | Ok(0)));
        assert!(
            timeout(Duration::from_millis(100), default_target.accept())
                .await
                .is_err(),
            "default fallback must not be selected for an unmapped ALPN"
        );

        inbound.close().await.unwrap();
    }

    #[tokio::test]
    async fn accepts_trojan_go_smux_tcp_stream() {
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
            let mut payload = [0_u8; 16];
            let (size, source) =
                udp_target.recv_from(&mut payload).await.unwrap();
            udp_target.send_to(&payload[..size], source).await.unwrap();
        });
        let options: TrojanInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0,
            "users":[{"name":"alice","password":"secret"}]
        }))
        .unwrap();
        let runtime_options: Options = serde_json::from_value(json!({
            "outbounds":[{"type":"direct","tag":"direct"}]
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&runtime_options, "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "direct").unwrap());
        let mut inbound =
            TrojanInbound::new("trojan", options, router, outbounds).unwrap();
        inbound.start(StartStage::Start).await.unwrap();

        let mut transport = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        write_request(
            &mut transport,
            &key("secret"),
            Command::Mux,
            &SocksAddr::new("0.0.0.0", 0),
        )
        .await
        .unwrap();
        let config = smux::Config {
            enable_keep_alive: false,
            max_frame_size: 32 * 1024 + 8,
            ..Default::default()
        };
        let session = smux::Session::client(transport, config).await.unwrap();
        let mut stream = session.open_stream().await.unwrap();
        stream.write_u8(COMMAND_TCP).await.unwrap();
        write_address(&mut stream, &destination.into())
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");

        let mut udp_stream = session.open_stream().await.unwrap();
        udp_stream.write_u8(COMMAND_UDP).await.unwrap();
        write_address(&mut udp_stream, &SocksAddr::new("0.0.0.0", 0))
            .await
            .unwrap();
        let packet =
            TrojanPacketConnection::new(Box::new(udp_stream) as Stream);
        packet
            .send_to(b"datagram", &udp_destination.into())
            .await
            .unwrap();
        let mut response = [0_u8; 16];
        let (size, source) = packet.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"datagram");
        assert_eq!(source, udp_destination.into());

        stream.shutdown().await.unwrap();
        session.close().await.unwrap();
        inbound.close().await.unwrap();
        echo.await.unwrap();
        udp_echo.await.unwrap();
    }

    #[tokio::test]
    async fn proxies_authenticated_tcp_and_udp_end_to_end() {
        proxies_authenticated_tcp_and_udp(None).await;
    }

    #[tokio::test]
    async fn proxies_quic_tcp_and_udp_end_to_end() {
        proxies_authenticated_tcp_and_udp(Some("quic")).await;
    }

    async fn proxies_authenticated_tcp_and_udp(transport: Option<&str>) {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_destination = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut data = [0_u8; 16];
            let (size, source) = udp_target.recv_from(&mut data).await.unwrap();
            udp_target.send_to(&data[..size], source).await.unwrap();
        });
        let tls = if transport == Some("quic") {
            let CertifiedKey { cert, key_pair } =
                generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            Some(json!({
                "enabled":true,
                "certificate":cert.pem(),
                "key":key_pair.serialize_pem(),
                "alpn":["h3"]
            }))
        } else {
            None
        };
        let options: TrojanInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0,
            "udp_timeout":"5s",
            "users":[{"name":"alice","password":"secret"}],
            "tls":tls,
            "transport":transport.map(|_| json!({"type":"quic"}))
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
            TrojanInbound::new("trojan", options, router, outbounds).unwrap();
        inbound.start(StartStage::Start).await.unwrap();

        let server = inbound.local_addr().unwrap();
        let upstream: Arc<dyn Dialer> = if transport == Some("quic") {
            Arc::new(
                QuicDialer::new(
                    server.into(),
                    "localhost",
                    build_client_config(
                        "localhost",
                        &OutboundTlsOptions {
                            enabled: true,
                            insecure: true,
                            ..Default::default()
                        },
                        &["h3"],
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
        } else {
            Arc::new(DirectOutbound::new(Default::default()))
        };
        let client = TrojanOutbound::new(upstream, server.into(), "secret");
        let mut tcp = client.dial_tcp(&tcp_destination.into()).await.unwrap();
        tcp.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        tcp.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");

        let packet = client.listen_udp(&udp_destination.into()).await.unwrap();
        packet
            .send_to(b"datagram", &udp_destination.into())
            .await
            .unwrap();
        let mut response = [0_u8; 16];
        let (size, source) = packet.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"datagram");
        assert_eq!(source, SocksAddr::from(udp_destination));

        inbound.close().await.unwrap();
        tcp_echo.await.unwrap();
        udp_echo.await.unwrap();
    }
}
