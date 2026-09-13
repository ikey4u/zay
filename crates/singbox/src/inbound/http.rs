//! HTTP CONNECT TCP inbound.

use std::{
    convert::Infallible,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode, Uri, Version,
    body::Incoming,
    client::conn::http1 as client_http1,
    header::{CONNECTION, HOST, HeaderMap, PROXY_AUTHENTICATE, UPGRADE},
    server::conn::http1 as server_http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{
        AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader, copy_bidirectional,
    },
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::Stream,
    common::{
        certificate_store::CertificateStore,
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::Network,
        ntp::NtpClock,
        system_proxy::SystemProxyLease,
        tls::build_server_config,
    },
    inbound::{
        TcpInboundContext, TcpInboundInjector, TcpInjectFuture,
        inherited_tcp_metadata, prepare_tcp_inbound_detour,
        serve_hijacked_dns_stream_with_context, sniff_and_route_stream,
        socks::restore_fake_ip, with_tcp_inbound_context,
    },
    option::HttpMixedInboundOptions,
    outbound::OutboundManager,
    protocol::http::authenticate_basic,
    route::{Action, Metadata, Router},
};

pub struct HttpInbound {
    name: String,
    tag: String,
    options: HttpMixedInboundOptions,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    mixed: bool,
    local_addr: Option<SocketAddr>,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
    system_proxy: Option<SystemProxyLease>,
}

/// HTTP/mixed protocol handler for an already accepted TCP stream.
///
/// This is the Rust equivalent of sing-box's `TCPInjectableInbound` and is
/// used by listener detours such as ShadowTLS. It owns no listener or task
/// lifecycle because the outer inbound owns the physical socket.
#[derive(Clone)]
pub struct HttpTcpInjector {
    tag: String,
    users: Vec<crate::option::User>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    mixed: bool,
    tls: Option<crate::common::tls::ServerTlsConfig>,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
}

impl HttpTcpInjector {
    pub fn new(
        tag: impl Into<String>,
        options: HttpMixedInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, crate::common::tls::TlsError> {
        Self::new_with_runtime_context(
            tag, options, router, outbounds, false, None, None,
        )
    }

    pub fn new_mixed(
        tag: impl Into<String>,
        options: HttpMixedInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, crate::common::tls::TlsError> {
        Self::new_with_runtime_context(
            tag, options, router, outbounds, true, None, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_runtime_context(
        tag: impl Into<String>,
        options: HttpMixedInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        mixed: bool,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<CertificateStore>,
    ) -> Result<Self, crate::common::tls::TlsError> {
        let tls = options
            .tls
            .as_ref()
            .filter(|tls| tls.enabled)
            .map(build_server_config)
            .transpose()?;
        let udp_timeout = options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        Ok(Self {
            tag: tag.into(),
            users: options.users,
            router,
            outbounds,
            udp_timeout,
            mixed,
            tls,
            ntp_clock,
            certificate_store,
        })
    }
}

impl TcpInboundInjector for HttpTcpInjector {
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
            if let Some(tls) = &self.tls {
                let stream = tls.accept_stream(stream).await?;
                dispatch(
                    stream,
                    local_ip,
                    source,
                    self.tag.clone(),
                    self.users.clone(),
                    self.router.clone(),
                    self.outbounds.clone(),
                    self.udp_timeout,
                    self.mixed,
                    self.ntp_clock.clone(),
                    self.certificate_store.clone(),
                )
                .await
            } else {
                dispatch(
                    stream,
                    local_ip,
                    source,
                    self.tag.clone(),
                    self.users.clone(),
                    self.router.clone(),
                    self.outbounds.clone(),
                    self.udp_timeout,
                    self.mixed,
                    self.ntp_clock.clone(),
                    self.certificate_store.clone(),
                )
                .await
            }
        }))
    }
}

impl HttpInbound {
    pub fn new(
        tag: impl Into<String>,
        options: HttpMixedInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Self {
        Self::new_with_runtime_context(
            tag, options, router, outbounds, None, None,
        )
    }

    pub(crate) fn new_with_runtime_context(
        tag: impl Into<String>,
        options: HttpMixedInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<CertificateStore>,
    ) -> Self {
        let tag = tag.into();
        Self {
            name: format!("inbound/http[{tag}]"),
            tag,
            options,
            router,
            outbounds,
            cancellation: CancellationToken::new(),
            task: None,
            mixed: false,
            local_addr: None,
            ntp_clock,
            certificate_store,
            system_proxy: None,
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn new_mixed(
        tag: impl Into<String>,
        options: HttpMixedInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Self {
        Self::new_mixed_with_runtime_context(
            tag, options, router, outbounds, None, None,
        )
    }

    pub(crate) fn new_mixed_with_runtime_context(
        tag: impl Into<String>,
        options: HttpMixedInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<CertificateStore>,
    ) -> Self {
        let mut inbound = Self::new_with_runtime_context(
            tag,
            options,
            router,
            outbounds,
            ntp_clock,
            certificate_store,
        );
        inbound.name = format!("inbound/mixed[{}]", inbound.tag);
        inbound.mixed = true;
        inbound
    }

    async fn bind(&mut self) -> io::Result<()> {
        let tls = self
            .options
            .tls
            .as_ref()
            .filter(|tls| tls.enabled)
            .map(build_server_config)
            .transpose()
            .map_err(io::Error::other)?;
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
        if self.options.set_system_proxy {
            let local_addr = listener.local_addr()?;
            self.system_proxy = Some(
                SystemProxyLease::enable(
                    system_proxy_server_address(ip, local_addr),
                    self.mixed,
                )
                .await
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("initialize system proxy: {error}"),
                    )
                })?,
            );
        }
        let cancellation = self.cancellation.clone();
        let tag = self.tag.clone();
        let users = self.options.users.clone();
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        let mixed = self.mixed;
        let ntp_clock = self.ntp_clock.clone();
        let certificate_store = self.certificate_store.clone();
        let udp_timeout = self
            .options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        self.task = Some(tokio::spawn(async move {
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
                        let tls = tls.clone();
                        let ntp_clock = ntp_clock.clone();
                        let certificate_store = certificate_store.clone();
                        connections.spawn(async move {
                            let result = if let Some(tls) = tls {
                                let stream = tls.accept_stream(Box::new(stream)).await;
                                match stream {
                                    Ok(stream) => dispatch(
                                        stream, local_ip, source, tag, users, router,
                                        outbounds, udp_timeout, mixed,
                                        ntp_clock, certificate_store,
                                    ).await,
                                    Err(error) => Err(error),
                                }
                            } else {
                                dispatch(
                                    stream, local_ip, source, tag, users, router,
                                    outbounds, udp_timeout, mixed,
                                    ntp_clock, certificate_store,
                                ).await
                            };
                            let _ = result;
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            Ok(())
        }));
        Ok(())
    }
}

fn system_proxy_server_address(
    configured_ip: IpAddr,
    bound: SocketAddr,
) -> SocketAddr {
    let address = if configured_ip.is_unspecified() {
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    } else {
        configured_ip
    };
    SocketAddr::new(address, bound.port())
}

impl Lifecycle for HttpInbound {
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
            let mut failures = Vec::new();
            if let Some(mut system_proxy) = self.system_proxy.take()
                && let Err(error) = system_proxy.close().await
            {
                failures.push(format!("disable system proxy: {error}"));
            }
            self.cancellation.cancel();
            if let Some(task) = self.task.take() {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        failures.push(error.to_string());
                    }
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => {
                        failures.push(error.to_string());
                    }
                }
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(LifecycleError::Close {
                    component: self.name.clone(),
                    message: failures.join("; "),
                })
            }
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch<S>(
    stream: S,
    local_ip: IpAddr,
    source: SocketAddr,
    tag: String,
    users: Vec<crate::option::User>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    mixed: bool,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !mixed {
        return handle(
            stream,
            source,
            tag,
            users,
            router,
            outbounds,
            udp_timeout,
            ntp_clock,
            certificate_store,
        )
        .await;
    }
    let mut stream = BufReader::new(stream);
    let first = stream.fill_buf().await?;
    if first.first().is_some_and(|byte| matches!(byte, 4 | 5)) {
        crate::inbound::socks::handle_connection(
            stream,
            local_ip,
            source,
            &tag,
            &users,
            &router,
            &outbounds,
            udp_timeout,
        )
        .await
    } else {
        handle(
            stream,
            source,
            tag,
            users,
            router,
            outbounds,
            udp_timeout,
            ntp_clock,
            certificate_store,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle<S>(
    client: S,
    source: SocketAddr,
    tag: String,
    users: Vec<crate::option::User>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    server_http1::Builder::new()
        .keep_alive(true)
        .serve_connection(
            TokioIo::new(client),
            service_fn(move |request| {
                proxy_request(
                    request,
                    source,
                    tag.clone(),
                    users.clone(),
                    router.clone(),
                    outbounds.clone(),
                    udp_timeout,
                    ntp_clock.clone(),
                    certificate_store.clone(),
                )
            }),
        )
        .with_upgrades()
        .await
        .map_err(io::Error::other)
}

type ProxyBody = BoxBody<Bytes, hyper::Error>;

#[allow(clippy::too_many_arguments)]
async fn proxy_request(
    mut request: Request<Incoming>,
    source: SocketAddr,
    tag: String,
    users: Vec<crate::option::User>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
) -> Result<Response<ProxyBody>, Infallible> {
    let keep_alive = proxy_keep_alive(&request);
    let user = if users.is_empty() {
        None
    } else {
        let authorization = request
            .headers()
            .get("proxy-authorization")
            .and_then(|value| value.to_str().ok());
        match authenticate_basic(authorization, &users) {
            Some(user) => Some(user),
            None => {
                let mut response = status_response(
                    StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                    "proxy authentication required",
                );
                response.headers_mut().insert(
                    PROXY_AUTHENTICATE,
                    "Basic realm=\"sing-box\" charset=\"UTF-8\""
                        .parse()
                        .expect("static header"),
                );
                if !keep_alive {
                    response.headers_mut().insert(
                        CONNECTION,
                        "close".parse().expect("static header"),
                    );
                }
                return Ok(response);
            }
        }
    };
    let source = forwarded_source(&request, source);
    let destination = match request_destination(&request) {
        Ok(destination) => destination,
        Err(error) => {
            return Ok(status_response(
                StatusCode::BAD_REQUEST,
                error.to_string(),
            ));
        }
    };
    if request.method() == Method::CONNECT
        && let Some(version) =
            crate::protocol::uot::destination_version(&destination)
    {
        let upgraded = hyper::upgrade::on(&mut request);
        tokio::spawn(async move {
            let Ok(upgraded) = upgraded.await else {
                return;
            };
            let stream =
                Box::new(TokioIo::new(upgraded)) as crate::adapter::Stream;
            let Ok(connection) =
                crate::protocol::uot::accept(stream, version).await
            else {
                return;
            };
            let _ = crate::inbound::socks::proxy_packet_connection(
                Box::new(connection),
                source,
                &tag,
                user,
                &router,
                &outbounds,
                udp_timeout,
            )
            .await;
        });
        return Ok(status_response(StatusCode::OK, Bytes::new()));
    }
    if request.method() == Method::CONNECT {
        let upgraded = hyper::upgrade::on(&mut request);
        let context = TcpInboundContext {
            source,
            metadata: inherited_tcp_metadata(source, &tag),
        };
        tokio::spawn(with_tcp_inbound_context(context, async move {
            let Ok(upgraded) = upgraded.await else {
                return;
            };
            let client = Box::new(TokioIo::new(upgraded)) as Stream;
            let _ = proxy_connect_tunnel(
                client,
                destination,
                source,
                &tag,
                user.as_deref(),
                &router,
                &outbounds,
            )
            .await;
        }));
        return Ok(status_response(StatusCode::OK, Bytes::new()));
    }
    let mut remote = match route_and_dial(
        &destination,
        source,
        &tag,
        user.as_deref(),
        &router,
        &outbounds,
    )
    .await
    {
        Ok(remote) => remote,
        Err(error) => {
            let status = if error.kind() == io::ErrorKind::PermissionDenied {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::BAD_GATEWAY
            };
            return Ok(status_response(status, error.to_string()));
        }
    };

    if request.uri().scheme_str() == Some("https") {
        let mut tls_options = crate::option::OutboundTlsOptions {
            enabled: true,
            ..Default::default()
        };
        tls_options.set_runtime_context(ntp_clock, certificate_store);
        let tls = match crate::common::tls::build_client_config(
            &destination.host(),
            &tls_options,
            &["http/1.1"],
        ) {
            Ok(tls) => tls,
            Err(error) => {
                return Ok(status_response(
                    StatusCode::BAD_GATEWAY,
                    error.to_string(),
                ));
            }
        };
        remote = match tls.connect_stream(remote).await {
            Ok(stream) => stream.into_stream(),
            Err(error) => {
                return Ok(status_response(
                    StatusCode::BAD_GATEWAY,
                    error.to_string(),
                ));
            }
        };
    }

    let upgrade_requested = is_upgrade(request.headers());
    let client_upgrade =
        upgrade_requested.then(|| hyper::upgrade::on(&mut request));
    remove_hop_by_hop_headers(request.headers_mut(), upgrade_requested);
    request.headers_mut().remove("proxy-authorization");
    normalize_http_host(request.headers_mut());
    let origin_uri = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    *request.uri_mut() = origin_uri
        .parse::<Uri>()
        .unwrap_or_else(|_| Uri::from_static("/"));

    let (mut sender, connection) =
        match client_http1::handshake(TokioIo::new(remote)).await {
            Ok(value) => value,
            Err(error) => {
                return Ok(status_response(
                    StatusCode::BAD_GATEWAY,
                    error.to_string(),
                ));
            }
        };
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let mut response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            return Ok(status_response(
                StatusCode::BAD_GATEWAY,
                error.to_string(),
            ));
        }
    };
    let upgrade_accepted = upgrade_requested
        && response.status() == StatusCode::SWITCHING_PROTOCOLS;
    if upgrade_accepted {
        let server_upgrade = hyper::upgrade::on(&mut response);
        let client_upgrade = client_upgrade.expect("upgrade requested");
        tokio::spawn(async move {
            if let (Ok(client), Ok(server)) =
                (client_upgrade.await, server_upgrade.await)
            {
                let mut client = TokioIo::new(client);
                let mut server = TokioIo::new(server);
                let _ = copy_bidirectional(&mut client, &mut server).await;
            }
        });
    } else {
        remove_hop_by_hop_headers(response.headers_mut(), false);
        if keep_alive {
            response.headers_mut().insert(
                "proxy-connection",
                "keep-alive".parse().expect("static header"),
            );
            response.headers_mut().insert(
                CONNECTION,
                "keep-alive".parse().expect("static header"),
            );
            response.headers_mut().insert(
                "keep-alive",
                "timeout=4".parse().expect("static header"),
            );
        } else {
            response
                .headers_mut()
                .insert(CONNECTION, "close".parse().expect("static header"));
        }
    }
    Ok(response.map(|body| body.boxed()))
}

fn request_destination(
    request: &Request<Incoming>,
) -> io::Result<crate::common::network::SocksAddr> {
    let authority = request.uri().authority().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP proxy request has no authority",
        )
    })?;
    let port = authority.port_u16().unwrap_or_else(|| {
        if request.uri().scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });
    Ok(crate::common::network::SocksAddr::new(
        authority.host(),
        port,
    ))
}

async fn route_and_dial(
    original_destination: &crate::common::network::SocksAddr,
    source: SocketAddr,
    tag: &str,
    user: Option<&str>,
    router: &Router,
    outbounds: &OutboundManager,
) -> io::Result<crate::adapter::Stream> {
    let destination = match original_destination {
        crate::common::network::SocksAddr::Ip(address)
            if outbounds.dns().is_fake_ip(address.ip()) =>
        {
            let domain = outbounds
                .dns()
                .fake_ip_domain(address.ip())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "missing fakeip record",
                    )
                })?;
            crate::common::network::SocksAddr::new(domain, address.port())
        }
        _ => original_destination.clone(),
    };
    let fake_ip = destination != *original_destination;
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination.clone()),
        origin_destination: fake_ip.then(|| original_destination.clone()),
        fake_ip,
        network: Some(Network::Tcp),
        protocol: "http".into(),
        user: user.unwrap_or_default().to_owned(),
        ..inherited_tcp_metadata(source, tag)
    };
    if let Some(injector) =
        prepare_tcp_inbound_detour(&mut metadata, outbounds)?
    {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = injector
                .inject(
                    Box::new(server),
                    TcpInboundContext { source, metadata },
                )
                .await;
        });
        return Ok(Box::new(client));
    }
    let mut route_state = router.route_state();
    let decision = loop {
        let decision = router.route_next(&metadata, &mut route_state);
        match decision.action().cloned() {
            // The HTTP request has already supplied protocol/domain metadata,
            // so route_next normally skips sniff itself. Keep this branch for
            // parity with Go's ordered action loop if metadata evolves.
            Some(Action::Sniff(_)) => continue,
            Some(Action::Resolve(options)) => {
                let routed = metadata
                    .destination
                    .as_ref()
                    .map(|value| decision.destination(value));
                super::resolve_metadata(
                    &mut metadata,
                    routed.as_ref(),
                    &options,
                    outbounds,
                )
                .await?;
            }
            _ => break decision,
        }
    };
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "rejected by route rule",
        ));
    }
    let routed_destination = decision
        .destination(metadata.destination.as_ref().unwrap_or(&destination));
    let connection_options = decision.connection_options();
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })?
    };
    let remote = dialer
        .dial_tcp_with_options(&routed_destination, &connection_options.network)
        .await?;
    super::apply_routed_tcp_options(remote, &connection_options)
}

#[allow(clippy::too_many_arguments)]
async fn proxy_connect_tunnel(
    client: Stream,
    original_destination: crate::common::network::SocksAddr,
    source: SocketAddr,
    tag: &str,
    user: Option<&str>,
    router: &Router,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let (destination, origin_destination) =
        restore_fake_ip(original_destination, outbounds)?;
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination.clone()),
        origin_destination: origin_destination.clone(),
        fake_ip: origin_destination.is_some(),
        network: Some(Network::Tcp),
        user: user.unwrap_or_default().to_owned(),
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
            "rejected by route rule",
        ));
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
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

fn is_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        && headers.contains_key(UPGRADE)
}

fn proxy_keep_alive<B>(request: &Request<B>) -> bool {
    request.version() != Version::HTTP_10
        && request
            .headers()
            .get("proxy-connection")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.trim().eq_ignore_ascii_case("keep-alive")
            })
}

fn forwarded_source<B>(request: &Request<B>, source: SocketAddr) -> SocketAddr {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .find_map(|address| address.parse::<IpAddr>().ok())
        })
        .map_or(source, |address| SocketAddr::new(address, source.port()))
}

fn normalize_http_host(headers: &mut HeaderMap) {
    let Some(authority) = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<hyper::http::uri::Authority>().ok())
    else {
        return;
    };
    if authority.port_u16() != Some(80) {
        return;
    }
    let host = authority.host();
    let normalized = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if let Ok(normalized) = normalized.parse() {
        headers.insert(HOST, normalized);
    }
}

fn remove_hop_by_hop_headers(headers: &mut HeaderMap, preserve_upgrade: bool) {
    let named = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(|value| {
            hyper::header::HeaderName::from_bytes(value.as_bytes()).ok()
        })
        .collect::<Vec<_>>();
    for name in named {
        if !preserve_upgrade || name != UPGRADE {
            headers.remove(name);
        }
    }
    for name in [
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
    ] {
        headers.remove(name);
    }
    if !preserve_upgrade {
        headers.remove(CONNECTION);
        headers.remove(UPGRADE);
    }
}

fn status_response(
    status: StatusCode,
    body: impl Into<Bytes>,
) -> Response<ProxyBody> {
    let body = Full::new(body.into())
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .body(body)
        .expect("valid static response")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream},
    };
    use tokio_rustls::TlsConnector;

    use super::{
        HttpInbound, HttpTcpInjector, forwarded_source, normalize_http_host,
        proxy_keep_alive, route_and_dial, system_proxy_server_address,
    };
    use crate::{
        common::{
            lifecycle::{Lifecycle, StartStage},
            tls::build_client_config,
        },
        inbound::{TcpInboundContext, TcpInboundInjector},
        option::{HttpMixedInboundOptions, Options, OutboundTlsOptions},
        outbound::OutboundManager,
        protocol::{
            http::client_handshake,
            uot::{
                MAGIC_ADDRESS, Request as UotRequest, UotPacketConnection,
                write_request as write_uot_request,
            },
        },
        route::Router,
    };

    #[test]
    fn system_proxy_uses_loopback_for_unspecified_listener_and_bound_port() {
        assert_eq!(
            system_proxy_server_address(
                "::".parse().unwrap(),
                "[::]:49152".parse().unwrap(),
            ),
            "127.0.0.1:49152".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(
            system_proxy_server_address(
                "192.0.2.3".parse().unwrap(),
                "192.0.2.3:49153".parse().unwrap(),
            ),
            "192.0.2.3:49153".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn forward_dial_runs_resolve_before_terminal_cidr_rule() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let options: Options = serde_json::from_value(json!({
            "dns": {"servers": [{
                "type":"hosts",
                "tag":"route-dns",
                "predefined":{"forward.origin":"127.0.0.1"}
            }]},
            "outbounds": [
                {
                    "type":"direct",
                    "tag":"direct",
                    "domain_resolver":"route-dns"
                },
                {"type":"block", "tag":"block"}
            ]
        }))
        .unwrap();
        let outbounds =
            OutboundManager::from_options(&options, "block").unwrap();
        let router = Router::from_json(
            &[
                json!({
                    "domain":"forward.origin",
                    "action":"resolve",
                    "server":"route-dns"
                }),
                json!({"ip_cidr":"127.0.0.0/8", "outbound":"direct"}),
            ],
            "block",
        )
        .unwrap();
        let mut stream = route_and_dial(
            &crate::common::network::SocksAddr::new(
                "forward.origin",
                target_port,
            ),
            "127.0.0.1:50000".parse().unwrap(),
            "http-resolve",
            None,
            &router,
            &outbounds,
        )
        .await
        .unwrap();
        stream.write_all(b"http").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"http");
        echo.await.unwrap();
    }

    #[test]
    fn honors_forwarded_source_and_upstream_keep_alive_rules() {
        let source = "127.0.0.1:1234".parse().unwrap();
        let request = hyper::Request::builder()
            .header("x-forwarded-for", "invalid,203.0.113.9")
            .header("proxy-connection", " Keep-Alive ")
            .body(())
            .unwrap();
        assert_eq!(
            forwarded_source(&request, source),
            "203.0.113.9:1234".parse::<std::net::SocketAddr>().unwrap()
        );
        assert!(proxy_keep_alive(&request));

        let request = hyper::Request::builder()
            .version(hyper::Version::HTTP_10)
            .header("proxy-connection", "keep-alive")
            .body(())
            .unwrap();
        assert!(!proxy_keep_alive(&request));
    }

    #[test]
    fn strips_only_the_default_http_port_from_host() {
        let mut headers = hyper::HeaderMap::new();
        headers
            .insert(hyper::header::HOST, "[2001:db8::1]:80".parse().unwrap());
        normalize_http_host(&mut headers);
        assert_eq!(headers[hyper::header::HOST], "[2001:db8::1]");

        headers
            .insert(hyper::header::HOST, "example.com:8080".parse().unwrap());
        normalize_http_host(&mut headers);
        assert_eq!(headers[hyper::header::HOST], "example.com:8080");
    }

    #[tokio::test]
    async fn injected_http_and_mixed_connect_proxy_end_to_end() {
        for mixed in [false, true] {
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_address = target.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut bytes = [0_u8; 4];
                stream.read_exact(&mut bytes).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
            });
            let outbounds = Arc::new(
                OutboundManager::from_options(&Options::default(), "").unwrap(),
            );
            let router = Arc::new(Router::from_json(&[], "").unwrap());
            let injector = HttpTcpInjector::new_with_runtime_context(
                if mixed { "mixed" } else { "http" },
                HttpMixedInboundOptions::default(),
                router,
                outbounds,
                mixed,
                None,
                None,
            )
            .unwrap();
            let (mut client, server) = tokio::io::duplex(16 * 1024);
            let injected = tokio::spawn(async move {
                injector
                    .inject(
                        Box::new(server),
                        TcpInboundContext::accepted(
                            "127.0.0.1:12345".parse().unwrap(),
                            "outer",
                        ),
                    )
                    .await
            });

            client_handshake(
                &mut client,
                &target_address.into(),
                None,
                "",
                &serde_json::Map::new(),
            )
            .await
            .unwrap();
            client.write_all(b"ping").await.unwrap();
            let mut bytes = [0_u8; 4];
            client.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            client.shutdown().await.unwrap();
            injected.await.unwrap().unwrap();
            echo.await.unwrap();
        }
    }

    #[tokio::test]
    async fn injected_http_applies_the_detour_tls_layer() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let options: HttpMixedInboundOptions = serde_json::from_value(json!({
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
        let injector = HttpTcpInjector::new_with_runtime_context(
            "http", options, router, outbounds, false, None, None,
        )
        .unwrap();
        let (client, server) = tokio::io::duplex(16 * 1024);
        let injected = tokio::spawn(async move {
            injector
                .inject(
                    Box::new(server),
                    TcpInboundContext::accepted(
                        "127.0.0.1:12345".parse().unwrap(),
                        "outer",
                    ),
                )
                .await
        });
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let mut client = TlsConnector::from(tls.config)
            .connect(tls.server_name, client)
            .await
            .unwrap();
        client_handshake(
            &mut client,
            &target_address.into(),
            None,
            "",
            &serde_json::Map::new(),
        )
        .await
        .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut bytes = [0_u8; 4];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
        client.shutdown().await.unwrap();
        injected.await.unwrap().unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn tls_http_connect_inbound_proxies_end_to_end() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let options: HttpMixedInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0,
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
        let mut inbound = HttpInbound::new("tls", options, router, outbounds);
        inbound.start(StartStage::Start).await.unwrap();

        let tcp = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let mut client = TlsConnector::from(tls.config)
            .connect(tls.server_name, tcp)
            .await
            .unwrap();
        client_handshake(
            &mut client,
            &target_address.into(),
            None,
            "",
            &serde_json::Map::new(),
        )
        .await
        .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut bytes = [0_u8; 4];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
        inbound.close().await.unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn forwards_http_requests_bodies_and_keep_alive() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            for index in 0..2 {
                let (stream, _) = origin.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut header = Vec::new();
                loop {
                    let mut line = Vec::new();
                    stream.read_until(b'\n', &mut line).await.unwrap();
                    header.extend_from_slice(&line);
                    if line == b"\r\n" {
                        break;
                    }
                }
                let header = String::from_utf8(header).unwrap();
                assert!(!header.to_ascii_lowercase().contains("proxy-"));
                assert!(!header.to_ascii_lowercase().contains("x-hop:"));
                if index == 0 {
                    assert!(
                        header.starts_with("POST /upload?x=1 HTTP/1.1\r\n")
                    );
                    let mut body = [0_u8; 4];
                    stream.read_exact(&mut body).await.unwrap();
                    assert_eq!(&body, b"body");
                } else {
                    assert!(header.starts_with("GET /next HTTP/1.1\r\n"));
                }
                stream
                    .get_mut()
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            }
        });
        let options: HttpMixedInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound = HttpInbound::new("http", options, router, outbounds);
        inbound.start(StartStage::Start).await.unwrap();
        let stream = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        let mut client = BufReader::new(stream);

        client
            .get_mut()
            .write_all(
                format!(
                    "POST http://{origin_address}/upload?x=1 HTTP/1.1\r\nHost: {origin_address}\r\nContent-Length: 4\r\nProxy-Connection: keep-alive\r\nConnection: X-Hop\r\nX-Hop: secret\r\n\r\nbody"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert_eq!(read_response_body(&mut client).await, b"ok");
        client
            .get_mut()
            .write_all(
                format!(
                    "GET http://{origin_address}/next HTTP/1.1\r\nHost: {origin_address}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert_eq!(read_response_body(&mut client).await, b"ok");

        inbound.close().await.unwrap();
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn forwards_http_upgrade_and_tunnels_after_101() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut header = String::new();
            loop {
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
                header.push_str(&line);
            }
            assert!(header.starts_with("GET /socket HTTP/1.1\r\n"));
            assert!(header.to_ascii_lowercase().contains("upgrade: test"));
            stream
                .get_mut()
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n",
                )
                .await
                .unwrap();
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.get_mut().write_all(&bytes).await.unwrap();
        });
        let options: HttpMixedInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound = HttpInbound::new("http", options, router, outbounds);
        inbound.start(StartStage::Start).await.unwrap();
        let stream = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        let mut client = BufReader::new(stream);
        client
            .get_mut()
            .write_all(
                format!(
                    "GET http://{origin_address}/socket HTTP/1.1\r\nHost: {origin_address}\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut status = String::new();
        client.read_line(&mut status).await.unwrap();
        assert!(status.contains("101"));
        loop {
            let mut line = String::new();
            client.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
        }
        client.get_mut().write_all(b"ping").await.unwrap();
        let mut bytes = [0_u8; 4];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
        inbound.close().await.unwrap();
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn absolute_https_requests_start_origin_tls() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut record_header = [0_u8; 5];
            stream.read_exact(&mut record_header).await.unwrap();
            assert_eq!(record_header[0], 0x16, "expected TLS handshake record");
            assert_eq!(&record_header[1..3], &[0x03, 0x01]);
        });
        let options: HttpMixedInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound = HttpInbound::new("http", options, router, outbounds);
        inbound.start(StartStage::Start).await.unwrap();
        let mut client = BufReader::new(
            TcpStream::connect(inbound.local_addr().unwrap())
                .await
                .unwrap(),
        );
        client
            .get_mut()
            .write_all(
                format!(
                    "GET https://{origin_address}/secure HTTP/1.1\r\nHost: {origin_address}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut status = String::new();
        client.read_line(&mut status).await.unwrap();
        assert!(status.contains("502"), "unexpected status: {status}");
        inbound.close().await.unwrap();
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn accepts_udp_over_tcp_via_http_connect() {
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut bytes = [0_u8; 16];
            let (size, source) = target.recv_from(&mut bytes).await.unwrap();
            target.send_to(&bytes[..size], source).await.unwrap();
        });
        let options: HttpMixedInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0,
            "udp_timeout":"5s"
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound = HttpInbound::new("http", options, router, outbounds);
        inbound.start(StartStage::Start).await.unwrap();
        let mut client = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        client_handshake(
            &mut client,
            &crate::common::network::SocksAddr::new(MAGIC_ADDRESS, 0),
            None,
            "",
            &serde_json::Map::new(),
        )
        .await
        .unwrap();
        let request = UotRequest {
            is_connect: false,
            destination: target_address.into(),
        };
        write_uot_request(&mut client, &request).await.unwrap();
        let connection = UotPacketConnection::new(Box::new(client), request);
        crate::adapter::PacketConnection::send_to(
            &connection,
            b"uot",
            &target_address.into(),
        )
        .await
        .unwrap();
        let mut bytes = [0_u8; 16];
        let (size, source) = crate::adapter::PacketConnection::recv_from(
            &connection,
            &mut bytes,
        )
        .await
        .unwrap();
        assert_eq!(source, target_address.into());
        assert_eq!(&bytes[..size], b"uot");
        inbound.close().await.unwrap();
        echo.await.unwrap();
    }

    async fn read_response_body(stream: &mut BufReader<TcpStream>) -> Vec<u8> {
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert!(!line.is_empty());
            if line == "\r\n" {
                break;
            }
            if let Some(value) =
                line.to_ascii_lowercase().strip_prefix("content-length:")
            {
                content_length = value.trim().parse().unwrap();
            }
        }
        let mut body = vec![0_u8; content_length];
        stream.read_exact(&mut body).await.unwrap();
        body
    }
}
