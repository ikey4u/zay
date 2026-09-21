//! Hysteria2 HTTP/3 and TCP stream inbound.

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use quinn::{AsyncUdpSocket, Runtime as _};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::Stream,
    common::{
        certificate_store::CertificateStore,
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::{Network, SocksAddr},
        ntp::NtpClock,
        sniff::{SniffError, sniff_stream},
        tls::{
            TlsError, build_client_config,
            build_server_config_with_default_alpn,
        },
    },
    inbound::{
        PacketDestinationNat, TcpInboundContext,
        hijack_dns_packet_with_context, prepare_tcp_inbound_detour,
        resolve_metadata, serve_hijacked_dns_stream_with_context,
        sniff_and_route_packet, socks::restore_fake_ip,
    },
    option::{
        Hysteria2InboundOptions, Hysteria2Masquerade,
        Hysteria2MasqueradeObject, Hysteria2Obfs,
    },
    outbound::OutboundManager,
    protocol::{
        hysteria::HysteriaBrutalServerConfig,
        hysteria2::{
            Hysteria2MasqueradeHandler, Hysteria2MasqueradeResponse,
            Hysteria2ObfsConfig, Hysteria2QuicOptions, Hysteria2ServerSession,
            Hysteria2TcpStream, UdpDefragmenter, UdpMessage,
            encode_tcp_response, fragment_udp_message,
            hysteria2_server_endpoint_with_transport_obfs,
            hysteria2_server_endpoint_with_transport_obfs_socket,
            server_brutal_bps,
        },
        hysteria2_realm::{
            RealmControlClient, RealmPacketSocket, RealmPortMappingOptions,
            RealmServerConnector,
        },
    },
    route::{Action, Metadata, Router},
};

#[derive(Debug, thiserror::Error)]
pub enum Hysteria2InboundError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("invalid Hysteria2 inbound configuration: {0}")]
    Config(String),
}

pub struct Hysteria2Inbound {
    name: String,
    tag: String,
    options: Hysteria2InboundOptions,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    masquerade: Option<Hysteria2MasqueradeHandler>,
    realm: Option<RealmServerConnector>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

impl Hysteria2Inbound {
    pub fn new(
        tag: impl Into<String>,
        options: Hysteria2InboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, Hysteria2InboundError> {
        Self::new_in(tag, options, router, outbounds, Path::new("."))
    }

    pub fn new_in(
        tag: impl Into<String>,
        options: Hysteria2InboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        base_path: &Path,
    ) -> Result<Self, Hysteria2InboundError> {
        Self::new_in_with_runtime_context(
            tag, options, router, outbounds, base_path, None, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_in_with_runtime_context(
        tag: impl Into<String>,
        options: Hysteria2InboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        base_path: &Path,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<CertificateStore>,
    ) -> Result<Self, Hysteria2InboundError> {
        if options.users.is_empty() {
            return Err(Hysteria2InboundError::Config("missing users".into()));
        }
        if options.tls.as_ref().is_none_or(|tls| !tls.enabled) {
            return Err(Hysteria2InboundError::Config(
                "TLS is required".into(),
            ));
        }
        build_obfs_config(options.obfs.as_ref())?;
        crate::protocol::quic_bbr::BbrProfile::parse(&options.bbr_profile)
            .map_err(|error| {
                Hysteria2InboundError::Config(error.to_string())
            })?;
        let masquerade = build_masquerade_with_runtime_context(
            options.masquerade.as_ref(),
            base_path,
            ntp_clock.clone(),
            certificate_store.clone(),
        )?;
        let realm = options
            .realm
            .as_ref()
            .map(|realm| {
                if realm.ip_version != 0
                    && let Some(listen) = options.listen.listen
                    && ((realm.ip_version == 6 && listen.0.is_ipv4())
                        || (realm.ip_version == 4
                            && listen.0.is_ipv6()
                            && !listen.0.is_unspecified()))
                {
                    return Err(Hysteria2InboundError::Config(format!(
                        "realm.ip_version {} conflicts with listen address {}",
                        realm.ip_version, listen.0
                    )));
                }
                let mut http_options =
                    realm.http_client.clone().unwrap_or_default();
                http_options
                    .tls
                    .get_or_insert_with(Default::default)
                    .set_runtime_context(
                        ntp_clock.clone(),
                        certificate_store.clone(),
                    );
                let http_dialer = outbounds
                    .http_client_dialer(&http_options.dialer, false)
                    .map_err(|error| {
                        Hysteria2InboundError::Config(format!(
                            "Realm HTTP dialer: {error}"
                        ))
                    })?;
                let control = RealmControlClient::new_with_dialer(
                    realm.server_url.clone(),
                    realm.token.clone(),
                    http_dialer,
                    http_options,
                    ntp_clock.clone(),
                )
                .map_err(|error| {
                    Hysteria2InboundError::Config(error.to_string())
                })?;
                let mut connector = RealmServerConnector::new(
                    control,
                    realm.realm_id.clone(),
                    realm.stun_servers.0.clone(),
                    realm.ip_version,
                )
                .map_err(|error| {
                    Hysteria2InboundError::Config(error.to_string())
                })?;
                if let Some(mapping) = realm
                    .port_mapping
                    .as_ref()
                    .filter(|mapping| mapping.enabled)
                {
                    connector = connector
                        .with_port_mapping(RealmPortMappingOptions::new(
                            mapping.timeout.as_std(),
                            mapping.lifetime.as_std(),
                        ))
                        .map_err(|error| {
                            Hysteria2InboundError::Config(error.to_string())
                        })?;
                }
                let (resolver, lookup_options) =
                    match realm.stun_domain_resolver.as_ref() {
                        Some(options) => {
                            let resolver = outbounds
                            .dns()
                            .resolver(&options.server)
                            .ok_or_else(|| {
                                Hysteria2InboundError::Config(format!(
                                    "Realm STUN domain resolver {:?} not found",
                                    options.server
                                ))
                            })?;
                            (
                                resolver,
                                crate::dns::LookupOptions {
                                    strategy: options.strategy,
                                    timeout: options
                                        .timeout
                                        .as_std()
                                        .filter(|duration| !duration.is_zero()),
                                    disable_cache: options.disable_cache,
                                    disable_optimistic_cache: options
                                        .disable_optimistic_cache,
                                    rewrite_ttl: options.rewrite_ttl,
                                    client_subnet: options
                                        .client_subnet
                                        .as_ref()
                                        .map(|prefix| prefix.0),
                                    ..Default::default()
                                },
                            )
                        }
                        None => (
                            outbounds.dns().default(),
                            crate::dns::LookupOptions::default(),
                        ),
                    };
                connector = connector.with_resolver(resolver, lookup_options);
                Ok(connector)
            })
            .transpose()?;
        let tag = tag.into();
        Ok(Self {
            name: format!("inbound/hysteria2[{tag}]"),
            tag,
            options,
            router,
            outbounds,
            masquerade,
            realm,
            cancellation: CancellationToken::new(),
            task: None,
            local_addr: None,
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    async fn bind(&mut self) -> io::Result<()> {
        let tls_options = self.options.tls.as_ref().expect("validated TLS");
        let tls = build_server_config_with_default_alpn(tls_options, &["h3"])
            .map_err(io::Error::other)?;
        let mut listen_ip = self
            .options
            .listen
            .listen
            .map(|address| address.0)
            .unwrap_or(std::net::Ipv6Addr::UNSPECIFIED.into());
        if self
            .realm
            .as_ref()
            .is_some_and(|realm| !realm.uses_ipv6_socket())
            && listen_ip.is_ipv6()
            && listen_ip.is_unspecified()
        {
            listen_ip = std::net::Ipv4Addr::UNSPECIFIED.into();
        }
        let address =
            SocketAddr::new(listen_ip, self.options.listen.listen_port);
        let send_bps =
            u64::try_from(self.options.up_mbps.max(0)).unwrap() * 125_000;
        let receive_bps =
            u64::try_from(self.options.down_mbps.max(0)).unwrap() * 125_000;
        let bbr_profile = crate::protocol::quic_bbr::BbrProfile::parse(
            &self.options.bbr_profile,
        )
        .map_err(io::Error::other)?;
        let server_brutal = Arc::new(HysteriaBrutalServerConfig::with_profile(
            0,
            self.options.brutal_debug,
            bbr_profile,
        ));
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
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "negative max_concurrent_streams",
                )
            })?,
            initial_packet_size: u64::try_from(
                self.options.quic.initial_packet_size,
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "negative initial_packet_size",
                )
            })?,
            disable_path_mtu_discovery: self
                .options
                .quic
                .disable_path_mtu_discovery,
        }
        .build()?;
        transport.congestion_controller_factory(server_brutal.clone());
        let transport = Arc::new(transport);
        let obfs =
            build_obfs_config(self.options.obfs.as_ref()).map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
            })?;
        let (endpoint, realm_socket) = if self.realm.is_some() {
            let socket = std::net::UdpSocket::bind(address)?;
            socket.set_nonblocking(true)?;
            let socket = quinn::TokioRuntime.wrap_udp_socket(socket)?;
            let socket = RealmPacketSocket::new(socket);
            let endpoint =
                hysteria2_server_endpoint_with_transport_obfs_socket(
                    tls,
                    transport,
                    obfs,
                    socket.clone() as Arc<dyn AsyncUdpSocket>,
                )?;
            (endpoint, Some(socket))
        } else {
            (
                hysteria2_server_endpoint_with_transport_obfs(
                    address, tls, transport, obfs,
                )?,
                None,
            )
        };
        self.local_addr = Some(endpoint.local_addr()?);
        let users = Arc::new(
            self.options
                .users
                .iter()
                .map(|user| (user.password.clone(), user.name.clone()))
                .collect::<HashMap<_, _>>(),
        );
        let tag = self.tag.clone();
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        let cancellation = self.cancellation.clone();
        let realm = self.realm.clone();
        let ignore_client_bandwidth = self.options.ignore_client_bandwidth;
        let masquerade = self.masquerade.clone();
        let udp_timeout = self
            .options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        self.task = Some(tokio::spawn(async move {
            let realm_task = match (realm, realm_socket) {
                (Some(realm), Some(socket)) => {
                    let cancellation = cancellation.clone();
                    Some(tokio::spawn(async move {
                        realm
                            .run(socket, cancellation)
                            .await
                            .map_err(io::Error::other)
                    }))
                }
                _ => None,
            };
            let result = accept_loop(
                endpoint,
                cancellation.clone(),
                users,
                tag,
                router,
                outbounds,
                server_brutal,
                send_bps,
                receive_bps,
                ignore_client_bandwidth,
                udp_timeout,
                masquerade,
            )
            .await;
            cancellation.cancel();
            if let Some(realm_task) = realm_task {
                let realm_result =
                    realm_task.await.map_err(io::Error::other)?;
                if result.is_ok() {
                    realm_result?;
                }
            }
            result
        }));
        Ok(())
    }
}

#[cfg(test)]
fn build_masquerade(
    options: Option<&Hysteria2Masquerade>,
    base_path: &Path,
) -> Result<Option<Hysteria2MasqueradeHandler>, Hysteria2InboundError> {
    build_masquerade_with_runtime_context(options, base_path, None, None)
}

fn build_masquerade_with_runtime_context(
    options: Option<&Hysteria2Masquerade>,
    base_path: &Path,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
) -> Result<Option<Hysteria2MasqueradeHandler>, Hysteria2InboundError> {
    let Some(options) = options else {
        return Ok(None);
    };
    match options {
        Hysteria2Masquerade::Url(value) => {
            let url = parse_masquerade_url(value)?;
            match url.scheme() {
                "file" => {
                    let path = url.to_file_path().map_err(|_| {
                        Hysteria2InboundError::Config(
                            "invalid file masquerade URL".into(),
                        )
                    })?;
                    build_file_masquerade_path(
                        expand_environment(&path.to_string_lossy()),
                        base_path,
                    )
                }
                "http" | "https" => build_proxy_masquerade(
                    url,
                    false,
                    ntp_clock,
                    certificate_store,
                ),
                scheme => Err(Hysteria2InboundError::Config(format!(
                    "unknown masquerade URL scheme: {scheme}"
                ))),
            }
        }
        Hysteria2Masquerade::Object(Hysteria2MasqueradeObject::File {
            directory,
        }) => {
            build_file_masquerade_path(expand_environment(directory), base_path)
        }
        Hysteria2Masquerade::Object(Hysteria2MasqueradeObject::Proxy {
            url,
            rewrite_host,
        }) => build_proxy_masquerade(
            parse_masquerade_url(url)?,
            *rewrite_host,
            ntp_clock,
            certificate_store,
        ),
        Hysteria2Masquerade::Object(Hysteria2MasqueradeObject::String {
            status_code,
            headers,
            content,
        }) => build_string_masquerade(*status_code, headers, content),
    }
}

fn build_file_masquerade_path(
    directory: PathBuf,
    base_path: &Path,
) -> Result<Option<Hysteria2MasqueradeHandler>, Hysteria2InboundError> {
    let directory = if directory.is_absolute() {
        directory
    } else {
        base_path.join(directory)
    };
    match std::fs::read_dir(&directory) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Hysteria2InboundError::Config(format!(
                "read masquerade directory: {error}"
            )));
        }
    }
    Ok(Some(Hysteria2MasqueradeHandler::File { directory }))
}

fn parse_masquerade_url(
    value: &str,
) -> Result<url::Url, Hysteria2InboundError> {
    url::Url::parse(value).map_err(|error| {
        Hysteria2InboundError::Config(format!(
            "invalid masquerade URL {value:?}: {error}"
        ))
    })
}

fn build_proxy_masquerade(
    url: url::Url,
    rewrite_host: bool,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
) -> Result<Option<Hysteria2MasqueradeHandler>, Hysteria2InboundError> {
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return Err(Hysteria2InboundError::Config(
            "proxy masquerade URL must use http or https and include a host"
                .into(),
        ));
    }
    let mut builder =
        reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if url.scheme() == "https" {
        let host = url.host_str().expect("validated proxy URL host");
        let mut tls_options = crate::option::OutboundTlsOptions {
            enabled: true,
            ..Default::default()
        };
        tls_options.set_runtime_context(ntp_clock, certificate_store);
        let tls = build_client_config(host, &tls_options, &["h2", "http/1.1"])
            .map_err(Hysteria2InboundError::Tls)?;
        builder = builder.use_preconfigured_tls(tls.config.as_ref().clone());
    }
    let client = builder
        .build()
        .map_err(|error| Hysteria2InboundError::Config(error.to_string()))?;
    Ok(Some(Hysteria2MasqueradeHandler::Proxy {
        url,
        rewrite_host,
        client,
    }))
}

fn build_string_masquerade(
    status_code: i32,
    headers: &HashMap<String, crate::option::Listable<String>>,
    content: &str,
) -> Result<Option<Hysteria2MasqueradeHandler>, Hysteria2InboundError> {
    let status = if status_code == 0 {
        StatusCode::OK
    } else {
        StatusCode::from_u16(u16::try_from(status_code).map_err(|_| {
            Hysteria2InboundError::Config(
                "invalid masquerade status_code".into(),
            )
        })?)
        .map_err(|error| Hysteria2InboundError::Config(error.to_string()))?
    };
    let mut response_headers = HeaderMap::new();
    for (name, values) in headers {
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                Hysteria2InboundError::Config(format!(
                    "invalid masquerade header name {name:?}: {error}"
                ))
            })?;
        for value in values.as_slice() {
            response_headers.append(
                name.clone(),
                HeaderValue::from_str(value).map_err(|error| {
                    Hysteria2InboundError::Config(format!(
                        "invalid masquerade header value: {error}"
                    ))
                })?,
            );
        }
    }
    Ok(Some(Hysteria2MasqueradeHandler::String(
        Hysteria2MasqueradeResponse {
            status,
            headers: response_headers,
            content: Bytes::copy_from_slice(content.as_bytes()),
        },
    )))
}

fn expand_environment(path: &str) -> PathBuf {
    let mut output = String::new();
    let mut chars = path.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '$' {
            output.push(character);
            continue;
        }
        let braced = chars.peek() == Some(&'{');
        if braced {
            chars.next();
        }
        let mut name = String::new();
        while let Some(next) = chars.peek().copied() {
            let ended = if braced {
                next == '}'
            } else {
                next != '_' && !next.is_ascii_alphanumeric()
            };
            if ended {
                break;
            }
            name.push(next);
            chars.next();
        }
        if braced && chars.peek() == Some(&'}') {
            chars.next();
        }
        if let Ok(value) = std::env::var(name) {
            output.push_str(&value);
        }
    }
    PathBuf::from(output)
}

fn build_obfs_config(
    options: Option<&Hysteria2Obfs>,
) -> Result<Option<Hysteria2ObfsConfig>, Hysteria2InboundError> {
    let Some(options) = options else {
        return Ok(None);
    };
    if options.password().is_empty() {
        return Err(Hysteria2InboundError::Config(
            "missing obfs password".into(),
        ));
    }
    Ok(Some(match options {
        Hysteria2Obfs::Salamander { password } => {
            Hysteria2ObfsConfig::Salamander {
                password: password.as_bytes().to_vec(),
            }
        }
        Hysteria2Obfs::Gecko {
            password,
            min_packet_size,
            max_packet_size,
        } => Hysteria2ObfsConfig::gecko(
            password.as_bytes().to_vec(),
            usize::try_from(*min_packet_size).map_err(|_| {
                Hysteria2InboundError::Config(
                    "negative Gecko min_packet_size".into(),
                )
            })?,
            usize::try_from(*max_packet_size).map_err(|_| {
                Hysteria2InboundError::Config(
                    "negative Gecko max_packet_size".into(),
                )
            })?,
        )
        .map_err(|error| Hysteria2InboundError::Config(error.to_string()))?,
    }))
}

impl Lifecycle for Hysteria2Inbound {
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
    users: Arc<HashMap<String, String>>,
    tag: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    server_brutal: Arc<HysteriaBrutalServerConfig>,
    send_bps: u64,
    receive_bps: u64,
    ignore_client_bandwidth: bool,
    udp_timeout: std::time::Duration,
    masquerade: Option<Hysteria2MasqueradeHandler>,
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
                let masquerade = masquerade.clone();
                let connecting = incoming.accept().map_err(io::Error::other)?;
                let brutal = server_brutal.take_pending().ok_or_else(|| {
                    io::Error::other("Hysteria2 Brutal controller was not constructed")
                })?;
                connections.spawn(async move {
                    let connection = connecting.await.map_err(io::Error::other)?;
                    let source = connection.remote_address();
                    let session = Hysteria2ServerSession::authenticate_with_masquerade(
                        connection,
                        &users,
                        true,
                        receive_bps,
                        ignore_client_bandwidth,
                        masquerade.as_ref(),
                    ).await?;
                    let negotiated_send_bps = server_brutal_bps(
                        send_bps,
                        session.client_receive_bps,
                        session.receive_auto,
                    );
                    brutal.set_bps(negotiated_send_bps);
                    let user = session.user.clone();
                    let mut streams = JoinSet::new();
                    let mut udp_sessions = HashMap::<u32, UdpState>::new();
                    let (udp_closed_sender, mut udp_closed_receiver) =
                        mpsc::unbounded_channel();
                    loop {
                        tokio::select! {
                            result = session.accept_tcp() => {
                                let (stream, destination) = match result {
                                    Ok(value) => value,
                                    Err(_error) if session.connection().close_reason().is_some() => break,
                                    Err(error) => return Err(error),
                                };
                                let tag = tag.clone();
                                let user = user.clone();
                                let router = router.clone();
                                let outbounds = outbounds.clone();
                                streams.spawn(async move {
                                    let _ = proxy_tcp(
                                        stream, source, &tag, destination,
                                        user, &router, &outbounds,
                                    ).await;
                                });
                            }
                            result = session.read_udp() => {
                                let message = match result {
                                    Ok(message) => message,
                                    Err(_error) if session.connection().close_reason().is_some() => break,
                                    Err(error) => return Err(error),
                                };
                                let session_id = message.session_id;
                                if udp_sessions.get(&session_id).is_none_or(|state| state.sender.is_closed()) {
                                    udp_sessions.remove(&session_id);
                                    let (sender, receiver) = mpsc::channel(64);
                                    udp_sessions.insert(session_id, UdpState { sender, defragmenter: UdpDefragmenter::default() });
                                    let connection = session.connection().clone();
                                    let tag = tag.clone();
                                    let user = user.clone();
                                    let router = router.clone();
                                    let outbounds = outbounds.clone();
                                    let udp_closed_sender = udp_closed_sender.clone();
                                    streams.spawn(async move {
                                        let result = proxy_udp_session(
                                            connection, receiver, session_id,
                                            source, &tag, user, &router,
                                            &outbounds, udp_timeout,
                                        ).await;
                                        let _ = udp_closed_sender.send(session_id);
                                        let _ = result;
                                    });
                                }
                                let state = udp_sessions.get_mut(&session_id).expect("UDP session inserted");
                                let Some(message) = state.defragmenter.feed(message) else {
                                    continue;
                                };
                                let _ = state.sender.try_send(message);
                            }
                            Some(session_id) = udp_closed_receiver.recv() => {
                                udp_sessions.remove(&session_id);
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
    mut receiver: mpsc::Receiver<UdpMessage>,
    session_id: u32,
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
                "Hysteria2 UDP session timed out",
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Hysteria2 UDP session closed",
            )
        })?;
    let client_destination: SocksAddr = first.address.parse()?;
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
    let mut response_packet_id = 0_u32;
    if matches!(decision.action(), Some(Action::HijackDns)) {
        let mut pending = Some(first);
        loop {
            if let Some(message) = pending.take() {
                let response = hijack_dns_packet_with_context(
                    &message.data,
                    outbounds,
                    &metadata,
                )
                .await?;
                send_udp_response(
                    &connection,
                    session_id,
                    &mut response_packet_id,
                    message.address,
                    response,
                )?;
            }
            pending = Some(
                timeout(udp_timeout, receiver.recv())
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Hysteria2 UDP session timed out",
                        )
                    })?
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "Hysteria2 UDP session closed",
                        )
                    })?,
            );
        }
    }

    let routed_destination = decision.destination(&destination);
    let mut destination_nat =
        PacketDestinationNat::new(destination.clone(), routed_destination);
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
            let client_destination: SocksAddr = message.address.parse()?;
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
                "Hysteria2 UDP session timed out",
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
                    source.to_string(),
                    response[..size].to_vec(),
                )?;
            }
        }
    }
}

fn send_udp_response(
    connection: &quinn::Connection,
    session_id: u32,
    packet_id: &mut u32,
    source: String,
    data: Vec<u8>,
) -> io::Result<()> {
    *packet_id = packet_id.wrapping_add(1);
    let response = UdpMessage {
        session_id,
        packet_id: (*packet_id % u32::from(u16::MAX)) as u16,
        fragment_id: 0,
        fragment_count: 1,
        address: source,
        data,
    };
    let mtu = connection.max_datagram_size().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "QUIC peer does not support datagrams",
        )
    })?;
    for fragment in fragment_udp_message(response, mtu)? {
        connection
            .send_datagram(bytes::Bytes::from(fragment.encode()?))
            .map_err(io::Error::other)?;
    }
    Ok(())
}

async fn proxy_tcp(
    mut client: Hysteria2TcpStream,
    source: SocketAddr,
    tag: &str,
    destination: String,
    user: String,
    router: &Router,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let destination: SocksAddr = match destination.parse() {
        Ok(destination) => destination,
        Err(error) => {
            send_tcp_failure(&mut client, &error).await;
            return Err(error);
        }
    };
    let (destination, origin_destination) =
        match restore_fake_ip(destination, outbounds) {
            Ok(destination) => destination,
            Err(error) => {
                send_tcp_failure(&mut client, &error).await;
                return Err(error);
            }
        };
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
        client
            .send
            .write_all(&encode_tcp_response(true, "", &[])?)
            .await?;
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
        client
            .send
            .write_all(&encode_tcp_response(true, "", &[])?)
            .await?;
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
    client
        .send
        .write_all(&encode_tcp_response(true, "", &[])?)
        .await?;
    if !inspected.is_empty() {
        remote.write_all(&inspected).await?;
    }
    copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

async fn send_tcp_failure(client: &mut Hysteria2TcpStream, error: &io::Error) {
    if let Ok(response) = encode_tcp_response(false, &error.to_string(), &[]) {
        let _ = client.send.write_all(&response).await;
        let _ = client.send.finish();
    }
}

#[cfg(test)]
mod tests {
    use std::{path::Path, sync::Arc};

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    use super::{Hysteria2Inbound, build_masquerade};
    use crate::{
        adapter::Dialer,
        common::{
            lifecycle::{Lifecycle, StartStage},
            network::SocksAddr,
            tls::build_client_config,
        },
        option::{
            DirectOutboundOptions, Hysteria2InboundOptions,
            HysteriaRealmServiceOptions, Options, OutboundTlsOptions,
        },
        outbound::OutboundManager,
        protocol::{
            direct::DirectOutbound,
            hysteria2::{Hysteria2ObfsConfig, Hysteria2Outbound},
            hysteria2_realm::{RealmClientConnector, RealmControlClient},
        },
        route::Router,
        service::hysteria_realm::HysteriaRealmService,
    };

    #[test]
    fn resolves_file_and_proxy_masquerade_forms() {
        let base = tempfile::tempdir().unwrap();
        std::fs::create_dir(base.path().join("cover")).unwrap();
        let file: crate::option::Hysteria2Masquerade =
            serde_json::from_value(json!({
                "type":"file", "directory":"cover"
            }))
            .unwrap();
        match build_masquerade(Some(&file), base.path()).unwrap().unwrap() {
            crate::protocol::hysteria2::Hysteria2MasqueradeHandler::File {
                directory,
            } => assert_eq!(directory, base.path().join("cover")),
            _ => panic!("expected file masquerade"),
        }

        let absolute = base.path().join("cover");
        let file_url: crate::option::Hysteria2Masquerade =
            serde_json::from_value(json!(format!(
                "file://{}",
                absolute.display()
            )))
            .unwrap();
        assert!(matches!(
            build_masquerade(Some(&file_url), Path::new("ignored")).unwrap(),
            Some(
                crate::protocol::hysteria2::Hysteria2MasqueradeHandler::File { .. }
            )
        ));

        for value in [
            json!("https://cover.example/base"),
            json!({
                "type":"proxy", "url":"http://cover.example/base",
                "rewrite_host":true
            }),
        ] {
            let proxy = serde_json::from_value(value).unwrap();
            assert!(matches!(
                build_masquerade(Some(&proxy), base.path()).unwrap(),
                Some(crate::protocol::hysteria2::Hysteria2MasqueradeHandler::Proxy { .. })
            ));
        }
    }

    #[tokio::test]
    async fn proxies_authenticated_tcp_and_udp_end_to_end() {
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
        let certificate = cert.pem();
        let options: Hysteria2InboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1", "listen_port":0,
            "users":[{"name":"alice","password":"secret"}],
            "up_mbps":10,
            "down_mbps":20,
            "bbr_profile":"aggressive",
            "brutal_debug":true,
            "obfs":{
                "type":"gecko",
                "password":"cover-secret",
                "min_packet_size":256,
                "max_packet_size":1350
            },
            "tls":{
                "enabled":true,
                "certificate":certificate,
                "key":key_pair.serialize_pem()
            }
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound =
            Hysteria2Inbound::new("hy2-in", options, router, outbounds)
                .unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let server = inbound.local_addr().unwrap();
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &["h3"],
        )
        .unwrap();
        let outbound =
            Hysteria2Outbound::new_with_transport_obfs_and_packet_dialer_and_profile(
                server.into(),
                "localhost",
                "secret",
                30 * 125_000,
                false,
                40 * 125_000,
                tls,
                crate::protocol::hysteria2::Hysteria2QuicOptions::default()
                    .build()
                    .unwrap(),
                Some(
                    Hysteria2ObfsConfig::gecko(
                        b"cover-secret".to_vec(),
                        256,
                        1350,
                    )
                    .unwrap(),
                ),
                Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
                crate::protocol::quic_bbr::BbrProfile::Aggressive,
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
            (0..3500).map(|index| (index % 251) as u8).collect();
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
        let unavailable_address = unavailable.local_addr().unwrap();
        drop(unavailable);
        let result = outbound.dial_tcp(&unavailable_address.into()).await;
        let error = match result {
            Ok(_) => {
                panic!("Hysteria2 target dial failure was reported as success")
            }
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("Hysteria2 remote error"),
            "unexpected error: {error}"
        );

        inbound.close().await.unwrap();
        echo.await.unwrap();
        udp_echo.await.unwrap();
    }

    #[tokio::test]
    async fn realm_inbound_and_outbound_connect_end_to_end() {
        let realm_options: HysteriaRealmServiceOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "users":[{"name":"realm-user","token":"realm-secret"}]
            }))
            .unwrap();
        let (mut realm_service, realm_handle) =
            HysteriaRealmService::new("realm-e2e", realm_options).unwrap();
        realm_service.start(StartStage::Start).await.unwrap();
        let realm_url =
            format!("http://{}", realm_handle.local_addr().unwrap());

        let stun = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun.local_addr().unwrap();
        let stun_responder = tokio::spawn(async move {
            let mut request = [0_u8; 64];
            for _ in 0..2 {
                let (_, client_addr) =
                    stun.recv_from(&mut request).await.unwrap();
                let transaction_id: [u8; 12] =
                    request[8..20].try_into().unwrap();
                let cookie = 0x2112_A442_u32.to_be_bytes();
                let mut response = vec![0x01, 0x01, 0, 12];
                response.extend_from_slice(&cookie);
                response.extend_from_slice(&transaction_id);
                response.extend_from_slice(&0x0020_u16.to_be_bytes());
                response.extend_from_slice(&8_u16.to_be_bytes());
                response.extend_from_slice(&[0, 1]);
                response.extend_from_slice(
                    &(client_addr.port() ^ 0x2112_u16).to_be_bytes(),
                );
                let std::net::IpAddr::V4(ip) = client_addr.ip() else {
                    panic!("expected IPv4 STUN client");
                };
                response
                    .extend(ip.octets().iter().zip(cookie).map(|(a, b)| a ^ b));
                stun.send_to(&response, client_addr).await.unwrap();
            }
        });

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let inbound_options: Hysteria2InboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "users":[{"name":"alice","password":"password"}],
                "tls":{
                    "enabled":true,
                    "certificate":cert.pem(),
                    "key":key_pair.serialize_pem()
                },
                "realm":{
                    "server_url":realm_url,
                    "token":"realm-secret",
                    "realm_id":"rust-e2e",
                    "stun_servers":[stun_addr.to_string()],
                    "ip_version":4,
                    "http_client": {
                        "version": 1,
                        "headers": {"X-Realm-Test": "enabled"}
                    }
                }
            }))
            .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound = Hysteria2Inbound::new(
            "realm-in",
            inbound_options,
            router,
            outbounds,
        )
        .unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let control =
            RealmControlClient::new(realm_url, "realm-secret", None).unwrap();
        let connector = RealmClientConnector::new(
            control,
            "rust-e2e",
            vec![stun_addr.to_string()],
            4,
        )
        .unwrap();
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &["h3"],
        )
        .unwrap();
        let outbound = Hysteria2Outbound::new_with_realm(
            "localhost",
            "password",
            0,
            false,
            0,
            tls,
            crate::protocol::hysteria2::Hysteria2QuicOptions::default()
                .build()
                .unwrap(),
            None,
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            connector,
        );
        let mut stream = outbound.dial_tcp(&destination.into()).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        drop(stream);
        drop(outbound);
        inbound.close().await.unwrap();
        realm_service.close().await.unwrap();
        stun_responder.await.unwrap();
        echo.await.unwrap();
    }
}
