//! Hysteria2 Realm control-plane and UDP hole-punch wire primitives.
//!
//! This mirrors `sing-quic/hysteria2/realm`.  The control client is kept
//! independent from the Hysteria2 QUIC session so inbound and outbound realm
//! orchestration can share the same authenticated HTTP/SSE implementation.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    future::poll_fn,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU16,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures_util::{StreamExt as _, stream::FuturesUnordered};
use n0_watcher::Watcher as _;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use reqwest::{Client, Method, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::adapter::Dialer;
use crate::common::{
    http::{DownloadClient, DownloadOptions, StreamingResponse},
    network::SocksAddr,
    ntp::NtpClock,
    tls::build_client_config,
};
use crate::{dns::manager::SharedResolver, option::HttpClientOptions};

const SALT_LENGTH: usize = 8;
const MAGIC_LENGTH: usize = 8;
const NONCE_LENGTH: usize = 16;
const MIN_BODY_SIZE: usize = MAGIC_LENGTH + 1 + NONCE_LENGTH;
const MAX_PADDING: usize = 1024;
const MIN_PACKET_LENGTH: usize = SALT_LENGTH + MIN_BODY_SIZE;
const MAX_ERROR_BODY_SIZE: usize = 64 * 1024;
const MAX_EVENT_SIZE: usize = 64 * 1024;
const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
const PUNCH_MAGIC: [u8; MAGIC_LENGTH] = *b"HYRLMv1\0";
const DEFAULT_PORT_MAPPING_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_PORT_MAPPING_LIFETIME: Duration = Duration::from_secs(10 * 60);
const CONNECT_STUN_CACHE_TTL: Duration = Duration::from_secs(10);
const SSE_BACKOFF_MIN: Duration = Duration::from_secs(1);
const SSE_BACKOFF_MAX: Duration = Duration::from_secs(30);

pub const PUNCH_HELLO: u8 = 0x01;
pub const PUNCH_ACK: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealmPortMappingOptions {
    pub timeout: Duration,
    pub lifetime: Duration,
}

impl RealmPortMappingOptions {
    pub fn new(timeout: Option<Duration>, lifetime: Option<Duration>) -> Self {
        Self {
            timeout: timeout
                .filter(|duration| !duration.is_zero())
                .unwrap_or(DEFAULT_PORT_MAPPING_TIMEOUT),
            lifetime: lifetime
                .filter(|duration| !duration.is_zero())
                .unwrap_or(DEFAULT_PORT_MAPPING_LIFETIME),
        }
    }
}

type UpnpGateway = igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>;

#[derive(Debug)]
enum RealmPortMappingBackend {
    Nat {
        mapping: crab_nat::PortMapping,
        external_ip: IpAddr,
    },
    Upnp {
        gateway: UpnpGateway,
        local_addr: SocketAddr,
        external_addr: SocketAddr,
        lease_seconds: u32,
    },
}

impl RealmPortMappingBackend {
    fn external_addr(&self) -> SocketAddr {
        match self {
            Self::Nat {
                mapping,
                external_ip,
            } => SocketAddr::new(*external_ip, mapping.external_port().get()),
            Self::Upnp { external_addr, .. } => *external_addr,
        }
    }

    async fn renew(&mut self) -> Result<SocketAddr, RealmError> {
        match self {
            Self::Nat {
                mapping,
                external_ip,
            } => {
                mapping.renew().await.map_err(|error| {
                    RealmError::PortMapping(format!(
                        "renew PCP/NAT-PMP mapping: {error}"
                    ))
                })?;
                *external_ip = nat_mapping_external_ip(mapping).await?;
            }
            Self::Upnp {
                gateway,
                local_addr,
                external_addr,
                lease_seconds,
            } => {
                gateway
                    .add_port(
                        igd_next::PortMappingProtocol::UDP,
                        external_addr.port(),
                        *local_addr,
                        *lease_seconds,
                        "hysteria-realm",
                    )
                    .await
                    .map_err(|error| {
                        RealmError::PortMapping(format!(
                            "renew UPnP mapping: {error}"
                        ))
                    })?;
                let external_ip =
                    gateway.get_external_ip().await.map_err(|error| {
                        RealmError::PortMapping(format!(
                            "get UPnP external address: {error}"
                        ))
                    })?;
                *external_addr =
                    SocketAddr::new(external_ip, external_addr.port());
            }
        }
        let address = self.external_addr();
        validate_mapped_address(address)?;
        Ok(address)
    }

    async fn release(self) {
        match self {
            Self::Nat { mapping, .. } => {
                let _ = mapping.try_drop().await;
            }
            Self::Upnp {
                gateway,
                external_addr,
                ..
            } => {
                let _ = gateway
                    .remove_port(
                        igd_next::PortMappingProtocol::UDP,
                        external_addr.port(),
                    )
                    .await;
            }
        }
    }
}

/// Live UPnP IGD, PCP, or NAT-PMP mapping with the exact configured lease.
/// Keeping this value alive renews the mapping every half-lifetime; closing or
/// dropping it schedules explicit removal from the gateway.
pub struct RealmPortMapping {
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
    address: tokio::sync::watch::Receiver<Option<SocketAddr>>,
    timeout: Duration,
    lifetime: Duration,
}

impl fmt::Debug for RealmPortMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealmPortMapping")
            .field("external_addr", &self.external_addr())
            .field("timeout", &self.timeout)
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

impl RealmPortMapping {
    pub async fn start(
        internal_port: u16,
        options: RealmPortMappingOptions,
    ) -> Result<Self, RealmError> {
        let port = NonZeroU16::new(internal_port).ok_or_else(|| {
            RealmError::PortMapping("invalid internal port".into())
        })?;
        let mut backend = tokio::time::timeout(
            options.timeout,
            create_port_mapping(port, options),
        )
        .await
        .map_err(|_| {
            RealmError::PortMapping(format!(
                "gateway discovery timed out after {:?}",
                options.timeout
            ))
        })??;
        let external = backend.external_addr();
        validate_mapped_address(external)?;
        let (address_tx, address) = tokio::sync::watch::channel(Some(external));
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let timeout = options.timeout;
        let renew_interval =
            (options.lifetime / 2).max(Duration::from_millis(1));
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_cancellation.cancelled() => {
                        let _ = tokio::time::timeout(timeout, backend.release()).await;
                        let _ = address_tx.send(None);
                        break;
                    }
                    _ = tokio::time::sleep(renew_interval) => {
                        if let Ok(Ok(external)) = tokio::time::timeout(
                            timeout,
                            backend.renew(),
                        ).await
                            && address_tx.borrow().as_ref() != Some(&external)
                        {
                            let _ = address_tx.send(Some(external));
                        }
                    }
                }
            }
        });
        Ok(Self {
            cancellation,
            task: Some(task),
            address,
            timeout: options.timeout,
            lifetime: options.lifetime,
        })
    }

    pub fn external_addr(&self) -> Option<SocketAddr> {
        *self.address.borrow()
    }

    pub async fn changed(&mut self) -> Result<Option<SocketAddr>, RealmError> {
        self.address.changed().await.map_err(|_| {
            RealmError::PortMapping("port mapping service stopped".into())
        })?;
        let address = self.external_addr();
        if let Some(address) = address {
            validate_mapped_address(address)?;
        }
        Ok(address)
    }

    pub async fn close(mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(self.timeout, task).await;
        }
    }
}

impl Drop for RealmPortMapping {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn mapping_lifetime_seconds(lifetime: Duration) -> u32 {
    lifetime.as_secs().clamp(1, u64::from(u32::MAX)) as u32
}

fn nat_timeout_config(timeout: Duration) -> crab_nat::TimeoutConfig {
    let initial_timeout = timeout.min(Duration::from_millis(250));
    crab_nat::TimeoutConfig {
        initial_timeout,
        max_retries: 1,
        max_retry_timeout: Some(timeout),
    }
}

async fn nat_mapping_external_ip(
    mapping: &crab_nat::PortMapping,
) -> Result<IpAddr, RealmError> {
    match mapping.mapping_type() {
        crab_nat::PortMappingType::Pcp { external_ip, .. } => Ok(external_ip),
        crab_nat::PortMappingType::NatPmp => {
            crab_nat::natpmp::external_address(
                mapping.gateway(),
                Some(mapping.timeout_config),
            )
            .await
            .map(IpAddr::V4)
            .map_err(|error| {
                RealmError::PortMapping(format!(
                    "get NAT-PMP external address: {error}"
                ))
            })
        }
    }
}

async fn create_nat_mapping(
    port: NonZeroU16,
    options: RealmPortMappingOptions,
) -> Result<RealmPortMappingBackend, RealmError> {
    let router = netwatch::interfaces::HomeRouter::new().ok_or_else(|| {
        RealmError::PortMapping("no IPv4 home router discovered".into())
    })?;
    let (IpAddr::V4(gateway), Some(IpAddr::V4(client))) =
        (router.gateway, router.my_ip)
    else {
        return Err(RealmError::PortMapping(
            "no IPv4 gateway/client pair discovered".into(),
        ));
    };
    let gateway = crab_nat::GatewayAddress::IpV4(gateway);
    let mapping_options = crab_nat::PortMappingOptions {
        external_port: None,
        lifetime_seconds: Some(mapping_lifetime_seconds(options.lifetime)),
        timeout_config: Some(nat_timeout_config(options.timeout)),
    };
    let mapping = match crab_nat::PortMapping::new(
        gateway,
        IpAddr::V4(client),
        crab_nat::InternetProtocol::Udp,
        port,
        mapping_options,
    )
    .await
    {
        Ok(mapping) => mapping,
        Err(pcp_error) => crab_nat::natpmp::port_mapping(
            gateway,
            crab_nat::InternetProtocol::Udp,
            port,
            mapping_options,
        )
        .await
        .map_err(|nat_pmp_error| {
            RealmError::PortMapping(format!(
                "PCP failed ({pcp_error}); NAT-PMP failed ({nat_pmp_error})"
            ))
        })?,
    };
    let external_ip = match nat_mapping_external_ip(&mapping).await {
        Ok(external_ip) => external_ip,
        Err(error) => {
            // Creating the lease and discovering the external address are two
            // separate gateway operations. Revoke a successfully-created
            // lease if the second operation prevents us from returning it.
            let _ = mapping.try_drop().await;
            return Err(error);
        }
    };
    Ok(RealmPortMappingBackend::Nat {
        mapping,
        external_ip,
    })
}

async fn create_upnp_mapping(
    port: NonZeroU16,
    options: RealmPortMappingOptions,
) -> Result<RealmPortMappingBackend, RealmError> {
    let gateway =
        igd_next::aio::tokio::search_gateway(igd_next::SearchOptions {
            timeout: Some(options.timeout),
            single_search_timeout: Some(options.timeout),
            ..Default::default()
        })
        .await
        .map_err(|error| {
            RealmError::PortMapping(format!("discover UPnP gateway: {error}"))
        })?;
    let bind_addr = if gateway.addr.is_ipv4() {
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
    };
    let route_socket =
        tokio::net::UdpSocket::bind(bind_addr)
            .await
            .map_err(|error| {
                RealmError::PortMapping(format!(
                    "bind UPnP route probe: {error}"
                ))
            })?;
    route_socket.connect(gateway.addr).await.map_err(|error| {
        RealmError::PortMapping(format!("connect UPnP route probe: {error}"))
    })?;
    let local_addr = SocketAddr::new(
        route_socket
            .local_addr()
            .map_err(|error| {
                RealmError::PortMapping(format!(
                    "read UPnP route address: {error}"
                ))
            })?
            .ip(),
        port.get(),
    );
    let lease_seconds = mapping_lifetime_seconds(options.lifetime);
    let external_addr = gateway
        .get_any_address(
            igd_next::PortMappingProtocol::UDP,
            local_addr,
            lease_seconds,
            "hysteria-realm",
        )
        .await
        .map_err(|error| {
            RealmError::PortMapping(format!("add UPnP mapping: {error}"))
        })?;
    Ok(RealmPortMappingBackend::Upnp {
        gateway,
        local_addr,
        external_addr,
        lease_seconds,
    })
}

async fn create_port_mapping(
    port: NonZeroU16,
    options: RealmPortMappingOptions,
) -> Result<RealmPortMappingBackend, RealmError> {
    match create_nat_mapping(port, options).await {
        Ok(mapping) => Ok(mapping),
        Err(nat_error) => create_upnp_mapping(port, options).await.map_err(
            |upnp_error| {
                RealmError::PortMapping(format!(
                    "PCP/NAT-PMP unavailable ({nat_error}); UPnP unavailable ({upnp_error})"
                ))
            },
        ),
    }
}

fn validate_mapped_address(address: SocketAddr) -> Result<(), RealmError> {
    if address.ip().is_unspecified() || address.ip().is_loopback() {
        return Err(RealmError::PortMapping(format!(
            "gateway returned unusable external address: {address}"
        )));
    }
    Ok(())
}

struct RealmHttpDnsResolver {
    resolver: SharedResolver,
    options: crate::dns::LookupOptions,
}

impl reqwest::dns::Resolve for RealmHttpDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolver = self.resolver.clone();
        let options = self.options;
        let domain = name.as_str().to_owned();
        Box::pin(async move {
            let addresses =
                resolver.lookup_with_options(&domain, options).await?;
            Ok(Box::new(
                addresses
                    .into_iter()
                    .map(|address| SocketAddr::new(address, 0)),
            ) as reqwest::dns::Addrs)
        })
    }
}

/// Build the compatibility reqwest backend used by callers that supply no
/// singbox [`Dialer`]. Runtime integrations should prefer
/// [`RealmControlClient::new_with_dialer`] so detours and HTTP/3 remain active.
pub fn build_realm_http_client(
    server_url: &str,
    options: &HttpClientOptions,
    resolver: Option<(SharedResolver, crate::dns::LookupOptions)>,
) -> Result<Client, RealmError> {
    if !matches!(options.engine.as_str(), "" | "go") {
        return Err(RealmError::Config(format!(
            "unsupported Realm HTTP client engine {:?}",
            options.engine
        )));
    }
    if !matches!(options.version, 0..=2) {
        return Err(RealmError::Config(format!(
            "unsupported Realm HTTP version {}",
            options.version
        )));
    }
    if !options.dialer.detour.is_empty() {
        return Err(RealmError::Config(
            "the reqwest compatibility backend cannot own a Realm detour; use RealmControlClient::new_with_dialer"
                .into(),
        ));
    }
    let parsed = reqwest::Url::parse(server_url).map_err(|error| {
        RealmError::Config(format!("invalid control server URL: {error}"))
    })?;
    let host = parsed.host_str().ok_or_else(|| {
        RealmError::Config("Realm HTTP server URL has no host".into())
    })?;
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in &options.headers {
        let name = reqwest::header::HeaderName::try_from(name.as_str())
            .map_err(|error| RealmError::Config(error.to_string()))?;
        let values: Vec<&str> = match value {
            serde_json::Value::String(value) => vec![value],
            serde_json::Value::Array(values) => values
                .iter()
                .map(|value| {
                    value.as_str().ok_or_else(|| {
                        RealmError::Config(format!(
                            "Realm HTTP header {name} contains a non-string value"
                        ))
                    })
                })
                .collect::<Result<_, _>>()?,
            _ => {
                return Err(RealmError::Config(format!(
                    "Realm HTTP header {name} must be a string or string array"
                )));
            }
        };
        for value in values {
            headers.append(
                name.clone(),
                reqwest::header::HeaderValue::try_from(value)
                    .map_err(|error| RealmError::Config(error.to_string()))?,
            );
        }
    }
    let mut builder = Client::builder()
        .default_headers(headers)
        .user_agent(concat!("sing-box/", env!("CARGO_PKG_VERSION")));
    if let Some(timeout) = options
        .dialer
        .abstract_options
        .connect_timeout
        .as_std()
        .filter(|duration| !duration.is_zero())
    {
        builder = builder.connect_timeout(timeout);
    }
    if let Some(timeout) = options
        .idle_timeout
        .as_std()
        .filter(|duration| !duration.is_zero())
    {
        builder = builder.pool_idle_timeout(timeout);
    }
    builder = match options.version {
        1 => builder.http1_only(),
        2 if options.disable_version_fallback => {
            builder.http2_prior_knowledge()
        }
        _ => builder,
    };
    if let Some((resolver, lookup_options)) = resolver {
        builder = builder.dns_resolver(Arc::new(RealmHttpDnsResolver {
            resolver,
            options: lookup_options,
        }));
    }
    if parsed.scheme() == "https" {
        let mut tls_options = options.tls.clone().unwrap_or_default();
        tls_options.enabled = true;
        let tls = build_client_config(host, &tls_options, &["h2", "http/1.1"])
            .map_err(|error| RealmError::Config(error.to_string()))?;
        // reqwest downcasts the supplied value to rustls::ClientConfig;
        // passing the Arc wrapper is accepted by the type system but rejected
        // by its runtime backend check.
        builder = builder.use_preconfigured_tls(tls.config.as_ref().clone());
    }
    builder
        .build()
        .map_err(|error| RealmError::Config(format!("{error:?}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchMetadata {
    pub nonce: [u8; NONCE_LENGTH],
    pub obfuscation_key: [u8; 32],
}

impl PunchMetadata {
    pub fn generate() -> Result<Self, RealmError> {
        let mut metadata = Self {
            nonce: [0; NONCE_LENGTH],
            obfuscation_key: [0; 32],
        };
        getrandom::fill(&mut metadata.nonce)
            .map_err(|error| RealmError::Entropy(error.to_string()))?;
        getrandom::fill(&mut metadata.obfuscation_key)
            .map_err(|error| RealmError::Entropy(error.to_string()))?;
        Ok(metadata)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RealmError {
    #[error("invalid Realm configuration: {0}")]
    Config(String),
    #[error("Realm HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Realm HTTP transport failed: {0}")]
    HttpTransport(String),
    #[error("control {status}/{code}: {message}")]
    Status {
        status: StatusCode,
        code: String,
        message: String,
    },
    #[error("invalid Realm response: {0}")]
    Response(String),
    #[error("invalid punch packet: {0}")]
    Punch(String),
    #[error("Realm entropy failure: {0}")]
    Entropy(String),
    #[error("Realm port mapping failure: {0}")]
    PortMapping(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RealmRegistration {
    pub session_id: String,
    pub ttl: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmConnectResponse {
    pub addresses: Vec<SocketAddr>,
    pub metadata: PunchMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmPunchEvent {
    pub addresses: Vec<SocketAddr>,
    pub metadata: PunchMetadata,
}

#[derive(Debug, Serialize)]
struct AddressesRequest<'a> {
    addresses: &'a [SocketAddr],
}

#[derive(Debug, Serialize)]
struct HeartbeatRequest<'a> {
    #[serde(skip_serializing_if = "<[SocketAddr]>::is_empty")]
    addresses: &'a [SocketAddr],
}

#[derive(Debug, Deserialize)]
struct HeartbeatResponse {
    ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PunchMetadataWire {
    addresses: Vec<SocketAddr>,
    nonce: String,
    obfs: String,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

#[derive(Clone)]
enum RealmHttpBackend {
    Reqwest(Client),
    Dialer(Arc<DownloadClient>),
}

#[derive(Clone)]
pub struct RealmControlClient {
    server_url: String,
    token: String,
    client: RealmHttpBackend,
}

impl RealmControlClient {
    pub fn new(
        server_url: impl Into<String>,
        token: impl Into<String>,
        client: Option<Client>,
    ) -> Result<Self, RealmError> {
        let server_url = server_url.into();
        if server_url.is_empty() {
            return Err(RealmError::Config(
                "control server URL is required".into(),
            ));
        }
        reqwest::Url::parse(&server_url).map_err(|error| {
            RealmError::Config(format!("invalid control server URL: {error}"))
        })?;
        Ok(Self {
            server_url: server_url.trim_end_matches('/').to_owned(),
            token: token.into(),
            client: RealmHttpBackend::Reqwest(client.unwrap_or_default()),
        })
    }

    /// Build a Realm control client on the crate's outbound-aware HTTP stack.
    /// This is the native library path for detours and HTTP/3; the original
    /// reqwest constructor remains available for embedding and tests.
    pub fn new_with_dialer(
        server_url: impl Into<String>,
        token: impl Into<String>,
        dialer: Arc<dyn Dialer>,
        options: HttpClientOptions,
        clock: Option<NtpClock>,
    ) -> Result<Self, RealmError> {
        let server_url = server_url.into();
        if server_url.is_empty() {
            return Err(RealmError::Config(
                "control server URL is required".into(),
            ));
        }
        reqwest::Url::parse(&server_url).map_err(|error| {
            RealmError::Config(format!("invalid control server URL: {error}"))
        })?;
        let client = DownloadClient::new_with_clock(
            dialer,
            DownloadOptions { client: options },
            clock,
        )
        .map_err(|error| RealmError::Config(error.to_string()))?;
        Ok(Self {
            server_url: server_url.trim_end_matches('/').to_owned(),
            token: token.into(),
            client: RealmHttpBackend::Dialer(Arc::new(client)),
        })
    }

    fn realm_url(&self, realm_id: &str, suffix: &str) -> String {
        format!(
            "{}/v1/{}{}",
            self.server_url,
            utf8_percent_encode(realm_id, NON_ALPHANUMERIC),
            suffix
        )
    }

    async fn request<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: String,
        token: &str,
        body: Option<&B>,
    ) -> Result<Vec<u8>, RealmError> {
        let body =
            body.map(serde_json::to_vec).transpose().map_err(|error| {
                RealmError::Response(format!(
                    "marshal control request: {error}"
                ))
            })?;
        match &self.client {
            RealmHttpBackend::Reqwest(client) => {
                let mut request = client.request(method, url);
                if !token.is_empty() {
                    request = request.bearer_auth(token);
                }
                if let Some(body) = body {
                    request = request
                        .header(
                            reqwest::header::CONTENT_TYPE,
                            "application/json",
                        )
                        .body(body);
                }
                read_response(request.send().await?).await
            }
            RealmHttpBackend::Dialer(client) => {
                let mut headers = reqwest::header::HeaderMap::new();
                if !token.is_empty() {
                    headers.insert(
                        reqwest::header::AUTHORIZATION,
                        format!("Bearer {token}").parse().map_err(
                            |error: reqwest::header::InvalidHeaderValue| {
                                RealmError::Config(error.to_string())
                            },
                        )?,
                    );
                }
                if body.is_some() {
                    headers.insert(
                        reqwest::header::CONTENT_TYPE,
                        reqwest::header::HeaderValue::from_static(
                            "application/json",
                        ),
                    );
                }
                let response = client
                    .request_stream(
                        method,
                        &url,
                        &headers,
                        body.map_or_else(bytes::Bytes::new, bytes::Bytes::from),
                    )
                    .await
                    .map_err(|error| {
                        RealmError::HttpTransport(error.to_string())
                    })?;
                read_streaming_response(response).await
            }
        }
    }

    async fn request_json<B: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: Method,
        url: String,
        token: &str,
        body: Option<&B>,
    ) -> Result<R, RealmError> {
        let bytes = self.request(method, url, token, body).await?;
        serde_json::from_slice(&bytes).map_err(|error| {
            RealmError::Response(format!("decode control response: {error}"))
        })
    }

    pub async fn register(
        &self,
        realm_id: &str,
        addresses: &[SocketAddr],
    ) -> Result<RealmRegistration, RealmError> {
        self.request_json(
            Method::POST,
            self.realm_url(realm_id, "/"),
            &self.token,
            Some(&AddressesRequest { addresses }),
        )
        .await
    }

    pub async fn deregister(
        &self,
        realm_id: &str,
        session_token: &str,
    ) -> Result<(), RealmError> {
        self.request::<()>(
            Method::DELETE,
            self.realm_url(realm_id, "/"),
            session_token,
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn heartbeat(
        &self,
        realm_id: &str,
        session_token: &str,
        addresses: &[SocketAddr],
    ) -> Result<u64, RealmError> {
        let response: HeartbeatResponse = self
            .request_json(
                Method::POST,
                self.realm_url(realm_id, "/heartbeat"),
                session_token,
                Some(&HeartbeatRequest { addresses }),
            )
            .await?;
        Ok(response.ttl)
    }

    pub async fn connect(
        &self,
        realm_id: &str,
        addresses: &[SocketAddr],
        metadata: PunchMetadata,
    ) -> Result<RealmConnectResponse, RealmError> {
        let wire = PunchMetadataWire {
            addresses: addresses.to_vec(),
            nonce: hex::encode(metadata.nonce),
            obfs: hex::encode(metadata.obfuscation_key),
        };
        let response: PunchMetadataWire = self
            .request_json(
                Method::POST,
                self.realm_url(realm_id, "/connect"),
                &self.token,
                Some(&wire),
            )
            .await?;
        Ok(RealmConnectResponse {
            addresses: response.addresses,
            metadata: decode_metadata(&response.nonce, &response.obfs)?,
        })
    }

    pub async fn connect_response(
        &self,
        realm_id: &str,
        session_token: &str,
        nonce: &[u8; NONCE_LENGTH],
        addresses: &[SocketAddr],
    ) -> Result<(), RealmError> {
        self.request(
            Method::POST,
            self.realm_url(
                realm_id,
                &format!("/connects/{}", hex::encode(nonce)),
            ),
            session_token,
            Some(&AddressesRequest { addresses }),
        )
        .await?;
        Ok(())
    }

    pub async fn events(
        &self,
        realm_id: &str,
        session_token: &str,
    ) -> Result<RealmEventStream, RealmError> {
        let url = self.realm_url(realm_id, "/events");
        let response = match &self.client {
            RealmHttpBackend::Reqwest(client) => {
                let response = client
                    .get(url)
                    .bearer_auth(session_token)
                    .header(reqwest::header::ACCEPT, "text/event-stream")
                    .send()
                    .await?;
                if !response.status().is_success() {
                    let _ = read_response(response).await?;
                    unreachable!("non-success response returned an error")
                }
                RealmEventBody::Reqwest(response)
            }
            RealmHttpBackend::Dialer(client) => {
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {session_token}").parse().map_err(
                        |error: reqwest::header::InvalidHeaderValue| {
                            RealmError::Config(error.to_string())
                        },
                    )?,
                );
                headers.insert(
                    reqwest::header::ACCEPT,
                    reqwest::header::HeaderValue::from_static(
                        "text/event-stream",
                    ),
                );
                let response = client
                    .request_stream(
                        Method::GET,
                        &url,
                        &headers,
                        bytes::Bytes::new(),
                    )
                    .await
                    .map_err(|error| {
                        RealmError::HttpTransport(error.to_string())
                    })?;
                if !response.status.is_success() {
                    let _ = read_streaming_response(response).await?;
                    unreachable!("non-success response returned an error")
                }
                RealmEventBody::Dialer(Box::new(response))
            }
        };
        Ok(RealmEventStream {
            response,
            buffer: Vec::new(),
        })
    }
}

#[derive(Clone)]
pub struct RealmClientConnector {
    control: RealmControlClient,
    realm_id: String,
    stun_servers: Vec<String>,
    ip_version: i32,
    port_mapping: Option<RealmPortMappingOptions>,
    resolver: Option<(SharedResolver, crate::dns::LookupOptions)>,
}

#[derive(Debug)]
pub struct RealmConnectOutcome {
    pub peer_addr: SocketAddr,
    pub port_mapping: Option<RealmPortMapping>,
}

#[derive(Debug)]
pub struct RealmFamilyConnectOutcome {
    pub socket: Arc<RealmPacketSocket>,
    pub peer_addr: SocketAddr,
    pub port_mapping: Option<RealmPortMapping>,
}

impl RealmClientConnector {
    pub fn new(
        control: RealmControlClient,
        realm_id: impl Into<String>,
        stun_servers: Vec<String>,
        ip_version: i32,
    ) -> Result<Self, RealmError> {
        let realm_id = realm_id.into();
        if realm_id.is_empty() {
            return Err(RealmError::Config("realm ID is required".into()));
        }
        if stun_servers.is_empty() {
            return Err(RealmError::Config(
                "at least one STUN server is required".into(),
            ));
        }
        if !matches!(ip_version, 0 | 4 | 6) {
            return Err(RealmError::Config(format!(
                "invalid IP version: {ip_version}"
            )));
        }
        Ok(Self {
            control,
            realm_id,
            stun_servers,
            ip_version,
            port_mapping: None,
            resolver: None,
        })
    }

    pub fn with_port_mapping(
        mut self,
        options: RealmPortMappingOptions,
    ) -> Result<Self, RealmError> {
        if self.ip_version == 6 {
            return Err(RealmError::Config(
                "port mapping requires IPv4".into(),
            ));
        }
        self.port_mapping = Some(options);
        Ok(self)
    }

    pub fn with_resolver(
        mut self,
        resolver: SharedResolver,
        options: crate::dns::LookupOptions,
    ) -> Self {
        self.resolver = Some((resolver, options));
        self
    }

    pub fn route_destination(&self) -> Result<SocksAddr, RealmError> {
        let first = self.stun_servers.first().expect("validated STUN servers");
        let (host, port) = parse_stun_authority(first)?;
        Ok(SocksAddr::new(host, port))
    }

    pub fn uses_ipv6_socket(&self) -> bool {
        self.ip_version == 6
    }

    pub async fn route_destinations(
        &self,
    ) -> Result<Vec<(bool, SocksAddr)>, RealmError> {
        let servers = self.resolve_stun_servers().await?;
        let families: &[bool] = match self.ip_version {
            4 => &[true],
            6 => &[false],
            _ => &[true, false],
        };
        let destinations = families
            .iter()
            .filter_map(|ipv4| {
                servers
                    .iter()
                    .find(|server| server.is_ipv4() == *ipv4)
                    .copied()
                    .map(|server| (*ipv4, SocksAddr::Ip(server)))
            })
            .collect::<Vec<_>>();
        if destinations.is_empty() {
            return Err(RealmError::Response(
                "no STUN server matches an available address family".into(),
            ));
        }
        Ok(destinations)
    }

    pub async fn connect(
        &self,
        socket: Arc<RealmPacketSocket>,
    ) -> Result<RealmConnectOutcome, RealmError> {
        let stun_servers = self.resolve_stun_servers().await?;
        let mut port_mapping = if let Some(options) = self.port_mapping {
            let local_port = socket
                .local_addr()
                .map_err(|error| {
                    RealmError::PortMapping(format!(
                        "read local UDP address: {error}"
                    ))
                })?
                .port();
            // Upstream treats an unavailable gateway as non-fatal.
            RealmPortMapping::start(local_port, options).await.ok()
        } else {
            None
        };
        let mut addresses = socket.discover_stun(&stun_servers).await?;
        merge_mapped_address(&mut addresses, port_mapping.as_ref());
        let metadata = PunchMetadata::generate()?;
        let response = self
            .control
            .connect(&self.realm_id, &addresses, metadata)
            .await?;
        let response_addresses = response
            .addresses
            .into_iter()
            .filter(|address| {
                self.ip_version == 0
                    || address.is_ipv4() == (self.ip_version == 4)
            })
            .collect::<Vec<_>>();
        let peer_addr = socket
            .punch(&response_addresses, response.metadata)
            .await
            .map(|result| result.peer_addr)?;
        Ok(RealmConnectOutcome {
            peer_addr,
            port_mapping: port_mapping.take(),
        })
    }

    /// Discover and race one independently-bound socket per address family.
    /// This is the `ip_version: 0` path used by sing-quic: an unavailable
    /// family is discarded, and the first successful punch owns the QUIC
    /// session while all losing sockets are dropped.
    pub async fn connect_families(
        &self,
        families: Vec<(bool, Arc<RealmPacketSocket>)>,
    ) -> Result<RealmFamilyConnectOutcome, RealmError> {
        if families.is_empty() {
            return Err(RealmError::Response(
                "no UDP sockets available for Realm".into(),
            ));
        }
        let stun_servers = self.resolve_stun_servers().await?;
        let mapped_socket = families
            .iter()
            .find(|(ipv4, _)| *ipv4)
            .map(|(_, socket)| socket.clone());
        let mut port_mapping = if let (Some(options), Some(socket)) =
            (self.port_mapping, mapped_socket.as_ref())
        {
            RealmPortMapping::start(
                socket
                    .local_addr()
                    .map_err(|error| {
                        RealmError::PortMapping(format!(
                            "read local UDP address: {error}"
                        ))
                    })?
                    .port(),
                options,
            )
            .await
            .ok()
        } else {
            None
        };

        let discoveries = families.into_iter().map(|(ipv4, socket)| {
            let servers = stun_servers
                .iter()
                .filter(|server| server.is_ipv4() == ipv4)
                .copied()
                .collect::<Vec<_>>();
            async move {
                if servers.is_empty() {
                    return Err(format!(
                        "{}: no matching STUN servers",
                        if ipv4 { "v4" } else { "v6" }
                    ));
                }
                socket
                    .discover_stun(&servers)
                    .await
                    .map(|addresses| (ipv4, socket, addresses))
                    .map_err(|error| {
                        format!("{}: {error}", if ipv4 { "v4" } else { "v6" })
                    })
            }
        });
        let mut surviving = Vec::new();
        let mut discovery_errors = Vec::new();
        for result in futures_util::future::join_all(discoveries).await {
            match result {
                Ok(family) => surviving.push(family),
                Err(error) => discovery_errors.push(error),
            }
        }
        if surviving.is_empty() {
            return Err(RealmError::Response(format!(
                "Realm STUN discovery failed: {}",
                discovery_errors.join("; ")
            )));
        }
        let mapped_survived = mapped_socket.as_ref().is_some_and(|mapped| {
            surviving
                .iter()
                .any(|(_, socket, _)| Arc::ptr_eq(mapped, socket))
        });
        if !mapped_survived && let Some(mapping) = port_mapping.take() {
            mapping.close().await;
        }
        let mut local_addresses = surviving
            .iter()
            .flat_map(|(_, _, addresses)| addresses.iter().copied())
            .collect::<Vec<_>>();
        merge_mapped_address(&mut local_addresses, port_mapping.as_ref());
        let metadata = PunchMetadata::generate()?;
        let response = self
            .control
            .connect(&self.realm_id, &local_addresses, metadata)
            .await?;

        let mut punches = FuturesUnordered::new();
        for (ipv4, socket, _) in surviving {
            let peer_addresses = response
                .addresses
                .iter()
                .filter(|address| address.is_ipv4() == ipv4)
                .copied()
                .collect::<Vec<_>>();
            let metadata = response.metadata;
            punches.push(async move {
                socket
                    .punch(&peer_addresses, metadata)
                    .await
                    .map(|result| (ipv4, socket, result.peer_addr))
                    .map_err(|error| {
                        format!("{}: {error}", if ipv4 { "v4" } else { "v6" })
                    })
            });
        }
        let mut punch_errors = Vec::new();
        while let Some(result) = punches.next().await {
            match result {
                Ok((ipv4, socket, peer_addr)) => {
                    drop(punches);
                    if !ipv4 && let Some(mapping) = port_mapping.take() {
                        mapping.close().await;
                    }
                    return Ok(RealmFamilyConnectOutcome {
                        socket,
                        peer_addr,
                        port_mapping,
                    });
                }
                Err(error) => punch_errors.push(error),
            }
        }
        Err(RealmError::Response(format!(
            "Realm punch failed: {}",
            punch_errors.join("; ")
        )))
    }

    async fn resolve_stun_servers(
        &self,
    ) -> Result<Vec<SocketAddr>, RealmError> {
        let resolutions = self.stun_servers.iter().map(|server| async move {
            let (host, port) = parse_stun_authority(server)?;
            if let Ok(address) = host.parse::<IpAddr>() {
                return Ok(vec![SocketAddr::new(address, port)]);
            }
            if let Some((resolver, options)) = &self.resolver {
                return resolver
                    .lookup_with_options(&host, *options)
                    .await
                    .map(|addresses| {
                        addresses
                            .into_iter()
                            .map(|address| SocketAddr::new(address, port))
                            .collect()
                    })
                    .map_err(|error| {
                        RealmError::Response(format!(
                            "resolve STUN server {server}: {error}"
                        ))
                    });
            }
            tokio::net::lookup_host((host.as_str(), port))
                .await
                .map(|addresses| addresses.collect::<Vec<_>>())
                .map_err(|error| {
                    RealmError::Response(format!(
                        "resolve STUN server {server}: {error}"
                    ))
                })
        });
        let mut resolved = Vec::new();
        for result in futures_util::future::join_all(resolutions).await {
            for address in result? {
                if self.ip_version == 0
                    || address.is_ipv4() == (self.ip_version == 4)
                {
                    resolved.push(address);
                }
            }
        }
        if resolved.is_empty() {
            return Err(RealmError::Response(
                "no STUN servers resolved".into(),
            ));
        }
        Ok(resolved)
    }
}

#[derive(Clone)]
pub struct RealmServerConnector {
    inner: RealmClientConnector,
}

#[derive(Debug, Default)]
struct RealmStunCache {
    addresses: Vec<SocketAddr>,
    updated_at: Option<Instant>,
}

async fn invalidate_stun_cache(cache: &tokio::sync::Mutex<RealmStunCache>) {
    // Keep the last successful addresses as a stale fallback, matching
    // sing-quic's reset behavior, but force the next lookup through STUN.
    cache.lock().await.updated_at = None;
}

async fn discover_server_addresses(
    socket: &Arc<RealmPacketSocket>,
    stun_servers: &[SocketAddr],
    cache: &tokio::sync::Mutex<RealmStunCache>,
    mapped_address: Option<SocketAddr>,
) -> Result<Vec<SocketAddr>, RealmError> {
    // Holding this mutex across discovery deliberately provides the same
    // single-flight behavior as the Go implementation.
    let mut cache = cache.lock().await;
    if cache
        .updated_at
        .is_some_and(|at| at.elapsed() < CONNECT_STUN_CACHE_TTL)
        && !cache.addresses.is_empty()
    {
        let mut addresses = cache.addresses.clone();
        merge_address(&mut addresses, mapped_address);
        return Ok(addresses);
    }
    match socket.discover_stun_demuxed(stun_servers).await {
        Ok(addresses) => {
            cache.addresses = addresses.clone();
            cache.updated_at = Some(Instant::now());
            let mut addresses = addresses;
            merge_address(&mut addresses, mapped_address);
            Ok(addresses)
        }
        Err(_error) if !cache.addresses.is_empty() => {
            let mut addresses = cache.addresses.clone();
            merge_address(&mut addresses, mapped_address);
            Ok(addresses)
        }
        Err(error) => Err(error),
    }
}

impl RealmServerConnector {
    pub fn new(
        control: RealmControlClient,
        realm_id: impl Into<String>,
        stun_servers: Vec<String>,
        ip_version: i32,
    ) -> Result<Self, RealmError> {
        Ok(Self {
            inner: RealmClientConnector::new(
                control,
                realm_id,
                stun_servers,
                ip_version,
            )?,
        })
    }

    pub fn route_destination(&self) -> Result<SocksAddr, RealmError> {
        self.inner.route_destination()
    }

    pub fn uses_ipv6_socket(&self) -> bool {
        self.inner.uses_ipv6_socket()
    }

    pub fn with_port_mapping(
        mut self,
        options: RealmPortMappingOptions,
    ) -> Result<Self, RealmError> {
        self.inner = self.inner.with_port_mapping(options)?;
        Ok(self)
    }

    pub fn with_resolver(
        mut self,
        resolver: SharedResolver,
        options: crate::dns::LookupOptions,
    ) -> Self {
        self.inner = self.inner.with_resolver(resolver, options);
        self
    }

    pub async fn run(
        &self,
        socket: Arc<RealmPacketSocket>,
        cancellation: CancellationToken,
    ) -> Result<(), RealmError> {
        let stun_servers = self.inner.resolve_stun_servers().await?;
        let mut port_mapping = if let Some(options) = self.inner.port_mapping {
            let local_port = socket
                .local_addr()
                .map_err(|error| {
                    RealmError::PortMapping(format!(
                        "read local UDP address: {error}"
                    ))
                })?
                .port();
            RealmPortMapping::start(local_port, options).await.ok()
        } else {
            None
        };
        let stun_cache =
            Arc::new(tokio::sync::Mutex::new(RealmStunCache::default()));
        // sing-box calls realm.Server.Reset from its network-change callback.
        // netwatch supplies the same signal for this standalone Rust service.
        // Monitoring is best-effort: failure to install it must not prevent a
        // Realm session from operating on otherwise usable interfaces.
        let network_monitor =
            crate::common::network_monitor::NetworkMonitor::new()
                .await
                .ok();
        let mut interface_watcher = network_monitor
            .as_ref()
            .map(|monitor| monitor.interface_state());
        let mut last_interface_state =
            interface_watcher.as_mut().map(n0_watcher::Watcher::get);
        let mut addresses = loop {
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                result = discover_server_addresses(
                    &socket,
                    &stun_servers,
                    &stun_cache,
                    port_mapping.as_ref().and_then(RealmPortMapping::external_addr),
                ) => {
                    match result {
                        Ok(addresses) => break addresses,
                        Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                    }
                }
            }
        };
        let mut registration = loop {
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                result = self.inner.control.register(&self.inner.realm_id, &addresses) => {
                    match result {
                        Ok(registration) => break registration,
                        Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                    }
                }
            }
        };
        let mut sse_backoff = SSE_BACKOFF_MIN;
        'session: loop {
            let mut events = match self
                .inner
                .control
                .events(&self.inner.realm_id, &registration.session_id)
                .await
            {
                Ok(events) => {
                    sse_backoff = SSE_BACKOFF_MIN;
                    events
                }
                Err(_) => {
                    tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = tokio::time::sleep(sse_backoff) => {
                            sse_backoff = (sse_backoff * 2).min(SSE_BACKOFF_MAX);
                            continue;
                        },
                    }
                }
            };
            let mut published_addresses = addresses.clone();
            let heartbeat = tokio::time::sleep(Duration::from_secs(
                (registration.ttl / 2).max(1),
            ));
            tokio::pin!(heartbeat);
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break 'session,
                    _ = &mut heartbeat => {
                        let mut current_addresses = addresses.clone();
                        merge_mapped_address(
                            &mut current_addresses,
                            port_mapping.as_ref(),
                        );
                        let changed = current_addresses != published_addresses;
                        match self.inner.control.heartbeat(
                            &self.inner.realm_id,
                            &registration.session_id,
                            if changed { &current_addresses } else { &[] },
                        ).await {
                            Ok(ttl) => {
                                registration.ttl = ttl;
                                if changed {
                                    addresses = current_addresses.clone();
                                    published_addresses = current_addresses;
                                }
                            }
                            Err(RealmError::Status {
                                status: StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND,
                                ..
                            }) => {
                                registration = self.inner.control.register(
                                    &self.inner.realm_id,
                                    &current_addresses,
                                ).await?;
                                addresses = current_addresses;
                                continue 'session;
                            }
                            Err(_) => {}
                        }
                        heartbeat.as_mut().reset(
                            tokio::time::Instant::now()
                                + Duration::from_secs((registration.ttl / 2).max(1)),
                        );
                    }
                    mapping = async {
                        match port_mapping.as_mut() {
                            Some(mapping) => mapping.changed().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        if mapping.is_err() {
                            port_mapping = None;
                        }
                    }
                    network_state = async {
                        match interface_watcher.as_mut() {
                            Some(watcher) => watcher.updated().await.ok(),
                            None => std::future::pending::<Option<netwatch::netmon::State>>().await,
                        }
                    } => {
                        let Some(network_state) = network_state else {
                            interface_watcher = None;
                            continue;
                        };
                        let is_major_change = last_interface_state
                            .as_ref()
                            .is_none_or(|previous| network_state.is_major_change(previous));
                        last_interface_state = Some(network_state);
                        if !is_major_change {
                            continue;
                        }
                        invalidate_stun_cache(&stun_cache).await;
                        if let Ok(fresh_addresses) = discover_server_addresses(
                            &socket,
                            &stun_servers,
                            &stun_cache,
                            port_mapping
                                .as_ref()
                                .and_then(RealmPortMapping::external_addr),
                        ).await {
                            addresses = fresh_addresses;
                            // Publish the refreshed path without waiting for
                            // half of the old session TTL to elapse.
                            heartbeat.as_mut().reset(tokio::time::Instant::now());
                        }
                    }
                    event = events.next() => {
                        let event = match event {
                            Ok(event) => event,
                            Err(_) => {
                                tokio::select! {
                                    _ = cancellation.cancelled() => break 'session,
                                    _ = tokio::time::sleep(SSE_BACKOFF_MIN) => break,
                                }
                            },
                        };
                        let control = self.inner.control.clone();
                        let realm_id = self.inner.realm_id.clone();
                        let session_id = registration.session_id.clone();
                        let fallback_addresses = addresses.clone();
                        let socket = socket.clone();
                        let stun_servers = stun_servers.clone();
                        let stun_cache = stun_cache.clone();
                        let mapped_address = port_mapping
                            .as_ref()
                            .and_then(RealmPortMapping::external_addr);
                        tokio::spawn(async move {
                            let fresh_addresses = discover_server_addresses(
                                &socket,
                                &stun_servers,
                                &stun_cache,
                                mapped_address,
                            )
                            .await
                            .unwrap_or(fallback_addresses);
                            if !fresh_addresses.is_empty() {
                                let _ = control.connect_response(
                                    &realm_id,
                                    &session_id,
                                    &event.metadata.nonce,
                                    &fresh_addresses,
                                ).await;
                            }
                            let _ = socket.punch_demuxed(
                                &event.addresses,
                                event.metadata,
                            ).await;
                        });
                    }
                }
            }
        }
        let _ = self
            .inner
            .control
            .deregister(&self.inner.realm_id, &registration.session_id)
            .await;
        if let Some(mapping) = port_mapping {
            mapping.close().await;
        }
        Ok(())
    }
}

fn merge_mapped_address(
    addresses: &mut Vec<SocketAddr>,
    mapping: Option<&RealmPortMapping>,
) {
    merge_address(addresses, mapping.and_then(RealmPortMapping::external_addr));
}

fn merge_address(addresses: &mut Vec<SocketAddr>, address: Option<SocketAddr>) {
    if let Some(address) = address
        && !addresses.contains(&address)
    {
        addresses.push(address);
    }
}

fn parse_stun_authority(server: &str) -> Result<(String, u16), RealmError> {
    if let Ok(address) = server.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    if let Ok(address) = server.parse::<IpAddr>() {
        return Ok((address.to_string(), 3478));
    }
    if let Some(host) = server
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        && let Ok(address) = host.parse::<Ipv6Addr>()
    {
        return Ok((address.to_string(), 3478));
    }
    if server.matches(':').count() <= 1
        && let Some((host, port)) = server.rsplit_once(':')
    {
        let port = port.parse::<u16>().map_err(|error| {
            RealmError::Config(format!("resolve STUN port {port}: {error}"))
        })?;
        if host.is_empty() {
            return Err(RealmError::Config("empty STUN server host".into()));
        }
        return Ok((host.to_owned(), port));
    }
    if server.is_empty() {
        return Err(RealmError::Config("empty STUN server".into()));
    }
    Ok((server.to_owned(), 3478))
}

enum RealmEventBody {
    Reqwest(reqwest::Response),
    Dialer(Box<StreamingResponse>),
}

pub struct RealmEventStream {
    response: RealmEventBody,
    buffer: Vec<u8>,
}

impl RealmEventStream {
    pub async fn next(&mut self) -> Result<RealmPunchEvent, RealmError> {
        loop {
            while let Some(record_end) = find_event_end(&self.buffer) {
                let record =
                    self.buffer.drain(..record_end).collect::<Vec<_>>();
                let delimiter_length = if self.buffer.starts_with(b"\r\n\r\n") {
                    4
                } else {
                    2
                };
                self.buffer.drain(..delimiter_length);
                if let Some(event) = parse_event(&record)? {
                    return Ok(event);
                }
            }
            let chunk = match &mut self.response {
                RealmEventBody::Reqwest(response) => response.chunk().await?,
                RealmEventBody::Dialer(response) => {
                    response.chunk().await.map_err(|error| {
                        RealmError::HttpTransport(error.to_string())
                    })?
                }
            }
            .ok_or_else(|| {
                RealmError::Response("event stream closed".into())
            })?;
            if self
                .buffer
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > MAX_EVENT_SIZE)
            {
                return Err(RealmError::Response(
                    "event stream record exceeds 64 KiB".into(),
                ));
            }
            self.buffer.extend_from_slice(&chunk);
        }
    }
}

async fn read_response(
    response: reqwest::Response,
) -> Result<Vec<u8>, RealmError> {
    let status = response.status();
    let bytes = response.bytes().await?.to_vec();
    decode_response(status, bytes)
}

async fn read_streaming_response(
    response: StreamingResponse,
) -> Result<Vec<u8>, RealmError> {
    let status = response.status;
    let bytes = response
        .collect(16 * 1024 * 1024)
        .await
        .map_err(|error| RealmError::HttpTransport(error.to_string()))?
        .to_vec();
    decode_response(status, bytes)
}

fn decode_response(
    status: StatusCode,
    bytes: Vec<u8>,
) -> Result<Vec<u8>, RealmError> {
    if status.is_success() {
        return Ok(bytes);
    }
    let error = serde_json::from_slice::<ErrorResponse>(
        &bytes[..bytes.len().min(MAX_ERROR_BODY_SIZE)],
    )
    .unwrap_or(ErrorResponse {
        error: String::new(),
        message: String::new(),
    });
    Err(RealmError::Status {
        status,
        code: error.error,
        message: error.message,
    })
}

fn find_event_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(2)
        .position(|window| window == b"\n\n")
        .or_else(|| buffer.windows(4).position(|window| window == b"\r\n\r\n"))
}

fn parse_event(record: &[u8]) -> Result<Option<RealmPunchEvent>, RealmError> {
    let record = String::from_utf8_lossy(record);
    let mut event_type = "";
    let mut data = String::new();
    for line in record.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with(':') {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match field {
            "event" => event_type = value,
            "data" => {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(value);
            }
            _ => {}
        }
    }
    if event_type != "punch" || data.is_empty() {
        return Ok(None);
    }
    let wire: PunchMetadataWire =
        serde_json::from_str(&data).map_err(|error| {
            RealmError::Response(format!("decode punch event: {error}"))
        })?;
    Ok(Some(RealmPunchEvent {
        addresses: wire.addresses,
        metadata: decode_metadata(&wire.nonce, &wire.obfs)?,
    }))
}

fn decode_metadata(
    nonce: &str,
    obfs: &str,
) -> Result<PunchMetadata, RealmError> {
    let nonce = hex::decode(nonce).map_err(|error| {
        RealmError::Response(format!("decode nonce: {error}"))
    })?;
    let obfs = hex::decode(obfs).map_err(|error| {
        RealmError::Response(format!("decode obfs: {error}"))
    })?;
    Ok(PunchMetadata {
        nonce: nonce.try_into().map_err(|value: Vec<u8>| {
            RealmError::Response(format!(
                "invalid nonce length: {}",
                value.len()
            ))
        })?,
        obfuscation_key: obfs.try_into().map_err(|value: Vec<u8>| {
            RealmError::Response(format!(
                "invalid obfs length: {}",
                value.len()
            ))
        })?,
    })
}

pub fn encode_punch_packet(
    packet_type: u8,
    metadata: PunchMetadata,
) -> Result<Vec<u8>, RealmError> {
    let mut random = [0_u8; SALT_LENGTH + 2 + MAX_PADDING];
    getrandom::fill(&mut random)
        .map_err(|error| RealmError::Entropy(error.to_string()))?;
    encode_punch_packet_with_random(packet_type, metadata, &random)
}

fn encode_punch_packet_with_random(
    packet_type: u8,
    metadata: PunchMetadata,
    random: &[u8; SALT_LENGTH + 2 + MAX_PADDING],
) -> Result<Vec<u8>, RealmError> {
    if packet_type != PUNCH_HELLO && packet_type != PUNCH_ACK {
        return Err(RealmError::Punch(format!(
            "unknown punch type: {packet_type}"
        )));
    }
    let padding_length = ((usize::from(random[SALT_LENGTH]) << 8)
        | usize::from(random[SALT_LENGTH + 1]))
        % (MAX_PADDING + 1);
    let mut packet = vec![0_u8; SALT_LENGTH + MIN_BODY_SIZE + padding_length];
    packet[..SALT_LENGTH].copy_from_slice(&random[..SALT_LENGTH]);
    let body = &mut packet[SALT_LENGTH..];
    body[..MAGIC_LENGTH].copy_from_slice(&PUNCH_MAGIC);
    body[MAGIC_LENGTH] = packet_type;
    body[MAGIC_LENGTH + 1..MAGIC_LENGTH + 1 + NONCE_LENGTH]
        .copy_from_slice(&metadata.nonce);
    if padding_length > 0 {
        body[MIN_BODY_SIZE..].copy_from_slice(
            &random[SALT_LENGTH + 2..SALT_LENGTH + 2 + padding_length],
        );
    }
    xor_obfuscate(metadata.obfuscation_key, &mut packet);
    Ok(packet)
}

pub fn decode_punch_packet(
    data: &[u8],
    metadata: PunchMetadata,
) -> Result<u8, RealmError> {
    if data.len() < MIN_PACKET_LENGTH {
        return Err(RealmError::Punch("packet too short".into()));
    }
    if data.len() > SALT_LENGTH + MIN_BODY_SIZE + MAX_PADDING {
        return Err(RealmError::Punch("packet too long".into()));
    }
    let mut packet = data.to_vec();
    xor_obfuscate(metadata.obfuscation_key, &mut packet);
    let body = &packet[SALT_LENGTH..];
    if body[..MAGIC_LENGTH] != PUNCH_MAGIC {
        return Err(RealmError::Punch("magic mismatch".into()));
    }
    let packet_type = body[MAGIC_LENGTH];
    if packet_type != PUNCH_HELLO && packet_type != PUNCH_ACK {
        return Err(RealmError::Punch(format!(
            "unknown punch type: {packet_type}"
        )));
    }
    if body[MAGIC_LENGTH + 1..MAGIC_LENGTH + 1 + NONCE_LENGTH] != metadata.nonce
    {
        return Err(RealmError::Punch("nonce mismatch".into()));
    }
    Ok(packet_type)
}

fn xor_obfuscate(obfuscation_key: [u8; 32], packet: &mut [u8]) {
    let (salt, body) = packet.split_at_mut(SALT_LENGTH);
    let mut hasher = Sha256::new();
    hasher.update(obfuscation_key);
    hasher.update(salt);
    let key = hasher.finalize();
    for (index, byte) in body.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

pub fn candidate_punch_addresses(
    peer_addresses: &[SocketAddr],
) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut candidates = peer_addresses
        .iter()
        .copied()
        .filter(|address| address.port() != 0 && seen.insert(*address))
        .collect::<Vec<_>>();
    let mut ports_by_ip = HashMap::<Ipv4Addr, Vec<u16>>::new();
    for address in &candidates {
        if let IpAddr::V4(ip) = address.ip() {
            ports_by_ip.entry(ip).or_default().push(address.port());
        }
    }
    for (ip, mut ports) in ports_by_ip {
        ports.sort_unstable();
        ports.dedup();
        if ports.len() < 2 || ports.windows(2).any(|pair| pair[1] - pair[0] > 4)
        {
            continue;
        }
        let start = usize::from(ports[0]);
        let end = usize::from(*ports.last().expect("non-empty ports"))
            .saturating_add(4)
            .min(65_535);
        let mut added = 0;
        for port in start..=end {
            let address = SocketAddr::new(
                IpAddr::V4(ip),
                u16::try_from(port).expect("port bounded to u16"),
            );
            if seen.insert(address) {
                candidates.push(address);
                added += 1;
                if added >= 32 {
                    break;
                }
            }
        }
    }
    candidates
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchResult {
    pub peer_addr: SocketAddr,
    pub packet_type: u8,
}

struct PunchAttempt {
    metadata: PunchMetadata,
    sender: mpsc::UnboundedSender<PunchResult>,
}

struct StunEvent {
    message: Vec<u8>,
}

/// A Quinn socket that consumes Realm STUN and authenticated punch packets
/// before forwarding ordinary QUIC datagrams to Quinn.
pub struct RealmPacketSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    attempts: Mutex<HashMap<String, PunchAttempt>>,
    stun_sender: mpsc::UnboundedSender<StunEvent>,
    stun_receiver: tokio::sync::Mutex<mpsc::UnboundedReceiver<StunEvent>>,
}

impl fmt::Debug for RealmPacketSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealmPacketSocket")
            .field("local_addr", &self.inner.local_addr())
            .finish_non_exhaustive()
    }
}

impl RealmPacketSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>) -> Arc<Self> {
        let (stun_sender, stun_receiver) = mpsc::unbounded_channel();
        Arc::new(Self {
            inner,
            attempts: Mutex::new(HashMap::new()),
            stun_sender,
            stun_receiver: tokio::sync::Mutex::new(stun_receiver),
        })
    }

    pub async fn send_to(
        &self,
        destination: SocketAddr,
        contents: &[u8],
    ) -> io::Result<()> {
        let transmit = Transmit {
            destination,
            ecn: None,
            contents,
            segment_size: None,
            src_ip: None,
        };
        loop {
            match self.inner.try_send(&transmit) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut poller = self.inner.clone().create_io_poller();
                    poll_fn(|context| poller.as_mut().poll_writable(context))
                        .await?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn receive_raw(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut buffer = vec![0_u8; 65_535];
        let mut metadata = [RecvMeta {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];
        poll_fn(|context| {
            let mut buffers = [IoSliceMut::new(&mut buffer)];
            self.inner.poll_recv(context, &mut buffers, &mut metadata)
        })
        .await?;
        buffer.truncate(metadata[0].len);
        Ok((buffer, metadata[0].addr))
    }

    pub async fn discover_stun(
        &self,
        servers: &[SocketAddr],
    ) -> Result<Vec<SocketAddr>, RealmError> {
        if servers.is_empty() {
            return Err(RealmError::Config("no STUN servers".into()));
        }
        let requests = servers
            .iter()
            .map(|server| Ok((*server, StunBindingRequest::generate()?)))
            .collect::<Result<Vec<_>, RealmError>>()?;
        let mut pending = requests
            .iter()
            .map(|(_, request)| request.transaction_id)
            .collect::<HashSet<_>>();
        let mut seen = HashSet::new();
        let mut addresses = Vec::new();
        for attempt_timeout in [
            Duration::from_millis(500),
            Duration::from_secs(2),
            Duration::from_secs(4),
        ] {
            if pending.is_empty() {
                break;
            }
            for (server, request) in &requests {
                if pending.contains(&request.transaction_id) {
                    self.send_to(*server, &request.message).await.map_err(
                        |error| {
                            RealmError::Response(format!(
                                "send STUN request to {server}: {error}"
                            ))
                        },
                    )?;
                }
            }
            let deadline = tokio::time::Instant::now() + attempt_timeout;
            while !pending.is_empty() {
                let (message, _source) =
                    match tokio::time::timeout_at(deadline, self.receive_raw())
                        .await
                    {
                        Ok(Ok(event)) => event,
                        Ok(Err(error)) => {
                            return Err(RealmError::Response(format!(
                                "read STUN response: {error}"
                            )));
                        }
                        Err(_) => break,
                    };
                let Some(transaction_id) = stun_transaction_id(&message) else {
                    continue;
                };
                if !pending.remove(&transaction_id) {
                    continue;
                }
                if let Ok(address) =
                    decode_stun_xor_mapped_address(&message, transaction_id)
                    && seen.insert(address)
                {
                    addresses.push(address);
                }
            }
        }
        if addresses.is_empty() {
            return Err(RealmError::Response(
                "no STUN responses received".into(),
            ));
        }
        Ok(addresses)
    }

    pub async fn discover_stun_demuxed(
        &self,
        servers: &[SocketAddr],
    ) -> Result<Vec<SocketAddr>, RealmError> {
        if servers.is_empty() {
            return Err(RealmError::Config("no STUN servers".into()));
        }
        let requests = servers
            .iter()
            .map(|server| Ok((*server, StunBindingRequest::generate()?)))
            .collect::<Result<Vec<_>, RealmError>>()?;
        let mut pending = requests
            .iter()
            .map(|(_, request)| request.transaction_id)
            .collect::<HashSet<_>>();
        let mut receiver = self.stun_receiver.lock().await;
        let mut seen = HashSet::new();
        let mut addresses = Vec::new();
        for attempt_timeout in [
            Duration::from_millis(500),
            Duration::from_secs(2),
            Duration::from_secs(4),
        ] {
            if pending.is_empty() {
                break;
            }
            for (server, request) in &requests {
                if pending.contains(&request.transaction_id) {
                    self.send_to(*server, &request.message).await.map_err(
                        |error| {
                            RealmError::Response(format!(
                                "send STUN request to {server}: {error}"
                            ))
                        },
                    )?;
                }
            }
            let deadline = tokio::time::Instant::now() + attempt_timeout;
            while !pending.is_empty() {
                let event =
                    match tokio::time::timeout_at(deadline, receiver.recv())
                        .await
                    {
                        Ok(Some(event)) => event,
                        Ok(None) => {
                            return Err(RealmError::Response(
                                "STUN event channel closed".into(),
                            ));
                        }
                        Err(_) => break,
                    };
                let Some(transaction_id) = stun_transaction_id(&event.message)
                else {
                    continue;
                };
                if !pending.remove(&transaction_id) {
                    continue;
                }
                if let Ok(address) = decode_stun_xor_mapped_address(
                    &event.message,
                    transaction_id,
                ) && seen.insert(address)
                {
                    addresses.push(address);
                }
            }
        }
        if addresses.is_empty() {
            return Err(RealmError::Response(
                "no STUN responses received".into(),
            ));
        }
        Ok(addresses)
    }

    pub async fn punch(
        &self,
        peer_addresses: &[SocketAddr],
        metadata: PunchMetadata,
    ) -> Result<PunchResult, RealmError> {
        let candidates = candidate_punch_addresses(peer_addresses);
        if candidates.is_empty() {
            return Err(RealmError::Punch(
                "no compatible peer addresses".into(),
            ));
        }
        let deadline = tokio::time::Instant::now() + PUNCH_TIMEOUT;
        loop {
            let hello = encode_punch_packet(PUNCH_HELLO, metadata)?;
            for address in &candidates {
                self.send_to(*address, &hello).await.map_err(|error| {
                    RealmError::Punch(format!(
                        "send punch packet to {address}: {error}"
                    ))
                })?;
            }
            let interval_deadline =
                (tokio::time::Instant::now() + PUNCH_INTERVAL).min(deadline);
            loop {
                let (data, peer_addr) = match tokio::time::timeout_at(
                    interval_deadline,
                    self.receive_raw(),
                )
                .await
                {
                    Ok(Ok(event)) => event,
                    Ok(Err(error)) => {
                        return Err(RealmError::Punch(format!(
                            "read punch packet: {error}"
                        )));
                    }
                    Err(_) if tokio::time::Instant::now() >= deadline => {
                        return Err(RealmError::Punch("punch timeout".into()));
                    }
                    Err(_) => break,
                };
                let Ok(packet_type) = decode_punch_packet(&data, metadata)
                else {
                    continue;
                };
                if packet_type == PUNCH_HELLO {
                    let ack = encode_punch_packet(PUNCH_ACK, metadata)?;
                    self.send_to(peer_addr, &ack).await.map_err(|error| {
                        RealmError::Punch(format!(
                            "send punch ack to {peer_addr}: {error}"
                        ))
                    })?;
                }
                return Ok(PunchResult {
                    peer_addr,
                    packet_type,
                });
            }
        }
    }

    pub async fn punch_demuxed(
        &self,
        peer_addresses: &[SocketAddr],
        metadata: PunchMetadata,
    ) -> Result<PunchResult, RealmError> {
        let candidates = candidate_punch_addresses(peer_addresses);
        if candidates.is_empty() {
            return Err(RealmError::Punch(
                "no compatible peer addresses".into(),
            ));
        }
        let mut id_bytes = [0_u8; 8];
        getrandom::fill(&mut id_bytes)
            .map_err(|error| RealmError::Entropy(error.to_string()))?;
        let attempt_id = hex::encode(id_bytes);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        self.attempts
            .lock()
            .map_err(|_| RealmError::Punch("attempt lock poisoned".into()))?
            .insert(attempt_id.clone(), PunchAttempt { metadata, sender });

        let result = async {
            let deadline = tokio::time::Instant::now() + PUNCH_TIMEOUT;
            loop {
                let hello = encode_punch_packet(PUNCH_HELLO, metadata)?;
                for address in &candidates {
                    self.send_to(*address, &hello).await.map_err(|error| {
                        RealmError::Punch(format!(
                            "send punch packet to {address}: {error}"
                        ))
                    })?;
                }
                match tokio::time::timeout_at(
                    (tokio::time::Instant::now() + PUNCH_INTERVAL)
                        .min(deadline),
                    receiver.recv(),
                )
                .await
                {
                    Ok(Some(event)) => {
                        if event.packet_type == PUNCH_HELLO {
                            let ack = encode_punch_packet(PUNCH_ACK, metadata)?;
                            self.send_to(event.peer_addr, &ack).await.map_err(
                                |error| {
                                    RealmError::Punch(format!(
                                        "send punch ack to {}: {error}",
                                        event.peer_addr
                                    ))
                                },
                            )?;
                        }
                        return Ok(event);
                    }
                    Ok(None) => {
                        return Err(RealmError::Punch(
                            "punch event channel closed".into(),
                        ));
                    }
                    Err(_) if tokio::time::Instant::now() >= deadline => {
                        return Err(RealmError::Punch("punch timeout".into()));
                    }
                    Err(_) => {}
                }
            }
        }
        .await;
        self.attempts
            .lock()
            .map_err(|_| RealmError::Punch("attempt lock poisoned".into()))?
            .remove(&attempt_id);
        result
    }
}

impl AsyncUdpSocket for RealmPacketSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        context: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let received =
                match self.inner.poll_recv(context, buffers, metadata) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result?,
                };
            let mut ordinary = Vec::new();
            for index in 0..received {
                let data = buffers[index][..metadata[index].len].to_vec();
                let source = metadata[index].addr;
                if stun_transaction_id(&data).is_some() {
                    let _ = self.stun_sender.send(StunEvent { message: data });
                    continue;
                }
                let matched = {
                    let attempts = self.attempts.lock().map_err(|_| {
                        io::Error::other("Realm attempt lock poisoned")
                    })?;
                    attempts.values().find_map(|attempt| {
                        decode_punch_packet(&data, attempt.metadata).ok().map(
                            |packet_type| (attempt.sender.clone(), packet_type),
                        )
                    })
                };
                if let Some((sender, packet_type)) = matched {
                    let _ = sender.send(PunchResult {
                        peer_addr: source,
                        packet_type,
                    });
                    continue;
                }
                ordinary.push((data, metadata[index]));
            }
            if ordinary.is_empty() {
                continue;
            }
            let ordinary_count = ordinary.len();
            for (index, (data, meta)) in ordinary.into_iter().enumerate() {
                if data.len() > buffers[index].len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Realm datagram exceeds receive buffer",
                    )));
                }
                buffers[index][..data.len()].copy_from_slice(&data);
                metadata[index] = meta;
            }
            return Poll::Ready(Ok(ordinary_count));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunBindingRequest {
    pub transaction_id: [u8; 12],
    pub message: [u8; 20],
}

fn stun_transaction_id(message: &[u8]) -> Option<[u8; 12]> {
    if message.len() < 20
        || message[0] & 0xc0 != 0
        || message[4..8] != 0x2112_A442_u32.to_be_bytes()
    {
        return None;
    }
    let declared = usize::from(u16::from_be_bytes([message[2], message[3]]));
    if declared > message.len() - 20 {
        return None;
    }
    message[8..20].try_into().ok()
}

impl StunBindingRequest {
    pub fn generate() -> Result<Self, RealmError> {
        let mut transaction_id = [0_u8; 12];
        getrandom::fill(&mut transaction_id)
            .map_err(|error| RealmError::Entropy(error.to_string()))?;
        Ok(Self::new(transaction_id))
    }

    pub fn new(transaction_id: [u8; 12]) -> Self {
        let mut message = [0_u8; 20];
        message[..2].copy_from_slice(&0x0001_u16.to_be_bytes());
        message[4..8].copy_from_slice(&0x2112_A442_u32.to_be_bytes());
        message[8..].copy_from_slice(&transaction_id);
        Self {
            transaction_id,
            message,
        }
    }
}

pub fn decode_stun_xor_mapped_address(
    message: &[u8],
    transaction_id: [u8; 12],
) -> Result<SocketAddr, RealmError> {
    if message.len() < 20
        || message[4..8] != 0x2112_A442_u32.to_be_bytes()
        || message[8..20] != transaction_id
    {
        return Err(RealmError::Response(
            "invalid STUN response header".into(),
        ));
    }
    let declared = usize::from(u16::from_be_bytes([message[2], message[3]]));
    if declared > message.len() - 20 {
        return Err(RealmError::Response(
            "truncated STUN response attributes".into(),
        ));
    }
    let mut offset = 20;
    let end = 20 + declared;
    while offset + 4 <= end {
        let kind = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([
            message[offset + 2],
            message[offset + 3],
        ]));
        let value_start = offset + 4;
        let value_end = value_start.checked_add(length).ok_or_else(|| {
            RealmError::Response("invalid STUN attribute length".into())
        })?;
        if value_end > end {
            return Err(RealmError::Response(
                "truncated STUN attribute".into(),
            ));
        }
        if kind == 0x0020 {
            return decode_xor_address(
                &message[value_start..value_end],
                transaction_id,
            );
        }
        offset =
            value_end.checked_add((4 - length % 4) % 4).ok_or_else(|| {
                RealmError::Response("invalid STUN attribute padding".into())
            })?;
    }
    Err(RealmError::Response(
        "STUN response has no XOR-MAPPED-ADDRESS".into(),
    ))
}

fn decode_xor_address(
    value: &[u8],
    transaction_id: [u8; 12],
) -> Result<SocketAddr, RealmError> {
    if value.len() < 4 {
        return Err(RealmError::Response(
            "truncated XOR-MAPPED-ADDRESS".into(),
        ));
    }
    let cookie = 0x2112_A442_u32.to_be_bytes();
    let port = u16::from_be_bytes([value[2], value[3]])
        ^ u16::from_be_bytes([cookie[0], cookie[1]]);
    let ip = match value[1] {
        0x01 if value.len() == 8 => IpAddr::V4(Ipv4Addr::new(
            value[4] ^ cookie[0],
            value[5] ^ cookie[1],
            value[6] ^ cookie[2],
            value[7] ^ cookie[3],
        )),
        0x02 if value.len() == 20 => {
            let mut mask = [0_u8; 16];
            mask[..4].copy_from_slice(&cookie);
            mask[4..].copy_from_slice(&transaction_id);
            let mut address = [0_u8; 16];
            for index in 0..16 {
                address[index] = value[4 + index] ^ mask[index];
            }
            IpAddr::V6(Ipv6Addr::from(address))
        }
        _ => {
            return Err(RealmError::Response(
                "invalid XOR-MAPPED-ADDRESS family or length".into(),
            ));
        }
    };
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use quinn::{AsyncUdpSocket, Runtime as _};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::{
        adapter::{DialFuture, Dialer},
        common::{
            lifecycle::{Lifecycle, StartStage},
            network::SocksAddr,
            tls::{build_client_config, build_server_config_with_default_alpn},
        },
        option::{
            DirectOutboundOptions, HysteriaRealmServiceOptions,
            InboundTlsOptions, OutboundTlsOptions,
        },
        protocol::{
            direct::DirectOutbound,
            hysteria2::{
                Hysteria2Outbound, Hysteria2ServerSession, encode_tcp_response,
                hysteria2_server_endpoint_with_transport_obfs_socket,
            },
        },
        service::hysteria_realm::HysteriaRealmService,
    };

    fn metadata() -> PunchMetadata {
        PunchMetadata {
            nonce: *b"0123456789abcdef",
            obfuscation_key: [0x5a; 32],
        }
    }

    #[test]
    fn port_mapping_defaults_and_ipv6_validation_match_upstream() {
        let defaults = RealmPortMappingOptions::new(None, None);
        assert_eq!(defaults.timeout, Duration::from_secs(10));
        assert_eq!(defaults.lifetime, Duration::from_secs(600));
        assert_eq!(mapping_lifetime_seconds(defaults.lifetime), 600);
        assert_eq!(mapping_lifetime_seconds(Duration::from_nanos(1)), 1);
        assert_eq!(
            mapping_lifetime_seconds(Duration::from_secs(u64::MAX)),
            u32::MAX
        );
        assert!(
            validate_mapped_address("203.0.113.9:443".parse().unwrap()).is_ok()
        );
        assert!(
            validate_mapped_address("0.0.0.0:443".parse().unwrap()).is_err()
        );
        assert!(
            validate_mapped_address("127.0.0.1:443".parse().unwrap()).is_err()
        );

        let control =
            RealmControlClient::new("https://realm.example", "token", None)
                .unwrap();
        let connector = RealmClientConnector::new(
            control,
            "edge",
            vec!["[::1]:3478".into()],
            6,
        )
        .unwrap();
        assert!(connector.with_port_mapping(defaults).is_err());
    }

    struct StaticResolver {
        calls: AtomicUsize,
    }

    impl crate::dns::Resolver for StaticResolver {
        fn lookup<'a>(
            &'a self,
            domain: &'a str,
            strategy: crate::option::DomainStrategy,
        ) -> crate::dns::LookupFuture<'a> {
            self.lookup_with_options(
                domain,
                crate::dns::LookupOptions {
                    strategy,
                    ..Default::default()
                },
            )
        }

        fn lookup_with_options<'a>(
            &'a self,
            domain: &'a str,
            options: crate::dns::LookupOptions,
        ) -> crate::dns::LookupFuture<'a> {
            Box::pin(async move {
                assert_eq!(domain, "stun.test");
                assert_eq!(
                    options.strategy,
                    crate::option::DomainStrategy::Ipv4Only
                );
                self.calls.fetch_add(1, Ordering::Relaxed);
                Ok(vec!["192.0.2.9".parse().unwrap()])
            })
        }
    }

    #[tokio::test]
    async fn resolves_stun_with_the_configured_dns_resolver() {
        let resolver = Arc::new(StaticResolver {
            calls: AtomicUsize::new(0),
        });
        let connector = RealmClientConnector::new(
            RealmControlClient::new("https://realm.example", "", None).unwrap(),
            "edge",
            vec!["stun.test:5349".into()],
            4,
        )
        .unwrap()
        .with_resolver(
            resolver.clone(),
            crate::dns::LookupOptions {
                strategy: crate::option::DomainStrategy::Ipv4Only,
                ..Default::default()
            },
        );
        assert_eq!(
            connector.resolve_stun_servers().await.unwrap(),
            ["192.0.2.9:5349".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
    }

    struct DualStackResolver;

    impl crate::dns::Resolver for DualStackResolver {
        fn lookup<'a>(
            &'a self,
            domain: &'a str,
            strategy: crate::option::DomainStrategy,
        ) -> crate::dns::LookupFuture<'a> {
            self.lookup_with_options(
                domain,
                crate::dns::LookupOptions {
                    strategy,
                    ..Default::default()
                },
            )
        }

        fn lookup_with_options<'a>(
            &'a self,
            _domain: &'a str,
            _options: crate::dns::LookupOptions,
        ) -> crate::dns::LookupFuture<'a> {
            Box::pin(async {
                Ok(vec![
                    "192.0.2.10".parse().unwrap(),
                    "2001:db8::10".parse().unwrap(),
                ])
            })
        }
    }

    #[tokio::test]
    async fn automatic_ip_version_opens_one_route_per_available_family() {
        let connector = RealmClientConnector::new(
            RealmControlClient::new("https://realm.example", "", None).unwrap(),
            "edge",
            vec!["stun.test:3478".into()],
            0,
        )
        .unwrap()
        .with_resolver(
            Arc::new(DualStackResolver),
            crate::dns::LookupOptions::default(),
        );
        let routes = connector.route_destinations().await.unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(
            routes[0],
            (
                true,
                "192.0.2.10:3478".parse::<SocketAddr>().unwrap().into()
            )
        );
        assert_eq!(
            routes[1],
            (
                false,
                "[2001:db8::10]:3478".parse::<SocketAddr>().unwrap().into()
            )
        );
    }

    #[tokio::test]
    async fn network_reset_invalidates_stun_age_but_keeps_fallback() {
        let fallback = "198.51.100.7:41000".parse().unwrap();
        let cache = tokio::sync::Mutex::new(RealmStunCache {
            addresses: vec![fallback],
            updated_at: Some(Instant::now()),
        });

        invalidate_stun_cache(&cache).await;

        let cache = cache.lock().await;
        assert_eq!(cache.addresses, [fallback]);
        assert!(cache.updated_at.is_none());
    }

    #[test]
    fn punch_packet_round_trip_and_fixed_wire() {
        let mut random = [0_u8; SALT_LENGTH + 2 + MAX_PADDING];
        for (index, byte) in random.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let packet =
            encode_punch_packet_with_random(PUNCH_HELLO, metadata(), &random)
                .unwrap();
        assert_eq!(packet.len(), 31 + 9);
        assert_eq!(decode_punch_packet(&packet, metadata()).unwrap(), 1);
        assert_eq!(
            hex::encode(&packet),
            "0001020304050607eb032c9cee7ad37c7a0183d9bfe04df11164382a34a706f45492265c708cc810"
        );
        let mut tampered = packet;
        tampered[10] ^= 1;
        assert!(decode_punch_packet(&tampered, metadata()).is_err());
    }

    #[test]
    fn expands_predictable_symmetric_nat_ports() {
        let addresses = [
            "192.0.2.1:4000".parse().unwrap(),
            "192.0.2.1:4002".parse().unwrap(),
            "192.0.2.1:4002".parse().unwrap(),
            "[2001:db8::1]:5000".parse().unwrap(),
        ];
        let candidates = candidate_punch_addresses(&addresses);
        assert_eq!(candidates.len(), 8);
        assert!(candidates.contains(&"192.0.2.1:4006".parse().unwrap()));
        assert_eq!(
            candidates
                .iter()
                .filter(|address| address.ip().is_ipv6())
                .count(),
            1
        );
    }

    #[test]
    fn decodes_stun_ipv4_and_ipv6_xor_addresses() {
        let transaction_id = *b"abcdefghijkl";
        let mut ipv4 = vec![0x01, 0x01, 0, 12];
        ipv4.extend_from_slice(&0x2112_A442_u32.to_be_bytes());
        ipv4.extend_from_slice(&transaction_id);
        ipv4.extend_from_slice(&0x0020_u16.to_be_bytes());
        ipv4.extend_from_slice(&8_u16.to_be_bytes());
        ipv4.extend_from_slice(&[0, 1]);
        ipv4.extend_from_slice(&(3478_u16 ^ 0x2112_u16).to_be_bytes());
        let ip = Ipv4Addr::new(203, 0, 113, 7).octets();
        let cookie = 0x2112_A442_u32.to_be_bytes();
        ipv4.extend(ip.iter().zip(cookie).map(|(a, b)| a ^ b));
        assert_eq!(
            decode_stun_xor_mapped_address(&ipv4, transaction_id).unwrap(),
            "203.0.113.7:3478".parse::<SocketAddr>().unwrap()
        );

        let address: Ipv6Addr = "2001:db8::1234".parse().unwrap();
        let mut ipv6 = vec![0x01, 0x01, 0, 24];
        ipv6.extend_from_slice(&0x2112_A442_u32.to_be_bytes());
        ipv6.extend_from_slice(&transaction_id);
        ipv6.extend_from_slice(&0x0020_u16.to_be_bytes());
        ipv6.extend_from_slice(&20_u16.to_be_bytes());
        ipv6.extend_from_slice(&[0, 2]);
        ipv6.extend_from_slice(&(443_u16 ^ 0x2112_u16).to_be_bytes());
        let mut mask = [0_u8; 16];
        mask[..4].copy_from_slice(&cookie);
        mask[4..].copy_from_slice(&transaction_id);
        ipv6.extend(address.octets().iter().zip(mask).map(|(a, b)| a ^ b));
        assert_eq!(
            decode_stun_xor_mapped_address(&ipv6, transaction_id).unwrap(),
            "[2001:db8::1234]:443".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parses_only_punch_sse_events() {
        assert!(
            parse_event(b"event: heartbeat_ack\ndata: {\"ttl\":60}")
                .unwrap()
                .is_none()
        );
        let wire = format!(
            "event: punch\ndata: {{\"addresses\":[\"127.0.0.1:1234\"],\"nonce\":\"30313233343536373839616263646566\",\"obfs\":\"{}\"}}",
            "5a".repeat(32)
        );
        let event = parse_event(wire.as_bytes()).unwrap().unwrap();
        assert_eq!(
            event.addresses,
            ["127.0.0.1:1234".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(event.metadata, metadata());
    }

    fn realm_socket() -> (Arc<RealmPacketSocket>, SocketAddr) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let address = socket.local_addr().unwrap();
        let runtime = quinn::TokioRuntime;
        let socket = runtime.wrap_udp_socket(socket).unwrap();
        (RealmPacketSocket::new(socket), address)
    }

    struct RecordingRealmDialer {
        direct: DirectOutbound,
        tcp_calls: Arc<AtomicUsize>,
    }

    impl Dialer for RecordingRealmDialer {
        fn dial_tcp<'a>(
            &'a self,
            destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            self.tcp_calls.fetch_add(1, Ordering::Relaxed);
            self.direct.dial_tcp(destination)
        }
    }

    #[tokio::test]
    async fn punches_two_real_udp_sockets() {
        let (left, left_addr) = realm_socket();
        let (right, right_addr) = realm_socket();
        let metadata = metadata();
        let left_candidates = [right_addr];
        let right_candidates = [left_addr];
        let (left_result, right_result) = tokio::join!(
            left.punch(&left_candidates, metadata),
            right.punch(&right_candidates, metadata)
        );
        assert_eq!(left_result.unwrap().peer_addr, right_addr);
        assert_eq!(right_result.unwrap().peer_addr, left_addr);
    }

    #[tokio::test]
    async fn discovers_mapped_address_from_real_stun_socket() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut request = [0_u8; 64];
            let (size, client_addr) =
                server.recv_from(&mut request).await.unwrap();
            assert_eq!(size, 20);
            let transaction_id: [u8; 12] = request[8..20].try_into().unwrap();
            let mut response = vec![0x01, 0x01, 0, 12];
            let cookie = 0x2112_A442_u32.to_be_bytes();
            response.extend_from_slice(&cookie);
            response.extend_from_slice(&transaction_id);
            response.extend_from_slice(&0x0020_u16.to_be_bytes());
            response.extend_from_slice(&8_u16.to_be_bytes());
            response.extend_from_slice(&[0, 1]);
            response.extend_from_slice(
                &(client_addr.port() ^ 0x2112_u16).to_be_bytes(),
            );
            let IpAddr::V4(client_ip) = client_addr.ip() else {
                panic!("IPv4 test socket returned IPv6 address");
            };
            response.extend(
                client_ip.octets().iter().zip(cookie).map(|(a, b)| a ^ b),
            );
            server.send_to(&response, client_addr).await.unwrap();
            client_addr
        });
        let (client, _) = realm_socket();
        let addresses = client.discover_stun(&[server_addr]).await.unwrap();
        assert_eq!(addresses, [responder.await.unwrap()]);
    }

    #[tokio::test]
    async fn connector_discovers_rendezvous_and_punches_peer() {
        let options: HysteriaRealmServiceOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "users":[{"name":"alice","token":"secret"}]
            }))
            .unwrap();
        let (mut service, handle) =
            HysteriaRealmService::new("connector-test", options).unwrap();
        service.start(StartStage::Start).await.unwrap();
        let tcp_calls = Arc::new(AtomicUsize::new(0));
        let control = RealmControlClient::new_with_dialer(
            format!("http://{}", handle.local_addr().unwrap()),
            "secret",
            Arc::new(RecordingRealmDialer {
                direct: DirectOutbound::new(DirectOutboundOptions::default()),
                tcp_calls: tcp_calls.clone(),
            }),
            HttpClientOptions {
                version: 1,
                ..Default::default()
            },
            None,
        )
        .unwrap();

        let stun = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun.local_addr().unwrap();
        let stun_responder = tokio::spawn(async move {
            let mut request = [0_u8; 64];
            let (size, client_addr) =
                stun.recv_from(&mut request).await.unwrap();
            assert_eq!(size, 20);
            let transaction_id: [u8; 12] = request[8..20].try_into().unwrap();
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
            let IpAddr::V4(client_ip) = client_addr.ip() else {
                panic!("IPv4 test socket returned IPv6 address");
            };
            response.extend(
                client_ip.octets().iter().zip(cookie).map(|(a, b)| a ^ b),
            );
            stun.send_to(&response, client_addr).await.unwrap();
        });

        let (peer_socket, peer_addr) = realm_socket();
        let registration =
            control.register("edge", &[peer_addr]).await.unwrap();
        let mut events = control
            .events("edge", &registration.session_id)
            .await
            .unwrap();
        let responding = {
            let control = control.clone();
            let session_id = registration.session_id.clone();
            tokio::spawn(async move {
                let event = events.next().await.unwrap();
                control
                    .connect_response(
                        "edge",
                        &session_id,
                        &event.metadata.nonce,
                        &[peer_addr],
                    )
                    .await
                    .unwrap();
                peer_socket
                    .punch(&event.addresses, event.metadata)
                    .await
                    .unwrap()
            })
        };
        let connector = RealmClientConnector::new(
            control.clone(),
            "edge",
            vec![stun_addr.to_string()],
            4,
        )
        .unwrap();
        let (client_socket, _) = realm_socket();
        let connected_peer =
            connector.connect(client_socket).await.unwrap().peer_addr;
        assert_eq!(connected_peer, peer_addr);
        assert_eq!(
            responding.await.unwrap().peer_addr.ip(),
            Ipv4Addr::LOCALHOST
        );
        stun_responder.await.unwrap();
        control
            .deregister("edge", &registration.session_id)
            .await
            .unwrap();
        assert!(tcp_calls.load(Ordering::Relaxed) > 0);
        service.close().await.unwrap();
    }

    #[tokio::test]
    async fn hysteria2_outbound_connects_through_realm_rendezvous() {
        let options: HysteriaRealmServiceOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "users":[{"name":"alice","token":"secret"}]
            }))
            .unwrap();
        let (mut realm_service, realm_handle) =
            HysteriaRealmService::new("outbound-test", options).unwrap();
        realm_service.start(StartStage::Start).await.unwrap();
        let control = RealmControlClient::new(
            format!("http://{}", realm_handle.local_addr().unwrap()),
            "secret",
            None,
        )
        .unwrap();

        let stun = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun.local_addr().unwrap();
        let stun_responder = tokio::spawn(async move {
            let mut request = [0_u8; 64];
            let (_, client_addr) = stun.recv_from(&mut request).await.unwrap();
            let transaction_id: [u8; 12] = request[8..20].try_into().unwrap();
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
            let IpAddr::V4(client_ip) = client_addr.ip() else {
                panic!("IPv4 test socket returned IPv6 address");
            };
            response.extend(
                client_ip.octets().iter().zip(cookie).map(|(a, b)| a ^ b),
            );
            stun.send_to(&response, client_addr).await.unwrap();
        });

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_tls_options: InboundTlsOptions =
            serde_json::from_value(json!({
                "enabled":true,
                "certificate":cert.pem(),
                "key":key_pair.serialize_pem()
            }))
            .unwrap();
        let server_tls =
            build_server_config_with_default_alpn(&server_tls_options, &["h3"])
                .unwrap();
        let client_tls_options: OutboundTlsOptions =
            serde_json::from_value(json!({
                "enabled":true,
                "server_name":"localhost",
                "insecure":true
            }))
            .unwrap();
        let client_tls =
            build_client_config("localhost", &client_tls_options, &["h3"])
                .unwrap();

        let (peer_socket, peer_addr) = realm_socket();
        let registration =
            control.register("quic", &[peer_addr]).await.unwrap();
        let mut events = control
            .events("quic", &registration.session_id)
            .await
            .unwrap();
        let (done_sender, done_receiver) = tokio::sync::oneshot::channel();
        let server = {
            let control = control.clone();
            let session_id = registration.session_id.clone();
            tokio::spawn(async move {
                let event = events.next().await.unwrap();
                control
                    .connect_response(
                        "quic",
                        &session_id,
                        &event.metadata.nonce,
                        &[peer_addr],
                    )
                    .await
                    .unwrap();
                peer_socket
                    .punch(&event.addresses, event.metadata)
                    .await
                    .unwrap();
                let endpoint =
                    hysteria2_server_endpoint_with_transport_obfs_socket(
                        server_tls,
                        Arc::new(quinn::TransportConfig::default()),
                        None,
                        peer_socket as Arc<dyn AsyncUdpSocket>,
                    )
                    .unwrap();
                let connection =
                    endpoint.accept().await.unwrap().await.unwrap();
                let users =
                    HashMap::from([("password".into(), "alice".into())]);
                let session = Hysteria2ServerSession::authenticate(
                    connection,
                    &users,
                    true,
                    Some(0),
                )
                .await
                .unwrap();
                let (mut stream, destination) =
                    session.accept_tcp().await.unwrap();
                assert_eq!(destination, "example.com:443");
                stream
                    .write_all(&encode_tcp_response(true, "", &[]).unwrap())
                    .await
                    .unwrap();
                let mut payload = [0_u8; 4];
                stream.read_exact(&mut payload).await.unwrap();
                stream.write_all(&payload).await.unwrap();
                let _ = done_receiver.await;
            })
        };
        let connector = RealmClientConnector::new(
            control.clone(),
            "quic",
            vec![stun_addr.to_string()],
            4,
        )
        .unwrap();
        let outbound = Hysteria2Outbound::new_with_realm(
            "localhost",
            "password",
            0,
            false,
            0,
            client_tls,
            quinn::TransportConfig::default(),
            None,
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            connector,
        );
        let mut stream = outbound
            .dial_tcp(&SocksAddr::new("example.com", 443))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        let _ = done_sender.send(());
        server.await.unwrap();
        stun_responder.await.unwrap();
        control
            .deregister("quic", &registration.session_id)
            .await
            .unwrap();
        realm_service.close().await.unwrap();
    }

    #[tokio::test]
    async fn control_client_interoperates_with_realm_service() {
        let options: HysteriaRealmServiceOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "users":[{"name":"alice","token":"secret"}]
            }))
            .unwrap();
        let (mut service, handle) =
            HysteriaRealmService::new("control-test", options).unwrap();
        service.start(StartStage::Start).await.unwrap();
        let control = RealmControlClient::new(
            format!("http://{}", handle.local_addr().unwrap()),
            "secret",
            None,
        )
        .unwrap();
        let registered = control
            .register("control", &["127.0.0.1:1000".parse().unwrap()])
            .await
            .unwrap();
        assert_eq!(registered.ttl, 60);
        let mut events = control
            .events("control", &registered.session_id)
            .await
            .unwrap();
        let connecting = {
            let control = control.clone();
            tokio::spawn(async move {
                control
                    .connect(
                        "control",
                        &["127.0.0.1:2000".parse().unwrap()],
                        metadata(),
                    )
                    .await
            })
        };
        let event = events.next().await.unwrap();
        assert_eq!(event.metadata, metadata());
        assert_eq!(
            event.addresses,
            ["127.0.0.1:2000".parse::<SocketAddr>().unwrap()]
        );
        control
            .connect_response(
                "control",
                &registered.session_id,
                &event.metadata.nonce,
                &["127.0.0.1:3000".parse().unwrap()],
            )
            .await
            .unwrap();
        let connected = connecting.await.unwrap().unwrap();
        assert_eq!(connected.metadata, metadata());
        assert_eq!(
            connected.addresses,
            ["127.0.0.1:3000".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            control
                .heartbeat(
                    "control",
                    &registered.session_id,
                    &["127.0.0.1:4000".parse().unwrap()]
                )
                .await
                .unwrap(),
            60
        );
        control
            .deregister("control", &registered.session_id)
            .await
            .unwrap();
        service.close().await.unwrap();
    }
}
