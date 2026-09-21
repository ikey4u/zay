//! Outbound registry, dependency resolution and protocol construction.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::SystemTime,
};

use futures_util::future::join_all;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::broadcast,
};
use tokio_util::sync::CancellationToken;

tokio::task_local! {
    static TRAFFIC_ATTRIBUTION: TrafficAttribution;
}

const MAX_PROCESS_TRAFFIC_RECORDS: usize = 2048;

#[derive(Debug, Clone, Default)]
pub(crate) struct TrafficAttribution {
    pub source: Option<SocksAddr>,
    pub domain: String,
    pub rule: String,
    pub process_name: String,
    pub process_path: String,
    pub process_lookup: String,
}

pub(crate) async fn with_traffic_attribution<F, T>(
    attribution: TrafficAttribution,
    future: F,
) -> T
where
    F: Future<Output = T>,
{
    TRAFFIC_ATTRIBUTION.scope(attribution, future).await
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
use crate::common::platform_network::{
    PlatformNetworkDefaults, PlatformNetworkProvider,
};
use crate::{
    adapter::{
        DialFuture, Dialer, IcmpResponse, IpPacketPort, NetworkDialOptions,
        PacketConnection, PacketFuture, PacketStream, Stream,
        interruptible_stream,
    },
    common::{
        network::SocksAddr,
        ntp::NtpClock,
        platform_network::RouteDialerDefaults,
        tls::{ClientTlsDialer, build_client_config_with_runtime_context},
    },
    dns::{
        ConfiguredResolver, Resolver,
        manager::{
            ManagerError as DnsManagerError, ResolvingDetourDialer,
            SharedResolver, TransportManager,
        },
        persistent::PersistentDnsCache,
        rule::RdrcOptions,
    },
    inbound::TcpInboundInjector,
    option::{
        AbstractDialerOptions, AnyTlsOutboundOptions, BridgeOutboundOptions,
        ConfigError, DialerOptions, DirectOutboundOptions, DomainStrategy,
        HttpOutboundOptions, Hysteria2Obfs, Hysteria2OutboundOptions,
        HysteriaOutboundOptions, NaiveOutboundOptions,
        Network as OptionNetwork, NetworkList, Options,
        OutboundMultiplexOptions, SelectorOutboundOptions,
        ShadowTlsOutboundOptions, ShadowsocksOutboundOptions,
        SnellOutboundOptions, SocksOutboundOptions, SshOutboundOptions,
        TaggedOptions, TorOutboundOptions, TrojanOutboundOptions,
        TuicOutboundOptions, UrlTestOutboundOptions, V2RayTransportOptions,
        VMessOutboundOptions, VlessOutboundOptions,
    },
    protocol::{
        anytls::AnyTlsOutbound,
        block::BlockOutbound,
        bridge::{BridgeOutbound, BridgeOutboundService},
        direct::DirectOutbound,
        http::HttpConnectOutbound,
        hysteria::{
            DEFAULT_HOP_INTERVAL, HysteriaOutbound, MBPS_TO_BPS,
            MIN_HOP_INTERVAL, MIN_SPEED_BPS, parse_server_ports,
            port_hopping_dialer,
        },
        hysteria2::{
            Hysteria2ObfsConfig, Hysteria2Outbound, Hysteria2QuicOptions,
        },
        hysteria2_realm::{RealmClientConnector, RealmControlClient},
        mux::MuxClient,
        naive::{NaiveHttp3Outbound, NaiveOutbound},
        selector::SelectorOutbound,
        shadowsocks::ShadowsocksOutbound,
        shadowtls::ShadowTlsV1Outbound,
        simple_obfs::{SimpleObfsDialer, SimpleObfsOptions},
        snell::{ObfsMode as SnellObfsMode, SnellV4Outbound},
        snell_v6::{Mode as SnellV6Mode, SnellV6Outbound},
        socks::{Socks4Outbound, Socks5Outbound, SocksVersion},
        ssh::SshOutbound,
        tor::{
            ExternalTorConfig, ExternalTorOutbound, TorOutbound,
            expand_data_directory,
        },
        trojan::TrojanOutbound,
        tuic::TuicOutbound,
        uot::UotOutbound,
        urltest::{GroupRegistry, UrlTestOutbound, probe_url_with_timeout},
        v2ray_plugin::{V2RayPluginDialer, V2RayPluginOptions},
        vless::VlessOutbound,
        vmess::{VmessClientConfig, VmessOutbound},
    },
    transport::{
        quic::QuicDialer,
        v2ray::{
            GrpcDialer, HttpDialer, HttpUpgradeDialer, WebsocketDialer,
            tls_alpn,
        },
    },
};

pub type SharedDialer = Arc<dyn Dialer>;

/// Preserve sing-box's outbound `Network()` contract at the library boundary.
///
/// The Go router checks the configured network list before dispatching a TCP
/// stream or UDP packet connection. Rust exposes outbounds directly as
/// `Dialer`s as well, so enforcing the same capability on the dialer keeps
/// routed, detoured, grouped, and direct library callers consistent.
struct NetworkRestrictedDialer {
    inner: SharedDialer,
    tag: String,
    tcp: bool,
    udp: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetworkCapability {
    tcp: bool,
    udp: bool,
}

impl NetworkCapability {
    const BOTH: Self = Self {
        tcp: true,
        udp: true,
    };

    fn from_networks(networks: &NetworkList) -> Self {
        let networks = networks.build();
        Self {
            tcp: networks.contains(&OptionNetwork::Tcp),
            udp: networks.contains(&OptionNetwork::Udp),
        }
    }
}

impl NetworkRestrictedDialer {
    fn new(
        inner: SharedDialer,
        tag: &str,
        capability: NetworkCapability,
    ) -> Self {
        Self {
            inner,
            tag: tag.to_owned(),
            tcp: capability.tcp,
            udp: capability.udp,
        }
    }

    fn unsupported(&self, network: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{network} is not supported by outbound: {}", self.tag),
        )
    }
}

impl Dialer for NetworkRestrictedDialer {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        if !self.tcp {
            let error = self.unsupported("TCP");
            return Box::pin(async move { Err(error) });
        }
        self.inner.dial_tcp(destination)
    }

    fn dial_tcp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> DialFuture<'a> {
        if !self.tcp {
            let error = self.unsupported("TCP");
            return Box::pin(async move { Err(error) });
        }
        self.inner.dial_tcp_with_options(destination, options)
    }

    fn bind_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        if !self.tcp {
            let error = self.unsupported("TCP");
            return Box::pin(async move { Err(error) });
        }
        self.inner.bind_tcp(destination)
    }

    fn dial_vision_tcp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> crate::adapter::VisionDialFuture<'a> {
        if !self.tcp {
            let error = self.unsupported("TCP");
            return Box::pin(async move { Err(error) });
        }
        self.inner.dial_vision_tcp(destination)
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        if !self.udp {
            let error = self.unsupported("UDP");
            return Box::pin(async move { Err(error) });
        }
        self.inner.listen_udp(destination)
    }

    fn listen_udp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, PacketStream> {
        if !self.udp {
            let error = self.unsupported("UDP");
            return Box::pin(async move { Err(error) });
        }
        self.inner.listen_udp_with_options(destination, options)
    }

    fn listen_udp_on<'a>(
        &'a self,
        destination: &'a SocksAddr,
        local_port: u16,
    ) -> PacketFuture<'a, PacketStream> {
        if !self.udp {
            let error = self.unsupported("UDP");
            return Box::pin(async move { Err(error) });
        }
        self.inner.listen_udp_on(destination, local_port)
    }

    fn exchange_icmp<'a>(
        &'a self,
        packet: &'a [u8],
        source: std::net::IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, IcmpResponse> {
        self.inner
            .exchange_icmp(packet, source, hop_limit, destination)
    }

    fn exchange_icmp_with_options<'a>(
        &'a self,
        packet: &'a [u8],
        source: std::net::IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, IcmpResponse> {
        self.inner.exchange_icmp_with_options(
            packet,
            source,
            hop_limit,
            destination,
            options,
        )
    }

    fn preferred_domain(&self, domain: &str) -> bool {
        self.inner.preferred_domain(domain)
    }

    fn preferred_address(&self, address: std::net::IpAddr) -> bool {
        self.inner.preferred_address(address)
    }

    fn icmp_flow_addresses(
        &self,
    ) -> Option<(Option<std::net::IpAddr>, Option<std::net::IpAddr>)> {
        self.inner.icmp_flow_addresses()
    }

    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        self.inner.packet_port()
    }
}

#[derive(Default, serde::Deserialize)]
struct OutboundNetworkOptions {
    #[serde(default)]
    network: NetworkList,
}

fn configured_network_capability(
    option: &TaggedOptions,
) -> Result<Option<NetworkCapability>, OutboundError> {
    if !matches!(
        option.kind.as_str(),
        "socks"
            | "tuic"
            | "hysteria"
            | "hysteria2"
            | "shadowsocks"
            | "vmess"
            | "vless"
            | "trojan"
            | "snell"
    ) {
        return Ok(None);
    }
    let options: OutboundNetworkOptions = option.decode()?;
    Ok(Some(NetworkCapability::from_networks(&options.network)))
}

struct OutboundDnsResolver {
    manager: Arc<TransportManager>,
    outbound: String,
}

impl Resolver for OutboundDnsResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: DomainStrategy,
    ) -> crate::dns::LookupFuture<'a> {
        self.lookup_with_options(
            domain,
            crate::dns::LookupOptions {
                strategy,
                ..crate::dns::LookupOptions::default()
            },
        )
    }

    fn lookup_with_options<'a>(
        &'a self,
        domain: &'a str,
        options: crate::dns::LookupOptions,
    ) -> crate::dns::LookupFuture<'a> {
        Box::pin(async move {
            self.manager
                .lookup_with_context(
                    domain,
                    options,
                    &crate::route::Metadata {
                        outbound: self.outbound.clone(),
                        ..crate::route::Metadata::default()
                    },
                )
                .await
        })
    }

    fn exchange<'a>(
        &'a self,
        request: &'a hickory_proto::op::Message,
    ) -> crate::dns::MessageFuture<'a> {
        self.exchange_with_options(
            request,
            crate::dns::LookupOptions::default(),
        )
    }

    fn exchange_with_options<'a>(
        &'a self,
        request: &'a hickory_proto::op::Message,
        options: crate::dns::LookupOptions,
    ) -> crate::dns::MessageFuture<'a> {
        Box::pin(async move {
            self.manager
                .exchange_with_context(
                    request,
                    options,
                    &crate::route::Metadata {
                        outbound: self.outbound.clone(),
                        ..crate::route::Metadata::default()
                    },
                )
                .await
        })
    }
}

struct TrafficCounters {
    upload: AtomicU64,
    download: AtomicU64,
    connections: Mutex<HashMap<String, ActiveConnection>>,
    process_traffic_enabled: AtomicBool,
    process_traffic_generation: AtomicU64,
    process_traffic: Mutex<HashMap<String, ProcessTrafficEntry>>,
    process_traffic_started_at: Mutex<Option<SystemTime>>,
    events: broadcast::Sender<TrafficConnectionEvent>,
}

impl Default for TrafficCounters {
    fn default() -> Self {
        let (events, _) = broadcast::channel(128);
        Self {
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            connections: Mutex::new(HashMap::new()),
            process_traffic_enabled: AtomicBool::new(false),
            process_traffic_generation: AtomicU64::new(0),
            process_traffic: Mutex::new(HashMap::new()),
            process_traffic_started_at: Mutex::new(None),
            events,
        }
    }
}

impl TrafficCounters {
    fn totals(&self) -> (u64, u64) {
        (
            self.upload.load(Ordering::Relaxed),
            self.download.load(Ordering::Relaxed),
        )
    }

    fn register(
        &self,
        outbound: &str,
        destination: &SocksAddr,
        network: &'static str,
    ) -> ActiveHandle {
        let id = uuid::Uuid::new_v4().to_string();
        let upload = Arc::new(AtomicU64::new(0));
        let download = Arc::new(AtomicU64::new(0));
        let cancellation = CancellationToken::new();
        let attribution = TRAFFIC_ATTRIBUTION
            .try_with(Clone::clone)
            .unwrap_or_default();
        let connection = ActiveConnection {
            id: id.clone(),
            outbound: outbound.to_owned(),
            destination: destination.clone(),
            network,
            upload: upload.clone(),
            download: download.clone(),
            created_at: SystemTime::now(),
            cancellation: cancellation.clone(),
            attribution: attribution.clone(),
        };
        let snapshot = connection.snapshot();
        let mut connections = self
            .connections
            .lock()
            .expect("traffic connections lock poisoned");
        connections.insert(id.clone(), connection);
        let _ = self.events.send(TrafficConnectionEvent::New(snapshot));
        drop(connections);
        ActiveHandle {
            id,
            upload,
            download,
            cancellation,
            attribution,
            process_traffic_generation: AtomicU64::new(0),
        }
    }

    fn count_upload(&self, active: &ActiveHandle, size: u64) {
        self.upload.fetch_add(size, Ordering::Relaxed);
        active.upload.fetch_add(size, Ordering::Relaxed);
        self.record_process_traffic(active, size, 0);
    }

    fn count_download(&self, active: &ActiveHandle, size: u64) {
        self.download.fetch_add(size, Ordering::Relaxed);
        active.download.fetch_add(size, Ordering::Relaxed);
        self.record_process_traffic(active, 0, size);
    }

    fn record_process_traffic(
        &self,
        active: &ActiveHandle,
        upload: u64,
        download: u64,
    ) {
        if !self.process_traffic_enabled.load(Ordering::Relaxed) {
            return;
        }
        let attribution = &active.attribution;
        let key = if !attribution.process_path.is_empty() {
            &attribution.process_path
        } else if !attribution.process_name.is_empty() {
            &attribution.process_name
        } else {
            return;
        };
        let now = SystemTime::now();
        let generation =
            self.process_traffic_generation.load(Ordering::Acquire);
        let new_connection = active
            .process_traffic_generation
            .swap(generation, Ordering::AcqRel)
            != generation;
        let mut records = self
            .process_traffic
            .lock()
            .expect("process traffic lock poisoned");
        if records.len() >= MAX_PROCESS_TRAFFIC_RECORDS
            && !records.contains_key(key)
            && let Some(oldest) = records
                .iter()
                .min_by_key(|(_, record)| record.last_seen)
                .map(|(key, _)| key.clone())
        {
            records.remove(&oldest);
        }
        let record = records.entry(key.to_owned()).or_insert_with(|| {
            ProcessTrafficEntry {
                process_name: attribution.process_name.clone(),
                process_path: attribution.process_path.clone(),
                process_lookup: attribution.process_lookup.clone(),
                upload: 0,
                download: 0,
                connections: 0,
                first_seen: now,
                last_seen: now,
            }
        });
        record.upload = record.upload.saturating_add(upload);
        record.download = record.download.saturating_add(download);
        if new_connection {
            record.connections = record.connections.saturating_add(1);
        }
        record.last_seen = now;
    }

    fn set_process_traffic_enabled(&self, enabled: bool) {
        self.process_traffic_enabled
            .store(enabled, Ordering::Release);
        self.process_traffic_generation
            .fetch_add(1, Ordering::AcqRel);
        self.process_traffic
            .lock()
            .expect("process traffic lock poisoned")
            .clear();
        *self
            .process_traffic_started_at
            .lock()
            .expect("process traffic start lock poisoned") =
            enabled.then(SystemTime::now);
    }

    fn process_traffic_snapshot(&self) -> ProcessTrafficState {
        let enabled = self.process_traffic_enabled.load(Ordering::Acquire);
        let started_at = *self
            .process_traffic_started_at
            .lock()
            .expect("process traffic start lock poisoned");
        let mut records = self
            .process_traffic
            .lock()
            .expect("process traffic lock poisoned")
            .values()
            .map(ProcessTrafficEntry::snapshot)
            .collect::<Vec<_>>();
        records.sort_by_key(|record| {
            std::cmp::Reverse(record.upload.saturating_add(record.download))
        });
        ProcessTrafficState {
            enabled,
            started_at,
            records,
        }
    }

    fn remove(&self, id: &str) {
        let mut connections = self
            .connections
            .lock()
            .expect("traffic connections lock poisoned");
        if let Some(connection) = connections.remove(id) {
            let _ = self.events.send(TrafficConnectionEvent::Closed {
                connection: connection.snapshot(),
                closed_at: SystemTime::now(),
            });
        }
    }

    fn close(&self, id: &str) {
        let mut connections = self
            .connections
            .lock()
            .expect("traffic connections lock poisoned");
        if let Some(connection) = connections.remove(id) {
            connection.cancellation.cancel();
            let _ = self.events.send(TrafficConnectionEvent::Closed {
                connection: connection.snapshot(),
                closed_at: SystemTime::now(),
            });
        }
    }
}

struct ActiveConnection {
    id: String,
    outbound: String,
    destination: SocksAddr,
    network: &'static str,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
    created_at: SystemTime,
    cancellation: CancellationToken,
    attribution: TrafficAttribution,
}

impl ActiveConnection {
    fn snapshot(&self) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id: self.id.clone(),
            outbound: self.outbound.clone(),
            destination: self.destination.clone(),
            network: self.network,
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
            created_at: self.created_at,
            source: self.attribution.source.clone(),
            domain: self.attribution.domain.clone(),
            rule: self.attribution.rule.clone(),
            process_name: self.attribution.process_name.clone(),
            process_path: self.attribution.process_path.clone(),
            process_lookup: self.attribution.process_lookup.clone(),
        }
    }
}

struct ActiveHandle {
    id: String,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
    cancellation: CancellationToken,
    attribution: TrafficAttribution,
    process_traffic_generation: AtomicU64,
}

struct ProcessTrafficEntry {
    process_name: String,
    process_path: String,
    process_lookup: String,
    upload: u64,
    download: u64,
    connections: usize,
    first_seen: SystemTime,
    last_seen: SystemTime,
}

impl ProcessTrafficEntry {
    fn snapshot(&self) -> ProcessTrafficSnapshot {
        ProcessTrafficSnapshot {
            process_name: self.process_name.clone(),
            process_path: self.process_path.clone(),
            process_lookup: self.process_lookup.clone(),
            upload: self.upload,
            download: self.download,
            connections: self.connections,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
        }
    }
}

pub(crate) struct PacketFlowTracker {
    traffic: Arc<TrafficCounters>,
    active: ActiveHandle,
    closed: AtomicBool,
}

impl PacketFlowTracker {
    pub(crate) fn count_forward(&self, size: usize) {
        self.traffic.count_upload(&self.active, size as u64);
    }

    pub(crate) fn count_reverse(&self, size: usize) {
        self.traffic.count_download(&self.active, size as u64);
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.active.cancellation.is_cancelled()
    }

    pub(crate) fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.traffic.remove(&self.active.id);
        }
    }
}

impl Drop for PacketFlowTracker {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.traffic.remove(&self.active.id);
        }
    }
}

struct ActiveConnectionCleanup {
    traffic: Arc<TrafficCounters>,
    id: String,
}

impl Drop for ActiveConnectionCleanup {
    fn drop(&mut self) {
        self.traffic.remove(&self.id);
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionSnapshot {
    pub id: String,
    pub outbound: String,
    pub destination: SocksAddr,
    pub network: &'static str,
    pub upload: u64,
    pub download: u64,
    pub created_at: SystemTime,
    pub source: Option<SocksAddr>,
    pub domain: String,
    pub rule: String,
    pub process_name: String,
    pub process_path: String,
    pub process_lookup: String,
}

#[derive(Debug, Clone)]
pub struct ProcessTrafficSnapshot {
    pub process_name: String,
    pub process_path: String,
    pub process_lookup: String,
    pub upload: u64,
    pub download: u64,
    pub connections: usize,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
}

#[derive(Debug, Clone)]
pub struct ProcessTrafficState {
    pub enabled: bool,
    pub started_at: Option<SystemTime>,
    pub records: Vec<ProcessTrafficSnapshot>,
}

#[derive(Debug, Clone)]
pub(crate) enum TrafficConnectionEvent {
    New(ConnectionSnapshot),
    Closed {
        connection: ConnectionSnapshot,
        closed_at: SystemTime,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Dns(#[from] DnsManagerError),
    #[error("DNS resolver {resolver:?} not found for outbound {outbound:?}")]
    DnsResolverNotFound { outbound: String, resolver: String },
    #[error("outbound dependency {dependency:?} not found for {outbound:?}")]
    DependencyNotFound {
        outbound: String,
        dependency: String,
    },
    #[error("circular outbound dependency: {0}")]
    CircularDependency(String),
    #[error("default outbound not found: {0}")]
    DefaultNotFound(String),
    #[error("outbound {tag:?} uses unsupported {kind} functionality: {detail}")]
    Unsupported {
        tag: String,
        kind: String,
        detail: String,
    },
    #[error("{0}")]
    Removed(String),
    #[error("create TLS for outbound {tag:?}: {message}")]
    Tls { tag: String, message: String },
}

pub struct OutboundManager {
    order: Vec<String>,
    kinds: HashMap<String, String>,
    networks: HashMap<String, NetworkCapability>,
    entries: HashMap<String, SharedDialer>,
    /// Per-rule direct dialers use internal keys so existing route call sites
    /// can select them without exposing synthetic outbounds to embedding
    /// applications.
    route_direct_entries: HashMap<String, SharedDialer>,
    endpoint_entries: RwLock<HashMap<String, SharedDialer>>,
    endpoint_order: RwLock<Vec<String>>,
    endpoint_kinds: RwLock<HashMap<String, String>>,
    empty_direct_tags: HashSet<String>,
    default_tag: String,
    dns: Arc<TransportManager>,
    selectors: HashMap<String, Arc<SelectorOutbound>>,
    urltests: HashMap<String, Arc<UrlTestOutbound>>,
    bridges: Vec<Arc<BridgeOutbound>>,
    groups: Arc<GroupRegistry>,
    persistent_cache: Option<Arc<PersistentDnsCache>>,
    traffic: Arc<TrafficCounters>,
    urltest_history: Mutex<HashMap<String, (SystemTime, u16)>>,
    action_direct: SharedDialer,
    route_dialer_defaults: RouteDialerDefaults,
    inbound_tcp_detours: RwLock<HashMap<String, InboundTcpDetour>>,
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    platform_network_provider: Option<Arc<dyn PlatformNetworkProvider>>,
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    platform_network_defaults: PlatformNetworkDefaults,
}

#[derive(Clone)]
struct InboundTcpDetour {
    target: String,
    target_exists: bool,
    injector: Option<Arc<dyn TcpInboundInjector>>,
}

pub(crate) struct InboundTcpDetourResolution {
    pub target: String,
    pub target_exists: bool,
    pub injector: Option<Arc<dyn TcpInboundInjector>>,
}

impl OutboundManager {
    pub(crate) fn register_inbound_tcp_detour(
        &self,
        source: impl Into<String>,
        target: impl Into<String>,
        target_exists: bool,
        injector: Option<Arc<dyn TcpInboundInjector>>,
    ) {
        self.inbound_tcp_detours
            .write()
            .expect("inbound TCP detour registry poisoned")
            .insert(
                source.into(),
                InboundTcpDetour {
                    target: target.into(),
                    target_exists,
                    injector,
                },
            );
    }

    pub(crate) fn inbound_tcp_detour(
        &self,
        source: &str,
    ) -> Option<InboundTcpDetourResolution> {
        self.inbound_tcp_detours
            .read()
            .expect("inbound TCP detour registry poisoned")
            .get(source)
            .map(|detour| InboundTcpDetourResolution {
                target: detour.target.clone(),
                target_exists: detour.target_exists,
                injector: detour.injector.clone(),
            })
    }
    pub fn from_options(
        options: &Options,
        default_tag: &str,
    ) -> Result<Self, OutboundError> {
        Self::from_options_in(options, default_tag, Path::new("."))
    }

    /// Build an outbound registry with relative filesystem options resolved
    /// against the embedding application's configuration directory.
    pub fn from_options_in(
        options: &Options,
        default_tag: &str,
        base_path: &Path,
    ) -> Result<Self, OutboundError> {
        let persistent_cache = Self::open_persistent_cache(options, base_path)?;
        Self::from_options_with_runtime_context(
            options,
            default_tag,
            base_path,
            persistent_cache,
            None,
            None,
            None,
            None,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            None,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            PlatformNetworkDefaults::default(),
        )
    }

    /// Build an outbound registry whose TLS clients share an NTP-corrected
    /// wall clock. This is primarily used by [`crate::Runtime`], but is public
    /// so embedding applications can construct the registry independently.
    pub fn from_options_with_clock(
        options: &Options,
        default_tag: &str,
        ntp_clock: Option<NtpClock>,
    ) -> Result<Self, OutboundError> {
        let persistent_cache =
            Self::open_persistent_cache(options, Path::new("."))?;
        Self::from_options_with_persistent_cache_and_clock(
            options,
            default_tag,
            persistent_cache,
            ntp_clock,
        )
    }

    /// Build an outbound registry with the same shared clock and reloadable
    /// certificate store used by [`crate::Runtime`].
    pub fn from_options_with_clock_and_certificate_store(
        options: &Options,
        default_tag: &str,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<
            crate::common::certificate_store::CertificateStore,
        >,
    ) -> Result<Self, OutboundError> {
        let persistent_cache =
            Self::open_persistent_cache(options, Path::new("."))?;
        Self::from_options_with_persistent_cache_clock_and_certificate_store(
            options,
            default_tag,
            persistent_cache,
            ntp_clock,
            certificate_store,
        )
    }

    pub(crate) fn open_persistent_cache(
        options: &Options,
        base_path: &Path,
    ) -> Result<Option<Arc<PersistentDnsCache>>, OutboundError> {
        let cache_options = options
            .experimental
            .as_ref()
            .and_then(|experimental| experimental.cache_file.as_ref())
            .filter(|cache| cache.enabled);
        cache_options
            .map(|cache| {
                let configured_path = if cache.path.is_empty() {
                    Path::new("cache.db")
                } else {
                    Path::new(&cache.path)
                };
                let path = if configured_path.is_absolute() {
                    configured_path.to_owned()
                } else {
                    base_path.join(configured_path)
                };
                PersistentDnsCache::open(&path, &cache.cache_id)
                    .map(Arc::new)
                    .map_err(|error| {
                        DnsManagerError::InvalidOptions(format!(
                            "open persistent DNS cache at {path:?}: {error}"
                        ))
                    })
            })
            .transpose()
            .map_err(OutboundError::from)
    }

    pub(crate) fn from_options_with_persistent_cache_and_clock(
        options: &Options,
        default_tag: &str,
        persistent_cache: Option<Arc<PersistentDnsCache>>,
        ntp_clock: Option<NtpClock>,
    ) -> Result<Self, OutboundError> {
        Self::from_options_with_persistent_cache_clock_and_certificate_store(
            options,
            default_tag,
            persistent_cache,
            ntp_clock,
            None,
        )
    }

    pub(crate) fn from_options_with_persistent_cache_clock_and_certificate_store(
        options: &Options,
        default_tag: &str,
        persistent_cache: Option<Arc<PersistentDnsCache>>,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<
            crate::common::certificate_store::CertificateStore,
        >,
    ) -> Result<Self, OutboundError> {
        Self::from_options_with_runtime_context(
            options,
            default_tag,
            Path::new("."),
            persistent_cache,
            ntp_clock,
            certificate_store,
            None,
            None,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            None,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            PlatformNetworkDefaults::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_options_with_runtime_context(
        options: &Options,
        default_tag: &str,
        base_path: &Path,
        persistent_cache: Option<Arc<PersistentDnsCache>>,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<
            crate::common::certificate_store::CertificateStore,
        >,
        neighbor_resolver: Option<Arc<dyn crate::adapter::NeighborResolver>>,
        rule_set_router: Option<&crate::route::Router>,
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        platform_network_provider: Option<
            Arc<dyn PlatformNetworkProvider>,
        >,
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        platform_network_defaults: PlatformNetworkDefaults,
    ) -> Result<Self, OutboundError> {
        let route_dialer_defaults = options
            .route
            .as_ref()
            .map(RouteDialerDefaults::from_route_options)
            .unwrap_or_default();
        let cache_options = options
            .experimental
            .as_ref()
            .and_then(|experimental| experimental.cache_file.as_ref())
            .filter(|cache| cache.enabled);
        let persistent_dns_cache = cache_options
            .filter(|cache| cache.store_dns)
            .and(persistent_cache.clone());
        let persistent_fakeip_cache = cache_options
            .filter(|cache| cache.store_fakeip)
            .and(persistent_cache.clone());
        let rdrc =
            cache_options
                .filter(|cache| cache.store_rdrc)
                .and_then(|cache| {
                    persistent_cache.clone().map(|persistent_cache| {
                        RdrcOptions {
                            cache: persistent_cache,
                            timeout: cache
                                .rdrc_timeout
                                .as_std()
                                .filter(|timeout| !timeout.is_zero())
                                .unwrap_or(std::time::Duration::from_secs(
                                    7 * 24 * 60 * 60,
                                )),
                        }
                    })
                });
        let dns =
            Arc::new(TransportManager::from_options_with_runtime_context(
                options.dns.as_ref(),
                persistent_dns_cache,
                persistent_fakeip_cache,
                rdrc,
                certificate_store.clone(),
                ntp_clock.clone(),
                neighbor_resolver,
                route_dialer_defaults.clone(),
                rule_set_router,
                #[cfg(any(
                    target_os = "android",
                    target_os = "ios",
                    target_os = "macos"
                ))]
                platform_network_provider.clone(),
                #[cfg(any(
                    target_os = "android",
                    target_os = "ios",
                    target_os = "macos"
                ))]
                platform_network_defaults.clone(),
            )?);
        let manager = Builder::new(
            &options.outbounds,
            base_path,
            dns,
            persistent_cache,
            ntp_clock,
            certificate_store,
            route_dialer_defaults,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_provider,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_defaults,
        )
        .build(default_tag)?;
        for tag in manager.order.clone() {
            if manager.dns.uses_outbound_detour(&tag)
                && manager.kinds.get(&tag).is_some_and(|kind| kind == "direct")
            {
                let direct = options
                    .outbounds
                    .iter()
                    .enumerate()
                    .find(|(index, option)| {
                        effective_tag(option, *index) == tag
                    })
                    .map(|(_, option)| option.decode::<DirectOutboundOptions>())
                    .transpose()?
                    .unwrap_or_default();
                if direct == DirectOutboundOptions::default() {
                    return Err(OutboundError::Dns(
                        DnsManagerError::InvalidOptions(format!(
                            "DNS detour to empty direct outbound {tag:?} makes no sense"
                        )),
                    ));
                }
            }
            let dialer = manager
                .entries
                .get(&tag)
                .cloned()
                .expect("built outbound is registered");
            manager
                .dns
                .bind_outbound_detour(&tag, dialer)
                .map_err(OutboundError::Dns)?;
        }
        let endpoint_tags = options
            .endpoints
            .iter()
            .enumerate()
            .map(|(index, endpoint)| effective_tag(endpoint, index))
            .collect::<HashSet<_>>();
        manager
            .dns
            .validate_outbound_detours(&endpoint_tags)
            .map_err(OutboundError::Dns)?;
        Ok(manager)
    }

    pub fn outbound(&self, tag: &str) -> Option<SharedDialer> {
        let route_direct = self.route_direct_entries.get(tag).cloned();
        route_direct
            .clone()
            .or_else(|| self.entries.get(tag).cloned())
            .or_else(|| self.endpoint_entries.read().ok()?.get(tag).cloned())
            .map(|dialer| {
                Arc::new(MeteredDialer {
                    inner: dialer,
                    traffic: self.traffic.clone(),
                    outbound: if route_direct.is_some() {
                        "direct".into()
                    } else {
                        tag.to_owned()
                    },
                }) as SharedDialer
            })
    }

    pub(crate) fn register_route_direct(
        &mut self,
        tag: &str,
        options: &AbstractDialerOptions,
    ) -> Result<(), OutboundError> {
        let dialer = self.direct_or_detour_dialer(
            "route direct action",
            &DialerOptions {
                detour: String::new(),
                abstract_options: options.clone(),
            },
            false,
        )?;
        self.route_direct_entries.insert(tag.to_owned(), dialer);
        Ok(())
    }

    pub(crate) fn bridge_service(&self) -> Option<BridgeOutboundService> {
        (!self.bridges.is_empty())
            .then(|| BridgeOutboundService::new(self.bridges.clone()))
    }

    pub(crate) fn register_endpoint(
        &self,
        tag: &str,
        kind: &str,
        dialer: SharedDialer,
    ) -> io::Result<()> {
        if self.entries.contains_key(tag) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("endpoint tag {tag:?} conflicts with an outbound"),
            ));
        }
        let dns_dialer = dialer.clone();
        let mut entries = self.endpoint_entries.write().map_err(|_| {
            io::Error::other("endpoint outbound registry lock poisoned")
        })?;
        if entries.contains_key(tag) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("duplicate endpoint tag {tag:?}"),
            ));
        }
        let mut order = self.endpoint_order.write().map_err(|_| {
            io::Error::other("endpoint outbound order lock poisoned")
        })?;
        let mut kinds = self.endpoint_kinds.write().map_err(|_| {
            io::Error::other("endpoint outbound kind lock poisoned")
        })?;
        entries.insert(tag.to_owned(), dialer);
        order.push(tag.to_owned());
        kinds.insert(tag.to_owned(), kind.to_owned());
        drop(kinds);
        drop(order);
        drop(entries);
        self.dns
            .bind_outbound_detour(tag, dns_dialer)
            .map_err(io::Error::other)
    }

    pub fn default(&self) -> SharedDialer {
        self.outbound(&self.default_tag)
            .expect("default outbound exists")
    }

    pub fn select(&self, tag: Option<&str>) -> Option<SharedDialer> {
        let tag = match tag {
            Some(tag) if !tag.is_empty() => tag,
            _ => &self.default_tag,
        };
        let outbound = self.outbound(tag)?;
        let capability =
            self.effective_network_capability(tag, &mut HashSet::new());
        if capability == NetworkCapability::BOTH {
            Some(outbound)
        } else {
            Some(Arc::new(NetworkRestrictedDialer::new(
                outbound, tag, capability,
            )))
        }
    }

    fn effective_network_capability(
        &self,
        tag: &str,
        visited: &mut HashSet<String>,
    ) -> NetworkCapability {
        if !visited.insert(tag.to_owned()) {
            return NetworkCapability::BOTH;
        }
        let capability = self
            .group_selected(tag)
            .map(|selected| {
                self.effective_network_capability(&selected, visited)
            })
            .or_else(|| self.networks.get(tag).copied())
            .unwrap_or(NetworkCapability::BOTH);
        visited.remove(tag);
        capability
    }

    pub fn tags(&self) -> impl Iterator<Item = &str> {
        self.order.iter().map(String::as_str)
    }

    pub fn outbound_items(&self) -> Vec<(String, String)> {
        let mut items = self
            .order
            .iter()
            .filter_map(|tag| {
                self.kinds.get(tag).map(|kind| (tag.clone(), kind.clone()))
            })
            .collect::<Vec<_>>();
        let order = self
            .endpoint_order
            .read()
            .expect("endpoint outbound order lock poisoned");
        let kinds = self
            .endpoint_kinds
            .read()
            .expect("endpoint outbound kind lock poisoned");
        items.extend(order.iter().filter_map(|tag| {
            kinds.get(tag).map(|kind| (tag.clone(), kind.clone()))
        }));
        items
    }

    pub(crate) fn populate_preferred_by(
        &self,
        metadata: &mut crate::route::Metadata,
        pre_match: bool,
    ) {
        let Ok(entries) = self.endpoint_entries.read() else {
            return;
        };
        let Ok(order) = self.endpoint_order.read() else {
            return;
        };
        metadata.preferred_by.retain(|candidate| {
            !order.iter().any(|tag| tag == candidate)
                && !self.bridges.iter().any(|bridge| bridge.tag() == candidate)
        });
        let domain = metadata.domain().map(str::to_owned);
        let mut addresses = metadata.destination_addresses.clone();
        if let Some(address) = metadata.destination_ip()
            && !addresses.contains(&address)
        {
            addresses.push(address);
        }
        for tag in order.iter() {
            if metadata.preferred_by.contains(tag) {
                continue;
            }
            let Some(dialer) = entries.get(tag) else {
                continue;
            };
            let preferred = domain
                .as_deref()
                .is_some_and(|domain| dialer.preferred_domain(domain))
                || addresses
                    .iter()
                    .any(|address| dialer.preferred_address(*address));
            if preferred {
                metadata.preferred_by.push(tag.clone());
            }
        }
        if pre_match {
            for bridge in &self.bridges {
                if metadata.preferred_by.iter().any(|tag| tag == bridge.tag()) {
                    continue;
                }
                if addresses.iter().copied().any(|address| {
                    bridge.preferred_address_for_pre_match(address)
                }) {
                    metadata.preferred_by.push(bridge.tag().to_owned());
                }
            }
        }
    }

    pub fn kind_owned(&self, tag: &str) -> Option<String> {
        self.kinds
            .get(tag)
            .cloned()
            .or_else(|| self.endpoint_kinds.read().ok()?.get(tag).cloned())
    }

    pub fn kind(&self, tag: &str) -> Option<&str> {
        self.kinds.get(tag).map(String::as_str)
    }

    pub fn group_choices(&self, tag: &str) -> Option<Vec<String>> {
        if let Some(selector) = self.selectors.get(tag) {
            return Some(selector.choices().map(str::to_owned).collect());
        }
        self.urltests
            .get(tag)
            .map(|group| group.choices().map(str::to_owned).collect())
    }

    pub fn group_selected(&self, tag: &str) -> Option<String> {
        self.selected_group(tag)
            .or_else(|| self.urltest_selected(tag))
    }

    pub fn default_tag(&self) -> &str {
        &self.default_tag
    }

    pub fn dns(&self) -> &TransportManager {
        &self.dns
    }

    pub fn direct(&self) -> SharedDialer {
        Arc::new(MeteredDialer {
            inner: self.action_direct.clone(),
            traffic: self.traffic.clone(),
            outbound: "direct".into(),
        })
    }

    pub(crate) fn http_client_dialer(
        &self,
        options: &DialerOptions,
        default_outbound: bool,
    ) -> Result<SharedDialer, OutboundError> {
        self.http_client_dialer_with_options(options, default_outbound, false)
    }

    pub(crate) fn http_client_dialer_with_options(
        &self,
        options: &DialerOptions,
        default_outbound: bool,
        disable_empty_direct_check: bool,
    ) -> Result<SharedDialer, OutboundError> {
        if default_outbound && options.detour.is_empty() {
            return Ok(self.default());
        }
        self.direct_or_detour_dialer(
            "http-client",
            options,
            disable_empty_direct_check,
        )
    }

    pub(crate) fn endpoint_dialer(
        &self,
        tag: &str,
        options: &DialerOptions,
    ) -> Result<SharedDialer, OutboundError> {
        self.direct_or_detour_dialer(tag, options, false)
    }

    pub(crate) fn resolver_on_detour_dialer(
        &self,
        owner: &str,
        options: &DialerOptions,
        require_unambiguous_resolver: bool,
    ) -> Result<SharedDialer, OutboundError> {
        let mut abstract_options = options.abstract_options.clone();
        self.apply_platform_network_defaults(&mut abstract_options);
        if require_unambiguous_resolver
            && abstract_options.domain_resolver.is_none()
            && self.dns.tags().nth(1).is_some()
        {
            return Err(unsupported(
                owner,
                "domain resolver",
                "missing domain resolver for domain server address",
            ));
        }
        if options.detour.is_empty() {
            return self.direct_or_detour_dialer(owner, options, false);
        }
        self.reject_empty_direct_detour(owner, &options.detour, false)?;
        let dialer = self.outbound(&options.detour).ok_or_else(|| {
            OutboundError::DependencyNotFound {
                outbound: owner.into(),
                dependency: options.detour.clone(),
            }
        })?;
        let (resolver, strategy) =
            dialer_resolver(&self.dns, owner, &abstract_options)?;
        Ok(Arc::new(ResolvingDetourDialer::new(
            dialer, resolver, strategy,
        )))
    }

    pub(crate) fn endpoint_destination_resolver(
        &self,
        owner: &str,
        options: &DialerOptions,
    ) -> Result<(SharedResolver, DomainStrategy), OutboundError> {
        let mut abstract_options = options.abstract_options.clone();
        self.apply_platform_network_defaults(&mut abstract_options);
        dialer_resolver(&self.dns, owner, &abstract_options)
    }

    fn direct_or_detour_dialer(
        &self,
        owner: &str,
        options: &DialerOptions,
        disable_empty_direct_check: bool,
    ) -> Result<SharedDialer, OutboundError> {
        if !options.detour.is_empty() {
            self.reject_empty_direct_detour(
                owner,
                &options.detour,
                disable_empty_direct_check,
            )?;
            let dialer = self.outbound(&options.detour).ok_or_else(|| {
                OutboundError::DependencyNotFound {
                    outbound: owner.into(),
                    dependency: options.detour.clone(),
                }
            })?;
            if options.abstract_options.domain_resolver.is_none() {
                return Ok(dialer);
            }
            let (resolver, strategy) =
                dialer_resolver(&self.dns, owner, &options.abstract_options)?;
            return Ok(Arc::new(ResolvingDetourDialer::new(
                dialer, resolver, strategy,
            )));
        }
        let mut direct_options = DirectOutboundOptions {
            dialer: options.clone(),
            ..Default::default()
        };
        self.apply_platform_network_defaults(
            &mut direct_options.dialer.abstract_options,
        );
        let (resolver, strategy) = dialer_resolver(
            &self.dns,
            owner,
            &direct_options.dialer.abstract_options,
        )?;
        let direct = DirectOutbound::with_underlay_resolver(
            direct_options,
            resolver,
            strategy,
        );
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        let direct = match self.platform_network_provider.as_ref() {
            Some(provider) => {
                direct.with_platform_network_provider(provider.clone())
            }
            None => direct,
        };
        let direct = self.attach_auto_detect_interface(direct);
        Ok(Arc::new(direct))
    }

    fn reject_empty_direct_detour(
        &self,
        owner: &str,
        detour: &str,
        disabled: bool,
    ) -> Result<(), OutboundError> {
        if !disabled && self.empty_direct_tags.contains(detour) {
            return Err(unsupported(
                owner,
                "detour",
                "detour to an empty direct outbound makes no sense",
            ));
        }
        Ok(())
    }

    fn attach_auto_detect_interface(
        &self,
        direct: DirectOutbound,
    ) -> DirectOutbound {
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        if let Some(provider) =
            self.route_dialer_defaults.auto_detect_interface.as_ref()
        {
            return direct
                .with_auto_detect_interface_provider(provider.clone());
        }
        direct
    }

    fn apply_platform_network_defaults(
        &self,
        options: &mut AbstractDialerOptions,
    ) {
        self.route_dialer_defaults.apply(options);
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        self.platform_network_defaults.apply(options);
    }

    pub fn select_group(
        &self,
        group: &str,
        outbound: &str,
    ) -> Result<(), OutboundError> {
        let selector = self.selectors.get(group).ok_or_else(|| {
            OutboundError::Unsupported {
                tag: group.to_owned(),
                kind: "selector".into(),
                detail: "selector group not found".into(),
            }
        })?;
        selector
            .select(outbound)
            .map_err(|error| OutboundError::Unsupported {
                tag: group.to_owned(),
                kind: "selector".into(),
                detail: error.to_string(),
            })
    }

    pub fn selected_group(&self, group: &str) -> Option<String> {
        self.selectors
            .get(group)
            .map(|selector| selector.selected())
    }

    pub fn urltest_selected(&self, group: &str) -> Option<String> {
        self.urltests.get(group).and_then(|group| group.selected())
    }

    pub fn urltest_history(&self, group: &str) -> Option<HashMap<String, u16>> {
        self.urltests.get(group).map(|group| group.history())
    }

    /// Subscribe to URLTest history and selector-selection changes.
    ///
    /// Each event is an edge-triggered invalidation signal. Consumers should
    /// reload the desired history entries after receiving it. A lagged
    /// receiver can likewise reload once and continue, matching the upstream
    /// observable's coalescing semantics.
    pub fn subscribe_urltest_updates(&self) -> broadcast::Receiver<()> {
        self.groups.subscribe_updates()
    }

    pub async fn refresh_urltest(
        &self,
        group: &str,
    ) -> Result<HashMap<String, u16>, OutboundError> {
        let urltest = self.urltests.get(group).ok_or_else(|| {
            unsupported(group, "urltest", "URLTest group not found")
        })?;
        Ok(urltest.refresh(true).await)
    }

    pub async fn test_outbound_delay(
        &self,
        tag: &str,
        url: &str,
        timeout: std::time::Duration,
    ) -> io::Result<u16> {
        let dialer = self.entries.get(tag).cloned().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "outbound not found")
        })?;
        let url = url::Url::parse(if url.is_empty() {
            "https://www.gstatic.com/generate_204"
        } else {
            url
        })
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let real_tag = self.real_tag(tag);
        let result = probe_url_with_timeout(dialer, &url, timeout).await;
        let mut history = self
            .urltest_history
            .lock()
            .expect("URL test history lock poisoned");
        match &result {
            Ok(delay) => {
                history.insert(real_tag, (SystemTime::now(), *delay));
            }
            Err(_) => {
                history.remove(&real_tag);
            }
        }
        drop(history);
        self.groups.notify_updated();
        result
    }

    pub async fn test_group_delay(
        &self,
        tag: &str,
        url: &str,
        timeout: std::time::Duration,
    ) -> io::Result<HashMap<String, u16>> {
        if self.group_choices(tag).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "outbound group not found",
            ));
        }
        let mut visited = HashSet::new();
        let mut groups = Vec::new();
        let mut choices = Vec::new();
        self.collect_group_delay_targets(
            tag,
            &mut visited,
            &mut groups,
            &mut choices,
        );
        if choices.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "outbound group has no testable members",
            ));
        }
        let tests = choices.into_iter().map(|choice| async move {
            let result = self.test_outbound_delay(&choice, url, timeout).await;
            (choice, result)
        });
        let mut result: HashMap<_, _> = join_all(tests)
            .await
            .into_iter()
            .filter_map(|(tag, result)| result.ok().map(|delay| (tag, delay)))
            .collect();
        for group in groups {
            if let Some(delay) = result.get(&self.real_tag(&group)).copied() {
                result.insert(group, delay);
            }
        }
        Ok(result)
    }

    fn collect_group_delay_targets(
        &self,
        tag: &str,
        visited: &mut HashSet<String>,
        groups: &mut Vec<String>,
        leaves: &mut Vec<String>,
    ) {
        if !visited.insert(tag.to_owned()) {
            return;
        }
        if let Some(choices) = self.group_choices(tag) {
            groups.push(tag.to_owned());
            for choice in choices {
                self.collect_group_delay_targets(
                    &choice, visited, groups, leaves,
                );
            }
        } else if self.entries.contains_key(tag) {
            leaves.push(tag.to_owned());
        }
    }

    pub fn urltest_history_entry(
        &self,
        tag: &str,
    ) -> Option<(SystemTime, u16)> {
        let real_tag = self.real_tag(tag);
        let manual = self
            .urltest_history
            .lock()
            .expect("URL test history lock poisoned")
            .get(&real_tag)
            .copied();
        self.urltests
            .values()
            .filter_map(|group| group.history_entry(&real_tag))
            .chain(manual)
            .max_by_key(|(time, _)| *time)
    }

    fn real_tag(&self, tag: &str) -> String {
        self.groups.real_tag(tag)
    }

    pub fn load_mode(&self) -> Option<String> {
        self.persistent_cache
            .as_ref()
            .and_then(|cache| cache.load_mode().ok().flatten())
    }

    pub fn save_mode(&self, mode: &str) {
        if let Some(cache) = &self.persistent_cache {
            let _ = cache.save_mode(mode);
        }
    }

    pub fn group_expand(&self, group: &str) -> io::Result<Option<bool>> {
        self.persistent_cache
            .as_ref()
            .map(|cache| cache.load_group_expand(group))
            .transpose()
            .map(Option::flatten)
    }

    pub fn set_group_expand(
        &self,
        group: &str,
        expanded: bool,
    ) -> io::Result<()> {
        if let Some(cache) = &self.persistent_cache {
            cache.save_group_expand(group, expanded)?;
        }
        Ok(())
    }

    pub fn traffic_totals(&self) -> (u64, u64) {
        self.traffic.totals()
    }

    pub fn process_traffic(&self) -> ProcessTrafficState {
        self.traffic.process_traffic_snapshot()
    }

    pub fn set_process_traffic_enabled(&self, enabled: bool) {
        self.traffic.set_process_traffic_enabled(enabled);
    }

    pub(crate) fn register_packet_flow(
        &self,
        outbound: &str,
        destination: &SocksAddr,
        network: &'static str,
    ) -> PacketFlowTracker {
        PacketFlowTracker {
            traffic: self.traffic.clone(),
            active: self.traffic.register(outbound, destination, network),
            closed: AtomicBool::new(false),
        }
    }

    pub fn connections(&self) -> Vec<ConnectionSnapshot> {
        self.traffic
            .connections
            .lock()
            .expect("traffic connections lock poisoned")
            .values()
            .map(ActiveConnection::snapshot)
            .collect()
    }

    pub(crate) fn connection_state(
        &self,
    ) -> (
        Vec<ConnectionSnapshot>,
        broadcast::Receiver<TrafficConnectionEvent>,
    ) {
        let connections = self
            .traffic
            .connections
            .lock()
            .expect("traffic connections lock poisoned");
        let receiver = self.traffic.events.subscribe();
        let snapshots = connections
            .values()
            .map(ActiveConnection::snapshot)
            .collect();
        (snapshots, receiver)
    }

    pub fn close_connection(&self, id: &str) {
        self.traffic.close(id);
    }

    pub fn close_all_connections(&self) {
        let ids = self
            .traffic
            .connections
            .lock()
            .expect("traffic connections lock poisoned")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for id in ids {
            self.traffic.close(&id);
        }
    }
}

struct MeteredDialer {
    inner: SharedDialer,
    traffic: Arc<TrafficCounters>,
    outbound: String,
}

impl Dialer for MeteredDialer {
    fn icmp_flow_addresses(
        &self,
    ) -> Option<(Option<std::net::IpAddr>, Option<std::net::IpAddr>)> {
        self.inner.icmp_flow_addresses()
    }

    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        self.inner.packet_port()
    }

    fn dial_tcp<'a>(
        &'a self,
        destination: &'a crate::common::network::SocksAddr,
    ) -> DialFuture<'a> {
        Box::pin(async move {
            let inner = self.inner.dial_tcp(destination).await?;
            let active =
                self.traffic.register(&self.outbound, destination, "tcp");
            let inner =
                interruptible_stream(inner, active.cancellation.clone());
            let socket = crate::adapter::stream_socket(&inner);
            Ok(crate::adapter::preserve_stream_socket(
                Box::new(MeteredStream {
                    inner,
                    traffic: self.traffic.clone(),
                    active,
                }),
                socket,
            ))
        })
    }

    fn dial_tcp_with_options<'a>(
        &'a self,
        destination: &'a crate::common::network::SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> DialFuture<'a> {
        Box::pin(async move {
            let inner = self
                .inner
                .dial_tcp_with_options(destination, options)
                .await?;
            let active =
                self.traffic.register(&self.outbound, destination, "tcp");
            let inner =
                interruptible_stream(inner, active.cancellation.clone());
            let socket = crate::adapter::stream_socket(&inner);
            Ok(crate::adapter::preserve_stream_socket(
                Box::new(MeteredStream {
                    inner,
                    traffic: self.traffic.clone(),
                    active,
                }),
                socket,
            ))
        })
    }

    fn bind_tcp<'a>(
        &'a self,
        destination: &'a crate::common::network::SocksAddr,
    ) -> DialFuture<'a> {
        Box::pin(async move {
            let inner = self.inner.bind_tcp(destination).await?;
            let active =
                self.traffic
                    .register(&self.outbound, destination, "tcp-bind");
            let inner =
                interruptible_stream(inner, active.cancellation.clone());
            let socket = crate::adapter::stream_socket(&inner);
            Ok(crate::adapter::preserve_stream_socket(
                Box::new(MeteredStream {
                    inner,
                    traffic: self.traffic.clone(),
                    active,
                }),
                socket,
            ))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a crate::common::network::SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let inner = self.inner.listen_udp(destination).await?;
            let active =
                self.traffic.register(&self.outbound, destination, "udp");
            Ok(Box::new(MeteredPacketConnection {
                inner,
                traffic: self.traffic.clone(),
                active,
            }) as PacketStream)
        })
    }

    fn listen_udp_with_options<'a>(
        &'a self,
        destination: &'a crate::common::network::SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let inner = self
                .inner
                .listen_udp_with_options(destination, options)
                .await?;
            let active =
                self.traffic.register(&self.outbound, destination, "udp");
            Ok(Box::new(MeteredPacketConnection {
                inner,
                traffic: self.traffic.clone(),
                active,
            }) as PacketStream)
        })
    }

    fn exchange_icmp<'a>(
        &'a self,
        packet: &'a [u8],
        source: std::net::IpAddr,
        hop_limit: u8,
        destination: &'a crate::common::network::SocksAddr,
    ) -> PacketFuture<'a, IcmpResponse> {
        Box::pin(async move {
            let active =
                self.traffic.register(&self.outbound, destination, "icmp");
            let _cleanup = ActiveConnectionCleanup {
                traffic: self.traffic.clone(),
                id: active.id.clone(),
            };
            let result = tokio::select! {
                biased;
                _ = active.cancellation.cancelled() => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "outbound group selection changed",
                )),
                result = self.inner.exchange_icmp(packet, source, hop_limit, destination) => result,
            };
            if let Ok(response) = &result {
                let upload = packet.len() as u64;
                let download = response.packet.len() as u64;
                self.traffic.count_upload(&active, upload);
                self.traffic.count_download(&active, download);
            }
            result
        })
    }

    fn exchange_icmp_with_options<'a>(
        &'a self,
        packet: &'a [u8],
        source: std::net::IpAddr,
        hop_limit: u8,
        destination: &'a crate::common::network::SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, IcmpResponse> {
        Box::pin(async move {
            let active =
                self.traffic.register(&self.outbound, destination, "icmp");
            let _cleanup = ActiveConnectionCleanup {
                traffic: self.traffic.clone(),
                id: active.id.clone(),
            };
            let result = tokio::select! {
                biased;
                _ = active.cancellation.cancelled() => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "outbound group selection changed",
                )),
                result = self.inner.exchange_icmp_with_options(
                    packet, source, hop_limit, destination, options
                ) => result,
            };
            if let Ok(response) = &result {
                let upload = packet.len() as u64;
                let download = response.packet.len() as u64;
                self.traffic.count_upload(&active, upload);
                self.traffic.count_download(&active, download);
            }
            result
        })
    }

    fn preferred_domain(&self, domain: &str) -> bool {
        self.inner.preferred_domain(domain)
    }

    fn preferred_address(&self, address: std::net::IpAddr) -> bool {
        self.inner.preferred_address(address)
    }
}

struct MeteredStream {
    inner: Stream,
    traffic: Arc<TrafficCounters>,
    active: ActiveHandle,
}

impl AsyncRead for MeteredStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if result.is_ready() {
            let size = buffer.filled().len().saturating_sub(before) as u64;
            self.traffic.count_download(&self.active, size);
        }
        result
    }
}

impl AsyncWrite for MeteredStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, buffer);
        if let Poll::Ready(Ok(size)) = &result {
            self.traffic.count_upload(&self.active, *size as u64);
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl Drop for MeteredStream {
    fn drop(&mut self) {
        self.traffic.remove(&self.active.id);
    }
}

struct MeteredPacketConnection {
    inner: PacketStream,
    traffic: Arc<TrafficCounters>,
    active: ActiveHandle,
}

impl PacketConnection for MeteredPacketConnection {
    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.local_addr()
    }

    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a crate::common::network::SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let size = tokio::select! {
                _ = self.active.cancellation.cancelled() => {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "connection closed"));
                }
                result = self.inner.send_to(data, destination) => result?,
            };
            self.traffic.count_upload(&self.active, size as u64);
            Ok(size)
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, crate::common::network::SocksAddr)> {
        Box::pin(async move {
            let (size, source) = tokio::select! {
                _ = self.active.cancellation.cancelled() => {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "connection closed"));
                }
                result = self.inner.recv_from(data) => result?,
            };
            self.traffic.count_download(&self.active, size as u64);
            Ok((size, source))
        })
    }
}

impl Drop for MeteredPacketConnection {
    fn drop(&mut self) {
        self.traffic.remove(&self.active.id);
    }
}

struct Builder {
    configs: HashMap<String, TaggedOptions>,
    order: Vec<String>,
    entries: HashMap<String, SharedDialer>,
    visiting: Vec<String>,
    visiting_set: HashSet<String>,
    dns: Arc<TransportManager>,
    selectors: HashMap<String, Arc<SelectorOutbound>>,
    urltests: HashMap<String, Arc<UrlTestOutbound>>,
    bridges: Vec<Arc<BridgeOutbound>>,
    groups: Arc<GroupRegistry>,
    base_path: std::path::PathBuf,
    persistent_cache: Option<Arc<PersistentDnsCache>>,
    ntp_clock: Option<NtpClock>,
    certificate_store:
        Option<crate::common::certificate_store::CertificateStore>,
    route_dialer_defaults: RouteDialerDefaults,
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    platform_network_provider: Option<Arc<dyn PlatformNetworkProvider>>,
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    platform_network_defaults: PlatformNetworkDefaults,
}

impl Builder {
    #[allow(clippy::too_many_arguments)]
    fn new(
        options: &[TaggedOptions],
        base_path: &Path,
        dns: Arc<TransportManager>,
        persistent_cache: Option<Arc<PersistentDnsCache>>,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<
            crate::common::certificate_store::CertificateStore,
        >,
        route_dialer_defaults: RouteDialerDefaults,
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        platform_network_provider: Option<
            Arc<dyn PlatformNetworkProvider>,
        >,
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        platform_network_defaults: PlatformNetworkDefaults,
    ) -> Self {
        let mut configs = HashMap::new();
        let mut order = Vec::new();
        for (index, option) in options.iter().enumerate() {
            let tag = effective_tag(option, index);
            order.push(tag.clone());
            configs.insert(tag, option.clone());
        }
        Self {
            configs,
            order,
            entries: HashMap::new(),
            visiting: Vec::new(),
            visiting_set: HashSet::new(),
            dns,
            selectors: HashMap::new(),
            urltests: HashMap::new(),
            bridges: Vec::new(),
            groups: Arc::default(),
            base_path: base_path.to_owned(),
            persistent_cache,
            ntp_clock,
            certificate_store,
            route_dialer_defaults,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_provider,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_defaults,
        }
    }

    fn build(
        mut self,
        requested_default: &str,
    ) -> Result<OutboundManager, OutboundError> {
        if self.order.is_empty() {
            self.order.push("direct".into());
            self.entries.insert(
                "direct".into(),
                Arc::new(
                    self.direct("direct", DirectOutboundOptions::default())?,
                ),
            );
        }
        for tag in self.order.clone() {
            self.build_tag(&tag)?;
        }
        let default_tag = if requested_default.is_empty() {
            self.order[0].clone()
        } else if self.entries.contains_key(requested_default) {
            requested_default.to_owned()
        } else {
            return Err(OutboundError::DefaultNotFound(
                requested_default.into(),
            ));
        };
        let mut kinds: HashMap<_, _> = self
            .configs
            .iter()
            .map(|(tag, options)| (tag.clone(), options.kind.clone()))
            .collect();
        let mut networks = HashMap::new();
        for (tag, option) in &self.configs {
            if let Some(capability) = configured_network_capability(option)? {
                networks.insert(tag.clone(), capability);
            }
        }
        if !kinds.contains_key("direct") && self.order == ["direct"] {
            kinds.insert("direct".into(), "direct".into());
        }
        let mut empty_direct_tags = HashSet::new();
        if self.configs.is_empty() && self.order == ["direct"] {
            empty_direct_tags.insert("direct".into());
        }
        for (tag, option) in &self.configs {
            if option.kind == "direct"
                && option.decode::<DirectOutboundOptions>()?
                    == DirectOutboundOptions::default()
            {
                empty_direct_tags.insert(tag.clone());
            }
        }
        let mut action_direct_options = DirectOutboundOptions::default();
        self.apply_platform_network_defaults(
            &mut action_direct_options.dialer.abstract_options,
        );
        let action_direct = DirectOutbound::with_resolver(
            action_direct_options,
            self.dns.default(),
            DomainStrategy::AsIs,
        );
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        let action_direct = match self.platform_network_provider.as_ref() {
            Some(provider) => {
                action_direct.with_platform_network_provider(provider.clone())
            }
            None => action_direct,
        };
        let action_direct = self.attach_auto_detect_interface(action_direct);
        let action_direct: SharedDialer = Arc::new(action_direct);
        Ok(OutboundManager {
            order: self.order,
            kinds,
            networks,
            entries: self.entries,
            route_direct_entries: HashMap::new(),
            endpoint_entries: RwLock::new(HashMap::new()),
            endpoint_order: RwLock::new(Vec::new()),
            endpoint_kinds: RwLock::new(HashMap::new()),
            empty_direct_tags,
            default_tag,
            dns: self.dns,
            selectors: self.selectors,
            urltests: self.urltests,
            bridges: self.bridges,
            groups: self.groups,
            persistent_cache: self.persistent_cache,
            traffic: Arc::new(TrafficCounters::default()),
            urltest_history: Mutex::new(HashMap::new()),
            action_direct,
            route_dialer_defaults: self.route_dialer_defaults,
            inbound_tcp_detours: RwLock::new(HashMap::new()),
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_provider: self.platform_network_provider,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_defaults: self.platform_network_defaults,
        })
    }

    fn build_tag(&mut self, tag: &str) -> Result<SharedDialer, OutboundError> {
        if let Some(outbound) = self.entries.get(tag) {
            return Ok(outbound.clone());
        }
        if !self.visiting_set.insert(tag.to_owned()) {
            let start = self
                .visiting
                .iter()
                .position(|item| item == tag)
                .unwrap_or(0);
            let mut cycle = self.visiting[start..].to_vec();
            cycle.push(tag.to_owned());
            return Err(OutboundError::CircularDependency(cycle.join(" -> ")));
        }
        self.visiting.push(tag.to_owned());
        let result = self.build_tag_inner(tag);
        self.visiting.pop();
        self.visiting_set.remove(tag);
        let outbound = result?;
        self.entries.insert(tag.to_owned(), outbound.clone());
        Ok(outbound)
    }

    fn build_tag_inner(
        &mut self,
        tag: &str,
    ) -> Result<SharedDialer, OutboundError> {
        let option = self.configs.get(tag).cloned().ok_or_else(|| {
            let outbound = self.visiting.first().cloned().unwrap_or_default();
            OutboundError::DependencyNotFound {
                outbound,
                dependency: tag.to_owned(),
            }
        })?;
        match option.kind.as_str() {
            "direct" => {
                let options: DirectOutboundOptions = option.decode()?;
                if !options.dialer.detour.is_empty() {
                    return Err(unsupported(
                        tag,
                        "direct detour",
                        "`detour` is not supported in direct context",
                    ));
                }
                Ok(Arc::new(self.direct(tag, options)?))
            }
            "block" => Ok(Arc::new(BlockOutbound)),
            "bridge" => {
                let options: BridgeOutboundOptions = option.decode()?;
                let bridge = BridgeOutbound::new(tag, options).map_err(|error| {
                    unsupported(tag, "bridge", error.to_string())
                })?;
                self.bridges.push(bridge.clone());
                Ok(bridge)
            }
            "shadowsocksr" => Err(OutboundError::Removed(
                "ShadowsocksR is deprecated and removed in sing-box 1.6.0"
                    .into(),
            )),
            "wireguard" => Err(OutboundError::Removed(
                "WireGuard outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use WireGuard endpoint instead"
                    .into(),
            )),
            "socks" => {
                let options: SocksOutboundOptions = option.decode()?;
                let version =
                    SocksVersion::parse(&options.version).map_err(|error| {
                        unsupported(tag, "SOCKS", error.to_string())
                    })?;
                let uot = options.udp_over_tcp.filter(|value| value.enabled);
                let upstream =
                    self.build_upstream(tag, &options.dialer)?;
                let server = SocksAddr::new(
                    options.server.server.clone(),
                    options.server.server_port,
                );
                let base: SharedDialer = match version {
                    SocksVersion::V5 => Arc::new(Socks5Outbound::new(
                        upstream,
                        server,
                        options.username,
                        options.password,
                    )),
                    SocksVersion::V4 | SocksVersion::V4a => {
                        Arc::new(Socks4Outbound::new(
                            upstream,
                            Arc::new(OutboundDnsResolver {
                                manager: self.dns.clone(),
                                outbound: tag.to_owned(),
                            }),
                            DomainStrategy::AsIs,
                            server,
                            options.username,
                            version == SocksVersion::V4,
                        ))
                    }
                };
                if let Some(uot) = uot {
                    Ok(Arc::new(UotOutbound::new(base, uot.version).map_err(
                        |error| {
                            unsupported(tag, "UDP-over-TCP", error.to_string())
                        },
                    )?))
                } else {
                    Ok(base)
                }
            }
            "http" => {
                let options: HttpOutboundOptions = option.decode()?;
                let mut upstream =
                    self.build_upstream(tag, &options.dialer)?;
                let server = SocksAddr::new(
                    options.server.server.clone(),
                    options.server.server_port,
                );
                if let Some(tls_options) =
                    options.tls.as_ref().filter(|tls| tls.enabled)
                {
                    let tls = build_client_config_with_runtime_context(
                        &options.server.server,
                        tls_options,
                        &[],
                        self.dns.clone(),
                        self.ntp_clock.clone(),
                    self.certificate_store.clone(),
                    )
                    .map_err(|error| {
                        OutboundError::Tls {
                            tag: tag.to_owned(),
                            message: error.to_string(),
                        }
                    })?;
                    upstream = Arc::new(ClientTlsDialer::new(upstream, tls));
                }
                Ok(Arc::new(HttpConnectOutbound::new(
                    upstream,
                    server,
                    options.username,
                    options.password,
                    options.path,
                    options.headers,
                )))
            }
            "naive" => {
                let options: NaiveOutboundOptions = option.decode()?;
                let tls_options =
                    options.tls.as_ref().filter(|tls| tls.enabled).ok_or_else(
                        || unsupported(tag, "NaiveProxy", "TLS is required"),
                    )?;
                if tls_options.disable_sni
                    || tls_options.insecure
                    || !tls_options.alpn.as_slice().is_empty()
                    || !tls_options.min_version.is_empty()
                    || !tls_options.max_version.is_empty()
                    || !tls_options.cipher_suites.as_slice().is_empty()
                    || !tls_options.curve_preferences.as_slice().is_empty()
                    || !tls_options.client_certificate.as_slice().is_empty()
                    || !tls_options.client_certificate_path.is_empty()
                    || !tls_options.client_key.as_slice().is_empty()
                    || !tls_options.client_key_path.is_empty()
                    || tls_options.fragment
                    || tls_options.record_fragment
                    || tls_options.kernel_tx
                    || tls_options.kernel_rx
                    || tls_options
                        .utls
                        .as_ref()
                        .is_some_and(|value| value.enabled)
                    || tls_options
                        .reality
                        .as_ref()
                        .is_some_and(|value| value.enabled)
                {
                    return Err(unsupported(
                        tag,
                        "NaiveProxy TLS",
                        "this option is rejected by the upstream Cronet client",
                    ));
                }
                if options.server.server.is_empty()
                    || options.server.server_port == 0
                {
                    return Err(unsupported(
                        tag,
                        "NaiveProxy server",
                        "server and server_port are required",
                    ));
                }
                if options.quic && options.insecure_concurrency > 1 {
                    return Err(unsupported(
                        tag,
                        "NaiveProxy QUIC",
                        "insecure concurrency is not supported with QUIC",
                    ));
                }
                let server = SocksAddr::new(
                    options.server.server.clone(),
                    options.server.server_port,
                );
                let server_name = if tls_options.server_name.is_empty() {
                    options.server.server.clone()
                } else {
                    tls_options.server_name.clone()
                };
                let tls = build_client_config_with_runtime_context(
                    &options.server.server,
                    tls_options,
                    if options.quic {
                        &["h3"]
                    } else {
                        &["h2", "http/1.1"]
                    },
                    self.dns.clone(),
                    self.ntp_clock.clone(),
                self.certificate_store.clone(),
                )
                .map_err(|error| OutboundError::Tls {
                    tag: tag.to_owned(),
                    message: error.to_string(),
                })?;
                let base: SharedDialer = if options.quic {
                    let upstream = self
                        .build_upstream_resolver_on_detour(
                            tag,
                            &options.dialer,
                        )?;
                    Arc::new(
                        NaiveHttp3Outbound::new_with_packet_dialer(
                            server,
                            server_name,
                            options.username,
                            options.password,
                            options.extra_headers,
                            tls,
                            options
                                .stream_receive_window
                                .map(|value| value.value()),
                            options
                                .quic_session_receive_window
                                .map(|value| value.value()),
                            &options.quic_congestion_control,
                            upstream,
                        )
                        .map_err(|error| {
                            unsupported(
                                tag,
                                "NaiveProxy QUIC",
                                error.to_string(),
                            )
                        })?,
                    )
                } else {
                    if options.quic_session_receive_window.is_some()
                        || !options.quic_congestion_control.is_empty()
                    {
                        return Err(unsupported(
                            tag,
                            "NaiveProxy Cronet tuning",
                            "QUIC session receive-window and congestion tuning require quic=true",
                        ));
                    }
                    let upstream = self
                        .build_upstream_resolver_on_detour(
                            tag,
                            &options.dialer,
                        )?;
                    Arc::new(
                        NaiveOutbound::new_tls_with_options(
                            upstream,
                            server,
                            options.username,
                            options.password,
                            options.extra_headers,
                            tls,
                            options.insecure_concurrency,
                            options
                                .stream_receive_window
                                .map(|value| value.value()),
                        )
                        .map_err(|error| {
                            unsupported(
                                tag,
                                "NaiveProxy HTTP/2",
                                error.to_string(),
                            )
                        })?,
                    )
                };
                if let Some(uot) =
                    options.udp_over_tcp.filter(|value| value.enabled)
                {
                    Ok(Arc::new(UotOutbound::new(base, uot.version).map_err(
                        |error| {
                            unsupported(
                                tag,
                                "NaiveProxy UoT",
                                error.to_string(),
                            )
                        },
                    )?))
                } else {
                    Ok(base)
                }
            }
            "ssh" => {
                let options: SshOutboundOptions = option.decode()?;
                let upstream =
                    self.build_upstream(tag, &options.dialer)?;
                Ok(Arc::new(SshOutbound::new(upstream, options).map_err(
                    |error| unsupported(tag, "SSH", error.to_string()),
                )?))
            }
            "tor" => {
                let options: TorOutboundOptions = option.decode()?;
                let upstream =
                    self.build_upstream(tag, &options.dialer)?;
                let data_directory = (!options.data_directory.is_empty())
                    .then(|| expand_data_directory(&options.data_directory))
                    .map(|path| {
                        if path.is_absolute() {
                            path
                        } else {
                            self.base_path.join(path)
                        }
                    });
                if !options.executable_path.is_empty()
                    || !options.extra_args.is_empty()
                    || !options.torrc.is_empty()
                {
                    Ok(Arc::new(ExternalTorOutbound::new(
                        upstream,
                        ExternalTorConfig {
                            executable_path: options.executable_path,
                            extra_args: options.extra_args,
                            data_directory,
                            torrc: options.torrc,
                        },
                    )))
                } else {
                    Ok(Arc::new(TorOutbound::new(
                        upstream,
                        data_directory.as_deref(),
                    )))
                }
            }
            "shadowtls" => {
                let options: ShadowTlsOutboundOptions = option.decode()?;
                let version = if options.version == 0 {
                    1
                } else {
                    options.version
                };
                if !matches!(version, 1..=3) {
                    return Err(unsupported(
                        tag,
                        "ShadowTLS",
                        format!("version {version} is not ported yet"),
                    ));
                }
                let mut tls_options =
                    options.tls.filter(|tls| tls.enabled).ok_or_else(|| {
                        unsupported(tag, "ShadowTLS", "TLS is required")
                    })?;
                if version == 1 {
                    tls_options.min_version = "1.2".into();
                    tls_options.max_version = "1.2".into();
                }
                let tls = build_client_config_with_runtime_context(
                    &options.server.server,
                    &tls_options,
                    &[],
                    self.dns.clone(),
                    self.ntp_clock.clone(),
                self.certificate_store.clone(),
                )
                .map_err(|error| OutboundError::Tls {
                    tag: tag.to_owned(),
                    message: error.to_string(),
                })?;
                let upstream =
                    self.build_upstream(tag, &options.dialer)?;
                let server = SocksAddr::new(
                    options.server.server,
                    options.server.server_port,
                );
                match version {
                    1 => Ok(Arc::new(ShadowTlsV1Outbound::new(
                        upstream, server, tls,
                    ))),
                    2 => Ok(Arc::new(ShadowTlsV1Outbound::new_v2(
                        upstream,
                        server,
                        options.password,
                        tls,
                    ))),
                    3 => Ok(Arc::new(ShadowTlsV1Outbound::new_v3(
                        upstream,
                        server,
                        options.password,
                        tls,
                    ))),
                    _ => unreachable!("validated ShadowTLS version"),
                }
            }
            "snell" => {
                let options: SnellOutboundOptions = option.decode()?;
                let upstream =
                    self.build_upstream(tag, &options.dialer)?;
                let server = SocksAddr::new(
                    options.server.server,
                    options.server.server_port,
                );
                match options.version {
                    4 => Ok(Arc::new(
                        SnellV4Outbound::new_with_obfs(
                            upstream,
                            server,
                            options.psk,
                            options.userkey,
                            SnellObfsMode::parse(&options.obfs_mode).map_err(
                                |error| {
                                    unsupported(tag, "Snell", error.to_string())
                                },
                            )?,
                            options.obfs_host,
                            options.reuse,
                        )
                        .map_err(|error| {
                            unsupported(tag, "Snell", error.to_string())
                        })?,
                    )),
                    6 => Ok(Arc::new(
                        SnellV6Outbound::new(
                            upstream,
                            server,
                            options.psk,
                            options.userkey,
                            SnellV6Mode::parse(&options.mode).map_err(
                                |error| {
                                    unsupported(tag, "Snell", error.to_string())
                                },
                            )?,
                            options.reuse,
                        )
                        .map_err(|error| {
                            unsupported(tag, "Snell", error.to_string())
                        })?,
                    )),
                    _ => Err(unsupported(
                        tag,
                        "Snell",
                        "unsupported client version",
                    )),
                }
            }
            "trojan" => {
                let options: TrojanOutboundOptions = option.decode()?;
                let quic = matches!(
                    options.transport,
                    Some(V2RayTransportOptions::Quic)
                );
                let server = SocksAddr::new(
                    options.server.server.clone(),
                    options.server.server_port,
                );
                let mut upstream =
                    self.build_upstream(tag, &options.dialer)?;
                if let Some(tls_options) =
                    options.tls.as_ref().filter(|tls| tls.enabled)
                {
                    let tls = build_client_config_with_runtime_context(
                        &options.server.server,
                        tls_options,
                        tls_alpn(options.transport.as_ref()),
                        self.dns.clone(),
                        self.ntp_clock.clone(),
                    self.certificate_store.clone(),
                    )
                    .map_err(|error| {
                        OutboundError::Tls {
                            tag: tag.to_owned(),
                            message: error.to_string(),
                        }
                    })?;
                    if quic {
                        upstream = Arc::new(
                            QuicDialer::new_with_packet_dialer(
                                server.clone(),
                                if tls_options.server_name.is_empty() {
                                    options.server.server.clone()
                                } else {
                                    tls_options.server_name.clone()
                                },
                                tls,
                                upstream.clone(),
                            )
                            .map_err(|error| {
                                unsupported(
                                    tag,
                                    "V2Ray QUIC",
                                    error.to_string(),
                                )
                            })?,
                        );
                    } else {
                        upstream =
                            Arc::new(ClientTlsDialer::new(upstream, tls));
                    }
                } else if quic {
                    return Err(unsupported(
                        tag,
                        "V2Ray QUIC",
                        "TLS is required",
                    ));
                }
                if !quic {
                    upstream = self.wrap_v2ray_transport(
                        tag,
                        upstream,
                        &server,
                        options.transport.as_ref(),
                        options.tls.as_ref().is_some_and(|tls| tls.enabled),
                    )?;
                }
                let base: SharedDialer = Arc::new(TrojanOutbound::new(
                    upstream,
                    server,
                    &options.password,
                ));
                self.wrap_multiplex(tag, base, options.multiplex.as_ref())
            }
            "vless" => {
                let options: VlessOutboundOptions = option.decode()?;
                if !matches!(
                    options.flow.as_str(),
                    "" | crate::protocol::vless::FLOW_VISION
                ) {
                    return Err(unsupported(
                        tag,
                        "VLESS flow",
                        format!("unknown flow {:?}", options.flow),
                    ));
                }
                let (legacy_udp, packet_addr) =
                    match options.packet_encoding.as_deref() {
                        Some("") => (true, false),
                        None | Some("xudp") => (false, false),
                        Some("packetaddr") => (true, true),
                        Some(value) => {
                            return Err(unsupported(
                                tag,
                                "VLESS packet encoding",
                                format!("unknown packet encoding {value:?}"),
                            ));
                        }
                    };
                let quic = matches!(
                    options.transport,
                    Some(V2RayTransportOptions::Quic)
                );
                let server = SocksAddr::new(
                    options.server.server.clone(),
                    options.server.server_port,
                );
                let mut upstream =
                    self.build_upstream(tag, &options.dialer)?;
                if let Some(tls_options) =
                    options.tls.as_ref().filter(|tls| tls.enabled)
                {
                    let tls = build_client_config_with_runtime_context(
                        &options.server.server,
                        tls_options,
                        tls_alpn(options.transport.as_ref()),
                        self.dns.clone(),
                        self.ntp_clock.clone(),
                    self.certificate_store.clone(),
                    )
                    .map_err(|error| {
                        OutboundError::Tls {
                            tag: tag.to_owned(),
                            message: error.to_string(),
                        }
                    })?;
                    if quic {
                        upstream = Arc::new(
                            QuicDialer::new_with_packet_dialer(
                                server.clone(),
                                if tls_options.server_name.is_empty() {
                                    options.server.server.clone()
                                } else {
                                    tls_options.server_name.clone()
                                },
                                tls,
                                upstream.clone(),
                            )
                            .map_err(|error| {
                                unsupported(
                                    tag,
                                    "V2Ray QUIC",
                                    error.to_string(),
                                )
                            })?,
                        );
                    } else {
                        upstream =
                            Arc::new(ClientTlsDialer::new(upstream, tls));
                    }
                } else if quic {
                    return Err(unsupported(
                        tag,
                        "V2Ray QUIC",
                        "TLS is required",
                    ));
                }
                if !quic {
                    upstream = self.wrap_v2ray_transport(
                        tag,
                        upstream,
                        &server,
                        options.transport.as_ref(),
                        options.tls.as_ref().is_some_and(|tls| tls.enabled),
                    )?;
                }
                let base: SharedDialer = Arc::new(
                    VlessOutbound::new_with_flow(
                        upstream,
                        server,
                        &options.uuid,
                        legacy_udp,
                        packet_addr,
                        &options.flow,
                    )
                    .map_err(|error| {
                        unsupported(tag, "VLESS", error.to_string())
                    })?,
                );
                self.wrap_multiplex(tag, base, options.multiplex.as_ref())
            }
            "shadowsocks" => {
                let options: ShadowsocksOutboundOptions = option.decode()?;
                if !matches!(
                    options.plugin.as_str(),
                    "" | "obfs-local" | "v2ray-plugin"
                ) {
                    return Err(unsupported(
                        tag,
                        "Shadowsocks SIP003 plugin",
                        format!("plugin not found: {}", options.plugin),
                    ));
                }
                let uot = options.udp_over_tcp.filter(|value| value.enabled);
                if uot.is_some()
                    && options
                        .multiplex
                        .as_ref()
                        .is_some_and(|multiplex| multiplex.enabled)
                {
                    return Err(unsupported(
                        tag,
                        "Shadowsocks multiplex",
                        "multiplex conflicts with udp_over_tcp",
                    ));
                }
                let mut upstream =
                    self.build_upstream(tag, &options.dialer)?;
                let server = SocksAddr::new(
                    options.server.server,
                    options.server.server_port,
                );
                if options.plugin == "obfs-local" {
                    let plugin = SimpleObfsOptions::parse(&options.plugin_opts)
                        .map_err(|error| {
                            unsupported(
                                tag,
                                "Shadowsocks obfs-local",
                                error.to_string(),
                            )
                        })?;
                    upstream = Arc::new(SimpleObfsDialer::new(
                        upstream,
                        server.clone(),
                        plugin,
                    ));
                } else if options.plugin == "v2ray-plugin" {
                    let mut plugin =
                        V2RayPluginOptions::parse(&options.plugin_opts)
                            .map_err(|error| {
                                unsupported(
                                    tag,
                                    "Shadowsocks v2ray-plugin",
                                    error.to_string(),
                                )
                            })?;
                    if let Some(tls) = plugin.tls.as_mut() {
                        tls.set_runtime_context(
                            self.ntp_clock.clone(),
                            self.certificate_store.clone(),
                        );
                    }
                    upstream = Arc::new(
                        V2RayPluginDialer::new(
                            upstream,
                            server.clone(),
                            plugin,
                        )
                        .map_err(|error| {
                            unsupported(
                                tag,
                                "Shadowsocks v2ray-plugin",
                                error.to_string(),
                            )
                        })?,
                    );
                }
                let base: SharedDialer = Arc::new(
                    ShadowsocksOutbound::new_with_clock(
                        upstream,
                        server,
                        &options.method,
                        &options.password,
                        self.ntp_clock.clone(),
                    )
                    .map_err(|error| {
                        unsupported(tag, "Shadowsocks", error.to_string())
                    })?,
                );
                if let Some(uot) = uot {
                    Ok(Arc::new(UotOutbound::new(base, uot.version).map_err(
                        |error| {
                            unsupported(tag, "UDP-over-TCP", error.to_string())
                        },
                    )?))
                } else {
                    self.wrap_multiplex(tag, base, options.multiplex.as_ref())
                }
            }
            "vmess" => {
                let options: VMessOutboundOptions = option.decode()?;
                let quic = matches!(
                    options.transport,
                    Some(V2RayTransportOptions::Quic)
                );
                let server = SocksAddr::new(
                    options.server.server.clone(),
                    options.server.server_port,
                );
                let mut upstream =
                    self.build_upstream(tag, &options.dialer)?;
                if let Some(tls_options) =
                    options.tls.as_ref().filter(|tls| tls.enabled)
                {
                    let tls = build_client_config_with_runtime_context(
                        &options.server.server,
                        tls_options,
                        tls_alpn(options.transport.as_ref()),
                        self.dns.clone(),
                        self.ntp_clock.clone(),
                    self.certificate_store.clone(),
                    )
                    .map_err(|error| {
                        OutboundError::Tls {
                            tag: tag.to_owned(),
                            message: error.to_string(),
                        }
                    })?;
                    if quic {
                        upstream = Arc::new(
                            QuicDialer::new_with_packet_dialer(
                                server.clone(),
                                if tls_options.server_name.is_empty() {
                                    options.server.server.clone()
                                } else {
                                    tls_options.server_name.clone()
                                },
                                tls,
                                upstream.clone(),
                            )
                            .map_err(|error| {
                                unsupported(
                                    tag,
                                    "V2Ray QUIC",
                                    error.to_string(),
                                )
                            })?,
                        );
                    } else {
                        upstream =
                            Arc::new(ClientTlsDialer::new(upstream, tls));
                    }
                } else if quic {
                    return Err(unsupported(
                        tag,
                        "V2Ray QUIC",
                        "TLS is required",
                    ));
                }
                if !quic {
                    upstream = self.wrap_v2ray_transport(
                        tag,
                        upstream,
                        &server,
                        options.transport.as_ref(),
                        options.tls.as_ref().is_some_and(|tls| tls.enabled),
                    )?;
                }
                let base: SharedDialer = Arc::new(
                    VmessOutbound::new_with_clock(
                        upstream,
                        server,
                        &options.uuid,
                        VmessClientConfig {
                            security: &options.security,
                            alter_id: options.alter_id,
                            global_padding: options.global_padding,
                            authenticated_length: options.authenticated_length,
                            packet_encoding: &options.packet_encoding,
                        },
                        self.ntp_clock.clone(),
                    )
                    .map_err(|error| {
                        unsupported(tag, "VMess", error.to_string())
                    })?,
                );
                self.wrap_multiplex(tag, base, options.multiplex.as_ref())
            }
            "anytls" => {
                let options: AnyTlsOutboundOptions = option.decode()?;
                if options.tls.as_ref().is_none_or(|tls| !tls.enabled) {
                    return Err(unsupported(tag, "AnyTLS", "TLS is required"));
                }
                if options.dialer.abstract_options.tcp_fast_open {
                    return Err(unsupported(
                        tag,
                        "AnyTLS",
                        "tcp_fast_open is incompatible with AnyTLS",
                    ));
                }
                let server = SocksAddr::new(
                    options.server.server.clone(),
                    options.server.server_port,
                );
                let mut upstream =
                    self.build_upstream(tag, &options.dialer)?;
                let tls_options = options.tls.as_ref().expect("checked above");
                let tls = build_client_config_with_runtime_context(
                    &options.server.server,
                    tls_options,
                    &[],
                    self.dns.clone(),
                    self.ntp_clock.clone(),
                self.certificate_store.clone(),
                )
                .map_err(|error| OutboundError::Tls {
                    tag: tag.to_owned(),
                    message: error.to_string(),
                })?;
                upstream = Arc::new(ClientTlsDialer::new(upstream, tls));
                let base: SharedDialer = Arc::new(
                    AnyTlsOutbound::new_with_session_policy(
                    upstream,
                    server,
                    &options.password,
                    options.client_metadata,
                    options
                        .idle_session_check_interval
                        .as_std()
                        .unwrap_or_default(),
                    options
                        .idle_session_timeout
                        .as_std()
                        .unwrap_or_default(),
                    options.min_idle_session,
                ));
                Ok(Arc::new(
                    UotOutbound::new(base, crate::protocol::uot::VERSION)
                        .map_err(|error| {
                            unsupported(tag, "AnyTLS UoT", error.to_string())
                        })?,
                ))
            }
            "hysteria2" => {
                let options: Hysteria2OutboundOptions = option.decode()?;
                let bbr_profile =
                    crate::protocol::quic_bbr::BbrProfile::parse(
                        &options.bbr_profile,
                    )
                    .map_err(|error| {
                        unsupported(
                        tag,
                        "Hysteria2 BBR profile",
                        error.to_string(),
                    )
                    })?;
                let chrome_parrot = !options.disable_chrome_parrot;
                let mut tls_options =
                    options.tls.as_ref().filter(|tls| tls.enabled).ok_or_else(
                        || unsupported(tag, "Hysteria2", "TLS is required"),
                    )?.clone();
                tls_options.chrome_quic_parrot = chrome_parrot;
                let mut upstream =
                    self.build_upstream(tag, &options.dialer)?;
                let obfs = match options.obfs.as_ref() {
                    None => None,
                    Some(value) if value.password().is_empty() => {
                        return Err(unsupported(
                            tag,
                            "Hysteria2 obfuscation",
                            "missing obfs password",
                        ));
                    }
                    Some(Hysteria2Obfs::Salamander { password }) => {
                        Some(Hysteria2ObfsConfig::Salamander {
                            password: password.as_bytes().to_vec(),
                        })
                    }
                    Some(Hysteria2Obfs::Gecko {
                        password,
                        min_packet_size,
                        max_packet_size,
                    }) => Some(
                        Hysteria2ObfsConfig::gecko(
                            password.as_bytes().to_vec(),
                            usize::try_from(*min_packet_size).map_err(
                                |_| {
                                    unsupported(
                                        tag,
                                        "Hysteria2 Gecko obfuscation",
                                        "negative min_packet_size",
                                    )
                                },
                            )?,
                            usize::try_from(*max_packet_size).map_err(
                                |_| {
                                    unsupported(
                                        tag,
                                        "Hysteria2 Gecko obfuscation",
                                        "negative max_packet_size",
                                    )
                                },
                            )?,
                        )
                        .map_err(|error| {
                            unsupported(
                                tag,
                                "Hysteria2 Gecko obfuscation",
                                error.to_string(),
                            )
                        })?,
                    ),
                };
                let server_ports = parse_server_ports(&options.server_ports.0)
                    .map_err(|error| {
                        unsupported(
                            tag,
                            "Hysteria2 port hopping",
                            error.to_string(),
                        )
                    })?;
                let realm = options
                    .realm
                    .as_ref()
                    .map(|realm| {
                        if !options.server.server.is_empty()
                            || options.server.server_port != 0
                            || !server_ports.is_empty()
                        {
                            return Err(unsupported(
                                tag,
                                "Hysteria2 realm",
                                "realm conflicts with server, server_port, and server_ports",
                            ));
                        }
                        let server_url = reqwest::Url::parse(&realm.server_url)
                            .map_err(|error| {
                                unsupported(
                                    tag,
                                    "Hysteria2 realm",
                                    format!("parse realm server_url: {error}"),
                                )
                            })?;
                        let server_host = server_url
                            .host_str()
                            .filter(|host| !host.is_empty())
                            .ok_or_else(|| {
                                unsupported(
                                    tag,
                                    "Hysteria2 realm",
                                    "missing host in realm server_url",
                                )
                            })?
                            .to_owned();
                        let mut http_options =
                            realm.http_client.clone().unwrap_or_default();
                        http_options
                            .tls
                            .get_or_insert_with(Default::default)
                            .set_runtime_context(
                                self.ntp_clock.clone(),
                                self.certificate_store.clone(),
                            );
                        let http_dialer = self
                            .build_upstream(tag, &http_options.dialer)
                            .map_err(|error| {
                                unsupported(
                                    tag,
                                    "Hysteria2 realm HTTP dialer",
                                    error.to_string(),
                                )
                            })?;
                        let control = RealmControlClient::new_with_dialer(
                            realm.server_url.clone(),
                            realm.token.clone(),
                            http_dialer,
                            http_options,
                            self.ntp_clock.clone(),
                        )
                        .map_err(|error| {
                            unsupported(
                                tag,
                                "Hysteria2 realm",
                                error.to_string(),
                            )
                        })?;
                        let mut connector = RealmClientConnector::new(
                            control,
                            realm.realm_id.clone(),
                            realm.stun_servers.0.clone(),
                            realm.ip_version,
                        )
                        .map_err(|error| {
                            unsupported(
                                tag,
                                "Hysteria2 realm",
                                error.to_string(),
                            )
                        })?;
                        if let Some(mapping) = realm
                            .port_mapping
                            .as_ref()
                            .filter(|mapping| mapping.enabled)
                        {
                            connector = connector
                                .with_port_mapping(
                                    crate::protocol::hysteria2_realm::RealmPortMappingOptions::new(
                                        mapping.timeout.as_std(),
                                        mapping.lifetime.as_std(),
                                    ),
                                )
                                .map_err(|error| {
                                    unsupported(
                                        tag,
                                        "Hysteria2 realm port mapping",
                                        error.to_string(),
                                    )
                                })?;
                        }
                        let (resolver, strategy) = self.resolve_options(
                            tag,
                            &options.dialer.abstract_options,
                        )?;
                        let mut lookup_options = crate::dns::LookupOptions {
                            strategy,
                            ..Default::default()
                        };
                        if let Some(domain) = options
                            .dialer
                            .abstract_options
                            .domain_resolver
                            .as_ref()
                        {
                            lookup_options.timeout = domain
                                .timeout
                                .as_std()
                                .filter(|duration| !duration.is_zero());
                            lookup_options.disable_cache = domain.disable_cache;
                            lookup_options.disable_optimistic_cache =
                                domain.disable_optimistic_cache;
                            lookup_options.rewrite_ttl = domain.rewrite_ttl;
                            lookup_options.client_subnet = domain
                                .client_subnet
                                .as_ref()
                                .map(|prefix| prefix.0);
                        }
                        connector =
                            connector.with_resolver(resolver, lookup_options);
                        Ok((connector, server_host))
                    })
                    .transpose()?;
                if realm.is_none()
                    && (options.server.server.is_empty()
                        || (options.server.server_port == 0
                            && server_ports.is_empty()))
                {
                    return Err(unsupported(
                        tag,
                        "Hysteria2 server",
                        "server and server_port are required",
                    ));
                }
                let server = SocksAddr::new(
                    options.server.server.clone(),
                    options.server.server_port,
                );
                if !server_ports.is_empty() {
                    let minimum_nanos = options.hop_interval.as_nanos();
                    let maximum_nanos = options.hop_interval_max.as_nanos();
                    if minimum_nanos < 0 || maximum_nanos < 0 {
                        return Err(unsupported(
                            tag,
                            "Hysteria2 port hopping",
                            "hop intervals must not be negative",
                        ));
                    }
                    let (minimum, maximum) = match (
                        minimum_nanos,
                        maximum_nanos,
                    ) {
                        (0, 0) => {
                            (DEFAULT_HOP_INTERVAL, DEFAULT_HOP_INTERVAL)
                        }
                        (0, _) => {
                            return Err(unsupported(
                                tag,
                                "Hysteria2 port hopping",
                                "minimum and maximum hop interval must both be set",
                            ));
                        }
                        (minimum, 0) => {
                            let minimum = std::time::Duration::from_nanos(
                                minimum as u64,
                            );
                            (minimum, minimum)
                        }
                        (minimum, maximum) => (
                            std::time::Duration::from_nanos(minimum as u64),
                            std::time::Duration::from_nanos(maximum as u64),
                        ),
                    };
                    upstream = port_hopping_dialer(
                        upstream,
                        server.clone(),
                        server_ports,
                        minimum,
                        maximum,
                    )
                    .map_err(|error| {
                        unsupported(
                            tag,
                            "Hysteria2 port hopping",
                            error.to_string(),
                        )
                    })?;
                }
                let server_host = realm
                    .as_ref()
                    .map(|(_, server_host)| server_host.as_str())
                    .unwrap_or(&options.server.server);
                let server_name = if tls_options.server_name.is_empty() {
                    server_host.to_owned()
                } else {
                    tls_options.server_name.clone()
                };
                let tls = build_client_config_with_runtime_context(
                    server_host,
                    &tls_options,
                    &["h3"],
                    self.dns.clone(),
                    self.ntp_clock.clone(),
                self.certificate_store.clone(),
                )
                .map_err(|error| OutboundError::Tls {
                    tag: tag.to_owned(),
                    message: error.to_string(),
                })?;
                let transport = Hysteria2QuicOptions {
                    idle_timeout: options.quic.idle_timeout.as_std(),
                    keep_alive_period: options.quic.keep_alive_period.as_std(),
                    stream_receive_window: options.quic.stream_receive_window.0,
                    connection_receive_window: options
                        .quic
                        .connection_receive_window
                        .0,
                    max_concurrent_streams: u64::try_from(
                        options.quic.max_concurrent_streams,
                    )
                    .map_err(|_| {
                        unsupported(
                            tag,
                            "Hysteria2 QUIC",
                            "negative max_concurrent_streams",
                        )
                    })?,
                    initial_packet_size: u64::try_from(
                        options.quic.initial_packet_size,
                    )
                    .map_err(|_| {
                        unsupported(
                            tag,
                            "Hysteria2 QUIC",
                            "negative initial_packet_size",
                        )
                    })?,
                    disable_path_mtu_discovery: options
                        .quic
                        .disable_path_mtu_discovery,
                }
                .build_for_client(chrome_parrot)
                .map_err(|error| {
                    unsupported(tag, "Hysteria2 QUIC", error.to_string())
                })?;
                let send_bps =
                    u64::try_from(options.up_mbps.max(0)).unwrap() * 125_000;
                let receive_bps =
                    u64::try_from(options.down_mbps.max(0)).unwrap() * 125_000;
                let outbound = if let Some((realm, _)) = realm {
                    Hysteria2Outbound::new_with_realm_profile_and_chrome_parrot(
                        server_name,
                        options.password,
                        send_bps,
                        options.brutal_debug,
                        receive_bps,
                        tls,
                        transport,
                        obfs,
                        upstream,
                        realm,
                        bbr_profile,
                        chrome_parrot,
                    )
                } else {
                    Hysteria2Outbound::new_with_transport_obfs_packet_dialer_profile_and_chrome_parrot(
                        server,
                        server_name,
                        options.password,
                        send_bps,
                        options.brutal_debug,
                        receive_bps,
                        tls,
                        transport,
                        obfs,
                        upstream,
                        bbr_profile,
                        chrome_parrot,
                    )
                };
                Ok(Arc::new(outbound))
            }
            "hysteria" => {
                let options: HysteriaOutboundOptions = option.decode()?;
                let tls_options =
                    options.tls.as_ref().filter(|tls| tls.enabled).ok_or_else(
                        || unsupported(tag, "Hysteria", "TLS is required"),
                    )?;
                let upstream =
                    self.build_upstream(tag, &options.dialer)?;
                let server_ports = parse_server_ports(&options.server_ports.0)
                    .map_err(|error| {
                        unsupported(
                            tag,
                            "Hysteria port hopping",
                            error.to_string(),
                        )
                    })?;
                let hop_interval = match options.hop_interval.as_nanos() {
                    value if value < 0 => {
                        return Err(unsupported(
                            tag,
                            "Hysteria port hopping",
                            "hop_interval must not be negative",
                        ));
                    }
                    0 => DEFAULT_HOP_INTERVAL,
                    value => std::time::Duration::from_nanos(value as u64),
                };
                if !server_ports.is_empty() && hop_interval < MIN_HOP_INTERVAL
                {
                    return Err(unsupported(
                        tag,
                        "Hysteria port hopping",
                        "hop_interval must be at least 5 seconds",
                    ));
                }
                if options.server.server.is_empty()
                    || (options.server.server_port == 0
                        && server_ports.is_empty())
                {
                    return Err(unsupported(
                        tag,
                        "Hysteria server",
                        "server and server_port are required",
                    ));
                }
                let send_bps = options
                    .up
                    .map(|value| value.value())
                    .filter(|value| *value != 0)
                    .unwrap_or_else(|| {
                        u64::try_from(options.up_mbps.max(0)).unwrap()
                            * MBPS_TO_BPS
                    });
                let receive_bps = options
                    .down
                    .map(|value| value.value())
                    .filter(|value| *value != 0)
                    .unwrap_or_else(|| {
                        u64::try_from(options.down_mbps.max(0)).unwrap()
                            * MBPS_TO_BPS
                    });
                if send_bps < MIN_SPEED_BPS || receive_bps < MIN_SPEED_BPS {
                    return Err(unsupported(
                        tag,
                        "Hysteria bandwidth",
                        "upload/download speed is missing or too small",
                    ));
                }
                let server = SocksAddr::new(
                    options.server.server.clone(),
                    options.server.server_port,
                );
                let server_name = if tls_options.server_name.is_empty() {
                    options.server.server.clone()
                } else {
                    tls_options.server_name.clone()
                };
                let tls = build_client_config_with_runtime_context(
                    &options.server.server,
                    tls_options,
                    &[crate::protocol::hysteria::DEFAULT_ALPN],
                    self.dns.clone(),
                    self.ntp_clock.clone(),
                self.certificate_store.clone(),
                )
                .map_err(|error| OutboundError::Tls {
                    tag: tag.to_owned(),
                    message: error.to_string(),
                })?;
                let stream_window = if options.quic.stream_receive_window.0 == 0
                {
                    options.recv_window
                } else {
                    options.quic.stream_receive_window.0
                };
                let connection_window =
                    if options.quic.connection_receive_window.0 == 0 {
                        options.recv_window_conn
                    } else {
                        options.quic.connection_receive_window.0
                    };
                let transport = Hysteria2QuicOptions {
                    idle_timeout: options
                        .quic
                        .idle_timeout
                        .as_std()
                        .or(Some(std::time::Duration::from_secs(30))),
                    keep_alive_period: options
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
                    max_concurrent_streams: u64::try_from(
                        options.quic.max_concurrent_streams,
                    )
                    .map_err(|_| {
                        unsupported(
                            tag,
                            "Hysteria QUIC",
                            "negative max_concurrent_streams",
                        )
                    })?,
                    initial_packet_size: u64::try_from(
                        options.quic.initial_packet_size,
                    )
                    .map_err(|_| {
                        unsupported(
                            tag,
                            "Hysteria QUIC",
                            "negative initial_packet_size",
                        )
                    })?,
                    disable_path_mtu_discovery: options
                        .quic
                        .disable_path_mtu_discovery
                        || options.disable_mtu_discovery,
                }
                .build()
                .map_err(|error| {
                    unsupported(tag, "Hysteria QUIC", error.to_string())
                })?;
                let password = options.password();
                let obfs = (!options.obfs.is_empty())
                    .then(|| options.obfs.into_bytes());
                if server_ports.is_empty() {
                    Ok(Arc::new(HysteriaOutbound::new_with_packet_dialer(
                        server,
                        server_name,
                        password,
                        send_bps,
                        receive_bps,
                        tls,
                        transport,
                        obfs,
                        upstream,
                    )))
                } else {
                    Ok(Arc::new(HysteriaOutbound::new_with_port_hopping(
                        server,
                        server_name,
                        password,
                        send_bps,
                        receive_bps,
                        tls,
                        transport,
                        obfs,
                        upstream,
                        server_ports,
                        hop_interval,
                    )))
                }
            }
            "tuic" => {
                let options: TuicOutboundOptions = option.decode()?;
                let tls_options =
                    options.tls.as_ref().filter(|tls| tls.enabled).ok_or_else(
                        || unsupported(tag, "TUIC", "TLS is required"),
                    )?;
                let upstream =
                    self.build_upstream(tag, &options.dialer)?;
                if options.udp_over_stream && !options.udp_relay_mode.is_empty()
                {
                    return Err(unsupported(
                        tag,
                        "TUIC UDP mode",
                        "udp_over_stream conflicts with udp_relay_mode",
                    ));
                }
                let udp_stream = match options.udp_relay_mode.as_str() {
                    "" | "native" => false,
                    "quic" => true,
                    value => {
                        return Err(unsupported(
                            tag,
                            "TUIC UDP relay mode",
                            format!("unknown mode {value:?}"),
                        ));
                    }
                };
                if options.server.server.is_empty()
                    || options.server.server_port == 0
                {
                    return Err(unsupported(
                        tag,
                        "TUIC server",
                        "server and server_port are required",
                    ));
                }
                let uuid =
                    uuid::Uuid::parse_str(&options.uuid).map_err(|error| {
                        unsupported(tag, "TUIC UUID", error.to_string())
                    })?;
                let server = SocksAddr::new(
                    options.server.server.clone(),
                    options.server.server_port,
                );
                let server_name = if tls_options.server_name.is_empty() {
                    options.server.server.clone()
                } else {
                    tls_options.server_name.clone()
                };
                let tls = build_client_config_with_runtime_context(
                    &options.server.server,
                    tls_options,
                    &[crate::protocol::tuic::DEFAULT_ALPN],
                    self.dns.clone(),
                    self.ntp_clock.clone(),
                self.certificate_store.clone(),
                )
                .map_err(|error| OutboundError::Tls {
                    tag: tag.to_owned(),
                    message: error.to_string(),
                })?;
                let mut transport = Hysteria2QuicOptions {
                    idle_timeout: options.quic.idle_timeout.as_std(),
                    keep_alive_period: options.quic.keep_alive_period.as_std(),
                    stream_receive_window: options.quic.stream_receive_window.0,
                    connection_receive_window: options
                        .quic
                        .connection_receive_window
                        .0,
                    max_concurrent_streams: u64::try_from(
                        options.quic.max_concurrent_streams,
                    )
                    .map_err(|_| {
                        unsupported(
                            tag,
                            "TUIC QUIC",
                            "negative max_concurrent_streams",
                        )
                    })?,
                    initial_packet_size: u64::try_from(
                        options.quic.initial_packet_size,
                    )
                    .map_err(|_| {
                        unsupported(
                            tag,
                            "TUIC QUIC",
                            "negative initial_packet_size",
                        )
                    })?,
                    disable_path_mtu_discovery: options
                        .quic
                        .disable_path_mtu_discovery,
                }
                .build()
                .map_err(|error| {
                    unsupported(tag, "TUIC QUIC", error.to_string())
                })?;
                match options.congestion_control.as_str() {
                    "" | "cubic" => {}
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
                    value => {
                        return Err(unsupported(
                            tag,
                            "TUIC congestion control",
                            format!("unknown algorithm {value:?}"),
                        ));
                    }
                }
                let base: SharedDialer = Arc::new(
                    TuicOutbound::new_with_packet_dialer(
                    server,
                    server_name,
                    uuid,
                    options.password,
                    tls,
                    Arc::new(transport),
                    udp_stream,
                    options
                        .heartbeat
                        .as_std()
                        .unwrap_or(std::time::Duration::from_secs(10)),
                    upstream,
                    options.zero_rtt_handshake,
                ));
                if options.udp_over_stream {
                    Ok(Arc::new(
                        UotOutbound::new(base, crate::protocol::uot::VERSION)
                            .map_err(|error| {
                            unsupported(tag, "TUIC UoT", error.to_string())
                        })?,
                    ))
                } else {
                    Ok(base)
                }
            }
            "selector" => {
                let options: SelectorOutboundOptions = option.decode()?;
                let selected = if options.default.is_empty() {
                    options.outbounds.first()
                } else {
                    Some(&options.default)
                }
                .ok_or_else(|| {
                    unsupported(tag, "selector", "empty outbound list")
                })?
                .clone();
                let mut choices = HashMap::new();
                for choice in &options.outbounds {
                    if choices.contains_key(choice) {
                        return Err(unsupported(
                            tag,
                            "selector",
                            format!("duplicate outbound {choice:?}"),
                        ));
                    }
                    choices.insert(choice.clone(), self.build_tag(choice)?);
                }
                let selector = Arc::new(
                    SelectorOutbound::new_with_cache_and_updates(
                        tag.to_owned(),
                        options.outbounds,
                        choices,
                        selected,
                        options.interrupt_exist_connections,
                        self.persistent_cache.clone(),
                        Some(self.groups.clone()),
                    )
                    .map_err(|error| {
                        unsupported(tag, "selector", error.to_string())
                    })?,
                );
                self.selectors.insert(tag.to_owned(), selector.clone());
                self.groups.register_selector(tag.to_owned(), &selector);
                Ok(selector)
            }
            "urltest" => {
                let options: UrlTestOutboundOptions = option.decode()?;
                let mut choices = HashMap::new();
                for choice in &options.outbounds {
                    if choices.contains_key(choice) {
                        return Err(unsupported(
                            tag,
                            "urltest",
                            format!("duplicate outbound {choice:?}"),
                        ));
                    }
                    choices.insert(choice.clone(), self.build_tag(choice)?);
                }
                let urltest = Arc::new(
                    UrlTestOutbound::new_with_registry_and_context(
                        options,
                        choices,
                        self.groups.clone(),
                        self.ntp_clock.clone(),
                        self.certificate_store.clone(),
                    )
                    .map_err(|error| {
                        unsupported(tag, "urltest", error.to_string())
                    })?,
                );
                urltest.attach();
                self.urltests.insert(tag.to_owned(), urltest.clone());
                self.groups.register_urltest(tag.to_owned(), &urltest);
                Ok(urltest)
            }
            kind => Err(unsupported(
                tag,
                kind,
                "runtime constructor is not ported yet",
            )),
        }
    }

    fn build_upstream(
        &mut self,
        owner: &str,
        options: &DialerOptions,
    ) -> Result<SharedDialer, OutboundError> {
        if options.detour.is_empty() {
            let mut direct_options = DirectOutboundOptions {
                dialer: options.clone(),
                ..Default::default()
            };
            self.apply_platform_network_defaults(
                &mut direct_options.dialer.abstract_options,
            );
            let (resolver, strategy) = self.resolve_options(
                owner,
                &direct_options.dialer.abstract_options,
            )?;
            let direct = DirectOutbound::with_underlay_resolver(
                direct_options,
                resolver,
                strategy,
            );
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            let direct = match self.platform_network_provider.as_ref() {
                Some(provider) => {
                    direct.with_platform_network_provider(provider.clone())
                }
                None => direct,
            };
            let direct = self.attach_auto_detect_interface(direct);
            Ok(Arc::new(direct))
        } else if self.configs.contains_key(&options.detour) {
            self.reject_empty_direct_detour(owner, &options.detour)?;
            let dialer = self.build_tag(&options.detour)?;
            if options.abstract_options.domain_resolver.is_none() {
                return Ok(dialer);
            }
            let (resolver, strategy) =
                self.resolve_options(owner, &options.abstract_options)?;
            Ok(Arc::new(ResolvingDetourDialer::new(
                dialer, resolver, strategy,
            )))
        } else {
            Err(OutboundError::DependencyNotFound {
                outbound: owner.to_owned(),
                dependency: options.detour.clone(),
            })
        }
    }

    fn build_upstream_resolver_on_detour(
        &mut self,
        owner: &str,
        options: &DialerOptions,
    ) -> Result<SharedDialer, OutboundError> {
        let mut abstract_options = options.abstract_options.clone();
        self.apply_platform_network_defaults(&mut abstract_options);
        if abstract_options.domain_resolver.is_none()
            && self.dns.tags().nth(1).is_some()
        {
            return Err(unsupported(
                owner,
                "domain resolver",
                "missing domain resolver for domain server address",
            ));
        }
        if options.detour.is_empty() {
            return self.build_upstream(owner, options);
        }
        if !self.configs.contains_key(&options.detour) {
            return Err(OutboundError::DependencyNotFound {
                outbound: owner.to_owned(),
                dependency: options.detour.clone(),
            });
        }
        self.reject_empty_direct_detour(owner, &options.detour)?;
        let dialer = self.build_tag(&options.detour)?;
        let (resolver, strategy) =
            self.resolve_options(owner, &abstract_options)?;
        Ok(Arc::new(ResolvingDetourDialer::new(
            dialer, resolver, strategy,
        )))
    }

    fn reject_empty_direct_detour(
        &self,
        owner: &str,
        detour: &str,
    ) -> Result<(), OutboundError> {
        let Some(option) = self.configs.get(detour) else {
            return Ok(());
        };
        if option.kind == "direct"
            && option.decode::<DirectOutboundOptions>()?
                == DirectOutboundOptions::default()
        {
            return Err(unsupported(
                owner,
                "detour",
                "detour to an empty direct outbound makes no sense",
            ));
        }
        Ok(())
    }

    fn wrap_v2ray_transport(
        &self,
        tag: &str,
        upstream: SharedDialer,
        server: &SocksAddr,
        transport: Option<&V2RayTransportOptions>,
        tls_enabled: bool,
    ) -> Result<SharedDialer, OutboundError> {
        match transport {
            None => Ok(upstream),
            Some(V2RayTransportOptions::Http(options)) => Ok(Arc::new(
                (if tls_enabled {
                    HttpDialer::new_http2(
                        upstream,
                        server.clone(),
                        options.clone(),
                    )
                } else {
                    HttpDialer::new(upstream, server.clone(), options.clone())
                })
                .map_err(|error| {
                    unsupported(tag, "V2Ray HTTP", error.to_string())
                })?,
            )),
            Some(V2RayTransportOptions::Grpc(options)) => Ok(Arc::new(
                GrpcDialer::new(upstream, server.clone(), options.clone())
                    .map_err(|error| {
                        unsupported(tag, "V2Ray gRPC", error.to_string())
                    })?,
            )),
            Some(V2RayTransportOptions::Websocket(options)) => Ok(Arc::new(
                WebsocketDialer::new(upstream, server.clone(), options.clone())
                    .map_err(|error| {
                        unsupported(tag, "V2Ray WebSocket", error.to_string())
                    })?,
            )),
            Some(V2RayTransportOptions::HttpUpgrade(options)) => Ok(Arc::new(
                HttpUpgradeDialer::new(
                    upstream,
                    server.clone(),
                    options.clone(),
                )
                .map_err(|error| {
                    unsupported(tag, "V2Ray HTTPUpgrade", error.to_string())
                })?,
            )),
            Some(_) => Err(unsupported(
                tag,
                "V2Ray transport",
                "QUIC is not ported yet",
            )),
        }
    }

    fn wrap_multiplex(
        &self,
        tag: &str,
        upstream: SharedDialer,
        options: Option<&OutboundMultiplexOptions>,
    ) -> Result<SharedDialer, OutboundError> {
        let Some(options) = options.filter(|options| options.enabled) else {
            return Ok(upstream);
        };
        Ok(Arc::new(
            MuxClient::new(upstream, options.clone()).map_err(|error| {
                unsupported(tag, "sing-mux", error.to_string())
            })?,
        ))
    }

    fn direct(
        &self,
        owner: &str,
        mut options: DirectOutboundOptions,
    ) -> Result<DirectOutbound, OutboundError> {
        options
            .validate_removed_override_fields()
            .and_then(|_| options.validate_removed_proxy_protocol())
            .map_err(|message| OutboundError::Removed(message.into()))?;
        self.apply_platform_network_defaults(
            &mut options.dialer.abstract_options,
        );
        let (resolver, strategy) =
            self.resolve_options(owner, &options.dialer.abstract_options)?;
        let direct = DirectOutbound::with_resolver(options, resolver, strategy);
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        let direct = match self.platform_network_provider.as_ref() {
            Some(provider) => {
                direct.with_platform_network_provider(provider.clone())
            }
            None => direct,
        };
        let direct = self.attach_auto_detect_interface(direct);
        Ok(direct)
    }

    fn attach_auto_detect_interface(
        &self,
        direct: DirectOutbound,
    ) -> DirectOutbound {
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        if let Some(provider) =
            self.route_dialer_defaults.auto_detect_interface.as_ref()
        {
            return direct
                .with_auto_detect_interface_provider(provider.clone());
        }
        direct
    }

    fn apply_platform_network_defaults(
        &self,
        options: &mut AbstractDialerOptions,
    ) {
        self.route_dialer_defaults.apply(options);
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        self.platform_network_defaults.apply(options);
    }

    fn resolve_options(
        &self,
        owner: &str,
        options: &AbstractDialerOptions,
    ) -> Result<(SharedResolver, DomainStrategy), OutboundError> {
        dialer_resolver(&self.dns, owner, options)
    }
}

fn dialer_resolver(
    dns: &Arc<TransportManager>,
    owner: &str,
    options: &AbstractDialerOptions,
) -> Result<(SharedResolver, DomainStrategy), OutboundError> {
    if let Some(domain_resolver) = &options.domain_resolver {
        let resolver =
            dns.resolver(&domain_resolver.server).ok_or_else(|| {
                OutboundError::DnsResolverNotFound {
                    outbound: owner.to_owned(),
                    resolver: domain_resolver.server.clone(),
                }
            })?;
        let strategy = if domain_resolver.strategy == DomainStrategy::AsIs {
            options.domain_strategy
        } else {
            domain_resolver.strategy
        };
        let resolver = Arc::new(ConfiguredResolver::new(
            resolver,
            domain_resolver,
            options.domain_strategy,
        ));
        return Ok((resolver, strategy));
    }
    Ok((
        Arc::new(OutboundDnsResolver {
            manager: dns.clone(),
            outbound: owner.to_owned(),
        }),
        options.domain_strategy,
    ))
}

fn effective_tag(option: &TaggedOptions, index: usize) -> String {
    if option.tag.is_empty() {
        index.to_string()
    } else {
        option.tag.clone()
    }
}

fn unsupported(
    tag: &str,
    kind: impl Into<String>,
    detail: impl Into<String>,
) -> OutboundError {
    OutboundError::Unsupported {
        tag: tag.to_owned(),
        kind: kind.into(),
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc, time::Duration};

    use hickory_proto::{
        op::{Message, Query},
        rr::{Name, RecordType},
    };
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedKey,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
        generate_simple_self_signed,
    };
    use rustls::{
        ServerConfig,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::TlsAcceptor;

    use super::{
        OutboundManager, TrafficAttribution, TrafficCounters,
        with_traffic_attribution,
    };
    use crate::{
        adapter::{Dialer, PacketConnection},
        common::network::SocksAddr,
        option::{DialerOptions, Options},
        protocol::{
            socks::{
                SocksCommand, SocksVersion, client_accept_bind, server_request,
                write_reply, write_reply_for_version,
            },
            trojan::{
                Command as TrojanCommand, TrojanPacketConnection,
                key as trojan_key, read_request as read_trojan_request,
            },
            vless::{
                Command as VlessCommand, read_request as read_vless_request,
                write_response as write_vless_response,
            },
        },
        route::{Metadata, Router},
    };

    #[tokio::test]
    async fn process_traffic_is_opt_in_and_cleared_when_disabled() {
        let traffic = TrafficCounters::default();
        let destination: SocksAddr = "example.com:443".parse().unwrap();
        let attribution = TrafficAttribution {
            process_name: "curl".into(),
            process_path: "/usr/bin/curl".into(),
            process_lookup: "socket_snapshot".into(),
            ..TrafficAttribution::default()
        };

        with_traffic_attribution(attribution.clone(), async {
            let active = traffic.register("Proxy", &destination, "tcp");
            traffic.count_upload(&active, 64);
            traffic.count_download(&active, 128);
        })
        .await;
        assert!(!traffic.process_traffic_snapshot().enabled);
        assert!(traffic.process_traffic_snapshot().records.is_empty());

        traffic.set_process_traffic_enabled(true);
        with_traffic_attribution(attribution, async {
            let active = traffic.register("Proxy", &destination, "tcp");
            traffic.count_upload(&active, 256);
            traffic.count_download(&active, 512);
        })
        .await;
        let state = traffic.process_traffic_snapshot();
        assert!(state.enabled);
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.records[0].process_name, "curl");
        assert_eq!(state.records[0].process_path, "/usr/bin/curl");
        assert_eq!(state.records[0].upload, 256);
        assert_eq!(state.records[0].download, 512);

        traffic.set_process_traffic_enabled(false);
        let state = traffic.process_traffic_snapshot();
        assert!(!state.enabled);
        assert!(state.records.is_empty());
    }

    #[tokio::test]
    async fn dns_reverse_mapping_enriches_ip_destination_before_route_match() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {
                "servers": [{
                    "type": "hosts",
                    "tag": "hosts",
                    "predefined": {"reverse.example": "192.0.2.88"}
                }],
                "final": "hosts",
                "reverse_mapping": true
            },
            "outbounds": [
                {"type": "block", "tag": "matched"},
                {"type": "block", "tag": "fallback"}
            ]
        }))
        .unwrap();
        let manager = Arc::new(
            OutboundManager::from_options(&options, "fallback").unwrap(),
        );
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("reverse.example").unwrap(),
            RecordType::A,
        ));
        manager.dns().exchange(&request).await.unwrap();

        let mut router = Router::from_json(
            &[serde_json::json!({
                "domain": "reverse.example",
                "outbound": "matched"
            })],
            "fallback",
        )
        .unwrap();
        router.configure_preferred_outbounds(&manager);
        let metadata = Metadata {
            destination: Some("192.0.2.88:443".parse().unwrap()),
            ..Metadata::default()
        };
        assert_eq!(router.route(&metadata).outbound(), Some("matched"));
    }

    #[test]
    fn selects_first_outbound_and_resolves_selector() {
        let options: Options = serde_json::from_str(r#"{
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds": [
                {"type":"block","tag":"deny"},
                {"type":"direct","tag":"direct"},
                {"type":"selector","tag":"pick","outbounds":["deny","direct"],"default":"deny"}
            ]
        }"#).unwrap();
        let manager = OutboundManager::from_options(&options, "pick").unwrap();
        let mut updates = manager.subscribe_urltest_updates();
        assert_eq!(manager.default_tag(), "pick");
        assert_eq!(
            manager.tags().collect::<Vec<_>>(),
            ["deny", "direct", "pick"]
        );
        assert_eq!(manager.selected_group("pick").as_deref(), Some("deny"));
        manager.select_group("pick", "direct").unwrap();
        assert_eq!(updates.try_recv(), Ok(()));
        assert_eq!(manager.selected_group("pick").as_deref(), Some("direct"));
        manager.select_group("pick", "direct").unwrap();
        assert!(matches!(
            updates.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert!(manager.select_group("pick", "missing").is_err());
        manager
            .register_endpoint(
                "wg",
                "wireguard",
                Arc::new(crate::protocol::block::BlockOutbound),
            )
            .unwrap();
        assert_eq!(
            manager.outbound_items(),
            [
                ("deny".into(), "block".into()),
                ("direct".into(), "direct".into()),
                ("pick".into(), "selector".into()),
                ("wg".into(), "wireguard".into()),
            ]
        );
        assert_eq!(manager.kind_owned("wg").as_deref(), Some("wireguard"));
    }

    #[tokio::test]
    async fn configured_outbound_network_restricts_tcp_and_udp_calls() {
        let udp_only: Options = serde_json::from_value(serde_json::json!({
            "outbounds": [{
                "type": "socks",
                "tag": "udp-only",
                "server": "127.0.0.1",
                "server_port": 9,
                "network": "udp"
            }]
        }))
        .unwrap();
        let manager =
            OutboundManager::from_options(&udp_only, "udp-only").unwrap();
        let error = manager
            .select(None)
            .unwrap()
            .dial_tcp(&SocksAddr::new("example.com", 443))
            .await
            .err()
            .expect("UDP-only outbound must reject TCP");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(
            error.to_string(),
            "TCP is not supported by outbound: udp-only"
        );

        let tcp_only: Options = serde_json::from_value(serde_json::json!({
            "outbounds": [{
                "type": "socks",
                "tag": "tcp-only",
                "server": "127.0.0.1",
                "server_port": 9,
                "network": ["tcp"]
            }]
        }))
        .unwrap();
        let manager =
            OutboundManager::from_options(&tcp_only, "tcp-only").unwrap();
        let error = manager
            .select(None)
            .unwrap()
            .listen_udp(&SocksAddr::new("example.com", 53))
            .await
            .err()
            .expect("TCP-only outbound must reject UDP");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(
            error.to_string(),
            "UDP is not supported by outbound: tcp-only"
        );
    }

    #[tokio::test]
    async fn selector_preserves_selected_outbound_network_capability() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "outbounds": [
                {
                    "type": "socks",
                    "tag": "udp-only",
                    "server": "127.0.0.1",
                    "server_port": 9,
                    "network": "udp"
                },
                {
                    "type": "socks",
                    "tag": "tcp-only",
                    "server": "127.0.0.1",
                    "server_port": 9,
                    "network": "tcp"
                },
                {
                    "type": "selector",
                    "tag": "pick",
                    "outbounds": ["udp-only", "tcp-only"]
                }
            ]
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&options, "pick").unwrap();
        let error = manager
            .select(None)
            .unwrap()
            .dial_tcp(&SocksAddr::new("example.com", 443))
            .await
            .err()
            .expect("selector must preserve the selected network restriction");
        assert_eq!(error.to_string(), "TCP is not supported by outbound: pick");
        manager.select_group("pick", "tcp-only").unwrap();
        let error = manager
            .select(None)
            .unwrap()
            .listen_udp(&SocksAddr::new("example.com", 53))
            .await
            .err()
            .expect("selector must refresh the selected network restriction");
        assert_eq!(error.to_string(), "UDP is not supported by outbound: pick");
    }

    #[tokio::test]
    async fn every_network_configurable_outbound_uses_the_capability_gate() {
        for kind in [
            "socks",
            "tuic",
            "hysteria",
            "hysteria2",
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "snell",
        ] {
            let option: crate::option::TaggedOptions =
                serde_json::from_value(serde_json::json!({
                    "type": kind,
                    "tag": kind,
                    "network": "tcp"
                }))
                .unwrap();
            let capability = super::configured_network_capability(&option)
                .unwrap()
                .expect("outbound type must expose its network setting");
            let outbound = super::NetworkRestrictedDialer::new(
                Arc::new(crate::protocol::block::BlockOutbound),
                kind,
                capability,
            );
            let error = outbound
                .listen_udp(&SocksAddr::new("example.com", 53))
                .await
                .err()
                .expect("TCP-only outbound must reject UDP");
            assert_eq!(
                error.to_string(),
                format!("UDP is not supported by outbound: {kind}")
            );
        }
    }

    #[test]
    fn rejects_empty_direct_detours_except_when_explicitly_disabled() {
        let invalid: Options = serde_json::from_value(serde_json::json!({
            "outbounds": [
                {"type": "direct", "tag": "plain"},
                {
                    "type": "socks",
                    "tag": "proxy",
                    "server": "127.0.0.1",
                    "server_port": 1080,
                    "detour": "plain"
                }
            ]
        }))
        .unwrap();
        let error = OutboundManager::from_options(&invalid, "proxy")
            .err()
            .expect("empty direct detour must be rejected");
        assert!(error.to_string().contains("makes no sense"));

        let valid: Options = serde_json::from_value(serde_json::json!({
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "configured",
                    "connect_timeout": "1s"
                },
                {
                    "type": "socks",
                    "tag": "proxy",
                    "server": "127.0.0.1",
                    "server_port": 1080,
                    "detour": "configured"
                }
            ]
        }))
        .unwrap();
        OutboundManager::from_options(&valid, "proxy").unwrap();

        let direct_only: Options = serde_json::from_value(serde_json::json!({
            "outbounds": [{"type": "direct", "tag": "plain"}]
        }))
        .unwrap();
        let manager =
            OutboundManager::from_options(&direct_only, "plain").unwrap();
        let dialer = DialerOptions {
            detour: "plain".into(),
            ..Default::default()
        };
        let endpoint_error = match manager.endpoint_dialer("endpoint", &dialer)
        {
            Ok(_) => panic!("empty direct endpoint detour was accepted"),
            Err(error) => error,
        };
        assert!(endpoint_error.to_string().contains("makes no sense"));
        let resolver_error = match manager
            .resolver_on_detour_dialer("endpoint", &dialer, false)
        {
            Ok(_) => panic!("empty direct resolving detour was accepted"),
            Err(error) => error,
        };
        assert!(resolver_error.to_string().contains("makes no sense"));
        manager
            .http_client_dialer_with_options(&dialer, false, true)
            .unwrap();
    }

    #[tokio::test]
    async fn runtime_direct_dialer_preserves_configured_resolver_options() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {
                "servers": [{
                    "type": "hosts",
                    "tag": "hosts",
                    "predefined": {"ipv6-only.test": "::1"}
                }],
                "final": "hosts"
            }
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&options, "").unwrap();
        let dialer_options: DialerOptions =
            serde_json::from_value(serde_json::json!({
                "domain_resolver": {"server": "hosts"},
                "domain_strategy": "ipv4_only"
            }))
            .unwrap();
        let dialer =
            manager.http_client_dialer(&dialer_options, false).unwrap();

        let error = dialer
            .dial_tcp(&SocksAddr::new("ipv6-only.test", 65534))
            .await
            .err()
            .expect("IPv4-only lookup must reject an IPv6-only result");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn new_endpoint_dialer_rejects_ambiguous_domain_resolution() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [
                {"type": "hosts", "tag": "one"},
                {"type": "hosts", "tag": "two"}
            ]},
            "outbounds": [{"type": "block", "tag": "transport"}]
        }))
        .unwrap();
        let manager =
            OutboundManager::from_options(&options, "transport").unwrap();
        let dialer: DialerOptions = serde_json::from_value(serde_json::json!({
            "detour": "transport"
        }))
        .unwrap();

        let error = manager
            .resolver_on_detour_dialer("endpoint", &dialer, true)
            .err()
            .expect("NewDialer must reject ambiguous DNS transports")
            .to_string();
        assert!(error.contains("missing domain resolver"), "{error}");
        manager
            .resolver_on_detour_dialer("endpoint", &dialer, false)
            .expect("legacy endpoint dialer may use the DNS router default");

        let explicit: DialerOptions =
            serde_json::from_value(serde_json::json!({
                "detour": "transport",
                "domain_resolver": "two"
            }))
            .unwrap();
        manager
            .resolver_on_detour_dialer("endpoint", &explicit, true)
            .expect("an explicit resolver removes the ambiguity");
    }

    #[test]
    fn bridge_registers_as_l3_outbound_and_lifecycle_component() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "outbounds": [{
                "type": "bridge",
                "tag": "system",
                "interface": "en0",
                "bridge_name": "bridge-test"
            }]
        }))
        .unwrap();
        let manager =
            OutboundManager::from_options(&options, "system").unwrap();
        let outbound = manager.outbound("system").unwrap();
        let port = outbound.packet_port().expect("bridge packet port");
        assert!(
            port.port_addresses()
                .0
                .is_some_and(|address| address.is_ipv4())
        );
        assert!(
            port.port_addresses()
                .1
                .is_some_and(|address| address.is_ipv6())
        );
        assert_eq!(manager.kind_owned("system").as_deref(), Some("bridge"));
        assert!(manager.bridge_service().is_some());
    }

    #[test]
    fn metered_direct_dialer_preserves_icmp_flow_capability() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "outbounds": [{"type": "direct", "tag": "host"}]
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&options, "host").unwrap();
        let addresses = manager
            .outbound("host")
            .unwrap()
            .icmp_flow_addresses()
            .expect("direct ICMP flow capability");
        assert_eq!(addresses.0, Some("0.0.0.0".parse().unwrap()));
        assert_eq!(addresses.1, Some("::".parse().unwrap()));
    }

    #[tokio::test]
    async fn remote_dns_transports_bind_to_configured_outbound_detours() {
        for kind in ["udp", "tcp", "tls", "quic", "https", "h3"] {
            let tls = matches!(kind, "tls" | "quic" | "https" | "h3")
                .then(|| serde_json::json!({"insecure": true}));
            let mut server = serde_json::json!({
                "type": kind,
                "tag": "remote",
                "server": "dns.example",
                "detour": "deny"
            });
            if let Some(tls) = tls {
                server
                    .as_object_mut()
                    .expect("server object")
                    .insert("tls".into(), tls);
            }
            let options: Options = serde_json::from_value(serde_json::json!({
                "dns": {"servers": [server], "final": "remote"},
                "outbounds": [{"type": "block", "tag": "deny"}]
            }))
            .unwrap();
            let manager = OutboundManager::from_options(&options, "deny")
                .unwrap_or_else(|error| {
                    panic!("failed to construct {kind} DNS detour: {error}")
                });
            let error = manager
                .dns()
                .default()
                .lookup("example.com", Default::default())
                .await
                .expect_err("block detour must reject the DNS exchange");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied,
                "{kind} did not use its outbound detour: {error}"
            );
        }
    }

    #[test]
    fn remote_dns_detour_rejects_missing_outbound() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{
                "type": "udp",
                "tag": "remote",
                "server": "127.0.0.1",
                "detour": "missing"
            }]},
            "outbounds": [{"type": "block", "tag": "deny"}]
        }))
        .unwrap();
        let error = match OutboundManager::from_options(&options, "deny") {
            Ok(_) => panic!("missing DNS outbound detour was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("outbound detour not found"));
        assert!(error.to_string().contains("missing"));
    }

    #[test]
    fn remote_dns_detour_rejects_empty_direct_outbound() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{
                "type": "udp",
                "tag": "remote",
                "server": "127.0.0.1",
                "detour": "direct"
            }]},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap();
        let error = match OutboundManager::from_options(&options, "direct") {
            Ok(_) => panic!("empty direct DNS detour was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("makes no sense"));
    }

    #[test]
    fn remote_dns_detour_can_bind_a_late_endpoint() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{
                "type": "udp",
                "tag": "remote",
                "server": "127.0.0.1",
                "detour": "vpn"
            }]},
            "outbounds": [{"type": "block", "tag": "deny"}],
            "endpoints": [{"type": "wireguard", "tag": "vpn"}]
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&options, "deny").unwrap();
        assert!(
            manager
                .dns()
                .validate_outbound_detours(&HashSet::new())
                .is_err()
        );
        manager
            .register_endpoint(
                "vpn",
                "wireguard",
                Arc::new(crate::protocol::block::BlockOutbound),
            )
            .unwrap();
        manager
            .dns()
            .validate_outbound_detours(&HashSet::new())
            .unwrap();
    }

    #[test]
    fn dhcp_dns_transport_binds_to_configured_outbound_detour() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{
                "type": "dhcp",
                "tag": "lease",
                "interface": "en0",
                "detour": "deny"
            }]},
            "outbounds": [{"type": "block", "tag": "deny"}]
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&options, "deny").unwrap();
        manager
            .dns()
            .validate_outbound_detours(&HashSet::new())
            .unwrap();
    }

    #[tokio::test]
    async fn publishes_manual_urltest_history_updates() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let byte = stream.read_u8().await.unwrap();
                request.push(byte);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert!(request.starts_with(b"HEAD "));
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let options: Options = serde_json::from_str(
            r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#,
        )
        .unwrap();
        let manager =
            OutboundManager::from_options(&options, "direct").unwrap();
        let mut updates = manager.subscribe_urltest_updates();
        manager
            .test_outbound_delay(
                "direct",
                &format!("http://{address}/"),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), updates.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(manager.urltest_history_entry("direct").is_some());
        server.await.unwrap();
    }

    #[test]
    fn accepts_anytls_custom_idle_session_policy() {
        let options: Options = serde_json::from_str(
            r#"{
                "outbounds": [{
                    "type":"anytls", "tag":"proxy",
                    "server":"127.0.0.1", "server_port":443,
                    "password":"secret",
                    "idle_session_check_interval":"6s",
                    "idle_session_timeout":"7s",
                    "min_idle_session":2,
                    "tls":{"enabled":true,"insecure":true}
                }]
            }"#,
        )
        .unwrap();
        let manager = OutboundManager::from_options(&options, "proxy").unwrap();
        assert_eq!(manager.default_tag(), "proxy");
    }

    #[tokio::test]
    async fn dns_outbound_rule_sees_the_resolving_outbound_tag() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {
                "servers": [
                    {
                        "type":"hosts",
                        "tag":"fallback",
                        "predefined":{"service.test":"192.0.2.1"}
                    },
                    {
                        "type":"hosts",
                        "tag":"selected",
                        "predefined":{"service.test":"127.0.0.1"}
                    }
                ],
                "rules":[{"outbound":"proxy","server":"selected"}],
                "final":"fallback"
            },
            "outbounds":[{"type":"direct","tag":"proxy"}]
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&options, "proxy").unwrap();
        let accept =
            tokio::spawn(async move { listener.accept().await.unwrap() });
        let stream = manager
            .outbound("proxy")
            .unwrap()
            .dial_tcp(&SocksAddr::new("service.test", port))
            .await
            .unwrap();
        drop(stream);
        accept.await.unwrap();
    }

    #[test]
    fn selector_choice_survives_manager_restart_when_cache_is_enabled() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime-cache.db");
        let make_options = || -> Options {
            serde_json::from_value(serde_json::json!({
                "experimental": {
                    "cache_file": {
                        "enabled": true,
                        "path": path,
                        "cache_id": "profile-a"
                    }
                },
                "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
                "outbounds": [
                    {"type": "block", "tag": "deny"},
                    {"type": "direct", "tag": "direct"},
                    {
                        "type": "selector",
                        "tag": "pick",
                        "outbounds": ["deny", "direct"],
                        "default": "deny"
                    }
                ]
            }))
            .unwrap()
        };
        let first =
            OutboundManager::from_options(&make_options(), "pick").unwrap();
        assert_eq!(first.selected_group("pick").as_deref(), Some("deny"));
        first.select_group("pick", "direct").unwrap();
        drop(first);

        let second =
            OutboundManager::from_options(&make_options(), "pick").unwrap();
        assert_eq!(second.selected_group("pick").as_deref(), Some("direct"));
    }

    #[test]
    fn opens_enabled_persistent_dns_cache_from_experimental_options() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dns-cache.db");
        let options: Options = serde_json::from_value(serde_json::json!({
            "experimental": {
                "cache_file": {
                    "enabled": true,
                    "path": path,
                    "cache_id": "profile-a",
                    "store_dns": true
                }
            }
        }))
        .unwrap();
        OutboundManager::from_options(&options, "").unwrap();
        assert!(path.exists());
    }

    #[test]
    fn opens_cache_for_fakeip_without_persistent_dns_enabled() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fakeip-cache.db");
        let options: Options = serde_json::from_value(serde_json::json!({
            "experimental": {
                "cache_file": {
                    "enabled": true,
                    "path": path,
                    "store_fakeip": true
                }
            },
            "dns": {
                "servers": [
                    {"type": "hosts", "tag": "hosts"},
                    {
                        "type": "fakeip",
                        "tag": "fakeip",
                        "inet4_range": "198.18.0.0/15"
                    }
                ],
                "final": "hosts"
            }
        }))
        .unwrap();
        OutboundManager::from_options(&options, "").unwrap();
        assert!(path.exists());
    }

    #[tokio::test]
    async fn injects_persistent_fakeip_cache_into_dns_manager() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fakeip-cache.db");
        let make_options = || -> Options {
            serde_json::from_value(serde_json::json!({
                "experimental": {
                    "cache_file": {
                        "enabled": true,
                        "path": path,
                        "cache_id": "profile-a",
                        "store_fakeip": true
                    }
                },
                "dns": {
                    "servers": [
                        {"type": "hosts", "tag": "hosts"},
                        {
                            "type": "fakeip",
                            "tag": "fakeip",
                            "inet4_range": "198.18.0.0/15"
                        }
                    ],
                    "final": "hosts"
                }
            }))
            .unwrap()
        };
        let first = OutboundManager::from_options(&make_options(), "").unwrap();
        let address = first
            .dns()
            .resolver("fakeip")
            .unwrap()
            .lookup("Example.COM.", crate::option::DomainStrategy::Ipv4Only)
            .await
            .unwrap()[0];
        drop(first);

        let second =
            OutboundManager::from_options(&make_options(), "").unwrap();
        assert_eq!(
            second.dns().fake_ip_domain(address).as_deref(),
            Some("example.com")
        );
    }

    #[tokio::test]
    async fn injects_rdrc_cache_into_dns_response_matching() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rdrc-cache.db");
        let options: Options = serde_json::from_value(serde_json::json!({
            "experimental": {
                "cache_file": {
                    "enabled": true,
                    "path": path,
                    "cache_id": "profile-a",
                    "store_rdrc": true,
                    "rdrc_timeout": "1h"
                }
            },
            "dns": {
                "servers": [
                    {
                        "type": "hosts",
                        "tag": "bad",
                        "predefined": {"example.com": "192.0.2.9"}
                    },
                    {
                        "type": "hosts",
                        "tag": "fallback",
                        "predefined": {"example.com": "203.0.113.1"}
                    }
                ],
                "rules": [
                    {"action": "evaluate", "server": "bad", "tag": "checked"},
                    {
                        "match_response": "checked",
                        "ip_cidr": "203.0.113.0/24",
                        "action": "respond"
                    }
                ],
                "final": "fallback"
            }
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&options, "").unwrap();
        assert_eq!(
            manager
                .dns()
                .default()
                .lookup("example.com", crate::option::DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["203.0.113.1".parse::<std::net::IpAddr>().unwrap()]
        );
        let cache = crate::dns::persistent::PersistentDnsCache::open(
            &path,
            "profile-a",
        )
        .unwrap();
        assert!(cache.load_rdrc("bad", "example.com", 1).unwrap());
        drop(manager);
        let restarted: Options = serde_json::from_value(serde_json::json!({
            "experimental": {
                "cache_file": {
                    "enabled": true,
                    "path": path,
                    "cache_id": "profile-a",
                    "store_rdrc": true,
                    "rdrc_timeout": "1h"
                }
            },
            "dns": {
                "servers": [
                    {
                        "type": "hosts",
                        "tag": "bad",
                        "predefined": {"example.com": "203.0.113.9"}
                    },
                    {
                        "type": "hosts",
                        "tag": "fallback",
                        "predefined": {"example.com": "198.51.100.1"}
                    }
                ],
                "rules": [
                    {"action": "evaluate", "server": "bad", "tag": "checked"},
                    {
                        "match_response": "checked",
                        "ip_cidr": "203.0.113.0/24",
                        "action": "respond"
                    }
                ],
                "final": "fallback"
            }
        }))
        .unwrap();
        let restarted = OutboundManager::from_options(&restarted, "").unwrap();
        assert_eq!(
            restarted
                .dns()
                .default()
                .lookup("example.com", crate::option::DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["198.51.100.1".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn builds_urltest_groups_and_detects_cycles() {
        let options: Options = serde_json::from_str(
            r#"{
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "outbounds":[
                    {"type":"direct","tag":"one"},
                    {"type":"block","tag":"two"},
                    {"type":"urltest","tag":"auto","outbounds":["one","two"],"url":"http://probe.test/"}
                ]
            }"#,
        )
        .unwrap();
        let manager = OutboundManager::from_options(&options, "auto").unwrap();
        assert!(manager.outbound("auto").is_some());
        assert_eq!(manager.urltest_selected("auto"), None);
        assert_eq!(manager.urltest_history("auto").unwrap().len(), 0);
        assert!(manager.urltest_history("missing").is_none());

        let cyclic: Options = serde_json::from_str(
            r#"{
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "outbounds":[
                    {"type":"urltest","tag":"a","outbounds":["b"]},
                    {"type":"selector","tag":"b","outbounds":["a"]}
                ]
            }"#,
        )
        .unwrap();
        let error = match OutboundManager::from_options(&cyclic, "") {
            Ok(_) => panic!("circular URLTest dependency was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("a -> b -> a"));
    }

    #[test]
    fn detects_missing_and_circular_detours() {
        let missing: Options = serde_json::from_str(
            r#"{
            "outbounds":[{"type":"direct","tag":"a","detour":"missing"}]
        }"#,
        )
        .unwrap();
        let error = match OutboundManager::from_options(&missing, "") {
            Ok(_) => panic!("direct detour was accepted"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("direct context"),
            "unexpected error: {error}"
        );
        let cyclic: Options = serde_json::from_str(
            r#"{
            "outbounds":[
                {"type":"socks","tag":"a","server":"127.0.0.1","server_port":1080,"detour":"b"},
                {"type":"socks","tag":"b","server":"127.0.0.1","server_port":1080,"detour":"a"}
            ]
        }"#,
        )
        .unwrap();
        let error = match OutboundManager::from_options(&cyclic, "") {
            Ok(_) => panic!("circular dependency was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("a -> b -> a"));
    }

    #[tokio::test]
    async fn protocol_dialer_options_reach_the_physical_socket() {
        let options: Options = serde_json::from_str(
            r#"{
                "outbounds":[{
                    "type":"socks",
                    "tag":"proxy",
                    "server":"127.0.0.1",
                    "server_port":9,
                    "tcp_multi_path":true
                }]
            }"#,
        )
        .unwrap();
        let manager = OutboundManager::from_options(&options, "").unwrap();
        let result = manager
            .outbound("proxy")
            .unwrap()
            .dial_tcp(&SocksAddr::new("target.test", 443))
            .await;
        let error = match result {
            Ok(_) => panic!("protocol socket options were ignored"),
            Err(error) => error,
        };
        assert!(
            !error.to_string().contains("TCP multipath"),
            "tcp_multi_path should reach the physical dialer instead of being rejected: {error}"
        );
    }

    #[test]
    fn reports_upstream_removed_outbound_types() {
        for (kind, expected) in [
            (
                "shadowsocksr",
                "ShadowsocksR is deprecated and removed in sing-box 1.6.0",
            ),
            (
                "wireguard",
                "WireGuard outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use WireGuard endpoint instead",
            ),
        ] {
            let options: Options = serde_json::from_value(serde_json::json!({
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "outbounds":[{"type":kind,"tag":"removed"}]
            }))
            .unwrap();
            let error = match OutboundManager::from_options(&options, "") {
                Ok(_) => panic!("removed outbound was accepted"),
                Err(error) => error,
            };
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn builds_native_and_external_tor_modes() {
        let native: Options = serde_json::from_str(
            r#"{
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "outbounds":[
                    {"type":"direct","tag":"bootstrap","connect_timeout":"5s"},
                    {"type":"tor","tag":"tor","detour":"bootstrap","data_directory":"$HOME/.cache/sing-box/tor"}
                ]
            }"#,
        )
        .unwrap();
        if let Err(error) = OutboundManager::from_options(&native, "tor") {
            panic!("native Tor should build: {error}");
        }

        for legacy in [
            serde_json::json!({"executable_path":"/usr/bin/tor"}),
            serde_json::json!({"extra_args":["--UseBridges", "0"]}),
            serde_json::json!({"torrc":{"NewCircuitPeriod":"30"}}),
        ] {
            let mut outbound = serde_json::json!({
                "type":"tor", "tag":"tor"
            });
            outbound
                .as_object_mut()
                .unwrap()
                .extend(legacy.as_object().unwrap().clone());
            let options: Options = serde_json::from_value(serde_json::json!({
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "outbounds":[outbound]
            }))
            .unwrap();
            if let Err(error) = OutboundManager::from_options(&options, "tor") {
                panic!(
                    "external Tor compatibility option should build: {error}"
                );
            }
        }
    }

    #[test]
    fn builds_internal_shadowsocks_plugins_and_rejects_unknown_plugins() {
        let options: Options = serde_json::from_str(
            r#"{
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "outbounds":[{
                    "type":"shadowsocks", "tag":"ss",
                    "server":"127.0.0.1", "server_port":8388,
                    "method":"aes-128-gcm", "password":"secret"
                }]
            }"#,
        )
        .unwrap();
        assert!(OutboundManager::from_options(&options, "ss").is_ok());

        for plugin in ["obfs-local", "v2ray-plugin", "unknown-plugin"] {
            let outbound = serde_json::json!({
                "type":"shadowsocks", "tag":"ss",
                "server":"127.0.0.1", "server_port":8388,
                "method":"aes-128-gcm", "password":"secret",
                "plugin":plugin,
                "plugin_opts":"obfs=tls;obfs-host=cover.example"
            });
            let options: Options = serde_json::from_value(serde_json::json!({
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "outbounds":[outbound]
            }))
            .unwrap();
            let result = OutboundManager::from_options(&options, "ss");
            if matches!(plugin, "obfs-local" | "v2ray-plugin") {
                assert!(result.is_ok());
            } else {
                let error = match result {
                    Ok(_) => panic!("unknown Shadowsocks plugin was accepted"),
                    Err(error) => error,
                };
                assert!(error.to_string().contains("plugin not found"));
            }
        }
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds":[{
                "type":"shadowsocks", "tag":"ss",
                "server":"127.0.0.1", "server_port":8388,
                "method":"aes-128-gcm", "password":"secret",
                "multiplex":{"enabled":true,"max_connections":1}
            }]
        }))
        .unwrap();
        assert!(OutboundManager::from_options(&options, "ss").is_ok());
    }

    #[test]
    fn builds_snell_modes_and_rejects_unported_variants() {
        for extension in [
            serde_json::json!({"version":4}),
            serde_json::json!({"version":4,"obfs_mode":"http"}),
            serde_json::json!({"version":4,"obfs_mode":"tls"}),
            serde_json::json!({"version":4,"reuse":true}),
            serde_json::json!({"version":6,"mode":"default"}),
            serde_json::json!({"version":6,"mode":"unshaped"}),
            serde_json::json!({"version":6,"mode":"unsafe-raw"}),
        ] {
            let mut outbound = serde_json::json!({
                "type":"snell", "tag":"snell",
                "server":"127.0.0.1", "server_port":8010,
                "psk":"secret", "userkey":"key"
            });
            outbound
                .as_object_mut()
                .unwrap()
                .extend(extension.as_object().unwrap().clone());
            let options: Options = serde_json::from_value(
                serde_json::json!({"outbounds":[outbound]}),
            )
            .unwrap();
            assert!(OutboundManager::from_options(&options, "snell").is_ok());
        }
    }

    #[test]
    fn builds_shadowtls_versions_and_rejects_missing_tls() {
        for version in [1, 2, 3] {
            let options: Options =
                serde_json::from_value(serde_json::json!({
                    "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                    "outbounds":[{
                        "type":"shadowtls", "tag":"shadowtls",
                        "server":"127.0.0.1", "server_port":443,
                        "version":version, "password":"secret",
                        "tls":{"enabled":true,"server_name":"decoy.example","insecure":true}
                    }]
                }))
                .unwrap();
            if let Err(error) =
                OutboundManager::from_options(&options, "shadowtls")
            {
                panic!("ShadowTLS v{version} should build: {error}");
            }
        }

        {
            let fields = serde_json::json!({"version":1});
            let mut outbound = serde_json::json!({
                "type":"shadowtls", "tag":"shadowtls",
                "server":"127.0.0.1", "server_port":443
            });
            outbound
                .as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            let options: Options = serde_json::from_value(serde_json::json!({
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "outbounds":[outbound]
            }))
            .unwrap();
            assert!(
                OutboundManager::from_options(&options, "shadowtls").is_err()
            );
        }
    }

    #[tokio::test]
    async fn synthesizes_direct_default_when_outbounds_are_empty() {
        let manager =
            OutboundManager::from_options(&Options::default(), "").unwrap();
        let error = match manager
            .default()
            .dial_tcp(&SocksAddr::new("127.0.0.1", 0))
            .await
        {
            Ok(_) => panic!("port zero unexpectedly connected"),
            Err(error) => error,
        };
        assert!(!error.to_string().is_empty());
    }

    #[tokio::test]
    async fn direct_uses_the_configured_dns_transport_manager() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0_u8; 2];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let options: Options = serde_json::from_str(
            r#"{
            "dns": {
                "servers": [{
                    "type": "hosts",
                    "tag": "test-hosts",
                    "predefined": {"echo.test": "127.0.0.1"}
                }],
                "final": "test-hosts"
            },
            "outbounds": [{"type":"direct","tag":"direct"}]
        }"#,
        )
        .unwrap();
        let manager = OutboundManager::from_options(&options, "").unwrap();
        let mut stream = manager
            .default()
            .dial_tcp(&SocksAddr::new("echo.test", port))
            .await
            .unwrap();
        stream.write_all(b"ok").await.unwrap();
        let mut bytes = [0_u8; 2];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn socks4_outbound_resolves_domains_before_the_wire_handshake() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let request = server_request(&mut stream, &[]).await.unwrap();
            assert_eq!(request.version, SocksVersion::V4);
            assert_eq!(request.destination.to_string(), "192.0.2.9:443");
            assert_eq!(request.user.as_deref(), Some("alice"));
            write_reply_for_version(&mut stream, request.version, 0, None)
                .await
                .unwrap();
            let mut bytes = [0_u8; 2];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {
                "servers":[{
                    "type":"hosts",
                    "tag":"hosts",
                    "predefined":{"target.test":"192.0.2.9"}
                }],
                "final":"hosts"
            },
            "outbounds":[{
                "type":"socks",
                "tag":"proxy",
                "server":proxy_address.ip().to_string(),
                "server_port":proxy_address.port(),
                "version":"4",
                "username":"alice"
            }]
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&options, "").unwrap();
        let mut stream = manager
            .default()
            .dial_tcp(&SocksAddr::new("target.test", 443))
            .await
            .unwrap();
        stream.write_all(b"ok").await.unwrap();
        let mut bytes = [0_u8; 2];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_bind_survives_the_public_outbound_wrappers() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let request = server_request(&mut stream, &[]).await.unwrap();
            assert_eq!(request.version, SocksVersion::V5);
            assert_eq!(request.command, SocksCommand::Bind);
            assert_eq!(request.destination.to_string(), "peer.test:9443");
            write_reply(
                &mut stream,
                0,
                Some(&"127.0.0.1:43000".parse().unwrap()),
            )
            .await
            .unwrap();
            write_reply(
                &mut stream,
                0,
                Some(&"192.0.2.44:9443".parse().unwrap()),
            )
            .await
            .unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"bind");
            stream.write_all(b"ready").await.unwrap();
        });
        let options: Options = serde_json::from_value(serde_json::json!({
            "outbounds":[{
                "type":"socks",
                "tag":"proxy",
                "server":proxy_address.ip().to_string(),
                "server_port":proxy_address.port(),
                "version":"5"
            }]
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&options, "").unwrap();
        let mut stream = manager
            .default()
            .bind_tcp(&SocksAddr::new("peer.test", 9443))
            .await
            .unwrap();
        let peer = client_accept_bind(&mut stream).await.unwrap();
        assert_eq!(peer.to_string(), "192.0.2.44:9443");
        stream.write_all(b"bind").await.unwrap();
        let mut response = [0_u8; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ready");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_outbound_connects_to_a_tls_proxy() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = proxy.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let (destination, _) =
                crate::protocol::http::server_handshake(&mut stream, &[])
                    .await
                    .unwrap();
            assert_eq!(destination.to_string(), "target.test:443");
            crate::protocol::http::write_connect_response(&mut stream, true)
                .await
                .unwrap();
            let mut bytes = [0_u8; 2];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let options: Options = serde_json::from_value(serde_json::json!({
            "outbounds":[{
                "type":"http",
                "tag":"proxy",
                "server":proxy_address.ip().to_string(),
                "server_port":proxy_address.port(),
                "tls":{
                    "enabled":true,
                    "server_name":"localhost",
                    "insecure":true
                }
            }]
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&options, "").unwrap();
        let mut stream = manager
            .default()
            .dial_tcp(&SocksAddr::new("target.test", 443))
            .await
            .unwrap();
        stream.write_all(b"ok").await.unwrap();
        let mut bytes = [0_u8; 2];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn outbound_tls_uses_shared_ntp_clock() {
        let mut ca_parameters = CertificateParams::default();
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_parameters.not_before =
            time::OffsetDateTime::from_unix_timestamp(1_577_836_800).unwrap();
        ca_parameters.not_after =
            time::OffsetDateTime::from_unix_timestamp(1_893_456_000).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();
        let mut leaf_parameters =
            CertificateParams::new(vec!["localhost".into()]).unwrap();
        leaf_parameters.not_before =
            time::OffsetDateTime::from_unix_timestamp(1_609_459_200).unwrap();
        leaf_parameters.not_after =
            time::OffsetDateTime::from_unix_timestamp(1_640_995_200).unwrap();
        leaf_parameters.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_parameters.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_certificate = leaf_parameters
            .signed_by(&leaf_key, &ca_certificate, &ca_key)
            .unwrap();
        let server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf_certificate.der().clone(), ca_certificate.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                leaf_key.serialize_der(),
            )),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = proxy.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let (destination, _) =
                crate::protocol::http::server_handshake(&mut stream, &[])
                    .await
                    .unwrap();
            assert_eq!(destination.to_string(), "target.test:443");
            crate::protocol::http::write_connect_response(&mut stream, true)
                .await
                .unwrap();
        });
        let options: Options = serde_json::from_value(serde_json::json!({
            "outbounds":[{
                "type":"http",
                "tag":"proxy",
                "server":proxy_address.ip().to_string(),
                "server_port":proxy_address.port(),
                "tls":{
                    "enabled":true,
                    "server_name":"localhost",
                    "certificate":[ca_certificate.pem()]
                }
            }]
        }))
        .unwrap();
        let clock = crate::common::ntp::NtpClock::default();
        let manager = OutboundManager::from_options_with_clock(
            &options,
            "",
            Some(clock.clone()),
        )
        .unwrap();
        let system_unix_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;
        let target_unix_nanos = 1_625_097_600_i128 * 1_000_000_000;
        clock.update(crate::common::ntp::NtpSample {
            offset_nanos: i64::try_from(target_unix_nanos - system_unix_nanos)
                .unwrap(),
            round_trip_nanos: 1,
            stratum: 1,
        });
        manager
            .default()
            .dial_tcp(&SocksAddr::new("target.test", 443))
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn trojan_outbound_proxies_tcp_and_udp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let request =
                read_trojan_request(&mut tcp, &[trojan_key("secret")])
                    .await
                    .unwrap();
            assert_eq!(request.command, TrojanCommand::Tcp);
            assert_eq!(request.destination, SocksAddr::new("tcp.test", 443));
            let mut payload = [0_u8; 4];
            tcp.read_exact(&mut payload).await.unwrap();
            tcp.write_all(&payload).await.unwrap();

            let (tcp, _) = listener.accept().await.unwrap();
            let mut tcp: crate::adapter::Stream = Box::new(tcp);
            let request =
                read_trojan_request(&mut tcp, &[trojan_key("secret")])
                    .await
                    .unwrap();
            assert_eq!(request.command, TrojanCommand::Udp);
            let packet = TrojanPacketConnection::new(tcp);
            let mut payload = [0_u8; 16];
            let (size, destination) =
                packet.recv_from(&mut payload).await.unwrap();
            assert_eq!(&payload[..size], b"query");
            assert_eq!(destination, SocksAddr::new("dns.test", 53));
            packet.send_to(b"response", &destination).await.unwrap();
        });

        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{
                "type": "trojan",
                "tag": "trojan",
                "server": "127.0.0.1",
                "server_port": port,
                "password": "secret"
            }]
        }))
        .unwrap();
        let manager =
            OutboundManager::from_options(&options, "trojan").unwrap();

        let mut stream = manager
            .default()
            .dial_tcp(&SocksAddr::new("tcp.test", 443))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");

        let packet = manager
            .default()
            .listen_udp(&SocksAddr::new("dns.test", 53))
            .await
            .unwrap();
        packet
            .send_to(b"query", &SocksAddr::new("dns.test", 53))
            .await
            .unwrap();
        let mut response = [0_u8; 16];
        let (size, destination) =
            packet.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"response");
        assert_eq!(destination, SocksAddr::new("dns.test", 53));
        server.await.unwrap();
    }

    #[test]
    fn trojan_rejects_quic_without_tls_and_accepts_h2mux() {
        {
            let outbound = serde_json::json!({
                "type": "trojan",
                "tag": "trojan",
                "server": "127.0.0.1",
                "server_port": 443,
                "password": "secret",
                "transport":{"type":"quic"}
            });
            let options: Options = serde_json::from_value(serde_json::json!({
                "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
                "outbounds": [outbound]
            }))
            .unwrap();
            let error = match OutboundManager::from_options(&options, "trojan")
            {
                Ok(_) => {
                    panic!("unsupported Trojan feature was accepted")
                }
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("not ported")
                    || error.to_string().contains("TLS is required"),
                "unexpected error: {error}"
            );
        }
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{
                "type": "trojan", "tag": "trojan",
                "server": "127.0.0.1", "server_port": 443,
                "password": "secret",
                "multiplex": {"enabled": true, "max_connections": 1}
            }]
        }))
        .unwrap();
        assert!(OutboundManager::from_options(&options, "trojan").is_ok());
    }

    #[tokio::test]
    async fn vless_outbound_proxies_tcp_and_legacy_udp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let user = "00112233-4455-6677-8899-aabbccddeeff";
        let expected_user = uuid::Uuid::parse_str(user).unwrap();
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let request = read_vless_request(&mut tcp).await.unwrap();
            assert_eq!(request.uuid, expected_user);
            assert_eq!(request.command, VlessCommand::Tcp);
            assert_eq!(
                request.destination,
                Some(SocksAddr::new("tcp.test", 443))
            );
            let mut payload = [0_u8; 4];
            tcp.read_exact(&mut payload).await.unwrap();
            write_vless_response(&mut tcp).await.unwrap();
            tcp.write_all(&payload).await.unwrap();

            let (mut udp, _) = listener.accept().await.unwrap();
            let request = read_vless_request(&mut udp).await.unwrap();
            assert_eq!(request.command, VlessCommand::Udp);
            assert_eq!(
                request.destination,
                Some(SocksAddr::new("dns.test", 53))
            );
            let length = udp.read_u16().await.unwrap() as usize;
            let mut payload = vec![0_u8; length];
            udp.read_exact(&mut payload).await.unwrap();
            write_vless_response(&mut udp).await.unwrap();
            udp.write_u16(length as u16).await.unwrap();
            udp.write_all(&payload).await.unwrap();
        });
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{
                "type": "vless",
                "tag": "vless",
                "server": "127.0.0.1",
                "server_port": port,
                "uuid": user,
                "packet_encoding": ""
            }]
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&options, "vless").unwrap();

        let mut tcp = manager
            .default()
            .dial_tcp(&SocksAddr::new("tcp.test", 443))
            .await
            .unwrap();
        tcp.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        tcp.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");

        let packet = manager
            .default()
            .listen_udp(&SocksAddr::new("dns.test", 53))
            .await
            .unwrap();
        packet
            .send_to(b"query", &SocksAddr::new("ignored.test", 54))
            .await
            .unwrap();
        let mut response = [0_u8; 16];
        let (size, source) = packet.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"query");
        assert_eq!(source, SocksAddr::new("dns.test", 53));
        server.await.unwrap();
    }

    #[test]
    fn vless_packetaddr_builds_as_a_supported_encoding() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{
                "type": "vless",
                "tag": "vless",
                "server": "127.0.0.1",
                "server_port": 443,
                "uuid": "00112233-4455-6677-8899-aabbccddeeff",
                "packet_encoding": "packetaddr"
            }]
        }))
        .unwrap();
        assert!(OutboundManager::from_options(&options, "vless").is_ok());
    }

    #[tokio::test]
    async fn vless_vision_matches_upstream_connection_time_tls_validation() {
        let valid: Options = serde_json::from_value(serde_json::json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds":[{
                "type":"vless",
                "tag":"vision",
                "server":"127.0.0.1",
                "server_port":443,
                "uuid":"00112233-4455-6677-8899-aabbccddeeff",
                "flow":"xtls-rprx-vision",
                "tls":{"enabled":true,"insecure":true}
            }]
        }))
        .unwrap();
        assert!(OutboundManager::from_options(&valid, "vision").is_ok());

        let missing_tls: Options = serde_json::from_value(serde_json::json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds":[{
                "type":"vless",
                "tag":"vision",
                "server":"127.0.0.1",
                "server_port":443,
                "uuid":"00112233-4455-6677-8899-aabbccddeeff",
                "flow":"xtls-rprx-vision"
            }]
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&missing_tls, "vision")
            .expect("upstream accepts Vision without TLS at config time");
        let error = match manager
            .default()
            .dial_tcp(&SocksAddr::new("target.test", 443))
            .await
        {
            Ok(_) => panic!("Vision without TLS unexpectedly connected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("switchable outer TLS stream"));

        let wrapped: Options = serde_json::from_value(serde_json::json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds":[{
                "type":"vless",
                "tag":"vision",
                "server":"127.0.0.1",
                "server_port":443,
                "uuid":"00112233-4455-6677-8899-aabbccddeeff",
                "flow":"xtls-rprx-vision",
                "tls":{"enabled":true,"insecure":true},
                "transport":{"type":"ws"}
            }]
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&wrapped, "vision")
            .expect("upstream accepts Vision over a transport at config time");
        let error = match manager
            .default()
            .dial_tcp(&SocksAddr::new("target.test", 443))
            .await
        {
            Ok(_) => {
                panic!("Vision over WebSocket unexpectedly connected")
            }
            Err(error) => error,
        };
        assert!(error.to_string().contains("switchable outer TLS stream"));
    }

    #[test]
    fn hysteria_port_hopping_builds_and_validates_interval() {
        let make_options = |hop_interval: &str| {
            serde_json::from_value::<Options>(serde_json::json!({
                "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
                "outbounds": [{
                    "type": "hysteria",
                    "tag": "hy",
                    "server": "127.0.0.1",
                    "server_port": 443,
                    "server_ports": ["2000:2002"],
                    "hop_interval": hop_interval,
                    "up_mbps": 1,
                    "down_mbps": 1,
                    "auth_str": "secret",
                    "tls": {"enabled": true, "insecure": true}
                }]
            }))
            .unwrap()
        };
        assert!(
            OutboundManager::from_options(&make_options("5s"), "hy").is_ok()
        );
        let error = match OutboundManager::from_options(
            &make_options("4999ms"),
            "hy",
        ) {
            Ok(_) => panic!("too-short Hysteria hop interval was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("at least 5 seconds"));

        let hysteria2: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{
                "type": "hysteria2",
                "tag": "hy2",
                "server": "127.0.0.1",
                "server_port": 443,
                "server_ports": ["3000:3002"],
                "hop_interval": "5s",
                "hop_interval_max": "6s",
                "password": "secret",
                "bbr_profile": "standard",
                "brutal_debug": true,
                "tls": {"enabled": true, "insecure": true}
            }]
        }))
        .unwrap();
        assert!(
            OutboundManager::from_options(&hysteria2, "hy2").is_ok(),
            "Hysteria2 port hopping should build"
        );

        for profile in ["conservative", "aggressive"] {
            let profile_options: Options =
                serde_json::from_value(serde_json::json!({
                    "dns": {
                        "servers": [{"type": "hosts", "tag": "hosts"}]
                    },
                    "outbounds": [{
                        "type": "hysteria2",
                        "tag": "hy2-profile",
                        "server": "127.0.0.1",
                        "server_port": 443,
                        "password": "secret",
                        "bbr_profile": profile,
                        "tls": {"enabled": true, "insecure": true}
                    }]
                }))
                .unwrap();
            assert!(
                OutboundManager::from_options(&profile_options, "hy2-profile")
                    .is_ok(),
                "Hysteria2 {profile} BBR profile should build"
            );
        }

        let invalid_profile: Options =
            serde_json::from_value(serde_json::json!({
                "dns": {
                    "servers": [{"type": "hosts", "tag": "hosts"}]
                },
                "outbounds": [{
                    "type": "hysteria2",
                    "tag": "hy2-invalid-profile",
                    "server": "127.0.0.1",
                    "server_port": 443,
                    "password": "secret",
                    "bbr_profile": "fast",
                    "tls": {"enabled": true, "insecure": true}
                }]
            }))
            .unwrap();
        let error = match OutboundManager::from_options(
            &invalid_profile,
            "hy2-invalid-profile",
        ) {
            Ok(_) => panic!("invalid Hysteria2 BBR profile was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unsupported BBR profile: fast"));

        let realm: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{
                "type": "block",
                "tag": "realm-control"
            }, {
                "type": "hysteria2",
                "tag": "realm",
                "password": "secret",
                "tls": {"enabled": true, "insecure": true},
                "realm": {
                    "server_url": "https://realm.example",
                    "token": "realm-token",
                    "realm_id": "edge",
                    "stun_servers": ["stun.example:3478"],
                    "ip_version": 4,
                    "http_client": {
                        "version": 3,
                        "detour": "realm-control",
                        "headers": {"X-Realm-Test": "enabled"}
                    },
                    "port_mapping": {
                        "enabled": true,
                        "timeout": "250ms",
                        "lifetime": "10m"
                    }
                }
            }]
        }))
        .unwrap();
        let realm_result = OutboundManager::from_options(&realm, "realm");
        if let Err(error) = realm_result {
            panic!("Hysteria2 Realm outbound should build: {error}");
        }

        let ipv6_mapping: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{
                "type": "hysteria2",
                "tag": "realm",
                "password": "secret",
                "tls": {"enabled": true, "insecure": true},
                "realm": {
                    "server_url": "https://realm.example",
                    "realm_id": "edge",
                    "stun_servers": ["[::1]:3478"],
                    "ip_version": 6,
                    "port_mapping": {"enabled": true}
                }
            }]
        }))
        .unwrap();
        let error = OutboundManager::from_options(&ipv6_mapping, "realm")
            .err()
            .expect("IPv6 Realm port mapping must be rejected");
        assert!(error.to_string().contains("requires IPv4"));
    }
}
