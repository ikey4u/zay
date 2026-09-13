//! DNS resolver transport construction and default selection.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs, io,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock, Weak},
    time::{Duration, Instant, SystemTime},
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, svcb::SvcParamValue},
    },
};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

use crate::common::platform_network::RouteDialerDefaults;
#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
use crate::common::platform_network::{
    PlatformNetworkDefaults, PlatformNetworkProvider,
};
use crate::{
    adapter::{
        DialFuture, Dialer, IcmpResponse, NeighborResolver, NetworkDialOptions,
        PacketConnection, PacketFuture, PacketStream, VisionDialFuture,
    },
    common::{
        network::SocksAddr,
        ntp::NtpClock,
        tls::{EchConfigRecord, EchConfigResolver, build_client_config},
    },
    constant,
    dns::{
        ConfiguredResolver, LookupFuture, LookupOptions, MessageFuture,
        Resolver, SystemResolver, apply_strategy,
        client::{Client, ClientOptions},
        dhcp::DhcpTransport,
        fakeip::FakeIpResolver,
        local::LocalTransport,
        mdns::MdnsTransport,
        openconnect::{OpenConnectConfigurationProvider, OpenConnectResolver},
        openvpn::{OpenVpnConfigurationProvider, OpenVpnResolver},
        persistent::PersistentDnsCache,
        rule::{DnsRuleError, RdrcOptions, RoutingResolver},
        tailscale::{TailscaleNetmapProvider, TailscaleResolver},
        transport::{
            Http3Transport, HttpsTransport, QuicTransport, RemoteResolver,
            TcpTransport, TlsTransport, UdpTransport,
        },
    },
    option::{
        DhcpDnsServerOptions, DirectOutboundOptions, DnsClientOptions,
        DnsOptions, DnsServerOptions, DomainStrategy, FakeIpDnsServerOptions,
        HostsDnsServerOptions, LocalDnsServerOptions, MdnsDnsServerOptions,
        OpenConnectDnsServerOptions, OpenVpnDnsServerOptions,
        RemoteDnsServerOptions, RemoteHttpsDnsServerOptions,
        RemoteTlsDnsServerOptions, TailscaleDnsServerOptions,
    },
    protocol::direct::DirectOutbound,
    route::Metadata as RouteMetadata,
    transport::quic::QuicDialer,
};

pub type SharedResolver = Arc<dyn Resolver>;
const REVERSE_MAPPING_CAPACITY: usize = 1024;

#[derive(Debug)]
struct ReverseMappingEntry {
    domain: String,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct ReverseMappingCache {
    entries: HashMap<IpAddr, ReverseMappingEntry>,
    order: VecDeque<IpAddr>,
}

impl ReverseMappingCache {
    fn insert(&mut self, address: IpAddr, domain: String, ttl: u32) {
        if ttl == 0 {
            self.remove(address);
            return;
        }
        self.remove(address);
        self.entries.insert(
            address,
            ReverseMappingEntry {
                domain,
                expires_at: Instant::now()
                    + Duration::from_secs(u64::from(ttl)),
            },
        );
        self.order.push_back(address);
        while self.entries.len() > REVERSE_MAPPING_CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    fn get(&mut self, address: IpAddr) -> Option<String> {
        let now = Instant::now();
        let entry = self.entries.get(&address)?;
        if entry.expires_at <= now {
            self.remove(address);
            return None;
        }
        let domain = entry.domain.clone();
        self.order.retain(|candidate| *candidate != address);
        self.order.push_back(address);
        Some(domain)
    }

    fn remove(&mut self, address: IpAddr) {
        self.entries.remove(&address);
        self.order.retain(|candidate| *candidate != address);
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

type BuiltResolvers = (
    HashMap<String, SharedResolver>,
    Vec<Arc<FakeIpResolver>>,
    Vec<Arc<Client>>,
    Vec<Arc<OpenConnectResolver>>,
    Vec<Arc<OpenVpnResolver>>,
    Vec<Arc<TailscaleResolver>>,
    Vec<Arc<OutboundDetourDialer>>,
);

struct OutboundDetourDialer {
    dns_server: String,
    outbound: String,
    target: RwLock<Option<Weak<dyn Dialer>>>,
}

impl OutboundDetourDialer {
    fn new(dns_server: &str, outbound: &str) -> Self {
        Self {
            dns_server: dns_server.to_owned(),
            outbound: outbound.to_owned(),
            target: RwLock::new(None),
        }
    }

    fn bind(&self, target: Arc<dyn Dialer>) -> Result<(), ManagerError> {
        let mut slot = self.target.write().map_err(|_| {
            ManagerError::InvalidOptions(format!(
                "DNS outbound detour lock poisoned for {:?}",
                self.dns_server
            ))
        })?;
        if slot.is_none() {
            *slot = Some(Arc::downgrade(&target));
        }
        Ok(())
    }

    fn is_bound(&self) -> bool {
        self.target.read().is_ok_and(|target| {
            target.as_ref().and_then(Weak::upgrade).is_some()
        })
    }

    fn target(&self) -> io::Result<Arc<dyn Dialer>> {
        self.target
            .read()
            .map_err(|_| {
                io::Error::other(format!(
                    "DNS outbound detour lock poisoned for {:?}",
                    self.dns_server
                ))
            })?
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    format!(
                        "outbound detour {:?} is not initialized for DNS server {:?}",
                        self.outbound, self.dns_server
                    ),
                )
            })
    }
}

impl Dialer for OutboundDetourDialer {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        match self.target() {
            Ok(target) => {
                Box::pin(async move { target.dial_tcp(destination).await })
            }
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn dial_tcp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> DialFuture<'a> {
        match self.target() {
            Ok(target) => Box::pin(async move {
                target.dial_tcp_with_options(destination, options).await
            }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn bind_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        match self.target() {
            Ok(target) => {
                Box::pin(async move { target.bind_tcp(destination).await })
            }
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn dial_vision_tcp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> VisionDialFuture<'a> {
        match self.target() {
            Ok(target) => {
                Box::pin(
                    async move { target.dial_vision_tcp(destination).await },
                )
            }
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        match self.target() {
            Ok(target) => {
                Box::pin(async move { target.listen_udp(destination).await })
            }
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn listen_udp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, PacketStream> {
        match self.target() {
            Ok(target) => Box::pin(async move {
                target.listen_udp_with_options(destination, options).await
            }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn listen_udp_on<'a>(
        &'a self,
        destination: &'a SocksAddr,
        local_port: u16,
    ) -> PacketFuture<'a, PacketStream> {
        match self.target() {
            Ok(target) => Box::pin(async move {
                target.listen_udp_on(destination, local_port).await
            }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn exchange_icmp<'a>(
        &'a self,
        packet: &'a [u8],
        source: IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, IcmpResponse> {
        match self.target() {
            Ok(target) => Box::pin(async move {
                target
                    .exchange_icmp(packet, source, hop_limit, destination)
                    .await
            }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn exchange_icmp_with_options<'a>(
        &'a self,
        packet: &'a [u8],
        source: IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, IcmpResponse> {
        match self.target() {
            Ok(target) => Box::pin(async move {
                target
                    .exchange_icmp_with_options(
                        packet,
                        source,
                        hop_limit,
                        destination,
                        options,
                    )
                    .await
            }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn preferred_domain(&self, domain: &str) -> bool {
        self.target()
            .is_ok_and(|target| target.preferred_domain(domain))
    }

    fn preferred_address(&self, address: IpAddr) -> bool {
        self.target()
            .is_ok_and(|target| target.preferred_address(address))
    }
}

pub(crate) struct ResolvingDetourDialer {
    inner: Arc<dyn Dialer>,
    resolver: SharedResolver,
    strategy: DomainStrategy,
}

struct PreferredFallbackResolver {
    preferred: SharedResolver,
    fallback: SharedResolver,
}

impl PreferredFallbackResolver {
    fn should_fallback(error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::Unsupported
        )
    }
}

impl Resolver for PreferredFallbackResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: DomainStrategy,
    ) -> LookupFuture<'a> {
        Box::pin(async move {
            match self.preferred.lookup(domain, strategy).await {
                Err(error) if Self::should_fallback(&error) => {
                    self.fallback.lookup(domain, strategy).await
                }
                result => result,
            }
        })
    }

    fn lookup_with_options<'a>(
        &'a self,
        domain: &'a str,
        options: LookupOptions,
    ) -> LookupFuture<'a> {
        Box::pin(async move {
            match self.preferred.lookup_with_options(domain, options).await {
                Err(error) if Self::should_fallback(&error) => {
                    self.fallback.lookup_with_options(domain, options).await
                }
                result => result,
            }
        })
    }

    fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
        Box::pin(async move {
            match self.preferred.exchange(request).await {
                Err(error) if Self::should_fallback(&error) => {
                    self.fallback.exchange(request).await
                }
                result => result,
            }
        })
    }

    fn exchange_with_options<'a>(
        &'a self,
        request: &'a Message,
        options: LookupOptions,
    ) -> MessageFuture<'a> {
        Box::pin(async move {
            match self.preferred.exchange_with_options(request, options).await {
                Err(error) if Self::should_fallback(&error) => {
                    self.fallback.exchange_with_options(request, options).await
                }
                result => result,
            }
        })
    }

    fn preferred_domain(&self, domain: &str) -> Option<bool> {
        let preferred = self.preferred.preferred_domain(domain);
        let fallback = self.fallback.preferred_domain(domain);
        match (preferred, fallback) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), _) | (_, Some(false)) => Some(false),
            (None, None) => None,
        }
    }
}

impl ResolvingDetourDialer {
    pub(crate) fn new(
        inner: Arc<dyn Dialer>,
        resolver: SharedResolver,
        strategy: DomainStrategy,
    ) -> Self {
        Self {
            inner,
            resolver,
            strategy,
        }
    }

    async fn resolve_all(
        &self,
        destination: &SocksAddr,
    ) -> io::Result<Vec<SocksAddr>> {
        match destination {
            SocksAddr::Ip(_) => Ok(vec![destination.clone()]),
            SocksAddr::Domain { host, port } => {
                let destinations = self
                    .resolver
                    .lookup(host, self.strategy)
                    .await?
                    .into_iter()
                    .map(|address| {
                        SocksAddr::Ip(std::net::SocketAddr::new(address, *port))
                    })
                    .collect::<Vec<_>>();
                if destinations.is_empty() {
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("DNS server {host:?} resolved to no addresses"),
                    ))
                } else {
                    Ok(destinations)
                }
            }
        }
    }

    fn exhausted(last_error: Option<io::Error>) -> io::Error {
        last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "resolved destination has no usable addresses",
            )
        })
    }
}

struct ResolvedPacketConnection {
    inner: PacketStream,
    original: SocksAddr,
    resolved: SocksAddr,
}

impl PacketConnection for ResolvedPacketConnection {
    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.local_addr()
    }

    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        let destination = if destination == &self.original {
            &self.resolved
        } else {
            destination
        };
        self.inner.send_to(data, destination)
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let (size, source) = self.inner.recv_from(data).await?;
            Ok((
                size,
                if source == self.resolved {
                    self.original.clone()
                } else {
                    source
                },
            ))
        })
    }
}

fn restore_packet_destination(
    connection: PacketStream,
    original: &SocksAddr,
    resolved: SocksAddr,
) -> PacketStream {
    if original == &resolved {
        connection
    } else {
        Box::new(ResolvedPacketConnection {
            inner: connection,
            original: original.clone(),
            resolved,
        })
    }
}

impl Dialer for ResolvingDetourDialer {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let mut last_error = None;
            for resolved in self.resolve_all(destination).await? {
                match self.inner.dial_tcp(&resolved).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(Self::exhausted(last_error))
        })
    }

    fn dial_tcp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> DialFuture<'a> {
        Box::pin(async move {
            let mut last_error = None;
            for resolved in self.resolve_all(destination).await? {
                match self.inner.dial_tcp_with_options(&resolved, options).await
                {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(Self::exhausted(last_error))
        })
    }

    fn bind_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let mut last_error = None;
            for resolved in self.resolve_all(destination).await? {
                match self.inner.bind_tcp(&resolved).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(Self::exhausted(last_error))
        })
    }

    fn dial_vision_tcp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> VisionDialFuture<'a> {
        Box::pin(async move {
            let mut last_error = None;
            for resolved in self.resolve_all(destination).await? {
                match self.inner.dial_vision_tcp(&resolved).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(Self::exhausted(last_error))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let mut last_error = None;
            for resolved in self.resolve_all(destination).await? {
                match self.inner.listen_udp(&resolved).await {
                    Ok(connection) => {
                        return Ok(restore_packet_destination(
                            connection,
                            destination,
                            resolved,
                        ));
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            Err(Self::exhausted(last_error))
        })
    }

    fn listen_udp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let mut last_error = None;
            for resolved in self.resolve_all(destination).await? {
                match self
                    .inner
                    .listen_udp_with_options(&resolved, options)
                    .await
                {
                    Ok(connection) => {
                        return Ok(restore_packet_destination(
                            connection,
                            destination,
                            resolved,
                        ));
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            Err(Self::exhausted(last_error))
        })
    }

    fn listen_udp_on<'a>(
        &'a self,
        destination: &'a SocksAddr,
        local_port: u16,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let mut last_error = None;
            for resolved in self.resolve_all(destination).await? {
                match self.inner.listen_udp_on(&resolved, local_port).await {
                    Ok(connection) => {
                        return Ok(restore_packet_destination(
                            connection,
                            destination,
                            resolved,
                        ));
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            Err(Self::exhausted(last_error))
        })
    }

    fn exchange_icmp<'a>(
        &'a self,
        packet: &'a [u8],
        source: IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, IcmpResponse> {
        Box::pin(async move {
            let mut last_error = None;
            for resolved in self.resolve_all(destination).await? {
                match self
                    .inner
                    .exchange_icmp(packet, source, hop_limit, &resolved)
                    .await
                {
                    Ok(response) => return Ok(response),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(Self::exhausted(last_error))
        })
    }

    fn exchange_icmp_with_options<'a>(
        &'a self,
        packet: &'a [u8],
        source: IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, IcmpResponse> {
        Box::pin(async move {
            let mut last_error = None;
            for resolved in self.resolve_all(destination).await? {
                match self
                    .inner
                    .exchange_icmp_with_options(
                        packet, source, hop_limit, &resolved, options,
                    )
                    .await
                {
                    Ok(response) => return Ok(response),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(Self::exhausted(last_error))
        })
    }

    fn preferred_domain(&self, domain: &str) -> bool {
        self.inner.preferred_domain(domain)
    }

    fn preferred_address(&self, address: IpAddr) -> bool {
        self.inner.preferred_address(address)
    }

    fn icmp_flow_addresses(&self) -> Option<(Option<IpAddr>, Option<IpAddr>)> {
        self.inner.icmp_flow_addresses()
    }

    fn packet_port(&self) -> Option<Arc<dyn crate::adapter::IpPacketPort>> {
        self.inner.packet_port()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    #[error("decode DNS server {tag:?}: {message}")]
    Decode { tag: String, message: String },
    #[error("unsupported DNS transport {kind:?} for server {tag:?}: {detail}")]
    Unsupported {
        tag: String,
        kind: String,
        detail: String,
    },
    #[error("default DNS server not found: {0}")]
    DefaultNotFound(String),
    #[error("DNS server dependency {dependency:?} not found for {server:?}")]
    DependencyNotFound { server: String, dependency: String },
    #[error("circular DNS server dependency: {0}")]
    CircularDependency(String),
    #[error("invalid DNS options: {0}")]
    InvalidOptions(String),
    #[error("create local DNS transport: {0}")]
    Local(io::Error),
    #[error("create TLS for DNS server {tag:?}: {message}")]
    Tls { tag: String, message: String },
    #[error(transparent)]
    Rule(#[from] DnsRuleError),
}

pub struct TransportManager {
    order: Vec<String>,
    entries: HashMap<String, SharedResolver>,
    default_tag: String,
    default_resolver: SharedResolver,
    fake_ip: Vec<Arc<FakeIpResolver>>,
    routing: Option<Arc<RoutingResolver>>,
    clients: Vec<Arc<Client>>,
    openconnect: Vec<Arc<OpenConnectResolver>>,
    openvpn: Vec<Arc<OpenVpnResolver>>,
    tailscale: Vec<Arc<TailscaleResolver>>,
    outbound_detours: Vec<Arc<OutboundDetourDialer>>,
    reverse_mapping: Option<Mutex<ReverseMappingCache>>,
}

impl TransportManager {
    pub fn from_options(
        options: Option<&DnsOptions>,
    ) -> Result<Self, ManagerError> {
        Self::from_options_with_persistent_cache(options, None)
    }

    pub fn from_options_with_persistent_cache(
        options: Option<&DnsOptions>,
        persistent_cache: Option<Arc<PersistentDnsCache>>,
    ) -> Result<Self, ManagerError> {
        Self::from_options_with_persistent_caches(
            options,
            persistent_cache,
            None,
        )
    }

    pub fn from_options_with_persistent_caches(
        options: Option<&DnsOptions>,
        persistent_dns_cache: Option<Arc<PersistentDnsCache>>,
        persistent_fakeip_cache: Option<Arc<PersistentDnsCache>>,
    ) -> Result<Self, ManagerError> {
        Self::from_options_with_runtime_cache(
            options,
            persistent_dns_cache,
            persistent_fakeip_cache,
            None,
        )
    }

    pub fn from_options_with_runtime_cache(
        options: Option<&DnsOptions>,
        persistent_dns_cache: Option<Arc<PersistentDnsCache>>,
        persistent_fakeip_cache: Option<Arc<PersistentDnsCache>>,
        rdrc: Option<RdrcOptions>,
    ) -> Result<Self, ManagerError> {
        Self::from_options_with_runtime_cache_and_certificate_store(
            options,
            persistent_dns_cache,
            persistent_fakeip_cache,
            rdrc,
            None,
            None,
        )
    }

    pub(crate) fn from_options_with_runtime_cache_and_certificate_store(
        options: Option<&DnsOptions>,
        persistent_dns_cache: Option<Arc<PersistentDnsCache>>,
        persistent_fakeip_cache: Option<Arc<PersistentDnsCache>>,
        rdrc: Option<RdrcOptions>,
        certificate_store: Option<
            crate::common::certificate_store::CertificateStore,
        >,
        ntp_clock: Option<NtpClock>,
    ) -> Result<Self, ManagerError> {
        Self::from_options_with_runtime_context(
            options,
            persistent_dns_cache,
            persistent_fakeip_cache,
            rdrc,
            certificate_store,
            ntp_clock,
            None,
            RouteDialerDefaults::default(),
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

    // The cache, TLS clock/store and mobile network context are independent
    // runtime-owned resources; keeping them explicit prevents hidden globals.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_options_with_runtime_context(
        options: Option<&DnsOptions>,
        persistent_dns_cache: Option<Arc<PersistentDnsCache>>,
        persistent_fakeip_cache: Option<Arc<PersistentDnsCache>>,
        rdrc: Option<RdrcOptions>,
        certificate_store: Option<
            crate::common::certificate_store::CertificateStore,
        >,
        ntp_clock: Option<NtpClock>,
        neighbor_resolver: Option<Arc<dyn NeighborResolver>>,
        route_dialer_defaults: RouteDialerDefaults,
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
    ) -> Result<Self, ManagerError> {
        let mut order = Vec::new();
        if let Some(options) = options {
            for (index, server) in options.servers.iter().enumerate() {
                let tag = if server.tag.is_empty() {
                    index.to_string()
                } else {
                    server.tag.clone()
                };
                order.push(tag.clone());
            }
        }
        let fakeip_servers: HashSet<String> = options
            .into_iter()
            .flat_map(|options| options.servers.iter().enumerate())
            .filter(|(_, server)| server.kind == "fakeip")
            .map(|(index, server)| {
                if server.tag.is_empty() {
                    index.to_string()
                } else {
                    server.tag.clone()
                }
            })
            .collect();
        if fakeip_servers.len() > 1 {
            return Err(ManagerError::InvalidOptions(
                "multiple fakeip servers are not supported".into(),
            ));
        }
        let (
            mut entries,
            fake_ip,
            clients,
            openconnect,
            openvpn,
            tailscale,
            outbound_detours,
        ) = if let Some(options) = options {
            DnsBuilder::new(
                options,
                persistent_dns_cache,
                persistent_fakeip_cache,
                certificate_store,
                ntp_clock,
                neighbor_resolver,
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
            )?
            .build_all(&order)?
        } else {
            (
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
        };
        if order.is_empty() {
            order.push("local".into());
            entries.insert(
                "local".into(),
                Arc::new(SystemResolver::new().map_err(ManagerError::Local)?),
            );
        }
        let requested_default = options
            .map(|options| options.final_server.as_str())
            .unwrap_or("");
        let default_tag = if requested_default.is_empty() {
            order[0].clone()
        } else if entries.contains_key(requested_default) {
            requested_default.to_owned()
        } else {
            return Err(ManagerError::DefaultNotFound(
                requested_default.into(),
            ));
        };
        if fakeip_servers.contains(&default_tag) {
            return Err(ManagerError::InvalidOptions(
                "default DNS server cannot be fakeip".into(),
            ));
        }
        let fallback = entries[&default_tag].clone();
        let rule_values = options
            .map(|options| {
                options
                    .rules
                    .iter()
                    .map(crate::option::DnsRuleOptions::to_value)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()
            .map_err(|error| ManagerError::InvalidOptions(error.to_string()))?
            .unwrap_or_default();
        let (default_resolver, routing): (SharedResolver, _) = match options {
            Some(options) if !options.rules.is_empty() => {
                let routing = Arc::new(
                    RoutingResolver::compile_with_runtime_cache_and_rule_sets(
                        &rule_values,
                        entries.clone(),
                        fallback,
                        &fakeip_servers,
                        rdrc,
                        rule_set_router,
                    )?,
                );
                (routing.clone(), Some(routing))
            }
            _ => (fallback, None),
        };
        Ok(Self {
            order,
            entries,
            default_tag,
            default_resolver,
            fake_ip,
            routing,
            clients,
            openconnect,
            openvpn,
            tailscale,
            outbound_detours,
            reverse_mapping: options
                .filter(|options| options.reverse_mapping)
                .map(|_| Mutex::new(ReverseMappingCache::default())),
        })
    }

    pub(crate) fn bind_outbound_detour(
        &self,
        outbound_tag: &str,
        dialer: Arc<dyn Dialer>,
    ) -> Result<(), ManagerError> {
        for detour in self
            .outbound_detours
            .iter()
            .filter(|detour| detour.outbound == outbound_tag)
        {
            detour.bind(dialer.clone())?;
        }
        Ok(())
    }

    pub(crate) fn uses_outbound_detour(&self, outbound_tag: &str) -> bool {
        self.outbound_detours
            .iter()
            .any(|detour| detour.outbound == outbound_tag)
    }

    pub(crate) fn validate_outbound_detours(
        &self,
        allowed_unbound: &HashSet<String>,
    ) -> Result<(), ManagerError> {
        if let Some(detour) = self.outbound_detours.iter().find(|detour| {
            !detour.is_bound() && !allowed_unbound.contains(&detour.outbound)
        }) {
            return Err(ManagerError::InvalidOptions(format!(
                "outbound detour not found for DNS server {:?}: {:?}",
                detour.dns_server, detour.outbound
            )));
        }
        Ok(())
    }

    pub(crate) fn bind_openconnect_endpoint(
        &self,
        endpoint_tag: &str,
        dialer: Arc<dyn Dialer>,
        configuration: Arc<dyn OpenConnectConfigurationProvider>,
    ) -> Result<(), ManagerError> {
        let matching = self
            .openconnect
            .iter()
            .filter(|resolver| resolver.endpoint_tag() == endpoint_tag)
            .collect::<Vec<_>>();
        if matching.len() > 1 {
            return Err(ManagerError::InvalidOptions(format!(
                "only one OpenConnect DNS server is allowed for endpoint {endpoint_tag:?}"
            )));
        }
        if let Some(resolver) = matching.first() {
            resolver.bind(dialer, configuration).map_err(|error| {
                ManagerError::InvalidOptions(error.to_string())
            })?;
        }
        Ok(())
    }

    pub(crate) fn validate_openconnect_endpoints(
        &self,
    ) -> Result<(), ManagerError> {
        if let Some(resolver) = self
            .openconnect
            .iter()
            .find(|resolver| !resolver.is_bound())
        {
            return Err(ManagerError::InvalidOptions(format!(
                "OpenConnect DNS endpoint not found: {:?}",
                resolver.endpoint_tag()
            )));
        }
        Ok(())
    }

    pub(crate) fn bind_openvpn_endpoint(
        &self,
        endpoint_tag: &str,
        dialer: Arc<dyn Dialer>,
        configuration: Arc<dyn OpenVpnConfigurationProvider>,
    ) -> Result<(), ManagerError> {
        let matching = self
            .openvpn
            .iter()
            .filter(|resolver| resolver.endpoint_tag() == endpoint_tag)
            .collect::<Vec<_>>();
        if matching.len() > 1 {
            return Err(ManagerError::InvalidOptions(format!(
                "only one OpenVPN DNS server is allowed for endpoint {endpoint_tag:?}"
            )));
        }
        if let Some(resolver) = matching.first() {
            resolver.bind(dialer, configuration).map_err(|error| {
                ManagerError::InvalidOptions(error.to_string())
            })?;
        }
        Ok(())
    }

    pub(crate) fn validate_openvpn_endpoints(
        &self,
    ) -> Result<(), ManagerError> {
        if let Some(resolver) =
            self.openvpn.iter().find(|resolver| !resolver.is_bound())
        {
            return Err(ManagerError::InvalidOptions(format!(
                "OpenVPN DNS endpoint not found: {:?}",
                resolver.endpoint_tag()
            )));
        }
        Ok(())
    }

    pub(crate) fn bind_tailscale_endpoint(
        &self,
        endpoint_tag: &str,
        dialer: Arc<dyn Dialer>,
        provider: Arc<dyn TailscaleNetmapProvider>,
    ) -> Result<(), ManagerError> {
        let matching = self
            .tailscale
            .iter()
            .filter(|resolver| resolver.endpoint_tag() == endpoint_tag)
            .collect::<Vec<_>>();
        if matching.len() > 1 {
            return Err(ManagerError::InvalidOptions(format!(
                "only one Tailscale DNS server is allowed for endpoint {endpoint_tag:?}"
            )));
        }
        if let Some(resolver) = matching.first() {
            resolver.bind(dialer, provider).map_err(|error| {
                ManagerError::InvalidOptions(error.to_string())
            })?;
        }
        Ok(())
    }

    pub(crate) fn validate_tailscale_endpoints(
        &self,
    ) -> Result<(), ManagerError> {
        if let Some(resolver) =
            self.tailscale.iter().find(|resolver| !resolver.is_bound())
        {
            return Err(ManagerError::InvalidOptions(format!(
                "Tailscale DNS endpoint not found: {:?}",
                resolver.endpoint_tag()
            )));
        }
        Ok(())
    }

    pub fn resolver(&self, tag: &str) -> Option<SharedResolver> {
        self.entries.get(tag).cloned()
    }

    pub fn default(&self) -> SharedResolver {
        self.default_resolver.clone()
    }

    pub fn lookup_with_context<'a>(
        &'a self,
        domain: &'a str,
        options: crate::dns::LookupOptions,
        context: &'a RouteMetadata,
    ) -> LookupFuture<'a> {
        match &self.routing {
            Some(routing) => {
                routing.lookup_with_context(domain, options, context)
            }
            None => self.default_resolver.lookup_with_options(domain, options),
        }
    }

    pub fn exchange_with_context<'a>(
        &'a self,
        request: &'a Message,
        options: crate::dns::LookupOptions,
        context: &'a RouteMetadata,
    ) -> crate::dns::MessageFuture<'a> {
        Box::pin(async move {
            let response = match &self.routing {
                Some(routing) => {
                    routing
                        .exchange_with_context(request, options, context)
                        .await?
                }
                None => self.exchange_inner(request).await?,
            };
            self.record_reverse_mapping(request, &response);
            Ok(response)
        })
    }

    pub fn default_tag(&self) -> &str {
        &self.default_tag
    }

    pub fn tags(&self) -> impl Iterator<Item = &str> {
        self.order.iter().map(String::as_str)
    }

    pub fn fake_ip_domain(&self, address: IpAddr) -> Option<String> {
        self.fake_ip.iter().find_map(|resolver| {
            resolver
                .contains(address)
                .then(|| resolver.lookup_domain(address))
                .flatten()
        })
    }

    pub fn is_fake_ip(&self, address: IpAddr) -> bool {
        self.fake_ip
            .iter()
            .any(|resolver| resolver.contains(address))
    }

    pub fn lookup_reverse_mapping(&self, address: IpAddr) -> Option<String> {
        self.reverse_mapping.as_ref().and_then(|cache| {
            cache
                .lock()
                .expect("DNS reverse mapping cache lock poisoned")
                .get(address)
        })
    }

    fn record_reverse_mapping(&self, request: &Message, response: &Message) {
        let Some(cache) = &self.reverse_mapping else {
            return;
        };
        if request.queries.is_empty() || response.answers.is_empty() {
            return;
        }
        let mut cache = cache
            .lock()
            .expect("DNS reverse mapping cache lock poisoned");
        for answer in &response.answers {
            let address = match &answer.data {
                RData::A(address) => IpAddr::V4(address.0),
                RData::AAAA(address) => IpAddr::V6(address.0),
                _ => continue,
            };
            if self.is_fake_ip(address) {
                continue;
            }
            let domain = answer.name.to_utf8();
            let domain = domain.trim_end_matches('.');
            if !domain.is_empty() {
                cache.insert(address, domain.to_owned(), answer.ttl);
            }
        }
    }

    pub fn set_clash_mode(&self, mode: Option<String>) {
        if let Some(routing) = &self.routing {
            routing.set_clash_mode(mode);
        }
    }

    pub(crate) fn configure_rule_set_router(
        &self,
        router: &Arc<crate::route::Router>,
    ) -> Result<(), ManagerError> {
        if let Some(routing) = &self.routing {
            routing.configure_rule_set_router(router)?;
        }
        Ok(())
    }

    /// Clear all response caches owned by this manager. This is required on
    /// mode changes so a result selected under one rule set is never reused
    /// under another.
    pub fn clear_cache(&self) {
        for client in &self.clients {
            client.clear_cache();
        }
        if let Some(cache) = &self.reverse_mapping {
            cache
                .lock()
                .expect("DNS reverse mapping cache lock poisoned")
                .clear();
        }
    }

    pub fn clear_fake_ip(&self) {
        for resolver in &self.fake_ip {
            resolver.reset();
        }
    }

    /// Resolve an intercepted DNS query through the configured resolver graph
    /// and synthesize an address response. Raw remote exchange support is
    /// retained by remote transports; this path also works for hosts, fake-IP,
    /// and the native system resolver which only expose address lookup.
    pub async fn exchange(&self, request: &Message) -> io::Result<Message> {
        let response = self.exchange_inner(request).await?;
        self.record_reverse_mapping(request, &response);
        Ok(response)
    }

    async fn exchange_inner(&self, request: &Message) -> io::Result<Message> {
        if request.metadata.message_type != MessageType::Query
            || request.queries.is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DNS query",
            ));
        }
        match self.default().exchange(request).await {
            Ok(response) => return Ok(response),
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {}
            Err(error) => return Err(error),
        }
        let mut response = Message::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        response.queries = request.queries.clone();
        for query in &request.queries {
            let strategy = match query.query_type() {
                RecordType::A => DomainStrategy::Ipv4Only,
                RecordType::AAAA => DomainStrategy::Ipv6Only,
                record_type => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!(
                            "DNS hijack record type {record_type} is not supported"
                        ),
                    ));
                }
            };
            let domain = query.name().to_utf8();
            let addresses = self.default().lookup(&domain, strategy).await?;
            for address in addresses {
                let data = match address {
                    IpAddr::V4(address) => RData::A(A(address)),
                    IpAddr::V6(address) => RData::AAAA(AAAA(address)),
                };
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    60,
                    data,
                ));
            }
        }
        Ok(response)
    }
}

impl EchConfigResolver for TransportManager {
    fn resolve_ech<'a>(
        &'a self,
        server_name: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = io::Result<EchConfigRecord>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let name = Name::from_ascii(server_name).map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
            })?;
            let mut request =
                Message::new(0, MessageType::Query, OpCode::Query);
            request.metadata.recursion_desired = true;
            request.queries.push(Query::query(name, RecordType::HTTPS));
            let response = self.exchange(&request).await?;
            ech_config_from_response(&response, server_name)
        })
    }
}

fn ech_config_from_response(
    response: &Message,
    server_name: &str,
) -> io::Result<EchConfigRecord> {
    for answer in &response.answers {
        let RData::HTTPS(https) = &answer.data else {
            continue;
        };
        for (_, value) in &https.0.svc_params {
            if let SvcParamValue::EchConfigList(config) = value {
                if config.0.is_empty() {
                    continue;
                }
                return Ok(EchConfigRecord {
                    config_list: config.0.clone(),
                    ttl: Duration::from_secs(u64::from(answer.ttl)),
                });
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no ECH config found in DNS HTTPS records for {server_name}"),
    ))
}

struct DnsBuilder {
    configs: HashMap<String, DnsServerOptions>,
    entries: HashMap<String, SharedResolver>,
    visiting: Vec<String>,
    shared_client: Arc<Client>,
    clients: Vec<Arc<Client>>,
    client_options: ClientOptions,
    independent_cache: bool,
    default_strategy: DomainStrategy,
    client_subnet: Option<ipnet::IpNet>,
    fake_ip: Vec<Arc<FakeIpResolver>>,
    openconnect: Vec<Arc<OpenConnectResolver>>,
    openvpn: Vec<Arc<OpenVpnResolver>>,
    tailscale: Vec<Arc<TailscaleResolver>>,
    outbound_detours: Vec<Arc<OutboundDetourDialer>>,
    persistent_fakeip_cache: Option<Arc<PersistentDnsCache>>,
    certificate_store:
        Option<crate::common::certificate_store::CertificateStore>,
    ntp_clock: Option<NtpClock>,
    neighbor_resolver: Option<Arc<dyn NeighborResolver>>,
    route_dialer_defaults: RouteDialerDefaults,
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    platform_network_provider: Option<Arc<dyn PlatformNetworkProvider>>,
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    platform_network_defaults: PlatformNetworkDefaults,
}

impl DnsBuilder {
    #[allow(clippy::too_many_arguments)]
    fn new(
        options: &DnsOptions,
        persistent_dns_cache: Option<Arc<PersistentDnsCache>>,
        persistent_fakeip_cache: Option<Arc<PersistentDnsCache>>,
        certificate_store: Option<
            crate::common::certificate_store::CertificateStore,
        >,
        ntp_clock: Option<NtpClock>,
        neighbor_resolver: Option<Arc<dyn NeighborResolver>>,
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
    ) -> Result<Self, ManagerError> {
        let configs = options
            .servers
            .iter()
            .enumerate()
            .map(|(index, server)| {
                let tag = if server.tag.is_empty() {
                    index.to_string()
                } else {
                    server.tag.clone()
                };
                (tag, server.clone())
            })
            .collect();
        let mut client_options = client_options(&options.client)?;
        client_options.persistent_cache = persistent_dns_cache;
        let shared_client = Arc::new(Client::new(client_options.clone()));
        Ok(Self {
            configs,
            entries: HashMap::new(),
            visiting: Vec::new(),
            clients: vec![shared_client.clone()],
            shared_client,
            client_options,
            independent_cache: options.client.independent_cache,
            default_strategy: options.client.strategy,
            client_subnet: options
                .client
                .client_subnet
                .as_ref()
                .map(|prefix| prefix.0),
            fake_ip: Vec::new(),
            openconnect: Vec::new(),
            openvpn: Vec::new(),
            tailscale: Vec::new(),
            outbound_detours: Vec::new(),
            persistent_fakeip_cache,
            certificate_store,
            ntp_clock,
            neighbor_resolver,
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
        })
    }

    fn tls_options(
        &self,
        options: Option<crate::option::OutboundTlsOptions>,
    ) -> crate::option::OutboundTlsOptions {
        let mut options = options.unwrap_or_default();
        options.set_runtime_context(
            self.ntp_clock.clone(),
            self.certificate_store.clone(),
        );
        options
    }

    fn build_all(
        mut self,
        order: &[String],
    ) -> Result<BuiltResolvers, ManagerError> {
        for tag in order {
            self.build_tag(tag)?;
        }
        Ok((
            self.entries,
            self.fake_ip,
            self.clients,
            self.openconnect,
            self.openvpn,
            self.tailscale,
            self.outbound_detours,
        ))
    }

    fn build_tag(&mut self, tag: &str) -> Result<SharedResolver, ManagerError> {
        if let Some(resolver) = self.entries.get(tag) {
            return Ok(resolver.clone());
        }
        if let Some(start) = self.visiting.iter().position(|item| item == tag) {
            let mut cycle = self.visiting[start..].to_vec();
            cycle.push(tag.to_owned());
            return Err(ManagerError::CircularDependency(cycle.join(" -> ")));
        }
        let server = self.configs.get(tag).cloned().ok_or_else(|| {
            ManagerError::DependencyNotFound {
                server: self.visiting.first().cloned().unwrap_or_default(),
                dependency: tag.to_owned(),
            }
        })?;
        self.visiting.push(tag.to_owned());
        let result = self.build_server(tag, &server);
        self.visiting.pop();
        let resolver = result?;
        self.entries.insert(tag.to_owned(), resolver.clone());
        Ok(resolver)
    }

    fn build_server(
        &mut self,
        tag: &str,
        server: &DnsServerOptions,
    ) -> Result<SharedResolver, ManagerError> {
        match server.kind.as_str() {
            "local" => {
                let local: LocalDnsServerOptions = decode_server(tag, server)?;
                for domain in local.neighbor_domain.as_slice() {
                    if !domain.starts_with('.') {
                        return Err(ManagerError::InvalidOptions(format!(
                            "DNS server {tag:?}: neighbor_domain entry must start with '.': {domain}"
                        )));
                    }
                }
                if let Some(resolve_options) =
                    local.dialer.abstract_options.domain_resolver.as_ref()
                    && !resolve_options.server.is_empty()
                {
                    self.build_tag(&resolve_options.server)?;
                }
                let dialer = if local.dialer.detour.is_empty() {
                    Arc::new(self.attach_platform_network_provider(
                        DirectOutbound::new(
                            self.direct_options(local.dialer.clone()),
                        ),
                    )) as Arc<dyn Dialer>
                } else {
                    self.outbound_detour_dialer(tag, &local.dialer.detour)
                };
                let system: SharedResolver =
                    Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                        LocalTransport::new_with_prefer_go(
                            tag,
                            dialer,
                            local.prefer_go,
                        )
                        .map_err(ManagerError::Local)?,
                        self.client(),
                        self.default_strategy,
                        self.client_subnet,
                    ));
                let hosts: SharedResolver = Arc::new(HostsResolver::new(
                    HostsDnsServerOptions::default(),
                ));
                let preferred = match (
                    self.neighbor_resolver.clone(),
                    local.neighbor_domain.as_slice().is_empty(),
                ) {
                    (Some(neighbor), false) => {
                        Arc::new(PreferredFallbackResolver {
                            preferred: hosts,
                            fallback: Arc::new(NeighborDnsResolver::new(
                                neighbor,
                                local.neighbor_domain.as_slice(),
                            )),
                        }) as SharedResolver
                    }
                    _ => hosts,
                };
                Ok(Arc::new(PreferredFallbackResolver {
                    preferred,
                    fallback: system,
                }))
            }
            "hosts" => {
                let hosts: HostsDnsServerOptions = decode_server(tag, server)?;
                Ok(Arc::new(HostsResolver::new(hosts)))
            }
            "fakeip" => {
                let options: FakeIpDnsServerOptions =
                    decode_server(tag, server)?;
                let resolver = FakeIpResolver::new_with_cache(
                    options.inet4_range.map(|prefix| prefix.0),
                    options.inet6_range.map(|prefix| prefix.0),
                    self.persistent_fakeip_cache.clone(),
                )
                .map_err(|error| {
                    ManagerError::InvalidOptions(format!(
                        "DNS server {tag:?}: {error}"
                    ))
                })?;
                let resolver = Arc::new(resolver);
                self.fake_ip.push(resolver.clone());
                Ok(resolver)
            }
            "mdns" => {
                let options: MdnsDnsServerOptions = decode_server(tag, server)?;
                if let Some(resolve_options) = options
                    .local
                    .dialer
                    .abstract_options
                    .domain_resolver
                    .as_ref()
                    && !resolve_options.server.is_empty()
                {
                    self.build_tag(&resolve_options.server)?;
                }
                Ok(Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                    MdnsTransport::new(tag, options.interface.into_vec()),
                    self.client(),
                    self.default_strategy,
                    self.client_subnet,
                )))
            }
            "dhcp" => {
                let options: DhcpDnsServerOptions = decode_server(tag, server)?;
                let dialer = if options.local.dialer.detour.is_empty() {
                    Arc::new(self.attach_platform_network_provider(
                        DirectOutbound::new(
                            self.direct_options(options.local.dialer.clone()),
                        ),
                    )) as Arc<dyn Dialer>
                } else {
                    self.outbound_detour_dialer(
                        tag,
                        &options.local.dialer.detour,
                    )
                };
                Ok(Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                    DhcpTransport::new(tag, options.interface, dialer),
                    self.client(),
                    self.default_strategy,
                    self.client_subnet,
                )))
            }
            "openconnect" => {
                let options: OpenConnectDnsServerOptions =
                    decode_server(tag, server)?;
                if options.endpoint.is_empty() {
                    return Err(ManagerError::InvalidOptions(format!(
                        "OpenConnect DNS server {tag:?} is missing endpoint"
                    )));
                }
                let default_strategy = self.default_strategy;
                let client_subnet = self.client_subnet;
                let resolver = Arc::new(OpenConnectResolver::new(
                    tag,
                    options.endpoint,
                    options.accept_default_resolvers,
                    options.accept_search_domain,
                    self.client(),
                    default_strategy,
                    client_subnet,
                ));
                self.openconnect.push(resolver.clone());
                Ok(resolver)
            }
            "openvpn" => {
                let options: OpenVpnDnsServerOptions =
                    decode_server(tag, server)?;
                if options.endpoint.is_empty() {
                    return Err(ManagerError::InvalidOptions(format!(
                        "OpenVPN DNS server {tag:?} is missing endpoint"
                    )));
                }
                let resolver = Arc::new(OpenVpnResolver::new(
                    tag,
                    options.endpoint,
                    options.accept_default_resolvers,
                    options.accept_search_domain,
                    self.client(),
                    self.default_strategy,
                    self.client_subnet,
                    self.certificate_store.clone(),
                    self.ntp_clock.clone(),
                ));
                self.openvpn.push(resolver.clone());
                Ok(resolver)
            }
            "tailscale" => {
                let options: TailscaleDnsServerOptions =
                    decode_server(tag, server)?;
                if options.endpoint.is_empty() {
                    return Err(ManagerError::InvalidOptions(format!(
                        "Tailscale DNS server {tag:?} is missing endpoint"
                    )));
                }
                let resolver =
                    Arc::new(TailscaleResolver::new_with_runtime_context(
                        tag,
                        options.endpoint,
                        options.accept_default_resolvers,
                        options.accept_search_domain,
                        self.client(),
                        self.default_strategy,
                        self.client_subnet,
                        self.certificate_store.clone(),
                        self.ntp_clock.clone(),
                    ));
                self.tailscale.push(resolver.clone());
                Ok(resolver)
            }
            "udp" | "tcp" => {
                let remote: RemoteDnsServerOptions =
                    decode_server(tag, server)?;
                let endpoint = remote_endpoint(tag, &remote, 53)?;
                let dialer = self.remote_dialer(tag, &remote, &endpoint)?;
                let client = self.client();
                let resolver: SharedResolver = match server.kind.as_str() {
                    "udp" => Arc::new(
                        RemoteResolver::with_client_strategy_and_subnet(
                            UdpTransport::new(tag, endpoint, dialer),
                            client,
                            self.default_strategy,
                            self.client_subnet,
                        ),
                    ),
                    "tcp" => Arc::new(
                        RemoteResolver::with_client_strategy_and_subnet(
                            TcpTransport::new(tag, endpoint, dialer),
                            client,
                            self.default_strategy,
                            self.client_subnet,
                        ),
                    ),
                    _ => unreachable!(),
                };
                Ok(resolver)
            }
            "tls" => {
                let options: RemoteTlsDnsServerOptions =
                    decode_server(tag, server)?;
                let remote = &options.remote;
                let endpoint = remote_endpoint(tag, remote, 853)?;
                let dialer = self.remote_dialer(tag, remote, &endpoint)?;
                let tls_options = self.tls_options(options.tls);
                let tls = build_client_config(
                    &remote.address.server,
                    &tls_options,
                    &[],
                )
                .map_err(|error| ManagerError::Tls {
                    tag: tag.to_owned(),
                    message: error.to_string(),
                })?;
                Ok(Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                    TlsTransport::new(tag, endpoint, dialer, tls),
                    self.client(),
                    self.default_strategy,
                    self.client_subnet,
                )))
            }
            "quic" => {
                let options: RemoteTlsDnsServerOptions =
                    decode_server(tag, server)?;
                let remote = &options.remote;
                let endpoint = remote_endpoint(tag, remote, 853)?;
                let detour = (!remote.local.dialer.detour.is_empty())
                    .then(|| self.remote_detour_dialer(tag, remote))
                    .transpose()?;
                let resolver = if detour.is_none() && endpoint.is_domain() {
                    let resolve_options = remote
                        .local
                        .dialer
                        .abstract_options
                        .domain_resolver
                        .as_ref()
                        .ok_or_else(|| ManagerError::InvalidOptions(format!(
                            "DNS server {tag:?} requires domain_resolver for domain endpoint {}",
                            remote.address.server
                        )))?;
                    let resolver = ConfiguredResolver::new(
                        self.build_tag(&resolve_options.server)?,
                        resolve_options,
                        remote.local.dialer.abstract_options.domain_strategy,
                    );
                    let strategy = resolver.strategy();
                    let resolver = Arc::new(resolver) as SharedResolver;
                    Some((resolver, strategy))
                } else {
                    None
                };
                let tls_options = self.tls_options(options.tls);
                let tls = build_client_config(
                    &remote.address.server,
                    &tls_options,
                    &["doq"],
                )
                .map_err(|error| ManagerError::Tls {
                    tag: tag.to_owned(),
                    message: error.to_string(),
                })?;
                let server_name = if tls_options.server_name.is_empty() {
                    remote.address.server.clone()
                } else {
                    tls_options.server_name
                };
                let dialer = Arc::new(
                    match (detour, resolver) {
                        (Some(dialer), _) => {
                            QuicDialer::new_with_packet_dialer(
                                endpoint.clone(),
                                server_name,
                                tls,
                                dialer,
                            )
                        }
                        (None, Some((resolver, strategy))) => {
                            QuicDialer::new_with_resolver(
                                endpoint.clone(),
                                server_name,
                                tls,
                                resolver,
                                strategy,
                            )
                        }
                        (None, None) => {
                            QuicDialer::new(endpoint.clone(), server_name, tls)
                        }
                    }
                    .map_err(|error| {
                        ManagerError::Unsupported {
                            tag: tag.to_owned(),
                            kind: "quic".into(),
                            detail: error.to_string(),
                        }
                    })?,
                );
                Ok(Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                    QuicTransport::new(tag, endpoint, dialer),
                    self.client(),
                    self.default_strategy,
                    self.client_subnet,
                )))
            }
            "h3" => {
                let options: RemoteHttpsDnsServerOptions =
                    decode_server(tag, server)?;
                let remote = &options.remote_tls.remote;
                let endpoint = remote_endpoint(tag, remote, 443)?;
                let detour = (!remote.local.dialer.detour.is_empty())
                    .then(|| self.remote_detour_dialer(tag, remote))
                    .transpose()?;
                let resolver = if detour.is_none() && endpoint.is_domain() {
                    let resolve_options = remote
                        .local
                        .dialer
                        .abstract_options
                        .domain_resolver
                        .as_ref()
                        .ok_or_else(|| ManagerError::InvalidOptions(format!(
                            "DNS server {tag:?} requires domain_resolver for domain endpoint {}",
                            remote.address.server
                        )))?;
                    let resolver = ConfiguredResolver::new(
                        self.build_tag(&resolve_options.server)?,
                        resolve_options,
                        remote.local.dialer.abstract_options.domain_strategy,
                    );
                    let strategy = resolver.strategy();
                    let resolver = Arc::new(resolver) as SharedResolver;
                    Some((resolver, strategy))
                } else {
                    None
                };
                let tls_options = self.tls_options(options.remote_tls.tls);
                let tls = build_client_config(
                    &remote.address.server,
                    &tls_options,
                    &["h3"],
                )
                .map_err(|error| ManagerError::Tls {
                    tag: tag.to_owned(),
                    message: error.to_string(),
                })?;
                let server_name = if tls_options.server_name.is_empty() {
                    remote.address.server.clone()
                } else {
                    tls_options.server_name.clone()
                };
                let (headers, host_override) =
                    https_headers(tag, options.headers)?;
                let host = host_override
                    .or_else(|| {
                        (!tls_options.server_name.is_empty())
                            .then(|| tls_options.server_name.clone())
                    })
                    .unwrap_or_else(|| remote.address.server.clone());
                let authority =
                    format_authority(&host, remote.address.server_port, 443);
                let path = if options.path.is_empty() {
                    "/dns-query"
                } else {
                    &options.path
                };
                let mut url = url::Url::parse(&format!(
                    "https://{authority}/"
                ))
                .map_err(|error| ManagerError::InvalidOptions(format!(
                    "invalid DNS over HTTP/3 authority for {tag:?}: {error}"
                )))?;
                url.set_path(path);
                let uri = url.into();
                let transport = match detour {
                    Some(dialer) => Http3Transport::new_with_packet_dialer(
                        tag,
                        endpoint,
                        server_name,
                        tls,
                        uri,
                        headers,
                        dialer,
                    ),
                    None => Http3Transport::new(
                        tag,
                        endpoint,
                        server_name,
                        tls,
                        uri,
                        headers,
                        resolver,
                    ),
                }
                .map_err(|error| {
                    ManagerError::Unsupported {
                        tag: tag.to_owned(),
                        kind: "h3".into(),
                        detail: error.to_string(),
                    }
                })?;
                Ok(Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                    transport,
                    self.client(),
                    self.default_strategy,
                    self.client_subnet,
                )))
            }
            "https" => {
                let options: RemoteHttpsDnsServerOptions =
                    decode_server(tag, server)?;
                let remote = &options.remote_tls.remote;
                let endpoint = remote_endpoint(tag, remote, 443)?;
                let dialer = self.remote_dialer(tag, remote, &endpoint)?;
                let tls_options = self.tls_options(options.remote_tls.tls);
                let tls = build_client_config(
                    &remote.address.server,
                    &tls_options,
                    &["h2", "http/1.1"],
                )
                .map_err(|error| ManagerError::Tls {
                    tag: tag.to_owned(),
                    message: error.to_string(),
                })?;
                let (headers, host_override) =
                    https_headers(tag, options.headers)?;
                let host = host_override
                    .or_else(|| {
                        (!tls_options.server_name.is_empty())
                            .then(|| tls_options.server_name.clone())
                    })
                    .unwrap_or_else(|| remote.address.server.clone());
                let authority =
                    format_authority(&host, remote.address.server_port, 443);
                let path = if options.path.is_empty() {
                    "/dns-query"
                } else {
                    &options.path
                };
                let mut url = url::Url::parse(&format!(
                    "https://{authority}/"
                ))
                .map_err(|error| ManagerError::InvalidOptions(format!(
                    "invalid DNS over HTTPS authority for {tag:?}: {error}"
                )))?;
                url.set_path(path);
                Ok(Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                    HttpsTransport::new(
                        tag,
                        endpoint,
                        dialer,
                        tls,
                        url.into(),
                        headers,
                    ),
                    self.client(),
                    self.default_strategy,
                    self.client_subnet,
                )))
            }
            kind => Err(ManagerError::Unsupported {
                tag: tag.to_owned(),
                kind: kind.into(),
                detail: "resolver constructor is not ported yet".into(),
            }),
        }
    }

    fn remote_dialer(
        &mut self,
        tag: &str,
        remote: &RemoteDnsServerOptions,
        endpoint: &SocksAddr,
    ) -> Result<Arc<dyn Dialer>, ManagerError> {
        if !remote.local.dialer.detour.is_empty() {
            return self.remote_detour_dialer(tag, remote);
        }
        let direct_options = self.direct_options(remote.local.dialer.clone());
        if !endpoint.is_domain() {
            return Ok(Arc::new(self.attach_platform_network_provider(
                DirectOutbound::new(direct_options),
            )));
        }
        let resolve_options = remote
            .local
            .dialer
            .abstract_options
            .domain_resolver
            .as_ref()
            .ok_or_else(|| ManagerError::InvalidOptions(format!(
                "DNS server {tag:?} requires domain_resolver for domain endpoint {}",
                remote.address.server
            )))?;
        let resolver = ConfiguredResolver::new(
            self.build_tag(&resolve_options.server)?,
            resolve_options,
            remote.local.dialer.abstract_options.domain_strategy,
        );
        let strategy = resolver.strategy();
        Ok(Arc::new(self.attach_platform_network_provider(
            DirectOutbound::with_resolver(
                direct_options,
                Arc::new(resolver),
                strategy,
            ),
        )))
    }

    fn outbound_detour_dialer(
        &mut self,
        dns_server: &str,
        outbound: &str,
    ) -> Arc<dyn Dialer> {
        let dialer = Arc::new(OutboundDetourDialer::new(dns_server, outbound));
        self.outbound_detours.push(dialer.clone());
        dialer
    }

    fn remote_detour_dialer(
        &mut self,
        dns_server: &str,
        remote: &RemoteDnsServerOptions,
    ) -> Result<Arc<dyn Dialer>, ManagerError> {
        let dialer = self
            .outbound_detour_dialer(dns_server, &remote.local.dialer.detour);
        let Some(resolve_options) = remote
            .local
            .dialer
            .abstract_options
            .domain_resolver
            .as_ref()
        else {
            return Ok(dialer);
        };
        let resolver = ConfiguredResolver::new(
            self.build_tag(&resolve_options.server)?,
            resolve_options,
            remote.local.dialer.abstract_options.domain_strategy,
        );
        let strategy = resolver.strategy();
        Ok(Arc::new(ResolvingDetourDialer::new(
            dialer,
            Arc::new(resolver),
            strategy,
        )))
    }

    fn attach_platform_network_provider(
        &self,
        direct: DirectOutbound,
    ) -> DirectOutbound {
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        let direct =
            match self.route_dialer_defaults.auto_detect_interface.as_ref() {
                Some(provider) => {
                    direct.with_auto_detect_interface_provider(provider.clone())
                }
                None => direct,
            };
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        if let Some(provider) = self.platform_network_provider.as_ref() {
            return direct.with_platform_network_provider(provider.clone());
        }
        direct
    }

    fn direct_options(
        &self,
        dialer: crate::option::DialerOptions,
    ) -> DirectOutboundOptions {
        let mut options = DirectOutboundOptions {
            dialer,
            ..Default::default()
        };
        self.route_dialer_defaults
            .apply(&mut options.dialer.abstract_options);
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        self.platform_network_defaults
            .apply(&mut options.dialer.abstract_options);
        options
    }

    fn client(&mut self) -> Arc<Client> {
        if self.independent_cache {
            let client = Arc::new(Client::new(self.client_options.clone()));
            self.clients.push(client.clone());
            client
        } else {
            self.shared_client.clone()
        }
    }
}

fn decode_server<T: serde::de::DeserializeOwned>(
    tag: &str,
    server: &DnsServerOptions,
) -> Result<T, ManagerError> {
    server.decode().map_err(|error| ManagerError::Decode {
        tag: tag.to_owned(),
        message: error.to_string(),
    })
}

fn remote_endpoint(
    tag: &str,
    options: &RemoteDnsServerOptions,
    default_port: u16,
) -> Result<SocksAddr, ManagerError> {
    if options.address.server.is_empty() {
        return Err(ManagerError::InvalidOptions(format!(
            "DNS server {tag:?} has an empty server address"
        )));
    }
    let port = if options.address.server_port == 0 {
        default_port
    } else {
        options.address.server_port
    };
    Ok(SocksAddr::new(options.address.server.clone(), port))
}

fn https_headers(
    tag: &str,
    values: serde_json::Map<String, Value>,
) -> Result<(HeaderMap, Option<String>), ManagerError> {
    let mut headers = HeaderMap::new();
    let mut host = None;
    for (name, value) in values {
        let header_name =
            HeaderName::try_from(name.as_str()).map_err(|error| {
                ManagerError::InvalidOptions(format!(
                    "invalid DNS over HTTPS header for {tag:?}: {error}"
                ))
            })?;
        let values = match value {
            Value::String(value) => vec![value],
            Value::Array(values) => values
                .into_iter()
                .map(|value| {
                    value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                        ManagerError::InvalidOptions(format!(
                            "DNS over HTTPS header {name:?} for {tag:?} contains a non-string value"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => {
                return Err(ManagerError::InvalidOptions(format!(
                    "DNS over HTTPS header {name:?} for {tag:?} is not a string or string list"
                )));
            }
        };
        if header_name == hyper::header::HOST {
            host = values.first().cloned();
            continue;
        }
        for value in values {
            let value = HeaderValue::try_from(value).map_err(|error| {
                ManagerError::InvalidOptions(format!(
                    "invalid DNS over HTTPS header {name:?} for {tag:?}: {error}"
                ))
            })?;
            headers.append(header_name.clone(), value);
        }
    }
    Ok((headers, host))
}

fn format_authority(
    host: &str,
    configured_port: u16,
    default_port: u16,
) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if configured_port != 0 && configured_port != default_port {
        format!("{host}:{configured_port}")
    } else {
        host
    }
}

fn client_options(
    options: &DnsClientOptions,
) -> Result<ClientOptions, ManagerError> {
    if options
        .optimistic
        .is_some_and(|optimistic| optimistic.enabled)
    {
        if options.disable_cache {
            return Err(ManagerError::InvalidOptions(
                "`optimistic` conflicts with `disable_cache`".into(),
            ));
        }
        if options.disable_expire {
            return Err(ManagerError::InvalidOptions(
                "`optimistic` conflicts with `disable_expire`".into(),
            ));
        }
    }
    let optimistic_timeout = options
        .optimistic
        .filter(|options| options.enabled)
        .map(|options| {
            options
                .timeout
                .as_std()
                .filter(|timeout| !timeout.is_zero())
                .unwrap_or(Duration::from_secs(3 * 24 * 60 * 60))
        })
        .unwrap_or_default();
    Ok(ClientOptions {
        timeout: options
            .timeout
            .as_std()
            .filter(|timeout| !timeout.is_zero())
            .unwrap_or(constant::DNS_TIMEOUT),
        disable_cache: options.disable_cache,
        disable_expire: options.disable_expire,
        optimistic_timeout,
        cache_capacity: options.cache_capacity as usize,
        persistent_cache: None,
    })
}

struct NeighborDnsResolver {
    inner: Arc<dyn NeighborResolver>,
    suffixes: Vec<String>,
}

impl NeighborDnsResolver {
    fn new(inner: Arc<dyn NeighborResolver>, suffixes: &[String]) -> Self {
        Self {
            inner,
            suffixes: suffixes
                .iter()
                .map(|value| canonical_name(value))
                .collect(),
        }
    }

    fn hostname(&self, domain: &str) -> Option<String> {
        let domain = canonical_name(domain);
        self.suffixes.iter().find_map(|suffix| {
            let host = domain.strip_suffix(suffix)?;
            (!host.is_empty() && !host.contains('.')).then(|| host.to_owned())
        })
    }

    fn lookup_addresses(
        &self,
        domain: &str,
        strategy: DomainStrategy,
    ) -> io::Result<Vec<IpAddr>> {
        let hostname = self.hostname(domain).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("host {domain:?} is not a configured neighbor name"),
            )
        })?;
        let mut addresses = self.inner.lookup_addresses(&hostname);
        apply_strategy(&mut addresses, strategy);
        if addresses.is_empty() {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("neighbor {hostname:?} not found"),
            ))
        } else {
            Ok(addresses)
        }
    }
}

impl Resolver for NeighborDnsResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: DomainStrategy,
    ) -> LookupFuture<'a> {
        Box::pin(async move { self.lookup_addresses(domain, strategy) })
    }

    fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
        Box::pin(async move {
            let [query] = request.queries.as_slice() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "neighbor DNS exchange requires exactly one question",
                ));
            };
            let strategy = match query.query_type() {
                RecordType::A => DomainStrategy::Ipv4Only,
                RecordType::AAAA => DomainStrategy::Ipv6Only,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "neighbor DNS exchange only supports A and AAAA",
                    ));
                }
            };
            let addresses =
                self.lookup_addresses(&query.name().to_ascii(), strategy)?;
            let mut response = Message::new(
                request.metadata.id,
                MessageType::Response,
                request.metadata.op_code,
            );
            response.queries = request.queries.clone();
            for address in addresses {
                let data = match address {
                    IpAddr::V4(address) => RData::A(A(address)),
                    IpAddr::V6(address) => RData::AAAA(AAAA(address)),
                };
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    constant::DEFAULT_DNS_TTL,
                    data,
                ));
            }
            Ok(response)
        })
    }

    fn preferred_domain(&self, domain: &str) -> Option<bool> {
        Some(self.hostname(domain).is_some_and(|hostname| {
            !self.inner.lookup_addresses(&hostname).is_empty()
        }))
    }
}

struct HostsResolver {
    predefined: HashMap<String, Vec<IpAddr>>,
    files: Vec<HostsFile>,
}

impl HostsResolver {
    fn new(options: HostsDnsServerOptions) -> Self {
        let predefined = options
            .predefined
            .into_iter()
            .map(|(name, addresses)| {
                (canonical_name(&name), addresses.into_vec())
            })
            .collect();
        let paths: Vec<PathBuf> = if options.path.as_slice().is_empty() {
            default_hosts_path().into_iter().collect()
        } else {
            options
                .path
                .into_vec()
                .into_iter()
                .map(expand_environment)
                .collect()
        };
        Self {
            predefined,
            files: paths.into_iter().map(HostsFile::new).collect(),
        }
    }

    fn lookup_addresses(&self, domain: &str) -> Vec<IpAddr> {
        let name = canonical_name(domain);
        let mut addresses =
            self.predefined.get(&name).cloned().unwrap_or_default();
        if addresses.is_empty() {
            for file in &self.files {
                addresses.extend(file.lookup(&name));
                if !addresses.is_empty() {
                    break;
                }
            }
        }
        addresses
    }
}

impl Resolver for HostsResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: crate::option::DomainStrategy,
    ) -> LookupFuture<'a> {
        Box::pin(async move {
            let mut addresses = self.lookup_addresses(domain);
            apply_strategy(&mut addresses, strategy);
            if addresses.is_empty() {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("host {domain:?} not found"),
                ))
            } else {
                Ok(addresses)
            }
        })
    }

    fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
        Box::pin(async move {
            let [query] = request.queries.as_slice() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "hosts DNS exchange requires exactly one question",
                ));
            };
            let strategy = match query.query_type() {
                RecordType::A => DomainStrategy::Ipv4Only,
                RecordType::AAAA => DomainStrategy::Ipv6Only,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "hosts DNS exchange only supports A and AAAA",
                    ));
                }
            };
            let mut addresses = self.lookup_addresses(&query.name().to_ascii());
            apply_strategy(&mut addresses, strategy);
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("host {:?} not found", query.name()),
                ));
            }
            let mut response = Message::new(
                request.metadata.id,
                MessageType::Response,
                request.metadata.op_code,
            );
            response.queries = request.queries.clone();
            for address in addresses {
                let data = match address {
                    IpAddr::V4(address) => RData::A(A(address)),
                    IpAddr::V6(address) => RData::AAAA(AAAA(address)),
                };
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    constant::DEFAULT_DNS_TTL,
                    data,
                ));
            }
            Ok(response)
        })
    }

    fn preferred_domain(&self, domain: &str) -> Option<bool> {
        Some(!self.lookup_addresses(domain).is_empty())
    }
}

struct HostsFile {
    path: PathBuf,
    state: Mutex<HostsFileState>,
}

#[derive(Default)]
struct HostsFileState {
    by_name: HashMap<String, Vec<IpAddr>>,
    checked_at: Option<Instant>,
    modified: Option<SystemTime>,
    size: u64,
}

impl HostsFile {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(HostsFileState::default()),
        }
    }

    fn lookup(&self, name: &str) -> Vec<IpAddr> {
        let mut state = self.state.lock().expect("hosts file mutex poisoned");
        let needs_check = state
            .checked_at
            .is_none_or(|checked| checked.elapsed() >= Duration::from_secs(5));
        if needs_check {
            refresh_hosts_file(&self.path, &mut state);
        }
        state.by_name.get(name).cloned().unwrap_or_default()
    }
}

fn refresh_hosts_file(path: &Path, state: &mut HostsFileState) {
    state.checked_at = Some(Instant::now());
    let Ok(metadata) = fs::metadata(path) else {
        return;
    };
    let modified = metadata.modified().ok();
    if state.modified == modified
        && state.size == metadata.len()
        && !state.by_name.is_empty()
    {
        return;
    }
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    let mut by_name: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for line in content.lines() {
        let line = line.split_once('#').map(|(line, _)| line).unwrap_or(line);
        let mut fields = line.split_whitespace();
        let Some(address) =
            fields.next().and_then(|value| value.parse::<IpAddr>().ok())
        else {
            continue;
        };
        for name in fields {
            by_name
                .entry(canonical_name(name))
                .or_default()
                .push(address);
        }
    }
    state.by_name = by_name;
    state.modified = modified;
    state.size = metadata.len();
}

fn canonical_name(name: &str) -> String {
    format!("{}.", name.trim_end_matches('.').to_ascii_lowercase())
}

#[cfg(unix)]
fn default_hosts_path() -> Option<PathBuf> {
    Some(PathBuf::from("/etc/hosts"))
}

#[cfg(windows)]
fn default_hosts_path() -> Option<PathBuf> {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| root.join("System32/drivers/etc/hosts"))
}

#[cfg(not(any(unix, windows)))]
fn default_hosts_path() -> Option<PathBuf> {
    None
}

fn expand_environment(path: String) -> PathBuf {
    // Preserve unknown variables. Upstream uses os.ExpandEnv; this covers the
    // common $NAME and ${NAME} forms without invoking a shell.
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
            let name_ended = if braced {
                next == '}'
            } else {
                next != '_' && !next.is_ascii_alphanumeric()
            };
            if name_ended {
                break;
            }
            name.push(next);
            chars.next();
        }
        if braced && chars.peek() == Some(&'}') {
            chars.next();
        }
        if let Ok(value) = std::env::var(&name) {
            output.push_str(&value);
        }
    }
    PathBuf::from(output)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
        sync::{Arc, Mutex},
    };

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{
            Name, RData, Record, RecordType,
            rdata::{
                A, HTTPS, SVCB,
                svcb::{EchConfigList, SvcParamKey, SvcParamValue},
            },
        },
        serialize::binary::{
            BinDecodable, BinDecoder, BinEncodable, BinEncoder,
        },
    };
    use tokio::net::UdpSocket;

    use crate::{
        adapter::{
            DialFuture, Dialer, NeighborResolver, PacketConnection,
            PacketFuture, PacketStream,
        },
        common::network::SocksAddr,
        common::tls::EchConfigResolver,
        dns::{
            Resolver,
            manager::{
                HostsResolver, NeighborDnsResolver, ResolvingDetourDialer,
                TransportManager,
            },
        },
        option::{DnsOptions, DomainStrategy, HostsDnsServerOptions, Listable},
    };

    use super::{
        REVERSE_MAPPING_CAPACITY, ReverseMappingCache,
        ech_config_from_response, restore_packet_destination,
    };

    struct RecordingDialer {
        destinations: Arc<Mutex<Vec<SocksAddr>>>,
    }

    struct RecordingPacketConnection {
        destinations: Arc<Mutex<Vec<SocksAddr>>>,
        response_source: SocksAddr,
    }

    impl PacketConnection for RecordingPacketConnection {
        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            destination: &'a SocksAddr,
        ) -> PacketFuture<'a, usize> {
            self.destinations.lock().unwrap().push(destination.clone());
            Box::pin(async move { Ok(data.len()) })
        }

        fn recv_from<'a>(
            &'a self,
            data: &'a mut [u8],
        ) -> PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(async move {
                data[0] = 1;
                Ok((1, self.response_source.clone()))
            })
        }
    }

    struct StaticNeighbor;

    impl NeighborResolver for StaticNeighbor {
        fn lookup_addresses(&self, hostname: &str) -> Vec<IpAddr> {
            match hostname {
                "printer" => vec![
                    "192.0.2.44".parse().unwrap(),
                    "2001:db8::44".parse().unwrap(),
                ],
                _ => Vec::new(),
            }
        }
    }

    #[tokio::test]
    async fn reverse_mapping_records_dns_exchange_and_clears_with_cache() {
        let options: DnsOptions = serde_json::from_value(serde_json::json!({
            "servers": [{
                "type": "hosts",
                "tag": "hosts",
                "predefined": {"reverse.example": "192.0.2.77"}
            }],
            "final": "hosts",
            "reverse_mapping": true
        }))
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("reverse.example").unwrap(),
            RecordType::A,
        ));
        let response = manager.exchange(&request).await.unwrap();
        assert_eq!(response.answers.len(), 1);
        let address = "192.0.2.77".parse().unwrap();
        assert_eq!(
            manager.lookup_reverse_mapping(address).as_deref(),
            Some("reverse.example")
        );
        manager.clear_cache();
        assert_eq!(manager.lookup_reverse_mapping(address), None);

        let disabled = DnsOptions {
            reverse_mapping: false,
            ..options
        };
        let disabled = TransportManager::from_options(Some(&disabled)).unwrap();
        disabled.exchange(&request).await.unwrap();
        assert_eq!(disabled.lookup_reverse_mapping(address), None);
    }

    #[test]
    fn reverse_mapping_cache_is_ttl_bound_and_lru_capped() {
        let mut cache = ReverseMappingCache::default();
        for index in 1..=REVERSE_MAPPING_CAPACITY {
            cache.insert(
                IpAddr::V4(Ipv4Addr::from(index as u32)),
                format!("{index}.example"),
                60,
            );
        }
        let first = IpAddr::V4(Ipv4Addr::from(1));
        let second = IpAddr::V4(Ipv4Addr::from(2));
        assert_eq!(cache.get(first).as_deref(), Some("1.example"));
        cache.insert(
            IpAddr::V4(Ipv4Addr::from((REVERSE_MAPPING_CAPACITY + 1) as u32)),
            "new.example".into(),
            60,
        );
        assert_eq!(cache.get(second), None);
        assert_eq!(cache.get(first).as_deref(), Some("1.example"));
        cache.insert(first, "expired.example".into(), 0);
        assert_eq!(cache.get(first), None);
    }

    #[tokio::test]
    async fn neighbor_dns_matches_single_label_suffix_and_address_family() {
        let resolver = NeighborDnsResolver::new(
            Arc::new(StaticNeighbor),
            &[".lan".into()],
        );
        assert_eq!(
            resolver
                .lookup(
                    "Printer.LAN.",
                    crate::option::DomainStrategy::Ipv4Only,
                )
                .await
                .unwrap(),
            ["192.0.2.44".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            resolver
                .lookup("printer.lan", crate::option::DomainStrategy::Ipv6Only,)
                .await
                .unwrap(),
            ["2001:db8::44".parse::<IpAddr>().unwrap()]
        );
        assert!(
            resolver
                .lookup(
                    "nested.printer.lan",
                    crate::option::DomainStrategy::AsIs,
                )
                .await
                .is_err()
        );
    }

    impl Dialer for RecordingDialer {
        fn dial_tcp<'a>(
            &'a self,
            destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            self.destinations.lock().unwrap().push(destination.clone());
            Box::pin(async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "recorded TCP dial",
                ))
            })
        }

        fn listen_udp<'a>(
            &'a self,
            destination: &'a SocksAddr,
        ) -> PacketFuture<'a, PacketStream> {
            self.destinations.lock().unwrap().push(destination.clone());
            Box::pin(async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "recorded UDP dial",
                ))
            })
        }
    }

    #[tokio::test]
    async fn resolving_detour_tries_every_resolved_address_in_order() {
        let resolver_options: HostsDnsServerOptions =
            serde_json::from_value(serde_json::json!({
                "path": ["/definitely/missing/singbox-hosts"],
                "predefined": {
                    "multi.test": ["192.0.2.1", "192.0.2.2"]
                }
            }))
            .unwrap();
        let destinations = Arc::new(Mutex::new(Vec::new()));
        let inner: Arc<dyn Dialer> = Arc::new(RecordingDialer {
            destinations: destinations.clone(),
        });
        let dialer = ResolvingDetourDialer::new(
            inner,
            Arc::new(HostsResolver::new(resolver_options)),
            DomainStrategy::AsIs,
        );
        let error =
            match dialer.dial_tcp(&SocksAddr::new("multi.test", 443)).await {
                Ok(_) => panic!("recording dialer unexpectedly connected"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        assert_eq!(
            *destinations.lock().unwrap(),
            [
                SocksAddr::new("192.0.2.1", 443),
                SocksAddr::new("192.0.2.2", 443),
            ]
        );
    }

    #[tokio::test]
    async fn resolving_detour_restores_udp_domain_destination() {
        let original = SocksAddr::new("udp.test", 443);
        let resolved = SocksAddr::new("192.0.2.8", 443);
        let destinations = Arc::new(Mutex::new(Vec::new()));
        let connection = restore_packet_destination(
            Box::new(RecordingPacketConnection {
                destinations: destinations.clone(),
                response_source: resolved.clone(),
            }),
            &original,
            resolved.clone(),
        );
        assert_eq!(connection.send_to(b"x", &original).await.unwrap(), 1);
        assert_eq!(*destinations.lock().unwrap(), [resolved]);
        let mut response = [0_u8; 1];
        let (size, source) = connection.recv_from(&mut response).await.unwrap();
        assert_eq!(size, 1);
        assert_eq!(response, [1]);
        assert_eq!(source, original);
    }

    #[test]
    fn extracts_ech_config_and_ttl_from_https_answer() {
        let mut response =
            Message::new(7, MessageType::Response, OpCode::Query);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            321,
            RData::HTTPS(HTTPS(SVCB::new(
                1,
                Name::root(),
                vec![(
                    SvcParamKey::EchConfigList,
                    SvcParamValue::EchConfigList(EchConfigList(vec![
                        0, 3, 1, 2, 3,
                    ])),
                )],
            ))),
        ));

        let record =
            ech_config_from_response(&response, "example.com").unwrap();
        assert_eq!(record.config_list, [0, 3, 1, 2, 3]);
        assert_eq!(record.ttl, std::time::Duration::from_secs(321));
    }

    #[test]
    fn constructs_tailscale_transport_and_requires_a_matching_endpoint() {
        let options: DnsOptions = serde_json::from_value(serde_json::json!({
            "servers": [{
                "type": "tailscale",
                "tag": "tailnet",
                "endpoint": "ts",
                "accept_default_resolvers": true,
                "accept_search_domain": true
            }]
        }))
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        assert!(manager.resolver("tailnet").is_some());
        assert!(manager.validate_tailscale_endpoints().is_err());
    }

    #[test]
    fn constructs_openvpn_transport_and_requires_a_matching_endpoint() {
        let options: DnsOptions = serde_json::from_value(serde_json::json!({
            "servers": [{
                "type": "openvpn",
                "tag": "vpn-dns",
                "endpoint": "vpn",
                "accept_default_resolvers": true,
                "accept_search_domain": true
            }]
        }))
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        assert!(manager.resolver("vpn-dns").is_some());
        assert!(manager.validate_openvpn_endpoints().is_err());
    }

    #[tokio::test]
    async fn predefined_hosts_are_canonical_and_strategy_aware() {
        let resolver = HostsResolver::new(HostsDnsServerOptions {
            path: Listable(Vec::new()),
            predefined: HashMap::from([(
                "Example.COM".into(),
                Listable(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]),
            )]),
        });
        let result = resolver
            .lookup("example.com.", Default::default())
            .await
            .unwrap();
        assert_eq!(result, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
    }

    #[tokio::test]
    async fn dns_rule_preferred_by_routes_using_transport_ownership() {
        let options: DnsOptions = serde_json::from_value(serde_json::json!({
            "servers":[
                {
                    "type":"hosts",
                    "tag":"fallback",
                    "predefined":{"public.example":"192.0.2.1"}
                },
                {
                    "type":"hosts",
                    "tag":"corp",
                    "predefined":{"api.corp.example":"192.0.2.2"}
                }
            ],
            "rules":[{"preferred_by":"corp", "server":"corp"}],
            "final":"fallback"
        }))
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        assert_eq!(
            manager
                .default()
                .lookup("api.corp.example", DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["192.0.2.2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            manager
                .default()
                .lookup("public.example", DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn selects_configured_default_transport() {
        let options: DnsOptions = serde_json::from_str(r#"{
            "servers":[
                {"type":"hosts","tag":"one","predefined":{"one.test":"192.0.2.1"}},
                {"type":"hosts","tag":"two","predefined":{"two.test":"192.0.2.2"}}
            ],
            "final":"two"
        }"#).unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        assert_eq!(manager.default_tag(), "two");
        assert_eq!(manager.tags().collect::<Vec<_>>(), ["one", "two"]);
    }

    #[test]
    fn constructs_mdns_transport_with_interface_filter() {
        let options: DnsOptions = serde_json::from_str(
            r#"{
                "servers":[{
                    "type":"mdns",
                    "tag":"lan",
                    "interface":["en0","eth0"],
                    "detour":"ignored-like-upstream"
                }],
                "final":"lan"
            }"#,
        )
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        assert_eq!(manager.default_tag(), "lan");
        assert!(manager.resolver("lan").is_some());
        assert!(!manager.uses_outbound_detour("ignored-like-upstream"));
    }

    #[test]
    fn local_rejects_invalid_neighbor_domain() {
        let options: DnsOptions = serde_json::from_str(
            r#"{
                "servers":[{
                    "type":"local",
                    "tag":"local",
                    "neighbor_domain":"example.com"
                }]
            }"#,
        )
        .unwrap();
        let error = TransportManager::from_options(Some(&options))
            .err()
            .expect("invalid neighbor domain was accepted");
        assert!(error.to_string().contains("must start with '.'"));
    }

    #[test]
    fn constructs_dhcp_transport_without_eager_network_access() {
        let options: DnsOptions = serde_json::from_str(
            r#"{
                "servers":[{
                    "type":"dhcp",
                    "tag":"lease",
                    "interface":"en0"
                }],
                "final":"lease"
            }"#,
        )
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        assert_eq!(manager.default_tag(), "lease");
        assert!(manager.resolver("lease").is_some());
    }

    #[test]
    fn constructs_doq_transport_with_default_port() {
        let options: DnsOptions = serde_json::from_str(
            r#"{
                "servers":[{
                    "type":"quic",
                    "tag":"doq",
                    "server":"127.0.0.1",
                    "tls":{"insecure":true}
                }],
                "final":"doq"
            }"#,
        )
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        assert_eq!(manager.default_tag(), "doq");
        assert!(manager.resolver("doq").is_some());
    }

    #[test]
    fn constructs_doh3_transport_with_default_port_and_path() {
        let options: DnsOptions = serde_json::from_str(
            r#"{
                "servers":[{
                    "type":"h3",
                    "tag":"doh3",
                    "server":"127.0.0.1",
                    "headers":{"X-Test":"value"},
                    "tls":{"insecure":true,"server_name":"dns.example"}
                }],
                "final":"doh3"
            }"#,
        )
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        assert_eq!(manager.default_tag(), "doh3");
        assert!(manager.resolver("doh3").is_some());
    }

    #[tokio::test]
    async fn default_resolver_applies_domain_routing_rules() {
        let options: DnsOptions = serde_json::from_value(serde_json::json!({
            "servers": [
                {
                    "type": "hosts",
                    "tag": "fallback",
                    "predefined": {
                        "www.example.com": "192.0.2.1",
                        "other.test": "192.0.2.1"
                    }
                },
                {
                    "type": "hosts",
                    "tag": "special",
                    "predefined": {"www.example.com": "192.0.2.2"}
                }
            ],
            "rules": [{
                "domain_suffix": "example.com",
                "server": "special"
            }],
            "final": "fallback"
        }))
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        let special = manager
            .default()
            .lookup("www.example.com", Default::default())
            .await
            .unwrap();
        let fallback = manager
            .default()
            .lookup("other.test", Default::default())
            .await
            .unwrap();
        assert_eq!(special, ["192.0.2.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(fallback, ["192.0.2.1".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn query_type_dns_rule_routes_address_lookup() {
        let options: DnsOptions = serde_json::from_value(serde_json::json!({
            "servers": [{
                "type": "hosts",
                "tag": "fallback",
                "predefined": {"example.com": "192.0.2.1"}
            }],
            "rules": [{"query_type": "A", "server": "fallback"}]
        }))
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        assert_eq!(
            manager
                .default()
                .lookup("example.com", Default::default())
                .await
                .unwrap(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn remote_udp_can_resolve_its_server_through_a_later_transport() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let mut bytes = [0_u8; 1024];
                let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
                let request =
                    Message::read(&mut BinDecoder::new(&bytes[..size]))
                        .unwrap();
                let mut response = Message::new(
                    request.metadata.id,
                    MessageType::Response,
                    OpCode::Query,
                );
                response.queries = request.queries.clone();
                if request.queries[0].query_type() == RecordType::A {
                    response.add_answer(Record::from_rdata(
                        request.queries[0].name().clone(),
                        60,
                        RData::A(A::new(198, 51, 100, 4)),
                    ));
                }
                let mut output = Vec::new();
                response.emit(&mut BinEncoder::new(&mut output)).unwrap();
                socket.send_to(&output, peer).await.unwrap();
            }
        });
        let options: DnsOptions = serde_json::from_value(serde_json::json!({
            "servers": [
                {
                    "type": "udp",
                    "tag": "remote",
                    "server": "dns.bootstrap.test",
                    "server_port": port,
                    "domain_resolver": "bootstrap"
                },
                {
                    "type": "hosts",
                    "tag": "bootstrap",
                    "predefined": {"dns.bootstrap.test": "127.0.0.1"}
                }
            ],
            "final": "remote"
        }))
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        let addresses = manager
            .default()
            .lookup("example.com.", Default::default())
            .await
            .unwrap();
        assert_eq!(addresses, [IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))]);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn detoured_remote_dns_honors_explicit_domain_resolver() {
        let options: DnsOptions = serde_json::from_value(serde_json::json!({
            "servers": [
                {
                    "type": "udp",
                    "tag": "remote",
                    "server": "dns.bootstrap.test",
                    "server_port": 5353,
                    "detour": "proxy",
                    "domain_resolver": "bootstrap"
                },
                {
                    "type": "hosts",
                    "tag": "bootstrap",
                    "predefined": {"dns.bootstrap.test": "192.0.2.53"}
                }
            ],
            "final": "remote"
        }))
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        let destinations = Arc::new(Mutex::new(Vec::new()));
        let dialer: Arc<dyn Dialer> = Arc::new(RecordingDialer {
            destinations: destinations.clone(),
        });
        manager
            .bind_outbound_detour("proxy", dialer.clone())
            .unwrap();
        let error = manager
            .default()
            .lookup("example.com", Default::default())
            .await
            .expect_err("recording dialer intentionally refuses the exchange");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        let destinations = destinations.lock().unwrap();
        assert!(!destinations.is_empty());
        assert!(
            destinations.iter().all(|destination| *destination
                == SocksAddr::new("192.0.2.53", 5353))
        );
    }

    #[tokio::test]
    async fn local_dns_uses_bound_outbound_detour() {
        let options: DnsOptions = serde_json::from_value(serde_json::json!({
            "servers": [{
                "type": "local",
                "tag": "system",
                "detour": "proxy"
            }],
            "final": "system"
        }))
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        assert!(manager.uses_outbound_detour("proxy"));
        let destinations = Arc::new(Mutex::new(Vec::new()));
        let dialer: Arc<dyn Dialer> = Arc::new(RecordingDialer {
            destinations: destinations.clone(),
        });
        manager
            .bind_outbound_detour("proxy", dialer.clone())
            .unwrap();

        let error = manager
            .default()
            .lookup("example.com.", Default::default())
            .await
            .expect_err("recording dialer intentionally refuses the exchange");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        let destinations = destinations.lock().unwrap();
        assert!(!destinations.is_empty());
        assert!(destinations.iter().all(|destination| {
            matches!(destination, SocksAddr::Ip(address) if address.port() == 53)
        }));
    }

    #[tokio::test]
    async fn dynamic_ech_uses_configured_dns_https_transport() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut bytes = [0_u8; 2048];
            let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request =
                Message::read(&mut BinDecoder::new(&bytes[..size])).unwrap();
            assert_eq!(request.queries[0].query_type(), RecordType::HTTPS);
            assert_eq!(request.queries[0].name().to_utf8(), "ech.example.");
            let mut response = Message::new(
                request.metadata.id,
                MessageType::Response,
                OpCode::Query,
            );
            response.queries = request.queries.clone();
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                45,
                RData::HTTPS(HTTPS(SVCB::new(
                    1,
                    Name::root(),
                    vec![(
                        SvcParamKey::EchConfigList,
                        SvcParamValue::EchConfigList(EchConfigList(vec![
                            0, 2, 0xaa, 0xbb,
                        ])),
                    )],
                ))),
            ));
            let mut output = Vec::new();
            response.emit(&mut BinEncoder::new(&mut output)).unwrap();
            socket.send_to(&output, peer).await.unwrap();
        });
        let options: DnsOptions = serde_json::from_value(serde_json::json!({
            "servers": [{
                "type": "udp",
                "tag": "ech-dns",
                "server": "127.0.0.1",
                "server_port": port
            }],
            "final": "ech-dns"
        }))
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        let record = manager.resolve_ech("ech.example").await.unwrap();
        assert_eq!(record.config_list, [0, 2, 0xaa, 0xbb]);
        assert_eq!(record.ttl, std::time::Duration::from_secs(45));
        task.await.unwrap();
    }

    #[test]
    fn rejects_dns_dependency_cycles_and_optimistic_conflicts() {
        let cycle: DnsOptions = serde_json::from_str(r#"{
            "servers":[
                {"type":"udp","tag":"one","server":"one.test","domain_resolver":"two"},
                {"type":"tcp","tag":"two","server":"two.test","domain_resolver":"one"}
            ]
        }"#).unwrap();
        let error = match TransportManager::from_options(Some(&cycle)) {
            Ok(_) => panic!("DNS dependency cycle was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("one -> two -> one"));

        let conflict: DnsOptions = serde_json::from_str(
            r#"{
            "servers":[{"type":"local","tag":"local"}],
            "disable_cache":true,
            "optimistic":true
        }"#,
        )
        .unwrap();
        let error = match TransportManager::from_options(Some(&conflict)) {
            Ok(_) => panic!("conflicting DNS cache settings were accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("conflicts"));
    }

    #[tokio::test]
    async fn manager_exposes_fake_ip_reverse_mapping() {
        let options: DnsOptions = serde_json::from_str(
            r#"{
            "servers":[
                {"type":"hosts","tag":"hosts"},
                {
                    "type":"fakeip",
                    "tag":"fake",
                    "inet4_range":"198.18.0.0/15"
                }
            ],
            "final":"hosts"
        }"#,
        )
        .unwrap();
        let manager = TransportManager::from_options(Some(&options)).unwrap();
        let address = manager
            .resolver("fake")
            .unwrap()
            .lookup("Example.COM.", crate::option::DomainStrategy::Ipv4Only)
            .await
            .unwrap()[0];
        assert!(manager.is_fake_ip(address));
        assert_eq!(
            manager.fake_ip_domain(address).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn rejects_multiple_default_and_evaluate_fakeip_servers() {
        let default_fakeip: DnsOptions = serde_json::from_str(
            r#"{"servers":[{"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"}]}"#,
        )
        .unwrap();
        assert!(
            TransportManager::from_options(Some(&default_fakeip))
                .err()
                .unwrap()
                .to_string()
                .contains("default DNS server cannot be fakeip")
        );

        let multiple: DnsOptions = serde_json::from_str(
            r#"{
                "servers":[
                    {"type":"hosts","tag":"hosts"},
                    {"type":"fakeip","tag":"one","inet4_range":"198.18.0.0/15"},
                    {"type":"fakeip","tag":"two","inet6_range":"fc00::/18"}
                ],
                "final":"hosts"
            }"#,
        )
        .unwrap();
        assert!(
            TransportManager::from_options(Some(&multiple))
                .err()
                .unwrap()
                .to_string()
                .contains("multiple fakeip servers")
        );

        let evaluate: DnsOptions = serde_json::from_str(
            r#"{
                "servers":[
                    {"type":"hosts","tag":"hosts"},
                    {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"}
                ],
                "rules":[{"action":"evaluate","server":"fake"}],
                "final":"hosts"
            }"#,
        )
        .unwrap();
        assert!(
            TransportManager::from_options(Some(&evaluate))
                .err()
                .unwrap()
                .to_string()
                .contains("evaluate action cannot use fakeip server")
        );
    }
}
