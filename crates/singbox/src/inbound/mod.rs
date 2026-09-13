pub mod anytls;
pub mod cloudflared;
pub mod direct;
pub mod http;
pub mod hysteria;
pub mod hysteria2;
pub mod naive;
pub mod redirect;
pub mod shadowsocks;
pub mod shadowtls;
pub mod snell;
pub mod socks;
pub mod tproxy;
pub mod trojan;
pub mod tuic;
pub mod tun;
#[cfg(target_os = "linux")]
pub(crate) mod tun_auto_redirect_linux;
#[cfg(target_os = "linux")]
pub(crate) mod tun_nfqueue_linux;
pub mod tun_route;
#[cfg(target_os = "macos")]
pub(crate) mod tun_route_darwin;
#[cfg(target_os = "linux")]
pub(crate) mod tun_route_linux;
#[cfg(target_os = "windows")]
pub(crate) mod tun_route_windows;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub(crate) mod tun_system_interface;
pub mod vless;
pub mod vmess;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    hash::Hash,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use hickory_proto::serialize::binary::{
    BinDecodable, BinEncodable, BinEncoder,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

tokio::task_local! {
    static TCP_INBOUND_CONTEXT: TcpInboundContext;
}

use crate::{
    adapter::{PacketConnection, PacketStream, Stream, replay_stream},
    common::{
        network::{Network, SocksAddr},
        sniff::{
            PacketSniffState, PacketSniffer, SniffError,
            sniff_packet_with_state, sniff_stream,
        },
    },
    dns::{LookupOptions, Resolver},
    outbound::OutboundManager,
    route::{Action, Metadata, RouteDecision, RouteState, Router},
};

/// Bidirectional destination translation for one routed packet session.
///
/// sing-box applies a route action's address/port override to the destination
/// that selected the packet connection, rather than blindly rewriting every
/// later destination carried by an unbound UDP protocol. Responses from the
/// routed destination must be exposed with the address originally requested
/// by the client. The response maps also cover FakeIP/domain resolution, where
/// a raw UDP socket may report an IP address instead of the domain sent to it.
pub(crate) struct PacketDestinationNat {
    route_original: SocksAddr,
    route_destination: SocksAddr,
    client_route_original: Option<SocksAddr>,
    response_sources: HashMap<SocksAddr, SocksAddr>,
    response_sources_by_port: HashMap<u16, SocksAddr>,
    direct_response_hosts: HashSet<String>,
}

impl PacketDestinationNat {
    pub(crate) fn new(
        route_original: SocksAddr,
        route_destination: SocksAddr,
    ) -> Self {
        Self {
            route_original,
            route_destination,
            client_route_original: None,
            response_sources: HashMap::new(),
            response_sources_by_port: HashMap::new(),
            direct_response_hosts: HashSet::new(),
        }
    }

    pub(crate) fn route_destination(&self) -> &SocksAddr {
        &self.route_destination
    }

    pub(crate) fn translate_destination(
        &mut self,
        destination: SocksAddr,
        client_destination: SocksAddr,
    ) -> SocksAddr {
        let client_route_original = self
            .client_route_original
            .get_or_insert_with(|| client_destination.clone());
        // FakeIP NAT is scoped to the address that selected the packet
        // connection. A different FakeIP carried by the same unbound UDP
        // session is a direct destination, exactly like upstream's
        // `fakeIPNATPacketConn.directDestinations` handling.
        let destination = match (
            &self.route_original,
            &*client_route_original,
            &client_destination,
        ) {
            (
                SocksAddr::Domain { host, .. },
                SocksAddr::Ip(route_origin),
                SocksAddr::Ip(current),
            ) if route_origin.ip() == current.ip() => {
                SocksAddr::new(host.clone(), current.port())
            }
            (SocksAddr::Domain { .. }, SocksAddr::Ip(_), _) => {
                client_destination.clone()
            }
            _ => destination,
        };
        let routed = if destination == self.route_original {
            self.route_destination.clone()
        } else {
            destination
        };
        if routed != client_destination {
            self.response_sources
                .insert(routed.clone(), client_destination.clone());
            self.response_sources_by_port
                .insert(routed.port(), client_destination);
        } else if matches!(routed, SocksAddr::Ip(_)) {
            self.direct_response_hosts.insert(routed.host());
        }
        routed
    }

    pub(crate) fn translate_source(&self, source: SocksAddr) -> SocksAddr {
        if let Some(client_source) = self.response_sources.get(&source) {
            return client_source.clone();
        }
        if matches!(source, SocksAddr::Ip(_))
            && self.direct_response_hosts.contains(&source.host())
        {
            return source;
        }
        self.response_sources_by_port
            .get(&source.port())
            .cloned()
            .unwrap_or(source)
    }
}

struct PacketDestinationNatConnection {
    inner: PacketStream,
    nat: tokio::sync::Mutex<PacketDestinationNat>,
}

impl PacketConnection for PacketDestinationNatConnection {
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }

    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> crate::adapter::PacketFuture<'a, usize> {
        Box::pin(async move {
            let destination = self.nat.lock().await.translate_destination(
                destination.clone(),
                destination.clone(),
            );
            self.inner.send_to(data, &destination).await
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> crate::adapter::PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let (size, source) = self.inner.recv_from(data).await?;
            let source = self.nat.lock().await.translate_source(source);
            Ok((size, source))
        })
    }
}

pub(crate) fn wrap_packet_destination_nat(
    inner: PacketStream,
    original: SocksAddr,
    destination: SocksAddr,
) -> PacketStream {
    if original == destination {
        return inner;
    }
    Box::new(PacketDestinationNatConnection {
        inner,
        nat: tokio::sync::Mutex::new(PacketDestinationNat::new(
            original,
            destination,
        )),
    })
}

pub(crate) async fn proxy_routed_tcp(
    stream: Stream,
    source: SocketAddr,
    tag: &str,
    user: &str,
    destination: SocksAddr,
    router: &Router,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let (destination, origin_destination) =
        socks::restore_fake_ip(destination, outbounds)?;
    let fake_ip = origin_destination.is_some();
    proxy_routed_tcp_with_origin(
        stream,
        source,
        tag,
        user,
        destination,
        origin_destination,
        fake_ip,
        router,
        outbounds,
    )
    .await
}

pub(crate) fn apply_routed_tcp_options(
    stream: Stream,
    options: &crate::route::ConnectionOverride,
) -> io::Result<Stream> {
    let stream = crate::common::tls::wrap_tls_fragment(
        stream,
        options.tls_fragment,
        options.tls_record_fragment,
        options.tls_fragment_fallback_delay.unwrap_or_default(),
    );
    crate::common::tls_spoof::wrap_tls_spoof(
        stream,
        &options.tls_spoof,
        options.tls_spoof_method,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_routed_tcp_with_origin(
    stream: Stream,
    source: SocketAddr,
    tag: &str,
    user: &str,
    destination: SocksAddr,
    origin_destination: Option<SocksAddr>,
    fake_ip: bool,
    router: &Router,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination.clone()),
        origin_destination,
        fake_ip,
        network: Some(Network::Tcp),
        user: user.to_owned(),
        ..Metadata::default()
    };
    if let Some(injector) =
        prepare_tcp_inbound_detour(&mut metadata, outbounds)?
    {
        return injector
            .inject(stream, TcpInboundContext { source, metadata })
            .await;
    }
    let (mut stream, decision) =
        sniff_and_route_stream(stream, &mut metadata, router, outbounds)
            .await?;
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection rejected by route rule",
        ));
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        return serve_hijacked_dns_stream_with_context(
            stream, outbounds, &metadata,
        )
        .await;
    }
    let destination = decision
        .destination(metadata.destination.as_ref().unwrap_or(&destination));
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })?
    };
    let connection_options = decision.connection_options();
    let remote = dialer
        .dial_tcp_with_options(&destination, &connection_options.network)
        .await?;
    let mut remote = apply_routed_tcp_options(remote, &connection_options)?;
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

const MAX_SNIFF_BYTES: usize = 64 * 1024;

pub type TcpInjectFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

/// State carried when one inbound hands an accepted TCP stream to another.
///
/// The Go implementation passes the same metadata object through the detour
/// chain. Keeping it here (instead of reducing the hand-off to a peer address)
/// preserves the outer authentication, original destination and sniff fields.
#[derive(Debug, Clone)]
pub struct TcpInboundContext {
    pub source: SocketAddr,
    pub metadata: Metadata,
}

impl TcpInboundContext {
    pub fn accepted(source: SocketAddr, inbound: impl Into<String>) -> Self {
        Self {
            source,
            metadata: Metadata {
                inbound: inbound.into(),
                source: Some(source.into()),
                network: Some(Network::Tcp),
                ..Metadata::default()
            },
        }
    }
}

pub(crate) async fn with_tcp_inbound_context<F>(
    context: TcpInboundContext,
    future: F,
) -> F::Output
where
    F: Future,
{
    TCP_INBOUND_CONTEXT.scope(context, future).await
}

/// Start target-protocol metadata from the outer inbound's state when this
/// connection arrived through a listener detour.
pub(crate) fn inherited_tcp_metadata(
    source: SocketAddr,
    inbound: &str,
) -> Metadata {
    let mut metadata = TCP_INBOUND_CONTEXT
        .try_with(|context| context.metadata.clone())
        .unwrap_or_default();
    metadata.inbound = inbound.to_owned();
    metadata.source = Some(source.into());
    metadata.network = Some(Network::Tcp);
    metadata
}

pub trait TcpInboundInjector: Send + Sync {
    fn inject<'a>(
        &'a self,
        stream: Stream,
        context: TcpInboundContext,
    ) -> TcpInjectFuture<'a>;
}

/// Resolve and enter the listener detour configured for the current inbound.
/// The caller remains responsible for writing any protocol-level success
/// response before handing `stream` to the returned injector.
pub(crate) fn prepare_tcp_inbound_detour(
    metadata: &mut Metadata,
    outbounds: &OutboundManager,
) -> io::Result<Option<Arc<dyn TcpInboundInjector>>> {
    let Some(detour) = outbounds.inbound_tcp_detour(&metadata.inbound) else {
        return Ok(None);
    };
    let target = detour.target;
    if metadata.last_inbound == target {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("inbound detour loop: {} -> {target}", metadata.inbound),
        ));
    }
    if !detour.target_exists {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("inbound detour not found: {target}"),
        ));
    }
    let injector = detour.injector.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("inbound detour is not TCP injectable: {target}"),
        )
    })?;
    metadata.last_inbound = std::mem::replace(&mut metadata.inbound, target);
    Ok(Some(injector))
}

pub(crate) fn reject_udp_inbound_detour(
    metadata: &Metadata,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let Some(detour) = outbounds.inbound_tcp_detour(&metadata.inbound) else {
        return Ok(());
    };
    let target = detour.target;
    if metadata.last_inbound == target {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("inbound detour loop: {target}"),
        ));
    }
    if !detour.target_exists {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("inbound detour not found: {target}"),
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("inbound detour is not UDP injectable: {target}"),
    ))
}

/// Execute a stream sniff route action and replay every inspected byte.  The
/// returned decision is the first terminal action selected after metadata has
/// been enriched with the detected protocol, domain, and client.
pub(crate) async fn sniff_and_route_stream<'a>(
    stream: Stream,
    metadata: &mut Metadata,
    router: &'a Router,
    outbounds: &OutboundManager,
) -> io::Result<(Stream, RouteDecision<'a>)> {
    sniff_and_route_stream_from(
        stream,
        metadata,
        router,
        outbounds,
        router.route_state(),
        None,
    )
    .await
}

pub(crate) async fn sniff_and_route_stream_from<'a>(
    mut stream: Stream,
    metadata: &mut Metadata,
    router: &'a Router,
    outbounds: &OutboundManager,
    mut route_state: RouteState,
    mut first_decision: Option<RouteDecision<'a>>,
) -> io::Result<(Stream, RouteDecision<'a>)> {
    restore_fake_ip_metadata(metadata, outbounds)?;
    loop {
        let decision = first_decision
            .take()
            .unwrap_or_else(|| router.route_next(metadata, &mut route_state));
        match decision.action().cloned() {
            Some(Action::Sniff(options)) => {
                if should_skip_sniff(metadata)
                    || !metadata.protocol.is_empty()
                    || options.stream_sniffers.is_empty()
                {
                    continue;
                }
                let deadline = tokio::time::Instant::from_std(
                    Instant::now() + options.timeout,
                );
                let mut inspected = Vec::new();
                while inspected.len() < MAX_SNIFF_BYTES {
                    let mut chunk = [0_u8; 8192];
                    let limit =
                        chunk.len().min(MAX_SNIFF_BYTES - inspected.len());
                    let size = match tokio::time::timeout_at(
                        deadline,
                        stream.read(&mut chunk[..limit]),
                    )
                    .await
                    {
                        Ok(result) => result?,
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
                stream = replay_stream(stream, inspected);
            }
            Some(Action::Resolve(options)) => {
                let destination = metadata
                    .destination
                    .as_ref()
                    .map(|value| decision.destination(value));
                resolve_metadata(
                    metadata,
                    destination.as_ref(),
                    &options,
                    outbounds,
                )
                .await?;
            }
            _ => return Ok((stream, decision)),
        }
    }
}

pub(crate) async fn sniff_and_route_packet<'a>(
    packet: &[u8],
    metadata: &mut Metadata,
    router: &'a Router,
    outbounds: &OutboundManager,
) -> io::Result<RouteDecision<'a>> {
    sniff_and_route_packet_with_state(
        packet,
        metadata,
        router,
        outbounds,
        &mut PacketSniffState::default(),
    )
    .await
}

/// Route a stateful UDP session while retaining every datagram consumed by a
/// multi-packet sniffer. This mirrors sing-box's packet-connection routing:
/// fragmented QUIC Initial packets are read until the action timeout, then all
/// inspected packets are replayed to the selected outbound in receive order.
pub(crate) async fn sniff_and_route_packet_session<'a, T, F>(
    first: T,
    receiver: &mut tokio::sync::mpsc::Receiver<T>,
    payload: F,
    metadata: &mut Metadata,
    router: &'a Router,
    outbounds: &OutboundManager,
) -> io::Result<(RouteDecision<'a>, VecDeque<T>)>
where
    F: for<'packet> Fn(&'packet T) -> &'packet [u8],
{
    reject_udp_inbound_detour(metadata, outbounds)?;
    restore_fake_ip_metadata(metadata, outbounds)?;
    const DEFAULT_SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
    const QUIC_ONLY: [PacketSniffer; 1] = [PacketSniffer::Quic];

    let mut packets = VecDeque::from([first]);
    let mut sniff_state = PacketSniffState::default();
    let mut route_state = router.route_state();
    loop {
        let decision = router.route_next(metadata, &mut route_state);
        match decision.action().cloned() {
            Some(Action::Sniff(options)) => {
                if should_skip_sniff(metadata)
                    || !metadata.protocol.is_empty()
                    || options.packet_sniffers.is_empty()
                {
                    continue;
                }
                let sniff_timeout = if options.timeout.is_zero() {
                    DEFAULT_SNIFF_TIMEOUT
                } else {
                    options.timeout
                };
                let mut packet_index = 0;
                let mut quic_continuation = false;
                loop {
                    let sniffers = if quic_continuation {
                        &QUIC_ONLY[..]
                    } else {
                        &options.packet_sniffers
                    };
                    match sniff_packet_with_state(
                        payload(&packets[packet_index]),
                        sniffers,
                        &mut sniff_state,
                    ) {
                        Ok(result) => {
                            metadata.protocol = result.protocol;
                            metadata.domain = result.domain;
                            metadata.client = result.client;
                            break;
                        }
                        Err(SniffError::Invalid(_)) => break,
                        Err(SniffError::NeedMoreData) => {
                            quic_continuation = true;
                            packet_index += 1;
                            if packet_index < packets.len() {
                                continue;
                            }
                            match tokio::time::timeout(
                                sniff_timeout,
                                receiver.recv(),
                            )
                            .await
                            {
                                Ok(Some(packet)) => packets.push_back(packet),
                                Ok(None) => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::ConnectionAborted,
                                        "UDP session closed while sniffing",
                                    ));
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            }
            Some(Action::Resolve(options)) => {
                let destination = metadata
                    .destination
                    .as_ref()
                    .map(|value| decision.destination(value));
                resolve_metadata(
                    metadata,
                    destination.as_ref(),
                    &options,
                    outbounds,
                )
                .await?;
            }
            _ => return Ok((decision, packets)),
        }
    }
}

async fn sniff_and_route_packet_with_state<'a>(
    packet: &[u8],
    metadata: &mut Metadata,
    router: &'a Router,
    outbounds: &OutboundManager,
    sniff_state: &mut PacketSniffState,
) -> io::Result<RouteDecision<'a>> {
    reject_udp_inbound_detour(metadata, outbounds)?;
    restore_fake_ip_metadata(metadata, outbounds)?;
    let mut route_state = router.route_state();
    loop {
        let decision = router.route_next(metadata, &mut route_state);
        match decision.action().cloned() {
            Some(Action::Sniff(options)) => {
                if !should_skip_sniff(metadata)
                    && metadata.protocol.is_empty()
                    && !options.packet_sniffers.is_empty()
                    && let Ok(result) = sniff_packet_with_state(
                        packet,
                        &options.packet_sniffers,
                        sniff_state,
                    )
                {
                    metadata.protocol = result.protocol;
                    metadata.domain = result.domain;
                    metadata.client = result.client;
                }
            }
            Some(Action::Resolve(options)) => {
                let destination = metadata
                    .destination
                    .as_ref()
                    .map(|value| decision.destination(value));
                resolve_metadata(
                    metadata,
                    destination.as_ref(),
                    &options,
                    outbounds,
                )
                .await?;
            }
            _ => return Ok(decision),
        }
    }
}

fn should_skip_sniff(metadata: &Metadata) -> bool {
    metadata.destination.as_ref().is_some_and(|address| {
        matches!(address.port(), 25 | 110 | 143 | 465 | 587 | 993 | 995)
    })
}

/// Apply the route-level FakeIP reverse lookup shared by every ingress path.
///
/// Upstream performs this in `Router.prepareMatchMetadata`, after a TCP
/// listener detour and before the first rule match.  Keeping the operation at
/// the common sniff/route boundary prevents protocol implementations such as
/// redirect, TProxy and Snell from silently bypassing FakeIP restoration.
pub(crate) fn restore_fake_ip_metadata(
    metadata: &mut Metadata,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    if metadata.fake_ip {
        return Ok(());
    }
    let Some(destination) = metadata.destination.clone() else {
        return Ok(());
    };
    let (destination, origin_destination) =
        socks::restore_fake_ip(destination, outbounds)?;
    let Some(origin_destination) = origin_destination else {
        return Ok(());
    };
    if metadata.process_origin_destination.is_none() {
        metadata.process_origin_destination =
            metadata.origin_destination.clone();
    }
    metadata.destination = Some(destination);
    metadata.origin_destination = Some(origin_destination);
    metadata.fake_ip = true;
    Ok(())
}

struct PacketSniffSession {
    updated_at: Instant,
    state: PacketSniffState,
}

/// Retains packet-sniffer state per UDP flow. Upstream stores QUIC CRYPTO
/// fragments in the packet connection metadata; datagram inbounds need an
/// equivalent flow-keyed store because every receive otherwise creates fresh
/// metadata.
pub(crate) struct PacketSniffSessions<K> {
    entries: HashMap<K, PacketSniffSession>,
    timeout: Duration,
}

impl<K> PacketSniffSessions<K>
where
    K: Clone + Eq + Hash,
{
    pub(crate) fn new(timeout: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            timeout,
        }
    }

    pub(crate) async fn route<'a>(
        &mut self,
        key: K,
        packet: &[u8],
        metadata: &mut Metadata,
        router: &'a Router,
        outbounds: &OutboundManager,
    ) -> io::Result<RouteDecision<'a>> {
        let now = Instant::now();
        self.entries.retain(|_, session| {
            now.duration_since(session.updated_at) <= self.timeout
        });
        let session = self.entries.entry(key.clone()).or_insert_with(|| {
            PacketSniffSession {
                updated_at: now,
                state: PacketSniffState::default(),
            }
        });
        session.updated_at = now;
        let decision = sniff_and_route_packet_with_state(
            packet,
            metadata,
            router,
            outbounds,
            &mut session.state,
        )
        .await?;
        if !session.state.is_pending() {
            self.entries.remove(&key);
        }
        Ok(decision)
    }
}

pub(crate) async fn resolve_metadata(
    metadata: &mut Metadata,
    destination: Option<&crate::common::network::SocksAddr>,
    options: &crate::route::ResolveOptions,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let Some(crate::common::network::SocksAddr::Domain { host, .. }) =
        destination
    else {
        return Ok(());
    };
    let lookup_options = LookupOptions {
        strategy: options.strategy,
        timeout: options.timeout,
        disable_cache: options.disable_cache,
        disable_optimistic_cache: options.disable_optimistic_cache,
        rewrite_ttl: options.rewrite_ttl,
        client_subnet: options.client_subnet,
        remove_client_subnet: false,
    };
    let dns = outbounds.dns();
    let lookup = async {
        if options.server.is_empty() {
            dns.lookup_with_context(host, lookup_options, metadata)
                .await
        } else {
            let resolver = dns.resolver(&options.server).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("DNS server not found: {}", options.server),
                )
            })?;
            resolver.lookup_with_options(host, lookup_options).await
        }
    };
    metadata.destination_addresses = match options.timeout {
        Some(timeout) => {
            tokio::time::timeout(timeout, lookup).await.map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "DNS lookup timed out")
            })??
        }
        None => lookup.await?,
    };
    Ok(())
}

pub(crate) async fn hijack_dns_packet_with_context(
    packet: &[u8],
    outbounds: &OutboundManager,
    metadata: &Metadata,
) -> io::Result<Vec<u8>> {
    let request = hickory_proto::op::Message::from_bytes(packet)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let dns = outbounds.dns();
    let response = dns
        .exchange_with_context(&request, LookupOptions::default(), metadata)
        .await?;
    let mut output = Vec::with_capacity(512);
    response
        .emit(&mut BinEncoder::new(&mut output))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(output)
}

pub(crate) async fn serve_hijacked_dns_stream_with_context(
    mut stream: Stream,
    outbounds: &OutboundManager,
    metadata: &Metadata,
) -> io::Result<()> {
    loop {
        let length = match stream.read_u16().await {
            Ok(length) => usize::from(length),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let mut request = vec![0_u8; length];
        stream.read_exact(&mut request).await?;
        let response =
            hijack_dns_packet_with_context(&request, outbounds, metadata)
                .await?;
        let length = u16::try_from(response.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "DNS response too large")
        })?;
        stream.write_u16(length).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, RecordType},
        serialize::binary::{BinDecodable, BinEncodable, BinEncoder},
    };
    use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
        sync::mpsc,
    };

    use super::{
        PacketDestinationNat, TcpInboundContext,
        hijack_dns_packet_with_context, inherited_tcp_metadata,
        prepare_tcp_inbound_detour, proxy_routed_tcp_with_origin,
        serve_hijacked_dns_stream_with_context, sniff_and_route_packet,
        sniff_and_route_packet_session, sniff_and_route_stream,
        with_tcp_inbound_context, wrap_packet_destination_nat,
    };
    use crate::{
        adapter::{PacketConnection, ProcessInfo, ProcessResolver, Stream},
        common::{
            network::{Network, SocksAddr},
            sniff::{
                PacketSniffState, PacketSniffer, SniffError,
                sniff_packet_with_state,
            },
        },
        inbound::http::HttpTcpInjector,
        option::{HttpMixedInboundOptions, Options, OutboundTlsOptions},
        outbound::OutboundManager,
        route::{Metadata, Router},
    };

    struct TransparentProcessResolver;

    struct RecordingPacketConnection {
        sent: Arc<std::sync::Mutex<Option<SocksAddr>>>,
        response_source: SocksAddr,
    }

    impl PacketConnection for RecordingPacketConnection {
        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            destination: &'a SocksAddr,
        ) -> crate::adapter::PacketFuture<'a, usize> {
            Box::pin(async move {
                *self.sent.lock().unwrap() = Some(destination.clone());
                Ok(data.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            data: &'a mut [u8],
        ) -> crate::adapter::PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(async move {
                data[..4].copy_from_slice(b"pong");
                Ok((4, self.response_source.clone()))
            })
        }
    }

    impl ProcessResolver for TransparentProcessResolver {
        fn lookup(
            &self,
            _network: Network,
            source: std::net::SocketAddr,
            destination: Option<std::net::SocketAddr>,
        ) -> Option<ProcessInfo> {
            assert_eq!(
                source,
                "127.0.0.1:50000".parse::<std::net::SocketAddr>().unwrap()
            );
            assert_eq!(
                destination,
                Some("127.0.0.1:1080".parse::<std::net::SocketAddr>().unwrap())
            );
            Some(ProcessInfo {
                process_name: "transparent-client".into(),
                ..ProcessInfo::default()
            })
        }
    }

    #[test]
    fn packet_destination_nat_only_overrides_the_route_origin() {
        let original = SocksAddr::new("192.0.2.1", 53);
        let routed = SocksAddr::new("127.0.0.1", 5353);
        let mut nat =
            PacketDestinationNat::new(original.clone(), routed.clone());

        assert_eq!(
            nat.translate_destination(original.clone(), original.clone()),
            routed
        );
        let unrelated = SocksAddr::new("198.51.100.2", 5353);
        assert_eq!(
            nat.translate_destination(unrelated.clone(), unrelated.clone()),
            unrelated
        );
        assert_eq!(
            nat.translate_source(SocksAddr::new("127.0.0.1", 5353)),
            original
        );
        assert_eq!(
            nat.translate_source(SocksAddr::new("198.51.100.2", 5353)),
            SocksAddr::new("198.51.100.2", 5353)
        );
    }

    #[test]
    fn packet_destination_nat_scopes_fake_ip_to_session_origin() {
        let fake = SocksAddr::new("198.18.0.1", 53);
        let restored = SocksAddr::new("dns.example", 53);
        let mut nat =
            PacketDestinationNat::new(restored.clone(), restored.clone());

        assert_eq!(
            nat.translate_destination(restored.clone(), fake.clone()),
            restored
        );
        assert_eq!(
            nat.translate_destination(
                SocksAddr::new("dns.example", 5353),
                SocksAddr::new("198.18.0.1", 5353),
            ),
            SocksAddr::new("dns.example", 5353)
        );

        let other_fake = SocksAddr::new("198.18.0.2", 5353);
        assert_eq!(
            nat.translate_destination(
                SocksAddr::new("other.example", 5353),
                other_fake.clone(),
            ),
            other_fake
        );
        assert_eq!(
            nat.translate_source(SocksAddr::new("dns.example", 53)),
            fake
        );
        assert_eq!(
            nat.translate_source(SocksAddr::new("dns.example", 5353)),
            SocksAddr::new("198.18.0.1", 5353)
        );
        assert_eq!(nat.translate_source(other_fake.clone()), other_fake);
    }

    #[tokio::test]
    async fn packet_destination_nat_connection_translates_both_directions() {
        let original = SocksAddr::new("192.0.2.1", 53);
        let routed = SocksAddr::new("127.0.0.1", 5353);
        let sent = Arc::new(std::sync::Mutex::new(None));
        let connection = wrap_packet_destination_nat(
            Box::new(RecordingPacketConnection {
                sent: sent.clone(),
                response_source: routed.clone(),
            }),
            original.clone(),
            routed.clone(),
        );

        connection.send_to(b"ping", &original).await.unwrap();
        assert_eq!(*sent.lock().unwrap(), Some(routed));
        let mut response = [0_u8; 8];
        let (size, source) = connection.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"pong");
        assert_eq!(source, original);
    }

    #[tokio::test]
    async fn common_tcp_and_udp_route_boundaries_restore_fake_ip() {
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
        let fake_destination =
            SocksAddr::Ip(std::net::SocketAddr::new(fake_address, 443));
        let listener_destination = SocksAddr::new("127.0.0.1", 1080);
        let mut router = Router::from_json(
            &[json!({
                "domain":"echo.test",
                "process_name":"transparent-client",
                "outbound":"direct"
            })],
            "block",
        )
        .unwrap();
        router.configure_process_resolver(Some(Arc::new(
            TransparentProcessResolver,
        )));

        let metadata = |network| Metadata {
            inbound: "transparent".into(),
            source: Some(SocksAddr::new("127.0.0.1", 50000)),
            destination: Some(fake_destination.clone()),
            origin_destination: Some(listener_destination.clone()),
            network: Some(network),
            ..Metadata::default()
        };

        let mut udp_metadata = metadata(Network::Udp);
        let udp_decision = sniff_and_route_packet(
            b"payload",
            &mut udp_metadata,
            &router,
            &outbounds,
        )
        .await
        .unwrap();
        assert_eq!(udp_decision.outbound(), Some("direct"));
        assert_eq!(
            udp_metadata.destination,
            Some(SocksAddr::new("echo.test", 443))
        );
        assert_eq!(
            udp_metadata.origin_destination,
            Some(fake_destination.clone())
        );
        assert!(udp_metadata.fake_ip);

        let (client, _server) = tokio::io::duplex(64);
        let mut tcp_metadata = metadata(Network::Tcp);
        let (_, tcp_decision) = sniff_and_route_stream(
            Box::new(client),
            &mut tcp_metadata,
            &router,
            &outbounds,
        )
        .await
        .unwrap();
        assert_eq!(tcp_decision.outbound(), Some("direct"));
        assert_eq!(
            tcp_metadata.destination,
            Some(SocksAddr::new("echo.test", 443))
        );
        assert_eq!(tcp_metadata.origin_destination, Some(fake_destination));
        assert!(tcp_metadata.fake_ip);
    }

    #[tokio::test]
    async fn common_tcp_proxy_dials_restored_fake_ip_destination() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let options: Options = serde_json::from_value(json!({
            "dns": {"servers": [
                {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"},
                {"type":"hosts","tag":"real","predefined":{"proxy.test":"127.0.0.1"}}
            ], "final":"real"},
            "outbounds": [
                {"type":"direct","tag":"direct","domain_resolver":"real"},
                {"type":"block","tag":"block"}
            ]
        }))
        .unwrap();
        let outbounds =
            OutboundManager::from_options(&options, "block").unwrap();
        let fake_address = outbounds
            .dns()
            .resolver("fake")
            .unwrap()
            .lookup("proxy.test", crate::option::DomainStrategy::Ipv4Only)
            .await
            .unwrap()[0];
        let router = Router::from_json(
            &[json!({"domain":"proxy.test", "outbound":"direct"})],
            "block",
        )
        .unwrap();
        let (server, mut client) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(async move {
            proxy_routed_tcp_with_origin(
                Box::new(server),
                "127.0.0.1:50000".parse().unwrap(),
                "userspace",
                "",
                SocksAddr::Ip(std::net::SocketAddr::new(
                    fake_address,
                    target_port,
                )),
                None,
                false,
                &router,
                &outbounds,
            )
            .await
        });
        client.write_all(b"fake").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"fake");
        drop(client);
        proxy.await.unwrap().unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn injected_tcp_context_preserves_outer_metadata() {
        let source = "127.0.0.1:12345".parse().unwrap();
        let origin = SocksAddr::new("original.example", 443);
        let context = TcpInboundContext {
            source,
            metadata: Metadata {
                inbound: "inner".into(),
                last_inbound: "outer".into(),
                source: Some(source.into()),
                origin_destination: Some(origin.clone()),
                client: "outer-client".into(),
                process_name: "browser".into(),
                ..Metadata::default()
            },
        };
        let metadata = with_tcp_inbound_context(context, async {
            inherited_tcp_metadata(source, "inner")
        })
        .await;
        assert_eq!(metadata.inbound, "inner");
        assert_eq!(metadata.last_inbound, "outer");
        assert_eq!(metadata.origin_destination, Some(origin));
        assert_eq!(metadata.client, "outer-client");
        assert_eq!(metadata.process_name, "browser");
        assert_eq!(metadata.network, Some(Network::Tcp));
    }

    #[tokio::test]
    async fn udp_rejects_a_tcp_only_inbound_detour() {
        let options: Options = serde_json::from_value(json!({
            "outbounds":[{"type":"direct","tag":"direct"}]
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&options, "direct").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "direct").unwrap());
        let injector = Arc::new(
            HttpTcpInjector::new(
                "inner",
                HttpMixedInboundOptions::default(),
                router.clone(),
                outbounds.clone(),
            )
            .unwrap(),
        );
        outbounds.register_inbound_tcp_detour(
            "outer",
            "inner",
            true,
            Some(injector.clone()),
        );
        let mut metadata = Metadata {
            inbound: "outer".into(),
            network: Some(Network::Udp),
            destination: Some(SocksAddr::new("example.com", 53)),
            ..Metadata::default()
        };
        let error = match sniff_and_route_packet(
            b"not-a-dns-packet",
            &mut metadata,
            &router,
            &outbounds,
        )
        .await
        {
            Ok(_) => panic!("HTTP inbound accepted UDP injection"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "inbound detour is not UDP injectable: inner"
        );

        outbounds.register_inbound_tcp_detour(
            "missing-source",
            "missing",
            false,
            None,
        );
        let mut missing = Metadata {
            inbound: "missing-source".into(),
            ..Metadata::default()
        };
        let error = match prepare_tcp_inbound_detour(&mut missing, &outbounds) {
            Ok(_) => panic!("missing inbound detour was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "inbound detour not found: missing");

        outbounds.register_inbound_tcp_detour(
            "non-injectable-source",
            "direct",
            true,
            None,
        );
        let mut non_injectable = Metadata {
            inbound: "non-injectable-source".into(),
            ..Metadata::default()
        };
        let error =
            match prepare_tcp_inbound_detour(&mut non_injectable, &outbounds) {
                Ok(_) => panic!("non-injectable inbound detour was accepted"),
                Err(error) => error,
            };
        assert_eq!(
            error.to_string(),
            "inbound detour is not TCP injectable: direct"
        );

        outbounds.register_inbound_tcp_detour(
            "loop-a",
            "loop-b",
            true,
            Some(injector),
        );
        let mut looped = Metadata {
            inbound: "loop-a".into(),
            last_inbound: "loop-b".into(),
            ..Metadata::default()
        };
        let error = match prepare_tcp_inbound_detour(&mut looped, &outbounds) {
            Ok(_) => panic!("inbound detour loop was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "inbound detour loop: loop-a -> loop-b");
    }

    #[tokio::test]
    async fn sniff_enriches_metadata_reroutes_and_replays_payload() {
        let router = Router::from_json(
            &[
                json!({"action": "sniff", "sniffer": "http"}),
                json!({
                    "protocol": "http",
                    "domain_suffix": "example.com",
                    "outbound": "sniffed"
                }),
            ],
            "fallback",
        )
        .unwrap();
        let outbounds =
            OutboundManager::from_options(&Options::default(), "").unwrap();
        let mut metadata = Metadata {
            destination: Some(SocksAddr::new("192.0.2.1", 80)),
            network: Some(Network::Tcp),
            ..Metadata::default()
        };
        let request = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\nbody";
        let (server, mut client) = tokio::io::duplex(1024);
        let write = tokio::spawn(async move {
            client.write_all(request).await.unwrap();
        });
        let (mut server, decision) = sniff_and_route_stream(
            Box::new(server) as Stream,
            &mut metadata,
            &router,
            &outbounds,
        )
        .await
        .unwrap();
        assert_eq!(metadata.protocol, "http");
        assert_eq!(metadata.domain, "www.example.com");
        assert_eq!(decision.outbound(), Some("sniffed"));
        let mut replayed = vec![0_u8; request.len()];
        server.read_exact(&mut replayed).await.unwrap();
        assert_eq!(replayed, request);
        write.await.unwrap();
    }

    #[tokio::test]
    async fn sniff_failure_uses_fallback_and_replays_payload() {
        let router = Router::from_json(
            &[json!({
                "action": "sniff",
                "sniffer": "http",
                "timeout": "1s"
            })],
            "fallback",
        )
        .unwrap();
        let outbounds =
            OutboundManager::from_options(&Options::default(), "").unwrap();
        let mut metadata = Metadata {
            destination: Some(SocksAddr::new("192.0.2.1", 80)),
            network: Some(Network::Tcp),
            ..Metadata::default()
        };
        let payload = b"not-http";
        let (server, mut client) = tokio::io::duplex(1024);
        client.write_all(payload).await.unwrap();
        let (mut server, decision) = sniff_and_route_stream(
            Box::new(server) as Stream,
            &mut metadata,
            &router,
            &outbounds,
        )
        .await
        .unwrap();
        assert!(metadata.protocol.is_empty());
        assert_eq!(decision.outbound(), Some("fallback"));
        let mut replayed = vec![0_u8; payload.len()];
        server.read_exact(&mut replayed).await.unwrap();
        assert_eq!(replayed, payload);
    }

    #[tokio::test]
    async fn packet_only_sniff_action_does_not_read_a_tcp_stream() {
        let router = Router::from_json(
            &[json!({"action": "sniff", "sniffer": "quic"})],
            "fallback",
        )
        .unwrap();
        let outbounds =
            OutboundManager::from_options(&Options::default(), "").unwrap();
        let mut metadata = Metadata {
            destination: Some(SocksAddr::new("192.0.2.1", 443)),
            network: Some(Network::Tcp),
            ..Metadata::default()
        };
        let (server, _client) = tokio::io::duplex(64);
        let (_, decision) = tokio::time::timeout(
            Duration::from_millis(50),
            sniff_and_route_stream(
                Box::new(server) as Stream,
                &mut metadata,
                &router,
                &outbounds,
            ),
        )
        .await
        .expect("packet-only sniff action read from the TCP stream")
        .unwrap();
        assert!(metadata.protocol.is_empty());
        assert_eq!(decision.outbound(), Some("fallback"));
    }

    #[tokio::test]
    async fn packet_sniff_skips_server_first_destination_ports() {
        let router = Router::from_json(
            &[
                json!({"action": "sniff", "sniffer": "dns"}),
                json!({"protocol": "dns", "outbound": "sniffed"}),
            ],
            "fallback",
        )
        .unwrap();
        let outbounds =
            OutboundManager::from_options(&Options::default(), "").unwrap();
        let mut metadata = Metadata {
            destination: Some(SocksAddr::new("192.0.2.1", 25)),
            network: Some(Network::Udp),
            ..Metadata::default()
        };
        let query = hex::decode(
            "740701000001000000000000012a06676f6f676c6503636f6d0000010001",
        )
        .unwrap();
        let decision =
            sniff_and_route_packet(&query, &mut metadata, &router, &outbounds)
                .await
                .unwrap();
        assert!(metadata.protocol.is_empty());
        assert_eq!(decision.outbound(), Some("fallback"));
    }

    #[tokio::test]
    async fn packet_sniff_reroutes_dns_without_changing_destination() {
        let router = Router::from_json(
            &[
                json!({"action": "sniff", "sniffer": "dns"}),
                json!({"protocol": "dns", "outbound": "dns-out"}),
            ],
            "fallback",
        )
        .unwrap();
        let outbounds =
            OutboundManager::from_options(&Options::default(), "").unwrap();
        let destination = SocksAddr::new("192.0.2.53", 53);
        let mut metadata = Metadata {
            destination: Some(destination.clone()),
            network: Some(Network::Udp),
            ..Metadata::default()
        };
        let query = hex::decode(
            "740701000001000000000000012a06676f6f676c6503636f6d0000010001",
        )
        .unwrap();
        let decision =
            sniff_and_route_packet(&query, &mut metadata, &router, &outbounds)
                .await
                .unwrap();
        assert_eq!(metadata.protocol, "dns");
        assert_eq!(metadata.destination, Some(destination));
        assert_eq!(decision.outbound(), Some("dns-out"));
    }

    #[tokio::test]
    async fn packet_session_sniff_buffers_fragmented_quic_in_order() {
        let capture = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut tls = crate::common::tls::build_client_config(
            "buffered-quic.example",
            &OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        Arc::make_mut(&mut tls.config).alpn_protocols = (0..96)
            .map(|index| {
                format!("h3-buffer-{index:03}-{}", "x".repeat(32)).into_bytes()
            })
            .collect();
        let crypto = QuicClientConfig::try_from(tls.config).unwrap();
        let mut endpoint =
            Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));
        let connecting = endpoint
            .connect(capture.local_addr().unwrap(), "buffered-quic.example")
            .unwrap();
        let attempt = tokio::spawn(async move {
            let _ = connecting.await;
        });

        let mut scratch = vec![0_u8; 65_535];
        let mut captured = Vec::new();
        let mut sniff_state = PacketSniffState::default();
        loop {
            let size = tokio::time::timeout(
                Duration::from_secs(1),
                capture.recv(&mut scratch),
            )
            .await
            .unwrap()
            .unwrap();
            captured.push(scratch[..size].to_vec());
            match sniff_packet_with_state(
                captured.last().unwrap(),
                &[PacketSniffer::Quic],
                &mut sniff_state,
            ) {
                Ok(_) => break,
                Err(SniffError::NeedMoreData) => {}
                Err(error) => panic!("unexpected QUIC sniff error: {error}"),
            }
        }
        assert!(
            captured.len() > 1,
            "ClientHello unexpectedly fit one packet"
        );

        let router = Router::from_json(
            &[
                json!({
                    "action": "sniff",
                    "sniffer": "quic",
                    "timeout": "1s"
                }),
                json!({
                    "protocol": "quic",
                    "domain": "buffered-quic.example",
                    "outbound": "sniffed"
                }),
            ],
            "fallback",
        )
        .unwrap();
        let outbounds =
            OutboundManager::from_options(&Options::default(), "").unwrap();
        let mut metadata = Metadata {
            destination: Some(SocksAddr::new("192.0.2.1", 443)),
            network: Some(Network::Udp),
            ..Metadata::default()
        };
        let (sender, mut receiver) = mpsc::channel(captured.len());
        for packet in captured.iter().skip(1).cloned() {
            sender.send(packet).await.unwrap();
        }
        let (decision, buffered) = sniff_and_route_packet_session(
            captured[0].clone(),
            &mut receiver,
            |packet: &Vec<u8>| packet.as_slice(),
            &mut metadata,
            &router,
            &outbounds,
        )
        .await
        .unwrap();
        assert_eq!(metadata.protocol, "quic");
        assert_eq!(metadata.domain, "buffered-quic.example");
        assert_eq!(decision.outbound(), Some("sniffed"));
        assert_eq!(buffered.into_iter().collect::<Vec<_>>(), captured);

        endpoint.close(0_u32.into(), b"");
        attempt.abort();
    }

    #[tokio::test]
    async fn resolve_action_populates_addresses_for_following_cidr_rule() {
        let options: Options = serde_json::from_value(json!({
            "dns": {
                "servers": [{
                    "type": "hosts",
                    "tag": "route-dns",
                    "predefined": {"resolve.example": "203.0.113.7"}
                }]
            }
        }))
        .unwrap();
        let outbounds = OutboundManager::from_options(&options, "").unwrap();
        let router = Router::from_json(
            &[
                json!({
                    "domain": "resolve.example",
                    "action": "resolve",
                    "server": "route-dns",
                    "strategy": "ipv4_only",
                    "timeout": "1s"
                }),
                json!({
                    "ip_cidr": "203.0.113.0/24",
                    "outbound": "resolved"
                }),
            ],
            "fallback",
        )
        .unwrap();
        let mut metadata = Metadata {
            destination: Some(SocksAddr::new("resolve.example", 443)),
            network: Some(Network::Tcp),
            ..Metadata::default()
        };
        let (server, _client) = tokio::io::duplex(64);
        let (_server, decision) = sniff_and_route_stream(
            Box::new(server) as Stream,
            &mut metadata,
            &router,
            &outbounds,
        )
        .await
        .unwrap();
        assert_eq!(
            metadata.destination_addresses,
            ["203.0.113.7".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(decision.outbound(), Some("resolved"));
        assert_eq!(metadata.destination.unwrap().host(), "resolve.example");
    }

    #[tokio::test]
    async fn hijack_dns_answers_udp_and_length_framed_tcp_queries() {
        let options: Options = serde_json::from_value(json!({
            "dns": {
                "servers": [
                    {
                        "type": "hosts",
                        "tag": "fallback",
                        "predefined": {"dns.example": "192.0.2.44"}
                    },
                    {
                        "type": "hosts",
                        "tag": "office",
                        "predefined": {"dns.example": "192.0.2.77"}
                    }
                ],
                "rules": [{"inbound":"office-in","server":"office"}],
                "final":"fallback"
            }
        }))
        .unwrap();
        let outbounds = OutboundManager::from_options(&options, "").unwrap();
        let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("dns.example.").unwrap(),
            RecordType::A,
        ));
        let mut wire = Vec::new();
        query.emit(&mut BinEncoder::new(&mut wire)).unwrap();

        let metadata = Metadata {
            inbound: "office-in".into(),
            network: Some(Network::Udp),
            ..Metadata::default()
        };
        let response =
            hijack_dns_packet_with_context(&wire, &outbounds, &metadata)
                .await
                .unwrap();
        let response = Message::from_bytes(&response).unwrap();
        assert_eq!(response.id, 0x1234);
        assert!(matches!(
            &response.answers[0].data,
            RData::A(address) if address.0.to_string() == "192.0.2.77"
        ));

        let (server, mut client) = tokio::io::duplex(2048);
        let task = tokio::spawn(async move {
            serve_hijacked_dns_stream_with_context(
                Box::new(server),
                &outbounds,
                &metadata,
            )
            .await
        });
        client.write_u16(wire.len() as u16).await.unwrap();
        client.write_all(&wire).await.unwrap();
        let length = client.read_u16().await.unwrap();
        let mut framed_response = vec![0_u8; usize::from(length)];
        client.read_exact(&mut framed_response).await.unwrap();
        let framed_response = Message::from_bytes(&framed_response).unwrap();
        assert_eq!(framed_response.id, 0x1234);
        assert!(matches!(
            &framed_response.answers[0].data,
            RData::A(address) if address.0.to_string() == "192.0.2.77"
        ));
        drop(client);
        task.await.unwrap().unwrap();
    }
}
