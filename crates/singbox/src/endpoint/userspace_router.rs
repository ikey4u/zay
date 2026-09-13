//! Inbound flow routing for IP-medium userspace endpoints.
//!
//! smoltcp has no gVisor-style transport forwarder. Before an authenticated
//! tunnel packet is injected, this adapter installs an AnyIP listener for the
//! original destination. Accepted TCP streams and UDP NAT sessions then enter
//! the same sing-box router used by ordinary inbounds.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, RwLock, Weak,
        atomic::{
            AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering,
        },
    },
    time::{Duration, Instant},
};

use n0_watcher::Watcher as _;
use tokio::{
    sync::{Mutex, Notify, Semaphore, mpsc},
    time::MissedTickBehavior,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::PacketConnection,
    common::{
        network::{Network, SocksAddr},
        network_monitor::DirectInterfaceClassifier,
        udp_nat::{UdpNatFilter, UdpNatFilterSession},
    },
    inbound::{
        PacketDestinationNat, PacketSniffSessions,
        hijack_dns_packet_with_context, proxy_routed_tcp_with_origin,
        resolve_metadata, serve_hijacked_dns_stream_with_context,
    },
    option::UdpNatBehavior,
    outbound::OutboundManager,
    route::{Action, Metadata, Router},
};

use super::flow_dispatch::FlowDispatcher;
use super::tokio_smoltcp::{Net, TcpListener, UdpSocket as SmoltcpUdpSocket};

const MAX_PACKET_SIZE: usize = 65_535;
const ICMP_FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);
const ICMP_FRAGMENT_MAX_ENTRIES: usize = 256;
const ICMP_FRAGMENT_MAX_BYTES: usize = 8 * 1024 * 1024;
static NEXT_ICMP_IPV4_IDENTIFICATION: AtomicU16 = AtomicU16::new(1);
static NEXT_ICMP_IPV6_IDENTIFICATION: AtomicU32 = AtomicU32::new(1);
static NEXT_TCP_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
type UdpListenerFuture<'a> = Pin<
    Box<
        dyn Future<Output = io::Result<Option<Arc<SmoltcpUdpSocket>>>>
            + Send
            + 'a,
    >,
>;

#[derive(Clone)]
pub(crate) struct EndpointFlowContext {
    pub(crate) tag: String,
    pub(crate) router: Arc<Router>,
    pub(crate) outbounds: Arc<OutboundManager>,
    pub(crate) udp_timeout: Duration,
    pub(crate) udp_mapping: UdpNatBehavior,
    pub(crate) udp_filtering: UdpNatBehavior,
    pub(crate) udp_nat_max: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportPacket {
    Tcp {
        destination: SocketAddr,
        initial_syn: bool,
    },
    Udp {
        destination: SocketAddr,
    },
    IcmpEcho {
        source: IpAddr,
        destination: IpAddr,
        hop_limit: u8,
        transport_offset: usize,
    },
    Other,
}

pub(crate) struct UserspaceEndpointRouter {
    net: Weak<Net>,
    egress: mpsc::Sender<Vec<u8>>,
    flow_dispatcher: Arc<FlowDispatcher>,
    tag: String,
    local_networks: Vec<ipnet::IpNet>,
    local_prefix_match: bool,
    dns_hijack_addresses: HashSet<IpAddr>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: Duration,
    udp_mapping: UdpNatBehavior,
    udp_nat_max: usize,
    udp_filter: UdpNatFilter,
    direct_interfaces: RwLock<DirectInterfaceClassifier>,
    direct_interfaces_ready: AtomicBool,
    direct_interfaces_notify: Notify,
    effective_mtu: AtomicUsize,
    icmp_slots: Arc<Semaphore>,
    icmp_fragments: Mutex<IcmpFragmentCache>,
    cancellation: CancellationToken,
    tcp_connections: Arc<Mutex<HashMap<u64, CancellationToken>>>,
    tcp_listeners: Mutex<HashMap<SocketAddr, TcpListenerEntry>>,
    udp_listeners: Mutex<HashMap<SocketAddr, UdpListenerEntry>>,
    udp_state: Mutex<UdpState>,
}

impl UserspaceEndpointRouter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        net: &Arc<Net>,
        egress: mpsc::Sender<Vec<u8>>,
        tag: impl Into<String>,
        local_networks: Vec<ipnet::IpNet>,
        local_prefix_match: bool,
        dns_hijack_addresses: Vec<IpAddr>,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        udp_timeout: Duration,
        udp_mapping: UdpNatBehavior,
        udp_filtering: UdpNatBehavior,
        udp_nat_max: u32,
        effective_mtu: usize,
    ) -> Arc<Self> {
        net.set_any_ip(true);
        let tag = tag.into();
        let cancellation = CancellationToken::new();
        let writeback =
            spawn_flow_writeback(egress.clone(), cancellation.clone());
        let flow_dispatcher = FlowDispatcher::new(
            tag.clone(),
            router.clone(),
            outbounds.clone(),
            writeback,
            udp_timeout,
        );
        let udp_nat_max = crate::common::udp_nat::udp_nat_max(udp_nat_max);
        let this = Arc::new(Self {
            net: Arc::downgrade(net),
            egress,
            flow_dispatcher,
            tag,
            local_networks,
            local_prefix_match,
            dns_hijack_addresses: dns_hijack_addresses.into_iter().collect(),
            router,
            outbounds,
            udp_timeout,
            udp_mapping,
            udp_nat_max,
            udp_filter: UdpNatFilter::new(
                udp_mapping,
                udp_filtering,
                udp_nat_max,
            ),
            direct_interfaces: RwLock::new(DirectInterfaceClassifier::default()),
            direct_interfaces_ready: AtomicBool::new(false),
            direct_interfaces_notify: Notify::new(),
            effective_mtu: AtomicUsize::new(effective_mtu),
            icmp_slots: Arc::new(Semaphore::new(1024)),
            icmp_fragments: Mutex::new(IcmpFragmentCache::default()),
            cancellation,
            tcp_connections: Arc::new(Mutex::new(HashMap::new())),
            tcp_listeners: Mutex::new(HashMap::new()),
            udp_listeners: Mutex::new(HashMap::new()),
            udp_state: Mutex::new(UdpState::new(udp_timeout)),
        });
        Self::spawn_expiry(&this);
        Self::spawn_network_monitor(&this);
        this
    }

    pub(crate) async fn prepare_packet(
        self: &Arc<Self>,
        packet: &[u8],
    ) -> io::Result<bool> {
        let local_destination = packet_destination_address(packet)
            .is_some_and(|address| self.is_local_address(address));
        if !local_destination && self.flow_dispatcher.dispatch(packet).await? {
            return Ok(false);
        }
        let reassembled = match self.icmp_fragments.lock().await.push(packet)? {
            FragmentDisposition::NotFragmented => None,
            FragmentDisposition::Pending | FragmentDisposition::Drop => {
                return Ok(false);
            }
            FragmentDisposition::Complete(packet) => Some(packet),
        };
        let packet = reassembled.as_deref().unwrap_or(packet);
        match parse_transport_packet(packet)? {
            TransportPacket::Tcp {
                destination,
                initial_syn: true,
            } => {
                self.ensure_tcp_listener(destination).await?;
                Ok(true)
            }
            TransportPacket::Udp { destination } => {
                self.ensure_udp_listener(destination).await?;
                Ok(true)
            }
            TransportPacket::IcmpEcho {
                source,
                destination,
                hop_limit,
                transport_offset,
            } => {
                let Ok(slot) = self.icmp_slots.clone().try_acquire_owned()
                else {
                    return Ok(false);
                };
                let packet = packet.to_vec();
                let this = self.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    let cancellation = this.cancellation.clone();
                    tokio::select! {
                        _ = cancellation.cancelled() => {}
                        _ = this.route_icmp(source, destination, hop_limit, transport_offset, packet) => {}
                    }
                });
                // Never inject an echo request into smoltcp: with AnyIP it
                // would synthesize a local reply and bypass route policy.
                Ok(false)
            }
            TransportPacket::Tcp { .. } | TransportPacket::Other => {
                Ok(reassembled.is_none())
            }
        }
    }

    async fn route_icmp(
        self: &Arc<Self>,
        source: IpAddr,
        original_destination: IpAddr,
        hop_limit: u8,
        transport_offset: usize,
        original_packet: Vec<u8>,
    ) {
        let Some(message) = original_packet.get(transport_offset..) else {
            return;
        };
        let original = SocketAddr::new(original_destination, 0);
        let (local_destination, local_origin) =
            self.translate_local_destination(original);
        let (destination, fake_origin) =
            match crate::inbound::socks::restore_fake_ip(
                SocksAddr::from(local_destination),
                &self.outbounds,
            ) {
                Ok(result) => result,
                Err(_) => return,
            };
        let fake_ip = fake_origin.is_some();
        let origin_destination =
            fake_origin.or(local_origin.map(SocksAddr::from));
        let mut metadata = Metadata {
            inbound: self.tag.clone(),
            source: Some(SocksAddr::from(SocketAddr::new(source, 0))),
            destination: Some(destination.clone()),
            origin_destination,
            fake_ip,
            network: Some(Network::Icmp),
            ..Metadata::default()
        };
        let mut route_state = self.router.route_state();
        let decision = loop {
            let decision = self
                .router
                .route_pre_match_next(&metadata, &mut route_state);
            match decision.action().cloned() {
                Some(Action::Sniff(_)) => continue,
                Some(Action::Resolve(options)) => {
                    let routed = metadata
                        .destination
                        .as_ref()
                        .map(|value| decision.destination(value));
                    if resolve_metadata(
                        &mut metadata,
                        routed.as_ref(),
                        &options,
                        &self.outbounds,
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                }
                Some(Action::Bypass { outbound, .. })
                    if outbound.is_empty() =>
                {
                    return;
                }
                Some(Action::Reject { .. } | Action::HijackDns) => return,
                _ => break decision,
            }
        };
        let routed_destination = decision
            .destination(metadata.destination.as_ref().unwrap_or(&destination));
        let connection_options = decision.connection_options();
        let dialer = if matches!(decision.action(), Some(Action::Direct)) {
            self.outbounds.direct()
        } else if let Some(dialer) = self.outbounds.select(decision.outbound())
        {
            dialer
        } else {
            return;
        };
        // Go's pre-match path only accepts FlowOutbound implementations.
        // A protocol dialer must not become an ICMP route merely because it
        // happens to expose a similarly shaped helper.
        if dialer.icmp_flow_addresses().is_none() {
            return;
        }
        let Ok(response) = dialer
            .exchange_icmp_with_options(
                message,
                source,
                hop_limit,
                &routed_destination,
                &connection_options.network,
            )
            .await
        else {
            return;
        };
        // Transparent endpoint semantics require the response to retain the
        // address the tunnel peer originally contacted, even after FakeIP,
        // local-address, DNS, or route destination translation.
        let response_source =
            icmp_response_source(original_destination, &response);
        let Ok(response_packet) = build_icmp_response_packet(
            response_source,
            source,
            response.hop_limit,
            &response.packet,
        ) else {
            return;
        };
        let identification =
            NEXT_ICMP_IPV4_IDENTIFICATION.fetch_add(1, Ordering::Relaxed);
        let ipv6_identification =
            NEXT_ICMP_IPV6_IDENTIFICATION.fetch_add(1, Ordering::Relaxed);
        let Ok(packets) = prepare_icmp_egress(
            response_packet,
            self.effective_mtu.load(Ordering::Acquire),
            identification,
            ipv6_identification,
        ) else {
            return;
        };
        for packet in packets {
            if self.egress.send(packet).await.is_err() {
                break;
            }
        }
    }

    pub(crate) fn set_effective_mtu(&self, mtu: usize) {
        self.effective_mtu.store(mtu, Ordering::Release);
    }

    async fn ensure_tcp_listener(
        self: &Arc<Self>,
        destination: SocketAddr,
    ) -> io::Result<()> {
        let mut listeners = self.tcp_listeners.lock().await;
        if let Some(listener) = listeners.get_mut(&destination) {
            listener.updated_at = Instant::now();
            return Ok(());
        }
        evict_oldest_tcp_listener(&mut listeners, self.udp_nat_max);
        let net = self.net.upgrade().ok_or_else(endpoint_stopped)?;
        let listener = net.tcp_bind(destination).await.map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "bind userspace TCP forwarder for {destination}: {error}"
                ),
            )
        })?;
        let marker = Arc::new(());
        let listener_cancellation = self.cancellation.child_token();
        listeners.insert(
            destination,
            TcpListenerEntry {
                marker: marker.clone(),
                cancellation: listener_cancellation.clone(),
                updated_at: Instant::now(),
            },
        );
        drop(listeners);

        let weak = Arc::downgrade(self);
        let connection_cancellation = self.cancellation.clone();
        let tag = self.tag.clone();
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        let tcp_connections = self.tcp_connections.clone();
        let (route_destination, origin_destination) =
            self.translate_local_destination(destination);
        let hijack_dns = self.dns_hijack_addresses.contains(&destination.ip());
        tokio::spawn(async move {
            tcp_accept_loop(
                listener,
                route_destination,
                origin_destination,
                hijack_dns,
                tag,
                router,
                outbounds,
                listener_cancellation,
                connection_cancellation,
                tcp_connections,
            )
            .await;
            if let Some(this) = weak.upgrade() {
                let mut listeners = this.tcp_listeners.lock().await;
                if listeners
                    .get(&destination)
                    .is_some_and(|active| Arc::ptr_eq(&active.marker, &marker))
                {
                    listeners.remove(&destination);
                }
            }
        });
        Ok(())
    }

    fn ensure_udp_listener(
        self: &Arc<Self>,
        destination: SocketAddr,
    ) -> UdpListenerFuture<'_> {
        Box::pin(async move {
            let mut listeners = self.udp_listeners.lock().await;
            if let Some(listener) = listeners.get_mut(&destination) {
                listener.updated_at = Instant::now();
                return Ok(Some(listener.socket.clone()));
            }
            evict_oldest_udp_listener(&mut listeners, self.udp_nat_max);
            let net = self.net.upgrade().ok_or_else(endpoint_stopped)?;
            let socket = match net.udp_bind(destination).await {
                Ok(socket) => Arc::new(socket),
                Err(_) if self.is_local_address(destination.ip()) => {
                    // A packet for a local address can be a response for an
                    // endpoint-originated UDP socket which already owns the
                    // port.
                    return Ok(None);
                }
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "bind userspace UDP forwarder for {destination}: {error}"
                        ),
                    ));
                }
            };
            let listener_cancellation = self.cancellation.child_token();
            listeners.insert(
                destination,
                UdpListenerEntry {
                    socket: socket.clone(),
                    cancellation: listener_cancellation.clone(),
                    updated_at: Instant::now(),
                },
            );
            drop(listeners);

            let weak = Arc::downgrade(self);
            let task_socket = socket.clone();
            tokio::spawn(async move {
                udp_receive_loop(
                    weak.clone(),
                    task_socket.clone(),
                    destination,
                    listener_cancellation,
                )
                .await;
                if let Some(this) = weak.upgrade() {
                    let mut listeners = this.udp_listeners.lock().await;
                    if listeners.get(&destination).is_some_and(|active| {
                        Arc::ptr_eq(&active.socket, &task_socket)
                    }) {
                        listeners.remove(&destination);
                    }
                }
            });
            Ok(Some(socket))
        })
    }

    async fn route_udp(
        self: &Arc<Self>,
        source: SocketAddr,
        original_destination: SocketAddr,
        payload: Vec<u8>,
    ) {
        let original = SocksAddr::from(original_destination);
        if self
            .dns_hijack_addresses
            .contains(&original_destination.ip())
        {
            let metadata = Metadata {
                inbound: self.tag.clone(),
                source: Some(source.into()),
                destination: Some(original.clone()),
                network: Some(Network::Udp),
                protocol: "dns".into(),
                ..Metadata::default()
            };
            if let Ok(response) = hijack_dns_packet_with_context(
                &payload,
                &self.outbounds,
                &metadata,
            )
            .await
            {
                self.send_udp_response(source, original_destination, &response)
                    .await;
            }
            return;
        }

        if !self.wait_for_direct_interfaces().await {
            return;
        }
        let direct_interface = self
            .direct_interfaces
            .read()
            .expect("direct interface classifier poisoned")
            .classify(&original);
        let key =
            NatKey::new(self.udp_mapping, source, &original, direct_interface);
        let now = Instant::now();
        let existing = {
            let mut state = self.udp_state.lock().await;
            state.expire(now);
            state.sessions.get_mut(&key).map(|session| {
                session.updated_at = now;
                session.clone_parts()
            })
        };
        if let Some(session) = existing {
            let (local_destination, _) =
                self.translate_local_destination(original_destination);
            let Ok((destination, _)) = crate::inbound::socks::restore_fake_ip(
                SocksAddr::from(local_destination),
                &self.outbounds,
            ) else {
                return;
            };
            session.filter.record(&original);
            let routed_destination = session
                .destination_nat
                .lock()
                .await
                .translate_destination(destination, original);
            let _ = session
                .connection
                .send_to(&payload, &routed_destination)
                .await;
            return;
        }

        let (local_destination, local_origin) =
            self.translate_local_destination(original_destination);
        let (destination, fake_origin) =
            match crate::inbound::socks::restore_fake_ip(
                SocksAddr::from(local_destination),
                &self.outbounds,
            ) {
                Ok(result) => result,
                Err(_) => return,
            };
        let fake_ip = fake_origin.is_some();
        let origin_destination =
            fake_origin.or(local_origin.map(SocksAddr::from));
        let mut metadata = Metadata {
            inbound: self.tag.clone(),
            source: Some(source.into()),
            destination: Some(destination.clone()),
            origin_destination: origin_destination.clone(),
            fake_ip,
            network: Some(Network::Udp),
            ..Metadata::default()
        };
        let decision = {
            let mut state = self.udp_state.lock().await;
            match state
                .sniff_sessions
                .route(
                    (source, original_destination),
                    &payload,
                    &mut metadata,
                    &self.router,
                    &self.outbounds,
                )
                .await
            {
                Ok(decision) => decision,
                Err(_) => return,
            }
        };
        if matches!(decision.action(), Some(Action::Reject { .. })) {
            return;
        }
        if matches!(decision.action(), Some(Action::HijackDns)) {
            if let Ok(response) = hijack_dns_packet_with_context(
                &payload,
                &self.outbounds,
                &metadata,
            )
            .await
            {
                self.send_udp_response(source, original_destination, &response)
                    .await;
            }
            return;
        }

        let route_original = metadata
            .destination
            .clone()
            .unwrap_or_else(|| destination.clone());
        let routed_destination = decision.destination(&route_original);
        let connection_options = decision.connection_options();
        let udp_timeout =
            connection_options.udp_timeout.unwrap_or(self.udp_timeout);
        let dialer = if matches!(decision.action(), Some(Action::Direct)) {
            self.outbounds.direct()
        } else if let Some(dialer) = self.outbounds.select(decision.outbound())
        {
            dialer
        } else {
            return;
        };
        let connection = match dialer
            .listen_udp_with_options(
                &routed_destination,
                &connection_options.network,
            )
            .await
        {
            Ok(connection) => Arc::<dyn PacketConnection>::from(connection),
            Err(_) => return,
        };
        let filter = self.udp_filter.open(&original);
        let destination_nat = Arc::new(Mutex::new(PacketDestinationNat::new(
            route_original,
            routed_destination,
        )));
        let cancellation = self.cancellation.child_token();
        let fresh = NatSession {
            connection: connection.clone(),
            filter: filter.clone(),
            destination_nat: destination_nat.clone(),
            cancellation: cancellation.clone(),
            updated_at: now,
            timeout: udp_timeout,
        };
        let session = {
            let mut state = self.udp_state.lock().await;
            state.expire(now);
            if let Some(session) = state.sessions.get_mut(&key) {
                cancellation.cancel();
                session.updated_at = now;
                session.clone_parts()
            } else {
                if state.sessions.len() >= self.udp_nat_max
                    && let Some(oldest) = state
                        .sessions
                        .iter()
                        .min_by_key(|(_, session)| session.updated_at)
                        .map(|(key, _)| key.clone())
                    && let Some(session) = state.sessions.remove(&oldest)
                {
                    session.cancellation.cancel();
                }
                let parts = fresh.clone_parts();
                state.sessions.insert(key.clone(), fresh);
                spawn_udp_response_relay(
                    Arc::downgrade(self),
                    connection,
                    filter,
                    destination_nat,
                    source,
                    original_destination,
                    cancellation,
                );
                parts
            }
        };
        session.filter.record(&original);
        let routed_destination = session
            .destination_nat
            .lock()
            .await
            .translate_destination(destination, original);
        let _ = session
            .connection
            .send_to(&payload, &routed_destination)
            .await;
    }

    async fn send_udp_response(
        self: &Arc<Self>,
        client: SocketAddr,
        source: SocketAddr,
        payload: &[u8],
    ) {
        if let Ok(Some(socket)) = self.ensure_udp_listener(source).await {
            let _ = socket.send_to(payload, client).await;
        }
    }

    fn translate_local_destination(
        &self,
        destination: SocketAddr,
    ) -> (SocketAddr, Option<SocketAddr>) {
        if !self.is_local_address(destination.ip()) {
            return (destination, None);
        }
        let translated = SocketAddr::new(
            match destination.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            },
            destination.port(),
        );
        (translated, Some(destination))
    }

    fn is_local_address(&self, address: IpAddr) -> bool {
        self.local_networks.iter().any(|network| {
            if self.local_prefix_match {
                network.contains(&address)
            } else {
                network.addr() == address
            }
        })
    }

    fn spawn_expiry(this: &Arc<Self>) {
        let weak = Arc::downgrade(this);
        let cancellation = this.cancellation.clone();
        let interval = this
            .udp_timeout
            .min(Duration::from_secs(1))
            .max(Duration::from_millis(10));
        tokio::spawn(async move {
            let mut expiry = tokio::time::interval(interval);
            expiry.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    _ = expiry.tick() => {}
                }
                let Some(this) = weak.upgrade() else { break };
                this.udp_state.lock().await.expire(Instant::now());
                {
                    let mut listeners = this.tcp_listeners.lock().await;
                    expire_tcp_listeners(
                        &mut listeners,
                        Instant::now(),
                        this.udp_timeout,
                    );
                }
                {
                    let mut listeners = this.udp_listeners.lock().await;
                    expire_udp_listeners(
                        &mut listeners,
                        Instant::now(),
                        this.udp_timeout,
                    );
                }
            }
        });
    }

    fn spawn_network_monitor(this: &Arc<Self>) {
        let weak = Arc::downgrade(this);
        let cancellation = this.cancellation.clone();
        tokio::spawn(async move {
            let Ok(monitor) =
                crate::common::network_monitor::NetworkMonitor::new().await
            else {
                if let Some(this) = weak.upgrade() {
                    this.direct_interfaces_ready.store(true, Ordering::Release);
                    this.direct_interfaces_notify.notify_waiters();
                }
                return;
            };
            let mut watcher = monitor.interface_state();
            let mut previous = watcher.get();
            let Some(this) = weak.upgrade() else {
                return;
            };
            *this
                .direct_interfaces
                .write()
                .expect("direct interface classifier poisoned") =
                DirectInterfaceClassifier::from_system();
            this.direct_interfaces_ready.store(true, Ordering::Release);
            this.direct_interfaces_notify.notify_waiters();
            drop(this);
            loop {
                let current = tokio::select! {
                    _ = cancellation.cancelled() => break,
                    current = watcher.updated() => match current {
                        Ok(current) => current,
                        Err(_) => break,
                    },
                };
                let changed = current.is_major_change(&previous);
                previous = current;
                let Some(this) = weak.upgrade() else {
                    break;
                };
                *this
                    .direct_interfaces
                    .write()
                    .expect("direct interface classifier poisoned") =
                    DirectInterfaceClassifier::from_system();
                if !changed {
                    continue;
                }
                this.reset_network().await;
                tracing::info!(
                    inbound = %this.tag,
                    "reset userspace endpoint flow tables after network change"
                );
            }
        });
    }

    async fn wait_for_direct_interfaces(&self) -> bool {
        loop {
            let notified = self.direct_interfaces_notify.notified();
            if self.direct_interfaces_ready.load(Ordering::Acquire) {
                return true;
            }
            tokio::select! {
                _ = self.cancellation.cancelled() => return false,
                _ = notified => {}
            }
        }
    }

    async fn reset_network(&self) {
        self.flow_dispatcher.reset_network();
        cancel_tcp_connections(&self.tcp_connections).await;
        let mut state = self.udp_state.lock().await;
        for session in state.sessions.values() {
            session.cancellation.cancel();
        }
        state.sessions.clear();
        state.sniff_sessions = PacketSniffSessions::new(self.udp_timeout);
    }
}

/// Bridge the synchronous `IpPacketReturn` callback into smoltcp's bounded
/// egress without treating temporary queue pressure as a packet write error.
///
/// sing-tun writes matched return packets synchronously and consumes them even
/// if the final device write fails. The return trait cannot await capacity, so
/// the ingress-facing side is intentionally unbounded while this single task
/// preserves packet order and applies backpressure at the actual egress.
fn spawn_flow_writeback(
    egress: mpsc::Sender<Vec<u8>>,
    cancellation: CancellationToken,
) -> mpsc::UnboundedSender<Vec<u8>> {
    let (writeback, mut packets) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let packet = tokio::select! {
                _ = cancellation.cancelled() => break,
                packet = packets.recv() => packet,
            };
            let Some(packet) = packet else {
                break;
            };
            if egress.send(packet).await.is_err() {
                break;
            }
        }
    });
    writeback
}

async fn cancel_tcp_connections(
    connections: &Mutex<HashMap<u64, CancellationToken>>,
) {
    let mut connections = connections.lock().await;
    for cancellation in connections.values() {
        cancellation.cancel();
    }
    connections.clear();
}

impl Drop for UserspaceEndpointRouter {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut connections) = self.tcp_connections.try_lock() {
            for cancellation in connections.values() {
                cancellation.cancel();
            }
            connections.clear();
        }
        if let Ok(mut state) = self.udp_state.try_lock() {
            for session in state.sessions.values() {
                session.cancellation.cancel();
            }
            state.sessions.clear();
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn tcp_accept_loop(
    mut listener: TcpListener,
    destination: SocketAddr,
    origin_destination: Option<SocketAddr>,
    hijack_dns: bool,
    tag: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    listener_cancellation: CancellationToken,
    connection_cancellation: CancellationToken,
    tcp_connections: Arc<Mutex<HashMap<u64, CancellationToken>>>,
) {
    loop {
        tokio::select! {
            _ = listener_cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((stream, source)) = accepted else { break };
                let router = router.clone();
                let outbounds = outbounds.clone();
                let tag = tag.clone();
                let connection_id =
                    NEXT_TCP_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
                let cancellation = connection_cancellation.child_token();
                tcp_connections
                    .lock()
                    .await
                    .insert(connection_id, cancellation.clone());
                let active_connections = tcp_connections.clone();
                tokio::spawn(async move {
                    let proxy = async {
                        if hijack_dns {
                            let metadata = Metadata {
                                inbound: tag,
                                source: Some(source.into()),
                                destination: Some(destination.into()),
                                origin_destination: origin_destination
                                    .map(SocksAddr::from),
                                network: Some(Network::Tcp),
                                protocol: "dns".into(),
                                ..Metadata::default()
                            };
                            serve_hijacked_dns_stream_with_context(
                                Box::new(stream),
                                &outbounds,
                                &metadata,
                            )
                            .await
                        } else {
                            proxy_routed_tcp_with_origin(
                                Box::new(stream),
                                source,
                                &tag,
                                "",
                                destination.into(),
                                origin_destination.map(SocksAddr::from),
                                false,
                                &router,
                                &outbounds,
                            )
                            .await
                        }
                    };
                    tokio::select! {
                        _ = cancellation.cancelled() => {}
                        _ = proxy => {}
                    }
                    active_connections.lock().await.remove(&connection_id);
                });
            }
        }
    }
}

struct TcpListenerEntry {
    marker: Arc<()>,
    cancellation: CancellationToken,
    updated_at: Instant,
}

struct UdpListenerEntry {
    socket: Arc<SmoltcpUdpSocket>,
    cancellation: CancellationToken,
    updated_at: Instant,
}

fn evict_oldest_tcp_listener(
    listeners: &mut HashMap<SocketAddr, TcpListenerEntry>,
    max: usize,
) {
    if listeners.len() < max {
        return;
    }
    if let Some(oldest) = listeners
        .iter()
        .min_by_key(|(_, listener)| listener.updated_at)
        .map(|(address, _)| *address)
        && let Some(listener) = listeners.remove(&oldest)
    {
        listener.cancellation.cancel();
    }
}

fn evict_oldest_udp_listener(
    listeners: &mut HashMap<SocketAddr, UdpListenerEntry>,
    max: usize,
) {
    if listeners.len() < max {
        return;
    }
    if let Some(oldest) = listeners
        .iter()
        .min_by_key(|(_, listener)| listener.updated_at)
        .map(|(address, _)| *address)
        && let Some(listener) = listeners.remove(&oldest)
    {
        listener.cancellation.cancel();
    }
}

fn expire_tcp_listeners(
    listeners: &mut HashMap<SocketAddr, TcpListenerEntry>,
    now: Instant,
    timeout: Duration,
) {
    listeners.retain(|_, listener| {
        let alive = now.duration_since(listener.updated_at) <= timeout;
        if !alive {
            listener.cancellation.cancel();
        }
        alive
    });
}

fn expire_udp_listeners(
    listeners: &mut HashMap<SocketAddr, UdpListenerEntry>,
    now: Instant,
    timeout: Duration,
) {
    listeners.retain(|_, listener| {
        let alive = now.duration_since(listener.updated_at) <= timeout;
        if !alive {
            listener.cancellation.cancel();
        }
        alive
    });
}

async fn udp_receive_loop(
    router: Weak<UserspaceEndpointRouter>,
    socket: Arc<SmoltcpUdpSocket>,
    destination: SocketAddr,
    cancellation: CancellationToken,
) {
    let mut packet = vec![0_u8; MAX_PACKET_SIZE];
    loop {
        let received = tokio::select! {
            _ = cancellation.cancelled() => break,
            received = socket.recv_from(&mut packet) => received,
        };
        let Ok((length, source)) = received else {
            break;
        };
        let Some(router) = router.upgrade() else {
            break;
        };
        router
            .route_udp(source, destination, packet[..length].to_vec())
            .await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum NatKey {
    Endpoint(SocketAddr, Option<u32>),
    Address(SocketAddr, String),
    AddressAndPort(SocketAddr, SocksAddr),
}

impl NatKey {
    fn new(
        mapping: UdpNatBehavior,
        source: SocketAddr,
        destination: &SocksAddr,
        direct_interface: Option<u32>,
    ) -> Self {
        match mapping {
            UdpNatBehavior::EndpointIndependent => {
                Self::Endpoint(source, direct_interface)
            }
            UdpNatBehavior::AddressDependent => {
                Self::Address(source, destination.host())
            }
            UdpNatBehavior::AddressAndPortDependent => {
                Self::AddressAndPort(source, destination.clone())
            }
        }
    }
}

struct UdpState {
    sniff_sessions: PacketSniffSessions<(SocketAddr, SocketAddr)>,
    sessions: HashMap<NatKey, NatSession>,
}

impl UdpState {
    fn new(timeout: Duration) -> Self {
        Self {
            sniff_sessions: PacketSniffSessions::new(timeout),
            sessions: HashMap::new(),
        }
    }

    fn expire(&mut self, now: Instant) {
        self.sessions.retain(|_, session| {
            let alive =
                now.duration_since(session.updated_at) <= session.timeout;
            if !alive {
                session.cancellation.cancel();
            }
            alive
        });
    }
}

struct NatSession {
    connection: Arc<dyn PacketConnection>,
    filter: UdpNatFilterSession,
    destination_nat: Arc<Mutex<PacketDestinationNat>>,
    cancellation: CancellationToken,
    updated_at: Instant,
    timeout: Duration,
}

struct NatSessionParts {
    connection: Arc<dyn PacketConnection>,
    filter: UdpNatFilterSession,
    destination_nat: Arc<Mutex<PacketDestinationNat>>,
}

impl NatSession {
    fn clone_parts(&self) -> NatSessionParts {
        NatSessionParts {
            connection: self.connection.clone(),
            filter: self.filter.clone(),
            destination_nat: self.destination_nat.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FragmentKey {
    V4 {
        source: Ipv4Addr,
        destination: Ipv4Addr,
        identifier: u16,
    },
    V6 {
        source: Ipv6Addr,
        destination: Ipv6Addr,
        identifier: u32,
    },
}

enum FragmentPrefix {
    V4(Vec<u8>),
    V6 {
        bytes: Vec<u8>,
        previous_next_header: usize,
        fragment_next_header: u8,
    },
}

struct FragmentEntry {
    prefix: Option<FragmentPrefix>,
    fragments: Vec<(usize, Vec<u8>)>,
    total_len: Option<usize>,
    stored_bytes: usize,
    updated_at: Instant,
}

impl FragmentEntry {
    fn new() -> Self {
        Self {
            prefix: None,
            fragments: Vec::new(),
            total_len: None,
            stored_bytes: 0,
            updated_at: Instant::now(),
        }
    }

    fn insert(&mut self, fragment: FragmentInput<'_>) -> io::Result<()> {
        let end = fragment
            .offset
            .checked_add(fragment.payload.len())
            .ok_or_else(|| invalid_packet("ICMP fragment offset overflow"))?;
        if end > MAX_PACKET_SIZE {
            return Err(invalid_packet("reassembled ICMP packet is too large"));
        }
        if fragment.more && !fragment.payload.len().is_multiple_of(8) {
            return Err(invalid_packet(
                "non-final ICMP fragment payload is not 8-byte aligned",
            ));
        }
        for (existing_offset, existing) in &self.fragments {
            let existing_end = existing_offset + existing.len();
            let overlap_start = fragment.offset.max(*existing_offset);
            let overlap_end = end.min(existing_end);
            if overlap_start < overlap_end {
                let incoming = &fragment.payload[overlap_start - fragment.offset
                    ..overlap_end - fragment.offset];
                let old = &existing[overlap_start - existing_offset
                    ..overlap_end - existing_offset];
                if incoming != old {
                    return Err(invalid_packet(
                        "conflicting overlapping ICMP fragments",
                    ));
                }
            }
        }
        if fragment.offset == 0 {
            self.prefix = fragment.prefix;
        }
        if !fragment.more {
            if self.total_len.is_some_and(|total| total != end) {
                return Err(invalid_packet(
                    "conflicting final ICMP fragment lengths",
                ));
            }
            self.total_len = Some(end);
        }
        self.stored_bytes =
            self.stored_bytes.saturating_add(fragment.payload.len());
        self.fragments
            .push((fragment.offset, fragment.payload.to_vec()));
        self.updated_at = Instant::now();
        Ok(())
    }

    fn reassemble(&mut self) -> io::Result<Option<Vec<u8>>> {
        let (Some(total_len), Some(prefix)) =
            (self.total_len, self.prefix.as_ref())
        else {
            return Ok(None);
        };
        self.fragments.sort_by_key(|(offset, _)| *offset);
        let mut payload = Vec::with_capacity(total_len);
        for (offset, fragment) in &self.fragments {
            if *offset > payload.len() {
                return Ok(None);
            }
            let skip =
                payload.len().saturating_sub(*offset).min(fragment.len());
            payload.extend_from_slice(&fragment[skip..]);
            if payload.len() >= total_len {
                payload.truncate(total_len);
                break;
            }
        }
        if payload.len() != total_len {
            return Ok(None);
        }
        match prefix {
            FragmentPrefix::V4(header) => {
                let packet_len =
                    header.len().checked_add(payload.len()).ok_or_else(
                        || invalid_packet("IPv4 reassembly overflow"),
                    )?;
                let total = u16::try_from(packet_len).map_err(|_| {
                    invalid_packet("reassembled IPv4 packet is too large")
                })?;
                let mut packet = header.clone();
                packet.extend_from_slice(&payload);
                packet[2..4].copy_from_slice(&total.to_be_bytes());
                let flags = u16::from_be_bytes([packet[6], packet[7]]) & 0xc000;
                packet[6..8].copy_from_slice(&flags.to_be_bytes());
                packet[10..12].fill(0);
                let checksum = internet_checksum(&packet[..header.len()]);
                packet[10..12].copy_from_slice(&checksum.to_be_bytes());
                Ok(Some(packet))
            }
            FragmentPrefix::V6 {
                bytes,
                previous_next_header,
                fragment_next_header,
            } => {
                let payload_len = bytes
                    .len()
                    .checked_sub(40)
                    .and_then(|length| length.checked_add(payload.len()))
                    .ok_or_else(|| {
                        invalid_packet("IPv6 reassembly overflow")
                    })?;
                let payload_len = u16::try_from(payload_len).map_err(|_| {
                    invalid_packet("reassembled IPv6 packet is too large")
                })?;
                let mut packet = bytes.clone();
                packet[*previous_next_header] = *fragment_next_header;
                packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
                packet.extend_from_slice(&payload);
                Ok(Some(packet))
            }
        }
    }
}

struct FragmentInput<'a> {
    key: FragmentKey,
    offset: usize,
    more: bool,
    payload: &'a [u8],
    prefix: Option<FragmentPrefix>,
}

enum FragmentDisposition {
    NotFragmented,
    Pending,
    Complete(Vec<u8>),
    Drop,
}

#[derive(Default)]
struct IcmpFragmentCache {
    entries: HashMap<FragmentKey, FragmentEntry>,
    stored_bytes: usize,
}

impl IcmpFragmentCache {
    fn push(&mut self, packet: &[u8]) -> io::Result<FragmentDisposition> {
        self.prune();
        let Some(fragment) = parse_icmp_fragment(packet)? else {
            return Ok(FragmentDisposition::NotFragmented);
        };
        let key = fragment.key.clone();
        while (!self.entries.contains_key(&key)
            && self.entries.len() >= ICMP_FRAGMENT_MAX_ENTRIES)
            || self.stored_bytes.saturating_add(fragment.payload.len())
                > ICMP_FRAGMENT_MAX_BYTES
        {
            if !self.evict_oldest() {
                return Ok(FragmentDisposition::Drop);
            }
        }
        let entry = self
            .entries
            .entry(key.clone())
            .or_insert_with(FragmentEntry::new);
        let before = entry.stored_bytes;
        if let Err(error) = entry.insert(fragment) {
            self.stored_bytes = self.stored_bytes.saturating_sub(before);
            self.entries.remove(&key);
            return Err(error);
        }
        self.stored_bytes = self
            .stored_bytes
            .saturating_add(entry.stored_bytes.saturating_sub(before));
        match entry.reassemble() {
            Ok(Some(packet)) => {
                let entry = self.entries.remove(&key).expect("entry exists");
                self.stored_bytes =
                    self.stored_bytes.saturating_sub(entry.stored_bytes);
                Ok(FragmentDisposition::Complete(packet))
            }
            Ok(None) => Ok(FragmentDisposition::Pending),
            Err(error) => {
                let entry = self.entries.remove(&key).expect("entry exists");
                self.stored_bytes =
                    self.stored_bytes.saturating_sub(entry.stored_bytes);
                Err(error)
            }
        }
    }

    fn prune(&mut self) {
        let now = Instant::now();
        let mut removed = 0_usize;
        self.entries.retain(|_, entry| {
            let keep =
                now.duration_since(entry.updated_at) < ICMP_FRAGMENT_TIMEOUT;
            if !keep {
                removed = removed.saturating_add(entry.stored_bytes);
            }
            keep
        });
        self.stored_bytes = self.stored_bytes.saturating_sub(removed);
    }

    fn evict_oldest(&mut self) -> bool {
        let Some(key) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.updated_at)
            .map(|(key, _)| key.clone())
        else {
            return false;
        };
        if let Some(entry) = self.entries.remove(&key) {
            self.stored_bytes =
                self.stored_bytes.saturating_sub(entry.stored_bytes);
        }
        true
    }
}

fn parse_icmp_fragment(packet: &[u8]) -> io::Result<Option<FragmentInput<'_>>> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => parse_ipv4_icmp_fragment(packet),
        Some(6) => parse_ipv6_icmp_fragment(packet),
        _ => Ok(None),
    }
}

fn parse_ipv4_icmp_fragment(
    packet: &[u8],
) -> io::Result<Option<FragmentInput<'_>>> {
    if packet.len() < 20 || packet[9] != 1 {
        return Ok(None);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < 20 || total_len < header_len || packet.len() < total_len {
        return Err(invalid_packet("invalid fragmented IPv4 packet"));
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let more = fragment & 0x2000 != 0;
    let offset = usize::from(fragment & 0x1fff) * 8;
    if !more && offset == 0 {
        return Ok(None);
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination =
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Ok(Some(FragmentInput {
        key: FragmentKey::V4 {
            source,
            destination,
            identifier: u16::from_be_bytes([packet[4], packet[5]]),
        },
        offset,
        more,
        payload: &packet[header_len..total_len],
        prefix: (offset == 0)
            .then(|| FragmentPrefix::V4(packet[..header_len].to_vec())),
    }))
}

fn parse_ipv6_icmp_fragment(
    packet: &[u8],
) -> io::Result<Option<FragmentInput<'_>>> {
    if packet.len() < 40 {
        return Ok(None);
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let packet_len = 40_usize
        .checked_add(payload_len)
        .ok_or_else(|| invalid_packet("IPv6 payload length overflow"))?;
    if packet.len() < packet_len {
        return Err(invalid_packet("truncated fragmented IPv6 packet"));
    }
    let mut next_header = packet[6];
    let mut offset = 40_usize;
    let mut previous_next_header = 6_usize;
    loop {
        match next_header {
            44 => break,
            0 | 43 | 60 | 135 | 139 | 140 => {
                let extension =
                    packet.get(offset..offset + 2).ok_or_else(|| {
                        invalid_packet(
                            "truncated IPv6 extension before fragment",
                        )
                    })?;
                previous_next_header = offset;
                next_header = extension[0];
                offset = offset
                    .checked_add((usize::from(extension[1]) + 1) * 8)
                    .ok_or_else(|| invalid_packet("IPv6 extension overflow"))?;
            }
            51 => {
                let extension =
                    packet.get(offset..offset + 2).ok_or_else(|| {
                        invalid_packet("truncated IPv6 AH before fragment")
                    })?;
                previous_next_header = offset;
                next_header = extension[0];
                offset = offset
                    .checked_add((usize::from(extension[1]) + 2) * 4)
                    .ok_or_else(|| invalid_packet("IPv6 AH overflow"))?;
            }
            _ => return Ok(None),
        }
        if offset > packet_len {
            return Err(invalid_packet("IPv6 extension exceeds packet"));
        }
    }
    let fragment = packet
        .get(offset..offset + 8)
        .ok_or_else(|| invalid_packet("truncated IPv6 fragment header"))?;
    if fragment[0] != 58 {
        return Ok(None);
    }
    let offset_flags = u16::from_be_bytes([fragment[2], fragment[3]]);
    let fragment_offset = usize::from(offset_flags & 0xfff8);
    let more = offset_flags & 1 != 0;
    if !more && fragment_offset == 0 {
        return Ok(None);
    }
    let source = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[8..24]).expect("checked IPv6 source"),
    );
    let destination = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[24..40])
            .expect("checked IPv6 destination"),
    );
    Ok(Some(FragmentInput {
        key: FragmentKey::V6 {
            source,
            destination,
            identifier: u32::from_be_bytes([
                fragment[4],
                fragment[5],
                fragment[6],
                fragment[7],
            ]),
        },
        offset: fragment_offset,
        more,
        payload: &packet[offset + 8..packet_len],
        prefix: (fragment_offset == 0).then(|| FragmentPrefix::V6 {
            bytes: packet[..offset].to_vec(),
            previous_next_header,
            fragment_next_header: fragment[0],
        }),
    }))
}

#[allow(clippy::too_many_arguments)]
fn spawn_udp_response_relay(
    router: Weak<UserspaceEndpointRouter>,
    connection: Arc<dyn PacketConnection>,
    filter: UdpNatFilterSession,
    destination_nat: Arc<Mutex<PacketDestinationNat>>,
    client: SocketAddr,
    original_destination: SocketAddr,
    cancellation: CancellationToken,
) {
    tokio::spawn(async move {
        let mut response = vec![0_u8; MAX_PACKET_SIZE];
        loop {
            let received = tokio::select! {
                _ = cancellation.cancelled() => break,
                received = connection.recv_from(&mut response) => received,
            };
            let Ok((length, response_source)) = received else {
                break;
            };
            let Some(router) = router.upgrade() else {
                break;
            };
            let response_source = destination_nat
                .lock()
                .await
                .translate_source(response_source);
            if !filter.allows(&response_source) {
                continue;
            }
            let source = match response_source {
                SocksAddr::Ip(source) => source,
                SocksAddr::Domain { .. } => original_destination,
            };
            router
                .send_udp_response(client, source, &response[..length])
                .await;
        }
    });
}

fn parse_transport_packet(packet: &[u8]) -> io::Result<TransportPacket> {
    let Some(version) = packet.first().map(|value| value >> 4) else {
        return Err(invalid_packet("empty IP packet"));
    };
    let (source, destination, protocol, transport_offset) = match version {
        4 => parse_ipv4_transport(packet)?,
        6 => parse_ipv6_transport(packet)?,
        _ => return Err(invalid_packet("unsupported IP version")),
    };
    if protocol == 1 || protocol == 58 {
        let transport = packet.get(transport_offset..).ok_or_else(|| {
            invalid_packet("ICMP header starts past the IP packet")
        })?;
        if transport.len() < 8 {
            return Err(invalid_packet("truncated ICMP header"));
        }
        let echo_type = if protocol == 1 { 8 } else { 128 };
        return Ok(if transport[0] == echo_type && transport[1] == 0 {
            TransportPacket::IcmpEcho {
                source,
                destination,
                hop_limit: if version == 4 { packet[8] } else { packet[7] },
                transport_offset,
            }
        } else {
            TransportPacket::Other
        });
    }
    if protocol != 6 && protocol != 17 {
        return Ok(TransportPacket::Other);
    }
    let transport = packet.get(transport_offset..).ok_or_else(|| {
        invalid_packet("transport header starts past the IP packet")
    })?;
    if transport.len() < 4 {
        return Err(invalid_packet("truncated TCP/UDP header"));
    }
    let destination_port = u16::from_be_bytes([transport[2], transport[3]]);
    let destination = SocketAddr::new(destination, destination_port);
    if protocol == 17 {
        return Ok(TransportPacket::Udp { destination });
    }
    if transport.len() < 14 {
        return Err(invalid_packet("truncated TCP header"));
    }
    let flags = transport[13];
    Ok(TransportPacket::Tcp {
        destination,
        initial_syn: flags & 0x02 != 0 && flags & 0x10 == 0,
    })
}

fn packet_destination_address(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).ok()?,
        ))),
        _ => None,
    }
}

fn build_icmp_response_packet(
    source: IpAddr,
    destination: IpAddr,
    hop_limit: u8,
    message: &[u8],
) -> io::Result<Vec<u8>> {
    if message.len() < 8 {
        return Err(invalid_packet("truncated ICMP response"));
    }
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let total_len =
                20_usize.checked_add(message.len()).ok_or_else(|| {
                    invalid_packet("IPv4 ICMP response length overflow")
                })?;
            let total_len = u16::try_from(total_len).map_err(|_| {
                invalid_packet("IPv4 ICMP response exceeds 65535 bytes")
            })?;
            let mut packet = vec![0_u8; usize::from(total_len)];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&total_len.to_be_bytes());
            packet[8] = hop_limit.max(1);
            packet[9] = 1;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&destination.octets());
            packet[20..].copy_from_slice(message);
            packet[22..24].fill(0);
            let icmp_checksum = internet_checksum(&packet[20..]);
            packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
            let header_checksum = internet_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            Ok(packet)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let payload_len = u16::try_from(message.len()).map_err(|_| {
                invalid_packet("IPv6 ICMP response exceeds 65535 bytes")
            })?;
            let mut packet = vec![0_u8; 40 + message.len()];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
            packet[6] = 58;
            packet[7] = hop_limit.max(1);
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&destination.octets());
            packet[40..].copy_from_slice(message);
            packet[42..44].fill(0);
            let checksum = icmpv6_checksum(source, destination, &packet[40..]);
            packet[42..44].copy_from_slice(&checksum.to_be_bytes());
            Ok(packet)
        }
        _ => Err(invalid_packet("ICMP response address family changed")),
    }
}

/// Apply the link MTU before an ICMP response bypasses smoltcp and enters the
/// tunnel egress. sing-tun injects returned ping packets through gVisor's
/// `WritePacketDirect`; those packets are locally originated from the stack's
/// perspective, so both IPv4 and IPv6 are source-fragmented as necessary.
fn prepare_icmp_egress(
    response: Vec<u8>,
    effective_mtu: usize,
    ipv4_identification: u16,
    ipv6_identification: u32,
) -> io::Result<Vec<Vec<u8>>> {
    if effective_mtu == 0 || response.len() <= effective_mtu {
        return Ok(vec![response]);
    }
    match response.first().map(|byte| byte >> 4) {
        Some(4) => {
            fragment_ipv4_packet(&response, effective_mtu, ipv4_identification)
        }
        Some(6) => {
            fragment_ipv6_packet(&response, effective_mtu, ipv6_identification)
        }
        _ => Err(invalid_packet("invalid ICMP response IP version")),
    }
}

fn fragment_ipv4_packet(
    packet: &[u8],
    effective_mtu: usize,
    identification: u16,
) -> io::Result<Vec<Vec<u8>>> {
    if packet.first().map(|byte| byte >> 4) != Some(4) || packet.len() < 20 {
        return Err(invalid_packet("invalid IPv4 packet for fragmentation"));
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if !(20..packet.len()).contains(&header_len)
        || total_len < header_len
        || total_len > packet.len()
    {
        return Err(invalid_packet("invalid IPv4 fragmentation lengths"));
    }
    let max_payload = effective_mtu.saturating_sub(header_len) & !7;
    if max_payload == 0 {
        return Err(invalid_packet("IPv4 MTU is too small to fragment packet"));
    }
    let payload = &packet[header_len..total_len];
    let original_fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let base_offset = original_fragment & 0x1fff;
    let base_flags = original_fragment & 0xc000;
    let original_more = original_fragment & 0x2000 != 0;
    let mut fragments = Vec::with_capacity(payload.len().div_ceil(max_payload));
    for start in (0..payload.len()).step_by(max_payload) {
        let end = (start + max_payload).min(payload.len());
        let mut fragment = Vec::with_capacity(header_len + end - start);
        fragment.extend_from_slice(&packet[..header_len]);
        fragment.extend_from_slice(&payload[start..end]);
        let fragment_len = u16::try_from(fragment.len()).map_err(|_| {
            invalid_packet("IPv4 fragment exceeds maximum packet size")
        })?;
        fragment[2..4].copy_from_slice(&fragment_len.to_be_bytes());
        fragment[4..6].copy_from_slice(&identification.to_be_bytes());
        let mut fragment_field = base_flags
            | base_offset
                .checked_add(u16::try_from(start / 8).map_err(|_| {
                    invalid_packet("IPv4 fragment offset overflow")
                })?)
                .ok_or_else(|| {
                    invalid_packet("IPv4 fragment offset overflow")
                })?;
        if original_more || end < payload.len() {
            fragment_field |= 0x2000;
        }
        fragment[6..8].copy_from_slice(&fragment_field.to_be_bytes());
        fragment[10..12].fill(0);
        let checksum = internet_checksum(&fragment[..header_len]);
        fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
        fragments.push(fragment);
    }
    if fragments.is_empty() {
        return Err(invalid_packet("cannot fragment empty IPv4 payload"));
    }
    Ok(fragments)
}

fn fragment_ipv6_packet(
    packet: &[u8],
    effective_mtu: usize,
    identification: u32,
) -> io::Result<Vec<Vec<u8>>> {
    if packet.first().map(|byte| byte >> 4) != Some(6) || packet.len() < 40 {
        return Err(invalid_packet("invalid IPv6 packet for fragmentation"));
    }
    let total_len = 40_usize
        .checked_add(usize::from(u16::from_be_bytes([packet[4], packet[5]])))
        .ok_or_else(|| invalid_packet("IPv6 packet length overflow"))?;
    if total_len > packet.len() || total_len <= 40 {
        return Err(invalid_packet("invalid IPv6 fragmentation lengths"));
    }
    let max_payload = effective_mtu.saturating_sub(48) & !7;
    if max_payload == 0 {
        return Err(invalid_packet("IPv6 MTU is too small to fragment packet"));
    }
    let next_header = packet[6];
    let payload = &packet[40..total_len];
    let mut fragments = Vec::with_capacity(payload.len().div_ceil(max_payload));
    for start in (0..payload.len()).step_by(max_payload) {
        let end = (start + max_payload).min(payload.len());
        let fragment_payload_len = u16::try_from(8 + end - start)
            .map_err(|_| invalid_packet("IPv6 fragment payload overflow"))?;
        let mut fragment =
            Vec::with_capacity(40 + usize::from(fragment_payload_len));
        fragment.extend_from_slice(&packet[..40]);
        fragment[4..6].copy_from_slice(&fragment_payload_len.to_be_bytes());
        fragment[6] = 44;
        fragment.extend_from_slice(&[next_header, 0, 0, 0, 0, 0, 0, 0]);
        let offset = u16::try_from(start)
            .map_err(|_| invalid_packet("IPv6 fragment offset overflow"))?;
        let offset_more = offset | u16::from(end < payload.len());
        fragment[42..44].copy_from_slice(&offset_more.to_be_bytes());
        fragment[44..48].copy_from_slice(&identification.to_be_bytes());
        fragment.extend_from_slice(&payload[start..end]);
        fragments.push(fragment);
    }
    if fragments.is_empty() {
        return Err(invalid_packet("cannot fragment empty IPv6 payload"));
    }
    Ok(fragments)
}

fn icmp_response_source(
    echo_destination: IpAddr,
    response: &crate::adapter::IcmpResponse,
) -> IpAddr {
    let is_error = matches!(
        (echo_destination, response.packet.first()),
        (IpAddr::V4(_), Some(3 | 11)) | (IpAddr::V6(_), Some(1..=4))
    );
    if is_error {
        response.source
    } else {
        echo_destination
    }
}

fn icmpv6_checksum(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    message: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + message.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(message.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(message);
    internet_checksum(&pseudo)
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn parse_ipv4_transport(
    packet: &[u8],
) -> io::Result<(IpAddr, IpAddr, u8, usize)> {
    if packet.len() < 20 {
        return Err(invalid_packet("truncated IPv4 header"));
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return Err(invalid_packet("invalid IPv4 header length"));
    }
    let source = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let protocol = if fragment & 0x1fff == 0 { packet[9] } else { 0 };
    Ok((source, destination, protocol, header_len))
}

fn parse_ipv6_transport(
    packet: &[u8],
) -> io::Result<(IpAddr, IpAddr, u8, usize)> {
    if packet.len() < 40 {
        return Err(invalid_packet("truncated IPv6 header"));
    }
    let source = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[8..24]).expect("checked IPv6 header"),
    ));
    let destination = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[24..40]).expect("checked IPv6 header"),
    ));
    let mut protocol = packet[6];
    let mut offset = 40;
    loop {
        match protocol {
            0 | 43 | 60 | 135 | 139 | 140 => {
                let extension =
                    packet.get(offset..offset + 2).ok_or_else(|| {
                        invalid_packet("truncated IPv6 extension")
                    })?;
                protocol = extension[0];
                let length = (usize::from(extension[1]) + 1) * 8;
                offset = offset.checked_add(length).ok_or_else(|| {
                    invalid_packet("IPv6 extension length overflow")
                })?;
                if offset > packet.len() {
                    return Err(invalid_packet("truncated IPv6 extension"));
                }
            }
            44 => {
                let extension = packet
                    .get(offset..offset + 8)
                    .ok_or_else(|| invalid_packet("truncated IPv6 fragment"))?;
                protocol = extension[0];
                let fragment = u16::from_be_bytes([extension[2], extension[3]]);
                offset += 8;
                if fragment & 0xfff8 != 0 {
                    return Ok((source, destination, 0, offset));
                }
            }
            51 => {
                let extension =
                    packet.get(offset..offset + 2).ok_or_else(|| {
                        invalid_packet("truncated IPv6 AH header")
                    })?;
                protocol = extension[0];
                let length = (usize::from(extension[1]) + 2) * 4;
                offset = offset
                    .checked_add(length)
                    .ok_or_else(|| invalid_packet("IPv6 AH length overflow"))?;
                if offset > packet.len() {
                    return Err(invalid_packet("truncated IPv6 AH header"));
                }
            }
            _ => return Ok((source, destination, protocol, offset)),
        }
    }
}

fn endpoint_stopped() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "userspace endpoint network is stopped",
    )
}

fn invalid_packet(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::{
        FragmentDisposition, IcmpFragmentCache, NatKey, TransportPacket,
        build_icmp_response_packet, cancel_tcp_connections,
        icmp_response_source, icmpv6_checksum, internet_checksum,
        parse_transport_packet, prepare_icmp_egress, spawn_flow_writeback,
    };
    use crate::{
        adapter::IcmpResponse, common::network::SocksAddr,
        option::UdpNatBehavior,
    };

    #[test]
    fn parses_ipv4_tcp_syn_and_udp_destinations() {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 7]);
        packet[20..22].copy_from_slice(&12345_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[33] = 0x02;
        assert_eq!(
            parse_transport_packet(&packet).unwrap(),
            TransportPacket::Tcp {
                destination: "198.51.100.7:443".parse().unwrap(),
                initial_syn: true,
            }
        );

        packet[33] = 0x12;
        assert_eq!(
            parse_transport_packet(&packet).unwrap(),
            TransportPacket::Tcp {
                destination: "198.51.100.7:443".parse().unwrap(),
                initial_syn: false,
            }
        );

        packet[9] = 17;
        assert_eq!(
            parse_transport_packet(&packet).unwrap(),
            TransportPacket::Udp {
                destination: "198.51.100.7:443".parse().unwrap(),
            }
        );
    }

    #[tokio::test]
    async fn network_reset_cancels_every_registered_tcp_flow() {
        let first = tokio_util::sync::CancellationToken::new();
        let second = tokio_util::sync::CancellationToken::new();
        let connections =
            tokio::sync::Mutex::new(std::collections::HashMap::from([
                (1, first.clone()),
                (2, second.clone()),
            ]));
        cancel_tcp_connections(&connections).await;
        assert!(first.is_cancelled());
        assert!(second.is_cancelled());
        assert!(connections.lock().await.is_empty());
    }

    #[tokio::test]
    async fn flow_writeback_waits_for_bounded_egress_without_dropping() {
        let (egress, mut output) = tokio::sync::mpsc::channel(1);
        egress.send(vec![0]).await.unwrap();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let writeback = spawn_flow_writeback(egress, cancellation.clone());

        for value in 1..=4 {
            writeback.send(vec![value]).unwrap();
        }

        for expected in 0..=4 {
            let packet = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                output.recv(),
            )
            .await
            .expect("writeback stalled")
            .expect("writeback closed");
            assert_eq!(packet, vec![expected]);
        }
        cancellation.cancel();
    }

    #[test]
    fn parses_ipv6_extension_chain_and_ignores_non_initial_fragments() {
        let mut packet = vec![0_u8; 68];
        packet[0] = 0x60;
        packet[6] = 0;
        packet[8..24].copy_from_slice(
            &"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets(),
        );
        packet[24..40].copy_from_slice(
            &"2001:db8::7"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        packet[40] = 17;
        packet[41] = 0;
        packet[48..50].copy_from_slice(&12345_u16.to_be_bytes());
        packet[50..52].copy_from_slice(&53_u16.to_be_bytes());
        assert_eq!(
            parse_transport_packet(&packet).unwrap(),
            TransportPacket::Udp {
                destination: "[2001:db8::7]:53".parse().unwrap(),
            }
        );

        packet[6] = 44;
        packet[40] = 17;
        packet[42..44].copy_from_slice(&8_u16.to_be_bytes());
        assert_eq!(
            parse_transport_packet(&packet).unwrap(),
            TransportPacket::Other
        );
    }

    #[test]
    fn parses_icmp_echo_without_treating_replies_as_new_flows() {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[8] = 51;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 7]);
        packet[20] = 8;
        packet[24..26].copy_from_slice(&0x1234_u16.to_be_bytes());
        assert_eq!(
            parse_transport_packet(&packet).unwrap(),
            TransportPacket::IcmpEcho {
                source: "10.0.0.2".parse().unwrap(),
                destination: "198.51.100.7".parse().unwrap(),
                hop_limit: 51,
                transport_offset: 20,
            }
        );
        packet[20] = 0;
        assert_eq!(
            parse_transport_packet(&packet).unwrap(),
            TransportPacket::Other
        );
    }

    #[test]
    fn reassembles_out_of_order_ipv4_icmp_fragments() {
        let mut message =
            b"\x08\x00\x00\x00\x12\x34\x00\x09fragmented-icmp".to_vec();
        let checksum = internet_checksum(&message);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());
        let fragment = |offset: usize, payload: &[u8], more: bool| {
            let mut packet = vec![0_u8; 20 + payload.len()];
            packet[0] = 0x45;
            let total = packet.len() as u16;
            packet[2..4].copy_from_slice(&total.to_be_bytes());
            packet[4..6].copy_from_slice(&77_u16.to_be_bytes());
            let field = ((offset / 8) as u16) | if more { 0x2000 } else { 0 };
            packet[6..8].copy_from_slice(&field.to_be_bytes());
            packet[8] = 43;
            packet[9] = 1;
            packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
            packet[16..20].copy_from_slice(&[198, 51, 100, 7]);
            packet[20..].copy_from_slice(payload);
            packet
        };
        let first = fragment(0, &message[..16], true);
        let second = fragment(16, &message[16..], false);
        let mut cache = IcmpFragmentCache::default();
        assert!(matches!(
            cache.push(&second).unwrap(),
            FragmentDisposition::Pending
        ));
        let FragmentDisposition::Complete(packet) = cache.push(&first).unwrap()
        else {
            panic!("fragments were not reassembled");
        };
        assert_eq!(&packet[20..], &message);
        assert_eq!(packet[6] & 0x20, 0);
        assert_eq!(internet_checksum(&packet[..20]), 0);
        assert!(matches!(
            parse_transport_packet(&packet).unwrap(),
            TransportPacket::IcmpEcho {
                hop_limit: 43,
                transport_offset: 20,
                ..
            }
        ));
    }

    #[test]
    fn reassembles_out_of_order_ipv6_icmp_fragments() {
        let message = b"\x80\x00\x00\x00\x56\x78\x00\x0aipv6frag";
        let fragment = |offset: usize, payload: &[u8], more: bool| {
            let mut packet = vec![0_u8; 48 + payload.len()];
            packet[0] = 0x60;
            let payload_len = (8 + payload.len()) as u16;
            packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
            packet[6] = 44;
            packet[7] = 39;
            packet[8..24].copy_from_slice(
                &"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            );
            packet[24..40].copy_from_slice(
                &"2001:db8::7"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
            packet[40] = 58;
            let field = (offset as u16) | u16::from(more);
            packet[42..44].copy_from_slice(&field.to_be_bytes());
            packet[44..48].copy_from_slice(&99_u32.to_be_bytes());
            packet[48..].copy_from_slice(payload);
            packet
        };
        let first = fragment(0, &message[..8], true);
        let second = fragment(8, &message[8..], false);
        let mut cache = IcmpFragmentCache::default();
        assert!(matches!(
            cache.push(&second).unwrap(),
            FragmentDisposition::Pending
        ));
        let FragmentDisposition::Complete(packet) = cache.push(&first).unwrap()
        else {
            panic!("fragments were not reassembled");
        };
        assert_eq!(packet[6], 58);
        assert_eq!(&packet[40..], message);
        assert!(matches!(
            parse_transport_packet(&packet).unwrap(),
            TransportPacket::IcmpEcho {
                hop_limit: 39,
                transport_offset: 40,
                ..
            }
        ));
    }

    #[test]
    fn rejects_conflicting_overlapping_icmp_fragments() {
        let mut first = vec![0_u8; 36];
        first[0] = 0x45;
        first[2..4].copy_from_slice(&36_u16.to_be_bytes());
        first[4..6].copy_from_slice(&7_u16.to_be_bytes());
        first[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        first[9] = 1;
        first[12..16].copy_from_slice(&[10, 0, 0, 2]);
        first[16..20].copy_from_slice(&[198, 51, 100, 7]);
        first[20..].fill(1);
        let mut overlap = first.clone();
        overlap[6..8].copy_from_slice(&1_u16.to_be_bytes());
        overlap[20..].fill(2);
        let mut cache = IcmpFragmentCache::default();
        assert!(matches!(
            cache.push(&first).unwrap(),
            FragmentDisposition::Pending
        ));
        assert!(cache.push(&overlap).is_err());
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn builds_valid_ipv4_and_ipv6_icmp_responses() {
        let mut echo4 = b"\x00\x00\x00\x00\x12\x34\x00\x01payload".to_vec();
        let checksum = internet_checksum(&echo4);
        echo4[2..4].copy_from_slice(&checksum.to_be_bytes());
        let packet4 = build_icmp_response_packet(
            "198.51.100.7".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            51,
            &echo4,
        )
        .unwrap();
        assert_eq!(packet4[0], 0x45);
        assert_eq!(packet4[8], 51);
        assert_eq!(internet_checksum(&packet4[..20]), 0);
        assert_eq!(internet_checksum(&packet4[20..]), 0);

        let source: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
        let destination: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
        let echo6 = b"\x81\x00\x00\x00\x12\x34\x00\x01payload";
        let packet6 = build_icmp_response_packet(
            source.into(),
            destination.into(),
            47,
            echo6,
        )
        .unwrap();
        assert_eq!(packet6[0], 0x60);
        assert_eq!(packet6[6], 58);
        assert_eq!(packet6[7], 47);
        assert_eq!(icmpv6_checksum(source, destination, &packet6[40..]), 0);

        let intermediate: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(
            icmp_response_source(
                "198.51.100.7".parse().unwrap(),
                &IcmpResponse {
                    source: intermediate,
                    packet: vec![11, 0, 0, 0, 0, 0, 0, 0],
                    hop_limit: 62,
                },
            ),
            intermediate,
        );
    }

    #[test]
    fn fragments_oversized_ipv4_icmp_response_at_effective_mtu() {
        let mut request_message = vec![0_u8; 2_008];
        request_message[0] = 8;
        request_message[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        request_message[6..8].copy_from_slice(&7_u16.to_be_bytes());
        let checksum = internet_checksum(&request_message);
        request_message[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut reply_message = request_message.clone();
        reply_message[0] = 0;
        reply_message[2..4].fill(0);
        let checksum = internet_checksum(&reply_message);
        reply_message[2..4].copy_from_slice(&checksum.to_be_bytes());
        let reply = build_icmp_response_packet(
            "198.51.100.7".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            62,
            &reply_message,
        )
        .unwrap();

        let fragments =
            prepare_icmp_egress(reply.clone(), 576, 0x4567, 0).unwrap();
        assert_eq!(fragments.len(), 4);
        let mut reassembled = Vec::new();
        for (index, fragment) in fragments.iter().enumerate() {
            assert!(fragment.len() <= 576);
            assert_eq!(&fragment[4..6], &0x4567_u16.to_be_bytes());
            assert_eq!(internet_checksum(&fragment[..20]), 0);
            let field = u16::from_be_bytes([fragment[6], fragment[7]]);
            assert_eq!(usize::from(field & 0x1fff) * 8, reassembled.len());
            assert_eq!(field & 0x2000 != 0, index + 1 < fragments.len());
            reassembled.extend_from_slice(&fragment[20..]);
        }
        assert_eq!(reassembled, reply[20..]);
    }

    #[test]
    fn fragments_locally_originated_ipv4_df_response_like_gvisor() {
        let mut reply_message = vec![0_u8; 800];
        reply_message[4..6].copy_from_slice(&0xabcd_u16.to_be_bytes());
        let checksum = internet_checksum(&reply_message);
        reply_message[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut reply = build_icmp_response_packet(
            "198.51.100.7".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            62,
            &reply_message,
        )
        .unwrap();
        reply[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        reply[10..12].fill(0);
        let checksum = internet_checksum(&reply[..20]);
        reply[10..12].copy_from_slice(&checksum.to_be_bytes());

        let fragments = prepare_icmp_egress(reply, 576, 0x4567, 0).unwrap();
        assert_eq!(fragments.len(), 2);
        for (index, fragment) in fragments.iter().enumerate() {
            let field = u16::from_be_bytes([fragment[6], fragment[7]]);
            assert_ne!(field & 0x4000, 0);
            assert_eq!(field & 0x2000 != 0, index == 0);
            assert_eq!(internet_checksum(&fragment[..20]), 0);
        }
    }

    #[test]
    fn source_fragments_oversized_ipv6_echo_response() {
        let source: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
        let destination: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
        let mut reply_message = vec![0_u8; 1_500];
        reply_message[0] = 129;
        reply_message[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        let checksum = icmpv6_checksum(destination, source, &reply_message);
        reply_message[2..4].copy_from_slice(&checksum.to_be_bytes());
        let reply = build_icmp_response_packet(
            destination.into(),
            source.into(),
            62,
            &reply_message,
        )
        .unwrap();

        let fragments =
            prepare_icmp_egress(reply, 1_400, 0, 0x89ab_cdef).unwrap();
        assert_eq!(fragments.len(), 2);
        let mut reassembled = Vec::new();
        for (index, fragment) in fragments.iter().enumerate() {
            assert!(fragment.len() <= 1_400);
            assert_eq!(fragment[6], 44);
            assert_eq!(fragment[40], 58);
            assert_eq!(
                u32::from_be_bytes([
                    fragment[44],
                    fragment[45],
                    fragment[46],
                    fragment[47],
                ]),
                0x89ab_cdef,
            );
            let offset_more = u16::from_be_bytes([fragment[42], fragment[43]]);
            assert_eq!(usize::from(offset_more & 0xfff8), reassembled.len());
            assert_eq!(offset_more & 1 != 0, index + 1 < fragments.len());
            reassembled.extend_from_slice(&fragment[48..]);
        }
        assert_eq!(reassembled, reply_message);
        assert_eq!(icmpv6_checksum(destination, source, &reassembled), 0);
    }

    #[test]
    fn udp_nat_mapping_and_filtering_follow_dependency_levels() {
        let client = "10.8.0.2:40000".parse().unwrap();
        let first = SocksAddr::new("198.51.100.1", 53);
        let same_address = SocksAddr::new("198.51.100.1", 5353);
        let second = SocksAddr::new("203.0.113.2", 53);

        assert_eq!(
            NatKey::new(
                UdpNatBehavior::EndpointIndependent,
                client,
                &first,
                None
            ),
            NatKey::new(
                UdpNatBehavior::EndpointIndependent,
                client,
                &second,
                None
            )
        );
        assert_eq!(
            NatKey::new(UdpNatBehavior::AddressDependent, client, &first, None),
            NatKey::new(
                UdpNatBehavior::AddressDependent,
                client,
                &same_address,
                None
            )
        );
        assert_ne!(
            NatKey::new(
                UdpNatBehavior::AddressAndPortDependent,
                client,
                &first,
                None
            ),
            NatKey::new(
                UdpNatBehavior::AddressAndPortDependent,
                client,
                &same_address,
                None
            )
        );
        assert_ne!(
            NatKey::new(
                UdpNatBehavior::EndpointIndependent,
                client,
                &first,
                Some(3)
            ),
            NatKey::new(
                UdpNatBehavior::EndpointIndependent,
                client,
                &first,
                Some(7)
            )
        );
    }
}
