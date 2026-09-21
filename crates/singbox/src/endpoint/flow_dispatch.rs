//! Stateful raw-IP flow forwarding between userspace endpoints.
//!
//! This mirrors the central contract of sing-tun's `ForwardDispatcher`: a
//! packet selected for an L3 outbound is source-NATed to that port's address,
//! while replies are matched and rewritten back to the original tunnel flow.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::mpsc;

use crate::{
    adapter::{IpPacketPort, IpPacketReturn},
    common::network::{Network, SocksAddr},
    inbound::{sniff_and_route_packet, socks::restore_fake_ip},
    outbound::{OutboundManager, PacketFlowTracker},
    route::{Action, Metadata, Router},
};

const NAT_SELECTOR_START: u16 = 49_152;
const FLOW_CAPACITY: usize = 16_384;
const TCP_TRANSITORY_TIMEOUT: Duration = Duration::from_secs(4 * 60);
const TCP_ESTABLISHED_TIMEOUT: Duration =
    Duration::from_secs(2 * 60 * 60 + 4 * 60);
const TCP_CLOSING_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
// sing-tun's internal fallback is one minute, but pinned sing-box always
// supplies its public connection timeout (10 seconds) to every endpoint.
const ICMP_TIMEOUT: Duration = crate::constant::ICMP_TIMEOUT;
const FLOW_TOMBSTONE_TIMEOUT: Duration = Duration::from_secs(4 * 60);
const FLOW_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
const FLOW_SWEEP_LIMIT: usize = FLOW_CAPACITY / 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    protocol: u8,
    source: SocketAddr,
    destination: SocketAddr,
}

impl FlowKey {
    fn reversed(self) -> Self {
        Self {
            protocol: self.protocol,
            source: self.destination,
            destination: self.source,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Rewrite {
    source_address: IpAddr,
    source_selector: u16,
    destination_address: IpAddr,
    destination_selector: u16,
}

struct Flow {
    forward_key: FlowKey,
    reverse_key: FlowKey,
    port_id: usize,
    forward: Rewrite,
    reverse: Rewrite,
    port: Arc<dyn IpPacketPort>,
    mtu: usize,
    protocol: u8,
    udp_timeout: Duration,
    idle: Mutex<Duration>,
    expires_at: Mutex<Instant>,
    last_reverse: Mutex<Option<Instant>>,
    fin_forward: AtomicBool,
    established: AtomicBool,
    fin_reverse: AtomicBool,
    reported: AtomicBool,
    closed: AtomicBool,
    tombstoned: AtomicBool,
    tracker: PacketFlowTracker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimpleAction {
    Accept,
    Reject,
    Drop,
}

struct SimpleEntry {
    action: SimpleAction,
    idle: Duration,
    expires_at: Instant,
}

struct PortNatState {
    port: Weak<dyn IpPacketPort>,
    selector_range: (u16, u16),
    counter: u32,
}

impl Flow {
    fn idle_timeout(&self) -> Duration {
        match self.protocol {
            6 if self.fin_forward.load(Ordering::Relaxed)
                && self.fin_reverse.load(Ordering::Relaxed) =>
            {
                TCP_CLOSING_TIMEOUT
            }
            6 if self.established.load(Ordering::Relaxed)
                && !self.fin_forward.load(Ordering::Relaxed)
                && !self.fin_reverse.load(Ordering::Relaxed) =>
            {
                TCP_ESTABLISHED_TIMEOUT
            }
            6 => TCP_TRANSITORY_TIMEOUT,
            17 => self.udp_timeout,
            _ => ICMP_TIMEOUT,
        }
    }

    fn refresh_forward_deadline(&self, now: Instant) {
        let idle = self.idle_timeout();
        if let Ok(mut current) = self.idle.lock() {
            *current = idle;
        }
        if let Ok(mut expires_at) = self.expires_at.lock() {
            *expires_at = now + idle;
        }
    }

    fn expired(&self, now: Instant) -> bool {
        let Ok(mut expires_at) = self.expires_at.lock() else {
            return true;
        };
        if now <= *expires_at {
            return false;
        }
        let last_reverse =
            self.last_reverse.lock().ok().and_then(|value| *value);
        if let Some(last_reverse) = last_reverse {
            let idle = self.idle.lock().map(|idle| *idle).unwrap_or_default();
            let reverse_deadline = last_reverse + idle;
            if now <= reverse_deadline {
                *expires_at = reverse_deadline;
                return false;
            }
        }
        true
    }

    fn observe_forward(&self, packet: ParsedPacket, now: Instant) -> bool {
        if self.protocol == 6 {
            if packet.tcp_flags & 0x01 != 0 {
                self.fin_forward.store(true, Ordering::Relaxed);
            } else if self.fin_forward.load(Ordering::Relaxed)
                && self.fin_reverse.load(Ordering::Relaxed)
            {
                self.report();
            }
            if packet.tcp_flags & 0x04 != 0 {
                return true;
            }
        }
        self.refresh_forward_deadline(now);
        false
    }

    fn observe_reverse(&self, packet: ParsedPacket, now: Instant) {
        if let Ok(mut last_reverse) = self.last_reverse.lock() {
            *last_reverse = Some(now);
        }
        if self.protocol == 6 {
            self.established.store(true, Ordering::Relaxed);
            if packet.tcp_flags & 0x01 != 0 {
                self.fin_reverse.store(true, Ordering::Relaxed);
            } else if self.fin_reverse.load(Ordering::Relaxed)
                && self.fin_forward.load(Ordering::Relaxed)
            {
                self.report();
            }
            if packet.tcp_flags & 0x04 != 0 {
                self.close();
            }
        }
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.report();
        }
    }

    fn touch_tombstone(&self, now: Instant) {
        self.tombstoned.store(true, Ordering::Release);
        if let Ok(mut idle) = self.idle.lock() {
            *idle = FLOW_TOMBSTONE_TIMEOUT;
        }
        if let Ok(mut expires_at) = self.expires_at.lock() {
            *expires_at = now + FLOW_TOMBSTONE_TIMEOUT;
        }
    }

    fn report(&self) {
        if !self.reported.swap(true, Ordering::AcqRel) {
            self.tracker.close();
        }
    }
}

#[derive(Default)]
struct State {
    forward: HashMap<FlowKey, Arc<Flow>>,
    simple: HashMap<FlowKey, SimpleEntry>,
    reverse: HashMap<(usize, FlowKey), Arc<Flow>>,
    ports: HashMap<usize, PortNatState>,
    port_order: Vec<usize>,
    port_by_address: HashMap<IpAddr, usize>,
    last_sweep: Option<Instant>,
    sweep_cursor: usize,
    eviction_cursor: usize,
}

#[derive(Clone, Copy)]
enum StateEntryKey {
    Flow(FlowKey),
    Simple(FlowKey),
}

struct SweepAfterDispatch<'a>(&'a FlowDispatcher);

impl Drop for SweepAfterDispatch<'_> {
    fn drop(&mut self) {
        self.0.maybe_sweep(Instant::now());
    }
}

pub(crate) struct FlowDispatcher {
    inbound: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    writeback: mpsc::UnboundedSender<Vec<u8>>,
    udp_timeout: Duration,
    state: Mutex<State>,
    self_return: OnceLock<Weak<dyn IpPacketReturn>>,
}

impl FlowDispatcher {
    pub(crate) fn new(
        inbound: impl Into<String>,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        writeback: mpsc::UnboundedSender<Vec<u8>>,
        udp_timeout: Duration,
    ) -> Arc<Self> {
        let dispatcher = Arc::new(Self {
            inbound: inbound.into(),
            router,
            outbounds,
            writeback,
            udp_timeout: if udp_timeout.is_zero() {
                UDP_TIMEOUT
            } else {
                udp_timeout
            },
            state: Mutex::new(State::default()),
            self_return: OnceLock::new(),
        });
        let return_path: Arc<dyn IpPacketReturn> = dispatcher.clone();
        let _ = dispatcher.self_return.set(Arc::downgrade(&return_path));
        dispatcher
    }

    pub(crate) async fn dispatch(
        self: &Arc<Self>,
        packet: &[u8],
    ) -> io::Result<bool> {
        // sing-tun sweeps from `Flush`, after the current packet batch has
        // been dispatched. Keeping the guard alive across every return path
        // preserves that ordering without duplicating cleanup calls, even
        // when the packet is malformed, fragmented, or has no trackable flow.
        let _sweep_after_dispatch = SweepAfterDispatch(self);
        let parsed = match ParsedPacket::parse(packet) {
            Some(parsed) if !parsed.fragmented => parsed,
            _ => return Ok(false),
        };
        let Some(forward_key) = parsed.flow_key() else {
            return Ok(false);
        };

        if let Some(flow) = self.lookup_forward(&forward_key) {
            let now = Instant::now();
            if flow.tracker.cancelled() {
                flow.close();
            }
            if flow.closed.load(Ordering::Acquire) {
                flow.touch_tombstone(now);
                return Ok(true);
            }
            let reset = flow.observe_forward(parsed, now);
            if let Err(error) = self.forward_to_port(&flow, packet).await {
                tracing::trace!(%error, "forward raw IP flow packet");
            }
            if reset {
                flow.close();
                flow.touch_tombstone(now);
            }
            return Ok(true);
        }
        if let Some(handled) = self.handle_simple(&forward_key, parsed, packet)
        {
            return Ok(handled);
        }

        if parsed.protocol == 6 && !parsed.initial_tcp_syn() {
            return Ok(false);
        }
        let source = parsed.source;
        let original_destination = parsed.destination;
        let network = match parsed.protocol {
            6 => Network::Tcp,
            17 => Network::Udp,
            1 | 58 if parsed.is_icmp_echo_request() => Network::Icmp,
            _ => return Ok(false),
        };
        let original_socks = SocksAddr::from(SocketAddr::new(
            original_destination.ip(),
            if network == Network::Icmp {
                0
            } else {
                original_destination.port()
            },
        ));
        let (destination, fake_origin) =
            restore_fake_ip(original_socks.clone(), &self.outbounds)?;
        let mut metadata = Metadata {
            inbound: self.inbound.clone(),
            source: Some(SocksAddr::from(SocketAddr::new(
                source.ip(),
                if network == Network::Icmp {
                    0
                } else {
                    source.port()
                },
            ))),
            destination: Some(destination.clone()),
            origin_destination: fake_origin.clone(),
            fake_ip: fake_origin.is_some(),
            network: Some(network),
            ..Metadata::default()
        };
        let first_packet = if parsed.protocol == 17 {
            packet
                .get(parsed.transport_offset + 8..parsed.packet_len)
                .unwrap_or_default()
        } else {
            &[]
        };
        let decision = sniff_and_route_packet(
            first_packet,
            &mut metadata,
            &self.router,
            &self.outbounds,
        )
        .await?;
        if let Some(Action::Reject { method, .. }) = decision.action() {
            let action = if method == "drop" || decision.reject_is_drop() {
                SimpleAction::Drop
            } else {
                SimpleAction::Reject
            };
            self.install_simple(forward_key, action, parsed.protocol);
            if action == SimpleAction::Reject
                && let Some(reply) = build_reject(packet, parsed)
            {
                let _ = self.writeback.send(reply);
            }
            return Ok(true);
        }
        if matches!(decision.action(), Some(Action::HijackDns)) {
            return Ok(false);
        }
        let accept = || {
            self.install_simple(
                forward_key,
                SimpleAction::Accept,
                parsed.protocol,
            );
            false
        };
        if matches!(decision.action(), Some(Action::Direct))
            || matches!(
                decision.action(),
                Some(Action::Bypass { outbound, .. }) if outbound.is_empty()
            )
        {
            return Ok(accept());
        }
        let Some(dialer) = self.outbounds.select(decision.outbound()) else {
            return Ok(accept());
        };
        let Some(port) = dialer.packet_port() else {
            return Ok(accept());
        };
        let routed_destination = decision.destination(&destination);
        let udp_timeout = decision
            .connection_options()
            .udp_timeout
            .unwrap_or(self.udp_timeout);
        let routed_destination = match routed_destination {
            SocksAddr::Ip(destination) => destination,
            SocksAddr::Domain { port, .. } => {
                let Some(address) = metadata
                    .destination_addresses
                    .iter()
                    .copied()
                    .find(|address| address.is_ipv4() == source.is_ipv4())
                else {
                    return Ok(accept());
                };
                SocketAddr::new(address, port)
            }
        };
        if routed_destination.is_ipv4() != source.is_ipv4() {
            return Ok(accept());
        }
        let port_address = if source.is_ipv4() {
            port.port_addresses().0
        } else {
            port.port_addresses().1
        };
        let Some(port_address) = port_address else {
            return Ok(accept());
        };
        if source.is_ipv6() && port.port_mtu() != 0 && port.port_mtu() < 1280 {
            return Ok(accept());
        }
        let port_id = match self.ensure_return_attached(port.clone()) {
            Ok(port_id) => port_id,
            Err(error) => {
                tracing::trace!(%error, "attach raw IP flow return path");
                return Ok(accept());
            }
        };
        let selector = match self.allocate_selector(
            port_id,
            parsed.protocol,
            port_address,
            routed_destination,
            source.port(),
        ) {
            Ok(selector) => selector,
            Err(error) => {
                tracing::warn!(%error, %routed_destination, "raw IP flow selector range exhausted");
                self.install_simple(
                    forward_key,
                    SimpleAction::Reject,
                    parsed.protocol,
                );
                if let Some(reply) = build_reject(packet, parsed) {
                    let _ = self.writeback.send(reply);
                }
                return Ok(true);
            }
        };
        let server_selector = if parsed.is_icmp() {
            selector
        } else {
            routed_destination.port()
        };
        let reverse_key = FlowKey {
            protocol: parsed.protocol,
            source: SocketAddr::new(routed_destination.ip(), server_selector),
            destination: SocketAddr::new(port_address, selector),
        };
        let tracker = self.outbounds.register_packet_flow(
            decision.outbound().unwrap_or("direct"),
            &destination,
            match network {
                Network::Tcp => "tcp",
                Network::Udp => "udp",
                Network::Icmp => "icmp",
            },
        );
        let flow = Arc::new(Flow {
            forward_key,
            reverse_key,
            port_id,
            forward: Rewrite {
                source_address: port_address,
                source_selector: selector,
                destination_address: routed_destination.ip(),
                destination_selector: if parsed.is_icmp() {
                    selector
                } else {
                    routed_destination.port()
                },
            },
            reverse: Rewrite {
                source_address: original_destination.ip(),
                source_selector: original_destination.port(),
                destination_address: source.ip(),
                destination_selector: source.port(),
            },
            port: port.clone(),
            mtu: port.port_mtu(),
            protocol: parsed.protocol,
            udp_timeout,
            idle: Mutex::new(if parsed.protocol == 6 {
                TCP_TRANSITORY_TIMEOUT
            } else if parsed.protocol == 17 {
                udp_timeout
            } else {
                ICMP_TIMEOUT
            }),
            expires_at: Mutex::new(
                Instant::now()
                    + if parsed.protocol == 6 {
                        TCP_TRANSITORY_TIMEOUT
                    } else if parsed.protocol == 17 {
                        udp_timeout
                    } else {
                        ICMP_TIMEOUT
                    },
            ),
            last_reverse: Mutex::new(None),
            fin_forward: AtomicBool::new(false),
            established: AtomicBool::new(false),
            fin_reverse: AtomicBool::new(false),
            reported: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            tombstoned: AtomicBool::new(false),
            tracker,
        });
        self.insert_flow(flow.clone());

        if let Err(error) = self.forward_to_port(&flow, packet).await {
            tracing::trace!(%error, "forward initial raw IP flow packet");
        }
        Ok(true)
    }

    async fn forward_to_port(
        &self,
        flow: &Flow,
        packet: &[u8],
    ) -> io::Result<()> {
        let parsed = ParsedPacket::parse(packet).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid IP packet")
        })?;
        let packet = &packet[..parsed.packet_len];
        if flow.mtu != 0 && packet.len() > flow.mtu {
            if parsed.protocol == 6 {
                flow.tracker.count_forward(packet.len());
                let mut forwarded = packet.to_vec();
                let reparsed =
                    ParsedPacket::parse(&forwarded).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid IP packet",
                        )
                    })?;
                rewrite_packet(&mut forwarded, reparsed, flow.forward)?;
                clamp_tcp_mss(&mut forwarded, reparsed, flow.mtu)?;
                if reparsed.ip_version == 6 && reparsed.transport_offset != 40 {
                    self.stage_packet_too_big(packet, reparsed, flow.mtu);
                    return Ok(());
                }
                let segments =
                    segment_tcp_packet(&forwarded, reparsed, flow.mtu)?;
                if segments.is_empty() {
                    return Ok(());
                }
                return flow.port.write_packets(segments).await;
            }
            if parsed.ip_version == 4 {
                let flags_fragment = u16::from_be_bytes([packet[6], packet[7]]);
                if flags_fragment & 0x4000 == 0 {
                    flow.tracker.count_forward(packet.len());
                    let mut forwarded = packet.to_vec();
                    let reparsed =
                        ParsedPacket::parse(&forwarded).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid IP packet",
                            )
                        })?;
                    rewrite_packet(&mut forwarded, reparsed, flow.forward)?;
                    let fragments =
                        fragment_ipv4_packet(&forwarded, reparsed, flow.mtu)?;
                    if fragments.is_empty() {
                        return Ok(());
                    }
                    return flow.port.write_packets(fragments).await;
                }
                if let Some(reply) =
                    build_fragmentation_needed(packet, parsed, flow.mtu)
                {
                    let _ = self.writeback.send(reply);
                }
                return Ok(());
            }
            self.stage_packet_too_big(packet, parsed, flow.mtu);
            return Ok(());
        }

        flow.tracker.count_forward(packet.len());
        let mut forwarded = packet.to_vec();
        let reparsed = ParsedPacket::parse(&forwarded).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid IP packet")
        })?;
        rewrite_packet(&mut forwarded, reparsed, flow.forward)?;
        clamp_tcp_mss(&mut forwarded, reparsed, flow.mtu)?;
        flow.port.write_packets(vec![forwarded]).await
    }

    fn stage_packet_too_big(
        &self,
        packet: &[u8],
        parsed: ParsedPacket,
        mtu: usize,
    ) {
        if let Some(reply) = build_packet_too_big(packet, parsed, mtu) {
            let _ = self.writeback.send(reply);
        }
    }

    fn lookup_forward(&self, key: &FlowKey) -> Option<Arc<Flow>> {
        let now = Instant::now();
        let mut state = self.state.lock().ok()?;
        let flow = state.forward.get(key)?.clone();
        if flow.expired(now) {
            state.forward.remove(&flow.forward_key);
            state.reverse.remove(&(flow.port_id, flow.reverse_key));
            return None;
        }
        Some(flow)
    }

    fn handle_simple(
        &self,
        key: &FlowKey,
        packet: ParsedPacket,
        raw: &[u8],
    ) -> Option<bool> {
        let now = Instant::now();
        let action = {
            let mut state = self.state.lock().ok()?;
            let entry = state.simple.get_mut(key)?;
            if now > entry.expires_at {
                state.simple.remove(key);
                return None;
            }
            if entry.action == SimpleAction::Accept && packet.protocol == 6 {
                if packet.tcp_flags & 0x04 != 0 {
                    state.simple.remove(key);
                    return Some(false);
                }
                if packet.tcp_flags & 0x02 == 0 {
                    entry.idle = TCP_ESTABLISHED_TIMEOUT;
                }
            }
            entry.expires_at = now + entry.idle;
            entry.action
        };
        match action {
            SimpleAction::Accept => Some(false),
            SimpleAction::Drop => Some(true),
            SimpleAction::Reject => {
                if let Some(reply) = build_reject(raw, packet) {
                    let _ = self.writeback.send(reply);
                }
                Some(true)
            }
        }
    }

    fn install_simple(&self, key: FlowKey, action: SimpleAction, protocol: u8) {
        let now = Instant::now();
        let idle = match protocol {
            6 => TCP_TRANSITORY_TIMEOUT,
            17 => self.udp_timeout,
            _ => ICMP_TIMEOUT,
        };
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        Self::evict_if_full(&mut state, now);
        state.simple.insert(
            key,
            SimpleEntry {
                action,
                idle,
                expires_at: now + idle,
            },
        );
    }

    fn maybe_sweep(&self, now: Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state
            .last_sweep
            .is_some_and(|last| now.duration_since(last) < FLOW_SWEEP_INTERVAL)
        {
            return;
        }
        state.last_sweep = Some(now);
        let keys = state
            .forward
            .keys()
            .copied()
            .map(StateEntryKey::Flow)
            .chain(state.simple.keys().copied().map(StateEntryKey::Simple))
            .collect::<Vec<_>>();
        let scan_count = keys.len().min(FLOW_SWEEP_LIMIT);
        let start = if keys.is_empty() {
            0
        } else {
            state.sweep_cursor % keys.len()
        };
        let scanned = (0..scan_count)
            .map(|offset| keys[(start + offset) % keys.len()])
            .collect::<Vec<_>>();
        state.sweep_cursor = if keys.is_empty() {
            0
        } else {
            (start + scan_count) % keys.len()
        };
        for key in scanned {
            match key {
                StateEntryKey::Flow(key) => {
                    let Some(flow) = state.forward.get(&key).cloned() else {
                        continue;
                    };
                    if flow.closed.load(Ordering::Acquire)
                        && !flow.tombstoned.load(Ordering::Acquire)
                    {
                        flow.touch_tombstone(now);
                    } else if flow.expired(now) {
                        Self::remove_state_entry(
                            &mut state,
                            StateEntryKey::Flow(key),
                        );
                    }
                }
                StateEntryKey::Simple(key) => {
                    if state
                        .simple
                        .get(&key)
                        .is_some_and(|entry| now > entry.expires_at)
                    {
                        Self::remove_state_entry(
                            &mut state,
                            StateEntryKey::Simple(key),
                        );
                    }
                }
            }
        }
    }

    /// Drop every cached verdict and active raw-IP NAT mapping after the host
    /// network changes. Attached packet ports remain registered, matching
    /// sing-tun's `ForwardDispatcher.ResetNetwork` contract.
    pub(crate) fn reset_network(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let flows = state
            .forward
            .drain()
            .map(|(_, flow)| flow)
            .collect::<Vec<_>>();
        state.reverse.clear();
        state.simple.clear();
        state.last_sweep = None;
        state.sweep_cursor = 0;
        state.eviction_cursor = 0;
        drop(state);
        for flow in flows {
            flow.close();
        }
    }

    fn ensure_return_attached(
        &self,
        port: Arc<dyn IpPacketPort>,
    ) -> io::Result<usize> {
        let id = Arc::as_ptr(&port) as *const () as usize;
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("flow table lock poisoned"))?;
            if state
                .ports
                .get(&id)
                .and_then(|nat| nat.port.upgrade())
                .is_some()
            {
                return Ok(id);
            }
            state.ports.remove(&id);
            state.port_order.retain(|port_id| *port_id != id);
            state.port_by_address.retain(|_, port_id| *port_id != id);
        }
        let return_path =
            self.self_return.get().cloned().ok_or_else(|| {
                io::Error::other("flow return path unavailable")
            })?;
        let selector_range = port.port_selector_range();
        if selector_range.1 != 0
            && u32::from(selector_range.0) + u32::from(selector_range.1)
                > u32::from(u16::MAX) + 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid IP packet port selector range",
            ));
        }
        port.attach_return(return_path)?;
        let addresses = port.port_addresses();
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("flow table lock poisoned"))?;
        if !state.ports.contains_key(&id) {
            state.port_order.push(id);
            for address in [addresses.0, addresses.1].into_iter().flatten() {
                // As in sing-tun's revNAT map, the most recently attached
                // port is the preferred lookup for a shared port address.
                state.port_by_address.insert(address, id);
            }
            state.ports.insert(
                id,
                PortNatState {
                    port: Arc::downgrade(&port),
                    selector_range,
                    counter: 0,
                },
            );
        }
        Ok(id)
    }

    fn lookup_reverse(state: &State, key: FlowKey) -> Option<Arc<Flow>> {
        if let Some(port_id) = state.port_by_address.get(&key.destination.ip())
            && let Some(flow) = state.reverse.get(&(*port_id, key))
        {
            return Some(flow.clone());
        }
        state
            .port_order
            .iter()
            .find_map(|port_id| state.reverse.get(&(*port_id, key)).cloned())
    }

    fn allocate_selector(
        &self,
        port_id: usize,
        protocol: u8,
        port_address: IpAddr,
        server: SocketAddr,
        preferred: u16,
    ) -> io::Result<u16> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("flow table lock poisoned"))?;
        let free = |candidate: u16, state: &State| {
            let source_selector = if protocol == 1 || protocol == 58 {
                candidate
            } else {
                server.port()
            };
            !state.reverse.contains_key(&(
                port_id,
                FlowKey {
                    protocol,
                    source: SocketAddr::new(server.ip(), source_selector),
                    destination: SocketAddr::new(port_address, candidate),
                },
            ))
        };
        let nat = state.ports.get(&port_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "IP packet port return path is not attached",
            )
        })?;
        let selector_range = nat.selector_range;
        let mut counter = nat.counter;
        let selector_range = if protocol == 1 || protocol == 58 {
            (0, 0)
        } else {
            selector_range
        };
        let (selector_start, selector_count) = match selector_range {
            (_, 0) => (
                NAT_SELECTOR_START,
                u32::from(u16::MAX) - u32::from(NAT_SELECTOR_START) + 1,
            ),
            (start, count)
                if u32::from(start) + u32::from(count)
                    <= u32::from(u16::MAX) + 1 =>
            {
                (start, u32::from(count))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid IP packet port selector range",
                ));
            }
        };
        let selector_end = u32::from(selector_start) + selector_count;
        if preferred != 0
            && u32::from(preferred) >= u32::from(selector_start)
            && u32::from(preferred) < selector_end
            && free(preferred, &state)
        {
            return Ok(preferred);
        }
        for _ in 0..selector_count {
            counter = counter.wrapping_add(1);
            let candidate =
                (u32::from(selector_start) + counter % selector_count) as u16;
            if free(candidate, &state) {
                if let Some(nat) = state.ports.get_mut(&port_id) {
                    nat.counter = counter;
                }
                return Ok(candidate);
            }
        }
        if let Some(nat) = state.ports.get_mut(&port_id) {
            nat.counter = counter;
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "IP packet flow selector range exhausted",
        ))
    }

    fn insert_flow(&self, flow: Arc<Flow>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        Self::evict_if_full(&mut state, Instant::now());
        state.forward.insert(flow.forward_key, flow.clone());
        state.reverse.insert((flow.port_id, flow.reverse_key), flow);
    }

    fn evict_if_full(state: &mut State, now: Instant) {
        if state.forward.len() + state.simple.len() < FLOW_CAPACITY {
            return;
        }
        let keys = state
            .forward
            .keys()
            .copied()
            .map(StateEntryKey::Flow)
            .chain(state.simple.keys().copied().map(StateEntryKey::Simple))
            .collect::<Vec<_>>();
        if keys.is_empty() {
            return;
        }
        let scan_count = keys.len().min(FLOW_SWEEP_LIMIT);
        let start = state.eviction_cursor % keys.len();
        state.eviction_cursor = (start + scan_count) % keys.len();
        let mut expired = Vec::new();
        let mut oldest: Option<(StateEntryKey, Instant)> = None;
        for offset in 0..scan_count {
            let key = keys[(start + offset) % keys.len()];
            let (is_expired, deadline) = match key {
                StateEntryKey::Flow(key) => {
                    let Some(flow) = state.forward.get(&key) else {
                        continue;
                    };
                    let is_expired = flow.expired(now);
                    let deadline = flow
                        .expires_at
                        .lock()
                        .map(|deadline| *deadline)
                        .unwrap_or(now);
                    (is_expired, deadline)
                }
                StateEntryKey::Simple(key) => {
                    let Some(entry) = state.simple.get(&key) else {
                        continue;
                    };
                    (now > entry.expires_at, entry.expires_at)
                }
            };
            if is_expired {
                expired.push(key);
            } else if oldest
                .as_ref()
                .is_none_or(|(_, oldest_deadline)| deadline < *oldest_deadline)
            {
                oldest = Some((key, deadline));
            }
        }
        if expired.is_empty() {
            if let Some((key, _)) = oldest {
                Self::remove_state_entry(state, key);
            }
        } else {
            for key in expired {
                Self::remove_state_entry(state, key);
            }
        }
    }

    fn remove_state_entry(state: &mut State, key: StateEntryKey) {
        match key {
            StateEntryKey::Flow(key) => {
                if let Some(flow) = state.forward.remove(&key) {
                    state.reverse.remove(&(flow.port_id, flow.reverse_key));
                    flow.close();
                }
            }
            StateEntryKey::Simple(key) => {
                state.simple.remove(&key);
            }
        };
    }
}

impl Drop for FlowDispatcher {
    fn drop(&mut self) {
        let Some(return_path) = self.self_return.get() else {
            return;
        };
        if let Ok(state) = self.state.lock() {
            for flow in state.forward.values() {
                flow.close();
            }
            for port in
                state.ports.values().filter_map(|nat| nat.port.upgrade())
            {
                port.detach_return(return_path);
            }
        }
    }
}

impl IpPacketReturn for FlowDispatcher {
    fn return_packets(&self, packets: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut unconsumed = Vec::new();
        for mut packet in packets {
            let parsed = match ParsedPacket::parse(&packet) {
                Some(parsed) if !parsed.fragmented => parsed,
                _ => {
                    unconsumed.push(packet);
                    continue;
                }
            };
            let Some(key) = parsed.flow_key() else {
                if parsed.is_icmp_error()
                    && self.return_icmp_error(&mut packet, parsed)
                {
                    if self.writeback.send(packet).is_err() {
                        continue;
                    }
                    continue;
                }
                unconsumed.push(packet);
                continue;
            };
            let flow = self
                .state
                .lock()
                .ok()
                .and_then(|state| Self::lookup_reverse(&state, key));
            let Some(flow) = flow else {
                unconsumed.push(packet);
                continue;
            };
            let now = Instant::now();
            if flow.tracker.cancelled() {
                flow.close();
            }
            if flow.closed.load(Ordering::Acquire) {
                continue;
            }
            flow.tracker.count_reverse(packet.len());
            flow.observe_reverse(parsed, now);
            if rewrite_packet(&mut packet, parsed, flow.reverse).is_err() {
                continue;
            }
            if parsed.protocol == 6
                && clamp_tcp_mss(&mut packet, parsed, flow.mtu).is_err()
            {
                continue;
            }
            if self.writeback.send(packet).is_err() {
                // A stopped source endpoint must not divert the packet into
                // the destination endpoint's own stack.
                continue;
            }
        }
        unconsumed
    }
}

impl FlowDispatcher {
    fn return_icmp_error(
        &self,
        packet: &mut [u8],
        parsed: ParsedPacket,
    ) -> bool {
        let Some(embedded) = EmbeddedPacket::parse(packet, parsed) else {
            return false;
        };
        let reverse_key = embedded.flow_key().reversed();
        let flow = self
            .state
            .lock()
            .ok()
            .and_then(|state| Self::lookup_reverse(&state, reverse_key));
        let Some(flow) = flow else {
            return false;
        };
        if flow.tracker.cancelled() {
            flow.close();
        }
        if flow.closed.load(Ordering::Acquire) {
            return false;
        }
        if rewrite_embedded_packet(
            packet,
            embedded,
            flow.reverse.destination_address,
            flow.reverse.destination_selector,
            flow.reverse.source_address,
            flow.reverse.source_selector,
        )
        .is_err()
        {
            return false;
        }
        let outer_source =
            if parsed.source.ip() == flow.forward.destination_address {
                flow.reverse.source_address
            } else {
                parsed.source.ip()
            };
        let rewrite = Rewrite {
            source_address: outer_source,
            source_selector: parsed.source.port(),
            destination_address: flow.reverse.destination_address,
            destination_selector: parsed.destination.port(),
        };
        rewrite_packet(packet, parsed, rewrite).is_ok()
    }
}

#[derive(Debug, Clone, Copy)]
struct ParsedPacket {
    ip_version: u8,
    protocol: u8,
    source: SocketAddr,
    destination: SocketAddr,
    ip_header_len: usize,
    transport_offset: usize,
    packet_len: usize,
    tcp_flags: u8,
    icmp_type: u8,
    has_flow: bool,
    fragmented: bool,
}

impl ParsedPacket {
    fn parse(packet: &[u8]) -> Option<Self> {
        let version = packet.first()? >> 4;
        match version {
            4 => Self::parse_v4(packet),
            6 => Self::parse_v6(packet),
            _ => None,
        }
    }

    fn parse_v4(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let packet_len =
            usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if header_len < 20
            || packet_len < header_len
            || packet_len > packet.len()
        {
            return None;
        }
        let fragment = u16::from_be_bytes([packet[6], packet[7]]);
        let source = IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ));
        let destination = IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ));
        Self::finish(
            packet,
            4,
            packet[9],
            source,
            destination,
            header_len,
            header_len,
            packet_len,
            fragment & 0x3fff != 0,
        )
    }

    fn parse_v6(packet: &[u8]) -> Option<Self> {
        if packet.len() < 40 {
            return None;
        }
        let payload_len =
            usize::from(u16::from_be_bytes([packet[4], packet[5]]));
        let packet_len = 40usize.checked_add(payload_len)?;
        if packet_len > packet.len() {
            return None;
        }
        let source = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[8..24]).ok()?,
        ));
        let destination = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).ok()?,
        ));
        let mut protocol = packet[6];
        let mut offset = 40;
        loop {
            match protocol {
                0 | 43 | 60 => {
                    let extension = packet.get(offset..packet_len)?;
                    if extension.len() < 2 {
                        return None;
                    }
                    let length = (usize::from(extension[1]) + 1) * 8;
                    if length > extension.len() {
                        return None;
                    }
                    protocol = extension[0];
                    offset += length;
                }
                44 => {
                    return Self::finish(
                        packet,
                        6,
                        protocol,
                        source,
                        destination,
                        40,
                        offset,
                        packet_len,
                        true,
                    );
                }
                _ => break,
            }
        }
        Self::finish(
            packet,
            6,
            protocol,
            source,
            destination,
            40,
            offset,
            packet_len,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        packet: &[u8],
        ip_version: u8,
        protocol: u8,
        source_ip: IpAddr,
        destination_ip: IpAddr,
        ip_header_len: usize,
        transport_offset: usize,
        packet_len: usize,
        fragmented: bool,
    ) -> Option<Self> {
        if fragmented {
            return Some(Self {
                ip_version,
                protocol,
                source: SocketAddr::new(source_ip, 0),
                destination: SocketAddr::new(destination_ip, 0),
                ip_header_len,
                transport_offset,
                packet_len,
                tcp_flags: 0,
                icmp_type: 0,
                has_flow: false,
                fragmented,
            });
        }
        let transport = packet.get(transport_offset..packet_len)?;
        let (
            source_selector,
            destination_selector,
            tcp_flags,
            icmp_type,
            has_flow,
        ) = match protocol {
            6 if transport.len() >= 20 => (
                u16::from_be_bytes([transport[0], transport[1]]),
                u16::from_be_bytes([transport[2], transport[3]]),
                transport[13],
                0,
                true,
            ),
            17 if transport.len() >= 8 => (
                u16::from_be_bytes([transport[0], transport[1]]),
                u16::from_be_bytes([transport[2], transport[3]]),
                0,
                0,
                true,
            ),
            1 | 58 if transport.len() >= 8 => {
                let identifier =
                    u16::from_be_bytes([transport[4], transport[5]]);
                let icmp_type = transport[0];
                let has_flow = matches!(
                    (protocol, icmp_type),
                    (1, 0 | 8) | (58, 128 | 129)
                );
                (identifier, identifier, 0, icmp_type, has_flow)
            }
            _ => (0, 0, 0, 0, false),
        };
        Some(Self {
            ip_version,
            protocol,
            source: SocketAddr::new(source_ip, source_selector),
            destination: SocketAddr::new(destination_ip, destination_selector),
            ip_header_len,
            transport_offset,
            packet_len,
            tcp_flags,
            icmp_type,
            has_flow,
            fragmented,
        })
    }

    fn flow_key(self) -> Option<FlowKey> {
        self.has_flow.then_some(FlowKey {
            protocol: self.protocol,
            source: self.source,
            destination: self.destination,
        })
    }

    fn is_icmp(self) -> bool {
        self.protocol == 1 || self.protocol == 58
    }

    fn is_icmp_echo_request(self) -> bool {
        matches!((self.protocol, self.icmp_type), (1, 8) | (58, 128))
    }

    fn initial_tcp_syn(self) -> bool {
        self.protocol != 6
            || self.tcp_flags & 0x02 != 0 && self.tcp_flags & 0x10 == 0
    }

    fn is_icmp_error(self) -> bool {
        matches!(
            (self.protocol, self.icmp_type),
            (1, 3 | 4 | 5 | 11 | 12) | (58, 1..=4)
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct EmbeddedPacket {
    ip_version: u8,
    protocol: u8,
    source: SocketAddr,
    destination: SocketAddr,
    ip_offset: usize,
    ip_header_len: usize,
    transport_offset: usize,
}

impl EmbeddedPacket {
    fn parse(packet: &[u8], outer: ParsedPacket) -> Option<Self> {
        let ip_offset = outer.transport_offset.checked_add(8)?;
        let inner = packet.get(ip_offset..outer.packet_len)?;
        match inner.first()? >> 4 {
            4 => {
                if inner.len() < 20 {
                    return None;
                }
                let header_len = usize::from(inner[0] & 0x0f) * 4;
                if header_len < 20 || header_len > inner.len() {
                    return None;
                }
                let source = IpAddr::V4(Ipv4Addr::new(
                    inner[12], inner[13], inner[14], inner[15],
                ));
                let destination = IpAddr::V4(Ipv4Addr::new(
                    inner[16], inner[17], inner[18], inner[19],
                ));
                Self::finish(
                    packet,
                    4,
                    inner[9],
                    source,
                    destination,
                    ip_offset,
                    header_len,
                    ip_offset + header_len,
                )
            }
            6 => {
                if inner.len() < 40 {
                    return None;
                }
                let source = IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&inner[8..24]).ok()?,
                ));
                let destination = IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&inner[24..40]).ok()?,
                ));
                let mut protocol = inner[6];
                let mut offset = 40;
                loop {
                    match protocol {
                        0 | 43 | 60 => {
                            let extension = inner.get(offset..)?;
                            if extension.len() < 2 {
                                return None;
                            }
                            let length = (usize::from(extension[1]) + 1) * 8;
                            if length > extension.len() {
                                return None;
                            }
                            protocol = extension[0];
                            offset += length;
                        }
                        44 => return None,
                        _ => break,
                    }
                }
                Self::finish(
                    packet,
                    6,
                    protocol,
                    source,
                    destination,
                    ip_offset,
                    40,
                    ip_offset + offset,
                )
            }
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        packet: &[u8],
        ip_version: u8,
        protocol: u8,
        source_ip: IpAddr,
        destination_ip: IpAddr,
        ip_offset: usize,
        ip_header_len: usize,
        transport_offset: usize,
    ) -> Option<Self> {
        let transport = packet.get(transport_offset..)?;
        let (source_selector, destination_selector) = match protocol {
            6 | 17 if transport.len() >= 4 => (
                u16::from_be_bytes([transport[0], transport[1]]),
                u16::from_be_bytes([transport[2], transport[3]]),
            ),
            1 | 58 if transport.len() >= 8 => {
                let identifier =
                    u16::from_be_bytes([transport[4], transport[5]]);
                (identifier, identifier)
            }
            _ => return None,
        };
        Some(Self {
            ip_version,
            protocol,
            source: SocketAddr::new(source_ip, source_selector),
            destination: SocketAddr::new(destination_ip, destination_selector),
            ip_offset,
            ip_header_len,
            transport_offset,
        })
    }

    fn flow_key(self) -> FlowKey {
        FlowKey {
            protocol: self.protocol,
            source: self.source,
            destination: self.destination,
        }
    }
}

fn segment_tcp_packet(
    packet: &[u8],
    parsed: ParsedPacket,
    mtu: usize,
) -> io::Result<Vec<Vec<u8>>> {
    let transport = packet
        .get(parsed.transport_offset..parsed.packet_len)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "short TCP packet")
        })?;
    if transport.len() < 20 {
        return Ok(Vec::new());
    }
    let tcp_header_len = usize::from(transport[12] >> 4) * 4;
    if !(20..=transport.len()).contains(&tcp_header_len) {
        return Ok(Vec::new());
    }
    let total_header_len = parsed.transport_offset + tcp_header_len;
    let Some(segment_size) = mtu.checked_sub(total_header_len) else {
        return Ok(Vec::new());
    };
    if segment_size == 0 {
        return Ok(Vec::new());
    }
    let payload = &packet[total_header_len..parsed.packet_len];
    let first_sequence = u32::from_be_bytes(
        transport[4..8]
            .try_into()
            .expect("TCP sequence slice has fixed length"),
    );
    let original_id = if parsed.ip_version == 4 {
        u16::from_be_bytes([packet[4], packet[5]])
    } else {
        0
    };
    let mut segments = Vec::with_capacity(payload.len().div_ceil(segment_size));
    for (index, chunk) in payload.chunks(segment_size).enumerate() {
        let total_len = total_header_len + chunk.len();
        let mut segment = Vec::with_capacity(total_len);
        segment.extend_from_slice(&packet[..total_header_len]);
        segment.extend_from_slice(chunk);
        if parsed.ip_version == 4 {
            segment[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            segment[4..6].copy_from_slice(
                &original_id.wrapping_add(index as u16).to_be_bytes(),
            );
        } else {
            segment[4..6]
                .copy_from_slice(&((total_len - 40) as u16).to_be_bytes());
        }
        let sequence = first_sequence
            .wrapping_add((index.saturating_mul(segment_size)) as u32);
        segment[parsed.transport_offset + 4..parsed.transport_offset + 8]
            .copy_from_slice(&sequence.to_be_bytes());
        if index + 1 < payload.len().div_ceil(segment_size) {
            segment[parsed.transport_offset + 13] &= !(0x01 | 0x08);
        }
        let segment_parsed =
            ParsedPacket::parse(&segment).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid segmented TCP packet",
                )
            })?;
        recompute_checksums(&mut segment, segment_parsed)?;
        segments.push(segment);
    }
    Ok(segments)
}

fn build_reject(packet: &[u8], parsed: ParsedPacket) -> Option<Vec<u8>> {
    match parsed.protocol {
        6 => build_tcp_reset(packet, parsed),
        17 => build_icmp_unreachable(packet, parsed, 3, 4),
        _ => build_icmp_unreachable(packet, parsed, 1, 3),
    }
}

fn build_tcp_reset(packet: &[u8], parsed: ParsedPacket) -> Option<Vec<u8>> {
    let transport = packet.get(parsed.transport_offset..parsed.packet_len)?;
    if transport.len() < 20 {
        return None;
    }
    let header_len = usize::from(transport[12] >> 4) * 4;
    if header_len < 20 || header_len > transport.len() {
        return None;
    }
    let original_sequence =
        u32::from_be_bytes(transport[4..8].try_into().ok()?);
    let original_ack = u32::from_be_bytes(transport[8..12].try_into().ok()?);
    let original_flags = transport[13];
    let (sequence, acknowledgement, flags) = if original_flags & 0x10 != 0 {
        (original_ack, 0, 0x04)
    } else {
        let mut acknowledgement = original_sequence
            .wrapping_add(u32::try_from(transport.len() - header_len).ok()?);
        if original_flags & 0x02 != 0 {
            acknowledgement = acknowledgement.wrapping_add(1);
        }
        if original_flags & 0x01 != 0 {
            acknowledgement = acknowledgement.wrapping_add(1);
        }
        (0, acknowledgement, 0x14)
    };
    let ip_header_len = if parsed.ip_version == 4 { 20 } else { 40 };
    let mut reply = vec![0_u8; ip_header_len + 20];
    match (parsed.destination.ip(), parsed.source.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            reply[0] = 0x45;
            reply[2..4].copy_from_slice(&40_u16.to_be_bytes());
            reply[8] = 64;
            reply[9] = 6;
            reply[12..16].copy_from_slice(&source.octets());
            reply[16..20].copy_from_slice(&destination.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            reply[0] = 0x60;
            reply[4..6].copy_from_slice(&20_u16.to_be_bytes());
            reply[6] = 6;
            reply[7] = 64;
            reply[8..24].copy_from_slice(&source.octets());
            reply[24..40].copy_from_slice(&destination.octets());
        }
        _ => return None,
    }
    let tcp = &mut reply[ip_header_len..];
    tcp[0..2].copy_from_slice(&parsed.destination.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&parsed.source.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    let reply_parsed = ParsedPacket::parse(&reply)?;
    recompute_checksums(&mut reply, reply_parsed).ok()?;
    Some(reply)
}

fn build_icmp_unreachable(
    packet: &[u8],
    parsed: ParsedPacket,
    ipv4_code: u8,
    ipv6_code: u8,
) -> Option<Vec<u8>> {
    let packet = packet.get(..parsed.packet_len)?;
    if packet.len() < parsed.ip_header_len.checked_add(8)? {
        return None;
    }
    match (parsed.destination.ip(), parsed.source.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let quote_len = packet.len().min(576 - 20 - 8);
            let total_len = 20 + 8 + quote_len;
            let mut reply = vec![0_u8; total_len];
            reply[0] = 0x45;
            reply[2..4]
                .copy_from_slice(&u16::try_from(total_len).ok()?.to_be_bytes());
            reply[8] = 64;
            reply[9] = 1;
            reply[12..16].copy_from_slice(&source.octets());
            reply[16..20].copy_from_slice(&destination.octets());
            reply[20] = 3;
            reply[21] = ipv4_code;
            reply[28..].copy_from_slice(&packet[..quote_len]);
            let parsed = ParsedPacket::parse(&reply)?;
            recompute_checksums(&mut reply, parsed).ok()?;
            Some(reply)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let quote_len = packet.len().min(1280 - 40 - 8);
            let payload_len = 8 + quote_len;
            let mut reply = vec![0_u8; 40 + payload_len];
            reply[0] = 0x60;
            reply[4..6].copy_from_slice(
                &u16::try_from(payload_len).ok()?.to_be_bytes(),
            );
            reply[6] = 58;
            reply[7] = 64;
            reply[8..24].copy_from_slice(&source.octets());
            reply[24..40].copy_from_slice(&destination.octets());
            reply[40] = 1;
            reply[41] = ipv6_code;
            reply[48..].copy_from_slice(&packet[..quote_len]);
            let parsed = ParsedPacket::parse(&reply)?;
            recompute_checksums(&mut reply, parsed).ok()?;
            Some(reply)
        }
        _ => None,
    }
}

fn fragment_ipv4_packet(
    packet: &[u8],
    parsed: ParsedPacket,
    mtu: usize,
) -> io::Result<Vec<Vec<u8>>> {
    let header_len = parsed.ip_header_len;
    if header_len < 20 || header_len >= parsed.packet_len {
        return Ok(Vec::new());
    }
    let max_payload = mtu.saturating_sub(header_len) & !7;
    if max_payload == 0 {
        return Ok(Vec::new());
    }
    let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
    let base_offset = flags_offset & 0x1fff;
    let base_flags = flags_offset & 0xc000;
    let original_more = flags_offset & 0x2000 != 0;
    let payload = &packet[header_len..parsed.packet_len];
    let mut fragments = Vec::with_capacity(payload.len().div_ceil(max_payload));
    for (index, chunk) in payload.chunks(max_payload).enumerate() {
        let start = index * max_payload;
        let total_len = header_len + chunk.len();
        let mut fragment = Vec::with_capacity(total_len);
        fragment.extend_from_slice(&packet[..header_len]);
        fragment.extend_from_slice(chunk);
        fragment[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        let more = original_more || start + chunk.len() < payload.len();
        let fragment_field = base_flags
            | if more { 0x2000 } else { 0 }
            | base_offset.wrapping_add((start / 8) as u16);
        fragment[6..8].copy_from_slice(&fragment_field.to_be_bytes());
        fragment[10..12].fill(0);
        let checksum = internet_checksum(&fragment[..header_len]);
        fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
        fragments.push(fragment);
    }
    Ok(fragments)
}

fn build_fragmentation_needed(
    packet: &[u8],
    parsed: ParsedPacket,
    mtu: usize,
) -> Option<Vec<u8>> {
    if parsed.ip_version != 4
        || parsed.packet_len < parsed.ip_header_len.checked_add(8)?
    {
        return None;
    }
    let payload_len = parsed.packet_len.min(576 - 20 - 8);
    let total_len = 20 + 8 + payload_len;
    let mut reply = vec![0u8; total_len];
    reply[0] = 0x45;
    reply[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    reply[8] = 64;
    reply[9] = 1;
    reply[12..16].copy_from_slice(&packet[16..20]);
    reply[16..20].copy_from_slice(&packet[12..16]);
    reply[20] = 3;
    reply[21] = 4;
    reply[26..28].copy_from_slice(
        &(mtu.max(68).min(usize::from(u16::MAX)) as u16).to_be_bytes(),
    );
    reply[28..].copy_from_slice(&packet[..payload_len]);
    let ip_checksum = internet_checksum(&reply[..20]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    let icmp_checksum = internet_checksum(&reply[20..]);
    reply[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    Some(reply)
}

fn build_packet_too_big(
    packet: &[u8],
    parsed: ParsedPacket,
    mtu: usize,
) -> Option<Vec<u8>> {
    if parsed.ip_version != 6 || parsed.packet_len < 40 {
        return None;
    }
    let payload_len = parsed.packet_len.min(1280 - 40 - 8);
    let total_len = 40 + 8 + payload_len;
    let mut reply = vec![0u8; total_len];
    reply[0] = 0x60;
    reply[4..6].copy_from_slice(&((total_len - 40) as u16).to_be_bytes());
    reply[6] = 58;
    reply[7] = 64;
    reply[8..24].copy_from_slice(&packet[24..40]);
    reply[24..40].copy_from_slice(&packet[8..24]);
    reply[40] = 2;
    reply[44..48].copy_from_slice(
        &u32::try_from(mtu.max(1280))
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    reply[48..].copy_from_slice(&packet[..payload_len]);
    let checksum =
        transport_checksum(&reply[8..24], &reply[24..40], 58, &reply[40..], 6);
    reply[42..44].copy_from_slice(&checksum.to_be_bytes());
    Some(reply)
}

fn rewrite_embedded_packet(
    packet: &mut [u8],
    embedded: EmbeddedPacket,
    source_address: IpAddr,
    source_selector: u16,
    destination_address: IpAddr,
    destination_selector: u16,
) -> io::Result<()> {
    if source_address.is_ipv4() != (embedded.ip_version == 4)
        || destination_address.is_ipv4() != (embedded.ip_version == 4)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "embedded packet rewrite address family mismatch",
        ));
    }
    let old_source = embedded.source.ip();
    let old_destination = embedded.destination.ip();
    match (source_address, destination_address) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            packet[embedded.ip_offset + 12..embedded.ip_offset + 16]
                .copy_from_slice(&source.octets());
            packet[embedded.ip_offset + 16..embedded.ip_offset + 20]
                .copy_from_slice(&destination.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            packet[embedded.ip_offset + 8..embedded.ip_offset + 24]
                .copy_from_slice(&source.octets());
            packet[embedded.ip_offset + 24..embedded.ip_offset + 40]
                .copy_from_slice(&destination.octets());
        }
        _ => unreachable!(),
    }
    if embedded.ip_version == 4 {
        let header = &mut packet
            [embedded.ip_offset..embedded.ip_offset + embedded.ip_header_len];
        header[10..12].fill(0);
        let checksum = internet_checksum(header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
    }

    let transport =
        packet.get_mut(embedded.transport_offset..).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "short embedded transport",
            )
        })?;
    match embedded.protocol {
        6 if transport.len() >= 4 => {
            transport[0..2].copy_from_slice(&source_selector.to_be_bytes());
            transport[2..4]
                .copy_from_slice(&destination_selector.to_be_bytes());
        }
        17 if transport.len() >= 8 => {
            let checksum = u16::from_be_bytes([transport[6], transport[7]]);
            transport[0..2].copy_from_slice(&source_selector.to_be_bytes());
            transport[2..4]
                .copy_from_slice(&destination_selector.to_be_bytes());
            if checksum != 0 || embedded.ip_version == 6 {
                let mut checksum = checksum;
                checksum = adjust_checksum_address(
                    checksum,
                    old_source,
                    source_address,
                );
                checksum = adjust_checksum_address(
                    checksum,
                    old_destination,
                    destination_address,
                );
                checksum = adjust_checksum_word(
                    checksum,
                    embedded.source.port(),
                    source_selector,
                );
                checksum = adjust_checksum_word(
                    checksum,
                    embedded.destination.port(),
                    destination_selector,
                );
                transport[6..8].copy_from_slice(&checksum.to_be_bytes());
            }
        }
        1 if transport.len() >= 8 => {
            let checksum = u16::from_be_bytes([transport[2], transport[3]]);
            let checksum = adjust_checksum_word(
                checksum,
                embedded.source.port(),
                source_selector,
            );
            transport[2..4].copy_from_slice(&checksum.to_be_bytes());
            transport[4..6].copy_from_slice(&source_selector.to_be_bytes());
        }
        58 if transport.len() >= 8 => {
            let mut checksum = u16::from_be_bytes([transport[2], transport[3]]);
            checksum =
                adjust_checksum_address(checksum, old_source, source_address);
            checksum = adjust_checksum_address(
                checksum,
                old_destination,
                destination_address,
            );
            checksum = adjust_checksum_word(
                checksum,
                embedded.source.port(),
                source_selector,
            );
            transport[2..4].copy_from_slice(&checksum.to_be_bytes());
            transport[4..6].copy_from_slice(&source_selector.to_be_bytes());
        }
        _ => {}
    }
    Ok(())
}

fn adjust_checksum_address(
    checksum: u16,
    old_address: IpAddr,
    new_address: IpAddr,
) -> u16 {
    match (old_address, new_address) {
        (IpAddr::V4(old), IpAddr::V4(new)) => old
            .octets()
            .chunks_exact(2)
            .zip(new.octets().chunks_exact(2))
            .fold(checksum, |checksum, (old, new)| {
                adjust_checksum_word(
                    checksum,
                    u16::from_be_bytes([old[0], old[1]]),
                    u16::from_be_bytes([new[0], new[1]]),
                )
            }),
        (IpAddr::V6(old), IpAddr::V6(new)) => old
            .octets()
            .chunks_exact(2)
            .zip(new.octets().chunks_exact(2))
            .fold(checksum, |checksum, (old, new)| {
                adjust_checksum_word(
                    checksum,
                    u16::from_be_bytes([old[0], old[1]]),
                    u16::from_be_bytes([new[0], new[1]]),
                )
            }),
        _ => checksum,
    }
}

fn adjust_checksum_word(checksum: u16, old: u16, new: u16) -> u16 {
    let mut sum = u32::from(!checksum) + u32::from(!old) + u32::from(new);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn rewrite_packet(
    packet: &mut [u8],
    parsed: ParsedPacket,
    rewrite: Rewrite,
) -> io::Result<()> {
    if rewrite.source_address.is_ipv4() != (parsed.ip_version == 4)
        || rewrite.destination_address.is_ipv4() != (parsed.ip_version == 4)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet rewrite address family mismatch",
        ));
    }
    match (rewrite.source_address, rewrite.destination_address) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&destination.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&destination.octets());
        }
        _ => unreachable!(),
    }
    let transport = packet
        .get_mut(parsed.transport_offset..parsed.packet_len)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "short transport packet")
        })?;
    match parsed.protocol {
        6 | 17 => {
            transport[0..2]
                .copy_from_slice(&rewrite.source_selector.to_be_bytes());
            transport[2..4]
                .copy_from_slice(&rewrite.destination_selector.to_be_bytes());
        }
        1 | 58 => {
            transport[4..6]
                .copy_from_slice(&rewrite.source_selector.to_be_bytes());
        }
        _ => {}
    }
    recompute_checksums(packet, parsed)
}

fn recompute_checksums(
    packet: &mut [u8],
    parsed: ParsedPacket,
) -> io::Result<()> {
    recompute_checksums_with_zero_udp_policy(packet, parsed, true)
}

fn recompute_checksums_with_zero_udp_policy(
    packet: &mut [u8],
    parsed: ParsedPacket,
    preserve_zero_udp_v4: bool,
) -> io::Result<()> {
    if parsed.ip_version == 4 {
        packet[10..12].fill(0);
        let checksum = internet_checksum(&packet[..parsed.ip_header_len]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    }
    let source = match parsed.ip_version {
        4 => packet[12..16].to_vec(),
        _ => packet[8..24].to_vec(),
    };
    let destination = match parsed.ip_version {
        4 => packet[16..20].to_vec(),
        _ => packet[24..40].to_vec(),
    };
    let transport = packet
        .get_mut(parsed.transport_offset..parsed.packet_len)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "short transport packet")
        })?;
    let checksum_offset = match parsed.protocol {
        6 => 16,
        17 => 6,
        1 | 58 => 2,
        _ => return Ok(()),
    };
    if transport.len() < checksum_offset + 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short transport packet",
        ));
    }
    let preserve_zero_udp = preserve_zero_udp_v4
        && parsed.protocol == 17
        && parsed.ip_version == 4
        && transport[checksum_offset..checksum_offset + 2] == [0, 0];
    transport[checksum_offset..checksum_offset + 2].fill(0);
    if preserve_zero_udp {
        return Ok(());
    }
    let checksum = if parsed.protocol == 1 {
        internet_checksum(transport)
    } else {
        transport_checksum(
            &source,
            &destination,
            parsed.protocol,
            transport,
            parsed.ip_version,
        )
    };
    let checksum = if checksum == 0 && parsed.protocol == 17 {
        u16::MAX
    } else {
        checksum
    };
    transport[checksum_offset..checksum_offset + 2]
        .copy_from_slice(&checksum.to_be_bytes());
    Ok(())
}

/// Complete checksums that a kernel forwarding path may leave deferred when
/// transmitting to a TUN device. This mirrors sing-box bridge's scalar read
/// path: malformed and fragmented packets are left untouched, while UDP zero
/// checksums are materialized because they can represent deferred offload.
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) fn fix_return_checksum(packet: &mut [u8]) {
    let Some(parsed) = ParsedPacket::parse(packet) else {
        return;
    };
    if parsed.fragmented {
        return;
    }
    let _ = recompute_checksums_with_zero_udp_policy(packet, parsed, false);
}

fn clamp_tcp_mss(
    packet: &mut [u8],
    parsed: ParsedPacket,
    mtu: usize,
) -> io::Result<()> {
    if mtu == 0 || parsed.protocol != 6 || parsed.tcp_flags & 0x02 == 0 {
        return Ok(());
    }
    let transport = packet
        .get_mut(parsed.transport_offset..parsed.packet_len)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "short TCP packet")
        })?;
    if transport.len() < 20 {
        return Ok(());
    }
    let header_len = usize::from(transport[12] >> 4) * 4;
    if !(20..=transport.len()).contains(&header_len) {
        return Ok(());
    }
    let Some(max_mss) = mtu
        .checked_sub(parsed.transport_offset + 20)
        .and_then(|value| u16::try_from(value.min(usize::from(u16::MAX))).ok())
    else {
        return Ok(());
    };
    let mut offset = 20;
    let mut changed = false;
    while offset < header_len {
        match transport[offset] {
            0 => break,
            1 => offset += 1,
            2 if offset + 4 <= header_len && transport[offset + 1] == 4 => {
                let current = u16::from_be_bytes([
                    transport[offset + 2],
                    transport[offset + 3],
                ]);
                if current > max_mss {
                    transport[offset + 2..offset + 4]
                        .copy_from_slice(&max_mss.to_be_bytes());
                    changed = true;
                }
                break;
            }
            _ if offset + 2 <= header_len => {
                let length = usize::from(transport[offset + 1]);
                if length < 2 || offset + length > header_len {
                    break;
                }
                offset += length;
            }
            _ => break,
        }
    }
    if changed {
        recompute_checksums(packet, parsed)?;
    }
    Ok(())
}

fn transport_checksum(
    source: &[u8],
    destination: &[u8],
    protocol: u8,
    transport: &[u8],
    ip_version: u8,
) -> u16 {
    let mut sum = checksum_sum(source) + checksum_sum(destination);
    if ip_version == 4 {
        sum += u32::from(protocol);
        sum += transport.len() as u32;
    } else {
        let length = (transport.len() as u32).to_be_bytes();
        sum += checksum_sum(&length);
        sum += u32::from(protocol);
    }
    finish_checksum(sum + checksum_sum(transport))
}

fn internet_checksum(data: &[u8]) -> u16 {
    finish_checksum(checksum_sum(data))
}

fn checksum_sum(data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    let mut sum = chunks.by_ref().fold(0u32, |sum, chunk| {
        sum + u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
    });
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    sum
}

fn finish_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{IpAddr, Ipv6Addr},
        sync::{Arc, Mutex, Weak, atomic::Ordering},
        time::{Duration, Instant},
    };

    use super::{
        EmbeddedPacket, FlowDispatcher, ParsedPacket, Rewrite,
        TCP_CLOSING_TIMEOUT, TCP_TRANSITORY_TIMEOUT, UDP_TIMEOUT,
        build_fragmentation_needed, build_packet_too_big, build_reject,
        fix_return_checksum, fragment_ipv4_packet, internet_checksum,
        recompute_checksums, rewrite_embedded_packet, rewrite_packet,
        segment_tcp_packet, transport_checksum,
    };
    use crate::{
        adapter::{
            DialFuture, Dialer, IpPacketPort, IpPacketReturn, PacketFuture,
        },
        common::network::SocksAddr,
        option::Options,
        outbound::OutboundManager,
        route::Router,
    };

    #[derive(Default)]
    struct TestPort {
        written: Mutex<Vec<Vec<u8>>>,
        return_path: Mutex<Option<Weak<dyn IpPacketReturn>>>,
        selector_range: Mutex<(u16, u16)>,
    }

    impl TestPort {
        fn take_written(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.written.lock().unwrap())
        }

        fn return_packets(&self, packets: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
            let path = self
                .return_path
                .lock()
                .unwrap()
                .as_ref()
                .and_then(Weak::upgrade);
            match path {
                Some(path) => path.return_packets(packets),
                None => packets,
            }
        }
    }

    impl IpPacketPort for TestPort {
        fn port_addresses(&self) -> (Option<IpAddr>, Option<IpAddr>) {
            (Some("10.8.0.2".parse().unwrap()), None)
        }

        fn port_mtu(&self) -> usize {
            1500
        }

        fn port_selector_range(&self) -> (u16, u16) {
            *self.selector_range.lock().unwrap()
        }

        fn attach_return(
            &self,
            return_path: Weak<dyn IpPacketReturn>,
        ) -> io::Result<()> {
            *self.return_path.lock().unwrap() = Some(return_path);
            Ok(())
        }

        fn detach_return(&self, return_path: &Weak<dyn IpPacketReturn>) {
            let mut current = self.return_path.lock().unwrap();
            if current
                .as_ref()
                .is_some_and(|current| current.ptr_eq(return_path))
            {
                current.take();
            }
        }

        fn write_packets<'a>(
            &'a self,
            packets: Vec<Vec<u8>>,
        ) -> PacketFuture<'a, ()> {
            Box::pin(async move {
                self.written.lock().unwrap().extend(packets);
                Ok(())
            })
        }
    }

    struct TestDialer(Arc<TestPort>);

    impl Dialer for TestDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "test dialer only exposes an IP packet port",
                ))
            })
        }

        fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
            Some(self.0.clone())
        }
    }

    fn udp_v4() -> Vec<u8> {
        let mut packet = vec![0u8; 32];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(32u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&12u16.to_be_bytes());
        packet[28..].copy_from_slice(b"test");
        packet
    }

    fn tcp_v4(payload_len: usize) -> Vec<u8> {
        let total_len = 40 + payload_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(
            &(u16::try_from(total_len).unwrap()).to_be_bytes(),
        );
        packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..28].copy_from_slice(&1000u32.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = 0x10 | 0x08 | 0x01;
        for (index, byte) in packet[40..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        let parsed = ParsedPacket::parse(&packet).unwrap();
        recompute_checksums(&mut packet, parsed).unwrap();
        packet
    }

    fn tcp_v4_with_flags(flags: u8) -> Vec<u8> {
        let mut packet = tcp_v4(0);
        packet[33] = flags;
        let parsed = ParsedPacket::parse(&packet).unwrap();
        recompute_checksums(&mut packet, parsed).unwrap();
        packet
    }

    fn reverse_tcp_packet(forwarded: &[u8], flags: u8) -> Vec<u8> {
        let mut packet = forwarded.to_vec();
        let parsed = ParsedPacket::parse(&packet).unwrap();
        rewrite_packet(
            &mut packet,
            parsed,
            Rewrite {
                source_address: parsed.destination.ip(),
                source_selector: parsed.destination.port(),
                destination_address: parsed.source.ip(),
                destination_selector: parsed.source.port(),
            },
        )
        .unwrap();
        packet[33] = flags;
        let parsed = ParsedPacket::parse(&packet).unwrap();
        recompute_checksums(&mut packet, parsed).unwrap();
        packet
    }

    fn routed_dispatcher(
        route_rule: serde_json::Value,
        udp_timeout: Duration,
    ) -> (
        Arc<FlowDispatcher>,
        Arc<TestPort>,
        tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        Arc<OutboundManager>,
    ) {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]}
        }))
        .unwrap();
        let outbounds =
            Arc::new(OutboundManager::from_options(&options, "").unwrap());
        let port = Arc::new(TestPort::default());
        outbounds
            .register_endpoint(
                "wg",
                "wireguard",
                Arc::new(TestDialer(port.clone())),
            )
            .unwrap();
        let router =
            Arc::new(Router::from_json(&[route_rule], "direct").unwrap());
        let (writeback, returned) = tokio::sync::mpsc::unbounded_channel();
        let dispatcher = FlowDispatcher::new(
            "source",
            router,
            outbounds.clone(),
            writeback,
            udp_timeout,
        );
        (dispatcher, port, returned, outbounds)
    }

    fn table_key(selector: u16) -> super::FlowKey {
        super::FlowKey {
            protocol: 17,
            source: std::net::SocketAddr::new(
                "10.0.0.2".parse().unwrap(),
                selector,
            ),
            destination: "1.1.1.1:53".parse().unwrap(),
        }
    }

    fn icmp_v4() -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20] = 8;
        packet[24..26].copy_from_slice(&1234u16.to_be_bytes());
        packet[26..28].copy_from_slice(&1u16.to_be_bytes());
        let parsed = ParsedPacket::parse(&packet).unwrap();
        recompute_checksums(&mut packet, parsed).unwrap();
        packet
    }

    #[test]
    fn capacity_eviction_scans_one_bounded_upstream_window() {
        let now = Instant::now();
        let mut state = super::State::default();
        for selector in 0..super::FLOW_CAPACITY as u16 {
            state.simple.insert(
                table_key(selector),
                super::SimpleEntry {
                    action: super::SimpleAction::Drop,
                    idle: Duration::from_secs(1),
                    expires_at: now - Duration::from_secs(1),
                },
            );
        }

        FlowDispatcher::evict_if_full(&mut state, now);

        assert_eq!(
            state.simple.len(),
            super::FLOW_CAPACITY - super::FLOW_SWEEP_LIMIT
        );
    }

    #[test]
    fn capacity_eviction_removes_one_oldest_scanned_live_entry() {
        let now = Instant::now();
        let mut state = super::State::default();
        for selector in 0..super::FLOW_CAPACITY as u16 {
            state.simple.insert(
                table_key(selector),
                super::SimpleEntry {
                    action: super::SimpleAction::Accept,
                    idle: UDP_TIMEOUT,
                    expires_at: now + UDP_TIMEOUT,
                },
            );
        }

        FlowDispatcher::evict_if_full(&mut state, now);

        assert_eq!(state.simple.len(), super::FLOW_CAPACITY - 1);
    }

    #[test]
    fn periodic_sweep_bounds_combined_simple_table_work() {
        let (dispatcher, _, _, _) = routed_dispatcher(
            serde_json::json!({"action": "route", "outbound": "wg"}),
            UDP_TIMEOUT,
        );
        let now = Instant::now();
        {
            let mut state = dispatcher.state.lock().unwrap();
            for selector in 0..(super::FLOW_SWEEP_LIMIT * 2) as u16 {
                state.simple.insert(
                    table_key(selector),
                    super::SimpleEntry {
                        action: super::SimpleAction::Reject,
                        idle: Duration::from_secs(1),
                        expires_at: now - Duration::from_secs(1),
                    },
                );
            }
            state.last_sweep = Some(now - super::FLOW_SWEEP_INTERVAL);
        }

        dispatcher.maybe_sweep(now);

        assert_eq!(
            dispatcher.state.lock().unwrap().simple.len(),
            super::FLOW_SWEEP_LIMIT
        );
    }

    #[tokio::test]
    async fn post_dispatch_sweep_runs_for_unhandled_packets() {
        let (dispatcher, _, _, _) = routed_dispatcher(
            serde_json::json!({"action": "route", "outbound": "wg"}),
            UDP_TIMEOUT,
        );
        let now = Instant::now();
        {
            let mut state = dispatcher.state.lock().unwrap();
            state.simple.insert(
                table_key(1234),
                super::SimpleEntry {
                    action: super::SimpleAction::Drop,
                    idle: Duration::from_secs(1),
                    expires_at: now - Duration::from_secs(1),
                },
            );
            state.last_sweep = Some(now - super::FLOW_SWEEP_INTERVAL);
        }

        assert!(!dispatcher.dispatch(&[]).await.unwrap());
        assert!(dispatcher.state.lock().unwrap().simple.is_empty());
    }

    #[tokio::test]
    async fn icmp_flow_uses_the_sing_box_ten_second_timeout() {
        let (dispatcher, port, _, _) = routed_dispatcher(
            serde_json::json!({"action": "route", "outbound": "wg"}),
            UDP_TIMEOUT,
        );
        let request = icmp_v4();
        let key = ParsedPacket::parse(&request).unwrap().flow_key().unwrap();

        assert!(dispatcher.dispatch(&request).await.unwrap());
        assert_eq!(port.take_written().len(), 1);
        let flow = dispatcher
            .state
            .lock()
            .unwrap()
            .forward
            .get(&key)
            .unwrap()
            .clone();
        assert_eq!(*flow.idle.lock().unwrap(), crate::constant::ICMP_TIMEOUT);
        let remaining = flow
            .expires_at
            .lock()
            .unwrap()
            .saturating_duration_since(Instant::now());
        assert!(remaining <= crate::constant::ICMP_TIMEOUT);
        assert!(remaining > Duration::from_secs(9));
    }

    #[test]
    fn rewrites_ipv4_udp_and_checksums() {
        let mut packet = udp_v4();
        let parsed = ParsedPacket::parse(&packet).unwrap();
        rewrite_packet(
            &mut packet,
            parsed,
            Rewrite {
                source_address: "10.8.0.2".parse().unwrap(),
                source_selector: 49_152,
                destination_address: "8.8.8.8".parse().unwrap(),
                destination_selector: 5353,
            },
        )
        .unwrap();
        let parsed = ParsedPacket::parse(&packet).unwrap();
        assert_eq!(parsed.source.ip(), "10.8.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.source.port(), 49_152);
        assert_eq!(
            parsed.destination.ip(),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        assert_eq!(parsed.destination.port(), 5353);
        assert_eq!(internet_checksum(&packet[..20]), 0);
    }

    #[test]
    fn bridge_return_checksum_materializes_deferred_udp_checksum() {
        let mut packet = udp_v4();
        assert_eq!(&packet[26..28], &[0, 0]);
        fix_return_checksum(&mut packet);
        assert_ne!(&packet[26..28], &[0, 0]);
        assert_eq!(internet_checksum(&packet[..20]), 0);
        assert_eq!(
            transport_checksum(
                &packet[12..16],
                &packet[16..20],
                17,
                &packet[20..],
                4
            ),
            0
        );
    }

    #[test]
    fn bridge_return_checksum_leaves_fragments_untouched() {
        let mut packet = udp_v4();
        packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        let original = packet.clone();
        fix_return_checksum(&mut packet);
        assert_eq!(packet, original);
    }

    #[test]
    fn parses_ipv6_extension_header_transport() {
        let mut packet = vec![0u8; 56];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16u16.to_be_bytes());
        packet[6] = 60;
        packet[8..24]
            .copy_from_slice(&"fd00::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40]
            .copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        packet[40] = 17;
        packet[41] = 0;
        packet[48..50].copy_from_slice(&1000u16.to_be_bytes());
        packet[50..52].copy_from_slice(&2000u16.to_be_bytes());
        packet[52..54].copy_from_slice(&8u16.to_be_bytes());
        let parsed = ParsedPacket::parse(&packet).unwrap();
        assert_eq!(parsed.protocol, 17);
        assert_eq!(parsed.transport_offset, 48);
        assert_eq!(parsed.source.port(), 1000);
        assert_eq!(parsed.destination.port(), 2000);
    }

    #[test]
    fn clamps_tcp_syn_mss_to_packet_port_mtu() {
        let mut packet = vec![0u8; 44];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&44u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[32] = 6 << 4;
        packet[33] = 0x02;
        packet[40..44].copy_from_slice(&[2, 4, 0x05, 0xb4]);
        let parsed = ParsedPacket::parse(&packet).unwrap();
        rewrite_packet(
            &mut packet,
            parsed,
            Rewrite {
                source_address: "10.8.0.2".parse().unwrap(),
                source_selector: 49_152,
                destination_address: parsed.destination.ip(),
                destination_selector: parsed.destination.port(),
            },
        )
        .unwrap();
        super::clamp_tcp_mss(&mut packet, parsed, 1280).unwrap();
        assert_eq!(u16::from_be_bytes([packet[42], packet[43]]), 1240);
        assert_eq!(internet_checksum(&packet[..20]), 0);
    }

    #[test]
    fn packet_port_selector_range_uses_start_and_count_contract() {
        let (dispatcher, port, _returned, _outbounds) = routed_dispatcher(
            serde_json::json!({"action": "route", "outbound": "wg"}),
            UDP_TIMEOUT,
        );
        *port.selector_range.lock().unwrap() = (50_000, 2);
        let port_id = dispatcher.ensure_return_attached(port).unwrap();
        let port_address = "10.8.0.2".parse().unwrap();
        let server = "1.1.1.1:53".parse().unwrap();
        assert_eq!(
            dispatcher
                .allocate_selector(port_id, 17, port_address, server, 50_001)
                .unwrap(),
            50_001
        );
        let generated = dispatcher
            .allocate_selector(port_id, 17, port_address, server, 50_002)
            .unwrap();
        assert!((50_000..50_002).contains(&generated));

        let invalid = Arc::new(TestPort::default());
        *invalid.selector_range.lock().unwrap() = (65_530, 10);
        assert!(dispatcher.ensure_return_attached(invalid).is_err());
    }

    #[tokio::test]
    async fn selector_occupancy_is_isolated_per_packet_port() {
        let (dispatcher, first_port, _, _) = routed_dispatcher(
            serde_json::json!({"action": "route", "outbound": "wg"}),
            UDP_TIMEOUT,
        );
        *first_port.selector_range.lock().unwrap() = (1200, 100);
        let request = udp_v4();
        assert!(dispatcher.dispatch(&request).await.unwrap());
        let forwarded = first_port.take_written().pop().unwrap();
        let parsed = ParsedPacket::parse(&forwarded).unwrap();
        assert_eq!(parsed.source.port(), 1234);
        let first_port_id = dispatcher
            .state
            .lock()
            .unwrap()
            .forward
            .values()
            .next()
            .unwrap()
            .port_id;

        let second_port = Arc::new(TestPort::default());
        *second_port.selector_range.lock().unwrap() = (1200, 100);
        let second_port_id =
            dispatcher.ensure_return_attached(second_port).unwrap();
        assert_ne!(first_port_id, second_port_id);
        assert_eq!(
            dispatcher
                .allocate_selector(
                    second_port_id,
                    17,
                    "10.8.0.2".parse().unwrap(),
                    "1.1.1.1:53".parse().unwrap(),
                    1234,
                )
                .unwrap(),
            1234
        );
    }

    #[test]
    fn resegments_oversized_tcp_like_sing_tun_gso_split() {
        let packet = tcp_v4(3000);
        let parsed = ParsedPacket::parse(&packet).unwrap();
        let segments = segment_tcp_packet(&packet, parsed, 1500).unwrap();
        assert_eq!(
            segments.iter().map(Vec::len).collect::<Vec<_>>(),
            [1500, 1500, 120]
        );
        for (index, segment) in segments.iter().enumerate() {
            let parsed = ParsedPacket::parse(segment).unwrap();
            assert_eq!(internet_checksum(&segment[..20]), 0);
            assert_eq!(
                transport_checksum(
                    &segment[12..16],
                    &segment[16..20],
                    6,
                    &segment[20..],
                    4,
                ),
                0
            );
            assert_eq!(
                u32::from_be_bytes(segment[24..28].try_into().unwrap()),
                1000 + (index * 1460) as u32
            );
            assert_eq!(
                u16::from_be_bytes(segment[4..6].try_into().unwrap()),
                0x1234u16.wrapping_add(index as u16)
            );
            assert_eq!(parsed.tcp_flags & (0x01 | 0x08) != 0, index == 2);
        }
    }

    #[test]
    fn fragments_oversized_ipv4_udp_on_eight_byte_boundaries() {
        let mut packet = vec![0u8; 20 + 8 + 3000];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[4..6].copy_from_slice(&0x4567u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&(3008u16).to_be_bytes());
        let parsed = ParsedPacket::parse(&packet).unwrap();
        recompute_checksums(&mut packet, parsed).unwrap();
        let fragments = fragment_ipv4_packet(&packet, parsed, 1500).unwrap();
        assert_eq!(
            fragments.iter().map(Vec::len).collect::<Vec<_>>(),
            [1500, 1500, 68]
        );
        for (index, fragment) in fragments.iter().enumerate() {
            assert_eq!(internet_checksum(&fragment[..20]), 0);
            assert_eq!(
                u16::from_be_bytes(fragment[6..8].try_into().unwrap()) & 0x1fff,
                [0, 185, 370][index]
            );
            assert_eq!(fragment[6] & 0x20 != 0, index != 2);
        }
    }

    #[test]
    fn builds_ipv4_fragmentation_needed_with_quoted_packet() {
        let mut packet = udp_v4();
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        let parsed = ParsedPacket::parse(&packet).unwrap();
        let reply = build_fragmentation_needed(&packet, parsed, 1200).unwrap();
        assert_eq!(&reply[12..16], &packet[16..20]);
        assert_eq!(&reply[16..20], &packet[12..16]);
        assert_eq!(&reply[20..22], &[3, 4]);
        assert_eq!(u16::from_be_bytes(reply[26..28].try_into().unwrap()), 1200);
        assert_eq!(&reply[28..], packet.as_slice());
        assert_eq!(internet_checksum(&reply[..20]), 0);
        assert_eq!(internet_checksum(&reply[20..]), 0);
    }

    #[test]
    fn builds_ipv6_packet_too_big_with_minimum_advertised_mtu() {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24]
            .copy_from_slice(&"fd00::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40]
            .copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        packet[40..42].copy_from_slice(&1234u16.to_be_bytes());
        packet[42..44].copy_from_slice(&53u16.to_be_bytes());
        packet[44..46].copy_from_slice(&8u16.to_be_bytes());
        let parsed = ParsedPacket::parse(&packet).unwrap();
        let reply = build_packet_too_big(&packet, parsed, 1000).unwrap();
        assert_eq!(&reply[8..24], &packet[24..40]);
        assert_eq!(&reply[24..40], &packet[8..24]);
        assert_eq!(&reply[40..42], &[2, 0]);
        assert_eq!(u32::from_be_bytes(reply[44..48].try_into().unwrap()), 1280);
        assert_eq!(
            transport_checksum(
                &reply[8..24],
                &reply[24..40],
                58,
                &reply[40..],
                6,
            ),
            0
        );
    }

    #[test]
    fn reject_builds_tcp_reset_with_sing_tun_sequence_rules() {
        let syn = tcp_v4_with_flags(0x02);
        let parsed = ParsedPacket::parse(&syn).unwrap();
        let reset = build_reject(&syn, parsed).unwrap();
        let reset_parsed = ParsedPacket::parse(&reset).unwrap();
        assert_eq!(reset_parsed.source, parsed.destination);
        assert_eq!(reset_parsed.destination, parsed.source);
        assert_eq!(reset_parsed.tcp_flags, 0x14);
        assert_eq!(u32::from_be_bytes(reset[28..32].try_into().unwrap()), 1001);
        assert_eq!(internet_checksum(&reset[..20]), 0);
        assert_eq!(
            transport_checksum(
                &reset[12..16],
                &reset[16..20],
                6,
                &reset[20..],
                4,
            ),
            0
        );
    }

    #[test]
    fn reject_builds_ipv4_udp_port_unreachable_with_quote() {
        let packet = udp_v4();
        let parsed = ParsedPacket::parse(&packet).unwrap();
        let reject = build_reject(&packet, parsed).unwrap();
        assert_eq!(&reject[12..16], &packet[16..20]);
        assert_eq!(&reject[16..20], &packet[12..16]);
        assert_eq!(&reject[20..22], &[3, 3]);
        assert_eq!(&reject[28..], packet.as_slice());
        assert_eq!(internet_checksum(&reject[..20]), 0);
        assert_eq!(internet_checksum(&reject[20..]), 0);
    }

    #[test]
    fn rewrites_icmp_error_embedded_udp_mapping() {
        let mut inner = udp_v4();
        fix_return_checksum(&mut inner);
        let parsed = ParsedPacket::parse(&inner).unwrap();
        rewrite_packet(
            &mut inner,
            parsed,
            Rewrite {
                source_address: "10.8.0.2".parse().unwrap(),
                source_selector: 49_152,
                destination_address: "8.8.8.8".parse().unwrap(),
                destination_selector: 5353,
            },
        )
        .unwrap();
        let mut packet = vec![0u8; 20 + 8 + inner.len()];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[8, 8, 8, 8]);
        packet[16..20].copy_from_slice(&[10, 8, 0, 2]);
        packet[20] = 3;
        packet[21] = 3;
        packet[28..].copy_from_slice(&inner);
        let outer = ParsedPacket::parse(&packet).unwrap();
        recompute_checksums(&mut packet, outer).unwrap();
        let embedded = EmbeddedPacket::parse(&packet, outer).unwrap();
        rewrite_embedded_packet(
            &mut packet,
            embedded,
            "10.0.0.2".parse().unwrap(),
            1234,
            "1.1.1.1".parse().unwrap(),
            53,
        )
        .unwrap();
        let inner = &packet[28..];
        let parsed = ParsedPacket::parse(inner).unwrap();
        assert_eq!(
            parsed.source,
            "10.0.0.2:1234".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(
            parsed.destination,
            "1.1.1.1:53".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(internet_checksum(&inner[..20]), 0);
        assert_eq!(
            transport_checksum(
                &inner[12..16],
                &inner[16..20],
                17,
                &inner[20..],
                4,
            ),
            0
        );
    }

    #[test]
    fn accepts_zero_icmp_identifier_and_rewrites_it() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20] = 8;
        let parsed = ParsedPacket::parse(&packet).unwrap();
        assert!(parsed.flow_key().is_some());
        rewrite_packet(
            &mut packet,
            parsed,
            Rewrite {
                source_address: "10.8.0.2".parse().unwrap(),
                source_selector: 50_000,
                destination_address: parsed.destination.ip(),
                destination_selector: 50_000,
            },
        )
        .unwrap();
        assert_eq!(u16::from_be_bytes([packet[24], packet[25]]), 50_000);
        assert_eq!(internet_checksum(&packet[20..]), 0);
    }

    #[tokio::test]
    async fn dispatcher_nat_round_trip_uses_selected_packet_port() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]}
        }))
        .unwrap();
        let outbounds =
            Arc::new(OutboundManager::from_options(&options, "").unwrap());
        let port = Arc::new(TestPort::default());
        outbounds
            .register_endpoint(
                "wg",
                "wireguard",
                Arc::new(TestDialer(port.clone())),
            )
            .unwrap();
        let router = Arc::new(
            Router::from_json(
                &[serde_json::json!({
                    "action": "route",
                    "outbound": "wg"
                })],
                "direct",
            )
            .unwrap(),
        );
        let (writeback, mut returned) = tokio::sync::mpsc::unbounded_channel();
        let dispatcher = FlowDispatcher::new(
            "source",
            router,
            outbounds,
            writeback,
            UDP_TIMEOUT,
        );

        let request = udp_v4();
        assert!(dispatcher.dispatch(&request).await.unwrap());
        let mut forwarded = port.take_written().pop().unwrap();
        let forwarded_packet = ParsedPacket::parse(&forwarded).unwrap();
        assert_eq!(
            forwarded_packet.source.ip(),
            "10.8.0.2".parse::<IpAddr>().unwrap()
        );
        assert!(forwarded_packet.source.port() >= 49_152);
        assert_eq!(forwarded_packet.destination.port(), 53);

        rewrite_packet(
            &mut forwarded,
            forwarded_packet,
            Rewrite {
                source_address: forwarded_packet.destination.ip(),
                source_selector: forwarded_packet.destination.port(),
                destination_address: forwarded_packet.source.ip(),
                destination_selector: forwarded_packet.source.port(),
            },
        )
        .unwrap();
        assert!(port.return_packets(vec![forwarded]).is_empty());
        let returned = returned.recv().await.unwrap();
        let returned = ParsedPacket::parse(&returned).unwrap();
        assert_eq!(returned.source.ip(), "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(returned.source.port(), 53);
        assert_eq!(
            returned.destination.ip(),
            "10.0.0.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(returned.destination.port(), 1234);
    }

    #[tokio::test]
    async fn tcp_lifecycle_establishes_only_on_reverse_and_closes_after_both_fins()
     {
        let (dispatcher, port, mut returned, outbounds) = routed_dispatcher(
            serde_json::json!({"action": "route", "outbound": "wg"}),
            UDP_TIMEOUT,
        );
        let syn = tcp_v4_with_flags(0x02);
        let key = ParsedPacket::parse(&syn).unwrap().flow_key().unwrap();
        assert!(dispatcher.dispatch(&syn).await.unwrap());
        let forwarded_syn = port.take_written().pop().unwrap();
        let flow = dispatcher
            .state
            .lock()
            .unwrap()
            .forward
            .get(&key)
            .unwrap()
            .clone();
        assert!(!flow.established.load(Ordering::Relaxed));

        // A forward ACK does not prove that the packet port has returned any
        // traffic, so sing-tun keeps the flow in its transitory state.
        assert!(dispatcher.dispatch(&tcp_v4_with_flags(0x10)).await.unwrap());
        assert!(!flow.established.load(Ordering::Relaxed));
        assert!(
            flow.expires_at
                .lock()
                .unwrap()
                .saturating_duration_since(Instant::now())
                <= TCP_TRANSITORY_TIMEOUT
        );
        port.take_written();

        let syn_ack = reverse_tcp_packet(&forwarded_syn, 0x12);
        assert!(port.return_packets(vec![syn_ack]).is_empty());
        returned.try_recv().unwrap();
        assert!(flow.established.load(Ordering::Relaxed));
        assert!(
            flow.expires_at
                .lock()
                .unwrap()
                .saturating_duration_since(Instant::now())
                <= TCP_TRANSITORY_TIMEOUT
        );

        // Reverse traffic marks the flow established, but the forward entry
        // adopts the established timeout only on the next client packet.
        assert!(dispatcher.dispatch(&tcp_v4_with_flags(0x10)).await.unwrap());
        assert!(
            flow.expires_at
                .lock()
                .unwrap()
                .saturating_duration_since(Instant::now())
                > Duration::from_secs(2 * 60 * 60)
        );
        port.take_written();

        assert!(dispatcher.dispatch(&tcp_v4_with_flags(0x11)).await.unwrap());
        assert!(flow.fin_forward.load(Ordering::Relaxed));
        let reverse_fin = reverse_tcp_packet(&forwarded_syn, 0x11);
        assert!(port.return_packets(vec![reverse_fin]).is_empty());
        returned.try_recv().unwrap();
        assert!(flow.fin_reverse.load(Ordering::Relaxed));
        assert_eq!(outbounds.connections().len(), 1);

        // As above, the reverse FIN changes flow state but does not mutate the
        // forward table entry's timeout until the next client packet.
        assert!(dispatcher.dispatch(&tcp_v4_with_flags(0x10)).await.unwrap());
        let closing_remaining = flow
            .expires_at
            .lock()
            .unwrap()
            .saturating_duration_since(Instant::now());
        assert!(closing_remaining <= TCP_CLOSING_TIMEOUT);
        assert!(closing_remaining > Duration::from_secs(9));

        // The first non-FIN packet after both FINs reports the connection as
        // finished, while the short closing flow remains available to carry
        // final acknowledgements.
        assert!(outbounds.connections().is_empty());
        assert!(!flow.closed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn tcp_reset_creates_a_refreshable_drop_tombstone() {
        let (dispatcher, port, mut returned, _outbounds) = routed_dispatcher(
            serde_json::json!({"action": "route", "outbound": "wg"}),
            UDP_TIMEOUT,
        );
        let syn = tcp_v4_with_flags(0x02);
        let key = ParsedPacket::parse(&syn).unwrap().flow_key().unwrap();
        assert!(dispatcher.dispatch(&syn).await.unwrap());
        let forwarded_syn = port.take_written().pop().unwrap();
        let flow = dispatcher
            .state
            .lock()
            .unwrap()
            .forward
            .get(&key)
            .unwrap()
            .clone();

        assert!(dispatcher.dispatch(&tcp_v4_with_flags(0x14)).await.unwrap());
        assert_eq!(port.take_written().len(), 1);
        assert!(flow.closed.load(Ordering::Acquire));

        let old_deadline = *flow.expires_at.lock().unwrap();
        assert!(dispatcher.dispatch(&tcp_v4_with_flags(0x10)).await.unwrap());
        assert!(port.take_written().is_empty());
        assert!(*flow.expires_at.lock().unwrap() >= old_deadline);

        let reverse_ack = reverse_tcp_packet(&forwarded_syn, 0x10);
        assert!(port.return_packets(vec![reverse_ack]).is_empty());
        assert!(returned.try_recv().is_err());
    }

    #[tokio::test]
    async fn reverse_activity_extends_only_when_forward_entry_is_checked() {
        let (dispatcher, port, mut returned, _outbounds) = routed_dispatcher(
            serde_json::json!({"action": "route", "outbound": "wg"}),
            Duration::from_secs(30),
        );
        let request = udp_v4();
        let key = ParsedPacket::parse(&request).unwrap().flow_key().unwrap();
        assert!(dispatcher.dispatch(&request).await.unwrap());
        let mut response = port.take_written().pop().unwrap();
        let flow = dispatcher
            .state
            .lock()
            .unwrap()
            .forward
            .get(&key)
            .unwrap()
            .clone();
        *flow.expires_at.lock().unwrap() =
            Instant::now() - Duration::from_secs(1);
        let parsed = ParsedPacket::parse(&response).unwrap();
        rewrite_packet(
            &mut response,
            parsed,
            Rewrite {
                source_address: parsed.destination.ip(),
                source_selector: parsed.destination.port(),
                destination_address: parsed.source.ip(),
                destination_selector: parsed.source.port(),
            },
        )
        .unwrap();

        // sing-tun accepts reverse packets without consulting the forward
        // deadline. It records lastReverse, and only a later forward lookup or
        // sweep extends the entry by its currently installed idle timeout.
        assert!(port.return_packets(vec![response]).is_empty());
        returned.try_recv().unwrap();
        assert!(*flow.expires_at.lock().unwrap() < Instant::now());
        assert!(dispatcher.dispatch(&request).await.unwrap());
        assert!(*flow.expires_at.lock().unwrap() > Instant::now());
    }

    #[tokio::test]
    async fn reverse_reset_is_forwarded_before_sweep_creates_tombstone() {
        let (dispatcher, port, mut returned, _outbounds) = routed_dispatcher(
            serde_json::json!({"action": "route", "outbound": "wg"}),
            UDP_TIMEOUT,
        );
        let request = tcp_v4_with_flags(0x02);
        let key = ParsedPacket::parse(&request).unwrap().flow_key().unwrap();
        assert!(dispatcher.dispatch(&request).await.unwrap());
        let forwarded = port.take_written().pop().unwrap();
        let flow = dispatcher
            .state
            .lock()
            .unwrap()
            .forward
            .get(&key)
            .unwrap()
            .clone();

        let reset = reverse_tcp_packet(&forwarded, 0x14);
        assert!(port.return_packets(vec![reset]).is_empty());
        assert_eq!(
            ParsedPacket::parse(&returned.try_recv().unwrap())
                .unwrap()
                .tcp_flags,
            0x14
        );
        assert!(flow.closed.load(Ordering::Acquire));
        assert!(!flow.tombstoned.load(Ordering::Acquire));

        let now = Instant::now();
        dispatcher.state.lock().unwrap().last_sweep =
            Some(now - super::FLOW_SWEEP_INTERVAL);
        dispatcher.maybe_sweep(now);
        assert!(flow.tombstoned.load(Ordering::Acquire));
        let remaining = flow
            .expires_at
            .lock()
            .unwrap()
            .saturating_duration_since(Instant::now());
        assert!(remaining <= super::FLOW_TOMBSTONE_TIMEOUT);
        assert!(remaining > Duration::from_secs(239));

        let ack = reverse_tcp_packet(&forwarded, 0x10);
        assert!(port.return_packets(vec![ack]).is_empty());
        assert!(returned.try_recv().is_err());
    }

    #[tokio::test]
    async fn route_udp_timeout_overrides_dispatcher_default() {
        let (dispatcher, _port, _returned, _outbounds) = routed_dispatcher(
            serde_json::json!({
                "action": "route",
                "outbound": "wg",
                "udp_timeout": "17s"
            }),
            Duration::from_secs(31),
        );
        let packet = udp_v4();
        let key = ParsedPacket::parse(&packet).unwrap().flow_key().unwrap();
        assert!(dispatcher.dispatch(&packet).await.unwrap());
        let flow = dispatcher
            .state
            .lock()
            .unwrap()
            .forward
            .get(&key)
            .unwrap()
            .clone();
        assert_eq!(flow.udp_timeout, Duration::from_secs(17));
        let remaining = flow
            .expires_at
            .lock()
            .unwrap()
            .saturating_duration_since(Instant::now());
        assert!(remaining <= Duration::from_secs(17));
        assert!(remaining > Duration::from_secs(16));
    }

    #[tokio::test]
    async fn packet_port_flow_is_metered_and_host_close_tombstones_it() {
        let (dispatcher, port, mut returned, outbounds) = routed_dispatcher(
            serde_json::json!({"action": "route", "outbound": "wg"}),
            UDP_TIMEOUT,
        );
        let request = udp_v4();
        assert!(dispatcher.dispatch(&request).await.unwrap());
        assert_eq!(outbounds.traffic_totals(), (request.len() as u64, 0));
        let connection = outbounds.connections().pop().unwrap();
        assert_eq!(connection.outbound, "wg");
        assert_eq!(connection.network, "udp");

        let mut response = port.take_written().pop().unwrap();
        let parsed = ParsedPacket::parse(&response).unwrap();
        rewrite_packet(
            &mut response,
            parsed,
            Rewrite {
                source_address: parsed.destination.ip(),
                source_selector: parsed.destination.port(),
                destination_address: parsed.source.ip(),
                destination_selector: parsed.source.port(),
            },
        )
        .unwrap();
        assert!(port.return_packets(vec![response]).is_empty());
        returned.try_recv().unwrap();
        assert_eq!(
            outbounds.traffic_totals(),
            (request.len() as u64, request.len() as u64)
        );

        outbounds.close_connection(&connection.id);
        assert!(outbounds.connections().is_empty());
        assert!(dispatcher.dispatch(&request).await.unwrap());
        assert!(port.take_written().is_empty());
    }

    #[tokio::test]
    async fn packet_port_meter_excludes_locally_rejected_mtu_packets() {
        let (dispatcher, port, mut returned, outbounds) = routed_dispatcher(
            serde_json::json!({"action": "route", "outbound": "wg"}),
            UDP_TIMEOUT,
        );
        let mut request = vec![0u8; 20 + 8 + 1_600];
        request[0] = 0x45;
        let packet_len = request.len() as u16;
        request[2..4].copy_from_slice(&packet_len.to_be_bytes());
        request[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        request[8] = 64;
        request[9] = 17;
        request[12..16].copy_from_slice(&[10, 0, 0, 2]);
        request[16..20].copy_from_slice(&[1, 1, 1, 1]);
        request[20..22].copy_from_slice(&1234u16.to_be_bytes());
        request[22..24].copy_from_slice(&53u16.to_be_bytes());
        request[24..26].copy_from_slice(&(8u16 + 1_600).to_be_bytes());

        assert!(dispatcher.dispatch(&request).await.unwrap());
        assert!(port.take_written().is_empty());
        assert_eq!(&returned.try_recv().unwrap()[20..22], &[3, 4]);
        assert_eq!(outbounds.traffic_totals(), (0, 0));

        // Clearing DF makes the same cached flow fragment and forward the
        // original packet, which is then counted exactly once before split.
        request[6..8].fill(0);
        assert!(dispatcher.dispatch(&request).await.unwrap());
        assert!(port.take_written().len() > 1);
        assert_eq!(outbounds.traffic_totals(), (request.len() as u64, 0));
    }

    #[tokio::test]
    async fn network_reset_drops_nat_and_simple_cache_but_keeps_port_attached()
    {
        let (dispatcher, port, _returned, outbounds) = routed_dispatcher(
            serde_json::json!({"action": "route", "outbound": "wg"}),
            UDP_TIMEOUT,
        );
        let request = udp_v4();
        assert!(dispatcher.dispatch(&request).await.unwrap());
        let old_forwarded = port.take_written().pop().unwrap();
        assert_eq!(outbounds.connections().len(), 1);
        assert_eq!(dispatcher.state.lock().unwrap().ports.len(), 1);

        dispatcher.install_simple(
            ParsedPacket::parse(&tcp_v4_with_flags(0x02))
                .unwrap()
                .flow_key()
                .unwrap(),
            super::SimpleAction::Accept,
            6,
        );
        dispatcher.reset_network();
        {
            let state = dispatcher.state.lock().unwrap();
            assert!(state.forward.is_empty());
            assert!(state.reverse.is_empty());
            assert!(state.simple.is_empty());
            assert_eq!(state.ports.len(), 1);
        }
        assert!(outbounds.connections().is_empty());

        // A packet from the retired mapping is no longer claimed, while the
        // same client tuple creates a fresh mapping without reattaching the
        // packet port.
        let mut old_response = old_forwarded;
        let old = ParsedPacket::parse(&old_response).unwrap();
        rewrite_packet(
            &mut old_response,
            old,
            Rewrite {
                source_address: old.destination.ip(),
                source_selector: old.destination.port(),
                destination_address: old.source.ip(),
                destination_selector: old.source.port(),
            },
        )
        .unwrap();
        assert_eq!(port.return_packets(vec![old_response]).len(), 1);
        assert!(dispatcher.dispatch(&request).await.unwrap());
        assert_eq!(port.take_written().len(), 1);
        assert_eq!(outbounds.connections().len(), 1);
        assert_eq!(dispatcher.state.lock().unwrap().ports.len(), 1);
    }

    #[tokio::test]
    async fn reject_and_drop_verdicts_are_cached_before_userspace_stack() {
        let (reject_dispatcher, reject_port, mut reject_returned, _) =
            routed_dispatcher(
                serde_json::json!({"action": "reject"}),
                UDP_TIMEOUT,
            );
        let request = udp_v4();
        assert!(reject_dispatcher.dispatch(&request).await.unwrap());
        let first = reject_returned.try_recv().unwrap();
        assert_eq!(&first[20..22], &[3, 3]);
        assert!(reject_dispatcher.dispatch(&request).await.unwrap());
        assert_eq!(&reject_returned.try_recv().unwrap()[20..22], &[3, 3]);
        assert_eq!(reject_dispatcher.state.lock().unwrap().simple.len(), 1);
        assert!(reject_port.take_written().is_empty());

        let (drop_dispatcher, drop_port, mut drop_returned, _) =
            routed_dispatcher(
                serde_json::json!({
                    "action": "reject",
                    "method": "drop"
                }),
                UDP_TIMEOUT,
            );
        assert!(drop_dispatcher.dispatch(&request).await.unwrap());
        assert!(drop_dispatcher.dispatch(&request).await.unwrap());
        assert!(drop_returned.try_recv().is_err());
        assert_eq!(drop_dispatcher.state.lock().unwrap().simple.len(), 1);
        assert!(drop_port.take_written().is_empty());
    }
}
