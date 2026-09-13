use std::{
    cell::UnsafeCell,
    collections::HashMap,
    io,
    net::IpAddr,
    ptr,
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use ipnet::IpNet;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use windivert::{
    CloseAction, WinDivert, layer,
    packet::WinDivertPacket,
    prelude::{WinDivertFlags, WinDivertShutdownMode},
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, INVALID_SOCKET, IPPROTO_TCP, SOCK_STREAM, SOCKET, SOCKET_ERROR,
    WSADATA, WSAIoctl, WSAStartup, closesocket, socket,
};

use super::{BridgeOutbound, BridgeWrite, RunningBridge};

const RESERVED_PORT_COUNT: u16 = 1024;
const SIO_ACQUIRE_PORT_RESERVATION: u32 = 0x8000_0000 | 0x1800_0000 | 100;
const BATCH_BUFFER_SIZE: usize = 256 * 1024;
const ICMP_FLOW_TIMEOUT: Duration = Duration::from_secs(60);
const RETRY_MIN: Duration = Duration::from_millis(100);
const RETRY_MAX: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalSegment {
    prefix: IpNet,
    address: IpAddr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct EgressState {
    ipv4: Option<IpAddr>,
    ipv6: Option<IpAddr>,
    mtu: usize,
    ipv4_segments: Vec<LocalSegment>,
    ipv6_segments: Vec<LocalSegment>,
}

impl EgressState {
    fn source_address(&self, destination: IpAddr) -> Option<IpAddr> {
        let (segments, fallback) = if destination.is_ipv4() {
            (&self.ipv4_segments, self.ipv4)
        } else {
            (&self.ipv6_segments, self.ipv6)
        };
        segments
            .iter()
            .find(|segment| segment.prefix.contains(&destination))
            .map(|segment| segment.address)
            .or(fallback)
    }

    fn divert_addresses(&self, ipv6: bool) -> Vec<IpAddr> {
        let (primary, segments) = if ipv6 {
            (self.ipv6, &self.ipv6_segments)
        } else {
            (self.ipv4, &self.ipv4_segments)
        };
        let Some(primary) = primary else {
            return Vec::new();
        };
        let mut addresses = vec![primary];
        for address in segments.iter().map(|segment| segment.address) {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        addresses
    }

    fn capture_identity(&self) -> (Vec<IpAddr>, Vec<IpAddr>) {
        (self.divert_addresses(false), self.divert_addresses(true))
    }
}

#[derive(Default)]
struct IcmpTable {
    active: HashMap<(u16, IpAddr), Instant>,
    last_sweep: Option<Instant>,
}

impl IcmpTable {
    fn register(&mut self, identifier: u16, remote: IpAddr) {
        let now = Instant::now();
        if self
            .last_sweep
            .is_none_or(|last| now.duration_since(last) >= ICMP_FLOW_TIMEOUT)
        {
            self.last_sweep = Some(now);
            self.active.retain(|_, last| {
                now.duration_since(*last) < ICMP_FLOW_TIMEOUT
            });
        }
        self.active.insert((identifier, remote), now);
    }

    fn is_active(&mut self, identifier: u16, remote: IpAddr) -> bool {
        let now = Instant::now();
        let Some(last) = self.active.get_mut(&(identifier, remote)) else {
            return false;
        };
        if now.duration_since(*last) >= ICMP_FLOW_TIMEOUT {
            self.active.remove(&(identifier, remote));
            return false;
        }
        *last = now;
        true
    }
}

struct Shared {
    outbound: Arc<BridgeOutbound>,
    egress: RwLock<EgressState>,
    icmp4: Mutex<IcmpTable>,
    icmp6: Mutex<IcmpTable>,
    reserved_start: u16,
    reserved_end: u16,
}

impl Shared {
    fn port_reserved(&self, port: u16) -> bool {
        (self.reserved_start..=self.reserved_end).contains(&port)
    }

    fn icmp_table(&self, ipv6: bool) -> &Mutex<IcmpTable> {
        if ipv6 { &self.icmp6 } else { &self.icmp4 }
    }

    fn prepare_outbound(&self, packet: &mut [u8]) -> bool {
        let Some(info) = PacketInfo::parse(packet) else {
            return false;
        };
        if info.packet_len != packet.len() {
            return false;
        }
        let destination = info.destination(packet);
        let source = self
            .egress
            .read()
            .ok()
            .and_then(|state| state.source_address(destination));
        let Some(source) = source else {
            return false;
        };
        match info.protocol {
            6 | 17 => {
                if let Some(offset) = info.transport_offset {
                    let Some(transport) = packet.get(offset..) else {
                        return false;
                    };
                    if transport.len() < 4
                        || !self.port_reserved(u16::from_be_bytes([
                            transport[0],
                            transport[1],
                        ]))
                    {
                        return false;
                    }
                }
            }
            1 | 58 => {
                if let Some(offset) = info.transport_offset {
                    let Some(identifier) = icmp_identifier(
                        packet.get(offset..).unwrap_or_default(),
                        info.ipv6,
                    ) else {
                        return false;
                    };
                    if let Ok(mut table) = self.icmp_table(info.ipv6).lock() {
                        table.register(identifier, destination);
                    }
                }
            }
            _ => return false,
        }
        rewrite_address(packet, info, source, true)
    }

    fn classify_inbound(&self, packet: &mut [u8]) -> bool {
        let Some(info) = PacketInfo::parse(packet) else {
            return false;
        };
        let port_address = if info.ipv6 {
            self.outbound.ipv6_port
        } else {
            self.outbound.ipv4_port
        };
        match info.protocol {
            6 | 17 => rewrite_address(packet, info, port_address, false),
            1 | 58 => {
                let Some(offset) = info.transport_offset else {
                    return false;
                };
                let transport = packet.get(offset..).unwrap_or_default();
                let Some(kind) = transport.first().copied() else {
                    return false;
                };
                let echo_reply =
                    matches!((info.protocol, kind), (1, 0) | (58, 129));
                if echo_reply {
                    let Some(identifier) =
                        icmp_identifier(transport, info.ipv6)
                    else {
                        return false;
                    };
                    let remote = info.source(packet);
                    let active = self.icmp_table(info.ipv6).lock().is_ok_and(
                        |mut table| table.is_active(identifier, remote),
                    );
                    active && rewrite_address(packet, info, port_address, false)
                } else if is_icmp_error(info.protocol, kind) && !info.fragmented
                {
                    self.classify_icmp_error(packet, info, port_address)
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn classify_icmp_error(
        &self,
        packet: &mut [u8],
        outer: PacketInfo,
        port_address: IpAddr,
    ) -> bool {
        let Some(outer_transport) = outer.transport_offset else {
            return false;
        };
        let Some(inner_offset) = outer_transport.checked_add(8) else {
            return false;
        };
        let Some(inner) = PacketInfo::parse_embedded(packet, inner_offset)
        else {
            return false;
        };
        let outer_destination = outer.destination(packet);
        if inner.source(packet) != outer_destination {
            return false;
        }
        let remote = inner.destination(packet);
        let active = match inner.protocol {
            6 | 17 => inner.transport_offset.is_some_and(|offset| {
                packet.get(offset..offset + 2).is_some_and(|port| {
                    self.port_reserved(u16::from_be_bytes([port[0], port[1]]))
                })
            }),
            1 | 58 => inner.transport_offset.is_some_and(|offset| {
                let transport = packet.get(offset..).unwrap_or_default();
                let expected = if inner.ipv6 { 128 } else { 8 };
                if transport.first().copied() != Some(expected) {
                    return false;
                }
                icmp_identifier(transport, inner.ipv6).is_some_and(
                    |identifier| {
                        self.icmp_table(inner.ipv6).lock().is_ok_and(
                            |mut table| table.is_active(identifier, remote),
                        )
                    },
                )
            }),
            _ => false,
        };
        active && rewrite_address(packet, inner, port_address, true)
    }
}

pub(crate) struct WindowsBridge {
    cancellation: CancellationToken,
    write_task: JoinHandle<()>,
    supervisor: JoinHandle<()>,
    _reservation: PortReservation,
}

impl WindowsBridge {
    pub(crate) async fn close(self) -> io::Result<()> {
        self.cancellation.cancel();
        let _ = self.write_task.await;
        let _ = self.supervisor.await;
        Ok(())
    }
}

pub(crate) async fn start(
    outbound: Arc<BridgeOutbound>,
) -> io::Result<RunningBridge> {
    let reservation = PortReservation::acquire(RESERVED_PORT_COUNT)?;
    let reserved_start = reservation.start;
    let reserved_end = reserved_start
        .checked_add(RESERVED_PORT_COUNT - 1)
        .ok_or_else(|| io::Error::other("invalid reserved port block"))?;
    outbound.set_selector_start(reserved_start);

    let state = current_egress(outbound.options().interface.as_str());
    apply_egress(&outbound, &state);
    let shared = Arc::new(Shared {
        outbound: outbound.clone(),
        egress: RwLock::new(state.clone()),
        icmp4: Mutex::new(IcmpTable::default()),
        icmp6: Mutex::new(IcmpTable::default()),
        reserved_start,
        reserved_end,
    });

    let inject = WinDivert::network(
        "false",
        i16::MAX,
        WinDivertFlags::default().set_send_only(),
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("open WinDivert injection handle (Administrator required): {error}"),
        )
    })?;
    let captures = CaptureSet::open(shared.clone(), &state)?;
    let cancellation = CancellationToken::new();
    let (writes, write_rx) = mpsc::channel::<BridgeWrite>(64);
    let write_task = tokio::spawn(write_loop(
        shared.clone(),
        inject,
        write_rx,
        cancellation.clone(),
    ));
    let supervisor = tokio::spawn(supervise(
        shared,
        outbound.clone(),
        outbound.options().interface.clone(),
        state,
        captures,
        cancellation.clone(),
    ));
    Ok(RunningBridge {
        writes,
        backend: WindowsBridge {
            cancellation,
            write_task,
            supervisor,
            _reservation: reservation,
        },
    })
}

async fn write_loop(
    shared: Arc<Shared>,
    mut inject: WinDivert<layer::NetworkLayer>,
    mut writes: mpsc::Receiver<BridgeWrite>,
    cancellation: CancellationToken,
) {
    loop {
        let write = tokio::select! {
            _ = cancellation.cancelled() => break,
            write = writes.recv() => {
                let Some(write) = write else { break; };
                write
            }
        };
        let mut packets = Vec::with_capacity(write.packets.len());
        for mut bytes in write.packets {
            if bytes.is_empty()
                || bytes.len() > u16::MAX as usize
                || !shared.prepare_outbound(&mut bytes)
            {
                continue;
            }
            // SAFETY: all required network-layer address fields are populated
            // before the packet is passed to WinDivert.
            let mut packet =
                unsafe { WinDivertPacket::<layer::NetworkLayer>::new(bytes) };
            packet.address.set_outbound(true);
            packet.address.as_mut().set_ipv6(
                packet.data.first().is_some_and(|byte| byte >> 4 == 6),
            );
            packet.address.set_ip_checksum(true);
            packet.address.set_tcp_checksum(true);
            packet.address.set_udp_checksum(true);
            packets.push(packet);
        }
        let result = if packets.is_empty() {
            Ok(())
        } else {
            inject.send_ex(packets.iter()).map(|_| ()).map_err(|error| {
                io::Error::other(format!("WinDivert inject: {error}"))
            })
        };
        let _ = write.result.send(result);
    }
    let _ = inject.close(CloseAction::Nothing);
}

async fn supervise(
    shared: Arc<Shared>,
    outbound: Arc<BridgeOutbound>,
    interface: String,
    mut state: EgressState,
    mut captures: CaptureSet,
    cancellation: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            _ = interval.tick() => {}
        }
        let interface = interface.clone();
        let next =
            tokio::task::spawn_blocking(move || current_egress(&interface))
                .await
                .unwrap_or_default();
        if next == state {
            continue;
        }
        let rebuild = next.capture_identity() != state.capture_identity();
        if rebuild {
            captures.stop();
            match CaptureSet::open(shared.clone(), &next) {
                Ok(next_captures) => captures = next_captures,
                Err(error) => {
                    tracing::warn!(%error, "rebuild Windows bridge WinDivert captures");
                    let empty = EgressState::default();
                    if let Ok(mut current) = shared.egress.write() {
                        *current = empty.clone();
                    }
                    apply_egress(&outbound, &empty);
                    state = empty;
                    continue;
                }
            }
        }
        if let Ok(mut current) = shared.egress.write() {
            *current = next.clone();
        }
        apply_egress(&outbound, &next);
        state = next;
    }
    captures.stop();
}

fn apply_egress(outbound: &BridgeOutbound, state: &EgressState) {
    outbound.set_effective_mtu(state.mtu);
    outbound.set_ipv6_active(state.ipv6.is_some());
}

fn current_egress(interface: &str) -> EgressState {
    let interfaces = netdev::get_interfaces();
    let selected = if interface.is_empty() {
        netdev::get_default_interface().ok()
    } else {
        interfaces
            .iter()
            .find(|candidate| {
                candidate.name == interface
                    || candidate.friendly_name.as_deref() == Some(interface)
                    || candidate.description.as_deref() == Some(interface)
            })
            .cloned()
    };
    let Some(selected) = selected else {
        return EgressState::default();
    };
    let mut state = EgressState {
        ipv4: selected
            .ipv4
            .iter()
            .map(|network| IpAddr::V4(network.addr()))
            .find(|address| usable_address(*address)),
        ipv6: selected
            .ipv6
            .iter()
            .map(|network| IpAddr::V6(network.addr()))
            .find(|address| usable_address(*address)),
        mtu: selected.mtu.unwrap_or(0) as usize,
        ..EgressState::default()
    };
    for candidate in &interfaces {
        if !interface.is_empty() && candidate.index != selected.index {
            continue;
        }
        if !candidate.is_up()
            || candidate.is_loopback()
            || candidate.is_point_to_point()
        {
            continue;
        }
        for network in &candidate.ipv4 {
            let address = IpAddr::V4(network.addr());
            if state.ipv4.is_some() && usable_address(address) {
                append_segment(
                    &mut state.ipv4_segments,
                    LocalSegment {
                        prefix: IpNet::V4(*network).trunc(),
                        address,
                    },
                );
            }
        }
        for network in &candidate.ipv6 {
            let address = IpAddr::V6(network.addr());
            if state.ipv6.is_some() && usable_address(address) {
                append_segment(
                    &mut state.ipv6_segments,
                    LocalSegment {
                        prefix: IpNet::V6(*network).trunc(),
                        address,
                    },
                );
            }
        }
    }
    sort_segments(&mut state.ipv4_segments);
    sort_segments(&mut state.ipv6_segments);
    state
}

fn usable_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_multicast()
                && !address.is_broadcast()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_unicast_link_local()
                && !address.is_multicast()
        }
    }
}

fn append_segment(segments: &mut Vec<LocalSegment>, segment: LocalSegment) {
    if !segments
        .iter()
        .any(|existing| existing.prefix == segment.prefix)
    {
        segments.push(segment);
    }
}

fn sort_segments(segments: &mut [LocalSegment]) {
    segments.sort_by(|left, right| {
        right
            .prefix
            .prefix_len()
            .cmp(&left.prefix.prefix_len())
            .then_with(|| left.prefix.addr().cmp(&right.prefix.addr()))
            .then_with(|| left.address.cmp(&right.address))
    });
}

struct SharedHandle {
    divert: UnsafeCell<WinDivert<layer::NetworkLayer>>,
    closed: AtomicBool,
}

// SAFETY: exactly one capture worker performs recv/send. The supervisor only
// invokes WinDivertShutdown to interrupt that worker, which the API explicitly
// permits concurrently with a blocking receive.
unsafe impl Send for SharedHandle {}
unsafe impl Sync for SharedHandle {}

impl SharedHandle {
    fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        // SAFETY: concurrent shutdown is allowed by WinDivert.
        let _ = unsafe { &mut *self.divert.get() }
            .shutdown(WinDivertShutdownMode::Recv);
    }

    fn close(&self) {
        // SAFETY: called by the worker after its receive loop has ended.
        let _ = unsafe { &mut *self.divert.get() }.close(CloseAction::Nothing);
    }
}

struct CaptureWorker {
    handle: Arc<SharedHandle>,
    thread: Option<thread::JoinHandle<()>>,
}

struct CaptureSet {
    workers: Vec<CaptureWorker>,
}

impl CaptureSet {
    fn open(shared: Arc<Shared>, state: &EgressState) -> io::Result<Self> {
        let mut set = Self {
            workers: Vec::new(),
        };
        for ipv6 in [false, true] {
            let addresses = state.divert_addresses(ipv6);
            if addresses.is_empty() {
                continue;
            }
            let filter = capture_filter(
                &addresses,
                ipv6,
                shared.reserved_start,
                shared.reserved_end,
            );
            let divert =
                WinDivert::network(&filter, 0, WinDivertFlags::default())
                    .map_err(|error| {
                        io::Error::other(format!(
                            "open WinDivert capture: {error}"
                        ))
                    })?;
            let handle = Arc::new(SharedHandle {
                divert: UnsafeCell::new(divert),
                closed: AtomicBool::new(false),
            });
            let worker_handle = handle.clone();
            let worker_shared = shared.clone();
            let thread = thread::Builder::new()
                .name(format!(
                    "singbox-bridge-windivert-{}",
                    if ipv6 { "v6" } else { "v4" }
                ))
                .spawn(move || capture_loop(worker_shared, worker_handle))
                .map_err(|error| {
                    io::Error::other(format!(
                        "start WinDivert capture: {error}"
                    ))
                })?;
            set.workers.push(CaptureWorker {
                handle,
                thread: Some(thread),
            });
        }
        Ok(set)
    }

    fn stop(&mut self) {
        for worker in &self.workers {
            worker.handle.shutdown();
        }
        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                let _ = thread.join();
            }
        }
        self.workers.clear();
    }
}

impl Drop for CaptureSet {
    fn drop(&mut self) {
        self.stop();
    }
}

fn capture_loop(shared: Arc<Shared>, handle: Arc<SharedHandle>) {
    let mut buffer = vec![0u8; BATCH_BUFFER_SIZE];
    let mut retry = RETRY_MIN;
    loop {
        // SAFETY: this worker is the sole receiver/sender for the handle.
        let received = unsafe { &*handle.divert.get() }.recv_ex(
            Some(&mut buffer),
            usize::from(WinDivert::<()>::MAX_BATCH),
        );
        let packets = match received {
            Ok(packets) => {
                retry = RETRY_MIN;
                packets
            }
            Err(_) => {
                if handle.closed.load(Ordering::Acquire) {
                    break;
                }
                thread::sleep(retry);
                retry = (retry * 2).min(RETRY_MAX);
                continue;
            }
        };
        for packet in packets {
            let mut bytes = packet.data.to_vec();
            if shared.classify_inbound(&mut bytes) {
                shared.outbound.deliver_return(bytes);
            } else {
                // SAFETY: only this worker sends through the capture handle.
                if unsafe { &*handle.divert.get() }.send(&packet).is_err() {
                    tracing::debug!(
                        "reinject unclaimed Windows bridge packet failed"
                    );
                }
            }
        }
    }
    handle.close();
}

fn capture_filter(
    addresses: &[IpAddr],
    ipv6: bool,
    port_start: u16,
    port_end: u16,
) -> String {
    let (network, address_field, icmp) = if ipv6 {
        ("ipv6", "ipv6.DstAddr", "icmpv6")
    } else {
        ("ip", "ip.DstAddr", "icmp")
    };
    let addresses = addresses
        .iter()
        .map(|address| format!("{address_field} == {address}"))
        .collect::<Vec<_>>()
        .join(" or ");
    let errors = if ipv6 {
        format!("({icmp}.Type >= 1 and {icmp}.Type <= 4)")
    } else {
        format!(
            "({icmp}.Type == 3 or {icmp}.Type == 4 or {icmp}.Type == 5 or {icmp}.Type == 11 or {icmp}.Type == 12)"
        )
    };
    let echo_reply = if ipv6 { 129 } else { 0 };
    format!(
        "inbound and {network} and ({addresses}) and ((tcp and (tcp.DstPort >= {port_start}) and (tcp.DstPort <= {port_end})) or (udp and (udp.DstPort >= {port_start}) and (udp.DstPort <= {port_end})) or ({icmp} and ({icmp}.Type == {echo_reply} or {errors})))"
    )
}

#[derive(Debug, Clone, Copy)]
struct PacketInfo {
    ipv6: bool,
    protocol: u8,
    ip_offset: usize,
    ip_header_len: usize,
    transport_offset: Option<usize>,
    packet_len: usize,
    fragmented: bool,
}

impl PacketInfo {
    fn parse(packet: &[u8]) -> Option<Self> {
        Self::parse_at(packet, 0, true)
    }

    fn parse_embedded(packet: &[u8], offset: usize) -> Option<Self> {
        Self::parse_at(packet, offset, false)
    }

    fn parse_at(
        packet: &[u8],
        offset: usize,
        enforce_length: bool,
    ) -> Option<Self> {
        let inner = packet.get(offset..)?;
        match inner.first()? >> 4 {
            4 => {
                if inner.len() < 20 {
                    return None;
                }
                let header_len = usize::from(inner[0] & 0x0f) * 4;
                let declared =
                    usize::from(u16::from_be_bytes([inner[2], inner[3]]));
                if header_len < 20
                    || header_len > inner.len()
                    || declared < header_len
                    || enforce_length && declared > inner.len()
                {
                    return None;
                }
                let fragment = u16::from_be_bytes([inner[6], inner[7]]);
                Some(Self {
                    ipv6: false,
                    protocol: inner[9],
                    ip_offset: offset,
                    ip_header_len: header_len,
                    transport_offset: (fragment & 0x1fff == 0)
                        .then_some(offset + header_len),
                    packet_len: if enforce_length {
                        declared
                    } else {
                        inner.len()
                    },
                    fragmented: fragment & 0x3fff != 0,
                })
            }
            6 => {
                if inner.len() < 40 {
                    return None;
                }
                let declared =
                    40usize.checked_add(usize::from(u16::from_be_bytes([
                        inner[4], inner[5],
                    ])))?;
                if enforce_length && declared > inner.len() {
                    return None;
                }
                let available = if enforce_length {
                    declared
                } else {
                    inner.len()
                };
                let mut protocol = inner[6];
                let mut cursor = 40;
                let mut fragmented = false;
                loop {
                    match protocol {
                        0 | 43 | 60 => {
                            let extension = inner.get(cursor..available)?;
                            if extension.len() < 2 {
                                return None;
                            }
                            let length = (usize::from(extension[1]) + 1) * 8;
                            if length > extension.len() {
                                return None;
                            }
                            protocol = extension[0];
                            cursor += length;
                        }
                        44 => {
                            let extension = inner.get(cursor..cursor + 8)?;
                            fragmented = true;
                            protocol = extension[0];
                            let fragment = u16::from_be_bytes([
                                extension[2],
                                extension[3],
                            ]);
                            cursor += 8;
                            if fragment & 0xfff8 != 0 {
                                return Some(Self {
                                    ipv6: true,
                                    protocol,
                                    ip_offset: offset,
                                    ip_header_len: 40,
                                    transport_offset: None,
                                    packet_len: available,
                                    fragmented,
                                });
                            }
                        }
                        59 => return None,
                        _ => break,
                    }
                }
                Some(Self {
                    ipv6: true,
                    protocol,
                    ip_offset: offset,
                    ip_header_len: 40,
                    transport_offset: Some(offset + cursor),
                    packet_len: available,
                    fragmented,
                })
            }
            _ => None,
        }
    }

    fn source(self, packet: &[u8]) -> IpAddr {
        if self.ipv6 {
            IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(
                    &packet[self.ip_offset + 8..self.ip_offset + 24],
                )
                .expect("validated IPv6 source"),
            ))
        } else {
            IpAddr::V4(std::net::Ipv4Addr::new(
                packet[self.ip_offset + 12],
                packet[self.ip_offset + 13],
                packet[self.ip_offset + 14],
                packet[self.ip_offset + 15],
            ))
        }
    }

    fn destination(self, packet: &[u8]) -> IpAddr {
        if self.ipv6 {
            IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(
                    &packet[self.ip_offset + 24..self.ip_offset + 40],
                )
                .expect("validated IPv6 destination"),
            ))
        } else {
            IpAddr::V4(std::net::Ipv4Addr::new(
                packet[self.ip_offset + 16],
                packet[self.ip_offset + 17],
                packet[self.ip_offset + 18],
                packet[self.ip_offset + 19],
            ))
        }
    }
}

fn rewrite_address(
    packet: &mut [u8],
    info: PacketInfo,
    address: IpAddr,
    source: bool,
) -> bool {
    if address.is_ipv6() != info.ipv6 {
        return false;
    }
    let old = if source {
        info.source(packet)
    } else {
        info.destination(packet)
    };
    match address {
        IpAddr::V4(address) => {
            let offset = info.ip_offset + if source { 12 } else { 16 };
            packet[offset..offset + 4].copy_from_slice(&address.octets());
            let header = &mut packet
                [info.ip_offset..info.ip_offset + info.ip_header_len];
            header[10..12].fill(0);
            let checksum = internet_checksum(header);
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        IpAddr::V6(address) => {
            let offset = info.ip_offset + if source { 8 } else { 24 };
            packet[offset..offset + 16].copy_from_slice(&address.octets());
        }
    }
    if let Some(offset) = info.transport_offset {
        adjust_transport_address(
            packet.get_mut(offset..).unwrap_or_default(),
            info.protocol,
            info.ipv6,
            old,
            address,
        );
    }
    true
}

fn adjust_transport_address(
    transport: &mut [u8],
    protocol: u8,
    ipv6: bool,
    old: IpAddr,
    new: IpAddr,
) {
    let checksum_offset = match protocol {
        6 if transport.len() >= 18 => 16,
        17 if transport.len() >= 8 => 6,
        58 if ipv6 && transport.len() >= 4 => 2,
        _ => return,
    };
    let checksum = u16::from_be_bytes([
        transport[checksum_offset],
        transport[checksum_offset + 1],
    ]);
    if protocol == 17 && checksum == 0 {
        return;
    }
    let checksum = adjust_checksum_address(checksum, old, new);
    let checksum = if protocol == 17 && checksum == 0 {
        u16::MAX
    } else {
        checksum
    };
    transport[checksum_offset..checksum_offset + 2]
        .copy_from_slice(&checksum.to_be_bytes());
}

fn adjust_checksum_address(checksum: u16, old: IpAddr, new: IpAddr) -> u16 {
    let old = address_bytes(old);
    let new = address_bytes(new);
    old.chunks_exact(2).zip(new.chunks_exact(2)).fold(
        checksum,
        |checksum, (old, new)| {
            adjust_checksum_word(
                checksum,
                u16::from_be_bytes([old[0], old[1]]),
                u16::from_be_bytes([new[0], new[1]]),
            )
        },
    )
}

fn address_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

fn adjust_checksum_word(checksum: u16, old: u16, new: u16) -> u16 {
    let mut sum = u32::from(!checksum) + u32::from(!old) + u32::from(new);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut chunks = data.chunks_exact(2);
    let mut sum = chunks.by_ref().fold(0u32, |sum, chunk| {
        sum + u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
    });
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmp_identifier(transport: &[u8], ipv6: bool) -> Option<u16> {
    if transport.len() < 8
        || !matches!((ipv6, transport[0]), (false, 0 | 8) | (true, 128 | 129))
    {
        return None;
    }
    Some(u16::from_be_bytes([transport[4], transport[5]]))
}

fn is_icmp_error(protocol: u8, kind: u8) -> bool {
    matches!((protocol, kind), (1, 3 | 4 | 5 | 11 | 12) | (58, 1..=4))
}

struct PortReservation {
    socket: SOCKET,
    start: u16,
}

impl PortReservation {
    fn acquire(count: u16) -> io::Result<Self> {
        ensure_winsock()?;
        // SAFETY: parameters are Windows socket constants and no pointers are
        // involved in socket creation.
        let socket =
            unsafe { socket(i32::from(AF_INET), SOCK_STREAM, IPPROTO_TCP) };
        if socket == INVALID_SOCKET {
            return Err(io::Error::last_os_error());
        }
        let mut input = [0u8; 4];
        input[2..4].copy_from_slice(&count.to_le_bytes());
        let mut output = [0u8; 16];
        let mut returned = 0u32;
        // SAFETY: input/output buffers and their lengths are valid for the
        // SIO_ACQUIRE_PORT_RESERVATION contract; overlapped completion is not
        // requested.
        let result = unsafe {
            WSAIoctl(
                socket,
                SIO_ACQUIRE_PORT_RESERVATION,
                input.as_ptr().cast(),
                input.len() as u32,
                output.as_mut_ptr().cast(),
                output.len() as u32,
                &mut returned,
                ptr::null_mut(),
                None,
            )
        };
        if result == SOCKET_ERROR {
            let error = io::Error::last_os_error();
            // SAFETY: socket is a live handle returned above.
            unsafe { closesocket(socket) };
            return Err(error);
        }
        let start = u16::from_be_bytes([output[0], output[1]]);
        let reserved = u16::from_le_bytes([output[2], output[3]]);
        if start == 0 || reserved < count {
            // SAFETY: socket is a live handle returned above.
            unsafe { closesocket(socket) };
            return Err(io::Error::other(format!(
                "Windows reserved only {reserved} of {count} bridge ports"
            )));
        }
        Ok(Self { socket, start })
    }
}

impl Drop for PortReservation {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the socket.
        unsafe { closesocket(self.socket) };
    }
}

fn ensure_winsock() -> io::Result<()> {
    static STARTUP: OnceLock<i32> = OnceLock::new();
    let result = *STARTUP.get_or_init(|| {
        let mut data = std::mem::MaybeUninit::<WSADATA>::zeroed();
        // SAFETY: data points to writable WSADATA storage.
        unsafe { WSAStartup(0x0202, data.as_mut_ptr()) }
    });
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_covers_reserved_transport_and_icmp_return_classes() {
        let filter = capture_filter(
            &["192.0.2.8".parse().unwrap()],
            false,
            50_000,
            51_023,
        );
        assert!(filter.contains("tcp.DstPort >= 50000"));
        assert!(filter.contains("udp.DstPort <= 51023"));
        assert!(filter.contains("icmp.Type == 0"));
        assert!(filter.contains("icmp.Type == 3"));
    }

    #[test]
    fn connected_segment_source_wins_over_default_egress() {
        let state = EgressState {
            ipv4: Some("198.51.100.7".parse().unwrap()),
            ipv4_segments: vec![LocalSegment {
                prefix: "192.168.1.0/24".parse().unwrap(),
                address: "192.168.1.10".parse().unwrap(),
            }],
            ..EgressState::default()
        };
        assert_eq!(
            state.source_address("192.168.1.22".parse().unwrap()),
            Some("192.168.1.10".parse().unwrap())
        );
        assert_eq!(
            state.source_address("1.1.1.1".parse().unwrap()),
            Some("198.51.100.7".parse().unwrap())
        );
    }
}
