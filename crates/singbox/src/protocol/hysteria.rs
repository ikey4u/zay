//! Hysteria v1 protocol wire formats.
//!
//! The original protocol uses a dedicated QUIC control stream, one request
//! header per proxy stream, and a fixed-width datagram header. These codecs
//! intentionally do not depend on a QUIC implementation so they can be
//! checked byte-for-byte against `sing-quic/hysteria`.

use std::{
    any::Any,
    collections::{HashMap, VecDeque},
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use n0_watcher::Watcher as _;
use quinn::{
    AsyncUdpSocket, Connection, Endpoint, EndpointConfig, RecvStream,
    Runtime as _, SendStream, TokioRuntime, UdpPoller,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    udp::{RecvMeta, Transmit},
};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    sync::Mutex,
    task::JoinHandle,
};

use crate::{
    adapter::{
        DialFuture, Dialer, PacketConnection, PacketFuture, PacketStream,
        Stream,
    },
    common::{
        network::SocksAddr,
        quic::PacketUdpSocket,
        tls::{ClientTlsConfig, ServerTlsConfig},
    },
};

pub const MBPS_TO_BPS: u64 = 125_000;
pub const MIN_SPEED_BPS: u64 = 16_384;
pub const DEFAULT_ALPN: &str = "hysteria";
pub const PROTOCOL_VERSION: u8 = 3;
pub const XPLUS_SALT_LENGTH: usize = 16;
pub const MAX_UDP_SIZE: usize = u16::MAX as usize;
pub const DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);
pub const MIN_HOP_INTERVAL: Duration = Duration::from_secs(5);

const BRUTAL_PACKET_INFO_SLOTS: usize = 5;
const BRUTAL_MIN_SAMPLE_COUNT: u64 = 50;
const BRUTAL_MIN_ACK_RATE: f64 = 0.8;
const BRUTAL_INITIAL_WINDOW: u64 = 10_240;

/// Mutable rate shared between a Quinn congestion-controller instance and the
/// Hysteria control-stream handshake. Quinn constructs the controller before
/// that handshake completes, so the peer-advertised receive limit is applied
/// through this handle immediately after `ServerHello` is authenticated.
#[derive(Clone)]
pub struct HysteriaBrutalConfig {
    bps: Arc<AtomicU64>,
    debug: bool,
    bbr_profile: super::quic_bbr::BbrProfile,
}

impl HysteriaBrutalConfig {
    pub fn new(bps: u64) -> Self {
        Self::with_debug(bps, false)
    }

    pub fn with_debug(bps: u64, debug: bool) -> Self {
        Self::with_profile(
            bps,
            debug,
            crate::protocol::quic_bbr::BbrProfile::Standard,
        )
    }

    pub fn with_profile(
        bps: u64,
        debug: bool,
        bbr_profile: super::quic_bbr::BbrProfile,
    ) -> Self {
        Self {
            bps: Arc::new(AtomicU64::new(bps)),
            debug,
            bbr_profile,
        }
    }

    pub fn bps(&self) -> u64 {
        self.bps.load(Ordering::Relaxed)
    }

    pub fn set_bps(&self, bps: u64) {
        self.bps.store(bps, Ordering::Relaxed);
    }

    pub const fn bbr_profile(&self) -> super::quic_bbr::BbrProfile {
        self.bbr_profile
    }
}

impl quinn::congestion::ControllerFactory for HysteriaBrutalConfig {
    fn build(
        self: Arc<Self>,
        now: std::time::Instant,
        current_mtu: u16,
    ) -> Box<dyn quinn::congestion::Controller> {
        Box::new(HysteriaBrutalController::new(
            self.bps.clone(),
            self.debug,
            self.bbr_profile,
            now,
            current_mtu,
        ))
    }
}

/// Server-side factory that gives every accepted QUIC connection an isolated
/// mutable rate. `Incoming::accept` constructs the controller synchronously,
/// allowing the accept loop to take the just-created handle before it spawns
/// authentication for that connection.
pub struct HysteriaBrutalServerConfig {
    initial_bps: u64,
    debug: bool,
    bbr_profile: super::quic_bbr::BbrProfile,
    pending: StdMutex<VecDeque<HysteriaBrutalConfig>>,
}

impl HysteriaBrutalServerConfig {
    pub fn new(initial_bps: u64) -> Self {
        Self::with_debug(initial_bps, false)
    }

    pub fn with_debug(initial_bps: u64, debug: bool) -> Self {
        Self::with_profile(
            initial_bps,
            debug,
            super::quic_bbr::BbrProfile::Standard,
        )
    }

    pub fn with_profile(
        initial_bps: u64,
        debug: bool,
        bbr_profile: super::quic_bbr::BbrProfile,
    ) -> Self {
        Self {
            initial_bps,
            debug,
            bbr_profile,
            pending: StdMutex::new(VecDeque::new()),
        }
    }

    pub fn take_pending(&self) -> Option<HysteriaBrutalConfig> {
        self.pending.lock().unwrap().pop_back()
    }
}

impl quinn::congestion::ControllerFactory for HysteriaBrutalServerConfig {
    fn build(
        self: Arc<Self>,
        now: std::time::Instant,
        current_mtu: u16,
    ) -> Box<dyn quinn::congestion::Controller> {
        let rate = HysteriaBrutalConfig::with_profile(
            self.initial_bps,
            self.debug,
            self.bbr_profile,
        );
        self.pending.lock().unwrap().push_back(rate.clone());
        Box::new(HysteriaBrutalController::new(
            rate.bps,
            rate.debug,
            rate.bbr_profile,
            now,
            current_mtu,
        ))
    }
}

#[derive(Clone, Copy)]
struct BrutalPacketInfo {
    timestamp: u64,
    ack_count: u64,
    loss_count: u64,
}

impl Default for BrutalPacketInfo {
    fn default() -> Self {
        Self {
            timestamp: u64::MAX,
            ack_count: 0,
            loss_count: 0,
        }
    }
}

struct HysteriaBrutalController {
    bps: Arc<AtomicU64>,
    debug: bool,
    fallback: Box<dyn quinn::congestion::Controller>,
    started: std::time::Instant,
    mtu: u16,
    smoothed_rtt: Option<Duration>,
    packet_info: [BrutalPacketInfo; BRUTAL_PACKET_INFO_SLOTS],
    ack_rate: f64,
    last_debug_timestamp: u64,
}

impl Clone for HysteriaBrutalController {
    fn clone(&self) -> Self {
        Self {
            bps: self.bps.clone(),
            debug: self.debug,
            fallback: self.fallback.clone_box(),
            started: self.started,
            mtu: self.mtu,
            smoothed_rtt: self.smoothed_rtt,
            packet_info: self.packet_info,
            ack_rate: self.ack_rate,
            last_debug_timestamp: self.last_debug_timestamp,
        }
    }
}

impl HysteriaBrutalController {
    fn new(
        bps: Arc<AtomicU64>,
        debug: bool,
        bbr_profile: super::quic_bbr::BbrProfile,
        started: std::time::Instant,
        mtu: u16,
    ) -> Self {
        Self {
            bps,
            debug,
            fallback: quinn::congestion::ControllerFactory::build(
                Arc::new(super::quic_bbr::BbrConfig::new(bbr_profile)),
                started,
                mtu,
            ),
            started,
            mtu,
            smoothed_rtt: None,
            packet_info: [BrutalPacketInfo::default();
                BRUTAL_PACKET_INFO_SLOTS],
            ack_rate: 1.0,
            last_debug_timestamp: 0,
        }
    }

    fn timestamp(&self, now: std::time::Instant) -> u64 {
        now.saturating_duration_since(self.started).as_secs()
    }

    fn record(&mut self, now: std::time::Instant, acked: u64, lost: u64) {
        let timestamp = self.timestamp(now);
        let slot = usize::try_from(
            timestamp % u64::try_from(BRUTAL_PACKET_INFO_SLOTS).unwrap(),
        )
        .unwrap();
        let info = &mut self.packet_info[slot];
        if info.timestamp != timestamp {
            *info = BrutalPacketInfo {
                timestamp,
                ack_count: acked,
                loss_count: lost,
            };
        } else {
            info.ack_count = info.ack_count.saturating_add(acked);
            info.loss_count = info.loss_count.saturating_add(lost);
        }
        let minimum = timestamp.saturating_sub(BRUTAL_PACKET_INFO_SLOTS as u64);
        let (ack_count, loss_count) = self
            .packet_info
            .iter()
            .filter(|info| {
                info.timestamp != u64::MAX && info.timestamp >= minimum
            })
            .fold((0_u64, 0_u64), |(acks, losses), info| {
                (
                    acks.saturating_add(info.ack_count),
                    losses.saturating_add(info.loss_count),
                )
            });
        let sample_count = ack_count.saturating_add(loss_count);
        self.ack_rate = if sample_count < BRUTAL_MIN_SAMPLE_COUNT {
            1.0
        } else {
            (ack_count as f64 / sample_count as f64).max(BRUTAL_MIN_ACK_RATE)
        };
        if self.debug
            && timestamp.saturating_sub(self.last_debug_timestamp) >= 2
        {
            self.last_debug_timestamp = timestamp;
            tracing::debug!(
                target: "singbox::hysteria::brutal",
                ack_rate = self.ack_rate,
                samples = sample_count,
                acked = ack_count,
                lost = loss_count,
                "Hysteria Brutal ACK rate"
            );
        }
    }

    fn compensated_bps(&self) -> u64 {
        ((self.bps.load(Ordering::Relaxed) as f64 / self.ack_rate).round()
            as u64)
            .max(1)
    }

    fn brutal_enabled(&self) -> bool {
        self.bps.load(Ordering::Relaxed) != 0
    }
}

impl quinn::congestion::Controller for HysteriaBrutalController {
    fn on_sent(
        &mut self,
        now: std::time::Instant,
        bytes: u64,
        last_packet_number: u64,
    ) {
        if !self.brutal_enabled() {
            self.fallback.on_sent(now, bytes, last_packet_number);
        }
    }

    fn on_ack(
        &mut self,
        now: std::time::Instant,
        _sent: std::time::Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        if !self.brutal_enabled() {
            self.fallback.on_ack(now, _sent, _bytes, _app_limited, rtt);
            return;
        }
        self.smoothed_rtt = Some(rtt.get());
        self.record(now, 1, 0);
    }

    fn on_end_acks(
        &mut self,
        now: std::time::Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        if !self.brutal_enabled() {
            self.fallback.on_end_acks(
                now,
                in_flight,
                app_limited,
                largest_packet_num_acked,
            );
        }
    }

    fn on_congestion_event(
        &mut self,
        now: std::time::Instant,
        _sent: std::time::Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if !self.brutal_enabled() {
            self.fallback.on_congestion_event(
                now,
                _sent,
                _is_persistent_congestion,
                lost_bytes,
            );
            return;
        }
        if lost_bytes != 0 {
            let lost_packets = lost_bytes.div_ceil(u64::from(self.mtu)).max(1);
            self.record(now, 0, lost_packets);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        self.fallback.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        if !self.brutal_enabled() {
            return self.fallback.window();
        }
        let Some(rtt) = self.smoothed_rtt else {
            return BRUTAL_INITIAL_WINDOW;
        };
        ((self.compensated_bps() as f64 * rtt.as_secs_f64() * 2.0).round()
            as u64)
            .max(u64::from(self.mtu))
    }

    fn metrics(&self) -> quinn::congestion::ControllerMetrics {
        if !self.brutal_enabled() {
            return self.fallback.metrics();
        }
        let mut metrics = quinn::congestion::ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate = Some(self.compensated_bps().saturating_mul(8));
        metrics
    }

    fn clone_box(&self) -> Box<dyn quinn::congestion::Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        if self.brutal_enabled() {
            BRUTAL_INITIAL_WINDOW
        } else {
            self.fallback.initial_window()
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn put_string(value: &str, output: &mut Vec<u8>) -> io::Result<()> {
    let length = u16::try_from(value.len())
        .map_err(|_| invalid("Hysteria string exceeds u16"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn take_string(input: &[u8], offset: &mut usize) -> io::Result<String> {
    let length = input
        .get(*offset..*offset + 2)
        .ok_or_else(|| invalid("truncated Hysteria string length"))?;
    *offset += 2;
    let length = usize::from(u16::from_be_bytes(length.try_into().unwrap()));
    let value = input
        .get(*offset..*offset + length)
        .ok_or_else(|| invalid("truncated Hysteria string"))?;
    *offset += length;
    String::from_utf8(value.to_vec())
        .map_err(|_| invalid("Hysteria string is not UTF-8"))
}

pub fn parse_server_ports(values: &[String]) -> io::Result<Vec<u16>> {
    let mut ports = Vec::new();
    for value in values {
        let (start, end) = value.split_once(':').ok_or_else(|| {
            invalid(format!("bad Hysteria port range: {value}"))
        })?;
        let start = if start.is_empty() {
            0
        } else {
            start.parse::<u16>().map_err(|error| {
                invalid(format!("bad Hysteria port range {value}: {error}"))
            })?
        };
        let end = if end.is_empty() {
            u16::MAX
        } else {
            end.parse::<u16>().map_err(|error| {
                invalid(format!("bad Hysteria port range {value}: {error}"))
            })?
        };
        ports.extend(start..=end);
    }
    Ok(ports)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub send_bps: u64,
    pub receive_bps: u64,
    pub auth: String,
}

impl ClientHello {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(19 + self.auth.len());
        output.push(PROTOCOL_VERSION);
        output.extend_from_slice(&self.send_bps.to_be_bytes());
        output.extend_from_slice(&self.receive_bps.to_be_bytes());
        put_string(&self.auth, &mut output)?;
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> io::Result<(Self, usize)> {
        if input.first() != Some(&PROTOCOL_VERSION) {
            return Err(invalid(format!(
                "unsupported Hysteria client version: {}",
                input.first().copied().unwrap_or_default()
            )));
        }
        let send_bps = u64::from_be_bytes(
            input
                .get(1..9)
                .ok_or_else(|| invalid("truncated client hello"))?
                .try_into()
                .unwrap(),
        );
        let receive_bps = u64::from_be_bytes(
            input
                .get(9..17)
                .ok_or_else(|| invalid("truncated client hello"))?
                .try_into()
                .unwrap(),
        );
        if send_bps == 0 || receive_bps == 0 {
            return Err(invalid("invalid rate from Hysteria client"));
        }
        let mut offset = 17;
        let auth = take_string(input, &mut offset)?;
        Ok((
            Self {
                send_bps,
                receive_bps,
                auth,
            },
            offset,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub ok: bool,
    pub send_bps: u64,
    pub receive_bps: u64,
    pub message: String,
}

impl ServerHello {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(19 + self.message.len());
        output.push(u8::from(self.ok));
        output.extend_from_slice(&self.send_bps.to_be_bytes());
        output.extend_from_slice(&self.receive_bps.to_be_bytes());
        put_string(&self.message, &mut output)?;
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> io::Result<(Self, usize)> {
        let ok = *input
            .first()
            .ok_or_else(|| invalid("truncated server hello"))?
            == 1;
        let send_bps = u64::from_be_bytes(
            input
                .get(1..9)
                .ok_or_else(|| invalid("truncated server hello"))?
                .try_into()
                .unwrap(),
        );
        let receive_bps = u64::from_be_bytes(
            input
                .get(9..17)
                .ok_or_else(|| invalid("truncated server hello"))?
                .try_into()
                .unwrap(),
        );
        let mut offset = 17;
        let message = take_string(input, &mut offset)?;
        Ok((
            Self {
                ok,
                send_bps,
                receive_bps,
                message,
            },
            offset,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRequest {
    pub udp: bool,
    pub host: String,
    pub port: u16,
}

impl ClientRequest {
    pub fn encode(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut output =
            Vec::with_capacity(5 + self.host.len() + payload.len());
        output.push(u8::from(self.udp));
        put_string(&self.host, &mut output)?;
        output.extend_from_slice(&self.port.to_be_bytes());
        output.extend_from_slice(payload);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> io::Result<(Self, &[u8])> {
        let udp = *input
            .first()
            .ok_or_else(|| invalid("truncated client request"))?
            != 0;
        let mut offset = 1;
        let host = take_string(input, &mut offset)?;
        let port = u16::from_be_bytes(
            input
                .get(offset..offset + 2)
                .ok_or_else(|| invalid("truncated client request port"))?
                .try_into()
                .unwrap(),
        );
        offset += 2;
        Ok((Self { udp, host, port }, &input[offset..]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerResponse {
    pub ok: bool,
    pub udp_session_id: u32,
    pub message: String,
}

impl ServerResponse {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(7 + self.message.len());
        output.push(u8::from(self.ok));
        output.extend_from_slice(&self.udp_session_id.to_be_bytes());
        put_string(&self.message, &mut output)?;
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> io::Result<(Self, usize)> {
        let ok = *input
            .first()
            .ok_or_else(|| invalid("truncated server response"))?
            == 1;
        let udp_session_id = u32::from_be_bytes(
            input
                .get(1..5)
                .ok_or_else(|| invalid("truncated server response"))?
                .try_into()
                .unwrap(),
        );
        let mut offset = 5;
        let message = take_string(input, &mut offset)?;
        Ok((
            Self {
                ok,
                udp_session_id,
                message,
            },
            offset,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub host: String,
    pub port: u16,
    pub data: Vec<u8>,
}

impl UdpMessage {
    pub fn header_size(&self) -> io::Result<usize> {
        u16::try_from(self.host.len())
            .map_err(|_| invalid("host exceeds u16"))?;
        Ok(14 + self.host.len())
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let data_length = u16::try_from(self.data.len())
            .map_err(|_| invalid("Hysteria UDP payload exceeds u16"))?;
        let mut output =
            Vec::with_capacity(self.header_size()? + self.data.len());
        output.extend_from_slice(&self.session_id.to_be_bytes());
        put_string(&self.host, &mut output)?;
        output.extend_from_slice(&self.port.to_be_bytes());
        output.extend_from_slice(&self.packet_id.to_be_bytes());
        output.push(self.fragment_id);
        output.push(self.fragment_count);
        output.extend_from_slice(&data_length.to_be_bytes());
        output.extend_from_slice(&self.data);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> io::Result<Self> {
        let session_id = u32::from_be_bytes(
            input
                .get(..4)
                .ok_or_else(|| invalid("truncated UDP message"))?
                .try_into()
                .unwrap(),
        );
        let mut offset = 4;
        let host = take_string(input, &mut offset)?;
        let port = take_u16(input, &mut offset)?;
        let packet_id = take_u16(input, &mut offset)?;
        let fragment_id = *input
            .get(offset)
            .ok_or_else(|| invalid("truncated UDP fragment"))?;
        let fragment_count = *input
            .get(offset + 1)
            .ok_or_else(|| invalid("truncated UDP fragment"))?;
        offset += 2;
        let data_length = usize::from(take_u16(input, &mut offset)?);
        let data = input
            .get(offset..)
            .ok_or_else(|| invalid("truncated UDP data"))?;
        if data.len() != data_length {
            return Err(invalid("invalid Hysteria UDP data length"));
        }
        Ok(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            host,
            port,
            data: data.to_vec(),
        })
    }
}

fn take_u16(input: &[u8], offset: &mut usize) -> io::Result<u16> {
    let value = u16::from_be_bytes(
        input
            .get(*offset..*offset + 2)
            .ok_or_else(|| invalid("truncated u16"))?
            .try_into()
            .unwrap(),
    );
    *offset += 2;
    Ok(value)
}

pub fn fragment_udp_message(
    message: UdpMessage,
    maximum_packet_size: usize,
) -> io::Result<Vec<UdpMessage>> {
    let payload_mtu = maximum_packet_size
        .checked_sub(message.header_size()?)
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            invalid("maximum packet size is smaller than UDP header")
        })?;
    if message.data.len() <= payload_mtu {
        return Ok(vec![message]);
    }
    let count = u8::try_from(message.data.len().div_ceil(payload_mtu))
        .map_err(|_| invalid("too many UDP fragments"))?;
    Ok(message
        .data
        .chunks(payload_mtu)
        .enumerate()
        .map(|(index, data)| UdpMessage {
            session_id: message.session_id,
            packet_id: message.packet_id,
            fragment_id: index as u8,
            fragment_count: count,
            host: message.host.clone(),
            port: message.port,
            data: data.to_vec(),
        })
        .collect())
}

#[derive(Default)]
pub struct UdpDefragmenter {
    entries: HashMap<u16, FragmentEntry>,
}

struct FragmentEntry {
    updated: Instant,
    parts: Vec<Option<UdpMessage>>,
}

impl UdpDefragmenter {
    pub fn feed(&mut self, message: UdpMessage) -> Option<UdpMessage> {
        if message.fragment_count <= 1 {
            return Some(message);
        }
        if message.fragment_id >= message.fragment_count {
            return None;
        }
        if self.entries.len() >= 10
            && !self.entries.contains_key(&message.packet_id)
        {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, value)| value.updated)
                .map(|(key, _)| *key)?;
            self.entries.remove(&oldest);
        }
        let packet_id = message.packet_id;
        let entry =
            self.entries.entry(message.packet_id).or_insert_with(|| {
                FragmentEntry {
                    updated: Instant::now(),
                    parts: std::iter::repeat_with(|| None)
                        .take(usize::from(message.fragment_count))
                        .collect(),
                }
            });
        if entry.parts.len() != usize::from(message.fragment_count) {
            entry.parts = std::iter::repeat_with(|| None)
                .take(usize::from(message.fragment_count))
                .collect();
        }
        let index = usize::from(message.fragment_id);
        if entry.parts[index].is_some() {
            return None;
        }
        entry.parts[index] = Some(message);
        entry.updated = Instant::now();
        if entry.parts.iter().any(Option::is_none) {
            return None;
        }
        let entry = self.entries.remove(&packet_id)?;
        let mut parts = entry.parts.into_iter().flatten();
        let mut output = parts.next()?;
        output.fragment_id = 0;
        output.fragment_count = 1;
        for part in parts {
            output.data.extend_from_slice(&part.data);
        }
        Some(output)
    }
}

pub fn encode_xplus_with_salt(
    key: &[u8],
    salt: [u8; XPLUS_SALT_LENGTH],
    payload: &[u8],
) -> Vec<u8> {
    let mask = Sha256::digest([key, &salt].concat());
    let mut output = Vec::with_capacity(XPLUS_SALT_LENGTH + payload.len());
    output.extend_from_slice(&salt);
    output.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % mask.len()]),
    );
    output
}

pub fn encode_xplus(key: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut salt = [0_u8; XPLUS_SALT_LENGTH];
    getrandom::fill(&mut salt).map_err(io::Error::other)?;
    Ok(encode_xplus_with_salt(key, salt, payload))
}

pub fn decode_xplus(key: &[u8], packet: &[u8]) -> Vec<u8> {
    if packet.len() < XPLUS_SALT_LENGTH {
        return Vec::new();
    }
    let salt = &packet[..XPLUS_SALT_LENGTH];
    let mask = Sha256::digest([key, salt].concat());
    packet[XPLUS_SALT_LENGTH..]
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ mask[index % mask.len()])
        .collect()
}

struct XPlusSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    key: Vec<u8>,
}

impl fmt::Debug for XPlusSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XPlusSocket")
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for XPlusSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let encoded = encode_xplus(&self.key, transmit.contents)?;
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &encoded,
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        context: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let count = match self.inner.poll_recv(context, buffers, metadata) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(count)) => count,
            };
            let mut output = Vec::new();
            for index in 0..count {
                let item = metadata[index];
                let stride = if item.stride == 0 {
                    item.len
                } else {
                    item.stride.min(item.len)
                };
                if stride == 0 {
                    continue;
                }
                for packet in buffers[index][..item.len].chunks(stride) {
                    let packet = decode_xplus(&self.key, packet);
                    if !packet.is_empty() {
                        output.push((packet, item));
                    }
                }
            }
            if output.is_empty() {
                continue;
            }
            if output.len() > buffers.len() {
                return Poll::Ready(Err(invalid(
                    "XPlus receive batch exceeds buffer count",
                )));
            }
            let output_count = output.len();
            for (index, (packet, mut item)) in output.into_iter().enumerate() {
                if packet.len() > buffers[index].len() {
                    return Poll::Ready(Err(invalid(
                        "decoded QUIC datagram exceeds receive buffer",
                    )));
                }
                buffers[index][..packet.len()].copy_from_slice(&packet);
                item.len = packet.len();
                item.stride = packet.len();
                metadata[index] = item;
            }
            return Poll::Ready(Ok(output_count));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

fn endpoint(
    address: SocketAddr,
    server_config: Option<quinn::ServerConfig>,
    xplus_password: Option<Vec<u8>>,
) -> io::Result<Endpoint> {
    endpoint_with_socket(address, server_config, xplus_password, None)
}

fn endpoint_with_socket(
    address: SocketAddr,
    server_config: Option<quinn::ServerConfig>,
    xplus_password: Option<Vec<u8>>,
    socket: Option<Arc<dyn AsyncUdpSocket>>,
) -> io::Result<Endpoint> {
    let runtime = Arc::new(TokioRuntime);
    let socket = match socket {
        Some(socket) => socket,
        None => {
            let socket = std::net::UdpSocket::bind(address)?;
            socket.set_nonblocking(true)?;
            runtime.wrap_udp_socket(socket)?
        }
    };
    let socket: Arc<dyn AsyncUdpSocket> = match xplus_password {
        Some(key) => Arc::new(XPlusSocket { inner: socket, key }),
        None => socket,
    };
    Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        server_config,
        socket,
        runtime,
    )
}

pub fn server_endpoint(
    address: SocketAddr,
    tls: ServerTlsConfig,
    transport: Arc<quinn::TransportConfig>,
    xplus_password: Option<Vec<u8>>,
) -> io::Result<Endpoint> {
    let server = server_config(tls, transport)?;
    endpoint(address, Some(server), xplus_password)
}

/// Build an endpoint together with the clonable server configuration used by
/// Hysteria's accept loop. A fresh transport clone is selected for each
/// incoming connection so its post-authentication Brutal rate is isolated
/// from every other client.
pub fn server_endpoint_with_config(
    address: SocketAddr,
    tls: ServerTlsConfig,
    transport: Arc<quinn::TransportConfig>,
    xplus_password: Option<Vec<u8>>,
) -> io::Result<(Endpoint, quinn::ServerConfig)> {
    let server = server_config(tls, transport)?;
    let endpoint = endpoint(address, Some(server.clone()), xplus_password)?;
    Ok((endpoint, server))
}

fn server_config(
    tls: ServerTlsConfig,
    transport: Arc<quinn::TransportConfig>,
) -> io::Result<quinn::ServerConfig> {
    let crypto = QuicServerConfig::try_from(tls.config)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(transport);
    Ok(server)
}

pub struct HysteriaStream {
    pub send: SendStream,
    pub recv: RecvStream,
}

impl AsyncRead for HysteriaStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(context, buffer)
    }
}

impl AsyncWrite for HysteriaStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(context)
    }
}

pub struct ClientSession {
    endpoint: Endpoint,
    connection: Connection,
    _control: HysteriaStream,
    udp_channels:
        Arc<Mutex<HashMap<u32, tokio::sync::mpsc::Sender<UdpMessage>>>>,
    udp_driver: JoinHandle<()>,
    network_driver: Option<JoinHandle<()>>,
    /// Sender rate selected by the Hysteria handshake. The peer's advertised
    /// receive capacity always caps the locally configured upload rate.
    pub negotiated_send_bps: u64,
    pub server_hello: ServerHello,
}

impl ClientSession {
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        remote: SocketAddr,
        server_name: &str,
        auth: &str,
        send_bps: u64,
        receive_bps: u64,
        tls: ClientTlsConfig,
        mut transport: quinn::TransportConfig,
        xplus_password: Option<Vec<u8>>,
    ) -> io::Result<Self> {
        let brutal = HysteriaBrutalConfig::new(send_bps);
        transport.congestion_controller_factory(Arc::new(brutal.clone()));
        Self::connect_with_socket(
            remote,
            server_name,
            auth,
            send_bps,
            receive_bps,
            tls,
            Arc::new(transport),
            brutal,
            xplus_password,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_with_socket(
        remote: SocketAddr,
        server_name: &str,
        auth: &str,
        send_bps: u64,
        receive_bps: u64,
        tls: ClientTlsConfig,
        transport: Arc<quinn::TransportConfig>,
        brutal: HysteriaBrutalConfig,
        xplus_password: Option<Vec<u8>>,
        socket: Option<Arc<dyn AsyncUdpSocket>>,
    ) -> io::Result<Self> {
        if send_bps < MIN_SPEED_BPS || receive_bps < MIN_SPEED_BPS {
            return Err(invalid("Hysteria speed is missing or too small"));
        }
        let tls_config =
            tls.config_for_handshake().await.map_err(io::Error::other)?;
        let crypto = QuicClientConfig::try_from(tls_config)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        client.transport_config(transport);
        let bind = if remote.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let mut endpoint =
            endpoint_with_socket(bind, None, xplus_password, socket)?;
        endpoint.set_default_client_config(client);
        let connection = endpoint
            .connect(remote, server_name)
            .map_err(|error| io::Error::other(error.to_string()))?
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        send.write_all(
            &ClientHello {
                send_bps,
                receive_bps,
                auth: auth.to_owned(),
            }
            .encode()?,
        )
        .await?;
        let server_hello = read_server_hello(&mut recv).await?;
        if !server_hello.ok {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                server_hello.message.clone(),
            ));
        }
        if server_hello.receive_bps == 0 {
            return Err(invalid("invalid receive bandwidth from server"));
        }
        let negotiated_send_bps = send_bps.min(server_hello.receive_bps);
        brutal.set_bps(negotiated_send_bps);
        let udp_channels = Arc::new(Mutex::new(HashMap::<
            u32,
            tokio::sync::mpsc::Sender<UdpMessage>,
        >::new()));
        let udp_connection = connection.clone();
        let driver_channels = udp_channels.clone();
        let udp_driver = tokio::spawn(async move {
            while let Ok(packet) = udp_connection.read_datagram().await {
                let Ok(message) = UdpMessage::decode(&packet) else {
                    continue;
                };
                let sender = driver_channels
                    .lock()
                    .await
                    .get(&message.session_id)
                    .cloned();
                if let Some(sender) = sender {
                    let _ = sender.send(message).await;
                }
            }
        });
        let network_driver =
            crate::common::network_monitor::NetworkMonitor::new()
                .await
                .ok()
                .map(|monitor| {
                    let connection = connection.clone();
                    tokio::spawn(async move {
                        let mut watcher = monitor.interface_state();
                        let mut previous = watcher.get();
                        while let Ok(current) = watcher.updated().await {
                            let changed = current.is_major_change(&previous);
                            previous = current;
                            if changed {
                                connection
                                    .close(0_u32.into(), b"network changed");
                                break;
                            }
                        }
                    })
                });
        Ok(Self {
            endpoint,
            connection,
            _control: HysteriaStream { send, recv },
            udp_channels,
            udp_driver,
            network_driver,
            negotiated_send_bps,
            server_hello,
        })
    }

    pub async fn open_tcp(
        &self,
        host: &str,
        port: u16,
        early_payload: &[u8],
    ) -> io::Result<HysteriaStream> {
        let (mut send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        send.write_all(
            &ClientRequest {
                udp: false,
                host: host.to_owned(),
                port,
            }
            .encode(early_payload)?,
        )
        .await?;
        Ok(HysteriaStream { send, recv })
    }

    pub async fn open_tcp_checked(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<HysteriaStream> {
        let mut stream = self.open_tcp(host, port, &[]).await?;
        let response = read_server_response(&mut stream.recv).await?;
        if !response.ok {
            return Err(io::Error::other(format!(
                "Hysteria remote error: {}",
                response.message
            )));
        }
        Ok(stream)
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub async fn open_udp(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<HysteriaPacketConnection> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        send.write_all(
            &ClientRequest {
                udp: true,
                host: host.to_owned(),
                port,
            }
            .encode(&[])?,
        )
        .await?;
        let response = read_server_response(&mut recv).await?;
        if !response.ok {
            return Err(io::Error::other(response.message));
        }
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        self.udp_channels
            .lock()
            .await
            .insert(response.udp_session_id, sender);
        Ok(HysteriaPacketConnection {
            connection: self.connection.clone(),
            session_id: response.udp_session_id,
            packet_id: AtomicU32::new(0),
            receiver: Mutex::new(receiver),
            defragmenter: Mutex::new(UdpDefragmenter::default()),
            channels: self.udp_channels.clone(),
            _control: HysteriaStream { send, recv },
        })
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        self.udp_driver.abort();
        if let Some(driver) = self.network_driver.take() {
            driver.abort();
        }
        self.connection.close(0_u32.into(), b"");
        self.endpoint.close(0_u32.into(), b"");
    }
}

pub struct HysteriaPacketConnection {
    connection: Connection,
    session_id: u32,
    packet_id: AtomicU32,
    receiver: Mutex<tokio::sync::mpsc::Receiver<UdpMessage>>,
    defragmenter: Mutex<UdpDefragmenter>,
    channels: Arc<Mutex<HashMap<u32, tokio::sync::mpsc::Sender<UdpMessage>>>>,
    _control: HysteriaStream,
}

impl PacketConnection for HysteriaPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            if data.len() > MAX_UDP_SIZE {
                return Err(invalid("Hysteria UDP payload exceeds u16"));
            }
            let message = UdpMessage {
                session_id: self.session_id,
                packet_id: self.packet_id.fetch_add(1, Ordering::Relaxed)
                    as u16,
                fragment_id: 0,
                fragment_count: 1,
                host: destination.host(),
                port: destination.port(),
                data: data.to_vec(),
            };
            let mtu = self.connection.max_datagram_size().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "QUIC datagrams unavailable",
                )
            })?;
            for fragment in fragment_udp_message(message, mtu)? {
                self.connection
                    .send_datagram(bytes::Bytes::from(fragment.encode()?))
                    .map_err(|error| io::Error::other(error.to_string()))?;
            }
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            loop {
                let message =
                    self.receiver.lock().await.recv().await.ok_or_else(
                        || {
                            io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "Hysteria UDP session closed",
                            )
                        },
                    )?;
                let Some(message) =
                    self.defragmenter.lock().await.feed(message)
                else {
                    continue;
                };
                if message.data.len() > data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "receive buffer is too small",
                    ));
                }
                data[..message.data.len()].copy_from_slice(&message.data);
                return Ok((
                    message.data.len(),
                    SocksAddr::new(message.host, message.port),
                ));
            }
        })
    }
}

impl Drop for HysteriaPacketConnection {
    fn drop(&mut self) {
        if let Ok(mut channels) = self.channels.try_lock() {
            channels.remove(&self.session_id);
        }
    }
}

pub struct ServerSession {
    connection: Connection,
    _control: HysteriaStream,
    pub user: String,
    pub client_hello: ClientHello,
    /// Sender rate selected by the Hysteria handshake. The client's
    /// advertised receive capacity caps the server upload rate.
    pub negotiated_send_bps: u64,
}

impl ServerSession {
    pub async fn authenticate(
        connection: Connection,
        users: &HashMap<String, String>,
        send_bps: u64,
        receive_bps: u64,
    ) -> io::Result<Self> {
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        let client_hello = read_client_hello(&mut recv).await?;
        let Some(user) = users.get(&client_hello.auth).cloned() else {
            send.write_all(
                &ServerHello {
                    ok: false,
                    send_bps: 0,
                    receive_bps: 0,
                    message: "Wrong password".into(),
                }
                .encode()?,
            )
            .await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Hysteria authentication failed",
            ));
        };
        send.write_all(
            &ServerHello {
                ok: true,
                send_bps,
                receive_bps,
                message: String::new(),
            }
            .encode()?,
        )
        .await?;
        Ok(Self {
            connection,
            _control: HysteriaStream { send, recv },
            user,
            negotiated_send_bps: send_bps.min(client_hello.receive_bps),
            client_hello,
        })
    }

    pub async fn accept_request(
        &self,
    ) -> io::Result<(HysteriaStream, ClientRequest)> {
        let (send, mut recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        let request = read_client_request(&mut recv).await?;
        Ok((HysteriaStream { send, recv }, request))
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub async fn read_udp(&self) -> io::Result<UdpMessage> {
        let packet = self
            .connection
            .read_datagram()
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        UdpMessage::decode(&packet)
    }

    pub fn send_udp(&self, message: UdpMessage) -> io::Result<()> {
        let mtu = self.connection.max_datagram_size().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "QUIC datagrams unavailable",
            )
        })?;
        for fragment in fragment_udp_message(message, mtu)? {
            self.connection
                .send_datagram(bytes::Bytes::from(fragment.encode()?))
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
        Ok(())
    }
}

async fn read_client_hello(reader: &mut RecvStream) -> io::Result<ClientHello> {
    let version = reader.read_u8().await.map_err(io::Error::other)?;
    let send_bps = reader.read_u64().await.map_err(io::Error::other)?;
    let receive_bps = reader.read_u64().await.map_err(io::Error::other)?;
    let auth = read_string(reader).await?;
    let mut encoded = vec![version];
    encoded.extend_from_slice(&send_bps.to_be_bytes());
    encoded.extend_from_slice(&receive_bps.to_be_bytes());
    put_string(&auth, &mut encoded)?;
    Ok(ClientHello::decode(&encoded)?.0)
}

async fn read_server_hello(reader: &mut RecvStream) -> io::Result<ServerHello> {
    let ok = reader.read_u8().await.map_err(io::Error::other)? == 1;
    let send_bps = reader.read_u64().await.map_err(io::Error::other)?;
    let receive_bps = reader.read_u64().await.map_err(io::Error::other)?;
    let message = read_string(reader).await?;
    Ok(ServerHello {
        ok,
        send_bps,
        receive_bps,
        message,
    })
}

pub async fn write_server_response(
    writer: &mut SendStream,
    response: &ServerResponse,
) -> io::Result<()> {
    writer
        .write_all(&response.encode()?)
        .await
        .map_err(io::Error::other)
}

async fn read_server_response(
    reader: &mut RecvStream,
) -> io::Result<ServerResponse> {
    let ok = reader.read_u8().await.map_err(io::Error::other)? == 1;
    let udp_session_id = reader.read_u32().await.map_err(io::Error::other)?;
    let message = read_string(reader).await?;
    Ok(ServerResponse {
        ok,
        udp_session_id,
        message,
    })
}

async fn read_client_request(
    reader: &mut RecvStream,
) -> io::Result<ClientRequest> {
    let udp = reader.read_u8().await.map_err(io::Error::other)? != 0;
    let host = read_string(reader).await?;
    let port = reader.read_u16().await.map_err(io::Error::other)?;
    Ok(ClientRequest { udp, host, port })
}

async fn read_string(reader: &mut RecvStream) -> io::Result<String> {
    let length =
        usize::from(reader.read_u16().await.map_err(io::Error::other)?);
    let mut value = vec![0_u8; length];
    reader
        .read_exact(&mut value)
        .await
        .map_err(io::Error::other)?;
    String::from_utf8(value)
        .map_err(|_| invalid("Hysteria string is not UTF-8"))
}

struct HysteriaHopDialer {
    inner: Arc<dyn Dialer>,
    server: SocksAddr,
    ports: Vec<u16>,
    interval: Duration,
    interval_max: Duration,
}

impl Dialer for HysteriaHopDialer {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        self.inner.dial_tcp(destination)
    }

    fn listen_udp<'a>(
        &'a self,
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let index = random_port_index(self.ports.len());
            let destination =
                SocksAddr::new(self.server.host(), self.ports[index]);
            let inner = self.inner.listen_udp(&destination).await?;
            Ok(Box::new(HysteriaHopPacketConnection {
                inner,
                server: self.server.clone(),
                ports: self.ports.clone(),
                interval: self.interval,
                interval_max: self.interval_max,
                state: StdMutex::new(HopState {
                    destination,
                    next_hop: Instant::now()
                        + random_hop_interval(self.interval, self.interval_max),
                }),
            }) as PacketStream)
        })
    }
}

struct HopState {
    destination: SocksAddr,
    next_hop: Instant,
}

struct HysteriaHopPacketConnection {
    inner: PacketStream,
    server: SocksAddr,
    ports: Vec<u16>,
    interval: Duration,
    interval_max: Duration,
    state: StdMutex<HopState>,
}

impl PacketConnection for HysteriaHopPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let destination = {
                let mut state = self.state.lock().map_err(|_| {
                    io::Error::other("Hysteria hop state lock poisoned")
                })?;
                if Instant::now() >= state.next_hop {
                    let index = random_port_index(self.ports.len());
                    state.destination =
                        SocksAddr::new(self.server.host(), self.ports[index]);
                    state.next_hop = Instant::now()
                        + random_hop_interval(self.interval, self.interval_max);
                }
                state.destination.clone()
            };
            self.inner.send_to(data, &destination).await
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let (size, _) = self.inner.recv_from(data).await?;
            Ok((size, self.server.clone()))
        })
    }
}

fn random_port_index(length: usize) -> usize {
    let mut value = [0_u8; 8];
    if getrandom::fill(&mut value).is_err() {
        return 0;
    }
    (u64::from_ne_bytes(value) % length as u64) as usize
}

fn random_hop_interval(minimum: Duration, maximum: Duration) -> Duration {
    if minimum == maximum {
        return minimum;
    }
    let range = maximum.as_nanos().saturating_sub(minimum.as_nanos());
    let mut value = [0_u8; 8];
    if getrandom::fill(&mut value).is_err() {
        return minimum;
    }
    minimum
        + Duration::from_nanos(
            (u128::from(u64::from_ne_bytes(value)) % (range + 1)) as u64,
        )
}

pub(crate) fn port_hopping_dialer(
    inner: Arc<dyn Dialer>,
    server: SocksAddr,
    ports: Vec<u16>,
    interval: Duration,
    interval_max: Duration,
) -> io::Result<Arc<dyn Dialer>> {
    if ports.is_empty() {
        return Err(invalid("Hysteria port list is empty"));
    }
    if interval < MIN_HOP_INTERVAL {
        return Err(invalid("hop interval must be at least 5 seconds"));
    }
    if interval > interval_max {
        return Err(invalid(
            "minimum hop interval must not be greater than maximum",
        ));
    }
    Ok(Arc::new(HysteriaHopDialer {
        inner,
        server,
        ports,
        interval,
        interval_max,
    }))
}

pub struct HysteriaOutbound {
    server: SocksAddr,
    server_name: String,
    auth: String,
    send_bps: u64,
    receive_bps: u64,
    tls: ClientTlsConfig,
    transport: Arc<quinn::TransportConfig>,
    brutal: HysteriaBrutalConfig,
    xplus_password: Option<Vec<u8>>,
    packet_dialer: Option<Arc<dyn Dialer>>,
    server_ports: Vec<u16>,
    hop_interval: Duration,
    state: Mutex<Option<ClientSession>>,
}

impl HysteriaOutbound {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: SocksAddr,
        server_name: impl Into<String>,
        auth: impl Into<String>,
        send_bps: u64,
        receive_bps: u64,
        tls: ClientTlsConfig,
        mut transport: quinn::TransportConfig,
        xplus_password: Option<Vec<u8>>,
    ) -> Self {
        let brutal = HysteriaBrutalConfig::new(send_bps);
        transport.congestion_controller_factory(Arc::new(brutal.clone()));
        Self {
            server,
            server_name: server_name.into(),
            auth: auth.into(),
            send_bps,
            receive_bps,
            tls,
            transport: Arc::new(transport),
            brutal,
            xplus_password,
            packet_dialer: None,
            server_ports: Vec::new(),
            hop_interval: DEFAULT_HOP_INTERVAL,
            state: Mutex::new(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_packet_dialer(
        server: SocksAddr,
        server_name: impl Into<String>,
        auth: impl Into<String>,
        send_bps: u64,
        receive_bps: u64,
        tls: ClientTlsConfig,
        mut transport: quinn::TransportConfig,
        xplus_password: Option<Vec<u8>>,
        packet_dialer: Arc<dyn Dialer>,
    ) -> Self {
        let brutal = HysteriaBrutalConfig::new(send_bps);
        transport.congestion_controller_factory(Arc::new(brutal.clone()));
        Self {
            server,
            server_name: server_name.into(),
            auth: auth.into(),
            send_bps,
            receive_bps,
            tls,
            transport: Arc::new(transport),
            brutal,
            xplus_password,
            packet_dialer: Some(packet_dialer),
            server_ports: Vec::new(),
            hop_interval: DEFAULT_HOP_INTERVAL,
            state: Mutex::new(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_port_hopping(
        server: SocksAddr,
        server_name: impl Into<String>,
        auth: impl Into<String>,
        send_bps: u64,
        receive_bps: u64,
        tls: ClientTlsConfig,
        mut transport: quinn::TransportConfig,
        xplus_password: Option<Vec<u8>>,
        packet_dialer: Arc<dyn Dialer>,
        server_ports: Vec<u16>,
        hop_interval: Duration,
    ) -> Self {
        let brutal = HysteriaBrutalConfig::new(send_bps);
        transport.congestion_controller_factory(Arc::new(brutal.clone()));
        Self {
            server,
            server_name: server_name.into(),
            auth: auth.into(),
            send_bps,
            receive_bps,
            tls,
            transport: Arc::new(transport),
            brutal,
            xplus_password,
            packet_dialer: Some(packet_dialer),
            server_ports,
            hop_interval,
            state: Mutex::new(None),
        }
    }

    async fn ensure_session<'a>(
        &self,
        state: &'a mut Option<ClientSession>,
    ) -> io::Result<&'a ClientSession> {
        let active = state
            .as_ref()
            .is_some_and(|session| session.connection.close_reason().is_none());
        if !active {
            let (socket, remote) = if let Some(dialer) = &self.packet_dialer {
                let dialer: Arc<dyn Dialer> = if self.server_ports.is_empty() {
                    dialer.clone()
                } else {
                    Arc::new(HysteriaHopDialer {
                        inner: dialer.clone(),
                        server: self.server.clone(),
                        ports: self.server_ports.clone(),
                        interval: self.hop_interval,
                        interval_max: self.hop_interval,
                    })
                };
                let (socket, remote) =
                    PacketUdpSocket::connect(dialer, &self.server).await?;
                (Some(socket), remote)
            } else {
                let remote = self
                    .server
                    .resolve()
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "Hysteria server resolved to no addresses",
                        )
                    })?;
                (None, remote)
            };
            let tls = self.tls.clone();
            *state = Some(
                ClientSession::connect_with_socket(
                    remote,
                    &self.server_name,
                    &self.auth,
                    self.send_bps,
                    self.receive_bps,
                    tls,
                    self.transport.clone(),
                    self.brutal.clone(),
                    self.xplus_password.clone(),
                    socket,
                )
                .await?,
            );
        }
        Ok(state.as_ref().expect("Hysteria session initialized"))
    }

    /// Close the active QUIC session so the next operation resolves and dials
    /// again. This mirrors sing-box's `InterfaceUpdated` lifecycle hook and is
    /// also useful to embedders that already own a platform network monitor.
    pub async fn reset(&self) {
        let session = self.state.lock().await.take();
        drop(session);
    }
}

impl Dialer for HysteriaOutbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let stream = self
                .ensure_session(&mut state)
                .await?
                .open_tcp_checked(&destination.host(), destination.port())
                .await?;
            Ok(Box::new(stream) as Stream)
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let connection = self
                .ensure_session(&mut state)
                .await?
                .open_udp(&destination.host(), destination.port())
                .await?;
            Ok(Box::new(connection) as PacketStream)
        })
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::{
        common::tls::{
            build_client_config, build_server_config_with_default_alpn,
        },
        option::{InboundTlsOptions, OutboundTlsOptions},
    };

    struct RecordingPacketConnection {
        sent: Arc<StdMutex<Vec<SocksAddr>>>,
    }

    impl PacketConnection for RecordingPacketConnection {
        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            destination: &'a SocksAddr,
        ) -> PacketFuture<'a, usize> {
            Box::pin(async move {
                self.sent.lock().unwrap().push(destination.clone());
                Ok(data.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            _data: &'a mut [u8],
        ) -> PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(async { Ok((0, SocksAddr::new("127.0.0.1", 2001))) })
        }
    }

    #[test]
    fn port_ranges_match_upstream_expansion() {
        assert_eq!(
            parse_server_ports(&["2000:2002".into(), "443:443".into()])
                .unwrap(),
            vec![2000, 2001, 2002, 443]
        );
        assert_eq!(parse_server_ports(&[":2".into()]).unwrap(), vec![0, 1, 2]);
        assert!(parse_server_ports(&["443".into()]).is_err());
        assert!(parse_server_ports(&["bad:444".into()]).is_err());
    }

    #[tokio::test]
    async fn port_hopping_changes_wire_destination_and_hides_hop_port() {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let connection = HysteriaHopPacketConnection {
            inner: Box::new(RecordingPacketConnection { sent: sent.clone() }),
            server: SocksAddr::new("127.0.0.1", 443),
            ports: vec![2001],
            interval: Duration::ZERO,
            interval_max: Duration::ZERO,
            state: StdMutex::new(HopState {
                destination: SocksAddr::new("127.0.0.1", 2000),
                next_hop: Instant::now(),
            }),
        };
        connection
            .send_to(b"packet", &SocksAddr::new("127.0.0.1", 443))
            .await
            .unwrap();
        assert_eq!(
            sent.lock().unwrap().as_slice(),
            &[SocksAddr::new("127.0.0.1", 2001)]
        );
        let mut response = [];
        assert_eq!(
            connection.recv_from(&mut response).await.unwrap().1,
            SocksAddr::new("127.0.0.1", 443)
        );
    }

    #[test]
    fn control_and_request_frames_match_go_layout() {
        let hello = ClientHello {
            send_bps: 125_000,
            receive_bps: 250_000,
            auth: "secret".into(),
        };
        assert_eq!(
            hex::encode(hello.encode().unwrap()),
            "03000000000001e848000000000003d0900006736563726574"
        );
        assert_eq!(
            ClientHello::decode(&hello.encode().unwrap()).unwrap().0,
            hello
        );
        let request = ClientRequest {
            udp: false,
            host: "example.com".into(),
            port: 443,
        };
        let encoded = request.encode(b"ping").unwrap();
        assert_eq!(
            hex::encode(&encoded),
            "00000b6578616d706c652e636f6d01bb70696e67"
        );
        assert_eq!(
            ClientRequest::decode(&encoded).unwrap(),
            (request, b"ping".as_slice())
        );
        let response = ServerResponse {
            ok: true,
            udp_session_id: 7,
            message: String::new(),
        };
        assert_eq!(hex::encode(response.encode().unwrap()), "01000000070000");
    }

    #[test]
    fn udp_fragmentation_and_xplus_round_trip() {
        let message = UdpMessage {
            session_id: 1,
            packet_id: 2,
            fragment_id: 0,
            fragment_count: 1,
            host: "1.2.3.4".into(),
            port: 53,
            data: b"abcdefghij".to_vec(),
        };
        assert_eq!(
            hex::encode(message.encode().unwrap()),
            "000000010007312e322e332e34003500020001000a6162636465666768696a"
        );
        let fragments = fragment_udp_message(message, 26).unwrap();
        assert_eq!(fragments.len(), 2);
        let mut defrag = UdpDefragmenter::default();
        assert!(defrag.feed(fragments[1].clone()).is_none());
        assert_eq!(
            defrag.feed(fragments[0].clone()).unwrap().data,
            b"abcdefghij"
        );
        let encoded = encode_xplus_with_salt(b"cover", [1; 16], b"hysteria");
        assert_eq!(decode_xplus(b"cover", &encoded), b"hysteria");
    }

    #[test]
    fn brutal_controller_tracks_negotiated_rate_and_compensates_loss() {
        let config = HysteriaBrutalConfig::new(1_000_000);
        let started = std::time::Instant::now();
        let mut controller = HysteriaBrutalController::new(
            config.bps.clone(),
            false,
            crate::protocol::quic_bbr::BbrProfile::Standard,
            started,
            1_200,
        );
        assert_eq!(
            quinn::congestion::Controller::window(&controller),
            BRUTAL_INITIAL_WINDOW
        );
        controller.smoothed_rtt = Some(Duration::from_millis(100));
        controller.record(started, 40, 10);
        assert_eq!(controller.compensated_bps(), 1_250_000);
        assert_eq!(quinn::congestion::Controller::window(&controller), 250_000);

        config.set_bps(500_000);
        assert_eq!(config.bps(), 500_000);
        assert_eq!(controller.compensated_bps(), 625_000);
    }

    #[test]
    fn brutal_server_factory_isolates_connection_rates() {
        let factory =
            Arc::new(HysteriaBrutalServerConfig::with_debug(1_000_000, true));
        let now = std::time::Instant::now();
        let _first_controller = quinn::congestion::ControllerFactory::build(
            factory.clone(),
            now,
            1_200,
        );
        let first = factory.take_pending().unwrap();
        let _second_controller = quinn::congestion::ControllerFactory::build(
            factory.clone(),
            now,
            1_200,
        );
        let second = factory.take_pending().unwrap();
        assert!(first.debug);
        assert!(second.debug);
        first.set_bps(250_000);
        assert_eq!(first.bps(), 250_000);
        assert_eq!(second.bps(), 1_000_000);
    }

    #[tokio::test]
    async fn authenticated_xplus_quic_tcp_interoperates() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_options: InboundTlsOptions = serde_json::from_value(json!({
            "enabled":true,
            "certificate":cert.pem(),
            "key":key_pair.serialize_pem()
        }))
        .unwrap();
        let server_tls = build_server_config_with_default_alpn(
            &server_options,
            &[DEFAULT_ALPN],
        )
        .unwrap();
        let endpoint = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            server_tls,
            Arc::new(quinn::TransportConfig::default()),
            Some(b"cover".to_vec()),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let users = HashMap::from([("secret".into(), "alice".into())]);
            let session = ServerSession::authenticate(
                connection, &users, 1_000_000, 2_000_000,
            )
            .await
            .unwrap();
            assert_eq!(session.user, "alice");
            assert_eq!(session.negotiated_send_bps, 1_000_000);
            let (mut stream, request) = session.accept_request().await.unwrap();
            assert_eq!(request.host, "example.com");
            assert_eq!(request.port, 443);
            assert!(!request.udp);
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();

            let (mut udp_control, request) =
                session.accept_request().await.unwrap();
            assert!(request.udp);
            assert_eq!(request.host, "1.2.3.4");
            assert_eq!(request.port, 53);
            write_server_response(
                &mut udp_control.send,
                &ServerResponse {
                    ok: true,
                    udp_session_id: 7,
                    message: String::new(),
                },
            )
            .await
            .unwrap();
            let mut defragmenter = UdpDefragmenter::default();
            let message = loop {
                let message = session.read_udp().await.unwrap();
                if let Some(message) = defragmenter.feed(message) {
                    break message;
                }
            };
            assert_eq!(message.session_id, 7);
            assert_eq!(message.data.len(), 3000);
            session.send_udp(message).unwrap();
            let _ = done_rx.await;
        });
        let client_tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &[DEFAULT_ALPN],
        )
        .unwrap();
        let client = ClientSession::connect(
            address,
            "localhost",
            "secret",
            2_000_000,
            1_000_000,
            client_tls,
            quinn::TransportConfig::default(),
            Some(b"cover".to_vec()),
        )
        .await
        .unwrap();
        assert_eq!(client.server_hello.send_bps, 1_000_000);
        assert_eq!(client.negotiated_send_bps, 2_000_000);
        let mut stream =
            client.open_tcp("example.com", 443, b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        let udp = client.open_udp("1.2.3.4", 53).await.unwrap();
        let packet: Vec<u8> =
            (0..3000).map(|index| (index % 251) as u8).collect();
        let destination = SocksAddr::new("1.2.3.4", 53);
        udp.send_to(&packet, &destination).await.unwrap();
        let mut received = vec![0_u8; 4096];
        let (size, source) = udp.recv_from(&mut received).await.unwrap();
        assert_eq!(&received[..size], packet);
        assert_eq!(source, destination);
        let _ = done_tx.send(());
        server.await.unwrap();
    }
}
