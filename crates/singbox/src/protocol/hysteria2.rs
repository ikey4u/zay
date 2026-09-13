//! Hysteria2 wire framing and UDP obfuscation primitives.
//!
//! These formats mirror `sing-quic/hysteria2/internal/protocol`.  Keeping the
//! protocol core independent from Quinn makes byte-for-byte differential tests
//! possible before the HTTP/3 session layer is attached.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    future::poll_fn,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Component, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU32, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use blake2::{
    Blake2bVar,
    digest::{Update as _, VariableOutput as _},
};
use bytes::{Buf as _, Bytes};
use http::{
    HeaderMap, Method, Request, Response, StatusCode,
    header::{CONTENT_TYPE, HeaderValue},
};
use n0_watcher::Watcher as _;
use percent_encoding::percent_decode_str;
use quinn::{
    AsyncUdpSocket, Connection, Endpoint, EndpointConfig, RecvStream,
    Runtime as _, SendStream, TokioRuntime, UdpPoller,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    udp::{RecvMeta, Transmit},
};
use rand::RngCore as _;
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
    protocol::hysteria2_realm::{
        RealmClientConnector, RealmPacketSocket, RealmPortMapping,
    },
};

pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
pub const MAX_ADDRESS_LENGTH: usize = 2048;
pub const MAX_MESSAGE_LENGTH: usize = 2048;
pub const MAX_PADDING_LENGTH: usize = 4096;
pub const MAX_UDP_SIZE: usize = 4096;
pub const SALAMANDER_SALT_LEN: usize = 8;
pub const GECKO_DEFAULT_MIN_PACKET_SIZE: usize = 512;
pub const GECKO_DEFAULT_MAX_PACKET_SIZE: usize = 1200;
pub const GECKO_MAX_ON_WIRE_SIZE: usize = 2048;

const GECKO_FRAGMENT_FLAG: u8 = 0x80;
const GECKO_HEADER_LEN: usize = 5;
const GECKO_MIN_CHUNKS: usize = 2;
const GECKO_MAX_CHUNKS: usize = 8;
const GECKO_REASSEMBLY_TTL: Duration = Duration::from_secs(8);
const GECKO_MAX_REASSEMBLY: usize = 4096;
const GECKO_MAX_PER_SOURCE: usize = 8;

const MAX_QUIC_VARINT: u64 = (1_u64 << 62) - 1;
const PADDING_CHARS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const AUTH_HOST: &str = "hysteria";
const AUTH_PATH: &str = "/auth";
const HEADER_AUTH: &str = "hysteria-auth";
const HEADER_UDP: &str = "hysteria-udp";
const HEADER_CC_RX: &str = "hysteria-cc-rx";
const HEADER_PADDING: &str = "hysteria-padding";
const STATUS_AUTH_OK: u16 = 233;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hysteria2ObfsConfig {
    Salamander {
        password: Vec<u8>,
    },
    Gecko {
        password: Vec<u8>,
        min_packet_size: usize,
        max_packet_size: usize,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hysteria2QuicOptions {
    pub idle_timeout: Option<Duration>,
    pub keep_alive_period: Option<Duration>,
    pub stream_receive_window: u64,
    pub connection_receive_window: u64,
    pub max_concurrent_streams: u64,
    pub initial_packet_size: u64,
    pub disable_path_mtu_discovery: bool,
}

/// QUIC values pinned by sing-box when Hysteria2 Chrome parrot is enabled.
///
/// The values are deliberately kept separate from user QUIC options because
/// upstream ignores conflicting user settings in this mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hysteria2ChromeParrotParameters {
    pub idle_timeout: Duration,
    pub stream_receive_window: u64,
    pub connection_receive_window: u64,
    pub max_concurrent_bidi_streams: u64,
    pub max_concurrent_uni_streams: u64,
    pub initial_packet_size: u16,
    pub max_udp_payload_size: u16,
    pub max_datagram_frame_size: usize,
}

impl Default for Hysteria2ChromeParrotParameters {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30),
            stream_receive_window: 6_291_456,
            connection_receive_window: 15_728_640,
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 103,
            initial_packet_size: 1_250,
            max_udp_payload_size: 1_472,
            max_datagram_frame_size: 65_536,
        }
    }
}

impl Hysteria2QuicOptions {
    pub fn build(&self) -> io::Result<quinn::TransportConfig> {
        self.build_for_client(false)
    }

    /// Build Hysteria2 client transport settings.
    ///
    /// Chrome parrot pins the values exposed by Quinn to the same values as
    /// sing-box's quic-go fork, including the asymmetric 100/103 stream limits
    /// and an advertised DATAGRAM limit of 65536 bytes.
    pub fn build_for_client(
        &self,
        chrome_parrot: bool,
    ) -> io::Result<quinn::TransportConfig> {
        let mut transport = quinn::TransportConfig::default();
        if let Some(duration) =
            self.keep_alive_period.filter(|value| !value.is_zero())
        {
            transport.keep_alive_interval(Some(duration));
        }
        if chrome_parrot {
            let chrome = Hysteria2ChromeParrotParameters::default();
            transport.max_idle_timeout(Some(
                chrome.idle_timeout.try_into().map_err(|_| {
                    invalid("Chrome parrot idle timeout exceeds varint range")
                })?,
            ));
            transport.stream_receive_window(
                quinn::VarInt::from_u64(chrome.stream_receive_window)
                    .map_err(other)?,
            );
            transport.receive_window(
                quinn::VarInt::from_u64(chrome.connection_receive_window)
                    .map_err(other)?,
            );
            transport.max_concurrent_bidi_streams(
                quinn::VarInt::from_u64(chrome.max_concurrent_bidi_streams)
                    .map_err(other)?,
            );
            transport.max_concurrent_uni_streams(
                quinn::VarInt::from_u64(chrome.max_concurrent_uni_streams)
                    .map_err(other)?,
            );
            transport.initial_mtu(chrome.initial_packet_size);
            transport.datagram_receive_buffer_size(Some(
                chrome.max_datagram_frame_size,
            ));
            if self.disable_path_mtu_discovery {
                transport.mtu_discovery_config(None);
            }
            return Ok(transport);
        }
        if let Some(duration) =
            self.idle_timeout.filter(|value| !value.is_zero())
        {
            transport.max_idle_timeout(Some(duration.try_into().map_err(
                |_| invalid("QUIC idle timeout exceeds varint range"),
            )?));
        }
        if self.stream_receive_window != 0 {
            transport.stream_receive_window(
                quinn::VarInt::from_u64(self.stream_receive_window)
                    .map_err(other)?,
            );
        }
        if self.connection_receive_window != 0 {
            transport.receive_window(
                quinn::VarInt::from_u64(self.connection_receive_window)
                    .map_err(other)?,
            );
        }
        if self.max_concurrent_streams != 0 {
            transport.max_concurrent_bidi_streams(
                quinn::VarInt::from_u64(self.max_concurrent_streams)
                    .map_err(other)?,
            );
        }
        if self.initial_packet_size != 0 {
            transport.initial_mtu(
                u16::try_from(self.initial_packet_size)
                    .map_err(|_| invalid("initial_packet_size exceeds u16"))?,
            );
        }
        if self.disable_path_mtu_discovery {
            transport.mtu_discovery_config(None);
        }
        Ok(transport)
    }
}

fn hysteria2_client_endpoint_config(
    chrome_parrot: bool,
) -> io::Result<EndpointConfig> {
    let mut endpoint = EndpointConfig::default();
    if chrome_parrot {
        let chrome = Hysteria2ChromeParrotParameters::default();
        endpoint
            .max_udp_payload_size(chrome.max_udp_payload_size)
            .map_err(other)?;
        endpoint.cid_generator(|| {
            Box::new(quinn_proto::RandomConnectionIdGenerator::new(0))
        });
    }
    Ok(endpoint)
}

fn chrome_initial_destination_connection_id() -> quinn_proto::ConnectionId {
    let mut bytes = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    quinn_proto::ConnectionId::new(&bytes)
}

impl Hysteria2ObfsConfig {
    pub fn gecko(
        password: Vec<u8>,
        min_packet_size: usize,
        max_packet_size: usize,
    ) -> io::Result<Self> {
        let min_packet_size = if min_packet_size == 0 {
            GECKO_DEFAULT_MIN_PACKET_SIZE
        } else {
            min_packet_size
        };
        let max_packet_size = if max_packet_size == 0 {
            GECKO_DEFAULT_MAX_PACKET_SIZE
        } else {
            max_packet_size
        };
        if min_packet_size == 0
            || min_packet_size > max_packet_size
            || max_packet_size > GECKO_MAX_ON_WIRE_SIZE
        {
            return Err(invalid("Gecko packet size range is invalid"));
        }
        Ok(Self::Gecko {
            password,
            min_packet_size,
            max_packet_size,
        })
    }

    fn password(&self) -> &[u8] {
        match self {
            Self::Salamander { password } | Self::Gecko { password, .. } => {
                password
            }
        }
    }
}

struct OwnedTransmit {
    destination: SocketAddr,
    ecn: Option<quinn::udp::EcnCodepoint>,
    contents: Vec<u8>,
    src_ip: Option<IpAddr>,
}

impl OwnedTransmit {
    fn borrowed(&self) -> Transmit<'_> {
        Transmit {
            destination: self.destination,
            ecn: self.ecn,
            contents: &self.contents,
            segment_size: None,
            src_ip: self.src_ip,
        }
    }
}

#[derive(Default)]
struct ObfsSendState {
    original: Option<(SocketAddr, Vec<u8>)>,
    pending: VecDeque<OwnedTransmit>,
}

/// QUIC's abstract datagram socket wrapped with the two Hysteria2 UDP
/// obfuscators. The wrapper intentionally disables GSO/GRO at its boundary:
/// obfuscation changes packet lengths and Gecko can fan one QUIC datagram out
/// into several UDP datagrams.
struct Hysteria2ObfsSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    config: Hysteria2ObfsConfig,
    send_state: std::sync::Mutex<ObfsSendState>,
    gecko_reassembler: std::sync::Mutex<GeckoReassembler>,
    gecko_message_id: AtomicU8,
}

impl fmt::Debug for Hysteria2ObfsSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hysteria2ObfsSocket")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Hysteria2ObfsSocket {
    fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        config: Hysteria2ObfsConfig,
    ) -> Self {
        Self {
            inner,
            config,
            send_state: std::sync::Mutex::new(ObfsSendState::default()),
            gecko_reassembler: std::sync::Mutex::new(
                GeckoReassembler::default(),
            ),
            gecko_message_id: AtomicU8::new(0),
        }
    }

    fn encode(&self, payload: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        match &self.config {
            Hysteria2ObfsConfig::Salamander { password } => {
                Ok(vec![encode_salamander(password, payload)?])
            }
            Hysteria2ObfsConfig::Gecko {
                password,
                min_packet_size,
                max_packet_size,
            } => encode_gecko(
                password,
                payload,
                self.gecko_message_id.fetch_add(1, Ordering::Relaxed),
                *min_packet_size,
                *max_packet_size,
            ),
        }
    }

    fn decode(
        &self,
        source: SocketAddr,
        packet: &[u8],
    ) -> io::Result<Option<Vec<u8>>> {
        match &self.config {
            Hysteria2ObfsConfig::Salamander { password } => {
                let decoded = decode_salamander(password, packet)?;
                Ok((!decoded.is_empty()).then_some(decoded))
            }
            Hysteria2ObfsConfig::Gecko { .. } => self
                .gecko_reassembler
                .lock()
                .map_err(|_| io::Error::other("Gecko state lock poisoned"))?
                .feed_obfuscated(
                    &source.to_string(),
                    self.config.password(),
                    packet,
                ),
        }
    }
}

impl AsyncUdpSocket for Hysteria2ObfsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let mut state = self
            .send_state
            .lock()
            .map_err(|_| io::Error::other("obfs send state lock poisoned"))?;
        if !state.pending.is_empty() {
            while let Some(packet) = state.pending.front() {
                self.inner.try_send(&packet.borrowed())?;
                state.pending.pop_front();
            }
            if state
                .original
                .as_ref()
                .is_some_and(|(destination, contents)| {
                    *destination == transmit.destination
                        && contents.as_slice() == transmit.contents
                })
            {
                state.original = None;
                return Ok(());
            }
            state.original = None;
        }

        let packets = self.encode(transmit.contents)?;
        for (index, contents) in packets.iter().enumerate() {
            let packet = OwnedTransmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: contents.clone(),
                src_ip: transmit.src_ip,
            };
            if let Err(error) = self.inner.try_send(&packet.borrowed()) {
                if error.kind() == io::ErrorKind::WouldBlock {
                    state.original = Some((
                        transmit.destination,
                        transmit.contents.to_vec(),
                    ));
                    state.pending.push_back(packet);
                    state.pending.extend(packets[index + 1..].iter().map(
                        |contents| OwnedTransmit {
                            destination: transmit.destination,
                            ecn: transmit.ecn,
                            contents: contents.clone(),
                            src_ip: transmit.src_ip,
                        },
                    ));
                }
                return Err(error);
            }
        }
        Ok(())
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
            let mut decoded = Vec::new();
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
                    if let Ok(Some(packet)) = self.decode(item.addr, packet) {
                        decoded.push((packet, item));
                    }
                }
            }
            if decoded.is_empty() {
                continue;
            }
            if decoded.len() > buffers.len() {
                return Poll::Ready(Err(invalid(
                    "obfs receive batch exceeds buffer count",
                )));
            }
            let decoded_count = decoded.len();
            for (index, (packet, mut item)) in decoded.into_iter().enumerate() {
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
            return Poll::Ready(Ok(decoded_count));
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

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

pub fn encode_quic_varint(value: u64, output: &mut Vec<u8>) -> io::Result<()> {
    match value {
        0..=63 => output.push(value as u8),
        64..=16_383 => {
            output.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes());
        }
        16_384..=1_073_741_823 => {
            output
                .extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes());
        }
        1_073_741_824..=MAX_QUIC_VARINT => {
            output.extend_from_slice(
                &(value | 0xc000_0000_0000_0000).to_be_bytes(),
            );
        }
        _ => return Err(invalid("QUIC varint exceeds 62 bits")),
    }
    Ok(())
}

pub fn decode_quic_varint(input: &[u8]) -> io::Result<(u64, usize)> {
    let first = *input
        .first()
        .ok_or_else(|| invalid("truncated QUIC varint"))?;
    let length = 1_usize << (first >> 6);
    if input.len() < length {
        return Err(invalid("truncated QUIC varint"));
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, length))
}

fn random_padding(min: usize, max: usize) -> io::Result<Vec<u8>> {
    debug_assert!(min < max);
    let mut seed = [0_u8; 8];
    getrandom::fill(&mut seed).map_err(io::Error::other)?;
    let length = min
        + (u64::from_be_bytes(seed) % u64::try_from(max - min).unwrap())
            as usize;
    let mut random = vec![0_u8; length];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    for byte in &mut random {
        *byte = PADDING_CHARS[usize::from(*byte) % PADDING_CHARS.len()];
    }
    Ok(random)
}

pub fn encode_tcp_request(
    address: &str,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let padding = random_padding(64, 512)?;
    encode_tcp_request_with_padding(address, &padding, payload)
}

pub fn encode_tcp_request_with_padding(
    address: &str,
    padding: &[u8],
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    validate_address(address)?;
    validate_padding(padding)?;
    let mut output =
        Vec::with_capacity(16 + address.len() + padding.len() + payload.len());
    encode_quic_varint(FRAME_TYPE_TCP_REQUEST, &mut output)?;
    encode_vstring(address, &mut output)?;
    encode_quic_varint(padding.len() as u64, &mut output)?;
    output.extend_from_slice(padding);
    output.extend_from_slice(payload);
    Ok(output)
}

/// Decodes a TCP request after the HTTP/3 stream dispatcher consumed the
/// `FRAME_TYPE_TCP_REQUEST` varint. The returned slice is zero-copy early data.
pub fn decode_tcp_request(input: &[u8]) -> io::Result<(String, &[u8])> {
    let (address, consumed) = decode_vstring(input, false)?;
    if address.is_empty() {
        return Err(invalid("invalid address length"));
    }
    let (padding_length, padding_prefix) =
        decode_quic_varint(&input[consumed..])?;
    let padding_length = usize::try_from(padding_length)
        .map_err(|_| invalid("invalid padding length"))?;
    if padding_length > MAX_PADDING_LENGTH {
        return Err(invalid("invalid padding length"));
    }
    let payload_offset = consumed
        .checked_add(padding_prefix)
        .and_then(|offset| offset.checked_add(padding_length))
        .ok_or_else(|| invalid("invalid padding length"))?;
    if input.len() < payload_offset {
        return Err(invalid("truncated TCP request padding"));
    }
    Ok((address, &input[payload_offset..]))
}

pub fn decode_tcp_request_frame(input: &[u8]) -> io::Result<(String, &[u8])> {
    let (frame_type, consumed) = decode_quic_varint(input)?;
    if frame_type != FRAME_TYPE_TCP_REQUEST {
        return Err(invalid(format!(
            "unexpected Hysteria2 stream frame type {frame_type:#x}"
        )));
    }
    decode_tcp_request(&input[consumed..])
}

pub fn encode_tcp_response(
    ok: bool,
    message: &str,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let padding = random_padding(128, 1024)?;
    encode_tcp_response_with_padding(ok, message, &padding, payload)
}

pub fn encode_tcp_response_with_padding(
    ok: bool,
    message: &str,
    padding: &[u8],
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    validate_padding(padding)?;
    let message = truncate_utf8(message, MAX_MESSAGE_LENGTH);
    let mut output =
        Vec::with_capacity(16 + message.len() + padding.len() + payload.len());
    output.push(u8::from(!ok));
    encode_vstring_unchecked(message, &mut output)?;
    encode_quic_varint(padding.len() as u64, &mut output)?;
    output.extend_from_slice(padding);
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn decode_tcp_response(input: &[u8]) -> io::Result<(bool, String, &[u8])> {
    let status = *input
        .first()
        .ok_or_else(|| invalid("truncated TCP response"))?;
    let (message, message_length) = decode_vstring(&input[1..], true)?;
    let offset = 1 + message_length;
    let (padding_length, padding_prefix) =
        decode_quic_varint(&input[offset..])?;
    let padding_length = usize::try_from(padding_length)
        .map_err(|_| invalid("invalid padding length"))?;
    if padding_length > MAX_PADDING_LENGTH {
        return Err(invalid("invalid padding length"));
    }
    let payload_offset = offset
        .checked_add(padding_prefix)
        .and_then(|value| value.checked_add(padding_length))
        .ok_or_else(|| invalid("invalid padding length"))?;
    if input.len() < payload_offset {
        return Err(invalid("truncated TCP response padding"));
    }
    Ok((status == 0, message, &input[payload_offset..]))
}

fn truncate_utf8(value: &str, limit: usize) -> &str {
    if value.len() <= limit {
        return value;
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn validate_address(address: &str) -> io::Result<()> {
    if address.is_empty() || address.len() > MAX_ADDRESS_LENGTH {
        return Err(invalid("invalid address length"));
    }
    Ok(())
}

fn validate_padding(padding: &[u8]) -> io::Result<()> {
    if padding.len() > MAX_PADDING_LENGTH {
        return Err(invalid("invalid padding length"));
    }
    Ok(())
}

fn encode_vstring(value: &str, output: &mut Vec<u8>) -> io::Result<()> {
    validate_address(value)?;
    encode_vstring_unchecked(value, output)
}

fn encode_vstring_unchecked(
    value: &str,
    output: &mut Vec<u8>,
) -> io::Result<()> {
    encode_quic_varint(value.len() as u64, output)?;
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn decode_vstring(input: &[u8], message: bool) -> io::Result<(String, usize)> {
    let (length, prefix) = decode_quic_varint(input)?;
    let length =
        usize::try_from(length).map_err(|_| invalid("invalid length"))?;
    let maximum = if message {
        MAX_MESSAGE_LENGTH
    } else {
        MAX_ADDRESS_LENGTH
    };
    if length > maximum {
        return Err(invalid(if message {
            "invalid message length"
        } else {
            "invalid address length"
        }));
    }
    let end = prefix
        .checked_add(length)
        .ok_or_else(|| invalid("invalid string length"))?;
    let bytes = input
        .get(prefix..end)
        .ok_or_else(|| invalid("truncated variable string"))?;
    let value = std::str::from_utf8(bytes)
        .map_err(|_| invalid("variable string is not UTF-8"))?
        .to_owned();
    Ok((value, end))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub address: String,
    pub data: Vec<u8>,
}

impl UdpMessage {
    pub fn header_size(&self) -> io::Result<usize> {
        validate_address(&self.address)?;
        Ok(
            8 + quic_varint_len(self.address.len() as u64)?
                + self.address.len(),
        )
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if self.data.len() > MAX_UDP_SIZE {
            return Err(invalid("UDP payload exceeds maximum size"));
        }
        let mut output =
            Vec::with_capacity(self.header_size()? + self.data.len());
        output.extend_from_slice(&self.session_id.to_be_bytes());
        output.extend_from_slice(&self.packet_id.to_be_bytes());
        output.push(self.fragment_id);
        output.push(self.fragment_count);
        encode_vstring(&self.address, &mut output)?;
        output.extend_from_slice(&self.data);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> io::Result<Self> {
        if input.len() < 9 {
            return Err(invalid("truncated UDP message"));
        }
        let session_id = u32::from_be_bytes(input[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(input[4..6].try_into().unwrap());
        let fragment_id = input[6];
        let fragment_count = input[7];
        let (address, consumed) = decode_vstring(&input[8..], false)?;
        if address.is_empty() {
            return Err(invalid("invalid address length"));
        }
        Ok(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address,
            data: input[8 + consumed..].to_vec(),
        })
    }
}

pub fn fragment_udp_message(
    message: UdpMessage,
    maximum_packet_size: usize,
) -> io::Result<Vec<UdpMessage>> {
    let header_size = message.header_size()?;
    let payload_mtu = maximum_packet_size
        .checked_sub(header_size)
        .filter(|size| *size > 0)
        .ok_or_else(|| {
            invalid("maximum packet size is smaller than UDP header")
        })?;
    if message.data.len() <= payload_mtu {
        return Ok(vec![message]);
    }
    let count = message.data.len().div_ceil(payload_mtu);
    let count = u8::try_from(count)
        .map_err(|_| invalid("too many Hysteria2 UDP fragments"))?;
    let mut fragments = Vec::with_capacity(usize::from(count));
    for (index, chunk) in message.data.chunks(payload_mtu).enumerate() {
        fragments.push(UdpMessage {
            session_id: message.session_id,
            packet_id: message.packet_id,
            fragment_id: index as u8,
            fragment_count: count,
            address: message.address.clone(),
            data: chunk.to_vec(),
        });
    }
    Ok(fragments)
}

#[derive(Default)]
pub struct UdpDefragmenter {
    entries: HashMap<(u32, u16), FragmentEntry>,
}

struct FragmentEntry {
    updated: Instant,
    address: String,
    fragments: Vec<Option<Vec<u8>>>,
}

impl UdpDefragmenter {
    pub fn feed(&mut self, message: UdpMessage) -> Option<UdpMessage> {
        self.expire();
        if message.fragment_count <= 1 {
            return Some(message);
        }
        if message.fragment_id >= message.fragment_count {
            return None;
        }
        let key = (message.session_id, message.packet_id);
        if self.entries.len() >= 10
            && !self.entries.contains_key(&key)
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.updated)
                .map(|(key, _)| *key)
        {
            self.entries.remove(&oldest);
        }
        let entry = self.entries.entry(key).or_insert_with(|| FragmentEntry {
            updated: Instant::now(),
            address: message.address.clone(),
            fragments: vec![None; usize::from(message.fragment_count)],
        });
        if entry.fragments.len() != usize::from(message.fragment_count) {
            *entry = FragmentEntry {
                updated: Instant::now(),
                address: message.address.clone(),
                fragments: vec![None; usize::from(message.fragment_count)],
            };
        }
        let index = usize::from(message.fragment_id);
        if entry.fragments[index].is_some() {
            return None;
        }
        entry.updated = Instant::now();
        entry.fragments[index] = Some(message.data);
        if entry.fragments.iter().any(Option::is_none) {
            return None;
        }
        let entry = self.entries.remove(&key).unwrap();
        let data = entry.fragments.into_iter().flatten().flatten().collect();
        Some(UdpMessage {
            session_id: key.0,
            packet_id: key.1,
            fragment_id: 0,
            fragment_count: 1,
            address: entry.address,
            data,
        })
    }

    fn expire(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| {
            now.duration_since(entry.updated) < Duration::from_secs(10)
        });
    }
}

pub fn encode_salamander_with_salt(
    password: &[u8],
    salt: [u8; SALAMANDER_SALT_LEN],
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let key = salamander_key(password, &salt)?;
    let mut output = Vec::with_capacity(SALAMANDER_SALT_LEN + payload.len());
    output.extend_from_slice(&salt);
    output.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % key.len()]),
    );
    Ok(output)
}

pub fn encode_salamander(
    password: &[u8],
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut salt = [0_u8; SALAMANDER_SALT_LEN];
    getrandom::fill(&mut salt).map_err(io::Error::other)?;
    encode_salamander_with_salt(password, salt, payload)
}

pub fn decode_salamander(
    password: &[u8],
    packet: &[u8],
) -> io::Result<Vec<u8>> {
    if packet.len() <= SALAMANDER_SALT_LEN {
        return Ok(Vec::new());
    }
    let salt: [u8; SALAMANDER_SALT_LEN] =
        packet[..SALAMANDER_SALT_LEN].try_into().unwrap();
    let key = salamander_key(password, &salt)?;
    Ok(packet[SALAMANDER_SALT_LEN..]
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ key[index % key.len()])
        .collect())
}

fn salamander_key(
    password: &[u8],
    salt: &[u8; SALAMANDER_SALT_LEN],
) -> io::Result<[u8; 32]> {
    let mut hash = Blake2bVar::new(32).map_err(io::Error::other)?;
    hash.update(password);
    hash.update(salt);
    let mut key = [0_u8; 32];
    hash.finalize_variable(&mut key).map_err(io::Error::other)?;
    Ok(key)
}

/// Builds the plaintext Gecko frames that are subsequently wrapped by
/// Salamander. Packets without the high marker bit are passed through.
pub fn encode_gecko_frames_with_padding(
    payload: &[u8],
    message_id: u8,
    chunk_count: usize,
    padding: &[Vec<u8>],
) -> io::Result<Vec<Vec<u8>>> {
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    if payload[0] & GECKO_FRAGMENT_FLAG == 0 {
        return Ok(vec![payload.to_vec()]);
    }
    if !(GECKO_MIN_CHUNKS..=GECKO_MAX_CHUNKS).contains(&chunk_count)
        || padding.len() != chunk_count
    {
        return Err(invalid("invalid Gecko chunk count"));
    }
    let chunk_size = payload.len() / chunk_count;
    let mut frames = Vec::with_capacity(chunk_count);
    for (index, padding_bytes) in padding.iter().enumerate() {
        let start = index * chunk_size;
        let end = if index + 1 == chunk_count {
            payload.len()
        } else {
            start + chunk_size
        };
        let padding_length = u16::try_from(padding_bytes.len())
            .map_err(|_| invalid("Gecko padding is too large"))?;
        let mut frame = Vec::with_capacity(
            GECKO_HEADER_LEN + padding_bytes.len() + end - start,
        );
        frame.push(GECKO_FRAGMENT_FLAG);
        frame.push(message_id);
        frame.push((index as u8) << 4 | chunk_count as u8);
        frame.extend_from_slice(&padding_length.to_be_bytes());
        frame.extend_from_slice(padding_bytes);
        frame.extend_from_slice(&payload[start..end]);
        frames.push(frame);
    }
    Ok(frames)
}

pub fn encode_gecko(
    password: &[u8],
    payload: &[u8],
    message_id: u8,
    min_packet_size: usize,
    max_packet_size: usize,
) -> io::Result<Vec<Vec<u8>>> {
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    if payload[0] & GECKO_FRAGMENT_FLAG == 0 {
        return Ok(vec![encode_salamander(password, payload)?]);
    }
    let minimum = if min_packet_size == 0 {
        GECKO_DEFAULT_MIN_PACKET_SIZE
    } else {
        min_packet_size
    };
    let maximum = if max_packet_size == 0 {
        GECKO_DEFAULT_MAX_PACKET_SIZE
    } else {
        max_packet_size
    };
    if minimum > maximum {
        return Err(invalid("Gecko minimum packet size exceeds maximum"));
    }
    let chunk_count = GECKO_MIN_CHUNKS
        + random_bounded(GECKO_MAX_CHUNKS - GECKO_MIN_CHUNKS + 1)?;
    let chunk_size = payload.len() / chunk_count;
    let mut padding = Vec::with_capacity(chunk_count);
    for index in 0..chunk_count {
        let start = index * chunk_size;
        let end = if index + 1 == chunk_count {
            payload.len()
        } else {
            start + chunk_size
        };
        let base = SALAMANDER_SALT_LEN + GECKO_HEADER_LEN + end - start;
        let lower = minimum.max(base);
        let padding_length = if lower > maximum {
            0
        } else {
            lower - base + random_bounded(maximum - lower + 1)?
        };
        let mut bytes = vec![0_u8; padding_length];
        getrandom::fill(&mut bytes).map_err(io::Error::other)?;
        padding.push(bytes);
    }
    encode_gecko_frames_with_padding(
        payload,
        message_id,
        chunk_count,
        &padding,
    )?
    .into_iter()
    .map(|frame| encode_salamander(password, &frame))
    .collect()
}

fn random_bounded(bound: usize) -> io::Result<usize> {
    debug_assert!(bound > 0);
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok((u64::from_be_bytes(bytes) % bound as u64) as usize)
}

#[derive(Default)]
pub struct GeckoReassembler {
    entries: HashMap<(String, u8), GeckoEntry>,
    per_source: HashMap<String, usize>,
}

struct GeckoEntry {
    deadline: Instant,
    fragments: Vec<Option<Vec<u8>>>,
}

impl GeckoReassembler {
    /// Feeds one Salamander-decoded Gecko packet. Invalid fragments are
    /// silently discarded, matching the Go packet-connection behavior.
    pub fn feed(&mut self, source: &str, packet: &[u8]) -> Option<Vec<u8>> {
        self.expire();
        let first = *packet.first()?;
        if first & GECKO_FRAGMENT_FLAG == 0 {
            return Some(packet.to_vec());
        }
        if packet.len() < GECKO_HEADER_LEN {
            return None;
        }
        let message_id = packet[1];
        let fragment_id = packet[2] >> 4;
        let fragment_count = packet[2] & 0x0f;
        if !(GECKO_MIN_CHUNKS as u8..=GECKO_MAX_CHUNKS as u8)
            .contains(&fragment_count)
            || fragment_id >= fragment_count
        {
            return None;
        }
        let padding_length =
            usize::from(u16::from_be_bytes([packet[3], packet[4]]));
        let payload_offset = GECKO_HEADER_LEN.checked_add(padding_length)?;
        let payload = packet.get(payload_offset..)?;
        let key = (source.to_owned(), message_id);
        if !self.entries.contains_key(&key) {
            if self.per_source.get(source).copied().unwrap_or_default()
                >= GECKO_MAX_PER_SOURCE
            {
                return None;
            }
            if self.entries.len() >= GECKO_MAX_REASSEMBLY {
                self.evict_oldest();
            }
            self.entries.insert(
                key.clone(),
                GeckoEntry {
                    deadline: Instant::now() + GECKO_REASSEMBLY_TTL,
                    fragments: vec![None; usize::from(fragment_count)],
                },
            );
            *self.per_source.entry(source.to_owned()).or_default() += 1;
        }
        let entry = self.entries.get_mut(&key)?;
        if entry.fragments.len() != usize::from(fragment_count) {
            return None;
        }
        let slot = &mut entry.fragments[usize::from(fragment_id)];
        if slot.is_some() {
            return None;
        }
        *slot = Some(payload.to_vec());
        if entry.fragments.iter().any(Option::is_none) {
            return None;
        }
        let entry = self.remove_entry(&key)?;
        Some(entry.fragments.into_iter().flatten().flatten().collect())
    }

    pub fn feed_obfuscated(
        &mut self,
        source: &str,
        password: &[u8],
        packet: &[u8],
    ) -> io::Result<Option<Vec<u8>>> {
        let plaintext = decode_salamander(password, packet)?;
        Ok(self.feed(source, &plaintext))
    }

    fn expire(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| now > entry.deadline)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.remove_entry(&key);
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(key) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.deadline)
            .map(|(key, _)| key.clone())
        {
            self.remove_entry(&key);
        }
    }

    fn remove_entry(&mut self, key: &(String, u8)) -> Option<GeckoEntry> {
        let entry = self.entries.remove(key)?;
        if let Some(count) = self.per_source.get_mut(&key.0) {
            *count -= 1;
            if *count == 0 {
                self.per_source.remove(&key.0);
            }
        }
        Some(entry)
    }
}

fn quic_varint_len(value: u64) -> io::Result<usize> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        1_073_741_824..=MAX_QUIC_VARINT => Ok(8),
        _ => Err(invalid("QUIC varint exceeds 62 bits")),
    }
}

pub struct Hysteria2TcpStream {
    pub send: SendStream,
    pub recv: RecvStream,
}

impl AsyncRead for Hysteria2TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(context, buffer)
    }
}

impl AsyncWrite for Hysteria2TcpStream {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hysteria2AuthResponse {
    pub udp_enabled: bool,
    pub receive_bps: u64,
    pub receive_auto: bool,
}

fn client_brutal_bps(
    send_bps: u64,
    server_receive_bps: u64,
    auto: bool,
) -> u64 {
    if auto || send_bps == 0 {
        0
    } else if server_receive_bps == 0 || server_receive_bps > send_bps {
        send_bps
    } else {
        server_receive_bps
    }
}

pub fn server_brutal_bps(
    send_bps: u64,
    client_receive_bps: u64,
    auto: bool,
) -> u64 {
    if auto || client_receive_bps == 0 {
        0
    } else if send_bps == 0 {
        client_receive_bps
    } else {
        send_bps.min(client_receive_bps)
    }
}

type H3ClientConnection = h3::client::Connection<h3_quinn::Connection, Bytes>;
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3ServerConnection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type H3ServerRequestStream =
    h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Authenticated Hysteria2 QUIC session. The HTTP/3 driver remains alive for
/// the lifetime of the session while proxy streams use native QUIC bidi
/// streams, matching sing-quic's stream dispatcher model.
pub struct Hysteria2ClientSession {
    endpoint: Endpoint,
    connection: Connection,
    _request_sender: H3SendRequest,
    http3_driver: JoinHandle<h3::error::ConnectionError>,
    udp_channels:
        Arc<Mutex<HashMap<u32, tokio::sync::mpsc::Sender<UdpMessage>>>>,
    udp_session_id: AtomicU32,
    udp_driver: Option<JoinHandle<()>>,
    network_driver: Option<JoinHandle<()>>,
    _realm_port_mapping: Option<RealmPortMapping>,
    pub negotiated_send_bps: u64,
    pub auth: Hysteria2AuthResponse,
}

impl Hysteria2ClientSession {
    pub async fn connect(
        remote: SocketAddr,
        server_name: &str,
        password: &str,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
    ) -> io::Result<Self> {
        Self::connect_with_obfs(
            remote,
            server_name,
            password,
            send_bps,
            brutal_debug,
            receive_bps,
            tls,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_obfs(
        remote: SocketAddr,
        server_name: &str,
        password: &str,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        obfs: Option<Hysteria2ObfsConfig>,
    ) -> io::Result<Self> {
        Self::connect_with_transport_obfs(
            remote,
            server_name,
            password,
            send_bps,
            brutal_debug,
            receive_bps,
            tls,
            quinn::TransportConfig::default(),
            obfs,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_transport_obfs(
        remote: SocketAddr,
        server_name: &str,
        password: &str,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        transport: quinn::TransportConfig,
        obfs: Option<Hysteria2ObfsConfig>,
    ) -> io::Result<Self> {
        Self::connect_with_transport_obfs_and_profile(
            remote,
            server_name,
            password,
            send_bps,
            brutal_debug,
            receive_bps,
            tls,
            transport,
            obfs,
            crate::protocol::quic_bbr::BbrProfile::Standard,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_transport_obfs_and_profile(
        remote: SocketAddr,
        server_name: &str,
        password: &str,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        transport: quinn::TransportConfig,
        obfs: Option<Hysteria2ObfsConfig>,
        bbr_profile: crate::protocol::quic_bbr::BbrProfile,
    ) -> io::Result<Self> {
        Self::connect_with_transport_obfs_profile_and_chrome_parrot(
            remote,
            server_name,
            password,
            send_bps,
            brutal_debug,
            receive_bps,
            tls,
            transport,
            obfs,
            bbr_profile,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_transport_obfs_profile_and_chrome_parrot(
        remote: SocketAddr,
        server_name: &str,
        password: &str,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        mut transport: quinn::TransportConfig,
        obfs: Option<Hysteria2ObfsConfig>,
        bbr_profile: crate::protocol::quic_bbr::BbrProfile,
        chrome_parrot: bool,
    ) -> io::Result<Self> {
        let brutal =
            crate::protocol::hysteria::HysteriaBrutalConfig::with_profile(
                0,
                brutal_debug,
                bbr_profile,
            );
        transport.congestion_controller_factory(Arc::new(brutal.clone()));
        Self::connect_with_transport_obfs_socket(
            remote,
            server_name,
            password,
            send_bps,
            receive_bps,
            tls,
            Arc::new(transport),
            brutal,
            obfs,
            None,
            chrome_parrot,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_with_transport_obfs_socket(
        remote: SocketAddr,
        server_name: &str,
        password: &str,
        send_bps: u64,
        receive_bps: u64,
        tls: ClientTlsConfig,
        transport: Arc<quinn::TransportConfig>,
        brutal: crate::protocol::hysteria::HysteriaBrutalConfig,
        obfs: Option<Hysteria2ObfsConfig>,
        socket: Option<Arc<dyn AsyncUdpSocket>>,
        chrome_parrot: bool,
    ) -> io::Result<Self> {
        let tls_config = tls.config_for_handshake().await.map_err(other)?;
        let crypto = QuicClientConfig::try_from(tls_config).map_err(other)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(transport);
        if chrome_parrot {
            client_config.initial_dst_cid_provider(Arc::new(
                chrome_initial_destination_connection_id,
            ));
            client_config.chrome_parrot(true);
        }
        let bind = if remote.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let mut endpoint = hysteria2_endpoint_with_socket(
            bind,
            None,
            obfs,
            socket,
            chrome_parrot,
        )?;
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(remote, server_name)
            .map_err(other)?
            .await
            .map_err(other)?;
        let (mut http3, mut sender): (H3ClientConnection, H3SendRequest) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .map_err(other)?;
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://hysteria/auth")
            .header(HEADER_AUTH, password)
            .header(HEADER_CC_RX, receive_bps.to_string())
            .header(
                HEADER_PADDING,
                HeaderValue::from_bytes(&random_padding(256, 2048)?)
                    .map_err(other)?,
            )
            .body(())
            .map_err(other)?;
        let mut stream = sender.send_request(request).await.map_err(other)?;
        stream.finish().await.map_err(other)?;
        let response = stream.recv_response().await.map_err(other)?;
        if response.status().as_u16() != STATUS_AUTH_OK {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Hysteria2 authentication failed with status {}",
                    response.status()
                ),
            ));
        }
        let udp_enabled = response
            .headers()
            .get(HEADER_UDP)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .unwrap_or(false);
        let receive_header = response
            .headers()
            .get(HEADER_CC_RX)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let (receive_bps, receive_auto) = if receive_header == "auto" {
            (0, true)
        } else {
            (receive_header.parse().unwrap_or(0), false)
        };
        let negotiated_send_bps =
            client_brutal_bps(send_bps, receive_bps, receive_auto);
        brutal.set_bps(negotiated_send_bps);
        let http3_driver = tokio::spawn(async move {
            poll_fn(|context| http3.poll_close(context)).await
        });
        let udp_channels = Arc::new(Mutex::new(HashMap::<
            u32,
            tokio::sync::mpsc::Sender<UdpMessage>,
        >::new()));
        let udp_driver = if udp_enabled {
            let connection = connection.clone();
            let udp_channels = udp_channels.clone();
            Some(tokio::spawn(async move {
                while let Ok(packet) = connection.read_datagram().await {
                    let Ok(message) = UdpMessage::decode(&packet) else {
                        continue;
                    };
                    let sender = udp_channels
                        .lock()
                        .await
                        .get(&message.session_id)
                        .cloned();
                    if let Some(sender) = sender {
                        let _ = sender.send(message).await;
                    }
                }
            }))
        } else {
            None
        };
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
            _request_sender: sender,
            http3_driver,
            udp_channels,
            udp_session_id: AtomicU32::new(0),
            udp_driver,
            network_driver,
            _realm_port_mapping: None,
            negotiated_send_bps,
            auth: Hysteria2AuthResponse {
                udp_enabled,
                receive_bps,
                receive_auto,
            },
        })
    }

    pub async fn open_tcp(
        &self,
        address: &str,
        early_payload: &[u8],
    ) -> io::Result<Hysteria2TcpStream> {
        let (mut send, recv) =
            self.connection.open_bi().await.map_err(other)?;
        let request = encode_tcp_request(address, early_payload)?;
        send.write_all(&request).await?;
        Ok(Hysteria2TcpStream { send, recv })
    }

    pub async fn open_tcp_checked(
        &self,
        address: &str,
    ) -> io::Result<Hysteria2TcpStream> {
        let mut stream = self.open_tcp(address, &[]).await?;
        let (ok, message) = read_tcp_response_async(&mut stream.recv).await?;
        if !ok {
            return Err(io::Error::other(format!(
                "Hysteria2 remote error: {message}"
            )));
        }
        Ok(stream)
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub async fn open_udp(&self) -> io::Result<Hysteria2PacketConnection> {
        if !self.auth.udp_enabled {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP is disabled by the Hysteria2 server",
            ));
        }
        let session_id = self.udp_session_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        self.udp_channels.lock().await.insert(session_id, sender);
        Ok(Hysteria2PacketConnection {
            connection: self.connection.clone(),
            session_id,
            packet_id: AtomicU32::new(0),
            receiver: Mutex::new(receiver),
            defragmenter: Mutex::new(UdpDefragmenter::default()),
            channels: self.udp_channels.clone(),
        })
    }
}

impl Drop for Hysteria2ClientSession {
    fn drop(&mut self) {
        self.http3_driver.abort();
        if let Some(driver) = self.udp_driver.take() {
            driver.abort();
        }
        if let Some(driver) = self.network_driver.take() {
            driver.abort();
        }
        self.connection.close(0_u32.into(), b"");
        self.endpoint.close(0_u32.into(), b"");
    }
}

pub struct Hysteria2PacketConnection {
    connection: Connection,
    session_id: u32,
    packet_id: AtomicU32,
    receiver: Mutex<tokio::sync::mpsc::Receiver<UdpMessage>>,
    defragmenter: Mutex<UdpDefragmenter>,
    channels: Arc<Mutex<HashMap<u32, tokio::sync::mpsc::Sender<UdpMessage>>>>,
}

impl PacketConnection for Hysteria2PacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            if data.len() > MAX_UDP_SIZE {
                return Err(invalid("UDP payload exceeds maximum size"));
            }
            let message = UdpMessage {
                session_id: self.session_id,
                packet_id: self.packet_id.fetch_add(1, Ordering::Relaxed)
                    as u16,
                fragment_id: 0,
                fragment_count: 1,
                address: destination.to_string(),
                data: data.to_vec(),
            };
            let mtu = self.connection.max_datagram_size().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "QUIC peer does not support datagrams",
                )
            })?;
            for fragment in fragment_udp_message(message, mtu)? {
                self.connection
                    .send_datagram(Bytes::from(fragment.encode()?))
                    .map_err(other)?;
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
                                "Hysteria2 UDP session closed",
                            )
                        },
                    )?;
                let Some(message) =
                    self.defragmenter.lock().await.feed(message)
                else {
                    continue;
                };
                if data.len() < message.data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "receive buffer is too small",
                    ));
                }
                data[..message.data.len()].copy_from_slice(&message.data);
                return Ok((message.data.len(), message.address.parse()?));
            }
        })
    }
}

impl Drop for Hysteria2PacketConnection {
    fn drop(&mut self) {
        if let Ok(mut channels) = self.channels.try_lock() {
            channels.remove(&self.session_id);
        }
    }
}

pub struct Hysteria2ServerSession {
    connection: Connection,
    _http3: H3ServerConnection,
    pub user: String,
    pub client_receive_bps: u64,
    pub receive_auto: bool,
}

#[derive(Debug, Clone)]
pub struct Hysteria2MasqueradeResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub content: Bytes,
}

#[derive(Debug, Clone)]
pub enum Hysteria2MasqueradeHandler {
    String(Hysteria2MasqueradeResponse),
    File {
        directory: PathBuf,
    },
    Proxy {
        url: url::Url,
        rewrite_host: bool,
        client: reqwest::Client,
    },
}

impl Hysteria2MasqueradeHandler {
    async fn serve_proxy_stream(
        &self,
        request: &Request<()>,
        stream: H3ServerRequestStream,
    ) -> io::Result<()> {
        let Self::Proxy {
            url,
            rewrite_host,
            client,
        } = self
        else {
            return Err(invalid("masquerade handler is not a proxy"));
        };

        let target = reverse_proxy_url(url, request.uri())?;
        let (mut send_stream, recv_stream) = stream.split();
        let request_body = futures_util::stream::try_unfold(
            recv_stream,
            |mut recv_stream| async move {
                match recv_stream.recv_data().await.map_err(other)? {
                    Some(mut chunk) => Ok::<_, io::Error>(Some((
                        chunk.copy_to_bytes(chunk.remaining()),
                        recv_stream,
                    ))),
                    None => Ok::<_, io::Error>(None),
                }
            },
        );
        let mut outbound = client
            .request(request.method().clone(), target)
            .body(reqwest::Body::wrap_stream(request_body));
        let mut headers = request.headers().clone();
        remove_hop_by_hop_headers(&mut headers);
        if *rewrite_host {
            headers.remove(http::header::HOST);
        } else if !headers.contains_key(http::header::HOST)
            && let Some(authority) = request.uri().authority()
        {
            headers.insert(
                http::header::HOST,
                HeaderValue::from_str(authority.as_str()).map_err(other)?,
            );
        }
        outbound = outbound.headers(headers);

        let mut response = match outbound.send().await {
            Ok(response) => response,
            Err(_) => {
                let response = bad_gateway_masquerade();
                send_masquerade_response(&mut send_stream, response).await?;
                return Ok(());
            }
        };
        let mut headers = response.headers().clone();
        remove_hop_by_hop_headers(&mut headers);
        let mut response_head = Response::builder().status(response.status());
        if let Some(response_headers) = response_head.headers_mut() {
            response_headers.extend(headers);
        }
        send_stream
            .send_response(response_head.body(()).map_err(other)?)
            .await
            .map_err(other)?;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    send_stream.send_data(chunk).await.map_err(other)?;
                }
                Ok(None) => break,
                Err(_) => {
                    send_stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                    return Ok(());
                }
            }
        }
        send_stream.finish().await.map_err(other)
    }

    async fn response(
        &self,
        request: &Request<()>,
        request_body: Bytes,
    ) -> io::Result<Hysteria2MasqueradeResponse> {
        match self {
            Self::String(response) => Ok(response.clone()),
            Self::File { directory } => {
                if !matches!(*request.method(), Method::GET | Method::HEAD) {
                    return Ok(Hysteria2MasqueradeResponse {
                        status: StatusCode::METHOD_NOT_ALLOWED,
                        headers: HeaderMap::new(),
                        content: Bytes::new(),
                    });
                }
                let decoded = percent_decode_str(request.uri().path())
                    .decode_utf8()
                    .map_err(|_| invalid("invalid masquerade request path"))?;
                let mut path = directory.clone();
                for component in
                    std::path::Path::new(decoded.trim_start_matches('/'))
                        .components()
                {
                    match component {
                        Component::Normal(component) => path.push(component),
                        Component::CurDir => {}
                        _ => return Ok(not_found_masquerade()),
                    }
                }
                if decoded.ends_with('/') || path == *directory {
                    path.push("index.html");
                }
                let root = match tokio::fs::canonicalize(directory).await {
                    Ok(root) => root,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Ok(not_found_masquerade());
                    }
                    Err(error) => return Err(error),
                };
                let path = match tokio::fs::canonicalize(&path).await {
                    Ok(path) if path.starts_with(&root) => path,
                    Ok(_) => return Ok(not_found_masquerade()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Ok(not_found_masquerade());
                    }
                    Err(error) => return Err(error),
                };
                let content = match tokio::fs::read(&path).await {
                    Ok(content) => content,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Ok(not_found_masquerade());
                    }
                    Err(error) => return Err(error),
                };
                let mut headers = HeaderMap::new();
                headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static(content_type_for_path(&path)),
                );
                Ok(Hysteria2MasqueradeResponse {
                    status: StatusCode::OK,
                    headers,
                    content: if request.method() == Method::HEAD {
                        Bytes::new()
                    } else {
                        Bytes::from(content)
                    },
                })
            }
            Self::Proxy {
                url,
                rewrite_host,
                client,
            } => {
                let target = reverse_proxy_url(url, request.uri())?;
                let mut outbound = client
                    .request(request.method().clone(), target)
                    .body(request_body);
                let mut headers = request.headers().clone();
                remove_hop_by_hop_headers(&mut headers);
                if *rewrite_host {
                    headers.remove(http::header::HOST);
                } else if !headers.contains_key(http::header::HOST)
                    && let Some(authority) = request.uri().authority()
                {
                    headers.insert(
                        http::header::HOST,
                        HeaderValue::from_str(authority.as_str())
                            .map_err(other)?,
                    );
                }
                outbound = outbound.headers(headers);
                let response = match outbound.send().await {
                    Ok(response) => response,
                    Err(_) => return Ok(bad_gateway_masquerade()),
                };
                let status = response.status();
                let mut headers = response.headers().clone();
                remove_hop_by_hop_headers(&mut headers);
                let content = match response.bytes().await {
                    Ok(content) => content,
                    Err(_) => return Ok(bad_gateway_masquerade()),
                };
                Ok(Hysteria2MasqueradeResponse {
                    status,
                    headers,
                    content,
                })
            }
        }
    }
}

fn reverse_proxy_url(
    base: &url::Url,
    request: &http::Uri,
) -> io::Result<url::Url> {
    let base_path = base.path().trim_end_matches('/');
    let request_path = request.path().trim_start_matches('/');
    let path = if request_path.is_empty() {
        if base.path().is_empty() {
            "/"
        } else {
            base.path()
        }
        .to_owned()
    } else if base_path.is_empty() {
        format!("/{request_path}")
    } else {
        format!("{base_path}/{request_path}")
    };
    let query = match (base.query(), request.query()) {
        (Some(base), Some(request))
            if !base.is_empty() && !request.is_empty() =>
        {
            Some(format!("{base}&{request}"))
        }
        (Some(base), _) if !base.is_empty() => Some(base.to_owned()),
        (_, Some(request)) if !request.is_empty() => Some(request.to_owned()),
        _ => None,
    };
    let mut serialized =
        format!("{}{}", &base[..url::Position::BeforePath], path);
    if let Some(query) = query {
        serialized.push('?');
        serialized.push_str(&query);
    }
    let target = url::Url::parse(&serialized).map_err(other)?;
    if !matches!(target.scheme(), "http" | "https") || target.host().is_none() {
        return Err(invalid("invalid Hysteria2 proxy masquerade URL"));
    }
    Ok(target)
}

fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
    let connection_tokens = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| {
            http::header::HeaderName::from_bytes(value.trim().as_bytes()).ok()
        })
        .collect::<Vec<_>>();
    for name in connection_tokens {
        headers.remove(name);
    }
    for name in [
        http::header::CONNECTION,
        http::header::HeaderName::from_static("proxy-connection"),
        http::header::HeaderName::from_static("keep-alive"),
        http::header::HeaderName::from_static("proxy-authenticate"),
        http::header::HeaderName::from_static("proxy-authorization"),
        http::header::TE,
        http::header::TRAILER,
        http::header::TRANSFER_ENCODING,
        http::header::UPGRADE,
    ] {
        headers.remove(name);
    }
}

fn not_found_masquerade() -> Hysteria2MasqueradeResponse {
    Hysteria2MasqueradeResponse {
        status: StatusCode::NOT_FOUND,
        headers: HeaderMap::new(),
        content: Bytes::from_static(b"404 page not found\n"),
    }
}

fn bad_gateway_masquerade() -> Hysteria2MasqueradeResponse {
    Hysteria2MasqueradeResponse {
        status: StatusCode::BAD_GATEWAY,
        headers: HeaderMap::new(),
        content: Bytes::new(),
    }
}

async fn send_masquerade_response<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    masquerade: Hysteria2MasqueradeResponse,
) -> io::Result<()>
where
    S: h3::quic::SendStream<Bytes>,
{
    let mut response = Response::builder().status(masquerade.status);
    if let Some(headers) = response.headers_mut() {
        headers.extend(masquerade.headers);
    }
    stream
        .send_response(response.body(()).map_err(other)?)
        .await
        .map_err(other)?;
    if !masquerade.content.is_empty() {
        stream.send_data(masquerade.content).await.map_err(other)?;
    }
    stream.finish().await.map_err(other)
}

fn content_type_for_path(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

impl Hysteria2ServerSession {
    pub async fn authenticate(
        connection: Connection,
        users: &HashMap<String, String>,
        udp_enabled: bool,
        receive_bps: Option<u64>,
    ) -> io::Result<Self> {
        let (receive_bps, ignore_client_bandwidth) = match receive_bps {
            Some(receive_bps) => (receive_bps, false),
            None => (0, true),
        };
        Self::authenticate_with_bandwidth_policy(
            connection,
            users,
            udp_enabled,
            receive_bps,
            ignore_client_bandwidth,
        )
        .await
    }

    pub async fn authenticate_with_bandwidth_policy(
        connection: Connection,
        users: &HashMap<String, String>,
        udp_enabled: bool,
        receive_bps: u64,
        ignore_client_bandwidth: bool,
    ) -> io::Result<Self> {
        Self::authenticate_with_masquerade(
            connection,
            users,
            udp_enabled,
            receive_bps,
            ignore_client_bandwidth,
            None,
        )
        .await
    }

    pub async fn authenticate_with_masquerade(
        connection: Connection,
        users: &HashMap<String, String>,
        udp_enabled: bool,
        receive_bps: u64,
        ignore_client_bandwidth: bool,
        masquerade: Option<&Hysteria2MasqueradeHandler>,
    ) -> io::Result<Self> {
        let mut http3: H3ServerConnection = h3::server::Connection::new(
            h3_quinn::Connection::new(connection.clone()),
        )
        .await
        .map_err(other)?;
        let (request, mut stream) = loop {
            let resolver =
                http3.accept().await.map_err(other)?.ok_or_else(|| {
                    invalid("Hysteria2 connection closed before authentication")
                })?;
            let (request, mut stream) =
                resolver.resolve_request().await.map_err(other)?;
            if request.method() == Method::POST
                && request.uri().host() == Some(AUTH_HOST)
                && request.uri().path() == AUTH_PATH
            {
                break (request, stream);
            }
            if let Some(handler @ Hysteria2MasqueradeHandler::Proxy { .. }) =
                masquerade
            {
                handler.serve_proxy_stream(&request, stream).await?;
                continue;
            }
            let mut request_body = Vec::new();
            while let Some(mut chunk) =
                stream.recv_data().await.map_err(other)?
            {
                request_body
                    .extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            let masquerade = match masquerade {
                Some(handler) => {
                    handler
                        .response(&request, Bytes::from(request_body))
                        .await?
                }
                None => not_found_masquerade(),
            };
            send_masquerade_response(&mut stream, masquerade).await?;
        };
        let password = request
            .headers()
            .get(HEADER_AUTH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let Some(user) = users.get(password).cloned() else {
            stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(())
                        .map_err(other)?,
                )
                .await
                .map_err(other)?;
            stream.finish().await.map_err(other)?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid Hysteria2 authentication token",
            ));
        };
        let client_receive_bps = request
            .headers()
            .get(HEADER_CC_RX)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let receive_header = match server_receive_policy(
            receive_bps,
            ignore_client_bandwidth,
            client_receive_bps,
        ) {
            Ok(receive_header) => receive_header,
            Err(error) => {
                stream
                    .send_response(
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(())
                            .map_err(other)?,
                    )
                    .await
                    .map_err(other)?;
                stream.finish().await.map_err(other)?;
                return Err(error);
            }
        };
        let receive_auto = receive_header == "auto";
        let mut response = Response::builder()
            .status(StatusCode::from_u16(STATUS_AUTH_OK).unwrap())
            .header(HEADER_UDP, udp_enabled.to_string())
            .header(HEADER_CC_RX, receive_header);
        response = response.header(
            HEADER_PADDING,
            HeaderValue::from_bytes(&random_padding(256, 2048)?)
                .map_err(other)?,
        );
        stream
            .send_response(response.body(()).map_err(other)?)
            .await
            .map_err(other)?;
        stream.finish().await.map_err(other)?;
        Ok(Self {
            connection,
            _http3: http3,
            user,
            client_receive_bps,
            receive_auto,
        })
    }

    pub async fn accept_tcp(&self) -> io::Result<(Hysteria2TcpStream, String)> {
        let (send, mut recv) =
            self.connection.accept_bi().await.map_err(other)?;
        let frame_type = read_quic_varint(&mut recv).await?;
        if frame_type != FRAME_TYPE_TCP_REQUEST {
            return Err(invalid(format!(
                "unexpected Hysteria2 stream frame type {frame_type:#x}"
            )));
        }
        let address_length = read_quic_varint(&mut recv).await?;
        let address_length = usize::try_from(address_length)
            .map_err(|_| invalid("invalid address length"))?;
        if address_length == 0 || address_length > MAX_ADDRESS_LENGTH {
            return Err(invalid("invalid address length"));
        }
        let mut address = vec![0_u8; address_length];
        recv.read_exact(&mut address).await.map_err(other)?;
        let address = String::from_utf8(address)
            .map_err(|_| invalid("Hysteria2 address is not UTF-8"))?;
        let padding_length = read_quic_varint(&mut recv).await?;
        let padding_length = usize::try_from(padding_length)
            .map_err(|_| invalid("invalid padding length"))?;
        if padding_length > MAX_PADDING_LENGTH {
            return Err(invalid("invalid padding length"));
        }
        let mut padding = vec![0_u8; padding_length];
        recv.read_exact(&mut padding).await.map_err(other)?;
        Ok((Hysteria2TcpStream { send, recv }, address))
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub async fn read_udp(&self) -> io::Result<UdpMessage> {
        let packet = self.connection.read_datagram().await.map_err(other)?;
        UdpMessage::decode(&packet)
    }

    pub fn send_udp(&self, message: UdpMessage) -> io::Result<()> {
        let mtu = self.connection.max_datagram_size().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "QUIC peer does not support datagrams",
            )
        })?;
        for fragment in fragment_udp_message(message, mtu)? {
            self.connection
                .send_datagram(Bytes::from(fragment.encode()?))
                .map_err(other)?;
        }
        Ok(())
    }
}

fn server_receive_policy(
    receive_bps: u64,
    ignore_client_bandwidth: bool,
    client_receive_bps: u64,
) -> io::Result<String> {
    if receive_bps > 0 && ignore_client_bandwidth && client_receive_bps == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hysteria2 client bandwidth is required by server",
        ));
    }
    if client_receive_bps == 0 || (receive_bps == 0 && ignore_client_bandwidth)
    {
        Ok("auto".into())
    } else {
        Ok(receive_bps.to_string())
    }
}

pub fn hysteria2_server_endpoint(
    address: SocketAddr,
    tls: ServerTlsConfig,
) -> io::Result<Endpoint> {
    hysteria2_server_endpoint_with_obfs(address, tls, None)
}

pub fn hysteria2_server_endpoint_with_obfs(
    address: SocketAddr,
    tls: ServerTlsConfig,
    obfs: Option<Hysteria2ObfsConfig>,
) -> io::Result<Endpoint> {
    hysteria2_server_endpoint_with_transport_obfs(
        address,
        tls,
        Arc::new(quinn::TransportConfig::default()),
        obfs,
    )
}

pub fn hysteria2_server_endpoint_with_transport_obfs(
    address: SocketAddr,
    tls: ServerTlsConfig,
    transport: Arc<quinn::TransportConfig>,
    obfs: Option<Hysteria2ObfsConfig>,
) -> io::Result<Endpoint> {
    let crypto = QuicServerConfig::try_from(tls.config).map_err(other)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(transport);
    hysteria2_endpoint(address, Some(server_config), obfs)
}

pub fn hysteria2_server_endpoint_with_transport_obfs_socket(
    tls: ServerTlsConfig,
    transport: Arc<quinn::TransportConfig>,
    obfs: Option<Hysteria2ObfsConfig>,
    socket: Arc<dyn AsyncUdpSocket>,
) -> io::Result<Endpoint> {
    let crypto = QuicServerConfig::try_from(tls.config).map_err(other)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(transport);
    let address = socket.local_addr()?;
    hysteria2_endpoint_with_socket(
        address,
        Some(server_config),
        obfs,
        Some(socket),
        false,
    )
}

fn hysteria2_endpoint(
    address: SocketAddr,
    server_config: Option<quinn::ServerConfig>,
    obfs: Option<Hysteria2ObfsConfig>,
) -> io::Result<Endpoint> {
    hysteria2_endpoint_with_socket(address, server_config, obfs, None, false)
}

fn hysteria2_endpoint_with_socket(
    address: SocketAddr,
    server_config: Option<quinn::ServerConfig>,
    obfs: Option<Hysteria2ObfsConfig>,
    socket: Option<Arc<dyn AsyncUdpSocket>>,
    chrome_parrot: bool,
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
    let socket: Arc<dyn AsyncUdpSocket> = match obfs {
        Some(config) => Arc::new(Hysteria2ObfsSocket::new(socket, config)),
        None => socket,
    };
    Endpoint::new_with_abstract_socket(
        hysteria2_client_endpoint_config(chrome_parrot)?,
        server_config,
        socket,
        runtime,
    )
}

async fn read_quic_varint(reader: &mut RecvStream) -> io::Result<u64> {
    let first = reader.read_u8().await.map_err(other)?;
    let length = 1_usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..length {
        value =
            (value << 8) | u64::from(reader.read_u8().await.map_err(other)?);
    }
    Ok(value)
}

async fn read_tcp_response_async(
    reader: &mut RecvStream,
) -> io::Result<(bool, String)> {
    let status = reader.read_u8().await.map_err(other)?;
    let message_length = read_quic_varint(reader).await?;
    let message_length = usize::try_from(message_length)
        .map_err(|_| invalid("invalid message length"))?;
    if message_length > MAX_MESSAGE_LENGTH {
        return Err(invalid("invalid message length"));
    }
    let mut message = vec![0_u8; message_length];
    reader.read_exact(&mut message).await.map_err(other)?;
    let message = String::from_utf8(message)
        .map_err(|_| invalid("Hysteria2 response message is not UTF-8"))?;
    let padding_length = read_quic_varint(reader).await?;
    let padding_length = usize::try_from(padding_length)
        .map_err(|_| invalid("invalid padding length"))?;
    if padding_length > MAX_PADDING_LENGTH {
        return Err(invalid("invalid padding length"));
    }
    let mut padding = vec![0_u8; padding_length];
    reader.read_exact(&mut padding).await.map_err(other)?;
    Ok((status == 0, message))
}

pub struct Hysteria2Outbound {
    server: SocksAddr,
    server_name: String,
    password: String,
    send_bps: u64,
    receive_bps: u64,
    tls: ClientTlsConfig,
    transport: Arc<quinn::TransportConfig>,
    brutal: crate::protocol::hysteria::HysteriaBrutalConfig,
    obfs: Option<Hysteria2ObfsConfig>,
    chrome_parrot: bool,
    packet_dialer: Option<Arc<dyn Dialer>>,
    realm: Option<RealmClientConnector>,
    state: Mutex<Option<Hysteria2ClientSession>>,
}

impl Hysteria2Outbound {
    pub fn new(
        server: SocksAddr,
        server_name: impl Into<String>,
        password: impl Into<String>,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
    ) -> Self {
        Self::new_with_transport_obfs(
            server,
            server_name,
            password,
            send_bps,
            brutal_debug,
            receive_bps,
            tls,
            quinn::TransportConfig::default(),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_obfs(
        server: SocksAddr,
        server_name: impl Into<String>,
        password: impl Into<String>,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        obfs: Option<Hysteria2ObfsConfig>,
    ) -> Self {
        Self::new_with_transport_obfs(
            server,
            server_name,
            password,
            send_bps,
            brutal_debug,
            receive_bps,
            tls,
            quinn::TransportConfig::default(),
            obfs,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_transport_obfs(
        server: SocksAddr,
        server_name: impl Into<String>,
        password: impl Into<String>,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        transport: quinn::TransportConfig,
        obfs: Option<Hysteria2ObfsConfig>,
    ) -> Self {
        Self::new_with_transport_obfs_and_profile(
            server,
            server_name,
            password,
            send_bps,
            brutal_debug,
            receive_bps,
            tls,
            transport,
            obfs,
            crate::protocol::quic_bbr::BbrProfile::Standard,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_transport_obfs_and_profile(
        server: SocksAddr,
        server_name: impl Into<String>,
        password: impl Into<String>,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        transport: quinn::TransportConfig,
        obfs: Option<Hysteria2ObfsConfig>,
        bbr_profile: crate::protocol::quic_bbr::BbrProfile,
    ) -> Self {
        Self::new_with_transport_obfs_profile_and_chrome_parrot(
            server,
            server_name,
            password,
            send_bps,
            brutal_debug,
            receive_bps,
            tls,
            transport,
            obfs,
            bbr_profile,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_transport_obfs_profile_and_chrome_parrot(
        server: SocksAddr,
        server_name: impl Into<String>,
        password: impl Into<String>,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        mut transport: quinn::TransportConfig,
        obfs: Option<Hysteria2ObfsConfig>,
        bbr_profile: crate::protocol::quic_bbr::BbrProfile,
        chrome_parrot: bool,
    ) -> Self {
        let brutal =
            crate::protocol::hysteria::HysteriaBrutalConfig::with_profile(
                0,
                brutal_debug,
                bbr_profile,
            );
        transport.congestion_controller_factory(Arc::new(brutal.clone()));
        Self {
            server,
            server_name: server_name.into(),
            password: password.into(),
            send_bps,
            receive_bps,
            tls,
            transport: Arc::new(transport),
            brutal,
            obfs,
            chrome_parrot,
            packet_dialer: None,
            realm: None,
            state: Mutex::new(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_transport_obfs_and_packet_dialer(
        server: SocksAddr,
        server_name: impl Into<String>,
        password: impl Into<String>,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        transport: quinn::TransportConfig,
        obfs: Option<Hysteria2ObfsConfig>,
        packet_dialer: Arc<dyn Dialer>,
    ) -> Self {
        Self::new_with_transport_obfs_and_packet_dialer_and_profile(
            server,
            server_name,
            password,
            send_bps,
            brutal_debug,
            receive_bps,
            tls,
            transport,
            obfs,
            packet_dialer,
            crate::protocol::quic_bbr::BbrProfile::Standard,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_transport_obfs_and_packet_dialer_and_profile(
        server: SocksAddr,
        server_name: impl Into<String>,
        password: impl Into<String>,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        transport: quinn::TransportConfig,
        obfs: Option<Hysteria2ObfsConfig>,
        packet_dialer: Arc<dyn Dialer>,
        bbr_profile: crate::protocol::quic_bbr::BbrProfile,
    ) -> Self {
        Self::new_with_transport_obfs_packet_dialer_profile_and_chrome_parrot(
            server,
            server_name,
            password,
            send_bps,
            brutal_debug,
            receive_bps,
            tls,
            transport,
            obfs,
            packet_dialer,
            bbr_profile,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_transport_obfs_packet_dialer_profile_and_chrome_parrot(
        server: SocksAddr,
        server_name: impl Into<String>,
        password: impl Into<String>,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        mut transport: quinn::TransportConfig,
        obfs: Option<Hysteria2ObfsConfig>,
        packet_dialer: Arc<dyn Dialer>,
        bbr_profile: crate::protocol::quic_bbr::BbrProfile,
        chrome_parrot: bool,
    ) -> Self {
        let brutal =
            crate::protocol::hysteria::HysteriaBrutalConfig::with_profile(
                0,
                brutal_debug,
                bbr_profile,
            );
        transport.congestion_controller_factory(Arc::new(brutal.clone()));
        Self {
            server,
            server_name: server_name.into(),
            password: password.into(),
            send_bps,
            receive_bps,
            tls,
            transport: Arc::new(transport),
            brutal,
            obfs,
            chrome_parrot,
            packet_dialer: Some(packet_dialer),
            realm: None,
            state: Mutex::new(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_realm(
        server_name: impl Into<String>,
        password: impl Into<String>,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        transport: quinn::TransportConfig,
        obfs: Option<Hysteria2ObfsConfig>,
        packet_dialer: Arc<dyn Dialer>,
        realm: RealmClientConnector,
    ) -> Self {
        Self::new_with_realm_and_profile(
            server_name,
            password,
            send_bps,
            brutal_debug,
            receive_bps,
            tls,
            transport,
            obfs,
            packet_dialer,
            realm,
            crate::protocol::quic_bbr::BbrProfile::Standard,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_realm_and_profile(
        server_name: impl Into<String>,
        password: impl Into<String>,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        transport: quinn::TransportConfig,
        obfs: Option<Hysteria2ObfsConfig>,
        packet_dialer: Arc<dyn Dialer>,
        realm: RealmClientConnector,
        bbr_profile: crate::protocol::quic_bbr::BbrProfile,
    ) -> Self {
        Self::new_with_realm_profile_and_chrome_parrot(
            server_name,
            password,
            send_bps,
            brutal_debug,
            receive_bps,
            tls,
            transport,
            obfs,
            packet_dialer,
            realm,
            bbr_profile,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_realm_profile_and_chrome_parrot(
        server_name: impl Into<String>,
        password: impl Into<String>,
        send_bps: u64,
        brutal_debug: bool,
        receive_bps: u64,
        tls: ClientTlsConfig,
        mut transport: quinn::TransportConfig,
        obfs: Option<Hysteria2ObfsConfig>,
        packet_dialer: Arc<dyn Dialer>,
        realm: RealmClientConnector,
        bbr_profile: crate::protocol::quic_bbr::BbrProfile,
        chrome_parrot: bool,
    ) -> Self {
        let server_name = server_name.into();
        let brutal =
            crate::protocol::hysteria::HysteriaBrutalConfig::with_profile(
                0,
                brutal_debug,
                bbr_profile,
            );
        transport.congestion_controller_factory(Arc::new(brutal.clone()));
        Self {
            server: SocksAddr::new(server_name.clone(), 0),
            server_name,
            password: password.into(),
            send_bps,
            receive_bps,
            tls,
            transport: Arc::new(transport),
            brutal,
            obfs,
            chrome_parrot,
            packet_dialer: Some(packet_dialer),
            realm: Some(realm),
            state: Mutex::new(None),
        }
    }

    async fn ensure_session<'a>(
        &self,
        state: &'a mut Option<Hysteria2ClientSession>,
    ) -> io::Result<&'a Hysteria2ClientSession> {
        let active = state
            .as_ref()
            .is_some_and(|session| session.connection.close_reason().is_none());
        if !active {
            let (socket, remote, realm_port_mapping) =
                if let Some(realm) = &self.realm {
                    let dialer =
                        self.packet_dialer.as_ref().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "Hysteria2 Realm requires a packet dialer",
                            )
                        })?;
                    let route_destinations = realm
                        .route_destinations()
                        .await
                        .map_err(io::Error::other)?;
                    let sockets = futures_util::future::join_all(
                        route_destinations.into_iter().map(
                            |(ipv4, destination)| {
                                let dialer = dialer.clone();
                                async move {
                                    PacketUdpSocket::bind(
                                        dialer,
                                        &destination,
                                        !ipv4,
                                    )
                                    .await
                                    .map(|socket| {
                                        (ipv4, RealmPacketSocket::new(socket))
                                    })
                                    .map_err(|error| {
                                        format!(
                                            "{}: {error}",
                                            if ipv4 { "v4" } else { "v6" }
                                        )
                                    })
                                }
                            },
                        ),
                    )
                    .await;
                    let mut families = Vec::new();
                    let mut listen_errors = Vec::new();
                    for socket in sockets {
                        match socket {
                            Ok(socket) => families.push(socket),
                            Err(error) => listen_errors.push(error),
                        }
                    }
                    if families.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            format!(
                                "listen UDP for Realm: {}",
                                listen_errors.join("; ")
                            ),
                        ));
                    }
                    let outcome = realm
                        .connect_families(families)
                        .await
                        .map_err(io::Error::other)?;
                    (
                        Some(outcome.socket as Arc<dyn AsyncUdpSocket>),
                        outcome.peer_addr,
                        outcome.port_mapping,
                    )
                } else if let Some(dialer) = &self.packet_dialer {
                    let (socket, remote) =
                        PacketUdpSocket::connect(dialer.clone(), &self.server)
                            .await?;
                    (Some(socket), remote, None)
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
                                "Hysteria2 server resolved to no addresses",
                            )
                        })?;
                    (None, remote, None)
                };
            let tls = self.tls.clone();
            let mut session =
                Hysteria2ClientSession::connect_with_transport_obfs_socket(
                    remote,
                    &self.server_name,
                    &self.password,
                    self.send_bps,
                    self.receive_bps,
                    tls,
                    self.transport.clone(),
                    self.brutal.clone(),
                    self.obfs.clone(),
                    socket,
                    self.chrome_parrot,
                )
                .await?;
            session._realm_port_mapping = realm_port_mapping;
            *state = Some(session);
        }
        Ok(state.as_ref().expect("Hysteria2 session initialized"))
    }

    async fn open_tcp(
        &self,
        destination: &SocksAddr,
    ) -> io::Result<Hysteria2TcpStream> {
        let mut state = self.state.lock().await;
        self.ensure_session(&mut state)
            .await?
            .open_tcp_checked(&destination.to_string())
            .await
    }

    async fn open_udp(&self) -> io::Result<Hysteria2PacketConnection> {
        let mut state = self.state.lock().await;
        self.ensure_session(&mut state).await?.open_udp().await
    }
}

impl Dialer for Hysteria2Outbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            Ok(Box::new(self.open_tcp(destination).await?) as Stream)
        })
    }

    fn listen_udp<'a>(
        &'a self,
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(
            async move { Ok(Box::new(self.open_udp().await?) as PacketStream) },
        )
    }
}

#[cfg(test)]
mod tests {
    use bytes::Buf as _;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;

    use super::*;

    use crate::{
        common::tls::{
            build_client_config, build_server_config_with_default_alpn,
        },
        option::{InboundTlsOptions, OutboundTlsOptions},
    };

    #[test]
    fn server_bandwidth_policy_matches_upstream_headers() {
        assert_eq!(server_receive_policy(0, true, 0).unwrap(), "auto");
        assert_eq!(server_receive_policy(0, true, 123).unwrap(), "auto");
        assert_eq!(server_receive_policy(123, false, 0).unwrap(), "auto");
        assert_eq!(server_receive_policy(123, false, 456).unwrap(), "123");
        assert_eq!(server_receive_policy(0, false, 456).unwrap(), "0");
        assert_eq!(server_receive_policy(123, true, 456).unwrap(), "123");
        assert!(server_receive_policy(123, true, 0).is_err());
    }

    #[test]
    fn brutal_bandwidth_selection_matches_sing_quic() {
        assert_eq!(client_brutal_bps(1_000, 400, false), 400);
        assert_eq!(client_brutal_bps(1_000, 2_000, false), 1_000);
        assert_eq!(client_brutal_bps(1_000, 0, false), 1_000);
        assert_eq!(client_brutal_bps(1_000, 400, true), 0);
        assert_eq!(client_brutal_bps(0, 400, false), 0);

        assert_eq!(server_brutal_bps(1_000, 400, false), 400);
        assert_eq!(server_brutal_bps(1_000, 2_000, false), 1_000);
        assert_eq!(server_brutal_bps(0, 400, false), 400);
        assert_eq!(server_brutal_bps(1_000, 400, true), 0);
    }

    #[test]
    fn quic_varint_boundary_vectors() {
        let vectors = [
            (0, "00"),
            (63, "3f"),
            (64, "4040"),
            (16_383, "7fff"),
            (16_384, "80004000"),
            (1_073_741_823, "bfffffff"),
            (1_073_741_824, "c000000040000000"),
            (MAX_QUIC_VARINT, "ffffffffffffffff"),
        ];
        for (value, expected) in vectors {
            let mut encoded = Vec::new();
            encode_quic_varint(value, &mut encoded).unwrap();
            assert_eq!(hex::encode(&encoded), expected);
            assert_eq!(
                decode_quic_varint(&encoded).unwrap(),
                (value, encoded.len())
            );
        }
    }

    #[test]
    fn tcp_request_and_response_match_go_wire_layout() {
        let request =
            encode_tcp_request_with_padding("example.com:443", b"abc", b"hi")
                .unwrap();
        assert_eq!(
            hex::encode(&request),
            "44010f6578616d706c652e636f6d3a343433036162636869"
        );
        let (address, payload) = decode_tcp_request_frame(&request).unwrap();
        assert_eq!(address, "example.com:443");
        assert_eq!(payload, b"hi");

        let response =
            encode_tcp_response_with_padding(true, "", b"xy", b"ok").unwrap();
        assert_eq!(hex::encode(&response), "00000278796f6b");
        let (ok, message, payload) = decode_tcp_response(&response).unwrap();
        assert!(ok);
        assert!(message.is_empty());
        assert_eq!(payload, b"ok");
    }

    #[test]
    fn udp_wire_fragmentation_and_out_of_order_reassembly() {
        let message = UdpMessage {
            session_id: 0x0102_0304,
            packet_id: 0x0506,
            fragment_id: 0,
            fragment_count: 1,
            address: "1.2.3.4:53".into(),
            data: b"abcdefghij".to_vec(),
        };
        let encoded = message.encode().unwrap();
        assert_eq!(
            hex::encode(&encoded),
            "01020304050600010a312e322e332e343a35336162636465666768696a"
        );
        assert_eq!(UdpMessage::decode(&encoded).unwrap(), message);

        let fragments = fragment_udp_message(message, 24).unwrap();
        assert_eq!(fragments.len(), 2);
        assert_eq!(fragments[0].fragment_count, 2);
        let mut defragger = UdpDefragmenter::default();
        assert!(defragger.feed(fragments[1].clone()).is_none());
        let joined = defragger.feed(fragments[0].clone()).unwrap();
        assert_eq!(joined.data, b"abcdefghij");
        assert_eq!(joined.address, "1.2.3.4:53");
    }

    #[test]
    fn salamander_fixed_salt_vector_and_round_trip() {
        let encoded = encode_salamander_with_salt(
            b"password",
            *b"12345678",
            b"hysteria2",
        )
        .unwrap();
        assert_eq!(hex::encode(&encoded), "3132333435363738ad2392f576b1484311");
        assert_eq!(
            decode_salamander(b"password", &encoded).unwrap(),
            b"hysteria2"
        );
    }

    #[test]
    fn rejects_oversized_and_truncated_fields() {
        assert!(encode_tcp_request_with_padding("", b"", b"").is_err());
        assert!(decode_tcp_request(&[0x40]).is_err());
        let mut bad = vec![0_u8; 8];
        bad.push(0x40);
        assert!(UdpMessage::decode(&bad).is_err());
    }

    #[test]
    fn gecko_wire_layout_and_out_of_order_reassembly() {
        let payload = [0x80, 1, 2, 3, 4, 5, 6, 7];
        let frames = encode_gecko_frames_with_padding(
            &payload,
            0x22,
            2,
            &[vec![0xaa], vec![0xbb, 0xcc]],
        )
        .unwrap();
        assert_eq!(hex::encode(&frames[0]), "8022020001aa80010203");
        assert_eq!(hex::encode(&frames[1]), "8022120002bbcc04050607");
        let mut reassembler = GeckoReassembler::default();
        assert!(reassembler.feed("peer", &frames[1]).is_none());
        assert_eq!(reassembler.feed("peer", &frames[0]).unwrap(), payload);

        assert_eq!(
            encode_gecko_frames_with_padding(b"plain", 1, 2, &[]).unwrap(),
            vec![b"plain".to_vec()]
        );
    }

    #[test]
    fn validates_gecko_and_quic_configuration_bounds() {
        assert!(Hysteria2ObfsConfig::gecko(vec![1], 0, 0).is_ok());
        assert!(Hysteria2ObfsConfig::gecko(vec![1], 1200, 1199).is_err());
        assert!(Hysteria2ObfsConfig::gecko(vec![1], 512, 2049).is_err());
        assert!(
            Hysteria2QuicOptions {
                idle_timeout: Some(Duration::from_secs(30)),
                keep_alive_period: Some(Duration::from_secs(10)),
                stream_receive_window: 4 * 1024 * 1024,
                connection_receive_window: 16 * 1024 * 1024,
                max_concurrent_streams: 128,
                initial_packet_size: 1400,
                disable_path_mtu_discovery: true,
            }
            .build()
            .is_ok()
        );
        assert!(
            Hysteria2QuicOptions {
                initial_packet_size: u64::from(u16::MAX) + 1,
                ..Default::default()
            }
            .build()
            .is_err()
        );

        let chrome = Hysteria2ChromeParrotParameters::default();
        assert_eq!(chrome.idle_timeout, Duration::from_secs(30));
        assert_eq!(chrome.stream_receive_window, 6_291_456);
        assert_eq!(chrome.connection_receive_window, 15_728_640);
        assert_eq!(chrome.max_concurrent_bidi_streams, 100);
        assert_eq!(chrome.max_concurrent_uni_streams, 103);
        assert_eq!(chrome.initial_packet_size, 1_250);
        assert_eq!(chrome.max_udp_payload_size, 1_472);
        assert_eq!(chrome.max_datagram_frame_size, 65_536);
        assert_eq!(chrome_initial_destination_connection_id().len(), 8);
        assert_eq!(
            hysteria2_client_endpoint_config(true)
                .unwrap()
                .get_max_udp_payload_size(),
            1_472
        );
        assert!(
            Hysteria2QuicOptions {
                idle_timeout: Some(Duration::from_secs(1)),
                stream_receive_window: u64::MAX,
                connection_receive_window: u64::MAX,
                max_concurrent_streams: u64::MAX,
                initial_packet_size: u64::MAX,
                ..Default::default()
            }
            .build_for_client(true)
            .is_ok(),
            "Chrome parrot must override conflicting user QUIC values"
        );
    }

    #[tokio::test]
    async fn http3_authentication_and_tcp_stream_interoperate() {
        assert_http3_tcp(None, false).await;
    }

    #[tokio::test]
    async fn chrome_parrot_public_quinn_profile_interoperates() {
        assert_http3_tcp(None, true).await;
    }

    #[tokio::test]
    async fn string_masquerade_serves_http3_before_authentication() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_options: InboundTlsOptions = serde_json::from_value(json!({
            "enabled":true,
            "certificate":cert.pem(),
            "key":key_pair.serialize_pem()
        }))
        .unwrap();
        let server_tls =
            build_server_config_with_default_alpn(&server_options, &["h3"])
                .unwrap();
        let endpoint = hysteria2_server_endpoint_with_obfs(
            "127.0.0.1:0".parse().unwrap(),
            server_tls,
            None,
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let users = HashMap::from([("secret".into(), "alice".into())]);
            let mut headers = HeaderMap::new();
            headers.insert("x-cover", HeaderValue::from_static("yes"));
            let masquerade = Hysteria2MasqueradeHandler::String(
                Hysteria2MasqueradeResponse {
                    status: StatusCode::NOT_FOUND,
                    headers,
                    content: Bytes::from_static(b"not found"),
                },
            );
            let session = Hysteria2ServerSession::authenticate_with_masquerade(
                connection,
                &users,
                true,
                0,
                true,
                Some(&masquerade),
            )
            .await
            .unwrap();
            assert_eq!(session.user, "alice");
            tokio::time::sleep(Duration::from_millis(20)).await;
        });

        let client_tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &["h3"],
        )
        .unwrap();
        let crypto = QuicClientConfig::try_from(client_tls.config).unwrap();
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::new(quinn::TransportConfig::default()));
        let mut client_endpoint = hysteria2_endpoint_with_socket(
            "127.0.0.1:0".parse().unwrap(),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        client_endpoint.set_default_client_config(config);
        let connection = client_endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (_http3, mut sender): (H3ClientConnection, H3SendRequest) =
            h3::client::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://cover.example/")
            .body(())
            .unwrap();
        let mut stream = sender.send_request(request).await.unwrap();
        stream.finish().await.unwrap();
        let response = stream.recv_response().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["x-cover"], "yes");
        let mut content = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            content.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        assert_eq!(content, b"not found");

        let request = Request::builder()
            .method(Method::POST)
            .uri("https://hysteria/auth")
            .header(HEADER_AUTH, "secret")
            .header(HEADER_CC_RX, "0")
            .body(())
            .unwrap();
        let mut stream = sender.send_request(request).await.unwrap();
        stream.finish().await.unwrap();
        assert_eq!(
            stream.recv_response().await.unwrap().status().as_u16(),
            STATUS_AUTH_OK
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn proxy_masquerade_forwards_http3_method_body_path_query_and_host() {
        use http_body_util::{BodyExt as _, Full};
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use tokio::net::TcpListener;

        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_address = backend.local_addr().unwrap();
        let (first_body_tx, first_body_rx) = tokio::sync::oneshot::channel();
        let first_body_tx =
            Arc::new(std::sync::Mutex::new(Some(first_body_tx)));
        let backend_task = tokio::spawn(async move {
            let (stream, _) = backend.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(
                        move |request: hyper::Request<
                            hyper::body::Incoming,
                        >| {
                            let first_body_tx = first_body_tx.clone();
                            async move {
                                assert_eq!(request.method(), Method::POST);
                                assert_eq!(
                                    request.uri(),
                                    "/base/hello?fixed=1&from=h3"
                                );
                                assert_eq!(
                                    request.headers()[http::header::HOST],
                                    "cover.example"
                                );
                                assert_eq!(
                                    request.headers()["x-forwarded"],
                                    "yes"
                                );
                                let mut body = request.into_body();
                                let first = body
                                    .frame()
                                    .await
                                    .unwrap()
                                    .unwrap()
                                    .into_data()
                                    .unwrap();
                                let mut content = first.to_vec();
                                first_body_tx
                                    .lock()
                                    .unwrap()
                                    .take()
                                    .unwrap()
                                    .send(())
                                    .unwrap();
                                while let Some(frame) = body.frame().await {
                                    if let Ok(data) = frame.unwrap().into_data()
                                    {
                                        content.extend_from_slice(&data);
                                    }
                                }
                                assert_eq!(content, b"payload");
                                Ok::<_, std::convert::Infallible>(
                                    hyper::Response::builder()
                                        .status(StatusCode::CREATED)
                                        .header("x-backend", "ok")
                                        .body(Full::new(Bytes::from_static(
                                            b"proxied",
                                        )))
                                        .unwrap(),
                                )
                            }
                        },
                    ),
                )
                .await
                .unwrap();
        });

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_options: InboundTlsOptions = serde_json::from_value(json!({
            "enabled":true,
            "certificate":cert.pem(),
            "key":key_pair.serialize_pem()
        }))
        .unwrap();
        let server_tls =
            build_server_config_with_default_alpn(&server_options, &["h3"])
                .unwrap();
        let endpoint = hysteria2_server_endpoint_with_obfs(
            "127.0.0.1:0".parse().unwrap(),
            server_tls,
            None,
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let users = HashMap::from([("secret".into(), "alice".into())]);
            let masquerade = Hysteria2MasqueradeHandler::Proxy {
                url: url::Url::parse(&format!(
                    "http://{backend_address}/base?fixed=1"
                ))
                .unwrap(),
                rewrite_host: false,
                client: reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap(),
            };
            let session = Hysteria2ServerSession::authenticate_with_masquerade(
                connection,
                &users,
                true,
                0,
                true,
                Some(&masquerade),
            )
            .await
            .unwrap();
            assert_eq!(session.user, "alice");
            tokio::time::sleep(Duration::from_millis(20)).await;
        });

        let client_tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &["h3"],
        )
        .unwrap();
        let crypto = QuicClientConfig::try_from(client_tls.config).unwrap();
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::new(quinn::TransportConfig::default()));
        let mut client_endpoint = hysteria2_endpoint_with_socket(
            "127.0.0.1:0".parse().unwrap(),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        client_endpoint.set_default_client_config(config);
        let connection = client_endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (_http3, mut sender): (H3ClientConnection, H3SendRequest) =
            h3::client::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://cover.example/hello?from=h3")
            .header("x-forwarded", "yes")
            .body(())
            .unwrap();
        let mut stream = sender.send_request(request).await.unwrap();
        stream.send_data(Bytes::from_static(b"pay")).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), first_body_rx)
            .await
            .expect("proxy must forward the first request chunk before H3 EOF")
            .unwrap();
        stream.send_data(Bytes::from_static(b"load")).await.unwrap();
        stream.finish().await.unwrap();
        let response = stream.recv_response().await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["x-backend"], "ok");
        let mut content = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            content.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        assert_eq!(content, b"proxied");

        let request = Request::builder()
            .method(Method::POST)
            .uri("https://hysteria/auth")
            .header(HEADER_AUTH, "secret")
            .header(HEADER_CC_RX, "0")
            .body(())
            .unwrap();
        let mut stream = sender.send_request(request).await.unwrap();
        stream.finish().await.unwrap();
        assert_eq!(
            stream.recv_response().await.unwrap().status().as_u16(),
            STATUS_AUTH_OK
        );
        server.await.unwrap();
        backend_task.await.unwrap();
    }

    #[tokio::test]
    async fn file_masquerade_serves_index_and_rejects_traversal() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("index.html"), b"cover").unwrap();
        let handler = Hysteria2MasqueradeHandler::File {
            directory: directory.path().to_owned(),
        };
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://cover.example/")
            .body(())
            .unwrap();
        let response = handler.response(&request, Bytes::new()).await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.headers[CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(response.content, b"cover".as_slice());

        let traversal = Request::builder()
            .method(Method::GET)
            .uri("https://cover.example/%2e%2e/Cargo.toml")
            .body(())
            .unwrap();
        assert_eq!(
            handler
                .response(&traversal, Bytes::new())
                .await
                .unwrap()
                .status,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn salamander_and_gecko_wrap_real_quic_sessions() {
        assert_http3_tcp(
            Some(Hysteria2ObfsConfig::Salamander {
                password: b"cover-secret".to_vec(),
            }),
            false,
        )
        .await;
        assert_http3_tcp(
            Some(Hysteria2ObfsConfig::Gecko {
                password: b"cover-secret".to_vec(),
                min_packet_size: 256,
                max_packet_size: 1350,
            }),
            false,
        )
        .await;
    }

    async fn assert_http3_tcp(
        obfs: Option<Hysteria2ObfsConfig>,
        chrome_parrot: bool,
    ) {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_options: InboundTlsOptions = serde_json::from_value(json!({
            "enabled":true,
            "certificate":cert.pem(),
            "key":key_pair.serialize_pem()
        }))
        .unwrap();
        let server_tls =
            build_server_config_with_default_alpn(&server_options, &["h3"])
                .unwrap();
        let endpoint = hysteria2_server_endpoint_with_obfs(
            "127.0.0.1:0".parse().unwrap(),
            server_tls,
            obfs.clone(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let users = HashMap::from([("secret".into(), "alice".into())]);
            let session = Hysteria2ServerSession::authenticate(
                connection,
                &users,
                true,
                Some(123_456),
            )
            .await
            .unwrap();
            assert_eq!(session.user, "alice");
            assert_eq!(session.client_receive_bps, 654_321);
            assert!(!session.receive_auto);
            let (mut stream, destination) = session.accept_tcp().await.unwrap();
            assert_eq!(destination, "example.com:443");
            let mut early = [0_u8; 4];
            stream.recv.read_exact(&mut early).await.unwrap();
            assert_eq!(&early, b"ping");
            let response =
                encode_tcp_response_with_padding(true, "", b"xy", b"pong")
                    .unwrap();
            stream.send.write_all(&response).await.unwrap();
            stream.send.finish().unwrap();
            let _ = done_rx.await;
        });
        let mut client_tls_options = OutboundTlsOptions {
            enabled: true,
            insecure: true,
            ..Default::default()
        };
        client_tls_options.chrome_quic_parrot = chrome_parrot;
        let client_tls =
            build_client_config("localhost", &client_tls_options, &["h3"])
                .unwrap();
        let transport_options = if chrome_parrot {
            Hysteria2QuicOptions {
                idle_timeout: Some(Duration::from_secs(1)),
                stream_receive_window: 1,
                connection_receive_window: 1,
                max_concurrent_streams: 1,
                initial_packet_size: 1_200,
                ..Default::default()
            }
        } else {
            Hysteria2QuicOptions::default()
        };
        let transport =
            transport_options.build_for_client(chrome_parrot).unwrap();
        let client = Hysteria2ClientSession::connect_with_transport_obfs_profile_and_chrome_parrot(
            address,
            "localhost",
            "secret",
            999_999,
            false,
            654_321,
            client_tls,
            transport,
            obfs,
            crate::protocol::quic_bbr::BbrProfile::Standard,
            chrome_parrot,
        )
        .await
        .unwrap();
        assert_eq!(
            client.auth,
            Hysteria2AuthResponse {
                udp_enabled: true,
                receive_bps: 123_456,
                receive_auto: false,
            }
        );
        assert_eq!(client.negotiated_send_bps, 123_456);
        let mut stream =
            client.open_tcp("example.com:443", b"ping").await.unwrap();
        let response = stream.recv.read_to_end(4096).await.unwrap();
        let (ok, message, payload) = decode_tcp_response(&response).unwrap();
        assert!(ok);
        assert!(message.is_empty());
        assert_eq!(payload, b"pong");
        let _ = done_tx.send(());
        server.await.unwrap();
    }
}
