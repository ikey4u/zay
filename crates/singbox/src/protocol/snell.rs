//! Snell v4/v5 shared wire primitives.
//!
//! No maintained Rust library exposes sing-box's current Snell v4-v6 client
//! and server surface. These primitives therefore follow the pinned
//! `sing-snell` implementation and are kept independent from socket/runtime
//! policy so they can be differential-tested byte for byte.

use std::{
    collections::VecDeque,
    io,
    net::IpAddr,
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead as _, KeyInit as _, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use n0_watcher::Watcher as _;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::Mutex,
};

use crate::{
    adapter::{
        DialFuture, Dialer, PacketConnection, PacketFuture, PacketStream,
        Stream,
    },
    common::network::SocksAddr,
};

pub const HEADER_VERSION: u8 = 0x04;
pub const HEADER_PLAIN_LEN: usize = 7;
pub const AEAD_TAG_LEN: usize = 16;
pub const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + AEAD_TAG_LEN;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const MAX_PAYLOAD_LEN: usize = 0x3fff;
pub const REQUEST_VERSION: u8 = 0x01;

pub const COMMAND_PING: u8 = 0x00;
pub const COMMAND_CONNECT: u8 = 0x01;
pub const COMMAND_CONNECT_V2: u8 = 0x05;
pub const COMMAND_UDP: u8 = 0x06;
pub const UDP_COMMAND_FORWARD: u8 = 0x01;
pub const ADDRESS_TYPE_IPV4: u8 = 0x04;
pub const ADDRESS_TYPE_IPV6: u8 = 0x06;
pub const REPLY_TUNNEL: u8 = 0x00;
pub const REPLY_PONG: u8 = 0x01;
pub const REPLY_ERROR: u8 = 0x02;

pub const DEFAULT_OBFS_HOST: &str = "bing.com";
pub const DEFAULT_OBFS_URI: &str = "/";
pub const DEFAULT_TLS_OBFS_HOST: &str = "cloudfront.net";
const REUSE_POOL_SIZE: usize = 10;
const REUSE_POOL_MAX_AGE: Duration = Duration::from_secs(180);
const REUSE_POOL_TIMER_INTERVAL: Duration = Duration::from_secs(20);
const REUSE_WAITING_DISCARD_LIMIT: usize = 0x80001;
const V4_FRAME_SIZE: usize = 1460;
const V4_FIRST_RECORD_OVERHEAD: usize = 55;
const V4_RESET_RECORD_OVERHEAD: usize = 39;
const V4_PAYLOAD_RESET_INTERVAL: u64 = 31;

const TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN: usize = 0x400;
const TLS_OBFS_RECORD_PAYLOAD_LEN: usize = 0x4000;
const TLS_OBFS_CLIENT_RECORD_OVERHEAD: usize = 0xd4;
const TLS_OBFS_CLIENT_HANDSHAKE_OVERHEAD: usize = 0xd0;
const TLS_OBFS_CLIENT_EXTENSIONS_OVERHEAD: usize = 0x4f;
const TLS_OBFS_CLIENT_PAYLOAD_OFFSET: usize = 0x8e;
const TLS_OBFS_SERVER_PAYLOAD_OFFSET: usize = 0x6b;
const TLS_OBFS_CLIENT_NAME_HEADER_LEN: usize = 9;
const TLS_OBFS_CLIENT_TRAILER_LEN: usize = 0x42;

const SALT_REPLAY_GENERATION_SIZE: usize = 500_000;
const SALT_REPLAY_FALSE_POSITIVE_RATE: f64 = 1e-10;
const MURMUR_DEFAULT_SEED: u32 = 0x9747_b28c;

#[derive(Default)]
pub struct SaltReplayCache {
    state: StdMutex<SaltReplayState>,
}

#[derive(Default)]
struct SaltReplayState {
    current: usize,
    counts: [usize; 2],
    filters: [SaltReplayBloom; 2],
}

#[derive(Default)]
struct SaltReplayBloom {
    bits: Vec<u8>,
    bit_count: u32,
    hash_count: usize,
}

impl SaltReplayBloom {
    fn initialize(&mut self) {
        let bits_per_entry = -SALT_REPLAY_FALSE_POSITIVE_RATE.ln()
            / (std::f64::consts::LN_2 * std::f64::consts::LN_2);
        self.bit_count =
            (SALT_REPLAY_GENERATION_SIZE as f64 * bits_per_entry) as u32;
        self.hash_count =
            (bits_per_entry * std::f64::consts::LN_2).ceil() as usize;
        self.bits = vec![0; self.bit_count.div_ceil(8) as usize];
    }

    fn contains(&self, data: &[u8]) -> bool {
        let first = murmur_hash(data, MURMUR_DEFAULT_SEED);
        let step = murmur_hash(data, first);
        let mut value = first;
        for _ in 0..self.hash_count {
            let index = value % self.bit_count;
            if self.bits[(index >> 3) as usize] & (1 << (index & 7)) == 0 {
                return false;
            }
            value = value.wrapping_add(step);
        }
        true
    }

    fn add(&mut self, data: &[u8]) {
        let first = murmur_hash(data, MURMUR_DEFAULT_SEED);
        let step = murmur_hash(data, first);
        let mut value = first;
        for _ in 0..self.hash_count {
            let index = value % self.bit_count;
            self.bits[(index >> 3) as usize] |= 1 << (index & 7);
            value = value.wrapping_add(step);
        }
    }
}

impl SaltReplayCache {
    pub fn check_and_add(&self, salt: &[u8]) -> bool {
        let mut state = self.state.lock().expect("Snell replay cache poisoned");
        if state.filters[0].bits.is_empty() {
            state.filters[0].initialize();
            state.filters[1].initialize();
        }
        if state.filters.iter().any(|filter| filter.contains(salt)) {
            return true;
        }
        let current = state.current;
        state.filters[current].add(salt);
        state.counts[current] += 1;
        if state.counts[current] >= SALT_REPLAY_GENERATION_SIZE {
            state.counts[current] = 0;
            state.current ^= 1;
            let current = state.current;
            state.filters[current].bits.fill(0);
        }
        false
    }
}

fn murmur_hash(mut data: &[u8], seed: u32) -> u32 {
    let mut hash = seed ^ data.len() as u32;
    while data.len() >= 4 {
        let mut chunk = u32::from_le_bytes(data[..4].try_into().unwrap());
        chunk = chunk.wrapping_mul(0x5bd1_e995);
        chunk ^= chunk >> 24;
        chunk = chunk.wrapping_mul(0x5bd1_e995);
        hash = hash.wrapping_mul(0x5bd1_e995) ^ chunk;
        data = &data[4..];
    }
    match data.len() {
        3 => {
            hash ^= u32::from(data[2]) << 16;
            hash ^= u32::from(data[1]) << 8;
            hash ^= u32::from(data[0]);
            hash = hash.wrapping_mul(0x5bd1_e995);
        }
        2 => {
            hash ^= u32::from(data[1]) << 8;
            hash ^= u32::from(data[0]);
            hash = hash.wrapping_mul(0x5bd1_e995);
        }
        1 => {
            hash ^= u32::from(data[0]);
            hash = hash.wrapping_mul(0x5bd1_e995);
        }
        _ => {}
    }
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0x5bd1_e995);
    hash ^ (hash >> 15)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfsMode {
    None,
    Http,
    Tls,
}

impl ObfsMode {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "" | "none" => Ok(Self::None),
            "http" => Ok(Self::Http),
            "tls" => Ok(Self::Tls),
            _ => {
                Err(invalid_input(format!("snell: unknown obfs mode: {value}")))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: u8,
    pub client_id: Vec<u8>,
    pub destination: Option<SocksAddr>,
}

pub fn derive_key(psk: &[u8], salt: &[u8]) -> io::Result<[u8; 16]> {
    if psk.is_empty() {
        return Err(invalid_input("snell: missing pre-shared key"));
    }
    if salt.len() != SALT_LEN {
        return Err(invalid_input("snell: invalid salt length"));
    }
    let params = Params::new(8, 3, 1, Some(32)).map_err(|error| {
        invalid_input(format!("snell Argon2 params: {error}"))
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut expanded = [0_u8; 32];
    argon2
        .hash_password_into(psk, salt, &mut expanded)
        .map_err(|error| invalid_input(format!("snell Argon2 key: {error}")))?;
    Ok(expanded[..16].try_into().expect("fixed key length"))
}

pub fn encode_request(request: &Request) -> io::Result<Vec<u8>> {
    let client_len = u8::try_from(request.client_id.len())
        .map_err(|_| invalid_input("snell: client id too long"))?;
    let mut output = vec![REQUEST_VERSION, request.command, client_len];
    output.extend_from_slice(&request.client_id);
    match request.command {
        COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
            let destination =
                request.destination.as_ref().ok_or_else(|| {
                    invalid_input("snell: connect destination is missing")
                })?;
            encode_connect_address(destination, &mut output)?;
        }
        COMMAND_PING | COMMAND_UDP => {}
        command => {
            return Err(invalid_input(format!(
                "snell: unsupported command: {command}"
            )));
        }
    }
    Ok(output)
}

pub fn decode_request(input: &[u8]) -> io::Result<(Request, usize)> {
    let version = *input
        .first()
        .ok_or_else(|| invalid_data("snell: truncated request"))?;
    if version != REQUEST_VERSION {
        return Err(invalid_data(format!(
            "snell: bad request version: {version}"
        )));
    }
    let command = *input
        .get(1)
        .ok_or_else(|| invalid_data("snell: truncated request command"))?;
    let client_len = usize::from(
        *input
            .get(2)
            .ok_or_else(|| invalid_data("snell: truncated client id"))?,
    );
    if command == COMMAND_PING {
        return Ok((
            Request {
                command,
                client_id: Vec::new(),
                destination: None,
            },
            3,
        ));
    }
    let client_end = 3_usize
        .checked_add(client_len)
        .filter(|end| *end <= input.len())
        .ok_or_else(|| invalid_data("snell: truncated client id"))?;
    let client_id = input[3..client_end].to_vec();
    let (destination, consumed) = match command {
        COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
            let (destination, length) =
                decode_connect_address(&input[client_end..])?;
            (Some(destination), client_end + length)
        }
        COMMAND_UDP => (None, client_end),
        command => {
            return Err(invalid_data(format!(
                "snell: unsupported command: {command}"
            )));
        }
    };
    Ok((
        Request {
            command,
            client_id,
            destination,
        },
        consumed,
    ))
}

pub fn encode_connect_address(
    destination: &SocksAddr,
    output: &mut Vec<u8>,
) -> io::Result<()> {
    let host = destination.host();
    let host_len = u8::try_from(host.len())
        .map_err(|_| invalid_input("snell: host too long"))?;
    output.push(host_len);
    output.extend_from_slice(host.as_bytes());
    output.extend_from_slice(&destination.port().to_be_bytes());
    Ok(())
}

pub fn decode_connect_address(input: &[u8]) -> io::Result<(SocksAddr, usize)> {
    let host_len = usize::from(
        *input
            .first()
            .ok_or_else(|| invalid_data("snell: truncated host length"))?,
    );
    let port_offset = 1_usize
        .checked_add(host_len)
        .filter(|offset| offset + 2 <= input.len())
        .ok_or_else(|| invalid_data("snell: truncated connect address"))?;
    let host = std::str::from_utf8(&input[1..port_offset])
        .map_err(|_| invalid_data("snell: host is not UTF-8"))?;
    let port = u16::from_be_bytes([input[port_offset], input[port_offset + 1]]);
    Ok((SocksAddr::new(host, port), port_offset + 2))
}

pub fn encode_udp_request_address(
    destination: &SocksAddr,
    output: &mut Vec<u8>,
) -> io::Result<()> {
    match destination {
        SocksAddr::Ip(address) => {
            output.push(0);
            match address.ip() {
                IpAddr::V4(ip) => {
                    output.push(ADDRESS_TYPE_IPV4);
                    output.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    output.push(ADDRESS_TYPE_IPV6);
                    output.extend_from_slice(&ip.octets());
                }
            }
        }
        SocksAddr::Domain { host, .. } => {
            let length = u8::try_from(host.len())
                .map_err(|_| invalid_input("snell: invalid udp host"))?;
            if length == 0 {
                return Err(invalid_input("snell: invalid udp host"));
            }
            output.push(length);
            output.extend_from_slice(host.as_bytes());
        }
    }
    output.extend_from_slice(&destination.port().to_be_bytes());
    Ok(())
}

pub fn decode_udp_request_address(
    input: &[u8],
) -> io::Result<(SocksAddr, usize)> {
    let first = *input
        .first()
        .ok_or_else(|| invalid_data("snell: truncated udp address"))?;
    if first != 0 {
        let host_len = usize::from(first);
        let port_offset = 1_usize
            .checked_add(host_len)
            .filter(|offset| offset + 2 <= input.len())
            .ok_or_else(|| invalid_data("snell: truncated udp domain"))?;
        let host = std::str::from_utf8(&input[1..port_offset])
            .map_err(|_| invalid_data("snell: udp host is not UTF-8"))?;
        let port =
            u16::from_be_bytes([input[port_offset], input[port_offset + 1]]);
        return Ok((SocksAddr::new(host, port), port_offset + 2));
    }
    decode_ip_address(&input[1..])
        .map(|(address, length)| (address, length + 1))
}

pub fn encode_udp_response_address(
    source: &SocksAddr,
    output: &mut Vec<u8>,
) -> io::Result<()> {
    let SocksAddr::Ip(source) = source else {
        return Err(invalid_input("snell: udp response source is not an ip"));
    };
    match source.ip() {
        IpAddr::V4(ip) => {
            output.push(ADDRESS_TYPE_IPV4);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(ADDRESS_TYPE_IPV6);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&source.port().to_be_bytes());
    Ok(())
}

pub fn decode_udp_response_address(
    input: &[u8],
) -> io::Result<(SocksAddr, usize)> {
    decode_ip_address(input)
}

fn decode_ip_address(input: &[u8]) -> io::Result<(SocksAddr, usize)> {
    match input.first().copied() {
        Some(ADDRESS_TYPE_IPV4) if input.len() >= 7 => {
            let ip = [input[1], input[2], input[3], input[4]];
            let port = u16::from_be_bytes([input[5], input[6]]);
            Ok((SocksAddr::new(IpAddr::from(ip).to_string(), port), 7))
        }
        Some(ADDRESS_TYPE_IPV6) if input.len() >= 19 => {
            let ip: [u8; 16] = input[1..17].try_into().unwrap();
            let port = u16::from_be_bytes([input[17], input[18]]);
            Ok((SocksAddr::new(IpAddr::from(ip).to_string(), port), 19))
        }
        Some(ADDRESS_TYPE_IPV4) | Some(ADDRESS_TYPE_IPV6) => {
            Err(invalid_data("snell: truncated udp ip address"))
        }
        Some(address_type) => Err(invalid_data(format!(
            "snell: unknown udp address type: {address_type}"
        ))),
        None => Err(invalid_data("snell: truncated udp address")),
    }
}

/// Stateful v4/v5 record encoder. Callers choose padding bytes explicitly;
/// production wrappers can generate Surge-compatible padding while tests can
/// inject deterministic vectors.
pub struct RecordEncoder {
    cipher: Aes128Gcm,
    nonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    payload_limit: usize,
    last_write_unix: u64,
}

impl RecordEncoder {
    pub fn new(psk: &[u8], salt: [u8; SALT_LEN]) -> io::Result<Self> {
        let key = derive_key(psk, &salt)?;
        let cipher = Aes128Gcm::new_from_slice(&key)
            .map_err(|_| invalid_input("snell: invalid AES key"))?;
        Ok(Self {
            cipher,
            nonce: [0; NONCE_LEN],
            salt,
            salt_sent: false,
            payload_limit: 0,
            last_write_unix: 0,
        })
    }

    pub fn random(psk: &[u8]) -> io::Result<Self> {
        let mut salt = [0_u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|error| {
            io::Error::other(format!("snell: generate salt: {error}"))
        })?;
        Self::new(psk, salt)
    }

    pub fn encode_record(
        &mut self,
        payload: &[u8],
        padding: &[u8],
    ) -> io::Result<Vec<u8>> {
        if payload.len() > MAX_PAYLOAD_LEN || padding.len() > MAX_PAYLOAD_LEN {
            return Err(invalid_input("snell: record exceeds maximum"));
        }
        if payload.is_empty() && !padding.is_empty() {
            return Err(invalid_input(
                "snell: zero-length record carries padding",
            ));
        }
        let mut header = [0_u8; HEADER_PLAIN_LEN];
        header[0] = HEADER_VERSION;
        header[3..5].copy_from_slice(&(padding.len() as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let header_cipher = self.seal(&header)?;

        let mut output = Vec::with_capacity(
            usize::from(!self.salt_sent) * SALT_LEN
                + HEADER_CIPHER_LEN
                + padding.len()
                + payload.len()
                + usize::from(!payload.is_empty()) * AEAD_TAG_LEN,
        );
        if !self.salt_sent {
            output.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
        output.extend_from_slice(&header_cipher);
        let padding_start = output.len();
        output.extend_from_slice(padding);
        if !payload.is_empty() {
            let mut payload_cipher = self.seal(payload)?;
            let swap_count = padding.len().min(payload_cipher.len());
            for index in (0..swap_count).step_by(2) {
                std::mem::swap(
                    &mut output[padding_start + index],
                    &mut payload_cipher[index],
                );
            }
            output.extend_from_slice(&payload_cipher);
        }
        Ok(output)
    }

    fn begin_stream_write(&mut self, initial_padding_len: usize) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let reset_limit = V4_FRAME_SIZE - V4_RESET_RECORD_OVERHEAD;
        let limit = if !self.salt_sent {
            V4_FRAME_SIZE
                .saturating_sub(V4_FIRST_RECORD_OVERHEAD)
                .saturating_sub(initial_padding_len)
        } else if self.last_write_unix != 0
            && now.saturating_sub(self.last_write_unix)
                < V4_PAYLOAD_RESET_INTERVAL
            && self.payload_limit > 0
        {
            self.payload_limit
        } else {
            reset_limit
        };
        self.last_write_unix = now;
        self.payload_limit =
            limit.saturating_add(reset_limit).min(MAX_PAYLOAD_LEN);
        limit.clamp(1, MAX_PAYLOAD_LEN)
    }

    fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let result = self
            .cipher
            .encrypt(
                (&self.nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| invalid_data("snell: AES-GCM encryption failed"))?;
        increase_nonce(&mut self.nonce);
        Ok(result)
    }
}

async fn write_v4_stream_payload<W>(
    writer: &mut W,
    encoder: &mut RecordEncoder,
    payload: &[u8],
) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    if payload.is_empty() {
        return writer.write_all(&encoder.encode_record(&[], &[])?).await;
    }
    let initial_padding = if encoder.salt_sent {
        Vec::new()
    } else {
        random_initial_padding()?
    };
    let limit = encoder.begin_stream_write(initial_padding.len());
    for (index, chunk) in payload.chunks(limit).enumerate() {
        let padding = if index == 0 {
            initial_padding.as_slice()
        } else {
            &[]
        };
        writer
            .write_all(&encoder.encode_record(chunk, padding)?)
            .await?;
    }
    Ok(())
}

pub struct RecordDecoder {
    psk: Vec<u8>,
    cipher: Option<Aes128Gcm>,
    nonce: [u8; NONCE_LEN],
    salt: Option<[u8; SALT_LEN]>,
}

impl RecordDecoder {
    pub fn new(psk: impl Into<Vec<u8>>) -> Self {
        Self {
            psk: psk.into(),
            cipher: None,
            nonce: [0; NONCE_LEN],
            salt: None,
        }
    }

    pub fn decode_record(
        &mut self,
        input: &[u8],
    ) -> io::Result<(Vec<u8>, usize)> {
        let mut offset = 0;
        if self.cipher.is_none() {
            let salt: [u8; SALT_LEN] = input
                .get(..SALT_LEN)
                .ok_or_else(|| invalid_data("snell: truncated record salt"))?
                .try_into()
                .unwrap();
            self.initialize(&salt)?;
            offset += SALT_LEN;
        }
        let header_end = offset + HEADER_CIPHER_LEN;
        let header_cipher = input
            .get(offset..header_end)
            .ok_or_else(|| invalid_data("snell: truncated record header"))?;
        let header = self.open(header_cipher, "record header")?;
        if header.len() != HEADER_PLAIN_LEN || header[0] != HEADER_VERSION {
            return Err(invalid_data("snell: bad header version"));
        }
        let padding_len =
            usize::from(u16::from_be_bytes([header[3], header[4]]));
        let payload_len =
            usize::from(u16::from_be_bytes([header[5], header[6]]));
        if padding_len > MAX_PAYLOAD_LEN || payload_len > MAX_PAYLOAD_LEN {
            return Err(invalid_data("snell: payload length exceeds maximum"));
        }
        offset = header_end;
        if payload_len == 0 {
            return Ok((Vec::new(), offset));
        }
        let body_end = offset
            .checked_add(padding_len + payload_len + AEAD_TAG_LEN)
            .filter(|end| *end <= input.len())
            .ok_or_else(|| invalid_data("snell: truncated record payload"))?;
        let mut padding = input[offset..offset + padding_len].to_vec();
        let mut payload_cipher = input[offset + padding_len..body_end].to_vec();
        let swap_count = padding.len().min(payload_cipher.len());
        for index in (0..swap_count).step_by(2) {
            std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
        }
        let payload = self.open(&payload_cipher, "record payload")?;
        if payload.len() != payload_len {
            return Err(invalid_data("snell: invalid record payload length"));
        }
        Ok((payload, body_end))
    }

    pub async fn read_record<R>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<Vec<u8>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        if self.cipher.is_none() {
            let mut salt = [0_u8; SALT_LEN];
            reader.read_exact(&mut salt).await?;
            self.initialize(&salt)?;
        }
        let mut header_cipher = [0_u8; HEADER_CIPHER_LEN];
        reader.read_exact(&mut header_cipher).await?;
        let header = self.open(&header_cipher, "record header")?;
        if header.len() != HEADER_PLAIN_LEN || header[0] != HEADER_VERSION {
            return Err(invalid_data("snell: bad header version"));
        }
        let padding_len =
            usize::from(u16::from_be_bytes([header[3], header[4]]));
        let payload_len =
            usize::from(u16::from_be_bytes([header[5], header[6]]));
        if padding_len > MAX_PAYLOAD_LEN || payload_len > MAX_PAYLOAD_LEN {
            return Err(invalid_data("snell: payload length exceeds maximum"));
        }
        if payload_len == 0 {
            return Ok(Vec::new());
        }
        let mut padding = vec![0_u8; padding_len];
        reader.read_exact(&mut padding).await?;
        let mut payload_cipher = vec![0_u8; payload_len + AEAD_TAG_LEN];
        reader.read_exact(&mut payload_cipher).await?;
        let swap_count = padding.len().min(payload_cipher.len());
        for index in (0..swap_count).step_by(2) {
            std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
        }
        let payload = self.open(&payload_cipher, "record payload")?;
        if payload.len() != payload_len {
            return Err(invalid_data("snell: invalid record payload length"));
        }
        Ok(payload)
    }

    fn initialize(&mut self, salt: &[u8; SALT_LEN]) -> io::Result<()> {
        let key = derive_key(&self.psk, salt)?;
        self.cipher = Some(
            Aes128Gcm::new_from_slice(&key)
                .map_err(|_| invalid_input("snell: invalid AES key"))?,
        );
        self.salt = Some(*salt);
        Ok(())
    }

    pub fn salt(&self) -> Option<[u8; SALT_LEN]> {
        self.salt
    }

    fn open(&mut self, ciphertext: &[u8], field: &str) -> io::Result<Vec<u8>> {
        let cipher = self.cipher.as_ref().expect("record decoder initialized");
        let result = cipher
            .decrypt(
                (&self.nonce).into(),
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| invalid_data(format!("snell: open {field}")))?;
        increase_nonce(&mut self.nonce);
        Ok(result)
    }
}

fn http_client_fingerprint() -> &'static (String, String) {
    static FINGERPRINT: OnceLock<(String, String)> = OnceLock::new();
    FINGERPRINT.get_or_init(|| {
        let mut key = [0_u8; 16];
        getrandom::fill(&mut key).expect("operating system randomness");
        let os_minor = 9 + usize::from(random_byte().unwrap_or_default() % 6);
        let firefox =
            22 + usize::from(random_byte().unwrap_or_default() % 43);
        (
            format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.{os_minor}; rv:64.0) Gecko/20100101 Firefox/{firefox}.0"
            ),
            STANDARD.encode(key),
        )
    })
}

fn http_server_response() -> &'static [u8] {
    static RESPONSE: OnceLock<Vec<u8>> = OnceLock::new();
    RESPONSE.get_or_init(|| {
        let mut accept = [0_u8; 16];
        getrandom::fill(&mut accept).expect("operating system randomness");
        let major = random_byte().unwrap_or_default() % 14;
        let minor = random_byte().unwrap_or_default() % 12;
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.{major}.{minor}\r\nDate: Thu, 01 Jan 1970 00:00:00 GMT\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            STANDARD.encode(accept)
        )
        .into_bytes()
    })
}

fn spawn_http_obfs(raw: Stream, client: bool, host: String) -> Stream {
    let (application, bridge) = tokio::io::duplex(64 * 1024);
    let (mut application_reader, mut application_writer) =
        tokio::io::split(bridge);
    let (mut raw_reader, mut raw_writer) = tokio::io::split(raw);

    tokio::spawn(async move {
        let mut matched = 0_usize;
        const TERMINATOR: &[u8] = b"\r\n\r\n";
        while matched < TERMINATOR.len() {
            let value = match raw_reader.read_u8().await {
                Ok(value) => value,
                Err(_) => return,
            };
            matched = if value == TERMINATOR[matched] {
                matched + 1
            } else if value == TERMINATOR[0] {
                1
            } else {
                0
            };
        }
        let _ = tokio::io::copy(&mut raw_reader, &mut application_writer).await;
        let _ = application_writer.shutdown().await;
    });

    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 64 * 1024];
        let first_size = match application_reader.read(&mut buffer).await {
            Ok(size) => size,
            Err(_) => return,
        };
        if first_size == 0 {
            let _ = raw_writer.shutdown().await;
            return;
        }
        if client {
            let (user_agent, key) = http_client_fingerprint();
            let host = if host.is_empty() {
                DEFAULT_OBFS_HOST
            } else {
                &host
            };
            let request = format!(
                "GET {DEFAULT_OBFS_URI} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: {first_size}\r\nSec-WebSocket-Key: {key}\r\n\r\n"
            );
            if raw_writer.write_all(request.as_bytes()).await.is_err() {
                return;
            }
        } else if raw_writer.write_all(http_server_response()).await.is_err() {
            return;
        }
        if raw_writer.write_all(&buffer[..first_size]).await.is_err() {
            return;
        }
        let _ = tokio::io::copy(&mut application_reader, &mut raw_writer).await;
        let _ = raw_writer.shutdown().await;
    });
    Box::new(application)
}

fn append_be_u16(output: &mut Vec<u8>, value: usize) {
    output.extend_from_slice(&(value as u16).to_be_bytes());
}

fn append_tls_records(output: &mut Vec<u8>, mut payload: &[u8]) {
    while !payload.is_empty() {
        let size = payload.len().min(TLS_OBFS_RECORD_PAYLOAD_LEN);
        output.extend_from_slice(&[0x17, 0x03, 0x03]);
        append_be_u16(output, size);
        output.extend_from_slice(&payload[..size]);
        payload = &payload[size..];
    }
}

fn build_tls_client_hello(host: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    if host.len() > u16::MAX as usize {
        return Err(invalid_input("snell: TLS obfs host is too long"));
    }
    let first_size = payload.len().min(TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN);
    let first = &payload[..first_size];
    let mut random = [0_u8; 28];
    let mut session_id = [0_u8; 32];
    getrandom::fill(&mut random)
        .map_err(|error| io::Error::other(error.to_string()))?;
    getrandom::fill(&mut session_id)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let unix_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;

    let mut output = Vec::with_capacity(0xd9 + host.len() + payload.len());
    output.extend_from_slice(&[0x16, 0x03, 0x01]);
    append_be_u16(
        &mut output,
        TLS_OBFS_CLIENT_RECORD_OVERHEAD + host.len() + first_size,
    );
    output.extend_from_slice(&[0x01, 0x00]);
    append_be_u16(
        &mut output,
        TLS_OBFS_CLIENT_HANDSHAKE_OVERHEAD + host.len() + first_size,
    );
    output.extend_from_slice(&[0x03, 0x03]);
    output.extend_from_slice(&unix_time.to_be_bytes());
    output.extend_from_slice(&random);
    output.push(0x20);
    output.extend_from_slice(&session_id);
    append_be_u16(&mut output, 0x38);
    output.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa,
        0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b,
        0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39,
        0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
        0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);
    output.extend_from_slice(&[0x01, 0x00]);
    append_be_u16(
        &mut output,
        TLS_OBFS_CLIENT_EXTENSIONS_OVERHEAD + host.len() + first_size,
    );
    append_be_u16(&mut output, 0x23);
    append_be_u16(&mut output, first_size);
    output.extend_from_slice(first);
    append_be_u16(&mut output, 0);
    append_be_u16(&mut output, host.len() + 5);
    append_be_u16(&mut output, host.len() + 3);
    output.push(0);
    append_be_u16(&mut output, host.len());
    output.extend_from_slice(host.as_bytes());
    output.extend_from_slice(&[
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x0a,
        0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18, 0x00, 0x0d,
        0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01,
        0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
        0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x16,
        0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
    ]);
    append_tls_records(&mut output, &payload[first_size..]);
    Ok(output)
}

fn build_tls_server_hello(payload: &[u8]) -> io::Result<Vec<u8>> {
    let first_size = payload.len().min(TLS_OBFS_RECORD_PAYLOAD_LEN);
    let mut random = [0_u8; 28];
    let mut session_id = [0_u8; 32];
    getrandom::fill(&mut random)
        .map_err(|error| io::Error::other(error.to_string()))?;
    getrandom::fill(&mut session_id)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let unix_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let mut output =
        Vec::with_capacity(TLS_OBFS_SERVER_PAYLOAD_OFFSET + payload.len() + 5);
    output.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 91]);
    output.extend_from_slice(&[0x02, 0x00, 0x00, 0x57, 0x03, 0x03]);
    output.extend_from_slice(&unix_time.to_be_bytes());
    output.extend_from_slice(&random);
    output.push(0x20);
    output.extend_from_slice(&session_id);
    output.extend_from_slice(&[
        0xcc, 0xa8, 0x00, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x17,
        0x00, 0x00, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x14, 0x03, 0x03, 0x00,
        0x01, 0x01, 0x16, 0x03, 0x03,
    ]);
    append_be_u16(&mut output, first_size);
    output.extend_from_slice(&payload[..first_size]);
    append_tls_records(&mut output, &payload[first_size..]);
    Ok(output)
}

async fn copy_tls_records<R, W>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        let mut header = [0_u8; 5];
        reader.read_exact(&mut header).await?;
        let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if size == 0 {
            continue;
        }
        let mut payload = vec![0_u8; size];
        reader.read_exact(&mut payload).await?;
        writer.write_all(&payload).await?;
    }
}

fn spawn_tls_obfs(raw: Stream, client: bool, host: String) -> Stream {
    let (application, bridge) = tokio::io::duplex(64 * 1024);
    let (mut application_reader, mut application_writer) =
        tokio::io::split(bridge);
    let (mut raw_reader, mut raw_writer) = tokio::io::split(raw);

    tokio::spawn(async move {
        let result = async {
            let offset = if client {
                TLS_OBFS_SERVER_PAYLOAD_OFFSET
            } else {
                TLS_OBFS_CLIENT_PAYLOAD_OFFSET
            };
            let mut prefix = vec![0_u8; offset];
            raw_reader.read_exact(&mut prefix).await?;
            let size = usize::from(u16::from_be_bytes([
                prefix[offset - 2],
                prefix[offset - 1],
            ]));
            if size > 0 {
                let mut payload = vec![0_u8; size];
                raw_reader.read_exact(&mut payload).await?;
                application_writer.write_all(&payload).await?;
            }
            if !client {
                let mut name_prefix =
                    vec![0_u8; TLS_OBFS_CLIENT_NAME_HEADER_LEN];
                raw_reader.read_exact(&mut name_prefix).await?;
                let name_len = usize::from(u16::from_be_bytes([
                    name_prefix[TLS_OBFS_CLIENT_NAME_HEADER_LEN - 2],
                    name_prefix[TLS_OBFS_CLIENT_NAME_HEADER_LEN - 1],
                ]));
                let mut trailer =
                    vec![0_u8; name_len + TLS_OBFS_CLIENT_TRAILER_LEN];
                raw_reader.read_exact(&mut trailer).await?;
            }
            copy_tls_records(&mut raw_reader, &mut application_writer).await
        }
        .await;
        let _ = result;
        let _ = application_writer.shutdown().await;
    });

    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 64 * 1024];
        let first_size = match application_reader.read(&mut buffer).await {
            Ok(size) => size,
            Err(_) => return,
        };
        if first_size == 0 {
            let _ = raw_writer.shutdown().await;
            return;
        }
        let first = if client {
            let host = if host.is_empty() {
                DEFAULT_TLS_OBFS_HOST
            } else {
                &host
            };
            build_tls_client_hello(host, &buffer[..first_size])
        } else {
            build_tls_server_hello(&buffer[..first_size])
        };
        let Ok(first) = first else {
            return;
        };
        if raw_writer.write_all(&first).await.is_err() {
            return;
        }
        loop {
            let size = match application_reader.read(&mut buffer).await {
                Ok(size) => size,
                Err(_) => return,
            };
            if size == 0 {
                let _ = raw_writer.shutdown().await;
                return;
            }
            let mut framed = Vec::with_capacity(size + 5);
            append_tls_records(&mut framed, &buffer[..size]);
            if raw_writer.write_all(&framed).await.is_err() {
                return;
            }
        }
    });
    Box::new(application)
}

pub fn wrap_obfs_client(
    raw: Stream,
    mode: ObfsMode,
    host: impl Into<String>,
) -> io::Result<Stream> {
    match mode {
        ObfsMode::None => Ok(raw),
        ObfsMode::Http => Ok(spawn_http_obfs(raw, true, host.into())),
        ObfsMode::Tls => Ok(spawn_tls_obfs(raw, true, host.into())),
    }
}

/// The SIP003 `obfs-local` TLS mode uses the configured host verbatim, while
/// Snell substitutes its own default camouflage host when empty.
pub fn wrap_simple_tls_obfs_client(
    raw: Stream,
    host: impl Into<String>,
) -> io::Result<Stream> {
    Ok(spawn_tls_obfs(raw, true, host.into()))
}

pub fn wrap_obfs_server(raw: Stream, mode: ObfsMode) -> io::Result<Stream> {
    match mode {
        ObfsMode::None => Ok(raw),
        ObfsMode::Http => Ok(spawn_http_obfs(raw, false, String::new())),
        ObfsMode::Tls => Ok(spawn_tls_obfs(raw, false, String::new())),
    }
}

/// Write a v4 client request and return a plaintext stream carried by Snell
/// records. The initial request record uses Surge's 256–511 byte padding
/// interval.
pub async fn connect_v4(
    mut raw: Stream,
    psk: &[u8],
    user_key: &[u8],
    destination: SocksAddr,
) -> io::Result<Stream> {
    if user_key.len() > u8::MAX as usize {
        return Err(invalid_input("snell: user key too long"));
    }
    let request = encode_request(&Request {
        command: COMMAND_CONNECT_V2,
        client_id: user_key.to_vec(),
        destination: Some(destination),
    })?;
    let mut encoder = RecordEncoder::random(psk)?;
    write_v4_stream_payload(&mut raw, &mut encoder, &request).await?;
    Ok(spawn_record_bridge(
        raw,
        RecordDecoder::new(psk.to_vec()),
        encoder,
        Vec::new(),
        Vec::new(),
        true,
    ))
}

pub async fn connect_v4_udp(
    mut raw: Stream,
    psk: &[u8],
    user_key: &[u8],
) -> io::Result<PacketStream> {
    if user_key.len() > u8::MAX as usize {
        return Err(invalid_input("snell: user key too long"));
    }
    let request = encode_request(&Request {
        command: COMMAND_UDP,
        client_id: user_key.to_vec(),
        destination: None,
    })?;
    let mut encoder = RecordEncoder::random(psk)?;
    write_v4_stream_payload(&mut raw, &mut encoder, &request).await?;
    let mut decoder = RecordDecoder::new(psk.to_vec());
    let reply = decoder.read_record(&mut raw).await?;
    if reply.first().copied() != Some(REPLY_TUNNEL) {
        return Err(invalid_data("snell: unexpected UDP reply"));
    }
    Ok(packet_connection(raw, decoder, encoder, PacketRole::Client))
}

/// Accept one v4/v5 request record and return the decoded request plus a
/// plaintext stream. Bytes coalesced after the request are replayed first.
pub async fn accept_v5(
    raw: Stream,
    psk: &[u8],
) -> io::Result<(Stream, Request)> {
    match accept_v5_connection(raw, psk).await? {
        AcceptedV5::Tcp { stream, request } => Ok((stream, request)),
        AcceptedV5::Udp { .. } => {
            Err(invalid_data("snell: expected TCP request, received UDP"))
        }
        AcceptedV5::Pong => {
            Err(invalid_data("snell: expected TCP request, received ping"))
        }
    }
}

pub enum AcceptedV5 {
    Tcp {
        stream: Stream,
        request: Request,
    },
    Udp {
        packets: PacketStream,
        request: Request,
    },
    Pong,
}

pub struct V5ServerSession {
    reader: ReadHalf<Stream>,
    writer: WriteHalf<Stream>,
    decoder: RecordDecoder,
    encoder: RecordEncoder,
}

pub async fn accept_v5_server_session(
    mut raw: Stream,
    psk: &[u8],
    replay_cache: Option<&SaltReplayCache>,
) -> io::Result<(V5ServerSession, Request, Vec<u8>)> {
    let mut decoder = RecordDecoder::new(psk.to_vec());
    let first = decoder.read_record(&mut raw).await?;
    if let (Some(cache), Some(salt)) = (replay_cache, decoder.salt())
        && cache.check_and_add(&salt)
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "snell: duplicated salt",
        ));
    }
    let (request, consumed) = decode_request(&first)?;
    let early_payload = first[consumed..].to_vec();
    let (reader, writer) = tokio::io::split(raw);
    Ok((
        V5ServerSession {
            reader,
            writer,
            decoder,
            encoder: RecordEncoder::random(psk)?,
        },
        request,
        early_payload,
    ))
}

impl V5ServerSession {
    async fn write_record(&mut self, payload: &[u8]) -> io::Result<()> {
        write_v4_stream_payload(&mut self.writer, &mut self.encoder, payload)
            .await
    }

    pub async fn bridge_logical(
        &mut self,
        bridge: tokio::io::DuplexStream,
        early_payload: Vec<u8>,
    ) -> io::Result<()> {
        let (mut app_reader, mut app_writer) = tokio::io::split(bridge);
        if !early_payload.is_empty() {
            app_writer.write_all(&early_payload).await?;
        }
        let mut reply_written = false;
        let mut client_closed = false;
        let mut target_closed = false;
        let mut buffer = vec![0_u8; MAX_PAYLOAD_LEN - 1];
        while !client_closed || !target_closed {
            tokio::select! {
                result = self.decoder.read_record(&mut self.reader), if !client_closed => {
                    let payload = result?;
                    if payload.is_empty() {
                        client_closed = true;
                        app_writer.shutdown().await?;
                    } else {
                        app_writer.write_all(&payload).await?;
                    }
                }
                result = app_reader.read(&mut buffer), if !target_closed => {
                    let size = result?;
                    if size == 0 {
                        target_closed = true;
                        if !reply_written {
                            let mut error = vec![REPLY_ERROR, 0x65, 10];
                            error.extend_from_slice(b"Remote EOF");
                            self.write_record(&error).await?;
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "snell: remote EOF before reply",
                            ));
                        }
                        self.write_record(&[]).await?;
                    } else {
                        let mut payload = Vec::with_capacity(
                            size + usize::from(!reply_written),
                        );
                        if !reply_written {
                            payload.push(REPLY_TUNNEL);
                            reply_written = true;
                        }
                        payload.extend_from_slice(&buffer[..size]);
                        self.write_record(&payload).await?;
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn next_request(&mut self) -> io::Result<(Request, Vec<u8>)> {
        let record = self.decoder.read_record(&mut self.reader).await?;
        let (request, consumed) = decode_request(&record)?;
        Ok((request, record[consumed..].to_vec()))
    }

    pub async fn into_packet_connection(mut self) -> io::Result<PacketStream> {
        self.write_record(&[REPLY_TUNNEL]).await?;
        let raw = self.reader.unsplit(self.writer);
        Ok(packet_connection(
            raw,
            self.decoder,
            self.encoder,
            PacketRole::Server,
        ))
    }

    pub async fn write_pong(mut self) -> io::Result<()> {
        self.write_record(&[REPLY_PONG]).await?;
        self.writer.shutdown().await
    }
}

pub async fn accept_v5_connection(
    raw: Stream,
    psk: &[u8],
) -> io::Result<AcceptedV5> {
    accept_v5_connection_with_cache(raw, psk, None).await
}

pub async fn accept_v5_connection_with_cache(
    mut raw: Stream,
    psk: &[u8],
    replay_cache: Option<&SaltReplayCache>,
) -> io::Result<AcceptedV5> {
    let mut decoder = RecordDecoder::new(psk.to_vec());
    let first = decoder.read_record(&mut raw).await?;
    if let (Some(cache), Some(salt)) = (replay_cache, decoder.salt())
        && cache.check_and_add(&salt)
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "snell: duplicated salt",
        ));
    }
    let (request, consumed) = decode_request(&first)?;
    let early_payload = first[consumed..].to_vec();
    match request.command {
        COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
            let encoder = RecordEncoder::random(psk)?;
            let stream = spawn_record_bridge(
                raw,
                decoder,
                encoder,
                vec![REPLY_TUNNEL],
                early_payload,
                false,
            );
            Ok(AcceptedV5::Tcp { stream, request })
        }
        COMMAND_UDP => {
            let mut encoder = RecordEncoder::random(psk)?;
            write_v4_stream_payload(&mut raw, &mut encoder, &[REPLY_TUNNEL])
                .await?;
            let packets =
                packet_connection(raw, decoder, encoder, PacketRole::Server);
            Ok(AcceptedV5::Udp { packets, request })
        }
        COMMAND_PING => {
            let mut encoder = RecordEncoder::random(psk)?;
            write_v4_stream_payload(&mut raw, &mut encoder, &[REPLY_PONG])
                .await?;
            raw.shutdown().await?;
            Ok(AcceptedV5::Pong)
        }
        _ => Err(invalid_data("snell: unsupported command")),
    }
}

fn spawn_record_bridge(
    raw: Stream,
    mut decoder: RecordDecoder,
    mut encoder: RecordEncoder,
    write_prefix: Vec<u8>,
    early_payload: Vec<u8>,
    parse_reply: bool,
) -> Stream {
    let (application, bridge) = tokio::io::duplex(64 * 1024);
    let (mut application_reader, mut application_writer) =
        tokio::io::split(bridge);
    let (mut raw_reader, mut raw_writer) = tokio::io::split(raw);

    tokio::spawn(async move {
        let mut first_write = true;
        let mut buffer = vec![0_u8; MAX_PAYLOAD_LEN.saturating_sub(1)];
        loop {
            let size = match application_reader.read(&mut buffer).await {
                Ok(size) => size,
                Err(_) => return,
            };
            let mut payload = Vec::with_capacity(
                size + usize::from(first_write) * write_prefix.len(),
            );
            let first_record = first_write;
            if first_record {
                payload.extend_from_slice(&write_prefix);
                first_write = false;
            }
            payload.extend_from_slice(&buffer[..size]);
            if payload.is_empty() && size == 0 {
                let _ =
                    write_v4_stream_payload(&mut raw_writer, &mut encoder, &[])
                        .await;
                let _ = raw_writer.shutdown().await;
                return;
            }
            if write_v4_stream_payload(&mut raw_writer, &mut encoder, &payload)
                .await
                .is_err()
            {
                return;
            }
            if size == 0 {
                let _ = raw_writer.shutdown().await;
                return;
            }
        }
    });

    tokio::spawn(async move {
        if !early_payload.is_empty()
            && application_writer.write_all(&early_payload).await.is_err()
        {
            return;
        }
        let mut first_read = true;
        loop {
            let mut payload = match decoder.read_record(&mut raw_reader).await {
                Ok(payload) => payload,
                Err(_) => return,
            };
            if payload.is_empty() {
                let _ = application_writer.shutdown().await;
                return;
            }
            if first_read && parse_reply {
                first_read = false;
                match payload.first().copied() {
                    Some(REPLY_TUNNEL) => {
                        payload.remove(0);
                    }
                    Some(REPLY_PONG) | Some(REPLY_ERROR) | None | Some(_) => {
                        return;
                    }
                }
            }
            if !payload.is_empty()
                && application_writer.write_all(&payload).await.is_err()
            {
                return;
            }
        }
    });
    Box::new(application)
}

#[derive(Debug, Clone, Copy)]
enum PacketRole {
    Client,
    Server,
}

struct PacketReader {
    raw: ReadHalf<Stream>,
    decoder: RecordDecoder,
}

struct PacketWriter {
    raw: WriteHalf<Stream>,
    encoder: RecordEncoder,
}

struct SnellPacketConnection {
    reader: Mutex<PacketReader>,
    writer: Mutex<PacketWriter>,
    role: PacketRole,
}

fn packet_connection(
    raw: Stream,
    decoder: RecordDecoder,
    encoder: RecordEncoder,
    role: PacketRole,
) -> PacketStream {
    let (reader, writer) = tokio::io::split(raw);
    Box::new(SnellPacketConnection {
        reader: Mutex::new(PacketReader {
            raw: reader,
            decoder,
        }),
        writer: Mutex::new(PacketWriter {
            raw: writer,
            encoder,
        }),
        role,
    })
}

impl PacketConnection for SnellPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let mut payload = Vec::with_capacity(data.len() + 260);
            match self.role {
                PacketRole::Client => {
                    payload.push(UDP_COMMAND_FORWARD);
                    encode_udp_request_address(destination, &mut payload)?;
                }
                PacketRole::Server => {
                    encode_udp_response_address(destination, &mut payload)?;
                }
            }
            payload.extend_from_slice(data);
            if payload.len() > MAX_PAYLOAD_LEN {
                return Err(invalid_input(
                    "snell: UDP payload exceeds maximum",
                ));
            }
            let mut writer = self.writer.lock().await;
            let record = writer.encoder.encode_record(&payload, &[])?;
            writer.raw.write_all(&record).await?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut reader = self.reader.lock().await;
            let PacketReader { raw, decoder } = &mut *reader;
            let payload = decoder.read_record(raw).await?;
            let (source, offset) = match self.role {
                PacketRole::Client => decode_udp_response_address(&payload)?,
                PacketRole::Server => {
                    if payload.first().copied() != Some(UDP_COMMAND_FORWARD) {
                        return Err(invalid_data(
                            "snell: unsupported UDP command",
                        ));
                    }
                    let (destination, consumed) =
                        decode_udp_request_address(&payload[1..])?;
                    (destination, consumed + 1)
                }
            };
            let packet = &payload[offset..];
            if packet.len() > data.len() {
                return Err(invalid_data(
                    "snell: UDP payload exceeds receive buffer",
                ));
            }
            data[..packet.len()].copy_from_slice(packet);
            Ok((packet.len(), source))
        })
    }
}

fn random_byte() -> io::Result<u8> {
    let mut value = [0_u8; 1];
    getrandom::fill(&mut value).map_err(|error| {
        io::Error::other(format!("snell: generate random byte: {error}"))
    })?;
    Ok(value[0])
}

fn random_initial_padding() -> io::Result<Vec<u8>> {
    let padding_len = 0x100 + usize::from(random_byte()?);
    let mut padding = vec![0_u8; padding_len];
    getrandom::fill(&mut padding).map_err(|error| {
        io::Error::other(format!("snell: generate padding: {error}"))
    })?;
    Ok(padding)
}

pub struct SnellV4Outbound {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    psk: Vec<u8>,
    user_key: Vec<u8>,
    obfs_mode: ObfsMode,
    obfs_host: String,
    reuse: bool,
    reuse_pool: Arc<ReusablePool>,
}

struct ReusableClientSession {
    reader: ReadHalf<Stream>,
    writer: WriteHalf<Stream>,
    decoder: RecordDecoder,
    encoder: RecordEncoder,
}

struct ReusablePoolEntry {
    inserted: Instant,
    session: ReusableClientSession,
}

#[derive(Default)]
struct ReusablePool {
    entries: Mutex<VecDeque<ReusablePoolEntry>>,
    ticking: AtomicBool,
    network_monitor_started: AtomicBool,
    cancellation: tokio_util::sync::CancellationToken,
}

impl Drop for ReusablePool {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl SnellV4Outbound {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        psk: impl Into<Vec<u8>>,
        user_key: impl Into<Vec<u8>>,
    ) -> io::Result<Self> {
        Self::new_with_obfs(
            upstream,
            server,
            psk,
            user_key,
            ObfsMode::None,
            String::new(),
            false,
        )
    }

    pub fn new_with_obfs(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        psk: impl Into<Vec<u8>>,
        user_key: impl Into<Vec<u8>>,
        obfs_mode: ObfsMode,
        obfs_host: impl Into<String>,
        reuse: bool,
    ) -> io::Result<Self> {
        let psk = psk.into();
        let user_key = user_key.into();
        if psk.is_empty() {
            return Err(invalid_input("snell: missing pre-shared key"));
        }
        if user_key.len() > u8::MAX as usize {
            return Err(invalid_input("snell: user key too long"));
        }
        Ok(Self {
            upstream,
            server,
            psk,
            user_key,
            obfs_mode,
            obfs_host: obfs_host.into(),
            reuse,
            reuse_pool: Arc::new(ReusablePool::default()),
        })
    }

    /// Discard every idle reusable session immediately.
    ///
    /// Active logical connections are left alone and will only be returned to
    /// the pool after they finish, matching sing-box's client-close behavior
    /// for connections that are already in use.
    pub async fn reset(&self) {
        self.reuse_pool.entries.lock().await.clear();
    }
}

async fn take_reusable_session(
    pool: &ReusablePool,
) -> Option<ReusableClientSession> {
    let mut pool = pool.entries.lock().await;
    let now = Instant::now();
    while pool.front().is_some_and(|entry| {
        now.duration_since(entry.inserted) > REUSE_POOL_MAX_AGE
    }) {
        pool.pop_front();
    }
    pool.pop_front().map(|entry| entry.session)
}

async fn return_reusable_session(
    pool: &Arc<ReusablePool>,
    session: ReusableClientSession,
) {
    let mut entries = pool.entries.lock().await;
    let now = Instant::now();
    while entries.front().is_some_and(|entry| {
        now.duration_since(entry.inserted) > REUSE_POOL_MAX_AGE
    }) {
        entries.pop_front();
    }
    if entries.len() < REUSE_POOL_SIZE {
        entries.push_back(ReusablePoolEntry {
            inserted: now,
            session,
        });
    }
    let start_ticker = !entries.is_empty()
        && pool
            .ticking
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
    drop(entries);
    if start_ticker {
        spawn_reuse_expiry(Arc::downgrade(pool));
    }
}

fn spawn_reuse_expiry(pool: std::sync::Weak<ReusablePool>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REUSE_POOL_TIMER_INTERVAL).await;
            let Some(pool) = pool.upgrade() else {
                return;
            };
            let mut entries = pool.entries.lock().await;
            let now = Instant::now();
            while entries.front().is_some_and(|entry| {
                now.duration_since(entry.inserted) > REUSE_POOL_MAX_AGE
            }) {
                entries.pop_front();
            }
            if entries.is_empty() {
                pool.ticking.store(false, Ordering::Release);
                return;
            }
        }
    });
}

fn ensure_reuse_network_monitor(pool: &Arc<ReusablePool>) {
    if pool
        .network_monitor_started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let weak_pool = Arc::downgrade(pool);
    let cancellation = pool.cancellation.clone();
    tokio::spawn(async move {
        let Ok(monitor) =
            crate::common::network_monitor::NetworkMonitor::new().await
        else {
            if let Some(pool) = weak_pool.upgrade() {
                pool.network_monitor_started.store(false, Ordering::Release);
            }
            return;
        };
        let mut watcher = monitor.interface_state();
        let mut previous = watcher.get();
        loop {
            let current = tokio::select! {
                _ = cancellation.cancelled() => return,
                current = watcher.updated() => match current {
                    Ok(current) => current,
                    Err(_) => return,
                },
            };
            let changed = current.is_major_change(&previous);
            previous = current;
            if changed {
                let Some(pool) = weak_pool.upgrade() else {
                    return;
                };
                pool.entries.lock().await.clear();
            }
        }
    });
}

async fn run_reused_logical_connection(
    session: &mut ReusableClientSession,
    bridge: tokio::io::DuplexStream,
    request: Vec<u8>,
) -> io::Result<()> {
    write_v4_stream_payload(
        &mut session.writer,
        &mut session.encoder,
        &request,
    )
    .await?;
    let (mut app_reader, mut app_writer) = tokio::io::split(bridge);
    let mut reply_read = false;
    let mut local_closed = false;
    let mut remote_closed = false;
    let mut application_read_closed = false;
    let mut discarded = 0_usize;
    let mut buffer = vec![0_u8; MAX_PAYLOAD_LEN];
    while !local_closed || !remote_closed {
        tokio::select! {
            result = app_reader.read(&mut buffer), if !local_closed => {
                let size = result?;
                write_v4_stream_payload(
                    &mut session.writer,
                    &mut session.encoder,
                    &buffer[..size],
                ).await?;
                if size == 0 {
                    local_closed = true;
                }
            }
            result = session.decoder.read_record(&mut session.reader), if !remote_closed => {
                let mut payload = result?;
                if payload.is_empty() {
                    remote_closed = true;
                    if let Err(error) = app_writer.shutdown().await
                        && !local_closed
                    {
                        return Err(error);
                    }
                    continue;
                }
                if !reply_read {
                    reply_read = true;
                    match payload.first().copied() {
                        Some(REPLY_TUNNEL) => { payload.remove(0); }
                        Some(REPLY_ERROR) => {
                            return Err(invalid_data("snell: server rejected reused connection"));
                        }
                        _ => return Err(invalid_data("snell: unexpected reused reply")),
                    }
                }
                if !payload.is_empty() {
                    if application_read_closed {
                        discarded = discarded.saturating_add(payload.len());
                    } else if let Err(error) = app_writer.write_all(&payload).await {
                        if !local_closed {
                            return Err(error);
                        }
                        application_read_closed = true;
                        discarded = discarded.saturating_add(payload.len());
                    }
                    if discarded >= REUSE_WAITING_DISCARD_LIMIT {
                        return Err(invalid_data(
                            "snell: waiting reuse session exceeded discard limit",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

impl Dialer for SnellV4Outbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            if self.reuse {
                ensure_reuse_network_monitor(&self.reuse_pool);
                let mut session = if let Some(session) =
                    take_reusable_session(&self.reuse_pool).await
                {
                    session
                } else {
                    let raw = self.upstream.dial_tcp(&self.server).await?;
                    let raw = wrap_obfs_client(
                        raw,
                        self.obfs_mode,
                        self.obfs_host.clone(),
                    )?;
                    let (reader, writer) = tokio::io::split(raw);
                    ReusableClientSession {
                        reader,
                        writer,
                        decoder: RecordDecoder::new(self.psk.clone()),
                        encoder: RecordEncoder::random(&self.psk)?,
                    }
                };
                let request = encode_request(&Request {
                    command: COMMAND_CONNECT_V2,
                    client_id: self.user_key.clone(),
                    destination: Some(destination.clone()),
                })?;
                let (application, bridge) = tokio::io::duplex(64 * 1024);
                let pool = self.reuse_pool.clone();
                tokio::spawn(async move {
                    if run_reused_logical_connection(
                        &mut session,
                        bridge,
                        request,
                    )
                    .await
                    .is_ok()
                    {
                        return_reusable_session(&pool, session).await;
                    }
                });
                return Ok(Box::new(application) as Stream);
            }
            let raw = self.upstream.dial_tcp(&self.server).await?;
            let raw =
                wrap_obfs_client(raw, self.obfs_mode, self.obfs_host.clone())?;
            connect_v4(raw, &self.psk, &self.user_key, destination.clone())
                .await
        })
    }

    fn listen_udp<'a>(
        &'a self,
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let raw = self.upstream.dial_tcp(&self.server).await?;
            let raw =
                wrap_obfs_client(raw, self.obfs_mode, self.obfs_host.clone())?;
            connect_v4_udp(raw, &self.psk, &self.user_key).await
        })
    }
}

pub fn increase_nonce(nonce: &mut [u8]) {
    for byte in nonce {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[test]
    fn request_and_address_forms_round_trip() {
        for destination in [
            SocksAddr::new("example.com", 443),
            SocksAddr::new("192.0.2.1", 53),
            SocksAddr::new("2001:db8::1", 5353),
        ] {
            let request = Request {
                command: COMMAND_CONNECT_V2,
                client_id: b"user-key".to_vec(),
                destination: Some(destination.clone()),
            };
            let wire = encode_request(&request).unwrap();
            let (decoded, consumed) = decode_request(&wire).unwrap();
            assert_eq!(decoded, request);
            assert_eq!(consumed, wire.len());

            let mut udp = Vec::new();
            encode_udp_request_address(&destination, &mut udp).unwrap();
            let (decoded, consumed) = decode_udp_request_address(&udp).unwrap();
            assert_eq!(decoded, destination);
            assert_eq!(consumed, udp.len());
        }
        let (ping, consumed) =
            decode_request(&[REQUEST_VERSION, COMMAND_PING, 0xff]).unwrap();
        assert_eq!(ping.command, COMMAND_PING);
        assert!(ping.client_id.is_empty());
        assert_eq!(consumed, 3);
    }

    #[test]
    fn records_round_trip_with_alternating_padding_swap() {
        let salt = [0x11; SALT_LEN];
        let mut encoder = RecordEncoder::new(b"secret", salt).unwrap();
        let first = encoder
            .encode_record(b"first payload", &[0x55; 37])
            .unwrap();
        let second = encoder.encode_record(b"second", &[]).unwrap();
        assert_eq!(&first[..SALT_LEN], &salt);
        assert_ne!(
            &first[SALT_LEN + HEADER_CIPHER_LEN..][..13],
            b"first payload"
        );

        let mut decoder = RecordDecoder::new(b"secret".to_vec());
        let (payload, consumed) = decoder.decode_record(&first).unwrap();
        assert_eq!(payload, b"first payload");
        assert_eq!(consumed, first.len());
        let (payload, consumed) = decoder.decode_record(&second).unwrap();
        assert_eq!(payload, b"second");
        assert_eq!(consumed, second.len());
    }

    #[test]
    fn matches_go_sing_snell_vectors() {
        let salt = [0x11; SALT_LEN];
        assert_eq!(
            hex::encode(derive_key(b"secret", &salt).unwrap()),
            "a171f344d9aadb7a765e51b781f82986"
        );
        let request = Request {
            command: COMMAND_CONNECT_V2,
            client_id: b"user-key".to_vec(),
            destination: Some(SocksAddr::new("example.com", 443)),
        };
        assert_eq!(
            hex::encode(encode_request(&request).unwrap()),
            "010508757365722d6b65790b6578616d706c652e636f6d01bb"
        );
        let mut encoder = RecordEncoder::new(b"secret", salt).unwrap();
        assert_eq!(
            hex::encode(
                encoder
                    .encode_record(b"first payload", &[0x55; 37])
                    .unwrap()
            ),
            concat!(
                "11111111111111111111111111111111",
                "4c2b06e52981d6fb7b857a0be980a007dcd6ae5fc4038ae",
                "7559a55e455db5574556c5571558d55de5544559555bc5527",
                "55e4559f5555555555555555555d550d5555557355db55ce55",
                "4255725588554955ba55ad5551557655"
            )
        );
    }

    #[test]
    fn nonce_is_a_little_endian_counter() {
        let mut nonce = [0_u8; NONCE_LEN];
        nonce[0] = u8::MAX;
        increase_nonce(&mut nonce);
        assert_eq!(nonce[0], 0);
        assert_eq!(nonce[1], 1);
    }

    #[test]
    fn v4_stream_payload_limit_matches_surge_growth_and_reset() {
        let mut encoder =
            RecordEncoder::new(b"secret", [7_u8; SALT_LEN]).unwrap();
        assert_eq!(encoder.begin_stream_write(0x1ff), 894);
        encoder.encode_record(b"x", &[0_u8; 0x1ff]).unwrap();
        assert_eq!(encoder.begin_stream_write(0), 2315);
        assert_eq!(encoder.begin_stream_write(0), 3736);
        encoder.last_write_unix = encoder
            .last_write_unix
            .saturating_sub(V4_PAYLOAD_RESET_INTERVAL);
        assert_eq!(encoder.begin_stream_write(0), 1421);
    }

    #[tokio::test]
    async fn v5_rejects_a_replayed_first_record_salt() {
        let request = encode_request(&Request {
            command: COMMAND_CONNECT_V2,
            client_id: Vec::new(),
            destination: Some(SocksAddr::new("target.example", 443)),
        })
        .unwrap();
        let wire = RecordEncoder::new(b"secret", [0x42; SALT_LEN])
            .unwrap()
            .encode_record(&request, &[])
            .unwrap();
        let cache = SaltReplayCache::default();

        for replayed in [false, true] {
            let (mut sender, receiver) = tokio::io::duplex(4096);
            sender.write_all(&wire).await.unwrap();
            drop(sender);
            let result = accept_v5_connection_with_cache(
                Box::new(receiver),
                b"secret",
                Some(&cache),
            )
            .await;
            if replayed {
                let Err(error) = result else {
                    panic!("replayed salt was accepted");
                };
                assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            } else {
                assert!(matches!(result.unwrap(), AcceptedV5::Tcp { .. }));
            }
        }
    }

    #[tokio::test]
    async fn v4_client_and_v5_server_streams_interoperate() {
        let (client_raw, server_raw) = tokio::io::duplex(8192);
        let mut client = connect_v4(
            Box::new(client_raw),
            b"secret",
            b"user-key",
            SocksAddr::new("target.example", 443),
        )
        .await
        .unwrap();
        let (mut server, request) =
            accept_v5(Box::new(server_raw), b"secret").await.unwrap();
        assert_eq!(request.command, COMMAND_CONNECT_V2);
        assert_eq!(request.client_id, b"user-key");
        assert_eq!(
            request.destination,
            Some(SocksAddr::new("target.example", 443))
        );

        client.write_all(b"client payload").await.unwrap();
        let mut received = [0_u8; 14];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"client payload");

        server.write_all(b"server payload").await.unwrap();
        let mut response = [0_u8; 14];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"server payload");
    }

    #[tokio::test]
    async fn http_obfs_v4_client_and_v5_server_interoperate() {
        let (client_raw, server_raw) = tokio::io::duplex(16 * 1024);
        let client_raw = wrap_obfs_client(
            Box::new(client_raw),
            ObfsMode::Http,
            "cdn.example",
        )
        .unwrap();
        let server_raw =
            wrap_obfs_server(Box::new(server_raw), ObfsMode::Http).unwrap();
        let mut client = connect_v4(
            client_raw,
            b"secret",
            b"user-key",
            SocksAddr::new("target.example", 443),
        )
        .await
        .unwrap();
        let (mut server, request) =
            accept_v5(server_raw, b"secret").await.unwrap();
        assert_eq!(
            request.destination,
            Some(SocksAddr::new("target.example", 443))
        );

        client.write_all(b"request body").await.unwrap();
        let mut request_body = [0_u8; 12];
        server.read_exact(&mut request_body).await.unwrap();
        assert_eq!(&request_body, b"request body");
        server.write_all(b"response body").await.unwrap();
        let mut response_body = [0_u8; 13];
        client.read_exact(&mut response_body).await.unwrap();
        assert_eq!(&response_body, b"response body");
    }

    #[tokio::test]
    async fn tls_obfs_v4_client_and_v5_server_interoperate() {
        let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
        let client_raw = wrap_obfs_client(
            Box::new(client_raw),
            ObfsMode::Tls,
            "cdn.example",
        )
        .unwrap();
        let server_raw =
            wrap_obfs_server(Box::new(server_raw), ObfsMode::Tls).unwrap();
        let mut client = connect_v4(
            client_raw,
            b"secret",
            b"user-key",
            SocksAddr::new("target.example", 443),
        )
        .await
        .unwrap();
        let (mut server, request) =
            accept_v5(server_raw, b"secret").await.unwrap();
        assert_eq!(
            request.destination,
            Some(SocksAddr::new("target.example", 443))
        );

        client.write_all(b"request body").await.unwrap();
        let mut request_body = [0_u8; 12];
        server.read_exact(&mut request_body).await.unwrap();
        assert_eq!(&request_body, b"request body");
        server.write_all(b"response body").await.unwrap();
        let mut response_body = [0_u8; 13];
        client.read_exact(&mut response_body).await.unwrap();
        assert_eq!(&response_body, b"response body");
    }

    #[tokio::test]
    async fn v4_client_and_v5_server_packets_interoperate() {
        let (client_raw, server_raw) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let AcceptedV5::Udp { packets, request } =
                accept_v5_connection(Box::new(server_raw), b"secret")
                    .await
                    .unwrap()
            else {
                panic!("expected a Snell UDP tunnel");
            };
            assert_eq!(request.command, COMMAND_UDP);
            assert_eq!(request.client_id, b"user-key");

            let mut payload = [0_u8; 64];
            let (size, destination) =
                packets.recv_from(&mut payload).await.unwrap();
            assert_eq!(&payload[..size], b"client datagram");
            assert_eq!(destination, SocksAddr::new("target.example", 53));
            packets
                .send_to(b"server datagram", &SocksAddr::new("192.0.2.9", 5353))
                .await
                .unwrap();
        });

        let packets =
            connect_v4_udp(Box::new(client_raw), b"secret", b"user-key")
                .await
                .unwrap();
        packets
            .send_to(b"client datagram", &SocksAddr::new("target.example", 53))
            .await
            .unwrap();
        let mut response = [0_u8; 64];
        let (size, source) = packets.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"server datagram");
        assert_eq!(source, SocksAddr::new("192.0.2.9", 5353));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn v4_outbound_dials_a_v5_server() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut stream, request) =
                accept_v5(Box::new(stream), b"secret").await.unwrap();
            assert_eq!(
                request.destination,
                Some(SocksAddr::new("target.example", 443))
            );
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let outbound = SnellV4Outbound::new(
            Arc::new(crate::protocol::direct::DirectOutbound::new(
                crate::option::DirectOutboundOptions::default(),
            )),
            server_address.into(),
            b"secret".to_vec(),
            b"user-key".to_vec(),
        )
        .unwrap();
        let mut stream = outbound
            .dial_tcp(&SocksAddr::new("target.example", 443))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn v4_outbound_reuses_one_physical_connection() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut decoder = RecordDecoder::new(b"secret".to_vec());
            let mut encoder = RecordEncoder::random(b"secret").unwrap();
            for index in 0..2 {
                let request = decoder.read_record(&mut stream).await.unwrap();
                let (request, consumed) = decode_request(&request).unwrap();
                assert_eq!(request.command, COMMAND_CONNECT_V2);
                assert_eq!(
                    request.destination,
                    Some(SocksAddr::new(
                        format!("target-{index}.example"),
                        443
                    ))
                );
                assert_eq!(consumed, encode_request(&request).unwrap().len());
                let payload = decoder.read_record(&mut stream).await.unwrap();
                assert_eq!(payload, b"ping");
                let mut response = vec![REPLY_TUNNEL];
                response.extend_from_slice(b"pong");
                let padding = if encoder.salt_sent {
                    Vec::new()
                } else {
                    random_initial_padding().unwrap()
                };
                stream
                    .write_all(
                        &encoder.encode_record(&response, &padding).unwrap(),
                    )
                    .await
                    .unwrap();
                assert!(
                    decoder.read_record(&mut stream).await.unwrap().is_empty()
                );
                stream
                    .write_all(&encoder.encode_record(&[], &[]).unwrap())
                    .await
                    .unwrap();
            }
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(50),
                    listener.accept(),
                )
                .await
                .is_err()
            );
        });
        let outbound = SnellV4Outbound::new_with_obfs(
            Arc::new(crate::protocol::direct::DirectOutbound::new(
                crate::option::DirectOutboundOptions::default(),
            )),
            server_address.into(),
            b"secret".to_vec(),
            b"user-key".to_vec(),
            ObfsMode::None,
            String::new(),
            true,
        )
        .unwrap();
        for index in 0..2 {
            let mut stream = outbound
                .dial_tcp(&SocksAddr::new(
                    format!("target-{index}.example"),
                    443,
                ))
                .await
                .unwrap();
            stream.write_all(b"ping").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"pong");
        }
        server.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !outbound.reuse_pool.entries.lock().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(outbound.reuse_pool.ticking.load(Ordering::Acquire));
        outbound.reset().await;
        assert!(outbound.reuse_pool.entries.lock().await.is_empty());
    }

    #[tokio::test]
    async fn v4_waiting_reuse_closes_after_upstream_discard_limit() {
        let (client_raw, mut server_raw) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(Box::new(client_raw) as Stream);
        let mut session = ReusableClientSession {
            reader,
            writer,
            decoder: RecordDecoder::new(b"secret".to_vec()),
            encoder: RecordEncoder::random(b"secret").unwrap(),
        };
        let request = encode_request(&Request {
            command: COMMAND_CONNECT_V2,
            client_id: b"user-key".to_vec(),
            destination: Some(SocksAddr::new("target.example", 443)),
        })
        .unwrap();
        let (application, bridge) = tokio::io::duplex(64 * 1024);
        drop(application);

        let server = tokio::spawn(async move {
            let mut decoder = RecordDecoder::new(b"secret".to_vec());
            decoder.read_record(&mut server_raw).await.unwrap();
            let mut encoder = RecordEncoder::random(b"secret").unwrap();
            let padding = random_initial_padding().unwrap();
            server_raw
                .write_all(
                    &encoder.encode_record(&[REPLY_TUNNEL], &padding).unwrap(),
                )
                .await
                .unwrap();
            let mut remaining = REUSE_WAITING_DISCARD_LIMIT;
            while remaining != 0 {
                let size = remaining.min(MAX_PAYLOAD_LEN);
                if server_raw
                    .write_all(
                        &encoder.encode_record(&vec![0x42; size], &[]).unwrap(),
                    )
                    .await
                    .is_err()
                {
                    break;
                }
                remaining -= size;
            }
        });
        let error = tokio::time::timeout(
            // This path deliberately decrypts and discards slightly more than
            // 512 KiB.  Under the full parallel suite, debug crypto can exceed
            // two seconds even though the limit is reached correctly.
            Duration::from_secs(10),
            run_reused_logical_connection(&mut session, bridge, request),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("discard limit"));
        server.await.unwrap();
    }
}
