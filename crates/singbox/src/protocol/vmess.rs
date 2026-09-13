//! VMess AEAD authentication and request-header protocol core.
//!
//! This module intentionally starts at the wire boundary: every derivation and
//! header parser accepts deterministic inputs so it can be checked against the
//! pinned Go `sing-vmess` implementation before stream framing is layered on.

use std::{
    io,
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use aes::{
    Aes128,
    cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as _},
};
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, Payload},
};
use chacha20poly1305::ChaCha20Poly1305;
use crc32fast::hash as crc32;
use md5::{Digest as _, Md5};
use sha2::Sha256;
use sha3::{
    Shake128, Shake128Reader,
    digest::{ExtendableOutput, XofReader},
};
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf,
    },
    sync::Mutex,
};
use uuid::Uuid;

use crate::{
    adapter::{
        DialFuture, Dialer, PacketConnection, PacketFuture, PacketStream,
        Stream,
    },
    common::{network::SocksAddr, ntp::NtpClock},
};

pub const VERSION: u8 = 1;
pub const CIPHER_OVERHEAD: usize = 16;
pub const KDF_SALT: &[u8] = b"VMess AEAD KDF";
pub const AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
pub const HEADER_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
pub const HEADER_LENGTH_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
pub const HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
pub const HEADER_PAYLOAD_NONCE: &[u8] = b"VMess Header AEAD Nonce";
pub const RESPONSE_LENGTH_KEY: &[u8] = b"AEAD Resp Header Len Key";
pub const RESPONSE_LENGTH_NONCE: &[u8] = b"AEAD Resp Header Len IV";
pub const RESPONSE_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
pub const RESPONSE_PAYLOAD_NONCE: &[u8] = b"AEAD Resp Header IV";
pub const AUTHENTICATED_LENGTH_KEY: &[u8] = b"auth_len";

pub const OPTION_CHUNK_STREAM: u8 = 1;
pub const OPTION_CHUNK_MASKING: u8 = 4;
pub const OPTION_GLOBAL_PADDING: u8 = 8;
pub const OPTION_AUTHENTICATED_LENGTH: u8 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Security {
    Legacy = 1,
    Auto = 2,
    Aes128Gcm = 3,
    Chacha20Poly1305 = 4,
    None = 5,
    Zero = 6,
}

impl Security {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "auto" | "" => Ok(Self::Auto),
            "none" => Ok(Self::None),
            "zero" => Ok(Self::Zero),
            "aes-128-cfb" => Ok(Self::Legacy),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" => Ok(Self::Chacha20Poly1305),
            _ => Err(invalid_input(format!(
                "unsupported VMess security: {value}"
            ))),
        }
    }

    pub fn wire(self) -> u8 {
        match self {
            Self::Zero => Self::None as u8,
            value => value as u8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Tcp = 1,
    Udp = 2,
    Mux = 3,
}

impl Command {
    fn parse(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Tcp),
            2 => Ok(Self::Udp),
            3 => Ok(Self::Mux),
            _ => Err(invalid_data(format!("unknown VMess command: {value}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub request_nonce: [u8; 16],
    pub request_key: [u8; 16],
    pub response_header: u8,
    pub option: u8,
    pub security: u8,
    pub command: Command,
    pub destination: Option<SocksAddr>,
    pub legacy_header: bool,
}

pub fn new_request_header(
    command: Command,
    destination: Option<SocksAddr>,
    security: Security,
) -> io::Result<RequestHeader> {
    let security = match security {
        Security::None | Security::Zero => Security::None,
        Security::Auto => auto_security(),
        Security::Legacy | Security::Aes128Gcm | Security::Chacha20Poly1305 => {
            security
        }
    };
    let mut request_nonce = [0_u8; 16];
    let mut request_key = [0_u8; 16];
    let mut response_header = [0_u8; 1];
    getrandom::fill(&mut request_nonce).map_err(random_error)?;
    getrandom::fill(&mut request_key).map_err(random_error)?;
    getrandom::fill(&mut response_header).map_err(random_error)?;
    Ok(RequestHeader {
        request_nonce,
        request_key,
        response_header: response_header[0],
        option: match security {
            Security::None if command == Command::Udp => OPTION_CHUNK_STREAM,
            Security::Legacy => OPTION_CHUNK_STREAM,
            Security::Aes128Gcm | Security::Chacha20Poly1305 => {
                OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING
            }
            _ => 0,
        },
        security: security.wire(),
        command,
        destination,
        legacy_header: false,
    })
}

pub async fn write_request<S>(
    stream: &mut S,
    command_key: &[u8; 16],
    alter_key: Option<&[u8; 16]>,
    request: &RequestHeader,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    write_request_with_clock(stream, command_key, alter_key, request, None)
        .await
}

pub async fn write_request_with_clock<S>(
    stream: &mut S,
    command_key: &[u8; 16],
    alter_key: Option<&[u8; 16]>,
    request: &RequestHeader,
    clock: Option<&NtpClock>,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let now = unix_time(clock)?;
    if let Some(alter_key) = alter_key {
        return write_legacy_request(
            stream,
            command_key,
            alter_key,
            request,
            now,
        )
        .await;
    }
    let mut random = [0_u8; 12];
    getrandom::fill(&mut random).map_err(random_error)?;
    let auth = auth_id(command_key, now, random[..4].try_into().unwrap());
    let header = encode_request_header(request, &[])?;
    let sealed = seal_request_header(
        command_key,
        auth,
        random[4..].try_into().unwrap(),
        &header,
    )?;
    stream.write_all(&sealed).await?;
    stream.flush().await
}

pub async fn read_request<S>(
    stream: &mut S,
    command_keys: &[[u8; 16]],
    alter_ids: &[Vec<[u8; 16]>],
) -> io::Result<(RequestHeader, usize, [u8; 16])>
where
    S: AsyncRead + Unpin + ?Sized,
{
    read_request_with_clock(stream, command_keys, alter_ids, None).await
}

pub async fn read_request_with_clock<S>(
    stream: &mut S,
    command_keys: &[[u8; 16]],
    alter_ids: &[Vec<[u8; 16]>],
    clock: Option<&NtpClock>,
) -> io::Result<(RequestHeader, usize, [u8; 16])>
where
    S: AsyncRead + Unpin + ?Sized,
{
    const PREFIX: usize = 16 + 2 + CIPHER_OVERHEAD + 8;
    let mut prefix = [0_u8; PREFIX];
    stream.read_exact(&mut prefix).await?;
    let auth: [u8; 16] = prefix[..16].try_into().unwrap();
    let now = unix_time(clock)?;
    let found = command_keys
        .iter()
        .enumerate()
        .find(|(_, key)| verify_auth_id(key, &auth, now))
        .map(|(user, key)| (user, key, None));
    let found = if found.is_some() {
        found
    } else {
        find_legacy_user(alter_ids, &auth, now).map(|(user, timestamp)| {
            (user, &command_keys[user], Some(timestamp))
        })
    };
    let (user, command_key, legacy_timestamp) = found.ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "invalid VMess auth ID")
    })?;
    if let Some(timestamp) = legacy_timestamp {
        let request = read_legacy_request(
            stream,
            command_key,
            timestamp,
            prefix[16..].to_vec(),
        )
        .await?;
        return Ok((request, user, auth));
    }
    let header_length = open_request_length(command_key, &prefix)?;
    let mut request =
        Vec::with_capacity(PREFIX + header_length + CIPHER_OVERHEAD);
    request.extend_from_slice(&prefix);
    request.resize(PREFIX + header_length + CIPHER_OVERHEAD, 0);
    stream.read_exact(&mut request[PREFIX..]).await?;
    let (header, consumed) = open_request_header(command_key, &request, now)?;
    debug_assert_eq!(consumed, request.len());
    Ok((header, user, auth))
}

async fn write_legacy_request<S>(
    stream: &mut S,
    command_key: &[u8; 16],
    alter_key: &[u8; 16],
    request: &RequestHeader,
    now: u64,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let auth = hmac_md5(alter_key, &now.to_be_bytes());
    let mut padding_selector = [0_u8; 1];
    getrandom::fill(&mut padding_selector).map_err(random_error)?;
    let mut padding = vec![0_u8; usize::from(padding_selector[0] & 0x0f)];
    getrandom::fill(&mut padding).map_err(random_error)?;
    let mut header = encode_request_header(request, &padding)?;
    AesCfb::new(*command_key, legacy_timestamp_nonce(now), true)
        .apply(&mut header);
    stream.write_all(&auth).await?;
    stream.write_all(&header).await?;
    stream.flush().await
}

fn unix_time(clock: Option<&NtpClock>) -> io::Result<u64> {
    clock
        .map(NtpClock::now)
        .unwrap_or_else(SystemTime::now)
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)
        .map(|duration| duration.as_secs())
}

fn find_legacy_user(
    alter_ids: &[Vec<[u8; 16]>],
    auth: &[u8; 16],
    now: u64,
) -> Option<(usize, u64)> {
    for (user, ids) in alter_ids.iter().enumerate() {
        for id in ids {
            for timestamp in now.saturating_sub(120)..=now.saturating_add(120) {
                if hmac_md5(id, &timestamp.to_be_bytes()) == *auth {
                    return Some((user, timestamp));
                }
            }
        }
    }
    None
}

async fn read_legacy_request<S>(
    stream: &mut S,
    command_key: &[u8; 16],
    timestamp: u64,
    mut encrypted: Vec<u8>,
) -> io::Result<RequestHeader>
where
    S: AsyncRead + Unpin + ?Sized,
{
    encrypted.resize(38, 0);
    stream.read_exact(&mut encrypted[26..]).await?;
    let mut cfb =
        AesCfb::new(*command_key, legacy_timestamp_nonce(timestamp), false);
    cfb.apply(&mut encrypted);
    let mut header = encrypted;
    let command = Command::parse(header[37])?;
    if command != Command::Mux {
        read_legacy_header_part(stream, &mut cfb, &mut header, 3).await?;
        match header[40] {
            1 => {
                read_legacy_header_part(stream, &mut cfb, &mut header, 4)
                    .await?;
            }
            3 => {
                read_legacy_header_part(stream, &mut cfb, &mut header, 16)
                    .await?;
            }
            2 => {
                read_legacy_header_part(stream, &mut cfb, &mut header, 1)
                    .await?;
                let domain_length = usize::from(*header.last().unwrap());
                read_legacy_header_part(
                    stream,
                    &mut cfb,
                    &mut header,
                    domain_length,
                )
                .await?;
            }
            family => {
                return Err(invalid_data(format!(
                    "unknown VMess address type: {family}"
                )));
            }
        }
    }
    let tail = usize::from(header[35] >> 4) + 4;
    read_legacy_header_part(stream, &mut cfb, &mut header, tail).await?;
    let mut request = decode_request_header(&header)?;
    request.legacy_header = true;
    Ok(request)
}

async fn read_legacy_header_part<S>(
    stream: &mut S,
    cfb: &mut AesCfb,
    output: &mut Vec<u8>,
    length: usize,
) -> io::Result<()>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let start = output.len();
    output.resize(start + length, 0);
    stream.read_exact(&mut output[start..]).await?;
    cfb.apply(&mut output[start..]);
    Ok(())
}

fn legacy_timestamp_nonce(timestamp: u64) -> [u8; 16] {
    let bytes = timestamp.to_be_bytes();
    let mut repeated = [0_u8; 32];
    for part in repeated.chunks_exact_mut(8) {
        part.copy_from_slice(&bytes);
    }
    Md5::digest(repeated).into()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    let normalized: Vec<u8> = if key.len() > 64 {
        Md5::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    for (index, byte) in normalized.into_iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Md5::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Md5::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

pub async fn write_response<S>(
    stream: &mut S,
    request: &RequestHeader,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    if request.legacy_header {
        let (key, nonce) = response_key_nonce(request);
        let mut response = [request.response_header, request.option, 0, 0];
        AesCfb::new(key, nonce, true).apply(&mut response);
        stream.write_all(&response).await?;
    } else {
        stream.write_all(&seal_response_header(request)?).await?;
    }
    stream.flush().await
}

pub async fn read_response<S>(
    stream: &mut S,
    request: &RequestHeader,
) -> io::Result<()>
where
    S: AsyncRead + Unpin + ?Sized,
{
    if request.legacy_header {
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await?;
        let (key, nonce) = response_key_nonce(request);
        AesCfb::new(key, nonce, false).apply(&mut response);
        if response[0] != request.response_header {
            return Err(invalid_data("invalid legacy VMess response header"));
        }
        return Ok(());
    }
    let mut length_bytes = [0_u8; 2 + CIPHER_OVERHEAD];
    stream.read_exact(&mut length_bytes).await?;
    let length = open_response_length(request, &length_bytes)?;
    let mut response =
        Vec::with_capacity(length_bytes.len() + length + CIPHER_OVERHEAD);
    response.extend_from_slice(&length_bytes);
    response.resize(length_bytes.len() + length + CIPHER_OVERHEAD, 0);
    stream
        .read_exact(&mut response[length_bytes.len()..])
        .await?;
    open_response_header(request, &response)?;
    Ok(())
}

pub struct VmessOutbound {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    command_key: [u8; 16],
    alter_key: Option<[u8; 16]>,
    security: Security,
    global_padding: bool,
    authenticated_length: bool,
    packet_addr: bool,
    xudp: bool,
    clock: Option<NtpClock>,
}

#[derive(Debug, Clone, Copy)]
pub struct VmessClientConfig<'a> {
    pub security: &'a str,
    pub alter_id: i32,
    pub global_padding: bool,
    pub authenticated_length: bool,
    pub packet_encoding: &'a str,
}

impl VmessOutbound {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        user: &str,
        options: VmessClientConfig<'_>,
    ) -> io::Result<Self> {
        Self::new_with_clock(upstream, server, user, options, None)
    }

    pub fn new_with_clock(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        user: &str,
        options: VmessClientConfig<'_>,
        clock: Option<NtpClock>,
    ) -> io::Result<Self> {
        let VmessClientConfig {
            security,
            alter_id,
            global_padding,
            authenticated_length,
            packet_encoding,
        } = options;
        if alter_id < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess alter_id cannot be negative",
            ));
        }
        let user = user_id(user);
        let (packet_addr, xudp) = match packet_encoding {
            "" => (false, false),
            "packetaddr" => (true, false),
            "xudp" => (false, true),
            value => {
                return Err(invalid_input(format!(
                    "unknown VMess packet encoding: {value}"
                )));
            }
        };
        let security = Security::parse(security)?;
        if !matches!(
            security,
            Security::None
                | Security::Zero
                | Security::Auto
                | Security::Legacy
                | Security::Aes128Gcm
                | Security::Chacha20Poly1305
        ) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this VMess body security is not ported yet",
            ));
        }
        Ok(Self {
            upstream,
            server,
            command_key: command_key(user),
            alter_key: (alter_id > 0).then(|| alter_id_key(user, 1)),
            security,
            global_padding,
            authenticated_length,
            packet_addr,
            xudp,
            clock,
        })
    }
}

impl Dialer for VmessOutbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let mut stream = self.upstream.dial_tcp(&self.server).await?;
            let socket = crate::adapter::stream_socket(&stream);
            let mut request = new_request_header(
                Command::Tcp,
                Some(destination.clone()),
                self.security,
            )?;
            request.option |= self.body_options();
            request.legacy_header = self.alter_key.is_some();
            write_request_with_clock(
                &mut stream,
                &self.command_key,
                self.alter_key.as_ref(),
                &request,
                self.clock.as_ref(),
            )
            .await?;
            read_response(&mut stream, &request).await?;
            let stream = wrap_body_stream(stream, &request, false)?;
            Ok(crate::adapter::preserve_stream_socket(stream, socket))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let mut stream = self.upstream.dial_tcp(&self.server).await?;
            if self.xudp {
                let mut request =
                    new_request_header(Command::Mux, None, self.security)?;
                request.option |= self.body_options();
                request.legacy_header = self.alter_key.is_some();
                write_request_with_clock(
                    &mut stream,
                    &self.command_key,
                    self.alter_key.as_ref(),
                    &request,
                    self.clock.as_ref(),
                )
                .await?;
                read_response(&mut stream, &request).await?;
                let stream = wrap_body_stream(stream, &request, false)?;
                return Ok(Box::new(
                    crate::protocol::vless::XudpPacketConnection::new(
                        stream,
                        destination.clone(),
                    ),
                ) as PacketStream);
            }
            let request_destination = if self.packet_addr {
                if destination.is_domain() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "packetaddr does not support domain destinations",
                    ));
                }
                SocksAddr::new(crate::protocol::packetaddr::MAGIC_ADDRESS, 0)
            } else {
                destination.clone()
            };
            let mut request = new_request_header(
                Command::Udp,
                Some(request_destination.clone()),
                self.security,
            )?;
            request.option |= self.body_options();
            request.legacy_header = self.alter_key.is_some();
            write_request_with_clock(
                &mut stream,
                &self.command_key,
                self.alter_key.as_ref(),
                &request,
                self.clock.as_ref(),
            )
            .await?;
            let packet: PacketStream = Box::new(VmessPacketConnection::new(
                stream,
                request,
                request_destination,
                false,
            ));
            if self.packet_addr {
                Ok(Box::new(
                    crate::protocol::packetaddr::PacketAddrConnection::new(
                        packet,
                    ),
                ) as PacketStream)
            } else {
                Ok(packet)
            }
        })
    }
}

impl VmessOutbound {
    fn body_options(&self) -> u8 {
        if matches!(
            self.security,
            Security::None | Security::Zero | Security::Legacy
        ) {
            return 0;
        }
        let mut option = 0;
        if self.global_padding {
            option |= OPTION_GLOBAL_PADDING;
        }
        if self.authenticated_length {
            option |= OPTION_AUTHENTICATED_LENGTH;
        }
        option
    }
}

pub struct VmessPacketConnection {
    reader: Mutex<(ReadHalf<Stream>, bool, BodyDecoder)>,
    writer: Mutex<(WriteHalf<Stream>, bool, BodyEncoder)>,
    request: RequestHeader,
    destination: SocksAddr,
    server_side: bool,
}

impl VmessPacketConnection {
    pub fn new(
        stream: Stream,
        request: RequestHeader,
        destination: SocksAddr,
        server_side: bool,
    ) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        let (read_key, read_nonce, write_key, write_nonce) =
            body_direction_keys(&request, server_side);
        Self {
            reader: Mutex::new((
                reader,
                false,
                BodyDecoder::new(
                    request.security,
                    request.option,
                    read_key,
                    read_nonce,
                    request.request_key,
                    request.request_nonce,
                )
                .expect("validated VMess body decoder"),
            )),
            writer: Mutex::new((
                writer,
                false,
                BodyEncoder::new(
                    request.security,
                    request.option,
                    write_key,
                    write_nonce,
                    request.request_key,
                    request.request_nonce,
                )
                .expect("validated VMess body encoder"),
            )),
            request,
            destination,
            server_side,
        }
    }
}

impl PacketConnection for VmessPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let mut writer = self.writer.lock().await;
            if self.server_side && !writer.1 {
                write_response(&mut writer.0, &self.request).await?;
                writer.1 = true;
            }
            let frame = writer.2.encode(data)?;
            writer.0.write_all(&frame).await?;
            writer.0.flush().await?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut reader = self.reader.lock().await;
            if !self.server_side && !reader.1 {
                read_response(&mut reader.0, &self.request).await?;
                reader.1 = true;
            }
            let (stream, _, decoder) = &mut *reader;
            let packet = decoder.decode_from(stream).await?;
            if packet.len() > data.len() {
                return Err(invalid_data(
                    "VMess UDP payload exceeds receive buffer",
                ));
            }
            data[..packet.len()].copy_from_slice(&packet);
            Ok((packet.len(), self.destination.clone()))
        })
    }
}

const BODY_CHUNK_SIZE: usize = 15_000;

fn auto_security() -> Security {
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "s390x"
    ))]
    {
        Security::Aes128Gcm
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "s390x"
    )))]
    {
        Security::Chacha20Poly1305
    }
}

fn body_security(value: u8) -> io::Result<Security> {
    match value {
        1 => Ok(Security::Legacy),
        3 => Ok(Security::Aes128Gcm),
        4 => Ok(Security::Chacha20Poly1305),
        5 | 6 => Ok(Security::None),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported VMess body security: {value}"),
        )),
    }
}

fn masking_reader(nonce: [u8; 16], option: u8) -> Option<Shake128Reader> {
    if option & (OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING) == 0 {
        return None;
    }
    let mut shake = Shake128::default();
    sha3::digest::Update::update(&mut shake, &nonce);
    Some(shake.finalize_xof())
}

struct BodyEncoder {
    security: Security,
    key: [u8; 16],
    nonce: [u8; 16],
    counter: u16,
    option: u8,
    masking: Option<Shake128Reader>,
    authenticated_key: Option<[u8; 16]>,
    authenticated_nonce: [u8; 16],
    authenticated_counter: u16,
    cfb: Option<AesCfb>,
}

impl BodyEncoder {
    fn new(
        security: u8,
        option: u8,
        key: [u8; 16],
        nonce: [u8; 16],
        request_key: [u8; 16],
        request_nonce: [u8; 16],
    ) -> io::Result<Self> {
        let security = body_security(security)?;
        if option & OPTION_AUTHENTICATED_LENGTH != 0
            && security == Security::None
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "authenticated VMess length requires an AEAD body",
            ));
        }
        let authenticated_key = (option & OPTION_AUTHENTICATED_LENGTH != 0)
            .then(|| {
                kdf(&request_key, AUTHENTICATED_LENGTH_KEY, &[])[..16]
                    .try_into()
                    .unwrap()
            });
        Ok(Self {
            security,
            key,
            nonce,
            counter: 0,
            option,
            masking: masking_reader(nonce, option),
            authenticated_key,
            authenticated_nonce: request_nonce,
            authenticated_counter: 0,
            cfb: (security == Security::Legacy)
                .then(|| AesCfb::new(key, nonce, true)),
        })
    }

    fn next_mask(&mut self) -> u16 {
        let mut value = [0_u8; 2];
        self.masking.as_mut().unwrap().read(&mut value);
        u16::from_be_bytes(value)
    }

    fn encode(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let payload = match self.security {
            Security::None => plaintext.to_vec(),
            Security::Legacy => {
                let mut payload = Vec::with_capacity(4 + plaintext.len());
                payload.extend_from_slice(&fnv1a(plaintext).to_be_bytes());
                payload.extend_from_slice(plaintext);
                payload
            }
            Security::Aes128Gcm => {
                let mut nonce = self.nonce[..12].to_vec();
                nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
                self.counter = self.counter.wrapping_add(1);
                seal_aes_gcm(&self.key, &nonce, plaintext, &[])?
            }
            Security::Chacha20Poly1305 => {
                let mut nonce = self.nonce[..12].to_vec();
                nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
                self.counter = self.counter.wrapping_add(1);
                seal_chacha20_poly1305(&self.key, &nonce, plaintext)?
            }
            _ => unreachable!("body security was validated"),
        };
        let padding_length = if self.option & OPTION_GLOBAL_PADDING != 0 {
            self.next_mask() % 64
        } else {
            0
        };
        let mut output =
            Vec::with_capacity(2 + payload.len() + usize::from(padding_length));
        let total_length = payload.len() + usize::from(padding_length);
        if let Some(key) = self.authenticated_key {
            let plain_length =
                total_length.checked_sub(CIPHER_OVERHEAD).ok_or_else(|| {
                    invalid_input("invalid authenticated VMess chunk length")
                })?;
            let length = u16::try_from(plain_length).map_err(|_| {
                invalid_input("VMess body chunk exceeds 65535 bytes")
            })?;
            let mut nonce = self.authenticated_nonce[..12].to_vec();
            nonce[..2]
                .copy_from_slice(&self.authenticated_counter.to_be_bytes());
            self.authenticated_counter =
                self.authenticated_counter.wrapping_add(1);
            let encrypted = match self.security {
                Security::Aes128Gcm => {
                    seal_aes_gcm(&key, &nonce, &length.to_be_bytes(), &[])?
                }
                Security::Chacha20Poly1305 => {
                    seal_chacha20_poly1305(&key, &nonce, &length.to_be_bytes())?
                }
                _ => unreachable!("authenticated length requires AEAD"),
            };
            output.extend_from_slice(&encrypted);
        } else {
            let mut length = u16::try_from(total_length).map_err(|_| {
                invalid_input("VMess body chunk exceeds 65535 bytes")
            })?;
            if self.option & OPTION_CHUNK_MASKING != 0 {
                length ^= self.next_mask();
            }
            output.extend_from_slice(&length.to_be_bytes());
        }
        output.extend_from_slice(&payload);
        if padding_length != 0 {
            let start = output.len();
            output.resize(start + usize::from(padding_length), 0);
            getrandom::fill(&mut output[start..]).map_err(random_error)?;
        }
        if let Some(cfb) = &mut self.cfb {
            cfb.apply(&mut output);
        }
        Ok(output)
    }
}

struct BodyDecoder {
    security: Security,
    key: [u8; 16],
    nonce: [u8; 16],
    counter: u16,
    option: u8,
    masking: Option<Shake128Reader>,
    authenticated_key: Option<[u8; 16]>,
    authenticated_nonce: [u8; 16],
    authenticated_counter: u16,
    cfb: Option<AesCfb>,
}

impl BodyDecoder {
    fn new(
        security: u8,
        option: u8,
        key: [u8; 16],
        nonce: [u8; 16],
        request_key: [u8; 16],
        request_nonce: [u8; 16],
    ) -> io::Result<Self> {
        let security = body_security(security)?;
        if option & OPTION_AUTHENTICATED_LENGTH != 0
            && security == Security::None
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "authenticated VMess length requires an AEAD body",
            ));
        }
        let authenticated_key = (option & OPTION_AUTHENTICATED_LENGTH != 0)
            .then(|| {
                kdf(&request_key, AUTHENTICATED_LENGTH_KEY, &[])[..16]
                    .try_into()
                    .unwrap()
            });
        Ok(Self {
            security,
            key,
            nonce,
            counter: 0,
            option,
            masking: masking_reader(nonce, option),
            authenticated_key,
            authenticated_nonce: request_nonce,
            authenticated_counter: 0,
            cfb: (security == Security::Legacy)
                .then(|| AesCfb::new(key, nonce, false)),
        })
    }

    fn next_mask(&mut self) -> u16 {
        let mut value = [0_u8; 2];
        self.masking.as_mut().unwrap().read(&mut value);
        u16::from_be_bytes(value)
    }

    async fn decode_from<R>(&mut self, reader: &mut R) -> io::Result<Vec<u8>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        let mut length =
            if let Some(key) = self.authenticated_key {
                let mut encrypted = [0_u8; 2 + CIPHER_OVERHEAD];
                reader.read_exact(&mut encrypted).await?;
                let mut nonce = self.authenticated_nonce[..12].to_vec();
                nonce[..2]
                    .copy_from_slice(&self.authenticated_counter.to_be_bytes());
                self.authenticated_counter =
                    self.authenticated_counter.wrapping_add(1);
                let plain = match self.security {
                    Security::Aes128Gcm => {
                        open_aes_gcm(&key, &nonce, &encrypted, &[])?
                    }
                    Security::Chacha20Poly1305 => {
                        open_chacha20_poly1305(&key, &nonce, &encrypted)?
                    }
                    _ => unreachable!("authenticated length requires AEAD"),
                };
                u16::from_be_bytes(plain.as_slice().try_into().map_err(
                    |_| invalid_data("invalid VMess length plaintext"),
                )?)
                .checked_add(CIPHER_OVERHEAD as u16)
                .ok_or_else(|| invalid_data("VMess body length overflow"))?
            } else {
                let mut raw_length = [0_u8; 2];
                reader.read_exact(&mut raw_length).await?;
                if let Some(cfb) = &mut self.cfb {
                    cfb.apply(&mut raw_length);
                }
                u16::from_be_bytes(raw_length)
            };
        let padding_length = if self.option & OPTION_GLOBAL_PADDING != 0 {
            self.next_mask() % 64
        } else {
            0
        };
        if self.authenticated_key.is_none()
            && self.option & OPTION_CHUNK_MASKING != 0
        {
            length ^= self.next_mask();
        }
        let payload_length = usize::from(length)
            .checked_sub(usize::from(padding_length))
            .ok_or_else(|| invalid_data("invalid VMess body padding length"))?;
        if payload_length == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        let mut wire = vec![0_u8; usize::from(length)];
        reader.read_exact(&mut wire).await?;
        if let Some(cfb) = &mut self.cfb {
            cfb.apply(&mut wire);
        }
        wire.truncate(payload_length);
        match self.security {
            Security::None => Ok(wire),
            Security::Legacy => {
                if wire.len() < 4 {
                    return Err(invalid_data(
                        "VMess legacy chunk is too short",
                    ));
                }
                let expected =
                    u32::from_be_bytes(wire[..4].try_into().unwrap());
                let payload = wire[4..].to_vec();
                if fnv1a(&payload) != expected {
                    return Err(invalid_data(
                        "invalid VMess legacy chunk checksum",
                    ));
                }
                Ok(payload)
            }
            Security::Aes128Gcm => {
                let mut nonce = self.nonce[..12].to_vec();
                nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
                self.counter = self.counter.wrapping_add(1);
                open_aes_gcm(&self.key, &nonce, &wire, &[])
            }
            Security::Chacha20Poly1305 => {
                let mut nonce = self.nonce[..12].to_vec();
                nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
                self.counter = self.counter.wrapping_add(1);
                open_chacha20_poly1305(&self.key, &nonce, &wire)
            }
            _ => unreachable!("body security was validated"),
        }
    }
}

struct AesCfb {
    cipher: Aes128,
    feedback: [u8; 16],
    keystream: [u8; 16],
    position: usize,
    encrypt: bool,
}

impl AesCfb {
    fn new(key: [u8; 16], nonce: [u8; 16], encrypt: bool) -> Self {
        Self {
            cipher: Aes128::new_from_slice(&key).expect("fixed AES key"),
            feedback: nonce,
            keystream: [0; 16],
            position: 0,
            encrypt,
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.position == 0 {
                let mut block = Block::<Aes128>::from(self.feedback);
                self.cipher.encrypt_block(&mut block);
                self.keystream = block.into();
            }
            let input = *byte;
            *byte ^= self.keystream[self.position];
            self.feedback[self.position] =
                if self.encrypt { *byte } else { input };
            self.position = (self.position + 1) % 16;
        }
    }
}

fn body_direction_keys(
    request: &RequestHeader,
    server_side: bool,
) -> ([u8; 16], [u8; 16], [u8; 16], [u8; 16]) {
    let response = response_key_nonce(request);
    if server_side {
        (
            request.request_key,
            request.request_nonce,
            response.0,
            response.1,
        )
    } else {
        (
            response.0,
            response.1,
            request.request_key,
            request.request_nonce,
        )
    }
}

pub fn wrap_body_stream(
    stream: Stream,
    request: &RequestHeader,
    server_side: bool,
) -> io::Result<Stream> {
    if request.option & OPTION_CHUNK_STREAM == 0
        && request.security == Security::None.wire()
    {
        return Ok(stream);
    }
    let (read_key, read_nonce, write_key, write_nonce) =
        body_direction_keys(request, server_side);
    let mut decoder = BodyDecoder::new(
        request.security,
        request.option,
        read_key,
        read_nonce,
        request.request_key,
        request.request_nonce,
    )?;
    let mut encoder = BodyEncoder::new(
        request.security,
        request.option,
        write_key,
        write_nonce,
        request.request_key,
        request.request_nonce,
    )?;
    let (network_reader, network_writer) = tokio::io::split(stream);
    let (application, bridge) = tokio::io::duplex(BODY_CHUNK_SIZE * 2);
    let (mut bridge_reader, mut bridge_writer) = tokio::io::split(bridge);
    tokio::spawn(async move {
        let mut network_reader = network_reader;
        while let Ok(chunk) = decoder.decode_from(&mut network_reader).await {
            if bridge_writer.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = bridge_writer.shutdown().await;
    });
    tokio::spawn(async move {
        let mut network_writer = network_writer;
        let mut buffer = vec![0_u8; BODY_CHUNK_SIZE];
        loop {
            let size = match bridge_reader.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(size) => size,
            };
            let frame = match encoder.encode(&buffer[..size]) {
                Ok(frame) => frame,
                Err(_) => break,
            };
            if network_writer.write_all(&frame).await.is_err() {
                break;
            }
            if network_writer.flush().await.is_err() {
                break;
            }
        }
        let _ = network_writer.shutdown().await;
    });
    Ok(Box::new(application))
}

trait VmessHash: Send + Sync {
    fn clone_state(&self) -> Box<dyn VmessHash>;
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> [u8; 32];
}

struct Sha256Hash(Sha256);

impl VmessHash for Sha256Hash {
    fn clone_state(&self) -> Box<dyn VmessHash> {
        Box::new(Self(self.0.clone()))
    }

    fn update(&mut self, data: &[u8]) {
        sha2::Digest::update(&mut self.0, data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        sha2::Digest::finalize(self.0.clone()).into()
    }
}

struct RecursiveHash {
    inner: Box<dyn VmessHash>,
    outer: Box<dyn VmessHash>,
    inner_pad: [u8; 64],
    outer_pad: [u8; 64],
}

impl RecursiveHash {
    fn new(key: &[u8], hash: Box<dyn VmessHash>) -> Self {
        debug_assert!(key.len() <= 64);
        let mut inner_pad = [0x36; 64];
        let mut outer_pad = [0x5c; 64];
        for (index, value) in key.iter().copied().enumerate() {
            inner_pad[index] ^= value;
            outer_pad[index] ^= value;
        }
        let mut inner = hash.clone_state();
        inner.update(&inner_pad);
        Self {
            inner,
            outer: hash,
            inner_pad,
            outer_pad,
        }
    }
}

impl VmessHash for RecursiveHash {
    fn clone_state(&self) -> Box<dyn VmessHash> {
        Box::new(Self {
            inner: self.inner.clone_state(),
            outer: self.outer.clone_state(),
            inner_pad: self.inner_pad,
            outer_pad: self.outer_pad,
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        self.outer.update(&self.outer_pad);
        let inner = self.inner.finalize();
        self.outer.update(&inner);
        self.outer.finalize()
    }
}

/// VMess's recursively nested HMAC-SHA256 KDF.
pub fn kdf(key: &[u8], salt: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut hash: Box<dyn VmessHash> = Box::new(RecursiveHash::new(
        KDF_SALT,
        Box::new(Sha256Hash(Sha256::new())),
    ));
    hash = Box::new(RecursiveHash::new(salt, hash));
    for item in path {
        hash = Box::new(RecursiveHash::new(item, hash));
    }
    hash.update(key);
    hash.finalize()
}

pub fn user_id(value: &str) -> Uuid {
    Uuid::parse_str(value)
        .unwrap_or_else(|_| Uuid::new_v5(&Uuid::nil(), value.as_bytes()))
}

pub fn command_key(user: Uuid) -> [u8; 16] {
    let mut md5 = Md5::new();
    md5.update(user.as_bytes());
    md5.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    md5.finalize().into()
}

pub fn alter_id(user: Uuid) -> Uuid {
    let mut md5 = Md5::new();
    md5.update(user.as_bytes());
    md5.update(b"16167dc8-16b6-4e6d-b8bb-65dd68113a81");
    loop {
        let value: [u8; 16] = md5.clone().finalize().into();
        if value != *user.as_bytes() {
            return Uuid::from_bytes(value);
        }
        md5.update(b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2");
    }
}

pub fn alter_id_key(user: Uuid, index: usize) -> [u8; 16] {
    let mut current = user;
    for _ in 0..index {
        current = alter_id(current);
    }
    *current.as_bytes()
}

pub fn auth_id(
    command_key: &[u8; 16],
    unix_time: u64,
    random: [u8; 4],
) -> [u8; 16] {
    let mut plain = [0_u8; 16];
    plain[..8].copy_from_slice(&unix_time.to_be_bytes());
    plain[8..12].copy_from_slice(&random);
    let checksum = crc32(&plain[..12]);
    plain[12..].copy_from_slice(&checksum.to_be_bytes());
    let key = kdf(command_key, AUTH_ID_ENCRYPTION_KEY, &[]);
    let cipher = Aes128::new_from_slice(&key[..16]).expect("fixed AES key");
    let mut block = Block::<Aes128>::from(plain);
    cipher.encrypt_block(&mut block);
    block.into()
}

pub fn verify_auth_id(
    command_key: &[u8; 16],
    auth_id: &[u8; 16],
    unix_time: u64,
) -> bool {
    let key = kdf(command_key, AUTH_ID_ENCRYPTION_KEY, &[]);
    let cipher = Aes128::new_from_slice(&key[..16]).expect("fixed AES key");
    let mut block = Block::<Aes128>::from(*auth_id);
    cipher.decrypt_block(&mut block);
    let plain: [u8; 16] = block.into();
    let timestamp = u64::from_be_bytes(plain[..8].try_into().unwrap());
    crc32(&plain[..12]) == u32::from_be_bytes(plain[12..].try_into().unwrap())
        && timestamp.abs_diff(unix_time) <= 120
}

pub fn encode_request_header(
    request: &RequestHeader,
    padding: &[u8],
) -> io::Result<Vec<u8>> {
    if padding.len() > 15 {
        return Err(invalid_input("VMess header padding exceeds 15 bytes"));
    }
    let mut header = Vec::with_capacity(64);
    header.push(VERSION);
    header.extend_from_slice(&request.request_nonce);
    header.extend_from_slice(&request.request_key);
    header.push(request.response_header);
    header.push(request.option);
    header.push((padding.len() as u8) << 4 | (request.security & 0x0f));
    header.push(0);
    header.push(request.command as u8);
    if request.command != Command::Mux {
        encode_address(
            &mut header,
            request.destination.as_ref().ok_or_else(|| {
                invalid_input("VMess request command requires a destination")
            })?,
        )?;
    }
    header.extend_from_slice(padding);
    header.extend_from_slice(&fnv1a(&header).to_be_bytes());
    Ok(header)
}

pub fn decode_request_header(header: &[u8]) -> io::Result<RequestHeader> {
    if header.len() < 42 {
        return Err(invalid_data("VMess request header is too short"));
    }
    let (payload, checksum) = header.split_at(header.len() - 4);
    if fnv1a(payload) != u32::from_be_bytes(checksum.try_into().unwrap()) {
        return Err(invalid_data("invalid VMess request header checksum"));
    }
    if payload[0] != VERSION {
        return Err(invalid_data(format!(
            "unknown VMess version: {}",
            payload[0]
        )));
    }
    let request_nonce = payload[1..17].try_into().unwrap();
    let request_key = payload[17..33].try_into().unwrap();
    let response_header = payload[33];
    let option = payload[34];
    let padding_length = (payload[35] >> 4) as usize;
    let security = payload[35] & 0x0f;
    let command = Command::parse(payload[37])?;
    let mut cursor = 38;
    let destination = if command == Command::Mux {
        None
    } else {
        Some(decode_address(payload, &mut cursor)?)
    };
    let expected = cursor
        .checked_add(padding_length)
        .ok_or_else(|| invalid_data("VMess padding length overflow"))?;
    if expected != payload.len() {
        return Err(invalid_data("invalid VMess request padding length"));
    }
    Ok(RequestHeader {
        request_nonce,
        request_key,
        response_header,
        option,
        security,
        command,
        destination,
        legacy_header: false,
    })
}

pub fn seal_request_header(
    command_key: &[u8; 16],
    auth_id: [u8; 16],
    connection_nonce: [u8; 8],
    header: &[u8],
) -> io::Result<Vec<u8>> {
    let length = u16::try_from(header.len()).map_err(|_| {
        invalid_input("VMess request header exceeds 65535 bytes")
    })?;
    let length_key = kdf(
        command_key,
        HEADER_LENGTH_KEY,
        &[&auth_id, &connection_nonce],
    );
    let length_nonce = kdf(
        command_key,
        HEADER_LENGTH_NONCE,
        &[&auth_id, &connection_nonce],
    );
    let encrypted_length = seal_aes_gcm(
        &length_key[..16],
        &length_nonce[..12],
        &length.to_be_bytes(),
        &auth_id,
    )?;
    let payload_key = kdf(
        command_key,
        HEADER_PAYLOAD_KEY,
        &[&auth_id, &connection_nonce],
    );
    let payload_nonce = kdf(
        command_key,
        HEADER_PAYLOAD_NONCE,
        &[&auth_id, &connection_nonce],
    );
    let encrypted_header = seal_aes_gcm(
        &payload_key[..16],
        &payload_nonce[..12],
        header,
        &auth_id,
    )?;
    let mut output = Vec::with_capacity(
        16 + encrypted_length.len() + 8 + encrypted_header.len(),
    );
    output.extend_from_slice(&auth_id);
    output.extend_from_slice(&encrypted_length);
    output.extend_from_slice(&connection_nonce);
    output.extend_from_slice(&encrypted_header);
    Ok(output)
}

pub fn open_request_header(
    command_key: &[u8; 16],
    request: &[u8],
    unix_time: u64,
) -> io::Result<(RequestHeader, usize)> {
    const PREFIX: usize = 16 + 2 + CIPHER_OVERHEAD + 8;
    if request.len() < PREFIX {
        return Err(invalid_data("VMess AEAD request is too short"));
    }
    let auth: [u8; 16] = request[..16].try_into().unwrap();
    if !verify_auth_id(command_key, &auth, unix_time) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid VMess auth ID",
        ));
    }
    let connection_nonce: [u8; 8] = request[34..42].try_into().unwrap();
    let length_key =
        kdf(command_key, HEADER_LENGTH_KEY, &[&auth, &connection_nonce]);
    let length_nonce = kdf(
        command_key,
        HEADER_LENGTH_NONCE,
        &[&auth, &connection_nonce],
    );
    let length = open_aes_gcm(
        &length_key[..16],
        &length_nonce[..12],
        &request[16..34],
        &auth,
    )?;
    if length.len() != 2 {
        return Err(invalid_data("invalid VMess header length plaintext"));
    }
    let length = u16::from_be_bytes(length.try_into().unwrap()) as usize;
    let end = PREFIX
        .checked_add(length + CIPHER_OVERHEAD)
        .ok_or_else(|| invalid_data("VMess header length overflow"))?;
    if request.len() < end {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete VMess AEAD request header",
        ));
    }
    let payload_key =
        kdf(command_key, HEADER_PAYLOAD_KEY, &[&auth, &connection_nonce]);
    let payload_nonce = kdf(
        command_key,
        HEADER_PAYLOAD_NONCE,
        &[&auth, &connection_nonce],
    );
    let header = open_aes_gcm(
        &payload_key[..16],
        &payload_nonce[..12],
        &request[PREFIX..end],
        &auth,
    )?;
    Ok((decode_request_header(&header)?, end))
}

fn open_request_length(
    command_key: &[u8; 16],
    prefix: &[u8],
) -> io::Result<usize> {
    if prefix.len() < 42 {
        return Err(invalid_data("VMess AEAD request prefix is too short"));
    }
    let auth: [u8; 16] = prefix[..16].try_into().unwrap();
    let connection_nonce: [u8; 8] = prefix[34..42].try_into().unwrap();
    let length_key =
        kdf(command_key, HEADER_LENGTH_KEY, &[&auth, &connection_nonce]);
    let length_nonce = kdf(
        command_key,
        HEADER_LENGTH_NONCE,
        &[&auth, &connection_nonce],
    );
    let length = open_aes_gcm(
        &length_key[..16],
        &length_nonce[..12],
        &prefix[16..34],
        &auth,
    )?;
    if length.len() != 2 {
        return Err(invalid_data("invalid VMess request header length"));
    }
    Ok(u16::from_be_bytes(length.try_into().unwrap()) as usize)
}

pub fn seal_response_header(request: &RequestHeader) -> io::Result<Vec<u8>> {
    let (key, nonce) = response_key_nonce(request);
    let length_key = kdf(&key, RESPONSE_LENGTH_KEY, &[]);
    let length_nonce = kdf(&nonce, RESPONSE_LENGTH_NONCE, &[]);
    let encrypted_length = seal_aes_gcm(
        &length_key[..16],
        &length_nonce[..12],
        &4_u16.to_be_bytes(),
        &[],
    )?;
    let payload_key = kdf(&key, RESPONSE_PAYLOAD_KEY, &[]);
    let payload_nonce = kdf(&nonce, RESPONSE_PAYLOAD_NONCE, &[]);
    let encrypted_payload = seal_aes_gcm(
        &payload_key[..16],
        &payload_nonce[..12],
        &[request.response_header, request.option, 0, 0],
        &[],
    )?;
    let mut response = Vec::with_capacity(38);
    response.extend_from_slice(&encrypted_length);
    response.extend_from_slice(&encrypted_payload);
    Ok(response)
}

pub fn open_response_header(
    request: &RequestHeader,
    response: &[u8],
) -> io::Result<usize> {
    if response.len() < 2 + CIPHER_OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete VMess response length",
        ));
    }
    let (key, nonce) = response_key_nonce(request);
    let length_key = kdf(&key, RESPONSE_LENGTH_KEY, &[]);
    let length_nonce = kdf(&nonce, RESPONSE_LENGTH_NONCE, &[]);
    let length = open_aes_gcm(
        &length_key[..16],
        &length_nonce[..12],
        &response[..18],
        &[],
    )?;
    if length.len() != 2 {
        return Err(invalid_data("invalid VMess response header length"));
    }
    let length = u16::from_be_bytes(length.try_into().unwrap()) as usize;
    let end = 18_usize
        .checked_add(length + CIPHER_OVERHEAD)
        .ok_or_else(|| invalid_data("VMess response length overflow"))?;
    if response.len() < end {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete VMess response header",
        ));
    }
    let payload_key = kdf(&key, RESPONSE_PAYLOAD_KEY, &[]);
    let payload_nonce = kdf(&nonce, RESPONSE_PAYLOAD_NONCE, &[]);
    let payload = open_aes_gcm(
        &payload_key[..16],
        &payload_nonce[..12],
        &response[18..end],
        &[],
    )?;
    if payload.len() < 4 || payload[0] != request.response_header {
        return Err(invalid_data("invalid VMess response header"));
    }
    let command_length = payload[3] as usize;
    if payload.len() != 4 + command_length {
        return Err(invalid_data("invalid VMess response command length"));
    }
    Ok(end)
}

fn open_response_length(
    request: &RequestHeader,
    response: &[u8],
) -> io::Result<usize> {
    if response.len() < 18 {
        return Err(invalid_data("VMess response length is too short"));
    }
    let (key, nonce) = response_key_nonce(request);
    let length_key = kdf(&key, RESPONSE_LENGTH_KEY, &[]);
    let length_nonce = kdf(&nonce, RESPONSE_LENGTH_NONCE, &[]);
    let length = open_aes_gcm(
        &length_key[..16],
        &length_nonce[..12],
        &response[..18],
        &[],
    )?;
    if length.len() != 2 {
        return Err(invalid_data("invalid VMess response header length"));
    }
    Ok(u16::from_be_bytes(length.try_into().unwrap()) as usize)
}

fn response_key_nonce(request: &RequestHeader) -> ([u8; 16], [u8; 16]) {
    if request.legacy_header {
        return (
            Md5::digest(request.request_key).into(),
            Md5::digest(request.request_nonce).into(),
        );
    }
    let key_hash: [u8; 32] = Sha256::digest(request.request_key).into();
    let nonce_hash: [u8; 32] = Sha256::digest(request.request_nonce).into();
    (
        key_hash[..16].try_into().unwrap(),
        nonce_hash[..16].try_into().unwrap(),
    )
}

fn seal_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|_| invalid_input("invalid VMess AES key length"))?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| invalid_input("invalid VMess AES nonce length"))?;
    cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| invalid_data("VMess AES-GCM encryption failed"))
}

fn open_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|_| invalid_input("invalid VMess AES key length"))?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| invalid_input("invalid VMess AES nonce length"))?;
    cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| invalid_data("VMess AES-GCM authentication failed"))
}

fn chacha20_poly1305_key(key: &[u8; 16]) -> [u8; 32] {
    let first: [u8; 16] = Md5::digest(key).into();
    let second: [u8; 16] = Md5::digest(first).into();
    let mut output = [0_u8; 32];
    output[..16].copy_from_slice(&first);
    output[16..].copy_from_slice(&second);
    output
}

fn seal_chacha20_poly1305(
    key: &[u8; 16],
    nonce: &[u8],
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(&chacha20_poly1305_key(key))
        .map_err(|_| invalid_input("invalid VMess ChaCha20 key length"))?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| invalid_input("invalid VMess ChaCha20 nonce length"))?;
    cipher
        .encrypt((&nonce).into(), plaintext)
        .map_err(|_| invalid_data("VMess ChaCha20-Poly1305 encryption failed"))
}

fn open_chacha20_poly1305(
    key: &[u8; 16],
    nonce: &[u8],
    ciphertext: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(&chacha20_poly1305_key(key))
        .map_err(|_| invalid_input("invalid VMess ChaCha20 key length"))?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| invalid_input("invalid VMess ChaCha20 nonce length"))?;
    cipher.decrypt((&nonce).into(), ciphertext).map_err(|_| {
        invalid_data("VMess ChaCha20-Poly1305 authentication failed")
    })
}

fn encode_address(output: &mut Vec<u8>, address: &SocksAddr) -> io::Result<()> {
    output.extend_from_slice(&address.port().to_be_bytes());
    match address {
        SocksAddr::Ip(address) => match address.ip() {
            IpAddr::V4(ip) => {
                output.push(1);
                output.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                output.push(3);
                output.extend_from_slice(&ip.octets());
            }
        },
        SocksAddr::Domain { host, .. } => {
            output.push(2);
            output.push(u8::try_from(host.len()).map_err(|_| {
                invalid_input("VMess domain is longer than 255 bytes")
            })?);
            output.extend_from_slice(host.as_bytes());
        }
    }
    Ok(())
}

fn decode_address(input: &[u8], cursor: &mut usize) -> io::Result<SocksAddr> {
    if input.len() < *cursor + 3 {
        return Err(invalid_data("truncated VMess destination"));
    }
    let port =
        u16::from_be_bytes(input[*cursor..*cursor + 2].try_into().unwrap());
    *cursor += 2;
    let family = input[*cursor];
    *cursor += 1;
    let host = match family {
        1 => {
            let value = take(input, cursor, 4)?;
            IpAddr::from(<[u8; 4]>::try_from(value).unwrap()).to_string()
        }
        3 => {
            let value = take(input, cursor, 16)?;
            IpAddr::from(<[u8; 16]>::try_from(value).unwrap()).to_string()
        }
        2 => {
            let length = *take(input, cursor, 1)?.first().unwrap() as usize;
            String::from_utf8(take(input, cursor, length)?.to_vec())
                .map_err(|_| invalid_data("VMess domain is not UTF-8"))?
        }
        _ => {
            return Err(invalid_data(format!(
                "unknown VMess address type: {family}"
            )));
        }
    };
    Ok(SocksAddr::new(host, port))
}

fn take<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> io::Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| invalid_data("VMess address length overflow"))?;
    let value = input
        .get(*cursor..end)
        .ok_or_else(|| invalid_data("truncated VMess address"))?;
    *cursor = end;
    Ok(value)
}

fn fnv1a(input: &[u8]) -> u32 {
    input.iter().fold(2_166_136_261, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(16_777_619)
    })
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn random_error(error: getrandom::Error) -> io::Error {
    io::Error::other(format!("generate VMess randomness: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const NOW: u64 = 1_700_000_000;

    #[test]
    fn command_key_and_kdf_match_go_sing_vmess_vectors() {
        let key = command_key(user_id(USER));
        assert_eq!(hex::encode(key), "d34482dca079f1e8ad37ff8d08a382cf");
        assert_eq!(
            hex::encode(kdf(&key, AUTH_ID_ENCRYPTION_KEY, &[])),
            "870e934a0d8e955ec8df4c2ee2390b5d4e44e24acacff61a7c9b53425d5a8974"
        );
        assert_eq!(
            hex::encode(kdf(
                &key,
                HEADER_LENGTH_KEY,
                &[b"0123456789abcdef", b"12345678"]
            )),
            "0aa0d909e6cc6c4f172c390eb10514769735a78aa95e5e5247aa1440854f6969"
        );
        assert_eq!(
            hex::encode(kdf(
                &key,
                HEADER_LENGTH_NONCE,
                &[b"0123456789abcdef", b"12345678"]
            )),
            "dea610168f6794895250e363086c54f485e7b764172ffebbd1cf255930a5fb64"
        );
    }

    #[test]
    fn auth_id_validates_checksum_and_time_window() {
        let key = command_key(user_id(USER));
        let id = auth_id(&key, NOW, [1, 2, 3, 4]);
        assert!(verify_auth_id(&key, &id, NOW + 120));
        assert!(!verify_auth_id(&key, &id, NOW + 121));
        let mut damaged = id;
        damaged[7] ^= 1;
        assert!(!verify_auth_id(&key, &damaged, NOW));
    }

    #[tokio::test]
    async fn request_authentication_uses_ntp_clock() {
        let key = command_key(user_id(USER));
        let clock = NtpClock::default();
        let system_unix_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;
        let target_unix_nanos = i128::from(NOW) * 1_000_000_000;
        clock.update(crate::common::ntp::NtpSample {
            offset_nanos: i64::try_from(target_unix_nanos - system_unix_nanos)
                .unwrap(),
            round_trip_nanos: 1,
            stratum: 1,
        });
        let request = new_request_header(
            Command::Tcp,
            Some(SocksAddr::new("example.com", 443)),
            Security::None,
        )
        .unwrap();
        let mut wire = Vec::new();
        write_request_with_clock(&mut wire, &key, None, &request, Some(&clock))
            .await
            .unwrap();

        let mut system_input = wire.as_slice();
        assert!(
            read_request(&mut system_input, &[key], &[vec![]])
                .await
                .is_err()
        );
        let mut corrected_input = wire.as_slice();
        let (decoded, user, _) = read_request_with_clock(
            &mut corrected_input,
            &[key],
            &[vec![]],
            Some(&clock),
        )
        .await
        .unwrap();
        assert_eq!(user, 0);
        assert_eq!(decoded.destination, request.destination);
    }

    #[test]
    fn aead_request_header_round_trips_all_address_families() {
        let key = command_key(user_id(USER));
        for destination in [
            SocksAddr::new("192.0.2.1", 443),
            SocksAddr::new("2001:db8::1", 53),
            SocksAddr::new("example.com", 8443),
        ] {
            let header = RequestHeader {
                request_nonce: [0x11; 16],
                request_key: [0x22; 16],
                response_header: 0x33,
                option: OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING,
                security: Security::Aes128Gcm.wire(),
                command: Command::Tcp,
                destination: Some(destination),
                legacy_header: false,
            };
            let plaintext = encode_request_header(&header, &[7, 8, 9]).unwrap();
            let auth = auth_id(&key, NOW, [1, 2, 3, 4]);
            let request =
                seal_request_header(&key, auth, [5; 8], &plaintext).unwrap();
            let (decoded, consumed) =
                open_request_header(&key, &request, NOW).unwrap();
            assert_eq!(decoded, header);
            assert_eq!(consumed, request.len());
        }
    }

    #[test]
    fn rejects_header_checksum_and_aead_tampering() {
        let header = RequestHeader {
            request_nonce: [0; 16],
            request_key: [1; 16],
            response_header: 2,
            option: 0,
            security: Security::None.wire(),
            command: Command::Mux,
            destination: None,
            legacy_header: false,
        };
        let mut plaintext = encode_request_header(&header, &[]).unwrap();
        plaintext[10] ^= 1;
        assert!(decode_request_header(&plaintext).is_err());

        let key = command_key(user_id(USER));
        let auth = auth_id(&key, NOW, [1, 2, 3, 4]);
        let plaintext = encode_request_header(&header, &[]).unwrap();
        let mut request =
            seal_request_header(&key, auth, [5; 8], &plaintext).unwrap();
        *request.last_mut().unwrap() ^= 1;
        assert!(open_request_header(&key, &request, NOW).is_err());
    }

    #[test]
    fn aead_response_header_round_trips_and_authenticates_marker() {
        let request = RequestHeader {
            request_nonce: [0x10; 16],
            request_key: [0x20; 16],
            response_header: 0x30,
            option: OPTION_CHUNK_STREAM,
            security: Security::None.wire(),
            command: Command::Udp,
            destination: Some(SocksAddr::new("dns.test", 53)),
            legacy_header: false,
        };
        let mut response = seal_response_header(&request).unwrap();
        assert_eq!(open_response_header(&request, &response).unwrap(), 38);
        response[20] ^= 1;
        assert!(open_response_header(&request, &response).is_err());
    }

    #[tokio::test]
    async fn aes_body_frame_matches_go_sing_vmess_vector() {
        let key: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap();
        let nonce: [u8; 16] = hex::decode("ffeeddccbbaa99887766554433221100")
            .unwrap()
            .try_into()
            .unwrap();
        let option = OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING;
        let mut encoder = BodyEncoder::new(
            Security::Aes128Gcm.wire(),
            option,
            key,
            nonce,
            key,
            nonce,
        )
        .unwrap();
        let frame = encoder.encode(b"hello vmess body").unwrap();
        assert_eq!(
            hex::encode(&frame),
            "745ea3fb7d07c7804dac07b6d37ef53cb1b13f277f2c82fce08758b7103adac807ba"
        );

        let mut decoder = BodyDecoder::new(
            Security::Aes128Gcm.wire(),
            option,
            key,
            nonce,
            key,
            nonce,
        )
        .unwrap();
        let mut input = frame.as_slice();
        assert_eq!(
            decoder.decode_from(&mut input).await.unwrap(),
            b"hello vmess body"
        );
    }

    #[tokio::test]
    async fn chacha_body_frame_matches_go_sing_vmess_vector() {
        let key: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap();
        let nonce: [u8; 16] = hex::decode("ffeeddccbbaa99887766554433221100")
            .unwrap()
            .try_into()
            .unwrap();
        let option = OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING;
        let mut encoder = BodyEncoder::new(
            Security::Chacha20Poly1305.wire(),
            option,
            key,
            nonce,
            key,
            nonce,
        )
        .unwrap();
        let frame = encoder.encode(b"hello vmess body").unwrap();
        assert_eq!(
            hex::encode(&frame),
            "745e782b5901d8def00848c6264d0aba2e5599b0584a1fbc3d6c0c20213d692a4520"
        );
        let mut decoder = BodyDecoder::new(
            Security::Chacha20Poly1305.wire(),
            option,
            key,
            nonce,
            key,
            nonce,
        )
        .unwrap();
        let mut input = frame.as_slice();
        assert_eq!(
            decoder.decode_from(&mut input).await.unwrap(),
            b"hello vmess body"
        );
    }

    #[tokio::test]
    async fn authenticated_length_matches_go_and_global_padding_round_trips() {
        let key: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap();
        let nonce: [u8; 16] = hex::decode("ffeeddccbbaa99887766554433221100")
            .unwrap()
            .try_into()
            .unwrap();
        let option = OPTION_CHUNK_STREAM
            | OPTION_CHUNK_MASKING
            | OPTION_AUTHENTICATED_LENGTH;
        let mut encoder = BodyEncoder::new(
            Security::Aes128Gcm.wire(),
            option,
            key,
            nonce,
            key,
            nonce,
        )
        .unwrap();
        let frame = encoder.encode(b"hello vmess body").unwrap();
        assert_eq!(
            hex::encode(&frame),
            "cac4ba8a9d89a928ea05512840dac93ea08ba3fb7d07c7804dac07b6d37ef53cb1b13f277f2c82fce08758b7103adac807ba"
        );

        let padded_option = option | OPTION_GLOBAL_PADDING;
        let mut encoder = BodyEncoder::new(
            Security::Aes128Gcm.wire(),
            padded_option,
            key,
            nonce,
            key,
            nonce,
        )
        .unwrap();
        let padded = encoder.encode(b"padded payload").unwrap();
        let mut decoder = BodyDecoder::new(
            Security::Aes128Gcm.wire(),
            padded_option,
            key,
            nonce,
            key,
            nonce,
        )
        .unwrap();
        let mut input = padded.as_slice();
        assert_eq!(
            decoder.decode_from(&mut input).await.unwrap(),
            b"padded payload"
        );
    }

    #[tokio::test]
    async fn legacy_cfb_body_matches_go_sing_vmess_vector() {
        let key: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap();
        let nonce: [u8; 16] = hex::decode("ffeeddccbbaa99887766554433221100")
            .unwrap()
            .try_into()
            .unwrap();
        let mut encoder = BodyEncoder::new(
            Security::Legacy.wire(),
            OPTION_CHUNK_STREAM,
            key,
            nonce,
            key,
            nonce,
        )
        .unwrap();
        let frame = encoder.encode(b"hello vmess body").unwrap();
        assert_eq!(
            hex::encode(&frame),
            "7235ace39f5d2518628f9d024d973e46a634bcde48e5"
        );
        let mut decoder = BodyDecoder::new(
            Security::Legacy.wire(),
            OPTION_CHUNK_STREAM,
            key,
            nonce,
            key,
            nonce,
        )
        .unwrap();
        let mut input = frame.as_slice();
        assert_eq!(
            decoder.decode_from(&mut input).await.unwrap(),
            b"hello vmess body"
        );
    }
}
