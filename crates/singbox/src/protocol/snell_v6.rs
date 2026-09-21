//! Snell v6 non-shaped record modes.
//!
//! `unsafe-raw` and `unshaped` are distinct v6 wire protocols.  The default
//! shaped mode is profile-derived and is implemented separately from these
//! deliberately small codecs.

use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead as _, KeyInit as _, Payload},
};
use n0_watcher::Watcher as _;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, ReadHalf, WriteHalf},
    sync::Mutex,
};

use crate::{
    adapter::{
        DialFuture, Dialer, PacketConnection, PacketFuture, PacketStream,
        Stream,
    },
    common::network::SocksAddr,
    protocol::{
        snell::{
            AEAD_TAG_LEN, COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_PING,
            COMMAND_UDP, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, HEADER_VERSION,
            NONCE_LEN, REPLY_PONG, REPLY_TUNNEL, Request, SALT_LEN,
            UDP_COMMAND_FORWARD, decode_request, decode_udp_request_address,
            decode_udp_response_address, derive_key, encode_request,
            encode_udp_request_address, encode_udp_response_address,
            increase_nonce,
        },
        snell_v6_profile::Profile,
    },
};

pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;
const REUSE_POOL_SIZE: usize = 10;
const REUSE_POOL_MAX_AGE: Duration = Duration::from_secs(180);
const REUSE_POOL_TIMER_INTERVAL: Duration = Duration::from_secs(20);
const REUSE_WAITING_DISCARD_LIMIT: usize = 0x80001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Default,
    Unshaped,
    UnsafeRaw,
}

impl Mode {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "" | "default" => Ok(Self::Default),
            "unshaped" => Ok(Self::Unshaped),
            "unsafe-raw" => Ok(Self::UnsafeRaw),
            _ => Err(invalid_input(format!("snell: unknown v6 mode: {value}"))),
        }
    }
}

struct RecordEncoder {
    mode: Mode,
    cipher: Option<Aes128Gcm>,
    nonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    profile: Option<Profile>,
    sequence: u32,
    chunk_size: usize,
    last_write_unix: u64,
}

impl RecordEncoder {
    fn random(psk: &[u8], mode: Mode) -> io::Result<Self> {
        let mut salt = [0_u8; SALT_LEN];
        let cipher = if mode != Mode::UnsafeRaw {
            getrandom::fill(&mut salt)
                .map_err(|error| io::Error::other(error.to_string()))?;
            Some(
                Aes128Gcm::new_from_slice(&derive_key(psk, &salt)?)
                    .map_err(|_| invalid_input("snell: invalid AES key"))?,
            )
        } else {
            None
        };
        Ok(Self {
            mode,
            cipher,
            nonce: [0; NONCE_LEN],
            salt,
            salt_sent: false,
            profile: (mode == Mode::Default).then(|| Profile::new(psk)),
            sequence: 0,
            chunk_size: 0,
            last_write_unix: 0,
        })
    }

    fn next_payload_limit(&mut self) -> usize {
        let Some(profile) = self.profile.as_ref() else {
            return MAX_PAYLOAD_LEN;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.last_write_unix == 0
            || now.saturating_sub(self.last_write_unix) > profile.idle_reset_sec
        {
            self.chunk_size = profile.chunk_initial;
        }
        if self.chunk_size == 0 {
            self.chunk_size = profile.chunk_initial;
        }
        let mut limit =
            profile.chunk_payload_limit(self.sequence, self.chunk_size);
        if self.sequence == 0 {
            limit = limit.min(profile.first_record_cap);
        }
        self.chunk_size = profile.next_chunk_size(self.chunk_size);
        self.last_write_unix = now;
        limit.clamp(1, MAX_PAYLOAD_LEN)
    }

    fn encode_record(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(invalid_input("snell: v6 record exceeds maximum"));
        }
        let mut header = [0_u8; HEADER_PLAIN_LEN];
        header[0] = HEADER_VERSION;
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        match self.mode {
            Mode::UnsafeRaw => {
                let mut output =
                    Vec::with_capacity(header.len() + payload.len());
                output.extend_from_slice(&header);
                output.extend_from_slice(payload);
                Ok(output)
            }
            Mode::Unshaped => {
                let cipher = self.cipher.as_ref().expect("v6 cipher");
                let header_cipher = cipher
                    .encrypt((&self.nonce).into(), header.as_slice())
                    .map_err(|_| invalid_data("snell: seal v6 header"))?;
                increase_nonce(&mut self.nonce);
                let mut output = Vec::with_capacity(
                    usize::from(!self.salt_sent) * SALT_LEN
                        + HEADER_CIPHER_LEN
                        + payload.len()
                        + usize::from(!payload.is_empty()) * AEAD_TAG_LEN,
                );
                if !self.salt_sent {
                    output.extend_from_slice(&self.salt);
                    self.salt_sent = true;
                }
                output.extend_from_slice(&header_cipher);
                if !payload.is_empty() {
                    let body = cipher
                        .encrypt(
                            (&self.nonce).into(),
                            Payload {
                                msg: payload,
                                aad: &[],
                            },
                        )
                        .map_err(|_| invalid_data("snell: seal v6 payload"))?;
                    increase_nonce(&mut self.nonce);
                    output.extend_from_slice(&body);
                }
                Ok(output)
            }
            Mode::Default => {
                let profile = self.profile.as_ref().expect("v6 profile");
                let prefix_len = profile.record_prefix_len(self.sequence);
                let salt_block_len = if self.salt_sent {
                    0
                } else {
                    profile.salt_block_len
                };
                let salt_prefix_len = salt_block_len.saturating_sub(SALT_LEN);
                let padding_len = profile.padding_len(
                    self.sequence,
                    payload.len(),
                    prefix_len,
                    salt_prefix_len,
                    salt_block_len,
                );
                header[3..5]
                    .copy_from_slice(&(padding_len as u16).to_be_bytes());
                let mut output = Vec::with_capacity(
                    salt_block_len
                        + prefix_len
                        + HEADER_CIPHER_LEN
                        + padding_len
                        + payload.len()
                        + usize::from(!payload.is_empty()) * AEAD_TAG_LEN,
                );
                if salt_block_len > 0 {
                    let mut block = vec![0_u8; salt_block_len];
                    profile.fill_padding(u32::MAX, &mut block);
                    profile.write_salt_block(&self.salt, &mut block);
                    output.extend_from_slice(&block);
                    self.salt_sent = true;
                }
                let mut prefix = vec![0_u8; prefix_len];
                profile.fill_padding(self.sequence, &mut prefix);
                output.extend_from_slice(&prefix);
                let cipher = self.cipher.as_ref().expect("v6 cipher");
                let header_cipher = cipher
                    .encrypt(
                        (&self.nonce).into(),
                        Payload {
                            msg: &header,
                            aad: &prefix,
                        },
                    )
                    .map_err(|_| invalid_data("snell: seal shaped header"))?;
                increase_nonce(&mut self.nonce);
                output.extend_from_slice(&header_cipher);
                let mut padding = vec![0_u8; padding_len];
                profile.fill_padding(self.sequence, &mut padding);
                if payload.is_empty() {
                    output.extend_from_slice(&padding);
                } else {
                    let mut body = cipher
                        .encrypt(
                            (&self.nonce).into(),
                            Payload {
                                msg: payload,
                                aad: &padding,
                            },
                        )
                        .map_err(|_| {
                            invalid_data("snell: seal shaped payload")
                        })?;
                    increase_nonce(&mut self.nonce);
                    profile.mix_padding_payload(
                        self.sequence,
                        &mut padding,
                        &mut body,
                    );
                    output.extend_from_slice(&padding);
                    output.extend_from_slice(&body);
                }
                self.sequence = self.sequence.wrapping_add(1);
                Ok(output)
            }
        }
    }
}

struct RecordDecoder {
    mode: Mode,
    psk: Vec<u8>,
    cipher: Option<Aes128Gcm>,
    nonce: [u8; NONCE_LEN],
    profile: Option<Profile>,
    sequence: u32,
}

impl RecordDecoder {
    fn new(psk: &[u8], mode: Mode) -> io::Result<Self> {
        Ok(Self {
            mode,
            psk: psk.to_vec(),
            cipher: None,
            nonce: [0; NONCE_LEN],
            profile: (mode == Mode::Default).then(|| Profile::new(psk)),
            sequence: 0,
        })
    }

    async fn read_record<R>(&mut self, reader: &mut R) -> io::Result<Vec<u8>>
    where
        R: tokio::io::AsyncRead + Unpin + ?Sized,
    {
        let (header, shaped_padding) = match self.mode {
            Mode::UnsafeRaw => {
                let mut header = [0_u8; HEADER_PLAIN_LEN];
                reader.read_exact(&mut header).await?;
                (header.to_vec(), None)
            }
            Mode::Unshaped => {
                if self.cipher.is_none() {
                    let mut salt = [0_u8; SALT_LEN];
                    reader.read_exact(&mut salt).await?;
                    self.cipher = Some(
                        Aes128Gcm::new_from_slice(&derive_key(
                            &self.psk, &salt,
                        )?)
                        .map_err(|_| invalid_input("snell: invalid AES key"))?,
                    );
                }
                let mut encrypted = [0_u8; HEADER_CIPHER_LEN];
                reader.read_exact(&mut encrypted).await?;
                let header = self
                    .cipher
                    .as_ref()
                    .expect("v6 cipher")
                    .decrypt((&self.nonce).into(), encrypted.as_slice())
                    .map_err(|_| invalid_data("snell: open v6 header"))?;
                increase_nonce(&mut self.nonce);
                (header, None)
            }
            Mode::Default => {
                let profile = self.profile.as_ref().expect("v6 profile");
                if self.cipher.is_none() {
                    let mut block = vec![0_u8; profile.salt_block_len];
                    reader.read_exact(&mut block).await?;
                    let salt = profile.extract_salt(&block);
                    self.cipher = Some(
                        Aes128Gcm::new_from_slice(&derive_key(
                            &self.psk, &salt,
                        )?)
                        .map_err(|_| invalid_input("snell: invalid AES key"))?,
                    );
                }
                let prefix_len = profile.record_prefix_len(self.sequence);
                let mut prefix = vec![0_u8; prefix_len];
                reader.read_exact(&mut prefix).await?;
                let mut encrypted = [0_u8; HEADER_CIPHER_LEN];
                reader.read_exact(&mut encrypted).await?;
                let header = self
                    .cipher
                    .as_ref()
                    .expect("v6 cipher")
                    .decrypt(
                        (&self.nonce).into(),
                        Payload {
                            msg: &encrypted,
                            aad: &prefix,
                        },
                    )
                    .map_err(|_| invalid_data("snell: open shaped header"))?;
                increase_nonce(&mut self.nonce);
                (header, Some(()))
            }
        };
        if header.len() != HEADER_PLAIN_LEN || header[0] != HEADER_VERSION {
            return Err(invalid_data("snell: bad v6 record version"));
        }
        if shaped_padding.is_none() && (header[1] != 0 || header[2] != 0) {
            return Err(invalid_data("snell: v6 reserved bytes are non-zero"));
        }
        if shaped_padding.is_none() && (header[3] != 0 || header[4] != 0) {
            return Err(invalid_data(
                "snell: unexpected padding in non-default record",
            ));
        }
        let size = usize::from(u16::from_be_bytes([header[5], header[6]]));
        let padding_len =
            usize::from(u16::from_be_bytes([header[3], header[4]]));
        if self.mode == Mode::Default {
            let mut padding = vec![0_u8; padding_len];
            reader.read_exact(&mut padding).await?;
            if size == 0 {
                self.sequence = self.sequence.wrapping_add(1);
                return Ok(Vec::new());
            }
            let mut encrypted = vec![0_u8; size + AEAD_TAG_LEN];
            reader.read_exact(&mut encrypted).await?;
            let profile = self.profile.as_ref().expect("v6 profile");
            profile.mix_padding_payload(
                self.sequence,
                &mut padding,
                &mut encrypted,
            );
            let mut expected_padding = vec![0_u8; padding_len];
            profile.fill_padding(self.sequence, &mut expected_padding);
            if padding != expected_padding {
                return Err(invalid_data(format!(
                    "snell: shaped padding restoration mismatch at sequence {}",
                    self.sequence
                )));
            }
            let payload = self
                .cipher
                .as_ref()
                .expect("v6 cipher")
                .decrypt(
                    (&self.nonce).into(),
                    Payload {
                        msg: &encrypted,
                        aad: &padding,
                    },
                )
                .map_err(|_| invalid_data("snell: open shaped payload"))?;
            increase_nonce(&mut self.nonce);
            self.sequence = self.sequence.wrapping_add(1);
            return Ok(payload);
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        match self.mode {
            Mode::UnsafeRaw => {
                let mut payload = vec![0_u8; size];
                reader.read_exact(&mut payload).await?;
                Ok(payload)
            }
            Mode::Unshaped => {
                let mut encrypted = vec![0_u8; size + AEAD_TAG_LEN];
                reader.read_exact(&mut encrypted).await?;
                let payload = self
                    .cipher
                    .as_ref()
                    .expect("v6 cipher")
                    .decrypt((&self.nonce).into(), encrypted.as_slice())
                    .map_err(|_| invalid_data("snell: open v6 payload"))?;
                increase_nonce(&mut self.nonce);
                Ok(payload)
            }
            Mode::Default => unreachable!(),
        }
    }
}

pub enum AcceptedV6 {
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

/// Stateful server-side v6 record session. Command 5 keeps this session alive
/// after both directions exchange an empty record, allowing the next request
/// to reuse the same physical TCP connection.
pub struct V6ServerSession {
    reader: ReadHalf<Stream>,
    writer: WriteHalf<Stream>,
    decoder: RecordDecoder,
    encoder: RecordEncoder,
}

pub async fn accept_v6_server_session(
    mut raw: Stream,
    psk: &[u8],
    mode: Mode,
) -> io::Result<(V6ServerSession, Request, Vec<u8>)> {
    let mut decoder = RecordDecoder::new(psk, mode)?;
    let first = decoder.read_record(&mut raw).await?;
    let (request, consumed) = decode_request(&first)?;
    let early_payload = first[consumed..].to_vec();
    let (reader, writer) = tokio::io::split(raw);
    Ok((
        V6ServerSession {
            reader,
            writer,
            decoder,
            encoder: RecordEncoder::random(psk, mode)?,
        },
        request,
        early_payload,
    ))
}

impl V6ServerSession {
    async fn write_record(&mut self, payload: &[u8]) -> io::Result<()> {
        self.encoder.next_payload_limit();
        self.writer
            .write_all(&self.encoder.encode_record(payload)?)
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
                            let mut error = vec![crate::protocol::snell::REPLY_ERROR, 0x65, 10];
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

pub async fn connect_v6(
    mut raw: Stream,
    psk: &[u8],
    user_key: &[u8],
    destination: SocksAddr,
    mode: Mode,
) -> io::Result<Stream> {
    let request = encode_request(&Request {
        command: COMMAND_CONNECT_V2,
        client_id: user_key.to_vec(),
        destination: Some(destination),
    })?;
    let mut encoder = RecordEncoder::random(psk, mode)?;
    encoder.next_payload_limit();
    raw.write_all(&encoder.encode_record(&request)?).await?;
    Ok(spawn_stream_bridge(
        raw,
        RecordDecoder::new(psk, mode)?,
        encoder,
        Vec::new(),
        Vec::new(),
        true,
    ))
}

pub async fn connect_v6_udp(
    mut raw: Stream,
    psk: &[u8],
    user_key: &[u8],
    mode: Mode,
) -> io::Result<PacketStream> {
    let request = encode_request(&Request {
        command: COMMAND_UDP,
        client_id: user_key.to_vec(),
        destination: None,
    })?;
    let mut encoder = RecordEncoder::random(psk, mode)?;
    encoder.next_payload_limit();
    raw.write_all(&encoder.encode_record(&request)?).await?;
    let mut decoder = RecordDecoder::new(psk, mode)?;
    let reply = decoder.read_record(&mut raw).await?;
    if reply.first().copied() != Some(REPLY_TUNNEL) {
        return Err(invalid_data("snell: unexpected v6 UDP reply"));
    }
    Ok(packet_connection(raw, decoder, encoder, PacketRole::Client))
}

pub async fn accept_v6_connection(
    mut raw: Stream,
    psk: &[u8],
    mode: Mode,
) -> io::Result<AcceptedV6> {
    let mut decoder = RecordDecoder::new(psk, mode)?;
    let first = decoder.read_record(&mut raw).await?;
    let (request, consumed) = decode_request(&first)?;
    let early_payload = first[consumed..].to_vec();
    match request.command {
        COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
            let encoder = RecordEncoder::random(psk, mode)?;
            Ok(AcceptedV6::Tcp {
                stream: spawn_stream_bridge(
                    raw,
                    decoder,
                    encoder,
                    vec![REPLY_TUNNEL],
                    early_payload,
                    false,
                ),
                request,
            })
        }
        COMMAND_UDP => {
            let mut encoder = RecordEncoder::random(psk, mode)?;
            encoder.next_payload_limit();
            raw.write_all(&encoder.encode_record(&[REPLY_TUNNEL])?)
                .await?;
            Ok(AcceptedV6::Udp {
                packets: packet_connection(
                    raw,
                    decoder,
                    encoder,
                    PacketRole::Server,
                ),
                request,
            })
        }
        COMMAND_PING => {
            let mut encoder = RecordEncoder::random(psk, mode)?;
            encoder.next_payload_limit();
            raw.write_all(&encoder.encode_record(&[REPLY_PONG])?)
                .await?;
            raw.shutdown().await?;
            Ok(AcceptedV6::Pong)
        }
        _ => Err(invalid_data("snell: unsupported v6 command")),
    }
}

fn spawn_stream_bridge(
    raw: Stream,
    mut decoder: RecordDecoder,
    mut encoder: RecordEncoder,
    prefix: Vec<u8>,
    early_payload: Vec<u8>,
    parse_reply: bool,
) -> Stream {
    let (application, bridge) = tokio::io::duplex(64 * 1024);
    let (mut app_reader, mut app_writer) = tokio::io::split(bridge);
    let (mut raw_reader, mut raw_writer) = tokio::io::split(raw);
    tokio::spawn(async move {
        let mut first = true;
        let mut buffer = vec![0_u8; MAX_PAYLOAD_LEN - 1];
        loop {
            let limit = encoder.next_payload_limit();
            let prefix_len = if first { prefix.len() } else { 0 };
            let read_limit = limit.saturating_sub(prefix_len).max(1);
            let read_limit = read_limit.min(buffer.len());
            let size = match app_reader.read(&mut buffer[..read_limit]).await {
                Ok(size) => size,
                Err(_) => return,
            };
            let mut payload = Vec::with_capacity(size + prefix.len());
            if first {
                payload.extend_from_slice(&prefix);
                first = false;
            }
            payload.extend_from_slice(&buffer[..size]);
            let Ok(record) = encoder.encode_record(&payload) else {
                return;
            };
            if raw_writer.write_all(&record).await.is_err() {
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
            && app_writer.write_all(&early_payload).await.is_err()
        {
            return;
        }
        let mut first = true;
        loop {
            let mut payload = match decoder.read_record(&mut raw_reader).await {
                Ok(payload) => payload,
                Err(_) => return,
            };
            if payload.is_empty() {
                let _ = app_writer.shutdown().await;
                return;
            }
            if first && parse_reply {
                first = false;
                if payload.first().copied() != Some(REPLY_TUNNEL) {
                    return;
                }
                payload.remove(0);
            }
            if !payload.is_empty()
                && app_writer.write_all(&payload).await.is_err()
            {
                return;
            }
        }
    });
    Box::new(application)
}

#[derive(Clone, Copy)]
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

struct SnellV6PacketConnection {
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
    Box::new(SnellV6PacketConnection {
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

impl PacketConnection for SnellV6PacketConnection {
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
                return Err(invalid_input("snell: v6 UDP payload too large"));
            }
            let mut writer = self.writer.lock().await;
            writer.encoder.next_payload_limit();
            let record = writer.encoder.encode_record(&payload)?;
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
            let (address, offset) = match self.role {
                PacketRole::Client => decode_udp_response_address(&payload)?,
                PacketRole::Server => {
                    if payload.first().copied() != Some(UDP_COMMAND_FORWARD) {
                        return Err(invalid_data(
                            "snell: unsupported UDP command",
                        ));
                    }
                    let (address, size) =
                        decode_udp_request_address(&payload[1..])?;
                    (address, size + 1)
                }
            };
            let packet = &payload[offset..];
            if packet.len() > data.len() {
                return Err(invalid_data(
                    "snell: UDP receive buffer too small",
                ));
            }
            data[..packet.len()].copy_from_slice(packet);
            Ok((packet.len(), address))
        })
    }
}

pub struct SnellV6Outbound {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    psk: Vec<u8>,
    user_key: Vec<u8>,
    mode: Mode,
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

impl SnellV6Outbound {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        psk: impl Into<Vec<u8>>,
        user_key: impl Into<Vec<u8>>,
        mode: Mode,
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
            mode,
            reuse,
            reuse_pool: Arc::new(ReusablePool::default()),
        })
    }

    /// Discard every idle reusable session immediately while preserving
    /// logical connections that are currently in use.
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
    session.encoder.next_payload_limit();
    session
        .writer
        .write_all(&session.encoder.encode_record(&request)?)
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
                session.encoder.next_payload_limit();
                session.writer.write_all(&session.encoder.encode_record(&buffer[..size])?).await?;
                if size == 0 { local_closed = true; }
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
                    if payload.first().copied() != Some(REPLY_TUNNEL) {
                        return Err(invalid_data("snell: unexpected reused v6 reply"));
                    }
                    payload.remove(0);
                }
                if !payload.is_empty() {
                    if application_read_closed {
                        discarded = discarded.saturating_add(payload.len());
                    } else if let Err(error) = app_writer.write_all(&payload).await {
                        if !local_closed { return Err(error); }
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

impl Dialer for SnellV6Outbound {
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
                    let (reader, writer) = tokio::io::split(raw);
                    ReusableClientSession {
                        reader,
                        writer,
                        decoder: RecordDecoder::new(&self.psk, self.mode)?,
                        encoder: RecordEncoder::random(&self.psk, self.mode)?,
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
            connect_v6(
                raw,
                &self.psk,
                &self.user_key,
                destination.clone(),
                self.mode,
            )
            .await
        })
    }

    fn listen_udp<'a>(
        &'a self,
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let raw = self.upstream.dial_tcp(&self.server).await?;
            connect_v6_udp(raw, &self.psk, &self.user_key, self.mode).await
        })
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

    #[tokio::test]
    async fn reset_discards_idle_reuse_sessions() {
        let outbound = SnellV6Outbound::new(
            Arc::new(crate::protocol::direct::DirectOutbound::new(
                crate::option::DirectOutboundOptions::default(),
            )),
            SocksAddr::new("127.0.0.1", 1),
            b"secret".to_vec(),
            b"user-key".to_vec(),
            Mode::Unshaped,
            true,
        )
        .unwrap();
        let (stream, peer) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(Box::new(stream) as Stream);
        outbound
            .reuse_pool
            .entries
            .lock()
            .await
            .push_back(ReusablePoolEntry {
                inserted: Instant::now(),
                session: ReusableClientSession {
                    reader,
                    writer,
                    decoder: RecordDecoder::new(b"secret", Mode::Unshaped)
                        .unwrap(),
                    encoder: RecordEncoder::random(b"secret", Mode::Unshaped)
                        .unwrap(),
                },
            });
        outbound.reset().await;
        assert!(outbound.reuse_pool.entries.lock().await.is_empty());
        drop(peer);
    }

    async fn assert_stream_mode(mode: Mode) {
        let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
        let mut client = connect_v6(
            Box::new(client_raw),
            b"secret",
            b"user-key",
            SocksAddr::new("target.example", 443),
            mode,
        )
        .await
        .unwrap();
        let AcceptedV6::Tcp {
            mut stream,
            request,
        } = accept_v6_connection(Box::new(server_raw), b"secret", mode)
            .await
            .unwrap()
        else {
            panic!("expected TCP");
        };
        assert_eq!(
            request.destination,
            Some(SocksAddr::new("target.example", 443))
        );
        client.write_all(b"ping").await.unwrap();
        let mut data = [0_u8; 4];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"ping");
        stream.write_all(b"pong").await.unwrap();
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"pong");
    }

    #[tokio::test]
    async fn unshaped_stream_interoperates() {
        assert_stream_mode(Mode::Unshaped).await;
    }

    #[tokio::test]
    async fn unsafe_raw_stream_interoperates() {
        assert_stream_mode(Mode::UnsafeRaw).await;
    }

    #[tokio::test]
    async fn default_shaped_stream_interoperates() {
        assert_stream_mode(Mode::Default).await;
    }

    #[tokio::test]
    async fn unshaped_packets_interoperate() {
        let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let AcceptedV6::Udp { packets, request } = accept_v6_connection(
                Box::new(server_raw),
                b"secret",
                Mode::Unshaped,
            )
            .await
            .unwrap() else {
                panic!("expected UDP");
            };
            assert_eq!(request.client_id, b"user-key");
            let mut data = [0_u8; 64];
            let (size, destination) =
                packets.recv_from(&mut data).await.unwrap();
            assert_eq!(&data[..size], b"ping packet");
            assert_eq!(destination, SocksAddr::new("target.example", 53));
            packets
                .send_to(b"pong packet", &SocksAddr::new("192.0.2.1", 53))
                .await
                .unwrap();
        });
        let packets = connect_v6_udp(
            Box::new(client_raw),
            b"secret",
            b"user-key",
            Mode::Unshaped,
        )
        .await
        .unwrap();
        packets
            .send_to(b"ping packet", &SocksAddr::new("target.example", 53))
            .await
            .unwrap();
        let mut data = [0_u8; 64];
        let (size, source) = packets.recv_from(&mut data).await.unwrap();
        assert_eq!(&data[..size], b"pong packet");
        assert_eq!(source, SocksAddr::new("192.0.2.1", 53));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn v6_waiting_reuse_closes_after_upstream_discard_limit() {
        let mode = Mode::Unshaped;
        let (client_raw, mut server_raw) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(Box::new(client_raw) as Stream);
        let mut session = ReusableClientSession {
            reader,
            writer,
            decoder: RecordDecoder::new(b"secret", mode).unwrap(),
            encoder: RecordEncoder::random(b"secret", mode).unwrap(),
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
            let mut decoder = RecordDecoder::new(b"secret", mode).unwrap();
            decoder.read_record(&mut server_raw).await.unwrap();
            let mut encoder = RecordEncoder::random(b"secret", mode).unwrap();
            server_raw
                .write_all(&encoder.encode_record(&[REPLY_TUNNEL]).unwrap())
                .await
                .unwrap();
            let mut remaining = REUSE_WAITING_DISCARD_LIMIT;
            while remaining != 0 {
                let size = remaining.min(MAX_PAYLOAD_LEN);
                if server_raw
                    .write_all(
                        &encoder.encode_record(&vec![0x42; size]).unwrap(),
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
