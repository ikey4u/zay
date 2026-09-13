//! Tailscale 2021 control transport over Noise IK.
//!
//! This module owns the Tailscale-specific HTTP upgrade and record framing.
//! HTTP/2 and control-plane JSON sit above the returned authenticated stream.

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Method, Request, Response,
    body::{Body, Incoming},
    client::conn::http2::SendRequest,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use thiserror::Error;
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf,
};

use super::tailscale_control_types::{
    TAILSCALE_MAP_PATH, TAILSCALE_REGISTER_PATH,
    TAILSCALE_REGISTER_RESPONSE_LIMIT, TAILSCALE_SET_DNS_PATH,
    TAILSCALE_SET_DNS_RESPONSE_LIMIT, TAILSCALE_TKA_BOOTSTRAP_PATH,
    TAILSCALE_TKA_BOOTSTRAP_RESPONSE_LIMIT, TAILSCALE_TKA_SYNC_OFFER_PATH,
    TAILSCALE_TKA_SYNC_RESPONSE_LIMIT, TAILSCALE_TKA_SYNC_SEND_PATH,
    TailscaleMapRequest, TailscaleRegisterRequest, TailscaleRegisterResponse,
    TailscaleSetDnsRequest, TailscaleSetDnsResponse,
    TailscaleTkaBootstrapRequest, TailscaleTkaBootstrapResponse,
    TailscaleTkaSyncOfferRequest, TailscaleTkaSyncOfferResponse,
    TailscaleTkaSyncSendRequest, TailscaleTkaSyncSendResponse,
};

pub const TAILSCALE_CONTROL_NOISE_PROTOCOL: &str =
    "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const TAILSCALE_CONTROL_PROLOGUE_PREFIX: &str =
    "Tailscale Control Protocol v";
pub const TAILSCALE_CONTROL_UPGRADE_PATH: &str = "/ts2021";
pub const TAILSCALE_CONTROL_UPGRADE_PROTOCOL: &str =
    "tailscale-control-protocol";
pub const TAILSCALE_CONTROL_HANDSHAKE_HEADER: &str = "X-Tailscale-Handshake";
pub const TAILSCALE_CONTROL_EARLY_PAYLOAD_MAGIC: &[u8; 5] = b"\xff\xff\xffTS";
pub const TAILSCALE_CONTROL_MAX_MESSAGE_SIZE: usize = 4096;
pub const TAILSCALE_CONTROL_HEADER_LENGTH: usize = 3;
pub const TAILSCALE_CONTROL_TAG_LENGTH: usize = 16;
pub const TAILSCALE_CONTROL_MAX_PLAINTEXT_SIZE: usize =
    TAILSCALE_CONTROL_MAX_MESSAGE_SIZE
        - TAILSCALE_CONTROL_HEADER_LENGTH
        - TAILSCALE_CONTROL_TAG_LENGTH;
pub const TAILSCALE_CONTROL_MAX_EARLY_PAYLOAD_SIZE: usize = 10 << 20;
pub const TAILSCALE_CONTROL_MAX_KEY_RESPONSE_SIZE: usize = 64 << 10;
pub const TAILSCALE_CONTROL_MAX_ERROR_RESPONSE_SIZE: usize = 64 << 10;

const MESSAGE_INITIATION: u8 = 1;
const MESSAGE_RESPONSE: u8 = 2;
const MESSAGE_ERROR: u8 = 3;
const MESSAGE_RECORD: u8 = 4;
const INITIATION_HEADER_LENGTH: usize = 5;
const INITIATION_PAYLOAD_LENGTH: usize = 96;
const RESPONSE_PAYLOAD_LENGTH: usize = 48;

#[derive(Debug, Error)]
pub enum TailscaleControlError {
    #[error("Tailscale control key must not be all zero")]
    ZeroKey,
    #[error("invalid Tailscale control HTTP request: {0}")]
    InvalidHttpRequest(String),
    #[error("Tailscale control HTTP response header exceeds 64 KiB")]
    HttpHeaderTooLarge,
    #[error("invalid Tailscale control HTTP response: {0}")]
    InvalidHttpResponse(String),
    #[error(
        "Tailscale control HTTP upgrade failed with status {status}: {reason}"
    )]
    HttpUpgrade { status: u16, reason: String },
    #[error("Tailscale control server switched to unexpected protocol {0:?}")]
    UnexpectedUpgrade(String),
    #[error("Tailscale control server rejected handshake: {0}")]
    ServerHandshake(String),
    #[error(
        "unexpected Tailscale control message type {actual}; expected {expected}"
    )]
    UnexpectedMessageType { actual: u8, expected: u8 },
    #[error(
        "invalid Tailscale control message length {actual}; expected {expected}"
    )]
    InvalidMessageLength { actual: usize, expected: usize },
    #[error(
        "Tailscale control record exceeds {TAILSCALE_CONTROL_MAX_MESSAGE_SIZE} bytes"
    )]
    RecordTooLarge,
    #[error("Tailscale control Noise state failed: {0}")]
    Noise(String),
    #[error("invalid Tailscale early payload: {0}")]
    EarlyPayload(String),
    #[error("Tailscale control HTTP/2 failed: {0}")]
    Http2(String),
    #[error("Tailscale control RPC returned HTTP {status}: {message}")]
    ControlHttpStatus { status: u16, message: String },
    #[error("Tailscale control RPC body exceeds {maximum} bytes")]
    ControlBodyTooLarge { maximum: usize },
    #[error("invalid Tailscale control JSON: {0}")]
    ControlJson(String),
    #[error("Tailscale map compressed frame exceeds {maximum} bytes: {actual}")]
    MapFrameTooLarge { actual: usize, maximum: usize },
    #[error("invalid Tailscale map zstd frame: {0}")]
    MapCompression(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub struct TailscaleControlHandshake {
    version: u16,
    control_public_key: [u8; 32],
    initial_message: [u8; INITIATION_HEADER_LENGTH + INITIATION_PAYLOAD_LENGTH],
    state: HandshakeState,
}

impl TailscaleControlHandshake {
    pub fn start(
        machine_private_key: [u8; 32],
        control_public_key: [u8; 32],
        version: u16,
    ) -> Result<Self, TailscaleControlError> {
        validate_key(&machine_private_key)?;
        validate_key(&control_public_key)?;
        let params: NoiseParams = TAILSCALE_CONTROL_NOISE_PROTOCOL
            .parse()
            .map_err(noise_error)?;
        let prologue = format!("{TAILSCALE_CONTROL_PROLOGUE_PREFIX}{version}");
        let mut state = Builder::new(params)
            .prologue(prologue.as_bytes())
            .map_err(noise_error)?
            .local_private_key(&machine_private_key)
            .map_err(noise_error)?
            .remote_public_key(&control_public_key)
            .map_err(noise_error)?
            .build_initiator()
            .map_err(noise_error)?;
        let mut initial_message =
            [0_u8; INITIATION_HEADER_LENGTH + INITIATION_PAYLOAD_LENGTH];
        initial_message[..2].copy_from_slice(&version.to_be_bytes());
        initial_message[2] = MESSAGE_INITIATION;
        initial_message[3..5]
            .copy_from_slice(&(INITIATION_PAYLOAD_LENGTH as u16).to_be_bytes());
        let written = state
            .write_message(
                &[],
                &mut initial_message[INITIATION_HEADER_LENGTH..],
            )
            .map_err(noise_error)?;
        if written != INITIATION_PAYLOAD_LENGTH {
            return Err(TailscaleControlError::InvalidMessageLength {
                actual: written,
                expected: INITIATION_PAYLOAD_LENGTH,
            });
        }
        Ok(Self {
            version,
            control_public_key,
            initial_message,
            state,
        })
    }

    pub fn initial_message(&self) -> &[u8; 101] {
        &self.initial_message
    }

    pub fn http_upgrade_request(
        &self,
        authority: &str,
    ) -> Result<String, TailscaleControlError> {
        validate_http_component("authority", authority)?;
        Ok(format!(
            "POST {TAILSCALE_CONTROL_UPGRADE_PATH} HTTP/1.1\r\nHost: {authority}\r\nUpgrade: {TAILSCALE_CONTROL_UPGRADE_PROTOCOL}\r\nConnection: upgrade\r\n{TAILSCALE_CONTROL_HANDSHAKE_HEADER}: {}\r\nContent-Length: 0\r\n\r\n",
            STANDARD.encode(self.initial_message)
        ))
    }

    pub async fn finish<S>(
        mut self,
        mut stream: S,
    ) -> Result<TailscaleControlStream<S>, TailscaleControlError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut header = [0_u8; TAILSCALE_CONTROL_HEADER_LENGTH];
        stream.read_exact(&mut header).await?;
        let message_type = header[0];
        let length = usize::from(u16::from_be_bytes([header[1], header[2]]));
        if message_type == MESSAGE_ERROR {
            if length > u16::MAX as usize {
                return Err(TailscaleControlError::RecordTooLarge);
            }
            let mut message = vec![0_u8; length];
            stream.read_exact(&mut message).await?;
            return Err(TailscaleControlError::ServerHandshake(
                String::from_utf8_lossy(&message).into_owned(),
            ));
        }
        if message_type != MESSAGE_RESPONSE {
            return Err(TailscaleControlError::UnexpectedMessageType {
                actual: message_type,
                expected: MESSAGE_RESPONSE,
            });
        }
        if length != RESPONSE_PAYLOAD_LENGTH {
            return Err(TailscaleControlError::InvalidMessageLength {
                actual: length,
                expected: RESPONSE_PAYLOAD_LENGTH,
            });
        }
        let mut response = [0_u8; RESPONSE_PAYLOAD_LENGTH];
        stream.read_exact(&mut response).await?;
        let mut empty = [];
        self.state
            .read_message(&response, &mut empty)
            .map_err(noise_error)?;
        let handshake_hash: [u8; 32] =
            self.state.get_handshake_hash().try_into().map_err(|_| {
                TailscaleControlError::Noise(
                    "unexpected handshake hash length".into(),
                )
            })?;
        let transport =
            self.state.into_transport_mode().map_err(noise_error)?;
        Ok(TailscaleControlStream {
            stream,
            transport,
            version: self.version,
            control_public_key: self.control_public_key,
            handshake_hash,
            plaintext: VecDeque::new(),
            read_header: [0; TAILSCALE_CONTROL_HEADER_LENGTH],
            read_header_filled: 0,
            read_ciphertext: Vec::new(),
            read_ciphertext_filled: 0,
            write_wire: Vec::new(),
            write_wire_offset: 0,
        })
    }
}

pub struct TailscaleControlStream<S> {
    stream: S,
    transport: TransportState,
    version: u16,
    control_public_key: [u8; 32],
    handshake_hash: [u8; 32],
    plaintext: VecDeque<u8>,
    read_header: [u8; TAILSCALE_CONTROL_HEADER_LENGTH],
    read_header_filled: usize,
    read_ciphertext: Vec<u8>,
    read_ciphertext_filled: usize,
    write_wire: Vec<u8>,
    write_wire_offset: usize,
}

impl<S> TailscaleControlStream<S> {
    pub fn protocol_version(&self) -> u16 {
        self.version
    }

    pub fn peer(&self) -> [u8; 32] {
        self.control_public_key
    }

    pub fn handshake_hash(&self) -> [u8; 32] {
        self.handshake_hash
    }

    pub fn into_stream(self) -> S {
        self.stream
    }
}

impl<S> TailscaleControlStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn write_plaintext(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(), TailscaleControlError> {
        if self.write_wire_offset < self.write_wire.len() {
            self.stream
                .write_all(&self.write_wire[self.write_wire_offset..])
                .await?;
            self.write_wire.clear();
            self.write_wire_offset = 0;
        }
        for chunk in plaintext.chunks(TAILSCALE_CONTROL_MAX_PLAINTEXT_SIZE) {
            let mut encrypted =
                vec![0_u8; chunk.len() + TAILSCALE_CONTROL_TAG_LENGTH];
            let written = self
                .transport
                .write_message(chunk, &mut encrypted)
                .map_err(noise_error)?;
            encrypted.truncate(written);
            let mut header = [0_u8; TAILSCALE_CONTROL_HEADER_LENGTH];
            header[0] = MESSAGE_RECORD;
            header[1..].copy_from_slice(&(written as u16).to_be_bytes());
            self.stream.write_all(&header).await?;
            self.stream.write_all(&encrypted).await?;
        }
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn read_plaintext_record(
        &mut self,
    ) -> Result<Vec<u8>, TailscaleControlError> {
        let mut header = [0_u8; TAILSCALE_CONTROL_HEADER_LENGTH];
        self.stream.read_exact(&mut header).await?;
        if header[0] != MESSAGE_RECORD {
            return Err(TailscaleControlError::UnexpectedMessageType {
                actual: header[0],
                expected: MESSAGE_RECORD,
            });
        }
        let length = usize::from(u16::from_be_bytes([header[1], header[2]]));
        if length + TAILSCALE_CONTROL_HEADER_LENGTH
            > TAILSCALE_CONTROL_MAX_MESSAGE_SIZE
        {
            return Err(TailscaleControlError::RecordTooLarge);
        }
        if length < TAILSCALE_CONTROL_TAG_LENGTH {
            return Err(TailscaleControlError::InvalidMessageLength {
                actual: length,
                expected: TAILSCALE_CONTROL_TAG_LENGTH,
            });
        }
        let mut encrypted = vec![0_u8; length];
        self.stream.read_exact(&mut encrypted).await?;
        let mut plaintext = vec![0_u8; length - TAILSCALE_CONTROL_TAG_LENGTH];
        let written = self
            .transport
            .read_message(&encrypted, &mut plaintext)
            .map_err(noise_error)?;
        plaintext.truncate(written);
        Ok(plaintext)
    }

    pub async fn read_exact_plaintext(
        &mut self,
        length: usize,
    ) -> Result<Vec<u8>, TailscaleControlError> {
        while self.plaintext.len() < length {
            let record = self.read_plaintext_record().await?;
            self.plaintext.extend(record);
        }
        Ok(self.plaintext.drain(..length).collect())
    }

    /// Read the optional EarlyNoise JSON prefix. When the server starts HTTP/2
    /// immediately, the already-consumed nine-byte SETTINGS header is returned.
    pub async fn read_early_payload(
        &mut self,
    ) -> Result<TailscaleControlEarlyPayload, TailscaleControlError> {
        let header = self.read_exact_plaintext(9).await?;
        let Some(length) = parse_early_payload_length(&header)? else {
            for byte in header.iter().rev() {
                self.plaintext.push_front(*byte);
            }
            return Ok(TailscaleControlEarlyPayload::Http2Prefix(header));
        };
        let json = self.read_exact_plaintext(length).await?;
        let value = serde_json::from_slice(&json).map_err(|error| {
            TailscaleControlError::EarlyPayload(error.to_string())
        })?;
        Ok(TailscaleControlEarlyPayload::Json(value))
    }
}

impl<S> AsyncRead for TailscaleControlStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.plaintext.is_empty() {
                let count = output.remaining().min(self.plaintext.len());
                for _ in 0..count {
                    output.put_slice(&[self
                        .plaintext
                        .pop_front()
                        .expect("checked length")]);
                }
                return Poll::Ready(Ok(()));
            }

            while self.read_header_filled < TAILSCALE_CONTROL_HEADER_LENGTH {
                let remaining =
                    TAILSCALE_CONTROL_HEADER_LENGTH - self.read_header_filled;
                let mut scratch = [0_u8; TAILSCALE_CONTROL_HEADER_LENGTH];
                let mut input = ReadBuf::new(&mut scratch[..remaining]);
                match Pin::new(&mut self.stream).poll_read(context, &mut input)
                {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if input.filled().is_empty() => {
                        return if self.read_header_filled == 0 {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated Tailscale control record header",
                            )))
                        };
                    }
                    Poll::Ready(Ok(())) => {
                        let start = self.read_header_filled;
                        let end = start + input.filled().len();
                        self.read_header[start..end]
                            .copy_from_slice(input.filled());
                        self.read_header_filled = end;
                    }
                }
            }

            if self.read_ciphertext.is_empty() {
                if self.read_header[0] != MESSAGE_RECORD {
                    return Poll::Ready(Err(io::Error::other(
                        TailscaleControlError::UnexpectedMessageType {
                            actual: self.read_header[0],
                            expected: MESSAGE_RECORD,
                        },
                    )));
                }
                let length = usize::from(u16::from_be_bytes([
                    self.read_header[1],
                    self.read_header[2],
                ]));
                if length + TAILSCALE_CONTROL_HEADER_LENGTH
                    > TAILSCALE_CONTROL_MAX_MESSAGE_SIZE
                {
                    return Poll::Ready(Err(io::Error::other(
                        TailscaleControlError::RecordTooLarge,
                    )));
                }
                if length < TAILSCALE_CONTROL_TAG_LENGTH {
                    return Poll::Ready(Err(io::Error::other(
                        TailscaleControlError::InvalidMessageLength {
                            actual: length,
                            expected: TAILSCALE_CONTROL_TAG_LENGTH,
                        },
                    )));
                }
                self.read_ciphertext.resize(length, 0);
                self.read_ciphertext_filled = 0;
            }

            while self.read_ciphertext_filled < self.read_ciphertext.len() {
                let remaining =
                    self.read_ciphertext.len() - self.read_ciphertext_filled;
                let mut scratch = [0_u8; TAILSCALE_CONTROL_MAX_MESSAGE_SIZE];
                let mut input = ReadBuf::new(&mut scratch[..remaining]);
                match Pin::new(&mut self.stream).poll_read(context, &mut input)
                {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if input.filled().is_empty() => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated Tailscale control record",
                        )));
                    }
                    Poll::Ready(Ok(())) => {
                        let start = self.read_ciphertext_filled;
                        let end = start + input.filled().len();
                        self.read_ciphertext[start..end]
                            .copy_from_slice(input.filled());
                        self.read_ciphertext_filled = end;
                    }
                }
            }

            let ciphertext = std::mem::take(&mut self.read_ciphertext);
            let mut plaintext =
                vec![0_u8; ciphertext.len() - TAILSCALE_CONTROL_TAG_LENGTH];
            let written = match self
                .transport
                .read_message(&ciphertext, &mut plaintext)
            {
                Ok(written) => written,
                Err(error) => {
                    return Poll::Ready(Err(io::Error::other(noise_error(
                        error,
                    ))));
                }
            };
            plaintext.truncate(written);
            self.plaintext.extend(plaintext);
            self.read_header_filled = 0;
            self.read_ciphertext_filled = 0;
        }
    }
}

impl<S> AsyncWrite for TailscaleControlStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().poll_drain_write(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = input.len().min(TAILSCALE_CONTROL_MAX_PLAINTEXT_SIZE);
        let mut encrypted = vec![0_u8; count + TAILSCALE_CONTROL_TAG_LENGTH];
        let written = match self
            .transport
            .write_message(&input[..count], &mut encrypted)
        {
            Ok(written) => written,
            Err(error) => {
                return Poll::Ready(Err(io::Error::other(noise_error(error))));
            }
        };
        encrypted.truncate(written);
        self.write_wire
            .reserve(TAILSCALE_CONTROL_HEADER_LENGTH + written);
        self.write_wire.push(MESSAGE_RECORD);
        self.write_wire
            .extend_from_slice(&(written as u16).to_be_bytes());
        self.write_wire.extend_from_slice(&encrypted);
        self.write_wire_offset = 0;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().poll_drain_write(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                Pin::new(&mut self.stream).poll_flush(context)
            }
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().poll_drain_write(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                Pin::new(&mut self.stream).poll_shutdown(context)
            }
        }
    }
}

impl<S> TailscaleControlStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_drain_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.write_wire_offset < self.write_wire.len() {
            let pending = self.write_wire[self.write_wire_offset..].to_vec();
            match Pin::new(&mut self.stream).poll_write(context, &pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write Tailscale control record",
                    )));
                }
                Poll::Ready(Ok(written)) => self.write_wire_offset += written,
            }
        }
        self.write_wire.clear();
        self.write_wire_offset = 0;
        Poll::Ready(Ok(()))
    }
}

fn parse_early_payload_length(
    header: &[u8],
) -> Result<Option<usize>, TailscaleControlError> {
    if !header.starts_with(TAILSCALE_CONTROL_EARLY_PAYLOAD_MAGIC) {
        return Ok(None);
    }
    if header.len() < 9 {
        return Err(TailscaleControlError::EarlyPayload(
            "truncated early payload header".into(),
        ));
    }
    let length =
        u32::from_be_bytes(header[5..9].try_into().expect("four-byte length"))
            as usize;
    if length > TAILSCALE_CONTROL_MAX_EARLY_PAYLOAD_SIZE {
        return Err(TailscaleControlError::EarlyPayload(format!(
            "length {length} exceeds 10 MiB"
        )));
    }
    Ok(Some(length))
}

#[derive(Debug, Clone, PartialEq)]
pub enum TailscaleControlEarlyPayload {
    Json(Value),
    Http2Prefix(Vec<u8>),
}

pub struct TailscaleControlHttp2Client {
    sender: SendRequest<Full<Bytes>>,
    driver: tokio::task::JoinHandle<Result<(), hyper::Error>>,
}

impl TailscaleControlHttp2Client {
    pub async fn send_request(
        &mut self,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>, TailscaleControlError> {
        self.sender
            .ready()
            .await
            .map_err(|error| TailscaleControlError::Http2(error.to_string()))?;
        self.sender
            .send_request(request)
            .await
            .map_err(|error| TailscaleControlError::Http2(error.to_string()))
    }

    pub fn driver(&self) -> &tokio::task::JoinHandle<Result<(), hyper::Error>> {
        &self.driver
    }

    /// Send one JSON control RPC over the persistent TS2021 HTTP/2 session.
    /// `lb_keys` become repeated `Ts-Lb` headers as in the Go client.
    pub async fn json_request<T>(
        &mut self,
        method: Method,
        authority: &str,
        path: &str,
        value: &T,
        lb_keys: &[&str],
    ) -> Result<Response<Incoming>, TailscaleControlError>
    where
        T: Serialize,
    {
        validate_http_component("authority", authority)?;
        validate_http_component("path", path)?;
        if !path.starts_with('/') {
            return Err(TailscaleControlError::InvalidHttpRequest(
                "control RPC path must start with '/'".into(),
            ));
        }
        let body = serde_json::to_vec(value).map_err(|error| {
            TailscaleControlError::ControlJson(error.to_string())
        })?;
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", authority)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|error| {
                TailscaleControlError::InvalidHttpRequest(error.to_string())
            })?;
        for key in lb_keys {
            validate_http_component("Ts-Lb", key)?;
            let value =
                hyper::header::HeaderValue::from_str(key).map_err(|error| {
                    TailscaleControlError::InvalidHttpRequest(error.to_string())
                })?;
            request.headers_mut().append("ts-lb", value);
        }
        self.send_request(request).await
    }

    pub async fn post_json<T>(
        &mut self,
        authority: &str,
        path: &str,
        value: &T,
        lb_keys: &[&str],
    ) -> Result<Response<Incoming>, TailscaleControlError>
    where
        T: Serialize,
    {
        self.json_request(Method::POST, authority, path, value, lb_keys)
            .await
    }

    /// TKA synchronization uses GET-with-JSON-body for compatibility with the
    /// upstream Noise RPC contract.
    pub async fn get_json<T>(
        &mut self,
        authority: &str,
        path: &str,
        value: &T,
        lb_keys: &[&str],
    ) -> Result<Response<Incoming>, TailscaleControlError>
    where
        T: Serialize,
    {
        self.json_request(Method::GET, authority, path, value, lb_keys)
            .await
    }

    /// Register a node over the authenticated control connection.
    pub async fn register(
        &mut self,
        authority: &str,
        request: &TailscaleRegisterRequest,
        lb_keys: &[&str],
    ) -> Result<TailscaleRegisterResponse, TailscaleControlError> {
        let response = self
            .post_json(authority, TAILSCALE_REGISTER_PATH, request, lb_keys)
            .await?;
        decode_tailscale_control_json_response(
            response,
            TAILSCALE_REGISTER_RESPONSE_LIMIT,
        )
        .await
    }

    /// Publish an ACME DNS-01 TXT record through the authenticated control
    /// channel.
    pub async fn set_dns(
        &mut self,
        authority: &str,
        request: &TailscaleSetDnsRequest,
        lb_keys: &[&str],
    ) -> Result<TailscaleSetDnsResponse, TailscaleControlError> {
        let response = self
            .post_json(authority, TAILSCALE_SET_DNS_PATH, request, lb_keys)
            .await?;
        decode_tailscale_control_json_response(
            response,
            TAILSCALE_SET_DNS_RESPONSE_LIMIT,
        )
        .await
    }

    /// Start a streaming `/machine/map` RPC. The response body is consumed by
    /// [`TailscaleMapFrameDecoder`].
    pub async fn start_map(
        &mut self,
        authority: &str,
        request: &TailscaleMapRequest,
        lb_keys: &[&str],
    ) -> Result<Response<Incoming>, TailscaleControlError> {
        let response = self
            .post_json(authority, TAILSCALE_MAP_PATH, request, lb_keys)
            .await?;
        if response.status() == hyper::StatusCode::OK {
            return Ok(response);
        }
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|error| {
                TailscaleControlError::Http2(error.to_string())
            })?;
            if let Some(data) = frame.data_ref() {
                let remaining = TAILSCALE_CONTROL_MAX_ERROR_RESPONSE_SIZE
                    .saturating_sub(bytes.len());
                bytes.extend_from_slice(&data[..data.len().min(remaining)]);
            }
            if bytes.len() == TAILSCALE_CONTROL_MAX_ERROR_RESPONSE_SIZE {
                break;
            }
        }
        Err(TailscaleControlError::ControlHttpStatus {
            status,
            message: String::from_utf8_lossy(&bytes)
                .trim()
                .chars()
                .take(200)
                .collect(),
        })
    }

    pub async fn tka_bootstrap(
        &mut self,
        authority: &str,
        request: &TailscaleTkaBootstrapRequest,
        lb_keys: &[&str],
    ) -> Result<TailscaleTkaBootstrapResponse, TailscaleControlError> {
        let response = self
            .get_json(authority, TAILSCALE_TKA_BOOTSTRAP_PATH, request, lb_keys)
            .await?;
        decode_tailscale_control_json_response(
            response,
            TAILSCALE_TKA_BOOTSTRAP_RESPONSE_LIMIT,
        )
        .await
    }

    pub async fn tka_sync_offer(
        &mut self,
        authority: &str,
        request: &TailscaleTkaSyncOfferRequest,
        lb_keys: &[&str],
    ) -> Result<TailscaleTkaSyncOfferResponse, TailscaleControlError> {
        let response = self
            .get_json(
                authority,
                TAILSCALE_TKA_SYNC_OFFER_PATH,
                request,
                lb_keys,
            )
            .await?;
        decode_tailscale_control_json_response(
            response,
            TAILSCALE_TKA_SYNC_RESPONSE_LIMIT,
        )
        .await
    }

    pub async fn tka_sync_send(
        &mut self,
        authority: &str,
        request: &TailscaleTkaSyncSendRequest,
        lb_keys: &[&str],
    ) -> Result<TailscaleTkaSyncSendResponse, TailscaleControlError> {
        let response = self
            .get_json(authority, TAILSCALE_TKA_SYNC_SEND_PATH, request, lb_keys)
            .await?;
        decode_tailscale_control_json_response(
            response,
            TAILSCALE_TKA_SYNC_RESPONSE_LIMIT,
        )
        .await
    }
}

impl Drop for TailscaleControlHttp2Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Consume an authenticated TS2021 connection and start its persistent HTTP/2
/// client. The optional value is the server's EarlyNoise JSON.
pub async fn start_tailscale_control_http2<S>(
    mut stream: TailscaleControlStream<S>,
) -> Result<(Option<Value>, TailscaleControlHttp2Client), TailscaleControlError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let early_payload = match stream.read_early_payload().await? {
        TailscaleControlEarlyPayload::Json(value) => Some(value),
        TailscaleControlEarlyPayload::Http2Prefix(_) => None,
    };
    let (sender, connection) =
        hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|error| TailscaleControlError::Http2(error.to_string()))?;
    let driver = tokio::spawn(connection);
    Ok((
        early_payload,
        TailscaleControlHttp2Client { sender, driver },
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleControlServerKeys {
    pub legacy_public_key: Option<[u8; 32]>,
    pub public_key: [u8; 32],
}

/// Collect and decode a bounded JSON response from a register-style control
/// RPC. Map long-poll responses use [`TailscaleMapFrameDecoder`] instead.
pub async fn decode_tailscale_control_json_response<T, B>(
    response: Response<B>,
    maximum: usize,
) -> Result<T, TailscaleControlError>
where
    T: DeserializeOwned,
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let status = response.status();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|error| TailscaleControlError::Http2(error.to_string()))?;
        if let Some(data) = frame.data_ref() {
            if bytes.len().saturating_add(data.len()) > maximum {
                return Err(TailscaleControlError::ControlBodyTooLarge {
                    maximum,
                });
            }
            bytes.extend_from_slice(data);
        }
    }
    if status != hyper::StatusCode::OK {
        let message = String::from_utf8_lossy(&bytes);
        return Err(TailscaleControlError::ControlHttpStatus {
            status: status.as_u16(),
            message: message.trim().chars().take(200).collect(),
        });
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| TailscaleControlError::ControlJson(error.to_string()))
}

/// Incremental decoder for `/machine/map`'s little-endian length-prefixed,
/// independent zstd frames.
pub struct TailscaleMapFrameDecoder {
    buffer: Vec<u8>,
    maximum_compressed_size: usize,
    maximum_decoded_size: usize,
}

impl TailscaleMapFrameDecoder {
    pub fn new(
        maximum_compressed_size: usize,
        maximum_decoded_size: usize,
    ) -> Self {
        Self {
            buffer: Vec::new(),
            maximum_compressed_size,
            maximum_decoded_size,
        }
    }

    pub fn push(
        &mut self,
        bytes: &[u8],
    ) -> Result<Vec<Value>, TailscaleControlError> {
        self.push_typed(bytes)
    }

    /// Decode frames directly into the caller's control response type.
    pub fn push_typed<T>(
        &mut self,
        bytes: &[u8],
    ) -> Result<Vec<T>, TailscaleControlError>
    where
        T: DeserializeOwned,
    {
        self.buffer.extend_from_slice(bytes);
        let mut messages = Vec::new();
        loop {
            if self.buffer.len() < 4 {
                return Ok(messages);
            }
            let length = u32::from_le_bytes(
                self.buffer[..4].try_into().expect("four-byte map length"),
            ) as usize;
            if length > self.maximum_compressed_size {
                return Err(TailscaleControlError::MapFrameTooLarge {
                    actual: length,
                    maximum: self.maximum_compressed_size,
                });
            }
            if self.buffer.len() < 4 + length {
                return Ok(messages);
            }
            let compressed = self.buffer[4..4 + length].to_vec();
            self.buffer.drain(..4 + length);
            let decoded =
                zstd::bulk::decompress(&compressed, self.maximum_decoded_size)
                    .map_err(|error| {
                        TailscaleControlError::MapCompression(error.to_string())
                    })?;
            let response =
                serde_json::from_slice(&decoded).map_err(|error| {
                    TailscaleControlError::ControlJson(error.to_string())
                })?;
            messages.push(response);
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

#[derive(Deserialize)]
struct TailscaleControlServerKeysJson {
    #[serde(rename = "legacyPublicKey")]
    #[serde(default)]
    legacy_public_key: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

/// Build the TLS bootstrap path used to discover the control server Noise key.
pub fn tailscale_control_key_path(capability_version: u32) -> String {
    format!("/key?v={capability_version}")
}

/// Parse the modern `/key` JSON response, with the legacy raw 64-hex response
/// fallback retained for older coordination servers.
pub fn parse_tailscale_control_server_keys(
    response: &[u8],
) -> Result<TailscaleControlServerKeys, TailscaleControlError> {
    if response.len() > TAILSCALE_CONTROL_MAX_KEY_RESPONSE_SIZE {
        return Err(TailscaleControlError::InvalidHttpResponse(
            "control key response exceeds 64 KiB".into(),
        ));
    }
    if let Ok(response) =
        serde_json::from_slice::<TailscaleControlServerKeysJson>(response)
    {
        let public_key = parse_machine_public_key(&response.public_key)?;
        validate_key(&public_key)?;
        let legacy_public_key =
            if is_zero_machine_public_key(&response.legacy_public_key) {
                None
            } else {
                Some(parse_machine_public_key(&response.legacy_public_key)?)
            };
        return Ok(TailscaleControlServerKeys {
            legacy_public_key,
            public_key,
        });
    }
    let legacy_public_key = parse_machine_public_key(
        std::str::from_utf8(response).map_err(|_| {
            TailscaleControlError::InvalidHttpResponse(
                "control key response is neither JSON nor ASCII hex".into(),
            )
        })?,
    )?;
    validate_key(&legacy_public_key)?;
    Ok(TailscaleControlServerKeys {
        legacy_public_key: Some(legacy_public_key),
        public_key: [0; 32],
    })
}

fn parse_machine_public_key(
    value: &str,
) -> Result<[u8; 32], TailscaleControlError> {
    let value = value.strip_prefix("mkey:").unwrap_or(value);
    if value.len() != 64 {
        return Err(TailscaleControlError::InvalidHttpResponse(
            "machine public key must contain 64 hexadecimal digits".into(),
        ));
    }
    let decoded = hex::decode(value).map_err(|error| {
        TailscaleControlError::InvalidHttpResponse(format!(
            "invalid machine public key: {error}"
        ))
    })?;
    Ok(decoded.try_into().expect("validated 32-byte key"))
}

fn is_zero_machine_public_key(value: &str) -> bool {
    let value = value.strip_prefix("mkey:").unwrap_or(value);
    value.is_empty()
        || (value.len() == 64 && value.bytes().all(|byte| byte == b'0'))
}

pub async fn connect_tailscale_control<S>(
    mut stream: S,
    authority: &str,
    machine_private_key: [u8; 32],
    control_public_key: [u8; 32],
    version: u16,
) -> Result<TailscaleControlStream<S>, TailscaleControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let handshake = TailscaleControlHandshake::start(
        machine_private_key,
        control_public_key,
        version,
    )?;
    let request = handshake.http_upgrade_request(authority)?;
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    read_control_upgrade_response(&mut stream).await?;
    handshake.finish(stream).await
}

async fn read_control_upgrade_response<S>(
    stream: &mut S,
) -> Result<(), TailscaleControlError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let header = read_http_header(stream).await?;
    let header = std::str::from_utf8(&header).map_err(|_| {
        TailscaleControlError::InvalidHttpResponse(
            "header is not UTF-8/ASCII".into(),
        )
    })?;
    let mut lines = header.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut fields = status_line.splitn(3, ' ');
    let protocol = fields.next().unwrap_or_default();
    let status = fields
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            TailscaleControlError::InvalidHttpResponse(
                "malformed status".into(),
            )
        })?;
    let reason = fields.next().unwrap_or_default().to_owned();
    if !protocol.starts_with("HTTP/1.") {
        return Err(TailscaleControlError::InvalidHttpResponse(
            "upgrade response is not HTTP/1.x".into(),
        ));
    }
    if status != 101 {
        return Err(TailscaleControlError::HttpUpgrade { status, reason });
    }
    let upgrade = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("Upgrade"))
        .map(|(_, value)| value.trim())
        .unwrap_or_default();
    if upgrade != TAILSCALE_CONTROL_UPGRADE_PROTOCOL {
        return Err(TailscaleControlError::UnexpectedUpgrade(upgrade.into()));
    }
    Ok(())
}

async fn read_http_header<S>(
    stream: &mut S,
) -> Result<Vec<u8>, TailscaleControlError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut header = Vec::with_capacity(512);
    loop {
        if header.len() == 64 << 10 {
            return Err(TailscaleControlError::HttpHeaderTooLarge);
        }
        header.push(stream.read_u8().await?);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
}

fn validate_key(key: &[u8; 32]) -> Result<(), TailscaleControlError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(TailscaleControlError::ZeroKey);
    }
    Ok(())
}

fn validate_http_component(
    label: &str,
    value: &str,
) -> Result<(), TailscaleControlError> {
    if value.is_empty()
        || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return Err(TailscaleControlError::InvalidHttpRequest(format!(
            "{label} is empty or contains a line break"
        )));
    }
    Ok(())
}

fn noise_error(error: impl std::fmt::Display) -> TailscaleControlError {
    TailscaleControlError::Noise(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tailscale::tailscale_node_public_key;

    fn responder(control_private: &[u8; 32], version: u16) -> HandshakeState {
        let params: NoiseParams =
            TAILSCALE_CONTROL_NOISE_PROTOCOL.parse().unwrap();
        Builder::new(params)
            .prologue(
                format!("{TAILSCALE_CONTROL_PROLOGUE_PREFIX}{version}")
                    .as_bytes(),
            )
            .unwrap()
            .local_private_key(control_private)
            .unwrap()
            .build_responder()
            .unwrap()
    }

    async fn write_server_record<S: AsyncWrite + Unpin>(
        stream: &mut S,
        transport: &mut TransportState,
        plaintext: &[u8],
    ) {
        let mut encrypted =
            vec![0; plaintext.len() + TAILSCALE_CONTROL_TAG_LENGTH];
        let written =
            transport.write_message(plaintext, &mut encrypted).unwrap();
        stream.write_u8(MESSAGE_RECORD).await.unwrap();
        stream.write_u16(written as u16).await.unwrap();
        stream.write_all(&encrypted[..written]).await.unwrap();
        stream.flush().await.unwrap();
    }

    #[test]
    fn initiation_and_upgrade_request_match_ts2021_layout() {
        let control_public = tailscale_node_public_key([2; 32]).unwrap();
        let handshake =
            TailscaleControlHandshake::start([1; 32], control_public, 123)
                .unwrap();
        assert_eq!(handshake.initial_message().len(), 101);
        assert_eq!(&handshake.initial_message()[..2], &123_u16.to_be_bytes());
        assert_eq!(handshake.initial_message()[2], MESSAGE_INITIATION);
        assert_eq!(&handshake.initial_message()[3..5], &(96_u16).to_be_bytes());
        let request = handshake
            .http_upgrade_request("control.example:443")
            .unwrap();
        assert!(request.starts_with("POST /ts2021 HTTP/1.1\r\n"));
        assert!(request.contains("Upgrade: tailscale-control-protocol\r\n"));
        let encoded = request
            .lines()
            .find_map(|line| line.strip_prefix("X-Tailscale-Handshake: "))
            .unwrap();
        assert_eq!(
            STANDARD.decode(encoded).unwrap(),
            handshake.initial_message()
        );
    }

    #[test]
    fn parses_modern_and_legacy_control_key_responses() {
        let legacy = [7_u8; 32];
        let noise = [8_u8; 32];
        let response = serde_json::json!({
            "legacyPublicKey": format!("mkey:{}", hex::encode(legacy)),
            "publicKey": format!("mkey:{}", hex::encode(noise))
        });
        assert_eq!(
            parse_tailscale_control_server_keys(
                &serde_json::to_vec(&response).unwrap()
            )
            .unwrap(),
            TailscaleControlServerKeys {
                legacy_public_key: Some(legacy),
                public_key: noise,
            }
        );
        assert_eq!(
            parse_tailscale_control_server_keys(hex::encode(legacy).as_bytes())
                .unwrap(),
            TailscaleControlServerKeys {
                legacy_public_key: Some(legacy),
                public_key: [0; 32],
            }
        );
        assert_eq!(tailscale_control_key_path(138), "/key?v=138");
    }

    #[test]
    fn map_decoder_handles_partial_and_concatenated_zstd_frames() {
        let encode = |json: &[u8]| {
            let compressed = zstd::bulk::compress(json, 0).unwrap();
            let mut framed = (compressed.len() as u32).to_le_bytes().to_vec();
            framed.extend_from_slice(&compressed);
            framed
        };
        let mut wire = encode(br#"{"KeepAlive":true}"#);
        wire.extend_from_slice(&encode(
            br#"{"Seq":7,"Domain":"example.test"}"#,
        ));
        let split = wire.len() / 3;
        let mut decoder = TailscaleMapFrameDecoder::new(1 << 20, 1 << 20);
        assert!(decoder.push(&wire[..split]).unwrap().is_empty());
        assert_eq!(
            decoder.push(&wire[split..]).unwrap(),
            vec![
                serde_json::json!({"KeepAlive": true}),
                serde_json::json!({"Seq": 7, "Domain": "example.test"})
            ]
        );
        assert_eq!(decoder.buffered_len(), 0);

        let mut oversized = TailscaleMapFrameDecoder::new(4, 1024);
        assert!(matches!(
            oversized.push(&5_u32.to_le_bytes()),
            Err(TailscaleControlError::MapFrameTooLarge {
                actual: 5,
                maximum: 4
            })
        ));
    }

    #[tokio::test]
    async fn bounded_control_json_response_checks_status_and_size() {
        let response = Response::builder()
            .status(200)
            .body(Full::new(Bytes::from_static(br#"{"ok":true}"#)))
            .unwrap();
        assert_eq!(
            decode_tailscale_control_json_response::<Value, _>(response, 64)
                .await
                .unwrap(),
            serde_json::json!({"ok": true})
        );
        let denied = Response::builder()
            .status(403)
            .body(Full::new(Bytes::from_static(b" denied ")))
            .unwrap();
        assert!(matches!(
            decode_tailscale_control_json_response::<Value, _>(denied, 64).await,
            Err(TailscaleControlError::ControlHttpStatus {
                status: 403,
                message
            }) if message == "denied"
        ));
        let oversized = Response::new(Full::new(Bytes::from_static(b"12345")));
        assert!(matches!(
            decode_tailscale_control_json_response::<Value, _>(oversized, 4)
                .await,
            Err(TailscaleControlError::ControlBodyTooLarge { maximum: 4 })
        ));
    }

    #[tokio::test]
    async fn http_noise_handshake_records_and_early_payload_interoperate() {
        let machine_private = [31_u8; 32];
        let machine_public =
            tailscale_node_public_key(machine_private).unwrap();
        let control_private = [41_u8; 32];
        let control_public =
            tailscale_node_public_key(control_private).unwrap();
        let version = 138;
        let (client_stream, mut server_stream) = tokio::io::duplex(32 << 10);
        let server = tokio::spawn(async move {
            let request = String::from_utf8(
                read_http_header(&mut server_stream).await.unwrap(),
            )
            .unwrap();
            let encoded = request
                .lines()
                .find_map(|line| line.strip_prefix("X-Tailscale-Handshake: "))
                .unwrap();
            let initial = STANDARD.decode(encoded).unwrap();
            assert_eq!(initial.len(), 101);
            let mut noise = responder(&control_private, version);
            let mut empty = [];
            noise.read_message(&initial[5..], &mut empty).unwrap();
            assert_eq!(noise.get_remote_static().unwrap(), machine_public);
            let mut response = [0_u8; RESPONSE_PAYLOAD_LENGTH];
            let written = noise.write_message(&[], &mut response).unwrap();
            assert_eq!(written, RESPONSE_PAYLOAD_LENGTH);
            server_stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\n\r\n",
                )
                .await
                .unwrap();
            server_stream.write_u8(MESSAGE_RESPONSE).await.unwrap();
            server_stream
                .write_u16(RESPONSE_PAYLOAD_LENGTH as u16)
                .await
                .unwrap();
            server_stream.write_all(&response).await.unwrap();
            server_stream.flush().await.unwrap();
            let mut transport = noise.into_transport_mode().unwrap();

            let expected = vec![0x5a; 5000];
            let mut received = Vec::new();
            while received.len() < expected.len() {
                assert_eq!(
                    server_stream.read_u8().await.unwrap(),
                    MESSAGE_RECORD
                );
                let length = server_stream.read_u16().await.unwrap() as usize;
                assert!(length + 3 <= TAILSCALE_CONTROL_MAX_MESSAGE_SIZE);
                let mut encrypted = vec![0; length];
                server_stream.read_exact(&mut encrypted).await.unwrap();
                let mut plaintext = vec![0; length - 16];
                let read =
                    transport.read_message(&encrypted, &mut plaintext).unwrap();
                received.extend_from_slice(&plaintext[..read]);
            }
            assert_eq!(received, expected);

            let json = br#"{"nodeKeyChallenge":"test"}"#;
            let mut early = TAILSCALE_CONTROL_EARLY_PAYLOAD_MAGIC.to_vec();
            early.extend_from_slice(&(json.len() as u32).to_be_bytes());
            early.extend_from_slice(json);
            write_server_record(&mut server_stream, &mut transport, &early)
                .await;
            write_server_record(
                &mut server_stream,
                &mut transport,
                b"http2 plaintext",
            )
            .await;
        });

        let mut client = connect_tailscale_control(
            client_stream,
            "control.example:443",
            machine_private,
            control_public,
            version,
        )
        .await
        .unwrap();
        assert_eq!(client.protocol_version(), version);
        assert_eq!(client.peer(), control_public);
        assert_ne!(client.handshake_hash(), [0; 32]);
        client.write_all(&vec![0x5a; 5000]).await.unwrap();
        client.flush().await.unwrap();
        assert_eq!(
            client.read_early_payload().await.unwrap(),
            TailscaleControlEarlyPayload::Json(
                serde_json::json!({"nodeKeyChallenge": "test"})
            )
        );
        let mut plaintext = [0_u8; 15];
        client.read_exact(&mut plaintext).await.unwrap();
        assert_eq!(&plaintext, b"http2 plaintext");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn early_payload_preserves_http2_prefix_and_rejects_oversize() {
        let control_private = [51_u8; 32];
        let control_public =
            tailscale_node_public_key(control_private).unwrap();
        let (client_stream, mut server_stream) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let request = String::from_utf8(
                read_http_header(&mut server_stream).await.unwrap(),
            )
            .unwrap();
            let init = STANDARD
                .decode(
                    request
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("X-Tailscale-Handshake: ")
                        })
                        .unwrap(),
                )
                .unwrap();
            let mut noise = responder(&control_private, 1);
            noise.read_message(&init[5..], &mut []).unwrap();
            let mut response = [0; 48];
            noise.write_message(&[], &mut response).unwrap();
            server_stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\n\r\n\x02\x00\x30")
                .await
                .unwrap();
            server_stream.write_all(&response).await.unwrap();
            server_stream.flush().await.unwrap();
            let mut transport = noise.into_transport_mode().unwrap();
            write_server_record(
                &mut server_stream,
                &mut transport,
                b"\x00\x00\x00\x04\x00\x00\x00\x00\x00",
            )
            .await;
        });
        let mut client = connect_tailscale_control(
            client_stream,
            "control.example",
            [61; 32],
            control_public,
            1,
        )
        .await
        .unwrap();
        let prefix = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00";
        assert_eq!(
            client.read_early_payload().await.unwrap(),
            TailscaleControlEarlyPayload::Http2Prefix(prefix.to_vec())
        );
        let mut replayed = [0_u8; 9];
        client.read_exact(&mut replayed).await.unwrap();
        assert_eq!(&replayed, prefix);
        server.await.unwrap();

        let mut huge = TAILSCALE_CONTROL_EARLY_PAYLOAD_MAGIC.to_vec();
        huge.extend_from_slice(&((10_u32 << 20) + 1).to_be_bytes());
        assert!(matches!(
            parse_early_payload_length(&huge),
            Err(TailscaleControlError::EarlyPayload(_))
        ));
    }

    #[tokio::test]
    async fn authenticated_stream_starts_a_real_hyper_http2_client() {
        let control_private = [71_u8; 32];
        let control_public =
            tailscale_node_public_key(control_private).unwrap();
        let (client_stream, mut server_stream) = tokio::io::duplex(32 << 10);
        let server = tokio::spawn(async move {
            let request = String::from_utf8(
                read_http_header(&mut server_stream).await.unwrap(),
            )
            .unwrap();
            let initial = STANDARD
                .decode(
                    request
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("X-Tailscale-Handshake: ")
                        })
                        .unwrap(),
                )
                .unwrap();
            let mut noise = responder(&control_private, 1);
            noise.read_message(&initial[5..], &mut []).unwrap();
            let mut response = [0; 48];
            noise.write_message(&[], &mut response).unwrap();
            server_stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\n\r\n\x02\x00\x30")
                .await
                .unwrap();
            server_stream.write_all(&response).await.unwrap();
            server_stream.flush().await.unwrap();
            let mut transport = noise.into_transport_mode().unwrap();
            write_server_record(
                &mut server_stream,
                &mut transport,
                b"\x00\x00\x00\x04\x00\x00\x00\x00\x00",
            )
            .await;

            let mut plaintext = Vec::new();
            while plaintext.len() < 24 {
                assert_eq!(
                    server_stream.read_u8().await.unwrap(),
                    MESSAGE_RECORD
                );
                let length = server_stream.read_u16().await.unwrap() as usize;
                let mut encrypted = vec![0; length];
                server_stream.read_exact(&mut encrypted).await.unwrap();
                let mut decoded =
                    vec![0; length - TAILSCALE_CONTROL_TAG_LENGTH];
                let written =
                    transport.read_message(&encrypted, &mut decoded).unwrap();
                plaintext.extend_from_slice(&decoded[..written]);
            }
            assert!(plaintext.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
        });

        let stream = connect_tailscale_control(
            client_stream,
            "control.example",
            [72; 32],
            control_public,
            1,
        )
        .await
        .unwrap();
        let (early, client) =
            start_tailscale_control_http2(stream).await.unwrap();
        assert!(early.is_none());
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        drop(client);
    }

    #[tokio::test]
    async fn authenticated_http2_json_rpcs_use_typed_wire_models() {
        use super::super::tailscale_control_types::{
            TailscaleNodePublicKey, TailscaleRegisterRequest,
            TailscaleRegisterResponse, TailscaleSetDnsRequest,
            TailscaleSetDnsResponse, TailscaleTkaBootstrapRequest,
            TailscaleTkaBootstrapResponse,
        };

        let control_private = [81_u8; 32];
        let control_public =
            tailscale_node_public_key(control_private).unwrap();
        let (client_stream, mut server_stream) = tokio::io::duplex(64 << 10);
        let server = tokio::spawn(async move {
            let request = String::from_utf8(
                read_http_header(&mut server_stream).await.unwrap(),
            )
            .unwrap();
            let initial = STANDARD
                .decode(
                    request
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("X-Tailscale-Handshake: ")
                        })
                        .unwrap(),
                )
                .unwrap();
            let mut noise = responder(&control_private, 1);
            noise.read_message(&initial[5..], &mut []).unwrap();
            let mut response = [0; 48];
            noise.write_message(&[], &mut response).unwrap();
            let handshake_hash = noise.get_handshake_hash().try_into().unwrap();
            server_stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\n\r\n\x02\x00\x30")
                .await
                .unwrap();
            server_stream.write_all(&response).await.unwrap();
            server_stream.flush().await.unwrap();
            let stream = TailscaleControlStream {
                stream: server_stream,
                transport: noise.into_transport_mode().unwrap(),
                version: 1,
                control_public_key: [0; 32],
                handshake_hash,
                plaintext: VecDeque::new(),
                read_header: [0; TAILSCALE_CONTROL_HEADER_LENGTH],
                read_header_filled: 0,
                read_ciphertext: Vec::new(),
                read_ciphertext_filled: 0,
                write_wire: Vec::new(),
                write_wire_offset: 0,
            };
            let service = hyper::service::service_fn(
                |request: Request<Incoming>| async move {
                    assert_eq!(
                        request.headers().get_all("ts-lb").iter().count(),
                        2
                    );
                    let method = request.method().clone();
                    let path = request.uri().path().to_owned();
                    let body =
                        request.into_body().collect().await.unwrap().to_bytes();
                    let body = match path.as_str() {
                        TAILSCALE_REGISTER_PATH => {
                            assert_eq!(method, Method::POST);
                            let register: TailscaleRegisterRequest =
                                serde_json::from_slice(&body).unwrap();
                            assert_eq!(register.version, 138);
                            serde_json::to_vec(&TailscaleRegisterResponse {
                                machine_authorized: true,
                                ..Default::default()
                            })
                            .unwrap()
                        }
                        TAILSCALE_TKA_BOOTSTRAP_PATH => {
                            assert_eq!(method, Method::GET);
                            let bootstrap: TailscaleTkaBootstrapRequest =
                                serde_json::from_slice(&body).unwrap();
                            assert_eq!(bootstrap.head, "LOCAL");
                            serde_json::to_vec(&TailscaleTkaBootstrapResponse {
                                genesis_aum: vec![1, 2, 3],
                                disablement_secret: Vec::new(),
                            })
                            .unwrap()
                        }
                        TAILSCALE_SET_DNS_PATH => {
                            assert_eq!(method, Method::POST);
                            let set_dns: TailscaleSetDnsRequest =
                                serde_json::from_slice(&body).unwrap();
                            assert_eq!(set_dns.version, 142);
                            assert_eq!(
                                set_dns.node_key,
                                TailscaleNodePublicKey::from_bytes([85; 32])
                            );
                            assert_eq!(
                                set_dns.name,
                                "_acme-challenge.node.tail.ts.net"
                            );
                            assert_eq!(set_dns.record_type, "TXT");
                            assert_eq!(set_dns.value, "dns-value");
                            serde_json::to_vec(&TailscaleSetDnsResponse {})
                                .unwrap()
                        }
                        path => panic!("unexpected control RPC {path}"),
                    };
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                        Bytes::from(body),
                    )))
                },
            );
            let _ =
                hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
        });

        let stream = connect_tailscale_control(
            client_stream,
            "control.example",
            [82; 32],
            control_public,
            1,
        )
        .await
        .unwrap();
        let (_, mut client) =
            start_tailscale_control_http2(stream).await.unwrap();
        let response = client
            .register(
                "control.example",
                &TailscaleRegisterRequest {
                    version: 138,
                    node_key: TailscaleNodePublicKey::from_bytes([83; 32]),
                    ..Default::default()
                },
                &["nodekey:first", "nodekey:second"],
            )
            .await
            .unwrap();
        assert!(response.machine_authorized);
        let response = client
            .tka_bootstrap(
                "control.example",
                &TailscaleTkaBootstrapRequest {
                    version: 142,
                    node_key: TailscaleNodePublicKey::from_bytes([84; 32]),
                    head: "LOCAL".into(),
                },
                &["nodekey:first", "nodekey:second"],
            )
            .await
            .unwrap();
        assert_eq!(response.genesis_aum, vec![1, 2, 3]);
        client
            .set_dns(
                "control.example",
                &TailscaleSetDnsRequest {
                    version: 142,
                    node_key: TailscaleNodePublicKey::from_bytes([85; 32]),
                    name: "_acme-challenge.node.tail.ts.net".into(),
                    record_type: "TXT".into(),
                    value: "dns-value".into(),
                },
                &["nodekey:first", "nodekey:second"],
            )
            .await
            .unwrap();
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}
