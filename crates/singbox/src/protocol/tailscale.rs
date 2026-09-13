//! Tailscale DERP wire primitives.
//!
//! DERP carries encrypted WireGuard and disco packets when peers cannot use a
//! direct UDP path. The codec is deliberately independent from an endpoint so
//! the embedding runtime can route its HTTP/TLS connection through any dialer.

use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead as _, generic_array::GenericArray},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    sync::mpsc,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{Dialer, Stream},
    common::network::SocksAddr,
};

pub const TAILSCALE_DERP_MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";
pub const TAILSCALE_DERP_PROTOCOL_VERSION: u8 = 2;
pub const TAILSCALE_DERP_KEY_LENGTH: usize = 32;
pub const TAILSCALE_DERP_NONCE_LENGTH: usize = 24;
pub const TAILSCALE_DERP_FRAME_HEADER_LENGTH: usize = 5;
pub const TAILSCALE_DERP_MAX_PACKET_SIZE: usize = 64 << 10;
pub const TAILSCALE_DERP_MAX_INFO_LENGTH: usize = 1 << 20;
pub const TAILSCALE_DERP_MAX_CLIENT_INFO_LENGTH: usize = 256 << 10;
pub const TAILSCALE_DERP_MAX_HTTP_HEADER_LENGTH: usize = 64 << 10;
pub const TAILSCALE_DERP_WRITE_QUEUE_DEPTH: usize = 32;
pub const TAILSCALE_DERP_RECEIVE_QUEUE_DEPTH: usize = 1;
pub const TAILSCALE_DERP_FAST_START_HEADER: &str = "Derp-Fast-Start";
pub const TAILSCALE_DERP_IDEAL_NODE_HEADER: &str = "Ideal-Node";

pub const TAILSCALE_DERP_FRAME_SERVER_KEY: u8 = 0x01;
pub const TAILSCALE_DERP_FRAME_CLIENT_INFO: u8 = 0x02;
pub const TAILSCALE_DERP_FRAME_SERVER_INFO: u8 = 0x03;
pub const TAILSCALE_DERP_FRAME_SEND_PACKET: u8 = 0x04;
pub const TAILSCALE_DERP_FRAME_RECV_PACKET: u8 = 0x05;
pub const TAILSCALE_DERP_FRAME_KEEP_ALIVE: u8 = 0x06;
pub const TAILSCALE_DERP_FRAME_NOTE_PREFERRED: u8 = 0x07;
pub const TAILSCALE_DERP_FRAME_PEER_GONE: u8 = 0x08;
pub const TAILSCALE_DERP_FRAME_PEER_PRESENT: u8 = 0x09;
pub const TAILSCALE_DERP_FRAME_FORWARD_PACKET: u8 = 0x0a;
pub const TAILSCALE_DERP_FRAME_WATCH_CONNECTIONS: u8 = 0x10;
pub const TAILSCALE_DERP_FRAME_CLOSE_PEER: u8 = 0x11;
pub const TAILSCALE_DERP_FRAME_PING: u8 = 0x12;
pub const TAILSCALE_DERP_FRAME_PONG: u8 = 0x13;
pub const TAILSCALE_DERP_FRAME_HEALTH: u8 = 0x14;
pub const TAILSCALE_DERP_FRAME_RESTARTING: u8 = 0x15;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDerpFrame {
    pub frame_type: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDerpPacket {
    pub peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
    pub packet: Vec<u8>,
}

/// Typed messages produced by a connected DERP v2 client.
///
/// Unknown frame types and the historically tolerated short peer/ping frames
/// are skipped by [`TailscaleDerpClient::receive_message`]. Health payloads
/// remain bytes because Go strings can preserve invalid UTF-8 on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleDerpReceivedMessage {
    ServerInfo(TailscaleDerpServerInfo),
    Packet(TailscaleDerpPacket),
    KeepAlive,
    PeerGone {
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
        reason: u8,
    },
    PeerPresent {
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
        ip_port: Option<SocketAddr>,
        flags: u8,
    },
    Ping([u8; 8]),
    Pong([u8; 8]),
    Health(Vec<u8>),
    ServerRestarting {
        reconnect_in: Duration,
        try_for: Duration,
    },
}

/// Running I/O owner for one authenticated DERP connection.
///
/// The stream is split only after authentication. One task then serializes all
/// writes, reads typed events, and answers server pings without requiring the
/// embedding application to coordinate concurrent mutable access.
pub struct TailscaleDerpSession {
    writes: mpsc::Sender<Vec<u8>>,
    events: mpsc::Receiver<
        Result<TailscaleDerpReceivedMessage, TailscaleDerpError>,
    >,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl TailscaleDerpSession {
    pub fn try_send_packet(
        &self,
        destination: [u8; TAILSCALE_DERP_KEY_LENGTH],
        packet: &[u8],
    ) -> Result<(), TailscaleDerpError> {
        self.try_send_frame(encode_tailscale_derp_send_packet(
            destination,
            packet,
        )?)
    }

    pub fn try_send_ping(
        &self,
        payload: [u8; 8],
    ) -> Result<(), TailscaleDerpError> {
        self.try_send_frame(encode_tailscale_derp_frame(
            TAILSCALE_DERP_FRAME_PING,
            &payload,
            8,
        )?)
    }

    pub fn try_note_preferred(
        &self,
        preferred: bool,
    ) -> Result<(), TailscaleDerpError> {
        self.try_send_frame(encode_tailscale_derp_frame(
            TAILSCALE_DERP_FRAME_NOTE_PREFERRED,
            &[u8::from(preferred)],
            1,
        )?)
    }

    pub async fn next_event(
        &mut self,
    ) -> Option<Result<TailscaleDerpReceivedMessage, TailscaleDerpError>> {
        self.events.recv().await
    }

    pub fn is_closed(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub async fn close(mut self) -> Result<(), TailscaleDerpError> {
        self.cancellation.cancel();
        self.task
            .take()
            .expect("DERP session task is present")
            .await
            .map_err(|error| {
                TailscaleDerpError::Io(io::Error::other(format!(
                    "DERP session task failed: {error}"
                )))
            })
    }

    fn try_send_frame(&self, frame: Vec<u8>) -> Result<(), TailscaleDerpError> {
        self.writes.try_send(frame).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                TailscaleDerpError::WriteQueueFull
            }
            mpsc::error::TrySendError::Closed(_) => {
                TailscaleDerpError::SessionClosed
            }
        })
    }
}

impl Drop for TailscaleDerpSession {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDerpConnectOptions {
    pub authority: String,
    pub path: String,
    pub ideal_node: Option<String>,
    /// TLS 1.3 meta-certificate discovery can supply this key and enable
    /// DERP fast-start. `None` performs the ordinary HTTP 101 exchange.
    pub known_server_public_key: Option<[u8; TAILSCALE_DERP_KEY_LENGTH]>,
    pub client_info: TailscaleDerpClientInfo,
}

impl TailscaleDerpConnectOptions {
    pub fn new(authority: impl Into<String>) -> Self {
        Self {
            authority: authority.into(),
            path: "/derp".into(),
            ideal_node: None,
            known_server_public_key: None,
            client_info: TailscaleDerpClientInfo::default(),
        }
    }
}

/// Connected DERP protocol session over a caller-provided transport.
///
/// Supplying the transport keeps the library usable over direct TCP, rustls,
/// an outbound detour, or a test stream without coupling DERP to a CLI.
pub struct TailscaleDerpClient<S> {
    stream: S,
    private_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    public_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    server_public_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
}

impl<S> TailscaleDerpClient<S> {
    pub fn public_key(&self) -> [u8; TAILSCALE_DERP_KEY_LENGTH] {
        self.public_key
    }

    pub fn server_public_key(&self) -> [u8; TAILSCALE_DERP_KEY_LENGTH] {
        self.server_public_key
    }

    pub fn stream(&self) -> &S {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn into_stream(self) -> S {
        self.stream
    }
}

impl<S> TailscaleDerpClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn connect(
        mut stream: S,
        private_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
        options: TailscaleDerpConnectOptions,
    ) -> Result<Self, TailscaleDerpError> {
        validate_http_component("authority", &options.authority)?;
        validate_http_component("path", &options.path)?;
        if !options.path.starts_with('/') {
            return Err(TailscaleDerpError::InvalidHttpRequest(
                "DERP path must start with '/'".into(),
            ));
        }
        if let Some(ideal_node) = options.ideal_node.as_deref() {
            validate_http_component("ideal node", ideal_node)?;
        }
        let public_key = tailscale_node_public_key(private_key)?;
        let fast_start = options.known_server_public_key.is_some();
        let request =
            build_tailscale_derp_http_upgrade_request(&options, fast_start)?;
        stream.write_all(request.as_bytes()).await?;
        if !fast_start {
            stream.flush().await?;
        }

        let server_public_key = if let Some(server_public_key) =
            options.known_server_public_key
        {
            validate_tailscale_node_key(&server_public_key)?;
            server_public_key
        } else {
            read_tailscale_derp_http_upgrade_response(&mut stream).await?;
            let frame = read_tailscale_derp_frame(&mut stream, 1 << 10).await?;
            parse_tailscale_derp_server_key(&frame)?
        };

        let mut nonce = [0_u8; TAILSCALE_DERP_NONCE_LENGTH];
        getrandom::fill(&mut nonce)
            .map_err(|error| TailscaleDerpError::Random(error.to_string()))?;
        let client_info = encode_tailscale_derp_client_info(
            private_key,
            server_public_key,
            nonce,
            &options.client_info,
        )?;
        stream.write_all(&client_info).await?;
        stream.flush().await?;
        Ok(Self {
            stream,
            private_key,
            public_key,
            server_public_key,
        })
    }

    pub async fn send_packet(
        &mut self,
        destination: [u8; TAILSCALE_DERP_KEY_LENGTH],
        packet: &[u8],
    ) -> Result<(), TailscaleDerpError> {
        self.stream
            .write_all(&encode_tailscale_derp_send_packet(destination, packet)?)
            .await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn send_ping(
        &mut self,
        data: [u8; 8],
    ) -> Result<(), TailscaleDerpError> {
        write_tailscale_derp_frame(
            &mut self.stream,
            TAILSCALE_DERP_FRAME_PING,
            &data,
            8,
        )
        .await
    }

    pub async fn send_pong(
        &mut self,
        data: [u8; 8],
    ) -> Result<(), TailscaleDerpError> {
        write_tailscale_derp_frame(
            &mut self.stream,
            TAILSCALE_DERP_FRAME_PONG,
            &data,
            8,
        )
        .await
    }

    pub async fn note_preferred(
        &mut self,
        preferred: bool,
    ) -> Result<(), TailscaleDerpError> {
        write_tailscale_derp_frame(
            &mut self.stream,
            TAILSCALE_DERP_FRAME_NOTE_PREFERRED,
            &[u8::from(preferred)],
            1,
        )
        .await
    }

    pub async fn watch_connections(
        &mut self,
    ) -> Result<(), TailscaleDerpError> {
        write_tailscale_derp_frame(
            &mut self.stream,
            TAILSCALE_DERP_FRAME_WATCH_CONNECTIONS,
            &[],
            0,
        )
        .await
    }

    pub async fn receive_frame(
        &mut self,
    ) -> Result<TailscaleDerpFrame, TailscaleDerpError> {
        read_tailscale_derp_frame(
            &mut self.stream,
            TAILSCALE_DERP_MAX_INFO_LENGTH,
        )
        .await
    }

    /// Receive the next application-visible DERP message.
    ///
    /// This mirrors `derp.Client.Recv`: future frame types and malformed short
    /// peer/ping notifications are ignored, while an invalid authenticated
    /// server-info frame remains fatal for the connection.
    pub async fn receive_message(
        &mut self,
    ) -> Result<TailscaleDerpReceivedMessage, TailscaleDerpError> {
        loop {
            let frame = self.receive_frame().await?;
            if let Some(message) = parse_tailscale_derp_received_message(
                self.private_key,
                self.server_public_key,
                frame,
            )? {
                return Ok(message);
            }
        }
    }

    pub fn parse_server_info(
        &self,
        frame: &TailscaleDerpFrame,
    ) -> Result<TailscaleDerpServerInfo, TailscaleDerpError> {
        parse_tailscale_derp_server_info(
            self.private_key,
            self.server_public_key,
            frame,
        )
    }
}

impl<S> TailscaleDerpClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Move this authenticated client into its bounded single-connection I/O
    /// supervisor. Regional reconnect and path selection intentionally live
    /// above this layer.
    pub fn into_session(self) -> TailscaleDerpSession {
        let Self {
            stream,
            private_key,
            server_public_key,
            ..
        } = self;
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (write_tx, mut write_rx) =
            mpsc::channel::<Vec<u8>>(TAILSCALE_DERP_WRITE_QUEUE_DEPTH);
        let (event_tx, event_rx) = mpsc::channel::<
            Result<TailscaleDerpReceivedMessage, TailscaleDerpError>,
        >(TAILSCALE_DERP_RECEIVE_QUEUE_DEPTH);
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = task_cancellation.cancelled() => break,
                    frame = read_tailscale_derp_frame(
                        &mut reader,
                        TAILSCALE_DERP_MAX_INFO_LENGTH,
                    ) => {
                        let frame = match frame {
                            Ok(frame) => frame,
                            Err(error) => {
                                let _ = event_tx.try_send(Err(error));
                                break;
                            }
                        };
                        let message = match parse_tailscale_derp_received_message(
                            private_key,
                            server_public_key,
                            frame,
                        ) {
                            Ok(Some(message)) => message,
                            Ok(None) => continue,
                            Err(error) => {
                                let _ = event_tx.try_send(Err(error));
                                break;
                            }
                        };
                        if let TailscaleDerpReceivedMessage::Ping(payload) = message {
                            let reply = write_tailscale_derp_frame(
                                    &mut writer,
                                    TAILSCALE_DERP_FRAME_PONG,
                                    &payload,
                                    8,
                                );
                            tokio::select! {
                                biased;
                                _ = task_cancellation.cancelled() => break,
                                result = reply => if let Err(error) = result {
                                    let _ = event_tx.try_send(Err(error));
                                    break;
                                },
                            }
                            continue;
                        }
                        tokio::select! {
                            biased;
                            _ = task_cancellation.cancelled() => break,
                            result = event_tx.send(Ok(message)) => if result.is_err() {
                                break;
                            },
                        }
                    }
                    frame = write_rx.recv() => {
                        let Some(frame) = frame else {
                            break;
                        };
                        let write = async {
                            writer.write_all(&frame).await?;
                            writer.flush().await
                        };
                        tokio::select! {
                            biased;
                            _ = task_cancellation.cancelled() => break,
                            result = write => if let Err(error) = result {
                                let _ = event_tx.try_send(Err(
                                    TailscaleDerpError::Io(error),
                                ));
                                break;
                            },
                        }
                    }
                }
            }
        });
        TailscaleDerpSession {
            writes: write_tx,
            events: event_rx,
            cancellation,
            task: Some(task),
        }
    }
}

/// Dial and authenticate a DERP session through any singbox dialer.
///
/// Wrap `dialer` in [`crate::common::tls::ClientTlsDialer`] for HTTPS DERP;
/// leave it unwrapped for the upstream-supported HTTP form.
pub async fn dial_tailscale_derp<D>(
    dialer: &D,
    destination: &SocksAddr,
    private_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    options: TailscaleDerpConnectOptions,
) -> Result<TailscaleDerpClient<Stream>, TailscaleDerpError>
where
    D: Dialer + ?Sized,
{
    let stream = dialer.dial_tcp(destination).await?;
    TailscaleDerpClient::connect(stream, private_key, options).await
}

/// Information sent by a DERP client immediately after the server greeting.
///
/// The unusual field casing is part of DERP's Go JSON wire contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleDerpClientInfo {
    #[serde(rename = "meshKey", skip_serializing_if = "Option::is_none")]
    pub mesh_key: Option<String>,
    #[serde(default = "tailscale_derp_protocol_version")]
    pub version: i64,
    #[serde(rename = "CanAckPings", default)]
    pub can_ack_pings: bool,
    #[serde(
        rename = "IsProber",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub is_prober: bool,
}

impl Default for TailscaleDerpClientInfo {
    fn default() -> Self {
        Self {
            mesh_key: None,
            version: i64::from(TAILSCALE_DERP_PROTOCOL_VERSION),
            can_ack_pings: false,
            is_prober: false,
        }
    }
}

/// Rate-limit metadata delivered in DERP's encrypted server-info frame.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleDerpServerInfo {
    #[serde(default)]
    pub version: i64,
    #[serde(rename = "TokenBucketBytesPerSecond", default)]
    pub token_bucket_bytes_per_second: i64,
    #[serde(rename = "TokenBucketBytesBurst", default)]
    pub token_bucket_bytes_burst: i64,
}

const fn tailscale_derp_protocol_version() -> i64 {
    TAILSCALE_DERP_PROTOCOL_VERSION as i64
}

#[derive(Debug, Error)]
pub enum TailscaleDerpError {
    #[error("DERP frame payload exceeds {maximum} bytes: {actual}")]
    FrameTooLarge { actual: usize, maximum: usize },
    #[error("DERP packet exceeds {TAILSCALE_DERP_MAX_PACKET_SIZE} bytes")]
    PacketTooLarge,
    #[error("DERP frame {frame_type:#04x} is shorter than {minimum} bytes")]
    FrameTooShort { frame_type: u8, minimum: usize },
    #[error("DERP server-key frame has invalid magic")]
    InvalidServerMagic,
    #[error("DERP node key must not be all zero")]
    ZeroNodeKey,
    #[error("DERP NaCl box is shorter than its 24-byte nonce")]
    BoxTooShort,
    #[error("DERP NaCl box authentication failed")]
    BoxAuthentication,
    #[error("invalid DERP mesh key: expected exactly 64 hexadecimal digits")]
    InvalidMeshKey,
    #[error("invalid DERP HTTP request: {0}")]
    InvalidHttpRequest(String),
    #[error("DERP HTTP response header exceeds 64 KiB")]
    HttpHeaderTooLarge,
    #[error("invalid DERP HTTP response: {0}")]
    InvalidHttpResponse(String),
    #[error("DERP HTTP upgrade failed with status {status}: {reason}")]
    HttpUpgrade { status: u16, reason: String },
    #[error("operating-system randomness failed: {0}")]
    Random(String),
    #[error("DERP write queue is full")]
    WriteQueueFull,
    #[error("DERP session is closed")]
    SessionClosed,
    #[error("unknown DERP region {0}")]
    UnknownRegion(u32),
    #[error("invalid DERP information JSON: {0}")]
    InvalidInfoJson(#[from] serde_json::Error),
    #[error(
        "unexpected DERP frame type {actual:#04x}; expected {expected:#04x}"
    )]
    UnexpectedFrameType { actual: u8, expected: u8 },
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn build_tailscale_derp_http_upgrade_request(
    options: &TailscaleDerpConnectOptions,
    fast_start: bool,
) -> Result<String, TailscaleDerpError> {
    validate_http_component("authority", &options.authority)?;
    validate_http_component("path", &options.path)?;
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n",
        options.path, options.authority
    );
    if let Some(ideal_node) = options.ideal_node.as_deref() {
        validate_http_component("ideal node", ideal_node)?;
        request.push_str(TAILSCALE_DERP_IDEAL_NODE_HEADER);
        request.push_str(": ");
        request.push_str(ideal_node);
        request.push_str("\r\n");
    }
    if fast_start {
        request.push_str(TAILSCALE_DERP_FAST_START_HEADER);
        request.push_str(": 1\r\n");
    }
    request.push_str("\r\n");
    Ok(request)
}

pub async fn read_tailscale_derp_http_upgrade_response<S>(
    stream: &mut S,
) -> Result<(), TailscaleDerpError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let bytes = read_tailscale_derp_http_header(stream).await?;
    let header = std::str::from_utf8(&bytes).map_err(|_| {
        TailscaleDerpError::InvalidHttpResponse(
            "response header is not valid UTF-8/ASCII".into(),
        )
    })?;
    let status_line = header.lines().next().ok_or_else(|| {
        TailscaleDerpError::InvalidHttpResponse("empty response".into())
    })?;
    let mut fields = status_line.splitn(3, ' ');
    let version = fields.next().unwrap_or_default();
    let status = fields
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            TailscaleDerpError::InvalidHttpResponse(
                "malformed status line".into(),
            )
        })?;
    let reason = fields.next().unwrap_or_default().trim().to_owned();
    if !version.starts_with("HTTP/1.") {
        return Err(TailscaleDerpError::InvalidHttpResponse(
            "upgrade response is not HTTP/1.x".into(),
        ));
    }
    if status != 101 {
        return Err(TailscaleDerpError::HttpUpgrade { status, reason });
    }
    Ok(())
}

async fn read_tailscale_derp_http_header<S>(
    stream: &mut S,
) -> Result<Vec<u8>, TailscaleDerpError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut header = Vec::with_capacity(512);
    loop {
        if header.len() == TAILSCALE_DERP_MAX_HTTP_HEADER_LENGTH {
            return Err(TailscaleDerpError::HttpHeaderTooLarge);
        }
        let byte = stream.read_u8().await?;
        header.push(byte);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
}

fn validate_http_component(
    label: &str,
    value: &str,
) -> Result<(), TailscaleDerpError> {
    if value.is_empty()
        || value.bytes().any(|byte| byte == b'\r' || byte == b'\n')
    {
        return Err(TailscaleDerpError::InvalidHttpRequest(format!(
            "{label} is empty or contains a line break"
        )));
    }
    Ok(())
}

pub fn tailscale_node_public_key(
    private_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
) -> Result<[u8; TAILSCALE_DERP_KEY_LENGTH], TailscaleDerpError> {
    validate_tailscale_node_key(&private_key)?;
    Ok(*SecretKey::from(private_key).public_key().as_bytes())
}

/// Encrypt a DERP information message using the exact `key.NodePrivate.SealTo`
/// layout: nonce first, followed by a NaCl authenticated box.
pub fn seal_tailscale_derp_box(
    private_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    peer_public_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    nonce: [u8; TAILSCALE_DERP_NONCE_LENGTH],
    plaintext: &[u8],
) -> Result<Vec<u8>, TailscaleDerpError> {
    validate_tailscale_node_key(&private_key)?;
    validate_tailscale_node_key(&peer_public_key)?;
    let secret = SecretKey::from(private_key);
    let peer = PublicKey::from(peer_public_key);
    let cipher = SalsaBox::new(&peer, &secret);
    let encrypted = cipher
        .encrypt(GenericArray::from_slice(&nonce), plaintext)
        .map_err(|_| TailscaleDerpError::BoxAuthentication)?;
    let mut sealed = Vec::with_capacity(nonce.len() + encrypted.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&encrypted);
    Ok(sealed)
}

pub fn open_tailscale_derp_box(
    private_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    peer_public_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    sealed: &[u8],
) -> Result<Vec<u8>, TailscaleDerpError> {
    validate_tailscale_node_key(&private_key)?;
    validate_tailscale_node_key(&peer_public_key)?;
    if sealed.len() < TAILSCALE_DERP_NONCE_LENGTH {
        return Err(TailscaleDerpError::BoxTooShort);
    }
    let secret = SecretKey::from(private_key);
    let peer = PublicKey::from(peer_public_key);
    SalsaBox::new(&peer, &secret)
        .decrypt(
            GenericArray::from_slice(&sealed[..TAILSCALE_DERP_NONCE_LENGTH]),
            &sealed[TAILSCALE_DERP_NONCE_LENGTH..],
        )
        .map_err(|_| TailscaleDerpError::BoxAuthentication)
}

pub fn encode_tailscale_derp_client_info(
    private_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    server_public_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    nonce: [u8; TAILSCALE_DERP_NONCE_LENGTH],
    info: &TailscaleDerpClientInfo,
) -> Result<Vec<u8>, TailscaleDerpError> {
    validate_tailscale_mesh_key(info.mesh_key.as_deref())?;
    let json = serde_json::to_vec(info)?;
    let sealed =
        seal_tailscale_derp_box(private_key, server_public_key, nonce, &json)?;
    let mut payload =
        Vec::with_capacity(TAILSCALE_DERP_KEY_LENGTH + sealed.len());
    payload.extend_from_slice(&tailscale_node_public_key(private_key)?);
    payload.extend_from_slice(&sealed);
    encode_tailscale_derp_frame(
        TAILSCALE_DERP_FRAME_CLIENT_INFO,
        &payload,
        TAILSCALE_DERP_MAX_CLIENT_INFO_LENGTH,
    )
}

pub fn parse_tailscale_derp_server_info(
    private_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    server_public_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    frame: &TailscaleDerpFrame,
) -> Result<TailscaleDerpServerInfo, TailscaleDerpError> {
    if frame.frame_type != TAILSCALE_DERP_FRAME_SERVER_INFO {
        return Err(TailscaleDerpError::UnexpectedFrameType {
            actual: frame.frame_type,
            expected: TAILSCALE_DERP_FRAME_SERVER_INFO,
        });
    }
    if frame.payload.len() < TAILSCALE_DERP_NONCE_LENGTH {
        return Err(TailscaleDerpError::FrameTooShort {
            frame_type: frame.frame_type,
            minimum: TAILSCALE_DERP_NONCE_LENGTH,
        });
    }
    let maximum = TAILSCALE_DERP_NONCE_LENGTH + TAILSCALE_DERP_MAX_INFO_LENGTH;
    if frame.payload.len() > maximum {
        return Err(TailscaleDerpError::FrameTooLarge {
            actual: frame.payload.len(),
            maximum,
        });
    }
    let json = open_tailscale_derp_box(
        private_key,
        server_public_key,
        &frame.payload,
    )?;
    Ok(serde_json::from_slice(&json)?)
}

fn validate_tailscale_node_key(
    key: &[u8; TAILSCALE_DERP_KEY_LENGTH],
) -> Result<(), TailscaleDerpError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(TailscaleDerpError::ZeroNodeKey);
    }
    Ok(())
}

fn validate_tailscale_mesh_key(
    key: Option<&str>,
) -> Result<(), TailscaleDerpError> {
    if let Some(key) = key
        && (key.len() != 64
            || !key.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(TailscaleDerpError::InvalidMeshKey);
    }
    Ok(())
}

pub fn encode_tailscale_derp_frame(
    frame_type: u8,
    payload: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, TailscaleDerpError> {
    if payload.len() > maximum || payload.len() > u32::MAX as usize {
        return Err(TailscaleDerpError::FrameTooLarge {
            actual: payload.len(),
            maximum: maximum.min(u32::MAX as usize),
        });
    }
    let mut frame =
        Vec::with_capacity(TAILSCALE_DERP_FRAME_HEADER_LENGTH + payload.len());
    frame.push(frame_type);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub async fn read_tailscale_derp_frame<R>(
    reader: &mut R,
    maximum: usize,
) -> Result<TailscaleDerpFrame, TailscaleDerpError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; TAILSCALE_DERP_FRAME_HEADER_LENGTH];
    reader.read_exact(&mut header).await?;
    let length =
        u32::from_be_bytes(header[1..].try_into().expect("four-byte length"))
            as usize;
    if length > maximum {
        return Err(TailscaleDerpError::FrameTooLarge {
            actual: length,
            maximum,
        });
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(TailscaleDerpFrame {
        frame_type: header[0],
        payload,
    })
}

pub async fn write_tailscale_derp_frame<W>(
    writer: &mut W,
    frame_type: u8,
    payload: &[u8],
    maximum: usize,
) -> Result<(), TailscaleDerpError>
where
    W: AsyncWrite + Unpin,
{
    let frame = encode_tailscale_derp_frame(frame_type, payload, maximum)?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

pub fn parse_tailscale_derp_server_key(
    frame: &TailscaleDerpFrame,
) -> Result<[u8; TAILSCALE_DERP_KEY_LENGTH], TailscaleDerpError> {
    if frame.frame_type != TAILSCALE_DERP_FRAME_SERVER_KEY {
        return Err(TailscaleDerpError::UnexpectedFrameType {
            actual: frame.frame_type,
            expected: TAILSCALE_DERP_FRAME_SERVER_KEY,
        });
    }
    let minimum = TAILSCALE_DERP_MAGIC.len() + TAILSCALE_DERP_KEY_LENGTH;
    if frame.payload.len() < minimum {
        return Err(TailscaleDerpError::FrameTooShort {
            frame_type: frame.frame_type,
            minimum,
        });
    }
    if &frame.payload[..TAILSCALE_DERP_MAGIC.len()] != TAILSCALE_DERP_MAGIC {
        return Err(TailscaleDerpError::InvalidServerMagic);
    }
    Ok(frame.payload[TAILSCALE_DERP_MAGIC.len()..minimum]
        .try_into()
        .expect("checked key length"))
}

pub fn encode_tailscale_derp_send_packet(
    destination: [u8; TAILSCALE_DERP_KEY_LENGTH],
    packet: &[u8],
) -> Result<Vec<u8>, TailscaleDerpError> {
    if packet.len() > TAILSCALE_DERP_MAX_PACKET_SIZE {
        return Err(TailscaleDerpError::PacketTooLarge);
    }
    let mut payload =
        Vec::with_capacity(TAILSCALE_DERP_KEY_LENGTH + packet.len());
    payload.extend_from_slice(&destination);
    payload.extend_from_slice(packet);
    encode_tailscale_derp_frame(
        TAILSCALE_DERP_FRAME_SEND_PACKET,
        &payload,
        TAILSCALE_DERP_KEY_LENGTH + TAILSCALE_DERP_MAX_PACKET_SIZE,
    )
}

pub fn parse_tailscale_derp_received_packet(
    frame: TailscaleDerpFrame,
) -> Result<TailscaleDerpPacket, TailscaleDerpError> {
    if frame.frame_type != TAILSCALE_DERP_FRAME_RECV_PACKET {
        return Err(TailscaleDerpError::UnexpectedFrameType {
            actual: frame.frame_type,
            expected: TAILSCALE_DERP_FRAME_RECV_PACKET,
        });
    }
    if frame.payload.len() < TAILSCALE_DERP_KEY_LENGTH {
        return Err(TailscaleDerpError::FrameTooShort {
            frame_type: frame.frame_type,
            minimum: TAILSCALE_DERP_KEY_LENGTH,
        });
    }
    let peer = frame.payload[..TAILSCALE_DERP_KEY_LENGTH]
        .try_into()
        .expect("checked key length");
    let packet = frame.payload[TAILSCALE_DERP_KEY_LENGTH..].to_vec();
    if packet.len() > TAILSCALE_DERP_MAX_PACKET_SIZE {
        return Err(TailscaleDerpError::PacketTooLarge);
    }
    Ok(TailscaleDerpPacket { peer, packet })
}

/// Parse one server-to-client DERP frame using the same compatibility rules as
/// the pinned Go client. `Ok(None)` means the frame is intentionally ignored.
pub fn parse_tailscale_derp_received_message(
    private_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    server_public_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    frame: TailscaleDerpFrame,
) -> Result<Option<TailscaleDerpReceivedMessage>, TailscaleDerpError> {
    let message = match frame.frame_type {
        TAILSCALE_DERP_FRAME_SERVER_INFO => {
            TailscaleDerpReceivedMessage::ServerInfo(
                parse_tailscale_derp_server_info(
                    private_key,
                    server_public_key,
                    &frame,
                )?,
            )
        }
        TAILSCALE_DERP_FRAME_RECV_PACKET => {
            if frame.payload.len() < TAILSCALE_DERP_KEY_LENGTH {
                return Ok(None);
            }
            TailscaleDerpReceivedMessage::Packet(
                parse_tailscale_derp_received_packet(frame)?,
            )
        }
        TAILSCALE_DERP_FRAME_KEEP_ALIVE => {
            TailscaleDerpReceivedMessage::KeepAlive
        }
        TAILSCALE_DERP_FRAME_PEER_GONE => {
            if frame.payload.len() < TAILSCALE_DERP_KEY_LENGTH {
                return Ok(None);
            }
            let peer = frame.payload[..TAILSCALE_DERP_KEY_LENGTH]
                .try_into()
                .expect("checked peer key length");
            let reason = frame
                .payload
                .get(TAILSCALE_DERP_KEY_LENGTH)
                .copied()
                .unwrap_or(0);
            TailscaleDerpReceivedMessage::PeerGone { peer, reason }
        }
        TAILSCALE_DERP_FRAME_PEER_PRESENT => {
            if frame.payload.len() < TAILSCALE_DERP_KEY_LENGTH {
                return Ok(None);
            }
            let peer = frame.payload[..TAILSCALE_DERP_KEY_LENGTH]
                .try_into()
                .expect("checked peer key length");
            let address_offset = TAILSCALE_DERP_KEY_LENGTH;
            let address_end = address_offset + 16;
            let port_end = address_end + 2;
            let ip_port = if frame.payload.len() >= port_end {
                let raw_address: [u8; 16] = frame.payload
                    [address_offset..address_end]
                    .try_into()
                    .expect("checked IP address length");
                let ipv6 = Ipv6Addr::from(raw_address);
                let address = ipv6
                    .to_ipv4_mapped()
                    .map(IpAddr::V4)
                    .unwrap_or(IpAddr::V6(ipv6));
                let port = u16::from_be_bytes(
                    frame.payload[address_end..port_end]
                        .try_into()
                        .expect("checked port length"),
                );
                Some(SocketAddr::new(address, port))
            } else {
                None
            };
            let flags = frame.payload.get(port_end).copied().unwrap_or(0);
            TailscaleDerpReceivedMessage::PeerPresent {
                peer,
                ip_port,
                flags,
            }
        }
        TAILSCALE_DERP_FRAME_PING | TAILSCALE_DERP_FRAME_PONG => {
            if frame.payload.len() < 8 {
                return Ok(None);
            }
            let payload = frame.payload[..8]
                .try_into()
                .expect("checked ping payload length");
            if frame.frame_type == TAILSCALE_DERP_FRAME_PING {
                TailscaleDerpReceivedMessage::Ping(payload)
            } else {
                TailscaleDerpReceivedMessage::Pong(payload)
            }
        }
        TAILSCALE_DERP_FRAME_HEALTH => {
            TailscaleDerpReceivedMessage::Health(frame.payload)
        }
        TAILSCALE_DERP_FRAME_RESTARTING => {
            if frame.payload.len() < 8 {
                return Ok(None);
            }
            let reconnect_in =
                Duration::from_millis(u64::from(u32::from_be_bytes(
                    frame.payload[..4]
                        .try_into()
                        .expect("checked duration length"),
                )));
            let try_for = Duration::from_millis(u64::from(u32::from_be_bytes(
                frame.payload[4..8]
                    .try_into()
                    .expect("checked duration length"),
            )));
            TailscaleDerpReceivedMessage::ServerRestarting {
                reconnect_in,
                try_for,
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_and_packet_layout_match_derp_v2() {
        assert_eq!(
            encode_tailscale_derp_frame(
                TAILSCALE_DERP_FRAME_PING,
                b"12345678",
                8,
            )
            .unwrap(),
            b"\x12\x00\x00\x00\x0812345678"
        );
        let destination = [7_u8; TAILSCALE_DERP_KEY_LENGTH];
        let frame =
            encode_tailscale_derp_send_packet(destination, b"packet").unwrap();
        assert_eq!(frame[0], TAILSCALE_DERP_FRAME_SEND_PACKET);
        assert_eq!(u32::from_be_bytes(frame[1..5].try_into().unwrap()), 38);
        assert_eq!(&frame[5..37], &destination);
        assert_eq!(&frame[37..], b"packet");
    }

    #[tokio::test]
    async fn async_codec_round_trips_and_rejects_before_allocation() {
        let mut wire = Vec::new();
        write_tailscale_derp_frame(
            &mut wire,
            TAILSCALE_DERP_FRAME_HEALTH,
            b"healthy",
            64,
        )
        .await
        .unwrap();
        let mut wire = std::io::Cursor::new(wire);
        assert_eq!(
            read_tailscale_derp_frame(&mut wire, 64).await.unwrap(),
            TailscaleDerpFrame {
                frame_type: TAILSCALE_DERP_FRAME_HEALTH,
                payload: b"healthy".to_vec(),
            }
        );

        let mut oversized = std::io::Cursor::new(vec![0x14, 0, 0, 1, 0]);
        assert!(matches!(
            read_tailscale_derp_frame(&mut oversized, 255).await,
            Err(TailscaleDerpError::FrameTooLarge { actual: 256, .. })
        ));
    }

    #[test]
    fn server_key_and_received_packet_are_strict() {
        let key = [9_u8; TAILSCALE_DERP_KEY_LENGTH];
        let mut payload = TAILSCALE_DERP_MAGIC.to_vec();
        payload.extend_from_slice(&key);
        payload.extend_from_slice(b"future");
        assert_eq!(
            parse_tailscale_derp_server_key(&TailscaleDerpFrame {
                frame_type: TAILSCALE_DERP_FRAME_SERVER_KEY,
                payload,
            })
            .unwrap(),
            key
        );

        let mut payload = key.to_vec();
        payload.extend_from_slice(b"wireguard");
        assert_eq!(
            parse_tailscale_derp_received_packet(TailscaleDerpFrame {
                frame_type: TAILSCALE_DERP_FRAME_RECV_PACKET,
                payload,
            })
            .unwrap(),
            TailscaleDerpPacket {
                peer: key,
                packet: b"wireguard".to_vec(),
            }
        );
    }

    #[test]
    fn nacl_box_matches_go_x_crypto_oracle() {
        let alice = std::array::from_fn(|index| (index + 1) as u8);
        let bob = std::array::from_fn(|index| (32 - index) as u8);
        let nonce = std::array::from_fn(|index| index as u8);
        let bob_public = tailscale_node_public_key(bob).unwrap();
        assert_eq!(
            hex::encode(tailscale_node_public_key(alice).unwrap()),
            "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
        );
        assert_eq!(
            hex::encode(bob_public),
            "0d799600f6ffaee2e121e6b8f7a05dc66874b51db3102d0d71f799a09cb4c461"
        );
        let sealed = seal_tailscale_derp_box(
            alice,
            bob_public,
            nonce,
            br#"{"version":2,"CanAckPings":true}"#,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&sealed),
            "000102030405060708090a0b0c0d0e0f1011121314151617d3630176c6e9524ca2fad3f701b156bdb265c4f5f0de2bccf160f3c53a0b081e4bc674d50fd4e07d5d8292b954f1f28d"
        );
        assert_eq!(
            open_tailscale_derp_box(
                bob,
                tailscale_node_public_key(alice).unwrap(),
                &sealed
            )
            .unwrap(),
            br#"{"version":2,"CanAckPings":true}"#
        );
    }

    #[test]
    fn encrypted_client_and_server_info_match_go_json_contract() {
        let client_private = [7_u8; TAILSCALE_DERP_KEY_LENGTH];
        let server_private = [9_u8; TAILSCALE_DERP_KEY_LENGTH];
        let server_public = tailscale_node_public_key(server_private).unwrap();
        let client_info = TailscaleDerpClientInfo {
            can_ack_pings: true,
            ..Default::default()
        };
        let encoded = encode_tailscale_derp_client_info(
            client_private,
            server_public,
            [3_u8; TAILSCALE_DERP_NONCE_LENGTH],
            &client_info,
        )
        .unwrap();
        assert_eq!(encoded[0], TAILSCALE_DERP_FRAME_CLIENT_INFO);
        let payload = &encoded[TAILSCALE_DERP_FRAME_HEADER_LENGTH..];
        let client_public: [u8; 32] = payload[..32].try_into().unwrap();
        assert_eq!(
            client_public,
            tailscale_node_public_key(client_private).unwrap()
        );
        assert_eq!(
            open_tailscale_derp_box(
                server_private,
                client_public,
                &payload[32..]
            )
            .unwrap(),
            br#"{"version":2,"CanAckPings":true}"#
        );

        let server_json =
            br#"{"version":2,"TokenBucketBytesPerSecond":-1,"TokenBucketBytesBurst":4096}"#;
        let server_payload = seal_tailscale_derp_box(
            server_private,
            client_public,
            [4_u8; TAILSCALE_DERP_NONCE_LENGTH],
            server_json,
        )
        .unwrap();
        let parsed = parse_tailscale_derp_server_info(
            client_private,
            server_public,
            &TailscaleDerpFrame {
                frame_type: TAILSCALE_DERP_FRAME_SERVER_INFO,
                payload: server_payload,
            },
        )
        .unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.token_bucket_bytes_per_second, -1);
        assert_eq!(parsed.token_bucket_bytes_burst, 4096);
    }

    #[test]
    fn encrypted_info_rejects_invalid_keys_mesh_and_authentication() {
        let info = TailscaleDerpClientInfo {
            mesh_key: Some("short".into()),
            ..Default::default()
        };
        assert!(matches!(
            encode_tailscale_derp_client_info(
                [1; 32],
                tailscale_node_public_key([2; 32]).unwrap(),
                [0; 24],
                &info,
            ),
            Err(TailscaleDerpError::InvalidMeshKey)
        ));
        assert!(matches!(
            tailscale_node_public_key([0; 32]),
            Err(TailscaleDerpError::ZeroNodeKey)
        ));
        assert!(matches!(
            open_tailscale_derp_box([1; 32], [2; 32], &[0; 24]),
            Err(TailscaleDerpError::BoxAuthentication)
        ));
    }

    #[tokio::test]
    async fn ordinary_http_upgrade_authenticates_like_go_client() {
        let client_private = [11_u8; 32];
        let server_private = [12_u8; 32];
        let server_public = tailscale_node_public_key(server_private).unwrap();
        let (client_stream, mut server_stream) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let request = read_tailscale_derp_http_header(&mut server_stream)
                .await
                .unwrap();
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /derp HTTP/1.1\r\n"));
            assert!(request.contains("Host: derp.example:443\r\n"));
            assert!(request.contains("Upgrade: DERP\r\n"));
            assert!(!request.contains(TAILSCALE_DERP_FAST_START_HEADER));
            server_stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n")
                .await
                .unwrap();
            let mut greeting = TAILSCALE_DERP_MAGIC.to_vec();
            greeting.extend_from_slice(&server_public);
            write_tailscale_derp_frame(
                &mut server_stream,
                TAILSCALE_DERP_FRAME_SERVER_KEY,
                &greeting,
                1024,
            )
            .await
            .unwrap();
            let client_info =
                read_tailscale_derp_frame(&mut server_stream, 256 << 10)
                    .await
                    .unwrap();
            assert_eq!(
                client_info.frame_type,
                TAILSCALE_DERP_FRAME_CLIENT_INFO
            );
            let client_public: [u8; 32] =
                client_info.payload[..32].try_into().unwrap();
            let json = open_tailscale_derp_box(
                server_private,
                client_public,
                &client_info.payload[32..],
            )
            .unwrap();
            assert_eq!(
                serde_json::from_slice::<TailscaleDerpClientInfo>(&json)
                    .unwrap(),
                TailscaleDerpClientInfo {
                    can_ack_pings: true,
                    ..Default::default()
                }
            );
        });

        let mut options = TailscaleDerpConnectOptions::new("derp.example:443");
        options.client_info.can_ack_pings = true;
        let client = TailscaleDerpClient::connect(
            client_stream,
            client_private,
            options,
        )
        .await
        .unwrap();
        assert_eq!(client.server_public_key(), server_public);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fast_start_sends_auth_without_waiting_for_http_response() {
        let client_private = [21_u8; 32];
        let server_private = [22_u8; 32];
        let server_public = tailscale_node_public_key(server_private).unwrap();
        let (client_stream, mut server_stream) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let request = String::from_utf8(
                read_tailscale_derp_http_header(&mut server_stream)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert!(request.contains("Derp-Fast-Start: 1\r\n"));
            assert!(request.contains("Ideal-Node: derp-1\r\n"));
            let client_info =
                read_tailscale_derp_frame(&mut server_stream, 256 << 10)
                    .await
                    .unwrap();
            let client_public: [u8; 32] =
                client_info.payload[..32].try_into().unwrap();
            open_tailscale_derp_box(
                server_private,
                client_public,
                &client_info.payload[32..],
            )
            .unwrap()
        });

        let mut options = TailscaleDerpConnectOptions::new("derp.example");
        options.ideal_node = Some("derp-1".into());
        options.known_server_public_key = Some(server_public);
        let client = TailscaleDerpClient::connect(
            client_stream,
            client_private,
            options,
        )
        .await
        .unwrap();
        assert_eq!(client.server_public_key(), server_public);
        assert_eq!(
            server.await.unwrap(),
            br#"{"version":2,"CanAckPings":false}"#
        );
    }

    #[tokio::test]
    async fn http_upgrade_rejects_non_101_and_injection() {
        let mut response = std::io::Cursor::new(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec(),
        );
        assert!(matches!(
            read_tailscale_derp_http_upgrade_response(&mut response).await,
            Err(TailscaleDerpError::HttpUpgrade { status: 403, .. })
        ));
        let options = TailscaleDerpConnectOptions::new("good\r\nInjected: yes");
        assert!(matches!(
            build_tailscale_derp_http_upgrade_request(&options, false),
            Err(TailscaleDerpError::InvalidHttpRequest(_))
        ));
    }

    #[test]
    fn typed_receive_parser_matches_peer_ping_and_restart_semantics() {
        let private_key = [31_u8; 32];
        let server_public_key = tailscale_node_public_key([32_u8; 32]).unwrap();
        let peer = [33_u8; 32];

        let gone = parse_tailscale_derp_received_message(
            private_key,
            server_public_key,
            TailscaleDerpFrame {
                frame_type: TAILSCALE_DERP_FRAME_PEER_GONE,
                payload: peer.to_vec(),
            },
        )
        .unwrap();
        assert_eq!(
            gone,
            Some(TailscaleDerpReceivedMessage::PeerGone { peer, reason: 0 })
        );

        let mut present_payload = peer.to_vec();
        present_payload.extend_from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 4,
        ]);
        present_payload.extend_from_slice(&41641_u16.to_be_bytes());
        present_payload.extend_from_slice(&[0b1001, 0xaa]);
        let present = parse_tailscale_derp_received_message(
            private_key,
            server_public_key,
            TailscaleDerpFrame {
                frame_type: TAILSCALE_DERP_FRAME_PEER_PRESENT,
                payload: present_payload,
            },
        )
        .unwrap();
        assert_eq!(
            present,
            Some(TailscaleDerpReceivedMessage::PeerPresent {
                peer,
                ip_port: Some("192.0.2.4:41641".parse().unwrap()),
                flags: 0b1001,
            })
        );

        for frame_type in [TAILSCALE_DERP_FRAME_PING, TAILSCALE_DERP_FRAME_PONG]
        {
            let message = parse_tailscale_derp_received_message(
                private_key,
                server_public_key,
                TailscaleDerpFrame {
                    frame_type,
                    payload: b"12345678future".to_vec(),
                },
            )
            .unwrap();
            let expected = if frame_type == TAILSCALE_DERP_FRAME_PING {
                TailscaleDerpReceivedMessage::Ping(*b"12345678")
            } else {
                TailscaleDerpReceivedMessage::Pong(*b"12345678")
            };
            assert_eq!(message, Some(expected));
        }

        let mut restarting = 250_u32.to_be_bytes().to_vec();
        restarting.extend_from_slice(&4_000_u32.to_be_bytes());
        restarting.push(0xff);
        assert_eq!(
            parse_tailscale_derp_received_message(
                private_key,
                server_public_key,
                TailscaleDerpFrame {
                    frame_type: TAILSCALE_DERP_FRAME_RESTARTING,
                    payload: restarting,
                },
            )
            .unwrap(),
            Some(TailscaleDerpReceivedMessage::ServerRestarting {
                reconnect_in: Duration::from_millis(250),
                try_for: Duration::from_secs(4),
            })
        );
    }

    #[test]
    fn typed_receive_parser_preserves_legacy_and_future_compatibility() {
        let private_key = [41_u8; 32];
        let server_public_key = tailscale_node_public_key([42_u8; 32]).unwrap();
        let peer = [43_u8; 32];
        assert_eq!(
            parse_tailscale_derp_received_message(
                private_key,
                server_public_key,
                TailscaleDerpFrame {
                    frame_type: TAILSCALE_DERP_FRAME_PEER_PRESENT,
                    payload: peer.to_vec(),
                },
            )
            .unwrap(),
            Some(TailscaleDerpReceivedMessage::PeerPresent {
                peer,
                ip_port: None,
                flags: 0,
            })
        );
        for (frame_type, payload) in [
            (TAILSCALE_DERP_FRAME_PEER_GONE, vec![0; 31]),
            (TAILSCALE_DERP_FRAME_PEER_PRESENT, vec![0; 31]),
            (TAILSCALE_DERP_FRAME_RECV_PACKET, vec![0; 31]),
            (TAILSCALE_DERP_FRAME_PING, vec![0; 7]),
            (TAILSCALE_DERP_FRAME_RESTARTING, vec![0; 7]),
            (0xff, vec![1, 2, 3]),
        ] {
            assert_eq!(
                parse_tailscale_derp_received_message(
                    private_key,
                    server_public_key,
                    TailscaleDerpFrame {
                        frame_type,
                        payload,
                    },
                )
                .unwrap(),
                None
            );
        }
        assert_eq!(
            parse_tailscale_derp_received_message(
                private_key,
                server_public_key,
                TailscaleDerpFrame {
                    frame_type: TAILSCALE_DERP_FRAME_HEALTH,
                    payload: vec![0xff, b'x'],
                },
            )
            .unwrap(),
            Some(TailscaleDerpReceivedMessage::Health(vec![0xff, b'x']))
        );
    }

    #[tokio::test]
    async fn receive_message_skips_ignored_frames() {
        let private_key = [51_u8; 32];
        let server_public_key = tailscale_node_public_key([52_u8; 32]).unwrap();
        let (stream, mut server) = tokio::io::duplex(1024);
        let mut client = TailscaleDerpClient {
            stream,
            private_key,
            public_key: tailscale_node_public_key(private_key).unwrap(),
            server_public_key,
        };
        let writer = tokio::spawn(async move {
            write_tailscale_derp_frame(&mut server, 0xfe, b"future", 64)
                .await
                .unwrap();
            write_tailscale_derp_frame(
                &mut server,
                TAILSCALE_DERP_FRAME_PING,
                b"short",
                64,
            )
            .await
            .unwrap();
            write_tailscale_derp_frame(
                &mut server,
                TAILSCALE_DERP_FRAME_HEALTH,
                b"duplicate",
                64,
            )
            .await
            .unwrap();
        });
        assert_eq!(
            client.receive_message().await.unwrap(),
            TailscaleDerpReceivedMessage::Health(b"duplicate".to_vec())
        );
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn session_serializes_writes_answers_ping_and_delivers_packets() {
        let private_key = [61_u8; 32];
        let server_public_key = tailscale_node_public_key([62_u8; 32]).unwrap();
        let destination = [63_u8; 32];
        let source = [64_u8; 32];
        let (stream, mut server) = tokio::io::duplex(8192);
        let client = TailscaleDerpClient {
            stream,
            private_key,
            public_key: tailscale_node_public_key(private_key).unwrap(),
            server_public_key,
        };
        let server_task = tokio::spawn(async move {
            write_tailscale_derp_frame(
                &mut server,
                TAILSCALE_DERP_FRAME_PING,
                b"pingpong",
                8,
            )
            .await
            .unwrap();
            let mut received_pong = false;
            let mut received_packet = false;
            while !received_pong || !received_packet {
                let frame =
                    read_tailscale_derp_frame(&mut server, 1024).await.unwrap();
                match frame.frame_type {
                    TAILSCALE_DERP_FRAME_PONG => {
                        assert_eq!(frame.payload, b"pingpong");
                        received_pong = true;
                    }
                    TAILSCALE_DERP_FRAME_SEND_PACKET => {
                        assert_eq!(&frame.payload[..32], &destination);
                        assert_eq!(&frame.payload[32..], b"wireguard");
                        received_packet = true;
                    }
                    frame_type => {
                        panic!("unexpected client frame {frame_type:#x}")
                    }
                }
            }
            let mut payload = source.to_vec();
            payload.extend_from_slice(b"incoming");
            write_tailscale_derp_frame(
                &mut server,
                TAILSCALE_DERP_FRAME_RECV_PACKET,
                &payload,
                1024,
            )
            .await
            .unwrap();
        });

        let mut session = client.into_session();
        session.try_send_packet(destination, b"wireguard").unwrap();
        assert_eq!(
            session.next_event().await.unwrap().unwrap(),
            TailscaleDerpReceivedMessage::Packet(TailscaleDerpPacket {
                peer: source,
                packet: b"incoming".to_vec(),
            })
        );
        server_task.await.unwrap();
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn dropping_session_cancels_its_io_task() {
        let private_key = [71_u8; 32];
        let server_public_key = tailscale_node_public_key([72_u8; 32]).unwrap();
        let (stream, mut server) = tokio::io::duplex(1024);
        let client = TailscaleDerpClient {
            stream,
            private_key,
            public_key: tailscale_node_public_key(private_key).unwrap(),
            server_public_key,
        };

        let session = client.into_session();
        drop(session);

        let closed =
            tokio::time::timeout(Duration::from_secs(1), server.read_u8())
                .await
                .expect("dropping a session must stop its I/O task");
        assert_eq!(closed.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }
}
