//! Raw DNS transports and resolver adapter for remote UDP/TCP servers.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::{Buf as _, Bytes};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, RecordType,
        rdata::opt::{ClientSubnet, EdnsCode, EdnsOption},
    },
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Request, StatusCode,
    client::conn::{http1, http2},
    header::{ACCEPT, CONTENT_TYPE, HOST, HeaderMap},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use n0_watcher::Watcher as _;
use quinn::{Endpoint, crypto::rustls::QuicClientConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, mpsc, oneshot},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{Dialer, Stream},
    common::{network::SocksAddr, quic::PacketUdpSocket, tls::ClientTlsConfig},
    dns::{
        LookupFuture, LookupOptions, MessageFuture, Resolver, apply_strategy,
        client::{
            Client, ClientOptions, ExchangeFuture, ExchangeOptions, Transport,
        },
    },
    option::DomainStrategy,
    transport::quic::QuicDialer,
};

pub struct UdpTransport {
    tag: String,
    server: SocksAddr,
    dialer: Arc<dyn Dialer>,
}

impl UdpTransport {
    pub fn new(
        tag: impl Into<String>,
        server: SocksAddr,
        dialer: Arc<dyn Dialer>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server,
            dialer,
        }
    }
}

impl Transport for UdpTransport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn exchange<'a>(&'a self, message: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let request = encode_message(message)?;
            if request.len() > u16::MAX as usize {
                return Err(invalid_data(
                    "DNS request exceeds UDP message size",
                ));
            }
            let connection = self.dialer.listen_udp(&self.server).await?;
            connection.send_to(&request, &self.server).await?;
            let mut response = vec![0_u8; u16::MAX as usize];
            let (size, _) = connection.recv_from(&mut response).await?;
            let response = decode_message(&response[..size])?;
            validate_response(message, &response)?;
            if response.metadata.truncation {
                return exchange_framed_single(
                    self.dialer.dial_tcp(&self.server).await?,
                    message,
                    "TCP fallback",
                )
                .await;
            }
            Ok(response)
        })
    }
}

pub struct TcpTransport {
    tag: String,
    server: SocksAddr,
    dialer: Arc<dyn Dialer>,
    connection: Arc<Mutex<Option<Arc<FramedConnection>>>>,
    reuse: Arc<ReuseCapability>,
    network_monitor_started: Arc<AtomicBool>,
    cancellation: CancellationToken,
}

pub struct TlsTransport {
    tag: String,
    server: SocksAddr,
    dialer: Arc<dyn Dialer>,
    tls: ClientTlsConfig,
    connection: Arc<Mutex<Option<Arc<FramedConnection>>>>,
    reuse: Arc<ReuseCapability>,
    network_monitor_started: Arc<AtomicBool>,
    cancellation: CancellationToken,
}

struct FramedConnection {
    sender: mpsc::Sender<Vec<u8>>,
    pending: Arc<StdMutex<HashMap<u16, oneshot::Sender<io::Result<Message>>>>>,
    next_id: AtomicU16,
    alive: Arc<AtomicBool>,
    responses: Arc<AtomicU64>,
    writer_abort: tokio::task::AbortHandle,
    reader_abort: tokio::task::AbortHandle,
}

impl FramedConnection {
    fn new(stream: Stream) -> Self {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(64);
        let pending = Arc::new(StdMutex::new(HashMap::<
            u16,
            oneshot::Sender<io::Result<Message>>,
        >::new()));
        let alive = Arc::new(AtomicBool::new(true));
        let responses = Arc::new(AtomicU64::new(0));

        let writer_pending = pending.clone();
        let writer_alive = alive.clone();
        let writer_task = tokio::spawn(async move {
            while let Some(request) = receiver.recv().await {
                let length = match u16::try_from(request.len()) {
                    Ok(length) => length,
                    Err(_) => {
                        fail_framed_pending(
                            &writer_pending,
                            io::ErrorKind::InvalidData,
                            "DNS request exceeds framed transport size",
                        );
                        writer_alive.store(false, Ordering::Release);
                        return;
                    }
                };
                if let Err(error) = async {
                    writer.write_u16(length).await?;
                    writer.write_all(&request).await?;
                    writer.flush().await
                }
                .await
                {
                    fail_framed_pending(
                        &writer_pending,
                        error.kind(),
                        &error.to_string(),
                    );
                    writer_alive.store(false, Ordering::Release);
                    return;
                }
            }
        });

        let reader_pending = pending.clone();
        let reader_alive = alive.clone();
        let reader_responses = responses.clone();
        let reader_task = tokio::spawn(async move {
            let result: io::Result<()> = async {
                loop {
                    let length = reader.read_u16().await? as usize;
                    let mut bytes = vec![0_u8; length];
                    reader.read_exact(&mut bytes).await?;
                    let response = decode_message(&bytes)?;
                    let response_id = response.metadata.id;
                    let callback = reader_pending
                        .lock()
                        .expect("DNS framed pending mutex poisoned")
                        .remove(&response_id);
                    if let Some(callback) = callback {
                        reader_responses.fetch_add(1, Ordering::Relaxed);
                        let _ = callback.send(Ok(response));
                    }
                }
            }
            .await;
            if let Err(error) = result {
                fail_framed_pending(
                    &reader_pending,
                    error.kind(),
                    &error.to_string(),
                );
            }
            reader_alive.store(false, Ordering::Release);
        });

        Self {
            sender,
            pending,
            next_id: AtomicU16::new(1),
            alive,
            responses,
            writer_abort: writer_task.abort_handle(),
            reader_abort: reader_task.abort_handle(),
        }
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    fn has_read_response(&self) -> bool {
        self.responses.load(Ordering::Relaxed) != 0
    }

    async fn exchange(
        &self,
        message: &Message,
        transport: &str,
    ) -> io::Result<Message> {
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("DNS {transport} connection is closed"),
            ));
        }
        let original_id = message.metadata.id;
        let (response_sender, response_receiver) = oneshot::channel();
        let registered_response_epoch = self.responses.load(Ordering::Acquire);
        let query_id = loop {
            let candidate = self.next_id.fetch_add(1, Ordering::Relaxed);
            if candidate == 0 {
                continue;
            }
            let mut pending = self
                .pending
                .lock()
                .expect("DNS framed pending mutex poisoned");
            if let std::collections::hash_map::Entry::Vacant(entry) =
                pending.entry(candidate)
            {
                entry.insert(response_sender);
                break candidate;
            }
        };
        let mut pending_guard = FramedPendingGuard {
            pending: self.pending.clone(),
            query_id,
            active: true,
            registered_response_epoch,
            responses: self.responses.clone(),
            alive: self.alive.clone(),
            writer_abort: self.writer_abort.clone(),
            reader_abort: self.reader_abort.clone(),
        };
        let mut wire_message = message.clone();
        wire_message.metadata.id = query_id;
        let request = encode_message(&wire_message)?;
        self.sender.send(request).await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("DNS {transport} writer is closed"),
            )
        })?;
        let mut response = response_receiver.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("DNS {transport} response channel is closed"),
            )
        })??;
        pending_guard.active = false;
        validate_response(&wire_message, &response)?;
        response.metadata.id = original_id;
        Ok(response)
    }
}

impl Drop for FramedConnection {
    fn drop(&mut self) {
        self.writer_abort.abort();
        self.reader_abort.abort();
        fail_framed_pending(
            &self.pending,
            io::ErrorKind::Interrupted,
            "DNS framed connection was dropped",
        );
    }
}

struct FramedPendingGuard {
    pending: Arc<StdMutex<HashMap<u16, oneshot::Sender<io::Result<Message>>>>>,
    query_id: u16,
    active: bool,
    registered_response_epoch: u64,
    responses: Arc<AtomicU64>,
    alive: Arc<AtomicBool>,
    writer_abort: tokio::task::AbortHandle,
    reader_abort: tokio::task::AbortHandle,
}

impl Drop for FramedPendingGuard {
    fn drop(&mut self) {
        if self.active {
            let removed = self
                .pending
                .lock()
                .expect("DNS framed pending mutex poisoned")
                .remove(&self.query_id)
                .is_some();
            if removed
                && self.responses.load(Ordering::Acquire)
                    == self.registered_response_epoch
                && self.alive.swap(false, Ordering::AcqRel)
            {
                self.writer_abort.abort();
                self.reader_abort.abort();
                fail_framed_pending(
                    &self.pending,
                    io::ErrorKind::TimedOut,
                    "DNS framed query was cancelled before any response",
                );
            }
        }
    }
}

fn fail_framed_pending(
    pending: &StdMutex<HashMap<u16, oneshot::Sender<io::Result<Message>>>>,
    kind: io::ErrorKind,
    message: &str,
) {
    let callbacks = std::mem::take(
        &mut *pending.lock().expect("DNS framed pending mutex poisoned"),
    );
    for callback in callbacks.into_values() {
        let _ = callback.send(Err(io::Error::new(kind, message.to_owned())));
    }
}

const REUSE_UNKNOWN: u8 = 0;
const REUSE_PROBING: u8 = 1;
const REUSE_SUPPORTED: u8 = 2;
const REUSE_UNSUPPORTED: u8 = 3;
const REUSE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const REUSE_PROBE_RETRY_INTERVAL: Duration = Duration::from_secs(60);
const REUSE_DEMOTE_FAILURE_LIMIT: u8 = 3;

struct ReuseCapability {
    state: AtomicU8,
    failures: AtomicU8,
    last_probe: StdMutex<Option<Instant>>,
}

impl ReuseCapability {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(REUSE_UNKNOWN),
            failures: AtomicU8::new(0),
            last_probe: StdMutex::new(None),
        }
    }

    fn supported(&self) -> bool {
        self.state.load(Ordering::Acquire) == REUSE_SUPPORTED
    }

    fn begin_probe(&self) -> bool {
        let mut last_probe = self
            .last_probe
            .lock()
            .expect("DNS reuse probe mutex poisoned");
        let state = self.state.load(Ordering::Acquire);
        if state == REUSE_SUPPORTED || state == REUSE_PROBING {
            return false;
        }
        if last_probe
            .as_ref()
            .is_some_and(|last| last.elapsed() < REUSE_PROBE_RETRY_INTERVAL)
        {
            return false;
        }
        *last_probe = Some(Instant::now());
        self.state.store(REUSE_PROBING, Ordering::Release);
        true
    }

    fn finish_probe(&self, outcome: ProbeOutcome) {
        let state = match outcome {
            ProbeOutcome::Supported => {
                self.failures.store(0, Ordering::Release);
                REUSE_SUPPORTED
            }
            ProbeOutcome::DialFailed => REUSE_UNKNOWN,
            ProbeOutcome::Unsupported => REUSE_UNSUPPORTED,
        };
        self.state.store(state, Ordering::Release);
    }

    fn record_shared_failure(&self, connection: &FramedConnection) {
        if !self.supported() || !connection.has_read_response() {
            return;
        }
        if self.failures.fetch_add(1, Ordering::AcqRel) + 1
            < REUSE_DEMOTE_FAILURE_LIMIT
        {
            return;
        }
        self.state.store(REUSE_UNSUPPORTED, Ordering::Release);
        *self
            .last_probe
            .lock()
            .expect("DNS reuse probe mutex poisoned") = Some(Instant::now());
        self.failures.store(0, Ordering::Release);
    }
}

#[derive(Clone, Copy)]
enum ProbeOutcome {
    Supported,
    DialFailed,
    Unsupported,
}

async fn exchange_framed_single(
    mut stream: Stream,
    message: &Message,
    transport: &str,
) -> io::Result<Message> {
    write_framed_message(&mut stream, message)
        .await
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("write DNS {transport} request: {error}"),
            )
        })?;
    let response = read_framed_message(&mut stream).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("read DNS {transport} response: {error}"),
        )
    })?;
    validate_response(message, &response)?;
    Ok(response)
}

async fn execute_reuse_probe(mut stream: Stream, name: Name) -> io::Result<()> {
    let mut query_a = Message::new(1, MessageType::Query, OpCode::Query);
    query_a.add_query(Query::query(name.clone(), RecordType::A));
    let mut query_aaaa = Message::new(2, MessageType::Query, OpCode::Query);
    query_aaaa.add_query(Query::query(name, RecordType::AAAA));
    write_framed_message(&mut stream, &query_a).await?;
    write_framed_message(&mut stream, &query_aaaa).await?;
    let mut seen_a = false;
    let mut seen_aaaa = false;
    while !seen_a || !seen_aaaa {
        match read_framed_message(&mut stream).await?.metadata.id {
            1 => seen_a = true,
            2 => seen_aaaa = true,
            _ => {}
        }
    }
    Ok(())
}

async fn write_framed_message(
    stream: &mut Stream,
    message: &Message,
) -> io::Result<()> {
    let request = encode_message(message)?;
    let length = u16::try_from(request.len())
        .map_err(|_| invalid_data("DNS request exceeds framed size"))?;
    stream.write_u16(length).await?;
    stream.write_all(&request).await?;
    stream.flush().await
}

async fn read_framed_message(stream: &mut Stream) -> io::Result<Message> {
    let length = stream.read_u16().await? as usize;
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await?;
    decode_message(&bytes)
}

async fn dial_tls_stream(
    dialer: Arc<dyn Dialer>,
    server: SocksAddr,
    tls: &ClientTlsConfig,
) -> io::Result<Stream> {
    let connection = dialer.dial_tcp(&server).await?;
    Ok(tls.connect_stream(connection).await?.into_stream())
}

pub struct QuicTransport {
    tag: String,
    server: SocksAddr,
    dialer: Arc<QuicDialer>,
}

impl QuicTransport {
    pub fn new(
        tag: impl Into<String>,
        server: SocksAddr,
        dialer: Arc<QuicDialer>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server,
            dialer,
        }
    }

    /// Close the reusable DoQ connection. The next exchange performs a new
    /// QUIC handshake.
    pub async fn reset(&self) {
        self.dialer.reset().await;
    }
}

impl Transport for QuicTransport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn exchange<'a>(&'a self, message: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let request = encode_message(message)?;
            let request_length =
                u16::try_from(request.len()).map_err(|_| {
                    invalid_data("DNS request exceeds QUIC frame size")
                })?;
            let mut stream = self.dialer.dial_tcp(&self.server).await?;
            stream.write_u16(request_length).await?;
            stream.write_all(&request).await?;
            stream.shutdown().await?;
            let response_length = stream.read_u16().await? as usize;
            let mut response = vec![0_u8; response_length];
            stream.read_exact(&mut response).await?;
            let response = decode_message(&response)?;
            validate_response(message, &response)?;
            Ok(response)
        })
    }
}

impl TlsTransport {
    pub fn new(
        tag: impl Into<String>,
        server: SocksAddr,
        dialer: Arc<dyn Dialer>,
        tls: ClientTlsConfig,
    ) -> Self {
        Self {
            tag: tag.into(),
            server,
            dialer,
            tls,
            connection: Arc::new(Mutex::new(None)),
            reuse: Arc::new(ReuseCapability::new()),
            network_monitor_started: Arc::new(AtomicBool::new(false)),
            cancellation: CancellationToken::new(),
        }
    }

    /// Drop the shared framed TLS connection. The next eligible exchange
    /// performs a fresh handshake.
    pub async fn reset(&self) {
        self.connection.lock().await.take();
    }

    #[cfg(test)]
    fn assume_reuse_supported(&self) {
        self.reuse.state.store(REUSE_SUPPORTED, Ordering::Release);
    }

    async fn dial_stream(&self) -> io::Result<Stream> {
        dial_tls_stream(self.dialer.clone(), self.server.clone(), &self.tls)
            .await
    }

    fn maybe_start_probe(&self, message: &Message) {
        let Some(query) = message.queries.first() else {
            return;
        };
        if !self.reuse.begin_probe() {
            return;
        }
        let dialer = self.dialer.clone();
        let server = self.server.clone();
        let tls = self.tls.clone();
        let name = query.name().clone();
        let reuse = self.reuse.clone();
        tokio::spawn(async move {
            let outcome = timeout(REUSE_PROBE_TIMEOUT, async {
                let stream = dial_tls_stream(dialer, server, &tls)
                    .await
                    .map_err(|_| ProbeOutcome::DialFailed)?;
                execute_reuse_probe(stream, name)
                    .await
                    .map_err(|_| ProbeOutcome::Unsupported)
            })
            .await
            .map_or(ProbeOutcome::Unsupported, |result| {
                result
                    .map_or_else(|outcome| outcome, |_| ProbeOutcome::Supported)
            });
            reuse.finish_probe(outcome);
        });
    }

    async fn connection(&self) -> io::Result<(Arc<FramedConnection>, bool)> {
        let mut state = self.connection.lock().await;
        if let Some(connection) = state.as_ref()
            && connection.is_alive()
        {
            return Ok((connection.clone(), true));
        }
        let connection =
            Arc::new(FramedConnection::new(self.dial_stream().await?));
        *state = Some(connection.clone());
        Ok((connection, false))
    }

    async fn discard(&self, connection: &Arc<FramedConnection>) {
        let mut state = self.connection.lock().await;
        if state
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, connection))
        {
            *state = None;
        }
    }
}

impl Transport for TlsTransport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn exchange<'a>(&'a self, message: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            ensure_network_reset_monitor(
                &self.connection,
                &self.network_monitor_started,
                &self.cancellation,
            );
            if !self.reuse.supported() {
                self.maybe_start_probe(message);
                return exchange_framed_single(
                    self.dial_stream().await?,
                    message,
                    "TLS",
                )
                .await;
            }
            for attempt in 0..2 {
                let (connection, reused) = self.connection().await?;
                let result = connection.exchange(message, "TLS").await;
                if result.is_ok() {
                    return result;
                }
                let retry = reused
                    && attempt == 0
                    && result.as_ref().unwrap_err().kind()
                        != io::ErrorKind::InvalidData;
                if result.as_ref().is_err_and(|error| {
                    error.kind() != io::ErrorKind::InvalidData
                }) {
                    self.reuse.record_shared_failure(&connection);
                }
                self.discard(&connection).await;
                if !retry {
                    return result;
                }
            }
            unreachable!("DNS TLS retry loop always returns")
        })
    }
}

impl Drop for TlsTransport {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut connection) = self.connection.try_lock() {
            connection.take();
        }
    }
}

pub struct HttpsTransport {
    tag: String,
    server: SocksAddr,
    dialer: Arc<dyn Dialer>,
    tls: ClientTlsConfig,
    uri: String,
    headers: HeaderMap,
    state: Arc<Mutex<Option<HttpsSession>>>,
    network_monitor_started: Arc<AtomicBool>,
    cancellation: CancellationToken,
}

type H1SendRequest = http1::SendRequest<Full<Bytes>>;
type H2SendRequest = http2::SendRequest<Full<Bytes>>;

enum HttpsSession {
    Http1 {
        sender: H1SendRequest,
        driver: tokio::task::JoinHandle<Result<(), hyper::Error>>,
    },
    Http2 {
        sender: H2SendRequest,
        driver: tokio::task::JoinHandle<Result<(), hyper::Error>>,
    },
}

impl HttpsSession {
    fn is_finished(&self) -> bool {
        match self {
            Self::Http1 { driver, .. } | Self::Http2 { driver, .. } => {
                driver.is_finished()
            }
        }
    }
}

impl Drop for HttpsSession {
    fn drop(&mut self) {
        match self {
            Self::Http1 { driver, .. } | Self::Http2 { driver, .. } => {
                driver.abort();
            }
        }
    }
}

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

struct Http3Session {
    endpoint: Endpoint,
    sender: H3SendRequest,
    driver: tokio::task::JoinHandle<h3::error::ConnectionError>,
}

impl Drop for Http3Session {
    fn drop(&mut self) {
        self.driver.abort();
        self.endpoint.close(0_u32.into(), b"");
    }
}

/// DNS-over-HTTP/3 transport with a reusable QUIC connection.
pub struct Http3Transport {
    tag: String,
    server: SocksAddr,
    server_name: String,
    uri: String,
    headers: HeaderMap,
    client_config: quinn::ClientConfig,
    resolver: Option<(Arc<dyn Resolver>, DomainStrategy)>,
    packet_dialer: Option<Arc<dyn Dialer>>,
    state: Arc<Mutex<Option<Http3Session>>>,
    network_monitor_started: Arc<AtomicBool>,
    cancellation: CancellationToken,
}

impl Http3Transport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tag: impl Into<String>,
        server: SocksAddr,
        server_name: impl Into<String>,
        tls: ClientTlsConfig,
        uri: String,
        headers: HeaderMap,
        resolver: Option<(Arc<dyn Resolver>, DomainStrategy)>,
    ) -> io::Result<Self> {
        Self::new_inner(
            tag,
            server,
            server_name,
            tls,
            uri,
            headers,
            resolver,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_packet_dialer(
        tag: impl Into<String>,
        server: SocksAddr,
        server_name: impl Into<String>,
        tls: ClientTlsConfig,
        uri: String,
        headers: HeaderMap,
        packet_dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        Self::new_inner(
            tag,
            server,
            server_name,
            tls,
            uri,
            headers,
            None,
            Some(packet_dialer),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        tag: impl Into<String>,
        server: SocksAddr,
        server_name: impl Into<String>,
        tls: ClientTlsConfig,
        uri: String,
        headers: HeaderMap,
        resolver: Option<(Arc<dyn Resolver>, DomainStrategy)>,
        packet_dialer: Option<Arc<dyn Dialer>>,
    ) -> io::Result<Self> {
        let crypto = QuicClientConfig::try_from(
            tls.rustls_config().map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        Ok(Self {
            tag: tag.into(),
            server,
            server_name: server_name.into(),
            uri,
            headers,
            client_config: quinn::ClientConfig::new(Arc::new(crypto)),
            resolver,
            packet_dialer,
            state: Arc::new(Mutex::new(None)),
            network_monitor_started: Arc::new(AtomicBool::new(false)),
            cancellation: CancellationToken::new(),
        })
    }

    async fn connect(&self) -> io::Result<Http3Session> {
        let (mut endpoint, remote) = if let Some(dialer) = &self.packet_dialer {
            let (socket, remote) =
                PacketUdpSocket::connect(dialer.clone(), &self.server).await?;
            (
                Endpoint::new_with_abstract_socket(
                    quinn::EndpointConfig::default(),
                    None,
                    socket,
                    Arc::new(quinn::TokioRuntime),
                )?,
                remote,
            )
        } else {
            let remote =
                resolve_http3_server(&self.server, self.resolver.as_ref())
                    .await?;
            let bind = if remote.is_ipv4() {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            };
            (Endpoint::client(bind)?, remote)
        };
        endpoint.set_default_client_config(self.client_config.clone());
        let connection = endpoint
            .connect(remote, &self.server_name)
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)?;
        let (connection, sender) =
            h3::client::new(h3_quinn::Connection::new(connection))
                .await
                .map_err(io::Error::other)?;
        let driver = tokio::spawn(async move {
            let mut connection = connection;
            futures_util::future::poll_fn(|context| {
                connection.poll_close(context)
            })
            .await
        });
        Ok(Http3Session {
            endpoint,
            sender,
            driver,
        })
    }

    /// Close the cached HTTP/3 session. The next DNS exchange reconnects and
    /// re-resolves the configured server.
    pub async fn reset(&self) {
        self.state.lock().await.take();
    }

    async fn request(&self, payload: Vec<u8>) -> io::Result<Vec<u8>> {
        ensure_network_reset_monitor(
            &self.state,
            &self.network_monitor_started,
            &self.cancellation,
        );
        let mut request = Request::post(&self.uri)
            .body(())
            .map_err(|error| invalid_data(error.to_string()))?;
        *request.headers_mut() = self.headers.clone();
        request.headers_mut().insert(
            CONTENT_TYPE,
            "application/dns-message".parse().expect("static header"),
        );
        request.headers_mut().insert(
            ACCEPT,
            "application/dns-message".parse().expect("static header"),
        );

        let mut state = self.state.lock().await;
        if state
            .as_ref()
            .is_none_or(|session| session.driver.is_finished())
        {
            *state = Some(self.connect().await?);
        }
        let stream = state
            .as_mut()
            .expect("HTTP/3 session exists")
            .sender
            .send_request(request)
            .await;
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                *state = None;
                return Err(io::Error::other(error));
            }
        };
        drop(state);

        stream
            .send_data(Bytes::from(payload))
            .await
            .map_err(io::Error::other)?;
        stream.finish().await.map_err(io::Error::other)?;
        let response =
            stream.recv_response().await.map_err(io::Error::other)?;
        if response.status() != StatusCode::OK {
            return Err(io::Error::other(format!(
                "unexpected DNS over HTTP/3 status: {}",
                response.status()
            )));
        }
        let mut bytes = Vec::new();
        while let Some(mut chunk) =
            stream.recv_data().await.map_err(io::Error::other)?
        {
            bytes.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        Ok(bytes)
    }
}

impl Drop for Http3Transport {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut state) = self.state.try_lock() {
            state.take();
        }
    }
}

impl Transport for Http3Transport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn exchange<'a>(&'a self, message: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let original_id = message.metadata.id;
            let mut wire_message = message.clone();
            wire_message.metadata.id = 0;
            let response_bytes =
                self.request(encode_message(&wire_message)?).await?;
            let mut response = decode_message(&response_bytes)?;
            validate_response(&wire_message, &response)?;
            response.metadata.id = original_id;
            Ok(response)
        })
    }
}

async fn resolve_http3_server(
    server: &SocksAddr,
    resolver: Option<&(Arc<dyn Resolver>, DomainStrategy)>,
) -> io::Result<SocketAddr> {
    match server {
        SocksAddr::Ip(address) => Ok(*address),
        SocksAddr::Domain { host, port } => {
            if let Some((resolver, strategy)) = resolver {
                return resolver
                    .lookup(host, *strategy)
                    .await?
                    .into_iter()
                    .next()
                    .map(|address| SocketAddr::new(address, *port))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!(
                                "HTTP/3 DNS server {host:?} resolved to no addresses"
                            ),
                        )
                    });
            }
            tokio::net::lookup_host((host.as_str(), *port))
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "HTTP/3 DNS server {host:?} resolved to no addresses"
                        ),
                    )
                })
        }
    }
}

impl HttpsTransport {
    pub fn new(
        tag: impl Into<String>,
        server: SocksAddr,
        dialer: Arc<dyn Dialer>,
        tls: ClientTlsConfig,
        uri: String,
        headers: HeaderMap,
    ) -> Self {
        Self {
            tag: tag.into(),
            server,
            dialer,
            tls,
            uri,
            headers,
            state: Arc::new(Mutex::new(None)),
            network_monitor_started: Arc::new(AtomicBool::new(false)),
            cancellation: CancellationToken::new(),
        }
    }

    /// Close the cached HTTP/1.1 or HTTP/2 session. The next DNS exchange
    /// reconnects through the configured dialer.
    pub async fn reset(&self) {
        self.state.lock().await.take();
    }

    async fn connect(&self) -> io::Result<HttpsSession> {
        let connection = self.dialer.dial_tcp(&self.server).await?;
        let connection = self.tls.connect_stream(connection).await?;
        let http2 = connection.negotiated_alpn() == Some(b"h2");
        let connection = connection.into_stream();
        if http2 {
            let (sender, connection) =
                http2::Builder::new(TokioExecutor::new())
                    .handshake(TokioIo::new(connection))
                    .await
                    .map_err(io::Error::other)?;
            Ok(HttpsSession::Http2 {
                sender,
                driver: tokio::spawn(connection),
            })
        } else {
            let (sender, connection) =
                http1::handshake(TokioIo::new(connection))
                    .await
                    .map_err(io::Error::other)?;
            Ok(HttpsSession::Http1 {
                sender,
                driver: tokio::spawn(connection),
            })
        }
    }

    async fn request(
        &self,
        request: Request<Full<Bytes>>,
    ) -> io::Result<Bytes> {
        ensure_network_reset_monitor(
            &self.state,
            &self.network_monitor_started,
            &self.cancellation,
        );
        let mut state = self.state.lock().await;
        if state.as_ref().is_none_or(HttpsSession::is_finished) {
            *state = Some(self.connect().await?);
        }
        match state.as_mut().expect("HTTPS session exists") {
            HttpsSession::Http1 { sender, .. } => {
                let response = match sender.send_request(request).await {
                    Ok(response) => response,
                    Err(error) => {
                        *state = None;
                        return Err(io::Error::other(error));
                    }
                };
                let body = collect_doh_response(response).await;
                if body.is_err() {
                    *state = None;
                }
                body
            }
            HttpsSession::Http2 { sender, .. } => {
                let mut sender = sender.clone();
                drop(state);
                let response = match sender.send_request(request).await {
                    Ok(response) => response,
                    Err(error) => {
                        *self.state.lock().await = None;
                        return Err(io::Error::other(error));
                    }
                };
                let body = collect_doh_response(response).await;
                if body.is_err() {
                    *self.state.lock().await = None;
                }
                body
            }
        }
    }
}

impl Drop for HttpsTransport {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut state) = self.state.try_lock() {
            state.take();
        }
    }
}

fn ensure_network_reset_monitor<T: Send + 'static>(
    state: &Arc<Mutex<Option<T>>>,
    started: &Arc<AtomicBool>,
    cancellation: &CancellationToken,
) {
    if started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let state = state.clone();
    let started = started.clone();
    let cancellation = cancellation.clone();
    tokio::spawn(async move {
        let Ok(monitor) =
            crate::common::network_monitor::NetworkMonitor::new().await
        else {
            started.store(false, Ordering::Release);
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
                state.lock().await.take();
            }
        }
    });
}

async fn collect_doh_response(
    response: hyper::Response<hyper::body::Incoming>,
) -> io::Result<Bytes> {
    if response.status() != StatusCode::OK {
        return Err(io::Error::other(format!(
            "unexpected DNS over HTTPS status: {}",
            response.status()
        )));
    }
    response
        .into_body()
        .collect()
        .await
        .map(|body| body.to_bytes())
        .map_err(io::Error::other)
}

impl Transport for HttpsTransport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn exchange<'a>(&'a self, message: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let original_id = message.metadata.id;
            let mut wire_message = message.clone();
            wire_message.metadata.id = 0;
            let payload = encode_message(&wire_message)?;
            let mut request = Request::post(&self.uri)
                .body(Full::new(Bytes::from(payload)))
                .map_err(|error| invalid_data(error.to_string()))?;
            *request.headers_mut() = self.headers.clone();
            request.headers_mut().insert(
                CONTENT_TYPE,
                "application/dns-message".parse().expect("static header"),
            );
            request.headers_mut().insert(
                ACCEPT,
                "application/dns-message".parse().expect("static header"),
            );
            if !request.headers().contains_key(HOST) {
                let authority = request
                    .uri()
                    .authority()
                    .ok_or_else(|| invalid_data("DoH URI has no authority"))?
                    .as_str()
                    .parse()
                    .map_err(|error: hyper::header::InvalidHeaderValue| {
                        invalid_data(error.to_string())
                    })?;
                request.headers_mut().insert(HOST, authority);
            }
            let response_bytes = self.request(request).await?;
            let mut response = decode_message(&response_bytes)?;
            validate_response(&wire_message, &response)?;
            response.metadata.id = original_id;
            Ok(response)
        })
    }
}

impl TcpTransport {
    pub fn new(
        tag: impl Into<String>,
        server: SocksAddr,
        dialer: Arc<dyn Dialer>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server,
            dialer,
            connection: Arc::new(Mutex::new(None)),
            reuse: Arc::new(ReuseCapability::new()),
            network_monitor_started: Arc::new(AtomicBool::new(false)),
            cancellation: CancellationToken::new(),
        }
    }

    /// Drop the shared framed TCP connection. The next eligible exchange
    /// creates a new physical connection.
    pub async fn reset(&self) {
        self.connection.lock().await.take();
    }

    #[cfg(test)]
    fn assume_reuse_supported(&self) {
        self.reuse.state.store(REUSE_SUPPORTED, Ordering::Release);
    }

    async fn dial_stream(&self) -> io::Result<Stream> {
        self.dialer.dial_tcp(&self.server).await
    }

    fn maybe_start_probe(&self, message: &Message) {
        let Some(query) = message.queries.first() else {
            return;
        };
        if !self.reuse.begin_probe() {
            return;
        }
        let dialer = self.dialer.clone();
        let server = self.server.clone();
        let name = query.name().clone();
        let reuse = self.reuse.clone();
        tokio::spawn(async move {
            let outcome = timeout(REUSE_PROBE_TIMEOUT, async {
                let stream = dialer
                    .dial_tcp(&server)
                    .await
                    .map_err(|_| ProbeOutcome::DialFailed)?;
                execute_reuse_probe(stream, name)
                    .await
                    .map_err(|_| ProbeOutcome::Unsupported)
            })
            .await
            .map_or(ProbeOutcome::Unsupported, |result| {
                result
                    .map_or_else(|outcome| outcome, |_| ProbeOutcome::Supported)
            });
            reuse.finish_probe(outcome);
        });
    }

    async fn connection(&self) -> io::Result<(Arc<FramedConnection>, bool)> {
        let mut state = self.connection.lock().await;
        if let Some(connection) = state.as_ref()
            && connection.is_alive()
        {
            return Ok((connection.clone(), true));
        }
        let stream = self.dial_stream().await?;
        let connection = Arc::new(FramedConnection::new(stream));
        *state = Some(connection.clone());
        Ok((connection, false))
    }

    async fn discard(&self, connection: &Arc<FramedConnection>) {
        let mut state = self.connection.lock().await;
        if state
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, connection))
        {
            *state = None;
        }
    }
}

impl Transport for TcpTransport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn exchange<'a>(&'a self, message: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            ensure_network_reset_monitor(
                &self.connection,
                &self.network_monitor_started,
                &self.cancellation,
            );
            if !self.reuse.supported() {
                self.maybe_start_probe(message);
                return exchange_framed_single(
                    self.dial_stream().await?,
                    message,
                    "TCP",
                )
                .await;
            }
            for attempt in 0..2 {
                let (connection, reused) = self.connection().await?;
                let result = connection.exchange(message, "TCP").await;
                if result.is_ok() {
                    return result;
                }
                let retry = reused
                    && attempt == 0
                    && result.as_ref().unwrap_err().kind()
                        != io::ErrorKind::InvalidData;
                if result.as_ref().is_err_and(|error| {
                    error.kind() != io::ErrorKind::InvalidData
                }) {
                    self.reuse.record_shared_failure(&connection);
                }
                self.discard(&connection).await;
                if !retry {
                    return result;
                }
            }
            unreachable!("DNS TCP retry loop always returns")
        })
    }
}

impl Drop for TcpTransport {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut connection) = self.connection.try_lock() {
            connection.take();
        }
    }
}

pub struct RemoteResolver {
    client: Arc<Client>,
    transport: Arc<dyn Transport>,
    default_strategy: DomainStrategy,
    client_subnet: Option<ipnet::IpNet>,
}

impl RemoteResolver {
    pub fn new(
        transport: impl Transport + 'static,
        options: ClientOptions,
    ) -> Self {
        Self::with_client(transport, Arc::new(Client::new(options)))
    }

    pub fn with_client(
        transport: impl Transport + 'static,
        client: Arc<Client>,
    ) -> Self {
        Self::with_client_and_strategy(transport, client, DomainStrategy::AsIs)
    }

    pub fn with_client_and_strategy(
        transport: impl Transport + 'static,
        client: Arc<Client>,
        default_strategy: DomainStrategy,
    ) -> Self {
        Self {
            client,
            transport: Arc::new(transport),
            default_strategy,
            client_subnet: None,
        }
    }

    pub fn with_client_strategy_and_subnet(
        transport: impl Transport + 'static,
        client: Arc<Client>,
        default_strategy: DomainStrategy,
        client_subnet: Option<ipnet::IpNet>,
    ) -> Self {
        Self {
            client,
            transport: Arc::new(transport),
            default_strategy,
            client_subnet,
        }
    }

    async fn lookup_type(
        &self,
        domain: &str,
        record_type: RecordType,
        options: LookupOptions,
    ) -> io::Result<Vec<IpAddr>> {
        let name = Name::from_ascii(domain).map_err(|error| {
            invalid_data(format!("invalid DNS name: {error}"))
        })?;
        let mut request = Message::query();
        request.add_query(Query::query(name, record_type));
        if let Some(client_subnet) = options.client_subnet.or_else(|| {
            (!options.remove_client_subnet)
                .then_some(self.client_subnet)
                .flatten()
        }) {
            set_client_subnet(&mut request, client_subnet);
        }
        let response = self
            .client
            .exchange_owned_with_options(
                self.transport.clone(),
                &request,
                ExchangeOptions {
                    timeout: options.timeout,
                    disable_cache: options.disable_cache,
                    disable_optimistic_cache: options.disable_optimistic_cache,
                    rewrite_ttl: options.rewrite_ttl,
                },
            )
            .await?;
        if response.metadata.response_code != ResponseCode::NoError {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "DNS response code: {}",
                    response.metadata.response_code
                ),
            ));
        }
        Ok(response
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(address) => Some(IpAddr::V4(address.0)),
                RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                _ => None,
            })
            .collect())
    }

    async fn lookup_inner(
        &self,
        domain: &str,
        mut options: LookupOptions,
    ) -> io::Result<Vec<IpAddr>> {
        if options.strategy == DomainStrategy::AsIs {
            options.strategy = self.default_strategy;
        }
        let mut addresses = match options.strategy {
            DomainStrategy::Ipv4Only => {
                self.lookup_type(domain, RecordType::A, options).await?
            }
            DomainStrategy::Ipv6Only => {
                self.lookup_type(domain, RecordType::AAAA, options).await?
            }
            _ => {
                let (ipv4, ipv6) = tokio::join!(
                    self.lookup_type(domain, RecordType::A, options),
                    self.lookup_type(domain, RecordType::AAAA, options),
                );
                match (ipv4, ipv6) {
                    (Ok(mut ipv4), Ok(ipv6)) => {
                        ipv4.extend(ipv6);
                        ipv4
                    }
                    (Ok(addresses), Err(_)) | (Err(_), Ok(addresses))
                        if !addresses.is_empty() =>
                    {
                        addresses
                    }
                    (Err(ipv4), Err(ipv6)) => {
                        return Err(io::Error::new(
                            ipv4.kind(),
                            format!(
                                "IPv4 DNS lookup failed: {ipv4}; IPv6 DNS lookup failed: {ipv6}"
                            ),
                        ));
                    }
                    (Ok(_), Err(error)) | (Err(error), Ok(_)) => {
                        return Err(error);
                    }
                }
            }
        };
        apply_strategy(&mut addresses, options.strategy);
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("DNS response for {domain:?} has no matching address"),
            ));
        }
        Ok(addresses)
    }
}

fn set_client_subnet(message: &mut Message, subnet: ipnet::IpNet) {
    let edns = message.edns.get_or_insert_with(Edns::new);
    edns.options_mut().remove(EdnsCode::Subnet);
    edns.options_mut()
        .insert(EdnsOption::Subnet(ClientSubnet::from(subnet)));
}

impl Resolver for RemoteResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: DomainStrategy,
    ) -> LookupFuture<'a> {
        Box::pin(self.lookup_inner(
            domain,
            LookupOptions {
                strategy,
                ..LookupOptions::default()
            },
        ))
    }

    fn lookup_with_options<'a>(
        &'a self,
        domain: &'a str,
        options: LookupOptions,
    ) -> LookupFuture<'a> {
        Box::pin(self.lookup_inner(domain, options))
    }

    fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
        self.exchange_with_options(request, LookupOptions::default())
    }

    fn exchange_with_options<'a>(
        &'a self,
        request: &'a Message,
        options: LookupOptions,
    ) -> MessageFuture<'a> {
        Box::pin(async move {
            let mut request = request.clone();
            if let Some(client_subnet) = options.client_subnet.or_else(|| {
                (!options.remove_client_subnet)
                    .then_some(self.client_subnet)
                    .flatten()
            }) {
                set_client_subnet(&mut request, client_subnet);
            }
            self.client
                .exchange_owned_with_options(
                    self.transport.clone(),
                    &request,
                    ExchangeOptions {
                        timeout: options.timeout,
                        disable_cache: options.disable_cache,
                        disable_optimistic_cache: options
                            .disable_optimistic_cache,
                        rewrite_ttl: options.rewrite_ttl,
                    },
                )
                .await
        })
    }

    fn preferred_domain(&self, domain: &str) -> Option<bool> {
        self.transport.preferred_domain(domain)
    }
}

fn encode_message(message: &Message) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(512);
    message
        .emit(&mut BinEncoder::new(&mut bytes))
        .map_err(|error| invalid_data(error.to_string()))?;
    Ok(bytes)
}

fn decode_message(bytes: &[u8]) -> io::Result<Message> {
    Message::read(&mut BinDecoder::new(bytes))
        .map_err(|error| invalid_data(error.to_string()))
}

fn validate_response(request: &Message, response: &Message) -> io::Result<()> {
    if response.metadata.message_type != MessageType::Response {
        return Err(invalid_data("DNS transport returned a query"));
    }
    if response.metadata.op_code != OpCode::Query
        || response.metadata.id != request.metadata.id
    {
        return Err(invalid_data("DNS response does not match request"));
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use bytes::{Buf as _, Bytes};
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{
            RData, Record, RecordType,
            rdata::{
                A, TXT,
                opt::{EdnsCode, EdnsOption},
            },
        },
        serialize::binary::{
            BinDecodable, BinDecoder, BinEncodable, BinEncoder,
        },
    };
    use http_body_util::{BodyExt as _, Full};
    use hyper::{
        Response, StatusCode,
        header::{CONTENT_TYPE, HeaderMap},
        service::service_fn,
    };
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{
        ServerConfig,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };
    use tokio_rustls::TlsAcceptor;

    use super::{
        Http3Transport, HttpsTransport, QuicTransport, RemoteResolver,
        TcpTransport, TlsTransport, UdpTransport, set_client_subnet,
    };
    use crate::{
        common::tls::{ServerTlsConfig, build_client_config},
        dns::{
            Resolver,
            client::{ClientOptions, Transport},
        },
        option::{DirectOutboundOptions, OutboundTlsOptions},
        protocol::direct::DirectOutbound,
        transport::quic::{QuicDialer, server_endpoint},
    };

    #[tokio::test]
    async fn udp_transport_resolves_against_a_wire_server() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let mut bytes = [0_u8; 1024];
                let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
                let request =
                    Message::read(&mut BinDecoder::new(&bytes[..size]))
                        .unwrap();
                let mut response = Message::new(
                    request.metadata.id,
                    MessageType::Response,
                    OpCode::Query,
                );
                response.queries = request.queries.clone();
                if request.queries[0].query_type() == RecordType::A {
                    response.add_answer(Record::from_rdata(
                        request.queries[0].name().clone(),
                        60,
                        RData::A(A::new(192, 0, 2, 9)),
                    ));
                }
                let mut output = Vec::new();
                response.emit(&mut BinEncoder::new(&mut output)).unwrap();
                socket.send_to(&output, peer).await.unwrap();
            }
        });
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let resolver = RemoteResolver::new(
            UdpTransport::new("remote", server.into(), dialer),
            ClientOptions::default(),
        );
        let addresses = resolver
            .lookup("example.com.", Default::default())
            .await
            .unwrap();
        assert_eq!(addresses[0].to_string(), "192.0.2.9");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn remote_resolver_preserves_raw_non_address_responses() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut bytes = [0_u8; 1024];
            let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request =
                Message::read(&mut BinDecoder::new(&bytes[..size])).unwrap();
            let mut response = Message::new(
                request.metadata.id,
                MessageType::Response,
                OpCode::Query,
            );
            response.queries = request.queries.clone();
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                123,
                RData::TXT(TXT::new(vec!["raw-response".into()])),
            ));
            let mut output = Vec::new();
            response.emit(&mut BinEncoder::new(&mut output)).unwrap();
            socket.send_to(&output, peer).await.unwrap();
        });
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let resolver = RemoteResolver::new(
            UdpTransport::new("remote", server.into(), dialer),
            ClientOptions::default(),
        );
        let mut request = Message::new(77, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            "example.com.".parse().unwrap(),
            RecordType::TXT,
        ));
        let response = resolver.exchange(&request).await.unwrap();
        assert_eq!(response.metadata.id, 77);
        assert_eq!(response.answers[0].ttl, 123);
        assert!(matches!(&response.answers[0].data, RData::TXT(_)));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_transport_uses_dns_length_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for _ in 0..2 {
                let size = stream.read_u16().await.unwrap() as usize;
                let mut bytes = vec![0_u8; size];
                stream.read_exact(&mut bytes).await.unwrap();
                let request =
                    Message::read(&mut BinDecoder::new(&bytes)).unwrap();
                let output = answer(&request, false);
                stream.write_u16(output.len() as u16).await.unwrap();
                stream.write_all(&output).await.unwrap();
            }
        });
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let transport = TcpTransport::new("remote", server.into(), dialer);
        transport.assume_reuse_supported();
        let resolver = RemoteResolver::new(transport, ClientOptions::default());
        let addresses = resolver
            .lookup("example.com.", Default::default())
            .await
            .unwrap();
        assert_eq!(addresses[0].to_string(), "192.0.2.9");
        drop(resolver);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_transport_multiplexes_out_of_order_responses_by_query_id() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut responses = Vec::new();
            for _ in 0..2 {
                let size = stream.read_u16().await.unwrap() as usize;
                let mut bytes = vec![0_u8; size];
                stream.read_exact(&mut bytes).await.unwrap();
                let request =
                    Message::read(&mut BinDecoder::new(&bytes)).unwrap();
                responses.push(answer(&request, false));
            }
            for response in responses.into_iter().rev() {
                stream.write_u16(response.len() as u16).await.unwrap();
                stream.write_all(&response).await.unwrap();
            }
        });
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let transport = TcpTransport::new("remote", server.into(), dialer);
        transport.assume_reuse_supported();
        let mut first = Message::new(501, MessageType::Query, OpCode::Query);
        first.add_query(Query::query(
            "first.example.".parse().unwrap(),
            RecordType::A,
        ));
        let mut second = Message::new(502, MessageType::Query, OpCode::Query);
        second.add_query(Query::query(
            "second.example.".parse().unwrap(),
            RecordType::A,
        ));
        let (first_response, second_response) = tokio::join!(
            transport.exchange(&first),
            transport.exchange(&second)
        );
        let first_response = first_response.unwrap();
        let second_response = second_response.unwrap();
        assert_eq!(first_response.metadata.id, 501);
        assert_eq!(second_response.metadata.id, 502);
        assert_eq!(first_response.queries[0].name(), first.queries[0].name());
        assert_eq!(second_response.queries[0].name(), second.queries[0].name());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_transport_probes_before_enabling_connection_reuse() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_server = accepted.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                accepted_server.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    loop {
                        let Ok(size) = stream.read_u16().await else {
                            return;
                        };
                        let mut bytes = vec![0_u8; size as usize];
                        if stream.read_exact(&mut bytes).await.is_err() {
                            return;
                        }
                        let request =
                            Message::read(&mut BinDecoder::new(&bytes))
                                .unwrap();
                        let response = answer(&request, false);
                        if stream
                            .write_u16(response.len() as u16)
                            .await
                            .is_err()
                            || stream.write_all(&response).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let transport = TcpTransport::new("remote", server.into(), dialer);
        let mut request = Message::new(701, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            "example.com.".parse().unwrap(),
            RecordType::A,
        ));
        transport.exchange(&request).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !transport.reuse.supported() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let before = accepted.load(Ordering::Relaxed);
        let mut second = request.clone();
        second.metadata.id = 702;
        let (first_result, second_result) = tokio::join!(
            transport.exchange(&request),
            transport.exchange(&second)
        );
        first_result.unwrap();
        second_result.unwrap();
        assert_eq!(accepted.load(Ordering::Relaxed) - before, 1);
        let before_reset = accepted.load(Ordering::Relaxed);
        transport.reset().await;
        request.metadata.id = 707;
        transport.exchange(&request).await.unwrap();
        assert_eq!(accepted.load(Ordering::Relaxed) - before_reset, 1);
        task.abort();
    }

    #[tokio::test]
    async fn tcp_transport_keeps_one_query_per_connection_when_probe_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_server = accepted.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                accepted_server.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let Ok(size) = stream.read_u16().await else {
                        return;
                    };
                    let mut bytes = vec![0_u8; size as usize];
                    if stream.read_exact(&mut bytes).await.is_err() {
                        return;
                    }
                    let request =
                        Message::read(&mut BinDecoder::new(&bytes)).unwrap();
                    let response = answer(&request, false);
                    let _ = stream.write_u16(response.len() as u16).await;
                    let _ = stream.write_all(&response).await;
                });
            }
        });
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let transport = TcpTransport::new("remote", server.into(), dialer);
        let mut request = Message::new(703, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            "example.com.".parse().unwrap(),
            RecordType::A,
        ));
        transport.exchange(&request).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while transport.reuse.state.load(Ordering::Acquire)
                != super::REUSE_UNSUPPORTED
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let before = accepted.load(Ordering::Relaxed);
        for id in 704..707 {
            request.metadata.id = id;
            transport.exchange(&request).await.unwrap();
        }
        assert_eq!(accepted.load(Ordering::Relaxed) - before, 3);
        task.abort();
    }

    #[tokio::test]
    async fn tcp_transport_retries_read_error_on_a_reused_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let size = first.read_u16().await.unwrap() as usize;
            let mut bytes = vec![0_u8; size];
            first.read_exact(&mut bytes).await.unwrap();
            let request = Message::read(&mut BinDecoder::new(&bytes)).unwrap();
            let response = answer(&request, false);
            first.write_u16(response.len() as u16).await.unwrap();
            first.write_all(&response).await.unwrap();

            let size = first.read_u16().await.unwrap() as usize;
            let mut bytes = vec![0_u8; size];
            first.read_exact(&mut bytes).await.unwrap();
            drop(first);

            let (mut second, _) = listener.accept().await.unwrap();
            let size = second.read_u16().await.unwrap() as usize;
            let mut bytes = vec![0_u8; size];
            second.read_exact(&mut bytes).await.unwrap();
            let request = Message::read(&mut BinDecoder::new(&bytes)).unwrap();
            let response = answer(&request, false);
            second.write_u16(response.len() as u16).await.unwrap();
            second.write_all(&response).await.unwrap();
        });
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let transport = TcpTransport::new("remote", server.into(), dialer);
        transport.assume_reuse_supported();
        let mut request = Message::new(708, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            "first.example.".parse().unwrap(),
            RecordType::A,
        ));
        transport.exchange(&request).await.unwrap();
        request.metadata.id = 709;
        request.queries[0] =
            Query::query("second.example.".parse().unwrap(), RecordType::A);
        transport.exchange(&request).await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_transport_demotes_repeatedly_broken_reuse() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let server_accepted = accepted.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                server_accepted.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    for served in 0.. {
                        let Ok(size) = stream.read_u16().await else {
                            return;
                        };
                        let mut bytes = vec![0_u8; size as usize];
                        if stream.read_exact(&mut bytes).await.is_err() {
                            return;
                        }
                        if served >= 2 {
                            return;
                        }
                        let request =
                            Message::read(&mut BinDecoder::new(&bytes))
                                .unwrap();
                        let response = answer(&request, false);
                        if stream
                            .write_u16(response.len() as u16)
                            .await
                            .is_err()
                            || stream.write_all(&response).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let transport = TcpTransport::new("remote", server.into(), dialer);
        transport.assume_reuse_supported();
        let mut request = Message::new(730, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            "example.com.".parse().unwrap(),
            RecordType::A,
        ));
        for id in 730..737 {
            request.metadata.id = id;
            transport.exchange(&request).await.unwrap();
        }
        assert_eq!(
            transport.reuse.state.load(Ordering::Acquire),
            super::REUSE_UNSUPPORTED
        );

        let before = accepted.load(Ordering::Relaxed);
        for id in 737..740 {
            request.metadata.id = id;
            transport.exchange(&request).await.unwrap();
        }
        assert_eq!(accepted.load(Ordering::Relaxed) - before, 3);
        task.abort();
    }

    #[tokio::test]
    async fn tcp_query_timeout_invalidates_a_silent_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let server_accepted = accepted.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                server_accepted.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    loop {
                        let Ok(size) = stream.read_u16().await else {
                            return;
                        };
                        let mut bytes = vec![0_u8; size as usize];
                        if stream.read_exact(&mut bytes).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let transport = TcpTransport::new("remote", server.into(), dialer);
        transport.assume_reuse_supported();
        let mut request = Message::new(710, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            "silent.example.".parse().unwrap(),
            RecordType::A,
        ));

        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                transport.exchange(&request),
            )
            .await
            .is_err()
        );
        request.metadata.id = 711;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                transport.exchange(&request),
            )
            .await
            .is_err()
        );
        assert_eq!(accepted.load(Ordering::Relaxed), 2);
        task.abort();
    }

    #[tokio::test]
    async fn slow_query_timeout_keeps_a_connection_with_newer_responses() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let server_accepted = accepted.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                server_accepted.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    loop {
                        let Ok(size) = stream.read_u16().await else {
                            return;
                        };
                        let mut bytes = vec![0_u8; size as usize];
                        if stream.read_exact(&mut bytes).await.is_err() {
                            return;
                        }
                        let request =
                            Message::read(&mut BinDecoder::new(&bytes))
                                .unwrap();
                        if request.queries[0].name().to_ascii()
                            == "slow.example."
                        {
                            continue;
                        }
                        let response = answer(&request, false);
                        if stream
                            .write_u16(response.len() as u16)
                            .await
                            .is_err()
                            || stream.write_all(&response).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let transport =
            Arc::new(TcpTransport::new("remote", server.into(), dialer));
        transport.assume_reuse_supported();

        let slow_transport = transport.clone();
        let mut slow = Message::new(720, MessageType::Query, OpCode::Query);
        slow.add_query(Query::query(
            "slow.example.".parse().unwrap(),
            RecordType::A,
        ));
        let slow_task = tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_millis(300),
                slow_transport.exchange(&slow),
            )
            .await
        });

        for id in 721..727 {
            let mut fast = Message::new(id, MessageType::Query, OpCode::Query);
            fast.add_query(Query::query(
                "fast.example.".parse().unwrap(),
                RecordType::A,
            ));
            tokio::time::timeout(
                Duration::from_millis(200),
                transport.exchange(&fast),
            )
            .await
            .unwrap()
            .unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        assert!(slow_task.await.unwrap().is_err());

        let mut final_request =
            Message::new(727, MessageType::Query, OpCode::Query);
        final_request.add_query(Query::query(
            "fast.example.".parse().unwrap(),
            RecordType::A,
        ));
        transport.exchange(&final_request).await.unwrap();
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
        task.abort();
    }

    #[tokio::test]
    async fn truncated_udp_response_retries_over_tcp() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(server).await.unwrap();
        let udp_task = tokio::spawn(async move {
            for _ in 0..2 {
                let mut bytes = [0_u8; 1024];
                let (size, peer) = udp.recv_from(&mut bytes).await.unwrap();
                let request =
                    Message::read(&mut BinDecoder::new(&bytes[..size]))
                        .unwrap();
                let output = answer(&request, true);
                udp.send_to(&output, peer).await.unwrap();
            }
        });
        let tcp_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = tcp.accept().await.unwrap();
                let size = stream.read_u16().await.unwrap() as usize;
                let mut bytes = vec![0_u8; size];
                stream.read_exact(&mut bytes).await.unwrap();
                let request =
                    Message::read(&mut BinDecoder::new(&bytes)).unwrap();
                let output = answer(&request, false);
                stream.write_u16(output.len() as u16).await.unwrap();
                stream.write_all(&output).await.unwrap();
            }
        });
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let resolver = RemoteResolver::new(
            UdpTransport::new("remote", server.into(), dialer),
            ClientOptions::default(),
        );
        let addresses = resolver
            .lookup("example.com.", Default::default())
            .await
            .unwrap();
        assert_eq!(addresses[0].to_string(), "192.0.2.9");
        udp_task.await.unwrap();
        tcp_task.await.unwrap();
    }

    #[tokio::test]
    async fn tls_transport_uses_dns_over_tls_framing() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            for _ in 0..2 {
                let size = stream.read_u16().await.unwrap() as usize;
                let mut bytes = vec![0_u8; size];
                stream.read_exact(&mut bytes).await.unwrap();
                let request =
                    Message::read(&mut BinDecoder::new(&bytes)).unwrap();
                let output = answer(&request, false);
                stream.write_u16(output.len() as u16).await.unwrap();
                stream.write_all(&output).await.unwrap();
            }
        });
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let transport = TlsTransport::new("remote", server.into(), dialer, tls);
        transport.assume_reuse_supported();
        let resolver = RemoteResolver::new(transport, ClientOptions::default());
        let addresses = resolver
            .lookup("example.com.", Default::default())
            .await
            .unwrap();
        assert_eq!(addresses[0].to_string(), "192.0.2.9");
        drop(resolver);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn tls_transport_multiplexes_out_of_order_responses_by_query_id() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut responses = Vec::new();
            for _ in 0..2 {
                let size = stream.read_u16().await.unwrap() as usize;
                let mut bytes = vec![0_u8; size];
                stream.read_exact(&mut bytes).await.unwrap();
                let request =
                    Message::read(&mut BinDecoder::new(&bytes)).unwrap();
                responses.push(answer(&request, false));
            }
            for response in responses.into_iter().rev() {
                stream.write_u16(response.len() as u16).await.unwrap();
                stream.write_all(&response).await.unwrap();
            }
        });
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let transport = TlsTransport::new("remote", server.into(), dialer, tls);
        transport.assume_reuse_supported();
        let mut first = Message::new(601, MessageType::Query, OpCode::Query);
        first.add_query(Query::query(
            "first.example.".parse().unwrap(),
            RecordType::A,
        ));
        let mut second = Message::new(602, MessageType::Query, OpCode::Query);
        second.add_query(Query::query(
            "second.example.".parse().unwrap(),
            RecordType::A,
        ));
        let (first_response, second_response) = tokio::join!(
            transport.exchange(&first),
            transport.exchange(&second)
        );
        let first_response = first_response.unwrap();
        let second_response = second_response.unwrap();
        assert_eq!(first_response.metadata.id, 601);
        assert_eq!(second_response.metadata.id, 602);
        assert_eq!(first_response.queries[0].name(), first.queries[0].name());
        assert_eq!(second_response.queries[0].name(), second.queries[0].name());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn tls_transport_probes_before_enabling_connection_reuse() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_server = accepted.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let accepted = accepted_server.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    accepted.fetch_add(1, Ordering::Relaxed);
                    loop {
                        let Ok(size) = stream.read_u16().await else {
                            return;
                        };
                        let mut bytes = vec![0_u8; size as usize];
                        if stream.read_exact(&mut bytes).await.is_err() {
                            return;
                        }
                        let request =
                            Message::read(&mut BinDecoder::new(&bytes))
                                .unwrap();
                        let response = answer(&request, false);
                        if stream
                            .write_u16(response.len() as u16)
                            .await
                            .is_err()
                            || stream.write_all(&response).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let transport = TlsTransport::new("remote", server.into(), dialer, tls);
        let mut request = Message::new(801, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            "example.com.".parse().unwrap(),
            RecordType::A,
        ));
        transport.exchange(&request).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !transport.reuse.supported() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let before = accepted.load(Ordering::Relaxed);
        let mut second = request.clone();
        second.metadata.id = 802;
        let (first_result, second_result) = tokio::join!(
            transport.exchange(&request),
            transport.exchange(&second)
        );
        first_result.unwrap();
        second_result.unwrap();
        assert_eq!(accepted.load(Ordering::Relaxed) - before, 1);
        let before_reset = accepted.load(Ordering::Relaxed);
        transport.reset().await;
        request.metadata.id = 803;
        transport.exchange(&request).await.unwrap();
        assert_eq!(accepted.load(Ordering::Relaxed) - before_reset, 1);
        task.abort();
    }

    #[tokio::test]
    async fn quic_transport_uses_doq_stream_framing() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        server_config.alpn_protocols = vec![b"doq".to_vec()];
        let endpoint = server_endpoint(
            ServerTlsConfig {
                config: Arc::new(server_config),
                handshake_timeout: None,
                reality: None,
                kernel_tx: false,
                kernel_rx: false,
            },
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server = endpoint.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            for _ in 0..2 {
                let (mut send, mut receive) =
                    connection.accept_bi().await.unwrap();
                let size = receive.read_u16().await.unwrap() as usize;
                let mut bytes = vec![0_u8; size];
                receive.read_exact(&mut bytes).await.unwrap();
                let request =
                    Message::read(&mut BinDecoder::new(&bytes)).unwrap();
                let output = answer(&request, false);
                send.write_u16(output.len() as u16).await.unwrap();
                send.write_all(&output).await.unwrap();
                send.shutdown().await.unwrap();
            }
        });
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &["doq"],
        )
        .unwrap();
        let dialer =
            Arc::new(QuicDialer::new(server.into(), "localhost", tls).unwrap());
        let resolver = RemoteResolver::new(
            QuicTransport::new("remote", server.into(), dialer),
            ClientOptions::default(),
        );
        let addresses = resolver
            .lookup("example.com.", Default::default())
            .await
            .unwrap();
        assert_eq!(addresses[0].to_string(), "192.0.2.9");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn http3_transport_posts_dns_messages_and_reuses_connection() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        server_config.alpn_protocols = vec![b"h3".to_vec()];
        let endpoint = server_endpoint(
            ServerTlsConfig {
                config: Arc::new(server_config),
                handshake_timeout: None,
                reality: None,
                kernel_tx: false,
                kernel_rx: false,
            },
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server = endpoint.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let mut http3 = h3::server::Connection::new(
                h3_quinn::Connection::new(connection),
            )
            .await
            .unwrap();
            for _ in 0..2 {
                let resolver = http3.accept().await.unwrap().unwrap();
                let (request, mut stream) =
                    resolver.resolve_request().await.unwrap();
                assert_eq!(request.method(), hyper::Method::POST);
                assert_eq!(request.uri().path(), "/dns-query");
                assert_eq!(
                    request.headers()[CONTENT_TYPE],
                    "application/dns-message"
                );
                let mut wire = Vec::new();
                while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                    wire.extend_from_slice(
                        &chunk.copy_to_bytes(chunk.remaining()),
                    );
                }
                let request =
                    Message::read(&mut BinDecoder::new(&wire)).unwrap();
                assert_eq!(request.metadata.id, 0);
                let output = answer(&request, false);
                stream
                    .send_response(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/dns-message")
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                stream.send_data(Bytes::from(output)).await.unwrap();
                stream.finish().await.unwrap();
            }
        });
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &["h3"],
        )
        .unwrap();
        let transport = Http3Transport::new(
            "remote",
            server.into(),
            "localhost",
            tls,
            format!("https://localhost:{}/dns-query", server.port()),
            HeaderMap::new(),
            None,
        )
        .unwrap();
        let resolver = RemoteResolver::new(transport, ClientOptions::default());
        let addresses = resolver
            .lookup("example.com.", Default::default())
            .await
            .unwrap();
        assert_eq!(addresses[0].to_string(), "192.0.2.9");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn https_transport_sends_http2_dns_messages() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let server_active = active.clone();
        let server_max_active = max_active.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(
                        move |request: hyper::Request<
                            hyper::body::Incoming,
                        >| {
                            let active = server_active.clone();
                            let max_active = server_max_active.clone();
                            async move {
                                let current =
                                    active.fetch_add(1, Ordering::SeqCst) + 1;
                                max_active.fetch_max(current, Ordering::SeqCst);
                                tokio::time::sleep(Duration::from_millis(40))
                                    .await;
                                active.fetch_sub(1, Ordering::SeqCst);
                                assert_eq!(request.uri().path(), "/dns-query");
                                assert_eq!(
                                    request.headers()["x-test"],
                                    "value"
                                );
                                let payload = request
                                    .into_body()
                                    .collect()
                                    .await
                                    .unwrap()
                                    .to_bytes();
                                let request = Message::read(
                                    &mut BinDecoder::new(&payload),
                                )
                                .unwrap();
                                assert_eq!(request.metadata.id, 0);
                                Ok::<_, std::convert::Infallible>(
                                    Response::new(Full::new(Bytes::from(
                                        answer(&request, false),
                                    ))),
                                )
                            }
                        },
                    ),
                )
                .await
                .unwrap();
        });
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &["h2", "http/1.1"],
        )
        .unwrap();
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let mut headers = HeaderMap::new();
        headers.insert("x-test", "value".parse().unwrap());
        let resolver = RemoteResolver::new(
            HttpsTransport::new(
                "remote",
                server.into(),
                dialer,
                tls,
                format!("https://localhost:{}/dns-query", server.port()),
                headers,
            ),
            ClientOptions::default(),
        );
        let addresses = resolver
            .lookup("example.com.", Default::default())
            .await
            .unwrap();
        assert_eq!(addresses[0].to_string(), "192.0.2.9");
        assert_eq!(max_active.load(Ordering::SeqCst), 2);
        drop(resolver);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn https_transport_falls_back_to_http1() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(
                            |request: hyper::Request<hyper::body::Incoming>| async move {
                                let payload = request
                                    .into_body()
                                    .collect()
                                    .await
                                    .unwrap()
                                    .to_bytes();
                                let request = Message::read(
                                    &mut BinDecoder::new(&payload),
                                )
                                .unwrap();
                                Ok::<_, std::convert::Infallible>(
                                    Response::new(Full::new(Bytes::from(
                                        answer(&request, false),
                                    ))),
                                )
                            },
                        ),
                    )
                    .await
                    .unwrap();
        });
        let tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &["h2", "http/1.1"],
        )
        .unwrap();
        let dialer =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let resolver = RemoteResolver::new(
            HttpsTransport::new(
                "remote",
                server.into(),
                dialer,
                tls,
                format!("https://localhost:{}/dns-query", server.port()),
                HeaderMap::new(),
            ),
            ClientOptions::default(),
        );
        let addresses = resolver
            .lookup("example.com.", Default::default())
            .await
            .unwrap();
        assert_eq!(addresses[0].to_string(), "192.0.2.9");
        drop(resolver);
        task.await.unwrap();
    }

    #[test]
    fn sets_edns_client_subnet_without_discarding_edns() {
        let mut message = Message::query();
        message.add_query(hickory_proto::op::Query::query(
            "example.com.".parse().unwrap(),
            RecordType::A,
        ));
        set_client_subnet(&mut message, "203.0.113.7/24".parse().unwrap());
        let option = message
            .edns
            .as_ref()
            .unwrap()
            .option(EdnsCode::Subnet)
            .unwrap();
        let EdnsOption::Subnet(subnet) = option else {
            panic!("unexpected EDNS option")
        };
        assert_eq!(subnet.addr().to_string(), "203.0.113.7");
        assert_eq!(subnet.source_prefix(), 24);
    }

    fn answer(request: &Message, truncated: bool) -> Vec<u8> {
        let mut response = Message::new(
            request.metadata.id,
            MessageType::Response,
            OpCode::Query,
        );
        response.metadata.truncation = truncated;
        response.queries = request.queries.clone();
        if !truncated && request.queries[0].query_type() == RecordType::A {
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::A(A::new(192, 0, 2, 9)),
            ));
        }
        let mut output = Vec::new();
        response.emit(&mut BinEncoder::new(&mut output)).unwrap();
        output
    }
}
