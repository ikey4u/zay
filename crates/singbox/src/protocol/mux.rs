//! SagerNet sing-mux framing and the default HTTP/2 multiplex transport.

use std::{
    convert::Infallible,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use http_body_util::Empty;
use hyper::{
    Request, Response, StatusCode, body::Incoming,
    client::conn::http2 as client_http2, server::conn::http2 as server_http2,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf,
    },
    sync::{Mutex, mpsc, oneshot},
};
use tokio_util::compat::{
    FuturesAsyncReadCompatExt as _, TokioAsyncReadCompatExt as _,
};
use tokio_util::sync::CancellationToken;

use n0_watcher::Watcher as _;

use crate::{
    adapter::{
        DialFuture, Dialer, PacketConnection, PacketFuture, PacketStream,
        Stream, stream_socket,
    },
    common::network::SocksAddr,
    inbound::{
        TcpInboundContext, inherited_tcp_metadata, prepare_tcp_inbound_detour,
        reject_udp_inbound_detour,
        socks::{proxy_packet_connection, restore_fake_ip},
    },
    option::OutboundMultiplexOptions,
    outbound::OutboundManager,
    protocol::socks::{read_address, write_address},
    route::{Action, Metadata, Router},
};

pub const DESTINATION_HOST: &str = "sp.mux.sing-box.arpa";
pub const DESTINATION_PORT: u16 = 444;
pub const BRUTAL_EXCHANGE_DOMAIN: &str = "_BrutalBwExchange";
pub const BRUTAL_MIN_SPEED_BPS: u64 = 65_536;
const MBPS_TO_BPS: u64 = 125_000;

const VERSION_0: u8 = 0;
const VERSION_1: u8 = 1;
const PROTOCOL_SMUX: u8 = 0;
const PROTOCOL_YAMUX: u8 = 1;
const PROTOCOL_H2MUX: u8 = 2;
const FLAG_UDP: u16 = 1;
const FLAG_PACKET_ADDR: u16 = 2;
const STATUS_SUCCESS: u8 = 0;
const STATUS_ERROR: u8 = 1;

/// Write the sing-mux TCP Brutal receive-rate request. The Go implementation
/// uses a single network-byte-order uint64 with no length prefix.
pub async fn write_brutal_request<W>(
    writer: &mut W,
    receive_bps: u64,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    writer.write_u64(receive_bps).await
}

pub async fn read_brutal_request<R>(reader: &mut R) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
{
    reader.read_u64().await
}

/// Write the Go-compatible Brutal response: a one-byte bool followed by either
/// a big-endian uint64 or a Go `binary.Uvarint` length-prefixed error string.
pub async fn write_brutal_response<W>(
    writer: &mut W,
    receive_bps: u64,
    result: Result<(), &str>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    match result {
        Ok(()) => {
            writer.write_u8(1).await?;
            writer.write_u64(receive_bps).await?;
        }
        Err(message) => {
            writer.write_u8(0).await?;
            write_uvarint(writer, message.len() as u64).await?;
            writer.write_all(message.as_bytes()).await?;
        }
    }
    writer.flush().await
}

pub async fn read_brutal_response<R>(reader: &mut R) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
{
    match reader.read_u8().await? {
        1 => reader.read_u64().await,
        0 => {
            let length =
                usize::try_from(read_uvarint(reader).await?).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "error is too long",
                    )
                })?;
            let mut message = vec![0; length];
            reader.read_exact(&mut message).await?;
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("remote error: {}", String::from_utf8_lossy(&message)),
            ))
        }
        value => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid sing-mux Brutal response flag: {value}"),
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrutalRuntimeOptions {
    pub send_bps: u64,
    pub receive_bps: u64,
}

impl BrutalRuntimeOptions {
    pub fn from_options(
        options: Option<&crate::option::BrutalOptions>,
    ) -> io::Result<Option<Self>> {
        let Some(options) = options.filter(|options| options.enabled) else {
            return Ok(None);
        };
        let send_bps = u64::try_from(options.up_mbps)
            .ok()
            .and_then(|value| value.checked_mul(MBPS_TO_BPS))
            .filter(|value| *value >= BRUTAL_MIN_SPEED_BPS)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "brutal: invalid upload speed",
                )
            })?;
        let receive_bps = u64::try_from(options.down_mbps)
            .ok()
            .and_then(|value| value.checked_mul(MBPS_TO_BPS))
            .filter(|value| *value >= BRUTAL_MIN_SPEED_BPS)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "brutal: invalid download speed",
                )
            })?;
        Ok(Some(Self {
            send_bps,
            receive_bps,
        }))
    }
}

pub fn server_brutal_options(
    options: Option<&crate::option::BrutalOptions>,
) -> io::Result<Option<BrutalRuntimeOptions>> {
    let options = BrutalRuntimeOptions::from_options(options)?;
    if options.is_some()
        && !cfg!(target_os = "linux")
        && !cfg!(debug_assertions)
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP Brutal is only supported on Linux",
        ));
    }
    Ok(options)
}

type BrutalSocket = crate::adapter::StreamSocket;

#[cfg(target_os = "linux")]
fn set_brutal_options(
    socket: Option<BrutalSocket>,
    send_bps: u64,
) -> io::Result<()> {
    const TCP_BRUTAL_PARAMS: libc::c_int = 23_301;
    #[repr(C)]
    struct TcpBrutalParams {
        rate: u64,
        cwnd_gain: u32,
    }

    let socket = socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "brutal: nested multiplexing is not supported: no physical TCP socket",
        )
    })?;
    let algorithm = b"brutal";
    // SAFETY: `socket` is a live TCP file descriptor supplied by the transport;
    // both pointed-to values remain valid for the duration of each syscall.
    let result = unsafe {
        libc::setsockopt(
            socket,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            algorithm.as_ptr().cast(),
            algorithm.len() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "setsockopt IPPROTO_TCP TCP_CONGESTION brutal: {}; please make sure the tcp-brutal kernel module is installed",
                io::Error::last_os_error()
            ),
        ));
    }
    let params = TcpBrutalParams {
        rate: send_bps,
        cwnd_gain: 20,
    };
    // SAFETY: the kernel module expects the C layout mirrored above and the
    // pointer/length pair describes exactly one initialized value.
    let result = unsafe {
        libc::setsockopt(
            socket,
            libc::IPPROTO_TCP,
            TCP_BRUTAL_PARAMS,
            std::ptr::from_ref(&params).cast(),
            std::mem::size_of::<TcpBrutalParams>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "setsockopt IPPROTO_TCP TCP_BRUTAL_PARAMS: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_brutal_options(
    _socket: Option<BrutalSocket>,
    _send_bps: u64,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP Brutal is only supported on Linux",
    ))
}

struct BrutalServerState {
    options: BrutalRuntimeOptions,
    socket: Option<BrutalSocket>,
}

impl BrutalServerState {
    async fn exchange(&self, stream: &mut Stream) -> io::Result<()> {
        let client_receive_bps = read_brutal_request(stream).await?;
        let send_bps = self.options.send_bps.min(client_receive_bps);
        if let Err(error) = set_brutal_options(self.socket, send_bps)
            && !cfg!(debug_assertions)
        {
            let message = format!("enable TCP Brutal: {error}");
            write_brutal_response(stream, 0, Err(&message)).await?;
            return Ok(());
        }
        write_brutal_response(stream, self.options.receive_bps, Ok(())).await
    }
}

pub fn destination() -> SocksAddr {
    SocksAddr::new(DESTINATION_HOST, DESTINATION_PORT)
}

pub fn is_destination(value: &SocksAddr) -> bool {
    matches!(value, SocksAddr::Domain { host, port } if host == DESTINATION_HOST && *port == DESTINATION_PORT)
}

type Body = Empty<Bytes>;
pub type HandlerFuture =
    Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'static>>;
pub type TcpHandler =
    Arc<dyn Fn(Stream, SocksAddr) -> HandlerFuture + Send + Sync>;
pub type UdpHandler =
    Arc<dyn Fn(PacketStream, SocksAddr) -> HandlerFuture + Send + Sync>;

pub struct MuxClient {
    upstream: Arc<dyn Dialer>,
    options: OutboundMultiplexOptions,
    sessions: Arc<Mutex<Vec<Arc<ClientSession>>>>,
    network_monitor_started: Arc<AtomicBool>,
    cancellation: CancellationToken,
    brutal: Option<BrutalRuntimeOptions>,
}

impl MuxClient {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        options: OutboundMultiplexOptions,
    ) -> io::Result<Self> {
        if !matches!(options.protocol.as_str(), "" | "h2mux" | "smux" | "yamux")
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "sing-mux protocol {:?} is not ported yet",
                    options.protocol
                ),
            ));
        }
        let brutal =
            BrutalRuntimeOptions::from_options(options.brutal.as_ref())?;
        if options.max_connections < 0
            || options.min_streams < 0
            || options.max_streams < 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sing-mux stream and connection limits cannot be negative",
            ));
        }
        Ok(Self {
            upstream,
            options,
            sessions: Arc::new(Mutex::new(Vec::new())),
            network_monitor_started: Arc::new(AtomicBool::new(false)),
            cancellation: CancellationToken::new(),
            brutal,
        })
    }

    async fn open_stream(&self) -> io::Result<Stream> {
        self.ensure_network_monitor();
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|session| !session.closed());
        let selected = sessions
            .iter()
            .filter(|session| session.can_open())
            .min_by_key(|session| session.active())
            .cloned();
        let selected = if let Some(session) = selected {
            if self.brutal.is_some() {
                drop(sessions);
                return session.open().await;
            }
            let active = session.active() as i32;
            let connection_limit_reached = self.options.max_connections > 0
                && sessions.len() >= self.options.max_connections as usize;
            let should_reuse = active == 0
                || connection_limit_reached
                || (self.options.max_connections > 0
                    && active < self.options.min_streams)
                || (self.options.max_connections == 0
                    && self.options.max_streams > 0
                    && active < self.options.max_streams);
            if should_reuse {
                session
            } else {
                let session = self.new_session().await?;
                sessions.push(session.clone());
                session
            }
        } else {
            let session = self.new_session().await?;
            sessions.push(session.clone());
            session
        };
        drop(sessions);
        selected.open().await
    }

    /// Close all physical multiplex sessions. This is the direct counterpart
    /// of `sing-mux.Client.Reset` and is also invoked after a major interface
    /// or default-route change.
    pub async fn reset(&self) {
        close_sessions(&self.sessions).await;
    }

    fn ensure_network_monitor(&self) {
        if self
            .network_monitor_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let sessions = self.sessions.clone();
        let cancellation = self.cancellation.clone();
        let started = self.network_monitor_started.clone();
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
                    _ = cancellation.cancelled() => break,
                    current = watcher.updated() => match current {
                        Ok(current) => current,
                        Err(_) => break,
                    },
                };
                if current.is_major_change(&previous) {
                    close_sessions(&sessions).await;
                }
                previous = current;
            }
        });
    }

    async fn new_session(&self) -> io::Result<Arc<ClientSession>> {
        let mut stream = self.upstream.dial_tcp(&destination()).await?;
        let brutal_socket = stream_socket(&stream);
        let protocol = match self.options.protocol.as_str() {
            "smux" => PROTOCOL_SMUX,
            "yamux" => PROTOCOL_YAMUX,
            _ => PROTOCOL_H2MUX,
        };
        if self.options.padding {
            let padding_length = random_padding_length()?;
            stream.write_all(&[VERSION_1, protocol, 1]).await?;
            stream.write_u16(padding_length).await?;
            stream
                .write_all(&vec![0; usize::from(padding_length)])
                .await?;
        } else {
            stream.write_all(&[VERSION_0, protocol]).await?;
        }
        stream.flush().await?;
        let stream = if self.options.padding {
            padding_stream(stream)
        } else {
            stream
        };
        let session = match protocol {
            PROTOCOL_SMUX => {
                ClientSession::Smux(SmuxClientSession::new(stream).await?)
            }
            PROTOCOL_YAMUX => {
                ClientSession::Yamux(YamuxClientSession::new(stream))
            }
            _ => ClientSession::H2(H2ClientSession::new(stream).await?),
        };
        if let Some(brutal) = self.brutal {
            let mut exchange = session.open().await?;
            write_stream_request(
                &mut exchange,
                false,
                false,
                &SocksAddr::new(BRUTAL_EXCHANGE_DOMAIN, 0),
            )
            .await?;
            write_brutal_request(&mut exchange, brutal.receive_bps).await?;
            exchange.flush().await?;
            let server_receive_bps =
                read_brutal_response(&mut exchange).await?;
            let _ = exchange.shutdown().await;
            // The client side intentionally treats kernel activation as best
            // effort, matching sing-mux. The server's response still governs
            // whether the negotiated session may be used.
            let _ = set_brutal_options(
                brutal_socket,
                brutal.send_bps.min(server_receive_bps),
            );
        }
        Ok(Arc::new(session))
    }
}

impl Drop for MuxClient {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl Dialer for MuxClient {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let mut mux_stream = self.open_stream().await?;
            write_stream_request(&mut mux_stream, false, false, destination)
                .await?;
            let (application, bridge) = tokio::io::duplex(32 * 1024);
            tokio::spawn(client_tcp_bridge(bridge, mux_stream));
            Ok(Box::new(application) as Stream)
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let mut stream = self.open_stream().await?;
            write_stream_request(&mut stream, true, true, destination).await?;
            Ok(Box::new(MuxPacketConnection::new(
                stream,
                true,
                destination.clone(),
                true,
            )) as PacketStream)
        })
    }
}

struct H2ClientSession {
    sender: Mutex<client_http2::SendRequest<Body>>,
    active: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    cancellation: CancellationToken,
}

enum ClientSession {
    H2(H2ClientSession),
    Smux(SmuxClientSession),
    Yamux(YamuxClientSession),
}

impl ClientSession {
    fn active(&self) -> usize {
        match self {
            Self::H2(session) => session.active(),
            Self::Smux(session) => session.active(),
            Self::Yamux(session) => session.active(),
        }
    }

    fn closed(&self) -> bool {
        match self {
            Self::H2(session) => session.closed(),
            Self::Smux(session) => session.closed(),
            Self::Yamux(session) => session.closed(),
        }
    }

    fn can_open(&self) -> bool {
        !self.closed()
    }

    async fn open(&self) -> io::Result<Stream> {
        match self {
            Self::H2(session) => session.open().await,
            Self::Smux(session) => session.open().await,
            Self::Yamux(session) => session.open().await,
        }
    }

    async fn close(&self) {
        match self {
            Self::H2(session) => session.cancellation.cancel(),
            Self::Smux(session) => {
                let _ = session.session.close().await;
            }
            Self::Yamux(session) => session.cancellation.cancel(),
        }
    }
}

async fn close_sessions(sessions: &Mutex<Vec<Arc<ClientSession>>>) {
    let sessions = {
        let mut guard = sessions.lock().await;
        std::mem::take(&mut *guard)
    };
    for session in sessions {
        session.close().await;
    }
}

type YamuxOpenResult = io::Result<yamux::Stream>;

struct YamuxClientSession {
    requests: mpsc::Sender<oneshot::Sender<YamuxOpenResult>>,
    active: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    cancellation: CancellationToken,
}

impl YamuxClientSession {
    fn new(stream: Stream) -> Self {
        let (requests, mut receiver) =
            mpsc::channel::<oneshot::Sender<YamuxOpenResult>>(32);
        let closed = Arc::new(AtomicUsize::new(0));
        let driver_closed = closed.clone();
        let cancellation = CancellationToken::new();
        let driver_cancellation = cancellation.clone();
        tokio::spawn(async move {
            let mut connection = yamux::Connection::new(
                stream.compat(),
                yamux::Config::default(),
                yamux::Mode::Client,
            );
            loop {
                tokio::select! {
                    _ = driver_cancellation.cancelled() => break,
                    request = receiver.recv() => {
                        let Some(request) = request else { break };
                        let result = poll_fn(|cx| connection.poll_new_outbound(cx))
                            .await
                            .map_err(io::Error::other);
                        let _ = request.send(result);
                    }
                    inbound = poll_fn(|cx| connection.poll_next_inbound(cx)) => {
                        match inbound {
                            Some(Ok(stream)) => drop(stream),
                            Some(Err(_)) | None => break,
                        }
                    }
                }
            }
            driver_closed.store(1, Ordering::Release);
        });
        Self {
            requests,
            active: Arc::new(AtomicUsize::new(0)),
            closed,
            cancellation,
        }
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) != 0
    }

    async fn open(&self) -> io::Result<Stream> {
        let (send, receive) = oneshot::channel();
        self.requests.send(send).await.map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "yamux session closed")
        })?;
        let stream = receive.await.map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "yamux session closed")
        })??;
        self.active.fetch_add(1, Ordering::AcqRel);
        Ok(Box::new(CountedStream {
            inner: stream.compat(),
            active: self.active.clone(),
        }))
    }
}

struct SmuxClientSession {
    session: smux::Session,
    active: Arc<AtomicUsize>,
}

impl SmuxClientSession {
    async fn new(stream: Stream) -> io::Result<Self> {
        let session =
            smux::Session::client(SyncStream::new(stream), smux_config())
                .await
                .map_err(io::Error::other)?;
        Ok(Self {
            session,
            active: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    fn closed(&self) -> bool {
        self.session.is_closed()
    }

    async fn open(&self) -> io::Result<Stream> {
        let stream =
            self.session.open_stream().await.map_err(io::Error::other)?;
        self.active.fetch_add(1, Ordering::AcqRel);
        Ok(Box::new(CountedStream {
            inner: stream,
            active: self.active.clone(),
        }))
    }
}

impl H2ClientSession {
    async fn new(stream: Stream) -> io::Result<Self> {
        let (sender, connection) =
            client_http2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(stream))
                .await
                .map_err(io::Error::other)?;
        let closed = Arc::new(AtomicUsize::new(0));
        let connection_closed = closed.clone();
        let cancellation = CancellationToken::new();
        let driver_cancellation = cancellation.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = driver_cancellation.cancelled() => {}
                _ = connection => {}
            }
            connection_closed.store(1, Ordering::Release);
        });
        Ok(Self {
            sender: Mutex::new(sender),
            active: Arc::new(AtomicUsize::new(0)),
            closed,
            cancellation,
        })
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) != 0
    }

    async fn open(&self) -> io::Result<Stream> {
        let request = Request::builder()
            .method("CONNECT")
            .uri("https://localhost")
            .body(Empty::new())
            .map_err(io::Error::other)?;
        let mut response = self
            .sender
            .lock()
            .await
            .send_request(request)
            .await
            .map_err(io::Error::other)?;
        if response.status() != StatusCode::OK {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("unexpected h2mux status: {}", response.status()),
            ));
        }
        let upgraded = hyper::upgrade::on(&mut response)
            .await
            .map_err(io::Error::other)?;
        self.active.fetch_add(1, Ordering::AcqRel);
        Ok(Box::new(CountedStream {
            inner: TokioIo::new(upgraded),
            active: self.active.clone(),
        }))
    }
}

pub async fn serve_h2mux(
    stream: Stream,
    tcp_handler: TcpHandler,
    udp_handler: UdpHandler,
) -> io::Result<()> {
    let eager_handler: TcpHandler = Arc::new(move |mut stream, destination| {
        let tcp_handler = tcp_handler.clone();
        Box::pin(async move {
            stream.write_u8(STATUS_SUCCESS).await?;
            stream.flush().await?;
            tcp_handler(stream, destination).await
        })
    });
    serve_h2mux_with_padding(stream, false, None, eager_handler, udp_handler)
        .await
}

async fn serve_h2mux_with_padding(
    mut stream: Stream,
    require_padding: bool,
    brutal_options: Option<BrutalRuntimeOptions>,
    tcp_handler: TcpHandler,
    udp_handler: UdpHandler,
) -> io::Result<()> {
    let brutal = brutal_options.map(|options| {
        Arc::new(BrutalServerState {
            options,
            socket: stream_socket(&stream),
        })
    });
    let version = stream.read_u8().await?;
    let protocol = stream.read_u8().await?;
    if !matches!(version, VERSION_0 | VERSION_1) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported sing-mux version: {version}"),
        ));
    }
    if !matches!(protocol, PROTOCOL_SMUX | PROTOCOL_YAMUX | PROTOCOL_H2MUX) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported sing-mux protocol: {protocol}"),
        ));
    }
    let padded = if version == VERSION_1 {
        let padded = stream.read_u8().await? != 0;
        if padded {
            let padding_length = stream.read_u16().await? as usize;
            let mut padding = vec![0; padding_length];
            stream.read_exact(&mut padding).await?;
        }
        padded
    } else {
        false
    };
    if require_padding && !padded {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "non-padded sing-mux connection rejected",
        ));
    }
    if padded {
        stream = padding_stream(stream);
    }
    if protocol == PROTOCOL_SMUX {
        return serve_smux_session(stream, brutal, tcp_handler, udp_handler)
            .await;
    }
    if protocol == PROTOCOL_YAMUX {
        return serve_yamux_session(stream, brutal, tcp_handler, udp_handler)
            .await;
    }
    let service = service_fn(move |mut request: Request<Incoming>| {
        let tcp_handler = tcp_handler.clone();
        let udp_handler = udp_handler.clone();
        let brutal = brutal.clone();
        async move {
            if request.method() != "CONNECT" {
                return Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::METHOD_NOT_ALLOWED)
                        .body(empty_body())
                        .expect("fixed h2mux rejection"),
                );
            }
            tokio::spawn(async move {
                if let Ok(upgraded) = hyper::upgrade::on(&mut request).await {
                    let _ = dispatch_server_stream(
                        Box::new(TokioIo::new(upgraded)),
                        brutal,
                        tcp_handler,
                        udp_handler,
                    )
                    .await;
                }
            });
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Empty::new())
                    .expect("fixed h2mux response"),
            )
        }
    });
    server_http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await
        .map_err(io::Error::other)
}

async fn serve_smux_session(
    stream: Stream,
    brutal: Option<Arc<BrutalServerState>>,
    tcp_handler: TcpHandler,
    udp_handler: UdpHandler,
) -> io::Result<()> {
    let session = smux::Session::server(SyncStream::new(stream), smux_config())
        .await
        .map_err(io::Error::other)?;
    loop {
        let stream = session.accept_stream().await.map_err(io::Error::other)?;
        let tcp_handler = tcp_handler.clone();
        let udp_handler = udp_handler.clone();
        let brutal = brutal.clone();
        tokio::spawn(async move {
            let _ = dispatch_server_stream(
                Box::new(stream),
                brutal,
                tcp_handler,
                udp_handler,
            )
            .await;
        });
    }
}

async fn serve_yamux_session(
    stream: Stream,
    brutal: Option<Arc<BrutalServerState>>,
    tcp_handler: TcpHandler,
    udp_handler: UdpHandler,
) -> io::Result<()> {
    let mut connection = yamux::Connection::new(
        stream.compat(),
        yamux::Config::default(),
        yamux::Mode::Server,
    );
    loop {
        let stream = poll_fn(|cx| connection.poll_next_inbound(cx)).await;
        let Some(stream) = stream else {
            return Ok(());
        };
        let stream = stream.map_err(io::Error::other)?;
        let tcp_handler = tcp_handler.clone();
        let udp_handler = udp_handler.clone();
        let brutal = brutal.clone();
        tokio::spawn(async move {
            let _ = dispatch_server_stream(
                Box::new(stream.compat()),
                brutal,
                tcp_handler,
                udp_handler,
            )
            .await;
        });
    }
}

fn smux_config() -> smux::Config {
    smux::Config {
        enable_keep_alive: false,
        ..smux::Config::default()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_routed_h2mux(
    stream: Stream,
    source: SocketAddr,
    tag: String,
    user: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    require_padding: bool,
    brutal: Option<BrutalRuntimeOptions>,
) -> io::Result<()> {
    let inherited_metadata = inherited_tcp_metadata(source, &tag);
    let tcp_tag = tag.clone();
    let tcp_user = user.clone();
    let tcp_router = router.clone();
    let tcp_outbounds = outbounds.clone();
    let tcp_metadata = inherited_metadata.clone();
    let tcp_handler: TcpHandler = Arc::new(move |stream, destination| {
        let tag = tcp_tag.clone();
        let user = tcp_user.clone();
        let router = tcp_router.clone();
        let outbounds = tcp_outbounds.clone();
        let metadata = tcp_metadata.clone();
        Box::pin(async move {
            route_tcp_stream(
                stream,
                source,
                &tag,
                destination,
                user,
                &router,
                &outbounds,
                metadata,
            )
            .await
        })
    });
    let udp_handler: UdpHandler = Arc::new(move |packets, _destination| {
        let tag = tag.clone();
        let user = user.clone();
        let router = router.clone();
        let outbounds = outbounds.clone();
        let mut metadata = inherited_metadata.clone();
        Box::pin(async move {
            metadata.inbound = tag.clone();
            metadata.network = Some(crate::common::network::Network::Udp);
            reject_udp_inbound_detour(&metadata, &outbounds)?;
            proxy_packet_connection(
                packets,
                source,
                &tag,
                Some(user),
                &router,
                &outbounds,
                udp_timeout,
            )
            .await
        })
    });
    serve_h2mux_with_padding(
        stream,
        require_padding,
        brutal,
        tcp_handler,
        udp_handler,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn route_tcp_stream(
    mut stream: Stream,
    source: SocketAddr,
    tag: &str,
    destination: SocksAddr,
    user: String,
    router: &Router,
    outbounds: &OutboundManager,
    inherited_metadata: Metadata,
) -> io::Result<()> {
    let (destination, origin_destination) =
        match restore_fake_ip(destination, outbounds) {
            Ok(destination) => destination,
            Err(error) => {
                write_stream_failure(&mut stream, &error).await;
                return Err(error);
            }
        };
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination.clone()),
        origin_destination: origin_destination.clone(),
        fake_ip: origin_destination.is_some(),
        network: Some(crate::common::network::Network::Tcp),
        user,
        ..inherited_metadata
    };
    if let Some(injector) =
        prepare_tcp_inbound_detour(&mut metadata, outbounds)?
    {
        stream.write_u8(STATUS_SUCCESS).await?;
        stream.flush().await?;
        return injector
            .inject(stream, TcpInboundContext { source, metadata })
            .await;
    }
    let decision = router.route(&metadata);
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        let error = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection rejected by route rule",
        );
        write_stream_failure(&mut stream, &error).await;
        return Err(error);
    }
    let destination = decision.destination(&destination);
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        Ok(outbounds.direct())
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })
    };
    let dialer = match dialer {
        Ok(dialer) => dialer,
        Err(error) => {
            write_stream_failure(&mut stream, &error).await;
            return Err(error);
        }
    };
    let mut remote = match dialer.dial_tcp(&destination).await {
        Ok(remote) => remote,
        Err(error) => {
            write_stream_failure(&mut stream, &error).await;
            return Err(error);
        }
    };
    stream.write_u8(STATUS_SUCCESS).await?;
    stream.flush().await?;
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

async fn write_stream_failure(stream: &mut Stream, error: &io::Error) {
    let message = error.to_string();
    let _ = async {
        stream.write_u8(STATUS_ERROR).await?;
        write_uvarint(stream, message.len() as u64).await?;
        stream.write_all(message.as_bytes()).await?;
        stream.flush().await
    }
    .await;
}

async fn dispatch_server_stream(
    mut stream: Stream,
    brutal: Option<Arc<BrutalServerState>>,
    tcp_handler: TcpHandler,
    udp_handler: UdpHandler,
) -> io::Result<()> {
    let flags = stream.read_u16().await?;
    let destination = read_address(&mut stream).await?;
    if flags & FLAG_UDP == 0 {
        if matches!(&destination, SocksAddr::Domain { host, .. } if host == BRUTAL_EXCHANGE_DOMAIN)
        {
            return match brutal {
                Some(brutal) => brutal.exchange(&mut stream).await,
                None => {
                    write_brutal_response(
                        &mut stream,
                        0,
                        Err("brutal is not enabled by the server"),
                    )
                    .await
                }
            };
        }
        tcp_handler(stream, destination).await
    } else {
        let packet_addr = flags & FLAG_PACKET_ADDR != 0;
        let (packets, response) = MuxPacketConnection::new_server(
            stream,
            packet_addr,
            destination.clone(),
        );
        let result = udp_handler(Box::new(packets), destination).await;
        if let Err(error) = &result {
            response.failure(error).await;
        }
        result
    }
}

async fn write_stream_request<S: AsyncWrite + Unpin + ?Sized>(
    stream: &mut S,
    udp: bool,
    packet_addr: bool,
    destination: &SocksAddr,
) -> io::Result<()> {
    let mut flags = 0_u16;
    if udp {
        flags |= FLAG_UDP;
    }
    if packet_addr {
        flags |= FLAG_PACKET_ADDR;
    }
    stream.write_u16(flags).await?;
    write_address(stream, destination).await?;
    stream.flush().await
}

async fn client_tcp_bridge(
    bridge: tokio::io::DuplexStream,
    mux_stream: Stream,
) {
    let (mut app_reader, mut app_writer) = tokio::io::split(bridge);
    let (mut mux_reader, mut mux_writer) = tokio::io::split(mux_stream);
    let upload = async {
        let result = tokio::io::copy(&mut app_reader, &mut mux_writer).await;
        let _ = mux_writer.shutdown().await;
        result
    };
    let download = async {
        match read_status(&mut mux_reader).await {
            Ok(()) => {
                let result =
                    tokio::io::copy(&mut mux_reader, &mut app_writer).await;
                let _ = app_writer.shutdown().await;
                result.map(|_| ())
            }
            Err(error) => {
                let _ = app_writer.shutdown().await;
                Err(error)
            }
        }
    };
    let _ = tokio::join!(upload, download);
}

async fn read_status<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
) -> io::Result<()> {
    match reader.read_u8().await? {
        STATUS_SUCCESS => Ok(()),
        STATUS_ERROR => {
            let length = read_uvarint(reader).await?;
            let length = usize::try_from(length).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "error is too long")
            })?;
            let mut message = vec![0; length];
            reader.read_exact(&mut message).await?;
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("remote error: {}", String::from_utf8_lossy(&message)),
            ))
        }
        value => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid sing-mux stream status: {value}"),
        )),
    }
}

async fn read_uvarint<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
) -> io::Result<u64> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = reader.read_u8().await?;
        if shift == 63 && byte > 1 {
            break;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid uvarint",
    ))
}

async fn write_uvarint<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    mut value: u64,
) -> io::Result<()> {
    let mut encoded = [0_u8; 10];
    let mut length = 0;
    while value >= 0x80 {
        encoded[length] = value as u8 | 0x80;
        value >>= 7;
        length += 1;
    }
    encoded[length] = value as u8;
    writer.write_all(&encoded[..=length]).await
}

struct PacketReader {
    inner: ReadHalf<Stream>,
    response_pending: bool,
}

struct PacketWriter {
    inner: WriteHalf<Stream>,
    response_pending: bool,
}

#[derive(Clone)]
struct PacketResponse {
    writer: Arc<Mutex<PacketWriter>>,
}

impl PacketResponse {
    async fn failure(&self, error: &io::Error) {
        let mut writer = self.writer.lock().await;
        if !writer.response_pending {
            return;
        }
        let message = error.to_string();
        let _ = async {
            writer.inner.write_u8(STATUS_ERROR).await?;
            write_uvarint(&mut writer.inner, message.len() as u64).await?;
            writer.inner.write_all(message.as_bytes()).await?;
            writer.inner.flush().await
        }
        .await;
        writer.response_pending = false;
    }
}

struct MuxPacketConnection {
    reader: Mutex<PacketReader>,
    writer: Arc<Mutex<PacketWriter>>,
    packet_addr: bool,
    destination: SocksAddr,
}

fn random_padding_length() -> io::Result<u16> {
    let mut random = [0_u8; 2];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    Ok(256 + u16::from_be_bytes(random) % 512)
}

fn padding_stream(stream: Stream) -> Stream {
    let (application, bridge) = tokio::io::duplex(64 * 1024);
    let (app_reader, app_writer) = tokio::io::split(bridge);
    let (network_reader, network_writer) = tokio::io::split(stream);
    tokio::spawn(encode_padding(app_reader, network_writer));
    tokio::spawn(decode_padding(network_reader, app_writer));
    Box::new(application)
}

async fn encode_padding<R, W>(mut reader: R, mut writer: W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut data = vec![0_u8; u16::MAX as usize];
    for frame in 0.. {
        let size = reader.read(&mut data).await?;
        if size == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        if frame < 16 {
            let padding_length = random_padding_length()?;
            writer.write_u16(size as u16).await?;
            writer.write_u16(padding_length).await?;
            writer.write_all(&data[..size]).await?;
            writer
                .write_all(&vec![0; usize::from(padding_length)])
                .await?;
        } else {
            writer.write_all(&data[..size]).await?;
        }
        writer.flush().await?;
    }
    unreachable!()
}

async fn decode_padding<R, W>(mut reader: R, mut writer: W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut data = vec![0_u8; u16::MAX as usize];
    for _ in 0..16 {
        let size = match reader.read_u16().await {
            Ok(size) => size as usize,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                writer.shutdown().await?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let padding_length = reader.read_u16().await? as usize;
        reader.read_exact(&mut data[..size]).await?;
        writer.write_all(&data[..size]).await?;
        let mut padding = vec![0; padding_length];
        reader.read_exact(&mut padding).await?;
    }
    tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await
}

/// `smux` only mutably polls its transport, but its public constructor also
/// requires the transport value to be `Sync`. A mutex supplies that marker for
/// the crate-wide boxed stream without changing the common `Stream` contract.
struct SyncStream {
    inner: StdMutex<Stream>,
}

impl SyncStream {
    fn new(inner: Stream) -> Self {
        Self {
            inner: StdMutex::new(inner),
        }
    }

    fn inner_mut(&mut self) -> &mut Stream {
        self.inner
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl AsyncRead for SyncStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(self.inner_mut()).poll_read(cx, buffer)
    }
}

impl AsyncWrite for SyncStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(self.inner_mut()).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(self.inner_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(self.inner_mut()).poll_shutdown(cx)
    }
}

struct CountedStream<T> {
    inner: T,
    active: Arc<AtomicUsize>,
}

impl<T> Drop for CountedStream<T> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountedStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountedStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl MuxPacketConnection {
    fn new(
        stream: Stream,
        packet_addr: bool,
        destination: SocksAddr,
        response_pending: bool,
    ) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(PacketReader {
                inner: reader,
                response_pending,
            }),
            writer: Arc::new(Mutex::new(PacketWriter {
                inner: writer,
                response_pending: false,
            })),
            packet_addr,
            destination,
        }
    }

    fn new_server(
        stream: Stream,
        packet_addr: bool,
        destination: SocksAddr,
    ) -> (Self, PacketResponse) {
        let (reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(PacketWriter {
            inner: writer,
            response_pending: true,
        }));
        (
            Self {
                reader: Mutex::new(PacketReader {
                    inner: reader,
                    response_pending: false,
                }),
                writer: writer.clone(),
                packet_addr,
                destination,
            },
            PacketResponse { writer },
        )
    }
}

impl PacketConnection for MuxPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let length = u16::try_from(data.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sing-mux UDP payload exceeds 65535 bytes",
                )
            })?;
            let mut writer = self.writer.lock().await;
            if writer.response_pending {
                writer.inner.write_u8(STATUS_SUCCESS).await?;
                writer.response_pending = false;
            }
            if self.packet_addr {
                write_address(&mut writer.inner, destination).await?;
            }
            writer.inner.write_u16(length).await?;
            writer.inner.write_all(data).await?;
            writer.inner.flush().await?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut reader = self.reader.lock().await;
            if reader.response_pending {
                read_status(&mut reader.inner).await?;
                reader.response_pending = false;
            }
            let source = if self.packet_addr {
                read_address(&mut reader.inner).await?
            } else {
                self.destination.clone()
            };
            let length = reader.inner.read_u16().await? as usize;
            if length > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sing-mux UDP payload exceeds receive buffer",
                ));
            }
            reader.inner.read_exact(&mut data[..length]).await?;
            Ok((length, source))
        })
    }
}

fn empty_body() -> Body {
    Empty::new()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    struct OneConnectionDialer {
        stream: Mutex<Option<Stream>>,
        dials: AtomicUsize,
    }

    impl Dialer for OneConnectionDialer {
        fn dial_tcp<'a>(
            &'a self,
            destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async move {
                assert!(is_destination(destination));
                self.dials.fetch_add(1, Ordering::SeqCst);
                self.stream.lock().await.take().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "no stream")
                })
            })
        }
    }

    #[tokio::test]
    async fn brutal_exchange_frames_match_go_wire_layout() {
        let mut request = Vec::new();
        write_brutal_request(&mut request, 0x0102_0304_0506_0708)
            .await
            .unwrap();
        assert_eq!(request, 0x0102_0304_0506_0708_u64.to_be_bytes());
        assert_eq!(
            read_brutal_request(&mut request.as_slice()).await.unwrap(),
            0x0102_0304_0506_0708
        );

        let mut accepted = Vec::new();
        write_brutal_response(&mut accepted, 1_250_000, Ok(()))
            .await
            .unwrap();
        assert_eq!(
            accepted,
            [vec![1], 1_250_000_u64.to_be_bytes().to_vec()].concat()
        );
        assert_eq!(
            read_brutal_response(&mut accepted.as_slice())
                .await
                .unwrap(),
            1_250_000
        );

        let mut rejected = Vec::new();
        write_brutal_response(&mut rejected, 0, Err("disabled"))
            .await
            .unwrap();
        assert_eq!(rejected, b"\0\x08disabled");
        let error = read_brutal_response(&mut rejected.as_slice())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "remote error: disabled");
    }

    #[tokio::test]
    async fn brutal_exchange_precedes_application_streams() {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let upstream = Arc::new(OneConnectionDialer {
            stream: Mutex::new(Some(Box::new(client))),
            dials: AtomicUsize::new(0),
        });
        let tcp_handler: TcpHandler = Arc::new(|mut stream, destination| {
            Box::pin(async move {
                assert_eq!(destination, SocksAddr::new("tcp.test", 443));
                stream.write_u8(STATUS_SUCCESS).await?;
                stream.flush().await?;
                let value = stream.read_u8().await?;
                stream.write_u8(value).await
            })
        });
        let udp_handler: UdpHandler =
            Arc::new(|_, _| Box::pin(async { Ok(()) }));
        let server_brutal = BrutalRuntimeOptions {
            send_bps: 10_000_000,
            receive_bps: 12_500_000,
        };
        tokio::spawn(async move {
            serve_h2mux_with_padding(
                Box::new(server),
                false,
                Some(server_brutal),
                tcp_handler,
                udp_handler,
            )
            .await
            .unwrap();
        });
        let mux = MuxClient::new(
            upstream.clone(),
            OutboundMultiplexOptions {
                enabled: true,
                protocol: "smux".into(),
                brutal: Some(crate::option::BrutalOptions {
                    enabled: true,
                    up_mbps: 100,
                    down_mbps: 80,
                }),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mux
            .dial_tcp(&SocksAddr::new("tcp.test", 443))
            .await
            .unwrap();
        stream.write_u8(42).await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 42);
        assert_eq!(upstream.dials.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn brutal_bandwidth_validation_matches_sing_box() {
        let invalid = crate::option::BrutalOptions {
            enabled: true,
            up_mbps: 0,
            down_mbps: 100,
        };
        assert_eq!(
            BrutalRuntimeOptions::from_options(Some(&invalid))
                .unwrap_err()
                .to_string(),
            "brutal: invalid upload speed"
        );
        let valid = crate::option::BrutalOptions {
            enabled: true,
            up_mbps: 1,
            down_mbps: 2,
        };
        assert_eq!(
            BrutalRuntimeOptions::from_options(Some(&valid)).unwrap(),
            Some(BrutalRuntimeOptions {
                send_bps: 125_000,
                receive_bps: 250_000,
            })
        );
    }

    #[tokio::test]
    async fn multiplexes_tcp_and_packet_addr_udp_over_one_h2_session() {
        assert_multiplexes_tcp_and_udp("h2mux").await;
    }

    #[tokio::test]
    async fn multiplexes_tcp_and_packet_addr_udp_over_one_smux_session() {
        assert_multiplexes_tcp_and_udp("smux").await;
    }

    #[tokio::test]
    async fn multiplexes_tcp_and_packet_addr_udp_over_one_yamux_session() {
        assert_multiplexes_tcp_and_udp("yamux").await;
    }

    #[tokio::test]
    async fn routed_tcp_reports_dial_failure_before_success() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable = listener.local_addr().unwrap();
        drop(listener);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let outbounds = Arc::new(
            crate::outbound::OutboundManager::from_options(
                &crate::option::Options::default(),
                "",
            )
            .unwrap(),
        );
        let router = Arc::new(
            crate::route::Router::from_json(&[json!({"action":"direct"})], "")
                .unwrap(),
        );
        let server_task = tokio::spawn(serve_routed_h2mux(
            Box::new(server),
            "127.0.0.1:12345".parse().unwrap(),
            "mux-in".into(),
            "alice".into(),
            router,
            outbounds,
            std::time::Duration::from_secs(5),
            false,
            None,
        ));
        client.write_all(&[VERSION_0, PROTOCOL_SMUX]).await.unwrap();
        client.flush().await.unwrap();
        let session = smux::Session::client(
            SyncStream::new(Box::new(client)),
            smux_config(),
        )
        .await
        .unwrap();
        let mut stream = session.open_stream().await.unwrap();
        write_stream_request(
            &mut stream,
            false,
            false,
            &SocksAddr::from(unavailable),
        )
        .await
        .unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), STATUS_ERROR);
        let length = read_uvarint(&mut stream).await.unwrap() as usize;
        let mut message = vec![0; length];
        stream.read_exact(&mut message).await.unwrap();
        assert!(!message.is_empty());
        server_task.abort();
    }

    #[tokio::test]
    async fn routed_udp_reports_route_failure_before_success() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let outbounds = Arc::new(
            crate::outbound::OutboundManager::from_options(
                &crate::option::Options::default(),
                "",
            )
            .unwrap(),
        );
        let router = Arc::new(
            crate::route::Router::from_json(&[], "missing-outbound").unwrap(),
        );
        let server_task = tokio::spawn(serve_routed_h2mux(
            Box::new(server),
            "127.0.0.1:12345".parse().unwrap(),
            "mux-in".into(),
            "alice".into(),
            router,
            outbounds,
            std::time::Duration::from_secs(5),
            false,
            None,
        ));
        client.write_all(&[VERSION_0, PROTOCOL_SMUX]).await.unwrap();
        client.flush().await.unwrap();
        let session = smux::Session::client(
            SyncStream::new(Box::new(client)),
            smux_config(),
        )
        .await
        .unwrap();
        let mut stream = session.open_stream().await.unwrap();
        write_stream_request(
            &mut stream,
            true,
            false,
            &SocksAddr::new("udp.test", 53),
        )
        .await
        .unwrap();
        stream.write_u16(5).await.unwrap();
        stream.write_all(b"query").await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), STATUS_ERROR);
        let length = read_uvarint(&mut stream).await.unwrap() as usize;
        let mut message = vec![0; length];
        stream.read_exact(&mut message).await.unwrap();
        assert!(String::from_utf8_lossy(&message).contains("outbound"));
        server_task.abort();
    }

    async fn assert_multiplexes_tcp_and_udp(protocol: &str) {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let upstream = Arc::new(OneConnectionDialer {
            stream: Mutex::new(Some(Box::new(client))),
            dials: AtomicUsize::new(0),
        });
        let tcp_handler: TcpHandler = Arc::new(|mut stream, destination| {
            Box::pin(async move {
                assert_eq!(destination, SocksAddr::new("tcp.test", 443));
                let mut value = [0; 4];
                stream.read_exact(&mut value).await?;
                stream.write_all(&value).await
            })
        });
        let udp_handler: UdpHandler = Arc::new(|packets, destination| {
            Box::pin(async move {
                assert_eq!(destination, SocksAddr::new("seed.test", 53));
                let mut value = [0; 32];
                let (size, destination) = packets.recv_from(&mut value).await?;
                packets.send_to(&value[..size], &destination).await?;
                Ok(())
            })
        });
        tokio::spawn(async move {
            serve_h2mux(Box::new(server), tcp_handler, udp_handler)
                .await
                .unwrap();
        });
        let mux = Arc::new(
            MuxClient::new(
                upstream.clone(),
                OutboundMultiplexOptions {
                    enabled: true,
                    protocol: protocol.to_owned(),
                    max_connections: 1,
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        let mut first = mux
            .dial_tcp(&SocksAddr::new("tcp.test", 443))
            .await
            .unwrap();
        let mut second = mux
            .dial_tcp(&SocksAddr::new("tcp.test", 443))
            .await
            .unwrap();
        first.write_all(b"one!").await.unwrap();
        second.write_all(b"two!").await.unwrap();
        let mut one = [0; 4];
        let mut two = [0; 4];
        first.read_exact(&mut one).await.unwrap();
        second.read_exact(&mut two).await.unwrap();
        assert_eq!(&one, b"one!");
        assert_eq!(&two, b"two!");

        let packets = mux
            .listen_udp(&SocksAddr::new("seed.test", 53))
            .await
            .unwrap();
        let actual = SocksAddr::new("actual.test", 5353);
        packets.send_to(b"packet", &actual).await.unwrap();
        let mut response = [0; 32];
        let (size, source) = packets.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"packet");
        assert_eq!(source, actual);
        assert_eq!(upstream.dials.load(Ordering::SeqCst), 1);
    }
}
