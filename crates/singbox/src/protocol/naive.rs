//! NaiveProxy CONNECT and first-eight-write padding layer.

use std::{
    collections::HashMap,
    convert::Infallible,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::{Buf as _, Bytes};
use http_body_util::{BodyExt as _, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, StatusCode,
    body::{Frame, Incoming},
    client::conn::http2 as client_http2,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use n0_watcher::Watcher as _;
use quinn::{
    Endpoint, EndpointConfig, TokioRuntime, VarInt,
    crypto::rustls::QuicClientConfig,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{DialFuture, Dialer, Stream},
    common::{network::SocksAddr, quic::PacketUdpSocket, tls::ClientTlsConfig},
    option::{Listable, User},
};

pub struct NaiveOutbound<D> {
    upstream: D,
    server: SocksAddr,
    username: String,
    password: String,
    extra_headers: std::collections::HashMap<String, Listable<String>>,
    tls: Option<ClientTlsConfig>,
    http2: Http2Pool,
    insecure_concurrency: usize,
    pool_counter: AtomicU64,
    http2_session_receive_window: u32,
    http2_stream_receive_window: u32,
    network_monitor_started: Arc<AtomicBool>,
    cancellation: CancellationToken,
}

type H2SendRequest = client_http2::SendRequest<StreamingBody>;
type Http2Slot = Arc<Mutex<Option<Http2Session>>>;
type Http2Pool = Arc<Mutex<HashMap<usize, Http2Slot>>>;

struct Http2Session {
    sender: H2SendRequest,
    driver: tokio::task::JoinHandle<Result<(), hyper::Error>>,
}

impl Drop for Http2Session {
    fn drop(&mut self) {
        self.driver.abort();
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

/// Native HTTP/3 NaiveProxy client. A single QUIC/H3 session is reused for
/// concurrent CONNECT streams, matching the connection-pool behavior of the
/// upstream Cronet transport.
pub struct NaiveHttp3Outbound {
    server: SocksAddr,
    server_name: String,
    username: String,
    password: String,
    extra_headers: std::collections::HashMap<String, Listable<String>>,
    tls: ClientTlsConfig,
    transport: Arc<quinn::TransportConfig>,
    packet_dialer: Option<Arc<dyn Dialer>>,
    state: Arc<Mutex<Option<Http3Session>>>,
    network_monitor_started: Arc<AtomicBool>,
    cancellation: CancellationToken,
}

impl NaiveHttp3Outbound {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: SocksAddr,
        server_name: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        extra_headers: std::collections::HashMap<String, Listable<String>>,
        tls: ClientTlsConfig,
        stream_receive_window: Option<u64>,
        session_receive_window: Option<u64>,
        congestion_control: &str,
    ) -> io::Result<Self> {
        let mut transport = quinn::TransportConfig::default();
        let stream_receive_window =
            stream_receive_window.unwrap_or(6 * 1024 * 1024);
        transport.stream_receive_window(quic_varint(
            stream_receive_window,
            "stream_receive_window",
        )?);
        let session_receive_window =
            session_receive_window.unwrap_or(15 * 1024 * 1024);
        transport.receive_window(quic_varint(
            session_receive_window,
            "quic_session_receive_window",
        )?);
        match congestion_control {
            "" | "cubic" => {
                transport.congestion_controller_factory(Arc::new(
                    quinn::congestion::CubicConfig::default(),
                ));
            }
            "bbr" => {
                transport.congestion_controller_factory(Arc::new(
                    super::quic_bbr::BbrConfig::new(
                        super::quic_bbr::BbrProfile::Standard,
                    ),
                ));
            }
            "reno" => {
                transport.congestion_controller_factory(Arc::new(
                    quinn::congestion::NewRenoConfig::default(),
                ));
            }
            "bbr2" => {
                transport.congestion_controller_factory(Arc::new(
                    super::quic_bbr2::Bbr2Config::default(),
                ));
            }
            value => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown QUIC congestion control {value:?}"),
                ));
            }
        }
        Ok(Self {
            server,
            server_name: server_name.into(),
            username: username.into(),
            password: password.into(),
            extra_headers,
            tls,
            transport: Arc::new(transport),
            packet_dialer: None,
            state: Arc::new(Mutex::new(None)),
            network_monitor_started: Arc::new(AtomicBool::new(false)),
            cancellation: CancellationToken::new(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_packet_dialer(
        server: SocksAddr,
        server_name: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        extra_headers: std::collections::HashMap<String, Listable<String>>,
        tls: ClientTlsConfig,
        stream_receive_window: Option<u64>,
        session_receive_window: Option<u64>,
        congestion_control: &str,
        packet_dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        let mut outbound = Self::new(
            server,
            server_name,
            username,
            password,
            extra_headers,
            tls,
            stream_receive_window,
            session_receive_window,
            congestion_control,
        )?;
        outbound.packet_dialer = Some(packet_dialer);
        Ok(outbound)
    }

    async fn connect(&self) -> io::Result<Http3Session> {
        let (socket, remote) = if let Some(dialer) = &self.packet_dialer {
            let (socket, remote) =
                PacketUdpSocket::connect(dialer.clone(), &self.server).await?;
            (Some(socket), remote)
        } else {
            let remote = match &self.server {
                SocksAddr::Ip(address) => *address,
                SocksAddr::Domain { host, port } => {
                    tokio::net::lookup_host((host.as_str(), *port))
                        .await?
                        .next()
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                format!(
                                    "NaiveProxy server {host:?} resolved to no addresses"
                                ),
                            )
                        })?
                }
            };
            (None, remote)
        };
        let bind = if remote.is_ipv4() {
            "0.0.0.0:0".parse().expect("valid IPv4 bind address")
        } else {
            "[::]:0".parse().expect("valid IPv6 bind address")
        };
        let mut endpoint = if let Some(socket) = socket {
            Endpoint::new_with_abstract_socket(
                EndpointConfig::default(),
                None,
                socket,
                Arc::new(TokioRuntime),
            )?
        } else {
            Endpoint::client(bind)?
        };
        let tls_config = self
            .tls
            .config_for_handshake()
            .await
            .map_err(io::Error::other)?;
        let crypto =
            QuicClientConfig::try_from(tls_config).map_err(io::Error::other)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(self.transport.clone());
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(remote, &self.server_name)
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)?;
        let (http3, sender) =
            h3::client::new(h3_quinn::Connection::new(connection))
                .await
                .map_err(io::Error::other)?;
        let driver = tokio::spawn(async move {
            let mut http3 = http3;
            futures_util::future::poll_fn(|context| http3.poll_close(context))
                .await
        });
        Ok(Http3Session {
            endpoint,
            sender,
            driver,
        })
    }

    /// Close every cached HTTP/3 connection. The next dial reconnects.
    pub async fn reset(&self) {
        self.state.lock().await.take();
    }

    async fn open_tunnel(
        &self,
        sender: &mut H3SendRequest,
        destination: &SocksAddr,
    ) -> io::Result<Stream> {
        let uri = format!("https://{}/", self.server);
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("-connect-authority", destination.to_string())
            .header("padding", generate_padding_header()?)
            .body(())
            .map_err(io::Error::other)?;
        if !self.username.is_empty() {
            let value = format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", self.username, self.password))
            );
            request.headers_mut().insert(
                hyper::header::PROXY_AUTHORIZATION,
                value.parse().map_err(io::Error::other)?,
            );
        }
        for (name, values) in &self.extra_headers {
            validate_header(name, values)?;
            if let Some(value) = values.0.first() {
                request.headers_mut().insert(
                    hyper::header::HeaderName::from_bytes(name.as_bytes())
                        .map_err(io::Error::other)?,
                    value.parse().map_err(io::Error::other)?,
                );
            }
        }
        let mut stream = sender
            .send_request(request)
            .await
            .map_err(io::Error::other)?;
        let response =
            stream.recv_response().await.map_err(io::Error::other)?;
        if !response.status().is_success() {
            return Err(io::Error::new(
                if response.status()
                    == StatusCode::PROXY_AUTHENTICATION_REQUIRED
                {
                    io::ErrorKind::PermissionDenied
                } else {
                    io::ErrorKind::ConnectionRefused
                },
                format!(
                    "NaiveProxy CONNECT failed with status {}",
                    response.status()
                ),
            ));
        }
        if response
            .headers()
            .get("padding")
            .and_then(|value| value.to_str().ok())
            .is_none_or(str::is_empty)
        {
            return Err(invalid("missing NaiveProxy response padding"));
        }
        Ok(Box::new(PaddingStream::new(bridge_http3_client(stream))))
    }
}

impl Dialer for NaiveHttp3Outbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            ensure_network_reset_monitor(
                &self.state,
                &self.network_monitor_started,
                &self.cancellation,
            );
            let mut state = self.state.lock().await;
            if state
                .as_ref()
                .is_none_or(|session| session.driver.is_finished())
            {
                *state = Some(self.connect().await?);
            }
            let result = self
                .open_tunnel(
                    &mut state.as_mut().expect("HTTP/3 session exists").sender,
                    destination,
                )
                .await;
            if result.is_err() {
                *state = None;
            }
            result
        })
    }
}

impl Drop for NaiveHttp3Outbound {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut state) = self.state.try_lock() {
            state.take();
        }
    }
}

fn quic_varint(value: u64, name: &str) -> io::Result<VarInt> {
    VarInt::from_u64(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} exceeds the QUIC variable-integer limit"),
        )
    })
}

impl<D> NaiveOutbound<D> {
    pub fn new(
        upstream: D,
        server: SocksAddr,
        username: impl Into<String>,
        password: impl Into<String>,
        extra_headers: std::collections::HashMap<String, Listable<String>>,
    ) -> Self {
        Self::new_with_options(
            upstream,
            server,
            username,
            password,
            extra_headers,
            0,
            None,
        )
        .expect("default NaiveProxy options are valid")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_options(
        upstream: D,
        server: SocksAddr,
        username: impl Into<String>,
        password: impl Into<String>,
        extra_headers: std::collections::HashMap<String, Listable<String>>,
        insecure_concurrency: i32,
        stream_receive_window: Option<u64>,
    ) -> io::Result<Self> {
        let session_receive_window = stream_receive_window.unwrap_or({
            #[cfg(target_os = "ios")]
            {
                4 * 1024 * 1024
            }
            #[cfg(not(target_os = "ios"))]
            {
                128 * 1024 * 1024
            }
        });
        let session_receive_window = valid_http2_window(
            session_receive_window,
            "stream_receive_window",
        )?;
        Ok(Self {
            upstream,
            server,
            username: username.into(),
            password: password.into(),
            extra_headers,
            tls: None,
            http2: Arc::new(Mutex::new(HashMap::new())),
            insecure_concurrency: usize::try_from(insecure_concurrency.max(1))
                .expect("positive i32 fits usize"),
            pool_counter: AtomicU64::new(0),
            http2_session_receive_window: session_receive_window,
            http2_stream_receive_window: session_receive_window / 2,
            network_monitor_started: Arc::new(AtomicBool::new(false)),
            cancellation: CancellationToken::new(),
        })
    }

    pub fn new_tls(
        upstream: D,
        server: SocksAddr,
        username: impl Into<String>,
        password: impl Into<String>,
        extra_headers: std::collections::HashMap<String, Listable<String>>,
        tls: ClientTlsConfig,
    ) -> Self {
        let mut outbound =
            Self::new(upstream, server, username, password, extra_headers);
        outbound.tls = Some(tls);
        outbound
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_tls_with_options(
        upstream: D,
        server: SocksAddr,
        username: impl Into<String>,
        password: impl Into<String>,
        extra_headers: std::collections::HashMap<String, Listable<String>>,
        tls: ClientTlsConfig,
        insecure_concurrency: i32,
        stream_receive_window: Option<u64>,
    ) -> io::Result<Self> {
        let mut outbound = Self::new_with_options(
            upstream,
            server,
            username,
            password,
            extra_headers,
            insecure_concurrency,
            stream_receive_window,
        )?;
        outbound.tls = Some(tls);
        Ok(outbound)
    }

    /// Close every cached HTTP/2 connection. HTTP/1.1 connections are never
    /// cached, so they require no explicit reset.
    pub async fn reset(&self) {
        self.http2.lock().await.clear();
    }

    fn next_pool_index(&self) -> usize {
        if self.insecure_concurrency > 1 {
            usize::try_from(
                self.pool_counter
                    .fetch_add(1, Ordering::Relaxed)
                    .wrapping_add(1)
                    % self.insecure_concurrency as u64,
            )
            .expect("NaiveProxy pool index fits usize")
        } else {
            0
        }
    }
}

fn valid_http2_window(value: u64, name: &str) -> io::Result<u32> {
    let value = u32::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} exceeds the HTTP/2 flow-control limit"),
        )
    })?;
    if value > 0x7fff_ffff {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} exceeds the HTTP/2 flow-control limit"),
        ));
    }
    Ok(value)
}

impl<D: Dialer> Dialer for NaiveOutbound<D> {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            if let Some(tls) = &self.tls {
                ensure_http2_network_reset_monitor(
                    &self.http2,
                    &self.network_monitor_started,
                    &self.cancellation,
                );
                let credentials = (!self.username.is_empty()).then_some((
                    self.username.as_str(),
                    self.password.as_str(),
                ));
                let pool_index = self.next_pool_index();
                let slot = {
                    let mut sessions = self.http2.lock().await;
                    sessions
                        .entry(pool_index)
                        .or_insert_with(|| Arc::new(Mutex::new(None)))
                        .clone()
                };
                let mut state = slot.lock().await;
                if state
                    .as_ref()
                    .is_some_and(|session| !session.driver.is_finished())
                {
                    let result = open_http2_tunnel(
                        &mut state
                            .as_mut()
                            .expect("HTTP/2 session exists")
                            .sender,
                        &self.server,
                        destination,
                        credentials,
                        &self.extra_headers,
                    )
                    .await;
                    if result.is_err() {
                        *state = None;
                    }
                    return result;
                }
                *state = None;
                let stream = self.upstream.dial_tcp(&self.server).await?;
                let connection = tls.connect_stream(stream).await?;
                let http2 = connection.negotiated_alpn() == Some(b"h2");
                let connection = connection.into_stream();
                if http2 {
                    let mut builder =
                        client_http2::Builder::new(TokioExecutor::new());
                    builder.initial_connection_window_size(
                        self.http2_session_receive_window,
                    );
                    builder.initial_stream_window_size(
                        self.http2_stream_receive_window,
                    );
                    let (sender, connection) = builder
                        .handshake(TokioIo::new(connection))
                        .await
                        .map_err(io::Error::other)?;
                    *state = Some(Http2Session {
                        sender,
                        driver: tokio::spawn(connection),
                    });
                    let result = open_http2_tunnel(
                        &mut state
                            .as_mut()
                            .expect("HTTP/2 session exists")
                            .sender,
                        &self.server,
                        destination,
                        credentials,
                        &self.extra_headers,
                    )
                    .await;
                    if result.is_err() {
                        *state = None;
                    }
                    return result;
                }
                drop(state);
                let mut stream = Box::new(connection) as Stream;
                client_handshake(
                    &mut stream,
                    &self.server,
                    destination,
                    credentials,
                    &self.extra_headers,
                )
                .await?;
                return Ok(Box::new(PaddingStream::new(stream)) as Stream);
            }
            let mut stream = self.upstream.dial_tcp(&self.server).await?;
            client_handshake(
                &mut stream,
                &self.server,
                destination,
                (!self.username.is_empty()).then_some((
                    self.username.as_str(),
                    self.password.as_str(),
                )),
                &self.extra_headers,
            )
            .await?;
            Ok(Box::new(PaddingStream::new(stream)) as Stream)
        })
    }
}

impl<D> Drop for NaiveOutbound<D> {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut state) = self.http2.try_lock() {
            state.clear();
        }
    }
}

fn ensure_http2_network_reset_monitor(
    state: &Http2Pool,
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
                state.lock().await.clear();
            }
        }
    });
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

pub const PADDING_COUNT: u8 = 8;
pub const MAX_PADDING_CHUNK_SIZE: usize = u16::MAX as usize;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub fn generate_padding_header() -> io::Result<String> {
    let mut random = [0_u8; 9];
    getrandom::fill(&mut random)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let length = 30 + usize::from(random[0] & 31);
    let alphabet = b"!#$()+<>?@[]^`{}";
    let mut output = vec![b'~'; length];
    for index in 0..16 {
        output[index] = alphabet
            [usize::from(random[index / 2 + 1] >> ((index % 2) * 4) & 15)];
    }
    String::from_utf8(output).map_err(io::Error::other)
}

pub async fn client_handshake<S>(
    stream: &mut S,
    server: &SocksAddr,
    destination: &SocksAddr,
    credentials: Option<(&str, &str)>,
    extra_headers: &std::collections::HashMap<String, Listable<String>>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut request = format!(
        "CONNECT / HTTP/1.1\r\nHost: {server}\r\n-connect-authority: {destination}\r\nPadding: {}\r\n",
        generate_padding_header()?
    );
    if let Some((username, password)) = credentials {
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&STANDARD.encode(format!("{username}:{password}")));
        request.push_str("\r\n");
    }
    for (name, values) in extra_headers {
        validate_header(name, values)?;
        if let Some(value) = values.0.first() {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let response = read_header(stream).await?;
    let mut lines = response.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| invalid("invalid NaiveProxy response status"))?;
    if !(200..300).contains(&status) {
        return Err(io::Error::new(
            if status == 407 {
                io::ErrorKind::PermissionDenied
            } else {
                io::ErrorKind::ConnectionRefused
            },
            format!("NaiveProxy CONNECT failed with status {status}"),
        ));
    }
    let padded =
        lines
            .filter_map(|line| line.split_once(':'))
            .any(|(name, value)| {
                name.eq_ignore_ascii_case("padding") && !value.trim().is_empty()
            });
    if !padded {
        return Err(invalid("missing NaiveProxy response padding"));
    }
    Ok(())
}

pub(crate) type StreamingBody = UnsyncBoxBody<Bytes, Infallible>;

pub async fn client_handshake_http2(
    stream: Stream,
    server: &SocksAddr,
    destination: &SocksAddr,
    credentials: Option<(&str, &str)>,
    extra_headers: &std::collections::HashMap<String, Listable<String>>,
) -> io::Result<Stream> {
    let (mut sender, connection) =
        client_http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(stream))
            .await
            .map_err(io::Error::other)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    open_http2_tunnel(
        &mut sender,
        server,
        destination,
        credentials,
        extra_headers,
    )
    .await
}

async fn open_http2_tunnel(
    sender: &mut H2SendRequest,
    server: &SocksAddr,
    destination: &SocksAddr,
    credentials: Option<(&str, &str)>,
    extra_headers: &std::collections::HashMap<String, Listable<String>>,
) -> io::Result<Stream> {
    let (body_tx, body_rx) = tokio::sync::mpsc::channel(1);
    drop(body_tx);
    let uri = format!("https://{server}/");
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("-connect-authority", destination.to_string())
        .header("padding", generate_padding_header()?)
        .body(streaming_body(body_rx))
        .map_err(io::Error::other)?;
    if let Some((username, password)) = credentials {
        let value = format!(
            "Basic {}",
            STANDARD.encode(format!("{username}:{password}"))
        );
        request.headers_mut().insert(
            hyper::header::PROXY_AUTHORIZATION,
            value.parse().map_err(io::Error::other)?,
        );
    }
    for (name, values) in extra_headers {
        validate_header(name, values)?;
        if let Some(value) = values.0.first() {
            request.headers_mut().insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(io::Error::other)?,
                value.parse().map_err(io::Error::other)?,
            );
        }
    }
    let mut response = sender
        .send_request(request)
        .await
        .map_err(io::Error::other)?;
    if !response.status().is_success() {
        return Err(io::Error::new(
            if response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                io::ErrorKind::PermissionDenied
            } else {
                io::ErrorKind::ConnectionRefused
            },
            format!(
                "NaiveProxy CONNECT failed with status {}",
                response.status()
            ),
        ));
    }
    if response
        .headers()
        .get("padding")
        .and_then(|value| value.to_str().ok())
        .is_none_or(str::is_empty)
    {
        return Err(invalid("missing NaiveProxy response padding"));
    }
    let upgraded = hyper::upgrade::on(&mut response)
        .await
        .map_err(io::Error::other)?;
    Ok(Box::new(PaddingStream::new(Box::new(TokioIo::new(
        upgraded,
    )))))
}

pub(crate) fn validate_http2_request(
    request: &Request<Incoming>,
    users: &[User],
) -> io::Result<(SocksAddr, String)> {
    validate_connect_request(request, users)
}

pub(crate) fn validate_http3_request(
    request: &Request<()>,
    users: &[User],
) -> io::Result<(SocksAddr, String)> {
    validate_connect_request(request, users)
}

fn validate_connect_request<B>(
    request: &Request<B>,
    users: &[User],
) -> io::Result<(SocksAddr, String)> {
    if request.method() != Method::CONNECT {
        return Err(invalid("invalid NaiveProxy CONNECT request"));
    }
    if request
        .headers()
        .get("padding")
        .and_then(|value| value.to_str().ok())
        .is_none_or(str::is_empty)
    {
        return Err(invalid("missing NaiveProxy request padding"));
    }
    let authorization = request
        .headers()
        .get(hyper::header::PROXY_AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let user = authenticate(authorization, users).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "NaiveProxy authentication failed",
        )
    })?;
    let destination = request
        .headers()
        .get("-connect-authority")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .or_else(|| request.uri().authority().map(|value| value.as_str()))
        .or_else(|| {
            request
                .headers()
                .get(hyper::header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .ok_or_else(|| invalid("missing NaiveProxy destination"))?
        .parse()?;
    Ok((destination, user))
}

pub(crate) fn bridge_http3_server(
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Stream {
    let (mut sender, mut receiver) = stream.split();
    let (application, transport) = tokio::io::duplex(64 * 1024);
    let (mut transport_reader, mut transport_writer) =
        tokio::io::split(transport);
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            match transport_reader.read(&mut buffer).await {
                Ok(0) => {
                    let _ = sender.finish().await;
                    break;
                }
                Ok(length) => {
                    if sender
                        .send_data(Bytes::copy_from_slice(&buffer[..length]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    tokio::spawn(async move {
        loop {
            match receiver.recv_data().await {
                Ok(Some(mut data)) => {
                    let bytes = data.copy_to_bytes(data.remaining());
                    if transport_writer.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => {
                    let _ = transport_writer.shutdown().await;
                    break;
                }
            }
        }
    });
    Box::new(application)
}

fn bridge_http3_client(
    stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Stream {
    let (mut sender, mut receiver) = stream.split();
    let (application, transport) = tokio::io::duplex(64 * 1024);
    let (mut transport_reader, mut transport_writer) =
        tokio::io::split(transport);
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            match transport_reader.read(&mut buffer).await {
                Ok(0) => {
                    let _ = sender.finish().await;
                    break;
                }
                Ok(length) => {
                    if sender
                        .send_data(Bytes::copy_from_slice(&buffer[..length]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    tokio::spawn(async move {
        loop {
            match receiver.recv_data().await {
                Ok(Some(mut data)) => {
                    let bytes = data.copy_to_bytes(data.remaining());
                    if transport_writer.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => {
                    let _ = transport_writer.shutdown().await;
                    break;
                }
            }
        }
    });
    Box::new(application)
}

pub(crate) fn streaming_body(
    receiver: tokio::sync::mpsc::Receiver<Bytes>,
) -> StreamingBody {
    let stream =
        futures_util::stream::unfold(receiver, |mut receiver| async move {
            receiver.recv().await.map(|bytes| {
                (Ok::<_, Infallible>(Frame::data(bytes)), receiver)
            })
        });
    StreamBody::new(stream).boxed_unsync()
}

pub async fn server_handshake<S>(
    stream: &mut S,
    users: &[User],
) -> io::Result<(SocksAddr, String)>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let request = read_header(stream).await?;
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let parts: Vec<_> = request_line.split_whitespace().collect();
    if parts.len() != 3
        || parts[0] != "CONNECT"
        || !parts[2].starts_with("HTTP/1.")
    {
        write_response(stream, 400, "Bad Request", false).await?;
        return Err(invalid("invalid NaiveProxy CONNECT request"));
    }
    let headers: Vec<_> =
        lines.filter_map(|line| line.split_once(':')).collect();
    if !headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("padding") && !value.trim().is_empty()
    }) {
        write_response(stream, 400, "Bad Request", false).await?;
        return Err(invalid("missing NaiveProxy request padding"));
    }
    let authorization = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, value)| value.trim());
    let user = authenticate(authorization, users).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "NaiveProxy authentication failed",
        )
    });
    let user = match user {
        Ok(user) => user,
        Err(error) => {
            write_response(stream, 407, "Proxy Authentication Required", false)
                .await?;
            return Err(error);
        }
    };
    let destination = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("-connect-authority"))
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or(parts[1])
        .parse::<SocksAddr>()?;
    write_response(stream, 200, "OK", true).await?;
    Ok((destination, user))
}

fn authenticate(header: Option<&str>, users: &[User]) -> Option<String> {
    if users.is_empty() {
        return Some(String::new());
    }
    let encoded = header?.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    let (username, password) = decoded.split_at(separator);
    users
        .iter()
        .find(|user| {
            constant_time_equal(username, user.username.as_bytes())
                & constant_time_equal(&password[1..], user.password.as_bytes())
        })
        .map(|user| user.username.clone())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0)
                ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

fn validate_header(name: &str, values: &Listable<String>) -> io::Result<()> {
    if name.is_empty()
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
        || values.0.iter().any(|value| value.contains(['\r', '\n']))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid NaiveProxy extra header",
        ));
    }
    Ok(())
}

async fn read_header<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
) -> io::Result<String> {
    let mut bytes = Vec::with_capacity(512);
    loop {
        if bytes.len() == 64 * 1024 {
            return Err(invalid("NaiveProxy header is too large"));
        }
        bytes.push(stream.read_u8().await?);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|_| invalid("NaiveProxy header is not UTF-8"));
        }
    }
}

async fn write_response<S: AsyncWrite + Unpin + ?Sized>(
    stream: &mut S,
    status: u16,
    reason: &str,
    padding: bool,
) -> io::Result<()> {
    let mut response = format!("HTTP/1.1 {status} {reason}\r\n");
    if padding {
        response.push_str("Padding: ");
        response.push_str(&generate_padding_header()?);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

pub struct PaddingStream {
    inner: Stream,
    read_padding: u8,
    read_header: [u8; 3],
    read_header_pos: usize,
    read_remaining: usize,
    padding_remaining: usize,
    write_padding: u8,
    write_pending: Option<(Vec<u8>, usize, usize)>,
}

impl PaddingStream {
    pub fn new(inner: Stream) -> Self {
        Self {
            inner,
            read_padding: 0,
            read_header: [0; 3],
            read_header_pos: 0,
            read_remaining: 0,
            padding_remaining: 0,
            write_padding: 0,
            write_pending: None,
        }
    }

    fn poll_discard(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.padding_remaining > 0 {
            let mut scratch = [0_u8; 256];
            let length = self.padding_remaining.min(scratch.len());
            let mut buffer = ReadBuf::new(&mut scratch[..length]);
            match Pin::new(&mut self.inner).poll_read(context, &mut buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated NaiveProxy padding",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    self.padding_remaining -= buffer.filled().len();
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for PaddingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.read_remaining > 0 {
                let length = self.read_remaining.min(output.remaining());
                let mut scratch = vec![0_u8; length];
                let mut buffer = ReadBuf::new(&mut scratch);
                match Pin::new(&mut self.inner).poll_read(context, &mut buffer)
                {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated NaiveProxy payload",
                        )));
                    }
                    Poll::Ready(Ok(())) => {
                        let length = buffer.filled().len();
                        output.put_slice(buffer.filled());
                        self.read_remaining -= length;
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            match self.poll_discard(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            if self.read_padding >= PADDING_COUNT {
                return Pin::new(&mut self.inner).poll_read(context, output);
            }
            while self.read_header_pos < 3 {
                let position = self.read_header_pos;
                let mut byte = [0_u8; 1];
                let mut buffer = ReadBuf::new(&mut byte);
                match Pin::new(&mut self.inner).poll_read(context, &mut buffer)
                {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated NaiveProxy padding header",
                        )));
                    }
                    Poll::Ready(Ok(())) => {
                        self.read_header[position] = byte[0];
                        self.read_header_pos += 1;
                    }
                }
            }
            self.read_remaining = usize::from(u16::from_be_bytes([
                self.read_header[0],
                self.read_header[1],
            ]));
            self.padding_remaining = usize::from(self.read_header[2]);
            self.read_header_pos = 0;
            self.read_padding += 1;
            if self.read_remaining == 0 {
                continue;
            }
        }
    }
}

impl AsyncWrite for PaddingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_pending.is_none() {
            if self.write_padding >= PADDING_COUNT {
                return Pin::new(&mut self.inner).poll_write(context, input);
            }
            if input.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let length = input.len().min(MAX_PADDING_CHUNK_SIZE);
            let mut random = [0_u8; 1];
            if let Err(error) = getrandom::fill(&mut random) {
                return Poll::Ready(Err(io::Error::other(error.to_string())));
            }
            let padding = usize::from(random[0]);
            let mut frame = Vec::with_capacity(3 + length + padding);
            frame.extend_from_slice(&(length as u16).to_be_bytes());
            frame.push(random[0]);
            frame.extend_from_slice(&input[..length]);
            frame.resize(frame.len() + padding, 0);
            self.write_pending = Some((frame, 0, length));
        }
        loop {
            let (frame, offset, _) = self.write_pending.as_ref().unwrap();
            let slice = frame[*offset..].to_vec();
            match Pin::new(&mut self.inner).poll_write(context, &slice) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write NaiveProxy frame returned zero",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    let pending = self.write_pending.as_mut().unwrap();
                    pending.1 += written;
                    if pending.1 == pending.0.len() {
                        let (_, _, input_length) =
                            self.write_pending.take().unwrap();
                        self.write_padding += 1;
                        return Poll::Ready(Ok(input_length));
                    }
                }
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[test]
    fn http2_tuning_matches_cronet_pool_and_window_defaults() {
        let configured = NaiveOutbound::new_with_options(
            (),
            SocksAddr::new("proxy.example", 443),
            "",
            "",
            HashMap::new(),
            3,
            Some(8 * 1024 * 1024),
        )
        .unwrap();
        assert_eq!(configured.insecure_concurrency, 3);
        assert_eq!(configured.http2_session_receive_window, 8 * 1024 * 1024);
        assert_eq!(configured.http2_stream_receive_window, 4 * 1024 * 1024);
        assert_eq!(
            (0..6)
                .map(|_| configured.next_pool_index())
                .collect::<Vec<_>>(),
            vec![1, 2, 0, 1, 2, 0]
        );

        let defaulted = NaiveOutbound::new_with_options(
            (),
            SocksAddr::new("proxy.example", 443),
            "",
            "",
            HashMap::new(),
            -1,
            None,
        )
        .unwrap();
        assert_eq!(defaulted.insecure_concurrency, 1);
        #[cfg(target_os = "ios")]
        assert_eq!(defaulted.http2_session_receive_window, 4 * 1024 * 1024);
        #[cfg(not(target_os = "ios"))]
        assert_eq!(defaulted.http2_session_receive_window, 128 * 1024 * 1024);
    }

    #[test]
    fn http2_receive_window_rejects_values_outside_the_wire_limit() {
        let result = NaiveOutbound::new_with_options(
            (),
            SocksAddr::new("proxy.example", 443),
            "",
            "",
            HashMap::new(),
            1,
            Some(0x8000_0000),
        );
        let error = match result {
            Ok(_) => {
                panic!("oversized HTTP/2 flow-control window was accepted")
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn http3_accepts_every_upstream_congestion_controller() {
        for congestion_control in ["", "bbr", "bbr2", "cubic", "reno"] {
            NaiveHttp3Outbound::new(
                SocksAddr::new("proxy.example", 443),
                "proxy.example",
                "",
                "",
                HashMap::new(),
                crate::common::tls::build_client_config(
                    "proxy.example",
                    &crate::option::OutboundTlsOptions::default(),
                    &["h3"],
                )
                .unwrap(),
                None,
                None,
                congestion_control,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "failed to construct Naive HTTP/3 with {congestion_control:?}: {error}"
                )
            });
        }
    }

    #[tokio::test]
    async fn first_eight_writes_are_padded_and_round_trip() {
        let (left, right) = tokio::io::duplex(256 * 1024);
        let mut writer = PaddingStream::new(Box::new(left));
        let mut reader = PaddingStream::new(Box::new(right));
        let send = tokio::spawn(async move {
            for index in 0..10_u8 {
                writer.write_all(&[index; 17]).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });
        for index in 0..10_u8 {
            let mut payload = [0_u8; 17];
            reader.read_exact(&mut payload).await.unwrap();
            assert_eq!(payload, [index; 17]);
        }
        send.await.unwrap();
    }

    #[tokio::test]
    async fn client_and_server_connect_handshakes_interoperate() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let users = vec![User {
            username: "alice".into(),
            password: "secret".into(),
        }];
        let task = tokio::spawn(async move {
            server_handshake(&mut server, &users).await.unwrap()
        });
        client_handshake(
            &mut client,
            &SocksAddr::new("proxy.example", 443),
            &SocksAddr::new("target.example", 80),
            Some(("alice", "secret")),
            &std::collections::HashMap::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            task.await.unwrap(),
            (SocksAddr::new("target.example", 80), "alice".into())
        );
    }
}
