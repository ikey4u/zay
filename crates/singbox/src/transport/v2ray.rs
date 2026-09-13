//! V2Ray-compatible stream transports.

use std::{
    convert::Infallible,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt as _, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Request as HttpRequest, Response as HttpResponse, StatusCode,
    body::{Frame, Incoming},
    client::conn::http2 as client_http2,
    server::conn::http2 as server_http2,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use n0_watcher::Watcher as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async, client_async,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        handshake::server::{Request, Response},
        http::{HeaderName, HeaderValue},
    },
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{DialFuture, Dialer, Stream},
    common::network::SocksAddr,
    option::{
        V2RayGrpcOptions, V2RayHttpOptions, V2RayHttpUpgradeOptions,
        V2RayTransportOptions, V2RayWebsocketOptions,
    },
};

pub struct GrpcDialer {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    options: V2RayGrpcOptions,
    http2: Arc<Http2ClientPool>,
}

type H2SendRequest = client_http2::SendRequest<GrpcBody>;

struct Http2ClientSession {
    sender: H2SendRequest,
    driver: tokio::task::JoinHandle<Result<(), hyper::Error>>,
    socket: Option<crate::adapter::StreamSocket>,
}

impl Drop for Http2ClientSession {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

struct Http2ClientPool {
    state: Arc<tokio::sync::Mutex<Option<Http2ClientSession>>>,
    monitor_started: Arc<AtomicBool>,
    cancellation: CancellationToken,
}

impl Default for Http2ClientPool {
    fn default() -> Self {
        Self {
            state: Arc::new(tokio::sync::Mutex::new(None)),
            monitor_started: Arc::new(AtomicBool::new(false)),
            cancellation: CancellationToken::new(),
        }
    }
}

impl Http2ClientPool {
    async fn sender(
        &self,
        upstream: &Arc<dyn Dialer>,
        server: &SocksAddr,
        idle_timeout: crate::option::Duration,
        ping_timeout: crate::option::Duration,
        permit_without_stream: bool,
        default_ping_timeout: std::time::Duration,
    ) -> io::Result<(H2SendRequest, Option<crate::adapter::StreamSocket>)> {
        self.ensure_network_monitor();
        let mut state = self.state.lock().await;
        if state.as_ref().is_some_and(|session| {
            !session.driver.is_finished() && !session.sender.is_closed()
        }) {
            let session = state.as_ref().expect("HTTP/2 session exists");
            return Ok((session.sender.clone(), session.socket));
        }
        state.take();
        let stream = upstream.dial_tcp(server).await?;
        let socket = crate::adapter::stream_socket(&stream);
        let mut builder = client_http2::Builder::new(TokioExecutor::new());
        configure_client_keepalive(
            &mut builder,
            idle_timeout,
            ping_timeout,
            permit_without_stream,
            default_ping_timeout,
        );
        let (sender, connection) = builder
            .handshake(TokioIo::new(stream))
            .await
            .map_err(io::Error::other)?;
        let session = Http2ClientSession {
            sender: sender.clone(),
            driver: tokio::spawn(connection),
            socket,
        };
        *state = Some(session);
        Ok((sender, socket))
    }

    async fn reset(&self) {
        self.state.lock().await.take();
    }

    fn ensure_network_monitor(&self) {
        if self
            .monitor_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let state = self.state.clone();
        let started = self.monitor_started.clone();
        let cancellation = self.cancellation.clone();
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
}

impl Drop for Http2ClientPool {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut state) = self.state.try_lock() {
            state.take();
        }
    }
}

impl GrpcDialer {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        options: V2RayGrpcOptions,
    ) -> io::Result<Self> {
        validate_grpc_options(&options)?;
        Ok(Self {
            upstream,
            server,
            options,
            http2: Arc::new(Http2ClientPool::default()),
        })
    }
}

impl Dialer for GrpcDialer {
    fn dial_tcp<'a>(&'a self, _destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            for attempt in 0..2 {
                let (sender, socket) = self
                    .http2
                    .sender(
                        &self.upstream,
                        &self.server,
                        self.options.idle_timeout,
                        self.options.ping_timeout,
                        self.options.permit_without_stream,
                        std::time::Duration::from_secs(20),
                    )
                    .await?;
                match open_grpc_stream(sender, &self.server, &self.options)
                    .await
                {
                    Ok(stream) => {
                        return Ok(crate::adapter::preserve_stream_socket(
                            stream, socket,
                        ));
                    }
                    Err(error) if attempt == 0 => {
                        self.http2.reset().await;
                        tracing::debug!(%error, "retry V2Ray gRPC on a fresh HTTP/2 connection");
                    }
                    Err(error) => return Err(error),
                }
            }
            unreachable!("bounded HTTP/2 retry loop")
        })
    }
}

pub struct HttpDialer {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    options: V2RayHttpOptions,
    http2: bool,
    http2_pool: Arc<Http2ClientPool>,
}

pub struct WebsocketDialer {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    options: V2RayWebsocketOptions,
}

pub struct HttpUpgradeDialer {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    options: V2RayHttpUpgradeOptions,
}

impl HttpDialer {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        options: V2RayHttpOptions,
    ) -> io::Result<Self> {
        validate_http_options(&options)?;
        Ok(Self {
            upstream,
            server,
            options,
            http2: false,
            http2_pool: Arc::new(Http2ClientPool::default()),
        })
    }

    pub fn new_http2(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        options: V2RayHttpOptions,
    ) -> io::Result<Self> {
        validate_http_options(&options)?;
        Ok(Self {
            upstream,
            server,
            options,
            http2: true,
            http2_pool: Arc::new(Http2ClientPool::default()),
        })
    }
}

impl Dialer for HttpDialer {
    fn dial_tcp<'a>(&'a self, _destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            if self.http2 {
                for attempt in 0..2 {
                    let (sender, socket) = self
                        .http2_pool
                        .sender(
                            &self.upstream,
                            &self.server,
                            self.options.idle_timeout,
                            self.options.ping_timeout,
                            true,
                            std::time::Duration::from_secs(15),
                        )
                        .await?;
                    match open_http2_stream(sender, &self.server, &self.options)
                        .await
                    {
                        Ok(stream) => {
                            return Ok(crate::adapter::preserve_stream_socket(
                                stream, socket,
                            ));
                        }
                        Err(error) if attempt == 0 => {
                            self.http2_pool.reset().await;
                            tracing::debug!(%error, "retry V2Ray HTTP/2 on a fresh connection");
                        }
                        Err(error) => return Err(error),
                    }
                }
                unreachable!("bounded HTTP/2 retry loop")
            }
            let stream = self.upstream.dial_tcp(&self.server).await?;
            let socket = crate::adapter::stream_socket(&stream);
            let stream =
                connect_http(stream, &self.server, &self.options).await?;
            Ok(crate::adapter::preserve_stream_socket(stream, socket))
        })
    }
}

impl HttpUpgradeDialer {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        options: V2RayHttpUpgradeOptions,
    ) -> io::Result<Self> {
        validate_header_map(&options.headers)?;
        Ok(Self {
            upstream,
            server,
            options,
        })
    }
}

impl Dialer for HttpUpgradeDialer {
    fn dial_tcp<'a>(&'a self, _destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let stream = self.upstream.dial_tcp(&self.server).await?;
            let socket = crate::adapter::stream_socket(&stream);
            let stream =
                connect_http_upgrade(stream, &self.server, &self.options)
                    .await?;
            Ok(crate::adapter::preserve_stream_socket(stream, socket))
        })
    }
}

impl WebsocketDialer {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        options: V2RayWebsocketOptions,
    ) -> io::Result<Self> {
        validate_websocket_options(&options)?;
        Ok(Self {
            upstream,
            server,
            options,
        })
    }
}

impl Dialer for WebsocketDialer {
    fn dial_tcp<'a>(&'a self, _destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let stream = self.upstream.dial_tcp(&self.server).await?;
            let socket = crate::adapter::stream_socket(&stream);
            let stream =
                connect_websocket(stream, &self.server, &self.options).await?;
            Ok(crate::adapter::preserve_stream_socket(stream, socket))
        })
    }
}

pub async fn connect_websocket(
    stream: Stream,
    server: &SocksAddr,
    options: &V2RayWebsocketOptions,
) -> io::Result<Stream> {
    validate_websocket_options(options)?;
    if options.max_early_data > 0 {
        return Ok(early_websocket_byte_stream(
            stream,
            server.clone(),
            options.clone(),
        ));
    }
    connect_websocket_now(stream, server, options, &[]).await
}

async fn connect_websocket_now(
    stream: Stream,
    server: &SocksAddr,
    options: &V2RayWebsocketOptions,
    early_data: &[u8],
) -> io::Result<Stream> {
    let path = normalized_path(&options.path);
    let authority = server.to_string();
    let encoded = URL_SAFE_NO_PAD.encode(early_data);
    let request_path = if early_data.is_empty()
        || !options.early_data_header_name.is_empty()
    {
        path
    } else {
        append_path_suffix(&path, &encoded)
    };
    let uri = format!("ws://{authority}{request_path}");
    let mut request = uri.into_client_request().map_err(io::Error::other)?;
    request
        .headers_mut()
        .insert("User-Agent", HeaderValue::from_static("Go-http-client/1.1"));
    apply_headers(request.headers_mut(), &options.headers)?;
    if !early_data.is_empty() && !options.early_data_header_name.is_empty() {
        let name =
            HeaderName::try_from(options.early_data_header_name.as_str())
                .map_err(io::Error::other)?;
        let value = HeaderValue::try_from(encoded).map_err(io::Error::other)?;
        request.headers_mut().insert(name, value);
    }
    let (websocket, _) = client_async(request, stream)
        .await
        .map_err(io::Error::other)?;
    Ok(websocket_byte_stream(websocket))
}

#[allow(clippy::result_large_err)]
pub async fn accept_websocket(
    stream: Stream,
    options: &V2RayWebsocketOptions,
) -> io::Result<Stream> {
    validate_websocket_options(options)?;
    let path = normalized_path(&options.path);
    let headers = options.headers.clone();
    let max_early_data = options.max_early_data;
    let early_header = options.early_data_header_name.clone();
    let early_data = Arc::new(StdMutex::new(Vec::new()));
    let captured_early_data = early_data.clone();
    let websocket = accept_hdr_async(
        stream,
        move |request: &Request, mut response: Response| {
            let request_uri = request
                .uri()
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or_else(|| request.uri().path());
            let encoded = if early_header.is_empty() {
                if max_early_data == 0 {
                    if request.uri().path() != path {
                        return Err(websocket_rejection(
                            404,
                            "bad websocket path",
                        ));
                    }
                    ""
                } else if let Some(suffix) = request_uri.strip_prefix(&path) {
                    suffix
                } else {
                    return Err(websocket_rejection(404, "bad websocket path"));
                }
            } else {
                if request.uri().path() != path {
                    return Err(websocket_rejection(404, "bad websocket path"));
                }
                request
                    .headers()
                    .get(early_header.as_str())
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
            };
            let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(decoded) => decoded,
                Err(_) => {
                    return Err(websocket_rejection(
                        400,
                        "invalid websocket early data",
                    ));
                }
            };
            if let Ok(mut destination) = captured_early_data.lock() {
                *destination = decoded;
            } else {
                return Err(websocket_rejection(
                    500,
                    "websocket early data lock failed",
                ));
            }
            if early_header.eq_ignore_ascii_case("Sec-WebSocket-Protocol")
                && let Some(protocol) =
                    request.headers().get("Sec-WebSocket-Protocol").cloned()
            {
                response
                    .headers_mut()
                    .insert("Sec-WebSocket-Protocol", protocol);
            }
            if apply_headers(response.headers_mut(), &headers).is_err() {
                return Err(
                    tokio_tungstenite::tungstenite::http::Response::builder()
                        .status(400)
                        .body(Some(
                            "invalid websocket response header".to_owned(),
                        ))
                        .expect("fixed websocket rejection"),
                );
            }
            Ok(response)
        },
    )
    .await
    .map_err(io::Error::other)?;
    let early_data = early_data
        .lock()
        .map_err(|_| io::Error::other("websocket early data lock failed"))?
        .clone();
    let stream = websocket_byte_stream(websocket);
    if early_data.is_empty() {
        Ok(stream)
    } else {
        Ok(Box::new(PrefixedStream {
            prefix: early_data,
            offset: 0,
            inner: stream,
        }))
    }
}

pub async fn connect_http_upgrade(
    mut stream: Stream,
    server: &SocksAddr,
    options: &V2RayHttpUpgradeOptions,
) -> io::Result<Stream> {
    validate_header_map(&options.headers)?;
    let path = normalized_path(&options.path);
    let host = if options.host.is_empty() {
        server.to_string()
    } else {
        options.host.clone()
    };
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
    );
    append_raw_headers(&mut request, &options.headers)?;
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let response = read_http_head(&mut stream).await?;
    let mut lines = response.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 101 ") && status != "HTTP/1.1 101" {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("unexpected V2Ray HTTPUpgrade response: {status}"),
        ));
    }
    let headers = parsed_headers(lines)?;
    if !header_has_token(&headers, "connection", "upgrade")
        || !header_has_token(&headers, "upgrade", "websocket")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid V2Ray HTTPUpgrade response headers",
        ));
    }
    Ok(stream)
}

/// Establish the HTTP/1.1 variant of the V2Ray HTTP stream transport.
///
/// The Go implementation delays this preface until the first application
/// write so it can coalesce that payload with the request. Sending the
/// request immediately is wire-compatible and avoids hiding handshake
/// failures behind the first protocol write.
pub async fn connect_http(
    mut stream: Stream,
    server: &SocksAddr,
    options: &V2RayHttpOptions,
) -> io::Result<Stream> {
    validate_http_options(options)?;
    let method = if options.method.is_empty() {
        "PUT"
    } else {
        options.method.as_str()
    };
    let path = normalized_path(&options.path);
    let host = options
        .host
        .as_slice()
        .first()
        .cloned()
        .unwrap_or_else(|| server.to_string());
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Go-http-client/1.1\r\n"
    );
    append_raw_headers(&mut request, &options.headers)?;
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let response = read_http_head(&mut stream).await?;
    let status = response.split("\r\n").next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 200 ") && status != "HTTP/1.1 200" {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("unexpected V2Ray HTTP response: {status}"),
        ));
    }
    Ok(stream)
}

pub async fn accept_http(
    mut stream: Stream,
    options: &V2RayHttpOptions,
) -> io::Result<Stream> {
    validate_http_options(options)?;
    let request = read_http_head(&mut stream).await?;
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    let headers = parsed_headers(lines)?;
    let request_path = target.split('?').next().unwrap_or_default();
    let configured_path = normalized_path(&options.path);
    let host_matches = options.host.as_slice().is_empty()
        || headers.get("host").is_some_and(|host| {
            options
                .host
                .as_slice()
                .iter()
                .any(|allowed| allowed == host)
        });
    let method_matches = options.method.is_empty() || options.method == method;
    if version != "HTTP/1.1"
        || !request_path
            .starts_with(configured_path.split('?').next().unwrap_or_default())
        || !host_matches
        || !method_matches
    {
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid V2Ray HTTP request",
        ));
    }
    let mut response =
        String::from("HTTP/1.1 200 OK\r\nCache-Control: no-store\r\n");
    append_raw_headers(&mut response, &options.headers)?;
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(stream)
}

pub async fn accept_http_upgrade(
    mut stream: Stream,
    options: &V2RayHttpUpgradeOptions,
) -> io::Result<Stream> {
    validate_header_map(&options.headers)?;
    let request = read_http_head(&mut stream).await?;
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    let path = target.split('?').next().unwrap_or_default();
    let headers = parsed_headers(lines)?;
    let host_matches = options.host.is_empty()
        || headers
            .get("host")
            .is_some_and(|value| value == &options.host);
    let valid = method == "GET"
        && version == "HTTP/1.1"
        && path == normalized_path(&options.path)
        && host_matches
        && header_has_token(&headers, "connection", "upgrade")
        && header_has_token(&headers, "upgrade", "websocket")
        && !headers.contains_key("sec-websocket-key");
    if !valid {
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid V2Ray HTTPUpgrade request",
        ));
    }
    let mut response = String::from(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
    );
    append_raw_headers(&mut response, &options.headers)?;
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(stream)
}

pub async fn connect_http2(
    stream: Stream,
    server: &SocksAddr,
    options: &V2RayHttpOptions,
) -> io::Result<Stream> {
    validate_http_options(options)?;
    let mut builder = client_http2::Builder::new(TokioExecutor::new());
    configure_client_keepalive(
        &mut builder,
        options.idle_timeout,
        options.ping_timeout,
        true,
        std::time::Duration::from_secs(15),
    );
    let (sender, connection) = builder
        .handshake(TokioIo::new(stream))
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    open_http2_stream(sender, server, options).await
}

async fn open_http2_stream(
    mut sender: H2SendRequest,
    server: &SocksAddr,
    options: &V2RayHttpOptions,
) -> io::Result<Stream> {
    let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Bytes>(16);
    let method = if options.method.is_empty() {
        "PUT"
    } else {
        options.method.as_str()
    };
    let host = options
        .host
        .as_slice()
        .first()
        .cloned()
        .unwrap_or_else(|| "www.example.com".to_owned());
    let mut request = HttpRequest::builder()
        .method(method)
        .uri(normalized_path(&options.path))
        .header("Host", host)
        .body(grpc_body(body_rx))
        .map_err(io::Error::other)?;
    apply_headers(request.headers_mut(), &options.headers)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(io::Error::other)?;
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("unexpected V2Ray HTTP/2 status: {}", response.status()),
        ));
    }
    let (application, bridge) = tokio::io::duplex(32 * 1024);
    tokio::spawn(raw_http2_client_bridge(
        bridge,
        response.into_body(),
        body_tx,
    ));
    let _ = server;
    Ok(Box::new(application))
}

pub async fn accept_http2(
    stream: Stream,
    options: &V2RayHttpOptions,
) -> io::Result<Stream> {
    let mut streams = accept_http2_streams(stream, options)?;
    streams.recv().await.unwrap_or_else(|| {
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "V2Ray HTTP/2 connection closed before a stream was accepted",
        ))
    })
}

fn accept_http2_streams(
    stream: Stream,
    options: &V2RayHttpOptions,
) -> io::Result<TransportStreamReceiver> {
    validate_http_options(options)?;
    let options = options.clone();
    let (accepted_tx, accepted_rx) =
        tokio::sync::mpsc::channel::<io::Result<Stream>>(32);
    let service_sender = accepted_tx.clone();
    let service = service_fn(move |request: HttpRequest<Incoming>| {
        let options = options.clone();
        let service_sender = service_sender.clone();
        async move {
            let host = request
                .headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
                .or_else(|| {
                    request.uri().authority().map(|value| value.as_str())
                })
                .unwrap_or_default();
            let configured_path = normalized_path(&options.path);
            let host_matches = options.host.as_slice().is_empty()
                || options
                    .host
                    .as_slice()
                    .iter()
                    .any(|allowed| allowed == host);
            let method_matches = options.method.is_empty()
                || options.method.as_str() == request.method().as_str();
            let valid = request.uri().path().starts_with(
                configured_path.split('?').next().unwrap_or_default(),
            ) && host_matches
                && method_matches;
            if !valid {
                let _ = service_sender
                    .send(Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "invalid V2Ray HTTP/2 request",
                    )))
                    .await;
                return Ok::<_, Infallible>(
                    HttpResponse::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(empty_grpc_body())
                        .expect("fixed HTTP/2 rejection response"),
                );
            }
            let (application, bridge) = tokio::io::duplex(32 * 1024);
            if service_sender
                .send(Ok(Box::new(application)))
                .await
                .is_err()
            {
                return Ok::<_, Infallible>(
                    HttpResponse::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(empty_grpc_body())
                        .expect("fixed unavailable HTTP/2 response"),
                );
            }
            let (body_tx, body_rx) = tokio::sync::mpsc::channel(16);
            tokio::spawn(raw_http2_server_bridge(
                bridge,
                request.into_body(),
                body_tx,
            ));
            let mut response = HttpResponse::builder()
                .status(StatusCode::OK)
                .header("Cache-Control", "no-store")
                .body(grpc_body(body_rx))
                .expect("fixed HTTP/2 response");
            if apply_headers(response.headers_mut(), &options.headers).is_err()
            {
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            }
            Ok::<_, Infallible>(response)
        }
    });
    let connection_sender = accepted_tx;
    tokio::spawn(async move {
        if let Err(error) = server_http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
        {
            let _ = connection_sender.send(Err(io::Error::other(error))).await;
        }
    });
    Ok(accepted_rx)
}

async fn raw_http2_client_bridge(
    bridge: tokio::io::DuplexStream,
    response: Incoming,
    outgoing: tokio::sync::mpsc::Sender<Bytes>,
) {
    let (reader, writer) = tokio::io::split(bridge);
    let _ = tokio::join!(
        raw_encode_stream(reader, outgoing),
        raw_decode_body(response, writer),
    );
}

async fn raw_http2_server_bridge(
    bridge: tokio::io::DuplexStream,
    request: Incoming,
    outgoing: tokio::sync::mpsc::Sender<Bytes>,
) {
    let (reader, writer) = tokio::io::split(bridge);
    let _ = tokio::join!(
        raw_encode_stream(reader, outgoing),
        raw_decode_body(request, writer),
    );
}

async fn raw_encode_stream<R>(
    mut reader: R,
    outgoing: tokio::sync::mpsc::Sender<Bytes>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut data = vec![0_u8; 16 * 1024];
    loop {
        let size = reader.read(&mut data).await?;
        if size == 0 {
            return Ok(());
        }
        if outgoing
            .send(Bytes::copy_from_slice(&data[..size]))
            .await
            .is_err()
        {
            return Ok(());
        }
    }
}

async fn raw_decode_body<W>(mut body: Incoming, mut writer: W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(io::Error::other)?;
        if let Ok(data) = frame.into_data() {
            writer.write_all(&data).await?;
        }
    }
    writer.shutdown().await
}

type GrpcBody = UnsyncBoxBody<Bytes, Infallible>;

pub async fn connect_grpc(
    stream: Stream,
    server: &SocksAddr,
    options: &V2RayGrpcOptions,
) -> io::Result<Stream> {
    validate_grpc_options(options)?;
    let mut builder = client_http2::Builder::new(TokioExecutor::new());
    configure_client_keepalive(
        &mut builder,
        options.idle_timeout,
        options.ping_timeout,
        options.permit_without_stream,
        std::time::Duration::from_secs(20),
    );
    let (sender, connection) = builder
        .handshake(TokioIo::new(stream))
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    open_grpc_stream(sender, server, options).await
}

async fn open_grpc_stream(
    mut sender: H2SendRequest,
    server: &SocksAddr,
    options: &V2RayGrpcOptions,
) -> io::Result<Stream> {
    let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Bytes>(16);
    let body = grpc_body(body_rx);
    let path = grpc_path(&options.service_name);
    let request = HttpRequest::builder()
        .method("POST")
        .uri(path)
        .header("Host", server.to_string())
        .header("Content-Type", "application/grpc")
        .header("User-Agent", "grpc-go/1.48.0")
        .header("TE", "trailers")
        .body(body)
        .map_err(io::Error::other)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(io::Error::other)?;
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("unexpected V2Ray gRPC status: {}", response.status()),
        ));
    }

    let (application, bridge) = tokio::io::duplex(32 * 1024);
    tokio::spawn(grpc_client_bridge(bridge, response.into_body(), body_tx));
    Ok(Box::new(application))
}

pub async fn accept_grpc(
    stream: Stream,
    options: &V2RayGrpcOptions,
) -> io::Result<Stream> {
    let mut streams = accept_grpc_streams(stream, options)?;
    streams.recv().await.unwrap_or_else(|| {
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "V2Ray gRPC connection closed before a stream was accepted",
        ))
    })
}

fn accept_grpc_streams(
    stream: Stream,
    options: &V2RayGrpcOptions,
) -> io::Result<TransportStreamReceiver> {
    validate_grpc_options(options)?;
    let expected_path = grpc_path(&options.service_name);
    let (accepted_tx, accepted_rx) =
        tokio::sync::mpsc::channel::<io::Result<Stream>>(32);
    let service_sender = accepted_tx.clone();
    let service = service_fn(move |request: HttpRequest<Incoming>| {
        let expected_path = expected_path.clone();
        let service_sender = service_sender.clone();
        async move {
            let content_type = request
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let valid = request.method() == "POST"
                && request.uri().path() == expected_path
                && content_type.starts_with("application/grpc");
            if !valid {
                let _ = service_sender
                    .send(Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "invalid V2Ray gRPC request",
                    )))
                    .await;
                return Ok::<_, Infallible>(
                    HttpResponse::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(empty_grpc_body())
                        .expect("fixed gRPC rejection response"),
                );
            }

            let (application, bridge) = tokio::io::duplex(32 * 1024);
            if service_sender
                .send(Ok(Box::new(application)))
                .await
                .is_err()
            {
                return Ok::<_, Infallible>(
                    HttpResponse::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(empty_grpc_body())
                        .expect("fixed unavailable gRPC response"),
                );
            }
            let (body_tx, body_rx) = tokio::sync::mpsc::channel(16);
            tokio::spawn(grpc_server_bridge(
                bridge,
                request.into_body(),
                body_tx,
            ));
            Ok::<_, Infallible>(
                HttpResponse::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/grpc")
                    .header("TE", "trailers")
                    .body(grpc_body(body_rx))
                    .expect("fixed gRPC response"),
            )
        }
    });
    let mut builder = server_http2::Builder::new(TokioExecutor::new());
    configure_server_keepalive(
        &mut builder,
        options.idle_timeout,
        options.ping_timeout,
    );
    let connection_sender = accepted_tx;
    tokio::spawn(async move {
        if let Err(error) = builder
            .serve_connection(TokioIo::new(stream), service)
            .await
        {
            let _ = connection_sender.send(Err(io::Error::other(error))).await;
        }
    });
    Ok(accepted_rx)
}

fn grpc_body(receiver: tokio::sync::mpsc::Receiver<Bytes>) -> GrpcBody {
    let stream =
        futures_util::stream::unfold(receiver, |mut receiver| async move {
            receiver.recv().await.map(|bytes| {
                (Ok::<_, Infallible>(Frame::data(bytes)), receiver)
            })
        });
    StreamBody::new(stream).boxed_unsync()
}

fn empty_grpc_body() -> GrpcBody {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    drop(sender);
    grpc_body(receiver)
}

fn configure_client_keepalive(
    builder: &mut client_http2::Builder<TokioExecutor>,
    idle_timeout: crate::option::Duration,
    ping_timeout: crate::option::Duration,
    permit_without_stream: bool,
    default_ping_timeout: std::time::Duration,
) {
    let Some(idle_timeout) =
        idle_timeout.as_std().filter(|timeout| !timeout.is_zero())
    else {
        return;
    };
    builder
        .timer(TokioTimer::new())
        .keep_alive_interval(idle_timeout)
        .keep_alive_timeout(
            ping_timeout
                .as_std()
                .filter(|timeout| !timeout.is_zero())
                .unwrap_or(default_ping_timeout),
        )
        .keep_alive_while_idle(permit_without_stream);
}

fn configure_server_keepalive(
    builder: &mut server_http2::Builder<TokioExecutor>,
    idle_timeout: crate::option::Duration,
    ping_timeout: crate::option::Duration,
) {
    let Some(idle_timeout) =
        idle_timeout.as_std().filter(|timeout| !timeout.is_zero())
    else {
        return;
    };
    builder
        .timer(TokioTimer::new())
        .keep_alive_interval(idle_timeout)
        .keep_alive_timeout(
            ping_timeout
                .as_std()
                .filter(|timeout| !timeout.is_zero())
                .unwrap_or(std::time::Duration::from_secs(20)),
        );
}

async fn grpc_client_bridge(
    bridge: tokio::io::DuplexStream,
    response: Incoming,
    outgoing: tokio::sync::mpsc::Sender<Bytes>,
) {
    let (reader, writer) = tokio::io::split(bridge);
    let _ = tokio::join!(
        grpc_encode_stream(reader, outgoing),
        grpc_decode_body(response, writer),
    );
}

async fn grpc_server_bridge(
    bridge: tokio::io::DuplexStream,
    request: Incoming,
    outgoing: tokio::sync::mpsc::Sender<Bytes>,
) {
    let (reader, writer) = tokio::io::split(bridge);
    let _ = tokio::join!(
        grpc_encode_stream(reader, outgoing),
        grpc_decode_body(request, writer),
    );
}

async fn grpc_encode_stream<R>(
    mut reader: R,
    outgoing: tokio::sync::mpsc::Sender<Bytes>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut data = vec![0_u8; 16 * 1024];
    loop {
        let size = reader.read(&mut data).await?;
        if size == 0 {
            return Ok(());
        }
        if outgoing
            .send(Bytes::from(grpc_encode_message(&data[..size])))
            .await
            .is_err()
        {
            return Ok(());
        }
    }
}

async fn grpc_decode_body<W>(
    mut body: Incoming,
    mut writer: W,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut decoder = GrpcDecoder::default();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(io::Error::other)?;
        if let Ok(data) = frame.into_data() {
            decoder.push(&data);
            while let Some(message) = decoder.next_message()? {
                writer.write_all(&message).await?;
            }
        }
    }
    writer.shutdown().await
}

#[derive(Default)]
struct GrpcDecoder {
    buffer: Vec<u8>,
}

impl GrpcDecoder {
    fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn next_message(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.buffer.len() < 5 {
            return Ok(None);
        }
        if self.buffer[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed V2Ray gRPC messages are unsupported",
            ));
        }
        let frame_size = u32::from_be_bytes(
            self.buffer[1..5].try_into().expect("fixed slice"),
        ) as usize;
        if self.buffer.len() < 5 + frame_size {
            return Ok(None);
        }
        let frame = &self.buffer[5..5 + frame_size];
        if frame.first() != Some(&0x0a) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid V2Ray gRPC Hunk field",
            ));
        }
        let (data_size, varint_size) = decode_varint(&frame[1..])?;
        let start = 1 + varint_size;
        let end = start.checked_add(data_size as usize).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "gRPC Hunk is too large")
        })?;
        if end > frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated V2Ray gRPC Hunk",
            ));
        }
        let data = frame[start..end].to_vec();
        self.buffer.drain(..5 + frame_size);
        Ok(Some(data))
    }
}

fn grpc_encode_message(data: &[u8]) -> Vec<u8> {
    let mut length = Vec::with_capacity(10);
    encode_varint(data.len() as u64, &mut length);
    let protobuf_size = 1 + length.len() + data.len();
    let mut output = Vec::with_capacity(5 + protobuf_size);
    output.push(0);
    output.extend_from_slice(&(protobuf_size as u32).to_be_bytes());
    output.push(0x0a);
    output.extend_from_slice(&length);
    output.extend_from_slice(data);
    output
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn decode_varint(data: &[u8]) -> io::Result<(u64, usize)> {
    let mut value = 0_u64;
    for (index, byte) in data.iter().copied().take(10).enumerate() {
        if index == 9 && byte > 1 {
            break;
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid V2Ray gRPC varint",
    ))
}

fn grpc_path(service_name: &str) -> String {
    format!("/{service_name}/Tun")
}

pub fn validate_grpc_options(_options: &V2RayGrpcOptions) -> io::Result<()> {
    Ok(())
}

pub fn tls_alpn(
    transport: Option<&V2RayTransportOptions>,
) -> &'static [&'static str] {
    match transport {
        Some(V2RayTransportOptions::Http(_))
        | Some(V2RayTransportOptions::Grpc(_)) => &["h2"],
        Some(V2RayTransportOptions::Websocket(_))
        | Some(V2RayTransportOptions::HttpUpgrade(_)) => &["http/1.1"],
        Some(V2RayTransportOptions::Quic) => &["h3"],
        None => &[],
    }
}

pub fn validate_server_transport(
    transport: &V2RayTransportOptions,
) -> io::Result<()> {
    match transport {
        V2RayTransportOptions::Http(options) => validate_http_options(options),
        V2RayTransportOptions::Grpc(options) => validate_grpc_options(options),
        V2RayTransportOptions::Websocket(options) => {
            validate_websocket_options(options)
        }
        V2RayTransportOptions::HttpUpgrade(options) => {
            validate_header_map(&options.headers)
        }
        V2RayTransportOptions::Quic => Ok(()),
    }
}

pub async fn accept_transport(
    stream: Stream,
    transport: &V2RayTransportOptions,
    tls_enabled: bool,
) -> io::Result<Stream> {
    match transport {
        V2RayTransportOptions::Http(options) if tls_enabled => {
            accept_http2(stream, options).await
        }
        V2RayTransportOptions::Http(options) => {
            accept_http(stream, options).await
        }
        V2RayTransportOptions::Grpc(options) => {
            accept_grpc(stream, options).await
        }
        V2RayTransportOptions::Websocket(options) => {
            accept_websocket(stream, options).await
        }
        V2RayTransportOptions::HttpUpgrade(options) => {
            accept_http_upgrade(stream, options).await
        }
        V2RayTransportOptions::Quic => Ok(stream),
    }
}

pub type TransportStreamReceiver =
    tokio::sync::mpsc::Receiver<io::Result<Stream>>;

/// Accept all logical streams carried by one physical V2Ray transport.
/// HTTP/2 and gRPC can deliver many concurrent requests on the same TCP
/// connection; the remaining transports yield exactly one stream.
pub async fn accept_transport_streams(
    stream: Stream,
    transport: Option<&V2RayTransportOptions>,
    tls_enabled: bool,
) -> io::Result<TransportStreamReceiver> {
    match transport {
        Some(V2RayTransportOptions::Http(options)) if tls_enabled => {
            accept_http2_streams(stream, options)
        }
        Some(V2RayTransportOptions::Grpc(options)) => {
            accept_grpc_streams(stream, options)
        }
        transport => {
            let stream = match transport {
                Some(V2RayTransportOptions::Http(options)) => {
                    accept_http(stream, options).await?
                }
                Some(V2RayTransportOptions::Websocket(options)) => {
                    accept_websocket(stream, options).await?
                }
                Some(V2RayTransportOptions::HttpUpgrade(options)) => {
                    accept_http_upgrade(stream, options).await?
                }
                Some(V2RayTransportOptions::Quic) | None => stream,
                Some(V2RayTransportOptions::Grpc(_)) => {
                    unreachable!("gRPC handled above")
                }
            };
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            sender
                .send(Ok(stream))
                .await
                .expect("new transport receiver is alive");
            Ok(receiver)
        }
    }
}

pub fn validate_http_options(options: &V2RayHttpOptions) -> io::Result<()> {
    validate_header_map(&options.headers)?;
    if options
        .host
        .as_slice()
        .iter()
        .any(|host| host.contains(['\r', '\n']))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "V2Ray HTTP host contains a line break",
        ));
    }
    if options.method.contains(['\r', '\n', ' ']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid V2Ray HTTP method",
        ));
    }
    Ok(())
}

async fn read_http_head(stream: &mut Stream) -> io::Result<String> {
    const MAX_HEADER_SIZE: usize = 1 << 20;
    let mut data = Vec::with_capacity(1024);
    while !data.ends_with(b"\r\n\r\n") {
        if data.len() == MAX_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "V2Ray HTTPUpgrade header is too large",
            ));
        }
        data.push(stream.read_u8().await?);
    }
    String::from_utf8(data).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "HTTP header is not UTF-8")
    })
}

fn parsed_headers<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> io::Result<std::collections::HashMap<String, String>> {
    let mut output = std::collections::HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP header")
        })?;
        output
            .entry(name.trim().to_ascii_lowercase())
            .and_modify(|existing: &mut String| {
                existing.push(',');
                existing.push_str(value.trim());
            })
            .or_insert_with(|| value.trim().to_owned());
    }
    Ok(output)
}

fn header_has_token(
    headers: &std::collections::HashMap<String, String>,
    name: &str,
    token: &str,
) -> bool {
    headers.get(name).is_some_and(|value| {
        value
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case(token))
    })
}

fn validate_header_map(
    headers: &serde_json::Map<String, serde_json::Value>,
) -> io::Result<()> {
    let mut destination =
        tokio_tungstenite::tungstenite::http::HeaderMap::new();
    apply_headers(&mut destination, headers)
}

fn append_raw_headers(
    output: &mut String,
    headers: &serde_json::Map<String, serde_json::Value>,
) -> io::Result<()> {
    let mut validated = tokio_tungstenite::tungstenite::http::HeaderMap::new();
    apply_headers(&mut validated, headers)?;
    for (name, value) in &validated {
        output.push_str(name.as_str());
        output.push_str(": ");
        output.push_str(value.to_str().map_err(io::Error::other)?);
        output.push_str("\r\n");
    }
    Ok(())
}

pub fn validate_websocket_options(
    options: &V2RayWebsocketOptions,
) -> io::Result<()> {
    validate_header_map(&options.headers)?;
    if !options.early_data_header_name.is_empty() {
        HeaderName::try_from(options.early_data_header_name.as_str())
            .map_err(io::Error::other)?;
    }
    Ok(())
}

fn normalized_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

fn append_path_suffix(path: &str, suffix: &str) -> String {
    match path.split_once('?') {
        Some((path, query)) => format!("{path}{suffix}?{query}"),
        None => format!("{path}{suffix}"),
    }
}

fn websocket_rejection(
    status: u16,
    message: &str,
) -> tokio_tungstenite::tungstenite::handshake::server::ErrorResponse {
    tokio_tungstenite::tungstenite::http::Response::builder()
        .status(status)
        .body(Some(message.to_owned()))
        .expect("fixed websocket rejection")
}

fn apply_headers(
    destination: &mut tokio_tungstenite::tungstenite::http::HeaderMap,
    headers: &serde_json::Map<String, serde_json::Value>,
) -> io::Result<()> {
    for (name, value) in headers {
        let name =
            HeaderName::try_from(name.as_str()).map_err(io::Error::other)?;
        let values = match value {
            serde_json::Value::String(value) => vec![value.as_str()],
            serde_json::Value::Array(values) => values
                .iter()
                .map(|value| {
                    value.as_str().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "WebSocket header array must contain strings",
                        )
                    })
                })
                .collect::<io::Result<Vec<_>>>()?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "WebSocket header value must be a string or string array",
                ));
            }
        };
        destination.remove(&name);
        for value in values {
            destination.append(
                name.clone(),
                HeaderValue::try_from(value).map_err(io::Error::other)?,
            );
        }
    }
    Ok(())
}

fn websocket_byte_stream<S>(websocket: WebSocketStream<S>) -> Stream
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (application, bridge) = tokio::io::duplex(32 * 1024);
    let (mut bridge_reader, mut bridge_writer) = tokio::io::split(bridge);
    tokio::spawn(async move {
        let mut websocket = websocket;
        let mut outgoing = vec![0_u8; 16 * 1024];
        loop {
            tokio::select! {
                incoming = websocket.next() => match incoming {
                    Some(Ok(Message::Binary(data))) => {
                        if bridge_writer.write_all(&data).await.is_err() { break; }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if websocket.send(Message::Pong(data)).await.is_err() { break; }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => {}
                },
                read = bridge_reader.read(&mut outgoing) => match read {
                    Ok(0) | Err(_) => {
                        let _ = websocket.close(None).await;
                        break;
                    }
                    Ok(size) => {
                        if websocket.send(Message::Binary(outgoing[..size].to_vec().into())).await.is_err() { break; }
                    }
                }
            }
        }
        let _ = bridge_writer.shutdown().await;
    });
    Box::new(application)
}

fn early_websocket_byte_stream(
    stream: Stream,
    server: SocksAddr,
    options: V2RayWebsocketOptions,
) -> Stream {
    let (application, bridge) = tokio::io::duplex(32 * 1024);
    tokio::spawn(async move {
        let (mut bridge_reader, mut bridge_writer) = tokio::io::split(bridge);
        // A bounded buffer still honors max_early_data: sending fewer bytes is
        // valid, and prevents an untrusted configuration from allocating GiB.
        let capacity = usize::try_from(options.max_early_data)
            .unwrap_or(64 * 1024)
            .clamp(1, 64 * 1024);
        let mut early_data = vec![0_u8; capacity];
        let size = match bridge_reader.read(&mut early_data).await {
            Ok(size) => size,
            Err(_) => return,
        };
        early_data.truncate(size);
        let websocket =
            match connect_websocket_now(stream, &server, &options, &early_data)
                .await
            {
                Ok(stream) => stream,
                Err(_) => return,
            };
        let (mut websocket_reader, mut websocket_writer) =
            tokio::io::split(websocket);
        let client_to_server = async {
            tokio::io::copy(&mut bridge_reader, &mut websocket_writer).await
        };
        let server_to_client = async {
            tokio::io::copy(&mut websocket_reader, &mut bridge_writer).await
        };
        let _ = tokio::try_join!(client_to_server, server_to_client);
    });
    Box::new(application)
}

struct PrefixedStream {
    prefix: Vec<u8>,
    offset: usize,
    inner: Stream,
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() && buffer.remaining() > 0 {
            let size = buffer
                .remaining()
                .min(self.prefix.len().saturating_sub(self.offset));
            let end = self.offset + size;
            buffer.put_slice(&self.prefix[self.offset..end]);
            self.offset = end;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn websocket_client_and_server_form_a_byte_stream() {
        let options = V2RayWebsocketOptions {
            path: "/tunnel".into(),
            ..Default::default()
        };
        let (client, server) = tokio::io::duplex(4096);
        let server_options = options.clone();
        let server = tokio::spawn(async move {
            let mut stream =
                accept_websocket(Box::new(server), &server_options)
                    .await
                    .unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let mut client = connect_websocket(
            Box::new(client),
            &SocksAddr::new("example.test", 80),
            &options,
        )
        .await
        .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn websocket_path_early_data_forms_a_byte_stream() {
        websocket_early_data_round_trip("").await;
    }

    #[tokio::test]
    async fn websocket_header_early_data_forms_a_byte_stream() {
        websocket_early_data_round_trip("Sec-WebSocket-Protocol").await;
    }

    async fn websocket_early_data_round_trip(header: &str) {
        let options = V2RayWebsocketOptions {
            path: "/early".into(),
            max_early_data: 2048,
            early_data_header_name: header.into(),
            ..Default::default()
        };
        let (client, server) = tokio::io::duplex(4096);
        let server_options = options.clone();
        let server = tokio::spawn(async move {
            let mut stream =
                accept_websocket(Box::new(server), &server_options)
                    .await
                    .unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let mut client = connect_websocket(
            Box::new(client),
            &SocksAddr::new("example.test", 80),
            &options,
        )
        .await
        .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_upgrade_client_and_server_form_a_raw_byte_stream() {
        let options = V2RayHttpUpgradeOptions {
            path: "/upgrade".into(),
            ..Default::default()
        };
        let (client, server) = tokio::io::duplex(4096);
        let server_options = options.clone();
        let server = tokio::spawn(async move {
            let mut stream =
                accept_http_upgrade(Box::new(server), &server_options)
                    .await
                    .unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let mut client = connect_http_upgrade(
            Box::new(client),
            &SocksAddr::new("example.test", 80),
            &options,
        )
        .await
        .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_client_and_server_form_a_raw_byte_stream() {
        let options = V2RayHttpOptions {
            host: serde_json::from_value(serde_json::json!(["front.example"]))
                .unwrap(),
            path: "/tunnel".into(),
            ..Default::default()
        };
        let (client, server) = tokio::io::duplex(4096);
        let server_options = options.clone();
        let server = tokio::spawn(async move {
            let mut stream = accept_http(Box::new(server), &server_options)
                .await
                .unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let mut client = connect_http(
            Box::new(client),
            &SocksAddr::new("example.test", 80),
            &options,
        )
        .await
        .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http2_client_and_server_form_a_raw_byte_stream() {
        let options = V2RayHttpOptions {
            host: serde_json::from_value(serde_json::json!("front.example"))
                .unwrap(),
            path: "/tunnel".into(),
            idle_timeout: crate::option::Duration::from_nanos(50_000_000),
            ping_timeout: crate::option::Duration::from_nanos(50_000_000),
            ..Default::default()
        };
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_options = options.clone();
        let server = tokio::spawn(async move {
            let mut stream = accept_http2(Box::new(server), &server_options)
                .await
                .unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let mut client = connect_http2(
            Box::new(client),
            &SocksAddr::new("example.test", 443),
            &options,
        )
        .await
        .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn grpc_client_and_server_form_a_byte_stream() {
        let options = V2RayGrpcOptions {
            service_name: "GunService".into(),
            idle_timeout: crate::option::Duration::from_nanos(50_000_000),
            ping_timeout: crate::option::Duration::from_nanos(50_000_000),
            permit_without_stream: true,
        };
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_options = options.clone();
        let server = tokio::spawn(async move {
            let mut stream = accept_grpc(Box::new(server), &server_options)
                .await
                .unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let mut client = connect_grpc(
            Box::new(client),
            &SocksAddr::new("example.test", 443),
            &options,
        )
        .await
        .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http2_dialer_reuses_one_physical_connection_for_two_streams() {
        let options = V2RayHttpOptions {
            host: serde_json::from_value(serde_json::json!("front.example"))
                .unwrap(),
            path: "/pool".into(),
            ..Default::default()
        };
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_options = options.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut accepted =
                accept_http2_streams(Box::new(stream), &server_options)
                    .unwrap();
            for expected in [b"one!", b"two!"] {
                let mut stream = accepted.recv().await.unwrap().unwrap();
                let mut data = [0_u8; 4];
                stream.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, expected);
                stream.write_all(&data).await.unwrap();
            }
        });
        let upstream: Arc<dyn Dialer> = Arc::new(
            crate::protocol::direct::DirectOutbound::new(Default::default()),
        );
        let dialer =
            HttpDialer::new_http2(upstream, SocksAddr::from(address), options)
                .unwrap();
        for data in [b"one!", b"two!"] {
            let mut stream = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                dialer.dial_tcp(&SocksAddr::new("ignored.test", 80)),
            )
            .await
            .expect("pooled HTTP/2 dial timed out")
            .unwrap();
            stream.write_all(data).await.unwrap();
            let mut echoed = [0_u8; 4];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, data);
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn grpc_dialer_reuses_one_physical_connection_for_two_streams() {
        let options = V2RayGrpcOptions {
            service_name: "PooledGun".into(),
            ..Default::default()
        };
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_options = options.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut accepted =
                accept_grpc_streams(Box::new(stream), &server_options).unwrap();
            for expected in [b"one!", b"two!"] {
                let mut stream = accepted.recv().await.unwrap().unwrap();
                let mut data = [0_u8; 4];
                stream.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, expected);
                stream.write_all(&data).await.unwrap();
            }
        });
        let upstream: Arc<dyn Dialer> = Arc::new(
            crate::protocol::direct::DirectOutbound::new(Default::default()),
        );
        let dialer =
            GrpcDialer::new(upstream, SocksAddr::from(address), options)
                .unwrap();
        for data in [b"one!", b"two!"] {
            let mut stream = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                dialer.dial_tcp(&SocksAddr::new("ignored.test", 80)),
            )
            .await
            .expect("pooled gRPC dial timed out")
            .unwrap();
            stream.write_all(data).await.unwrap();
            let mut echoed = [0_u8; 4];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, data);
        }
        server.await.unwrap();
    }
}
