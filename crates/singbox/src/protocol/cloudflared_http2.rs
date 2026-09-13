//! Cloudflare Tunnel HTTP/2 edge request and response mapping.

use std::{
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode,
};
use http_body_util::{BodyExt as _, channel::Channel};
use hyper::{
    body::{Body as _, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf},
    sync::oneshot,
};
use tokio_util::sync::CancellationToken;

use super::cloudflared::{
    CLOUDFLARED_H2_HEADER_RESPONSE_META, CLOUDFLARED_H2_HEADER_RESPONSE_USER,
    CLOUDFLARED_H2_HEADER_TCP_SOURCE, CLOUDFLARED_H2_HEADER_UPGRADE,
    CLOUDFLARED_H2_RESPONSE_META_ORIGIN, CLOUDFLARED_H2_UPGRADE_CONFIGURATION,
    CLOUDFLARED_H2_UPGRADE_CONTROL_STREAM, CLOUDFLARED_H2_UPGRADE_WEBSOCKET,
    CLOUDFLARED_METADATA_HTTP_HEADER_PREFIX, CLOUDFLARED_METADATA_HTTP_HOST,
    CLOUDFLARED_METADATA_HTTP_METHOD, CLOUDFLARED_METADATA_HTTP_STATUS,
    CloudflaredConnectRequest, CloudflaredConnectionType, CloudflaredError,
    CloudflaredMetadata, CloudflaredRegistrationOptions,
    CloudflaredRegistrationResult, cloudflared_has_flow_connect_rate_limited,
    cloudflared_registration_rpc, is_cloudflared_control_response_header,
    is_cloudflared_websocket_client_header, serialize_cloudflared_headers,
};
use super::cloudflared_quic::CLOUDFLARED_REGISTRATION_TIMEOUT;
use super::cloudflared_supervisor::CloudflaredManagedConnection;

pub const CLOUDFLARED_H2_RESPONSE_META_EDGE: &str = r#"{"src":"cloudflared"}"#;
pub const CLOUDFLARED_H2_RESPONSE_META_EDGE_RATE_LIMITED: &str =
    r#"{"src":"cloudflared","flow_rate_limited":true}"#;
pub const CLOUDFLARED_H2_CONTENT_TYPE_SSE: &str = "text/event-stream";
pub const CLOUDFLARED_H2_CONTENT_TYPE_GRPC: &str = "application/grpc";
pub const CLOUDFLARED_H2_CONTENT_TYPE_NDJSON: &str = "application/x-ndjson";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflaredHttp2RequestKind {
    Control,
    Configuration,
    Data(CloudflaredConnectionType),
}

pub fn classify_cloudflared_http2_request<B>(
    request: &Request<B>,
) -> CloudflaredHttp2RequestKind {
    let upgrade = request
        .headers()
        .get(CLOUDFLARED_H2_HEADER_UPGRADE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if upgrade == CLOUDFLARED_H2_UPGRADE_CONTROL_STREAM {
        CloudflaredHttp2RequestKind::Control
    } else if upgrade == CLOUDFLARED_H2_UPGRADE_WEBSOCKET {
        CloudflaredHttp2RequestKind::Data(CloudflaredConnectionType::Websocket)
    } else if request
        .headers()
        .get(CLOUDFLARED_H2_HEADER_TCP_SOURCE)
        .is_some_and(|value| !value.is_empty())
    {
        CloudflaredHttp2RequestKind::Data(CloudflaredConnectionType::Tcp)
    } else if upgrade == CLOUDFLARED_H2_UPGRADE_CONFIGURATION {
        CloudflaredHttp2RequestKind::Configuration
    } else {
        CloudflaredHttp2RequestKind::Data(CloudflaredConnectionType::Http)
    }
}

pub fn decode_cloudflared_http2_connect_request<B>(
    request: &Request<B>,
    connection_type: CloudflaredConnectionType,
) -> CloudflaredConnectRequest {
    let host = request
        .headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri().authority().map(|value| value.as_str()))
        .unwrap_or_default();
    let destination = if connection_type == CloudflaredConnectionType::Tcp {
        host.to_owned()
    } else if request.uri().scheme().is_some()
        && request.uri().authority().is_some()
    {
        request.uri().to_string()
    } else {
        let path = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        format!("http://{host}{path}")
    };
    let mut metadata = vec![
        CloudflaredMetadata {
            key: CLOUDFLARED_METADATA_HTTP_METHOD.into(),
            value: request.method().as_str().into(),
        },
        CloudflaredMetadata {
            key: CLOUDFLARED_METADATA_HTTP_HOST.into(),
            value: host.into(),
        },
    ];
    for (name, value) in request.headers() {
        if name == CLOUDFLARED_H2_HEADER_UPGRADE
            || name == CLOUDFLARED_H2_HEADER_TCP_SOURCE
        {
            continue;
        }
        if let Ok(value) = value.to_str() {
            metadata.push(CloudflaredMetadata {
                key: format!(
                    "{CLOUDFLARED_METADATA_HTTP_HEADER_PREFIX}{}",
                    name.as_str()
                ),
                value: value.into(),
            });
        }
    }
    CloudflaredConnectRequest {
        destination,
        connection_type,
        metadata,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredHttp2ResponseHead {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub should_flush: bool,
}

pub fn encode_cloudflared_http2_response_head(
    response_error: Option<&str>,
    metadata: &[CloudflaredMetadata],
) -> Result<CloudflaredHttp2ResponseHead, CloudflaredError> {
    let mut headers = HeaderMap::new();
    if response_error.is_some() {
        let response_meta =
            if cloudflared_has_flow_connect_rate_limited(metadata) {
                CLOUDFLARED_H2_RESPONSE_META_EDGE_RATE_LIMITED
            } else {
                CLOUDFLARED_H2_RESPONSE_META_EDGE
            };
        headers.insert(
            CLOUDFLARED_H2_HEADER_RESPONSE_META,
            HeaderValue::from_static(response_meta),
        );
        return Ok(CloudflaredHttp2ResponseHead {
            status: StatusCode::BAD_GATEWAY,
            headers,
            should_flush: true,
        });
    }

    let mut status = StatusCode::OK;
    let mut user_headers = HeaderMap::new();
    for entry in metadata {
        if entry.key == CLOUDFLARED_METADATA_HTTP_STATUS {
            if let Ok(value) = entry.value.parse::<u16>()
                && let Ok(value) = StatusCode::from_u16(value)
            {
                status = value;
            }
            continue;
        }
        let Some(name) = entry
            .key
            .strip_prefix(CLOUDFLARED_METADATA_HTTP_HEADER_PREFIX)
        else {
            continue;
        };
        let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(header_value) = HeaderValue::from_str(&entry.value) else {
            continue;
        };
        if header_name == http::header::CONTENT_LENGTH {
            headers.insert(header_name.clone(), header_value.clone());
        }
        if !is_cloudflared_control_response_header(header_name.as_str())
            || is_cloudflared_websocket_client_header(header_name.as_str())
        {
            user_headers.append(header_name, header_value);
        }
    }
    headers.insert(
        CLOUDFLARED_H2_HEADER_RESPONSE_USER,
        HeaderValue::from_str(&serialize_cloudflared_headers(&user_headers))
            .map_err(|error| CloudflaredError::Transport(error.to_string()))?,
    );
    headers.insert(
        CLOUDFLARED_H2_HEADER_RESPONSE_META,
        HeaderValue::from_static(CLOUDFLARED_H2_RESPONSE_META_ORIGIN),
    );
    if status == StatusCode::SWITCHING_PROTOCOLS {
        status = StatusCode::OK;
    }
    Ok(CloudflaredHttp2ResponseHead {
        status,
        should_flush: cloudflared_http2_should_flush_headers(&user_headers),
        headers,
    })
}

pub fn cloudflared_http2_should_flush_headers(headers: &HeaderMap) -> bool {
    if !headers.contains_key(http::header::CONTENT_LENGTH) {
        return true;
    }
    if headers
        .get(http::header::TRANSFER_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        return true;
    }
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    [
        CLOUDFLARED_H2_CONTENT_TYPE_SSE,
        CLOUDFLARED_H2_CONTENT_TYPE_GRPC,
        CLOUDFLARED_H2_CONTENT_TYPE_NDJSON,
    ]
    .iter()
    .any(|flushable| content_type.starts_with(flushable))
}

#[derive(Debug, Deserialize)]
struct ConfigurationRequest {
    version: i32,
    config: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigurationResponse<'a> {
    last_applied_version: i32,
    err: Option<&'a str>,
}

pub fn decode_cloudflared_http2_configuration(
    body: &[u8],
) -> Result<(i32, Vec<u8>), CloudflaredError> {
    let request: ConfigurationRequest = serde_json::from_slice(body)
        .map_err(|error| CloudflaredError::Transport(error.to_string()))?;
    let config = serde_json::to_vec(&request.config)
        .map_err(|error| CloudflaredError::Transport(error.to_string()))?;
    Ok((request.version, config))
}

pub fn encode_cloudflared_http2_configuration_response(
    last_applied_version: i32,
    error: Option<&str>,
) -> Result<Vec<u8>, CloudflaredError> {
    serde_json::to_vec(&ConfigurationResponse {
        last_applied_version,
        err: error,
    })
    .map_err(|error| CloudflaredError::Transport(error.to_string()))
}

pub fn cloudflared_http2_method_is_bodyless(method: &Method) -> bool {
    method == Method::HEAD
}

pub trait CloudflaredHttp2Io:
    AsyncRead + AsyncWrite + Unpin + Send + 'static
{
}

impl<T> CloudflaredHttp2Io for T where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static
{
}

pub struct CloudflaredHttp2Stream {
    reader: HyperIncomingReader,
    writer: tokio::io::DuplexStream,
}

impl AsyncRead for CloudflaredHttp2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(context, buffer)
    }
}

impl AsyncWrite for CloudflaredHttp2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(context)
    }
}

struct HyperIncomingReader {
    body: Incoming,
    current: Bytes,
}

impl HyperIncomingReader {
    fn new(body: Incoming) -> Self {
        Self {
            body,
            current: Bytes::new(),
        }
    }
}

impl AsyncRead for HyperIncomingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.current.is_empty() {
                let amount = self.current.len().min(buffer.remaining());
                buffer.put_slice(&self.current[..amount]);
                self.current.advance(amount);
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.body).poll_frame(context)) {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.current = data;
                    }
                }
                Some(Err(error)) => {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

fn cloudflared_http2_stream(
    incoming: Incoming,
) -> (
    CloudflaredHttp2Stream,
    Channel<Bytes, Infallible>,
    Arc<Mutex<HeaderMap>>,
) {
    let trailers = Arc::new(Mutex::new(HeaderMap::new()));
    let (writer, body) =
        cloudflared_http2_body_writer_with_trailers(Some(trailers.clone()));
    (
        CloudflaredHttp2Stream {
            reader: HyperIncomingReader::new(incoming),
            writer,
        },
        body,
        trailers,
    )
}

#[cfg(test)]
fn cloudflared_http2_body_writer()
-> (tokio::io::DuplexStream, Channel<Bytes, Infallible>) {
    cloudflared_http2_body_writer_with_trailers(None)
}

fn cloudflared_http2_body_writer_with_trailers(
    trailers: Option<Arc<Mutex<HeaderMap>>>,
) -> (tokio::io::DuplexStream, Channel<Bytes, Infallible>) {
    let (mut sender, body) = Channel::new(16);
    let (writer, mut pump) = tokio::io::duplex(64 * 1024);
    tokio::task::spawn_local(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            match pump.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(length) => {
                    if sender
                        .send_data(Bytes::copy_from_slice(&buffer[..length]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        if let Some(trailers) = trailers {
            let trailers = std::mem::take(
                &mut *trailers.lock().expect("trailer lock poisoned"),
            );
            if !trailers.is_empty() {
                let _ = sender.send_trailers(trailers).await;
            }
        }
    });
    (writer, body)
}

pub struct CloudflaredHttp2ResponseWriter {
    head: Mutex<Option<oneshot::Sender<CloudflaredHttp2ResponseHead>>>,
    headers_sent: AtomicBool,
    trailers: Arc<Mutex<HeaderMap>>,
}

impl CloudflaredHttp2ResponseWriter {
    fn new(
        head: oneshot::Sender<CloudflaredHttp2ResponseHead>,
        trailers: Arc<Mutex<HeaderMap>>,
    ) -> Self {
        Self {
            head: Mutex::new(Some(head)),
            headers_sent: AtomicBool::new(false),
            trailers,
        }
    }

    pub fn write_response(
        &self,
        response_error: Option<&str>,
        metadata: &[CloudflaredMetadata],
    ) -> Result<(), CloudflaredError> {
        let head =
            encode_cloudflared_http2_response_head(response_error, metadata)?;
        self.headers_sent.store(true, Ordering::Release);
        if let Some(sender) =
            self.head.lock().expect("head lock poisoned").take()
        {
            let _ = sender.send(head);
        }
        Ok(())
    }

    pub fn add_trailer(&self, name: HeaderName, value: HeaderValue) {
        if !self.headers_sent.load(Ordering::Acquire) {
            return;
        }
        self.trailers
            .lock()
            .expect("trailer lock poisoned")
            .append(name, value);
    }
}

impl Drop for CloudflaredHttp2ResponseWriter {
    fn drop(&mut self) {
        if let Some(sender) =
            self.head.lock().expect("head lock poisoned").take()
        {
            self.headers_sent.store(true, Ordering::Release);
            let _ = sender.send(
                encode_cloudflared_http2_response_head(None, &[])
                    .expect("empty response metadata is valid"),
            );
        }
    }
}

#[async_trait]
pub trait CloudflaredHttp2Handler: Send + Sync + 'static {
    async fn dispatch_request(
        &self,
        stream: CloudflaredHttp2Stream,
        response: CloudflaredHttp2ResponseWriter,
        request: CloudflaredConnectRequest,
    );
}

#[derive(Clone)]
struct LocalExecutor;

impl<F> hyper::rt::Executor<F> for LocalExecutor
where
    F: Future + 'static,
{
    fn execute(&self, future: F) {
        tokio::task::spawn_local(future);
    }
}

struct Http2State {
    connection_index: u8,
    registration_options: CloudflaredRegistrationOptions,
    grace_period: Duration,
    handler: Arc<dyn CloudflaredHttp2Handler>,
    configuration: Arc<dyn super::cloudflared::CloudflaredConfigurationApplier>,
    registration_started: AtomicBool,
    registered: AtomicBool,
    active_requests: AtomicUsize,
    active_changed: tokio::sync::Notify,
    control_shutdown: CancellationToken,
    registration_error: Mutex<Option<CloudflaredError>>,
    registration_failed: tokio::sync::Notify,
    unregister_done: tokio::sync::Notify,
    ready: Arc<tokio::sync::Notify>,
}

struct ActiveRequest(Arc<Http2State>);

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.active_requests.fetch_sub(1, Ordering::SeqCst);
        self.0.active_changed.notify_waiters();
    }
}

pub struct CloudflaredHttp2Connection {
    stream: Box<dyn CloudflaredHttp2Io>,
    connection_index: u8,
    registration_options: CloudflaredRegistrationOptions,
    grace_period: Duration,
    handler: Arc<dyn CloudflaredHttp2Handler>,
    configuration: Arc<dyn super::cloudflared::CloudflaredConfigurationApplier>,
}

impl CloudflaredHttp2Connection {
    pub fn new<S>(
        stream: S,
        connection_index: u8,
        registration_options: CloudflaredRegistrationOptions,
        grace_period: Duration,
        handler: Arc<dyn CloudflaredHttp2Handler>,
        configuration: Arc<
            dyn super::cloudflared::CloudflaredConfigurationApplier,
        >,
    ) -> Self
    where
        S: CloudflaredHttp2Io,
    {
        Self {
            stream: Box::new(stream),
            connection_index,
            registration_options,
            grace_period,
            handler,
            configuration,
        }
    }

    async fn serve_inner(
        self,
        cancellation: CancellationToken,
        ready: Arc<tokio::sync::Notify>,
    ) -> Result<(), CloudflaredError> {
        let state = Arc::new(Http2State {
            connection_index: self.connection_index,
            registration_options: self.registration_options,
            grace_period: self.grace_period,
            handler: self.handler,
            configuration: self.configuration,
            registration_started: AtomicBool::new(false),
            registered: AtomicBool::new(false),
            active_requests: AtomicUsize::new(0),
            active_changed: tokio::sync::Notify::new(),
            control_shutdown: CancellationToken::new(),
            registration_error: Mutex::new(None),
            registration_failed: tokio::sync::Notify::new(),
            unregister_done: tokio::sync::Notify::new(),
            ready,
        });
        let service_state = Arc::clone(&state);
        let service = service_fn(move |request| {
            dispatch_cloudflared_http2(request, Arc::clone(&service_state))
        });
        let mut builder =
            hyper::server::conn::http2::Builder::new(LocalExecutor);
        builder.timer(TokioTimer::new());
        builder.max_concurrent_streams(Some(u32::MAX));
        let connection =
            builder.serve_connection(TokioIo::new(self.stream), service);
        let graceful_shutdown = CancellationToken::new();
        let connection_shutdown = graceful_shutdown.clone();
        let mut connection_task = tokio::task::spawn_local(async move {
            tokio::pin!(connection);
            tokio::select! {
                result = &mut connection => result,
                () = connection_shutdown.cancelled() => {
                    connection.as_mut().graceful_shutdown();
                    connection.await
                }
            }
        });

        tokio::select! {
            result = &mut connection_task => {
                result.map_err(|error| CloudflaredError::Transport(format!(
                    "HTTP/2 connection task failed: {error}"
                )))?.map_err(|error| {
                    state
                        .registration_error
                        .lock()
                        .expect("registration error lock poisoned")
                        .take()
                        .unwrap_or_else(|| CloudflaredError::Transport(
                            error.to_string(),
                        ))
                })?;
                if let Some(error) = state
                    .registration_error
                    .lock()
                    .expect("registration error lock poisoned")
                    .take()
                {
                    return Err(error);
                }
                if !state.registered.load(Ordering::SeqCst) {
                    return Err(CloudflaredError::Transport(
                        "edge connection closed before registration".into(),
                    ));
                }
                Err(CloudflaredError::Transport(
                    "edge connection closed".into(),
                ))
            }
            () = state.registration_failed.notified() => {
                graceful_shutdown.cancel();
                let _ = tokio::time::timeout(
                    state.grace_period,
                    &mut connection_task,
                ).await;
                Err(state
                    .registration_error
                    .lock()
                    .expect("registration error lock poisoned")
                    .take()
                    .unwrap_or_else(|| CloudflaredError::Transport(
                        "registration failed".into(),
                    )))
            }
            () = cancellation.cancelled() => {
                state.control_shutdown.cancel();
                if state.registered.load(Ordering::SeqCst) {
                    let _ = tokio::time::timeout(
                        state.grace_period,
                        state.unregister_done.notified(),
                    ).await;
                }
                graceful_shutdown.cancel();
                let drain = async {
                    while state.active_requests.load(Ordering::SeqCst) != 0 {
                        state.active_changed.notified().await;
                    }
                };
                let _ = tokio::time::timeout(state.grace_period, drain).await;
                let _ = tokio::time::timeout(
                    state.grace_period,
                    &mut connection_task,
                ).await;
                Ok(())
            }
        }
    }
}

#[async_trait(?Send)]
impl CloudflaredManagedConnection for CloudflaredHttp2Connection {
    async fn serve(
        self: Box<Self>,
        cancellation: CancellationToken,
        ready: Arc<tokio::sync::Notify>,
    ) -> Result<(), CloudflaredError> {
        self.serve_inner(cancellation, ready).await
    }
}

async fn dispatch_cloudflared_http2(
    request: Request<Incoming>,
    state: Arc<Http2State>,
) -> Result<Response<Channel<Bytes, Infallible>>, Infallible> {
    let response = match classify_cloudflared_http2_request(&request) {
        CloudflaredHttp2RequestKind::Control => {
            dispatch_cloudflared_http2_control(request, state)
        }
        CloudflaredHttp2RequestKind::Configuration => {
            dispatch_cloudflared_http2_configuration(request, state).await
        }
        CloudflaredHttp2RequestKind::Data(connection_type) => {
            dispatch_cloudflared_http2_data(request, connection_type, state)
                .await
        }
    };
    Ok(response)
}

fn empty_http2_body() -> Channel<Bytes, Infallible> {
    let (sender, body) = Channel::new(1);
    drop(sender);
    body
}

fn response_with_body(
    status: StatusCode,
    headers: HeaderMap,
    body: Channel<Bytes, Infallible>,
) -> Response<Channel<Bytes, Infallible>> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

fn dispatch_cloudflared_http2_control(
    request: Request<Incoming>,
    state: Arc<Http2State>,
) -> Response<Channel<Bytes, Infallible>> {
    if state.registration_started.swap(true, Ordering::SeqCst) {
        return response_with_body(
            StatusCode::CONFLICT,
            HeaderMap::new(),
            empty_http2_body(),
        );
    }
    let (stream, body, _trailers) =
        cloudflared_http2_stream(request.into_body());
    tokio::task::spawn_local(async move {
        let (registration, rpc) = cloudflared_registration_rpc(stream);
        let rpc_task = tokio::task::spawn_local(rpc);
        let mut options = state.registration_options.clone();
        options.connection_index = state.connection_index;
        let result = tokio::time::timeout(
            CLOUDFLARED_REGISTRATION_TIMEOUT,
            registration.register_connection(&options),
        )
        .await;
        let registration_result = match result {
            Ok(Ok(result)) if result.tunnel_is_remotely_managed => result,
            Ok(Ok(_)) => {
                *state
                    .registration_error
                    .lock()
                    .expect("registration error lock poisoned") =
                    Some(CloudflaredError::NonRemoteManagedTunnel);
                state.registration_failed.notify_one();
                rpc_task.abort();
                return;
            }
            Ok(Err(error)) => {
                *state
                    .registration_error
                    .lock()
                    .expect("registration error lock poisoned") = Some(error);
                state.registration_failed.notify_one();
                rpc_task.abort();
                return;
            }
            Err(_) => {
                *state
                    .registration_error
                    .lock()
                    .expect("registration error lock poisoned") =
                    Some(CloudflaredError::Transport(
                        "registration timed out".into(),
                    ));
                state.registration_failed.notify_one();
                rpc_task.abort();
                return;
            }
        };
        let _registration_result: CloudflaredRegistrationResult =
            registration_result;
        state.registered.store(true, Ordering::SeqCst);
        state.ready.notify_one();
        state.control_shutdown.cancelled().await;
        let _ = tokio::time::timeout(
            state.grace_period,
            registration.unregister_connection(),
        )
        .await;
        rpc_task.abort();
        state.unregister_done.notify_one();
    });
    response_with_body(StatusCode::OK, HeaderMap::new(), body)
}

async fn dispatch_cloudflared_http2_configuration(
    request: Request<Incoming>,
    state: Arc<Http2State>,
) -> Response<Channel<Bytes, Infallible>> {
    state.active_requests.fetch_add(1, Ordering::SeqCst);
    let _active = ActiveRequest(Arc::clone(&state));
    let collected = request.into_body().collect().await;
    let (status, body) = match collected {
        Ok(body) => {
            match decode_cloudflared_http2_configuration(&body.to_bytes()) {
                Ok((version, config)) => {
                    let result = state
                        .configuration
                        .apply_configuration(version, &config);
                    (
                        StatusCode::OK,
                        encode_cloudflared_http2_configuration_response(
                            result.latest_applied_version,
                            result.error.as_deref(),
                        )
                        .unwrap_or_default(),
                    )
                }
                Err(_) => (StatusCode::BAD_GATEWAY, Vec::new()),
            }
        }
        Err(_) => (StatusCode::BAD_GATEWAY, Vec::new()),
    };
    let (mut sender, response_body) = Channel::new(1);
    if !body.is_empty() {
        let _ = sender.send_data(Bytes::from(body)).await;
    }
    drop(sender);
    response_with_body(status, HeaderMap::new(), response_body)
}

async fn dispatch_cloudflared_http2_data(
    request: Request<Incoming>,
    connection_type: CloudflaredConnectionType,
    state: Arc<Http2State>,
) -> Response<Channel<Bytes, Infallible>> {
    state.active_requests.fetch_add(1, Ordering::SeqCst);
    let active = ActiveRequest(Arc::clone(&state));
    let connect_request =
        decode_cloudflared_http2_connect_request(&request, connection_type);
    let (stream, body, trailers) =
        cloudflared_http2_stream(request.into_body());
    let (head_tx, head_rx) = oneshot::channel();
    let response_writer =
        CloudflaredHttp2ResponseWriter::new(head_tx, trailers);
    let handler = Arc::clone(&state.handler);
    tokio::task::spawn_local(async move {
        handler
            .dispatch_request(stream, response_writer, connect_request)
            .await;
        drop(active);
    });
    let head = head_rx.await.unwrap_or_else(|_| {
        encode_cloudflared_http2_response_head(None, &[])
            .expect("empty response metadata is valid")
    });
    response_with_body(head.status, head.headers, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cloudflared_tunnelrpc_capnp as tunnelrpc,
        protocol::cloudflared::{
            CLOUDFLARED_METADATA_FLOW_CONNECT_RATE_LIMITED,
            CLOUDFLARED_METADATA_HTTP_HEADER, CloudflaredConfigurationUpdate,
            CloudflaredCredentials,
        },
    };
    use serde_json::json;
    use std::sync::atomic::AtomicBool;
    use tokio::io::AsyncWriteExt as _;
    use tokio_util::compat::TokioAsyncReadCompatExt as _;
    use uuid::Uuid;

    #[tokio::test(flavor = "current_thread")]
    async fn response_writer_emits_origin_trailers_after_body() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let trailers = Arc::new(Mutex::new(HeaderMap::new()));
                let (mut writer, mut body) =
                    cloudflared_http2_body_writer_with_trailers(Some(
                        trailers.clone(),
                    ));
                let (head_sender, head_receiver) = oneshot::channel();
                let response =
                    CloudflaredHttp2ResponseWriter::new(head_sender, trailers);
                response.add_trailer(
                    HeaderName::from_static("x-before-head"),
                    HeaderValue::from_static("ignored"),
                );
                response.write_response(None, &[]).unwrap();
                response.add_trailer(
                    HeaderName::from_static("x-origin-trailer"),
                    HeaderValue::from_static("first"),
                );
                response.add_trailer(
                    HeaderName::from_static("x-origin-trailer"),
                    HeaderValue::from_static("second"),
                );
                writer.write_all(b"body").await.unwrap();
                writer.shutdown().await.unwrap();

                let head = head_receiver.await.unwrap();
                assert_eq!(head.status, StatusCode::OK);
                let mut data = Vec::new();
                let mut received_trailers = HeaderMap::new();
                while let Some(frame) = body.frame().await {
                    let frame = frame.unwrap();
                    match frame.into_data() {
                        Ok(bytes) => data.extend_from_slice(&bytes),
                        Err(frame) => {
                            if let Ok(trailers) = frame.into_trailers() {
                                received_trailers = trailers;
                            }
                        }
                    }
                }
                assert_eq!(data, b"body");
                assert!(!received_trailers.contains_key("x-before-head"));
                assert_eq!(
                    received_trailers
                        .get_all("x-origin-trailer")
                        .iter()
                        .map(|value| value.to_str().unwrap())
                        .collect::<Vec<_>>(),
                    ["first", "second"]
                );
            })
            .await;
    }

    #[test]
    fn classifies_and_maps_all_edge_request_types() {
        let control = Request::builder()
            .header(
                CLOUDFLARED_H2_HEADER_UPGRADE,
                CLOUDFLARED_H2_UPGRADE_CONTROL_STREAM,
            )
            .body(())
            .unwrap();
        assert_eq!(
            classify_cloudflared_http2_request(&control),
            CloudflaredHttp2RequestKind::Control
        );

        let websocket = Request::builder()
            .method("GET")
            .uri("https://edge.example/ws?q=1")
            .header(
                CLOUDFLARED_H2_HEADER_UPGRADE,
                CLOUDFLARED_H2_UPGRADE_WEBSOCKET,
            )
            .header("x-test", "one")
            .body(())
            .unwrap();
        assert_eq!(
            classify_cloudflared_http2_request(&websocket),
            CloudflaredHttp2RequestKind::Data(
                CloudflaredConnectionType::Websocket
            )
        );
        let decoded = decode_cloudflared_http2_connect_request(
            &websocket,
            CloudflaredConnectionType::Websocket,
        );
        assert_eq!(decoded.destination, "https://edge.example/ws?q=1");
        assert!(decoded.metadata.iter().any(|entry| {
            entry.key == "HttpHeader:x-test" && entry.value == "one"
        }));
        assert!(!decoded.metadata.iter().any(|entry| {
            entry.key.contains(CLOUDFLARED_H2_HEADER_UPGRADE)
        }));

        let tcp = Request::builder()
            .method("CONNECT")
            .uri("origin.example:443")
            .header(CLOUDFLARED_H2_HEADER_TCP_SOURCE, "198.51.100.2")
            .body(())
            .unwrap();
        assert_eq!(
            classify_cloudflared_http2_request(&tcp),
            CloudflaredHttp2RequestKind::Data(CloudflaredConnectionType::Tcp)
        );
        assert_eq!(
            decode_cloudflared_http2_connect_request(
                &tcp,
                CloudflaredConnectionType::Tcp
            )
            .destination,
            "origin.example:443"
        );

        let configuration = Request::builder()
            .header(
                CLOUDFLARED_H2_HEADER_UPGRADE,
                CLOUDFLARED_H2_UPGRADE_CONFIGURATION,
            )
            .body(())
            .unwrap();
        assert_eq!(
            classify_cloudflared_http2_request(&configuration),
            CloudflaredHttp2RequestKind::Configuration
        );
    }

    #[test]
    fn response_headers_match_cloudflared_filtering_and_flush_rules() {
        let head = encode_cloudflared_http2_response_head(
            None,
            &[
                CloudflaredMetadata {
                    key: CLOUDFLARED_METADATA_HTTP_STATUS.into(),
                    value: "101".into(),
                },
                CloudflaredMetadata {
                    key: format!(
                        "{CLOUDFLARED_METADATA_HTTP_HEADER}:content-length"
                    ),
                    value: "12".into(),
                },
                CloudflaredMetadata {
                    key: format!(
                        "{CLOUDFLARED_METADATA_HTTP_HEADER}:content-type"
                    ),
                    value: "text/event-stream; charset=utf-8".into(),
                },
                CloudflaredMetadata {
                    key: format!(
                        "{CLOUDFLARED_METADATA_HTTP_HEADER}:cf-int-secret"
                    ),
                    value: "hidden".into(),
                },
                CloudflaredMetadata {
                    key: format!("{CLOUDFLARED_METADATA_HTTP_HEADER}:upgrade"),
                    value: "websocket".into(),
                },
            ],
        )
        .unwrap();
        assert_eq!(head.status, StatusCode::OK);
        assert_eq!(head.headers[http::header::CONTENT_LENGTH], "12");
        assert_eq!(
            head.headers[CLOUDFLARED_H2_HEADER_RESPONSE_META],
            CLOUDFLARED_H2_RESPONSE_META_ORIGIN
        );
        let user = head.headers[CLOUDFLARED_H2_HEADER_RESPONSE_USER]
            .to_str()
            .unwrap();
        assert!(!user.contains("hidden"));
        assert!(head.should_flush);

        let failure = encode_cloudflared_http2_response_head(
            Some("rejected"),
            &[CloudflaredMetadata {
                key: CLOUDFLARED_METADATA_FLOW_CONNECT_RATE_LIMITED.into(),
                value: "true".into(),
            }],
        )
        .unwrap();
        assert_eq!(failure.status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            failure.headers[CLOUDFLARED_H2_HEADER_RESPONSE_META],
            CLOUDFLARED_H2_RESPONSE_META_EDGE_RATE_LIMITED
        );
    }

    #[test]
    fn configuration_wire_and_bodyless_method_are_exact() {
        let (version, config) = decode_cloudflared_http2_configuration(
            br#"{"version":7,"config":{"ingress":[{"service":"http://localhost"}]}}"#,
        )
        .unwrap();
        assert_eq!(version, 7);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&config).unwrap(),
            json!({"ingress":[{"service":"http://localhost"}]})
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &encode_cloudflared_http2_configuration_response(
                    7,
                    Some("stale")
                )
                .unwrap()
            )
            .unwrap(),
            json!({"lastAppliedVersion":7,"err":"stale"})
        );
        assert!(cloudflared_http2_method_is_bodyless(&Method::HEAD));
        assert!(!cloudflared_http2_method_is_bodyless(&Method::GET));
    }

    struct Http2RegistrationServer {
        unregistered: Arc<AtomicBool>,
    }

    impl tunnelrpc::registration_server::Server for Http2RegistrationServer {
        async fn register_connection(
            self: capnp::capability::Rc<Self>,
            params: tunnelrpc::registration_server::RegisterConnectionParams,
            mut results: tunnelrpc::registration_server::RegisterConnectionResults,
        ) -> Result<(), capnp::Error> {
            assert_eq!(params.get()?.get_conn_index(), 4);
            let response = results.get().init_result();
            let mut details = response.get_result().init_connection_details();
            details.set_uuid(
                Uuid::parse_str("550e8400-e29a-41d4-a716-446655440010")
                    .unwrap()
                    .as_bytes(),
            );
            details.set_location_name("AMS");
            details.set_tunnel_is_remotely_managed(true);
            Ok(())
        }

        async fn unregister_connection(
            self: capnp::capability::Rc<Self>,
            _params: tunnelrpc::registration_server::UnregisterConnectionParams,
            _results: tunnelrpc::registration_server::UnregisterConnectionResults,
        ) -> Result<(), capnp::Error> {
            self.unregistered.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Default)]
    struct Http2Recorder {
        request: Mutex<Option<CloudflaredConnectRequest>>,
        request_body: Mutex<Vec<u8>>,
        configuration: Mutex<Option<(i32, Vec<u8>)>>,
    }

    #[async_trait]
    impl CloudflaredHttp2Handler for Http2Recorder {
        async fn dispatch_request(
            &self,
            mut stream: CloudflaredHttp2Stream,
            response: CloudflaredHttp2ResponseWriter,
            request: CloudflaredConnectRequest,
        ) {
            let mut body = Vec::new();
            stream.read_to_end(&mut body).await.unwrap();
            *self.request.lock().unwrap() = Some(request);
            *self.request_body.lock().unwrap() = body.clone();
            response
                .write_response(
                    None,
                    &[
                        CloudflaredMetadata {
                            key: CLOUDFLARED_METADATA_HTTP_STATUS.into(),
                            value: "201".into(),
                        },
                        CloudflaredMetadata {
                            key: format!(
                                "{CLOUDFLARED_METADATA_HTTP_HEADER}:content-length"
                            ),
                            value: body.len().to_string(),
                        },
                        CloudflaredMetadata {
                            key: format!(
                                "{CLOUDFLARED_METADATA_HTTP_HEADER}:x-origin"
                            ),
                            value: "rust".into(),
                        },
                    ],
                )
                .unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    }

    impl super::super::cloudflared::CloudflaredConfigurationApplier
        for Http2Recorder
    {
        fn apply_configuration(
            &self,
            version: i32,
            configuration: &[u8],
        ) -> CloudflaredConfigurationUpdate {
            *self.configuration.lock().unwrap() =
                Some((version, configuration.to_vec()));
            CloudflaredConfigurationUpdate {
                latest_applied_version: version,
                error: None,
            }
        }
    }

    fn test_registration_options() -> CloudflaredRegistrationOptions {
        CloudflaredRegistrationOptions {
            credentials: CloudflaredCredentials {
                account_tag: "account".into(),
                tunnel_secret: vec![7; 32],
                tunnel_id: Uuid::parse_str(
                    "550e8400-e29a-41d4-a716-446655440000",
                )
                .unwrap(),
                endpoint: String::new(),
            },
            connection_index: 0,
            client_id: vec![9; 16],
            client_features: vec!["http2".into()],
            client_version: "singbox-rust-test".into(),
            client_arch: "test".into(),
            origin_local_ip: "127.0.0.1".parse().unwrap(),
            replace_existing: false,
            compression_quality: 0,
            previous_attempts: 0,
        }
    }

    fn channel_body(data: &'static [u8]) -> Channel<Bytes, Infallible> {
        let (mut sender, body) = Channel::new(1);
        tokio::task::spawn_local(async move {
            sender.send_data(Bytes::from_static(data)).await.unwrap();
        });
        body
    }

    #[tokio::test(flavor = "current_thread")]
    async fn live_http2_transport_registers_dispatches_and_unregisters() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (origin_io, edge_io) = tokio::io::duplex(1024 * 1024);
                let recorder = Arc::new(Http2Recorder::default());
                let connection = CloudflaredHttp2Connection::new(
                    origin_io,
                    4,
                    test_registration_options(),
                    Duration::from_secs(2),
                    recorder.clone(),
                    recorder.clone(),
                );
                let cancellation = CancellationToken::new();
                let ready = Arc::new(tokio::sync::Notify::new());
                let serve_cancellation = cancellation.clone();
                let serve_ready = Arc::clone(&ready);
                let serve_task = tokio::task::spawn_local(async move {
                    Box::new(connection)
                        .serve(serve_cancellation, serve_ready)
                        .await
                });

                let (mut edge, edge_connection) =
                    hyper::client::conn::http2::handshake(
                        LocalExecutor,
                        TokioIo::new(edge_io),
                    )
                    .await
                    .unwrap();
                let edge_task = tokio::task::spawn_local(edge_connection);

                let (control_writer, control_body) =
                    cloudflared_http2_body_writer();
                let control_response = edge
                    .send_request(
                        Request::builder()
                            .uri("https://edge.example/control")
                            .header(
                                CLOUDFLARED_H2_HEADER_UPGRADE,
                                CLOUDFLARED_H2_UPGRADE_CONTROL_STREAM,
                            )
                            .body(control_body)
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(control_response.status(), StatusCode::OK);
                let control_stream = CloudflaredHttp2Stream {
                    reader: HyperIncomingReader::new(
                        control_response.into_body(),
                    ),
                    writer: control_writer,
                };
                let unregistered = Arc::new(AtomicBool::new(false));
                let bootstrap: tunnelrpc::registration_server::Client =
                    capnp_rpc::new_client(Http2RegistrationServer {
                        unregistered: Arc::clone(&unregistered),
                    });
                let (control_reader, control_writer) =
                    futures::io::AsyncReadExt::split(
                        control_stream.compat(),
                    );
                let network = Box::new(capnp_rpc::twoparty::VatNetwork::new(
                    futures::io::BufReader::new(control_reader),
                    futures::io::BufWriter::new(control_writer),
                    capnp_rpc::rpc_twoparty_capnp::Side::Server,
                    capnp::message::ReaderOptions::new(),
                ));
                let control_rpc = capnp_rpc::RpcSystem::new(
                    network,
                    Some(bootstrap.client),
                );
                let control_task = tokio::task::spawn_local(control_rpc);
                tokio::time::timeout(Duration::from_secs(2), ready.notified())
                    .await
                    .unwrap();

                let response = edge
                    .send_request(
                        Request::builder()
                            .method(Method::POST)
                            .uri("https://origin.example/hello?q=1")
                            .header("host", "origin.example")
                            .header("x-test", "edge")
                            .body(channel_body(b"payload"))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::CREATED);
                assert_eq!(
                    response.headers()[CLOUDFLARED_H2_HEADER_RESPONSE_META],
                    CLOUDFLARED_H2_RESPONSE_META_ORIGIN
                );
                assert!(response.headers()[CLOUDFLARED_H2_HEADER_RESPONSE_USER]
                    .to_str()
                    .unwrap()
                    .contains("eC1vcmlnaW4"));
                assert_eq!(
                    response.collect().await.unwrap().to_bytes(),
                    Bytes::from_static(b"payload")
                );
                let recorded = recorder.request.lock().unwrap().clone().unwrap();
                assert_eq!(
                    recorded.destination,
                    "https://origin.example/hello?q=1"
                );
                assert_eq!(&*recorder.request_body.lock().unwrap(), b"payload");

                let configuration_response = edge
                    .send_request(
                        Request::builder()
                            .method(Method::POST)
                            .uri("https://edge.example/config")
                            .header(
                                CLOUDFLARED_H2_HEADER_UPGRADE,
                                CLOUDFLARED_H2_UPGRADE_CONFIGURATION,
                            )
                            .body(channel_body(
                                br#"{"version":12,"config":{"warp":true},"future":1}"#,
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(configuration_response.status(), StatusCode::OK);
                let configuration_body = configuration_response
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(
                        &configuration_body
                    )
                    .unwrap(),
                    json!({"lastAppliedVersion":12,"err":null})
                );
                assert_eq!(
                    recorder.configuration.lock().unwrap().as_ref().unwrap().0,
                    12
                );

                cancellation.cancel();
                tokio::time::timeout(Duration::from_secs(3), serve_task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert!(unregistered.load(Ordering::SeqCst));
                control_task.abort();
                edge_task.abort();
            })
            .await;
    }
}
