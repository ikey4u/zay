//! Hysteria2 realm rendezvous service.

use std::{
    collections::HashMap,
    convert::Infallible,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{
    BodyExt as _, Full, channel::Channel, combinators::BoxBody,
};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body as _, Incoming},
    header::{CACHE_CONTROL, CONNECTION, CONTENT_TYPE},
    server::conn::{http1, http2},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    io::AsyncReadExt as _,
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{Stream, replay_stream},
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        tls::{ServerTlsConfig, build_server_config_with_default_alpn},
    },
    option::{Http2Options, HysteriaRealmServiceOptions, HysteriaRealmUser},
};

type ApiBody = BoxBody<Bytes, Infallible>;

const SESSION_TTL: Duration = Duration::from_secs(60);
const MAX_REQUEST_BODY_BYTES: usize = 4 << 10;
const MAX_ADDRESSES: usize = 8;
const NONCE_HEX_LENGTH: usize = 32;
const OBFS_HEX_LENGTH: usize = 64;
const EVENT_CHANNEL_SIZE: usize = 16;
const MAX_PENDING_ATTEMPTS: usize = 16;
const CONNECT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Clone)]
struct RealmUser {
    name: String,
    max_realms: i32,
}

struct RealmEvent {
    kind: &'static str,
    data: Value,
}

struct RealmSession {
    token: String,
    realm_id: String,
    username: String,
    addresses: Mutex<Vec<String>>,
    expires: Mutex<Instant>,
    events_tx: mpsc::Sender<RealmEvent>,
    events_rx: tokio::sync::Mutex<mpsc::Receiver<RealmEvent>>,
    pending: Mutex<HashMap<String, oneshot::Sender<Vec<String>>>>,
    done: CancellationToken,
}

#[derive(Default)]
struct RealmInner {
    realms: HashMap<String, Arc<RealmSession>>,
    sessions: HashMap<String, Arc<RealmSession>>,
    user_counts: HashMap<String, i32>,
}

struct RealmState {
    users: HashMap<String, RealmUser>,
    inner: Mutex<RealmInner>,
}

impl RealmState {
    fn new(users: &[HysteriaRealmUser]) -> io::Result<Arc<Self>> {
        if users.is_empty() {
            return Err(invalid_input("missing users"));
        }
        let mut token_map = HashMap::with_capacity(users.len());
        for (index, user) in users.iter().enumerate() {
            if user.name.is_empty() {
                return Err(invalid_input(format!(
                    "missing name for user[{index}]"
                )));
            }
            if user.token.is_empty() {
                return Err(invalid_input(format!(
                    "missing token for user[{index}]"
                )));
            }
            token_map.insert(
                user.token.clone(),
                RealmUser {
                    name: user.name.clone(),
                    max_realms: user.max_realms,
                },
            );
        }
        Ok(Arc::new(Self {
            users: token_map,
            inner: Mutex::new(RealmInner::default()),
        }))
    }

    fn user(&self, request: &Request<Incoming>) -> Option<RealmUser> {
        let token = bearer_token(request)?;
        self.users.get(token).cloned()
    }

    fn session(
        self: &Arc<Self>,
        request: &Request<Incoming>,
        realm_id: &str,
    ) -> Option<Arc<RealmSession>> {
        let token = bearer_token(request)?;
        let session = self
            .inner
            .lock()
            .expect("realm state lock poisoned")
            .sessions
            .get(token)
            .cloned()?;
        if session.realm_id != realm_id {
            return None;
        }
        if Instant::now()
            > *session.expires.lock().expect("realm expiry lock poisoned")
        {
            self.remove(&session);
            return None;
        }
        Some(session)
    }

    fn realm(self: &Arc<Self>, realm_id: &str) -> Option<Arc<RealmSession>> {
        let session = self
            .inner
            .lock()
            .expect("realm state lock poisoned")
            .realms
            .get(realm_id)
            .cloned()?;
        if Instant::now()
            > *session.expires.lock().expect("realm expiry lock poisoned")
        {
            self.remove(&session);
            return None;
        }
        Some(session)
    }

    fn register(
        self: &Arc<Self>,
        user: &RealmUser,
        realm_id: &str,
        addresses: Vec<String>,
    ) -> Result<Arc<RealmSession>, RegisterError> {
        let token = random_token().map_err(|_| RegisterError::Entropy)?;
        let (events_tx, events_rx) = mpsc::channel(EVENT_CHANNEL_SIZE);
        let session = Arc::new(RealmSession {
            token: token.clone(),
            realm_id: realm_id.to_owned(),
            username: user.name.clone(),
            addresses: Mutex::new(addresses),
            expires: Mutex::new(Instant::now() + SESSION_TTL),
            events_tx,
            events_rx: tokio::sync::Mutex::new(events_rx),
            pending: Mutex::new(HashMap::new()),
            done: CancellationToken::new(),
        });
        {
            let mut inner =
                self.inner.lock().expect("realm state lock poisoned");
            if inner.realms.contains_key(realm_id) {
                return Err(RegisterError::Taken);
            }
            if user.max_realms > 0
                && inner.user_counts.get(&user.name).copied().unwrap_or(0)
                    >= user.max_realms
            {
                return Err(RegisterError::Limit);
            }
            inner.realms.insert(realm_id.to_owned(), session.clone());
            inner.sessions.insert(token, session.clone());
            *inner.user_counts.entry(user.name.clone()).or_default() += 1;
        }
        spawn_expiry(Arc::downgrade(self), Arc::downgrade(&session));
        Ok(session)
    }

    fn remove(&self, session: &Arc<RealmSession>) {
        let removed = {
            let mut inner =
                self.inner.lock().expect("realm state lock poisoned");
            if !inner
                .sessions
                .get(&session.token)
                .is_some_and(|current| Arc::ptr_eq(current, session))
            {
                false
            } else {
                inner.sessions.remove(&session.token);
                if inner
                    .realms
                    .get(&session.realm_id)
                    .is_some_and(|current| Arc::ptr_eq(current, session))
                {
                    inner.realms.remove(&session.realm_id);
                }
                if let Some(count) =
                    inner.user_counts.get_mut(&session.username)
                {
                    *count -= 1;
                    if *count <= 0 {
                        inner.user_counts.remove(&session.username);
                    }
                }
                true
            }
        };
        if removed {
            session.done.cancel();
            session
                .pending
                .lock()
                .expect("realm pending lock poisoned")
                .clear();
        }
    }

    fn close_all(&self) {
        let sessions = self
            .inner
            .lock()
            .expect("realm state lock poisoned")
            .sessions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for session in sessions {
            self.remove(&session);
        }
    }
}

#[derive(Debug)]
enum RegisterError {
    Taken,
    Limit,
    Entropy,
}

fn spawn_expiry(state: Weak<RealmState>, session: Weak<RealmSession>) {
    tokio::spawn(async move {
        loop {
            let Some(session) = session.upgrade() else {
                return;
            };
            let remaining = session
                .expires
                .lock()
                .expect("realm expiry lock poisoned")
                .saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                if let Some(state) = state.upgrade() {
                    state.remove(&session);
                }
                return;
            }
            tokio::select! {
                _ = tokio::time::sleep(remaining) => {}
                _ = session.done.cancelled() => return,
            }
        }
    });
}

struct PendingGuard {
    session: Arc<RealmSession>,
    nonce: String,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.session
            .pending
            .lock()
            .expect("realm pending lock poisoned")
            .remove(&self.nonce);
    }
}

#[derive(Clone, Default)]
pub struct HysteriaRealmHandle {
    local_addr: Arc<Mutex<Option<SocketAddr>>>,
}

impl HysteriaRealmHandle {
    pub fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.lock().expect("realm address lock poisoned")
    }
}

pub struct HysteriaRealmService {
    name: String,
    options: HysteriaRealmServiceOptions,
    state: Arc<RealmState>,
    tls: Option<ServerTlsConfig>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    handle: HysteriaRealmHandle,
}

impl HysteriaRealmService {
    pub fn new(
        tag: impl Into<String>,
        options: HysteriaRealmServiceOptions,
    ) -> io::Result<(Self, HysteriaRealmHandle)> {
        if options.http2.max_concurrent_streams < 0 {
            return Err(invalid_input("negative max_concurrent_streams"));
        }
        let state = RealmState::new(&options.users)?;
        let tls = options
            .tls
            .as_ref()
            .filter(|tls| tls.enabled)
            .map(|tls| {
                build_server_config_with_default_alpn(tls, &["h2", "http/1.1"])
            })
            .transpose()
            .map_err(io::Error::other)?;
        let tag = tag.into();
        let handle = HysteriaRealmHandle::default();
        Ok((
            Self {
                name: format!("service/hysteria-realm[{tag}]"),
                options,
                state,
                tls,
                cancellation: CancellationToken::new(),
                task: None,
                handle: handle.clone(),
            },
            handle,
        ))
    }

    async fn bind(&mut self) -> io::Result<()> {
        let ip =
            self.options.listen.listen.map(|value| value.0).unwrap_or(
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            );
        let listener = crate::common::socket::bind_tcp_listener(
            SocketAddr::new(ip, self.options.listen.listen_port),
            &self.options.listen,
        )
        .await?;
        *self
            .handle
            .local_addr
            .lock()
            .expect("realm address lock poisoned") =
            Some(listener.local_addr()?);
        let state = self.state.clone();
        let tls = self.tls.clone();
        let http2_options = self.options.http2.clone();
        let cancellation = self.cancellation.clone();
        self.task = Some(tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted?;
                        let state = state.clone();
                        let tls = tls.clone();
                        let http2_options = http2_options.clone();
                        connections.spawn(async move {
                            if let Some(tls) = tls {
                                let stream = tls.accept_stream(Box::new(stream)).await?;
                                let h2 = stream.alpn_protocol() == Some(b"h2");
                                serve_http(Box::new(stream), h2, state, &http2_options).await
                            } else {
                                serve_h2c(stream, state, &http2_options).await
                            }
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            Ok(())
        }));
        Ok(())
    }
}

impl Lifecycle for HysteriaRealmService {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage == StartStage::Start {
                self.bind().await.map_err(|error| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: error.to_string(),
                })?;
            }
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            self.state.close_all();
            if let Some(task) = self.task.take()
                && let Err(error) = task.await
                && !error.is_cancelled()
            {
                return Err(LifecycleError::Close {
                    component: self.name.clone(),
                    message: error.to_string(),
                });
            }
            Ok(())
        })
    }
}

async fn serve_h2c(
    mut stream: tokio::net::TcpStream,
    state: Arc<RealmState>,
    options: &Http2Options,
) -> io::Result<()> {
    let mut prefix = Vec::with_capacity(HTTP2_PREFACE.len());
    while prefix.len() < HTTP2_PREFACE.len() {
        let mut buffer = [0_u8; 24];
        let size = stream.read(&mut buffer).await?;
        if size == 0 {
            return Ok(());
        }
        prefix.extend_from_slice(&buffer[..size]);
        if !HTTP2_PREFACE.starts_with(&prefix) {
            break;
        }
    }
    let h2 = prefix.starts_with(HTTP2_PREFACE);
    let stream = replay_stream(Box::new(stream), prefix);
    serve_http(stream, h2, state, options).await
}

async fn serve_http(
    stream: Stream,
    h2: bool,
    state: Arc<RealmState>,
    options: &Http2Options,
) -> io::Result<()> {
    if h2 {
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        if options.stream_receive_window.0 != 0 {
            builder.initial_stream_window_size(Some(
                options.stream_receive_window.0.min(u32::MAX.into()) as u32,
            ));
        }
        if options.connection_receive_window.0 != 0 {
            builder.initial_connection_window_size(Some(
                options.connection_receive_window.0.min(u32::MAX.into()) as u32,
            ));
        }
        if options.max_concurrent_streams > 0 {
            builder.max_concurrent_streams(Some(
                options.max_concurrent_streams as u32,
            ));
        }
        if let Some(period) = options.keep_alive_period.as_std() {
            builder.keep_alive_interval(Some(period));
        }
        builder
            .serve_connection(
                TokioIo::new(stream),
                service_fn(move |request| dispatch(request, state.clone())),
            )
            .await
            .map_err(io::Error::other)
    } else {
        http1::Builder::new()
            .keep_alive(true)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(move |request| dispatch(request, state.clone())),
            )
            .await
            .map_err(io::Error::other)
    }
}

async fn dispatch(
    mut request: Request<Incoming>,
    state: Arc<RealmState>,
) -> Result<Response<ApiBody>, Infallible> {
    let path = request.uri().path().to_owned();
    let Some(relative) = path.strip_prefix("/v1/") else {
        return Ok(api_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "unknown path",
        ));
    };
    let mut parts = relative.split('/');
    let encoded_id = parts.next().unwrap_or_default();
    let realm_id = match percent_decode_str(encoded_id).decode_utf8() {
        Ok(value) => value.into_owned(),
        Err(_) => {
            return Ok(api_error(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "invalid realm name",
            ));
        }
    };
    if !valid_realm_id(&realm_id) {
        return Ok(api_error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "invalid realm name",
        ));
    }
    let tail = parts.collect::<Vec<_>>();
    let response = match tail.as_slice() {
        [""] => match *request.method() {
            Method::POST => register(&mut request, &state, &realm_id).await,
            Method::DELETE => deregister(&request, &state, &realm_id),
            _ => method_not_allowed(),
        },
        ["events"] => {
            if request.method() == Method::GET {
                events(&request, &state, &realm_id)
            } else {
                method_not_allowed()
            }
        }
        ["heartbeat"] => {
            if request.method() == Method::POST {
                heartbeat(&mut request, &state, &realm_id).await
            } else {
                method_not_allowed()
            }
        }
        ["connect"] => {
            if request.method() == Method::POST {
                connect(&mut request, &state, &realm_id).await
            } else {
                method_not_allowed()
            }
        }
        ["connects", encoded_nonce] => {
            if request.method() == Method::POST {
                let nonce = percent_decode_str(encoded_nonce)
                    .decode_utf8_lossy()
                    .into_owned();
                connect_response(&mut request, &state, &realm_id, &nonce).await
            } else {
                method_not_allowed()
            }
        }
        _ => api_error(StatusCode::NOT_FOUND, "not_found", "unknown path"),
    };
    Ok(response)
}

#[derive(Deserialize)]
struct AddressesRequest {
    addresses: Vec<String>,
}

#[derive(Deserialize)]
struct ConnectRequest {
    addresses: Vec<String>,
    nonce: String,
    obfs: String,
}

async fn register(
    request: &mut Request<Incoming>,
    state: &Arc<RealmState>,
    realm_id: &str,
) -> Response<ApiBody> {
    let Some(user) = state.user(request) else {
        return invalid_token("realm");
    };
    let body: AddressesRequest = match read_json(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(message) = validate_addresses(&body.addresses) {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", &message);
    }
    match state.register(&user, realm_id, body.addresses) {
        Ok(session) => json_response(
            StatusCode::OK,
            json!({"session_id":session.token,"ttl":SESSION_TTL.as_secs()}),
        ),
        Err(RegisterError::Taken) => api_error(
            StatusCode::CONFLICT,
            "realm_taken",
            "realm already registered",
        ),
        Err(RegisterError::Limit) => api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "realm_limit_reached",
            "per-user realm limit reached",
        ),
        Err(RegisterError::Entropy) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "entropy failure",
        ),
    }
}

fn deregister(
    request: &Request<Incoming>,
    state: &Arc<RealmState>,
    realm_id: &str,
) -> Response<ApiBody> {
    let Some(session) = state.session(request, realm_id) else {
        return invalid_token("session");
    };
    state.remove(&session);
    empty(StatusCode::NO_CONTENT)
}

async fn heartbeat(
    request: &mut Request<Incoming>,
    state: &Arc<RealmState>,
    realm_id: &str,
) -> Response<ApiBody> {
    let Some(session) = state.session(request, realm_id) else {
        return invalid_token("session");
    };
    let body = match read_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let addresses = if body.is_empty() {
        None
    } else {
        #[derive(Deserialize)]
        struct HeartbeatRequest {
            addresses: Option<Vec<String>>,
        }
        match serde_json::from_slice::<HeartbeatRequest>(&body) {
            Ok(body) => body.addresses,
            Err(_) => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    "invalid json",
                );
            }
        }
    };
    if let Some(addresses) = addresses.as_ref()
        && let Err(message) = validate_addresses(addresses)
    {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", &message);
    }
    *session.expires.lock().expect("realm expiry lock poisoned") =
        Instant::now() + SESSION_TTL;
    if let Some(addresses) = addresses {
        *session
            .addresses
            .lock()
            .expect("realm address lock poisoned") = addresses;
    }
    let _ = session.events_tx.try_send(RealmEvent {
        kind: "heartbeat_ack",
        data: json!({"ttl":SESSION_TTL.as_secs()}),
    });
    json_response(StatusCode::OK, json!({"ttl":SESSION_TTL.as_secs()}))
}

fn events(
    request: &Request<Incoming>,
    state: &Arc<RealmState>,
    realm_id: &str,
) -> Response<ApiBody> {
    let Some(session) = state.session(request, realm_id) else {
        return invalid_token("session");
    };
    let (mut sender, body) = Channel::<Bytes, Infallible>::new(4);
    tokio::spawn(async move {
        let mut receiver = session.events_rx.lock().await;
        loop {
            tokio::select! {
                _ = session.done.cancelled() => break,
                event = receiver.recv() => {
                    let Some(event) = event else { break; };
                    let payload = format!("event: {}\ndata: {}\n\n", event.kind, event.data);
                    if sender.send_data(Bytes::from(payload)).await.is_err() { break; }
                }
            }
        }
    });
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/event-stream")
        .header(CACHE_CONTROL, "no-cache");
    if request.version() != hyper::Version::HTTP_2 {
        response = response.header(CONNECTION, "keep-alive");
    }
    response
        .body(body.boxed())
        .expect("valid realm SSE response")
}

async fn connect(
    request: &mut Request<Incoming>,
    state: &Arc<RealmState>,
    realm_id: &str,
) -> Response<ApiBody> {
    if state.user(request).is_none() {
        return invalid_token("realm");
    }
    let body: ConnectRequest = match read_json(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(message) = validate_addresses(&body.addresses) {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", &message);
    }
    if let Err(message) = validate_hex("nonce", &body.nonce, NONCE_HEX_LENGTH) {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", &message);
    }
    if let Err(message) = validate_hex("obfs", &body.obfs, OBFS_HEX_LENGTH) {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", &message);
    }
    let Some(session) = state.realm(realm_id) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "realm_not_found",
            "realm not registered",
        );
    };
    let server_addresses = session
        .addresses
        .lock()
        .expect("realm address lock poisoned")
        .clone();
    let (response_tx, response_rx) = oneshot::channel();
    {
        let mut pending =
            session.pending.lock().expect("realm pending lock poisoned");
        if pending.len() >= MAX_PENDING_ATTEMPTS
            || pending.contains_key(&body.nonce)
        {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "rate_limited",
                "too many in-flight connect attempts",
            );
        }
        pending.insert(body.nonce.clone(), response_tx);
    }
    let _guard = PendingGuard {
        session: session.clone(),
        nonce: body.nonce.clone(),
    };
    if session
        .events_tx
        .try_send(RealmEvent {
            kind: "punch",
            data: json!({
                "addresses":body.addresses,
                "nonce":body.nonce,
                "obfs":body.obfs,
            }),
        })
        .is_err()
    {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "rate_limited",
            "server event buffer full",
        );
    }
    let response_addresses = tokio::select! {
        response = response_rx => match response {
            Ok(addresses) if !addresses.is_empty() => addresses,
            Ok(_) => server_addresses,
            Err(_) => return api_error(StatusCode::NOT_FOUND, "realm_not_found", "realm not registered"),
        },
        _ = tokio::time::sleep(CONNECT_RESPONSE_TIMEOUT) => server_addresses,
        _ = session.done.cancelled() => return api_error(StatusCode::NOT_FOUND, "realm_not_found", "realm not registered"),
    };
    json_response(
        StatusCode::OK,
        json!({
            "addresses":response_addresses,
            "nonce":body.nonce,
            "obfs":body.obfs,
        }),
    )
}

async fn connect_response(
    request: &mut Request<Incoming>,
    state: &Arc<RealmState>,
    realm_id: &str,
    nonce: &str,
) -> Response<ApiBody> {
    let Some(session) = state.session(request, realm_id) else {
        return invalid_token("session");
    };
    if let Err(message) = validate_hex("nonce", nonce, NONCE_HEX_LENGTH) {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", &message);
    }
    let body: AddressesRequest = match read_json(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(message) = validate_addresses(&body.addresses) {
        return api_error(StatusCode::BAD_REQUEST, "bad_request", &message);
    }
    let sender = session
        .pending
        .lock()
        .expect("realm pending lock poisoned")
        .remove(nonce);
    let Some(sender) = sender else {
        return api_error(
            StatusCode::NOT_FOUND,
            "attempt_not_found",
            "no pending attempt for nonce",
        );
    };
    let _ = sender.send(body.addresses);
    empty(StatusCode::NO_CONTENT)
}

async fn read_json<T: for<'de> Deserialize<'de>>(
    request: &mut Request<Incoming>,
) -> Result<T, Response<ApiBody>> {
    let body = read_body(request).await?;
    serde_json::from_slice(&body).map_err(|_| {
        api_error(StatusCode::BAD_REQUEST, "bad_request", "invalid json")
    })
}

async fn read_body(
    request: &mut Request<Incoming>,
) -> Result<Bytes, Response<ApiBody>> {
    if request
        .body()
        .size_hint()
        .upper()
        .is_some_and(|size| size > MAX_REQUEST_BODY_BYTES as u64)
    {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "bad_request",
            "request body too large",
        ));
    }
    let mut body = Vec::new();
    while let Some(frame) = request.body_mut().frame().await {
        let frame = frame.map_err(|_| {
            api_error(StatusCode::BAD_REQUEST, "bad_request", "invalid json")
        })?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if body
            .len()
            .checked_add(data.len())
            .is_none_or(|size| size > MAX_REQUEST_BODY_BYTES)
        {
            return Err(api_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "bad_request",
                "request body too large",
            ));
        }
        body.extend_from_slice(&data);
    }
    Ok(Bytes::from(body))
}

fn bearer_token(request: &Request<Incoming>) -> Option<&str> {
    let header = request.headers().get("authorization")?.to_str().ok()?;
    let (scheme, token) = header.split_once(' ')?;
    (scheme == "Bearer").then_some(token)
}

fn valid_realm_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
        })
}

fn validate_addresses(addresses: &[String]) -> Result<(), String> {
    if addresses.is_empty() {
        return Err("at least one address required".into());
    }
    if addresses.len() > MAX_ADDRESSES {
        return Err(format!("too many addresses (max {MAX_ADDRESSES})"));
    }
    for address in addresses {
        if address.parse::<SocketAddr>().is_err() {
            return Err(format!("invalid address: {address}"));
        }
    }
    Ok(())
}

fn validate_hex(name: &str, value: &str, length: usize) -> Result<(), String> {
    if value.len() != length {
        return Err(format!("{name} must be {length} hex characters"));
    }
    hex::decode(value)
        .map(|_| ())
        .map_err(|_| format!("{name} must be valid hex"))
}

fn random_token() -> io::Result<String> {
    let mut token = [0_u8; 16];
    getrandom::fill(&mut token)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(hex::encode(token))
}

fn invalid_token(kind: &str) -> Response<ApiBody> {
    api_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        &format!("invalid {kind} token"),
    )
}

fn method_not_allowed() -> Response<ApiBody> {
    api_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "bad_request",
        "method not allowed",
    )
}

fn api_error(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Response<ApiBody> {
    json_response(status, json!({"error":code,"message":message}))
}

fn json_response(status: StatusCode, value: Value) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .body(full(Bytes::from(value.to_string())))
        .expect("valid realm JSON response")
}

fn empty(status: StatusCode) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .body(full(Bytes::new()))
        .expect("valid empty realm response")
}

fn full(bytes: Bytes) -> ApiBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[test]
    fn validates_users_and_http2_limits() {
        let missing: HysteriaRealmServiceOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "users":[]
            }))
            .unwrap();
        assert!(HysteriaRealmService::new("realm", missing).is_err());
        let negative: HysteriaRealmServiceOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "max_concurrent_streams":-1,
                "users":[{"name":"alice","token":"secret"}]
            }))
            .unwrap();
        assert!(HysteriaRealmService::new("realm", negative).is_err());
    }

    #[tokio::test]
    async fn expired_session_is_removed_and_releases_user_quota() {
        let users = [HysteriaRealmUser {
            name: "alice".into(),
            token: "secret".into(),
            max_realms: 1,
        }];
        let state = RealmState::new(&users).unwrap();
        let user = state.users.get("secret").unwrap();
        let session = state
            .register(user, "expired", vec!["127.0.0.1:1000".into()])
            .unwrap();
        *session.expires.lock().unwrap() =
            Instant::now() - Duration::from_secs(1);
        assert!(state.realm("expired").is_none());
        assert!(session.done.is_cancelled());
        assert!(
            state
                .register(user, "replacement", vec!["127.0.0.1:1001".into()])
                .is_ok()
        );
        state.close_all();
    }

    #[tokio::test]
    async fn registration_sse_connect_heartbeat_and_h2c_interoperate() {
        let options: HysteriaRealmServiceOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "keep_alive_period":"1s",
                "stream_receive_window":"1MB",
                "connection_receive_window":"2MB",
                "max_concurrent_streams":32,
                "users":[{"name":"alice","token":"secret","max_realms":2}]
            }))
            .unwrap();
        let (mut service, handle) =
            HysteriaRealmService::new("realm", options).unwrap();
        service.start(StartStage::Start).await.unwrap();
        let base = format!("http://{}", handle.local_addr().unwrap());
        let client = reqwest::Client::new();
        let mut oversized =
            tokio::net::TcpStream::connect(handle.local_addr().unwrap())
                .await
                .unwrap();
        oversized
            .write_all(
                b"POST /v1/too-large/ HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1001\r\n",
            )
            .await
            .unwrap();
        oversized.write_all(&vec![b'a'; 4097]).await.unwrap();
        oversized.write_all(b"\r\n0\r\n\r\n").await.unwrap();
        let mut oversized_response = Vec::new();
        oversized
            .read_to_end(&mut oversized_response)
            .await
            .unwrap();
        assert!(oversized_response.starts_with(b"HTTP/1.1 413"));

        let register = client
            .post(format!("{base}/v1/test-realm/"))
            .header("authorization", "Bearer secret")
            .body(json!({"addresses":["127.0.0.1:1000"]}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(register.status(), StatusCode::OK);
        let registered: Value =
            serde_json::from_str(&register.text().await.unwrap()).unwrap();
        assert_eq!(registered["ttl"], 60);
        let session_token =
            registered["session_id"].as_str().unwrap().to_owned();
        assert_eq!(session_token.len(), 32);

        let duplicate = client
            .post(format!("{base}/v1/test-realm/"))
            .header("authorization", "Bearer secret")
            .body(json!({"addresses":["127.0.0.1:1000"]}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);

        let mut events = client
            .get(format!("{base}/v1/test-realm/events"))
            .header("authorization", format!("Bearer {session_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(events.status(), StatusCode::OK);
        assert_eq!(
            events.headers().get(CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );

        let nonce = "11".repeat(16);
        let obfs = "22".repeat(32);
        let connect_client = client.clone();
        let connect_url = format!("{base}/v1/test-realm/connect");
        let connect_nonce = nonce.clone();
        let connect_obfs = obfs.clone();
        let connecting = tokio::spawn(async move {
            connect_client
                .post(connect_url)
                .header("authorization", "Bearer secret")
                .body(
                    json!({
                        "addresses":["127.0.0.1:2000"],
                        "nonce":connect_nonce,
                        "obfs":connect_obfs,
                    })
                    .to_string(),
                )
                .send()
                .await
                .unwrap()
        });
        let event =
            tokio::time::timeout(Duration::from_secs(2), events.chunk())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        let event = String::from_utf8(event.to_vec()).unwrap();
        assert!(event.contains("event: punch"));
        assert!(event.contains(&nonce));
        assert!(event.contains(&obfs));

        let response = client
            .post(format!("{base}/v1/test-realm/connects/{nonce}"))
            .header("authorization", format!("Bearer {session_token}"))
            .body(json!({"addresses":["127.0.0.1:3000"]}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let connected = connecting.await.unwrap();
        assert_eq!(connected.status(), StatusCode::OK);
        let connected: Value =
            serde_json::from_str(&connected.text().await.unwrap()).unwrap();
        assert_eq!(connected["addresses"], json!(["127.0.0.1:3000"]));
        assert_eq!(connected["nonce"], nonce);
        assert_eq!(connected["obfs"], obfs);

        let heartbeat = client
            .post(format!("{base}/v1/test-realm/heartbeat"))
            .header("authorization", format!("Bearer {session_token}"))
            .body(json!({"addresses":["127.0.0.1:4000"]}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(heartbeat.status(), StatusCode::OK);
        let event =
            tokio::time::timeout(Duration::from_secs(2), events.chunk())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert!(
            String::from_utf8(event.to_vec())
                .unwrap()
                .contains("event: heartbeat_ack")
        );

        let h2 = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .unwrap();
        let h2_register = h2
            .post(format!("{base}/v1/h2-realm/"))
            .header("authorization", "Bearer secret")
            .body(json!({"addresses":["[::1]:5000"]}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(h2_register.status(), StatusCode::OK);

        let deleted = client
            .delete(format!("{base}/v1/test-realm/"))
            .header("authorization", format!("Bearer {session_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        let expired = client
            .post(format!("{base}/v1/test-realm/heartbeat"))
            .header("authorization", format!("Bearer {session_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
        service.close().await.unwrap();
    }

    #[tokio::test]
    async fn serves_realm_api_over_tls_http2() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let options: HysteriaRealmServiceOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "tls":{
                    "enabled":true,
                    "certificate":cert.pem(),
                    "key":key_pair.serialize_pem()
                },
                "users":[{"name":"alice","token":"secret"}]
            }))
            .unwrap();
        let (mut service, handle) =
            HysteriaRealmService::new("realm-tls", options).unwrap();
        service.start(StartStage::Start).await.unwrap();
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .http2_prior_knowledge()
            .build()
            .unwrap();
        let response = client
            .post(format!(
                "https://{}/v1/tls-realm/",
                handle.local_addr().unwrap()
            ))
            .header("authorization", "Bearer secret")
            .body(json!({"addresses":["127.0.0.1:1000"]}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), hyper::Version::HTTP_2);
        service.close().await.unwrap();
    }
}
