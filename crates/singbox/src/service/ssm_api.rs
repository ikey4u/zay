//! Shadowsocks Server Management API (`ssm-api`) service.

use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::CONTENT_TYPE,
    server::conn::{http1, http2},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::{JoinHandle, JoinSet},
    time::{MissedTickBehavior, interval},
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::Stream,
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        tls::{ServerTlsConfig, build_server_config_with_default_alpn},
    },
    inbound::shadowsocks::ManagedShadowsocksHandle,
    option::SsmApiServiceOptions,
};

type ApiBody = BoxBody<Bytes, Infallible>;

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SsmUserObject {
    pub username: String,
    #[serde(
        rename = "uPSK",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub password: String,
    pub downlink_bytes: i64,
    pub uplink_bytes: i64,
    pub downlink_packets: i64,
    pub uplink_packets: i64,
    pub tcp_sessions: i64,
    pub udp_sessions: i64,
}

#[derive(Default)]
struct UserCounters {
    uplink: AtomicI64,
    downlink: AtomicI64,
    uplink_packets: AtomicI64,
    downlink_packets: AtomicI64,
    tcp_sessions: AtomicI64,
    udp_sessions: AtomicI64,
}

#[derive(Default)]
pub(crate) struct SsmTrafficManager {
    global: UserCounters,
    users: Mutex<HashMap<String, Arc<UserCounters>>>,
}

impl SsmTrafficManager {
    fn user(&self, username: &str) -> Arc<UserCounters> {
        self.users
            .lock()
            .expect("SSM traffic user lock poisoned")
            .entry(username.to_owned())
            .or_default()
            .clone()
    }

    pub(crate) fn track_tcp(
        self: &Arc<Self>,
        stream: Stream,
        user: &str,
    ) -> Stream {
        self.global.tcp_sessions.fetch_add(1, Ordering::Relaxed);
        let counters = self.user(user);
        counters.tcp_sessions.fetch_add(1, Ordering::Relaxed);
        Box::new(TrafficStream {
            inner: stream,
            global: self.clone(),
            user: counters,
        })
    }

    pub(crate) fn record_udp_session(&self, user: &str) {
        self.global.udp_sessions.fetch_add(1, Ordering::Relaxed);
        self.user(user).udp_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_udp_uplink(&self, user: &str, bytes: usize) {
        let bytes = i64::try_from(bytes).unwrap_or(i64::MAX);
        self.global.uplink.fetch_add(bytes, Ordering::Relaxed);
        self.global.uplink_packets.fetch_add(1, Ordering::Relaxed);
        let counters = self.user(user);
        counters.uplink.fetch_add(bytes, Ordering::Relaxed);
        counters.uplink_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_udp_downlink(&self, user: &str, bytes: usize) {
        let bytes = i64::try_from(bytes).unwrap_or(i64::MAX);
        self.global.downlink.fetch_add(bytes, Ordering::Relaxed);
        self.global.downlink_packets.fetch_add(1, Ordering::Relaxed);
        let counters = self.user(user);
        counters.downlink.fetch_add(bytes, Ordering::Relaxed);
        counters.downlink_packets.fetch_add(1, Ordering::Relaxed);
    }

    fn retain_users(&self, users: impl Iterator<Item = String>) {
        let keep: std::collections::HashSet<_> = users.collect();
        self.users
            .lock()
            .expect("SSM traffic user lock poisoned")
            .retain(|name, _| keep.contains(name));
    }

    fn read_user(&self, username: &str, clear: bool) -> SsmUserObject {
        let counters = self.user(username);
        SsmUserObject {
            username: username.to_owned(),
            uplink_bytes: load(&counters.uplink, clear),
            downlink_bytes: load(&counters.downlink, clear),
            uplink_packets: load(&counters.uplink_packets, clear),
            downlink_packets: load(&counters.downlink_packets, clear),
            tcp_sessions: load(&counters.tcp_sessions, clear),
            udp_sessions: load(&counters.udp_sessions, clear),
            ..SsmUserObject::default()
        }
    }

    fn read_global(&self, clear: bool) -> SsmUserObject {
        SsmUserObject {
            uplink_bytes: load(&self.global.uplink, clear),
            downlink_bytes: load(&self.global.downlink, clear),
            uplink_packets: load(&self.global.uplink_packets, clear),
            downlink_packets: load(&self.global.downlink_packets, clear),
            tcp_sessions: load(&self.global.tcp_sessions, clear),
            udp_sessions: load(&self.global.udp_sessions, clear),
            ..SsmUserObject::default()
        }
    }

    fn cache(&self) -> TrafficCache {
        let users = self
            .users
            .lock()
            .expect("SSM traffic user lock poisoned")
            .iter()
            .map(|(name, counters)| {
                (name.clone(), UserCounterCache::from(counters.as_ref()))
            })
            .collect();
        TrafficCache {
            global: UserCounterCache::from(&self.global),
            users,
        }
    }

    fn restore(&self, cache: &TrafficCache) {
        cache.global.store(&self.global);
        let mut users =
            self.users.lock().expect("SSM traffic user lock poisoned");
        users.clear();
        for (name, saved) in &cache.users {
            let counters = Arc::new(UserCounters::default());
            saved.store(&counters);
            users.insert(name.clone(), counters);
        }
    }
}

fn load(counter: &AtomicI64, clear: bool) -> i64 {
    if clear {
        counter.swap(0, Ordering::Relaxed)
    } else {
        counter.load(Ordering::Relaxed)
    }
}

struct TrafficStream {
    inner: Stream,
    global: Arc<SsmTrafficManager>,
    user: Arc<UserCounters>,
}

impl AsyncRead for TrafficStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if let Poll::Ready(Ok(())) = result {
            let count = i64::try_from(buffer.filled().len() - before)
                .unwrap_or(i64::MAX);
            self.global
                .global
                .uplink
                .fetch_add(count, Ordering::Relaxed);
            self.user.uplink.fetch_add(count, Ordering::Relaxed);
        }
        result
    }
}

impl AsyncWrite for TrafficStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, buffer);
        if let Poll::Ready(Ok(count)) = result {
            let count = i64::try_from(count).unwrap_or(i64::MAX);
            self.global
                .global
                .downlink
                .fetch_add(count, Ordering::Relaxed);
            self.user.downlink.fetch_add(count, Ordering::Relaxed);
        }
        result
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

struct SsmEndpoint {
    inbound: ManagedShadowsocksHandle,
    traffic: Arc<SsmTrafficManager>,
    users: Mutex<BTreeMap<String, String>>,
}

impl SsmEndpoint {
    fn new(inbound: ManagedShadowsocksHandle) -> Arc<Self> {
        let traffic = Arc::new(SsmTrafficManager::default());
        inbound.set_traffic(traffic.clone());
        Arc::new(Self {
            inbound,
            traffic,
            users: Mutex::new(BTreeMap::new()),
        })
    }

    fn list(&self) -> Vec<SsmUserObject> {
        self.users
            .lock()
            .expect("SSM user lock poisoned")
            .iter()
            .map(|(username, password)| SsmUserObject {
                username: username.clone(),
                password: password.clone(),
                ..SsmUserObject::default()
            })
            .collect()
    }

    fn get(&self, username: &str) -> Option<SsmUserObject> {
        let password = self
            .users
            .lock()
            .expect("SSM user lock poisoned")
            .get(username)
            .cloned()?;
        let mut user = self.traffic.read_user(username, false);
        user.password = password;
        Some(user)
    }

    fn mutate(&self, operation: UserMutation<'_>) -> io::Result<()> {
        let mut current = self.users.lock().expect("SSM user lock poisoned");
        let mut next = current.clone();
        match operation {
            UserMutation::Add(name, password) => {
                if next.contains_key(name) {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("user {name} already exists"),
                    ));
                }
                next.insert(name.to_owned(), password.to_owned());
            }
            UserMutation::Update(name, password) => {
                if !next.contains_key(name) {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("user {name} not found"),
                    ));
                }
                next.insert(name.to_owned(), password.to_owned());
            }
            UserMutation::Delete(name) => {
                if next.remove(name).is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("user {name} not found"),
                    ));
                }
            }
        }
        self.inbound.update_users(
            next.iter()
                .map(|(name, password)| (name.clone(), password.clone())),
        )?;
        self.traffic.retain_users(next.keys().cloned());
        *current = next;
        Ok(())
    }

    fn restore(
        &self,
        users: BTreeMap<String, String>,
        traffic: &TrafficCache,
    ) -> io::Result<()> {
        self.inbound.update_users(
            users
                .iter()
                .map(|(name, password)| (name.clone(), password.clone())),
        )?;
        self.traffic.restore(traffic);
        *self.users.lock().expect("SSM user lock poisoned") = users;
        Ok(())
    }
}

enum UserMutation<'a> {
    Add(&'a str, &'a str),
    Update(&'a str, &'a str),
    Delete(&'a str),
}

#[derive(Clone, Default)]
pub struct SsmApiHandle {
    local_addr: Arc<Mutex<Option<SocketAddr>>>,
}

impl SsmApiHandle {
    pub fn local_addr(&self) -> Option<SocketAddr> {
        *self
            .local_addr
            .lock()
            .expect("SSM API address lock poisoned")
    }
}

pub struct SsmApiServer {
    name: String,
    options: SsmApiServiceOptions,
    endpoints: Arc<BTreeMap<String, Arc<SsmEndpoint>>>,
    cache_path: Option<PathBuf>,
    tls: Option<ServerTlsConfig>,
    cancellation: CancellationToken,
    tasks: Vec<JoinHandle<io::Result<()>>>,
    handle: SsmApiHandle,
}

impl SsmApiServer {
    pub fn new(
        tag: impl Into<String>,
        options: SsmApiServiceOptions,
        managed: &HashMap<String, ManagedShadowsocksHandle>,
        base_path: &Path,
    ) -> io::Result<(Self, SsmApiHandle)> {
        if options.servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing servers",
            ));
        }
        let mut endpoints = BTreeMap::new();
        for (prefix, inbound_tag) in &options.servers {
            if prefix != "/"
                && (!prefix.starts_with('/') || prefix.ends_with('/'))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid SSM API route prefix {prefix:?}"),
                ));
            }
            let inbound = managed.get(inbound_tag).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("inbound {inbound_tag:?} is not a managed Shadowsocks server"))
            })?;
            endpoints.insert(prefix.clone(), SsmEndpoint::new(inbound.clone()));
        }
        let cache_path = (!options.cache_path.is_empty()).then(|| {
            let path = PathBuf::from(&options.cache_path);
            if path.is_relative() {
                base_path.join(path)
            } else {
                path
            }
        });
        let tls = options
            .tls
            .as_ref()
            .filter(|tls| tls.enabled)
            .map(|tls| {
                build_server_config_with_default_alpn(tls, &["h2", "http/1.1"])
            })
            .transpose()
            .map_err(io::Error::other)?;
        let handle = SsmApiHandle::default();
        let tag = tag.into();
        Ok((
            Self {
                name: format!("service/ssm-api[{tag}]"),
                options,
                endpoints: Arc::new(endpoints),
                cache_path,
                tls,
                cancellation: CancellationToken::new(),
                tasks: Vec::new(),
                handle: handle.clone(),
            },
            handle,
        ))
    }

    async fn bind(&mut self) -> io::Result<()> {
        if self.load_cache().await.is_err()
            && let Some(path) = &self.cache_path
        {
            let _ = tokio::fs::remove_file(path).await;
        }
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
            .expect("SSM API address lock poisoned") =
            Some(listener.local_addr()?);
        let endpoints = self.endpoints.clone();
        let cancellation = self.cancellation.clone();
        let tls = self.tls.clone();
        self.tasks.push(tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted?;
                        let endpoints = endpoints.clone();
                        let tls = tls.clone();
                        connections.spawn(async move {
                            if let Some(tls) = tls {
                                let stream = tls.accept_stream(Box::new(stream)).await?;
                                let h2 = stream.alpn_protocol() == Some(b"h2");
                                if h2 {
                                    http2::Builder::new(TokioExecutor::new())
                                        .serve_connection(TokioIo::new(stream), service_fn(move |request| dispatch(request, endpoints.clone())))
                                        .await.map_err(io::Error::other)?;
                                } else {
                                    http1::Builder::new().keep_alive(true)
                                        .serve_connection(TokioIo::new(stream), service_fn(move |request| dispatch(request, endpoints.clone())))
                                        .await.map_err(io::Error::other)?;
                                }
                            } else {
                                http1::Builder::new().keep_alive(true)
                                    .serve_connection(TokioIo::new(stream), service_fn(move |request| dispatch(request, endpoints.clone())))
                                    .await.map_err(io::Error::other)?;
                            }
                            Ok::<(), io::Error>(())
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            Ok(())
        }));
        if let Some(path) = self.cache_path.clone() {
            let endpoints = self.endpoints.clone();
            let cancellation = self.cancellation.clone();
            self.tasks.push(tokio::spawn(async move {
                let mut ticker = interval(std::time::Duration::from_secs(60));
                ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
                ticker.tick().await;
                loop {
                    tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = ticker.tick() => save_cache_at(&path, &endpoints).await?,
                    }
                }
                Ok(())
            }));
        }
        Ok(())
    }

    async fn load_cache(&self) -> io::Result<()> {
        let Some(path) = &self.cache_path else {
            return Ok(());
        };
        let data = match tokio::fs::read(path).await {
            Ok(data) => data,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if data.is_empty() {
            return Ok(());
        }
        let cache: Cache = serde_json::from_slice(&data).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, error)
        })?;
        for (prefix, saved) in cache.endpoints {
            if let Some(endpoint) = self.endpoints.get(&prefix) {
                let traffic = saved.traffic();
                endpoint.restore(saved.users, &traffic)?;
            }
        }
        Ok(())
    }
}

impl Lifecycle for SsmApiServer {
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
            for task in self.tasks.drain(..) {
                if let Err(error) = task.await
                    && !error.is_cancelled()
                {
                    return Err(LifecycleError::Close {
                        component: self.name.clone(),
                        message: error.to_string(),
                    });
                }
            }
            let save_result = if let Some(path) = &self.cache_path {
                save_cache_at(path, &self.endpoints).await
            } else {
                Ok(())
            };
            save_result.map_err(|error| LifecycleError::Close {
                component: self.name.clone(),
                message: error.to_string(),
            })
        })
    }
}

async fn dispatch(
    request: Request<Incoming>,
    endpoints: Arc<BTreeMap<String, Arc<SsmEndpoint>>>,
) -> Result<Response<ApiBody>, Infallible> {
    let path = request.uri().path();
    let selected = endpoints
        .iter()
        .filter_map(|(prefix, endpoint)| {
            let relative = if prefix == "/" {
                Some(path)
            } else {
                path.strip_prefix(prefix)
                    .filter(|rest| rest.starts_with('/'))
            }?;
            Some((prefix.len(), relative.to_owned(), endpoint.clone()))
        })
        .max_by_key(|entry| entry.0);
    let Some((_, path, endpoint)) = selected else {
        return Ok(empty(StatusCode::NOT_FOUND));
    };
    let response = dispatch_endpoint(request, &path, &endpoint).await;
    Ok(response)
}

async fn dispatch_endpoint(
    mut request: Request<Incoming>,
    path: &str,
    endpoint: &SsmEndpoint,
) -> Response<ApiBody> {
    if path == "/server/v1/" && request.method() == Method::GET {
        return json_response(
            StatusCode::OK,
            json!({"server": format!("sing-box {}", crate::VERSION), "apiVersion": "v1"}),
        );
    }
    if path == "/server/v1/users" {
        return match *request.method() {
            Method::GET => {
                json_response(StatusCode::OK, json!({"users": endpoint.list()}))
            }
            Method::POST => {
                #[derive(Deserialize)]
                struct Add {
                    username: String,
                    #[serde(rename = "uPSK")]
                    password: String,
                }
                let body = match request.body_mut().collect().await {
                    Ok(body) => body.to_bytes(),
                    Err(error) => {
                        return text_response(
                            StatusCode::BAD_REQUEST,
                            &error.to_string(),
                        );
                    }
                };
                let add: Add = match serde_json::from_slice(&body) {
                    Ok(add) => add,
                    Err(error) => {
                        return text_response(
                            StatusCode::BAD_REQUEST,
                            &error.to_string(),
                        );
                    }
                };
                match endpoint
                    .mutate(UserMutation::Add(&add.username, &add.password))
                {
                    Ok(()) => empty(StatusCode::CREATED),
                    Err(error) => text_response(
                        StatusCode::BAD_REQUEST,
                        &error.to_string(),
                    ),
                }
            }
            _ => empty(StatusCode::METHOD_NOT_ALLOWED),
        };
    }
    if path == "/server/v1/stats" && request.method() == Method::GET {
        let clear = request.uri().query().is_some_and(|query| {
            query.split('&').any(|part| part == "clear=true")
        });
        let users = endpoint
            .users
            .lock()
            .expect("SSM user lock poisoned")
            .keys()
            .map(|name| endpoint.traffic.read_user(name, clear))
            .collect::<Vec<_>>();
        let global = endpoint.traffic.read_global(clear);
        return json_response(
            StatusCode::OK,
            json!({
                "uplinkBytes": global.uplink_bytes,
                "downlinkBytes": global.downlink_bytes,
                "uplinkPackets": global.uplink_packets,
                "downlinkPackets": global.downlink_packets,
                "tcpSessions": global.tcp_sessions,
                "udpSessions": global.udp_sessions,
                "users": users,
            }),
        );
    }
    if let Some(encoded) = path.strip_prefix("/server/v1/users/") {
        let username = match percent_decode_str(encoded).decode_utf8() {
            Ok(value) if !value.is_empty() && !value.contains('/') => {
                value.into_owned()
            }
            _ => return empty(StatusCode::BAD_REQUEST),
        };
        return match *request.method() {
            Method::GET => endpoint.get(&username).map_or_else(
                || empty(StatusCode::NOT_FOUND),
                |user| json_response(StatusCode::OK, json!(user)),
            ),
            Method::PUT => {
                #[derive(Deserialize)]
                struct Update {
                    #[serde(rename = "uPSK")]
                    password: String,
                }
                let body = match request.body_mut().collect().await {
                    Ok(body) => body.to_bytes(),
                    Err(error) => {
                        return text_response(
                            StatusCode::BAD_REQUEST,
                            &error.to_string(),
                        );
                    }
                };
                let update: Update = match serde_json::from_slice(&body) {
                    Ok(update) => update,
                    Err(error) => {
                        return text_response(
                            StatusCode::BAD_REQUEST,
                            &error.to_string(),
                        );
                    }
                };
                match endpoint
                    .mutate(UserMutation::Update(&username, &update.password))
                {
                    Ok(()) => empty(StatusCode::NO_CONTENT),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        empty(StatusCode::NOT_FOUND)
                    }
                    Err(error) => text_response(
                        StatusCode::BAD_REQUEST,
                        &error.to_string(),
                    ),
                }
            }
            Method::DELETE => match endpoint
                .mutate(UserMutation::Delete(&username))
            {
                Ok(()) => empty(StatusCode::NO_CONTENT),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    empty(StatusCode::NOT_FOUND)
                }
                Err(error) => {
                    text_response(StatusCode::BAD_REQUEST, &error.to_string())
                }
            },
            _ => empty(StatusCode::METHOD_NOT_ALLOWED),
        };
    }
    empty(StatusCode::NOT_FOUND)
}

fn json_response(status: StatusCode, value: Value) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .body(full(Bytes::from(value.to_string())))
        .expect("valid SSM API response")
}

fn text_response(status: StatusCode, value: &str) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(Bytes::copy_from_slice(value.as_bytes())))
        .expect("valid SSM API response")
}

fn empty(status: StatusCode) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .body(full(Bytes::new()))
        .expect("valid SSM API response")
}

fn full(bytes: Bytes) -> ApiBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Cache {
    endpoints: BTreeMap<String, EndpointCache>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EndpointCache {
    global_uplink: i64,
    global_downlink: i64,
    global_uplink_packets: i64,
    global_downlink_packets: i64,
    global_tcp_sessions: i64,
    global_udp_sessions: i64,
    user_uplink: BTreeMap<String, i64>,
    user_downlink: BTreeMap<String, i64>,
    user_uplink_packets: BTreeMap<String, i64>,
    user_downlink_packets: BTreeMap<String, i64>,
    user_tcp_sessions: BTreeMap<String, i64>,
    user_udp_sessions: BTreeMap<String, i64>,
    users: BTreeMap<String, String>,
}

impl EndpointCache {
    fn new(users: BTreeMap<String, String>, traffic: TrafficCache) -> Self {
        let project = |select: fn(&UserCounterCache) -> i64| {
            traffic
                .users
                .iter()
                .filter_map(|(name, value)| {
                    let value = select(value);
                    (value != 0).then(|| (name.clone(), value))
                })
                .collect()
        };
        Self {
            global_uplink: traffic.global.uplink,
            global_downlink: traffic.global.downlink,
            global_uplink_packets: traffic.global.uplink_packets,
            global_downlink_packets: traffic.global.downlink_packets,
            global_tcp_sessions: traffic.global.tcp_sessions,
            global_udp_sessions: traffic.global.udp_sessions,
            user_uplink: project(|value| value.uplink),
            user_downlink: project(|value| value.downlink),
            user_uplink_packets: project(|value| value.uplink_packets),
            user_downlink_packets: project(|value| value.downlink_packets),
            user_tcp_sessions: project(|value| value.tcp_sessions),
            user_udp_sessions: project(|value| value.udp_sessions),
            users,
        }
    }

    fn traffic(&self) -> TrafficCache {
        let mut names = std::collections::BTreeSet::new();
        names.extend(self.user_uplink.keys().cloned());
        names.extend(self.user_downlink.keys().cloned());
        names.extend(self.user_uplink_packets.keys().cloned());
        names.extend(self.user_downlink_packets.keys().cloned());
        names.extend(self.user_tcp_sessions.keys().cloned());
        names.extend(self.user_udp_sessions.keys().cloned());
        let users = names
            .into_iter()
            .map(|name| {
                let counters = UserCounterCache {
                    uplink: self.user_uplink.get(&name).copied().unwrap_or(0),
                    downlink: self
                        .user_downlink
                        .get(&name)
                        .copied()
                        .unwrap_or(0),
                    uplink_packets: self
                        .user_uplink_packets
                        .get(&name)
                        .copied()
                        .unwrap_or(0),
                    downlink_packets: self
                        .user_downlink_packets
                        .get(&name)
                        .copied()
                        .unwrap_or(0),
                    tcp_sessions: self
                        .user_tcp_sessions
                        .get(&name)
                        .copied()
                        .unwrap_or(0),
                    udp_sessions: self
                        .user_udp_sessions
                        .get(&name)
                        .copied()
                        .unwrap_or(0),
                };
                (name, counters)
            })
            .collect();
        TrafficCache {
            global: UserCounterCache {
                uplink: self.global_uplink,
                downlink: self.global_downlink,
                uplink_packets: self.global_uplink_packets,
                downlink_packets: self.global_downlink_packets,
                tcp_sessions: self.global_tcp_sessions,
                udp_sessions: self.global_udp_sessions,
            },
            users,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TrafficCache {
    global: UserCounterCache,
    users: BTreeMap<String, UserCounterCache>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct UserCounterCache {
    uplink: i64,
    downlink: i64,
    uplink_packets: i64,
    downlink_packets: i64,
    tcp_sessions: i64,
    udp_sessions: i64,
}

impl From<&UserCounters> for UserCounterCache {
    fn from(value: &UserCounters) -> Self {
        Self {
            uplink: value.uplink.load(Ordering::Relaxed),
            downlink: value.downlink.load(Ordering::Relaxed),
            uplink_packets: value.uplink_packets.load(Ordering::Relaxed),
            downlink_packets: value.downlink_packets.load(Ordering::Relaxed),
            tcp_sessions: value.tcp_sessions.load(Ordering::Relaxed),
            udp_sessions: value.udp_sessions.load(Ordering::Relaxed),
        }
    }
}

impl UserCounterCache {
    fn store(&self, value: &UserCounters) {
        value.uplink.store(self.uplink, Ordering::Relaxed);
        value.downlink.store(self.downlink, Ordering::Relaxed);
        value
            .uplink_packets
            .store(self.uplink_packets, Ordering::Relaxed);
        value
            .downlink_packets
            .store(self.downlink_packets, Ordering::Relaxed);
        value
            .tcp_sessions
            .store(self.tcp_sessions, Ordering::Relaxed);
        value
            .udp_sessions
            .store(self.udp_sessions, Ordering::Relaxed);
    }
}

async fn save_cache_at(
    path: &Path,
    endpoints: &BTreeMap<String, Arc<SsmEndpoint>>,
) -> io::Result<()> {
    let cache = Cache {
        endpoints: endpoints
            .iter()
            .map(|(prefix, endpoint)| {
                let users = endpoint
                    .users
                    .lock()
                    .expect("SSM user lock poisoned")
                    .clone();
                (
                    prefix.clone(),
                    EndpointCache::new(users, endpoint.traffic.cache()),
                )
            })
            .collect(),
    };
    let mut data =
        serde_json::to_vec_pretty(&cache).map_err(io::Error::other)?;
    data.push(b'\n');
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension("tmp");
    tokio::fs::write(&temporary, data).await?;
    tokio::fs::rename(temporary, path).await
}
