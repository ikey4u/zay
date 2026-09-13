//! Clash-compatible HTTP control surface.

use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use futures_util::SinkExt as _;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, Record, RecordType},
};
use http_body_util::{
    BodyExt as _, Full, channel::Channel, combinators::BoxBody,
};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{
        ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
        ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE, AUTHORIZATION,
        CONTENT_TYPE, HeaderName, HeaderValue, LOCATION,
    },
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    common::{
        http::download,
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
    },
    log::{Factory as LogFactory, Level},
    option::ClashApiOptions,
    outbound::OutboundManager,
    route::Router,
};

type ApiBody = BoxBody<Bytes, Infallible>;

#[derive(Clone, Default)]
pub struct ClashApiHandle {
    local_addr: Arc<Mutex<Option<SocketAddr>>>,
}

impl ClashApiHandle {
    pub fn local_addr(&self) -> Option<SocketAddr> {
        *self
            .local_addr
            .lock()
            .expect("Clash API address lock poisoned")
    }
}

pub struct ClashApiServer {
    options: ClashApiOptions,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    log: Arc<LogFactory>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    handle: ClashApiHandle,
}

impl ClashApiServer {
    pub fn new(
        options: ClashApiOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        log: Arc<LogFactory>,
    ) -> io::Result<(Self, ClashApiHandle)> {
        if options.store_mode
            || options.store_selected
            || options.store_fakeip
            || !options.cache_file.is_empty()
            || !options.cache_id.is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache_file and related fields in Clash API is deprecated in sing-box 1.8.0, use experimental.cache_file instead.",
            ));
        }
        if !options.external_ui.is_empty() {
            match std::fs::metadata(&options.external_ui) {
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "external_ui is not a directory",
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let handle = ClashApiHandle::default();
        Ok((
            Self {
                options,
                router,
                outbounds,
                log,
                cancellation: CancellationToken::new(),
                task: None,
                handle: handle.clone(),
            },
            handle,
        ))
    }

    async fn bind(&mut self) -> io::Result<()> {
        if self.options.external_controller.is_empty() {
            return Ok(());
        }
        if !self.options.external_ui.is_empty() {
            tokio::fs::create_dir_all(&self.options.external_ui).await?;
            let mut entries =
                tokio::fs::read_dir(&self.options.external_ui).await?;
            if entries.next_entry().await?.is_none()
                && let Err(error) =
                    download_external_ui(&self.options, &self.outbounds).await
            {
                let _ = self
                    .log
                    .logger()
                    .error(format!("download external ui error: {error}"));
            }
        }
        let listener =
            TcpListener::bind(&self.options.external_controller).await?;
        *self
            .handle
            .local_addr
            .lock()
            .expect("Clash API address lock poisoned") =
            Some(listener.local_addr()?);
        let cancellation = self.cancellation.clone();
        let options = Arc::new(self.options.clone());
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        let log = self.log.clone();
        self.task = Some(tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    result = listener.accept() => {
                        let (stream, _) = result?;
                        let options = options.clone();
                        let router = router.clone();
                        let outbounds = outbounds.clone();
                        let log = log.clone();
                        let connection_cancellation = cancellation.clone();
                        connections.spawn(async move {
                            let _ = http1::Builder::new()
                                .keep_alive(true)
                                .serve_connection(
                                    TokioIo::new(stream),
                                    service_fn(move |request| dispatch(
                                        request,
                                        options.clone(),
                                        router.clone(),
                                        outbounds.clone(),
                                        log.clone(),
                                        connection_cancellation.clone(),
                                    )),
                                )
                                .with_upgrades()
                                .await;
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

impl Lifecycle for ClashApiServer {
    fn name(&self) -> &str {
        "clash api"
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage == StartStage::Started {
                self.bind().await.map_err(|error| LifecycleError::Start {
                    component: self.name().to_owned(),
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
            if let Some(task) = self.task.take() {
                task.await
                    .map_err(|error| LifecycleError::Close {
                        component: self.name().to_owned(),
                        message: error.to_string(),
                    })?
                    .map_err(|error| LifecycleError::Close {
                        component: self.name().to_owned(),
                        message: error.to_string(),
                    })?;
            }
            Ok(())
        })
    }
}

async fn dispatch(
    mut request: Request<Incoming>,
    options: Arc<ClashApiOptions>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    log: Arc<LogFactory>,
    cancellation: CancellationToken,
) -> Result<Response<ApiBody>, Infallible> {
    let origin = request.headers().get("origin").cloned();
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let wants_json = request
        .headers()
        .get(CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes() == b"application/json");
    let mut response = if request.method() == Method::OPTIONS {
        empty(StatusCode::NO_CONTENT)
    } else if !authenticated(&request, &options.secret) {
        json_response(
            StatusCode::UNAUTHORIZED,
            json!({"message":"Unauthorized"}),
        )
    } else {
        match (&method, path.as_str()) {
            (&Method::GET, "/") => {
                if !options.external_ui.is_empty() && !wants_json {
                    redirect(StatusCode::TEMPORARY_REDIRECT, "/ui/")
                } else {
                    json_response(StatusCode::OK, json!({"hello":"clash"}))
                }
            }
            (&Method::GET, "/ui") if !options.external_ui.is_empty() => {
                redirect(StatusCode::MOVED_PERMANENTLY, "/ui/")
            }
            (&Method::GET, path)
                if path.starts_with("/ui/")
                    && !options.external_ui.is_empty() =>
            {
                static_ui(&options.external_ui, &path[4..]).await
            }
            (&Method::GET, "/version") => json_response(
                StatusCode::OK,
                json!({
                    "version": format!("sing-box {}", crate::VERSION),
                    "premium": true,
                    "meta": true
                }),
            ),
            (&Method::GET, "/configs" | "/configs/") => json_response(
                StatusCode::OK,
                json!({
                    "port": 0,
                    "socks-port": 0,
                    "redir-port": 0,
                    "tproxy-port": 0,
                    "mixed-port": 0,
                    "allow-lan": false,
                    "bind-address": "*",
                    "mode": router.clash_mode().unwrap_or_default(),
                    "mode-list": router.clash_modes(),
                    "log-level": clash_config_log_level(log.level()),
                    "ipv6": false,
                    "tun": {}
                }),
            ),
            (&Method::PUT, "/configs" | "/configs/") => {
                empty(StatusCode::NO_CONTENT)
            }
            (&Method::PATCH, "/configs" | "/configs/") => {
                match request.collect().await {
                    Ok(body) => {
                        match serde_json::from_slice::<Value>(&body.to_bytes())
                        {
                            Ok(value) => {
                                if let Some(mode) =
                                    value.get("mode").and_then(Value::as_str)
                                    && !mode.is_empty()
                                {
                                    set_mode(&router, &outbounds, mode);
                                }
                                empty(StatusCode::NO_CONTENT)
                            }
                            Err(_) => json_response(
                                StatusCode::BAD_REQUEST,
                                json!({"message":"Body invalid"}),
                            ),
                        }
                    }
                    Err(_) => json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"message":"Body invalid"}),
                    ),
                }
            }
            (&Method::POST, "/cache/dns/flush") => {
                outbounds.dns().clear_cache();
                empty(StatusCode::NO_CONTENT)
            }
            (&Method::POST, "/cache/fakeip/flush") => {
                outbounds.dns().clear_fake_ip();
                empty(StatusCode::NO_CONTENT)
            }
            (&Method::GET, "/dns/query") => dns_query(&query, &outbounds).await,
            (&Method::GET, "/logs") => {
                logs(&mut request, &query, &log, cancellation)
            }
            (&Method::GET, "/traffic") => {
                traffic(&mut request, outbounds.clone(), cancellation)
            }
            (&Method::GET, "/memory") => memory(&mut request, cancellation),
            (&Method::POST, "/upgrade/ui" | "/upgrade/ui/") => {
                if options.external_ui.is_empty() {
                    json_response(
                        StatusCode::NOT_FOUND,
                        json!({"message":"external UI not enabled"}),
                    )
                } else {
                    let _ = log.logger().info("upgrading external UI");
                    match download_external_ui(&options, &outbounds).await {
                        Ok(()) => {
                            let _ = log.logger().info("updated external UI");
                            json_response(
                                StatusCode::OK,
                                json!({"status":"ok"}),
                            )
                        }
                        Err(error) => {
                            let _ = log
                                .logger()
                                .error(format!("upgrade external ui: {error}"));
                            json_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                json!({"message":error.to_string()}),
                            )
                        }
                    }
                }
            }
            (&Method::GET, "/connections" | "/connections/") => connections(
                &mut request,
                &query,
                outbounds.clone(),
                cancellation,
            ),
            (&Method::DELETE, "/connections" | "/connections/") => {
                outbounds.close_all_connections();
                empty(StatusCode::NO_CONTENT)
            }
            (&Method::DELETE, path) if path.starts_with("/connections/") => {
                let id = &path["/connections/".len()..];
                if !id.is_empty() && !id.contains('/') {
                    outbounds.close_connection(id);
                }
                empty(StatusCode::NO_CONTENT)
            }
            (&Method::GET, "/proxies" | "/proxies/") => all_proxies(&outbounds),
            (&Method::GET, path)
                if path.starts_with("/proxies/")
                    && path.ends_with("/delay") =>
            {
                proxy_delay(
                    &path["/proxies/".len()..path.len() - "/delay".len()],
                    &query,
                    &outbounds,
                )
                .await
            }
            (_, path) if path.starts_with("/proxies/") => {
                proxy_request(&method, path, request, &outbounds).await
            }
            (&Method::GET, "/group" | "/group/") => groups(&outbounds),
            (&Method::GET, path)
                if path.starts_with("/group/") && path.ends_with("/delay") =>
            {
                group_delay(
                    &path["/group/".len()..path.len() - "/delay".len()],
                    &query,
                    &outbounds,
                )
                .await
            }
            (&Method::GET, path) if path.starts_with("/group/") => {
                group(&outbounds, &path["/group/".len()..])
            }
            (&Method::GET, "/rules" | "/rules/") => json_response(
                StatusCode::OK,
                json!({"rules": router.clash_rules()}),
            ),
            (&Method::GET, "/providers/proxies" | "/providers/proxies/") => {
                json_response(StatusCode::OK, json!({"providers": {}}))
            }
            (&Method::GET, "/providers/rules" | "/providers/rules/") => {
                json_response(StatusCode::OK, json!({"providers": []}))
            }
            (_, path)
                if path.starts_with("/providers/proxies/")
                    || path.starts_with("/providers/rules/") =>
            {
                json_response(
                    StatusCode::NOT_FOUND,
                    json!({"message":"Resource not found"}),
                )
            }
            (&Method::POST, "/script" | "/script/") => json_response(
                StatusCode::BAD_REQUEST,
                json!({"message":"not implemented"}),
            ),
            (&Method::PATCH, "/script" | "/script/") => {
                empty(StatusCode::NO_CONTENT)
            }
            (&Method::GET, "/profile/tracing") => json_response(
                StatusCode::NOT_FOUND,
                json!({"message":"Resource not found"}),
            ),
            _ => json_response(
                StatusCode::NOT_FOUND,
                json!({"message":"Resource not found"}),
            ),
        }
    };
    add_cors(&request_origin(origin), &options, &mut response);
    Ok(response)
}

fn clash_config_log_level(level: Level) -> &'static str {
    match level {
        Level::Panic | Level::Fatal | Level::Error => "error",
        Level::Warn => "warning",
        Level::Info => "info",
        Level::Debug | Level::Trace => "debug",
    }
}

async fn download_external_ui(
    options: &ClashApiOptions,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let download_url = if options.external_ui_download_url.is_empty() {
        "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip"
    } else {
        &options.external_ui_download_url
    };
    let dialer = if options.external_ui_download_detour.is_empty() {
        outbounds.default()
    } else {
        outbounds
            .outbound(&options.external_ui_download_detour)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "detour outbound not found: {}",
                        options.external_ui_download_detour
                    ),
                )
            })?
    };
    let archive = download_http(dialer, download_url).await?;
    let output = PathBuf::from(&options.external_ui);
    tokio::task::spawn_blocking(move || {
        extract_external_ui(&archive, &output)
            .inspect_err(|_| clear_directory(&output))
    })
    .await
    .map_err(io::Error::other)?
}

async fn download_http(
    dialer: crate::outbound::SharedDialer,
    source: &str,
) -> io::Result<Bytes> {
    let response = download(dialer, source, &hyper::HeaderMap::new()).await?;
    if response.status != StatusCode::OK {
        return Err(io::Error::other(format!(
            "download external ui failed: {}",
            response.status
        )));
    }
    Ok(response.body)
}

fn extract_external_ui(archive: &[u8], output: &Path) -> io::Result<()> {
    let reader = std::io::Cursor::new(archive);
    let mut archive = zip::ZipArchive::new(reader).map_err(io::Error::other)?;
    let paths: Vec<_> = (0..archive.len())
        .filter_map(|index| {
            archive
                .by_index(index)
                .ok()
                .filter(|entry| !entry.is_dir())
                .and_then(|entry| entry.enclosed_name())
        })
        .collect();
    let first_directory = paths
        .first()
        .and_then(|path| path.components().next())
        .map(|component| component.as_os_str().to_owned())
        .filter(|_| paths.iter().all(|path| path.components().count() > 1))
        .filter(|first| {
            paths.iter().all(|path| {
                path.components()
                    .next()
                    .is_some_and(|component| component.as_os_str() == first)
            })
        });
    std::fs::create_dir_all(output)?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(io::Error::other)?;
        if entry.is_dir() {
            continue;
        }
        let path = entry.enclosed_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "external UI archive contains an unsafe path",
            )
        })?;
        let relative = if first_directory.is_some() {
            path.components().skip(1).collect::<PathBuf>()
        } else {
            path.to_owned()
        };
        if relative.as_os_str().is_empty() {
            continue;
        }
        let destination = output.join(relative);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::File::create(destination)?;
        std::io::copy(&mut entry, &mut file)?;
    }
    Ok(())
}

fn clear_directory(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(path);
        } else {
            let _ = std::fs::remove_file(path);
        }
    }
}

async fn proxy_delay(
    encoded_tag: &str,
    query: &str,
    outbounds: &OutboundManager,
) -> Response<ApiBody> {
    let Some((tag, url, timeout)) = delay_parameters(encoded_tag, query) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"message":"Body invalid"}),
        );
    };
    if outbounds.kind(&tag).is_none() {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({"message":"Resource not found"}),
        );
    }
    match outbounds.test_outbound_delay(&tag, &url, timeout).await {
        Ok(delay) if delay != 0 => {
            json_response(StatusCode::OK, json!({"delay": delay}))
        }
        Err(error) if error.kind() == io::ErrorKind::TimedOut => json_response(
            StatusCode::GATEWAY_TIMEOUT,
            json!({"message":"Timeout"}),
        ),
        _ => json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"message":"An error occurred in the delay test"}),
        ),
    }
}

async fn group_delay(
    encoded_tag: &str,
    query: &str,
    outbounds: &OutboundManager,
) -> Response<ApiBody> {
    let Some((tag, url, timeout)) = delay_parameters(encoded_tag, query) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"message":"Body invalid"}),
        );
    };
    if outbounds.group_choices(&tag).is_none() {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({"message":"Resource not found"}),
        );
    }
    match outbounds.test_group_delay(&tag, &url, timeout).await {
        Ok(result) => json_response(StatusCode::OK, json!(result)),
        Err(error) => json_response(
            StatusCode::GATEWAY_TIMEOUT,
            json!({"message":error.to_string()}),
        ),
    }
}

fn delay_parameters(
    encoded_tag: &str,
    query: &str,
) -> Option<(String, String, std::time::Duration)> {
    if encoded_tag.is_empty() || encoded_tag.contains('/') {
        return None;
    }
    let tag = percent_decode_str(encoded_tag)
        .decode_utf8()
        .ok()?
        .into_owned();
    let parameters: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
    let timeout = parameters.get("timeout")?.parse::<i64>().ok()?;
    let mut url = parameters.get("url").cloned().unwrap_or_default();
    if url.starts_with("http://") {
        url.clear();
    }
    Some((
        tag,
        url,
        std::time::Duration::from_millis(timeout.max(0) as u64),
    ))
}

fn logs(
    request: &mut Request<Incoming>,
    query: &str,
    log: &Arc<LogFactory>,
    cancellation: CancellationToken,
) -> Response<ApiBody> {
    let parameters: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
    let level = parameters
        .get("level")
        .map(String::as_str)
        .unwrap_or("info");
    let level = match Level::parse(level) {
        Ok(level) => level,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"message":"Body invalid"}),
            );
        }
    };
    let mut entries = match log.subscribe() {
        Ok(entries) => entries,
        Err(_) => return empty(StatusCode::NO_CONTENT),
    };
    let websocket = request
        .headers()
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if websocket {
        let Some(key) = request.headers().get("sec-websocket-key") else {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"message":"Body invalid"}),
            );
        };
        let accept =
            tokio_tungstenite::tungstenite::handshake::derive_accept_key(
                key.as_bytes(),
            );
        let upgrade = hyper::upgrade::on(request);
        tokio::spawn(async move {
            let upgraded = tokio::select! {
                _ = cancellation.cancelled() => return,
                result = upgrade => match result {
                    Ok(upgraded) => upgraded,
                    Err(_) => return,
                }
            };
            let mut socket =
                tokio_tungstenite::WebSocketStream::from_raw_socket(
                    TokioIo::new(upgraded),
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    None,
                )
                .await;
            loop {
                let entry = tokio::select! {
                    _ = cancellation.cancelled() => break,
                    entry = entries.recv() => match entry {
                        Some(entry) => entry,
                        None => break,
                    }
                };
                if entry.level > level {
                    continue;
                }
                let payload = json!({
                    "type": entry.level.as_str(),
                    "payload": entry.message
                })
                .to_string();
                if socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        payload.into(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = socket.close(None).await;
        });
        return Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-accept", accept)
            .body(full(Bytes::new()))
            .expect("valid WebSocket upgrade response");
    }

    let (mut sender, body) = Channel::<Bytes, Infallible>::new(16);
    tokio::spawn(async move {
        loop {
            let entry = tokio::select! {
                _ = cancellation.cancelled() => break,
                entry = entries.recv() => match entry {
                    Some(entry) => entry,
                    None => break,
                }
            };
            if entry.level > level {
                continue;
            }
            let payload = format!(
                "{}\n",
                json!({
                    "type": entry.level.as_str(),
                    "payload": entry.message
                })
            );
            if sender.send_data(Bytes::from(payload)).await.is_err() {
                break;
            }
        }
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(body.boxed())
        .expect("valid streaming log response")
}

fn traffic(
    request: &mut Request<Incoming>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
) -> Response<ApiBody> {
    let websocket = request
        .headers()
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if websocket {
        let Some(key) = request.headers().get("sec-websocket-key") else {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"message":"Body invalid"}),
            );
        };
        let accept =
            tokio_tungstenite::tungstenite::handshake::derive_accept_key(
                key.as_bytes(),
            );
        let upgrade = hyper::upgrade::on(request);
        tokio::spawn(async move {
            let upgraded = tokio::select! {
                _ = cancellation.cancelled() => return,
                result = upgrade => match result {
                    Ok(upgraded) => upgraded,
                    Err(_) => return,
                }
            };
            let mut socket =
                tokio_tungstenite::WebSocketStream::from_raw_socket(
                    TokioIo::new(upgraded),
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    None,
                )
                .await;
            let (mut previous_up, mut previous_down) =
                outbounds.traffic_totals();
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(1));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    _ = interval.tick() => {}
                }
                let (up, down) = outbounds.traffic_totals();
                let payload = json!({
                    "up": up.saturating_sub(previous_up),
                    "down": down.saturating_sub(previous_down)
                })
                .to_string();
                previous_up = up;
                previous_down = down;
                if socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        payload.into(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = socket.close(None).await;
        });
        return Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-accept", accept)
            .body(full(Bytes::new()))
            .expect("valid WebSocket upgrade response");
    }

    let (mut sender, body) = Channel::<Bytes, Infallible>::new(4);
    tokio::spawn(async move {
        let (mut previous_up, mut previous_down) = outbounds.traffic_totals();
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(1));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = interval.tick() => {}
            }
            let (up, down) = outbounds.traffic_totals();
            let payload = format!(
                "{}\n",
                json!({
                    "up": up.saturating_sub(previous_up),
                    "down": down.saturating_sub(previous_down)
                })
            );
            previous_up = up;
            previous_down = down;
            if sender.send_data(Bytes::from(payload)).await.is_err() {
                break;
            }
        }
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(body.boxed())
        .expect("valid streaming traffic response")
}

fn memory(
    request: &mut Request<Incoming>,
    cancellation: CancellationToken,
) -> Response<ApiBody> {
    let websocket = request
        .headers()
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if websocket {
        let Some(key) = request.headers().get("sec-websocket-key") else {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"message":"Body invalid"}),
            );
        };
        let accept =
            tokio_tungstenite::tungstenite::handshake::derive_accept_key(
                key.as_bytes(),
            );
        let upgrade = hyper::upgrade::on(request);
        tokio::spawn(async move {
            let upgraded = tokio::select! {
                _ = cancellation.cancelled() => return,
                result = upgrade => match result {
                    Ok(upgraded) => upgraded,
                    Err(_) => return,
                }
            };
            let mut socket =
                tokio_tungstenite::WebSocketStream::from_raw_socket(
                    TokioIo::new(upgraded),
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    None,
                )
                .await;
            let mut first = true;
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(1));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    _ = interval.tick() => {}
                }
                let inuse = if first {
                    first = false;
                    0
                } else {
                    inuse_memory()
                };
                let payload = json!({"inuse": inuse, "oslimit": 0});
                if socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        payload.to_string().into(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = socket.close(None).await;
        });
        return Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-accept", accept)
            .body(full(Bytes::new()))
            .expect("valid WebSocket upgrade response");
    }

    let (mut sender, body) = Channel::<Bytes, Infallible>::new(4);
    tokio::spawn(async move {
        let mut first = true;
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(1));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = interval.tick() => {}
            }
            let inuse = if first {
                first = false;
                0
            } else {
                inuse_memory()
            };
            let payload = format!(
                "{}\n",
                json!({
                    "inuse": inuse,
                    "oslimit": 0
                })
            );
            if sender.send_data(Bytes::from(payload)).await.is_err() {
                break;
            }
        }
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(body.boxed())
        .expect("valid streaming memory response")
}

fn inuse_memory() -> u64 {
    let Ok(pid) = sysinfo::get_current_pid() else {
        return 0;
    };
    sysinfo::System::new_all()
        .process(pid)
        .map(sysinfo::Process::memory)
        .unwrap_or(0)
}

fn connections(
    request: &mut Request<Incoming>,
    query: &str,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
) -> Response<ApiBody> {
    let websocket = request
        .headers()
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if !websocket {
        return json_response(StatusCode::OK, connections_value(&outbounds));
    }
    let parameters: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
    let interval = match parameters.get("interval") {
        Some(value) => match value.parse::<u64>() {
            Ok(value) => value,
            Err(_) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"message":"Body invalid"}),
                );
            }
        },
        None => 1_000,
    };
    let Some(key) = request.headers().get("sec-websocket-key") else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"message":"Body invalid"}),
        );
    };
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(
        key.as_bytes(),
    );
    let upgrade = hyper::upgrade::on(request);
    tokio::spawn(async move {
        let upgraded = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = upgrade => match result {
                Ok(upgraded) => upgraded,
                Err(_) => return,
            }
        };
        let mut socket = tokio_tungstenite::WebSocketStream::from_raw_socket(
            TokioIo::new(upgraded),
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;
        if socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                connections_value(&outbounds).to_string().into(),
            ))
            .await
            .is_ok()
        {
            let mut ticker = tokio::time::interval(
                std::time::Duration::from_millis(interval.max(1)),
            );
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    _ = ticker.tick() => {}
                }
                if socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        connections_value(&outbounds).to_string().into(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
        let _ = socket.close(None).await;
    });
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-accept", accept)
        .body(full(Bytes::new()))
        .expect("valid WebSocket upgrade response")
}

fn connections_value(outbounds: &OutboundManager) -> Value {
    let (upload_total, download_total) = outbounds.traffic_totals();
    let connections: Vec<_> = outbounds
        .connections()
        .into_iter()
        .map(|connection| {
            let (destination_ip, host, destination_port) = match &connection
                .destination
            {
                crate::common::network::SocksAddr::Ip(address) => {
                    (address.ip().to_string(), String::new(), address.port())
                }
                crate::common::network::SocksAddr::Domain { host, port } => {
                    (String::new(), host.clone(), *port)
                }
            };
            let start = time::OffsetDateTime::from(connection.created_at)
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            json!({
                "id": connection.id,
                "metadata": {
                    "network": connection.network,
                    "type": "",
                    "sourceIP": "",
                    "destinationIP": destination_ip,
                    "sourcePort": "0",
                    "destinationPort": destination_port.to_string(),
                    "host": host,
                    "dnsMode": "normal",
                    "processPath": ""
                },
                "upload": connection.upload,
                "download": connection.download,
                "start": start,
                "chains": [connection.outbound],
                "rule": "final",
                "rulePayload": ""
            })
        })
        .collect();
    json!({
        "downloadTotal": download_total,
        "uploadTotal": upload_total,
        "connections": connections,
        "memory": inuse_memory()
    })
}

fn groups(outbounds: &OutboundManager) -> Response<ApiBody> {
    let values: Vec<_> = outbounds
        .tags()
        .filter(|tag| outbounds.group_choices(tag).is_some())
        .map(|tag| proxy_info(outbounds, tag))
        .collect();
    json_response(StatusCode::OK, json!({"proxies": values}))
}

fn group(outbounds: &OutboundManager, encoded_tag: &str) -> Response<ApiBody> {
    if encoded_tag.is_empty() || encoded_tag.contains('/') {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({"message":"Resource not found"}),
        );
    }
    let Ok(tag) = percent_decode_str(encoded_tag).decode_utf8() else {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({"message":"Resource not found"}),
        );
    };
    if outbounds.group_choices(&tag).is_none() {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({"message":"Resource not found"}),
        );
    }
    json_response(StatusCode::OK, proxy_info(outbounds, &tag))
}

async fn dns_query(
    query: &str,
    outbounds: &OutboundManager,
) -> Response<ApiBody> {
    let parameters: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
    let name = parameters.get("name").map(String::as_str).unwrap_or("");
    let query_type = parameters.get("type").map(String::as_str).unwrap_or("A");
    let record_type =
        match RecordType::from_str(&query_type.to_ascii_uppercase()) {
            Ok(record_type) => record_type,
            Err(_) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"message":"invalid query type"}),
                );
            }
        };
    let fqdn = if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.")
    };
    let name = match Name::from_ascii(&fqdn) {
        Ok(name) => name,
        Err(error) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"message":error.to_string()}),
            );
        }
    };
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, record_type));
    let response = match tokio::time::timeout(
        crate::constant::DNS_TIMEOUT,
        outbounds.dns().exchange(&message),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"message":error.to_string()}),
            );
        }
        Err(error) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"message":error.to_string()}),
            );
        }
    };
    let mut value = json!({
        "Status": u16::from(response.metadata.response_code),
        "Question": response.queries.iter().map(|question| json!({
            "Name": question.name().to_utf8(),
            "Qtype": u16::from(question.query_type()),
            "Qclass": u16::from(question.query_class())
        })).collect::<Vec<_>>(),
        "Server": "internal",
        "TC": response.metadata.truncation,
        "RD": response.metadata.recursion_desired,
        "RA": response.metadata.recursion_available,
        "AD": response.metadata.authentic_data,
        "CD": response.metadata.checking_disabled
    });
    insert_records(&mut value, "Answer", &response.answers);
    insert_records(&mut value, "Authority", &response.authorities);
    insert_records(&mut value, "Additional", &response.additionals);
    json_response(StatusCode::OK, value)
}

fn insert_records(value: &mut Value, key: &str, records: &[Record]) {
    if records.is_empty() {
        return;
    }
    value[key] = Value::Array(
        records
            .iter()
            .map(|record| {
                json!({
                    "name": record.name.to_utf8(),
                    "type": u16::from(record.record_type()),
                    "TTL": record.ttl,
                    "data": record.data.to_string()
                })
            })
            .collect(),
    );
}

fn all_proxies(outbounds: &OutboundManager) -> Response<ApiBody> {
    let tags: Vec<_> = outbounds.tags().map(str::to_owned).collect();
    let mut selectable: Vec<_> = tags
        .iter()
        .filter(|tag| {
            !matches!(outbounds.kind(tag), Some("direct" | "block" | "dns"))
        })
        .cloned()
        .collect();
    if let Some(position) = selectable
        .iter()
        .position(|tag| tag == outbounds.default_tag())
    {
        selectable.swap(0, position);
    }
    let mut proxies = serde_json::Map::new();
    proxies.insert(
        "GLOBAL".into(),
        json!({
            "type": "Fallback",
            "name": "GLOBAL",
            "udp": true,
            "history": [],
            "all": selectable,
            "now": outbounds.default_tag()
        }),
    );
    for tag in tags {
        proxies.insert(tag.clone(), proxy_info(outbounds, &tag));
    }
    json_response(StatusCode::OK, json!({"proxies": proxies}))
}

async fn proxy_request(
    method: &Method,
    path: &str,
    request: Request<Incoming>,
    outbounds: &OutboundManager,
) -> Response<ApiBody> {
    let tail = &path["/proxies/".len()..];
    if tail.is_empty() || tail.contains('/') {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({"message":"Resource not found"}),
        );
    }
    let tag = match percent_decode_str(tail).decode_utf8() {
        Ok(tag) => tag.into_owned(),
        Err(_) => {
            return json_response(
                StatusCode::NOT_FOUND,
                json!({"message":"Resource not found"}),
            );
        }
    };
    if outbounds.kind(&tag).is_none() {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({"message":"Resource not found"}),
        );
    }
    if method == Method::GET {
        json_response(StatusCode::OK, proxy_info(outbounds, &tag))
    } else if method == Method::PUT {
        match request.collect().await {
            Ok(body) => match serde_json::from_slice::<Value>(&body.to_bytes())
            {
                Ok(value) => {
                    let Some(selected) =
                        value.get("name").and_then(Value::as_str)
                    else {
                        return json_response(
                            StatusCode::BAD_REQUEST,
                            json!({"message":"Body invalid"}),
                        );
                    };
                    if outbounds.kind(&tag) != Some("selector") {
                        return json_response(
                            StatusCode::BAD_REQUEST,
                            json!({"message":"Must be a Selector"}),
                        );
                    }
                    match outbounds.select_group(&tag, selected) {
                        Ok(()) => empty(StatusCode::NO_CONTENT),
                        Err(_) => json_response(
                            StatusCode::BAD_REQUEST,
                            json!({"message":"Selector update error: not found"}),
                        ),
                    }
                }
                Err(_) => json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"message":"Body invalid"}),
                ),
            },
            Err(_) => json_response(
                StatusCode::BAD_REQUEST,
                json!({"message":"Body invalid"}),
            ),
        }
    } else {
        json_response(
            StatusCode::NOT_FOUND,
            json!({"message":"Resource not found"}),
        )
    }
}

fn proxy_info(outbounds: &OutboundManager, tag: &str) -> Value {
    let kind = outbounds.kind(tag).unwrap_or_default();
    let history = outbounds
        .urltest_history_entry(tag)
        .map(|(checked, delay)| {
            let checked = time::OffsetDateTime::from(checked)
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            vec![json!({"time": checked, "delay": delay})]
        })
        .unwrap_or_default();
    let mut value = json!({
        "type": clash_proxy_type(kind),
        "name": tag,
        "udp": true,
        "history": history
    });
    if let Some(choices) = outbounds.group_choices(tag) {
        value["all"] = json!(choices);
        value["now"] = json!(outbounds.group_selected(tag).unwrap_or_default());
    }
    value
}

fn clash_proxy_type(kind: &str) -> &str {
    match kind {
        "block" => "Reject",
        "direct" => "Direct",
        "selector" => "Selector",
        "urltest" => "URLTest",
        "shadowsocks" => "Shadowsocks",
        "vmess" => "Vmess",
        "vless" => "Vless",
        "trojan" => "Trojan",
        "socks" => "Socks5",
        "http" => "Http",
        "hysteria" => "Hysteria",
        "hysteria2" => "Hysteria2",
        "tuic" => "Tuic",
        "ssh" => "SSH",
        "tor" => "Tor",
        "anytls" => "AnyTLS",
        "shadowtls" => "ShadowTLS",
        "snell" => "Snell",
        _ => kind,
    }
}

fn set_mode(router: &Router, outbounds: &OutboundManager, mode: &str) -> bool {
    if !router.set_clash_mode(mode) {
        return false;
    }
    if let Some(mode) = router.clash_mode() {
        outbounds.dns().set_clash_mode(Some(mode.clone()));
        outbounds.dns().clear_cache();
        outbounds.save_mode(&mode);
    }
    true
}

fn authenticated(request: &Request<Incoming>, secret: &str) -> bool {
    if secret.is_empty() {
        return true;
    }
    let websocket = request
        .headers()
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if websocket
        && request.uri().query().is_some_and(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .any(|(key, value)| key == "token" && value == secret)
        })
    {
        return true;
    }
    request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(&format!("Bearer {secret}"))
}

fn request_origin(origin: Option<HeaderValue>) -> Option<String> {
    origin.and_then(|value| value.to_str().ok().map(str::to_owned))
}

fn add_cors(
    origin: &Option<String>,
    options: &ClashApiOptions,
    response: &mut Response<ApiBody>,
) {
    let allowed = options.access_control_allow_origin.as_slice();
    let value = if allowed.is_empty() || allowed.iter().any(|item| item == "*")
    {
        Some("*")
    } else {
        origin
            .as_deref()
            .filter(|origin| allowed.iter().any(|allowed| allowed == origin))
    };
    if let Some(value) =
        value.and_then(|value| HeaderValue::from_str(value).ok())
    {
        response
            .headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE"),
    );
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type, Authorization"),
    );
    response
        .headers_mut()
        .insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("300"));
    if options.access_control_allow_private_network {
        response.headers_mut().insert(
            HeaderName::from_static("access-control-allow-private-network"),
            HeaderValue::from_static("true"),
        );
    }
}

fn json_response(status: StatusCode, value: Value) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .body(full(Bytes::from(value.to_string())))
        .expect("valid Clash API response")
}

fn empty(status: StatusCode) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .body(full(Bytes::new()))
        .expect("valid empty Clash API response")
}

fn redirect(status: StatusCode, location: &'static str) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .header(LOCATION, location)
        .body(full(Bytes::new()))
        .expect("valid Clash API redirect")
}

async fn static_ui(root: &str, relative: &str) -> Response<ApiBody> {
    let relative = match percent_decode_str(relative).decode_utf8() {
        Ok(relative) => relative,
        Err(_) => return empty(StatusCode::NOT_FOUND),
    };
    let mut safe = PathBuf::new();
    for component in Path::new(relative.as_ref()).components() {
        match component {
            Component::Normal(component) => safe.push(component),
            Component::CurDir => {}
            _ => return empty(StatusCode::NOT_FOUND),
        }
    }
    if safe.as_os_str().is_empty() {
        safe.push("index.html");
    }
    let path = Path::new(root).join(safe);
    let data = match tokio::fs::read(&path).await {
        Ok(data) => data,
        Err(_) => return empty(StatusCode::NOT_FOUND),
    };
    let content_type = match path.extension().and_then(|value| value.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .body(full(Bytes::from(data)))
        .expect("valid static UI response")
}

fn full(bytes: Bytes) -> ApiBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}
