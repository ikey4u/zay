//! Embedded React WebUI and in-process core control.

use std::{
    collections::HashMap,
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use clap::Args;
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use tokio::sync::Notify;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value, value};

use crate::{runtime::CoreSupervisor, settings};

const INDEX_HTML: &str =
    include_str!(concat!(env!("OUT_DIR"), "/webui/index.html"));
const APP_JS: &str = include_str!(concat!(env!("OUT_DIR"), "/webui/app.js"));
const APP_CSS: &str = include_str!(concat!(env!("OUT_DIR"), "/webui/app.css"));
const LOGO_SVG: &str =
    include_str!(concat!(env!("OUT_DIR"), "/webui/logo.svg"));

fn default_listen() -> SocketAddr {
    "127.0.0.1:8787"
        .parse()
        .expect("valid WebUI listen address")
}

#[derive(Args, Debug, Clone)]
pub struct WebUiCli {
    /// Address for the WebUI (loopback by default; no desktop is required)
    #[arg(long, default_value_t = default_listen())]
    listen: SocketAddr,
    /// Open the WebUI in the platform browser after startup
    #[arg(long)]
    open: bool,
    /// Bearer token required when listening beyond loopback
    #[arg(long, env = "ZAY_WEBUI_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// Start only the WebUI; leave enabled core components stopped
    #[arg(long = "no-start-core", default_value_t = true, action = clap::ArgAction::SetFalse)]
    start_core: bool,
    /// Zay data directory
    #[arg(short, long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
    /// Path to zay.toml
    #[arg(short = 'c', long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Clone)]
struct AppState {
    data_dir: PathBuf,
    config_path: PathBuf,
    token: Option<Arc<str>>,
    core: Arc<CoreSupervisor>,
    shutdown: Arc<Notify>,
    node_latencies: Arc<Mutex<HashMap<String, NodeTestResult>>>,
}

#[derive(Debug, Clone, Serialize)]
struct NodeTestResult {
    id: String,
    latency_ms: Option<u64>,
    error: Option<String>,
    checked_at: String,
}

#[derive(Debug, Deserialize)]
struct NodeTestRequest {
    #[serde(default)]
    nodes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ConfigUpdate {
    proxy: ProxyInput,
    #[serde(default)]
    mesh: MeshInput,
}

#[derive(Debug, Deserialize)]
struct ProxyInput {
    enabled: bool,
    #[serde(default)]
    subscriptions: Vec<String>,
    #[serde(default)]
    active_nodes: Vec<String>,
    #[serde(default)]
    gateway: bool,
    mixed_port: u16,
    update_interval: u64,
    health_check_url: String,
    log_level: String,
    tun_enabled: bool,
    #[serde(default)]
    tun_exclude_routes: Vec<String>,
    #[serde(default)]
    domain_rules: Vec<DomainRuleInput>,
}

#[derive(Debug, Deserialize)]
struct DomainRuleInput {
    #[serde(default = "default_enabled")]
    enabled: bool,
    name: String,
    #[serde(default)]
    by_suffix: Vec<String>,
    #[serde(default)]
    host: Vec<String>,
    #[serde(default)]
    process: Vec<String>,
    #[serde(default)]
    source: Vec<String>,
    #[serde(default)]
    destination: Vec<String>,
    #[serde(default)]
    outbounds: Vec<String>,
    health_check_url: Option<String>,
    interval: Option<u64>,
    tolerance: Option<u16>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct MeshInput {
    enabled: bool,
    role: String,
    name: String,
    network_name: String,
    network_secret: String,
    ipv4: String,
    listeners: Vec<String>,
    peers: Vec<String>,
    proxy_networks: Vec<String>,
    mesh_routes: Vec<String>,
    wireguard_listen: String,
    wireguard_client_cidr: String,
    wireguard_client_address: String,
}

impl Default for MeshInput {
    fn default() -> Self {
        Self {
            enabled: false,
            role: "node".into(),
            name: String::new(),
            network_name: String::new(),
            network_secret: String::new(),
            ipv4: String::new(),
            listeners: Vec::new(),
            peers: Vec::new(),
            proxy_networks: Vec::new(),
            mesh_routes: Vec::new(),
            wireguard_listen: String::new(),
            wireguard_client_cidr: String::new(),
            wireguard_client_address: String::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: &'static str,
    message: String,
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    error: anyhow::Error,
}

impl ApiError {
    fn new(
        status: StatusCode,
        code: &'static str,
        error: impl Into<anyhow::Error>,
    ) -> Self {
        Self {
            status,
            code,
            error: error.into(),
        }
    }

    fn bad_request(error: impl Into<anyhow::Error>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", error)
    }

    fn internal(error: impl Into<anyhow::Error>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                error: self.code,
                message: format!("{:#}", self.error),
            }),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

pub fn run(cli: WebUiCli) -> Result<()> {
    if !cli.listen.ip().is_loopback()
        && cli.token.as_deref().is_none_or(|token| token.len() < 16)
    {
        bail!(
            "--token (at least 16 characters) is required when WebUI listens beyond loopback"
        );
    }
    let (data_dir, config_path) = settings::stack_config_paths(
        cli.data_dir.as_deref(),
        cli.config.as_deref(),
    );
    settings::ensure_zay_toml(&data_dir, &config_path)?;
    #[cfg(unix)]
    let startup_password = if cli.start_core {
        let cfg = settings::load_persistent_config(
            Some(&data_dir),
            Some(&config_path),
        )?;
        if cfg.requires_root() && !crate::privilege::is_root() {
            crate::privilege::prompt_core_authorization()?
        } else {
            None
        }
    } else {
        None
    };
    #[cfg(not(unix))]
    let startup_password = None;
    tokio::runtime::Runtime::new()
        .context("creating WebUI runtime")?
        .block_on(run_async(cli, startup_password))
}

async fn run_async(
    cli: WebUiCli,
    startup_password: Option<String>,
) -> Result<()> {
    let (data_dir, config_path) = settings::stack_config_paths(
        cli.data_dir.as_deref(),
        cli.config.as_deref(),
    );
    settings::ensure_zay_toml(&data_dir, &config_path)?;
    let core =
        Arc::new(CoreSupervisor::new(data_dir.clone(), config_path.clone()));
    let shutdown = Arc::new(Notify::new());
    let startup_error = if cli.start_core {
        core.start(startup_password)
            .await
            .err()
            .map(|error| format!("{error:#}"))
    } else {
        None
    };
    let state = AppState {
        data_dir,
        config_path,
        token: cli.token.map(Arc::from),
        core: core.clone(),
        shutdown: shutdown.clone(),
        node_latencies: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/assets/app.js", get(javascript))
        .route("/assets/app.css", get(stylesheet))
        .route("/logo.svg", get(logo))
        .route("/api/v1/state", get(get_state))
        .route("/api/v1/config", put(update_config))
        .route("/api/v1/core/start", post(start_core))
        .route("/api/v1/core/stop", post(stop_core))
        .route("/api/v1/core/restart", post(restart_core))
        .route("/api/v1/proxy/nodes/test", post(test_proxy_nodes))
        .route("/api/v1/exit", post(exit_webui))
        .route("/api/v1/logs", get(get_logs))
        .route("/api/v1/events", get(get_events))
        .route("/api/v1/process-traffic", get(get_process_traffic))
        .route(
            "/api/v1/process-traffic/{action}",
            post(set_process_traffic),
        )
        .route(
            "/api/v1/rules/{group}/{name}",
            get(get_rule_set).put(put_rule_set),
        )
        .layer(DefaultBodyLimit::max(32 * 1024 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("binding WebUI to {}", cli.listen))?;
    let address = listener.local_addr().context("reading WebUI address")?;
    let display_host = if address.ip().is_unspecified() {
        "127.0.0.1".to_string()
    } else {
        address.ip().to_string()
    };
    let url = format!("http://{display_host}:{}/", address.port());
    println!("Zay WebUI: {url}");
    if let Some(error) = startup_error {
        eprintln!("core not started: {error}");
    }
    if !address.ip().is_loopback() {
        println!("Remote API access requires the configured bearer token.");
    }
    if cli.open {
        open_browser(&url);
    }

    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown))
        .await
        .context("serving WebUI");
    core.stop().await.context("stopping core")?;
    result
}

async fn shutdown_signal(shutdown: Arc<Notify>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
                _ = shutdown.notified() => {},
            }
            return;
        }
    }
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = shutdown.notified() => {},
    }
}

async fn index() -> Response {
    static_asset(INDEX_HTML, "text/html; charset=utf-8")
}
async fn javascript() -> Response {
    static_asset(APP_JS, "text/javascript; charset=utf-8")
}
async fn stylesheet() -> Response {
    static_asset(APP_CSS, "text/css; charset=utf-8")
}
async fn logo() -> Response {
    static_asset(LOGO_SVG, "image/svg+xml; charset=utf-8")
}

fn static_asset(body: &'static str, content_type: &'static str) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-cache")
        .header("X-Content-Type-Options", "nosniff")
        .header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        .body(Body::from(body))
        .expect("valid static response")
}

async fn get_state(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    Ok(Json(snapshot(&state).await?))
}

async fn update_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ConfigUpdate>,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    let raw =
        fs::read_to_string(&state.config_path).map_err(ApiError::internal)?;
    let mut doc = raw.parse::<DocumentMut>().map_err(ApiError::bad_request)?;
    apply_config(&mut doc, input).map_err(ApiError::bad_request)?;
    let next = doc.to_string();
    settings::validate_persistent_toml(&next).map_err(ApiError::bad_request)?;
    atomic_write(&state.config_path, next.as_bytes())
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true, "restart_required": true })))
}

async fn start_core(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    state.core.start(None).await.map_err(core_error)?;
    Ok(Json(snapshot(&state).await?))
}

async fn stop_core(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    state.core.stop().await.map_err(ApiError::internal)?;
    Ok(Json(snapshot(&state).await?))
}

async fn restart_core(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    state.core.restart(None).await.map_err(core_error)?;
    Ok(Json(snapshot(&state).await?))
}

async fn test_proxy_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<NodeTestRequest>,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    let port = clash_api_port(&state).map_err(ApiError::bad_request)?;
    let raw =
        fs::read_to_string(&state.config_path).map_err(ApiError::internal)?;
    let config: toml::Value =
        toml::from_str(&raw).map_err(ApiError::internal)?;
    let health_url = config["proxy"]["health_check_url"]
        .as_str()
        .unwrap_or("https://www.gstatic.com/generate_204")
        .to_string();
    let available = proxy_node_tags(&state.data_dir);
    let requested = if input.nodes.is_empty() {
        available
    } else {
        input
            .nodes
            .into_iter()
            .filter(|tag| available.contains(tag))
            .collect::<Vec<_>>()
    };
    if requested.is_empty() {
        return Err(ApiError::bad_request(anyhow::anyhow!(
            "no available proxy nodes selected"
        )));
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(ApiError::internal)?;
    let results = stream::iter(requested.into_iter().map(|tag| {
        let client = client.clone();
        let health_url = health_url.clone();
        async move {
            let endpoint = node_delay_url(port, &tag, &health_url);
            let result = async {
                let response = client.get(endpoint).send().await?;
                if !response.status().is_success() {
                    let status = response.status();
                    let body = response.bytes().await?;
                    anyhow::bail!(
                        "health check returned {status}: {}",
                        String::from_utf8_lossy(&body)
                    );
                }
                let body = response.bytes().await?;
                let value = serde_json::from_slice::<JsonValue>(&body)?;
                value["delay"]
                    .as_u64()
                    .context("health check returned no delay")
            }
            .await;
            NodeTestResult {
                id: tag,
                latency_ms: result.as_ref().ok().copied(),
                error: result.err().map(|error| format!("{error:#}")),
                checked_at: chrono::Utc::now()
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            }
        }
    }))
    .buffer_unordered(8)
    .collect::<Vec<_>>()
    .await;
    {
        let mut cache =
            state.node_latencies.lock().expect("node latency cache");
        for result in &results {
            cache.insert(result.id.clone(), result.clone());
        }
    }
    Ok(Json(json!({ "results": results })))
}

fn clash_api_port(state: &AppState) -> Result<u16> {
    let port_path = state
        .data_dir
        .join(settings::SINGBOX_DIR)
        .join("clash-api-port");
    fs::read_to_string(&port_path)
        .with_context(|| {
            format!(
                "a running proxy core is required ({})",
                port_path.display()
            )
        })?
        .trim()
        .parse::<u16>()
        .context("invalid Clash API port")
}

async fn get_process_traffic(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    Ok(Json(
        process_traffic_request(&state, reqwest::Method::GET, "").await?,
    ))
}

async fn set_process_traffic(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(action): AxumPath<String>,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    if action != "enable" && action != "disable" {
        return Err(ApiError::bad_request(anyhow::anyhow!(
            "process traffic action must be enable or disable"
        )));
    }
    Ok(Json(
        process_traffic_request(&state, reqwest::Method::POST, &action).await?,
    ))
}

async fn process_traffic_request(
    state: &AppState,
    method: reqwest::Method,
    action: &str,
) -> ApiResult<JsonValue> {
    let port = clash_api_port(state).map_err(ApiError::bad_request)?;
    let suffix = if action.is_empty() {
        String::new()
    } else {
        format!("/{action}")
    };
    let endpoint =
        format!("http://127.0.0.1:{port}/zay/process-traffic{suffix}");
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(ApiError::internal)?;
    let response = client
        .request(method, endpoint)
        .send()
        .await
        .map_err(ApiError::internal)?;
    let status = response.status();
    let body = response.bytes().await.map_err(ApiError::internal)?;
    if !status.is_success() {
        return Err(ApiError::internal(anyhow::anyhow!(
            "process traffic API returned {status}: {}",
            String::from_utf8_lossy(&body)
        )));
    }
    serde_json::from_slice(&body).map_err(ApiError::internal)
}

fn node_delay_url(port: u16, tag: &str, health_url: &str) -> reqwest::Url {
    let mut endpoint =
        reqwest::Url::parse(&format!("http://127.0.0.1:{port}/proxies"))
            .expect("valid loopback Clash API URL");
    endpoint
        .path_segments_mut()
        .expect("Clash API URL supports path segments")
        .push(tag)
        .push("delay");
    endpoint
        .query_pairs_mut()
        .append_pair("url", health_url)
        .append_pair("timeout", "5000");
    endpoint
}

async fn exit_webui(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    state.core.stop().await.map_err(ApiError::internal)?;
    state.shutdown.notify_one();
    Ok(Json(json!({ "ok": true })))
}

fn core_error(error: anyhow::Error) -> ApiError {
    if format!("{error:#}").contains("administrator authorization expired") {
        ApiError::new(
            StatusCode::CONFLICT,
            "terminal_authorization_required",
            error,
        )
    } else {
        ApiError::internal(error)
    }
}

async fn get_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    let path = state.data_dir.join("logs").join("zay.log");
    let text = read_rolling_tail(&path, 128 * 1024)?;
    let lines: Vec<&str> = text.lines().rev().take(400).collect();
    Ok(Json(json!({
        "path": path,
        "text": lines.into_iter().rev().collect::<Vec<_>>().join("\n")
    })))
}

async fn get_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    let path = state.data_dir.join("logs").join("events.jsonl");
    let events = read_recent_json_events(&path, 600)?;
    Ok(Json(json!({ "path": path, "events": events })))
}

async fn get_rule_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((group, name)): AxumPath<(String, String)>,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    let path = rule_set_path(&state, &group, &name)?;
    let bytes = fs::read(&path).map_err(ApiError::internal)?;
    let content = std::str::from_utf8(&bytes).ok();
    Ok(Json(json!({
        "group": group,
        "name": name,
        "bytes": bytes.len(),
        "binary": content.is_none(),
        "editable": group == "external",
        "content": content,
    })))
}

async fn put_rule_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((group, name)): AxumPath<(String, String)>,
    bytes: Bytes,
) -> ApiResult<Json<JsonValue>> {
    authorize(&state, &headers)?;
    if group != "external" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "read_only_rule_set",
            anyhow::anyhow!("built-in rule sets are read-only"),
        ));
    }
    let path = rule_set_path(&state, &group, &name)?;
    if name.ends_with(".json") {
        let value = serde_json::from_slice::<JsonValue>(&bytes)
            .map_err(ApiError::bad_request)?;
        if !value["rules"].is_array() {
            return Err(ApiError::bad_request(anyhow::anyhow!(
                "sing-box rule-set JSON must contain a rules array"
            )));
        }
    } else if bytes.is_empty() {
        return Err(ApiError::bad_request(anyhow::anyhow!(
            "binary rule-set must not be empty"
        )));
    }
    atomic_write(&path, &bytes).map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true, "restart_required": true })))
}

fn rule_set_path(
    state: &AppState,
    group: &str,
    name: &str,
) -> ApiResult<PathBuf> {
    let valid_name = Path::new(name)
        .file_name()
        .and_then(|candidate| candidate.to_str())
        .is_some_and(|candidate| candidate == name)
        && (name.ends_with(".json") || name.ends_with(".srs"));
    if !valid_name {
        return Err(ApiError::bad_request(anyhow::anyhow!(
            "invalid rule-set file name"
        )));
    }
    let singbox_dir = state.data_dir.join(settings::SINGBOX_DIR);
    let directory = match group {
        "builtin" => crate::singbox::rules::embedded_ruleset_dir(&singbox_dir),
        "external" => crate::singbox::rules::download_ruleset_dir(&singbox_dir),
        _ => {
            return Err(ApiError::bad_request(anyhow::anyhow!(
                "rule-set group must be builtin or external"
            )));
        }
    };
    Ok(directory.join(name))
}

fn read_recent_json_events(
    path: &Path,
    limit: usize,
) -> ApiResult<Vec<JsonValue>> {
    let text = read_rolling_tail(path, 512 * 1024)?;
    let mut events = text
        .lines()
        .filter_map(|line| serde_json::from_str::<JsonValue>(line).ok())
        .rev()
        .take(limit)
        .collect::<Vec<_>>();
    events.reverse();
    Ok(events)
}

fn read_rolling_tail(path: &Path, max_bytes: usize) -> ApiResult<String> {
    let Some(parent) = path.parent() else {
        return Ok(String::new());
    };
    let Some(base) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(String::new());
    };
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(String::new());
        }
        Err(error) => return Err(ApiError::internal(error)),
    };
    let mut files = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            if name != base && !name.starts_with(&format!("{base}.")) {
                return None;
            }
            let metadata = entry.metadata().ok()?;
            metadata
                .is_file()
                .then_some((metadata.modified().ok(), entry.path()))
        })
        .collect::<Vec<_>>();
    files.sort_by_key(|(modified, _)| *modified);
    let mut chunks = Vec::new();
    let mut remaining = max_bytes;
    for (_, file) in files.into_iter().rev() {
        if remaining == 0 {
            break;
        }
        let bytes = fs::read(file).map_err(ApiError::internal)?;
        let start = bytes.len().saturating_sub(remaining);
        let chunk = bytes[start..].to_vec();
        remaining = remaining.saturating_sub(chunk.len());
        chunks.push(chunk);
    }
    chunks.reverse();
    let bytes = chunks.into_iter().flatten().collect::<Vec<_>>();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn authorize(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let Some(expected) = state.token.as_deref() else {
        return Ok(());
    };
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if constant_time_eq(expected.as_bytes(), supplied.as_bytes()) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            anyhow::anyhow!("a valid WebUI bearer token is required"),
        ))
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        diff |= usize::from(
            left.get(index).copied().unwrap_or(0)
                ^ right.get(index).copied().unwrap_or(0),
        );
    }
    diff == 0
}

async fn snapshot(state: &AppState) -> ApiResult<JsonValue> {
    let raw =
        fs::read_to_string(&state.config_path).map_err(ApiError::internal)?;
    let config: toml::Value =
        toml::from_str(&raw).map_err(ApiError::internal)?;
    let core = state.core.status().await;
    let mesh =
        if core.running {
            state.core.mesh_status().await.unwrap_or_else(
                |error| json!({ "error": format!("{error:#}") }),
            )
        } else {
            json!([])
        };
    Ok(json!({
        "version": env!("ZAY_VERSION"),
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "process_attribution": crate::platform::process_attribution::backend_name(),
        },
        "core": core,
        "mesh": mesh,
        "proxy_nodes": proxy_nodes(
            &state.data_dir,
            &state.node_latencies.lock().expect("node latency cache"),
        ),
        "rule_sets": rule_set_inventory(&state.data_dir),
        "config": config,
        "paths": {
            "data_dir": state.data_dir,
            "config": state.config_path,
            "log": state.data_dir.join("logs").join("zay.log"),
        }
    }))
}

fn rule_set_inventory(data_dir: &Path) -> JsonValue {
    let singbox_dir = data_dir.join(settings::SINGBOX_DIR);
    json!({
        "builtin": rule_set_files(
            &crate::singbox::rules::embedded_ruleset_dir(&singbox_dir),
            false,
        ),
        "external": rule_set_files(
            &crate::singbox::rules::download_ruleset_dir(&singbox_dir),
            true,
        ),
    })
}

fn rule_set_files(directory: &Path, editable: bool) -> Vec<JsonValue> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut files = entries
        .flatten()
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            if !metadata.is_file() {
                return None;
            }
            let name = entry.file_name().to_str()?.to_string();
            if !name.ends_with(".json") && !name.ends_with(".srs") {
                return None;
            }
            Some(json!({
                "id": name.trim_end_matches(".json").trim_end_matches(".srs"),
                "name": name,
                "format": if name.ends_with(".json") { "json" } else { "srs" },
                "bytes": metadata.len(),
                "editable": editable,
            }))
        })
        .collect::<Vec<_>>();
    files.sort_by(|left, right| {
        left["name"].as_str().cmp(&right["name"].as_str())
    });
    files
}

fn proxy_node_tags(data_dir: &Path) -> Vec<String> {
    proxy_nodes(data_dir, &HashMap::new())
        .into_iter()
        .filter_map(|node| node["id"].as_str().map(str::to_string))
        .collect()
}

fn proxy_nodes(
    data_dir: &Path,
    latencies: &HashMap<String, NodeTestResult>,
) -> Vec<JsonValue> {
    let path = data_dir.join(settings::SINGBOX_DIR).join("config.json");
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(config) = serde_json::from_str::<JsonValue>(&raw) else {
        return Vec::new();
    };
    config["outbounds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|outbound| {
            let tag = outbound["tag"].as_str()?;
            let rest = tag.strip_prefix("sub")?;
            let (provider_index, name) = rest.split_once('-')?;
            if provider_index.parse::<usize>().is_err() {
                return None;
            }
            let protocol = outbound["type"].as_str().unwrap_or("unknown");
            let latency = latencies.get(tag);
            Some(json!({
                "id": tag,
                "provider_id": format!("sub{provider_index}"),
                "provider_index": provider_index.parse::<usize>().ok(),
                "name": name,
                "protocol": protocol,
                "server": outbound["server"].as_str(),
                "port": outbound["server_port"].as_u64(),
                "tls": outbound["tls"].is_object(),
                "latency_ms": latency.and_then(|value| value.latency_ms),
                "latency_error": latency.and_then(|value| value.error.as_deref()),
                "latency_checked_at": latency.map(|value| value.checked_at.as_str()),
            }))
        })
        .collect()
}

fn apply_config(doc: &mut DocumentMut, input: ConfigUpdate) -> Result<()> {
    let proxy = table_mut(doc.as_table_mut(), "proxy")?;
    proxy["enabled"] = value(input.proxy.enabled);
    proxy["subscriptions"] = string_array(input.proxy.subscriptions);
    proxy["active_nodes"] = string_array(input.proxy.active_nodes);
    proxy["gateway"] = value(input.proxy.gateway);
    proxy["mixed_port"] = value(i64::from(input.proxy.mixed_port));
    proxy["update_interval"] = value(input.proxy.update_interval as i64);
    proxy["health_check_url"] = value(input.proxy.health_check_url.trim());
    proxy["log_level"] = value(input.proxy.log_level.trim());
    let tun = child_table_mut(proxy, "tun")?;
    tun["enabled"] = value(input.proxy.tun_enabled);
    tun["exclude_routes"] = string_array(input.proxy.tun_exclude_routes);

    let mut names = std::collections::BTreeSet::new();
    let mut domain_rules = ArrayOfTables::new();
    for rule in input.proxy.domain_rules {
        let name = rule.name.trim();
        if name.is_empty() {
            bail!("custom rule name must not be empty");
        }
        if !names.insert(name.to_string()) {
            bail!("duplicate custom rule name {name:?}");
        }
        let suffixes = rule
            .by_suffix
            .into_iter()
            .map(|suffix| suffix.trim().trim_start_matches('.').to_string())
            .filter(|suffix| !suffix.is_empty())
            .collect::<Vec<_>>();
        let hosts = normalized_strings(rule.host);
        let processes = normalized_strings(rule.process);
        let sources = normalized_strings(rule.source);
        let destinations = normalized_strings(rule.destination);
        let outbounds = rule
            .outbounds
            .into_iter()
            .map(|outbound| outbound.trim().to_string())
            .filter(|outbound| !outbound.is_empty())
            .collect::<Vec<_>>();
        if (suffixes.is_empty()
            && hosts.is_empty()
            && processes.is_empty()
            && sources.is_empty()
            && destinations.is_empty())
            || outbounds.is_empty()
        {
            bail!(
                "custom rule {name:?} requires at least one matcher and outbound"
            );
        }
        let mut table = Table::new();
        table["enabled"] = value(rule.enabled);
        table["name"] = value(name);
        table["by_suffix"] = string_array(suffixes);
        table["host"] = string_array(hosts);
        table["process"] = string_array(processes);
        table["source"] = string_array(sources);
        table["destination"] = string_array(destinations);
        table["outbounds"] = string_array(outbounds);
        if let Some(url) = rule
            .health_check_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
        {
            table["health_check_url"] = value(url);
        }
        if let Some(interval) = rule.interval {
            table["interval"] = value(interval as i64);
        }
        if let Some(tolerance) = rule.tolerance {
            table["tolerance"] = value(i64::from(tolerance));
        }
        domain_rules.push(table);
    }
    proxy["domain_rule"] = Item::ArrayOfTables(domain_rules);

    let has_mesh = proxy.get("mesh").is_some();
    if input.mesh.enabled || has_mesh {
        if input.mesh.enabled {
            if !matches!(input.mesh.role.as_str(), "node" | "relay") {
                bail!("mesh role must be node or relay");
            }
            if input.mesh.network_name.trim().is_empty()
                || input.mesh.network_secret.is_empty()
            {
                bail!("mesh network name and secret are required");
            }
        }
        let mesh = child_table_mut(proxy, "mesh")?;
        mesh["enabled"] = value(input.mesh.enabled);
        mesh["role"] = value(input.mesh.role.as_str());
        mesh["network_name"] = value(input.mesh.network_name.trim());
        mesh["network_secret"] = value(input.mesh.network_secret.as_str());
        set_optional_string(mesh, "name", &input.mesh.name);
        set_optional_string(mesh, "ipv4", &input.mesh.ipv4);
        set_optional_array(mesh, "listeners", input.mesh.listeners);
        set_optional_array(mesh, "peers", input.mesh.peers);
        set_optional_array(mesh, "proxy_networks", input.mesh.proxy_networks);
        set_optional_array(mesh, "mesh_routes", input.mesh.mesh_routes);
        set_optional_string(
            mesh,
            "wireguard_listen",
            &input.mesh.wireguard_listen,
        );
        set_optional_string(
            mesh,
            "wireguard_client_cidr",
            &input.mesh.wireguard_client_cidr,
        );
        set_optional_string(
            mesh,
            "wireguard_client_address",
            &input.mesh.wireguard_client_address,
        );
    }
    Ok(())
}

fn normalized_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn table_mut<'a>(root: &'a mut Table, key: &str) -> Result<&'a mut Table> {
    if !root.contains_key(key) {
        root.insert(key, Item::Table(Table::new()));
    }
    root.get_mut(key)
        .and_then(Item::as_table_mut)
        .with_context(|| format!("{key} must be a table"))
}

fn child_table_mut<'a>(
    parent: &'a mut Table,
    key: &str,
) -> Result<&'a mut Table> {
    if !parent.contains_key(key) {
        parent.insert(key, Item::Table(Table::new()));
    }
    parent
        .get_mut(key)
        .and_then(Item::as_table_mut)
        .with_context(|| format!("{key} must be a table"))
}

fn string_array(values: Vec<String>) -> Item {
    let mut array = Array::new();
    for item in values
        .into_iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
    {
        array.push(item);
    }
    Item::Value(Value::Array(array))
}

fn set_optional_array(table: &mut Table, key: &str, values: Vec<String>) {
    let item = string_array(values);
    let empty = item
        .as_value()
        .and_then(Value::as_array)
        .is_some_and(Array::is_empty);
    if empty {
        table.remove(key);
    } else {
        table[key] = item;
    }
}

fn set_optional_string(table: &mut Table, key: &str, input: &str) {
    let input = input.trim();
    if input.is_empty() {
        table.remove(key);
    } else {
        table[key] = value(input);
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("creating {}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("zay.toml");
    let temporary =
        parent.join(format!(".{name}.webui-{}.tmp", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    let result = (|| -> Result<()> {
        file.write_all(bytes).context("writing temporary config")?;
        file.sync_all().context("syncing temporary config")?;
        if let Ok(metadata) = fs::metadata(path) {
            fs::set_permissions(&temporary, metadata.permissions())
                .context("preserving config permissions")?;
        }
        fs::rename(&temporary, path)
            .with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    )))]
    let result: std::io::Result<std::process::Child> =
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "opening a browser is not supported on this platform",
        ));
    if let Err(error) = result {
        eprintln!("warning: could not open browser: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_update_preserves_unrelated_sections() {
        let mut doc = "[proxy]\nenabled = false\nmixin = \"keep\"\n\n[[ssh]]\nenabled = true\nssh_host = \"example\"\n"
            .parse::<DocumentMut>().unwrap();
        apply_config(
            &mut doc,
            ConfigUpdate {
                proxy: ProxyInput {
                    enabled: true,
                    subscriptions: vec!["https://example/sub".into()],
                    active_nodes: vec!["sub0-test".into()],
                    gateway: false,
                    mixed_port: 7890,
                    update_interval: 3600,
                    health_check_url: "https://example/generate_204".into(),
                    log_level: "info".into(),
                    tun_enabled: true,
                    tun_exclude_routes: vec![],
                    domain_rules: vec![DomainRuleInput {
                        enabled: true,
                        name: "example".into(),
                        by_suffix: vec!["example.com".into()],
                        host: vec!["*.example.net".into()],
                        process: vec!["curl".into()],
                        source: vec!["10.14.14.1".into()],
                        destination: vec!["203.0.113.8:443".into()],
                        outbounds: vec!["Proxy".into()],
                        health_check_url: None,
                        interval: None,
                        tolerance: None,
                    }],
                },
                mesh: MeshInput::default(),
            },
        )
        .unwrap();
        let output = doc.to_string();
        assert!(output.contains("mixin = \"keep\""));
        assert!(output.contains("[[ssh]]"));
        assert!(output.contains("mixed_port = 7890"));
        assert!(output.contains("active_nodes = [\"sub0-test\"]"));
        assert!(output.contains("[[proxy.domain_rule]]"));
        assert!(output.contains("by_suffix = [\"example.com\"]"));
        assert!(output.contains("host = [\"*.example.net\"]"));
        assert!(output.contains("process = [\"curl\"]"));
        assert!(output.contains("source = [\"10.14.14.1\"]"));
        assert!(output.contains("destination = [\"203.0.113.8:443\"]"));
    }

    #[test]
    fn token_comparison_handles_different_lengths() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"different"));
    }

    #[test]
    fn node_delay_url_encodes_node_tag_as_path_segment() {
        let endpoint = node_delay_url(
            55914,
            "sub0-🇭🇰 香港实验性 IEPL 专线 1",
            "https://www.gstatic.com/generate_204",
        );
        assert_eq!(
            endpoint.as_str(),
            "http://127.0.0.1:55914/proxies/sub0-%F0%9F%87%AD%F0%9F%87%B0%20%E9%A6%99%E6%B8%AF%E5%AE%9E%E9%AA%8C%E6%80%A7%20IEPL%20%E4%B8%93%E7%BA%BF%201/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=5000"
        );
    }
}
