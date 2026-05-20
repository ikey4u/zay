use std::{
    fs,
    sync::{Arc, RwLock},
    thread,
};

use anyhow::Context;
use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use tokio::net::TcpListener;

use crate::{bootstrap::Prepared, mihomo, settings::Settings};

#[derive(Clone)]
pub struct AppState {
    pub config_yaml: Arc<RwLock<String>>,
    pub settings: Settings,
    pub tun_enabled: bool,
}

impl AppState {
    pub fn config_yaml_text(&self) -> String {
        self.config_yaml.read().expect("config lock").clone()
    }
}

impl From<Prepared> for AppState {
    fn from(p: Prepared) -> Self {
        Self {
            config_yaml: Arc::new(RwLock::new(p.config_yaml)),
            settings: p.settings,
            tun_enabled: p.tun_enabled,
        }
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            self.0.to_string(),
        )
            .into_response()
    }
}

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(e: E) -> Self {
        Self(e.into())
    }
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn config_dump(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    let config_path = state.settings.data_dir.join("config.yaml");
    let base = fs::read_to_string(&config_path)
        .unwrap_or_else(|_| state.config_yaml_text());
    let full = mihomo::expand_runtime_config(&base, &state.settings)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/yaml; charset=utf-8")],
        full,
    ))
}

pub fn spawn(state: Arc<AppState>, addr: &str) -> thread::JoinHandle<()> {
    let addr = addr.to_string();
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        if let Err(e) = rt.block_on(run_server(state, &addr)) {
            eprintln!("API server error: {e:#}");
        }
    })
}

async fn run_server(state: Arc<AppState>, addr: &str) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/config", get(config_dump))
        .with_state(state);

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding API on {addr}"))?;
    let bound = listener.local_addr()?;
    eprintln!("API listening on http://{bound}");

    axum::serve(listener, app).await.context("serving API")?;
    Ok(())
}
