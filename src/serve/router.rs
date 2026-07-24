//! Axum router for `zay serve`.

use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use axum::{
    Router, middleware,
    routing::{any, get, post},
};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

use super::{
    app::ServeApp, auth, clash_proxy, config_api, jobs_api, stack_api, ws,
};
use crate::webui;

pub async fn run(
    app: Arc<ServeApp>,
    listen: SocketAddr,
    no_ui: bool,
    cors: bool,
) -> anyhow::Result<()> {
    let api = Router::new()
        .route("/meta", get(meta))
        .route("/health", get(health))
        .route(
            "/config",
            get(config_api::get_config).put(config_api::put_config),
        )
        .route("/config/validate", post(config_api::validate_config))
        .route(
            "/config/keys/{*key}",
            axum::routing::patch(config_api::patch_key)
                .delete(config_api::delete_key),
        )
        .route("/stack/status", get(stack_api::stack_status))
        .route("/stack/start", post(stack_api::stack_start))
        .route("/stack/stop", post(stack_api::stack_stop))
        .route("/stack/config", get(stack_api::stack_config))
        .route("/stack/logs", get(stack_api::stack_logs))
        .route("/stack/clash/{*path}", any(clash_proxy::clash_proxy))
        .route("/jobs", get(jobs_api::list_jobs))
        .route("/jobs/ssh", post(jobs_api::create_ssh_job))
        .route("/jobs/fwd", post(jobs_api::create_fwd_job))
        .route("/jobs/http", post(jobs_api::create_http_job))
        .route(
            "/jobs/{id}",
            get(jobs_api::get_job).delete(jobs_api::stop_job),
        )
        .route("/ws/events", get(ws::ws_events))
        .with_state(app.clone());

    let api = Router::new().nest("/api/v1", api).layer(
        middleware::from_fn_with_state(app.clone(), auth::require_bearer),
    );

    let mut app_router = if no_ui || !webui::EMBEDDED_UI {
        api
    } else {
        Router::new().merge(api).fallback(serve_static)
    };

    if cors {
        app_router = app_router.layer(CorsLayer::permissive());
    }

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding serve on {listen}"))?;
    axum::serve(listener, app_router)
        .await
        .context("serving zay serve")?;
    Ok(())
}

async fn meta(
    axum::extract::State(app): axum::extract::State<Arc<ServeApp>>,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "singbox_version": crate::singbox::VERSION,
        "webui_version": env!("CARGO_PKG_VERSION"),
        "data_dir": app.paths.data_dir.display().to_string(),
        "features": ["serve", "webui", "config", "stack", "ssh", "fwd", "http", "clash"],
        "embedded_ui": webui::EMBEDDED_UI,
    }))
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

async fn serve_static(uri: axum::http::Uri) -> axum::response::Response {
    let path = uri.path();
    if let Some(file) = webui::lookup(path) {
        let cache = if path.starts_with("/assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return (
            axum::http::StatusCode::OK,
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static(file.content_type),
                ),
                (
                    axum::http::header::CACHE_CONTROL,
                    axum::http::HeaderValue::from_static(cache),
                ),
            ],
            file.body,
        )
            .into_response();
    }
    if let Some(index) = webui::lookup("/index.html") {
        return (
            axum::http::StatusCode::OK,
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static(index.content_type),
                ),
                (
                    axum::http::header::CACHE_CONTROL,
                    axum::http::HeaderValue::from_static("no-cache"),
                ),
            ],
            index.body,
        )
            .into_response();
    }
    (
        axum::http::StatusCode::NOT_FOUND,
        "WebUI not embedded — run: cd webui && pnpm build && cargo build",
    )
        .into_response()
}

use axum::response::IntoResponse;
