//! Config REST handlers.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use serde::Deserialize;

use super::{
    app::ServeApp,
    error::{ApiError, ApiResult},
};
use crate::config::{self, ConfigPathOpts};

fn path_opts(app: &ServeApp) -> ConfigPathOpts {
    ConfigPathOpts {
        data_dir: Some(app.paths.data_dir.clone()),
        config: Some(app.paths.toml_path.clone()),
    }
}

pub async fn get_config(
    State(app): State<Arc<ServeApp>>,
) -> ApiResult<impl IntoResponse> {
    let raw = config::read_raw(&path_opts(&app)).map_err(ApiError::from)?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        raw,
    ))
}

#[derive(Deserialize)]
pub struct PutConfigBody {
    pub content: String,
}

pub async fn put_config(
    State(app): State<Arc<ServeApp>>,
    Json(body): Json<PutConfigBody>,
) -> ApiResult<Json<serde_json::Value>> {
    config::write_raw(&path_opts(&app), &body.content).map_err(|e| {
        ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "CONFIG_INVALID",
            format!("{e:#}"),
        )
    })?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct PatchKeyBody {
    pub value: String,
}

pub async fn patch_key(
    State(app): State<Arc<ServeApp>>,
    Path(key): Path<String>,
    Json(body): Json<PatchKeyBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let opts = path_opts(&app);
    let toml_path =
        config::ensure_config_path(&opts).map_err(ApiError::from)?;
    let raw = std::fs::read_to_string(&toml_path).map_err(ApiError::from)?;
    let mut doc = raw.parse::<toml_edit::DocumentMut>().map_err(|e| {
        ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "CONFIG_INVALID",
            format!("{e}"),
        )
    })?;
    config::set_key(&mut doc, &key, &body.value).map_err(|e| {
        ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "CONFIG_INVALID",
            format!("{e:#}"),
        )
    })?;
    std::fs::write(&toml_path, doc.to_string()).map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn delete_key(
    State(app): State<Arc<ServeApp>>,
    Path(key): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let opts = path_opts(&app);
    let toml_path =
        config::ensure_config_path(&opts).map_err(ApiError::from)?;
    let raw = std::fs::read_to_string(&toml_path).map_err(ApiError::from)?;
    let mut doc = raw
        .parse::<toml_edit::DocumentMut>()
        .map_err(ApiError::from)?;
    config::unset_key(&mut doc, &key).map_err(|e| {
        ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "CONFIG_INVALID",
            format!("{e:#}"),
        )
    })?;
    std::fs::write(&toml_path, doc.to_string()).map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn validate_config(
    State(app): State<Arc<ServeApp>>,
) -> ApiResult<Json<serde_json::Value>> {
    config::validate_file(&path_opts(&app)).map_err(|e| {
        ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "CONFIG_INVALID",
            format!("{e:#}"),
        )
    })?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
