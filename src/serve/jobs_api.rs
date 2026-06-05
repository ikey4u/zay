//! Job management REST.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::Value as JsonValue;

use super::{
    app::ServeApp,
    error::{ApiError, ApiResult},
    jobs::JobSummary,
};

pub async fn list_jobs(
    State(app): State<Arc<ServeApp>>,
) -> Json<Vec<JobSummary>> {
    Json(app.jobs.list())
}

pub async fn get_job(
    State(app): State<Arc<ServeApp>>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let (summary, log_tail) = app
        .jobs
        .get(&id)
        .ok_or_else(|| ApiError::not_found(format!("job {id}")))?;
    Ok(Json(serde_json::json!({
        "job": summary,
        "logs": log_tail,
    })))
}

pub async fn stop_job(
    State(app): State<Arc<ServeApp>>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    app.jobs.stop(&id).map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn create_ssh_job(
    State(app): State<Arc<ServeApp>>,
    Json(spec): Json<JsonValue>,
) -> ApiResult<Json<JobSummary>> {
    let job = app.jobs.start_ssh(spec).await.map_err(ApiError::from)?;
    Ok(Json(job))
}

pub async fn create_fwd_job(
    State(app): State<Arc<ServeApp>>,
    Json(spec): Json<JsonValue>,
) -> ApiResult<Json<JobSummary>> {
    let job = app.jobs.start_fwd(spec).await.map_err(ApiError::from)?;
    Ok(Json(job))
}

pub async fn create_http_job(
    State(app): State<Arc<ServeApp>>,
    Json(spec): Json<JsonValue>,
) -> ApiResult<Json<JobSummary>> {
    let job = app.jobs.start_http(spec).await.map_err(ApiError::from)?;
    Ok(Json(job))
}
