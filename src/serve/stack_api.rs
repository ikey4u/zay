//! Stack control REST + log SSE.

use std::{convert::Infallible, sync::Arc};

use axum::{
    Json,
    extract::State,
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::stream::{self, Stream};

use super::{
    app::ServeApp,
    error::{ApiError, ApiResult},
};
use crate::{singbox::mixin, stack::controller::StackStartRequest};

pub async fn stack_status(
    State(app): State<Arc<ServeApp>>,
) -> Json<crate::stack::controller::StackStatus> {
    Json(app.stack.status())
}

pub async fn stack_start(
    State(app): State<Arc<ServeApp>>,
    Json(req): Json<StackStartRequest>,
) -> ApiResult<Json<crate::stack::controller::StackStatus>> {
    if app.stack.is_running() {
        return Err(ApiError::conflict("stack is already running"));
    }
    app.paths.ensure_config().map_err(ApiError::from)?;
    app.stack
        .start(req, &app.paths)
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    Ok(Json(app.stack.status()))
}

pub async fn stack_stop(
    State(app): State<Arc<ServeApp>>,
) -> ApiResult<Json<serde_json::Value>> {
    app.stack.stop().map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn stack_config(
    State(app): State<Arc<ServeApp>>,
) -> ApiResult<impl IntoResponse> {
    let config_path = app.paths.data_dir.join("singbox/config.json");
    let base = std::fs::read_to_string(&config_path).unwrap_or_default();
    let settings = crate::settings::resolve_stack(
        &crate::ProxyOpts {
            data_dir: Some(app.paths.data_dir.clone()),
            config: Some(app.paths.toml_path.clone()),
            ..Default::default()
        },
        Default::default(),
    )
    .map_err(ApiError::from)?;
    let full = mixin::merge_config(&base, &settings).map_err(ApiError::from)?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )],
        full,
    ))
}

pub async fn stack_logs(
    State(app): State<Arc<ServeApp>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let logs = app.stack.logs().clone();
    let stream = stream::unfold((logs, 0u64), |(logs, tick)| async move {
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        let lines = if tick == 0 {
            logs.tail(200)
        } else {
            logs.tail(20)
        };
        let payload = lines.join("\n");
        Some((Ok(Event::default().data(payload)), (logs, tick + 1)))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
