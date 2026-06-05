//! Bearer token middleware for `/api/v1/*` (except `/api/v1/meta`).

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::app::ServeApp;

pub async fn require_bearer(
    State(state): State<Arc<ServeApp>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path == "/api/v1/meta" {
        return next.run(request).await;
    }
    if !path.starts_with("/api/v1/") {
        return next.run(request).await;
    }

    let query_token = request.uri().query().and_then(|q| {
        q.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == "token").then(|| v.to_string())
        })
    });

    let authorized = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|t| t == state.token.as_str())
        .unwrap_or(false)
        || query_token.as_deref() == Some(state.token.as_str());

    if authorized {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "missing or invalid Authorization: Bearer token"
                }
            })),
        )
            .into_response()
    }
}
