//! Reverse proxy to sing-box Clash external API.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::Response,
};
use reqwest::Client;

use super::{
    app::ServeApp,
    error::{ApiError, ApiResult},
};

fn clash_base(app: &ServeApp) -> ApiResult<(String, String)> {
    let config_path = app.paths.data_dir.join("singbox/config.json");
    let raw = std::fs::read_to_string(&config_path).map_err(|_| {
        ApiError::not_found("singbox/config.json not found — start stack first")
    })?;
    let doc: serde_json::Value =
        serde_json::from_str(&raw).map_err(ApiError::from)?;
    let controller = doc
        .pointer("/experimental/clash_api/external_controller")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ApiError::not_found(
                "external_controller missing in sing-box config",
            )
        })?;
    let secret = doc
        .pointer("/experimental/clash_api/secret")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let base = if controller.starts_with("http") {
        controller.to_string()
    } else {
        format!("http://{controller}")
    };
    Ok((base, secret.to_string()))
}

pub async fn clash_proxy(
    State(app): State<Arc<ServeApp>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    let (base, secret) = clash_base(&app)?;
    let path = uri.path();
    let suffix = path
        .strip_prefix("/api/v1/stack/clash")
        .unwrap_or("")
        .trim_start_matches('/');
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let url = if suffix.is_empty() {
        format!("{base}{query}")
    } else {
        format!("{base}/{suffix}{query}")
    };

    let client = Client::builder().build().map_err(ApiError::from)?;
    let bytes = axum::body::to_bytes(body, 8 * 1024 * 1024)
        .await
        .map_err(ApiError::from)?;

    let mut req = client.request(method.clone(), &url).body(bytes);
    if !secret.is_empty() {
        req = req.header("Authorization", format!("Bearer {secret}"));
    }
    for (name, value) in headers.iter() {
        if name == axum::http::header::AUTHORIZATION
            || name == axum::http::header::HOST
            || name == axum::http::header::CONNECTION
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            req = req.header(name.as_str(), v);
        }
    }

    let resp = req.send().await.map_err(ApiError::from)?;
    let status = StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out_headers = HeaderMap::new();
    for (k, v) in resp.headers().iter() {
        if let Ok(hv) = HeaderValue::from_bytes(v.as_bytes()) {
            out_headers.insert(k, hv);
        }
    }
    let body = resp.bytes().await.map_err(ApiError::from)?;
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = out_headers;
    Ok(response)
}
