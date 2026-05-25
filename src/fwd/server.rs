use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional,
    },
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
    time::{sleep, timeout},
};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async, connect_async,
    tungstenite::{
        Error as WsError, Message,
        client::IntoClientRequest,
        handshake::server::{ErrorResponse, Request, Response},
        http::{
            HeaderValue, StatusCode,
            header::{AUTHORIZATION, LOCATION},
        },
    },
};
use tracing::{debug, info, warn};
use url::{Url, form_urlencoded};

use crate::fwd::{FwdArgs, FwdEndpoint, TcpEndpoint, WebSocketEndpoint};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 1024;
const UPSTREAM_RETRIES: u32 = 3;
const UPSTREAM_RETRY_DELAY: Duration = Duration::from_millis(500);
const MAX_WEBSOCKET_REDIRECTS: u8 = 5;

type ClientRequest = tokio_tungstenite::tungstenite::http::Request<()>;

pub async fn run(args: FwdArgs) -> Result<()> {
    let token = args.token.map(Arc::<str>::from);

    match (args.to, args.from) {
        (FwdEndpoint::Tcp(listen), FwdEndpoint::Tcp(target)) => {
            tcp_tcp(listen, target).await
        }
        (FwdEndpoint::Tcp(listen), FwdEndpoint::Ws(target))
        | (FwdEndpoint::Tcp(listen), FwdEndpoint::Wss(target)) => {
            tcp_websocket(listen, target, token).await
        }
        (FwdEndpoint::Ws(listen), FwdEndpoint::Tcp(target)) => {
            websocket_tcp(listen, target, token).await
        }
        _ => unreachable!("fwd args are validated by cli::parse"),
    }
}

async fn tcp_tcp(listen: TcpEndpoint, target: TcpEndpoint) -> Result<()> {
    let listener =
        TcpListener::bind(&listen.addr).await.with_context(|| {
            format!("Failed to bind TCP listener {}", listen.addr)
        })?;

    info!("TCP fwd: {} → {}", listen.addr, target.addr);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        let (stream, peer_addr) = match accept_or_shutdown(&listener).await? {
            Some(pair) => pair,
            None => {
                info!("Bridge stopped");
                return Ok(());
            }
        };

        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .context("Connection limiter closed")?;

        if let Err(e) = stream.set_nodelay(true) {
            warn!("Unable to set TCP_NODELAY on client {peer_addr}: {e}");
        }

        debug!("Accepted TCP client {peer_addr}");
        let target = target.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_tcp_tcp(stream, target).await {
                debug!("TCP bridge connection closed: {e:#}");
            }
        });
    }
}

async fn handle_tcp_tcp(
    mut stream: TcpStream,
    target: TcpEndpoint,
) -> Result<()> {
    let mut backend = connect_upstream_tcp(&target.addr).await?;

    if let Err(e) = backend.set_nodelay(true) {
        warn!(
            "Unable to set TCP_NODELAY on backend connection {}: {e}",
            target.addr
        );
    }

    copy_bidirectional(&mut stream, &mut backend)
        .await
        .context("TCP forwarding failed")?;

    Ok(())
}

async fn connect_upstream_tcp(addr: &str) -> Result<TcpStream> {
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 1..=UPSTREAM_RETRIES {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = Some(e.into()),
            Err(e) => last_err = Some(e.into()),
        }

        if attempt < UPSTREAM_RETRIES {
            debug!(
                "Upstream TCP connect to {addr} failed (attempt {attempt}/{UPSTREAM_RETRIES}), retrying..."
            );
            sleep(UPSTREAM_RETRY_DELAY).await;
        }
    }

    let err =
        last_err.unwrap_or_else(|| anyhow::anyhow!("upstream connect failed"));
    warn!(
        "Failed to connect TCP target {addr} after {UPSTREAM_RETRIES} attempts: {err:#}"
    );

    Err(err).with_context(|| {
        format!("Failed to connect TCP target {addr} after {UPSTREAM_RETRIES} attempts")
    })
}

async fn tcp_websocket(
    listen: TcpEndpoint,
    target: WebSocketEndpoint,
    token: Option<Arc<str>>,
) -> Result<()> {
    let listener =
        TcpListener::bind(&listen.addr).await.with_context(|| {
            format!("Failed to bind TCP listener {}", listen.addr)
        })?;

    info!(
        "TCP to WebSocket bridge: {} → {}",
        listen.addr,
        websocket_endpoint_label(&target)
    );
    log_websocket_endpoint_mapping("upstream", &target);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        let (stream, peer_addr) = match accept_or_shutdown(&listener).await? {
            Some(pair) => pair,
            None => {
                info!("Bridge stopped");
                return Ok(());
            }
        };

        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .context("Connection limiter closed")?;

        debug!("Accepted TCP client {peer_addr}");
        let target = target.clone();
        let token = token.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_tcp_websocket(stream, target, token).await {
                debug!("TCP to WebSocket connection closed: {e:#}");
            }
        });
    }
}

async fn websocket_tcp(
    listen: WebSocketEndpoint,
    target: TcpEndpoint,
    token: Option<Arc<str>>,
) -> Result<()> {
    let listener =
        TcpListener::bind(&listen.bind_addr)
            .await
            .with_context(|| {
                format!("Failed to bind WebSocket listener {}", listen.url)
            })?;

    info!(
        "WebSocket to TCP bridge: {} → {}",
        websocket_endpoint_label(&listen),
        target.addr
    );
    log_websocket_endpoint_mapping("listener", &listen);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        let (stream, peer_addr) = match accept_or_shutdown(&listener).await? {
            Some(pair) => pair,
            None => {
                info!("Bridge stopped");
                return Ok(());
            }
        };

        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .context("Connection limiter closed")?;

        debug!("Accepted WebSocket client {peer_addr}");
        let target = target.clone();
        let expected_path = listen.path.clone();
        let token = token.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) =
                handle_websocket_tcp(stream, target, expected_path, token).await
            {
                debug!("WebSocket to TCP connection closed: {e:#}");
            }
        });
    }
}

/// Accept the next client or exit cleanly on Ctrl+C.
async fn accept_or_shutdown(
    listener: &TcpListener,
) -> Result<Option<(TcpStream, std::net::SocketAddr)>> {
    tokio::select! {
        result = listener.accept() => match result {
            Ok(pair) => Ok(Some(pair)),
            Err(e) => Err(e).context("accept() failed"),
        },
        _ = tokio::signal::ctrl_c() => Ok(None),
    }
}

async fn handle_tcp_websocket(
    stream: TcpStream,
    target: WebSocketEndpoint,
    token: Option<Arc<str>>,
) -> Result<()> {
    let request = websocket_request(&target, token.as_deref())?;
    let (websocket, _) =
        connect_upstream_websocket(request, &target.url).await?;

    proxy_tcp_websocket(stream, websocket).await
}

async fn connect_upstream_websocket(
    mut request: ClientRequest,
    url: &str,
) -> Result<(
    WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    tokio_tungstenite::tungstenite::http::Response<Option<Vec<u8>>>,
)> {
    let mut last_err: Option<anyhow::Error> = None;
    let mut current_url = url.to_string();

    for attempt in 1..=UPSTREAM_RETRIES {
        let mut redirects = 0;

        loop {
            match timeout(CONNECT_TIMEOUT, connect_async(request.clone())).await
            {
                Ok(Ok(pair)) => {
                    debug!(
                        "Connected WebSocket upstream {}",
                        redact_url(&current_url)
                    );
                    return Ok(pair);
                }
                Ok(Err(e)) => {
                    if let Some((next_request, next_url)) =
                        websocket_redirect_request(&request, &current_url, &e)?
                    {
                        if redirects >= MAX_WEBSOCKET_REDIRECTS {
                            last_err = Some(anyhow::anyhow!(
                                "too many WebSocket redirects after {MAX_WEBSOCKET_REDIRECTS} redirects"
                            ));
                            break;
                        }

                        redirects += 1;
                        info!(
                            "WebSocket upstream redirect: {} → {}",
                            redact_url(&current_url),
                            redact_url(&next_url)
                        );
                        request = next_request;
                        current_url = next_url;
                        continue;
                    }

                    last_err = Some(anyhow::anyhow!(
                        websocket_connect_error_summary(&e)
                    ));
                }
                Err(e) => {
                    last_err = Some(e.into());
                }
            }

            break;
        }

        if attempt < UPSTREAM_RETRIES {
            debug!(
                "Upstream WebSocket connect to {} failed (attempt {attempt}/{UPSTREAM_RETRIES}): {:#}",
                redact_url(&current_url),
                last_err
                    .as_ref()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown error".to_string())
            );
            sleep(UPSTREAM_RETRY_DELAY).await;
        }
    }

    let err =
        last_err.unwrap_or_else(|| anyhow::anyhow!("upstream connect failed"));
    warn!(
        "Failed to connect WebSocket target {} after {UPSTREAM_RETRIES} attempts: {err:#}",
        redact_url(&current_url)
    );

    Err(err).with_context(|| {
        format!(
            "Failed to connect WebSocket target {} after {UPSTREAM_RETRIES} attempts",
            redact_url(&current_url)
        )
    })
}

fn websocket_redirect_request(
    request: &ClientRequest,
    current_url: &str,
    error: &WsError,
) -> Result<Option<(ClientRequest, String)>> {
    let response = match error {
        WsError::Http(response) if is_redirect_status(response.status()) => {
            response
        }
        _ => return Ok(None),
    };

    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "HTTP {} redirect without Location header",
                response.status()
            )
        })?;
    let next_url = websocket_redirect_url(current_url, location)?;
    let mut next_request =
        next_url.as_str().into_client_request().with_context(|| {
            format!(
                "Invalid WebSocket redirect target {}",
                redact_url(next_url.as_str())
            )
        })?;

    if same_redirect_host(current_url, next_url.as_str()) {
        if let Some(value) = request.headers().get(AUTHORIZATION) {
            next_request
                .headers_mut()
                .insert(AUTHORIZATION, value.clone());
        }
    } else if request.headers().contains_key(AUTHORIZATION) {
        warn!(
            "Not forwarding Authorization header across WebSocket redirect {} → {}",
            redact_url(current_url),
            redact_url(next_url.as_str())
        );
    }

    Ok(Some((next_request, next_url.to_string())))
}

fn is_redirect_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn websocket_redirect_url(current_url: &str, location: &str) -> Result<Url> {
    let base = Url::parse(current_url).with_context(|| {
        format!("Invalid WebSocket URL {}", redact_url(current_url))
    })?;
    let parsed_location = match Url::parse(location) {
        Ok(url) => url,
        Err(url::ParseError::RelativeUrlWithoutBase) => base
            .join(location)
            .with_context(|| format!("Invalid redirect Location {location}"))?,
        Err(e) => {
            return Err(e).with_context(|| {
                format!("Invalid redirect Location {location}")
            });
        }
    };
    let mut next = preserve_origin_for_same_host_websocket_redirect(
        &base,
        parsed_location,
    );

    match next.scheme() {
        "http" => next
            .set_scheme("ws")
            .map_err(|_| anyhow::anyhow!("invalid redirect Location scheme"))?,
        "https" => next
            .set_scheme("wss")
            .map_err(|_| anyhow::anyhow!("invalid redirect Location scheme"))?,
        "ws" | "wss" => {}
        scheme => {
            bail!(
                "unsupported WebSocket redirect Location scheme '{scheme}': use ws://, wss://, http://, or https://"
            );
        }
    }

    Ok(next)
}

fn preserve_origin_for_same_host_websocket_redirect(
    current: &Url,
    mut location: Url,
) -> Url {
    let same_host = current
        .host_str()
        .zip(location.host_str())
        .map(|(current, location)| current.eq_ignore_ascii_case(location))
        .unwrap_or(false);

    if !same_host {
        return location;
    }

    if current.port() == location.port() {
        return location;
    }

    let location_scheme = location.scheme();
    let current_is_ws_origin = matches!(current.scheme(), "ws" | "wss");
    let location_is_http_origin =
        matches!(location_scheme, "http" | "https" | "ws" | "wss");

    if current_is_ws_origin && location_is_http_origin {
        info!(
            "WebSocket redirect Location changes port on the same host; preserving original origin {} and using redirected path {}",
            websocket_origin_label(current),
            location.path()
        );
        let _ = location.set_scheme(current.scheme());
        let _ = location.set_port(current.port());
    }

    location
}

fn websocket_origin_label(url: &Url) -> String {
    match url.port() {
        Some(port) => format!(
            "{}://{}:{port}",
            url.scheme(),
            url.host_str().unwrap_or("")
        ),
        None => format!("{}://{}", url.scheme(), url.host_str().unwrap_or("")),
    }
}

fn same_redirect_host(current_url: &str, next_url: &str) -> bool {
    let Ok(current) = Url::parse(current_url) else {
        return false;
    };
    let Ok(next) = Url::parse(next_url) else {
        return false;
    };

    current
        .host_str()
        .zip(next.host_str())
        .map(|(current, next)| current.eq_ignore_ascii_case(next))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_http_location_to_ws() {
        let url = websocket_redirect_url(
            "ws://example.com/db",
            "http://example.com/db/",
        )
        .unwrap();

        assert_eq!(url.as_str(), "ws://example.com/db/");
    }

    #[test]
    fn redirect_preserves_origin_when_same_host_location_changes_port() {
        let url = websocket_redirect_url(
            "ws://example.com/db",
            "http://example.com:1479/db/",
        )
        .unwrap();

        assert_eq!(url.as_str(), "ws://example.com/db/");
    }

    #[test]
    fn redirect_keeps_cross_host_location_origin() {
        let url = websocket_redirect_url(
            "ws://example.com/db",
            "http://other.example.com:1479/db/",
        )
        .unwrap();

        assert_eq!(url.as_str(), "ws://other.example.com:1479/db/");
    }

    #[test]
    fn redirect_resolves_relative_location() {
        let url =
            websocket_redirect_url("ws://example.com/db", "/db/?a=1").unwrap();

        assert_eq!(url.as_str(), "ws://example.com/db/?a=1");
    }

    #[test]
    fn redirect_rejects_non_websocket_scheme() {
        let err = websocket_redirect_url(
            "ws://example.com/db",
            "ftp://example.com/db",
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("unsupported WebSocket redirect Location scheme")
        );
    }
}

fn websocket_connect_error_summary(error: &WsError) -> String {
    match error {
        WsError::Http(response) => {
            let mut summary = format!("HTTP {}", response.status());
            if let Some(location) = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
            {
                summary.push_str(&format!("; location={location}"));
            }
            summary
        }
        _ => error.to_string(),
    }
}

async fn handle_websocket_tcp(
    stream: TcpStream,
    target: TcpEndpoint,
    expected_path: String,
    token: Option<Arc<str>>,
) -> Result<()> {
    let websocket = timeout(
        HANDSHAKE_TIMEOUT,
        accept_hdr_async(
            stream,
            move |request: &Request, response: Response| {
                validate_websocket_request(
                    request,
                    response,
                    &expected_path,
                    token.as_deref(),
                )
            },
        ),
    )
    .await
    .context("WebSocket handshake timed out")?
    .context("WebSocket handshake failed")?;

    let tcp = match connect_upstream_tcp(&target.addr).await {
        Ok(tcp) => tcp,
        Err(e) => {
            let mut websocket = websocket;
            let _ = websocket.close(None).await;
            return Err(e);
        }
    };

    proxy_tcp_websocket(tcp, websocket).await
}

fn websocket_request(
    target: &WebSocketEndpoint,
    token: Option<&str>,
) -> Result<tokio_tungstenite::tungstenite::http::Request<()>> {
    let mut request =
        target.url.as_str().into_client_request().with_context(|| {
            format!("Invalid WebSocket target {}", redact_url(&target.url))
        })?;

    if let Some(token) = token {
        let value = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("Invalid authorization token")?;
        request.headers_mut().insert(AUTHORIZATION, value);
    }

    Ok(request)
}

#[allow(clippy::result_large_err)]
fn validate_websocket_request(
    request: &Request,
    response: Response,
    expected_path: &str,
    token: Option<&str>,
) -> std::result::Result<Response, ErrorResponse> {
    let actual_path = request.uri().path();

    if actual_path != expected_path {
        warn!(
            "Rejecting WebSocket client: expected path {expected_path}, got {actual_path}"
        );
        return Err(error_response(
            StatusCode::NOT_FOUND,
            format!(
                "expected WebSocket path {expected_path}, got {actual_path}"
            ),
        ));
    }

    if let Some(token) = token {
        if !is_authorized(request, token) {
            warn!(
                "Rejecting WebSocket client on path {actual_path}: missing or invalid token"
            );
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "missing or invalid token".to_string(),
            ));
        }
    }

    Ok(response)
}

fn is_authorized(request: &Request, token: &str) -> bool {
    let bearer_ok = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value == format!("Bearer {token}"))
        .unwrap_or(false);

    if bearer_ok {
        return true;
    }

    request
        .uri()
        .query()
        .map(|query| {
            form_urlencoded::parse(query.as_bytes())
                .any(|(key, value)| key == "token" && value == token)
        })
        .unwrap_or(false)
}

fn error_response(status: StatusCode, body: String) -> ErrorResponse {
    Response::builder()
        .status(status)
        .body(Some(body))
        .expect("valid response")
}

fn redact_url(raw: &str) -> String {
    Url::parse(raw)
        .map(|mut url| {
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        })
        .unwrap_or_else(|_| raw.to_string())
}

fn websocket_endpoint_label(endpoint: &WebSocketEndpoint) -> String {
    let original = redact_url(&endpoint.original_url);
    let websocket = redact_url(&endpoint.url);

    if original == websocket {
        websocket
    } else {
        format!("{original} (WebSocket upgrade as {websocket})")
    }
}

fn log_websocket_endpoint_mapping(role: &str, endpoint: &WebSocketEndpoint) {
    let original = redact_url(&endpoint.original_url);
    let websocket = redact_url(&endpoint.url);

    if original == websocket {
        debug!("WebSocket {role} endpoint: {websocket}");
    } else {
        info!(
            "Endpoint {role} {} is treated as WebSocket upgrade endpoint {}; it is not plain HTTP forwarding",
            original, websocket
        );
    }
}

async fn proxy_tcp_websocket<S>(
    tcp: TcpStream,
    websocket: WebSocketStream<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut tcp_reader, mut tcp_writer) = tcp.into_split();
    let (ws_writer, mut ws_reader) = websocket.split();
    let ws_writer = Arc::new(Mutex::new(ws_writer));

    let tcp_to_ws_writer = Arc::clone(&ws_writer);
    let tcp_to_ws = async {
        let mut buf = vec![0_u8; 16 * 1024];

        loop {
            let n =
                tcp_reader.read(&mut buf).await.context("TCP read failed")?;
            if n == 0 {
                let _ = tcp_to_ws_writer.lock().await.close().await;
                return Ok::<(), anyhow::Error>(());
            }

            tcp_to_ws_writer
                .lock()
                .await
                .send(Message::Binary(buf[..n].to_vec().into()))
                .await
                .context("WebSocket send failed")?;
        }
    };

    let ws_to_tcp_writer = Arc::clone(&ws_writer);
    let ws_to_tcp = async {
        while let Some(message) = ws_reader.next().await {
            match message.context("WebSocket receive failed")? {
                Message::Binary(data) => tcp_writer
                    .write_all(&data)
                    .await
                    .context("TCP write failed")?,
                Message::Ping(data) => ws_to_tcp_writer
                    .lock()
                    .await
                    .send(Message::Pong(data))
                    .await
                    .context("WebSocket pong failed")?,
                Message::Close(_) => {
                    let _ = ws_to_tcp_writer.lock().await.close().await;
                    break;
                }
                Message::Text(text) => tcp_writer
                    .write_all(text.as_bytes())
                    .await
                    .context("TCP write failed")?,
                Message::Pong(_) | Message::Frame(_) => {}
            }
        }

        let _ = tcp_writer.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };

    tokio::pin!(tcp_to_ws);
    tokio::pin!(ws_to_tcp);

    tokio::select! {
        result = &mut tcp_to_ws => {
            result?;
            ws_to_tcp.await
        }
        result = &mut ws_to_tcp => result,
    }
}
