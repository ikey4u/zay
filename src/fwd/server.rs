use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
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
        Message,
        client::IntoClientRequest,
        handshake::server::{ErrorResponse, Request, Response},
        http::{HeaderValue, StatusCode, header::AUTHORIZATION},
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

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("upstream connect failed"))).with_context(
        || format!("Failed to connect TCP target {addr} after {UPSTREAM_RETRIES} attempts"),
    )
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
        redact_url(&target.url)
    );
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
        redact_url(&listen.url),
        target.addr
    );
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
    request: tokio_tungstenite::tungstenite::http::Request<()>,
    url: &str,
) -> Result<(
    WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    tokio_tungstenite::tungstenite::http::Response<Option<Vec<u8>>>,
)> {
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 1..=UPSTREAM_RETRIES {
        match timeout(CONNECT_TIMEOUT, connect_async(request.clone())).await {
            Ok(Ok(pair)) => return Ok(pair),
            Ok(Err(e)) => last_err = Some(e.into()),
            Err(e) => last_err = Some(e.into()),
        }

        if attempt < UPSTREAM_RETRIES {
            debug!(
                "Upstream WebSocket connect to {} failed (attempt {attempt}/{UPSTREAM_RETRIES}), retrying...",
                redact_url(url)
            );
            sleep(UPSTREAM_RETRY_DELAY).await;
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("upstream connect failed"))).with_context(
        || {
            format!(
                "Failed to connect WebSocket target {} after {UPSTREAM_RETRIES} attempts",
                redact_url(url)
            )
        },
    )
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
        return Err(error_response(
            StatusCode::NOT_FOUND,
            format!(
                "expected WebSocket path {expected_path}, got {actual_path}"
            ),
        ));
    }

    if let Some(token) = token {
        if !is_authorized(request, token) {
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
