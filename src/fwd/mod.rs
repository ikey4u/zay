//! TCP / WebSocket forwarding (`zay fwd`).

mod server;

use anyhow::{Context, Result, bail};
use clap::Args;
pub use server::run;
use tracing_subscriber::EnvFilter;
use url::Url;

#[derive(Args, Debug)]
#[command(
    about = "Forward TCP streams directly or over WebSocket (TCP/WS relay)",
    long_about = concat!(
        "zay fwd forwards TCP streams directly, TCP streams to WebSocket streams, or WebSocket streams to TCP.\n",
        "\n",
        "  --to    where clients connect (local listener)\n",
        "  --from  upstream zay dials for each accepted connection\n",
        "\n",
        "SUPPORTED ENDPOINTS:\n",
        "  --to    tcp://host:port, ws://host:port/path, or http://host:port/path\n",
        "  --from  tcp://host:port, ws://host:port/path, wss://host:port/path, http://host:port/path, or https://host:port/path\n",
        "  --token optional bearer token for WebSocket authorization\n",
        "\n",
        "EXAMPLES:\n",
        "  zay fwd --to tcp://0.0.0.0:8080 --from tcp://127.0.0.1:80\n",
        "  zay fwd --to tcp://127.0.0.1:3306 --from wss://public.com:443/wss"
    )
)]
pub struct FwdCli {
    /// Where clients connect (local listener)
    #[arg(long, value_name = "ENDPOINT")]
    to: String,

    /// Upstream endpoint dialed for each accepted connection
    #[arg(long, value_name = "ENDPOINT")]
    from: String,

    /// Bearer token for WebSocket authorization
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,
}

#[derive(Debug)]
pub struct FwdArgs {
    pub to: FwdEndpoint,
    pub from: FwdEndpoint,
    pub token: Option<String>,
}

#[derive(Debug)]
pub enum FwdEndpoint {
    Tcp(TcpEndpoint),
    Ws(WebSocketEndpoint),
    Wss(WebSocketEndpoint),
}

#[derive(Debug, Clone)]
pub struct TcpEndpoint {
    pub addr: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct WebSocketEndpoint {
    pub url: String,
    pub bind_addr: String,
    pub path: String,
}

pub async fn run_cli(cli: FwdCli) -> Result<()> {
    init_tracing();
    run(parse(cli)?).await
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
}

fn parse(cli: FwdCli) -> Result<FwdArgs> {
    let to = parse_fwd_to_endpoint(&cli.to)?;
    let from = parse_fwd_from_endpoint(&cli.from)?;

    match (&to, &from) {
        (FwdEndpoint::Tcp(_), FwdEndpoint::Tcp(_)) => {
            if cli.token.is_some() {
                bail!(
                    "--token is only supported when a WebSocket endpoint is used"
                );
            }
            Ok(FwdArgs {
                to,
                from,
                token: None,
            })
        }
        (FwdEndpoint::Tcp(_), FwdEndpoint::Ws(_))
        | (FwdEndpoint::Tcp(_), FwdEndpoint::Wss(_))
        | (FwdEndpoint::Ws(_), FwdEndpoint::Tcp(_)) => Ok(FwdArgs {
            to,
            from,
            token: cli.token,
        }),
        _ => bail!(
            "fwd supports tcp→tcp, tcp→ws(s), or ws/http→tcp endpoint combinations"
        ),
    }
}

fn parse_fwd_to_endpoint(raw: &str) -> Result<FwdEndpoint> {
    let url = parse_endpoint_url(raw)?;

    match url.scheme() {
        "tcp" => Ok(FwdEndpoint::Tcp(parse_tcp_endpoint(raw, &url)?)),
        "ws" => Ok(FwdEndpoint::Ws(parse_websocket_endpoint(&url, false)?)),
        "http" => Ok(FwdEndpoint::Ws(parse_websocket_endpoint(
            &with_scheme(url, "ws")?,
            false,
        )?)),
        "wss" | "https" => bail!(
            "wss/https --to endpoints require TLS server support and are not supported yet"
        ),
        scheme => bail!(
            "unsupported --to endpoint scheme '{scheme}': use tcp://, ws://, or http://"
        ),
    }
}

fn parse_fwd_from_endpoint(raw: &str) -> Result<FwdEndpoint> {
    let url = parse_endpoint_url(raw)?;

    match url.scheme() {
        "tcp" => Ok(FwdEndpoint::Tcp(parse_tcp_endpoint(raw, &url)?)),
        "ws" => Ok(FwdEndpoint::Ws(parse_websocket_endpoint(&url, true)?)),
        "wss" => Ok(FwdEndpoint::Wss(parse_websocket_endpoint(&url, true)?)),
        "http" => Ok(FwdEndpoint::Ws(parse_websocket_endpoint(
            &with_scheme(url, "ws")?,
            true,
        )?)),
        "https" => Ok(FwdEndpoint::Wss(parse_websocket_endpoint(
            &with_scheme(url, "wss")?,
            true,
        )?)),
        scheme => bail!(
            "unsupported --from endpoint scheme '{scheme}': use tcp://, ws://, wss://, http://, or https://"
        ),
    }
}

fn parse_endpoint_url(raw: &str) -> Result<Url> {
    Url::parse(raw).with_context(|| format!("invalid endpoint URL '{raw}'"))
}

fn with_scheme(mut url: Url, scheme: &str) -> Result<Url> {
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("invalid endpoint scheme '{scheme}'"))?;
    Ok(url)
}

fn parse_tcp_endpoint(raw: &str, url: &Url) -> Result<TcpEndpoint> {
    validate_url_common(raw, url)?;

    if !matches!(url.path(), "" | "/") || url.query().is_some() {
        bail!("invalid TCP endpoint '{raw}': expected tcp://host:port");
    }

    let host = url
        .host_str()
        .ok_or_else(|| {
            anyhow::anyhow!("invalid endpoint '{raw}': host is required")
        })?
        .to_string();
    let port = url.port().ok_or_else(|| {
        anyhow::anyhow!("invalid endpoint '{raw}': port is required")
    })?;

    Ok(TcpEndpoint {
        addr: url_host_port(raw, url, false)?,
        host,
        port,
    })
}

fn parse_websocket_endpoint(
    url: &Url,
    allow_query: bool,
) -> Result<WebSocketEndpoint> {
    validate_url_common(url.as_str(), url)?;

    if !allow_query && url.query().is_some() {
        bail!("invalid --to endpoint '{}': query is not supported", url);
    }

    Ok(WebSocketEndpoint {
        url: url.as_str().to_string(),
        bind_addr: url_host_port(url.as_str(), url, true)?,
        path: url_path(url),
    })
}

fn validate_url_common(raw: &str, url: &Url) -> Result<()> {
    if !url.username().is_empty() || url.password().is_some() {
        bail!("invalid endpoint '{raw}': user info is not supported");
    }
    if url.fragment().is_some() {
        bail!("invalid endpoint '{raw}': fragments are not supported");
    }
    if url.host_str().is_none() {
        bail!("invalid endpoint '{raw}': host is required");
    }
    Ok(())
}

fn url_host_port(
    raw: &str,
    url: &Url,
    allow_default_port: bool,
) -> Result<String> {
    let host = url.host_str().ok_or_else(|| {
        anyhow::anyhow!("invalid endpoint '{raw}': host is required")
    })?;
    let port = if allow_default_port {
        url.port_or_known_default()
    } else {
        url.port()
    }
    .ok_or_else(|| {
        anyhow::anyhow!("invalid endpoint '{raw}': port is required")
    })?;

    if host.contains(':') && !host.starts_with('[') {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn url_path(url: &Url) -> String {
    if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    }
}
