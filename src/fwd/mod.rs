//! TCP / WebSocket forwarding (`zay run fwd`).

mod server;

use std::sync::Once;

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Args};
pub use server::run;
use tracing_subscriber::EnvFilter;
use url::Url;

static RUSTLS_PROVIDER: Once = Once::new();

#[derive(Args, Debug, serde::Deserialize)]
#[command(
    about = "Forward TCP streams directly or over WebSocket (TCP/WS relay)",
    long_about = concat!(
        "zay run fwd forwards TCP streams directly, TCP streams to WebSocket streams, or WebSocket streams to TCP.\n",
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
        "  zay run fwd --to tcp://0.0.0.0:8080 --from tcp://127.0.0.1:80\n",
        "  zay run fwd --to tcp://127.0.0.1:3306 --from wss://public.com:443/wss"
    )
)]
pub struct FwdCli {
    /// Print an equivalent persistent-service TOML configuration and exit
    #[arg(long)]
    pub dump_config: bool,

    /// Where clients connect (local listener)
    #[arg(long, value_name = "ENDPOINT")]
    pub to: String,

    /// Upstream endpoint dialed for each accepted connection
    #[arg(long, value_name = "ENDPOINT")]
    pub from: String,

    /// Bearer token for WebSocket authorization
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,

    /// Increase diagnostic logging (-v for debug, -vv for trace)
    #[arg(short, long, action = ArgAction::Count)]
    pub verbose: u8,
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
    pub original_url: String,
    pub url: String,
    pub bind_addr: String,
    pub path: String,
}

pub async fn run_cli(cli: FwdCli) -> Result<()> {
    if cli.dump_config {
        print!("{}", dump_config(&cli)?);
        return Ok(());
    }
    init_rustls_provider();
    init_tracing(cli.verbose);
    run(parse(cli)?).await
}

fn dump_config(cli: &FwdCli) -> Result<String> {
    #[derive(serde::Serialize)]
    struct Config {
        fwd: Vec<crate::settings::PersistentFwdFile>,
    }

    toml::to_string_pretty(&Config {
        fwd: vec![crate::settings::PersistentFwdFile {
            name: None,
            enabled: true,
            to: cli.to.clone(),
            from: cli.from.clone(),
            token: cli.token.clone(),
            verbose: cli.verbose,
        }],
    })
    .context("serializing forwarding service configuration")
}

fn init_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn init_tracing(verbose: u8) {
    let default_filter = match verbose {
        0 => "zay::fwd=info",
        1 => "zay::fwd=debug,tungstenite=info",
        _ => "zay::fwd=trace,tungstenite=debug",
    };

    let filter = match std::env::var("RUST_LOG") {
        Ok(value) if !value.trim().is_empty() => EnvFilter::new(value),
        _ => EnvFilter::new(default_filter),
    };

    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
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
        "ws" => {
            Ok(FwdEndpoint::Ws(parse_websocket_endpoint(raw, &url, false)?))
        }
        "http" => Ok(FwdEndpoint::Ws(parse_websocket_endpoint(
            raw,
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
        "ws" => Ok(FwdEndpoint::Ws(parse_websocket_endpoint(raw, &url, true)?)),
        "wss" => {
            Ok(FwdEndpoint::Wss(parse_websocket_endpoint(raw, &url, true)?))
        }
        "http" => Ok(FwdEndpoint::Ws(parse_websocket_endpoint(
            raw,
            &with_scheme(url, "ws")?,
            true,
        )?)),
        "https" => Ok(FwdEndpoint::Wss(parse_websocket_endpoint(
            raw,
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
    original_raw: &str,
    url: &Url,
    allow_query: bool,
) -> Result<WebSocketEndpoint> {
    validate_url_common(url.as_str(), url)?;

    if !allow_query && url.query().is_some() {
        bail!("invalid --to endpoint '{}': query is not supported", url);
    }

    Ok(WebSocketEndpoint {
        original_url: original_raw.to_string(),
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
