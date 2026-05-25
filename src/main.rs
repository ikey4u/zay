mod api;
mod assets;
mod bootstrap;
mod fwd;
mod http;
mod mihomo;
mod settings;
mod ssh;
mod stack;
mod yaml;

#[cfg(unix)]
mod privilege;

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

const LONG_ABOUT: &str = r#"Zay – proxy, mesh, and connection tools.

Proxy (default, requires -s):
  zay -s "https://your-subscription-url"
  zay -s "https://sub-a" -s "https://sub-b" --api-port 8787 --mixed-port 7890

Stack (Mihomo always; optional mesh / gateway / subscription / TUN):
  zay stack --mesh --gateway
  zay stack --gateway
  zay stack --proxy "https://..." --gateway

Port relay and SSH tunnels:
  zay fwd --to tcp://0.0.0.0:8080 --from tcp://127.0.0.1:80
  zay ssh -L 3307:10.0.0.5:3306 myserver

Static HTTP server:
  zay http --root dist --spa
  zay http --root dist --listen 127.0.0.1:8443 --cert cert.pem --key key.pem

HTTP API (proxy / stack mode):
  GET  /api/health
  GET  /api/config
"#;

/// Zay – simple proxy with HTTP API, fwd relay, and ssh tunnels.
#[derive(Parser, Debug)]
#[clap(
    name = "zay",
    author,
    about = "A simple network proxy",
    long_about = LONG_ABOUT
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub proxy: ProxyOpts,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run Mihomo (+ optional EasyTier mesh, gateway, subscription, TUN)
    Stack(stack::StackCli),
    /// Serve a static directory over HTTP/HTTPS
    Http(http::HttpCli),
    /// Forward TCP streams directly or over WebSocket
    Fwd(fwd::FwdCli),
    /// Stable SSH port forwarding with auto-reconnect
    Ssh(ssh::SshCli),
}

/// Options for the default proxy run (`zay -s …`).
#[derive(clap::Args, Debug, Default)]
pub struct ProxyOpts {
    /// Subscription URL (repeat -s for multiple subscriptions)
    #[clap(short, long = "subscription", value_name = "URL", action = clap::ArgAction::Append)]
    pub subscriptions: Vec<String>,

    /// Zay config directory — zay.toml & mixin.yaml at top level; Mihomo files under mihomo/
    #[clap(short, long, value_name = "DIR")]
    pub data_dir: Option<std::path::PathBuf>,

    /// Path to zay.toml (default: <data-dir>/zay.toml)
    #[clap(short = 'c', long, value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,

    /// Zay HTTP API listen port (binds 127.0.0.1)
    #[clap(long, value_name = "PORT", default_value_t = 8787)]
    pub api_port: u16,

    /// HTTP/SOCKS mixed proxy port (default: 7890)
    #[clap(long, value_name = "PORT")]
    pub mixed_port: Option<u16>,

    /// Proxy provider update interval in seconds (default: 3600)
    #[clap(long, value_name = "SECS")]
    pub update_interval: Option<u64>,

    /// URL used for proxy health checks (default: http://cp.cloudflare.com/generate_204)
    #[clap(long, value_name = "URL")]
    pub health_check_url: Option<String>,

    /// Log level: debug, info, warning, error (default: info)
    #[clap(long, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Allow LAN connections (default: false)
    #[clap(long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    pub allow_lan: bool,

    /// Enable TUN mode (default: false; uses sudo cache when available, else prompts)
    #[clap(long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    pub tun: bool,

    /// YAML mixin merged into generated config.yaml
    #[clap(long, value_name = "FILE")]
    pub mixin: Option<std::path::PathBuf>,

    /// Bootstrap proxy YAML (one Mihomo proxy) used to fetch the subscription URL
    #[clap(long, value_name = "FILE")]
    pub bootstrap_proxy: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Stack(stack)) => stack::run(stack),
        Some(Command::Http(http)) => run_http(http),
        Some(Command::Fwd(fwd)) => run_fwd(fwd),
        Some(Command::Ssh(ssh)) => run_ssh(ssh),
        None => run_proxy(cli),
    }
}

fn run_http(cli: http::HttpCli) -> Result<()> {
    tokio::runtime::Runtime::new()
        .context("creating tokio runtime")?
        .block_on(http::run(cli))
}

fn run_fwd(cli: fwd::FwdCli) -> Result<()> {
    tokio::runtime::Runtime::new()
        .context("creating tokio runtime")?
        .block_on(fwd::run_cli(cli))
}

fn run_ssh(cli: ssh::SshCli) -> Result<()> {
    tokio::runtime::Runtime::new()
        .context("creating tokio runtime")?
        .block_on(ssh::run_cli(cli))
}

fn run_proxy(cli: Cli) -> Result<()> {
    if cli.proxy.subscriptions.is_empty() {
        bail!(
            "at least one subscription URL is required (-s URL), or use: zay stack, zay fwd, zay ssh"
        );
    }
    let prepared = bootstrap::prepare_proxy(&cli.proxy)?;
    eprintln!("config dir → {}", prepared.settings.data_dir.display());
    eprintln!("mihomo dir → {}", prepared.settings.mihomo_dir().display());

    let state = Arc::new(api::AppState::from(prepared));
    let api_listen = format!("127.0.0.1:{}", cli.proxy.api_port);
    let _api = api::spawn(state.clone(), &api_listen);

    let engine = assets::resolve_binary()?;
    eprintln!(
        "starting – mixed proxy on 0.0.0.0:{}",
        state.settings.mixed_port
    );

    let config_path = state.settings.config_path();
    if state.tun_enabled {
        eprintln!("TUN enabled – elevated privileges required for proxy");
    }
    let mut child = assets::spawn(
        &engine,
        &state.settings.mihomo_dir(),
        &config_path,
        false,
        state.tun_enabled,
    )?;

    if let Some(stdout) = child.stdout.take() {
        assets::pipe_logs(stdout);
    }
    if let Some(stderr) = child.stderr.take() {
        assets::pipe_logs(stderr);
    }

    mihomo::geo::spawn_background_download(
        state.settings.clone(),
        Some(state.config_yaml.clone()),
    );

    let pid = child.id();
    ctrlc::set_handler(move || {
        assets::terminate_process(pid);
        eprintln!("stopping");
        std::process::exit(130);
    })
    .context("installing Ctrl-C handler")?;

    let status = child.wait().context("waiting for zay")?;
    let code = status.code().unwrap_or(1);
    if code != 0 {
        bail!("zay exited with status {code}");
    }
    Ok(())
}
