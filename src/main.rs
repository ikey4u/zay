mod api;
mod assets;
mod bootstrap;
mod mihomo;
mod settings;
mod yaml;

#[cfg(unix)]
mod privilege;

use std::sync::Arc;

use anyhow::{Context, bail};
use clap::Parser;

const LONG_ABOUT: &str = r#"Zay – a simple proxy with a built-in HTTP API.

Start:
  zay -s "https://your-subscription-url"
  zay -s "https://sub-a" -s "https://sub-b" --api-port 8787 --mixed-port 7890

Runs the mixed proxy and Zay API (default http://127.0.0.1:8787).

HTTP API:
  GET  /api/health
       Health check

  GET  /api/config
       Return full zay config YAML (proxies inlined from subscription)

Examples:
  curl http://127.0.0.1:8787/api/health
  curl http://127.0.0.1:8787/api/config
"#;

/// Zay – simple proxy with HTTP API.
#[derive(Parser, Debug)]
#[clap(
    name = "zay",
    author,
    about = "A simple network proxy",
    long_about = LONG_ABOUT
)]
pub struct Cli {
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.subscriptions.is_empty() {
        bail!("at least one subscription URL is required (-s URL)");
    }
    let prepared = bootstrap::prepare(&cli)?;
    eprintln!("config dir → {}", prepared.settings.data_dir.display());
    eprintln!("mihomo dir → {}", prepared.settings.mihomo_dir().display());

    let state = Arc::new(api::AppState::from(prepared));
    let api_listen = format!("127.0.0.1:{}", cli.api_port);
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
