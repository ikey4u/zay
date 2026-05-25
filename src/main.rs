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

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

const LONG_ABOUT: &str = r#"Zay – network stack and connection tools.

Network stack:
  zay stack --mesh --gateway
  zay stack --gateway
  zay stack --proxy "https://..." --gateway

Port relay and SSH tunnels:
  zay fwd --to tcp://0.0.0.0:8080 --from tcp://127.0.0.1:80
  zay ssh -L 3307:10.0.0.5:3306 myserver

Static HTTP server:
  zay http --root dist --spa
  zay http --root dist --listen 127.0.0.1:8443 --cert cert.pem --key key.pem

HTTP API (stack mode):
  GET  /api/health
  GET  /api/config
"#;

/// Zay – simple network tool.
#[derive(Parser, Debug)]
#[clap(
    name = "zay",
    author,
    about = "A simple network tool",
    long_about = LONG_ABOUT,
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the network stack: proxy, mesh, gateway, and TUN
    Stack(stack::StackCli),
    /// Serve a static directory over HTTP/HTTPS
    Http(http::HttpCli),
    /// Forward TCP streams directly or over WebSocket
    Fwd(fwd::FwdCli),
    /// Stable SSH port forwarding with auto-reconnect
    Ssh(ssh::SshCli),
}

/// Options for `zay stack`.
#[derive(clap::Args, Debug, Default)]
pub struct ProxyOpts {
    /// Remote proxy subscription URL (repeatable)
    #[clap(
        short = 's',
        long = "proxy",
        value_name = "URL",
        action = clap::ArgAction::Append
    )]
    pub subscriptions: Vec<String>,

    /// Zay config directory (zay.toml, mixin.yaml, and runtime files)
    #[clap(short, long, value_name = "DIR")]
    pub data_dir: Option<std::path::PathBuf>,

    /// Path to zay.toml (default: <data-dir>/zay.toml)
    #[clap(short = 'c', long, value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,

    /// Local Zay API port
    #[clap(long, value_name = "PORT", default_value_t = 8787)]
    pub api_port: u16,

    /// Local HTTP/SOCKS proxy port (default: 7890)
    #[clap(long, value_name = "PORT")]
    pub mixed_port: Option<u16>,

    /// Subscription provider update interval in seconds (default: 3600)
    #[clap(long, value_name = "SECS")]
    pub update_interval: Option<u64>,

    /// URL used for provider health checks
    #[clap(long, value_name = "URL")]
    pub health_check_url: Option<String>,

    /// Log level: debug, info, warning, error (default: info)
    #[clap(long, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Allow LAN access to the local proxy port
    #[clap(long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    pub allow_lan: bool,

    /// Capture system traffic through a TUN interface
    #[clap(long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    pub tun: bool,

    /// YAML mixin merged into generated proxy config
    #[clap(long, value_name = "FILE")]
    pub mixin: Option<std::path::PathBuf>,

    /// Bootstrap proxy YAML used to fetch remote subscriptions
    #[clap(long, value_name = "FILE")]
    pub bootstrap_proxy: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Stack(stack) => stack::run(stack),
        Command::Http(http) => run_http(http),
        Command::Fwd(fwd) => run_fwd(fwd),
        Command::Ssh(ssh) => run_ssh(ssh),
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
