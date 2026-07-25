mod api;
mod bootstrap;
mod config;
mod daemon;
mod fwd;
mod http;
mod logging;
mod runtime;
mod settings;
mod singbox;
mod ssh;
mod stack;
#[cfg(windows)]
mod windows_tun_worker;
mod yaml;

#[cfg(unix)]
mod privilege;

use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};

const LONG_ABOUT: &str = r#"Zay – network stack and connection tools.

Network stack:
  sudo zay run proxy -s "https://..."
  zay run proxy --mesh relay --mesh-auth 'net:secret' --mesh-ip 10.126.126.1/24
  zay run proxy --help

Configuration:
  zay config dump
  zay config set mixed_port 7891
  zay config edit

One-off tasks:
  zay run fwd --to tcp://0.0.0.0:8080 --from tcp://127.0.0.1:80
  zay run ssh -L 3307:10.0.0.5:3306 myserver
  zay run http --root dist --spa

Persistent services:
  zay service start
  zay service status
  zay service logs --follow
  zay service stop

"#;

const AFTER_HELP: &str = include_str!("../docs/USAGE_EXAMPLE.md");

/// Zay – simple network tool.
#[derive(Parser, Debug)]
#[clap(
    name = "zay",
    author,
    about = "A simple network tool",
    long_about = LONG_ABOUT,
    after_long_help = AFTER_HELP,
    subcommand_required = false,
    arg_required_else_help = false
)]
pub struct Cli {
    /// Data directory passed by the internal service re-exec.
    #[arg(short, long, value_name = "DIR", hide = true)]
    data_dir: Option<std::path::PathBuf>,

    /// Path to zay.toml passed by the internal service re-exec.
    #[arg(short = 'c', long, value_name = "FILE", hide = true)]
    config: Option<std::path::PathBuf>,

    /// Internal re-exec entry used by the detached service runtime.
    #[arg(long, hide = true)]
    run_daemon: bool,

    /// Internal elevated sing-box TUN worker.
    #[cfg(windows)]
    #[arg(long, hide = true)]
    run_tun_worker: bool,
    #[cfg(windows)]
    #[arg(long, hide = true)]
    tun_worker_binary: Option<std::path::PathBuf>,
    #[cfg(windows)]
    #[arg(long, hide = true)]
    tun_worker_runtime_dir: Option<std::path::PathBuf>,
    #[cfg(windows)]
    #[arg(long, hide = true)]
    tun_worker_config: Option<std::path::PathBuf>,
    #[cfg(windows)]
    #[arg(long, hide = true)]
    tun_worker_pipe: Option<String>,
    #[cfg(windows)]
    #[arg(long, hide = true)]
    tun_worker_token: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run one-off foreground tasks
    Run(RunCli),
    /// Inspect and edit zay.toml
    Config(config::ConfigCli),
    /// Manage configured persistent services
    Service(ServiceCli),
}

#[derive(Args, Debug)]
pub struct RunCli {
    #[command(subcommand)]
    command: RunCommand,
}

#[derive(Subcommand, Debug)]
pub enum RunCommand {
    /// Run the network proxy/TUN and optional EasyTier mesh
    Proxy(stack::StackCli),
    /// Serve a static directory over HTTP/HTTPS
    Http(http::HttpCli),
    /// Forward TCP streams directly or over WebSocket
    Fwd(fwd::FwdCli),
    /// Stable SSH port forwarding with auto-reconnect
    Ssh(ssh::SshCli),
}

#[derive(Args, Debug)]
pub struct ServiceCli {
    #[command(flatten)]
    opts: ServiceOpts,

    #[command(subcommand)]
    command: ServiceCommand,
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommand {
    /// Start all enabled components from zay.toml in the background
    Start,
    /// Show persistent service status
    Status,
    /// Request graceful shutdown of persistent services
    Stop,
    /// Print persistent service logs
    Logs(LogsCli),
    /// Inspect proxies available to persistent services
    Proxy(ServiceProxyCli),
}

#[derive(Args, Debug, Clone)]
pub struct ServiceOpts {
    /// Data directory for the persistent service runtime
    #[arg(short, long, value_name = "DIR", global = true)]
    data_dir: Option<std::path::PathBuf>,

    /// Path to zay.toml for the persistent service runtime
    #[arg(short = 'c', long, value_name = "FILE", global = true)]
    config: Option<std::path::PathBuf>,
}

#[derive(Args, Debug)]
pub struct LogsCli {
    /// Keep streaming new lines
    #[arg(short, long)]
    follow: bool,
    /// Match a domain or destination with a regular expression
    #[arg(long)]
    domain: Option<String>,
    /// Match an application with a regular expression
    #[arg(long)]
    app: Option<String>,
    /// Match an IP address with a regular expression
    #[arg(long)]
    ip: Option<String>,
    /// Match a proxy node with a regular expression
    #[arg(long)]
    node: Option<String>,
    /// Match the event level (trace, debug, info, warn, error)
    #[arg(long)]
    level: Option<String>,
    /// Match the complete structured log line with a regular expression
    #[arg(long)]
    regex: Option<String>,
    /// Read unparsed sing-box logs instead
    #[arg(long)]
    raw: bool,
}

#[derive(Args, Debug)]
pub struct ServiceProxyCli {
    #[command(subcommand)]
    command: ServiceProxyCommand,
}

#[derive(Subcommand, Debug)]
pub enum ServiceProxyCommand {
    /// List current subscription proxy tags
    List,
}

/// Options for `zay run proxy`.
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

    /// Internal persistent-service data directory.
    #[clap(skip)]
    pub data_dir: Option<std::path::PathBuf>,

    /// Internal persistent-service configuration path.
    #[clap(skip)]
    pub config: Option<std::path::PathBuf>,

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

    /// Disable system TUN (default: TUN on for `zay run proxy`)
    #[clap(long = "no-tun", action = clap::ArgAction::SetTrue)]
    pub no_tun: bool,

    /// Extra CIDR excluded from proxy TUN auto-route (repeatable; mesh/SSH excludes are automatic)
    #[clap(long = "tun-exclude", value_name = "CIDR", action = clap::ArgAction::Append)]
    pub tun_exclude_routes: Vec<String>,

    /// Internal persistent-service bootstrap proxy configuration.
    #[clap(skip)]
    pub bootstrap_proxy: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    #[cfg(windows)]
    if cli.run_tun_worker {
        return windows_tun_worker::run(windows_tun_worker::Args {
            binary: cli
                .tun_worker_binary
                .context("missing TUN worker binary")?,
            runtime_dir: cli
                .tun_worker_runtime_dir
                .context("missing TUN worker runtime directory")?,
            config_path: cli
                .tun_worker_config
                .context("missing TUN worker config")?,
            pipe_name: cli
                .tun_worker_pipe
                .context("missing TUN worker pipe")?,
            token: cli.tun_worker_token.context("missing TUN worker token")?,
        });
    }
    if cli.run_daemon {
        let guard =
            daemon::enter(cli.data_dir.as_deref(), cli.config.as_deref())?;
        let sudo_password = daemon::take_sudo_password()?;
        return tokio::runtime::Runtime::new()
            .context("creating tokio runtime")?
            .block_on(runtime::run_daemon(
                cli.data_dir,
                cli.config,
                &guard,
                sudo_password,
            ));
    }
    let Some(command) = cli.command else {
        Cli::command().print_help().context("printing help")?;
        println!();
        return Ok(());
    };
    match command {
        Command::Run(run) => match run.command {
            RunCommand::Proxy(stack) => stack::run(stack),
            RunCommand::Http(http) => run_http(http),
            RunCommand::Fwd(fwd) => run_fwd(fwd),
            RunCommand::Ssh(ssh) => run_ssh(ssh),
        },
        Command::Config(config) => config::run(config),
        Command::Service(service) => run_service(service),
    }
}

fn run_service(service: ServiceCli) -> Result<()> {
    let opts = service.opts;
    match service.command {
        ServiceCommand::Start => {
            daemon::ensure_not_running(
                opts.data_dir.as_deref(),
                opts.config.as_deref(),
            )?;
            #[cfg(unix)]
            let sudo_password = preflight_persistent_tun(&opts)?;
            #[cfg(not(unix))]
            let sudo_password = None;
            daemon::spawn(opts.data_dir, opts.config, sudo_password)
        }
        ServiceCommand::Status => run_status(opts.data_dir, opts.config),
        ServiceCommand::Stop => run_stop(opts.data_dir, opts.config),
        ServiceCommand::Logs(logs) => {
            run_logs(opts.data_dir, opts.config, logs)
        }
        ServiceCommand::Proxy(proxy) => match proxy.command {
            ServiceProxyCommand::List => run_service_proxy_list(&opts),
        },
    }
}

fn run_service_proxy_list(opts: &ServiceOpts) -> Result<()> {
    let (data_dir, _) = settings::stack_config_paths(
        opts.data_dir.as_deref(),
        opts.config.as_deref(),
    );
    let path = data_dir.join(settings::SINGBOX_DIR).join("config.json");
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let config: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", path.display()))?;
    for tag in subscription_proxy_tags(&config)? {
        println!("{tag}");
    }
    Ok(())
}

fn subscription_proxy_tags(config: &serde_json::Value) -> Result<Vec<String>> {
    let tags = config
        .get("outbounds")
        .and_then(serde_json::Value::as_array)
        .and_then(|outbounds| {
            outbounds.iter().find(|outbound| {
                outbound.get("tag").and_then(serde_json::Value::as_str) == Some("Auto")
                    && outbound
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        == Some("urltest")
            })
        })
        .and_then(|auto| auto.get("outbounds"))
        .and_then(serde_json::Value::as_array)
        .context("subscription proxy list unavailable; start the proxy service first")?;
    Ok(tags
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_owned)
        .collect())
}

/// Keep the persistent supervisor unprivileged. When configured, only the
/// proxy child that owns TUN/routing is elevated after service detachment.
#[cfg(unix)]
fn preflight_persistent_tun(opts: &ServiceOpts) -> Result<Option<String>> {
    let cfg = settings::load_persistent_config(
        opts.data_dir.as_deref(),
        opts.config.as_deref(),
    )?;
    let relay_forces_tun_off = cfg
        .mesh
        .as_ref()
        .is_some_and(|mesh| mesh.role == settings::MeshRole::Relay);
    if (cfg.stack.enabled || cfg.mesh.is_some())
        && cfg.stack.tun.enabled
        && !relay_forces_tun_off
    {
        return privilege::daemon_tun_password();
    }
    Ok(None)
}

fn print_mesh_status(response: &str) -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(&response)
        .context("parsing mesh status response")?;
    if let Some(error) = value.get("error").and_then(|value| value.as_str()) {
        anyhow::bail!("mesh status unavailable: {error}");
    }
    let instances: Vec<crate::stack::easytier::MeshInstanceStatus> =
        serde_json::from_value(value).context("decoding mesh status")?;
    if instances.is_empty() {
        println!("mesh: no local EasyTier instance is running");
        return Ok(());
    }
    for instance in instances {
        println!(
            "instance {}: local mesh IP {}, {} connected peer(s), {} route(s)",
            instance.instance_id,
            instance.virtual_ipv4.as_deref().unwrap_or("(relay/no IP)"),
            instance.connected_peers,
            instance.routes
        );
        if instance.peers.is_empty() {
            println!("  no route-bearing peer nodes reported");
        } else {
            for peer in instance.peers {
                println!(
                    "  {}  mesh IP {}  peer {}",
                    peer.hostname.as_deref().unwrap_or("(unnamed)"),
                    peer.virtual_ipv4.as_deref().unwrap_or("?"),
                    peer.peer_id
                );
            }
        }
    }
    Ok(())
}

fn run_status(
    data_dir: Option<std::path::PathBuf>,
    config: Option<std::path::PathBuf>,
) -> Result<()> {
    let paths = daemon::paths(data_dir.as_deref(), config.as_deref());
    let runtime =
        tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    let result = runtime.block_on(daemon::request(&paths, "status"));
    match result {
        Ok(status) => {
            println!("zay: {status}");
            match runtime.block_on(daemon::request(&paths, "mesh-status")) {
                Ok(response) => print_mesh_status(&response)?,
                Err(error) => eprintln!("mesh: status unavailable ({error:#})"),
            }
        }
        Err(_) => match daemon::status(data_dir.as_deref(), config.as_deref())?
        {
            Some(pid) => {
                println!("zay: running (pid {pid}; control unavailable)")
            }
            None => println!("zay: stopped"),
        },
    }
    Ok(())
}

fn run_stop(
    data_dir: Option<std::path::PathBuf>,
    config: Option<std::path::PathBuf>,
) -> Result<()> {
    let paths = daemon::paths(data_dir.as_deref(), config.as_deref());
    let result = tokio::runtime::Runtime::new()
        .context("creating tokio runtime")?
        .block_on(daemon::request(&paths, "stop"));
    match result {
        Ok(status) => println!("zay: {status}"),
        Err(_) => {
            daemon::terminate(data_dir.as_deref(), config.as_deref())?;
            println!("zay: SIGTERM sent");
        }
    }
    Ok(())
}

fn run_logs(
    data_dir: Option<std::path::PathBuf>,
    config: Option<std::path::PathBuf>,
    logs: LogsCli,
) -> Result<()> {
    use std::{io::Read, thread, time::Duration};

    let paths = daemon::paths(data_dir.as_deref(), config.as_deref());
    let path = if logs.raw {
        paths.log_dir.join("singbox.raw.log")
    } else {
        paths.log_dir.join("events.jsonl")
    };
    let filters = LogFilters::from_cli(&logs)?;
    if logs.raw && filters.has_fields() {
        anyhow::bail!(
            "--raw only supports --regex; structured field filters require events.jsonl"
        );
    }
    let mut offset = 0_u64;
    loop {
        let mut file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && !logs.follow =>
            {
                anyhow::bail!("log file not found: {}", path.display())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(250));
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("opening {}", path.display()));
            }
        };
        use std::io::Seek;
        let len = file.metadata()?.len();
        if len < offset {
            // The daemon may have rotated its file since the previous poll.
            offset = 0;
        }
        file.seek(std::io::SeekFrom::Start(offset))?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        if !text.is_empty() {
            for line in text.lines() {
                if filters.matches(line, logs.raw) {
                    println!("{}", render_log_line(line, logs.raw));
                }
            }
            offset += text.len() as u64;
        }
        if !logs.follow {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    Ok(())
}

struct LogFilters {
    domain: Option<regex::Regex>,
    app: Option<regex::Regex>,
    ip: Option<regex::Regex>,
    node: Option<regex::Regex>,
    level: Option<regex::Regex>,
    regex: Option<regex::Regex>,
}

impl LogFilters {
    fn from_cli(cli: &LogsCli) -> Result<Self> {
        let compile =
            |pattern: &Option<String>| -> Result<Option<regex::Regex>> {
                pattern
                    .as_deref()
                    .map(regex::Regex::new)
                    .transpose()
                    .context("compiling log filter")
            };
        Ok(Self {
            domain: compile(&cli.domain)?,
            app: compile(&cli.app)?,
            ip: compile(&cli.ip)?,
            node: compile(&cli.node)?,
            level: compile(&cli.level)?,
            regex: compile(&cli.regex)?,
        })
    }

    fn has_fields(&self) -> bool {
        self.domain.is_some()
            || self.app.is_some()
            || self.ip.is_some()
            || self.node.is_some()
            || self.level.is_some()
    }

    fn matches(&self, line: &str, raw: bool) -> bool {
        if raw {
            return self
                .regex
                .as_ref()
                .is_none_or(|filter| filter.is_match(line));
        }
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        let field = |key: &str| event["fields"][key].as_str().unwrap_or("");
        let destination = field("destination");
        let domain = field("domain");
        let is_ip_destination = destination
            .split(':')
            .next()
            .is_some_and(|host| host.parse::<std::net::IpAddr>().is_ok());
        self.domain.as_ref().is_none_or(|filter| {
            filter.is_match(domain)
                || (!is_ip_destination && filter.is_match(destination))
        }) && self
            .app
            .as_ref()
            .is_none_or(|filter| filter.is_match(field("app")))
            && self.ip.as_ref().is_none_or(|filter| {
                is_ip_destination && filter.is_match(destination)
            })
            && self
                .node
                .as_ref()
                .is_none_or(|filter| filter.is_match(field("node")))
            && self.level.as_ref().is_none_or(|filter| {
                filter.is_match(event["level"].as_str().unwrap_or(""))
            })
            && self
                .regex
                .as_ref()
                .is_none_or(|filter| filter.is_match(line))
    }
}

fn render_log_line(line: &str, raw: bool) -> String {
    if raw {
        return line.to_string();
    }
    let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
        return line.to_string();
    };
    let source = event["source"].as_str().unwrap_or("zay");
    // Older events.jsonl records used `kind` instead of component/event.
    // Keep them useful after upgrading rather than rendering `-.event`.
    let component = event["component"]
        .as_str()
        .unwrap_or(if source == "singbox" { "proxy" } else { "zay" });
    let name = event["event"]
        .as_str()
        .or_else(|| event["kind"].as_str())
        .unwrap_or("event");
    let level = event["level"].as_str().unwrap_or("info");
    let mut rendered = format!("{source} {component}.{name} level={level}");
    if let Some(fields) = event["fields"].as_object() {
        for (key, value) in fields {
            // sing-box's connection ID is only an internal correlation key;
            // it is useful in JSONL/debugging but not in normal diagnostics.
            if key == "connection" {
                continue;
            }
            if let Some(value) = value.as_str() {
                rendered.push_str(&format!(" {key}={value:?}"));
            }
        }
    }
    if let Some(error) = event["error"].as_str() {
        rendered.push_str(&format!(" error={error:?}"));
    }
    if event["component"].is_null() {
        if let Some(message) = event["message"].as_str() {
            rendered.push_str(&format!(" message={message:?}"));
        }
    }
    rendered
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_auto_proxy_members_only() {
        let config = serde_json::json!({
            "outbounds": [
                { "tag": "direct", "type": "direct" },
                { "tag": "Auto", "type": "urltest", "outbounds": ["sg-1", "sg-2"] },
                { "tag": "Proxy", "type": "selector", "outbounds": ["Auto", "sg-1"] }
            ]
        });

        assert_eq!(subscription_proxy_tags(&config).unwrap(), ["sg-1", "sg-2"]);
    }
}
