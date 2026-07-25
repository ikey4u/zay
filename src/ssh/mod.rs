//! Stable SSH port forwarding (`zay run ssh`).

pub(crate) mod client;
pub(crate) mod config;
pub mod forward;
pub(crate) mod session;
pub(crate) mod tunnel;

use anyhow::{Result, bail};
use clap::Args;
use forward::{ForwardKind, SshForward};
use tracing_subscriber::EnvFilter;

#[derive(Args, Debug, serde::Deserialize)]
#[command(
    about = "Stable SSH port forwarding with auto-reconnect",
    long_about = concat!(
        "OpenSSH-compatible -L / -R with automatic reconnect.\n",
        "\n",
        "SYNTAX\n",
        "  [bind_host:]bind_port:remote_host:remote_port\n",
        "\n",
        "EXAMPLES\n",
        "  zay run ssh -L 3307:10.0.0.5:3306 myserver\n",
        "  zay run ssh -J bastion -L 3307:mysql.internal:3306 app-server"
    )
)]
pub struct SshCli {
    /// Print an equivalent persistent-service TOML configuration and exit
    #[arg(long)]
    pub dump_config: bool,

    /// Local forward (repeatable). [bind_host:]bind_port:remote_host:remote_port
    #[arg(
        short = 'L',
        long = "local-forward",
        value_name = "SPEC",
        action = clap::ArgAction::Append
    )]
    pub local_forwards: Vec<String>,

    /// Remote forward (repeatable). [bind_host:]bind_port:remote_host:remote_port
    #[arg(
        short = 'R',
        long = "remote-forward",
        value_name = "SPEC",
        action = clap::ArgAction::Append
    )]
    pub remote_forwards: Vec<String>,

    /// SSH host or ~/.ssh/config host alias
    pub ssh_host: String,

    /// Jump host(s), comma-separated or repeat -J. Overrides ~/.ssh/config ProxyJump
    #[arg(
        short = 'J',
        long = "jump",
        value_name = "HOST",
        action = clap::ArgAction::Append
    )]
    pub proxy_jump: Vec<String>,

    /// SSH username (overrides ~/.ssh/config)
    #[arg(short, long)]
    pub user: Option<String>,

    /// SSH password for password authentication
    #[arg(short = 'P', long)]
    pub password: Option<String>,

    /// SSH private key file (overrides ~/.ssh/config identity files)
    #[arg(short = 'i', long)]
    pub identity: Option<String>,

    /// SSH port (overrides ~/.ssh/config)
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// Reject unknown host keys instead of adding them to ~/.ssh/known_hosts
    #[arg(long)]
    pub strict_host_keys: bool,
}

#[derive(Debug)]
pub struct SshArgs {
    pub forwards: Vec<SshForward>,
    pub ssh_host: String,
    pub proxy_jump: Vec<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub identity: Option<String>,
    pub port: Option<u16>,
    pub strict_host_keys: bool,
}

pub async fn run_cli(cli: SshCli) -> Result<()> {
    if cli.dump_config {
        print!("{}", dump_config(&cli)?);
        return Ok(());
    }
    init_tracing();
    tunnel::run(parse(cli)?).await
}

fn dump_config(cli: &SshCli) -> Result<String> {
    #[derive(serde::Serialize)]
    struct Config {
        ssh: Vec<crate::settings::PersistentSshFile>,
    }

    toml::to_string_pretty(&Config {
        ssh: vec![crate::settings::PersistentSshFile {
            name: None,
            enabled: true,
            ssh_host: cli.ssh_host.clone(),
            local_forwards: cli.local_forwards.clone(),
            remote_forwards: cli.remote_forwards.clone(),
            proxy_jump: cli.proxy_jump.clone(),
            user: cli.user.clone(),
            password: cli.password.clone(),
            identity: cli.identity.clone(),
            port: cli.port,
            strict_host_keys: cli.strict_host_keys,
        }],
    })
    .map_err(Into::into)
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
}

fn parse(cli: SshCli) -> Result<SshArgs> {
    if cli.local_forwards.is_empty() && cli.remote_forwards.is_empty() {
        bail!("at least one -L or -R forward is required");
    }

    let mut forwards = Vec::new();
    let mut seen_local = std::collections::HashSet::<(String, u16)>::new();
    let mut seen_remote = std::collections::HashSet::<(String, u16)>::new();

    for spec in &cli.local_forwards {
        let fwd = SshForward::parse(spec, ForwardKind::Local)?;
        let key = (fwd.bind_host.clone(), fwd.bind_port);
        if !seen_local.insert(key) {
            bail!(
                "duplicate local forward (-L) bind address {}",
                SshForward::socket_addr(&fwd.bind_host, fwd.bind_port)
            );
        }
        forwards.push(fwd);
    }
    for spec in &cli.remote_forwards {
        let fwd = SshForward::parse(spec, ForwardKind::Remote)?;
        if fwd.bind_port != 0 {
            let key = (fwd.bind_host.clone(), fwd.bind_port);
            if !seen_remote.insert(key) {
                bail!(
                    "duplicate remote forward (-R) bind address {}",
                    SshForward::socket_addr(&fwd.bind_host, fwd.bind_port)
                );
            }
        }
        forwards.push(fwd);
    }

    Ok(SshArgs {
        forwards,
        ssh_host: cli.ssh_host,
        proxy_jump: cli.proxy_jump,
        user: cli.user,
        password: cli.password,
        identity: cli.identity,
        port: cli.port,
        strict_host_keys: cli.strict_host_keys,
    })
}
