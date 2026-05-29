//! `zay stack` — Mihomo always on; optional EasyTier mesh.

pub mod easytier;
pub mod mesh;
pub mod mihomo;

use std::{fs, net::Ipv4Addr, path::PathBuf, process::Child, sync::Arc};

use anyhow::{Context, Result, bail};
use clap::Args;

use crate::{
    ProxyOpts, api, assets, bootstrap,
    mihomo::geo,
    settings::{self as zay_settings, Settings, StackFlags, default_zay_toml},
};

const LONG_ABOUT: &str = "Run the network stack: local proxy, LAN/VM gateway, private mesh, and TUN capture.";

const AFTER_HELP: &str = include_str!("../../docs/USAGE_EXAMPLE.md");

#[derive(Args, Debug)]
#[command(long_about = LONG_ABOUT, after_long_help = AFTER_HELP)]
pub struct StackCli {
    #[command(flatten, next_help_heading = "Runtime options")]
    pub common: ProxyOpts,

    /// Join the configured private mesh network
    #[arg(long, help_heading = "Stack options")]
    pub mesh: bool,

    /// Share the local proxy port with LAN/VM clients
    #[arg(long, help_heading = "Stack options")]
    pub gateway: bool,

    /// Static EasyTier virtual IPv4 CIDR for this node, e.g. 10.126.126.10/24
    #[arg(
        long = "mesh-ipv4",
        value_name = "CIDR",
        help_heading = "Mesh auto-config"
    )]
    pub mesh_ipv4: Option<String>,

    /// EasyTier network name used when auto-creating [mesh]
    #[arg(
        long = "mesh-network-name",
        value_name = "NAME",
        default_value = "zay",
        help_heading = "Mesh auto-config"
    )]
    pub mesh_network_name: String,

    /// EasyTier network secret used when auto-creating [mesh]
    #[arg(
        long = "mesh-network-secret",
        value_name = "SECRET",
        help_heading = "Mesh auto-config"
    )]
    pub mesh_network_secret: Option<String>,

    /// EasyTier peer URI used when auto-creating [mesh]
    #[arg(
        long = "mesh-peer",
        value_name = "URI",
        action = clap::ArgAction::Append,
        help_heading = "Mesh auto-config"
    )]
    pub mesh_peers: Vec<String>,

    /// EasyTier listener URI used when auto-creating [mesh]
    #[arg(
        long = "mesh-listener",
        value_name = "URI",
        action = clap::ArgAction::Append,
        help_heading = "Mesh auto-config"
    )]
    pub mesh_listeners: Vec<String>,

    /// Mesh route CIDR for Mihomo exclusion; defaults to the network of --mesh-ipv4
    #[arg(
        long = "mesh-route",
        value_name = "CIDR",
        action = clap::ArgAction::Append,
        help_heading = "Mesh auto-config"
    )]
    pub mesh_routes: Vec<String>,
}

pub fn run(cli: StackCli) -> Result<()> {
    let flags = StackFlags {
        mesh: cli.mesh,
        gateway: cli.gateway,
        tun: cli.common.tun,
    };
    ensure_stack_config_exists(&cli.common)?;
    ensure_mesh_config_from_stack(&cli, flags)?;
    let prepared = bootstrap::prepare_stack(&cli.common, flags)?;

    #[cfg(unix)]
    if prepared.tun_enabled {
        crate::privilege::elevate_self_for_tun()?;
    }

    eprintln!("config dir → {}", prepared.settings.data_dir.display());
    eprintln!("mihomo dir → {}", prepared.settings.mihomo_dir().display());

    let mesh_started = if flags.mesh {
        let cfg = prepared
            .settings
            .mesh
            .as_ref()
            .context("[mesh] missing in zay.toml")?;
        easytier::start(cfg, &prepared.settings.data_dir)?;
        true
    } else {
        false
    };

    let state = Arc::new(api::AppState::from(prepared));
    let api_listen = format!("127.0.0.1:{}", cli.common.api_port);
    let _api = api::spawn(state.clone(), &api_listen);

    let engine = assets::resolve_binary()?;
    let listen_host = if flags.gateway {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    let proxy_scope = if flags.gateway {
        "gateway proxy"
    } else {
        "local proxy"
    };
    eprintln!(
        "stack – {proxy_scope} on {listen_host}:{} (gateway={}, mesh={}, tun={})",
        state.settings.mixed_port, flags.gateway, flags.mesh, state.tun_enabled,
    );

    let config_path = state.settings.config_path();

    let mut child = match spawn_mihomo(
        &engine,
        &state.settings,
        &config_path,
        state.tun_enabled,
    ) {
        Ok(child) => child,
        Err(e) => {
            if mesh_started {
                let _ = easytier::stop_all();
            }
            return Err(e);
        }
    };

    if let Some(stdout) = child.stdout.take() {
        assets::pipe_logs(stdout);
    }
    if let Some(stderr) = child.stderr.take() {
        assets::pipe_logs(stderr);
    }

    if !state.settings.subscriptions.is_empty() {
        geo::spawn_background_download(
            state.settings.clone(),
            Some(state.config_yaml.clone()),
        );
    }

    let pid = child.id();
    ctrlc::set_handler(move || {
        if flags.mesh {
            let _ = easytier::stop_all();
        }
        assets::terminate_process(pid);
        eprintln!("stopping stack");
        std::process::exit(130);
    })
    .context("installing Ctrl-C handler")?;

    let status = child.wait().context("waiting for network stack")?;
    if mesh_started {
        easytier::stop_all()?;
    }

    let code = status.code().unwrap_or(1);
    if code != 0 {
        bail!("network stack exited with status {code}");
    }
    Ok(())
}

fn ensure_stack_config_exists(common: &ProxyOpts) -> Result<()> {
    let (data_dir, toml_path) = stack_config_paths(common);
    if toml_path.is_file() {
        return Ok(());
    }
    fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;
    fs::write(&toml_path, default_zay_toml())
        .with_context(|| format!("writing {}", toml_path.display()))?;
    eprintln!("created default config at {}", toml_path.display());
    Ok(())
}

fn ensure_mesh_config_from_stack(
    cli: &StackCli,
    flags: StackFlags,
) -> Result<()> {
    if !flags.mesh {
        return Ok(());
    }

    let (data_dir, toml_path) = stack_config_paths(&cli.common);
    if toml_path.is_file() {
        let raw = fs::read_to_string(&toml_path)
            .with_context(|| format!("reading {}", toml_path.display()))?;
        let parsed: toml::Value = toml::from_str(&raw)
            .with_context(|| format!("parsing {}", toml_path.display()))?;
        if parsed.get("mesh").is_some() {
            return Ok(());
        }
    }

    let ipv4 = cli.mesh_ipv4.as_deref().with_context(|| {
        format!(
            "--mesh requires [mesh] in {} or --mesh-ipv4 to auto-create it",
            toml_path.display()
        )
    })?;
    let network_secret = cli.mesh_network_secret.as_deref().with_context(
        || "--mesh-network-secret is required when auto-creating [mesh]",
    )?;
    let mesh_routes = if cli.mesh_routes.is_empty() {
        vec![ipv4_network_cidr(ipv4)?]
    } else {
        cli.mesh_routes.clone()
    };
    let peers = if cli.mesh_peers.is_empty() {
        vec!["tcp://public.easytier.top:11010".to_string()]
    } else {
        cli.mesh_peers.clone()
    };

    fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;
    let mut raw = if toml_path.is_file() {
        fs::read_to_string(&toml_path)
            .with_context(|| format!("reading {}", toml_path.display()))?
    } else {
        String::new()
    };
    if !raw.ends_with('\n') && !raw.is_empty() {
        raw.push('\n');
    }
    raw.push_str(&mesh_config_toml(
        &cli.mesh_network_name,
        network_secret,
        ipv4,
        &cli.mesh_listeners,
        &peers,
        &mesh_routes,
    )?);
    fs::write(&toml_path, raw)
        .with_context(|| format!("writing {}", toml_path.display()))?;
    eprintln!("created [mesh] config in {}", toml_path.display());
    Ok(())
}

fn stack_config_paths(common: &ProxyOpts) -> (PathBuf, PathBuf) {
    zay_settings::stack_config_paths(
        common.data_dir.as_deref(),
        common.config.as_deref(),
    )
}

fn mesh_config_toml(
    network_name: &str,
    network_secret: &str,
    ipv4: &str,
    listeners: &[String],
    peers: &[String],
    mesh_routes: &[String],
) -> Result<String> {
    let mut table = toml::map::Map::new();
    table.insert("instance_name".into(), "zay".into());
    table.insert("network_name".into(), network_name.into());
    table.insert("network_secret".into(), network_secret.into());
    table.insert("ipv4".into(), ipv4.into());
    if !listeners.is_empty() {
        table.insert(
            "listeners".into(),
            toml::Value::Array(
                listeners.iter().cloned().map(toml::Value::String).collect(),
            ),
        );
    }
    table.insert(
        "peers".into(),
        toml::Value::Array(
            peers.iter().cloned().map(toml::Value::String).collect(),
        ),
    );
    table.insert(
        "mesh_routes".into(),
        toml::Value::Array(
            mesh_routes
                .iter()
                .cloned()
                .map(toml::Value::String)
                .collect(),
        ),
    );

    let mut root = toml::map::Map::new();
    root.insert("mesh".into(), toml::Value::Table(table));
    toml::to_string_pretty(&toml::Value::Table(root))
        .context("serializing [mesh]")
}

fn ipv4_network_cidr(cidr: &str) -> Result<String> {
    let (addr, prefix) = cidr.split_once('/').with_context(|| {
        format!("--mesh-ipv4 must be CIDR notation, got {cidr:?}")
    })?;
    let addr: Ipv4Addr = addr
        .parse()
        .with_context(|| format!("invalid IPv4 address in {cidr:?}"))?;
    let prefix: u32 = prefix
        .parse()
        .with_context(|| format!("invalid IPv4 prefix in {cidr:?}"))?;
    if prefix > 32 {
        bail!("invalid IPv4 prefix in {cidr:?}: must be <= 32");
    }
    let ip = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(format!("{}/{}", Ipv4Addr::from(ip & mask), prefix))
}

#[cfg(test)]
mod tests {
    use super::ipv4_network_cidr;

    #[test]
    fn derives_mesh_route_from_node_ipv4() {
        assert_eq!(
            ipv4_network_cidr("10.126.126.10/24").unwrap(),
            "10.126.126.0/24"
        );
        assert_eq!(
            ipv4_network_cidr("10.126.126.10/32").unwrap(),
            "10.126.126.10/32"
        );
    }
}

fn spawn_mihomo(
    engine: &std::path::Path,
    settings: &Settings,
    config_path: &std::path::Path,
    tun_enabled: bool,
) -> Result<Child> {
    assets::spawn(
        engine,
        &settings.mihomo_dir(),
        config_path,
        false,
        tun_enabled,
    )
}

pub fn validate(settings: &Settings) -> Result<()> {
    let flags = settings.stack;
    if flags.mesh {
        settings
            .mesh
            .as_ref()
            .context("--mesh requires a [mesh] section in zay.toml")?;
    }
    Ok(())
}
