//! `zay stack` — Mihomo always on; optional EasyTier mesh.

pub mod easytier;
pub mod mesh;
pub mod mihomo;

use std::{process::Child, sync::Arc};

use anyhow::{Context, Result, bail};
use clap::Args;

use crate::{
    ProxyOpts, api, assets, bootstrap,
    mihomo::geo,
    settings::{Settings, StackFlags},
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
}

pub fn run(cli: StackCli) -> Result<()> {
    let flags = StackFlags {
        mesh: cli.mesh,
        gateway: cli.gateway,
        tun: cli.common.tun,
    };
    let prepared = bootstrap::prepare_stack(&cli.common, flags)?;
    eprintln!("config dir → {}", prepared.settings.data_dir.display());
    eprintln!("mihomo dir → {}", prepared.settings.mihomo_dir().display());

    let mesh_started = if flags.mesh {
        let cfg = prepared
            .settings
            .mesh
            .as_ref()
            .context("[mesh] missing in zay.toml")?;
        easytier::start(cfg)?;
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
    if state.tun_enabled {
        eprintln!("TUN enabled – elevated privileges required");
    }

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
        let mesh = settings
            .mesh
            .as_ref()
            .context("--mesh requires a [mesh] section in zay.toml")?;
        if flags.tun && mesh.no_tun != Some(true) {
            bail!(
                "--tun with --mesh requires `no_tun = true` in [mesh] (stack owns TUN; mesh virtual IP only)"
            );
        }
    }
    Ok(())
}
