//! `zay stack` — sing-box TUN + optional EasyTier mesh (WireGuard portal).

pub mod easytier;
pub mod mesh;
pub mod mihomo;

use std::{
    fs,
    net::Ipv4Addr,
    path::PathBuf,
    process::Child,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::Args;

use crate::{
    ProxyOpts, api, assets,
    bootstrap::singbox as bootstrap,
    settings::{self as zay_settings, Settings, StackFlags, default_zay_toml},
    singbox::{self, mixin, rules},
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

    /// Mesh route CIDR sent to sing-box WireGuard endpoint
    #[arg(
        long = "mesh-route",
        value_name = "CIDR",
        action = clap::ArgAction::Append,
        help_heading = "Mesh auto-config"
    )]
    pub mesh_routes: Vec<String>,

    /// Skip downloading clash-rules (use cached rule-sets or simple fallback routes)
    #[arg(long = "no-rules", help_heading = "Stack options")]
    pub no_rules: bool,
}

pub fn run(cli: StackCli) -> Result<()> {
    let flags = StackFlags {
        mesh: cli.mesh,
        gateway: cli.gateway,
        tun: !cli.common.no_tun,
        no_rules: cli.no_rules,
    };
    ensure_stack_config_exists(&cli.common)?;
    ensure_mesh_config_from_stack(&cli, flags)?;

    let mut prepared = bootstrap::prepare_stack(&cli.common, flags)?;

    eprintln!("config dir → {}", prepared.settings.data_dir.display());
    eprintln!(
        "sing-box dir → {}",
        prepared.settings.singbox_dir().display()
    );

    let mesh_started = if flags.mesh {
        let cfg = prepared
            .settings
            .mesh
            .as_ref()
            .context("[mesh] missing in zay.toml")?;
        if mesh::is_hub(cfg) {
            eprintln!(
                "mesh hub: sing-box TUN disabled (EasyTier relay only; SSH stays on eth0)"
            );
        } else {
            let mesh_proxy = !prepared.settings.subscriptions.is_empty();
            if mesh_proxy {
                eprintln!(
                    "mesh client + proxy: full TUN capture (Google/etc. via sing-box; mesh still uses easytier-wg)"
                );
            } else if crate::singbox::tun_route::tun_selective_mesh_routes(
                &prepared.settings,
            ) {
                eprintln!(
                    "mesh client: TUN captures only [mesh].mesh_routes (relay SSH + public traffic stay on physical NIC)"
                );
                if let Some(routes) = prepared
                    .settings
                    .mesh
                    .as_ref()
                    .and_then(|m| m.mesh_routes.as_ref())
                {
                    eprintln!(
                        "mesh client: route_address → {}",
                        routes.join(", ")
                    );
                }
                if let Some(portal) =
                    prepared.settings.mesh.as_ref().and_then(|m| {
                        crate::stack::mesh::portal_client_host_cidr(m)
                    })
                {
                    let tun = prepared.settings.mesh.as_ref().and_then(|m| {
                        crate::stack::mesh::portal_tun_prefix_cidr(m)
                    });
                    eprintln!(
                        "mesh client: WG portal host {portal}, TUN prefix {} (TCP replies route back via mesh; portal /32 must be unique per node)",
                        tun.as_deref().unwrap_or("?")
                    );
                }
            } else if prepared.settings.stack.gateway {
                eprintln!(
                    "mesh client: --gateway set → full TUN capture (not SSH-safe to relay)"
                );
            }
        }
        eprintln!(
            "mesh tip: reach a peer service with `curl http://<mesh-ip>:<port>/` from another node; \
             the server must run `zay stack --mesh` and listen on 0.0.0.0 or 127.0.0.1 (not only the mesh IP)"
        );
        if std::env::var("ZAY_EASYTIER_DEBUG").is_err() {
            eprintln!(
                "tip: export ZAY_EASYTIER_DEBUG=1 for verbose EasyTier listener logs"
            );
        }
        easytier::start_for_singbox(cfg, &prepared.settings.data_dir)?;
        if mesh::is_hub(cfg) {
            eprintln!(
                "mesh hub: when Mac/Linux clients connect, this node should show 2+ remote peers \
                 (e.g. weapon + macbook); only 1 peer means the client is not on the same network_name/secret"
            );
            crate::singbox::tun_route::wait_for_mesh_listeners(
                cfg,
                std::time::Duration::from_secs(30),
            )
            .with_context(|| {
                "EasyTier hub listeners not ready — clients cannot connect on :11010".to_string()
            })?;
        }
        let wg_listen =
            cfg.wireguard_listen.as_deref().unwrap_or("127.0.0.1:51820");
        match crate::singbox::tun_route::wait_for_wireguard_port(
            wg_listen,
            std::time::Duration::from_secs(10),
        ) {
            Ok(()) => {}
            Err(e) => {
                eprintln!(
                    "warn: {e:#} — continuing; mesh 10.x via easytier-wg may be down until portal is up"
                );
            }
        }
        if std::env::var("ZAY_MESH_REQUIRE_PEERS").ok().as_deref() == Some("1")
        {
            easytier::wait_for_mesh_peers(
                std::time::Duration::from_secs(45),
                cfg,
            )
            .context("EasyTier mesh not ready")?;
        } else {
            easytier::spawn_mesh_peer_watch(cfg.clone());
            eprintln!(
                "mesh: peer discovery in background — starting sing-box now"
            );
        }
        true
    } else {
        false
    };

    // Hot reload while `easytier-wg` is up hangs sing-box (endpoint close never finishes).
    // Mesh-only: prefetch rules before sing-box (direct HTTP). Mesh + proxy: fetch after sing-box starts.
    let mesh_rules_pending = flags.mesh
        && !flags.no_rules
        && !rules::files_present(&prepared.settings.singbox_dir());
    if mesh_rules_pending && prepared.settings.subscriptions.is_empty() {
        eprintln!(
            "mesh: prefetching clash-rules before sing-box (hot reload disabled with --mesh)…"
        );
        match rules::download_all(&prepared.settings) {
            Ok(()) => {
                let base =
                    singbox::builder::build_config(&prepared.settings, true)?;
                prepared.config_json =
                    mixin::merge_config(&base, &prepared.settings)?;
                fs::write(
                    prepared.settings.config_path(),
                    &prepared.config_json,
                )
                .with_context(|| {
                    format!(
                        "writing {}",
                        prepared.settings.config_path().display()
                    )
                })?;
                eprintln!("config updated with clash-rules");
            }
            Err(e) => {
                eprintln!(
                    "warn: clash-rules prefetch failed: {e:#}; continuing with fallback routes"
                );
            }
        }
    }

    let state = Arc::new(api::AppState::from(prepared));
    let api_listen = format!("127.0.0.1:{}", cli.common.api_port);
    let _api = api::spawn(state.clone(), &api_listen);

    let engine = singbox::resolve_binary()?;
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
    if state.tun_enabled && !state.settings.subscriptions.is_empty() {
        eprintln!(
            "tip: desktop Firefox (RDP) — Settings → Network → **No proxy** when TUN is on; \
             do NOT use Manual proxy localhost:7890 (curl uses tun0, not mixed). \
             If system proxy is stuck: gsettings set org.gnome.system.proxy mode 'none'"
        );
    }

    let config_path = state.settings.config_path();

    if state.tun_enabled {
        let refreshed = bootstrap::refresh_config(&state.settings, flags)?;
        singbox::tun_route::log_tun_routing(&refreshed);
        *state.config_json.write().expect("config lock") = refreshed;
    }

    let mut child = match spawn_singbox(
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

    if state.tun_enabled {
        let settings = state.settings.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(3));
            singbox::tun_route::linux_register_tun_dns(&settings);
        });
    }

    if mesh_rules_pending && !state.settings.subscriptions.is_empty() {
        match mesh_fetch_rules_restart_singbox(
            &state.settings,
            &engine,
            &config_path,
            state.tun_enabled,
            &mut child,
            &state.config_json,
        ) {
            Ok(()) => {
                if let Some(stdout) = child.stdout.take() {
                    assets::pipe_logs(stdout);
                }
                if let Some(stderr) = child.stderr.take() {
                    assets::pipe_logs(stderr);
                }
            }
            Err(e) => eprintln!(
                "warn: clash-rules fetch via proxy failed: {e:#}; \
                 fallback routes still apply (final outbound → Proxy)"
            ),
        }
    }

    if !flags.mesh
        && !flags.no_rules
        && (!state.settings.subscriptions.is_empty()
            || !rules::files_present(&state.settings.singbox_dir()))
    {
        rules::spawn_background_download(
            state.settings.clone(),
            state.config_json.clone(),
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

fn spawn_singbox(
    engine: &std::path::Path,
    settings: &Settings,
    config_path: &std::path::Path,
    tun_enabled: bool,
) -> Result<Child> {
    singbox::spawn(
        engine,
        &settings.singbox_dir(),
        config_path,
        false,
        tun_enabled,
    )
}

/// After sing-box is up, download clash-rules through mixed proxy and restart (mesh hot reload is unsafe).
fn mesh_fetch_rules_restart_singbox(
    settings: &Settings,
    engine: &std::path::Path,
    config_path: &std::path::Path,
    tun_enabled: bool,
    child: &mut Child,
    config_json: &Arc<RwLock<String>>,
) -> Result<()> {
    eprintln!("mesh: fetching clash-rules via local proxy (sing-box is up)…");
    rules::download_all(settings)?;
    let base = singbox::builder::build_config(settings, true)?;
    let json = mixin::merge_config(&base, settings)?;
    fs::write(config_path, &json)
        .with_context(|| format!("writing {}", config_path.display()))?;
    *config_json.write().expect("config lock") = json;
    eprintln!("config updated with clash-rules; restarting sing-box…");
    assets::terminate_process(child.id());
    let _ = child
        .wait()
        .context("waiting for sing-box before rules restart")?;
    *child = spawn_singbox(engine, settings, config_path, tun_enabled)?;
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
    table.insert("wireguard_listen".into(), "127.0.0.1:51820".into());
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

pub fn validate(settings: &Settings) -> Result<()> {
    let flags = settings.stack;
    if flags.mesh {
        let mesh = settings
            .mesh
            .as_ref()
            .context("--mesh requires a [mesh] section in zay.toml")?;
        let routes = mesh.mesh_routes.as_deref().unwrap_or(&[]);
        if routes.is_empty() {
            bail!(
                "[mesh].mesh_routes is required (e.g. [\"10.126.126.0/24\"]) so sing-box routes mesh traffic to easytier-wg"
            );
        }
        if mesh.ipv4.as_deref().unwrap_or("").trim().is_empty() {
            eprintln!(
                "warn: [mesh].ipv4 unset — use a fixed virtual address per node (e.g. 10.126.126.10/24)"
            );
        }
        if mesh.peers.as_deref().is_none_or(|p| p.is_empty())
            && mesh.listeners.as_deref().is_none_or(|l| l.is_empty())
        {
            bail!(
                "[mesh] needs at least one peer or listener to join the EasyTier network"
            );
        }
        if !flags.tun && !mesh::is_hub(mesh) {
            bail!(
                "--mesh requires sing-box TUN on client nodes (Mac/Linux); omit --no-tun. \
                 Hub/relay nodes with [mesh].listeners skip TUN automatically."
            );
        }
        mesh::warn_mesh_role(mesh);
    }
    Ok(())
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
    }
}
