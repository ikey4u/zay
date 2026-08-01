//! `zay run proxy` — sing-box TUN + optional EasyTier mesh (WireGuard portal).

pub mod controller;
pub mod easytier;
pub mod log_buf;
pub mod mesh;

use std::{fs, path::PathBuf, sync::Arc, thread, time::Duration};

use anyhow::{Context, Result, bail};
use clap::Args;
use serde::{Deserialize, Serialize};
use toml_edit::{Array, DocumentMut, Item, Table, Value};

use crate::{
    ProxyOpts, api,
    bootstrap::singbox as bootstrap,
    settings::{
        self as zay_settings, MeshConfig, MeshRole, Settings, StackFlags,
        default_zay_toml,
    },
    singbox::{self, assets, rules},
};

/// CLI value for `--mesh <relay|node>`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum MeshCliMode {
    /// Public rendezvous / optional hub; sing-box TUN is forced off.
    Relay,
    /// Join the virtual network (requires `--mesh-ip`; EasyTier creates a kernel TUN)
    Node,
}

impl From<MeshCliMode> for MeshRole {
    fn from(m: MeshCliMode) -> Self {
        match m {
            MeshCliMode::Relay => MeshRole::Relay,
            MeshCliMode::Node => MeshRole::Node,
        }
    }
}

const LONG_ABOUT: &str = "\
Run the network stack: sing-box (mixed proxy + optional system TUN) and optional EasyTier mesh.

With -s/--proxy, Loyalsoldier rules send GFW domains to Proxy and CN/private to direct. \
With --mesh node, EasyTier owns a kernel TUN for mesh CIDRs (sing-box excludes them). \
With --mesh relay, this host is a rendezvous (TUN off; optional --mesh-ip hub).";

#[derive(Args, Debug)]
#[command(long_about = LONG_ABOUT)]
pub struct StackCli {
    /// Print an equivalent persistent-service TOML configuration and exit
    #[arg(long)]
    pub dump_config: bool,

    #[command(flatten, next_help_heading = "Runtime options")]
    pub common: ProxyOpts,

    /// EasyTier role: `relay` (rendezvous / optional hub, TUN off) or `node` (join mesh)
    #[arg(long, value_name = "relay|node", help_heading = "Stack options")]
    pub mesh: Option<MeshCliMode>,

    /// Bind the mixed proxy port on LAN (0.0.0.0) so other hosts/VMs can use it
    #[arg(long, help_heading = "Stack options")]
    pub gateway: bool,

    /// Mesh credentials (`user` = network name, `password` = network secret).
    ///
    /// Relay: `user:password` (listens 0.0.0.0:11010 TCP+UDP; `@host:port` ignored).
    /// Optional `--mesh-ip 10.x.x.1/24` joins the virtual net as hub (recommended).
    /// Node: `user:password@tcp://relay:port` (peer to dial; UDP also ok).
    #[arg(
        long = "mesh-auth",
        value_name = "USER:PASS[@tcp://HOST:PORT]",
        help_heading = "Mesh"
    )]
    pub mesh_auth: Option<String>,

    /// This node's virtual mesh IPv4 CIDR (required for `--mesh node`; recommended for hub `relay`)
    #[arg(long = "mesh-ip", value_name = "IP/MASK", help_heading = "Mesh")]
    pub mesh_ip: Option<String>,
}

pub fn run(cli: StackCli) -> Result<()> {
    let flags = StackFlags {
        mesh: cli.mesh.map(MeshRole::from),
        gateway: cli.gateway,
        tun: !cli.common.no_tun,
        no_rules: false,
    };
    let mesh = flags
        .mesh
        .map(|role| build_mesh_config_from_cli(&cli, role))
        .transpose()?;
    if cli.dump_config {
        print!("{}", dump_config(&cli, mesh)?);
        return Ok(());
    }
    let prepared =
        bootstrap::prepare_transient_stack(&cli.common, flags, mesh)?;
    log_mesh_effective_config(&prepared.settings);

    eprintln!("runtime dir → {}", prepared.settings.data_dir.display());
    eprintln!(
        "sing-box dir → {}",
        prepared.settings.singbox_dir().display()
    );

    let mesh_started = if flags.mesh_enabled() {
        let cfg = prepared
            .settings
            .mesh
            .as_ref()
            .context("[mesh] missing in zay.toml")?;
        if cfg.is_relay() {
            eprintln!(
                "mesh relay: sing-box TUN disabled (EasyTier forward-only; SSH stays on physical NIC)"
            );
        } else {
            let mesh_proxy = !prepared.settings.subscriptions.is_empty();
            if mesh_proxy {
                eprintln!(
                    "mesh client + proxy: full TUN for gfw/Proxy; EasyTier TUN owns mesh_routes \
                     (sing-box excludes them); control plane stays on physical NIC"
                );
            } else if crate::singbox::tun_route::mesh_only_no_proxy(
                &prepared.settings,
            ) {
                eprintln!(
                    "mesh client: EasyTier TUN owns mesh_routes; sing-box TUN disabled (no proxy)"
                );
                if let Some(routes) = prepared
                    .settings
                    .mesh
                    .as_ref()
                    .and_then(|m| m.mesh_routes.as_ref())
                {
                    eprintln!(
                        "mesh client: EasyTier routes → {}",
                        routes.join(", ")
                    );
                }
            } else if prepared.settings.stack.gateway {
                eprintln!(
                    "mesh client: --gateway set → full TUN capture (not SSH-safe to relay)"
                );
            }
        }
        if cfg.is_node() {
            eprintln!(
                "mesh tip: reach a peer service with `curl http://<mesh-ip>:<port>/` from another node; \
                 the server must run `zay run proxy --mesh node` and listen on 0.0.0.0 or 127.0.0.1"
            );
        }
        if std::env::var("ZAY_EASYTIER_DEBUG").is_err() {
            eprintln!(
                "tip: export ZAY_EASYTIER_DEBUG=1 for verbose EasyTier listener logs"
            );
        }
        easytier::start_for_singbox(cfg, &prepared.settings.data_dir)?;
        if cfg.is_relay() {
            eprintln!(
                "mesh relay: when clients connect, this node should show 2+ remote peers; \
                 only 1 peer usually means wrong network_name/network_secret on a client"
            );
            crate::singbox::tun_route::wait_for_mesh_listeners(
                cfg,
                std::time::Duration::from_secs(30),
            )
            .with_context(|| {
                "EasyTier relay listeners not ready — clients cannot connect on :11010"
                    .to_string()
            })?;
        } else if cfg.is_node() {
            // Match relay listener wait; native TUN address can take a few seconds.
            easytier::wait_for_virtual_ip(std::time::Duration::from_secs(30))
                .context("EasyTier mesh TUN not ready")?;
            eprintln!("mesh node: EasyTier virtual IP ready");
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

    let state = Arc::new(api::AppState::from(prepared));

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
        state.settings.mixed_port,
        flags.gateway,
        flags
            .mesh
            .map(|m| format!("{m:?}"))
            .unwrap_or_else(|| "off".into()),
        state.tun_enabled,
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
        None,
    ) {
        Ok(child) => child,
        Err(e) => {
            if mesh_started {
                let _ = easytier::stop_all();
            }
            return Err(e);
        }
    };

    if let Some(stdout) = child.take_stdout() {
        assets::pipe_logs(stdout);
    }
    if let Some(stderr) = child.take_stderr() {
        assets::pipe_logs(stderr);
    }

    if state.tun_enabled {
        let settings = state.settings.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(3));
            singbox::tun_route::linux_register_tun_dns(&settings);
        });
    }

    if !flags.no_rules {
        rules::spawn_background_download(
            state.settings.clone(),
            state.config_json.clone(),
        );
    }

    let pid = child.id();
    ctrlc::set_handler(move || {
        if flags.mesh_enabled() {
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

fn dump_config(cli: &StackCli, mesh: Option<MeshConfig>) -> Result<String> {
    #[derive(Serialize)]
    struct Config {
        proxy: zay_settings::PersistentProxyFile,
    }

    toml::to_string_pretty(&Config {
        proxy: zay_settings::PersistentProxyFile {
            enabled: true,
            subscriptions: cli.common.subscriptions.clone(),
            gateway: cli.gateway,
            mixed_port: Some(cli.common.mixed_port.unwrap_or(7890)),
            update_interval: Some(cli.common.update_interval.unwrap_or(3600)),
            health_check_url: Some(
                cli.common.health_check_url.clone().unwrap_or_else(|| {
                    "http://cp.cloudflare.com/generate_204".into()
                }),
            ),
            log_level: Some(
                cli.common
                    .log_level
                    .clone()
                    .unwrap_or_else(|| "info".into()),
            ),
            tun: zay_settings::PersistentTunFile {
                enabled: !cli.common.no_tun,
                exclude_routes: cli.common.tun_exclude_routes.clone(),
            },
            bootstrap: None,
            mesh,
            mixin: None,
            domain_rule: Vec::new(),
        },
    })
    .context("serializing proxy service configuration")
}

pub(crate) fn spawn_singbox(
    engine: &std::path::Path,
    settings: &Settings,
    config_path: &std::path::Path,
    tun_enabled: bool,
    sudo_password: Option<&str>,
) -> Result<crate::singbox::assets::ManagedChild> {
    singbox::spawn(
        engine,
        &settings.singbox_dir(),
        config_path,
        false,
        tun_enabled,
        sudo_password,
    )
}

pub(crate) fn ensure_stack_config_exists(common: &ProxyOpts) -> Result<()> {
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

fn zay_toml_has_mesh(toml_path: &PathBuf) -> Result<bool> {
    if !toml_path.is_file() {
        return Ok(false);
    }
    let raw = fs::read_to_string(toml_path)
        .with_context(|| format!("reading {}", toml_path.display()))?;
    let parsed: toml::Value = toml::from_str(&raw)
        .with_context(|| format!("parsing {}", toml_path.display()))?;
    Ok(parsed
        .get("proxy")
        .and_then(toml::Value::as_table)
        .and_then(|proxy| proxy.get("mesh"))
        .is_some())
}

fn load_mesh_from_toml(toml_path: &PathBuf) -> Result<MeshConfig> {
    let raw = fs::read_to_string(toml_path)
        .with_context(|| format!("reading {}", toml_path.display()))?;
    #[derive(Deserialize)]
    struct Root {
        proxy: Proxy,
    }
    #[derive(Deserialize)]
    struct Proxy {
        mesh: MeshConfig,
    }
    let root: Root = toml::from_str(&raw).with_context(|| {
        format!("parsing [proxy.mesh] in {}", toml_path.display())
    })?;
    Ok(root.proxy.mesh)
}

/// Apply `--mesh-auth` / `--mesh-ip` onto an existing `[mesh]` (CLI wins over file).
fn apply_mesh_cli_overrides(
    mut mesh: MeshConfig,
    cli: &StackCli,
    role: MeshRole,
) -> Result<(MeshConfig, bool)> {
    let mut changed = false;

    if let Some(auth_raw) = cli.mesh_auth.as_deref() {
        let auth = mesh::parse_mesh_auth(auth_raw, role)?;
        if mesh.network_name != auth.network_name {
            mesh.network_name = auth.network_name;
            changed = true;
        }
        if mesh.network_secret != auth.network_secret {
            mesh.network_secret = auth.network_secret;
            changed = true;
        }
        if role == MeshRole::Node && !auth.endpoint.is_empty() {
            let want = vec![auth.endpoint];
            if mesh.peers.as_deref() != Some(want.as_slice()) {
                mesh.peers = Some(want);
                changed = true;
            }
        }
    }

    if role == MeshRole::Node {
        if let Some(ipv4) = cli
            .mesh_ip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let routes = vec![ipv4_network_cidr(ipv4)?];
            if mesh.ipv4.as_deref().map(str::trim) != Some(ipv4) {
                mesh.ipv4 = Some(ipv4.to_string());
                changed = true;
            }
            if mesh.mesh_routes.as_deref() != Some(routes.as_slice()) {
                mesh.mesh_routes = Some(routes);
                changed = true;
            }
        }
    } else if role == MeshRole::Relay {
        if let Some(ipv4) = cli
            .mesh_ip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            && mesh.ipv4.as_deref().map(str::trim) != Some(ipv4)
        {
            mesh.ipv4 = Some(ipv4.to_string());
            changed = true;
        }
    }

    Ok((mesh, changed))
}

fn mesh_config_to_edit_table(mesh: &MeshConfig) -> Table {
    let mut t = Table::new();
    t.insert(
        "role",
        Item::Value(Value::from(match mesh.role {
            MeshRole::Relay => "relay",
            MeshRole::Node => "node",
        })),
    );
    if let Some(v) = &mesh.instance_name {
        t.insert("instance_name", Item::Value(Value::from(v.as_str())));
    }
    t.insert(
        "network_name",
        Item::Value(Value::from(mesh.network_name.as_str())),
    );
    t.insert(
        "network_secret",
        Item::Value(Value::from(mesh.network_secret.as_str())),
    );
    if let Some(v) = &mesh.ipv4 {
        t.insert("ipv4", Item::Value(Value::from(v.as_str())));
    }
    if let Some(v) = mesh.dhcp {
        t.insert("dhcp", Item::Value(Value::from(v)));
    }
    if let Some(listeners) = &mesh.listeners {
        let mut arr = Array::new();
        for l in listeners {
            arr.push(l.as_str());
        }
        t.insert("listeners", Item::Value(Value::Array(arr)));
    }
    if let Some(peers) = &mesh.peers {
        let mut arr = Array::new();
        for p in peers {
            arr.push(p.as_str());
        }
        t.insert("peers", Item::Value(Value::Array(arr)));
    }
    if let Some(cidrs) = &mesh.proxy_networks {
        let mut arr = Array::new();
        for c in cidrs {
            arr.push(c.as_str());
        }
        t.insert("proxy_networks", Item::Value(Value::Array(arr)));
    }
    if let Some(routes) = &mesh.mesh_routes {
        let mut arr = Array::new();
        for r in routes {
            arr.push(r.as_str());
        }
        t.insert("mesh_routes", Item::Value(Value::Array(arr)));
    }
    if let Some(v) = &mesh.wireguard_listen {
        t.insert("wireguard_listen", Item::Value(Value::from(v.as_str())));
    }
    if let Some(v) = &mesh.wireguard_client_cidr {
        t.insert(
            "wireguard_client_cidr",
            Item::Value(Value::from(v.as_str())),
        );
    }
    if let Some(v) = &mesh.wireguard_client_address {
        t.insert(
            "wireguard_client_address",
            Item::Value(Value::from(v.as_str())),
        );
    }
    t
}

fn write_mesh_section(toml_path: &PathBuf, mesh: &MeshConfig) -> Result<()> {
    let raw = if toml_path.is_file() {
        fs::read_to_string(toml_path)
            .with_context(|| format!("reading {}", toml_path.display()))?
    } else {
        String::new()
    };
    let mut doc: DocumentMut = if raw.trim().is_empty() {
        DocumentMut::new()
    } else {
        raw.parse::<DocumentMut>()
            .with_context(|| format!("parsing {}", toml_path.display()))?
    };
    if !doc["proxy"].is_table() {
        doc["proxy"] = Item::Table(Table::new());
    }
    doc["proxy"]["mesh"] = Item::Table(mesh_config_to_edit_table(mesh));
    fs::write(toml_path, doc.to_string())
        .with_context(|| format!("writing {}", toml_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(toml_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(toml_path, perms);
        }
    }
    Ok(())
}

fn build_mesh_config_from_cli(
    cli: &StackCli,
    role: MeshRole,
) -> Result<MeshConfig> {
    let auth_raw = cli.mesh_auth.as_deref().with_context(|| {
        let label = match role {
            MeshRole::Relay => "relay",
            MeshRole::Node => "node",
        };
        format!("--mesh-auth is required when creating [proxy.mesh] (see `zay run proxy --mesh {label}`)")
    })?;
    let auth = mesh::parse_mesh_auth(auth_raw, role)?;
    match role {
        MeshRole::Relay => {
            let ipv4 = cli
                .mesh_ip
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            Ok(MeshConfig {
                enabled: true,
                role,
                instance_name: Some("relay".into()),
                network_name: auth.network_name,
                network_secret: auth.network_secret,
                dhcp: None,
                ipv4: ipv4.map(str::to_string),
                listeners: Some(mesh::default_relay_listeners()),
                peers: None,
                proxy_networks: None,
                mesh_routes: None,
                wireguard_listen: ipv4.map(|_| "127.0.0.1:51820".into()),
                wireguard_client_cidr: None,
                wireguard_client_address: None,
            })
        }
        MeshRole::Node => {
            let ipv4 = cli.mesh_ip.as_deref().with_context(
                || "`zay run proxy --mesh node` requires --mesh-ip IP/MASK",
            )?;
            Ok(MeshConfig {
                enabled: true,
                role,
                instance_name: Some("zay".into()),
                network_name: auth.network_name,
                network_secret: auth.network_secret,
                dhcp: None,
                ipv4: Some(ipv4.to_string()),
                listeners: None,
                peers: Some(vec![auth.endpoint]),
                proxy_networks: None,
                mesh_routes: Some(vec![ipv4_network_cidr(ipv4)?]),
                // Node uses EasyTier kernel TUN; WG portal is relay-hub only.
                wireguard_listen: None,
                wireguard_client_cidr: None,
                wireguard_client_address: None,
            })
        }
    }
}

pub(crate) fn log_mesh_effective_config(settings: &Settings) {
    let Some(mesh) = settings.mesh.as_ref() else {
        return;
    };
    eprintln!(
        "mesh config: role={:?}, network_name={:?}, ipv4={}, peers={:?}, mesh_routes={:?}",
        mesh.role,
        mesh.network_name,
        mesh.ipv4.as_deref().unwrap_or("(none)"),
        mesh.peers.as_deref().unwrap_or(&[]),
        mesh.mesh_routes.as_deref().unwrap_or(&[]),
    );
    if mesh.is_node() {
        if let Some(routes) = mesh.mesh_routes.as_ref() {
            eprintln!(
                "mesh config: EasyTier TUN owns routes → {}",
                routes.join(", ")
            );
        }
    }
}

pub(crate) fn validate_mesh_cli(
    cli: &StackCli,
    flags: StackFlags,
) -> Result<()> {
    let Some(cli_role) = flags.mesh else {
        return Ok(());
    };
    let (_, toml_path) = stack_config_paths(&cli.common);
    if zay_toml_has_mesh(&toml_path)? {
        if let Some(auth_raw) = cli.mesh_auth.as_deref() {
            mesh::parse_mesh_auth(auth_raw, cli_role)?;
        }
        return Ok(());
    }
    let auth_raw = cli.mesh_auth.as_deref().with_context(|| {
        let hint = match cli_role {
            MeshRole::Relay => {
                "--mesh-auth user:password (optional --mesh-ip 10.x.1/24 for hub-style relay)"
            }
            MeshRole::Node => {
                "--mesh-auth user:password@tcp://host:port and --mesh-ip IP/MASK"
            }
        };
        format!(
            "persistent [proxy.mesh] configuration requires {hint} when it is missing in {}",
            toml_path.display()
        )
    })?;
    mesh::parse_mesh_auth(auth_raw, cli_role)?;
    match cli_role {
        MeshRole::Relay => {}
        MeshRole::Node => {
            if cli.mesh_ip.is_none() {
                bail!(
                    "persistent node mesh configuration requires --mesh-ip IP/MASK when creating [proxy.mesh]"
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn ensure_mesh_config_from_stack(
    cli: &StackCli,
    flags: StackFlags,
) -> Result<()> {
    let Some(role) = flags.mesh else {
        return Ok(());
    };

    let (data_dir, toml_path) = stack_config_paths(&cli.common);
    fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;

    if zay_toml_has_mesh(&toml_path)? {
        if cli.mesh_auth.is_none() && cli.mesh_ip.is_none() {
            return Ok(());
        }
        let mesh = load_mesh_from_toml(&toml_path)?;
        let (mesh, changed) = apply_mesh_cli_overrides(mesh, cli, role)?;
        if !changed {
            return Ok(());
        }
        write_mesh_section(&toml_path, &mesh)?;
        eprintln!(
            "updated [mesh] in {} from CLI (--mesh-auth / --mesh-ip override file)",
            toml_path.display()
        );
        return Ok(());
    }

    let mesh = build_mesh_config_from_cli(cli, role)?;
    write_mesh_section(&toml_path, &mesh)?;
    eprintln!("created [mesh] config in {}", toml_path.display());
    Ok(())
}

fn stack_config_paths(common: &ProxyOpts) -> (PathBuf, PathBuf) {
    zay_settings::stack_config_paths(
        common.data_dir.as_deref(),
        common.config.as_deref(),
    )
}

fn ipv4_network_cidr(cidr: &str) -> Result<String> {
    zay_settings::ipv4_network_cidr(cidr).with_context(|| {
        format!("--mesh-ip must be CIDR notation, got {cidr:?}")
    })
}

pub fn validate(settings: &Settings) -> Result<()> {
    let flags = settings.stack;
    let Some(cli_role) = flags.mesh else {
        return Ok(());
    };
    let mesh = settings
        .mesh
        .as_ref()
        .with_context(|| "--mesh requires a [mesh] section in zay.toml with role = \"relay\" or \"node\"")?;

    if mesh.role != cli_role {
        bail!(
            "[proxy.mesh].role = {:?} does not match `zay run proxy --mesh {}`",
            mesh.role,
            match cli_role {
                MeshRole::Relay => "relay",
                MeshRole::Node => "node",
            }
        );
    }

    match mesh.role {
        MeshRole::Relay => {
            if mesh.peers.as_ref().is_some_and(|p| !p.is_empty()) {
                bail!("[mesh].peers must be empty when role = \"relay\"");
            }
            if mesh.mesh_routes.as_ref().is_some_and(|r| !r.is_empty()) {
                bail!("[mesh].mesh_routes is only for role = \"node\"");
            }
            if mesh.ipv4.as_deref().unwrap_or("").trim().is_empty() {
                eprintln!(
                    "warn: relay has no [mesh].ipv4 — mesh traffic may not route; \
                     use --mesh-ip 10.x.1/24 on the VPS (hub-style relay)"
                );
            }
            if !mesh::has_mesh_listeners(mesh) {
                eprintln!(
                    "warn: [mesh].listeners unset on relay — EasyTier will use default {}",
                    mesh::DEFAULT_RELAY_LISTENERS.join(", ")
                );
            }
        }
        MeshRole::Node => {
            let routes = mesh.mesh_routes.as_deref().unwrap_or(&[]);
            if routes.is_empty() {
                bail!(
                    "[mesh].mesh_routes is required for role = \"node\" \
                     (set [mesh].ipv4 so routes can be derived, or set mesh_routes explicitly)"
                );
            }
            if mesh.ipv4.as_deref().unwrap_or("").trim().is_empty() {
                bail!(
                    "[mesh].ipv4 is required for role = \"node\" (e.g. 10.126.126.10/24)"
                );
            }
            if mesh.peers.as_deref().is_none_or(|p| p.is_empty())
                && !mesh::has_mesh_listeners(mesh)
            {
                bail!(
                    "[mesh].peers or [mesh].listeners required for role = \"node\""
                );
            }
            // Mesh-only: EasyTier owns the TUN; sing-box TUN is optional/off.
            // Mesh + subscription (or --gateway): sing-box TUN is required for proxy.
            if !flags.tun
                && !crate::singbox::tun_route::mesh_only_no_proxy(settings)
            {
                bail!(
                    "`zay run proxy --mesh node` with a subscription (or --gateway) \
                     requires sing-box TUN (omit --no-tun); mesh-only may use --no-tun"
                );
            }
            mesh::warn_mesh_role(mesh);
        }
    }

    let _ = easytier::to_easytier_toml(mesh)?;
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
