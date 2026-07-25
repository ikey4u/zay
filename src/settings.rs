use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use toml::Value as TomlValue;

use crate::{ProxyOpts, bootstrap::proxy};

pub const ZAY_TOML_FILE: &str = "zay.toml";
/// Sing-box runtime home (`config.json`, rule-sets, cache, …).
pub const SINGBOX_DIR: &str = "singbox";

pub fn default_zay_toml() -> &'static str {
    include_str!("../assets/config/template.toml")
}

/// EasyTier mesh section in `zay.toml` (see `docs/stack.md`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeshConfig {
    #[serde(default)]
    pub enabled: bool,
    pub role: MeshRole,
    pub instance_name: Option<String>,
    pub network_name: String,
    pub network_secret: String,
    pub dhcp: Option<bool>,
    pub ipv4: Option<String>,
    pub listeners: Option<Vec<String>>,
    pub peers: Option<Vec<String>>,
    pub proxy_networks: Option<Vec<String>>,
    /// Zay-only: mesh CIDRs routed to EasyTier WireGuard endpoint in the proxy.
    pub mesh_routes: Option<Vec<String>>,
    /// Local WireGuard portal listen (`host:port`). Default `127.0.0.1:51820` when mesh runs with proxy.
    pub wireguard_listen: Option<String>,
    /// Portal client CIDR (EasyTier `vpn_portal_config.client_cidr`).
    pub wireguard_client_cidr: Option<String>,
    /// Proxy WireGuard endpoint interface address (defaults to `[mesh].ipv4`).
    pub wireguard_client_address: Option<String>,
}

fn derive_node_mesh_routes(mesh: &mut Option<MeshConfig>) -> Result<()> {
    let Some(mesh) = mesh.as_mut() else {
        return Ok(());
    };
    if !mesh.enabled
        || mesh.role != MeshRole::Node
        || mesh
            .mesh_routes
            .as_ref()
            .is_some_and(|routes| !routes.is_empty())
    {
        return Ok(());
    }
    let Some(cidr) = mesh.ipv4.as_deref() else {
        return Ok(());
    };
    let (address, prefix) = cidr.split_once('/').with_context(|| {
        format!("proxy.mesh.ipv4 must use CIDR notation, got {cidr:?}")
    })?;
    let address: Ipv4Addr = address
        .parse()
        .with_context(|| format!("invalid proxy.mesh.ipv4 address {cidr:?}"))?;
    let prefix: u32 = prefix
        .parse()
        .with_context(|| format!("invalid proxy.mesh.ipv4 prefix {cidr:?}"))?;
    if prefix > 32 {
        bail!("invalid proxy.mesh.ipv4 prefix {prefix}: must be <= 32");
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    mesh.mesh_routes = Some(vec![format!(
        "{}/{}",
        Ipv4Addr::from(u32::from(address) & mask),
        prefix
    )]);
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
struct ZayFile {
    proxy: PersistentProxyFile,
    http: Vec<PersistentHttpFile>,
    fwd: Vec<PersistentFwdFile>,
    ssh: Vec<PersistentSshFile>,
}

/// Configuration of the persistent proxy started by `zay` / `zay service start`.
///
/// The existing `zay run proxy …` command remains an explicit, foreground override. This
/// section is deliberately separate from the generated proxy configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct PersistentProxyFile {
    pub enabled: bool,
    pub subscriptions: Vec<String>,
    pub gateway: bool,
    pub mixed_port: Option<u16>,
    pub update_interval: Option<u64>,
    pub health_check_url: Option<String>,
    pub log_level: Option<String>,
    pub tun: PersistentTunFile,
    /// Inline proxy used to fetch subscriptions before normal proxy routes exist.
    pub bootstrap: Option<TomlValue>,
    pub mesh: Option<MeshConfig>,
    pub mixin: Option<String>,
    pub domain_rule: Vec<DomainRuleFile>,
}

/// A domain suffix set routed through a dedicated proxy candidate group.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct DomainRuleFile {
    pub name: String,
    pub by_suffix: Vec<String>,
    pub outbounds: Vec<String>,
    pub health_check_url: Option<String>,
    pub interval: Option<u64>,
    pub tolerance: Option<u16>,
}

/// Persistent proxy TUN configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct PersistentTunFile {
    pub enabled: bool,
    pub exclude_routes: Vec<String>,
}

impl Default for PersistentTunFile {
    fn default() -> Self {
        Self {
            enabled: true,
            exclude_routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PersistentHttpFile {
    pub name: Option<String>,
    pub enabled: bool,
    pub root: Option<PathBuf>,
    pub listen: Option<std::net::SocketAddr>,
    pub spa: bool,
    pub cors: bool,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
}

impl Default for PersistentHttpFile {
    fn default() -> Self {
        Self {
            name: None,
            enabled: false,
            root: None,
            listen: None,
            spa: false,
            cors: false,
            cert: None,
            key: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct PersistentFwdFile {
    pub name: Option<String>,
    pub enabled: bool,
    pub to: String,
    pub from: String,
    pub token: Option<String>,
    pub verbose: u8,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct PersistentSshFile {
    pub name: Option<String>,
    pub enabled: bool,
    pub ssh_host: String,
    pub local_forwards: Vec<String>,
    pub remote_forwards: Vec<String>,
    pub proxy_jump: Vec<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub identity: Option<String>,
    pub port: Option<u16>,
    pub strict_host_keys: bool,
}

/// Fully resolved configuration for the unified persistent runner.
#[derive(Debug, Clone)]
pub struct PersistentConfig {
    pub data_dir: PathBuf,
    pub toml_path: PathBuf,
    pub stack: PersistentProxyFile,
    pub mesh: Option<MeshConfig>,
    pub http: Vec<PersistentHttpFile>,
    pub fwd: Vec<PersistentFwdFile>,
    pub ssh: Vec<PersistentSshFile>,
}

impl Default for ZayFile {
    fn default() -> Self {
        Self {
            proxy: PersistentProxyFile::default(),
            http: Vec::new(),
            fwd: Vec::new(),
            ssh: Vec::new(),
        }
    }
}

/// Single proxy node for bootstrapping subscription download (see `proxy-providers.*.proxy`).
#[derive(Debug, Clone)]
pub struct BootstrapProxy {
    pub name: String,
    pub proxy: Value,
}

/// `[proxy.mesh].role` and `zay run proxy --mesh <relay|node>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MeshRole {
    /// Public rendezvous only: no virtual mesh IP, no WG portal.
    Relay,
    /// Full mesh member: virtual IP, WG portal, proxy routes `mesh_routes`.
    Node,
}

/// Flags passed to `zay run proxy`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StackFlags {
    pub mesh: Option<MeshRole>,
    pub gateway: bool,
    pub tun: bool,
    /// Do not download Loyalsoldier clash-rules from the network.
    pub no_rules: bool,
}

impl StackFlags {
    pub fn mesh_enabled(&self) -> bool {
        self.mesh.is_some()
    }

    pub fn is_mesh_relay(&self) -> bool {
        self.mesh == Some(MeshRole::Relay)
    }

    pub fn is_mesh_node(&self) -> bool {
        self.mesh == Some(MeshRole::Node)
    }
}

#[derive(Clone)]
pub struct Settings {
    pub subscriptions: Vec<String>,
    pub data_dir: PathBuf,
    pub mixed_port: u16,
    pub allow_lan: bool,
    pub tun: bool,
    pub log_level: String,
    pub health_check_url: String,
    pub update_interval: u64,
    pub tun_exclude_routes: Vec<String>,
    /// Inline JSON mixin from `[proxy].mixin`.
    pub proxy_mixin: Option<String>,
    pub bootstrap_proxy: Option<BootstrapProxy>,
    pub domain_rule: Vec<DomainRuleFile>,
    pub mesh: Option<MeshConfig>,
    pub stack: StackFlags,
}

impl MeshConfig {
    pub fn is_relay(&self) -> bool {
        self.role == MeshRole::Relay
    }

    pub fn is_node(&self) -> bool {
        self.role == MeshRole::Node
    }
}

impl Settings {
    pub fn mesh_is_relay(&self) -> bool {
        self.stack.mesh_enabled()
            && self.mesh.as_ref().is_some_and(MeshConfig::is_relay)
    }

    pub fn mesh_is_node(&self) -> bool {
        self.stack.mesh_enabled()
            && self.mesh.as_ref().is_some_and(MeshConfig::is_node)
    }

    /// Directory passed to the proxy runtime.
    pub fn singbox_dir(&self) -> PathBuf {
        self.data_dir.join(SINGBOX_DIR)
    }

    pub fn config_path(&self) -> PathBuf {
        self.singbox_dir().join("config.json")
    }

    /// Mihomo `proxy-providers` name for subscription at `index` (`sub0`, `sub1`, …).
    pub fn subscription_provider_id(index: usize) -> String {
        format!("sub{index}")
    }

    pub fn subscription_provider_ids(&self) -> Vec<String> {
        (0..self.subscriptions.len())
            .map(Self::subscription_provider_id)
            .collect()
    }

    pub fn subscription_cache_path(&self, index: usize) -> PathBuf {
        self.singbox_dir()
            .join("providers")
            .join(format!("sub{index}.yaml"))
    }

    /// Prefix applied to every node from `proxy-providers.sub{i}` (via Mihomo `override`).
    pub fn subscription_name_prefix(index: usize) -> String {
        format!("sub{index}-")
    }
}

#[cfg(unix)]
fn home_for_user(username: &str) -> Option<PathBuf> {
    use std::ffi::CString;

    let name = CString::new(username).ok()?;
    unsafe {
        let entry = libc::getpwnam(name.as_ptr());
        if entry.is_null() {
            return None;
        }
        let home = std::ffi::CStr::from_ptr((*entry).pw_dir).to_str().ok()?;
        Some(PathBuf::from(home))
    }
}

/// When running under `sudo`, use the invoking user's home (not `/root`).
#[cfg(unix)]
pub fn sudo_invoker_home() -> Option<PathBuf> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let user = std::env::var("SUDO_USER").ok()?;
    if user == "root" || user.is_empty() {
        return None;
    }
    home_for_user(&user)
}

#[cfg(not(unix))]
pub fn sudo_invoker_home() -> Option<PathBuf> {
    None
}

fn xdg_config_home(home: &Path) -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
}

pub fn default_data_dir() -> PathBuf {
    if let Some(home) = sudo_invoker_home() {
        return xdg_config_home(&home).join("zay");
    }
    dirs_next::config_dir()
        .map(|p| p.join("zay"))
        .unwrap_or_else(|| std::env::temp_dir().join("zay"))
}

pub fn default_cache_dir() -> PathBuf {
    if let Some(home) = sudo_invoker_home() {
        let cache = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cache"));
        return cache.join("zay");
    }
    dirs_next::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("zay")
}

fn load_zay_toml(path: &Path) -> Result<ZayFile> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

pub fn stack_config_paths(
    data_dir: Option<&Path>,
    config: Option<&Path>,
) -> (PathBuf, PathBuf) {
    let data_dir = data_dir
        .map(Path::to_path_buf)
        .or_else(|| config.map(config_parent_dir))
        .unwrap_or_else(default_data_dir);
    let toml_path = config
        .map(Path::to_path_buf)
        .unwrap_or_else(|| data_dir.join(ZAY_TOML_FILE));
    (data_dir, toml_path)
}

fn config_parent_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn ensure_zay_toml(data_dir: &Path, toml_path: &Path) -> Result<()> {
    fs::create_dir_all(data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;
    if toml_path.is_file() {
        return Ok(());
    }
    fs::write(toml_path, default_zay_toml())
        .with_context(|| format!("writing {}", toml_path.display()))?;
    eprintln!("created default config at {}", toml_path.display());
    Ok(())
}

/// Load the configuration used by the no-subcommand persistent runner.
///
/// A configured mesh implies that the stack runtime must be started too: EasyTier is
/// hosted by Zay and the current implementation uses the same proxy lifecycle.
/// `[proxy].enabled` is the explicit switch for persistent proxy deployments.
pub fn load_persistent_config(
    data_dir: Option<&Path>,
    config: Option<&Path>,
) -> Result<PersistentConfig> {
    let (data_dir, toml_path) = stack_config_paths(data_dir, config);
    ensure_zay_toml(&data_dir, &toml_path)?;
    let mut file = load_zay_toml(&toml_path)?;
    derive_node_mesh_routes(&mut file.proxy.mesh)?;
    let mesh = file.proxy.mesh.clone().filter(|mesh| mesh.enabled);
    Ok(PersistentConfig {
        data_dir,
        toml_path,
        stack: file.proxy,
        mesh,
        http: file.http,
        fwd: file.fwd,
        ssh: file.ssh,
    })
}

fn resolve_bootstrap_proxy(
    raw: &TomlValue,
    toml_path: &Path,
    data_dir: &Path,
) -> Result<BootstrapProxy> {
    match raw {
        TomlValue::String(rel) => {
            let path = PathBuf::from(rel);
            let path = if path.is_absolute() {
                path
            } else {
                toml_path.parent().unwrap_or(data_dir).join(path)
            };
            proxy::load_from_yaml_file(&path)
        }
        TomlValue::Table(table) => proxy::load_from_toml_table(table),
        _ => bail!(
            "proxy.bootstrap must be a file path string or a [proxy.bootstrap] table"
        ),
    }
}

pub fn resolve_stack(cli: &ProxyOpts, stack: StackFlags) -> Result<Settings> {
    resolve_inner(cli, stack)
}

/// Resolve a one-off `zay run proxy` invocation without accessing zay.toml.
pub fn resolve_transient_stack(
    cli: &ProxyOpts,
    stack: StackFlags,
    mesh: Option<MeshConfig>,
) -> Settings {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let data_dir = std::env::temp_dir()
        .join(format!("zay-run-{}-{nonce}", std::process::id()));
    Settings {
        subscriptions: cli.subscriptions.clone(),
        data_dir,
        mixed_port: cli.mixed_port.unwrap_or(7890),
        allow_lan: stack.gateway,
        tun: stack.tun,
        log_level: cli.log_level.clone().unwrap_or_else(|| "info".into()),
        health_check_url: cli
            .health_check_url
            .clone()
            .unwrap_or_else(|| "http://cp.cloudflare.com/generate_204".into()),
        update_interval: cli.update_interval.unwrap_or(3600),
        tun_exclude_routes: cli.tun_exclude_routes.clone(),
        proxy_mixin: None,
        bootstrap_proxy: None,
        domain_rule: Vec::new(),
        mesh,
        stack,
    }
}

fn resolve_inner(cli: &ProxyOpts, stack: StackFlags) -> Result<Settings> {
    let (data_dir, toml_path) =
        stack_config_paths(cli.data_dir.as_deref(), cli.config.as_deref());

    ensure_zay_toml(&data_dir, &toml_path)?;
    let mut file = load_zay_toml(&toml_path)?;
    if stack.mesh.is_some() {
        if let Some(mesh) = file.proxy.mesh.as_mut() {
            mesh.enabled = true;
        }
    }
    derive_node_mesh_routes(&mut file.proxy.mesh)?;

    let proxy_mixin = file.proxy.mixin.clone();

    let bootstrap_proxy = if let Some(path) = &cli.bootstrap_proxy {
        Some(proxy::load_from_yaml_file(path)?)
    } else if let Some(raw) = &file.proxy.bootstrap {
        Some(resolve_bootstrap_proxy(raw, &toml_path, &data_dir)?)
    } else {
        None
    };

    let allow_lan = stack.gateway;
    let tun = stack.tun;
    let tun_exclude_routes = cli.tun_exclude_routes.clone();

    Ok(Settings {
        subscriptions: if cli.subscriptions.is_empty() {
            file.proxy.subscriptions.clone()
        } else {
            cli.subscriptions.clone()
        },
        data_dir,
        mixed_port: cli.mixed_port.or(file.proxy.mixed_port).unwrap_or(7890),
        allow_lan,
        tun,
        log_level: cli
            .log_level
            .clone()
            .or(file.proxy.log_level.clone())
            .unwrap_or_else(|| "info".into()),
        health_check_url: cli
            .health_check_url
            .clone()
            .or(file.proxy.health_check_url.clone())
            .unwrap_or_else(|| "http://cp.cloudflare.com/generate_204".into()),
        update_interval: cli
            .update_interval
            .or(file.proxy.update_interval)
            .unwrap_or(3600),
        tun_exclude_routes,
        proxy_mixin,
        bootstrap_proxy,
        domain_rule: file.proxy.domain_rule,
        mesh: file.proxy.mesh.filter(|mesh| mesh.enabled),
        stack,
    })
}

fn is_invalid_subscription_body(raw: &str) -> bool {
    let trimmed = raw.trim_start();
    trimmed.starts_with('<')
        || trimmed.starts_with("<!doctype")
        || trimmed.starts_with("<!DOCTYPE")
}

pub fn cleanup_stale_subscription_cache(runtime_dir: &Path, sub_count: usize) {
    let providers = runtime_dir.join("providers");
    let mut paths: Vec<PathBuf> = (0..sub_count)
        .map(|i| providers.join(format!("sub{i}.yaml")))
        .collect();
    let legacy = providers.join("subscription.yaml");
    if sub_count == 1 {
        paths.push(legacy);
    }
    for cache in paths {
        let Ok(raw) = fs::read_to_string(&cache) else {
            continue;
        };
        if is_invalid_subscription_body(&raw) {
            let _ = fs::remove_file(&cache);
            eprintln!(
                "removed invalid subscription cache at {}",
                cache.display()
            );
        }
    }

    if let Ok(entries) = fs::read_dir(&providers) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(idx_str) = name
                .strip_prefix("sub")
                .and_then(|s| s.strip_suffix(".yaml"))
            else {
                continue;
            };
            let Ok(idx) = idx_str.parse::<usize>() else {
                continue;
            };
            if idx >= sub_count {
                if fs::remove_file(&path).is_ok() {
                    eprintln!(
                        "removed orphan subscription cache at {}",
                        path.display()
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn default_config_has_no_legacy_proxy_configuration() {
        let parsed: ZayFile = toml::from_str(&default_zay_toml()).unwrap();

        assert!(!default_zay_toml().contains("[mihomo]"));
        assert!(parsed.proxy.mixin.is_none());
    }

    #[test]
    fn transient_proxy_uses_system_temp_directory_without_toml() {
        let settings = resolve_transient_stack(
            &ProxyOpts::default(),
            StackFlags {
                mesh: None,
                gateway: false,
                tun: false,
                no_rules: false,
            },
            None,
        );

        assert!(settings.data_dir.starts_with(std::env::temp_dir()));
        assert!(!settings.data_dir.join(ZAY_TOML_FILE).exists());
        assert!(settings.proxy_mixin.is_none());
        assert!(settings.bootstrap_proxy.is_none());
    }

    #[test]
    fn config_path_uses_current_dir_for_bare_config_file() {
        let (data_dir, toml_path) =
            stack_config_paths(None, Some(Path::new("zay.toml")));

        assert_eq!(data_dir, PathBuf::from("."));
        assert_eq!(toml_path, PathBuf::from("zay.toml"));
    }

    #[test]
    fn explicit_data_dir_and_config_are_preserved() {
        let (data_dir, toml_path) = stack_config_paths(
            Some(Path::new("/tmp/zay-data")),
            Some(Path::new("/tmp/zay-config/zay.toml")),
        );

        assert_eq!(data_dir, PathBuf::from("/tmp/zay-data"));
        assert_eq!(toml_path, PathBuf::from("/tmp/zay-config/zay.toml"));
    }

    #[test]
    fn parses_persistent_components() {
        let raw = r#"
[proxy]
enabled = true
subscriptions = ["https://sub.example"]

[proxy.tun]
enabled = false

[proxy.mesh]
role = "node"
network_name = "test"
network_secret = "secret"

[proxy.bootstrap]
name = "Bootstrap"
type = "socks5"
server = "127.0.0.1"
port = 1080

[[proxy.domain_rule]]
name = "cursor"
by_suffix = ["cursor.com", "cursor.sh"]
outbounds = ["sg-1", "sg-2"]
interval = 60

[[http]]
enabled = true
root = "/srv/site"
listen = "127.0.0.1:8081"

[[fwd]]
enabled = true
from = "tcp://127.0.0.1:3307"
to = "tcp://db.internal:3306"

[[ssh]]
enabled = true
ssh_host = "bastion"
local_forwards = ["3308:db.internal:3306"]
"#;
        let parsed: ZayFile = toml::from_str(raw).unwrap();
        assert!(parsed.proxy.enabled);
        assert_eq!(parsed.proxy.subscriptions, ["https://sub.example"]);
        assert!(!parsed.proxy.tun.enabled);
        assert_eq!(parsed.proxy.mesh.unwrap().role, MeshRole::Node);
        assert!(matches!(parsed.proxy.bootstrap, Some(TomlValue::Table(_))));
        assert_eq!(parsed.proxy.domain_rule[0].name, "cursor");
        assert_eq!(parsed.proxy.domain_rule[0].outbounds, ["sg-1", "sg-2"]);
        assert_eq!(parsed.http.len(), 1);
        assert_eq!(parsed.fwd[0].to, "tcp://db.internal:3306");
        assert_eq!(parsed.ssh[0].ssh_host, "bastion");
    }

    #[test]
    fn derives_node_mesh_routes_from_ipv4() {
        let mut mesh = Some(MeshConfig {
            enabled: true,
            role: MeshRole::Node,
            instance_name: None,
            network_name: "test".into(),
            network_secret: "secret".into(),
            dhcp: None,
            ipv4: Some("10.126.126.3/24".into()),
            listeners: None,
            peers: Some(vec!["tcp://relay.example:11010".into()]),
            proxy_networks: None,
            mesh_routes: None,
            wireguard_listen: None,
            wireguard_client_cidr: None,
            wireguard_client_address: None,
        });
        derive_node_mesh_routes(&mut mesh).unwrap();
        assert_eq!(
            mesh.unwrap().mesh_routes,
            Some(vec!["10.126.126.0/24".into()])
        );
    }

    #[test]
    fn cleanup_removes_orphan_provider_caches() {
        let dir = std::env::temp_dir()
            .join(format!("zay-test-{}", std::process::id()));
        let providers = dir.join("providers");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&providers).unwrap();
        fs::write(providers.join("sub0.yaml"), "proxies: []\n").unwrap();
        fs::write(providers.join("sub2.yaml"), "proxies: []\n").unwrap();
        cleanup_stale_subscription_cache(&dir, 1);
        assert!(providers.join("sub0.yaml").is_file());
        assert!(!providers.join("sub2.yaml").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
