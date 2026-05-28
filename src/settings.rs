use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_yaml::Value;
use toml::Value as TomlValue;

use crate::{ProxyOpts, bootstrap::proxy};

pub const ZAY_TOML_FILE: &str = "zay.toml";
/// Mihomo runtime home under the Zay config directory (`config.yaml`, geo, ruleset, providers, …).
pub const MIHOMO_DIR: &str = "mihomo";

pub const DEFAULT_MIXIN: &str = r#"# =============================================================================
# [mihomo].mixin — 合并进 Zay 生成的 config.yaml（可选）
# =============================================================================
#
# 位置：zay.toml 中的 [mihomo].mixin；Mihomo 文件在 mihomo/ 子目录
#
# 用法：
#   1. 取消下方示例的行首 #，或自行添加 YAML
#   2. 仅有注释/空行时不会参与合并
#   3. mixin 里的 rules 会排在 Zay 内置规则 **之前**（先匹配先生效）
#   4. rule-providers 与内置 Loyalsoldier 规则集 **合并**（可同时存在）
#   5. proxy-groups 按 name **合并**（同名组合并字段；proxies/use 列表追加去重）
#   6. 其它顶层键（mixed-port、tun、dns 等）按字段覆盖生成配置
#   7. 修改后重启 zay 生效
#
# Zay 内置代理组名：Proxy、Auto（不是 PROXY）
# 策略：DIRECT（直连）、REJECT（拒绝）、Proxy / Auto（走代理）
#
# =============================================================================
# 其它全局项示例
# =============================================================================
#
# mixed-port: 7891
#
# tun:
#   enable: true
#
# =============================================================================
# rule-providers — 外部规则集
# =============================================================================
#
# 本地列表（在 mihomo/ruleset/ 新建 my-direct.txt，每行一个域名）：
#
# rule-providers:
#   my-direct:
#     type: file
#     behavior: domain
#     path: ./ruleset/my-direct.txt
#
# 远程规则：
#
# rule-providers:
#   my-remote:
#     type: http
#     behavior: domain
#     url: "https://example.com/rules.txt"
#     path: ./ruleset/my-remote.yaml
#     interval: 86400
#
# behavior：domain | ipcidr | classical
#
# =============================================================================
# rules — 分流（从上到下，命中第一条即停止）
# =============================================================================
#
# rules:
#   - RULE-SET,my-direct,DIRECT
#   - DOMAIN-SUFFIX,company.internal,DIRECT
#   - DOMAIN,www.example.com,DIRECT
#   - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
#   - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
#   - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
#   - PROCESS-NAME,Telegram.exe,Proxy
#
# 避免在离线/受限网络启动阶段使用 GEOIP 规则；缺少 MMDB 时 Mihomo 会尝试联网下载。
# Zay 会在 MMDB 缺失时把 GEOIP,PRIVATE 规则改写为私网 IP-CIDR 规则。
#
# 勿在 mixin 写 MATCH,DIRECT — 内置规则末尾已包含（黑名单模式：仅 GFW 等走 Proxy）。
#
# =============================================================================
# proxy-groups — 按 name 合并（勿整段覆盖 Auto/Proxy）
# =============================================================================
#
# proxy-groups:
#   - name: Proxy
#     proxies:
#       - DIRECT
#       - 我的备用节点
#
# =============================================================================
# 你的配置
# =============================================================================
#
# rule-providers:
#
# rules:
#
"#;

pub fn default_zay_toml() -> String {
    let mut raw = String::from(
        r#"# Zay – simple settings (edit this file, then: zay stack)
# Stack proxy URL(s) on the CLI: zay stack --proxy "https://..." [--proxy "https://..."]
# Mihomo runtime files (config, geo, ruleset, providers) live in ./mihomo/
# Reference: mihomo/config.template.yaml (upstream docs/config.yaml, created on first run)

mixed_port = 7890
log_level = "info"
health_check_url = "http://cp.cloudflare.com/generate_204"
update_interval = 3600
# Extra CIDRs that Mihomo TUN should not capture. Useful for corporate proxy gateways.
# tun_exclude_routes = ["11.155.134.0/24"]

# Bootstrap proxy: used only to fetch stack proxy subscriptions when the URL is blocked on DIRECT.
# Either a path to a YAML file (one Mihomo proxy), or an inline table — see below.
# bootstrap_proxy = "bootstrap.yaml"
#
# [bootstrap_proxy]
# name = "Bootstrap"
# type = "ss"
# server = "1.2.3.4"
# port = 8388
# cipher = "aes-256-gcm"
# password = "secret"

[mihomo]
# YAML mixin merged into generated mihomo/config.yaml.
mixin = '''
"#,
    );
    raw.push_str(DEFAULT_MIXIN);
    raw.push_str(
        r#"'''

# EasyTier mesh (used with: zay stack --mesh). See docs/stack.md — no separate easytier.toml.
# [mesh]
# instance_name = "zay"
# network_name = "my-network"
# network_secret = "change-me"
# dhcp = true
# ipv4 = "10.126.126.10/24"
# Mihomo TUN excludes mesh_routes, so EasyTier TUN owns these CIDRs.
# listeners = ["tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"]
# peers = ["tcp://public.easytier.top:11010"]
# mesh_routes = ["10.126.126.0/24"]
"#,
    );
    raw
}

/// EasyTier mesh section in `zay.toml` (see `docs/stack.md`).
#[derive(Debug, Clone, Deserialize)]
pub struct MeshConfig {
    pub instance_name: Option<String>,
    pub network_name: String,
    pub network_secret: String,
    pub dhcp: Option<bool>,
    pub ipv4: Option<String>,
    pub listeners: Option<Vec<String>>,
    pub peers: Option<Vec<String>>,
    pub proxy_networks: Option<Vec<String>>,
    /// Zay-only: injected as Mihomo `IP-CIDR,...,DIRECT` rules and TUN route excludes when `--mesh`.
    pub mesh_routes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct ZayFile {
    mixed_port: u16,
    allow_lan: bool,
    tun: bool,
    log_level: String,
    health_check_url: String,
    update_interval: u64,
    tun_exclude_routes: Vec<String>,
    /// Mihomo `external-controller` listen address (default 127.0.0.1:19090).
    controller_port: Option<u16>,
    /// Mihomo API `secret` (auto-generated per run if omitted).
    api_secret: Option<String>,
    mihomo: MihomoFile,
    /// Path to a YAML file, or omit when using `[bootstrap_proxy]` table.
    bootstrap_proxy: Option<TomlValue>,
    mesh: Option<MeshConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct MihomoFile {
    mixin: Option<String>,
}

impl Default for ZayFile {
    fn default() -> Self {
        Self {
            mixed_port: 7890,
            allow_lan: false,
            tun: false,
            log_level: "info".into(),
            health_check_url: "http://cp.cloudflare.com/generate_204".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            controller_port: None,
            api_secret: None,
            mihomo: MihomoFile::default(),
            bootstrap_proxy: None,
            mesh: None,
        }
    }
}

/// Single proxy node for bootstrapping subscription download (see `proxy-providers.*.proxy`).
#[derive(Debug, Clone)]
pub struct BootstrapProxy {
    pub name: String,
    pub proxy: Value,
}

/// Flags passed to `zay stack` (Mihomo always runs; these shape the profile).
#[derive(Debug, Clone, Copy, Default)]
pub struct StackFlags {
    pub mesh: bool,
    pub gateway: bool,
    pub tun: bool,
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
    /// `external-controller` value written into Mihomo config (e.g. `127.0.0.1:19090`).
    pub external_controller: String,
    pub api_secret: String,
    /// Inline YAML mixin from `[mihomo].mixin`.
    pub mihomo_mixin: Option<String>,
    pub bootstrap_proxy: Option<BootstrapProxy>,
    pub mesh: Option<MeshConfig>,
    pub stack: StackFlags,
}

impl Settings {
    /// Directory passed to Mihomo `-d` (generated config, geo, rules, subscription cache).
    pub fn mihomo_dir(&self) -> PathBuf {
        self.data_dir.join(MIHOMO_DIR)
    }

    pub fn config_path(&self) -> PathBuf {
        self.mihomo_dir().join("config.yaml")
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
        self.mihomo_dir()
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

fn ensure_zay_toml(data_dir: &Path, toml_path: &Path) -> Result<()> {
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
            "bootstrap_proxy must be a file path string or [bootstrap_proxy] table"
        ),
    }
}

pub fn resolve_stack(cli: &ProxyOpts, stack: StackFlags) -> Result<Settings> {
    resolve_inner(cli, stack)
}

fn resolve_inner(cli: &ProxyOpts, stack: StackFlags) -> Result<Settings> {
    let data_dir = cli
        .data_dir
        .clone()
        .or_else(|| {
            cli.config
                .as_ref()
                .and_then(|p| p.parent().map(Path::to_path_buf))
        })
        .unwrap_or_else(default_data_dir);

    let toml_path = cli
        .config
        .clone()
        .unwrap_or_else(|| data_dir.join(ZAY_TOML_FILE));

    ensure_zay_toml(&data_dir, &toml_path)?;
    let file = load_zay_toml(&toml_path)?;

    let mihomo_mixin = file.mihomo.mixin;

    let bootstrap_proxy = if let Some(path) = &cli.bootstrap_proxy {
        Some(proxy::load_from_yaml_file(path)?)
    } else if let Some(raw) = &file.bootstrap_proxy {
        Some(resolve_bootstrap_proxy(raw, &toml_path, &data_dir)?)
    } else {
        None
    };

    let controller_port = file.controller_port.unwrap_or(19090);
    let api_secret = file
        .api_secret
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(generate_api_secret);

    let allow_lan = stack.gateway;
    let tun = stack.tun;
    let mut tun_exclude_routes = file.tun_exclude_routes;
    tun_exclude_routes.extend(cli.tun_exclude_routes.clone());

    Ok(Settings {
        subscriptions: cli.subscriptions.clone(),
        data_dir,
        mixed_port: cli.mixed_port.unwrap_or(file.mixed_port),
        allow_lan,
        tun,
        log_level: cli.log_level.clone().unwrap_or(file.log_level),
        health_check_url: cli
            .health_check_url
            .clone()
            .unwrap_or(file.health_check_url),
        update_interval: cli.update_interval.unwrap_or(file.update_interval),
        tun_exclude_routes,
        external_controller: format!("127.0.0.1:{controller_port}"),
        api_secret,
        mihomo_mixin,
        bootstrap_proxy,
        mesh: file.mesh,
        stack,
    })
}

fn generate_api_secret() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("zay-{nanos:032x}")
}

fn is_invalid_subscription_body(raw: &str) -> bool {
    let trimmed = raw.trim_start();
    trimmed.starts_with('<')
        || trimmed.starts_with("<!doctype")
        || trimmed.starts_with("<!DOCTYPE")
}

pub fn cleanup_stale_subscription_cache(mihomo_dir: &Path, sub_count: usize) {
    let providers = mihomo_dir.join("providers");
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
    fn default_config_contains_inline_mihomo_mixin() {
        let parsed: ZayFile = toml::from_str(&default_zay_toml()).unwrap();

        let mixin = parsed.mihomo.mixin.unwrap();
        assert!(mixin.contains("[mihomo].mixin"));
        assert!(mixin.contains("rules:"));
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
