//! Route rules and local rule-sets (Loyalsoldier clash-rules, adapted for sing-box).

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde_json::{Value, json};

use crate::settings::Settings;

/// Build-time rule-sets extracted from the binary (`ensure_embedded_rules`).
pub const EMBEDDED_RULESET_DIR: &str = "ruleset-embedded";
/// Rule-sets downloaded at runtime via proxy (`update_rules_via_proxy`).
pub const DOWNLOAD_RULESET_DIR: &str = "ruleset-download";

const CLASH_RULES_SOURCES: &[&str] = &[
    "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release",
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release",
];

#[derive(Clone, Copy)]
pub struct RuleSetDef {
    pub id: &'static str,
}

pub const RULE_SETS: &[RuleSetDef] = &[
    RuleSetDef { id: "applications" },
    RuleSetDef { id: "reject" },
    RuleSetDef { id: "icloud" },
    RuleSetDef { id: "apple" },
    RuleSetDef { id: "google" },
    RuleSetDef { id: "proxy" },
    RuleSetDef { id: "direct" },
    RuleSetDef { id: "private" },
    RuleSetDef { id: "gfw" },
    RuleSetDef { id: "telegramcidr" },
    RuleSetDef { id: "cncidr" },
    RuleSetDef { id: "lancidr" },
];

/// Rule-sets required for blacklist routing (excluding optional `applications`).
const CORE_RULE_SETS: &[RuleSetDef] = &[
    RuleSetDef { id: "reject" },
    RuleSetDef { id: "icloud" },
    RuleSetDef { id: "apple" },
    RuleSetDef { id: "google" },
    RuleSetDef { id: "proxy" },
    RuleSetDef { id: "direct" },
    RuleSetDef { id: "private" },
    RuleSetDef { id: "gfw" },
    RuleSetDef { id: "telegramcidr" },
    RuleSetDef { id: "cncidr" },
    RuleSetDef { id: "lancidr" },
];

pub fn embedded_ruleset_dir(singbox_dir: &Path) -> PathBuf {
    singbox_dir.join(EMBEDDED_RULESET_DIR)
}

pub fn download_ruleset_dir(singbox_dir: &Path) -> PathBuf {
    singbox_dir.join(DOWNLOAD_RULESET_DIR)
}

pub fn embedded_rule_path(singbox_dir: &Path, id: &str) -> PathBuf {
    embedded_ruleset_dir(singbox_dir).join(format!("{id}.json"))
}

pub fn download_rule_path(singbox_dir: &Path, id: &str) -> PathBuf {
    download_ruleset_dir(singbox_dir).join(format!("{id}.json"))
}

/// Merged view: runtime download wins over embedded when both exist.
pub fn resolved_rule_path(singbox_dir: &Path, id: &str) -> Option<PathBuf> {
    let downloaded = download_rule_path(singbox_dir, id);
    if rule_file_valid(&downloaded) {
        return Some(downloaded);
    }
    let embedded = embedded_rule_path(singbox_dir, id);
    if rule_file_valid(&embedded) {
        return Some(embedded);
    }
    None
}

pub fn files_present(singbox_dir: &Path) -> bool {
    CORE_RULE_SETS
        .iter()
        .all(|def| resolved_rule_path(singbox_dir, def.id).is_some())
}

pub fn applications_present(singbox_dir: &Path) -> bool {
    resolved_rule_path(singbox_dir, "applications").is_some()
}

pub fn rule_file_valid(path: &Path) -> bool {
    path.is_file()
        && fs::read_to_string(path).ok().is_some_and(|raw| {
            super::rules_convert::is_valid_singbox_ruleset_json(&raw)
        })
}

/// Path written into `config.json` (relative to sing-box `-D`); prefers `ruleset-download/`.
pub fn rule_set_config_path(singbox_dir: &Path, id: &str) -> String {
    if rule_file_valid(&download_rule_path(singbox_dir, id)) {
        format!("{DOWNLOAD_RULESET_DIR}/{id}.json")
    } else {
        format!("{EMBEDDED_RULESET_DIR}/{id}.json")
    }
}

/// One-time: move valid `ruleset/*.json` (legacy layout) into `ruleset-download/`.
pub fn migrate_legacy_ruleset(singbox_dir: &Path) -> Result<()> {
    let legacy = singbox_dir.join("ruleset");
    if !legacy.is_dir() {
        return Ok(());
    }
    let download = download_ruleset_dir(singbox_dir);
    fs::create_dir_all(&download)
        .with_context(|| format!("creating {}", download.display()))?;
    let mut moved = 0usize;
    for def in RULE_SETS {
        let old = legacy.join(format!("{}.json", def.id));
        let new = download_rule_path(singbox_dir, def.id);
        if rule_file_valid(&old) && !rule_file_valid(&new) {
            fs::copy(&old, &new).with_context(|| {
                format!("migrating {} → {}", old.display(), new.display())
            })?;
            moved += 1;
        }
    }
    if moved > 0 {
        eprintln!(
            "clash-rules: migrated {moved} rule-set(s) from ruleset/ to {DOWNLOAD_RULESET_DIR}/"
        );
    }
    Ok(())
}

/// Extract embedded rule-sets and migrate legacy paths.
pub fn ensure_embedded_rules(settings: &Settings) -> Result<()> {
    migrate_legacy_ruleset(&settings.singbox_dir())?;
    super::embedded_rules::ensure_installed(settings)?;
    // Download copies may still use pre-1.9 leading-dot suffixes; strip so apex
    // hosts (e.g. x.com) match Proxy/gfw instead of falling through to final direct.
    migrate_domain_suffix_leading_dots(&settings.singbox_dir())
}

/// Strip leading `.` from `domain_suffix` in on-disk rule-set JSON (sing-box ≥1.9).
fn migrate_domain_suffix_leading_dots(singbox_dir: &Path) -> Result<()> {
    let mut fixed = 0usize;
    for dir in [
        download_ruleset_dir(singbox_dir),
        embedded_ruleset_dir(singbox_dir),
    ] {
        if !dir.is_dir() {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(raw) = fs::read_to_string(&path) else {
                continue;
            };
            let Some(new) =
                super::rules_convert::strip_leading_dots_in_ruleset_json(&raw)
            else {
                continue;
            };
            fs::write(&path, new).with_context(|| {
                format!("rewriting domain_suffix in {}", path.display())
            })?;
            fixed += 1;
        }
    }
    if fixed > 0 {
        eprintln!(
            "clash-rules: normalized domain_suffix (no leading '.') in {fixed} rule-set(s)"
        );
    }
    Ok(())
}

/// sing-geoip CN rule-set (replaces legacy GEOIP,CN / country.mmdb in Mihomo).
pub const GEOIP_CN_TAG: &str = "geoip-cn";
const GEOIP_CN_RULESET_URL: &str = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs";

/// sing-geosite CN rule-set (Clash `GEOSITE,cn,DIRECT`; works with FakeIP domain matching).
pub const GEOSITE_CN_TAG: &str = "geosite-cn";
const GEOSITE_CN_RULESET_URL: &str = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs";

fn binary_ruleset_srs_valid(path: &Path) -> bool {
    path.is_file() && fs::metadata(path).ok().is_some_and(|m| m.len() > 64)
}

pub fn download_geoip_cn_path(singbox_dir: &Path) -> PathBuf {
    download_ruleset_dir(singbox_dir).join(format!("{GEOIP_CN_TAG}.srs"))
}

pub fn embedded_geoip_cn_path(singbox_dir: &Path) -> PathBuf {
    embedded_ruleset_dir(singbox_dir).join(format!("{GEOIP_CN_TAG}.srs"))
}

pub fn geoip_cn_srs_valid(path: &Path) -> bool {
    binary_ruleset_srs_valid(path)
}

pub fn download_geosite_cn_path(singbox_dir: &Path) -> PathBuf {
    download_ruleset_dir(singbox_dir).join(format!("{GEOSITE_CN_TAG}.srs"))
}

pub fn embedded_geosite_cn_path(singbox_dir: &Path) -> PathBuf {
    embedded_ruleset_dir(singbox_dir).join(format!("{GEOSITE_CN_TAG}.srs"))
}

pub fn geosite_cn_srs_valid(path: &Path) -> bool {
    binary_ruleset_srs_valid(path)
}

/// Prefer runtime download, then build-time embedded copy (avoids cold-start fetch from GitHub).
pub fn resolved_geoip_cn_path(singbox_dir: &Path) -> Option<PathBuf> {
    let downloaded = download_geoip_cn_path(singbox_dir);
    if geoip_cn_srs_valid(&downloaded) {
        return Some(downloaded);
    }
    let embedded = embedded_geoip_cn_path(singbox_dir);
    if geoip_cn_srs_valid(&embedded) {
        return Some(embedded);
    }
    None
}

fn geoip_cn_config_path(singbox_dir: &Path) -> String {
    if geoip_cn_srs_valid(&download_geoip_cn_path(singbox_dir)) {
        format!("{DOWNLOAD_RULESET_DIR}/{GEOIP_CN_TAG}.srs")
    } else {
        format!("{EMBEDDED_RULESET_DIR}/{GEOIP_CN_TAG}.srs")
    }
}

/// Prefer runtime download, then build-time embedded copy.
pub fn resolved_geosite_cn_path(singbox_dir: &Path) -> Option<PathBuf> {
    let downloaded = download_geosite_cn_path(singbox_dir);
    if geosite_cn_srs_valid(&downloaded) {
        return Some(downloaded);
    }
    let embedded = embedded_geosite_cn_path(singbox_dir);
    if geosite_cn_srs_valid(&embedded) {
        return Some(embedded);
    }
    None
}

fn geosite_cn_config_path(singbox_dir: &Path) -> String {
    if geosite_cn_srs_valid(&download_geosite_cn_path(singbox_dir)) {
        format!("{DOWNLOAD_RULESET_DIR}/{GEOSITE_CN_TAG}.srs")
    } else {
        format!("{EMBEDDED_RULESET_DIR}/{GEOSITE_CN_TAG}.srs")
    }
}

/// Paths wired into `route.rule_set` for sing-box (relative to `-D` / `singbox_dir`).
pub fn rule_set_definitions(settings: &Settings) -> Vec<Value> {
    let singbox_dir = settings.singbox_dir();
    let mut defs: Vec<Value> = RULE_SETS
        .iter()
        .filter_map(|def| {
            if resolved_rule_path(&singbox_dir, def.id).is_none() {
                return None;
            }
            Some(json!({
                "type": "local",
                "tag": def.id,
                "format": "source",
                "path": rule_set_config_path(&singbox_dir, def.id)
            }))
        })
        .collect();
    defs.push(geoip_cn_rule_set(settings));
    defs.push(geosite_cn_rule_set(settings));
    defs
}

/// Log rule-sets that will be passed to sing-box (`route.rule_set`).
pub fn log_singbox_rule_sets(settings: &Settings) {
    let defs = rule_set_definitions(settings);
    if defs.is_empty() {
        eprintln!(
            "warn: no rule-sets in config — run `cargo build` then restart (need {EMBEDDED_RULESET_DIR}/)"
        );
        return;
    }
    eprintln!(
        "sing-box rule-sets: {} loaded into config.json (paths relative to {})",
        defs.len(),
        settings.singbox_dir().display()
    );
    for def in &defs {
        let tag = def.get("tag").and_then(|v| v.as_str()).unwrap_or("?");
        let path = def.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        let kind = def.get("type").and_then(|v| v.as_str()).unwrap_or("?");
        eprintln!("  - {tag}: {kind} → {path}");
    }
}

fn geoip_cn_rule_set(settings: &Settings) -> Value {
    let singbox_dir = settings.singbox_dir();
    if resolved_geoip_cn_path(&singbox_dir).is_some() {
        return json!({
            "type": "local",
            "tag": GEOIP_CN_TAG,
            "format": "binary",
            "path": geoip_cn_config_path(&singbox_dir)
        });
    }
    // Fallback only when embedded rules were not installed (e.g. skipped `cargo build`).
    let detour = if settings.subscriptions.is_empty() {
        "direct"
    } else {
        "Proxy"
    };
    eprintln!(
        "warn: geoip-cn.srs missing locally — sing-box will fetch from GitHub via {detour} \
         (slow/blocked networks may hang at \"initialize rule-set\")"
    );
    json!({
        "type": "remote",
        "tag": GEOIP_CN_TAG,
        "format": "binary",
        "url": GEOIP_CN_RULESET_URL,
        "update_interval": "168h",
        "download_detour": detour
    })
}

fn geosite_cn_rule_set(settings: &Settings) -> Value {
    let singbox_dir = settings.singbox_dir();
    if resolved_geosite_cn_path(&singbox_dir).is_some() {
        return json!({
            "type": "local",
            "tag": GEOSITE_CN_TAG,
            "format": "binary",
            "path": geosite_cn_config_path(&singbox_dir)
        });
    }
    let detour = if settings.subscriptions.is_empty() {
        "direct"
    } else {
        "Proxy"
    };
    eprintln!(
        "warn: geosite-cn.srs missing locally — sing-box will fetch from GitHub via {detour} \
         (slow/blocked networks may hang at \"initialize rule-set\")"
    );
    json!({
        "type": "remote",
        "tag": GEOSITE_CN_TAG,
        "format": "binary",
        "url": GEOSITE_CN_RULESET_URL,
        "update_interval": "168h",
        "download_detour": detour
    })
}

/// DNS rules for Mihomo-style FakeIP + Loyalsoldier rule-sets.
///
/// GFW/proxy and domestic direct lists use real DNS (`dns-direct`) so route `rule_set`
/// matching has a stable domain↔IP mapping; everything else uses FakeIP.
pub fn clash_dns_rules(has_rules: bool) -> Vec<Value> {
    let mut rules = vec![json!({
        "domain_suffix": [".lan", ".local", ".internal"],
        "action": "route",
        "server": "dns-direct"
    })];
    if has_rules {
        rules.extend([
            json!({
                "rule_set": ["gfw", "proxy"],
                "query_type": ["A", "AAAA"],
                "action": "route",
                "server": "dns-direct"
            }),
            json!({
                "rule_set": ["geosite-cn", "direct", "icloud", "apple"],
                "query_type": ["A", "AAAA"],
                "action": "route",
                "server": "dns-direct"
            }),
            json!({
                "rule_set": ["private", "lancidr"],
                "query_type": ["A", "AAAA"],
                "action": "route",
                "server": "dns-direct"
            }),
        ]);
    }
    rules.push(json!({
        "query_type": ["A", "AAAA"],
        "action": "route",
        "server": "fake-ip"
    }));
    rules
}

pub fn log_routing_mode(settings: &Settings, has_rules: bool) {
    if settings.stack.no_rules {
        eprintln!("routing: --no-rules (minimal routes)");
        return;
    }
    if has_rules {
        eprintln!(
            "routing: Loyalsoldier blacklist (Clash GEOSITE,cn via geosite-cn; gfw → Proxy; cncidr/direct/geosite-cn → direct; final → direct)"
        );
    } else {
        eprintln!(
            "warn: clash-rules missing — run `cargo build` to embed rules, or use --no-rules"
        );
    }
}

/// Loyalsoldier **blacklist** routing — matches `src/mihomo/rules.rs` order and semantics.
pub fn builtin_route_rules(
    proxy_tag: &str,
    include_applications: bool,
) -> Vec<Value> {
    let mut rules = Vec::new();
    if include_applications {
        rules.push(json!({ "action": "route", "rule_set": ["applications"], "outbound": "direct" }));
    }
    // gfw/proxy before cncidr: blocked domains must reach Proxy even when DNS returns a CN edge IP
    // (sing-box FakeIP + domain rules; see SagerNet/sing-box#627).
    rules.extend([
        json!({ "action": "route", "rule_set": ["private"], "outbound": "direct" }),
        json!({ "action": "reject", "rule_set": ["reject"] }),
        json!({ "action": "route", "rule_set": ["icloud"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["apple"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["geosite-cn", "direct"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["gfw", "proxy"], "outbound": proxy_tag }),
        json!({ "action": "route", "rule_set": ["telegramcidr"], "outbound": proxy_tag }),
        json!({ "action": "route", "rule_set": ["lancidr"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["cncidr"], "outbound": "direct" }),
        // curl http://IP:80 — real IP, no Host yet; Mihomo fake-ip avoids this path entirely.
        foreign_http_proxy_fallback(proxy_tag),
        json!({ "action": "route", "ip_is_private": true, "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["geoip-cn"], "outbound": "direct" }),
    ]);
    rules
}

/// Non-CN HTTP to raw IP (no SNI/Host yet) → Proxy; skip when domain is in geosite-cn/direct.
fn foreign_http_proxy_fallback(proxy_tag: &str) -> Value {
    json!({
        "type": "logical",
        "mode": "and",
        "rules": [
            { "network": "tcp", "port": [80] },
            { "ip_is_private": false },
            { "rule_set": ["geoip-cn"], "invert": true },
            { "rule_set": ["cncidr"], "invert": true },
            { "rule_set": ["geosite-cn", "direct"], "invert": true }
        ],
        "action": "route",
        "outbound": proxy_tag
    })
}

pub fn proxy_fetch_rules(proxy_tag: &str) -> Vec<Value> {
    ["jsdelivr.net", "githubusercontent.com", "github.com"]
        .into_iter()
        .map(|suffix| {
            json!({
                "action": "route",
                "domain_suffix": [suffix],
                "outbound": proxy_tag
            })
        })
        .chain(std::iter::once(json!({
            "action": "route",
            "domain_keyword": ["github"],
            "outbound": proxy_tag
        })))
        .collect()
}

pub fn spawn_background_download(
    settings: Settings,
    config_json: Arc<RwLock<String>>,
) {
    thread::spawn(move || {
        if let Err(e) = update_rules_via_proxy(&settings) {
            eprintln!("clash-rules update: {e:#}");
            return;
        }
        if !files_present(&settings.singbox_dir()) {
            return;
        }
        match crate::singbox::builder::build_config(&settings, true) {
            Ok(json) => {
                let path = settings.config_path();
                if let Err(e) = fs::write(&path, &json) {
                    eprintln!("writing config after rules update: {e:#}");
                    return;
                }
                *config_json.write().expect("config lock") = json;
                if settings.mesh_is_node() {
                    eprintln!(
                        "clash-rules updated on disk; restart `zay stack --mesh …` to apply \
                         (hot reload disabled with --mesh)"
                    );
                    return;
                }
                if let Err(e) = crate::singbox::reload::reload_config(&settings)
                {
                    eprintln!("sing-box reload after rules update: {e:#}");
                } else {
                    eprintln!("clash-rules updated via proxy");
                }
            }
            Err(e) => eprintln!("rebuild config after rules update: {e:#}"),
        }
    });
}

/// Refresh Loyalsoldier rule-sets from the network (never at cold start — use embedded rules).
pub fn update_rules_via_proxy(settings: &Settings) -> Result<()> {
    if settings.stack.no_rules {
        return Ok(());
    }
    if settings.subscriptions.is_empty() && settings.bootstrap_proxy.is_none() {
        return Ok(());
    }
    subscription::wait_for_proxy(settings, Duration::from_secs(120))?;
    eprintln!("clash-rules: updating via local proxy…");
    download_all(settings, true)
}

pub fn download_all(settings: &Settings, force: bool) -> Result<()> {
    let singbox_dir = settings.singbox_dir();
    fs::create_dir_all(download_ruleset_dir(&singbox_dir))?;
    let clients = rule_download_clients(settings)?;

    for def in RULE_SETS {
        let dest = download_rule_path(&singbox_dir, def.id);
        fetch_rule(&clients, def.id, &dest, force)?;
    }
    fetch_binary_ruleset_srs(
        &clients,
        &download_geoip_cn_path(&singbox_dir),
        GEOIP_CN_TAG,
        &[
            GEOIP_CN_RULESET_URL,
            "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/rule-set/geoip-cn.srs",
        ],
        force,
    )?;
    fetch_binary_ruleset_srs(
        &clients,
        &download_geosite_cn_path(&singbox_dir),
        GEOSITE_CN_TAG,
        &[
            GEOSITE_CN_RULESET_URL,
            "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/rule-set/geosite-cn.srs",
        ],
        force,
    )?;
    Ok(())
}

fn fetch_binary_ruleset_srs(
    clients: &[Client],
    dest: &Path,
    tag: &str,
    urls: &[&str],
    force: bool,
) -> Result<()> {
    if !force && binary_ruleset_srs_valid(dest) {
        return Ok(());
    }
    let mut last_err = None;
    for url in urls {
        for client in clients {
            match client.get(*url).send() {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp
                        .bytes()
                        .with_context(|| format!("reading {tag}.srs"))?;
                    if body.len() <= 64 {
                        last_err =
                            Some(anyhow::anyhow!("{url}: body too small"));
                        continue;
                    }
                    if let Some(parent) = dest.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(dest, &body).with_context(|| {
                        format!("writing {}", dest.display())
                    })?;
                    eprintln!("saved rule-set {tag} → {}", dest.display());
                    return Ok(());
                }
                Ok(resp) => {
                    last_err =
                        Some(anyhow::anyhow!("{url}: HTTP {}", resp.status()));
                }
                Err(e) => last_err = Some(e.into()),
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("{tag} download failed")))
}

/// HTTP clients for runtime rule updates — always via proxy when subscriptions are configured.
fn rule_download_clients(settings: &Settings) -> Result<Vec<Client>> {
    if settings.bootstrap_proxy.is_some() {
        return Ok(vec![crate::singbox::subscription::client_via_bootstrap(
            settings.bootstrap_proxy.as_ref().expect("checked"),
        )?]);
    }

    if settings.subscriptions.is_empty() {
        let direct = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .context("building direct HTTP client")?;
        return Ok(vec![direct]);
    }

    if mixed_proxy_reachable(settings.mixed_port) {
        return crate::mihomo::geo::http_clients_via_proxy(settings.mixed_port);
    }

    crate::singbox::subscription::wait_for_mixed_proxy(
        settings,
        Duration::from_secs(120),
    )?;
    crate::mihomo::geo::http_clients_via_proxy(settings.mixed_port)
}

fn mixed_proxy_reachable(mixed_port: u16) -> bool {
    use std::{
        net::{SocketAddr, TcpStream},
        time::Duration,
    };
    let Ok(addr) = format!("127.0.0.1:{mixed_port}").parse::<SocketAddr>()
    else {
        return false;
    };
    TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
}

fn fetch_rule(
    clients: &[Client],
    id: &str,
    dest: &Path,
    force: bool,
) -> Result<()> {
    if !force && rule_file_valid(dest) {
        return Ok(());
    }
    let legacy_txt = dest.with_extension("txt");
    if legacy_txt.is_file() {
        let _ = fs::remove_file(&legacy_txt);
    }

    let urls: Vec<String> = CLASH_RULES_SOURCES
        .iter()
        .map(|base| format!("{base}/{id}.txt"))
        .collect();
    let mut last_err = None;
    'url: for url in urls {
        for client in clients {
            match client.get(&url).send() {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp.bytes().context("reading rule body")?;
                    let raw = std::str::from_utf8(&body)
                        .context("rule body is not UTF-8")?;
                    let json = super::rules_convert::loyalsoldier_yaml_to_singbox_source(raw)
                        .with_context(|| format!("converting clash-rules {id}"))?;
                    if let Some(parent) = dest.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(dest, json.as_bytes())?;
                    eprintln!("saved rule-set {id} → {}", dest.display());
                    continue 'url;
                }
                Ok(resp) => {
                    last_err = Some(format!("{url}: HTTP {}", resp.status()));
                }
                Err(e) => last_err = Some(format!("{url}: {e}")),
            }
        }
    }
    if !force && rule_file_valid(dest) {
        return Ok(());
    }
    bail!(
        "failed to download rule-set {id}: {}",
        last_err.unwrap_or_else(|| "unknown".into())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn geosite_cn_uses_local_when_srs_present() {
        let data_dir = std::env::temp_dir()
            .join(format!("zay-geosite-{}", std::process::id()));
        let cleanup = data_dir.clone();
        let _ = fs::remove_dir_all(&cleanup);
        let singbox_dir = data_dir.join("singbox");
        fs::create_dir_all(embedded_ruleset_dir(&singbox_dir)).unwrap();
        fs::write(embedded_geosite_cn_path(&singbox_dir), vec![0u8; 128])
            .unwrap();
        let settings = Settings {
            subscriptions: vec!["https://example.com/sub".into()],
            data_dir,
            mixed_port: 7890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://example.com".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            external_controller: "127.0.0.1:19090".into(),
            api_secret: "".into(),
            mihomo_mixin: None,
            singbox_mixin: None,
            bootstrap_proxy: None,
            mesh: None,
            stack: crate::settings::StackFlags {
                mesh: None,
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };
        let defs = rule_set_definitions(&settings);
        let geosite = defs
            .iter()
            .find(|d| {
                d.get("tag").and_then(|t| t.as_str()) == Some(GEOSITE_CN_TAG)
            })
            .expect("geosite-cn rule-set");
        assert_eq!(geosite.get("type").and_then(|t| t.as_str()), Some("local"));
        assert!(!geosite.get("url").is_some());
        let _ = fs::remove_dir_all(&cleanup);
    }

    #[test]
    fn foreign_http_fallback_skips_geosite_cn_domains() {
        let rule = foreign_http_proxy_fallback("Proxy");
        let logical = rule.get("rules").and_then(|r| r.as_array()).unwrap();
        let excludes_geosite = logical.iter().any(|r| {
            r.get("rule_set")
                .and_then(|s| s.as_array())
                .is_some_and(|a| {
                    a.iter().any(|v| v.as_str() == Some("geosite-cn"))
                })
                && r.get("invert").and_then(|v| v.as_bool()) == Some(true)
        });
        assert!(excludes_geosite);
    }

    #[test]
    fn geoip_cn_uses_local_when_srs_present() {
        let data_dir = std::env::temp_dir()
            .join(format!("zay-geoip-{}", std::process::id()));
        let cleanup = data_dir.clone();
        let _ = fs::remove_dir_all(&cleanup);
        let singbox_dir = data_dir.join("singbox");
        fs::create_dir_all(embedded_ruleset_dir(&singbox_dir)).unwrap();
        fs::write(embedded_geoip_cn_path(&singbox_dir), vec![0u8; 128])
            .unwrap();
        let settings = Settings {
            subscriptions: vec!["https://example.com/sub".into()],
            data_dir,
            mixed_port: 7890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://example.com".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            external_controller: "127.0.0.1:19090".into(),
            api_secret: "".into(),
            mihomo_mixin: None,
            singbox_mixin: None,
            bootstrap_proxy: None,
            mesh: None,
            stack: crate::settings::StackFlags {
                mesh: None,
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };
        let defs = rule_set_definitions(&settings);
        let geoip = defs
            .iter()
            .find(|d| {
                d.get("tag").and_then(|t| t.as_str()) == Some(GEOIP_CN_TAG)
            })
            .expect("geoip-cn rule-set");
        assert_eq!(geoip.get("type").and_then(|t| t.as_str()), Some("local"));
        assert!(!geoip.get("url").is_some());
        let _ = fs::remove_dir_all(&cleanup);
    }

    #[test]
    fn download_overrides_embedded_in_config_path() {
        let tmp = std::env::temp_dir()
            .join(format!("zay-rules-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(embedded_ruleset_dir(&tmp)).unwrap();
        fs::create_dir_all(download_ruleset_dir(&tmp)).unwrap();
        let valid =
            r#"{"version":4,"rules":[{"domain_suffix":[".example.com"]}]}"#;
        fs::write(embedded_rule_path(&tmp, "gfw"), valid).unwrap();
        fs::write(download_rule_path(&tmp, "gfw"), valid).unwrap();
        assert_eq!(
            rule_set_config_path(&tmp, "gfw"),
            "ruleset-download/gfw.json"
        );
        let _ = fs::remove_file(download_rule_path(&tmp, "gfw"));
        assert_eq!(
            rule_set_config_path(&tmp, "gfw"),
            "ruleset-embedded/gfw.json"
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}

pub mod subscription {
    use super::*;

    pub fn wait_for_proxy(
        settings: &Settings,
        timeout: Duration,
    ) -> Result<()> {
        if settings.bootstrap_proxy.is_some() {
            return Ok(());
        }
        let deadline = Instant::now() + timeout;
        eprintln!("waiting for sing-box mixed proxy before rules download…");
        loop {
            if crate::mihomo::geo::http_client_via_proxy(settings.mixed_port)
                .ok()
                .and_then(|c| {
                    c.get("http://cp.cloudflare.com/generate_204").send().ok()
                })
                .is_some()
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("proxy not ready after {}s", timeout.as_secs());
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
}
