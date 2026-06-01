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

pub const RULESET_DIR: &str = "ruleset";

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

pub fn ruleset_dir(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join(RULESET_DIR)
}

pub fn rule_file_path(runtime_dir: &Path, id: &str) -> PathBuf {
    ruleset_dir(runtime_dir).join(format!("{id}.json"))
}

pub fn files_present(runtime_dir: &Path) -> bool {
    CORE_RULE_SETS
        .iter()
        .all(|def| rule_set_valid(runtime_dir, def.id))
}

pub fn applications_present(runtime_dir: &Path) -> bool {
    rule_set_valid(runtime_dir, "applications")
}

fn rule_set_valid(runtime_dir: &Path, id: &str) -> bool {
    let path = rule_file_path(runtime_dir, id);
    path.is_file()
        && fs::read_to_string(&path).ok().is_some_and(|raw| {
            super::rules_convert::is_valid_singbox_ruleset_json(&raw)
        })
}

/// Path written into `config.json` (relative to sing-box `-D` runtime directory).
pub fn rule_set_config_path(id: &str) -> String {
    format!("{RULESET_DIR}/{id}.json")
}

/// sing-geoip CN rule-set (replaces legacy GEOIP,CN / country.mmdb in Mihomo).
const GEOIP_CN_RULESET_URL: &str = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs";

pub fn rule_set_definitions(settings: &Settings) -> Vec<Value> {
    let mut defs: Vec<Value> = RULE_SETS
        .iter()
        .map(|def| {
            json!({
                "type": "local",
                "tag": def.id,
                "format": "source",
                "path": rule_set_config_path(def.id)
            })
        })
        .collect();
    defs.push(geoip_cn_rule_set(settings));
    defs
}

fn geoip_cn_rule_set(_settings: &Settings) -> Value {
    json!({
        "type": "remote",
        "tag": "geoip-cn",
        "format": "binary",
        "url": GEOIP_CN_RULESET_URL,
        "update_interval": "168h",
        "download_detour": "direct"
    })
}

pub fn log_routing_mode(settings: &Settings, has_rules: bool) {
    if settings.stack.no_rules {
        eprintln!("routing: --no-rules (minimal routes)");
        return;
    }
    if has_rules {
        eprintln!(
            "routing: Loyalsoldier blacklist (same as Mihomo/Clash: gfw → Proxy, cncidr/direct → direct, geoip-cn → direct, final → direct)"
        );
    } else if !settings.subscriptions.is_empty() {
        eprintln!(
            "warn: clash-rules not loaded — domestic sites (baidu.cn) may wrongly use Proxy; \
             curl google may work while baidu fails until rules download succeeds"
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
    rules.extend([
        json!({ "action": "route", "rule_set": ["private"], "outbound": "direct" }),
        json!({ "action": "reject", "rule_set": ["reject"] }),
        json!({ "action": "route", "rule_set": ["icloud"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["apple"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["direct"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["lancidr"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["cncidr"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["gfw", "proxy"], "outbound": proxy_tag }),
        json!({ "action": "route", "rule_set": ["telegramcidr"], "outbound": proxy_tag }),
        // curl http://IP:80 — real IP, no Host yet; Mihomo fake-ip avoids this path entirely.
        foreign_http_proxy_fallback(proxy_tag),
        json!({ "action": "route", "ip_is_private": true, "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["geoip-cn"], "outbound": "direct" }),
    ]);
    rules
}

/// Non-CN HTTP to raw IP (no SNI/Host yet) → Proxy; CN IPs already matched by cncidr above.
fn foreign_http_proxy_fallback(proxy_tag: &str) -> Value {
    json!({
        "type": "logical",
        "mode": "and",
        "rules": [
            { "network": "tcp", "port": [80] },
            { "ip_is_private": false },
            { "rule_set": ["geoip-cn"], "invert": true },
            { "rule_set": ["cncidr"], "invert": true }
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
        if let Err(e) = download_all(&settings) {
            eprintln!("clash-rules download failed: {e:#}");
            return;
        }
        match crate::singbox::builder::build_config(&settings, true) {
            Ok(json) => {
                let path = settings.config_path();
                if let Err(e) = fs::write(&path, &json) {
                    eprintln!("writing config after rules download: {e:#}");
                    return;
                }
                *config_json.write().expect("config lock") = json;
                if settings.stack.mesh {
                    eprintln!(
                        "clash-rules updated on disk; restart `zay stack --mesh` to apply \
                         (hot reload disabled with --mesh)"
                    );
                    return;
                }
                if let Err(e) = crate::singbox::reload::reload_config(&settings)
                {
                    eprintln!("sing-box reload after rules: {e:#}");
                }
            }
            Err(e) => eprintln!("rebuild config after rules: {e:#}"),
        }
    });
}

pub fn download_all(settings: &Settings) -> Result<()> {
    fs::create_dir_all(ruleset_dir(&settings.singbox_dir()))?;
    let clients = rule_download_clients(settings)?;

    for def in RULE_SETS {
        let dest = rule_file_path(&settings.singbox_dir(), def.id);
        fetch_rule(&clients, def.id, &dest)?;
    }
    Ok(())
}

/// HTTP clients for clash-rules download. Uses mixed proxy when already listening; otherwise direct
/// (mesh pre-start) or waits for sing-box to come up (normal stack).
fn rule_download_clients(settings: &Settings) -> Result<Vec<Client>> {
    let direct = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("building direct HTTP client")?;

    if settings.subscriptions.is_empty() {
        return Ok(vec![direct]);
    }

    if settings.bootstrap_proxy.is_some() {
        return Ok(vec![crate::singbox::subscription::client_via_bootstrap(
            settings.bootstrap_proxy.as_ref().expect("checked"),
        )?]);
    }

    if mixed_proxy_reachable(settings.mixed_port) {
        return crate::mihomo::geo::http_clients_via_proxy(settings.mixed_port);
    }

    if settings.stack.mesh {
        eprintln!(
            "mixed proxy not listening yet; trying direct download for clash-rules"
        );
        return Ok(vec![direct]);
    }

    crate::singbox::subscription::wait_for_mixed_proxy(
        settings,
        Duration::from_secs(90),
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

fn fetch_rule(clients: &[Client], id: &str, dest: &Path) -> Result<()> {
    if dest.is_file() {
        if let Ok(raw) = fs::read_to_string(dest)
            && super::rules_convert::is_valid_singbox_ruleset_json(&raw)
        {
            return Ok(());
        }
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
    if dest.is_file()
        && fs::read_to_string(dest).ok().is_some_and(|raw| {
            super::rules_convert::is_valid_singbox_ruleset_json(&raw)
        })
    {
        return Ok(());
    }
    bail!(
        "failed to download rule-set {id}: {}",
        last_err.unwrap_or_else(|| "unknown".into())
    )
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
