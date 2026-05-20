//! [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) — downloaded at runtime via the local mixed proxy.
//!
//! Files land in `<data-dir>/ruleset/*.txt` and are referenced from `rule-providers` (`type: file`).

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;

use super::{
    config::{RuleProvider, RuleProviders},
    geo,
};
use crate::settings::Settings;

pub const RULESET_DIR: &str = "ruleset";

/// Download sources (tried in order, still via mixed-port proxy).
const CLASH_RULES_SOURCES: &[&str] = &[
    "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release",
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release",
];

#[derive(Clone, Copy)]
pub struct RuleSetDef {
    pub id: &'static str,
    pub behavior: &'static str,
}

/// Rule sets from Loyalsoldier `release`.
pub const RULE_SETS: &[RuleSetDef] = &[
    RuleSetDef {
        id: "applications",
        behavior: "classical",
    },
    RuleSetDef {
        id: "reject",
        behavior: "domain",
    },
    RuleSetDef {
        id: "icloud",
        behavior: "domain",
    },
    RuleSetDef {
        id: "apple",
        behavior: "domain",
    },
    RuleSetDef {
        id: "google",
        behavior: "domain",
    },
    RuleSetDef {
        id: "proxy",
        behavior: "domain",
    },
    RuleSetDef {
        id: "direct",
        behavior: "domain",
    },
    RuleSetDef {
        id: "private",
        behavior: "domain",
    },
    RuleSetDef {
        id: "gfw",
        behavior: "domain",
    },
    RuleSetDef {
        id: "telegramcidr",
        behavior: "ipcidr",
    },
    RuleSetDef {
        id: "cncidr",
        behavior: "ipcidr",
    },
    RuleSetDef {
        id: "lancidr",
        behavior: "ipcidr",
    },
];

pub fn ruleset_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(RULESET_DIR)
}

pub fn rule_file_path(data_dir: &Path, id: &str) -> PathBuf {
    ruleset_dir(data_dir).join(format!("{id}.txt"))
}

pub fn files_present(data_dir: &Path) -> bool {
    RULE_SETS.iter().all(|def| {
        let path = rule_file_path(data_dir, def.id);
        path.is_file() && fs::metadata(&path).is_ok_and(|m| m.len() > 0)
    })
}

fn download_urls(id: &str) -> Vec<String> {
    CLASH_RULES_SOURCES
        .iter()
        .map(|base| format!("{base}/{id}.txt"))
        .collect()
}

/// Outbound policy used while fetching Loyalsoldier files (must exist in `proxy-groups` / `proxies`).
pub fn fetch_outbound_name(settings: &Settings) -> String {
    settings
        .bootstrap_proxy
        .as_ref()
        .map(|b| b.name.clone())
        .unwrap_or_else(|| "Auto".into())
}

/// Route rule/CDN hosts through a working outbound before `MATCH,Proxy` (fixes TLS eof when `sub*` is empty).
pub fn proxy_fetch_rule_lines(settings: &Settings) -> Vec<String> {
    let outbound = fetch_outbound_name(settings);
    [
        "DOMAIN-SUFFIX,jsdelivr.net",
        "DOMAIN-SUFFIX,githubusercontent.com",
        "DOMAIN-SUFFIX,github.com",
        "DOMAIN-KEYWORD,github",
    ]
    .into_iter()
    .map(|domain| format!("{domain},{outbound}"))
    .collect()
}

/// Built-in routing rules plus proxy-fetch rules (always prepended).
pub fn compose_routing_rules(
    settings: &Settings,
    has_mmdb: bool,
    has_builtin_rules: bool,
) -> Vec<String> {
    let mut lines = proxy_fetch_rule_lines(settings);
    if has_builtin_rules {
        lines.extend(routing_rule_lines(has_mmdb));
    } else {
        lines.extend(fallback_rule_lines(has_mmdb));
    }
    lines
}

fn subscription_cache_ready(settings: &Settings) -> bool {
    settings.subscriptions.iter().enumerate().any(|(i, _)| {
        let path = settings.subscription_cache_path(i);
        fs::read_to_string(&path).ok().is_some_and(|raw| {
            raw.contains("proxies:") && !raw.contains("proxies: []")
        })
    })
}

/// Wait until Mihomo can dial Loyalsoldier hosts through the mixed proxy (bootstrap or fetched sub).
pub fn wait_for_fetch_outbound(
    settings: &Settings,
    timeout: Duration,
) -> Result<()> {
    if settings.bootstrap_proxy.is_some() {
        eprintln!(
            "clash-rules fetch outbound: {}",
            fetch_outbound_name(settings)
        );
        return Ok(());
    }

    let deadline = Instant::now() + timeout;
    eprintln!("waiting for subscription proxies before clash-rules download…");
    while Instant::now() < deadline {
        if subscription_cache_ready(settings) {
            eprintln!("subscription cache ready for clash-rules fetch");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    bail!(
        "subscription proxies not ready after {}s (set bootstrap_proxy or wait for sub fetch)",
        timeout.as_secs()
    )
}

fn fetch_rule(clients: &[Client], id: &str, dest: &Path) -> Result<()> {
    if dest.is_file() && fs::metadata(dest).is_ok_and(|m| m.len() > 0) {
        eprintln!("reusing cached clash-rules {id}.txt at {}", dest.display());
        return Ok(());
    }

    let mut last_err = None;
    'url: for url in download_urls(id) {
        for (i, client) in clients.iter().enumerate() {
            eprintln!(
                "downloading clash-rules {id}.txt via proxy from {url} (client {i})"
            );
            match client.get(&url).send() {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp
                        .bytes()
                        .with_context(|| format!("reading {id}.txt body"))?;
                    if body.is_empty() {
                        last_err = Some(format!("{url}: empty body"));
                        continue;
                    }
                    if let Some(parent) = dest.parent() {
                        fs::create_dir_all(parent).with_context(|| {
                            format!("creating {}", parent.display())
                        })?;
                    }
                    fs::write(dest, &body).with_context(|| {
                        format!("writing {}", dest.display())
                    })?;
                    eprintln!(
                        "clash-rules {id}.txt saved to {} ({} bytes)",
                        dest.display(),
                        body.len()
                    );
                    return Ok(());
                }
                Ok(resp) => {
                    last_err = Some(format!("{url}: HTTP {}", resp.status()));
                }
                Err(e) => {
                    last_err = Some(format!("{url}: {e}"));
                }
            }
        }
    }

    bail!(
        "clash-rules {id}.txt: all sources failed ({})",
        last_err.unwrap_or_else(|| "unknown".into())
    )
}

/// After the mixed proxy is up, download any missing Loyalsoldier rule files and refresh `config.yaml`.
pub fn download_when_ready(
    settings: &Settings,
    config_snapshot: Option<Arc<RwLock<String>>>,
) -> Result<()> {
    if files_present(&settings.data_dir) {
        return Ok(());
    }

    geo::wait_for_proxy(settings.mixed_port, Duration::from_secs(120))?;
    wait_for_fetch_outbound(settings, Duration::from_secs(180))?;

    // Push fetch routing rules + reload so HTTPS to GitHub/jsDelivr uses bootstrap/Auto, not empty Proxy.
    geo::refresh_config_on_disk(settings, config_snapshot.clone())?;
    thread::sleep(Duration::from_millis(800));

    let clients = geo::http_clients_via_proxy(settings.mixed_port)?;
    fs::create_dir_all(ruleset_dir(&settings.data_dir)).with_context(|| {
        format!("creating {}", ruleset_dir(&settings.data_dir).display())
    })?;

    for def in RULE_SETS {
        let dest = rule_file_path(&settings.data_dir, def.id);
        if let Err(e) = fetch_rule(&clients, def.id, &dest) {
            eprintln!("clash-rules {id}: {e:#}", id = def.id);
        }
    }

    if !files_present(&settings.data_dir) {
        bail!("clash-rules download incomplete");
    }

    geo::refresh_config_on_disk(settings, config_snapshot)?;
    Ok(())
}

/// Built-in Loyalsoldier `rule-providers` (`type: file`).
pub fn rule_providers_map() -> RuleProviders {
    let mut providers = RuleProviders::new();
    for def in RULE_SETS {
        providers.insert(
            def.id.to_string(),
            RuleProvider {
                kind: "file".into(),
                behavior: def.behavior.into(),
                path: Some(format!("./{RULESET_DIR}/{}.txt", def.id)),
                url: None,
                interval: None,
                proxy: None,
                format: None,
                size_limit: None,
                payload: None,
                download_detour: None,
                hidden: None,
            },
        );
    }
    providers
}

/// Loyalsoldier **blacklist** routing: only listed blocked domains use `Proxy`, default is `DIRECT`.
///
/// Unlike Loyalsoldier's optional whitelist (`MATCH,PROXY`), this avoids sending sites like
/// `sec.gov` through the proxy when they are not on the GFW list.
fn builtin_rule_lines(has_mmdb: bool) -> Vec<String> {
    let mut lines = vec![
        "RULE-SET,applications,DIRECT".into(),
        "RULE-SET,private,DIRECT".into(),
        "RULE-SET,reject,REJECT".into(),
        "RULE-SET,icloud,DIRECT".into(),
        "RULE-SET,apple,DIRECT".into(),
        "RULE-SET,direct,DIRECT".into(),
        "RULE-SET,lancidr,DIRECT".into(),
        "RULE-SET,cncidr,DIRECT".into(),
        "RULE-SET,gfw,Proxy".into(),
        "RULE-SET,telegramcidr,Proxy".into(),
    ];
    if has_mmdb {
        lines.push("GEOIP,PRIVATE,DIRECT".into());
        lines.push("GEOIP,CN,DIRECT".into());
    }
    lines.push("MATCH,DIRECT".into());
    lines
}

/// Default routing when Loyalsoldier rule files are present.
pub fn routing_rule_lines(has_mmdb: bool) -> Vec<String> {
    builtin_rule_lines(has_mmdb)
}

pub fn fallback_rule_lines(has_mmdb: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if has_mmdb {
        lines.push("GEOIP,PRIVATE,DIRECT".into());
        lines.push("GEOIP,CN,DIRECT".into());
    }
    lines.push("MATCH,DIRECT".into());
    lines
}
