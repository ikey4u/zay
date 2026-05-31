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
    RULE_SETS.iter().all(|def| {
        let path = rule_file_path(runtime_dir, def.id);
        path.is_file()
            && fs::read_to_string(&path).ok().is_some_and(|raw| {
                super::rules_convert::is_valid_singbox_ruleset_json(&raw)
            })
    })
}

/// Path written into `config.json` (relative to sing-box `-D` runtime directory).
pub fn rule_set_config_path(id: &str) -> String {
    format!("{RULESET_DIR}/{id}.json")
}

pub fn rule_set_definitions() -> Vec<Value> {
    RULE_SETS
        .iter()
        .map(|def| {
            json!({
                "type": "local",
                "tag": def.id,
                "format": "source",
                "path": rule_set_config_path(def.id)
            })
        })
        .collect()
}

pub fn builtin_route_rules(proxy_tag: &str) -> Vec<Value> {
    vec![
        json!({ "action": "route", "rule_set": ["private"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["cncidr"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["lancidr"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["icloud", "apple", "direct"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["gfw", "proxy", "google"], "outbound": proxy_tag }),
        json!({ "action": "route", "rule_set": ["telegramcidr"], "outbound": proxy_tag }),
        json!({ "action": "reject", "rule_set": ["reject"] }),
    ]
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
    let clients = if settings.subscriptions.is_empty() {
        vec![
            Client::builder()
                .timeout(Duration::from_secs(120))
                .build()?,
        ]
    } else {
        crate::singbox::subscription::wait_for_mixed_proxy(
            settings,
            Duration::from_secs(90),
        )?;
        crate::mihomo::geo::http_clients_via_proxy(settings.mixed_port)?
    };

    for def in RULE_SETS {
        let dest = rule_file_path(&settings.singbox_dir(), def.id);
        fetch_rule(&clients, def.id, &dest)?;
    }
    Ok(())
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
