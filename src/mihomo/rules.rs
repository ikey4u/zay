//! [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) — downloaded at runtime via the local mixed proxy.
//!
//! Files land in `<data-dir>/ruleset/*.txt` and are referenced from `rule-providers` (`type: file`).

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;

use super::{
    config::{RuleProvider, RuleProviders},
    geo,
};
use crate::settings::Settings;

pub const RULESET_DIR: &str = "ruleset";
pub const CLASH_RULES_BASE: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release";

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

fn download_url(id: &str) -> String {
    format!("{CLASH_RULES_BASE}/{id}.txt")
}

fn fetch_rule(client: &Client, id: &str, dest: &Path) -> Result<()> {
    if dest.is_file() && fs::metadata(dest).is_ok_and(|m| m.len() > 0) {
        eprintln!("reusing cached clash-rules {id}.txt at {}", dest.display());
        return Ok(());
    }

    let url = download_url(id);
    eprintln!("downloading clash-rules {id}.txt via proxy from {url}");
    let response = client
        .get(&url)
        .send()
        .with_context(|| format!("GET {url} failed"))?;
    if !response.status().is_success() {
        bail!("{id}.txt download returned HTTP {}", response.status());
    }
    let body = response
        .bytes()
        .with_context(|| format!("reading {id}.txt body"))?;
    if body.is_empty() {
        bail!("{id}.txt is empty");
    }

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(dest, &body)
        .with_context(|| format!("writing {}", dest.display()))?;
    eprintln!(
        "clash-rules {id}.txt saved to {} ({} bytes)",
        dest.display(),
        body.len()
    );
    Ok(())
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
    let client = geo::http_client_via_proxy(settings.mixed_port)?;
    fs::create_dir_all(ruleset_dir(&settings.data_dir)).with_context(|| {
        format!("creating {}", ruleset_dir(&settings.data_dir).display())
    })?;

    for def in RULE_SETS {
        let dest = rule_file_path(&settings.data_dir, def.id);
        if let Err(e) = fetch_rule(&client, def.id, &dest) {
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

fn builtin_rule_lines(has_mmdb: bool) -> Vec<String> {
    let mut lines = vec![
        "RULE-SET,applications,DIRECT".into(),
        "RULE-SET,private,DIRECT".into(),
        "RULE-SET,reject,REJECT".into(),
        "RULE-SET,icloud,DIRECT".into(),
        "RULE-SET,apple,DIRECT".into(),
        "RULE-SET,google,Proxy".into(),
        "RULE-SET,proxy,Proxy".into(),
        "RULE-SET,direct,DIRECT".into(),
        "RULE-SET,lancidr,DIRECT".into(),
        "RULE-SET,cncidr,DIRECT".into(),
        "RULE-SET,telegramcidr,Proxy".into(),
    ];
    if has_mmdb {
        lines.push("GEOIP,PRIVATE,DIRECT".into());
        lines.push("GEOIP,CN,DIRECT".into());
    }
    lines.push("MATCH,Proxy".into());
    lines
}

/// Loyalsoldier whitelist-style rules; Zay proxy group is `Proxy`.
pub fn routing_rule_lines(has_mmdb: bool) -> Vec<String> {
    builtin_rule_lines(has_mmdb)
}

pub fn fallback_rule_lines(has_mmdb: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if has_mmdb {
        lines.push("GEOIP,PRIVATE,DIRECT".into());
        lines.push("GEOIP,CN,DIRECT".into());
    }
    lines.push("MATCH,Proxy".into());
    lines
}
