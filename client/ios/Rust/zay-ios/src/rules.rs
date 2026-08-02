//! Loyalsoldier clash-rules routing helpers (aligned with desktop `src/singbox/rules.rs`).

use std::fs;
use std::path::Path;

use serde_json::{Value, json};

pub const EMBEDDED_RULESET_DIR: &str = "ruleset-embedded";
/// User-added rule-sets (Clash / Shadowrocket / plain / sing-box JSON).
pub const CUSTOM_RULESET_DIR: &str = "ruleset-custom";

pub const GEOIP_CN_TAG: &str = "geoip-cn";
pub const GEOSITE_CN_TAG: &str = "geosite-cn";

/// One enabled custom rule-set to inject into sing-box.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CustomRuleSet {
    /// File stem under `ruleset-custom/` (and rule_set tag).
    pub id: String,
    /// `proxy` | `direct` | `reject`
    #[serde(default = "default_action")]
    pub action: String,
}

fn default_action() -> String {
    "proxy".into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RulesStage(pub u8);

impl RulesStage {
    /// Core sets only (no multi-MB direct/reject).
    pub const CORE: Self = Self(0);
    /// Core + `direct` (~2.5MB).
    pub const WITH_DIRECT: Self = Self(1);
    /// Core + `direct` + `reject` (~5MB).
    pub const WITH_REJECT: Self = Self(2);

    pub const MAX: u8 = 2;

    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("0") | Some("core") | Some("lean") => Self::CORE,
            Some("1") | Some("direct") => Self::WITH_DIRECT,
            Some("2") | Some("full") | Some("reject") => Self::WITH_REJECT,
            Some(s) => s
                .parse::<u8>()
                .ok()
                .map(|n| Self(n.min(Self::MAX)))
                .unwrap_or(Self::CORE),
            None => Self::CORE,
        }
    }

    pub fn includes_direct(self) -> bool {
        self.0 >= 1
    }

    pub fn includes_reject(self) -> bool {
        self.0 >= 2
    }
}

#[derive(Clone, Copy)]
pub struct RuleSetDef {
    pub id: &'static str,
}

/// Same IDs as desktop.
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

/// Never useful inside Packet Tunnel (no process matching).
pub fn never_on_ios(id: &str) -> bool {
    id == "applications"
}

/// Multi‑MB source sets loaded only at higher progressive stages.
fn ios_memory_heavy(id: &str) -> bool {
    matches!(id, "reject" | "direct")
}

pub fn rule_file_valid(path: &Path) -> bool {
    path.is_file()
        && fs::read_to_string(path).ok().is_some_and(|raw| {
            raw.contains("\"version\"") && raw.contains("\"rules\"")
        })
}

pub fn files_present(working_dir: &Path) -> bool {
    let dir = working_dir.join(EMBEDDED_RULESET_DIR);
    RULE_SETS
        .iter()
        .filter(|def| !never_on_ios(def.id) && !ios_memory_heavy(def.id))
        .all(|def| rule_file_valid(&dir.join(format!("{}.json", def.id))))
        && binary_ok(&dir.join("geoip-cn.srs"))
        && binary_ok(&dir.join("geosite-cn.srs"))
}

fn binary_ok(path: &Path) -> bool {
    fs::metadata(path).ok().is_some_and(|m| m.len() > 64)
}

fn include_ruleset(id: &str, stage: RulesStage) -> bool {
    if never_on_ios(id) {
        return false;
    }
    match id {
        "direct" => stage.includes_direct(),
        "reject" => stage.includes_reject(),
        _ => true,
    }
}

pub fn rule_set_definitions(working_dir: &Path, stage: RulesStage) -> Vec<Value> {
    let dir = working_dir.join(EMBEDDED_RULESET_DIR);
    let mut defs: Vec<Value> = RULE_SETS
        .iter()
        .filter(|def| include_ruleset(def.id, stage))
        .filter(|def| rule_file_valid(&dir.join(format!("{}.json", def.id))))
        .map(|def| {
            json!({
                "type": "local",
                "tag": def.id,
                "format": "source",
                "path": format!("{EMBEDDED_RULESET_DIR}/{}.json", def.id)
            })
        })
        .collect();

    if binary_ok(&dir.join("geoip-cn.srs")) {
        defs.push(json!({
            "type": "local",
            "tag": GEOIP_CN_TAG,
            "format": "binary",
            "path": format!("{EMBEDDED_RULESET_DIR}/geoip-cn.srs")
        }));
    }
    if binary_ok(&dir.join("geosite-cn.srs")) {
        defs.push(json!({
            "type": "local",
            "tag": GEOSITE_CN_TAG,
            "format": "binary",
            "path": format!("{EMBEDDED_RULESET_DIR}/geosite-cn.srs")
        }));
    }
    defs
}

/// Local rule_set defs for enabled custom sets that exist on disk.
pub fn custom_rule_set_definitions(
    working_dir: &Path,
    custom: &[CustomRuleSet],
) -> Vec<Value> {
    let dir = working_dir.join(CUSTOM_RULESET_DIR);
    custom
        .iter()
        .filter(|c| {
            let id = c.id.trim();
            !id.is_empty() && rule_file_valid(&dir.join(format!("{id}.json")))
        })
        .map(|c| {
            let id = c.id.trim();
            json!({
                "type": "local",
                "tag": format!("custom-{id}"),
                "format": "source",
                "path": format!("{CUSTOM_RULESET_DIR}/{id}.json")
            })
        })
        .collect()
}

/// Route rules for custom sets — inserted before builtin blacklist rules.
pub fn custom_route_rules(custom: &[CustomRuleSet], proxy_tag: &str) -> Vec<Value> {
    custom
        .iter()
        .filter(|c| !c.id.trim().is_empty())
        .filter_map(|c| {
            let tag = format!("custom-{}", c.id.trim());
            let action = c.action.trim().to_ascii_lowercase();
            match action.as_str() {
                "direct" => Some(json!({
                    "action": "route",
                    "rule_set": [tag],
                    "outbound": "direct"
                })),
                "reject" => Some(json!({
                    "action": "reject",
                    "rule_set": [tag]
                })),
                _ => Some(json!({
                    "action": "route",
                    "rule_set": [tag],
                    "outbound": proxy_tag
                })),
            }
        })
        .collect()
}

/// DNS rules for FakeIP + Loyalsoldier domain rule-sets.
///
/// Do **not** attach IP/CIDR-only rule-sets (`private`, `lancidr`, `cncidr`, …) here:
/// sing-box 1.14 rejects that as legacy address-filter without `match_response`.
/// Private/LAN DNS is covered by `domain_suffix`; IP routing stays in route rules.
pub fn clash_dns_rules(stage: RulesStage) -> Vec<Value> {
    let domestic: Vec<&str> = if stage.includes_direct() {
        vec!["geosite-cn", "direct", "icloud", "apple"]
    } else {
        vec!["geosite-cn", "icloud", "apple"]
    };
    vec![
        json!({
            "domain_suffix": [".lan", ".local", ".internal"],
            "action": "route",
            "server": "dns-direct"
        }),
        json!({
            "rule_set": ["gfw", "proxy"],
            "query_type": ["A", "AAAA"],
            "action": "route",
            "server": "dns-direct"
        }),
        json!({
            "rule_set": domestic,
            "query_type": ["A", "AAAA"],
            "action": "route",
            "server": "dns-direct"
        }),
        json!({
            "query_type": ["A", "AAAA"],
            "action": "route",
            "server": "fake-ip"
        }),
    ]
}

pub fn builtin_route_rules(proxy_tag: &str, stage: RulesStage) -> Vec<Value> {
    let mut rules = vec![
        json!({ "action": "route", "rule_set": ["private"], "outbound": "direct" }),
    ];
    if stage.includes_reject() {
        rules.push(json!({ "action": "reject", "rule_set": ["reject"] }));
    }
    rules.extend([
        json!({ "action": "route", "rule_set": ["icloud"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["apple"], "outbound": "direct" }),
    ]);
    if stage.includes_direct() {
        rules.push(json!({
            "action": "route",
            "rule_set": ["geosite-cn", "direct"],
            "outbound": "direct"
        }));
    } else {
        rules.push(json!({
            "action": "route",
            "rule_set": ["geosite-cn"],
            "outbound": "direct"
        }));
    }
    rules.extend([
        json!({ "action": "route", "rule_set": ["gfw", "proxy"], "outbound": proxy_tag }),
        json!({ "action": "route", "rule_set": ["telegramcidr"], "outbound": proxy_tag }),
        json!({ "action": "route", "rule_set": ["lancidr"], "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["cncidr"], "outbound": "direct" }),
        json!({ "action": "route", "ip_is_private": true, "outbound": "direct" }),
        json!({ "action": "route", "rule_set": ["geoip-cn"], "outbound": "direct" }),
    ]);
    rules
}

pub fn proxy_fetch_rules(proxy_tag: &str) -> Vec<Value> {
    ["jsdelivr.net", "githubusercontent.com", "github.com"]
        .into_iter()
        .map(|d| {
            json!({
                "action": "route",
                "domain_suffix": [d],
                "outbound": proxy_tag
            })
        })
        .collect()
}
