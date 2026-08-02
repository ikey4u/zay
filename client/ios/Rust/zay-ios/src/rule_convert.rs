//! Convert user-supplied rule lists (Clash / Shadowrocket / plain / sing-box)
//! into sing-box source rule-set JSON. Shared convert logic lives in
//! `shared/clash_rules_convert.rs`.

#[path = "../../../../../shared/clash_rules_convert.rs"]
mod clash_rules_convert;

use anyhow::{Context, Result, bail};
use serde_json::json;

pub use clash_rules_convert::{is_valid_singbox_ruleset_json, rule_text_to_singbox_source};

/// Detect format + convert. Returns `{ "format", "rule_count", "json" }`.
pub fn convert_rule_text(raw: &str, hint: Option<&str>) -> Result<String> {
    let format = detect_format(raw, hint);
    let json_text = match format.as_str() {
        "singbox" if is_valid_singbox_ruleset_json(raw.trim()) => raw.trim().to_string(),
        _ => rule_text_to_singbox_source(raw)?,
    };
    let rule_count = count_entries(&json_text).unwrap_or(0);
    let out = json!({
        "format": format,
        "rule_count": rule_count,
        "json": json_text,
    });
    serde_json::to_string(&out).context("serialize convert result")
}

fn detect_format(raw: &str, hint: Option<&str>) -> String {
    if let Some(h) = hint.map(|s| s.trim().to_ascii_lowercase()) {
        if matches!(
            h.as_str(),
            "clash" | "shadowrocket" | "singbox" | "plain" | "auto"
        ) && h != "auto"
        {
            return h;
        }
    }
    let t = raw.trim();
    if t.starts_with('{') && is_valid_singbox_ruleset_json(t) {
        return "singbox".into();
    }
    if t.contains("payload:") {
        return "clash".into();
    }
    let upper = t.to_ascii_uppercase();
    if upper.contains("DOMAIN-SUFFIX,")
        || upper.contains("DOMAIN,")
        || upper.contains("DOMAIN-KEYWORD,")
        || upper.contains("IP-CIDR,")
        || upper.contains("IP-CIDR6,")
        || upper.contains("USER-AGENT,")
        || upper.contains("URL-REGEX,")
    {
        return "shadowrocket".into();
    }
    "plain".into()
}

fn count_entries(json_text: &str) -> Result<usize> {
    let v: serde_json::Value = serde_json::from_str(json_text)?;
    let rules = v
        .get("rules")
        .and_then(|r| r.as_array())
        .context("missing rules")?;
    let mut n = 0usize;
    for rule in rules {
        let Some(obj) = rule.as_object() else { continue };
        for (k, val) in obj {
            if k == "type" || k == "mode" || k == "invert" {
                continue;
            }
            if let Some(arr) = val.as_array() {
                n += arr.len();
            }
        }
    }
    if n == 0 {
        bail!("empty rules");
    }
    Ok(n)
}
