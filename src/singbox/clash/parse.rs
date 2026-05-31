use anyhow::{Context, Result};
use serde_yaml::Value;

#[derive(Debug, Default)]
pub struct ClashDoc {
    pub proxies: Vec<Value>,
    pub proxy_groups: Vec<Value>,
    pub rules: Vec<String>,
}

pub fn parse_clash_yaml(raw: &str) -> Result<ClashDoc> {
    let doc: Value =
        serde_yaml::from_str(raw).context("parsing clash subscription YAML")?;
    let mut out = ClashDoc::default();

    if let Some(proxies) = doc.get("proxies").and_then(|v| v.as_sequence()) {
        out.proxies.extend(proxies.iter().cloned());
    }

    if let Some(groups) = doc.get("proxy-groups").and_then(|v| v.as_sequence())
    {
        out.proxy_groups.extend(groups.iter().cloned());
    }

    if let Some(rules) = doc.get("rules").and_then(|v| v.as_sequence()) {
        for rule in rules {
            if let Some(s) = rule.as_str() {
                out.rules.push(s.to_string());
            }
        }
    }

    Ok(out)
}
