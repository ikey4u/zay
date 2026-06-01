//! Convert Loyalsoldier `payload:` YAML (Clash rule-provider) to sing-box rule-set source JSON.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

/// sing-box 1.11+ source rule-set version (matches pinned sing-box 1.12.x).
const RULESET_VERSION: u8 = 3;

/// Max entries per headless rule item (keeps JSON size reasonable).
const CHUNK: usize = 512;

pub fn loyalsoldier_yaml_to_singbox_source(raw: &str) -> Result<String> {
    if raw.trim_start().starts_with('<') {
        bail!("rule body looks like HTML, not clash-rules YAML");
    }
    let doc: serde_yaml::Value =
        serde_yaml::from_str(raw).context("parsing Loyalsoldier YAML")?;
    let payload = doc
        .get("payload")
        .and_then(|v| v.as_sequence())
        .with_context(
            || "expected top-level `payload:` list in clash-rules file",
        )?;

    let mut domain_suffix = Vec::new();
    let mut domain = Vec::new();
    let mut domain_keyword = Vec::new();
    let mut domain_regex = Vec::new();
    let mut ip_cidr = Vec::new();
    let mut process_name = Vec::new();

    for item in payload {
        let Some(line) = item.as_str() else { continue };
        classify_line(
            line.trim(),
            &mut domain_suffix,
            &mut domain,
            &mut domain_keyword,
            &mut domain_regex,
            &mut ip_cidr,
            &mut process_name,
        );
    }

    let mut rules: Vec<Value> = Vec::new();
    push_chunks(&mut rules, "domain_suffix", &domain_suffix);
    push_chunks(&mut rules, "domain", &domain);
    push_chunks(&mut rules, "domain_keyword", &domain_keyword);
    push_chunks(&mut rules, "domain_regex", &domain_regex);
    push_chunks(&mut rules, "ip_cidr", &ip_cidr);
    push_chunks(&mut rules, "process_name", &process_name);

    if rules.is_empty() {
        bail!("no rules extracted from payload");
    }

    let doc = json!({
        "version": RULESET_VERSION,
        "rules": rules,
    });
    serde_json::to_string_pretty(&doc).context("serializing sing-box rule-set")
}

pub fn is_valid_singbox_ruleset_json(raw: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(raw) else {
        return false;
    };
    v.get("version").is_some()
        && v.get("rules").and_then(|r| r.as_array()).is_some()
}

fn push_chunks(rules: &mut Vec<Value>, key: &str, values: &[String]) {
    for chunk in values.chunks(CHUNK) {
        rules.push(json!({ key: chunk }));
    }
}

fn classify_line(
    line: &str,
    domain_suffix: &mut Vec<String>,
    domain: &mut Vec<String>,
    domain_keyword: &mut Vec<String>,
    domain_regex: &mut Vec<String>,
    ip_cidr: &mut Vec<String>,
    process_name: &mut Vec<String>,
) {
    if line.is_empty() || line.starts_with('#') {
        return;
    }

    if let Some(rest) = line.strip_prefix("PROCESS-NAME,") {
        let name = rest.split(',').next().unwrap_or(rest).trim();
        if !name.is_empty() {
            process_name.push(name.to_string());
        }
        return;
    }

    if let Some(rest) = line.strip_prefix("DOMAIN-SUFFIX,") {
        domain_suffix.push(normalize_suffix(rest.trim()));
        return;
    }
    if let Some(rest) = line.strip_prefix("DOMAIN,") {
        domain.push(rest.trim().to_string());
        return;
    }
    if let Some(rest) = line.strip_prefix("DOMAIN-KEYWORD,") {
        domain_keyword.push(rest.trim().to_string());
        return;
    }
    if let Some(rest) = line.strip_prefix("DOMAIN-REGEX,") {
        domain_regex.push(rest.trim().to_string());
        return;
    }
    if let Some(rest) = line.strip_prefix("IP-CIDR,") {
        let cidr = rest.split(',').next().unwrap_or(rest).trim();
        if looks_like_cidr(cidr) {
            ip_cidr.push(cidr.to_string());
        }
        return;
    }
    if let Some(rest) = line.strip_prefix("IP-CIDR6,") {
        let cidr = rest.split(',').next().unwrap_or(rest).trim();
        if looks_like_cidr(cidr) {
            ip_cidr.push(cidr.to_string());
        }
        return;
    }

    if looks_like_cidr(line) {
        ip_cidr.push(line.to_string());
        return;
    }

    if let Some(rest) = line.strip_prefix("+.") {
        domain_suffix.push(format!(".{rest}"));
        return;
    }
    if line.starts_with('.') {
        domain_suffix.push(line.to_string());
        return;
    }
    if line.starts_with('+') {
        domain_suffix.push(normalize_suffix(line.trim_start_matches('+')));
        return;
    }

    // Bare hostname in some lists
    if line.contains('/') {
        return;
    }
    domain_suffix.push(normalize_suffix(line));
}

fn normalize_suffix(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('.') {
        s.to_string()
    } else {
        format!(".{s}")
    }
}

fn looks_like_cidr(s: &str) -> bool {
    let (addr, prefix) = match s.split_once('/') {
        Some(p) => p,
        None => return false,
    };
    if prefix.parse::<u8>().is_err() && prefix.parse::<u16>().is_err() {
        return false;
    }
    addr.parse::<std::net::Ipv4Addr>().is_ok()
        || addr.parse::<std::net::Ipv6Addr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_process_name() {
        let raw = r#"payload:
  - 'PROCESS-NAME,sing-box'
  - 'PROCESS-NAME,sing-box.exe'
"#;
        let json = loyalsoldier_yaml_to_singbox_source(raw).unwrap();
        assert!(json.contains("process_name"));
        assert!(json.contains("sing-box"));
    }

    #[test]
    fn converts_payload_yaml() {
        let raw = r#"payload:
  - '+.example.com'
  - '1.2.3.0/24'
"#;
        let json = loyalsoldier_yaml_to_singbox_source(raw).unwrap();
        assert!(json.contains("\"version\": 3"));
        assert!(json.contains(".example.com"));
        assert!(json.contains("1.2.3.0/24"));
        assert!(is_valid_singbox_ruleset_json(&json));
    }

    #[test]
    fn rejects_html() {
        let err = loyalsoldier_yaml_to_singbox_source("<html>").unwrap_err();
        assert!(err.to_string().contains("HTML"));
    }
}
