// Loyalsoldier clash-rules YAML → sing-box rule-set JSON (shared by build.rs and runtime).

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

/// sing-box source rule-set version (pinned sing-box 1.13.x → version 4).
const RULESET_VERSION: u8 = 4;

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

    let mut lines = Vec::new();
    for item in payload {
        if let Some(line) = item.as_str() {
            lines.push(line.to_string());
        }
    }
    lines_to_singbox_source(&lines)
}

/// Convert well-known rule list text into sing-box source rule-set JSON.
///
/// Supported:
/// - sing-box source JSON (`{"version":4,"rules":[…]}`)
/// - Loyalsoldier / Clash `payload:` YAML
/// - Shadowrocket / Clash / QuantumultX rule lines (`DOMAIN-SUFFIX,…`)
/// - Plain domain / `+.suffix` / CIDR lists (one per line)
pub fn rule_text_to_singbox_source(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("rule text is empty");
    }
    if trimmed.starts_with('<') {
        bail!("rule body looks like HTML");
    }

    if trimmed.starts_with('{') {
        if is_valid_singbox_ruleset_json(trimmed) {
            return Ok(trimmed.to_string());
        }
        bail!("JSON is not a valid sing-box rule-set");
    }

    // Clash payload YAML
    if trimmed.contains("payload:") {
        if let Ok(json) = loyalsoldier_yaml_to_singbox_source(trimmed) {
            return Ok(json);
        }
    }

    let lines: Vec<String> = trimmed
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    lines_to_singbox_source(&lines)
}

fn lines_to_singbox_source(lines: &[String]) -> Result<String> {
    let mut domain_suffix = Vec::new();
    let mut domain = Vec::new();
    let mut domain_keyword = Vec::new();
    let mut domain_regex = Vec::new();
    let mut ip_cidr = Vec::new();
    let mut process_name = Vec::new();

    for line in lines {
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
        bail!("no rules extracted");
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

/// Rewrite rule-set JSON so `domain_suffix` entries have no leading `.`.
/// Returns `Some(new_json)` when any entry was changed.
pub fn strip_leading_dots_in_ruleset_json(raw: &str) -> Option<String> {
    let mut v: Value = serde_json::from_str(raw).ok()?;
    let rules = v.get_mut("rules")?.as_array_mut()?;
    let mut changed = false;
    for rule in rules.iter_mut() {
        let Some(obj) = rule.as_object_mut() else {
            continue;
        };
        let Some(suffixes) = obj.get_mut("domain_suffix") else {
            continue;
        };
        let Some(arr) = suffixes.as_array_mut() else {
            continue;
        };
        for item in arr.iter_mut() {
            let Some(s) = item.as_str() else { continue };
            if let Some(stripped) = s.strip_prefix('.') {
                if !stripped.is_empty() {
                    *item = Value::String(stripped.to_string());
                    changed = true;
                }
            }
        }
    }
    if !changed {
        return None;
    }
    serde_json::to_string_pretty(&v).ok()
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
        let host = rest.split(',').next().unwrap_or(rest).trim();
        domain_suffix.push(normalize_suffix(host));
        return;
    }
    if let Some(rest) = line.strip_prefix("DOMAIN,") {
        let host = rest.split(',').next().unwrap_or(rest).trim();
        domain.push(host.to_string());
        return;
    }
    if let Some(rest) = line.strip_prefix("DOMAIN-KEYWORD,") {
        let kw = rest.split(',').next().unwrap_or(rest).trim();
        domain_keyword.push(kw.to_string());
        return;
    }
    if let Some(rest) = line.strip_prefix("DOMAIN-REGEX,") {
        let re = rest.split(',').next().unwrap_or(rest).trim();
        domain_regex.push(re.to_string());
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

    // Skip policy / UA / URL rules that are not domain/IP matchers.
    let upper = line.to_ascii_uppercase();
    if upper.starts_with("USER-AGENT,")
        || upper.starts_with("URL-REGEX,")
        || upper.starts_with("SCRIPT,")
        || upper.starts_with("AND,")
        || upper.starts_with("OR,")
        || upper.starts_with("NOT,")
        || upper.starts_with("GEOIP,")
        || upper.starts_with("FINAL,")
        || upper.starts_with("MATCH,")
        || upper.starts_with("RULE-SET,")
    {
        return;
    }

    if looks_like_cidr(line) {
        ip_cidr.push(line.to_string());
        return;
    }

    if let Some(rest) = line.strip_prefix("+.") {
        domain_suffix.push(normalize_suffix(rest));
        return;
    }
    if line.starts_with('.') {
        domain_suffix.push(normalize_suffix(line));
        return;
    }
    if line.starts_with('+') {
        domain_suffix.push(normalize_suffix(line.trim_start_matches('+')));
        return;
    }

    if line.contains('/') {
        return;
    }
    domain_suffix.push(normalize_suffix(line));
}

/// Clash DOMAIN-SUFFIX / `+.host` means apex + subdomains.
///
/// sing-box ≥1.9: `domain_suffix` **with** a leading `.` matches subdomains only;
/// **without** a leading `.` matches `(domain|.+\.domain)`. Strip dots so Loyalsoldier
/// lists match apex hosts like `x.com`, not only `www.x.com`.
fn normalize_suffix(s: &str) -> String {
    s.trim().trim_start_matches('.').to_string()
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
