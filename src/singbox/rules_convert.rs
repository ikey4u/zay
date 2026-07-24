//! Convert Loyalsoldier `payload:` YAML (Clash rule-provider) to sing-box rule-set JSON.

include!("../../shared/clash_rules_convert.rs");

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
        assert!(json.contains("\"version\": 4"));
        // sing-box ≥1.9: no leading dot → match apex + subdomains
        assert!(json.contains("\"example.com\""));
        assert!(!json.contains("\".example.com\""));
        assert!(json.contains("1.2.3.0/24"));
        assert!(is_valid_singbox_ruleset_json(&json));
    }

    #[test]
    fn apex_domain_suffix_from_plain_host() {
        let raw = "payload:\n  - 'x.com'\n  - '.twitter.com'\n";
        let json = loyalsoldier_yaml_to_singbox_source(raw).unwrap();
        assert!(json.contains("\"x.com\""));
        assert!(json.contains("\"twitter.com\""));
        assert!(!json.contains("\".x.com\""));
        assert!(!json.contains("\".twitter.com\""));
    }

    #[test]
    fn rejects_html() {
        let err = loyalsoldier_yaml_to_singbox_source("<html>").unwrap_err();
        assert!(err.to_string().contains("HTML"));
    }

    #[test]
    fn strips_leading_dots_in_existing_json() {
        let raw = r#"{"version":4,"rules":[{"domain_suffix":[".x.com",".lan","ok.com"]}]}"#;
        let out = strip_leading_dots_in_ruleset_json(raw).unwrap();
        assert!(out.contains("\"x.com\""));
        assert!(out.contains("\"lan\""));
        assert!(out.contains("\"ok.com\""));
        assert!(!out.contains("\".x.com\""));
        assert!(strip_leading_dots_in_ruleset_json(&out).is_none());
    }
}
