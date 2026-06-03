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
