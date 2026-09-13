//! AdGuard DNS-filter and hosts-file conversion for source rule-sets.

use std::net::IpAddr;

use super::{RouteError, SourceRuleSet};
use crate::option::{
    DefaultHeadlessRuleOptions, HeadlessRuleOptions, Listable,
    LogicalHeadlessRuleOptions, LogicalRuleMode,
};

const INVALID_ADGUARD_RULE_SET: &str = "invalid binary AdGuard rule-set";

/// Result of converting an AdGuard filter into sing-box headless rules.
#[derive(Debug, Clone, PartialEq)]
pub struct AdGuardConversion {
    pub rule_set: SourceRuleSet,
    pub parsed_lines: usize,
    pub ignored_lines: usize,
}

#[derive(Debug)]
struct RuleLine {
    value: String,
    raw_domain: bool,
    exclude: bool,
    suffix: bool,
    start: bool,
    end: bool,
    regex: bool,
    important: bool,
}

/// Convert AdGuard DNS filter or hosts-file text into a source rule-set.
///
/// Unsupported URL, cosmetic, query, modifier, port and IP-CIDR filters are
/// counted and skipped, matching pinned sing-box's converter behavior.
pub fn convert_rule_set(
    content: &[u8],
) -> Result<AdGuardConversion, RouteError> {
    let content = std::str::from_utf8(content).map_err(|error| {
        RouteError::InvalidRuleSet(format!(
            "invalid UTF-8 in AdGuard rule-set: {error}"
        ))
    })?;
    let mut rule_lines = Vec::new();
    let mut ignored_lines = 0;

    'parse_line: for original in content.lines() {
        if original.is_empty()
            || original.starts_with('!')
            || original.starts_with('#')
        {
            continue;
        }
        if is_domain_name(original) {
            rule_lines.push(RuleLine {
                value: original.to_owned(),
                raw_domain: true,
                exclude: false,
                suffix: false,
                start: false,
                end: false,
                regex: false,
                important: false,
            });
            continue;
        }
        if let Some(host) = parse_hosts_line(original) {
            if !host.is_empty() {
                rule_lines.push(RuleLine {
                    value: host,
                    raw_domain: true,
                    exclude: false,
                    suffix: false,
                    start: true,
                    end: true,
                    regex: false,
                    important: false,
                });
            }
            continue;
        }

        let mut value = original.trim_end_matches('|');
        let mut important = false;
        if !value.starts_with('/')
            && let Some((rule, parameters)) = value.split_once('$')
        {
            for parameter in parameters.split(',') {
                let parts = parameter.split('=').collect::<Vec<_>>();
                let supported = match parts.as_slice() {
                    ["important"] | ["important", _] => {
                        important = true;
                        true
                    }
                    ["dnsrewrite", address] => address
                        .parse::<IpAddr>()
                        .is_ok_and(|address| address.is_unspecified()),
                    _ => false,
                };
                if !supported {
                    ignored_lines += 1;
                    continue 'parse_line;
                }
            }
            value = rule;
        }

        let mut exclude = false;
        if let Some(rest) = value.strip_prefix("@@") {
            value = rest;
            exclude = true;
        }
        value = value.trim_end_matches('|');

        let mut suffix = false;
        let mut start = false;
        if let Some(rest) = value.strip_prefix("||") {
            value = rest;
            suffix = true;
        } else if let Some(rest) = value.strip_prefix('|') {
            value = rest;
            start = true;
        }

        let mut end = false;
        if let Some(rest) = value.strip_suffix('^') {
            value = rest;
            end = true;
        }

        let mut regex = false;
        if value.starts_with('/') && value.ends_with('/') {
            value = &value[1..value.len() - 1];
            if ignores_ip_cidr_regex(value) {
                ignored_lines += 1;
                continue;
            }
            regex = true;
        } else {
            if let Some((_, host)) = value.split_once("://") {
                value = host;
                suffix = true;
            }
            if value.contains('/')
                || value.contains('?')
                || value.contains('&')
                || value.contains(['[', ']', '(', ')', '!', '#'])
                || value.contains('~')
            {
                ignored_lines += 1;
                continue;
            }
            let mut domain_check = if value.starts_with(['.', '-']) {
                format!("r{value}")
            } else {
                value.to_owned()
            };
            if value.is_empty() {
                ignored_lines += 1;
                continue;
            }
            domain_check = domain_check.replace('*', "x");
            if !is_domain_name(&domain_check) {
                ignored_lines += 1;
                continue;
            }
        }

        rule_lines.push(RuleLine {
            value: value.to_owned(),
            raw_domain: false,
            exclude,
            suffix,
            start,
            end,
            regex,
            important,
        });
    }

    if rule_lines.is_empty() {
        return Err(RouteError::InvalidRuleSet(
            "AdGuard rule-set is empty or all rules are unsupported".into(),
        ));
    }

    let parsed_lines = rule_lines.len();
    let rule = if rule_lines.iter().all(|line| line.raw_domain) {
        default_rule(
            rule_lines.into_iter().map(|line| line.value).collect(),
            Vec::new(),
            Vec::new(),
            false,
        )
    } else {
        build_filter_rule(rule_lines)
    };
    Ok(AdGuardConversion {
        rule_set: SourceRuleSet {
            // The pinned converter deliberately emits the first SRS version
            // which supports AdGuard matchers.
            version: 2,
            rules: vec![rule],
        },
        parsed_lines,
        ignored_lines,
    })
}

/// Export the canonical rule tree produced by [`convert_rule_set`] back to
/// AdGuard filter syntax.
pub fn export_rule_set(source: &SourceRuleSet) -> Result<Vec<u8>, RouteError> {
    let [root] = source.rules.as_slice() else {
        return invalid();
    };
    let mut current = root.clone();
    let mut important_domain = Vec::new();
    let mut important_regex = Vec::new();
    let mut important_exclude_domain = Vec::new();
    let mut important_exclude_regex = Vec::new();
    let mut exclude_domain = Vec::new();
    let mut exclude_regex = Vec::new();

    let (domain, regex) = loop {
        match current {
            HeadlessRuleOptions::Logical(logical) => {
                let [first, second] = logical.rules.as_slice() else {
                    return invalid();
                };
                let HeadlessRuleOptions::Default(first) = first else {
                    return invalid();
                };
                match (logical.mode, first.invert) {
                    (LogicalRuleMode::And, true) => {
                        if important_exclude_domain.is_empty()
                            && important_exclude_regex.is_empty()
                        {
                            important_exclude_domain =
                                first.adguard_domain.as_slice().to_vec();
                            important_exclude_regex =
                                first.domain_regex.as_slice().to_vec();
                            if important_exclude_domain.is_empty()
                                && important_exclude_regex.is_empty()
                            {
                                return invalid();
                            }
                        } else {
                            exclude_domain =
                                first.adguard_domain.as_slice().to_vec();
                            exclude_regex =
                                first.domain_regex.as_slice().to_vec();
                            if exclude_domain.is_empty()
                                && exclude_regex.is_empty()
                            {
                                return invalid();
                            }
                        }
                    }
                    (LogicalRuleMode::Or, false) => {
                        important_domain =
                            first.adguard_domain.as_slice().to_vec();
                        important_regex =
                            first.domain_regex.as_slice().to_vec();
                        if important_domain.is_empty()
                            && important_regex.is_empty()
                        {
                            return invalid();
                        }
                    }
                    _ => return invalid(),
                }
                current = second.clone();
            }
            HeadlessRuleOptions::Default(rule) => {
                let domain = rule.adguard_domain.into_vec();
                let regex = rule.domain_regex.into_vec();
                if domain.is_empty() && regex.is_empty() {
                    return invalid();
                }
                break (domain, regex);
            }
        }
    };

    let mut output = String::new();
    append_rules(&mut output, &important_domain, "", "$important\n");
    append_rules(&mut output, &important_regex, "/", "/$important\n");
    append_rules(&mut output, &important_exclude_domain, "@@", "$important\n");
    append_rules(
        &mut output,
        &important_exclude_regex,
        "@@/",
        "/$important\n",
    );
    append_rules(&mut output, &domain, "", "\n");
    append_rules(&mut output, &regex, "/", "/\n");
    append_rules(&mut output, &exclude_domain, "@@", "\n");
    append_rules(&mut output, &exclude_regex, "@@/", "/\n");
    Ok(output.into_bytes())
}

fn build_filter_rule(lines: Vec<RuleLine>) -> HeadlessRuleOptions {
    let map_domain = |line: &RuleLine| {
        let mut value = if line.suffix {
            format!("||{}", line.value)
        } else if line.start {
            format!("|{}", line.value)
        } else {
            line.value.clone()
        };
        if line.end {
            value.push('^');
        }
        value
    };
    let collect = |important: bool, regex: bool, exclude: bool| {
        lines
            .iter()
            .filter(|line| {
                line.important == important
                    && line.regex == regex
                    && line.exclude == exclude
            })
            .map(&map_domain)
            .collect::<Vec<_>>()
    };

    let important_domain = collect(true, false, false);
    let important_regex = collect(true, true, false);
    let important_exclude_domain = collect(true, false, true);
    let important_exclude_regex = collect(true, true, true);
    let domain = collect(false, false, false);
    let regex = collect(false, true, false);
    let exclude_domain = collect(false, false, true);
    let exclude_regex = collect(false, true, true);

    let mut current = default_rule(Vec::new(), domain, regex, false);
    if !exclude_domain.is_empty() || !exclude_regex.is_empty() {
        current = logical_rule(
            LogicalRuleMode::And,
            default_rule(Vec::new(), exclude_domain, exclude_regex, true),
            current,
        );
    }
    if !important_domain.is_empty() || !important_regex.is_empty() {
        current = logical_rule(
            LogicalRuleMode::Or,
            default_rule(Vec::new(), important_domain, important_regex, false),
            current,
        );
    }
    if !important_exclude_domain.is_empty()
        || !important_exclude_regex.is_empty()
    {
        current = logical_rule(
            LogicalRuleMode::And,
            default_rule(
                Vec::new(),
                important_exclude_domain,
                important_exclude_regex,
                true,
            ),
            current,
        );
    }
    current
}

fn default_rule(
    domain: Vec<String>,
    adguard_domain: Vec<String>,
    domain_regex: Vec<String>,
    invert: bool,
) -> HeadlessRuleOptions {
    HeadlessRuleOptions::Default(Box::new(DefaultHeadlessRuleOptions {
        domain: Listable(domain),
        adguard_domain: Listable(adguard_domain),
        domain_regex: Listable(domain_regex),
        invert,
        ..DefaultHeadlessRuleOptions::default()
    }))
}

fn logical_rule(
    mode: LogicalRuleMode,
    first: HeadlessRuleOptions,
    second: HeadlessRuleOptions,
) -> HeadlessRuleOptions {
    HeadlessRuleOptions::Logical(LogicalHeadlessRuleOptions {
        mode,
        rules: vec![first, second],
        invert: false,
    })
}

fn append_rules(
    output: &mut String,
    rules: &[String],
    prefix: &str,
    suffix: &str,
) {
    for rule in rules {
        output.push_str(prefix);
        output.push_str(rule);
        output.push_str(suffix);
    }
}

fn invalid<T>() -> Result<T, RouteError> {
    Err(RouteError::InvalidRuleSet(INVALID_ADGUARD_RULE_SET.into()))
}

fn parse_hosts_line(line: &str) -> Option<String> {
    let (address, domain) = line.split_once(' ')?;
    let address = address.parse::<IpAddr>().ok()?;
    if !address.is_unspecified() || !is_domain_name(domain) {
        return Some(String::new());
    }
    Some(domain.to_owned())
}

fn is_domain_name(value: &str) -> bool {
    if value == "." {
        return true;
    }
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 254
        || (bytes.len() == 254 && bytes.last() != Some(&b'.'))
    {
        return false;
    }
    let mut last = b'.';
    let mut non_numeric = false;
    let mut label_length = 0;
    for &current in bytes {
        match current {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                label_length += 1;
            }
            b'0'..=b'9' => label_length += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                non_numeric = true;
                label_length += 1;
            }
            b'.' => {
                if matches!(last, b'.' | b'-')
                    || label_length == 0
                    || label_length > 63
                {
                    return false;
                }
                label_length = 0;
            }
            _ => return false,
        }
        last = current;
    }
    last != b'-' && label_length <= 63 && non_numeric
}

fn ignores_ip_cidr_regex(mut value: &str) -> bool {
    if let Some(rest) = value.strip_prefix(r"(http?:\/\/)") {
        value = rest;
    } else if let Some(rest) = value.strip_prefix(r"(https?:\/\/)") {
        value = rest;
    } else if let Some(rest) = value.strip_prefix('^') {
        value = rest;
    }
    value
        .split_once(r"\.")
        .map_or(value, |(first, _)| first)
        .parse::<u8>()
        .is_ok()
        || value
            .split_once('.')
            .map_or(value, |(first, _)| first)
            .parse::<u8>()
            .is_ok()
}

#[cfg(test)]
mod tests {
    use super::{convert_rule_set, export_rule_set, is_domain_name};

    const FILTER: &str = "||sagernet.org^$important\n@@|sing-box.sagernet.org^$important\n||example.org^\n|example.com^\nexample.net^\n||example.edu\n||example.edu.tw^\n|example.gov\nexample.arpa\n@@|sagernet.example.org^\n";

    #[test]
    fn converts_and_round_trips_upstream_filter_fixture() {
        let conversion = convert_rule_set(FILTER.as_bytes()).unwrap();
        assert_eq!(conversion.parsed_lines, 10);
        assert_eq!(conversion.ignored_lines, 0);
        for domain in [
            "example.org",
            "www.example.org",
            "example.com",
            "example.net",
            "isexample.net",
            "www.example.net",
            "example.edu",
            "example.edu.cn",
            "example.edu.tw",
            "www.example.edu",
            "www.example.edu.cn",
            "example.gov",
            "example.gov.cn",
            "example.arpa",
            "www.example.arpa",
            "isexample.arpa",
            "example.arpa.cn",
            "www.example.arpa.cn",
            "isexample.arpa.cn",
            "sagernet.org",
            "www.sagernet.org",
        ] {
            assert_eq!(
                conversion.rule_set.matching_rules(domain).unwrap(),
                [0],
                "{domain}"
            );
        }
        for domain in [
            "example.org.cn",
            "notexample.org",
            "example.com.cn",
            "www.example.com.cn",
            "example.net.cn",
            "notexample.edu",
            "notexample.edu.cn",
            "www.example.gov",
            "notexample.gov",
            "sagernet.example.org",
            "sing-box.sagernet.org",
        ] {
            assert!(
                conversion
                    .rule_set
                    .matching_rules(domain)
                    .unwrap()
                    .is_empty(),
                "{domain}"
            );
        }
        assert_eq!(
            export_rule_set(&conversion.rule_set).unwrap(),
            FILTER.as_bytes()
        );
    }

    #[test]
    fn converts_upstream_hosts_fixture() {
        let conversion = convert_rule_set(
            b"\n127.0.0.1 localhost\n::1 localhost #[IPv6]\n0.0.0.0 google.com\n",
        )
        .unwrap();
        assert_eq!(conversion.parsed_lines, 1);
        assert_eq!(
            conversion.rule_set.matching_rules("google.com").unwrap(),
            [0]
        );
        for domain in ["www.google.com", "notgoogle.com", "localhost"] {
            assert!(
                conversion
                    .rule_set
                    .matching_rules(domain)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn converts_upstream_simple_hosts_fixture() {
        let conversion =
            convert_rule_set(b"\nexample.com\nwww.example.org\n").unwrap();
        for domain in ["example.com", "www.example.org"] {
            assert_eq!(
                conversion.rule_set.matching_rules(domain).unwrap(),
                [0]
            );
        }
        for domain in [
            "example.com.cn",
            "www.example.com",
            "notexample.com",
            "example.org",
        ] {
            assert!(
                conversion
                    .rule_set
                    .matching_rules(domain)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn domain_validation_matches_go_net_contract() {
        for domain in [".", "localhost", "a_b.example", "example.com."] {
            assert!(is_domain_name(domain), "{domain}");
        }
        for domain in [
            "",
            "1234",
            "123.456",
            "-example.com",
            "example-.com",
            "例子.测试",
        ] {
            assert!(!is_domain_name(domain), "{domain}");
        }
    }
}
