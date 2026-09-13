//! Collection and localization of upstream configuration deprecation notes.

use std::{collections::HashSet, net::IpAddr};

use serde_json::Value;

use crate::option::{HttpClientReference, Options, TaggedOptions};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeprecatedNote {
    pub name: &'static str,
    pub description: &'static str,
    pub deprecated_version: &'static str,
    pub scheduled_version: &'static str,
    pub migration_link: &'static str,
}

impl DeprecatedNote {
    pub fn impending(self) -> bool {
        let Some(current_minor) = version_minor(crate::UPSTREAM_VERSION) else {
            return false;
        };
        let Some(scheduled_minor) = version_minor(self.scheduled_version)
        else {
            return false;
        };
        scheduled_minor <= current_minor.saturating_add(1)
    }

    pub fn message_for_locale(self, locale: &str) -> String {
        let has_link = !self.migration_link.is_empty();
        match locale {
            "zh-Hans" => {
                let suffix = "\n\n如果您不明白此消息意味着什么：您的配置文件已过时，且将很快不可用。请联系您的配置提供者以更新配置。";
                if has_link {
                    format!(
                        "{} 已在 sing-box {} 中被弃用，且将在 sing-box {} 中被移除，请参阅迁移指南。{suffix}",
                        self.description,
                        self.deprecated_version,
                        self.scheduled_version
                    )
                } else {
                    format!(
                        "{} 已在 sing-box {} 中被弃用，且将在 sing-box {} 中被移除。{suffix}",
                        self.description,
                        self.deprecated_version,
                        self.scheduled_version
                    )
                }
            }
            "zh-Hant" => {
                if has_link {
                    format!(
                        "{} 已在 sing-box {} 中棄用，且將在 sing-box {} 中移除，請參閱遷移指南。",
                        self.description,
                        self.deprecated_version,
                        self.scheduled_version
                    )
                } else {
                    format!(
                        "{} 已在 sing-box {} 中棄用，且將在 sing-box {} 中移除。",
                        self.description,
                        self.deprecated_version,
                        self.scheduled_version
                    )
                }
            }
            "fa" => {
                if has_link {
                    format!(
                        "{} از sing-box {} منسوخ شده است و در sing-box {} حذف خواهد شد؛ لطفاً راهنمای مهاجرت را ببینید.",
                        self.description,
                        self.deprecated_version,
                        self.scheduled_version
                    )
                } else {
                    format!(
                        "{} از sing-box {} منسوخ شده است و در sing-box {} حذف خواهد شد.",
                        self.description,
                        self.deprecated_version,
                        self.scheduled_version
                    )
                }
            }
            "ru" => {
                if has_link {
                    format!(
                        "Использование {} устарело в sing-box {}, и эта возможность будет удалена в sing-box {}. Ознакомьтесь с руководством по миграции.",
                        self.description,
                        self.deprecated_version,
                        self.scheduled_version
                    )
                } else {
                    format!(
                        "Использование {} устарело в sing-box {}, и эта возможность будет удалена в sing-box {}.",
                        self.description,
                        self.deprecated_version,
                        self.scheduled_version
                    )
                }
            }
            _ => {
                if has_link {
                    format!(
                        "{} is deprecated in sing-box {} and will be removed in sing-box {}. Please check the documentation for migration.",
                        self.description,
                        self.deprecated_version,
                        self.scheduled_version
                    )
                } else {
                    format!(
                        "{} is deprecated in sing-box {} and will be removed in sing-box {}.",
                        self.description,
                        self.deprecated_version,
                        self.scheduled_version
                    )
                }
            }
        }
    }
}

pub const OUTBOUND_DNS_RULE_ITEM: DeprecatedNote = DeprecatedNote {
    name: "outbound-dns-rule-item",
    description: "outbound DNS rule item",
    deprecated_version: "1.12.0",
    scheduled_version: "1.14.0",
    migration_link: "https://sing-box.sagernet.org/migration/#migrate-outbound-dns-rule-items-to-domain-resolver",
};

pub const MISSING_DOMAIN_RESOLVER: DeprecatedNote = DeprecatedNote {
    name: "missing-domain-resolver",
    description: "missing `route.default_domain_resolver` or `domain_resolver` in dial fields",
    deprecated_version: "1.12.0",
    scheduled_version: "1.14.0",
    migration_link: "https://sing-box.sagernet.org/migration/#migrate-outbound-dns-rule-items-to-domain-resolver",
};

pub const LEGACY_DOMAIN_STRATEGY_OPTIONS: DeprecatedNote = DeprecatedNote {
    name: "legacy-domain-strategy-options",
    description: "legacy domain strategy options",
    deprecated_version: "1.12.0",
    scheduled_version: "1.14.0",
    migration_link: "https://sing-box.sagernet.org/migration/#migrate-domain-strategy-options",
};

pub const INLINE_ACME: DeprecatedNote = DeprecatedNote {
    name: "inline-acme-options",
    description: "inline ACME options in TLS",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "https://sing-box.sagernet.org/migration/#migrate-inline-acme-to-certificate-provider",
};

pub const LEGACY_RULE_SET_DOWNLOAD_DETOUR: DeprecatedNote = DeprecatedNote {
    name: "legacy-rule-set-download-detour",
    description: "legacy `download_detour` remote rule-set option",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "",
};

pub const RULE_SET_IP_CIDR_ACCEPT_EMPTY: DeprecatedNote = DeprecatedNote {
    name: "dns-rule-rule-set-ip-cidr-accept-empty",
    description: "Legacy `rule_set_ip_cidr_accept_empty` DNS rule item",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "https://sing-box.sagernet.org/migration/#migrate-address-filter-fields-to-response-matching",
};

pub const LEGACY_DNS_ADDRESS_FILTER: DeprecatedNote = DeprecatedNote {
    name: "legacy-dns-address-filter",
    description: "Legacy Address Filter Fields in DNS rules",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "https://sing-box.sagernet.org/migration/#migrate-address-filter-fields-to-response-matching",
};

pub const LEGACY_DNS_RULE_STRATEGY: DeprecatedNote = DeprecatedNote {
    name: "legacy-dns-rule-strategy",
    description: "Legacy `strategy` DNS rule action option",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "https://sing-box.sagernet.org/migration/#migrate-dns-rule-action-strategy-to-rule-items",
};

pub const INDEPENDENT_DNS_CACHE: DeprecatedNote = DeprecatedNote {
    name: "independent-dns-cache",
    description: "`independent_cache` DNS option",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "https://sing-box.sagernet.org/migration/#migrate-independent-dns-cache",
};

pub const STORE_RDRC: DeprecatedNote = DeprecatedNote {
    name: "store-rdrc",
    description: "`store_rdrc` cache file option",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "https://sing-box.sagernet.org/migration/#migrate-store-rdrc",
};

pub const IMPLICIT_DEFAULT_HTTP_CLIENT: DeprecatedNote = DeprecatedNote {
    name: "implicit-default-http-client",
    description: "implicit default HTTP client using default outbound for remote rule-sets",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "",
};

/// Collect notes at the same configuration boundaries currently implemented by
/// the Rust runtime. Notes are deduplicated by upstream name.
pub fn collect(options: &Options) -> Vec<DeprecatedNote> {
    let mut collector = Collector::default();
    if options
        .dns
        .as_ref()
        .is_some_and(|dns| dns.client.independent_cache)
    {
        collector.push(INDEPENDENT_DNS_CACHE);
    }
    if options
        .experimental
        .as_ref()
        .and_then(|experimental| experimental.cache_file.as_ref())
        .is_some_and(|cache| cache.store_rdrc)
    {
        collector.push(STORE_RDRC);
    }

    if let Some(dns) = &options.dns {
        for rule in &dns.rules {
            collect_dns_rule(
                &rule.to_value().expect("typed DNS rules serialize to JSON"),
                &mut collector,
            );
        }
    }

    let default_domain_resolver = options
        .route
        .as_ref()
        .and_then(|route| route.default_domain_resolver.as_ref())
        .is_some_and(|resolver| !resolver.server.is_empty());
    for tagged in options.outbounds.iter().chain(&options.endpoints) {
        collect_dialer(tagged, default_domain_resolver, &mut collector);
        if contains_nested_key(&Value::Object(tagged.fields.clone()), "acme") {
            collector.push(INLINE_ACME);
        }
    }
    if let Some(dns) = &options.dns {
        for server in &dns.servers {
            let tagged = TaggedOptions {
                kind: server.kind.clone(),
                tag: server.tag.clone(),
                fields: server.fields.clone(),
            };
            collect_dialer(&tagged, default_domain_resolver, &mut collector);
        }
    }

    if let Some(route) = options.route.as_ref() {
        let has_default_http_client = !route.default_http_client.is_empty();
        for rule_set in &route.rule_set {
            let Some(remote) = rule_set.remote() else {
                continue;
            };
            if !remote.download_detour.is_empty() {
                collector.push(LEGACY_RULE_SET_DOWNLOAD_DETOUR);
            }
            let has_http_client = remote.http_client.as_ref().is_some_and(
                |client| match client {
                    HttpClientReference::Tag(tag) => !tag.is_empty(),
                    HttpClientReference::Inline(options) => !options.is_empty(),
                },
            );
            if !has_default_http_client
                && !has_http_client
                && remote.download_detour.is_empty()
            {
                collector.push(IMPLICIT_DEFAULT_HTTP_CLIENT);
            }
        }
    }
    collector.notes
}

#[derive(Default)]
struct Collector {
    names: HashSet<&'static str>,
    notes: Vec<DeprecatedNote>,
}

impl Collector {
    fn push(&mut self, note: DeprecatedNote) {
        if self.names.insert(note.name) {
            self.notes.push(note);
        }
    }
}

fn collect_dns_rule(value: &Value, collector: &mut Collector) {
    let Some(rule) = value.as_object() else {
        return;
    };
    if rule.get("outbound").is_some_and(is_present) {
        collector.push(OUTBOUND_DNS_RULE_ITEM);
    }
    if rule
        .get("rule_set_ip_cidr_accept_empty")
        .is_some_and(is_present)
    {
        collector.push(RULE_SET_IP_CIDR_ACCEPT_EMPTY);
    }
    if ["ip_cidr", "ip_is_private", "ip_accept_any"]
        .iter()
        .any(|key| rule.get(*key).is_some_and(is_present))
    {
        collector.push(LEGACY_DNS_ADDRESS_FILTER);
    }
    if rule.get("strategy").is_some_and(is_present) {
        collector.push(LEGACY_DNS_RULE_STRATEGY);
    }
    if let Some(children) = rule.get("rules").and_then(Value::as_array) {
        for child in children {
            collect_dns_rule(child, collector);
        }
    }
}

fn collect_dialer(
    tagged: &TaggedOptions,
    has_default_domain_resolver: bool,
    collector: &mut Collector,
) {
    if tagged.fields.get("domain_strategy").is_some_and(is_present)
        || tagged
            .fields
            .get("network_strategy")
            .is_some_and(is_present)
    {
        collector.push(LEGACY_DOMAIN_STRATEGY_OPTIONS);
    }
    if has_default_domain_resolver
        || tagged.fields.get("domain_resolver").is_some_and(is_present)
    {
        return;
    }
    let Some(server) = tagged.fields.get("server").and_then(Value::as_str)
    else {
        return;
    };
    if !server.is_empty() && server.parse::<IpAddr>().is_err() {
        collector.push(MISSING_DOMAIN_RESOLVER);
    }
}

fn contains_nested_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(name, value)| {
            (name == key && is_present(value))
                || contains_nested_key(value, key)
        }),
        Value::Array(values) => {
            values.iter().any(|value| contains_nested_key(value, key))
        }
        _ => false,
    }
}

fn is_present(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(_) => true,
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn version_minor(version: &str) -> Option<u64> {
    version
        .trim_start_matches('v')
        .split('.')
        .nth(1)?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::{INDEPENDENT_DNS_CACHE, collect};
    use crate::option::Options;

    #[test]
    fn collects_deduplicates_and_localizes_upstream_notes() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {
                "independent_cache": true,
                "servers": [{"type": "hosts", "tag": "hosts"}],
                "rules": [
                    {"outbound": "proxy", "server": "hosts"},
                    {"outbound": "other", "server": "hosts"}
                ]
            },
            "outbounds": [{
                "type": "socks",
                "tag": "proxy",
                "server": "proxy.example",
                "server_port": 1080,
                "domain_strategy": "ipv4_only"
            }],
            "experimental": {
                "cache_file": {"enabled": true, "store_rdrc": true}
            },
            "route": {
                "rule_set": [{
                    "type": "remote",
                    "tag": "remote",
                    "format": "source",
                    "url": "https://rules.example/rules.json"
                }]
            }
        }))
        .unwrap();
        let notes = collect(&options);
        let names = notes.iter().map(|note| note.name).collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "independent-dns-cache",
                "store-rdrc",
                "outbound-dns-rule-item",
                "legacy-domain-strategy-options",
                "missing-domain-resolver",
                "implicit-default-http-client",
            ]
        );
        assert!(!INDEPENDENT_DNS_CACHE.impending());
        assert!(notes[2].impending());
        assert!(
            notes[2]
                .message_for_locale("en")
                .contains("Please check the documentation for migration")
        );
        assert!(
            notes[2]
                .message_for_locale("zh-Hans")
                .contains("请联系您的配置提供者")
        );
    }
}
