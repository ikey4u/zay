use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct DnsFallbackFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipcidr: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geosite: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct DnsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefer_h3: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_timeout: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_hosts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_system_hosts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub respect_rules: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enhanced_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_ip_range: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_ip_range6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_ip_filter: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_ip_filter_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_ip_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_nameserver: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nameserver: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_filter: Option<DnsFallbackFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_server_nameserver: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_server_nameserver_policy: Option<IndexMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_nameserver: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_nameserver_follow_policy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nameserver_policy: Option<IndexMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_max_size: Option<i32>,
}
