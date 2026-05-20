use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

use super::proxy::Proxy;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct HealthCheck {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lazy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ProviderOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_suffix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_name: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ProviderHeader {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<Vec<String>>,
    #[serde(rename = "User-Agent", skip_serializing_if = "Option::is_none")]
    pub user_agent_raw: Option<Vec<String>>,
    #[serde(rename = "Authorization", skip_serializing_if = "Option::is_none")]
    pub authorization_raw: Option<Vec<String>>,
}

/// `proxy-providers` entry (`http` / `file` / `inline`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyProvider {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheck>,
    #[serde(rename = "override", skip_serializing_if = "Option::is_none")]
    pub override_section: Option<ProviderOverride>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Vec<Proxy>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialer_proxy: Option<String>,
}

/// `rule-providers` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleProvider {
    #[serde(rename = "type")]
    pub kind: String,
    pub behavior: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_detour: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
}

pub type ProxyProviders = IndexMap<String, ProxyProvider>;
pub type RuleProviders = IndexMap<String, RuleProvider>;
