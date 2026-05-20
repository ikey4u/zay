use serde::{Deserialize, Serialize};

/// `proxy-groups` entry (discriminated by `type` in YAML).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ProxyGroup {
    #[serde(rename = "select")]
    Select(SelectGroup),
    #[serde(rename = "url-test")]
    UrlTest(UrlTestGroup),
    #[serde(rename = "fallback")]
    Fallback(FallbackGroup),
    #[serde(rename = "load-balance")]
    LoadBalance(LoadBalanceGroup),
    #[serde(rename = "relay")]
    Relay(RelayGroup),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectGroup {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(rename = "disable-udp", skip_serializing_if = "Option::is_none")]
    pub disable_udp: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlTestGroup {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tolerance: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lazy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackGroup {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalanceGroup {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayGroup {
    pub name: String,
    pub proxies: Vec<String>,
}
