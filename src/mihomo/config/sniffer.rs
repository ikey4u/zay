use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SnifferConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_destination: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_domain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_src_address: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_dst_address: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_domain: Option<Vec<String>>,
    #[serde(
        rename = "port-whitelist",
        skip_serializing_if = "Option::is_none"
    )]
    pub port_whitelist: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_dns_mapping: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_pure_ip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniff: Option<IndexMap<String, SniffProtocolConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SniffProtocolConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_destination: Option<bool>,
}
