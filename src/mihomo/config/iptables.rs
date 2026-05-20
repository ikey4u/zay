use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct IptablesConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bypass: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_redirect: Option<bool>,
}
