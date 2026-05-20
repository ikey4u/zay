use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct GeoxUrl {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mmdb: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geosite: Option<String>,
}
