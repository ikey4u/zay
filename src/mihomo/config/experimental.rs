use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ExperimentalConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprints: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quic_go_disable_gso: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quic_go_disable_ecn: Option<bool>,
    #[serde(
        rename = "dialer-ip4p-convert",
        skip_serializing_if = "Option::is_none"
    )]
    pub dialer_ip4p_convert: Option<bool>,
}
