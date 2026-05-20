use serde::{Deserialize, Serialize};

/// `tunnels` entry (one-line string or structured mapping).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TunnelEntry {
    OneLine(String),
    Structured(TunnelConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct TunnelConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
}
