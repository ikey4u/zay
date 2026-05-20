use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct TlsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_auth_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_auth_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ech_key: Option<String>,
    #[serde(
        rename = "custom-certifactes",
        skip_serializing_if = "Option::is_none"
    )]
    pub custom_certificates: Option<Vec<String>>,
}
