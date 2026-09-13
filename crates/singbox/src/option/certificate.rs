//! Managed certificate-provider configuration.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::{Duration, HttpClientReference, Listable};

/// Root certificate bundle selected by the top-level `certificate` block.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum CertificateStoreKind {
    #[default]
    System,
    Mozilla,
    Chrome,
    None,
}

impl CertificateStoreKind {
    pub const fn is_system(&self) -> bool {
        matches!(self, Self::System)
    }

    pub const fn exclusive_anchors(self) -> bool {
        !matches!(self, Self::System)
    }
}

/// Process-wide trust store configuration shared by outbound TLS clients.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateOptions {
    #[serde(default, skip_serializing_if = "CertificateStoreKind::is_system")]
    pub store: CertificateStoreKind,
    #[serde(default, skip_serializing_if = "Listable::is_empty")]
    pub certificate: Listable<String>,
    #[serde(default, skip_serializing_if = "Listable::is_empty")]
    pub certificate_path: Listable<String>,
    #[serde(default, skip_serializing_if = "Listable::is_empty")]
    pub certificate_directory_path: Listable<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeExternalAccountOptions {
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub mac_key: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeDns01CommonOptions {
    #[serde(default)]
    pub ttl: Duration,
    #[serde(default)]
    pub propagation_delay: Duration,
    #[serde(default)]
    pub propagation_timeout: Duration,
    #[serde(default)]
    pub resolvers: Listable<String>,
    #[serde(default)]
    pub override_domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "lowercase", deny_unknown_fields)]
pub enum AcmeDns01ChallengeOptions {
    #[serde(rename = "alidns")]
    AliDns {
        #[serde(flatten)]
        common: AcmeDns01CommonOptions,
        #[serde(default)]
        access_key_id: String,
        #[serde(default)]
        access_key_secret: String,
        #[serde(default)]
        region_id: String,
        #[serde(default)]
        security_token: String,
    },
    Cloudflare {
        #[serde(flatten)]
        common: AcmeDns01CommonOptions,
        #[serde(default)]
        api_token: String,
        #[serde(default)]
        zone_token: String,
    },
    #[serde(rename = "acmedns")]
    AcmeDns {
        #[serde(flatten)]
        common: AcmeDns01CommonOptions,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        subdomain: String,
        #[serde(default)]
        server_url: String,
    },
}

impl AcmeDns01ChallengeOptions {
    pub fn common(&self) -> &AcmeDns01CommonOptions {
        match self {
            Self::AliDns { common, .. }
            | Self::Cloudflare { common, .. }
            | Self::AcmeDns { common, .. } => common,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AcmeKeyType {
    #[default]
    #[serde(rename = "")]
    Default,
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "p256")]
    P256,
    #[serde(rename = "p384")]
    P384,
    #[serde(rename = "rsa2048")]
    Rsa2048,
    #[serde(rename = "rsa4096")]
    Rsa4096,
}

impl AcmeKeyType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "",
            Self::Ed25519 => "ed25519",
            Self::P256 => "p256",
            Self::P384 => "p384",
            Self::Rsa2048 => "rsa2048",
            Self::Rsa4096 => "rsa4096",
        }
    }
}

impl fmt::Display for AcmeKeyType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AcmeKeyType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.to_ascii_lowercase().as_str() {
            "" => Ok(Self::Default),
            "ed25519" => Ok(Self::Ed25519),
            "p256" => Ok(Self::P256),
            "p384" => Ok(Self::P384),
            "rsa2048" => Ok(Self::Rsa2048),
            "rsa4096" => Ok(Self::Rsa4096),
            _ => Err(serde::de::Error::custom(format!(
                "unknown ACME key type: {value}"
            ))),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeCertificateProviderOptions {
    #[serde(default)]
    pub domain: Listable<String>,
    #[serde(default)]
    pub data_directory: String,
    #[serde(default)]
    pub default_server_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub account_key: String,
    #[serde(default)]
    pub disable_http_challenge: bool,
    #[serde(default)]
    pub disable_tls_alpn_challenge: bool,
    #[serde(default)]
    pub alternative_http_port: u16,
    #[serde(default)]
    pub alternative_tls_port: u16,
    #[serde(default)]
    pub external_account: Option<AcmeExternalAccountOptions>,
    #[serde(default)]
    pub dns01_challenge: Option<AcmeDns01ChallengeOptions>,
    #[serde(default)]
    pub key_type: AcmeKeyType,
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub http_client: Option<HttpClientReference>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailscaleCertificateProviderOptions {
    #[serde(default)]
    pub endpoint: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareOriginCaCertificateProviderOptions {
    #[serde(default)]
    pub domain: Listable<String>,
    #[serde(default)]
    pub data_directory: String,
    #[serde(default)]
    pub api_token: String,
    #[serde(default)]
    pub origin_ca_key: String,
    #[serde(default)]
    pub request_type: String,
    #[serde(default)]
    pub requested_validity: u16,
    #[serde(default)]
    pub http_client: Option<HttpClientReference>,
}

#[cfg(test)]
mod tests {
    use super::{
        AcmeCertificateProviderOptions, AcmeDns01ChallengeOptions, AcmeKeyType,
        CloudflareOriginCaCertificateProviderOptions,
    };

    #[test]
    fn decodes_acme_and_origin_ca_provider_options() {
        let acme: AcmeCertificateProviderOptions = serde_json::from_str(
            r#"{"domain":["one.example","two.example"],"provider":"letsencrypt","email":"admin@example.com","key_type":"p256"}"#,
        )
        .unwrap();
        assert_eq!(acme.domain.as_slice().len(), 2);
        assert_eq!(acme.provider, "letsencrypt");
        assert_eq!(acme.key_type, AcmeKeyType::P256);

        let origin: CloudflareOriginCaCertificateProviderOptions =
            serde_json::from_str(
                r#"{"domain":"origin.example","api_token":"secret","request_type":"origin-ecc","requested_validity":365}"#,
            )
            .unwrap();
        assert_eq!(origin.domain.as_slice(), ["origin.example"]);
        assert_eq!(origin.requested_validity, 365);
    }

    #[test]
    fn decodes_strict_acme_extensions() {
        let options: AcmeCertificateProviderOptions = serde_json::from_str(
            r#"{
                "domain": "example.com",
                "external_account": {"key_id":"kid","mac_key":"secret"},
                "dns01_challenge": {
                    "provider":"cloudflare",
                    "api_token":"token",
                    "ttl":"2m",
                    "propagation_delay":"15s",
                    "resolvers":["1.1.1.1","8.8.8.8"],
                    "override_domain":"_acme.example.net"
                },
                "key_type":"RSA4096"
            }"#,
        )
        .unwrap();
        assert_eq!(options.key_type, AcmeKeyType::Rsa4096);
        assert_eq!(options.external_account.unwrap().key_id, "kid");
        let challenge = options.dns01_challenge.unwrap();
        assert_eq!(challenge.common().ttl.to_string(), "2m");
        assert!(matches!(
            challenge,
            AcmeDns01ChallengeOptions::Cloudflare { .. }
        ));

        assert!(
            serde_json::from_str::<AcmeCertificateProviderOptions>(
                r#"{"domain":"example.com","dns01_challenge":{"provider":"route53"}}"#,
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<AcmeCertificateProviderOptions>(
                r#"{"domain":"example.com","dns01_challenge":{"provider":"cloudflare","typo":true}}"#,
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<AcmeCertificateProviderOptions>(
                r#"{"domain":"example.com","key_type":"rsa1024"}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn certificate_provider_options_are_strict() {
        assert!(
            serde_json::from_str::<AcmeCertificateProviderOptions>(
                r#"{"domain":"example.com","unknown":true}"#,
            )
            .is_err()
        );
    }
}
