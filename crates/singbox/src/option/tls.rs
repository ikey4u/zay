use std::{fmt, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::server::ResolvesServerCert;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::{Map, Value};

use super::{
    AcmeCertificateProviderOptions, DialerOptions, Duration, Listable,
    ServerOptions,
};
use crate::common::{certificate_store::CertificateStore, ntp::NtpClock};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Base64Bytes(pub Vec<u8>);

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        STANDARD
            .decode(encoded)
            .map(Self)
            .map_err(de::Error::custom)
    }
}

impl Serialize for Base64Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
pub enum ClientAuthType {
    #[default]
    #[serde(rename = "no")]
    No,
    #[serde(rename = "request")]
    Request,
    #[serde(rename = "require-any")]
    RequireAny,
    #[serde(rename = "verify-if-given")]
    VerifyIfGiven,
    #[serde(rename = "require-and-verify")]
    RequireAndVerify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurvePreference {
    P256,
    P384,
    P521,
    X25519,
    X25519MlKem768,
}

impl<'de> Deserialize<'de> for CurvePreference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.to_ascii_uppercase().as_str() {
            "P256" => Ok(Self::P256),
            "P384" => Ok(Self::P384),
            "P521" => Ok(Self::P521),
            "X25519" => Ok(Self::X25519),
            "X25519MLKEM768" => Ok(Self::X25519MlKem768),
            _ => Err(de::Error::custom(format!("unknown curve name: {value}"))),
        }
    }
}

impl Serialize for CurvePreference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::P256 => "P256",
            Self::P384 => "P384",
            Self::P521 => "P521",
            Self::X25519 => "X25519",
            Self::X25519MlKem768 => "X25519MLKEM768",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CertificateProviderOptions {
    Reference(String),
    Inline(Map<String, Value>),
}

/// Runtime-only resolver attached after configuration decoding.
///
/// It is deliberately skipped by serde: JSON continues to contain only the
/// upstream-compatible `certificate_provider` reference or inline object.
#[derive(Clone, Default)]
pub(crate) struct CertificateResolverOption(
    pub Option<Arc<dyn ResolvesServerCert>>,
    pub bool,
);

impl fmt::Debug for CertificateResolverOption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CertificateResolverOption")
            .field(&self.0.is_some())
            .field(&self.1)
            .finish()
    }
}

impl PartialEq for CertificateResolverOption {
    fn eq(&self, other: &Self) -> bool {
        self.1 == other.1
            && match (&self.0, &other.0) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct InboundTlsOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub alpn: Listable<String>,
    #[serde(default)]
    pub min_version: String,
    #[serde(default)]
    pub max_version: String,
    #[serde(default)]
    pub cipher_suites: Listable<String>,
    #[serde(default)]
    pub curve_preferences: Listable<CurvePreference>,
    #[serde(default)]
    pub certificate: Listable<String>,
    #[serde(default)]
    pub certificate_path: String,
    #[serde(default)]
    pub client_authentication: ClientAuthType,
    #[serde(default)]
    pub client_certificate: Listable<String>,
    #[serde(default)]
    pub client_certificate_path: Listable<String>,
    #[serde(default)]
    pub client_certificate_public_key_sha256: Listable<Base64Bytes>,
    #[serde(default)]
    pub key: Listable<String>,
    #[serde(default)]
    pub key_path: String,
    #[serde(default)]
    pub kernel_tx: bool,
    #[serde(default)]
    pub kernel_rx: bool,
    #[serde(default)]
    pub handshake_timeout: Duration,
    #[serde(default)]
    pub certificate_provider: Option<CertificateProviderOptions>,
    #[serde(skip)]
    pub(crate) certificate_resolver: CertificateResolverOption,
    #[serde(skip)]
    pub(crate) ntp_clock: Option<NtpClock>,
    #[serde(default)]
    pub acme: Option<AcmeCertificateProviderOptions>,
    #[serde(default)]
    pub ech: Option<InboundEchOptions>,
    #[serde(default)]
    pub reality: Option<InboundRealityOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutboundTlsOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub engine: String,
    #[serde(default)]
    pub disable_sni: bool,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub alpn: Listable<String>,
    #[serde(default)]
    pub min_version: String,
    #[serde(default)]
    pub max_version: String,
    #[serde(default)]
    pub cipher_suites: Listable<String>,
    #[serde(default)]
    pub curve_preferences: Listable<CurvePreference>,
    #[serde(default)]
    pub certificate: Listable<String>,
    #[serde(default)]
    pub certificate_path: String,
    #[serde(default)]
    pub certificate_public_key_sha256: Listable<Base64Bytes>,
    /// Internal embedding hook for protocol-specific TLS options that require
    /// a custom CA bundle without also trusting platform roots.
    #[serde(skip)]
    pub system_trust_disabled: bool,
    /// Runtime-only process-wide trust store. Per-TLS `certificate` and
    /// `certificate_path` settings take precedence over this store.
    #[serde(skip)]
    #[doc(hidden)]
    pub certificate_store: Option<CertificateStore>,
    /// Runtime-only NTP-corrected wall clock used for certificate validity and
    /// TLS ticket age checks by protocol-internal clients.
    #[serde(skip)]
    #[doc(hidden)]
    pub ntp_clock: Option<NtpClock>,
    /// Internal protocol-specific certificate fingerprints. Unlike the
    /// public full SHA-256 pin option, OpenConnect accepts legacy SHA-1 and
    /// abbreviated textual prefixes.
    #[serde(skip)]
    pub server_certificate_fingerprints: Vec<ServerCertificateFingerprint>,
    #[serde(default)]
    pub client_certificate: Listable<String>,
    #[serde(default)]
    pub client_certificate_path: String,
    #[serde(default)]
    pub client_key: Listable<String>,
    #[serde(default)]
    pub client_key_path: String,
    #[serde(default)]
    pub fragment: bool,
    #[serde(default)]
    pub fragment_fallback_delay: Duration,
    #[serde(default)]
    pub record_fragment: bool,
    #[serde(default)]
    pub spoof: String,
    #[serde(default)]
    pub spoof_method: String,
    #[serde(default)]
    pub kernel_tx: bool,
    #[serde(default)]
    pub kernel_rx: bool,
    #[serde(default)]
    pub handshake_timeout: Duration,
    #[serde(default)]
    pub ech: Option<OutboundEchOptions>,
    #[serde(default)]
    pub utls: Option<OutboundUtlsOptions>,
    /// Internal Hysteria2 hook for the Chrome QUIC ClientHello. This is not a
    /// public sing-box TLS option; `disable_chrome_parrot` controls it.
    #[serde(skip)]
    #[doc(hidden)]
    pub chrome_quic_parrot: bool,
    #[serde(default)]
    pub reality: Option<OutboundRealityOptions>,
}

impl OutboundTlsOptions {
    /// Attach a reloadable process-wide certificate store when constructing a
    /// TLS client outside [`crate::Runtime`].
    pub fn with_certificate_store(mut self, store: CertificateStore) -> Self {
        self.certificate_store = Some(store);
        self
    }

    pub(crate) fn with_certificate_store_if_some(
        mut self,
        store: Option<CertificateStore>,
    ) -> Self {
        self.certificate_store = store;
        self
    }

    pub(crate) fn set_runtime_context(
        &mut self,
        clock: Option<NtpClock>,
        store: Option<CertificateStore>,
    ) {
        self.ntp_clock = clock;
        self.certificate_store = store;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerCertificateFingerprintAlgorithm {
    CertificateSha1Hex,
    SpkiSha1Hex,
    SpkiSha256Hex,
    SpkiSha256Base64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCertificateFingerprint {
    pub algorithm: ServerCertificateFingerprintAlgorithm,
    pub encoded_prefix: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundEchOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub key: Listable<String>,
    #[serde(default)]
    pub key_path: String,
    #[serde(default)]
    pub pq_signature_schemes_enabled: bool,
    #[serde(default)]
    pub dynamic_record_sizing_disabled: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundEchOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub config: Listable<String>,
    #[serde(default)]
    pub config_path: String,
    #[serde(default)]
    pub query_server_name: String,
    #[serde(default)]
    pub pq_signature_schemes_enabled: bool,
    #[serde(default)]
    pub dynamic_record_sizing_disabled: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundUtlsOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub fingerprint: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundRealityOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundEchRealityHandshakeOptions {
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(flatten)]
    pub dialer: DialerOptions,
}

pub type InboundRealityHandshakeOptions = InboundEchRealityHandshakeOptions;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundRealityOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub handshake: InboundRealityHandshakeOptions,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub short_id: Listable<String>,
    #[serde(default)]
    pub max_time_difference: Duration,
}

#[cfg(test)]
mod tests {
    use super::{Base64Bytes, CurvePreference, InboundTlsOptions};

    #[test]
    fn curve_names_are_case_insensitive_and_canonicalized() {
        let curve: CurvePreference =
            serde_json::from_str("\"x25519mlkem768\"").unwrap();
        assert_eq!(curve, CurvePreference::X25519MlKem768);
        assert_eq!(
            serde_json::to_string(&curve).unwrap(),
            "\"X25519MLKEM768\""
        );
    }

    #[test]
    fn certificate_hashes_use_go_base64_byte_encoding() {
        let options: InboundTlsOptions = serde_json::from_str(
            r#"{"client_certificate_public_key_sha256":"AQID"}"#,
        )
        .unwrap();
        assert_eq!(
            options.client_certificate_public_key_sha256.as_slice(),
            &[Base64Bytes(vec![1, 2, 3])]
        );
    }

    #[test]
    fn legacy_acme_is_decoded_as_strict_typed_configuration() {
        let options: InboundTlsOptions = serde_json::from_str(
            r#"{"enabled":true,"acme":{"domain":"example.com","key_type":"p256"}}"#,
        )
        .unwrap();
        let acme = options.acme.expect("typed legacy ACME options");
        assert_eq!(acme.domain.as_slice(), ["example.com"]);
        assert_eq!(acme.key_type.as_str(), "p256");

        assert!(
            serde_json::from_str::<InboundTlsOptions>(
                r#"{"enabled":true,"acme":{"domain":"example.com","unknown":true}}"#,
            )
            .is_err()
        );
    }
}
