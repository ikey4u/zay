//! HTTP client options shared by remote resources and services.

use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Map, Value};

use super::{DialerOptions, Duration, MemoryBytes, OutboundTlsOptions};

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct HttpClientOptions {
    #[serde(default)]
    pub engine: String,
    #[serde(default)]
    pub version: u8,
    #[serde(default)]
    pub disable_version_fallback: bool,
    #[serde(default)]
    pub headers: Map<String, Value>,
    #[serde(default)]
    pub tls: Option<OutboundTlsOptions>,
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(default)]
    pub idle_timeout: Duration,
    #[serde(default)]
    pub keep_alive_period: Duration,
    #[serde(default)]
    pub stream_receive_window: MemoryBytes,
    #[serde(default)]
    pub connection_receive_window: MemoryBytes,
    #[serde(default)]
    pub max_concurrent_streams: i32,
    #[serde(default)]
    pub initial_packet_size: i32,
    #[serde(default)]
    pub disable_path_mtu_discovery: bool,
}

impl<'de> Deserialize<'de> for HttpClientOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| de::Error::custom("HTTP client is not an object"))?;
        const KEYS: &[&str] = &[
            "engine",
            "version",
            "disable_version_fallback",
            "headers",
            "tls",
            "detour",
            "bind_interface",
            "inet4_bind_address",
            "inet6_bind_address",
            "bind_address_no_port",
            "protect_path",
            "routing_mark",
            "reuse_addr",
            "netns",
            "connect_timeout",
            "tcp_fast_open",
            "tcp_multi_path",
            "disable_tcp_keep_alive",
            "tcp_keep_alive",
            "tcp_keep_alive_interval",
            "udp_fragment",
            "domain_resolver",
            "network_strategy",
            "network_type",
            "fallback_network_type",
            "fallback_delay",
            "domain_strategy",
            "idle_timeout",
            "keep_alive_period",
            "stream_receive_window",
            "connection_receive_window",
            "max_concurrent_streams",
            "initial_packet_size",
            "disable_path_mtu_discovery",
        ];
        if let Some(key) =
            object.keys().find(|key| !KEYS.contains(&key.as_str()))
        {
            return Err(de::Error::unknown_field(key, KEYS));
        }

        #[derive(Default, Deserialize)]
        struct Raw {
            #[serde(default)]
            engine: String,
            #[serde(default)]
            version: u8,
            #[serde(default)]
            disable_version_fallback: bool,
            #[serde(default)]
            headers: Map<String, Value>,
            #[serde(default)]
            tls: Option<OutboundTlsOptions>,
            #[serde(flatten)]
            dialer: DialerOptions,
            #[serde(default)]
            idle_timeout: Duration,
            #[serde(default)]
            keep_alive_period: Duration,
            #[serde(default)]
            stream_receive_window: MemoryBytes,
            #[serde(default)]
            connection_receive_window: MemoryBytes,
            #[serde(default)]
            max_concurrent_streams: i32,
            #[serde(default)]
            initial_packet_size: i32,
            #[serde(default)]
            disable_path_mtu_discovery: bool,
        }
        let raw: Raw =
            serde_json::from_value(value).map_err(de::Error::custom)?;
        Ok(Self {
            engine: raw.engine,
            version: raw.version,
            disable_version_fallback: raw.disable_version_fallback,
            headers: raw.headers,
            tls: raw.tls,
            dialer: raw.dialer,
            idle_timeout: raw.idle_timeout,
            keep_alive_period: raw.keep_alive_period,
            stream_receive_window: raw.stream_receive_window,
            connection_receive_window: raw.connection_receive_window,
            max_concurrent_streams: raw.max_concurrent_streams,
            initial_packet_size: raw.initial_packet_size,
            disable_path_mtu_discovery: raw.disable_path_mtu_discovery,
        })
    }
}

impl HttpClientOptions {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Validate the transport shape independently from runtime construction.
    ///
    /// In particular, the Apple engine has a deliberately smaller option
    /// surface because it is implemented by `NSURLSession`, matching the
    /// upstream sing-box validation boundary.
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.engine.as_str(), "" | "go" | "apple") {
            return Err(format!("unknown HTTP engine: {}", self.engine));
        }
        if self.version > 3 {
            return Err(format!("unknown HTTP version: {}", self.version));
        }
        if self.engine == "apple" {
            self.validate_apple()?;
        }
        Ok(())
    }

    fn validate_apple(&self) -> Result<(), String> {
        match self.version {
            0 | 2 => {}
            1 => {
                return Err(
                    "HTTP/1.1 is unsupported in Apple HTTP engine".into()
                );
            }
            3 => {
                return Err("HTTP/3 is unsupported in Apple HTTP engine".into());
            }
            version => return Err(format!("unknown HTTP version: {version}")),
        }
        if self.disable_version_fallback {
            return Err(
                "disable_version_fallback is unsupported in Apple HTTP engine"
                    .into(),
            );
        }
        if self.idle_timeout != Duration::default()
            || self.keep_alive_period != Duration::default()
            || self.stream_receive_window != MemoryBytes::default()
            || self.connection_receive_window != MemoryBytes::default()
            || self.max_concurrent_streams != 0
        {
            return Err(
                "HTTP/2 options are unsupported in Apple HTTP engine".into()
            );
        }
        if self.initial_packet_size != 0 || self.disable_path_mtu_discovery {
            return Err(
                "QUIC options are unsupported in Apple HTTP engine".into()
            );
        }
        let Some(tls) = self.tls.as_ref() else {
            return Ok(());
        };
        if !tls.engine.is_empty() {
            return Err("tls.engine is unsupported in Apple HTTP engine".into());
        }
        if !tls.alpn.as_slice().is_empty() {
            return Err("tls.alpn is unsupported in Apple HTTP engine".into());
        }
        if tls.reality.as_ref().is_some_and(|options| options.enabled) {
            return Err("reality is unsupported in Apple HTTP engine".into());
        }
        if tls.utls.as_ref().is_some_and(|options| options.enabled) {
            return Err("utls is unsupported in Apple HTTP engine".into());
        }
        if tls.ech.as_ref().is_some_and(|options| options.enabled) {
            return Err("ech is unsupported in Apple HTTP engine".into());
        }
        if tls.disable_sni {
            return Err(
                "disable_sni is unsupported in Apple HTTP engine".into()
            );
        }
        if !tls.cipher_suites.as_slice().is_empty() {
            return Err(
                "cipher_suites is unsupported in Apple HTTP engine".into()
            );
        }
        if !tls.curve_preferences.as_slice().is_empty() {
            return Err(
                "curve_preferences is unsupported in Apple HTTP engine".into(),
            );
        }
        if !tls.client_certificate.as_slice().is_empty()
            || !tls.client_certificate_path.is_empty()
            || !tls.client_key.as_slice().is_empty()
            || !tls.client_key_path.is_empty()
        {
            return Err(
                "client certificate is unsupported in Apple HTTP engine".into(),
            );
        }
        if tls.fragment || tls.record_fragment {
            return Err(
                "tls fragment is unsupported in Apple HTTP engine".into()
            );
        }
        if tls.kernel_tx || tls.kernel_rx {
            return Err("ktls is unsupported in Apple HTTP engine".into());
        }
        if !tls.spoof.is_empty() || !tls.spoof_method.is_empty() {
            return Err("spoof is unsupported in Apple HTTP engine".into());
        }
        if !tls.certificate_public_key_sha256.as_slice().is_empty()
            && (!tls.certificate.as_slice().is_empty()
                || !tls.certificate_path.is_empty())
        {
            return Err("certificate_public_key_sha256 is conflict with certificate or certificate_path".into());
        }
        if let Some(pin) = tls
            .certificate_public_key_sha256
            .as_slice()
            .iter()
            .find(|pin| pin.0.len() != 32)
        {
            return Err(format!(
                "invalid certificate_public_key_sha256 length: {}",
                pin.0.len()
            ));
        }
        let minimum = apple_tls_version(&tls.min_version, "min_version")?;
        let maximum = apple_tls_version(&tls.max_version, "max_version")?;
        if minimum.unwrap_or(0x0301) > maximum.unwrap_or(0x0304) {
            return Err(
                "minimum TLS version exceeds maximum TLS version".into()
            );
        }
        Ok(())
    }
}

fn apple_tls_version(value: &str, field: &str) -> Result<Option<u16>, String> {
    match value {
        "" => Ok(None),
        "1.0" => Ok(Some(0x0301)),
        "1.1" => Ok(Some(0x0302)),
        "1.2" => Ok(Some(0x0303)),
        "1.3" => Ok(Some(0x0304)),
        value => Err(format!("parse {field}: invalid TLS version {value:?}")),
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct HttpClient {
    #[serde(default)]
    pub tag: String,
    #[serde(flatten)]
    pub options: HttpClientOptions,
}

impl<'de> Deserialize<'de> for HttpClient {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = Value::deserialize(deserializer)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| de::Error::custom("HTTP client is not an object"))?;
        let tag = object
            .remove("tag")
            .map(serde_json::from_value)
            .transpose()
            .map_err(de::Error::custom)?
            .unwrap_or_default();
        let options =
            serde_json::from_value(value).map_err(de::Error::custom)?;
        Ok(Self { tag, options })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HttpClientReference {
    Tag(String),
    Inline(Box<HttpClientOptions>),
}

#[cfg(test)]
mod tests {
    use super::{HttpClient, HttpClientOptions, HttpClientReference};
    use crate::option::Options;

    #[test]
    fn decodes_named_and_inline_http_clients() {
        let client: HttpClient = serde_json::from_str(
            r#"{"tag":"rules","version":2,"headers":{"X-Test":["one","two"]},"detour":"proxy","tls":{"enabled":true,"server_name":"rules.example"},"idle_timeout":"30s"}"#,
        )
        .unwrap();
        assert_eq!(client.tag, "rules");
        assert_eq!(client.options.version, 2);
        assert_eq!(client.options.dialer.detour, "proxy");
        assert_eq!(
            client.options.tls.as_ref().unwrap().server_name,
            "rules.example"
        );

        let reference: HttpClientReference =
            serde_json::from_str(r#""rules""#).unwrap();
        assert_eq!(reference, HttpClientReference::Tag("rules".into()));
        let reference: HttpClientReference =
            serde_json::from_str(r#"{"version":1}"#).unwrap();
        assert!(matches!(reference, HttpClientReference::Inline(_)));
    }

    #[test]
    fn rejects_unknown_http_client_fields_and_versions_outside_schema() {
        assert!(
            serde_json::from_str::<HttpClient>(
                r#"{"tag":"rules","unknown":true}"#
            )
            .is_err()
        );
        let options: Options = serde_json::from_str(
            r#"{"http_clients":[{"tag":"rules","version":4}]}"#,
        )
        .unwrap();
        assert!(options.validate().is_err());
    }

    #[test]
    fn validates_apple_http_engine_option_boundary() {
        let valid: HttpClientOptions =
            serde_json::from_value(serde_json::json!({
                "engine":"apple",
                "version":2,
                "tls":{
                    "enabled":true,
                    "server_name":"rules.example",
                    "min_version":"1.0",
                    "max_version":"1.3"
                }
            }))
            .unwrap();
        valid.validate().unwrap();

        for (value, expected) in [
            (
                serde_json::json!({"engine":"apple","version":1}),
                "HTTP/1.1 is unsupported",
            ),
            (
                serde_json::json!({
                    "engine":"apple",
                    "disable_version_fallback":true
                }),
                "disable_version_fallback is unsupported",
            ),
            (
                serde_json::json!({
                    "engine":"apple",
                    "idle_timeout":"1s"
                }),
                "HTTP/2 options are unsupported",
            ),
            (
                serde_json::json!({
                    "engine":"apple",
                    "tls":{"utls":{"enabled":true}}
                }),
                "utls is unsupported",
            ),
            (
                serde_json::json!({
                    "engine":"apple",
                    "tls":{"certificate_public_key_sha256":"AQID"}
                }),
                "invalid certificate_public_key_sha256 length: 3",
            ),
            (
                serde_json::json!({
                    "engine":"apple",
                    "tls":{"min_version":"1.3","max_version":"1.2"}
                }),
                "minimum TLS version exceeds maximum TLS version",
            ),
        ] {
            let options: HttpClientOptions =
                serde_json::from_value(value).unwrap();
            let error = options.validate().unwrap_err();
            assert!(
                error.contains(expected),
                "expected {expected:?} in {error:?}"
            );
        }
    }
}
