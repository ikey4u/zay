//! Strongly typed OpenConnect endpoint options.

use serde::{Deserialize, Serialize};

use crate::common::{certificate_store::CertificateStore, ntp::NtpClock};

use super::{DialerOptions, Duration, Listable, UdpNatBehavior};

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenConnectEndpointOptions {
    #[serde(skip)]
    #[doc(hidden)]
    pub certificate_store: Option<CertificateStore>,
    #[serde(skip)]
    #[doc(hidden)]
    pub ntp_clock: Option<NtpClock>,
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(default)]
    pub system: bool,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub udp_timeout: Duration,
    #[serde(default)]
    pub udp_mapping: UdpNatBehavior,
    #[serde(default)]
    pub udp_filtering: UdpNatBehavior,
    #[serde(default)]
    pub udp_nat_max: u32,
    pub server: String,
    #[serde(default)]
    pub flavor: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub auth_group: String,
    #[serde(default)]
    pub cookie: String,
    #[serde(default)]
    pub token: Option<OpenConnectTokenOptions>,
    #[serde(default)]
    pub reported_os: String,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub local_hostname: String,
    #[serde(default)]
    pub mobile: Option<OpenConnectMobileOptions>,
    #[serde(default)]
    pub csd: Option<OpenConnectCsdOptions>,
    #[serde(default)]
    pub hip: Option<OpenConnectHipOptions>,
    #[serde(default)]
    pub tncc: Option<OpenConnectTnccOptions>,
    #[serde(default)]
    pub fortinet_host_check: Option<OpenConnectFortinetHostCheckOptions>,
    #[serde(default)]
    pub no_udp: bool,
    #[serde(default)]
    pub dtls_local_port: u16,
    #[serde(default)]
    pub compression_disabled: bool,
    #[serde(default)]
    pub compression_mode: String,
    #[serde(default)]
    pub ipv6_disabled: bool,
    #[serde(default)]
    pub http_keep_alive_disabled: bool,
    #[serde(default)]
    pub xml_post_disabled: bool,
    #[serde(default)]
    pub external_auth_disabled: bool,
    #[serde(default)]
    pub password_authentication_disabled: bool,
    #[serde(default)]
    pub tcp_keep_alive_enabled: bool,
    #[serde(default)]
    pub pfs: bool,
    #[serde(default)]
    pub mtu: u32,
    #[serde(default)]
    pub base_mtu: u32,
    #[serde(default)]
    pub dpd_interval: Duration,
    #[serde(default)]
    pub reconnect_timeout: Duration,
    #[serde(default)]
    pub trojan_interval: Duration,
    #[serde(default)]
    pub queue_length: u32,
    #[serde(default)]
    pub allow_insecure_crypto: bool,
    #[serde(default)]
    pub tls: OpenConnectTlsOptions,
    #[serde(default)]
    pub form_entries: Vec<OpenConnectFormEntryOptions>,
}

impl OpenConnectEndpointOptions {
    pub(crate) fn server_is_domain(&self) -> bool {
        let normalized = if self.server.contains("://") {
            self.server.clone()
        } else {
            format!("https://{}", self.server)
        };
        url::Url::parse(&normalized)
            .ok()
            .is_some_and(|url| matches!(url.host(), Some(url::Host::Domain(_))))
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

impl OpenConnectEndpointOptions {
    pub fn validate(&self) -> Result<(), String> {
        if self.server.trim().is_empty() {
            return Err("missing server".into());
        }
        if !matches!(
            self.flavor.as_str(),
            "" | "anyconnect" | "gp" | "fortinet" | "f5" | "pulse" | "nc"
        ) {
            return Err(format!("unknown flavor: {}", self.flavor));
        }
        if !matches!(self.compression_mode.as_str(), "" | "stateless" | "all") {
            return Err(format!(
                "unknown compression_mode: {}",
                self.compression_mode
            ));
        }
        if let Some(token) = &self.token {
            token.validate()?;
        }
        let keepalive_configured = self.tcp_keep_alive_enabled
            || self.dialer.abstract_options.tcp_keep_alive != Duration::ZERO
            || self.dialer.abstract_options.tcp_keep_alive_interval
                != Duration::ZERO;
        if keepalive_configured
            && self.dialer.abstract_options.disable_tcp_keep_alive
        {
            return Err(
                "tcp_keep_alive_enabled conflicts with disable_tcp_keep_alive"
                    .into(),
            );
        }
        validate_material_pair(
            "tls.certificate_authority",
            self.tls.certificate_authority.as_slice(),
            &self.tls.certificate_authority_path,
        )?;
        validate_material_pair(
            "tls.client_certificate",
            self.tls.client_certificate.as_slice(),
            &self.tls.client_certificate_path,
        )?;
        validate_material_pair(
            "tls.client_key",
            self.tls.client_key.as_slice(),
            &self.tls.client_key_path,
        )?;
        validate_material_pair(
            "tls.mca_certificate",
            self.tls.mca_certificate.as_slice(),
            &self.tls.mca_certificate_path,
        )?;
        validate_material_pair(
            "tls.mca_key",
            self.tls.mca_key.as_slice(),
            &self.tls.mca_key_path,
        )?;
        if let Some(tncc) = &self.tncc {
            if tncc
                .device_id
                .bytes()
                .any(|byte| matches!(byte, b';' | b'\r' | b'\n'))
            {
                return Err(
                    "TNCC device ID contains a protocol delimiter".into()
                );
            }
            if tncc
                .user_agent
                .bytes()
                .any(|byte| matches!(byte, b'\r' | b'\n'))
            {
                return Err("TNCC user agent contains a line delimiter".into());
            }
            if !tncc.wrapper_path.is_empty()
                && (!tncc.device_id.is_empty()
                    || !tncc.user_agent.is_empty()
                    || tncc.machine_identification_enabled
                    || !tncc.certificates.is_empty())
            {
                return Err(
                    "external Network Connect TNCC wrapper options cannot be combined with built-in TNCC identity options"
                        .into(),
                );
            }
            if !tncc.certificates.is_empty()
                && !tncc.machine_identification_enabled
            {
                return Err(
                    "TNCC certificates require machine identification".into()
                );
            }
            for (index, certificate) in tncc.certificates.iter().enumerate() {
                validate_material_pair(
                    &format!("tncc.certificates[{index}].certificate"),
                    certificate.certificate.as_slice(),
                    &certificate.certificate_path,
                )?;
            }
        }
        Ok(())
    }
}

fn validate_material_pair(
    name: &str,
    inline: &[String],
    path: &str,
) -> Result<(), String> {
    if !inline.is_empty() && !path.is_empty() {
        Err(format!("{name} contains both inline content and path"))
    } else {
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectTokenOptions {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub secret_path: String,
    #[serde(default)]
    pub pin: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub counter: u64,
}

impl OpenConnectTokenOptions {
    fn validate(&self) -> Result<(), String> {
        if !matches!(
            self.mode.as_str(),
            "" | "totp" | "hotp" | "stoken" | "oidc"
        ) {
            return Err(format!("unknown token mode: {}", self.mode));
        }
        if !self.secret.is_empty() && !self.secret_path.is_empty() {
            return Err("token contains both secret and secret_path".into());
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectMobileOptions {
    pub platform_version: String,
    pub device_type: String,
    pub device_unique_id: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectCsdOptions {
    #[serde(default)]
    pub wrapper_path: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectHipOptions {
    #[serde(default)]
    pub wrapper_path: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectTnccOptions {
    #[serde(default)]
    pub wrapper_path: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub machine_identification_enabled: bool,
    #[serde(default)]
    pub certificates: Vec<OpenConnectTnccCertificateOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectTnccCertificateOptions {
    #[serde(default)]
    pub certificate: Listable<String>,
    #[serde(default)]
    pub certificate_path: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectFortinetHostCheckOptions {
    #[serde(default)]
    pub hostcheck: String,
    #[serde(default)]
    pub check_virtual_desktop: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectTlsOptions {
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub peer_fingerprint: Listable<String>,
    #[serde(default)]
    pub system_trust_disabled: bool,
    #[serde(default)]
    pub certificate_authority: Listable<String>,
    #[serde(default)]
    pub certificate_authority_path: String,
    #[serde(default)]
    pub client_certificate: Listable<String>,
    #[serde(default)]
    pub client_certificate_path: String,
    #[serde(default)]
    pub client_key: Listable<String>,
    #[serde(default)]
    pub client_key_path: String,
    #[serde(default)]
    pub client_key_password: String,
    #[serde(default)]
    pub mca_certificate: Listable<String>,
    #[serde(default)]
    pub mca_certificate_path: String,
    #[serde(default)]
    pub mca_key: Listable<String>,
    #[serde(default)]
    pub mca_key_path: String,
    #[serde(default)]
    pub mca_key_password: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectFormEntryOptions {
    #[serde(default)]
    pub form_id: String,
    #[serde(default)]
    pub submission_key: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub promote: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectDnsServerOptions {
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub accept_default_resolvers: bool,
    #[serde(default)]
    pub accept_search_domain: bool,
}

#[cfg(test)]
mod tests {
    use super::OpenConnectEndpointOptions;

    #[test]
    fn decodes_full_endpoint_and_flattened_dialer_fields() {
        let options: OpenConnectEndpointOptions = serde_json::from_str(
            r#"{
                "server":"https://vpn.example",
                "flavor":"gp",
                "username":"alice",
                "token":{"mode":"hotp","secret":"JBSWY3DPEHPK3PXP","counter":7},
                "mobile":{"platform_version":"17.0","device_type":"iPhone","device_unique_id":"device"},
                "compression_mode":"all",
                "tls":{"server_name":"vpn.example","peer_fingerprint":["pin"]},
                "form_entries":[{"form_id":"main","name":"password","value":"secret"}],
                "detour":"bootstrap"
            }"#,
        )
        .unwrap();
        assert_eq!(options.flavor, "gp");
        assert_eq!(options.token.as_ref().unwrap().counter, 7);
        assert_eq!(options.dialer.detour, "bootstrap");
        assert!(options.server_is_domain());
        assert!(options.validate().is_ok());
    }

    #[test]
    fn detects_domain_and_ip_server_urls() {
        for server in ["vpn.example", "https://vpn.example:8443/path"] {
            let options: OpenConnectEndpointOptions =
                serde_json::from_value(serde_json::json!({"server": server}))
                    .unwrap();
            assert!(options.server_is_domain(), "{server}");
        }
        for server in ["192.0.2.1", "https://[2001:db8::1]:443/"] {
            let options: OpenConnectEndpointOptions =
                serde_json::from_value(serde_json::json!({"server": server}))
                    .unwrap();
            assert!(!options.server_is_domain(), "{server}");
        }
    }

    #[test]
    fn validates_flavor_keepalive_token_and_material_conflicts() {
        for value in [
            serde_json::json!({"server":"vpn.example","flavor":"other"}),
            serde_json::json!({"server":"vpn.example","token":{"mode":"bad"}}),
            serde_json::json!({"server":"vpn.example","tcp_keep_alive_enabled":true,"disable_tcp_keep_alive":true}),
            serde_json::json!({"server":"vpn.example","tls":{"client_certificate":"cert","client_certificate_path":"cert.pem"}}),
            serde_json::json!({"server":"vpn.example","flavor":"nc","tncc":{"device_id":"bad;id"}}),
            serde_json::json!({"server":"vpn.example","flavor":"nc","tncc":{"user_agent":"bad\nagent"}}),
            serde_json::json!({"server":"vpn.example","flavor":"nc","tncc":{"wrapper_path":"/wrapper","device_id":"device"}}),
            serde_json::json!({"server":"vpn.example","flavor":"nc","tncc":{"certificates":[{"certificate":"cert"}]}}),
        ] {
            let options: OpenConnectEndpointOptions =
                serde_json::from_value(value).unwrap();
            assert!(options.validate().is_err());
        }
    }
}
