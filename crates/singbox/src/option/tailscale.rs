//! Strongly typed Tailscale option surface from upstream `option/tailscale.go`.

use std::net::SocketAddr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::common::{certificate_store::CertificateStore, ntp::NtpClock};

use super::{DialerOptions, Listable, Prefix, UdpTimeout};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleEndpointOptions {
    #[serde(skip)]
    #[doc(hidden)]
    pub certificate_store: Option<CertificateStore>,
    #[serde(skip)]
    #[doc(hidden)]
    pub ntp_clock: Option<NtpClock>,
    #[serde(default)]
    pub state_directory: String,
    #[serde(default)]
    pub auth_key: String,
    #[serde(default)]
    pub control_url: String,
    #[serde(default)]
    pub ephemeral: bool,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub accept_routes: bool,
    #[serde(default)]
    pub exit_node: String,
    #[serde(default)]
    pub exit_node_allow_lan_access: bool,
    #[serde(default)]
    pub advertise_routes: Vec<Prefix>,
    #[serde(default)]
    pub advertise_exit_node: bool,
    #[serde(default)]
    pub advertise_tags: Listable<String>,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub relay_server_port: Option<u16>,
    #[serde(default)]
    pub relay_server_static_endpoints: Vec<SocketAddr>,
    #[serde(default)]
    pub system_interface: bool,
    #[serde(default)]
    pub system_interface_name: String,
    #[serde(default)]
    pub system_interface_mtu: u32,
    #[serde(default)]
    pub udp_timeout: UdpTimeout,
    #[serde(default)]
    pub ssh_server: Option<TailscaleSshServerOptions>,
    #[serde(default)]
    pub taildrop_directory: String,
    #[serde(flatten)]
    pub dialer: DialerOptions,
}

impl TailscaleEndpointOptions {
    pub(crate) fn set_runtime_context(
        &mut self,
        clock: Option<NtpClock>,
        store: Option<CertificateStore>,
    ) {
        self.ntp_clock = clock;
        self.certificate_store = store;
    }
}

impl TailscaleEndpointOptions {
    pub fn validate(&self) -> Result<(), String> {
        if self
            .advertise_routes
            .iter()
            .any(|prefix| prefix.0.prefix_len() == 0)
        {
            return Err(
                "advertise_routes cannot contain a default route; use advertise_exit_node instead"
                    .into(),
            );
        }
        if self.advertise_exit_node && !self.exit_node.is_empty() {
            return Err(
                "cannot advertise an exit node and use an exit node at the same time"
                    .into(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TailscaleSshServerOptions {
    pub enabled: bool,
    pub disable_pty: bool,
    pub disable_sftp: bool,
    pub disable_forwarding: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TailscaleSshServerObject {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    disable_pty: bool,
    #[serde(default)]
    disable_sftp: bool,
    #[serde(default)]
    disable_forwarding: bool,
}

impl<'de> Deserialize<'de> for TailscaleSshServerOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum BooleanOrObject {
            Boolean(bool),
            Object(TailscaleSshServerObject),
        }
        Ok(match BooleanOrObject::deserialize(deserializer)? {
            BooleanOrObject::Boolean(enabled) => Self {
                enabled,
                ..Self::default()
            },
            BooleanOrObject::Object(options) => Self {
                enabled: options.enabled,
                disable_pty: options.disable_pty,
                disable_sftp: options.disable_sftp,
                disable_forwarding: options.disable_forwarding,
            },
        })
    }
}

impl Serialize for TailscaleSshServerOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !self.disable_pty && !self.disable_sftp && !self.disable_forwarding {
            return self.enabled.serialize(serializer);
        }
        TailscaleSshServerObject {
            enabled: self.enabled,
            disable_pty: self.disable_pty,
            disable_sftp: self.disable_sftp,
            disable_forwarding: self.disable_forwarding,
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailscaleDnsServerOptions {
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub accept_default_resolvers: bool,
    #[serde(default)]
    pub accept_search_domain: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_full_endpoint_and_boolean_or_object_ssh() {
        let options: TailscaleEndpointOptions = serde_json::from_value(
            serde_json::json!({
                "state_directory": "state",
                "auth_key": "tskey-auth-test",
                "control_url": "https://control.example",
                "ephemeral": true,
                "hostname": "node-a",
                "accept_routes": true,
                "exit_node": "100.64.0.1",
                "exit_node_allow_lan_access": true,
                "advertise_routes": ["10.0.0.0/8"],
                "advertise_tags": "tag:server",
                "listen_port": 41641,
                "relay_server_port": 443,
                "relay_server_static_endpoints": ["192.0.2.1:443", "[2001:db8::1]:443"],
                "system_interface": true,
                "system_interface_name": "tailscale0",
                "system_interface_mtu": 1280,
                "udp_timeout": "5m",
                "ssh_server": {
                    "enabled": true,
                    "disable_pty": true,
                    "disable_sftp": true,
                    "disable_forwarding": true
                },
                "taildrop_directory": "Taildrop",
                "detour": "direct"
            }),
        )
        .unwrap();
        assert_eq!(options.listen_port, 41641);
        assert_eq!(options.advertise_tags.0, vec!["tag:server"]);
        assert!(options.ssh_server.unwrap().disable_forwarding);

        let boolean: TailscaleEndpointOptions =
            serde_json::from_value(serde_json::json!({"ssh_server": true}))
                .unwrap();
        assert_eq!(
            serde_json::to_value(boolean.ssh_server.unwrap()).unwrap(),
            serde_json::json!(true)
        );
    }

    #[test]
    fn validates_exit_node_and_default_route_conflicts() {
        let default_route: TailscaleEndpointOptions = serde_json::from_value(
            serde_json::json!({"advertise_routes": ["0.0.0.0/0"]}),
        )
        .unwrap();
        assert!(default_route.validate().is_err());

        let conflict: TailscaleEndpointOptions =
            serde_json::from_value(serde_json::json!({
                "advertise_exit_node": true,
                "exit_node": "100.64.0.1"
            }))
            .unwrap();
        assert!(conflict.validate().is_err());
    }

    #[test]
    fn dns_and_certificate_options_are_strict() {
        let dns: TailscaleDnsServerOptions =
            serde_json::from_value(serde_json::json!({
                "endpoint": "ts",
                "accept_default_resolvers": true,
                "accept_search_domain": true
            }))
            .unwrap();
        assert_eq!(dns.endpoint, "ts");
        assert!(
            serde_json::from_value::<
                crate::option::TailscaleCertificateProviderOptions,
            >(
                serde_json::json!({"endpoint": "ts", "unknown": true})
            )
            .is_err()
        );
    }
}
