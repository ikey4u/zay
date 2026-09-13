//! Strongly typed Cloudflare Tunnel inbound options.

use serde::{Deserialize, Serialize};

use super::{DialerOptions, Duration};
use crate::protocol::cloudflared::{
    CloudflaredProtocolSelection, parse_cloudflared_token,
};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflaredInboundOptions {
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub ha_connections: i32,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub post_quantum: bool,
    #[serde(default)]
    pub edge_ip_version: i32,
    #[serde(default)]
    pub datagram_version: String,
    #[serde(default)]
    pub grace_period: Duration,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub control_dialer: DialerOptions,
    #[serde(default)]
    pub tunnel_dialer: DialerOptions,
}

impl CloudflaredInboundOptions {
    pub fn validate(&self) -> Result<(), String> {
        let credentials = parse_cloudflared_token(&self.token)
            .map_err(|error| error.to_string())?;
        CloudflaredProtocolSelection::new(&self.protocol, self.post_quantum)
            .map_err(|error| error.to_string())?;
        if !matches!(self.edge_ip_version, 0 | 4 | 6) {
            return Err(format!(
                "unsupported edge_ip_version: {}, expected 0, 4 or 6",
                self.edge_ip_version
            ));
        }
        if !matches!(self.datagram_version.as_str(), "" | "v2" | "v3") {
            return Err(format!(
                "unsupported datagram_version: {}, expected v2 or v3",
                self.datagram_version
            ));
        }
        if !self.region.is_empty() && !credentials.endpoint.is_empty() {
            return Err(
                "region cannot be specified when credentials already include an endpoint"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn effective_ha_connections(&self) -> usize {
        usize::try_from(self.ha_connections)
            .ok()
            .filter(|connections| *connections > 0)
            .unwrap_or(4)
    }

    pub fn effective_grace_period(&self) -> std::time::Duration {
        self.grace_period
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(std::time::Duration::from_secs(30))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "eyJhIjoiYWNjb3VudDEyMyIsInQiOiI1NTBlODQwMC1lMjlhLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJzIjoiYzJWamNtVjBMVE15TFdKNWRHVnpMV3h2Ym1jdGVIZz0iLCJlIjoiZmVkIn0=";

    #[test]
    fn cloudflared_options_match_upstream_defaults_and_validation() {
        let options: CloudflaredInboundOptions =
            serde_json::from_value(serde_json::json!({
                "token": TOKEN,
                "protocol": "auto",
                "edge_ip_version": 6,
                "datagram_version": "v3",
                "control_dialer": {"detour": "control"},
                "tunnel_dialer": {"detour": "tunnel"}
            }))
            .unwrap();
        options.validate().unwrap();
        assert_eq!(options.effective_ha_connections(), 4);
        assert_eq!(
            options.effective_grace_period(),
            std::time::Duration::from_secs(30)
        );
        assert_eq!(options.control_dialer.detour, "control");
        assert_eq!(options.tunnel_dialer.detour, "tunnel");

        for invalid in [
            serde_json::json!({"token": "bad"}),
            serde_json::json!({"token": TOKEN, "protocol": "http2", "post_quantum": true}),
            serde_json::json!({"token": TOKEN, "edge_ip_version": 5}),
            serde_json::json!({"token": TOKEN, "datagram_version": "v1"}),
            serde_json::json!({"token": TOKEN, "region": "other"}),
        ] {
            assert!(
                serde_json::from_value::<CloudflaredInboundOptions>(invalid)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }
}
