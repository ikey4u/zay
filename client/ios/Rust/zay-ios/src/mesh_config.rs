//! Build EasyTier TOML for an iOS mesh **node**.
//!
//! iOS has a single Packet Tunnel FD owned by sing-box/Libbox. EasyTier
//! therefore runs with `no_tun=true` and exposes a local SOCKS5 portal;
//! sing-box routes mesh CIDRs to that portal.

use anyhow::{Result, bail};
use serde::Deserialize;

pub const INSTANCE_NAME: &str = "zay-ios";
pub const DEFAULT_SOCKS_PORT: u16 = 18080;

#[derive(Debug, Clone, Deserialize)]
pub struct MeshInput {
    pub network_name: String,
    pub network_secret: String,
    /// EasyTier peer URI, e.g. `tcp://1.2.3.4:11010`.
    pub relay_url: String,
    /// Optional fixed VIP `10.126.126.5/24`. When absent, DHCP is used.
    pub ipv4: Option<String>,
    pub instance_name: Option<String>,
    /// Peer display name shown on other nodes. Defaults to instance_name.
    pub hostname: Option<String>,
    /// Local SOCKS5 portal port (sing-box routes mesh here).
    pub socks_port: Option<u16>,
}

pub fn build_easytier_toml(input: &MeshInput) -> Result<String> {
    let network_name = input.network_name.trim();
    let network_secret = input.network_secret.trim();
    let relay = input.relay_url.trim();
    if network_name.is_empty() {
        bail!("network_name must not be empty");
    }
    if network_secret.is_empty() {
        bail!("network_secret must not be empty");
    }
    if relay.is_empty() {
        bail!("relay_url must not be empty");
    }
    let peer = normalize_peer_uri(relay)?;

    let instance_name = input
        .instance_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(INSTANCE_NAME);

    let hostname = input
        .hostname
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(instance_name);

    let socks_port = input.socks_port.unwrap_or(DEFAULT_SOCKS_PORT);

    let mut out = String::new();
    out.push_str(&format!("instance_name = {instance_name:?}\n"));
    out.push_str(&format!("hostname = {hostname:?}\n"));

    if let Some(ipv4) = input
        .ipv4
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        out.push_str(&format!("ipv4 = {ipv4:?}\n"));
        out.push_str("dhcp = false\n");
    } else {
        out.push_str("dhcp = true\n");
    }

    // SOCKS portal for mesh traffic demuxed by sing-box.
    out.push_str(&format!(
        "socks5_proxy = \"socks5://127.0.0.1:{socks_port}\"\n"
    ));

    // Listeners help LAN P2P when possible; on cellular they are best-effort.
    out.push_str("\nlisteners = [\"tcp://0.0.0.0:11010\", \"udp://0.0.0.0:11010\"]\n");

    out.push_str("\n[[peer]]\n");
    out.push_str(&format!("uri = {peer:?}\n"));

    out.push_str("\n[network_identity]\n");
    out.push_str(&format!("network_name = {network_name:?}\n"));
    out.push_str(&format!("network_secret = {network_secret:?}\n"));

    out.push_str("\n[flags]\n");
    out.push_str("no_tun = true\n");
    out.push_str("default_protocol = \"udp\"\n");
    out.push_str("latency_first = true\n");
    out.push_str("mtu = 1420\n");
    out.push_str("disable_udp_hole_punching = false\n");

    Ok(out)
}

fn normalize_peer_uri(raw: &str) -> Result<String> {
    let t = raw.trim();
    if t.contains("://") {
        let u = url::Url::parse(t).map_err(|e| anyhow::anyhow!("invalid relay_url: {e}"))?;
        match u.scheme() {
            "tcp" | "udp" | "ws" | "wss" | "quic" | "wg" => Ok(t.to_string()),
            other => bail!("unsupported relay scheme: {other}"),
        }
    } else {
        Ok(format!("tcp://{t}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_node_toml() {
        let toml = build_easytier_toml(&MeshInput {
            network_name: "mesh.example".into(),
            network_secret: "s3cret".into(),
            relay_url: "1.2.3.4:11010".into(),
            ipv4: None,
            instance_name: None,
            hostname: Some("iphone-m9".into()),
            socks_port: Some(18080),
        })
        .unwrap();
        assert!(toml.contains("network_name = \"mesh.example\""));
        assert!(toml.contains("hostname = \"iphone-m9\""));
        assert!(toml.contains("uri = \"tcp://1.2.3.4:11010\""));
        assert!(toml.contains("no_tun = true"));
        assert!(toml.contains("socks5_proxy = \"socks5://127.0.0.1:18080\""));
    }
}
