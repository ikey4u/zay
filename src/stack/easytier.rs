//! EasyTier mesh leg for `zay stack --mesh`.

use std::fmt::Write as _;

use anyhow::{Result, bail};

use crate::settings::MeshConfig;

/// Serialize `[mesh]` to EasyTier TOML for `TomlConfigLoader`.
pub fn to_easytier_toml(mesh: &MeshConfig) -> Result<String> {
    let instance_name = mesh.instance_name.as_deref().unwrap_or("zay").trim();
    if instance_name.is_empty() {
        bail!("[mesh].instance_name must not be empty");
    }

    let mut out = String::new();
    writeln!(out, "instance_name = {instance_name:?}")?;
    if let Some(ipv4) = mesh
        .ipv4
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if mesh.dhcp == Some(true) {
            bail!("[mesh].ipv4 requires dhcp = false or omitted");
        }
        writeln!(out, "ipv4 = {ipv4:?}")?;
        writeln!(out, "dhcp = false")?;
    } else if mesh.dhcp.unwrap_or(true) {
        writeln!(out, "dhcp = true")?;
    } else {
        writeln!(out, "dhcp = false")?;
    }
    writeln!(out)?;
    writeln!(out, "[network_identity]")?;
    writeln!(out, "network_name = {:?}", mesh.network_name)?;
    writeln!(out, "network_secret = {:?}", mesh.network_secret)?;

    if let Some(listeners) = &mesh.listeners
        && !listeners.is_empty()
    {
        writeln!(out)?;
        write!(out, "listeners = [")?;
        for (i, l) in listeners.iter().enumerate() {
            if i > 0 {
                write!(out, ", ")?;
            }
            write!(out, "{l:?}")?;
        }
        writeln!(out, "]")?;
    }

    if let Some(peers) = &mesh.peers {
        for peer in peers {
            writeln!(out)?;
            writeln!(out, "[[peer]]")?;
            writeln!(out, "uri = {peer:?}")?;
        }
    }

    if let Some(proxy_networks) = &mesh.proxy_networks {
        for cidr in proxy_networks {
            writeln!(out)?;
            writeln!(out, "[[proxy_network]]")?;
            writeln!(out, "cidr = {cidr:?}")?;
            writeln!(out, "allow = [\"tcp\", \"udp\", \"icmp\"]")?;
        }
    }

    Ok(out)
}

mod imp {
    use std::path::Path;

    use anyhow::{Context, Result};
    use easytier::{
        common::config::{ConfigFileControl, TomlConfigLoader},
        instance_manager::NetworkInstanceManager,
    };
    use once_cell::sync::Lazy;
    use uuid::Uuid;

    use super::to_easytier_toml;
    use crate::settings::MeshConfig;

    static INSTANCE_MANAGER: Lazy<NetworkInstanceManager> =
        Lazy::new(NetworkInstanceManager::new);

    /// Start the mesh network instance (blocking; call from a dedicated thread).
    pub fn start(mesh: &MeshConfig, _data_dir: &Path) -> Result<Uuid> {
        let toml = to_easytier_toml(mesh)?;
        let cfg = TomlConfigLoader::new_from_str(&toml)
            .context("parsing EasyTier mesh config")?;
        let id = INSTANCE_MANAGER
            .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
            .context("starting EasyTier mesh")?;
        eprintln!("mesh started (instance {id})");
        Ok(id)
    }

    /// Stop all EasyTier instances managed by this process.
    pub fn stop_all() -> Result<()> {
        INSTANCE_MANAGER
            .retain_network_instance(Vec::new())
            .context("stopping EasyTier mesh")?;
        Ok(())
    }
}

pub use imp::{start, stop_all};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::MeshConfig;

    fn mesh() -> MeshConfig {
        MeshConfig {
            instance_name: Some("zay".into()),
            network_name: "test-net".into(),
            network_secret: "secret".into(),
            dhcp: None,
            ipv4: None,
            listeners: None,
            peers: None,
            proxy_networks: None,
            mesh_routes: None,
        }
    }

    #[test]
    fn emits_dhcp_by_default() {
        let toml = to_easytier_toml(&mesh()).unwrap();

        assert!(toml.contains("dhcp = true"));
        assert!(!toml.contains("ipv4 ="));
        assert!(!toml.contains("socks5_proxy"));
        assert!(!toml.contains("no_tun"));
    }

    #[test]
    fn emits_static_ipv4_and_disables_dhcp() {
        let mut mesh = mesh();
        mesh.ipv4 = Some("10.126.126.10/24".into());

        let toml = to_easytier_toml(&mesh).unwrap();

        assert!(toml.contains("ipv4 = \"10.126.126.10/24\""));
        assert!(toml.contains("dhcp = false"));
        assert!(!toml.contains("no_tun"));
    }

    #[test]
    fn rejects_static_ipv4_with_dhcp_enabled() {
        let mut mesh = mesh();
        mesh.ipv4 = Some("10.126.126.10/24".into());
        mesh.dhcp = Some(true);

        let err = to_easytier_toml(&mesh).unwrap_err();

        assert!(err.to_string().contains("requires dhcp = false"));
    }
}
