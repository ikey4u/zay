//! EasyTier mesh leg for `zay stack --mesh`.

#[cfg(not(windows))]
mod imp {
    use std::fmt::Write as _;

    use anyhow::{Context, Result, bail};
    use easytier::{
        common::config::{ConfigFileControl, TomlConfigLoader},
        instance_manager::NetworkInstanceManager,
    };
    use once_cell::sync::Lazy;
    use uuid::Uuid;

    use crate::settings::MeshConfig;

    static INSTANCE_MANAGER: Lazy<NetworkInstanceManager> =
        Lazy::new(NetworkInstanceManager::new);

    /// Serialize `[mesh]` to EasyTier TOML for `TomlConfigLoader`.
    pub fn to_easytier_toml(mesh: &MeshConfig) -> Result<String> {
        let instance_name =
            mesh.instance_name.as_deref().unwrap_or("zay").trim();
        if instance_name.is_empty() {
            bail!("[mesh].instance_name must not be empty");
        }

        let mut out = String::new();
        writeln!(out, "instance_name = {instance_name:?}")?;
        if mesh.dhcp.unwrap_or(true) {
            writeln!(out, "dhcp = true")?;
        }
        writeln!(out)?;
        writeln!(out, "[network_identity]")?;
        writeln!(out, "network_name = {:?}", mesh.network_name)?;
        writeln!(out, "network_secret = {:?}", mesh.network_secret)?;

        if let Some(listeners) = &mesh.listeners {
            if !listeners.is_empty() {
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

        if mesh.no_tun.unwrap_or(false) {
            writeln!(out)?;
            writeln!(out, "[flags]")?;
            writeln!(out, "no_tun = true")?;
        }

        Ok(out)
    }

    /// Start the mesh network instance (blocking; call from a dedicated thread).
    pub fn start(mesh: &MeshConfig) -> Result<Uuid> {
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

#[cfg(windows)]
mod imp {
    use anyhow::{Result, bail};
    use uuid::Uuid;

    use crate::settings::MeshConfig;

    pub fn start(_: &MeshConfig) -> Result<Uuid> {
        bail!(
            "zay stack --mesh is not supported in the Windows package; run EasyTier separately on Windows or use Zay mesh on macOS/Linux"
        )
    }

    pub fn stop_all() -> Result<()> {
        Ok(())
    }
}

pub use imp::*;
