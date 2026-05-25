use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct HostConfig {
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
}

/// Destination host plus ordered jump hosts (ProxyJump / `-J`).
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub destination: HostConfig,
    pub jumps: Vec<HostConfig>,
}

impl ResolvedTarget {
    pub fn hop_count(&self) -> usize {
        self.jumps.len() + 1
    }

    pub fn path_label(&self) -> String {
        let mut parts: Vec<String> =
            self.jumps.iter().map(|h| h.hostname.clone()).collect();
        parts.push(self.destination.hostname.clone());
        parts.join(" → ")
    }
}

pub fn resolve_target(
    dest_alias: &str,
    port_override: Option<u16>,
    user_override: Option<&str>,
    identity_override: Option<&str>,
    jump_override: &[String],
) -> Result<ResolvedTarget> {
    let mut dest_params = resolve_host(dest_alias)?;

    if let Some(port) = port_override {
        dest_params.port = port;
    }
    if let Some(user) = user_override {
        dest_params.user = user.to_string();
    }
    if let Some(identity) = identity_override {
        dest_params.identity_files = vec![PathBuf::from(identity)];
    }

    let jump_names = if jump_override.is_empty() {
        dest_params.proxy_jump.clone().unwrap_or_default()
    } else {
        flatten_jump_names(jump_override)
    };

    let jumps = jump_names
        .iter()
        .map(|alias| {
            resolve_host(alias)
                .map(|p| p.into_host_config())
                .with_context(|| {
                    format!("Failed to resolve ProxyJump host '{alias}'")
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let destination = dest_params.into_host_config();

    debug!(
        destination = %destination.hostname,
        port = destination.port,
        user = %destination.user,
        jumps = ?jumps.iter().map(|j| &j.hostname).collect::<Vec<_>>(),
        "Resolved SSH target"
    );

    Ok(ResolvedTarget { destination, jumps })
}

#[derive(Debug, Clone)]
struct HostParams {
    hostname: String,
    port: u16,
    user: String,
    identity_files: Vec<PathBuf>,
    proxy_jump: Option<Vec<String>>,
}

impl HostParams {
    fn into_host_config(self) -> HostConfig {
        HostConfig {
            hostname: self.hostname,
            port: self.port,
            user: self.user,
            identity_files: self.identity_files,
        }
    }
}

fn resolve_host(alias: &str) -> Result<HostParams> {
    let (user_from_alias, host_part, port_from_alias) =
        split_host_port_alias(alias);

    let mut params = HostParams {
        hostname: host_part.clone(),
        port: port_from_alias.unwrap_or(22),
        user: current_user(),
        identity_files: default_identity_files(),
        proxy_jump: None,
    };

    if let Some(home) = dirs::home_dir() {
        let ssh_config_path = home.join(".ssh").join("config");
        if ssh_config_path.exists() {
            if let Err(e) =
                apply_ssh_config(&mut params, &host_part, &ssh_config_path)
            {
                debug!("SSH config parse error: {e}");
            }
        }
    }

    if let Some(user) = user_from_alias {
        params.user = user;
    }
    if let Some(port) = port_from_alias {
        params.port = port;
    }

    Ok(params)
}

fn apply_ssh_config(
    params: &mut HostParams,
    host: &str,
    path: &Path,
) -> Result<()> {
    use std::{fs::File, io::BufReader};

    use ssh2_config::{ParseRule, SshConfig};

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let ssh_config = SshConfig::default()
        .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)?;

    let query = ssh_config.query(host);

    if let Some(hostname) = query.host_name {
        params.hostname = hostname;
    }
    if let Some(port) = query.port {
        params.port = port;
    }
    if let Some(user) = query.user {
        params.user = user;
    }
    if let Some(identity_files) = query.identity_file {
        if !identity_files.is_empty() {
            params.identity_files =
                identity_files.into_iter().map(expand_tilde).collect();
        }
    }
    if let Some(proxy_jump) = query.proxy_jump {
        params.proxy_jump = Some(proxy_jump);
    }

    Ok(())
}

/// `user@host`, `host:port`, or `user@host:port` in `-J` / ProxyJump entries.
fn split_host_port_alias(alias: &str) -> (Option<String>, String, Option<u16>) {
    let alias = alias.trim();
    let (user, rest) = match alias.split_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, alias),
    };

    if let Some((host, port_str)) = rest.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return (user, host.to_string(), Some(port));
            }
        }
    }

    (user, rest.to_string(), None)
}

fn flatten_jump_names(entries: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for entry in entries {
        for part in entry.split(',') {
            let part = part.trim();
            if !part.is_empty() {
                out.push(part.to_string());
            }
        }
    }
    out
}

fn expand_tilde(path: PathBuf) -> PathBuf {
    if let Some(s) = path.to_str() {
        if let Some(rest) = s.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(rest);
            }
        }
    }
    path
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

fn default_identity_files() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return vec![];
    };
    let ssh_dir = home.join(".ssh");
    ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"]
        .iter()
        .map(|name| ssh_dir.join(name))
        .filter(|p| p.exists())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_jump_names_splits_commas() {
        assert_eq!(
            flatten_jump_names(&[
                "jump1,jump2".to_string(),
                "jump3".to_string()
            ]),
            vec!["jump1", "jump2", "jump3"]
        );
    }

    #[test]
    fn split_host_port_alias_parses_user_host_port() {
        let (u, h, p) = split_host_port_alias("admin@bastion:2222");
        assert_eq!(u.as_deref(), Some("admin"));
        assert_eq!(h, "bastion");
        assert_eq!(p, Some(2222));
    }
}
