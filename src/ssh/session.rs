use std::sync::Arc;

use anyhow::{Context, Result};
use russh::{client::Handle, keys::PrivateKeyWithHashAlg};
use tracing::{debug, info};

use crate::ssh::{
    client::{ClientHandler, RemoteForwardEntry},
    config::{HostConfig, ResolvedTarget},
};

type SshHandle = Handle<ClientHandler>;

/// Final SSH session plus intermediate hop sessions that must stay alive.
pub struct SessionHolder {
    pub handle: Arc<SshHandle>,
    /// Monotonic id; changes on every successful reconnect.
    pub generation: u64,
    /// Intermediate hop handles; must be held while `handle` is active.
    #[allow(dead_code)]
    chain: Vec<Arc<SshHandle>>,
}

impl SessionHolder {
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

static SESSION_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

fn next_generation() -> u64 {
    SESSION_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

pub async fn connect_target(
    target: &ResolvedTarget,
    password: &Option<String>,
    strict_host_keys: bool,
    remote_forwards: Arc<Vec<RemoteForwardEntry>>,
) -> Result<SessionHolder> {
    let ssh_config = default_client_config();

    if target.jumps.is_empty() {
        return connect_direct(
            &ssh_config,
            &target.destination,
            password,
            true,
            strict_host_keys,
            remote_forwards,
        )
        .await;
    }

    info!("ProxyJump path: {}", target.path_label());

    let mut chain = Vec::new();
    let mut current = connect_direct(
        &ssh_config,
        &target.jumps[0],
        password,
        false,
        strict_host_keys,
        empty_forwards(),
    )
    .await?;
    chain.push(Arc::clone(&current.handle));

    for next in target.jumps.iter().skip(1) {
        current = connect_via_channel(
            &ssh_config,
            &current.handle,
            next,
            password,
            false,
            strict_host_keys,
            empty_forwards(),
            &format!("ProxyJump to {}", next.hostname),
        )
        .await?;
        chain.push(Arc::clone(&current.handle));
    }

    let final_session = connect_via_channel(
        &ssh_config,
        &current.handle,
        &target.destination,
        password,
        true,
        strict_host_keys,
        remote_forwards,
        &format!("target {}", target.destination.hostname),
    )
    .await?;

    Ok(SessionHolder {
        handle: final_session.handle,
        generation: final_session.generation,
        chain,
    })
}

async fn connect_direct(
    ssh_config: &Arc<russh::client::Config>,
    host: &HostConfig,
    password: &Option<String>,
    allow_password: bool,
    strict_host_keys: bool,
    remote_forwards: Arc<Vec<RemoteForwardEntry>>,
) -> Result<SessionHolder> {
    info!(
        "Connecting to {}:{} as {}",
        host.hostname, host.port, host.user
    );

    let handler = ClientHandler::new(
        host.hostname.clone(),
        host.port,
        strict_host_keys,
        remote_forwards,
    );
    let mut handle = russh::client::connect(
        Arc::clone(ssh_config),
        (host.hostname.as_str(), host.port),
        handler,
    )
    .await
    .with_context(|| {
        format!("SSH TCP connect failed for {}:{}", host.hostname, host.port)
    })?;

    authenticate(&mut handle, host, password, allow_password).await?;
    info!("Authenticated to {} as {}", host.hostname, host.user);

    Ok(SessionHolder {
        handle: Arc::new(handle),
        generation: next_generation(),
        chain: Vec::new(),
    })
}

async fn connect_via_channel(
    ssh_config: &Arc<russh::client::Config>,
    via: &Arc<SshHandle>,
    host: &HostConfig,
    password: &Option<String>,
    allow_password: bool,
    strict_host_keys: bool,
    remote_forwards: Arc<Vec<RemoteForwardEntry>>,
    label: &str,
) -> Result<SessionHolder> {
    info!(
        "Opening tunnel via {} to {}:{} ({label})",
        "previous hop", host.hostname, host.port
    );

    let channel = via
        .channel_open_direct_tcpip(
            &host.hostname,
            host.port as u32,
            "127.0.0.1",
            0,
        )
        .await
        .with_context(|| {
            format!(
                "direct-tcpip to {}:{} failed ({label})",
                host.hostname, host.port
            )
        })?;

    let stream = channel.into_stream();
    let handler = ClientHandler::new(
        host.hostname.clone(),
        host.port,
        strict_host_keys,
        remote_forwards,
    );
    let mut handle =
        russh::client::connect_stream(Arc::clone(ssh_config), stream, handler)
            .await
            .with_context(|| {
                format!("SSH handshake over tunnel failed ({label})")
            })?;

    authenticate(&mut handle, host, password, allow_password).await?;
    info!(
        "Authenticated to {} as {user} ({label})",
        host.hostname,
        user = host.user
    );

    Ok(SessionHolder {
        handle: Arc::new(handle),
        generation: next_generation(),
        chain: Vec::new(),
    })
}

pub async fn authenticate(
    handle: &mut SshHandle,
    host_config: &HostConfig,
    password: &Option<String>,
    allow_password: bool,
) -> Result<()> {
    let user = &host_config.user;

    for key_path in &host_config.identity_files {
        if !key_path.exists() {
            continue;
        }
        debug!("Trying key: {}", key_path.display());

        match russh::keys::load_secret_key(key_path, None) {
            Ok(key) => {
                let hash_alg = if key.algorithm().is_rsa() {
                    match handle.best_supported_rsa_hash().await {
                        Ok(Some(alg)) => alg,
                        Ok(None) => {
                            debug!("Server does not support RSA, skipping key");
                            continue;
                        }
                        Err(e) => {
                            debug!("Could not query RSA hash algorithm: {e}");
                            None
                        }
                    }
                } else {
                    None
                };
                let key_with_alg =
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
                match handle.authenticate_publickey(user, key_with_alg).await {
                    Ok(result) if result.success() => {
                        debug!(
                            "Authenticated with key: {}",
                            key_path.display()
                        );
                        return Ok(());
                    }
                    Ok(_) => {
                        debug!("Key rejected: {}", key_path.display());
                    }
                    Err(e) => {
                        debug!(
                            "Key auth error for {}: {e}",
                            key_path.display()
                        );
                    }
                }
            }
            Err(e) => {
                debug!("Cannot load key {}: {e}", key_path.display());
            }
        }
    }

    if allow_password {
        if let Some(pwd) = password {
            match handle.authenticate_password(user, pwd).await {
                Ok(result) if result.success() => {
                    debug!("Authenticated with password");
                    return Ok(());
                }
                Ok(_) => {
                    anyhow::bail!(
                        "Password authentication rejected by server ({})",
                        host_config.hostname
                    );
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!(
                            "Password authentication failed for {}",
                            host_config.hostname
                        )
                    });
                }
            }
        }
    }

    anyhow::bail!(
        "All authentication methods failed for user '{}' on {}. \
         Tried {} key(s){}.",
        user,
        host_config.hostname,
        host_config.identity_files.len(),
        if allow_password && password.is_some() {
            " and password"
        } else if password.is_some() {
            " (-P applies only to the final SSH host, not ProxyJump hops; use keys for jumps)"
        } else {
            ""
        }
    )
}

fn default_client_config() -> Arc<russh::client::Config> {
    // Keepalive is handled by the explicit ping loop in tunnel.rs.
    Arc::new(russh::client::Config::default())
}

fn empty_forwards() -> Arc<Vec<RemoteForwardEntry>> {
    Arc::new(Vec::new())
}
