use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};

use anyhow::{Context, Result};
use russh::client::{Handler, Msg, Session};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::ssh::forward::{ForwardKind, SshForward};

/// One `-R` rule; `actual_port` is set after `tcpip_forward` succeeds.
pub struct RemoteForwardEntry {
    pub spec: SshForward,
    actual_port: AtomicU16,
}

impl RemoteForwardEntry {
    pub fn new(spec: SshForward) -> Self {
        Self {
            spec,
            actual_port: AtomicU16::new(0),
        }
    }

    pub fn set_bound_port(&self, port: u16) {
        self.actual_port.store(port, Ordering::Release);
    }

    pub fn bound_port(&self) -> u16 {
        self.actual_port.load(Ordering::Acquire)
    }

    fn matches(&self, connected_address: &str, connected_port: u32) -> bool {
        if self.spec.kind != ForwardKind::Remote {
            return false;
        }
        let port = connected_port as u16;
        let bound = self.bound_port();
        if bound != 0 && port == bound {
            return true;
        }
        if self.spec.bind_port != 0
            && port == self.spec.bind_port
            && (hosts_equivalent(&self.spec.bind_host, connected_address)
                || connected_address.is_empty())
        {
            return true;
        }
        false
    }

    pub fn reset_bound_port(&self) {
        self.actual_port.store(0, Ordering::Release);
    }
}

/// Loopback / any-address aliases for `-R` rule matching.
fn hosts_equivalent(expected: &str, actual: &str) -> bool {
    if expected == actual {
        return true;
    }
    normalize_bind_host(expected) == normalize_bind_host(actual)
}

fn normalize_bind_host(host: &str) -> String {
    match host {
        "localhost" | "127.0.0.1" | "::1" => "loopback".to_string(),
        "0.0.0.0" | "*" | "" => "any".to_string(),
        other => other.to_string(),
    }
}

pub struct ClientHandler {
    server_host: String,
    server_port: u16,
    strict_host_keys: bool,
    remote_forwards: Arc<Vec<RemoteForwardEntry>>,
}

impl ClientHandler {
    pub fn new(
        server_host: String,
        server_port: u16,
        strict_host_keys: bool,
        remote_forwards: Arc<Vec<RemoteForwardEntry>>,
    ) -> Self {
        Self {
            server_host,
            server_port,
            strict_host_keys,
            remote_forwards,
        }
    }
}

impl Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let host = &self.server_host;
        let port = self.server_port;

        match russh::keys::check_known_hosts(host, port, server_public_key) {
            Ok(true) => Ok(true),
            Ok(false) if self.strict_host_keys => Err(anyhow::anyhow!(
                "unknown host key for {host}:{port} (--strict-host-keys); \
                 connect once without the flag or add the key to ~/.ssh/known_hosts"
            )),
            Ok(false) => {
                russh::keys::known_hosts::learn_known_hosts(
                    host,
                    port,
                    server_public_key,
                )
                .map_err(|e| {
                    anyhow::anyhow!("failed to record host key: {e}")
                })?;
                tracing::info!(
                    "Recorded new host key for {} in ~/.ssh/known_hosts",
                    if port == 22 {
                        host.clone()
                    } else {
                        format!("[{host}]:{port}")
                    }
                );
                Ok(true)
            }
            Err(russh::keys::Error::KeyChanged { line }) => {
                Err(anyhow::anyhow!(
                    "host key for {host}:{port} changed (known_hosts line {line}); \
                 remove the old entry or fix known_hosts"
                ))
            }
            Err(e) => Err(anyhow::anyhow!(
                "known_hosts verification failed for {host}:{port}: {e}"
            )),
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Return immediately; all work runs off the SSH session task.
        let remote_forwards = Arc::clone(&self.remote_forwards);
        let connected_address = connected_address.to_string();
        let originator = format!("{originator_address}:{originator_port}");

        tokio::spawn(async move {
            if let Err(e) = process_remote_forward(
                channel,
                remote_forwards,
                connected_address,
                connected_port,
                originator,
            )
            .await
            {
                debug!("Remote forward task ended: {e:#}");
            }
        });

        Ok(())
    }
}

enum RemoteForwardTarget {
    Forward(SshForward),
    IgnoreNoRule,
    IgnoreAmbiguous,
}

fn resolve_remote_forward(
    entries: &[RemoteForwardEntry],
    connected_address: &str,
    connected_port: u32,
) -> RemoteForwardTarget {
    let matches: Vec<_> = entries
        .iter()
        .filter(|e| e.matches(connected_address, connected_port))
        .collect();

    match matches.len() {
        0 => RemoteForwardTarget::IgnoreNoRule,
        1 => RemoteForwardTarget::Forward(matches[0].spec.clone()),
        _ => RemoteForwardTarget::IgnoreAmbiguous,
    }
}

async fn process_remote_forward(
    channel: russh::Channel<Msg>,
    remote_forwards: Arc<Vec<RemoteForwardEntry>>,
    connected_address: String,
    connected_port: u32,
    originator: String,
) -> Result<()> {
    let spec = match resolve_remote_forward(
        &remote_forwards,
        &connected_address,
        connected_port,
    ) {
        RemoteForwardTarget::Forward(spec) => spec,
        RemoteForwardTarget::IgnoreNoRule => {
            warn!(
                "Ignoring remote forward connection to {connected_address}:{connected_port} \
                 (no matching -R rule)"
            );
            let _ = channel.close().await;
            return Ok(());
        }
        RemoteForwardTarget::IgnoreAmbiguous => {
            warn!(
                "Ignoring remote forward connection to {connected_address}:{connected_port} \
                 (ambiguous -R rules)"
            );
            let _ = channel.close().await;
            return Ok(());
        }
    };

    let dest = SshForward::socket_addr(&spec.dest_host, spec.dest_port);
    debug!(
        "Remote forward accepted {originator} on {connected_address}:{connected_port} → {dest}"
    );

    // Start SSH channel I/O immediately (before any local TCP connect await).
    let mut remote = channel.into_stream();

    let mut local = match TcpStream::connect(&dest).await {
        Ok(stream) => stream,
        Err(e) => {
            drop(remote);
            return Err(e).with_context(|| {
                format!("Failed to connect local target {dest}")
            });
        }
    };

    if let Err(e) = tokio::io::copy_bidirectional(&mut local, &mut remote)
        .await
        .context("Remote forward data transfer error")
    {
        debug!(
            "Remote forward {connected_address}:{connected_port} → {dest} ended: {e:#}"
        );
    }

    Ok(())
}

pub async fn cancel_remote_forwards(
    handle: &russh::client::Handle<ClientHandler>,
    entries: &[RemoteForwardEntry],
) {
    for entry in entries {
        let port = entry.bound_port();
        if port == 0 {
            continue;
        }
        let addr = SshForward::socket_addr(&entry.spec.bind_host, port);
        if let Err(e) = handle
            .cancel_tcpip_forward(&entry.spec.bind_host, port as u32)
            .await
        {
            warn!("Failed to cancel remote forward {addr}: {e}");
        } else {
            debug!("Cancelled remote forward {addr}");
        }
        entry.reset_bound_port();
    }
}

pub fn reset_all_bound_ports(entries: &[RemoteForwardEntry]) {
    for entry in entries {
        entry.reset_bound_port();
    }
}
