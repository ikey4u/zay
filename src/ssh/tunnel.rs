use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    time::sleep,
};
use tracing::{debug, error, info, warn};

use crate::ssh::{
    SshArgs,
    client::{
        RemoteForwardEntry, cancel_remote_forwards, reset_all_bound_ports,
    },
    config::{self as ssh_config, ResolvedTarget},
    forward::{ForwardKind, SshForward},
    session::{self as ssh_session, SessionHolder},
};

type SharedSession = Arc<SessionHolder>;

const LOCAL_FORWARD_MAX_RETRIES: u32 = 8;
const LOCAL_FORWARD_RETRY_DELAY: Duration = Duration::from_millis(200);
const MAX_LOCAL_FORWARD_WAITING: usize = 1024;
const MAX_LOCAL_FORWARD_ACTIVE: usize = 1024;

pub async fn run(args: SshArgs) -> Result<()> {
    let target = ssh_config::resolve_target(
        &args.ssh_host,
        args.port,
        args.user.as_deref(),
        args.identity.as_deref(),
        &args.proxy_jump,
    )?;

    if target.jumps.is_empty() {
        info!(
            "SSH target: {}:{}",
            target.destination.hostname, target.destination.port
        );
    } else {
        info!("SSH path: {}", target.path_label());
    }

    let remote_specs: Vec<SshForward> = args
        .forwards
        .iter()
        .filter(|f| f.kind == ForwardKind::Remote)
        .cloned()
        .collect();

    validate_no_duplicate_binds(&args.forwards)?;

    let remote_entries: Arc<Vec<RemoteForwardEntry>> = Arc::new(
        remote_specs
            .iter()
            .map(|s| RemoteForwardEntry::new(s.clone()))
            .collect(),
    );

    let (session_tx, session_rx) =
        watch::channel::<Option<SharedSession>>(None);

    let wait_permits = Arc::new(Semaphore::new(MAX_LOCAL_FORWARD_WAITING));
    let forward_permits = Arc::new(Semaphore::new(MAX_LOCAL_FORWARD_ACTIVE));

    for spec in args
        .forwards
        .iter()
        .filter(|f| f.kind == ForwardKind::Local)
    {
        let rx = session_rx.clone();
        let wait = Arc::clone(&wait_permits);
        let forward = Arc::clone(&forward_permits);
        let spec = spec.clone();
        tokio::spawn(async move {
            if let Err(e) =
                local_forward_listener(spec, rx, wait, forward).await
            {
                error!("Local forward listener fatal error: {e:#}");
            }
        });
    }

    let mut delay = Duration::from_secs(1);
    let mut ever_connected = false;
    let mut attempt: u32 = 0;

    loop {
        attempt += 1;
        let started_at = Instant::now();

        if attempt > 1 {
            info!("Reconnect attempt {attempt} via {}", target.path_label());
        }

        let connect_result = tokio::select! {
            r = connect_and_run(
                &target,
                &args.password,
                args.strict_host_keys,
                Arc::clone(&remote_entries),
                &session_tx,
            ) => r,
            _ = tokio::signal::ctrl_c() => {
                info!("Interrupted during SSH setup, exiting");
                return Ok(());
            }
        };

        let was_connected = session_tx.borrow().is_some();

        if let Some(session) = session_tx.borrow().clone() {
            cancel_remote_forwards(&session.handle, &remote_entries).await;
        }
        let _ = session_tx.send(None);

        match connect_result {
            Ok(()) => {
                info!("Shutdown complete");
                break;
            }
            Err(e) => {
                if !was_connected && !ever_connected {
                    return Err(e).context(format!(
                        "Initial connection failed (path: {})",
                        target.path_label()
                    ));
                }

                ever_connected = true;

                if started_at.elapsed() > Duration::from_secs(10) {
                    delay = Duration::from_secs(1);
                }

                warn!("Tunnel down: {e:#}");
                warn!(
                    "Reconnecting in {delay:.0?} (local -L listeners stay up)..."
                );

                tokio::select! {
                    _ = sleep(delay) => {}
                    _ = tokio::signal::ctrl_c() => {
                        info!("Interrupted during reconnect wait, exiting");
                        return Ok(());
                    }
                }

                delay = (delay * 2).min(Duration::from_secs(60));
            }
        }
    }

    Ok(())
}

fn validate_no_duplicate_binds(forwards: &[SshForward]) -> Result<()> {
    let mut local_binds = HashSet::new();
    let mut remote_binds = HashSet::new();

    for fwd in forwards {
        let key = (fwd.bind_host.as_str(), fwd.bind_port);
        match fwd.kind {
            ForwardKind::Local => {
                if !local_binds.insert(key) {
                    bail!(
                        "duplicate local forward (-L) bind address {}",
                        SshForward::socket_addr(&fwd.bind_host, fwd.bind_port)
                    );
                }
            }
            ForwardKind::Remote => {
                if fwd.bind_port == 0 {
                    continue;
                }
                if !remote_binds.insert(key) {
                    bail!(
                        "duplicate remote forward (-R) bind address {}",
                        SshForward::socket_addr(&fwd.bind_host, fwd.bind_port)
                    );
                }
            }
        }
    }

    Ok(())
}

fn gateway_ports_hint(bind_host: &str) -> &'static str {
    if bind_host == "0.0.0.0" || bind_host == "*" {
        " (remote bind on all interfaces may require GatewayPorts yes in sshd_config)"
    } else {
        ""
    }
}

async fn setup_remote_forwards(
    session: &SessionHolder,
    remote_entries: &[RemoteForwardEntry],
    server_hostname: &str,
) -> Result<()> {
    reset_all_bound_ports(remote_entries);

    let mut registered: Vec<usize> = Vec::new();

    for (idx, entry) in remote_entries.iter().enumerate() {
        let spec = &entry.spec;
        let bind_addr =
            SshForward::socket_addr(&spec.bind_host, spec.bind_port);

        match session
            .handle
            .tcpip_forward(&spec.bind_host, spec.bind_port as u32)
            .await
        {
            Ok(bound_port) => {
                entry.set_bound_port(bound_port as u16);
                registered.push(idx);
                info!(
                    "Remote forward (-R): {} → {} (listening on port {})",
                    bind_addr,
                    SshForward::socket_addr(&spec.dest_host, spec.dest_port),
                    bound_port
                );
            }
            Err(e) => {
                rollback_remote_forwards(
                    &session.handle,
                    remote_entries,
                    &registered,
                )
                .await;
                let hint = gateway_ports_hint(&spec.bind_host);
                return Err(e).context(format!(
                    "Failed to request remote forward {bind_addr} on {server_hostname}{hint}"
                ));
            }
        }
    }

    Ok(())
}

async fn rollback_remote_forwards(
    handle: &russh::client::Handle<crate::ssh::client::ClientHandler>,
    entries: &[RemoteForwardEntry],
    registered: &[usize],
) {
    for &idx in registered {
        let entry = &entries[idx];
        let port = entry.bound_port();
        if port == 0 {
            continue;
        }
        let addr = SshForward::socket_addr(&entry.spec.bind_host, port);
        if let Err(e) = handle
            .cancel_tcpip_forward(&entry.spec.bind_host, port as u32)
            .await
        {
            warn!("Rollback: failed to cancel remote forward {addr}: {e}");
        } else {
            debug!("Rollback: cancelled remote forward {addr}");
        }
        entry.reset_bound_port();
    }
}

async fn connect_and_run(
    target: &ResolvedTarget,
    password: &Option<String>,
    strict_host_keys: bool,
    remote_entries: Arc<Vec<RemoteForwardEntry>>,
    session_tx: &watch::Sender<Option<SharedSession>>,
) -> Result<()> {
    let session = ssh_session::connect_target(
        target,
        password,
        strict_host_keys,
        Arc::clone(&remote_entries),
    )
    .await
    .with_context(|| {
        format!("SSH session setup failed for {}", target.path_label())
    })?;

    if !remote_entries.is_empty() {
        setup_remote_forwards(
            &session,
            &remote_entries,
            &target.destination.hostname,
        )
        .await?;
    }

    let shared = session.into_shared();
    let _ = session_tx.send(Some(Arc::clone(&shared)));

    info!(
        "Tunnel ready ({} hop(s)); forwards active",
        target.hop_count()
    );

    let ping_session = Arc::clone(&shared);
    let (dead_tx, dead_rx) = tokio::sync::oneshot::channel::<anyhow::Error>();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;

        loop {
            interval.tick().await;
            if let Err(e) = ping_session.handle.send_ping().await {
                let _ =
                    dead_tx.send(anyhow::anyhow!("Keepalive ping failed: {e}"));
                break;
            }
        }
    });

    tokio::select! {
        result = dead_rx => {
            match result {
                Ok(e) => Err(e),
                Err(_) => Err(anyhow::anyhow!(
                    "SSH session monitor exited unexpectedly"
                )),
            }
        }
        result = tokio::signal::ctrl_c() => {
            result.context("Failed to listen for Ctrl+C")?;
            info!("Ctrl+C received, disconnecting...");
            let _ = shared
                .handle
                .disconnect(russh::Disconnect::ByApplication, "user request", "en")
                .await;
            Ok(())
        }
    }
}

async fn local_forward_listener(
    spec: SshForward,
    session_rx: watch::Receiver<Option<SharedSession>>,
    wait_permits: Arc<Semaphore>,
    forward_permits: Arc<Semaphore>,
) -> Result<()> {
    let bind_addr = SshForward::socket_addr(&spec.bind_host, spec.bind_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind local address {bind_addr}"))?;

    info!(
        "Local forward (-L): {} → {} (listener stays up across reconnects)",
        bind_addr,
        SshForward::socket_addr(&spec.dest_host, spec.dest_port)
    );

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("accept() error on {bind_addr}: {e}");
                continue;
            }
        };
        debug!("Accepted {peer_addr} → {bind_addr}");

        let dest_host = spec.dest_host.clone();
        let dest_port = spec.dest_port;
        let mut rx = session_rx.clone();
        let wait = Arc::clone(&wait_permits);
        let forward = Arc::clone(&forward_permits);

        let wait_permit = match wait.try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(
                    "Rejecting local forward client {peer_addr}: too many clients waiting for SSH (max {MAX_LOCAL_FORWARD_WAITING})"
                );
                drop(stream);
                continue;
            }
        };

        tokio::spawn(async move {
            if let Err(e) = handle_local_connection(
                stream,
                dest_host,
                dest_port,
                &mut rx,
                wait_permit,
                forward,
            )
            .await
            {
                debug!("Local forward connection closed: {e}");
            }
        });
    }
}

async fn wait_for_session(
    session_rx: &mut watch::Receiver<Option<SharedSession>>,
) -> Result<SharedSession> {
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            {
                let guard = session_rx.borrow_and_update();
                if let Some(s) = guard.as_ref() {
                    return Ok::<SharedSession, anyhow::Error>(Arc::clone(s));
                }
            }
            session_rx
                .changed()
                .await
                .context("Session watcher closed")?;
        }
    })
    .await
    .context("Timeout waiting for SSH tunnel (still reconnecting?)")?
}

async fn handle_local_connection(
    stream: TcpStream,
    dest_host: String,
    dest_port: u16,
    session_rx: &mut watch::Receiver<Option<SharedSession>>,
    wait_permit: tokio::sync::OwnedSemaphorePermit,
    forward_permits: Arc<Semaphore>,
) -> Result<()> {
    let mut stream = stream;
    let mut attempts = 0u32;

    let mut session = {
        let _wait = wait_permit;
        wait_for_session(session_rx).await?
    };

    loop {
        attempts += 1;
        let generation = session.generation;

        let _forward = Arc::clone(&forward_permits)
            .acquire_owned()
            .await
            .context("Local forward connection limiter closed")?;

        match session
            .handle
            .channel_open_direct_tcpip(
                &dest_host,
                dest_port as u32,
                "127.0.0.1",
                0,
            )
            .await
        {
            Ok(channel) => {
                let mut ch_stream = channel.into_stream();
                return tokio::io::copy_bidirectional(
                    &mut stream,
                    &mut ch_stream,
                )
                .await
                .context("Data transfer error")
                .map(|_| ());
            }
            Err(e) => {
                let session_gone = session_rx
                    .borrow()
                    .as_ref()
                    .is_none_or(|s| s.generation != generation);
                if !session_gone {
                    return Err(e)
                        .context("Failed to open direct-tcpip channel");
                }
                if attempts >= LOCAL_FORWARD_MAX_RETRIES {
                    return Err(e)
                        .context("Failed to open direct-tcpip channel");
                }
                debug!(
                    "Local forward channel open failed after reconnect \
                     ({attempts}/{LOCAL_FORWARD_MAX_RETRIES}), retrying: {e}"
                );
                sleep(LOCAL_FORWARD_RETRY_DELAY).await;
                session = wait_for_session(session_rx).await?;
            }
        }
    }
}
