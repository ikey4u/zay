//! Tailscale SSH policy and session-boundary compatibility.

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, Request};
use http_body_util::Full;
#[cfg(not(unix))]
use portable_pty::CommandBuilder;
#[cfg(any(not(unix), test))]
use portable_pty::{PtySize, native_pty_system};
use russh::{
    Channel, ChannelId,
    keys::{Certificate, PublicKey},
    server::{self, Auth, Msg, Session},
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::TcpListener,
    process::Command,
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

use super::{
    tailscale_control::decode_tailscale_control_json_response,
    tailscale_control_supervisor::TailscaleTs2021DialConnector,
    tailscale_control_types::{
        TailscaleNetmapState, TailscaleSshAction, TailscaleSshPolicy,
        TailscaleSshPrincipal,
    },
    tailscale_ssh_recording::{
        TailscaleSshCastHeader, TailscaleSshOutputRecording,
        TailscaleSshRecordingAttempt, TailscaleSshRecordingEventType,
        TailscaleSshRecordingNotification, connect_tailscale_ssh_recorder,
    },
};
use crate::{adapter::Dialer, common::network::SocksAddr};

pub const TAILSCALE_SSH_MAXIMUM_DELEGATION_HOPS: usize = 10;
pub const TAILSCALE_SSH_DELEGATION_TIMEOUT: Duration =
    Duration::from_secs(30 * 60);
pub const TAILSCALE_SSH_DELEGATE_RESPONSE_LIMIT: usize = 1024 * 1024;
pub const TAILSCALE_CAPABILITY_SSH_ENVIRONMENT_VARIABLES: &str = "ssh-env-vars";
pub const TAILSCALE_SSH_HOST_KEY_FILE_NAME: &str = "ssh_host_ed25519_key";

/// Persistent host identity and ready-to-use russh server configuration.
/// The private key remains inside `config`; only the authorized-key form is
/// exposed for `Hostinfo.sshHostKeys`.
pub struct TailscaleSshServerIdentity {
    pub config: Arc<server::Config>,
    pub public_key: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleSshPeerIdentity {
    pub node_id: i64,
    pub stable_id: String,
    pub name: String,
    pub user_id: i64,
    pub tags: Vec<String>,
    pub addresses: Vec<IpAddr>,
    pub user_login: String,
    pub tagged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleSshAuthorization {
    pub requested_user: String,
    pub local_user: String,
    pub action: TailscaleSshAction,
    pub initial_action: TailscaleSshAction,
    pub accept_environment: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleSshPtyRequest {
    pub terminal: String,
    pub columns: u16,
    pub rows: u16,
    pub width_pixels: u16,
    pub height_pixels: u16,
    pub modes: Vec<(russh::Pty, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleSshSessionKind {
    Shell,
    Exec(String),
    Sftp,
}

#[derive(Debug, Clone)]
pub struct TailscaleSshSessionRequest {
    pub authorization: TailscaleSshAuthorization,
    pub kind: TailscaleSshSessionKind,
    pub environment: BTreeMap<String, String>,
    pub pty: Option<TailscaleSshPtyRequest>,
    pub agent_forwarding: bool,
    pub recording: Option<Arc<TailscaleSshOutputRecording>>,
    pub source_address: Option<SocketAddr>,
    pub destination_address: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub enum TailscaleSshSessionEvent {
    Resize {
        columns: u16,
        rows: u16,
        width_pixels: u16,
        height_pixels: u16,
    },
    Signal(russh::Sig),
}

/// Host/platform session boundary. Implementations own the russh channel so
/// native helpers can provide PTY, process impersonation, agent forwarding,
/// SFTP, and recording without putting any binary behavior in this crate.
#[async_trait]
pub trait TailscaleSshSessionBackend: Send + Sync {
    fn supports_pty(&self) -> bool {
        false
    }

    fn supports_sftp(&self) -> bool {
        false
    }

    async fn run_session(
        &self,
        request: TailscaleSshSessionRequest,
        channel: Channel<Msg>,
        events: mpsc::Receiver<TailscaleSshSessionEvent>,
        cancellation: CancellationToken,
    ) -> Result<(), String>;
}

/// Built-in operating-system process backend. On Unix it resolves the policy's
/// local account and, when zay is privileged, drops supplementary groups, GID,
/// and UID in the child before exec. The historical type name is retained as
/// public API compatibility; it never changes the identity of the zay process.
#[derive(Debug, Default)]
pub struct TailscaleSshCurrentUserProcessBackend;

#[derive(Debug, Clone)]
struct CurrentUserIdentity {
    name: String,
    home: String,
    shell: String,
    #[cfg(unix)]
    uid: libc::uid_t,
    #[cfg(unix)]
    gid: libc::gid_t,
    #[cfg(unix)]
    groups: Vec<libc::gid_t>,
}

#[async_trait]
impl TailscaleSshSessionBackend for TailscaleSshCurrentUserProcessBackend {
    fn supports_pty(&self) -> bool {
        true
    }

    fn supports_sftp(&self) -> bool {
        tailscale_ssh_sftp_server_path().is_some()
    }

    async fn run_session(
        &self,
        request: TailscaleSshSessionRequest,
        channel: Channel<Msg>,
        mut events: mpsc::Receiver<TailscaleSshSessionEvent>,
        cancellation: CancellationToken,
    ) -> Result<(), String> {
        let identity =
            match local_user_identity(&request.authorization.local_user) {
                Ok(identity) => identity,
                Err(error) => {
                    return reject_tailscale_ssh_session(channel, error).await;
                }
            };
        #[cfg(unix)]
        if let Err(error) = validate_tailscale_ssh_user_switch(&identity) {
            return reject_tailscale_ssh_session(channel, error).await;
        }
        if request.pty.is_some() {
            if matches!(request.kind, TailscaleSshSessionKind::Sftp) {
                return reject_tailscale_ssh_session(
                    channel,
                    "SFTP does not support a PTY".into(),
                )
                .await;
            }
            return run_current_user_pty_session(
                request,
                channel,
                events,
                cancellation,
                identity,
            )
            .await;
        }
        let program = match &request.kind {
            TailscaleSshSessionKind::Sftp => {
                let Some(path) = tailscale_ssh_sftp_server_path() else {
                    return reject_tailscale_ssh_session(
                        channel,
                        "OpenSSH sftp-server is unavailable".into(),
                    )
                    .await;
                };
                path
            }
            _ => PathBuf::from(&identity.shell),
        };
        let mut command = Command::new(program);
        match &request.kind {
            TailscaleSshSessionKind::Shell => {
                #[cfg(unix)]
                {
                    let shell_name = Path::new(&identity.shell)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("sh");
                    command.arg0(format!("-{shell_name}"));
                }
            }
            TailscaleSshSessionKind::Exec(value) => {
                command.arg("-c").arg(value);
            }
            TailscaleSshSessionKind::Sftp => {}
        }
        command
            .current_dir(&identity.home)
            .env_clear()
            .env("USER", &identity.name)
            .env("HOME", &identity.home)
            .env("SHELL", &identity.shell)
            .env("PATH", default_tailscale_ssh_path())
            .envs(&request.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        configure_tailscale_ssh_unix_child(&mut command, &identity, false);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                return reject_tailscale_ssh_session(
                    channel,
                    format!("failed to start SSH process: {error}"),
                )
                .await;
            }
        };
        let pid = child.id();
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "SSH child stdin is unavailable".to_owned())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "SSH child stdout is unavailable".to_owned())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "SSH child stderr is unavailable".to_owned())?;
        let (mut reader, writer) = channel.split();
        let writer = Arc::new(writer);
        let input = tokio::spawn(async move {
            let mut channel_input = reader.make_reader();
            let _ = tokio::io::copy(&mut channel_input, &mut stdin).await;
            let _ = stdin.shutdown().await;
        });
        let stdout_writer = writer.clone();
        let stdout_recording = request.recording.clone();
        let stdout_cancellation = cancellation.clone();
        let output = tokio::spawn(async move {
            let mut stdout = stdout;
            let mut buffer = vec![0_u8; 16 * 1024];
            loop {
                let length = stdout
                    .read(&mut buffer)
                    .await
                    .map_err(|error| error.to_string())?;
                if length == 0 {
                    break;
                }
                if let Some(recording) = &stdout_recording
                    && let Err(error) =
                        recording.record_output(&buffer[..length]).await
                {
                    stdout_cancellation.cancel();
                    return Err(error.to_string());
                }
                stdout_writer
                    .data(std::io::Cursor::new(buffer[..length].to_vec()))
                    .await
                    .map_err(|error| error.to_string())?;
            }
            Ok::<_, String>(())
        });
        let stderr_writer = writer.clone();
        let stderr_recording = request.recording.clone();
        let stderr_cancellation = cancellation.clone();
        let error_output = tokio::spawn(async move {
            let mut stderr = stderr;
            let mut buffer = vec![0_u8; 16 * 1024];
            loop {
                let length = stderr
                    .read(&mut buffer)
                    .await
                    .map_err(|error| error.to_string())?;
                if length == 0 {
                    break;
                }
                if let Some(recording) = &stderr_recording
                    && let Err(error) =
                        recording.record_output(&buffer[..length]).await
                {
                    stderr_cancellation.cancel();
                    return Err(error.to_string());
                }
                stderr_writer
                    .extended_data(
                        1,
                        std::io::Cursor::new(buffer[..length].to_vec()),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
            }
            Ok::<_, String>(())
        });
        let status = loop {
            tokio::select! {
                _ = cancellation.cancelled() => {
                    let _ = child.start_kill();
                    break child.wait().await.map_err(|error| error.to_string())?;
                }
                event = events.recv() => {
                    match event {
                        Some(TailscaleSshSessionEvent::Signal(signal)) => {
                            signal_tailscale_ssh_process(pid, &signal);
                        }
                        Some(TailscaleSshSessionEvent::Resize { .. }) => {}
                        None => {}
                    }
                }
                status = child.wait() => {
                    break status.map_err(|error| error.to_string())?;
                }
            }
        };
        input.abort();
        let _ = output.await;
        let _ = error_output.await;
        let exit_status = status.code().map_or(1, |code| code.max(0) as u32);
        writer
            .exit_status(exit_status)
            .await
            .map_err(|error| error.to_string())?;
        let _ = writer.eof().await;
        let _ = writer.close().await;
        Ok(())
    }
}

#[cfg(unix)]
async fn run_current_user_pty_session(
    request: TailscaleSshSessionRequest,
    channel: Channel<Msg>,
    mut events: mpsc::Receiver<TailscaleSshSessionEvent>,
    cancellation: CancellationToken,
    identity: CurrentUserIdentity,
) -> Result<(), String> {
    use std::os::fd::FromRawFd as _;

    let requested_pty = request
        .pty
        .as_ref()
        .ok_or_else(|| "PTY request is missing".to_owned())?;
    let mut size = libc::winsize {
        ws_row: requested_pty.rows,
        ws_col: requested_pty.columns,
        ws_xpixel: requested_pty.width_pixels,
        ws_ypixel: requested_pty.height_pixels,
    };
    let mut master_fd = -1;
    let mut slave_fd = -1;
    if unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    } == -1
    {
        return reject_tailscale_ssh_session(
            channel,
            format!(
                "failed to allocate SSH PTY: {}",
                io::Error::last_os_error()
            ),
        )
        .await;
    }
    // SAFETY: openpty returned two newly owned descriptors.
    let master = unsafe { std::fs::File::from_raw_fd(master_fd) };
    let slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };
    if let Err(error) = set_tailscale_ssh_close_on_exec(master_fd)
        .and_then(|_| set_tailscale_ssh_close_on_exec(slave_fd))
    {
        return reject_tailscale_ssh_session(
            channel,
            format!("failed to secure SSH PTY descriptors: {error}"),
        )
        .await;
    }
    if let Err(error) =
        apply_tailscale_ssh_terminal_modes_fd(master_fd, &requested_pty.modes)
    {
        return reject_tailscale_ssh_session(
            channel,
            format!("failed to configure SSH PTY modes: {error}"),
        )
        .await;
    }
    let mut command = match &request.kind {
        TailscaleSshSessionKind::Shell => {
            let mut command = Command::new(&identity.shell);
            let shell_name = Path::new(&identity.shell)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("sh");
            command.arg0(format!("-{shell_name}"));
            command
        }
        TailscaleSshSessionKind::Exec(value) => {
            let mut command = Command::new(&identity.shell);
            command.arg("-c").arg(value);
            command
        }
        TailscaleSshSessionKind::Sftp => unreachable!(),
    };
    let stdin = slave.try_clone().map_err(|error| error.to_string())?;
    let stdout = slave.try_clone().map_err(|error| error.to_string())?;
    command
        .current_dir(&identity.home)
        .env_clear()
        .env("USER", &identity.name)
        .env("HOME", &identity.home)
        .env("SHELL", &identity.shell)
        .env("TERM", &requested_pty.terminal)
        .env("PATH", default_tailscale_ssh_path())
        .envs(&request.environment)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(
            slave.try_clone().map_err(|error| error.to_string())?,
        ))
        .kill_on_drop(true);
    configure_tailscale_ssh_unix_child(&mut command, &identity, true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return reject_tailscale_ssh_session(
                channel,
                format!("failed to start SSH PTY process: {error}"),
            )
            .await;
        }
    };
    drop(slave);
    let pid = child.id();
    let master_reader = master
        .try_clone()
        .map(tokio::fs::File::from_std)
        .map_err(|error| error.to_string())?;
    let master_writer = master
        .try_clone()
        .map(tokio::fs::File::from_std)
        .map_err(|error| error.to_string())?;
    let (mut channel_reader, channel_writer) = channel.split();
    let channel_writer = Arc::new(channel_writer);
    let input = tokio::spawn(async move {
        let mut channel_input = channel_reader.make_reader();
        let mut writer = master_writer;
        let _ = tokio::io::copy(&mut channel_input, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    let output_writer = channel_writer.clone();
    let output_recording = request.recording.clone();
    let output_cancellation = cancellation.clone();
    let output = tokio::spawn(async move {
        let mut reader = master_reader;
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let length = match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(length) => length,
                Err(error) if tailscale_ssh_pty_eof_error(&error) => break,
                Err(error) => return Err(error.to_string()),
            };
            if let Some(recording) = &output_recording
                && let Err(error) =
                    recording.record_output(&buffer[..length]).await
            {
                output_cancellation.cancel();
                return Err(error.to_string());
            }
            output_writer
                .data(std::io::Cursor::new(buffer[..length].to_vec()))
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok::<_, String>(())
    });

    let status = loop {
        tokio::select! {
            _ = cancellation.cancelled() => {
                if let Some(pid) = pid {
                    unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL); }
                }
                let _ = child.start_kill();
                break child.wait().await.map_err(|error| error.to_string())?;
            }
            event = events.recv() => {
                match event {
                    Some(TailscaleSshSessionEvent::Resize {
                        columns,
                        rows,
                        width_pixels,
                        height_pixels,
                    }) => {
                        let size = libc::winsize {
                            ws_row: rows,
                            ws_col: columns,
                            ws_xpixel: width_pixels,
                            ws_ypixel: height_pixels,
                        };
                        unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ as _, &size); }
                    }
                    Some(TailscaleSshSessionEvent::Signal(signal)) => {
                        signal_tailscale_ssh_process_group(
                            pid.and_then(|pid| i32::try_from(pid).ok()),
                            pid,
                            &signal,
                        );
                    }
                    None => {}
                }
            }
            status = child.wait() => {
                break status.map_err(|error| error.to_string())?;
            }
        }
    };
    input.abort();
    let _ = input.await;
    drop(master);
    let _ = output.await;
    let exit_status = status.code().map_or(1, |code| code.max(0) as u32);
    channel_writer
        .exit_status(exit_status)
        .await
        .map_err(|error| error.to_string())?;
    let _ = channel_writer.eof().await;
    let _ = channel_writer.close().await;
    Ok(())
}

#[cfg(unix)]
fn set_tailscale_ssh_close_on_exec(fd: libc::c_int) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1
        || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) }
            == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
async fn run_current_user_pty_session(
    request: TailscaleSshSessionRequest,
    channel: Channel<Msg>,
    mut events: mpsc::Receiver<TailscaleSshSessionEvent>,
    cancellation: CancellationToken,
    identity: CurrentUserIdentity,
) -> Result<(), String> {
    let requested_pty = request
        .pty
        .as_ref()
        .ok_or_else(|| "PTY request is missing".to_owned())?;
    let size = PtySize {
        rows: requested_pty.rows,
        cols: requested_pty.columns,
        pixel_width: requested_pty.width_pixels,
        pixel_height: requested_pty.height_pixels,
    };
    let pty_system = native_pty_system();
    let pair = match pty_system.openpty(size) {
        Ok(pair) => pair,
        Err(error) => {
            return reject_tailscale_ssh_session(
                channel,
                format!("failed to allocate SSH PTY: {error}"),
            )
            .await;
        }
    };
    let mut command = match &request.kind {
        TailscaleSshSessionKind::Shell => CommandBuilder::new_default_prog(),
        TailscaleSshSessionKind::Exec(_) => {
            CommandBuilder::new(&identity.shell)
        }
        TailscaleSshSessionKind::Sftp => unreachable!(),
    };
    if let TailscaleSshSessionKind::Exec(value) = &request.kind {
        command.arg("-c");
        command.arg(value);
    }
    command.cwd(&identity.home);
    command.env_clear();
    command.env("USER", &identity.name);
    command.env("LOGNAME", &identity.name);
    command.env("HOME", &identity.home);
    command.env("SHELL", &identity.shell);
    command.env("TERM", &requested_pty.terminal);
    command.env("PATH", default_tailscale_ssh_path());
    for (name, value) in &request.environment {
        command.env(name, value);
    }

    let master = pair.master;
    #[cfg(unix)]
    if let Err(error) = apply_tailscale_ssh_terminal_modes(
        master.as_ref(),
        &requested_pty.modes,
    ) {
        return reject_tailscale_ssh_session(
            channel,
            format!("failed to configure SSH PTY modes: {error}"),
        )
        .await;
    }
    let reader = match master.try_clone_reader() {
        Ok(reader) => reader,
        Err(error) => {
            return reject_tailscale_ssh_session(
                channel,
                format!("failed to open SSH PTY output: {error}"),
            )
            .await;
        }
    };
    let pty_writer = match master.take_writer() {
        Ok(writer) => writer,
        Err(error) => {
            return reject_tailscale_ssh_session(
                channel,
                format!("failed to open SSH PTY input: {error}"),
            )
            .await;
        }
    };
    let slave = pair.slave;
    let child = match tokio::task::spawn_blocking(move || {
        slave
            .spawn_command(command)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
    {
        Ok(child) => child,
        Err(error) => {
            return reject_tailscale_ssh_session(
                channel,
                format!("failed to start SSH PTY process: {error}"),
            )
            .await;
        }
    };
    let pid = child.process_id();
    let process_group = {
        #[cfg(unix)]
        {
            master.process_group_leader()
        }
        #[cfg(not(unix))]
        {
            None
        }
    };
    let mut killer = child.clone_killer();
    let mut child_wait = tokio::task::spawn_blocking(move || {
        let mut child = child;
        child.wait().map_err(|error| error.to_string())
    });

    let (mut channel_reader, channel_writer) = channel.split();
    let channel_writer = Arc::new(channel_writer);
    let (pty_input_tx, mut pty_input_rx) = mpsc::channel::<Vec<u8>>(32);
    let input = tokio::spawn(async move {
        let mut channel_input = channel_reader.make_reader();
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let length = channel_input.read(&mut buffer).await?;
            if length == 0 {
                break;
            }
            if pty_input_tx.send(buffer[..length].to_vec()).await.is_err() {
                break;
            }
        }
        Ok::<_, io::Error>(())
    });
    let pty_input = tokio::task::spawn_blocking(move || {
        let mut writer = pty_writer;
        while let Some(data) = pty_input_rx.blocking_recv() {
            std::io::Write::write_all(&mut writer, &data)?;
            std::io::Write::flush(&mut writer)?;
        }
        Ok::<_, io::Error>(())
    });
    let (pty_output_tx, mut pty_output_rx) = mpsc::channel::<Vec<u8>>(32);
    let pty_output = tokio::task::spawn_blocking(move || {
        let mut reader = reader;
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            match std::io::Read::read(&mut reader, &mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    if pty_output_tx
                        .blocking_send(buffer[..length].to_vec())
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) if tailscale_ssh_pty_eof_error(&error) => break,
                Err(error) => return Err(error),
            }
        }
        Ok::<_, io::Error>(())
    });
    let output_writer = channel_writer.clone();
    let output_recording = request.recording.clone();
    let output_cancellation = cancellation.clone();
    let output = tokio::spawn(async move {
        while let Some(data) = pty_output_rx.recv().await {
            if let Some(recording) = &output_recording
                && let Err(error) = recording.record_output(&data).await
            {
                output_cancellation.cancel();
                return Err(error.to_string());
            }
            output_writer
                .data(std::io::Cursor::new(data))
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok::<_, String>(())
    });

    let status = loop {
        tokio::select! {
            _ = cancellation.cancelled() => {
                let _ = killer.kill();
                break child_wait.await.map_err(|error| error.to_string())??;
            }
            event = events.recv() => {
                match event {
                    Some(TailscaleSshSessionEvent::Resize {
                        columns,
                        rows,
                        width_pixels,
                        height_pixels,
                    }) => {
                        let _ = master.resize(PtySize {
                            rows,
                            cols: columns,
                            pixel_width: width_pixels,
                            pixel_height: height_pixels,
                        });
                    }
                    Some(TailscaleSshSessionEvent::Signal(signal)) => {
                        signal_tailscale_ssh_process_group(
                            process_group,
                            pid,
                            &signal,
                        );
                    }
                    None => {}
                }
            }
            status = &mut child_wait => {
                break status.map_err(|error| error.to_string())??;
            }
        }
    };
    input.abort();
    let _ = input.await;
    let _ = pty_input.await;
    drop(master);
    let _ = pty_output.await;
    let _ = output.await;
    channel_writer
        .exit_status(status.exit_code())
        .await
        .map_err(|error| error.to_string())?;
    let _ = channel_writer.eof().await;
    let _ = channel_writer.close().await;
    Ok(())
}

async fn reject_tailscale_ssh_session(
    channel: Channel<Msg>,
    message: String,
) -> Result<(), String> {
    let (_, writer) = channel.split();
    let body = std::io::Cursor::new(format!("{message}\r\n").into_bytes());
    let _ = writer.extended_data(1, body).await;
    let _ = writer.exit_status(1).await;
    let _ = writer.eof().await;
    let _ = writer.close().await;
    Err(message)
}

#[cfg(all(unix, test))]
fn current_user_identity() -> Result<CurrentUserIdentity, String> {
    use std::ffi::CStr;
    let uid = unsafe { libc::geteuid() };
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer =
        vec![0 as libc::c_char; usize::try_from(size.max(16_384)).unwrap()];
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            record.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(format!("failed to resolve current user (errno {status})"));
    }
    let record = unsafe { record.assume_init() };
    let field = |value: *const libc::c_char| -> String {
        if value.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(value) }
                .to_string_lossy()
                .into_owned()
        }
    };
    let name = field(record.pw_name);
    let home = field(record.pw_dir);
    let shell = field(record.pw_shell);
    Ok(CurrentUserIdentity {
        groups: unix_user_groups(&name, record.pw_gid),
        name,
        home: if home.is_empty() { "/".into() } else { home },
        shell: if shell.is_empty() {
            default_tailscale_ssh_shell()
        } else {
            shell
        },
        uid: record.pw_uid,
        gid: record.pw_gid,
    })
}

#[cfg(unix)]
fn local_user_identity(name: &str) -> Result<CurrentUserIdentity, String> {
    use std::ffi::{CStr, CString};

    let requested = CString::new(name)
        .map_err(|_| "SSH local username contains NUL".to_owned())?;
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer: Vec<libc::c_char> =
        vec![Default::default(); usize::try_from(size.max(16_384)).unwrap()];
    let status = unsafe {
        libc::getpwnam_r(
            requested.as_ptr(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 {
        return Err(format!(
            "failed to resolve SSH local user {name} (errno {status})"
        ));
    }
    if result.is_null() {
        return Err(format!("SSH local user {name} does not exist"));
    }
    let record = unsafe { record.assume_init() };
    let field = |value: *const libc::c_char| -> String {
        if value.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(value) }
                .to_string_lossy()
                .into_owned()
        }
    };
    let resolved_name = field(record.pw_name);
    let home = field(record.pw_dir);
    let shell = field(record.pw_shell);
    Ok(CurrentUserIdentity {
        groups: unix_user_groups(&resolved_name, record.pw_gid),
        name: resolved_name,
        home: if home.is_empty() { "/".into() } else { home },
        shell: if shell.is_empty() {
            default_tailscale_ssh_shell()
        } else {
            shell
        },
        uid: record.pw_uid,
        gid: record.pw_gid,
    })
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn unix_user_groups(name: &str, primary_gid: libc::gid_t) -> Vec<libc::gid_t> {
    let Ok(name) = std::ffi::CString::new(name) else {
        return Vec::new();
    };
    let mut count = 0_i32;
    unsafe {
        libc::getgrouplist(
            name.as_ptr(),
            primary_gid,
            std::ptr::null_mut(),
            &mut count,
        );
    }
    if count <= 0 {
        return Vec::new();
    }
    let mut groups = vec![primary_gid; count as usize];
    let status = unsafe {
        libc::getgrouplist(
            name.as_ptr(),
            primary_gid,
            groups.as_mut_ptr(),
            &mut count,
        )
    };
    if status < 0 || count < 0 {
        return Vec::new();
    }
    groups.truncate(count as usize);
    groups
}

#[cfg(target_vendor = "apple")]
fn unix_user_groups(name: &str, primary_gid: libc::gid_t) -> Vec<libc::gid_t> {
    let Ok(name) = std::ffi::CString::new(name) else {
        return Vec::new();
    };
    let Ok(primary_gid) = libc::c_int::try_from(primary_gid) else {
        return Vec::new();
    };
    let mut count = 0_i32;
    unsafe {
        libc::getgrouplist(
            name.as_ptr(),
            primary_gid,
            std::ptr::null_mut(),
            &mut count,
        );
    }
    if count <= 0 {
        return Vec::new();
    }
    let mut groups = vec![primary_gid; count as usize];
    let status = unsafe {
        libc::getgrouplist(
            name.as_ptr(),
            primary_gid,
            groups.as_mut_ptr(),
            &mut count,
        )
    };
    if status < 0 || count < 0 {
        return Vec::new();
    }
    groups.truncate(count as usize);
    groups
        .into_iter()
        .filter_map(|group| libc::gid_t::try_from(group).ok())
        .collect()
}

#[cfg(unix)]
fn default_tailscale_ssh_shell() -> String {
    ["/bin/zsh", "/bin/bash", "/bin/sh"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .unwrap_or("/bin/sh")
        .into()
}

#[cfg(unix)]
fn validate_tailscale_ssh_user_switch(
    identity: &CurrentUserIdentity,
) -> Result<(), String> {
    let current_uid = unsafe { libc::geteuid() };
    let current_gid = unsafe { libc::getegid() };
    if identity.uid == current_uid && identity.gid == current_gid {
        return Ok(());
    }
    if current_uid != 0 {
        return Err(format!(
            "SSH session cannot switch from uid {current_uid}/gid {current_gid} to local user {} (uid {}/gid {}) without root privileges",
            identity.name, identity.uid, identity.gid
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn configure_tailscale_ssh_unix_child(
    command: &mut Command,
    identity: &CurrentUserIdentity,
    controlling_terminal: bool,
) {
    let uid = identity.uid;
    let gid = identity.gid;
    let current_uid = unsafe { libc::geteuid() };
    let current_gid = unsafe { libc::getegid() };
    let switch_identity = uid != current_uid || gid != current_gid;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let groups = {
        let mut groups = identity.groups.clone();
        groups.truncate(16);
        groups
    };
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let groups = identity.groups.clone();
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if controlling_terminal
                && libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if switch_identity {
                if tailscale_ssh_setgroups(&groups) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setgid(gid) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(uid) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
unsafe fn tailscale_ssh_setgroups(groups: &[libc::gid_t]) -> libc::c_int {
    unsafe { libc::setgroups(groups.len(), groups.as_ptr()) }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
unsafe fn tailscale_ssh_setgroups(groups: &[libc::gid_t]) -> libc::c_int {
    let Ok(count) = libc::c_int::try_from(groups.len()) else {
        return -1;
    };
    unsafe { libc::setgroups(count, groups.as_ptr()) }
}

#[cfg(not(unix))]
fn current_user_identity() -> Result<CurrentUserIdentity, String> {
    let name = std::env::var("USERNAME")
        .map_err(|_| "current Windows username is unavailable".to_owned())?;
    Ok(CurrentUserIdentity {
        name,
        home: std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".into()),
        shell: std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into()),
    })
}

#[cfg(not(unix))]
fn local_user_identity(name: &str) -> Result<CurrentUserIdentity, String> {
    let identity = current_user_identity()?;
    if identity.name.eq_ignore_ascii_case(name) {
        Ok(identity)
    } else {
        Err(format!(
            "SSH session cannot impersonate local user {name} while running as {}",
            identity.name
        ))
    }
}

fn default_tailscale_ssh_path() -> &'static str {
    if cfg!(windows) {
        r"C:\Windows\System32;C:\Windows"
    } else {
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    }
}

fn new_tailscale_ssh_connection_id() -> String {
    let timestamp = OffsetDateTime::now_utc()
        .format(time::macros::format_description!(
            "[year][month][day]T[hour][minute][second]"
        ))
        .unwrap_or_else(|_| "00000000T000000".into());
    let mut random = [0_u8; 5];
    let _ = getrandom::fill(&mut random);
    format!("ssh-conn-{timestamp}-{}", hex::encode(random))
}

#[cfg(all(unix, test))]
fn apply_tailscale_ssh_terminal_modes(
    master: &dyn portable_pty::MasterPty,
    modes: &[(russh::Pty, u32)],
) -> io::Result<()> {
    let Some(fd) = master.as_raw_fd() else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "PTY does not expose a terminal file descriptor",
        ));
    };
    apply_tailscale_ssh_terminal_modes_fd(fd, modes)
}

#[cfg(unix)]
fn apply_tailscale_ssh_terminal_modes_fd(
    fd: libc::c_int,
    modes: &[(russh::Pty, u32)],
) -> io::Result<()> {
    let mut attributes = unsafe {
        let mut attributes = std::mem::zeroed::<libc::termios>();
        if libc::tcgetattr(fd, &mut attributes) != 0 {
            return Err(io::Error::last_os_error());
        }
        attributes
    };
    for (mode, value) in modes {
        let enabled = *value != 0;
        match mode {
            russh::Pty::VINTR => {
                attributes.c_cc[libc::VINTR] = *value as libc::cc_t
            }
            russh::Pty::VQUIT => {
                attributes.c_cc[libc::VQUIT] = *value as libc::cc_t
            }
            russh::Pty::VERASE => {
                attributes.c_cc[libc::VERASE] = *value as libc::cc_t
            }
            russh::Pty::VKILL => {
                attributes.c_cc[libc::VKILL] = *value as libc::cc_t
            }
            russh::Pty::VEOF => {
                attributes.c_cc[libc::VEOF] = *value as libc::cc_t
            }
            russh::Pty::VEOL => {
                attributes.c_cc[libc::VEOL] = *value as libc::cc_t
            }
            #[cfg(any(
                target_os = "android",
                target_os = "linux",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            russh::Pty::VEOL2 => {
                attributes.c_cc[libc::VEOL2] = *value as libc::cc_t
            }
            russh::Pty::VSTART => {
                attributes.c_cc[libc::VSTART] = *value as libc::cc_t
            }
            russh::Pty::VSTOP => {
                attributes.c_cc[libc::VSTOP] = *value as libc::cc_t
            }
            russh::Pty::VSUSP => {
                attributes.c_cc[libc::VSUSP] = *value as libc::cc_t
            }
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            russh::Pty::VDSUSP => {
                attributes.c_cc[libc::VDSUSP] = *value as libc::cc_t
            }
            #[cfg(any(
                target_os = "android",
                target_os = "linux",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            russh::Pty::VREPRINT => {
                attributes.c_cc[libc::VREPRINT] = *value as libc::cc_t
            }
            #[cfg(any(
                target_os = "android",
                target_os = "linux",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            russh::Pty::VWERASE => {
                attributes.c_cc[libc::VWERASE] = *value as libc::cc_t
            }
            #[cfg(any(
                target_os = "android",
                target_os = "linux",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            russh::Pty::VLNEXT => {
                attributes.c_cc[libc::VLNEXT] = *value as libc::cc_t
            }
            #[cfg(any(
                target_os = "android",
                target_os = "linux",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            russh::Pty::VFLUSH | russh::Pty::VDISCARD => {
                attributes.c_cc[libc::VDISCARD] = *value as libc::cc_t
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            russh::Pty::VSWTCH => {
                attributes.c_cc[libc::VSWTC] = *value as libc::cc_t
            }
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            russh::Pty::VSTATUS => {
                attributes.c_cc[libc::VSTATUS] = *value as libc::cc_t
            }
            russh::Pty::IGNPAR => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::IGNPAR,
                enabled,
            ),
            russh::Pty::PARMRK => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::PARMRK,
                enabled,
            ),
            russh::Pty::INPCK => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::INPCK,
                enabled,
            ),
            russh::Pty::ISTRIP => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::ISTRIP,
                enabled,
            ),
            russh::Pty::INLCR => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::INLCR,
                enabled,
            ),
            russh::Pty::IGNCR => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::IGNCR,
                enabled,
            ),
            russh::Pty::ICRNL => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::ICRNL,
                enabled,
            ),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            russh::Pty::IUCLC => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::IUCLC,
                enabled,
            ),
            russh::Pty::IXON => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::IXON,
                enabled,
            ),
            #[cfg(any(
                target_os = "android",
                target_os = "linux",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            russh::Pty::IXANY => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::IXANY,
                enabled,
            ),
            russh::Pty::IXOFF => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::IXOFF,
                enabled,
            ),
            #[cfg(any(
                target_os = "android",
                target_os = "linux",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            russh::Pty::IMAXBEL => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::IMAXBEL,
                enabled,
            ),
            #[cfg(any(
                target_os = "android",
                target_os = "linux",
                target_os = "macos",
                target_os = "ios"
            ))]
            russh::Pty::IUTF8 => set_tailscale_ssh_termios_flag(
                &mut attributes.c_iflag,
                libc::IUTF8,
                enabled,
            ),
            russh::Pty::ISIG => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::ISIG,
                enabled,
            ),
            russh::Pty::ICANON => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::ICANON,
                enabled,
            ),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            russh::Pty::XCASE => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::XCASE,
                enabled,
            ),
            russh::Pty::ECHO => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::ECHO,
                enabled,
            ),
            russh::Pty::ECHOE => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::ECHOE,
                enabled,
            ),
            russh::Pty::ECHOK => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::ECHOK,
                enabled,
            ),
            russh::Pty::ECHONL => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::ECHONL,
                enabled,
            ),
            russh::Pty::NOFLSH => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::NOFLSH,
                enabled,
            ),
            russh::Pty::TOSTOP => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::TOSTOP,
                enabled,
            ),
            russh::Pty::IEXTEN => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::IEXTEN,
                enabled,
            ),
            #[cfg(any(
                target_os = "android",
                target_os = "linux",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            russh::Pty::ECHOCTL => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::ECHOCTL,
                enabled,
            ),
            #[cfg(any(
                target_os = "android",
                target_os = "linux",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            russh::Pty::ECHOKE => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::ECHOKE,
                enabled,
            ),
            #[cfg(any(
                target_os = "android",
                target_os = "linux",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            russh::Pty::PENDIN => set_tailscale_ssh_termios_flag(
                &mut attributes.c_lflag,
                libc::PENDIN,
                enabled,
            ),
            russh::Pty::OPOST => set_tailscale_ssh_termios_flag(
                &mut attributes.c_oflag,
                libc::OPOST,
                enabled,
            ),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            russh::Pty::OLCUC => set_tailscale_ssh_termios_flag(
                &mut attributes.c_oflag,
                libc::OLCUC,
                enabled,
            ),
            russh::Pty::ONLCR => set_tailscale_ssh_termios_flag(
                &mut attributes.c_oflag,
                libc::ONLCR,
                enabled,
            ),
            russh::Pty::OCRNL => set_tailscale_ssh_termios_flag(
                &mut attributes.c_oflag,
                libc::OCRNL,
                enabled,
            ),
            russh::Pty::ONOCR => set_tailscale_ssh_termios_flag(
                &mut attributes.c_oflag,
                libc::ONOCR,
                enabled,
            ),
            russh::Pty::ONLRET => set_tailscale_ssh_termios_flag(
                &mut attributes.c_oflag,
                libc::ONLRET,
                enabled,
            ),
            russh::Pty::CS7 if enabled => {
                attributes.c_cflag &= !libc::CSIZE;
                attributes.c_cflag |= libc::CS7;
            }
            russh::Pty::CS8 if enabled => {
                attributes.c_cflag &= !libc::CSIZE;
                attributes.c_cflag |= libc::CS8;
            }
            russh::Pty::PARENB => set_tailscale_ssh_termios_flag(
                &mut attributes.c_cflag,
                libc::PARENB,
                enabled,
            ),
            russh::Pty::PARODD => set_tailscale_ssh_termios_flag(
                &mut attributes.c_cflag,
                libc::PARODD,
                enabled,
            ),
            russh::Pty::TTY_OP_ISPEED => {
                if let Some(speed) = tailscale_ssh_baud_rate(*value) {
                    unsafe {
                        libc::cfsetispeed(&mut attributes, speed);
                    }
                }
            }
            russh::Pty::TTY_OP_OSPEED => {
                if let Some(speed) = tailscale_ssh_baud_rate(*value) {
                    unsafe {
                        libc::cfsetospeed(&mut attributes, speed);
                    }
                }
            }
            _ => {}
        }
    }
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &attributes) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn set_tailscale_ssh_termios_flag(
    field: &mut libc::tcflag_t,
    flag: libc::tcflag_t,
    enabled: bool,
) {
    if enabled {
        *field |= flag;
    } else {
        *field &= !flag;
    }
}

#[cfg(unix)]
fn tailscale_ssh_baud_rate(value: u32) -> Option<libc::speed_t> {
    Some(match value {
        0 => libc::B0,
        50 => libc::B50,
        75 => libc::B75,
        110 => libc::B110,
        134 => libc::B134,
        150 => libc::B150,
        200 => libc::B200,
        300 => libc::B300,
        600 => libc::B600,
        1200 => libc::B1200,
        1800 => libc::B1800,
        2400 => libc::B2400,
        4800 => libc::B4800,
        9600 => libc::B9600,
        19_200 => libc::B19200,
        38_400 => libc::B38400,
        57_600 => libc::B57600,
        115_200 => libc::B115200,
        _ => return None,
    })
}

pub fn tailscale_ssh_sftp_server_path() -> Option<PathBuf> {
    [
        "/usr/libexec/sftp-server",
        "/usr/lib/openssh/sftp-server",
        "/usr/lib/ssh/sftp-server",
        "/usr/libexec/openssh/sftp-server",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
}

#[cfg(unix)]
fn signal_tailscale_ssh_process(pid: Option<u32>, signal: &russh::Sig) {
    let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) else {
        return;
    };
    let Some(signal) = tailscale_ssh_signal_number(signal) else {
        return;
    };
    unsafe {
        libc::kill(pid, signal);
    }
}

#[cfg(unix)]
fn tailscale_ssh_signal_number(signal: &russh::Sig) -> Option<i32> {
    Some(match signal {
        russh::Sig::ABRT => libc::SIGABRT,
        russh::Sig::ALRM => libc::SIGALRM,
        russh::Sig::FPE => libc::SIGFPE,
        russh::Sig::HUP => libc::SIGHUP,
        russh::Sig::ILL => libc::SIGILL,
        russh::Sig::INT => libc::SIGINT,
        russh::Sig::KILL => libc::SIGKILL,
        russh::Sig::PIPE => libc::SIGPIPE,
        russh::Sig::QUIT => libc::SIGQUIT,
        russh::Sig::SEGV => libc::SIGSEGV,
        russh::Sig::TERM => libc::SIGTERM,
        russh::Sig::USR1 => libc::SIGUSR1,
        russh::Sig::Custom(_) => return None,
    })
}

#[cfg(unix)]
fn signal_tailscale_ssh_process_group(
    process_group: Option<i32>,
    pid: Option<u32>,
    signal: &russh::Sig,
) {
    let Some(signal) = tailscale_ssh_signal_number(signal) else {
        return;
    };
    let target = process_group
        .map(|process_group| -process_group.abs())
        .or_else(|| pid.and_then(|pid| i32::try_from(pid).ok()));
    if let Some(target) = target {
        unsafe {
            libc::kill(target, signal);
        }
    }
}

#[cfg(not(unix))]
fn signal_tailscale_ssh_process(_pid: Option<u32>, _signal: &russh::Sig) {}

#[cfg(not(unix))]
fn signal_tailscale_ssh_process_group(
    _process_group: Option<i32>,
    pid: Option<u32>,
    signal: &russh::Sig,
) {
    signal_tailscale_ssh_process(pid, signal);
}

#[cfg(unix)]
fn tailscale_ssh_pty_eof_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EIO)
}

#[cfg(not(unix))]
fn tailscale_ssh_pty_eof_error(_error: &io::Error) -> bool {
    false
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TailscaleSshSocketIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
async fn tailscale_ssh_socket_identity(
    path: &str,
) -> io::Result<TailscaleSshSocketIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = tokio::fs::symlink_metadata(path).await?;
    Ok(TailscaleSshSocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
async fn remove_tailscale_ssh_socket_if_owned(
    path: &str,
    expected: TailscaleSshSocketIdentity,
) {
    if tailscale_ssh_socket_identity(path).await.ok() == Some(expected) {
        let _ = tokio::fs::remove_file(path).await;
    }
}

#[cfg(unix)]
struct TailscaleSshAgentForwarder {
    socket_path: String,
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

#[cfg(not(unix))]
struct TailscaleSshAgentForwarder;

#[cfg(not(unix))]
impl TailscaleSshAgentForwarder {
    fn socket_path(&self) -> &str {
        ""
    }

    async fn close(self) {}
}

#[cfg(unix)]
impl TailscaleSshAgentForwarder {
    fn socket_path(&self) -> &str {
        &self.socket_path
    }

    async fn close(mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

#[cfg(unix)]
impl Drop for TailscaleSshAgentForwarder {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[cfg(unix)]
async fn start_tailscale_ssh_agent_forwarder(
    handle: server::Handle,
    parent_cancellation: &CancellationToken,
    local_user: &str,
) -> io::Result<TailscaleSshAgentForwarder> {
    use std::os::unix::fs::PermissionsExt as _;

    let identity = local_user_identity(local_user).map_err(io::Error::other)?;
    validate_tailscale_ssh_user_switch(&identity).map_err(io::Error::other)?;
    let switched_user = identity.uid != unsafe { libc::geteuid() }
        || identity.gid != unsafe { libc::getegid() };

    // Darwin's sockaddr_un path is only 104 bytes; its TMPDIR is commonly
    // already long enough that a descriptive directory plus socket overflows.
    let temporary_root = if Path::new("/tmp").is_dir() {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    let random = uuid::Uuid::new_v4().simple().to_string();
    let directory = temporary_root.join(format!("tsa-{}", &random[..16]));
    tokio::fs::create_dir(&directory).await?;
    if let Err(error) = tokio::fs::set_permissions(
        &directory,
        std::fs::Permissions::from_mode(0o700),
    )
    .await
    {
        let _ = tokio::fs::remove_dir(&directory).await;
        return Err(error);
    }
    let directory_path = directory.to_string_lossy().into_owned();
    let directory_identity =
        match tailscale_ssh_socket_identity(&directory_path).await {
            Ok(identity) => identity,
            Err(error) => {
                let _ = tokio::fs::remove_dir(&directory).await;
                return Err(error);
            }
        };
    let socket_path = directory.join("listener.sock");
    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = tokio::fs::remove_dir(&directory).await;
            return Err(error);
        }
    };
    if let Err(error) = tokio::fs::set_permissions(
        &socket_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .await
    {
        drop(listener);
        let _ = tokio::fs::remove_file(&socket_path).await;
        let _ = tokio::fs::remove_dir(&directory).await;
        return Err(error);
    }
    if switched_user {
        if let Err(error) =
            chown_tailscale_ssh_path(&socket_path, identity.uid, identity.gid)
        {
            drop(listener);
            let _ = tokio::fs::remove_file(&socket_path).await;
            let _ = tokio::fs::remove_dir(&directory).await;
            return Err(error);
        }
        if let Err(error) = tokio::fs::set_permissions(
            &directory,
            std::fs::Permissions::from_mode(0o755),
        )
        .await
        {
            drop(listener);
            let _ = tokio::fs::remove_file(&socket_path).await;
            let _ = tokio::fs::remove_dir(&directory).await;
            return Err(error);
        }
    }
    let socket_path = socket_path.to_string_lossy().into_owned();
    let socket_identity =
        match tailscale_ssh_socket_identity(&socket_path).await {
            Ok(identity) => identity,
            Err(error) => {
                drop(listener);
                let _ = tokio::fs::remove_file(&socket_path).await;
                let _ = tokio::fs::remove_dir(&directory).await;
                return Err(error);
            }
        };
    let cancellation = parent_cancellation.child_token();
    let task_cancellation = cancellation.clone();
    let task_socket_path = socket_path.clone();
    let task = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = task_cancellation.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((mut local, _)) = accepted else {
                break;
            };
            let handle = handle.clone();
            let connection_cancellation = task_cancellation.child_token();
            tokio::spawn(async move {
                let Ok(channel) = handle.channel_open_agent().await else {
                    return;
                };
                let mut channel = channel.into_stream();
                tokio::select! {
                    _ = connection_cancellation.cancelled() => {}
                    _ = tokio::io::copy_bidirectional(&mut channel, &mut local) => {}
                }
            });
        }
        drop(listener);
        remove_tailscale_ssh_socket_if_owned(
            &task_socket_path,
            socket_identity,
        )
        .await;
        if tailscale_ssh_socket_identity(&directory_path).await.ok()
            == Some(directory_identity)
        {
            let _ = tokio::fs::remove_dir(&directory_path).await;
        }
    });
    Ok(TailscaleSshAgentForwarder {
        socket_path,
        cancellation,
        task: Some(task),
    })
}

#[cfg(unix)]
fn chown_tailscale_ssh_path(
    path: &Path,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;

    let path =
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL")
        })?;
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleSshPolicyDecision {
    Accept(Box<TailscaleSshAuthorization>),
    HoldAndDelegate(Box<TailscaleSshAuthorization>),
    Reject { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleSshDelegateContext<'a> {
    pub source_node_ip: IpAddr,
    pub source_node_id: i64,
    pub destination_node_ip: IpAddr,
    pub destination_node_id: i64,
    pub requested_user: &'a str,
    pub local_user: &'a str,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TailscaleSshPolicyError {
    #[error("tailscale ssh: no policy")]
    NoPolicy,
    #[error("tailscale ssh: no matching rule")]
    NoMatchingRule,
    #[error("tailscale ssh: invalid rule expiry: {0}")]
    InvalidRuleExpiry(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TailscaleSshDelegationError {
    #[error("Tailscale SSH delegation was cancelled")]
    Cancelled,
    #[error("Tailscale SSH delegation timed out")]
    TimedOut,
    #[error("Tailscale SSH delegation chain exceeds {0} hops")]
    TooManyHops(usize),
    #[error("Tailscale SSH delegation rejected the session: {0}")]
    Rejected(String),
}

/// Authenticated control-plane request hook. The endpoint supplies a Noise
/// control client; tests and alternative embedders can inject the same narrow
/// operation without exposing SSH credentials or transport internals.
#[async_trait]
pub trait TailscaleSshDelegateClient: Send + Sync {
    async fn request_action(
        &self,
        url: &str,
    ) -> Result<TailscaleSshAction, String>;
}

/// Sends session-recording failures over the authenticated control channel.
#[async_trait]
pub trait TailscaleSshRecordingNotifier: Send + Sync {
    async fn notify_recording_event(
        &self,
        url: &str,
        notification: &TailscaleSshRecordingNotification,
    ) -> Result<(), String>;
}

/// Opens a fresh authenticated TS2021 connection for each delegated decision,
/// matching LocalBackend.DoNoiseRequest without sharing the streaming map
/// session. Delegate URLs are restricted to the configured control authority
/// so a policy cannot exfiltrate machine-authenticated requests elsewhere.
pub struct TailscaleSshControlDelegateClient {
    connector: Arc<TailscaleTs2021DialConnector>,
}

impl TailscaleSshControlDelegateClient {
    pub fn new(connector: Arc<TailscaleTs2021DialConnector>) -> Self {
        Self { connector }
    }
}

#[async_trait]
impl TailscaleSshDelegateClient for TailscaleSshControlDelegateClient {
    async fn request_action(
        &self,
        url: &str,
    ) -> Result<TailscaleSshAction, String> {
        let path = tailscale_ssh_delegate_control_path(
            url,
            &self.connector.authority,
        )?;
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header("host", &self.connector.authority)
            .body(Full::new(Bytes::new()))
            .map_err(|error| error.to_string())?;
        for key in &self.connector.load_balancer_keys {
            let value = http::HeaderValue::from_str(key)
                .map_err(|error| error.to_string())?;
            request.headers_mut().append("ts-lb", value);
        }
        let mut client = self
            .connector
            .connect_http2_client()
            .await
            .map_err(|error| error.to_string())?;
        let response = client
            .send_request(request)
            .await
            .map_err(|error| error.to_string())?;
        decode_tailscale_control_json_response(
            response,
            TAILSCALE_SSH_DELEGATE_RESPONSE_LIMIT,
        )
        .await
        .map_err(|error| error.to_string())
    }
}

#[async_trait]
impl TailscaleSshRecordingNotifier for TailscaleSshControlDelegateClient {
    async fn notify_recording_event(
        &self,
        url: &str,
        notification: &TailscaleSshRecordingNotification,
    ) -> Result<(), String> {
        let path = tailscale_ssh_notification_control_path(url)?;
        let body = serde_json::to_vec(notification)
            .map_err(|error| error.to_string())?;
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("host", &self.connector.authority)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|error| error.to_string())?;
        for key in &self.connector.load_balancer_keys {
            let value = http::HeaderValue::from_str(key)
                .map_err(|error| error.to_string())?;
            request.headers_mut().append("ts-lb", value);
        }
        let mut client = self
            .connector
            .connect_http2_client()
            .await
            .map_err(|error| error.to_string())?;
        let response = client
            .send_request(request)
            .await
            .map_err(|error| error.to_string())?;
        if response.status() != http::StatusCode::CREATED {
            return Err(format!(
                "SSH recording notification returned status {}",
                response.status()
            ));
        }
        Ok(())
    }
}

fn tailscale_ssh_notification_control_path(
    url: &str,
) -> Result<String, String> {
    let url = url::Url::parse(url)
        .map_err(|error| format!("invalid SSH notification URL: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("SSH notification URL must use HTTP or HTTPS".into());
    }
    if url.host_str().is_none() {
        return Err("SSH notification URL is missing a host".into());
    }
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    Ok(path)
}

fn tailscale_ssh_delegate_control_path(
    delegate_url: &str,
    control_authority: &str,
) -> Result<String, String> {
    let url = url::Url::parse(delegate_url)
        .map_err(|error| format!("invalid SSH delegate URL: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("SSH delegate URL must use HTTP or HTTPS".into());
    }
    let expected = control_authority
        .parse::<http::uri::Authority>()
        .map_err(|error| format!("invalid control authority: {error}"))?;
    let Some(host) = url.host_str() else {
        return Err("SSH delegate URL is missing a host".into());
    };
    let expected_host = expected.host().trim_matches(['[', ']']);
    let expected_port = expected
        .port_u16()
        .or_else(|| (url.scheme() == "https").then_some(443))
        .or_else(|| (url.scheme() == "http").then_some(80));
    if !host.eq_ignore_ascii_case(expected_host)
        || url.port_or_known_default() != expected_port
    {
        return Err(
            "SSH delegate URL does not match the control authority".into()
        );
    }
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    Ok(path)
}

/// Resolve an upstream `holdAndDelegate` chain. Temporary request, HTTP, or
/// JSON failures retry once per second until the connection is cancelled or
/// the exact 30-minute deadline elapses.
pub async fn resolve_tailscale_ssh_delegation(
    authorization: TailscaleSshAuthorization,
    context: &TailscaleSshDelegateContext<'_>,
    client: &(dyn TailscaleSshDelegateClient + Send + Sync),
    cancellation: &CancellationToken,
) -> Result<TailscaleSshAuthorization, TailscaleSshDelegationError> {
    resolve_tailscale_ssh_delegation_with_limits(
        authorization,
        context,
        client,
        cancellation,
        TAILSCALE_SSH_DELEGATION_TIMEOUT,
        Duration::from_secs(1),
    )
    .await
}

async fn resolve_tailscale_ssh_delegation_with_limits(
    mut authorization: TailscaleSshAuthorization,
    context: &TailscaleSshDelegateContext<'_>,
    client: &(dyn TailscaleSshDelegateClient + Send + Sync),
    cancellation: &CancellationToken,
    timeout: Duration,
    retry_delay: Duration,
) -> Result<TailscaleSshAuthorization, TailscaleSshDelegationError> {
    let deadline = tokio::time::Instant::now() + timeout;
    for hop in 0..=TAILSCALE_SSH_MAXIMUM_DELEGATION_HOPS {
        if authorization.action.hold_and_delegate.is_empty() {
            if authorization.action.reject || !authorization.action.accept {
                return Err(TailscaleSshDelegationError::Rejected(
                    authorization.action.message.clone(),
                ));
            }
            return Ok(authorization);
        }
        if hop == TAILSCALE_SSH_MAXIMUM_DELEGATION_HOPS {
            return Err(TailscaleSshDelegationError::TooManyHops(
                TAILSCALE_SSH_MAXIMUM_DELEGATION_HOPS,
            ));
        }
        let url = expand_tailscale_ssh_delegate_url(
            &authorization.action.hold_and_delegate,
            context,
        );
        loop {
            let action = tokio::select! {
                _ = cancellation.cancelled() => {
                    return Err(TailscaleSshDelegationError::Cancelled);
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(TailscaleSshDelegationError::TimedOut);
                }
                result = client.request_action(&url) => result,
            };
            match action {
                Ok(action) => {
                    authorization.action = action;
                    break;
                }
                Err(_) => {
                    tokio::select! {
                        _ = cancellation.cancelled() => {
                            return Err(TailscaleSshDelegationError::Cancelled);
                        }
                        _ = tokio::time::sleep_until(deadline) => {
                            return Err(TailscaleSshDelegationError::TimedOut);
                        }
                        _ = tokio::time::sleep(retry_delay) => {}
                    }
                }
            }
        }
    }
    unreachable!("delegation loop returns at the configured hop bound")
}

#[derive(Debug, Error)]
pub enum TailscaleSshHostKeyError {
    #[error("Tailscale SSH host-key I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid Tailscale SSH host key: {0}")]
    InvalidKey(String),
    #[error("failed to generate Tailscale SSH host key: {0}")]
    Generate(String),
}

/// Load the stable Ed25519 host key used by the embedded Tailscale SSH
/// listener, or create it atomically with private permissions. A malformed
/// existing key is never overwritten silently.
pub async fn load_or_generate_tailscale_ssh_server_identity(
    state_directory: &Path,
) -> Result<TailscaleSshServerIdentity, TailscaleSshHostKeyError> {
    let path = state_directory.join(TAILSCALE_SSH_HOST_KEY_FILE_NAME);
    let key = match tokio::fs::read_to_string(&path).await {
        Ok(encoded) => russh::keys::PrivateKey::from_openssh(&encoded)
            .map_err(|error| {
                TailscaleSshHostKeyError::InvalidKey(error.to_string())
            })?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            tokio::fs::create_dir_all(state_directory).await?;
            restrict_tailscale_ssh_directory(state_directory).await?;
            let key = russh::keys::PrivateKey::random(
                &mut russh::keys::key::safe_rng(),
                russh::keys::Algorithm::Ed25519,
            )
            .map_err(|error| {
                TailscaleSshHostKeyError::Generate(error.to_string())
            })?;
            let encoded = key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .map_err(|error| {
                    TailscaleSshHostKeyError::Generate(error.to_string())
                })?;
            write_tailscale_ssh_host_key_atomically(&path, encoded.as_bytes())
                .await?;
            key
        }
        Err(error) => return Err(error.into()),
    };
    restrict_tailscale_ssh_file(&path).await?;
    let public_key = key.public_key().to_openssh().map_err(|error| {
        TailscaleSshHostKeyError::InvalidKey(error.to_string())
    })?;
    let config = server::Config {
        server_id: russh::SshId::Standard(Cow::Borrowed("SSH-2.0-sing-box")),
        keys: vec![key],
        ..Default::default()
    };
    Ok(TailscaleSshServerIdentity {
        config: Arc::new(config),
        public_key,
        path,
    })
}

async fn write_tailscale_ssh_host_key_atomically(
    path: &Path,
    encoded: &[u8],
) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let temporary = parent.join(format!(
        ".{TAILSCALE_SSH_HOST_KEY_FILE_NAME}.{}.tmp",
        hex::encode(suffix)
    ));
    let result = async {
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        set_tailscale_ssh_private_file_mode(&mut options);
        let mut file = options.open(&temporary).await?;
        file.write_all(encoded).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temporary, path).await?;
        restrict_tailscale_ssh_file(path).await
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
    }
    result
}

#[cfg(unix)]
fn set_tailscale_ssh_private_file_mode(options: &mut tokio::fs::OpenOptions) {
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_tailscale_ssh_private_file_mode(_options: &mut tokio::fs::OpenOptions) {}

#[cfg(unix)]
async fn restrict_tailscale_ssh_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
}

#[cfg(not(unix))]
async fn restrict_tailscale_ssh_file(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
async fn restrict_tailscale_ssh_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .await
}

#[cfg(not(unix))]
async fn restrict_tailscale_ssh_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Resolve an authenticated WireGuard source address to the identity used by
/// SSH policy. Connections not represented in the current netmap fail closed.
pub fn tailscale_ssh_peer_identity(
    netmap: &TailscaleNetmapState,
    source: IpAddr,
) -> Option<TailscaleSshPeerIdentity> {
    let source = match source {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        source => source,
    };
    let peer = netmap.peers.values().find(|peer| {
        peer.addresses.iter().any(|address| {
            address
                .parse::<ipnet::IpNet>()
                .is_ok_and(|prefix| prefix.contains(&source))
        })
    })?;
    let user_login = netmap
        .user_profiles
        .get(&peer.user)
        .map(|profile| profile.login_name.clone())
        .unwrap_or_default();
    let addresses = peer
        .addresses
        .iter()
        .filter_map(|address| address.parse::<ipnet::IpNet>().ok())
        .map(|prefix| prefix.addr())
        .collect();
    Some(TailscaleSshPeerIdentity {
        node_id: peer.id,
        stable_id: peer.stable_id.clone(),
        name: peer.name.trim_end_matches('.').to_owned(),
        user_id: peer.user,
        tags: peer.tags.clone(),
        addresses,
        user_login,
        tagged: !peer.tags.is_empty(),
    })
}

/// Per-connection SSH transport handler. Tailscale authenticates the peer at
/// the WireGuard layer, so SSH password/public-key contents do not grant
/// access; every SSH auth method is gated by the current tailnet SSH policy.
pub struct TailscaleSshConnectionHandler {
    policy: Arc<RwLock<Option<TailscaleSshPolicy>>>,
    peer: TailscaleSshPeerIdentity,
    source_ip: IpAddr,
    source_address: Option<SocketAddr>,
    destination_address: Option<SocketAddr>,
    dialer: Arc<dyn Dialer>,
    disable_forwarding: bool,
    authorization: Option<TailscaleSshAuthorization>,
    delegation: Option<TailscaleSshConnectionDelegation>,
    recording_notifier: Option<TailscaleSshConnectionRecordingNotifier>,
    session_backend: Option<Arc<dyn TailscaleSshSessionBackend>>,
    disable_pty: bool,
    disable_sftp: bool,
    environment_capability: bool,
    pending_sessions: HashMap<ChannelId, PendingTailscaleSshSession>,
    running_sessions:
        Arc<Mutex<HashMap<ChannelId, RunningTailscaleSshSession>>>,
    remote_forwards: HashMap<(String, u16), CancellationToken>,
    #[cfg(unix)]
    streamlocal_forwards: HashMap<String, CancellationToken>,
    session_cancellation: CancellationToken,
    connection_id: String,
}

struct TailscaleSshConnectionDelegation {
    client: Arc<dyn TailscaleSshDelegateClient>,
    destination_ip: IpAddr,
    destination_node_id: i64,
    cancellation: CancellationToken,
}

#[derive(Clone)]
struct TailscaleSshConnectionRecordingNotifier {
    client: Arc<dyn TailscaleSshRecordingNotifier>,
    node_key: String,
    capability_version: u32,
}

struct PendingTailscaleSshSession {
    channel: Channel<Msg>,
    environment: BTreeMap<String, String>,
    pty: Option<TailscaleSshPtyRequest>,
    agent_forwarding: bool,
    session_handle: server::Handle,
}

struct RunningTailscaleSshSession {
    events: mpsc::Sender<TailscaleSshSessionEvent>,
    cancellation: CancellationToken,
}

impl TailscaleSshConnectionHandler {
    pub fn new(
        policy: Arc<RwLock<Option<TailscaleSshPolicy>>>,
        peer: TailscaleSshPeerIdentity,
        source_ip: IpAddr,
        dialer: Arc<dyn Dialer>,
        disable_forwarding: bool,
    ) -> Self {
        Self {
            policy,
            peer,
            source_ip,
            source_address: None,
            destination_address: None,
            dialer,
            disable_forwarding,
            authorization: None,
            delegation: None,
            recording_notifier: None,
            session_backend: None,
            disable_pty: false,
            disable_sftp: false,
            environment_capability: false,
            pending_sessions: HashMap::new(),
            running_sessions: Arc::new(Mutex::new(HashMap::new())),
            remote_forwards: HashMap::new(),
            #[cfg(unix)]
            streamlocal_forwards: HashMap::new(),
            session_cancellation: CancellationToken::new(),
            connection_id: new_tailscale_ssh_connection_id(),
        }
    }

    pub fn with_delegation(
        mut self,
        client: Arc<dyn TailscaleSshDelegateClient>,
        destination_ip: IpAddr,
        destination_node_id: i64,
        cancellation: CancellationToken,
    ) -> Self {
        self.delegation = Some(TailscaleSshConnectionDelegation {
            client,
            destination_ip,
            destination_node_id,
            cancellation,
        });
        self
    }

    pub fn with_connection_addresses(
        mut self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Self {
        self.source_address = Some(source);
        self.destination_address = Some(destination);
        self
    }

    pub fn with_recording_notifier(
        mut self,
        client: Arc<dyn TailscaleSshRecordingNotifier>,
        node_key: impl Into<String>,
        capability_version: u32,
    ) -> Self {
        self.recording_notifier =
            Some(TailscaleSshConnectionRecordingNotifier {
                client,
                node_key: node_key.into(),
                capability_version,
            });
        self
    }

    pub fn with_session_backend(
        mut self,
        backend: Arc<dyn TailscaleSshSessionBackend>,
        disable_pty: bool,
        disable_sftp: bool,
        environment_capability: bool,
    ) -> Self {
        self.session_backend = Some(backend);
        self.disable_pty = disable_pty;
        self.disable_sftp = disable_sftp;
        self.environment_capability = environment_capability;
        self
    }

    pub fn authorization(&self) -> Option<&TailscaleSshAuthorization> {
        self.authorization.as_ref()
    }

    fn recording_notification(
        &self,
        event_type: TailscaleSshRecordingEventType,
        authorization: &TailscaleSshAuthorization,
        recording_attempts: Vec<TailscaleSshRecordingAttempt>,
    ) -> Option<(
        Arc<dyn TailscaleSshRecordingNotifier>,
        TailscaleSshRecordingNotification,
    )> {
        let notifier = self.recording_notifier.as_ref()?;
        Some((
            notifier.client.clone(),
            TailscaleSshRecordingNotification {
                event_type,
                connection_id: self.connection_id.clone(),
                cap_version: notifier.capability_version,
                node_key: notifier.node_key.clone(),
                src_node: self.peer.node_id,
                ssh_user: authorization.requested_user.clone(),
                local_user: authorization.local_user.clone(),
                recording_attempts,
            },
        ))
    }

    async fn notify_recording_event(
        &self,
        url: &str,
        event_type: TailscaleSshRecordingEventType,
        authorization: &TailscaleSshAuthorization,
        recording_attempts: Vec<TailscaleSshRecordingAttempt>,
    ) {
        if url.is_empty() || recording_attempts.is_empty() {
            return;
        }
        if let Some((client, notification)) = self.recording_notification(
            event_type,
            authorization,
            recording_attempts,
        ) {
            let _ = client.notify_recording_event(url, &notification).await;
        }
    }

    async fn authenticate(&mut self, user: &str) -> Auth {
        if let Some(authorization) = &self.authorization {
            return if authorization.requested_user == user {
                Auth::Accept
            } else {
                Auth::reject()
            };
        }
        let decision = self.policy.read().ok().and_then(|policy| {
            evaluate_tailscale_ssh_policy(
                policy.as_ref(),
                user,
                &self.peer,
                self.source_ip,
                OffsetDateTime::now_utc(),
            )
            .ok()
        });
        match decision {
            Some(TailscaleSshPolicyDecision::Accept(authorization)) => {
                self.authorization = Some(*authorization);
                Auth::Accept
            }
            Some(TailscaleSshPolicyDecision::HoldAndDelegate(
                authorization,
            )) => {
                let Some(delegation) = &self.delegation else {
                    return Auth::reject();
                };
                let requested_user = authorization.requested_user.clone();
                let local_user = authorization.local_user.clone();
                let context = TailscaleSshDelegateContext {
                    source_node_ip: self.source_ip,
                    source_node_id: self.peer.node_id,
                    destination_node_ip: delegation.destination_ip,
                    destination_node_id: delegation.destination_node_id,
                    requested_user: &requested_user,
                    local_user: &local_user,
                };
                match resolve_tailscale_ssh_delegation(
                    *authorization,
                    &context,
                    delegation.client.as_ref(),
                    &delegation.cancellation,
                )
                .await
                {
                    Ok(authorization) => {
                        self.authorization = Some(authorization);
                        Auth::Accept
                    }
                    Err(_) => Auth::reject(),
                }
            }
            _ => Auth::reject(),
        }
    }

    fn local_forwarding_allowed(&self) -> bool {
        !self.disable_forwarding
            && self.authorization.as_ref().is_some_and(|authorization| {
                authorization.action.allow_local_port_forwarding
            })
    }

    fn remote_forwarding_allowed(&self) -> bool {
        !self.disable_forwarding
            && self.authorization.as_ref().is_some_and(|authorization| {
                authorization.action.allow_remote_port_forwarding
            })
    }

    async fn launch_session(
        &mut self,
        channel_id: ChannelId,
        kind: TailscaleSshSessionKind,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let Some(backend) = self.session_backend.clone() else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        if matches!(kind, TailscaleSshSessionKind::Sftp)
            && (self.disable_sftp || !backend.supports_sftp())
        {
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        let Some(pending) = self.pending_sessions.remove(&channel_id) else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        if pending.pty.is_some()
            && (self.disable_pty || !backend.supports_pty())
        {
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        let Some(authorization) = self.authorization.clone() else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        let cancellation = self.session_cancellation.child_token();
        let recording_action = if authorization.action.recorders.is_empty() {
            &authorization.initial_action
        } else {
            &authorization.action
        };
        let recording_failure = recording_action.on_recording_failure.clone();
        let mut recording_attempts = Vec::new();
        let recording = if !matches!(kind, TailscaleSshSessionKind::Sftp)
            && !recording_action.recorders.is_empty()
        {
            let connected = connect_tailscale_ssh_recorder(
                self.dialer.clone(),
                &recording_action.recorders,
                self.session_cancellation.clone(),
            )
            .await;
            match connected {
                Ok((upload, mut attempts)) => {
                    let mut header = TailscaleSshCastHeader::new(
                        std::time::SystemTime::now(),
                    );
                    if let Some(pty) = &pending.pty {
                        header.width = pty.columns;
                        header.height = pty.rows;
                        header.env.insert("TERM".into(), pty.terminal.clone());
                    } else {
                        header
                            .env
                            .insert("TERM".into(), "xterm-256color".into());
                    }
                    if let TailscaleSshSessionKind::Exec(command) = &kind {
                        header.command = command.clone();
                    }
                    header.source_node = self.peer.name.clone();
                    header.source_node_id = self.peer.stable_id.clone();
                    if self.peer.tagged {
                        header.source_node_tags = self.peer.tags.clone();
                    } else {
                        header.source_node_user_id = Some(self.peer.user_id);
                        header.source_node_user = self.peer.user_login.clone();
                    }
                    header.ssh_user = authorization.requested_user.clone();
                    header.local_user = authorization.local_user.clone();
                    header.connection_id = self.connection_id.clone();
                    let fail_open =
                        recording_failure.as_ref().is_none_or(|failure| {
                            failure.terminate_session_with_message.is_empty()
                        });
                    match TailscaleSshOutputRecording::start(
                        upload, &header, fail_open,
                    )
                    .await
                    {
                        Ok(recording) => {
                            recording_attempts = attempts;
                            Some(Arc::new(recording))
                        }
                        Err(error) => {
                            if let Some(attempt) = attempts.last_mut() {
                                attempt.failure_message = error.to_string();
                            }
                            if let Some(failure) = &recording_failure {
                                let event_type = if failure
                                    .reject_session_with_message
                                    .is_empty()
                                {
                                    TailscaleSshRecordingEventType::Failed
                                } else {
                                    TailscaleSshRecordingEventType::Rejected
                                };
                                self.notify_recording_event(
                                    &failure.notify_url,
                                    event_type,
                                    &authorization,
                                    attempts,
                                )
                                .await;
                            }
                            if let Some(message) = recording_failure
                                .as_ref()
                                .map(|failure| {
                                    &failure.reject_session_with_message
                                })
                                .filter(|message| !message.is_empty())
                            {
                                session.channel_success(channel_id)?;
                                let _ = reject_tailscale_ssh_session(
                                    pending.channel,
                                    message.clone(),
                                )
                                .await;
                                return Ok(());
                            }
                            None
                        }
                    }
                }
                Err((_error, attempts)) => {
                    if let Some(failure) = &recording_failure {
                        let event_type =
                            if failure.reject_session_with_message.is_empty() {
                                TailscaleSshRecordingEventType::Failed
                            } else {
                                TailscaleSshRecordingEventType::Rejected
                            };
                        self.notify_recording_event(
                            &failure.notify_url,
                            event_type,
                            &authorization,
                            attempts,
                        )
                        .await;
                    }
                    if let Some(message) = recording_failure
                        .as_ref()
                        .map(|failure| &failure.reject_session_with_message)
                        .filter(|message| !message.is_empty())
                    {
                        session.channel_success(channel_id)?;
                        let _ = reject_tailscale_ssh_session(
                            pending.channel,
                            message.clone(),
                        )
                        .await;
                        return Ok(());
                    }
                    None
                }
            }
        } else {
            None
        };
        let agent_forwarder: Option<TailscaleSshAgentForwarder> =
            if pending.agent_forwarding {
                #[cfg(unix)]
                {
                    start_tailscale_ssh_agent_forwarder(
                        pending.session_handle.clone(),
                        &cancellation,
                        &authorization.local_user,
                    )
                    .await
                    .ok()
                }
                #[cfg(not(unix))]
                {
                    None
                }
            } else {
                None
            };
        let mut environment = pending.environment;
        if pending.pty.is_some() {
            environment.remove("TERM");
        }
        if let Some(agent_forwarder) = &agent_forwarder {
            environment.insert(
                "SSH_AUTH_SOCK".into(),
                agent_forwarder.socket_path().to_owned(),
            );
        }
        if let (Some(source), Some(destination)) =
            (self.source_address, self.destination_address)
        {
            environment.insert(
                "SSH_CLIENT".into(),
                format!(
                    "{} {} {}",
                    source.ip(),
                    source.port(),
                    destination.port()
                ),
            );
            environment.insert(
                "SSH_CONNECTION".into(),
                format!(
                    "{} {} {} {}",
                    source.ip(),
                    source.port(),
                    destination.ip(),
                    destination.port()
                ),
            );
        }
        let request = TailscaleSshSessionRequest {
            authorization: authorization.clone(),
            kind,
            environment,
            pty: pending.pty,
            agent_forwarding: agent_forwarder.is_some(),
            recording: recording.clone(),
            source_address: self.source_address,
            destination_address: self.destination_address,
        };
        if authorization.action.session_duration_nanoseconds > 0 {
            let duration = Duration::from_nanos(
                u64::try_from(
                    authorization.action.session_duration_nanoseconds,
                )
                .unwrap_or(u64::MAX),
            );
            let timeout_cancellation = cancellation.clone();
            tokio::spawn(async move {
                tokio::time::sleep(duration).await;
                timeout_cancellation.cancel();
            });
        }
        let (events, event_rx) = mpsc::channel(128);
        self.running_sessions.lock().unwrap().insert(
            channel_id,
            RunningTailscaleSshSession {
                events,
                cancellation: cancellation.clone(),
            },
        );
        session.channel_success(channel_id)?;
        let running_sessions = self.running_sessions.clone();
        let session_finished = CancellationToken::new();
        if let (Some(recording), Some(failure)) =
            (recording.as_ref(), recording_failure.as_ref())
            && (!failure.terminate_session_with_message.is_empty()
                || !failure.notify_url.is_empty())
        {
            let mut result = recording.subscribe();
            let termination = failure.terminate_session_with_message.clone();
            let notify_url = failure.notify_url.clone();
            let event_type = if termination.is_empty() {
                TailscaleSshRecordingEventType::Failed
            } else {
                TailscaleSshRecordingEventType::Terminated
            };
            let notification = self.recording_notification(
                event_type,
                &authorization,
                recording_attempts,
            );
            let session_handle = pending.session_handle.clone();
            let cancellation = cancellation.clone();
            let finished = session_finished.clone();
            tokio::spawn(async move {
                let upload_result = loop {
                    if let Some(result) = result.borrow().clone() {
                        break result;
                    }
                    let changed = tokio::select! {
                        _ = finished.cancelled() => return,
                        changed = result.changed() => changed,
                    };
                    if changed.is_err() {
                        return;
                    }
                };
                let failure_message =
                    upload_result.err().unwrap_or_else(|| {
                        "recording upload ended before the SSH session".into()
                    });
                if !notify_url.is_empty()
                    && let Some((client, mut notification)) = notification
                {
                    if let Some(attempt) =
                        notification.recording_attempts.last_mut()
                    {
                        attempt.failure_message = failure_message;
                    }
                    let _ = client
                        .notify_recording_event(&notify_url, &notification)
                        .await;
                }
                if !termination.is_empty() {
                    let _ = session_handle
                        .extended_data(
                            channel_id,
                            1,
                            Bytes::from(format!("{termination}\r\n")),
                        )
                        .await;
                    cancellation.cancel();
                }
            });
        }
        tokio::spawn(async move {
            let _ = backend
                .run_session(request, pending.channel, event_rx, cancellation)
                .await;
            session_finished.cancel();
            if let Some(recording) = recording {
                let _ = recording.close().await;
            }
            if let Some(agent_forwarder) = agent_forwarder {
                agent_forwarder.close().await;
            }
            running_sessions.lock().unwrap().remove(&channel_id);
        });
        Ok(())
    }
}

impl Drop for TailscaleSshConnectionHandler {
    fn drop(&mut self) {
        self.session_cancellation.cancel();
    }
}

impl server::Handler for TailscaleSshConnectionHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        Ok(self.authenticate(user).await)
    }

    async fn auth_password(
        &mut self,
        user: &str,
        _password: &str,
    ) -> Result<Auth, Self::Error> {
        Ok(self.authenticate(user).await)
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(self.authenticate(user).await)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(self.authenticate(user).await)
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        _certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        Ok(self.authenticate(user).await)
    }

    async fn authentication_banner(
        &mut self,
    ) -> Result<Option<String>, Self::Error> {
        Ok(self
            .authorization
            .as_ref()
            .map(|authorization| authorization.action.message.clone())
            .filter(|message| !message.is_empty()))
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if self.authorization.is_none() || self.session_backend.is_none() {
            return Ok(false);
        }
        self.pending_sessions.insert(
            channel.id(),
            PendingTailscaleSshSession {
                channel,
                environment: BTreeMap::new(),
                pty: None,
                agent_forwarding: false,
                session_handle: session.handle(),
            },
        );
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let supported = !self.disable_pty
            && self
                .session_backend
                .as_ref()
                .is_some_and(|backend| backend.supports_pty());
        let Some(pending) = self.pending_sessions.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if !supported {
            session.channel_failure(channel)?;
            return Ok(());
        }
        pending.pty = Some(TailscaleSshPtyRequest {
            terminal: term.into(),
            columns: clamp_tailscale_ssh_window_dimension(col_width),
            rows: clamp_tailscale_ssh_window_dimension(row_height),
            width_pixels: clamp_tailscale_ssh_window_dimension(pix_width),
            height_pixels: clamp_tailscale_ssh_window_dimension(pix_height),
            modes: modes.to_vec(),
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let accepted = self.authorization.as_ref().is_some_and(|value| {
            tailscale_ssh_environment_accepted(
                variable_name,
                &value.accept_environment,
                self.environment_capability,
            )
        });
        let Some(pending) = self.pending_sessions.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if accepted {
            pending
                .environment
                .insert(variable_name.into(), variable_value.into());
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.launch_session(channel, TailscaleSshSessionKind::Shell, session)
            .await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Ok(command) = std::str::from_utf8(data) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        self.launch_session(
            channel,
            TailscaleSshSessionKind::Exec(command.into()),
            session,
        )
        .await
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.launch_session(channel, TailscaleSshSessionKind::Sftp, session)
            .await
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let allowed = !self.disable_forwarding
            && self.authorization.as_ref().is_some_and(|authorization| {
                authorization.action.allow_agent_forwarding
            });
        if allowed
            && let Some(pending) = self.pending_sessions.get_mut(&channel)
        {
            pending.agent_forwarding = true;
            return Ok(true);
        }
        Ok(false)
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let running_sessions = self.running_sessions.lock().unwrap();
        let Some(running) = running_sessions.get(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        let _ = running.events.try_send(TailscaleSshSessionEvent::Resize {
            columns: clamp_tailscale_ssh_window_dimension(col_width),
            rows: clamp_tailscale_ssh_window_dimension(row_height),
            width_pixels: clamp_tailscale_ssh_window_dimension(pix_width),
            height_pixels: clamp_tailscale_ssh_window_dimension(pix_height),
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: russh::Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(running) =
            self.running_sessions.lock().unwrap().get(&channel)
        {
            let _ = running
                .events
                .try_send(TailscaleSshSessionEvent::Signal(signal));
        }
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !self.local_forwarding_allowed() || port_to_connect > u16::MAX as u32
        {
            return Ok(false);
        }
        let destination =
            SocksAddr::new(host_to_connect, port_to_connect as u16);
        let mut remote = match self.dialer.dial_tcp(&destination).await {
            Ok(remote) => remote,
            Err(_) => return Ok(false),
        };
        let mut channel = channel.into_stream();
        tokio::spawn(async move {
            let _ =
                tokio::io::copy_bidirectional(&mut channel, &mut remote).await;
        });
        Ok(true)
    }

    #[cfg(unix)]
    async fn channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !self.local_forwarding_allowed() {
            return Ok(false);
        }
        let mut remote = match UnixStream::connect(socket_path).await {
            Ok(remote) => remote,
            Err(_) => return Ok(false),
        };
        let mut channel = channel.into_stream();
        tokio::spawn(async move {
            let _ =
                tokio::io::copy_bidirectional(&mut channel, &mut remote).await;
        });
        Ok(true)
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !self.remote_forwarding_allowed() || *port > u16::MAX as u32 {
            return Ok(false);
        }
        let listener = match TcpListener::bind((address, *port as u16)).await {
            Ok(listener) => listener,
            Err(_) => return Ok(false),
        };
        let allocated_port = match listener.local_addr() {
            Ok(address) => address.port(),
            Err(_) => return Ok(false),
        };
        let key = (address.to_owned(), allocated_port);
        if self.remote_forwards.contains_key(&key) {
            return Ok(false);
        }
        *port = u32::from(allocated_port);
        let cancellation = self.session_cancellation.child_token();
        self.remote_forwards.insert(key, cancellation.clone());
        let connected_address = address.to_owned();
        let handle = session.handle();
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = cancellation.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((mut stream, originator)) = accepted else {
                    break;
                };
                let handle = handle.clone();
                let connected_address = connected_address.clone();
                tokio::spawn(async move {
                    let Ok(channel) = handle
                        .channel_open_forwarded_tcpip(
                            connected_address,
                            u32::from(allocated_port),
                            originator.ip().to_string(),
                            u32::from(originator.port()),
                        )
                        .await
                    else {
                        return;
                    };
                    let mut channel = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(
                        &mut channel,
                        &mut stream,
                    )
                    .await;
                });
            }
        });
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Ok(port) = u16::try_from(port) else {
            return Ok(false);
        };
        let Some(cancellation) =
            self.remote_forwards.remove(&(address.to_owned(), port))
        else {
            return Ok(false);
        };
        cancellation.cancel();
        Ok(true)
    }

    #[cfg(unix)]
    async fn streamlocal_forward(
        &mut self,
        socket_path: &str,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !self.remote_forwarding_allowed()
            || self.streamlocal_forwards.contains_key(socket_path)
        {
            return Ok(false);
        }
        let listener = match UnixListener::bind(socket_path) {
            Ok(listener) => listener,
            Err(_) => return Ok(false),
        };
        let identity = match tailscale_ssh_socket_identity(socket_path).await {
            Ok(identity) => identity,
            Err(_) => return Ok(false),
        };
        let cancellation = self.session_cancellation.child_token();
        self.streamlocal_forwards
            .insert(socket_path.to_owned(), cancellation.clone());
        let server_socket_path = socket_path.to_owned();
        let handle = session.handle();
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = cancellation.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((mut stream, _)) = accepted else {
                    break;
                };
                let handle = handle.clone();
                let server_socket_path = server_socket_path.clone();
                tokio::spawn(async move {
                    let Ok(channel) = handle
                        .channel_open_forwarded_streamlocal(server_socket_path)
                        .await
                    else {
                        return;
                    };
                    let mut channel = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(
                        &mut channel,
                        &mut stream,
                    )
                    .await;
                });
            }
            drop(listener);
            remove_tailscale_ssh_socket_if_owned(&server_socket_path, identity)
                .await;
        });
        Ok(true)
    }

    #[cfg(unix)]
    async fn cancel_streamlocal_forward(
        &mut self,
        socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(cancellation) = self.streamlocal_forwards.remove(socket_path)
        else {
            return Ok(false);
        };
        cancellation.cancel();
        Ok(true)
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pending_sessions.remove(&channel);
        if let Some(running) =
            self.running_sessions.lock().unwrap().remove(&channel)
        {
            running.cancellation.cancel();
        }
        Ok(())
    }
}

pub async fn serve_tailscale_ssh_connection<R>(
    config: Arc<server::Config>,
    stream: R,
    handler: TailscaleSshConnectionHandler,
) -> Result<(), russh::Error>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    server::run_stream(config, stream, handler).await?.await
}

pub fn evaluate_tailscale_ssh_policy(
    policy: Option<&TailscaleSshPolicy>,
    requested_user: &str,
    peer: &TailscaleSshPeerIdentity,
    source_ip: IpAddr,
    now: OffsetDateTime,
) -> Result<TailscaleSshPolicyDecision, TailscaleSshPolicyError> {
    let policy = policy.ok_or(TailscaleSshPolicyError::NoPolicy)?;
    for rule in &policy.rules {
        if let Some(expiry) = &rule.rule_expires {
            let expiry =
                OffsetDateTime::parse(expiry, &Rfc3339).map_err(|_| {
                    TailscaleSshPolicyError::InvalidRuleExpiry(expiry.clone())
                })?;
            if now > expiry {
                continue;
            }
        }
        if !rule
            .principals
            .iter()
            .any(|principal| ssh_principal_matches(principal, peer, source_ip))
        {
            continue;
        }
        let Some(action) = &rule.action else {
            continue;
        };
        if action.reject {
            return Ok(TailscaleSshPolicyDecision::Reject {
                message: action.message.clone(),
            });
        }
        let Some(local_user) =
            match_tailscale_ssh_user(&rule.ssh_users, requested_user)
        else {
            continue;
        };
        if !action.accept && action.hold_and_delegate.is_empty() {
            return Ok(TailscaleSshPolicyDecision::Reject {
                message: action.message.clone(),
            });
        }
        let authorization = Box::new(TailscaleSshAuthorization {
            requested_user: requested_user.into(),
            local_user,
            action: action.clone(),
            initial_action: action.clone(),
            accept_environment: rule.accept_environment.clone(),
        });
        return Ok(if action.hold_and_delegate.is_empty() {
            TailscaleSshPolicyDecision::Accept(authorization)
        } else {
            TailscaleSshPolicyDecision::HoldAndDelegate(authorization)
        });
    }
    Err(TailscaleSshPolicyError::NoMatchingRule)
}

pub fn match_tailscale_ssh_user(
    users: &BTreeMap<String, String>,
    requested_user: &str,
) -> Option<String> {
    let local_user = users.get(requested_user).or_else(|| users.get("*"))?;
    if local_user.is_empty() {
        None
    } else if local_user == "=" {
        Some(requested_user.into())
    } else {
        Some(local_user.clone())
    }
}

pub fn tailscale_ssh_environment_accepted(
    name: &str,
    accept_environment: &[String],
    environment_capability: bool,
) -> bool {
    if is_dangerous_tailscale_ssh_environment(name)
        || matches!(name, "USER" | "LOGNAME" | "HOME" | "SHELL" | "PATH")
    {
        return false;
    }
    if name == "TERM" || name == "LANG" || name.starts_with("LC_") {
        return true;
    }
    environment_capability
        && accept_environment
            .iter()
            .any(|pattern| environment_glob_matches(pattern, name))
}

pub fn is_dangerous_tailscale_ssh_environment(name: &str) -> bool {
    name.starts_with("LD_")
        || name.starts_with("DYLD_")
        || matches!(
            name,
            "IFS"
                | "ENV"
                | "BASH_ENV"
                | "SHELLOPTS"
                | "BASHOPTS"
                | "PS4"
                | "GLOBIGNORE"
        )
}

pub fn clamp_tailscale_ssh_window_dimension(value: u32) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

pub fn expand_tailscale_ssh_delegate_url(
    template: &str,
    context: &TailscaleSshDelegateContext<'_>,
) -> String {
    [
        (
            "$SRC_NODE_IP",
            query_escape(&context.source_node_ip.to_string()),
        ),
        ("$SRC_NODE_ID", context.source_node_id.to_string()),
        (
            "$DST_NODE_IP",
            query_escape(&context.destination_node_ip.to_string()),
        ),
        ("$DST_NODE_ID", context.destination_node_id.to_string()),
        ("$SSH_USER", query_escape(context.requested_user)),
        ("$LOCAL_USER", query_escape(context.local_user)),
    ]
    .into_iter()
    .fold(template.to_owned(), |url, (name, value)| {
        url.replace(name, &value)
    })
}

fn ssh_principal_matches(
    principal: &TailscaleSshPrincipal,
    peer: &TailscaleSshPeerIdentity,
    source_ip: IpAddr,
) -> bool {
    principal.any
        || (!principal.node.is_empty() && principal.node == peer.stable_id)
        || (!principal.node_ip.is_empty()
            && principal
                .node_ip
                .parse::<IpAddr>()
                .is_ok_and(|address| address == source_ip))
        || (!principal.user_login.is_empty()
            && principal.user_login == peer.user_login)
}

fn query_escape(value: &str) -> String {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("", value)
        .finish();
    encoded.strip_prefix('=').unwrap_or(&encoded).into()
}

fn environment_glob_matches(pattern: &str, name: &str) -> bool {
    let mut expression = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '*' => expression.push_str(".*"),
            '?' => expression.push('.'),
            '\\' => {
                let Some(literal) = chars.next() else {
                    return false;
                };
                expression.push_str(&regex::escape(&literal.to_string()));
            }
            '[' => {
                expression.push('[');
                if chars
                    .peek()
                    .is_some_and(|value| *value == '!' || *value == '^')
                {
                    chars.next();
                    expression.push('^');
                }
                let mut closed = false;
                for class_character in chars.by_ref() {
                    if class_character == ']' {
                        closed = true;
                        expression.push(']');
                        break;
                    }
                    if class_character == '\\' {
                        expression.push_str("\\\\");
                    } else {
                        expression.push(class_character);
                    }
                }
                if !closed {
                    return false;
                }
            }
            literal => {
                expression.push_str(&regex::escape(&literal.to_string()))
            }
        }
    }
    expression.push('$');
    regex::Regex::new(&expression)
        .is_ok_and(|expression| expression.is_match(name))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use russh::{
        client,
        keys::{Algorithm, PrivateKey},
    };
    use tokio::net::TcpStream;

    use super::*;
    use crate::{
        option::DirectOutboundOptions,
        protocol::{
            direct::DirectOutbound,
            tailscale_control_types::{
                TailscaleNode, TailscaleSshRecorderFailureAction,
                TailscaleSshRule, TailscaleUserProfile,
            },
        },
    };

    struct AcceptHostKey;

    struct RemoteForwardClient;

    #[cfg(unix)]
    struct AgentForwardClient;

    #[cfg(unix)]
    struct AgentProbeBackend;

    struct DelegateQueue {
        responses: Mutex<VecDeque<Result<TailscaleSshAction, String>>>,
    }

    struct RecordingNotifierQueue {
        events: Mutex<Vec<(String, TailscaleSshRecordingNotification)>>,
    }

    #[async_trait]
    impl TailscaleSshDelegateClient for DelegateQueue {
        async fn request_action(
            &self,
            _url: &str,
        ) -> Result<TailscaleSshAction, String> {
            self.responses.lock().unwrap().pop_front().unwrap()
        }
    }

    #[async_trait]
    impl TailscaleSshRecordingNotifier for RecordingNotifierQueue {
        async fn notify_recording_event(
            &self,
            url: &str,
            notification: &TailscaleSshRecordingNotification,
        ) -> Result<(), String> {
            self.events
                .lock()
                .unwrap()
                .push((url.to_owned(), notification.clone()));
            Ok(())
        }
    }

    impl client::Handler for AcceptHostKey {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    impl client::Handler for RemoteForwardClient {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn server_channel_open_forwarded_tcpip(
            &mut self,
            channel: Channel<client::Msg>,
            _connected_address: &str,
            _connected_port: u32,
            _originator_address: &str,
            _originator_port: u32,
            _session: &mut client::Session,
        ) -> Result<(), Self::Error> {
            tokio::spawn(async move {
                let mut stream = channel.into_stream();
                let mut request = [0_u8; 4];
                if stream.read_exact(&mut request).await.is_ok() {
                    let _ = stream.write_all(&request).await;
                }
            });
            Ok(())
        }

        async fn server_channel_open_forwarded_streamlocal(
            &mut self,
            channel: Channel<client::Msg>,
            _socket_path: &str,
            _session: &mut client::Session,
        ) -> Result<(), Self::Error> {
            tokio::spawn(async move {
                let mut stream = channel.into_stream();
                let mut request = [0_u8; 4];
                if stream.read_exact(&mut request).await.is_ok() {
                    let _ = stream.write_all(&request).await;
                }
            });
            Ok(())
        }
    }

    #[cfg(unix)]
    impl client::Handler for AgentForwardClient {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn server_channel_open_agent_forward(
            &mut self,
            channel: Channel<client::Msg>,
            _session: &mut client::Session,
        ) -> Result<(), Self::Error> {
            tokio::spawn(async move {
                let mut stream = channel.into_stream();
                let mut request = [0_u8; 4];
                if stream.read_exact(&mut request).await.is_ok() {
                    let _ = stream.write_all(&request).await;
                }
            });
            Ok(())
        }
    }

    #[cfg(unix)]
    #[async_trait]
    impl TailscaleSshSessionBackend for AgentProbeBackend {
        async fn run_session(
            &self,
            request: TailscaleSshSessionRequest,
            channel: Channel<Msg>,
            _events: mpsc::Receiver<TailscaleSshSessionEvent>,
            _cancellation: CancellationToken,
        ) -> Result<(), String> {
            if !request.agent_forwarding {
                return reject_tailscale_ssh_session(
                    channel,
                    "agent forwarding was not established".into(),
                )
                .await;
            }
            let probe = async {
                let socket_path =
                    request.environment.get("SSH_AUTH_SOCK").ok_or_else(
                        || "SSH_AUTH_SOCK was not injected".to_owned(),
                    )?;
                let mut agent = UnixStream::connect(socket_path)
                    .await
                    .map_err(|error| error.to_string())?;
                agent
                    .write_all(b"ping")
                    .await
                    .map_err(|error| error.to_string())?;
                let mut response = [0_u8; 4];
                agent
                    .read_exact(&mut response)
                    .await
                    .map_err(|error| error.to_string())?;
                Ok::<_, String>(response)
            }
            .await;
            let response = match probe {
                Ok(response) => response,
                Err(error) => {
                    return reject_tailscale_ssh_session(channel, error).await;
                }
            };
            let (_, writer) = channel.split();
            writer
                .data(std::io::Cursor::new(response))
                .await
                .map_err(|error| error.to_string())?;
            writer
                .exit_status(0)
                .await
                .map_err(|error| error.to_string())?;
            let _ = writer.eof().await;
            let _ = writer.close().await;
            Ok(())
        }
    }

    fn peer() -> TailscaleSshPeerIdentity {
        TailscaleSshPeerIdentity {
            node_id: 42,
            stable_id: "node-42".into(),
            name: "source.example.ts.net".into(),
            user_id: 7,
            tags: Vec::new(),
            addresses: vec!["100.64.0.42".parse().unwrap()],
            user_login: "alice@example.com".into(),
            tagged: false,
        }
    }

    #[tokio::test]
    async fn host_key_is_private_persistent_and_refuses_corruption() {
        let directory = tempfile::tempdir().unwrap();
        let first =
            load_or_generate_tailscale_ssh_server_identity(directory.path())
                .await
                .unwrap();
        assert_eq!(
            first.path.file_name().unwrap(),
            TAILSCALE_SSH_HOST_KEY_FILE_NAME
        );
        assert!(first.public_key.starts_with("ssh-ed25519 "));
        let second =
            load_or_generate_tailscale_ssh_server_identity(directory.path())
                .await
                .unwrap();
        assert_eq!(first.public_key, second.public_key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&first.path).unwrap().permissions().mode()
                    & 0o777,
                0o600
            );
        }
        tokio::fs::write(&first.path, b"not an ssh key")
            .await
            .unwrap();
        assert!(matches!(
            load_or_generate_tailscale_ssh_server_identity(directory.path())
                .await,
            Err(TailscaleSshHostKeyError::InvalidKey(_))
        ));
    }

    #[test]
    fn peer_identity_comes_from_current_netmap() {
        let mut netmap = TailscaleNetmapState::default();
        netmap.peers.insert(
            42,
            TailscaleNode {
                id: 42,
                stable_id: "node-42".into(),
                user: 7,
                addresses: vec!["100.64.0.42/32".into(), "fd7a::42/128".into()],
                tags: vec!["tag:server".into()],
                ..Default::default()
            },
        );
        netmap.user_profiles.insert(
            7,
            TailscaleUserProfile {
                id: 7,
                login_name: "alice@example.com".into(),
                ..Default::default()
            },
        );
        let identity = tailscale_ssh_peer_identity(
            &netmap,
            "::ffff:100.64.0.42".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(identity.node_id, 42);
        assert_eq!(identity.user_login, "alice@example.com");
        assert!(identity.tagged);
        assert!(
            tailscale_ssh_peer_identity(
                &netmap,
                "100.64.0.99".parse().unwrap()
            )
            .is_none()
        );
    }

    #[test]
    fn policy_matches_principal_and_exact_then_wildcard_user() {
        let policy = TailscaleSshPolicy {
            rules: vec![TailscaleSshRule {
                principals: vec![TailscaleSshPrincipal {
                    user_login: "alice@example.com".into(),
                    ..Default::default()
                }],
                ssh_users: [
                    ("root".into(), "operator".into()),
                    ("*".into(), "=".into()),
                ]
                .into(),
                action: Some(TailscaleSshAction {
                    accept: true,
                    ..Default::default()
                }),
                accept_environment: vec!["GIT_*".into()],
                ..Default::default()
            }],
        };
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let TailscaleSshPolicyDecision::Accept(root) =
            evaluate_tailscale_ssh_policy(
                Some(&policy),
                "root",
                &peer(),
                "100.64.0.42".parse().unwrap(),
                now,
            )
            .unwrap()
        else {
            panic!("expected accept");
        };
        assert_eq!(root.local_user, "operator");
        let TailscaleSshPolicyDecision::Accept(git) =
            evaluate_tailscale_ssh_policy(
                Some(&policy),
                "git",
                &peer(),
                "100.64.0.42".parse().unwrap(),
                now,
            )
            .unwrap()
        else {
            panic!("expected accept");
        };
        assert_eq!(git.local_user, "git");
    }

    #[test]
    fn policy_skips_expired_rules_and_preserves_reject_message() {
        let policy = TailscaleSshPolicy {
            rules: vec![
                TailscaleSshRule {
                    rule_expires: Some("2020-01-01T00:00:00Z".into()),
                    principals: vec![TailscaleSshPrincipal {
                        any: true,
                        ..Default::default()
                    }],
                    ssh_users: [("*".into(), "=".into())].into(),
                    action: Some(TailscaleSshAction {
                        accept: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                TailscaleSshRule {
                    principals: vec![TailscaleSshPrincipal {
                        node: "node-42".into(),
                        ..Default::default()
                    }],
                    action: Some(TailscaleSshAction {
                        reject: true,
                        message: "maintenance".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
        };
        assert_eq!(
            evaluate_tailscale_ssh_policy(
                Some(&policy),
                "root",
                &peer(),
                "100.64.0.42".parse().unwrap(),
                OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            )
            .unwrap(),
            TailscaleSshPolicyDecision::Reject {
                message: "maintenance".into()
            }
        );
    }

    #[test]
    fn hold_and_delegate_is_not_a_final_accept() {
        let policy = TailscaleSshPolicy {
            rules: vec![TailscaleSshRule {
                principals: vec![TailscaleSshPrincipal {
                    any: true,
                    ..Default::default()
                }],
                ssh_users: [("root".into(), "operator".into())].into(),
                action: Some(TailscaleSshAction {
                    hold_and_delegate: "https://control/authorize".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        let decision = evaluate_tailscale_ssh_policy(
            Some(&policy),
            "root",
            &peer(),
            "100.64.0.42".parse().unwrap(),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        assert!(matches!(
            decision,
            TailscaleSshPolicyDecision::HoldAndDelegate(_)
        ));
    }

    #[tokio::test]
    async fn delegation_retries_and_resolves_multiple_hops() {
        let initial_action = TailscaleSshAction {
            hold_and_delegate:
                "https://control/first?user=$SSH_USER&local=$LOCAL_USER".into(),
            recorders: vec!["recorder-a".into()],
            ..Default::default()
        };
        let authorization = TailscaleSshAuthorization {
            requested_user: "user name".into(),
            local_user: "operator".into(),
            action: initial_action.clone(),
            initial_action,
            accept_environment: vec![],
        };
        let client = DelegateQueue {
            responses: Mutex::new(VecDeque::from([
                Err("temporary".into()),
                Ok(TailscaleSshAction {
                    hold_and_delegate: "https://control/second".into(),
                    ..Default::default()
                }),
                Ok(TailscaleSshAction {
                    accept: true,
                    allow_local_port_forwarding: true,
                    ..Default::default()
                }),
            ])),
        };
        let context = TailscaleSshDelegateContext {
            source_node_ip: "100.64.0.42".parse().unwrap(),
            source_node_id: 42,
            destination_node_ip: "100.64.0.1".parse().unwrap(),
            destination_node_id: 1,
            requested_user: "user name",
            local_user: "operator",
        };
        let resolved = resolve_tailscale_ssh_delegation_with_limits(
            authorization,
            &context,
            &client,
            &CancellationToken::new(),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .await
        .unwrap();
        assert!(resolved.action.accept);
        assert!(resolved.action.allow_local_port_forwarding);
        assert_eq!(resolved.initial_action.recorders, ["recorder-a"]);
    }

    #[tokio::test]
    async fn delegation_cancel_is_fail_closed() {
        struct Never;
        #[async_trait]
        impl TailscaleSshDelegateClient for Never {
            async fn request_action(
                &self,
                _url: &str,
            ) -> Result<TailscaleSshAction, String> {
                std::future::pending().await
            }
        }
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let authorization = TailscaleSshAuthorization {
            requested_user: "root".into(),
            local_user: "root".into(),
            action: TailscaleSshAction {
                hold_and_delegate: "https://control/authorize".into(),
                ..Default::default()
            },
            initial_action: TailscaleSshAction::default(),
            accept_environment: vec![],
        };
        let context = TailscaleSshDelegateContext {
            source_node_ip: "100.64.0.42".parse().unwrap(),
            source_node_id: 42,
            destination_node_ip: "100.64.0.1".parse().unwrap(),
            destination_node_id: 1,
            requested_user: "root",
            local_user: "root",
        };
        assert_eq!(
            resolve_tailscale_ssh_delegation(
                authorization,
                &context,
                &Never,
                &cancellation,
            )
            .await
            .unwrap_err(),
            TailscaleSshDelegationError::Cancelled
        );
    }

    #[test]
    fn delegate_control_url_is_authority_bound_and_preserves_query() {
        assert_eq!(
            tailscale_ssh_delegate_control_path(
                "https://control.example.test/ssh/action?user=a%2Bb&node=42",
                "control.example.test",
            )
            .unwrap(),
            "/ssh/action?user=a%2Bb&node=42"
        );
        assert!(
            tailscale_ssh_delegate_control_path(
                "https://attacker.example/ssh/action",
                "control.example.test",
            )
            .is_err()
        );
        assert!(
            tailscale_ssh_delegate_control_path(
                "https://control.example.test:8443/ssh/action",
                "control.example.test",
            )
            .is_err()
        );
        assert!(
            tailscale_ssh_delegate_control_path(
                "file:///tmp/action",
                "control.example.test",
            )
            .is_err()
        );
    }

    #[test]
    fn notification_url_uses_policy_path_but_ignores_policy_host() {
        assert_eq!(
            tailscale_ssh_notification_control_path(
                "https://ignored.example/ssh/recording?connection=42",
            )
            .unwrap(),
            "/ssh/recording?connection=42"
        );
        assert!(
            tailscale_ssh_notification_control_path("file:///tmp/notify")
                .is_err()
        );
    }

    #[test]
    fn environment_gate_never_forwards_loader_or_identity_variables() {
        let patterns = vec!["*".into(), "GIT_[A-Z]*".into()];
        assert!(tailscale_ssh_environment_accepted("LANG", &patterns, false));
        assert!(tailscale_ssh_environment_accepted(
            "GIT_AUTHOR",
            &patterns,
            true
        ));
        for rejected in [
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "HOME",
            "PATH",
            "BASH_ENV",
        ] {
            assert!(!tailscale_ssh_environment_accepted(
                rejected, &patterns, true
            ));
        }
        assert!(!tailscale_ssh_environment_accepted(
            "GIT_AUTHOR",
            &patterns,
            false
        ));
    }

    #[test]
    fn delegate_url_query_escapes_client_controlled_values() {
        let context = TailscaleSshDelegateContext {
            source_node_ip: "100.64.0.42".parse().unwrap(),
            source_node_id: 42,
            destination_node_ip: "100.64.0.1".parse().unwrap(),
            destination_node_id: 1,
            requested_user: "user name&admin=true",
            local_user: "local+name",
        };
        assert_eq!(
            expand_tailscale_ssh_delegate_url(
                "https://control/ssh?src=$SRC_NODE_IP&id=$SRC_NODE_ID&dst=$DST_NODE_IP&did=$DST_NODE_ID&ssh=$SSH_USER&local=$LOCAL_USER",
                &context,
            ),
            "https://control/ssh?src=100.64.0.42&id=42&dst=100.64.0.1&did=1&ssh=user+name%26admin%3Dtrue&local=local%2Bname"
        );
    }

    #[tokio::test]
    async fn russh_transport_authenticates_from_tailnet_policy_not_credentials()
    {
        let policy = Arc::new(RwLock::new(Some(TailscaleSshPolicy {
            rules: vec![TailscaleSshRule {
                principals: vec![TailscaleSshPrincipal {
                    any: true,
                    ..Default::default()
                }],
                ssh_users: [("root".into(), "operator".into())].into(),
                action: Some(TailscaleSshAction {
                    accept: true,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        })));
        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let config = Arc::new(server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_policy = policy.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, source) = listener.accept().await.unwrap();
                let handler = TailscaleSshConnectionHandler::new(
                    server_policy.clone(),
                    peer(),
                    source.ip(),
                    Arc::new(DirectOutbound::new(
                        DirectOutboundOptions::default(),
                    )),
                    false,
                );
                let config = config.clone();
                tokio::spawn(async move {
                    let _ =
                        serve_tailscale_ssh_connection(config, stream, handler)
                            .await;
                });
            }
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut accepted = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            AcceptHostKey,
        )
        .await
        .unwrap();
        assert!(
            accepted
                .authenticate_password("root", "ignored password")
                .await
                .unwrap()
                .success()
        );
        drop(accepted);

        let stream = TcpStream::connect(address).await.unwrap();
        let mut rejected = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            AcceptHostKey,
        )
        .await
        .unwrap();
        assert!(
            !rejected
                .authenticate_none("nobody")
                .await
                .unwrap()
                .success()
        );
        drop(rejected);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn authorized_local_forward_uses_the_library_dialer() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let policy = Arc::new(RwLock::new(Some(TailscaleSshPolicy {
            rules: vec![TailscaleSshRule {
                principals: vec![TailscaleSshPrincipal {
                    any: true,
                    ..Default::default()
                }],
                ssh_users: [("root".into(), "operator".into())].into(),
                action: Some(TailscaleSshAction {
                    accept: true,
                    allow_local_port_forwarding: true,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        })));
        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let config = Arc::new(server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, source) = listener.accept().await.unwrap();
            let handler = TailscaleSshConnectionHandler::new(
                policy,
                peer(),
                source.ip(),
                Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
                false,
            );
            let _ =
                serve_tailscale_ssh_connection(config, stream, handler).await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            AcceptHostKey,
        )
        .await
        .unwrap();
        assert!(client.authenticate_none("root").await.unwrap().success());
        let channel = client
            .channel_open_direct_tcpip(
                target_address.ip().to_string(),
                u32::from(target_address.port()),
                "100.64.0.42",
                12345,
            )
            .await
            .unwrap();
        let mut forwarded = channel.into_stream();
        forwarded.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        forwarded.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        drop(forwarded);
        drop(client);
        echo.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn authorized_remote_forward_opens_and_cancels_listener() {
        let policy = Arc::new(RwLock::new(Some(TailscaleSshPolicy {
            rules: vec![TailscaleSshRule {
                principals: vec![TailscaleSshPrincipal {
                    any: true,
                    ..Default::default()
                }],
                ssh_users: [("root".into(), "root".into())].into(),
                action: Some(TailscaleSshAction {
                    accept: true,
                    allow_remote_port_forwarding: true,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        })));
        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let config = Arc::new(server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, source) = listener.accept().await.unwrap();
            let handler = TailscaleSshConnectionHandler::new(
                policy,
                peer(),
                source.ip(),
                Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
                false,
            );
            let _ =
                serve_tailscale_ssh_connection(config, stream, handler).await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            RemoteForwardClient,
        )
        .await
        .unwrap();
        assert!(client.authenticate_none("root").await.unwrap().success());
        let port = client.tcpip_forward("127.0.0.1", 0).await.unwrap();
        assert_ne!(port, 0);
        let mut forwarded = TcpStream::connect(("127.0.0.1", port as u16))
            .await
            .unwrap();
        forwarded.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        tokio::time::timeout(
            Duration::from_secs(5),
            forwarded.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response, b"ping");
        client
            .cancel_tcpip_forward("127.0.0.1", port)
            .await
            .unwrap();
        drop(forwarded);
        drop(client);
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn authorized_streamlocal_forwarding_works_in_both_directions() {
        let directory = tempfile::tempdir().unwrap();
        let direct_path = directory.path().join("direct.sock");
        let remote_path = directory.path().join("remote.sock");
        let direct_listener = UnixListener::bind(&direct_path).unwrap();
        let direct_echo = tokio::spawn(async move {
            let (mut stream, _) = direct_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&request).await.unwrap();
        });
        let policy = Arc::new(RwLock::new(Some(TailscaleSshPolicy {
            rules: vec![TailscaleSshRule {
                principals: vec![TailscaleSshPrincipal {
                    any: true,
                    ..Default::default()
                }],
                ssh_users: [("root".into(), "root".into())].into(),
                action: Some(TailscaleSshAction {
                    accept: true,
                    allow_local_port_forwarding: true,
                    allow_remote_port_forwarding: true,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        })));
        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let config = Arc::new(server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, source) = listener.accept().await.unwrap();
            let handler = TailscaleSshConnectionHandler::new(
                policy,
                peer(),
                source.ip(),
                Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
                false,
            );
            let _ =
                serve_tailscale_ssh_connection(config, stream, handler).await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            RemoteForwardClient,
        )
        .await
        .unwrap();
        assert!(client.authenticate_none("root").await.unwrap().success());

        let channel = client
            .channel_open_direct_streamlocal(
                direct_path.to_string_lossy().into_owned(),
            )
            .await
            .unwrap();
        let mut direct = channel.into_stream();
        direct.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        direct.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        drop(direct);
        direct_echo.await.unwrap();

        let remote_path = remote_path.to_string_lossy().into_owned();
        client
            .streamlocal_forward(remote_path.clone())
            .await
            .unwrap();
        let mut remote = UnixStream::connect(&remote_path).await.unwrap();
        remote.write_all(b"pong").await.unwrap();
        remote.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        client
            .cancel_streamlocal_forward(remote_path.clone())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while tokio::fs::symlink_metadata(&remote_path).await.is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled streamlocal socket was not removed");
        drop(remote);
        drop(client);
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn authorized_agent_forwarding_injects_socket_and_opens_channel() {
        let local_user = current_user_identity().unwrap().name;
        let policy = Arc::new(RwLock::new(Some(TailscaleSshPolicy {
            rules: vec![TailscaleSshRule {
                principals: vec![TailscaleSshPrincipal {
                    any: true,
                    ..Default::default()
                }],
                ssh_users: [("root".into(), local_user)].into(),
                action: Some(TailscaleSshAction {
                    accept: true,
                    allow_agent_forwarding: true,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        })));
        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let config = Arc::new(server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, source) = listener.accept().await.unwrap();
            let handler = TailscaleSshConnectionHandler::new(
                policy,
                peer(),
                source.ip(),
                Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
                false,
            )
            .with_connection_addresses(source, address)
            .with_session_backend(
                Arc::new(AgentProbeBackend),
                false,
                false,
                false,
            );
            let _ =
                serve_tailscale_ssh_connection(config, stream, handler).await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            AgentForwardClient,
        )
        .await
        .unwrap();
        assert!(client.authenticate_none("root").await.unwrap().success());
        let (output, errors, exit_status) =
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut channel = client.channel_open_session().await.unwrap();
                channel.agent_forward(true).await.unwrap();
                channel.exec(true, "probe-agent").await.unwrap();
                let mut output = Vec::new();
                let mut errors = Vec::new();
                let mut exit_status = None;
                while let Some(message) = channel.wait().await {
                    match message {
                        russh::ChannelMsg::Data { data } => {
                            output.extend_from_slice(&data);
                        }
                        russh::ChannelMsg::ExtendedData { data, .. } => {
                            errors.extend_from_slice(&data);
                        }
                        russh::ChannelMsg::ExitStatus {
                            exit_status: status,
                        } => exit_status = Some(status),
                        russh::ChannelMsg::Close => break,
                        _ => {}
                    }
                }
                (output, errors, exit_status)
            })
            .await
            .expect("SSH agent forwarding session timed out");
        assert_eq!(
            output,
            b"ping",
            "agent probe error: {}",
            String::from_utf8_lossy(&errors)
        );
        assert_eq!(exit_status, Some(0));
        drop(client);
        server.abort();
    }

    #[tokio::test]
    async fn current_user_backend_executes_and_returns_output_and_status() {
        let local_user = current_user_identity().unwrap().name;
        let policy = Arc::new(RwLock::new(Some(TailscaleSshPolicy {
            rules: vec![TailscaleSshRule {
                principals: vec![TailscaleSshPrincipal {
                    any: true,
                    ..Default::default()
                }],
                ssh_users: [("remote".into(), local_user)].into(),
                action: Some(TailscaleSshAction {
                    accept: true,
                    ..Default::default()
                }),
                accept_environment: vec!["TEST_*".into()],
                ..Default::default()
            }],
        })));
        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let config = Arc::new(server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, source) = listener.accept().await.unwrap();
            let handler = TailscaleSshConnectionHandler::new(
                policy,
                peer(),
                source.ip(),
                Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
                false,
            )
            .with_connection_addresses(source, address)
            .with_session_backend(
                Arc::new(TailscaleSshCurrentUserProcessBackend),
                true,
                false,
                true,
            );
            let _ =
                serve_tailscale_ssh_connection(config, stream, handler).await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let client_source = stream.local_addr().unwrap();
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            AcceptHostKey,
        )
        .await
        .unwrap();
        assert!(client.authenticate_none("remote").await.unwrap().success());
        let (output, exit_status) =
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut channel = client.channel_open_session().await.unwrap();
                channel
                    .set_env(true, "TEST_VALUE", "session-output")
                    .await
                    .unwrap();
                channel
                    .exec(
                        true,
                        "printf '%s|%s|%s' \"$TEST_VALUE\" \"$SSH_CLIENT\" \"$SSH_CONNECTION\"",
                    )
                    .await
                    .unwrap();
                let mut output = Vec::new();
                let mut exit_status = None;
                while let Some(message) = channel.wait().await {
                    match message {
                        russh::ChannelMsg::Data { data } => {
                            output.extend_from_slice(&data);
                        }
                        russh::ChannelMsg::ExitStatus {
                            exit_status: status,
                        } => {
                            exit_status = Some(status);
                        }
                        russh::ChannelMsg::Close => break,
                        _ => {}
                    }
                }
                (output, exit_status)
            })
            .await
            .expect("SSH exec session timed out");
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!(
                "session-output|{} {} {}|{} {} {} {}",
                client_source.ip(),
                client_source.port(),
                address.port(),
                client_source.ip(),
                client_source.port(),
                address.ip(),
                address.port()
            )
        );
        assert_eq!(exit_status, Some(0));
        if tailscale_ssh_sftp_server_path().is_some() {
            let channel = client.channel_open_session().await.unwrap();
            channel.request_subsystem(true, "sftp").await.unwrap();
            let mut stream = channel.into_stream();
            stream
                .write_all(&[0, 0, 0, 5, 1, 0, 0, 0, 3])
                .await
                .unwrap();
            let mut version = [0_u8; 9];
            tokio::time::timeout(
                Duration::from_secs(5),
                stream.read_exact(&mut version),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(u32::from_be_bytes(version[..4].try_into().unwrap()) >= 5);
            assert_eq!(version[4], 2);
            assert!(u32::from_be_bytes(version[5..].try_into().unwrap()) >= 3);
        }
        drop(client);
        server.abort();
    }

    #[tokio::test]
    async fn current_user_backend_records_output_but_never_input() {
        let recorder_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let recorder_address = recorder_listener.local_addr().unwrap();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let recorder_output = recorded.clone();
        let recorder = tokio::spawn(async move {
            // The v2 h2c probe uses a dedicated connection. Closing it makes
            // the client exercise the legacy /record + 100-continue path.
            let (probe, _) = recorder_listener.accept().await.unwrap();
            drop(probe);
            let (mut stream, _) = recorder_listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
                assert!(request.len() < 64 << 10);
            }
            assert!(request.starts_with(b"POST /record HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .unwrap();
            loop {
                let mut length = Vec::new();
                while !length.ends_with(b"\r\n") {
                    length.push(stream.read_u8().await.unwrap());
                }
                let length = usize::from_str_radix(
                    std::str::from_utf8(&length[..length.len() - 2]).unwrap(),
                    16,
                )
                .unwrap();
                if length == 0 {
                    let mut ending = [0_u8; 2];
                    stream.read_exact(&mut ending).await.unwrap();
                    break;
                }
                let mut data = vec![0; length];
                stream.read_exact(&mut data).await.unwrap();
                let mut ending = [0_u8; 2];
                stream.read_exact(&mut ending).await.unwrap();
                recorder_output.lock().unwrap().extend(data);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let local_user = current_user_identity().unwrap().name;
        let policy = Arc::new(RwLock::new(Some(TailscaleSshPolicy {
            rules: vec![TailscaleSshRule {
                principals: vec![TailscaleSshPrincipal {
                    any: true,
                    ..Default::default()
                }],
                ssh_users: [("remote".into(), local_user)].into(),
                action: Some(TailscaleSshAction {
                    accept: true,
                    recorders: vec![recorder_address.to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            }],
        })));
        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let config = Arc::new(server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, source) = listener.accept().await.unwrap();
            let handler = TailscaleSshConnectionHandler::new(
                policy,
                peer(),
                source.ip(),
                Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
                false,
            )
            .with_session_backend(
                Arc::new(TailscaleSshCurrentUserProcessBackend),
                true,
                false,
                false,
            );
            let _ =
                serve_tailscale_ssh_connection(config, stream, handler).await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            AcceptHostKey,
        )
        .await
        .unwrap();
        assert!(client.authenticate_none("remote").await.unwrap().success());
        let mut channel = client.channel_open_session().await.unwrap();
        channel
            .exec(true, "read secret; printf visible-output")
            .await
            .unwrap();
        channel
            .data(std::io::Cursor::new(b"hidden-input\n"))
            .await
            .unwrap();
        channel.eof().await.unwrap();
        let mut output = Vec::new();
        while let Some(message) = channel.wait().await {
            match message {
                russh::ChannelMsg::Data { data } => {
                    output.extend_from_slice(&data)
                }
                russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(output, b"visible-output");
        tokio::time::timeout(Duration::from_secs(5), recorder)
            .await
            .unwrap()
            .unwrap();
        let recording = recorded.lock().unwrap().clone();
        let recording = String::from_utf8(recording).unwrap();
        let mut lines = recording.lines();
        let header: serde_json::Value =
            serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(header["version"], 2);
        assert_eq!(header["command"], "read secret; printf visible-output");
        assert_eq!(header["srcNode"], "source.example.ts.net");
        assert_eq!(header["srcNodeID"], "node-42");
        assert_eq!(header["sshUser"], "remote");
        assert!(
            header["connectionID"]
                .as_str()
                .unwrap()
                .starts_with("ssh-conn-")
        );
        let output = lines
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()
            })
            .map(|line| line[2].as_str().unwrap().to_owned())
            .collect::<String>();
        assert_eq!(output, "visible-output");
        assert!(!recording.contains("hidden-input"));
        drop(client);
        server.abort();
    }

    #[tokio::test]
    async fn unavailable_recorder_rejects_and_notifies_control() {
        let local_user = current_user_identity().unwrap().name;
        let policy = Arc::new(RwLock::new(Some(TailscaleSshPolicy {
            rules: vec![TailscaleSshRule {
                principals: vec![TailscaleSshPrincipal {
                    any: true,
                    ..Default::default()
                }],
                ssh_users: [("remote".into(), local_user)].into(),
                action: Some(TailscaleSshAction {
                    accept: true,
                    recorders: vec!["not-a-recorder".into()],
                    on_recording_failure: Some(
                        TailscaleSshRecorderFailureAction {
                            reject_session_with_message: "recording required"
                                .into(),
                            notify_url: "https://ignored.example/ssh/notify"
                                .into(),
                            ..Default::default()
                        },
                    ),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        })));
        let notifications = Arc::new(RecordingNotifierQueue {
            events: Mutex::new(Vec::new()),
        });
        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let config = Arc::new(server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_notifications = notifications.clone();
        let server = tokio::spawn(async move {
            let (stream, source) = listener.accept().await.unwrap();
            let handler = TailscaleSshConnectionHandler::new(
                policy,
                peer(),
                source.ip(),
                Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
                false,
            )
            .with_session_backend(
                Arc::new(TailscaleSshCurrentUserProcessBackend),
                true,
                false,
                false,
            )
            .with_recording_notifier(
                server_notifications,
                "nodekey:test",
                142,
            );
            let _ =
                serve_tailscale_ssh_connection(config, stream, handler).await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            AcceptHostKey,
        )
        .await
        .unwrap();
        assert!(client.authenticate_none("remote").await.unwrap().success());
        let mut channel = client.channel_open_session().await.unwrap();
        channel.exec(true, "printf must-not-run").await.unwrap();
        let mut errors = Vec::new();
        let mut exit_status = None;
        while let Some(message) = channel.wait().await {
            match message {
                russh::ChannelMsg::ExtendedData { data, .. } => {
                    errors.extend_from_slice(&data)
                }
                russh::ChannelMsg::ExitStatus {
                    exit_status: status,
                } => exit_status = Some(status),
                russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(errors, b"recording required\r\n");
        assert_eq!(exit_status, Some(1));
        let events = notifications.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "https://ignored.example/ssh/notify");
        let notification = &events[0].1;
        assert_eq!(
            notification.event_type,
            TailscaleSshRecordingEventType::Rejected
        );
        assert_eq!(notification.node_key, "nodekey:test");
        assert_eq!(notification.cap_version, 142);
        assert_eq!(notification.src_node, 42);
        assert_eq!(notification.recording_attempts.len(), 1);
        assert!(
            !notification.recording_attempts[0]
                .failure_message
                .is_empty()
        );
        drop(events);
        drop(client);
        server.abort();
    }

    #[cfg(unix)]
    #[test]
    fn local_user_lookup_matches_current_process_identity() {
        let current = current_user_identity().unwrap();
        let resolved = local_user_identity(&current.name).unwrap();
        assert_eq!(resolved.name, current.name);
        assert_eq!(resolved.uid, current.uid);
        assert_eq!(resolved.gid, current.gid);
        assert_eq!(resolved.home, current.home);
        assert_eq!(resolved.shell, current.shell);
        if !resolved.groups.is_empty() {
            assert!(resolved.groups.contains(&resolved.gid));
        }
        validate_tailscale_ssh_user_switch(&resolved).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unprivileged_user_switch_is_rejected_before_spawn() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let root = local_user_identity("root").unwrap();
        if root.uid != unsafe { libc::geteuid() }
            || root.gid != unsafe { libc::getegid() }
        {
            let error = validate_tailscale_ssh_user_switch(&root).unwrap_err();
            assert!(error.contains("without root privileges"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn terminal_modes_update_termios_control_flags_and_speeds() {
        let pair = native_pty_system().openpty(PtySize::default()).unwrap();
        apply_tailscale_ssh_terminal_modes(
            pair.master.as_ref(),
            &[
                (russh::Pty::ECHO, 0),
                (russh::Pty::VINTR, 7),
                (russh::Pty::VEOL2, 21),
                (russh::Pty::IXANY, 1),
                (russh::Pty::ECHOCTL, 0),
                (russh::Pty::TTY_OP_ISPEED, 115_200),
                (russh::Pty::TTY_OP_OSPEED, 115_200),
            ],
        )
        .unwrap();
        let fd = pair.master.as_raw_fd().unwrap();
        let attributes = unsafe {
            let mut attributes = std::mem::zeroed::<libc::termios>();
            assert_eq!(libc::tcgetattr(fd, &mut attributes), 0);
            attributes
        };
        assert_eq!(attributes.c_lflag & libc::ECHO, 0);
        assert_eq!(attributes.c_lflag & libc::ECHOCTL, 0);
        assert_ne!(attributes.c_iflag & libc::IXANY, 0);
        assert_eq!(attributes.c_cc[libc::VINTR], 7);
        assert_eq!(attributes.c_cc[libc::VEOL2], 21);
        assert_eq!(unsafe { libc::cfgetispeed(&attributes) }, libc::B115200);
        assert_eq!(unsafe { libc::cfgetospeed(&attributes) }, libc::B115200);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn current_user_backend_runs_pty_and_applies_resize() {
        let local_user = current_user_identity().unwrap().name;
        let policy = Arc::new(RwLock::new(Some(TailscaleSshPolicy {
            rules: vec![TailscaleSshRule {
                principals: vec![TailscaleSshPrincipal {
                    any: true,
                    ..Default::default()
                }],
                ssh_users: [("remote".into(), local_user)].into(),
                action: Some(TailscaleSshAction {
                    accept: true,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        })));
        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let config = Arc::new(server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, source) = listener.accept().await.unwrap();
            let handler = TailscaleSshConnectionHandler::new(
                policy,
                peer(),
                source.ip(),
                Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
                false,
            )
            .with_session_backend(
                Arc::new(TailscaleSshCurrentUserProcessBackend),
                false,
                false,
                false,
            );
            let _ =
                serve_tailscale_ssh_connection(config, stream, handler).await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            AcceptHostKey,
        )
        .await
        .unwrap();
        assert!(client.authenticate_none("remote").await.unwrap().success());
        let (output, exit_status) =
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut channel = client.channel_open_session().await.unwrap();
                channel
                    .request_pty(
                        true,
                        "xterm-256color",
                        80,
                        24,
                        0,
                        0,
                        &[
                            (russh::Pty::ECHO, 0),
                            (russh::Pty::VINTR, 3),
                            (russh::Pty::TTY_OP_ISPEED, 115_200),
                        ],
                    )
                    .await
                    .unwrap();
                channel
                    .set_env(true, "TERM", "client-must-not-override-pty")
                    .await
                    .unwrap();
                channel
                    .exec(
                        true,
                        "sleep 0.2; stty size; if stty -a | grep -q -- '-echo'; then printf '|noecho|'; else exit 7; fi; printf '|%s|' \"$TERM\"",
                    )
                    .await
                    .unwrap();
                channel.window_change(100, 40, 0, 0).await.unwrap();
                let mut output = Vec::new();
                let mut exit_status = None;
                while let Some(message) = channel.wait().await {
                    match message {
                        russh::ChannelMsg::Data { data } => {
                            output.extend_from_slice(&data);
                        }
                        russh::ChannelMsg::ExitStatus {
                            exit_status: status,
                        } => {
                            exit_status = Some(status);
                        }
                        russh::ChannelMsg::Close => break,
                        _ => {}
                    }
                }
                (output, exit_status)
            })
            .await
            .expect("SSH PTY session timed out");
        let output = String::from_utf8_lossy(&output);
        assert!(
            output.contains("40 100"),
            "unexpected PTY output: {output:?}"
        );
        assert!(
            output.contains("|xterm-256color|"),
            "unexpected PTY output: {output:?}"
        );
        assert!(
            output.contains("|noecho|"),
            "unexpected PTY output: {output:?}"
        );
        assert_eq!(exit_status, Some(0));
        drop(client);
        server.abort();
    }
}
