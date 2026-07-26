//! Programmatic proxy lifecycle for the persistent runtime.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use super::log_buf::{LogBuffer, SingboxLogWriter, pipe_singbox_to_buffer};
use crate::{
    api,
    bootstrap::singbox as bootstrap,
    settings::{Settings, StackFlags},
    singbox::{self, assets, rules},
    stack::{
        StackCli, easytier, ensure_mesh_config_from_stack,
        ensure_stack_config_exists, log_mesh_effective_config, spawn_singbox,
        validate_mesh_cli,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StackRunState {
    Stopped,
    Starting,
    Running,
    Failed,
    Stopping,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackStatus {
    pub state: StackRunState,
    pub pid: Option<u32>,
    pub mixed_port: Option<u16>,
    pub tun_enabled: bool,
    pub mesh_enabled: bool,
    pub gateway: bool,
    pub error: Option<String>,
}

impl Default for StackStatus {
    fn default() -> Self {
        Self {
            state: StackRunState::Stopped,
            pid: None,
            mixed_port: None,
            tun_enabled: false,
            mesh_enabled: false,
            gateway: false,
            error: None,
        }
    }
}

pub struct StackController {
    status: Arc<Mutex<StackStatus>>,
    pid: Arc<AtomicU32>,
    running: Arc<AtomicBool>,
    join: Mutex<Option<JoinHandle<()>>>,
    logs: LogBuffer,
}

impl StackController {
    pub fn new(logs: LogBuffer) -> Self {
        Self {
            status: Arc::new(Mutex::new(StackStatus::default())),
            pid: Arc::new(AtomicU32::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            join: Mutex::new(None),
            logs,
        }
    }

    pub fn status(&self) -> StackStatus {
        self.status.lock().expect("stack status").clone()
    }

    pub fn logs(&self) -> &LogBuffer {
        &self.logs
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Start a stack from an already-resolved persistent configuration.
    pub fn start_cli(
        &self,
        cli: StackCli,
        sudo_password: Option<String>,
    ) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            bail!("stack is already running");
        }
        {
            let mut st = self.status.lock().expect("stack status");
            *st = StackStatus {
                state: StackRunState::Starting,
                ..Default::default()
            };
        }
        self.running.store(true, Ordering::SeqCst);

        let status = self.status.clone();
        let pid_atom = self.pid.clone();
        let running = self.running.clone();
        let logs = self.logs.clone();
        let failure_logs = logs.clone();

        let handle = thread::spawn(move || {
            let result = run_stack_managed(
                cli,
                logs,
                pid_atom.clone(),
                status.clone(),
                sudo_password,
            );
            running.store(false, Ordering::SeqCst);
            pid_atom.store(0, Ordering::SeqCst);
            let mut st = status.lock().expect("stack status");
            match result {
                Ok(()) => {
                    st.state = StackRunState::Stopped;
                    st.pid = None;
                }
                Err(e) => {
                    let error = format!("{e:#}");
                    crate::logging::emit_error("proxy", "failed", &error);
                    failure_logs.push(format!("proxy stack failed: {error}"));
                    st.state = StackRunState::Failed;
                    st.error = Some(error);
                    st.pid = None;
                }
            }
        });
        *self.join.lock().expect("stack join") = Some(handle);
        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        {
            let mut st = self.status.lock().expect("stack status");
            st.state = StackRunState::Stopping;
        }
        let pid = self.pid.load(Ordering::SeqCst);
        if pid != 0 {
            assets::terminate_process(pid);
        }
        let _ = easytier::stop_all();
        if let Some(handle) = self.join.lock().expect("stack join").take() {
            let _ = handle.join();
        }
        self.running.store(false, Ordering::SeqCst);
        self.pid.store(0, Ordering::SeqCst);
        let mut st = self.status.lock().expect("stack status");
        st.state = StackRunState::Stopped;
        st.pid = None;
        Ok(())
    }
}

fn run_stack_managed(
    cli: StackCli,
    logs: LogBuffer,
    pid_atom: Arc<AtomicU32>,
    status: Arc<Mutex<StackStatus>>,
    sudo_password: Option<String>,
) -> Result<()> {
    let flags = StackFlags {
        mesh: cli.mesh.map(crate::stack::MeshCliMode::into),
        gateway: cli.gateway,
        tun: !cli.common.no_tun,
        no_rules: false,
    };
    ensure_stack_config_exists(&cli.common)?;
    validate_mesh_cli(&cli, flags)?;
    ensure_mesh_config_from_stack(&cli, flags)?;

    let prepared = bootstrap::prepare_stack(&cli.common, flags)?;
    crate::logging::init(&prepared.settings.data_dir.join("logs"));
    log_mesh_effective_config(&prepared.settings);

    logs.push(format!(
        "config dir → {}",
        prepared.settings.data_dir.display()
    ));

    let mesh_started = start_mesh_if_needed(&prepared.settings, flags, &logs)?;

    let state = Arc::new(api::AppState::from(prepared));
    {
        let mut st = status.lock().expect("stack status");
        st.state = StackRunState::Running;
        st.mixed_port = Some(state.settings.mixed_port);
        st.tun_enabled = state.tun_enabled;
        st.mesh_enabled = flags.mesh_enabled();
        st.gateway = flags.gateway;
        st.error = None;
    }

    let engine = singbox::resolve_binary()?;
    let config_path = state.settings.config_path();

    if state.tun_enabled {
        let refreshed = bootstrap::refresh_config(&state.settings, flags)?;
        *state.config_json.write().expect("config lock") = refreshed;
    }

    let spawn_result = spawn_singbox(
        &engine,
        &state.settings,
        &config_path,
        state.tun_enabled,
        sudo_password.as_deref(),
    );
    let mut child = spawn_result?;
    drop(sudo_password);

    let pid = child.id();
    pid_atom.store(pid, Ordering::SeqCst);
    {
        let mut st = status.lock().expect("stack status");
        st.pid = Some(pid);
    }
    logs.push(format!("sing-box started pid={pid}"));
    let singbox_logs =
        SingboxLogWriter::new(state.settings.data_dir.join("logs"));

    if let Some(stdout) = child.take_stdout() {
        pipe_singbox_to_buffer(stdout, logs.clone(), singbox_logs.clone());
    }
    if let Some(stderr) = child.take_stderr() {
        pipe_singbox_to_buffer(stderr, logs.clone(), singbox_logs);
    }

    if state.tun_enabled {
        let settings = state.settings.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(3));
            singbox::tun_route::linux_register_tun_dns(&settings);
        });
    }

    if !flags.no_rules {
        rules::spawn_background_download(
            state.settings.clone(),
            state.config_json.clone(),
        );
    }

    let status_wait = loop {
        match child.try_wait().context("waiting for sing-box")? {
            Some(s) => break s,
            None => {
                if pid_atom.load(Ordering::SeqCst) == 0 {
                    let _ = child.kill();
                    break child.wait().context("wait after kill")?;
                }
                thread::sleep(Duration::from_millis(200));
            }
        }
    };

    if mesh_started {
        easytier::stop_all()?;
    }

    let code = status_wait.code().unwrap_or(1);
    if code != 0 {
        bail!("sing-box exited with status {code}");
    }
    Ok(())
}

fn start_mesh_if_needed(
    settings: &Settings,
    flags: StackFlags,
    logs: &LogBuffer,
) -> Result<bool> {
    if !flags.mesh_enabled() {
        return Ok(false);
    }
    let cfg = settings
        .mesh
        .as_ref()
        .context("[mesh] missing in zay.toml")?;
    easytier::start_for_singbox(cfg, &settings.data_dir)?;
    logs.push("EasyTier mesh started".to_string());
    if cfg.is_relay() {
        crate::singbox::tun_route::wait_for_mesh_listeners(
            cfg,
            std::time::Duration::from_secs(30),
        )?;
    } else if cfg.is_node() {
        let wg_listen =
            cfg.wireguard_listen.as_deref().unwrap_or("127.0.0.1:51820");
        let _ = crate::singbox::tun_route::wait_for_wireguard_port(
            wg_listen,
            std::time::Duration::from_secs(10),
        );
    }
    easytier::spawn_mesh_peer_watch(cfg.clone());
    Ok(true)
}
