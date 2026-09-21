//! Unified persistent component runner used by `zay x service start`.
//!
//! Existing subcommands remain foreground tools. This module is intentionally
//! configuration-driven: it starts only components explicitly enabled in zay.toml.

use std::{path::PathBuf, process::Child, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::{
    sync::{Mutex, oneshot},
    task::JoinHandle,
};

use crate::{
    ProxyOpts, daemon,
    fwd::{self, FwdCli},
    http::{self, HttpCli},
    settings::{self, MeshRole, PersistentConfig},
    ssh::{self, SshCli},
    stack::{MeshCliMode, StackCli, controller::StackController},
};

/// Foreground core entry used only by the WebUI's supervised privileged child.
/// It intentionally does not detach or create an operating-system service.
pub async fn run_foreground_core(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
) -> Result<()> {
    run_inner(data_dir, config).await
}

async fn run_inner(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
) -> Result<()> {
    let cfg = settings::load_persistent_config(
        data_dir.as_deref(),
        config.as_deref(),
    )?;
    let running = RunningComponents::from_config(&cfg, None)?;

    let paths = daemon::paths(Some(&cfg.data_dir), Some(&cfg.toml_path));
    crate::logging::init(&paths.log_dir);
    crate::logging::emit(
        "info",
        "runtime",
        "started",
        "persistent runtime started",
    );
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let control =
        daemon::start_control(&paths, shutdown_tx, running.stack.clone())
            .await?;
    crate::logging::emit(
        "info",
        "runtime",
        "waiting_for_shutdown",
        "persistent runtime started; press Ctrl-C to stop",
    );
    wait_for_shutdown(&mut shutdown_rx).await?;
    control.abort();
    daemon::remove_control(&paths);
    running.stop().await
}

async fn wait_for_shutdown(shutdown: &mut oneshot::Receiver<()>) -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term =
            signal(SignalKind::terminate()).context("handling SIGTERM")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("waiting for Ctrl-C")?,
            _ = term.recv() => {},
            _ = shutdown => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("waiting for Ctrl-C")?,
            _ = shutdown => {},
        }
    }
    Ok(())
}

struct RunningComponents {
    stack: Option<Arc<StackController>>,
    tasks: Vec<JoinHandle<()>>,
}

impl RunningComponents {
    fn new() -> Self {
        Self {
            stack: None,
            tasks: Vec::new(),
        }
    }

    fn any(&self) -> bool {
        self.stack.is_some() || !self.tasks.is_empty()
    }

    fn from_config(
        cfg: &PersistentConfig,
        sudo_password: Option<String>,
    ) -> Result<Self> {
        let mut running = Self::new();
        if cfg.stack.enabled || cfg.mesh.is_some() {
            running.start_stack(cfg, sudo_password)?;
        }
        for item in cfg.http.iter().filter(|item| item.enabled) {
            running.start_http(item.clone());
        }
        for item in cfg.fwd.iter().filter(|item| item.enabled) {
            running.start_fwd(item.clone());
        }
        for item in cfg.ssh.iter().filter(|item| item.enabled) {
            running.start_ssh(item.clone());
        }
        if !running.any() {
            bail!(
                "no component is enabled; configure [proxy], [[http]], [[fwd]], or [[ssh]] in zay.toml"
            );
        }
        Ok(running)
    }

    fn start_stack(
        &mut self,
        cfg: &PersistentConfig,
        sudo_password: Option<String>,
    ) -> Result<()> {
        let mesh = cfg.mesh.as_ref().map(|mesh| match mesh.role {
            MeshRole::Relay => MeshCliMode::Relay,
            MeshRole::Node => MeshCliMode::Node,
        });
        let stack = &cfg.stack;
        let cli = StackCli {
            dump_config: false,
            common: ProxyOpts {
                subscriptions: stack.subscriptions.clone(),
                data_dir: Some(cfg.data_dir.clone()),
                config: Some(cfg.toml_path.clone()),
                mixed_port: stack.mixed_port,
                update_interval: stack.update_interval,
                health_check_url: stack.health_check_url.clone(),
                log_level: stack.log_level.clone(),
                no_tun: !stack.tun.enabled,
                tun_exclude_routes: stack.tun.exclude_routes.clone(),
                bootstrap_proxy: None,
            },
            mesh,
            gateway: stack.gateway,
            mesh_auth: None,
            mesh_ip: None,
        };
        let controller = Arc::new(StackController::new(
            crate::stack::log_buf::LogBuffer::with_default_capacity(),
        ));
        controller.start_cli(cli, sudo_password)?;
        self.stack = Some(controller);
        Ok(())
    }

    fn start_http(&mut self, item: settings::PersistentHttpFile) {
        self.tasks.push(tokio::spawn(async move {
            let cli = HttpCli {
                dump_config: false,
                root: item.root.unwrap_or_else(|| PathBuf::from(".")),
                listen: item.listen.unwrap_or_else(|| {
                    "127.0.0.1:8080".parse().expect("valid default")
                }),
                spa: item.spa,
                cors: item.cors,
                cert: item.cert,
                key: item.key,
            };
            if let Err(error) = http::run(cli).await {
                crate::logging::emit_error("http", "stopped", error);
            }
        }));
    }

    fn start_fwd(&mut self, item: settings::PersistentFwdFile) {
        self.tasks.push(tokio::spawn(async move {
            let cli = FwdCli {
                dump_config: false,
                to: item.to,
                from: item.from,
                token: item.token,
                verbose: item.verbose,
            };
            if let Err(error) = fwd::run_cli(cli).await {
                crate::logging::emit_error("fwd", "stopped", error);
            }
        }));
    }

    fn start_ssh(&mut self, item: settings::PersistentSshFile) {
        self.tasks.push(tokio::spawn(async move {
            let cli = SshCli {
                dump_config: false,
                local_forwards: item.local_forwards,
                remote_forwards: item.remote_forwards,
                ssh_host: item.ssh_host,
                proxy_jump: item.proxy_jump,
                user: item.user,
                password: item.password,
                identity: item.identity,
                port: item.port,
                strict_host_keys: item.strict_host_keys,
            };
            if let Err(error) = ssh::run_cli(cli).await {
                crate::logging::emit_error("ssh", "stopped", error);
            }
        }));
    }

    async fn stop(mut self) -> Result<()> {
        crate::logging::emit(
            "info",
            "runtime",
            "stopping",
            "stopping persistent components",
        );
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        if let Some(stack) = self.stack.take() {
            stack.stop()?;
        }
        Ok(())
    }
}

/// In-process lifecycle used by `zay webui`.
///
/// It never forks, detaches, or creates an operating-system service. The
/// caller's process manager owns the WebUI process and all of its tasks.
pub struct CoreSupervisor {
    data_dir: PathBuf,
    config_path: PathBuf,
    running: Mutex<Option<CoreHandle>>,
}

enum CoreHandle {
    InProcess(RunningComponents),
    PrivilegedChild(Child),
}

#[derive(Debug, Serialize)]
pub struct CoreStatus {
    pub running: bool,
    pub health: CoreHealth,
    pub error: Option<String>,
    pub stack: Option<crate::stack::controller::StackStatus>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreHealth {
    Stopped,
    Starting,
    Healthy,
    Degraded,
    Failed,
    Stopping,
}

impl CoreStatus {
    fn running(stack: Option<crate::stack::controller::StackStatus>) -> Self {
        use crate::stack::controller::StackRunState;

        let health = match stack.as_ref().map(|status| status.state) {
            Some(StackRunState::Starting) => CoreHealth::Starting,
            Some(StackRunState::Degraded) => CoreHealth::Degraded,
            Some(StackRunState::Stopped | StackRunState::Failed) => {
                CoreHealth::Failed
            }
            Some(StackRunState::Stopping) => CoreHealth::Stopping,
            Some(StackRunState::Running) | None => CoreHealth::Healthy,
        };
        let error = stack
            .as_ref()
            .and_then(|status| status.error.clone())
            .or_else(|| {
                matches!(health, CoreHealth::Failed)
                    .then(|| "网络栈已意外停止".to_string())
            });
        Self {
            running: true,
            health,
            error,
            stack,
        }
    }

    fn failed(error: impl Into<String>) -> Self {
        Self {
            running: true,
            health: CoreHealth::Failed,
            error: Some(error.into()),
            stack: None,
        }
    }

    fn stopped() -> Self {
        Self {
            running: false,
            health: CoreHealth::Stopped,
            error: None,
            stack: None,
        }
    }
}

impl CoreSupervisor {
    pub fn new(data_dir: PathBuf, config_path: PathBuf) -> Self {
        Self {
            data_dir,
            config_path,
            running: Mutex::new(None),
        }
    }

    pub async fn start(&self, password: Option<String>) -> Result<()> {
        let mut guard = self.running.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let cfg = settings::load_persistent_config(
            Some(&self.data_dir),
            Some(&self.config_path),
        )?;
        #[cfg(unix)]
        if cfg.requires_root() && !crate::privilege::is_root() {
            if password.is_none() {
                crate::privilege::validate_cached_authorization()?;
            }
            *guard = Some(CoreHandle::PrivilegedChild(
                self.spawn_privileged_child(password.as_deref()).await?,
            ));
            return Ok(());
        }
        let _ = password;
        *guard = Some(CoreHandle::InProcess(RunningComponents::from_config(
            &cfg, None,
        )?));
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let running = self.running.lock().await.take();
        if let Some(running) = running {
            match running {
                CoreHandle::InProcess(running) => running.stop().await?,
                CoreHandle::PrivilegedChild(mut child) => {
                    let paths = daemon::paths(
                        Some(&self.data_dir),
                        Some(&self.config_path),
                    );
                    let _ = daemon::request(&paths, "stop").await;
                    for _ in 0..50 {
                        if child
                            .try_wait()
                            .context("checking core child")?
                            .is_some()
                        {
                            daemon::remove_control(&paths);
                            return Ok(());
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    child
                        .kill()
                        .context("terminating unresponsive core child")?;
                    let _ = child.wait();
                    daemon::remove_control(&paths);
                }
            }
        }
        Ok(())
    }

    pub async fn restart(&self, password: Option<String>) -> Result<()> {
        #[cfg(unix)]
        {
            let cfg = settings::load_persistent_config(
                Some(&self.data_dir),
                Some(&self.config_path),
            )?;
            if cfg.requires_root() && !crate::privilege::is_root() {
                crate::privilege::validate_cached_authorization()?;
            }
        }
        self.stop().await?;
        self.start(password).await
    }

    pub async fn status(&self) -> CoreStatus {
        let mut guard = self.running.lock().await;
        match guard.as_mut() {
            Some(CoreHandle::InProcess(running)) => CoreStatus::running(
                running.stack.as_ref().map(|stack| stack.status()),
            ),
            Some(CoreHandle::PrivilegedChild(child)) => {
                if child.try_wait().ok().flatten().is_some() {
                    *guard = None;
                    return CoreStatus::stopped();
                }
                let paths = daemon::paths(
                    Some(&self.data_dir),
                    Some(&self.config_path),
                );
                match daemon::request(&paths, "stack-status").await {
                    Ok(raw) => match serde_json::from_str(&raw) {
                        Ok(stack) => CoreStatus::running(Some(stack)),
                        Err(error) => CoreStatus::failed(format!(
                            "核心状态响应无法解析：{error}"
                        )),
                    },
                    Err(error) => CoreStatus::failed(format!(
                        "无法读取特权核心状态：{error:#}"
                    )),
                }
            }
            None => CoreStatus::stopped(),
        }
    }

    pub async fn mesh_status(&self) -> Result<serde_json::Value> {
        let guard = self.running.lock().await;
        match guard.as_ref() {
            Some(CoreHandle::PrivilegedChild(_)) => {
                let paths = daemon::paths(
                    Some(&self.data_dir),
                    Some(&self.config_path),
                );
                let raw = daemon::request(&paths, "mesh-status").await?;
                serde_json::from_str(&raw).context("decoding mesh status")
            }
            Some(CoreHandle::InProcess(_)) => {
                drop(guard);
                let (sender, receiver) = oneshot::channel();
                std::thread::spawn(move || {
                    let result =
                        crate::stack::easytier::status().and_then(|status| {
                            serde_json::to_value(status)
                                .context("serializing mesh status")
                        });
                    let _ = sender.send(result);
                });
                receiver.await.context("mesh status thread exited")?
            }
            None => Ok(serde_json::json!([])),
        }
    }

    #[cfg(unix)]
    async fn spawn_privileged_child(
        &self,
        password: Option<&str>,
    ) -> Result<Child> {
        let paths =
            daemon::paths(Some(&self.data_dir), Some(&self.config_path));
        daemon::remove_control(&paths);
        let executable =
            std::env::current_exe().context("locating zay executable")?;
        let (mut command, write_password) = if let Some(password) = password {
            crate::privilege::command_for_program_with_password(
                &executable,
                true,
                Some(password),
            )?
        } else {
            (
                crate::privilege::command_for_program_with_cached_authorization(
                    &executable,
                )?,
                false,
            )
        };
        command
            .arg("--run-core")
            .arg("--data-dir")
            .arg(&self.data_dir)
            .arg("--config")
            .arg(&self.config_path);
        let mut child =
            command.spawn().context("starting privileged core child")?;
        if write_password {
            crate::privilege::write_password_stdin(
                &mut child,
                password.context("sudo password missing")?,
            )?;
        }
        for _ in 0..450 {
            if paths.control.is_file() {
                return Ok(child);
            }
            if let Some(status) =
                child.try_wait().context("checking core startup")?
            {
                bail!(
                    "privileged core exited during startup ({status}); if sudo authorization expired, restart `zay webui` from a terminal"
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = child.kill();
        bail!("timed out waiting for privileged core startup")
    }
}
