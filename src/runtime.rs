//! Unified persistent component runner used by `zay x service start`.
//!
//! Existing subcommands remain foreground tools. This module is intentionally
//! configuration-driven: it starts only components explicitly enabled in zay.toml.

use std::{path::PathBuf, process::Child, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
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

// Live-runtime tests share EasyTier's process-global instance manager.
#[cfg(test)]
pub(crate) static TEST_RUNTIME_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Foreground core entry used only by the WebUI's supervised privileged child.
/// It intentionally does not detach or create an operating-system service.
pub async fn run_foreground_core(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
) -> Result<()> {
    run_inner(data_dir, config, None).await
}

pub async fn run_supervised_core(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    parent: u32,
) -> Result<()> {
    run_inner(data_dir, config, Some(parent)).await
}

async fn run_inner(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    parent: Option<u32>,
) -> Result<()> {
    let (data_dir, config_path) =
        settings::stack_config_paths(data_dir.as_deref(), config.as_deref());
    let paths = daemon::paths(Some(&data_dir), Some(&config_path));
    crate::logging::init(&paths.log_dir);
    let mut core = CoreRuntime::new(data_dir, config_path);
    // A supervised host starts idle; the WebUI controls component lifetime.
    if parent.is_none() {
        core.start().await?;
    }
    let core = Arc::new(Mutex::new(core));
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let control =
        daemon::start_control(&paths, shutdown_tx, core.clone()).await?;
    let parent_gone = async {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if parent.is_some_and(|pid| !daemon::process_is_alive(pid)) {
                break;
            }
        }
    };
    tokio::select! {
        result = wait_for_shutdown(&mut shutdown_rx) => { result?; }
        _ = parent_gone => {}
    }
    // Finish an in-flight mutation before stopping the control task; cancelling
    // halfway through startup could strand a worker outside the stored runtime.
    let mut core = core.lock().await;
    control.abort();
    let _ = control.await;
    daemon::remove_control(&paths);
    core.stop().await
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
    http_tasks: Vec<JoinHandle<()>>,
    fwd_tasks: Vec<JoinHandle<()>>,
    ssh_tasks: Vec<JoinHandle<()>>,
    config: PersistentConfig,
    startup_error: Option<String>,
}

impl RunningComponents {
    async fn from_config(cfg: &PersistentConfig) -> Result<Self> {
        let mut running = Self {
            stack: None,
            http_tasks: Vec::new(),
            fwd_tasks: Vec::new(),
            ssh_tasks: Vec::new(),
            config: cfg.clone(),
            startup_error: None,
        };
        if let Err(error) = running.start_mesh(cfg).await {
            let _ = on_thread(crate::stack::easytier::stop_all).await;
            return Err(error);
        }
        if cfg.stack.enabled || cfg.mesh.is_some() {
            if let Err(error) = running.start_stack(cfg).await {
                // A proxy failure must not tear down an already-started Mesh
                // or prevent unrelated services from starting.
                running.startup_error = Some(format!("{error:#}"));
            }
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
        Ok(running)
    }

    async fn start_mesh(&self, cfg: &PersistentConfig) -> Result<()> {
        let Some(mesh) = cfg.mesh.clone() else {
            return Ok(());
        };
        let data_dir = cfg.data_dir.clone();
        on_thread(move || {
            crate::stack::easytier::start_for_singbox(&mesh, &data_dir)?;
            if mesh.is_node() {
                crate::stack::easytier::wait_for_virtual_ip(
                    Duration::from_secs(30),
                )?;
            } else {
                crate::singbox::tun_route::wait_for_mesh_listeners(
                    &mesh,
                    Duration::from_secs(30),
                )?;
            }
            Ok(())
        })
        .await
    }

    async fn apply(
        &mut self,
        cfg: &PersistentConfig,
        force_proxy: bool,
    ) -> Result<ApplyResult> {
        let plan = ChangePlan::between(&self.config, cfg, force_proxy)?;
        if let Some(mesh) = &cfg.mesh {
            crate::stack::easytier::to_easytier_toml(mesh)?;
        }
        // Stop the affected proxy first when its TUN depends on the mesh routes.
        if plan.proxy {
            if let Some(stack) = self.stack.take() {
                on_thread(move || stack.stop()).await?;
            }
        }
        if plan.mesh {
            on_thread(crate::stack::easytier::stop_all).await?;
            self.start_mesh(cfg).await?;
            self.config.mesh = cfg.mesh.clone();
        }
        if plan.proxy && (cfg.stack.enabled || cfg.mesh.is_some()) {
            self.start_stack(cfg).await?;
        }
        if plan.http {
            stop_tasks(&mut self.http_tasks).await;
            for item in cfg.http.iter().filter(|item| item.enabled) {
                self.start_http(item.clone());
            }
        }
        if plan.fwd {
            stop_tasks(&mut self.fwd_tasks).await;
            for item in cfg.fwd.iter().filter(|item| item.enabled) {
                self.start_fwd(item.clone());
            }
        }
        if plan.ssh {
            stop_tasks(&mut self.ssh_tasks).await;
            for item in cfg.ssh.iter().filter(|item| item.enabled) {
                self.start_ssh(item.clone());
            }
        }
        self.config = cfg.clone();
        Ok(ApplyResult {
            applied: true,
            components: plan.components(),
            error: None,
        })
    }

    async fn start_stack(&mut self, cfg: &PersistentConfig) -> Result<()> {
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
        controller.start_proxy_cli(cli)?;
        self.stack = Some(controller.clone());
        controller.wait_started().await
    }

    fn start_http(&mut self, item: settings::PersistentHttpFile) {
        self.http_tasks.push(tokio::spawn(async move {
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
        self.fwd_tasks.push(tokio::spawn(async move {
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
        self.ssh_tasks.push(tokio::spawn(async move {
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
        stop_tasks(&mut self.http_tasks).await;
        stop_tasks(&mut self.fwd_tasks).await;
        stop_tasks(&mut self.ssh_tasks).await;
        if let Some(stack) = self.stack.take() {
            on_thread(move || stack.stop()).await?;
        }
        if self.config.mesh.is_some() {
            on_thread(crate::stack::easytier::stop_all).await?;
            self.config.mesh = None;
        }
        Ok(())
    }
}

impl Drop for RunningComponents {
    fn drop(&mut self) {
        for task in self
            .http_tasks
            .iter()
            .chain(&self.fwd_tasks)
            .chain(&self.ssh_tasks)
        {
            task.abort();
        }
        if let Some(stack) = self.stack.take() {
            let _ = stack.stop();
        }
        if self.config.mesh.is_some() {
            let _ = crate::stack::easytier::stop_all();
        }
    }
}

async fn stop_tasks(tasks: &mut Vec<JoinHandle<()>>) {
    for task in tasks.iter() {
        task.abort();
    }
    for task in tasks.drain(..) {
        let _ = task.await;
    }
}

// EasyTier performs block_on internally, so keep it outside Tokio worker threads.
async fn on_thread<T: Send + 'static>(
    job: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let (sender, receiver) = oneshot::channel();
    std::thread::spawn(move || {
        let _ = sender.send(job());
    });
    receiver
        .await
        .context("component operation thread exited")?
}

#[derive(Debug, Default)]
struct ChangePlan {
    proxy: bool,
    mesh: bool,
    http: bool,
    fwd: bool,
    ssh: bool,
}

impl ChangePlan {
    fn between(
        old: &PersistentConfig,
        new: &PersistentConfig,
        force_proxy: bool,
    ) -> Result<Self> {
        let proxy_active =
            |cfg: &PersistentConfig| cfg.stack.enabled || cfg.mesh.is_some();
        let proxy_view = |cfg: &PersistentConfig| -> Result<serde_json::Value> {
            let mut proxy = cfg.stack.clone();
            proxy.mesh = None;
            proxy.mixed_port.get_or_insert(7890);
            proxy.update_interval.get_or_insert(3600);
            proxy.log_level.get_or_insert_with(|| "info".into());
            proxy.health_check_url.get_or_insert_with(|| {
                "http://cp.cloudflare.com/generate_204".into()
            });
            // These fields feed the proxy's TUN address, exclusions and mesh bypass rules.
            let mesh_routes = cfg.mesh.as_ref().map(|mesh| serde_json::json!({
                "role": mesh.role, "ipv4": mesh.ipv4, "peers": mesh.peers,
                "listeners": mesh.listeners, "mesh_routes": mesh.mesh_routes,
                "wireguard_client_address": mesh.wireguard_client_address,
            }));
            Ok(
                serde_json::json!({ "proxy": proxy, "mesh_routes": mesh_routes }),
            )
        };
        let differs = |a: serde_json::Value, b: serde_json::Value| a != b;
        Ok(Self {
            proxy: (proxy_active(old) || proxy_active(new))
                && (force_proxy || proxy_view(old)? != proxy_view(new)?),
            mesh: differs(
                serde_json::to_value(&old.mesh)?,
                serde_json::to_value(&new.mesh)?,
            ),
            http: differs(
                serde_json::to_value(&old.http)?,
                serde_json::to_value(&new.http)?,
            ),
            fwd: differs(
                serde_json::to_value(&old.fwd)?,
                serde_json::to_value(&new.fwd)?,
            ),
            ssh: differs(
                serde_json::to_value(&old.ssh)?,
                serde_json::to_value(&new.ssh)?,
            ),
        })
    }

    fn components(&self) -> Vec<String> {
        [
            (self.proxy, "proxy"),
            (self.mesh, "mesh"),
            (self.http, "http"),
            (self.fwd, "fwd"),
            (self.ssh, "ssh"),
        ]
        .into_iter()
        .filter(|(changed, _)| *changed)
        .map(|(_, name)| name.into())
        .collect()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ApplyResult {
    pub applied: bool,
    pub components: Vec<String>,
    pub error: Option<String>,
}

/// The authorized host remains alive while components are stopped or replaced.
/// Its lifetime ends only when the owning WebUI exits.
pub struct CoreRuntime {
    data_dir: PathBuf,
    config_path: PathBuf,
    running: Option<RunningComponents>,
    apply_error: Option<String>,
    pending_proxy: bool,
}

impl CoreRuntime {
    pub fn new(data_dir: PathBuf, config_path: PathBuf) -> Self {
        Self {
            data_dir,
            config_path,
            running: None,
            apply_error: None,
            pending_proxy: false,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running.is_some() {
            return Ok(());
        }
        if self.running.is_none() {
            let cfg = settings::load_persistent_config(
                Some(&self.data_dir),
                Some(&self.config_path),
            )?;
            match RunningComponents::from_config(&cfg).await {
                Ok(mut running) => {
                    let error = running.startup_error.take();
                    self.running = Some(running);
                    if let Some(error) = error {
                        self.apply_error = Some(error.clone());
                        self.pending_proxy = true;
                        bail!("{error}");
                    }
                }
                Err(error) => {
                    self.apply_error = Some(format!("{error:#}"));
                    return Err(error);
                }
            }
        }
        self.apply_error = None;
        self.pending_proxy = false;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if let Some(running) = self.running.take() {
            running.stop().await?;
        }
        self.apply_error = None;
        self.pending_proxy = false;
        Ok(())
    }

    pub async fn restart(&mut self) -> Result<()> {
        // Validate before interrupting any running component.
        settings::load_persistent_config(
            Some(&self.data_dir),
            Some(&self.config_path),
        )?;
        self.stop().await?;
        self.start().await
    }

    pub async fn apply(&mut self, force_proxy: bool) -> Result<ApplyResult> {
        let cfg = settings::load_persistent_config(
            Some(&self.data_dir),
            Some(&self.config_path),
        )?;
        let Some(running) = self.running.as_mut() else {
            return Ok(ApplyResult::default());
        };
        self.pending_proxy |= force_proxy;
        match running.apply(&cfg, self.pending_proxy).await {
            Ok(result) => {
                self.apply_error = None;
                self.pending_proxy = false;
                Ok(result)
            }
            Err(error) => {
                self.apply_error = Some(format!("{error:#}"));
                self.pending_proxy = true;
                Err(error)
            }
        }
    }

    pub fn status(&self) -> CoreStatus {
        let Some(running) = &self.running else {
            let mut status = CoreStatus::stopped();
            if let Some(error) = &self.apply_error {
                status.health = CoreHealth::Failed;
                status.error = Some(error.clone());
            }
            return status;
        };
        let mut status = CoreStatus::running(
            running.stack.as_ref().map(|stack| stack.status()),
        );
        status.pending_changes = self.apply_error.is_some()
            || settings::load_persistent_config(
                Some(&self.data_dir),
                Some(&self.config_path),
            )
            .and_then(|cfg| ChangePlan::between(&running.config, &cfg, false))
            .map(|plan| !plan.components().is_empty())
            .unwrap_or(true);
        if let Some(error) = &self.apply_error {
            status.health = CoreHealth::Degraded;
            status.error = Some(error.clone());
        }
        status
    }
}

pub struct CoreSupervisor {
    data_dir: PathBuf,
    config_path: PathBuf,
    running: Mutex<Option<CoreHandle>>,
}

enum CoreHandle {
    InProcess(CoreRuntime),
    PrivilegedChild(Child),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoreStatus {
    pub running: bool,
    #[serde(default)]
    pub pending_changes: bool,
    pub health: CoreHealth,
    pub error: Option<String>,
    pub stack: Option<crate::stack::controller::StackStatus>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
                matches!(health, CoreHealth::Failed).then(|| {
                    "The network stack stopped unexpectedly".to_string()
                })
            });
        Self {
            running: true,
            pending_changes: false,
            health,
            error,
            stack,
        }
    }

    fn failed(error: impl Into<String>) -> Self {
        Self {
            running: true,
            pending_changes: false,
            health: CoreHealth::Failed,
            error: Some(error.into()),
            stack: None,
        }
    }

    fn stopped() -> Self {
        Self {
            running: false,
            pending_changes: false,
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

    pub async fn initialize(&self, password: Option<String>) -> Result<()> {
        let mut guard = self.running.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        #[cfg(unix)]
        if !crate::privilege::is_root() {
            *guard = Some(CoreHandle::PrivilegedChild(
                self.spawn_privileged_child(password.as_deref()).await?,
            ));
            return Ok(());
        }
        let _ = password;
        *guard = Some(CoreHandle::InProcess(CoreRuntime::new(
            self.data_dir.clone(),
            self.config_path.clone(),
        )));
        Ok(())
    }

    async fn remote<T: serde::de::DeserializeOwned>(
        &self,
        command: &str,
    ) -> Result<T> {
        let paths =
            daemon::paths(Some(&self.data_dir), Some(&self.config_path));
        let raw = daemon::request(&paths, command).await?;
        let response: serde_json::Value =
            serde_json::from_str(&raw).context("decoding core response")?;
        if let Some(error) = response.get("error").and_then(|v| v.as_str()) {
            bail!("{error}");
        }
        serde_json::from_value(response).context("decoding core result")
    }

    pub async fn start(&self, password: Option<String>) -> Result<()> {
        self.initialize(password).await?;
        let mut guard = self.running.lock().await;
        match guard.as_mut().context("core host is unavailable")? {
            CoreHandle::InProcess(core) => core.start().await,
            CoreHandle::PrivilegedChild(_) => {
                self.remote::<serde_json::Value>("components-start").await?;
                Ok(())
            }
        }
    }

    pub async fn stop(&self) -> Result<()> {
        let mut guard = self.running.lock().await;
        match guard.as_mut() {
            Some(CoreHandle::InProcess(core)) => core.stop().await,
            Some(CoreHandle::PrivilegedChild(_)) => {
                self.remote::<serde_json::Value>("components-stop").await?;
                Ok(())
            }
            None => Ok(()),
        }
    }

    pub async fn restart(&self, _password: Option<String>) -> Result<()> {
        let mut guard = self.running.lock().await;
        match guard.as_mut().context("core host is unavailable")? {
            CoreHandle::InProcess(core) => core.restart().await,
            CoreHandle::PrivilegedChild(_) => {
                self.remote::<serde_json::Value>("components-restart")
                    .await?;
                Ok(())
            }
        }
    }

    pub async fn apply(&self, force_proxy: bool) -> Result<ApplyResult> {
        let mut guard = self.running.lock().await;
        match guard.as_mut() {
            Some(CoreHandle::InProcess(core)) => core.apply(force_proxy).await,
            Some(CoreHandle::PrivilegedChild(_)) => {
                self.remote(if force_proxy {
                    "proxy-apply"
                } else {
                    "components-apply"
                })
                .await
            }
            None => Ok(ApplyResult::default()),
        }
    }

    pub async fn status(&self) -> CoreStatus {
        let mut guard = self.running.lock().await;
        match guard.as_mut() {
            Some(CoreHandle::InProcess(core)) => core.status(),
            Some(CoreHandle::PrivilegedChild(child)) => {
                if child.try_wait().ok().flatten().is_some() {
                    *guard = None;
                    return CoreStatus::failed(
                        "The privileged core host exited; check the Zay service logs",
                    );
                }
                let paths = daemon::paths(
                    Some(&self.data_dir),
                    Some(&self.config_path),
                );
                match daemon::request(&paths, "core-status").await.and_then(
                    |raw| {
                        serde_json::from_str(&raw)
                            .context("decoding core status")
                    },
                ) {
                    Ok(status) => status,
                    Err(error) => CoreStatus::failed(format!(
                        "Failed to read core status: {error:#}"
                    )),
                }
            }
            None => CoreStatus::stopped(),
        }
    }

    /// Exit the authorized host only when the owning WebUI is shutting down.
    pub async fn shutdown(&self) -> Result<()> {
        let running = self.running.lock().await.take();
        match running {
            Some(CoreHandle::InProcess(mut core)) => core.stop().await,
            Some(CoreHandle::PrivilegedChild(mut child)) => {
                let paths = daemon::paths(
                    Some(&self.data_dir),
                    Some(&self.config_path),
                );
                let _ = daemon::request(&paths, "stop").await;
                for _ in 0..100 {
                    if child.try_wait()?.is_some() {
                        daemon::remove_control(&paths);
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                child.kill().context("terminating unresponsive core host")?;
                let _ = child.wait();
                daemon::remove_control(&paths);
                Ok(())
            }
            None => Ok(()),
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
        if paths.control.exists()
            && daemon::request(&paths, "status").await.is_ok()
        {
            bail!("another Zay core already manages this data directory");
        }
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
            .arg("--core-parent-pid")
            .arg(std::process::id().to_string())
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
                    "privileged core host exited during startup ({status}); check administrator authorization and service logs"
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = child.kill();
        bail!("timed out waiting for privileged core startup")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> PersistentConfig {
        let mesh: settings::MeshConfig = serde_json::from_value(json!({
            "enabled": true, "role": "node", "network_name": "test", "network_secret": "test",
            "ipv4": "10.126.0.1/24", "mesh_routes": ["10.126.0.0/24"],
            "peers": ["tcp://192.0.2.1:11010"]
        })).unwrap();
        PersistentConfig {
            data_dir: PathBuf::from("/tmp/test"),
            toml_path: PathBuf::from("/tmp/test/zay.toml"),
            stack: settings::PersistentProxyFile {
                enabled: true,
                mesh: Some(mesh.clone()),
                ..Default::default()
            },
            mesh: Some(mesh),
            http: vec![],
            fwd: vec![],
            ssh: vec![],
        }
    }

    #[test]
    fn change_plan_isolates_proxy_and_mesh_and_normalizes_defaults() {
        let old = config();
        let mut next = old.clone();
        next.stack.mixed_port = Some(7890);
        next.stack.log_level = Some("info".into());
        next.stack.update_interval = Some(3600);
        next.stack.health_check_url =
            Some("http://cp.cloudflare.com/generate_204".into());
        assert!(
            ChangePlan::between(&old, &next, false)
                .unwrap()
                .components()
                .is_empty()
        );
        next.stack.active_nodes = vec!["sg".into()];
        assert_eq!(
            ChangePlan::between(&old, &next, false)
                .unwrap()
                .components(),
            ["proxy"]
        );
        let mut next = old.clone();
        next.mesh.as_mut().unwrap().name = Some("new name".into());
        next.mesh.as_mut().unwrap().network_secret = "new secret".into();
        assert_eq!(
            ChangePlan::between(&old, &next, false)
                .unwrap()
                .components(),
            ["mesh"]
        );
        next.mesh.as_mut().unwrap().peers =
            Some(vec!["tcp://192.0.2.2:11010".into()]);
        assert_eq!(
            ChangePlan::between(&old, &next, false)
                .unwrap()
                .components(),
            ["proxy", "mesh"]
        );
        assert_eq!(
            ChangePlan::between(&old, &old, true).unwrap().components(),
            ["proxy"]
        );
    }

    #[tokio::test]
    async fn core_host_can_stop_start_and_apply_without_being_recreated() {
        let _guard = TEST_RUNTIME_LOCK.lock().unwrap();
        let directory = std::env::temp_dir()
            .join(format!("zay-core-lifecycle-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("zay.toml");
        let original = "[proxy]\nenabled = false\n[[http]]\nenabled = true\nlisten = '127.0.0.1:0'\n";
        std::fs::write(&path, original).unwrap();
        let mut core = CoreRuntime::new(directory.clone(), path.clone());
        core.start().await.unwrap();
        let task = core.running.as_ref().unwrap().http_tasks[0].id();
        assert!(core.apply(false).await.unwrap().components.is_empty());
        assert_eq!(core.running.as_ref().unwrap().http_tasks[0].id(), task);
        std::fs::write(&path, format!("{original}cors = true\n")).unwrap();
        assert_eq!(core.apply(false).await.unwrap().components, ["http"]);
        assert_ne!(core.running.as_ref().unwrap().http_tasks[0].id(), task);
        core.stop().await.unwrap();
        assert!(!core.status().running);
        assert!(!core.apply(false).await.unwrap().applied);
        core.start().await.unwrap();
        assert!(core.status().running);
        core.stop().await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[tokio::test]
    async fn core_proxy_apply_preserves_other_tasks_and_retries_failed_config()
    {
        let _guard = TEST_RUNTIME_LOCK.lock().unwrap();
        let directory = std::env::temp_dir()
            .join(format!("zay-core-proxy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("zay.toml");
        let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port1 = first.local_addr().unwrap().port();
        let port2 = second.local_addr().unwrap().port();
        drop(first);
        drop(second);
        let config = |port, invalid| {
            format!(
                "[proxy]\nenabled = true\nmixed_port = {port}\n{}[proxy.tun]\nenabled = false\n[[http]]\nenabled = true\nlisten = '127.0.0.1:0'\n",
                if invalid { "mixin = '{invalid'\n" } else { "" }
            )
        };
        std::fs::write(&path, config(port1, false)).unwrap();
        let mut core = CoreRuntime::new(directory.clone(), path.clone());
        core.start().await.unwrap();
        let http = core.running.as_ref().unwrap().http_tasks[0].id();
        let proxy = core.running.as_ref().unwrap().stack.clone().unwrap();
        assert!(core.apply(false).await.unwrap().components.is_empty());
        assert!(Arc::ptr_eq(
            &proxy,
            core.running.as_ref().unwrap().stack.as_ref().unwrap()
        ));
        std::fs::write(&path, config(port2, false)).unwrap();
        assert_eq!(core.apply(false).await.unwrap().components, ["proxy"]);
        assert_eq!(core.running.as_ref().unwrap().http_tasks[0].id(), http);
        assert!(std::net::TcpStream::connect(("127.0.0.1", port1)).is_err());
        assert!(std::net::TcpStream::connect(("127.0.0.1", port2)).is_ok());
        std::fs::write(&path, config(port2, true)).unwrap();
        assert!(core.apply(false).await.is_err());
        assert!(core.status().pending_changes);
        assert_eq!(core.running.as_ref().unwrap().http_tasks[0].id(), http);
        std::fs::write(&path, config(port2, false)).unwrap();
        assert_eq!(core.apply(false).await.unwrap().components, ["proxy"]);
        assert!(!core.status().pending_changes);
        core.stop().await.unwrap();
        std::fs::write(&path, config(port2, true)).unwrap();
        assert!(core.start().await.is_err());
        assert_eq!(core.running.as_ref().unwrap().http_tasks.len(), 1);
        assert!(core.status().pending_changes);
        std::fs::write(&path, config(port2, false)).unwrap();
        assert_eq!(core.apply(false).await.unwrap().components, ["proxy"]);
        core.stop().await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}
