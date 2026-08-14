//! Unified persistent component runner used by `zay service start`.
//!
//! Existing subcommands remain foreground tools. This module is intentionally
//! configuration-driven: it starts only components explicitly enabled in zay.toml.

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use tokio::{sync::oneshot, task::JoinHandle};

use crate::{
    ProxyOpts, daemon,
    fwd::{self, FwdCli},
    http::{self, HttpCli},
    settings::{self, MeshRole, PersistentConfig},
    ssh::{self, SshCli},
    stack::{MeshCliMode, StackCli, controller::StackController},
};

pub async fn run_daemon(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    guard: &daemon::Guard,
    sudo_password: Option<String>,
) -> Result<()> {
    run_inner(data_dir, config, Some(guard), sudo_password).await
}

async fn run_inner(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    daemon_guard: Option<&daemon::Guard>,
    mut sudo_password: Option<String>,
) -> Result<()> {
    let cfg = settings::load_persistent_config(
        data_dir.as_deref(),
        config.as_deref(),
    )?;
    let mut running = RunningComponents::new();

    if cfg.stack.enabled || cfg.mesh.is_some() {
        running.start_stack(&cfg, sudo_password.take())?;
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
            "no persistent component is enabled; configure [proxy], [[http]], [[fwd]], or [[ssh]] in zay.toml"
        );
    }

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
    if let Some(guard) = daemon_guard {
        guard.mark_ready()?;
    }

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
