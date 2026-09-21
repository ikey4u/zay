//! Elevated Unix host for the embeddable Rust sing-box TUN runtime.
//!
//! The worker is a hidden zay entry point, not a binary target owned by the
//! `singbox` crate.  Keeping the privilege boundary in zay lets the library
//! remain process- and signal-agnostic.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use tokio::signal::unix::{SignalKind, signal};

use crate::singbox::native::NativeRuntime;

pub const READY_MESSAGE: &str = "zay native TUN worker ready";

pub struct Args {
    pub runtime_dir: PathBuf,
    pub config_path: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    let mut runtime =
        NativeRuntime::start(&args.config_path, &args.runtime_dir)?;
    eprintln!("{READY_MESSAGE}");
    let control = runtime.handle();
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating native TUN worker control runtime")?;
    executor.block_on(async {
        let mut interrupt =
            signal(SignalKind::interrupt()).context("handling SIGINT")?;
        let mut terminate =
            signal(SignalKind::terminate()).context("handling SIGTERM")?;
        loop {
            tokio::select! {
                _ = interrupt.recv() => break,
                _ = terminate.recv() => break,
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if !runtime.is_running() {
                        break;
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    })?;
    control.cancel();
    runtime.wait()
}
