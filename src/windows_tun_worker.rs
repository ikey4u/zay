//! Elevated Windows host for the embeddable Rust sing-box TUN runtime.
//!
//! The unprivileged Zay supervisor talks to this process over a randomly
//! named local pipe.  The pipe token prevents unrelated local processes from
//! issuing lifecycle commands.

use std::{fs, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::ServerOptions,
    time::sleep,
};

use crate::singbox::native::NativeRuntime;

pub struct Args {
    pub runtime_dir: PathBuf,
    pub config_path: PathBuf,
    pub pipe_name: String,
    pub token: String,
}

struct MetadataGuard(PathBuf);

impl Drop for MetadataGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub fn run(args: Args) -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating Windows TUN worker runtime")?
        .block_on(run_inner(args))
}

async fn run_inner(args: Args) -> Result<()> {
    let metadata_path = args.runtime_dir.join("sing-box-worker.json");
    let pipe = format!(r"\\.\pipe\{}", args.pipe_name);
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe)
        .with_context(|| format!("creating TUN worker pipe {pipe}"))?;

    let mut runtime =
        NativeRuntime::start(&args.config_path, &args.runtime_dir)?;

    fs::write(
        &metadata_path,
        serde_json::json!({
            "pid": std::process::id(),
            "pipe": args.pipe_name,
            "token": args.token,
        })
        .to_string(),
    )
    .with_context(|| format!("writing {}", metadata_path.display()))?;
    let _metadata_guard = MetadataGuard(metadata_path);

    let received_stop = {
        let connected = server.connect();
        tokio::pin!(connected);
        tokio::select! {
            result = &mut connected => {
                result.context("accepting TUN worker command")?;
                true
            }
            () = wait_for_runtime(&runtime) => {
                false
            }
        }
    };
    let result = if received_stop {
        let mut request = String::new();
        server
            .read_to_string(&mut request)
            .await
            .context("reading TUN worker command")?;
        if !valid_stop_request(&request, &args.token) {
            bail!("rejected unauthenticated TUN worker command");
        }
        runtime.stop().context("stopping native sing-box runtime")?;
        server.write_all(b"stopped\n").await.ok();
        Ok(())
    } else {
        runtime
            .wait()
            .context("waiting for native sing-box runtime")
    };
    result
}

fn valid_stop_request(request: &str, token: &str) -> bool {
    request.trim() == format!("{token} stop")
}

async fn wait_for_runtime(runtime: &NativeRuntime) {
    loop {
        if !runtime.is_running() {
            return;
        }
        sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::valid_stop_request;

    #[test]
    fn stop_request_requires_exact_token() {
        assert!(valid_stop_request("secret stop\n", "secret"));
        assert!(!valid_stop_request("wrong stop", "secret"));
        assert!(!valid_stop_request("secret restart", "secret"));
    }
}
