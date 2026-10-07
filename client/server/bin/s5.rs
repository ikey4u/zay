//! Standalone SOCKS server using singbox's existing SOCKS inbound.

use std::{future::Future, io, net::SocketAddr};

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::json;
use singbox_core::{Options, Runtime};

#[derive(Parser)]
#[command(
    version,
    about = "A standalone SOCKS5 server with TCP and UDP forwarding"
)]
struct Args {
    /// Address to listen on (use [::1]:1080 for IPv6).
    #[arg(short, long, default_value = "127.0.0.1:1080", value_parser = listen_address)]
    listen: SocketAddr,

    /// Require this username and password for all connections.
    #[arg(long, env = "S5_USERNAME", requires = "password", value_parser = credential)]
    username: Option<String>,

    /// Authentication password; S5_PASSWORD avoids exposing it in process arguments.
    #[arg(long, env = "S5_PASSWORD", hide_env_values = true, requires = "username", value_parser = credential)]
    password: Option<String>,

    /// UDP association idle timeout in seconds.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u32).range(1..))]
    udp_timeout: u32,
}

fn listen_address(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value.parse().map_err(|_| {
        "expected an IP address and port, such as 127.0.0.1:1080".to_owned()
    })?;
    if address.port() == 0 {
        return Err("listen port must be between 1 and 65535".to_owned());
    }
    Ok(address)
}

fn credential(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 255 {
        return Err(
            "credentials must contain between 1 and 255 bytes".to_owned()
        );
    }
    Ok(value.to_owned())
}

impl Args {
    fn options(&self) -> Result<Options> {
        let users = match (&self.username, &self.password) {
            (Some(username), Some(password)) => {
                vec![json!({ "username": username, "password": password })]
            }
            (None, None) => Vec::new(),
            _ => {
                anyhow::bail!("username and password must be supplied together")
            }
        };
        // Runtime creates SocksInbound and owns its router, DNS resolver, and
        // outbound lifecycle. All destinations use the native direct dialer.
        serde_json::from_value(json!({
            "log": { "level": "info" },
            "inbounds": [{
                "type": "socks",
                "tag": "s5-in",
                "listen": self.listen.ip().to_string(),
                "listen_port": self.listen.port(),
                "users": users,
                "udp_timeout": format!("{}s", self.udp_timeout)
            }],
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": { "final": "direct" }
        }))
        .context("building SOCKS server configuration")
    }
}

// Register SIGTERM before starting the listener so service managers can stop
// the server throughout its lifetime. Ctrl+C is also supported on Windows.
fn shutdown_signal() -> io::Result<impl Future<Output = io::Result<()>>> {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )?;
        Ok(async move {
            tokio::select! {
                result = tokio::signal::ctrl_c() => result,
                _ = terminate.recv() => Ok(()),
            }
        })
    }
    #[cfg(not(unix))]
    {
        Ok(tokio::signal::ctrl_c())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let shutdown = shutdown_signal().context("registering shutdown signals")?;
    let mut runtime = Runtime::from_options(args.options()?)
        .context("creating SOCKS server")?;
    runtime.start().await.context("starting SOCKS server")?;
    eprintln!("s5 listening on {} (TCP and UDP)", args.listen);
    let signal_result = shutdown.await;
    // Close active TCP connections and UDP associations even if signal
    // handling fails, rather than leaving cleanup to process termination.
    let close_result = runtime.close().await;
    signal_result.context("waiting for shutdown signal")?;
    close_result.context("closing SOCKS server")?;
    Ok(())
}
