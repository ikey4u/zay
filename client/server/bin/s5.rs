//! Standalone SOCKS server using singbox's existing SOCKS inbound.

use std::{future::Future, io, net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use singbox_core::{
    inbound::socks::{SocksServer, SocksServerOptions},
    option::User,
};

#[path = "s5/share.rs"]
mod share;

const SYSTEMD_HELP: &str = "\
Run as a systemd service:
  s5 --help-systemd prints a unit file for this binary, with install steps";

#[derive(Parser)]
#[command(
    name = "s5",
    version,
    about = "A standalone SOCKS5 server with TCP and UDP forwarding",
    after_help = SYSTEMD_HELP
)]
struct Args {
    /// Address to listen on (use [::1]:1080 for IPv6).
    #[arg(short, long, default_value = "127.0.0.1:1080", value_parser = listen_address)]
    listen: SocketAddr,

    /// Hostname or IP address phones should connect to (for example, your public server IP).
    #[arg(long, value_parser = share::advertise_host)]
    advertise: Option<String>,

    /// HTTP port for QR configuration imports (zero selects an available port).
    #[arg(long, default_value_t = 1081)]
    import_port: u16,

    /// Keep subscription URLs stable across restarts (32–64 URL-safe characters).
    #[arg(long, env = "S5_IMPORT_TOKEN", hide_env_values = true, value_parser = share::import_token)]
    import_token: Option<String>,

    /// QR payload format; use all to print every available format.
    #[arg(long, value_enum, default_value = "clash")]
    qr: share::QrFormat,

    /// Require this username and password for all connections.
    #[arg(long, env = "S5_USERNAME", requires = "password", value_parser = credential)]
    username: Option<String>,

    /// Authentication password; S5_PASSWORD avoids exposing it in process arguments.
    #[arg(long, env = "S5_PASSWORD", hide_env_values = true, requires = "username", value_parser = credential)]
    password: Option<String>,

    /// UDP association idle timeout in seconds.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u32).range(1..))]
    udp_timeout: u32,

    /// Concurrent SOCKS connections; each uses up to four file descriptors.
    #[arg(long, default_value_t = 1024, value_parser = clap::value_parser!(u32).range(1..))]
    max_connections: u32,

    /// Print a ready-to-use systemd unit for this binary and exit.
    #[arg(long)]
    help_systemd: bool,
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
    fn options(&self) -> Result<SocksServerOptions> {
        let users = match (&self.username, &self.password) {
            (Some(username), Some(password)) => {
                vec![User {
                    username: username.clone(),
                    password: password.clone(),
                }]
            }
            (None, None) => Vec::new(),
            _ => {
                anyhow::bail!("username and password must be supplied together")
            }
        };
        Ok(SocksServerOptions {
            listen: self.listen,
            users,
            udp_timeout: Duration::from_secs(self.udp_timeout.into()),
            max_connections: self.max_connections as usize,
            ..SocksServerOptions::default()
        })
    }
}

// Quote the ExecStart= program path; systemd expands `%` and `$` there.
fn systemd_word(value: &str) -> String {
    let word = value.replace('%', "%%").replace('$', "$$");
    let plain = !word.is_empty()
        && word.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || b"_-.,:/@+=%".contains(&byte)
        });
    if plain {
        return word;
    }
    format!("\"{}\"", word.replace('\\', "\\\\").replace('"', "\\\""))
}

// The unit starts the running binary from its resolved path with default
// options; the comments are valid unit syntax, so the output installs as is.
fn systemd_unit() -> Result<String> {
    let binary = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("locating the s5 binary")?;
    let binary = binary
        .to_str()
        .context("the s5 binary path is not valid UTF-8")?;
    let binary = systemd_word(binary);
    // A connection holds up to four descriptors (--max-connections is 1024).
    Ok(format!(
        "\
# Install and start:
#   s5 --help-systemd | sudo tee /etc/systemd/system/s5.service >/dev/null
#   sudo chmod 600 /etc/systemd/system/s5.service   # if it holds credentials
#   sudo systemctl daemon-reload
#   sudo systemctl enable --now s5
# Inspect:
#   systemctl status s5
#   journalctl -u s5 -f        # logs, including the import links
# After editing this file or replacing the binary:
#   sudo systemctl daemon-reload && sudo systemctl restart s5

[Unit]
Description=s5 SOCKS5 server
Wants=network-online.target
After=network-online.target

[Service]
# Append options to ExecStart= (see s5 --help), for example:
#   --listen 0.0.0.0:1080 --advertise HOST
ExecStart={binary}
# Uncomment to require authentication and keep import URLs stable:
#Environment=S5_USERNAME=alice
#Environment=S5_PASSWORD=secret
#Environment=S5_IMPORT_TOKEN=<output of: openssl rand -hex 32>
Restart=on-failure
RestartSec=2
# Keep at least four descriptors per --max-connections.
LimitNOFILE=4352
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
"
    ))
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
    if args.help_systemd {
        // Checked on the raw arguments: clap's `exclusive` also rejects
        // options that come from the S5_* environment variables.
        if std::env::args_os().len() != 2 {
            Args::command()
                .error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "--help-systemd cannot be combined with other options",
                )
                .exit();
        }
        print!("{}", systemd_unit()?);
        return Ok(());
    }
    let shutdown = shutdown_signal().context("registering shutdown signals")?;
    let host = args
        .advertise
        .clone()
        .unwrap_or_else(|| share::local_host(args.listen));
    let import = share::ImportServer::bind(
        SocketAddr::new(args.listen.ip(), args.import_port),
        &host,
        args.listen.port(),
        args.username.as_deref(),
        args.password.as_deref(),
        args.import_token.as_deref(),
    )
    .await
    .context("starting QR import server")?;
    let mut server =
        SocksServer::new(args.options()?).context("creating SOCKS server")?;
    server.start().await.context("starting SOCKS server")?;
    eprintln!("s5 listening on {} (TCP and UDP)", args.listen);
    match import.print(args.qr) {
        Ok(()) => {
            if args.listen.ip().is_loopback() {
                eprintln!(
                    "This listener is local only. Use --listen 0.0.0.0:1080 and --advertise HOST for mobile access."
                );
            }
        }
        Err(error) => {
            eprintln!("Could not print the server QR code: {error:#}")
        }
    }
    let mut import_task = tokio::spawn(import.run());
    // Either listener stopping is fatal: exit with an error so a service
    // manager restarts the process instead of leaving it half alive.
    let stop_result = tokio::select! {
        result = shutdown => result.context("waiting for shutdown signal"),
        result = &mut import_task => Err(anyhow::anyhow!("QR import server stopped: {result:?}")),
        result = server.wait() => Err(match result {
            Ok(()) => anyhow::anyhow!("SOCKS server stopped unexpectedly"),
            Err(error) => anyhow::Error::new(error).context("SOCKS server stopped"),
        }),
    };
    if !import_task.is_finished() {
        import_task.abort();
        let _ = import_task.await;
    }
    // Close active TCP connections and UDP associations even if signal
    // handling fails, rather than leaving cleanup to process termination.
    let close_result = server.close().await;
    stop_result?;
    close_result.context("closing SOCKS server")?;
    Ok(())
}
