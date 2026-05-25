//! Static HTTP(S) file server.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use clap::Args;
use tower_http::{
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
};

#[derive(Args, Debug)]
pub struct HttpCli {
    /// Directory to serve
    #[arg(long, value_name = "DIR", default_value = ".")]
    pub root: PathBuf,

    /// Address to listen on
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,

    /// Serve index.html for unknown paths (SPA fallback)
    #[arg(long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    pub spa: bool,

    /// Enable permissive CORS for local development
    #[arg(long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    pub cors: bool,

    /// TLS certificate PEM file
    #[arg(long, value_name = "FILE", requires = "key")]
    pub cert: Option<PathBuf>,

    /// TLS private key PEM file
    #[arg(long, value_name = "FILE", requires = "cert")]
    pub key: Option<PathBuf>,
}

pub async fn run(cli: HttpCli) -> Result<()> {
    let root = validate_root(cli.root)?;
    validate_tls_files(cli.cert.as_ref(), cli.key.as_ref())?;

    let mut app = if cli.spa {
        let index = root.join("index.html");
        if !index.is_file() {
            bail!("--spa requires {}", index.display());
        }
        Router::new().fallback_service(
            ServeDir::new(&root).fallback(ServeFile::new(index)),
        )
    } else {
        Router::new().fallback_service(ServeDir::new(&root))
    };

    if cli.cors {
        app = app.layer(CorsLayer::permissive());
    }

    if let (Some(cert), Some(key)) = (cli.cert, cli.key) {
        let config = RustlsConfig::from_pem_file(&cert, &key)
            .await
            .with_context(|| {
                format!(
                    "loading TLS certificate {} and key {}",
                    cert.display(),
                    key.display()
                )
            })?;
        eprintln!("serving https://{} from {}", cli.listen, root.display());
        axum_server::bind_rustls(cli.listen, config)
            .serve(app.into_make_service())
            .await
            .context("serving HTTPS")?;
    } else {
        let listener = tokio::net::TcpListener::bind(cli.listen)
            .await
            .with_context(|| format!("binding {}", cli.listen))?;
        eprintln!("serving http://{} from {}", cli.listen, root.display());
        axum::serve(listener, app).await.context("serving HTTP")?;
    }

    Ok(())
}

fn validate_root(root: PathBuf) -> Result<PathBuf> {
    let meta = std::fs::metadata(&root)
        .with_context(|| format!("reading root {}", root.display()))?;
    if !meta.is_dir() {
        bail!("--root must be a directory: {}", root.display());
    }
    root.canonicalize()
        .with_context(|| format!("canonicalizing root {}", root.display()))
}

fn validate_tls_files(
    cert: Option<&PathBuf>,
    key: Option<&PathBuf>,
) -> Result<()> {
    match (cert, key) {
        (Some(cert), Some(key)) => {
            if !cert.is_file() {
                bail!("TLS cert file not found: {}", cert.display());
            }
            if !key.is_file() {
                bail!("TLS key file not found: {}", key.display());
            }
            Ok(())
        }
        (None, None) => Ok(()),
        _ => bail!("TLS requires both --cert and --key"),
    }
}
