//! JSON job specs (WebUI → serve API).

use serde::Deserialize;

use crate::ssh::SshArgs;

#[derive(Debug, Deserialize)]
pub struct SshJobSpec {
    pub ssh_host: String,
    #[serde(default)]
    pub local_forwards: Vec<String>,
    #[serde(default)]
    pub remote_forwards: Vec<String>,
    #[serde(default)]
    pub proxy_jump: Vec<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub identity: Option<String>,
    pub port: Option<u16>,
    #[serde(default)]
    pub strict_host_keys: bool,
}

#[derive(Debug, Deserialize)]
pub struct FwdJobSpec {
    pub to: String,
    pub from: String,
    pub token: Option<String>,
    #[serde(default)]
    pub verbose: u8,
}

#[derive(Debug, Deserialize)]
pub struct HttpJobSpec {
    #[serde(default = "default_root")]
    pub root: String,
    #[serde(default = "default_http_listen")]
    pub listen: String,
    #[serde(default)]
    pub spa: bool,
    #[serde(default)]
    pub cors: bool,
    pub cert: Option<String>,
    pub key: Option<String>,
}

fn default_root() -> String {
    ".".to_string()
}

fn default_http_listen() -> String {
    "127.0.0.1:8080".to_string()
}

impl SshJobSpec {
    pub fn into_args(self) -> SshArgs {
        use crate::ssh::{
            SshArgs,
            forward::{ForwardKind, SshForward},
        };
        let mut forwards = Vec::new();
        for spec in self.local_forwards {
            if let Ok(f) = SshForward::parse(&spec, ForwardKind::Local) {
                forwards.push(f);
            }
        }
        for spec in self.remote_forwards {
            if let Ok(f) = SshForward::parse(&spec, ForwardKind::Remote) {
                forwards.push(f);
            }
        }
        SshArgs {
            forwards,
            ssh_host: self.ssh_host,
            proxy_jump: self.proxy_jump,
            user: self.user,
            password: self.password,
            identity: self.identity,
            port: self.port,
            strict_host_keys: self.strict_host_keys,
        }
    }
}

impl FwdJobSpec {
    pub fn into_cli(self) -> anyhow::Result<crate::fwd::FwdCli> {
        Ok(crate::fwd::FwdCli {
            to: self.to,
            from: self.from,
            token: self.token,
            verbose: self.verbose,
        })
    }
}

impl HttpJobSpec {
    pub fn into_cli(self) -> anyhow::Result<crate::http::HttpCli> {
        use std::{net::SocketAddr, path::PathBuf};
        let listen: SocketAddr = self.listen.parse()?;
        Ok(crate::http::HttpCli {
            root: PathBuf::from(self.root),
            listen,
            spa: self.spa,
            cors: self.cors,
            cert: self.cert.map(PathBuf::from),
            key: self.key.map(PathBuf::from),
        })
    }
}
