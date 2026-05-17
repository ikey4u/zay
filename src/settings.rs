use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::Args;

pub const ZAY_TOML_FILE: &str = "zay.toml";

pub const DEFAULT_ZAY_TOML: &str = r#"# Zay – simple settings (edit this file, then: zay serve)
# Advanced clash overrides: mixin.yaml (YAML merge)

subscription = "https://your-subscription-url"

mixed_port = 7890
allow_lan = false
tun = false
log_level = "info"
health_check_url = "http://cp.cloudflare.com/generate_204"
update_interval = 3600

# controller = "127.0.0.1:9090"
# secret = "set-your-secret"

# mixin = "mixin.yaml"
"#;

pub const DEFAULT_MIXIN: &str = r#"# Optional clash overrides merged into generated config.yaml
# Example:
#   mixed-port: 7891
#   rules:
#     - DOMAIN-SUFFIX,example.com,DIRECT
"#;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct ZayFile {
    subscription: Option<String>,
    mixed_port: u16,
    allow_lan: bool,
    tun: bool,
    log_level: String,
    health_check_url: String,
    update_interval: u64,
    controller: Option<String>,
    secret: Option<String>,
    mixin: Option<String>,
}

impl Default for ZayFile {
    fn default() -> Self {
        Self {
            subscription: None,
            mixed_port: 7890,
            allow_lan: false,
            tun: false,
            log_level: "info".into(),
            health_check_url: "http://cp.cloudflare.com/generate_204".into(),
            update_interval: 3600,
            controller: None,
            secret: None,
            mixin: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub subscription: String,
    pub data_dir: PathBuf,
    pub mixed_port: u16,
    pub allow_lan: bool,
    pub tun: bool,
    pub log_level: String,
    pub health_check_url: String,
    pub update_interval: u64,
    pub controller: Option<String>,
    pub secret: Option<String>,
    pub mixin: Option<PathBuf>,
}

impl Settings {
    pub fn mixin_path(&self) -> PathBuf {
        self.mixin
            .clone()
            .unwrap_or_else(|| self.data_dir.join("mixin.yaml"))
    }
}

pub fn default_data_dir() -> PathBuf {
    dirs_next::config_dir()
        .map(|p| p.join("zay"))
        .unwrap_or_else(|| std::env::temp_dir().join("zay"))
}

fn load_zay_toml(path: &Path) -> Result<ZayFile> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

fn ensure_zay_toml(data_dir: &Path, toml_path: &Path) -> Result<()> {
    if toml_path.is_file() {
        return Ok(());
    }
    fs::create_dir_all(data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;
    fs::write(toml_path, DEFAULT_ZAY_TOML)
        .with_context(|| format!("writing {}", toml_path.display()))?;
    eprintln!("zay: created default config at {}", toml_path.display());
    Ok(())
}

pub fn ensure_default_mixin(settings: &Settings) -> Result<()> {
    let mixin_path = settings.mixin_path();
    if mixin_path.is_file() {
        return Ok(());
    }
    if let Some(parent) = mixin_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(&mixin_path, DEFAULT_MIXIN)
        .with_context(|| format!("writing {}", mixin_path.display()))?;
    eprintln!("zay: created default mixin at {}", mixin_path.display());
    Ok(())
}

pub fn resolve(cli: &Args) -> Result<Settings> {
    let data_dir = cli
        .data_dir
        .clone()
        .or_else(|| {
            cli.config
                .as_ref()
                .and_then(|p| p.parent().map(Path::to_path_buf))
        })
        .unwrap_or_else(default_data_dir);

    let toml_path = cli
        .config
        .clone()
        .unwrap_or_else(|| data_dir.join(ZAY_TOML_FILE));

    ensure_zay_toml(&data_dir, &toml_path)?;
    let file = load_zay_toml(&toml_path)?;

    let subscription = cli
        .subscription
        .clone()
        .or(file.subscription)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "subscription is required — set `subscription` in {} or pass --subscription",
                toml_path.display()
            )
        })?;

    let mixin = cli.mixin.clone().or_else(|| {
        file.mixin.map(|rel| {
            let path = PathBuf::from(&rel);
            if path.is_absolute() {
                path
            } else {
                toml_path.parent().unwrap_or(&data_dir).join(path)
            }
        })
    });

    Ok(Settings {
        subscription,
        data_dir,
        mixed_port: cli.mixed_port.unwrap_or(file.mixed_port),
        allow_lan: cli.allow_lan.unwrap_or(file.allow_lan),
        tun: cli.tun.unwrap_or(file.tun),
        log_level: cli.log_level.clone().unwrap_or(file.log_level),
        health_check_url: cli
            .health_check_url
            .clone()
            .unwrap_or(file.health_check_url),
        update_interval: cli.update_interval.unwrap_or(file.update_interval),
        controller: cli.controller.clone().or(file.controller),
        secret: cli.secret.clone().or(file.secret),
        mixin,
    })
}

pub fn cleanup_stale_subscription_cache(data_dir: &Path) {
    let cache = data_dir.join("providers/subscription.yaml");
    let Ok(raw) = fs::read_to_string(&cache) else {
        return;
    };
    let trimmed = raw.trim_start();
    let invalid = trimmed.starts_with('<')
        || trimmed.starts_with("<!doctype")
        || trimmed.starts_with("<!DOCTYPE");
    if invalid {
        let _ = fs::remove_file(&cache);
        eprintln!(
            "zay: removed invalid subscription cache at {}",
            cache.display()
        );
    }
}
