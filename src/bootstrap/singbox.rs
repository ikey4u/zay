//! Prepare sing-box stack (`zay stack` on the singbox branch).

use std::fs;

use anyhow::{Context, Result};

use crate::{
    ProxyOpts,
    settings::{self as zay_settings, Settings, StackFlags},
    singbox::{self, mixin, rules},
    stack,
};

pub struct Prepared {
    pub config_json: String,
    pub settings: Settings,
    pub tun_enabled: bool,
}

pub fn prepare_stack(cli: &ProxyOpts, flags: StackFlags) -> Result<Prepared> {
    let settings = zay_settings::resolve_stack(cli, flags)?;
    stack::validate(&settings)?;
    prepare_inner(settings, flags)
}

fn prepare_inner(settings: Settings, flags: StackFlags) -> Result<Prepared> {
    eprintln!("sing-box {}", singbox::VERSION);
    if flags.no_rules {
        eprintln!("external-controller {}", settings.external_controller);
    } else {
        eprintln!(
            "external-controller {} (reload after rules download)",
            settings.external_controller
        );
    }

    std::fs::create_dir_all(&settings.data_dir).with_context(|| {
        format!("creating data dir {}", settings.data_dir.display())
    })?;
    std::fs::create_dir_all(settings.singbox_dir()).with_context(|| {
        format!("creating {}", settings.singbox_dir().display())
    })?;
    std::fs::create_dir_all(settings.singbox_dir().join("providers"))
        .with_context(|| {
            format!(
                "creating {}",
                settings.singbox_dir().join("providers").display()
            )
        })?;
    std::fs::create_dir_all(rules::ruleset_dir(&settings.singbox_dir()))
        .with_context(|| {
            format!(
                "creating {}",
                rules::ruleset_dir(&settings.singbox_dir()).display()
            )
        })?;

    // sing-box opens cache.db under `-D`; create an empty file so first start never fails on ENOENT.
    let cache_db = settings.singbox_dir().join("cache.db");
    if !cache_db.exists() {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&cache_db)
            .with_context(|| format!("creating {}", cache_db.display()))?;
    }

    if !settings.subscriptions.is_empty() {
        zay_settings::cleanup_stale_subscription_cache(
            &settings.singbox_dir(),
            settings.subscriptions.len(),
        );
    }

    let has_rules = rules::files_present(&settings.singbox_dir());
    if flags.no_rules {
        if has_rules {
            eprintln!(
                "clash-rules: using cached rule-sets (--no-rules, no download)"
            );
        } else {
            eprintln!(
                "clash-rules skipped (--no-rules); using simple fallback routes"
            );
        }
    } else if !has_rules {
        if settings.subscriptions.is_empty() {
            eprintln!("clash-rules missing; using simple fallback routes");
        } else {
            eprintln!(
                "clash-rules missing; will download via proxy after startup"
            );
        }
    }

    if let Some(bp) = &settings.bootstrap_proxy {
        eprintln!("bootstrap proxy \"{}\" will fetch subscription", bp.name);
    }

    let base = singbox::build_config(&settings, has_rules)?;
    let config_json = mixin::merge_config(&base, &settings)?;

    let config_path = settings.config_path();
    std::fs::write(&config_path, &config_json).with_context(|| {
        format!("writing config to {}", config_path.display())
    })?;
    eprintln!("config → {}", config_path.display());

    let mut tun_enabled = singbox::tun_route::singbox_tun_enabled(&settings);
    if tun_enabled
        && !settings.tun
        && !settings.stack.tun
        && singbox::config_has_tun(&config_json)
    {
        eprintln!("TUN enabled in merged config (e.g. [singbox].mixin)");
    } else if !tun_enabled
        && singbox::config_has_tun(&config_json)
        && settings.stack.mesh
        && settings
            .mesh
            .as_ref()
            .is_some_and(|m| crate::stack::mesh::is_hub(m))
    {
        eprintln!(
            "mesh hub: ignoring TUN in [singbox].mixin (relay stays SSH-safe)"
        );
    }

    Ok(Prepared {
        config_json,
        settings,
        tun_enabled,
    })
}

/// Rebuild sing-box config immediately before spawn (SSH client IPs, hub route_address).
pub fn refresh_config(
    settings: &Settings,
    _flags: StackFlags,
) -> Result<String> {
    let has_rules = rules::files_present(&settings.singbox_dir());
    let base = singbox::builder::build_config(settings, has_rules)?;
    let config_json = mixin::merge_config(&base, settings)?;
    fs::write(settings.config_path(), &config_json).with_context(|| {
        format!("writing config to {}", settings.config_path().display())
    })?;
    Ok(config_json)
}
