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

/// Prepare a one-off proxy invocation without loading zay.toml.
pub fn prepare_transient_stack(
    cli: &ProxyOpts,
    flags: StackFlags,
    mesh: Option<zay_settings::MeshConfig>,
) -> Result<Prepared> {
    let settings = zay_settings::resolve_transient_stack(cli, flags, mesh);
    stack::validate(&settings)?;
    prepare_inner(settings, flags)
}

fn prepare_inner(settings: Settings, flags: StackFlags) -> Result<Prepared> {
    eprintln!("sing-box {}", singbox::VERSION);
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
    std::fs::create_dir_all(rules::embedded_ruleset_dir(
        &settings.singbox_dir(),
    ))
    .with_context(|| {
        format!(
            "creating {}",
            rules::embedded_ruleset_dir(&settings.singbox_dir()).display()
        )
    })?;
    std::fs::create_dir_all(rules::download_ruleset_dir(
        &settings.singbox_dir(),
    ))
    .with_context(|| {
        format!(
            "creating {}",
            rules::download_ruleset_dir(&settings.singbox_dir()).display()
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

    if !flags.no_rules {
        rules::ensure_embedded_rules(&settings)?;
    }
    let has_rules = rules::files_present(&settings.singbox_dir());
    rules::log_routing_mode(&settings, has_rules);
    if flags.no_rules {
        if has_rules {
            eprintln!(
                "clash-rules: using cached rule-sets (--no-rules, no network update)"
            );
        } else {
            eprintln!(
                "clash-rules skipped (--no-rules); using simple fallback routes"
            );
        }
    } else if has_rules {
        log_clash_rules_layout(&settings);
        rules::log_singbox_rule_sets(&settings);
        if !settings.subscriptions.is_empty()
            || settings.bootstrap_proxy.is_some()
        {
            eprintln!(
                "clash-rules: will refresh {}/ via proxy after startup",
                rules::DOWNLOAD_RULESET_DIR
            );
        }
    }

    if let Some(bp) = &settings.bootstrap_proxy {
        eprintln!("bootstrap proxy \"{}\" will fetch subscription", bp.name);
    }

    let effective_has_rules =
        has_rules && !rules::rule_set_definitions(&settings).is_empty();
    if has_rules && !effective_has_rules {
        eprintln!(
            "warn: clash-rules on disk incomplete — rebuild with `cargo build` and restart"
        );
    }
    let base = singbox::build_config(&settings, effective_has_rules)?;
    let config_json = mixin::merge_config(&base, &settings)?;

    let config_path = settings.config_path();
    std::fs::write(&config_path, &config_json).with_context(|| {
        format!("writing config to {}", config_path.display())
    })?;
    eprintln!("config → {}", config_path.display());

    let tun_enabled = singbox::tun_route::singbox_tun_enabled(&settings);
    if tun_enabled
        && !settings.tun
        && !settings.stack.tun
        && singbox::config_has_tun(&config_json)
    {
        eprintln!("TUN enabled in merged config (e.g. [singbox].mixin)");
    } else if !tun_enabled
        && singbox::config_has_tun(&config_json)
        && settings.mesh_is_relay()
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

fn log_clash_rules_layout(settings: &Settings) {
    let dir = settings.singbox_dir();
    let downloaded = rules::RULE_SETS
        .iter()
        .filter(|def| {
            rules::rule_file_valid(&rules::download_rule_path(&dir, def.id))
        })
        .count();
    eprintln!(
        "clash-rules: {}/ (embedded) + {}/ (runtime, {downloaded} present); config uses download when both exist",
        rules::EMBEDDED_RULESET_DIR,
        rules::DOWNLOAD_RULESET_DIR,
    );
}

/// Rebuild sing-box config immediately before spawn (SSH client IPs, hub route_address).
pub fn refresh_config(
    settings: &Settings,
    flags: StackFlags,
) -> Result<String> {
    if !flags.no_rules {
        rules::ensure_embedded_rules(settings)?;
    }
    let has_rules = rules::files_present(&settings.singbox_dir())
        && !rules::rule_set_definitions(settings).is_empty();
    let base = singbox::builder::build_config(settings, has_rules)?;
    let config_json = mixin::merge_config(&base, settings)?;
    fs::write(settings.config_path(), &config_json).with_context(|| {
        format!("writing config to {}", settings.config_path().display())
    })?;
    Ok(config_json)
}
