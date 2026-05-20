pub mod proxy;

use anyhow::{Context, Result};

use crate::{
    Cli, assets,
    mihomo::{self, config, geo, rules},
    settings::{self as zay_settings, Settings},
};

pub struct Prepared {
    pub config_yaml: String,
    pub settings: Settings,
    /// True when TUN is on in settings or the merged config (e.g. via mixin).
    pub tun_enabled: bool,
}

pub fn prepare(cli: &Cli) -> Result<Prepared> {
    let settings = zay_settings::resolve(cli)?;
    eprintln!(
        "mihomo {} (config schema {})",
        config::MIHOMO_VERSION,
        config::CONFIG_TAG
    );
    eprintln!(
        "external-controller {} (reload after geo/rules download)",
        settings.external_controller
    );

    std::fs::create_dir_all(&settings.data_dir).with_context(|| {
        format!("creating data dir {}", settings.data_dir.display())
    })?;
    std::fs::create_dir_all(settings.mihomo_dir()).with_context(|| {
        format!("creating {}", settings.mihomo_dir().display())
    })?;
    std::fs::create_dir_all(settings.mihomo_dir().join("providers"))
        .with_context(|| {
            format!(
                "creating {}",
                settings.mihomo_dir().join("providers").display()
            )
        })?;
    std::fs::create_dir_all(rules::ruleset_dir(&settings.mihomo_dir()))
        .with_context(|| {
            format!(
                "creating {}",
                rules::ruleset_dir(&settings.mihomo_dir()).display()
            )
        })?;
    assets::ensure_config_template(&settings.mihomo_dir())?;

    zay_settings::cleanup_stale_subscription_cache(
        &settings.mihomo_dir(),
        settings.subscriptions.len(),
    );
    zay_settings::ensure_default_mixin(&settings)?;

    let has_rules = rules::files_present(&settings.mihomo_dir());
    if !has_rules {
        eprintln!("clash-rules missing; will download via proxy after startup");
    }

    let (has_mmdb, has_geosite) = geo::files_present(&settings.mihomo_dir());
    if !has_mmdb || !has_geosite {
        eprintln!("geo rules missing; will download after proxy is ready");
    }

    if let Some(bp) = &settings.bootstrap_proxy {
        eprintln!("bootstrap proxy \"{}\" will fetch subscription", bp.name);
    }

    let config_yaml = mihomo::finalize_config(
        &settings,
        mihomo::build_config(&settings, has_mmdb, has_geosite, has_rules)?,
    )?;

    let config_path = settings.config_path();
    std::fs::write(&config_path, &config_yaml).with_context(|| {
        format!("writing config to {}", config_path.display())
    })?;
    eprintln!("config → {}", config_path.display());

    let tun_enabled = settings.tun || mihomo::config_has_tun(&config_yaml);
    if tun_enabled && !settings.tun {
        eprintln!("TUN enabled in merged config (e.g. mixin.yaml)");
    }

    Ok(Prepared {
        config_yaml,
        settings,
        tun_enabled,
    })
}
