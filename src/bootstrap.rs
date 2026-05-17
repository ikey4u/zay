use anyhow::{Context, Result};

use crate::{
    Cli, geo, mihomo,
    settings::{self as zay_settings, Settings},
};

pub struct Prepared {
    pub config_yaml: String,
    pub settings: Settings,
    /// True when TUN is on in settings or the merged config (e.g. via mixin).
    pub tun_enabled: bool,
}

pub fn prepare(cli: &Cli) -> Result<Prepared> {
    let settings = zay_settings::resolve(&cli.subscription, cli)?;

    std::fs::create_dir_all(&settings.data_dir).with_context(|| {
        format!("creating data dir {}", settings.data_dir.display())
    })?;
    std::fs::create_dir_all(settings.data_dir.join("providers")).with_context(
        || {
            format!(
                "creating {}",
                settings.data_dir.join("providers").display()
            )
        },
    )?;

    zay_settings::cleanup_stale_subscription_cache(&settings.data_dir);
    zay_settings::ensure_default_mixin(&settings)?;

    let (has_mmdb, has_geosite) = geo::files_present(&settings.data_dir);
    if !has_mmdb || !has_geosite {
        eprintln!("geo rules missing; will download after proxy is ready");
    }

    let config_yaml = mihomo::finalize_config(
        &settings,
        mihomo::build_config(&settings, has_mmdb, has_geosite),
    )?;

    let config_path = settings.data_dir.join("config.yaml");
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
