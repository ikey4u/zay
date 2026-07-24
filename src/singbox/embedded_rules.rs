//! Clash-rules baked into the binary at compile time (`build.rs` → `ruleset-embedded/`).

include!(env!("ZAY_EMBEDDED_RULES_RS"));

use std::fs;

use anyhow::{Context, Result};

use super::rules::{self, RULE_SETS};
use crate::settings::Settings;

const EMBEDDED_VERSION: &str = env!("ZAY_EMBEDDED_RULES_VERSION");

/// Extract embedded rule-sets into `<singbox-dir>/ruleset-embedded/`.
///
/// When the embedded [EMBEDDED_VERSION] differs from `ruleset-embedded/version`, all embedded
/// files are replaced. Otherwise only missing or invalid files are written.
pub fn ensure_installed(settings: &Settings) -> Result<()> {
    if settings.stack.no_rules {
        return Ok(());
    }
    let dir = rules::embedded_ruleset_dir(&settings.singbox_dir());
    fs::create_dir_all(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;

    let version_path = dir.join("version");
    let installed = fs::read_to_string(&version_path)
        .ok()
        .map(|s| s.trim().to_string());
    let version_changed = installed.as_deref() != Some(EMBEDDED_VERSION);

    let mut written = 0usize;
    for (id, json) in EMBEDDED_RULE_SETS {
        if !RULE_SETS.iter().any(|def| def.id == *id) {
            continue;
        }
        let path = rules::embedded_rule_path(&settings.singbox_dir(), id);
        if version_changed || !rules::rule_file_valid(&path) {
            fs::write(&path, json)
                .with_context(|| format!("writing embedded rule-set {id}"))?;
            written += 1;
        }
    }

    let geoip_path = dir.join("geoip-cn.srs");
    if version_changed || !binary_ruleset_srs_valid(&geoip_path) {
        fs::write(&geoip_path, EMBEDDED_GEOIP_CN_SRS)
            .with_context(|| format!("writing {}", geoip_path.display()))?;
        written += 1;
    }

    let geosite_path = dir.join("geosite-cn.srs");
    if version_changed || !binary_ruleset_srs_valid(&geosite_path) {
        fs::write(&geosite_path, EMBEDDED_GEOSITE_CN_SRS)
            .with_context(|| format!("writing {}", geosite_path.display()))?;
        written += 1;
    }

    if version_changed {
        fs::write(&version_path, EMBEDDED_VERSION)
            .with_context(|| format!("writing {}", version_path.display()))?;
        eprintln!(
            "clash-rules: refreshed ruleset-embedded ({EMBEDDED_VERSION}, {written} file(s))"
        );
    } else if written > 0 {
        eprintln!(
            "clash-rules: filled {written} missing embedded rule-set(s) ({EMBEDDED_VERSION})"
        );
    }

    Ok(())
}

fn binary_ruleset_srs_valid(path: &std::path::Path) -> bool {
    std::fs::metadata(path).ok().is_some_and(|m| m.len() > 64)
}
