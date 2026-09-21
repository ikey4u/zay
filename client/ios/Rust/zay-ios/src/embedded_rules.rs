//! Extract compile-time embedded clash-rules into the singbox working directory.

include!(env!("ZAY_EMBEDDED_RULES_RS"));

use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde_json::json;

use crate::rules::{
    EMBEDDED_RULESET_DIR, RULE_SETS, never_on_ios, rule_file_valid,
};

const EMBEDDED_VERSION: &str = env!("ZAY_EMBEDDED_RULES_VERSION");

/// Write `ruleset-embedded/` under the embedded runtime's `working_dir`.
pub fn ensure_installed(working_dir: &Path) -> Result<()> {
    let dir = working_dir.join(EMBEDDED_RULESET_DIR);
    fs::create_dir_all(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;

    let version_path = dir.join("version");
    let installed = fs::read_to_string(&version_path)
        .ok()
        .map(|s| s.trim().to_string());
    // `direct` and `reject` are precompiled by build.rs. Keeping their multi-MB
    // source documents out of the extension avoids source-parser memory spikes.
    let stamp = format!("{EMBEDDED_VERSION}+ios-srs-v1");
    let version_changed = installed.as_deref() != Some(stamp.as_str());

    // Packet Tunnel cannot match by process — drop leftover applications sets.
    let unused_id = "applications";
    let unused_path = dir.join(format!("{unused_id}.json"));
    if unused_path.is_file() {
        let _ = fs::remove_file(&unused_path);
        tracing::info!("clash-rules: removed unused set {unused_id}");
    }

    let mut written = 0usize;
    for (id, json) in EMBEDDED_RULE_SETS {
        if !RULE_SETS.iter().any(|def| def.id == *id) {
            continue;
        }
        if never_on_ios(id) {
            continue;
        }
        if matches!(*id, "direct" | "reject") {
            let legacy = dir.join(format!("{id}.json"));
            if legacy.is_file() {
                let _ = fs::remove_file(legacy);
            }
            continue;
        }
        let path = dir.join(format!("{id}.json"));
        if version_changed || !rule_file_valid(&path) {
            fs::write(&path, json)
                .with_context(|| format!("writing embedded rule-set {id}"))?;
            written += 1;
        }
    }

    for (id, binary) in [
        ("direct", EMBEDDED_DIRECT_SRS),
        ("reject", EMBEDDED_REJECT_SRS),
    ] {
        let path = dir.join(format!("{id}.srs"));
        if version_changed || !binary_ok(&path) {
            fs::write(&path, binary)
                .with_context(|| format!("writing embedded rule-set {id}"))?;
            written += 1;
        }
    }

    let geoip_path = dir.join("geoip-cn.srs");
    if version_changed || !binary_ok(&geoip_path) {
        fs::write(&geoip_path, EMBEDDED_GEOIP_CN_SRS)
            .with_context(|| format!("writing {}", geoip_path.display()))?;
        written += 1;
    }

    let geosite_path = dir.join("geosite-cn.srs");
    if version_changed || !binary_ok(&geosite_path) {
        fs::write(&geosite_path, EMBEDDED_GEOSITE_CN_SRS)
            .with_context(|| format!("writing {}", geosite_path.display()))?;
        written += 1;
    }

    if version_changed {
        fs::write(&version_path, &stamp)
            .with_context(|| format!("writing {}", version_path.display()))?;
        tracing::info!(
            "clash-rules: refreshed {EMBEDDED_RULESET_DIR} ({stamp}, {written} file(s))"
        );
    } else if written > 0 {
        tracing::info!(
            "clash-rules: filled {written} missing embedded rule-set(s) ({stamp})"
        );
    } else {
        tracing::info!(
            "clash-rules: {EMBEDDED_RULESET_DIR} up to date ({stamp})"
        );
    }

    Ok(())
}

/// Overview of embedded rule-sets for Settings UI.
pub fn info_json(working_dir: Option<&Path>) -> String {
    let mut sets = Vec::new();
    for (id, json) in EMBEDDED_RULE_SETS {
        let skipped = never_on_ios(id);
        let heavy = matches!(*id, "reject" | "direct");
        let bytes = match *id {
            "direct" => EMBEDDED_DIRECT_SRS.len(),
            "reject" => EMBEDDED_REJECT_SRS.len(),
            _ => json.len(),
        };
        let on_disk = working_dir
            .map(|d| {
                let extension = if heavy { "srs" } else { "json" };
                let p = d
                    .join(EMBEDDED_RULESET_DIR)
                    .join(format!("{id}.{extension}"));
                if heavy {
                    binary_ok(&p)
                } else {
                    rule_file_valid(&p)
                }
            })
            .unwrap_or(false);
        sets.push(json!({
            "id": id,
            "bytes": bytes,
            "installed": on_disk,
            "skipped": skipped,
            "skip_reason": if skipped {
                "ios-process"
            } else {
                ""
            },
            "kind": if heavy { "binary" } else { "source" }
        }));
    }
    sets.push(json!({
        "id": "geoip-cn",
        "bytes": EMBEDDED_GEOIP_CN_SRS.len(),
        "installed": working_dir
            .map(|d| binary_ok(&d.join(EMBEDDED_RULESET_DIR).join("geoip-cn.srs")))
            .unwrap_or(false),
        "kind": "binary"
    }));
    sets.push(json!({
        "id": "geosite-cn",
        "bytes": EMBEDDED_GEOSITE_CN_SRS.len(),
        "installed": working_dir
            .map(|d| binary_ok(&d.join(EMBEDDED_RULESET_DIR).join("geosite-cn.srs")))
            .unwrap_or(false),
        "kind": "binary"
    }));

    json!({
        "version": EMBEDDED_VERSION,
        "directory": EMBEDDED_RULESET_DIR,
        "source": "Loyalsoldier clash-rules + sing-geoip/geosite CN",
        "mode": "blacklist",
        "sets": sets,
    })
    .to_string()
}

fn binary_ok(path: &Path) -> bool {
    fs::metadata(path).ok().is_some_and(|m| m.len() > 64)
}
