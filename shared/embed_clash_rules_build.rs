// Shared by root `build.rs` and `client/ios/Rust/zay-ios/build.rs`.
// Requires `include!("…/clash_rules_convert.rs")` in the same crate for
// `loyalsoldier_yaml_to_singbox_source` / `is_valid_singbox_ruleset_json`.

use std::{
    env, fs,
    io::Read,
    path::Path,
};

/// Keep in sync with `src/singbox/rules.rs` `RULE_SETS`.
pub const CLASH_RULE_SET_IDS: &[&str] = &[
    "applications",
    "reject",
    "icloud",
    "apple",
    "google",
    "proxy",
    "direct",
    "private",
    "gfw",
    "telegramcidr",
    "cncidr",
    "lancidr",
];

const CLASH_RULES_SOURCES: &[&str] = &[
    "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release",
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release",
];

const CLASH_RULES_STAMP_KEY: &str =
    "loyalsoldier-clash-rules@release+geoip-cn+geosite-cn+ruleset-v4+suffix-apex";

const GEOIP_CN_RULESET_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
    "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/rule-set/geoip-cn.srs",
];

const GEOSITE_CN_RULESET_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/rule-set/geosite-cn.srs",
];

pub fn embed_clash_rules(out_dir: &Path) {
    println!("cargo:rerun-if-changed=shared/clash_rules_convert.rs");
    embed_clash_rules_inner(out_dir).unwrap_or_else(|e| {
        panic!("failed to embed Loyalsoldier clash-rules at build time: {e}");
    });
}

fn embed_clash_rules_inner(out_dir: &Path) -> Result<(), String> {
    let rules_dir = out_dir.join("embedded-clash-rules");
    let stamp_path = out_dir.join("clash-rules.stamp");
    if clash_rules_stamp_matches(&stamp_path, CLASH_RULES_STAMP_KEY)
        && all_embedded_clash_rules_present(&rules_dir)
        && geoip_cn_srs_valid(&rules_dir.join("geoip-cn.srs"))
        && geosite_cn_srs_valid(&rules_dir.join("geosite-cn.srs"))
    {
        return emit_embedded_clash_rules_rs(out_dir);
    }

    fs::create_dir_all(&rules_dir).map_err(|e| e.to_string())?;
    for id in CLASH_RULE_SET_IDS {
        let raw = download_clash_rule_txt(id)?;
        let json = loyalsoldier_yaml_to_singbox_source(&raw)
            .map_err(|e| format!("convert clash-rules {id}: {e}"))?;
        if !is_valid_singbox_ruleset_json(&json) {
            return Err(format!("invalid sing-box rule-set JSON for {id}"));
        }
        let dest = rules_dir.join(format!("{id}.json"));
        fs::write(&dest, json).map_err(|e| e.to_string())?;
        eprintln!("cargo:warning=zay: embedded clash-rules {id}");
    }
    let geoip_dest = rules_dir.join("geoip-cn.srs");
    fs::write(
        &geoip_dest,
        download_binary_ruleset("geoip-cn", GEOIP_CN_RULESET_URLS)?,
    )
    .map_err(|e| e.to_string())?;
    eprintln!("cargo:warning=zay: embedded geoip-cn.srs");
    let geosite_dest = rules_dir.join("geosite-cn.srs");
    fs::write(
        &geosite_dest,
        download_binary_ruleset("geosite-cn", GEOSITE_CN_RULESET_URLS)?,
    )
    .map_err(|e| e.to_string())?;
    eprintln!("cargo:warning=zay: embedded geosite-cn.srs");
    write_clash_rules_stamp(&stamp_path, CLASH_RULES_STAMP_KEY)?;
    emit_embedded_clash_rules_rs(out_dir)
}

fn geoip_cn_srs_valid(path: &Path) -> bool {
    fs::metadata(path).ok().is_some_and(|m| m.len() > 64)
}

fn geosite_cn_srs_valid(path: &Path) -> bool {
    fs::metadata(path).ok().is_some_and(|m| m.len() > 64)
}

fn download_binary_ruleset(name: &str, urls: &[&str]) -> Result<Vec<u8>, String> {
    let mut last_err = String::from("no sources");
    for url in urls {
        match fetch_clash_rules_bytes(url) {
            Ok(body) if body.len() > 64 => return Ok(body),
            Ok(_) => last_err = format!("{url}: empty body"),
            Err(e) => last_err = format!("{url}: {e}"),
        }
    }
    Err(format!("failed to download {name}.srs: {last_err}"))
}

fn fetch_clash_rules_bytes(url: &str) -> Result<Vec<u8>, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(120))
        .build();
    let resp = agent.get(url).call().map_err(|e| e.to_string())?;
    if resp.status() != 200 {
        return Err(format!("HTTP {}", resp.status()));
    }
    let mut body = Vec::new();
    resp.into_reader()
        .read_to_end(&mut body)
        .map_err(|e| e.to_string())?;
    Ok(body)
}

fn all_embedded_clash_rules_present(rules_dir: &Path) -> bool {
    CLASH_RULE_SET_IDS.iter().all(|id| {
        let path = rules_dir.join(format!("{id}.json"));
        path.is_file()
            && fs::read_to_string(&path)
                .ok()
                .is_some_and(|raw| is_valid_singbox_ruleset_json(&raw))
    })
}

fn emit_embedded_clash_rules_rs(out_dir: &Path) -> Result<(), String> {
    let pkg_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0".into());
    let embedded_version = format!("{CLASH_RULES_STAMP_KEY}+zay-{pkg_version}");
    println!("cargo:rustc-env=ZAY_EMBEDDED_RULES_VERSION={embedded_version}");

    let path = out_dir.join("embedded_clash_rules.rs");
    let mut body = String::from("// Generated by build.rs — do not edit.\n\n");
    body.push_str("pub static EMBEDDED_RULE_SETS: &[(&str, &str)] = &[\n");
    for id in CLASH_RULE_SET_IDS {
        body.push_str(&format!(
            "    (\"{id}\", include_str!(concat!(env!(\"OUT_DIR\"), \"/embedded-clash-rules/{id}.json\"))),\n"
        ));
    }
    body.push_str("];\n\n");
    body.push_str(
        "pub static EMBEDDED_GEOIP_CN_SRS: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/embedded-clash-rules/geoip-cn.srs\"));\n",
    );
    body.push_str(
        "pub static EMBEDDED_GEOSITE_CN_SRS: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/embedded-clash-rules/geosite-cn.srs\"));\n",
    );
    fs::write(&path, &body).map_err(|e| e.to_string())?;
    println!("cargo:rustc-env=ZAY_EMBEDDED_RULES_RS={}", path.display());
    Ok(())
}

fn download_clash_rule_txt(id: &str) -> Result<String, String> {
    let mut last_err = String::from("no sources");
    for base in CLASH_RULES_SOURCES {
        let url = format!("{base}/{id}.txt");
        match fetch_clash_rules_text(&url) {
            Ok(body) => return Ok(body),
            Err(e) => last_err = format!("{url}: {e}"),
        }
    }
    Err(format!("failed to download clash-rules {id}: {last_err}"))
}

fn fetch_clash_rules_text(url: &str) -> Result<String, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(120))
        .build();
    let resp = agent.get(url).call().map_err(|e| e.to_string())?;
    if resp.status() != 200 {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.into_string().map_err(|e| e.to_string())
}

fn clash_rules_stamp_matches(path: &Path, expected: &str) -> bool {
    fs::read_to_string(path)
        .ok()
        .is_some_and(|s| s.trim() == expected)
}

fn write_clash_rules_stamp(path: &Path, key: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(path, key).map_err(|e| e.to_string())
}
