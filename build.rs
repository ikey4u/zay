use std::{
    env,
    fs::{self, File},
    io::{Read, Write, copy},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

include!("shared/clash_rules_convert.rs");

/// Pinned Mihomo release embedded by Zay (must match `mihomo::config` types).
const PINNED_MIHOMO_VERSION: &str = "v1.19.25";
/// Pinned sing-box release for `zay stack` on the singbox branch.
const PINNED_SINGBOX_VERSION: &str = "v1.13.12";
const SINGBOX_RELEASE_BASE: &str =
    "https://github.com/SagerNet/sing-box/releases/download";
const CONFIG_DOCS_URL: &str = "https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.25/docs/config.yaml";
const RELEASE_BASE: &str =
    "https://github.com/MetaCubeX/mihomo/releases/download";
const WINPCAP_DEV_PACK_URL: &str =
    "https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip";
const WINPCAP_DEV_PACK_SHA256: &str =
    "ea799cf2f26e4afb1892938070fd2b1ca37ce5cf75fec4349247df12b784edbd";
const WINPCAP_INSTALLER_URL: &str =
    "https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe";
const WINPCAP_INSTALLER_SHA256: &str =
    "fc4623b113a1f603c0d9ad5f83130bd6de1c62b973be9892305132389c8588de";
const WINTUN_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";
const WINTUN_SHA256: &str =
    "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";
const WINDIVERT_URL: &str = "https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";
const WINDIVERT_SHA256: &str =
    "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15";

/// Strip zig/cargo glibc suffix (e.g. `.2.17`) so Mihomo artifact lookup matches `*-linux-gnu`.
fn normalize_target(target: &str) -> &str {
    target
        .split_once('.')
        .map(|(base, _)| base)
        .unwrap_or(target)
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TARGET");

    let target_raw = env::var("TARGET").expect("TARGET not set by cargo");
    let target = normalize_target(&target_raw);
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    fetch_config_docs_template(&out_dir);
    prepare_windows_runtime(&out_dir, target);

    embed_mihomo(&out_dir, target);
    embed_singbox(&out_dir, target);
    embed_clash_rules(&out_dir);
    embed_webui(&out_dir);
}

/// Keep in sync with `src/singbox/rules.rs` `RULE_SETS`.
const CLASH_RULE_SET_IDS: &[&str] = &[
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
    "loyalsoldier-clash-rules@release+geoip-cn+geosite-cn+ruleset-v4";

const GEOIP_CN_RULESET_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
    "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/rule-set/geoip-cn.srs",
];

const GEOSITE_CN_RULESET_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/rule-set/geosite-cn.srs",
];

fn embed_clash_rules(out_dir: &Path) {
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

fn download_binary_ruleset(
    name: &str,
    urls: &[&str],
) -> Result<Vec<u8>, String> {
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
    let pkg_version =
        env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0".into());
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

fn embed_mihomo(out_dir: &Path, target: &str) {
    let (artifact, ext) =
        mihomo_artifact_for_target(target).unwrap_or_else(|| {
            panic!("unsupported build target for embedded Mihomo: {target}")
        });

    let version = PINNED_MIHOMO_VERSION.to_string();
    let exe_name = if target.contains("windows") {
        "mihomo.exe"
    } else {
        "mihomo"
    };
    let embed_path = out_dir.join(exe_name);
    let stamp_path = out_dir.join("mihomo.stamp");

    if stamp_matches(&stamp_path, &version, target) && embed_path.is_file() {
        emit_mihomo_rustc_env(&embed_path, &version);
        return;
    }

    let archive_path = out_dir.join(format!("{artifact}-{version}.{ext}"));
    let url = format!("{RELEASE_BASE}/{version}/{artifact}-{version}.{ext}");

    eprintln!("cargo:warning=zay: downloading Mihomo {version} for {target}");
    download(&url, &archive_path).unwrap_or_else(|e| {
        panic!("failed to download Mihomo from {url}: {e}");
    });

    extract(&archive_path, ext, &embed_path, artifact).unwrap_or_else(|e| {
        panic!(
            "failed to extract Mihomo archive {}: {e}",
            archive_path.display()
        );
    });

    let _ = fs::remove_file(&archive_path);
    chmod_executable(&embed_path);
    write_stamp(&stamp_path, &version, target).expect("write mihomo.stamp");
    emit_mihomo_rustc_env(&embed_path, &version);
}

fn embed_singbox(out_dir: &Path, target: &str) {
    let version_tag = PINNED_SINGBOX_VERSION.trim_start_matches('v');
    let (suffix, ext) =
        singbox_artifact_for_target(target).unwrap_or_else(|| {
            panic!("unsupported build target for embedded sing-box: {target}")
        });
    let artifact = format!("sing-box-{version_tag}-{suffix}");
    let version = PINNED_SINGBOX_VERSION;
    let exe_name = if target.contains("windows") {
        "sing-box.exe"
    } else {
        "sing-box"
    };
    let embed_path = out_dir.join(exe_name);
    let stamp_path = out_dir.join("singbox.stamp");

    if stamp_matches(&stamp_path, version, target) && embed_path.is_file() {
        emit_singbox_rustc_env(&embed_path, version);
        return;
    }

    let archive_path = out_dir.join(format!("{artifact}.{ext}"));
    let url = format!("{SINGBOX_RELEASE_BASE}/{version}/{artifact}.{ext}");

    eprintln!("cargo:warning=zay: downloading sing-box {version} for {target}");
    download(&url, &archive_path).unwrap_or_else(|e| {
        panic!("failed to download sing-box from {url}: {e}");
    });

    extract_singbox(&archive_path, ext, &embed_path, &artifact).unwrap_or_else(
        |e| {
            panic!(
                "failed to extract sing-box archive {}: {e}",
                archive_path.display()
            );
        },
    );

    let _ = fs::remove_file(&archive_path);
    chmod_executable(&embed_path);
    write_stamp(&stamp_path, version, target).expect("write singbox.stamp");
    emit_singbox_rustc_env(&embed_path, version);
}

#[cfg(unix)]
fn chmod_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .unwrap_or_else(|e| panic!("metadata for {}: {e}", path.display()))
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)
        .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
}

#[cfg(not(unix))]
fn chmod_executable(_path: &Path) {}

fn fetch_config_docs_template(out_dir: &Path) {
    let dest = out_dir.join("mihomo-docs-config.yaml");
    let body = fetch_bytes(CONFIG_DOCS_URL).unwrap_or_else(|e| {
        panic!("failed to download Mihomo config template from {CONFIG_DOCS_URL}: {e}");
    });
    fs::write(&dest, &body)
        .unwrap_or_else(|e| panic!("write {}: {e}", dest.display()));
    println!("cargo:rerun-if-changed={}", dest.display());
    println!(
        "cargo:rustc-env=MIHOMO_CONFIG_TAG={}",
        PINNED_MIHOMO_VERSION
    );
}

fn prepare_windows_runtime(out_dir: &Path, target: &str) {
    if target != "x86_64-pc-windows-gnu" {
        return;
    }

    let runtime_dir = out_dir.join("windows-runtime");
    fs::create_dir_all(&runtime_dir)
        .unwrap_or_else(|e| panic!("create {}: {e}", runtime_dir.display()));

    prepare_winpcap(out_dir, &runtime_dir);
    prepare_wintun(out_dir, &runtime_dir);
    prepare_windivert(out_dir, &runtime_dir);
}

fn prepare_winpcap(out_dir: &Path, runtime_dir: &Path) {
    let base_dir = out_dir.join("winpcap");
    let lib_dir = base_dir.join("lib");
    fs::create_dir_all(&lib_dir)
        .unwrap_or_else(|e| panic!("create {}: {e}", lib_dir.display()));

    let packet_lib = lib_dir.join("Packet.lib");
    let packet_a = lib_dir.join("x86").join("libpacket.a");
    if !packet_lib.is_file() || !packet_a.is_file() {
        let archive = base_dir.join("WpdPack_4_1_2.zip");
        download_if_missing(
            WINPCAP_DEV_PACK_URL,
            WINPCAP_DEV_PACK_SHA256,
            &archive,
        );
        if !packet_lib.is_file() {
            extract_zip_entry(
                &archive,
                "WpdPack/Lib/x64/Packet.lib",
                &packet_lib,
            )
            .unwrap_or_else(|e| panic!("extract WinPcap Packet.lib: {e}"));
        }

        if !packet_a.is_file() {
            if let Some(parent) = packet_a.parent() {
                fs::create_dir_all(parent).unwrap_or_else(|e| {
                    panic!("create {}: {e}", parent.display())
                });
            }
            extract_zip_entry(&archive, "WpdPack/Lib/libpacket.a", &packet_a)
                .unwrap_or_else(|e| panic!("extract WinPcap libpacket.a: {e}"));
        }
    }

    let packet_dll = runtime_dir.join("Packet.dll");
    if !packet_dll.is_file() || ensure_pe_x86_64(&packet_dll).is_err() {
        let installer = base_dir.join("WinPcap_4_1_3.exe");
        download_if_missing(
            WINPCAP_INSTALLER_URL,
            WINPCAP_INSTALLER_SHA256,
            &installer,
        );
        extract_winpcap_packet_dll(&installer, &packet_dll)
            .unwrap_or_else(|e| panic!("extract WinPcap Packet.dll: {e}"));
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!(
        "cargo:rustc-env=WINPCAP_PACKET_DLL={}",
        packet_dll.display()
    );
}

fn prepare_wintun(out_dir: &Path, runtime_dir: &Path) {
    let wintun_dll = runtime_dir.join("wintun.dll");
    if wintun_dll.is_file() && ensure_pe_x86_64(&wintun_dll).is_ok() {
        return;
    }

    let base_dir = out_dir.join("wintun");
    let archive = base_dir.join("wintun-0.14.1.zip");
    download_if_missing(WINTUN_URL, WINTUN_SHA256, &archive);
    extract_zip_entry(&archive, "wintun/bin/amd64/wintun.dll", &wintun_dll)
        .unwrap_or_else(|e| panic!("extract Wintun runtime: {e}"));
    ensure_pe_x86_64(&wintun_dll)
        .unwrap_or_else(|e| panic!("verify Wintun runtime: {e}"));
}

fn prepare_windivert(out_dir: &Path, runtime_dir: &Path) {
    let windivert_sys = runtime_dir.join("WinDivert64.sys");
    if windivert_sys.is_file() && ensure_pe_x86_64(&windivert_sys).is_ok() {
        return;
    }

    let base_dir = out_dir.join("windivert");
    let archive = base_dir.join("WinDivert-2.2.2-A.zip");
    download_if_missing(WINDIVERT_URL, WINDIVERT_SHA256, &archive);
    extract_zip_entry(
        &archive,
        "WinDivert-2.2.2-A/x64/WinDivert64.sys",
        &windivert_sys,
    )
    .unwrap_or_else(|e| panic!("extract WinDivert runtime: {e}"));
    ensure_pe_x86_64(&windivert_sys)
        .unwrap_or_else(|e| panic!("verify WinDivert runtime: {e}"));
}

fn download_if_missing(url: &str, sha256: &str, dest: &Path) {
    if dest.is_file()
        && fs::metadata(dest).is_ok_and(|m| m.len() > 0)
        && verify_sha256(dest, sha256).is_ok()
    {
        return;
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("create {}: {e}", parent.display()));
    }
    download(url, dest).unwrap_or_else(|e| panic!("download {url}: {e}"));
    verify_sha256(dest, sha256)
        .unwrap_or_else(|e| panic!("verify {url} checksum: {e}"));
}

fn verify_sha256(path: &Path, expected: &str) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let actual = format!("{:x}", Sha256::digest(&bytes));
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{} sha256 mismatch: expected {expected}, got {actual}",
            path.display()
        ))
    }
}

fn extract_zip_entry(
    archive_path: &Path,
    entry_name: &str,
    dest: &Path,
) -> Result<(), String> {
    let file = File::open(archive_path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let mut entry = zip.by_name(entry_name).map_err(|e| e.to_string())?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut output = File::create(dest).map_err(|e| e.to_string())?;
    copy(&mut entry, &mut output).map_err(|e| e.to_string())?;
    Ok(())
}

fn extract_winpcap_packet_dll(
    installer: &Path,
    dest: &Path,
) -> Result<(), String> {
    let bytes = fs::read(installer).map_err(|e| e.to_string())?;
    let nsis = nsis::NsisInstaller::from_bytes(&bytes)
        .map_err(|e| format!("parse NSIS installer: {e}"))?;
    let mut candidates = Vec::new();

    for file in nsis.files() {
        let file = file.map_err(|e| e.to_string())?;
        let name = file.name().map_err(|e| e.to_string())?.to_string();
        let normalized = name.replace('\\', "/").to_ascii_lowercase();
        if !normalized.ends_with("/packet.dll")
            && normalized.as_str() != "packet.dll"
        {
            continue;
        }

        let content = file.decompress().map_err(|e| e.to_string())?;
        if is_pe_x86_64_bytes(&content) {
            candidates.push((content.len(), content));
        }
    }
    candidates.sort_by_key(|(size, _)| *size);
    let Some((_, content)) = candidates.pop() else {
        return Err("no x86_64 Packet.dll found in WinPcap installer".into());
    };
    fs::write(dest, content).map_err(|e| e.to_string())?;
    Ok(())
}

fn is_pe_x86_64_bytes(buf: &[u8]) -> bool {
    if buf.len() < 0x40 || &buf[0..2] != b"MZ" {
        return false;
    }
    let pe_offset =
        u32::from_le_bytes([buf[0x3c], buf[0x3d], buf[0x3e], buf[0x3f]])
            as usize;
    if pe_offset + 6 > buf.len() || &buf[pe_offset..pe_offset + 4] != b"PE\0\0"
    {
        return false;
    }
    let machine = u16::from_le_bytes([buf[pe_offset + 4], buf[pe_offset + 5]]);
    machine == 0x8664
}

fn ensure_pe_x86_64(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if is_pe_x86_64_bytes(&bytes) {
        Ok(())
    } else {
        Err(format!("{} is not an x86_64 PE file", path.display()))
    }
}

fn emit_mihomo_rustc_env(embed_path: &Path, version: &str) {
    println!(
        "cargo:rustc-env=MIHOMO_EMBED={}",
        embed_path.to_string_lossy()
    );
    println!("cargo:rustc-env=MIHOMO_VERSION={version}");
}

fn emit_singbox_rustc_env(embed_path: &Path, version: &str) {
    println!(
        "cargo:rustc-env=SINGBOX_EMBED={}",
        embed_path.to_string_lossy()
    );
    println!("cargo:rustc-env=SINGBOX_VERSION={version}");
}

fn extract_singbox(
    archive: &Path,
    ext: &str,
    dest: &Path,
    artifact: &str,
) -> Result<(), String> {
    match ext {
        "tar.gz" => extract_tar_gz(archive, dest),
        "zip" => extract_zip(archive, dest, artifact),
        other => Err(format!("unsupported archive extension: {other}")),
    }
}

fn extract_tar_gz(archive_path: &Path, dest: &Path) -> Result<(), String> {
    let file = File::open(archive_path).map_err(|e| e.to_string())?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(decoder);
    for entry in tar.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path().map_err(|e| e.to_string())?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name == "sing-box" || name == "sing-box.exe" {
            let mut output = File::create(dest).map_err(|e| e.to_string())?;
            copy(&mut entry, &mut output).map_err(|e| e.to_string())?;
            return Ok(());
        }
    }
    Err(format!(
        "sing-box binary not found in {}",
        archive_path.display()
    ))
}

fn stamp_matches(stamp_path: &Path, version: &str, target: &str) -> bool {
    fs::read_to_string(stamp_path)
        .map(|s| s.trim() == format!("{version}\n{target}"))
        .unwrap_or(false)
}

fn write_stamp(
    stamp_path: &Path,
    version: &str,
    target: &str,
) -> std::io::Result<()> {
    let mut f = File::create(stamp_path)?;
    writeln!(f, "{version}")?;
    writeln!(f, "{target}")?;
    Ok(())
}

fn singbox_artifact_for_target(
    target: &str,
) -> Option<(&'static str, &'static str)> {
    Some(match target {
        "aarch64-apple-darwin" => ("darwin-arm64", "tar.gz"),
        "x86_64-apple-darwin" => ("darwin-amd64", "tar.gz"),
        "aarch64-unknown-linux-gnu" | "aarch64-unknown-linux-musl" => {
            ("linux-arm64", "tar.gz")
        }
        "x86_64-unknown-linux-gnu" | "x86_64-unknown-linux-musl" => {
            ("linux-amd64", "tar.gz")
        }
        "i686-unknown-linux-gnu" => ("linux-386", "tar.gz"),
        "armv7-unknown-linux-gnueabihf" => ("linux-armv7", "tar.gz"),
        "riscv64gc-unknown-linux-gnu" => ("linux-riscv64", "tar.gz"),
        "loongarch64-unknown-linux-gnu" => ("linux-loong64", "tar.gz"),
        "x86_64-pc-windows-msvc" | "x86_64-pc-windows-gnu" => {
            ("windows-amd64", "zip")
        }
        "i686-pc-windows-msvc" => ("windows-386", "zip"),
        "aarch64-pc-windows-msvc" => ("windows-arm64", "zip"),
        _ => return None,
    })
}

fn mihomo_artifact_for_target(
    target: &str,
) -> Option<(&'static str, &'static str)> {
    Some(match target {
        "aarch64-apple-darwin" => ("mihomo-darwin-arm64-go122", "gz"),
        "x86_64-apple-darwin" => ("mihomo-darwin-amd64-v2-go122", "gz"),
        "aarch64-unknown-linux-gnu" | "aarch64-unknown-linux-musl" => {
            ("mihomo-linux-arm64", "gz")
        }
        "x86_64-unknown-linux-gnu" | "x86_64-unknown-linux-musl" => {
            ("mihomo-linux-amd64-v2", "gz")
        }
        "i686-unknown-linux-gnu" => ("mihomo-linux-386", "gz"),
        "armv7-unknown-linux-gnueabihf" => ("mihomo-linux-armv7", "gz"),
        "riscv64gc-unknown-linux-gnu" => ("mihomo-linux-riscv64", "gz"),
        "loongarch64-unknown-linux-gnu" => ("mihomo-linux-loong64", "gz"),
        "x86_64-pc-windows-msvc"
        | "x86_64-pc-windows-gnu"
        | "i686-pc-windows-msvc"
        | "aarch64-pc-windows-msvc" => (windows_artifact(target)?, "zip"),
        _ => return None,
    })
}

fn windows_artifact(target: &str) -> Option<&'static str> {
    Some(match target {
        "x86_64-pc-windows-msvc" | "x86_64-pc-windows-gnu" => {
            "mihomo-windows-amd64-v2"
        }
        "i686-pc-windows-msvc" => "mihomo-windows-386",
        "aarch64-pc-windows-msvc" => "mihomo-windows-arm64",
        _ => return None,
    })
}

fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
    let response = ureq::get(url)
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let status = response.status();
    if !(200..300).contains(&status) {
        return Err(format!("GET {url}: HTTP {status}"));
    }
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .map_err(|e| format!("read {url}: {e}"))?;
    Ok(body)
}

fn download(url: &str, dest: &Path) -> Result<(), String> {
    let body = fetch_bytes(url)?;
    fs::write(dest, body)
        .map_err(|e| format!("write {}: {e}", dest.display()))?;
    Ok(())
}

fn extract(
    archive: &Path,
    ext: &str,
    dest: &Path,
    artifact: &str,
) -> Result<(), String> {
    match ext {
        "gz" => extract_gz(archive, dest),
        "zip" => extract_zip(archive, dest, artifact),
        other => Err(format!("unsupported archive extension: {other}")),
    }
}

fn extract_gz(archive: &Path, dest: &Path) -> Result<(), String> {
    let input = File::open(archive).map_err(|e| e.to_string())?;
    let mut decoder = flate2::read::GzDecoder::new(input);
    let mut output = File::create(dest).map_err(|e| e.to_string())?;
    copy(&mut decoder, &mut output).map_err(|e| e.to_string())?;
    Ok(())
}

fn extract_zip(
    archive_path: &Path,
    dest: &Path,
    artifact: &str,
) -> Result<(), String> {
    let file = File::open(archive_path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let expected = format!("{artifact}.exe");
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        let name = entry.name().to_string();
        if name.ends_with(".exe") || name == expected {
            let mut output = File::create(dest).map_err(|e| e.to_string())?;
            copy(&mut entry, &mut output).map_err(|e| e.to_string())?;
            return Ok(());
        }
    }
    Err(format!("no .exe found in {}", archive_path.display()))
}

// --- WebUI static embed (webui/dist → OUT_DIR/webui_embed/) ---

fn embed_webui(out_dir: &Path) {
    println!("cargo:rerun-if-changed=webui/dist");
    if let Err(e) = embed_webui_inner(out_dir) {
        let profile = env::var("PROFILE").unwrap_or_default();
        if profile == "release" {
            panic!("failed to embed WebUI: {e}");
        }
        eprintln!("cargo:warning=zay: WebUI embed skipped: {e}");
        emit_empty_webui_rs(out_dir).unwrap_or_else(|e2| {
            panic!("failed to emit empty webui embed: {e2}");
        });
    }
}

fn embed_webui_inner(out_dir: &Path) -> Result<(), String> {
    let dist = PathBuf::from("webui/dist");
    let index = dist.join("index.html");
    if !index.is_file() {
        return Err(
            "webui/dist/index.html missing — run: cd webui && pnpm install && pnpm build"
                .into(),
        );
    }

    let embed_dir = out_dir.join("webui_embed");
    if embed_dir.exists() {
        fs::remove_dir_all(&embed_dir).map_err(|e| e.to_string())?;
    }
    fs::create_dir_all(&embed_dir).map_err(|e| e.to_string())?;

    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    collect_webui_dist(&dist, &dist, &embed_dir, &mut entries)?;

    emit_webui_rs(out_dir, true, &entries)?;
    eprintln!(
        "cargo:warning=zay: embedded WebUI ({} file(s))",
        entries.len()
    );
    Ok(())
}

fn collect_webui_dist(
    root: &Path,
    dir: &Path,
    embed_dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            collect_webui_dist(root, &path, embed_dir, out)?;
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        let url_path = if rel == "index.html" {
            "/index.html".to_string()
        } else {
            format!("/{rel}")
        };
        let dest = embed_dir.join(&rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::copy(&path, &dest).map_err(|e| e.to_string())?;
        out.push((url_path, dest));
    }
    Ok(())
}

fn content_type_for_path(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn emit_webui_rs(
    out_dir: &Path,
    embedded: bool,
    entries: &[(String, PathBuf)],
) -> Result<(), String> {
    let path = out_dir.join("webui_embed.rs");
    let mut body = String::from("// Generated by build.rs — do not edit.\n\n");
    body.push_str(&format!("pub const EMBEDDED_UI: bool = {embedded};\n\n"));
    if !embedded || entries.is_empty() {
        body.push_str("pub static FILES: &[EmbeddedFile] = &[];\n");
        fs::write(&path, &body).map_err(|e| e.to_string())?;
        println!("cargo:rustc-env=ZAY_WEBUI_EMBED_RS={}", path.display());
        return Ok(());
    }

    body.push_str("pub static FILES: &[EmbeddedFile] = &[\n");
    for (url_path, dest) in entries {
        let ct = content_type_for_path(url_path);
        let rel = dest
            .strip_prefix(out_dir)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        body.push_str(&format!(
            "    EmbeddedFile {{\n        path: \"{url_path}\",\n        content_type: \"{ct}\",\n        body: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{rel}\")),\n    }},\n"
        ));
    }
    body.push_str("];\n");
    fs::write(&path, &body).map_err(|e| e.to_string())?;
    println!("cargo:rustc-env=ZAY_WEBUI_EMBED_RS={}", path.display());
    Ok(())
}

fn emit_empty_webui_rs(out_dir: &Path) -> Result<(), String> {
    emit_webui_rs(out_dir, false, &[])
}
