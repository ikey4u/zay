use std::{
    env,
    fs::{self, File},
    io::{Read, Write, copy},
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};

include!("shared/clash_rules_convert.rs");

/// Build embedded `sing-box` from the pinned `vendor/sing-box` submodule (requires Go).
const VENDOR_SINGBOX_DIR: &str = "vendor/sing-box";
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

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn git_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|output| output.status.success() && !output.stdout.is_empty())
        .unwrap_or(false)
}

/// Strip zig/cargo glibc suffix (e.g. `.2.17`) from a target triple.
fn normalize_target(target: &str) -> &str {
    target
        .split_once('.')
        .map(|(base, _)| base)
        .unwrap_or(target)
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-env-changed=TARGET");

    println!("cargo:rerun-if-changed=vendor/sing-box/go.mod");
    println!("cargo:rerun-if-changed=vendor/sing-box/cmd/sing-box");
    println!(
        "cargo:rerun-if-changed=vendor/sing-box/release/DEFAULT_BUILD_TAGS_OTHERS"
    );
    println!("cargo:rerun-if-changed=vendor/sing-box/release/LDFLAGS");
    println!("cargo:rerun-if-changed=vendor/Easytier/easytier/Cargo.toml");

    let pkg_version =
        env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let mut version = pkg_version.clone();
    if let Some(commit) = git_output(&["rev-parse", "--short", "HEAD"]) {
        version = format!("{pkg_version}-{commit}");
        if git_dirty() {
            version.push_str("+dirty");
        }
    }
    println!("cargo:rustc-env=ZAY_VERSION={version}");

    let target_raw = env::var("TARGET").expect("TARGET not set by cargo");
    let target = normalize_target(&target_raw);
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    prepare_windows_runtime(&out_dir, target);

    embed_singbox(&out_dir, target);
    embed_clash_rules(&out_dir);
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

const CLASH_RULES_STAMP_KEY: &str = "loyalsoldier-clash-rules@release+geoip-cn+geosite-cn+ruleset-v4+suffix-apex";

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

fn embed_singbox(out_dir: &Path, target: &str) {
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"),
    );
    let vendor = manifest_dir.join(VENDOR_SINGBOX_DIR);
    if !vendor.join("go.mod").is_file() {
        panic!(
            "missing {VENDOR_SINGBOX_DIR} (go.mod). Init submodules:\n  git submodule update --init --recursive"
        );
    }

    let commit = git_output(&[
        "-C",
        vendor.to_str().expect("vendor path utf-8"),
        "rev-parse",
        "HEAD",
    ])
    .unwrap_or_else(|| "unknown".into());
    let short = commit.chars().take(12).collect::<String>();
    let version = format!("vendor-{short}");

    let exe_name = if target.contains("windows") {
        "sing-box.exe"
    } else {
        "sing-box"
    };
    let embed_path = out_dir.join(exe_name);
    let stamp_path = out_dir.join("singbox.stamp");

    if stamp_matches(&stamp_path, &version, target) && embed_path.is_file() {
        emit_singbox_rustc_env(&embed_path, &version);
        return;
    }

    let (goos, goarch) =
        go_target_for_rust_target(target).unwrap_or_else(|| {
            panic!("unsupported build target for vendor sing-box: {target}")
        });
    let tags =
        fs::read_to_string(vendor.join("release/DEFAULT_BUILD_TAGS_OTHERS"))
            .unwrap_or_else(|e| {
                panic!(
                    "read {}: {e}",
                    vendor.join("release/DEFAULT_BUILD_TAGS_OTHERS").display()
                )
            });
    let tags = tags.trim();
    // Must include release/LDFLAGS (-checklinkname=0) or badtls go:linkname fails to link.
    let shared_ldflags = fs::read_to_string(vendor.join("release/LDFLAGS"))
        .unwrap_or_else(|e| {
            panic!("read {}: {e}", vendor.join("release/LDFLAGS").display())
        });
    let shared_ldflags = shared_ldflags.trim();
    let ldflags = format!(
        "-X 'github.com/sagernet/sing-box/constant.Version={version}' {shared_ldflags} -s -w -buildid="
    );

    eprintln!(
        "cargo:warning=zay: building sing-box from {VENDOR_SINGBOX_DIR} ({short}) for {goos}/{goarch}"
    );

    let status = Command::new("go")
        .current_dir(&vendor)
        .env("CGO_ENABLED", "0")
        .env("GOOS", goos)
        .env("GOARCH", goarch)
        .env("GOTOOLCHAIN", "auto")
        .args([
            "build",
            "-trimpath",
            "-tags",
            tags,
            "-ldflags",
            &ldflags,
            "-o",
        ])
        .arg(&embed_path)
        .arg("./cmd/sing-box")
        .status()
        .unwrap_or_else(|e| {
            panic!("failed to spawn `go` (install Go and ensure it is on PATH): {e}")
        });
    if !status.success() {
        panic!(
            "go build sing-box failed with {status} (cwd {})",
            vendor.display()
        );
    }

    chmod_executable(&embed_path);
    write_stamp(&stamp_path, &version, target).expect("write singbox.stamp");
    emit_singbox_rustc_env(&embed_path, &version);
}

fn go_target_for_rust_target(
    target: &str,
) -> Option<(&'static str, &'static str)> {
    Some(match target {
        "aarch64-apple-darwin" => ("darwin", "arm64"),
        "x86_64-apple-darwin" => ("darwin", "amd64"),
        "aarch64-unknown-linux-gnu" | "aarch64-unknown-linux-musl" => {
            ("linux", "arm64")
        }
        "x86_64-unknown-linux-gnu" | "x86_64-unknown-linux-musl" => {
            ("linux", "amd64")
        }
        "x86_64-pc-windows-gnu" | "x86_64-pc-windows-msvc" => {
            ("windows", "amd64")
        }
        "aarch64-pc-windows-msvc" => ("windows", "arm64"),
        _ => return None,
    })
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
    // WinPcap's installer ships several Packet.dll builds; the NetMon-enabled
    // x64 variant imports obsolete NPPTools.dll and fails to start on modern
    // Windows. Keep only a PE that does not depend on it.
    if !packet_dll.is_file() || ensure_winpcap_packet_dll(&packet_dll).is_err()
    {
        let installer = base_dir.join("WinPcap_4_1_3.exe");
        download_if_missing(
            WINPCAP_INSTALLER_URL,
            WINPCAP_INSTALLER_SHA256,
            &installer,
        );
        extract_winpcap_packet_dll(&installer, &packet_dll)
            .unwrap_or_else(|e| panic!("extract WinPcap Packet.dll: {e}"));
        ensure_winpcap_packet_dll(&packet_dll)
            .unwrap_or_else(|e| panic!("verify WinPcap Packet.dll: {e}"));
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
        if is_usable_winpcap_packet_dll(&content) {
            candidates.push((content.len(), content));
        }
    }
    candidates.sort_by_key(|(size, _)| *size);
    let Some((_, content)) = candidates.pop() else {
        return Err(
            "no usable x86_64 Packet.dll (without NPPTools.dll) in WinPcap installer"
                .into(),
        );
    };
    fs::write(dest, content).map_err(|e| e.to_string())?;
    Ok(())
}

fn pe_imports_dll(buf: &[u8], dll_name: &str) -> bool {
    let needle = dll_name.as_bytes();
    buf.windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn is_usable_winpcap_packet_dll(buf: &[u8]) -> bool {
    is_pe_x86_64_bytes(buf) && !pe_imports_dll(buf, "NPPTools.dll")
}

fn ensure_winpcap_packet_dll(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if is_usable_winpcap_packet_dll(&bytes) {
        Ok(())
    } else if !is_pe_x86_64_bytes(&bytes) {
        Err(format!("{} is not an x86_64 PE file", path.display()))
    } else {
        Err(format!(
            "{} depends on obsolete NPPTools.dll",
            path.display()
        ))
    }
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

fn emit_singbox_rustc_env(embed_path: &Path, version: &str) {
    println!(
        "cargo:rustc-env=SINGBOX_EMBED={}",
        embed_path.to_string_lossy()
    );
    println!("cargo:rustc-env=SINGBOX_VERSION={version}");
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
