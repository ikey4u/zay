use std::{
    env,
    fs::{self, File},
    io::{Read, Write, copy},
    path::{Path, PathBuf},
};

/// Pinned Mihomo release embedded by Zay (must match `mihomo::config` types).
const PINNED_MIHOMO_VERSION: &str = "v1.19.25";
const CONFIG_DOCS_URL: &str = "https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.25/docs/config.yaml";
const RELEASE_BASE: &str =
    "https://github.com/MetaCubeX/mihomo/releases/download";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TARGET");

    let target = env::var("TARGET").expect("TARGET not set by cargo");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    fetch_config_docs_template(&out_dir);

    let (artifact, ext) = artifact_for_target(&target).unwrap_or_else(|| {
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

    if stamp_matches(&stamp_path, &version, &target) && embed_path.is_file() {
        emit_rustc_env(&embed_path, &version);
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&embed_path)
            .expect("mihomo metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&embed_path, perms).expect("chmod mihomo");
    }

    write_stamp(&stamp_path, &version, &target).expect("write mihomo.stamp");
    emit_rustc_env(&embed_path, &version);
}

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
    println!(
        "cargo:rustc-env=MIHOMO_CONFIG_TEMPLATE={}",
        dest.to_string_lossy()
    );
}

fn emit_rustc_env(embed_path: &Path, version: &str) {
    println!(
        "cargo:rustc-env=MIHOMO_EMBED={}",
        embed_path.to_string_lossy()
    );
    println!("cargo:rustc-env=MIHOMO_VERSION={version}");
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

fn artifact_for_target(target: &str) -> Option<(&'static str, &'static str)> {
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
