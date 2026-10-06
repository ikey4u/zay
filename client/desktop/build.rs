use std::{
    env, fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
fn hash_sources(path: &Path, hash: &mut impl Hasher) {
    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for entry in entries {
        if entry.is_dir() {
            hash_sources(&entry, hash);
        } else if matches!(
            entry.extension().and_then(|s| s.to_str()),
            Some("rs" | "m")
        ) {
            fs::read(entry).unwrap().hash(hash);
        }
    }
}
fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    println!("cargo:rerun-if-env-changed=ZAY_MACOS_TEAM_ID");
    println!("cargo:rerun-if-env-changed=ZAY_DESKTOP_PLIST_DIR");
    for path in [
        "Info.plist",
        "../../src",
        "../../crates/singbox/src",
        "../../native/macos",
        "../../Cargo.toml",
        "../../build.rs",
        "src",
        "Cargo.lock",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    hash_sources(Path::new("../../src"), &mut hash);
    hash_sources(Path::new("../../crates/singbox/src"), &mut hash);
    hash_sources(Path::new("../../native/macos"), &mut hash);
    hash_sources(Path::new("src"), &mut hash);
    for path in [
        "Cargo.lock",
        "Cargo.toml",
        "build.rs",
        "../../Cargo.toml",
        "../../build.rs",
    ] {
        fs::read(path).unwrap().hash(&mut hash);
    }
    env::var("PROFILE").unwrap().hash(&mut hash);
    let build = format!("{:016x}", hash.finish());
    let version = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let team = env::var("ZAY_MACOS_TEAM_ID").unwrap_or_default();
    assert!(
        team.is_empty()
            || (team.len() == 10
                && team.chars().all(|c| c.is_ascii_alphanumeric())),
        "Invalid Apple signing Team ID"
    );
    let requirement = if team.is_empty() {
        // Ad-hoc builds support the unprivileged UI; never trust arbitrary local
        // processes merely because they share our bundle identifier.
        "cdhash H\"0000000000000000000000000000000000000000\"".to_owned()
    } else {
        format!(
            "anchor apple generic and identifier \"dev.zay.desktop\" and certificate leaf[subject.OU] = \"{team}\""
        )
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let info = out.join("helper-info.plist");
    let launchd = out.join("helper-launchd.plist");
    fs::write(
        &info,
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.zay.desktop.helper</string>
<key>CFBundleName</key><string>Zay Networking Helper</string>
<key>CFBundleDisplayName</key><string>Zay Desktop</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>{version}</string>
<key>ZayHelperBuild</key><string>{build}</string>
<key>SMAuthorizedClients</key><array><string>{requirement}</string></array>
</dict></plist>"#
        ),
    )
    .unwrap();
    fs::write(
        &launchd,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>dev.zay.desktop.helper</string>
<key>AssociatedBundleIdentifiers</key><array><string>dev.zay.desktop</string></array>
<key>MachServices</key><dict><key>dev.zay.desktop.helper</key><true/></dict>
</dict></plist>"#,
    )
    .unwrap();
    if let Some(destination) = env::var_os("ZAY_DESKTOP_PLIST_DIR") {
        let destination = PathBuf::from(destination);
        let mut app = fs::read_to_string("Info.plist").unwrap().replace(
            "<key>CFBundleVersion</key><string>1</string>",
            &format!("<key>CFBundleVersion</key><string>{version}</string>"),
        );
        let helper_requirement = requirement
            .replace("dev.zay.desktop\"", "dev.zay.desktop.helper\"");
        let ready = if team.is_empty() {
            "<false/>"
        } else {
            "<true/>"
        };
        let additions = format!(
            "<key>SMPrivilegedExecutables</key><dict><key>dev.zay.desktop.helper</key><string>{helper_requirement}</string></dict>\n<key>ZayPrivilegedHelperSigningReady</key>{ready}\n<key>ZayHelperBuild</key><string>{build}</string>\n"
        );
        app.insert_str(app.rfind("</dict>").unwrap(), &additions);
        fs::write(destination.join("Info.plist"), app).unwrap();
        fs::copy(&info, destination.join("helper-info.plist")).unwrap();
        fs::copy(&launchd, destination.join("helper-launchd.plist")).unwrap();
    }
    for (section, path) in
        [("__info_plist", info), ("__launchd_plist", launchd)]
    {
        println!(
            "cargo:rustc-link-arg-bin=zay-desktop-helper=-Wl,-sectcreate,__TEXT,{section},{}",
            path.display()
        );
    }
}
