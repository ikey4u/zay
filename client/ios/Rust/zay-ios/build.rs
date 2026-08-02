//! Embed Loyalsoldier clash-rules (+ geoip/geosite CN) at compile time — same as desktop zay.

include!("../../../../shared/clash_rules_convert.rs");
include!("../../../../shared/embed_clash_rules_build.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../../../shared/clash_rules_convert.rs");
    println!("cargo:rerun-if-changed=../../../../shared/embed_clash_rules_build.rs");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    embed_clash_rules(&out_dir);
}
