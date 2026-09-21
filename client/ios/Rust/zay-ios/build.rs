//! Embed Loyalsoldier clash-rules (+ geoip/geosite CN) at compile time — same as desktop zay.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

// Reuse the runtime's canonical SRS codec without pulling the complete
// sing-box networking core into the host-side build script.
#[path = "../../../../crates/singbox/src/route/srs.rs"]
#[allow(dead_code)]
mod srs;

mod option {
    use super::{Deserialize, Deserializer, Serialize, Serializer, de};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DnsQueryType(pub u16);

    impl<'de> Deserialize<'de> for DnsQueryType {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum NameOrNumber {
                Name(String),
                Number(u16),
            }
            match NameOrNumber::deserialize(deserializer)? {
                NameOrNumber::Number(value) => Ok(Self(value)),
                NameOrNumber::Name(name) => {
                    dns_type_number(&name).map(Self).ok_or_else(|| {
                        de::Error::custom(format!(
                            "unknown DNS query type: {name}"
                        ))
                    })
                }
            }
        }
    }

    impl Serialize for DnsQueryType {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match dns_type_name(self.0) {
                Some(name) => serializer.serialize_str(name),
                None => serializer.serialize_u16(self.0),
            }
        }
    }

    fn dns_type_number(name: &str) -> Option<u16> {
        Some(match name.to_ascii_uppercase().as_str() {
            "A" => 1,
            "NS" => 2,
            "CNAME" => 5,
            "SOA" => 6,
            "PTR" => 12,
            "MX" => 15,
            "TXT" => 16,
            "AAAA" => 28,
            "SRV" => 33,
            "NAPTR" => 35,
            "DS" => 43,
            "RRSIG" => 46,
            "NSEC" => 47,
            "DNSKEY" => 48,
            "TLSA" => 52,
            "SVCB" => 64,
            "HTTPS" => 65,
            "CAA" => 257,
            _ => return None,
        })
    }

    fn dns_type_name(value: u16) -> Option<&'static str> {
        Some(match value {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            35 => "NAPTR",
            43 => "DS",
            46 => "RRSIG",
            47 => "NSEC",
            48 => "DNSKEY",
            52 => "TLSA",
            64 => "SVCB",
            65 => "HTTPS",
            257 => "CAA",
            _ => return None,
        })
    }
}

include!("../../../../shared/clash_rules_convert.rs");
include!("../../../../shared/embed_clash_rules_build.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rerun-if-changed=../../../../shared/clash_rules_convert.rs"
    );
    println!(
        "cargo:rerun-if-changed=../../../../shared/embed_clash_rules_build.rs"
    );
    println!(
        "cargo:rerun-if-changed=../../../../crates/singbox/src/route/srs.rs"
    );
    let out_dir =
        std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    embed_clash_rules(&out_dir);
    compile_mobile_rule_sets(&out_dir);
}

/// Large source JSON rule-sets multiply in size when the packet-tunnel process
/// parses and compiles them. Compile those sets on the developer machine so
/// the iOS extension only has to decode compact SRS files at startup.
fn compile_mobile_rule_sets(out_dir: &std::path::Path) {
    use std::{fmt::Write as _, fs};

    let rules_dir = out_dir.join("embedded-clash-rules");
    let generated_path = out_dir.join("embedded_clash_rules.rs");
    let mut generated = fs::read_to_string(&generated_path)
        .expect("read generated embedded rule declarations");

    for id in ["direct", "reject"] {
        let source_path = rules_dir.join(format!("{id}.json"));
        let binary_path = rules_dir.join(format!("{id}.srs"));
        let source = fs::read(&source_path).unwrap_or_else(|error| {
            panic!("read {}: {error}", source_path.display())
        });
        let document: serde_json::Value = serde_json::from_slice(&source)
            .unwrap_or_else(|error| panic!("parse {id} rule-set: {error}"));
        let version = document
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
            .unwrap_or(4);
        let rules = document
            .get("rules")
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| panic!("{id} rule-set has no rules array"));
        let version = srs::downgrade_version(rules, version);
        let binary = srs::write(rules, version)
            .unwrap_or_else(|error| panic!("compile {id} rule-set: {error}"));
        let (decoded_version, decoded_rules) = srs::read_with_version(&binary)
            .unwrap_or_else(|error| {
                panic!("verify compiled {id} rule-set: {error}")
            });
        assert_eq!(decoded_version, version, "{id} SRS version mismatch");
        assert_eq!(
            decoded_rules.len(),
            rules.len(),
            "{id} SRS rule count mismatch"
        );
        fs::write(&binary_path, &binary).unwrap_or_else(|error| {
            panic!("write {}: {error}", binary_path.display())
        });
        writeln!(
            generated,
            "pub static EMBEDDED_{}_SRS: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/embedded-clash-rules/{id}.srs\"));",
            id.to_ascii_uppercase()
        )
        .expect("append embedded SRS declaration");
        eprintln!(
            "cargo:warning=zay: compiled iOS {id}.srs ({} -> {} bytes)",
            source.len(),
            binary.len()
        );
    }

    fs::write(&generated_path, generated)
        .expect("write generated embedded rule declarations");
}
