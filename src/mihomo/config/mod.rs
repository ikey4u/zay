//! Mihomo [`Config`](config::Config) types aligned with official v1.19.25 `docs/config.yaml` / `RawConfig`.
//!
//! Schema tag: **`v1.19.25`** (see `MIHOMO_CONFIG_TAG` / embedded `CONFIG_TEMPLATE` from `build.rs`).

pub mod cfa;
pub mod config;
pub mod cors;
pub mod dns;
pub mod experimental;
pub mod geox;
pub mod hosts;
pub mod iptables;
pub mod ntp;
pub mod profile;
pub mod providers;
pub mod proxy;
pub mod proxy_group;
pub mod sniffer;
pub mod tls;
pub mod tuic;
pub mod tun;
pub mod tunnel;
pub mod zay;

pub use config::{Config, DOCUMENTED_TOP_LEVEL_KEYS};
pub use providers::{ProviderOverride, RuleProvider, RuleProviders};

/// Embedded Mihomo binary version (matches `CONFIG_TAG`).
pub const MIHOMO_VERSION: &str = env!("MIHOMO_VERSION");

/// Mihomo release tag used when generating `mihomo::config` (matches embedded binary).
pub const CONFIG_TAG: &str = env!("MIHOMO_CONFIG_TAG");

/// Absolute path to the downloaded reference `docs/config.yaml` at build time.
pub const CONFIG_TEMPLATE_PATH: &str = env!("MIHOMO_CONFIG_TEMPLATE");

/// Full upstream template text (includes `#` comments; for reference / tooling, not for `serde` parsing).
pub const CONFIG_TEMPLATE: &str =
    include_str!(concat!(env!("OUT_DIR"), "/mihomo-docs-config.yaml"));
