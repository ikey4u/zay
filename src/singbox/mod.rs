//! Sing-box stack engine (isolated from `mihomo` for easier merges to `main`).

pub mod assets;
pub mod builder;
pub mod clash;
pub mod mesh;
pub mod mixin;
pub mod reload;
pub mod rules;
mod rules_convert;
pub mod subscription;
pub mod tun_route;

pub use assets::{resolve_binary, spawn};
pub use builder::{build_config, config_has_tun};
pub use mixin::merge_config;
pub use reload::reload_config;

pub const VERSION: &str = env!("SINGBOX_VERSION");
