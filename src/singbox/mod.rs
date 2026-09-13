//! Sing-box stack engine (isolated from `mihomo` for easier merges to `main`).

pub mod assets;
pub mod builder;
pub mod clash;
mod embedded_rules;
pub mod mesh;
pub mod mixin;
pub mod native;
pub mod rules;
mod rules_convert;
pub mod subscription;
pub mod tun_route;

pub use builder::{build_config, config_has_tun};

pub const VERSION: &str = singbox_core::VERSION;
