//! Clash/Mihomo YAML → sing-box JSON conversion (no external tools).

mod convert;
mod parse;

pub use convert::{convert_proxy, convert_subscription};
pub use parse::{ClashDoc, parse_clash_yaml};
