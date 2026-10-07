//! Embeddable Zay networking core for native clients.
#![allow(dead_code)]

mod api;
mod application_traffic;
mod bootstrap;
mod config;
mod daemon;
pub mod desktop;
mod fwd;
mod http;
mod logging;
#[cfg(unix)]
mod native_tun_worker;
mod options;
mod platform;
mod privilege;
mod runtime;
pub mod settings;
mod singbox;
mod ssh;
mod stack;
#[cfg(windows)]
mod windows_tun_worker;
mod yaml;

pub use options::ProxyOpts;
