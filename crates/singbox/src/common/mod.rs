//! Foundational helpers corresponding to the upstream `common` package.

#[cfg(target_vendor = "apple")]
pub(crate) mod apple_http;
#[cfg(target_vendor = "apple")]
pub(crate) mod apple_tls;
pub mod certificate_store;
pub mod http;
pub mod json;
pub mod keygen;
#[cfg(target_os = "linux")]
pub(crate) mod ktls;
pub mod lifecycle;
pub(crate) mod neighbor;
pub mod network;
pub(crate) mod network_monitor;
pub mod ntp;
pub mod platform_network;
pub(crate) mod process;
pub(crate) mod quic;
pub mod reality;
pub(crate) mod reality_tls;
pub mod redir;
pub mod sniff;
pub(crate) mod socket;
pub mod stun;
pub(crate) mod system_proxy;
pub mod tls;
pub mod tls_spoof;
pub(crate) mod udp_nat;
pub(crate) mod utls;
pub(crate) mod utls_profiles;
pub(crate) mod utls_shaping;
#[cfg(windows)]
pub(crate) mod windows_tls;
