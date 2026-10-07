//! Native Rust implementation of sing-box.
//!
//! This crate intentionally exposes only an embeddable engine library. The
//! owning application (zay) provides any command-line interface.
//!
//! The default `full` feature provides the complete engine. Disable defaults
//! and enable `socks` to embed a direct SOCKS server without the engine's
//! routing, tunnel, TLS, database, or RPC dependencies.

#[cfg(feature = "full")]
pub mod adapter;
#[cfg(feature = "full")]
pub mod certificate;
#[cfg(feature = "full")]
pub mod clash_api;
pub mod common;
#[cfg(feature = "full")]
pub mod constant;
#[cfg(feature = "full")]
pub mod daemon;
#[cfg(feature = "full")]
pub mod deprecated;
#[cfg(feature = "full")]
pub mod dns;
#[cfg(feature = "full")]
pub mod endpoint;
#[cfg_attr(not(feature = "full"), path = "inbound/minimal.rs")]
pub mod inbound;
#[cfg(feature = "full")]
pub mod log;
#[cfg(feature = "full")]
pub mod option;
#[cfg(not(feature = "full"))]
pub mod option {
    pub use crate::user::User;
}
#[cfg(feature = "full")]
pub mod outbound;
pub mod protocol;
#[cfg(feature = "full")]
pub mod route;
#[cfg(feature = "full")]
pub mod runtime;
#[cfg(feature = "full")]
pub mod schema;
#[cfg(feature = "full")]
pub mod service;
#[cfg(feature = "full")]
pub mod transport;
#[path = "option/user.rs"]
mod user;

#[cfg(feature = "full")]
#[doc(hidden)]
pub mod cloudflared_quic_metadata_capnp {
    include!(concat!(
        env!("OUT_DIR"),
        "/cloudflared_quic_metadata_capnp.rs"
    ));
}

#[cfg(feature = "full")]
#[doc(hidden)]
#[allow(clippy::match_single_binding)]
pub mod cloudflared_tunnelrpc_capnp {
    include!(concat!(env!("OUT_DIR"), "/cloudflared_tunnelrpc_capnp.rs"));
}

#[cfg(feature = "full")]
pub use adapter::{
    IpPacketPort, IpPacketReturn, NeighborResolver, ProcessInfo,
    ProcessLookupResult, ProcessLookupStatus, ProcessResolver,
    dns_response_addresses,
};
#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
#[cfg(feature = "full")]
pub use common::platform_network::{
    PlatformNetworkInterface, PlatformNetworkProvider, PlatformSocket,
};
#[cfg(any(target_os = "android", target_os = "ios"))]
#[cfg(feature = "full")]
pub use inbound::tun::{TunDeviceRequest, TunFileDescriptorProvider};
#[cfg(feature = "full")]
pub use option::{ConfigEntry, ConfigLoader, Options};
#[cfg(feature = "full")]
pub use protocol::quic_bbr::{BbrProfile, BbrProfileError};
#[cfg(feature = "full")]
pub use runtime::{Runtime, RuntimeError, RuntimeHandle, RuntimeHost};
#[cfg(feature = "full")]
pub use service::{Box, BoxBuilder, BoxError, BoxState};

/// Construct the operating system's built-in best-effort process resolver.
///
/// Embedding applications can wrap this resolver with a platform monitor and
/// retain the native socket-table implementation as a fallback.
#[cfg(feature = "full")]
pub fn native_process_resolver() -> Option<std::sync::Arc<dyn ProcessResolver>>
{
    common::process::native_process_resolver()
}

/// Upstream source revision this migration is tested against.
pub const UPSTREAM_REVISION: &str = "4bc15be97c25fa34453dbeab553f2a0c29a75539";

/// Semantic release line containing [`UPSTREAM_REVISION`].
pub const UPSTREAM_VERSION: &str = "1.14.0";

/// Rust port version. This is independent of the upstream sing-box version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
