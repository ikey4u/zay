//! Native Rust implementation of sing-box.
//!
//! This crate intentionally exposes only an embeddable engine library. The
//! owning application (zay) provides any command-line interface.

pub mod adapter;
pub mod certificate;
pub mod clash_api;
pub mod common;
pub mod constant;
pub mod daemon;
pub mod deprecated;
pub mod dns;
pub mod endpoint;
pub mod inbound;
pub mod log;
pub mod option;
pub mod outbound;
pub mod protocol;
pub mod route;
pub mod runtime;
pub mod schema;
pub mod service;
pub mod transport;

#[doc(hidden)]
pub mod cloudflared_quic_metadata_capnp {
    include!(concat!(
        env!("OUT_DIR"),
        "/cloudflared_quic_metadata_capnp.rs"
    ));
}

#[doc(hidden)]
#[allow(clippy::match_single_binding)]
pub mod cloudflared_tunnelrpc_capnp {
    include!(concat!(env!("OUT_DIR"), "/cloudflared_tunnelrpc_capnp.rs"));
}

pub use adapter::{
    IpPacketPort, IpPacketReturn, NeighborResolver, ProcessInfo,
    ProcessResolver, dns_response_addresses,
};
#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
pub use common::platform_network::{
    PlatformNetworkInterface, PlatformNetworkProvider, PlatformSocket,
};
#[cfg(any(target_os = "android", target_os = "ios"))]
pub use inbound::tun::{TunDeviceRequest, TunFileDescriptorProvider};
pub use option::{ConfigEntry, ConfigLoader, Options};
pub use protocol::quic_bbr::{BbrProfile, BbrProfileError};
pub use runtime::{Runtime, RuntimeError, RuntimeHandle, RuntimeHost};
pub use service::{Box, BoxBuilder, BoxError, BoxState};

/// Upstream source revision this migration is tested against.
pub const UPSTREAM_REVISION: &str = "4bc15be97c25fa34453dbeab553f2a0c29a75539";

/// Semantic release line containing [`UPSTREAM_REVISION`].
pub const UPSTREAM_VERSION: &str = "1.14.0";

/// Rust port version. This is independent of the upstream sing-box version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
