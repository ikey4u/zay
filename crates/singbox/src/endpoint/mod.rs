//! Endpoint protocol implementations.
//!
//! Unlike an outbound, an endpoint owns an IP network and can both originate
//! traffic and feed decrypted flows back into the router. The WireGuard module
//! starts with the reusable userspace packet engine; platform TUN and system
//! interface lifecycle are layered above it.

pub(crate) mod flow_dispatch;
pub mod openconnect;
pub mod openvpn;
pub mod openvpn_server;
pub mod tailscale;
/// Userspace IP stack primitives used by mobile embedding diagnostics.
///
/// This is public so an embedding host can exercise the exact L3 boundary
/// without requiring a kernel TUN (for example, in iOS Simulator where the
/// Network Extension preference service is unavailable).
#[doc(hidden)]
pub mod tokio_smoltcp;
pub(crate) mod userspace_router;
pub mod wireguard;
