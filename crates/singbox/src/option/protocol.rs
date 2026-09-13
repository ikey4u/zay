use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use super::{
    Addr, Base64Bytes, DialerOptions, Duration, FwMark,
    InboundMultiplexOptions, InboundTlsOptions, Listable, ListenOptions,
    MemoryBytes, NetworkBytesCompat, NetworkList, OutboundMultiplexOptions,
    OutboundTlsOptions, Prefix, ServerOptions, UdpTimeout, User,
    V2RayTransportOptions,
};

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
pub enum UdpNatBehavior {
    #[default]
    #[serde(rename = "endpoint_independent", alias = "")]
    EndpointIndependent,
    #[serde(rename = "address_dependent")]
    AddressDependent,
    #[serde(rename = "address_and_port_dependent")]
    AddressAndPortDependent,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardPeer {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub pre_shared_key: String,
    #[serde(default)]
    pub allowed_ips: Listable<Prefix>,
    #[serde(default)]
    pub persistent_keepalive_interval: u16,
    #[serde(default)]
    pub reserved: Vec<u8>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireGuardEndpointOptions {
    #[serde(default)]
    pub system: bool,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mtu: u32,
    pub address: Listable<Prefix>,
    pub private_key: String,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub peers: Vec<WireGuardPeer>,
    #[serde(default)]
    pub udp_timeout: Duration,
    #[serde(default)]
    pub udp_mapping: UdpNatBehavior,
    #[serde(default)]
    pub udp_filtering: UdpNatBehavior,
    #[serde(default)]
    pub udp_nat_max: u32,
    #[serde(default)]
    pub workers: i32,
    #[serde(flatten)]
    pub dialer: DialerOptions,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UdpOverTcpOptions {
    pub enabled: bool,
    pub version: u8,
}

impl<'de> Deserialize<'de> for UdpOverTcpOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum BooleanOrObject {
            Boolean(bool),
            Object { enabled: bool, version: u8 },
        }
        match BooleanOrObject::deserialize(deserializer)? {
            BooleanOrObject::Boolean(enabled) => Ok(Self {
                enabled,
                version: 0,
            }),
            BooleanOrObject::Object { enabled, version }
                if matches!(version, 1 | 2) =>
            {
                Ok(Self { enabled, version })
            }
            BooleanOrObject::Object { version, .. } => Err(de::Error::custom(
                format!("unknown UDP-over-TCP version: {version}"),
            )),
        }
    }
}

impl Serialize for UdpOverTcpOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if matches!(self.version, 0 | 2) {
            return self.enabled.serialize(serializer);
        }
        #[derive(Serialize)]
        struct Object {
            enabled: bool,
            version: u8,
        }
        Object {
            enabled: self.enabled,
            version: self.version,
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct SocksInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub users: Vec<User>,
    #[serde(default)]
    pub domain_resolver: Option<super::DomainResolveOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpMixedInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub users: Vec<User>,
    #[serde(default)]
    pub domain_resolver: Option<super::DomainResolveOptions>,
    #[serde(default)]
    pub set_system_proxy: bool,
    #[serde(default)]
    pub tls: Option<InboundTlsOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct SocksOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub network: NetworkList,
    #[serde(default)]
    pub udp_over_tcp: Option<UdpOverTcpOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub tls: Option<OutboundTlsOptions>,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub headers: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub network: NetworkList,
    #[serde(default)]
    pub override_address: String,
    #[serde(default)]
    pub override_port: u16,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedirectInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TProxyInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub network: NetworkList,
    #[serde(default)]
    pub udp_mapping: UdpNatBehavior,
    #[serde(default)]
    pub udp_filtering: UdpNatBehavior,
    #[serde(default)]
    pub udp_nat_max: u32,
}

/// Platform-owned HTTP proxy settings used by mobile TUN integrations.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunHttpProxyOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(default)]
    pub bypass_domain: Listable<String>,
    #[serde(default)]
    pub match_domain: Listable<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunPlatformOptions {
    #[serde(default)]
    pub http_proxy: Option<TunHttpProxyOptions>,
}

/// TUN inbound options at the pinned sing-box schema boundary.
///
/// Removed fields remain represented so callers constructing [`Options`]
/// without [`crate::option::ConfigLoader`] receive the same explicit migration
/// error instead of having stale settings silently ignored.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunInboundOptions {
    #[serde(default)]
    pub interface_name: String,
    #[serde(default)]
    pub netns: String,
    #[serde(default)]
    pub mtu: u32,
    #[serde(default)]
    pub address: Listable<Prefix>,
    #[serde(default)]
    pub dns_mode: String,
    #[serde(default)]
    pub dns_address: Listable<Addr>,
    #[serde(default)]
    pub auto_route: bool,
    #[serde(default)]
    pub iproute2_table_index: i32,
    #[serde(default)]
    pub iproute2_rule_index: i32,
    #[serde(default)]
    pub auto_redirect: bool,
    #[serde(default)]
    pub auto_redirect_input_mark: FwMark,
    #[serde(default)]
    pub auto_redirect_output_mark: FwMark,
    #[serde(default)]
    pub auto_redirect_reset_mark: FwMark,
    #[serde(default)]
    pub auto_redirect_nfqueue: u16,
    #[serde(default)]
    pub auto_redirect_iproute2_fallback_rule_index: i32,
    #[serde(default)]
    pub exclude_mptcp: bool,
    #[serde(default)]
    pub loopback_address: Listable<Addr>,
    #[serde(default)]
    pub strict_route: bool,
    #[serde(default)]
    pub route_address: Listable<Prefix>,
    #[serde(default)]
    pub route_address_set: Listable<String>,
    #[serde(default)]
    pub route_exclude_address: Listable<Prefix>,
    #[serde(default)]
    pub route_exclude_address_set: Listable<String>,
    #[serde(default)]
    pub include_interface: Listable<String>,
    #[serde(default)]
    pub exclude_interface: Listable<String>,
    #[serde(default)]
    pub include_uid: Listable<u32>,
    #[serde(default)]
    pub include_uid_range: Listable<String>,
    #[serde(default)]
    pub exclude_uid: Listable<u32>,
    #[serde(default)]
    pub exclude_uid_range: Listable<String>,
    #[serde(default)]
    pub include_android_user: Listable<i32>,
    #[serde(default)]
    pub include_package: Listable<String>,
    #[serde(default)]
    pub exclude_package: Listable<String>,
    #[serde(default)]
    pub include_mac_address: Listable<String>,
    #[serde(default)]
    pub exclude_mac_address: Listable<String>,
    #[serde(default)]
    pub udp_timeout: UdpTimeout,
    #[serde(default)]
    pub udp_mapping: UdpNatBehavior,
    #[serde(default)]
    pub udp_filtering: UdpNatBehavior,
    #[serde(default)]
    pub udp_nat_max: u32,
    #[serde(default)]
    pub stack: String,
    #[serde(default)]
    pub platform: Option<TunPlatformOptions>,

    // Removed by upstream sing-box. ConfigLoader rejects these through the
    // pinned schema; direct library construction is checked by TunInbound.
    #[serde(default)]
    pub gso: bool,
    #[serde(default)]
    pub inet4_address: Listable<Prefix>,
    #[serde(default)]
    pub inet6_address: Listable<Prefix>,
    #[serde(default)]
    pub inet4_route_address: Listable<Prefix>,
    #[serde(default)]
    pub inet6_route_address: Listable<Prefix>,
    #[serde(default)]
    pub inet4_route_exclude_address: Listable<Prefix>,
    #[serde(default)]
    pub inet6_route_exclude_address: Listable<Prefix>,
    #[serde(default)]
    pub endpoint_independent_nat: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicOptions {
    #[serde(default)]
    pub idle_timeout: Duration,
    #[serde(default)]
    pub keep_alive_period: Duration,
    #[serde(default)]
    pub stream_receive_window: MemoryBytes,
    #[serde(default)]
    pub connection_receive_window: MemoryBytes,
    #[serde(default)]
    pub max_concurrent_streams: i32,
    #[serde(default)]
    pub initial_packet_size: i32,
    #[serde(default)]
    pub disable_path_mtu_discovery: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuicUser {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct TuicInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub users: Vec<TuicUser>,
    #[serde(default)]
    pub congestion_control: String,
    #[serde(default)]
    pub auth_timeout: Duration,
    #[serde(default)]
    pub zero_rtt_handshake: bool,
    #[serde(default)]
    pub heartbeat: Duration,
    #[serde(default)]
    pub tls: Option<InboundTlsOptions>,
    #[serde(flatten)]
    pub quic: QuicOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct TuicOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub congestion_control: String,
    #[serde(default)]
    pub udp_relay_mode: String,
    #[serde(default)]
    pub udp_over_stream: bool,
    #[serde(default)]
    pub zero_rtt_handshake: bool,
    #[serde(default)]
    pub heartbeat: Duration,
    #[serde(default)]
    pub network: NetworkList,
    #[serde(default)]
    pub tls: Option<OutboundTlsOptions>,
    #[serde(flatten)]
    pub quic: QuicOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct NaiveInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub users: Vec<User>,
    #[serde(default)]
    pub network: NetworkList,
    #[serde(default)]
    pub quic_congestion_control: String,
    #[serde(default)]
    pub tls: Option<InboundTlsOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct NaiveOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub insecure_concurrency: i32,
    #[serde(default)]
    pub extra_headers: HashMap<String, Listable<String>>,
    #[serde(default)]
    pub stream_receive_window: Option<MemoryBytes>,
    #[serde(default)]
    pub udp_over_tcp: Option<UdpOverTcpOptions>,
    #[serde(default)]
    pub quic: bool,
    #[serde(default)]
    pub quic_congestion_control: String,
    #[serde(default)]
    pub quic_session_receive_window: Option<MemoryBytes>,
    #[serde(default)]
    pub tls: Option<OutboundTlsOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub private_key: Listable<String>,
    #[serde(default)]
    pub private_key_path: String,
    #[serde(default)]
    pub private_key_passphrase: String,
    #[serde(default)]
    pub host_key: Listable<String>,
    #[serde(default)]
    pub host_key_algorithms: Listable<String>,
    #[serde(default)]
    pub client_version: String,
    #[serde(default)]
    pub cipher: Listable<String>,
    #[serde(default)]
    pub mac: Listable<String>,
    #[serde(default)]
    pub kex_algorithm: Listable<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TorOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(default)]
    pub executable_path: String,
    #[serde(default)]
    pub extra_args: Vec<String>,
    #[serde(default)]
    pub data_directory: String,
    #[serde(default, rename = "torrc")]
    pub torrc: HashMap<String, String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HysteriaUser {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub auth: Base64Bytes,
    #[serde(default)]
    pub auth_str: String,
}

impl HysteriaUser {
    pub fn password(&self) -> String {
        if self.auth_str.is_empty() {
            String::from_utf8_lossy(&self.auth.0).into_owned()
        } else {
            self.auth_str.clone()
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct HysteriaInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub up: Option<NetworkBytesCompat>,
    #[serde(default)]
    pub up_mbps: i32,
    #[serde(default)]
    pub down: Option<NetworkBytesCompat>,
    #[serde(default)]
    pub down_mbps: i32,
    #[serde(default)]
    pub obfs: String,
    #[serde(default)]
    pub users: Vec<HysteriaUser>,
    #[serde(default)]
    pub recv_window_conn: u64,
    #[serde(default)]
    pub recv_window_client: u64,
    #[serde(default)]
    pub max_conn_client: i32,
    #[serde(default)]
    pub disable_mtu_discovery: bool,
    #[serde(default)]
    pub tls: Option<InboundTlsOptions>,
    #[serde(flatten)]
    pub quic: QuicOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct HysteriaOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(default)]
    pub server_ports: Listable<String>,
    #[serde(default)]
    pub hop_interval: Duration,
    #[serde(default)]
    pub up: Option<NetworkBytesCompat>,
    #[serde(default)]
    pub up_mbps: i32,
    #[serde(default)]
    pub down: Option<NetworkBytesCompat>,
    #[serde(default)]
    pub down_mbps: i32,
    #[serde(default)]
    pub obfs: String,
    #[serde(default)]
    pub auth: Base64Bytes,
    #[serde(default)]
    pub auth_str: String,
    #[serde(default)]
    pub recv_window_conn: u64,
    #[serde(default)]
    pub recv_window: u64,
    #[serde(default)]
    pub disable_mtu_discovery: bool,
    #[serde(default)]
    pub network: NetworkList,
    #[serde(default)]
    pub tls: Option<OutboundTlsOptions>,
    #[serde(flatten)]
    pub quic: QuicOptions,
}

impl HysteriaOutboundOptions {
    pub fn password(&self) -> String {
        if self.auth_str.is_empty() {
            String::from_utf8_lossy(&self.auth.0).into_owned()
        } else {
            self.auth_str.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Hysteria2Obfs {
    Salamander {
        #[serde(default)]
        password: String,
    },
    Gecko {
        #[serde(default)]
        password: String,
        #[serde(default)]
        min_packet_size: i32,
        #[serde(default)]
        max_packet_size: i32,
    },
}

impl Hysteria2Obfs {
    pub fn password(&self) -> &str {
        match self {
            Self::Salamander { password } | Self::Gecko { password, .. } => {
                password
            }
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hysteria2User {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hysteria2RealmPortMapping {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub timeout: Duration,
    #[serde(default)]
    pub lifetime: Duration,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hysteria2Realm {
    pub server_url: String,
    #[serde(default)]
    pub token: String,
    pub realm_id: String,
    pub stun_servers: Listable<String>,
    #[serde(default)]
    pub ip_version: i32,
    #[serde(default)]
    pub port_mapping: Option<Hysteria2RealmPortMapping>,
    #[serde(default)]
    pub http_client: Option<super::HttpClientOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hysteria2InboundRealm {
    #[serde(flatten)]
    pub realm: Hysteria2Realm,
    #[serde(default)]
    pub stun_domain_resolver: Option<super::DomainResolveOptions>,
}

impl std::ops::Deref for Hysteria2InboundRealm {
    type Target = Hysteria2Realm;

    fn deref(&self) -> &Self::Target {
        &self.realm
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Hysteria2MasqueradeObject {
    File {
        directory: String,
    },
    Proxy {
        url: String,
        #[serde(default)]
        rewrite_host: bool,
    },
    String {
        #[serde(default)]
        status_code: i32,
        #[serde(default)]
        headers: HashMap<String, Listable<String>>,
        content: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Hysteria2Masquerade {
    Url(String),
    Object(Hysteria2MasqueradeObject),
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hysteria2InboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub up_mbps: i32,
    #[serde(default)]
    pub down_mbps: i32,
    #[serde(default)]
    pub obfs: Option<Hysteria2Obfs>,
    #[serde(default)]
    pub users: Vec<Hysteria2User>,
    #[serde(default)]
    pub ignore_client_bandwidth: bool,
    #[serde(default)]
    pub tls: Option<InboundTlsOptions>,
    #[serde(flatten)]
    pub quic: QuicOptions,
    #[serde(default)]
    pub masquerade: Option<Hysteria2Masquerade>,
    #[serde(default)]
    pub bbr_profile: String,
    #[serde(default)]
    pub brutal_debug: bool,
    #[serde(default)]
    pub realm: Option<Hysteria2InboundRealm>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hysteria2OutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(default)]
    pub server_ports: Listable<String>,
    #[serde(default)]
    pub hop_interval: Duration,
    #[serde(default)]
    pub hop_interval_max: Duration,
    #[serde(default)]
    pub up_mbps: i32,
    #[serde(default)]
    pub down_mbps: i32,
    #[serde(default)]
    pub obfs: Option<Hysteria2Obfs>,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub network: NetworkList,
    #[serde(default)]
    pub tls: Option<OutboundTlsOptions>,
    #[serde(flatten)]
    pub quic: QuicOptions,
    #[serde(default)]
    pub bbr_profile: String,
    #[serde(default)]
    pub brutal_debug: bool,
    #[serde(default)]
    pub disable_chrome_parrot: bool,
    #[serde(default)]
    pub realm: Option<Hysteria2Realm>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeOutboundOptions {
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub bridge_name: String,
    #[serde(default)]
    pub iproute2_table_index: i32,
    #[serde(default)]
    pub iproute2_rule_index: i32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectorOutboundOptions {
    pub outbounds: Vec<String>,
    #[serde(default)]
    pub default: String,
    #[serde(default)]
    pub interrupt_exist_connections: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlTestOutboundOptions {
    pub outbounds: Vec<String>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub interval: Duration,
    #[serde(default)]
    pub tolerance: u16,
    #[serde(default)]
    pub idle_timeout: Duration,
    #[serde(default)]
    pub interrupt_exist_connections: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksUser {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksDestination {
    pub name: String,
    pub password: String,
    #[serde(flatten)]
    pub server: ServerOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowsocksInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub network: NetworkList,
    pub method: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub users: Vec<ShadowsocksUser>,
    #[serde(default)]
    pub destinations: Vec<ShadowsocksDestination>,
    #[serde(default)]
    pub multiplex: Option<InboundMultiplexOptions>,
    #[serde(default)]
    pub managed: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct SsmApiServiceOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    pub servers: HashMap<String, String>,
    #[serde(default)]
    pub cache_path: String,
    #[serde(default)]
    pub tls: Option<InboundTlsOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http2Options {
    #[serde(default)]
    pub idle_timeout: Duration,
    #[serde(default)]
    pub keep_alive_period: Duration,
    #[serde(default)]
    pub stream_receive_window: MemoryBytes,
    #[serde(default)]
    pub connection_receive_window: MemoryBytes,
    #[serde(default)]
    pub max_concurrent_streams: i32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HysteriaRealmUser {
    pub name: String,
    pub token: String,
    #[serde(default)]
    pub max_realms: i32,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct HysteriaRealmServiceOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub tls: Option<InboundTlsOptions>,
    #[serde(flatten)]
    pub http2: Http2Options,
    pub users: Vec<HysteriaRealmUser>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowsocksOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub plugin: String,
    #[serde(default)]
    pub plugin_opts: String,
    #[serde(default)]
    pub network: NetworkList,
    #[serde(default)]
    pub udp_over_tcp: Option<UdpOverTcpOptions>,
    #[serde(default)]
    pub multiplex: Option<OutboundMultiplexOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VMessUser {
    pub name: String,
    pub uuid: String,
    #[serde(default, rename = "alterId")]
    pub alter_id: i32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlessUser {
    pub name: String,
    pub uuid: String,
    #[serde(default)]
    pub flow: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrojanUser {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnyTlsUser {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub password: String,
}

macro_rules! v2ray_inbound {
    ($name:ident, $user:ty) => {
        #[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $name {
            #[serde(flatten)]
            pub listen: ListenOptions,
            #[serde(default)]
            pub users: Vec<$user>,
            #[serde(default)]
            pub tls: Option<InboundTlsOptions>,
            #[serde(default)]
            pub multiplex: Option<InboundMultiplexOptions>,
            #[serde(default)]
            pub transport: Option<V2RayTransportOptions>,
        }
    };
}

v2ray_inbound!(VMessInboundOptions, VMessUser);
v2ray_inbound!(VlessInboundOptions, VlessUser);

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct VMessOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    pub uuid: String,
    pub security: String,
    #[serde(default)]
    pub alter_id: i32,
    #[serde(default)]
    pub global_padding: bool,
    #[serde(default)]
    pub authenticated_length: bool,
    #[serde(default)]
    pub network: NetworkList,
    #[serde(default)]
    pub tls: Option<OutboundTlsOptions>,
    #[serde(default)]
    pub packet_encoding: String,
    #[serde(default)]
    pub multiplex: Option<OutboundMultiplexOptions>,
    #[serde(default)]
    pub transport: Option<V2RayTransportOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct VlessOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    pub uuid: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub network: NetworkList,
    #[serde(default)]
    pub tls: Option<OutboundTlsOptions>,
    #[serde(default)]
    pub multiplex: Option<OutboundMultiplexOptions>,
    #[serde(default)]
    pub transport: Option<V2RayTransportOptions>,
    #[serde(default)]
    pub packet_encoding: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrojanInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub users: Vec<TrojanUser>,
    #[serde(default)]
    pub tls: Option<InboundTlsOptions>,
    #[serde(default)]
    pub fallback: Option<ServerOptions>,
    #[serde(default)]
    pub fallback_for_alpn: std::collections::HashMap<String, ServerOptions>,
    #[serde(default)]
    pub multiplex: Option<InboundMultiplexOptions>,
    #[serde(default)]
    pub transport: Option<V2RayTransportOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrojanOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    pub password: String,
    #[serde(default)]
    pub network: NetworkList,
    #[serde(default)]
    pub tls: Option<OutboundTlsOptions>,
    #[serde(default)]
    pub multiplex: Option<OutboundMultiplexOptions>,
    #[serde(default)]
    pub transport: Option<V2RayTransportOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnyTlsInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub tls: Option<InboundTlsOptions>,
    #[serde(default)]
    pub users: Vec<AnyTlsUser>,
    #[serde(default)]
    pub padding_scheme: Listable<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnyTlsOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(default)]
    pub tls: Option<OutboundTlsOptions>,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub idle_session_check_interval: Duration,
    #[serde(default)]
    pub idle_session_timeout: Duration,
    #[serde(default)]
    pub min_idle_session: i32,
    #[serde(default)]
    pub client_metadata: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowTlsOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(default)]
    pub version: i32,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub tls: Option<OutboundTlsOptions>,
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ShadowTlsWildcardSni {
    #[default]
    #[serde(alias = "")]
    Off,
    Authed,
    All,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowTlsUser {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowTlsHandshakeOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowTlsInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(default)]
    pub version: i32,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub users: Vec<ShadowTlsUser>,
    #[serde(default)]
    pub handshake: ShadowTlsHandshakeOptions,
    #[serde(default)]
    pub handshake_for_server_name: HashMap<String, ShadowTlsHandshakeOptions>,
    #[serde(default)]
    pub strict_mode: bool,
    #[serde(default)]
    pub wildcard_sni: ShadowTlsWildcardSni,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnellUser {
    #[serde(default)]
    pub name: String,
    pub userkey: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
struct RawSnellInboundOptions {
    #[serde(flatten)]
    listen: ListenOptions,
    version: i32,
    psk: String,
    #[serde(default)]
    users: Vec<SnellUser>,
    #[serde(default)]
    obfs_mode: String,
    #[serde(default)]
    mode: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawSnellInboundOptions")]
pub struct SnellInboundOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    pub version: i32,
    pub psk: String,
    #[serde(default)]
    pub users: Vec<SnellUser>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub obfs_mode: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
}

impl TryFrom<RawSnellInboundOptions> for SnellInboundOptions {
    type Error = String;

    fn try_from(value: RawSnellInboundOptions) -> Result<Self, Self::Error> {
        match value.version {
            5 if !value.mode.is_empty() => {
                return Err("snell v5 inbound does not accept mode".into());
            }
            5 if !matches!(
                value.obfs_mode.as_str(),
                "" | "none" | "http" | "tls"
            ) =>
            {
                return Err(format!(
                    "snell: unknown obfs mode: {}",
                    value.obfs_mode
                ));
            }
            5 => {}
            6 if !value.obfs_mode.is_empty() => {
                return Err("snell v6 inbound does not accept obfs_mode".into());
            }
            6 if !matches!(
                value.mode.as_str(),
                "" | "default" | "unshaped" | "unsafe-raw"
            ) =>
            {
                return Err(format!("snell: unknown v6 mode: {}", value.mode));
            }
            6 => {}
            0 => return Err("snell: missing version".into()),
            version => {
                return Err(format!("snell: unsupported version: {version}"));
            }
        }
        Ok(Self {
            listen: value.listen,
            version: value.version,
            psk: value.psk,
            users: value.users,
            obfs_mode: value.obfs_mode,
            mode: value.mode,
        })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
struct RawSnellOutboundOptions {
    #[serde(flatten)]
    dialer: DialerOptions,
    #[serde(flatten)]
    server: ServerOptions,
    version: i32,
    psk: String,
    #[serde(default)]
    userkey: String,
    #[serde(default)]
    reuse: bool,
    #[serde(default)]
    network: NetworkList,
    #[serde(default)]
    obfs_mode: String,
    #[serde(default)]
    obfs_host: String,
    #[serde(default)]
    mode: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawSnellOutboundOptions")]
pub struct SnellOutboundOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    pub version: i32,
    pub psk: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub userkey: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reuse: bool,
    #[serde(default)]
    pub network: NetworkList,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub obfs_mode: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub obfs_host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
}

impl TryFrom<RawSnellOutboundOptions> for SnellOutboundOptions {
    type Error = String;

    fn try_from(value: RawSnellOutboundOptions) -> Result<Self, Self::Error> {
        match value.version {
            4 if !value.mode.is_empty() => {
                return Err("snell v4 outbound does not accept mode".into());
            }
            4 if !matches!(
                value.obfs_mode.as_str(),
                "" | "none" | "http" | "tls"
            ) =>
            {
                return Err(format!(
                    "snell: unknown obfs mode: {}",
                    value.obfs_mode
                ));
            }
            4 => {}
            6 if !value.obfs_mode.is_empty() || !value.obfs_host.is_empty() => {
                return Err(
                    "snell v6 outbound does not accept obfs options".into()
                );
            }
            6 if !matches!(
                value.mode.as_str(),
                "" | "default" | "unshaped" | "unsafe-raw"
            ) =>
            {
                return Err(format!("snell: unknown v6 mode: {}", value.mode));
            }
            6 => {}
            0 => return Err("snell: missing version".into()),
            version => {
                return Err(format!("snell: unsupported version: {version}"));
            }
        }
        Ok(Self {
            dialer: value.dialer,
            server: value.server,
            version: value.version,
            psk: value.psk,
            userkey: value.userkey,
            reuse: value.reuse,
            network: value.network,
            obfs_mode: value.obfs_mode,
            obfs_host: value.obfs_host,
            mode: value.mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        Hysteria2InboundOptions, Hysteria2Masquerade,
        Hysteria2MasqueradeObject, Hysteria2Obfs, Hysteria2OutboundOptions,
        HysteriaInboundOptions, HysteriaOutboundOptions, NaiveInboundOptions,
        NaiveOutboundOptions, ShadowTlsInboundOptions, ShadowTlsWildcardSni,
        SnellInboundOptions, SnellOutboundOptions, SocksOutboundOptions,
        SshOutboundOptions, TorOutboundOptions, TuicInboundOptions,
        TuicOutboundOptions, TunInboundOptions, UdpNatBehavior,
        UdpOverTcpOptions, VMessOutboundOptions,
    };
    use crate::option::{Network, TaggedOptions};

    #[test]
    fn udp_over_tcp_supports_boolean_and_versioned_forms() {
        let simple: UdpOverTcpOptions = serde_json::from_str("true").unwrap();
        assert!(simple.enabled);
        let versioned: UdpOverTcpOptions =
            serde_json::from_str(r#"{"enabled":true,"version":1}"#).unwrap();
        assert_eq!(versioned.version, 1);
        assert!(
            serde_json::from_str::<UdpOverTcpOptions>(
                r#"{"enabled":true,"version":3}"#
            )
            .is_err()
        );
    }

    #[test]
    fn tagged_options_decode_to_protocol_type() {
        let tagged: TaggedOptions = serde_json::from_value(json!({
            "type": "socks",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": 1080,
            "version": "5"
        }))
        .unwrap();
        let options: SocksOutboundOptions = tagged.decode().unwrap();
        assert_eq!(options.server.server_port, 1080);
        assert_eq!(options.version, "5");
    }

    #[test]
    fn tun_options_decode_the_full_upstream_surface() {
        let options: TunInboundOptions = serde_json::from_str(
            r#"{
                "interface_name":"tun0","netns":"ns0","mtu":9000,
                "address":["10.14.14.9/30","fdfe:dcba:9876::1/126"],
                "dns_mode":"native",
                "dns_address":["10.14.14.10","fdfe:dcba:9876::2"],
                "auto_route":true,"iproute2_table_index":2022,
                "iproute2_rule_index":9000,"auto_redirect":true,
                "auto_redirect_input_mark":"0x2023",
                "auto_redirect_output_mark":8224,
                "auto_redirect_reset_mark":"0x2025",
                "auto_redirect_nfqueue":8123,
                "auto_redirect_iproute2_fallback_rule_index":32768,
                "exclude_mptcp":true,
                "loopback_address":["10.7.0.1","fd00::1"],
                "strict_route":true,
                "route_address":["0.0.0.0/1","8000::/1"],
                "route_address_set":["geoip-cn"],
                "route_exclude_address":["192.168.0.0/16"],
                "route_exclude_address_set":["private"],
                "include_interface":["en0"],"exclude_interface":["utun3"],
                "include_uid":[501],"include_uid_range":["1000:2000"],
                "exclude_uid":[0],"exclude_uid_range":["3000:4000"],
                "include_android_user":[0,10],
                "include_package":["dev.zay"],
                "exclude_package":["com.example.direct"],
                "include_mac_address":["00:11:22:33:44:55"],
                "exclude_mac_address":["aa:bb:cc:dd:ee:ff"],
                "udp_timeout":"2m","udp_mapping":"address_dependent",
                "udp_filtering":"address_and_port_dependent",
                "udp_nat_max":4096,"stack":"gvisor",
                "platform":{"http_proxy":{
                    "enabled":true,"server":"127.0.0.1","server_port":8080,
                    "bypass_domain":["localhost"],"match_domain":["example.com"]
                }}
            }"#,
        )
        .unwrap();
        assert_eq!(options.address.as_slice().len(), 2);
        assert_eq!(options.auto_redirect_input_mark.0, 0x2023);
        assert_eq!(options.auto_redirect_output_mark.0, 8224);
        assert_eq!(options.udp_mapping, UdpNatBehavior::AddressDependent);
        assert_eq!(options.udp_timeout.0.as_nanos(), 120_000_000_000);
        assert_eq!(
            options
                .platform
                .unwrap()
                .http_proxy
                .unwrap()
                .server
                .server_port,
            8080
        );
    }

    #[test]
    fn tuic_options_decode_users_modes_and_quic_fields() {
        let inbound: TuicInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1", "listen_port":443,
            "users":[{
                "name":"alice",
                "uuid":"059032a9-7d40-4a96-9bb1-36823d848068",
                "password":"secret"
            }],
            "congestion_control":"cubic", "auth_timeout":"3s",
            "zero_rtt_handshake":false, "heartbeat":"10s",
            "stream_receive_window":"4MB",
            "tls":{"enabled":true,"certificate":"cert.pem","key":"key.pem"}
        }))
        .unwrap();
        assert_eq!(inbound.users[0].name, "alice");
        assert_eq!(inbound.auth_timeout.to_string(), "3s");
        assert_eq!(inbound.quic.stream_receive_window.0, 4 * 1024 * 1024);

        let outbound: TuicOutboundOptions = serde_json::from_value(json!({
            "server":"example.com", "server_port":443,
            "uuid":"059032a9-7d40-4a96-9bb1-36823d848068",
            "password":"secret", "udp_relay_mode":"quic",
            "network":["tcp","udp"], "heartbeat":"10s",
            "tls":{"enabled":true,"server_name":"example.com"}
        }))
        .unwrap();
        assert_eq!(outbound.udp_relay_mode, "quic");
        assert_eq!(outbound.server.server_port, 443);
    }

    #[test]
    fn naive_options_decode_users_headers_and_uot() {
        let inbound: NaiveInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1", "listen_port":443,
            "users":[{"username":"alice","password":"secret"}],
            "network":["tcp","udp"],
            "tls":{"enabled":true,"certificate":"cert.pem","key":"key.pem"}
        }))
        .unwrap();
        assert_eq!(inbound.users[0].username, "alice");
        assert_eq!(inbound.network.build(), &[Network::Tcp, Network::Udp]);

        let outbound: NaiveOutboundOptions = serde_json::from_value(json!({
            "server":"proxy.example", "server_port":443,
            "username":"alice", "password":"secret",
            "extra_headers":{"X-Test":["one","two"]},
            "udp_over_tcp":{"enabled":true,"version":2},
            "tls":{"enabled":true,"server_name":"proxy.example"}
        }))
        .unwrap();
        assert_eq!(
            outbound.extra_headers["X-Test"].as_slice(),
            &["one", "two"]
        );
        assert_eq!(outbound.udp_over_tcp.unwrap().version, 2);
    }

    #[test]
    fn ssh_options_decode_keys_and_algorithms() {
        let options: SshOutboundOptions = serde_json::from_value(json!({
            "server":"ssh.example", "server_port":2222,
            "user":"alice", "password":"secret",
            "private_key":["line1","line2"],
            "private_key_passphrase":"passphrase",
            "host_key":"ssh-ed25519 AAAA",
            "host_key_algorithms":["ssh-ed25519"],
            "client_version":"SSH-2.0-OpenSSH_8.9",
            "cipher":"aes128-ctr",
            "mac":"hmac-sha2-256",
            "kex_algorithm":"curve25519-sha256"
        }))
        .unwrap();
        assert_eq!(options.server.server_port, 2222);
        assert_eq!(options.private_key.as_slice(), &["line1", "line2"]);
        assert_eq!(options.cipher.as_slice(), &["aes128-ctr"]);
    }

    #[test]
    fn tor_options_decode_native_and_legacy_fields() {
        let options: TorOutboundOptions = serde_json::from_value(json!({
            "detour":"proxy",
            "executable_path":"/usr/bin/tor",
            "extra_args":["--UseBridges", "0"],
            "data_directory":"$HOME/.cache/sing-box/tor",
            "torrc":{"NewCircuitPeriod":"30"}
        }))
        .unwrap();
        assert_eq!(options.dialer.detour, "proxy");
        assert_eq!(options.extra_args.len(), 2);
        assert_eq!(options.torrc["NewCircuitPeriod"], "30");
    }

    #[test]
    fn shadowtls_inbound_decodes_users_sni_map_and_wildcard_mode() {
        let options: ShadowTlsInboundOptions = serde_json::from_value(json!({
            "version": 3,
            "users": [{"name":"alice", "password":"secret"}],
            "handshake": {"server":"default.example", "server_port":443},
            "handshake_for_server_name": {
                "special.example": {"server":"127.0.0.1", "server_port":8443}
            },
            "strict_mode": true,
            "wildcard_sni": "authed"
        }))
        .unwrap();
        assert_eq!(options.wildcard_sni, ShadowTlsWildcardSni::Authed);
        assert_eq!(options.users[0].name, "alice");
        assert_eq!(
            options.handshake_for_server_name["special.example"]
                .server
                .server_port,
            8443
        );
    }

    #[test]
    fn vmess_outbound_decodes_nested_transport_and_tls() {
        let options: VMessOutboundOptions = serde_json::from_value(json!({
            "server": "example.com",
            "server_port": 443,
            "uuid": "00000000-0000-0000-0000-000000000000",
            "security": "auto",
            "tls": {"enabled": true, "server_name": "example.com"},
            "transport": {"type": "ws", "path": "/socket"}
        }))
        .unwrap();
        assert_eq!(options.server.server, "example.com");
        assert!(options.tls.unwrap().enabled);
    }

    #[test]
    fn snell_options_enforce_version_specific_fields() {
        let inbound: SnellInboundOptions = serde_json::from_value(json!({
            "version": 5,
            "listen": "127.0.0.1",
            "listen_port": 8010,
            "psk": "secret",
            "obfs_mode": "http",
            "users": [{"name": "first", "userkey": "key"}]
        }))
        .unwrap();
        assert_eq!(inbound.version, 5);
        assert_eq!(inbound.users[0].userkey, "key");

        let outbound: SnellOutboundOptions = serde_json::from_value(json!({
            "version": 6,
            "server": "server.example",
            "server_port": 8010,
            "psk": "secret",
            "mode": "unshaped"
        }))
        .unwrap();
        assert_eq!(outbound.mode, "unshaped");
        assert!(
            serde_json::from_value::<SnellInboundOptions>(json!({
                "version": 5,
                "psk": "secret",
                "mode": "unsafe-raw"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<SnellOutboundOptions>(json!({
                "version": 7,
                "server": "server.example",
                "server_port": 8010,
                "psk": "secret"
            }))
            .is_err()
        );
    }

    #[test]
    fn hysteria2_options_decode_tagged_obfs_quic_and_masquerade() {
        let inbound: Hysteria2InboundOptions = serde_json::from_value(json!({
            "listen":"::", "listen_port":443,
            "users":[{"name":"alice","password":"secret"}],
            "obfs":{"type":"gecko","password":"cover","min_packet_size":600,"max_packet_size":1300},
            "stream_receive_window":"4MB",
            "connection_receive_window":"16MB",
            "masquerade":{"type":"string","status_code":404,"headers":{"x-test":"yes"},"content":"not found"},
            "tls":{"enabled":true,"certificate":"cert.pem","key":"key.pem"}
        }))
        .unwrap();
        assert_eq!(inbound.quic.stream_receive_window.value(), 4 * 1024 * 1024);
        assert!(matches!(inbound.obfs, Some(Hysteria2Obfs::Gecko { .. })));
        assert!(matches!(
            inbound.masquerade,
            Some(Hysteria2Masquerade::Object(
                Hysteria2MasqueradeObject::String { .. }
            ))
        ));

        let outbound: Hysteria2OutboundOptions =
            serde_json::from_value(json!({
                "server":"example.com", "server_port":443,
                "server_ports":["20000:30000", "443"],
                "password":"secret", "network":["tcp","udp"],
                "obfs":{"type":"salamander","password":"cover"},
                "tls":{"enabled":true,"server_name":"example.com"}
            }))
            .unwrap();
        assert_eq!(outbound.server_ports.as_slice().len(), 2);
        assert_eq!(outbound.obfs.unwrap().password(), "cover");
        assert!(
            serde_json::from_value::<Hysteria2OutboundOptions>(json!({
                "obfs":{"type":"unknown","password":"x"}
            }))
            .is_err()
        );
    }

    #[test]
    fn hysteria_options_decode_rates_and_binary_auth() {
        let inbound: HysteriaInboundOptions = serde_json::from_value(json!({
            "listen":"::", "listen_port":443,
            "up":"8Mbps", "down_mbps":20,
            "users":[{"name":"alice","auth":"c2VjcmV0"}],
            "obfs":"cover",
            "tls":{"enabled":true,"certificate":"cert.pem","key":"key.pem"}
        }))
        .unwrap();
        assert_eq!(inbound.up.unwrap().value(), 1_000_000);
        assert_eq!(inbound.users[0].password(), "secret");

        let outbound: HysteriaOutboundOptions = serde_json::from_value(json!({
            "server":"example.com", "server_port":443,
            "up_mbps":10, "down":"16Mbps",
            "auth":"aWdub3JlZA==", "auth_str":"preferred",
            "network":["tcp","udp"],
            "tls":{"enabled":true}
        }))
        .unwrap();
        assert_eq!(outbound.down.unwrap().value(), 2_000_000);
        assert_eq!(outbound.password(), "preferred");
    }
}
