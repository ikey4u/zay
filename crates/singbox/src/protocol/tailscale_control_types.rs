//! Strongly typed Tailscale control-plane messages and incremental netmap.
//!
//! Field names intentionally follow `tailcfg`'s Go JSON wire format. Unknown
//! top-level and node/DERP fields are retained so newer control servers can be
//! used while this library upgrades its typed surface.

use std::{collections::BTreeMap, fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

pub const TAILSCALE_REGISTER_PATH: &str = "/machine/register";
pub const TAILSCALE_MAP_PATH: &str = "/machine/map";
pub const TAILSCALE_SET_DNS_PATH: &str = "/machine/set-dns";
pub const TAILSCALE_TKA_BOOTSTRAP_PATH: &str = "/machine/tka/bootstrap";
pub const TAILSCALE_TKA_SYNC_OFFER_PATH: &str = "/machine/tka/sync/offer";
pub const TAILSCALE_TKA_SYNC_SEND_PATH: &str = "/machine/tka/sync/send";
pub const TAILSCALE_REGISTER_RESPONSE_LIMIT: usize = 1 << 20;
pub const TAILSCALE_SET_DNS_RESPONSE_LIMIT: usize = 1 << 20;
pub const TAILSCALE_TKA_BOOTSTRAP_RESPONSE_LIMIT: usize = 1 << 20;
pub const TAILSCALE_TKA_SYNC_RESPONSE_LIMIT: usize = 10 << 20;
pub const TAILSCALE_MAP_COMPRESSED_FRAME_LIMIT: usize = 16 << 20;
pub const TAILSCALE_MAP_DECODED_FRAME_LIMIT: usize = 64 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid {kind}: expected {prefix} followed by 64 hexadecimal digits")]
pub struct TailscaleKeyParseError {
    kind: &'static str,
    prefix: &'static str,
}

macro_rules! tailscale_key {
    ($name:ident, $prefix:literal, $kind:literal) => {
        #[derive(
            Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash,
        )]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub fn is_zero(&self) -> bool {
                self.0 == [0; 32]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}{}", $prefix, hex::encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = TailscaleKeyParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let raw = value.strip_prefix($prefix).ok_or(
                    TailscaleKeyParseError {
                        kind: $kind,
                        prefix: $prefix,
                    },
                )?;
                let mut bytes = [0_u8; 32];
                hex::decode_to_slice(raw, &mut bytes).map_err(|_| {
                    TailscaleKeyParseError {
                        kind: $kind,
                        prefix: $prefix,
                    }
                })?;
                Ok(Self(bytes))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

tailscale_key!(TailscaleNodePublicKey, "nodekey:", "node public key");
tailscale_key!(TailscaleMachinePublicKey, "mkey:", "machine public key");
tailscale_key!(TailscaleDiscoPublicKey, "discokey:", "disco public key");
tailscale_key!(
    TailscaleNetworkLockPublicKey,
    "nlpub:",
    "network-lock public key"
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TailscaleTimestamp(pub String);

impl Default for TailscaleTimestamp {
    fn default() -> Self {
        Self("0001-01-01T00:00:00Z".into())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleRegisterResponseAuth {
    #[serde(
        rename = "Oauth2Token",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub oauth2_token: Option<Value>,
    #[serde(
        rename = "AuthKey",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub auth_key: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleService {
    #[serde(rename = "Proto", default)]
    pub protocol: String,
    #[serde(rename = "Port", default)]
    pub port: u16,
    #[serde(rename = "Description", default)]
    pub description: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleHostinfo {
    #[serde(
        rename = "IPNVersion",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub ipn_version: String,
    #[serde(
        rename = "FrontendLogID",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub frontend_log_id: String,
    #[serde(
        rename = "BackendLogID",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub backend_log_id: String,
    #[serde(rename = "OS", default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(
        rename = "OSVersion",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub os_version: String,
    #[serde(rename = "Env", default, skip_serializing_if = "String::is_empty")]
    pub environment: String,
    #[serde(
        rename = "Distro",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub distro: String,
    #[serde(
        rename = "DistroVersion",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub distro_version: String,
    #[serde(
        rename = "DistroCodeName",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub distro_code_name: String,
    #[serde(rename = "App", default, skip_serializing_if = "String::is_empty")]
    pub app: String,
    #[serde(
        rename = "Package",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub package: String,
    #[serde(
        rename = "DeviceModel",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub device_model: String,
    #[serde(
        rename = "Hostname",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub hostname: String,
    #[serde(rename = "ShieldsUp", default, skip_serializing_if = "is_false")]
    pub shields_up: bool,
    #[serde(rename = "ShareeNode", default, skip_serializing_if = "is_false")]
    pub sharee_node: bool,
    #[serde(
        rename = "NoLogsNoSupport",
        default,
        skip_serializing_if = "is_false"
    )]
    pub no_logs_no_support: bool,
    #[serde(rename = "WireIngress", default, skip_serializing_if = "is_false")]
    pub wire_ingress: bool,
    #[serde(
        rename = "IngressEnabled",
        default,
        skip_serializing_if = "is_false"
    )]
    pub ingress_enabled: bool,
    #[serde(
        rename = "AllowsUpdate",
        default,
        skip_serializing_if = "is_false"
    )]
    pub allows_update: bool,
    #[serde(
        rename = "Machine",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub machine: String,
    #[serde(
        rename = "GoArch",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub go_arch: String,
    #[serde(
        rename = "GoArchVar",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub go_arch_var: String,
    #[serde(
        rename = "GoVersion",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub go_version: String,
    #[serde(
        rename = "RoutableIPs",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub routable_ips: Vec<String>,
    #[serde(
        rename = "RequestTags",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub request_tags: Vec<String>,
    #[serde(
        rename = "WoLMACs",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub wake_on_lan_macs: Vec<String>,
    #[serde(
        rename = "sshHostKeys",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ssh_host_keys: Vec<String>,
    #[serde(
        rename = "Cloud",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub cloud: String,
    #[serde(
        rename = "ExitNodeID",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub exit_node_id: String,
    #[serde(
        rename = "Services",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub services: Vec<TailscaleService>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleRegisterRequest {
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "NodeKey")]
    pub node_key: TailscaleNodePublicKey,
    #[serde(rename = "OldNodeKey", default)]
    pub old_node_key: TailscaleNodePublicKey,
    #[serde(rename = "NLKey", default)]
    pub network_lock_key: TailscaleNetworkLockPublicKey,
    #[serde(rename = "Auth", default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<TailscaleRegisterResponseAuth>,
    #[serde(rename = "Expiry", default)]
    pub expiry: TailscaleTimestamp,
    #[serde(rename = "Followup", default)]
    pub followup: String,
    #[serde(rename = "Hostinfo", default)]
    pub hostinfo: Option<TailscaleHostinfo>,
    #[serde(rename = "Ephemeral", default, skip_serializing_if = "is_false")]
    pub ephemeral: bool,
    #[serde(
        rename = "NodeKeySignature",
        default,
        with = "optional_base64_bytes"
    )]
    pub node_key_signature: Option<Vec<u8>>,
    #[serde(
        rename = "SignatureType",
        default,
        skip_serializing_if = "is_zero_i32"
    )]
    pub signature_type: i32,
    #[serde(
        rename = "Timestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub timestamp: Option<String>,
    #[serde(
        rename = "DeviceCert",
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "base64_bytes"
    )]
    pub device_cert: Vec<u8>,
    #[serde(
        rename = "Signature",
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "base64_bytes"
    )]
    pub signature: Vec<u8>,
    #[serde(
        rename = "Tailnet",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub tailnet: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleUser {
    #[serde(rename = "ID", default)]
    pub id: i64,
    #[serde(rename = "DisplayName", default)]
    pub display_name: String,
    #[serde(rename = "ProfilePicURL", default)]
    pub profile_pic_url: String,
    #[serde(rename = "Created", default)]
    pub created: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleLogin {
    #[serde(rename = "ID", default)]
    pub id: i64,
    #[serde(rename = "Provider", default)]
    pub provider: String,
    #[serde(rename = "LoginName", default)]
    pub login_name: String,
    #[serde(rename = "DisplayName", default)]
    pub display_name: String,
    #[serde(rename = "ProfilePicURL", default)]
    pub profile_pic_url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleRegisterResponse {
    #[serde(rename = "User", default)]
    pub user: TailscaleUser,
    #[serde(rename = "Login", default)]
    pub login: TailscaleLogin,
    #[serde(rename = "NodeKeyExpired", default)]
    pub node_key_expired: bool,
    #[serde(rename = "MachineAuthorized", default)]
    pub machine_authorized: bool,
    #[serde(rename = "AuthURL", default)]
    pub auth_url: String,
    #[serde(
        rename = "NodeKeySignature",
        default,
        with = "optional_base64_bytes"
    )]
    pub node_key_signature: Option<Vec<u8>>,
    #[serde(rename = "Error", default)]
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleMapRequest {
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(
        rename = "Compress",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub compress: String,
    #[serde(rename = "KeepAlive", default, skip_serializing_if = "is_false")]
    pub keep_alive: bool,
    #[serde(rename = "NodeKey")]
    pub node_key: TailscaleNodePublicKey,
    #[serde(rename = "DiscoKey", default)]
    pub disco_key: TailscaleDiscoPublicKey,
    #[serde(
        rename = "HardwareAttestationKey",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub hardware_attestation_key: String,
    #[serde(
        rename = "HardwareAttestationKeySignature",
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "base64_bytes"
    )]
    pub hardware_attestation_key_signature: Vec<u8>,
    #[serde(
        rename = "HardwareAttestationKeySignatureTimestamp",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub hardware_attestation_key_signature_timestamp: String,
    #[serde(rename = "Stream", default, skip_serializing_if = "is_false")]
    pub stream: bool,
    #[serde(rename = "Hostinfo", default)]
    pub hostinfo: Option<TailscaleHostinfo>,
    #[serde(
        rename = "MapSessionHandle",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub map_session_handle: String,
    #[serde(
        rename = "MapSessionSeq",
        default,
        skip_serializing_if = "is_zero_i64"
    )]
    pub map_session_seq: i64,
    #[serde(
        rename = "Endpoints",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub endpoints: Vec<String>,
    #[serde(
        rename = "EndpointTypes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub endpoint_types: Vec<i32>,
    #[serde(
        rename = "TKAHead",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub tka_head: String,
    #[serde(rename = "ReadOnly", default, skip_serializing_if = "is_false")]
    pub read_only: bool,
    #[serde(rename = "OmitPeers", default, skip_serializing_if = "is_false")]
    pub omit_peers: bool,
    #[serde(
        rename = "DebugFlags",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub debug_flags: Vec<String>,
    #[serde(
        rename = "ConnectionHandleForTest",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub connection_handle_for_test: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleNode {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(rename = "StableID", default)]
    pub stable_id: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "User", default)]
    pub user: i64,
    #[serde(rename = "Sharer", default)]
    pub sharer: i64,
    #[serde(rename = "Key", default)]
    pub key: TailscaleNodePublicKey,
    #[serde(rename = "KeyExpiry", default)]
    pub key_expiry: String,
    #[serde(rename = "KeySignature", default, with = "base64_bytes")]
    pub key_signature: Vec<u8>,
    #[serde(rename = "Machine", default)]
    pub machine: TailscaleMachinePublicKey,
    #[serde(rename = "DiscoKey", default)]
    pub disco_key: TailscaleDiscoPublicKey,
    #[serde(rename = "Addresses", default)]
    pub addresses: Vec<String>,
    #[serde(rename = "AllowedIPs", default)]
    pub allowed_ips: Vec<String>,
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Vec<String>,
    #[serde(rename = "DERP", default)]
    pub legacy_derp: String,
    #[serde(rename = "HomeDERP", default)]
    pub home_derp: i32,
    #[serde(rename = "Hostinfo", default)]
    pub hostinfo: Option<TailscaleHostinfo>,
    #[serde(rename = "Created", default)]
    pub created: String,
    #[serde(rename = "Cap", default)]
    pub capability_version: u32,
    #[serde(rename = "Tags", default)]
    pub tags: Vec<String>,
    #[serde(rename = "PrimaryRoutes", default)]
    pub primary_routes: Vec<String>,
    #[serde(rename = "LastSeen", default)]
    pub last_seen: Option<String>,
    #[serde(rename = "Online", default)]
    pub online: Option<bool>,
    #[serde(rename = "MachineAuthorized", default)]
    pub machine_authorized: bool,
    #[serde(rename = "Capabilities", default)]
    pub capabilities: Vec<String>,
    #[serde(rename = "CapMap", default)]
    pub capability_map: BTreeMap<String, Vec<Value>>,
    #[serde(rename = "UnsignedPeerAPIOnly", default)]
    pub unsigned_peer_api_only: bool,
    #[serde(rename = "Expired", default)]
    pub expired: bool,
    #[serde(rename = "IsWireGuardOnly", default)]
    pub is_wireguard_only: bool,
    #[serde(rename = "ExitNodeDNSResolvers", default)]
    pub exit_node_dns_resolvers: Vec<TailscaleDnsResolver>,
    #[serde(rename = "IsJailed", default)]
    pub is_jailed: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscalePeerChange {
    #[serde(rename = "NodeID")]
    pub node_id: i64,
    #[serde(rename = "DERPRegion", default)]
    pub derp_region: i32,
    #[serde(rename = "Cap", default)]
    pub capability_version: u32,
    #[serde(rename = "CapMap", default)]
    pub capability_map: Option<BTreeMap<String, Vec<Value>>>,
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Option<Vec<String>>,
    #[serde(rename = "Key", default)]
    pub key: Option<TailscaleNodePublicKey>,
    #[serde(rename = "KeySignature", default, with = "optional_base64_bytes")]
    pub key_signature: Option<Vec<u8>>,
    #[serde(rename = "DiscoKey", default)]
    pub disco_key: Option<TailscaleDiscoPublicKey>,
    #[serde(rename = "Online", default)]
    pub online: Option<bool>,
    #[serde(rename = "LastSeen", default)]
    pub last_seen: Option<String>,
    #[serde(rename = "KeyExpiry", default)]
    pub key_expiry: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleDerpMap {
    #[serde(rename = "HomeParams", default)]
    pub home_params: Option<TailscaleDerpHomeParams>,
    #[serde(rename = "Regions", default)]
    pub regions: Option<BTreeMap<i32, TailscaleDerpRegion>>,
    #[serde(rename = "omitDefaultRegions", default)]
    pub omit_default_regions: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleDerpHomeParams {
    #[serde(rename = "RegionScore", default)]
    pub region_score: Option<BTreeMap<i32, f64>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleDerpRegion {
    #[serde(rename = "RegionID", default)]
    pub region_id: i32,
    #[serde(rename = "RegionCode", default)]
    pub region_code: String,
    #[serde(rename = "RegionName", default)]
    pub region_name: String,
    #[serde(rename = "Latitude", default)]
    pub latitude: f64,
    #[serde(rename = "Longitude", default)]
    pub longitude: f64,
    #[serde(rename = "Avoid", default)]
    pub avoid: bool,
    #[serde(rename = "NoMeasureNoHome", default)]
    pub no_measure_no_home: bool,
    #[serde(rename = "Nodes", default)]
    pub nodes: Vec<TailscaleDerpNode>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleDerpNode {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "RegionID", default)]
    pub region_id: i32,
    #[serde(rename = "HostName", default)]
    pub host_name: String,
    #[serde(rename = "CertName", default)]
    pub cert_name: String,
    #[serde(rename = "IPv4", default)]
    pub ipv4: String,
    #[serde(rename = "IPv6", default)]
    pub ipv6: String,
    #[serde(rename = "STUNPort", default)]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly", default)]
    pub stun_only: bool,
    #[serde(rename = "DERPPort", default)]
    pub derp_port: i32,
    #[serde(rename = "CanPort80", default)]
    pub can_port_80: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscalePortRange {
    #[serde(rename = "First", default)]
    pub first: u16,
    #[serde(rename = "Last", default)]
    pub last: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleNetPortRange {
    #[serde(rename = "IP", default)]
    pub ip: String,
    #[serde(rename = "Bits", default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<i32>,
    #[serde(rename = "Ports", default)]
    pub ports: TailscalePortRange,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleCapabilityGrant {
    #[serde(rename = "Dsts", default)]
    pub destinations: Vec<String>,
    #[serde(rename = "Caps", default)]
    pub capabilities: Vec<String>,
    #[serde(rename = "CapMap", default)]
    pub capability_map: BTreeMap<String, Vec<Value>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleFilterRule {
    #[serde(rename = "SrcIPs", default)]
    pub source_ips: Vec<String>,
    #[serde(rename = "SrcBits", default)]
    pub source_bits: Vec<i32>,
    #[serde(rename = "DstPorts", default)]
    pub destination_ports: Vec<TailscaleNetPortRange>,
    #[serde(rename = "IPProto", default)]
    pub ip_protocols: Vec<i32>,
    #[serde(rename = "CapGrant", default)]
    pub capability_grants: Vec<TailscaleCapabilityGrant>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleDnsResolver {
    #[serde(rename = "Addr", default)]
    pub address: String,
    #[serde(rename = "BootstrapResolution", default)]
    pub bootstrap_resolution: Vec<String>,
    #[serde(rename = "UseWithExitNode", default)]
    pub use_with_exit_node: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleDnsRecord {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Type", default)]
    pub record_type: String,
    #[serde(rename = "Value", default)]
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleDnsConfig {
    #[serde(rename = "Resolvers", default)]
    pub resolvers: Vec<TailscaleDnsResolver>,
    #[serde(rename = "Routes", default)]
    pub routes: BTreeMap<String, Vec<TailscaleDnsResolver>>,
    #[serde(rename = "FallbackResolvers", default)]
    pub fallback_resolvers: Vec<TailscaleDnsResolver>,
    #[serde(rename = "Domains", default)]
    pub domains: Vec<String>,
    #[serde(rename = "Proxied", default)]
    pub proxied: bool,
    #[serde(rename = "Nameservers", default)]
    pub nameservers: Vec<String>,
    #[serde(rename = "CertDomains", default)]
    pub certificate_domains: Vec<String>,
    #[serde(rename = "ExtraRecords", default)]
    pub extra_records: Vec<TailscaleDnsRecord>,
    #[serde(rename = "ExitNodeFilteredSet", default)]
    pub exit_node_filtered_set: Vec<String>,
    #[serde(rename = "TempCorpIssue13969", default)]
    pub temporary_corp_issue_13969: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscalePingRequest {
    #[serde(rename = "URL", default)]
    pub url: String,
    #[serde(rename = "URLIsNoise", default)]
    pub url_is_noise: bool,
    #[serde(rename = "Log", default)]
    pub log: bool,
    #[serde(rename = "Types", default)]
    pub types: String,
    #[serde(rename = "IP", default)]
    pub ip: String,
    #[serde(rename = "Payload", default, with = "base64_bytes")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleDisplayMessageAction {
    #[serde(rename = "URL", default)]
    pub url: String,
    #[serde(rename = "Label", default)]
    pub label: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleDisplayMessage {
    #[serde(rename = "Title", default)]
    pub title: String,
    #[serde(rename = "Text", default)]
    pub text: String,
    #[serde(rename = "Severity", default)]
    pub severity: String,
    #[serde(rename = "ImpactsConnectivity", default)]
    pub impacts_connectivity: bool,
    #[serde(rename = "PrimaryAction", default)]
    pub primary_action: Option<TailscaleDisplayMessageAction>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleControlIpCandidate {
    #[serde(rename = "IP", default)]
    pub ip: String,
    #[serde(rename = "ACEHost", default)]
    pub ace_host: String,
    #[serde(rename = "DialStartDelaySec", default)]
    pub dial_start_delay_seconds: f64,
    #[serde(rename = "DialTimeoutSec", default)]
    pub dial_timeout_seconds: f64,
    #[serde(rename = "Priority", default)]
    pub priority: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleControlDialPlan {
    #[serde(rename = "Candidates", default)]
    pub candidates: Vec<TailscaleControlIpCandidate>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleClientVersion {
    #[serde(rename = "RunningLatest", default)]
    pub running_latest: bool,
    #[serde(rename = "LatestVersion", default)]
    pub latest_version: String,
    #[serde(rename = "UrgentSecurityUpdate", default)]
    pub urgent_security_update: bool,
    #[serde(rename = "Notify", default)]
    pub notify: bool,
    #[serde(rename = "NotifyURL", default)]
    pub notify_url: String,
    #[serde(rename = "NotifyText", default)]
    pub notify_text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleSshPrincipal {
    #[serde(rename = "node", default)]
    pub node: String,
    #[serde(rename = "nodeIP", default)]
    pub node_ip: String,
    #[serde(rename = "userLogin", default)]
    pub user_login: String,
    #[serde(rename = "any", default)]
    pub any: bool,
    #[serde(rename = "pubKeys", default)]
    pub deprecated_public_keys: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleSshRecorderFailureAction {
    #[serde(rename = "RejectSessionWithMessage", default)]
    pub reject_session_with_message: String,
    #[serde(rename = "TerminateSessionWithMessage", default)]
    pub terminate_session_with_message: String,
    #[serde(rename = "NotifyURL", default)]
    pub notify_url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleSshAction {
    #[serde(rename = "message", default)]
    pub message: String,
    #[serde(rename = "reject", default)]
    pub reject: bool,
    #[serde(rename = "accept", default)]
    pub accept: bool,
    #[serde(rename = "sessionDuration", default)]
    pub session_duration_nanoseconds: i64,
    #[serde(rename = "allowAgentForwarding", default)]
    pub allow_agent_forwarding: bool,
    #[serde(rename = "holdAndDelegate", default)]
    pub hold_and_delegate: String,
    #[serde(rename = "allowLocalPortForwarding", default)]
    pub allow_local_port_forwarding: bool,
    #[serde(rename = "allowRemotePortForwarding", default)]
    pub allow_remote_port_forwarding: bool,
    #[serde(rename = "recorders", default)]
    pub recorders: Vec<String>,
    #[serde(rename = "onRecordingFailure", default)]
    pub on_recording_failure: Option<TailscaleSshRecorderFailureAction>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleSshRule {
    #[serde(rename = "ruleExpires", default)]
    pub rule_expires: Option<String>,
    #[serde(rename = "principals", default)]
    pub principals: Vec<TailscaleSshPrincipal>,
    #[serde(rename = "sshUsers", default)]
    pub ssh_users: BTreeMap<String, String>,
    #[serde(rename = "action", default)]
    pub action: Option<TailscaleSshAction>,
    #[serde(rename = "acceptEnv", default)]
    pub accept_environment: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleSshPolicy {
    #[serde(rename = "rules", default)]
    pub rules: Vec<TailscaleSshRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleTkaInfo {
    #[serde(rename = "Head", default)]
    pub head: String,
    #[serde(rename = "Disabled", default)]
    pub disabled: bool,
}

/// Request used by a node to publish the TXT value for an ACME DNS-01
/// challenge. The control plane only accepts names derived from one of the
/// node's `DNSConfig.CertDomains` entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleSetDnsRequest {
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "NodeKey")]
    pub node_key: TailscaleNodePublicKey,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Type")]
    pub record_type: String,
    #[serde(rename = "Value")]
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleSetDnsResponse {}

/// Request used to reconcile whether tailnet lock is enabled locally and by
/// control. Tailscale intentionally sends these JSON RPCs as HTTP GET requests
/// with a body over the authenticated TS2021 connection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleTkaBootstrapRequest {
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "NodeKey")]
    pub node_key: TailscaleNodePublicKey,
    #[serde(rename = "Head", default)]
    pub head: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleTkaBootstrapResponse {
    #[serde(
        rename = "GenesisAUM",
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "base64_bytes"
    )]
    pub genesis_aum: Vec<u8>,
    #[serde(
        rename = "DisablementSecret",
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "base64_bytes"
    )]
    pub disablement_secret: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleTkaSyncOfferRequest {
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "NodeKey")]
    pub node_key: TailscaleNodePublicKey,
    #[serde(rename = "Head")]
    pub head: String,
    #[serde(rename = "Ancestors")]
    pub ancestors: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleTkaSyncOfferResponse {
    #[serde(rename = "Head")]
    pub head: String,
    #[serde(rename = "Ancestors")]
    pub ancestors: Vec<String>,
    #[serde(rename = "MissingAUMs", default, with = "base64_byte_arrays")]
    pub missing_aums: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleTkaSyncSendRequest {
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "NodeKey")]
    pub node_key: TailscaleNodePublicKey,
    #[serde(rename = "Head")]
    pub head: String,
    #[serde(rename = "MissingAUMs", default, with = "base64_byte_arrays")]
    pub missing_aums: Vec<Vec<u8>>,
    #[serde(rename = "Interactive", default)]
    pub interactive: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleTkaSyncSendResponse {
    #[serde(rename = "Head")]
    pub head: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleDebug {
    #[serde(rename = "SleepSeconds", default)]
    pub sleep_seconds: f64,
    #[serde(rename = "DisableLogTail", default)]
    pub disable_log_tail: bool,
    #[serde(rename = "Exit", default)]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TailscaleMapResponse {
    #[serde(rename = "MapSessionHandle", default)]
    pub map_session_handle: String,
    #[serde(rename = "Seq", default)]
    pub sequence: i64,
    #[serde(rename = "KeepAlive", default)]
    pub keep_alive: bool,
    #[serde(rename = "PingRequest", default)]
    pub ping_request: Option<TailscalePingRequest>,
    #[serde(rename = "PopBrowserURL", default)]
    pub pop_browser_url: String,
    #[serde(rename = "Node", default)]
    pub node: Option<TailscaleNode>,
    #[serde(rename = "DERPMap", default)]
    pub derp_map: Option<TailscaleDerpMap>,
    #[serde(rename = "Peers", default)]
    pub peers: Option<Vec<TailscaleNode>>,
    #[serde(rename = "PeersChanged", default)]
    pub peers_changed: Vec<TailscaleNode>,
    #[serde(rename = "PeersRemoved", default)]
    pub peers_removed: Vec<i64>,
    #[serde(rename = "PeersChangedPatch", default)]
    pub peers_changed_patch: Vec<TailscalePeerChange>,
    #[serde(rename = "PeerSeenChange", default)]
    pub peer_seen_change: BTreeMap<i64, bool>,
    #[serde(rename = "OnlineChange", default)]
    pub online_change: BTreeMap<i64, bool>,
    #[serde(rename = "DNSConfig", default)]
    pub dns_config: Option<TailscaleDnsConfig>,
    #[serde(rename = "Domain", default)]
    pub domain: String,
    #[serde(rename = "CollectServices", default)]
    pub collect_services: Option<bool>,
    #[serde(rename = "PacketFilter", default)]
    pub packet_filter: Option<Vec<TailscaleFilterRule>>,
    #[serde(rename = "PacketFilters", default)]
    pub packet_filters:
        Option<BTreeMap<String, Option<Vec<TailscaleFilterRule>>>>,
    #[serde(rename = "UserProfiles", default)]
    pub user_profiles: Vec<TailscaleUserProfile>,
    #[serde(rename = "Health", default)]
    pub health: Option<Vec<String>>,
    #[serde(rename = "DisplayMessages", default)]
    pub display_messages:
        Option<BTreeMap<String, Option<TailscaleDisplayMessage>>>,
    #[serde(rename = "SSHPolicy", default)]
    pub ssh_policy: Option<TailscaleSshPolicy>,
    #[serde(rename = "ControlTime", default)]
    pub control_time: Option<String>,
    #[serde(rename = "TKAInfo", default)]
    pub tka_info: Option<TailscaleTkaInfo>,
    #[serde(rename = "DomainDataPlaneAuditLogID", default)]
    pub domain_data_plane_audit_log_id: String,
    #[serde(rename = "Debug", default)]
    pub debug: Option<TailscaleDebug>,
    #[serde(rename = "ControlDialPlan", default)]
    pub control_dial_plan: Option<TailscaleControlDialPlan>,
    #[serde(rename = "ClientVersion", default)]
    pub client_version: Option<TailscaleClientVersion>,
    #[serde(rename = "DefaultAutoUpdate", default)]
    pub deprecated_default_auto_update: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleUserProfile {
    #[serde(rename = "ID", default)]
    pub id: i64,
    #[serde(rename = "LoginName", default)]
    pub login_name: String,
    #[serde(rename = "DisplayName", default)]
    pub display_name: String,
    #[serde(rename = "ProfilePicURL", default)]
    pub profile_pic_url: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TailscaleNetmapState {
    pub map_session_handle: String,
    pub sequence: i64,
    pub node: Option<TailscaleNode>,
    pub derp_map: Option<TailscaleDerpMap>,
    pub peers: BTreeMap<i64, TailscaleNode>,
    pub dns_config: Option<TailscaleDnsConfig>,
    pub domain: String,
    pub collect_services: Option<bool>,
    pub named_packet_filters: BTreeMap<String, Vec<TailscaleFilterRule>>,
    pub packet_filter: Vec<TailscaleFilterRule>,
    pub user_profiles: BTreeMap<i64, TailscaleUserProfile>,
    pub health: Option<Vec<String>>,
    pub display_messages: BTreeMap<String, TailscaleDisplayMessage>,
    pub ssh_policy: Option<TailscaleSshPolicy>,
    pub control_time: Option<String>,
    pub tka_info: Option<TailscaleTkaInfo>,
    pub domain_data_plane_audit_log_id: String,
    pub debug: Option<TailscaleDebug>,
    pub control_dial_plan: Option<TailscaleControlDialPlan>,
    pub client_version: Option<TailscaleClientVersion>,
    pub deprecated_default_auto_update: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TailscaleNetmapUpdate {
    pub added_peers: usize,
    pub changed_peers: usize,
    pub removed_peers: usize,
    pub keep_alive: bool,
}

impl TailscaleNetmapState {
    /// Apply one streamed `MapResponse` using Tailscale's map-session order.
    /// `now` must be an RFC3339 timestamp and is used by `PeerSeenChange=true`.
    pub fn apply(
        &mut self,
        response: TailscaleMapResponse,
        now: &str,
    ) -> TailscaleNetmapUpdate {
        if !response.map_session_handle.is_empty() {
            self.map_session_handle = response.map_session_handle.clone();
        }
        if response.sequence != 0 {
            self.sequence = response.sequence;
        }
        let mut update = TailscaleNetmapUpdate {
            keep_alive: response.keep_alive,
            ..Default::default()
        };
        if response.keep_alive {
            return update;
        }
        if let Some(node) = response.node {
            self.node = Some(node);
        }
        if let Some(mut derp_map) = response.derp_map {
            if let Some(previous) = &self.derp_map {
                if derp_map.regions.is_none() {
                    derp_map.regions = previous.regions.clone();
                    derp_map.omit_default_regions =
                        previous.omit_default_regions;
                }
                match (&mut derp_map.home_params, &previous.home_params) {
                    (None, Some(home)) => {
                        derp_map.home_params = Some(home.clone());
                    }
                    (Some(home), Some(previous_home))
                        if home.region_score.is_none() =>
                    {
                        home.region_score = previous_home.region_score.clone();
                    }
                    _ => {}
                }
            }
            self.derp_map = Some(derp_map);
        }
        if let Some(peers) = response.peers.filter(|peers| !peers.is_empty()) {
            let previous = std::mem::take(&mut self.peers);
            for peer in peers {
                if previous.contains_key(&peer.id) {
                    update.changed_peers += 1;
                } else {
                    update.added_peers += 1;
                }
                self.peers.insert(peer.id, peer);
            }
            update.removed_peers += previous
                .keys()
                .filter(|id| !self.peers.contains_key(id))
                .count();
        } else {
            for id in response.peers_removed {
                if self.peers.remove(&id).is_some() {
                    update.removed_peers += 1;
                }
            }
            for peer in response.peers_changed {
                if self.peers.insert(peer.id, peer).is_some() {
                    update.changed_peers += 1;
                } else {
                    update.added_peers += 1;
                }
            }
            for (id, seen) in response.peer_seen_change {
                if let Some(peer) = self.peers.get_mut(&id) {
                    peer.last_seen = seen.then(|| now.to_owned());
                    update.changed_peers += 1;
                }
            }
            for (id, online) in response.online_change {
                if let Some(peer) = self.peers.get_mut(&id) {
                    peer.online = Some(online);
                    update.changed_peers += 1;
                }
            }
            for patch in response.peers_changed_patch {
                if let Some(peer) = self.peers.get_mut(&patch.node_id) {
                    apply_peer_patch(peer, patch);
                    update.changed_peers += 1;
                }
            }
        }
        if let Some(packet_filter) = response.packet_filter {
            self.named_packet_filters
                .insert("base".into(), packet_filter);
            self.rebuild_packet_filter();
        }
        if let Some(packet_filters) = response.packet_filters {
            if matches!(packet_filters.get("*"), Some(None)) {
                self.named_packet_filters.clear();
            }
            for (name, rules) in packet_filters {
                if name == "*" {
                    continue;
                }
                if let Some(rules) = rules {
                    self.named_packet_filters.insert(name, rules);
                } else {
                    self.named_packet_filters.remove(&name);
                }
            }
            self.rebuild_packet_filter();
        }
        if let Some(config) = response.dns_config {
            self.dns_config = Some(config);
        }
        if !response.domain.is_empty() {
            self.domain = response.domain;
        }
        if response.collect_services.is_some() {
            self.collect_services = response.collect_services;
        }
        for profile in response.user_profiles {
            self.user_profiles.insert(profile.id, profile);
        }
        if let Some(health) = response.health {
            self.health = Some(health);
        }
        if let Some(messages) = response.display_messages {
            if matches!(messages.get("*"), Some(None)) {
                self.display_messages.clear();
            }
            for (id, message) in messages {
                if id == "*" {
                    continue;
                }
                if let Some(message) = message {
                    self.display_messages.insert(id, message);
                } else {
                    self.display_messages.remove(&id);
                }
            }
        }
        if let Some(policy) = response.ssh_policy {
            self.ssh_policy = Some(policy);
        }
        if let Some(control_time) = response.control_time {
            self.control_time = Some(control_time);
        }
        if let Some(tka_info) = response.tka_info {
            self.tka_info = Some(tka_info);
        }
        if !response.domain_data_plane_audit_log_id.is_empty() {
            self.domain_data_plane_audit_log_id =
                response.domain_data_plane_audit_log_id;
        }
        if let Some(debug) = response.debug {
            self.debug = Some(debug);
        }
        if let Some(control_dial_plan) = response.control_dial_plan {
            self.control_dial_plan = Some(control_dial_plan);
        }
        if let Some(client_version) = response.client_version {
            self.client_version = Some(client_version);
        }
        if response.deprecated_default_auto_update.is_some() {
            self.deprecated_default_auto_update =
                response.deprecated_default_auto_update;
        }
        update
    }

    fn rebuild_packet_filter(&mut self) {
        self.packet_filter = self
            .named_packet_filters
            .values()
            .flat_map(|rules| rules.iter().cloned())
            .collect();
    }
}

fn apply_peer_patch(peer: &mut TailscaleNode, patch: TailscalePeerChange) {
    if patch.derp_region != 0 {
        peer.home_derp = patch.derp_region;
    }
    if patch.capability_version != 0 {
        peer.capability_version = patch.capability_version;
    }
    if let Some(capability_map) = patch.capability_map {
        peer.capability_map = capability_map;
    }
    if let Some(endpoints) = patch.endpoints {
        peer.endpoints = endpoints;
    }
    if let Some(key) = patch.key {
        peer.key = key;
    }
    if let Some(signature) = patch.key_signature {
        peer.key_signature = signature;
    }
    if let Some(disco_key) = patch.disco_key {
        peer.disco_key = disco_key;
    }
    if let Some(online) = patch.online {
        peer.online = Some(online);
    }
    if let Some(last_seen) = patch.last_seen {
        peer.last_seen = Some(last_seen);
    }
    if let Some(key_expiry) = patch.key_expiry {
        peer.key_expiry = key_expiry;
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

mod base64_bytes {
    use super::*;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        STANDARD.decode(value).map_err(serde::de::Error::custom)
    }
}

mod optional_base64_bytes {
    use super::*;

    pub fn serialize<S>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(bytes) => serializer.serialize_some(&STANDARD.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .map(|value| {
                STANDARD.decode(value).map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

mod base64_byte_arrays {
    use super::*;

    pub fn serialize<S>(
        arrays: &[Vec<u8>],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        arrays
            .iter()
            .map(|bytes| STANDARD.encode(bytes))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|value| {
                STANDARD.decode(value).map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: i64, name: &str) -> TailscaleNode {
        TailscaleNode {
            id,
            name: name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn register_and_map_requests_match_go_json_names_and_bytes() {
        let register = TailscaleRegisterRequest {
            version: 138,
            node_key: TailscaleNodePublicKey::from_bytes([1; 32]),
            network_lock_key: TailscaleNetworkLockPublicKey::from_bytes(
                [2; 32],
            ),
            ephemeral: true,
            signature: vec![1, 2, 3],
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(register).unwrap(),
            serde_json::json!({
                "Version": 138,
                "NodeKey": format!("nodekey:{}", "01".repeat(32)),
                "OldNodeKey": format!("nodekey:{}", "00".repeat(32)),
                "NLKey": format!("nlpub:{}", "02".repeat(32)),
                "Expiry": "0001-01-01T00:00:00Z",
                "Followup": "",
                "Hostinfo": null,
                "Ephemeral": true,
                "NodeKeySignature": null,
                "Signature": "AQID"
            })
        );
        let map = TailscaleMapRequest {
            version: 138,
            compress: "zstd".into(),
            node_key: TailscaleNodePublicKey::from_bytes([1; 32]),
            disco_key: TailscaleDiscoPublicKey::from_bytes([3; 32]),
            stream: true,
            endpoints: vec!["192.0.2.1:1234".into()],
            endpoint_types: vec![2],
            ..Default::default()
        };
        let json = serde_json::to_value(map).unwrap();
        assert_eq!(json["Compress"], "zstd");
        assert_eq!(json["EndpointTypes"], serde_json::json!([2]));
        assert!(json["NodeKey"].as_str().unwrap().starts_with("nodekey:"));
        assert!(json["DiscoKey"].as_str().unwrap().starts_with("discokey:"));
        assert!(json["Hostinfo"].is_null());
        assert!(json.get("KeepAlive").is_none());

        assert_eq!(
            format!("{}", TailscaleMachinePublicKey::from_bytes([4; 32])),
            format!("mkey:{}", "04".repeat(32))
        );
        assert!("nodekey:bad".parse::<TailscaleNodePublicKey>().is_err());
    }

    #[test]
    fn tka_sync_messages_match_tailcfg_json_shape() {
        let node_key = TailscaleNodePublicKey::from_bytes([1; 32]);
        let bootstrap = TailscaleTkaBootstrapRequest {
            version: 142,
            node_key,
            head: "HEAD".into(),
        };
        assert_eq!(
            serde_json::to_value(bootstrap).unwrap(),
            serde_json::json!({
                "Version": 142,
                "NodeKey": format!("nodekey:{}", "01".repeat(32)),
                "Head": "HEAD"
            })
        );

        let offer: TailscaleTkaSyncOfferResponse =
            serde_json::from_value(serde_json::json!({
                "Head": "REMOTE",
                "Ancestors": ["OLDER"],
                "MissingAUMs": ["AQID", "BAU="]
            }))
            .unwrap();
        assert_eq!(offer.missing_aums, vec![vec![1, 2, 3], vec![4, 5]]);

        let send = TailscaleTkaSyncSendRequest {
            version: 142,
            node_key,
            head: "LOCAL".into(),
            missing_aums: vec![vec![6, 7, 8]],
            interactive: false,
        };
        assert_eq!(
            serde_json::to_value(send).unwrap()["MissingAUMs"],
            serde_json::json!(["BgcI"])
        );
    }

    #[test]
    fn incremental_netmap_matches_peer_update_order() {
        let mut state = TailscaleNetmapState::default();
        let first = TailscaleMapResponse {
            map_session_handle: "session".into(),
            sequence: 1,
            peers: Some(vec![node(1, "one"), node(2, "two")]),
            packet_filter: Some(vec![TailscaleFilterRule {
                source_ips: vec!["*".into()],
                ..Default::default()
            }]),
            user_profiles: vec![TailscaleUserProfile {
                id: 7,
                display_name: "Alice".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let update = state.apply(first, "2026-09-02T00:00:00Z");
        assert_eq!((update.added_peers, update.removed_peers), (2, 0));
        assert_eq!(state.packet_filter.len(), 1);

        let delta: TailscaleMapResponse =
            serde_json::from_value(serde_json::json!({
                "Seq": 2,
                "PeersRemoved": [2],
                "PeersChanged": [{"ID": 3, "Name": "three"}],
                "PeerSeenChange": {"1": true},
                "OnlineChange": {"1": false},
                "PeersChangedPatch": [{
                    "NodeID": 1,
                    "DERPRegion": 9,
                    "Endpoints": ["203.0.113.1:5678"],
                    "KeySignature": "AQI="
                }],
                "PacketFilters": {"*": null, "ssh": [{"IPProto":[6]}]}
            }))
            .unwrap();
        let update = state.apply(delta, "2026-09-02T00:00:00Z");
        assert_eq!(
            (
                update.added_peers,
                update.changed_peers,
                update.removed_peers
            ),
            (1, 3, 1)
        );
        let peer = &state.peers[&1];
        assert_eq!(peer.home_derp, 9);
        assert_eq!(peer.online, Some(false));
        assert_eq!(peer.last_seen.as_deref(), Some("2026-09-02T00:00:00Z"));
        assert_eq!(peer.key_signature, [1, 2]);
        assert_eq!(state.packet_filter[0].ip_protocols, [6]);
    }

    #[test]
    fn deep_map_models_decode_control_wire() {
        let response: TailscaleMapResponse =
            serde_json::from_value(serde_json::json!({
                "PingRequest": {
                    "URL": "https://control.example/ping",
                    "URLIsNoise": true,
                    "Payload": "R0VUIC8gSFRUUC8xLjANCg0K"
                },
                "DNSConfig": {
                    "Resolvers": [{
                        "Addr": "https://dns.example/dns-query",
                        "BootstrapResolution": ["192.0.2.53"],
                        "UseWithExitNode": true
                    }],
                    "Routes": {"tailnet.example": []},
                    "Domains": ["tailnet.example"],
                    "Proxied": true,
                    "ExtraRecords": [{
                        "Name": "host.tailnet.example.",
                        "Value": "100.64.0.1"
                    }]
                },
                "PacketFilter": [{
                    "SrcIPs": ["100.64.0.0/10"],
                    "DstPorts": [{
                        "IP": "*",
                        "Ports": {"First": 22, "Last": 22}
                    }],
                    "IPProto": [6]
                }],
                "DisplayMessages": {
                    "health": {
                        "Title": "Network issue",
                        "Text": "Check connectivity",
                        "Severity": "medium",
                        "PrimaryAction": {
                            "URL": "https://example",
                            "Label": "Help"
                        }
                    }
                },
                "SSHPolicy": {"rules": [{
                    "principals": [{"node": "stable-node"}],
                    "sshUsers": {"alice": "alice"},
                    "action": {
                        "accept": true,
                        "sessionDuration": 60000000000_i64
                    }
                }]},
                "ControlDialPlan": {"Candidates": [{
                    "IP": "192.0.2.1",
                    "ACEHost": "ace.example",
                    "Priority": 10
                }]},
                "ClientVersion": {
                    "RunningLatest": false,
                    "LatestVersion": "1.100.0",
                    "Notify": true
                },
                "TKAInfo": {"Head": "012345", "Disabled": false},
                "Debug": {
                    "SleepSeconds": 1.5,
                    "DisableLogTail": true,
                    "Exit": 23
                }
            }))
            .unwrap();
        assert_eq!(
            response.dns_config.as_ref().unwrap().resolvers[0].address,
            "https://dns.example/dns-query"
        );
        assert_eq!(
            response.packet_filter.as_ref().unwrap()[0].destination_ports[0]
                .ports
                .first,
            22
        );
        assert_eq!(response.tka_info.as_ref().unwrap().head, "012345");
        assert_eq!(response.debug.as_ref().unwrap().sleep_seconds, 1.5);
        assert!(response.debug.as_ref().unwrap().disable_log_tail);
        assert_eq!(response.debug.as_ref().unwrap().exit_code, Some(23));
        assert_eq!(
            response.ping_request.as_ref().unwrap().payload,
            b"GET / HTTP/1.0\r\n\r\n"
        );
        assert!(
            response.ssh_policy.as_ref().unwrap().rules[0]
                .action
                .as_ref()
                .unwrap()
                .accept
        );
        assert_eq!(
            response.control_dial_plan.as_ref().unwrap().candidates[0].priority,
            10
        );
        assert_eq!(response.client_version.unwrap().latest_version, "1.100.0");
    }

    #[test]
    fn derp_partial_update_inherits_previous_fields() {
        let mut state = TailscaleNetmapState::default();
        state.apply(
            TailscaleMapResponse {
                derp_map: Some(TailscaleDerpMap {
                    home_params: Some(TailscaleDerpHomeParams {
                        region_score: Some(BTreeMap::from([(1, 0.5)])),
                    }),
                    regions: Some(BTreeMap::from([(
                        1,
                        TailscaleDerpRegion {
                            region_id: 1,
                            ..Default::default()
                        },
                    )])),
                    omit_default_regions: true,
                }),
                ..Default::default()
            },
            "now",
        );
        state.apply(
            TailscaleMapResponse {
                derp_map: Some(TailscaleDerpMap {
                    home_params: Some(TailscaleDerpHomeParams::default()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            "now",
        );
        let derp = state.derp_map.unwrap();
        assert!(derp.omit_default_regions);
        assert_eq!(derp.regions.unwrap().len(), 1);
        assert_eq!(derp.home_params.unwrap().region_score.unwrap()[&1], 0.5);
    }

    #[test]
    fn keep_alive_only_advances_session_sequence() {
        let mut state = TailscaleNetmapState {
            peers: BTreeMap::from([(1, node(1, "one"))]),
            ..Default::default()
        };
        let update = state.apply(
            TailscaleMapResponse {
                map_session_handle: "resume".into(),
                sequence: 7,
                keep_alive: true,
                peers_removed: vec![1],
                ..Default::default()
            },
            "now",
        );
        assert!(update.keep_alive);
        assert_eq!(state.sequence, 7);
        assert!(state.peers.contains_key(&1));
    }
}
