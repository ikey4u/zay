//! Constants mirrored from `inner/sing-box/constant`.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceType {
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

impl InterfaceType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wifi => "wifi",
            Self::Cellular => "cellular",
            Self::Ethernet => "ethernet",
            Self::Other => "other",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "wifi" => Self::Wifi,
            "cellular" => Self::Cellular,
            "ethernet" => Self::Ethernet,
            "other" => Self::Other,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NetworkStrategy {
    #[default]
    Default,
    Fallback,
    Hybrid,
}

impl NetworkStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Fallback => "fallback",
            Self::Hybrid => "hybrid",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "default" => Self::Default,
            "fallback" => Self::Fallback,
            "hybrid" => Self::Hybrid,
            _ => return None,
        })
    }
}

pub const CERTIFICATE_STORE_SYSTEM: &str = "system";
pub const CERTIFICATE_STORE_MOZILLA: &str = "mozilla";
pub const CERTIFICATE_STORE_CHROME: &str = "chrome";
pub const CERTIFICATE_STORE_NONE: &str = "none";

pub const DEFAULT_DNS_TTL: u32 = 600;
pub const DHCP_TTL: Duration = Duration::from_secs(60 * 60);
pub const DHCP_TIMEOUT: Duration = Duration::from_secs(5);

pub const DNS_TYPE_LEGACY: &str = "legacy";
pub const DNS_TYPE_UDP: &str = "udp";
pub const DNS_TYPE_TCP: &str = "tcp";
pub const DNS_TYPE_TLS: &str = "tls";
pub const DNS_TYPE_HTTPS: &str = "https";
pub const DNS_TYPE_QUIC: &str = "quic";
pub const DNS_TYPE_HTTP3: &str = "h3";
pub const DNS_TYPE_LOCAL: &str = "local";
pub const DNS_TYPE_HOSTS: &str = "hosts";
pub const DNS_TYPE_FAKEIP: &str = "fakeip";
pub const DNS_TYPE_DHCP: &str = "dhcp";
pub const DNS_TYPE_MDNS: &str = "mdns";
pub const DNS_TYPE_TAILSCALE: &str = "tailscale";
pub const DNS_TYPE_OPENCONNECT: &str = "openconnect";
pub const DNS_TYPE_OPENVPN: &str = "openvpn";

pub const DNS_PROVIDER_ALIDNS: &str = "alidns";
pub const DNS_PROVIDER_CLOUDFLARE: &str = "cloudflare";
pub const DNS_PROVIDER_ACMEDNS: &str = "acmedns";

pub const DNS_TRANSPORT_TYPES: &[&str] = &[
    DNS_TYPE_LEGACY,
    DNS_TYPE_UDP,
    DNS_TYPE_TCP,
    DNS_TYPE_TLS,
    DNS_TYPE_HTTPS,
    DNS_TYPE_QUIC,
    DNS_TYPE_HTTP3,
    DNS_TYPE_LOCAL,
    DNS_TYPE_HOSTS,
    DNS_TYPE_FAKEIP,
    DNS_TYPE_DHCP,
    DNS_TYPE_MDNS,
    DNS_TYPE_TAILSCALE,
    DNS_TYPE_OPENCONNECT,
    DNS_TYPE_OPENVPN,
    TYPE_RESOLVED,
];

pub const HYSTERIA2_OBFS_TYPE_SALAMANDER: &str = "salamander";
pub const HYSTERIA2_OBFS_TYPE_GECKO: &str = "gecko";
pub const HYSTERIA2_MASQUERADE_TYPE_FILE: &str = "file";
pub const HYSTERIA2_MASQUERADE_TYPE_PROXY: &str = "proxy";
pub const HYSTERIA2_MASQUERADE_TYPE_STRING: &str = "string";

pub const NETNS_TYPE_DEFAULT: &str = "default";
pub const NETNS_TYPE_UNSHARE: &str = "unshare";

pub const PROTOCOL_TLS: &str = "tls";
pub const PROTOCOL_HTTP: &str = "http";
pub const PROTOCOL_QUIC: &str = "quic";
pub const PROTOCOL_DNS: &str = "dns";
pub const PROTOCOL_STUN: &str = "stun";
pub const PROTOCOL_BITTORRENT: &str = "bittorrent";
pub const PROTOCOL_DTLS: &str = "dtls";
pub const PROTOCOL_SSH: &str = "ssh";
pub const PROTOCOL_RDP: &str = "rdp";
pub const PROTOCOL_NTP: &str = "ntp";

pub const CLIENT_CHROMIUM: &str = "chromium";
pub const CLIENT_SAFARI: &str = "safari";
pub const CLIENT_FIREFOX: &str = "firefox";
pub const CLIENT_QUIC_GO: &str = "quic-go";
pub const CLIENT_UNKNOWN: &str = "unknown";

pub const TYPE_TUN: &str = "tun";
pub const TYPE_REDIRECT: &str = "redirect";
pub const TYPE_TPROXY: &str = "tproxy";
pub const TYPE_DIRECT: &str = "direct";
pub const TYPE_BRIDGE: &str = "bridge";
pub const TYPE_BLOCK: &str = "block";
pub const TYPE_DNS: &str = "dns";
pub const TYPE_SOCKS: &str = "socks";
pub const TYPE_HTTP: &str = "http";
pub const TYPE_MIXED: &str = "mixed";
pub const TYPE_SHADOWSOCKS: &str = "shadowsocks";
pub const TYPE_SNELL: &str = "snell";
pub const TYPE_VMESS: &str = "vmess";
pub const TYPE_TROJAN: &str = "trojan";
pub const TYPE_NAIVE: &str = "naive";
pub const TYPE_WIREGUARD: &str = "wireguard";
pub const TYPE_HYSTERIA: &str = "hysteria";
pub const TYPE_TOR: &str = "tor";
pub const TYPE_SSH: &str = "ssh";
pub const TYPE_SHADOWTLS: &str = "shadowtls";
pub const TYPE_ANYTLS: &str = "anytls";
pub const TYPE_SHADOWSOCKSR: &str = "shadowsocksr";
pub const TYPE_VLESS: &str = "vless";
pub const TYPE_TUIC: &str = "tuic";
pub const TYPE_HYSTERIA2: &str = "hysteria2";
pub const TYPE_OPENCONNECT: &str = "openconnect";
pub const TYPE_OPENVPN_CLIENT: &str = "openvpn-client";
pub const TYPE_OPENVPN_SERVER: &str = "openvpn-server";
pub const TYPE_TAILSCALE: &str = "tailscale";
pub const TYPE_CLOUDFLARED: &str = "cloudflared";
pub const TYPE_DERP: &str = "derp";
pub const TYPE_RESOLVED: &str = "resolved";
pub const TYPE_SSM_API: &str = "ssm-api";
pub const TYPE_API: &str = "api";
pub const TYPE_CCM: &str = "ccm";
pub const TYPE_OCM: &str = "ocm";
pub const TYPE_OOM_KILLER: &str = "oom-killer";
pub const TYPE_USBIP_SERVER: &str = "usbip-server";
pub const TYPE_USBIP_CLIENT: &str = "usbip-client";
pub const TYPE_HYSTERIA_REALM: &str = "hysteria-realm";
pub const TYPE_ACME: &str = "acme";
pub const TYPE_CLOUDFLARE_ORIGIN_CA: &str = "cloudflare-origin-ca";
pub const TYPE_SELECTOR: &str = "selector";
pub const TYPE_URLTEST: &str = "urltest";

pub const INBOUND_TYPES: &[&str] = &[
    TYPE_TUN,
    TYPE_REDIRECT,
    TYPE_TPROXY,
    TYPE_DIRECT,
    TYPE_SOCKS,
    TYPE_HTTP,
    TYPE_MIXED,
    TYPE_SHADOWSOCKS,
    TYPE_SNELL,
    TYPE_VMESS,
    TYPE_TROJAN,
    TYPE_NAIVE,
    TYPE_SHADOWTLS,
    TYPE_VLESS,
    TYPE_ANYTLS,
    TYPE_HYSTERIA,
    TYPE_TUIC,
    TYPE_HYSTERIA2,
    TYPE_CLOUDFLARED,
    TYPE_SHADOWSOCKSR,
];

pub const OUTBOUND_TYPES: &[&str] = &[
    TYPE_DIRECT,
    TYPE_BRIDGE,
    TYPE_BLOCK,
    TYPE_DNS,
    TYPE_SELECTOR,
    TYPE_URLTEST,
    TYPE_SOCKS,
    TYPE_HTTP,
    TYPE_SHADOWSOCKS,
    TYPE_SNELL,
    TYPE_VMESS,
    TYPE_TROJAN,
    TYPE_NAIVE,
    TYPE_TOR,
    TYPE_SSH,
    TYPE_SHADOWTLS,
    TYPE_VLESS,
    TYPE_ANYTLS,
    TYPE_HYSTERIA,
    TYPE_TUIC,
    TYPE_HYSTERIA2,
    TYPE_SHADOWSOCKSR,
    TYPE_WIREGUARD,
];

pub const ENDPOINT_TYPES: &[&str] = &[
    TYPE_WIREGUARD,
    TYPE_OPENCONNECT,
    TYPE_OPENVPN_CLIENT,
    TYPE_OPENVPN_SERVER,
    TYPE_TAILSCALE,
];

pub const SERVICE_TYPES: &[&str] = &[
    TYPE_API,
    TYPE_RESOLVED,
    TYPE_SSM_API,
    TYPE_HYSTERIA_REALM,
    TYPE_DERP,
    TYPE_CCM,
    TYPE_OCM,
    TYPE_OOM_KILLER,
    TYPE_USBIP_SERVER,
    TYPE_USBIP_CLIENT,
];

pub const CERTIFICATE_PROVIDER_TYPES: &[&str] =
    &[TYPE_ACME, TYPE_TAILSCALE, TYPE_CLOUDFLARE_ORIGIN_CA];

pub const RULE_SET_VERSION_CURRENT: u8 = 5;
pub const RULE_TYPE_DEFAULT: &str = "default";
pub const RULE_TYPE_LOGICAL: &str = "logical";
pub const LOGICAL_TYPE_AND: &str = "and";
pub const LOGICAL_TYPE_OR: &str = "or";
pub const RULE_SET_TYPE_INLINE: &str = "inline";
pub const RULE_SET_TYPE_LOCAL: &str = "local";
pub const RULE_SET_TYPE_REMOTE: &str = "remote";
pub const RULE_SET_FORMAT_SOURCE: &str = "source";
pub const RULE_SET_FORMAT_BINARY: &str = "binary";
pub const RULE_SET_TAG_PLACEHOLDER: &str = "{tag}";
pub const RULE_ACTION_TYPE_ROUTE: &str = "route";
pub const RULE_ACTION_TYPE_ROUTE_OPTIONS: &str = "route-options";
pub const RULE_ACTION_TYPE_EVALUATE: &str = "evaluate";
pub const RULE_ACTION_TYPE_RESPOND: &str = "respond";
pub const RULE_ACTION_TYPE_DIRECT: &str = "direct";
pub const RULE_ACTION_TYPE_BYPASS: &str = "bypass";
pub const RULE_ACTION_TYPE_REJECT: &str = "reject";
pub const RULE_ACTION_TYPE_HIJACK_DNS: &str = "hijack-dns";
pub const RULE_ACTION_TYPE_SNIFF: &str = "sniff";
pub const RULE_ACTION_TYPE_RESOLVE: &str = "resolve";
pub const RULE_ACTION_TYPE_PREDEFINED: &str = "predefined";
pub const RULE_ACTION_REJECT_METHOD_DEFAULT: &str = "default";
pub const RULE_ACTION_REJECT_METHOD_DROP: &str = "drop";
pub const RULE_ACTION_REJECT_METHOD_REPLY: &str = "reply";

pub const ACME_TLS1_PROTOCOL: &str = "acme-tls/1";
pub const TLS_ENGINE_DEFAULT: &str = "";
pub const TLS_ENGINE_GO: &str = "go";
pub const TLS_ENGINE_APPLE: &str = "apple";
pub const TLS_ENGINE_WINDOWS: &str = "windows";

pub const V2RAY_TRANSPORT_TYPE_HTTP: &str = "http";
pub const V2RAY_TRANSPORT_TYPE_WEBSOCKET: &str = "ws";
pub const V2RAY_TRANSPORT_TYPE_QUIC: &str = "quic";
pub const V2RAY_TRANSPORT_TYPE_GRPC: &str = "grpc";
pub const V2RAY_TRANSPORT_TYPE_HTTP_UPGRADE: &str = "httpupgrade";
pub const MBPS_TO_BPS: u64 = 125_000;

pub const TCP_KEEP_ALIVE_INITIAL: Duration = Duration::from_secs(5 * 60);
pub const TCP_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(75);
pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const TCP_TIMEOUT: Duration = Duration::from_secs(15);
pub const READ_PAYLOAD_TIMEOUT: Duration = Duration::from_millis(300);
pub const DNS_TIMEOUT: Duration = Duration::from_secs(10);
pub const UDP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const ICMP_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_URL_TEST_INTERVAL: Duration = Duration::from_secs(3 * 60);
pub const DEFAULT_URL_TEST_IDLE_TIMEOUT: Duration =
    Duration::from_secs(30 * 60);
pub const START_TIMEOUT: Duration = Duration::from_secs(10);
pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);
pub const FATAL_STOP_TIMEOUT: Duration = Duration::from_secs(10);
pub const FAKE_IP_METADATA_SAVE_INTERVAL: Duration = Duration::from_secs(10);
pub const TLS_FRAGMENT_FALLBACK_DELAY: Duration = Duration::from_millis(500);

pub fn proxy_display_name(proxy_type: &str) -> &'static str {
    match proxy_type {
        TYPE_TUN => "TUN",
        TYPE_REDIRECT => "Redirect",
        TYPE_TPROXY => "TProxy",
        TYPE_DIRECT => "Direct",
        TYPE_BRIDGE => "Bridge",
        TYPE_BLOCK => "Block",
        TYPE_DNS => "DNS",
        TYPE_SOCKS => "SOCKS",
        TYPE_HTTP => "HTTP",
        TYPE_MIXED => "Mixed",
        TYPE_SHADOWSOCKS => "Shadowsocks",
        TYPE_SNELL => "Snell",
        TYPE_VMESS => "VMess",
        TYPE_TROJAN => "Trojan",
        TYPE_NAIVE => "Naive",
        TYPE_WIREGUARD => "WireGuard",
        TYPE_HYSTERIA => "Hysteria",
        TYPE_TOR => "Tor",
        TYPE_SSH => "SSH",
        TYPE_SHADOWTLS => "ShadowTLS",
        TYPE_SHADOWSOCKSR => "ShadowsocksR",
        TYPE_VLESS => "VLESS",
        TYPE_TUIC => "TUIC",
        TYPE_HYSTERIA2 => "Hysteria2",
        TYPE_ANYTLS => "AnyTLS",
        TYPE_OPENCONNECT => "OpenConnect",
        TYPE_OPENVPN_CLIENT => "OpenVPN Client",
        TYPE_OPENVPN_SERVER => "OpenVPN Server",
        TYPE_TAILSCALE => "Tailscale",
        TYPE_CLOUDFLARED => "Cloudflared",
        TYPE_SELECTOR => "Selector",
        TYPE_URLTEST => "URLTest",
        _ => "Unknown",
    }
}
