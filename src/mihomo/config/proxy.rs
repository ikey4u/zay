//! Outbound `proxies` entries.
//!
//! Mihomo supports many `type` values (see `MIHOMO_CONFIG_TEMPLATE`). Zay keeps a
//! [`Proxy`] wrapper around [`serde_yaml::Value`] so subscription/bootstrap nodes round-trip
//! without listing every variant, while typed structs below match the v1.19.25 docs.

use serde::{Deserialize, Serialize};
use serde_yaml::Value;

/// One `proxies` item (any `type`; preserves unknown fields).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Proxy(pub Value);

impl Proxy {
    pub fn from_value(v: Value) -> Self {
        Self(v)
    }

    pub fn to_value(&self) -> Value {
        self.0.clone()
    }

    pub fn from_typed<T: Serialize>(value: &T) -> serde_yaml::Result<Self> {
        Ok(Self(serde_yaml::to_value(value)?))
    }
}

macro_rules! proxy_struct {
    ($name:ident, $type:literal, { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(rename_all = "kebab-case")]
        pub struct $name {
            pub name: String,
            #[serde(rename = "type")]
            pub kind: &'static str,
            $(#[serde(skip_serializing_if = "Option::is_none")] pub $field : Option<$ty>,)*
        }

        impl $name {
            pub fn into_proxy(self) -> serde_yaml::Result<Proxy> {
                Proxy::from_typed(&self)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    name: String::new(),
                    kind: $type,
                    $($field: None,)*
                }
            }
        }
    };
}

proxy_struct!(SsProxy, "ss", {
    server: String,
    port: u16,
    cipher: String,
    password: String,
    udp: bool,
    udp_over_tcp: bool,
});

proxy_struct!(VmessProxy, "vmess", {
    server: String,
    port: u16,
    uuid: String,
    alter_id: u32,
    cipher: String,
    udp: bool,
    tls: bool,
    servername: String,
    network: String,
});

proxy_struct!(VlessProxy, "vless", {
    server: String,
    port: u16,
    uuid: String,
    udp: bool,
    tls: bool,
    network: String,
    flow: String,
    servername: String,
});

proxy_struct!(TrojanProxy, "trojan", {
    server: String,
    port: u16,
    password: String,
    udp: bool,
    sni: String,
});

proxy_struct!(Socks5Proxy, "socks5", {
    server: String,
    port: u16,
    username: String,
    password: String,
    udp: bool,
    tls: bool,
});

proxy_struct!(HttpProxy, "http", {
    server: String,
    port: u16,
    username: String,
    password: String,
    tls: bool,
});

proxy_struct!(Hysteria2Proxy, "hysteria2", {
    server: String,
    port: u16,
    password: String,
    up: String,
    down: String,
    sni: String,
});

proxy_struct!(DirectProxy, "direct", {
    udp: bool,
});
