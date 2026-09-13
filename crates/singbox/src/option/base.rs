use std::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::{Map, Value};

use super::{Addr, DomainStrategy, Duration, FwMark, Listable, Prefixable};
use crate::constant;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    #[serde(default, rename = "username", alias = "Username")]
    pub username: String,
    #[serde(default, rename = "password", alias = "Password")]
    pub password: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerOptions {
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub server_port: u16,
}

impl ServerOptions {
    pub fn server_is_domain(&self) -> bool {
        self.server.parse::<IpAddr>().is_err()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DomainResolveOptions {
    pub server: String,
    pub timeout: Duration,
    pub strategy: DomainStrategy,
    pub disable_cache: bool,
    pub disable_optimistic_cache: bool,
    pub rewrite_ttl: Option<u32>,
    pub client_subnet: Option<Prefixable>,
}

#[derive(Serialize, Deserialize)]
struct DomainResolveObject {
    server: String,
    #[serde(default)]
    timeout: Duration,
    #[serde(default)]
    strategy: DomainStrategy,
    #[serde(default)]
    disable_cache: bool,
    #[serde(default)]
    disable_optimistic_cache: bool,
    #[serde(default)]
    rewrite_ttl: Option<u32>,
    #[serde(default)]
    client_subnet: Option<Prefixable>,
}

impl<'de> Deserialize<'de> for DomainResolveOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrObject {
            String(String),
            Object(DomainResolveObject),
        }
        match StringOrObject::deserialize(deserializer)? {
            StringOrObject::String(server) => Ok(Self {
                server,
                ..Self::default()
            }),
            StringOrObject::Object(object) => {
                if object.server.is_empty() {
                    return Err(de::Error::custom(
                        "empty domain_resolver.server",
                    ));
                }
                Ok(Self {
                    server: object.server,
                    timeout: object.timeout,
                    strategy: object.strategy,
                    disable_cache: object.disable_cache,
                    disable_optimistic_cache: object.disable_optimistic_cache,
                    rewrite_ttl: object.rewrite_ttl,
                    client_subnet: object.client_subnet,
                })
            }
        }
    }
}

impl Serialize for DomainResolveOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.server.is_empty() {
            return Map::<String, Value>::new().serialize(serializer);
        }
        if *self
            == (Self {
                server: self.server.clone(),
                ..Self::default()
            })
        {
            return self.server.serialize(serializer);
        }
        DomainResolveObject {
            server: self.server.clone(),
            timeout: self.timeout,
            strategy: self.strategy,
            disable_cache: self.disable_cache,
            disable_optimistic_cache: self.disable_optimistic_cache,
            rewrite_ttl: self.rewrite_ttl,
            client_subnet: self.client_subnet.clone(),
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkStrategy(pub constant::NetworkStrategy);

impl<'de> Deserialize<'de> for NetworkStrategy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        constant::NetworkStrategy::parse(&value)
            .map(Self)
            .ok_or_else(|| {
                de::Error::custom(format!("unknown network strategy: {value}"))
            })
    }
}

impl Serialize for NetworkStrategy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceType(pub constant::InterfaceType);

impl<'de> Deserialize<'de> for InterfaceType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        constant::InterfaceType::parse(&value)
            .map(Self)
            .ok_or_else(|| {
                de::Error::custom(format!("unknown interface type: {value}"))
            })
    }
}

impl Serialize for InterfaceType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenOptions {
    #[serde(default)]
    pub listen: Option<Addr>,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub bind_interface: String,
    #[serde(default)]
    pub routing_mark: FwMark,
    #[serde(default)]
    pub reuse_addr: bool,
    #[serde(default)]
    pub netns: String,
    #[serde(default)]
    pub disable_tcp_keep_alive: bool,
    #[serde(default)]
    pub tcp_keep_alive: Duration,
    #[serde(default)]
    pub tcp_keep_alive_interval: Duration,
    #[serde(default)]
    pub tcp_fast_open: bool,
    #[serde(default)]
    pub tcp_multi_path: bool,
    #[serde(default)]
    pub udp_fragment: Option<bool>,
    #[serde(default)]
    pub udp_timeout: UdpTimeout,
    #[serde(default)]
    pub detour: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UdpTimeout(pub Duration);

impl<'de> Deserialize<'de> for UdpTimeout {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum NumberOrDuration {
            Number(u64),
            Duration(Duration),
        }
        match NumberOrDuration::deserialize(deserializer)? {
            NumberOrDuration::Number(seconds) => i64::try_from(seconds)
                .ok()
                .and_then(|seconds| seconds.checked_mul(1_000_000_000))
                .map(Duration::from_nanos)
                .map(Self)
                .ok_or_else(|| {
                    de::Error::custom("UDP timeout overflows duration")
                }),
            NumberOrDuration::Duration(duration) => Ok(Self(duration)),
        }
    }
}

impl Serialize for UdpTimeout {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialerOptions {
    #[serde(default)]
    pub detour: String,
    #[serde(flatten)]
    pub abstract_options: AbstractDialerOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbstractDialerOptions {
    #[serde(default)]
    pub bind_interface: String,
    #[serde(default)]
    pub inet4_bind_address: Option<Addr>,
    #[serde(default)]
    pub inet6_bind_address: Option<Addr>,
    #[serde(default)]
    pub bind_address_no_port: bool,
    #[serde(default)]
    pub protect_path: String,
    #[serde(default)]
    pub routing_mark: FwMark,
    #[serde(default)]
    pub reuse_addr: bool,
    #[serde(default)]
    pub netns: String,
    #[serde(default)]
    pub connect_timeout: Duration,
    #[serde(default)]
    pub tcp_fast_open: bool,
    #[serde(default)]
    pub tcp_multi_path: bool,
    #[serde(default)]
    pub disable_tcp_keep_alive: bool,
    #[serde(default)]
    pub tcp_keep_alive: Duration,
    #[serde(default)]
    pub tcp_keep_alive_interval: Duration,
    #[serde(default)]
    pub udp_fragment: Option<bool>,
    #[serde(default)]
    pub domain_resolver: Option<DomainResolveOptions>,
    #[serde(default)]
    pub network_strategy: Option<NetworkStrategy>,
    #[serde(default)]
    pub network_type: Listable<InterfaceType>,
    #[serde(default)]
    pub fallback_network_type: Listable<InterfaceType>,
    #[serde(default)]
    pub fallback_delay: Duration,
    #[serde(default)]
    pub domain_strategy: DomainStrategy,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundMultiplexOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub padding: bool,
    #[serde(default)]
    pub brutal: Option<BrutalOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundMultiplexOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub max_connections: i32,
    #[serde(default)]
    pub min_streams: i32,
    #[serde(default)]
    pub max_streams: i32,
    #[serde(default)]
    pub padding: bool,
    #[serde(default)]
    pub brutal: Option<BrutalOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrutalOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub up_mbps: i32,
    #[serde(default)]
    pub down_mbps: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum V2RayTransportOptions {
    #[serde(rename = "http")]
    Http(V2RayHttpOptions),
    #[serde(rename = "ws")]
    Websocket(V2RayWebsocketOptions),
    #[serde(rename = "quic")]
    Quic,
    #[serde(rename = "grpc")]
    Grpc(V2RayGrpcOptions),
    #[serde(rename = "httpupgrade")]
    HttpUpgrade(V2RayHttpUpgradeOptions),
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2RayHttpOptions {
    #[serde(default)]
    pub host: Listable<String>,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub headers: Map<String, Value>,
    #[serde(default)]
    pub idle_timeout: Duration,
    #[serde(default)]
    pub ping_timeout: Duration,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2RayWebsocketOptions {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub headers: Map<String, Value>,
    #[serde(default)]
    pub max_early_data: u32,
    #[serde(default)]
    pub early_data_header_name: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2RayGrpcOptions {
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub idle_timeout: Duration,
    #[serde(default)]
    pub ping_timeout: Duration,
    #[serde(default)]
    pub permit_without_stream: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2RayHttpUpgradeOptions {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub headers: Map<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::{DomainResolveOptions, UdpTimeout, V2RayTransportOptions};

    #[test]
    fn domain_resolver_supports_reference_and_object_forms() {
        let reference: DomainResolveOptions =
            serde_json::from_str("\"dns-local\"").unwrap();
        assert_eq!(reference.server, "dns-local");
        assert_eq!(serde_json::to_string(&reference).unwrap(), "\"dns-local\"");
        let object: DomainResolveOptions = serde_json::from_str(
            r#"{"server":"dns-local","strategy":"ipv4_only"}"#,
        )
        .unwrap();
        assert_eq!(object.server, "dns-local");
        assert!(
            serde_json::to_string(&object)
                .unwrap()
                .contains("ipv4_only")
        );
    }

    #[test]
    fn udp_timeout_accepts_legacy_seconds() {
        let timeout: UdpTimeout = serde_json::from_str("5").unwrap();
        assert_eq!(timeout.0.as_nanos(), 5_000_000_000);
    }

    #[test]
    fn v2ray_transport_is_discriminated() {
        let transport: V2RayTransportOptions =
            serde_json::from_str(r#"{"type":"ws","path":"/ws"}"#).unwrap();
        assert!(matches!(
            transport,
            V2RayTransportOptions::Websocket(options) if options.path == "/ws"
        ));
    }
}
