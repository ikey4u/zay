use std::{fmt, net::IpAddr, str::FromStr, time::Duration as StdDuration};

use ipnet::IpNet;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, DeserializeOwned},
};
use serde_json::Value;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryBytes(pub u64);

impl MemoryBytes {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkBytesCompat(pub u64);

impl NetworkBytesCompat {
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for NetworkBytesCompat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Number(number) => {
                number.as_u64().map(Self).ok_or_else(|| {
                    de::Error::custom("network rate must be non-negative")
                })
            }
            Value::String(value) => parse_network_bytes_compat(&value)
                .map(Self)
                .map_err(de::Error::custom),
            _ => Err(de::Error::custom(
                "network rate must be an integer or unit string",
            )),
        }
    }
}

impl Serialize for NetworkBytesCompat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

fn parse_network_bytes_compat(value: &str) -> Result<u64, String> {
    let digit_end = value
        .char_indices()
        .take_while(|(_, character)| character.is_ascii_digit())
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or_default();
    if digit_end == 0 || digit_end == value.len() {
        return Err(format!("invalid network rate: {value}"));
    }
    let number: u64 = value[..digit_end]
        .parse()
        .map_err(|_| format!("invalid network rate: {value}"))?;
    let raw_unit = value[digit_end..].trim();
    let network_multiplier = match raw_unit {
        "Bps" => Some(1),
        "Kbps" => Some(125),
        "KBps" => Some(1_000),
        "Mbps" => Some(125_000),
        "MBps" => Some(1_000_000),
        "Gbps" => Some(125_000_000),
        "GBps" => Some(1_000_000_000),
        "Tbps" => Some(125_000_000_000),
        "TBps" => Some(1_000_000_000_000),
        "Pbps" => Some(125_000_000_000_000),
        "PBps" => Some(1_000_000_000_000_000),
        "Ebps" => Some(125_000_000_000_000_000),
        "EBps" => Some(1_000_000_000_000_000_000),
        _ => None,
    };
    let multiplier = network_multiplier.or_else(|| {
        match raw_unit.to_ascii_lowercase().as_str() {
            "b" => Some(1),
            "k" | "kb" => Some(1_000),
            "ki" | "kib" => Some(1 << 10),
            "m" | "mb" => Some(1_000_000),
            "mi" | "mib" => Some(1 << 20),
            "g" | "gb" => Some(1_000_000_000),
            "gi" | "gib" => Some(1 << 30),
            "t" | "tb" => Some(1_000_000_000_000),
            "ti" | "tib" => Some(1 << 40),
            "p" | "pb" => Some(1_000_000_000_000_000),
            "pi" | "pib" => Some(1 << 50),
            "e" | "eb" => Some(1_000_000_000_000_000_000),
            "ei" | "eib" => Some(1 << 60),
            _ => None,
        }
    });
    number
        .checked_mul(multiplier.ok_or_else(|| {
            format!("unsupported network rate unit: {raw_unit}")
        })?)
        .ok_or_else(|| format!("network rate overflows u64: {value}"))
}

impl<'de> Deserialize<'de> for MemoryBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Number(number) => {
                number.as_u64().map(Self).ok_or_else(|| {
                    de::Error::custom("memory size must be non-negative")
                })
            }
            Value::String(value) => parse_memory_bytes(&value)
                .map(Self)
                .map_err(de::Error::custom),
            _ => Err(de::Error::custom(
                "memory size must be an integer or unit string",
            )),
        }
    }
}

impl Serialize for MemoryBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

fn parse_memory_bytes(value: &str) -> Result<u64, String> {
    let digit_end = value
        .char_indices()
        .take_while(|(_, character)| character.is_ascii_digit())
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or_default();
    if digit_end == 0 {
        return Err(format!("invalid memory size: {value}"));
    }
    let number: u64 = value[..digit_end]
        .parse()
        .map_err(|_| format!("invalid memory size: {value}"))?;
    let unit = value[digit_end..].trim().to_ascii_lowercase();
    let exponent = match unit.as_str() {
        "b" => 0,
        "k" | "kb" => 1,
        "m" | "mb" => 2,
        "g" | "gb" => 3,
        "t" | "tb" => 4,
        "p" | "pb" => 5,
        "e" | "eb" => 6,
        _ => {
            return Err(format!(
                "unsupported memory unit: {}",
                &value[digit_end..]
            ));
        }
    };
    number
        .checked_mul(1_u64 << (exponent * 10))
        .ok_or_else(|| format!("memory size overflows: {value}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listable<T>(pub Vec<T>);

impl<T> Default for Listable<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> Listable<T> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<'de, T> Deserialize<'de> for Listable<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        if value.is_null() {
            return Ok(Self(Vec::new()));
        }
        match value {
            Value::Array(values) => values
                .into_iter()
                .map(serde_json::from_value)
                .collect::<Result<Vec<_>, _>>()
                .map(Self)
                .map_err(de::Error::custom),
            value => serde_json::from_value(value)
                .map(|value| Self(vec![value]))
                .map_err(de::Error::custom),
        }
    }
}

impl<T> Serialize for Listable<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let [value] = self.0.as_slice() {
            value.serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

/// Signed nanoseconds, matching Go's `time.Duration` representation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(i64);

impl Duration {
    pub const ZERO: Self = Self(0);

    pub const fn from_nanos(nanos: i64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos(self) -> i64 {
        self.0
    }

    pub fn as_std(self) -> Option<StdDuration> {
        u64::try_from(self.0).ok().map(StdDuration::from_nanos)
    }
}

impl FromStr for Duration {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input == "0" {
            return Ok(Self::ZERO);
        }
        let (negative, mut remaining) = match input.as_bytes().first() {
            Some(b'-') => (true, &input[1..]),
            Some(b'+') => (false, &input[1..]),
            _ => (false, input),
        };
        if remaining.is_empty() {
            return Err(format!("time: invalid duration {input:?}"));
        }
        let mut total = 0_f64;
        while !remaining.is_empty() {
            let number_end = remaining
                .char_indices()
                .take_while(|(_, ch)| ch.is_ascii_digit() || *ch == '.')
                .map(|(index, ch)| index + ch.len_utf8())
                .last()
                .unwrap_or(0);
            if number_end == 0 {
                return Err(format!("time: invalid duration {input:?}"));
            }
            let number: f64 = remaining[..number_end]
                .parse()
                .map_err(|_| format!("time: invalid duration {input:?}"))?;
            remaining = &remaining[number_end..];
            let unit_end = remaining
                .char_indices()
                .take_while(|(_, ch)| !ch.is_ascii_digit() && *ch != '.')
                .map(|(index, ch)| index + ch.len_utf8())
                .last()
                .unwrap_or(0);
            if unit_end == 0 {
                return Err(format!(
                    "time: missing unit in duration {input:?}"
                ));
            }
            let unit_name = &remaining[..unit_end];
            let unit = match unit_name {
                "ns" => 1_f64,
                "us" | "µs" | "μs" => 1_000_f64,
                "ms" => 1_000_000_f64,
                "s" => 1_000_000_000_f64,
                "m" => 60_000_000_000_f64,
                "h" => 3_600_000_000_000_f64,
                "d" => 86_400_000_000_000_f64,
                _ => {
                    return Err(format!(
                        "time: unknown unit {unit_name:?} in duration {input:?}"
                    ));
                }
            };
            total += number * unit;
            remaining = &remaining[unit_end..];
        }
        if negative {
            total = -total;
        }
        if !total.is_finite()
            || total < i64::MIN as f64
            || total > i64::MAX as f64
        {
            return Err(format!("time: invalid duration {input:?}"));
        }
        Ok(Self(total as i64))
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let negative = self.0 < 0;
        let nanos = self.0.unsigned_abs();
        if negative {
            formatter.write_str("-")?;
        }
        if nanos == 0 {
            return formatter.write_str("0s");
        }
        if nanos < 1_000 {
            return write!(formatter, "{nanos}ns");
        }
        if nanos < 1_000_000 {
            return write_fractional(formatter, nanos, 1_000, "µs");
        }
        if nanos < 1_000_000_000 {
            return write_fractional(formatter, nanos, 1_000_000, "ms");
        }
        let hours = nanos / 3_600_000_000_000;
        let after_hours = nanos % 3_600_000_000_000;
        let minutes = after_hours / 60_000_000_000;
        let after_minutes = after_hours % 60_000_000_000;
        if hours > 0 {
            write!(formatter, "{hours}h")?;
        }
        if minutes > 0 {
            write!(formatter, "{minutes}m")?;
        }
        if after_minutes > 0 || (hours == 0 && minutes == 0) {
            write_fractional(formatter, after_minutes, 1_000_000_000, "s")?;
        }
        Ok(())
    }
}

fn write_fractional(
    formatter: &mut fmt::Formatter<'_>,
    nanos: u64,
    unit: u64,
    suffix: &str,
) -> fmt::Result {
    let whole = nanos / unit;
    let remainder = nanos % unit;
    if remainder == 0 {
        return write!(formatter, "{whole}{suffix}");
    }
    let digits = unit.ilog10() as usize;
    let fractional = format!("{remainder:0digits$}");
    write!(
        formatter,
        "{whole}.{}{suffix}",
        fractional.trim_end_matches('0')
    )
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl Serialize for Duration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Addr(pub IpAddr);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Prefix(pub IpNet);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Prefixable(pub IpNet);

impl<'de> Deserialize<'de> for Prefixable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value
            .parse::<IpNet>()
            .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
            .map(Self)
            .map_err(de::Error::custom)
    }
}

impl Serialize for Prefixable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0.prefix_len() == self.0.max_prefix_len() {
            self.0.addr().serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FwMark(pub u32);

impl<'de> Deserialize<'de> for FwMark {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrNumber {
            String(String),
            Number(u32),
        }
        match StringOrNumber::deserialize(deserializer)? {
            StringOrNumber::Number(value) => Ok(Self(value)),
            StringOrNumber::String(value) => {
                let parsed = value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                    .map(|hex| u32::from_str_radix(hex, 16))
                    .unwrap_or_else(|| value.parse());
                parsed.map(Self).map_err(de::Error::custom)
            }
        }
    }
}

impl Serialize for FwMark {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{:x}", self.0))
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NetworkList(Vec<Network>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

impl NetworkList {
    pub fn build(&self) -> &[Network] {
        const DEFAULT: &[Network] = &[Network::Tcp, Network::Udp];
        if self.0.is_empty() { DEFAULT } else { &self.0 }
    }
}

impl<'de> Deserialize<'de> for NetworkList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(String),
            Many(Vec<String>),
        }
        let values = match OneOrMany::deserialize(deserializer)? {
            OneOrMany::One(value) => vec![value],
            OneOrMany::Many(values) => values,
        };
        let mut networks = Vec::with_capacity(values.len());
        for value in values {
            networks.push(match value.as_str() {
                "tcp" => Network::Tcp,
                "udp" => Network::Udp,
                _ => {
                    return Err(de::Error::custom(format!(
                        "unknown network: {value}"
                    )));
                }
            });
        }
        Ok(Self(networks))
    }
}

impl Serialize for NetworkList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = self
            .0
            .iter()
            .map(|network| match network {
                Network::Tcp => "tcp",
                Network::Udp => "udp",
            })
            .collect::<Vec<_>>()
            .join("\n");
        value.serialize(serializer)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

impl<'de> Deserialize<'de> for DomainStrategy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "" | "as_is" => Ok(Self::AsIs),
            "prefer_ipv4" => Ok(Self::PreferIpv4),
            "prefer_ipv6" => Ok(Self::PreferIpv6),
            "ipv4_only" => Ok(Self::Ipv4Only),
            "ipv6_only" => Ok(Self::Ipv6Only),
            _ => Err(de::Error::custom(format!(
                "unknown domain strategy: {value}"
            ))),
        }
    }
}

impl Serialize for DomainStrategy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::AsIs => "",
            Self::PreferIpv4 => "prefer_ipv4",
            Self::PreferIpv6 => "prefer_ipv6",
            Self::Ipv4Only => "ipv4_only",
            Self::Ipv6Only => "ipv6_only",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsQueryType(pub u16);

impl fmt::Display for DnsQueryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match dns_type_name(self.0) {
            Some(name) => f.write_str(name),
            None => self.0.fmt(f),
        }
    }
}

impl<'de> Deserialize<'de> for DnsQueryType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum NameOrNumber {
            Name(String),
            Number(u16),
        }
        match NameOrNumber::deserialize(deserializer)? {
            NameOrNumber::Number(value) => Ok(Self(value)),
            NameOrNumber::Name(name) => {
                dns_type_number(&name).map(Self).ok_or_else(|| {
                    de::Error::custom(format!("unknown DNS query type: {name}"))
                })
            }
        }
    }
}

impl Serialize for DnsQueryType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match dns_type_name(self.0) {
            Some(name) => serializer.serialize_str(name),
            None => serializer.serialize_u16(self.0),
        }
    }
}

fn dns_type_number(name: &str) -> Option<u16> {
    Some(match name.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "NAPTR" => 35,
        "DS" => 43,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "TLSA" => 52,
        "SVCB" => 64,
        "HTTPS" => 65,
        "CAA" => 257,
        _ => return None,
    })
}

fn dns_type_name(value: u16) -> Option<&'static str> {
    Some(match value {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        52 => "TLSA",
        64 => "SVCB",
        65 => "HTTPS",
        257 => "CAA",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DnsQueryType, DomainStrategy, Duration, FwMark, Listable, MemoryBytes,
        Network, NetworkBytesCompat, NetworkList, Prefixable,
    };

    #[test]
    fn network_list_accepts_string_and_array() {
        let one: NetworkList = serde_json::from_str("\"tcp\"").unwrap();
        assert_eq!(one.build(), &[Network::Tcp]);
        let many: NetworkList =
            serde_json::from_str("[\"tcp\",\"udp\"]").unwrap();
        assert_eq!(many.build(), &[Network::Tcp, Network::Udp]);
        assert!(serde_json::from_str::<NetworkList>("\"icmp\"").is_err());
    }

    #[test]
    fn domain_strategy_alias_matches_upstream() {
        let strategy: DomainStrategy =
            serde_json::from_str("\"as_is\"").unwrap();
        assert_eq!(strategy, DomainStrategy::AsIs);
        assert_eq!(serde_json::to_string(&strategy).unwrap(), "\"\"");
    }

    #[test]
    fn dns_query_type_accepts_names_and_numbers() {
        assert_eq!(
            serde_json::from_str::<DnsQueryType>("\"AAAA\"").unwrap().0,
            28
        );
        assert_eq!(
            serde_json::from_str::<DnsQueryType>("65000").unwrap().0,
            65000
        );
    }

    #[test]
    fn listable_uses_scalar_for_one_item() {
        let list: Listable<String> = serde_json::from_str("\"one\"").unwrap();
        assert_eq!(list.as_slice(), &["one"]);
        assert_eq!(serde_json::to_string(&list).unwrap(), "\"one\"");
        let list: Listable<u16> = serde_json::from_str("[53,853]").unwrap();
        assert_eq!(list.as_slice(), &[53, 853]);
    }

    #[test]
    fn duration_supports_upstream_day_extension_and_go_format() {
        let duration: Duration =
            serde_json::from_str("\"1d2h3m4.5s\"").unwrap();
        assert_eq!(duration.to_string(), "26h3m4.5s");
        assert_eq!(serde_json::to_string(&duration).unwrap(), "\"26h3m4.5s\"");
        assert_eq!(
            "300ms".parse::<Duration>().unwrap().as_nanos(),
            300_000_000
        );
        assert!("1fortnight".parse::<Duration>().is_err());
    }

    #[test]
    fn prefixable_and_fwmark_match_wire_forms() {
        let host: Prefixable = serde_json::from_str("\"192.0.2.1\"").unwrap();
        assert_eq!(serde_json::to_string(&host).unwrap(), "\"192.0.2.1\"");
        let net: Prefixable = serde_json::from_str("\"192.0.2.0/24\"").unwrap();
        assert_eq!(serde_json::to_string(&net).unwrap(), "\"192.0.2.0/24\"");
        assert_eq!(serde_json::from_str::<FwMark>("\"0xff\"").unwrap().0, 255);
        assert_eq!(serde_json::to_string(&FwMark(255)).unwrap(), "\"0xff\"");
    }

    #[test]
    fn memory_bytes_uses_binary_units_like_go() {
        assert_eq!(
            serde_json::from_str::<MemoryBytes>("\"4MB\"")
                .unwrap()
                .value(),
            4 * 1024 * 1024
        );
        assert_eq!(
            serde_json::from_str::<MemoryBytes>("4096").unwrap().value(),
            4096
        );
        assert!(serde_json::from_str::<MemoryBytes>("\"4MiB\"").is_err());
    }

    #[test]
    fn network_bytes_compat_accepts_rate_and_legacy_byte_units() {
        assert_eq!(
            serde_json::from_str::<NetworkBytesCompat>("\"8Mbps\"")
                .unwrap()
                .value(),
            1_000_000
        );
        assert_eq!(
            serde_json::from_str::<NetworkBytesCompat>("\"4MiB\"")
                .unwrap()
                .value(),
            4 * 1024 * 1024
        );
        assert!(
            serde_json::from_str::<NetworkBytesCompat>("\"8mbps\"").is_err()
        );
    }
}
