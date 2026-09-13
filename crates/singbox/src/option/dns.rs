use std::{collections::HashMap, fmt, net::IpAddr, str::FromStr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hickory_proto::{
    rr::{Name, Record},
    serialize::{
        binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
        txt::Parser,
    },
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::{Map, Value};

use super::{
    DialerOptions, DnsQueryType, DomainStrategy, Duration, InterfaceType,
    Listable, LogicalRuleMode, OutboundTlsOptions, Prefix, Prefixable,
    ServerOptions,
};

pub(crate) const LEGACY_DNS_FAKEIP_REMOVED_MESSAGE: &str = "legacy DNS fakeip options are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-to-new-dns-server-formats";
pub(crate) const LEGACY_DNS_SERVER_REMOVED_MESSAGE: &str = "legacy DNS server formats are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-to-new-dns-server-formats";

#[derive(Debug, Default, Clone, Serialize)]
pub struct DnsOptions {
    #[serde(default)]
    pub servers: Vec<DnsServerOptions>,
    #[serde(default)]
    pub rules: Vec<DnsRuleOptions>,
    #[serde(default, rename = "final")]
    pub final_server: String,
    #[serde(default)]
    pub reverse_mapping: bool,
    #[serde(flatten)]
    pub client: DnsClientOptions,
}

impl<'de> Deserialize<'de> for DnsOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        if value
            .as_object()
            .is_some_and(|object| object.contains_key("fakeip"))
        {
            return Err(de::Error::custom(LEGACY_DNS_FAKEIP_REMOVED_MESSAGE));
        }
        const FIELDS: &[&str] = &[
            "servers",
            "rules",
            "final",
            "reverse_mapping",
            "strategy",
            "timeout",
            "disable_cache",
            "disable_expire",
            "independent_cache",
            "cache_capacity",
            "optimistic",
            "client_subnet",
        ];
        if let Some(field) = value.as_object().and_then(|object| {
            object.keys().find(|key| !FIELDS.contains(&key.as_str()))
        }) {
            return Err(de::Error::unknown_field(field, FIELDS));
        }

        #[derive(Deserialize)]
        struct Wire {
            #[serde(default)]
            servers: Vec<DnsServerOptions>,
            #[serde(default)]
            rules: Vec<DnsRuleOptions>,
            #[serde(default, rename = "final")]
            final_server: String,
            #[serde(default)]
            reverse_mapping: bool,
            #[serde(flatten)]
            client: DnsClientOptions,
        }

        let wire: Wire = serde_json::from_value(value)
            .map_err(|error| de::Error::custom(error.to_string()))?;
        Ok(Self {
            servers: wire.servers,
            rules: wire.rules,
            final_server: wire.final_server,
            reverse_mapping: wire.reverse_mapping,
            client: wire.client,
        })
    }
}

const DEFAULT_DNS_MATCH_KEYS: &[&str] = &[
    "type",
    "inbound",
    "ip_version",
    "query_type",
    "query_client_subnet",
    "query_dnssec",
    "network",
    "auth_user",
    "protocol",
    "client",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "source_ip_cidr",
    "source_ip_is_private",
    "source_port",
    "source_port_range",
    "port",
    "port_range",
    "process_name",
    "process_path",
    "process_path_regex",
    "package_name",
    "package_name_regex",
    "user",
    "user_id",
    "outbound",
    "clash_mode",
    "network_type",
    "network_is_expensive",
    "network_is_constrained",
    "wifi_ssid",
    "wifi_bssid",
    "interface_address",
    "network_interface_address",
    "default_interface_address",
    "source_mac_address",
    "source_hostname",
    "preferred_by",
    "rule_set",
    "rule_set_ip_cidr_match_source",
    "match_response",
    "ip_cidr",
    "ip_is_private",
    "ip_accept_any",
    "response_rcode",
    "response_answer",
    "response_ns",
    "response_extra",
    "invert",
    "geosite",
    "source_geoip",
    "geoip",
    "rule_set_ip_cidr_accept_empty",
    "rule_set_ipcidr_match_source",
];

const LOGICAL_DNS_MATCH_KEYS: &[&str] = &["type", "mode", "rules", "invert"];

/// Strongly typed top-level DNS rule, including its action.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsRuleOptions {
    Default(Box<DefaultDnsRuleOptions>),
    Logical(Box<LogicalDnsRuleOptions>),
}

impl Default for DnsRuleOptions {
    fn default() -> Self {
        Self::Default(Box::default())
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct DefaultDnsRuleOptions {
    pub matcher: DefaultDnsRuleMatcherOptions,
    pub action: DnsRuleActionOptions,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogicalDnsRuleOptions {
    pub matcher: LogicalDnsRuleMatcherOptions,
    pub action: DnsRuleActionOptions,
}

/// Action-free recursive matcher used below a logical DNS rule.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsRuleMatcherOptions {
    Default(Box<DefaultDnsRuleMatcherOptions>),
    Logical(Box<LogicalDnsRuleMatcherOptions>),
}

impl Default for DnsRuleMatcherOptions {
    fn default() -> Self {
        Self::Default(Box::default())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DefaultDnsRuleMatcherOptions {
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub inbound: Listable<String>,
    #[serde(skip_serializing_if = "i32_is_zero")]
    pub ip_version: i32,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub query_type: Listable<DnsQueryType>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub query_client_subnet: Listable<Prefixable>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub query_dnssec: bool,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub network: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub auth_user: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub protocol: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub client: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub domain: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub domain_suffix: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub domain_keyword: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub domain_regex: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub source_ip_cidr: Listable<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub source_ip_is_private: bool,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub source_port: Listable<u16>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub source_port_range: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub port: Listable<u16>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub port_range: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub process_name: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub process_path: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub process_path_regex: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub package_name: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub package_name_regex: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub user: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub user_id: Listable<i32>,
    /// Deprecated upstream compatibility field.
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub outbound: Listable<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub clash_mode: String,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub network_type: Listable<InterfaceType>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub network_is_expensive: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub network_is_constrained: bool,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub wifi_ssid: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub wifi_bssid: Listable<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub interface_address: HashMap<String, Listable<Prefixable>>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub network_interface_address: HashMap<InterfaceType, Listable<Prefixable>>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub default_interface_address: Listable<Prefixable>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub source_mac_address: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub source_hostname: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub preferred_by: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub rule_set: Listable<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub rule_set_ip_cidr_match_source: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_response: Option<DnsRuleMatchResponse>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub ip_cidr: Listable<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ip_is_private: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ip_accept_any: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_rcode: Option<DnsRCode>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub response_answer: Listable<DnsRecordOptions>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub response_ns: Listable<DnsRecordOptions>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub response_extra: Listable<DnsRecordOptions>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
    /// Deprecated: removed upstream in sing-box 1.12.0.
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub geosite: Listable<String>,
    /// Deprecated: removed upstream in sing-box 1.12.0.
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub source_geoip: Listable<String>,
    /// Deprecated: removed upstream in sing-box 1.12.0.
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub geoip: Listable<String>,
    /// Deprecated in sing-box 1.14.0 and scheduled for removal in 1.16.0.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub rule_set_ip_cidr_accept_empty: bool,
    /// Deprecated spelling retained for config migration.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub rule_set_ipcidr_match_source: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalDnsRuleMatcherOptions {
    pub mode: LogicalRuleMode,
    pub rules: Vec<DnsRuleMatcherOptions>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRuleMatchResponse {
    Disabled,
    Anonymous,
    Tagged(String),
}

impl Serialize for DnsRuleMatchResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Disabled => serializer.serialize_bool(false),
            Self::Anonymous => serializer.serialize_bool(true),
            Self::Tagged(tag) => serializer.serialize_str(tag),
        }
    }
}

impl<'de> Deserialize<'de> for DnsRuleMatchResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Form {
            Boolean(bool),
            Tag(String),
        }
        match Form::deserialize(deserializer)? {
            Form::Boolean(false) => Ok(Self::Disabled),
            Form::Boolean(true) => Ok(Self::Anonymous),
            Form::Tag(tag) if tag.is_empty() => {
                Err(de::Error::custom("empty match_response tag"))
            }
            Form::Tag(tag) => Ok(Self::Tagged(tag)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DnsRCode(pub u16);

impl Serialize for DnsRCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match dns_rcode_name(self.0) {
            Some(name) => serializer.serialize_str(name),
            None => serializer.serialize_u16(self.0),
        }
    }
}

impl<'de> Deserialize<'de> for DnsRCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Form {
            Number(u16),
            Name(String),
        }
        match Form::deserialize(deserializer)? {
            Form::Number(value) => Ok(Self(value)),
            Form::Name(name) => {
                dns_rcode_number(&name).map(Self).ok_or_else(|| {
                    de::Error::custom(format!("unknown rcode: {name}"))
                })
            }
        }
    }
}

/// Validated DNS record in the textual or base64 wire form accepted by
/// sing-box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecordOptions {
    value: String,
    from_base64: bool,
    record: Record,
}

impl DnsRecordOptions {
    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn is_base64(&self) -> bool {
        self.from_base64
    }

    /// Return the validated DNS resource record represented by this option.
    pub fn build(&self) -> Record {
        self.record.clone()
    }

    /// Match a DNS resource record using RFC 2136 equality.  As in the
    /// pinned Go implementation, TTL is deliberately ignored.
    pub fn matches(&self, record: &Record) -> bool {
        self.record == *record
    }
}

impl fmt::Display for DnsRecordOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

impl FromStr for DnsRecordOptions {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(binary) = STANDARD.decode(value) {
            let mut decoder = BinDecoder::new(&binary);
            let record = Record::read(&mut decoder)
                .map_err(|_| "parse binary DNS record".to_owned())?;
            let mut canonical = Vec::new();
            record
                .emit(&mut BinEncoder::new(&mut canonical))
                .map_err(|error| error.to_string())?;
            return Ok(Self {
                value: STANDARD.encode(canonical),
                from_base64: true,
                record,
            });
        }
        // Hickory requires an origin even though the pinned Go parser uses an
        // empty one and rejects every relative name.  Parse against a sentinel
        // origin that does not occur in the input, then reject a record when
        // the sentinel appears in either its owner or RDATA rendering.
        let lower_value = value.to_ascii_lowercase();
        let mut origin_index = 0_u64;
        let origin = loop {
            let candidate =
                format!("_singbox-relative-{origin_index}.invalid.");
            if !lower_value.contains(&candidate) {
                break candidate;
            }
            origin_index += 1;
        };
        let zone = format!("$TTL 3600\n{value}\n");
        let (_, sets) = Parser::new(
            zone,
            None,
            Some(Name::from_ascii(&origin).map_err(|error| error.to_string())?),
        )
        .parse()
        .map_err(|error| error.to_string())?;
        let mut records = sets.into_values().flat_map(IntoIterator::into_iter);
        let record = records
            .next()
            .ok_or_else(|| "empty DNS record".to_owned())?;
        if records.next().is_some() {
            return Err("DNS record string contains multiple records".into());
        }
        if record.to_string().to_ascii_lowercase().contains(&origin) {
            return Err("relative domain name in DNS record".into());
        }
        // DNS wire encoding has no representation for relative names.  This
        // therefore validates both the owner and any domain names embedded in
        // RDATA without maintaining a record-type-specific name walker.
        let mut wire = Vec::new();
        record
            .emit(&mut BinEncoder::new(&mut wire))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            value: record.to_string(),
            from_base64: false,
            record,
        })
    }
}

impl Serialize for DnsRecordOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.value)
    }
}

impl<'de> Deserialize<'de> for DnsRecordOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsLookupOverrideOptions {
    #[serde(skip_serializing_if = "duration_is_zero")]
    pub timeout: Duration,
    #[serde(skip_serializing_if = "domain_strategy_is_default")]
    pub strategy: DomainStrategy,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub disable_cache: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub disable_optimistic_cache: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rewrite_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<Prefixable>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub remove_client_subnet: bool,
}

impl DnsLookupOverrideOptions {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsRouteActionOptions {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub speculative: bool,
    #[serde(flatten)]
    pub options: DnsLookupOverrideOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsEvaluateActionOptions {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub speculative: bool,
    #[serde(flatten)]
    pub options: DnsLookupOverrideOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsRejectActionOptions {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub no_drop: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsPredefinedActionOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rcode: Option<DnsRCode>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub answer: Listable<DnsRecordOptions>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub ns: Listable<DnsRecordOptions>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub extra: Listable<DnsRecordOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRuleActionKind {
    Route(DnsRouteActionOptions),
    Evaluate(DnsEvaluateActionOptions),
    Respond,
    RouteOptions(DnsLookupOverrideOptions),
    Reject(DnsRejectActionOptions),
    Predefined(DnsPredefinedActionOptions),
}

impl Default for DnsRuleActionKind {
    fn default() -> Self {
        Self::Route(DnsRouteActionOptions::default())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DnsRuleActionOptions {
    pub race: bool,
    pub action: DnsRuleActionKind,
}

impl DnsRuleOptions {
    pub fn to_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

impl Serialize for DnsRuleOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (mut object, action) = match self {
            Self::Default(rule) => {
                (dns_object_from(&rule.matcher), &rule.action)
            }
            Self::Logical(rule) => {
                let mut object = dns_object_from(&rule.matcher);
                object.insert("type".into(), Value::String("logical".into()));
                (object, &rule.action)
            }
        };
        object.extend(dns_action_object(action));
        Value::Object(object).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DnsRuleOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        parse_dns_rule(Value::deserialize(deserializer)?)
            .map_err(de::Error::custom)
    }
}

impl Serialize for DnsRuleMatcherOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let object = match self {
            Self::Default(options) => dns_object_from(options.as_ref()),
            Self::Logical(options) => {
                let mut object = dns_object_from(options.as_ref());
                object.insert("type".into(), Value::String("logical".into()));
                object
            }
        };
        Value::Object(object).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DnsRuleMatcherOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        parse_dns_matcher(Value::deserialize(deserializer)?)
            .map_err(de::Error::custom)
    }
}

fn parse_dns_rule(value: Value) -> Result<DnsRuleOptions, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "DNS rule is not an object".to_owned())?;
    let kind = dns_optional_string_field(object, "type", "DNS rule")?;
    match kind {
        "" | "default" => {
            let (mut matcher, action) =
                split_dns_rule_object(object, DEFAULT_DNS_MATCH_KEYS);
            matcher.remove("type");
            Ok(DnsRuleOptions::Default(Box::new(DefaultDnsRuleOptions {
                matcher: dns_decode_object(matcher)?,
                action: parse_dns_action(action)?,
            })))
        }
        "logical" => {
            let (mut matcher, action) =
                split_dns_rule_object(object, LOGICAL_DNS_MATCH_KEYS);
            matcher.remove("type");
            Ok(DnsRuleOptions::Logical(Box::new(LogicalDnsRuleOptions {
                matcher: dns_decode_object(matcher)?,
                action: parse_dns_action(action)?,
            })))
        }
        _ => Err(format!("unknown DNS rule type: {kind}")),
    }
}

fn parse_dns_matcher(value: Value) -> Result<DnsRuleMatcherOptions, String> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or_else(|| "nested DNS rule is not an object".to_owned())?;
    let kind = dns_optional_string_field(&object, "type", "nested DNS rule")?
        .to_owned();
    let allowed = match kind.as_str() {
        "" | "default" => DEFAULT_DNS_MATCH_KEYS,
        "logical" => LOGICAL_DNS_MATCH_KEYS,
        _ => return Err(format!("unknown nested DNS rule type: {kind}")),
    };
    if object
        .keys()
        .any(|key| DNS_RULE_ACTION_KEYS.contains(&key.as_str()))
    {
        return Err(DNS_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE.into());
    }
    dns_ensure_only(&object, allowed, "nested DNS rule")?;
    object.remove("type");
    match kind.as_str() {
        "" | "default" => dns_decode_object(object)
            .map(Box::new)
            .map(DnsRuleMatcherOptions::Default),
        "logical" => dns_decode_object(object)
            .map(Box::new)
            .map(DnsRuleMatcherOptions::Logical),
        _ => unreachable!(),
    }
}

fn split_dns_rule_object(
    object: &Map<String, Value>,
    matcher_keys: &[&str],
) -> (Map<String, Value>, Map<String, Value>) {
    object
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .partition(|(key, _)| matcher_keys.contains(&key.as_str()))
}

fn parse_dns_action(
    mut object: Map<String, Value>,
) -> Result<DnsRuleActionOptions, String> {
    let action = object
        .remove("action")
        .map(serde_json::from_value::<String>)
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or_else(|| "route".into());
    let race = dns_take_bool(&mut object, "race")?;
    let action = match action.as_str() {
        "" | "route" => {
            dns_ensure_only(
                &object,
                DNS_ROUTE_ACTION_KEYS,
                "DNS route action",
            )?;
            DnsRuleActionKind::Route(dns_decode_object(object)?)
        }
        "evaluate" => {
            dns_ensure_only(
                &object,
                DNS_EVALUATE_ACTION_KEYS,
                "DNS evaluate action",
            )?;
            DnsRuleActionKind::Evaluate(dns_decode_object(object)?)
        }
        "respond" => {
            dns_ensure_only(&object, &[], "DNS respond action")?;
            DnsRuleActionKind::Respond
        }
        "route-options" => {
            dns_ensure_only(
                &object,
                DNS_LOOKUP_OVERRIDE_KEYS,
                "DNS route-options action",
            )?;
            let options: DnsLookupOverrideOptions = dns_decode_object(object)?;
            if options.is_empty() {
                return Err("empty DNS route option action".into());
            }
            DnsRuleActionKind::RouteOptions(options)
        }
        "reject" => {
            dns_ensure_only(
                &object,
                &["method", "no_drop"],
                "DNS reject action",
            )?;
            let mut options: DnsRejectActionOptions =
                dns_decode_object(object)?;
            match options.method.as_str() {
                "" | "default" => options.method = "default".into(),
                "drop" => {}
                "reply" => {
                    return Err(DNS_REPLY_REJECT_UNSUPPORTED_MESSAGE.into());
                }
                method => {
                    return Err(format!("unknown DNS reject method: {method}"));
                }
            }
            if options.method == "drop" && options.no_drop {
                return Err(
                    "no_drop is not available with drop reject method".into()
                );
            }
            DnsRuleActionKind::Reject(options)
        }
        "predefined" => {
            dns_ensure_only(
                &object,
                &["rcode", "answer", "ns", "extra"],
                "DNS predefined action",
            )?;
            DnsRuleActionKind::Predefined(dns_decode_object(object)?)
        }
        _ => return Err(format!("unknown DNS rule action: {action}")),
    };
    Ok(DnsRuleActionOptions { race, action })
}

fn dns_action_object(action: &DnsRuleActionOptions) -> Map<String, Value> {
    let (kind, mut object) = match &action.action {
        DnsRuleActionKind::Route(options) => (None, dns_object_from(options)),
        DnsRuleActionKind::Evaluate(options) => {
            (Some("evaluate"), dns_object_from(options))
        }
        DnsRuleActionKind::Respond => (Some("respond"), Map::new()),
        DnsRuleActionKind::RouteOptions(options) => {
            (Some("route-options"), dns_object_from(options))
        }
        DnsRuleActionKind::Reject(options) => {
            let mut object = dns_object_from(options);
            if object.get("method").and_then(Value::as_str) == Some("default") {
                object.remove("method");
            }
            (Some("reject"), object)
        }
        DnsRuleActionKind::Predefined(options) => {
            (Some("predefined"), dns_object_from(options))
        }
    };
    if let Some(kind) = kind {
        object.insert("action".into(), Value::String(kind.into()));
    }
    if action.race {
        object.insert("race".into(), Value::Bool(true));
    }
    object
}

const DNS_LOOKUP_OVERRIDE_KEYS: &[&str] = &[
    "timeout",
    "strategy",
    "disable_cache",
    "disable_optimistic_cache",
    "rewrite_ttl",
    "client_subnet",
    "remove_client_subnet",
];

const DNS_ROUTE_ACTION_KEYS: &[&str] = &[
    "server",
    "speculative",
    "timeout",
    "strategy",
    "disable_cache",
    "disable_optimistic_cache",
    "rewrite_ttl",
    "client_subnet",
    "remove_client_subnet",
];

const DNS_EVALUATE_ACTION_KEYS: &[&str] = &[
    "server",
    "tag",
    "speculative",
    "timeout",
    "strategy",
    "disable_cache",
    "disable_optimistic_cache",
    "rewrite_ttl",
    "client_subnet",
    "remove_client_subnet",
];

pub const DNS_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE: &str =
    "DNS rule action is not supported in nested rules";

pub const DNS_REPLY_REJECT_UNSUPPORTED_MESSAGE: &str =
    "reject method `reply` is not supported for DNS rules";

const DNS_RULE_ACTION_KEYS: &[&str] = &[
    "action",
    "race",
    "server",
    "tag",
    "speculative",
    "timeout",
    "strategy",
    "disable_cache",
    "disable_optimistic_cache",
    "rewrite_ttl",
    "client_subnet",
    "remove_client_subnet",
];

fn dns_ensure_only(
    object: &Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), String> {
    if let Some(key) =
        object.keys().find(|key| !allowed.contains(&key.as_str()))
    {
        return Err(format!("{context}: unknown field {key:?}"));
    }
    Ok(())
}

fn dns_optional_string_field<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    context: &str,
) -> Result<&'a str, String> {
    match object.get(key) {
        None => Ok(""),
        Some(Value::String(value)) => Ok(value),
        Some(_) => Err(format!("{context} field {key:?} is not a string")),
    }
}

fn dns_take_bool(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<bool, String> {
    object
        .remove(key)
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| error.to_string())
        .map(Option::unwrap_or_default)
}

fn dns_decode_object<T: serde::de::DeserializeOwned>(
    object: Map<String, Value>,
) -> Result<T, String> {
    serde_json::from_value(Value::Object(object))
        .map_err(|error| error.to_string())
}

fn dns_object_from<T: Serialize>(value: &T) -> Map<String, Value> {
    serde_json::to_value(value)
        .expect("serializing a typed DNS option cannot fail")
        .as_object()
        .expect("typed DNS options serialize as objects")
        .clone()
}

fn dns_rcode_number(name: &str) -> Option<u16> {
    Some(match name.to_ascii_uppercase().as_str() {
        "NOERROR" => 0,
        "FORMERR" => 1,
        "SERVFAIL" => 2,
        "NXDOMAIN" => 3,
        "NOTIMP" => 4,
        "REFUSED" => 5,
        "YXDOMAIN" => 6,
        "YXRRSET" => 7,
        "NXRRSET" => 8,
        "NOTAUTH" => 9,
        "NOTZONE" => 10,
        "BADSIG" | "BADVERS" => 16,
        "BADKEY" => 17,
        "BADTIME" => 18,
        "BADMODE" => 19,
        "BADNAME" => 20,
        "BADALG" => 21,
        "BADTRUNC" => 22,
        "BADCOOKIE" => 23,
        _ => return None,
    })
}

fn dns_rcode_name(value: u16) -> Option<&'static str> {
    Some(match value {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADSIG",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => return None,
    })
}

fn i32_is_zero(value: &i32) -> bool {
    *value == 0
}

fn domain_strategy_is_default(value: &DomainStrategy) -> bool {
    *value == DomainStrategy::default()
}

fn duration_is_zero(value: &Duration) -> bool {
    *value == Duration::ZERO
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DnsClientOptions {
    #[serde(default)]
    pub strategy: DomainStrategy,
    #[serde(default)]
    pub timeout: Duration,
    #[serde(default)]
    pub disable_cache: bool,
    #[serde(default)]
    pub disable_expire: bool,
    #[serde(default)]
    pub independent_cache: bool,
    #[serde(default)]
    pub cache_capacity: u32,
    #[serde(default)]
    pub optimistic: Option<OptimisticDnsOptions>,
    #[serde(default)]
    pub client_subnet: Option<Prefixable>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OptimisticDnsOptions {
    pub enabled: bool,
    pub timeout: Duration,
}

impl<'de> Deserialize<'de> for OptimisticDnsOptions {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Form {
            Boolean(bool),
            Object {
                #[serde(default)]
                enabled: bool,
                #[serde(default)]
                timeout: Duration,
            },
        }
        Ok(match Form::deserialize(deserializer)? {
            Form::Boolean(enabled) => Self {
                enabled,
                timeout: Duration::ZERO,
            },
            Form::Object { enabled, timeout } => Self { enabled, timeout },
        })
    }
}

impl Serialize for OptimisticDnsOptions {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if self.timeout == Duration::ZERO {
            return self.enabled.serialize(serializer);
        }
        #[derive(Serialize)]
        struct Object {
            enabled: bool,
            timeout: Duration,
        }
        Object {
            enabled: self.enabled,
            timeout: self.timeout,
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerOptions {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub tag: String,
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

impl DnsServerOptions {
    pub fn decode<T: serde::de::DeserializeOwned>(
        &self,
    ) -> Result<T, serde_json::Error> {
        serde_json::from_value(Value::Object(self.fields.clone()))
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DnsServerAddressOptions {
    pub server: String,
    #[serde(default)]
    pub server_port: u16,
}

impl From<DnsServerAddressOptions> for ServerOptions {
    fn from(value: DnsServerAddressOptions) -> Self {
        Self {
            server: value.server,
            server_port: value.server_port,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HostsDnsServerOptions {
    #[serde(default)]
    pub path: Listable<String>,
    #[serde(default)]
    pub predefined: HashMap<String, Listable<IpAddr>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LocalDnsServerOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(default)]
    pub prefer_go: bool,
    #[serde(default)]
    pub neighbor_domain: Listable<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RemoteDnsServerOptions {
    #[serde(flatten)]
    pub local: LocalDnsServerOptions,
    #[serde(flatten)]
    pub address: DnsServerAddressOptions,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RemoteTlsDnsServerOptions {
    #[serde(flatten)]
    pub remote: RemoteDnsServerOptions,
    #[serde(default)]
    pub tls: Option<OutboundTlsOptions>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RemoteHttpsDnsServerOptions {
    #[serde(flatten)]
    pub remote_tls: RemoteTlsDnsServerOptions,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub headers: Map<String, Value>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FakeIpDnsServerOptions {
    #[serde(default)]
    pub inet4_range: Option<Prefix>,
    #[serde(default)]
    pub inet6_range: Option<Prefix>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DhcpDnsServerOptions {
    #[serde(flatten)]
    pub local: LocalDnsServerOptions,
    #[serde(default)]
    pub interface: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MdnsDnsServerOptions {
    #[serde(flatten)]
    pub local: LocalDnsServerOptions,
    #[serde(default)]
    pub interface: Listable<String>,
}

#[cfg(test)]
mod tests {
    use super::{
        DNS_REPLY_REJECT_UNSUPPORTED_MESSAGE,
        DNS_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE, DnsOptions,
        DnsRecordOptions, DnsRuleActionKind, DnsRuleMatchResponse,
        DnsRuleOptions, OptimisticDnsOptions, RemoteHttpsDnsServerOptions,
    };

    #[test]
    fn dns_records_reject_relative_names_and_match_without_ttl() {
        for record in [
            "@ IN A 1.1.1.1",
            "www IN CNAME example.com.",
            "example.com. IN CNAME @",
            "example.com. IN CNAME www",
        ] {
            assert!(record.parse::<DnsRecordOptions>().is_err(), "{record}");
        }

        let expected = "example.com. 600 IN A 1.1.1.1"
            .parse::<DnsRecordOptions>()
            .unwrap();
        let actual = "example.com. 60 IN A 1.1.1.1"
            .parse::<DnsRecordOptions>()
            .unwrap()
            .build();
        assert!(expected.matches(&actual));
    }

    #[test]
    fn optimistic_options_accept_boolean_and_object_forms() {
        let enabled: OptimisticDnsOptions =
            serde_json::from_str("true").unwrap();
        assert!(enabled.enabled);
        assert_eq!(serde_json::to_string(&enabled).unwrap(), "true");
        let object: OptimisticDnsOptions =
            serde_json::from_str(r#"{"enabled":true,"timeout":"50ms"}"#)
                .unwrap();
        assert_eq!(object.timeout.to_string(), "50ms");
    }

    #[test]
    fn decodes_tagged_https_transport() {
        let options: DnsOptions = serde_json::from_str(r#"{
            "servers":[{"type":"https","tag":"remote","server":"1.1.1.1","server_port":443,"path":"/dns-query","tls":{"enabled":true}}],
            "final":"remote"
        }"#).unwrap();
        let server: RemoteHttpsDnsServerOptions =
            options.servers[0].decode().unwrap();
        assert_eq!(server.remote_tls.remote.address.server, "1.1.1.1");
        assert!(server.remote_tls.tls.unwrap().enabled);
    }

    #[test]
    fn dns_rules_preserve_go_matcher_then_action_decoding() {
        let parsed: DnsRuleOptions =
            serde_json::from_value(serde_json::json!({
                "domain_suffix": "example.com",
                "outbound": "direct",
                "match_response": "bootstrap",
                "server": "remote",
                "strategy": "prefer_ipv4",
                "race": true
            }))
            .unwrap();
        let DnsRuleOptions::Default(rule) = &parsed else {
            panic!("expected default DNS rule");
        };
        assert_eq!(rule.matcher.outbound.as_slice(), ["direct"]);
        assert_eq!(
            rule.matcher.match_response,
            Some(DnsRuleMatchResponse::Tagged("bootstrap".into()))
        );
        let DnsRuleActionKind::Route(action) = &rule.action.action else {
            panic!("expected route action");
        };
        assert_eq!(action.server, "remote");
        assert!(rule.action.race);
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            serde_json::json!({
                "domain_suffix": "example.com",
                "outbound": "direct",
                "match_response": "bootstrap",
                "server": "remote",
                "strategy": "prefer_ipv4",
                "race": true
            })
        );
    }

    #[test]
    fn dns_rules_reject_nested_actions_and_action_shape_mixing() {
        for invalid in [
            serde_json::json!({
                "type": "logical",
                "mode": "or",
                "rules": [{"domain": "example.com", "server": "nested"}],
                "server": "remote"
            }),
            serde_json::json!({
                "type": "logical",
                "mode": "or",
                "rules": [{"domain": "example.com"}],
                "domain": "ignored",
                "server": "remote"
            }),
            serde_json::json!({
                "action": "respond",
                "server": "unexpected"
            }),
            serde_json::json!({
                "action": "route-options"
            }),
            serde_json::json!({
                "action": "reject",
                "method": "drop",
                "no_drop": true
            }),
            serde_json::json!({"type": 1, "server": "remote"}),
            serde_json::json!({"action": 1, "server": "remote"}),
        ] {
            assert!(serde_json::from_value::<DnsRuleOptions>(invalid).is_err());
        }

        let error =
            serde_json::from_value::<DnsRuleOptions>(serde_json::json!({
                "type": "logical",
                "mode": "and",
                "rules": [{"domain": "example.com", "server": "default"}]
            }))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(DNS_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE),
            "{error}"
        );

        let error =
            serde_json::from_value::<DnsRuleOptions>(serde_json::json!({
                "type": "logical",
                "mode": "and",
                "rules": [{"domain": "example.com", "foo": "bar"}]
            }))
            .unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
        assert!(
            !error
                .to_string()
                .contains(DNS_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE),
            "{error}"
        );

        let error =
            serde_json::from_value::<DnsRuleOptions>(serde_json::json!({
                "action": "reject",
                "method": "reply"
            }))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(DNS_REPLY_REJECT_UNSUPPORTED_MESSAGE),
            "{error}"
        );
    }

    #[test]
    fn dns_record_and_response_scalars_are_strict() {
        let rule: DnsRuleOptions = serde_json::from_value(serde_json::json!({
            "match_response": true,
            "response_rcode": "NXDOMAIN",
            "response_answer": ". 60 IN A 192.0.2.1",
            "action": "predefined",
            "rcode": 3,
            "answer": ". 60 IN A 192.0.2.2"
        }))
        .unwrap();
        let value = rule.to_value().unwrap();
        assert_eq!(value["match_response"], true);
        assert_eq!(value["response_rcode"], "NXDOMAIN");
        assert_eq!(value["rcode"], "NXDOMAIN");
        assert!(value["answer"].as_str().unwrap().contains("192.0.2.2"));

        assert!(
            serde_json::from_value::<DnsRuleOptions>(serde_json::json!({
                "action": "predefined",
                "answer": "not a DNS record"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DnsRuleOptions>(serde_json::json!({
                "match_response": ""
            }))
            .is_err()
        );
    }
}
