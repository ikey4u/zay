use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::{Map, Value};

use super::{
    AbstractDialerOptions, DnsQueryType, DomainResolveOptions, DomainStrategy,
    Duration, FwMark, HttpClientReference, InterfaceType, Listable,
    NetworkStrategy, Prefixable,
};

/// Top-level routing configuration at the pinned sing-box schema boundary.
///
/// Rule matchers/actions and rule-set sources are represented by strict,
/// recursive Rust enums so embedding applications do not need to construct
/// unvalidated `serde_json::Value` trees.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip: Option<GeoIpOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geosite: Option<GeositeOptions>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RouteRuleOptions>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<RuleSetOptions>,
    #[serde(
        rename = "final",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub final_outbound: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub find_process: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub find_neighbor: bool,
    #[serde(default, skip_serializing_if = "Listable::is_empty")]
    pub dhcp_lease_files: Listable<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auto_detect_interface: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub override_android_vpn: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_interface: String,
    #[serde(default, skip_serializing_if = "fwmark_is_zero")]
    pub default_mark: FwMark,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_domain_resolver: Option<DomainResolveOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_network_strategy: Option<NetworkStrategy>,
    #[serde(default, skip_serializing_if = "Listable::is_empty")]
    pub default_network_type: Listable<InterfaceType>,
    #[serde(default, skip_serializing_if = "Listable::is_empty")]
    pub default_fallback_network_type: Listable<InterfaceType>,
    #[serde(default, skip_serializing_if = "duration_is_zero")]
    pub default_fallback_delay: Duration,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_http_client: String,
}

/// Strongly typed fixed variants of a top-level sing-box rule-set source.
///
/// The rules inside an inline source intentionally remain recursive headless
/// rule syntax trees. Unlike the former unbounded top-level `Value`, this enum
/// makes the source kind and every source-specific field explicit and rejects
/// fields belonging to another variant.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleSetOptions {
    Inline(InlineRuleSetOptions),
    Local(LocalRuleSetOptions),
    Remote(RemoteRuleSetOptions),
}

/// Recursive, action-free rule used by inline and source rule-sets.
///
/// Keeping this separate from top-level route rules makes it impossible to
/// attach a route action to a nested rule through the typed API, matching the
/// pinned Go `HeadlessRule` contract.
#[derive(Debug, Clone, PartialEq)]
pub enum HeadlessRuleOptions {
    Default(Box<DefaultHeadlessRuleOptions>),
    Logical(LogicalHeadlessRuleOptions),
}

impl Default for HeadlessRuleOptions {
    fn default() -> Self {
        Self::Default(Box::default())
    }
}

impl HeadlessRuleOptions {
    pub fn to_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DefaultHeadlessRuleOptions {
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub query_type: Listable<DnsQueryType>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub network: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub domain: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub domain_suffix: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub domain_keyword: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub domain_regex: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub adguard_domain: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub source_ip_cidr: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub ip_cidr: Listable<String>,
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
    pub network_interface_address: HashMap<InterfaceType, Listable<Prefixable>>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub default_interface_address: Listable<Prefixable>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogicalRuleMode {
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalHeadlessRuleOptions {
    pub mode: LogicalRuleMode,
    pub rules: Vec<HeadlessRuleOptions>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
}

impl Serialize for HeadlessRuleOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let object = match self {
            Self::Default(options) => object_from(options),
            Self::Logical(options) => {
                let mut object = object_from(options);
                object.insert("type".into(), Value::String("logical".into()));
                object
            }
        };
        Value::Object(object).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HeadlessRuleOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = Value::deserialize(deserializer)?;
        let object = value.as_object_mut().ok_or_else(|| {
            de::Error::custom("headless rule is not an object")
        })?;
        let kind = object
            .remove("type")
            .map(serde_json::from_value::<String>)
            .transpose()
            .map_err(de::Error::custom)?
            .unwrap_or_default();
        match kind.as_str() {
            "" | "default" => serde_json::from_value(value)
                .map(Box::new)
                .map(Self::Default)
                .map_err(de::Error::custom),
            "logical" => serde_json::from_value(value)
                .map(Self::Logical)
                .map_err(de::Error::custom),
            _ => Err(de::Error::custom(format!(
                "unknown headless rule type: {kind}"
            ))),
        }
    }
}

const DEFAULT_ROUTE_MATCH_KEYS: &[&str] = &[
    "type",
    "inbound",
    "ip_version",
    "network",
    "auth_user",
    "protocol",
    "client",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "geosite",
    "source_geoip",
    "geoip",
    "source_ip_cidr",
    "source_ip_is_private",
    "ip_cidr",
    "ip_is_private",
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
    "rule_set_ipcidr_match_source",
    "invert",
];

const LOGICAL_ROUTE_MATCH_KEYS: &[&str] = &["type", "mode", "rules", "invert"];

/// Strongly typed top-level route rule, including its route action.
#[derive(Debug, Clone, PartialEq)]
pub enum RouteRuleOptions {
    Default(Box<DefaultRouteRuleOptions>),
    Logical(Box<LogicalRouteRuleOptions>),
}

impl Default for RouteRuleOptions {
    fn default() -> Self {
        Self::Default(Box::default())
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct DefaultRouteRuleOptions {
    pub matcher: DefaultRouteRuleMatcherOptions,
    pub action: RouteRuleActionOptions,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogicalRouteRuleOptions {
    pub matcher: LogicalRouteRuleMatcherOptions,
    pub action: RouteRuleActionOptions,
}

/// Action-free recursive matcher used below a logical route rule.
#[derive(Debug, Clone, PartialEq)]
pub enum RouteRuleMatcherOptions {
    Default(Box<DefaultRouteRuleMatcherOptions>),
    Logical(Box<LogicalRouteRuleMatcherOptions>),
}

impl Default for RouteRuleMatcherOptions {
    fn default() -> Self {
        Self::Default(Box::default())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DefaultRouteRuleMatcherOptions {
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub inbound: Listable<String>,
    #[serde(skip_serializing_if = "i32_is_zero")]
    pub ip_version: i32,
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
    /// Deprecated: removed upstream in sing-box 1.12.0.
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub geosite: Listable<String>,
    /// Deprecated: removed upstream in sing-box 1.12.0.
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub source_geoip: Listable<String>,
    /// Deprecated: removed upstream in sing-box 1.12.0.
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub geoip: Listable<String>,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub source_ip_cidr: Listable<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub source_ip_is_private: bool,
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub ip_cidr: Listable<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ip_is_private: bool,
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
    /// Deprecated spelling retained for config migration.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub rule_set_ipcidr_match_source: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRouteRuleMatcherOptions {
    pub mode: LogicalRuleMode,
    pub rules: Vec<RouteRuleMatcherOptions>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteOverrideOptions {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub override_address: String,
    #[serde(skip_serializing_if = "u16_is_zero")]
    pub override_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_strategy: Option<NetworkStrategy>,
    #[serde(skip_serializing_if = "u32_is_zero")]
    pub fallback_delay: u32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub udp_disable_domain_unmapping: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub udp_connect: bool,
    #[serde(skip_serializing_if = "duration_is_zero")]
    pub udp_timeout: Duration,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub tls_fragment: bool,
    #[serde(skip_serializing_if = "duration_is_zero")]
    pub tls_fragment_fallback_delay: Duration,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub tls_record_fragment: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tls_spoof: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tls_spoof_method: String,
}

impl RouteOverrideOptions {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RouteActionOptions {
    pub outbound: String,
    pub options: RouteOverrideOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RejectRouteActionOptions {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub no_drop: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SniffRouteActionOptions {
    #[serde(skip_serializing_if = "Listable::is_empty")]
    pub sniffer: Listable<String>,
    #[serde(skip_serializing_if = "duration_is_zero")]
    pub timeout: Duration,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResolveRouteActionOptions {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server: String,
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
}

#[derive(Debug, Clone, PartialEq)]
pub enum RouteRuleActionOptions {
    Route(RouteActionOptions),
    RouteOptions(RouteOverrideOptions),
    Direct(Box<AbstractDialerOptions>),
    Bypass(RouteActionOptions),
    Reject(RejectRouteActionOptions),
    HijackDns,
    Sniff(SniffRouteActionOptions),
    Resolve(ResolveRouteActionOptions),
}

impl Default for RouteRuleActionOptions {
    fn default() -> Self {
        Self::Route(RouteActionOptions::default())
    }
}

impl RouteRuleOptions {
    pub fn to_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    pub(crate) fn resolve_network_namespace(
        &mut self,
        paths: &HashMap<String, String>,
    ) {
        let action = match self {
            Self::Default(rule) => &mut rule.action,
            Self::Logical(rule) => &mut rule.action,
        };
        if let RouteRuleActionOptions::Direct(options) = action
            && let Some(path) = paths.get(&options.netns)
        {
            options.netns.clone_from(path);
        }
    }
}

impl Serialize for RouteRuleOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (mut object, action) = match self {
            Self::Default(rule) => (object_from(&rule.matcher), &rule.action),
            Self::Logical(rule) => {
                let mut object = object_from(&rule.matcher);
                object.insert("type".into(), Value::String("logical".into()));
                (object, &rule.action)
            }
        };
        object.extend(route_action_object(action));
        Value::Object(object).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RouteRuleOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        parse_route_rule(Value::deserialize(deserializer)?)
            .map_err(de::Error::custom)
    }
}

impl Serialize for RouteRuleMatcherOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let object = match self {
            Self::Default(options) => object_from(options.as_ref()),
            Self::Logical(options) => {
                let mut object = object_from(options.as_ref());
                object.insert("type".into(), Value::String("logical".into()));
                object
            }
        };
        Value::Object(object).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RouteRuleMatcherOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        parse_route_matcher(Value::deserialize(deserializer)?)
            .map_err(de::Error::custom)
    }
}

fn parse_route_rule(value: Value) -> Result<RouteRuleOptions, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "route rule is not an object".to_owned())?;
    let kind = optional_string_field(object, "type", "route rule")?;
    match kind {
        "" | "default" => {
            let (mut matcher, action) =
                split_route_rule_object(object, DEFAULT_ROUTE_MATCH_KEYS);
            matcher.remove("type");
            let matcher = decode_object(matcher)?;
            let action = parse_route_action(action)?;
            Ok(RouteRuleOptions::Default(Box::new(
                DefaultRouteRuleOptions { matcher, action },
            )))
        }
        "logical" => {
            let (mut matcher, action) =
                split_route_rule_object(object, LOGICAL_ROUTE_MATCH_KEYS);
            matcher.remove("type");
            let matcher = decode_object(matcher)?;
            let action = parse_route_action(action)?;
            Ok(RouteRuleOptions::Logical(Box::new(
                LogicalRouteRuleOptions { matcher, action },
            )))
        }
        _ => Err(format!("unknown route rule type: {kind}")),
    }
}

fn parse_route_matcher(
    value: Value,
) -> Result<RouteRuleMatcherOptions, String> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or_else(|| "nested route rule is not an object".to_owned())?;
    let kind =
        optional_string_field(&object, "type", "nested route rule")?.to_owned();
    let allowed = match kind.as_str() {
        "" | "default" => DEFAULT_ROUTE_MATCH_KEYS,
        "logical" => LOGICAL_ROUTE_MATCH_KEYS,
        _ => return Err(format!("unknown nested route rule type: {kind}")),
    };
    if object
        .keys()
        .any(|key| ROUTE_RULE_ACTION_KEYS.contains(&key.as_str()))
    {
        return Err(ROUTE_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE.into());
    }
    ensure_only(&object, allowed, "nested route rule")?;
    object.remove("type");
    match kind.as_str() {
        "" | "default" => decode_object(object)
            .map(Box::new)
            .map(RouteRuleMatcherOptions::Default),
        "logical" => decode_object(object)
            .map(Box::new)
            .map(RouteRuleMatcherOptions::Logical),
        _ => unreachable!(),
    }
}

fn split_route_rule_object(
    object: &Map<String, Value>,
    matcher_keys: &[&str],
) -> (Map<String, Value>, Map<String, Value>) {
    object
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .partition(|(key, _)| matcher_keys.contains(&key.as_str()))
}

fn route_action_object(action: &RouteRuleActionOptions) -> Map<String, Value> {
    let (kind, mut object) = match action {
        RouteRuleActionOptions::Route(options) => {
            let mut object = object_from(&options.options);
            if !options.outbound.is_empty() {
                object.insert(
                    "outbound".into(),
                    Value::String(options.outbound.clone()),
                );
            }
            (None, object)
        }
        RouteRuleActionOptions::RouteOptions(options) => {
            (Some("route-options"), object_from(options))
        }
        RouteRuleActionOptions::Direct(options) => {
            let mut object = object_from(options.as_ref());
            object.retain(|_, value| !is_default_json(value));
            if let Some(udp_fragment) = options.udp_fragment {
                object.insert("udp_fragment".into(), Value::Bool(udp_fragment));
            }
            (Some("direct"), object)
        }
        RouteRuleActionOptions::Bypass(options) => {
            let mut object = object_from(&options.options);
            if !options.outbound.is_empty() {
                object.insert(
                    "outbound".into(),
                    Value::String(options.outbound.clone()),
                );
            }
            (Some("bypass"), object)
        }
        RouteRuleActionOptions::Reject(options) => {
            let mut object = object_from(options);
            if object.get("method").and_then(Value::as_str) == Some("default") {
                object.remove("method");
            }
            (Some("reject"), object)
        }
        RouteRuleActionOptions::HijackDns => (Some("hijack-dns"), Map::new()),
        RouteRuleActionOptions::Sniff(options) => {
            (Some("sniff"), object_from(options))
        }
        RouteRuleActionOptions::Resolve(options) => {
            (Some("resolve"), object_from(options))
        }
    };
    if let Some(kind) = kind {
        object.insert("action".into(), Value::String(kind.into()));
    }
    object
}

fn parse_route_action(
    mut object: Map<String, Value>,
) -> Result<RouteRuleActionOptions, String> {
    let action = object
        .remove("action")
        .map(serde_json::from_value::<String>)
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or_else(|| "route".into());
    match action.as_str() {
        "" | "route" => {
            ensure_only(&object, ROUTE_OVERRIDE_WITH_OUTBOUND, "route action")?;
            let outbound = take_string(&mut object, "outbound")?;
            let options = decode_object(object)?;
            Ok(RouteRuleActionOptions::Route(RouteActionOptions {
                outbound,
                options,
            }))
        }
        "route-options" => {
            ensure_only(&object, ROUTE_OVERRIDE_KEYS, "route-options action")?;
            let options: RouteOverrideOptions = decode_object(object)?;
            if options.is_empty() {
                return Err("empty route option action".into());
            }
            if options.tls_fragment && options.tls_record_fragment {
                return Err(
                    "`tls_fragment` and `tls_record_fragment` are mutually exclusive"
                        .into(),
                );
            }
            Ok(RouteRuleActionOptions::RouteOptions(options))
        }
        "direct" => {
            ensure_only(&object, DIRECT_ACTION_KEYS, "direct action")?;
            decode_object(object)
                .map(Box::new)
                .map(RouteRuleActionOptions::Direct)
        }
        "bypass" => {
            ensure_only(
                &object,
                ROUTE_OVERRIDE_WITH_OUTBOUND,
                "bypass action",
            )?;
            let outbound = take_string(&mut object, "outbound")?;
            let options = decode_object(object)?;
            Ok(RouteRuleActionOptions::Bypass(RouteActionOptions {
                outbound,
                options,
            }))
        }
        "reject" => {
            ensure_only(&object, &["method", "no_drop"], "reject action")?;
            let mut options: RejectRouteActionOptions = decode_object(object)?;
            match options.method.as_str() {
                "" | "default" => options.method = "default".into(),
                "drop" | "reply" => {}
                method => {
                    return Err(format!("unknown reject method: {method}"));
                }
            }
            if options.method == "drop" && options.no_drop {
                return Err(
                    "no_drop is not available with drop reject method".into()
                );
            }
            Ok(RouteRuleActionOptions::Reject(options))
        }
        "hijack-dns" => {
            ensure_only(&object, &[], "hijack-dns action")?;
            Ok(RouteRuleActionOptions::HijackDns)
        }
        "sniff" => {
            ensure_only(&object, &["sniffer", "timeout"], "sniff action")?;
            decode_object(object).map(RouteRuleActionOptions::Sniff)
        }
        "resolve" => {
            ensure_only(
                &object,
                &[
                    "server",
                    "timeout",
                    "strategy",
                    "disable_cache",
                    "disable_optimistic_cache",
                    "rewrite_ttl",
                    "client_subnet",
                ],
                "resolve action",
            )?;
            decode_object(object).map(RouteRuleActionOptions::Resolve)
        }
        _ => Err(format!("unknown route rule action: {action}")),
    }
}

const ROUTE_OVERRIDE_KEYS: &[&str] = &[
    "override_address",
    "override_port",
    "network_strategy",
    "fallback_delay",
    "udp_disable_domain_unmapping",
    "udp_connect",
    "udp_timeout",
    "tls_fragment",
    "tls_fragment_fallback_delay",
    "tls_record_fragment",
    "tls_spoof",
    "tls_spoof_method",
];

const ROUTE_OVERRIDE_WITH_OUTBOUND: &[&str] = &[
    "outbound",
    "override_address",
    "override_port",
    "network_strategy",
    "fallback_delay",
    "udp_disable_domain_unmapping",
    "udp_connect",
    "udp_timeout",
    "tls_fragment",
    "tls_fragment_fallback_delay",
    "tls_record_fragment",
    "tls_spoof",
    "tls_spoof_method",
];

pub const ROUTE_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE: &str =
    "rule action is not supported in nested rules";

const ROUTE_RULE_ACTION_KEYS: &[&str] = &[
    "action",
    "outbound",
    "override_address",
    "override_port",
    "network_strategy",
    "fallback_delay",
    "udp_disable_domain_unmapping",
    "udp_connect",
    "udp_timeout",
    "tls_fragment",
    "tls_fragment_fallback_delay",
    "tls_record_fragment",
    "tls_spoof",
    "tls_spoof_method",
];

const DIRECT_ACTION_KEYS: &[&str] = &[
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "bind_address_no_port",
    "protect_path",
    "routing_mark",
    "reuse_addr",
    "netns",
    "connect_timeout",
    "tcp_fast_open",
    "tcp_multi_path",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "udp_fragment",
    "domain_resolver",
    "network_strategy",
    "network_type",
    "fallback_network_type",
    "fallback_delay",
    "domain_strategy",
];

fn ensure_only(
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

fn take_string(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<String, String> {
    object
        .remove(key)
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| error.to_string())
        .map(Option::unwrap_or_default)
}

fn optional_string_field<'a>(
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

fn decode_object<T: serde::de::DeserializeOwned>(
    object: Map<String, Value>,
) -> Result<T, String> {
    serde_json::from_value(Value::Object(object))
        .map_err(|error| error.to_string())
}

fn i32_is_zero(value: &i32) -> bool {
    *value == 0
}

fn u16_is_zero(value: &u16) -> bool {
    *value == 0
}

fn u32_is_zero(value: &u32) -> bool {
    *value == 0
}

fn domain_strategy_is_default(value: &DomainStrategy) -> bool {
    *value == DomainStrategy::default()
}

fn is_default_json(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(value) => !value,
        Value::Number(value) => value.as_i64() == Some(0),
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
    }
}

impl Default for RuleSetOptions {
    fn default() -> Self {
        Self::Inline(InlineRuleSetOptions::default())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineRuleSetOptions {
    pub tag: Listable<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<HeadlessRuleOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRuleSetOptions {
    pub tag: Listable<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub format: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteRuleSetOptions {
    pub tag: Listable<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub format: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub initial_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_client: Option<HttpClientReference>,
    #[serde(default, skip_serializing_if = "duration_is_zero")]
    pub update_interval: Duration,
    /// Deprecated upstream compatibility field; prefer `http_client`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub download_detour: String,
}

impl RuleSetOptions {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Inline(_) => "inline",
            Self::Local(_) => "local",
            Self::Remote(_) => "remote",
        }
    }

    pub fn tags(&self) -> &Listable<String> {
        match self {
            Self::Inline(options) => &options.tag,
            Self::Local(options) => &options.tag,
            Self::Remote(options) => &options.tag,
        }
    }

    pub fn remote(&self) -> Option<&RemoteRuleSetOptions> {
        match self {
            Self::Remote(options) => Some(options),
            _ => None,
        }
    }

    pub(crate) fn remote_mut(&mut self) -> Option<&mut RemoteRuleSetOptions> {
        match self {
            Self::Remote(options) => Some(options),
            _ => None,
        }
    }

    pub(crate) fn to_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

impl Serialize for RuleSetOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = match self {
            Self::Inline(options) => object_from(options),
            Self::Local(options) => {
                let mut object = object_from(options);
                object.insert("type".into(), Value::String("local".into()));
                object
            }
            Self::Remote(options) => {
                let mut object = object_from(options);
                object.insert("type".into(), Value::String("remote".into()));
                object
            }
        };
        if matches!(self, Self::Inline(_)) {
            object.remove("type");
        }
        Value::Object(object).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RuleSetOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = Value::deserialize(deserializer)?;
        let object = value.as_object_mut().ok_or_else(|| {
            de::Error::custom("rule-set options are not an object")
        })?;
        let kind = object
            .remove("type")
            .map(serde_json::from_value::<String>)
            .transpose()
            .map_err(de::Error::custom)?
            .unwrap_or_default();
        match kind.as_str() {
            "" | "inline" => serde_json::from_value(value)
                .map(Self::Inline)
                .map_err(de::Error::custom),
            "local" => serde_json::from_value(value)
                .map(Self::Local)
                .map_err(de::Error::custom),
            "remote" => serde_json::from_value(value)
                .map(Self::Remote)
                .map_err(de::Error::custom),
            _ => {
                Err(de::Error::custom(format!("unknown rule-set type: {kind}")))
            }
        }
    }
}

fn object_from<T: Serialize>(value: &T) -> Map<String, Value> {
    serde_json::to_value(value)
        .expect("serializing a typed route option cannot fail")
        .as_object()
        .expect("typed route options serialize as objects")
        .clone()
}

fn fwmark_is_zero(value: &FwMark) -> bool {
    value.0 == 0
}

fn duration_is_zero(value: &Duration) -> bool {
    value.as_nanos() == 0
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoIpOptions {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub download_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub download_detour: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeositeOptions {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub download_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub download_detour: String,
}

#[cfg(test)]
mod tests {
    use super::{
        ROUTE_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE, RouteOptions,
        RouteRuleActionOptions, RouteRuleOptions, RuleSetOptions,
    };

    #[test]
    fn route_rules_preserve_go_matcher_then_action_decoding() {
        let route: RouteOptions = serde_json::from_str(
            r#"{
                "rules": [
                    {
                        "domain_suffix":"example.com",
                        "network_type":"wifi",
                        "action":"direct",
                        "fallback_network_type":"ethernet",
                        "udp_fragment":false
                    },
                    {
                        "type":"logical",
                        "mode":"or",
                        "rules":[{"domain":"one.example"},{"port":443}],
                        "action":"direct",
                        "network_type":"cellular"
                    }
                ]
            }"#,
        )
        .unwrap();
        let RouteRuleOptions::Default(first) = &route.rules[0] else {
            panic!("expected default rule")
        };
        assert_eq!(first.matcher.network_type.as_slice().len(), 1);
        let RouteRuleActionOptions::Direct(first_action) = &first.action else {
            panic!("expected direct action")
        };
        assert!(first_action.network_type.is_empty());
        assert_eq!(first_action.fallback_network_type.as_slice().len(), 1);
        assert_eq!(first_action.udp_fragment, Some(false));

        let RouteRuleOptions::Logical(second) = &route.rules[1] else {
            panic!("expected logical rule")
        };
        let RouteRuleActionOptions::Direct(second_action) = &second.action
        else {
            panic!("expected direct action")
        };
        assert_eq!(second_action.network_type.as_slice().len(), 1);

        let encoded = serde_json::to_value(&route).unwrap();
        assert_eq!(encoded["rules"][0]["network_type"], "wifi");
        assert_eq!(encoded["rules"][0]["udp_fragment"], false);
        assert_eq!(encoded["rules"][1]["type"], "logical");
        assert_eq!(encoded["rules"][1]["network_type"], "cellular");
    }

    #[test]
    fn route_rules_preserve_deprecated_matcher_fields_for_migration() {
        let route: RouteOptions = serde_json::from_value(serde_json::json!({
            "rules": [{
                "geosite": "cn",
                "source_geoip": "private",
                "geoip": "cn",
                "rule_set": "legacy",
                "rule_set_ipcidr_match_source": true,
                "outbound": "direct"
            }]
        }))
        .unwrap();
        let RouteRuleOptions::Default(rule) = &route.rules[0] else {
            panic!("expected default rule")
        };
        assert_eq!(rule.matcher.geosite.as_slice(), ["cn"]);
        assert_eq!(rule.matcher.source_geoip.as_slice(), ["private"]);
        assert_eq!(rule.matcher.geoip.as_slice(), ["cn"]);
        assert!(rule.matcher.rule_set_ipcidr_match_source);
        assert_eq!(
            serde_json::to_value(route).unwrap()["rules"][0],
            serde_json::json!({
                "geosite": "cn",
                "source_geoip": "private",
                "geoip": "cn",
                "rule_set": "legacy",
                "rule_set_ipcidr_match_source": true,
                "outbound": "direct"
            })
        );
    }

    #[test]
    fn route_rules_reject_nested_actions_and_action_shape_mixing() {
        for invalid in [
            r#"{"rules":[{"type":7,"domain":"example.com"}]}"#,
            r#"{"rules":[{"type":"logical","mode":"or","rules":[{"domain":"example.com","outbound":"proxy"}],"outbound":"direct"}]}"#,
            r#"{"rules":[{"domain":"example.com","action":"reject","outbound":"proxy"}]}"#,
            r#"{"rules":[{"domain":"example.com","action":"route-options"}]}"#,
            r#"{"rules":[{"domain":"example.com","action":"route-options","tls_fragment":true,"tls_record_fragment":true}]}"#,
        ] {
            assert!(serde_json::from_str::<RouteOptions>(invalid).is_err());
        }
        serde_json::from_str::<RouteOptions>(
            r#"{"rules":[{"domain":"example.com","tls_fragment":true,"tls_record_fragment":true,"outbound":"proxy"}]}"#,
        )
        .unwrap();

        let error = serde_json::from_str::<RouteOptions>(
            r#"{"rules":[{"type":"logical","mode":"and","rules":[{"domain":"example.com","outbound":"direct"}]}]}"#,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(ROUTE_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE),
            "{error}"
        );

        let error = serde_json::from_str::<RouteOptions>(
            r#"{"rules":[{"type":"logical","mode":"and","rules":[{"domain":"example.com","foo":"bar"}]}]}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
        assert!(
            !error
                .to_string()
                .contains(ROUTE_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE),
            "{error}"
        );
    }

    #[test]
    fn rule_set_sources_are_typed_strict_and_canonical() {
        let route: RouteOptions = serde_json::from_str(
            r#"{
                "rule_set": [
                    {"type":"inline","tag":"private","rules":[
                        {"ip_cidr":"192.168.0.0/16"},
                        {"type":"logical","mode":"and","rules":[{"domain_suffix":"example.com"},{"network":"tcp"}],"invert":true}
                    ]},
                    {"type":"local","tag":["geoip","geosite"],"format":"binary","path":"rules-{tag}.srs"},
                    {"type":"remote","tag":"ads","url":"https://example.com/ads.srs","http_client":{"netns":"isolated"},"update_interval":"12h"}
                ]
            }"#,
        )
        .unwrap();
        assert!(matches!(route.rule_set[0], RuleSetOptions::Inline(_)));
        assert!(matches!(route.rule_set[1], RuleSetOptions::Local(_)));
        let remote = route.rule_set[2].remote().unwrap();
        assert_eq!(remote.url, "https://example.com/ads.srs");
        assert_eq!(remote.update_interval.to_string(), "12h");

        let encoded = serde_json::to_value(&route).unwrap();
        assert!(encoded["rule_set"][0].get("type").is_none());
        assert_eq!(encoded["rule_set"][0]["rules"][1]["type"], "logical");
        assert_eq!(encoded["rule_set"][1]["type"], "local");
        assert_eq!(encoded["rule_set"][2]["type"], "remote");

        for invalid in [
            r#"{"rule_set":[{"type":"inline","tag":"x","path":"x.srs"}]}"#,
            r#"{"rule_set":[{"type":"local","tag":"x","url":"https://example.com/x.srs"}]}"#,
            r#"{"rule_set":[{"type":"unknown","tag":"x"}]}"#,
            r#"{"rule_set":[{"tag":"x","rules":[{"type":"logical","mode":"or","rules":[{"domain":"example.com","outbound":"proxy"}]}]}]}"#,
        ] {
            assert!(serde_json::from_str::<RouteOptions>(invalid).is_err());
        }
    }
}
