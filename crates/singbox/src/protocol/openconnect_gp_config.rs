//! Palo Alto GlobalProtect tunnel-configuration wire compatibility.
//!
//! This module contains the configuration half of the GlobalProtect protocol:
//! the byte-stable `getconfig.esp` request, HTTP failure classification, and
//! XML response parsing.  Transport, authentication and GPST/ESP channels are
//! deliberately separate so the library can test and embed each layer.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, SystemTime},
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use quick_xml::{
    Reader, XmlVersion,
    events::{BytesStart, Event},
};
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{TunnelConfiguration, TunnelRoute};

pub const GLOBALPROTECT_CONFIGURATION_PATH: &str = "/ssl-vpn/getconfig.esp";
pub const GLOBALPROTECT_DEFAULT_TUNNEL_PATH: &str =
    "/ssl-tunnel-connect.sslvpn";
pub const GLOBALPROTECT_DEFAULT_DPD_INTERVAL: Duration =
    Duration::from_secs(10);
pub const GLOBALPROTECT_MAXIMUM_CONFIGURATION_BODY: usize = 16 * 1024 * 1024;
pub const GLOBALPROTECT_DEFAULT_BASE_MTU: u32 = 1406;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectConfigurationRequestOptions {
    pub client_version: String,
    pub ipv6_disabled: bool,
    pub reported_os: String,
    pub opaque_query: String,
    pub previous_ipv4: Option<Ipv4Addr>,
    pub previous_ipv6: Option<std::net::Ipv6Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalProtectFailureClass {
    Retryable,
    SessionRejected,
    AuthenticationFailed,
    ProtocolUnsupported,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalProtectTunnelOperation {
    Configuration,
    Gpst,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GlobalProtectConfigurationError {
    #[error("GlobalProtect XML is invalid: {0}")]
    InvalidXml(String),
    #[error("unexpected GlobalProtect tunnel configuration XML root: {0}")]
    UnexpectedRoot(String),
    #[error(
        "GlobalProtect gateway rejected the response ({class:?}): {message}"
    )]
    Gateway {
        class: GlobalProtectFailureClass,
        message: String,
    },
    #[error("invalid GlobalProtect {field}: {value}")]
    InvalidValue { field: &'static str, value: String },
    #[error("GlobalProtect tunnel configuration has no assigned IP address")]
    MissingAssignedAddress,
    #[error("invalid GlobalProtect tunnel MTU: {0}")]
    InvalidMtu(u64),
    #[error("GlobalProtect configuration response exceeds {0} bytes")]
    BodyTooLarge(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalProtectEspEncryption {
    Aes128Cbc,
    Aes256Cbc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalProtectEspAuthentication {
    HmacMd5_96,
    HmacSha1_96,
    HmacSha256_128,
}

impl GlobalProtectEspAuthentication {
    pub const fn icv_length(self) -> usize {
        match self {
            Self::HmacMd5_96 | Self::HmacSha1_96 => 12,
            Self::HmacSha256_128 => 16,
        }
    }

    pub const fn key_length(self) -> usize {
        match self {
            Self::HmacMd5_96 => 16,
            Self::HmacSha1_96 => 20,
            Self::HmacSha256_128 => 32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct GlobalProtectEspKeyMaterial {
    pub spi: u32,
    pub encryption_key: Vec<u8>,
    pub authentication_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct GlobalProtectEspConfiguration {
    #[zeroize(skip)]
    pub remote: std::net::SocketAddr,
    #[zeroize(skip)]
    pub magic: IpAddr,
    #[zeroize(skip)]
    pub encryption: GlobalProtectEspEncryption,
    #[zeroize(skip)]
    pub authentication: GlobalProtectEspAuthentication,
    pub outbound: GlobalProtectEspKeyMaterial,
    pub inbound: GlobalProtectEspKeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectTunnelConfiguration {
    pub configuration: TunnelConfiguration,
    pub tunnel_path: String,
    pub dpd: Duration,
    pub keepalive: Duration,
    pub rekey: Duration,
    pub assigned_ipv4: Option<Ipv4Addr>,
    pub assigned_ipv6: Option<std::net::Ipv6Addr>,
    pub esp: Option<GlobalProtectEspConfiguration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectConfigurationParseOptions {
    pub authenticated_address: Option<IpAddr>,
    pub ipv6_disabled: bool,
    pub no_udp: bool,
    pub requested_mtu: u32,
    pub base_mtu: u32,
    pub dpd_override: Option<Duration>,
    pub now: SystemTime,
}

impl GlobalProtectConfigurationParseOptions {
    pub fn new(authenticated_address: IpAddr) -> Self {
        Self {
            authenticated_address: Some(authenticated_address),
            ipv6_disabled: false,
            no_udp: false,
            requested_mtu: 0,
            base_mtu: 0,
            dpd_override: None,
            now: SystemTime::now(),
        }
    }

    pub fn new_unpinned() -> Self {
        Self {
            authenticated_address: None,
            ipv6_disabled: false,
            no_udp: false,
            requested_mtu: 0,
            base_mtu: 0,
            dpd_override: None,
            now: SystemTime::now(),
        }
    }
}

/// Build the exact ordered form body expected by `getconfig.esp`.
pub fn build_globalprotect_configuration_request(
    options: &GlobalProtectConfigurationRequestOptions,
) -> String {
    let mut body =
        String::from("client-type=1&protocol-version=p1&internal=no");
    append_encoded_option(&mut body, "app-version", &options.client_version);
    append_encoded_option(
        &mut body,
        "ipv6-support",
        if options.ipv6_disabled { "no" } else { "yes" },
    );
    append_encoded_option(
        &mut body,
        "clientos",
        globalprotect_client_os(&options.reported_os),
    );
    append_encoded_option(&mut body, "os-version", &options.reported_os);
    append_encoded_option(&mut body, "hmac-algo", "sha1,md5,sha256");
    append_encoded_option(&mut body, "enc-algo", "aes-128-cbc,aes-256-cbc");

    if options.previous_ipv4.is_some()
        || (!options.ipv6_disabled && options.previous_ipv6.is_some())
    {
        if let Some(address) = options.previous_ipv4 {
            append_encoded_option(
                &mut body,
                "preferred-ip",
                &address.to_string(),
            );
        }
        if !options.ipv6_disabled
            && let Some(address) = options.previous_ipv6
        {
            append_encoded_option(
                &mut body,
                "preferred-ipv6",
                &address.to_string(),
            );
        }
        append_opaque_query(
            &mut body,
            &filter_globalprotect_opaque_query(
                &options.opaque_query,
                &["preferred-ip", "preferred-ipv6"],
                false,
            ),
        );
    } else {
        let opaque = if options.ipv6_disabled {
            filter_globalprotect_opaque_query(
                &options.opaque_query,
                &["preferred-ipv6"],
                false,
            )
        } else {
            options.opaque_query.clone()
        };
        append_opaque_query(&mut body, &opaque);
    }
    body
}

pub fn encode_globalprotect_form_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
        {
            output.push(char::from(*byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    output
}

pub fn globalprotect_client_os(reported_os: &str) -> &'static str {
    match reported_os {
        "mac-intel" => "Mac",
        "apple-ios" => "iOS",
        "linux" | "linux-64" => "Linux",
        "android" => "Android",
        _ => "Windows",
    }
}

pub fn filter_globalprotect_opaque_query(
    query: &str,
    selected: &[&str],
    include_selected: bool,
) -> String {
    let selected = selected.iter().copied().collect::<BTreeSet<_>>();
    query
        .split('&')
        .filter(|part| {
            let name = part.split_once('=').map_or(*part, |(name, _)| name);
            selected.contains(name) == include_selected
        })
        .collect::<Vec<_>>()
        .join("&")
}

pub fn classify_globalprotect_tunnel_http_status(
    status: u16,
    operation: GlobalProtectTunnelOperation,
) -> Option<GlobalProtectFailureClass> {
    if status == 200 {
        return None;
    }
    if matches!(status, 401 | 403 | 512)
        || operation == GlobalProtectTunnelOperation::Gpst && status == 502
    {
        return Some(GlobalProtectFailureClass::SessionRejected);
    }
    if operation == GlobalProtectTunnelOperation::Gpst && status == 405 {
        return Some(GlobalProtectFailureClass::ProtocolUnsupported);
    }
    if status == 513 {
        return Some(GlobalProtectFailureClass::AuthenticationFailed);
    }
    if matches!(status, 408 | 425 | 429) || status >= 500 {
        return Some(GlobalProtectFailureClass::Retryable);
    }
    Some(GlobalProtectFailureClass::Terminal)
}

pub fn classify_globalprotect_response_error(
    message: &str,
) -> GlobalProtectFailureClass {
    match message {
        "GlobalProtect gateway does not exist"
        | "GlobalProtect portal does not exist" => {
            GlobalProtectFailureClass::Retryable
        }
        "Invalid authentication cookie" | "Portal name not found" => {
            GlobalProtectFailureClass::SessionRejected
        }
        "Valid client certificate is required" => {
            GlobalProtectFailureClass::AuthenticationFailed
        }
        _ => GlobalProtectFailureClass::ProtocolUnsupported,
    }
}

pub fn parse_globalprotect_tunnel_configuration(
    content: &[u8],
    options: &GlobalProtectConfigurationParseOptions,
) -> Result<GlobalProtectTunnelConfiguration, GlobalProtectConfigurationError> {
    if content.len() > GLOBALPROTECT_MAXIMUM_CONFIGURATION_BODY {
        return Err(GlobalProtectConfigurationError::BodyTooLarge(
            GLOBALPROTECT_MAXIMUM_CONFIGURATION_BODY,
        ));
    }
    let root = parse_xml(content)?;
    if root.name != "response" {
        return Err(GlobalProtectConfigurationError::UnexpectedRoot(root.name));
    }
    let response_error = root
        .children
        .iter()
        .find(|child| child.name == "error")
        .map(|child| child.text.trim())
        .unwrap_or_default();
    if !response_error.is_empty()
        || root
            .attribute("status")
            .is_some_and(|status| status.trim().eq_ignore_ascii_case("error"))
    {
        return Err(GlobalProtectConfigurationError::Gateway {
            class: classify_globalprotect_response_error(response_error),
            message: if response_error.is_empty() {
                "server returned an unspecified error".into()
            } else {
                response_error.to_owned()
            },
        });
    }

    let timer = options
        .dpd_override
        .filter(|value| !value.is_zero())
        .unwrap_or(GLOBALPROTECT_DEFAULT_DPD_INTERVAL);
    let mut result = GlobalProtectTunnelConfiguration {
        configuration: empty_configuration(options.authenticated_address),
        tunnel_path: GLOBALPROTECT_DEFAULT_TUNNEL_PATH.into(),
        dpd: timer,
        keepalive: timer,
        rekey: Duration::ZERO,
        assigned_ipv4: None,
        assigned_ipv6: None,
        esp: None,
    };
    let mut ipv4_text = "";
    let mut ipv6_text = "";
    let mut netmask_text = "";
    let mut configured_mtu = 0_u64;
    let mut lifetime = Duration::ZERO;
    let mut magic_ipv4 = None;
    let mut magic_ipv6 = None;
    let mut raw_esp = None;

    for child in &root.children {
        let value = child.text.trim();
        match child.name.as_str() {
            "ip-address" => ipv4_text = value,
            "ip-address-v6" => ipv6_text = value,
            "netmask" => netmask_text = value,
            "mtu" => configured_mtu = parse_unsigned(value, "MTU", 32)?,
            "lifetime" => {
                lifetime = parse_seconds(value, "authentication lifetime")?
            }
            "disconnect-on-idle" => {
                result.configuration.idle_timeout =
                    parse_seconds(value, "idle timeout")?;
            }
            "timeout" => {
                result.rekey = parse_adjusted_interval(value, "rekey interval")?
            }
            "ssl-tunnel-url" => result.tunnel_path = parse_tunnel_path(value)?,
            "gw-address" if !options.no_udp => {
                magic_ipv4 = parse_address(value, false).ok();
            }
            "gw-address-v6" if !options.no_udp => {
                magic_ipv6 = parse_address(value, true).ok();
            }
            "dns" | "dns-v6" => append_addresses(
                &mut result.configuration.dns,
                child,
                3,
                "DNS server",
                true,
            )?,
            "wins" => append_addresses(
                &mut result.configuration.nbns,
                child,
                3,
                "WINS server",
                false,
            )?,
            "dns-suffix" => result.configuration.search_domains.extend(
                child
                    .children
                    .iter()
                    .filter(|member| member.name == "member")
                    .map(|member| member.text.trim())
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned),
            ),
            "access-routes" => {
                append_routes(&mut result.configuration.routes, child, false)?
            }
            "access-routes-v6" => {
                append_routes(&mut result.configuration.routes, child, true)?
            }
            "exclude-access-routes" => append_routes(
                &mut result.configuration.excluded_routes,
                child,
                false,
            )?,
            "exclude-access-routes-v6" => append_routes(
                &mut result.configuration.excluded_routes,
                child,
                true,
            )?,
            "ipsec" if !options.no_udp => raw_esp = parse_raw_esp(child).ok(),
            _ => {}
        }
    }

    let (assigned_ipv4, ipv4_prefix) =
        parse_assigned_address(ipv4_text, netmask_text, false)?;
    let (mut assigned_ipv6, mut ipv6_prefix) =
        parse_assigned_address(ipv6_text, "", true)?;
    if options.ipv6_disabled {
        assigned_ipv6 = None;
        ipv6_prefix = None;
        magic_ipv6 = None;
    }
    if assigned_ipv4.is_none() && assigned_ipv6.is_none() {
        return Err(GlobalProtectConfigurationError::MissingAssignedAddress);
    }
    result.assigned_ipv4 = assigned_ipv4.and_then(|value| match value {
        IpAddr::V4(value) => Some(value),
        IpAddr::V6(_) => None,
    });
    result.assigned_ipv6 = assigned_ipv6.and_then(|value| match value {
        IpAddr::V6(value) => Some(value),
        IpAddr::V4(_) => None,
    });
    result.configuration.addresses.extend(ipv4_prefix);
    result.configuration.addresses.extend(ipv6_prefix);
    if !lifetime.is_zero() {
        result.configuration.authentication_expiration =
            options.now.checked_add(lifetime);
    }

    result.esp =
        options
            .authenticated_address
            .and_then(|authenticated_address| {
                raw_esp.and_then(|raw| {
                    build_esp_configuration(
                        raw,
                        authenticated_address,
                        assigned_ipv4,
                        assigned_ipv6,
                        magic_ipv4,
                        magic_ipv6,
                    )
                })
            });
    result.configuration.mtu = if configured_mtu == 0 {
        calculate_globalprotect_tunnel_mtu(
            options.requested_mtu,
            options.base_mtu,
            options
                .authenticated_address
                .is_some_and(|address| address.is_ipv6()),
            result.esp.as_ref().map(|esp| esp.authentication),
        )
    } else {
        let minimum = if assigned_ipv6.is_some() { 1280 } else { 576 };
        if configured_mtu < minimum || configured_mtu > u64::from(u16::MAX) {
            return Err(GlobalProtectConfigurationError::InvalidMtu(
                configured_mtu,
            ));
        }
        configured_mtu as u32
    };
    normalize_configuration(&mut result.configuration, options.ipv6_disabled);
    Ok(result)
}

pub fn calculate_globalprotect_tunnel_mtu(
    requested_mtu: u32,
    base_mtu: u32,
    outer_ipv6: bool,
    esp_authentication: Option<GlobalProtectEspAuthentication>,
) -> u32 {
    let base_mtu = if base_mtu == 0 {
        GLOBALPROTECT_DEFAULT_BASE_MTU
    } else {
        base_mtu.max(1280)
    };
    let mut mtu = if requested_mtu == 0 {
        base_mtu
            .saturating_sub(if outer_ipv6 { 40 } else { 20 })
            .saturating_sub(if esp_authentication.is_some() { 8 } else { 20 })
    } else {
        requested_mtu
    };
    let Some(authentication) = esp_authentication else {
        return mtu.saturating_sub(5);
    };
    mtu = mtu.saturating_sub(8 + authentication.icv_length() as u32 + 16);
    mtu -= mtu % 16;
    mtu.saturating_sub(2)
}

fn empty_configuration(remote_address: Option<IpAddr>) -> TunnelConfiguration {
    TunnelConfiguration {
        mtu: 0,
        remote_address,
        addresses: Vec::new(),
        routes: Vec::new(),
        excluded_routes: Vec::new(),
        dns: Vec::new(),
        nbns: Vec::new(),
        search_domains: Vec::new(),
        split_dns: Vec::new(),
        split_dns_rules: Vec::new(),
        proxy_auto_config_url: String::new(),
        banner: String::new(),
        tunnel_all_dns: false,
        client_bypass_protocol: false,
        idle_timeout: Duration::ZERO,
        authentication_expiration: None,
    }
}

fn normalize_configuration(
    configuration: &mut TunnelConfiguration,
    ipv6_disabled: bool,
) {
    if ipv6_disabled {
        configuration
            .addresses
            .retain(|prefix| prefix.addr().is_ipv4());
        configuration
            .routes
            .retain(|route| route.prefix.addr().is_ipv4());
        configuration
            .excluded_routes
            .retain(|route| route.prefix.addr().is_ipv4());
        configuration.dns.retain(IpAddr::is_ipv4);
        configuration.nbns.retain(IpAddr::is_ipv4);
    }
    let has_ipv4_address = configuration
        .addresses
        .iter()
        .any(|net| net.addr().is_ipv4());
    let has_ipv6_address = configuration
        .addresses
        .iter()
        .any(|net| net.addr().is_ipv6());
    let has_ipv4_route = configuration
        .routes
        .iter()
        .any(|route| route.prefix.addr().is_ipv4());
    let has_ipv6_route = configuration
        .routes
        .iter()
        .any(|route| route.prefix.addr().is_ipv6());
    if has_ipv4_address && !has_ipv4_route {
        configuration.routes.push(route(IpNet::V4(
            Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("valid prefix"),
        )));
    }
    if has_ipv6_address && !has_ipv6_route {
        configuration.routes.push(route(IpNet::V6(
            Ipv6Net::new(std::net::Ipv6Addr::UNSPECIFIED, 0)
                .expect("valid prefix"),
        )));
    }
}

fn route(prefix: IpNet) -> TunnelRoute {
    TunnelRoute {
        prefix,
        gateway: None,
        metric: 0,
    }
}

fn append_encoded_option(body: &mut String, name: &str, value: &str) {
    body.push('&');
    body.push_str(name);
    body.push('=');
    body.push_str(&encode_globalprotect_form_component(value));
}

fn append_opaque_query(body: &mut String, query: &str) {
    if !query.is_empty() {
        body.push('&');
        body.push_str(query);
    }
}

fn parse_unsigned(
    value: &str,
    field: &'static str,
    bits: u32,
) -> Result<u64, GlobalProtectConfigurationError> {
    let parsed = value
        .trim()
        .parse::<u64>()
        .map_err(|_| invalid(field, value))?;
    if bits < 64 && parsed >= (1_u64 << bits) {
        return Err(invalid(field, value));
    }
    Ok(parsed)
}

fn parse_seconds(
    value: &str,
    field: &'static str,
) -> Result<Duration, GlobalProtectConfigurationError> {
    let seconds = parse_unsigned(value, field, 64)?;
    if seconds > i64::MAX as u64 / 1_000_000_000 {
        return Err(invalid(field, value));
    }
    Ok(Duration::from_secs(seconds))
}

fn parse_adjusted_interval(
    value: &str,
    field: &'static str,
) -> Result<Duration, GlobalProtectConfigurationError> {
    let interval = parse_seconds(value, field)?;
    if interval.is_zero() {
        return Ok(interval);
    }
    if interval > Duration::from_secs(60) {
        return Ok(interval - Duration::from_secs(60));
    }
    Ok((interval / 2).max(Duration::from_secs(1)))
}

fn parse_assigned_address(
    address: &str,
    netmask: &str,
    ipv6: bool,
) -> Result<(Option<IpAddr>, Option<IpNet>), GlobalProtectConfigurationError> {
    let address = address.trim();
    if address.is_empty() {
        return Ok((None, None));
    }
    let (address, mut bits) = if let Ok(prefix) = address.parse::<IpNet>() {
        (prefix.addr(), prefix.prefix_len())
    } else {
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| invalid("assigned address", address))?;
        (address, if ipv6 { 128 } else { 32 })
    };
    if address.is_ipv6() != ipv6 {
        return Err(invalid("assigned address family", &address.to_string()));
    }
    if !ipv6 && !netmask.trim().is_empty() {
        bits = parse_ipv4_netmask(netmask)?;
    }
    let prefix = match address {
        IpAddr::V4(address) => {
            IpNet::V4(Ipv4Net::new(address, bits).map_err(|_| {
                invalid("assigned IPv4 prefix", address.to_string().as_str())
            })?)
        }
        IpAddr::V6(address) => {
            IpNet::V6(Ipv6Net::new(address, bits).map_err(|_| {
                invalid("assigned IPv6 prefix", address.to_string().as_str())
            })?)
        }
    };
    Ok((Some(address), Some(prefix)))
}

fn parse_ipv4_netmask(
    value: &str,
) -> Result<u8, GlobalProtectConfigurationError> {
    let value = value.trim().trim_start_matches('/');
    if !value.contains('.') {
        return value
            .parse::<u8>()
            .ok()
            .filter(|bits| *bits <= 32)
            .ok_or_else(|| invalid("IPv4 netmask", value));
    }
    let mask = value
        .parse::<Ipv4Addr>()
        .map_err(|_| invalid("IPv4 netmask", value))?;
    let mask = u32::from(mask);
    let bits = mask.leading_ones();
    if mask != u32::MAX.checked_shl(32 - bits).unwrap_or(0) {
        return Err(invalid("non-contiguous IPv4 netmask", value));
    }
    Ok(bits as u8)
}

fn append_addresses(
    destination: &mut Vec<IpAddr>,
    node: &XmlNode,
    maximum: usize,
    field: &'static str,
    deduplicate: bool,
) -> Result<(), GlobalProtectConfigurationError> {
    for member in node.children.iter().filter(|node| node.name == "member") {
        if destination.len() >= maximum {
            break;
        }
        let address = member
            .text
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| invalid(field, member.text.trim()))?;
        if !deduplicate || !destination.contains(&address) {
            destination.push(address);
        }
    }
    Ok(())
}

fn append_routes(
    destination: &mut Vec<TunnelRoute>,
    node: &XmlNode,
    ipv6: bool,
) -> Result<(), GlobalProtectConfigurationError> {
    for member in node.children.iter().filter(|node| node.name == "member") {
        let value = member.text.trim();
        let prefix = if value.contains('/') {
            value
                .parse::<IpNet>()
                .map_err(|_| invalid("tunnel route", value))?
        } else {
            match value
                .parse::<IpAddr>()
                .map_err(|_| invalid("tunnel route", value))?
            {
                IpAddr::V4(address) => {
                    IpNet::V4(Ipv4Net::new(address, 32).expect("valid prefix"))
                }
                IpAddr::V6(address) => {
                    IpNet::V6(Ipv6Net::new(address, 128).expect("valid prefix"))
                }
            }
        };
        if prefix.addr().is_ipv6() != ipv6 {
            return Err(invalid("tunnel route address family", value));
        }
        destination.push(route(prefix.trunc()));
    }
    Ok(())
}

#[derive(Debug, Default, Zeroize, ZeroizeOnDrop)]
struct RawEspConfiguration {
    port: u16,
    #[zeroize(skip)]
    encryption: Option<GlobalProtectEspEncryption>,
    #[zeroize(skip)]
    authentication: Option<GlobalProtectEspAuthentication>,
    outbound_spi: u32,
    inbound_spi: u32,
    outbound_encryption_key: Vec<u8>,
    inbound_encryption_key: Vec<u8>,
    outbound_authentication_key: Vec<u8>,
    inbound_authentication_key: Vec<u8>,
    mode: String,
}

fn parse_raw_esp(
    node: &XmlNode,
) -> Result<RawEspConfiguration, GlobalProtectConfigurationError> {
    let mut raw = RawEspConfiguration::default();
    for child in &node.children {
        let value = child.text.trim();
        match child.name.as_str() {
            "udp-port" => {
                raw.port =
                    u16::try_from(parse_unsigned(value, "ESP UDP port", 16)?)
                        .map_err(|_| invalid("ESP UDP port", value))?;
                if raw.port == 0 {
                    return Err(invalid("ESP UDP port", value));
                }
            }
            "enc-algo" => {
                raw.encryption = Some(match value {
                    "aes128" | "aes-128-cbc" => {
                        GlobalProtectEspEncryption::Aes128Cbc
                    }
                    "aes-256-cbc" => GlobalProtectEspEncryption::Aes256Cbc,
                    _ => {
                        return Err(invalid("ESP encryption algorithm", value));
                    }
                })
            }
            "hmac-algo" => {
                raw.authentication = Some(match value {
                    "md5" => GlobalProtectEspAuthentication::HmacMd5_96,
                    "sha1" => GlobalProtectEspAuthentication::HmacSha1_96,
                    "sha256" => GlobalProtectEspAuthentication::HmacSha256_128,
                    _ => {
                        return Err(invalid(
                            "ESP authentication algorithm",
                            value,
                        ));
                    }
                })
            }
            "c2s-spi" => raw.outbound_spi = parse_spi(value)?,
            "s2c-spi" => raw.inbound_spi = parse_spi(value)?,
            "ekey-c2s" => {
                raw.outbound_encryption_key =
                    parse_esp_key(child, "outbound encryption key")?
            }
            "ekey-s2c" => {
                raw.inbound_encryption_key =
                    parse_esp_key(child, "inbound encryption key")?
            }
            "akey-c2s" => {
                raw.outbound_authentication_key =
                    parse_esp_key(child, "outbound authentication key")?
            }
            "akey-s2c" => {
                raw.inbound_authentication_key =
                    parse_esp_key(child, "inbound authentication key")?
            }
            "ipsec-mode" => raw.mode = value.to_owned(),
            _ => {}
        }
    }
    Ok(raw)
}

fn parse_esp_key(
    node: &XmlNode,
    field: &'static str,
) -> Result<Vec<u8>, GlobalProtectConfigurationError> {
    let bits = node.child_text("bits").unwrap_or_default();
    let bits = parse_unsigned(bits, field, 32)?;
    let encoded = node.child_text("val").unwrap_or_default().trim();
    let mut key = hex::decode(encoded).map_err(|_| invalid(field, encoded))?;
    if bits == 0 || bits % 8 != 0 || key.len() as u64 != bits / 8 {
        key.zeroize();
        return Err(invalid(field, encoded));
    }
    Ok(key)
}

fn parse_spi(value: &str) -> Result<u32, GlobalProtectConfigurationError> {
    let value = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let spi = u32::from_str_radix(value, 16)
        .map_err(|_| invalid("ESP SPI", value))?;
    if spi == 0 {
        return Err(invalid("ESP SPI", value));
    }
    Ok(spi)
}

fn build_esp_configuration(
    raw: RawEspConfiguration,
    authenticated_address: IpAddr,
    assigned_ipv4: Option<IpAddr>,
    assigned_ipv6: Option<IpAddr>,
    magic_ipv4: Option<IpAddr>,
    magic_ipv6: Option<IpAddr>,
) -> Option<GlobalProtectEspConfiguration> {
    if !raw.mode.is_empty() && raw.mode != "esp-tunnel" {
        return None;
    }
    let encryption = raw.encryption?;
    let authentication = raw.authentication?;
    if raw.port == 0 || raw.outbound_spi == 0 || raw.inbound_spi == 0 {
        return None;
    }
    let magic = if assigned_ipv6.is_some() && magic_ipv6.is_some() {
        magic_ipv6?
    } else if assigned_ipv4.is_some() && magic_ipv4.is_some() {
        magic_ipv4?
    } else {
        return None;
    };
    let expected_encryption = match encryption {
        GlobalProtectEspEncryption::Aes128Cbc => 16,
        GlobalProtectEspEncryption::Aes256Cbc => 32,
    };
    if raw.outbound_encryption_key.len() != expected_encryption
        || raw.inbound_encryption_key.len() != expected_encryption
        || raw.outbound_authentication_key.len() != authentication.key_length()
        || raw.inbound_authentication_key.len() != authentication.key_length()
    {
        return None;
    }
    Some(GlobalProtectEspConfiguration {
        remote: std::net::SocketAddr::new(authenticated_address, raw.port),
        magic,
        encryption,
        authentication,
        outbound: GlobalProtectEspKeyMaterial {
            spi: raw.outbound_spi,
            encryption_key: raw.outbound_encryption_key.clone(),
            authentication_key: raw.outbound_authentication_key.clone(),
        },
        inbound: GlobalProtectEspKeyMaterial {
            spi: raw.inbound_spi,
            encryption_key: raw.inbound_encryption_key.clone(),
            authentication_key: raw.inbound_authentication_key.clone(),
        },
    })
}

fn parse_tunnel_path(
    value: &str,
) -> Result<String, GlobalProtectConfigurationError> {
    if !value.starts_with('/') || value.starts_with("//") {
        return Err(invalid("tunnel path", value));
    }
    let base =
        Url::parse("https://globalprotect.invalid/").expect("constant URL");
    let parsed = base
        .join(value)
        .map_err(|_| invalid("tunnel path", value))?;
    if parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str() != base.host_str()
    {
        return Err(invalid("tunnel path", value));
    }
    Ok(parsed.path().to_owned())
}

fn parse_address(
    value: &str,
    ipv6: bool,
) -> Result<IpAddr, GlobalProtectConfigurationError> {
    let address = value
        .parse::<IpAddr>()
        .map_err(|_| invalid("ESP magic address", value))?;
    if address.is_ipv6() != ipv6 {
        return Err(invalid("ESP magic address family", value));
    }
    Ok(address)
}

fn invalid(
    field: &'static str,
    value: &str,
) -> GlobalProtectConfigurationError {
    GlobalProtectConfigurationError::InvalidValue {
        field,
        value: value.into(),
    }
}

#[derive(Debug)]
pub(super) struct XmlNode {
    pub(super) name: String,
    pub(super) attributes: Vec<(String, String)>,
    pub(super) text: String,
    pub(super) children: Vec<XmlNode>,
}

impl XmlNode {
    pub(super) fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value.as_str()))
    }

    pub(super) fn child_text(&self, name: &str) -> Option<&str> {
        self.children.iter().find_map(|child| {
            (child.name == name).then_some(child.text.as_str())
        })
    }
}

pub(super) fn parse_xml(
    content: &[u8],
) -> Result<XmlNode, GlobalProtectConfigurationError> {
    let mut reader = Reader::from_reader(content);
    reader.config_mut().trim_text(false);
    let mut stack = Vec::new();
    let mut root = None;
    loop {
        match reader.read_event().map_err(|error| {
            GlobalProtectConfigurationError::InvalidXml(error.to_string())
        })? {
            Event::Start(start) => stack.push(xml_node(&reader, &start)?),
            Event::Empty(start) => attach_xml_node(
                &mut stack,
                &mut root,
                xml_node(&reader, &start)?,
            )?,
            Event::Text(text) => {
                let decoded = text.xml10_content().map_err(|error| {
                    GlobalProtectConfigurationError::InvalidXml(
                        error.to_string(),
                    )
                })?;
                let value =
                    quick_xml::escape::unescape(&decoded).map_err(|error| {
                        GlobalProtectConfigurationError::InvalidXml(
                            error.to_string(),
                        )
                    })?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&value);
                }
            }
            Event::CData(text) => {
                let value = text.decode().map_err(|error| {
                    GlobalProtectConfigurationError::InvalidXml(
                        error.to_string(),
                    )
                })?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&value);
                }
            }
            Event::End(_) => {
                let node = stack.pop().ok_or_else(|| {
                    GlobalProtectConfigurationError::InvalidXml(
                        "unexpected end tag".into(),
                    )
                })?;
                attach_xml_node(&mut stack, &mut root, node)?;
            }
            Event::Eof => break,
            Event::GeneralRef(reference) => {
                let value = if let Some(value) =
                    reference.resolve_char_ref().map_err(|error| {
                        GlobalProtectConfigurationError::InvalidXml(
                            error.to_string(),
                        )
                    })? {
                    value.to_string()
                } else {
                    match reference
                        .decode()
                        .map_err(|error| {
                            GlobalProtectConfigurationError::InvalidXml(
                                error.to_string(),
                            )
                        })?
                        .as_ref()
                    {
                        "amp" => "&".into(),
                        "lt" => "<".into(),
                        "gt" => ">".into(),
                        "apos" => "'".into(),
                        "quot" => "\"".into(),
                        name => {
                            return Err(
                                GlobalProtectConfigurationError::InvalidXml(
                                    format!("unknown entity reference: {name}"),
                                ),
                            );
                        }
                    }
                };
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&value);
                }
            }
            Event::Decl(_)
            | Event::PI(_)
            | Event::Comment(_)
            | Event::DocType(_) => {}
        }
    }
    if !stack.is_empty() {
        return Err(GlobalProtectConfigurationError::InvalidXml(
            "unclosed XML element".into(),
        ));
    }
    root.ok_or_else(|| {
        GlobalProtectConfigurationError::InvalidXml("empty document".into())
    })
}

fn xml_node(
    reader: &Reader<&[u8]>,
    start: &BytesStart<'_>,
) -> Result<XmlNode, GlobalProtectConfigurationError> {
    let name = xml_local_name(start.name().as_ref())?;
    let mut attributes = Vec::new();
    for attribute in start.attributes().with_checks(false) {
        let attribute = attribute.map_err(|error| {
            GlobalProtectConfigurationError::InvalidXml(error.to_string())
        })?;
        let key = xml_local_name(attribute.key.as_ref())?;
        let value = attribute
            .decoded_and_normalized_value(
                XmlVersion::Implicit1_0,
                reader.decoder(),
            )
            .map_err(|error| {
                GlobalProtectConfigurationError::InvalidXml(error.to_string())
            })?;
        attributes.push((key, value.into_owned()));
    }
    Ok(XmlNode {
        name,
        attributes,
        text: String::new(),
        children: Vec::new(),
    })
}

fn attach_xml_node(
    stack: &mut [XmlNode],
    root: &mut Option<XmlNode>,
    node: XmlNode,
) -> Result<(), GlobalProtectConfigurationError> {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else if root.replace(node).is_some() {
        return Err(GlobalProtectConfigurationError::InvalidXml(
            "multiple root elements".into(),
        ));
    }
    Ok(())
}

fn xml_local_name(
    raw: &[u8],
) -> Result<String, GlobalProtectConfigurationError> {
    let raw = raw.rsplit(|byte| *byte == b':').next().unwrap_or(raw);
    std::str::from_utf8(raw)
        .map(str::to_owned)
        .map_err(|error| {
            GlobalProtectConfigurationError::InvalidXml(error.to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_preserves_opaque_query_and_replaces_preferred_addresses() {
        let body = build_globalprotect_configuration_request(&GlobalProtectConfigurationRequestOptions {
            client_version: "6.3.0-33".into(),
            ipv6_disabled: false,
            reported_os: "linux-64".into(),
            opaque_query: "authcookie=a%2fb&preferred-ip=old&preferred-ipv6=old6&portal=p".into(),
            previous_ipv4: Some("192.0.2.7".parse().unwrap()),
            previous_ipv6: Some("2001:db8::7".parse().unwrap()),
        });
        assert!(body.starts_with(
            "client-type=1&protocol-version=p1&internal=no&app-version=6.3.0-33"
        ));
        assert!(body.contains("&preferred-ip=192.0.2.7"));
        assert!(body.contains("&preferred-ipv6=2001%3adb8%3a%3a7"));
        assert!(body.ends_with("&authcookie=a%2fb&portal=p"));
    }

    #[test]
    fn status_classification_matches_globalprotect_retry_contract() {
        assert_eq!(
            classify_globalprotect_tunnel_http_status(
                200,
                GlobalProtectTunnelOperation::Gpst
            ),
            None
        );
        assert_eq!(
            classify_globalprotect_tunnel_http_status(
                502,
                GlobalProtectTunnelOperation::Gpst
            ),
            Some(GlobalProtectFailureClass::SessionRejected)
        );
        assert_eq!(
            classify_globalprotect_tunnel_http_status(
                502,
                GlobalProtectTunnelOperation::Configuration
            ),
            Some(GlobalProtectFailureClass::Retryable)
        );
        assert_eq!(
            classify_globalprotect_tunnel_http_status(
                405,
                GlobalProtectTunnelOperation::Gpst
            ),
            Some(GlobalProtectFailureClass::ProtocolUnsupported)
        );
        assert_eq!(
            classify_globalprotect_tunnel_http_status(
                513,
                GlobalProtectTunnelOperation::Configuration
            ),
            Some(GlobalProtectFailureClass::AuthenticationFailed)
        );
    }

    #[test]
    fn parses_routes_dns_timers_and_defaults() {
        let xml = br#"<response status="success">
          <ip-address>10.20.30.40</ip-address><netmask>255.255.255.0</netmask>
          <ip-address-v6>2001:db8::4/64</ip-address-v6><mtu>1380</mtu>
          <lifetime>3600</lifetime><disconnect-on-idle>90</disconnect-on-idle><timeout>300</timeout>
          <ssl-tunnel-url>/custom/tunnel</ssl-tunnel-url>
          <dns><member>10.0.0.53</member><member>10.0.0.53</member><member>2001:db8::53</member></dns>
          <wins><member>10.0.0.54</member></wins>
          <dns-suffix><member>corp.example</member></dns-suffix>
          <access-routes><member>10.0.0.0/8</member></access-routes>
          <access-routes-v6><member>2001:db8:1::/48</member></access-routes-v6>
          <exclude-access-routes><member>10.9.0.0/16</member></exclude-access-routes>
        </response>"#;
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let mut options = GlobalProtectConfigurationParseOptions::new(
            "198.51.100.2".parse().unwrap(),
        );
        options.now = now;
        let parsed =
            parse_globalprotect_tunnel_configuration(xml, &options).unwrap();
        assert_eq!(parsed.assigned_ipv4, Some("10.20.30.40".parse().unwrap()));
        assert_eq!(parsed.assigned_ipv6, Some("2001:db8::4".parse().unwrap()));
        assert_eq!(parsed.configuration.mtu, 1380);
        assert_eq!(parsed.tunnel_path, "/custom/tunnel");
        assert_eq!(parsed.rekey, Duration::from_secs(240));
        assert_eq!(parsed.configuration.idle_timeout, Duration::from_secs(90));
        assert_eq!(
            parsed.configuration.authentication_expiration,
            Some(now + Duration::from_secs(3600))
        );
        assert_eq!(parsed.configuration.dns.len(), 2);
        assert_eq!(parsed.configuration.routes.len(), 2);
        assert_eq!(parsed.configuration.excluded_routes.len(), 1);
    }

    #[test]
    fn parses_complete_esp_parameters_and_uses_esp_mtu() {
        let xml = br#"<response><ip-address>10.0.0.2</ip-address><netmask>24</netmask>
          <gw-address>10.0.0.1</gw-address><ipsec><udp-port>4501</udp-port>
          <enc-algo>aes-128-cbc</enc-algo><hmac-algo>sha1</hmac-algo>
          <c2s-spi>0x01020304</c2s-spi><s2c-spi>05060708</s2c-spi>
          <ekey-c2s><bits>128</bits><val>000102030405060708090a0b0c0d0e0f</val></ekey-c2s>
          <ekey-s2c><bits>128</bits><val>101112131415161718191a1b1c1d1e1f</val></ekey-s2c>
          <akey-c2s><bits>160</bits><val>000102030405060708090a0b0c0d0e0f10111213</val></akey-c2s>
          <akey-s2c><bits>160</bits><val>202122232425262728292a2b2c2d2e2f30313233</val></akey-s2c>
          <ipsec-mode>esp-tunnel</ipsec-mode></ipsec></response>"#;
        let options = GlobalProtectConfigurationParseOptions::new(
            "198.51.100.2".parse().unwrap(),
        );
        let parsed =
            parse_globalprotect_tunnel_configuration(xml, &options).unwrap();
        let esp = parsed.esp.unwrap();
        assert_eq!(
            esp.remote,
            "198.51.100.2:4501".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(esp.magic, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(esp.outbound.spi, 0x0102_0304);
        assert_eq!(parsed.configuration.mtu, 1326);
    }

    #[test]
    fn rejects_invalid_netmask_path_and_missing_address() {
        for xml in [
            br#"<response><ip-address>10.0.0.2</ip-address><netmask>255.0.255.0</netmask></response>"#.as_slice(),
            br#"<response><ip-address>10.0.0.2</ip-address><ssl-tunnel-url>https://evil.invalid/x</ssl-tunnel-url></response>"#.as_slice(),
            br#"<response/>"#.as_slice(),
        ] {
            assert!(parse_globalprotect_tunnel_configuration(xml, &GlobalProtectConfigurationParseOptions::new("198.51.100.2".parse().unwrap())).is_err());
        }
    }
}
