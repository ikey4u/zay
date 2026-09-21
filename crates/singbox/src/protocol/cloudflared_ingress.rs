//! Remotely managed Cloudflare Tunnel ingress configuration.

use std::{net::IpAddr, sync::RwLock, time::Duration};

use regex::Regex;
use serde::Deserialize;
use url::Url;

use super::cloudflared::{
    CloudflaredConfigurationApplier, CloudflaredConfigurationUpdate,
};
use crate::common::network::SocksAddr;

pub const CLOUDFLARED_DEFAULT_HTTP_CONNECT_TIMEOUT: Duration =
    Duration::from_secs(30);
pub const CLOUDFLARED_DEFAULT_TLS_TIMEOUT: Duration = Duration::from_secs(10);
pub const CLOUDFLARED_DEFAULT_TCP_KEEP_ALIVE: Duration =
    Duration::from_secs(30);
pub const CLOUDFLARED_DEFAULT_KEEP_ALIVE_TIMEOUT: Duration =
    Duration::from_secs(90);
pub const CLOUDFLARED_DEFAULT_KEEP_ALIVE_CONNECTIONS: i32 = 100;
pub const CLOUDFLARED_DEFAULT_PROXY_ADDRESS: &str = "127.0.0.1";
pub const CLOUDFLARED_DEFAULT_WARP_CONNECT_TIMEOUT: Duration =
    Duration::from_secs(5);
pub const CLOUDFLARED_DEFAULT_WARP_TCP_KEEP_ALIVE: Duration =
    Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflaredResolvedServiceKind {
    Http,
    Stream,
    Status,
    Unix,
    UnixTls,
    Bastion,
    SocksProxy,
}

#[derive(Debug, Clone)]
pub struct CloudflaredResolvedService {
    pub kind: CloudflaredResolvedServiceKind,
    pub service: String,
    pub destination: Option<SocksAddr>,
    pub stream_has_port: bool,
    pub base_url: Option<Url>,
    pub unix_path: String,
    pub status_code: u16,
    pub socks_policy: Option<CloudflaredIpRulePolicy>,
    pub origin_request: CloudflaredOriginRequestConfig,
}

impl CloudflaredResolvedService {
    pub const fn router_controlled(&self) -> bool {
        matches!(
            self.kind,
            CloudflaredResolvedServiceKind::Http
                | CloudflaredResolvedServiceKind::Stream
        )
    }

    pub fn build_request_url(
        &self,
        request_url: &str,
    ) -> Result<String, String> {
        if !matches!(
            self.kind,
            CloudflaredResolvedServiceKind::Http
                | CloudflaredResolvedServiceKind::Unix
                | CloudflaredResolvedServiceKind::UnixTls
        ) {
            return Ok(request_url.into());
        }
        let request = Url::parse(request_url)
            .map_err(|error| format!("parse request URL: {error}"))?;
        let mut origin = self.base_url.clone().ok_or_else(|| {
            "HTTP ingress service is missing base URL".to_owned()
        })?;
        origin.set_path(request.path());
        origin.set_query(request.query());
        origin.set_fragment(request.fragment());
        Ok(origin.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CloudflaredAccessConfig {
    pub required: bool,
    pub team_name: String,
    pub aud_tag: Vec<String>,
    pub environment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredIpRule {
    pub prefix: String,
    pub ports: Vec<u16>,
    pub allow: bool,
}

#[derive(Debug, Clone)]
struct CompiledIpRule {
    prefix: ipnet::IpNet,
    ports: Vec<u16>,
    allow: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CloudflaredIpRulePolicy {
    rules: Vec<CompiledIpRule>,
}

impl CloudflaredIpRulePolicy {
    pub fn compile(rules: &[CloudflaredIpRule]) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            if rule.prefix.is_empty() {
                return Err("ip_rule prefix cannot be blank".into());
            }
            let prefix = rule
                .prefix
                .parse()
                .map_err(|error| format!("parse ip_rule prefix: {error}"))?;
            let mut ports = rule.ports.clone();
            ports.sort_unstable();
            compiled.push(CompiledIpRule {
                prefix,
                ports,
                allow: rule.allow,
            });
        }
        Ok(Self { rules: compiled })
    }

    pub fn allows(&self, address: IpAddr, port: u16) -> bool {
        self.rules
            .iter()
            .find_map(|rule| {
                if !rule.prefix.contains(&address) {
                    return None;
                }
                if rule.ports.is_empty()
                    || rule.ports.binary_search(&port).is_ok()
                {
                    Some(rule.allow)
                } else {
                    None
                }
            })
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredOriginRequestConfig {
    pub connect_timeout: Duration,
    pub tls_timeout: Duration,
    pub tcp_keep_alive: Duration,
    pub no_happy_eyeballs: bool,
    pub keep_alive_timeout: Duration,
    pub keep_alive_connections: i32,
    pub http_host_header: String,
    pub origin_server_name: String,
    pub match_sni_to_host: bool,
    pub ca_pool: String,
    pub no_tls_verify: bool,
    pub disable_chunked_encoding: bool,
    pub bastion_mode: bool,
    pub proxy_address: String,
    pub proxy_port: u16,
    pub proxy_type: String,
    pub ip_rules: Vec<CloudflaredIpRule>,
    pub http2_origin: bool,
    pub access: CloudflaredAccessConfig,
}

impl Default for CloudflaredOriginRequestConfig {
    fn default() -> Self {
        Self {
            connect_timeout: CLOUDFLARED_DEFAULT_HTTP_CONNECT_TIMEOUT,
            tls_timeout: CLOUDFLARED_DEFAULT_TLS_TIMEOUT,
            tcp_keep_alive: CLOUDFLARED_DEFAULT_TCP_KEEP_ALIVE,
            no_happy_eyeballs: false,
            keep_alive_timeout: CLOUDFLARED_DEFAULT_KEEP_ALIVE_TIMEOUT,
            keep_alive_connections: CLOUDFLARED_DEFAULT_KEEP_ALIVE_CONNECTIONS,
            http_host_header: String::new(),
            origin_server_name: String::new(),
            match_sni_to_host: false,
            ca_pool: String::new(),
            no_tls_verify: false,
            disable_chunked_encoding: false,
            bastion_mode: false,
            proxy_address: CLOUDFLARED_DEFAULT_PROXY_ADDRESS.into(),
            proxy_port: 0,
            proxy_type: String::new(),
            ip_rules: vec![],
            http2_origin: false,
            access: CloudflaredAccessConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredWarpRoutingConfig {
    pub connect_timeout: Duration,
    pub max_active_flows: u64,
    pub tcp_keep_alive: Duration,
}

impl Default for CloudflaredWarpRoutingConfig {
    fn default() -> Self {
        Self {
            connect_timeout: CLOUDFLARED_DEFAULT_WARP_CONNECT_TIMEOUT,
            max_active_flows: 0,
            tcp_keep_alive: CLOUDFLARED_DEFAULT_WARP_TCP_KEEP_ALIVE,
        }
    }
}

#[derive(Debug)]
pub struct CloudflaredIngressRule {
    pub hostname: String,
    pub punycode_hostname: String,
    pub path: Option<Regex>,
    pub service: CloudflaredResolvedService,
}

impl Clone for CloudflaredIngressRule {
    fn clone(&self) -> Self {
        Self {
            hostname: self.hostname.clone(),
            punycode_hostname: self.punycode_hostname.clone(),
            path: self.path.clone(),
            service: self.service.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CloudflaredRuntimeConfig {
    pub ingress: Vec<CloudflaredIngressRule>,
    pub origin_request: CloudflaredOriginRequestConfig,
    pub warp_routing: CloudflaredWarpRoutingConfig,
}

impl Default for CloudflaredRuntimeConfig {
    fn default() -> Self {
        let origin_request = CloudflaredOriginRequestConfig::default();
        Self {
            ingress: compile_cloudflared_ingress_rules(&origin_request, &[])
                .expect("default cloudflared ingress is valid"),
            origin_request,
            warp_routing: CloudflaredWarpRoutingConfig::default(),
        }
    }
}

impl CloudflaredRuntimeConfig {
    pub fn resolve(
        &self,
        hostname: &str,
        path: &str,
    ) -> Option<&CloudflaredResolvedService> {
        let hostname = strip_host_port(hostname);
        self.ingress
            .iter()
            .find(|rule| match_cloudflared_ingress_rule(rule, hostname, path))
            .map(|rule| &rule.service)
    }
}

#[derive(Debug, Clone)]
pub struct CloudflaredLocalIngressRule {
    pub hostname: String,
    pub path: String,
    pub service: String,
    pub origin_request: CloudflaredOriginRequestConfig,
}

struct ConfigState {
    version: i32,
    config: CloudflaredRuntimeConfig,
}

pub struct CloudflaredConfigManager {
    state: RwLock<ConfigState>,
}

impl Default for CloudflaredConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudflaredConfigManager {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(ConfigState {
                version: -1,
                config: CloudflaredRuntimeConfig::default(),
            }),
        }
    }

    pub fn current_version(&self) -> i32 {
        self.state.read().expect("config lock poisoned").version
    }

    pub fn snapshot(&self) -> CloudflaredRuntimeConfig {
        self.state
            .read()
            .expect("config lock poisoned")
            .config
            .clone()
    }

    pub fn apply(
        &self,
        version: i32,
        raw: &[u8],
    ) -> CloudflaredConfigurationUpdate {
        let mut state = self.state.write().expect("config lock poisoned");
        if version <= state.version {
            return CloudflaredConfigurationUpdate {
                latest_applied_version: state.version,
                error: None,
            };
        }
        match build_cloudflared_remote_config(raw) {
            Ok(config) => {
                state.config = config;
                state.version = version;
                CloudflaredConfigurationUpdate {
                    latest_applied_version: version,
                    error: None,
                }
            }
            Err(error) => CloudflaredConfigurationUpdate {
                latest_applied_version: state.version,
                error: Some(error),
            },
        }
    }

    pub fn resolve(
        &self,
        hostname: &str,
        path: &str,
    ) -> Option<CloudflaredResolvedService> {
        self.state
            .read()
            .expect("config lock poisoned")
            .config
            .resolve(hostname, path)
            .cloned()
    }
}

impl CloudflaredConfigurationApplier for CloudflaredConfigManager {
    fn apply_configuration(
        &self,
        version: i32,
        configuration: &[u8],
    ) -> CloudflaredConfigurationUpdate {
        self.apply(version, configuration)
    }
}

pub fn match_cloudflared_ingress_host(pattern: &str, hostname: &str) -> bool {
    pattern == hostname
        || pattern
            .strip_prefix("*.")
            .is_some_and(|suffix| hostname.ends_with(&format!(".{suffix}")))
}

pub fn match_cloudflared_ingress_rule(
    rule: &CloudflaredIngressRule,
    hostname: &str,
    path: &str,
) -> bool {
    let host_matches = matches!(rule.hostname.as_str(), "" | "*")
        || match_cloudflared_ingress_host(&rule.hostname, hostname)
        || (!rule.punycode_hostname.is_empty()
            && match_cloudflared_ingress_host(
                &rule.punycode_hostname,
                hostname,
            ));
    host_matches && rule.path.as_ref().is_none_or(|regex| regex.is_match(path))
}

pub fn compile_cloudflared_ingress_rules(
    default_origin_request: &CloudflaredOriginRequestConfig,
    rules: &[CloudflaredLocalIngressRule],
) -> Result<Vec<CloudflaredIngressRule>, String> {
    let default_rule;
    let rules = if rules.is_empty() {
        default_rule = vec![CloudflaredLocalIngressRule {
            hostname: String::new(),
            path: String::new(),
            service: "http_status:503".into(),
            origin_request: default_origin_request.clone(),
        }];
        &default_rule
    } else {
        rules
    };
    let last = rules.last().expect("rules is non-empty");
    if !is_catch_all(&last.hostname, &last.path) {
        return Err("the last ingress rule must be a catch-all rule".into());
    }
    rules
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            validate_hostname(&rule.hostname, index + 1 == rules.len())?;
            validate_access(&rule.origin_request.access)?;
            let path = if rule.path.is_empty() {
                None
            } else {
                Some(Regex::new(&rule.path).map_err(|error| {
                    format!("compile ingress path regex: {error}")
                })?)
            };
            let punycode_hostname = punycode_hostname(&rule.hostname);
            Ok(CloudflaredIngressRule {
                hostname: rule.hostname.clone(),
                punycode_hostname,
                path,
                service: parse_cloudflared_resolved_service(
                    &rule.service,
                    rule.origin_request.clone(),
                )?,
            })
        })
        .collect()
}

pub fn parse_cloudflared_resolved_service(
    service: &str,
    origin_request: CloudflaredOriginRequestConfig,
) -> Result<CloudflaredResolvedService, String> {
    let empty = |kind| CloudflaredResolvedService {
        kind,
        service: service.into(),
        destination: None,
        stream_has_port: false,
        base_url: None,
        unix_path: String::new(),
        status_code: 0,
        socks_policy: None,
        origin_request: origin_request.clone(),
    };
    if service.is_empty() {
        return if origin_request.bastion_mode {
            let mut result = empty(CloudflaredResolvedServiceKind::Bastion);
            result.service = "bastion".into();
            Ok(result)
        } else {
            Err("missing ingress service".into())
        };
    }
    if let Some(status) = service.strip_prefix("http_status:") {
        let status = status
            .parse::<u16>()
            .map_err(|error| format!("parse http_status service: {error}"))?;
        if !(100..=999).contains(&status) {
            return Err(format!("invalid http_status code: {status}"));
        }
        let mut result = empty(CloudflaredResolvedServiceKind::Status);
        result.status_code = status;
        return Ok(result);
    }
    if matches!(service, "hello_world" | "hello-world") {
        return Err("unsupported ingress service: hello_world".into());
    }
    if service == "bastion" {
        return Ok(empty(CloudflaredResolvedServiceKind::Bastion));
    }
    if service == "socks-proxy" {
        let mut result = empty(CloudflaredResolvedServiceKind::SocksProxy);
        result.socks_policy =
            Some(CloudflaredIpRulePolicy::compile(&origin_request.ip_rules)?);
        return Ok(result);
    }
    if let Some(path) = service.strip_prefix("unix:") {
        let mut result = empty(CloudflaredResolvedServiceKind::Unix);
        result.unix_path = path.into();
        result.base_url = Url::parse("http://localhost").ok();
        return Ok(result);
    }
    if let Some(path) = service.strip_prefix("unix+tls:") {
        let mut result = empty(CloudflaredResolvedServiceKind::UnixTls);
        result.unix_path = path.into();
        result.base_url = Url::parse("https://localhost").ok();
        return Ok(result);
    }

    let parsed = Url::parse(service)
        .map_err(|error| format!("parse ingress service URL: {error}"))?;
    let scheme = parsed.scheme();
    let host = parsed.host_str().ok_or_else(|| {
        format!("ingress service must include scheme and hostname: {service}")
    })?;
    if parsed.path() != "/" && !parsed.path().is_empty() {
        return Err(format!(
            "ingress service cannot include a path: {service}"
        ));
    }
    if matches!(scheme, "http" | "https" | "ws" | "wss") {
        let port = parsed.port().unwrap_or({
            if matches!(scheme, "https" | "wss") {
                443
            } else {
                80
            }
        });
        let mut base_url = parsed.clone();
        if scheme == "ws" {
            base_url.set_scheme("http").expect("valid scheme");
        } else if scheme == "wss" {
            base_url.set_scheme("https").expect("valid scheme");
        }
        let mut result = empty(CloudflaredResolvedServiceKind::Http);
        result.destination = Some(SocksAddr::new(host, port));
        result.base_url = Some(base_url);
        return Ok(result);
    }
    let default_port = match scheme {
        "ssh" => Some(22),
        "rdp" => Some(3389),
        "smb" => Some(445),
        "tcp" => Some(7864),
        _ => None,
    };
    let explicit_port = parsed.port();
    let mut result = empty(CloudflaredResolvedServiceKind::Stream);
    result.stream_has_port = explicit_port.is_some() || default_port.is_some();
    result.destination = Some(SocksAddr::new(
        host,
        explicit_port.or(default_port).unwrap_or(0),
    ));
    result.base_url = Some(parsed);
    Ok(result)
}

pub fn build_cloudflared_remote_config(
    raw: &[u8],
) -> Result<CloudflaredRuntimeConfig, String> {
    let remote: RemoteConfig = serde_json::from_slice(raw)
        .map_err(|error| format!("decode remote config: {error}"))?;
    let origin_request = merge_origin_request(
        CloudflaredOriginRequestConfig::default(),
        &remote.origin_request,
    )?;
    let rules = remote
        .ingress
        .into_iter()
        .map(|rule| {
            Ok(CloudflaredLocalIngressRule {
                hostname: rule.hostname,
                path: rule.path,
                service: rule.service,
                origin_request: merge_origin_request(
                    origin_request.clone(),
                    &rule.origin_request,
                )?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(CloudflaredRuntimeConfig {
        ingress: compile_cloudflared_ingress_rules(&origin_request, &rules)?,
        origin_request,
        warp_routing: CloudflaredWarpRoutingConfig {
            connect_timeout: seconds_or(
                remote.warp_routing.connect_timeout,
                CLOUDFLARED_DEFAULT_WARP_CONNECT_TIMEOUT,
            ),
            max_active_flows: remote.warp_routing.max_active_flows,
            tcp_keep_alive: seconds_or(
                remote.warp_routing.tcp_keep_alive,
                CLOUDFLARED_DEFAULT_WARP_TCP_KEEP_ALIVE,
            ),
        },
    })
}

fn seconds_or(seconds: i64, default: Duration) -> Duration {
    if seconds == 0 {
        default
    } else {
        Duration::from_secs(seconds.max(0) as u64)
    }
}

fn merge_origin_request(
    mut base: CloudflaredOriginRequestConfig,
    input: &RemoteOriginRequest,
) -> Result<CloudflaredOriginRequestConfig, String> {
    base.connect_timeout =
        seconds_or(input.connect_timeout, base.connect_timeout);
    base.tls_timeout = seconds_or(input.tls_timeout, base.tls_timeout);
    base.tcp_keep_alive = seconds_or(input.tcp_keep_alive, base.tcp_keep_alive);
    base.keep_alive_timeout =
        seconds_or(input.keep_alive_timeout, base.keep_alive_timeout);
    if let Some(value) = input.no_happy_eyeballs {
        base.no_happy_eyeballs = value;
    }
    if let Some(value) = input.keep_alive_connections {
        base.keep_alive_connections = value;
    }
    if !input.http_host_header.is_empty() {
        base.http_host_header.clone_from(&input.http_host_header);
    }
    if !input.origin_server_name.is_empty() {
        base.origin_server_name
            .clone_from(&input.origin_server_name);
    }
    if let Some(value) = input.match_sni_to_host {
        base.match_sni_to_host = value;
    }
    if !input.ca_pool.is_empty() {
        base.ca_pool.clone_from(&input.ca_pool);
    }
    if let Some(value) = input.no_tls_verify {
        base.no_tls_verify = value;
    }
    if let Some(value) = input.disable_chunked_encoding {
        base.disable_chunked_encoding = value;
    }
    if let Some(value) = input.bastion_mode {
        base.bastion_mode = value;
    }
    if !input.proxy_address.is_empty() {
        base.proxy_address.clone_from(&input.proxy_address);
    }
    if let Some(value) = input.proxy_port {
        base.proxy_port = u16::try_from(value)
            .map_err(|_| format!("invalid proxy port: {value}"))?;
    }
    if !input.proxy_type.is_empty() {
        base.proxy_type.clone_from(&input.proxy_type);
    }
    if !input.ip_rules.is_empty() {
        base.ip_rules = input
            .ip_rules
            .iter()
            .map(|rule| {
                let ports = rule
                    .ports
                    .iter()
                    .map(|port| {
                        u16::try_from(*port)
                            .ok()
                            .filter(|port| *port != 0)
                            .ok_or_else(|| {
                                format!("invalid ip_rule port: {port}")
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(CloudflaredIpRule {
                    prefix: rule.prefix.clone(),
                    ports,
                    allow: rule.allow,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
    }
    if let Some(value) = input.http2_origin {
        base.http2_origin = value;
    }
    if let Some(access) = &input.access {
        base.access = CloudflaredAccessConfig {
            required: access.required,
            team_name: access.team_name.clone(),
            aud_tag: access.aud_tag.clone(),
            environment: access.environment.clone(),
        };
    }
    Ok(base)
}

fn validate_hostname(hostname: &str, is_last: bool) -> Result<(), String> {
    if matches!(hostname, "" | "*") {
        return if is_last {
            Ok(())
        } else {
            Err("only the last ingress rule may be a catch-all rule".into())
        };
    }
    if hostname.matches('*').count() > 1
        || (hostname.contains('*') && !hostname.starts_with("*."))
    {
        return Err(
            "hostname wildcard must be in the form *.example.com".into()
        );
    }
    if strip_host_port(hostname) != hostname {
        return Err("ingress hostname cannot contain a port".into());
    }
    Ok(())
}

fn validate_access(access: &CloudflaredAccessConfig) -> Result<(), String> {
    if access.required
        && access.team_name.is_empty()
        && !access.aud_tag.is_empty()
    {
        Err(
            "access.team_name cannot be blank when access.aud_tag is present"
                .into(),
        )
    } else {
        Ok(())
    }
}

fn is_catch_all(hostname: &str, path: &str) -> bool {
    matches!(hostname, "" | "*") && path.is_empty()
}

fn strip_host_port(hostname: &str) -> &str {
    if hostname.starts_with('[') {
        return hostname
            .strip_prefix('[')
            .and_then(|value| value.split_once("]:"))
            .map_or(hostname, |(host, _)| host);
    }
    hostname
        .rsplit_once(':')
        .filter(|(_, port)| port.parse::<u16>().is_ok())
        .map_or(hostname, |(host, _)| host)
}

fn punycode_hostname(hostname: &str) -> String {
    if matches!(hostname, "" | "*") {
        return String::new();
    }
    let (prefix, host) = hostname
        .strip_prefix("*.")
        .map_or(("", hostname), |host| ("*.", host));
    Url::parse(&format!("http://{host}"))
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .filter(|ascii| ascii != host)
        .map_or_else(String::new, |ascii| format!("{prefix}{ascii}"))
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteConfig {
    #[serde(default)]
    origin_request: RemoteOriginRequest,
    #[serde(default)]
    ingress: Vec<RemoteIngressRule>,
    #[serde(default, rename = "warp-routing")]
    warp_routing: RemoteWarpRouting,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteIngressRule {
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    path: String,
    service: String,
    #[serde(default)]
    origin_request: RemoteOriginRequest,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteOriginRequest {
    #[serde(default)]
    connect_timeout: i64,
    #[serde(default)]
    tls_timeout: i64,
    #[serde(default)]
    tcp_keep_alive: i64,
    no_happy_eyeballs: Option<bool>,
    #[serde(default)]
    keep_alive_timeout: i64,
    keep_alive_connections: Option<i32>,
    #[serde(default)]
    http_host_header: String,
    #[serde(default)]
    origin_server_name: String,
    #[serde(rename = "matchSNIToHost", alias = "matchSniToHost")]
    match_sni_to_host: Option<bool>,
    #[serde(default)]
    ca_pool: String,
    #[serde(rename = "noTLSVerify", alias = "noTlsVerify")]
    no_tls_verify: Option<bool>,
    disable_chunked_encoding: Option<bool>,
    bastion_mode: Option<bool>,
    #[serde(default)]
    proxy_address: String,
    proxy_port: Option<u64>,
    #[serde(default)]
    proxy_type: String,
    #[serde(default)]
    ip_rules: Vec<RemoteIpRule>,
    http2_origin: Option<bool>,
    access: Option<RemoteAccess>,
}

#[derive(Debug, Default, Deserialize)]
struct RemoteAccess {
    #[serde(default)]
    required: bool,
    #[serde(default, rename = "teamName")]
    team_name: String,
    #[serde(default, rename = "audTag")]
    aud_tag: Vec<String>,
    #[serde(default)]
    environment: String,
}

#[derive(Debug, Default, Deserialize)]
struct RemoteIpRule {
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    ports: Vec<i64>,
    #[serde(default)]
    allow: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteWarpRouting {
    #[serde(default)]
    connect_timeout: i64,
    #[serde(default)]
    max_active_flows: u64,
    #[serde(default)]
    tcp_keep_alive: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_catch_all_503() {
        let config = CloudflaredRuntimeConfig::default();
        let service = config.resolve("anything.example", "/").unwrap();
        assert_eq!(service.kind, CloudflaredResolvedServiceKind::Status);
        assert_eq!(service.status_code, 503);
    }

    #[test]
    fn remote_config_merges_matches_and_rejects_stale_updates() {
        let manager = CloudflaredConfigManager::new();
        let update = manager.apply(
            7,
            r#"{
                "originRequest":{"connectTimeout":9,"httpHostHeader":"origin.internal","matchSNIToHost":true,"noTLSVerify":true,"http2Origin":true},
                "ingress":[
                    {"hostname":"*.bücher.example","path":"^/api/","service":"https://origin.example"},
                    {"service":"http_status:404"}
                ],
                "warp-routing":{"maxActiveFlows":12}
            }"#
                .as_bytes(),
        );
        assert_eq!(update.latest_applied_version, 7);
        assert!(update.error.is_none());
        let service = manager
            .resolve("www.xn--bcher-kva.example:443", "/api/test")
            .unwrap();
        assert_eq!(service.kind, CloudflaredResolvedServiceKind::Http);
        assert_eq!(service.destination.as_ref().unwrap().port(), 443);
        assert_eq!(service.origin_request.connect_timeout.as_secs(), 9);
        assert!(service.origin_request.match_sni_to_host);
        assert!(service.origin_request.no_tls_verify);
        assert!(service.origin_request.http2_origin);
        assert_eq!(manager.snapshot().warp_routing.max_active_flows, 12);
        assert_eq!(manager.apply(6, b"not-json").latest_applied_version, 7);
        assert_eq!(manager.current_version(), 7);
    }

    #[test]
    fn failed_new_configuration_preserves_last_good_snapshot() {
        let manager = CloudflaredConfigManager::new();
        manager.apply(1, br#"{"ingress":[{"service":"http_status:204"}]}"#);
        let failed = manager.apply(
            2,
            br#"{"ingress":[{"hostname":"example.com","service":"http://origin"}]}"#,
        );
        assert!(failed.error.is_some());
        assert_eq!(failed.latest_applied_version, 1);
        assert_eq!(manager.current_version(), 1);
        assert_eq!(
            manager.resolve("example.com", "/").unwrap().status_code,
            204
        );
    }

    #[test]
    fn service_and_ip_policy_boundaries_match_upstream() {
        let origin = CloudflaredOriginRequestConfig {
            ip_rules: vec![
                CloudflaredIpRule {
                    prefix: "10.0.0.0/8".into(),
                    ports: vec![443],
                    allow: true,
                },
                CloudflaredIpRule {
                    prefix: "0.0.0.0/0".into(),
                    ports: vec![],
                    allow: false,
                },
            ],
            ..Default::default()
        };
        let socks =
            parse_cloudflared_resolved_service("socks-proxy", origin).unwrap();
        let policy = socks.socks_policy.unwrap();
        assert!(policy.allows("10.1.2.3".parse::<IpAddr>().unwrap(), 443));
        assert!(!policy.allows("10.1.2.3".parse().unwrap(), 80));
        let ssh = parse_cloudflared_resolved_service(
            "ssh://server.example",
            CloudflaredOriginRequestConfig::default(),
        )
        .unwrap();
        assert_eq!(ssh.destination.unwrap().port(), 22);
        assert!(
            parse_cloudflared_resolved_service(
                "hello_world",
                CloudflaredOriginRequestConfig::default(),
            )
            .is_err()
        );
    }
}
