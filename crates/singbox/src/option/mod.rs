//! Configuration model and loader corresponding to `inner/sing-box/option`.

mod base;
mod certificate;
mod cloudflared;
mod dns;
mod http;
mod ntp;
mod openconnect;
mod openvpn;
mod protocol;
mod route;
mod tailscale;
mod tls;
mod types;

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub use base::*;
pub use certificate::*;
pub use cloudflared::*;
pub use dns::*;
pub use http::*;
pub use ntp::*;
pub use openconnect::*;
pub use openvpn::*;
pub use protocol::*;
pub use route::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
pub use tailscale::*;
pub use tls::*;
pub use types::{
    Addr, DnsQueryType, DomainStrategy, Duration, FwMark, Listable,
    MemoryBytes, Network, NetworkBytesCompat, NetworkList, Prefix, Prefixable,
};

use crate::{
    common::json::{merge_value, strip_comments},
    constant, schema,
};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("read config at {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("decode config at {path}: {message}")]
    Decode { path: PathBuf, message: String },
    #[error("JSON syntax error: {0}")]
    Syntax(String),
    #[error("merge options: {0}")]
    Merge(String),
    #[error("{0}")]
    Validation(String),
    #[error("no configuration files were supplied")]
    NoConfig,
}

#[derive(Debug, Clone)]
pub struct ConfigEntry {
    pub content: String,
    pub path: PathBuf,
    pub value: Value,
    pub options: Options,
}

#[derive(Debug, Default, Clone)]
pub struct ConfigLoader {
    paths: Vec<PathBuf>,
    directories: Vec<PathBuf>,
}

impl ConfigLoader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn path(mut self, path: impl Into<PathBuf>) -> Self {
        self.paths.push(path.into());
        self
    }

    pub fn directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.directories.push(path.into());
        self
    }

    pub fn read(&self) -> Result<Vec<ConfigEntry>, ConfigError> {
        let mut entries = Vec::new();
        for path in &self.paths {
            entries.push(read_config_at(path)?);
        }
        for directory in &self.directories {
            let dir_entries = fs::read_dir(directory).map_err(|source| {
                ConfigError::Read {
                    path: directory.clone(),
                    source,
                }
            })?;
            for entry in dir_entries {
                let entry = entry.map_err(|source| ConfigError::Read {
                    path: directory.clone(),
                    source,
                })?;
                let path = entry.path();
                if entry
                    .file_type()
                    .map(|kind| kind.is_file())
                    .unwrap_or(false)
                    && path
                        .extension()
                        .is_some_and(|extension| extension == "json")
                {
                    entries.push(read_config_at(&path)?);
                }
            }
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        if entries.is_empty() {
            return Err(ConfigError::NoConfig);
        }
        Ok(entries)
    }

    pub fn read_and_merge(&self) -> Result<Options, ConfigError> {
        let entries = self.read()?;
        if entries.len() == 1 {
            return Ok(entries.into_iter().next().expect("one entry").options);
        }
        let mut merged: Option<Value> = None;
        for entry in entries {
            merged = Some(match merged {
                Some(destination) => {
                    merge_value(entry.value, destination, false)?
                }
                None => entry.value,
            });
        }
        options_from_value(
            merged.expect("non-empty entries"),
            Path::new("<merged>"),
        )
    }
}

fn read_config_at(path: &Path) -> Result<ConfigEntry, ConfigError> {
    let content = if path == Path::new("stdin") {
        let mut content = String::new();
        std::io::stdin()
            .read_to_string(&mut content)
            .map_err(|source| ConfigError::Read {
                path: path.to_owned(),
                source,
            })?;
        content
    } else {
        fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?
    };
    let clean =
        strip_comments(&content).map_err(|error| ConfigError::Decode {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
    let value: Value =
        serde_json::from_str(&clean).map_err(|error| ConfigError::Decode {
            path: path.to_owned(),
            message: format!(
                "{error} (row {}, column {})",
                error.line(),
                error.column()
            ),
        })?;
    let options = options_from_value(value.clone(), path)?;
    Ok(ConfigEntry {
        content,
        path: path.to_owned(),
        value,
        options,
    })
}

fn options_from_value(
    value: Value,
    path: &Path,
) -> Result<Options, ConfigError> {
    schema::validate_runtime_config(&value).map_err(|error| {
        ConfigError::Decode {
            path: path.to_owned(),
            message: error.to_string(),
        }
    })?;
    let options: Options =
        serde_json::from_value(value).map_err(|error| ConfigError::Decode {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
    options.validate()?;
    Ok(options)
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentalOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_file: Option<CacheFileOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_api: Option<ClashApiOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v2ray_api: Option<V2RayApiOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug: Option<DebugOptions>,
}

/// Configuration surface of the excluded V2Ray stats API.
///
/// The Rust library intentionally does not start the application-control API,
/// but keeping its fixed Go option shape typed lets embedding applications
/// inspect, migrate, and reject malformed configurations deterministically.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2RayApiOptions {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub listen: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<V2RayStatsServiceOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2RayStatsServiceOptions {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<String>,
}

/// Go runtime debug knobs retained for configuration migration only.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugOptions {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub listen: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gc_percent: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_stack: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_threads: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub panic_on_fault: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub trace_back: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_limit: Option<MemoryBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oom_killer: Option<bool>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClashApiOptions {
    #[serde(default)]
    pub external_controller: String,
    #[serde(default)]
    pub external_ui: String,
    #[serde(default)]
    pub external_ui_download_url: String,
    #[serde(default)]
    pub external_ui_download_detour: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub default_mode: String,
    #[serde(default)]
    pub access_control_allow_origin: Listable<String>,
    #[serde(default)]
    pub access_control_allow_private_network: bool,
    // Deprecated since sing-box 1.8. Kept only to emit the upstream error.
    #[serde(default)]
    pub cache_file: String,
    #[serde(default)]
    pub cache_id: String,
    #[serde(default)]
    pub store_mode: bool,
    #[serde(default)]
    pub store_selected: bool,
    #[serde(default)]
    pub store_fakeip: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheFileOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub cache_id: String,
    #[serde(default)]
    pub store_fakeip: bool,
    #[serde(default)]
    pub store_rdrc: bool,
    #[serde(default)]
    pub rdrc_timeout: Duration,
    #[serde(default)]
    pub store_dns: bool,
}

/// A named Linux network namespace exposed to the embeddable runtime.
///
/// The upstream `unshare` variant relies on the `sing-box run` command to
/// create and hold a helper process.  The Rust crate deliberately remains a
/// library, so it accepts that shape for configuration compatibility but the
/// runtime rejects it with an actionable error.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkNamespaceOptions {
    #[serde(rename = "type", default)]
    pub kind: String,
    pub tag: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub pid_file: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(
        rename = "$schema",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<LogOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntp: Option<NtpOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertificateOptions>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_providers: Vec<TaggedOptions>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_clients: Vec<HttpClient>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_namespaces: Vec<NetworkNamespaceOptions>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<TaggedOptions>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<TaggedOptions>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<TaggedOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<RouteOptions>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<TaggedOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<ExperimentalOptions>,
}

#[derive(Debug, Default, Deserialize)]
struct RemovedInboundFields {
    #[serde(default)]
    sniff: bool,
    #[serde(default)]
    sniff_override_destination: bool,
    #[serde(default)]
    sniff_timeout: Duration,
    #[serde(default)]
    domain_strategy: DomainStrategy,
    #[serde(default)]
    udp_disable_domain_unmapping: bool,
}

impl RemovedInboundFields {
    fn has_legacy_route_fields(&self) -> bool {
        self.sniff
            || self.sniff_override_destination
            || self.sniff_timeout != Duration::ZERO
            || self.domain_strategy != DomainStrategy::default()
            || self.udp_disable_domain_unmapping
    }
}

impl Options {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut namespace_tags = HashSet::new();
        for namespace in &self.network_namespaces {
            if namespace.tag.is_empty() {
                return Err(ConfigError::Validation(
                    "network namespace: missing tag".into(),
                ));
            }
            if !namespace_tags.insert(namespace.tag.clone()) {
                return Err(ConfigError::Validation(format!(
                    "network namespace: duplicated tag: {}",
                    namespace.tag
                )));
            }
            match namespace.kind.as_str() {
                "" | "default" if namespace.path.is_empty() => {
                    return Err(ConfigError::Validation(format!(
                        "network namespace[{}]: missing path",
                        namespace.tag
                    )));
                }
                "" | "default" | "unshare" => {}
                kind => {
                    return Err(ConfigError::Validation(format!(
                        "unknown network namespace type: {kind}"
                    )));
                }
            }
        }
        if let Some(dns) = &self.dns {
            let mut tags = HashSet::new();
            for (index, server) in dns.servers.iter().enumerate() {
                if server.kind.is_empty()
                    || server.kind == constant::DNS_TYPE_LEGACY
                {
                    return Err(ConfigError::Validation(
                        dns::LEGACY_DNS_SERVER_REMOVED_MESSAGE.into(),
                    ));
                }
                if !constant::DNS_TRANSPORT_TYPES
                    .contains(&server.kind.as_str())
                {
                    return Err(ConfigError::Validation(format!(
                        "unknown DNS transport type: {}",
                        server.kind
                    )));
                }
                let tag = if server.tag.is_empty() {
                    index.to_string()
                } else {
                    server.tag.clone()
                };
                if !tags.insert(tag.clone()) {
                    return Err(ConfigError::Validation(format!(
                        "duplicate DNS server tag: {tag}"
                    )));
                }
            }
            if !dns.final_server.is_empty() && !tags.contains(&dns.final_server)
            {
                return Err(ConfigError::Validation(format!(
                    "default DNS server not found: {}",
                    dns.final_server
                )));
            }
        }
        if let Some(ntp) = &self.ntp {
            ntp.validate().map_err(|error| {
                ConfigError::Validation(format!("invalid NTP options: {error}"))
            })?;
        }
        validate_types("inbound", &self.inbounds, constant::INBOUND_TYPES)?;
        validate_types("outbound", &self.outbounds, constant::OUTBOUND_TYPES)?;
        validate_types("endpoint", &self.endpoints, constant::ENDPOINT_TYPES)?;
        validate_types("service", &self.services, constant::SERVICE_TYPES)?;
        validate_types(
            "certificate provider",
            &self.certificate_providers,
            constant::CERTIFICATE_PROVIDER_TYPES,
        )?;
        validate_unique_tags("inbound", &self.inbounds, None)?;
        validate_unique_tags("service", &self.services, None)?;

        for (index, inbound) in self.inbounds.iter().enumerate() {
            if inbound.kind != constant::TYPE_CLOUDFLARED {
                let removed: RemovedInboundFields = serde_json::from_value(
                    Value::Object(inbound.fields.clone()),
                )
                .map_err(|error| {
                    ConfigError::Validation(format!(
                        "decode {} options for tag {:?}: {error}",
                        inbound.kind, inbound.tag
                    ))
                })?;
                if removed.has_legacy_route_fields() {
                    return Err(ConfigError::Validation(
                        "legacy inbound fields are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-legacy-inbound-fields-to-rule-actions".into(),
                    ));
                }
            }
            if inbound.kind != constant::TYPE_CLOUDFLARED {
                continue;
            }
            let tag = if inbound.tag.is_empty() {
                index.to_string()
            } else {
                inbound.tag.clone()
            };
            inbound
                .decode::<CloudflaredInboundOptions>()?
                .validate()
                .map_err(|error| {
                    ConfigError::Validation(format!(
                        "invalid cloudflared inbound {tag:?}: {error}"
                    ))
                })?;
        }

        for outbound in &self.outbounds {
            if outbound.kind != constant::TYPE_DIRECT {
                continue;
            }
            let options = outbound.decode::<DirectOutboundOptions>()?;
            options
                .validate_removed_override_fields()
                .map_err(|message| ConfigError::Validation(message.into()))?;
        }

        let mut outbound_tags = HashSet::new();
        validate_unique_tags(
            "outbound/endpoint",
            &self.outbounds,
            Some(&mut outbound_tags),
        )?;
        validate_unique_tags(
            "outbound/endpoint",
            &self.endpoints,
            Some(&mut outbound_tags),
        )?;
        validate_unique_tags(
            "certificate provider",
            &self.certificate_providers,
            None,
        )?;

        for (index, endpoint) in self.endpoints.iter().enumerate() {
            let tag = if endpoint.tag.is_empty() {
                index.to_string()
            } else {
                endpoint.tag.clone()
            };
            let result = match endpoint.kind.as_str() {
                constant::TYPE_OPENVPN_CLIENT => endpoint
                    .decode::<OpenVpnClientEndpointOptions>()?
                    .validate()
                    .map_err(|error| error.to_string()),
                constant::TYPE_OPENVPN_SERVER => endpoint
                    .decode::<OpenVpnServerEndpointOptions>()?
                    .validate()
                    .map_err(|error| error.to_string()),
                constant::TYPE_OPENCONNECT => {
                    endpoint.decode::<OpenConnectEndpointOptions>()?.validate()
                }
                constant::TYPE_TAILSCALE => {
                    endpoint.decode::<TailscaleEndpointOptions>()?.validate()
                }
                _ => continue,
            };
            result.map_err(|error| {
                ConfigError::Validation(format!(
                    "invalid {} endpoint {tag:?}: {error}",
                    endpoint.kind
                ))
            })?;
        }

        let mut http_tags = HashSet::new();
        for client in &self.http_clients {
            if client.tag.is_empty() {
                return Err(ConfigError::Validation(
                    "missing http client tag".into(),
                ));
            }
            if !http_tags.insert(client.tag.clone()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate http client tag: {}",
                    client.tag
                )));
            }
            client.options.validate().map_err(|error| {
                ConfigError::Validation(format!(
                    "invalid http client {:?}: {error}",
                    client.tag
                ))
            })?;
        }
        if let Some(default_http_client) = self
            .route
            .as_ref()
            .map(|route| route.default_http_client.as_str())
            .filter(|tag| !tag.is_empty())
            && !http_tags.contains(default_http_client)
        {
            return Err(ConfigError::Validation(format!(
                "default http_client not found: {default_http_client}"
            )));
        }
        if let Some(route) = &self.route {
            #[cfg(not(any(
                target_os = "linux",
                target_os = "macos",
                target_os = "windows",
                target_os = "android",
                target_os = "ios"
            )))]
            if route.auto_detect_interface {
                return Err(ConfigError::Validation(
                    "route.auto_detect_interface is only supported on Linux, macOS, Windows, Android and iOS"
                        .into(),
                ));
            }
            #[cfg(not(any(
                target_os = "linux",
                target_os = "macos",
                target_os = "windows",
                target_os = "android",
                target_os = "ios"
            )))]
            if !route.default_interface.is_empty() {
                return Err(ConfigError::Validation(
                    "route.default_interface is only supported on Linux, macOS, Windows, Android and iOS"
                        .into(),
                ));
            }
            let has_network_defaults = route.default_network_strategy.is_some()
                || !route.default_network_type.is_empty()
                || !route.default_fallback_network_type.is_empty()
                || route.default_fallback_delay.as_nanos() != 0;
            if has_network_defaults && !route.auto_detect_interface {
                return Err(ConfigError::Validation(
                    "route.auto_detect_interface is required by default_network_strategy"
                        .into(),
                ));
            }
            if has_network_defaults && !route.default_interface.is_empty() {
                return Err(ConfigError::Validation(
                    "route.default_network_strategy conflicts with route.default_interface"
                        .into(),
                ));
            }
            #[cfg(not(target_os = "linux"))]
            if route.default_mark.0 != 0 {
                return Err(ConfigError::Validation(
                    "route.default_mark is only supported on Linux".into(),
                ));
            }
            #[cfg(not(target_os = "android"))]
            if route.override_android_vpn {
                return Err(ConfigError::Validation(
                    "route.override_android_vpn is only supported on Android"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn resolve_network_namespace_references(
        &mut self,
    ) -> Result<(), ConfigError> {
        let mut paths = HashMap::new();
        for namespace in &self.network_namespaces {
            match namespace.kind.as_str() {
                "" | "default" => {
                    paths.insert(namespace.tag.clone(), namespace.path.clone());
                }
                "unshare" => {
                    return Err(ConfigError::Validation(format!(
                        "network namespace[{}]: type unshare requires the excluded sing-box CLI holder; use type default with an existing namespace path",
                        namespace.tag
                    )));
                }
                _ => unreachable!("network namespace type validated"),
            }
        }
        if paths.is_empty() {
            return Ok(());
        }

        for client in &mut self.http_clients {
            resolve_namespace_name(
                &mut client.options.dialer.abstract_options.netns,
                &paths,
            );
        }
        for tagged in self
            .certificate_providers
            .iter_mut()
            .chain(&mut self.endpoints)
            .chain(&mut self.inbounds)
            .chain(&mut self.outbounds)
            .chain(&mut self.services)
        {
            resolve_namespace_values(&mut tagged.fields, &paths);
        }
        if let Some(dns) = &mut self.dns {
            for server in &mut dns.servers {
                resolve_namespace_values(&mut server.fields, &paths);
            }
        }
        if let Some(ntp) = &mut self.ntp {
            resolve_namespace_name(
                &mut ntp.dialer.abstract_options.netns,
                &paths,
            );
        }
        if let Some(route) = self.route.as_mut() {
            for rule in &mut route.rules {
                rule.resolve_network_namespace(&paths);
            }
            for rule_set in &mut route.rule_set {
                let Some(remote) = rule_set.remote_mut() else {
                    continue;
                };
                if let Some(HttpClientReference::Inline(client)) =
                    &mut remote.http_client
                {
                    resolve_namespace_name(
                        &mut client.dialer.abstract_options.netns,
                        &paths,
                    );
                }
            }
        }
        Ok(())
    }
}

fn resolve_namespace_name(value: &mut String, paths: &HashMap<String, String>) {
    if let Some(path) = paths.get(value) {
        value.clone_from(path);
    }
}

fn resolve_namespace_values(
    object: &mut Map<String, Value>,
    paths: &HashMap<String, String>,
) {
    for (key, value) in object {
        if key == "netns"
            && let Value::String(name) = value
        {
            resolve_namespace_name(name, paths);
        } else {
            resolve_namespace_value(value, paths);
        }
    }
}

fn resolve_namespace_value(value: &mut Value, paths: &HashMap<String, String>) {
    match value {
        Value::Object(object) => resolve_namespace_values(object, paths),
        Value::Array(values) => {
            for value in values {
                resolve_namespace_value(value, paths);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogOptions {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub level: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub output: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub timestamp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedOptions {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

impl TaggedOptions {
    /// Decode the already schema-checked payload into a protocol-specific
    /// option structure. `type` and `tag` are registry metadata and excluded.
    pub fn decode<T>(&self) -> Result<T, ConfigError>
    where
        T: serde::de::DeserializeOwned,
    {
        serde_json::from_value(Value::Object(self.fields.clone())).map_err(
            |error| {
                ConfigError::Validation(format!(
                    "decode {} options for tag {:?}: {error}",
                    self.kind, self.tag
                ))
            },
        )
    }

    pub fn to_value(&self) -> Value {
        let mut object = self.fields.clone();
        object.insert("type".into(), Value::String(self.kind.clone()));
        if !self.tag.is_empty() {
            object.insert("tag".into(), Value::String(self.tag.clone()));
        }
        Value::Object(object)
    }
}

fn validate_types(
    label: &str,
    values: &[TaggedOptions],
    allowed: &[&str],
) -> Result<(), ConfigError> {
    for value in values {
        if !allowed.contains(&value.kind.as_str()) {
            return Err(ConfigError::Validation(format!(
                "unknown {label} type: {}",
                value.kind
            )));
        }
        if label == "outbound" && value.kind == constant::TYPE_DNS {
            return Err(ConfigError::Validation(
                "dns outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use rule actions instead".into(),
                ));
        }
    }
    Ok(())
}

fn validate_unique_tags(
    label: &str,
    values: &[TaggedOptions],
    shared: Option<&mut HashSet<String>>,
) -> Result<(), ConfigError> {
    let mut local = HashSet::new();
    let seen = match shared {
        Some(seen) => seen,
        None => &mut local,
    };
    for (index, value) in values.iter().enumerate() {
        let tag = if value.tag.is_empty() {
            index.to_string()
        } else {
            value.tag.clone()
        };
        if !seen.insert(tag.clone()) {
            return Err(ConfigError::Validation(format!(
                "duplicate {label} tag: {tag}"
            )));
        }
    }
    Ok(())
}

/// Registry primitive used by protocol modules while they are ported.
#[derive(Debug, Default)]
pub struct Registry<T> {
    entries: HashMap<String, T>,
}

impl<T> Registry<T> {
    pub fn register(&mut self, kind: impl Into<String>, value: T) -> Option<T> {
        self.entries.insert(kind.into(), value)
    }

    pub fn get(&self, kind: &str) -> Option<&T> {
        self.entries.get(kind)
    }

    pub fn option_types(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        ConfigLoader, DirectOutboundOptions, DomainStrategy,
        HttpClientReference, Options, RemoteDnsServerOptions, RouteOptions,
        RouteRuleActionOptions,
    };

    #[test]
    fn rejects_unknown_top_level_fields() {
        let error =
            serde_json::from_str::<Options>(r#"{"unknown":true}"#).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn loader_preserves_schema_omitted_fields_for_go_compatible_handling() {
        let directory = tempfile::tempdir().unwrap();

        let hysteria = directory.path().join("hysteria.json");
        fs::write(
            &hysteria,
            r#"{"inbounds":[{"type":"hysteria","recv_window_conn":8388608,"disable_mtu_discovery":true}]}"#,
        )
        .unwrap();
        let options = ConfigLoader::new()
            .path(&hysteria)
            .read_and_merge()
            .unwrap();
        let decoded = options.inbounds[0]
            .decode::<super::HysteriaInboundOptions>()
            .unwrap();
        assert_eq!(decoded.recv_window_conn, 8_388_608);
        assert!(decoded.disable_mtu_discovery);

        let proxy = directory.path().join("proxy-protocol.json");
        fs::write(
            &proxy,
            r#"{"outbounds":[{"type":"direct","tag":"direct","proxy_protocol":2}]}"#,
        )
        .unwrap();
        let options =
            ConfigLoader::new().path(&proxy).read_and_merge().unwrap();
        let direct = options.outbounds[0]
            .decode::<DirectOutboundOptions>()
            .unwrap();
        assert_eq!(direct.proxy_protocol, 2);
        let error = direct.validate_removed_proxy_protocol().unwrap_err();
        assert_eq!(
            error,
            "Proxy Protocol is deprecated and removed in sing-box 1.6.0"
        );

        let nested_dialers = directory.path().join("nested-dialers.json");
        fs::write(
            &nested_dialers,
            r#"{
                "ntp": {
                    "enabled": true,
                    "server": "time.example.com",
                    "domain_strategy": "prefer_ipv4"
                },
                "dns": {
                    "servers": [{
                        "type": "udp",
                        "tag": "remote",
                        "server": "dns.example.com",
                        "domain_strategy": "prefer_ipv6"
                    }]
                },
                "http_clients": [{
                    "tag": "resources",
                    "domain_strategy": "ipv4_only"
                }],
                "route": {
                    "rules": [{
                        "action": "direct",
                        "domain": "example.com",
                        "domain_strategy": "ipv6_only"
                    }]
                }
            }"#,
        )
        .unwrap();
        let options = ConfigLoader::new()
            .path(&nested_dialers)
            .read_and_merge()
            .unwrap();
        assert_eq!(
            options.ntp.unwrap().dialer.abstract_options.domain_strategy,
            DomainStrategy::PreferIpv4
        );
        let remote = options.dns.unwrap().servers[0]
            .decode::<RemoteDnsServerOptions>()
            .unwrap();
        assert_eq!(
            remote.local.dialer.abstract_options.domain_strategy,
            DomainStrategy::PreferIpv6
        );
        assert_eq!(
            options.http_clients[0]
                .options
                .dialer
                .abstract_options
                .domain_strategy,
            DomainStrategy::Ipv4Only
        );
        let route = options.route.unwrap();
        let super::RouteRuleOptions::Default(rule) = &route.rules[0] else {
            panic!("expected a default route rule");
        };
        let RouteRuleActionOptions::Direct(dialer) = &rule.action else {
            panic!("expected a direct route action");
        };
        assert_eq!(dialer.domain_strategy, DomainStrategy::Ipv6Only);
    }

    #[test]
    fn loader_returns_upstream_errors_for_removed_hidden_fields() {
        let directory = tempfile::tempdir().unwrap();
        let inbound = directory.path().join("legacy-inbound.json");
        fs::write(&inbound, r#"{"inbounds":[{"type":"socks","sniff":true}]}"#)
            .unwrap();
        let error = ConfigLoader::new()
            .path(&inbound)
            .read_and_merge()
            .unwrap_err()
            .to_string();
        assert!(error.contains(
            "legacy inbound fields are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0"
        ));

        let direct = directory.path().join("legacy-direct.json");
        fs::write(
            &direct,
            r#"{"outbounds":[{"type":"direct","override_address":"127.0.0.1"}]}"#,
        )
        .unwrap();
        let error = ConfigLoader::new()
            .path(&direct)
            .read_and_merge()
            .unwrap_err()
            .to_string();
        assert!(error.contains(
            "destination override fields in direct outbound are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0"
        ));
    }

    #[test]
    fn experimental_fixed_shapes_are_typed_and_strict() {
        let options: Options = serde_json::from_str(
            r#"{
                "experimental": {
                    "v2ray_api": {
                        "listen": "127.0.0.1:10085",
                        "stats": {
                            "enabled": true,
                            "inbounds": ["mixed-in"],
                            "outbounds": ["proxy"],
                            "users": ["alice"]
                        }
                    },
                    "debug": {
                        "listen": "127.0.0.1:6060",
                        "gc_percent": 50,
                        "max_stack": 67108864,
                        "max_threads": 4096,
                        "panic_on_fault": true,
                        "trace_back": "all",
                        "memory_limit": "512MB",
                        "oom_killer": false
                    }
                }
            }"#,
        )
        .unwrap();
        let experimental = options.experimental.unwrap();
        let api = experimental.v2ray_api.unwrap();
        assert_eq!(api.listen, "127.0.0.1:10085");
        let stats = api.stats.unwrap();
        assert!(stats.enabled);
        assert_eq!(stats.inbounds, ["mixed-in"]);
        assert_eq!(stats.outbounds, ["proxy"]);
        assert_eq!(stats.users, ["alice"]);

        let debug = experimental.debug.unwrap();
        assert_eq!(debug.gc_percent, Some(50));
        assert_eq!(debug.max_stack, Some(67_108_864));
        assert_eq!(debug.max_threads, Some(4096));
        assert_eq!(debug.panic_on_fault, Some(true));
        assert_eq!(debug.memory_limit.unwrap().value(), 512 * 1024 * 1024);
        assert_eq!(debug.oom_killer, Some(false));

        let error = serde_json::from_str::<Options>(
            r#"{"experimental":{"v2ray_api":{"unknown":true}}}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
        let error = serde_json::from_str::<Options>(
            r#"{"experimental":{"debug":{"unknown":true}}}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn validates_duplicate_outbound_and_endpoint_tags() {
        let options: Options = serde_json::from_str(
            r#"{"outbounds":[{"type":"direct","tag":"same"}],"endpoints":[{"type":"wireguard","tag":"same"}]}"#,
        )
        .unwrap();
        assert!(
            options
                .validate()
                .unwrap_err()
                .to_string()
                .contains("duplicate outbound/endpoint tag")
        );
    }

    #[test]
    fn reports_the_upstream_dns_outbound_removal() {
        let options: Options = serde_json::from_str(
            r#"{"outbounds":[{"type":"dns","tag":"removed"}]}"#,
        )
        .unwrap();
        assert_eq!(
            options.validate().unwrap_err().to_string(),
            "dns outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use rule actions instead"
        );
    }

    #[test]
    fn rejects_removed_legacy_dns_shapes_with_upstream_errors() {
        for server in [
            serde_json::json!({"address":"1.1.1.1"}),
            serde_json::json!({"type":"legacy","address":"1.1.1.1"}),
        ] {
            let options: Options = serde_json::from_value(
                serde_json::json!({"dns":{"servers":[server]}}),
            )
            .unwrap();
            assert_eq!(
                options.validate().unwrap_err().to_string(),
                super::dns::LEGACY_DNS_SERVER_REMOVED_MESSAGE
            );
        }

        for fakeip in [
            serde_json::Value::Null,
            serde_json::json!({
                "enabled": true,
                "inet4_range": "198.18.0.0/15"
            }),
        ] {
            let error = serde_json::from_value::<Options>(serde_json::json!({
                "dns": {"fakeip": fakeip}
            }))
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                super::dns::LEGACY_DNS_FAKEIP_REMOVED_MESSAGE
            );
        }

        let error = serde_json::from_value::<Options>(serde_json::json!({
            "dns": {"unknown_dns_field": true}
        }))
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn validates_openvpn_endpoints_with_tagged_context() {
        let options: Options = serde_json::from_str(
            r#"{"endpoints":[{"type":"openvpn-client","tag":"office","server":"vpn.example","server_port":1194,"fragment":67,"tls":{"peer_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]}"#,
        )
        .unwrap();
        let error = options.validate().unwrap_err().to_string();
        assert!(
            error.contains("openvpn-client endpoint \"office\""),
            "{error}"
        );
        assert!(error.contains("fragment"), "{error}");

        let options: Options = serde_json::from_str(
            r#"{"endpoints":[{"type":"openvpn-server","tag":"gateway","address":"10.8.0.1/24","tls":{"certificate":"cert","key":"key"}}]}"#,
        )
        .unwrap();
        options.validate().unwrap();
    }

    #[test]
    fn resolves_named_network_namespaces_across_runtime_options() {
        let mut options: Options = serde_json::from_str(
            r#"{
                "network_namespaces":[{"tag":"isolated","path":"/proc/4321/ns/net"}],
                "http_clients":[{"tag":"rules","netns":"isolated"}],
                "dns":{"servers":[{"type":"udp","tag":"dns","server":"1.1.1.1","netns":"isolated"}]},
                "route":{"rule_set":[{"type":"remote","tag":"remote","url":"https://example.com/rules.srs","http_client":{"netns":"isolated"}}]},
                "inbounds":[{"type":"socks","tag":"in","netns":"isolated"}],
                "outbounds":[{"type":"direct","tag":"out","netns":"isolated"}]
            }"#,
        )
        .unwrap();
        options.validate().unwrap();
        options.resolve_network_namespace_references().unwrap();
        let expected = "/proc/4321/ns/net";
        assert_eq!(
            options.http_clients[0]
                .options
                .dialer
                .abstract_options
                .netns,
            expected
        );
        assert_eq!(
            options.dns.as_ref().unwrap().servers[0].fields["netns"],
            expected
        );
        assert_eq!(options.inbounds[0].fields["netns"], expected);
        assert_eq!(options.outbounds[0].fields["netns"], expected);
        let remote = options.route.as_ref().unwrap().rule_set[0]
            .remote()
            .unwrap();
        let HttpClientReference::Inline(client) =
            remote.http_client.as_ref().unwrap()
        else {
            panic!("expected inline HTTP client")
        };
        assert_eq!(client.dialer.abstract_options.netns, expected);
    }

    #[test]
    fn route_options_are_typed_and_preserve_recursive_payloads() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "route": {
                "rules": [{"domain_suffix": "example.com", "outbound": "proxy"}],
                "rule_set": [{"type": "inline", "tag": "private", "rules": [{"ip_cidr": "192.168.0.0/16"}]}],
                "final": "direct",
                "find_process": true,
                "find_neighbor": true,
                "dhcp_lease_files": "/var/lib/dhcp/dhclient.leases",
                "auto_detect_interface": true,
                "override_android_vpn": true,
                "default_mark": "0xca6c",
                "default_domain_resolver": {"server": "dns", "strategy": "prefer_ipv6"},
                "default_network_strategy": "fallback",
                "default_network_type": "wifi",
                "default_fallback_network_type": ["cellular", "ethernet"],
                "default_fallback_delay": "450ms",
                "default_http_client": "rules"
            }
        }))
        .unwrap();
        let route = options.route.as_ref().unwrap();
        assert_eq!(route.final_outbound, "direct");
        assert_eq!(route.default_mark.0, 0xca6c);
        assert_eq!(
            route.rules[0].to_value().unwrap()["domain_suffix"],
            "example.com"
        );
        assert_eq!(route.rule_set[0].tags().as_slice(), ["private"]);
        assert_eq!(
            route.default_domain_resolver.as_ref().unwrap().server,
            "dns"
        );
        assert_eq!(serde_json::to_value(route).unwrap()["final"], "direct");
        assert!(
            serde_json::from_value::<RouteOptions>(serde_json::json!({
                "final": "direct",
                "unknown_route_field": true
            }))
            .unwrap_err()
            .to_string()
            .contains("unknown field")
        );
    }

    #[test]
    fn route_network_defaults_validate_before_runtime_construction() {
        let missing_auto_detect: Options =
            serde_json::from_value(serde_json::json!({
                "route": {"default_network_strategy": "fallback"}
            }))
            .unwrap();
        assert!(
            missing_auto_detect
                .validate()
                .unwrap_err()
                .to_string()
                .contains("auto_detect_interface")
        );

        let conflicting_interface: Options =
            serde_json::from_value(serde_json::json!({
                "route": {
                    "auto_detect_interface": true,
                    "default_interface": "en0",
                    "default_network_strategy": "hybrid"
                }
            }))
            .unwrap();
        assert!(
            conflicting_interface
                .validate()
                .unwrap_err()
                .to_string()
                .contains("conflicts")
        );
    }

    #[test]
    fn rejects_cli_owned_unshare_network_namespace_at_runtime_resolution() {
        let mut options: Options = serde_json::from_str(
            r#"{"network_namespaces":[{"type":"unshare","tag":"isolated","pid_file":"/tmp/netns.pid"}]}"#,
        )
        .unwrap();
        options.validate().unwrap();
        let error = options
            .resolve_network_namespace_references()
            .unwrap_err()
            .to_string();
        assert!(error.contains("excluded sing-box CLI holder"), "{error}");
    }

    #[test]
    fn loader_sorts_directory_and_merges_like_go_cli() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("20.json"), r#"{"log":{"level":"debug"},"outbounds":[{"type":"block","tag":"b"}]}"#).unwrap();
        fs::write(directory.path().join("10.json"), r#"{"log":{"level":"info"},"outbounds":[{"type":"direct","tag":"a"}]}"#).unwrap();
        fs::write(directory.path().join("ignored.txt"), "{}").unwrap();
        let options = ConfigLoader::new()
            .directory(directory.path())
            .read_and_merge()
            .unwrap();
        assert_eq!(options.log.unwrap().level, "info");
        assert_eq!(
            options
                .outbounds
                .iter()
                .map(|item| item.tag.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }
}
