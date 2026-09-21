//! Route rule compilation and matching.

pub mod adguard;
mod srs;

use std::{
    collections::{HashMap, VecDeque},
    fmt, fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{Duration as StdDuration, Instant, SystemTime},
};

use ipnet::IpNet;
use n0_watcher::Watcher as _;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use tokio::{sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{
        NeighborResolver, NetworkDialOptions, ProcessLookupResult,
        ProcessLookupStatus, ProcessResolver,
    },
    common::{
        http::{DownloadClient, DownloadOptions},
        json::strip_comments,
        network::{Network, SocksAddr, is_private_address},
        sniff::{PacketSniffer, StreamSniffer},
    },
    dns::persistent::{PersistentDnsCache, PersistentRuleSetEntry},
    log::Logger,
    option::{
        AbstractDialerOptions, DnsQueryType, DomainStrategy,
        Duration as ConfigDuration, HeadlessRuleOptions, HttpClient,
        HttpClientOptions, HttpClientReference, Listable,
        NetworkStrategy as ConfigNetworkStrategy, Prefixable,
        ROUTE_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE,
    },
    outbound::OutboundManager,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub query_type: Option<u16>,
    /// Explicit address family carried by DNS queries or protocol-specific
    /// metadata. A concrete IP destination supersedes this value, as in Go's
    /// `prepareMatchMetadata`.
    pub ip_version: Option<u8>,
    pub inbound: String,
    /// Immediately preceding inbound in an inbound-detour chain.  sing-box
    /// uses this to reject an immediate A -> B -> A loop while preserving the
    /// rest of the connection metadata for the injected protocol handler.
    pub last_inbound: String,
    /// Outbound currently performing a DNS lookup. This is distinct from the
    /// route-selected outbound reported after an inbound decision.
    pub outbound: String,
    pub source: Option<SocksAddr>,
    pub destination: Option<SocksAddr>,
    pub destination_addresses: Vec<IpAddr>,
    pub origin_destination: Option<SocksAddr>,
    /// Destination snapshot used for process ownership lookup when route
    /// preprocessing later replaces `origin_destination` (for example while
    /// restoring a transparent FakeIP flow). This preserves upstream's
    /// process-before-FakeIP ordering.
    pub process_origin_destination: Option<SocksAddr>,
    pub fake_ip: bool,
    pub network: Option<Network>,
    pub auth_user: String,
    pub protocol: String,
    /// Domain discovered from payload sniffing or a preceding resolve action.
    /// The socket destination remains untouched so dialing an intercepted IP
    /// still reaches the address selected by the client.
    pub domain: String,
    pub client: String,
    pub process_name: String,
    pub process_path: String,
    /// Diagnostic outcome from the native connection-owner lookup.
    pub process_lookup: String,
    pub package_name: String,
    pub user: String,
    pub user_id: Option<i32>,
    pub clash_mode: String,
    pub network_type: String,
    pub network_is_expensive: bool,
    pub network_is_constrained: bool,
    pub wifi_ssid: String,
    pub wifi_bssid: String,
    pub interface_address: HashMap<String, Vec<IpAddr>>,
    pub network_interface_address: HashMap<String, Vec<IpAddr>>,
    pub default_interface_address: Vec<IpAddr>,
    pub preferred_by: Vec<String>,
    pub source_mac_address: String,
    pub source_hostname: String,
}

impl Metadata {
    pub fn domain(&self) -> Option<&str> {
        if !self.domain.is_empty() {
            return Some(&self.domain);
        }
        match &self.destination {
            Some(SocksAddr::Domain { host, .. }) => Some(host),
            _ => None,
        }
    }

    pub fn destination_ip(&self) -> Option<IpAddr> {
        match &self.destination {
            Some(SocksAddr::Ip(address)) => Some(address.ip()),
            _ => None,
        }
    }

    pub fn source_ip(&self) -> Option<IpAddr> {
        match &self.source {
            Some(SocksAddr::Ip(address)) => Some(address.ip()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Route {
        outbound: String,
        options: ConnectionOverride,
    },
    RouteOptions(ConnectionOverride),
    Direct,
    DirectOptions {
        options: AbstractDialerOptions,
        /// Internal outbound key installed by Runtime. It is deliberately
        /// absent from the public outbound list and metered as `direct`.
        outbound: String,
    },
    Bypass {
        outbound: String,
        options: ConnectionOverride,
    },
    Reject {
        method: String,
        no_drop: bool,
    },
    HijackDns,
    Sniff(SniffOptions),
    Resolve(ResolveOptions),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffOptions {
    pub names: Vec<String>,
    pub stream_sniffers: Vec<StreamSniffer>,
    pub packet_sniffers: Vec<PacketSniffer>,
    pub timeout: StdDuration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveOptions {
    pub server: String,
    pub timeout: Option<StdDuration>,
    pub strategy: DomainStrategy,
    pub disable_cache: bool,
    pub disable_optimistic_cache: bool,
    pub rewrite_ttl: Option<u32>,
    pub client_subnet: Option<IpNet>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConnectionOverride {
    pub address: String,
    pub port: u16,
    pub tls_fragment: bool,
    pub tls_fragment_fallback_delay: Option<StdDuration>,
    pub tls_record_fragment: bool,
    pub tls_spoof: String,
    pub tls_spoof_method: crate::common::tls_spoof::TlsSpoofMethod,
    pub network: NetworkDialOptions,
    pub udp_timeout: Option<StdDuration>,
}

impl ConnectionOverride {
    pub fn apply(&self, destination: &SocksAddr) -> SocksAddr {
        let host = if self.address.is_empty() {
            destination.host()
        } else {
            self.address.clone()
        };
        let port = if self.port == 0 {
            destination.port()
        } else {
            self.port
        };
        SocksAddr::new(host, port)
    }

    fn update(&mut self, next: &Self) {
        if !next.address.is_empty() {
            self.address.clone_from(&next.address);
        }
        if next.port != 0 {
            self.port = next.port;
        }
        if next.tls_fragment {
            self.tls_fragment = true;
            self.tls_fragment_fallback_delay = next.tls_fragment_fallback_delay;
        }
        if next.tls_record_fragment {
            self.tls_record_fragment = true;
        }
        if !next.tls_spoof.is_empty() {
            self.tls_spoof.clone_from(&next.tls_spoof);
            self.tls_spoof_method = next.tls_spoof_method;
        }
        if next.network.strategy.is_some() {
            self.network.strategy = next.network.strategy;
        }
        if !next.network.network_type.is_empty() {
            self.network
                .network_type
                .clone_from(&next.network.network_type);
        }
        if !next.network.fallback_network_type.is_empty() {
            self.network
                .fallback_network_type
                .clone_from(&next.network.fallback_network_type);
        }
        if next
            .network
            .fallback_delay
            .is_some_and(|delay| !delay.is_zero())
        {
            self.network.fallback_delay = next.network.fallback_delay;
        }
        if next.udp_timeout.is_some_and(|timeout| !timeout.is_zero()) {
            self.udp_timeout = next.udp_timeout;
        }
        if next.network.udp_disable_domain_unmapping {
            self.network.udp_disable_domain_unmapping = true;
        }
        if next.network.udp_connect {
            self.network.udp_connect = true;
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("invalid route rule: {0}")]
    InvalidRule(String),
    #[error("invalid regular expression {pattern:?}: {source}")]
    Regex {
        pattern: String,
        source: regex::Error,
    },
    #[error("invalid IP prefix {value:?}: {message}")]
    Prefix { value: String, message: String },
    #[error("invalid rule-set: {0}")]
    InvalidRuleSet(String),
    #[error("read rule-set at {path}: {source}")]
    ReadRuleSet {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Portable source representation used by sing-box rule-set JSON files.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRuleSet {
    pub version: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<HeadlessRuleOptions>,
}

impl SourceRuleSet {
    /// Decode extended JSON (including comments) and validate every rule.
    pub fn parse(content: &[u8]) -> Result<Self, RouteError> {
        parse_source_rule_set(content, "input")
    }

    /// Encode the source document as upstream-compatible SRS bytes.
    pub fn compile(&self) -> Result<Vec<u8>, RouteError> {
        validate_source_rule_set(self)?;
        let rules = headless_rule_values(&self.rules)?;
        let version = srs::downgrade_version(&rules, self.version);
        srs::write(&rules, version).map_err(RouteError::InvalidRuleSet)
    }

    /// Render canonical, pretty source JSON with a trailing newline.
    pub fn format(&self) -> Result<String, RouteError> {
        validate_source_rule_set(self)?;
        serde_json::to_string_pretty(self)
            .map(|value| value + "\n")
            .map_err(|error| RouteError::InvalidRuleSet(error.to_string()))
    }

    /// Return the zero-based indices of rules matching an IP address or domain.
    pub fn matching_rules(
        &self,
        address: &str,
    ) -> Result<Vec<usize>, RouteError> {
        validate_source_rule_set(self)?;
        let values = headless_rule_values(&self.rules)?;
        let rules = compile_headless_rules(&values)?;
        let metadata = Metadata {
            destination: Some(SocksAddr::new(address, 0)),
            ..Metadata::default()
        };
        Ok(rules
            .iter()
            .enumerate()
            .filter_map(|(index, rule)| {
                rule.matches_with_ip_source(&metadata, false)
                    .then_some(index)
            })
            .collect())
    }
}

/// Compile a source rule-set document into the binary SRS format.
pub fn compile_rule_set(content: &[u8]) -> Result<Vec<u8>, RouteError> {
    SourceRuleSet::parse(content)?.compile()
}

/// Recover a binary SRS document into its source representation.
pub fn decompile_rule_set(content: &[u8]) -> Result<SourceRuleSet, RouteError> {
    let (version, rules) =
        srs::read_with_version(content).map_err(RouteError::InvalidRuleSet)?;
    if has_rule_field(&rules, "adguard_domain") {
        return Err(RouteError::InvalidRuleSet(
            "unable to decompile binary AdGuard rules to rule-set".into(),
        ));
    }
    let rules = rules
        .into_iter()
        .map(|rule| {
            serde_json::from_value(rule)
                .map_err(|error| RouteError::InvalidRuleSet(error.to_string()))
        })
        .collect::<Result<_, _>>()?;
    let source = SourceRuleSet { version, rules };
    validate_source_rule_set(&source)?;
    Ok(source)
}

/// Merge source rule-sets in path order, preserving rule order and the newest
/// source version.
pub fn merge_rule_sets<'a>(
    contents: impl IntoIterator<Item = &'a [u8]>,
) -> Result<SourceRuleSet, RouteError> {
    let mut merged = SourceRuleSet {
        version: 0,
        rules: Vec::new(),
    };
    let mut found = false;
    for content in contents {
        let source = SourceRuleSet::parse(content)?;
        merged.version = merged.version.max(source.version);
        merged.rules.extend(source.rules);
        found = true;
    }
    if !found {
        return Err(RouteError::InvalidRuleSet(
            "no rule-set files were supplied".into(),
        ));
    }
    validate_source_rule_set(&merged)?;
    Ok(merged)
}

fn has_rule_field(rules: &[Value], field: &str) -> bool {
    rules.iter().any(|rule| {
        rule.get(field).is_some_and(|value| match value {
            Value::Array(values) => !values.is_empty(),
            Value::Null => false,
            _ => true,
        }) || rule
            .get("rules")
            .and_then(Value::as_array)
            .is_some_and(|rules| has_rule_field(rules, field))
    })
}

pub struct RuleSet {
    tag: String,
    state: RwLock<RuleSetState>,
    updates: watch::Sender<RuleSetUpdate>,
    update_validators: RwLock<Vec<Arc<dyn RuleSetUpdateValidator>>>,
    source: RuleSetSource,
    task: Mutex<Option<RuleSetTask>>,
}

#[derive(Debug)]
struct RuleSetState {
    rules: Vec<HeadlessRule>,
    metadata: RuleSetMetadata,
    generation: u64,
}

/// Matcher categories present in a rule-set snapshot.
///
/// This mirrors sing-box's `adapter.RuleSetMetadata` and lets embedding hosts
/// reject an update that would invalidate a platform-specific consumer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RuleSetMetadata {
    pub contains_process_rule: bool,
    pub contains_wifi_rule: bool,
    pub contains_ip_cidr_rule: bool,
    pub contains_dns_query_type_rule: bool,
    pub contains_non_ip_cidr_rule: bool,
}

/// Atomically published state notification for a successfully reloaded
/// local or remote rule-set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSetUpdate {
    pub generation: u64,
    pub metadata: RuleSetMetadata,
}

/// Validates a candidate rule-set snapshot before it becomes observable.
///
/// This is the embeddable counterpart of sing-box's
/// `adapter.DNSRuleSetUpdateValidator`. A rejection preserves the current
/// rules, metadata, generation, and update notification unchanged.
pub trait RuleSetUpdateValidator: Send + Sync {
    fn validate_rule_set_metadata_update(
        &self,
        tag: &str,
        metadata: RuleSetMetadata,
    ) -> Result<(), String>;
}

impl<F> RuleSetUpdateValidator for F
where
    F: Fn(&str, RuleSetMetadata) -> Result<(), String> + Send + Sync,
{
    fn validate_rule_set_metadata_update(
        &self,
        tag: &str,
        metadata: RuleSetMetadata,
    ) -> Result<(), String> {
        self(tag, metadata)
    }
}

enum RuleSetSource {
    Static,
    Local {
        path: PathBuf,
        format: String,
        modified: Mutex<Option<SystemTime>>,
    },
    Remote(Box<RemoteRuleSetSource>),
}

struct RemoteRuleSetSource {
    url: String,
    initial_path: Option<PathBuf>,
    format: String,
    update_interval: StdDuration,
    etag: Mutex<String>,
    cache: Option<Arc<PersistentDnsCache>>,
    url_hash: Vec<u8>,
    cached_content: Mutex<Vec<u8>>,
    last_updated: Mutex<Option<SystemTime>>,
    http_client: Option<HttpClientReference>,
    download_detour: String,
    download_client: Mutex<Option<Arc<DownloadClient>>>,
}

impl fmt::Debug for RuleSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuleSet")
            .field("tag", &self.tag)
            .finish()
    }
}

#[derive(Debug)]
struct RuleSetTask {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

impl RuleSet {
    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn matches(&self, metadata: &Metadata) -> bool {
        self.state
            .read()
            .expect("rule-set lock poisoned")
            .rules
            .iter()
            .any(|rule| rule.matches_with_ip_source(metadata, false))
    }

    pub fn metadata(&self) -> RuleSetMetadata {
        self.state.read().expect("rule-set lock poisoned").metadata
    }

    pub fn generation(&self) -> u64 {
        self.state
            .read()
            .expect("rule-set lock poisoned")
            .generation
    }

    /// Subscribe to successful rule-set replacements. The current snapshot is
    /// available immediately through `Receiver::borrow`.
    pub fn subscribe(&self) -> watch::Receiver<RuleSetUpdate> {
        self.updates.subscribe()
    }

    /// Register a validator that runs before every local or remote reload is
    /// committed. Validators are invoked in registration order.
    pub fn add_update_validator(
        &self,
        validator: Arc<dyn RuleSetUpdateValidator>,
    ) {
        self.update_validators
            .write()
            .expect("rule-set update-validator lock poisoned")
            .push(validator);
    }

    /// Validate and atomically replace this rule-set from source JSON or SRS
    /// bytes. The current snapshot is preserved when decoding or any
    /// registered metadata validator fails.
    pub fn reload(
        &self,
        format: &str,
        content: &[u8],
    ) -> Result<(), RouteError> {
        self.reload_bytes(format, content, "library reload")
    }

    /// Return all destination CIDR prefixes in the current snapshot, including
    /// prefixes nested inside logical rules.
    pub fn destination_prefixes(&self) -> Vec<IpNet> {
        let state = self.state.read().expect("rule-set lock poisoned");
        let mut prefixes = Vec::new();
        for rule in state.rules.iter() {
            rule.collect_destination_prefixes(&mut prefixes);
        }
        prefixes
    }

    fn matches_with_outer(
        &self,
        metadata: &Metadata,
        outer: RuleMatch,
        ip_cidr_match_source: bool,
    ) -> bool {
        self.matches_with_outer_accept_empty(
            metadata,
            outer,
            ip_cidr_match_source,
            false,
        )
    }

    fn matches_with_outer_accept_empty(
        &self,
        metadata: &Metadata,
        outer: RuleMatch,
        ip_cidr_match_source: bool,
        ip_cidr_accept_empty: bool,
    ) -> bool {
        let state = self.state.read().expect("rule-set lock poisoned");
        if let [HeadlessRule::Default(rule)] = state.rules.as_slice()
            && !rule.base.raw.invert
        {
            return outer
                .merge(rule.evaluate(
                    metadata,
                    ip_cidr_match_source,
                    ip_cidr_accept_empty,
                ))
                .done();
        }
        outer.done()
            && state.rules.iter().any(|rule| {
                rule.matches_with_ip_source_accept_empty(
                    metadata,
                    ip_cidr_match_source,
                    ip_cidr_accept_empty,
                )
            })
    }

    async fn start(self: &Arc<Self>) -> Result<(), RouteError> {
        if self
            .task
            .lock()
            .expect("rule-set task lock poisoned")
            .is_some()
        {
            return Ok(());
        }
        match &self.source {
            RuleSetSource::Static => Ok(()),
            RuleSetSource::Local { .. } => {
                let cancel = CancellationToken::new();
                let task_cancel = cancel.clone();
                let rule_set = self.clone();
                let handle = tokio::spawn(async move {
                    let mut interval =
                        tokio::time::interval(StdDuration::from_secs(1));
                    interval.tick().await;
                    loop {
                        tokio::select! {
                            _ = task_cancel.cancelled() => break,
                            _ = interval.tick() => {
                                rule_set.reload_local_if_changed();
                            }
                        }
                    }
                });
                *self.task.lock().expect("rule-set task lock poisoned") =
                    Some(RuleSetTask { cancel, handle });
                Ok(())
            }
            RuleSetSource::Remote(source) => {
                let mut loaded = !self
                    .state
                    .read()
                    .expect("rule-set lock poisoned")
                    .rules
                    .is_empty();
                if !loaded
                    && let Some(path) = &source.initial_path
                    && self.reload_path(path).is_ok()
                {
                    loaded = true;
                }
                if !loaded {
                    self.fetch_remote().await?;
                }
                let update_interval = source.update_interval;
                let cancel = CancellationToken::new();
                let task_cancel = cancel.clone();
                let rule_set = self.clone();
                let handle = tokio::spawn(async move {
                    let mut interval = tokio::time::interval(update_interval);
                    interval.tick().await;
                    let monitor =
                        crate::common::network_monitor::NetworkMonitor::new()
                            .await
                            .ok();
                    let mut watcher = monitor
                        .as_ref()
                        .map(crate::common::network_monitor::NetworkMonitor::interface_state);
                    let mut previous =
                        watcher.as_mut().map(|watcher| watcher.get());
                    loop {
                        tokio::select! {
                            _ = task_cancel.cancelled() => break,
                            _ = interval.tick() => {
                                if let Err(error) = rule_set.fetch_remote().await {
                                    tracing::warn!(
                                        rule_set = %rule_set.tag,
                                        %error,
                                        "update remote rule-set"
                                    );
                                }
                            }
                            current = async {
                                match watcher.as_mut() {
                                    Some(watcher) => watcher.updated().await.ok(),
                                    None => std::future::pending().await,
                                }
                            } => {
                                let Some(current) = current else {
                                    watcher = None;
                                    continue;
                                };
                                let major = previous
                                    .as_ref()
                                    .is_some_and(|previous| current.is_major_change(previous));
                                previous = Some(current);
                                if major {
                                    rule_set.reset_download_client().await;
                                    tracing::info!(
                                        rule_set = %rule_set.tag,
                                        "reset remote rule-set HTTP connection pool after network change"
                                    );
                                }
                            }
                        }
                    }
                });
                *self.task.lock().expect("rule-set task lock poisoned") =
                    Some(RuleSetTask { cancel, handle });
                Ok(())
            }
        }
    }

    async fn close(&self) {
        let task = self
            .task
            .lock()
            .expect("rule-set task lock poisoned")
            .take();
        if let Some(task) = task {
            task.cancel.cancel();
            let _ = task.handle.await;
        }
        self.reset_download_client().await;
    }

    async fn reset_download_client(&self) {
        let RuleSetSource::Remote(source) = &self.source else {
            return;
        };
        let client = source
            .download_client
            .lock()
            .expect("rule-set download client lock poisoned")
            .clone();
        if let Some(client) = client {
            client.reset().await;
        }
    }

    fn reload_path(&self, path: &Path) -> Result<(), RouteError> {
        let format = match &self.source {
            RuleSetSource::Local { format, .. } => format,
            RuleSetSource::Remote(source) => &source.format,
            RuleSetSource::Static => return Ok(()),
        };
        let content =
            fs::read(path).map_err(|source| RouteError::ReadRuleSet {
                path: path.to_owned(),
                source,
            })?;
        self.reload_bytes(format, &content, &path.display().to_string())
    }

    fn reload_bytes(
        &self,
        format: &str,
        content: &[u8],
        source: &str,
    ) -> Result<(), RouteError> {
        let rules = decode_rule_set(format, content, source)?;
        let metadata = rule_set_metadata(&rules);
        for validator in self
            .update_validators
            .read()
            .expect("rule-set update-validator lock poisoned")
            .iter()
        {
            validator
                .validate_rule_set_metadata_update(&self.tag, metadata)
                .map_err(|error| {
                    RouteError::InvalidRuleSet(format!(
                        "validate rule-set metadata update: {error}"
                    ))
                })?;
        }
        let update = {
            let mut state = self.state.write().expect("rule-set lock poisoned");
            let generation = state.generation.wrapping_add(1);
            *state = RuleSetState {
                rules,
                metadata,
                generation,
            };
            RuleSetUpdate {
                generation,
                metadata,
            }
        };
        self.updates.send_replace(update);
        Ok(())
    }

    fn reload_local_if_changed(&self) {
        let RuleSetSource::Local { path, modified, .. } = &self.source else {
            return;
        };
        let Ok(current) =
            fs::metadata(path).and_then(|metadata| metadata.modified())
        else {
            return;
        };
        let changed = modified
            .lock()
            .expect("rule-set modified lock poisoned")
            .is_none_or(|previous| previous != current);
        if changed {
            match self.reload_path(path) {
                Ok(()) => {
                    *modified
                        .lock()
                        .expect("rule-set modified lock poisoned") =
                        Some(current);
                    tracing::info!(
                        rule_set = %self.tag,
                        path = %path.display(),
                        generation = self.generation(),
                        "reloaded local rule-set"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        rule_set = %self.tag,
                        path = %path.display(),
                        %error,
                        "reload local rule-set"
                    );
                }
            }
        }
    }

    async fn fetch_remote(&self) -> Result<(), RouteError> {
        let RuleSetSource::Remote(source) = &self.source else {
            return Ok(());
        };
        let RemoteRuleSetSource {
            url,
            format,
            etag,
            cache,
            url_hash,
            cached_content,
            last_updated,
            http_client: _,
            download_detour,
            download_client,
            ..
        } = source.as_ref();
        let previous_etag =
            etag.lock().expect("rule-set ETag lock poisoned").clone();
        let configured_download = download_client
            .lock()
            .expect("rule-set download client lock poisoned")
            .clone();
        let (status, next_etag, content) =
            if configured_download.is_none() && download_detour.is_empty() {
                let client =
                    reqwest::Client::builder().build().map_err(|error| {
                        RouteError::InvalidRuleSet(format!(
                            "create rule-set HTTP client: {error}"
                        ))
                    })?;
                let mut request = client.get(url);
                if !previous_etag.is_empty() {
                    request = request.header(
                        reqwest::header::IF_NONE_MATCH,
                        previous_etag.clone(),
                    );
                }
                let response = request.send().await.map_err(|error| {
                    RouteError::InvalidRuleSet(format!(
                        "fetch rule-set {} from {url}: {error}",
                        self.tag
                    ))
                })?;
                let status = response.status().as_u16();
                let next_etag = response
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let content = response.bytes().await.map_err(|error| {
                    RouteError::InvalidRuleSet(format!(
                        "read rule-set {} from {url}: {error}",
                        self.tag
                    ))
                })?;
                (status, next_etag, content.to_vec())
            } else {
                let client = configured_download.ok_or_else(|| {
                    RouteError::InvalidRuleSet(format!(
                        "HTTP client is not initialized for rule-set {:?}",
                        self.tag
                    ))
                })?;
                let mut headers = hyper::HeaderMap::new();
                if !previous_etag.is_empty() {
                    headers.insert(
                    hyper::header::IF_NONE_MATCH,
                    previous_etag.parse().map_err(|error| {
                        RouteError::InvalidRuleSet(format!(
                            "invalid cached ETag for rule-set {:?}: {error}",
                            self.tag
                        ))
                    })?,
                );
                }
                let response =
                    client.download(url, &headers).await.map_err(|error| {
                        RouteError::InvalidRuleSet(format!(
                            "fetch rule-set {} from {url}: {error}",
                            self.tag
                        ))
                    })?;
                let next_etag = response
                    .headers
                    .get(hyper::header::ETAG)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                (response.status.as_u16(), next_etag, response.body.to_vec())
            };
        if status == 304 {
            let now = SystemTime::now();
            *last_updated
                .lock()
                .expect("rule-set last-updated lock poisoned") = Some(now);
            if let Some(cache) = cache {
                let entry = PersistentRuleSetEntry {
                    content: cached_content
                        .lock()
                        .expect("rule-set content lock poisoned")
                        .clone(),
                    last_updated: now,
                    etag: previous_etag,
                    url_hash: url_hash.clone(),
                };
                if let Err(error) = cache.save_rule_set(&self.tag, &entry) {
                    tracing::warn!(
                        rule_set = %self.tag,
                        %error,
                        "save remote rule-set revalidation time"
                    );
                }
            }
            tracing::info!(
                rule_set = %self.tag,
                %url,
                "remote rule-set not modified"
            );
            return Ok(());
        }
        if status != 200 {
            return Err(RouteError::InvalidRuleSet(format!(
                "fetch rule-set {} from {url}: unexpected status {status}",
                self.tag
            )));
        }
        self.reload_bytes(format, &content, url)?;
        if let Some(next_etag) = next_etag {
            *etag.lock().expect("rule-set ETag lock poisoned") = next_etag;
        }
        let now = SystemTime::now();
        *last_updated
            .lock()
            .expect("rule-set last-updated lock poisoned") = Some(now);
        *cached_content
            .lock()
            .expect("rule-set content lock poisoned") = content.clone();
        if let Some(cache) = cache {
            let entry = PersistentRuleSetEntry {
                content,
                last_updated: now,
                etag: etag.lock().expect("rule-set ETag lock poisoned").clone(),
                url_hash: url_hash.clone(),
            };
            if let Err(error) = cache.save_rule_set(&self.tag, &entry) {
                tracing::warn!(
                    rule_set = %self.tag,
                    %error,
                    "save updated remote rule-set"
                );
            }
        }
        tracing::info!(
            rule_set = %self.tag,
            %url,
            generation = self.generation(),
            "updated remote rule-set"
        );
        Ok(())
    }
}

const MATCH_SOURCE_ADDRESS: u8 = 1 << 0;
const MATCH_SOURCE_PORT: u8 = 1 << 1;
const MATCH_DESTINATION_ADDRESS: u8 = 1 << 2;
const MATCH_DESTINATION_PORT: u8 = 1 << 3;

#[derive(Debug, Clone, Copy)]
struct RuleMatch {
    ordinary: bool,
    required: u8,
    satisfied: u8,
}

impl RuleMatch {
    fn done(self) -> bool {
        self.ordinary && self.required & !self.satisfied == 0
    }

    fn merge(self, other: Self) -> Self {
        Self {
            ordinary: self.ordinary && other.ordinary,
            required: self.required | other.required,
            satisfied: self.satisfied | other.satisfied,
        }
    }
}

#[derive(Debug)]
enum HeadlessRule {
    Default(Box<HeadlessDefaultRule>),
    Logical(HeadlessLogicalRule),
}

impl HeadlessRule {
    fn compile(value: &Value, depth: usize) -> Result<Self, RouteError> {
        if depth > 100 {
            return Err(RouteError::InvalidRuleSet(
                "logical rule nested too deep".into(),
            ));
        }
        let object = value.as_object().ok_or_else(|| {
            RouteError::InvalidRuleSet("headless rule is not an object".into())
        })?;
        let kind = match object.get("type") {
            None => "",
            Some(Value::String(kind)) => kind.as_str(),
            Some(_) => {
                return Err(RouteError::InvalidRuleSet(
                    "headless rule type is not a string".into(),
                ));
            }
        };
        match kind {
            "" | "default" => Ok(Self::Default(Box::new(
                HeadlessDefaultRule::compile(value)?,
            ))),
            "logical" => Ok(Self::Logical(HeadlessLogicalRule::compile(
                value,
                depth + 1,
            )?)),
            kind => Err(RouteError::InvalidRuleSet(format!(
                "unknown headless rule type: {kind}"
            ))),
        }
    }

    fn matches_with_ip_source(
        &self,
        metadata: &Metadata,
        ip_cidr_match_source: bool,
    ) -> bool {
        self.matches_with_ip_source_accept_empty(
            metadata,
            ip_cidr_match_source,
            false,
        )
    }

    fn matches_with_ip_source_accept_empty(
        &self,
        metadata: &Metadata,
        ip_cidr_match_source: bool,
        ip_cidr_accept_empty: bool,
    ) -> bool {
        match self {
            Self::Default(rule) => rule.matches(
                metadata,
                ip_cidr_match_source,
                ip_cidr_accept_empty,
            ),
            Self::Logical(rule) => rule.matches(
                metadata,
                ip_cidr_match_source,
                ip_cidr_accept_empty,
            ),
        }
    }

    fn collect_destination_prefixes(&self, output: &mut Vec<IpNet>) {
        match self {
            Self::Default(rule) => {
                output.extend(rule.base.destination_prefixes.iter().copied());
            }
            Self::Logical(rule) => {
                for child in &rule.rules {
                    child.collect_destination_prefixes(output);
                }
            }
        }
    }

    fn accumulate_metadata(&self, metadata: &mut RuleSetMetadata) {
        match self {
            Self::Default(rule) => {
                let raw = &rule.base.raw;
                let contains_process_rule =
                    !raw.process_name.as_slice().is_empty()
                        || !raw.process_path.as_slice().is_empty()
                        || !raw.process_path_regex.as_slice().is_empty()
                        || !raw.package_name.as_slice().is_empty()
                        || !raw.package_name_regex.as_slice().is_empty();
                let contains_wifi_rule = !raw.wifi_ssid.as_slice().is_empty()
                    || !raw.wifi_bssid.as_slice().is_empty();
                metadata.contains_process_rule |= contains_process_rule;
                metadata.contains_wifi_rule |= contains_wifi_rule;
                metadata.contains_ip_cidr_rule |=
                    !raw.ip_cidr.as_slice().is_empty();
                metadata.contains_dns_query_type_rule |=
                    !rule.query_type.is_empty();
                metadata.contains_non_ip_cidr_rule |=
                    !rule.query_type.is_empty()
                        || !raw.network.as_slice().is_empty()
                        || !raw.domain.as_slice().is_empty()
                        || !raw.domain_suffix.as_slice().is_empty()
                        || !raw.domain_keyword.as_slice().is_empty()
                        || !raw.domain_regex.as_slice().is_empty()
                        || !rule.adguard_regex.is_empty()
                        || rule.compact_domain.is_some()
                        || rule.compact_adguard.is_some()
                        || !raw.source_ip_cidr.as_slice().is_empty()
                        || !raw.source_port.as_slice().is_empty()
                        || !raw.source_port_range.as_slice().is_empty()
                        || !raw.port.as_slice().is_empty()
                        || !raw.port_range.as_slice().is_empty()
                        || contains_process_rule
                        || !raw.network_type.as_slice().is_empty()
                        || raw.network_is_expensive
                        || raw.network_is_constrained
                        || contains_wifi_rule
                        || !rule.network_interface_prefixes.is_empty()
                        || !rule.default_interface_prefixes.is_empty();
            }
            Self::Logical(rule) => {
                for child in &rule.rules {
                    child.accumulate_metadata(metadata);
                }
            }
        }
    }
}

fn rule_set_metadata(rules: &[HeadlessRule]) -> RuleSetMetadata {
    let mut metadata = RuleSetMetadata::default();
    for rule in rules {
        rule.accumulate_metadata(&mut metadata);
    }
    metadata
}

#[derive(Debug)]
struct HeadlessLogicalRule {
    mode: LogicalMode,
    rules: Vec<HeadlessRule>,
    invert: bool,
}

impl HeadlessLogicalRule {
    fn compile(value: &Value, depth: usize) -> Result<Self, RouteError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(rename = "type", default)]
            _kind: String,
            mode: String,
            #[serde(default)]
            rules: Vec<Value>,
            #[serde(default)]
            invert: bool,
        }
        let raw: Raw = serde_json::from_value(value.clone())
            .map_err(|error| RouteError::InvalidRuleSet(error.to_string()))?;
        let mode = parse_logical_mode(&raw.mode, "headless")?;
        if raw.rules.is_empty() {
            return Err(RouteError::InvalidRuleSet(
                "logical headless rule has no child rules".into(),
            ));
        }
        Ok(Self {
            mode,
            rules: raw
                .rules
                .iter()
                .map(|rule| HeadlessRule::compile(rule, depth))
                .collect::<Result<_, _>>()?,
            invert: raw.invert,
        })
    }

    fn matches(
        &self,
        metadata: &Metadata,
        ip_cidr_match_source: bool,
        ip_cidr_accept_empty: bool,
    ) -> bool {
        let matched = match self.mode {
            LogicalMode::And => self.rules.iter().all(|rule| {
                rule.matches_with_ip_source_accept_empty(
                    metadata,
                    ip_cidr_match_source,
                    ip_cidr_accept_empty,
                )
            }),
            LogicalMode::Or => self.rules.iter().any(|rule| {
                rule.matches_with_ip_source_accept_empty(
                    metadata,
                    ip_cidr_match_source,
                    ip_cidr_accept_empty,
                )
            }),
        };
        matched != self.invert
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawHeadlessRule {
    #[serde(rename = "type")]
    _kind: String,
    query_type: Listable<DnsQueryType>,
    network: Listable<String>,
    domain: Listable<String>,
    domain_suffix: Listable<String>,
    domain_keyword: Listable<String>,
    domain_regex: Listable<String>,
    adguard_domain: Listable<String>,
    source_ip_cidr: Listable<String>,
    ip_cidr: Listable<String>,
    source_port: Listable<u16>,
    source_port_range: Listable<String>,
    port: Listable<u16>,
    port_range: Listable<String>,
    process_name: Listable<String>,
    process_path: Listable<String>,
    process_path_regex: Listable<String>,
    package_name: Listable<String>,
    package_name_regex: Listable<String>,
    network_type: Listable<String>,
    network_is_expensive: bool,
    network_is_constrained: bool,
    wifi_ssid: Listable<String>,
    wifi_bssid: Listable<String>,
    network_interface_address: HashMap<String, Listable<String>>,
    default_interface_address: Listable<String>,
    invert: bool,
}

#[derive(Debug)]
struct HeadlessDefaultRule {
    query_type: Vec<u16>,
    base: DefaultRule,
    network_interface_prefixes: HashMap<String, Vec<IpNet>>,
    default_interface_prefixes: Vec<IpNet>,
    adguard_regex: Vec<Regex>,
    compact_domain: Option<srs::SuccinctSet>,
    compact_adguard: Option<srs::SuccinctSet>,
}

impl HeadlessDefaultRule {
    fn compile(value: &Value) -> Result<Self, RouteError> {
        Self::compile_with_matchers(value, None, None)
    }

    fn compile_with_matchers(
        value: &Value,
        compact_domain: Option<srs::SuccinctSet>,
        compact_adguard: Option<srs::SuccinctSet>,
    ) -> Result<Self, RouteError> {
        let raw: RawHeadlessRule = serde_json::from_value(value.clone())
            .map_err(|error| RouteError::InvalidRuleSet(error.to_string()))?;
        if !raw.has_matcher()
            && compact_domain.is_none()
            && compact_adguard.is_none()
        {
            return Err(RouteError::InvalidRuleSet(
                "empty headless rule".into(),
            ));
        }
        let network_interface_prefixes = raw
            .network_interface_address
            .iter()
            .map(|(kind, values)| {
                Ok((kind.clone(), compile_prefixes(values.as_slice())?))
            })
            .collect::<Result<_, RouteError>>()?;
        let default_interface_prefixes =
            compile_prefixes(raw.default_interface_address.as_slice())?;
        let query_type = raw
            .query_type
            .as_slice()
            .iter()
            .map(|query_type| query_type.0)
            .collect();
        let adguard_regex =
            compile_adguard_patterns(raw.adguard_domain.as_slice())?;
        let base = DefaultRule::from_raw(
            RawDefaultRule {
                network: raw.network,
                domain: raw.domain,
                domain_suffix: raw.domain_suffix,
                domain_keyword: raw.domain_keyword,
                domain_regex: raw.domain_regex,
                source_ip_cidr: raw.source_ip_cidr,
                ip_cidr: raw.ip_cidr,
                source_port: raw.source_port,
                source_port_range: raw.source_port_range,
                port: raw.port,
                port_range: raw.port_range,
                process_name: raw.process_name,
                process_path: raw.process_path,
                process_path_regex: raw.process_path_regex,
                package_name: raw.package_name,
                package_name_regex: raw.package_name_regex,
                network_type: raw.network_type,
                network_is_expensive: raw.network_is_expensive,
                network_is_constrained: raw.network_is_constrained,
                wifi_ssid: raw.wifi_ssid,
                wifi_bssid: raw.wifi_bssid,
                invert: raw.invert,
                ..RawDefaultRule::default()
            },
            Action::Route {
                outbound: String::new(),
                options: ConnectionOverride::default(),
            },
            Vec::new(),
        )?;
        Ok(Self {
            query_type,
            base,
            network_interface_prefixes,
            default_interface_prefixes,
            adguard_regex,
            compact_domain,
            compact_adguard,
        })
    }

    fn matches(
        &self,
        metadata: &Metadata,
        ip_cidr_match_source: bool,
        ip_cidr_accept_empty: bool,
    ) -> bool {
        self.evaluate(metadata, ip_cidr_match_source, ip_cidr_accept_empty)
            .done()
            != self.base.raw.invert
    }

    fn evaluate(
        &self,
        metadata: &Metadata,
        ip_cidr_match_source: bool,
        ip_cidr_accept_empty: bool,
    ) -> RuleMatch {
        let mut evaluated = self.base.evaluate_with_ip_source_and_empty(
            metadata,
            ip_cidr_match_source,
            ip_cidr_accept_empty,
        );
        evaluated.ordinary &=
            matches_optional(&self.query_type, metadata.query_type)
                && matches_interface_prefixes(
                    &self.network_interface_prefixes,
                    &metadata.network_interface_address,
                )
                && matches_any_prefix(
                    &self.default_interface_prefixes,
                    &metadata.default_interface_address,
                );
        if !self.adguard_regex.is_empty() {
            evaluated.required |= MATCH_DESTINATION_ADDRESS;
            if metadata.domain().is_some_and(|domain| {
                self.adguard_regex
                    .iter()
                    .any(|pattern| pattern.is_match(domain))
            }) {
                evaluated.satisfied |= MATCH_DESTINATION_ADDRESS;
            }
        }
        if let Some(matcher) = &self.compact_domain {
            evaluated.required |= MATCH_DESTINATION_ADDRESS;
            if metadata.domain().is_some_and(|domain| {
                matcher.matches_domain(
                    &domain.trim_end_matches('.').to_ascii_lowercase(),
                )
            }) {
                evaluated.satisfied |= MATCH_DESTINATION_ADDRESS;
            }
        }
        if let Some(matcher) = &self.compact_adguard {
            evaluated.required |= MATCH_DESTINATION_ADDRESS;
            if metadata.domain().is_some_and(|domain| {
                matcher.matches_adguard(
                    &domain.trim_end_matches('.').to_ascii_lowercase(),
                )
            }) {
                evaluated.satisfied |= MATCH_DESTINATION_ADDRESS;
            }
        }
        evaluated
    }
}

impl RawHeadlessRule {
    fn has_matcher(&self) -> bool {
        !self.query_type.as_slice().is_empty()
            || !self.network.as_slice().is_empty()
            || !self.domain.as_slice().is_empty()
            || !self.domain_suffix.as_slice().is_empty()
            || !self.domain_keyword.as_slice().is_empty()
            || !self.domain_regex.as_slice().is_empty()
            || !self.adguard_domain.as_slice().is_empty()
            || !self.source_ip_cidr.as_slice().is_empty()
            || !self.ip_cidr.as_slice().is_empty()
            || !self.source_port.as_slice().is_empty()
            || !self.source_port_range.as_slice().is_empty()
            || !self.port.as_slice().is_empty()
            || !self.port_range.as_slice().is_empty()
            || !self.process_name.as_slice().is_empty()
            || !self.process_path.as_slice().is_empty()
            || !self.process_path_regex.as_slice().is_empty()
            || !self.package_name.as_slice().is_empty()
            || !self.package_name_regex.as_slice().is_empty()
            || !self.network_type.as_slice().is_empty()
            || self.network_is_expensive
            || self.network_is_constrained
            || !self.wifi_ssid.as_slice().is_empty()
            || !self.wifi_bssid.as_slice().is_empty()
            || !self.network_interface_address.is_empty()
            || !self.default_interface_address.as_slice().is_empty()
    }
}

fn compile_rule_sets(
    configs: &[Value],
    base_path: &Path,
    persistent_cache: Option<Arc<PersistentDnsCache>>,
) -> Result<HashMap<String, Arc<RuleSet>>, RouteError> {
    let mut compiled = HashMap::new();
    for (index, config) in configs.iter().enumerate() {
        let object = config.as_object().ok_or_else(|| {
            RouteError::InvalidRuleSet(format!(
                "rule_set[{index}] is not an object"
            ))
        })?;
        let kind = object.get("type").and_then(Value::as_str).unwrap_or("");
        let tags: Listable<String> = object
            .get("tag")
            .cloned()
            .ok_or_else(|| {
                RouteError::InvalidRuleSet(format!(
                    "rule_set[{index}] missing tag"
                ))
            })
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| {
                    RouteError::InvalidRuleSet(format!(
                        "rule_set[{index}] invalid tag: {error}"
                    ))
                })
            })?;
        if tags.as_slice().is_empty()
            || tags.as_slice().iter().any(String::is_empty)
        {
            return Err(RouteError::InvalidRuleSet(format!(
                "rule_set[{index}] missing tag"
            )));
        }
        match kind {
            "" | "inline" => {
                validate_rule_set_keys(
                    object,
                    &["type", "tag", "rules"],
                    index,
                )?;
                if tags.as_slice().len() != 1 {
                    return Err(RouteError::InvalidRuleSet(
                        "inline rule-set does not support multiple tags".into(),
                    ));
                }
                let rules = object
                    .get("rules")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        RouteError::InvalidRuleSet(format!(
                            "rule_set[{index}] has no rules array"
                        ))
                    })?;
                if rules.is_empty() {
                    return Err(RouteError::InvalidRuleSet(
                        "empty inline rule-set".into(),
                    ));
                }
                insert_rule_set(
                    &mut compiled,
                    tags.as_slice()[0].clone(),
                    compile_headless_rules(rules)?,
                    RuleSetSource::Static,
                )?;
            }
            "local" => {
                validate_rule_set_keys(
                    object,
                    &["type", "tag", "format", "path"],
                    index,
                )?;
                let path =
                    object.get("path").and_then(Value::as_str).unwrap_or("");
                if path.is_empty() {
                    return Err(RouteError::InvalidRuleSet(format!(
                        "rule_set[{index}] missing path"
                    )));
                }
                if tags.as_slice().len() > 1 && !path.contains("{tag}") {
                    return Err(RouteError::InvalidRuleSet(
                        "missing {tag} placeholder in path".into(),
                    ));
                }
                let configured_format =
                    object.get("format").and_then(Value::as_str).unwrap_or("");
                for tag in tags.as_slice() {
                    let tag_path = path.replace("{tag}", tag);
                    let format = if configured_format.is_empty() {
                        infer_rule_set_format(&tag_path)
                    } else {
                        configured_format
                    };
                    let path = resolve_rule_set_path(base_path, &tag_path);
                    let rules = match format {
                        "source" => load_source_rule_set(&path)?,
                        "binary" => load_binary_rule_set(&path)?,
                        "" => {
                            return Err(RouteError::InvalidRuleSet(format!(
                                "missing format for rule-set {tag:?}"
                            )));
                        }
                        other => {
                            return Err(RouteError::InvalidRuleSet(format!(
                                "unknown rule-set format: {other}"
                            )));
                        }
                    };
                    let modified = fs::metadata(&path)
                        .and_then(|metadata| metadata.modified())
                        .ok();
                    insert_rule_set(
                        &mut compiled,
                        tag.clone(),
                        rules,
                        RuleSetSource::Local {
                            path,
                            format: format.to_owned(),
                            modified: Mutex::new(modified),
                        },
                    )?;
                }
            }
            "remote" => {
                validate_rule_set_keys(
                    object,
                    &[
                        "type",
                        "tag",
                        "format",
                        "url",
                        "initial_path",
                        "http_client",
                        "update_interval",
                        "download_detour",
                    ],
                    index,
                )?;
                let url =
                    object.get("url").and_then(Value::as_str).unwrap_or("");
                if url.is_empty() {
                    return Err(RouteError::InvalidRuleSet(format!(
                        "rule_set[{index}] missing url"
                    )));
                }
                let initial_path = object
                    .get("initial_path")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if tags.as_slice().len() > 1 {
                    if !url.contains("{tag}") {
                        return Err(RouteError::InvalidRuleSet(
                            "missing {tag} placeholder in url".into(),
                        ));
                    }
                    if !initial_path.is_empty()
                        && !initial_path.contains("{tag}")
                    {
                        return Err(RouteError::InvalidRuleSet(
                            "missing {tag} placeholder in initial_path".into(),
                        ));
                    }
                }
                let http_client = object
                    .get("http_client")
                    .cloned()
                    .map(serde_json::from_value::<HttpClientReference>)
                    .transpose()
                    .map_err(|error| {
                        RouteError::InvalidRuleSet(format!(
                            "invalid http_client for rule-set {index}: {error}"
                        ))
                    })?;
                if http_client
                    .as_ref()
                    .is_some_and(|client| !http_client_is_empty(client))
                    && object
                        .get("download_detour")
                        .and_then(Value::as_str)
                        .is_some_and(|detour| !detour.is_empty())
                {
                    return Err(RouteError::InvalidRuleSet(
                        "http_client is conflict with deprecated download_detour field"
                            .into(),
                    ));
                }
                let download_detour = object
                    .get("download_detour")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let update_interval = object
                    .get("update_interval")
                    .cloned()
                    .map(serde_json::from_value::<ConfigDuration>)
                    .transpose()
                    .map_err(|error| {
                        RouteError::InvalidRuleSet(format!(
                            "invalid update_interval: {error}"
                        ))
                    })?
                    .and_then(ConfigDuration::as_std)
                    .filter(|interval| !interval.is_zero())
                    .unwrap_or_else(|| StdDuration::from_secs(24 * 60 * 60));
                let configured_format =
                    object.get("format").and_then(Value::as_str).unwrap_or("");
                for tag in tags.as_slice() {
                    let url = url.replace("{tag}", tag);
                    let format = if configured_format.is_empty() {
                        infer_rule_set_format(&url)
                    } else {
                        configured_format
                    };
                    if !matches!(format, "source" | "binary") {
                        return Err(RouteError::InvalidRuleSet(format!(
                            "missing or unknown format for rule-set {tag:?}: {format}"
                        )));
                    }
                    let initial_path = if initial_path.is_empty() {
                        None
                    } else {
                        Some(resolve_rule_set_path(
                            base_path,
                            &initial_path.replace("{tag}", tag),
                        ))
                    };
                    let url_hash = Sha256::digest(url.as_bytes()).to_vec();
                    let cached = persistent_cache
                        .as_ref()
                        .and_then(|cache| {
                            cache.load_rule_set(tag).ok().flatten()
                        })
                        .filter(|saved| {
                            saved.url_hash.is_empty()
                                || saved.url_hash == url_hash
                        });
                    let mut rules = Vec::new();
                    let mut cached_content = Vec::new();
                    let mut etag = String::new();
                    let mut last_updated = None;
                    if let Some(saved) = cached
                        && let Ok(decoded) =
                            decode_rule_set(format, &saved.content, &url)
                    {
                        rules = decoded;
                        cached_content = saved.content;
                        etag = saved.etag;
                        last_updated = Some(saved.last_updated);
                    }
                    insert_rule_set(
                        &mut compiled,
                        tag.clone(),
                        rules,
                        RuleSetSource::Remote(Box::new(RemoteRuleSetSource {
                            url,
                            initial_path,
                            format: format.to_owned(),
                            update_interval,
                            etag: Mutex::new(etag),
                            cache: persistent_cache.clone(),
                            url_hash,
                            cached_content: Mutex::new(cached_content),
                            last_updated: Mutex::new(last_updated),
                            http_client: http_client.clone(),
                            download_detour: download_detour.clone(),
                            download_client: Mutex::new(None),
                        })),
                    )?;
                }
            }
            other => {
                return Err(RouteError::InvalidRuleSet(format!(
                    "unknown rule-set type: {other}"
                )));
            }
        }
    }
    Ok(compiled)
}

fn validate_rule_set_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    index: usize,
) -> Result<(), RouteError> {
    if let Some(key) =
        object.keys().find(|key| !allowed.contains(&key.as_str()))
    {
        return Err(RouteError::InvalidRuleSet(format!(
            "rule_set[{index}] has invalid field {key:?}"
        )));
    }
    Ok(())
}

fn http_client_is_empty(client: &HttpClientReference) -> bool {
    match client {
        HttpClientReference::Tag(tag) => tag.is_empty(),
        HttpClientReference::Inline(options) => options.is_empty(),
    }
}

fn insert_rule_set(
    registry: &mut HashMap<String, Arc<RuleSet>>,
    tag: String,
    rules: Vec<HeadlessRule>,
    source: RuleSetSource,
) -> Result<(), RouteError> {
    let metadata = rule_set_metadata(&rules);
    let initial_update = RuleSetUpdate {
        generation: 0,
        metadata,
    };
    let (updates, _) = watch::channel(initial_update);
    let rule_set = Arc::new(RuleSet {
        tag: tag.clone(),
        state: RwLock::new(RuleSetState {
            rules,
            metadata,
            generation: 0,
        }),
        updates,
        update_validators: RwLock::new(Vec::new()),
        source,
        task: Mutex::new(None),
    });
    if registry.insert(tag.clone(), rule_set).is_some() {
        return Err(RouteError::InvalidRuleSet(format!(
            "duplicate rule-set tag: {tag}"
        )));
    }
    Ok(())
}

fn compile_headless_rules(
    rules: &[Value],
) -> Result<Vec<HeadlessRule>, RouteError> {
    rules
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            HeadlessRule::compile(rule, 0).map_err(|error| {
                RouteError::InvalidRuleSet(format!(
                    "parse rule_set.rules.[{index}]: {error}"
                ))
            })
        })
        .collect()
}

fn compile_runtime_rules(
    rules: Vec<srs::RuntimeRule>,
) -> Result<Vec<HeadlessRule>, RouteError> {
    rules
        .into_iter()
        .enumerate()
        .map(|(index, rule)| {
            compile_runtime_rule(rule, 0).map_err(|error| {
                RouteError::InvalidRuleSet(format!(
                    "parse rule_set.rules.[{index}]: {error}"
                ))
            })
        })
        .collect()
}

fn compile_runtime_rule(
    rule: srs::RuntimeRule,
    depth: usize,
) -> Result<HeadlessRule, RouteError> {
    if depth > 100 {
        return Err(RouteError::InvalidRuleSet(
            "logical rule nested too deep".into(),
        ));
    }
    match rule {
        srs::RuntimeRule::Default(rule) => {
            let srs::RuntimeDefaultRule {
                value,
                domain,
                adguard,
            } = *rule;
            Ok(HeadlessRule::Default(Box::new(
                HeadlessDefaultRule::compile_with_matchers(
                    &value, domain, adguard,
                )?,
            )))
        }
        srs::RuntimeRule::Logical {
            mode,
            rules,
            invert,
        } => {
            if rules.is_empty() {
                return Err(RouteError::InvalidRuleSet(
                    "logical headless rule has no child rules".into(),
                ));
            }
            let mode = match mode {
                srs::RuntimeLogicalMode::And => LogicalMode::And,
                srs::RuntimeLogicalMode::Or => LogicalMode::Or,
            };
            Ok(HeadlessRule::Logical(HeadlessLogicalRule {
                mode,
                rules: rules
                    .into_iter()
                    .map(|rule| compile_runtime_rule(rule, depth + 1))
                    .collect::<Result<_, _>>()?,
                invert,
            }))
        }
    }
}

fn load_source_rule_set(path: &Path) -> Result<Vec<HeadlessRule>, RouteError> {
    let content = fs::read(path).map_err(|source| RouteError::ReadRuleSet {
        path: path.to_owned(),
        source,
    })?;
    decode_rule_set("source", &content, &path.display().to_string())
}

fn decode_rule_set(
    format: &str,
    content: &[u8],
    source_name: &str,
) -> Result<Vec<HeadlessRule>, RouteError> {
    match format {
        "source" => decode_source_rule_set(content, source_name),
        "binary" => {
            let rules = srs::read_runtime(content).map_err(|error| {
                RouteError::InvalidRuleSet(format!(
                    "decode rule-set at {source_name}: {error}"
                ))
            })?;
            compile_runtime_rules(rules)
        }
        other => Err(RouteError::InvalidRuleSet(format!(
            "unknown rule-set format: {other}"
        ))),
    }
}

fn decode_source_rule_set(
    content: &[u8],
    source_name: &str,
) -> Result<Vec<HeadlessRule>, RouteError> {
    let source = parse_source_rule_set(content, source_name)?;
    let rules = headless_rule_values(&source.rules)?;
    compile_headless_rules(&rules)
}

fn parse_source_rule_set(
    content: &[u8],
    source_name: &str,
) -> Result<SourceRuleSet, RouteError> {
    let content = std::str::from_utf8(content).map_err(|error| {
        RouteError::InvalidRuleSet(format!(
            "decode rule-set at {source_name}: {error}"
        ))
    })?;
    let clean = strip_comments(content)
        .map_err(|error| RouteError::InvalidRuleSet(error.to_string()))?;
    let source: SourceRuleSet =
        serde_json::from_str(&clean).map_err(|error| {
            RouteError::InvalidRuleSet(format!(
                "decode rule-set at {source_name}: {error}"
            ))
        })?;
    validate_source_rule_set(&source)?;
    Ok(source)
}

fn validate_source_rule_set(source: &SourceRuleSet) -> Result<(), RouteError> {
    if !(1..=5).contains(&source.version) {
        return Err(RouteError::InvalidRuleSet(format!(
            "unknown rule-set version: {}",
            source.version
        )));
    }
    let rules = headless_rule_values(&source.rules)?;
    compile_headless_rules(&rules)?;
    Ok(())
}

fn headless_rule_values(
    rules: &[HeadlessRuleOptions],
) -> Result<Vec<Value>, RouteError> {
    rules
        .iter()
        .map(|rule| {
            rule.to_value()
                .map_err(|error| RouteError::InvalidRuleSet(error.to_string()))
        })
        .collect()
}

fn load_binary_rule_set(path: &Path) -> Result<Vec<HeadlessRule>, RouteError> {
    let content = fs::read(path).map_err(|source| RouteError::ReadRuleSet {
        path: path.to_owned(),
        source,
    })?;
    decode_rule_set("binary", &content, &path.display().to_string())
}

fn infer_rule_set_format(path: &str) -> &'static str {
    let path = url::Url::parse(path)
        .ok()
        .map(|url| url.path().to_owned())
        .unwrap_or_else(|| path.to_owned());
    match Path::new(&path)
        .extension()
        .and_then(|value| value.to_str())
    {
        Some("json") => "source",
        Some("srs") => "binary",
        _ => "",
    }
}

fn describe_rule(value: &Value) -> String {
    let Some(object) = value.as_object() else {
        return String::new();
    };
    let mut description = if object
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind == "logical")
    {
        let separator =
            if object.get("mode").and_then(Value::as_str) == Some("and") {
                " && "
            } else {
                " || "
            };
        object
            .get("rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(describe_rule)
            .collect::<Vec<_>>()
            .join(separator)
    } else {
        const MATCHERS: &[&str] = &[
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
        ];
        MATCHERS
            .iter()
            .filter_map(|key| object.get(*key).map(|value| (*key, value)))
            .filter_map(|(key, value)| describe_matcher(key, value))
            .collect::<Vec<_>>()
            .join(" ")
    };
    if object.get("invert").and_then(Value::as_bool) == Some(true) {
        description = format!("!({description})");
    }
    description
}

fn describe_matcher(key: &str, value: &Value) -> Option<String> {
    match value {
        Value::Bool(true) => Some(key.to_owned()),
        Value::Bool(false) | Value::Null => None,
        Value::Array(values) if values.is_empty() => None,
        Value::Array(values) if values.len() == 1 => {
            Some(format!("{key}={}", display_json_scalar(&values[0])))
        }
        Value::Array(values) => Some(format!(
            "{key}=[{}]",
            values
                .iter()
                .take(3)
                .map(display_json_scalar)
                .chain((values.len() > 3).then_some("...".to_owned()))
                .collect::<Vec<_>>()
                .join(" ")
        )),
        _ => Some(format!("{key}={}", display_json_scalar(value))),
    }
}

fn display_json_scalar(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn format_hardware_address(address: &[u8]) -> String {
    address
        .iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub(crate) fn describe_action(action: Option<&Action>) -> String {
    match action {
        Some(Action::Route { outbound, .. }) => format!("route({outbound})"),
        Some(Action::RouteOptions(_)) => "route-options()".into(),
        Some(Action::Direct) | Some(Action::DirectOptions { .. }) => {
            "direct".into()
        }
        Some(Action::Bypass { outbound, .. }) if outbound.is_empty() => {
            "bypass()".into()
        }
        Some(Action::Bypass { outbound, .. }) => {
            format!("bypass({outbound})")
        }
        Some(Action::Reject { method, .. }) if method == "default" => {
            "reject".into()
        }
        Some(Action::Reject { method, .. }) => format!("reject({method})"),
        Some(Action::HijackDns) => "hijack-dns".into(),
        Some(Action::Sniff(_)) => "sniff".into(),
        Some(Action::Resolve(_)) => "resolve".into(),
        None => String::new(),
    }
}

fn resolve_rule_set_path(base_path: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_owned()
    } else {
        base_path.join(path)
    }
}

pub struct Router {
    rules: Vec<Rule>,
    raw_rules: Vec<Value>,
    rule_sets: HashMap<String, Arc<RuleSet>>,
    final_outbound: String,
    clash_mode: RwLock<Option<String>>,
    clash_modes: Vec<String>,
    preferred_outbounds: Option<std::sync::Weak<OutboundManager>>,
    neighbor_resolver: Option<Arc<dyn NeighborResolver>>,
    process_resolver: Option<Arc<dyn ProcessResolver>>,
    flow_logger: Option<Logger>,
}

impl fmt::Debug for Router {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Router")
            .field("rules", &self.rules)
            .field("raw_rules", &self.raw_rules)
            .field("rule_sets", &self.rule_sets)
            .field("final_outbound", &self.final_outbound)
            .field("clash_modes", &self.clash_modes)
            .field(
                "has_preferred_outbounds",
                &self.preferred_outbounds.is_some(),
            )
            .field("has_neighbor_resolver", &self.neighbor_resolver.is_some())
            .field("has_process_resolver", &self.process_resolver.is_some())
            .field("has_flow_logger", &self.flow_logger.is_some())
            .finish_non_exhaustive()
    }
}

impl Router {
    pub fn from_json(
        rules: &[Value],
        final_outbound: impl Into<String>,
    ) -> Result<Self, RouteError> {
        Self::from_json_with_rule_sets(
            rules,
            final_outbound,
            &[],
            Path::new("."),
        )
    }

    pub fn from_json_with_rule_sets(
        rules: &[Value],
        final_outbound: impl Into<String>,
        rule_sets: &[Value],
        base_path: &Path,
    ) -> Result<Self, RouteError> {
        Self::from_json_with_rule_sets_and_cache(
            rules,
            final_outbound,
            rule_sets,
            base_path,
            None,
        )
    }

    pub(crate) fn from_json_with_rule_sets_and_cache(
        rules: &[Value],
        final_outbound: impl Into<String>,
        rule_sets: &[Value],
        base_path: &Path,
        persistent_cache: Option<Arc<PersistentDnsCache>>,
    ) -> Result<Self, RouteError> {
        let rule_sets =
            compile_rule_sets(rule_sets, base_path, persistent_cache)?;
        Ok(Self {
            raw_rules: rules.to_vec(),
            rules: rules
                .iter()
                .map(|rule| Rule::compile(rule, &rule_sets))
                .collect::<Result<_, _>>()?,
            rule_sets,
            final_outbound: final_outbound.into(),
            clash_mode: RwLock::new(None),
            clash_modes: Vec::new(),
            preferred_outbounds: None,
            neighbor_resolver: None,
            process_resolver: None,
            flow_logger: None,
        })
    }

    pub(crate) fn configure_flow_logger(&mut self, logger: Logger) {
        self.flow_logger = Some(logger);
    }

    /// Emit one structured observation for a routed flow.  Domain provenance
    /// matters here: payload/FakeIP evidence is exact, while a DNS reverse
    /// mapping is deliberately labelled as correlation because an IP can be
    /// shared by many unrelated hostnames.
    pub(crate) fn observe_flow(
        &self,
        metadata: &Metadata,
        decision: &RouteDecision<'_>,
    ) {
        let Some(logger) = &self.flow_logger else {
            return;
        };
        if matches!(decision.action(), Some(Action::HijackDns)) {
            return;
        }

        let had_runtime_domain = !metadata.domain.is_empty();
        let current = self.enriched_flow_metadata(metadata);
        let destination = metadata.destination.as_ref();
        let domain = current
            .domain()
            .map(|domain| domain.trim_end_matches('.').to_ascii_lowercase());
        let (domain_source, domain_confidence) =
            if metadata.fake_ip && domain.is_some() {
                ("fakeip", "exact")
            } else if had_runtime_domain && !metadata.protocol.is_empty() {
                ("sniff", "exact")
            } else if destination.is_some_and(SocksAddr::is_domain) {
                ("destination", "exact")
            } else if had_runtime_domain {
                ("resolved", "exact")
            } else if domain.is_some() {
                ("dns_reverse", "correlated")
            } else {
                ("none", "none")
            };
        let outbound = match decision.action() {
            Some(Action::Direct) | Some(Action::DirectOptions { .. }) => {
                "direct"
            }
            Some(Action::Reject { .. }) => "reject",
            _ => decision.outbound().unwrap_or("direct"),
        };
        let routed_destination = destination
            .map(|destination| decision.destination(destination).to_string())
            .unwrap_or_default();
        let event = serde_json::json!({
            "event": "flow",
            "network": current.network.map(Network::as_str).unwrap_or(""),
            "inbound": current.inbound,
            "source": current.source.as_ref().map(ToString::to_string).unwrap_or_default(),
            "destination": destination.map(ToString::to_string).unwrap_or_default(),
            "original_destination": current.origin_destination.as_ref().map(ToString::to_string).unwrap_or_default(),
            "routed_destination": routed_destination,
            "domain": domain.unwrap_or_default(),
            "domain_source": domain_source,
            "domain_confidence": domain_confidence,
            "protocol": current.protocol,
            "rule": describe_action(decision.action()),
            "outbound": outbound,
            "process_name": current.process_name,
            "process_path": current.process_path,
            "process_lookup": current.process_lookup,
        });
        let _ = logger.info(event.to_string());
    }

    /// Resolve process and domain attribution for diagnostics and optional
    /// per-process traffic accounting without mutating routing metadata.
    pub(crate) fn enriched_flow_metadata(
        &self,
        metadata: &Metadata,
    ) -> Metadata {
        let mut current = metadata.clone();
        self.apply_runtime_metadata(&mut current, false);
        current
    }

    pub(crate) fn configure_preferred_outbounds(
        &mut self,
        outbounds: &Arc<OutboundManager>,
    ) {
        self.preferred_outbounds = Some(Arc::downgrade(outbounds));
    }

    pub(crate) fn validate_preferred_outbounds(
        &self,
        outbounds: &OutboundManager,
    ) -> Result<(), RouteError> {
        let mut tags = Vec::new();
        for rule in &self.rules {
            rule.collect_preferred_by(&mut tags);
        }
        for tag in tags {
            let kind = outbounds.kind_owned(tag).ok_or_else(|| {
                RouteError::InvalidRule(format!("outbound not found: {tag}"))
            })?;
            if !matches!(
                kind.as_str(),
                "bridge"
                    | "wireguard"
                    | "openvpn-client"
                    | "openconnect"
                    | "tailscale"
            ) {
                return Err(RouteError::InvalidRule(format!(
                    "outbound type does not support preferred routes: {kind}"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn configure_neighbor_resolver(
        &mut self,
        resolver: Option<Arc<dyn NeighborResolver>>,
    ) {
        self.neighbor_resolver = resolver;
    }

    pub(crate) fn configure_process_resolver(
        &mut self,
        resolver: Option<Arc<dyn ProcessResolver>>,
    ) {
        self.process_resolver = resolver;
    }

    /// Resolve a local socket owner at the earliest point an endpoint sees a
    /// flow. Userspace TUN endpoints call this for the initial TCP SYN so a
    /// process that exits immediately after connect cannot disappear before
    /// normal route evaluation begins.
    pub(crate) fn lookup_process_owner(
        &self,
        network: Network,
        source: std::net::SocketAddr,
        destination: Option<std::net::SocketAddr>,
    ) -> ProcessLookupResult {
        self.process_resolver
            .as_ref()
            .map(|resolver| {
                resolver.lookup_detailed(network, source, destination)
            })
            .unwrap_or(ProcessLookupResult {
                process: None,
                status: ProcessLookupStatus::SocketSnapshotMiss,
            })
    }

    /// Build one direct dialer per configured direct rule action.
    ///
    /// Upstream constructs these dialers while compiling rules. Rust builds
    /// the router before the outbound registry, so Runtime performs this one
    /// explicit linking step before publishing either object through `Arc`.
    pub(crate) fn configure_direct_actions(
        &mut self,
        outbounds: &mut OutboundManager,
    ) -> Result<(), RouteError> {
        for (index, rule) in self.rules.iter_mut().enumerate() {
            let options = match rule.action_mut() {
                Action::Direct => AbstractDialerOptions::default(),
                Action::DirectOptions { options, .. } => options.clone(),
                _ => continue,
            };
            let internal_tag = format!("\0route-direct/{index}");
            outbounds
                .register_route_direct(&internal_tag, &options)
                .map_err(|error| {
                    RouteError::InvalidRule(format!(
                        "configure direct action at rule {index}: {error}"
                    ))
                })?;
            *rule.action_mut() = Action::DirectOptions {
                options,
                outbound: internal_tag,
            };
        }
        Ok(())
    }

    pub fn configure_clash_mode(
        &mut self,
        current: String,
        modes: Vec<String>,
    ) {
        self.clash_modes = modes;
        *self.clash_mode.write().expect("clash mode lock poisoned") =
            Some(current);
    }

    pub fn clash_mode(&self) -> Option<String> {
        self.clash_mode
            .read()
            .expect("clash mode lock poisoned")
            .clone()
    }

    pub fn clash_modes(&self) -> &[String] {
        &self.clash_modes
    }

    pub fn set_clash_mode(&self, mode: &str) -> bool {
        let Some(mode) = self
            .clash_modes
            .iter()
            .find(|candidate| candidate.eq_ignore_ascii_case(mode))
        else {
            return false;
        };
        let mut current =
            self.clash_mode.write().expect("clash mode lock poisoned");
        if current.as_deref() == Some(mode) {
            return true;
        }
        *current = Some(mode.clone());
        true
    }

    fn apply_runtime_metadata(&self, metadata: &mut Metadata, pre_match: bool) {
        if let Some(address) = metadata.destination_ip() {
            metadata.ip_version = Some(if address.is_ipv4() { 4 } else { 6 });
        }
        if let Some(mode) = self.clash_mode() {
            metadata.clash_mode = mode;
        }
        if let Some(outbounds) = self
            .preferred_outbounds
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            if metadata.domain.is_empty()
                && !metadata.fake_ip
                && let Some(address) = metadata.destination_ip()
                && let Some(domain) =
                    outbounds.dns().lookup_reverse_mapping(address)
            {
                metadata.domain = domain;
            }
            outbounds.populate_preferred_by(metadata, pre_match);
        }
        if let Some(resolver) = &self.neighbor_resolver
            && let Some(address) = metadata.source_ip()
        {
            if metadata.source_mac_address.is_empty()
                && let Some(mac) = resolver.lookup_mac(address)
            {
                metadata.source_mac_address = format_hardware_address(&mac);
            }
            if metadata.source_hostname.is_empty()
                && let Some(hostname) = resolver.lookup_hostname(address)
            {
                metadata.source_hostname = hostname;
            }
        }
        if let Some(resolver) = &self.process_resolver
            && let Some(network) = metadata.network
            && let Some(source) =
                metadata.source.as_ref().and_then(|address| match address {
                    SocksAddr::Ip(address) => Some(*address),
                    SocksAddr::Domain { .. } => None,
                })
            && metadata.process_name.is_empty()
            && metadata.process_path.is_empty()
            && metadata.package_name.is_empty()
            && metadata.user.is_empty()
            && metadata.user_id.is_none()
        {
            let destination = metadata
                .process_origin_destination
                .as_ref()
                .and_then(|address| match address {
                    SocksAddr::Ip(address) => Some(*address),
                    SocksAddr::Domain { .. } => None,
                })
                .or_else(|| {
                    metadata.origin_destination.as_ref().and_then(|address| {
                        match address {
                            SocksAddr::Ip(address) => Some(*address),
                            SocksAddr::Domain { .. } => None,
                        }
                    })
                })
                .or_else(|| {
                    metadata.destination.as_ref().and_then(|address| {
                        match address {
                            SocksAddr::Ip(address) => Some(*address),
                            SocksAddr::Domain { .. } => None,
                        }
                    })
                });
            let lookup = resolver.lookup_detailed(network, source, destination);
            metadata.process_lookup = lookup.status.as_str().to_string();
            if let Some(process) = lookup.process {
                metadata.process_name = process.process_name;
                metadata.process_path = process.process_path;
                metadata.package_name = process.package_name;
                metadata.user = process.user;
                metadata.user_id = process.user_id;
            }
        }
    }

    fn refresh_preferred_by(&self, metadata: &mut Metadata, pre_match: bool) {
        if let Some(outbounds) = self
            .preferred_outbounds
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            outbounds.populate_preferred_by(metadata, pre_match);
        }
    }

    pub fn rule_set_tags(&self) -> impl Iterator<Item = &str> {
        self.rule_sets.keys().map(String::as_str)
    }

    /// Return a shared rule-set handle for metadata inspection and update
    /// subscription by an embedding host.
    pub fn rule_set(&self, tag: &str) -> Option<Arc<RuleSet>> {
        self.rule_sets.get(tag).cloned()
    }

    pub(crate) fn has_rule_set(&self, tag: &str) -> bool {
        self.rule_sets.contains_key(tag)
    }

    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux", test)),
        allow(dead_code)
    )]
    pub(crate) fn rule_set_destination_prefixes(
        &self,
        tags: &[String],
    ) -> Result<Vec<IpNet>, RouteError> {
        let mut prefixes = Vec::new();
        for tag in tags {
            let rule_set = self.rule_sets.get(tag).ok_or_else(|| {
                RouteError::InvalidRuleSet(format!("rule-set not found: {tag}"))
            })?;
            prefixes.extend(rule_set.destination_prefixes());
        }
        Ok(prefixes)
    }

    pub(crate) fn matches_rule_sets_with_destination_outer(
        &self,
        tags: &[String],
        metadata: &Metadata,
        ip_cidr_match_source: bool,
        destination_required: bool,
        destination_satisfied: bool,
        ip_cidr_accept_empty: bool,
    ) -> bool {
        tags.iter().any(|tag| {
            self.rule_sets.get(tag).is_some_and(|rule_set| {
                rule_set.matches_with_outer_accept_empty(
                    metadata,
                    RuleMatch {
                        ordinary: true,
                        required: if destination_required {
                            MATCH_DESTINATION_ADDRESS
                        } else {
                            0
                        },
                        satisfied: if destination_required
                            && destination_satisfied
                        {
                            MATCH_DESTINATION_ADDRESS
                        } else {
                            0
                        },
                    },
                    ip_cidr_match_source,
                    ip_cidr_accept_empty,
                )
            })
        })
    }

    pub(crate) fn rule_sets_legacy_match_possibility(
        &self,
        tags: &[String],
        metadata: &Metadata,
        ip_cidr_match_source: bool,
        destination_required: bool,
        destination_can_match: bool,
        destination_can_miss: bool,
    ) -> (bool, bool) {
        let matched_without_unknown = self
            .matches_rule_sets_with_destination_outer(
                tags,
                metadata,
                ip_cidr_match_source,
                destination_required,
                !destination_can_miss,
                false,
            );
        if matched_without_unknown || ip_cidr_match_source {
            return (matched_without_unknown, !matched_without_unknown);
        }
        let matched_if_destination_matches = destination_can_match
            && self.matches_rule_sets_with_destination_outer(
                tags,
                metadata,
                ip_cidr_match_source,
                destination_required,
                true,
                false,
            );
        let can_match_after_response = tags.iter().any(|tag| {
            self.rule_sets.get(tag).is_some_and(|rule_set| {
                rule_set.metadata().contains_ip_cidr_rule
            })
        });
        (
            matched_if_destination_matches || can_match_after_response,
            true,
        )
    }

    pub(crate) fn rule_sets_contain_destination_ip(
        &self,
        tags: &[String],
    ) -> bool {
        tags.iter().any(|tag| {
            self.rule_sets.get(tag).is_some_and(|rule_set| {
                rule_set.metadata().contains_ip_cidr_rule
            })
        })
    }

    pub(crate) fn matches_rule_sets_legacy_response(
        &self,
        tags: &[String],
        metadata: &Metadata,
        ip_cidr_match_source: bool,
        ip_cidr_accept_empty: bool,
        destination_required: bool,
        destination_satisfied: bool,
    ) -> bool {
        self.matches_rule_sets_with_destination_outer(
            tags,
            metadata,
            ip_cidr_match_source,
            destination_required,
            destination_satisfied,
            ip_cidr_accept_empty,
        )
    }

    pub(crate) fn configure_rule_set_http_clients(
        &self,
        outbounds: &OutboundManager,
        clients: &[HttpClient],
        default_client: &str,
        ntp_clock: Option<crate::common::ntp::NtpClock>,
        certificate_store: Option<
            crate::common::certificate_store::CertificateStore,
        >,
    ) -> Result<(), RouteError> {
        let first_client = clients.first().map(|client| client.tag.as_str());
        let clients: HashMap<_, _> = clients
            .iter()
            .map(|client| (client.tag.as_str(), &client.options))
            .collect();
        let default_client = if default_client.is_empty() {
            first_client.unwrap_or("")
        } else {
            default_client
        };
        for rule_set in self.rule_sets.values() {
            let RuleSetSource::Remote(source) = &rule_set.source else {
                continue;
            };
            let explicit = source
                .http_client
                .as_ref()
                .filter(|client| !http_client_is_empty(client));
            let (mut client_options, default_outbound) = if let Some(client) =
                explicit
            {
                match client {
                    HttpClientReference::Tag(tag) => (
                        clients
                            .get(tag.as_str())
                            .copied()
                            .cloned()
                            .ok_or_else(|| {
                                RouteError::InvalidRuleSet(format!(
                                    "http_client not found: {tag}"
                                ))
                            })?,
                        false,
                    ),
                    HttpClientReference::Inline(options) => {
                        (options.as_ref().clone(), false)
                    }
                }
            } else if !source.download_detour.is_empty() {
                let mut options = HttpClientOptions::default();
                options.dialer.detour = source.download_detour.clone();
                (options, false)
            } else if !default_client.is_empty() {
                (
                    clients
                        .get(default_client)
                        .copied()
                        .cloned()
                        .ok_or_else(|| {
                            RouteError::InvalidRuleSet(format!(
                                "default http_client not found: {default_client}"
                            ))
                        })?,
                    false,
                )
            } else {
                (HttpClientOptions::default(), true)
            };
            client_options
                .tls
                .get_or_insert_with(Default::default)
                .set_runtime_context(
                    ntp_clock.clone(),
                    certificate_store.clone(),
                );
            let dialer = outbounds
                .http_client_dialer_with_options(
                    &client_options.dialer,
                    default_outbound,
                    !source.download_detour.is_empty(),
                )
                .map_err(|error| {
                    RouteError::InvalidRuleSet(format!(
                        "configure HTTP client for rule-set {:?}: {error}",
                        rule_set.tag
                    ))
                })?;
            let client = DownloadClient::new_with_clock(
                dialer,
                DownloadOptions {
                    client: client_options,
                },
                ntp_clock.clone(),
            )
            .map_err(|error| {
                RouteError::InvalidRuleSet(format!(
                    "configure HTTP client for rule-set {:?}: {error}",
                    rule_set.tag
                ))
            })?;
            *source
                .download_client
                .lock()
                .expect("rule-set download client lock poisoned") =
                Some(Arc::new(client));
        }
        Ok(())
    }

    pub fn clash_rules(&self) -> Vec<Value> {
        self.raw_rules
            .iter()
            .zip(&self.rules)
            .map(|(raw, rule)| {
                serde_json::json!({
                    "type": raw.get("type").and_then(Value::as_str).filter(|value| !value.is_empty()).unwrap_or("default"),
                    "payload": describe_rule(raw),
                    "proxy": describe_action(rule.action())
                })
            })
            .collect()
    }

    pub async fn start(&self) -> Result<(), RouteError> {
        for rule_set in self.rule_sets.values() {
            if let Err(error) = rule_set.start().await {
                self.close().await;
                return Err(error);
            }
        }
        Ok(())
    }

    pub async fn close(&self) {
        for rule_set in self.rule_sets.values() {
            rule_set.close().await;
        }
    }

    pub fn match_rule(&self, metadata: &Metadata) -> Option<&Rule> {
        let mut metadata = metadata.clone();
        self.apply_runtime_metadata(&mut metadata, false);
        self.rules.iter().find(|rule| rule.matches(&metadata))
    }

    pub fn route<'a>(&'a self, metadata: &Metadata) -> RouteDecision<'a> {
        self.route_internal(metadata, false, false)
    }

    /// Start an ordered route evaluation.  Non-terminal actions in sing-box
    /// are executed while walking the rule list once; rules before a sniff or
    /// resolve action must not be reconsidered after metadata changes.
    pub(crate) fn route_state(&self) -> RouteState {
        RouteState::default()
    }

    pub(crate) fn route_next<'a>(
        &'a self,
        metadata: &Metadata,
        state: &mut RouteState,
    ) -> RouteDecision<'a> {
        self.route_next_internal(metadata, state, false)
    }

    /// Evaluate one ordered rule step for the Linux NFQUEUE pre-match path.
    /// An empty-outbound bypass is terminal there: it means reinjecting the
    /// packet with the auto-redirect output mark, while the normal routed
    /// connection path treats the same action as a fall-through override.
    pub(crate) fn route_pre_match_next<'a>(
        &'a self,
        metadata: &Metadata,
        state: &mut RouteState,
    ) -> RouteDecision<'a> {
        self.route_next_internal(metadata, state, true)
    }

    fn route_next_internal<'a>(
        &'a self,
        metadata: &Metadata,
        state: &mut RouteState,
        preserve_empty_bypass: bool,
    ) -> RouteDecision<'a> {
        let mut current = metadata.clone();
        if let Some(destination) = &current.destination {
            current.destination = Some(state.options.apply(destination));
            if !preserve_empty_bypass && !state.options.address.is_empty() {
                current.destination_addresses.clear();
            }
        }
        self.apply_runtime_metadata(&mut current, preserve_empty_bypass);
        for (index, rule) in self.rules.iter().enumerate().skip(state.next_rule)
        {
            if !rule.matches(&current) {
                continue;
            }
            state.next_rule = index + 1;
            match rule.action() {
                Some(Action::RouteOptions(next)) => {
                    if let Some(destination) = &current.destination {
                        current.destination = Some(next.apply(destination));
                    }
                    if !preserve_empty_bypass && !next.address.is_empty() {
                        current.destination_addresses.clear();
                    }
                    state.options.update(next);
                    self.refresh_preferred_by(
                        &mut current,
                        preserve_empty_bypass,
                    );
                }
                Some(Action::Bypass { outbound, .. })
                    if outbound.is_empty() && !preserve_empty_bypass => {}
                Some(Action::Sniff(_)) if !metadata.protocol.is_empty() => {}
                action => {
                    return RouteDecision {
                        action,
                        options: state.options.clone(),
                        final_outbound: &self.final_outbound,
                        reject_drop: rule.reject_is_drop(),
                    };
                }
            }
        }
        RouteDecision {
            action: None,
            options: state.options.clone(),
            final_outbound: &self.final_outbound,
            reject_drop: false,
        }
    }

    /// Re-evaluate rules after a sniff action, without selecting another sniff
    /// action for the same connection.
    pub fn route_after_sniff<'a>(
        &'a self,
        metadata: &Metadata,
    ) -> RouteDecision<'a> {
        self.route_internal(metadata, true, false)
    }

    pub fn route_after_actions<'a>(
        &'a self,
        metadata: &Metadata,
        skip_sniff: bool,
        skip_resolve: bool,
    ) -> RouteDecision<'a> {
        self.route_internal(metadata, skip_sniff, skip_resolve)
    }

    fn route_internal<'a>(
        &'a self,
        metadata: &Metadata,
        skip_sniff: bool,
        skip_resolve: bool,
    ) -> RouteDecision<'a> {
        let mut options = ConnectionOverride::default();
        let mut current = metadata.clone();
        self.apply_runtime_metadata(&mut current, false);
        for rule in &self.rules {
            if !rule.matches(&current) {
                continue;
            }
            match rule.action() {
                Some(Action::RouteOptions(next)) => {
                    if let Some(destination) = &current.destination {
                        current.destination = Some(next.apply(destination));
                    }
                    if !next.address.is_empty() {
                        current.destination_addresses.clear();
                    }
                    options.update(next);
                    self.refresh_preferred_by(&mut current, false);
                }
                Some(Action::Bypass { outbound, .. })
                    if outbound.is_empty() => {}
                Some(Action::Sniff(_))
                    if skip_sniff || !metadata.protocol.is_empty() => {}
                Some(Action::Resolve(_)) if skip_resolve => {}
                action => {
                    return RouteDecision {
                        action,
                        options,
                        final_outbound: &self.final_outbound,
                        reject_drop: rule.reject_is_drop(),
                    };
                }
            }
        }
        RouteDecision {
            action: None,
            options,
            final_outbound: &self.final_outbound,
            reject_drop: false,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct RouteState {
    next_rule: usize,
    options: ConnectionOverride,
}

pub struct RouteDecision<'a> {
    action: Option<&'a Action>,
    options: ConnectionOverride,
    final_outbound: &'a str,
    reject_drop: bool,
}

impl RouteDecision<'_> {
    pub fn action(&self) -> Option<&Action> {
        self.action
    }

    /// Whether this reject invocation must be silent. Besides an explicit
    /// `method: drop`, sing-box turns the 51st default reject from one rule in
    /// a rolling 30-second window into a drop unless `no_drop` is set.
    pub(crate) fn reject_is_drop(&self) -> bool {
        self.reject_drop
    }

    pub fn outbound(&self) -> Option<&str> {
        match self.action {
            Some(Action::Route { outbound, .. })
            | Some(Action::Bypass { outbound, .. })
                if !outbound.is_empty() =>
            {
                Some(outbound)
            }
            Some(Action::Direct) => None,
            Some(Action::DirectOptions { outbound, .. })
                if !outbound.is_empty() =>
            {
                Some(outbound)
            }
            Some(Action::DirectOptions { .. }) => None,
            Some(Action::Reject { .. }) | Some(Action::HijackDns) => None,
            _ if self.final_outbound.is_empty() => None,
            _ => Some(self.final_outbound),
        }
    }

    pub fn destination(&self, original: &SocksAddr) -> SocksAddr {
        let destination = self.options.apply(original);
        match self.action {
            Some(Action::Route { options, .. })
            | Some(Action::Bypass { options, .. }) => {
                options.apply(&destination)
            }
            _ => destination,
        }
    }

    pub(crate) fn connection_options(&self) -> ConnectionOverride {
        let mut options = self.options.clone();
        if let Some(
            Action::Route {
                options: terminal, ..
            }
            | Action::Bypass {
                options: terminal, ..
            },
        ) = self.action
        {
            options.update(terminal);
        }
        options.network.external_connection = true;
        options
    }
}

#[derive(Debug)]
pub enum Rule {
    Default(Box<DefaultRule>),
    Logical(Box<LogicalRule>),
}

impl Rule {
    fn compile(
        value: &Value,
        rule_sets: &HashMap<String, Arc<RuleSet>>,
    ) -> Result<Self, RouteError> {
        Self::compile_nested(value, false, rule_sets)
    }

    fn compile_nested(
        value: &Value,
        nested: bool,
        rule_sets: &HashMap<String, Arc<RuleSet>>,
    ) -> Result<Self, RouteError> {
        let object = value.as_object().ok_or_else(|| {
            RouteError::InvalidRule("rule is not an object".into())
        })?;
        let kind = match object.get("type") {
            None => "",
            Some(Value::String(kind)) => kind.as_str(),
            Some(_) => {
                return Err(RouteError::InvalidRule(
                    "rule type is not a string".into(),
                ));
            }
        };
        match kind {
            "" | "default" => Ok(Self::Default(Box::new(
                DefaultRule::compile(value, nested, rule_sets)?,
            ))),
            "logical" => Ok(Self::Logical(Box::new(LogicalRule::compile(
                value, nested, rule_sets,
            )?))),
            kind => Err(RouteError::InvalidRule(format!(
                "unknown rule type: {kind}"
            ))),
        }
    }

    pub fn matches(&self, metadata: &Metadata) -> bool {
        match self {
            Self::Default(rule) => rule.matches(metadata),
            Self::Logical(rule) => rule.matches(metadata),
        }
    }

    pub fn action(&self) -> Option<&Action> {
        match self {
            Self::Default(rule) => Some(&rule.action),
            Self::Logical(rule) => Some(&rule.action),
        }
    }

    fn action_mut(&mut self) -> &mut Action {
        match self {
            Self::Default(rule) => &mut rule.action,
            Self::Logical(rule) => &mut rule.action,
        }
    }

    fn collect_preferred_by<'a>(&'a self, tags: &mut Vec<&'a str>) {
        match self {
            Self::Default(rule) => tags.extend(
                rule.raw.preferred_by.as_slice().iter().map(String::as_str),
            ),
            Self::Logical(rule) => {
                for rule in &rule.rules {
                    rule.collect_preferred_by(tags);
                }
            }
        }
    }

    fn reject_is_drop(&self) -> bool {
        match self {
            Self::Default(rule) => rule.reject_flood.is_drop(&rule.action),
            Self::Logical(rule) => rule.reject_flood.is_drop(&rule.action),
        }
    }
}

#[derive(Debug, Default)]
struct RejectFlood {
    recent: Mutex<VecDeque<Instant>>,
}

impl RejectFlood {
    fn is_drop(&self, action: &Action) -> bool {
        let Action::Reject { method, no_drop } = action else {
            return false;
        };
        if method == "drop" {
            return true;
        }
        if *no_drop || (!method.is_empty() && method != "default") {
            return false;
        }
        let now = Instant::now();
        let Ok(mut recent) = self.recent.lock() else {
            return false;
        };
        while recent.front().is_some_and(|timestamp| {
            now.duration_since(*timestamp) > StdDuration::from_secs(30)
        }) {
            recent.pop_front();
        }
        recent.push_back(now);
        recent.len() > 50
    }
}

#[derive(Debug)]
pub struct LogicalRule {
    mode: LogicalMode,
    rules: Vec<Rule>,
    invert: bool,
    action: Action,
    reject_flood: RejectFlood,
}

#[derive(Debug, Clone, Copy)]
enum LogicalMode {
    And,
    Or,
}

impl LogicalRule {
    fn compile(
        value: &Value,
        nested: bool,
        rule_sets: &HashMap<String, Arc<RuleSet>>,
    ) -> Result<Self, RouteError> {
        #[derive(Deserialize)]
        struct Raw {
            mode: String,
            rules: Vec<Value>,
            #[serde(default)]
            invert: bool,
        }
        let raw: Raw = serde_json::from_value(value.clone())
            .map_err(|error| RouteError::InvalidRule(error.to_string()))?;
        let mode = match raw.mode.as_str() {
            "and" => LogicalMode::And,
            "or" => LogicalMode::Or,
            _ => {
                return Err(RouteError::InvalidRule(format!(
                    "unknown logical mode: {}",
                    raw.mode
                )));
            }
        };
        if raw.rules.is_empty() {
            return Err(RouteError::InvalidRule(
                "logical rule has no child rules".into(),
            ));
        }
        validate_rule_keys(
            value
                .as_object()
                .expect("logical rule was decoded from object"),
            nested,
            true,
        )?;
        Ok(Self {
            mode,
            rules: raw
                .rules
                .iter()
                .map(|value| Rule::compile_nested(value, true, rule_sets))
                .collect::<Result<_, _>>()?,
            invert: raw.invert,
            action: parse_action(value, true)?,
            reject_flood: RejectFlood::default(),
        })
    }

    fn matches(&self, metadata: &Metadata) -> bool {
        let matched = match self.mode {
            LogicalMode::And => {
                self.rules.iter().all(|rule| rule.matches(metadata))
            }
            LogicalMode::Or => {
                self.rules.iter().any(|rule| rule.matches(metadata))
            }
        };
        matched != self.invert
    }
}

#[derive(Debug)]
pub struct DefaultRule {
    raw: RawDefaultRule,
    domain_regex: Vec<Regex>,
    process_path_regex: Vec<Regex>,
    package_name_regex: Vec<Regex>,
    source_prefixes: Vec<IpNet>,
    destination_prefixes: Vec<IpNet>,
    source_port_ranges: Vec<PortRange>,
    port_ranges: Vec<PortRange>,
    interface_prefixes: HashMap<String, Vec<IpNet>>,
    network_interface_prefixes: HashMap<String, Vec<IpNet>>,
    default_interface_prefixes: Vec<IpNet>,
    rule_sets: Vec<Arc<RuleSet>>,
    action: Action,
    reject_flood: RejectFlood,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
struct RawDefaultRule {
    inbound: Listable<String>,
    ip_version: i32,
    network: Listable<String>,
    auth_user: Listable<String>,
    protocol: Listable<String>,
    client: Listable<String>,
    domain: Listable<String>,
    domain_suffix: Listable<String>,
    domain_keyword: Listable<String>,
    domain_regex: Listable<String>,
    geosite: Listable<String>,
    source_geoip: Listable<String>,
    geoip: Listable<String>,
    source_ip_cidr: Listable<String>,
    source_ip_is_private: bool,
    ip_cidr: Listable<String>,
    ip_is_private: bool,
    source_port: Listable<u16>,
    source_port_range: Listable<String>,
    port: Listable<u16>,
    port_range: Listable<String>,
    process_name: Listable<String>,
    process_path: Listable<String>,
    process_path_regex: Listable<String>,
    package_name: Listable<String>,
    package_name_regex: Listable<String>,
    user: Listable<String>,
    user_id: Listable<i32>,
    clash_mode: String,
    network_type: Listable<String>,
    network_is_expensive: bool,
    network_is_constrained: bool,
    wifi_ssid: Listable<String>,
    wifi_bssid: Listable<String>,
    interface_address: HashMap<String, Listable<String>>,
    network_interface_address: HashMap<String, Listable<String>>,
    default_interface_address: Listable<String>,
    source_mac_address: Listable<String>,
    source_hostname: Listable<String>,
    preferred_by: Listable<String>,
    rule_set: Listable<String>,
    rule_set_ip_cidr_match_source: bool,
    rule_set_ipcidr_match_source: bool,
    invert: bool,
}

impl DefaultRule {
    fn compile(
        value: &Value,
        nested: bool,
        available_rule_sets: &HashMap<String, Arc<RuleSet>>,
    ) -> Result<Self, RouteError> {
        validate_rule_keys(
            value
                .as_object()
                .expect("default rule was decoded from object"),
            nested,
            false,
        )?;
        let raw: RawDefaultRule = serde_json::from_value(value.clone())
            .map_err(|error| RouteError::InvalidRule(error.to_string()))?;
        validate_deprecated_default_rule_fields(&raw)?;
        let rule_sets = raw
            .rule_set
            .as_slice()
            .iter()
            .map(|tag| {
                available_rule_sets.get(tag).cloned().ok_or_else(|| {
                    RouteError::InvalidRule(format!(
                        "rule-set not found: {tag}"
                    ))
                })
            })
            .collect::<Result<_, _>>()?;
        Self::from_raw(raw, parse_action(value, false)?, rule_sets)
    }

    fn from_raw(
        raw: RawDefaultRule,
        action: Action,
        rule_sets: Vec<Arc<RuleSet>>,
    ) -> Result<Self, RouteError> {
        if !matches!(raw.ip_version, 0 | 4 | 6) {
            return Err(RouteError::InvalidRule(format!(
                "invalid ip version: {}",
                raw.ip_version
            )));
        }
        validate_domain_items(
            raw.domain.as_slice(),
            raw.domain_suffix.as_slice(),
        )
        .map_err(RouteError::InvalidRule)?;
        let interface_prefixes = compile_prefix_map(&raw.interface_address)?;
        let network_interface_prefixes =
            compile_prefix_map(&raw.network_interface_address)?;
        let default_interface_prefixes =
            compile_prefixes(raw.default_interface_address.as_slice())?;
        Ok(Self {
            domain_regex: compile_regexes(raw.domain_regex.as_slice())?,
            process_path_regex: compile_regexes(
                raw.process_path_regex.as_slice(),
            )?,
            package_name_regex: compile_regexes(
                raw.package_name_regex.as_slice(),
            )?,
            source_prefixes: compile_prefixes(raw.source_ip_cidr.as_slice())?,
            destination_prefixes: compile_prefixes(raw.ip_cidr.as_slice())?,
            source_port_ranges: compile_port_ranges(
                raw.source_port_range.as_slice(),
            )?,
            port_ranges: compile_port_ranges(raw.port_range.as_slice())?,
            interface_prefixes,
            network_interface_prefixes,
            default_interface_prefixes,
            rule_sets,
            action,
            reject_flood: RejectFlood::default(),
            raw,
        })
    }

    fn matches(&self, metadata: &Metadata) -> bool {
        let outer = self.evaluate(metadata);
        let matched = if self.rule_sets.is_empty() {
            outer.done()
        } else {
            self.rule_sets.iter().any(|set| {
                set.matches_with_outer(
                    metadata,
                    outer,
                    self.raw.rule_set_ip_cidr_match_source,
                )
            })
        };
        matched != self.raw.invert
    }

    fn evaluate(&self, metadata: &Metadata) -> RuleMatch {
        self.evaluate_with_ip_source(metadata, false)
    }

    fn evaluate_with_ip_source(
        &self,
        metadata: &Metadata,
        ip_cidr_match_source: bool,
    ) -> RuleMatch {
        self.evaluate_with_ip_source_and_empty(
            metadata,
            ip_cidr_match_source,
            false,
        )
    }

    fn evaluate_with_ip_source_and_empty(
        &self,
        metadata: &Metadata,
        ip_cidr_match_source: bool,
        ip_cidr_accept_empty: bool,
    ) -> RuleMatch {
        let raw = &self.raw;
        let ordinary = matches_list(raw.inbound.as_slice(), &metadata.inbound)
            && matches_string_optional(
                raw.network.as_slice(),
                metadata.network.map(Network::as_str),
            )
            && matches_list(raw.auth_user.as_slice(), &metadata.auth_user)
            && matches_list(raw.protocol.as_slice(), &metadata.protocol)
            && matches_list(raw.client.as_slice(), &metadata.client)
            && matches_ip_version(
                raw.ip_version,
                metadata.ip_version,
                metadata.destination_ip(),
            )
            && matches_list(
                raw.process_name.as_slice(),
                &metadata.process_name,
            )
            && matches_list(
                raw.process_path.as_slice(),
                &metadata.process_path,
            )
            && matches_regex(&self.process_path_regex, &metadata.process_path)
            && matches_list(
                raw.package_name.as_slice(),
                &metadata.package_name,
            )
            && matches_regex(&self.package_name_regex, &metadata.package_name)
            && matches_list(raw.user.as_slice(), &metadata.user)
            && matches_optional(raw.user_id.as_slice(), metadata.user_id)
            && (raw.clash_mode.is_empty()
                || raw.clash_mode.eq_ignore_ascii_case(&metadata.clash_mode))
            && matches_list(
                raw.network_type.as_slice(),
                &metadata.network_type,
            )
            && (!raw.network_is_expensive || metadata.network_is_expensive)
            && (!raw.network_is_constrained || metadata.network_is_constrained)
            && matches_list(raw.wifi_ssid.as_slice(), &metadata.wifi_ssid)
            && matches_hardware_addresses(
                raw.wifi_bssid.as_slice(),
                &metadata.wifi_bssid,
                true,
            )
            && matches_interface_prefixes(
                &self.interface_prefixes,
                &metadata.interface_address,
            )
            && matches_interface_prefixes(
                &self.network_interface_prefixes,
                &metadata.network_interface_address,
            )
            && matches_any_prefix(
                &self.default_interface_prefixes,
                &metadata.default_interface_address,
            )
            && matches_hardware_addresses(
                raw.source_mac_address.as_slice(),
                &metadata.source_mac_address,
                false,
            )
            && matches_list(
                raw.source_hostname.as_slice(),
                &metadata.source_hostname,
            )
            && (raw.preferred_by.as_slice().is_empty()
                || raw
                    .preferred_by
                    .as_slice()
                    .iter()
                    .any(|tag| metadata.preferred_by.contains(tag)));
        let mut result = RuleMatch {
            ordinary,
            required: 0,
            satisfied: 0,
        };
        let has_source_address = !raw.source_ip_cidr.as_slice().is_empty()
            || raw.source_ip_is_private;
        let has_destination_ip =
            !raw.ip_cidr.as_slice().is_empty() || raw.ip_is_private;
        if has_source_address || (ip_cidr_match_source && has_destination_ip) {
            result.required |= MATCH_SOURCE_ADDRESS;
            if (has_source_address
                && self.matches_source_address(metadata.source_ip()))
                || (ip_cidr_match_source
                    && has_destination_ip
                    && self.matches_ip_address(metadata.source_ip()))
            {
                result.satisfied |= MATCH_SOURCE_ADDRESS;
            }
        }
        if !raw.source_port.as_slice().is_empty()
            || !self.source_port_ranges.is_empty()
        {
            result.required |= MATCH_SOURCE_PORT;
            if matches_port(
                raw.source_port.as_slice(),
                &self.source_port_ranges,
                metadata.source.as_ref().map(SocksAddr::port),
            ) {
                result.satisfied |= MATCH_SOURCE_PORT;
            }
        }
        if self.has_domain_condition()
            || (!ip_cidr_match_source && has_destination_ip)
        {
            result.required |= MATCH_DESTINATION_ADDRESS;
            if (self.has_domain_condition()
                && self.matches_domain(metadata.domain()))
                || (!ip_cidr_match_source
                    && has_destination_ip
                    && (self.matches_destination_ip_address(metadata)
                        || (ip_cidr_accept_empty
                            && metadata.destination_ip().is_none()
                            && metadata.destination_addresses.is_empty())))
            {
                result.satisfied |= MATCH_DESTINATION_ADDRESS;
            }
        }
        if !raw.port.as_slice().is_empty() || !self.port_ranges.is_empty() {
            result.required |= MATCH_DESTINATION_PORT;
            if matches_port(
                raw.port.as_slice(),
                &self.port_ranges,
                metadata.destination.as_ref().map(SocksAddr::port),
            ) {
                result.satisfied |= MATCH_DESTINATION_PORT;
            }
        }
        result
    }

    fn matches_domain(&self, domain: Option<&str>) -> bool {
        let Some(domain) = domain else {
            return false;
        };
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.raw.domain.as_slice().iter().any(|value| {
            value.trim_end_matches('.').eq_ignore_ascii_case(&domain)
        }) || self
            .raw
            .domain_suffix
            .as_slice()
            .iter()
            .any(|suffix| domain_matches_suffix(&domain, suffix))
            || self
                .raw
                .domain_keyword
                .as_slice()
                .iter()
                .any(|keyword| domain.contains(&keyword.to_ascii_lowercase()))
            || self
                .domain_regex
                .iter()
                .any(|pattern| pattern.is_match(&domain))
    }

    fn has_domain_condition(&self) -> bool {
        !self.raw.domain.as_slice().is_empty()
            || !self.raw.domain_suffix.as_slice().is_empty()
            || !self.raw.domain_keyword.as_slice().is_empty()
            || !self.domain_regex.is_empty()
    }

    fn matches_source_address(&self, address: Option<IpAddr>) -> bool {
        let has_cidr = !self.raw.source_ip_cidr.as_slice().is_empty();
        if !has_cidr && !self.raw.source_ip_is_private {
            return true;
        }
        (has_cidr
            && address.is_some_and(|address| {
                self.source_prefixes
                    .iter()
                    .any(|prefix| prefix.contains(&address))
            }))
            || (self.raw.source_ip_is_private
                && address.is_some_and(|address| is_private_address(&address)))
    }

    fn matches_ip_address(&self, address: Option<IpAddr>) -> bool {
        let has_cidr = !self.raw.ip_cidr.as_slice().is_empty();
        (has_cidr
            && address.is_some_and(|address| {
                self.destination_prefixes
                    .iter()
                    .any(|prefix| prefix.contains(&address))
            }))
            || (self.raw.ip_is_private
                && address.is_some_and(|address| is_private_address(&address)))
    }

    fn matches_destination_ip_address(&self, metadata: &Metadata) -> bool {
        if let Some(address) = metadata.destination_ip() {
            return self.matches_ip_address(Some(address));
        }
        metadata
            .destination_addresses
            .iter()
            .copied()
            .any(|address| self.matches_ip_address(Some(address)))
    }
}

fn validate_deprecated_default_rule_fields(
    raw: &RawDefaultRule,
) -> Result<(), RouteError> {
    if !raw.geosite.is_empty() {
        return Err(RouteError::InvalidRule(
            "geosite database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0"
                .into(),
        ));
    }
    if !raw.source_geoip.is_empty() || !raw.geoip.is_empty() {
        return Err(RouteError::InvalidRule(
            "geoip database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0"
                .into(),
        ));
    }
    if !raw.rule_set.is_empty() && raw.rule_set_ipcidr_match_source {
        return Err(RouteError::InvalidRule(
            "rule_set_ipcidr_match_source is deprecated in sing-box 1.10.0 and removed in sing-box 1.11.0"
                .into(),
        ));
    }
    Ok(())
}

/// Reuses the non-destination portion of the route metadata matcher for DNS
/// rules. Domain and DNS response address fields are deliberately cleared
/// here; the DNS matcher evaluates them as one upstream-compatible OR group.
#[derive(Debug)]
pub(crate) struct DnsContextMatcher(DefaultRule);

impl DnsContextMatcher {
    pub(crate) fn compile(value: &Value) -> Result<Self, RouteError> {
        let mut raw: RawDefaultRule = serde_json::from_value(value.clone())
            .map_err(|error| RouteError::InvalidRule(error.to_string()))?;
        raw.ip_version = 0;
        raw.domain = Listable::default();
        raw.domain_suffix = Listable::default();
        raw.domain_keyword = Listable::default();
        raw.domain_regex = Listable::default();
        raw.ip_cidr = Listable::default();
        raw.ip_is_private = false;
        raw.rule_set = Listable::default();
        raw.rule_set_ip_cidr_match_source = false;
        raw.preferred_by = Listable::default();
        raw.invert = false;
        let rule = DefaultRule::from_raw(
            raw,
            Action::Route {
                outbound: String::new(),
                options: ConnectionOverride::default(),
            },
            Vec::new(),
        )?;
        Ok(Self(rule))
    }

    pub(crate) fn matches(&self, metadata: &Metadata) -> bool {
        self.0.matches(metadata)
    }
}

#[derive(Debug, Clone, Copy)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

fn compile_regexes(patterns: &[String]) -> Result<Vec<Regex>, RouteError> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern).map_err(|source| RouteError::Regex {
                pattern: pattern.clone(),
                source,
            })
        })
        .collect()
}

fn compile_adguard_patterns(
    patterns: &[String],
) -> Result<Vec<Regex>, RouteError> {
    patterns
        .iter()
        .map(|pattern| {
            let (prefix, body) = if let Some(body) = pattern.strip_prefix("||")
            {
                (r"(?:^|\.)", body)
            } else if let Some(body) = pattern.strip_prefix('|') {
                ("^", body)
            } else {
                (".*", pattern.as_str())
            };
            let (body, suffix) = if let Some(body) = body.strip_suffix('^') {
                (body, "$")
            } else {
                (body, ".*")
            };
            let body = body
                .split('*')
                .map(regex::escape)
                .collect::<Vec<_>>()
                .join(".*");
            let expression = format!("(?i){prefix}{body}{suffix}");
            Regex::new(&expression).map_err(|source| RouteError::Regex {
                pattern: pattern.clone(),
                source,
            })
        })
        .collect()
}

fn compile_prefixes(values: &[String]) -> Result<Vec<IpNet>, RouteError> {
    values
        .iter()
        .map(|value| {
            if let Ok(prefix) = value.parse::<IpNet>() {
                return Ok(prefix);
            }
            let address = value.parse::<IpAddr>().map_err(|error| {
                RouteError::Prefix {
                    value: value.clone(),
                    message: error.to_string(),
                }
            })?;
            IpNet::new(address, if address.is_ipv4() { 32 } else { 128 })
                .map_err(|error| RouteError::Prefix {
                    value: value.clone(),
                    message: error.to_string(),
                })
        })
        .collect()
}

fn compile_prefix_map(
    values: &HashMap<String, Listable<String>>,
) -> Result<HashMap<String, Vec<IpNet>>, RouteError> {
    values
        .iter()
        .map(|(kind, prefixes)| {
            Ok((kind.clone(), compile_prefixes(prefixes.as_slice())?))
        })
        .collect()
}

fn compile_port_ranges(
    values: &[String],
) -> Result<Vec<PortRange>, RouteError> {
    values
        .iter()
        .map(|value| {
            let (start, end) = value.split_once(':').ok_or_else(|| {
                RouteError::InvalidRule(format!("bad port range: {value}"))
            })?;
            let start = if start.is_empty() {
                0
            } else {
                start.parse::<u16>().map_err(|_| {
                    RouteError::InvalidRule(format!("bad port range: {value}"))
                })?
            };
            let end = if end.is_empty() {
                u16::MAX
            } else {
                end.parse::<u16>().map_err(|_| {
                    RouteError::InvalidRule(format!("bad port range: {value}"))
                })?
            };
            Ok(PortRange { start, end })
        })
        .collect()
}

fn matches_list(values: &[String], actual: &str) -> bool {
    values.is_empty() || values.iter().any(|value| value == actual)
}

fn matches_optional<T: PartialEq>(values: &[T], actual: Option<T>) -> bool {
    values.is_empty() || actual.is_some_and(|actual| values.contains(&actual))
}

fn matches_string_optional(values: &[String], actual: Option<&str>) -> bool {
    values.is_empty()
        || actual
            .is_some_and(|actual| values.iter().any(|value| value == actual))
}

fn matches_regex(patterns: &[Regex], actual: &str) -> bool {
    patterns.is_empty()
        || patterns.iter().any(|pattern| pattern.is_match(actual))
}

fn matches_port(
    exact: &[u16],
    ranges: &[PortRange],
    actual: Option<u16>,
) -> bool {
    if exact.is_empty() && ranges.is_empty() {
        return true;
    }
    actual.is_some_and(|port| {
        exact.contains(&port) || ranges.iter().any(|range| range.contains(port))
    })
}

fn matches_ip_version(
    version: i32,
    explicit: Option<u8>,
    address: Option<IpAddr>,
) -> bool {
    let actual = address
        .map(|address| if address.is_ipv4() { 4 } else { 6 })
        .or(explicit);
    match version {
        0 => true,
        4 => actual == Some(4),
        6 => actual == Some(6),
        _ => false,
    }
}

fn matches_interface_prefixes(
    configured: &HashMap<String, Vec<IpNet>>,
    actual: &HashMap<String, Vec<IpAddr>>,
) -> bool {
    configured.is_empty()
        || configured.iter().all(|(kind, prefixes)| {
            actual.get(kind).is_some_and(|addresses| {
                prefixes.iter().all(|prefix| {
                    addresses.iter().any(|address| prefix.contains(address))
                })
            })
        })
}

fn matches_any_prefix(prefixes: &[IpNet], addresses: &[IpAddr]) -> bool {
    prefixes.is_empty()
        || prefixes.iter().all(|prefix| {
            addresses.iter().any(|address| prefix.contains(address))
        })
}

fn parse_logical_mode(
    value: &str,
    context: &str,
) -> Result<LogicalMode, RouteError> {
    match value {
        "and" => Ok(LogicalMode::And),
        "or" => Ok(LogicalMode::Or),
        _ => Err(RouteError::InvalidRuleSet(format!(
            "unknown {context} logical mode: {value}"
        ))),
    }
}

fn domain_matches_suffix(domain: &str, configured: &str) -> bool {
    let subdomains_only = configured.starts_with('.');
    let suffix = configured
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!subdomains_only && domain == suffix)
        || domain
            .strip_suffix(&suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn validate_domain_items(
    domains: &[String],
    suffixes: &[String],
) -> Result<(), String> {
    if domains.iter().any(String::is_empty) {
        return Err("domain: empty item is not allowed".into());
    }
    if suffixes.iter().any(String::is_empty) {
        return Err("domain_suffix: empty item is not allowed".into());
    }
    Ok(())
}

fn matches_hardware_addresses(
    configured: &[String],
    actual: &str,
    wifi: bool,
) -> bool {
    if configured.is_empty() {
        return true;
    }
    let actual = normalize_hardware_address(actual, wifi);
    configured
        .iter()
        .any(|value| normalize_hardware_address(value, wifi) == actual)
}

fn normalize_hardware_address(value: &str, wifi: bool) -> String {
    let value = if wifi { value.trim() } else { value };
    let parsed = if wifi
        && value.len() == 12
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        parse_hex_octets(value.as_bytes().chunks_exact(2))
    } else if value.contains('.') {
        let groups = value.split('.').collect::<Vec<_>>();
        if groups.len() == 3
            && groups
                .iter()
                .all(|group| group.len() == 4 && group.is_ascii())
        {
            let compact = groups.concat();
            parse_hex_octets(compact.as_bytes().chunks_exact(2))
        } else {
            None
        }
    } else {
        let separator = if value.contains(':') {
            ':'
        } else if value.contains('-') {
            '-'
        } else {
            return value.to_owned();
        };
        let groups = value.split(separator).collect::<Vec<_>>();
        if groups.iter().all(|group| group.len() == 2) {
            parse_hex_octets(groups.iter().map(|group| group.as_bytes()))
        } else {
            None
        }
    };
    let Some(parsed) = parsed.filter(|parsed| {
        if wifi {
            parsed.len() == 6
        } else {
            matches!(parsed.len(), 6 | 8 | 20)
        }
    }) else {
        return value.to_owned();
    };
    format_hardware_address(&parsed)
}

fn parse_hex_octets<'a>(
    octets: impl Iterator<Item = &'a [u8]>,
) -> Option<Vec<u8>> {
    octets
        .map(|octet| {
            std::str::from_utf8(octet)
                .ok()
                .and_then(|octet| u8::from_str_radix(octet, 16).ok())
        })
        .collect()
}

fn parse_action(value: &Value, logical: bool) -> Result<Action, RouteError> {
    let source = value.as_object().ok_or_else(|| {
        RouteError::InvalidRule("rule is not an object".into())
    })?;
    // Go decodes the matcher first, then removes every matcher field before
    // decoding the action via badjson.UnmarshallExcluded. A default rule's
    // `network_type` therefore remains a matcher even for `action: direct`,
    // while the same key belongs to the action on a logical top-level rule.
    let object = source
        .iter()
        .filter(|(key, _)| {
            if logical {
                !matches!(key.as_str(), "type" | "mode" | "rules" | "invert")
            } else {
                !is_default_route_match_key(key)
            }
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Map<_, _>>();
    let object = &object;
    let action = object
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("route");
    if action == "direct" {
        let direct_options = parse_direct_action_options(object)?;
        return Ok(if direct_options == AbstractDialerOptions::default() {
            Action::Direct
        } else {
            Action::DirectOptions {
                options: direct_options,
                outbound: String::new(),
            }
        });
    }
    let outbound = object
        .get("outbound")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let address = match object.get("override_address") {
        None => String::new(),
        Some(Value::String(value)) => value.clone(),
        Some(_) => {
            return Err(RouteError::InvalidRule(
                "override_address is not a string".into(),
            ));
        }
    };
    let port = match object.get("override_port") {
        None => 0,
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| {
                RouteError::InvalidRule("invalid override_port".into())
            })?,
        Some(_) => {
            return Err(RouteError::InvalidRule(
                "override_port is not an integer".into(),
            ));
        }
    };
    let tls_fragment = parse_action_bool(object, "tls_fragment")?;
    let tls_record_fragment = parse_action_bool(object, "tls_record_fragment")?;
    if action == "route-options" && tls_fragment && tls_record_fragment {
        return Err(RouteError::InvalidRule(
            "`tls_fragment` and `tls_record_fragment` are mutually exclusive"
                .into(),
        ));
    }
    let tls_fragment_fallback_delay = object
        .get("tls_fragment_fallback_delay")
        .cloned()
        .map(serde_json::from_value::<ConfigDuration>)
        .transpose()
        .map_err(|error| {
            RouteError::InvalidRule(format!(
                "invalid tls_fragment_fallback_delay: {error}"
            ))
        })?
        .map(|delay| {
            delay.as_std().ok_or_else(|| {
                RouteError::InvalidRule(
                    "tls_fragment_fallback_delay must not be negative".into(),
                )
            })
        })
        .transpose()?;
    let network_strategy = object
        .get("network_strategy")
        .cloned()
        .map(serde_json::from_value::<ConfigNetworkStrategy>)
        .transpose()
        .map_err(|error| {
            RouteError::InvalidRule(format!(
                "invalid network_strategy: {error}"
            ))
        })?
        .map(|strategy| strategy.0);
    let fallback_delay = match object.get("fallback_delay") {
        None => None,
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(u64::from)
            .map(StdDuration::from_nanos)
            .filter(|delay| !delay.is_zero()),
        Some(_) => {
            return Err(RouteError::InvalidRule(
                "fallback_delay is not an unsigned 32-bit nanosecond value"
                    .into(),
            ));
        }
    };
    if object.contains_key("fallback_delay") && fallback_delay.is_none() {
        let zero = object
            .get("fallback_delay")
            .and_then(Value::as_u64)
            .is_some_and(|value| value == 0);
        if !zero {
            return Err(RouteError::InvalidRule(
                "fallback_delay is outside the unsigned 32-bit range".into(),
            ));
        }
    }
    let udp_timeout = object
        .get("udp_timeout")
        .cloned()
        .map(serde_json::from_value::<ConfigDuration>)
        .transpose()
        .map_err(|error| {
            RouteError::InvalidRule(format!("invalid udp_timeout: {error}"))
        })?
        .map(|timeout| {
            timeout.as_std().ok_or_else(|| {
                RouteError::InvalidRule(
                    "udp_timeout must not be negative".into(),
                )
            })
        })
        .transpose()?
        .filter(|timeout| !timeout.is_zero());
    let udp_disable_domain_unmapping =
        parse_action_bool(object, "udp_disable_domain_unmapping")?;
    let udp_connect = parse_action_bool(object, "udp_connect")?;
    let tls_spoof = object
        .get("tls_spoof")
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                RouteError::InvalidRule("tls_spoof is not a string".into())
            })
        })
        .transpose()?
        .unwrap_or_default();
    let tls_spoof_method_name = object
        .get("tls_spoof_method")
        .map(|value| {
            value.as_str().ok_or_else(|| {
                RouteError::InvalidRule(
                    "tls_spoof_method is not a string".into(),
                )
            })
        })
        .transpose()?
        .unwrap_or_default();
    let tls_spoof_method = crate::common::tls_spoof::parse_options(
        &tls_spoof,
        tls_spoof_method_name,
    )
    .map_err(|error| RouteError::InvalidRule(error.to_string()))?
    .unwrap_or_default();
    let options = ConnectionOverride {
        address,
        port,
        tls_fragment,
        tls_fragment_fallback_delay,
        tls_record_fragment,
        tls_spoof,
        tls_spoof_method,
        network: NetworkDialOptions {
            strategy: network_strategy,
            network_type: Vec::new(),
            fallback_network_type: Vec::new(),
            fallback_delay,
            udp_disable_domain_unmapping,
            udp_connect,
            external_connection: false,
        },
        udp_timeout,
    };
    Ok(match action {
        "route" => Action::Route { outbound, options },
        "route-options" => {
            if options == ConnectionOverride::default() {
                return Err(RouteError::InvalidRule(
                    "empty route option action".into(),
                ));
            }
            Action::RouteOptions(options)
        }
        "bypass" => Action::Bypass { outbound, options },
        "reject" => {
            let method = object
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("default")
                .to_owned();
            if !matches!(method.as_str(), "" | "default" | "drop" | "reply") {
                return Err(RouteError::InvalidRule(format!(
                    "unknown reject method: {method}"
                )));
            }
            let no_drop = object
                .get("no_drop")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if method == "drop" && no_drop {
                return Err(RouteError::InvalidRule(
                    "no_drop is not available with drop reject method".into(),
                ));
            }
            Action::Reject { method, no_drop }
        }
        "sniff" => Action::Sniff(parse_sniff_options(object)?),
        "resolve" => Action::Resolve(parse_resolve_options(object)?),
        "hijack-dns" => Action::HijackDns,
        _ => {
            return Err(RouteError::InvalidRule(format!(
                "unknown rule action: {action}"
            )));
        }
    })
}

fn is_default_route_match_key(key: &str) -> bool {
    matches!(
        key,
        "type"
            | "inbound"
            | "ip_version"
            | "network"
            | "auth_user"
            | "protocol"
            | "client"
            | "domain"
            | "domain_suffix"
            | "domain_keyword"
            | "domain_regex"
            | "geosite"
            | "source_geoip"
            | "geoip"
            | "source_ip_cidr"
            | "source_ip_is_private"
            | "ip_cidr"
            | "ip_is_private"
            | "source_port"
            | "source_port_range"
            | "port"
            | "port_range"
            | "process_name"
            | "process_path"
            | "process_path_regex"
            | "package_name"
            | "package_name_regex"
            | "user"
            | "user_id"
            | "clash_mode"
            | "network_type"
            | "network_is_expensive"
            | "network_is_constrained"
            | "wifi_ssid"
            | "wifi_bssid"
            | "interface_address"
            | "network_interface_address"
            | "default_interface_address"
            | "source_mac_address"
            | "source_hostname"
            | "preferred_by"
            | "rule_set"
            | "rule_set_ip_cidr_match_source"
            | "rule_set_ipcidr_match_source"
            | "invert"
    )
}

fn parse_action_bool(
    object: &Map<String, Value>,
    name: &str,
) -> Result<bool, RouteError> {
    match object.get(name) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => {
            Err(RouteError::InvalidRule(format!("{name} is not a boolean")))
        }
    }
}

fn parse_direct_action_options(
    object: &Map<String, Value>,
) -> Result<AbstractDialerOptions, RouteError> {
    const KEYS: &[&str] = &[
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
    let payload = object
        .iter()
        .filter(|(key, _)| KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Map<_, _>>();
    serde_json::from_value(Value::Object(payload)).map_err(|error| {
        RouteError::InvalidRule(format!("invalid direct action: {error}"))
    })
}

fn parse_resolve_options(
    object: &Map<String, Value>,
) -> Result<ResolveOptions, RouteError> {
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Raw {
        server: String,
        timeout: ConfigDuration,
        strategy: DomainStrategy,
        disable_cache: bool,
        disable_optimistic_cache: bool,
        rewrite_ttl: Option<u32>,
        client_subnet: Option<Prefixable>,
    }
    let raw: Raw = serde_json::from_value(Value::Object(object.clone()))
        .map_err(|error| {
            RouteError::InvalidRule(format!("invalid resolve action: {error}"))
        })?;
    let timeout = if raw.timeout == ConfigDuration::ZERO {
        None
    } else {
        Some(raw.timeout.as_std().ok_or_else(|| {
            RouteError::InvalidRule("resolve timeout must be positive".into())
        })?)
    };
    Ok(ResolveOptions {
        server: raw.server,
        timeout,
        strategy: raw.strategy,
        disable_cache: raw.disable_cache,
        disable_optimistic_cache: raw.disable_optimistic_cache,
        rewrite_ttl: raw.rewrite_ttl,
        client_subnet: raw.client_subnet.map(|prefix| prefix.0),
    })
}

fn parse_sniff_options(
    object: &Map<String, Value>,
) -> Result<SniffOptions, RouteError> {
    let names = object
        .get("sniffer")
        .cloned()
        .map(serde_json::from_value::<Listable<String>>)
        .transpose()
        .map_err(|error| {
            RouteError::InvalidRule(format!("invalid sniffer: {error}"))
        })?
        .unwrap_or_default()
        .as_slice()
        .to_vec();
    let configured_timeout = object
        .get("timeout")
        .cloned()
        .map(serde_json::from_value::<ConfigDuration>)
        .transpose()
        .map_err(|error| {
            RouteError::InvalidRule(format!("invalid sniff timeout: {error}"))
        })?;
    let timeout = match configured_timeout {
        None | Some(ConfigDuration::ZERO) => StdDuration::from_millis(300),
        Some(timeout) => timeout.as_std().ok_or_else(|| {
            RouteError::InvalidRule("sniff timeout must be positive".into())
        })?,
    };
    let mut stream_sniffers = Vec::new();
    let mut packet_sniffers = Vec::new();
    let configured_names: &[String] = if names.is_empty() {
        &[
            "tls".into(),
            "http".into(),
            "quic".into(),
            "dns".into(),
            "bittorrent".into(),
            "ssh".into(),
            "rdp".into(),
            "stun".into(),
            "dtls".into(),
            "ntp".into(),
        ]
    } else {
        &names
    };
    for name in configured_names {
        match name.as_str() {
            "tls" => stream_sniffers.push(StreamSniffer::Tls),
            "http" => stream_sniffers.push(StreamSniffer::Http),
            "quic" => packet_sniffers.push(PacketSniffer::Quic),
            "dns" => {
                stream_sniffers.push(StreamSniffer::Dns);
                packet_sniffers.push(PacketSniffer::Dns);
            }
            "stun" => packet_sniffers.push(PacketSniffer::Stun),
            "bittorrent" => {
                stream_sniffers.push(StreamSniffer::BitTorrent);
                packet_sniffers.push(PacketSniffer::Utp);
                packet_sniffers.push(PacketSniffer::BitTorrent);
            }
            "dtls" => packet_sniffers.push(PacketSniffer::Dtls),
            "ssh" => stream_sniffers.push(StreamSniffer::Ssh),
            "rdp" => stream_sniffers.push(StreamSniffer::Rdp),
            "ntp" => packet_sniffers.push(PacketSniffer::Ntp),
            _ => {
                return Err(RouteError::InvalidRule(format!(
                    "unknown sniffer: {name}"
                )));
            }
        }
    }
    Ok(SniffOptions {
        names,
        stream_sniffers,
        packet_sniffers,
        timeout,
    })
}

fn validate_rule_keys(
    object: &Map<String, Value>,
    nested: bool,
    logical: bool,
) -> Result<(), RouteError> {
    const MATCH_KEYS: &[&str] = &[
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
    const ACTION_KEYS: &[&str] = &[
        "action",
        "outbound",
        "override_address",
        "override_port",
        "tls_fragment",
        "tls_fragment_fallback_delay",
        "tls_record_fragment",
        "network_strategy",
        "fallback_delay",
        "udp_timeout",
        "udp_disable_domain_unmapping",
        "udp_connect",
        "tls_spoof",
        "tls_spoof_method",
        "method",
        "no_drop",
        "sniffer",
        "timeout",
        "server",
        "strategy",
        "disable_cache",
        "disable_optimistic_cache",
        "rewrite_ttl",
        "client_subnet",
    ];
    let action = object
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("route");
    for key in object.keys() {
        let key = key.as_str();
        let matcher = if logical {
            matches!(key, "type" | "mode" | "rules" | "invert")
        } else {
            MATCH_KEYS.contains(&key)
        };
        if matcher {
            continue;
        }
        if nested && ACTION_KEYS.contains(&key) {
            return Err(RouteError::InvalidRule(
                ROUTE_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE.into(),
            ));
        }
        let action_key_allowed = match action {
            "" | "route" | "bypass" => matches!(
                key,
                "action"
                    | "outbound"
                    | "override_address"
                    | "override_port"
                    | "tls_fragment"
                    | "tls_fragment_fallback_delay"
                    | "tls_record_fragment"
                    | "network_strategy"
                    | "fallback_delay"
                    | "udp_timeout"
                    | "udp_disable_domain_unmapping"
                    | "udp_connect"
                    | "tls_spoof"
                    | "tls_spoof_method"
            ),
            "route-options" => matches!(
                key,
                "action"
                    | "override_address"
                    | "override_port"
                    | "tls_fragment"
                    | "tls_fragment_fallback_delay"
                    | "tls_record_fragment"
                    | "network_strategy"
                    | "fallback_delay"
                    | "udp_timeout"
                    | "udp_disable_domain_unmapping"
                    | "udp_connect"
                    | "tls_spoof"
                    | "tls_spoof_method"
            ),
            "direct" => matches!(
                key,
                "action"
                    | "bind_interface"
                    | "inet4_bind_address"
                    | "inet6_bind_address"
                    | "bind_address_no_port"
                    | "protect_path"
                    | "routing_mark"
                    | "reuse_addr"
                    | "netns"
                    | "connect_timeout"
                    | "tcp_fast_open"
                    | "tcp_multi_path"
                    | "disable_tcp_keep_alive"
                    | "tcp_keep_alive"
                    | "tcp_keep_alive_interval"
                    | "udp_fragment"
                    | "domain_resolver"
                    | "network_strategy"
                    | "network_type"
                    | "fallback_network_type"
                    | "fallback_delay"
                    | "domain_strategy"
            ),
            "reject" => matches!(key, "action" | "method" | "no_drop"),
            "hijack-dns" => key == "action",
            "resolve" => matches!(
                key,
                "action"
                    | "server"
                    | "timeout"
                    | "strategy"
                    | "disable_cache"
                    | "disable_optimistic_cache"
                    | "rewrite_ttl"
                    | "client_subnet"
            ),
            "sniff" => matches!(key, "action" | "sniffer" | "timeout"),
            _ => key == "action",
        };
        if !nested && action_key_allowed {
            continue;
        }
        return Err(RouteError::InvalidRule(format!(
            "route rule field {key:?} is not implemented or is invalid for action {action:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        Action, HeadlessRule, Metadata, Router, Rule, RuleSetMetadata,
        SourceRuleSet, decode_rule_set,
    };
    use crate::{
        adapter::{
            DialFuture, Dialer, NeighborResolver, ProcessInfo, ProcessResolver,
        },
        common::network::{Network, SocksAddr},
        dns::persistent::PersistentDnsCache,
        option::Options,
        outbound::OutboundManager,
    };

    struct StaticRouteNeighbor;

    struct PreferredRouteDialer(std::net::IpAddr);

    impl Dialer for PreferredRouteDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "test preference-only dialer",
                ))
            })
        }

        fn preferred_address(&self, address: std::net::IpAddr) -> bool {
            address == self.0
        }
    }

    impl NeighborResolver for StaticRouteNeighbor {
        fn lookup_addresses(&self, hostname: &str) -> Vec<std::net::IpAddr> {
            (hostname == "workstation")
                .then(|| "192.0.2.9".parse().unwrap())
                .into_iter()
                .collect()
        }

        fn lookup_mac(&self, address: std::net::IpAddr) -> Option<Vec<u8>> {
            (address == "192.0.2.9".parse::<std::net::IpAddr>().unwrap())
                .then_some(vec![0x02, 0, 0, 0, 0, 9])
        }

        fn lookup_hostname(&self, address: std::net::IpAddr) -> Option<String> {
            (address == "192.0.2.9".parse::<std::net::IpAddr>().unwrap())
                .then_some("workstation".into())
        }
    }

    struct StaticProcessResolver;

    impl ProcessResolver for StaticProcessResolver {
        fn lookup(
            &self,
            network: Network,
            source: std::net::SocketAddr,
            destination: Option<std::net::SocketAddr>,
        ) -> Option<ProcessInfo> {
            assert_eq!(network, Network::Tcp);
            assert_eq!(
                source,
                "127.0.0.1:50000".parse::<std::net::SocketAddr>().unwrap()
            );
            assert_eq!(
                destination,
                Some(
                    "203.0.113.8:8443".parse::<std::net::SocketAddr>().unwrap()
                )
            );
            Some(ProcessInfo {
                process_name: "zay".into(),
                process_path: "/Applications/Zay.app/Contents/MacOS/zay".into(),
                user: "m9".into(),
                user_id: Some(501),
                ..ProcessInfo::default()
            })
        }
    }

    #[test]
    fn process_resolver_enriches_local_flow_before_route_match() {
        let mut router = Router::from_json(
            &[json!({
                "process_name": "zay",
                "user": "m9",
                "user_id": 501,
                "action": "route",
                "outbound": "app"
            })],
            "direct",
        )
        .unwrap();
        router
            .configure_process_resolver(Some(Arc::new(StaticProcessResolver)));
        let metadata = Metadata {
            source: Some("127.0.0.1:50000".parse().unwrap()),
            destination: Some("198.51.100.1:443".parse().unwrap()),
            origin_destination: Some("203.0.113.8:8443".parse().unwrap()),
            network: Some(Network::Tcp),
            ..Metadata::default()
        };
        assert_eq!(router.route(&metadata).outbound(), Some("app"));

        let preset = Metadata {
            process_name: "explicit".into(),
            ..metadata
        };
        assert_eq!(router.route(&preset).outbound(), Some("direct"));
    }

    #[test]
    fn neighbor_resolver_enriches_source_route_metadata() {
        let mut router = Router::from_json(
            &[json!({
                "source_mac_address": "02:00:00:00:00:09",
                "source_hostname": "workstation",
                "action": "route",
                "outbound": "lan"
            })],
            "direct",
        )
        .unwrap();
        router.configure_neighbor_resolver(Some(Arc::new(StaticRouteNeighbor)));
        let metadata = Metadata {
            source: Some("192.0.2.9:50000".parse().unwrap()),
            destination: Some("198.51.100.1:443".parse().unwrap()),
            network: Some(Network::Tcp),
            ..Metadata::default()
        };
        assert_eq!(router.route(&metadata).outbound(), Some("lan"));

        let preset = Metadata {
            source_mac_address: "02:00:00:00:00:10".into(),
            source_hostname: "explicit".into(),
            ..metadata
        };
        assert_eq!(router.route(&preset).outbound(), Some("direct"));
    }

    #[test]
    fn default_rule_combines_matchers_and_routes_first_match() {
        let router = Router::from_json(
            &[
                json!({
                    "domain_suffix": ["example.com"],
                    "network": "tcp",
                    "port_range": "400:500",
                    "action": "route",
                    "outbound": "proxy"
                }),
                json!({
                    "ip_cidr": "10.0.0.0/8",
                    "action": "reject"
                }),
            ],
            "direct",
        )
        .unwrap();
        let metadata = Metadata {
            destination: Some(SocksAddr::new("www.example.com", 443)),
            network: Some(Network::Tcp),
            ..Metadata::default()
        };
        assert_eq!(router.route(&metadata).outbound(), Some("proxy"));

        let private = Metadata {
            destination: Some("10.1.2.3:80".parse().unwrap()),
            network: Some(Network::Tcp),
            ..Metadata::default()
        };
        assert!(matches!(
            router.route(&private).action(),
            Some(Action::Reject { .. })
        ));
    }

    #[test]
    fn private_ip_rules_use_sing_non_public_address_semantics() {
        let destination_router = Router::from_json(
            &[json!({
                "ip_is_private": true,
                "action": "route",
                "outbound": "private"
            })],
            "public",
        )
        .unwrap();
        for address in ["127.0.0.1", "169.254.1.1", "224.0.0.1", "ff02::1"] {
            let metadata = Metadata {
                destination: Some(SocksAddr::new(address, 443)),
                ..Metadata::default()
            };
            assert_eq!(
                destination_router.route(&metadata).outbound(),
                Some("private"),
                "{address} must match ip_is_private"
            );
        }
        let public = Metadata {
            destination: Some(SocksAddr::new("8.8.8.8", 443)),
            ..Metadata::default()
        };
        assert_eq!(
            destination_router.route(&public).outbound(),
            Some("public")
        );

        let source_router = Router::from_json(
            &[json!({
                "source_ip_is_private": true,
                "action": "route",
                "outbound": "private-source"
            })],
            "public-source",
        )
        .unwrap();
        let multicast_source = Metadata {
            source: Some(SocksAddr::new("224.0.0.1", 1234)),
            ..Metadata::default()
        };
        assert_eq!(
            source_router.route(&multicast_source).outbound(),
            Some("private-source")
        );
    }

    #[test]
    fn hardware_address_rules_normalize_go_compatible_spellings() {
        let source_router = Router::from_json(
            &[json!({
                "source_mac_address":"02-00-00-00-00-AB",
                "outbound":"matched"
            })],
            "fallback",
        )
        .unwrap();
        let source = Metadata {
            source_mac_address: "02:00:00:00:00:ab".into(),
            ..Metadata::default()
        };
        assert_eq!(source_router.route(&source).outbound(), Some("matched"));

        let wifi_router = Router::from_json(
            &[json!({
                "wifi_bssid":" 0200000000AB ",
                "outbound":"wifi"
            })],
            "fallback",
        )
        .unwrap();
        let wifi = Metadata {
            wifi_bssid: "02:00:00:00:00:ab".into(),
            ..Metadata::default()
        };
        assert_eq!(wifi_router.route(&wifi).outbound(), Some("wifi"));

        let cisco_router = Router::from_json(
            &[json!({
                "source_mac_address":"0200.0000.00AB",
                "outbound":"cisco"
            })],
            "fallback",
        )
        .unwrap();
        assert_eq!(cisco_router.route(&source).outbound(), Some("cisco"));
    }

    #[test]
    fn reject_flood_protection_is_per_rule_and_honors_no_drop() {
        let metadata = Metadata {
            destination: Some("198.51.100.1:443".parse().unwrap()),
            network: Some(Network::Tcp),
            ..Metadata::default()
        };
        let protected =
            Router::from_json(&[json!({"action": "reject"})], "direct")
                .unwrap();
        for _ in 0..50 {
            assert!(!protected.route(&metadata).reject_is_drop());
        }
        assert!(protected.route(&metadata).reject_is_drop());

        let unprotected = Router::from_json(
            &[json!({"action": "reject", "no_drop": true})],
            "direct",
        )
        .unwrap();
        for _ in 0..51 {
            assert!(!unprotected.route(&metadata).reject_is_drop());
        }

        let second_rule = Router::from_json(
            &[
                json!({
                    "domain": "unmatched.example",
                    "action": "reject"
                }),
                json!({"action": "reject"}),
            ],
            "direct",
        )
        .unwrap();
        assert!(!second_rule.route(&metadata).reject_is_drop());
    }

    #[test]
    fn prematch_preserves_empty_outbound_bypass_as_terminal() {
        let router = Router::from_json(
            &[json!({
                "network": "tcp",
                "action": "bypass"
            })],
            "proxy",
        )
        .unwrap();
        let metadata = Metadata {
            destination: Some("198.51.100.1:443".parse().unwrap()),
            network: Some(Network::Tcp),
            ..Metadata::default()
        };
        assert_eq!(router.route(&metadata).outbound(), Some("proxy"));
        let mut state = router.route_state();
        assert!(matches!(
            router.route_pre_match_next(&metadata, &mut state).action(),
            Some(Action::Bypass { outbound, .. }) if outbound.is_empty()
        ));
    }

    #[test]
    fn logical_and_invert_are_applied() {
        let router = Router::from_json(
            &[json!({
                "type": "logical",
                "mode": "and",
                "rules": [
                    {"domain_keyword": "tracking"},
                    {"port": 443}
                ],
                "invert": true,
                "action": "route",
                "outbound": "safe"
            })],
            "fallback",
        )
        .unwrap();
        let blocked_by_invert = Metadata {
            destination: Some(SocksAddr::new("tracking.example", 443)),
            ..Metadata::default()
        };
        assert_eq!(
            router.route(&blocked_by_invert).outbound(),
            Some("fallback")
        );
        let matches_invert = Metadata {
            destination: Some(SocksAddr::new("www.example", 443)),
            ..Metadata::default()
        };
        assert_eq!(router.route(&matches_invert).outbound(), Some("safe"));
    }

    #[test]
    fn address_matchers_in_the_same_upstream_group_are_or_combined() {
        let router = Router::from_json(
            &[json!({
                "domain": "example.com",
                "ip_cidr": "10.0.0.0/8",
                "action": "route",
                "outbound": "matched"
            })],
            "fallback",
        )
        .unwrap();
        let domain = Metadata {
            destination: Some(SocksAddr::new("example.com", 443)),
            ..Metadata::default()
        };
        assert_eq!(router.route(&domain).outbound(), Some("matched"));
        let address = Metadata {
            destination: Some("10.1.2.3:443".parse().unwrap()),
            ..Metadata::default()
        };
        assert_eq!(router.route(&address).outbound(), Some("matched"));
    }

    #[test]
    fn route_action_overrides_destination_address_and_port() {
        let router = Router::from_json(
            &[json!({
                "domain": "example.com",
                "outbound": "proxy",
                "override_address": "127.0.0.1",
                "override_port": 8443
            })],
            "fallback",
        )
        .unwrap();
        let original = SocksAddr::new("example.com", 443);
        let metadata = Metadata {
            destination: Some(original.clone()),
            ..Metadata::default()
        };
        assert_eq!(
            router.route(&metadata).destination(&original).to_string(),
            "127.0.0.1:8443"
        );
    }

    #[test]
    fn direct_action_accepts_the_full_upstream_dialer_surface() {
        let router = Router::from_json(
            &[json!({
                "action": "direct",
                "bind_interface": "lo0",
                "inet4_bind_address": "127.0.0.2",
                "inet6_bind_address": "::1",
                "bind_address_no_port": true,
                "protect_path": "/tmp/protect.sock",
                "routing_mark": "0x1234",
                "reuse_addr": true,
                "netns": "/run/netns/test",
                "connect_timeout": "2s",
                "tcp_fast_open": true,
                "tcp_multi_path": true,
                "disable_tcp_keep_alive": true,
                "tcp_keep_alive": "30s",
                "tcp_keep_alive_interval": "10s",
                "udp_fragment": false,
                "domain_resolver": {
                    "server": "resolver",
                    "strategy": "prefer_ipv6"
                },
                "network_strategy": "fallback",
                "network_type": ["wifi"],
                "fallback_network_type": ["ethernet"],
                "fallback_delay": "250ms",
                "domain_strategy": "prefer_ipv4"
            })],
            "fallback",
        )
        .unwrap();
        let Some(Action::DirectOptions { options, outbound }) =
            router.rules.first().and_then(|rule| rule.action())
        else {
            panic!("direct options were not compiled")
        };
        assert!(outbound.is_empty());
        assert_eq!(options.bind_interface, "lo0");
        assert_eq!(
            options.inet4_bind_address.unwrap().0.to_string(),
            "127.0.0.2"
        );
        assert_eq!(options.routing_mark.0, 0x1234);
        assert_eq!(
            options
                .domain_resolver
                .as_ref()
                .map(|resolver| resolver.server.as_str()),
            Some("resolver")
        );
        assert_eq!(
            options.fallback_delay.as_std(),
            Some(std::time::Duration::from_millis(250))
        );
    }

    #[test]
    fn direct_action_respects_go_parent_matcher_field_exclusion() {
        let router = Router::from_json(
            &[json!({
                "network_type":"wifi",
                "action":"direct",
                "fallback_network_type":"ethernet"
            })],
            "fallback",
        )
        .unwrap();
        let Some(Rule::Default(rule)) = router.rules.first() else {
            panic!("expected default rule")
        };
        assert_eq!(rule.raw.network_type.as_slice(), ["wifi"]);
        let Action::DirectOptions { options, .. } = &rule.action else {
            panic!("expected direct action")
        };
        assert!(options.network_type.is_empty());
        assert_eq!(options.fallback_network_type.as_slice().len(), 1);

        let router = Router::from_json(
            &[json!({
                "type":"logical",
                "mode":"or",
                "rules":[{"domain":"example.com"}],
                "action":"direct",
                "network_type":"cellular"
            })],
            "fallback",
        )
        .unwrap();
        let Some(Rule::Logical(rule)) = router.rules.first() else {
            panic!("expected logical rule")
        };
        let Action::DirectOptions { options, .. } = &rule.action else {
            panic!("expected direct action")
        };
        assert_eq!(options.network_type.as_slice().len(), 1);

        let error = Router::from_json(
            &[json!({
                "type":"logical",
                "mode":"or",
                "rules":[{"domain":"example.com"}],
                "outbound":"proxy",
                "network_type":"cellular"
            })],
            "fallback",
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid for action"));
    }

    #[test]
    fn route_options_actions_accumulate_and_continue_to_terminal_rule() {
        let router = Router::from_json(
            &[
                json!({
                    "domain_suffix":"example",
                    "action":"route-options",
                    "override_address":"first.test",
                    "tls_fragment":true,
                    "tls_fragment_fallback_delay":"25ms",
                    "network_strategy":"fallback"
                }),
                json!({
                    "domain":"first.test",
                    "action":"route-options",
                    "override_port":8443,
                    "fallback_delay":125000000,
                    "udp_timeout":"45s",
                    "udp_disable_domain_unmapping":true,
                    "udp_connect":true,
                    "tls_spoof":"allowed.example",
                    "tls_spoof_method":"wrong-ack"
                }),
                json!({
                    "port":8443,
                    "outbound":"proxy",
                    "override_address":"terminal.test"
                }),
            ],
            "direct",
        )
        .unwrap();
        let original = SocksAddr::new("www.example", 443);
        let metadata = Metadata {
            destination: Some(original.clone()),
            ..Metadata::default()
        };
        let decision = router.route(&metadata);
        assert_eq!(decision.outbound(), Some("proxy"));
        assert_eq!(
            decision.destination(&original).to_string(),
            "terminal.test:8443"
        );
        let options = decision.connection_options();
        assert!(options.tls_fragment);
        assert_eq!(
            options.tls_fragment_fallback_delay,
            Some(std::time::Duration::from_millis(25))
        );
        assert!(!options.tls_record_fragment);
        assert_eq!(
            options.network.strategy,
            Some(crate::constant::NetworkStrategy::Fallback)
        );
        assert!(options.network.network_type.is_empty());
        assert!(options.network.fallback_network_type.is_empty());
        assert_eq!(
            options.network.fallback_delay,
            Some(std::time::Duration::from_millis(125))
        );
        assert_eq!(
            options.udp_timeout,
            Some(std::time::Duration::from_secs(45))
        );
        assert!(options.network.udp_disable_domain_unmapping);
        assert!(options.network.udp_connect);
        assert!(options.network.external_connection);
        assert_eq!(options.tls_spoof, "allowed.example");
        assert_eq!(
            options.tls_spoof_method,
            crate::common::tls_spoof::TlsSpoofMethod::WrongAcknowledgment
        );

        let error = Router::from_json(
            &[json!({
                "action":"route-options",
                "tls_fragment":true,
                "tls_record_fragment":true
            })],
            "",
        )
        .unwrap_err();
        assert!(error.to_string().contains("mutually exclusive"));
        Router::from_json(
            &[json!({
                "action":"route",
                "tls_fragment":true,
                "tls_record_fragment":true
            })],
            "",
        )
        .unwrap();
    }

    #[test]
    fn rejects_invalid_regex_prefix_and_range() {
        assert!(Router::from_json(&[json!({"type": 7})], "").is_err());
        assert!(
            Router::from_json(&[json!({"domain_regex": "["})], "").is_err()
        );
        assert!(
            Router::from_json(&[json!({"ip_cidr": "10.0.0.1/99"})], "")
                .is_err()
        );
        assert!(
            Router::from_json(&[json!({"port_range": "400-500"})], "").is_err()
        );
        for (rule, expected) in [
            (
                json!({"domain":["example.com", ""]}),
                "domain: empty item is not allowed",
            ),
            (
                json!({"domain_suffix":["example.com", ""]}),
                "domain_suffix: empty item is not allowed",
            ),
        ] {
            let error = Router::from_json(&[rule], "").unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn port_ranges_accept_go_open_and_descending_forms() {
        let router = Router::from_json(
            &[
                json!({"port_range":":1024", "outbound":"low"}),
                json!({"port_range":"49152:", "outbound":"high"}),
                json!({"port_range":"500:400", "outbound":"never"}),
            ],
            "fallback",
        )
        .unwrap();
        for (port, expected) in [
            (0, "low"),
            (1024, "low"),
            (1025, "fallback"),
            (49152, "high"),
            (u16::MAX, "high"),
            (450, "low"),
        ] {
            let metadata = Metadata {
                destination: Some(SocksAddr::new("example.com", port)),
                ..Metadata::default()
            };
            assert_eq!(router.route(&metadata).outbound(), Some(expected));
        }
        let descending = Router::from_json(
            &[json!({"port_range":"500:400", "outbound":"never"})],
            "fallback",
        )
        .unwrap();
        let middle = Metadata {
            destination: Some(SocksAddr::new("example.com", 450)),
            ..Metadata::default()
        };
        assert_eq!(descending.route(&middle).outbound(), Some("fallback"));
    }

    #[test]
    fn ip_version_prefers_concrete_destination_then_explicit_metadata() {
        let router = Router::from_json(
            &[
                json!({"ip_version":4, "outbound":"ipv4"}),
                json!({"ip_version":6, "outbound":"ipv6"}),
            ],
            "fallback",
        )
        .unwrap();
        let explicit = Metadata {
            ip_version: Some(6),
            destination: Some(SocksAddr::new("example.com", 443)),
            ..Metadata::default()
        };
        assert_eq!(router.route(&explicit).outbound(), Some("ipv6"));

        let concrete = Metadata {
            ip_version: Some(6),
            destination: Some(SocksAddr::new("192.0.2.1", 443)),
            ..Metadata::default()
        };
        assert_eq!(router.route(&concrete).outbound(), Some("ipv4"));

        let error = Router::from_json(
            &[json!({"ip_version":5, "outbound":"invalid"})],
            "fallback",
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("invalid ip version: 5"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_unimplemented_matchers_actions_and_nested_actions() {
        for rule in [
            json!({"action":"direct","override_port":443}),
            json!({
                "type":"logical",
                "mode":"or",
                "rules":[{"domain":"example.com","outbound":"bad"}],
                "outbound":"direct"
            }),
        ] {
            let error = Router::from_json(&[rule], "").unwrap_err();
            assert!(
                error.to_string().contains("not implemented")
                    || error.to_string().contains("nested rules")
                    || error.to_string().contains("invalid for action"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn deprecated_route_matchers_report_go_compatible_errors() {
        for (rule, expected) in [
            (
                json!({"geosite":"cn","outbound":"direct"}),
                "geosite database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0",
            ),
            (
                json!({"source_geoip":"private","outbound":"direct"}),
                "geoip database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0",
            ),
            (
                json!({"geoip":"cn","outbound":"direct"}),
                "geoip database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0",
            ),
            (
                json!({
                    "rule_set":"missing",
                    "rule_set_ipcidr_match_source":true,
                    "outbound":"direct"
                }),
                "rule_set_ipcidr_match_source is deprecated in sing-box 1.10.0 and removed in sing-box 1.11.0",
            ),
        ] {
            let error = Router::from_json(&[rule], "").unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "unexpected error: {error}"
            );
        }

        Router::from_json(
            &[json!({
                "rule_set_ipcidr_match_source":true,
                "outbound":"direct"
            })],
            "",
        )
        .expect("Go ignores the deprecated spelling without rule_set");
    }

    #[test]
    fn compiles_sniff_actions_and_validates_sniffer_names() {
        let router = Router::from_json(
            &[json!({
                "action": "sniff",
                "sniffer": ["tls", "http", "dns", "bittorrent"],
                "timeout": "750ms"
            })],
            "direct",
        )
        .unwrap();
        let decision = router.route(&Metadata::default());
        let Some(Action::Sniff(options)) = decision.action() else {
            panic!("expected sniff action");
        };
        assert_eq!(options.timeout, std::time::Duration::from_millis(750));
        assert_eq!(options.stream_sniffers.len(), 4);
        assert_eq!(options.packet_sniffers.len(), 3);
        assert!(
            Router::from_json(
                &[json!({"action": "sniff", "sniffer": "unknown"})],
                ""
            )
            .is_err()
        );
    }

    #[test]
    fn ordered_route_state_does_not_revisit_rules_before_sniff() {
        let router = Router::from_json(
            &[
                json!({"protocol":"http","outbound":"wrong"}),
                json!({"action":"sniff","sniffer":"http"}),
                json!({"protocol":"http","outbound":"right"}),
            ],
            "direct",
        )
        .unwrap();
        let mut metadata = Metadata {
            destination: Some(SocksAddr::new("192.0.2.1", 80)),
            ..Metadata::default()
        };
        let mut state = router.route_state();
        assert!(matches!(
            router.route_next(&metadata, &mut state).action(),
            Some(Action::Sniff(_))
        ));
        metadata.protocol = "http".into();
        assert_eq!(
            router.route_next(&metadata, &mut state).outbound(),
            Some("right")
        );
    }

    #[test]
    fn ordered_route_state_carries_overrides_into_nonterminal_actions() {
        let router = Router::from_json(
            &[
                json!({
                    "action":"route-options",
                    "override_address":"resolved.example",
                    "override_port":5353
                }),
                json!({"action":"resolve"}),
            ],
            "direct",
        )
        .unwrap();
        let original = SocksAddr::new("original.example", 53);
        let metadata = Metadata {
            destination: Some(original.clone()),
            ..Metadata::default()
        };
        let mut state = router.route_state();
        let decision = router.route_next(&metadata, &mut state);
        assert!(matches!(decision.action(), Some(Action::Resolve(_))));
        assert_eq!(
            decision.destination(&original).to_string(),
            "resolved.example:5353"
        );
    }

    #[test]
    fn inline_rule_sets_match_any_headless_rule_and_compose_with_outer_rule() {
        let router = Router::from_json_with_rule_sets(
            &[
                json!({
                    "network":"tcp",
                    "rule_set":["geo-cn", "private"],
                    "outbound":"proxy"
                }),
                json!({"outbound":"direct"}),
            ],
            "",
            &[
                json!({
                    "type":"inline",
                    "tag":"geo-cn",
                    "rules":[
                        {"domain_suffix":"cn"},
                        {"type":"logical","mode":"and","rules":[
                            {"domain_keyword":"internal"},
                            {"port":443}
                        ]}
                    ]
                }),
                json!({
                    "type":"inline",
                    "tag":"private",
                    "rules":[{"ip_cidr":["10.0.0.0/8"]}]
                }),
            ],
            std::path::Path::new("."),
        )
        .unwrap();
        assert_eq!(router.rule_set_tags().count(), 2);

        let cn = Metadata {
            destination: Some(SocksAddr::new("www.example.cn", 80)),
            network: Some(Network::Tcp),
            ..Metadata::default()
        };
        assert_eq!(router.route(&cn).outbound(), Some("proxy"));

        let private_udp = Metadata {
            destination: Some(SocksAddr::new("10.1.2.3", 53)),
            network: Some(Network::Udp),
            ..Metadata::default()
        };
        assert_eq!(router.route(&private_udp).outbound(), Some("direct"));

        let logical = Metadata {
            destination: Some(SocksAddr::new("internal.example", 443)),
            network: Some(Network::Tcp),
            ..Metadata::default()
        };
        assert_eq!(router.route(&logical).outbound(), Some("proxy"));
    }

    #[test]
    fn extracts_destination_prefixes_from_nested_rule_sets_for_tun_routes() {
        let router = Router::from_json_with_rule_sets(
            &[],
            "direct",
            &[json!({
                "type":"inline",
                "tag":"tun-routes",
                "rules":[
                    {"source_ip_cidr":"192.0.2.0/24","ip_cidr":"10.0.0.0/8"},
                    {"type":"logical","mode":"or","rules":[
                        {"ip_cidr":["2001:db8::/32","172.16.0.0/12"]},
                        {"domain_suffix":"example"}
                    ]}
                ]
            })],
            std::path::Path::new("."),
        )
        .unwrap();
        assert_eq!(
            router
                .rule_set_destination_prefixes(&["tun-routes".into()])
                .unwrap(),
            [
                "10.0.0.0/8".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
                "172.16.0.0/12".parse().unwrap()
            ]
        );
    }

    #[test]
    fn singleton_default_rule_set_merges_address_match_groups() {
        let router = Router::from_json_with_rule_sets(
            &[json!({
                "domain_suffix":"example",
                "rule_set":"private",
                "outbound":"merged"
            })],
            "fallback",
            &[json!({
                "type":"inline",
                "tag":"private",
                "rules":[{"ip_cidr":"10.0.0.0/8"}]
            })],
            std::path::Path::new("."),
        )
        .unwrap();
        let metadata = Metadata {
            destination: Some(SocksAddr::new("10.2.3.4", 443)),
            ..Metadata::default()
        };
        assert_eq!(router.route(&metadata).outbound(), Some("merged"));
    }

    #[test]
    fn rule_set_ip_cidr_can_match_source_address() {
        let rule_sets = [json!({
            "type":"inline",
            "tag":"lan",
            "rules":[{"ip_cidr":"10.0.0.0/8"}]
        })];
        let source_router = Router::from_json_with_rule_sets(
            &[json!({
                "rule_set":"lan",
                "rule_set_ip_cidr_match_source":true,
                "outbound":"source"
            })],
            "miss",
            &rule_sets,
            std::path::Path::new("."),
        )
        .unwrap();
        let destination_router = Router::from_json_with_rule_sets(
            &[json!({"rule_set":"lan","outbound":"destination"})],
            "miss",
            &rule_sets,
            std::path::Path::new("."),
        )
        .unwrap();
        let metadata = Metadata {
            source: Some(SocksAddr::new("10.1.2.3", 1234)),
            destination: Some(SocksAddr::new("203.0.113.1", 443)),
            ..Metadata::default()
        };
        assert_eq!(source_router.route(&metadata).outbound(), Some("source"));
        assert_eq!(
            destination_router.route(&metadata).outbound(),
            Some("miss")
        );
    }

    #[test]
    fn matches_interface_addresses_and_preferred_routes() {
        let router = Router::from_json(
            &[json!({
                "interface_address": {
                    "en0": ["192.168.1.0/24", "2001:db8::/32"]
                },
                "network_interface_address": {
                    "wifi": "10.0.0.0/8",
                    "ethernet": "172.16.0.0/12"
                },
                "default_interface_address": ["100.64.0.0/10"],
                "preferred_by": ["wg", "tailscale"],
                "outbound": "matched"
            })],
            "fallback",
        )
        .unwrap();
        let mut metadata = Metadata {
            preferred_by: vec!["wg".into()],
            default_interface_address: vec!["100.64.1.2".parse().unwrap()],
            ..Metadata::default()
        };
        metadata.interface_address.insert(
            "en0".into(),
            vec![
                "192.168.1.2".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
        );
        metadata
            .network_interface_address
            .insert("wifi".into(), vec!["10.1.2.3".parse().unwrap()]);
        metadata
            .network_interface_address
            .insert("ethernet".into(), vec!["172.20.1.1".parse().unwrap()]);
        assert_eq!(router.route(&metadata).outbound(), Some("matched"));
        metadata.network_interface_address.remove("ethernet");
        assert_eq!(router.route(&metadata).outbound(), Some("fallback"));
    }

    #[test]
    fn preferred_by_references_only_route_aware_outbounds() {
        let manager = Arc::new(
            OutboundManager::from_options(
                &serde_json::from_value::<Options>(json!({
                    "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                    "outbounds":[
                        {"type":"direct","tag":"direct"},
                        {"type":"bridge","tag":"bridge","interface":"en0"}
                    ]
                }))
                .unwrap(),
                "direct",
            )
            .unwrap(),
        );

        let supported = Router::from_json(
            &[json!({
                "type":"logical",
                "mode":"and",
                "rules":[{"preferred_by":"bridge"}],
                "outbound":"bridge"
            })],
            "direct",
        )
        .unwrap();
        supported.validate_preferred_outbounds(&manager).unwrap();

        for (tag, expected) in [
            ("missing", "invalid route rule: outbound not found: missing"),
            (
                "direct",
                "invalid route rule: outbound type does not support preferred routes: direct",
            ),
        ] {
            let router = Router::from_json(
                &[json!({"preferred_by":tag,"outbound":"direct"})],
                "direct",
            )
            .unwrap();
            assert_eq!(
                router
                    .validate_preferred_outbounds(&manager)
                    .unwrap_err()
                    .to_string(),
                expected
            );
        }

        let mut router = Router::from_json(
            &[json!({"preferred_by":"bridge","outbound":"bridge"})],
            "direct",
        )
        .unwrap();
        router.configure_preferred_outbounds(&manager);
        let metadata = Metadata {
            destination: Some("198.51.100.9:443".parse().unwrap()),
            ..Metadata::default()
        };
        assert_eq!(router.route(&metadata).outbound(), Some("direct"));
        assert_eq!(
            router
                .route_pre_match_next(&metadata, &mut router.route_state())
                .outbound(),
            Some("bridge")
        );
    }

    #[test]
    fn route_options_recomputes_endpoint_preference_for_overridden_address() {
        let manager = Arc::new(
            OutboundManager::from_options(
                &serde_json::from_value::<Options>(json!({
                    "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                    "outbounds":[{"type":"direct","tag":"direct"}]
                }))
                .unwrap(),
                "direct",
            )
            .unwrap(),
        );
        manager
            .register_endpoint(
                "old",
                "wireguard",
                Arc::new(PreferredRouteDialer("203.0.113.8".parse().unwrap())),
            )
            .unwrap();
        manager
            .register_endpoint(
                "new",
                "wireguard",
                Arc::new(PreferredRouteDialer("198.51.100.9".parse().unwrap())),
            )
            .unwrap();
        let mut router = Router::from_json(
            &[
                json!({
                    "action":"route-options",
                    "override_address":"198.51.100.9"
                }),
                json!({"preferred_by":"old","outbound":"old"}),
                json!({"preferred_by":"new","outbound":"new"}),
            ],
            "direct",
        )
        .unwrap();
        router.configure_preferred_outbounds(&manager);
        router.validate_preferred_outbounds(&manager).unwrap();

        let metadata = Metadata {
            destination: Some("203.0.113.8:443".parse().unwrap()),
            destination_addresses: vec!["203.0.113.8".parse().unwrap()],
            ..Metadata::default()
        };
        assert_eq!(router.route(&metadata).outbound(), Some("new"));
        let mut state = router.route_state();
        assert_eq!(
            router.route_next(&metadata, &mut state).outbound(),
            Some("new")
        );
        assert_eq!(
            router
                .route_pre_match_next(&metadata, &mut router.route_state())
                .outbound(),
            Some("old")
        );
    }

    #[test]
    fn local_source_rule_sets_support_versions_comments_and_tag_templates() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("alpha.json"),
            r#"{
                // compatible with sing-box source rule-set files
                "version": 5,
                "rules": [{"domain": "alpha.example"}]
            }"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("beta.json"),
            r#"{"version":1,"rules":[{"query_type":28}]}"#,
        )
        .unwrap();
        let router = Router::from_json_with_rule_sets(
            &[json!({"rule_set":["alpha","beta"],"outbound":"hit"})],
            "miss",
            &[json!({
                "type":"local",
                "tag":["alpha","beta"],
                "path":"{tag}.json"
            })],
            directory.path(),
        )
        .unwrap();
        let domain = Metadata {
            destination: Some(SocksAddr::new("alpha.example", 443)),
            ..Metadata::default()
        };
        assert_eq!(router.route(&domain).outbound(), Some("hit"));
        let query = Metadata {
            query_type: Some(28),
            ..Metadata::default()
        };
        assert_eq!(router.route(&query).outbound(), Some("hit"));
    }

    #[test]
    fn rule_set_validation_rejects_unknown_references_and_invalid_shapes() {
        assert!(
            Router::from_json(&[json!({"rule_set":"missing"})], "")
                .unwrap_err()
                .to_string()
                .contains("rule-set not found")
        );
        assert!(
            Router::from_json_with_rule_sets(
                &[],
                "",
                &[json!({"type":"inline","tag":["a","b"],"rules":[{"domain":"x"}]})],
                std::path::Path::new("."),
            )
            .is_err()
        );
        assert!(
            Router::from_json_with_rule_sets(
                &[],
                "",
                &[json!({"type":"inline","tag":"empty","rules":[]})],
                std::path::Path::new("."),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn remote_rule_set_fetches_and_revalidates_with_etag() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (revalidated_tx, revalidated_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut revalidated_tx = Some(revalidated_tx);
            for request_index in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0_u8; 1024];
                    let size = stream.read(&mut buffer).await.unwrap();
                    if size == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..size]);
                    if request.windows(4).any(|part| part == b"\r\n\r\n") {
                        break;
                    }
                }
                if request_index == 0 {
                    let body = br#"{"version":5,"rules":[{"domain":"remote.example"}]}"#;
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(header.as_bytes()).await.unwrap();
                    stream.write_all(body).await.unwrap();
                } else {
                    let request = String::from_utf8(request).unwrap();
                    assert!(request.contains("if-none-match: \"v1\""));
                    stream
                        .write_all(
                            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    let _ = revalidated_tx.take().unwrap().send(());
                }
            }
        });
        let router = Router::from_json_with_rule_sets(
            &[json!({"rule_set":"remote","outbound":"hit"})],
            "miss",
            &[json!({
                "type":"remote",
                "tag":"remote",
                "format":"source",
                "url":format!("http://{address}/rules.json"),
                "update_interval":"50ms"
            })],
            std::path::Path::new("."),
        )
        .unwrap();
        router.start().await.unwrap();
        let metadata = Metadata {
            destination: Some(SocksAddr::new("remote.example", 443)),
            ..Metadata::default()
        };
        assert_eq!(router.route(&metadata).outbound(), Some("hit"));
        tokio::time::timeout(std::time::Duration::from_secs(2), revalidated_rx)
            .await
            .unwrap()
            .unwrap();
        router.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn remote_rule_set_uses_initial_path_before_network() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("initial.json"),
            r#"{"version":5,"rules":[{"domain":"initial.example"}]}"#,
        )
        .unwrap();
        let router = Router::from_json_with_rule_sets(
            &[json!({"rule_set":"remote","outbound":"hit"})],
            "miss",
            &[json!({
                "type":"remote",
                "tag":"remote",
                "format":"source",
                "url":"http://127.0.0.1:1/unreachable.json",
                "initial_path":"initial.json",
                "update_interval":"1h"
            })],
            directory.path(),
        )
        .unwrap();
        router.start().await.unwrap();
        let metadata = Metadata {
            destination: Some(SocksAddr::new("initial.example", 443)),
            ..Metadata::default()
        };
        assert_eq!(router.route(&metadata).outbound(), Some("hit"));
        router.close().await;
    }

    #[tokio::test]
    async fn remote_rule_set_restores_from_persistent_cache() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            PersistentDnsCache::open(directory.path().join("cache.db"), "")
                .unwrap(),
        );
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0_u8; 512];
                let size = stream.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..size]);
                if size == 0
                    || request.windows(4).any(|part| part == b"\r\n\r\n")
                {
                    break;
                }
            }
            let body =
                br#"{"version":5,"rules":[{"domain":"cached.example"}]}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: cached-v1\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(body).await.unwrap();
        });
        let url = format!("http://{address}/rules.json");
        let rules = [json!({"rule_set":"remote","outbound":"hit"})];
        let sets = [json!({
            "type":"remote", "tag":"remote", "format":"source",
            "url":url, "update_interval":"1h"
        })];
        let first = Router::from_json_with_rule_sets_and_cache(
            &rules,
            "miss",
            &sets,
            directory.path(),
            Some(cache.clone()),
        )
        .unwrap();
        first.start().await.unwrap();
        server.await.unwrap();
        first.close().await;

        let restarted = Router::from_json_with_rule_sets_and_cache(
            &rules,
            "miss",
            &sets,
            directory.path(),
            Some(cache),
        )
        .unwrap();
        let metadata = Metadata {
            destination: Some(SocksAddr::new("cached.example", 443)),
            ..Metadata::default()
        };
        assert_eq!(restarted.route(&metadata).outbound(), Some("hit"));
        restarted.start().await.unwrap();
        restarted.close().await;
    }

    #[tokio::test]
    async fn local_rule_set_reloads_after_file_change() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rules.json");
        std::fs::write(
            &path,
            r#"{"version":5,"rules":[{"domain":"before.example"}]}"#,
        )
        .unwrap();
        let router = Router::from_json_with_rule_sets(
            &[json!({"rule_set":"local","outbound":"hit"})],
            "miss",
            &[json!({
                "type":"local",
                "tag":"local",
                "path":"rules.json"
            })],
            directory.path(),
        )
        .unwrap();
        router.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        std::fs::write(
            &path,
            r#"{"version":5,"rules":[{"domain":"after.example"}]}"#,
        )
        .unwrap();
        let after = Metadata {
            destination: Some(SocksAddr::new("after.example", 443)),
            ..Metadata::default()
        };
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while router.route(&after).outbound() != Some("hit") {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        let before = Metadata {
            destination: Some(SocksAddr::new("before.example", 443)),
            ..Metadata::default()
        };
        assert_eq!(router.route(&before).outbound(), Some("miss"));
        router.close().await;
    }

    #[tokio::test]
    async fn rule_set_metadata_and_updates_publish_atomic_snapshots() {
        let router = Router::from_json_with_rule_sets(
            &[json!({"rule_set":"dynamic","outbound":"hit"})],
            "miss",
            &[json!({
                "type":"inline",
                "tag":"dynamic",
                "rules":[{"ip_cidr":"10.0.0.0/8"}]
            })],
            std::path::Path::new("."),
        )
        .unwrap();
        let rule_set = router.rule_set("dynamic").unwrap();
        let initial = rule_set.metadata();
        assert!(initial.contains_ip_cidr_rule);
        assert!(!initial.contains_non_ip_cidr_rule);
        assert_eq!(rule_set.generation(), 0);

        let mut updates = rule_set.subscribe();
        assert_eq!(updates.borrow().generation, 0);
        assert!(
            rule_set
                .reload_bytes(
                    "source",
                    br#"{"version":99,"rules":[{"domain":"bad.example"}]}"#,
                    "test",
                )
                .is_err()
        );
        assert!(!updates.has_changed().unwrap());
        assert!(rule_set.matches(&Metadata {
            destination: Some(SocksAddr::new("10.1.2.3", 443)),
            ..Metadata::default()
        }));

        rule_set
            .reload_bytes(
                "source",
                br#"{"version":5,"rules":[{"domain":"after.example"},{"process_name":"zay"},{"wifi_ssid":"office"},{"query_type":"A"}]}"#,
                "test",
            )
            .unwrap();
        updates.changed().await.unwrap();
        let update = *updates.borrow_and_update();
        assert_eq!(update.generation, 1);
        assert_eq!(rule_set.generation(), 1);
        assert_eq!(rule_set.metadata(), update.metadata);
        assert!(!update.metadata.contains_ip_cidr_rule);
        assert!(update.metadata.contains_non_ip_cidr_rule);
        assert!(update.metadata.contains_process_rule);
        assert!(update.metadata.contains_wifi_rule);
        assert!(update.metadata.contains_dns_query_type_rule);
        assert!(rule_set.matches(&Metadata {
            destination: Some(SocksAddr::new("after.example", 443)),
            ..Metadata::default()
        }));
        assert!(!rule_set.matches(&Metadata {
            destination: Some(SocksAddr::new("10.1.2.3", 443)),
            ..Metadata::default()
        }));
    }

    #[tokio::test]
    async fn rule_set_validator_rejects_metadata_before_atomic_commit() {
        let router = Router::from_json_with_rule_sets(
            &[],
            "",
            &[json!({
                "type":"inline",
                "tag":"dynamic",
                "rules":[{"domain":"before.example"}]
            })],
            std::path::Path::new("."),
        )
        .unwrap();
        let rule_set = router.rule_set("dynamic").unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let validator_calls = calls.clone();
        rule_set.add_update_validator(Arc::new(
            move |tag: &str, metadata: RuleSetMetadata| {
                assert_eq!(tag, "dynamic");
                validator_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if metadata.contains_dns_query_type_rule {
                    Err("dns conflict".into())
                } else {
                    Ok(())
                }
            },
        ));

        let mut updates = rule_set.subscribe();
        let initial = *updates.borrow_and_update();
        assert_eq!(initial.generation, 0);
        let error = rule_set
            .reload_bytes(
                "source",
                br#"{"version":5,"rules":[{"query_type":"A"}]}"#,
                "test",
            )
            .unwrap_err();
        assert!(error.to_string().contains("dns conflict"), "{error}");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(rule_set.generation(), 0);
        assert!(!updates.has_changed().unwrap());
        assert!(rule_set.matches(&Metadata {
            destination: Some(SocksAddr::new("before.example", 443)),
            ..Metadata::default()
        }));
    }

    #[test]
    fn binary_rule_set_keeps_succinct_domain_matchers_compact() {
        let source = SourceRuleSet {
            version: 5,
            rules: vec![serde_json::from_value(json!({
                "domain":["only.example"],
                "domain_suffix":["example.com", ".children.only", "例子.测试"],
                "adguard_domain":["||ads.example^", "|exact.test^", "track*pixel^"]
            }))
            .unwrap()],
        };
        let encoded = source.compile().unwrap();
        let rules = decode_rule_set("binary", &encoded, "memory").unwrap();
        let [HeadlessRule::Default(rule)] = rules.as_slice() else {
            panic!("expected one default rule");
        };
        assert!(rule.base.raw.domain.as_slice().is_empty());
        assert!(rule.base.raw.domain_suffix.as_slice().is_empty());
        assert!(rule.adguard_regex.is_empty());
        assert!(rule.compact_domain.is_some());
        assert!(rule.compact_adguard.is_some());

        let matches = |domain: &str| {
            rules[0].matches_with_ip_source(
                &Metadata {
                    destination: Some(SocksAddr::new(domain, 443)),
                    ..Metadata::default()
                },
                false,
            )
        };
        assert!(matches("only.example"));
        assert!(!matches("sub.only.example"));
        assert!(matches("example.com"));
        assert!(matches("www.example.com"));
        assert!(!matches("children.only"));
        assert!(matches("www.children.only"));
        assert!(matches("例子.测试"));
        assert!(matches("子.例子.测试"));
        assert!(matches("ads.example"));
        assert!(matches("sub.ads.example"));
        assert!(!matches("badads.example"));
        assert!(matches("exact.test"));
        assert!(!matches("sub.exact.test"));
        assert!(matches("prefix-track-any-pixel"));
        assert!(!matches("prefix-track-any-pixel-more"));
        assert!(!matches("unrelated.example"));
    }

    #[test]
    fn validates_reject_method_and_override_types() {
        assert!(
            Router::from_json(
                &[json!({"action":"reject","method":"unknown"})],
                ""
            )
            .is_err()
        );
        assert!(
            Router::from_json(
                &[json!({"action":"reject","method":"drop","no_drop":true})],
                ""
            )
            .is_err()
        );
        assert!(
            Router::from_json(&[json!({"override_port":"443"})], "").is_err()
        );
    }
}
