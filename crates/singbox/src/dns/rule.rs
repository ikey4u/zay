//! DNS rule selection for resolver lookups and raw DNS exchanges.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    net::IpAddr,
    sync::{Arc, RwLock, Weak},
    time::{Duration, Instant},
};

use futures_util::{FutureExt as _, StreamExt as _, stream::FuturesUnordered};
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::opt::{ClientSubnet, EdnsCode, EdnsOption},
    },
};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    adapter::dns_response_addresses,
    common::network::is_private_address,
    dns::{
        LookupFuture, LookupOptions, MessageFuture, Resolver, apply_strategy,
        persistent::PersistentDnsCache,
    },
    option::{
        DNS_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE, DnsRecordOptions,
        DomainStrategy, Duration as ConfigDuration, Listable, Prefixable,
    },
    route::{
        DnsContextMatcher, Metadata as RouteMetadata, Router, RuleSetMetadata,
    },
};

pub type ResolverMap = HashMap<String, Arc<dyn Resolver>>;

#[derive(Debug, thiserror::Error)]
pub enum DnsRuleError {
    #[error("invalid DNS rule: {0}")]
    Invalid(String),
    #[error("DNS rule references missing server {0:?}")]
    MissingServer(String),
    #[error(
        "DNS rule field {0:?} is not supported by domain lookup routing yet"
    )]
    UnsupportedField(String),
}

pub struct RoutingResolver {
    rules: Vec<DnsRule>,
    resolvers: ResolverMap,
    fallback: Arc<dyn Resolver>,
    has_message_matchers: bool,
    checked_selectors: HashSet<ResponseSelector>,
    rdrc: Option<RdrcOptions>,
    clash_mode: RwLock<Option<String>>,
    rule_set_router: Arc<RwLock<Option<Weak<Router>>>>,
    legacy_dns_mode: bool,
    mode_guard: Arc<RuleSetModeGuard>,
}

struct RuleSetModeGuard {
    raw_rules: Vec<Value>,
    legacy_dns_mode: bool,
}

#[derive(Clone)]
pub struct RdrcOptions {
    pub cache: Arc<PersistentDnsCache>,
    pub timeout: Duration,
}

impl RoutingResolver {
    pub fn compile(
        values: &[Value],
        resolvers: ResolverMap,
        fallback: Arc<dyn Resolver>,
    ) -> Result<Self, DnsRuleError> {
        Self::compile_with_fakeip_servers(
            values,
            resolvers,
            fallback,
            &HashSet::new(),
        )
    }

    pub fn compile_with_fakeip_servers(
        values: &[Value],
        resolvers: ResolverMap,
        fallback: Arc<dyn Resolver>,
        fakeip_servers: &HashSet<String>,
    ) -> Result<Self, DnsRuleError> {
        Self::compile_with_runtime_cache(
            values,
            resolvers,
            fallback,
            fakeip_servers,
            None,
        )
    }

    pub fn compile_with_runtime_cache(
        values: &[Value],
        resolvers: ResolverMap,
        fallback: Arc<dyn Resolver>,
        fakeip_servers: &HashSet<String>,
        rdrc: Option<RdrcOptions>,
    ) -> Result<Self, DnsRuleError> {
        Self::compile_with_runtime_cache_and_rule_sets(
            values,
            resolvers,
            fallback,
            fakeip_servers,
            rdrc,
            None,
        )
    }

    pub(crate) fn compile_with_runtime_cache_and_rule_sets(
        values: &[Value],
        resolvers: ResolverMap,
        fallback: Arc<dyn Resolver>,
        fakeip_servers: &HashSet<String>,
        rdrc: Option<RdrcOptions>,
        router: Option<&Router>,
    ) -> Result<Self, DnsRuleError> {
        let legacy_dns_mode =
            resolve_legacy_dns_mode_with_rule_sets(values, router, None)?;
        if !legacy_dns_mode && let Some(router) = router {
            validate_modern_rule_set_metadata(values, router, None)?;
        }
        let rule_set_router = Arc::new(RwLock::new(None));
        let rules = values
            .iter()
            .map(|value| {
                DnsRule::compile(
                    value,
                    false,
                    &resolvers,
                    rule_set_router.clone(),
                    legacy_dns_mode,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut has_anonymous_evaluation = false;
        let mut evaluation_tags = HashSet::new();
        for rule in &rules {
            let mut requires_anonymous = false;
            let mut required_tags = Vec::new();
            rule.response_requirements(
                &mut requires_anonymous,
                &mut required_tags,
            );
            if rule.race() {
                if !rule.action().is_terminal() {
                    return Err(DnsRuleError::Invalid(
                        "race requires a final action".into(),
                    ));
                }
                if !requires_anonymous && required_tags.is_empty() {
                    return Err(DnsRuleError::Invalid(
                        "race requires match_response".into(),
                    ));
                }
                if rule.action().speculative() {
                    return Err(DnsRuleError::Invalid(
                        "race and speculative cannot be combined on the same rule"
                            .into(),
                    ));
                }
            }
            if requires_anonymous && !has_anonymous_evaluation {
                return Err(DnsRuleError::Invalid(
                    "match_response requires a preceding anonymous evaluate action"
                        .into(),
                ));
            }
            if let Some(tag) = required_tags
                .iter()
                .find(|tag| !evaluation_tags.contains(**tag))
            {
                return Err(DnsRuleError::Invalid(format!(
                    "match_response references unevaluated tag {tag:?}"
                )));
            }
            match rule.action() {
                DnsAction::Evaluate { server, .. }
                    if fakeip_servers.contains(server) =>
                {
                    return Err(DnsRuleError::Invalid(format!(
                        "evaluate action cannot use fakeip server: {server}"
                    )));
                }
                DnsAction::Evaluate { tag: Some(tag), .. } => {
                    evaluation_tags.insert(tag.clone());
                }
                DnsAction::Evaluate { tag: None, .. } => {
                    has_anonymous_evaluation = true;
                }
                DnsAction::Respond
                    if rule.response_selector().is_none()
                        && !has_anonymous_evaluation =>
                {
                    return Err(DnsRuleError::Invalid(
                        "respond action requires a preceding evaluate action"
                            .into(),
                    ));
                }
                _ => {}
            }
            if let Some(server) = rule.action().server()
                && !resolvers.contains_key(server)
            {
                return Err(DnsRuleError::MissingServer(server.clone()));
            }
        }
        let has_message_matchers = legacy_dns_mode
            || rules.iter().any(DnsRule::requires_message_lookup);
        let mut checked_selectors = HashSet::new();
        for rule in &rules {
            let mut selectors = Vec::new();
            rule.response_selectors(&mut selectors);
            checked_selectors.extend(selectors);
        }
        Ok(Self {
            rules,
            resolvers,
            fallback,
            has_message_matchers,
            checked_selectors,
            rdrc,
            clash_mode: RwLock::new(None),
            rule_set_router,
            legacy_dns_mode,
            mode_guard: Arc::new(RuleSetModeGuard {
                raw_rules: values.to_vec(),
                legacy_dns_mode,
            }),
        })
    }

    pub(crate) fn configure_rule_set_router(
        &self,
        router: &Arc<Router>,
    ) -> Result<(), DnsRuleError> {
        if !self.legacy_dns_mode {
            validate_modern_rule_set_metadata(
                &self.mode_guard.raw_rules,
                router,
                None,
            )?;
        }
        for rule in &self.rules {
            rule.validate_rule_sets(router)?;
        }
        *self
            .rule_set_router
            .write()
            .expect("DNS rule-set router lock poisoned") =
            Some(Arc::downgrade(router));
        for tag in router.rule_set_tags() {
            let Some(rule_set) = router.rule_set(tag) else {
                continue;
            };
            let mode_guard = Arc::downgrade(&self.mode_guard);
            let router = Arc::downgrade(router);
            rule_set.add_update_validator(Arc::new(
                move |updated_tag: &str, metadata: RuleSetMetadata| {
                    let Some(mode_guard) = mode_guard.upgrade() else {
                        return Ok(());
                    };
                    let Some(router) = router.upgrade() else {
                        return Ok(());
                    };
                    let candidate = resolve_legacy_dns_mode_with_rule_sets(
                        &mode_guard.raw_rules,
                        Some(&router),
                        Some((updated_tag, metadata)),
                    )
                    .map_err(|error| error.to_string())?;
                    if !candidate {
                        validate_modern_rule_set_metadata(
                            &mode_guard.raw_rules,
                            &router,
                            Some((updated_tag, metadata)),
                        )
                        .map_err(|error| error.to_string())?;
                    }
                    if candidate != mode_guard.legacy_dns_mode {
                        return Err(legacy_dns_address_filter_message());
                    }
                    Ok(())
                },
            ));
        }
        Ok(())
    }

    pub fn set_clash_mode(&self, mode: Option<String>) {
        *self
            .clash_mode
            .write()
            .expect("DNS clash mode lock poisoned") = mode;
    }

    async fn lookup_direct(
        &self,
        domain: &str,
        mut options: LookupOptions,
        context: Option<&RouteMetadata>,
    ) -> io::Result<Vec<IpAddr>> {
        let metadata =
            QueryMetadata::for_domain(domain, None, context, self.clash_mode());
        let responses = EvaluatedResponses::default();
        let mut evaluated = None;
        for action in self
            .rules
            .iter()
            .filter(|rule| rule.matches(domain, &metadata, &responses))
            .map(DnsRule::action)
        {
            match action {
                DnsAction::Route {
                    server,
                    options: overrides,
                    ..
                } => {
                    overrides.apply(&mut options);
                    return self.resolvers[server]
                        .lookup_with_options(domain, options)
                        .await;
                }
                DnsAction::RouteOptions(overrides) => {
                    overrides.apply(&mut options);
                }
                DnsAction::Evaluate {
                    server,
                    options: overrides,
                    ..
                } => {
                    let mut evaluate_options = options;
                    overrides.apply(&mut evaluate_options);
                    evaluated = Some(
                        self.resolvers[server]
                            .lookup_with_options(domain, evaluate_options)
                            .await?,
                    );
                }
                DnsAction::Respond => {
                    return evaluated.take().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "DNS respond action has no evaluated response",
                        )
                    });
                }
                DnsAction::Reject(action) => {
                    return Err(rejected(if action.should_drop() {
                        "drop"
                    } else {
                        "default"
                    }));
                }
                DnsAction::Predefined(predefined) => {
                    return predefined.lookup(domain, options.strategy);
                }
            }
        }
        self.fallback.lookup_with_options(domain, options).await
    }

    async fn lookup_once(
        &self,
        domain: &str,
        options: LookupOptions,
        query_type: RecordType,
        context: Option<&RouteMetadata>,
    ) -> io::Result<Vec<IpAddr>> {
        let name = Name::from_ascii(domain).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, error)
        })?;
        let mut request = Message::query();
        request.add_query(Query::query(name, query_type));
        let response = self.exchange_once(&request, options, context).await?;
        if response.metadata.response_code != ResponseCode::NoError {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "DNS response code: {}",
                    response.metadata.response_code
                ),
            ));
        }
        let addresses = response
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(address) => Some(IpAddr::V4(address.0)),
                RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                _ => None,
            })
            .collect();
        filter_query_addresses(addresses, Some(query_type))
    }

    async fn lookup_routed(
        &self,
        domain: &str,
        options: LookupOptions,
        context: Option<&RouteMetadata>,
    ) -> io::Result<Vec<IpAddr>> {
        if !self.has_message_matchers {
            return self.lookup_direct(domain, options, context).await;
        }
        let mut addresses = match options.strategy {
            DomainStrategy::Ipv4Only => {
                self.lookup_once(domain, options, RecordType::A, context)
                    .await?
            }
            DomainStrategy::Ipv6Only => {
                self.lookup_once(domain, options, RecordType::AAAA, context)
                    .await?
            }
            _ => {
                let (ipv4, ipv6) = tokio::join!(
                    self.lookup_once(domain, options, RecordType::A, context),
                    self.lookup_once(
                        domain,
                        options,
                        RecordType::AAAA,
                        context
                    )
                );
                merge_address_results(ipv4, ipv6)?
            }
        };
        apply_strategy(&mut addresses, options.strategy);
        Ok(addresses)
    }

    pub(crate) fn lookup_with_context<'a>(
        &'a self,
        domain: &'a str,
        options: LookupOptions,
        context: &'a RouteMetadata,
    ) -> LookupFuture<'a> {
        Box::pin(self.lookup_routed(domain, options, Some(context)))
    }

    pub(crate) fn exchange_with_context<'a>(
        &'a self,
        request: &'a Message,
        options: LookupOptions,
        context: &'a RouteMetadata,
    ) -> MessageFuture<'a> {
        Box::pin(self.exchange_once(request, options, Some(context)))
    }

    async fn exchange_once(
        &self,
        request: &Message,
        mut options: LookupOptions,
        context: Option<&RouteMetadata>,
    ) -> io::Result<Message> {
        let Some(domain) =
            request.queries.first().map(|query| query.name().to_utf8())
        else {
            return Self::exchange_resolver(&self.fallback, request, options)
                .await;
        };
        let metadata =
            QueryMetadata::from_request(request, context, self.clash_mode());
        if self.legacy_dns_mode {
            return self
                .exchange_legacy(request, options, &domain, &metadata)
                .await;
        }
        let mut responses = EvaluatedResponses::default();
        let mut tasks = EvaluationTasks::default();
        let mut armed_races = Vec::new();
        for rule in &self.rules {
            if rule.race() {
                armed_races.push(ArmedRace { rule, options });
                continue;
            }
            let mut selectors = Vec::new();
            rule.response_selectors(&mut selectors);
            for selector in &selectors {
                tasks.settle(selector, &mut responses).await;
            }
            self.persist_response_rejections(
                rule, &domain, &metadata, &responses, request,
            );
            if !rule.matches(&domain, &metadata, &responses) {
                continue;
            }
            match rule.action() {
                DnsAction::Route {
                    server,
                    options: overrides,
                    speculative,
                } => {
                    let mut route_options = options;
                    overrides.apply(&mut route_options);
                    if armed_races.is_empty() {
                        return Self::exchange_resolver(
                            &self.resolvers[server],
                            request,
                            route_options,
                        )
                        .await;
                    }
                    let terminal_task = if *speculative {
                        let resolver = self.resolvers[server].clone();
                        let request = request.clone();
                        Some(AbortOnDropHandle::new(tokio::spawn(async move {
                            Self::exchange_resolver(
                                &resolver,
                                &request,
                                route_options,
                            )
                            .await
                        })))
                    } else {
                        None
                    };
                    if let Some(commit) = resolve_race_actions(
                        &armed_races,
                        &mut tasks,
                        &mut responses,
                        &domain,
                        &metadata,
                        self.rdrc.as_ref(),
                        request,
                    )
                    .await
                    {
                        if let Some(task) = terminal_task {
                            task.abort();
                        }
                        return self.finish_race_action(commit, request).await;
                    }
                    if let Some(task) = terminal_task {
                        return task.await.map_err(io::Error::other)?;
                    }
                    return Self::exchange_resolver(
                        &self.resolvers[server],
                        request,
                        route_options,
                    )
                    .await;
                }
                DnsAction::RouteOptions(overrides) => {
                    overrides.apply(&mut options);
                }
                DnsAction::Evaluate {
                    server,
                    tag,
                    options: overrides,
                    speculative,
                } => {
                    if !*speculative && !armed_races.is_empty() {
                        if let Some(commit) = resolve_race_actions(
                            &armed_races,
                            &mut tasks,
                            &mut responses,
                            &domain,
                            &metadata,
                            self.rdrc.as_ref(),
                            request,
                        )
                        .await
                        {
                            return self
                                .finish_race_action(commit, request)
                                .await;
                        }
                        armed_races.clear();
                    }
                    let mut evaluate_options = options;
                    overrides.apply(&mut evaluate_options);
                    let selector = tag
                        .as_ref()
                        .map_or(ResponseSelector::Anonymous, |tag| {
                            ResponseSelector::Tagged(tag.clone())
                        });
                    if self.checked_selectors.contains(&selector)
                        && self.rdrc_rejects(server, request)
                    {
                        if let Some(previous) = tasks.take(&selector) {
                            previous.abort();
                        }
                        continue;
                    }
                    let resolver = self.resolvers[server].clone();
                    let request = request.clone();
                    let task = tokio::spawn(async move {
                        Self::exchange_resolver(
                            &resolver,
                            &request,
                            evaluate_options,
                        )
                        .await
                    });
                    let task = EvaluationTask::new(task, server.clone());
                    if let Some(tag) = tag {
                        if let Some(previous) =
                            tasks.named.insert(tag.clone(), task)
                        {
                            previous.abort();
                        }
                    } else {
                        if let Some(previous) = tasks.anonymous.replace(task) {
                            previous.abort();
                        }
                    }
                }
                DnsAction::Respond => {
                    if !armed_races.is_empty() {
                        if let Some(commit) = resolve_race_actions(
                            &armed_races,
                            &mut tasks,
                            &mut responses,
                            &domain,
                            &metadata,
                            self.rdrc.as_ref(),
                            request,
                        )
                        .await
                        {
                            return self
                                .finish_race_action(commit, request)
                                .await;
                        }
                        armed_races.clear();
                    }
                    if rule.response_selector().is_none() {
                        tasks
                            .settle(
                                &ResponseSelector::Anonymous,
                                &mut responses,
                            )
                            .await;
                    }
                    let response = response_for_respond(rule, &responses);
                    return response.cloned().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "DNS respond action has no evaluated response",
                        )
                    });
                }
                DnsAction::Reject(action) => {
                    if !armed_races.is_empty() {
                        if let Some(commit) = resolve_race_actions(
                            &armed_races,
                            &mut tasks,
                            &mut responses,
                            &domain,
                            &metadata,
                            self.rdrc.as_ref(),
                            request,
                        )
                        .await
                        {
                            return self
                                .finish_race_action(commit, request)
                                .await;
                        }
                        armed_races.clear();
                    }
                    if action.should_drop() {
                        return Err(rejected("drop"));
                    }
                    return Ok(refused_response(request));
                }
                DnsAction::Predefined(predefined) => {
                    if !armed_races.is_empty()
                        && let Some(commit) = resolve_race_actions(
                            &armed_races,
                            &mut tasks,
                            &mut responses,
                            &domain,
                            &metadata,
                            self.rdrc.as_ref(),
                            request,
                        )
                        .await
                    {
                        return self.finish_race_action(commit, request).await;
                    }
                    return Ok(predefined.response(request));
                }
            }
        }
        if let Some(commit) = resolve_race_actions(
            &armed_races,
            &mut tasks,
            &mut responses,
            &domain,
            &metadata,
            self.rdrc.as_ref(),
            request,
        )
        .await
        {
            return self.finish_race_action(commit, request).await;
        }
        Self::exchange_resolver(&self.fallback, request, options).await
    }

    async fn exchange_legacy(
        &self,
        request: &Message,
        base_options: LookupOptions,
        domain: &str,
        metadata: &QueryMetadata,
    ) -> io::Result<Message> {
        let is_address_query = request.queries.iter().any(|query| {
            matches!(
                query.query_type(),
                RecordType::A | RecordType::AAAA | RecordType::HTTPS
            )
        });
        let mut start = 0usize;
        loop {
            let mut options = base_options;
            let mut selected = None;
            for (index, rule) in self.rules.iter().enumerate().skip(start) {
                if rule.has_legacy_address_limit() && !is_address_query {
                    continue;
                }
                if !rule.legacy_pre_matches(domain, metadata) {
                    continue;
                }
                match rule.action() {
                    DnsAction::Route {
                        server,
                        options: overrides,
                        ..
                    } => {
                        overrides.apply(&mut options);
                        selected =
                            Some((index, rule, server.as_str(), options));
                        break;
                    }
                    DnsAction::RouteOptions(overrides) => {
                        overrides.apply(&mut options);
                    }
                    DnsAction::Reject(action) => {
                        if action.should_drop() {
                            return Err(rejected("drop"));
                        }
                        return Ok(refused_response(request));
                    }
                    DnsAction::Predefined(predefined) => {
                        return Ok(predefined.response(request));
                    }
                    DnsAction::Evaluate { .. } | DnsAction::Respond => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "modern DNS action reached legacy routing mode",
                        ));
                    }
                }
            }
            let Some((index, rule, server, options)) = selected else {
                return Self::exchange_resolver(
                    &self.fallback,
                    request,
                    options,
                )
                .await;
            };
            if rule.has_legacy_address_limit()
                && self.rdrc_rejects(server, request)
            {
                start = index + 1;
                continue;
            }
            let response = Self::exchange_resolver(
                &self.resolvers[server],
                request,
                options,
            )
            .await?;
            if !rule.has_legacy_address_limit()
                || rule.legacy_matches_response(domain, metadata, &response)
            {
                return Ok(response);
            }
            if let (Some(rdrc), Some(query)) =
                (self.rdrc.as_ref(), request.queries.first())
            {
                let _ = rdrc.cache.save_rdrc(
                    server,
                    &query.name().to_utf8(),
                    u16::from(query.query_type()),
                    rdrc.timeout,
                );
            }
            start = index + 1;
        }
    }

    fn clash_mode(&self) -> Option<String> {
        self.clash_mode
            .read()
            .expect("DNS clash mode lock poisoned")
            .clone()
    }

    fn rdrc_rejects(&self, server: &str, request: &Message) -> bool {
        let Some(rdrc) = &self.rdrc else {
            return false;
        };
        let Some(query) = request.queries.first() else {
            return false;
        };
        rdrc.cache
            .load_rdrc(
                server,
                &query.name().to_utf8(),
                u16::from(query.query_type()),
            )
            .unwrap_or(false)
    }

    fn persist_response_rejections(
        &self,
        rule: &DnsRule,
        domain: &str,
        metadata: &QueryMetadata,
        responses: &EvaluatedResponses,
        request: &Message,
    ) {
        persist_rule_rejections(
            self.rdrc.as_ref(),
            rule,
            domain,
            metadata,
            responses,
            request,
        );
    }

    async fn finish_race_action(
        &self,
        commit: RaceCommit<'_>,
        request: &Message,
    ) -> io::Result<Message> {
        match commit {
            RaceCommit::Respond(response) => Ok(response),
            RaceCommit::MissingResponse => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS respond action has no evaluated response",
            )),
            RaceCommit::Route {
                server,
                mut options,
                overrides,
            } => {
                overrides.apply(&mut options);
                Self::exchange_resolver(
                    &self.resolvers[server],
                    request,
                    options,
                )
                .await
            }
            RaceCommit::Reject(action) if action.should_drop() => {
                Err(rejected("drop"))
            }
            RaceCommit::Reject(_) => Ok(refused_response(request)),
            RaceCommit::Predefined(predefined) => {
                Ok(predefined.response(request))
            }
        }
    }

    async fn exchange_resolver(
        resolver: &Arc<dyn Resolver>,
        request: &Message,
        mut options: LookupOptions,
    ) -> io::Result<Message> {
        match resolver.exchange_with_options(request, options).await {
            Ok(response) => return Ok(response),
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {}
            Err(error) => return Err(error),
        }
        if request.queries.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "address-only DNS resolver requires exactly one query",
            ));
        }
        let query = &request.queries[0];
        let query_type = query.query_type();
        force_query_strategy(&mut options, Some(query_type));
        if !matches!(query_type, RecordType::A | RecordType::AAAA) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "address-only DNS resolver does not support {query_type}"
                ),
            ));
        }
        let addresses = resolver
            .lookup_with_options(&query.name().to_utf8(), options)
            .await?;
        let mut response = Message::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        response.queries = request.queries.clone();
        for address in addresses {
            let data = match (query_type, address) {
                (RecordType::A, IpAddr::V4(address)) => {
                    Some(RData::A(hickory_proto::rr::rdata::A(address)))
                }
                (RecordType::AAAA, IpAddr::V6(address)) => {
                    Some(RData::AAAA(hickory_proto::rr::rdata::AAAA(address)))
                }
                _ => None,
            };
            if let Some(data) = data {
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    60,
                    data,
                ));
            }
        }
        Ok(response)
    }
}

impl Resolver for RoutingResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: DomainStrategy,
    ) -> LookupFuture<'a> {
        self.lookup_with_options(
            domain,
            LookupOptions {
                strategy,
                ..LookupOptions::default()
            },
        )
    }

    fn lookup_with_options<'a>(
        &'a self,
        domain: &'a str,
        options: LookupOptions,
    ) -> LookupFuture<'a> {
        Box::pin(self.lookup_routed(domain, options, None))
    }

    fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
        self.exchange_with_options(request, LookupOptions::default())
    }

    fn exchange_with_options<'a>(
        &'a self,
        request: &'a Message,
        options: LookupOptions,
    ) -> MessageFuture<'a> {
        Box::pin(self.exchange_once(request, options, None))
    }
}

#[derive(Clone, Default)]
struct QueryMetadata {
    query_type: Option<RecordType>,
    client_subnet: Option<ClientSubnet>,
    dnssec: bool,
    clash_mode: Option<String>,
    route: RouteMetadata,
}

#[derive(Default)]
struct EvaluatedResponses {
    anonymous: Option<Message>,
    named: HashMap<String, Message>,
    servers: HashMap<ResponseSelector, String>,
}

#[derive(Default)]
struct EvaluationTasks {
    anonymous: Option<EvaluationTask>,
    named: HashMap<String, EvaluationTask>,
}

struct EvaluationTask {
    handle: AbortOnDropHandle<io::Result<Message>>,
    server: String,
}

impl EvaluationTask {
    fn new(
        handle: tokio::task::JoinHandle<io::Result<Message>>,
        server: String,
    ) -> Self {
        Self {
            handle: AbortOnDropHandle::new(handle),
            server,
        }
    }

    fn abort(&self) {
        self.handle.abort();
    }
}

impl EvaluationTasks {
    fn take(&mut self, selector: &ResponseSelector) -> Option<EvaluationTask> {
        match selector {
            ResponseSelector::Anonymous => self.anonymous.take(),
            ResponseSelector::Tagged(tag) => self.named.remove(tag),
        }
    }

    async fn settle(
        &mut self,
        selector: &ResponseSelector,
        responses: &mut EvaluatedResponses,
    ) {
        let task = self.take(selector);
        let Some(task) = task else {
            return;
        };
        let server = task.server;
        let Ok(Ok(response)) = task.handle.await else {
            return;
        };
        responses.servers.insert(selector.clone(), server);
        match selector {
            ResponseSelector::Anonymous => responses.anonymous = Some(response),
            ResponseSelector::Tagged(tag) => {
                responses.named.insert(tag.clone(), response);
            }
        }
    }
}

struct ArmedRace<'a> {
    rule: &'a DnsRule,
    options: LookupOptions,
}

enum RaceCommit<'a> {
    Respond(Message),
    MissingResponse,
    Route {
        server: &'a str,
        options: LookupOptions,
        overrides: &'a DnsLookupOverride,
    },
    Reject(&'a DnsRejectAction),
    Predefined(&'a PredefinedAction),
}

async fn resolve_race_actions<'a>(
    armed: &'a [ArmedRace<'a>],
    tasks: &mut EvaluationTasks,
    responses: &mut EvaluatedResponses,
    domain: &str,
    metadata: &QueryMetadata,
    rdrc: Option<&RdrcOptions>,
    request: &Message,
) -> Option<RaceCommit<'a>> {
    let mut seen = HashSet::new();
    let mut pending_selectors = HashSet::new();
    let pending = FuturesUnordered::new();
    for armed_rule in armed {
        let mut selectors = Vec::new();
        armed_rule.rule.response_selectors(&mut selectors);
        for selector in selectors {
            if !seen.insert(selector.clone()) {
                continue;
            }
            if let Some(task) = tasks.take(&selector) {
                pending_selectors.insert(selector.clone());
                pending.push(
                    async move {
                        let server = task.server;
                        (selector, server, task.handle.await)
                    }
                    .boxed(),
                );
            }
        }
    }
    if let Some(commit) = ready_race_commit(
        armed,
        &pending_selectors,
        responses,
        domain,
        metadata,
    ) {
        return Some(commit);
    }
    futures_util::pin_mut!(pending);
    while let Some((selector, server, result)) = pending.next().await {
        pending_selectors.remove(&selector);
        if let Ok(Ok(response)) = result {
            responses.servers.insert(selector.clone(), server);
            match &selector {
                ResponseSelector::Anonymous => {
                    responses.anonymous = Some(response);
                }
                ResponseSelector::Tagged(tag) => {
                    responses.named.insert(tag.clone(), response);
                }
            }
            for armed_rule in armed {
                persist_rule_rejections(
                    rdrc,
                    armed_rule.rule,
                    domain,
                    metadata,
                    responses,
                    request,
                );
            }
        }
        if let Some(commit) = ready_race_commit(
            armed,
            &pending_selectors,
            responses,
            domain,
            metadata,
        ) {
            return Some(commit);
        }
    }
    None
}

fn persist_rule_rejections(
    rdrc: Option<&RdrcOptions>,
    rule: &DnsRule,
    domain: &str,
    metadata: &QueryMetadata,
    responses: &EvaluatedResponses,
    request: &Message,
) {
    let (Some(rdrc), Some(query)) = (rdrc, request.queries.first()) else {
        return;
    };
    let mut rejected = Vec::new();
    rule.rejected_response_selectors(
        domain,
        metadata,
        responses,
        &mut rejected,
    );
    for selector in rejected {
        let Some(server) = responses.servers.get(&selector) else {
            continue;
        };
        let _ = rdrc.cache.save_rdrc(
            server,
            &query.name().to_utf8(),
            u16::from(query.query_type()),
            rdrc.timeout,
        );
    }
}

fn ready_race_commit<'a>(
    armed: &'a [ArmedRace<'a>],
    pending: &HashSet<ResponseSelector>,
    responses: &EvaluatedResponses,
    domain: &str,
    metadata: &QueryMetadata,
) -> Option<RaceCommit<'a>> {
    armed.iter().find_map(|armed_rule| {
        let mut selectors = Vec::new();
        armed_rule.rule.response_selectors(&mut selectors);
        if selectors.iter().any(|selector| pending.contains(selector))
            || !armed_rule.rule.matches(domain, metadata, responses)
        {
            return None;
        }
        Some(race_commit(armed_rule, responses))
    })
}

fn race_commit<'a>(
    armed: &'a ArmedRace<'a>,
    responses: &EvaluatedResponses,
) -> RaceCommit<'a> {
    match armed.rule.action() {
        DnsAction::Respond => response_for_respond(armed.rule, responses)
            .cloned()
            .map_or(RaceCommit::MissingResponse, RaceCommit::Respond),
        DnsAction::Route {
            server, options, ..
        } => RaceCommit::Route {
            server,
            options: armed.options,
            overrides: options,
        },
        DnsAction::Reject(action) => RaceCommit::Reject(action),
        DnsAction::Predefined(predefined) => RaceCommit::Predefined(predefined),
        DnsAction::RouteOptions(_) | DnsAction::Evaluate { .. } => {
            unreachable!("race actions are validated as terminal")
        }
    }
}

fn response_for_respond<'a>(
    rule: &DnsRule,
    responses: &'a EvaluatedResponses,
) -> Option<&'a Message> {
    match rule.response_selector() {
        Some(selector) => responses.get(selector),
        None => responses.anonymous.as_ref(),
    }
}

impl Drop for EvaluationTasks {
    fn drop(&mut self) {
        if let Some(task) = &self.anonymous {
            task.abort();
        }
        for task in self.named.values() {
            task.abort();
        }
    }
}

impl EvaluatedResponses {
    fn get(&self, selector: &ResponseSelector) -> Option<&Message> {
        match selector {
            ResponseSelector::Anonymous => self.anonymous.as_ref(),
            ResponseSelector::Tagged(tag) => self.named.get(tag),
        }
    }
}

impl QueryMetadata {
    fn from_request(
        request: &Message,
        context: Option<&RouteMetadata>,
        clash_mode: Option<String>,
    ) -> Self {
        let domain = request
            .queries
            .first()
            .map(|query| query.name().to_utf8())
            .unwrap_or_default();
        Self::for_domain(
            &domain,
            request.queries.first().map(|query| query.query_type()),
            context,
            clash_mode,
        )
        .with_message(request)
    }

    fn for_domain(
        domain: &str,
        query_type: Option<RecordType>,
        context: Option<&RouteMetadata>,
        clash_mode: Option<String>,
    ) -> Self {
        let mut route = context.cloned().unwrap_or_default();
        route.domain = canonical(domain);
        route.query_type = query_type.map(u16::from);
        route.clash_mode = clash_mode.clone().unwrap_or_default();
        Self {
            query_type,
            clash_mode,
            route,
            ..Self::default()
        }
    }

    fn with_message(mut self, request: &Message) -> Self {
        self.client_subnet = request.edns.as_ref().and_then(|edns| {
            edns.option(EdnsCode::Subnet)
                .and_then(|option| match option {
                    EdnsOption::Subnet(subnet) => Some(*subnet),
                    _ => None,
                })
        });
        self.dnssec = request
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags().dnssec_ok);
        self
    }
}

fn force_query_strategy(
    options: &mut LookupOptions,
    query_type: Option<RecordType>,
) {
    match query_type {
        Some(RecordType::A) => options.strategy = DomainStrategy::Ipv4Only,
        Some(RecordType::AAAA) => options.strategy = DomainStrategy::Ipv6Only,
        _ => {}
    }
}

fn filter_query_addresses(
    mut addresses: Vec<IpAddr>,
    query_type: Option<RecordType>,
) -> io::Result<Vec<IpAddr>> {
    match query_type {
        Some(RecordType::A) => addresses.retain(IpAddr::is_ipv4),
        Some(RecordType::AAAA) => addresses.retain(IpAddr::is_ipv6),
        _ => {}
    }
    if addresses.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DNS response has no address matching the query type",
        ))
    } else {
        Ok(addresses)
    }
}

fn merge_address_results(
    ipv4: io::Result<Vec<IpAddr>>,
    ipv6: io::Result<Vec<IpAddr>>,
) -> io::Result<Vec<IpAddr>> {
    match (ipv4, ipv6) {
        (Ok(mut ipv4), Ok(ipv6)) => {
            ipv4.extend(ipv6);
            Ok(ipv4)
        }
        (Ok(addresses), Err(_)) | (Err(_), Ok(addresses))
            if !addresses.is_empty() =>
        {
            Ok(addresses)
        }
        (Err(ipv4), Err(ipv6)) => Err(io::Error::new(
            ipv4.kind(),
            format!(
                "IPv4 DNS lookup failed: {ipv4}; IPv6 DNS lookup failed: {ipv6}"
            ),
        )),
        (Ok(_), Err(error)) | (Err(error), Ok(_)) => Err(error),
    }
}

fn rejected(method: &str) -> io::Error {
    io::Error::new(
        if method == "drop" {
            io::ErrorKind::TimedOut
        } else {
            io::ErrorKind::PermissionDenied
        },
        format!("DNS request rejected using method {method}"),
    )
}

fn refused_response(request: &Message) -> Message {
    let mut response = Message::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.response_code = ResponseCode::Refused;
    response.queries = request.queries.clone();
    response
}

enum DnsRule {
    Default {
        matcher: Box<QueryMatcher>,
        invert: bool,
        race: bool,
        action: DnsAction,
    },
    Logical {
        mode: LogicalMode,
        rules: Vec<DnsRule>,
        invert: bool,
        race: bool,
        action: DnsAction,
    },
}

impl DnsRule {
    fn compile(
        value: &Value,
        nested: bool,
        resolvers: &ResolverMap,
        rule_set_router: Arc<RwLock<Option<Weak<Router>>>>,
        legacy_dns_mode: bool,
    ) -> Result<Self, DnsRuleError> {
        let object = value.as_object().ok_or_else(|| {
            DnsRuleError::Invalid("rule is not an object".into())
        })?;
        let kind = match object.get("type") {
            None => "",
            Some(Value::String(kind)) => kind.as_str(),
            Some(_) => {
                return Err(DnsRuleError::Invalid(
                    "DNS rule type is not a string".into(),
                ));
            }
        };
        match kind {
            "" | "default" => {
                validate_keys(object, nested, false)?;
                Ok(Self::Default {
                    matcher: Box::new(QueryMatcher::compile(
                        object,
                        resolvers,
                        rule_set_router,
                        legacy_dns_mode,
                    )?),
                    invert: bool_field(object, "invert")?,
                    race: bool_field(object, "race")?,
                    action: parse_action(object, nested, false)?,
                })
            }
            "logical" => {
                validate_keys(object, nested, true)?;
                let mode = match object.get("mode").and_then(Value::as_str) {
                    Some("and") => LogicalMode::And,
                    Some("or") => LogicalMode::Or,
                    Some(mode) => {
                        return Err(DnsRuleError::Invalid(format!(
                            "unknown logical mode: {mode}"
                        )));
                    }
                    None => {
                        return Err(DnsRuleError::Invalid(
                            "logical rule has no mode".into(),
                        ));
                    }
                };
                let values = object
                    .get("rules")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        DnsRuleError::Invalid(
                            "logical rule has no rule array".into(),
                        )
                    })?;
                if values.is_empty() {
                    return Err(DnsRuleError::Invalid(
                        "logical rule has no child rules".into(),
                    ));
                }
                Ok(Self::Logical {
                    mode,
                    rules: values
                        .iter()
                        .map(|value| {
                            Self::compile(
                                value,
                                true,
                                resolvers,
                                rule_set_router.clone(),
                                legacy_dns_mode,
                            )
                        })
                        .collect::<Result<_, _>>()?,
                    invert: bool_field(object, "invert")?,
                    race: bool_field(object, "race")?,
                    action: parse_action(object, nested, true)?,
                })
            }
            kind => {
                Err(DnsRuleError::Invalid(format!("unknown rule type: {kind}")))
            }
        }
    }

    fn validate_rule_sets(&self, router: &Router) -> Result<(), DnsRuleError> {
        match self {
            Self::Default { matcher, .. } => matcher
                .rule_sets
                .iter()
                .find(|tag| !router.has_rule_set(tag))
                .map_or(Ok(()), |tag| {
                    Err(DnsRuleError::Invalid(format!(
                        "rule-set not found: {tag:?}"
                    )))
                }),
            Self::Logical { rules, .. } => {
                for rule in rules {
                    rule.validate_rule_sets(router)?;
                }
                Ok(())
            }
        }
    }

    fn matches(
        &self,
        domain: &str,
        metadata: &QueryMetadata,
        responses: &EvaluatedResponses,
    ) -> bool {
        match self {
            Self::Default {
                matcher, invert, ..
            } => {
                let response = matcher
                    .response_selector()
                    .and_then(|selector| responses.get(selector));
                matcher.matches(domain, metadata, response) != *invert
            }
            Self::Logical {
                mode,
                rules,
                invert,
                ..
            } => {
                let matched = match mode {
                    LogicalMode::And => rules
                        .iter()
                        .all(|rule| rule.matches(domain, metadata, responses)),
                    LogicalMode::Or => rules
                        .iter()
                        .any(|rule| rule.matches(domain, metadata, responses)),
                };
                matched != *invert
            }
        }
    }

    fn legacy_pre_matches(
        &self,
        domain: &str,
        metadata: &QueryMetadata,
    ) -> bool {
        self.legacy_match_possibility(domain, metadata).can_match
    }

    fn legacy_match_possibility(
        &self,
        domain: &str,
        metadata: &QueryMetadata,
    ) -> MatchPossibility {
        match self {
            Self::Default {
                matcher, invert, ..
            } => matcher
                .legacy_match_possibility(domain, metadata)
                .inverted_if(*invert),
            Self::Logical {
                mode,
                rules,
                invert,
                ..
            } => {
                let matched = match mode {
                    LogicalMode::And => rules.iter().fold(
                        MatchPossibility::fixed(true),
                        |state, rule| {
                            state.and(
                                rule.legacy_match_possibility(domain, metadata),
                            )
                        },
                    ),
                    LogicalMode::Or => rules.iter().fold(
                        MatchPossibility::fixed(false),
                        |state, rule| {
                            state
                                .or(rule
                                    .legacy_match_possibility(domain, metadata))
                        },
                    ),
                };
                matched.inverted_if(*invert)
            }
        }
    }

    fn legacy_matches_response(
        &self,
        domain: &str,
        metadata: &QueryMetadata,
        response: &Message,
    ) -> bool {
        match self {
            Self::Default {
                matcher, invert, ..
            } => {
                matcher.legacy_matches_response(domain, metadata, response)
                    != *invert
            }
            Self::Logical {
                mode,
                rules,
                invert,
                ..
            } => {
                let matched = match mode {
                    LogicalMode::And => rules.iter().all(|rule| {
                        rule.legacy_matches_response(domain, metadata, response)
                    }),
                    LogicalMode::Or => rules.iter().any(|rule| {
                        rule.legacy_matches_response(domain, metadata, response)
                    }),
                };
                matched != *invert
            }
        }
    }

    fn has_legacy_address_limit(&self) -> bool {
        match self {
            Self::Default { matcher, .. } => matcher.has_legacy_address_limit(),
            Self::Logical { rules, .. } => {
                rules.iter().any(Self::has_legacy_address_limit)
            }
        }
    }

    fn action(&self) -> &DnsAction {
        match self {
            Self::Default { action, .. } | Self::Logical { action, .. } => {
                action
            }
        }
    }

    fn requires_message_lookup(&self) -> bool {
        match self {
            Self::Default { matcher, .. } => matcher.requires_message_lookup(),
            Self::Logical { rules, .. } => {
                rules.iter().any(Self::requires_message_lookup)
            }
        }
    }

    fn response_selector(&self) -> Option<&ResponseSelector> {
        match self {
            Self::Default { matcher, .. } => matcher.response_selector(),
            Self::Logical { .. } => None,
        }
    }

    fn race(&self) -> bool {
        match self {
            Self::Default { race, .. } | Self::Logical { race, .. } => *race,
        }
    }

    fn response_requirements<'a>(
        &'a self,
        anonymous: &mut bool,
        tags: &mut Vec<&'a str>,
    ) {
        match self {
            Self::Default { matcher, .. } => {
                if let Some(selector) = matcher.response_selector() {
                    match selector {
                        ResponseSelector::Anonymous => *anonymous = true,
                        ResponseSelector::Tagged(tag) => tags.push(tag),
                    }
                }
            }
            Self::Logical { rules, .. } => {
                for rule in rules {
                    rule.response_requirements(anonymous, tags);
                }
            }
        }
    }

    fn response_selectors(&self, selectors: &mut Vec<ResponseSelector>) {
        match self {
            Self::Default { matcher, .. } => {
                if let Some(selector) = matcher.response_selector() {
                    selectors.push(selector.clone());
                }
            }
            Self::Logical { rules, .. } => {
                for rule in rules {
                    rule.response_selectors(selectors);
                }
            }
        }
    }

    fn rejected_response_selectors(
        &self,
        domain: &str,
        metadata: &QueryMetadata,
        responses: &EvaluatedResponses,
        rejected: &mut Vec<ResponseSelector>,
    ) {
        match self {
            Self::Default {
                matcher,
                invert: false,
                ..
            } => {
                let Some(response_matcher) = matcher.response.as_ref() else {
                    return;
                };
                if matcher.matches_query(domain, metadata)
                    && responses.get(&response_matcher.selector).is_some_and(
                        |response| {
                            !matcher.matches(domain, metadata, Some(response))
                        },
                    )
                {
                    rejected.push(response_matcher.selector.clone());
                }
            }
            Self::Logical { rules, .. } => {
                for rule in rules {
                    rule.rejected_response_selectors(
                        domain, metadata, responses, rejected,
                    );
                }
            }
            Self::Default { .. } => {}
        }
    }
}

enum LogicalMode {
    And,
    Or,
}

#[derive(Clone, Copy)]
struct MatchPossibility {
    can_match: bool,
    can_miss: bool,
}

impl MatchPossibility {
    fn fixed(value: bool) -> Self {
        Self {
            can_match: value,
            can_miss: !value,
        }
    }

    fn unknown() -> Self {
        Self {
            can_match: true,
            can_miss: true,
        }
    }

    fn and(self, other: Self) -> Self {
        Self {
            can_match: self.can_match && other.can_match,
            can_miss: self.can_miss || other.can_miss,
        }
    }

    fn or(self, other: Self) -> Self {
        Self {
            can_match: self.can_match || other.can_match,
            can_miss: self.can_miss && other.can_miss,
        }
    }

    fn inverted_if(self, invert: bool) -> Self {
        if invert {
            Self {
                can_match: self.can_miss,
                can_miss: self.can_match,
            }
        } else {
            self
        }
    }
}

enum DnsAction {
    Route {
        server: String,
        speculative: bool,
        options: DnsLookupOverride,
    },
    RouteOptions(DnsLookupOverride),
    Evaluate {
        server: String,
        tag: Option<String>,
        speculative: bool,
        options: DnsLookupOverride,
    },
    Respond,
    Reject(DnsRejectAction),
    Predefined(PredefinedAction),
}

struct DnsRejectAction {
    method: String,
    no_drop: bool,
    recent: std::sync::Mutex<VecDeque<Instant>>,
}

impl DnsRejectAction {
    fn should_drop(&self) -> bool {
        if self.method == "drop" {
            return true;
        }
        if self.no_drop {
            return false;
        }
        let now = Instant::now();
        let mut recent = self.recent.lock().expect("DNS reject lock poisoned");
        while recent.front().is_some_and(|started| {
            now.duration_since(*started) > Duration::from_secs(30)
        }) {
            recent.pop_front();
        }
        recent.push_back(now);
        recent.len() > 50
    }
}

impl DnsAction {
    fn server(&self) -> Option<&String> {
        match self {
            Self::Route { server, .. } | Self::Evaluate { server, .. } => {
                Some(server)
            }
            _ => None,
        }
    }

    fn is_terminal(&self) -> bool {
        !matches!(self, Self::RouteOptions(_) | Self::Evaluate { .. })
    }

    fn speculative(&self) -> bool {
        match self {
            Self::Route { speculative, .. }
            | Self::Evaluate { speculative, .. } => *speculative,
            _ => false,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum ResponseSelector {
    Anonymous,
    Tagged(String),
}

#[derive(Default)]
struct DnsLookupOverride {
    timeout: Option<std::time::Duration>,
    strategy: DomainStrategy,
    disable_cache: bool,
    disable_optimistic_cache: bool,
    rewrite_ttl: Option<u32>,
    client_subnet: Option<ipnet::IpNet>,
    remove_client_subnet: bool,
}

impl DnsLookupOverride {
    fn apply(&self, options: &mut LookupOptions) {
        if let Some(timeout) = self.timeout {
            options.timeout = Some(timeout);
        }
        if self.strategy != DomainStrategy::AsIs {
            options.strategy = self.strategy;
        }
        options.disable_cache |= self.disable_cache;
        options.disable_optimistic_cache |= self.disable_optimistic_cache;
        if self.rewrite_ttl.is_some() {
            options.rewrite_ttl = self.rewrite_ttl;
        }
        if self.remove_client_subnet {
            options.client_subnet = None;
            options.remove_client_subnet = true;
        } else if self.client_subnet.is_some() {
            options.client_subnet = self.client_subnet;
            options.remove_client_subnet = false;
        }
    }

    fn is_empty(&self) -> bool {
        self.timeout.is_none()
            && self.strategy == DomainStrategy::AsIs
            && !self.disable_cache
            && !self.disable_optimistic_cache
            && self.rewrite_ttl.is_none()
            && self.client_subnet.is_none()
            && !self.remove_client_subnet
    }
}

struct PredefinedAction {
    response_code: ResponseCode,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
}

impl PredefinedAction {
    fn lookup(
        &self,
        domain: &str,
        strategy: DomainStrategy,
    ) -> io::Result<Vec<IpAddr>> {
        if self.response_code != ResponseCode::NoError {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("DNS response code: {}", self.response_code),
            ));
        }
        let query_name = Name::from_ascii(domain).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, error)
        })?;
        let mut addresses = self
            .answers
            .iter()
            .filter_map(|record| {
                let record = rewrite_record(record, &query_name);
                match record.data {
                    RData::A(address) => Some(IpAddr::V4(address.0)),
                    RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                    _ => None,
                }
            })
            .collect();
        apply_strategy(&mut addresses, strategy);
        Ok(addresses)
    }

    fn response(&self, request: &Message) -> Message {
        let mut response = Message::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        response.metadata.authoritative = true;
        response.metadata.recursion_desired = true;
        response.metadata.recursion_available = true;
        response.metadata.response_code = self.response_code;
        response.queries = request.queries.clone();
        let query_name = request.queries.first().map(|query| query.name());
        response.answers = rewrite_records(&self.answers, query_name);
        response.authorities = rewrite_records(&self.authorities, query_name);
        response.additionals = rewrite_records(&self.additionals, query_name);
        response
    }
}

fn rewrite_records(
    records: &[Record],
    query_name: Option<&hickory_proto::rr::Name>,
) -> Vec<Record> {
    records
        .iter()
        .map(|record| {
            query_name.map_or_else(
                || record.clone(),
                |name| rewrite_record(record, name),
            )
        })
        .collect()
}

fn rewrite_record(
    record: &Record,
    query_name: &hickory_proto::rr::Name,
) -> Record {
    let mut record = record.clone();
    let owner = record.name.to_utf8();
    if let Some(suffix) = owner.strip_prefix('*')
        && query_name.to_utf8().ends_with(suffix)
    {
        record.name = query_name.clone();
    }
    record
}

struct QueryMatcher {
    domain: DomainMatcher,
    context: DnsContextMatcher,
    outbounds: Vec<String>,
    outbound_any: bool,
    rule_sets: Vec<String>,
    rule_set_ip_cidr_match_source: bool,
    rule_set_router: Arc<RwLock<Option<Weak<Router>>>>,
    ip_version: Option<u8>,
    query_types: Vec<RecordType>,
    client_subnets: Vec<ipnet::IpNet>,
    query_dnssec: bool,
    clash_mode: String,
    preferred_by: Vec<Arc<dyn Resolver>>,
    response: Option<ResponseMatcher>,
    legacy_address: Option<AddressMatcher>,
    rule_set_ip_cidr_accept_empty: bool,
}

struct ResponseMatcher {
    selector: ResponseSelector,
    address: AddressMatcher,
    response_code: Option<ResponseCode>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
}

#[derive(Default)]
struct AddressMatcher {
    ip_cidrs: Vec<ipnet::IpNet>,
    ip_is_private: bool,
    ip_accept_any: bool,
}

impl QueryMatcher {
    fn compile(
        object: &Map<String, Value>,
        resolvers: &ResolverMap,
        rule_set_router: Arc<RwLock<Option<Weak<Router>>>>,
        legacy_dns_mode: bool,
    ) -> Result<Self, DnsRuleError> {
        let ip_version = match object.get("ip_version") {
            None | Some(Value::Null) => None,
            Some(Value::Number(value)) if value.as_u64() == Some(4) => Some(4),
            Some(Value::Number(value)) if value.as_u64() == Some(6) => Some(6),
            Some(Value::Number(value)) if value.as_i64() == Some(0) => None,
            Some(value) => {
                return Err(DnsRuleError::Invalid(format!(
                    "invalid ip version: {value}"
                )));
            }
        };
        let query_types = parse_query_types(object)?;
        let client_subnets =
            match object.get("query_client_subnet") {
                None => Vec::new(),
                Some(value) => serde_json::from_value::<Listable<Prefixable>>(
                    value.clone(),
                )
                .map(Listable::into_vec)
                .map(|values| values.into_iter().map(|value| value.0).collect())
                .map_err(|error| {
                    DnsRuleError::Invalid(format!(
                        "query_client_subnet: {error}"
                    ))
                })?,
            };
        validate_deprecated_dns_matcher_fields(object, legacy_dns_mode)?;
        let (response, legacy_address) =
            parse_response_matcher(object, legacy_dns_mode)?;
        let outbounds = string_list(object, "outbound")?;
        let outbound_any = outbounds.iter().any(|outbound| outbound == "any");
        let preferred_by = string_list(object, "preferred_by")?
            .into_iter()
            .map(|tag| {
                let resolver =
                    resolvers.get(&tag).cloned().ok_or_else(|| {
                        DnsRuleError::Invalid(format!(
                            "DNS server not found: {tag}"
                        ))
                    })?;
                if resolver.preferred_domain("").is_none() {
                    return Err(DnsRuleError::Invalid(format!(
                        "DNS server does not support preferred_by: {tag}"
                    )));
                }
                Ok(resolver)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            domain: DomainMatcher::compile(object)?,
            context: DnsContextMatcher::compile(&Value::Object(object.clone()))
                .map_err(|error| DnsRuleError::Invalid(error.to_string()))?,
            outbounds,
            outbound_any,
            rule_sets: string_list(object, "rule_set")?,
            rule_set_ip_cidr_match_source: bool_field(
                object,
                "rule_set_ip_cidr_match_source",
            )?,
            rule_set_router,
            ip_version,
            query_types,
            client_subnets,
            query_dnssec: bool_field(object, "query_dnssec")?,
            clash_mode: object
                .get("clash_mode")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            preferred_by,
            response,
            legacy_address,
            rule_set_ip_cidr_accept_empty: bool_field(
                object,
                "rule_set_ip_cidr_accept_empty",
            )?,
        })
    }

    fn matches(
        &self,
        domain: &str,
        metadata: &QueryMetadata,
        response: Option<&Message>,
    ) -> bool {
        if !self.matches_query_context(domain, metadata) {
            return false;
        }
        let domain_configured = !self.domain.is_empty();
        let domain_matches = self.domain.matches(domain);
        let mut route = metadata.route.clone();
        let (address_configured, address_matches) =
            if let Some(response_matcher) = self.response.as_ref() {
                let Some(response) = response else {
                    return false;
                };
                if !response_matcher.matches_metadata(response) {
                    return false;
                }
                route.destination_addresses = dns_response_addresses(response);
                let address_configured =
                    response_matcher.has_address_condition();
                (
                    address_configured,
                    address_configured
                        && response_matcher.matches_address(response),
                )
            } else {
                (false, false)
            };
        let destination_required = domain_configured || address_configured;
        let destination_satisfied =
            domain_configured && domain_matches || address_matches;
        if self.rule_sets.is_empty() {
            return !destination_required || destination_satisfied;
        }
        let router = self
            .rule_set_router
            .read()
            .expect("DNS rule-set router lock poisoned")
            .as_ref()
            .and_then(Weak::upgrade);
        let Some(router) = router else {
            return false;
        };
        router.matches_rule_sets_with_destination_outer(
            &self.rule_sets,
            &route,
            self.rule_set_ip_cidr_match_source,
            destination_required,
            destination_satisfied,
            false,
        )
    }

    fn matches_query(&self, domain: &str, metadata: &QueryMetadata) -> bool {
        self.matches_query_context(domain, metadata)
            && (self.domain.matches(domain)
                || self
                    .response
                    .as_ref()
                    .is_some_and(ResponseMatcher::has_address_condition))
    }

    fn matches_query_context(
        &self,
        domain: &str,
        metadata: &QueryMetadata,
    ) -> bool {
        if !self.context.matches(&metadata.route) {
            return false;
        }
        let outbound_matches = self.outbounds.is_empty()
            || self.outbounds.contains(&metadata.route.outbound)
            || (self.outbound_any && !metadata.route.outbound.is_empty());
        if !outbound_matches {
            return false;
        }
        if let Some(version) = self.ip_version {
            let matches_version = matches!(
                (version, metadata.query_type),
                (4, Some(RecordType::A)) | (6, Some(RecordType::AAAA))
            );
            if !matches_version {
                return false;
            }
        }
        if !self.query_types.is_empty()
            && metadata.query_type.is_none_or(|query_type| {
                !self.query_types.contains(&query_type)
            })
        {
            return false;
        }
        if !self.client_subnets.is_empty()
            && !metadata.client_subnet.is_some_and(|client_subnet| {
                ipnet::IpNet::new(
                    client_subnet.addr(),
                    client_subnet.source_prefix(),
                )
                .ok()
                .is_some_and(|query_subnet| {
                    self.client_subnets.iter().any(|prefix| {
                        query_subnet.prefix_len() >= prefix.prefix_len()
                            && prefix.contains(&query_subnet.addr())
                    })
                })
            })
        {
            return false;
        }
        if self.query_dnssec && !metadata.dnssec {
            return false;
        }
        if !self.clash_mode.is_empty()
            && !metadata
                .clash_mode
                .as_ref()
                .is_some_and(|mode| mode.eq_ignore_ascii_case(&self.clash_mode))
        {
            return false;
        }
        if !self.preferred_by.is_empty()
            && !self
                .preferred_by
                .iter()
                .any(|resolver| resolver.preferred_domain(domain) == Some(true))
        {
            return false;
        }
        true
    }

    fn legacy_match_possibility(
        &self,
        domain: &str,
        metadata: &QueryMetadata,
    ) -> MatchPossibility {
        if !self.matches_query_context(domain, metadata) {
            return MatchPossibility::fixed(false);
        }
        let domain_configured = !self.domain.is_empty();
        let domain_matches = self.domain.matches(domain);
        let destination = if domain_configured && domain_matches {
            MatchPossibility::fixed(true)
        } else if self.legacy_address.is_some() {
            MatchPossibility::unknown()
        } else if domain_configured {
            MatchPossibility::fixed(false)
        } else {
            MatchPossibility::fixed(true)
        };
        if self.rule_sets.is_empty() {
            return destination;
        }
        let router = self
            .rule_set_router
            .read()
            .expect("DNS rule-set router lock poisoned")
            .as_ref()
            .and_then(Weak::upgrade);
        let Some(router) = router else {
            return MatchPossibility::fixed(false);
        };
        let (can_match, can_miss) = router.rule_sets_legacy_match_possibility(
            &self.rule_sets,
            &metadata.route,
            self.rule_set_ip_cidr_match_source,
            domain_configured || self.legacy_address.is_some(),
            destination.can_match,
            destination.can_miss,
        );
        MatchPossibility {
            can_match,
            can_miss,
        }
    }

    fn legacy_matches_response(
        &self,
        domain: &str,
        metadata: &QueryMetadata,
        response: &Message,
    ) -> bool {
        if !self.matches_query_context(domain, metadata) {
            return false;
        }
        let domain_configured = !self.domain.is_empty();
        let address_matches = self
            .legacy_address
            .as_ref()
            .is_some_and(|matcher| matcher.matches(response, false));
        let destination_required =
            domain_configured || self.legacy_address.is_some();
        let destination_satisfied =
            domain_configured && self.domain.matches(domain) || address_matches;
        if self.rule_sets.is_empty() {
            return !destination_required || destination_satisfied;
        }
        let router = self
            .rule_set_router
            .read()
            .expect("DNS rule-set router lock poisoned")
            .as_ref()
            .and_then(Weak::upgrade);
        let Some(router) = router else {
            return false;
        };
        let mut route = metadata.route.clone();
        route.destination_addresses = dns_response_addresses(response);
        router.matches_rule_sets_legacy_response(
            &self.rule_sets,
            &route,
            self.rule_set_ip_cidr_match_source,
            self.rule_set_ip_cidr_accept_empty,
            destination_required,
            destination_satisfied,
        )
    }

    fn has_legacy_address_limit(&self) -> bool {
        if self.legacy_address.is_some() {
            return true;
        }
        if self.rule_set_ip_cidr_match_source || self.rule_sets.is_empty() {
            return false;
        }
        self.rule_set_router
            .read()
            .expect("DNS rule-set router lock poisoned")
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|router| {
                router.rule_sets_contain_destination_ip(&self.rule_sets)
            })
    }

    fn requires_message_lookup(&self) -> bool {
        self.ip_version.is_some()
            || !self.query_types.is_empty()
            || !self.client_subnets.is_empty()
            || self.query_dnssec
            || !self.clash_mode.is_empty()
            || self.response.is_some()
    }

    fn response_selector(&self) -> Option<&ResponseSelector> {
        self.response.as_ref().map(|matcher| &matcher.selector)
    }
}

fn validate_deprecated_dns_matcher_fields(
    object: &Map<String, Value>,
    legacy_dns_mode: bool,
) -> Result<(), DnsRuleError> {
    if !string_list(object, "geosite")?.is_empty() {
        return Err(DnsRuleError::Invalid(
            "geosite database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0"
                .into(),
        ));
    }
    if !string_list(object, "source_geoip")?.is_empty()
        || !string_list(object, "geoip")?.is_empty()
    {
        return Err(DnsRuleError::Invalid(
            "geoip database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0"
                .into(),
        ));
    }
    if !legacy_dns_mode && bool_field(object, "rule_set_ip_cidr_accept_empty")?
    {
        return Err(DnsRuleError::Invalid(
            rule_set_ip_cidr_accept_empty_message(),
        ));
    }
    if !string_list(object, "rule_set")?.is_empty()
        && bool_field(object, "rule_set_ipcidr_match_source")?
    {
        return Err(DnsRuleError::Invalid(
            "rule_set_ipcidr_match_source is deprecated in sing-box 1.10.0 and removed in sing-box 1.11.0"
                .into(),
        ));
    }
    Ok(())
}

impl ResponseMatcher {
    fn matches_metadata(&self, response: &Message) -> bool {
        if self
            .response_code
            .is_some_and(|code| response.metadata.response_code != code)
        {
            return false;
        }
        if !records_match(&self.answers, &response.answers)
            || !records_match(&self.authorities, &response.authorities)
            || !records_match(&self.additionals, &response.additionals)
        {
            return false;
        }
        true
    }

    fn has_address_condition(&self) -> bool {
        !self.address.is_empty()
    }

    fn matches_address(&self, response: &Message) -> bool {
        self.address.matches(response, false)
    }
}

impl AddressMatcher {
    fn is_empty(&self) -> bool {
        !self.ip_accept_any && !self.ip_is_private && self.ip_cidrs.is_empty()
    }

    fn matches(&self, response: &Message, accept_empty: bool) -> bool {
        if self.is_empty() {
            return true;
        }
        let addresses = dns_response_addresses(response);
        if addresses.is_empty() && accept_empty {
            return true;
        }
        (self.ip_accept_any && !addresses.is_empty())
            || (self.ip_is_private && addresses.iter().any(is_private_address))
            || (!self.ip_cidrs.is_empty()
                && addresses.iter().any(|address| {
                    self.ip_cidrs.iter().any(|prefix| prefix.contains(address))
                }))
    }
}

fn parse_response_matcher(
    object: &Map<String, Value>,
    legacy_dns_mode: bool,
) -> Result<(Option<ResponseMatcher>, Option<AddressMatcher>), DnsRuleError> {
    let selector = match object.get("match_response") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => None,
        Some(Value::Bool(true)) => Some(ResponseSelector::Anonymous),
        Some(Value::String(tag)) if !tag.is_empty() => {
            Some(ResponseSelector::Tagged(tag.clone()))
        }
        Some(Value::String(_)) => {
            return Err(DnsRuleError::Invalid(
                "empty match_response tag".into(),
            ));
        }
        Some(_) => {
            return Err(DnsRuleError::Invalid(
                "invalid match_response value".into(),
            ));
        }
    };
    let address = parse_address_matcher(object)?;
    let response_code = object
        .get("response_rcode")
        .map(|value| parse_response_code(Some(value)))
        .transpose()?;
    let answers = parse_records(object, "response_answer")?;
    let authorities = parse_records(object, "response_ns")?;
    let additionals = parse_records(object, "response_extra")?;
    let has_response_metadata = response_code.is_some()
        || !answers.is_empty()
        || !authorities.is_empty()
        || !additionals.is_empty();
    let Some(selector) = selector else {
        if has_response_metadata || (!legacy_dns_mode && !address.is_empty()) {
            return Err(DnsRuleError::Invalid(
                "response match fields require match_response".into(),
            ));
        }
        let legacy_address = (!address.is_empty()).then_some(address);
        return Ok((None, legacy_address));
    };
    Ok((
        Some(ResponseMatcher {
            selector,
            address,
            response_code,
            answers,
            authorities,
            additionals,
        }),
        None,
    ))
}

fn parse_address_matcher(
    object: &Map<String, Value>,
) -> Result<AddressMatcher, DnsRuleError> {
    let ip_cidrs = match object.get("ip_cidr") {
        None => Vec::new(),
        Some(value) => {
            serde_json::from_value::<Listable<Prefixable>>(value.clone())
                .map(Listable::into_vec)
                .map(|values| values.into_iter().map(|value| value.0).collect())
                .map_err(|error| {
                    DnsRuleError::Invalid(format!("ip_cidr: {error}"))
                })?
        }
    };
    let ip_is_private = bool_field(object, "ip_is_private")?;
    let ip_accept_any = bool_field(object, "ip_accept_any")?;
    Ok(AddressMatcher {
        ip_cidrs,
        ip_is_private,
        ip_accept_any,
    })
}

fn records_match(expected: &[Record], actual: &[Record]) -> bool {
    expected.is_empty()
        || expected.iter().any(|expected| {
            actual.iter().any(|actual| {
                expected.name == actual.name
                    && expected.dns_class == actual.dns_class
                    && expected.data == actual.data
            })
        })
}

fn parse_query_types(
    object: &Map<String, Value>,
) -> Result<Vec<RecordType>, DnsRuleError> {
    let Some(value) = object.get("query_type") else {
        return Ok(Vec::new());
    };
    let values = match value {
        Value::Array(values) => values.clone(),
        value => vec![value.clone()],
    };
    values
        .into_iter()
        .map(|value| match value {
            Value::Number(value) => value
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .map(RecordType::from)
                .ok_or_else(|| {
                    DnsRuleError::Invalid(format!(
                        "unknown DNS query type: {value}"
                    ))
                }),
            Value::String(value)
                if !value
                    .chars()
                    .any(|character| character.is_ascii_lowercase()) =>
            {
                value.parse::<RecordType>().map_err(|_| {
                    DnsRuleError::Invalid(format!(
                        "unknown DNS query type: {value:?}"
                    ))
                })
            }
            value => Err(DnsRuleError::Invalid(format!(
                "unknown DNS query type: {value}"
            ))),
        })
        .collect()
}

#[derive(Default)]
struct DomainMatcher {
    exact: Vec<String>,
    suffix: Vec<(String, bool)>,
    keyword: Vec<String>,
    regex: Vec<Regex>,
}

impl DomainMatcher {
    fn compile(object: &Map<String, Value>) -> Result<Self, DnsRuleError> {
        let exact = string_list(object, "domain")?;
        if exact.iter().any(String::is_empty) {
            return Err(DnsRuleError::Invalid(
                "domain: empty item is not allowed".into(),
            ));
        }
        let suffix = string_list(object, "domain_suffix")?;
        if suffix.iter().any(String::is_empty) {
            return Err(DnsRuleError::Invalid(
                "domain_suffix: empty item is not allowed".into(),
            ));
        }
        Ok(Self {
            exact: exact.into_iter().map(|value| canonical(&value)).collect(),
            suffix: suffix
                .into_iter()
                .map(|value| {
                    let subdomains_only = value.starts_with('.');
                    let value = value.strip_prefix('.').unwrap_or(&value);
                    (canonical(value), subdomains_only)
                })
                .collect(),
            keyword: string_list(object, "domain_keyword")?
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            regex: string_list(object, "domain_regex")?
                .into_iter()
                .map(|pattern| {
                    Regex::new(&pattern).map_err(|error| {
                        DnsRuleError::Invalid(format!(
                            "invalid domain regex {pattern:?}: {error}"
                        ))
                    })
                })
                .collect::<Result<_, _>>()?,
        })
    }

    fn matches(&self, domain: &str) -> bool {
        if self.is_empty() {
            return true;
        }
        let domain = canonical(domain);
        self.exact.contains(&domain)
            || self.suffix.iter().any(|(suffix, subdomains_only)| {
                (!subdomains_only && domain == *suffix)
                    || domain
                        .strip_suffix(suffix)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            })
            || self.keyword.iter().any(|keyword| domain.contains(keyword))
            || self.regex.iter().any(|regex| regex.is_match(&domain))
    }

    fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.suffix.is_empty()
            && self.keyword.is_empty()
            && self.regex.is_empty()
    }
}

fn parse_action(
    object: &Map<String, Value>,
    nested: bool,
    logical: bool,
) -> Result<DnsAction, DnsRuleError> {
    let matcher_keys = if logical {
        LOGICAL_MATCH_KEYS
    } else {
        DEFAULT_MATCH_KEYS
    };
    let action_object = object
        .iter()
        .filter(|(key, _)| !matcher_keys.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Map<_, _>>();
    if nested {
        if !action_object.is_empty() {
            return Err(DnsRuleError::Invalid(
                DNS_RULE_ACTION_NESTED_UNSUPPORTED_MESSAGE.into(),
            ));
        }
        return Ok(DnsAction::Route {
            server: String::new(),
            speculative: false,
            options: DnsLookupOverride::default(),
        });
    }
    let action = match action_object.get("action") {
        None => "route",
        Some(Value::String(action)) => action.as_str(),
        Some(_) => {
            return Err(DnsRuleError::Invalid(
                "DNS rule action is not a string".into(),
            ));
        }
    };
    validate_action_shape(&action_object, action)?;
    match action {
        "" | "route" => {
            let server = action_object
                .get("server")
                .and_then(Value::as_str)
                .filter(|server| !server.is_empty())
                .ok_or_else(|| {
                    DnsRuleError::Invalid(
                        "route action has no DNS server".into(),
                    )
                })?
                .to_owned();
            Ok(DnsAction::Route {
                server,
                speculative: bool_field(&action_object, "speculative")?,
                options: parse_lookup_override(&action_object)?,
            })
        }
        "route-options" => {
            let options = parse_lookup_override(&action_object)?;
            if options.is_empty() {
                return Err(DnsRuleError::Invalid(
                    "empty DNS route option action".into(),
                ));
            }
            Ok(DnsAction::RouteOptions(options))
        }
        "evaluate" => {
            let server = action_object
                .get("server")
                .and_then(Value::as_str)
                .filter(|server| !server.is_empty())
                .ok_or_else(|| {
                    DnsRuleError::Invalid(
                        "evaluate action has no DNS server".into(),
                    )
                })?
                .to_owned();
            let tag = match action_object.get("tag") {
                None | Some(Value::Null) => None,
                Some(Value::String(tag)) if tag.is_empty() => None,
                Some(Value::String(tag)) => Some(tag.clone()),
                Some(_) => {
                    return Err(DnsRuleError::Invalid(
                        "DNS evaluate tag is not a string".into(),
                    ));
                }
            };
            Ok(DnsAction::Evaluate {
                server,
                tag,
                speculative: bool_field(&action_object, "speculative")?,
                options: parse_lookup_override(&action_object)?,
            })
        }
        "respond" => Ok(DnsAction::Respond),
        "reject" => {
            let method = action_object
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("default");
            if method == "reply" {
                return Err(DnsRuleError::Invalid(
                    crate::option::DNS_REPLY_REJECT_UNSUPPORTED_MESSAGE.into(),
                ));
            }
            if !matches!(method, "" | "default" | "drop") {
                return Err(DnsRuleError::Invalid(format!(
                    "unknown DNS reject method: {method}"
                )));
            }
            if method == "drop" && bool_field(&action_object, "no_drop")? {
                return Err(DnsRuleError::Invalid(
                    "no_drop is not available with drop reject method".into(),
                ));
            }
            Ok(DnsAction::Reject(DnsRejectAction {
                method: if method.is_empty() { "default" } else { method }
                    .to_owned(),
                no_drop: bool_field(&action_object, "no_drop")?,
                recent: std::sync::Mutex::new(VecDeque::new()),
            }))
        }
        "predefined" => Ok(DnsAction::Predefined(PredefinedAction {
            response_code: parse_response_code(action_object.get("rcode"))?,
            answers: parse_records(&action_object, "answer")?,
            authorities: parse_records(&action_object, "ns")?,
            additionals: parse_records(&action_object, "extra")?,
        })),
        action => Err(DnsRuleError::Invalid(format!(
            "DNS rule action {action:?} is not implemented"
        ))),
    }
}

fn validate_action_shape(
    object: &Map<String, Value>,
    action: &str,
) -> Result<(), DnsRuleError> {
    const COMMON: &[&str] = &[
        "timeout",
        "strategy",
        "disable_cache",
        "disable_optimistic_cache",
        "rewrite_ttl",
        "client_subnet",
        "remove_client_subnet",
    ];
    let allowed = |key: &str| match action {
        "" | "route" => {
            key == "server" || key == "speculative" || COMMON.contains(&key)
        }
        "evaluate" => {
            matches!(key, "server" | "tag" | "speculative")
                || COMMON.contains(&key)
        }
        "route-options" => COMMON.contains(&key),
        "respond" => false,
        "reject" => matches!(key, "method" | "no_drop"),
        "predefined" => matches!(key, "rcode" | "answer" | "ns" | "extra"),
        _ => true,
    };
    for (key, value) in object {
        if matches!(
            key.as_str(),
            "type"
                | "inbound"
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
                | "ip_version"
                | "query_type"
                | "query_client_subnet"
                | "query_dnssec"
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
                | "outbound"
                | "rule_set"
                | "rule_set_ip_cidr_match_source"
                | "rule_set_ip_cidr_accept_empty"
                | "rule_set_ipcidr_match_source"
                | "match_response"
                | "ip_cidr"
                | "ip_is_private"
                | "ip_accept_any"
                | "response_rcode"
                | "response_answer"
                | "response_ns"
                | "response_extra"
                | "invert"
                | "mode"
                | "rules"
                | "action"
                | "race"
        ) || allowed(key)
            || is_default_json(value)
        {
            continue;
        }
        return Err(DnsRuleError::Invalid(format!(
            "DNS rule field {key:?} is invalid for action {action:?}"
        )));
    }
    Ok(())
}

fn validate_keys(
    object: &Map<String, Value>,
    nested: bool,
    logical: bool,
) -> Result<(), DnsRuleError> {
    const MATCH_KEYS: &[&str] = &[
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
        "geosite",
        "source_geoip",
        "geoip",
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
        "outbound",
        "rule_set",
        "rule_set_ip_cidr_match_source",
        "rule_set_ip_cidr_accept_empty",
        "rule_set_ipcidr_match_source",
        "match_response",
        "ip_cidr",
        "ip_is_private",
        "ip_accept_any",
        "response_rcode",
        "response_answer",
        "response_ns",
        "response_extra",
        "invert",
    ];
    const ACTION_KEYS: &[&str] = &[
        "action",
        "server",
        "strategy",
        "method",
        "no_drop",
        "race",
        "rcode",
        "answer",
        "ns",
        "extra",
        "timeout",
        "disable_cache",
        "disable_optimistic_cache",
        "rewrite_ttl",
        "client_subnet",
        "remove_client_subnet",
        "speculative",
        "tag",
    ];
    let match_keys = if logical {
        LOGICAL_MATCH_KEYS
    } else {
        MATCH_KEYS
    };
    for (key, value) in object {
        let allowed = match_keys.contains(&key.as_str())
            || (!nested && ACTION_KEYS.contains(&key.as_str()));
        if !allowed && !is_default_json(value) {
            return Err(DnsRuleError::UnsupportedField(key.clone()));
        }
    }
    Ok(())
}

const DEFAULT_MATCH_KEYS: &[&str] = &[
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
    "geosite",
    "source_geoip",
    "geoip",
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
    "outbound",
    "rule_set",
    "rule_set_ip_cidr_match_source",
    "rule_set_ip_cidr_accept_empty",
    "rule_set_ipcidr_match_source",
    "match_response",
    "ip_cidr",
    "ip_is_private",
    "ip_accept_any",
    "response_rcode",
    "response_answer",
    "response_ns",
    "response_extra",
    "invert",
];

const LOGICAL_MATCH_KEYS: &[&str] = &["type", "mode", "rules", "invert"];

fn parse_lookup_override(
    object: &Map<String, Value>,
) -> Result<DnsLookupOverride, DnsRuleError> {
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Raw {
        timeout: ConfigDuration,
        strategy: DomainStrategy,
        disable_cache: bool,
        disable_optimistic_cache: bool,
        rewrite_ttl: Option<u32>,
        client_subnet: Option<Prefixable>,
        remove_client_subnet: bool,
    }
    let raw: Raw = serde_json::from_value(Value::Object(object.clone()))
        .map_err(|error| {
            DnsRuleError::Invalid(format!("invalid DNS route options: {error}"))
        })?;
    let timeout = if raw.timeout == ConfigDuration::ZERO {
        None
    } else {
        Some(raw.timeout.as_std().ok_or_else(|| {
            DnsRuleError::Invalid("DNS route timeout must be positive".into())
        })?)
    };
    if raw.client_subnet.is_some() && raw.remove_client_subnet {
        return Err(DnsRuleError::Invalid(
            "client_subnet and remove_client_subnet are mutually exclusive"
                .into(),
        ));
    }
    Ok(DnsLookupOverride {
        timeout,
        strategy: raw.strategy,
        disable_cache: raw.disable_cache,
        disable_optimistic_cache: raw.disable_optimistic_cache,
        rewrite_ttl: raw.rewrite_ttl,
        client_subnet: raw.client_subnet.map(|prefix| prefix.0),
        remove_client_subnet: raw.remove_client_subnet,
    })
}

fn parse_response_code(
    value: Option<&Value>,
) -> Result<ResponseCode, DnsRuleError> {
    let Some(value) = value else {
        return Ok(ResponseCode::NoError);
    };
    if let Some(value) = value.as_u64() {
        let value = u16::try_from(value).map_err(|_| {
            DnsRuleError::Invalid("DNS response code exceeds 65535".into())
        })?;
        return Ok(value.into());
    }
    let Some(value) = value.as_str() else {
        return Err(DnsRuleError::Invalid(
            "DNS response code must be an integer or string".into(),
        ));
    };
    let code = match value.to_ascii_uppercase().as_str() {
        "NOERROR" => ResponseCode::NoError,
        "FORMERR" => ResponseCode::FormErr,
        "SERVFAIL" => ResponseCode::ServFail,
        "NXDOMAIN" => ResponseCode::NXDomain,
        "NOTIMP" => ResponseCode::NotImp,
        "REFUSED" => ResponseCode::Refused,
        "YXDOMAIN" => ResponseCode::YXDomain,
        "YXRRSET" => ResponseCode::YXRRSet,
        "NXRRSET" => ResponseCode::NXRRSet,
        "NOTAUTH" => ResponseCode::NotAuth,
        "NOTZONE" => ResponseCode::NotZone,
        "BADSIG" => ResponseCode::BADSIG,
        "BADKEY" => ResponseCode::BADKEY,
        "BADTIME" => ResponseCode::BADTIME,
        "BADMODE" => ResponseCode::BADMODE,
        "BADNAME" => ResponseCode::BADNAME,
        "BADALG" => ResponseCode::BADALG,
        "BADTRUNC" => ResponseCode::BADTRUNC,
        "BADCOOKIE" => ResponseCode::BADCOOKIE,
        _ => {
            return Err(DnsRuleError::Invalid(format!(
                "unknown DNS response code: {value}"
            )));
        }
    };
    Ok(code)
}

fn parse_records(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Vec<Record>, DnsRuleError> {
    string_list(object, key)?
        .into_iter()
        .map(|value| {
            parse_record(&value).map_err(|error| {
                DnsRuleError::Invalid(format!(
                    "invalid {key} DNS record: {error}"
                ))
            })
        })
        .collect()
}

fn parse_record(value: &str) -> Result<Record, String> {
    value
        .parse::<DnsRecordOptions>()
        .map(|options| options.build())
}

fn string_list(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Vec<String>, DnsRuleError> {
    let Some(value) = object.get(key) else {
        return Ok(Vec::new());
    };
    serde_json::from_value::<Listable<String>>(value.clone())
        .map(Listable::into_vec)
        .map_err(|error| DnsRuleError::Invalid(format!("{key}: {error}")))
}

fn bool_field(
    object: &Map<String, Value>,
    key: &str,
) -> Result<bool, DnsRuleError> {
    match object.get(key) {
        None | Some(Value::Bool(false)) => Ok(false),
        Some(Value::Bool(true)) => Ok(true),
        Some(_) => Err(DnsRuleError::Invalid(format!("{key} is not boolean"))),
    }
}

fn canonical(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
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

#[derive(Default)]
struct LegacyDnsModeFlags {
    disabled: bool,
    needed: bool,
    needed_from_strategy: bool,
}

impl LegacyDnsModeFlags {
    fn merge(&mut self, other: Self) {
        self.disabled |= other.disabled;
        self.needed |= other.needed;
        self.needed_from_strategy |= other.needed_from_strategy;
    }
}

fn resolve_legacy_dns_mode_with_rule_sets(
    rules: &[Value],
    router: Option<&Router>,
    metadata_override: Option<(&str, RuleSetMetadata)>,
) -> Result<bool, DnsRuleError> {
    let mut flags = LegacyDnsModeFlags::default();
    for rule in rules {
        flags.merge(legacy_dns_mode_flags(rule, router, metadata_override)?);
    }
    if flags.disabled && flags.needed_from_strategy {
        return Err(DnsRuleError::Invalid(
            "Legacy `strategy` DNS rule action option is deprecated in sing-box 1.14.0 and will be removed in sing-box 1.16.0, checkout documentation for migration: https://sing-box.sagernet.org/migration/#migrate-dns-rule-action-strategy-to-rule-items"
                .into(),
        ));
    }
    Ok(!flags.disabled && flags.needed)
}

fn validate_modern_rule_set_metadata(
    rules: &[Value],
    router: &Router,
    metadata_override: Option<(&str, RuleSetMetadata)>,
) -> Result<(), DnsRuleError> {
    for rule in rules {
        validate_modern_rule_set_metadata_in_rule(
            rule,
            router,
            metadata_override,
        )?;
    }
    Ok(())
}

fn validate_modern_rule_set_metadata_in_rule(
    rule: &Value,
    router: &Router,
    metadata_override: Option<(&str, RuleSetMetadata)>,
) -> Result<(), DnsRuleError> {
    let Some(object) = rule.as_object() else {
        return Ok(());
    };
    if object.get("type").and_then(Value::as_str) == Some("logical") {
        if let Some(rules) = object.get("rules").and_then(Value::as_array) {
            for rule in rules {
                validate_modern_rule_set_metadata_in_rule(
                    rule,
                    router,
                    metadata_override,
                )?;
            }
        }
        return Ok(());
    }
    let match_response = match object.get("match_response") {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(tag)) => !tag.is_empty(),
        _ => false,
    };
    let has_direct_response_fields = [
        "ip_cidr",
        "ip_is_private",
        "ip_accept_any",
        "response_rcode",
        "response_answer",
        "response_ns",
        "response_extra",
    ]
    .iter()
    .any(|key| {
        object
            .get(*key)
            .is_some_and(|value| !is_default_json(value))
    });
    if !match_response && has_direct_response_fields {
        return Err(DnsRuleError::Invalid(
            "Response Match Fields (ip_cidr, ip_is_private, ip_accept_any, response_rcode, response_answer, response_ns, response_extra) require match_response to be enabled"
                .into(),
        ));
    }
    if match_response {
        return Ok(());
    }
    for tag in string_list(object, "rule_set")? {
        let metadata =
            lookup_rule_set_metadata(router, &tag, metadata_override)?;
        if metadata.contains_ip_cidr_rule && !metadata.contains_non_ip_cidr_rule
        {
            return Err(DnsRuleError::Invalid(
                legacy_dns_address_filter_message(),
            ));
        }
    }
    if object
        .get("rule_set_ip_cidr_accept_empty")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(DnsRuleError::Invalid(
            rule_set_ip_cidr_accept_empty_message(),
        ));
    }
    Ok(())
}

fn lookup_rule_set_metadata(
    router: &Router,
    tag: &str,
    metadata_override: Option<(&str, RuleSetMetadata)>,
) -> Result<RuleSetMetadata, DnsRuleError> {
    metadata_override
        .filter(|(updated_tag, _)| *updated_tag == tag)
        .map(|(_, metadata)| metadata)
        .or_else(|| router.rule_set(tag).map(|set| set.metadata()))
        .ok_or_else(|| {
            DnsRuleError::Invalid(format!("rule-set not found: {tag:?}"))
        })
}

fn legacy_dns_mode_flags(
    rule: &Value,
    router: Option<&Router>,
    metadata_override: Option<(&str, RuleSetMetadata)>,
) -> Result<LegacyDnsModeFlags, DnsRuleError> {
    let Some(object) = rule.as_object() else {
        return Ok(LegacyDnsModeFlags::default());
    };
    let raw_action = object
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("route");
    let action = if raw_action.is_empty() {
        "route"
    } else {
        raw_action
    };
    let strategy = object
        .get("strategy")
        .is_some_and(|value| !is_default_json(value));
    let race = object.get("race").and_then(Value::as_bool).unwrap_or(false);
    let action_disables = race
        || object
            .get("disable_optimistic_cache")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || matches!(action, "route" | "evaluate")
            && object
                .get("speculative")
                .and_then(Value::as_bool)
                .unwrap_or(false);
    let mut flags = LegacyDnsModeFlags {
        disabled: matches!(action, "evaluate" | "respond") || action_disables,
        needed: strategy,
        needed_from_strategy: strategy,
    };
    if object.get("type").and_then(Value::as_str) == Some("logical") {
        if let Some(rules) = object.get("rules").and_then(Value::as_array) {
            for rule in rules {
                flags.merge(legacy_dns_mode_flags(
                    rule,
                    router,
                    metadata_override,
                )?);
            }
        }
        return Ok(flags);
    }
    let match_response = match object.get("match_response") {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(tag)) => !tag.is_empty(),
        _ => false,
    };
    let has_response_metadata = [
        "response_rcode",
        "response_answer",
        "response_ns",
        "response_extra",
    ]
    .iter()
    .any(|key| {
        object
            .get(*key)
            .is_some_and(|value| !is_default_json(value))
    });
    flags.disabled |= match_response
        || has_response_metadata
        || object
            .get("ip_version")
            .is_some_and(|value| !is_default_json(value))
        || object
            .get("query_type")
            .is_some_and(|value| !is_default_json(value));
    let has_legacy_address = !match_response
        && (["ip_cidr", "ip_is_private", "ip_accept_any"]
            .iter()
            .any(|key| {
                object
                    .get(*key)
                    .is_some_and(|value| !is_default_json(value))
            }));
    flags.needed |= has_legacy_address
        || object
            .get("rule_set_ip_cidr_accept_empty")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    let rule_sets = string_list(object, "rule_set")?;
    let match_source = object
        .get("rule_set_ip_cidr_match_source")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(router) = router {
        for tag in rule_sets {
            let metadata =
                lookup_rule_set_metadata(router, &tag, metadata_override)?;
            flags.disabled |= metadata.contains_dns_query_type_rule;
            if !match_response
                && !match_source
                && metadata.contains_ip_cidr_rule
            {
                flags.needed = true;
            }
        }
    } else if !match_response && !match_source && !rule_sets.is_empty() {
        // Standalone resolver construction has no route registry yet. Keep
        // the previous conservative behavior until the embedding runtime can
        // supply rule-set metadata.
        flags.needed = true;
    }
    Ok(flags)
}

fn legacy_dns_address_filter_message() -> String {
    let note = crate::deprecated::LEGACY_DNS_ADDRESS_FILTER;
    format!(
        "{} is deprecated in sing-box {} and will be removed in sing-box {}, checkout documentation for migration: {}",
        note.description,
        note.deprecated_version,
        note.scheduled_version,
        note.migration_link,
    )
}

fn rule_set_ip_cidr_accept_empty_message() -> String {
    let note = crate::deprecated::RULE_SET_IP_CIDR_ACCEPT_EMPTY;
    format!(
        "{} is deprecated in sing-box {} and will be removed in sing-box {}, checkout documentation for migration: {}",
        note.description,
        note.deprecated_version,
        note.scheduled_version,
        note.migration_link,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        io,
        net::IpAddr,
        path::Path,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use hickory_proto::{
        op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
        rr::{
            Name, RData, Record, RecordType,
            rdata::{
                A,
                opt::{ClientSubnet, EdnsOption},
            },
        },
        serialize::binary::{BinEncodable, BinEncoder},
    };
    use serde_json::json;

    use super::{RdrcOptions, RoutingResolver, parse_record};
    use crate::{
        common::network::{Network, SocksAddr},
        dns::{
            LookupFuture, LookupOptions, MessageFuture, Resolver,
            persistent::PersistentDnsCache,
        },
        option::DomainStrategy,
        route::{Metadata, Router},
    };

    struct Fixed(&'static str);

    struct Preferred {
        address: &'static str,
        suffix: &'static str,
    }

    struct Empty;

    impl Resolver for Fixed {
        fn lookup<'a>(
            &'a self,
            _domain: &'a str,
            _strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            Box::pin(async move {
                Ok(vec![self.0.parse::<IpAddr>().map_err(io::Error::other)?])
            })
        }
    }

    impl Resolver for Preferred {
        fn lookup<'a>(
            &'a self,
            _domain: &'a str,
            _strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            Box::pin(async move {
                Ok(vec![
                    self.address.parse::<IpAddr>().map_err(io::Error::other)?,
                ])
            })
        }

        fn preferred_domain(&self, domain: &str) -> Option<bool> {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            Some(
                domain == self.suffix
                    || domain
                        .strip_suffix(self.suffix)
                        .is_some_and(|prefix| prefix.ends_with('.')),
            )
        }
    }

    impl Resolver for Empty {
        fn lookup<'a>(
            &'a self,
            _domain: &'a str,
            _strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    struct Recording {
        options: Mutex<Vec<LookupOptions>>,
    }

    struct DelayedResponse {
        started: Arc<AtomicUsize>,
        delay: Duration,
        last_octet: u8,
        response_code: ResponseCode,
    }

    struct TrackedDelayedResponse {
        delay: Duration,
        last_octet: u8,
        completed: Arc<AtomicUsize>,
    }

    impl Resolver for TrackedDelayedResponse {
        fn lookup<'a>(
            &'a self,
            _domain: &'a str,
            _strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
            Box::pin(async move {
                tokio::time::sleep(self.delay).await;
                self.completed.fetch_add(1, Ordering::SeqCst);
                let mut response = Message::new(
                    request.metadata.id,
                    MessageType::Response,
                    request.metadata.op_code,
                );
                response.queries = request.queries.clone();
                response.add_answer(Record::from_rdata(
                    request.queries[0].name().clone(),
                    60,
                    RData::A(A::new(192, 0, 2, self.last_octet)),
                ));
                Ok(response)
            })
        }
    }

    impl Resolver for DelayedResponse {
        fn lookup<'a>(
            &'a self,
            _domain: &'a str,
            _strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            Box::pin(async move {
                tokio::time::sleep(self.delay).await;
                Ok(vec![IpAddr::from([192, 0, 2, self.last_octet])])
            })
        }

        fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
            Box::pin(async move {
                self.started.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(self.delay).await;
                let mut response = Message::new(
                    request.metadata.id,
                    MessageType::Response,
                    request.metadata.op_code,
                );
                response.metadata.response_code = self.response_code;
                response.queries = request.queries.clone();
                response.add_answer(Record::from_rdata(
                    request.queries[0].name().clone(),
                    60,
                    RData::A(A::new(192, 0, 2, self.last_octet)),
                ));
                Ok(response)
            })
        }
    }

    impl Resolver for Recording {
        fn lookup<'a>(
            &'a self,
            domain: &'a str,
            strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            self.lookup_with_options(
                domain,
                LookupOptions {
                    strategy,
                    ..LookupOptions::default()
                },
            )
        }

        fn lookup_with_options<'a>(
            &'a self,
            _domain: &'a str,
            options: LookupOptions,
        ) -> LookupFuture<'a> {
            Box::pin(async move {
                self.options.lock().unwrap().push(options);
                Ok(vec!["2001:db8::1".parse().unwrap()])
            })
        }

        fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
            self.exchange_with_options(request, LookupOptions::default())
        }

        fn exchange_with_options<'a>(
            &'a self,
            request: &'a Message,
            options: LookupOptions,
        ) -> MessageFuture<'a> {
            Box::pin(async move {
                self.options.lock().unwrap().push(options);
                let mut response = Message::new(
                    request.metadata.id,
                    MessageType::Response,
                    request.metadata.op_code,
                );
                response.queries = request.queries.clone();
                Ok(response)
            })
        }
    }

    #[tokio::test]
    async fn routes_domain_rules_and_logical_children() {
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
        let special: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.2"));
        let mut resolvers = HashMap::new();
        resolvers.insert("fallback".into(), fallback.clone());
        resolvers.insert("special".into(), special);
        let routing = RoutingResolver::compile(
            &[json!({
                "type":"logical",
                "mode":"and",
                "rules":[
                    {"domain_suffix":"example.com"},
                    {"domain_keyword":"api"}
                ],
                "server":"special"
            })],
            resolvers,
            fallback,
        )
        .unwrap();
        assert_eq!(
            routing
                .lookup("api.example.com", DomainStrategy::AsIs)
                .await
                .unwrap()[0]
                .to_string(),
            "192.0.2.2"
        );
        assert_eq!(
            routing
                .lookup("www.example.com", DomainStrategy::AsIs)
                .await
                .unwrap()[0]
                .to_string(),
            "192.0.2.1"
        );
    }

    #[tokio::test]
    async fn preferred_by_uses_dns_transport_domain_ownership() {
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
        let preferred: Arc<dyn Resolver> = Arc::new(Preferred {
            address: "192.0.2.2",
            suffix: "corp.example",
        });
        let mut resolvers = HashMap::new();
        resolvers.insert("corp-dns".into(), preferred);
        let routing = RoutingResolver::compile(
            &[json!({
                "preferred_by":"corp-dns",
                "server":"corp-dns"
            })],
            resolvers,
            fallback,
        )
        .unwrap();
        assert_eq!(
            routing
                .lookup("api.corp.example", DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["192.0.2.2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            routing
                .lookup("public.example", DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );

        let misleading_route_context = Metadata {
            preferred_by: vec!["corp-dns".into()],
            ..Metadata::default()
        };
        assert_eq!(
            routing
                .lookup_with_context(
                    "public.example",
                    LookupOptions {
                        strategy: DomainStrategy::Ipv4Only,
                        ..LookupOptions::default()
                    },
                    &misleading_route_context,
                )
                .await
                .unwrap(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );

        for (resolvers, expected) in [
            (HashMap::new(), "DNS server not found: missing"),
            (
                HashMap::from([(
                    "unsupported".into(),
                    Arc::new(Fixed("192.0.2.3")) as Arc<dyn Resolver>,
                )]),
                "DNS server does not support preferred_by: unsupported",
            ),
        ] {
            let tag = if resolvers.is_empty() {
                "missing"
            } else {
                "unsupported"
            };
            let error = RoutingResolver::compile(
                &[json!({"preferred_by":tag})],
                resolvers,
                Arc::new(Fixed("192.0.2.1")),
            )
            .err()
            .expect("invalid preferred_by must fail");
            assert!(
                error.to_string().contains(expected),
                "unexpected error: {error}"
            );
        }
    }

    #[tokio::test]
    async fn leading_dot_suffix_excludes_the_root_domain_like_go() {
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
        let special: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.2"));
        let mut resolvers = HashMap::new();
        resolvers.insert("special".into(), special);
        let routing = RoutingResolver::compile(
            &[json!({
                "domain_suffix":".example.com",
                "server":"special"
            })],
            resolvers,
            fallback,
        )
        .unwrap();
        assert_eq!(
            routing
                .lookup("www.example.com", DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["192.0.2.2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            routing
                .lookup("example.com", DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
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
            let error = RoutingResolver::compile(
                &[rule],
                HashMap::new(),
                Arc::new(Fixed("192.0.2.1")),
            )
            .err()
            .expect("empty domain item must fail");
            assert!(
                error.to_string().contains(expected),
                "unexpected error: {error}"
            );
        }
    }

    #[tokio::test]
    async fn dns_reject_flood_protection_and_no_drop_match_route_action() {
        async fn exercise(no_drop: bool) -> Vec<io::Result<Message>> {
            let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
            let routing = RoutingResolver::compile(
                &[json!({
                    "action": "reject",
                    "no_drop": no_drop
                })],
                HashMap::new(),
                fallback,
            )
            .unwrap();
            let mut request = Message::query();
            request.add_query(Query::query(
                Name::from_ascii("reject.example.").unwrap(),
                RecordType::A,
            ));
            let mut results = Vec::new();
            for _ in 0..51 {
                results.push(routing.exchange(&request).await);
            }
            results
        }

        let protected = exercise(false).await;
        assert!(protected[..50].iter().all(|result| {
            result.as_ref().is_ok_and(|response| {
                response.metadata.response_code == ResponseCode::Refused
            })
        }));
        assert_eq!(
            protected[50].as_ref().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );

        let no_drop = exercise(true).await;
        assert!(no_drop.iter().all(|result| {
            result.as_ref().is_ok_and(|response| {
                response.metadata.response_code == ResponseCode::Refused
            })
        }));
    }

    #[test]
    fn dns_rule_decoding_respects_go_parent_field_exclusion() {
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
        let remote: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.2"));
        let mut resolvers = HashMap::new();
        resolvers.insert("fallback".into(), fallback.clone());
        resolvers.insert("remote".into(), remote);

        RoutingResolver::compile(
            &[json!({
                "outbound": "direct",
                "server": "remote"
            })],
            resolvers.clone(),
            fallback.clone(),
        )
        .expect("default matcher owns outbound before action decoding");

        for invalid in [
            json!({
                "type": "logical",
                "mode": "or",
                "rules": [{"domain": "example.com"}],
                "domain": "must-not-be-ignored",
                "server": "remote"
            }),
            json!({"type": 1, "server": "remote"}),
            json!({"action": 1, "server": "remote"}),
        ] {
            assert!(
                RoutingResolver::compile(
                    &[invalid],
                    resolvers.clone(),
                    fallback.clone(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn deprecated_dns_matchers_report_go_compatible_errors() {
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
        for (rule, expected) in [
            (
                json!({"geosite":"cn","action":"reject"}),
                "geosite database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0",
            ),
            (
                json!({"source_geoip":"private","action":"reject"}),
                "geoip database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0",
            ),
            (
                json!({"geoip":"cn","action":"reject"}),
                "geoip database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0",
            ),
            (
                json!({
                    "rule_set_ip_cidr_accept_empty":true,
                    "query_type":"A",
                    "action":"reject"
                }),
                "Legacy `rule_set_ip_cidr_accept_empty` DNS rule item is deprecated in sing-box 1.14.0",
            ),
            (
                json!({
                    "rule_set":"missing",
                    "rule_set_ipcidr_match_source":true,
                    "action":"reject"
                }),
                "rule_set_ipcidr_match_source is deprecated in sing-box 1.10.0 and removed in sing-box 1.11.0",
            ),
        ] {
            let error = match RoutingResolver::compile(
                &[rule],
                HashMap::new(),
                fallback.clone(),
            ) {
                Ok(_) => panic!("deprecated DNS matcher unexpectedly compiled"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected),
                "unexpected error: {error}"
            );
        }

        RoutingResolver::compile(
            &[json!({
                "rule_set_ipcidr_match_source":true,
                "action":"reject"
            })],
            HashMap::new(),
            fallback,
        )
        .expect("Go ignores the deprecated spelling without rule_set");

        RoutingResolver::compile(
            &[json!({
                "rule_set_ip_cidr_accept_empty":true,
                "action":"reject"
            })],
            HashMap::new(),
            Arc::new(Fixed("192.0.2.1")),
        )
        .expect("Go retains this deprecated field in legacy DNS mode");
    }

    #[tokio::test]
    async fn legacy_address_filter_retries_the_next_route() {
        for (rule, candidate_ip, expected_ip) in [
            (
                json!({"ip_cidr":"203.0.113.0/24","server":"candidate"}),
                "203.0.113.9",
                "203.0.113.9",
            ),
            (
                json!({"ip_cidr":"203.0.113.0/24","server":"candidate"}),
                "198.51.100.9",
                "192.0.2.1",
            ),
            (
                json!({
                    "ip_cidr":"203.0.113.0/24",
                    "invert":true,
                    "server":"candidate"
                }),
                "198.51.100.9",
                "198.51.100.9",
            ),
            (
                json!({
                    "ip_cidr":"203.0.113.0/24",
                    "invert":true,
                    "server":"candidate"
                }),
                "203.0.113.9",
                "192.0.2.1",
            ),
        ] {
            let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.254"));
            let mut resolvers = HashMap::new();
            resolvers.insert(
                "candidate".into(),
                Arc::new(Fixed(candidate_ip)) as Arc<dyn Resolver>,
            );
            resolvers.insert(
                "backup".into(),
                Arc::new(Fixed("192.0.2.1")) as Arc<dyn Resolver>,
            );
            let routing = RoutingResolver::compile(
                &[rule, json!({"server":"backup"})],
                resolvers,
                fallback,
            )
            .unwrap();
            assert!(routing.legacy_dns_mode);
            assert_eq!(
                routing
                    .lookup("lookup.example", DomainStrategy::Ipv4Only)
                    .await
                    .unwrap(),
                [expected_ip.parse::<IpAddr>().unwrap()]
            );
        }
    }

    #[tokio::test]
    async fn legacy_rule_set_address_filter_and_accept_empty_match_go() {
        let route_router = Arc::new(
            Router::from_json_with_rule_sets(
                &[],
                "",
                &[json!({
                    "type":"inline",
                    "tag":"candidate-net",
                    "rules":[{"ip_cidr":"203.0.113.0/24"}]
                })],
                Path::new("."),
            )
            .unwrap(),
        );

        for (candidate_ip, invert, expected_ip) in [
            ("203.0.113.9", false, "203.0.113.9"),
            ("198.51.100.9", false, "192.0.2.1"),
            ("203.0.113.9", true, "192.0.2.1"),
            ("198.51.100.9", true, "198.51.100.9"),
        ] {
            let mut resolvers = HashMap::new();
            resolvers.insert(
                "candidate".into(),
                Arc::new(Fixed(candidate_ip)) as Arc<dyn Resolver>,
            );
            resolvers.insert(
                "backup".into(),
                Arc::new(Fixed("192.0.2.1")) as Arc<dyn Resolver>,
            );
            let routing = RoutingResolver::compile(
                &[
                    json!({
                        "rule_set":"candidate-net",
                        "invert":invert,
                        "server":"candidate"
                    }),
                    json!({"server":"backup"}),
                ],
                resolvers,
                Arc::new(Fixed("192.0.2.254")),
            )
            .unwrap();
            routing.configure_rule_set_router(&route_router).unwrap();
            assert!(routing.legacy_dns_mode);
            assert_eq!(
                routing
                    .lookup("lookup.example", DomainStrategy::Ipv4Only)
                    .await
                    .unwrap(),
                [expected_ip.parse::<IpAddr>().unwrap()],
                "candidate={candidate_ip} invert={invert}"
            );
        }

        for (accept_empty, expect_empty) in [(false, false), (true, true)] {
            let mut resolvers = HashMap::new();
            resolvers.insert(
                "candidate".into(),
                Arc::new(Empty) as Arc<dyn Resolver>,
            );
            resolvers.insert(
                "backup".into(),
                Arc::new(Fixed("192.0.2.1")) as Arc<dyn Resolver>,
            );
            let routing = RoutingResolver::compile(
                &[
                    json!({
                        "rule_set":"candidate-net",
                        "rule_set_ip_cidr_accept_empty":accept_empty,
                        "server":"candidate"
                    }),
                    json!({"server":"backup"}),
                ],
                resolvers,
                Arc::new(Fixed("192.0.2.254")),
            )
            .unwrap();
            routing.configure_rule_set_router(&route_router).unwrap();
            let mut request = Message::query();
            request.add_query(Query::query(
                Name::from_ascii("lookup.example.").unwrap(),
                RecordType::A,
            ));
            let response = routing.exchange(&request).await.unwrap();
            assert_eq!(response.answers.is_empty(), expect_empty);
            if !expect_empty {
                assert_eq!(response.answers[0].data.to_string(), "192.0.2.1");
            }
        }

        let started = Arc::new(AtomicUsize::new(0));
        let mut resolvers = HashMap::new();
        resolvers.insert(
            "candidate".into(),
            Arc::new(DelayedResponse {
                started: started.clone(),
                delay: Duration::ZERO,
                last_octet: 9,
                response_code: ResponseCode::NoError,
            }) as Arc<dyn Resolver>,
        );
        resolvers.insert(
            "backup".into(),
            Arc::new(Fixed("192.0.2.1")) as Arc<dyn Resolver>,
        );
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "domain_suffix":"domain-hit.example",
                    "rule_set":"candidate-net",
                    "invert":true,
                    "server":"candidate"
                }),
                json!({"server":"backup"}),
            ],
            resolvers,
            Arc::new(Fixed("192.0.2.254")),
        )
        .unwrap();
        routing.configure_rule_set_router(&route_router).unwrap();
        assert_eq!(
            routing
                .lookup("domain-hit.example", DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(started.load(Ordering::SeqCst), 0);

        let domain_router = Arc::new(
            Router::from_json_with_rule_sets(
                &[],
                "",
                &[json!({
                    "type":"inline",
                    "tag":"domain-only",
                    "rules":[{"domain_suffix":"example"}]
                })],
                Path::new("."),
            )
            .unwrap(),
        );
        let selected = Arc::new(Recording {
            options: Mutex::new(Vec::new()),
        });
        let routing = RoutingResolver::compile(
            &[json!({
                "rule_set":"domain-only",
                "server":"selected"
            })],
            HashMap::from([(
                "selected".into(),
                selected.clone() as Arc<dyn Resolver>,
            )]),
            Arc::new(Fixed("192.0.2.254")),
        )
        .unwrap();
        routing.configure_rule_set_router(&domain_router).unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("lookup.example.").unwrap(),
            RecordType::TXT,
        ));
        routing.exchange(&request).await.unwrap();
        assert_eq!(selected.options.lock().unwrap().len(), 1);
    }

    #[test]
    fn rule_set_metadata_selects_dns_mode_and_rejects_mode_changing_reload() {
        for (initial_rule, updated_rule, expected_legacy) in [
            (
                json!({"ip_cidr":"203.0.113.0/24"}),
                json!({"query_type":"A"}),
                true,
            ),
            (
                json!({"query_type":"A"}),
                json!({"ip_cidr":"203.0.113.0/24"}),
                false,
            ),
        ] {
            let route_router = Arc::new(
                Router::from_json_with_rule_sets(
                    &[],
                    "",
                    &[json!({
                        "type":"inline",
                        "tag":"dynamic",
                        "rules":[initial_rule]
                    })],
                    Path::new("."),
                )
                .unwrap(),
            );
            let routing =
                RoutingResolver::compile_with_runtime_cache_and_rule_sets(
                    &[json!({"rule_set":"dynamic","server":"selected"})],
                    HashMap::from([(
                        "selected".into(),
                        Arc::new(Fixed("192.0.2.1")) as Arc<dyn Resolver>,
                    )]),
                    Arc::new(Fixed("192.0.2.254")),
                    &HashSet::new(),
                    None,
                    Some(&route_router),
                )
                .unwrap();
            assert_eq!(routing.legacy_dns_mode, expected_legacy);
            routing.configure_rule_set_router(&route_router).unwrap();

            let rule_set = route_router.rule_set("dynamic").unwrap();
            let previous_metadata = rule_set.metadata();
            let content = serde_json::to_vec(&json!({
                "version": 5,
                "rules": [updated_rule]
            }))
            .unwrap();
            let error = rule_set.reload("source", &content).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Legacy Address Filter Fields in DNS rules"),
                "{error}"
            );
            assert_eq!(rule_set.generation(), 0);
            assert_eq!(rule_set.metadata(), previous_metadata);

            drop(routing);
            rule_set.reload("source", &content).unwrap();
            assert_eq!(rule_set.generation(), 1);
            assert_ne!(rule_set.metadata(), previous_metadata);
        }

        let route_router = Arc::new(
            Router::from_json_with_rule_sets(
                &[],
                "",
                &[json!({
                    "type":"inline",
                    "tag":"dynamic",
                    "rules":[{"domain":"before.example"}]
                })],
                Path::new("."),
            )
            .unwrap(),
        );
        let routing =
            RoutingResolver::compile_with_runtime_cache_and_rule_sets(
                &[json!({
                    "ip_cidr":"203.0.113.0/24",
                    "rule_set":"dynamic",
                    "server":"selected"
                })],
                HashMap::from([(
                    "selected".into(),
                    Arc::new(Fixed("192.0.2.1")) as Arc<dyn Resolver>,
                )]),
                Arc::new(Fixed("192.0.2.254")),
                &HashSet::new(),
                None,
                Some(&route_router),
            )
            .unwrap();
        assert!(routing.legacy_dns_mode);
        routing.configure_rule_set_router(&route_router).unwrap();
        let rule_set = route_router.rule_set("dynamic").unwrap();
        let content = serde_json::to_vec(&json!({
            "version":5,
            "rules":[{"query_type":"A"}]
        }))
        .unwrap();
        let error = rule_set.reload("source", &content).unwrap_err();
        assert!(
            error.to_string().contains(
                "Response Match Fields (ip_cidr, ip_is_private, ip_accept_any, response_rcode, response_answer, response_ns, response_extra) require match_response to be enabled"
            ),
            "{error}"
        );
        assert_eq!(rule_set.generation(), 0);
    }

    #[test]
    fn modern_dns_mode_rejects_pure_ip_rule_set_without_response_matching() {
        let pure_ip_router = Arc::new(
            Router::from_json_with_rule_sets(
                &[],
                "",
                &[json!({
                    "type":"inline",
                    "tag":"dynamic",
                    "rules":[{"ip_cidr":"203.0.113.0/24"}]
                })],
                Path::new("."),
            )
            .unwrap(),
        );
        let rules = [
            json!({"query_type":"A","server":"selected"}),
            json!({"rule_set":"dynamic","server":"selected"}),
        ];
        let resolvers = HashMap::from([(
            "selected".into(),
            Arc::new(Fixed("192.0.2.1")) as Arc<dyn Resolver>,
        )]);
        let result = RoutingResolver::compile_with_runtime_cache_and_rule_sets(
            &rules,
            resolvers.clone(),
            Arc::new(Fixed("192.0.2.254")),
            &HashSet::new(),
            None,
            Some(&pure_ip_router),
        );
        let error = match result {
            Ok(_) => panic!("pure-IP rule-set was accepted in modern DNS mode"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("Legacy Address Filter Fields in DNS rules"),
            "{error}"
        );

        let dynamic_router = Arc::new(
            Router::from_json_with_rule_sets(
                &[],
                "",
                &[json!({
                    "type":"inline",
                    "tag":"dynamic",
                    "rules":[{"domain":"before.example"}]
                })],
                Path::new("."),
            )
            .unwrap(),
        );
        let routing =
            RoutingResolver::compile_with_runtime_cache_and_rule_sets(
                &rules,
                resolvers,
                Arc::new(Fixed("192.0.2.254")),
                &HashSet::new(),
                None,
                Some(&dynamic_router),
            )
            .unwrap();
        assert!(!routing.legacy_dns_mode);
        routing.configure_rule_set_router(&dynamic_router).unwrap();

        let rule_set = dynamic_router.rule_set("dynamic").unwrap();
        let pure_ip = serde_json::to_vec(&json!({
            "version":5,
            "rules":[{"ip_cidr":"203.0.113.0/24"}]
        }))
        .unwrap();
        let error = rule_set.reload("source", &pure_ip).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Legacy Address Filter Fields in DNS rules"),
            "{error}"
        );
        assert_eq!(rule_set.generation(), 0);
        assert!(!rule_set.metadata().contains_ip_cidr_rule);

        let mixed = serde_json::to_vec(&json!({
            "version":5,
            "rules":[
                {"domain":"after.example"},
                {"ip_cidr":"203.0.113.0/24"}
            ]
        }))
        .unwrap();
        rule_set.reload("source", &mixed).unwrap();
        assert_eq!(rule_set.generation(), 1);
        assert!(rule_set.metadata().contains_ip_cidr_rule);
        assert!(rule_set.metadata().contains_non_ip_cidr_rule);
    }

    #[test]
    fn rejects_reply_method_with_upstream_dns_error() {
        let result = RoutingResolver::compile(
            &[json!({"action":"reject","method":"reply"})],
            HashMap::new(),
            Arc::new(Fixed("192.0.2.254")),
        );
        let error = match result {
            Ok(_) => panic!("DNS reply reject method was accepted"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains(crate::option::DNS_REPLY_REJECT_UNSUPPORTED_MESSAGE),
            "{error}"
        );
    }

    #[tokio::test]
    async fn legacy_address_filter_rejection_uses_rdrc() {
        let started = Arc::new(AtomicUsize::new(0));
        let mut resolvers = HashMap::new();
        resolvers.insert(
            "candidate".into(),
            Arc::new(DelayedResponse {
                started: started.clone(),
                delay: Duration::ZERO,
                last_octet: 9,
                response_code: ResponseCode::NoError,
            }) as Arc<dyn Resolver>,
        );
        resolvers.insert(
            "backup".into(),
            Arc::new(Fixed("192.0.2.1")) as Arc<dyn Resolver>,
        );
        let directory = tempfile::tempdir().unwrap();
        let routing = RoutingResolver::compile_with_runtime_cache(
            &[
                json!({
                    "ip_cidr":"203.0.113.0/24",
                    "server":"candidate"
                }),
                json!({"server":"backup"}),
            ],
            resolvers,
            Arc::new(Fixed("192.0.2.254")),
            &HashSet::new(),
            Some(RdrcOptions {
                cache: Arc::new(
                    PersistentDnsCache::open(
                        directory.path().join("cache.db"),
                        "",
                    )
                    .unwrap(),
                ),
                timeout: Duration::from_secs(60),
            }),
        )
        .unwrap();
        for _ in 0..2 {
            assert_eq!(
                routing
                    .lookup("lookup.example", DomainStrategy::Ipv4Only)
                    .await
                    .unwrap(),
                ["192.0.2.1".parse::<IpAddr>().unwrap()]
            );
        }
        assert_eq!(started.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn routes_with_inbound_process_and_network_context() {
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
        let contextual: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.77"));
        let mut resolvers = HashMap::new();
        resolvers.insert("fallback".into(), fallback.clone());
        resolvers.insert("contextual".into(), contextual);
        let routing = RoutingResolver::compile(
            &[json!({
                "domain_suffix":"example",
                "inbound":"office",
                "network":"tcp",
                "process_name":"browser",
                "source_ip_cidr":"10.0.0.0/8",
                "source_port_range":"1000:2000",
                "port":853,
                "user":"alice",
                "server":"contextual"
            })],
            resolvers,
            fallback,
        )
        .unwrap();
        let context = Metadata {
            inbound: "office".into(),
            source: Some(SocksAddr::new("10.0.0.2", 1234)),
            destination: Some(SocksAddr::new("resolver.example", 853)),
            network: Some(Network::Tcp),
            process_name: "browser".into(),
            user: "alice".into(),
            ..Metadata::default()
        };
        let options = LookupOptions {
            strategy: DomainStrategy::Ipv4Only,
            ..LookupOptions::default()
        };
        assert_eq!(
            routing
                .lookup_with_context("resolver.example", options, &context)
                .await
                .unwrap(),
            ["192.0.2.77".parse::<IpAddr>().unwrap()]
        );

        let mismatched = Metadata {
            process_name: "terminal".into(),
            ..context
        };
        assert_eq!(
            routing
                .lookup_with_context("resolver.example", options, &mismatched,)
                .await
                .unwrap(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn query_type_routes_each_lookup_address_family() {
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
        let ipv4: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.44"));
        let ipv6: Arc<dyn Resolver> = Arc::new(Fixed("2001:db8::44"));
        let mut resolvers = HashMap::new();
        resolvers.insert("fallback".into(), fallback.clone());
        resolvers.insert("ipv4".into(), ipv4);
        resolvers.insert("ipv6".into(), ipv6);
        let routing = RoutingResolver::compile(
            &[
                json!({"query_type":["A", 1],"server":"ipv4"}),
                json!({"ip_version":6,"server":"ipv6"}),
            ],
            resolvers,
            fallback,
        )
        .unwrap();
        assert_eq!(
            routing
                .lookup("example.com", DomainStrategy::AsIs)
                .await
                .unwrap(),
            [
                "192.0.2.44".parse::<IpAddr>().unwrap(),
                "2001:db8::44".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn raw_query_matches_ecs_and_dnssec_metadata() {
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "query_type":"TXT",
                    "query_client_subnet":"198.51.100.0/24",
                    "query_dnssec":true,
                    "action":"predefined",
                    "answer":"example.com. 60 IN TXT \"metadata-match\""
                }),
                json!({
                    "action":"predefined",
                    "answer":"example.com. 60 IN TXT \"fallback\""
                }),
            ],
            HashMap::new(),
            fallback,
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::TXT,
        ));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "198.51.100.17".parse().unwrap(),
                25,
                0,
            )));
        request.edns = Some(edns);
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.answers[0].data.to_string(), "metadata-match");

        request.edns = None;
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.answers[0].data.to_string(), "fallback");
    }

    #[tokio::test]
    async fn tagged_evaluate_matches_response_and_responds() {
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.9"));
        let evaluated: Arc<dyn Resolver> = Arc::new(
            RoutingResolver::compile(
                &[json!({
                    "action":"predefined",
                    "answer":[
                        "example.com. 60 IN A 10.0.0.7",
                        "example.com. 60 IN TXT \"candidate\""
                    ],
                    "ns":"example.com. 60 IN NS ns.example.com.",
                    "extra":"ns.example.com. 60 IN A 10.0.0.53"
                })],
                HashMap::new(),
                fallback.clone(),
            )
            .unwrap(),
        );
        let mut resolvers = HashMap::new();
        resolvers.insert("candidate".into(), evaluated);
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "action":"evaluate",
                    "server":"candidate",
                    "tag":"checked"
                }),
                json!({
                    "match_response":"checked",
                    "response_rcode":"NOERROR",
                    "ip_cidr":"10.0.0.0/8",
                    "ip_is_private":true,
                    "ip_accept_any":true,
                    "response_answer":"example.com. 1 IN TXT \"candidate\"",
                    "response_ns":"example.com. 1 IN NS ns.example.com.",
                    "response_extra":"ns.example.com. 1 IN A 10.0.0.53",
                    "action":"respond"
                }),
            ],
            resolvers,
            fallback,
        )
        .unwrap();

        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.answers[0].data.to_string(), "10.0.0.7");
        assert_eq!(
            routing
                .lookup("example.com", DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["10.0.0.7".parse::<IpAddr>().unwrap()]
        );

        assert!(
            RoutingResolver::compile(
                &[json!({
                    "response_rcode":"NXDOMAIN",
                    "action":"reject"
                })],
                HashMap::new(),
                Arc::new(Fixed("192.0.2.1")),
            )
            .is_err()
        );
        assert!(
            RoutingResolver::compile(
                &[json!({
                    "match_response":"missing",
                    "action":"reject"
                })],
                HashMap::new(),
                Arc::new(Fixed("192.0.2.1")),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn response_private_ip_uses_sing_non_public_address_semantics() {
        for candidate in ["169.254.1.1", "224.0.0.1", "ff02::1"] {
            let mut resolvers = HashMap::new();
            resolvers.insert(
                "candidate".into(),
                Arc::new(Fixed(candidate)) as Arc<dyn Resolver>,
            );
            let routing = RoutingResolver::compile(
                &[
                    json!({
                        "action":"evaluate",
                        "server":"candidate",
                        "tag":"checked"
                    }),
                    json!({
                        "match_response":"checked",
                        "ip_is_private":true,
                        "action":"respond"
                    }),
                ],
                resolvers,
                Arc::new(Fixed("8.8.8.8")),
            )
            .unwrap();
            assert_eq!(
                routing
                    .lookup(
                        "example.com",
                        if candidate.contains(':') {
                            DomainStrategy::Ipv6Only
                        } else {
                            DomainStrategy::Ipv4Only
                        },
                    )
                    .await
                    .unwrap(),
                [candidate.parse::<IpAddr>().unwrap()],
                "{candidate} must match ip_is_private"
            );
        }
    }

    #[tokio::test]
    async fn response_ip_matchers_ignore_addresses_from_error_rcodes() {
        let started = Arc::new(AtomicUsize::new(0));
        let candidate: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: started.clone(),
            delay: Duration::ZERO,
            last_octet: 7,
            response_code: ResponseCode::NXDomain,
        });
        let fallback: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started,
            delay: Duration::ZERO,
            last_octet: 9,
            response_code: ResponseCode::NoError,
        });
        let mut resolvers = HashMap::new();
        resolvers.insert("candidate".into(), candidate);
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "action":"evaluate",
                    "server":"candidate",
                    "tag":"checked"
                }),
                json!({
                    "match_response":"checked",
                    "ip_accept_any":true,
                    "action":"respond"
                }),
            ],
            resolvers,
            fallback,
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers[0].data.to_string(), "192.0.2.9");
    }

    #[tokio::test]
    async fn response_ip_matchers_include_https_address_hints() {
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.9"));
        let evaluated: Arc<dyn Resolver> = Arc::new(
            RoutingResolver::compile(
                &[json!({
                    "action":"predefined",
                    "answer":"example.com. 60 IN HTTPS 1 . ipv4hint=10.0.0.7 ipv6hint=fd00::7"
                })],
                HashMap::new(),
                fallback.clone(),
            )
            .unwrap(),
        );
        let mut resolvers = HashMap::new();
        resolvers.insert("candidate".into(), evaluated);
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "action":"evaluate",
                    "server":"candidate",
                    "tag":"checked"
                }),
                json!({
                    "match_response":"checked",
                    "ip_cidr":["10.0.0.0/8", "fd00::/8"],
                    "action":"respond"
                }),
            ],
            resolvers,
            fallback,
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::HTTPS,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert!(matches!(response.answers[0].data, RData::HTTPS(_)));
    }

    #[tokio::test]
    async fn independent_tagged_evaluations_launch_in_parallel() {
        let started = Arc::new(AtomicUsize::new(0));
        let x: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: started.clone(),
            delay: Duration::from_millis(60),
            last_octet: 1,
            response_code: ResponseCode::NoError,
        });
        let y: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: started.clone(),
            delay: Duration::from_millis(60),
            last_octet: 2,
            response_code: ResponseCode::NoError,
        });
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.9"));
        let mut resolvers = HashMap::new();
        resolvers.insert("x".into(), x);
        resolvers.insert("y".into(), y);
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "action":"evaluate",
                    "server":"x",
                    "tag":"x",
                    "speculative":true
                }),
                json!({"action":"evaluate","server":"y","tag":"y"}),
                json!({
                    "match_response":"x",
                    "response_rcode":"NOERROR",
                    "action":"respond"
                }),
            ],
            resolvers,
            fallback,
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("parallel.example.").unwrap(),
            RecordType::A,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.answers[0].data.to_string(), "192.0.2.1");
        assert_eq!(started.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rdrc_skips_a_previously_rejected_evaluation() {
        let started = Arc::new(AtomicUsize::new(0));
        let rejected: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: started.clone(),
            delay: Duration::ZERO,
            last_octet: 9,
            response_code: ResponseCode::NoError,
        });
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("203.0.113.1"));
        let mut resolvers = HashMap::new();
        resolvers.insert("rejected".into(), rejected);
        let directory = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            PersistentDnsCache::open(directory.path().join("cache.db"), "")
                .unwrap(),
        );
        let routing = RoutingResolver::compile_with_runtime_cache(
            &[
                json!({
                    "action":"evaluate",
                    "server":"rejected",
                    "tag":"checked"
                }),
                json!({
                    "match_response":"checked",
                    "ip_cidr":"203.0.113.0/24",
                    "action":"respond"
                }),
            ],
            resolvers,
            fallback,
            &HashSet::new(),
            Some(RdrcOptions {
                cache,
                timeout: Duration::from_secs(60),
            }),
        )
        .unwrap();
        assert_eq!(
            routing
                .lookup("example.com", DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["203.0.113.1".parse::<IpAddr>().unwrap()]
        );
        let after_first = started.load(Ordering::SeqCst);
        assert!(after_first > 0);
        assert_eq!(
            routing
                .lookup("example.com", DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["203.0.113.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(started.load(Ordering::SeqCst), after_first);
    }

    #[tokio::test]
    async fn response_domain_and_ip_items_share_go_or_semantics() {
        for (domain, evaluated_ip, expected_ip) in [
            ("domain-hit.example", "198.51.100.9", "198.51.100.9"),
            ("other.example", "203.0.113.9", "203.0.113.9"),
            ("other.example", "198.51.100.9", "192.0.2.1"),
        ] {
            let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
            let evaluated: Arc<dyn Resolver> = Arc::new(Fixed(evaluated_ip));
            let mut resolvers = HashMap::new();
            resolvers.insert("checked".into(), evaluated);
            let routing = RoutingResolver::compile(
                &[
                    json!({
                        "action":"evaluate",
                        "server":"checked",
                        "tag":"checked"
                    }),
                    json!({
                        "domain_suffix":"domain-hit.example",
                        "match_response":"checked",
                        "ip_cidr":"203.0.113.0/24",
                        "action":"respond"
                    }),
                ],
                resolvers,
                fallback,
            )
            .unwrap();
            assert_eq!(
                routing
                    .lookup(domain, DomainStrategy::Ipv4Only)
                    .await
                    .unwrap(),
                [expected_ip.parse::<IpAddr>().unwrap()]
            );
        }

        let mut resolvers = HashMap::new();
        resolvers.insert(
            "checked".into(),
            Arc::new(Fixed("198.51.100.9")) as Arc<dyn Resolver>,
        );
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "action":"evaluate",
                    "server":"checked",
                    "tag":"checked"
                }),
                json!({
                    "match_response":"checked",
                    "ip_cidr":"203.0.113.0/24",
                    "ip_accept_any":true,
                    "action":"respond"
                }),
            ],
            resolvers,
            Arc::new(Fixed("192.0.2.1")),
        )
        .unwrap();
        assert_eq!(
            routing
                .lookup("any.example", DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["198.51.100.9".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn response_domain_and_rule_set_ip_share_go_address_category() {
        let route_router = Arc::new(
            Router::from_json_with_rule_sets(
                &[],
                "",
                &[json!({
                    "type":"inline",
                    "tag":"response-net",
                    "rules":[{"ip_cidr":"203.0.113.0/24"}]
                })],
                Path::new("."),
            )
            .unwrap(),
        );
        for (domain, evaluated_ip, expected_ip) in [
            ("domain-hit.example", "198.51.100.9", "198.51.100.9"),
            ("other.example", "203.0.113.9", "203.0.113.9"),
            ("other.example", "198.51.100.9", "192.0.2.1"),
        ] {
            let mut route_metadata = Metadata {
                domain: domain.into(),
                ..Metadata::default()
            };
            route_metadata.destination_addresses =
                vec![evaluated_ip.parse().unwrap()];
            assert_eq!(
                route_router.matches_rule_sets_with_destination_outer(
                    &["response-net".into()],
                    &route_metadata,
                    false,
                    true,
                    domain == "domain-hit.example",
                    false,
                ),
                domain == "domain-hit.example"
                    || evaluated_ip.starts_with("203.0.113."),
                "route category mismatch for {domain} / {evaluated_ip}"
            );
            let mut resolvers = HashMap::new();
            resolvers.insert(
                "checked".into(),
                Arc::new(Fixed(evaluated_ip)) as Arc<dyn Resolver>,
            );
            let routing = RoutingResolver::compile(
                &[
                    json!({
                        "action":"evaluate",
                        "server":"checked",
                        "tag":"checked"
                    }),
                    json!({
                        "domain_suffix":"domain-hit.example",
                        "rule_set":"response-net",
                        "match_response":"checked",
                        "action":"respond"
                    }),
                ],
                resolvers,
                Arc::new(Fixed("192.0.2.1")),
            )
            .unwrap();
            routing.configure_rule_set_router(&route_router).unwrap();
            assert!(!routing.legacy_dns_mode);
            assert_eq!(
                routing
                    .lookup(domain, DomainStrategy::Ipv4Only)
                    .await
                    .unwrap(),
                [expected_ip.parse::<IpAddr>().unwrap()]
            );
        }
    }

    #[tokio::test]
    async fn race_respond_uses_the_first_matching_evaluation() {
        let started = Arc::new(AtomicUsize::new(0));
        let slow: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: started.clone(),
            delay: Duration::from_millis(100),
            last_octet: 1,
            response_code: ResponseCode::NoError,
        });
        let fast: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: started.clone(),
            delay: Duration::from_millis(10),
            last_octet: 2,
            response_code: ResponseCode::NoError,
        });
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.9"));
        let mut resolvers = HashMap::new();
        resolvers.insert("slow".into(), slow);
        resolvers.insert("fast".into(), fast);
        let routing = RoutingResolver::compile(
            &[
                json!({"action":"evaluate","server":"slow","tag":"slow"}),
                json!({"action":"evaluate","server":"fast","tag":"fast"}),
                json!({
                    "match_response":"slow",
                    "response_rcode":"NOERROR",
                    "action":"respond",
                    "race":true
                }),
                json!({
                    "match_response":"fast",
                    "response_rcode":"NOERROR",
                    "action":"respond",
                    "race":true
                }),
            ],
            resolvers,
            fallback,
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("race.example.").unwrap(),
            RecordType::A,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.answers[0].data.to_string(), "192.0.2.2");
        assert_eq!(started.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn race_respond_skips_a_fast_response_that_does_not_match() {
        let started = Arc::new(AtomicUsize::new(0));
        let slow: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: started.clone(),
            delay: Duration::from_millis(60),
            last_octet: 1,
            response_code: ResponseCode::NoError,
        });
        let fast_miss: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: started.clone(),
            delay: Duration::from_millis(5),
            last_octet: 2,
            response_code: ResponseCode::NXDomain,
        });
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.9"));
        let mut resolvers = HashMap::new();
        resolvers.insert("slow".into(), slow);
        resolvers.insert("fast-miss".into(), fast_miss);
        let routing = RoutingResolver::compile(
            &[
                json!({"action":"evaluate","server":"slow","tag":"slow"}),
                json!({"action":"evaluate","server":"fast-miss","tag":"fast"}),
                json!({
                    "match_response":"fast",
                    "response_rcode":"NOERROR",
                    "action":"respond",
                    "race":true
                }),
                json!({
                    "match_response":"slow",
                    "response_rcode":"NOERROR",
                    "action":"respond",
                    "race":true
                }),
            ],
            resolvers,
            fallback,
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("race-miss.example.").unwrap(),
            RecordType::A,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.answers[0].data.to_string(), "192.0.2.1");
        assert_eq!(started.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn logical_race_waits_for_all_selectors_and_falls_through_on_miss() {
        for (anonymous_code, expected_octet) in [
            (ResponseCode::NoError, 1_u8),
            (ResponseCode::NXDomain, 3_u8),
        ] {
            let started = Arc::new(AtomicUsize::new(0));
            let anonymous: Arc<dyn Resolver> = Arc::new(DelayedResponse {
                started: started.clone(),
                delay: Duration::from_millis(30),
                last_octet: 1,
                response_code: anonymous_code,
            });
            let tagged: Arc<dyn Resolver> = Arc::new(DelayedResponse {
                started: started.clone(),
                delay: Duration::from_millis(5),
                last_octet: 2,
                response_code: ResponseCode::NoError,
            });
            let fallback_race: Arc<dyn Resolver> = Arc::new(DelayedResponse {
                started: started.clone(),
                delay: Duration::from_millis(60),
                last_octet: 3,
                response_code: ResponseCode::NoError,
            });
            let routing = RoutingResolver::compile(
                &[
                    json!({"action":"evaluate","server":"x"}),
                    json!({"action":"evaluate","server":"y","tag":"y"}),
                    json!({"action":"evaluate","server":"z","tag":"z"}),
                    json!({
                        "type":"logical",
                        "mode":"and",
                        "rules":[
                            {
                                "match_response":true,
                                "response_rcode":"NOERROR"
                            },
                            {
                                "match_response":"y",
                                "response_rcode":"NOERROR"
                            }
                        ],
                        "action":"respond",
                        "race":true
                    }),
                    json!({
                        "match_response":"z",
                        "response_rcode":"NOERROR",
                        "action":"respond",
                        "race":true
                    }),
                ],
                HashMap::from([
                    ("x".into(), anonymous),
                    ("y".into(), tagged),
                    ("z".into(), fallback_race),
                ]),
                Arc::new(Fixed("192.0.2.9")),
            )
            .unwrap();
            let mut request = Message::query();
            request.add_query(Query::query(
                Name::from_ascii("logical-race.example.").unwrap(),
                RecordType::A,
            ));
            let response = routing.exchange(&request).await.unwrap();
            assert_eq!(
                response.answers[0].data.to_string(),
                format!("192.0.2.{expected_octet}")
            );
            assert_eq!(started.load(Ordering::SeqCst), 3);
        }
    }

    #[tokio::test]
    async fn race_route_commits_after_the_response_matches() {
        let started = Arc::new(AtomicUsize::new(0));
        let candidate: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started,
            delay: Duration::from_millis(5),
            last_octet: 1,
            response_code: ResponseCode::NoError,
        });
        let mut resolvers = HashMap::new();
        resolvers.insert("candidate".into(), candidate);
        resolvers.insert(
            "selected".into(),
            Arc::new(Fixed("198.51.100.7")) as Arc<dyn Resolver>,
        );
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "action":"evaluate",
                    "server":"candidate",
                    "tag":"checked"
                }),
                json!({
                    "match_response":"checked",
                    "response_rcode":"NOERROR",
                    "action":"route",
                    "server":"selected",
                    "race":true
                }),
            ],
            resolvers,
            Arc::new(Fixed("192.0.2.9")),
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("race-route.example.").unwrap(),
            RecordType::A,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.answers[0].data.to_string(), "198.51.100.7");
    }

    #[tokio::test]
    async fn race_reject_commits_after_the_response_matches() {
        let candidate: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: Arc::new(AtomicUsize::new(0)),
            delay: Duration::from_millis(5),
            last_octet: 1,
            response_code: ResponseCode::NoError,
        });
        let mut resolvers = HashMap::new();
        resolvers.insert("candidate".into(), candidate);
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "action":"evaluate",
                    "server":"candidate",
                    "tag":"checked"
                }),
                json!({
                    "match_response":"checked",
                    "response_rcode":"NOERROR",
                    "action":"reject",
                    "race":true
                }),
            ],
            resolvers,
            Arc::new(Fixed("192.0.2.9")),
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("race-reject.example.").unwrap(),
            RecordType::A,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    }

    #[tokio::test]
    async fn race_predefined_commits_after_the_response_matches() {
        let candidate: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: Arc::new(AtomicUsize::new(0)),
            delay: Duration::from_millis(5),
            last_octet: 1,
            response_code: ResponseCode::NoError,
        });
        let mut resolvers = HashMap::new();
        resolvers.insert("candidate".into(), candidate);
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "action":"evaluate",
                    "server":"candidate",
                    "tag":"checked"
                }),
                json!({
                    "match_response":"checked",
                    "response_rcode":"NOERROR",
                    "action":"predefined",
                    "answer":"*.example. 60 IN A 203.0.113.8",
                    "race":true
                }),
            ],
            resolvers,
            Arc::new(Fixed("192.0.2.9")),
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("race-predefined.example.").unwrap(),
            RecordType::A,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.answers[0].data.to_string(), "203.0.113.8");

        assert!(
            RoutingResolver::compile(
                &[
                    json!({
                        "action":"evaluate",
                        "server":"candidate",
                        "tag":"checked"
                    }),
                    json!({
                        "match_response":"checked",
                        "action":"route",
                        "server":"candidate",
                        "race":true,
                        "speculative":true
                    }),
                ],
                HashMap::from([(
                    "candidate".into(),
                    Arc::new(Fixed("192.0.2.1")) as Arc<dyn Resolver>,
                )]),
                Arc::new(Fixed("192.0.2.9")),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn speculative_terminal_route_starts_while_race_is_draining() {
        let started = Arc::new(AtomicUsize::new(0));
        let candidate: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: started.clone(),
            delay: Duration::from_millis(30),
            last_octet: 1,
            response_code: ResponseCode::NoError,
        });
        let terminal: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: started.clone(),
            delay: Duration::from_millis(100),
            last_octet: 9,
            response_code: ResponseCode::NoError,
        });
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "action":"evaluate",
                    "server":"candidate",
                    "tag":"checked"
                }),
                json!({
                    "match_response":"checked",
                    "response_rcode":"NOERROR",
                    "action":"respond",
                    "race":true
                }),
                json!({
                    "action":"route",
                    "server":"terminal",
                    "speculative":true
                }),
            ],
            HashMap::from([
                ("candidate".into(), candidate),
                ("terminal".into(), terminal),
            ]),
            Arc::new(Fixed("192.0.2.8")),
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("speculative-route.example.").unwrap(),
            RecordType::A,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.answers[0].data.to_string(), "192.0.2.1");
        assert_eq!(started.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn non_speculative_evaluate_waits_for_armed_race() {
        let race_started = Arc::new(AtomicUsize::new(0));
        let later_started = Arc::new(AtomicUsize::new(0));
        let candidate: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: race_started,
            delay: Duration::from_millis(5),
            last_octet: 1,
            response_code: ResponseCode::NoError,
        });
        let later: Arc<dyn Resolver> = Arc::new(DelayedResponse {
            started: later_started.clone(),
            delay: Duration::from_millis(5),
            last_octet: 2,
            response_code: ResponseCode::NoError,
        });
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "action":"evaluate",
                    "server":"candidate",
                    "tag":"checked"
                }),
                json!({
                    "match_response":"checked",
                    "response_rcode":"NOERROR",
                    "action":"respond",
                    "race":true
                }),
                json!({
                    "action":"evaluate",
                    "server":"later",
                    "tag":"later"
                }),
            ],
            HashMap::from([
                ("candidate".into(), candidate),
                ("later".into(), later),
            ]),
            Arc::new(Fixed("192.0.2.8")),
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("race-barrier.example.").unwrap(),
            RecordType::A,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.answers[0].data.to_string(), "192.0.2.1");
        assert_eq!(later_started.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn race_aborts_slower_evaluation_after_commit() {
        let completed = Arc::new(AtomicUsize::new(0));
        let fast: Arc<dyn Resolver> = Arc::new(TrackedDelayedResponse {
            delay: Duration::from_millis(5),
            last_octet: 1,
            completed: completed.clone(),
        });
        let slow: Arc<dyn Resolver> = Arc::new(TrackedDelayedResponse {
            delay: Duration::from_millis(50),
            last_octet: 2,
            completed: completed.clone(),
        });
        let routing = RoutingResolver::compile(
            &[
                json!({"action":"evaluate","server":"fast","tag":"fast"}),
                json!({"action":"evaluate","server":"slow","tag":"slow"}),
                json!({
                    "match_response":"fast",
                    "response_rcode":"NOERROR",
                    "action":"respond",
                    "race":true
                }),
                json!({
                    "match_response":"slow",
                    "response_rcode":"NOERROR",
                    "action":"respond",
                    "race":true
                }),
            ],
            HashMap::from([("fast".into(), fast), ("slow".into(), slow)]),
            Arc::new(Fixed("192.0.2.8")),
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("race-cancel.example.").unwrap(),
            RecordType::A,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.answers[0].data.to_string(), "192.0.2.1");
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn predefined_action_builds_response_and_rewrites_wildcard_owner() {
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
        let routing = RoutingResolver::compile(
            &[json!({
                "domain_suffix":"example.com",
                "action":"predefined",
                "answer":[
                    "*.example.com. 60 IN A 192.0.2.44",
                    "*.example.com. 120 IN TXT \"native-rust\""
                ],
                "ns":"example.com. 300 IN NS ns.example.com.",
                "extra":"ns.example.com. 300 IN A 192.0.2.53"
            })],
            HashMap::new(),
            fallback,
        )
        .unwrap();
        assert_eq!(
            routing
                .lookup("www.example.com", DomainStrategy::AsIs)
                .await
                .unwrap(),
            ["192.0.2.44".parse::<IpAddr>().unwrap()]
        );

        let mut request =
            Message::new(0x1234, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("www.example.com.").unwrap(),
            RecordType::TXT,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.metadata.id, 0x1234);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.metadata.authoritative);
        assert!(response.metadata.recursion_available);
        assert_eq!(response.answers.len(), 2);
        assert!(
            response
                .answers
                .iter()
                .all(|record| record.name == request.queries[0].name)
        );
        assert_eq!(response.authorities.len(), 1);
        assert_eq!(response.additionals.len(), 1);
    }

    #[tokio::test]
    async fn predefined_action_accepts_rcode_name_and_binary_record() {
        let record = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            42,
            RData::A(A::new(198, 51, 100, 7)),
        );
        let mut wire = Vec::new();
        record.emit(&mut BinEncoder::new(&mut wire)).unwrap();
        let encoded = STANDARD.encode(wire);
        assert_eq!(parse_record(&encoded).unwrap(), record);

        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
        let routing = RoutingResolver::compile(
            &[json!({
                "domain":"missing.example",
                "action":"predefined",
                "rcode":"NXDOMAIN"
            })],
            HashMap::new(),
            fallback,
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("missing.example.").unwrap(),
            RecordType::A,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(
            routing
                .lookup("missing.example", DomainStrategy::AsIs)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn route_options_accumulate_for_lookup_and_raw_exchange() {
        let selected = Arc::new(Recording {
            options: Mutex::new(Vec::new()),
        });
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
        let mut resolvers = HashMap::new();
        resolvers
            .insert("selected".into(), selected.clone() as Arc<dyn Resolver>);
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "domain_suffix":"example.com",
                    "action":"route-options",
                    "timeout":"2s",
                    "disable_cache":true,
                    "rewrite_ttl":90,
                    "client_subnet":"2001:db8::1234/48"
                }),
                json!({
                    "domain":"api.example.com",
                    "action":"route-options",
                    "remove_client_subnet":true
                }),
                json!({
                    "domain":"api.example.com",
                    "server":"selected",
                    "disable_optimistic_cache":true
                }),
            ],
            resolvers,
            fallback,
        )
        .unwrap();

        assert_eq!(
            routing
                .lookup("api.example.com", DomainStrategy::AsIs)
                .await
                .unwrap(),
            ["2001:db8::1".parse::<IpAddr>().unwrap()]
        );
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("api.example.com.").unwrap(),
            RecordType::TXT,
        ));
        routing.exchange(&request).await.unwrap();

        let captured = selected.options.lock().unwrap();
        assert_eq!(captured.len(), 2);
        for options in captured.iter() {
            assert_eq!(options.timeout, Some(Duration::from_secs(2)));
            assert_eq!(options.strategy, DomainStrategy::AsIs);
            assert!(options.disable_cache);
            assert!(options.disable_optimistic_cache);
            assert_eq!(options.rewrite_ttl, Some(90));
            assert_eq!(options.client_subnet, None);
            assert!(options.remove_client_subnet);
        }

        assert!(
            RoutingResolver::compile(
                &[json!({"action":"route-options"})],
                HashMap::new(),
                Arc::new(Fixed("192.0.2.1")),
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_dns_strategy_conflict_reports_go_migration_error() {
        let result = RoutingResolver::compile(
            &[
                json!({
                    "action":"route-options",
                    "strategy":"ipv6_only"
                }),
                json!({
                    "server":"selected",
                    "disable_optimistic_cache":true
                }),
            ],
            HashMap::from([(
                "selected".into(),
                Arc::new(Fixed("192.0.2.1")) as Arc<dyn Resolver>,
            )]),
            Arc::new(Fixed("192.0.2.254")),
        );
        let error = match result {
            Ok(_) => panic!("legacy strategy conflict unexpectedly compiled"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(
            "Legacy `strategy` DNS rule action option is deprecated in sing-box 1.14.0"
        ));
    }

    #[tokio::test]
    async fn legacy_dns_strategy_selects_mode_and_applies_to_transport() {
        let selected = Arc::new(Recording {
            options: Mutex::new(Vec::new()),
        });
        let routing = RoutingResolver::compile(
            &[json!({
                "server":"selected",
                "strategy":"ipv6_only"
            })],
            HashMap::from([(
                "selected".into(),
                selected.clone() as Arc<dyn Resolver>,
            )]),
            Arc::new(Fixed("192.0.2.254")),
        )
        .unwrap();
        assert!(routing.legacy_dns_mode);
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("lookup.example.").unwrap(),
            RecordType::A,
        ));
        routing.exchange(&request).await.unwrap();
        let options = selected.options.lock().unwrap();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].strategy, DomainStrategy::Ipv6Only);
    }

    #[tokio::test]
    async fn evaluate_then_respond_reuses_the_nonterminal_result() {
        let selected = Arc::new(Recording {
            options: Mutex::new(Vec::new()),
        });
        let fallback: Arc<dyn Resolver> = Arc::new(Fixed("192.0.2.1"));
        let mut resolvers = HashMap::new();
        resolvers
            .insert("selected".into(), selected.clone() as Arc<dyn Resolver>);
        let routing = RoutingResolver::compile(
            &[
                json!({
                    "domain":"evaluated.example",
                    "action":"evaluate",
                    "server":"selected",
                    "rewrite_ttl":30
                }),
                json!({
                    "domain":"evaluated.example",
                    "action":"respond"
                }),
            ],
            resolvers,
            fallback,
        )
        .unwrap();
        assert_eq!(
            routing
                .lookup("evaluated.example", DomainStrategy::AsIs)
                .await
                .unwrap(),
            ["2001:db8::1".parse::<IpAddr>().unwrap()]
        );

        let mut request = Message::new(91, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("evaluated.example.").unwrap(),
            RecordType::TXT,
        ));
        let response = routing.exchange(&request).await.unwrap();
        assert_eq!(response.metadata.id, 91);
        {
            let captured = selected.options.lock().unwrap();
            assert_eq!(captured.len(), 2);
            assert!(
                captured
                    .iter()
                    .all(|options| options.rewrite_ttl == Some(30))
            );
        }

        for invalid in [
            json!({"action":"respond"}),
            json!({"action":"evaluate","server":"missing","tag":"x"}),
            json!({"server":"missing","race":true}),
            json!({"server":"missing","speculative":true}),
            json!({
                "server":"missing",
                "client_subnet":"192.0.2.1/24",
                "remove_client_subnet":true
            }),
        ] {
            let result = RoutingResolver::compile(
                &[invalid],
                HashMap::new(),
                Arc::new(Fixed("192.0.2.1")),
            );
            if let Ok(resolver) = result {
                assert!(
                    resolver.lookup("x", DomainStrategy::AsIs).await.is_err()
                );
            }
        }
    }
}
