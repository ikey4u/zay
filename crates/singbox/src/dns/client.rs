//! DNS exchange client with sing-box-compatible TTL calculation, bounded LRU
//! caching, optimistic stale reads and duplicate-query coalescing.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use hickory_proto::{
    op::Message,
    rr::{
        Name, RData, RecordType,
        rdata::opt::{ClientSubnet, EdnsCode, EdnsOption},
    },
};
use tokio::{sync::oneshot, time::timeout};

use crate::{
    constant,
    dns::persistent::{PersistentDnsCache, PersistentEntry},
};

pub type ExchangeFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Message>> + Send + 'a>>;

pub trait Transport: Send + Sync {
    fn tag(&self) -> &str;
    fn exchange<'a>(&'a self, message: &'a Message) -> ExchangeFuture<'a>;

    fn preferred_domain(&self, _domain: &str) -> Option<bool> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub timeout: Duration,
    pub disable_cache: bool,
    pub disable_expire: bool,
    pub optimistic_timeout: Duration,
    pub cache_capacity: usize,
    pub persistent_cache: Option<Arc<PersistentDnsCache>>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ExchangeOptions {
    pub timeout: Option<Duration>,
    pub disable_cache: bool,
    pub disable_optimistic_cache: bool,
    pub rewrite_ttl: Option<u32>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            timeout: constant::DNS_TIMEOUT,
            disable_cache: false,
            disable_expire: false,
            optimistic_timeout: Duration::ZERO,
            cache_capacity: 1024,
            persistent_cache: None,
        }
    }
}

pub struct Client {
    options: ClientOptions,
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    cache: HashMap<CacheKey, CacheEntry>,
    order: VecDeque<(CacheKey, u64)>,
    generation: u64,
    flights: HashMap<CacheKey, Vec<oneshot::Sender<Result<Message, String>>>>,
    background_refresh: HashSet<CacheKey>,
    cache_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    transport: String,
    name: Name,
    record_type: RecordType,
    client_subnet: Option<ClientSubnet>,
    rewrite_ttl: Option<u32>,
}

struct CacheEntry {
    message: Message,
    expires_at: Instant,
    generation: u64,
}

enum CacheLookup {
    Fresh(Message),
    Stale(Message),
    Miss,
}

struct FlightGuard<'a> {
    client: &'a Client,
    key: CacheKey,
    active: bool,
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state =
            self.client.state.lock().expect("DNS cache mutex poisoned");
        let waiters = state.flights.remove(&self.key).unwrap_or_default();
        for waiter in waiters {
            let _ = waiter.send(Err("DNS exchange owner was cancelled".into()));
        }
    }
}

impl Client {
    pub fn new(mut options: ClientOptions) -> Self {
        if options.timeout.is_zero() {
            options.timeout = constant::DNS_TIMEOUT;
        }
        options.cache_capacity = options.cache_capacity.max(1024);
        Self {
            options,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    pub fn clear_cache(&self) {
        let mut state = self.state.lock().expect("DNS cache mutex poisoned");
        state.cache.clear();
        state.order.clear();
        state.background_refresh.clear();
        state.cache_epoch = state.cache_epoch.wrapping_add(1);
        if let Some(cache) = &self.options.persistent_cache {
            let _ = cache.clear();
        }
    }

    pub async fn exchange(
        &self,
        transport: &dyn Transport,
        request: &Message,
    ) -> io::Result<Message> {
        self.exchange_inner(
            transport,
            None,
            request,
            ExchangeOptions::default(),
        )
        .await
    }

    pub async fn exchange_owned(
        self: &Arc<Self>,
        transport: Arc<dyn Transport>,
        request: &Message,
    ) -> io::Result<Message> {
        self.exchange_owned_with_options(
            transport,
            request,
            ExchangeOptions::default(),
        )
        .await
    }

    pub async fn exchange_owned_with_options(
        self: &Arc<Self>,
        transport: Arc<dyn Transport>,
        request: &Message,
        options: ExchangeOptions,
    ) -> io::Result<Message> {
        self.exchange_inner(
            &*transport,
            Some(transport.clone()),
            request,
            options,
        )
        .await
    }

    async fn exchange_inner(
        &self,
        transport: &dyn Transport,
        owned_transport: Option<Arc<dyn Transport>>,
        request: &Message,
        overrides: ExchangeOptions,
    ) -> io::Result<Message> {
        let key = cache_key(transport.tag(), request, overrides.rewrite_ttl);
        if self.options.disable_cache
            || overrides.disable_cache
            || key.is_none()
        {
            return self
                .exchange_uncached_with_options(transport, request, overrides)
                .await;
        }
        let key = key.expect("checked above");
        let persistent_entry = self
            .options
            .persistent_cache
            .as_ref()
            .and_then(|cache| load_persistent(cache, &key).ok().flatten());
        let request_id = request.metadata.id;
        let mut receiver = None;
        let mut owns_flight = false;
        {
            let mut state =
                self.state.lock().expect("DNS cache mutex poisoned");
            if !state.cache.contains_key(&key)
                && let Some(entry) = persistent_entry
            {
                insert_persistent_entry(&mut state, key.clone(), entry);
            }
            match load_cache(
                &mut state,
                &key,
                &self.options,
                !overrides.disable_optimistic_cache,
            ) {
                CacheLookup::Fresh(mut response) => {
                    response.metadata.id = request_id;
                    return Ok(response);
                }
                CacheLookup::Stale(mut response) => {
                    response.metadata.id = request_id;
                    if let Some(transport) = owned_transport
                        && state.background_refresh.insert(key.clone())
                    {
                        let epoch = state.cache_epoch;
                        self.spawn_refresh(
                            transport,
                            request.clone(),
                            key.clone(),
                            epoch,
                            overrides,
                        );
                    }
                    return Ok(response);
                }
                CacheLookup::Miss => {}
            }
            if let Some(waiters) = state.flights.get_mut(&key) {
                let (sender, waiting) = oneshot::channel();
                waiters.push(sender);
                receiver = Some(waiting);
            } else {
                state.flights.insert(key.clone(), Vec::new());
                owns_flight = true;
            }
        }
        if let Some(waiting) = receiver {
            let mut response = waiting
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::Interrupted,
                        "DNS exchange owner dropped",
                    )
                })?
                .map_err(io::Error::other)?;
            response.metadata.id = request_id;
            return Ok(response);
        }

        debug_assert!(owns_flight);
        let mut flight_guard = FlightGuard {
            client: self,
            key: key.clone(),
            active: true,
        };

        let result = self
            .exchange_uncached_with_options(transport, request, overrides)
            .await;
        let mut state = self.state.lock().expect("DNS cache mutex poisoned");
        if let Ok(response) = &result {
            let ttl = compute_time_to_live(response);
            if ttl > 0 {
                insert_cache(
                    &mut state,
                    key.clone(),
                    response.clone(),
                    ttl,
                    self.options.cache_capacity,
                );
                if let Some(cache) = &self.options.persistent_cache {
                    let _ = save_persistent(cache, &key, response, ttl);
                }
            }
        }
        let waiters = state.flights.remove(&key).unwrap_or_default();
        flight_guard.active = false;
        let shared = result
            .as_ref()
            .map(Clone::clone)
            .map_err(ToString::to_string);
        for waiter in waiters {
            let _ = waiter.send(shared.clone());
        }
        result
    }

    fn spawn_refresh(
        &self,
        transport: Arc<dyn Transport>,
        request: Message,
        key: CacheKey,
        cache_epoch: u64,
        overrides: ExchangeOptions,
    ) {
        let client = Self {
            options: self.options.clone(),
            state: self.state.clone(),
        };
        tokio::spawn(async move {
            let result = client
                .exchange_uncached_with_options(
                    &*transport,
                    &request,
                    overrides,
                )
                .await;
            let mut state =
                client.state.lock().expect("DNS cache mutex poisoned");
            state.background_refresh.remove(&key);
            if state.cache_epoch != cache_epoch {
                return;
            }
            if let Ok(response) = result {
                let ttl = compute_time_to_live(&response);
                if ttl > 0 {
                    if let Some(cache) = &client.options.persistent_cache {
                        let _ = save_persistent(cache, &key, &response, ttl);
                    }
                    insert_cache(
                        &mut state,
                        key,
                        response,
                        ttl,
                        client.options.cache_capacity,
                    );
                }
            }
        });
    }

    async fn exchange_uncached_with_options(
        &self,
        transport: &dyn Transport,
        request: &Message,
        overrides: ExchangeOptions,
    ) -> io::Result<Message> {
        let mut response = timeout(
            overrides.timeout.unwrap_or(self.options.timeout),
            transport.exchange(request),
        )
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "DNS exchange timed out")
        })??;
        if let Some(ttl) = overrides.rewrite_ttl {
            normalize_ttl(&mut response, ttl);
        }
        Ok(response)
    }
}

fn cache_key(
    transport: &str,
    request: &Message,
    rewrite_ttl: Option<u32>,
) -> Option<CacheKey> {
    if request.queries.len() != 1
        || !request.authorities.is_empty()
        || !request.additionals.is_empty()
    {
        return None;
    }
    let query = &request.queries[0];
    Some(CacheKey {
        transport: transport.to_owned(),
        name: query.name().clone(),
        record_type: query.query_type(),
        client_subnet: request
            .edns
            .as_ref()
            .and_then(|edns| edns.option(EdnsCode::Subnet))
            .and_then(|option| match option {
                EdnsOption::Subnet(subnet) => Some(*subnet),
                _ => None,
            }),
        rewrite_ttl,
    })
}

fn load_persistent(
    cache: &PersistentDnsCache,
    key: &CacheKey,
) -> io::Result<Option<PersistentEntry>> {
    let subnet = key
        .client_subnet
        .map(|subnet| format!("{}/{}", subnet.addr(), subnet.source_prefix()));
    cache.load(
        &key.transport,
        &key.name.to_utf8(),
        u16::from(key.record_type),
        subnet.as_deref(),
        key.rewrite_ttl,
    )
}

fn save_persistent(
    cache: &PersistentDnsCache,
    key: &CacheKey,
    message: &Message,
    ttl: u32,
) -> io::Result<()> {
    let subnet = key
        .client_subnet
        .map(|subnet| format!("{}/{}", subnet.addr(), subnet.source_prefix()));
    cache.save(
        &key.transport,
        &key.name.to_utf8(),
        u16::from(key.record_type),
        subnet.as_deref(),
        key.rewrite_ttl,
        message,
        SystemTime::now() + Duration::from_secs(u64::from(ttl)),
    )
}

fn insert_persistent_entry(
    state: &mut State,
    key: CacheKey,
    entry: PersistentEntry,
) {
    let now_system = SystemTime::now();
    let now_instant = Instant::now();
    let expires_at = match entry.expires_at.duration_since(now_system) {
        Ok(remaining) => now_instant + remaining,
        Err(elapsed) => now_instant
            .checked_sub(elapsed.duration())
            .unwrap_or(now_instant),
    };
    state.generation = state.generation.wrapping_add(1);
    let generation = state.generation;
    state.cache.insert(
        key.clone(),
        CacheEntry {
            message: entry.message,
            expires_at,
            generation,
        },
    );
    state.order.push_back((key, generation));
}

fn load_cache(
    state: &mut State,
    key: &CacheKey,
    options: &ClientOptions,
    allow_optimistic: bool,
) -> CacheLookup {
    let now = Instant::now();
    let Some(entry) = state.cache.get_mut(key) else {
        return CacheLookup::Miss;
    };
    let mut response = entry.message.clone();
    if options.disable_expire {
        touch(state, key);
        return CacheLookup::Fresh(response);
    }
    if now < entry.expires_at {
        let remaining =
            entry.expires_at.saturating_duration_since(now).as_secs();
        normalize_ttl(
            &mut response,
            u32::try_from(remaining).unwrap_or(u32::MAX),
        );
        touch(state, key);
        return CacheLookup::Fresh(response);
    }
    if allow_optimistic
        && !options.optimistic_timeout.is_zero()
        && now < entry.expires_at + options.optimistic_timeout
    {
        normalize_ttl(&mut response, 1);
        touch(state, key);
        return CacheLookup::Stale(response);
    }
    state.cache.remove(key);
    CacheLookup::Miss
}

fn touch(state: &mut State, key: &CacheKey) {
    state.generation = state.generation.wrapping_add(1);
    let generation = state.generation;
    if let Some(entry) = state.cache.get_mut(key) {
        entry.generation = generation;
        state.order.push_back((key.clone(), generation));
    }
}

fn insert_cache(
    state: &mut State,
    key: CacheKey,
    message: Message,
    ttl: u32,
    capacity: usize,
) {
    state.generation = state.generation.wrapping_add(1);
    let generation = state.generation;
    state.cache.insert(
        key.clone(),
        CacheEntry {
            message,
            expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
            generation,
        },
    );
    state.order.push_back((key, generation));
    while state.cache.len() > capacity {
        let Some((candidate, candidate_generation)) = state.order.pop_front()
        else {
            break;
        };
        if state
            .cache
            .get(&candidate)
            .is_some_and(|entry| entry.generation == candidate_generation)
        {
            state.cache.remove(&candidate);
        }
    }
}

pub fn compute_time_to_live(response: &Message) -> u32 {
    if response.answers.is_empty() {
        for record in &response.authorities {
            if let RData::SOA(soa) = &record.data {
                return record.ttl.min(soa.minimum);
            }
        }
    }
    response
        .answers
        .iter()
        .chain(&response.authorities)
        .chain(&response.additionals)
        .filter(|record| record.record_type() != RecordType::OPT)
        .map(|record| record.ttl)
        .filter(|ttl| *ttl > 0)
        .min()
        .unwrap_or(0)
}

pub fn normalize_ttl(response: &mut Message, ttl: u32) {
    for record in response
        .answers
        .iter_mut()
        .chain(&mut response.authorities)
        .chain(&mut response.additionals)
    {
        if record.record_type() != RecordType::OPT {
            record.ttl = ttl;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, Record, RecordType, rdata::A},
    };

    use super::{
        Client, ClientOptions, ExchangeFuture, ExchangeOptions, Transport,
        compute_time_to_live,
    };
    use crate::dns::persistent::PersistentDnsCache;

    struct FakeTransport {
        calls: AtomicUsize,
        delay: Duration,
        ttl: u32,
    }

    impl Transport for FakeTransport {
        fn tag(&self) -> &str {
            "fake"
        }

        fn exchange<'a>(&'a self, request: &'a Message) -> ExchangeFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(self.delay).await;
                Ok(answer(request, self.ttl))
            })
        }
    }

    fn query(id: u16) -> Message {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        message
    }

    fn answer(request: &Message, ttl: u32) -> Message {
        let mut response = Message::new(
            request.metadata.id,
            MessageType::Response,
            OpCode::Query,
        );
        response.queries = request.queries.clone();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            ttl,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        response
    }

    #[tokio::test]
    async fn persistent_cache_survives_a_new_client_instance() {
        let directory = tempfile::tempdir().unwrap();
        let persistent = Arc::new(
            PersistentDnsCache::open(directory.path().join("cache.db"), "test")
                .unwrap(),
        );
        let transport = Arc::new(FakeTransport {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            ttl: 60,
        });
        let options = ClientOptions {
            persistent_cache: Some(persistent),
            ..Default::default()
        };
        Arc::new(Client::new(options.clone()))
            .exchange_owned(transport.clone(), &query(1))
            .await
            .unwrap();
        let response = Arc::new(Client::new(options))
            .exchange_owned(transport.clone(), &query(2))
            .await
            .unwrap();
        assert_eq!(response.metadata.id, 2);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn computes_minimum_positive_ttl() {
        let mut response = answer(&query(1), 120);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            30,
            RData::A(A::new(192, 0, 2, 2)),
        ));
        assert_eq!(compute_time_to_live(&response), 30);
    }

    #[tokio::test]
    async fn cache_restores_request_id_and_avoids_second_exchange() {
        let client = Client::new(ClientOptions::default());
        let transport = FakeTransport {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            ttl: 60,
        };
        assert_eq!(
            client.exchange(&transport, &query(10)).await.unwrap().id,
            10
        );
        assert_eq!(
            client.exchange(&transport, &query(20)).await.unwrap().id,
            20
        );
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_identical_queries_are_coalesced() -> io::Result<()> {
        let client = Arc::new(Client::new(ClientOptions::default()));
        let transport = Arc::new(FakeTransport {
            calls: AtomicUsize::new(0),
            delay: Duration::from_millis(20),
            ttl: 60,
        });
        let first = {
            let client = client.clone();
            let transport = transport.clone();
            tokio::spawn(async move {
                client.exchange(&*transport, &query(1)).await
            })
        };
        let second = {
            let client = client.clone();
            let transport = transport.clone();
            tokio::spawn(async move {
                client.exchange(&*transport, &query(2)).await
            })
        };
        assert_eq!(first.await.unwrap()?.id, 1);
        assert_eq!(second.await.unwrap()?.id, 2);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn zero_ttl_is_not_cached() {
        let client = Client::new(ClientOptions::default());
        let transport = FakeTransport {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            ttl: 0,
        };
        client.exchange(&transport, &query(1)).await.unwrap();
        client.exchange(&transport, &query(2)).await.unwrap();
        assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cancelling_exchange_owner_releases_waiters() {
        let client = Arc::new(Client::new(ClientOptions::default()));
        let transport = Arc::new(FakeTransport {
            calls: AtomicUsize::new(0),
            delay: Duration::from_secs(60),
            ttl: 60,
        });
        let owner = {
            let client = client.clone();
            let transport = transport.clone();
            tokio::spawn(async move {
                client.exchange(&*transport, &query(1)).await
            })
        };
        while transport.calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let waiter = {
            let client = client.clone();
            let transport = transport.clone();
            tokio::spawn(async move {
                client.exchange(&*transport, &query(2)).await
            })
        };
        loop {
            let registered = client
                .state
                .lock()
                .unwrap()
                .flights
                .values()
                .any(|waiters| !waiters.is_empty());
            if registered {
                break;
            }
            tokio::task::yield_now().await;
        }
        owner.abort();
        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter remained stuck")
            .unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn optimistic_hit_starts_one_background_refresh() {
        let client = Arc::new(Client::new(ClientOptions {
            optimistic_timeout: Duration::from_secs(60),
            ..Default::default()
        }));
        let transport = Arc::new(FakeTransport {
            calls: AtomicUsize::new(0),
            delay: Duration::from_millis(20),
            ttl: 60,
        });
        client
            .exchange_owned(transport.clone(), &query(1))
            .await
            .unwrap();
        {
            let mut state = client.state.lock().unwrap();
            let entry = state.cache.values_mut().next().unwrap();
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
        let mut tasks = Vec::new();
        for id in 2..10 {
            let client = client.clone();
            let transport = transport.clone();
            tasks.push(tokio::spawn(async move {
                client.exchange_owned(transport, &query(id)).await.unwrap()
            }));
        }
        for task in tasks {
            let response = task.await.unwrap();
            assert_eq!(response.answers[0].ttl, 1);
        }
        while !client.state.lock().unwrap().background_refresh.is_empty() {
            tokio::task::yield_now().await;
        }
        assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
        client
            .exchange_owned(transport.clone(), &query(20))
            .await
            .unwrap();
        assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn per_lookup_options_control_cache_timeout_and_ttl() {
        let client = Arc::new(Client::new(ClientOptions {
            optimistic_timeout: Duration::from_secs(60),
            ..Default::default()
        }));
        let transport = Arc::new(FakeTransport {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            ttl: 60,
        });
        for id in 1..=2 {
            client
                .exchange_owned_with_options(
                    transport.clone(),
                    &query(id),
                    ExchangeOptions {
                        disable_cache: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        }
        assert_eq!(transport.calls.load(Ordering::SeqCst), 2);

        let rewritten = client
            .exchange_owned_with_options(
                transport.clone(),
                &query(3),
                ExchangeOptions {
                    rewrite_ttl: Some(7),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(rewritten.answers[0].ttl, 7);
        {
            let mut state = client.state.lock().unwrap();
            let entry = state
                .cache
                .iter_mut()
                .find(|(key, _)| key.rewrite_ttl == Some(7))
                .unwrap()
                .1;
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
        client
            .exchange_owned_with_options(
                transport.clone(),
                &query(4),
                ExchangeOptions {
                    rewrite_ttl: Some(7),
                    disable_optimistic_cache: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(transport.calls.load(Ordering::SeqCst), 4);

        let slow = Arc::new(FakeTransport {
            calls: AtomicUsize::new(0),
            delay: Duration::from_secs(1),
            ttl: 60,
        });
        let error = client
            .exchange_owned_with_options(
                slow,
                &query(5),
                ExchangeOptions {
                    timeout: Some(Duration::from_millis(1)),
                    disable_cache: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
