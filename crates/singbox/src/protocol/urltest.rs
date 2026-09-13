//! Latency-tested outbound group compatible with sing-box URLTest selection.

use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{
        Arc, Mutex, OnceLock, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use futures_util::future::join_all;
use n0_watcher::Watcher as _;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex as AsyncMutex, broadcast},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    adapter::{
        DialFuture, Dialer, IcmpResponse, InterruptGenerations, IpPacketPort,
        NetworkDialOptions, PacketFuture, PacketStream, Stream,
    },
    common::{
        certificate_store::CertificateStore, network::SocksAddr, ntp::NtpClock,
        tls::build_client_config_with_clock,
    },
    option::{OutboundTlsOptions, UrlTestOutboundOptions},
    protocol::selector::SelectorOutbound,
};

const DEFAULT_URL: &str = "https://www.gstatic.com/generate_204";
const DEFAULT_INTERVAL: Duration = Duration::from_secs(3 * 60);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

pub(crate) struct GroupRegistry {
    selectors: RwLock<HashMap<String, Weak<SelectorOutbound>>>,
    urltests: RwLock<HashMap<String, Weak<UrlTestOutbound>>>,
    updates: broadcast::Sender<()>,
}

impl Default for GroupRegistry {
    fn default() -> Self {
        let (updates, _) = broadcast::channel(32);
        Self {
            selectors: RwLock::default(),
            urltests: RwLock::default(),
            updates,
        }
    }
}

impl GroupRegistry {
    pub(crate) fn subscribe_updates(&self) -> broadcast::Receiver<()> {
        self.updates.subscribe()
    }

    pub(crate) fn notify_updated(&self) {
        let _ = self.updates.send(());
    }

    pub(crate) fn register_selector(
        &self,
        tag: String,
        group: &Arc<SelectorOutbound>,
    ) {
        self.selectors
            .write()
            .expect("group registry lock poisoned")
            .insert(tag, Arc::downgrade(group));
    }

    pub(crate) fn register_urltest(
        &self,
        tag: String,
        group: &Arc<UrlTestOutbound>,
    ) {
        self.urltests
            .write()
            .expect("group registry lock poisoned")
            .insert(tag, Arc::downgrade(group));
    }

    fn selector(&self, tag: &str) -> Option<Arc<SelectorOutbound>> {
        self.selectors
            .read()
            .expect("group registry lock poisoned")
            .get(tag)
            .and_then(Weak::upgrade)
    }

    fn urltest(&self, tag: &str) -> Option<Arc<UrlTestOutbound>> {
        self.urltests
            .read()
            .expect("group registry lock poisoned")
            .get(tag)
            .and_then(Weak::upgrade)
    }

    pub(crate) fn real_tag(&self, tag: &str) -> String {
        let mut current = tag.to_owned();
        let mut visited = HashSet::new();
        while visited.insert(current.clone()) {
            if let Some(selector) = self.selector(&current) {
                current = selector.selected();
            } else if let Some(urltest) = self.urltest(&current) {
                current = urltest.selected_or_first();
            } else {
                break;
            }
        }
        current
    }

    fn collect_work(
        &self,
        tag: &str,
        dialer: Arc<dyn Dialer>,
        visited: &mut HashSet<String>,
        targets: &mut Vec<(String, Arc<dyn Dialer>)>,
        nested_urltests: &mut Vec<Arc<UrlTestOutbound>>,
        aliases: &mut Vec<String>,
    ) {
        if !visited.insert(tag.to_owned()) {
            return;
        }
        if let Some(selector) = self.selector(tag) {
            aliases.push(tag.to_owned());
            for child in selector.choices() {
                if let Some(dialer) = selector.choice(child) {
                    self.collect_work(
                        child,
                        dialer,
                        visited,
                        targets,
                        nested_urltests,
                        aliases,
                    );
                }
            }
        } else if let Some(urltest) = self.urltest(tag) {
            aliases.push(tag.to_owned());
            nested_urltests.push(urltest);
        } else {
            targets.push((tag.to_owned(), dialer));
        }
    }
}

pub struct UrlTestOutbound {
    order: Vec<String>,
    choices: HashMap<String, Arc<dyn Dialer>>,
    groups: Arc<GroupRegistry>,
    url: Url,
    interval: Duration,
    tolerance: u16,
    idle_timeout: Duration,
    interrupt_exist_connections: bool,
    state: Mutex<State>,
    check: AsyncMutex<()>,
    self_weak: OnceLock<Weak<Self>>,
    background_started: AtomicBool,
    network_monitor_started: AtomicBool,
    cancellation: CancellationToken,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
}

#[derive(Default)]
struct State {
    selected: Option<String>,
    history: HashMap<String, (Instant, u16)>,
    last_checked: Option<Instant>,
    last_active: Option<Instant>,
    generations: InterruptGenerations,
}

impl UrlTestOutbound {
    pub fn new(
        options: UrlTestOutboundOptions,
        choices: HashMap<String, Arc<dyn Dialer>>,
    ) -> io::Result<Self> {
        Self::new_with_registry(options, choices, Arc::default())
    }

    pub(crate) fn new_with_registry(
        options: UrlTestOutboundOptions,
        choices: HashMap<String, Arc<dyn Dialer>>,
        groups: Arc<GroupRegistry>,
    ) -> io::Result<Self> {
        Self::new_with_registry_and_context(
            options, choices, groups, None, None,
        )
    }

    pub(crate) fn new_with_registry_and_context(
        options: UrlTestOutboundOptions,
        choices: HashMap<String, Arc<dyn Dialer>>,
        groups: Arc<GroupRegistry>,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<CertificateStore>,
    ) -> io::Result<Self> {
        if options.outbounds.is_empty() {
            return Err(invalid_input("urltest outbound list is empty"));
        }
        if !options
            .outbounds
            .iter()
            .all(|tag| choices.contains_key(tag))
        {
            return Err(invalid_input(
                "urltest is missing a constructed outbound",
            ));
        }
        let url = Url::parse(if options.url.is_empty() {
            DEFAULT_URL
        } else {
            &options.url
        })
        .map_err(|error| {
            invalid_input(format!("invalid urltest URL: {error}"))
        })?;
        let interval = options
            .interval
            .as_std()
            .filter(|value| !value.is_zero())
            .unwrap_or(DEFAULT_INTERVAL);
        let idle_timeout = options
            .idle_timeout
            .as_std()
            .filter(|value| !value.is_zero())
            .unwrap_or(DEFAULT_IDLE_TIMEOUT);
        if interval > idle_timeout {
            return Err(invalid_input(
                "urltest interval must be less or equal than idle_timeout",
            ));
        }
        Ok(Self {
            order: options.outbounds,
            choices,
            groups,
            url,
            interval,
            tolerance: if options.tolerance == 0 {
                50
            } else {
                options.tolerance
            },
            idle_timeout,
            interrupt_exist_connections: options.interrupt_exist_connections,
            state: Mutex::new(State::default()),
            check: AsyncMutex::new(()),
            self_weak: OnceLock::new(),
            background_started: AtomicBool::new(false),
            network_monitor_started: AtomicBool::new(false),
            cancellation: CancellationToken::new(),
            ntp_clock,
            certificate_store,
        })
    }

    /// Attach the group to its owning `Arc` and start the upstream-style
    /// periodic checker when a Tokio runtime is available.
    pub(crate) fn attach(self: &Arc<Self>) {
        let _ = self.self_weak.set(Arc::downgrade(self));
        self.touch();
        self.ensure_background();
        self.ensure_network_monitor();
    }

    fn touch(&self) {
        self.state
            .lock()
            .expect("urltest lock poisoned")
            .last_active = Some(Instant::now());
        self.ensure_background();
    }

    fn ensure_background(&self) {
        if self.background_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(group) = self.self_weak.get().cloned() else {
            self.background_started.store(false, Ordering::Release);
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.background_started.store(false, Ordering::Release);
            return;
        };
        let interval = self.interval;
        let cancellation = self.cancellation.clone();
        runtime.spawn(async move {
            if let Some(group) = group.upgrade() {
                group.refresh(false).await;
            } else {
                return;
            }
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    _ = ticker.tick() => {}
                }
                let Some(group) = group.upgrade() else {
                    break;
                };
                let active = group
                    .state
                    .lock()
                    .expect("urltest lock poisoned")
                    .last_active
                    .is_some_and(|active| {
                        active.elapsed() <= group.idle_timeout
                    });
                if active {
                    group.refresh(false).await;
                }
            }
        });
    }

    fn ensure_network_monitor(&self) {
        if self.network_monitor_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(group) = self.self_weak.get().cloned() else {
            self.network_monitor_started.store(false, Ordering::Release);
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.network_monitor_started.store(false, Ordering::Release);
            return;
        };
        let cancellation = self.cancellation.clone();
        runtime.spawn(async move {
            let Ok(monitor) =
                crate::common::network_monitor::NetworkMonitor::new().await
            else {
                if let Some(group) = group.upgrade() {
                    group
                        .network_monitor_started
                        .store(false, Ordering::Release);
                }
                return;
            };
            let mut watcher = monitor.interface_state();
            let mut previous = watcher.get();
            loop {
                let current = tokio::select! {
                    _ = cancellation.cancelled() => return,
                    current = watcher.updated() => match current {
                        Ok(current) => current,
                        Err(_) => return,
                    },
                };
                let changed = current.is_major_change(&previous);
                previous = current;
                if changed {
                    let Some(group) = group.upgrade() else {
                        return;
                    };
                    group.interface_updated().await;
                }
            }
        });
    }

    /// Immediately re-probe every candidate after an interface or default
    /// route update, regardless of the normal refresh interval.
    pub async fn interface_updated(&self) {
        self.refresh(true).await;
    }

    pub fn selected(&self) -> Option<String> {
        self.state
            .lock()
            .expect("urltest lock poisoned")
            .selected
            .clone()
    }

    pub(crate) fn selected_or_first(&self) -> String {
        self.selected()
            .or_else(|| self.order.first().cloned())
            .unwrap_or_default()
    }

    pub fn history(&self) -> HashMap<String, u16> {
        self.state
            .lock()
            .expect("urltest lock poisoned")
            .history
            .iter()
            .map(|(tag, (_, delay))| (tag.clone(), *delay))
            .collect()
    }

    pub fn history_entry(&self, tag: &str) -> Option<(SystemTime, u16)> {
        let tag = self.groups.real_tag(tag);
        self.state
            .lock()
            .expect("urltest lock poisoned")
            .history
            .get(&tag)
            .map(|(checked, delay)| {
                (
                    SystemTime::now()
                        .checked_sub(checked.elapsed())
                        .unwrap_or(SystemTime::UNIX_EPOCH),
                    *delay,
                )
            })
    }

    pub fn choices(&self) -> impl Iterator<Item = &str> {
        self.order.iter().map(String::as_str)
    }

    async fn current(
        &self,
        external: bool,
    ) -> (String, Arc<dyn Dialer>, CancellationToken) {
        self.touch();
        self.refresh(false).await;
        let state = self.state.lock().expect("urltest lock poisoned");
        let selected = state
            .selected
            .clone()
            .unwrap_or_else(|| self.order[0].clone());
        (
            selected.clone(),
            self.choices[&selected].clone(),
            state.generations.token(external),
        )
    }

    fn invalidate(&self, tag: &str) {
        let tag = self.groups.real_tag(tag);
        let mut state = self.state.lock().expect("urltest lock poisoned");
        state.history.remove(&tag);
        state.last_checked = None;
        drop(state);
        self.groups.notify_updated();
    }

    pub async fn refresh(&self, force: bool) -> HashMap<String, u16> {
        if !force
            && self
                .state
                .lock()
                .expect("urltest lock poisoned")
                .last_checked
                .is_some_and(|checked| checked.elapsed() < self.interval)
        {
            return self.history();
        }
        let _guard = self.check.lock().await;
        if !force
            && self
                .state
                .lock()
                .expect("urltest lock poisoned")
                .last_checked
                .is_some_and(|checked| checked.elapsed() < self.interval)
        {
            return self.history();
        }
        let mut targets = Vec::new();
        let mut nested_urltests = Vec::new();
        let mut aliases = Vec::new();
        let mut visited = HashSet::new();
        for tag in &self.order {
            self.groups.collect_work(
                tag,
                self.choices[tag].clone(),
                &mut visited,
                &mut targets,
                &mut nested_urltests,
                &mut aliases,
            );
        }
        let tests = targets.into_iter().map(|(tag, dialer)| {
            let url = self.url.clone();
            let ntp_clock = self.ntp_clock.clone();
            let certificate_store = self.certificate_store.clone();
            async move {
                (
                    tag,
                    probe_url_with_context(
                        dialer,
                        &url,
                        crate::constant::TCP_TIMEOUT,
                        ntp_clock,
                        certificate_store,
                    )
                    .await,
                )
            }
        });
        let results = join_all(tests).await;
        let nested_results =
            join_all(nested_urltests.into_iter().map(|group| {
                Box::pin(async move { group.refresh(force).await })
            }))
            .await;
        let now = Instant::now();
        let mut state = self.state.lock().expect("urltest lock poisoned");
        for (tag, result) in results {
            match result {
                Ok(delay) => {
                    state.history.insert(tag, (now, delay));
                }
                Err(_) => {
                    state.history.remove(&tag);
                }
            }
        }
        for result in nested_results {
            for (tag, delay) in result {
                state.history.insert(tag, (now, delay));
            }
        }
        state.last_checked = Some(now);
        let best = self
            .order
            .iter()
            .filter_map(|tag| {
                let real_tag = self.groups.real_tag(tag);
                state.history.get(&real_tag).map(|(_, delay)| (tag, *delay))
            })
            .min_by_key(|(_, delay)| *delay);
        let previous = state.selected.clone();
        if let Some((best_tag, best_delay)) = best {
            let keep_current = state
                .selected
                .as_ref()
                .and_then(|tag| state.history.get(&self.groups.real_tag(tag)))
                .is_some_and(|(_, delay)| {
                    *delay <= best_delay.saturating_add(self.tolerance)
                });
            if !keep_current {
                state.selected = Some(best_tag.clone());
            }
        } else if state.selected.is_none() {
            state.selected = self.order.first().cloned();
        }
        if state.selected != previous {
            state
                .generations
                .interrupt(self.interrupt_exist_connections);
        }
        let mut result: HashMap<_, _> = state
            .history
            .iter()
            .map(|(tag, (_, delay))| (tag.clone(), *delay))
            .collect();
        for alias in aliases {
            if let Some((_, delay)) =
                state.history.get(&self.groups.real_tag(&alias))
            {
                result.insert(alias, *delay);
            }
        }
        drop(state);
        self.groups.notify_updated();
        result
    }
}

impl Drop for UrlTestOutbound {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.state
            .lock()
            .expect("urltest lock poisoned")
            .generations
            .cancel_all();
    }
}

impl Dialer for UrlTestOutbound {
    fn icmp_flow_addresses(
        &self,
    ) -> Option<(Option<std::net::IpAddr>, Option<std::net::IpAddr>)> {
        let selected = self.selected_or_first();
        self.choices.get(&selected)?.icmp_flow_addresses()
    }

    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        let selected = self.selected_or_first();
        self.choices.get(&selected)?.packet_port()
    }

    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let (tag, current, generation) = self.current(false).await;
            match current.dial_tcp(destination).await {
                Ok(stream) => {
                    Ok(crate::adapter::interruptible_stream(stream, generation))
                }
                Err(error) => {
                    self.invalidate(&tag);
                    Err(error)
                }
            }
        })
    }

    fn dial_tcp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> DialFuture<'a> {
        Box::pin(async move {
            let (tag, current, generation) =
                self.current(options.external_connection).await;
            match current.dial_tcp_with_options(destination, options).await {
                Ok(stream) => {
                    Ok(crate::adapter::interruptible_stream(stream, generation))
                }
                Err(error) => {
                    self.invalidate(&tag);
                    Err(error)
                }
            }
        })
    }

    fn bind_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let (tag, current, generation) = self.current(false).await;
            match current.bind_tcp(destination).await {
                Ok(stream) => {
                    Ok(crate::adapter::interruptible_stream(stream, generation))
                }
                Err(error) => {
                    self.invalidate(&tag);
                    Err(error)
                }
            }
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let (tag, current, generation) = self.current(false).await;
            match current.listen_udp(destination).await {
                Ok(packets) => Ok(crate::adapter::interruptible_packets(
                    packets, generation,
                )),
                Err(error) => {
                    self.invalidate(&tag);
                    Err(error)
                }
            }
        })
    }

    fn listen_udp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let (tag, current, generation) =
                self.current(options.external_connection).await;
            match current.listen_udp_with_options(destination, options).await {
                Ok(packets) => Ok(crate::adapter::interruptible_packets(
                    packets, generation,
                )),
                Err(error) => {
                    self.invalidate(&tag);
                    Err(error)
                }
            }
        })
    }

    fn exchange_icmp<'a>(
        &'a self,
        packet: &'a [u8],
        source: std::net::IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, IcmpResponse> {
        Box::pin(async move {
            let (tag, current, generation) = self.current(false).await;
            let result = tokio::select! {
                biased;
                _ = generation.cancelled() => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "outbound group selection changed",
                )),
                result = current.exchange_icmp(packet, source, hop_limit, destination) => result,
            };
            if result.is_err() {
                self.invalidate(&tag);
            }
            result
        })
    }

    fn exchange_icmp_with_options<'a>(
        &'a self,
        packet: &'a [u8],
        source: std::net::IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, IcmpResponse> {
        Box::pin(async move {
            let (tag, current, generation) =
                self.current(options.external_connection).await;
            let result = tokio::select! {
                biased;
                _ = generation.cancelled() => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "outbound group selection changed",
                )),
                result = current.exchange_icmp_with_options(
                    packet, source, hop_limit, destination, options
                ) => result,
            };
            if result.is_err() {
                self.invalidate(&tag);
            }
            result
        })
    }
}

pub(crate) async fn probe_url_with_timeout(
    dialer: Arc<dyn Dialer>,
    url: &Url,
    timeout_value: Duration,
) -> io::Result<u16> {
    probe_url_with_context(dialer, url, timeout_value, None, None).await
}

async fn probe_url_with_context(
    dialer: Arc<dyn Dialer>,
    url: &Url,
    timeout_value: Duration,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
) -> io::Result<u16> {
    timeout(
        timeout_value,
        probe_url_inner(dialer, url, ntp_clock, certificate_store),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "urltest timed out"))?
}

async fn probe_url_inner(
    dialer: Arc<dyn Dialer>,
    url: &Url,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
) -> io::Result<u16> {
    let host = url
        .host_str()
        .ok_or_else(|| invalid_input("urltest URL has no host"))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        invalid_input("urltest URL scheme has no default port")
    })?;
    let started = Instant::now();
    let stream = dialer.dial_tcp(&SocksAddr::new(host, port)).await?;
    let mut stream: Stream = if url.scheme() == "https" {
        let tls = build_client_config_with_clock(
            host,
            &OutboundTlsOptions::default()
                .with_certificate_store_if_some(certificate_store),
            &["http/1.1"],
            ntp_clock,
        )
        .map_err(io::Error::other)?;
        tls.connect_stream(stream).await?.into_stream()
    } else if url.scheme() == "http" {
        stream
    } else {
        return Err(invalid_input(format!(
            "unsupported urltest scheme {:?}",
            url.scheme()
        )));
    };
    let target = match url[url::Position::BeforePath..].split_once('#') {
        Some((target, _)) => target,
        None => &url[url::Position::BeforePath..],
    };
    let host_header = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    stream
        .write_all(
            format!(
                "HEAD {target} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    stream.flush().await?;
    let mut header = Vec::with_capacity(512);
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 1 << 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "urltest response header is too large",
            ));
        }
        header.push(stream.read_u8().await?);
    }
    if !header.starts_with(b"HTTP/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid urltest HTTP response",
        ));
    }
    Ok(u16::try_from(started.elapsed().as_millis()).unwrap_or(u16::MAX))
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, AtomicUsize};

    use super::*;
    use crate::adapter::DialFuture;

    struct ProbeDialer {
        name: &'static str,
        delay: Duration,
    }

    struct CountingProbeDialer(Arc<AtomicUsize>);

    struct SwitchingProbeDialer(Arc<AtomicU64>);

    impl Dialer for SwitchingProbeDialer {
        fn dial_tcp<'a>(
            &'a self,
            destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async move {
                let (client, mut server) = tokio::io::duplex(4096);
                if *destination == SocksAddr::new("probe.test", 80) {
                    let delay = self.0.load(Ordering::SeqCst);
                    tokio::spawn(async move {
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") {
                            request.push(server.read_u8().await.unwrap());
                        }
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        server
                            .write_all(
                                b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
                            )
                            .await
                            .unwrap();
                    });
                } else {
                    tokio::spawn(async move {
                        let _server = server;
                        std::future::pending::<()>().await;
                    });
                }
                Ok(Box::new(client) as Stream)
            })
        }
    }

    impl Dialer for CountingProbeDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                let (client, mut server) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        request.push(server.read_u8().await.unwrap());
                    }
                    server
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                });
                Ok(Box::new(client) as Stream)
            })
        }
    }

    impl Dialer for ProbeDialer {
        fn dial_tcp<'a>(
            &'a self,
            destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async move {
                if *destination != SocksAddr::new("probe.test", 80) {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        self.name,
                    ));
                }
                let (client, mut server) = tokio::io::duplex(4096);
                let delay = self.delay;
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        request.push(server.read_u8().await.unwrap());
                    }
                    tokio::time::sleep(delay).await;
                    server
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                });
                Ok(Box::new(client) as Stream)
            })
        }
    }

    #[tokio::test]
    async fn probes_candidates_and_routes_through_the_fastest() {
        let choices: HashMap<String, Arc<dyn Dialer>> = HashMap::from([
            (
                "slow".into(),
                Arc::new(ProbeDialer {
                    name: "slow",
                    delay: Duration::from_millis(30),
                }) as Arc<dyn Dialer>,
            ),
            (
                "fast".into(),
                Arc::new(ProbeDialer {
                    name: "fast",
                    delay: Duration::from_millis(1),
                }) as Arc<dyn Dialer>,
            ),
        ]);
        let options: UrlTestOutboundOptions =
            serde_json::from_value(serde_json::json!({
                "outbounds":["slow","fast"],
                "url":"http://probe.test/generate_204",
                "tolerance":1
            }))
            .unwrap();
        let registry = Arc::new(GroupRegistry::default());
        let mut updates = registry.subscribe_updates();
        let group =
            UrlTestOutbound::new_with_registry(options, choices, registry)
                .unwrap();
        let error = match group
            .dial_tcp(&SocksAddr::new("destination.test", 443))
            .await
        {
            Ok(_) => panic!("test dial unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "fast");
        assert_eq!(group.selected().as_deref(), Some("fast"));
        assert_eq!(group.history().len(), 1);
        assert!(group.history().contains_key("slow"));
        assert_eq!(updates.try_recv(), Ok(()));
    }

    #[tokio::test]
    async fn selection_change_only_preserves_external_connections_when_configured()
     {
        let one_delay = Arc::new(AtomicU64::new(1));
        let two_delay = Arc::new(AtomicU64::new(30));
        let choices: HashMap<String, Arc<dyn Dialer>> = HashMap::from([
            (
                "one".into(),
                Arc::new(SwitchingProbeDialer(one_delay.clone()))
                    as Arc<dyn Dialer>,
            ),
            (
                "two".into(),
                Arc::new(SwitchingProbeDialer(two_delay.clone()))
                    as Arc<dyn Dialer>,
            ),
        ]);
        let options: UrlTestOutboundOptions =
            serde_json::from_value(serde_json::json!({
                "outbounds":["one","two"],
                "url":"http://probe.test/generate_204",
                "tolerance":1,
                "interrupt_exist_connections":false
            }))
            .unwrap();
        let group = UrlTestOutbound::new(options, choices).unwrap();
        group.refresh(true).await;
        assert_eq!(group.selected().as_deref(), Some("one"));
        let destination = SocksAddr::new("destination.test", 443);
        let mut internal = group.dial_tcp(&destination).await.unwrap();
        let mut external = group
            .dial_tcp_with_options(
                &destination,
                &NetworkDialOptions {
                    external_connection: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        one_delay.store(40, Ordering::SeqCst);
        two_delay.store(1, Ordering::SeqCst);
        group.refresh(true).await;
        assert_eq!(group.selected().as_deref(), Some("two"));

        assert_eq!(
            internal.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), external.read_u8())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn recursively_refreshes_nested_groups_and_reports_aliases() {
        let fast = Arc::new(ProbeDialer {
            name: "fast",
            delay: Duration::from_millis(1),
        }) as Arc<dyn Dialer>;
        let slow = Arc::new(ProbeDialer {
            name: "slow",
            delay: Duration::from_millis(80),
        }) as Arc<dyn Dialer>;
        let medium = Arc::new(ProbeDialer {
            name: "medium",
            delay: Duration::from_millis(30),
        }) as Arc<dyn Dialer>;
        let registry = Arc::new(GroupRegistry::default());
        let selector = Arc::new(
            SelectorOutbound::new(
                vec!["fast".into(), "slow".into()],
                HashMap::from([("fast".into(), fast), ("slow".into(), slow)]),
                "fast".into(),
                false,
            )
            .unwrap(),
        );
        registry.register_selector("nested-selector".into(), &selector);
        let child_options: UrlTestOutboundOptions =
            serde_json::from_value(serde_json::json!({
                "outbounds":["nested-selector"],
                "url":"http://probe.test/generate_204",
                "tolerance":1
            }))
            .unwrap();
        let child = Arc::new(
            UrlTestOutbound::new_with_registry(
                child_options,
                HashMap::from([(
                    "nested-selector".into(),
                    selector.clone() as Arc<dyn Dialer>,
                )]),
                registry.clone(),
            )
            .unwrap(),
        );
        registry.register_urltest("child-urltest".into(), &child);
        let parent_options: UrlTestOutboundOptions =
            serde_json::from_value(serde_json::json!({
                "outbounds":["child-urltest", "medium"],
                "url":"http://probe.test/generate_204",
                "tolerance":1
            }))
            .unwrap();
        let parent = UrlTestOutbound::new_with_registry(
            parent_options,
            HashMap::from([
                ("child-urltest".into(), child.clone() as Arc<dyn Dialer>),
                ("medium".into(), medium),
            ]),
            registry.clone(),
        )
        .unwrap();

        let first = parent.refresh(true).await;
        assert_eq!(parent.selected().as_deref(), Some("child-urltest"));
        assert_eq!(child.selected().as_deref(), Some("nested-selector"));
        assert_eq!(registry.real_tag("child-urltest"), "fast");
        assert_eq!(first.get("nested-selector"), first.get("fast"));
        assert_eq!(first.get("child-urltest"), first.get("fast"));
        assert!(first.contains_key("slow"));
        assert!(first.contains_key("medium"));

        selector.select("slow").unwrap();
        let second = parent.refresh(true).await;
        assert_eq!(registry.real_tag("child-urltest"), "slow");
        assert_eq!(parent.selected().as_deref(), Some("medium"));
        assert_eq!(second.get("nested-selector"), second.get("slow"));
        assert_eq!(second.get("child-urltest"), second.get("slow"));
    }

    #[tokio::test]
    async fn background_checker_pauses_when_idle_and_resumes_on_touch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let choices = HashMap::from([(
            "one".into(),
            Arc::new(CountingProbeDialer(calls.clone())) as Arc<dyn Dialer>,
        )]);
        let options: UrlTestOutboundOptions =
            serde_json::from_value(serde_json::json!({
                "outbounds":["one"],
                "url":"http://probe.test/generate_204",
                "interval":"20ms",
                "idle_timeout":"70ms"
            }))
            .unwrap();
        let group = Arc::new(UrlTestOutbound::new(options, choices).unwrap());
        group.attach();
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("background checker did not perform a periodic probe");

        tokio::time::sleep(Duration::from_millis(100)).await;
        let idle_calls = calls.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(calls.load(Ordering::SeqCst), idle_calls);

        group.touch();
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::SeqCst) <= idle_calls {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("background checker did not resume after touch");
    }

    #[tokio::test]
    async fn interface_update_forces_a_probe_before_the_interval() {
        let calls = Arc::new(AtomicUsize::new(0));
        let choices = HashMap::from([(
            "one".into(),
            Arc::new(CountingProbeDialer(calls.clone())) as Arc<dyn Dialer>,
        )]);
        let options: UrlTestOutboundOptions =
            serde_json::from_value(serde_json::json!({
                "outbounds":["one"],
                "url":"http://probe.test/generate_204",
                "interval":"1h",
                "idle_timeout":"2h"
            }))
            .unwrap();
        let group = UrlTestOutbound::new(options, choices).unwrap();
        group.refresh(false).await;
        group.refresh(false).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        group.interface_updated().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn validates_group_members_and_timing() {
        let options: UrlTestOutboundOptions =
            serde_json::from_value(serde_json::json!({
                "outbounds":["missing"]
            }))
            .unwrap();
        assert!(UrlTestOutbound::new(options, HashMap::new()).is_err());

        let options: UrlTestOutboundOptions =
            serde_json::from_value(serde_json::json!({
                "outbounds":["one"],
                "interval":"2m",
                "idle_timeout":"1m"
            }))
            .unwrap();
        let choices = HashMap::from([(
            "one".into(),
            Arc::new(ProbeDialer {
                name: "one",
                delay: Duration::ZERO,
            }) as Arc<dyn Dialer>,
        )]);
        assert!(UrlTestOutbound::new(options, choices).is_err());
    }
}
