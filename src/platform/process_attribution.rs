//! Optional platform flow monitors layered over sing-box's native resolver.

use std::sync::Arc;

use singbox_core::ProcessResolver;

#[cfg(target_os = "macos")]
mod macos {
    use std::{
        collections::VecDeque,
        env,
        fs::{self, File},
        io::{Read, Seek, SeekFrom},
        net::SocketAddr,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        str::FromStr,
        sync::{Arc, Mutex},
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use serde::Deserialize;
    use singbox_core::{
        ProcessInfo, ProcessLookupResult, ProcessLookupStatus, ProcessResolver,
        common::network::Network,
    };

    const APP_GROUP_ID: &str = "group.dev.zay.macos";
    // The system extension runs as root, so its App Group container is
    // root's even when zay itself runs as the logged-in user.
    const ROOT_HOME: &str = "/private/var/root";
    const EVENT_TTL: Duration = Duration::from_secs(60);
    // An event that names only one end of the flow cannot tell two sockets
    // apart for long, so it is only believed right after it was observed.
    const WEAK_EVENT_TTL: Duration = Duration::from_secs(3);
    const DESTINATION_SCORE: u8 = 8;
    const SOURCE_SCORE: u8 = 5;
    const SOURCE_PORT_SCORE: u8 = 3;
    const STRONG_SCORE: u8 = DESTINATION_SCORE + SOURCE_PORT_SCORE;
    const EVENT_LIMIT: usize = 8192;
    const RETRY_COUNT: usize = 3;
    const RETRY_DELAY: Duration = Duration::from_millis(2);
    // Waiting for an event only pays off while the extension is publishing.
    const EXTENSION_LIVE_WINDOW: Duration = Duration::from_secs(300);

    #[derive(Debug, Deserialize)]
    struct FlowEvent {
        #[serde(default)]
        version: u8,
        observed_at_ms: u64,
        network: String,
        source: Option<String>,
        destination: Option<String>,
        #[serde(default)]
        process_name: String,
        #[serde(default)]
        process_path: String,
        #[serde(default)]
        signing_identifier: String,
        uid: Option<i32>,
    }

    #[derive(Debug, Clone)]
    struct CachedFlow {
        observed_at: SystemTime,
        network: Network,
        source: Option<SocketAddr>,
        destination: Option<SocketAddr>,
        process: ProcessInfo,
    }

    #[derive(Default)]
    struct TailState {
        offset: u64,
        file: Option<(u64, u64)>,
        pending: Vec<u8>,
    }

    pub(super) struct MacOsProcessAttributionResolver {
        paths: Vec<PathBuf>,
        tail: Mutex<TailState>,
        events: Mutex<VecDeque<CachedFlow>>,
        fallback: Option<Arc<dyn ProcessResolver>>,
    }

    impl MacOsProcessAttributionResolver {
        fn new(
            paths: Vec<PathBuf>,
            fallback: Option<Arc<dyn ProcessResolver>>,
        ) -> Self {
            Self {
                paths,
                tail: Mutex::new(TailState::default()),
                events: Mutex::new(VecDeque::new()),
                fallback,
            }
        }

        /// The first event file whose contents can be believed.
        fn event_file(&self) -> Option<(&Path, fs::Metadata)> {
            self.paths.iter().find_map(|path| {
                let metadata = fs::metadata(path).ok()?;
                trusted_event_file(&metadata)
                    .then_some((path.as_path(), metadata))
            })
        }

        fn extension_is_publishing(&self) -> bool {
            self.event_file().is_some_and(|(_, metadata)| {
                metadata
                    .modified()
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    // A timestamp in the future still means a live writer.
                    .is_none_or(|age| age < EXTENSION_LIVE_WINDOW)
            })
        }

        fn refresh(&self) {
            let Some((path, metadata)) = self.event_file() else {
                return;
            };
            let mut tail = self.tail.lock().expect("flow event tail lock");
            let file = (metadata.dev(), metadata.ino());
            if tail.file != Some(file) || metadata.len() < tail.offset {
                tail.offset = 0;
                tail.pending.clear();
                tail.file = Some(file);
            }
            let Ok(mut file) = File::open(path) else {
                return;
            };
            if file.seek(SeekFrom::Start(tail.offset)).is_err() {
                return;
            }
            let mut bytes = Vec::new();
            if file.read_to_end(&mut bytes).is_err() || bytes.is_empty() {
                return;
            }
            tail.offset += bytes.len() as u64;
            tail.pending.extend_from_slice(&bytes);
            let complete =
                tail.pending.iter().rposition(|byte| *byte == b'\n').map(
                    |index| tail.pending.drain(..=index).collect::<Vec<_>>(),
                );
            drop(tail);
            let Some(complete) = complete else {
                return;
            };
            let mut events = self.events.lock().expect("flow event cache lock");
            for line in complete.split(|byte| *byte == b'\n') {
                if line.is_empty() || line.len() > 64 * 1024 {
                    continue;
                }
                let Ok(event) = serde_json::from_slice::<FlowEvent>(line)
                else {
                    continue;
                };
                if let Some(event) = convert_event(event) {
                    events.push_back(event);
                }
            }
            prune(&mut events);
        }

        fn monitored_lookup(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> Option<ProcessInfo> {
            self.refresh();
            let mut events = self.events.lock().expect("flow event cache lock");
            prune(&mut events);
            select_process(events.iter(), network, source, destination)
        }
    }

    impl ProcessResolver for MacOsProcessAttributionResolver {
        fn lookup(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> Option<ProcessInfo> {
            self.lookup_detailed(network, source, destination).process
        }

        fn lookup_detailed(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> ProcessLookupResult {
            if let Some(process) =
                self.monitored_lookup(network, source, destination)
            {
                return monitored(process);
            }
            let fallback = self
                .fallback
                .as_ref()
                .map(|resolver| {
                    resolver.lookup_detailed(network, source, destination)
                })
                .unwrap_or_else(|| ProcessLookupResult {
                    process: None,
                    status: ProcessLookupStatus::SocketSnapshotMiss,
                });
            if fallback.process.is_some() || !self.extension_is_publishing() {
                return fallback;
            }
            // The content filter and packet tunnel callbacks can arrive on
            // adjacent queues. Give the signed extension a few milliseconds
            // to publish identity before returning an unresolved flow.
            for _ in 0..RETRY_COUNT {
                thread::sleep(RETRY_DELAY);
                if let Some(process) =
                    self.monitored_lookup(network, source, destination)
                {
                    return monitored(process);
                }
            }
            fallback
        }
    }

    fn monitored(process: ProcessInfo) -> ProcessLookupResult {
        ProcessLookupResult {
            process: Some(process),
            status: ProcessLookupStatus::PlatformMonitor,
        }
    }

    fn convert_event(event: FlowEvent) -> Option<CachedFlow> {
        if event.version != 1 || event.process_name.is_empty() {
            return None;
        }
        let network = match event.network.as_str() {
            "tcp" => Network::Tcp,
            "udp" => Network::Udp,
            _ => return None,
        };
        let observed_at = UNIX_EPOCH
            .checked_add(Duration::from_millis(event.observed_at_ms))?;
        if observed_at.elapsed().unwrap_or_default() > EVENT_TTL {
            return None;
        }
        Some(CachedFlow {
            observed_at,
            network,
            // The filter sees most outbound flows before they are bound and
            // reports port 0, which identifies no socket.
            source: parse_socket(event.source.as_deref())
                .filter(|source| source.port() != 0),
            destination: parse_socket(event.destination.as_deref())
                .filter(|destination| destination.port() != 0),
            process: ProcessInfo {
                process_name: event.process_name,
                process_path: event.process_path,
                package_name: event.signing_identifier,
                user_id: event.uid,
                ..ProcessInfo::default()
            },
        })
    }

    fn parse_socket(value: Option<&str>) -> Option<SocketAddr> {
        SocketAddr::from_str(value?).ok()
    }

    /// An event file is evidence only if no other user could have written
    /// it: it must belong to root or to this process and grant nobody else
    /// write access.
    fn trusted_event_file(metadata: &fs::Metadata) -> bool {
        let owner = metadata.uid();
        metadata.is_file()
            && (owner == 0 || owner == unsafe { libc::geteuid() })
            && metadata.mode() & 0o022 == 0
    }

    fn select_process<'a>(
        events: impl Iterator<Item = &'a CachedFlow>,
        network: Network,
        source: SocketAddr,
        destination: Option<SocketAddr>,
    ) -> Option<ProcessInfo> {
        let mut strong: Option<(u8, &CachedFlow)> = None;
        let mut weak: Vec<&CachedFlow> = Vec::new();
        for event in events.filter(|event| event.network == network) {
            let Some(score) = match_score(event, source, destination) else {
                continue;
            };
            if score >= STRONG_SCORE {
                if strong.is_none_or(|(best, current)| {
                    (score, event.observed_at) >= (best, current.observed_at)
                }) {
                    strong = Some((score, event));
                }
            } else if event.observed_at.elapsed().unwrap_or_default()
                < WEAK_EVENT_TTL
            {
                weak.push(event);
            }
        }
        if let Some((_, event)) = strong {
            return Some(event.process.clone());
        }
        // Several processes sharing one destination or one port leave no
        // way to choose; the socket table is the better witness then.
        let newest = weak.iter().max_by_key(|event| event.observed_at)?;
        weak.iter()
            .all(|event| event.process == newest.process)
            .then(|| newest.process.clone())
    }

    fn match_score(
        event: &CachedFlow,
        source: SocketAddr,
        destination: Option<SocketAddr>,
    ) -> Option<u8> {
        let mut score = 0;
        if let Some(candidate) = event.destination {
            if destination != Some(candidate) {
                return None;
            }
            score += DESTINATION_SCORE;
        }
        if let Some(candidate) = event.source {
            if candidate == source {
                score += SOURCE_SCORE;
            } else if candidate.port() == source.port() {
                score += SOURCE_PORT_SCORE;
            } else {
                return None;
            }
        }
        (score > 0).then_some(score)
    }

    fn prune(events: &mut VecDeque<CachedFlow>) {
        events.retain(|event| {
            event.observed_at.elapsed().unwrap_or_default() < EVENT_TTL
        });
        while events.len() > EVENT_LIMIT {
            events.pop_front();
        }
    }

    fn event_paths() -> Vec<PathBuf> {
        if let Some(path) = env::var_os("ZAY_PROCESS_ATTRIBUTION_FILE") {
            return vec![PathBuf::from(path)];
        }
        let mut homes = vec![PathBuf::from(ROOT_HOME)];
        if let Some(home) = dirs_next::home_dir()
            && !homes.contains(&home)
        {
            homes.insert(0, home);
        }
        homes
            .into_iter()
            .map(|home| {
                home.join("Library")
                    .join("Group Containers")
                    .join(APP_GROUP_ID)
                    .join("Library")
                    .join("Application Support")
                    .join("Zay")
                    .join("attribution")
                    .join("flows.jsonl")
            })
            .collect()
    }

    pub(super) fn resolver() -> Arc<dyn ProcessResolver> {
        Arc::new(MacOsProcessAttributionResolver::new(
            event_paths(),
            singbox_core::native_process_resolver(),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn matches_tun_flow_by_preserved_source_port() {
            let event = CachedFlow {
                observed_at: SystemTime::now(),
                network: Network::Udp,
                source: Some("192.168.1.8:53000".parse().unwrap()),
                destination: Some("1.1.1.1:53".parse().unwrap()),
                process: ProcessInfo::default(),
            };
            assert_eq!(
                match_score(
                    &event,
                    "10.14.14.9:53000".parse().unwrap(),
                    Some("1.1.1.1:53".parse().unwrap())
                ),
                Some(11)
            );
        }

        #[test]
        fn rejects_same_destination_with_different_source_port() {
            let event = CachedFlow {
                observed_at: SystemTime::now(),
                network: Network::Tcp,
                source: Some("192.168.1.8:53000".parse().unwrap()),
                destination: Some("1.1.1.1:443".parse().unwrap()),
                process: ProcessInfo::default(),
            };
            assert_eq!(
                match_score(
                    &event,
                    "10.14.14.9:53001".parse().unwrap(),
                    Some("1.1.1.1:443".parse().unwrap())
                ),
                None
            );
        }

        fn flow(
            age: Duration,
            source: Option<&str>,
            destination: Option<&str>,
            name: &str,
        ) -> CachedFlow {
            CachedFlow {
                observed_at: SystemTime::now() - age,
                network: Network::Tcp,
                source: source.map(|source| source.parse().unwrap()),
                destination: destination
                    .map(|destination| destination.parse().unwrap()),
                process: ProcessInfo {
                    process_name: name.into(),
                    ..ProcessInfo::default()
                },
            }
        }

        fn select(events: &[CachedFlow]) -> Option<String> {
            select_process(
                events.iter(),
                Network::Tcp,
                "10.14.14.9:53000".parse().unwrap(),
                Some("1.1.1.1:443".parse().unwrap()),
            )
            .map(|process| process.process_name)
        }

        #[test]
        fn unbound_source_is_not_a_mismatch() {
            let event = convert_event(FlowEvent {
                version: 1,
                observed_at_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                network: "tcp".into(),
                source: Some("0.0.0.0:0".into()),
                destination: Some("1.1.1.1:443".into()),
                process_name: "curl".into(),
                process_path: String::new(),
                signing_identifier: String::new(),
                uid: None,
            })
            .unwrap();
            assert_eq!(event.source, None);
            assert_eq!(select(&[event]).as_deref(), Some("curl"));
        }

        #[test]
        fn destination_only_event_must_be_fresh_and_unambiguous() {
            let second = Duration::from_secs(1);
            let target = Some("1.1.1.1:443");
            let fresh = flow(second, None, target, "curl");
            assert_eq!(select(&[fresh.clone()]).as_deref(), Some("curl"));

            let stale = flow(WEAK_EVENT_TTL + second, None, target, "curl");
            assert_eq!(select(&[stale]), None);

            let rival = flow(second, None, target, "wget");
            assert_eq!(select(&[fresh.clone(), rival.clone()]), None);

            // An event naming both ends settles it, even when it is older.
            let strong = flow(
                WEAK_EVENT_TTL + second,
                Some("192.168.1.8:53000"),
                target,
                "git",
            );
            assert_eq!(select(&[fresh, rival, strong]).as_deref(), Some("git"));
        }
    }
}

pub(crate) fn resolver() -> Option<Arc<dyn ProcessResolver>> {
    #[cfg(target_os = "macos")]
    {
        Some(macos::resolver())
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        singbox_core::native_process_resolver()
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    )))]
    {
        None
    }
}

pub(crate) const fn backend_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "network-extension+socket-snapshot"
    }
    #[cfg(target_os = "linux")]
    {
        "inet-diag+procfs"
    }
    #[cfg(target_os = "windows")]
    {
        "ip-helper-api"
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    )))]
    {
        "unavailable"
    }
}
