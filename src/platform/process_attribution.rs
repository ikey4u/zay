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
    const EVENT_TTL: Duration = Duration::from_secs(60);
    const EVENT_LIMIT: usize = 8192;
    const RETRY_COUNT: usize = 3;
    const RETRY_DELAY: Duration = Duration::from_millis(2);

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
        inode: Option<u64>,
        pending: Vec<u8>,
    }

    pub(super) struct MacOsProcessAttributionResolver {
        path: PathBuf,
        tail: Mutex<TailState>,
        events: Mutex<VecDeque<CachedFlow>>,
        fallback: Option<Arc<dyn ProcessResolver>>,
    }

    impl MacOsProcessAttributionResolver {
        fn new(
            path: PathBuf,
            fallback: Option<Arc<dyn ProcessResolver>>,
        ) -> Self {
            Self {
                path,
                tail: Mutex::new(TailState::default()),
                events: Mutex::new(VecDeque::new()),
                fallback,
            }
        }

        fn refresh(&self) {
            let Ok(metadata) = fs::metadata(&self.path) else {
                return;
            };
            let mut tail = self.tail.lock().expect("flow event tail lock");
            let inode = metadata.ino();
            if tail.inode != Some(inode) || metadata.len() < tail.offset {
                tail.offset = 0;
                tail.pending.clear();
                tail.inode = Some(inode);
            }
            let Ok(mut file) = File::open(&self.path) else {
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
            events
                .iter()
                .rev()
                .filter(|event| event.network == network)
                .filter_map(|event| {
                    let score = match_score(event, source, destination)?;
                    Some((score, event.observed_at, event.process.clone()))
                })
                .max_by_key(|(score, observed_at, _)| (*score, *observed_at))
                .map(|(_, _, process)| process)
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
            if fallback.process.is_some() || !self.path.is_file() {
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
            source: parse_socket(event.source.as_deref()),
            destination: parse_socket(event.destination.as_deref()),
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

    fn match_score(
        event: &CachedFlow,
        source: SocketAddr,
        destination: Option<SocketAddr>,
    ) -> Option<u8> {
        let mut score = 0;
        if let Some(candidate) = event.destination {
            let destination = destination?;
            if candidate != destination {
                return None;
            }
            score += 8;
        }
        if let Some(candidate) = event.source {
            if candidate == source {
                score += 5;
            } else if candidate.port() == source.port() {
                score += 3;
            } else {
                return None;
            }
        }
        (score >= 8 || event.source.is_some()).then_some(score)
    }

    fn prune(events: &mut VecDeque<CachedFlow>) {
        events.retain(|event| {
            event.observed_at.elapsed().unwrap_or_default() < EVENT_TTL
        });
        while events.len() > EVENT_LIMIT {
            events.pop_front();
        }
    }

    fn event_path() -> PathBuf {
        if let Some(path) = env::var_os("ZAY_PROCESS_ATTRIBUTION_FILE") {
            return PathBuf::from(path);
        }
        dirs_next::home_dir()
            .unwrap_or_else(|| Path::new("/").to_path_buf())
            .join("Library")
            .join("Group Containers")
            .join(APP_GROUP_ID)
            .join("Library")
            .join("Application Support")
            .join("Zay")
            .join("attribution")
            .join("flows.jsonl")
    }

    pub(super) fn resolver() -> Arc<dyn ProcessResolver> {
        Arc::new(MacOsProcessAttributionResolver::new(
            event_path(),
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
