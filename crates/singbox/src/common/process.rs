//! Native process ownership lookup used by process-aware route rules.

#[cfg(target_os = "macos")]
mod platform {
    use std::{
        collections::HashMap,
        ffi::CString,
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        path::Path,
        ptr,
        sync::{
            Arc, Mutex, OnceLock, Weak,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use crate::{
        adapter::{
            ProcessInfo, ProcessLookupResult, ProcessLookupStatus,
            ProcessResolver,
        },
        common::network::Network,
    };

    const SNAPSHOT_TTL: Duration = Duration::from_millis(200);
    const UDP_OWNER_TTL: Duration = Duration::from_secs(30);
    const UDP_OWNER_CACHE_LIMIT: usize = 4096;
    const UDP_SAMPLER_INTERVAL: Duration = Duration::from_millis(5);
    // Dumping the UDP socket table every few milliseconds is only worth its
    // CPU while UDP flows are actually being attributed.
    const UDP_SAMPLER_IDLE_INTERVAL: Duration = Duration::from_millis(100);
    const UDP_SAMPLER_ACTIVE_WINDOW: Duration = Duration::from_secs(10);
    // A PID can be reused or exec a new image, so the sampler only trusts a
    // resolved path briefly.
    const UDP_SAMPLER_PROCESS_TTL: Duration = Duration::from_secs(2);
    const XSO_SOCKET: u32 = 0x001;
    const XSO_INPCB: u32 = 0x010;
    const XINPCB_MIN_SIZE: usize = XINPCB_LOCAL_ADDR + 16;
    const XSOCKET_MIN_SIZE: usize = XSOCKET_LAST_PID + 4;
    const XINPGEN_SIZE: usize = 24;
    const XSOCKET_OFFSET: usize = 104;
    const XINPCB_FOREIGN_PORT: usize = 16;
    const XINPCB_LOCAL_PORT: usize = 18;
    const XINPCB_VFLAG: usize = 44;
    const XINPCB_FOREIGN_ADDR: usize = 48;
    const XINPCB_LOCAL_ADDR: usize = 64;
    const XINPCB_IPV4_ADDR: usize = 12;
    const XSOCKET_UID: usize = 64;
    const XSOCKET_LAST_PID: usize = 68;
    const TCP_EXTRA_STRUCT_SIZE: usize = 208;

    #[derive(Debug, Clone, Copy)]
    struct ConnectionEntry {
        local: SocketAddr,
        remote: SocketAddr,
        pid: u32,
        uid: i32,
    }

    #[derive(Clone)]
    struct Snapshot {
        created_at: Instant,
        entries: Vec<ConnectionEntry>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct FlowKey {
        source: SocketAddr,
        destination: Option<SocketAddr>,
    }

    #[derive(Clone)]
    struct CachedProcess {
        created_at: Instant,
        process: ProcessInfo,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MatchKind {
        Exact,
        LocalFallback,
        WildcardFallback,
    }

    pub(super) struct NativeProcessResolver {
        snapshots: Mutex<HashMap<Network, Snapshot>>,
        udp_owners: Arc<Mutex<HashMap<FlowKey, CachedProcess>>>,
        /// Milliseconds since `clock_start` of the latest UDP lookup.
        udp_activity: Arc<AtomicU64>,
    }

    impl Default for NativeProcessResolver {
        fn default() -> Self {
            let udp_owners = Arc::new(Mutex::new(HashMap::new()));
            let udp_activity = Arc::new(AtomicU64::new(clock_millis()));
            start_udp_sampler(
                Arc::downgrade(&udp_owners),
                udp_activity.clone(),
            );
            Self {
                snapshots: Mutex::new(HashMap::new()),
                udp_owners,
                udp_activity,
            }
        }
    }

    fn clock_millis() -> u64 {
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_millis() as u64
    }

    impl NativeProcessResolver {
        fn snapshot(
            &self,
            network: Network,
            force_refresh: bool,
        ) -> io::Result<(Snapshot, bool)> {
            let mut snapshots = self
                .snapshots
                .lock()
                .expect("process snapshot lock poisoned");
            if !force_refresh
                && let Some(snapshot) = snapshots.get(&network)
                && snapshot.created_at.elapsed() < SNAPSHOT_TTL
            {
                return Ok((snapshot.clone(), true));
            }
            let snapshot = build_snapshot(network)?;
            snapshots.insert(network, snapshot.clone());
            Ok((snapshot, false))
        }

        fn cached_udp_owner(&self, key: FlowKey) -> Option<ProcessInfo> {
            let mut owners = self
                .udp_owners
                .lock()
                .expect("UDP process cache lock poisoned");
            owners
                .retain(|_, value| value.created_at.elapsed() < UDP_OWNER_TTL);
            owners
                .get(&key)
                .or_else(|| {
                    owners
                        .iter()
                        .filter(|(candidate, _)| {
                            candidate.source.port() == key.source.port()
                                && candidate.source.is_ipv4()
                                    == key.source.is_ipv4()
                                && (candidate.source.ip() == key.source.ip()
                                    || candidate.source.ip().is_unspecified())
                                && (candidate.destination == key.destination
                                    || candidate.destination.is_none())
                        })
                        .max_by_key(|(_, value)| value.created_at)
                        .map(|(_, value)| value)
                })
                .map(|value| value.process.clone())
        }

        fn remember_udp_owner(&self, key: FlowKey, process: &ProcessInfo) {
            let mut owners = self
                .udp_owners
                .lock()
                .expect("UDP process cache lock poisoned");
            remember_udp_owner_in(&mut owners, key, process);
        }

        fn lookup_native(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> ProcessLookupResult {
            if !matches!(network, Network::Tcp | Network::Udp) {
                return ProcessLookupResult {
                    process: None,
                    status: ProcessLookupStatus::SocketSnapshotMiss,
                };
            }
            if network == Network::Udp {
                self.udp_activity.store(clock_millis(), Ordering::Relaxed);
            }
            let source = normalize(source);
            let destination = destination.map(normalize);
            let key = FlowKey {
                source,
                destination,
            };
            let mut matched = None;
            for attempt in 0..2 {
                let (snapshot, from_cache) =
                    match self.snapshot(network, attempt > 0) {
                        Ok(snapshot) => snapshot,
                        Err(_) => {
                            return ProcessLookupResult {
                                process: None,
                                status: ProcessLookupStatus::ResolverError,
                            };
                        }
                    };
                let Some((entry, kind)) = match_entry(
                    &snapshot.entries,
                    network,
                    source,
                    destination,
                ) else {
                    // A socket can be created immediately after a cached
                    // pcblist snapshot. Refresh once instead of treating that
                    // ordinary race as an unknown process.
                    if from_cache {
                        continue;
                    }
                    break;
                };
                if from_cache && kind != MatchKind::Exact {
                    continue;
                }
                matched = Some(entry);
                break;
            }

            let Some(entry) = matched else {
                if network == Network::Udp
                    && let Some(process) = self.cached_udp_owner(key)
                {
                    return ProcessLookupResult {
                        process: Some(process),
                        status: ProcessLookupStatus::UdpCache,
                    };
                }
                return ProcessLookupResult {
                    process: None,
                    status: ProcessLookupStatus::SocketSnapshotMiss,
                };
            };
            let mut process = ProcessInfo {
                user: (entry.uid >= 0)
                    .then(|| super::lookup_username(entry.uid as u32))
                    .flatten()
                    .unwrap_or_default(),
                user_id: Some(entry.uid),
                ..ProcessInfo::default()
            };
            if entry.pid == 0 {
                return ProcessLookupResult {
                    process: None,
                    status: ProcessLookupStatus::KernelSocket,
                };
            }
            match process_path(entry.pid) {
                Ok(path) => {
                    process.process_name = Path::new(&path)
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    process.process_path = path;
                    if network == Network::Udp {
                        self.remember_udp_owner(key, &process);
                    }
                    ProcessLookupResult {
                        process: Some(process),
                        status: ProcessLookupStatus::Found,
                    }
                }
                Err(error) => ProcessLookupResult {
                    process: None,
                    status: match error.kind() {
                        io::ErrorKind::PermissionDenied => {
                            ProcessLookupStatus::PermissionDenied
                        }
                        _ => ProcessLookupStatus::ProcessExited,
                    },
                },
            }
        }
    }

    fn start_udp_sampler(
        udp_owners: Weak<Mutex<HashMap<FlowKey, CachedProcess>>>,
        udp_activity: Arc<AtomicU64>,
    ) {
        let _ = thread::Builder::new()
            .name("singbox-udp-process-sampler".into())
            .spawn(move || {
                let mut processes = HashMap::<u32, CachedProcess>::new();
                loop {
                    let Some(owners) = udp_owners.upgrade() else {
                        break;
                    };
                    if let Ok(snapshot) = build_snapshot(Network::Udp) {
                        processes.retain(|_, process| {
                            process.created_at.elapsed()
                                < UDP_SAMPLER_PROCESS_TTL
                        });
                        for entry in snapshot.entries {
                            if entry.pid == 0 {
                                continue;
                            }
                            let process = if let Some(cached) =
                                processes.get(&entry.pid)
                            {
                                Some(cached.process.clone())
                            } else {
                                let process = process_info(entry).ok();
                                if let Some(process) = process.as_ref() {
                                    processes.insert(
                                        entry.pid,
                                        CachedProcess {
                                            created_at: Instant::now(),
                                            process: process.clone(),
                                        },
                                    );
                                }
                                process
                            };
                            let Some(process) = process else {
                                continue;
                            };
                            let destination =
                                (!entry.remote.ip().is_unspecified()
                                    || entry.remote.port() != 0)
                                    .then(|| normalize(entry.remote));
                            let key = FlowKey {
                                source: normalize(entry.local),
                                destination,
                            };
                            let mut owners = owners
                                .lock()
                                .expect("UDP process cache lock poisoned");
                            remember_udp_owner_in(&mut owners, key, &process);
                        }
                    }
                    drop(owners);
                    let idle = clock_millis()
                        .saturating_sub(udp_activity.load(Ordering::Relaxed));
                    thread::sleep(
                        if idle < UDP_SAMPLER_ACTIVE_WINDOW.as_millis() as u64 {
                            UDP_SAMPLER_INTERVAL
                        } else {
                            UDP_SAMPLER_IDLE_INTERVAL
                        },
                    );
                }
            });
    }

    fn process_info(entry: ConnectionEntry) -> io::Result<ProcessInfo> {
        let path = process_path(entry.pid)?;
        Ok(ProcessInfo {
            process_name: Path::new(&path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            process_path: path,
            user: (entry.uid >= 0)
                .then(|| super::lookup_username(entry.uid as u32))
                .flatten()
                .unwrap_or_default(),
            user_id: Some(entry.uid),
            ..ProcessInfo::default()
        })
    }

    fn remember_udp_owner_in(
        owners: &mut HashMap<FlowKey, CachedProcess>,
        key: FlowKey,
        process: &ProcessInfo,
    ) {
        owners.retain(|_, value| value.created_at.elapsed() < UDP_OWNER_TTL);
        if owners.len() >= UDP_OWNER_CACHE_LIMIT
            && let Some(oldest) = owners
                .iter()
                .min_by_key(|(_, value)| value.created_at)
                .map(|(key, _)| *key)
        {
            owners.remove(&oldest);
        }
        owners.insert(
            key,
            CachedProcess {
                created_at: Instant::now(),
                process: process.clone(),
            },
        );
    }

    impl ProcessResolver for NativeProcessResolver {
        fn lookup(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> Option<ProcessInfo> {
            self.lookup_native(network, source, destination).process
        }

        fn lookup_detailed(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> ProcessLookupResult {
            self.lookup_native(network, source, destination)
        }
    }

    fn build_snapshot(network: Network) -> io::Result<Snapshot> {
        let name = match network {
            Network::Tcp => "net.inet.tcp.pcblist_n",
            Network::Udp => "net.inet.udp.pcblist_n",
            Network::Icmp => return Err(io::ErrorKind::InvalidInput.into()),
        };
        let bytes = sysctl_raw(name)?;
        let mut entries = parse_snapshot(&bytes);
        if entries.is_empty() {
            // Keep the fixed-layout reader as a safety net for a kernel
            // whose records do not carry the expected kind tags.
            let struct_size = darwin_struct_size()?;
            let item_size = match network {
                Network::Tcp => struct_size + TCP_EXTRA_STRUCT_SIZE,
                _ => struct_size,
            };
            entries = parse_fixed_snapshot(&bytes, item_size, struct_size);
        }
        Ok(Snapshot {
            created_at: Instant::now(),
            entries,
        })
    }

    fn darwin_struct_size() -> io::Result<usize> {
        let release = sysctl_raw("kern.osrelease")?;
        let release = std::str::from_utf8(
            release.split(|byte| *byte == 0).next().unwrap_or_default(),
        )
        .map_err(io::Error::other)?;
        let major = release
            .split('.')
            .next()
            .unwrap_or_default()
            .parse::<u32>()
            .map_err(io::Error::other)?;
        Ok(if major >= 22 { 408 } else { 384 })
    }

    fn sysctl_raw(name: &str) -> io::Result<Vec<u8>> {
        let name = CString::new(name).map_err(io::Error::other)?;
        let mut length = 0usize;
        if unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                ptr::null_mut(),
                &mut length,
                ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut bytes = vec![0u8; length];
        if unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                &mut length,
                ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        bytes.truncate(length);
        Ok(bytes)
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
        let end = offset.checked_add(4)?;
        Some(u32::from_ne_bytes(bytes.get(offset..end)?.try_into().ok()?))
    }

    /// Walk the self-describing `pcblist_n` records.
    ///
    /// Every record starts with its own length and kind, so pairing each
    /// `xinpcb_n` with the `xsocket_n` that follows it needs no knowledge of
    /// how large the surrounding per-socket block is on this kernel.
    fn parse_snapshot(bytes: &[u8]) -> Vec<ConnectionEntry> {
        let mut entries = Vec::new();
        let Some(header) = read_u32(bytes, 0) else {
            return entries;
        };
        let mut offset = (header as usize).max(XINPGEN_SIZE);
        let mut pcb = None;
        while let (Some(length), Some(kind)) =
            (read_u32(bytes, offset), read_u32(bytes, offset + 4))
        {
            let length = length as usize;
            let Some(record) = offset
                .checked_add(length)
                .filter(|_| length >= 8)
                .and_then(|end| bytes.get(offset..end))
            else {
                break;
            };
            match kind {
                XSO_INPCB if length >= XINPCB_MIN_SIZE => pcb = Some(record),
                XSO_SOCKET if length >= XSOCKET_MIN_SIZE => {
                    if let Some(pcb) = pcb.take()
                        && let Some(entry) = parse_entry(pcb, record)
                    {
                        entries.push(entry);
                    }
                }
                _ => {}
            }
            // Records are padded to an 8-byte boundary.
            offset += (length + 7) & !7;
        }
        entries
    }

    fn parse_fixed_snapshot(
        bytes: &[u8],
        item_size: usize,
        struct_size: usize,
    ) -> Vec<ConnectionEntry> {
        if item_size == 0
            || bytes.len() < XINPGEN_SIZE
            || struct_size < XSOCKET_OFFSET + XSOCKET_MIN_SIZE
        {
            return Vec::new();
        }
        (XINPGEN_SIZE..bytes.len())
            .step_by(item_size)
            .filter_map(|offset| {
                let item = bytes.get(offset..offset.checked_add(item_size)?)?;
                parse_entry(
                    item.get(..XSOCKET_OFFSET)?,
                    item.get(XSOCKET_OFFSET..struct_size)?,
                )
            })
            .collect()
    }

    fn parse_entry(pcb: &[u8], socket: &[u8]) -> Option<ConnectionEntry> {
        if pcb.len() < XINPCB_MIN_SIZE || socket.len() < XSOCKET_MIN_SIZE {
            return None;
        }
        let vflag = pcb[XINPCB_VFLAG];
        let (local_ip, remote_ip) = if vflag & 0x1 != 0 {
            let local: [u8; 4] = pcb[XINPCB_LOCAL_ADDR + XINPCB_IPV4_ADDR..]
                [..4]
                .try_into()
                .ok()?;
            let remote: [u8; 4] = pcb[XINPCB_FOREIGN_ADDR + XINPCB_IPV4_ADDR..]
                [..4]
                .try_into()
                .ok()?;
            (
                IpAddr::V4(Ipv4Addr::from(local)),
                IpAddr::V4(Ipv4Addr::from(remote)),
            )
        } else if vflag & 0x2 != 0 {
            let local: [u8; 16] =
                pcb[XINPCB_LOCAL_ADDR..][..16].try_into().ok()?;
            let remote: [u8; 16] =
                pcb[XINPCB_FOREIGN_ADDR..][..16].try_into().ok()?;
            (
                IpAddr::V6(Ipv6Addr::from(local)),
                IpAddr::V6(Ipv6Addr::from(remote)),
            )
        } else {
            return None;
        };
        Some(ConnectionEntry {
            local: SocketAddr::new(
                local_ip,
                u16::from_be_bytes(
                    pcb[XINPCB_LOCAL_PORT..][..2].try_into().ok()?,
                ),
            ),
            remote: SocketAddr::new(
                remote_ip,
                u16::from_be_bytes(
                    pcb[XINPCB_FOREIGN_PORT..][..2].try_into().ok()?,
                ),
            ),
            pid: u32::from_ne_bytes(
                socket[XSOCKET_LAST_PID..][..4].try_into().ok()?,
            ),
            uid: u32::from_ne_bytes(socket[XSOCKET_UID..][..4].try_into().ok()?)
                as i32,
        })
    }

    fn match_entry(
        entries: &[ConnectionEntry],
        network: Network,
        source: SocketAddr,
        destination: Option<SocketAddr>,
    ) -> Option<(ConnectionEntry, MatchKind)> {
        let mut local = None;
        let mut wildcard = None;
        for entry in entries.iter().copied() {
            if entry.local.port() != source.port()
                || entry.local.is_ipv4() != source.is_ipv4()
            {
                continue;
            }
            if entry.local == source
                && destination
                    .is_some_and(|destination| entry.remote == destination)
            {
                return Some((entry, MatchKind::Exact));
            }
            if destination.is_none() && entry.local == source {
                return Some((entry, MatchKind::Exact));
            }
            // A proxy client is connected to the inbound rather than to the
            // routed destination, so its own endpoint is the only key left.
            if local.is_none() && entry.local == source {
                local = Some(entry);
            }
            if network == Network::Udp
                && wildcard.is_none()
                && entry.local.ip().is_unspecified()
            {
                wildcard = Some(entry);
            }
        }
        local
            .map(|entry| (entry, MatchKind::LocalFallback))
            .or_else(|| {
                wildcard.map(|entry| (entry, MatchKind::WildcardFallback))
            })
    }

    fn normalize(address: SocketAddr) -> SocketAddr {
        match address {
            SocketAddr::V6(address) => address
                .ip()
                .to_ipv4_mapped()
                .map(|ip| SocketAddr::new(IpAddr::V4(ip), address.port()))
                .unwrap_or(SocketAddr::V6(address)),
            address => address,
        }
    }

    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidpath(
            pid: libc::c_int,
            buffer: *mut libc::c_void,
            buffer_size: u32,
        ) -> libc::c_int;
    }

    fn process_path(pid: u32) -> io::Result<String> {
        let mut bytes = vec![0u8; 1024];
        let length = unsafe {
            proc_pidpath(pid as libc::c_int, bytes.as_mut_ptr().cast(), 1024)
        };
        if length <= 0 {
            return Err(io::Error::last_os_error());
        }
        bytes.truncate(length as usize);
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub(super) fn resolver() -> Arc<dyn ProcessResolver> {
        Arc::new(NativeProcessResolver::default())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn matches_exact_and_udp_fallback_entries() {
            let exact = ConnectionEntry {
                local: "127.0.0.1:1000".parse().unwrap(),
                remote: "127.0.0.1:2000".parse().unwrap(),
                pid: 1,
                uid: 2,
            };
            let wildcard = ConnectionEntry {
                local: "0.0.0.0:1000".parse().unwrap(),
                remote: "0.0.0.0:0".parse().unwrap(),
                pid: 3,
                uid: 4,
            };
            assert_eq!(
                match_entry(
                    &[wildcard, exact],
                    Network::Tcp,
                    exact.local,
                    Some(exact.remote)
                )
                .unwrap()
                .1,
                MatchKind::Exact
            );
            assert_eq!(
                match_entry(
                    &[wildcard],
                    Network::Udp,
                    "127.0.0.1:1000".parse().unwrap(),
                    None
                )
                .unwrap()
                .1,
                MatchKind::WildcardFallback
            );
            // A proxied TCP client is keyed by its own endpoint only, and a
            // TCP flow never borrows a wildcard listener.
            assert_eq!(
                match_entry(
                    &[wildcard, exact],
                    Network::Tcp,
                    exact.local,
                    Some("203.0.113.9:443".parse().unwrap())
                )
                .unwrap()
                .1,
                MatchKind::LocalFallback
            );
            assert!(
                match_entry(
                    &[wildcard],
                    Network::Tcp,
                    exact.local,
                    Some(exact.remote)
                )
                .is_none()
            );
        }

        fn record(kind: u32, length: usize) -> Vec<u8> {
            let mut record = vec![0u8; (length + 7) & !7];
            record[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
            record[4..8].copy_from_slice(&kind.to_ne_bytes());
            record
        }

        #[test]
        fn walks_tagged_records_of_any_block_size() {
            let mut header = vec![0u8; XINPGEN_SIZE];
            header[0..4].copy_from_slice(&(XINPGEN_SIZE as u32).to_ne_bytes());
            let mut pcb = record(XSO_INPCB, 104);
            pcb[XINPCB_VFLAG] = 0x1;
            pcb[XINPCB_LOCAL_PORT..][..2]
                .copy_from_slice(&1000u16.to_be_bytes());
            pcb[XINPCB_FOREIGN_PORT..][..2]
                .copy_from_slice(&443u16.to_be_bytes());
            pcb[XINPCB_LOCAL_ADDR + XINPCB_IPV4_ADDR..][..4]
                .copy_from_slice(&[10, 0, 0, 2]);
            pcb[XINPCB_FOREIGN_ADDR + XINPCB_IPV4_ADDR..][..4]
                .copy_from_slice(&[1, 1, 1, 1]);
            // A socket record longer than any released kernel uses.
            let mut socket = record(XSO_SOCKET, 131);
            socket[XSOCKET_UID..][..4].copy_from_slice(&501u32.to_ne_bytes());
            socket[XSOCKET_LAST_PID..][..4]
                .copy_from_slice(&4242u32.to_ne_bytes());
            let mut bytes = header.clone();
            for _ in 0..2 {
                bytes.extend(&pcb);
                bytes.extend(&socket);
                bytes.extend(record(0x002, 28));
                bytes.extend(record(0x008, 60));
            }
            // The trailing xinpgen reuses the kind slot for a socket count.
            let mut trailer = header;
            trailer[4..8].copy_from_slice(&XSO_INPCB.to_ne_bytes());
            bytes.extend(trailer);

            let entries = parse_snapshot(&bytes);
            let address = |text: &str| text.parse::<SocketAddr>().unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[1].local, address("10.0.0.2:1000"));
            assert_eq!(entries[1].remote, address("1.1.1.1:443"));
            assert_eq!(entries[1].pid, 4242);
            assert_eq!(entries[1].uid, 501);
        }

        #[test]
        fn native_resolver_finds_current_tcp_process() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let destination = listener.local_addr().unwrap();
            let client = std::net::TcpStream::connect(destination).unwrap();
            let source = client.local_addr().unwrap();
            let _server = listener.accept().unwrap().0;
            let process = NativeProcessResolver::default()
                .lookup(Network::Tcp, source, Some(destination))
                .expect("current TCP connection owner");
            assert_eq!(
                process.user_id,
                Some(unsafe { libc::geteuid() } as i32)
            );
            assert!(!process.process_path.is_empty());
        }

        #[test]
        fn cached_udp_snapshot_miss_forces_refresh() {
            let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let destination = server.local_addr().unwrap();
            let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            client.connect(destination).unwrap();
            client.send(b"probe").unwrap();
            let source = client.local_addr().unwrap();

            let resolver = NativeProcessResolver::default();
            resolver.snapshots.lock().unwrap().insert(
                Network::Udp,
                Snapshot {
                    created_at: Instant::now(),
                    entries: Vec::new(),
                },
            );
            let result = resolver.lookup_detailed(
                Network::Udp,
                source,
                Some(destination),
            );
            assert_eq!(result.status, ProcessLookupStatus::Found);
            assert!(!result.process.unwrap().process_path.is_empty());
        }

        #[test]
        fn remembers_udp_owner_by_full_flow_tuple() {
            let resolver = NativeProcessResolver::default();
            let key = FlowKey {
                source: "127.0.0.1:1000".parse().unwrap(),
                destination: Some("127.0.0.1:2000".parse().unwrap()),
            };
            let process = ProcessInfo {
                process_name: "client".into(),
                process_path: "/tmp/client".into(),
                ..ProcessInfo::default()
            };
            resolver.remember_udp_owner(key, &process);
            assert_eq!(resolver.cached_udp_owner(key), Some(process));
            assert_eq!(
                resolver.cached_udp_owner(FlowKey {
                    destination: Some("127.0.0.1:2001".parse().unwrap()),
                    ..key
                }),
                None
            );
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{
        collections::{HashMap, VecDeque},
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::fs::MetadataExt as _,
        },
        path::Path,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU32, Ordering},
        },
        time::{Duration, Instant},
    };

    use super::normalize;
    use crate::{
        adapter::{
            ProcessInfo, ProcessLookupResult, ProcessLookupStatus,
            ProcessResolver,
        },
        common::network::Network,
    };

    const SOCKET_DIAG_BY_FAMILY: u16 = 20;
    const NETLINK_HEADER_SIZE: usize = 16;
    const REQUEST_SIZE: usize = 72;
    const RESPONSE_MIN_SIZE: usize = 72;
    // The kernel queues sock_diag replies before the request write returns,
    // so this only bounds an anomaly instead of pacing normal lookups.
    const SOCKET_DIAG_TIMEOUT_MICROS: i32 = 10_000;
    const SOCKET_DIAG_MAX_READS: usize = 64;
    const INODE_CACHE_TTL: Duration = Duration::from_secs(1);
    const INODE_CACHE_CAPACITY: usize = 1024;
    const RECENT_PIDS_PER_UID: usize = 8;
    const RECENT_UID_CAPACITY: usize = 64;
    const DELETED_SUFFIX: &str = " (deleted)";

    static SEQUENCE: AtomicU32 = AtomicU32::new(1);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct SocketOwner {
        inode: u32,
        uid: u32,
    }

    #[derive(Debug, Clone, Copy)]
    struct DiagSocket {
        local: SocketAddr,
        remote: SocketAddr,
        owner: SocketOwner,
    }

    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct ReplyProgress {
        answered: bool,
        done: bool,
    }

    enum PathLookup {
        Found(String),
        NotFound,
        PermissionDenied,
    }

    #[derive(Default)]
    struct ProcessScan {
        found: Option<(u32, String)>,
        denied: bool,
    }

    struct SocketDiagConn {
        family: u8,
        protocol: u8,
        fd: Mutex<Option<OwnedFd>>,
    }

    impl SocketDiagConn {
        fn new(family: u8, protocol: u8) -> Self {
            Self {
                family,
                protocol,
                fd: Mutex::new(None),
            }
        }

        fn query(
            &self,
            source: SocketAddr,
            destination: SocketAddr,
        ) -> io::Result<Option<SocketOwner>> {
            let mut fd = self.fd.lock().expect("socket diag lock poisoned");
            let mut last_error = None;
            for _ in 0..2 {
                if fd.is_none() {
                    *fd = Some(open_socket_diag()?);
                }
                let sequence = next_sequence();
                let request = pack_request(
                    self.family,
                    self.protocol,
                    source,
                    Some(destination),
                    false,
                    sequence,
                );
                match query_socket_diag(
                    fd.as_ref().unwrap(),
                    &request,
                    sequence,
                    false,
                ) {
                    Ok(sockets) => {
                        return Ok(sockets.first().map(|socket| socket.owner));
                    }
                    Err(error) => {
                        last_error = Some(error);
                        fd.take();
                    }
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::other("socket diag query failed")
            }))
        }
    }

    /// Recent socket-owner answers. A new connection always has a new inode,
    /// so the inode map only serves repeated lookups of one socket; the
    /// recent PID list is what keeps a busy process from costing a full
    /// `/proc` walk per connection.
    #[derive(Default)]
    struct ProcessPathCache {
        inodes: HashMap<(u32, u32), (Instant, String)>,
        recent_pids: HashMap<u32, VecDeque<u32>>,
    }

    impl ProcessPathCache {
        fn remember(&mut self, owner: SocketOwner, pid: u32, path: &str) {
            if self.inodes.len() >= INODE_CACHE_CAPACITY {
                self.inodes.retain(|_, (created_at, _)| {
                    created_at.elapsed() < INODE_CACHE_TTL
                });
                if self.inodes.len() >= INODE_CACHE_CAPACITY {
                    self.inodes.clear();
                }
            }
            self.inodes.insert(
                (owner.uid, owner.inode),
                (Instant::now(), path.to_owned()),
            );
            if !self.recent_pids.contains_key(&owner.uid)
                && self.recent_pids.len() >= RECENT_UID_CAPACITY
            {
                self.recent_pids.clear();
            }
            let recent = self.recent_pids.entry(owner.uid).or_default();
            recent.retain(|candidate| *candidate != pid);
            recent.push_front(pid);
            recent.truncate(RECENT_PIDS_PER_UID);
        }
    }

    pub(super) struct NativeProcessResolver {
        diag: [SocketDiagConn; 4],
        process_paths: Mutex<ProcessPathCache>,
    }

    impl Default for NativeProcessResolver {
        fn default() -> Self {
            Self {
                diag: [
                    SocketDiagConn::new(
                        libc::AF_INET as u8,
                        libc::IPPROTO_TCP as u8,
                    ),
                    SocketDiagConn::new(
                        libc::AF_INET6 as u8,
                        libc::IPPROTO_TCP as u8,
                    ),
                    SocketDiagConn::new(
                        libc::AF_INET as u8,
                        libc::IPPROTO_UDP as u8,
                    ),
                    SocketDiagConn::new(
                        libc::AF_INET6 as u8,
                        libc::IPPROTO_UDP as u8,
                    ),
                ],
                process_paths: Mutex::new(ProcessPathCache::default()),
            }
        }
    }

    impl NativeProcessResolver {
        fn resolve_socket(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> io::Result<Option<SocketOwner>> {
            let (family, protocol) = socket_diag_settings(network, source)?;
            let mut last_error = None;
            if let Some(destination) = destination
                && source.is_ipv4() == destination.is_ipv4()
            {
                let conn = &self.diag[socket_diag_index(family, protocol)];
                match conn.query(source, destination) {
                    Ok(Some(owner)) => return Ok(Some(owner)),
                    Ok(None) => {}
                    // A failed exact query must not hide a socket the dump
                    // can still find.
                    Err(error) => last_error = Some(error),
                }
            }
            // An IPv4 flow can belong to a dual-stack IPv6 socket, which an
            // AF_INET dump does not list.
            let families = [
                Some(family),
                (family == libc::AF_INET as u8).then_some(libc::AF_INET6 as u8),
            ];
            let mut dumped = false;
            for family in families.into_iter().flatten() {
                match dump_sockets(family, protocol, source) {
                    Ok(sockets) => {
                        dumped = true;
                        if let Some(owner) =
                            select_dump_owner(&sockets, source, destination)
                        {
                            return Ok(Some(owner));
                        }
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            match last_error {
                Some(error) if !dumped => Err(error),
                _ => Ok(None),
            }
        }

        fn find_process_path(&self, owner: SocketOwner) -> PathLookup {
            let recent = {
                let cache = self
                    .process_paths
                    .lock()
                    .expect("process path cache lock poisoned");
                if let Some((created_at, path)) =
                    cache.inodes.get(&(owner.uid, owner.inode))
                    && created_at.elapsed() < INODE_CACHE_TTL
                {
                    return PathLookup::Found(path.clone());
                }
                cache
                    .recent_pids
                    .get(&owner.uid)
                    .cloned()
                    .unwrap_or_default()
            };
            let proc_root = Path::new("/proc");
            let mut denied = false;
            let mut found = recent.iter().find_map(|pid| {
                socket_owner_path(&proc_root.join(pid.to_string()), owner.inode)
                    .ok()
                    .flatten()
                    .map(|path| (*pid, path))
            });
            if found.is_none() {
                // A non-dumpable process keeps the socket's UID but exposes a
                // root-owned /proc entry, so root is the second candidate.
                let uids = [Some(owner.uid), (owner.uid != 0).then_some(0)];
                for uid in uids.into_iter().flatten() {
                    let scan = scan_processes(proc_root, uid, owner.inode);
                    denied |= scan.denied;
                    if scan.found.is_some() {
                        found = scan.found;
                        break;
                    }
                }
            }
            let Some((pid, path)) = found else {
                return if denied {
                    PathLookup::PermissionDenied
                } else {
                    PathLookup::NotFound
                };
            };
            self.process_paths
                .lock()
                .expect("process path cache lock poisoned")
                .remember(owner, pid, &path);
            PathLookup::Found(path)
        }

        fn lookup_native(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> ProcessLookupResult {
            let miss = |status| ProcessLookupResult {
                process: None,
                status,
            };
            if !matches!(network, Network::Tcp | Network::Udp) {
                return miss(ProcessLookupStatus::SocketSnapshotMiss);
            }
            let source = normalize(source);
            let destination = destination.map(normalize);
            let owner = match self.resolve_socket(network, source, destination)
            {
                Ok(Some(owner)) => owner,
                Ok(None) => {
                    return miss(ProcessLookupStatus::SocketSnapshotMiss);
                }
                Err(_) => return miss(ProcessLookupStatus::ResolverError),
            };
            // The socket's UID is known even when its process is not, and
            // user rules only need the UID.
            let mut process = ProcessInfo {
                user: super::lookup_username(owner.uid).unwrap_or_default(),
                user_id: Some(owner.uid as i32),
                ..ProcessInfo::default()
            };
            let status = match self.find_process_path(owner) {
                PathLookup::Found(path) => {
                    process.process_name = Path::new(&path)
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    process.process_path = path;
                    ProcessLookupStatus::Found
                }
                PathLookup::NotFound => ProcessLookupStatus::ProcessExited,
                PathLookup::PermissionDenied => {
                    ProcessLookupStatus::PermissionDenied
                }
            };
            ProcessLookupResult {
                process: Some(process),
                status,
            }
        }
    }

    impl ProcessResolver for NativeProcessResolver {
        fn lookup(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> Option<ProcessInfo> {
            self.lookup_native(network, source, destination).process
        }

        fn lookup_detailed(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> ProcessLookupResult {
            self.lookup_native(network, source, destination)
        }
    }

    fn next_sequence() -> u32 {
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    }

    fn socket_diag_settings(
        network: Network,
        source: SocketAddr,
    ) -> io::Result<(u8, u8)> {
        let protocol = match network {
            Network::Tcp => libc::IPPROTO_TCP as u8,
            Network::Udp => libc::IPPROTO_UDP as u8,
            Network::Icmp => return Err(io::ErrorKind::InvalidInput.into()),
        };
        let family = if source.is_ipv4() {
            libc::AF_INET as u8
        } else {
            libc::AF_INET6 as u8
        };
        Ok((family, protocol))
    }

    fn socket_diag_index(family: u8, protocol: u8) -> usize {
        usize::from(protocol == libc::IPPROTO_UDP as u8) * 2
            + usize::from(family == libc::AF_INET6 as u8)
    }

    fn open_socket_diag() -> io::Result<OwnedFd> {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::NETLINK_INET_DIAG,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: SOCKET_DIAG_TIMEOUT_MICROS as _,
        };
        for option in [libc::SO_SNDTIMEO, libc::SO_RCVTIMEO] {
            let result = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&raw const timeout).cast(),
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let result = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&raw const address).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    fn pack_request(
        family: u8,
        protocol: u8,
        source: SocketAddr,
        destination: Option<SocketAddr>,
        dump: bool,
        sequence: u32,
    ) -> [u8; REQUEST_SIZE] {
        let mut request = [0u8; REQUEST_SIZE];
        request[0..4].copy_from_slice(&(REQUEST_SIZE as u32).to_ne_bytes());
        request[4..6].copy_from_slice(&SOCKET_DIAG_BY_FAMILY.to_ne_bytes());
        let mut flags = libc::NLM_F_REQUEST as u16;
        if dump {
            flags |= libc::NLM_F_DUMP as u16;
        }
        request[6..8].copy_from_slice(&flags.to_ne_bytes());
        request[8..12].copy_from_slice(&sequence.to_ne_bytes());
        request[16] = family;
        request[17] = protocol;
        if dump {
            request[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
        }
        let (request_source, request_destination) =
            if protocol == libc::IPPROTO_UDP as u8 && !dump {
                (destination.unwrap_or(source), Some(source))
            } else {
                (source, destination)
            };
        request[24..26].copy_from_slice(&request_source.port().to_be_bytes());
        request[26..28].copy_from_slice(
            &request_destination
                .map_or(0, |destination| destination.port())
                .to_be_bytes(),
        );
        // A dump filters on ports only; a v4 source has no meaningful
        // address in a dual-stack AF_INET6 dump request.
        if !dump {
            write_ip(&mut request[28..44], request_source.ip());
            if let Some(destination) = request_destination {
                write_ip(&mut request[44..60], destination.ip());
            }
        }
        request[64..72].copy_from_slice(&u64::MAX.to_ne_bytes());
        request
    }

    fn write_ip(output: &mut [u8], address: IpAddr) {
        match address {
            IpAddr::V4(address) => {
                output[..4].copy_from_slice(&address.octets())
            }
            IpAddr::V6(address) => output.copy_from_slice(&address.octets()),
        }
    }

    fn dump_sockets(
        family: u8,
        protocol: u8,
        source: SocketAddr,
    ) -> io::Result<Vec<DiagSocket>> {
        let fd = open_socket_diag()?;
        let sequence = next_sequence();
        query_socket_diag(
            &fd,
            &pack_request(family, protocol, source, None, true, sequence),
            sequence,
            true,
        )
    }

    /// Pick the dumped socket that can have sent `source -> destination`.
    ///
    /// The kernel only filters a dump by port, so the local address is
    /// checked here: a socket bound to another address never owns the flow.
    fn select_dump_owner(
        sockets: &[DiagSocket],
        source: SocketAddr,
        destination: Option<SocketAddr>,
    ) -> Option<SocketOwner> {
        let mut best: Option<(u8, SocketOwner)> = None;
        for socket in sockets {
            if socket.local.port() != source.port() {
                continue;
            }
            let mut score = if socket.local.ip() == source.ip() {
                2
            } else if socket.local.ip().is_unspecified() {
                1
            } else {
                continue;
            };
            // A proxy client is connected to the inbound, not to the routed
            // destination, so a different peer only loses the bonus.
            if destination
                .is_some_and(|destination| socket.remote == destination)
            {
                score += 2;
            }
            if best.is_none_or(|(current, _)| score > current) {
                best = Some((score, socket.owner));
            }
        }
        best.map(|(_, owner)| owner)
    }

    fn query_socket_diag(
        fd: &OwnedFd,
        request: &[u8],
        sequence: u32,
        dump: bool,
    ) -> io::Result<Vec<DiagSocket>> {
        let written = unsafe {
            libc::write(fd.as_raw_fd(), request.as_ptr().cast(), request.len())
        };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if written as usize != request.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let mut sockets = Vec::new();
        let mut response = vec![0u8; 64 << 10];
        for _ in 0..SOCKET_DIAG_MAX_READS {
            let read = unsafe {
                libc::read(
                    fd.as_raw_fd(),
                    response.as_mut_ptr().cast(),
                    response.len(),
                )
            };
            if read < 0 {
                return Err(io::Error::last_os_error());
            }
            let progress = unpack_messages(
                &response[..read as usize],
                sequence,
                &mut sockets,
            )?;
            // A dump ends with NLMSG_DONE; a single query has one reply.
            if progress.done || (!dump && progress.answered) {
                return Ok(sockets);
            }
        }
        Err(io::Error::other("socket diag reply did not terminate"))
    }

    /// Collect the sockets answering `sequence`.
    ///
    /// A reply that arrives after its query timed out stays queued on the
    /// reused netlink socket; matching the sequence keeps it from being read
    /// as the owner of a later flow.
    fn unpack_messages(
        bytes: &[u8],
        sequence: u32,
        sockets: &mut Vec<DiagSocket>,
    ) -> io::Result<ReplyProgress> {
        let mut progress = ReplyProgress::default();
        let mut offset = 0usize;
        while offset + NETLINK_HEADER_SIZE <= bytes.len() {
            let length = u32::from_ne_bytes(
                bytes[offset..offset + 4].try_into().unwrap(),
            ) as usize;
            if length < NETLINK_HEADER_SIZE || offset + length > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid netlink message length",
                ));
            }
            let message_type = u16::from_ne_bytes(
                bytes[offset + 4..offset + 6].try_into().unwrap(),
            );
            let message_sequence = u32::from_ne_bytes(
                bytes[offset + 8..offset + 12].try_into().unwrap(),
            );
            let data = &bytes[offset + NETLINK_HEADER_SIZE..offset + length];
            offset += (length + 3) & !3;
            if message_sequence != sequence {
                continue;
            }
            progress.answered = true;
            if message_type == libc::NLMSG_DONE as u16 {
                progress.done = true;
                break;
            }
            if message_type == libc::NLMSG_ERROR as u16 {
                if data.len() < 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short netlink error message",
                    ));
                }
                let errno = i32::from_ne_bytes(data[..4].try_into().unwrap());
                if errno != 0 {
                    let errno = errno.unsigned_abs() as i32;
                    if matches!(errno, libc::ENOENT | libc::ESRCH) {
                        progress.done = true;
                        break;
                    }
                    return Err(io::Error::from_raw_os_error(errno));
                }
            } else if message_type == SOCKET_DIAG_BY_FAMILY
                && let Some(socket) = parse_diag_socket(data)
                && (socket.owner.inode != 0 || socket.owner.uid != 0)
            {
                sockets.push(socket);
            }
        }
        Ok(progress)
    }

    fn parse_diag_socket(data: &[u8]) -> Option<DiagSocket> {
        if data.len() < RESPONSE_MIN_SIZE {
            return None;
        }
        let address = |bytes: &[u8]| match i32::from(data[0]) {
            libc::AF_INET => {
                let octets: [u8; 4] = bytes[..4].try_into().ok()?;
                Some(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            libc::AF_INET6 => {
                let octets: [u8; 16] = bytes[..16].try_into().ok()?;
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        };
        let port = |bytes: &[u8]| {
            Some(u16::from_be_bytes(bytes[..2].try_into().ok()?))
        };
        Some(DiagSocket {
            local: normalize(SocketAddr::new(
                address(&data[8..24])?,
                port(&data[4..6])?,
            )),
            remote: normalize(SocketAddr::new(
                address(&data[24..40])?,
                port(&data[6..8])?,
            )),
            owner: SocketOwner {
                uid: u32::from_ne_bytes(data[64..68].try_into().ok()?),
                inode: u32::from_ne_bytes(data[68..72].try_into().ok()?),
            },
        })
    }

    fn scan_processes(proc_root: &Path, uid: u32, inode: u32) -> ProcessScan {
        let mut scan = ProcessScan::default();
        let Ok(entries) = std::fs::read_dir(proc_root) else {
            return scan;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) =
                name.to_str().and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_dir() || metadata.uid() != uid {
                continue;
            }
            match socket_owner_path(&entry.path(), inode) {
                Ok(Some(path)) => {
                    scan.found = Some((pid, path));
                    break;
                }
                Ok(None) => {}
                Err(error) => {
                    scan.denied |=
                        error.kind() == io::ErrorKind::PermissionDenied;
                }
            }
        }
        scan
    }

    /// Return the executable of `process_root` if it holds socket `inode`.
    fn socket_owner_path(
        process_root: &Path,
        inode: u32,
    ) -> io::Result<Option<String>> {
        let descriptors = match std::fs::read_dir(process_root.join("fd")) {
            Ok(descriptors) => descriptors,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        for descriptor in descriptors.flatten() {
            let Ok(link) = std::fs::read_link(descriptor.path()) else {
                continue;
            };
            if parse_socket_inode(&link) != Some(inode) {
                continue;
            }
            return match std::fs::read_link(process_root.join("exe")) {
                Ok(path) => Ok(Some(executable_path(&path))),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    Ok(None)
                }
                Err(error) => Err(error),
            };
        }
        Ok(None)
    }

    /// The kernel appends a marker once the running binary is replaced on
    /// disk; rules are written against the path the process was started from.
    fn executable_path(link: &Path) -> String {
        let path = link.to_string_lossy();
        path.strip_suffix(DELETED_SUFFIX)
            .unwrap_or(&path)
            .to_owned()
    }

    fn parse_socket_inode(link: &Path) -> Option<u32> {
        let link = link.as_os_str().to_string_lossy();
        link.strip_prefix("socket:[")?
            .strip_suffix(']')?
            .parse()
            .ok()
    }

    pub(super) fn resolver() -> Arc<dyn ProcessResolver> {
        Arc::new(NativeProcessResolver::default())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn diag_message(
            sequence: u32,
            family: u8,
            local: SocketAddr,
            remote: SocketAddr,
            owner: SocketOwner,
        ) -> Vec<u8> {
            let mut message = vec![0u8; NETLINK_HEADER_SIZE + 72];
            let length = message.len() as u32;
            message[0..4].copy_from_slice(&length.to_ne_bytes());
            message[4..6].copy_from_slice(&SOCKET_DIAG_BY_FAMILY.to_ne_bytes());
            message[8..12].copy_from_slice(&sequence.to_ne_bytes());
            let data = &mut message[NETLINK_HEADER_SIZE..];
            data[0] = family;
            data[4..6].copy_from_slice(&local.port().to_be_bytes());
            data[6..8].copy_from_slice(&remote.port().to_be_bytes());
            write_ip(&mut data[8..24], local.ip());
            write_ip(&mut data[24..40], remote.ip());
            data[64..68].copy_from_slice(&owner.uid.to_ne_bytes());
            data[68..72].copy_from_slice(&owner.inode.to_ne_bytes());
            message
        }

        fn socket(local: &str, remote: &str, inode: u32) -> DiagSocket {
            DiagSocket {
                local: local.parse().unwrap(),
                remote: remote.parse().unwrap(),
                owner: SocketOwner { inode, uid: 1000 },
            }
        }

        #[test]
        fn packs_exact_and_dump_socket_diag_requests() {
            let source: SocketAddr = "127.0.0.1:1234".parse().unwrap();
            let destination: SocketAddr = "127.0.0.2:4321".parse().unwrap();
            let tcp = pack_request(
                libc::AF_INET as u8,
                libc::IPPROTO_TCP as u8,
                source,
                Some(destination),
                false,
                7,
            );
            assert_eq!(&tcp[8..12], &7u32.to_ne_bytes());
            assert_eq!(&tcp[24..26], &1234u16.to_be_bytes());
            assert_eq!(&tcp[26..28], &4321u16.to_be_bytes());
            assert_eq!(&tcp[28..32], &[127, 0, 0, 1]);
            assert_eq!(&tcp[44..48], &[127, 0, 0, 2]);

            let udp = pack_request(
                libc::AF_INET as u8,
                libc::IPPROTO_UDP as u8,
                source,
                Some(destination),
                false,
                8,
            );
            assert_eq!(&udp[24..26], &4321u16.to_be_bytes());
            assert_eq!(&udp[26..28], &1234u16.to_be_bytes());

            let dump = pack_request(
                libc::AF_INET as u8,
                libc::IPPROTO_TCP as u8,
                source,
                None,
                true,
                9,
            );
            assert_eq!(&dump[20..24], &u32::MAX.to_ne_bytes());
            assert_eq!(&dump[24..26], &1234u16.to_be_bytes());
            assert_eq!(&dump[26..28], &[0, 0]);
            assert_eq!(&dump[28..44], &[0u8; 16]);
        }

        #[test]
        fn ignores_replies_to_an_earlier_query() {
            let local: SocketAddr = "127.0.0.1:1234".parse().unwrap();
            let remote: SocketAddr = "127.0.0.2:4321".parse().unwrap();
            let stale = SocketOwner { inode: 11, uid: 1 };
            let fresh = SocketOwner { inode: 22, uid: 2 };
            let family = libc::AF_INET as u8;
            let mut bytes = diag_message(4, family, local, remote, stale);
            let mut sockets = Vec::new();
            let progress = unpack_messages(&bytes, 5, &mut sockets).unwrap();
            assert_eq!(progress, ReplyProgress::default());
            assert!(sockets.is_empty());

            bytes.extend(diag_message(5, family, local, remote, fresh));
            let progress = unpack_messages(&bytes, 5, &mut sockets).unwrap();
            assert!(progress.answered && !progress.done);
            assert_eq!(sockets.len(), 1);
            assert_eq!(sockets[0].owner, fresh);
            assert_eq!(sockets[0].local, local);
            assert_eq!(sockets[0].remote, remote);
        }

        #[test]
        fn parses_dual_stack_sockets_as_ipv4() {
            let local: SocketAddr = "[::ffff:10.0.0.2]:1234".parse().unwrap();
            let remote: SocketAddr = "[::ffff:1.1.1.1]:443".parse().unwrap();
            let owner = SocketOwner { inode: 5, uid: 6 };
            let bytes =
                diag_message(1, libc::AF_INET6 as u8, local, remote, owner);
            let mut sockets = Vec::new();
            unpack_messages(&bytes, 1, &mut sockets).unwrap();
            let v4 = |address: &str| address.parse::<SocketAddr>().unwrap();
            assert_eq!(sockets[0].local, v4("10.0.0.2:1234"));
            assert_eq!(sockets[0].remote, v4("1.1.1.1:443"));
        }

        #[test]
        fn dump_selection_requires_a_matching_local_address() {
            let source: SocketAddr = "10.0.0.2:5000".parse().unwrap();
            let destination: SocketAddr = "1.1.1.1:443".parse().unwrap();
            let other = socket("192.168.1.9:5000", "1.1.1.1:443", 1);
            let wildcard = socket("0.0.0.0:5000", "0.0.0.0:0", 2);
            let dual_stack = socket("[::]:5000", "[::]:0", 3);
            let bound = socket("10.0.0.2:5000", "127.0.0.1:7890", 4);
            let exact = socket("10.0.0.2:5000", "1.1.1.1:443", 5);
            let inode = |sockets: &[DiagSocket]| {
                select_dump_owner(sockets, source, Some(destination))
                    .map(|owner| owner.inode)
            };
            assert_eq!(inode(&[other]), None);
            assert_eq!(inode(&[other, wildcard]), Some(2));
            assert_eq!(inode(&[dual_stack]), Some(3));
            assert_eq!(inode(&[wildcard, bound]), Some(4));
            assert_eq!(inode(&[bound, exact, wildcard]), Some(5));
        }

        #[test]
        fn parses_proc_socket_inode_links() {
            assert_eq!(
                parse_socket_inode(Path::new("socket:[12345]")),
                Some(12345)
            );
            assert_eq!(parse_socket_inode(Path::new("socket:[x]")), None);
            assert_eq!(parse_socket_inode(Path::new("pipe:[12345]")), None);
        }

        #[test]
        fn strips_replaced_binary_marker() {
            assert_eq!(
                executable_path(Path::new("/usr/bin/curl (deleted)")),
                "/usr/bin/curl"
            );
            assert_eq!(
                executable_path(Path::new("/usr/bin/curl")),
                "/usr/bin/curl"
            );
        }

        #[test]
        fn native_resolver_finds_current_tcp_process() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let destination = listener.local_addr().unwrap();
            let client = std::net::TcpStream::connect(destination).unwrap();
            let source = client.local_addr().unwrap();
            let _server = listener.accept().unwrap().0;
            let resolver = NativeProcessResolver::default();
            let result = resolver.lookup_detailed(
                Network::Tcp,
                source,
                Some(destination),
            );
            assert_eq!(result.status, ProcessLookupStatus::Found);
            let process = result.process.expect("current TCP connection owner");
            assert_eq!(
                process.user_id,
                Some(unsafe { libc::geteuid() } as i32)
            );
            let current = std::env::current_exe().unwrap();
            assert_eq!(Path::new(&process.process_path), current);

            // A proxied client is connected to the inbound, so the routed
            // destination only matches through the port dump.
            let routed = "203.0.113.9:443".parse().unwrap();
            let proxied = resolver
                .lookup(Network::Tcp, source, Some(routed))
                .expect("owner found without the socket's real peer");
            assert_eq!(proxied.process_path, process.process_path);
        }

        #[test]
        fn native_resolver_finds_dual_stack_udp_process() {
            let Ok(client) = std::net::UdpSocket::bind("[::]:0") else {
                return;
            };
            let port = client.local_addr().unwrap().port();
            let source = SocketAddr::from(([127, 0, 0, 1], port));
            let destination = "127.0.0.1:9".parse().unwrap();
            let Ok(_) = client.send_to(b"probe", "[::ffff:127.0.0.1]:9") else {
                return;
            };
            let process = NativeProcessResolver::default()
                .lookup(Network::Udp, source, Some(destination))
                .expect("dual-stack UDP socket owner");
            assert!(!process.process_path.is_empty());
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::{
        collections::HashMap,
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        path::Path,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER,
            ERROR_SUCCESS,
        },
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID,
            MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
            TCP_TABLE_OWNER_PID_CONNECTIONS, UDP_TABLE_OWNER_PID,
        },
        Networking::WinSock::{AF_INET, AF_INET6},
        System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
    };

    use super::normalize;
    use crate::{
        adapter::{
            ProcessInfo, ProcessLookupResult, ProcessLookupStatus,
            ProcessResolver,
        },
        common::network::Network,
    };

    const MAX_LONG_PATH: usize = 32_768;
    const SNAPSHOT_TTL: Duration = Duration::from_millis(200);

    #[derive(Debug, Clone, Copy)]
    struct ConnectionEntry {
        local: SocketAddr,
        /// UDP rows carry no peer.
        remote: Option<SocketAddr>,
        pid: u32,
    }

    #[derive(Clone)]
    struct Snapshot {
        created_at: Instant,
        entries: Arc<[ConnectionEntry]>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MatchKind {
        Exact,
        LocalFallback,
        WildcardFallback,
    }

    #[derive(Default)]
    pub(super) struct NativeProcessResolver {
        snapshots: Mutex<HashMap<(Network, bool), Snapshot>>,
    }

    impl NativeProcessResolver {
        /// Return the owner table for one protocol and family.
        ///
        /// The lock is held across the rebuild so a burst of new flows shares
        /// one IP Helper call instead of each fetching the whole table.
        fn snapshot(
            &self,
            network: Network,
            ipv6: bool,
            force_refresh: bool,
        ) -> io::Result<(Snapshot, bool)> {
            let mut snapshots = self
                .snapshots
                .lock()
                .expect("process snapshot lock poisoned");
            if !force_refresh
                && let Some(snapshot) = snapshots.get(&(network, ipv6))
                && snapshot.created_at.elapsed() < SNAPSHOT_TTL
            {
                return Ok((snapshot.clone(), true));
            }
            let snapshot = build_snapshot(network, ipv6)?;
            snapshots.insert((network, ipv6), snapshot.clone());
            Ok((snapshot, false))
        }

        fn find_pid(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> io::Result<Option<u32>> {
            for attempt in 0..2 {
                let (snapshot, from_cache) =
                    self.snapshot(network, source.is_ipv6(), attempt > 0)?;
                match match_entry(
                    &snapshot.entries,
                    network,
                    source,
                    destination,
                ) {
                    // A cached table can predate the socket, so only an exact
                    // hit is trusted without a refresh.
                    Some((entry, kind))
                        if !from_cache || kind == MatchKind::Exact =>
                    {
                        return Ok(Some(entry.pid));
                    }
                    _ if from_cache => continue,
                    _ => break,
                }
            }
            if network != Network::Udp || !source.is_ipv4() {
                return Ok(None);
            }
            // A dual-stack socket bound to [::] sends IPv4 datagrams but is
            // only listed in the IPv6 table.
            for attempt in 0..2 {
                let (snapshot, from_cache) =
                    self.snapshot(network, true, attempt > 0)?;
                if let Some(entry) = snapshot.entries.iter().find(|entry| {
                    entry.local.port() == source.port()
                        && entry.local.ip().is_unspecified()
                }) {
                    return Ok(Some(entry.pid));
                }
                if !from_cache {
                    break;
                }
            }
            Ok(None)
        }

        fn lookup_native(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> ProcessLookupResult {
            let miss = |status| ProcessLookupResult {
                process: None,
                status,
            };
            if !matches!(network, Network::Tcp | Network::Udp) {
                return miss(ProcessLookupStatus::SocketSnapshotMiss);
            }
            let pid = match self.find_pid(
                network,
                normalize(source),
                destination.map(normalize),
            ) {
                Ok(Some(pid)) => pid,
                Ok(None) => {
                    return miss(ProcessLookupStatus::SocketSnapshotMiss);
                }
                Err(_) => return miss(ProcessLookupStatus::ResolverError),
            };
            match process_path(pid) {
                Ok(process_path) => {
                    let process_name = Path::new(&process_path)
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    ProcessLookupResult {
                        process: Some(ProcessInfo {
                            process_name,
                            process_path,
                            ..ProcessInfo::default()
                        }),
                        status: ProcessLookupStatus::Found,
                    }
                }
                Err(error)
                    if error.raw_os_error()
                        == Some(ERROR_ACCESS_DENIED as i32) =>
                {
                    miss(ProcessLookupStatus::PermissionDenied)
                }
                Err(_) => miss(ProcessLookupStatus::ProcessExited),
            }
        }
    }

    impl ProcessResolver for NativeProcessResolver {
        fn lookup(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> Option<ProcessInfo> {
            self.lookup_native(network, source, destination).process
        }

        fn lookup_detailed(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> ProcessLookupResult {
            self.lookup_native(network, source, destination)
        }
    }

    fn match_entry(
        entries: &[ConnectionEntry],
        network: Network,
        source: SocketAddr,
        destination: Option<SocketAddr>,
    ) -> Option<(ConnectionEntry, MatchKind)> {
        let mut local = None;
        let mut wildcard = None;
        for entry in entries.iter().copied() {
            if entry.local.port() != source.port() {
                continue;
            }
            if entry.local.ip() != source.ip() {
                if network == Network::Udp
                    && entry.local.ip().is_unspecified()
                    && wildcard.is_none()
                {
                    wildcard = Some(entry);
                }
                continue;
            }
            match (entry.remote, destination) {
                (Some(remote), Some(destination)) if remote != destination => {
                    // A proxy client is connected to the inbound, not to the
                    // routed destination; keep it as the fallback.
                    if local.is_none() {
                        local = Some(entry);
                    }
                }
                _ => return Some((entry, MatchKind::Exact)),
            }
        }
        local
            .map(|entry| (entry, MatchKind::LocalFallback))
            .or_else(|| {
                wildcard.map(|entry| (entry, MatchKind::WildcardFallback))
            })
    }

    fn build_snapshot(network: Network, ipv6: bool) -> io::Result<Snapshot> {
        let family = if ipv6 { AF_INET6 } else { AF_INET } as u32;
        let entries: Vec<ConnectionEntry> = match (network, ipv6) {
            (Network::Tcp, false) => {
                table_rows::<MIB_TCPROW_OWNER_PID>(&get_table(true, family)?)?
                    .into_iter()
                    .map(|row| ConnectionEntry {
                        local: SocketAddr::new(
                            ipv4_address(row.dwLocalAddr).into(),
                            dword_port(row.dwLocalPort),
                        ),
                        remote: Some(SocketAddr::new(
                            ipv4_address(row.dwRemoteAddr).into(),
                            dword_port(row.dwRemotePort),
                        )),
                        pid: row.dwOwningPid,
                    })
                    .collect()
            }
            (Network::Tcp, true) => {
                table_rows::<MIB_TCP6ROW_OWNER_PID>(&get_table(true, family)?)?
                    .into_iter()
                    .map(|row| ConnectionEntry {
                        local: normalize(SocketAddr::new(
                            Ipv6Addr::from(row.ucLocalAddr).into(),
                            dword_port(row.dwLocalPort),
                        )),
                        remote: Some(normalize(SocketAddr::new(
                            Ipv6Addr::from(row.ucRemoteAddr).into(),
                            dword_port(row.dwRemotePort),
                        ))),
                        pid: row.dwOwningPid,
                    })
                    .collect()
            }
            (Network::Udp, false) => {
                table_rows::<MIB_UDPROW_OWNER_PID>(&get_table(false, family)?)?
                    .into_iter()
                    .map(|row| ConnectionEntry {
                        local: SocketAddr::new(
                            ipv4_address(row.dwLocalAddr).into(),
                            dword_port(row.dwLocalPort),
                        ),
                        remote: None,
                        pid: row.dwOwningPid,
                    })
                    .collect()
            }
            (Network::Udp, true) => {
                table_rows::<MIB_UDP6ROW_OWNER_PID>(&get_table(false, family)?)?
                    .into_iter()
                    .map(|row| ConnectionEntry {
                        local: SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                            dword_port(row.dwLocalPort),
                        ),
                        remote: None,
                        pid: row.dwOwningPid,
                    })
                    .collect()
            }
            (Network::Icmp, _) => {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        };
        Ok(Snapshot {
            created_at: Instant::now(),
            entries: entries.into(),
        })
    }

    fn get_table(tcp: bool, family: u32) -> io::Result<Vec<u8>> {
        let mut size = 0u32;
        let mut status = unsafe {
            if tcp {
                GetExtendedTcpTable(
                    std::ptr::null_mut(),
                    &mut size,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_CONNECTIONS,
                    0,
                )
            } else {
                GetExtendedUdpTable(
                    std::ptr::null_mut(),
                    &mut size,
                    0,
                    family,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            }
        };
        if status != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        loop {
            let mut table = vec![0u8; size as usize];
            status = unsafe {
                if tcp {
                    GetExtendedTcpTable(
                        table.as_mut_ptr().cast(),
                        &mut size,
                        0,
                        family,
                        TCP_TABLE_OWNER_PID_CONNECTIONS,
                        0,
                    )
                } else {
                    GetExtendedUdpTable(
                        table.as_mut_ptr().cast(),
                        &mut size,
                        0,
                        family,
                        UDP_TABLE_OWNER_PID,
                        0,
                    )
                }
            };
            if status == ERROR_INSUFFICIENT_BUFFER {
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            table.truncate(size as usize);
            return Ok(table);
        }
    }

    fn table_rows<T: Copy>(table: &[u8]) -> io::Result<Vec<T>> {
        if table.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short IP Helper table",
            ));
        }
        let count = u32::from_ne_bytes(table[..4].try_into().unwrap()) as usize;
        let bytes = count
            .checked_mul(std::mem::size_of::<T>())
            .and_then(|length| length.checked_add(4))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IP Helper table length overflow",
                )
            })?;
        if bytes > table.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated IP Helper table",
            ));
        }
        Ok((0..count)
            .map(|index| unsafe {
                std::ptr::read_unaligned(
                    table[4 + index * std::mem::size_of::<T>()..]
                        .as_ptr()
                        .cast::<T>(),
                )
            })
            .collect())
    }

    fn ipv4_address(value: u32) -> Ipv4Addr {
        Ipv4Addr::from(value.to_ne_bytes())
    }

    fn dword_port(value: u32) -> u16 {
        let bytes = value.to_ne_bytes();
        u16::from_be_bytes([bytes[0], bytes[1]])
    }

    fn process_path(pid: u32) -> io::Result<String> {
        match pid {
            0 => return Ok(":System Idle Process".into()),
            4 => return Ok(":System".into()),
            _ => {}
        }
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut path = vec![0u16; MAX_LONG_PATH];
        let mut length = path.len() as u32;
        let result = unsafe {
            QueryFullProcessImageNameW(
                handle,
                0,
                path.as_mut_ptr(),
                &mut length,
            )
        };
        // CloseHandle may reset the thread's last error.
        let error = io::Error::last_os_error();
        unsafe {
            CloseHandle(handle);
        }
        if result == 0 {
            return Err(error);
        }
        path.truncate(length as usize);
        Ok(String::from_utf16_lossy(&path))
    }

    pub(super) fn resolver() -> Arc<dyn ProcessResolver> {
        Arc::new(NativeProcessResolver::default())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn entry(
            local: &str,
            remote: Option<&str>,
            pid: u32,
        ) -> ConnectionEntry {
            ConnectionEntry {
                local: local.parse().unwrap(),
                remote: remote.map(|remote| remote.parse().unwrap()),
                pid,
            }
        }

        #[test]
        fn parses_ip_helper_address_and_port_wire_order() {
            assert_eq!(
                ipv4_address(u32::from_ne_bytes([127, 0, 0, 1])),
                Ipv4Addr::LOCALHOST
            );
            assert_eq!(
                dword_port(u32::from_ne_bytes([0x1f, 0x90, 0, 0])),
                8080
            );
        }

        #[test]
        fn parses_unaligned_variable_length_tables() {
            let rows = [MIB_UDPROW_OWNER_PID {
                dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
                dwLocalPort: u32::from_ne_bytes([0x14, 0xe9, 0, 0]),
                dwOwningPid: 42,
            }];
            let mut table = 1u32.to_ne_bytes().to_vec();
            let row = unsafe {
                std::slice::from_raw_parts(
                    rows.as_ptr().cast::<u8>(),
                    std::mem::size_of_val(&rows),
                )
            };
            table.extend_from_slice(row);
            let parsed = table_rows::<MIB_UDPROW_OWNER_PID>(&table).unwrap();
            assert_eq!(parsed.len(), 1);
            assert_eq!(parsed[0].dwOwningPid, 42);
        }

        #[test]
        fn prefers_the_connection_to_the_routed_destination() {
            let source: SocketAddr = "10.0.0.2:5000".parse().unwrap();
            let destination: SocketAddr = "1.1.1.1:443".parse().unwrap();
            let proxied = entry("10.0.0.2:5000", Some("127.0.0.1:7890"), 1);
            let exact = entry("10.0.0.2:5000", Some("1.1.1.1:443"), 2);
            let other = entry("192.168.1.9:5000", Some("1.1.1.1:443"), 3);
            let matched = |entries: &[ConnectionEntry]| {
                match_entry(entries, Network::Tcp, source, Some(destination))
                    .map(|(entry, kind)| (entry.pid, kind))
            };
            assert_eq!(matched(&[other]), None);
            assert_eq!(
                matched(&[proxied, other]),
                Some((1, MatchKind::LocalFallback))
            );
            assert_eq!(matched(&[proxied, exact]), Some((2, MatchKind::Exact)));
        }

        #[test]
        fn udp_falls_back_to_a_wildcard_listener() {
            let source: SocketAddr = "10.0.0.2:5000".parse().unwrap();
            let wildcard = entry("0.0.0.0:5000", None, 1);
            let bound = entry("10.0.0.2:5000", None, 2);
            let matched = |network, entries: &[ConnectionEntry]| {
                match_entry(entries, network, source, None)
                    .map(|(entry, kind)| (entry.pid, kind))
            };
            assert_eq!(
                matched(Network::Udp, &[wildcard]),
                Some((1, MatchKind::WildcardFallback))
            );
            assert_eq!(
                matched(Network::Udp, &[wildcard, bound]),
                Some((2, MatchKind::Exact))
            );
            assert_eq!(matched(Network::Tcp, &[wildcard]), None);
        }
    }
}

/// Fold an IPv4-mapped IPv6 endpoint into the IPv4 form socket tables use.
#[cfg(any(target_os = "linux", windows))]
fn normalize(address: std::net::SocketAddr) -> std::net::SocketAddr {
    use std::net::{IpAddr, SocketAddr};

    match address {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), v6.port()))
            .unwrap_or(address),
        address => address,
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn lookup_username(uid: u32) -> Option<String> {
    use std::{
        collections::HashMap,
        sync::{Mutex, OnceLock},
        time::{Duration, Instant},
    };

    // getpwuid_r can reach a remote directory service, which is too slow to
    // repeat for every connection.
    const TTL: Duration = Duration::from_secs(60);
    const CAPACITY: usize = 256;
    type Cache = Mutex<HashMap<u32, (Instant, Option<String>)>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();

    let cache = CACHE.get_or_init(Default::default);
    if let Some((created_at, name)) = cache
        .lock()
        .expect("username cache lock poisoned")
        .get(&uid)
        && created_at.elapsed() < TTL
    {
        return name.clone();
    }
    let name = query_username(uid);
    let mut cache = cache.lock().expect("username cache lock poisoned");
    if cache.len() >= CAPACITY {
        cache.clear();
    }
    cache.insert(uid, (Instant::now(), name.clone()));
    name
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn query_username(uid: u32) -> Option<String> {
    use std::{ffi::CStr, ptr};

    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let capacity = if suggested > 0 {
        suggested as usize
    } else {
        16 * 1024
    };
    let mut buffer = vec![0 as libc::c_char; capacity];
    let mut password: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = ptr::null_mut();
    let status = unsafe {
        libc::getpwuid_r(
            uid as libc::uid_t,
            &mut password,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() || password.pw_name.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(password.pw_name) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Refuses lookups for flows that did not originate on this host.
///
/// Socket tables are keyed by port, so a forwarded LAN client whose source
/// port collides with a local socket would otherwise inherit that socket's
/// process.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
mod local_source {
    use std::{
        collections::HashMap,
        io,
        net::{IpAddr, SocketAddr, UdpSocket},
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use crate::{
        adapter::{
            ProcessInfo, ProcessLookupResult, ProcessLookupStatus,
            ProcessResolver,
        },
        common::network::Network,
    };

    const LOCAL_TTL: Duration = Duration::from_secs(10);
    // An address can become local at any moment, for example when the TUN
    // interface comes up, so a negative answer is only trusted briefly.
    const FOREIGN_TTL: Duration = Duration::from_secs(1);
    const CACHE_LIMIT: usize = 256;

    pub(super) struct LocalSourceResolver {
        inner: Arc<dyn ProcessResolver>,
        addresses: Mutex<HashMap<IpAddr, (Instant, bool)>>,
    }

    impl LocalSourceResolver {
        pub(super) fn new(inner: Arc<dyn ProcessResolver>) -> Self {
            Self {
                inner,
                addresses: Mutex::new(HashMap::new()),
            }
        }

        fn is_local(&self, address: IpAddr) -> bool {
            let address = address.to_canonical();
            if address.is_loopback() || address.is_unspecified() {
                return true;
            }
            // A link-local address cannot be probed without its scope.
            if let IpAddr::V6(v6) = address
                && v6.is_unicast_link_local()
            {
                return true;
            }
            let mut addresses = self
                .addresses
                .lock()
                .expect("local address cache lock poisoned");
            if let Some((checked_at, local)) = addresses.get(&address) {
                let ttl = if *local { LOCAL_TTL } else { FOREIGN_TTL };
                if checked_at.elapsed() < ttl {
                    return *local;
                }
            }
            let local = probe_local(address);
            if addresses.len() >= CACHE_LIMIT {
                addresses.clear();
            }
            addresses.insert(address, (Instant::now(), local));
            local
        }
    }

    /// Only an address assigned to this host can be bound. Any other failure
    /// proves nothing, so it keeps the lookup enabled.
    fn probe_local(address: IpAddr) -> bool {
        match UdpSocket::bind(SocketAddr::new(address, 0)) {
            Ok(_) => true,
            Err(error) => error.kind() != io::ErrorKind::AddrNotAvailable,
        }
    }

    impl ProcessResolver for LocalSourceResolver {
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
            if !self.is_local(source.ip()) {
                return ProcessLookupResult {
                    process: None,
                    status: ProcessLookupStatus::NonLocalSource,
                };
            }
            self.inner.lookup_detailed(network, source, destination)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        struct Always;

        impl ProcessResolver for Always {
            fn lookup(
                &self,
                _network: Network,
                _source: SocketAddr,
                _destination: Option<SocketAddr>,
            ) -> Option<ProcessInfo> {
                Some(ProcessInfo::default())
            }
        }

        #[test]
        fn skips_sources_that_are_not_assigned_to_this_host() {
            let resolver = LocalSourceResolver::new(Arc::new(Always));
            let lookup = |source: &str| {
                resolver.lookup_detailed(
                    Network::Udp,
                    source.parse().unwrap(),
                    None,
                )
            };
            assert_eq!(
                lookup("127.0.0.1:5000").status,
                ProcessLookupStatus::Found
            );
            assert_eq!(
                lookup("[::ffff:127.0.0.1]:5000").status,
                ProcessLookupStatus::Found
            );
            // TEST-NET-3 is reserved and never assigned to an interface.
            let foreign = lookup("203.0.113.77:5000");
            assert_eq!(foreign.status, ProcessLookupStatus::NonLocalSource);
            assert!(foreign.process.is_none());
        }
    }
}

pub(crate) fn native_process_resolver()
-> Option<std::sync::Arc<dyn crate::adapter::ProcessResolver>> {
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    {
        Some(std::sync::Arc::new(local_source::LocalSourceResolver::new(
            platform::resolver(),
        )))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        None
    }
}
