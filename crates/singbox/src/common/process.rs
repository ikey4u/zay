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
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use crate::{
        adapter::{ProcessInfo, ProcessResolver},
        common::network::Network,
    };

    const SNAPSHOT_TTL: Duration = Duration::from_millis(200);
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MatchKind {
        Exact,
        LocalFallback,
        WildcardFallback,
    }

    #[derive(Default)]
    pub(super) struct NativeProcessResolver {
        snapshots: Mutex<HashMap<Network, Snapshot>>,
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
    }

    impl ProcessResolver for NativeProcessResolver {
        fn lookup(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> Option<ProcessInfo> {
            if !matches!(network, Network::Tcp | Network::Udp) {
                return None;
            }
            let source = normalize(source);
            let destination = destination.map(normalize);
            let mut last = None;
            for attempt in 0..2 {
                let (snapshot, from_cache) =
                    self.snapshot(network, attempt > 0).ok()?;
                let (entry, kind) = match_entry(
                    &snapshot.entries,
                    network,
                    source,
                    destination,
                )?;
                if from_cache && kind != MatchKind::Exact {
                    continue;
                }
                let mut process = ProcessInfo {
                    user: (entry.uid >= 0)
                        .then(|| super::lookup_username(entry.uid as u32))
                        .flatten()
                        .unwrap_or_default(),
                    user_id: Some(entry.uid),
                    ..ProcessInfo::default()
                };
                last = Some(process.clone());
                if entry.pid == 0 {
                    return Some(process);
                }
                if let Ok(path) = process_path(entry.pid) {
                    process.process_name = Path::new(&path)
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    process.process_path = path;
                    return Some(process);
                }
                if !from_cache {
                    return Some(process);
                }
            }
            last
        }
    }

    fn build_snapshot(network: Network) -> io::Result<Snapshot> {
        let (name, item_size) = match network {
            Network::Tcp => (
                "net.inet.tcp.pcblist_n",
                darwin_struct_size()? + TCP_EXTRA_STRUCT_SIZE,
            ),
            Network::Udp => ("net.inet.udp.pcblist_n", darwin_struct_size()?),
            Network::Icmp => return Err(io::ErrorKind::InvalidInput.into()),
        };
        let bytes = sysctl_raw(name)?;
        Ok(Snapshot {
            created_at: Instant::now(),
            entries: parse_snapshot(&bytes, item_size, darwin_struct_size()?),
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

    fn parse_snapshot(
        bytes: &[u8],
        item_size: usize,
        struct_size: usize,
    ) -> Vec<ConnectionEntry> {
        if item_size == 0 || bytes.len() < XINPGEN_SIZE {
            return Vec::new();
        }
        (XINPGEN_SIZE..bytes.len())
            .step_by(item_size)
            .filter_map(|offset| {
                let end = offset.checked_add(item_size)?;
                (end <= bytes.len()).then_some(())?;
                parse_entry(&bytes[offset..end], struct_size)
            })
            .collect()
    }

    fn parse_entry(
        bytes: &[u8],
        struct_size: usize,
    ) -> Option<ConnectionEntry> {
        if bytes.len() < struct_size
            || struct_size < XSOCKET_OFFSET + XSOCKET_LAST_PID + 4
        {
            return None;
        }
        let vflag = bytes[XINPCB_VFLAG];
        let (local_ip, remote_ip) = if vflag & 0x1 != 0 {
            let local: [u8; 4] = bytes[XINPCB_LOCAL_ADDR + XINPCB_IPV4_ADDR..]
                [..4]
                .try_into()
                .ok()?;
            let remote: [u8; 4] = bytes
                [XINPCB_FOREIGN_ADDR + XINPCB_IPV4_ADDR..][..4]
                .try_into()
                .ok()?;
            (
                IpAddr::V4(Ipv4Addr::from(local)),
                IpAddr::V4(Ipv4Addr::from(remote)),
            )
        } else if vflag & 0x2 != 0 {
            let local: [u8; 16] =
                bytes[XINPCB_LOCAL_ADDR..][..16].try_into().ok()?;
            let remote: [u8; 16] =
                bytes[XINPCB_FOREIGN_ADDR..][..16].try_into().ok()?;
            (
                IpAddr::V6(Ipv6Addr::from(local)),
                IpAddr::V6(Ipv6Addr::from(remote)),
            )
        } else {
            return None;
        };
        let socket = &bytes[XSOCKET_OFFSET..struct_size];
        Some(ConnectionEntry {
            local: SocketAddr::new(
                local_ip,
                u16::from_be_bytes(
                    bytes[XINPCB_LOCAL_PORT..][..2].try_into().ok()?,
                ),
            ),
            remote: SocketAddr::new(
                remote_ip,
                u16::from_be_bytes(
                    bytes[XINPCB_FOREIGN_PORT..][..2].try_into().ok()?,
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
            if network != Network::Udp {
                continue;
            }
            if local.is_none() && entry.local == source {
                local = Some(entry);
            }
            if wildcard.is_none() && entry.local.ip().is_unspecified() {
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
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{
        collections::HashMap,
        io,
        net::{IpAddr, SocketAddr},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::fs::MetadataExt as _,
        },
        path::Path,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use crate::{
        adapter::{ProcessInfo, ProcessResolver},
        common::network::Network,
    };

    const SOCKET_DIAG_BY_FAMILY: u16 = 20;
    const REQUEST_SIZE: usize = 72;
    const RESPONSE_MIN_SIZE: usize = 72;
    const PROCESS_CACHE_TTL: Duration = Duration::from_secs(1);
    const PROCESS_CACHE_CAPACITY: usize = 64;

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
        ) -> io::Result<Option<(u32, u32)>> {
            let request = pack_request(
                self.family,
                self.protocol,
                source,
                Some(destination),
                false,
            );
            let mut fd = self.fd.lock().expect("socket diag lock poisoned");
            let mut last_error = None;
            for _ in 0..2 {
                if fd.is_none() {
                    *fd = Some(open_socket_diag()?);
                }
                match query_socket_diag(fd.as_ref().unwrap(), &request) {
                    Ok(result) => return Ok(result),
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

    struct CachedProcessPaths {
        created_at: Instant,
        entries: HashMap<u32, String>,
    }

    pub(super) struct NativeProcessResolver {
        diag: [SocketDiagConn; 4],
        process_paths: Mutex<HashMap<u32, CachedProcessPaths>>,
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
                process_paths: Mutex::new(HashMap::new()),
            }
        }
    }

    impl NativeProcessResolver {
        fn resolve_socket(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> io::Result<Option<(u32, u32)>> {
            let (family, protocol) = socket_diag_settings(network, source)?;
            let conn = &self.diag[socket_diag_index(family, protocol)];
            if let Some(destination) = destination
                && source.is_ipv4() == destination.is_ipv4()
                && let Some(result) = conn.query(source, destination)?
            {
                return Ok(Some(result));
            }
            let fd = open_socket_diag()?;
            query_socket_diag(
                &fd,
                &pack_request(family, protocol, source, None, true),
            )
        }

        fn find_process_path(
            &self,
            inode: u32,
            uid: u32,
        ) -> io::Result<String> {
            let mut cache = self
                .process_paths
                .lock()
                .expect("process path cache lock poisoned");
            if let Some(cached) = cache.get(&uid)
                && cached.created_at.elapsed() < PROCESS_CACHE_TTL
                && let Some(path) = cached.entries.get(&inode)
            {
                return Ok(path.clone());
            }
            let entries = build_process_paths_by_uid(Path::new("/proc"), uid)?;
            let result = entries.get(&inode).cloned().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("process of uid({uid}), inode({inode}) not found"),
                )
            });
            if !cache.contains_key(&uid)
                && cache.len() >= PROCESS_CACHE_CAPACITY
                && let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, value)| value.created_at)
                    .map(|(uid, _)| *uid)
            {
                cache.remove(&oldest);
            }
            cache.insert(
                uid,
                CachedProcessPaths {
                    created_at: Instant::now(),
                    entries,
                },
            );
            result
        }
    }

    impl ProcessResolver for NativeProcessResolver {
        fn lookup(
            &self,
            network: Network,
            source: SocketAddr,
            destination: Option<SocketAddr>,
        ) -> Option<ProcessInfo> {
            let (inode, uid) =
                self.resolve_socket(network, source, destination).ok()??;
            let process_path =
                self.find_process_path(inode, uid).unwrap_or_default();
            let process_name = Path::new(&process_path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            Some(ProcessInfo {
                process_name,
                process_path,
                user: super::lookup_username(uid).unwrap_or_default(),
                user_id: Some(uid as i32),
                ..ProcessInfo::default()
            })
        }
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
            tv_usec: 100,
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
    ) -> [u8; REQUEST_SIZE] {
        let mut request = [0u8; REQUEST_SIZE];
        request[0..4].copy_from_slice(&(REQUEST_SIZE as u32).to_ne_bytes());
        request[4..6].copy_from_slice(&SOCKET_DIAG_BY_FAMILY.to_ne_bytes());
        let mut flags = libc::NLM_F_REQUEST as u16;
        if dump {
            flags |= libc::NLM_F_DUMP as u16;
        }
        request[6..8].copy_from_slice(&flags.to_ne_bytes());
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
        write_ip(&mut request[28..44], request_source.ip());
        if let Some(destination) = request_destination {
            write_ip(&mut request[44..60], destination.ip());
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

    fn query_socket_diag(
        fd: &OwnedFd,
        request: &[u8],
    ) -> io::Result<Option<(u32, u32)>> {
        let written = unsafe {
            libc::write(fd.as_raw_fd(), request.as_ptr().cast(), request.len())
        };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if written as usize != request.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let mut response = vec![0u8; 64 << 10];
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
        response.truncate(read as usize);
        unpack_messages(&response)
    }

    fn unpack_messages(bytes: &[u8]) -> io::Result<Option<(u32, u32)>> {
        let mut offset = 0usize;
        while offset + 16 <= bytes.len() {
            let length = u32::from_ne_bytes(
                bytes[offset..offset + 4].try_into().unwrap(),
            ) as usize;
            if length < 16 || offset + length > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid netlink message length",
                ));
            }
            let message_type = u16::from_ne_bytes(
                bytes[offset + 4..offset + 6].try_into().unwrap(),
            );
            let data = &bytes[offset + 16..offset + length];
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
                        return Ok(None);
                    }
                    return Err(io::Error::from_raw_os_error(errno));
                }
            } else if message_type == SOCKET_DIAG_BY_FAMILY
                && data.len() >= RESPONSE_MIN_SIZE
            {
                let uid = u32::from_ne_bytes(data[64..68].try_into().unwrap());
                let inode =
                    u32::from_ne_bytes(data[68..72].try_into().unwrap());
                if inode != 0 || uid != 0 {
                    return Ok(Some((inode, uid)));
                }
            }
            offset += (length + 3) & !3;
        }
        Ok(None)
    }

    fn build_process_paths_by_uid(
        proc_root: &Path,
        uid: u32,
    ) -> io::Result<HashMap<u32, String>> {
        let mut paths = HashMap::new();
        for entry in std::fs::read_dir(proc_root)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if ignorable_proc_error(&error) => continue,
                Err(error) => return Err(error),
            };
            let name = entry.file_name();
            if name.to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if ignorable_proc_error(&error) => continue,
                Err(error) => return Err(error),
            };
            if !metadata.is_dir() || metadata.uid() != uid {
                continue;
            }
            let process_root = entry.path();
            let executable = match std::fs::read_link(process_root.join("exe"))
            {
                Ok(path) => path.to_string_lossy().into_owned(),
                Err(error) if ignorable_proc_error(&error) => continue,
                Err(error) => return Err(error),
            };
            let descriptors = match std::fs::read_dir(process_root.join("fd")) {
                Ok(descriptors) => descriptors,
                Err(_) => continue,
            };
            for descriptor in descriptors.flatten() {
                let Ok(link) = std::fs::read_link(descriptor.path()) else {
                    continue;
                };
                if let Some(inode) = parse_socket_inode(&link) {
                    paths.entry(inode).or_insert_with(|| executable.clone());
                }
            }
        }
        Ok(paths)
    }

    fn parse_socket_inode(link: &Path) -> Option<u32> {
        let link = link.as_os_str().to_string_lossy();
        link.strip_prefix("socket:[")?
            .strip_suffix(']')?
            .parse()
            .ok()
    }

    fn ignorable_proc_error(error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
        )
    }

    pub(super) fn resolver() -> Arc<dyn ProcessResolver> {
        Arc::new(NativeProcessResolver::default())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

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
            );
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
            );
            assert_eq!(&udp[24..26], &4321u16.to_be_bytes());
            assert_eq!(&udp[26..28], &1234u16.to_be_bytes());

            let dump = pack_request(
                libc::AF_INET as u8,
                libc::IPPROTO_TCP as u8,
                source,
                None,
                true,
            );
            assert_eq!(&dump[20..24], &u32::MAX.to_ne_bytes());
            assert_eq!(&dump[26..28], &[0, 0]);
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
    }
}

#[cfg(windows)]
mod platform {
    use std::{io, net::SocketAddr, path::Path, sync::Arc};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS},
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

    use crate::{
        adapter::{ProcessInfo, ProcessResolver},
        common::network::Network,
    };

    const MAX_LONG_PATH: usize = 32_768;

    #[derive(Default)]
    pub(super) struct NativeProcessResolver;

    impl ProcessResolver for NativeProcessResolver {
        fn lookup(
            &self,
            network: Network,
            source: SocketAddr,
            _destination: Option<SocketAddr>,
        ) -> Option<ProcessInfo> {
            let pid = find_pid(network, source).ok()?;
            let process_path = process_path(pid).ok()?;
            let process_name = Path::new(&process_path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            Some(ProcessInfo {
                process_name,
                process_path,
                ..ProcessInfo::default()
            })
        }
    }

    fn find_pid(network: Network, source: SocketAddr) -> io::Result<u32> {
        match (network, source) {
            (Network::Tcp, SocketAddr::V4(source)) => {
                let table = get_table(true, AF_INET as u32)?;
                for row in table_rows::<MIB_TCPROW_OWNER_PID>(&table)? {
                    if ipv4_address(row.dwLocalAddr) == *source.ip()
                        && dword_port(row.dwLocalPort) == source.port()
                    {
                        return Ok(row.dwOwningPid);
                    }
                }
            }
            (Network::Tcp, SocketAddr::V6(source)) => {
                let table = get_table(true, AF_INET6 as u32)?;
                for row in table_rows::<MIB_TCP6ROW_OWNER_PID>(&table)? {
                    if row.ucLocalAddr == source.ip().octets()
                        && dword_port(row.dwLocalPort) == source.port()
                    {
                        return Ok(row.dwOwningPid);
                    }
                }
            }
            (Network::Udp, SocketAddr::V4(source)) => {
                let table = get_table(false, AF_INET as u32)?;
                for row in table_rows::<MIB_UDPROW_OWNER_PID>(&table)? {
                    let address = ipv4_address(row.dwLocalAddr);
                    if (address == *source.ip() || address.is_unspecified())
                        && dword_port(row.dwLocalPort) == source.port()
                    {
                        return Ok(row.dwOwningPid);
                    }
                }
            }
            (Network::Udp, SocketAddr::V6(source)) => {
                let table = get_table(false, AF_INET6 as u32)?;
                for row in table_rows::<MIB_UDP6ROW_OWNER_PID>(&table)? {
                    let address = std::net::Ipv6Addr::from(row.ucLocalAddr);
                    if (address == *source.ip() || address.is_unspecified())
                        && dword_port(row.dwLocalPort) == source.port()
                    {
                        return Ok(row.dwOwningPid);
                    }
                }
            }
            (Network::Icmp, _) => {}
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("process not found for {source}"),
        ))
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

    fn ipv4_address(value: u32) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(value.to_ne_bytes())
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
        unsafe {
            CloseHandle(handle);
        }
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        path.truncate(length as usize);
        Ok(String::from_utf16_lossy(&path))
    }

    pub(super) fn resolver() -> Arc<dyn ProcessResolver> {
        Arc::new(NativeProcessResolver)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_ip_helper_address_and_port_wire_order() {
            assert_eq!(
                ipv4_address(u32::from_ne_bytes([127, 0, 0, 1])),
                std::net::Ipv4Addr::LOCALHOST
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
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn lookup_username(uid: u32) -> Option<String> {
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

pub(crate) fn native_process_resolver()
-> Option<std::sync::Arc<dyn crate::adapter::ProcessResolver>> {
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    {
        Some(platform::resolver())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        None
    }
}
