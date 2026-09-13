//! Native desktop neighbor and DHCP lease resolver.
//!
//! sing-box combines the kernel ARP/NDP table with hostnames learned from
//! common DHCP lease files. The resolver owns runtime-scoped kernel event and
//! lease refresh monitoring, with an on-demand fallback, and does not require
//! an ambient async runtime.

#![cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(dead_code)
)]

use std::{
    collections::{HashMap, HashSet},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::adapter::NeighborResolver;

const REFRESH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Default)]
struct NeighborState {
    neighbor_ip_to_mac: HashMap<IpAddr, Vec<u8>>,
    lease_ip_to_mac: HashMap<IpAddr, Vec<u8>>,
    ip_to_hostname: HashMap<IpAddr, String>,
    mac_to_hostname: HashMap<String, String>,
}

struct RefreshState {
    neighbor_at: Option<Instant>,
    leases_at: Option<Instant>,
}

pub(crate) struct NativeNeighborResolver {
    lease_files: Vec<PathBuf>,
    state: RwLock<NeighborState>,
    refresh: Mutex<RefreshState>,
}

impl NativeNeighborResolver {
    fn new(lease_files: &[String], base_path: &Path) -> Arc<Self> {
        let lease_files = configured_lease_files(lease_files, base_path);
        let resolver = Arc::new(Self {
            lease_files,
            state: RwLock::new(NeighborState::default()),
            refresh: Mutex::new(RefreshState {
                neighbor_at: None,
                leases_at: None,
            }),
        });
        resolver.refresh(true);
        platform::start_monitor(Arc::downgrade(&resolver));
        resolver
    }

    fn refresh(&self, force: bool) {
        let now = Instant::now();
        let mut refresh = self.refresh.lock().expect("neighbor refresh lock");
        if force
            || refresh
                .neighbor_at
                .is_none_or(|last| now.duration_since(last) >= REFRESH_INTERVAL)
        {
            if let Ok(table) = platform::read_neighbor_table() {
                self.state
                    .write()
                    .expect("neighbor state lock")
                    .neighbor_ip_to_mac = table;
            }
            refresh.neighbor_at = Some(now);
        }
        if force
            || refresh
                .leases_at
                .is_none_or(|last| now.duration_since(last) >= REFRESH_INTERVAL)
        {
            let leases = reload_lease_files(&self.lease_files);
            let mut state = self.state.write().expect("neighbor state lock");
            state.lease_ip_to_mac = leases.ip_to_mac;
            state.ip_to_hostname = leases.ip_to_hostname;
            state.mac_to_hostname = leases.mac_to_hostname;
            refresh.leases_at = Some(now);
        }
    }

    fn neighbor_changed(&self) {
        self.refresh
            .lock()
            .expect("neighbor refresh lock")
            .neighbor_at = None;
        self.refresh(false);
    }
}

impl NeighborResolver for NativeNeighborResolver {
    fn lookup_addresses(&self, hostname: &str) -> Vec<IpAddr> {
        self.refresh(false);
        let hostname = hostname.trim_end_matches('.');
        if hostname.is_empty() {
            return Vec::new();
        }
        let state = self.state.read().expect("neighbor state lock");
        lookup_addresses_by_hostname(hostname, &state)
    }

    fn lookup_mac(&self, address: IpAddr) -> Option<Vec<u8>> {
        self.refresh(false);
        let state = self.state.read().expect("neighbor state lock");
        state
            .neighbor_ip_to_mac
            .get(&address)
            .or_else(|| state.lease_ip_to_mac.get(&address))
            .cloned()
            .or_else(|| extract_mac_from_eui64(address))
    }

    fn lookup_hostname(&self, address: IpAddr) -> Option<String> {
        self.refresh(false);
        let state = self.state.read().expect("neighbor state lock");
        if let Some(hostname) = state.ip_to_hostname.get(&address) {
            return Some(hostname.clone());
        }
        let mac = state
            .neighbor_ip_to_mac
            .get(&address)
            .or_else(|| state.lease_ip_to_mac.get(&address))
            .cloned()
            .or_else(|| extract_mac_from_eui64(address))?;
        state.mac_to_hostname.get(&format_mac(&mac)).cloned()
    }
}

pub(crate) fn native_neighbor_resolver(
    lease_files: &[String],
    base_path: &Path,
) -> Option<Arc<dyn NeighborResolver>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        Some(NativeNeighborResolver::new(lease_files, base_path))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (lease_files, base_path);
        None
    }
}

fn configured_lease_files(
    configured: &[String],
    base_path: &Path,
) -> Vec<PathBuf> {
    if !configured.is_empty() {
        return configured
            .iter()
            .map(PathBuf::from)
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    base_path.join(path)
                }
            })
            .collect();
    }
    platform::default_lease_files()
        .iter()
        .map(PathBuf::from)
        .filter(|path| {
            fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0)
        })
        .collect()
}

#[derive(Default)]
struct LeaseTables {
    ip_to_mac: HashMap<IpAddr, Vec<u8>>,
    ip_to_hostname: HashMap<IpAddr, String>,
    mac_to_hostname: HashMap<String, String>,
}

fn reload_lease_files(paths: &[PathBuf]) -> LeaseTables {
    let mut tables = LeaseTables::default();
    for path in paths {
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };
        let name = path.to_string_lossy();
        if name.ends_with("dhcpd_leases") {
            parse_bootpd_leases(&contents, &mut tables);
        } else if name.ends_with("kea-leases4.csv") {
            parse_kea_csv4(&contents, &mut tables);
        } else if name.ends_with("kea-leases6.csv") {
            parse_kea_csv6(&contents, &mut tables);
        } else if name.ends_with("dhcpd.leases") {
            parse_isc_dhcpd(&contents, &mut tables);
        } else {
            parse_dnsmasq_odhcpd(&contents, &mut tables);
        }
    }
    tables
}

fn insert_lease(
    tables: &mut LeaseTables,
    address: IpAddr,
    mac: Option<Vec<u8>>,
    hostname: &str,
) {
    if let Some(mac) = mac {
        tables.ip_to_mac.insert(address, mac.clone());
        if !hostname.is_empty() {
            tables
                .mac_to_hostname
                .insert(format_mac(&mac), hostname.to_owned());
        }
    }
    if !hostname.is_empty() {
        tables.ip_to_hostname.insert(address, hostname.to_owned());
    }
}

fn parse_dnsmasq_odhcpd(contents: &str, tables: &mut LeaseTables) {
    let now = unix_time();
    for line in contents.lines() {
        if line.starts_with("duid ") {
            continue;
        }
        if let Some(line) = line.strip_prefix("# ") {
            parse_odhcpd_line(line, now, tables);
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let Ok(expiry) = fields[0].parse::<i64>() else {
            continue;
        };
        if expiry != 0 && expiry < now {
            continue;
        }
        let Ok(address) = fields[2].parse::<IpAddr>() else {
            continue;
        };
        let hostname = if fields[3] != "*" { fields[3] } else { "" };
        let mac = if fields[1].contains(':') {
            parse_mac(fields[1])
        } else {
            fields
                .get(4)
                .and_then(|duid| parse_hex_bytes(duid))
                .and_then(|duid| extract_mac_from_duid(&duid))
        };
        if fields[1].contains(':') && mac.is_none() {
            continue;
        }
        insert_lease(tables, address, mac, hostname);
    }
}

fn parse_odhcpd_line(line: &str, now: i64, tables: &mut LeaseTables) {
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() < 5 {
        return;
    }
    let Ok(valid_time) = fields[4].parse::<i64>() else {
        return;
    };
    if valid_time == 0 || (valid_time > 0 && valid_time < now) {
        return;
    }
    let hostname = if fields[3] == "-" || fields[3].starts_with(r"broken\x20") {
        ""
    } else {
        fields[3]
    };
    if fields.len() >= 8 && fields[2] == "ipv4" {
        let Some(mac) = parse_mac(fields[1]) else {
            return;
        };
        let address = fields[7].split('/').next().unwrap_or_default();
        let Ok(address) = address.parse::<IpAddr>() else {
            return;
        };
        insert_lease(tables, address, Some(mac), hostname);
        return;
    }
    let mac = parse_hex_bytes(fields[1])
        .and_then(|duid| extract_mac_from_duid(&duid));
    for field in fields.iter().skip(7) {
        let address = field.split('/').next().unwrap_or_default();
        if let Ok(address) = address.parse::<IpAddr>() {
            insert_lease(tables, address, mac.clone(), hostname);
        }
    }
}

fn parse_isc_dhcpd(contents: &str, tables: &mut LeaseTables) {
    let mut current_ip = None;
    let mut current_mac = None;
    let mut current_hostname = String::new();
    let mut current_active = false;
    let mut in_lease = false;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.starts_with("lease ") && line.ends_with('{') {
            current_ip = line
                .strip_prefix("lease ")
                .and_then(|value| value.strip_suffix('{'))
                .and_then(|value| value.trim().parse::<IpAddr>().ok());
            if current_ip.is_some() {
                in_lease = true;
                current_mac = None;
                current_hostname.clear();
                current_active = false;
            }
            continue;
        }
        if line == "}" && in_lease {
            let address = current_ip.expect("active lease has an address");
            if current_active {
                if let Some(mac) = current_mac.take() {
                    insert_lease(tables, address, Some(mac), &current_hostname);
                }
            } else {
                tables.ip_to_mac.remove(&address);
                tables.ip_to_hostname.remove(&address);
            }
            in_lease = false;
            continue;
        }
        if !in_lease {
            continue;
        }
        if let Some(value) = line.strip_prefix("hardware ethernet ") {
            current_mac = parse_mac(value.trim_end_matches(';'));
        } else if let Some(value) = line.strip_prefix("client-hostname ") {
            current_hostname =
                value.trim_end_matches(';').trim_matches('"').to_owned();
        } else if let Some(value) = line.strip_prefix("binding state ") {
            current_active = value.trim_end_matches(';') == "active";
        }
    }
}

fn parse_kea_csv4(contents: &str, tables: &mut LeaseTables) {
    for line in contents.lines().skip(1) {
        let fields: Vec<_> = line.split(',').collect();
        if fields.len() < 10 || fields[9] != "0" {
            continue;
        }
        let (Ok(address), Some(mac)) =
            (fields[0].parse::<IpAddr>(), parse_mac(fields[1]))
        else {
            continue;
        };
        let hostname = fields.get(8).copied().unwrap_or_default();
        insert_lease(tables, address, Some(mac), hostname);
    }
}

fn parse_kea_csv6(contents: &str, tables: &mut LeaseTables) {
    for line in contents.lines().skip(1) {
        let fields: Vec<_> = line.split(',').collect();
        if fields.len() < 14 || fields[13] != "0" {
            continue;
        }
        let Ok(address) = fields[0].parse::<IpAddr>() else {
            continue;
        };
        let mac = (!fields[12].is_empty())
            .then(|| parse_mac(fields[12]))
            .flatten()
            .or_else(|| {
                parse_hex_bytes(fields[1])
                    .and_then(|duid| extract_mac_from_duid(&duid))
            });
        let hostname = fields.get(11).copied().unwrap_or_default();
        insert_lease(tables, address, mac, hostname);
    }
}

fn parse_bootpd_leases(contents: &str, tables: &mut LeaseTables) {
    let now = unix_time();
    let mut name = String::new();
    let mut address = None;
    let mut mac = None;
    let mut lease = 0_i64;
    let mut in_block = false;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line == "{" {
            in_block = true;
            name.clear();
            address = None;
            mac = None;
            lease = 0;
            continue;
        }
        if line == "}" && in_block {
            if (lease == 0 || lease >= now)
                && let (Some(address), Some(mac)) = (address, mac.take())
            {
                insert_lease(tables, address, Some(mac), &name);
            }
            in_block = false;
            continue;
        }
        if !in_block {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "name" => name = value.to_owned(),
            "ip_address" => address = value.parse().ok(),
            "hw_address" => {
                mac = value.strip_prefix("1,").and_then(parse_mac);
            }
            "lease" => {
                lease = i64::from_str_radix(value.trim_start_matches("0x"), 16)
                    .unwrap_or_default();
            }
            _ => {}
        }
    }
}

fn lookup_addresses_by_hostname(
    hostname: &str,
    state: &NeighborState,
) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    let mut add = |address: IpAddr| {
        if is_scoped_ipv6(address) || !seen.insert(address) {
            return;
        }
        result.push(address);
    };
    for (&address, entry_hostname) in &state.ip_to_hostname {
        if entry_hostname.eq_ignore_ascii_case(hostname) {
            add(address);
        }
    }
    for (mac, entry_hostname) in &state.mac_to_hostname {
        if !entry_hostname.eq_ignore_ascii_case(hostname) {
            continue;
        }
        for table in [&state.neighbor_ip_to_mac, &state.lease_ip_to_mac] {
            for (&address, entry_mac) in table {
                if format_mac(entry_mac) == *mac {
                    add(address);
                }
            }
        }
    }
    result
}

fn is_scoped_ipv6(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(_) => false,
        IpAddr::V6(address) => {
            let segments = address.segments();
            segments[0] & 0xffc0 == 0xfe80
        }
    }
}

fn extract_mac_from_duid(duid: &[u8]) -> Option<Vec<u8>> {
    if duid.len() < 4 || u16::from_be_bytes([duid[2], duid[3]]) != 1 {
        return None;
    }
    match u16::from_be_bytes([duid[0], duid[1]]) {
        1 if duid.len() >= 14 => Some(duid[8..14].to_vec()),
        3 if duid.len() >= 10 => Some(duid[4..10].to_vec()),
        _ => None,
    }
}

fn extract_mac_from_eui64(address: IpAddr) -> Option<Vec<u8>> {
    let IpAddr::V6(address) = address else {
        return None;
    };
    let bytes = address.octets();
    if bytes[11] != 0xff || bytes[12] != 0xfe {
        return None;
    }
    Some(vec![
        bytes[8] ^ 0x02,
        bytes[9],
        bytes[10],
        bytes[13],
        bytes[14],
        bytes[15],
    ])
}

fn parse_hex_bytes(value: &str) -> Option<Vec<u8>> {
    hex::decode(value.replace(':', "")).ok()
}

fn parse_mac(value: &str) -> Option<Vec<u8>> {
    let cleaned = value.replace([':', '-'], "");
    if cleaned.len() < 12 || !cleaned.len().is_multiple_of(2) {
        return None;
    }
    hex::decode(cleaned).ok()
}

fn format_mac(mac: &[u8]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{
        collections::HashMap,
        io, mem,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
        sync::Weak,
    };

    use super::{NativeNeighborResolver, REFRESH_INTERVAL};

    const DEFAULT_LEASE_FILES: &[&str] = &[
        "/tmp/dhcp.leases",
        "/var/lib/dhcp/dhcpd.leases",
        "/var/lib/dhcpd/dhcpd.leases",
        "/var/lib/kea/kea-leases4.csv",
        "/var/lib/kea/kea-leases6.csv",
    ];
    const NLMSG_DONE: u16 = 3;
    const NLMSG_ERROR: u16 = 2;
    const RTM_NEWNEIGH: u16 = 28;
    const RTM_GETNEIGH: u16 = 30;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_DUMP: u16 = 0x300;
    const NDA_DST: u16 = 1;
    const NDA_LLADDR: u16 = 2;

    pub(super) fn default_lease_files() -> &'static [&'static str] {
        DEFAULT_LEASE_FILES
    }

    pub(super) fn start_monitor(resolver: Weak<NativeNeighborResolver>) {
        let _ = std::thread::Builder::new()
            .name("singbox-neighbor".into())
            .spawn(move || monitor(resolver));
    }

    fn monitor(resolver: Weak<NativeNeighborResolver>) {
        let socket = subscribe_socket().ok();
        let mut buffer = vec![0_u8; 65_536];
        loop {
            if resolver.strong_count() == 0 {
                break;
            }
            let changed = if let Some(fd) = &socket {
                (unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        0,
                    )
                }) > 0
            } else {
                std::thread::sleep(REFRESH_INTERVAL);
                false
            };
            let Some(resolver) = resolver.upgrade() else {
                break;
            };
            if changed {
                resolver.neighbor_changed();
            } else {
                resolver.refresh(false);
            }
        }
    }

    fn subscribe_socket() -> io::Result<OwnedFd> {
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = 1 << (libc::RTNLGRP_NEIGH - 1);
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const address).cast(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        set_receive_timeout(fd.as_raw_fd(), REFRESH_INTERVAL);
        Ok(fd)
    }

    fn set_receive_timeout(fd: libc::c_int, timeout: std::time::Duration) {
        let timeout = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        let _ = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const timeout).cast(),
                mem::size_of_val(&timeout) as libc::socklen_t,
            )
        };
    }

    pub(super) fn read_neighbor_table() -> io::Result<HashMap<IpAddr, Vec<u8>>>
    {
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const address).cast(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        set_receive_timeout(fd.as_raw_fd(), std::time::Duration::from_secs(1));
        let mut request = [0_u8; 28];
        request[0..4].copy_from_slice(&28_u32.to_ne_bytes());
        request[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
        request[6..8]
            .copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
        request[16] = libc::AF_UNSPEC as u8;
        let sent = unsafe {
            libc::send(
                fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut result = HashMap::new();
        let mut buffer = vec![0_u8; 65_536];
        loop {
            let count = unsafe {
                libc::recv(
                    fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut offset = 0;
            let count = count as usize;
            while offset + 16 <= count {
                let length = read_u32(&buffer[offset..offset + 4]) as usize;
                if length < 16 || offset + length > count {
                    break;
                }
                let kind = read_u16(&buffer[offset + 4..offset + 6]);
                if kind == NLMSG_DONE {
                    return Ok(result);
                }
                if kind == NLMSG_ERROR {
                    if length >= 20 {
                        let code = i32::from_ne_bytes(
                            buffer[offset + 16..offset + 20]
                                .try_into()
                                .expect("netlink error size"),
                        );
                        if code != 0 {
                            return Err(io::Error::from_raw_os_error(-code));
                        }
                    }
                } else if kind == RTM_NEWNEIGH {
                    parse_neighbor_message(
                        &buffer[offset..offset + length],
                        &mut result,
                    );
                }
                offset += align4(length);
            }
        }
    }

    fn parse_neighbor_message(
        message: &[u8],
        table: &mut HashMap<IpAddr, Vec<u8>>,
    ) {
        if message.len() < 28 {
            return;
        }
        let family = message[16] as i32;
        let mut address = None;
        let mut mac = None;
        let mut offset = 28;
        while offset + 4 <= message.len() {
            let length = read_u16(&message[offset..offset + 2]) as usize;
            let kind = read_u16(&message[offset + 2..offset + 4]);
            if length < 4 || offset + length > message.len() {
                break;
            }
            let value = &message[offset + 4..offset + length];
            match (kind, family, value.len()) {
                (NDA_DST, libc::AF_INET, 4) => {
                    address = Some(IpAddr::V4(Ipv4Addr::new(
                        value[0], value[1], value[2], value[3],
                    )));
                }
                (NDA_DST, libc::AF_INET6, 16) => {
                    address = Some(IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(value)
                            .expect("IPv6 attribute size"),
                    )));
                }
                (NDA_LLADDR, _, length) if length > 0 => {
                    mac = Some(value.to_vec())
                }
                _ => {}
            }
            offset += align4(length);
        }
        if let (Some(address), Some(mac)) = (address, mac) {
            table.insert(address, mac);
        }
    }

    fn read_u16(value: &[u8]) -> u16 {
        u16::from_ne_bytes(value.try_into().expect("u16 size"))
    }

    fn read_u32(value: &[u8]) -> u32 {
        u32::from_ne_bytes(value.try_into().expect("u32 size"))
    }

    const fn align4(value: usize) -> usize {
        (value + 3) & !3
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_neighbor_netlink_message() {
            let mut message = vec![0_u8; 48];
            message[0..4].copy_from_slice(&48_u32.to_ne_bytes());
            message[4..6].copy_from_slice(&RTM_NEWNEIGH.to_ne_bytes());
            message[16] = libc::AF_INET as u8;
            message[28..30].copy_from_slice(&8_u16.to_ne_bytes());
            message[30..32].copy_from_slice(&NDA_DST.to_ne_bytes());
            message[32..36].copy_from_slice(&[192, 0, 2, 8]);
            message[36..38].copy_from_slice(&10_u16.to_ne_bytes());
            message[38..40].copy_from_slice(&NDA_LLADDR.to_ne_bytes());
            message[40..46].copy_from_slice(&[2, 0, 0, 0, 0, 8]);
            let mut table = HashMap::new();
            parse_neighbor_message(&message, &mut table);
            assert_eq!(
                table.get(&"192.0.2.8".parse().unwrap()).unwrap(),
                &[2, 0, 0, 0, 0, 8]
            );
        }

        #[test]
        fn reads_live_neighbor_table() {
            read_neighbor_table().unwrap();
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{
        collections::HashMap,
        io, mem,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
        ptr,
        sync::Weak,
    };

    use super::{NativeNeighborResolver, REFRESH_INTERVAL};

    const DEFAULT_LEASE_FILES: &[&str] =
        &["/var/db/dhcpd_leases", "/tmp/dhcp.leases"];
    const ROUTE_HEADER_SIZE: usize = 0x5c;
    const RTM_VERSION: u8 = 5;
    const RTAX_MAX: usize = 8;
    const RTAX_DST: usize = 0;
    const RTAX_GATEWAY: usize = 1;

    pub(super) fn default_lease_files() -> &'static [&'static str] {
        DEFAULT_LEASE_FILES
    }

    pub(super) fn start_monitor(resolver: Weak<NativeNeighborResolver>) {
        let _ = std::thread::Builder::new()
            .name("singbox-neighbor".into())
            .spawn(move || monitor(resolver));
    }

    fn monitor(resolver: Weak<NativeNeighborResolver>) {
        let socket = subscribe_socket().ok();
        let mut buffer = vec![0_u8; 65_536];
        loop {
            if resolver.strong_count() == 0 {
                break;
            }
            let changed = if let Some(fd) = &socket {
                (unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        0,
                    )
                }) > 0
            } else {
                std::thread::sleep(REFRESH_INTERVAL);
                false
            };
            let Some(resolver) = resolver.upgrade() else {
                break;
            };
            if changed {
                resolver.neighbor_changed();
            } else {
                resolver.refresh(false);
            }
        }
    }

    fn subscribe_socket() -> io::Result<OwnedFd> {
        let raw_fd = unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, 0) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        if flags >= 0 {
            let _ = unsafe {
                libc::fcntl(
                    fd.as_raw_fd(),
                    libc::F_SETFD,
                    flags | libc::FD_CLOEXEC,
                )
            };
        }
        let timeout = libc::timeval {
            tv_sec: REFRESH_INTERVAL.as_secs() as libc::time_t,
            tv_usec: REFRESH_INTERVAL.subsec_micros() as libc::suseconds_t,
        };
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const timeout).cast(),
                mem::size_of_val(&timeout) as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    pub(super) fn read_neighbor_table() -> io::Result<HashMap<IpAddr, Vec<u8>>>
    {
        let mut table = HashMap::new();
        for family in [libc::AF_INET, libc::AF_INET6] {
            let data = fetch_rib(family)?;
            parse_rib(&data, &mut table);
        }
        Ok(table)
    }

    fn fetch_rib(family: libc::c_int) -> io::Result<Vec<u8>> {
        let mut mib = [
            libc::CTL_NET,
            libc::PF_ROUTE,
            0,
            family,
            libc::NET_RT_FLAGS,
            libc::RTF_LLINFO,
        ];
        loop {
            let mut length = 0_usize;
            let result = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as u32,
                    ptr::null_mut(),
                    &mut length,
                    ptr::null_mut(),
                    0,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut data = vec![0_u8; length];
            let result = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as u32,
                    data.as_mut_ptr().cast(),
                    &mut length,
                    ptr::null_mut(),
                    0,
                )
            };
            if result == 0 {
                data.truncate(length);
                return Ok(data);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOMEM) {
                return Err(error);
            }
        }
    }

    fn parse_rib(data: &[u8], table: &mut HashMap<IpAddr, Vec<u8>>) {
        let mut offset = 0;
        while offset + ROUTE_HEADER_SIZE <= data.len() {
            let length =
                u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;
            if length < ROUTE_HEADER_SIZE || offset + length > data.len() {
                break;
            }
            let message = &data[offset..offset + length];
            if message[2] == RTM_VERSION
                && i32::from_ne_bytes(message[28..32].try_into().unwrap()) == 0
            {
                let addrs =
                    i32::from_ne_bytes(message[12..16].try_into().unwrap());
                if let Some((address, mac)) =
                    parse_addresses(addrs, &message[ROUTE_HEADER_SIZE..])
                {
                    table.insert(address, mac);
                }
            }
            offset += length;
        }
    }

    fn parse_addresses(addrs: i32, data: &[u8]) -> Option<(IpAddr, Vec<u8>)> {
        let mut offset = 0;
        let mut destination = None;
        let mut gateway = None;
        for index in 0..RTAX_MAX {
            if addrs & (1 << index) == 0 {
                continue;
            }
            if offset + 2 > data.len() {
                return None;
            }
            let length = data[offset] as usize;
            let step = align4(length);
            if length == 0
                || offset + length > data.len()
                || offset + step > data.len()
            {
                return None;
            }
            let address = &data[offset..offset + length];
            if index == RTAX_DST {
                destination = parse_ip(address);
            } else if index == RTAX_GATEWAY {
                gateway = parse_link_address(address);
            }
            offset += step;
        }
        Some((destination?, gateway?))
    }

    fn parse_ip(address: &[u8]) -> Option<IpAddr> {
        match address.get(1).copied()? as i32 {
            libc::AF_INET
                if address.len() >= mem::size_of::<libc::sockaddr_in>() =>
            {
                Some(IpAddr::V4(Ipv4Addr::new(
                    address[4], address[5], address[6], address[7],
                )))
            }
            libc::AF_INET6
                if address.len() >= mem::size_of::<libc::sockaddr_in6>() =>
            {
                Some(IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&address[8..24]).ok()?,
                )))
            }
            _ => None,
        }
    }

    fn parse_link_address(address: &[u8]) -> Option<Vec<u8>> {
        if address.get(1).copied()? as i32 != libc::AF_LINK || address.len() < 8
        {
            return None;
        }
        let name_length = address[5] as usize;
        let address_length = address[6] as usize;
        if address_length < 6
            || 8 + name_length + address_length > address.len()
        {
            return None;
        }
        Some(
            address[8 + name_length..8 + name_length + address_length].to_vec(),
        )
    }

    const fn align4(value: usize) -> usize {
        if value == 0 { 4 } else { (value + 3) & !3 }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_darwin_sockaddrs() {
            let mut addresses = vec![0_u8; 36];
            addresses[0] = 16;
            addresses[1] = libc::AF_INET as u8;
            addresses[4..8].copy_from_slice(&[192, 0, 2, 9]);
            addresses[16] = 20;
            addresses[17] = libc::AF_LINK as u8;
            addresses[21] = 2;
            addresses[22] = 6;
            addresses[26..32].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
            assert_eq!(
                parse_addresses(3, &addresses),
                Some(("192.0.2.9".parse().unwrap(), vec![2, 0, 0, 0, 0, 9]))
            );
        }

        #[test]
        fn reads_live_neighbor_table() {
            read_neighbor_table().unwrap();
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use std::{collections::HashMap, io, net::IpAddr, sync::Weak};

    use super::NativeNeighborResolver;

    pub(super) fn default_lease_files() -> &'static [&'static str] {
        &[]
    }

    pub(super) fn start_monitor(_resolver: Weak<NativeNeighborResolver>) {}

    pub(super) fn read_neighbor_table() -> io::Result<HashMap<IpAddr, Vec<u8>>>
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native neighbor resolver is unavailable",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_duid_and_eui64_mac_addresses() {
        assert_eq!(
            extract_mac_from_duid(&[0, 1, 0, 1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7]),
            Some(vec![2, 3, 4, 5, 6, 7])
        );
        assert_eq!(
            extract_mac_from_duid(&[0, 3, 0, 1, 10, 11, 12, 13, 14, 15]),
            Some(vec![10, 11, 12, 13, 14, 15])
        );
        assert_eq!(
            extract_mac_from_eui64("fe80::ff:fe00:9".parse().unwrap()),
            Some(vec![2, 0, 0, 0, 0, 9])
        );
    }

    #[test]
    fn parses_dnsmasq_and_odhcpd_leases() {
        let future = unix_time() + 3600;
        let input = format!(
            "{future} 02:00:00:00:00:01 192.0.2.1 laptop *\n# 1 020000000002 ipv4 phone {future} 0 0 192.0.2.2/32\n"
        );
        let mut tables = LeaseTables::default();
        parse_dnsmasq_odhcpd(&input, &mut tables);
        assert_eq!(
            tables.ip_to_hostname.get(&"192.0.2.1".parse().unwrap()),
            Some(&"laptop".to_owned())
        );
        assert_eq!(
            tables.ip_to_mac.get(&"192.0.2.2".parse().unwrap()),
            Some(&vec![2, 0, 0, 0, 0, 2])
        );
    }

    #[test]
    fn parses_isc_kea_and_bootpd_leases() {
        let mut tables = LeaseTables::default();
        parse_isc_dhcpd(
            r#"lease 192.0.2.3 {
  binding state active;
  hardware ethernet 02:00:00:00:00:03;
  client-hostname "desktop";
}"#,
            &mut tables,
        );
        parse_kea_csv4(
            "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n192.0.2.4,02:00:00:00:00:04,,,,,,,tablet,0\n",
            &mut tables,
        );
        parse_bootpd_leases(
            r#"{
name=macbook
ip_address=192.0.2.5
hw_address=1,02:00:00:00:00:05
lease=0x0
}"#,
            &mut tables,
        );
        for (address, hostname) in [
            ("192.0.2.3", "desktop"),
            ("192.0.2.4", "tablet"),
            ("192.0.2.5", "macbook"),
        ] {
            assert_eq!(
                tables.ip_to_hostname.get(&address.parse().unwrap()),
                Some(&hostname.to_owned())
            );
        }
    }

    #[test]
    fn hostname_lookup_joins_neighbor_and_lease_tables() {
        let mut state = NeighborState::default();
        state
            .mac_to_hostname
            .insert("02:00:00:00:00:06".into(), "printer".into());
        state
            .neighbor_ip_to_mac
            .insert("192.0.2.6".parse().unwrap(), vec![2, 0, 0, 0, 0, 6]);
        state
            .ip_to_hostname
            .insert("fe80::1".parse().unwrap(), "printer".into());
        assert_eq!(
            lookup_addresses_by_hostname("PRINTER", &state),
            vec!["192.0.2.6".parse::<IpAddr>().unwrap()]
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_resolver_tracks_configured_relative_lease_file() {
        let directory = tempfile::tempdir().unwrap();
        let lease = directory.path().join("dhcp.leases");
        fs::write(
            &lease,
            format!(
                "{} 02:00:00:00:00:07 192.0.2.7 console *\n",
                unix_time() + 60
            ),
        )
        .unwrap();
        let resolver = NativeNeighborResolver::new(
            &["dhcp.leases".into()],
            directory.path(),
        );
        assert_eq!(
            resolver.lookup_hostname("192.0.2.7".parse().unwrap()),
            Some("console".into())
        );
        assert_eq!(
            resolver.lookup_mac("192.0.2.7".parse().unwrap()),
            Some(vec![2, 0, 0, 0, 0, 7])
        );
        assert_eq!(
            resolver.lookup_addresses("CONSOLE."),
            vec!["192.0.2.7".parse::<IpAddr>().unwrap()]
        );
    }
}
