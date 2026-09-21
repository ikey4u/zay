//! DHCPv4-discovered DNS transport.

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "illumos",
    target_os = "solaris"
))]
use std::num::NonZeroU32;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use futures_util::{StreamExt as _, stream::FuturesUnordered};
use hickory_proto::op::Message;
use n0_watcher::Watcher as _;
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig as _};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{net::UdpSocket, sync::Mutex, time::Instant};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::Dialer,
    common::network::SocksAddr,
    constant,
    dns::{
        client::{ExchangeFuture, Transport},
        transport::UdpTransport,
    },
};

const CLIENT_PORT: u16 = 68;
const SERVER_PORT: u16 = 67;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

pub struct DhcpTransport {
    tag: String,
    interface: String,
    dialer: Arc<dyn Dialer>,
    state: Arc<Mutex<Option<CachedLease>>>,
    monitor_started: Arc<AtomicBool>,
    cancellation: CancellationToken,
}

struct CachedLease {
    updated_at: Instant,
    interface: SelectedInterface,
    lease: DhcpLease,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DhcpLease {
    servers: Vec<Ipv4Addr>,
    search: Vec<String>,
}

impl DhcpTransport {
    pub fn new(
        tag: impl Into<String>,
        interface: impl Into<String>,
        dialer: Arc<dyn Dialer>,
    ) -> Self {
        Self {
            tag: tag.into(),
            interface: interface.into(),
            dialer,
            state: Arc::new(Mutex::new(None)),
            monitor_started: Arc::new(AtomicBool::new(false)),
            cancellation: CancellationToken::new(),
        }
    }

    async fn servers(&self) -> io::Result<Vec<Ipv4Addr>> {
        self.ensure_interface_monitor();
        let mut state = self.state.lock().await;
        let interface = select_interface(&self.interface)?;
        if let Some(cached) = state.as_ref()
            && cached.updated_at.elapsed() < constant::DHCP_TTL
            && cached.interface == interface
        {
            return Ok(cached.lease.servers.clone());
        }
        let transaction_id = random_transaction_id()?;
        let request = build_discover(transaction_id, interface.mac);
        let socket = dhcp_socket(&interface)?;
        socket
            .send_to(
                &request,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), SERVER_PORT),
            )
            .await?;
        let deadline = Instant::now() + constant::DHCP_TIMEOUT;
        let mut buffer = vec![0_u8; 65_535];
        let lease = loop {
            let (size, _) = tokio::time::timeout_at(
                deadline,
                socket.recv_from(&mut buffer),
            )
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "DHCP query timed out")
            })??;
            match parse_offer(&buffer[..size], transaction_id) {
                Ok(lease) if !lease.servers.is_empty() => break lease,
                Ok(_) => continue,
                Err(_) => continue,
            }
        };
        let servers = lease.servers.clone();
        *state = Some(CachedLease {
            updated_at: Instant::now(),
            interface,
            lease,
        });
        Ok(servers)
    }

    fn ensure_interface_monitor(&self) {
        if !self.interface.is_empty()
            || self
                .monitor_started
                .compare_exchange(
                    false,
                    true,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return;
        }
        let state = self.state.clone();
        let started = self.monitor_started.clone();
        let cancellation = self.cancellation.clone();
        tokio::spawn(async move {
            let Ok(monitor) =
                crate::common::network_monitor::NetworkMonitor::new().await
            else {
                started.store(false, Ordering::Release);
                return;
            };
            let mut watcher = monitor.interface_state();
            let mut previous = watcher.get();
            loop {
                let current = tokio::select! {
                    _ = cancellation.cancelled() => return,
                    update = watcher.updated() => match update {
                        Ok(current) => current,
                        Err(_) => {
                            started.store(false, Ordering::Release);
                            return;
                        }
                    },
                };
                let changed = current.is_major_change(&previous);
                previous = current;
                if changed {
                    state.lock().await.take();
                }
            }
        });
    }
}

impl Drop for DhcpTransport {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl Transport for DhcpTransport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn exchange<'a>(&'a self, message: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let servers = self.servers().await?;
            let attempts = FuturesUnordered::new();
            for server in servers {
                let dialer = self.dialer.clone();
                let message = message.clone();
                attempts.push(async move {
                    UdpTransport::new(
                        "",
                        SocksAddr::from(SocketAddr::new(
                            IpAddr::V4(server),
                            53,
                        )),
                        dialer,
                    )
                    .exchange(&message)
                    .await
                });
            }
            futures_util::pin_mut!(attempts);
            let mut last_error = None;
            while let Some(result) = attempts.next().await {
                match result {
                    Ok(response) => return Ok(response),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "DHCP response contained no DNS servers",
                )
            }))
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SelectedInterface {
    index: u32,
    mac: [u8; 6],
    ipv4: Ipv4Addr,
}

fn select_interface(requested: &str) -> io::Result<SelectedInterface> {
    let interfaces = NetworkInterface::show().map_err(io::Error::other)?;
    let default_address =
        requested.is_empty().then(default_ipv4_address).flatten();
    let interface = interfaces
        .into_iter()
        .filter(|interface| {
            (requested.is_empty() || interface.name == requested)
                && (!interface.internal || !requested.is_empty())
        })
        .filter_map(|interface| {
            let mac = parse_mac(interface.mac_addr.as_deref()?)?;
            let ipv4 = interface
                .addr
                .iter()
                .filter_map(|address| match address {
                    Addr::V4(v4) if !v4.ip.is_loopback() => Some(v4.ip),
                    _ => None,
                })
                .min_by_key(|address| Some(*address) != default_address)?;
            Some(SelectedInterface {
                index: interface.index,
                mac,
                ipv4,
            })
        })
        .min_by_key(|interface| Some(interface.ipv4) != default_address)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                if requested.is_empty() {
                    "no usable DHCP interface with an IPv4 address and MAC"
                        .to_owned()
                } else {
                    format!("DHCP interface {requested:?} is not usable")
                },
            )
        })?;
    Ok(interface)
}

fn default_ipv4_address() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(address) if !address.is_unspecified() => Some(address),
        _ => None,
    }
}

fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let values = value
        .split([':', '-'])
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    values.try_into().ok()
}

fn random_transaction_id() -> io::Result<u32> {
    let mut bytes = [0_u8; 4];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok(u32::from_be_bytes(bytes))
}

fn build_discover(transaction_id: u32, mac: [u8; 6]) -> Vec<u8> {
    let mut packet = vec![0_u8; 240];
    packet[0] = 1;
    packet[1] = 1;
    packet[2] = 6;
    packet[4..8].copy_from_slice(&transaction_id.to_be_bytes());
    packet[10..12].copy_from_slice(&0x8000_u16.to_be_bytes());
    packet[28..34].copy_from_slice(&mac);
    packet[236..240].copy_from_slice(&MAGIC_COOKIE);
    packet.extend_from_slice(&[53, 1, 1]);
    packet.extend_from_slice(&[55, 3, 15, 6, 119]);
    packet.push(255);
    packet
}

fn parse_offer(packet: &[u8], transaction_id: u32) -> io::Result<DhcpLease> {
    if packet.len() < 240
        || packet[0] != 2
        || packet[4..8] != transaction_id.to_be_bytes()
        || packet[236..240] != MAGIC_COOKIE
    {
        return Err(invalid_data("invalid DHCP offer header"));
    }
    let mut options = ParsedOptions::default();
    parse_options(&packet[240..], &mut options)?;
    if options.overload & 1 != 0 {
        parse_options(&packet[108..236], &mut options)?;
    }
    if options.overload & 2 != 0 {
        parse_options(&packet[44..108], &mut options)?;
    }
    if options.message_type != Some(2) {
        return Err(invalid_data("DHCP response is not an OFFER"));
    }
    let search = options
        .search
        .filter(|search| !search.is_empty())
        .or_else(|| options.domain.map(|domain| vec![domain]))
        .unwrap_or_default();
    options.servers.sort_unstable();
    options.servers.dedup();
    Ok(DhcpLease {
        servers: options.servers,
        search,
    })
}

#[derive(Default)]
struct ParsedOptions {
    message_type: Option<u8>,
    servers: Vec<Ipv4Addr>,
    domain: Option<String>,
    search: Option<Vec<String>>,
    overload: u8,
}

fn parse_options(bytes: &[u8], options: &mut ParsedOptions) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let code = bytes[offset];
        offset += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            break;
        }
        let length = *bytes
            .get(offset)
            .ok_or_else(|| invalid_data("truncated DHCP option length"))?
            as usize;
        offset += 1;
        let value = bytes
            .get(offset..offset + length)
            .ok_or_else(|| invalid_data("truncated DHCP option value"))?;
        offset += length;
        match code {
            52 if value.len() == 1 => options.overload = value[0],
            53 if value.len() == 1 => options.message_type = Some(value[0]),
            6 if value.len() % 4 == 0 => {
                options.servers.extend(value.chunks_exact(4).map(|address| {
                    Ipv4Addr::new(
                        address[0], address[1], address[2], address[3],
                    )
                }));
            }
            15 => {
                options.domain = std::str::from_utf8(value)
                    .ok()
                    .map(canonical_search_domain);
            }
            119 => options.search = Some(decode_search_list(value)?),
            _ => {}
        }
    }
    Ok(())
}

fn decode_search_list(bytes: &[u8]) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let (name, consumed) = decode_search_name(bytes, offset, 0)?;
        if consumed == 0 {
            return Err(invalid_data("empty DHCP search-list name"));
        }
        offset += consumed;
        if !name.is_empty() {
            names.push(canonical_search_domain(&name));
        }
    }
    Ok(names)
}

fn decode_search_name(
    bytes: &[u8],
    start: usize,
    depth: usize,
) -> io::Result<(String, usize)> {
    if depth > 16 {
        return Err(invalid_data("DHCP search-list compression loop"));
    }
    let mut labels = Vec::new();
    let mut offset = start;
    let mut consumed = 0;
    loop {
        let length = *bytes
            .get(offset)
            .ok_or_else(|| invalid_data("truncated DHCP search-list name"))?;
        offset += 1;
        consumed += 1;
        if length == 0 {
            break;
        }
        if length & 0xc0 == 0xc0 {
            let low = *bytes.get(offset).ok_or_else(|| {
                invalid_data("truncated DHCP search-list pointer")
            })?;
            consumed += 1;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(low);
            let (suffix, _) = decode_search_name(bytes, pointer, depth + 1)?;
            if !suffix.is_empty() {
                labels.push(suffix);
            }
            break;
        }
        if length & 0xc0 != 0 {
            return Err(invalid_data("invalid DHCP search-list label"));
        }
        let label = bytes
            .get(offset..offset + usize::from(length))
            .ok_or_else(|| invalid_data("truncated DHCP search-list label"))?;
        labels.push(
            std::str::from_utf8(label)
                .map_err(|_| invalid_data("non-UTF-8 DHCP search-list label"))?
                .to_owned(),
        );
        offset += usize::from(length);
        consumed += usize::from(length);
    }
    Ok((labels.join("."), consumed))
}

fn canonical_search_domain(domain: &str) -> String {
    let domain = domain.trim_matches('.');
    if domain.is_empty() {
        String::new()
    } else {
        format!("{}.", domain.to_ascii_lowercase())
    }
}

fn dhcp_socket(interface: &SelectedInterface) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;
    bind_interface(&socket, interface)?;
    let bind_address = if cfg!(any(target_os = "linux", target_os = "android"))
    {
        Ipv4Addr::BROADCAST
    } else {
        Ipv4Addr::UNSPECIFIED
    };
    socket.bind(&SockAddr::from(SocketAddr::new(
        IpAddr::V4(bind_address),
        CLIENT_PORT,
    )))?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "illumos",
    target_os = "solaris"
))]
fn bind_interface(
    socket: &Socket,
    interface: &SelectedInterface,
) -> io::Result<()> {
    socket.bind_device_by_index_v4(NonZeroU32::new(interface.index))
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "illumos",
    target_os = "solaris"
)))]
fn bind_interface(
    _socket: &Socket,
    _interface: &SelectedInterface,
) -> io::Result<()> {
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{
        MAGIC_COOKIE, build_discover, decode_search_list, parse_mac,
        parse_offer,
    };

    #[test]
    fn discover_requests_dns_and_search_options() {
        let packet = build_discover(0x1234_5678, [0, 1, 2, 3, 4, 5]);
        assert_eq!(&packet[4..8], &0x1234_5678_u32.to_be_bytes());
        assert_eq!(&packet[28..34], &[0, 1, 2, 3, 4, 5]);
        assert_eq!(&packet[236..240], &MAGIC_COOKIE);
        assert!(packet.windows(5).any(|value| value == [55, 3, 15, 6, 119]));
    }

    #[test]
    fn offer_extracts_dns_domain_and_compressed_search_list() {
        let mut packet = vec![0_u8; 240];
        packet[0] = 2;
        packet[4..8].copy_from_slice(&7_u32.to_be_bytes());
        packet[236..240].copy_from_slice(&MAGIC_COOKIE);
        packet.extend_from_slice(&[53, 1, 2]);
        packet.extend_from_slice(&[6, 8, 1, 1, 1, 1, 8, 8, 8, 8]);
        let search = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0, 3, b'l', b'a', b'n', 0xc0, 0,
        ];
        packet.push(119);
        packet.push(search.len() as u8);
        packet.extend_from_slice(&search);
        packet.push(255);
        let lease = parse_offer(&packet, 7).unwrap();
        assert_eq!(
            lease.servers,
            [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
        );
        assert_eq!(lease.search, ["example.com.", "lan.example.com."]);
    }

    #[test]
    fn parses_common_mac_formats_and_rejects_invalid_values() {
        assert_eq!(
            parse_mac("00:11:22:aa:bb:cc"),
            Some([0, 17, 34, 170, 187, 204])
        );
        assert_eq!(
            parse_mac("00-11-22-AA-BB-CC"),
            Some([0, 17, 34, 170, 187, 204])
        );
        assert_eq!(parse_mac("00:11"), None);
        assert!(decode_search_list(&[0xc0, 0]).is_err());
    }

    #[test]
    fn offer_parses_options_overloaded_into_bootp_file_field() {
        let mut packet = vec![0_u8; 240];
        packet[0] = 2;
        packet[4..8].copy_from_slice(&9_u32.to_be_bytes());
        packet[236..240].copy_from_slice(&MAGIC_COOKIE);
        packet.extend_from_slice(&[53, 1, 2, 52, 1, 1, 255]);
        packet[108..115].copy_from_slice(&[6, 4, 9, 9, 9, 9, 255]);
        let lease = parse_offer(&packet, 9).unwrap();
        assert_eq!(lease.servers, [Ipv4Addr::new(9, 9, 9, 9)]);
    }
}
