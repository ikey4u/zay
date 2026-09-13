//! Multicast DNS transport compatible with sing-box's `mdns` resolver.

#[cfg(unix)]
use std::{collections::BTreeMap, ffi::CStr, ptr};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use futures_util::{StreamExt as _, stream::FuturesUnordered};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Record, RecordType},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
#[cfg(not(unix))]
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig as _};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    net::UdpSocket,
    time::{Instant, timeout_at},
};

use crate::dns::client::{ExchangeFuture, Transport};

const MDNS_PORT: u16 = 5353;
const MDNS_TIMEOUT: Duration = Duration::from_secs(1);
const MDNS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const LOCAL_ZONES: &[&str] = &[
    "local",
    "254.169.in-addr.arpa",
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
];

pub struct MdnsTransport {
    tag: String,
    interfaces: Vec<String>,
}

impl MdnsTransport {
    pub fn new(tag: impl Into<String>, interfaces: Vec<String>) -> Self {
        Self {
            tag: tag.into(),
            interfaces,
        }
    }
}

pub fn is_local_domain(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    LOCAL_ZONES.iter().any(|zone| {
        domain == *zone
            || domain
                .strip_suffix(zone)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

impl Transport for MdnsTransport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn exchange<'a>(&'a self, message: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let question =
                message.queries.first().cloned().ok_or_else(|| {
                    invalid_data("mDNS request has no question")
                })?;
            let targets = query_targets(&self.interfaces)?;
            if targets.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "mDNS has no usable multicast interface",
                ));
            }
            let wire = encode_query(message)?;
            let queries = FuturesUnordered::new();
            for target in targets {
                let wire = wire.clone();
                let question = question.clone();
                queries.push(async move {
                    exchange_target(target, wire, question).await
                });
            }
            futures_util::pin_mut!(queries);
            let mut merged = new_response(message, &question);
            let mut last_error = None;
            while let Some(result) = queries.next().await {
                match result {
                    Ok(response) => merge_response(&mut merged, response),
                    Err(error) => last_error = Some(error),
                }
            }
            if has_records(&merged) {
                Ok(merged)
            } else if let Some(error) = last_error {
                Err(error)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mDNS query timed out",
                ))
            }
        })
    }

    fn preferred_domain(&self, domain: &str) -> Option<bool> {
        Some(is_local_domain(domain))
    }
}

#[derive(Clone)]
struct QueryTarget {
    name: String,
    index: u32,
    family: AddressFamily,
    ipv4_address: Option<Ipv4Addr>,
    networks: Vec<ipnet::IpNet>,
}

#[derive(Clone, Copy)]
enum AddressFamily {
    V4,
    V6,
}

async fn exchange_target(
    target: QueryTarget,
    wire: Vec<u8>,
    question: Query,
) -> io::Result<Message> {
    let (socket, destination) = multicast_socket(&target)?;
    socket.send_to(&wire, destination).await?;
    let mut merged = new_response_from_question(&question);
    let mut buffer = vec![0_u8; u16::MAX as usize];
    let deadline = Instant::now() + MDNS_TIMEOUT;
    loop {
        let received =
            timeout_at(deadline, socket.recv_from(&mut buffer)).await;
        let Ok(result) = received else {
            return if has_records(&merged) {
                Ok(merged)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("mDNS query timed out on {}", target.name),
                ))
            };
        };
        let (size, source) = result?;
        if !valid_source(source, &target) {
            continue;
        }
        let Ok(mut candidate) = decode_message(&buffer[..size]) else {
            continue;
        };
        if !valid_response(&candidate, &question) {
            continue;
        }
        normalize_response(&mut candidate, &question);
        merge_response(&mut merged, candidate);
    }
}

fn multicast_socket(
    target: &QueryTarget,
) -> io::Result<(UdpSocket, SocketAddr)> {
    let socket = match target.family {
        AddressFamily::V4 => {
            let socket =
                Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            socket.bind(&SockAddr::from(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
            )))?;
            socket.set_multicast_if_v4(&target.ipv4_address.ok_or_else(
                || invalid_data("mDNS IPv4 target has no interface address"),
            )?)?;
            socket.set_multicast_ttl_v4(255)?;
            (socket, SocketAddr::new(IpAddr::V4(MDNS_V4), MDNS_PORT))
        }
        AddressFamily::V6 => {
            let socket =
                Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            socket.bind(&SockAddr::from(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                0,
            )))?;
            socket.set_multicast_if_v6(target.index)?;
            socket.set_multicast_hops_v6(255)?;
            (
                socket,
                SocketAddr::V6(std::net::SocketAddrV6::new(
                    MDNS_V6,
                    MDNS_PORT,
                    0,
                    target.index,
                )),
            )
        }
    };
    socket.0.set_nonblocking(true)?;
    Ok((UdpSocket::from_std(socket.0.into())?, socket.1))
}

fn valid_source(source: SocketAddr, target: &QueryTarget) -> bool {
    source.port() == MDNS_PORT
        && matches!(
            (target.family, source.ip()),
            (AddressFamily::V4, IpAddr::V4(_))
                | (AddressFamily::V6, IpAddr::V6(_))
        )
        && target
            .networks
            .iter()
            .any(|network| network.contains(&source.ip()))
}

fn valid_response(response: &Message, question: &Query) -> bool {
    response.metadata.message_type == MessageType::Response
        && response.metadata.op_code == OpCode::Query
        && response.metadata.response_code == ResponseCode::NoError
        && (response
            .queries
            .iter()
            .any(|query| question_matches(query, question))
            || response
                .answers
                .iter()
                .chain(&response.authorities)
                .chain(&response.additionals)
                .any(|record| record_matches(record, question)))
}

fn question_matches(left: &Query, right: &Query) -> bool {
    left.name
        .to_utf8()
        .eq_ignore_ascii_case(&right.name.to_utf8())
        && left.query_type == right.query_type
        && left.query_class == right.query_class
}

fn record_matches(record: &Record, question: &Query) -> bool {
    record
        .name
        .to_utf8()
        .eq_ignore_ascii_case(&question.name.to_utf8())
        && (question.query_type == RecordType::ANY
            || record.record_type() == question.query_type
            || record.record_type() == RecordType::CNAME)
}

fn encode_query(message: &Message) -> io::Result<Vec<u8>> {
    let mut request = Message::query();
    request.queries = message
        .queries
        .iter()
        .cloned()
        .map(|mut query| {
            query.mdns_unicast_response = false;
            query
        })
        .collect();
    encode_message(&request)
}

fn new_response(message: &Message, question: &Query) -> Message {
    let mut response = new_response_from_question(question);
    response.metadata.id = message.metadata.id;
    response
}

fn new_response_from_question(question: &Query) -> Message {
    let mut question = question.clone();
    question.mdns_unicast_response = false;
    let mut response = Message::new(0, MessageType::Response, OpCode::Query);
    response.metadata.authoritative = true;
    response.queries.push(question);
    response
}

fn normalize_response(response: &mut Message, question: &Query) {
    response.metadata.id = 0;
    response.queries = vec![question.clone()];
    response.queries[0].mdns_unicast_response = false;
    for record in response
        .answers
        .iter_mut()
        .chain(&mut response.authorities)
        .chain(&mut response.additionals)
    {
        record.mdns_cache_flush = false;
    }
}

fn merge_response(destination: &mut Message, source: Message) {
    merge_records(&mut destination.answers, source.answers);
    merge_records(&mut destination.authorities, source.authorities);
    merge_records(&mut destination.additionals, source.additionals);
}

fn merge_records(destination: &mut Vec<Record>, source: Vec<Record>) {
    for record in source {
        if !destination.contains(&record) {
            destination.push(record);
        }
    }
}

fn has_records(message: &Message) -> bool {
    !message.answers.is_empty()
        || !message.authorities.is_empty()
        || !message.additionals.is_empty()
}

fn encode_message(message: &Message) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut output);
    message.emit(&mut encoder).map_err(io::Error::other)?;
    Ok(output)
}

fn decode_message(bytes: &[u8]) -> io::Result<Message> {
    Message::read(&mut BinDecoder::new(bytes)).map_err(io::Error::other)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(unix)]
#[derive(Default)]
struct InterfaceInfo {
    index: u32,
    flags: u32,
    networks: Vec<ipnet::IpNet>,
}

#[cfg(unix)]
fn query_targets(selected: &[String]) -> io::Result<Vec<QueryTarget>> {
    struct IfAddrs(*mut libc::ifaddrs);
    impl Drop for IfAddrs {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }

    let mut head = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _guard = IfAddrs(head);
    let mut interfaces = BTreeMap::<String, InterfaceInfo>::new();
    let mut current = head;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null() && !entry.ifa_name.is_null() {
            let name = unsafe { CStr::from_ptr(entry.ifa_name) }
                .to_string_lossy()
                .into_owned();
            if selected.is_empty() || selected.contains(&name) {
                let info = interfaces.entry(name).or_default();
                info.flags = entry.ifa_flags;
                info.index = unsafe { libc::if_nametoindex(entry.ifa_name) };
                if !entry.ifa_netmask.is_null()
                    && let (Some(address), Some(mask)) =
                        (unsafe { sockaddr_ip(entry.ifa_addr) }, unsafe {
                            sockaddr_ip(entry.ifa_netmask)
                        })
                    && let Ok(network) =
                        ipnet::IpNet::with_netmask(address, mask)
                    && !network.addr().is_loopback()
                {
                    info.networks.push(network);
                }
            }
        }
        current = entry.ifa_next;
    }
    let mut targets = Vec::new();
    for (name, info) in interfaces {
        let usable = info.flags & libc::IFF_UP as u32 != 0
            && info.flags & libc::IFF_MULTICAST as u32 != 0
            && info.flags & libc::IFF_LOOPBACK as u32 == 0;
        if !usable || info.index == 0 {
            continue;
        }
        let ipv4_address =
            info.networks
                .iter()
                .find_map(|network| match network.addr() {
                    IpAddr::V4(address) => Some(address),
                    IpAddr::V6(_) => None,
                });
        if ipv4_address.is_some() {
            targets.push(QueryTarget {
                name: name.clone(),
                index: info.index,
                family: AddressFamily::V4,
                ipv4_address,
                networks: info.networks.clone(),
            });
        }
        if info.networks.iter().any(|network| network.addr().is_ipv6()) {
            targets.push(QueryTarget {
                name,
                index: info.index,
                family: AddressFamily::V6,
                ipv4_address: None,
                networks: info.networks,
            });
        }
    }
    Ok(targets)
}

#[cfg(not(unix))]
fn query_targets(selected: &[String]) -> io::Result<Vec<QueryTarget>> {
    let interfaces = NetworkInterface::show().map_err(io::Error::other)?;
    let mut targets = Vec::new();
    for interface in interfaces {
        if interface.internal
            || (!selected.is_empty() && !selected.contains(&interface.name))
        {
            continue;
        }
        let mut networks = Vec::new();
        let mut ipv4_address = None;
        let mut has_ipv6 = false;
        for address in interface.addr {
            match address {
                Addr::V4(address) if !address.ip.is_loopback() => {
                    ipv4_address.get_or_insert(address.ip);
                    networks.push(
                        ipnet::Ipv4Net::with_netmask(
                            address.ip,
                            address.netmask.unwrap_or(Ipv4Addr::BROADCAST),
                        )
                        .map(ipnet::IpNet::V4)
                        .map_err(io::Error::other)?,
                    );
                }
                Addr::V6(address) if !address.ip.is_loopback() => {
                    has_ipv6 = true;
                    networks.push(
                        ipnet::Ipv6Net::with_netmask(
                            address.ip,
                            address
                                .netmask
                                .unwrap_or(Ipv6Addr::from(u128::MAX)),
                        )
                        .map(ipnet::IpNet::V6)
                        .map_err(io::Error::other)?,
                    );
                }
                _ => {}
            }
        }
        if ipv4_address.is_some() {
            targets.push(QueryTarget {
                name: interface.name.clone(),
                index: interface.index,
                family: AddressFamily::V4,
                ipv4_address,
                networks: networks.clone(),
            });
        }
        if has_ipv6 {
            targets.push(QueryTarget {
                name: interface.name,
                index: interface.index,
                family: AddressFamily::V6,
                ipv4_address: None,
                networks,
            });
        }
    }
    Ok(targets)
}

#[cfg(unix)]
unsafe fn sockaddr_ip(address: *const libc::sockaddr) -> Option<IpAddr> {
    match unsafe { (*address).sa_family as i32 } {
        libc::AF_INET => {
            let address = unsafe { &*(address.cast::<libc::sockaddr_in>()) };
            Some(IpAddr::V4(Ipv4Addr::from(
                address.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 => {
            let address = unsafe { &*(address.cast::<libc::sockaddr_in6>()) };
            Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, Record, RecordType, rdata::A},
    };

    use super::{is_local_domain, merge_response, valid_response};

    #[test]
    fn local_domain_set_matches_rfc6762_zones() {
        assert!(is_local_domain("printer.local."));
        assert!(is_local_domain("1.0.254.169.in-addr.arpa"));
        assert!(is_local_domain("b.e.f.ip6.arpa."));
        assert!(!is_local_domain("local.example"));
    }

    #[test]
    fn response_validation_accepts_matching_records_without_questions() {
        let question = Query::query(
            Name::from_ascii("printer.local.").unwrap(),
            RecordType::A,
        );
        let mut response =
            Message::new(0, MessageType::Response, OpCode::Query);
        response.add_answer(Record::from_rdata(
            question.name.clone(),
            120,
            RData::A(A::new(192, 0, 2, 4)),
        ));
        assert!(valid_response(&response, &question));
    }

    #[test]
    fn merge_deduplicates_records_across_interfaces() {
        let name = Name::from_ascii("printer.local.").unwrap();
        let record = Record::from_rdata(
            name.clone(),
            120,
            RData::A(A::new(192, 0, 2, 4)),
        );
        let mut first = Message::new(1, MessageType::Response, OpCode::Query);
        first.add_query(Query::query(name, RecordType::A));
        first.add_answer(record.clone());
        let mut second = Message::new(0, MessageType::Response, OpCode::Query);
        second.add_answer(record);
        merge_response(&mut first, second);
        assert_eq!(first.answers.len(), 1);
    }
}
