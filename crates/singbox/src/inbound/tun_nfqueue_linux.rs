//! Linux NFQUEUE pre-match support for TUN auto-redirect.
//!
//! `sing-tun` uses the first TCP SYN, UDP datagram, or ICMP echo request to
//! short-circuit bypass/drop/reject decisions before traffic enters the TUN.
//! The queue itself is optional: if the kernel modules are unavailable the
//! caller keeps the ordinary auto-redirect path active.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use nfq::{Queue, Verdict};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    common::{
        network::{Network, SocksAddr},
        sniff::{PacketSniffState, sniff_packet_with_state},
    },
    route::{Action, Metadata, Router},
};

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_AUTHENTICATION: u8 = 51;
const IPV6_NO_NEXT_HEADER: u8 = 59;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreMatchVerdict {
    Accept,
    Bypass,
    Reject,
    Drop,
}

#[derive(Debug, PartialEq, Eq)]
struct PreMatchPacket<'a> {
    protocol: u8,
    source: SocketAddr,
    destination: SocketAddr,
    first_packet: &'a [u8],
}

pub(crate) struct NfQueueLease {
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl NfQueueLease {
    pub(crate) async fn start(
        queue_number: u16,
        output_mark: u32,
        reset_mark: u32,
        inbound: String,
        router: Arc<Router>,
        network_namespace: &str,
    ) -> io::Result<Self> {
        let namespace = network_namespace.to_owned();
        let mut queue = crate::common::socket::with_network_namespace(
            &namespace,
            move || {
                let mut queue = Queue::open()?;
                queue.bind(queue_number)?;
                queue.set_queue_max_len(queue_number, 4096)?;
                queue.set_fail_open(queue_number, true)?;
                queue.set_recv_gso(queue_number, true)?;
                queue.set_nonblocking(true);
                Ok::<_, io::Error>(queue)
            },
        )
        .await?;

        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::task::spawn_blocking(move || {
            while !task_cancellation.is_cancelled() {
                let mut message = match queue.recv() {
                    Ok(message) => message,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::Interrupted =>
                    {
                        continue;
                    }
                    Err(_) if task_cancellation.is_cancelled() => break,
                    Err(error) => return Err(error),
                };
                match parse_pre_match_packet(message.get_payload()) {
                    Some(packet) => match judge(&router, &inbound, &packet) {
                        PreMatchVerdict::Accept => {
                            message.set_verdict(Verdict::Accept);
                        }
                        PreMatchVerdict::Bypass => {
                            message.set_nfmark(output_mark);
                            message.set_verdict(Verdict::Repeat);
                        }
                        PreMatchVerdict::Reject
                            if packet.protocol == IPPROTO_TCP =>
                        {
                            message.set_nfmark(reset_mark);
                            message.set_verdict(Verdict::Repeat);
                        }
                        PreMatchVerdict::Reject => {
                            message.set_verdict(Verdict::Accept);
                        }
                        PreMatchVerdict::Drop => {
                            message.set_verdict(Verdict::Drop);
                        }
                    },
                    None => message.set_verdict(Verdict::Accept),
                }
                queue.verdict(message)?;
            }
            Ok(())
        });
        Ok(Self {
            cancellation,
            task: Some(task),
        })
    }

    pub(crate) async fn close(&mut self) -> io::Result<()> {
        self.cancellation.cancel();
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        task.await
            .map_err(|error| io::Error::other(error.to_string()))?
    }
}

fn judge(
    router: &Router,
    inbound: &str,
    packet: &PreMatchPacket<'_>,
) -> PreMatchVerdict {
    let network = match packet.protocol {
        IPPROTO_TCP => Network::Tcp,
        IPPROTO_UDP => Network::Udp,
        IPPROTO_ICMP | IPPROTO_ICMPV6 => Network::Icmp,
        _ => return PreMatchVerdict::Accept,
    };
    let (source, destination) = if network == Network::Icmp {
        (
            SocketAddr::new(packet.source.ip(), 0),
            SocketAddr::new(packet.destination.ip(), 0),
        )
    } else {
        (packet.source, packet.destination)
    };
    let mut metadata = Metadata {
        inbound: inbound.to_owned(),
        source: Some(SocksAddr::Ip(source)),
        destination: Some(SocksAddr::Ip(destination)),
        network: Some(network),
        ..Metadata::default()
    };
    let mut route_state = router.route_state();
    let mut sniff_state = PacketSniffState::default();
    loop {
        let decision = router.route_pre_match_next(&metadata, &mut route_state);
        match decision.action().cloned() {
            Some(Action::Sniff(options))
                if network == Network::Udp
                    && !packet.first_packet.is_empty() =>
            {
                if let Ok(result) = sniff_packet_with_state(
                    packet.first_packet,
                    &options.packet_sniffers,
                    &mut sniff_state,
                ) {
                    metadata.protocol = result.protocol;
                    metadata.domain = result.domain;
                    metadata.client = result.client;
                } else {
                    return PreMatchVerdict::Accept;
                }
            }
            Some(Action::Sniff(_)) | Some(Action::Resolve(_)) => {
                return PreMatchVerdict::Accept;
            }
            Some(Action::Bypass { outbound, .. }) if outbound.is_empty() => {
                return PreMatchVerdict::Bypass;
            }
            Some(Action::Reject { method, .. })
                if method == "drop" || decision.reject_is_drop() =>
            {
                return PreMatchVerdict::Drop;
            }
            Some(Action::Reject { .. }) => return PreMatchVerdict::Reject,
            _ => return PreMatchVerdict::Accept,
        }
    }
}

fn parse_pre_match_packet(packet: &[u8]) -> Option<PreMatchPacket<'_>> {
    let version = *packet.first()? >> 4;
    let (protocol, source, destination, transport_offset) = match version {
        4 => parse_ipv4(packet)?,
        6 => parse_ipv6(packet)?,
        _ => return None,
    };
    let transport = packet.get(transport_offset..)?;
    let (source_port, destination_port, first_packet) = match protocol {
        IPPROTO_TCP => {
            if transport.len() < 20 || transport[13] & 0x12 != 0x02 {
                return None;
            }
            (read_u16(transport, 0)?, read_u16(transport, 2)?, &[][..])
        }
        IPPROTO_UDP => {
            if transport.len() < 8 {
                return None;
            }
            let length = usize::from(read_u16(transport, 4)?);
            if length < 8 {
                return None;
            }
            let length = length.min(transport.len());
            (
                read_u16(transport, 0)?,
                read_u16(transport, 2)?,
                &transport[8..length],
            )
        }
        IPPROTO_ICMP if source.is_ipv4() => {
            if transport.len() < 8 || transport[0] != 8 || transport[1] != 0 {
                return None;
            }
            let identifier = read_u16(transport, 4)?;
            (identifier, identifier, &[][..])
        }
        IPPROTO_ICMPV6 if source.is_ipv6() => {
            if transport.len() < 8 || transport[0] != 128 || transport[1] != 0 {
                return None;
            }
            let identifier = read_u16(transport, 4)?;
            (identifier, identifier, &[][..])
        }
        _ => return None,
    };
    Some(PreMatchPacket {
        protocol,
        source: SocketAddr::new(source, source_port),
        destination: SocketAddr::new(destination, destination_port),
        first_packet,
    })
}

fn parse_ipv4(packet: &[u8]) -> Option<(u8, IpAddr, IpAddr, usize)> {
    if packet.len() < 20 {
        return None;
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    let total_length = usize::from(read_u16(packet, 2)?);
    let fragment = read_u16(packet, 6)?;
    if header_length < 20
        || header_length > packet.len()
        || total_length < header_length
        || fragment & 0x1fff != 0
    {
        return None;
    }
    Some((
        packet[9],
        IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
        header_length,
    ))
}

fn parse_ipv6(packet: &[u8]) -> Option<(u8, IpAddr, IpAddr, usize)> {
    if packet.len() < 40 {
        return None;
    }
    let source =
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
    let destination =
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));
    let mut protocol = packet[6];
    let mut offset = 40;
    loop {
        match protocol {
            IPV6_HOP_BY_HOP | IPV6_ROUTING | 60 => {
                let header = packet.get(offset..)?;
                let length = (usize::from(*header.get(1)?) + 1) * 8;
                protocol = header[0];
                offset = offset.checked_add(length)?;
                if offset > packet.len() {
                    return None;
                }
            }
            IPV6_FRAGMENT => {
                let header = packet.get(offset..offset + 8)?;
                if read_u16(header, 2)? & 0xfff8 != 0 {
                    return None;
                }
                protocol = header[0];
                offset += 8;
            }
            IPV6_AUTHENTICATION => {
                let header = packet.get(offset..)?;
                let length = (usize::from(*header.get(1)?) + 2) * 4;
                protocol = header[0];
                offset = offset.checked_add(length)?;
                if offset > packet.len() {
                    return None;
                }
            }
            IPV6_NO_NEXT_HEADER => return None,
            _ => return Some((protocol, source, destination, offset)),
        }
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *packet.get(offset)?,
        *packet.get(offset + 1)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp_syn_udp_and_icmp() {
        let mut tcp = vec![0_u8; 40];
        tcp[0] = 0x45;
        tcp[2..4].copy_from_slice(&40_u16.to_be_bytes());
        tcp[9] = IPPROTO_TCP;
        tcp[12..16].copy_from_slice(&[192, 0, 2, 1]);
        tcp[16..20].copy_from_slice(&[198, 51, 100, 2]);
        tcp[20..22].copy_from_slice(&1234_u16.to_be_bytes());
        tcp[22..24].copy_from_slice(&443_u16.to_be_bytes());
        tcp[33] = 0x02;
        let parsed = parse_pre_match_packet(&tcp).unwrap();
        assert_eq!(parsed.protocol, IPPROTO_TCP);
        assert_eq!(
            parsed.source,
            "192.0.2.1:1234".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(
            parsed.destination,
            "198.51.100.2:443".parse::<std::net::SocketAddr>().unwrap()
        );
        tcp[33] = 0x12;
        assert!(parse_pre_match_packet(&tcp).is_none());

        let mut udp = vec![0_u8; 31];
        udp[0] = 0x45;
        udp[2..4].copy_from_slice(&31_u16.to_be_bytes());
        udp[9] = IPPROTO_UDP;
        udp[12..16].copy_from_slice(&[10, 0, 0, 1]);
        udp[16..20].copy_from_slice(&[1, 1, 1, 1]);
        udp[20..22].copy_from_slice(&53_000_u16.to_be_bytes());
        udp[22..24].copy_from_slice(&53_u16.to_be_bytes());
        udp[24..26].copy_from_slice(&11_u16.to_be_bytes());
        udp[28..31].copy_from_slice(b"dns");
        let parsed = parse_pre_match_packet(&udp).unwrap();
        assert_eq!(parsed.first_packet, b"dns");

        let mut icmp = vec![0_u8; 28];
        icmp[0] = 0x45;
        icmp[2..4].copy_from_slice(&28_u16.to_be_bytes());
        icmp[9] = IPPROTO_ICMP;
        icmp[12..16].copy_from_slice(&[10, 0, 0, 2]);
        icmp[16..20].copy_from_slice(&[8, 8, 8, 8]);
        icmp[20] = 8;
        icmp[24..26].copy_from_slice(&0x1234_u16.to_be_bytes());
        let parsed = parse_pre_match_packet(&icmp).unwrap();
        assert_eq!(parsed.source.port(), 0x1234);
    }

    #[test]
    fn parses_ipv6_extensions_and_rejects_non_initial_fragments() {
        let mut packet = vec![0_u8; 68];
        packet[0] = 0x60;
        packet[6] = IPV6_HOP_BY_HOP;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(
            &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets(),
        );
        packet[40] = IPV6_FRAGMENT;
        packet[41] = 0;
        packet[48] = IPPROTO_ICMPV6;
        packet[56] = 128;
        packet[60..62].copy_from_slice(&7_u16.to_be_bytes());
        let parsed = parse_pre_match_packet(&packet).unwrap();
        assert_eq!(parsed.protocol, IPPROTO_ICMPV6);
        assert_eq!(parsed.destination.port(), 7);
        packet[50..52].copy_from_slice(&8_u16.to_be_bytes());
        assert!(parse_pre_match_packet(&packet).is_none());
    }

    #[test]
    fn malformed_packets_fail_closed_to_accept() {
        assert!(parse_pre_match_packet(&[]).is_none());
        assert!(parse_pre_match_packet(&[0x45; 19]).is_none());
        assert!(parse_pre_match_packet(&[0x60; 39]).is_none());
    }
}
