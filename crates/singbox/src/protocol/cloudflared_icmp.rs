//! Cloudflare Tunnel ICMP datagram bridge.
//!
//! The edge sends complete IPv4 or IPv6 packets. The embedding `Dialer`
//! routes the ICMP message through the same outbound selection surface used by
//! TUN endpoints, while this bridge preserves Cloudflare's packet framing,
//! hop-limit handling, and locally generated time-exceeded replies.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use super::{
    cloudflared::{
        CloudflaredDatagramV2Type, CloudflaredDatagramV3Type, CloudflaredError,
    },
    cloudflared_datagram::CloudflaredDatagramTransport,
};
use crate::{adapter::Dialer, common::network::SocksAddr};

pub const CLOUDFLARED_ICMP_FLOW_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);
pub const CLOUDFLARED_ICMP_TRACE_IDENTITY_LENGTH: usize = 16 + 8 + 1;
pub const CLOUDFLARED_ICMP_IPV4_TTL_QUOTE_LENGTH: usize = 548;
pub const CLOUDFLARED_ICMP_IPV6_TTL_QUOTE_LENGTH: usize = 1232;
pub const CLOUDFLARED_ICMP_MAX_PAYLOAD_LENGTH: usize = 1280;

const DEFAULT_PACKET_HOP_LIMIT: u8 = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredIcmpPacket {
    pub ip_version: u8,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub identifier: u16,
    pub sequence: u16,
    pub hop_limit: u8,
    pub ip_header_length: usize,
    pub raw_packet: Vec<u8>,
}

impl CloudflaredIcmpPacket {
    pub fn is_echo_request(&self) -> bool {
        matches!(
            (self.ip_version, self.icmp_type, self.icmp_code),
            (4, 8, 0) | (6, 128, 0)
        )
    }

    pub fn is_echo_reply(&self) -> bool {
        matches!(
            (self.ip_version, self.icmp_type, self.icmp_code),
            (4, 0, 0) | (6, 129, 0)
        )
    }

    fn message(&self) -> &[u8] {
        &self.raw_packet[self.ip_header_length..]
    }
}

pub fn parse_cloudflared_icmp_packet(
    packet: &[u8],
) -> Result<CloudflaredIcmpPacket, CloudflaredError> {
    let version = packet
        .first()
        .map(|byte| byte >> 4)
        .ok_or_else(|| icmp_error("empty IP packet"))?;
    match version {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        version => {
            Err(icmp_error(format!("unsupported IP version: {version}")))
        }
    }
}

fn parse_ipv4(
    packet: &[u8],
) -> Result<CloudflaredIcmpPacket, CloudflaredError> {
    if packet.len() < 20 {
        return Err(icmp_error("IPv4 packet too short"));
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || packet.len() < header_length + 8 {
        return Err(icmp_error("invalid IPv4 header length"));
    }
    if packet[9] != 1 {
        return Err(icmp_error("IPv4 packet is not ICMP"));
    }
    let message = &packet[header_length..];
    Ok(CloudflaredIcmpPacket {
        ip_version: 4,
        source: IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        destination: IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
        icmp_type: message[0],
        icmp_code: message[1],
        identifier: u16::from_be_bytes([message[4], message[5]]),
        sequence: u16::from_be_bytes([message[6], message[7]]),
        hop_limit: packet[8],
        ip_header_length: header_length,
        raw_packet: packet.to_vec(),
    })
}

fn parse_ipv6(
    packet: &[u8],
) -> Result<CloudflaredIcmpPacket, CloudflaredError> {
    if packet.len() < 48 {
        return Err(icmp_error("IPv6 packet too short"));
    }
    if packet[6] != 58 {
        return Err(icmp_error("IPv6 packet is not ICMP"));
    }
    let source: [u8; 16] =
        packet[8..24].try_into().expect("fixed IPv6 source length");
    let destination: [u8; 16] = packet[24..40]
        .try_into()
        .expect("fixed IPv6 destination length");
    let message = &packet[40..];
    Ok(CloudflaredIcmpPacket {
        ip_version: 6,
        source: IpAddr::V6(Ipv6Addr::from(source)),
        destination: IpAddr::V6(Ipv6Addr::from(destination)),
        icmp_type: message[0],
        icmp_code: message[1],
        identifier: u16::from_be_bytes([message[4], message[5]]),
        sequence: u16::from_be_bytes([message[6], message[7]]),
        hop_limit: packet[7],
        ip_header_length: 40,
        raw_packet: packet.to_vec(),
    })
}

pub struct CloudflaredIcmpBridge {
    dialer: Arc<dyn Dialer>,
}

impl CloudflaredIcmpBridge {
    pub fn new(dialer: Arc<dyn Dialer>) -> Self {
        Self { dialer }
    }

    pub async fn handle_v2(
        &self,
        datagram_type: CloudflaredDatagramV2Type,
        payload: &[u8],
        transport: &dyn CloudflaredDatagramTransport,
    ) -> Result<(), CloudflaredError> {
        let packet = match datagram_type {
            CloudflaredDatagramV2Type::Ip => payload,
            CloudflaredDatagramV2Type::IpWithTrace => payload
                .get(
                    ..payload
                        .len()
                        .saturating_sub(CLOUDFLARED_ICMP_TRACE_IDENTITY_LENGTH),
                )
                .filter(|_| {
                    payload.len() >= CLOUDFLARED_ICMP_TRACE_IDENTITY_LENGTH
                })
                .ok_or_else(|| icmp_error("icmp trace payload is too short"))?,
            _ => {
                return Err(icmp_error(format!(
                    "unsupported v2 icmp datagram type: {}",
                    datagram_type as u8
                )));
            }
        };
        let Some(reply) = self.route_packet(packet).await? else {
            return Ok(());
        };
        let mut datagram = reply;
        datagram.push(CloudflaredDatagramV2Type::Ip as u8);
        transport.send_datagram(datagram.into())
    }

    pub async fn handle_v3(
        &self,
        payload: &[u8],
        transport: &dyn CloudflaredDatagramTransport,
    ) -> Result<(), CloudflaredError> {
        let Some(reply) = self.route_packet(payload).await? else {
            return Ok(());
        };
        if reply.is_empty() || reply.len() > CLOUDFLARED_ICMP_MAX_PAYLOAD_LENGTH
        {
            return Err(icmp_error("icmp payload is too large"));
        }
        let mut datagram = Vec::with_capacity(reply.len() + 1);
        datagram.push(CloudflaredDatagramV3Type::Icmp as u8);
        datagram.extend_from_slice(&reply);
        transport.send_datagram(datagram.into())
    }

    async fn route_packet(
        &self,
        packet: &[u8],
    ) -> Result<Option<Vec<u8>>, CloudflaredError> {
        let packet = parse_cloudflared_icmp_packet(packet)?;
        if !packet.is_echo_request() {
            return Ok(None);
        }
        if packet.hop_limit <= 1 {
            return build_time_exceeded(&packet).map(Some);
        }
        let destination =
            SocksAddr::from(SocketAddr::new(packet.destination, 0));
        let response = self
            .dialer
            .exchange_icmp(
                packet.message(),
                packet.source,
                packet.hop_limit - 1,
                &destination,
            )
            .await
            .map_err(|error| icmp_error(error.to_string()))?;
        build_response_packet(
            response.source,
            packet.source,
            response.hop_limit,
            &response.packet,
        )
        .map(Some)
    }
}

fn build_time_exceeded(
    request: &CloudflaredIcmpPacket,
) -> Result<Vec<u8>, CloudflaredError> {
    match (request.source, request.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let quote_length = request
                .raw_packet
                .len()
                .min(CLOUDFLARED_ICMP_IPV4_TTL_QUOTE_LENGTH);
            let mut message = vec![0_u8; 8 + quote_length];
            message[0] = 11;
            message[1] = 0;
            message[8..].copy_from_slice(&request.raw_packet[..quote_length]);
            let checksum = internet_checksum(&message);
            message[2..4].copy_from_slice(&checksum.to_be_bytes());
            build_response_packet(
                IpAddr::V4(destination),
                IpAddr::V4(source),
                DEFAULT_PACKET_HOP_LIMIT,
                &message,
            )
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let quote_length = request
                .raw_packet
                .len()
                .min(CLOUDFLARED_ICMP_IPV6_TTL_QUOTE_LENGTH);
            let mut message = vec![0_u8; 8 + quote_length];
            message[0] = 3;
            message[1] = 0;
            message[8..].copy_from_slice(&request.raw_packet[..quote_length]);
            build_response_packet(
                IpAddr::V6(destination),
                IpAddr::V6(source),
                DEFAULT_PACKET_HOP_LIMIT,
                &message,
            )
        }
        _ => Err(icmp_error("ICMP request address family changed")),
    }
}

fn build_response_packet(
    source: IpAddr,
    destination: IpAddr,
    hop_limit: u8,
    message: &[u8],
) -> Result<Vec<u8>, CloudflaredError> {
    if message.len() < 8 {
        return Err(icmp_error("truncated ICMP response"));
    }
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let total_length = u16::try_from(20 + message.len())
                .map_err(|_| icmp_error("IPv4 ICMP response is too large"))?;
            let mut packet = vec![0_u8; usize::from(total_length)];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&total_length.to_be_bytes());
            packet[8] = hop_limit.max(1);
            packet[9] = 1;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&destination.octets());
            packet[20..].copy_from_slice(message);
            packet[22..24].fill(0);
            let checksum = internet_checksum(&packet[20..]);
            packet[22..24].copy_from_slice(&checksum.to_be_bytes());
            let checksum = internet_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            Ok(packet)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let payload_length = u16::try_from(message.len())
                .map_err(|_| icmp_error("IPv6 ICMP response is too large"))?;
            let mut packet = vec![0_u8; 40 + message.len()];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&payload_length.to_be_bytes());
            packet[6] = 58;
            packet[7] = hop_limit.max(1);
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&destination.octets());
            packet[40..].copy_from_slice(message);
            packet[42..44].fill(0);
            let checksum = icmpv6_checksum(source, destination, &packet[40..]);
            packet[42..44].copy_from_slice(&checksum.to_be_bytes());
            Ok(packet)
        }
        _ => Err(icmp_error("ICMP response address family changed")),
    }
}

fn icmpv6_checksum(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    message: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + message.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(message.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(message);
    internet_checksum(&pseudo)
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmp_error(message: impl Into<String>) -> CloudflaredError {
    CloudflaredError::Transport(message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use bytes::Bytes;

    use super::*;
    use crate::{
        adapter::{DialFuture, IcmpResponse, PacketFuture, Stream},
        protocol::cloudflared::CloudflaredIncomingDatagramVersion,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct IcmpCall {
        message: Vec<u8>,
        source: IpAddr,
        hop_limit: u8,
        destination: SocksAddr,
    }

    #[derive(Default)]
    struct EchoDialer {
        calls: Mutex<Vec<IcmpCall>>,
    }

    impl Dialer for EchoDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "TCP not used",
                ))
            })
        }

        fn exchange_icmp<'a>(
            &'a self,
            packet: &'a [u8],
            source: IpAddr,
            hop_limit: u8,
            destination: &'a SocksAddr,
        ) -> PacketFuture<'a, IcmpResponse> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(IcmpCall {
                    message: packet.to_vec(),
                    source,
                    hop_limit,
                    destination: destination.clone(),
                });
                let mut reply = packet.to_vec();
                reply[0] = if source.is_ipv4() { 0 } else { 129 };
                reply[2..4].fill(0);
                let target = if source.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))
                } else {
                    IpAddr::V6("2001:db8::2".parse().unwrap())
                };
                Ok(IcmpResponse {
                    source: target,
                    packet: reply,
                    hop_limit: 51,
                })
            })
        }
    }

    struct MemoryTransport {
        version: CloudflaredIncomingDatagramVersion,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl MemoryTransport {
        fn new(version: CloudflaredIncomingDatagramVersion) -> Self {
            Self {
                version,
                sent: Mutex::new(Vec::new()),
            }
        }

        fn take_sent(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.sent.lock().unwrap())
        }
    }

    #[async_trait]
    impl CloudflaredDatagramTransport for MemoryTransport {
        fn connection_id(&self) -> usize {
            7
        }

        fn datagram_version(&self) -> CloudflaredIncomingDatagramVersion {
            self.version
        }

        fn send_datagram(
            &self,
            datagram: Bytes,
        ) -> Result<(), CloudflaredError> {
            self.sent.lock().unwrap().push(datagram.to_vec());
            Ok(())
        }

        async fn open_rpc_stream(&self) -> Result<Stream, CloudflaredError> {
            Err(icmp_error("RPC not used"))
        }

        async fn closed(&self) {
            std::future::pending::<()>().await;
        }
    }

    fn ipv4_echo_request(hop_limit: u8) -> Vec<u8> {
        let message = b"cloudflared-icmp";
        let total_length = 20 + 8 + message.len();
        let mut packet = vec![0_u8; total_length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        packet[8] = hop_limit;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20] = 8;
        packet[24..26].copy_from_slice(&0x1234_u16.to_be_bytes());
        packet[26..28].copy_from_slice(&7_u16.to_be_bytes());
        packet[28..].copy_from_slice(message);
        let checksum = internet_checksum(&packet[20..]);
        packet[22..24].copy_from_slice(&checksum.to_be_bytes());
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn ipv6_echo_request(hop_limit: u8) -> Vec<u8> {
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let destination: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut packet = vec![0_u8; 48 + 4];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&12_u16.to_be_bytes());
        packet[6] = 58;
        packet[7] = hop_limit;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40] = 128;
        packet[44..46].copy_from_slice(&0x4321_u16.to_be_bytes());
        packet[46..48].copy_from_slice(&9_u16.to_be_bytes());
        packet[48..].copy_from_slice(b"icmp");
        let checksum = icmpv6_checksum(source, destination, &packet[40..]);
        packet[42..44].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[tokio::test]
    async fn v2_traced_echo_routes_and_replies_as_plain_ip() {
        let dialer = Arc::new(EchoDialer::default());
        let bridge = CloudflaredIcmpBridge::new(dialer.clone());
        let transport =
            MemoryTransport::new(CloudflaredIncomingDatagramVersion::V2);
        let request = ipv4_echo_request(64);
        let mut traced = request.clone();
        traced
            .extend_from_slice(&[0x7a; CLOUDFLARED_ICMP_TRACE_IDENTITY_LENGTH]);
        bridge
            .handle_v2(
                CloudflaredDatagramV2Type::IpWithTrace,
                &traced,
                &transport,
            )
            .await
            .unwrap();

        let calls = dialer.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].source, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(calls[0].hop_limit, 63);
        assert_eq!(calls[0].message, request[20..]);
        drop(calls);

        let response = transport.take_sent().pop().unwrap();
        assert_eq!(
            response.last(),
            Some(&(CloudflaredDatagramV2Type::Ip as u8))
        );
        let parsed =
            parse_cloudflared_icmp_packet(&response[..response.len() - 1])
                .unwrap();
        assert!(parsed.is_echo_reply());
        assert_eq!(parsed.source, "198.51.100.2".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.destination, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.hop_limit, 51);
        assert_eq!(internet_checksum(&parsed.raw_packet[..20]), 0);
        assert_eq!(internet_checksum(parsed.message()), 0);
    }

    #[tokio::test]
    async fn v3_ipv6_echo_uses_icmp_type_and_repairs_checksum() {
        let dialer = Arc::new(EchoDialer::default());
        let bridge = CloudflaredIcmpBridge::new(dialer.clone());
        let transport =
            MemoryTransport::new(CloudflaredIncomingDatagramVersion::V3);
        bridge
            .handle_v3(&ipv6_echo_request(32), &transport)
            .await
            .unwrap();

        assert_eq!(dialer.calls.lock().unwrap()[0].hop_limit, 31);
        let response = transport.take_sent().pop().unwrap();
        assert_eq!(response[0], CloudflaredDatagramV3Type::Icmp as u8);
        let parsed = parse_cloudflared_icmp_packet(&response[1..]).unwrap();
        assert!(parsed.is_echo_reply());
        let (IpAddr::V6(source), IpAddr::V6(destination)) =
            (parsed.source, parsed.destination)
        else {
            panic!("expected IPv6 response");
        };
        assert_eq!(icmpv6_checksum(source, destination, parsed.message()), 0);
    }

    #[tokio::test]
    async fn expired_hop_limit_returns_time_exceeded_without_dialing() {
        let dialer = Arc::new(EchoDialer::default());
        let bridge = CloudflaredIcmpBridge::new(dialer.clone());
        let transport =
            MemoryTransport::new(CloudflaredIncomingDatagramVersion::V3);
        let request = ipv4_echo_request(1);
        bridge.handle_v3(&request, &transport).await.unwrap();

        assert!(dialer.calls.lock().unwrap().is_empty());
        let response = transport.take_sent().pop().unwrap();
        let parsed = parse_cloudflared_icmp_packet(&response[1..]).unwrap();
        assert_eq!((parsed.icmp_type, parsed.icmp_code), (11, 0));
        assert_eq!(parsed.hop_limit, DEFAULT_PACKET_HOP_LIMIT);
        assert_eq!(&parsed.message()[8..], request);
    }
}
