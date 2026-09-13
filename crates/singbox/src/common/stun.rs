//! RFC 5389 binding and RFC 5780 NAT behavior discovery.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use tokio::time::{Instant, timeout_at};

use crate::{
    adapter::{Dialer, PacketConnection},
    common::network::SocksAddr,
};

pub const DEFAULT_SERVER: &str = "stun.voipgate.com:3478";

const MAGIC_COOKIE: u32 = 0x2112_a442;
const HEADER_SIZE: usize = 20;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const BINDING_ERROR_RESPONSE: u16 = 0x0111;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_CHANGE_REQUEST: u16 = 0x0003;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_OTHER_ADDRESS: u16 = 0x802c;
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;
const CHANGE_IP: u8 = 0x04;
const CHANGE_PORT: u8 = 0x02;
const DEFAULT_RTO: Duration = Duration::from_millis(500);
const MIN_RTO: Duration = Duration::from_millis(250);
const MAX_RETRANSMIT: usize = 2;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(i32)]
pub enum Phase {
    #[default]
    Binding = 0,
    NatMapping = 1,
    NatFiltering = 2,
    Done = 3,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(i32)]
pub enum NatMapping {
    #[default]
    Unknown = 0,
    EndpointIndependent = 2,
    AddressDependent = 3,
    AddressAndPortDependent = 4,
}

impl std::fmt::Display for NatMapping {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "Unknown",
            Self::EndpointIndependent => "Endpoint Independent",
            Self::AddressDependent => "Address Dependent",
            Self::AddressAndPortDependent => "Address and Port Dependent",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(i32)]
pub enum NatFiltering {
    #[default]
    Unknown = 0,
    EndpointIndependent = 1,
    AddressDependent = 2,
    AddressAndPortDependent = 3,
}

impl std::fmt::Display for NatFiltering {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "Unknown",
            Self::EndpointIndependent => "Endpoint Independent",
            Self::AddressDependent => "Address Dependent",
            Self::AddressAndPortDependent => "Address and Port Dependent",
        })
    }
}

pub type TransactionId = [u8; 12];

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Progress {
    pub phase: Phase,
    pub external_addr: String,
    pub latency_ms: i32,
    pub nat_mapping: NatMapping,
    pub nat_filtering: NatFiltering,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Result {
    pub external_addr: String,
    pub latency_ms: i32,
    pub nat_mapping: NatMapping,
    pub nat_filtering: NatFiltering,
    pub nat_type_supported: bool,
}

#[derive(Debug, Default)]
struct ParsedResponse {
    xor_mapped_addr: Option<SocketAddr>,
    mapped_addr: Option<SocketAddr>,
    other_addr: Option<SocketAddr>,
}

impl ParsedResponse {
    fn external_addr(&self) -> Option<SocketAddr> {
        self.xor_mapped_addr.or(self.mapped_addr)
    }
}

struct StunAttribute {
    kind: u16,
    value: Vec<u8>,
}

/// Build a plain RFC 5389 binding request for use by socket-owning protocols.
///
/// Tailscale must send STUN through the same UDP socket that carries disco and
/// WireGuard traffic, so it cannot use [`run`], which opens a fresh socket.
pub fn build_binding_request_message(transaction_id: TransactionId) -> Vec<u8> {
    build_binding_request(transaction_id, &[])
}

/// Parse the mapped endpoint from a binding response with the expected
/// transaction ID.
pub fn mapped_address_from_response(
    data: &[u8],
    transaction_id: TransactionId,
) -> io::Result<SocketAddr> {
    parse_response(data, transaction_id)?
        .external_addr()
        .ok_or_else(|| invalid_data("no mapped address in response"))
}

pub async fn run<F>(
    server: &str,
    dialer: &dyn Dialer,
    mut report_progress: F,
) -> io::Result<Result>
where
    F: FnMut(Progress),
{
    let server = parse_server(server)?;
    let packet_connection = dialer
        .listen_udp(&server)
        .await
        .map_err(|error| contextual(error, "create UDP socket"))?;
    let mut rto = DEFAULT_RTO;

    report_progress(Progress {
        phase: Phase::Binding,
        ..Progress::default()
    });
    let response = round_trip(
        packet_connection.as_ref(),
        &server,
        new_transaction_id()?,
        &[],
        rto,
    )
    .await
    .map_err(|error| contextual(error, "binding request"))?;
    let latency = response.1;
    rto = MIN_RTO.max(latency.saturating_mul(3));
    let external_addr = response
        .0
        .external_addr()
        .ok_or_else(|| invalid_data("no mapped address in response"))?;
    let mut result = Result {
        external_addr: external_addr.to_string(),
        latency_ms: duration_millis_i32(latency),
        ..Result::default()
    };
    report_progress(Progress {
        phase: Phase::Binding,
        external_addr: result.external_addr.clone(),
        latency_ms: result.latency_ms,
        ..Progress::default()
    });

    let Some(other_addr) = response.0.other_addr else {
        report_progress(Progress {
            phase: Phase::Done,
            external_addr: result.external_addr.clone(),
            latency_ms: result.latency_ms,
            ..Progress::default()
        });
        return Ok(result);
    };
    result.nat_type_supported = true;

    report_progress(Progress {
        phase: Phase::NatMapping,
        external_addr: result.external_addr.clone(),
        latency_ms: result.latency_ms,
        ..Progress::default()
    });
    result.nat_mapping = detect_nat_mapping(
        packet_connection.as_ref(),
        server.port(),
        external_addr,
        other_addr,
        rto,
    )
    .await;
    report_progress(Progress {
        phase: Phase::NatMapping,
        external_addr: result.external_addr.clone(),
        latency_ms: result.latency_ms,
        nat_mapping: result.nat_mapping,
        ..Progress::default()
    });

    report_progress(Progress {
        phase: Phase::NatFiltering,
        external_addr: result.external_addr.clone(),
        latency_ms: result.latency_ms,
        nat_mapping: result.nat_mapping,
        ..Progress::default()
    });
    result.nat_filtering =
        detect_nat_filtering(packet_connection.as_ref(), &server, rto).await;
    report_progress(Progress {
        phase: Phase::Done,
        external_addr: result.external_addr.clone(),
        latency_ms: result.latency_ms,
        nat_mapping: result.nat_mapping,
        nat_filtering: result.nat_filtering,
    });
    Ok(result)
}

async fn detect_nat_mapping(
    connection: &dyn PacketConnection,
    server_port: u16,
    external_addr: SocketAddr,
    other_addr: SocketAddr,
    rto: Duration,
) -> NatMapping {
    let test_two = SocksAddr::Ip(SocketAddr::new(other_addr.ip(), server_port));
    let Ok((response, _)) = round_trip(
        connection,
        &test_two,
        new_transaction_id().unwrap_or_default(),
        &[],
        rto,
    )
    .await
    else {
        return NatMapping::Unknown;
    };
    let Some(external_two) = response.external_addr() else {
        return NatMapping::Unknown;
    };
    if external_addr == external_two {
        return NatMapping::EndpointIndependent;
    }

    let Ok((response, _)) = round_trip(
        connection,
        &SocksAddr::Ip(other_addr),
        new_transaction_id().unwrap_or_default(),
        &[],
        rto,
    )
    .await
    else {
        return NatMapping::Unknown;
    };
    let Some(external_three) = response.external_addr() else {
        return NatMapping::Unknown;
    };
    if external_two == external_three {
        NatMapping::AddressDependent
    } else {
        NatMapping::AddressAndPortDependent
    }
}

async fn detect_nat_filtering(
    connection: &dyn PacketConnection,
    server: &SocksAddr,
    rto: Duration,
) -> NatFiltering {
    let both = [change_request_attribute(CHANGE_IP | CHANGE_PORT)];
    if round_trip(
        connection,
        server,
        new_transaction_id().unwrap_or_default(),
        &both,
        rto,
    )
    .await
    .is_ok()
    {
        return NatFiltering::EndpointIndependent;
    }
    let port = [change_request_attribute(CHANGE_PORT)];
    if round_trip(
        connection,
        server,
        new_transaction_id().unwrap_or_default(),
        &port,
        rto,
    )
    .await
    .is_ok()
    {
        return NatFiltering::AddressDependent;
    }
    NatFiltering::AddressAndPortDependent
}

async fn round_trip(
    connection: &dyn PacketConnection,
    destination: &SocksAddr,
    transaction_id: TransactionId,
    attributes: &[StunAttribute],
    rto: Duration,
) -> io::Result<(ParsedResponse, Duration)> {
    let request = build_binding_request(transaction_id, attributes);
    let mut current_rto = rto;
    let mut retransmits = 0;
    let mut send_time = Instant::now();
    connection
        .send_to(&request, destination)
        .await
        .map_err(|error| contextual(error, "send STUN request"))?;
    let mut buffer = [0_u8; 1024];
    loop {
        let deadline = send_time + current_rto;
        let received =
            timeout_at(deadline, connection.recv_from(&mut buffer)).await;
        let (size, _) = match received {
            Ok(Ok(received)) => received,
            Ok(Err(error)) => {
                return Err(contextual(error, "read STUN response"));
            }
            Err(_) if retransmits < MAX_RETRANSMIT => {
                retransmits += 1;
                current_rto = current_rto.saturating_mul(2);
                send_time = Instant::now();
                connection.send_to(&request, destination).await.map_err(
                    |error| contextual(error, "retransmit STUN request"),
                )?;
                continue;
            }
            Err(error) => {
                return Err(contextual(
                    io::Error::new(io::ErrorKind::TimedOut, error),
                    "read STUN response",
                ));
            }
        };
        if transaction_id_from_message(&buffer[..size]) != Some(transaction_id)
        {
            continue;
        }
        let latency = send_time.elapsed();
        return parse_response(&buffer[..size], transaction_id)
            .map(|response| (response, latency));
    }
}

fn new_transaction_id() -> io::Result<TransactionId> {
    let mut id = [0_u8; 12];
    getrandom::fill(&mut id).map_err(io::Error::other)?;
    Ok(id)
}

fn build_binding_request(
    transaction_id: TransactionId,
    attributes: &[StunAttribute],
) -> Vec<u8> {
    let attributes_len = attributes
        .iter()
        .map(|attribute| {
            4 + attribute.value.len() + padding_len(attribute.value.len())
        })
        .sum::<usize>();
    let mut message = vec![0_u8; HEADER_SIZE + attributes_len];
    message[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    message[2..4].copy_from_slice(
        &u16::try_from(attributes_len)
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    message[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message[8..20].copy_from_slice(&transaction_id);
    let mut offset = HEADER_SIZE;
    for attribute in attributes {
        let length = attribute.value.len();
        message[offset..offset + 2]
            .copy_from_slice(&attribute.kind.to_be_bytes());
        message[offset + 2..offset + 4].copy_from_slice(
            &u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes(),
        );
        message[offset + 4..offset + 4 + length]
            .copy_from_slice(&attribute.value);
        offset += 4 + length + padding_len(length);
    }
    message
}

fn change_request_attribute(flags: u8) -> StunAttribute {
    StunAttribute {
        kind: ATTR_CHANGE_REQUEST,
        value: vec![0, 0, 0, flags],
    }
}

fn parse_response(
    data: &[u8],
    expected_transaction_id: TransactionId,
) -> io::Result<ParsedResponse> {
    if data.len() < HEADER_SIZE {
        return Err(invalid_data("response too short"));
    }
    let message_type = u16::from_be_bytes([data[0], data[1]]);
    if message_type & 0xc000 != 0 {
        return Err(invalid_data("invalid STUN message: top 2 bits not zero"));
    }
    if u32::from_be_bytes(data[4..8].try_into().expect("four bytes"))
        != MAGIC_COOKIE
    {
        return Err(invalid_data("invalid magic cookie"));
    }
    if data[8..20] != expected_transaction_id {
        return Err(invalid_data("transaction ID mismatch"));
    }
    let message_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if message_len > data.len() - HEADER_SIZE {
        return Err(invalid_data("message length exceeds data"));
    }
    let attributes = &data[HEADER_SIZE..HEADER_SIZE + message_len];
    if message_type == BINDING_ERROR_RESPONSE {
        return Err(parse_error_response(attributes));
    }
    if message_type != BINDING_SUCCESS_RESPONSE {
        return Err(invalid_data(format!(
            "unexpected message type: 0x{message_type:04x}"
        )));
    }
    let mut response = ParsedResponse::default();
    let mut offset = 0;
    while offset + 4 <= attributes.len() {
        let kind =
            u16::from_be_bytes([attributes[offset], attributes[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([
            attributes[offset + 2],
            attributes[offset + 3],
        ]));
        if offset + 4 + length > attributes.len() {
            break;
        }
        let value = &attributes[offset + 4..offset + 4 + length];
        match kind {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Ok(address) =
                    parse_xor_mapped_address(value, expected_transaction_id)
                {
                    response.xor_mapped_addr = Some(address);
                }
            }
            ATTR_MAPPED_ADDRESS => {
                if let Ok(address) = parse_mapped_address(value) {
                    response.mapped_addr = Some(address);
                }
            }
            ATTR_OTHER_ADDRESS => {
                if let Ok(address) = parse_mapped_address(value) {
                    response.other_addr = Some(address);
                }
            }
            _ => {}
        }
        offset += 4 + length + padding_len(length);
    }
    Ok(response)
}

fn parse_error_response(data: &[u8]) -> io::Error {
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let kind = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([
            data[offset + 2],
            data[offset + 3],
        ]));
        if offset + 4 + length > data.len() {
            break;
        }
        if kind == ATTR_ERROR_CODE && length >= 4 {
            let value = &data[offset + 4..offset + 4 + length];
            let code =
                usize::from(value[2] & 0x07) * 100 + usize::from(value[3]);
            let reason = if length > 4 {
                format!(
                    "STUN error {code}: {}",
                    String::from_utf8_lossy(&value[4..])
                )
            } else {
                format!("STUN error {code}")
            };
            return invalid_data(reason);
        }
        offset += 4 + length + padding_len(length);
    }
    invalid_data("STUN error response")
}

fn parse_xor_mapped_address(
    data: &[u8],
    transaction_id: TransactionId,
) -> io::Result<SocketAddr> {
    if data.len() < 4 {
        return Err(invalid_data("XOR-MAPPED-ADDRESS too short"));
    }
    let port = u16::from_be_bytes([data[2], data[3]])
        ^ u16::try_from(MAGIC_COOKIE >> 16).expect("cookie prefix is u16");
    match data[1] {
        FAMILY_IPV4 if data.len() >= 8 => {
            let encoded =
                u32::from_be_bytes(data[4..8].try_into().expect("four bytes"));
            Ok(SocketAddr::new(
                Ipv4Addr::from(encoded ^ MAGIC_COOKIE).into(),
                port,
            ))
        }
        FAMILY_IPV4 => Err(invalid_data("XOR-MAPPED-ADDRESS IPv4 too short")),
        FAMILY_IPV6 if data.len() >= 20 => {
            let mut key = [0_u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(&transaction_id);
            let mut address = [0_u8; 16];
            for (output, (encoded, key)) in
                address.iter_mut().zip(data[4..20].iter().zip(key.iter()))
            {
                *output = encoded ^ key;
            }
            Ok(SocketAddr::new(address.into(), port))
        }
        FAMILY_IPV6 => Err(invalid_data("XOR-MAPPED-ADDRESS IPv6 too short")),
        family => {
            Err(invalid_data(format!("unknown address family: {family}")))
        }
    }
}

fn parse_mapped_address(data: &[u8]) -> io::Result<SocketAddr> {
    if data.len() < 4 {
        return Err(invalid_data("MAPPED-ADDRESS too short"));
    }
    let port = u16::from_be_bytes([data[2], data[3]]);
    match data[1] {
        FAMILY_IPV4 if data.len() >= 8 => Ok(SocketAddr::new(
            [data[4], data[5], data[6], data[7]].into(),
            port,
        )),
        FAMILY_IPV4 => Err(invalid_data("MAPPED-ADDRESS IPv4 too short")),
        FAMILY_IPV6 if data.len() >= 20 => {
            let mut address = [0_u8; 16];
            address.copy_from_slice(&data[4..20]);
            Ok(SocketAddr::new(address.into(), port))
        }
        FAMILY_IPV6 => Err(invalid_data("MAPPED-ADDRESS IPv6 too short")),
        family => {
            Err(invalid_data(format!("unknown address family: {family}")))
        }
    }
}

pub fn transaction_id_from_message(data: &[u8]) -> Option<TransactionId> {
    if data.len() < HEADER_SIZE
        || data[0] & 0xc0 != 0
        || data[4..8] != MAGIC_COOKIE.to_be_bytes()
    {
        return None;
    }
    let declared = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if declared > data.len() - HEADER_SIZE {
        return None;
    }
    data[8..20].try_into().ok()
}

fn parse_server(server: &str) -> io::Result<SocksAddr> {
    let server = if server.is_empty() {
        DEFAULT_SERVER
    } else {
        server
    };
    if let Ok(address) = server.parse::<SocksAddr>() {
        if address.port() != 0 {
            return Ok(address);
        }
        return Ok(match address {
            SocksAddr::Ip(address) => {
                SocksAddr::Ip(SocketAddr::new(address.ip(), 3478))
            }
            SocksAddr::Domain { host, .. } => {
                SocksAddr::Domain { host, port: 3478 }
            }
        });
    }
    if let Ok(address) = server.parse::<IpAddr>() {
        return Ok(SocksAddr::Ip(SocketAddr::new(address, 3478)));
    }
    Ok(SocksAddr::new(server, 3478))
}

fn padding_len(length: usize) -> usize {
    (4 - length % 4) % 4
}

fn duration_millis_i32(duration: Duration) -> i32 {
    i32::try_from(duration.as_millis()).unwrap_or(i32::MAX)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn contextual(error: io::Error, context: &str) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{
        BINDING_ERROR_RESPONSE, BINDING_SUCCESS_RESPONSE, MAGIC_COOKIE,
        NatFiltering, NatMapping, TransactionId, build_binding_request,
        change_request_attribute, parse_response, transaction_id_from_message,
    };

    fn address_attribute(kind: u16, address: std::net::SocketAddr) -> Vec<u8> {
        let mut value = vec![0, if address.is_ipv4() { 1 } else { 2 }];
        value.extend_from_slice(&address.port().to_be_bytes());
        match address.ip() {
            std::net::IpAddr::V4(address) => {
                value.extend_from_slice(&address.octets())
            }
            std::net::IpAddr::V6(address) => {
                value.extend_from_slice(&address.octets())
            }
        }
        let mut attribute = Vec::new();
        attribute.extend_from_slice(&kind.to_be_bytes());
        attribute.extend_from_slice(&(value.len() as u16).to_be_bytes());
        attribute.extend_from_slice(&value);
        while attribute.len() % 4 != 0 {
            attribute.push(0);
        }
        attribute
    }

    fn response(
        message_type: u16,
        transaction_id: TransactionId,
        attributes: &[u8],
    ) -> Vec<u8> {
        let mut message = vec![0_u8; 20];
        message[..2].copy_from_slice(&message_type.to_be_bytes());
        message[2..4].copy_from_slice(&(attributes.len() as u16).to_be_bytes());
        message[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message[8..20].copy_from_slice(&transaction_id);
        message.extend_from_slice(attributes);
        message
    }

    #[test]
    fn binding_wire_and_response_parsing_match_rfc_layout() {
        let transaction_id = *b"abcdefghijkl";
        let request = build_binding_request(
            transaction_id,
            &[change_request_attribute(6)],
        );
        assert_eq!(&request[..4], &[0, 1, 0, 8]);
        assert_eq!(transaction_id_from_message(&request), Some(transaction_id));
        assert_eq!(&request[20..], &[0, 3, 0, 4, 0, 0, 0, 6]);

        let mapped = "192.0.2.1:3478".parse().unwrap();
        let other = "198.51.100.2:3479".parse().unwrap();
        let mut attributes = address_attribute(0x0001, mapped);
        attributes.extend(address_attribute(0x802c, other));
        let parsed = parse_response(
            &response(BINDING_SUCCESS_RESPONSE, transaction_id, &attributes),
            transaction_id,
        )
        .unwrap();
        assert_eq!(parsed.external_addr(), Some(mapped));
        assert_eq!(parsed.other_addr, Some(other));

        let error_attribute = [0, 9, 0, 7, 0, 0, 4, 0, b'B', b'a', b'd', 0];
        let error = parse_response(
            &response(BINDING_ERROR_RESPONSE, transaction_id, &error_attribute),
            transaction_id,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "STUN error 400: Bad");
        assert_eq!(
            NatMapping::EndpointIndependent.to_string(),
            "Endpoint Independent"
        );
        assert_eq!(
            NatFiltering::AddressDependent.to_string(),
            "Address Dependent"
        );
    }
}
