//! PPP packet headers, control packets, and negotiation options.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use thiserror::Error;

use super::PPP_MAXIMUM_PAYLOAD_LENGTH;

pub const PPP_PROTOCOL_IPV4: u16 = 0x0021;
pub const PPP_PROTOCOL_IPV6: u16 = 0x0057;
pub const PPP_PROTOCOL_LCP: u16 = 0xc021;
pub const PPP_PROTOCOL_IPCP: u16 = 0x8021;
pub const PPP_PROTOCOL_IP6CP: u16 = 0x8057;
pub const PPP_PROTOCOL_CCP: u16 = 0x80fd;

pub const PPP_CODE_CONFIGURE_REQUEST: u8 = 1;
pub const PPP_CODE_CONFIGURE_ACKNOWLEDGEMENT: u8 = 2;
pub const PPP_CODE_CONFIGURE_NEGATIVE_ACKNOWLEDGEMENT: u8 = 3;
pub const PPP_CODE_CONFIGURE_REJECTION: u8 = 4;
pub const PPP_CODE_TERMINATE_REQUEST: u8 = 5;
pub const PPP_CODE_TERMINATE_ACKNOWLEDGEMENT: u8 = 6;
pub const PPP_CODE_CODE_REJECTION: u8 = 7;
pub const PPP_CODE_PROTOCOL_REJECTION: u8 = 8;
pub const PPP_CODE_ECHO_REQUEST: u8 = 9;
pub const PPP_CODE_ECHO_REPLY: u8 = 10;
pub const PPP_CODE_DISCARD_REQUEST: u8 = 11;

pub const PPP_LCP_OPTION_MRU: u8 = 1;
pub const PPP_LCP_OPTION_ASYNC_MAP: u8 = 2;
pub const PPP_LCP_OPTION_AUTHENTICATION: u8 = 3;
pub const PPP_LCP_OPTION_MAGIC: u8 = 5;
pub const PPP_LCP_OPTION_PROTOCOL_COMPRESSION: u8 = 7;
pub const PPP_LCP_OPTION_ADDRESS_COMPRESSION: u8 = 8;
pub const PPP_IPCP_OPTION_ADDRESSES: u8 = 1;
pub const PPP_IPCP_OPTION_COMPRESSION: u8 = 2;
pub const PPP_IPCP_OPTION_ADDRESS: u8 = 3;
pub const PPP_IPCP_OPTION_PRIMARY_DNS: u8 = 129;
pub const PPP_IPCP_OPTION_PRIMARY_NBNS: u8 = 130;
pub const PPP_IPCP_OPTION_SECONDARY_DNS: u8 = 131;
pub const PPP_IPCP_OPTION_SECONDARY_NBNS: u8 = 132;
pub const PPP_IP6CP_OPTION_INTERFACE_ID: u8 = 1;

pub const PPP_DEFAULT_MRU: u16 = 1500;
pub const PPP_MINIMUM_MRU: u16 = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppOption {
    pub kind: u8,
    pub value: Vec<u8>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppControlPacket {
    pub code: u8,
    pub identifier: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppPacket<'a> {
    pub protocol: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PppControlError {
    #[error("truncated PPP configuration option header")]
    TruncatedOptionHeader,
    #[error("invalid PPP configuration option length: {0}")]
    InvalidOptionLength(usize),
    #[error("PPP configuration option exceeds one-byte length field")]
    OptionTooLarge,
    #[error("PPP control packet exceeds maximum payload length")]
    ControlPacketTooLarge,
    #[error("PPP control packet is too short")]
    ControlPacketTooShort,
    #[error("invalid PPP control packet length: {0}")]
    InvalidControlPacketLength(usize),
    #[error("empty PPP packet")]
    EmptyPacket,
    #[error("PPP packet is missing a protocol field")]
    MissingProtocol,
    #[error("PPP packet has a truncated protocol field")]
    TruncatedProtocol,
    #[error("PPP protocol field has an invalid low bit")]
    InvalidProtocolLowBit,
    #[error("invalid PPP IPv4 option length: {0}")]
    InvalidIpv4OptionLength(usize),
    #[error("invalid PPP IPv6 interface identifier length: {0}")]
    InvalidIpv6InterfaceIdLength(usize),
}

pub fn parse_ppp_options(
    mut payload: &[u8],
) -> Result<Vec<PppOption>, PppControlError> {
    let mut result = Vec::new();
    while !payload.is_empty() {
        if payload.len() < 2 {
            return Err(PppControlError::TruncatedOptionHeader);
        }
        let length = usize::from(payload[1]);
        if length < 2 || length > payload.len() {
            return Err(PppControlError::InvalidOptionLength(length));
        }
        result.push(PppOption {
            kind: payload[0],
            value: payload[2..length].to_vec(),
            raw: payload[..length].to_vec(),
        });
        payload = &payload[length..];
    }
    Ok(result)
}

pub fn append_ppp_option(
    destination: &mut Vec<u8>,
    kind: u8,
    value: &[u8],
) -> Result<(), PppControlError> {
    let length = value
        .len()
        .checked_add(2)
        .and_then(|length| u8::try_from(length).ok())
        .ok_or(PppControlError::OptionTooLarge)?;
    destination.extend_from_slice(&[kind, length]);
    destination.extend_from_slice(value);
    Ok(())
}

pub fn append_ppp_option_u16(
    destination: &mut Vec<u8>,
    kind: u8,
    value: u16,
) -> Result<(), PppControlError> {
    append_ppp_option(destination, kind, &value.to_be_bytes())
}

pub fn append_ppp_option_u32(
    destination: &mut Vec<u8>,
    kind: u8,
    value: u32,
) -> Result<(), PppControlError> {
    append_ppp_option(destination, kind, &value.to_be_bytes())
}

pub fn build_ppp_control_packet(
    code: u8,
    identifier: u8,
    payload: &[u8],
) -> Result<Vec<u8>, PppControlError> {
    let packet_length = payload
        .len()
        .checked_add(4)
        .ok_or(PppControlError::ControlPacketTooLarge)?;
    if packet_length > PPP_MAXIMUM_PAYLOAD_LENGTH {
        return Err(PppControlError::ControlPacketTooLarge);
    }
    let mut packet = Vec::with_capacity(packet_length);
    packet.extend_from_slice(&[
        code,
        identifier,
        (packet_length >> 8) as u8,
        packet_length as u8,
    ]);
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub fn parse_ppp_control_packet(
    packet: &[u8],
) -> Result<PppControlPacket, PppControlError> {
    if packet.len() < 4 {
        return Err(PppControlError::ControlPacketTooShort);
    }
    let packet_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if packet_length < 4 || packet_length > packet.len() {
        return Err(PppControlError::InvalidControlPacketLength(packet_length));
    }
    Ok(PppControlPacket {
        code: packet[0],
        identifier: packet[1],
        payload: packet[4..packet_length].to_vec(),
    })
}

pub fn build_ppp_packet_header(
    protocol: u16,
    protocol_compression: bool,
    address_compression: bool,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(4);
    if protocol == PPP_PROTOCOL_LCP || !address_compression {
        header.extend_from_slice(&[0xff, 0x03]);
    }
    if protocol <= u8::MAX.into() && protocol_compression {
        header.push(protocol as u8);
    } else {
        header.extend_from_slice(&protocol.to_be_bytes());
    }
    header
}

pub fn parse_ppp_packet(
    packet: &[u8],
) -> Result<PppPacket<'_>, PppControlError> {
    if packet.is_empty() {
        return Err(PppControlError::EmptyPacket);
    }
    let mut position =
        usize::from(packet.len() >= 2 && packet[..2] == [0xff, 0x03]) * 2;
    if position >= packet.len() {
        return Err(PppControlError::MissingProtocol);
    }
    let first = packet[position];
    position += 1;
    let protocol = if first & 1 != 0 {
        u16::from(first)
    } else {
        if position >= packet.len() {
            return Err(PppControlError::TruncatedProtocol);
        }
        let protocol = u16::from_be_bytes([first, packet[position]]);
        position += 1;
        if protocol & 1 == 0 {
            return Err(PppControlError::InvalidProtocolLowBit);
        }
        protocol
    };
    Ok(PppPacket {
        protocol,
        payload: &packet[position..],
    })
}

pub fn random_ppp_magic() -> io::Result<[u8; 4]> {
    loop {
        let mut magic = [0_u8; 4];
        getrandom::fill(&mut magic).map_err(io::Error::other)?;
        if magic != [0; 4] {
            return Ok(magic);
        }
    }
}

pub fn ppp_ipv4_from_bytes(value: &[u8]) -> Result<Ipv4Addr, PppControlError> {
    let value: [u8; 4] = value
        .try_into()
        .map_err(|_| PppControlError::InvalidIpv4OptionLength(value.len()))?;
    Ok(Ipv4Addr::from(value))
}

pub fn ppp_ipv6_from_interface_id(
    value: &[u8],
) -> Result<Ipv6Addr, PppControlError> {
    let identifier: [u8; 8] = value.try_into().map_err(|_| {
        PppControlError::InvalidIpv6InterfaceIdLength(value.len())
    })?;
    let mut address = [0_u8; 16];
    address[..2].copy_from_slice(&[0xfe, 0x80]);
    address[8..].copy_from_slice(&identifier);
    Ok(Ipv6Addr::from(address))
}

pub fn ppp_interface_id(address: IpAddr) -> [u8; 8] {
    let IpAddr::V6(address) = address else {
        return [0; 8];
    };
    address.octets()[8..]
        .try_into()
        .expect("fixed slice length")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_and_control_packets_round_trip() {
        let mut options = Vec::new();
        append_ppp_option_u16(&mut options, PPP_LCP_OPTION_MRU, 1400).unwrap();
        append_ppp_option_u32(&mut options, PPP_LCP_OPTION_ASYNC_MAP, 0)
            .unwrap();
        let parsed = parse_ppp_options(&options).unwrap();
        assert_eq!(parsed[0].value, 1400_u16.to_be_bytes());
        assert_eq!(parsed[1].raw, [2, 6, 0, 0, 0, 0]);
        let packet =
            build_ppp_control_packet(PPP_CODE_CONFIGURE_REQUEST, 7, &options)
                .unwrap();
        let parsed = parse_ppp_control_packet(&packet).unwrap();
        assert_eq!(parsed.code, PPP_CODE_CONFIGURE_REQUEST);
        assert_eq!(parsed.identifier, 7);
        assert_eq!(parsed.payload, options);
    }

    #[test]
    fn packet_headers_cover_all_compression_combinations() {
        assert_eq!(
            build_ppp_packet_header(PPP_PROTOCOL_LCP, true, true),
            [0xff, 0x03, 0xc0, 0x21]
        );
        assert_eq!(
            build_ppp_packet_header(PPP_PROTOCOL_IPV4, true, true),
            [0x21]
        );
        assert_eq!(
            build_ppp_packet_header(PPP_PROTOCOL_IPV6, false, true),
            [0x00, 0x57]
        );
        let packet = parse_ppp_packet(&[0xff, 0x03, 0x21, 1, 2]).unwrap();
        assert_eq!(packet.protocol, PPP_PROTOCOL_IPV4);
        assert_eq!(packet.payload, [1, 2]);
    }

    #[test]
    fn rejects_malformed_options_control_and_protocol_fields() {
        assert!(matches!(
            parse_ppp_options(&[1]),
            Err(PppControlError::TruncatedOptionHeader)
        ));
        assert!(matches!(
            parse_ppp_options(&[1, 1]),
            Err(PppControlError::InvalidOptionLength(1))
        ));
        assert!(matches!(
            parse_ppp_control_packet(&[1, 1, 0, 8]),
            Err(PppControlError::InvalidControlPacketLength(8))
        ));
        assert!(matches!(
            parse_ppp_packet(&[0x00, 0x20]),
            Err(PppControlError::InvalidProtocolLowBit)
        ));
    }

    #[test]
    fn interface_ids_map_to_link_local_addresses() {
        let identifier = [1, 2, 3, 4, 5, 6, 7, 8];
        let address = ppp_ipv6_from_interface_id(&identifier).unwrap();
        assert_eq!(address.to_string(), "fe80::102:304:506:708");
        assert_eq!(ppp_interface_id(address.into()), identifier);
        assert_eq!(ppp_interface_id(Ipv4Addr::LOCALHOST.into()), [0; 8]);
        assert_ne!(random_ppp_magic().unwrap(), [0; 4]);
    }
}
