//! GlobalProtect ESP ICMP probe packets.

use std::net::IpAddr;

use thiserror::Error;

pub const GLOBALPROTECT_PROBE_IDENTIFIER: u16 = 0x4747;
pub const GLOBALPROTECT_PROBE_PAYLOAD: [u8; 16] = *b"monitor\0\0pan ha ";
const IPV4_HEADER_SIZE: usize = 20;
const IPV6_HEADER_SIZE: usize = 40;
const ICMP_HEADER_SIZE: usize = 8;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GlobalProtectProbeError {
    #[error("ESP probe requires matching assigned and magic addresses")]
    AddressFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalProtectEspProbe {
    pub assigned: IpAddr,
    pub magic: IpAddr,
}

impl GlobalProtectEspProbe {
    pub fn build(
        &self,
        sequence: u16,
    ) -> Result<Vec<u8>, GlobalProtectProbeError> {
        match (self.assigned, self.magic) {
            (IpAddr::V4(assigned), IpAddr::V4(magic)) => Ok(build_ipv4_probe(
                sequence,
                assigned.octets(),
                magic.octets(),
            )),
            (IpAddr::V6(assigned), IpAddr::V6(magic)) => Ok(build_ipv6_probe(
                sequence,
                assigned.octets(),
                magic.octets(),
            )),
            _ => Err(GlobalProtectProbeError::AddressFamily),
        }
    }

    pub fn matches(&self, packet: &[u8]) -> bool {
        match self.magic {
            IpAddr::V4(magic) => match_ipv4_probe(packet, magic.octets()),
            IpAddr::V6(magic) => match_ipv6_probe(packet, magic.octets()),
        }
    }
}

fn build_ipv4_probe(
    sequence: u16,
    assigned: [u8; 4],
    magic: [u8; 4],
) -> Vec<u8> {
    let mut packet = vec![0_u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + 16];
    packet[0] = 0x45;
    let packet_length = packet.len() as u16;
    packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
    packet[4..6].copy_from_slice(&GLOBALPROTECT_PROBE_IDENTIFIER.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&assigned);
    packet[16..20].copy_from_slice(&magic);
    let header_checksum = internet_checksum(&packet[..IPV4_HEADER_SIZE], 0);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    let icmp = &mut packet[IPV4_HEADER_SIZE..];
    icmp[0] = 8;
    icmp[4..6].copy_from_slice(&GLOBALPROTECT_PROBE_IDENTIFIER.to_be_bytes());
    icmp[6..8].copy_from_slice(&sequence.to_be_bytes());
    icmp[ICMP_HEADER_SIZE..].copy_from_slice(&GLOBALPROTECT_PROBE_PAYLOAD);
    let checksum = internet_checksum(icmp, 0);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn build_ipv6_probe(
    sequence: u16,
    assigned: [u8; 16],
    magic: [u8; 16],
) -> Vec<u8> {
    let mut packet = vec![0_u8; IPV6_HEADER_SIZE + ICMP_HEADER_SIZE + 16];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&24_u16.to_be_bytes());
    packet[6] = 58;
    packet[7] = 128;
    packet[8..24].copy_from_slice(&assigned);
    packet[24..40].copy_from_slice(&magic);
    let icmp = &mut packet[IPV6_HEADER_SIZE..];
    icmp[0] = 128;
    let mut identifier = GLOBALPROTECT_PROBE_IDENTIFIER.to_be_bytes();
    let _ = getrandom::fill(&mut identifier);
    icmp[4..6].copy_from_slice(&identifier);
    icmp[6..8].copy_from_slice(&sequence.to_be_bytes());
    icmp[ICMP_HEADER_SIZE..].copy_from_slice(&GLOBALPROTECT_PROBE_PAYLOAD);
    let mut pseudo_sum = checksum_words(&assigned, 0);
    pseudo_sum = checksum_words(&magic, pseudo_sum);
    pseudo_sum += icmp.len() as u32;
    pseudo_sum += 58;
    let checksum = internet_checksum(icmp, pseudo_sum);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn match_ipv4_probe(packet: &[u8], magic: [u8; 4]) -> bool {
    if packet.len() < IPV4_HEADER_SIZE + 1
        || packet.first().map(|byte| byte >> 4) != Some(4)
        || packet[9] != 1
        || packet[12..16] != magic
    {
        return false;
    }
    let header_size = usize::from(packet[0] & 0x0f) * 4;
    let payload_offset = header_size + ICMP_HEADER_SIZE;
    header_size >= IPV4_HEADER_SIZE
        && packet.len() >= payload_offset + GLOBALPROTECT_PROBE_PAYLOAD.len()
        && packet[header_size] == 0
        && packet[payload_offset..payload_offset + 16]
            == GLOBALPROTECT_PROBE_PAYLOAD
}

fn match_ipv6_probe(packet: &[u8], magic: [u8; 16]) -> bool {
    let payload_offset = IPV6_HEADER_SIZE + ICMP_HEADER_SIZE;
    packet.len() >= payload_offset + GLOBALPROTECT_PROBE_PAYLOAD.len()
        && packet.first().map(|byte| byte >> 4) == Some(6)
        && packet[6] == 58
        && packet[8..24] == magic
        && packet[IPV6_HEADER_SIZE] == 129
        && packet[payload_offset..payload_offset + 16]
            == GLOBALPROTECT_PROBE_PAYLOAD
}

pub fn internet_checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = checksum_words(data, initial);
    while sum > 0xffff {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !(sum as u16)
}

fn checksum_words(mut data: &[u8], mut sum: u32) -> u32 {
    while data.len() >= 2 {
        sum += u32::from(u16::from_be_bytes([data[0], data[1]]));
        data = &data[2..];
    }
    if let Some(value) = data.first() {
        sum += u32::from(*value) << 8;
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_probe_has_valid_headers_and_matches_reply() {
        let probe = GlobalProtectEspProbe {
            assigned: "10.0.0.2".parse().unwrap(),
            magic: "10.0.0.1".parse().unwrap(),
        };
        let request = probe.build(7).unwrap();
        assert_eq!(request.len(), 44);
        assert_eq!(internet_checksum(&request[..20], 0), 0);
        assert_eq!(internet_checksum(&request[20..], 0), 0);
        assert_eq!(&request[6..8], &0x4000_u16.to_be_bytes());
        assert_eq!(&request[26..28], &7_u16.to_be_bytes());
        assert!(!probe.matches(&request));
        let mut reply = request;
        reply[12..16].copy_from_slice(&[10, 0, 0, 1]);
        reply[16..20].copy_from_slice(&[10, 0, 0, 2]);
        reply[20] = 0;
        assert!(probe.matches(&reply));
    }

    #[test]
    fn ipv6_probe_checksum_and_reply_match() {
        let probe = GlobalProtectEspProbe {
            assigned: "2001:db8::2".parse().unwrap(),
            magic: "2001:db8::1".parse().unwrap(),
        };
        let request = probe.build(9).unwrap();
        assert_eq!(request.len(), 64);
        assert_eq!(&request[46..48], &9_u16.to_be_bytes());
        assert!(!probe.matches(&request));
        let mut reply = request;
        let magic = match probe.magic {
            IpAddr::V6(address) => address.octets(),
            _ => unreachable!(),
        };
        reply[8..24].copy_from_slice(&magic);
        reply[40] = 129;
        assert!(probe.matches(&reply));
    }

    #[test]
    fn mismatched_address_families_are_rejected() {
        let probe = GlobalProtectEspProbe {
            assigned: "10.0.0.2".parse().unwrap(),
            magic: "2001:db8::1".parse().unwrap(),
        };
        assert_eq!(
            probe.build(0).unwrap_err(),
            GlobalProtectProbeError::AddressFamily
        );
    }
}
