use std::net::IpAddr;

use super::{DataChannelFraming, OpenVpnDataCodec};

const IPV4_HEADER_MIN_LENGTH: usize = 20;
const IPV6_HEADER_LENGTH: usize = 40;
const TCP_HEADER_MIN_LENGTH: usize = 20;
const UDP_HEADER_LENGTH: usize = 8;
const TCP_CHECKSUM_OFFSET: usize = 16;
const TCP_SYN: u8 = 0x02;
const TCP_OPTION_END: u8 = 0;
const TCP_OPTION_NOP: u8 = 1;
const TCP_OPTION_MSS: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MssClamp {
    pub enabled: bool,
    pub maximum_segment_size: u16,
}

impl MssClamp {
    pub fn apply(&self, packet: &[u8]) -> Vec<u8> {
        if !self.enabled {
            return packet.to_vec();
        }
        let mut cloned = packet.to_vec();
        if self.apply_in_place(&mut cloned) {
            cloned
        } else {
            packet.to_vec()
        }
    }

    pub fn apply_in_place(&self, packet: &mut [u8]) -> bool {
        if !self.enabled || packet.is_empty() {
            return false;
        }
        let maximum = if packet[0] >> 4 == 6 {
            self.maximum_segment_size.wrapping_sub(
                (IPV6_HEADER_LENGTH - IPV4_HEADER_MIN_LENGTH) as u16,
            )
        } else {
            self.maximum_segment_size
        };
        let Some(tcp) = locate_tcp_syn_segment(packet) else {
            return false;
        };
        clamp_tcp_syn_mss(tcp, maximum)
    }
}

pub fn calculate_mss_clamp(
    mss_fix: u32,
    mss_fix_mode: &str,
    data_framing: Option<&DataChannelFraming>,
    codec: &dyn OpenVpnDataCodec,
    mut packet_header_size: usize,
    outer_transport_overhead: usize,
) -> MssClamp {
    if mss_fix == 0 {
        return MssClamp::default();
    }
    if mss_fix_mode == "fixed" {
        return MssClamp {
            enabled: true,
            maximum_segment_size: (mss_fix as u16).wrapping_sub(40),
        };
    }
    if mss_fix_mode == "mtu" {
        packet_header_size += outer_transport_overhead;
    }
    let framing_overhead =
        data_framing.map_or(0, DataChannelFraming::payload_overhead);
    let budget = calculate_data_payload_budget(
        mss_fix as isize,
        codec,
        packet_header_size,
        IPV4_HEADER_MIN_LENGTH + TCP_HEADER_MIN_LENGTH + framing_overhead,
    );
    MssClamp {
        enabled: true,
        maximum_segment_size: budget as u16,
    }
}

pub fn calculate_data_payload_budget(
    packet_size: isize,
    codec: &dyn OpenVpnDataCodec,
    packet_header_size: usize,
    fixed_payload_size: usize,
) -> isize {
    let minimum_packet_length =
        packet_header_size + codec.encoded_length(fixed_payload_size);
    if minimum_packet_length as isize >= packet_size {
        return packet_size - minimum_packet_length as isize;
    }
    let mut minimum_payload_size = 1_usize;
    let mut maximum_payload_size = packet_size as usize;
    while minimum_payload_size < maximum_payload_size {
        let candidate = minimum_payload_size
            + (maximum_payload_size - minimum_payload_size).div_ceil(2);
        let encoded = packet_header_size
            + codec.encoded_length(fixed_payload_size + candidate);
        if encoded <= packet_size as usize {
            minimum_payload_size = candidate;
        } else {
            maximum_payload_size = candidate - 1;
        }
    }
    minimum_payload_size as isize
}

pub fn openvpn_outer_transport_overhead(
    protocol: &str,
    remote_ip: Option<IpAddr>,
) -> usize {
    let ipv6 = remote_ip.is_some_and(|ip| ip.is_ipv6())
        || (remote_ip.is_none() && protocol.ends_with('6'));
    let ip_header = if ipv6 {
        IPV6_HEADER_LENGTH
    } else {
        IPV4_HEADER_MIN_LENGTH
    };
    ip_header
        + if protocol.starts_with("tcp") {
            TCP_HEADER_MIN_LENGTH
        } else {
            UDP_HEADER_LENGTH
        }
}

fn locate_tcp_syn_segment(packet: &mut [u8]) -> Option<&mut [u8]> {
    let ip_header_length = match packet.first()? >> 4 {
        4 => {
            if packet.len() < IPV4_HEADER_MIN_LENGTH
                || u16::from_be_bytes(packet[2..4].try_into().unwrap()) as usize
                    != packet.len()
                || u16::from_be_bytes(packet[6..8].try_into().unwrap()) & 0x3fff
                    != 0
            {
                return None;
            }
            let length = (packet[0] as usize & 0x0f) * 4;
            if length < IPV4_HEADER_MIN_LENGTH
                || length > packet.len()
                || packet[9] != 6
            {
                return None;
            }
            length
        }
        6 => {
            if packet.len() < IPV6_HEADER_LENGTH
                || u16::from_be_bytes(packet[4..6].try_into().unwrap()) as usize
                    + IPV6_HEADER_LENGTH
                    != packet.len()
                || packet[6] != 6
            {
                return None;
            }
            IPV6_HEADER_LENGTH
        }
        _ => return None,
    };
    let tcp = &mut packet[ip_header_length..];
    (tcp.len() >= TCP_HEADER_MIN_LENGTH && tcp[13] & TCP_SYN != 0)
        .then_some(tcp)
}

fn clamp_tcp_syn_mss(tcp: &mut [u8], maximum: u16) -> bool {
    let data_offset = (tcp[12] >> 4) as usize * 4;
    if data_offset < TCP_HEADER_MIN_LENGTH || data_offset > tcp.len() {
        return false;
    }
    let mut clamped = false;
    let mut offset = TCP_HEADER_MIN_LENGTH;
    while offset < data_offset {
        let kind = tcp[offset];
        if kind == TCP_OPTION_END {
            break;
        }
        if kind == TCP_OPTION_NOP {
            offset += 1;
            continue;
        }
        if offset + 1 >= data_offset {
            break;
        }
        let length = tcp[offset + 1] as usize;
        if length < 2 || offset + length > data_offset {
            break;
        }
        if kind == TCP_OPTION_MSS && length == 4 {
            let value_offset = offset + 2;
            let advertised = u16::from_be_bytes(
                tcp[value_offset..value_offset + 2].try_into().unwrap(),
            );
            if advertised > maximum {
                tcp[value_offset..value_offset + 2]
                    .copy_from_slice(&maximum.to_be_bytes());
                update_checksum(tcp, value_offset, advertised, maximum);
                clamped = true;
            }
        }
        offset += length;
    }
    clamped
}

fn update_checksum(
    tcp: &mut [u8],
    field_offset: usize,
    mut old: u16,
    mut new: u16,
) {
    if !field_offset.is_multiple_of(2) {
        old = old.swap_bytes();
        new = new.swap_bytes();
    }
    let current = u16::from_be_bytes(
        tcp[TCP_CHECKSUM_OFFSET..TCP_CHECKSUM_OFFSET + 2]
            .try_into()
            .unwrap(),
    );
    let mut sum = (!current as u32) + (!old as u32) + new as u32;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    tcp[TCP_CHECKSUM_OFFSET..TCP_CHECKSUM_OFFSET + 2]
        .copy_from_slice(&(!(sum as u16)).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::protocol::openvpn::TlsAeadDataCodec;

    fn ipv4_syn(mss: u16) -> Vec<u8> {
        let mut packet = vec![0; 44];
        packet[0] = 0x45;
        let packet_length = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
        packet[9] = 6;
        let tcp = &mut packet[20..];
        tcp[12] = 6 << 4;
        tcp[13] = TCP_SYN;
        tcp[16..18].copy_from_slice(&0x1234_u16.to_be_bytes());
        tcp[20..24].copy_from_slice(&[
            TCP_OPTION_MSS,
            4,
            (mss >> 8) as u8,
            mss as u8,
        ]);
        packet
    }

    #[test]
    fn clamps_ipv4_syn_mss_and_updates_checksum_incrementally() {
        let original = ipv4_syn(1460);
        let clamp = MssClamp {
            enabled: true,
            maximum_segment_size: 1300,
        };
        let updated = clamp.apply(&original);
        assert_eq!(
            u16::from_be_bytes(updated[42..44].try_into().unwrap()),
            1300
        );
        assert_ne!(&updated[36..38], &original[36..38]);
        assert_eq!(clamp.apply(&updated), updated);
    }

    #[test]
    fn ignores_non_syn_fragments_and_malformed_lengths() {
        let mut packet = ipv4_syn(1460);
        packet[33] = 0;
        assert_eq!(
            MssClamp {
                enabled: true,
                maximum_segment_size: 1200
            }
            .apply(&packet),
            packet
        );
        packet[33] = TCP_SYN;
        packet[6] = 0x20;
        assert_eq!(
            MssClamp {
                enabled: true,
                maximum_segment_size: 1200
            }
            .apply(&packet),
            packet
        );
    }

    #[test]
    fn calculates_codec_aware_budget_and_outer_overhead() {
        let codec = TlsAeadDataCodec::new(
            &[0; 256],
            false,
            "AES-256-GCM",
            0,
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(calculate_data_payload_budget(1500, &codec, 4, 40), 1436);
        assert_eq!(
            openvpn_outer_transport_overhead("udp6", None),
            IPV6_HEADER_LENGTH + UDP_HEADER_LENGTH
        );
        assert_eq!(
            openvpn_outer_transport_overhead(
                "tcp",
                Some("127.0.0.1".parse().unwrap())
            ),
            IPV4_HEADER_MIN_LENGTH + TCP_HEADER_MIN_LENGTH
        );
    }
}
