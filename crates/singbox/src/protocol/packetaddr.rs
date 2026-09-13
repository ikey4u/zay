//! V2Ray packet-address framing used by VMess and VLESS UDP streams.

use std::{io, net::IpAddr};

use crate::{
    adapter::{PacketConnection, PacketFuture, PacketStream},
    common::network::SocksAddr,
};

pub const MAGIC_ADDRESS: &str = "sp.packet-addr.v2fly.arpa";

pub fn is_magic(address: &SocksAddr) -> bool {
    matches!(address, SocksAddr::Domain { host, .. } if host.eq_ignore_ascii_case(MAGIC_ADDRESS))
}

pub struct PacketAddrConnection {
    upstream: PacketStream,
}

impl PacketAddrConnection {
    pub fn new(upstream: PacketStream) -> Self {
        Self { upstream }
    }
}

impl PacketConnection for PacketAddrConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let mut packet = encode_address(destination)?;
            packet.extend_from_slice(data);
            self.upstream.send_to(&packet, destination).await?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut packet = vec![0_u8; data.len().saturating_add(19)];
            let (size, _) = self.upstream.recv_from(&mut packet).await?;
            let (destination, consumed) = decode_address(&packet[..size])?;
            let payload = &packet[consumed..size];
            if payload.len() > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packetaddr payload exceeds receive buffer",
                ));
            }
            data[..payload.len()].copy_from_slice(payload);
            Ok((payload.len(), destination))
        })
    }
}

fn encode_address(destination: &SocksAddr) -> io::Result<Vec<u8>> {
    let SocksAddr::Ip(address) = destination else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "packetaddr does not support domain destinations",
        ));
    };
    let mut output = Vec::with_capacity(19);
    match address.ip() {
        IpAddr::V4(ip) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(2);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&address.port().to_be_bytes());
    Ok(output)
}

fn decode_address(input: &[u8]) -> io::Result<(SocksAddr, usize)> {
    let (ip, consumed) = match input.first().copied() {
        Some(1) if input.len() >= 7 => {
            (IpAddr::from(<[u8; 4]>::try_from(&input[1..5]).unwrap()), 7)
        }
        Some(2) if input.len() >= 19 => (
            IpAddr::from(<[u8; 16]>::try_from(&input[1..17]).unwrap()),
            19,
        ),
        Some(1 | 2) => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated packetaddr address",
            ));
        }
        Some(family) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown packetaddr family: {family}"),
            ));
        }
        None => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
    };
    let port =
        u16::from_be_bytes(input[consumed - 2..consumed].try_into().unwrap());
    Ok((SocksAddr::new(ip.to_string(), port), consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_wire_format_matches_v2ray_packetaddr() {
        assert_eq!(
            hex::encode(
                encode_address(&SocksAddr::new("192.0.2.1", 53)).unwrap()
            ),
            "01c00002010035"
        );
        let encoded =
            encode_address(&SocksAddr::new("2001:db8::1", 443)).unwrap();
        let (decoded, consumed) = decode_address(&encoded).unwrap();
        assert_eq!(decoded, SocksAddr::new("2001:db8::1", 443));
        assert_eq!(consumed, encoded.len());
    }
}
