use std::net::IpAddr;

use super::{OpenVpnAuthDigest, SessionId};

pub const DEFAULT_HANDSHAKE_WINDOW_SECONDS: i64 = 60;
pub const SESSION_ID_HMAC_PAST_BUCKETS: i64 = 2;
pub const SESSION_ID_HMAC_FUTURE_BUCKETS: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionPeerAddress {
    Udp { ip: IpAddr, port: u16, zone: String },
    Other { network: String, address: String },
}

#[derive(Debug, Clone)]
pub struct SessionIdHmacSigner {
    hmac_key: [u8; 32],
    handshake_window: i64,
}

impl SessionIdHmacSigner {
    pub fn new() -> Result<Self, getrandom::Error> {
        let mut hmac_key = [0; 32];
        getrandom::fill(&mut hmac_key)?;
        Ok(Self {
            hmac_key,
            handshake_window: DEFAULT_HANDSHAKE_WINDOW_SECONDS,
        })
    }

    pub fn with_key(hmac_key: [u8; 32], handshake_window: i64) -> Self {
        Self {
            hmac_key,
            handshake_window,
        }
    }

    pub fn derive_at(
        &self,
        client_session_id: SessionId,
        peer_address: Option<&SessionPeerAddress>,
        current_time: i64,
        offset: i64,
    ) -> SessionId {
        let bucket_width = (self.handshake_window + 1) / 2;
        let bucket = (current_time / bucket_width) as u32;
        let bucket = bucket.wrapping_add(offset as u32);
        let mut input = Vec::new();
        input.extend_from_slice(&bucket.to_be_bytes());
        input.extend_from_slice(&encode_peer_address(peer_address));
        input.extend_from_slice(&client_session_id);
        OpenVpnAuthDigest::Sha256.sign(&self.hmac_key, &input)[..8]
            .try_into()
            .unwrap()
    }

    pub fn validate_at(
        &self,
        client_session_id: SessionId,
        peer_address: Option<&SessionPeerAddress>,
        server_session_id: SessionId,
        current_time: i64,
    ) -> bool {
        (-SESSION_ID_HMAC_PAST_BUCKETS..=SESSION_ID_HMAC_FUTURE_BUCKETS).any(
            |offset| {
                constant_time_eq(
                    &self.derive_at(
                        client_session_id,
                        peer_address,
                        current_time,
                        offset,
                    ),
                    &server_session_id,
                )
            },
        )
    }
}

fn encode_peer_address(peer: Option<&SessionPeerAddress>) -> Vec<u8> {
    let Some(peer) = peer else {
        return Vec::new();
    };
    match peer {
        SessionPeerAddress::Udp { ip, port, zone } => {
            let (family, address): (u8, Vec<u8>) = match ip {
                IpAddr::V4(address) => (4, address.octets().to_vec()),
                IpAddr::V6(address) => (6, address.octets().to_vec()),
            };
            let zone = zone.as_bytes();
            let mut encoded =
                Vec::with_capacity(1 + address.len() + 4 + zone.len());
            encoded.push(family);
            encoded.extend_from_slice(&address);
            encoded.extend_from_slice(&port.to_be_bytes());
            encoded.extend_from_slice(&(zone.len() as u16).to_be_bytes());
            encoded.extend_from_slice(zone);
            encoded
        }
        SessionPeerAddress::Other { network, address } => {
            let network = network.as_bytes();
            let address = address.as_bytes();
            let mut encoded =
                Vec::with_capacity(4 + network.len() + address.len());
            encoded.extend_from_slice(&(network.len() as u16).to_be_bytes());
            encoded.extend_from_slice(network);
            encoded.extend_from_slice(&(address.len() as u16).to_be_bytes());
            encoded.extend_from_slice(address);
            encoded
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_address_and_time_bound_session_ids() {
        let signer = SessionIdHmacSigner::with_key([7; 32], 60);
        let client = *b"client01";
        let peer = SessionPeerAddress::Udp {
            ip: "192.0.2.1".parse().unwrap(),
            port: 1194,
            zone: String::new(),
        };
        let derived = signer.derive_at(client, Some(&peer), 120, 0);
        assert_eq!(hex::encode(derived), "7234f0184d5c151a");
        assert!(signer.validate_at(client, Some(&peer), derived, 149));
        assert!(!signer.validate_at(client, Some(&peer), derived, 300));
    }

    #[test]
    fn encodes_non_udp_addresses_with_length_prefixes() {
        assert_eq!(
            hex::encode(encode_peer_address(Some(
                &SessionPeerAddress::Other {
                    network: "tcp".into(),
                    address: "example:443".into(),
                }
            ))),
            "0003746370000b6578616d706c653a343433"
        );
    }
}
