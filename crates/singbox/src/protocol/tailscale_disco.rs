//! Tailscale encrypted discovery (`disco`) wire protocol.
//!
//! Disco messages are carried directly over UDP or inside DERP packets. This
//! module implements the complete current message set independently of socket
//! ownership so an embedding endpoint can use the same codec on both paths.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead as _, generic_array::GenericArray},
};
use thiserror::Error;

use super::tailscale::TailscaleDerpPacket;

pub const TAILSCALE_DISCO_MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";
pub const TAILSCALE_DISCO_KEY_LENGTH: usize = 32;
pub const TAILSCALE_DISCO_NONCE_LENGTH: usize = 24;
pub const TAILSCALE_DISCO_HEADER_LENGTH: usize =
    TAILSCALE_DISCO_MAGIC.len() + TAILSCALE_DISCO_KEY_LENGTH;
pub const TAILSCALE_DISCO_MESSAGE_HEADER_LENGTH: usize = 2;
pub const TAILSCALE_DISCO_TRANSACTION_ID_LENGTH: usize = 12;
pub const TAILSCALE_DISCO_ENDPOINT_LENGTH: usize = 18;
pub const TAILSCALE_DISCO_BIND_CHALLENGE_LENGTH: usize = 32;

pub const TAILSCALE_DISCO_TYPE_PING: u8 = 0x01;
pub const TAILSCALE_DISCO_TYPE_PONG: u8 = 0x02;
pub const TAILSCALE_DISCO_TYPE_CALL_ME_MAYBE: u8 = 0x03;
pub const TAILSCALE_DISCO_TYPE_BIND_UDP_RELAY_ENDPOINT: u8 = 0x04;
pub const TAILSCALE_DISCO_TYPE_BIND_UDP_RELAY_ENDPOINT_CHALLENGE: u8 = 0x05;
pub const TAILSCALE_DISCO_TYPE_BIND_UDP_RELAY_ENDPOINT_ANSWER: u8 = 0x06;
pub const TAILSCALE_DISCO_TYPE_CALL_ME_MAYBE_VIA: u8 = 0x07;
pub const TAILSCALE_DISCO_TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST: u8 = 0x08;
pub const TAILSCALE_DISCO_TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE: u8 = 0x09;

const DISCO_VERSION_ZERO: u8 = 0;
const BIND_COMMON_LENGTH: usize = 72;
const RELAY_ENDPOINT_FIXED_LENGTH: usize = 124;
const ALLOCATE_REQUEST_LENGTH: usize = 68;

#[derive(Debug, Error)]
pub enum TailscaleDiscoError {
    #[error("Tailscale disco key must not be all zero")]
    ZeroKey,
    #[error("Tailscale disco message is too short")]
    ShortMessage,
    #[error("Tailscale disco wrapper has invalid magic")]
    InvalidMagic,
    #[error("unknown Tailscale disco message type 0x{0:02x}")]
    UnknownMessageType(u8),
    #[error("Tailscale disco NaCl box authentication failed")]
    BoxAuthentication,
    #[error("failed to generate Tailscale disco nonce: {0}")]
    Random(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDiscoPing {
    pub transaction_id: [u8; TAILSCALE_DISCO_TRANSACTION_ID_LENGTH],
    pub node_key: Option<[u8; TAILSCALE_DISCO_KEY_LENGTH]>,
    pub padding: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDiscoPong {
    pub transaction_id: [u8; TAILSCALE_DISCO_TRANSACTION_ID_LENGTH],
    pub source: SocketAddr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleDiscoCallMeMaybe {
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDiscoBindCommon {
    pub vni: u32,
    pub generation: u32,
    pub remote_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
    pub challenge: [u8; TAILSCALE_DISCO_BIND_CHALLENGE_LENGTH],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDiscoRelayEndpoint {
    pub server_disco_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
    pub client_disco_keys: [[u8; TAILSCALE_DISCO_KEY_LENGTH]; 2],
    pub lamport_id: u64,
    pub vni: u32,
    pub bind_lifetime_nanoseconds: u64,
    pub steady_state_lifetime_nanoseconds: u64,
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleDiscoMessage {
    Ping(TailscaleDiscoPing),
    Pong(TailscaleDiscoPong),
    CallMeMaybe(TailscaleDiscoCallMeMaybe),
    BindUdpRelayEndpoint(TailscaleDiscoBindCommon),
    BindUdpRelayEndpointChallenge(TailscaleDiscoBindCommon),
    BindUdpRelayEndpointAnswer(TailscaleDiscoBindCommon),
    CallMeMaybeVia(TailscaleDiscoRelayEndpoint),
    AllocateUdpRelayEndpointRequest {
        client_disco_keys: [[u8; TAILSCALE_DISCO_KEY_LENGTH]; 2],
        generation: u32,
    },
    AllocateUdpRelayEndpointResponse {
        generation: u32,
        endpoint: TailscaleDiscoRelayEndpoint,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDiscoPacket {
    pub sender_public_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
    pub nonce: [u8; TAILSCALE_DISCO_NONCE_LENGTH],
    pub message: TailscaleDiscoMessage,
}

pub fn tailscale_disco_public_key(
    private_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
) -> Result<[u8; TAILSCALE_DISCO_KEY_LENGTH], TailscaleDiscoError> {
    validate_key(&private_key)?;
    Ok(*SecretKey::from(private_key).public_key().as_bytes())
}

pub fn looks_like_tailscale_disco_packet(packet: &[u8]) -> bool {
    packet.len() >= TAILSCALE_DISCO_HEADER_LENGTH + TAILSCALE_DISCO_NONCE_LENGTH
        && packet.starts_with(TAILSCALE_DISCO_MAGIC)
}

pub fn tailscale_disco_source(
    packet: &[u8],
) -> Option<[u8; TAILSCALE_DISCO_KEY_LENGTH]> {
    looks_like_tailscale_disco_packet(packet).then(|| {
        packet[TAILSCALE_DISCO_MAGIC.len()..TAILSCALE_DISCO_HEADER_LENGTH]
            .try_into()
            .expect("validated disco source key")
    })
}

pub fn encode_tailscale_disco_message(
    message: &TailscaleDiscoMessage,
) -> Result<Vec<u8>, TailscaleDiscoError> {
    let mut output = Vec::new();
    match message {
        TailscaleDiscoMessage::Ping(ping) => {
            append_header(&mut output, TAILSCALE_DISCO_TYPE_PING);
            output.extend_from_slice(&ping.transaction_id);
            if let Some(node_key) = ping.node_key {
                output.extend_from_slice(&node_key);
            }
            output.resize(output.len().saturating_add(ping.padding), 0);
        }
        TailscaleDiscoMessage::Pong(pong) => {
            append_header(&mut output, TAILSCALE_DISCO_TYPE_PONG);
            output.extend_from_slice(&pong.transaction_id);
            encode_endpoint(&mut output, pong.source);
        }
        TailscaleDiscoMessage::CallMeMaybe(call) => {
            append_header(&mut output, TAILSCALE_DISCO_TYPE_CALL_ME_MAYBE);
            for endpoint in &call.endpoints {
                encode_endpoint(&mut output, *endpoint);
            }
        }
        TailscaleDiscoMessage::BindUdpRelayEndpoint(common) => {
            append_header(
                &mut output,
                TAILSCALE_DISCO_TYPE_BIND_UDP_RELAY_ENDPOINT,
            );
            encode_bind_common(&mut output, common);
        }
        TailscaleDiscoMessage::BindUdpRelayEndpointChallenge(common) => {
            append_header(
                &mut output,
                TAILSCALE_DISCO_TYPE_BIND_UDP_RELAY_ENDPOINT_CHALLENGE,
            );
            encode_bind_common(&mut output, common);
        }
        TailscaleDiscoMessage::BindUdpRelayEndpointAnswer(common) => {
            append_header(
                &mut output,
                TAILSCALE_DISCO_TYPE_BIND_UDP_RELAY_ENDPOINT_ANSWER,
            );
            encode_bind_common(&mut output, common);
        }
        TailscaleDiscoMessage::CallMeMaybeVia(endpoint) => {
            append_header(&mut output, TAILSCALE_DISCO_TYPE_CALL_ME_MAYBE_VIA);
            encode_relay_endpoint(&mut output, endpoint);
        }
        TailscaleDiscoMessage::AllocateUdpRelayEndpointRequest {
            client_disco_keys,
            generation,
        } => {
            append_header(
                &mut output,
                TAILSCALE_DISCO_TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST,
            );
            output.extend_from_slice(&client_disco_keys[0]);
            output.extend_from_slice(&client_disco_keys[1]);
            output.extend_from_slice(&generation.to_be_bytes());
        }
        TailscaleDiscoMessage::AllocateUdpRelayEndpointResponse {
            generation,
            endpoint,
        } => {
            append_header(
                &mut output,
                TAILSCALE_DISCO_TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE,
            );
            output.extend_from_slice(&generation.to_be_bytes());
            encode_relay_endpoint(&mut output, endpoint);
        }
    }
    Ok(output)
}

pub fn parse_tailscale_disco_message(
    packet: &[u8],
) -> Result<TailscaleDiscoMessage, TailscaleDiscoError> {
    if packet.len() < TAILSCALE_DISCO_MESSAGE_HEADER_LENGTH {
        return Err(TailscaleDiscoError::ShortMessage);
    }
    let message_type = packet[0];
    let version = packet[1];
    let payload = &packet[TAILSCALE_DISCO_MESSAGE_HEADER_LENGTH..];
    match message_type {
        TAILSCALE_DISCO_TYPE_PING => parse_ping(payload),
        TAILSCALE_DISCO_TYPE_PONG => parse_pong(payload),
        TAILSCALE_DISCO_TYPE_CALL_ME_MAYBE => {
            Ok(TailscaleDiscoMessage::CallMeMaybe(
                if version == DISCO_VERSION_ZERO
                    && !payload.is_empty()
                    && payload
                        .len()
                        .is_multiple_of(TAILSCALE_DISCO_ENDPOINT_LENGTH)
                {
                    TailscaleDiscoCallMeMaybe {
                        endpoints: parse_endpoints(payload)?,
                    }
                } else {
                    TailscaleDiscoCallMeMaybe::default()
                },
            ))
        }
        TAILSCALE_DISCO_TYPE_BIND_UDP_RELAY_ENDPOINT => {
            Ok(TailscaleDiscoMessage::BindUdpRelayEndpoint(
                parse_bind_common(payload)?,
            ))
        }
        TAILSCALE_DISCO_TYPE_BIND_UDP_RELAY_ENDPOINT_CHALLENGE => {
            Ok(TailscaleDiscoMessage::BindUdpRelayEndpointChallenge(
                parse_bind_common(payload)?,
            ))
        }
        TAILSCALE_DISCO_TYPE_BIND_UDP_RELAY_ENDPOINT_ANSWER => {
            Ok(TailscaleDiscoMessage::BindUdpRelayEndpointAnswer(
                parse_bind_common(payload)?,
            ))
        }
        TAILSCALE_DISCO_TYPE_CALL_ME_MAYBE_VIA => {
            Ok(TailscaleDiscoMessage::CallMeMaybeVia(if version == 0 {
                parse_relay_endpoint(payload)?
            } else {
                empty_relay_endpoint()
            }))
        }
        TAILSCALE_DISCO_TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST => {
            if version != DISCO_VERSION_ZERO {
                return Ok(
                    TailscaleDiscoMessage::AllocateUdpRelayEndpointRequest {
                        client_disco_keys: [[0; 32]; 2],
                        generation: 0,
                    },
                );
            }
            if payload.len() < ALLOCATE_REQUEST_LENGTH {
                return Err(TailscaleDiscoError::ShortMessage);
            }
            Ok(TailscaleDiscoMessage::AllocateUdpRelayEndpointRequest {
                client_disco_keys: [
                    payload[..32].try_into().expect("32-byte disco key"),
                    payload[32..64].try_into().expect("32-byte disco key"),
                ],
                generation: u32::from_be_bytes(
                    payload[64..68].try_into().expect("four-byte generation"),
                ),
            })
        }
        TAILSCALE_DISCO_TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE => {
            if version != DISCO_VERSION_ZERO {
                return Ok(
                    TailscaleDiscoMessage::AllocateUdpRelayEndpointResponse {
                        generation: 0,
                        endpoint: empty_relay_endpoint(),
                    },
                );
            }
            if payload.len() < 4 {
                return Err(TailscaleDiscoError::ShortMessage);
            }
            Ok(TailscaleDiscoMessage::AllocateUdpRelayEndpointResponse {
                generation: u32::from_be_bytes(
                    payload[..4].try_into().expect("four-byte generation"),
                ),
                endpoint: parse_relay_endpoint(&payload[4..])?,
            })
        }
        other => Err(TailscaleDiscoError::UnknownMessageType(other)),
    }
}

pub fn seal_tailscale_disco_packet(
    private_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
    peer_public_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
    message: &TailscaleDiscoMessage,
) -> Result<Vec<u8>, TailscaleDiscoError> {
    let mut nonce = [0_u8; TAILSCALE_DISCO_NONCE_LENGTH];
    getrandom::fill(&mut nonce)
        .map_err(|error| TailscaleDiscoError::Random(error.to_string()))?;
    seal_tailscale_disco_packet_with_nonce(
        private_key,
        peer_public_key,
        nonce,
        message,
    )
}

pub fn seal_tailscale_disco_packet_with_nonce(
    private_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
    peer_public_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
    nonce: [u8; TAILSCALE_DISCO_NONCE_LENGTH],
    message: &TailscaleDiscoMessage,
) -> Result<Vec<u8>, TailscaleDiscoError> {
    validate_key(&private_key)?;
    validate_key(&peer_public_key)?;
    let sender_public_key = tailscale_disco_public_key(private_key)?;
    let plaintext = encode_tailscale_disco_message(message)?;
    let cipher = SalsaBox::new(
        &PublicKey::from(peer_public_key),
        &SecretKey::from(private_key),
    );
    let encrypted = cipher
        .encrypt(GenericArray::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| TailscaleDiscoError::BoxAuthentication)?;
    let mut packet = Vec::with_capacity(
        TAILSCALE_DISCO_HEADER_LENGTH + nonce.len() + encrypted.len(),
    );
    packet.extend_from_slice(TAILSCALE_DISCO_MAGIC);
    packet.extend_from_slice(&sender_public_key);
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&encrypted);
    Ok(packet)
}

pub fn open_tailscale_disco_packet(
    private_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
    packet: &[u8],
) -> Result<TailscaleDiscoPacket, TailscaleDiscoError> {
    validate_key(&private_key)?;
    if packet.len()
        < TAILSCALE_DISCO_HEADER_LENGTH + TAILSCALE_DISCO_NONCE_LENGTH
    {
        return Err(TailscaleDiscoError::ShortMessage);
    }
    if !packet.starts_with(TAILSCALE_DISCO_MAGIC) {
        return Err(TailscaleDiscoError::InvalidMagic);
    }
    let sender_public_key = packet
        [TAILSCALE_DISCO_MAGIC.len()..TAILSCALE_DISCO_HEADER_LENGTH]
        .try_into()
        .expect("validated disco sender key");
    validate_key(&sender_public_key)?;
    let nonce_offset = TAILSCALE_DISCO_HEADER_LENGTH;
    let payload_offset = nonce_offset + TAILSCALE_DISCO_NONCE_LENGTH;
    let nonce: [u8; TAILSCALE_DISCO_NONCE_LENGTH] = packet
        [nonce_offset..payload_offset]
        .try_into()
        .expect("validated disco nonce");
    let cipher = SalsaBox::new(
        &PublicKey::from(sender_public_key),
        &SecretKey::from(private_key),
    );
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&nonce), &packet[payload_offset..])
        .map_err(|_| TailscaleDiscoError::BoxAuthentication)?;
    Ok(TailscaleDiscoPacket {
        sender_public_key,
        nonce,
        message: parse_tailscale_disco_message(&plaintext)?,
    })
}

/// Decode a DERP-received payload when it is a disco message. Non-disco
/// WireGuard packets remain untouched for the endpoint's WireGuard engine.
pub fn open_tailscale_derp_disco_packet(
    private_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
    packet: &TailscaleDerpPacket,
) -> Result<Option<TailscaleDiscoPacket>, TailscaleDiscoError> {
    if !looks_like_tailscale_disco_packet(&packet.packet) {
        return Ok(None);
    }
    open_tailscale_disco_packet(private_key, &packet.packet).map(Some)
}

fn append_header(output: &mut Vec<u8>, message_type: u8) {
    output.extend_from_slice(&[message_type, DISCO_VERSION_ZERO]);
}

fn parse_ping(
    payload: &[u8],
) -> Result<TailscaleDiscoMessage, TailscaleDiscoError> {
    if payload.len() < TAILSCALE_DISCO_TRANSACTION_ID_LENGTH {
        return Err(TailscaleDiscoError::ShortMessage);
    }
    let transaction_id = payload[..TAILSCALE_DISCO_TRANSACTION_ID_LENGTH]
        .try_into()
        .expect("12-byte transaction ID");
    let remainder = &payload[TAILSCALE_DISCO_TRANSACTION_ID_LENGTH..];
    let node_key = (remainder.len() >= TAILSCALE_DISCO_KEY_LENGTH).then(|| {
        remainder[..TAILSCALE_DISCO_KEY_LENGTH]
            .try_into()
            .expect("32-byte node key")
    });
    let padding = remainder.len()
        - node_key.as_ref().map_or(0, |_| TAILSCALE_DISCO_KEY_LENGTH);
    Ok(TailscaleDiscoMessage::Ping(TailscaleDiscoPing {
        transaction_id,
        node_key,
        padding,
    }))
}

fn parse_pong(
    payload: &[u8],
) -> Result<TailscaleDiscoMessage, TailscaleDiscoError> {
    if payload.len()
        < TAILSCALE_DISCO_TRANSACTION_ID_LENGTH
            + TAILSCALE_DISCO_ENDPOINT_LENGTH
    {
        return Err(TailscaleDiscoError::ShortMessage);
    }
    Ok(TailscaleDiscoMessage::Pong(TailscaleDiscoPong {
        transaction_id: payload[..TAILSCALE_DISCO_TRANSACTION_ID_LENGTH]
            .try_into()
            .expect("12-byte transaction ID"),
        source: parse_endpoint(
            &payload[TAILSCALE_DISCO_TRANSACTION_ID_LENGTH..],
        )?,
    }))
}

fn encode_endpoint(output: &mut Vec<u8>, endpoint: SocketAddr) {
    let ip = match endpoint.ip() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    };
    output.extend_from_slice(&ip);
    output.extend_from_slice(&endpoint.port().to_be_bytes());
}

fn parse_endpoint(payload: &[u8]) -> Result<SocketAddr, TailscaleDiscoError> {
    if payload.len() < TAILSCALE_DISCO_ENDPOINT_LENGTH {
        return Err(TailscaleDiscoError::ShortMessage);
    }
    let octets: [u8; 16] = payload[..16].try_into().expect("16-byte IP");
    let ipv6 = Ipv6Addr::from(octets);
    let ip = ipv6
        .to_ipv4_mapped()
        .map(IpAddr::V4)
        .unwrap_or(IpAddr::V6(ipv6));
    Ok(SocketAddr::new(
        ip,
        u16::from_be_bytes(payload[16..18].try_into().expect("two-byte port")),
    ))
}

fn parse_endpoints(
    mut payload: &[u8],
) -> Result<Vec<SocketAddr>, TailscaleDiscoError> {
    let mut endpoints =
        Vec::with_capacity(payload.len() / TAILSCALE_DISCO_ENDPOINT_LENGTH);
    while !payload.is_empty() {
        endpoints.push(parse_endpoint(payload)?);
        payload = &payload[TAILSCALE_DISCO_ENDPOINT_LENGTH..];
    }
    Ok(endpoints)
}

fn encode_bind_common(output: &mut Vec<u8>, common: &TailscaleDiscoBindCommon) {
    output.extend_from_slice(&common.vni.to_be_bytes());
    output.extend_from_slice(&common.generation.to_be_bytes());
    output.extend_from_slice(&common.remote_key);
    output.extend_from_slice(&common.challenge);
}

fn parse_bind_common(
    payload: &[u8],
) -> Result<TailscaleDiscoBindCommon, TailscaleDiscoError> {
    if payload.len() < BIND_COMMON_LENGTH {
        return Err(TailscaleDiscoError::ShortMessage);
    }
    Ok(TailscaleDiscoBindCommon {
        vni: u32::from_be_bytes(
            payload[..4].try_into().expect("four-byte VNI"),
        ),
        generation: u32::from_be_bytes(
            payload[4..8].try_into().expect("four-byte generation"),
        ),
        remote_key: payload[8..40].try_into().expect("32-byte disco key"),
        challenge: payload[40..72].try_into().expect("32-byte challenge"),
    })
}

fn encode_relay_endpoint(
    output: &mut Vec<u8>,
    endpoint: &TailscaleDiscoRelayEndpoint,
) {
    output.extend_from_slice(&endpoint.server_disco_key);
    output.extend_from_slice(&endpoint.client_disco_keys[0]);
    output.extend_from_slice(&endpoint.client_disco_keys[1]);
    output.extend_from_slice(&endpoint.lamport_id.to_be_bytes());
    output.extend_from_slice(&endpoint.vni.to_be_bytes());
    output.extend_from_slice(&endpoint.bind_lifetime_nanoseconds.to_be_bytes());
    output.extend_from_slice(
        &endpoint.steady_state_lifetime_nanoseconds.to_be_bytes(),
    );
    for address in &endpoint.endpoints {
        encode_endpoint(output, *address);
    }
}

fn parse_relay_endpoint(
    payload: &[u8],
) -> Result<TailscaleDiscoRelayEndpoint, TailscaleDiscoError> {
    if payload.len()
        < RELAY_ENDPOINT_FIXED_LENGTH + TAILSCALE_DISCO_ENDPOINT_LENGTH
        || !(payload.len() - RELAY_ENDPOINT_FIXED_LENGTH)
            .is_multiple_of(TAILSCALE_DISCO_ENDPOINT_LENGTH)
    {
        return Err(TailscaleDiscoError::ShortMessage);
    }
    Ok(TailscaleDiscoRelayEndpoint {
        server_disco_key: payload[..32]
            .try_into()
            .expect("32-byte server disco key"),
        client_disco_keys: [
            payload[32..64].try_into().expect("32-byte client key"),
            payload[64..96].try_into().expect("32-byte client key"),
        ],
        lamport_id: u64::from_be_bytes(
            payload[96..104].try_into().expect("eight-byte Lamport ID"),
        ),
        vni: u32::from_be_bytes(
            payload[104..108].try_into().expect("four-byte VNI"),
        ),
        bind_lifetime_nanoseconds: u64::from_be_bytes(
            payload[108..116].try_into().expect("eight-byte lifetime"),
        ),
        steady_state_lifetime_nanoseconds: u64::from_be_bytes(
            payload[116..124].try_into().expect("eight-byte lifetime"),
        ),
        endpoints: parse_endpoints(&payload[RELAY_ENDPOINT_FIXED_LENGTH..])?,
    })
}

fn empty_relay_endpoint() -> TailscaleDiscoRelayEndpoint {
    TailscaleDiscoRelayEndpoint {
        server_disco_key: [0; 32],
        client_disco_keys: [[0; 32]; 2],
        lamport_id: 0,
        vni: 0,
        bind_lifetime_nanoseconds: 0,
        steady_state_lifetime_nanoseconds: 0,
        endpoints: Vec::new(),
    }
}

fn validate_key(
    key: &[u8; TAILSCALE_DISCO_KEY_LENGTH],
) -> Result<(), TailscaleDiscoError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(TailscaleDiscoError::ZeroKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay_endpoint() -> TailscaleDiscoRelayEndpoint {
        TailscaleDiscoRelayEndpoint {
            server_disco_key: [1; 32],
            client_disco_keys: [[2; 32], [3; 32]],
            lamport_id: 0x0102_0304_0506_0708,
            vni: 0x000a_0b0c,
            bind_lifetime_nanoseconds: 30_000_000_000,
            steady_state_lifetime_nanoseconds: 60_000_000_000,
            endpoints: vec![
                "192.0.2.1:1234".parse().unwrap(),
                "[2001:db8::1]:5678".parse().unwrap(),
            ],
        }
    }

    #[test]
    fn ping_pong_and_call_me_maybe_match_wire_layout() {
        let ping = TailscaleDiscoMessage::Ping(TailscaleDiscoPing {
            transaction_id: *b"123456789012",
            node_key: Some([0x11; 32]),
            padding: 3,
        });
        let encoded = encode_tailscale_disco_message(&ping).unwrap();
        assert_eq!(&encoded[..14], b"\x01\x00123456789012");
        assert_eq!(&encoded[14..46], &[0x11; 32]);
        assert_eq!(&encoded[46..], &[0; 3]);
        assert_eq!(
            hex::encode(&encoded),
            "01003132333435363738393031321111111111111111111111111111111111111111111111111111111111111111000000"
        );
        assert_eq!(parse_tailscale_disco_message(&encoded).unwrap(), ping);

        for (message, go_oracle) in [
            (
                TailscaleDiscoMessage::Pong(TailscaleDiscoPong {
                    transaction_id: *b"abcdefghijkl",
                    source: "192.0.2.10:4242".parse().unwrap(),
                }),
                "02006162636465666768696a6b6c00000000000000000000ffffc000020a1092",
            ),
            (
                TailscaleDiscoMessage::CallMeMaybe(TailscaleDiscoCallMeMaybe {
                    endpoints: vec![
                        "192.0.2.20:1000".parse().unwrap(),
                        "[2001:db8::20]:2000".parse().unwrap(),
                    ],
                }),
                "030000000000000000000000ffffc000021403e820010db800000000000000000000002007d0",
            ),
        ] {
            let encoded = encode_tailscale_disco_message(&message).unwrap();
            assert_eq!(hex::encode(&encoded), go_oracle);
            assert_eq!(
                parse_tailscale_disco_message(&encoded).unwrap(),
                message
            );
        }
    }

    #[test]
    fn relay_messages_round_trip_all_current_types() {
        let common = TailscaleDiscoBindCommon {
            vni: 0x00ab_cdef,
            generation: 42,
            remote_key: [4; 32],
            challenge: [5; 32],
        };
        let endpoint = relay_endpoint();
        assert_eq!(
            hex::encode(
                encode_tailscale_disco_message(
                    &TailscaleDiscoMessage::CallMeMaybeVia(endpoint.clone())
                )
                .unwrap()
            ),
            "07000101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030102030405060708000a0b0c00000006fc23ac000000000df847580000000000000000000000ffffc000020104d220010db8000000000000000000000001162e"
        );
        let messages = vec![
            TailscaleDiscoMessage::BindUdpRelayEndpoint(common.clone()),
            TailscaleDiscoMessage::BindUdpRelayEndpointChallenge(
                common.clone(),
            ),
            TailscaleDiscoMessage::BindUdpRelayEndpointAnswer(common),
            TailscaleDiscoMessage::CallMeMaybeVia(endpoint.clone()),
            TailscaleDiscoMessage::AllocateUdpRelayEndpointRequest {
                client_disco_keys: [[6; 32], [7; 32]],
                generation: 43,
            },
            TailscaleDiscoMessage::AllocateUdpRelayEndpointResponse {
                generation: 44,
                endpoint,
            },
        ];
        for message in messages {
            let encoded = encode_tailscale_disco_message(&message).unwrap();
            assert_eq!(
                parse_tailscale_disco_message(&encoded).unwrap(),
                message
            );
        }
    }

    #[test]
    fn encrypted_wrapper_authenticates_sender_and_payload() {
        let sender_private = [9; 32];
        let receiver_private = [10; 32];
        let receiver_public =
            tailscale_disco_public_key(receiver_private).unwrap();
        let message = TailscaleDiscoMessage::Ping(TailscaleDiscoPing {
            transaction_id: *b"tx-id-000001",
            node_key: None,
            padding: 8,
        });
        let mut packet = seal_tailscale_disco_packet_with_nonce(
            sender_private,
            receiver_public,
            [11; 24],
            &message,
        )
        .unwrap();
        assert!(looks_like_tailscale_disco_packet(&packet));
        assert_eq!(
            tailscale_disco_source(&packet),
            Some(tailscale_disco_public_key(sender_private).unwrap())
        );
        let opened =
            open_tailscale_disco_packet(receiver_private, &packet).unwrap();
        assert_eq!(opened.nonce, [11; 24]);
        assert_eq!(opened.message, message);
        let derp_packet = TailscaleDerpPacket {
            peer: [12; 32],
            packet: packet.clone(),
        };
        assert_eq!(
            open_tailscale_derp_disco_packet(receiver_private, &derp_packet)
                .unwrap()
                .unwrap()
                .message,
            message
        );
        assert!(
            open_tailscale_derp_disco_packet(
                receiver_private,
                &TailscaleDerpPacket {
                    peer: [12; 32],
                    packet: vec![1, 2, 3],
                },
            )
            .unwrap()
            .is_none()
        );

        *packet.last_mut().unwrap() ^= 1;
        assert!(matches!(
            open_tailscale_disco_packet(receiver_private, &packet),
            Err(TailscaleDiscoError::BoxAuthentication)
        ));
    }

    #[test]
    fn parser_matches_upstream_lax_version_and_length_rules() {
        assert_eq!(
            parse_tailscale_disco_message(b"\x03\x01garbage").unwrap(),
            TailscaleDiscoMessage::CallMeMaybe(
                TailscaleDiscoCallMeMaybe::default()
            )
        );
        assert!(matches!(
            parse_tailscale_disco_message(b"\xff\x00"),
            Err(TailscaleDiscoError::UnknownMessageType(0xff))
        ));
        assert!(matches!(
            parse_tailscale_disco_message(b"\x01\x00short"),
            Err(TailscaleDiscoError::ShortMessage)
        ));
    }
}
