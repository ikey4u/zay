//! Protocol sniffers ported from sing-box's `common/sniff` package.
//!
//! The functions operate on a replayable byte slice. Callers retain the
//! original bytes and can therefore inspect a stream without consuming data
//! before it is routed.

use aes::{
    Aes128,
    cipher::{Block, BlockCipherEncrypt, KeyInit as _},
};
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead as _, Payload},
};
use hickory_proto::{op::Message, serialize::binary::BinDecodable};
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SniffError {
    #[error("need more data")]
    NeedMoreData,
    #[error("not a valid {0} payload")]
    Invalid(&'static str),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SniffResult {
    pub protocol: String,
    pub domain: String,
    pub client: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSniffer {
    Tls,
    Http,
    Dns,
    Ssh,
    Rdp,
    BitTorrent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketSniffer {
    Quic,
    Dns,
    Stun,
    BitTorrent,
    Utp,
    Dtls,
    Ntp,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QuicSniffState {
    destination_id: Vec<u8>,
    fragments: Vec<QuicCryptoFragment>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PacketSniffState {
    quic: QuicSniffState,
}

impl PacketSniffState {
    pub fn is_pending(&self) -> bool {
        !self.quic.fragments.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QuicCryptoFragment {
    offset: u64,
    payload: Vec<u8>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ClientHelloFingerprint {
    server_name: String,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    elliptic_curves: Vec<u16>,
    versions: Vec<u16>,
    signature_algorithms: Vec<u16>,
}

pub fn sniff_stream(
    data: &[u8],
    sniffers: &[StreamSniffer],
) -> Result<SniffResult, SniffError> {
    let mut needs_more = false;
    for sniffer in sniffers {
        let result = match sniffer {
            StreamSniffer::Tls => tls_client_hello(data),
            StreamSniffer::Http => http_host(data),
            StreamSniffer::Dns => stream_domain_name_query(data),
            StreamSniffer::Ssh => ssh(data),
            StreamSniffer::Rdp => rdp(data),
            StreamSniffer::BitTorrent => bittorrent(data),
        };
        match result {
            Ok(result) => return Ok(result),
            Err(SniffError::NeedMoreData) => needs_more = true,
            Err(SniffError::Invalid(_)) => {}
        }
    }
    if needs_more {
        Err(SniffError::NeedMoreData)
    } else {
        Err(SniffError::Invalid("stream"))
    }
}

pub fn sniff_packet(
    data: &[u8],
    sniffers: &[PacketSniffer],
) -> Result<SniffResult, SniffError> {
    sniff_packet_with_state(data, sniffers, &mut PacketSniffState::default())
}

/// Run packet sniffers while retaining protocol-specific state that spans
/// datagrams. At present QUIC is the only multi-packet sniffer upstream uses.
pub fn sniff_packet_with_state(
    data: &[u8],
    sniffers: &[PacketSniffer],
    state: &mut PacketSniffState,
) -> Result<SniffResult, SniffError> {
    let mut needs_more = false;
    for sniffer in sniffers {
        let result = match sniffer {
            PacketSniffer::Quic => {
                quic_client_hello_with_state(data, &mut state.quic)
            }
            PacketSniffer::Dns => domain_name_query(data),
            PacketSniffer::Stun => stun_message(data),
            PacketSniffer::BitTorrent => udp_tracker(data),
            PacketSniffer::Utp => utp(data),
            PacketSniffer::Dtls => dtls_record(data),
            PacketSniffer::Ntp => ntp(data),
        };
        match result {
            Ok(result) => return Ok(result),
            Err(SniffError::NeedMoreData) => needs_more = true,
            Err(SniffError::Invalid(_)) => {}
        }
    }
    if needs_more {
        Err(SniffError::NeedMoreData)
    } else {
        Err(SniffError::Invalid("packet"))
    }
}

pub fn quic_client_hello(data: &[u8]) -> Result<SniffResult, SniffError> {
    quic_client_hello_with_state(data, &mut QuicSniffState::default())
}

/// Decrypt a QUIC Initial packet and retain incomplete CRYPTO frames across
/// datagrams. QUIC clients may split one TLS ClientHello over several Initial
/// packets, so callers handling a UDP session should reuse `state` until this
/// function succeeds or the sniff timeout expires.
pub fn quic_client_hello_with_state(
    data: &[u8],
    state: &mut QuicSniffState,
) -> Result<SniffResult, SniffError> {
    const VERSION_DRAFT_29: u32 = 0xff00_001d;
    const VERSION_1: u32 = 1;
    const VERSION_2: u32 = 0x6b33_43cf;
    const SALT_OLD: [u8; 20] = [
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1,
        0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
    ];
    const SALT_V1: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6,
        0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    const SALT_V2: [u8; 20] = [
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe,
        0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    ];

    let mut offset = 0;
    let first = *data.first().ok_or(SniffError::Invalid("QUIC"))?;
    offset += 1;
    if first & 0xc0 != 0xc0 {
        return Err(SniffError::Invalid("QUIC"));
    }
    let version = read_u32(data, &mut offset)?;
    if !matches!(version, VERSION_DRAFT_29 | VERSION_1 | VERSION_2) {
        return Err(SniffError::Invalid("QUIC"));
    }
    let packet_type = (first & 0x30) >> 4;
    if (version == VERSION_2 && packet_type != 1)
        || (version != VERSION_2 && packet_type != 0)
    {
        return Err(SniffError::Invalid("QUIC Initial"));
    }
    let destination_id_length = usize::from(read_byte(data, &mut offset)?);
    if !(1..=20).contains(&destination_id_length) {
        return Err(SniffError::Invalid("QUIC connection ID"));
    }
    let destination_id = take(data, &mut offset, destination_id_length)?;
    if state.destination_id.as_slice() != destination_id {
        state.destination_id.clear();
        state.destination_id.extend_from_slice(destination_id);
        state.fragments.clear();
    }
    let source_id_length = usize::from(read_byte(data, &mut offset)?);
    take(data, &mut offset, source_id_length)?;
    let token_length = read_quic_varint(data, &mut offset)?;
    take(
        data,
        &mut offset,
        usize::try_from(token_length)
            .map_err(|_| SniffError::Invalid("QUIC token"))?,
    )?;
    let packet_length =
        usize::try_from(read_quic_varint(data, &mut offset)?)
            .map_err(|_| SniffError::Invalid("QUIC packet length"))?;
    let packet_number_offset = offset;
    let packet_end = packet_number_offset
        .checked_add(packet_length)
        .filter(|end| *end <= data.len())
        .ok_or(SniffError::NeedMoreData)?;
    let sample: [u8; 16] = data
        .get(packet_number_offset + 4..packet_number_offset + 20)
        .ok_or(SniffError::NeedMoreData)?
        .try_into()
        .expect("fixed sample length");

    let (salt, key_label, iv_label, hp_label) = match version {
        VERSION_2 => (&SALT_V2[..], "quicv2 key", "quicv2 iv", "quicv2 hp"),
        VERSION_1 => (&SALT_V1[..], "quic key", "quic iv", "quic hp"),
        _ => (&SALT_OLD[..], "quic key", "quic iv", "quic hp"),
    };
    let initial = Hkdf::<Sha256>::new(Some(salt), destination_id);
    let mut client_secret = [0_u8; 32];
    hkdf_expand_label(&initial, "client in", &mut client_secret)?;
    let client = Hkdf::<Sha256>::from_prk(&client_secret)
        .map_err(|_| SniffError::Invalid("QUIC initial secret"))?;
    let mut hp_key = [0_u8; 16];
    hkdf_expand_label(&client, hp_label, &mut hp_key)?;
    let cipher = Aes128::new_from_slice(&hp_key)
        .map_err(|_| SniffError::Invalid("QUIC header key"))?;
    let mut mask = Block::<Aes128>::from(sample);
    cipher.encrypt_block(&mut mask);

    let mut packet = data[..packet_end].to_vec();
    packet[0] ^= mask[0] & 0x0f;
    let packet_number_length = usize::from((packet[0] & 0x03) + 1);
    if packet_number_length > packet_length {
        return Err(SniffError::Invalid("QUIC packet number"));
    }
    for index in 0..packet_number_length {
        packet[packet_number_offset + index] ^= mask[index + 1];
    }
    let packet_number = packet
        [packet_number_offset..packet_number_offset + packet_number_length]
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
    let header_end = packet_number_offset + packet_number_length;
    let ciphertext = &packet[header_end..packet_end];
    let mut key = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    hkdf_expand_label(&client, key_label, &mut key)?;
    hkdf_expand_label(&client, iv_label, &mut nonce)?;
    for (target, byte) in nonce[4..].iter_mut().zip(packet_number.to_be_bytes())
    {
        *target ^= byte;
    }
    let cipher = Aes128Gcm::new_from_slice(&key)
        .map_err(|_| SniffError::Invalid("QUIC packet key"))?;
    let plaintext = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ciphertext,
                aad: &packet[..header_end],
            },
        )
        .map_err(|_| SniffError::Invalid("QUIC Initial authentication"))?;
    let (fragments, frame_types) = collect_quic_crypto(&plaintext)?;
    state.fragments.extend(fragments);
    state.fragments.sort_by_key(|fragment| fragment.offset);
    state.fragments.dedup_by_key(|fragment| fragment.offset);
    let mut crypto = Vec::new();
    for fragment in &state.fragments {
        if fragment.offset != crypto.len() as u64 {
            break;
        }
        crypto.extend_from_slice(&fragment.payload);
    }
    if crypto.is_empty() {
        return Err(SniffError::NeedMoreData);
    }
    let length = u16::try_from(crypto.len())
        .map_err(|_| SniffError::Invalid("QUIC ClientHello"))?;
    let mut tls_record = Vec::with_capacity(5 + crypto.len());
    tls_record.extend_from_slice(&[22, 3, 3]);
    tls_record.extend_from_slice(&length.to_be_bytes());
    tls_record.extend_from_slice(&crypto);
    let fingerprint = parse_tls_client_hello(&tls_record)?;
    Ok(SniffResult {
        protocol: "quic".into(),
        domain: fingerprint.server_name.clone(),
        client: classify_quic_client(&frame_types, &fingerprint).into(),
    })
}

fn hkdf_expand_label(
    hkdf: &Hkdf<Sha256>,
    label: &str,
    output: &mut [u8],
) -> Result<(), SniffError> {
    let label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + label.len());
    info.extend_from_slice(&(output.len() as u16).to_be_bytes());
    info.push(label.len() as u8);
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    hkdf.expand(&info, output)
        .map_err(|_| SniffError::Invalid("QUIC HKDF label"))
}

fn collect_quic_crypto(
    data: &[u8],
) -> Result<(Vec<QuicCryptoFragment>, Vec<u64>), SniffError> {
    let mut offset = 0;
    let mut fragments = Vec::new();
    let mut frame_types = Vec::new();
    while offset < data.len() {
        let frame_type = read_quic_varint(data, &mut offset)?;
        frame_types.push(frame_type);
        match frame_type {
            0 | 1 => {}
            2 | 3 => {
                read_quic_varint(data, &mut offset)?;
                read_quic_varint(data, &mut offset)?;
                let range_count = read_quic_varint(data, &mut offset)?;
                read_quic_varint(data, &mut offset)?;
                for _ in 0..range_count {
                    read_quic_varint(data, &mut offset)?;
                    read_quic_varint(data, &mut offset)?;
                }
                if frame_type == 3 {
                    read_quic_varint(data, &mut offset)?;
                    read_quic_varint(data, &mut offset)?;
                    read_quic_varint(data, &mut offset)?;
                }
            }
            6 => {
                let crypto_offset = read_quic_varint(data, &mut offset)?;
                let length =
                    usize::try_from(read_quic_varint(data, &mut offset)?)
                        .map_err(|_| {
                            SniffError::Invalid("QUIC CRYPTO frame")
                        })?;
                fragments.push(QuicCryptoFragment {
                    offset: crypto_offset,
                    payload: take(data, &mut offset, length)?.to_vec(),
                });
            }
            0x1c => {
                read_quic_varint(data, &mut offset)?;
                read_quic_varint(data, &mut offset)?;
                let length =
                    usize::try_from(read_quic_varint(data, &mut offset)?)
                        .map_err(|_| SniffError::Invalid("QUIC close frame"))?;
                take(data, &mut offset, length)?;
            }
            _ => return Err(SniffError::Invalid("QUIC Initial frame")),
        }
    }
    Ok((fragments, frame_types))
}

fn classify_quic_client(
    frame_types: &[u64],
    fingerprint: &ClientHelloFingerprint,
) -> &'static str {
    const PADDING: u64 = 0;
    const PING: u64 = 1;
    const CRYPTO: u64 = 6;
    const GREASE_MASK: u16 = 0x0f0f;
    const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
    const X25519: u16 = 0x001d;
    const ECDSA_P256_SHA256: u16 = 0x0403;
    const X25519_KYBER_768_DRAFT_00: u16 = 0x11ec;
    const RENEGOTIATION_INFO: u16 = 0xff01;

    if frame_types.len() == 1 {
        return "firefox";
    }
    if frame_types.first() == Some(&CRYPTO)
        && frame_types[1..].iter().all(|frame| *frame == PADDING)
    {
        let apple_grease = fingerprint.versions.len() == 2
            && fingerprint.versions[0] & GREASE_MASK == 0x0a0a
            && fingerprint.elliptic_curves.len() == 5
            && fingerprint.elliptic_curves[0] & GREASE_MASK == 0x0a0a;
        let minimal_apple = fingerprint.cipher_suites
            == [TLS_AES_256_GCM_SHA384]
            && fingerprint.elliptic_curves == [X25519]
            && fingerprint.signature_algorithms == [ECDSA_P256_SHA256];
        if apple_grease || minimal_apple {
            return "safari";
        }
    }
    if frame_types.last() == Some(&CRYPTO)
        && frame_types[..frame_types.len().saturating_sub(1)]
            .iter()
            .all(|frame| *frame == PADDING)
    {
        return "quic-go";
    }
    if frame_types.iter().filter(|frame| **frame == CRYPTO).count() > 1
        || frame_types.contains(&PING)
    {
        if fingerprint
            .elliptic_curves
            .contains(&X25519_KYBER_768_DRAFT_00)
            || fingerprint.extensions.contains(&RENEGOTIATION_INFO)
        {
            return "quic-go";
        }
        return "chromium";
    }
    "unknown"
}

fn read_quic_varint(
    data: &[u8],
    offset: &mut usize,
) -> Result<u64, SniffError> {
    let first = read_byte(data, offset)?;
    let length = 1_usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for byte in take(data, offset, length - 1)? {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(value)
}

fn read_byte(data: &[u8], offset: &mut usize) -> Result<u8, SniffError> {
    Ok(*take(data, offset, 1)?
        .first()
        .ok_or(SniffError::Invalid("truncated payload"))?)
}

fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32, SniffError> {
    let value = take(data, offset, 4)?;
    Ok(u32::from_be_bytes(value.try_into().expect("fixed length")))
}

pub fn http_host(data: &[u8]) -> Result<SniffResult, SniffError> {
    let Some(header_end) = find_bytes(data, b"\r\n\r\n") else {
        return if data.windows(2).any(|window| window == b"\r\n")
            || is_http_method_prefix(data)
        {
            Err(SniffError::NeedMoreData)
        } else {
            Err(SniffError::Invalid("HTTP"))
        };
    };
    let header = std::str::from_utf8(&data[..header_end])
        .map_err(|_| SniffError::Invalid("HTTP"))?;
    let mut lines = header.split("\r\n");
    let request_line = lines.next().ok_or(SniffError::Invalid("HTTP"))?;
    let mut request = request_line.split_whitespace();
    let method = request.next().ok_or(SniffError::Invalid("HTTP"))?;
    let target = request.next().ok_or(SniffError::Invalid("HTTP"))?;
    let version = request.next().ok_or(SniffError::Invalid("HTTP"))?;
    if request.next().is_some()
        || !method.bytes().all(|value| value.is_ascii_uppercase())
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return Err(SniffError::Invalid("HTTP"));
    }
    let host = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
        .or_else(|| absolute_uri_host(target))
        .unwrap_or("");
    Ok(SniffResult {
        protocol: "http".into(),
        domain: strip_host_port(host).to_owned(),
        client: String::new(),
    })
}

pub fn tls_client_hello(data: &[u8]) -> Result<SniffResult, SniffError> {
    let fingerprint = parse_tls_client_hello(data)?;
    Ok(SniffResult {
        protocol: "tls".into(),
        domain: fingerprint.server_name,
        client: String::new(),
    })
}

fn parse_tls_client_hello(
    data: &[u8],
) -> Result<ClientHelloFingerprint, SniffError> {
    let mut offset = 0;
    let mut handshake = Vec::new();
    let expected_length = loop {
        if data.len().saturating_sub(offset) < 5 {
            return Err(SniffError::NeedMoreData);
        }
        if data[offset] != 22 {
            return Err(SniffError::Invalid("TLS ClientHello"));
        }
        let version = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
        if !(0x0300..=0x0304).contains(&version) {
            return Err(SniffError::Invalid("TLS ClientHello"));
        }
        let length =
            u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        if data.len().saturating_sub(offset + 5) < length {
            return Err(SniffError::NeedMoreData);
        }
        handshake.extend_from_slice(&data[offset + 5..offset + 5 + length]);
        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return Err(SniffError::Invalid("TLS ClientHello"));
            }
            let length = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            if handshake.len() >= 4 + length {
                break length;
            }
        }
        offset += 5 + length;
    };
    let hello = &handshake[4..4 + expected_length];
    parse_client_hello_fingerprint(hello)
}

fn parse_client_hello_fingerprint(
    hello: &[u8],
) -> Result<ClientHelloFingerprint, SniffError> {
    if hello.len() < 2 + 32 + 1 {
        return Err(SniffError::Invalid("TLS ClientHello"));
    }
    let mut fingerprint = ClientHelloFingerprint::default();
    let mut offset = 34;
    let session_length = usize::from(hello[offset]);
    offset += 1;
    take(hello, &mut offset, session_length)?;
    let cipher_length = read_u16(hello, &mut offset)? as usize;
    if !cipher_length.is_multiple_of(2) {
        return Err(SniffError::Invalid("TLS ClientHello"));
    }
    fingerprint.cipher_suites = take(hello, &mut offset, cipher_length)?
        .chunks_exact(2)
        .map(|cipher| u16::from_be_bytes([cipher[0], cipher[1]]))
        .collect();
    let compression_length = usize::from(
        *take(hello, &mut offset, 1)?
            .first()
            .ok_or(SniffError::Invalid("TLS ClientHello"))?,
    );
    take(hello, &mut offset, compression_length)?;
    if offset == hello.len() {
        return Ok(fingerprint);
    }
    let extensions_length = read_u16(hello, &mut offset)? as usize;
    let extensions = take(hello, &mut offset, extensions_length)?;
    let mut extension_offset = 0;
    while extension_offset < extensions.len() {
        let kind = read_u16(extensions, &mut extension_offset)?;
        let length = read_u16(extensions, &mut extension_offset)? as usize;
        let value = take(extensions, &mut extension_offset, length)?;
        fingerprint.extensions.push(kind);
        match kind {
            0 => {
                let mut name_offset = 0;
                let names_length = read_u16(value, &mut name_offset)? as usize;
                let names = take(value, &mut name_offset, names_length)?;
                let mut name_offset = 0;
                while name_offset < names.len() {
                    let name_type = read_byte(names, &mut name_offset)?;
                    let name_length =
                        read_u16(names, &mut name_offset)? as usize;
                    let name = take(names, &mut name_offset, name_length)?;
                    if name_type == 0 {
                        fingerprint.server_name = std::str::from_utf8(name)
                            .map(str::to_owned)
                            .map_err(|_| {
                                SniffError::Invalid("TLS ClientHello")
                            })?;
                        break;
                    }
                }
            }
            10 => {
                fingerprint.elliptic_curves = parse_u16_vector(value, false)?;
            }
            13 => {
                fingerprint.signature_algorithms =
                    parse_u16_vector(value, false)?;
            }
            43 => {
                fingerprint.versions = parse_u16_vector(value, true)?;
            }
            _ => {}
        }
    }
    Ok(fingerprint)
}

fn parse_u16_vector(
    data: &[u8],
    byte_length_prefix: bool,
) -> Result<Vec<u16>, SniffError> {
    let mut offset = 0;
    let length = if byte_length_prefix {
        usize::from(read_byte(data, &mut offset)?)
    } else {
        read_u16(data, &mut offset)? as usize
    };
    if !length.is_multiple_of(2) {
        return Err(SniffError::Invalid("TLS ClientHello"));
    }
    let values = take(data, &mut offset, length)?;
    if offset != data.len() {
        return Err(SniffError::Invalid("TLS ClientHello"));
    }
    Ok(values
        .chunks_exact(2)
        .map(|value| u16::from_be_bytes([value[0], value[1]]))
        .collect())
}

pub fn stream_domain_name_query(
    data: &[u8],
) -> Result<SniffResult, SniffError> {
    if data.len() < 2 {
        return Err(SniffError::NeedMoreData);
    }
    let length = u16::from_be_bytes([data[0], data[1]]) as usize;
    if length < 12 {
        return Err(SniffError::Invalid("DNS"));
    }
    let available = &data[2..];
    if available.len() > 2 && available[2] & 0x80 != 0 {
        return Err(SniffError::Invalid("DNS"));
    }
    if available.len() > 5 && available[4..6] == [0, 0] {
        return Err(SniffError::Invalid("DNS"));
    }
    if available
        .get(6..10)
        .is_some_and(|counts| counts.iter().any(|value| *value != 0))
    {
        return Err(SniffError::Invalid("DNS"));
    }
    if available.len() < length {
        return Err(SniffError::NeedMoreData);
    }
    domain_name_query(&available[..length])
}

pub fn domain_name_query(data: &[u8]) -> Result<SniffResult, SniffError> {
    let message =
        Message::from_bytes(data).map_err(|_| SniffError::Invalid("DNS"))?;
    if message.metadata.message_type == hickory_proto::op::MessageType::Response
        || message.queries.is_empty()
        || !message.answers.is_empty()
        || !message.authorities.is_empty()
    {
        return Err(SniffError::Invalid("DNS"));
    }
    Ok(protocol_only("dns"))
}

pub fn bittorrent(data: &[u8]) -> Result<SniffResult, SniffError> {
    const PREFIX: &[u8] = b"\x13BitTorrent protocol";
    if data.len() < PREFIX.len() {
        return if PREFIX.starts_with(data) {
            Err(SniffError::NeedMoreData)
        } else {
            Err(SniffError::Invalid("BitTorrent"))
        };
    }
    if !data.starts_with(PREFIX) {
        return Err(SniffError::Invalid("BitTorrent"));
    }
    Ok(protocol_only("bittorrent"))
}

pub fn utp(data: &[u8]) -> Result<SniffResult, SniffError> {
    if data.len() < 20 || data[0] & 0x0f != 1 || data[0] >> 4 > 4 {
        return Err(SniffError::Invalid("uTP"));
    }
    let mut extension = data[1];
    let mut offset = 20;
    while extension != 0 {
        if data.len().saturating_sub(offset) < 2 {
            return Err(SniffError::Invalid("uTP"));
        }
        extension = data[offset];
        if extension > 4 {
            return Err(SniffError::Invalid("uTP"));
        }
        let length = usize::from(data[offset + 1]);
        offset += 2;
        if data.len().saturating_sub(offset) < length {
            return Err(SniffError::Invalid("uTP"));
        }
        offset += length;
    }
    Ok(protocol_only("bittorrent"))
}

pub fn udp_tracker(data: &[u8]) -> Result<SniffResult, SniffError> {
    if data.len() < 16
        || u64::from_be_bytes(data[..8].try_into().expect("length checked"))
            != 0x0417_2710_1980
        || u32::from_be_bytes(data[8..12].try_into().expect("length checked"))
            != 0
    {
        return Err(SniffError::Invalid("BitTorrent UDP tracker"));
    }
    Ok(protocol_only("bittorrent"))
}

pub fn stun_message(data: &[u8]) -> Result<SniffResult, SniffError> {
    if data.len() < 20
        || u32::from_be_bytes(data[4..8].try_into().expect("length checked"))
            != 0x2112_a442
    {
        return Err(SniffError::Invalid("STUN"));
    }
    let length =
        u16::from_be_bytes(data[2..4].try_into().expect("length checked"))
            as usize;
    if data.len() < 20 + length {
        return Err(SniffError::Invalid("STUN"));
    }
    Ok(protocol_only("stun"))
}

pub fn dtls_record(data: &[u8]) -> Result<SniffResult, SniffError> {
    if data.len() < 13
        || !matches!(data[0], 20 | 21 | 22 | 23 | 25)
        || data[1] != 0xfe
        || !matches!(data[2], 0xff | 0xfd)
    {
        return Err(SniffError::Invalid("DTLS"));
    }
    Ok(protocol_only("dtls"))
}

pub fn ntp(data: &[u8]) -> Result<SniffResult, SniffError> {
    if data.len() < 48 {
        return Err(SniffError::Invalid("NTP"));
    }
    let version = (data[0] >> 3) & 7;
    let mode = data[0] & 7;
    let root_delay =
        u32::from_be_bytes(data[4..8].try_into().expect("length checked"));
    let root_dispersion =
        u32::from_be_bytes(data[8..12].try_into().expect("length checked"));
    if !matches!(version, 3 | 4)
        || mode != 3
        || root_delay > 16 * 65_536
        || root_dispersion > 16 * 65_536
    {
        return Err(SniffError::Invalid("NTP"));
    }
    Ok(protocol_only("ntp"))
}

pub fn ssh(data: &[u8]) -> Result<SniffResult, SniffError> {
    const PREFIX: &[u8] = b"SSH-2.0-";
    if data.len() < PREFIX.len() {
        return if PREFIX.starts_with(data) {
            Err(SniffError::NeedMoreData)
        } else {
            Err(SniffError::Invalid("SSH"))
        };
    }
    if !data.starts_with(PREFIX) {
        return Err(SniffError::Invalid("SSH"));
    }
    let end = data
        .iter()
        .position(|value| *value == b'\n')
        .ok_or(SniffError::NeedMoreData)?;
    let line = data[..end].strip_suffix(b"\r").unwrap_or(&data[..end]);
    let client = std::str::from_utf8(&line[PREFIX.len()..])
        .map_err(|_| SniffError::Invalid("SSH"))?;
    Ok(SniffResult {
        protocol: "ssh".into(),
        domain: String::new(),
        client: client.to_owned(),
    })
}

pub fn rdp(data: &[u8]) -> Result<SniffResult, SniffError> {
    let field =
        |index: usize| data.get(index).copied().ok_or(SniffError::NeedMoreData);
    if field(0)? != 3 || field(1)? != 0 {
        return Err(SniffError::Invalid("RDP"));
    }
    let tpkt_length = u16::from_be_bytes([field(2)?, field(3)?]);
    if tpkt_length != 19 || field(4)? != 14 || field(5)? != 0xe0 {
        return Err(SniffError::Invalid("RDP"));
    }
    // The fixed Go sniffer skips the COTP destination/source/reference and
    // class bytes, then reads the negotiation request header. It does not
    // require the optional four-byte negotiation payload to have arrived.
    if data.len() < 11 {
        return Err(SniffError::NeedMoreData);
    }
    if field(11)? != 1 {
        return Err(SniffError::Invalid("RDP"));
    }
    field(12)?; // flags are intentionally accepted verbatim upstream.
    if field(13)? != 8 {
        return Err(SniffError::Invalid("RDP"));
    }
    Ok(protocol_only("rdp"))
}

fn read_u16(data: &[u8], offset: &mut usize) -> Result<u16, SniffError> {
    let value = take(data, offset, 2)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn take<'a>(
    data: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], SniffError> {
    let end = offset
        .checked_add(length)
        .ok_or(SniffError::Invalid("TLS ClientHello"))?;
    let value = data
        .get(*offset..end)
        .ok_or(SniffError::Invalid("TLS ClientHello"))?;
    *offset = end;
    Ok(value)
}

fn protocol_only(protocol: &str) -> SniffResult {
    SniffResult {
        protocol: protocol.to_owned(),
        ..Default::default()
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn is_http_method_prefix(data: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"HEAD ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"CONNECT ",
        b"OPTIONS ",
        b"TRACE ",
        b"PATCH ",
    ];
    METHODS
        .iter()
        .any(|method| method.starts_with(data) || data.starts_with(method))
}

fn absolute_uri_host(target: &str) -> Option<&str> {
    let (_, rest) = target.split_once("://")?;
    Some(rest.split('/').next().unwrap_or(rest))
}

fn strip_host_port(host: &str) -> &str {
    if let Some(host) = host.strip_prefix('[')
        && let Some((host, _)) = host.split_once(']')
    {
        return host;
    }
    match host.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => host,
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
    use tokio::net::UdpSocket;

    use super::*;

    #[test]
    fn sniffs_http_host_and_port() {
        let result = http_host(
            b"GET / HTTP/1.1\r\nHost: www.gov.cn:8080\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert_eq!(result.protocol, "http");
        assert_eq!(result.domain, "www.gov.cn");
    }

    #[test]
    fn sniffs_tls_client_hello_sni() {
        let hello = hex::decode(concat!(
            "16030100430100003f0303",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00",
            "0002",
            "1301",
            "01",
            "00",
            "0014",
            "00000010",
            "000e",
            "00",
            "000b",
            "6578616d706c652e636f6d"
        ))
        .unwrap();
        let result = tls_client_hello(&hello).unwrap();
        assert_eq!(result.protocol, "tls");
        assert_eq!(result.domain, "example.com");
    }

    #[test]
    fn classifies_quic_clients_from_frames_and_tls_fingerprint() {
        let mut fingerprint = ClientHelloFingerprint::default();
        assert_eq!(classify_quic_client(&[6], &fingerprint), "firefox");

        fingerprint.versions = vec![0x1a1a, 0x0304];
        fingerprint.elliptic_curves =
            vec![0x2a2a, 0x001d, 0x0017, 0x0018, 0x0019];
        assert_eq!(classify_quic_client(&[6, 0], &fingerprint), "safari");

        fingerprint = ClientHelloFingerprint {
            cipher_suites: vec![0x1302],
            elliptic_curves: vec![0x001d],
            signature_algorithms: vec![0x0403],
            ..Default::default()
        };
        assert_eq!(classify_quic_client(&[6, 0], &fingerprint), "safari");

        fingerprint = ClientHelloFingerprint::default();
        assert_eq!(classify_quic_client(&[0, 0, 6], &fingerprint), "quic-go");
        assert_eq!(classify_quic_client(&[6, 1, 6], &fingerprint), "chromium");

        fingerprint.elliptic_curves.push(0x11ec);
        assert_eq!(classify_quic_client(&[6, 1], &fingerprint), "quic-go");
        fingerprint.elliptic_curves.clear();
        fingerprint.extensions.push(0xff01);
        assert_eq!(classify_quic_client(&[6, 6], &fingerprint), "quic-go");

        assert_eq!(
            classify_quic_client(&[6, 2], &ClientHelloFingerprint::default()),
            "unknown"
        );
    }

    #[test]
    fn parses_quic_client_fingerprint_fields() {
        let extensions = hex::decode(concat!(
            "00000010000e00000b6578616d706c652e636f6d",
            "000a0006000411ec001d",
            "000d000400020403",
            "002b0005041a1a0304",
            "ff01000100"
        ))
        .unwrap();
        let mut hello = hex::decode(concat!(
            "0303",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00",
            "00021302",
            "0100"
        ))
        .unwrap();
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        let mut handshake = vec![1];
        handshake.extend_from_slice(&[
            ((hello.len() >> 16) & 0xff) as u8,
            ((hello.len() >> 8) & 0xff) as u8,
            (hello.len() & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&hello);
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let fingerprint = parse_tls_client_hello(&record).unwrap();
        assert_eq!(fingerprint.server_name, "example.com");
        assert_eq!(fingerprint.cipher_suites, [0x1302]);
        assert_eq!(fingerprint.elliptic_curves, [0x11ec, 0x001d]);
        assert_eq!(fingerprint.signature_algorithms, [0x0403]);
        assert_eq!(fingerprint.versions, [0x1a1a, 0x0304]);
        assert!(fingerprint.extensions.contains(&0xff01));
    }

    #[test]
    fn classifies_pinned_go_quic_capture_fixtures() {
        const CASES: &[(&str, &str)] = &[
            (
                include_str!("testdata/quic_uquic_chrome115.hex"),
                "chromium",
            ),
            (include_str!("testdata/quic_firefox.hex"), "firefox"),
            (include_str!("testdata/quic_safari.hex"), "safari"),
        ];
        for (packet, expected_client) in CASES {
            let packet = hex::decode(packet.trim()).unwrap();
            let result = quic_client_hello(&packet).unwrap();
            assert_eq!(result.protocol, "quic");
            assert_eq!(result.domain, "www.google.com");
            assert_eq!(result.client, *expected_client);
        }
    }

    #[test]
    fn sniffs_dns_stream_and_packet() {
        let query = hex::decode(
            "740701000001000000000000012a06676f6f676c6503636f6d0000010001",
        )
        .unwrap();
        assert_eq!(domain_name_query(&query).unwrap().protocol, "dns");
        let mut stream = vec![0, query.len() as u8];
        stream.extend_from_slice(&query);
        assert_eq!(stream_domain_name_query(&stream).unwrap().protocol, "dns");
        assert_eq!(
            stream_domain_name_query(&stream[..10]),
            Err(SniffError::NeedMoreData)
        );
    }

    #[test]
    fn sniffs_bittorrent_and_udp_tracker() {
        assert_eq!(
            bittorrent(b"\x13BitTorrent protocolpayload")
                .unwrap()
                .protocol,
            "bittorrent"
        );
        assert_eq!(
            bittorrent(b"\x13BitTorrent"),
            Err(SniffError::NeedMoreData)
        );
        let tracker = hex::decode("00000417271019800000000078e90560").unwrap();
        assert_eq!(udp_tracker(&tracker).unwrap().protocol, "bittorrent");
    }

    #[test]
    fn sniffs_stun_dtls_ntp_and_utp_packets() {
        let stun =
            hex::decode("000100002112a44224b1a025d0c180c484341306").unwrap();
        assert_eq!(stun_message(&stun).unwrap().protocol, "stun");
        let dtls =
            hex::decode("16fefd0000000000000000007e010000720000000000000072")
                .unwrap();
        assert_eq!(dtls_record(&dtls).unwrap().protocol, "dtls");
        let mut ntp_packet = [0_u8; 48];
        ntp_packet[0] = (4 << 3) | 3;
        assert_eq!(ntp(&ntp_packet).unwrap().protocol, "ntp");
        let mut utp_packet = [0_u8; 20];
        utp_packet[0] = 1;
        assert_eq!(utp(&utp_packet).unwrap().protocol, "bittorrent");
    }

    #[test]
    fn sniffs_ssh_and_rdp_streams() {
        let ssh_result = ssh(b"SSH-2.0-dropbear\r\nrest").unwrap();
        assert_eq!(ssh_result.protocol, "ssh");
        assert_eq!(ssh_result.client, "dropbear");
        assert_eq!(ssh(b"SSH-2.0"), Err(SniffError::NeedMoreData));
        let rdp_packet = hex::decode(
            "030000130ee00000000000010008000b000000010008000b000000",
        )
        .unwrap();
        assert_eq!(rdp(&rdp_packet).unwrap().protocol, "rdp");
    }

    #[test]
    fn rdp_matches_incremental_go_reader_boundaries() {
        let minimum = hex::decode("030000130ee00000000000010008").unwrap();
        assert_eq!(minimum.len(), 14);
        assert_eq!(rdp(&minimum).unwrap().protocol, "rdp");
        assert_eq!(rdp(&minimum[..13]), Err(SniffError::NeedMoreData));
        assert_eq!(rdp(&[2]), Err(SniffError::Invalid("RDP")));
    }

    #[tokio::test]
    async fn decrypts_quic_v1_initial_and_extracts_sni() {
        let capture = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tls = crate::common::tls::build_client_config(
            "quic.example",
            &crate::option::OutboundTlsOptions {
                enabled: true,
                insecure: true,
                curve_preferences: crate::option::Listable(vec![
                    crate::option::CurvePreference::X25519,
                ]),
                ..Default::default()
            },
            &["h3"],
        )
        .unwrap();
        let crypto = QuicClientConfig::try_from(tls.config).unwrap();
        let mut endpoint =
            Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));
        let connecting = endpoint
            .connect(capture.local_addr().unwrap(), "quic.example")
            .unwrap();
        let attempt = tokio::spawn(async move {
            let _ = connecting.await;
        });
        let mut packet = vec![0_u8; 65_535];
        let size = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            capture.recv(&mut packet),
        )
        .await
        .unwrap()
        .unwrap();
        let result = quic_client_hello(&packet[..size]).unwrap();
        assert_eq!(result.protocol, "quic");
        assert_eq!(result.domain, "quic.example");
        endpoint.close(0_u32.into(), b"");
        attempt.abort();
    }

    #[tokio::test]
    async fn reassembles_quic_client_hello_across_initial_datagrams() {
        let capture = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut tls = crate::common::tls::build_client_config(
            "fragmented-quic.example",
            &crate::option::OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        Arc::make_mut(&mut tls.config).alpn_protocols = (0..96)
            .map(|index| {
                format!("h3-test-{index:03}-{}", "x".repeat(32)).into_bytes()
            })
            .collect();
        let crypto = QuicClientConfig::try_from(tls.config).unwrap();
        let mut endpoint =
            Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));
        let connecting = endpoint
            .connect(capture.local_addr().unwrap(), "fragmented-quic.example")
            .unwrap();
        let attempt = tokio::spawn(async move {
            let _ = connecting.await;
        });
        let mut packet = vec![0_u8; 65_535];
        let mut state = PacketSniffState::default();
        let mut needed_more = false;
        let result = loop {
            let size = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                capture.recv(&mut packet),
            )
            .await
            .unwrap()
            .unwrap();
            match sniff_packet_with_state(
                &packet[..size],
                &[PacketSniffer::Quic],
                &mut state,
            ) {
                Ok(result) => break result,
                Err(SniffError::NeedMoreData) => needed_more = true,
                Err(error) => panic!("unexpected QUIC sniff error: {error}"),
            }
        };
        assert!(needed_more, "ClientHello unexpectedly fit one datagram");
        assert_eq!(result.protocol, "quic");
        assert_eq!(result.domain, "fragmented-quic.example");
        endpoint.close(0_u32.into(), b"");
        attempt.abort();
    }
}
