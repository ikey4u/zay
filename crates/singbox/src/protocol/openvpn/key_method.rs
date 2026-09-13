use hmac13::{Hmac, KeyInit, Mac};
use md5::Md5;
use sha1_11::Sha1;

use super::{
    AllowCompressionPolicy, CompressionSettings, SessionId, tls_cipher_key_bits,
};

pub const TLS_KEY_METHOD_2: u8 = 2;
pub const TLS_IV_PROTO_DATA_V2: u32 = 1 << 1;
pub const TLS_IV_PROTO_REQUEST_PUSH: u32 = 1 << 2;
pub const TLS_IV_PROTO_TLS_KEY_EXPORT: u32 = 1 << 3;
pub const TLS_IV_PROTO_AUTH_PENDING_KW: u32 = 1 << 4;
pub const TLS_IV_PROTO_NCP_P2P: u32 = 1 << 5;
pub const TLS_IV_PROTO_CC_EXIT_NOTIFY: u32 = 1 << 7;
pub const TLS_IV_PROTO_AUTH_FAIL_TEMP: u32 = 1 << 8;

const TLS_PRF_MASTER_SECRET_LABEL: &str = "OpenVPN master secret";
const TLS_PRF_KEY_EXPANSION_LABEL: &str = "OpenVPN key expansion";
const TLS_PRF_MASTER_SECRET_LENGTH: usize = 48;
pub const TLS_PRF_KEY_MATERIAL_LENGTH: usize = 256;
pub const TLS_ADVERTISED_VERSION: &str = "2.6.14";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsKeySource {
    pub pre_master: Vec<u8>,
    pub random1: Vec<u8>,
    pub random2: Vec<u8>,
}

impl TlsKeySource {
    pub fn generate(is_client: bool) -> Result<Self, getrandom::Error> {
        let mut source = Self {
            pre_master: if is_client { vec![0; 48] } else { Vec::new() },
            random1: vec![0; 32],
            random2: vec![0; 32],
        };
        if is_client {
            getrandom::fill(&mut source.pre_master)?;
        }
        getrandom::fill(&mut source.random1)?;
        getrandom::fill(&mut source.random2)?;
        Ok(source)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsKeyMethodMessage {
    pub options_string: String,
    pub username: String,
    pub password: String,
    pub peer_info: String,
    pub key_source: TlsKeySource,
}

impl TlsKeyMethodMessage {
    /// Encode a key-method 2 plaintext. `server_message` omits the 48-byte
    /// pre-master secret, as required by the OpenVPN wire format.
    pub fn encode(
        &self,
        server_message: bool,
    ) -> Result<Vec<u8>, KeyMethodError> {
        let mut output = Vec::new();
        output.extend_from_slice(&0_u32.to_be_bytes());
        output.push(TLS_KEY_METHOD_2);
        if !server_message {
            require_length(
                "client pre-master",
                &self.key_source.pre_master,
                48,
            )?;
            output.extend_from_slice(&self.key_source.pre_master);
        }
        require_length("random1", &self.key_source.random1, 32)?;
        require_length("random2", &self.key_source.random2, 32)?;
        output.extend_from_slice(&self.key_source.random1);
        output.extend_from_slice(&self.key_source.random2);
        write_string(&mut output, &self.options_string)?;
        write_string(&mut output, &self.username)?;
        write_string(&mut output, &self.password)?;
        write_string(&mut output, &self.peer_info)?;
        Ok(output)
    }

    pub fn parse(
        mut input: &[u8],
        server_message: bool,
    ) -> Result<Self, KeyMethodError> {
        let _reserved = take(&mut input, 4)?;
        let method = take(&mut input, 1)?[0];
        if method & 0x0f != TLS_KEY_METHOD_2 {
            return Err(KeyMethodError::UnsupportedMethod(method));
        }
        let pre_master = if server_message {
            Vec::new()
        } else {
            take(&mut input, 48)?.to_vec()
        };
        let random1 = take(&mut input, 32)?.to_vec();
        let random2 = take(&mut input, 32)?.to_vec();
        Ok(Self {
            options_string: read_string(&mut input)?,
            username: read_string(&mut input)?,
            password: read_string(&mut input)?,
            peer_info: read_string(&mut input)?,
            key_source: TlsKeySource {
                pre_master,
                random1,
                random2,
            },
        })
    }
}

pub fn peer_info_iv_proto(peer_info: &str) -> Option<u32> {
    peer_info.lines().find_map(|line| {
        line.trim_end_matches('\r')
            .strip_prefix("IV_PROTO=")?
            .parse()
            .ok()
    })
}

pub fn peer_supports_iv_proto_flag(peer_info: &str, flag: u32) -> bool {
    peer_info_iv_proto(peer_info).is_some_and(|value| value & flag != 0)
}

pub fn peer_info_mtu(peer_info: &str) -> Option<u32> {
    peer_info.lines().find_map(|line| {
        let value: u32 = line
            .trim_end_matches('\r')
            .strip_prefix("IV_MTU=")?
            .parse()
            .ok()?;
        (value != 0).then_some(value)
    })
}

pub fn normalize_tls_control_message(payload: &[u8]) -> String {
    let end = payload
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(payload.len());
    String::from_utf8_lossy(&payload[..end]).trim().to_owned()
}

pub fn advertised_data_ciphers(configured: &[String]) -> Vec<String> {
    if configured.is_empty() {
        vec![
            "AES-256-GCM".into(),
            "AES-128-GCM".into(),
            "CHACHA20-POLY1305".into(),
        ]
    } else {
        configured.to_vec()
    }
}

pub fn supports_ncp_v2(ciphers: &[String]) -> bool {
    ciphers.iter().any(|cipher| cipher == "AES-128-GCM")
        && ciphers.iter().any(|cipher| cipher == "AES-256-GCM")
}

pub fn validate_server_pushed_cipher(
    configured: &[String],
    fallback: &str,
    pushed: &str,
) -> Result<Option<String>, KeyMethodError> {
    let pushed = pushed.trim();
    if pushed.is_empty() {
        return Ok(None);
    }
    if !fallback.is_empty() && fallback.eq_ignore_ascii_case(pushed) {
        return Ok(Some(fallback.to_owned()));
    }
    for cipher in advertised_data_ciphers(configured) {
        if cipher.eq_ignore_ascii_case(pushed) {
            return Ok(Some(cipher));
        }
    }
    Err(KeyMethodError::NegotiatedCipherNotAllowed(
        pushed.to_owned(),
    ))
}

pub fn tls_protocol_name(protocol: &str, is_client: bool) -> &'static str {
    match protocol {
        "udp" | "udp4" => "UDPv4",
        "udp6" => "UDPv6",
        "tcp" | "tcp4" if is_client => "TCPv4_CLIENT",
        "tcp" | "tcp4" => "TCPv4_SERVER",
        "tcp6" if is_client => "TCPv6_CLIENT",
        "tcp6" => "TCPv6_SERVER",
        _ => "UDPv4",
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_tls_options_string(
    protocol: &str,
    is_client: bool,
    tls_auth_enabled: bool,
    compression: CompressionSettings,
    cipher_name: &str,
    auth_name: &str,
    tun_mtu: u32,
) -> String {
    let tun_mtu = if tun_mtu == 0 { 1500 } else { tun_mtu };
    let cipher = if cipher_name.is_empty() {
        "AES-256-GCM"
    } else {
        cipher_name
    };
    let auth = if auth_name.is_empty() {
        "SHA1"
    } else {
        auth_name
    };
    let mut options = format!(
        "V4,dev-type tun,link-mtu {},tun-mtu {tun_mtu},proto {}",
        tun_mtu + 50,
        tls_protocol_name(protocol, is_client)
    );
    if compression.framing_enabled() {
        options.push_str(",comp-lzo");
    }
    options.push_str(",cipher ");
    options.push_str(cipher);
    options.push_str(",auth ");
    options.push_str(auth);
    if let Ok(bits) = tls_cipher_key_bits(cipher) {
        options.push_str(",keysize ");
        options.push_str(&bits.to_string());
    }
    if tls_auth_enabled {
        options.push_str(",tls-auth");
    }
    options.push_str(",key-method 2,");
    options.push_str(if is_client {
        "tls-client"
    } else {
        "tls-server"
    });
    options
}

pub fn advertised_platform(operating_system: &str) -> &'static str {
    match operating_system.trim().to_ascii_lowercase().as_str() {
        "linux" | "android" => "linux",
        "darwin" | "ios" => "mac",
        "windows" => "win",
        "freebsd" => "freebsd",
        "netbsd" => "netbsd",
        "openbsd" => "openbsd",
        "solaris" => "solaris",
        _ => "linux",
    }
}

pub fn build_tls_client_peer_info(
    data_ciphers: &[String],
    request_push: bool,
    tun_mtu: u32,
    allow_compression: AllowCompressionPolicy,
    operating_system: &str,
) -> String {
    let data_ciphers = advertised_data_ciphers(data_ciphers);
    let mut iv_proto = TLS_IV_PROTO_DATA_V2
        | TLS_IV_PROTO_TLS_KEY_EXPORT
        | TLS_IV_PROTO_CC_EXIT_NOTIFY;
    if request_push {
        iv_proto |= TLS_IV_PROTO_REQUEST_PUSH
            | TLS_IV_PROTO_AUTH_PENDING_KW
            | TLS_IV_PROTO_AUTH_FAIL_TEMP;
    } else {
        iv_proto |= TLS_IV_PROTO_NCP_P2P;
    }
    let mut info = format!(
        "IV_VER={TLS_ADVERTISED_VERSION}\nIV_PLAT={}\n",
        advertised_platform(operating_system)
    );
    if supports_ncp_v2(&data_ciphers) {
        info.push_str("IV_NCP=2\n");
    }
    info.push_str("IV_CIPHERS=");
    info.push_str(&data_ciphers.join(":"));
    info.push_str("\nIV_PROTO=");
    info.push_str(&iv_proto.to_string());
    info.push('\n');
    if request_push {
        info.push_str("IV_SSO=webauth,openurl,crtext\nIV_MTU=");
        info.push_str(&(if tun_mtu == 0 { 1500 } else { tun_mtu }).to_string());
        info.push('\n');
    }
    info.push_str("IV_LZ4=1\nIV_LZ4v2=1\n");
    if allow_compression != AllowCompressionPolicy::StubOnly {
        info.push_str("IV_LZO=1\n");
    } else {
        info.push_str("IV_LZO_STUB=1\n");
    }
    info.push_str("IV_COMP_STUB=1\nIV_COMP_STUBv2=1\nIV_TCPNL=1\n");
    info
}

pub fn build_tls_server_peer_info(data_ciphers: &[String]) -> String {
    let data_ciphers = advertised_data_ciphers(data_ciphers);
    let iv_proto = TLS_IV_PROTO_DATA_V2
        | TLS_IV_PROTO_TLS_KEY_EXPORT
        | TLS_IV_PROTO_CC_EXIT_NOTIFY;
    let mut info = format!("IV_PROTO={iv_proto}\n");
    if supports_ncp_v2(&data_ciphers) {
        info.push_str("IV_NCP=2\n");
    }
    if !data_ciphers.is_empty() {
        info.push_str("IV_CIPHERS=");
        info.push_str(&data_ciphers.join(":"));
        info.push('\n');
    }
    info
}

/// OpenVPN's TLS 1.0-compatible PRF (MD5 P_hash XOR SHA-1 P_hash).
pub fn openvpn_tls1_prf(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let half = secret.len() / 2;
    let split = half + (secret.len() & 1);
    let mut md5 = p_hash_md5(&secret[..split], seed, length);
    let sha1 = p_hash_sha1(&secret[half..half + split], seed, length);
    for (left, right) in md5.iter_mut().zip(sha1) {
        *left ^= right;
    }
    md5
}

pub fn derive_tls_key_material_prf(
    client_pre_master: &[u8],
    client_random1: &[u8],
    server_random1: &[u8],
    client_random2: &[u8],
    server_random2: &[u8],
    client_session_id: SessionId,
    server_session_id: SessionId,
) -> Vec<u8> {
    let master_seed = concat(&[
        TLS_PRF_MASTER_SECRET_LABEL.as_bytes(),
        client_random1,
        server_random1,
    ]);
    let mut master = openvpn_tls1_prf(
        client_pre_master,
        &master_seed,
        TLS_PRF_MASTER_SECRET_LENGTH,
    );
    let expansion_seed = concat(&[
        TLS_PRF_KEY_EXPANSION_LABEL.as_bytes(),
        client_random2,
        server_random2,
        &client_session_id,
        &server_session_id,
    ]);
    let material =
        openvpn_tls1_prf(&master, &expansion_seed, TLS_PRF_KEY_MATERIAL_LENGTH);
    master.fill(0);
    material
}

fn p_hash_md5(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    p_hash::<Md5>(secret, seed, length)
}

fn p_hash_sha1(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    p_hash::<Sha1>(secret, seed, length)
}

fn p_hash<D>(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8>
where
    D: hmac13::digest::block_api::EagerHash,
{
    let mut a_mac = <Hmac<D> as KeyInit>::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    a_mac.update(seed);
    let mut a = a_mac.finalize().into_bytes().to_vec();
    let mut output = Vec::with_capacity(length);
    while output.len() < length {
        let mut output_mac = <Hmac<D> as KeyInit>::new_from_slice(secret)
            .expect("HMAC accepts any key length");
        output_mac.update(&a);
        output_mac.update(seed);
        output.extend_from_slice(&output_mac.finalize().into_bytes());
        let mut next = <Hmac<D> as KeyInit>::new_from_slice(secret)
            .expect("HMAC accepts any key length");
        next.update(&a);
        a = next.finalize().into_bytes().to_vec();
    }
    output.truncate(length);
    output
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut output =
        Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in parts {
        output.extend_from_slice(part);
    }
    output
}

fn require_length(
    name: &'static str,
    value: &[u8],
    expected: usize,
) -> Result<(), KeyMethodError> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(KeyMethodError::InvalidLength {
            name,
            expected,
            actual: value.len(),
        })
    }
}

fn write_string(
    output: &mut Vec<u8>,
    value: &str,
) -> Result<(), KeyMethodError> {
    let length = value
        .len()
        .checked_add(1)
        .ok_or(KeyMethodError::StringTooLong)?;
    let length =
        u16::try_from(length).map_err(|_| KeyMethodError::StringTooLong)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    output.push(0);
    Ok(())
}

fn read_string(input: &mut &[u8]) -> Result<String, KeyMethodError> {
    let length =
        u16::from_be_bytes(take(input, 2)?.try_into().unwrap()) as usize;
    if length == 0 {
        return Ok(String::new());
    }
    let mut value = take(input, length)?;
    if value.last() == Some(&0) {
        value = &value[..value.len() - 1];
    }
    String::from_utf8(value.to_vec()).map_err(|_| KeyMethodError::InvalidUtf8)
}

fn take<'a>(
    input: &mut &'a [u8],
    length: usize,
) -> Result<&'a [u8], KeyMethodError> {
    if input.len() < length {
        return Err(KeyMethodError::TooShort);
    }
    let (value, remaining) = input.split_at(length);
    *input = remaining;
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyMethodError {
    #[error("OpenVPN key-method payload is too short")]
    TooShort,
    #[error("unsupported OpenVPN key-method byte {0:#x}")]
    UnsupportedMethod(u8),
    #[error("{name} must be {expected} bytes, got {actual}")]
    InvalidLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("OpenVPN length-prefixed string is too long")]
    StringTooLong,
    #[error("OpenVPN key-method string is not UTF-8")]
    InvalidUtf8,
    #[error("negotiated cipher is not allowed: {0}")]
    NegotiatedCipherNotAllowed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_method_client_and_server_messages_round_trip() {
        for server in [false, true] {
            let message = TlsKeyMethodMessage {
                options_string: "V4,dev-type tun".into(),
                username: "alice".into(),
                password: "secret".into(),
                peer_info: "IV_PROTO=142\nIV_MTU=1500\n".into(),
                key_source: TlsKeySource {
                    pre_master: if server { Vec::new() } else { vec![1; 48] },
                    random1: vec![2; 32],
                    random2: vec![3; 32],
                },
            };
            let encoded = message.encode(server).unwrap();
            assert_eq!(
                TlsKeyMethodMessage::parse(&encoded, server).unwrap(),
                message
            );
        }
    }

    #[test]
    fn parses_peer_capabilities_and_cipher_negotiation() {
        let info = "IV_PROTO=142\r\nIV_MTU=1500\n";
        assert_eq!(peer_info_iv_proto(info), Some(142));
        assert_eq!(peer_info_mtu(info), Some(1500));
        assert!(peer_supports_iv_proto_flag(info, TLS_IV_PROTO_DATA_V2));
        assert_eq!(
            validate_server_pushed_cipher(&[], "", "aes-128-gcm").unwrap(),
            Some("AES-128-GCM".into())
        );
        assert!(validate_server_pushed_cipher(&[], "", "BF-CBC").is_err());
    }

    #[test]
    fn builds_exact_options_and_peer_info_capabilities() {
        let options = build_tls_options_string(
            "tcp6",
            true,
            true,
            CompressionSettings {
                algorithm: super::super::CompressionAlgorithm::StubV2,
                ..CompressionSettings::default()
            },
            "AES-128-GCM",
            "SHA256",
            1400,
        );
        assert_eq!(
            options,
            "V4,dev-type tun,link-mtu 1450,tun-mtu 1400,proto TCPv6_CLIENT,comp-lzo,cipher AES-128-GCM,auth SHA256,keysize 128,tls-auth,key-method 2,tls-client"
        );
        let peer = build_tls_client_peer_info(
            &[],
            true,
            0,
            AllowCompressionPolicy::StubOnly,
            "darwin",
        );
        assert!(peer.starts_with("IV_VER=2.6.14\nIV_PLAT=mac\nIV_NCP=2\n"));
        assert!(peer.contains("IV_PROTO=414\n"));
        assert!(peer.contains("IV_MTU=1500\n"));
        assert!(peer.contains("IV_LZO_STUB=1\n"));
        assert_eq!(
            build_tls_server_peer_info(&["AES-256-GCM".into()]),
            "IV_PROTO=138\nIV_CIPHERS=AES-256-GCM\n"
        );
    }

    #[test]
    fn tls_prf_is_deterministic_and_sensitive_to_session_ids() {
        let first = derive_tls_key_material_prf(
            &[1; 48], &[2; 32], &[3; 32], &[4; 32], &[5; 32], [6; 8], [7; 8],
        );
        let second = derive_tls_key_material_prf(
            &[1; 48], &[2; 32], &[3; 32], &[4; 32], &[5; 32], [6; 8], [8; 8],
        );
        assert_eq!(first.len(), TLS_PRF_KEY_MATERIAL_LENGTH);
        assert_ne!(first, second);
        assert_eq!(
            hex::encode(openvpn_tls1_prf(b"secret", b"seed", 16)),
            "656f31cb0403d651e2e871f82004abba"
        );
    }
}
