use super::advertised_data_ciphers;

pub const SERVER_PUSH_BUNDLE_SIZE: usize = 1024;
pub const SERVER_PUSH_BUNDLE_OVERHEAD: usize = 84;
pub const SERVER_PUSH_SAFE_CAPACITY: usize =
    SERVER_PUSH_BUNDLE_SIZE - SERVER_PUSH_BUNDLE_OVERHEAD;

pub fn extract_remote_cipher_name(options_string: &str) -> Option<String> {
    options_string.split(',').find_map(|token| {
        let value = token.trim().strip_prefix("cipher ")?.trim();
        Some(
            if value == "[null-cipher]" {
                "none"
            } else {
                value
            }
            .to_owned(),
        )
    })
}

pub fn peer_info_cipher_list(peer_info: &str) -> (Vec<String>, bool) {
    for line in peer_info.split('\n') {
        if let Some(value) = line.strip_prefix("IV_CIPHERS=") {
            return (
                value
                    .split(':')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .collect(),
                true,
            );
        }
    }
    if peer_info_ncp_version(peer_info) >= 2 {
        return (vec!["AES-256-GCM".into(), "AES-128-GCM".into()], true);
    }
    (Vec::new(), false)
}

pub fn peer_info_ncp_version(peer_info: &str) -> i32 {
    peer_info
        .lines()
        .find_map(|line| {
            line.trim_end_matches('\r')
                .strip_prefix("IV_NCP=")?
                .parse()
                .ok()
        })
        .unwrap_or(0)
}

pub fn select_pulled_cipher(
    configured: &[String],
    fallback: &str,
    remote_cipher: &str,
) -> Result<String, CipherNegotiationError> {
    let advertised = advertised_data_ciphers(configured);
    let remote = remote_cipher.trim();
    if !remote.is_empty() {
        return advertised
            .into_iter()
            .find(|candidate| candidate.eq_ignore_ascii_case(remote))
            .ok_or_else(|| CipherNegotiationError::NoSharedCipher {
                local: advertised_data_ciphers(configured),
                remote: vec![remote.into()],
            });
    }
    if !fallback.is_empty() {
        return Ok(fallback.into());
    }
    Err(CipherNegotiationError::MissingPeerCipher)
}

pub fn select_p2p_cipher(
    configured: &[String],
    fallback: &str,
    peer_info: &str,
) -> Result<String, CipherNegotiationError> {
    let local = advertised_data_ciphers(configured);
    let (peer, _) = peer_info_cipher_list(peer_info);
    for peer_cipher in &peer {
        if let Some(cipher) = local
            .iter()
            .find(|cipher| cipher.eq_ignore_ascii_case(peer_cipher))
        {
            return Ok(cipher.clone());
        }
    }
    if !fallback.is_empty() {
        return Ok(fallback.into());
    }
    Err(CipherNegotiationError::NoSharedCipher {
        local,
        remote: peer,
    })
}

pub fn select_server_cipher(
    configured: &[String],
    fallback: &str,
    peer_info: &str,
    options_string: &str,
) -> Result<String, CipherNegotiationError> {
    let local = advertised_data_ciphers(configured);
    let (peer, peer_list_known) = peer_info_cipher_list(peer_info);
    let remote_options_cipher = (!peer_list_known)
        .then(|| extract_remote_cipher_name(options_string))
        .flatten();
    for local_cipher in &local {
        if peer
            .iter()
            .any(|cipher| cipher.eq_ignore_ascii_case(local_cipher))
            || remote_options_cipher
                .as_ref()
                .is_some_and(|cipher| cipher.eq_ignore_ascii_case(local_cipher))
        {
            return Ok(local_cipher.clone());
        }
    }
    if !peer_list_known
        && remote_options_cipher.is_none()
        && !fallback.is_empty()
    {
        return Ok(fallback.into());
    }
    Err(CipherNegotiationError::NoSharedCipher {
        local,
        remote: peer,
    })
}

pub fn tls_cipher_key_bits(
    cipher: &str,
) -> Result<u16, CipherNegotiationError> {
    let bits = match cipher {
        "AES-128-GCM" | "AES-128-CBC" | "AES-128-CFB" | "AES-128-OFB"
        | "ARIA-128-CBC" | "ARIA-128-CFB" | "ARIA-128-OFB"
        | "CAMELLIA-128-CBC" | "CAMELLIA-128-CFB" | "CAMELLIA-128-OFB"
        | "SEED-CBC" | "SEED-CFB" | "SEED-OFB" | "SM4-CBC" | "SM4-CFB"
        | "SM4-OFB" | "BF-CBC" | "BF-CFB" | "BF-OFB" | "CAST5-CBC"
        | "CAST5-CFB" | "CAST5-OFB" | "DES-EDE-CBC" | "DES-EDE-CFB"
        | "DES-EDE-OFB" => 128,
        "AES-192-GCM" | "AES-192-CBC" | "AES-192-CFB" | "AES-192-OFB"
        | "ARIA-192-CBC" | "ARIA-192-CFB" | "ARIA-192-OFB"
        | "CAMELLIA-192-CBC" | "CAMELLIA-192-CFB" | "CAMELLIA-192-OFB"
        | "DES-EDE3-CBC" | "DES-EDE3-CFB" | "DES-EDE3-OFB" => 192,
        "AES-256-GCM" | "AES-256-CBC" | "AES-256-CFB" | "AES-256-OFB"
        | "ARIA-256-CBC" | "ARIA-256-CFB" | "ARIA-256-OFB"
        | "CAMELLIA-256-CBC" | "CAMELLIA-256-CFB" | "CAMELLIA-256-OFB"
        | "CHACHA20-POLY1305" => 256,
        "DES-CBC" | "DES-CFB" | "DES-OFB" => 64,
        "NONE" => 0,
        _ => {
            return Err(CipherNegotiationError::UnsupportedCipher(
                cipher.into(),
            ));
        }
    };
    Ok(bits)
}

pub fn split_server_push_reply_fields(
    fields: &[String],
) -> Result<Vec<Vec<u8>>, CipherNegotiationError> {
    if fields.first().map(String::as_str) != Some("PUSH_REPLY") {
        return Err(CipherNegotiationError::InvalidPushFields);
    }
    let mut current = "PUSH_REPLY".to_owned();
    let mut multiple = false;
    let mut payloads = Vec::new();
    for field in &fields[1..] {
        let addition = format!(",{field}");
        if current.len() + addition.len() >= SERVER_PUSH_SAFE_CAPACITY {
            if current == "PUSH_REPLY" {
                return Err(CipherNegotiationError::PushOptionTooLong(
                    field.clone(),
                ));
            }
            current.push_str(",push-continuation 2");
            payloads.push(current.into_bytes());
            current = "PUSH_REPLY".into();
            multiple = true;
        }
        if current.len() + addition.len() >= SERVER_PUSH_SAFE_CAPACITY {
            return Err(CipherNegotiationError::PushOptionTooLong(
                field.clone(),
            ));
        }
        current.push_str(&addition);
    }
    if multiple {
        current.push_str(",push-continuation 1");
    }
    payloads.push(current.into_bytes());
    Ok(payloads)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CipherNegotiationError {
    #[error("OpenVPN cipher negotiation failed: no shared cipher")]
    NoSharedCipher {
        local: Vec<String>,
        remote: Vec<String>,
    },
    #[error(
        "OpenVPN peer announced no cipher; data-ciphers-fallback is required"
    )]
    MissingPeerCipher,
    #[error("unsupported OpenVPN cipher: {0}")]
    UnsupportedCipher(String),
    #[error("invalid OpenVPN push reply fields")]
    InvalidPushFields,
    #[error("OpenVPN push option is too long: {0}")]
    PushOptionTooLong(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_legacy_cipher_and_peer_ncp_lists() {
        assert_eq!(
            extract_remote_cipher_name("V4, cipher [null-cipher],dev-type tun"),
            Some("none".into())
        );
        assert_eq!(
            peer_info_cipher_list(
                "IV_CIPHERS=AES-128-GCM::CHACHA20-POLY1305\r\n"
            ),
            (vec!["AES-128-GCM".into(), "CHACHA20-POLY1305".into()], true)
        );
        assert_eq!(
            peer_info_cipher_list("IV_NCP=2\r\n").0,
            vec!["AES-256-GCM", "AES-128-GCM"]
        );
    }

    #[test]
    fn follows_client_and_server_cipher_ordering_rules() {
        let local = vec!["AES-256-GCM".into(), "AES-128-GCM".into()];
        assert_eq!(
            select_p2p_cipher(
                &local,
                "",
                "IV_CIPHERS=AES-128-GCM:AES-256-GCM\n"
            )
            .unwrap(),
            "AES-128-GCM"
        );
        assert_eq!(
            select_server_cipher(&local, "", "IV_CIPHERS=AES-128-GCM\n", "")
                .unwrap(),
            "AES-128-GCM"
        );
        assert_eq!(
            select_pulled_cipher(&local, "", "aes-256-gcm").unwrap(),
            "AES-256-GCM"
        );
        assert_eq!(
            select_pulled_cipher(&local, "BF-CBC", "").unwrap(),
            "BF-CBC"
        );
    }

    #[test]
    fn reports_key_bits_for_every_family() {
        assert_eq!(tls_cipher_key_bits("DES-CBC"), Ok(64));
        assert_eq!(tls_cipher_key_bits("SEED-OFB"), Ok(128));
        assert_eq!(tls_cipher_key_bits("DES-EDE3-CFB"), Ok(192));
        assert_eq!(tls_cipher_key_bits("CHACHA20-POLY1305"), Ok(256));
        assert_eq!(tls_cipher_key_bits("NONE"), Ok(0));
    }

    #[test]
    fn splits_large_push_replies_with_continuation_markers() {
        let fields = vec![
            "PUSH_REPLY".into(),
            format!("setenv a {}", "x".repeat(600)),
            format!("setenv b {}", "y".repeat(600)),
        ];
        let payloads = split_server_push_reply_fields(&fields).unwrap();
        assert_eq!(payloads.len(), 2);
        assert!(payloads[0].ends_with(b",push-continuation 2"));
        assert!(payloads[1].ends_with(b",push-continuation 1"));
    }
}
