//! Reusable key and certificate generation for embedding applications.

use std::io;

use p256::{SecretKey, elliptic_curve::sec1::ToSec1Point};
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256, RsaKeySize, SerialNumber,
};
use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair32 {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

/// Generate a WireGuard private key with the RFC 7748 clamping that wgctrl
/// applies before serializing it.
pub fn generate_wireguard_keypair() -> io::Result<KeyPair32> {
    let mut private_key = random_32()?;
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    let public_key = x25519(private_key, X25519_BASEPOINT_BYTES);
    Ok(KeyPair32 {
        private_key,
        public_key,
    })
}

/// Reality uses the same X25519 key material as WireGuard and differs only in
/// its CLI encoding (raw URL-safe base64 rather than padded standard base64).
pub fn generate_reality_keypair() -> io::Result<KeyPair32> {
    generate_wireguard_keypair()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VapidKeyPair {
    pub private_key: [u8; 32],
    /// Uncompressed ANSI X9.63 point: 0x04 || X || Y.
    pub public_key: [u8; 65],
}

pub fn generate_vapid_keypair() -> io::Result<VapidKeyPair> {
    for _ in 0..128 {
        let private_key = random_32()?;
        let Ok(secret) = SecretKey::from_slice(&private_key) else {
            continue;
        };
        let encoded = secret.public_key().to_sec1_point(false);
        let public_key: [u8; 65] =
            encoded.as_bytes().try_into().map_err(|_| {
                io::Error::other("P-256 generated an invalid public-key length")
            })?;
        return Ok(VapidKeyPair {
            private_key,
            public_key,
        });
    }
    Err(io::Error::other("failed to generate a valid P-256 key"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsKeyPair {
    pub private_key_pem: String,
    pub certificate_pem: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchKeyPair {
    pub config_pem: String,
    pub key_pem: String,
}

/// Generate the draft ECH configuration/key PEM pair emitted by upstream
/// `sing-box generate ech-keypair`.
pub fn generate_ech_keypair(public_name: &str) -> io::Result<EchKeyPair> {
    if public_name.is_empty() || public_name.len() > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ECH public name length must be between 1 and 255 bytes",
        ));
    }

    let private_key = random_32()?;
    let public_key = x25519(private_key, X25519_BASEPOINT_BYTES);

    // ECHConfigContents as emitted by upstream's marshalECHConfig:
    // config_id, X25519 KEM, public key, three HKDF-SHA256 cipher suites,
    // max_name_length, public_name, and an empty extension vector.
    let mut contents = Vec::with_capacity(64 + public_name.len());
    contents.push(0);
    contents.extend_from_slice(&0x0020_u16.to_be_bytes());
    push_u16_bytes(&mut contents, &public_key)?;
    let mut suites = Vec::with_capacity(12);
    for aead in [0x0001_u16, 0x0002, 0x0003] {
        suites.extend_from_slice(&0x0001_u16.to_be_bytes());
        suites.extend_from_slice(&aead.to_be_bytes());
    }
    push_u16_bytes(&mut contents, &suites)?;
    contents.push(0);
    contents.push(public_name.len() as u8);
    contents.extend_from_slice(public_name.as_bytes());
    contents.extend_from_slice(&0_u16.to_be_bytes());

    let mut config = Vec::with_capacity(contents.len() + 4);
    config.extend_from_slice(&0xfe0d_u16.to_be_bytes());
    push_u16_bytes(&mut config, &contents)?;

    let mut config_list = Vec::with_capacity(config.len() + 2);
    push_u16_bytes(&mut config_list, &config)?;

    let mut keys = Vec::with_capacity(36 + config.len());
    push_u16_bytes(&mut keys, &private_key)?;
    push_u16_bytes(&mut keys, &config)?;

    Ok(EchKeyPair {
        config_pem: pem::encode(&pem::Pem::new("ECH CONFIGS", config_list)),
        key_pem: pem::encode(&pem::Pem::new("ECH KEYS", keys)),
    })
}

/// Generate the RSA-2048 / SHA-256 self-signed server certificate emitted by
/// upstream `sing-box generate tls-keypair`.
pub fn generate_tls_keypair(
    server_name: &str,
    valid_months: i32,
) -> io::Result<TlsKeyPair> {
    if server_name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "server name is empty",
        ));
    }
    if valid_months <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "valid months must be positive",
        ));
    }
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::new(vec![server_name.to_owned()])
        .map_err(io::Error::other)?;
    params.not_before = now - Duration::hours(1);
    params.not_after = add_months(now, valid_months)?;
    let mut serial = [0_u8; 16];
    getrandom::fill(&mut serial).map_err(random_error)?;
    serial[0] &= 0x7f;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, server_name);
    params.key_usages = vec![
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
        .map_err(io::Error::other)?;
    let certificate = params.self_signed(&key).map_err(io::Error::other)?;
    Ok(TlsKeyPair {
        private_key_pem: key.serialize_pem(),
        certificate_pem: certificate.pem(),
    })
}

fn random_32() -> io::Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(random_error)?;
    Ok(bytes)
}

fn push_u16_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> io::Result<()> {
    let length = u16::try_from(bytes.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "ECH field is too long")
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn random_error(error: getrandom::Error) -> io::Error {
    io::Error::other(format!("generate random bytes: {error}"))
}

fn add_months(
    timestamp: OffsetDateTime,
    months: i32,
) -> io::Result<OffsetDateTime> {
    let date = timestamp.date();
    let absolute_month =
        date.year() * 12 + i32::from(u8::from(date.month())) - 1;
    let target = absolute_month.checked_add(months).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "certificate expiry overflow",
        )
    })?;
    let year = target.div_euclid(12);
    let month = Month::try_from((target.rem_euclid(12) + 1) as u8)
        .map_err(io::Error::other)?;
    let day = date.day().min(month.length(year));
    let date =
        Date::from_calendar_date(year, month, day).map_err(io::Error::other)?;
    Ok(PrimitiveDateTime::new(date, timestamp.time()).assume_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireguard_keys_are_clamped_and_public_key_matches() {
        let pair = generate_wireguard_keypair().unwrap();
        assert_eq!(pair.private_key[0] & 7, 0);
        assert_eq!(pair.private_key[31] & 0x80, 0);
        assert_ne!(pair.private_key[31] & 0x40, 0);
        assert_eq!(
            pair.public_key,
            x25519(pair.private_key, X25519_BASEPOINT_BYTES)
        );
    }

    #[test]
    fn vapid_public_key_is_uncompressed_p256() {
        let pair = generate_vapid_keypair().unwrap();
        assert_eq!(pair.public_key[0], 4);
        let secret = SecretKey::from_slice(&pair.private_key).unwrap();
        assert_eq!(
            pair.public_key.as_slice(),
            secret.public_key().to_sec1_point(false).as_bytes()
        );
    }

    #[test]
    fn tls_keypair_is_accepted_by_rustls() {
        let pair = generate_tls_keypair("server.example", 1).unwrap();
        let options = crate::option::InboundTlsOptions {
            enabled: true,
            certificate: crate::option::Listable(vec![pair.certificate_pem]),
            key: crate::option::Listable(vec![pair.private_key_pem]),
            ..Default::default()
        };
        crate::common::tls::build_server_config(&options).unwrap();
    }

    #[test]
    fn ech_keypair_uses_upstream_pem_and_wire_layout() {
        let pair = generate_ech_keypair("public.example").unwrap();
        let config = pem::parse(pair.config_pem).unwrap();
        let keys = pem::parse(pair.key_pem).unwrap();
        assert_eq!(config.tag(), "ECH CONFIGS");
        assert_eq!(keys.tag(), "ECH KEYS");

        let config_bytes = config.contents();
        assert_eq!(
            u16::from_be_bytes([config_bytes[0], config_bytes[1]]) as usize,
            config_bytes.len() - 2
        );
        assert_eq!(&config_bytes[2..4], &0xfe0d_u16.to_be_bytes());

        let key_bytes = keys.contents();
        assert_eq!(&key_bytes[..2], &32_u16.to_be_bytes());
        assert_eq!(
            u16::from_be_bytes([key_bytes[34], key_bytes[35]]) as usize,
            config_bytes.len() - 2
        );
        assert_eq!(&key_bytes[36..], &config_bytes[2..]);
    }
}
