use x509_parser::{extensions::ParsedExtension, prelude::*};

const KEY_USAGE_OID: &str = "2.5.29.15";
const EXTENDED_KEY_USAGE_OID: &str = "2.5.29.37";
const NETSCAPE_CERT_TYPE_OID: &str = "2.16.840.1.113730.1.1";
const MICROSOFT_SERVER_GATED_CRYPTO_OID: &str = "1.3.6.1.4.1.311.10.3.3";
const NETSCAPE_SERVER_GATED_CRYPTO_OID: &str = "2.16.840.1.113730.4.1";

pub const OPENSSL_KEY_USAGE_DIGITAL_SIGNATURE: u16 = 0x0080;
pub const OPENSSL_KEY_USAGE_KEY_ENCIPHERMENT: u16 = 0x0020;
pub const OPENSSL_KEY_USAGE_KEY_AGREEMENT: u16 = 0x0008;

const EXTENDED_KEY_USAGE_SSL_SERVER: u8 = 0x01;
const EXTENDED_KEY_USAGE_SSL_CLIENT: u8 = 0x02;
const EXTENDED_KEY_USAGE_SERVER_GATED_CRYPTO: u8 = 0x10;

pub const NETSCAPE_CERT_TYPE_SSL_CLIENT: u8 = 0x80;
pub const NETSCAPE_CERT_TYPE_SSL_SERVER: u8 = 0x40;
const NETSCAPE_CERT_TYPE_SSL_CA: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificatePurpose {
    SslClient,
    SslServer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CertificateUsageExtensions {
    pub key_usage: Option<u16>,
    pub extended_key_usage: Option<u8>,
    pub netscape_cert_type: Option<u8>,
}

impl CertificateUsageExtensions {
    fn rejects_key_usage(self, accepted: u16) -> bool {
        self.key_usage.is_some_and(|usage| usage & accepted == 0)
    }

    fn rejects_extended_key_usage(self, accepted: u8) -> bool {
        self.extended_key_usage
            .is_some_and(|usage| usage & accepted == 0)
    }

    fn rejects_netscape_cert_type(self, accepted: u8) -> bool {
        self.netscape_cert_type
            .is_some_and(|usage| usage & accepted == 0)
    }
}

pub fn read_certificate_usage_extensions(
    certificate_der: &[u8],
) -> Result<CertificateUsageExtensions, CertificatePurposeError> {
    let (remaining, certificate) = X509Certificate::from_der(certificate_der)
        .map_err(|error| {
        CertificatePurposeError::InvalidCertificate(error.to_string())
    })?;
    if !remaining.is_empty() {
        return Err(CertificatePurposeError::TrailingCertificateData);
    }
    let mut usage = CertificateUsageExtensions::default();
    for extension in certificate.extensions() {
        match extension.oid.to_id_string().as_str() {
            KEY_USAGE_OID => match extension.parsed_extension() {
                ParsedExtension::KeyUsage(key_usage) => {
                    usage.key_usage =
                        Some(openssl_key_usage_bits(key_usage.flags));
                }
                ParsedExtension::ParseError { error } => {
                    return Err(CertificatePurposeError::InvalidExtension(
                        error.to_string(),
                    ));
                }
                _ => return Err(CertificatePurposeError::InvalidKeyUsage),
            },
            EXTENDED_KEY_USAGE_OID => match extension.parsed_extension() {
                ParsedExtension::ExtendedKeyUsage(key_usage) => {
                    let mut bits = 0;
                    if key_usage.server_auth {
                        bits |= EXTENDED_KEY_USAGE_SSL_SERVER;
                    }
                    if key_usage.client_auth {
                        bits |= EXTENDED_KEY_USAGE_SSL_CLIENT;
                    }
                    for oid in &key_usage.other {
                        match oid.to_id_string().as_str() {
                            MICROSOFT_SERVER_GATED_CRYPTO_OID
                            | NETSCAPE_SERVER_GATED_CRYPTO_OID => {
                                bits |= EXTENDED_KEY_USAGE_SERVER_GATED_CRYPTO;
                            }
                            _ => {}
                        }
                    }
                    usage.extended_key_usage = Some(bits);
                }
                ParsedExtension::ParseError { error } => {
                    return Err(CertificatePurposeError::InvalidExtension(
                        error.to_string(),
                    ));
                }
                _ => {
                    return Err(
                        CertificatePurposeError::InvalidExtendedKeyUsage,
                    );
                }
            },
            NETSCAPE_CERT_TYPE_OID => {
                usage.netscape_cert_type =
                    Some(parse_first_bit_string_byte(extension.value)?);
            }
            _ => {}
        }
    }
    Ok(usage)
}

pub fn check_certificate_purpose(
    certificate_der: &[u8],
    purpose: CertificatePurpose,
    require_certificate_authority: bool,
) -> Result<bool, CertificatePurposeError> {
    let usage = read_certificate_usage_extensions(certificate_der)?;
    match purpose {
        CertificatePurpose::SslClient => {
            if usage.rejects_extended_key_usage(EXTENDED_KEY_USAGE_SSL_CLIENT) {
                return Ok(false);
            }
            if require_certificate_authority {
                return Ok(!usage
                    .rejects_netscape_cert_type(NETSCAPE_CERT_TYPE_SSL_CA));
            }
            Ok(!usage.rejects_key_usage(
                OPENSSL_KEY_USAGE_DIGITAL_SIGNATURE
                    | OPENSSL_KEY_USAGE_KEY_AGREEMENT,
            ) && !usage
                .rejects_netscape_cert_type(NETSCAPE_CERT_TYPE_SSL_CLIENT))
        }
        CertificatePurpose::SslServer => {
            if usage.rejects_extended_key_usage(
                EXTENDED_KEY_USAGE_SSL_SERVER
                    | EXTENDED_KEY_USAGE_SERVER_GATED_CRYPTO,
            ) {
                return Ok(false);
            }
            if require_certificate_authority {
                return Ok(!usage
                    .rejects_netscape_cert_type(NETSCAPE_CERT_TYPE_SSL_CA));
            }
            Ok(
                !usage
                    .rejects_netscape_cert_type(NETSCAPE_CERT_TYPE_SSL_SERVER)
                    && !usage.rejects_key_usage(
                        OPENSSL_KEY_USAGE_DIGITAL_SIGNATURE
                            | OPENSSL_KEY_USAGE_KEY_ENCIPHERMENT
                            | OPENSSL_KEY_USAGE_KEY_AGREEMENT,
                    ),
            )
        }
    }
}

pub fn openssl_key_usage_bits(flags: u16) -> u16 {
    let mut usage = 0;
    for bit in 0..8 {
        if flags & (1 << bit) != 0 {
            usage |= 1 << (7 - bit);
        }
    }
    for bit in 8..16 {
        if flags & (1 << bit) != 0 {
            usage |= 1 << (23 - bit);
        }
    }
    usage
}

fn parse_first_bit_string_byte(
    value: &[u8],
) -> Result<u8, CertificatePurposeError> {
    if value.len() < 3 || value[0] != 0x03 {
        return Err(CertificatePurposeError::InvalidNetscapeCertType);
    }
    let (length, header) = if value[1] & 0x80 == 0 {
        (usize::from(value[1]), 2)
    } else {
        let count = usize::from(value[1] & 0x7f);
        if count == 0 || count > 2 || value.len() < 2 + count {
            return Err(CertificatePurposeError::InvalidNetscapeCertType);
        }
        let mut length = 0;
        for byte in &value[2..2 + count] {
            length = length * 256 + usize::from(*byte);
        }
        (length, 2 + count)
    };
    if length == 0 || header + length != value.len() || value[header] > 7 {
        return Err(CertificatePurposeError::InvalidNetscapeCertType);
    }
    Ok(value.get(header + 1).copied().unwrap_or(0))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertificatePurposeError {
    #[error("invalid X.509 certificate: {0}")]
    InvalidCertificate(String),
    #[error("trailing data after X.509 certificate")]
    TrailingCertificateData,
    #[error("invalid certificate extension: {0}")]
    InvalidExtension(String),
    #[error("invalid key usage extension")]
    InvalidKeyUsage,
    #[error("invalid extended key usage extension")]
    InvalidExtendedKeyUsage,
    #[error("invalid Netscape certificate type extension")]
    InvalidNetscapeCertType,
}

#[cfg(test)]
mod tests {
    use rcgen::{
        CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    };

    use super::*;

    fn certificate(
        key_usages: Vec<KeyUsagePurpose>,
        extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
    ) -> Vec<u8> {
        let mut params =
            CertificateParams::new(vec!["vpn.test".into()]).unwrap();
        params.key_usages = key_usages;
        params.extended_key_usages = extended_key_usages;
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn missing_usage_extensions_accept_every_tls_purpose() {
        let der = certificate(Vec::new(), Vec::new());
        assert!(
            check_certificate_purpose(
                &der,
                CertificatePurpose::SslClient,
                false
            )
            .unwrap()
        );
        assert!(
            check_certificate_purpose(
                &der,
                CertificatePurpose::SslServer,
                false
            )
            .unwrap()
        );
    }

    #[test]
    fn enforces_leaf_key_and_extended_usage_like_openssl() {
        let server = certificate(
            vec![KeyUsagePurpose::DigitalSignature],
            vec![ExtendedKeyUsagePurpose::ServerAuth],
        );
        assert!(
            check_certificate_purpose(
                &server,
                CertificatePurpose::SslServer,
                false
            )
            .unwrap()
        );
        assert!(
            !check_certificate_purpose(
                &server,
                CertificatePurpose::SslClient,
                false
            )
            .unwrap()
        );
        assert_eq!(
            read_certificate_usage_extensions(&server)
                .unwrap()
                .key_usage,
            Some(OPENSSL_KEY_USAGE_DIGITAL_SIGNATURE)
        );
    }

    #[test]
    fn key_usage_mapping_preserves_openssl_two_byte_layout() {
        assert_eq!(openssl_key_usage_bits(1), 0x80);
        assert_eq!(openssl_key_usage_bits(1 << 2), 0x20);
        assert_eq!(openssl_key_usage_bits(1 << 4), 0x08);
        assert_eq!(openssl_key_usage_bits(1 << 8), 0x8000);
    }

    #[test]
    fn parses_netscape_bit_string_value() {
        assert_eq!(
            parse_first_bit_string_byte(&[3, 2, 0, 0xc0]).unwrap(),
            0xc0
        );
        assert!(parse_first_bit_string_byte(&[4, 2, 0, 0xc0]).is_err());
    }
}
