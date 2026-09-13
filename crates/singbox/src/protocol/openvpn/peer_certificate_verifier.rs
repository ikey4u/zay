use std::collections::HashSet;

use openssl::{nid::Nid, pkey::Id, sha::sha256, x509::X509Ref};
use x509_parser::{extensions::ParsedExtension, prelude::*};

use super::{
    CertificateProfile, CertificatePurpose, certificate_username,
    check_certificate_purpose, format_certificate_subject,
    read_certificate_usage_extensions,
};

const COMMON_NAME_OID: &str = "2.5.4.3";
const EXTENDED_KEY_USAGE_OID: &str = "2.5.29.37";
pub const SERVER_AUTH_OID: &str = "1.3.6.1.5.5.7.3.1";
pub const CLIENT_AUTH_OID: &str = "1.3.6.1.5.5.7.3.2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVpnPeerVerifierOptions {
    pub purpose: CertificatePurpose,
    pub verify_name: String,
    pub verify_name_type: String,
    pub peer_fingerprints: Vec<String>,
    pub required_key_usage: Vec<u64>,
    pub require_key_usage_extension: bool,
    pub required_extended_usage: Vec<String>,
    pub ns_certificate_type: String,
    pub certificate_profile: CertificateProfile,
    pub trust_store_present: bool,
}

#[derive(Debug, Clone)]
pub struct OpenVpnPeerVerifier {
    options: OpenVpnPeerVerifierOptions,
    fingerprints: HashSet<String>,
}

impl OpenVpnPeerVerifier {
    pub fn new(
        options: OpenVpnPeerVerifierOptions,
    ) -> Result<Self, PeerCertificateError> {
        validate_verify_name_type(&options.verify_name_type)?;
        validate_ns_certificate_type(&options.ns_certificate_type)?;
        for oid in &options.required_extended_usage {
            validate_object_identifier(oid)?;
        }
        let fingerprints = options
            .peer_fingerprints
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();
        Ok(Self {
            options,
            fingerprints,
        })
    }

    pub fn fingerprint_only(&self) -> bool {
        !self.options.trust_store_present && !self.fingerprints.is_empty()
    }

    pub fn verify_chain_certificate(
        &self,
        certificate: &X509Ref,
        is_certificate_authority: bool,
    ) -> Result<(), PeerCertificateError> {
        if self.fingerprint_only() {
            return Ok(());
        }
        enforce_certificate_profile(
            certificate,
            self.options.certificate_profile,
        )?;
        let der = certificate.to_der().map_err(backend_error)?;
        if !check_certificate_purpose(
            &der,
            self.options.purpose,
            is_certificate_authority,
        )
        .map_err(|error| {
            PeerCertificateError::InvalidCertificate(error.to_string())
        })? {
            return Err(PeerCertificateError::Purpose);
        }
        Ok(())
    }

    pub fn verify_peer_certificate(
        &self,
        certificate: &X509Ref,
    ) -> Result<(), PeerCertificateError> {
        verify_x509_name_match(
            certificate,
            &self.options.verify_name,
            &self.options.verify_name_type,
        )?;
        if !self.fingerprints.is_empty()
            && !self
                .fingerprints
                .contains(&certificate_fingerprint(certificate)?)
        {
            return Err(PeerCertificateError::Fingerprint);
        }
        let der = certificate.to_der().map_err(backend_error)?;
        let usage =
            read_certificate_usage_extensions(&der).map_err(|error| {
                PeerCertificateError::InvalidCertificate(error.to_string())
            })?;
        if !self.options.required_key_usage.is_empty()
            && self.options.required_key_usage[0] != 0
        {
            let key_usage =
                usage.key_usage.ok_or(PeerCertificateError::KeyUsage)?;
            let key_usage = if key_usage & 0xff == 0 {
                key_usage >> 8
            } else {
                key_usage
            };
            if !self.options.required_key_usage.iter().any(|required| {
                *required != 0 && u64::from(key_usage) & required == *required
            }) {
                return Err(PeerCertificateError::KeyUsage);
            }
        }
        if self.options.require_key_usage_extension && usage.key_usage.is_none()
        {
            return Err(PeerCertificateError::KeyUsage);
        }
        verify_required_extended_key_usage(
            &der,
            &self.options.required_extended_usage,
        )?;
        if !self.options.ns_certificate_type.is_empty() {
            let purpose = match self.options.ns_certificate_type.as_str() {
                "server" => CertificatePurpose::SslServer,
                "client" => CertificatePurpose::SslClient,
                _ => unreachable!("validated by constructor"),
            };
            if !check_certificate_purpose(&der, purpose, false).map_err(
                |error| {
                    PeerCertificateError::InvalidCertificate(error.to_string())
                },
            )? {
                return Err(PeerCertificateError::NetscapeCertificateType);
            }
        }
        Ok(())
    }
}

pub fn parse_remote_cert_key_usages(
    values: &[String],
) -> Result<Vec<u64>, PeerCertificateError> {
    values
        .iter()
        .map(|value| {
            if value.is_empty() {
                return Err(PeerCertificateError::EmptyKeyUsage);
            }
            u64::from_str_radix(value, 16).map_err(|_| {
                PeerCertificateError::InvalidKeyUsage(value.clone())
            })
        })
        .collect()
}

pub fn parse_remote_cert_extended_key_usage(
    value: &str,
) -> Result<Vec<String>, PeerCertificateError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let oid = match value {
        "server" | "TLS Web Server Authentication" => SERVER_AUTH_OID,
        "client" | "TLS Web Client Authentication" => CLIENT_AUTH_OID,
        "Code Signing" => "1.3.6.1.5.5.7.3.3",
        "E-mail Protection" => "1.3.6.1.5.5.7.3.4",
        "IPSec End System" => "1.3.6.1.5.5.7.3.5",
        "IPSec Tunnel" => "1.3.6.1.5.5.7.3.6",
        "IPSec User" => "1.3.6.1.5.5.7.3.7",
        "Time Stamping" => "1.3.6.1.5.5.7.3.8",
        "OCSP Signing" => "1.3.6.1.5.5.7.3.9",
        "Any Extended Key Usage" => "2.5.29.37.0",
        "Microsoft Server Gated Crypto" => "1.3.6.1.4.1.311.10.3.3",
        "Netscape Server Gated Crypto" => "2.16.840.1.113730.4.1",
        "Microsoft Commercial Code Signing" => "1.3.6.1.4.1.311.2.1.22",
        "Microsoft Individual Code Signing" => "1.3.6.1.4.1.311.2.1.21",
        value => {
            validate_object_identifier(value)?;
            value
        }
    };
    Ok(vec![oid.to_owned()])
}

pub fn expand_remote_cert_tls(
    mode: &str,
) -> Result<(bool, Vec<String>), PeerCertificateError> {
    match mode {
        "" | "none" => Ok((false, Vec::new())),
        "server" => Ok((true, vec![SERVER_AUTH_OID.into()])),
        "client" => Ok((true, vec![CLIENT_AUTH_OID.into()])),
        _ => Err(PeerCertificateError::InvalidRemoteCertificateTls(
            mode.into(),
        )),
    }
}

pub fn merge_extended_key_usage(
    mut existing: Vec<String>,
    additional: Vec<String>,
) -> Vec<String> {
    for addition in additional {
        if !existing.contains(&addition) {
            existing.push(addition);
        }
    }
    existing
}

pub fn certificate_fingerprint(
    certificate: &X509Ref,
) -> Result<String, PeerCertificateError> {
    let der = certificate.to_der().map_err(backend_error)?;
    Ok(hex::encode(sha256(&der)))
}

pub fn enforce_certificate_profile(
    certificate: &X509Ref,
    profile: CertificateProfile,
) -> Result<(), PeerCertificateError> {
    if profile == CertificateProfile::Insecure {
        return Ok(());
    }
    let key = certificate.public_key().map_err(backend_error)?;
    if profile == CertificateProfile::SuiteB {
        if key.id() != Id::EC {
            return Err(PeerCertificateError::SuiteBKey);
        }
        let curve = key.ec_key().map_err(backend_error)?.group().curve_name();
        if !matches!(curve, Some(Nid::X9_62_PRIME256V1 | Nid::SECP384R1)) {
            return Err(PeerCertificateError::SuiteBKey);
        }
    } else if key.id() == Id::RSA || key.id() == Id::RSA_PSS {
        let minimum = if profile == CertificateProfile::Preferred {
            2048
        } else {
            1024
        };
        if key.bits() < minimum {
            return Err(PeerCertificateError::RsaKeyTooSmall {
                profile,
                minimum,
            });
        }
    }

    let signature = certificate.signature_algorithm().object().nid();
    if profile == CertificateProfile::SuiteB {
        if !matches!(signature, Nid::ECDSA_WITH_SHA256 | Nid::ECDSA_WITH_SHA384)
        {
            return Err(PeerCertificateError::SuiteBSignature);
        }
    } else if matches!(
        signature,
        Nid::MD2WITHRSAENCRYPTION | Nid::MD5WITHRSAENCRYPTION | Nid::MD5WITHRSA
    ) {
        return Err(PeerCertificateError::InsecureSignature);
    } else if profile == CertificateProfile::Preferred
        && matches!(
            signature,
            Nid::SHA1WITHRSAENCRYPTION
                | Nid::SHA1WITHRSA
                | Nid::DSAWITHSHA1
                | Nid::DSAWITHSHA1_2
                | Nid::ECDSA_WITH_SHA1
        )
    {
        return Err(PeerCertificateError::Sha1Signature);
    }
    Ok(())
}

fn verify_x509_name_match(
    certificate: &X509Ref,
    expected: &str,
    name_type: &str,
) -> Result<(), PeerCertificateError> {
    if expected.is_empty() {
        return Ok(());
    }
    let subject = certificate.subject_name().to_der().map_err(backend_error)?;
    let matched = match name_type {
        "" | "subject" => {
            format_certificate_subject(&subject).map_err(|error| {
                PeerCertificateError::InvalidCertificate(error.to_string())
            })? == expected
        }
        "name" => {
            certificate_username(&subject, COMMON_NAME_OID).map_err(
                |error| {
                    PeerCertificateError::InvalidCertificate(error.to_string())
                },
            )? == expected
        }
        "name-prefix" => certificate_username(&subject, COMMON_NAME_OID)
            .map_err(|error| {
                PeerCertificateError::InvalidCertificate(error.to_string())
            })?
            .starts_with(expected),
        _ => unreachable!("validated by constructor"),
    };
    if matched {
        Ok(())
    } else {
        Err(PeerCertificateError::Name)
    }
}

fn verify_required_extended_key_usage(
    certificate_der: &[u8],
    required: &[String],
) -> Result<(), PeerCertificateError> {
    if required.is_empty() {
        return Ok(());
    }
    let (_, certificate) =
        X509Certificate::from_der(certificate_der).map_err(|error| {
            PeerCertificateError::InvalidCertificate(error.to_string())
        })?;
    let mut actual = HashSet::new();
    for extension in certificate.extensions() {
        if extension.oid.to_id_string() != EXTENDED_KEY_USAGE_OID {
            continue;
        }
        let ParsedExtension::ExtendedKeyUsage(usage) =
            extension.parsed_extension()
        else {
            return Err(PeerCertificateError::ExtendedKeyUsage);
        };
        if usage.any {
            actual.insert("2.5.29.37.0".to_owned());
        }
        if usage.server_auth {
            actual.insert(SERVER_AUTH_OID.to_owned());
        }
        if usage.client_auth {
            actual.insert(CLIENT_AUTH_OID.to_owned());
        }
        if usage.code_signing {
            actual.insert("1.3.6.1.5.5.7.3.3".to_owned());
        }
        if usage.email_protection {
            actual.insert("1.3.6.1.5.5.7.3.4".to_owned());
        }
        if usage.time_stamping {
            actual.insert("1.3.6.1.5.5.7.3.8".to_owned());
        }
        if usage.ocsp_signing {
            actual.insert("1.3.6.1.5.5.7.3.9".to_owned());
        }
        actual.extend(usage.other.iter().map(ToString::to_string));
    }
    if required.iter().all(|required| actual.contains(required)) {
        Ok(())
    } else {
        Err(PeerCertificateError::ExtendedKeyUsage)
    }
}

fn validate_verify_name_type(value: &str) -> Result<(), PeerCertificateError> {
    if matches!(value, "" | "subject" | "name" | "name-prefix") {
        Ok(())
    } else {
        Err(PeerCertificateError::InvalidNameType(value.into()))
    }
}

fn validate_ns_certificate_type(
    value: &str,
) -> Result<(), PeerCertificateError> {
    if matches!(value, "" | "server" | "client") {
        Ok(())
    } else {
        Err(PeerCertificateError::InvalidNetscapeType(value.into()))
    }
}

fn validate_object_identifier(value: &str) -> Result<(), PeerCertificateError> {
    let components = value
        .split('.')
        .map(str::parse::<i64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            PeerCertificateError::InvalidObjectIdentifier(value.into())
        })?;
    if components.len() < 2
        || components.iter().any(|component| *component < 0)
        || components[0] > 2
        || (components[0] < 2 && components[1] > 39)
    {
        return Err(PeerCertificateError::InvalidObjectIdentifier(
            value.into(),
        ));
    }
    Ok(())
}

fn backend_error(error: openssl::error::ErrorStack) -> PeerCertificateError {
    PeerCertificateError::Backend(error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerCertificateError {
    #[error("invalid X.509 certificate: {0}")]
    InvalidCertificate(String),
    #[error("peer certificate has an invalid TLS purpose")]
    Purpose,
    #[error("peer certificate X.509 name mismatch")]
    Name,
    #[error("peer certificate fingerprint mismatch")]
    Fingerprint,
    #[error("peer certificate key usage mismatch")]
    KeyUsage,
    #[error("peer certificate extended key usage mismatch")]
    ExtendedKeyUsage,
    #[error("peer certificate Netscape certificate type mismatch")]
    NetscapeCertificateType,
    #[error("empty key usage hex")]
    EmptyKeyUsage,
    #[error("invalid key usage hex: {0}")]
    InvalidKeyUsage(String),
    #[error("invalid remote-cert-tls value: {0}")]
    InvalidRemoteCertificateTls(String),
    #[error("invalid object identifier: {0}")]
    InvalidObjectIdentifier(String),
    #[error("invalid X.509 name type: {0}")]
    InvalidNameType(String),
    #[error("invalid Netscape certificate type: {0}")]
    InvalidNetscapeType(String),
    #[error("tls-cert-profile suiteb requires ECDSA P-256 or P-384")]
    SuiteBKey,
    #[error("tls-cert-profile suiteb requires ECDSA with SHA-256 or SHA-384")]
    SuiteBSignature,
    #[error(
        "tls-cert-profile {profile:?} rejects RSA key smaller than {minimum} bits"
    )]
    RsaKeyTooSmall {
        profile: CertificateProfile,
        minimum: u32,
    },
    #[error("certificate profile rejects an insecure signature algorithm")]
    InsecureSignature,
    #[error("tls-cert-profile preferred rejects SHA-1 signature algorithm")]
    Sha1Signature,
    #[error("OpenSSL certificate backend: {0}")]
    Backend(String),
}

#[cfg(test)]
mod tests {
    use openssl::x509::X509;
    use rcgen::{
        CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    };

    use super::*;

    fn certificate(common_name: &str, eku: ExtendedKeyUsagePurpose) -> X509 {
        let mut params =
            CertificateParams::new(vec![common_name.into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![eku];
        let key = KeyPair::generate().unwrap();
        X509::from_der(params.self_signed(&key).unwrap().der()).unwrap()
    }

    fn verifier() -> OpenVpnPeerVerifier {
        OpenVpnPeerVerifier::new(OpenVpnPeerVerifierOptions {
            purpose: CertificatePurpose::SslServer,
            verify_name: "vpn.test".into(),
            verify_name_type: "name".into(),
            peer_fingerprints: Vec::new(),
            required_key_usage: vec![0x80],
            require_key_usage_extension: true,
            required_extended_usage: vec![SERVER_AUTH_OID.into()],
            ns_certificate_type: String::new(),
            certificate_profile: CertificateProfile::Preferred,
            trust_store_present: true,
        })
        .unwrap()
    }

    #[test]
    fn parses_remote_certificate_options() {
        assert_eq!(
            parse_remote_cert_key_usages(&["a0".into(), "80".into()]).unwrap(),
            [0xa0, 0x80]
        );
        assert!(parse_remote_cert_key_usages(&[String::new()]).is_err());
        assert_eq!(
            parse_remote_cert_extended_key_usage("server").unwrap(),
            [SERVER_AUTH_OID]
        );
        assert_eq!(
            expand_remote_cert_tls("client").unwrap(),
            (true, vec![CLIENT_AUTH_OID.into()])
        );
        assert!(expand_remote_cert_tls("peer").is_err());
    }

    #[test]
    fn verifies_name_fingerprint_key_usage_and_eku() {
        let peer_certificate =
            certificate("vpn.test", ExtendedKeyUsagePurpose::ServerAuth);
        let verifier = verifier();
        verifier.verify_peer_certificate(&peer_certificate).unwrap();
        verifier
            .verify_chain_certificate(&peer_certificate, false)
            .unwrap();

        let wrong_name =
            certificate("other.test", ExtendedKeyUsagePurpose::ServerAuth);
        assert_eq!(
            verifier.verify_peer_certificate(&wrong_name).unwrap_err(),
            PeerCertificateError::Name
        );
    }

    #[test]
    fn fingerprint_only_skips_chain_profile_but_not_leaf_rules() {
        let peer_certificate =
            certificate("vpn.test", ExtendedKeyUsagePurpose::ServerAuth);
        let fingerprint = certificate_fingerprint(&peer_certificate).unwrap();
        let verifier = OpenVpnPeerVerifier::new(OpenVpnPeerVerifierOptions {
            peer_fingerprints: vec![fingerprint],
            trust_store_present: false,
            ..verifier().options
        })
        .unwrap();
        assert!(verifier.fingerprint_only());
        verifier
            .verify_chain_certificate(&peer_certificate, false)
            .unwrap();
        verifier.verify_peer_certificate(&peer_certificate).unwrap();
    }

    #[test]
    fn required_eku_is_conjunctive_and_oid_parser_is_strict() {
        let peer_certificate =
            certificate("vpn.test", ExtendedKeyUsagePurpose::ServerAuth);
        let verifier = OpenVpnPeerVerifier::new(OpenVpnPeerVerifierOptions {
            required_extended_usage: vec![
                SERVER_AUTH_OID.into(),
                CLIENT_AUTH_OID.into(),
            ],
            ..verifier().options
        })
        .unwrap();
        assert_eq!(
            verifier
                .verify_peer_certificate(&peer_certificate)
                .unwrap_err(),
            PeerCertificateError::ExtendedKeyUsage
        );
        assert!(
            parse_remote_cert_extended_key_usage("1.3.6.1.5.5.7.3.1").is_ok()
        );
        assert!(parse_remote_cert_extended_key_usage("1..3").is_err());
        assert!(parse_remote_cert_extended_key_usage("3.1").is_err());
    }
}
