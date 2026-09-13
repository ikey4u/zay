use std::{collections::HashSet, fs, path::PathBuf, sync::Arc};

use openssl::{
    pkey::PKey,
    ssl::{
        SslContext, SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode,
        SslVersion,
    },
    x509::{X509, X509PurposeId, store::X509Lookup, verify::X509VerifyFlags},
};

use super::{
    CertificatePurpose, OpenVpnPeerVerifier, OpenVpnPeerVerifierOptions,
    enforce_certificate_profile, expand_remote_cert_tls,
    merge_extended_key_usage, parse_remote_cert_extended_key_usage,
    parse_remote_cert_key_usages,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenVpnTlsRole {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyClientCertMode {
    None,
    Optional,
    Require,
}

pub fn resolve_verify_client_cert_mode(
    value: &str,
) -> Result<VerifyClientCertMode, OpenVpnTlsError> {
    match value {
        "" | "require" => Ok(VerifyClientCertMode::Require),
        "optional" => Ok(VerifyClientCertMode::Optional),
        "none" => Ok(VerifyClientCertMode::None),
        _ => Err(OpenVpnTlsError::InvalidVerifyClientCert(value.into())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OpenVpnTlsVersion {
    V1_0,
    V1_1,
    V1_2,
    V1_3,
}

impl OpenVpnTlsVersion {
    fn openssl(self) -> SslVersion {
        match self {
            Self::V1_0 => SslVersion::TLS1,
            Self::V1_1 => SslVersion::TLS1_1,
            Self::V1_2 => SslVersion::TLS1_2,
            Self::V1_3 => SslVersion::TLS1_3,
        }
    }
}

pub fn parse_tls_version_token(
    value: &str,
) -> Result<Option<OpenVpnTlsVersion>, OpenVpnTlsError> {
    match value {
        "" => Ok(None),
        "1.0" => Ok(Some(OpenVpnTlsVersion::V1_0)),
        "1.1" => Ok(Some(OpenVpnTlsVersion::V1_1)),
        "1.2" => Ok(Some(OpenVpnTlsVersion::V1_2)),
        "1.3" => Ok(Some(OpenVpnTlsVersion::V1_3)),
        _ => Err(OpenVpnTlsError::InvalidVersion(value.into())),
    }
}

pub fn resolve_tls_version_bounds(
    minimum: &str,
    maximum: &str,
) -> Result<(OpenVpnTlsVersion, Option<OpenVpnTlsVersion>), OpenVpnTlsError> {
    let minimum =
        parse_tls_version_token(minimum)?.unwrap_or(OpenVpnTlsVersion::V1_2);
    let maximum = parse_tls_version_token(maximum)?;
    if maximum.is_some_and(|maximum| maximum < minimum) {
        return Err(OpenVpnTlsError::MinAfterMax);
    }
    Ok((minimum, maximum))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateProfile {
    Legacy,
    Preferred,
    Insecure,
    SuiteB,
}

pub fn parse_tls_cert_profile(
    value: &str,
) -> Result<CertificateProfile, OpenVpnTlsError> {
    match value {
        "" | "legacy" => Ok(CertificateProfile::Legacy),
        "preferred" => Ok(CertificateProfile::Preferred),
        "insecure" => Ok(CertificateProfile::Insecure),
        "suiteb" => Ok(CertificateProfile::SuiteB),
        _ => Err(OpenVpnTlsError::InvalidCertificateProfile(value.into())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpenVpnTlsCipherSuite {
    pub openssl_name: &'static str,
    pub iana_name: &'static str,
    pub id: u16,
}

const TLS_CIPHER_SUITES: &[OpenVpnTlsCipherSuite] = &[
    suite("RC4-SHA", "TLS_RSA_WITH_RC4_128_SHA", 0x0005),
    suite("DES-CBC3-SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x000a),
    suite("AES128-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", 0x002f),
    suite("AES256-SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", 0x0035),
    suite("AES128-SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003c),
    suite(
        "AES128-GCM-SHA256",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009c,
    ),
    suite(
        "AES256-GCM-SHA384",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x009d,
    ),
    suite(
        "ECDHE-ECDSA-RC4-SHA",
        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        0xc007,
    ),
    suite(
        "ECDHE-ECDSA-AES128-SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc009,
    ),
    suite(
        "ECDHE-ECDSA-AES256-SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc00a,
    ),
    suite(
        "ECDHE-RSA-RC4-SHA",
        "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        0xc011,
    ),
    suite(
        "ECDHE-RSA-DES-CBC3-SHA",
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0xc012,
    ),
    suite(
        "ECDHE-RSA-AES128-SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc013,
    ),
    suite(
        "ECDHE-RSA-AES256-SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc014,
    ),
    suite(
        "ECDHE-ECDSA-AES128-SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc023,
    ),
    suite(
        "ECDHE-RSA-AES128-SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc027,
    ),
    suite(
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02b,
    ),
    suite(
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02c,
    ),
    suite(
        "ECDHE-RSA-AES128-GCM-SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc02f,
    ),
    suite(
        "ECDHE-RSA-AES256-GCM-SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xc030,
    ),
    suite(
        "ECDHE-RSA-CHACHA20-POLY1305",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca8,
    ),
    suite(
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9,
    ),
];

const fn suite(
    openssl_name: &'static str,
    iana_name: &'static str,
    id: u16,
) -> OpenVpnTlsCipherSuite {
    OpenVpnTlsCipherSuite {
        openssl_name,
        iana_name,
        id,
    }
}

pub fn lookup_tls_cipher_suite(
    value: &str,
) -> Result<OpenVpnTlsCipherSuite, OpenVpnTlsError> {
    TLS_CIPHER_SUITES
        .iter()
        .copied()
        .find(|suite| suite.openssl_name == value || suite.iana_name == value)
        .ok_or_else(|| OpenVpnTlsError::UnsupportedCipher(value.into()))
}

pub fn parse_tls_cipher_suites(
    value: &str,
) -> Result<Vec<OpenVpnTlsCipherSuite>, OpenVpnTlsError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = HashSet::new();
    let mut suites = Vec::new();
    for token in value.split(':') {
        if token.is_empty() {
            return Err(OpenVpnTlsError::EmptyCipher);
        }
        let suite = lookup_tls_cipher_suite(token)?;
        if seen.insert(suite.id) {
            suites.push(suite);
        }
    }
    Ok(suites)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenVpnTlsGroup {
    X25519,
    P256,
    P384,
    P521,
}

impl OpenVpnTlsGroup {
    fn openssl_name(self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }
}

pub fn parse_tls_groups(
    value: &str,
) -> Result<Vec<OpenVpnTlsGroup>, OpenVpnTlsError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = HashSet::new();
    let mut groups = Vec::new();
    for token in value.split(':') {
        let group = match token {
            "X25519" | "CURVE25519" => OpenVpnTlsGroup::X25519,
            "SECP256R1" | "PRIME256V1" | "P-256" | "NISTP256" => {
                OpenVpnTlsGroup::P256
            }
            "SECP384R1" | "P-384" | "NISTP384" => OpenVpnTlsGroup::P384,
            "SECP521R1" | "P-521" | "NISTP521" => OpenVpnTlsGroup::P521,
            _ => return Err(OpenVpnTlsError::UnsupportedGroup(token.into())),
        };
        if seen.insert(group) {
            groups.push(group);
        }
    }
    Ok(groups)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsMaterial {
    pub path: Option<PathBuf>,
    pub content: Vec<u8>,
}

impl TlsMaterial {
    pub fn from_pem(content: impl Into<Vec<u8>>) -> Self {
        Self {
            path: None,
            content: content.into(),
        }
    }

    pub fn load(&self) -> Result<Option<Vec<u8>>, OpenVpnTlsError> {
        if self.path.is_some() && !self.content.is_empty() {
            return Err(OpenVpnTlsError::MaterialSourceConflict);
        }
        if !self.content.is_empty() {
            return Ok(Some(self.content.clone()));
        }
        self.path
            .as_ref()
            .map(fs::read)
            .transpose()
            .map_err(|error| OpenVpnTlsError::Backend(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct OpenVpnTlsContextOptions {
    pub role: OpenVpnTlsRole,
    pub certificate_authority: TlsMaterial,
    pub certificate: TlsMaterial,
    pub key: TlsMaterial,
    pub peer_fingerprints: Vec<String>,
    pub verify_name: String,
    pub verify_name_type: String,
    pub crl_path: String,
    pub remote_certificate_ku: Vec<String>,
    pub remote_certificate_eku: String,
    pub remote_certificate_tls: String,
    pub ns_certificate_type: String,
    pub verify_client_certificate: VerifyClientCertMode,
    pub version_min: String,
    pub version_max: String,
    pub cipher: String,
    pub groups: String,
    pub certificate_profile: String,
}

impl OpenVpnTlsContextOptions {
    pub fn client() -> Self {
        Self {
            role: OpenVpnTlsRole::Client,
            certificate_authority: TlsMaterial::default(),
            certificate: TlsMaterial::default(),
            key: TlsMaterial::default(),
            peer_fingerprints: Vec::new(),
            verify_name: String::new(),
            verify_name_type: String::new(),
            crl_path: String::new(),
            remote_certificate_ku: Vec::new(),
            remote_certificate_eku: String::new(),
            remote_certificate_tls: String::new(),
            ns_certificate_type: String::new(),
            verify_client_certificate: VerifyClientCertMode::None,
            version_min: String::new(),
            version_max: String::new(),
            cipher: String::new(),
            groups: String::new(),
            certificate_profile: String::new(),
        }
    }

    pub fn server() -> Self {
        Self {
            role: OpenVpnTlsRole::Server,
            verify_client_certificate: VerifyClientCertMode::Require,
            ..Self::client()
        }
    }
}

pub fn build_openssl_tls_context(
    options: &OpenVpnTlsContextOptions,
) -> Result<SslContext, OpenVpnTlsError> {
    let ca = options.certificate_authority.load()?;
    let certificate = options.certificate.load()?;
    let key = options.key.load()?;
    let profile = parse_tls_cert_profile(&options.certificate_profile)?;
    let (minimum, maximum) =
        resolve_tls_version_bounds(&options.version_min, &options.version_max)?;
    let mut suites = parse_tls_cipher_suites(&options.cipher)?;
    if profile == CertificateProfile::SuiteB && suites.is_empty() {
        suites = vec![
            lookup_tls_cipher_suite("ECDHE-ECDSA-AES128-GCM-SHA256")?,
            lookup_tls_cipher_suite("ECDHE-ECDSA-AES256-GCM-SHA384")?,
        ];
    }
    let groups = parse_tls_groups(&options.groups)?;
    let required_key_usage =
        parse_remote_cert_key_usages(&options.remote_certificate_ku)
            .map_err(peer_verifier_error)?;
    let required_extended_usage =
        parse_remote_cert_extended_key_usage(&options.remote_certificate_eku)
            .map_err(peer_verifier_error)?;
    let remote_certificate_tls = match options.remote_certificate_tls.as_str() {
        "none" => "",
        value => value,
    };
    let (require_key_usage_extension, shorthand_extended_usage) =
        expand_remote_cert_tls(remote_certificate_tls)
            .map_err(peer_verifier_error)?;
    let required_extended_usage = merge_extended_key_usage(
        required_extended_usage,
        shorthand_extended_usage,
    );

    match options.role {
        OpenVpnTlsRole::Client => {
            if ca.is_none() && options.peer_fingerprints.is_empty() {
                return Err(OpenVpnTlsError::MissingCaOrFingerprint);
            }
        }
        OpenVpnTlsRole::Server => {
            if certificate.is_none() || key.is_none() {
                return Err(OpenVpnTlsError::ServerCertificateRequired);
            }
            if options.verify_client_certificate != VerifyClientCertMode::None
                && ca.is_none()
                && options.peer_fingerprints.is_empty()
            {
                return Err(OpenVpnTlsError::MissingCaOrFingerprint);
            }
        }
    }
    if certificate.is_some() != key.is_some() {
        return Err(OpenVpnTlsError::CertificateKeyPairRequired);
    }

    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).map_err(backend_error)?;
    // OpenVPN applies certificate profile checks itself. Keep OpenSSL's
    // transport layer permissive so legacy/suiteb policy is enforced once.
    builder.set_security_level(0);
    builder
        .set_min_proto_version(Some(minimum.openssl()))
        .map_err(backend_error)?;
    builder
        .set_max_proto_version(maximum.map(OpenVpnTlsVersion::openssl))
        .map_err(backend_error)?;
    if !suites.is_empty() {
        builder
            .set_cipher_list(
                &suites
                    .iter()
                    .map(|suite| suite.openssl_name)
                    .collect::<Vec<_>>()
                    .join(":"),
            )
            .map_err(backend_error)?;
    }
    if !groups.is_empty() {
        builder
            .set_groups_list(
                &groups
                    .iter()
                    .map(|group| group.openssl_name())
                    .collect::<Vec<_>>()
                    .join(":"),
            )
            .map_err(backend_error)?;
    }
    if let Some(ca) = ca {
        let roots = X509::stack_from_pem(&ca).map_err(backend_error)?;
        if roots.is_empty() {
            return Err(OpenVpnTlsError::InvalidCertificateAuthority);
        }
        for root in roots {
            builder
                .cert_store_mut()
                .add_cert(root)
                .map_err(backend_error)?;
        }
    }
    let has_ca = options.certificate_authority.load()?.is_some();
    if has_ca {
        let purpose = match options.role {
            OpenVpnTlsRole::Client => X509PurposeId::SSL_SERVER,
            OpenVpnTlsRole::Server => X509PurposeId::SSL_CLIENT,
        };
        builder
            .cert_store_mut()
            .set_purpose(purpose)
            .map_err(backend_error)?;
    }
    if !options.crl_path.is_empty() {
        let lookup = builder
            .cert_store_mut()
            .add_lookup(X509Lookup::file())
            .map_err(backend_error)?;
        if lookup
            .load_crl_file(&options.crl_path, SslFiletype::PEM)
            .is_err()
        {
            // OpenVPN retries an unrecognized PEM CRL as DER/ASN.1.
            lookup
                .load_crl_file(&options.crl_path, SslFiletype::ASN1)
                .map_err(backend_error)?;
        }
        builder
            .cert_store_mut()
            .set_flags(
                X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL,
            )
            .map_err(backend_error)?;
    }
    if let (Some(certificate), Some(key)) = (certificate, key) {
        let mut chain =
            X509::stack_from_pem(&certificate).map_err(backend_error)?;
        if chain.is_empty() {
            return Err(OpenVpnTlsError::InvalidCertificate);
        }
        let leaf = chain.remove(0);
        enforce_certificate_profile(&leaf, profile)
            .map_err(peer_verifier_error)?;
        builder.set_certificate(&leaf).map_err(backend_error)?;
        for intermediate in chain {
            enforce_certificate_profile(&intermediate, profile)
                .map_err(peer_verifier_error)?;
            builder
                .add_extra_chain_cert(intermediate)
                .map_err(backend_error)?;
        }
        let key = PKey::private_key_from_pem(&key).map_err(backend_error)?;
        builder.set_private_key(&key).map_err(backend_error)?;
        builder.check_private_key().map_err(backend_error)?;
    }

    let verifier = Arc::new(
        OpenVpnPeerVerifier::new(OpenVpnPeerVerifierOptions {
            purpose: match options.role {
                OpenVpnTlsRole::Client => CertificatePurpose::SslServer,
                OpenVpnTlsRole::Server => CertificatePurpose::SslClient,
            },
            verify_name: options.verify_name.clone(),
            verify_name_type: options.verify_name_type.clone(),
            peer_fingerprints: options.peer_fingerprints.clone(),
            required_key_usage,
            require_key_usage_extension,
            required_extended_usage,
            ns_certificate_type: options.ns_certificate_type.clone(),
            certificate_profile: profile,
            trust_store_present: has_ca,
        })
        .map_err(peer_verifier_error)?,
    );
    let verify_mode = match options.role {
        OpenVpnTlsRole::Client => SslVerifyMode::PEER,
        OpenVpnTlsRole::Server => match options.verify_client_certificate {
            VerifyClientCertMode::None => SslVerifyMode::NONE,
            VerifyClientCertMode::Optional => SslVerifyMode::PEER,
            VerifyClientCertMode::Require => {
                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
            }
        },
    };
    if verify_mode != SslVerifyMode::NONE {
        builder.set_verify_callback(
            verify_mode,
            move |preverified, context| {
                if !preverified && !verifier.fingerprint_only() {
                    return false;
                }
                let Some(certificate) = context.current_cert() else {
                    return false;
                };
                let depth = context.error_depth();
                verifier
                    .verify_chain_certificate(certificate, depth > 0)
                    .is_ok()
                    && (depth != 0
                        || verifier
                            .verify_peer_certificate(certificate)
                            .is_ok())
            },
        );
    }
    Ok(builder.build())
}

fn backend_error(error: openssl::error::ErrorStack) -> OpenVpnTlsError {
    OpenVpnTlsError::Backend(error.to_string())
}

fn peer_verifier_error(error: super::PeerCertificateError) -> OpenVpnTlsError {
    OpenVpnTlsError::PeerCertificate(error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenVpnTlsError {
    #[error("verify-client-cert must be none, optional, or require: {0}")]
    InvalidVerifyClientCert(String),
    #[error("unknown tls-version parameter: {0}")]
    InvalidVersion(String),
    #[error("tls-version-min bigger than tls-version-max")]
    MinAfterMax,
    #[error("unknown tls-cert-profile value: {0}")]
    InvalidCertificateProfile(String),
    #[error("tls-cipher contains an empty cipher suite")]
    EmptyCipher,
    #[error("unsupported tls-cipher name: {0}")]
    UnsupportedCipher(String),
    #[error("unsupported tls-groups name: {0}")]
    UnsupportedGroup(String),
    #[error("material path and content are both set")]
    MaterialSourceConflict,
    #[error("tls mode requires certificate-authority or peer-fingerprint")]
    MissingCaOrFingerprint,
    #[error("tls server requires certificate and key")]
    ServerCertificateRequired,
    #[error("certificate and key must both be set or both omitted")]
    CertificateKeyPairRequired,
    #[error("invalid certificate authority bundle")]
    InvalidCertificateAuthority,
    #[error("invalid certificate bundle")]
    InvalidCertificate,
    #[error("OpenSSL TLS backend: {0}")]
    Backend(String),
    #[error("peer certificate verifier: {0}")]
    PeerCertificate(String),
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;

    use openssl::sha::sha256;
    use openssl::ssl::Ssl;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_openssl::SslStream;

    use super::*;

    #[test]
    fn parses_version_profile_and_client_auth_modes() {
        assert_eq!(
            resolve_tls_version_bounds("", "").unwrap(),
            (OpenVpnTlsVersion::V1_2, None)
        );
        assert_eq!(
            resolve_tls_version_bounds("1.0", "1.1").unwrap(),
            (OpenVpnTlsVersion::V1_0, Some(OpenVpnTlsVersion::V1_1))
        );
        assert!(resolve_tls_version_bounds("1.3", "1.2").is_err());
        assert_eq!(
            parse_tls_cert_profile("").unwrap(),
            CertificateProfile::Legacy
        );
        assert_eq!(
            resolve_verify_client_cert_mode("").unwrap(),
            VerifyClientCertMode::Require
        );
        assert!(resolve_verify_client_cert_mode("yes").is_err());
    }

    #[test]
    fn translates_openssl_and_iana_cipher_names_and_deduplicates() {
        let suites = parse_tls_cipher_suites(
            "ECDHE-RSA-AES128-GCM-SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:ECDHE-ECDSA-CHACHA20-POLY1305",
        )
        .unwrap();
        assert_eq!(suites.len(), 2);
        assert_eq!(suites[0].id, 0xc02f);
        assert_eq!(suites[1].id, 0xcca9);
        assert!(parse_tls_cipher_suites("AES128-SHA:").is_err());
        assert!(parse_tls_cipher_suites("unknown").is_err());
    }

    #[test]
    fn normalizes_and_deduplicates_tls_groups() {
        assert_eq!(
            parse_tls_groups("CURVE25519:X25519:PRIME256V1:NISTP384").unwrap(),
            [
                OpenVpnTlsGroup::X25519,
                OpenVpnTlsGroup::P256,
                OpenVpnTlsGroup::P384
            ]
        );
        assert!(parse_tls_groups("x25519").is_err());
        assert!(parse_tls_groups("X25519:").is_err());
    }

    #[test]
    fn validates_material_and_role_requirements() {
        let client = OpenVpnTlsContextOptions::client();
        assert_eq!(
            build_openssl_tls_context(&client).unwrap_err(),
            OpenVpnTlsError::MissingCaOrFingerprint
        );
        let mut server = OpenVpnTlsContextOptions::server();
        server.verify_client_certificate = VerifyClientCertMode::None;
        assert_eq!(
            build_openssl_tls_context(&server).unwrap_err(),
            OpenVpnTlsError::ServerCertificateRequired
        );
        let material = TlsMaterial {
            path: Some("unused".into()),
            content: b"content".to_vec(),
        };
        assert_eq!(
            material.load().unwrap_err(),
            OpenVpnTlsError::MaterialSourceConflict
        );
    }

    #[tokio::test]
    async fn openssl_contexts_form_a_tls12_control_stream() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["openvpn.test".into()]).unwrap();
        let certificate = cert.pem().into_bytes();
        let key = key_pair.serialize_pem().into_bytes();
        let server = build_openssl_tls_context(&OpenVpnTlsContextOptions {
            role: OpenVpnTlsRole::Server,
            certificate: TlsMaterial::from_pem(certificate.clone()),
            key: TlsMaterial::from_pem(key),
            verify_client_certificate: VerifyClientCertMode::None,
            version_min: "1.2".into(),
            version_max: "1.2".into(),
            cipher: "ECDHE-ECDSA-AES128-GCM-SHA256".into(),
            ..OpenVpnTlsContextOptions::server()
        })
        .unwrap();
        let client = build_openssl_tls_context(&OpenVpnTlsContextOptions {
            certificate_authority: TlsMaterial::from_pem(certificate),
            version_min: "1.2".into(),
            version_max: "1.2".into(),
            cipher: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
            ..OpenVpnTlsContextOptions::client()
        })
        .unwrap();
        let (left, right) = tokio::io::duplex(16 * 1024);
        let mut client_stream =
            SslStream::new(Ssl::new(&client).unwrap(), left).unwrap();
        let mut server_stream =
            SslStream::new(Ssl::new(&server).unwrap(), right).unwrap();
        tokio::try_join!(
            Pin::new(&mut client_stream).connect(),
            Pin::new(&mut server_stream).accept()
        )
        .unwrap();
        client_stream.write_all(b"PUSH_REQUEST\0").await.unwrap();
        let mut record = [0_u8; 13];
        server_stream.read_exact(&mut record).await.unwrap();
        assert_eq!(&record, b"PUSH_REQUEST\0");
    }

    #[tokio::test]
    async fn peer_fingerprint_can_replace_a_ca_store() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["openvpn.test".into()]).unwrap();
        let certificate = cert.pem().into_bytes();
        let der = X509::from_pem(&certificate).unwrap().to_der().unwrap();
        let fingerprint = hex::encode(sha256(&der));
        let server = build_openssl_tls_context(&OpenVpnTlsContextOptions {
            role: OpenVpnTlsRole::Server,
            certificate: TlsMaterial::from_pem(certificate),
            key: TlsMaterial::from_pem(key_pair.serialize_pem()),
            verify_client_certificate: VerifyClientCertMode::None,
            ..OpenVpnTlsContextOptions::server()
        })
        .unwrap();
        let client = build_openssl_tls_context(&OpenVpnTlsContextOptions {
            peer_fingerprints: vec![fingerprint],
            ..OpenVpnTlsContextOptions::client()
        })
        .unwrap();
        let (left, right) = tokio::io::duplex(16 * 1024);
        let mut client_stream =
            SslStream::new(Ssl::new(&client).unwrap(), left).unwrap();
        let mut server_stream =
            SslStream::new(Ssl::new(&server).unwrap(), right).unwrap();
        tokio::try_join!(
            Pin::new(&mut client_stream).connect(),
            Pin::new(&mut server_stream).accept()
        )
        .unwrap();
    }
}
