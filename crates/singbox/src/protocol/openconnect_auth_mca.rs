//! AnyConnect multiple-certificate authentication (MCA) wire compatibility.
//!
//! The gateway's raw XML challenge is signed exactly as received. Certificate
//! chains use a degenerate PKCS#7 SignedData object, matching OpenConnect and
//! `sing-openconnect` rather than a TLS certificate-list encoding.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::{
    hash::MessageDigest,
    pkcs7::{Pkcs7, Pkcs7Flags},
    pkey::{Id, PKey, Private},
    sign::{Signer, Verifier},
    stack::Stack,
    x509::X509,
};
use thiserror::Error;

use super::{
    AnyConnectAuthClientIdentity, AnyConnectAuthError, AnyConnectAuthForm,
    auth::{
        auth_writer, write_capabilities, write_end, write_identity,
        write_opaque, write_root_start, write_start, write_text,
    },
};

#[derive(Clone, PartialEq, Eq)]
pub enum AnyConnectMcaPrivateKey {
    Pem(Vec<u8>),
    Der(Vec<u8>),
}

impl fmt::Debug for AnyConnectMcaPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (format, length) = match self {
            Self::Pem(value) => ("Pem", value.len()),
            Self::Der(value) => ("Der", value.len()),
        };
        formatter
            .debug_struct("AnyConnectMcaPrivateKey")
            .field("format", &format)
            .field("length", &length)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyConnectMcaIdentity {
    /// Leaf certificate first, followed by any intermediate certificates.
    pub certificates_der: Vec<Vec<u8>>,
    pub private_key: AnyConnectMcaPrivateKey,
    /// Password for an encrypted PEM or PKCS#8 DER private key.
    pub private_key_password: Option<Vec<u8>>,
}

#[derive(Debug, Error)]
pub enum AnyConnectMcaError {
    #[error("multiple-certificate authentication requires an MCA identity")]
    MissingIdentity,
    #[error("multiple-certificate request omitted the raw challenge response")]
    MissingChallenge,
    #[error("MCA identity has no certificates")]
    MissingCertificates,
    #[error("parse AnyConnect MCA certificate {index}: {source}")]
    InvalidCertificate {
        index: usize,
        source: openssl::error::ErrorStack,
    },
    #[error("parse AnyConnect MCA private key: {0}")]
    InvalidPrivateKey(openssl::error::ErrorStack),
    #[error("AnyConnect MCA private key does not match the leaf certificate")]
    KeyMismatch,
    #[error("unsupported AnyConnect MCA signing key type")]
    UnsupportedKey,
    #[error("MCA signature hash negotiation failed; gateway offered: {0}")]
    HashNegotiation(String),
    #[error("generate AnyConnect MCA {algorithm} signature: {source}")]
    Sign {
        algorithm: &'static str,
        source: openssl::error::ErrorStack,
    },
    #[error("verify AnyConnect MCA {algorithm} signature: {source}")]
    Verify {
        algorithm: &'static str,
        source: openssl::error::ErrorStack,
    },
    #[error("generated AnyConnect MCA {0} signature failed verification")]
    InvalidSignature(&'static str),
    #[error("marshal AnyConnect MCA PKCS#7 certificate chain: {0}")]
    Pkcs7(openssl::error::ErrorStack),
    #[error(transparent)]
    Xml(#[from] AnyConnectAuthError),
}

/// Build the XMLPOST MCA response for a gateway challenge.
pub fn build_anyconnect_mca_response(
    identity: &AnyConnectAuthClientIdentity,
    mca_identity: Option<&AnyConnectMcaIdentity>,
    form: &AnyConnectAuthForm,
) -> Result<Vec<u8>, AnyConnectMcaError> {
    let mca_identity =
        mca_identity.ok_or(AnyConnectMcaError::MissingIdentity)?;
    if form.raw_response.is_empty() {
        return Err(AnyConnectMcaError::MissingChallenge);
    }
    let certificates = parse_certificates(mca_identity)?;
    let private_key = parse_private_key(mca_identity)?;
    let leaf_public_key = certificates[0]
        .public_key()
        .map_err(AnyConnectMcaError::InvalidPrivateKey)?;
    if !private_key.public_eq(&leaf_public_key) {
        return Err(AnyConnectMcaError::KeyMismatch);
    }
    if !matches!(private_key.id(), Id::RSA | Id::EC) {
        return Err(AnyConnectMcaError::UnsupportedKey);
    }

    let certificate_data = marshal_certificates(&certificates, &private_key)?;
    let (hash_name, signature) = sign_challenge(
        &private_key,
        &form.multiple_certificate_hash_methods,
        &form.raw_response,
    )?;
    let encoded_certificates = wrapped_base64(&certificate_data);
    let encoded_signature = wrapped_base64(&signature);

    let mut writer = auth_writer();
    write_root_start(&mut writer, "auth-reply")?;
    write_identity(&mut writer, identity)?;
    write_capabilities(&mut writer, identity)?;
    write_text(&mut writer, "session-token", "", &[])?;
    write_text(&mut writer, "session-id", "", &[])?;
    if let Some(opaque) = &form.opaque {
        write_opaque(&mut writer, opaque)?;
    }
    write_start(&mut writer, "auth", &[])?;
    write_start(&mut writer, "client-cert-chain", &[("cert-store", "1M")])?;
    write_text(&mut writer, "client-cert-sent-via-protocol", "", &[])?;
    write_end(&mut writer, "client-cert-chain")?;
    write_start(&mut writer, "client-cert-chain", &[("cert-store", "1U")])?;
    write_text(
        &mut writer,
        "client-cert",
        &encoded_certificates,
        &[("cert-format", "pkcs7")],
    )?;
    write_text(
        &mut writer,
        "client-cert-auth-signature",
        &encoded_signature,
        &[("hash-algorithm-chosen", hash_name)],
    )?;
    write_end(&mut writer, "client-cert-chain")?;
    write_end(&mut writer, "auth")?;
    write_end(&mut writer, "config-auth")?;
    Ok(writer.into_inner())
}

fn parse_certificates(
    identity: &AnyConnectMcaIdentity,
) -> Result<Vec<X509>, AnyConnectMcaError> {
    if identity.certificates_der.is_empty() {
        return Err(AnyConnectMcaError::MissingCertificates);
    }
    identity
        .certificates_der
        .iter()
        .enumerate()
        .map(|(index, der)| {
            X509::from_der(der).map_err(|source| {
                AnyConnectMcaError::InvalidCertificate { index, source }
            })
        })
        .collect()
}

fn parse_private_key(
    identity: &AnyConnectMcaIdentity,
) -> Result<PKey<Private>, AnyConnectMcaError> {
    let password = identity.private_key_password.as_deref();
    let result = match (&identity.private_key, password) {
        (AnyConnectMcaPrivateKey::Pem(value), Some(password)) => {
            PKey::private_key_from_pem_passphrase(value, password)
        }
        (AnyConnectMcaPrivateKey::Pem(value), None) => {
            PKey::private_key_from_pem(value)
        }
        (AnyConnectMcaPrivateKey::Der(value), Some(password)) => {
            PKey::private_key_from_pkcs8_passphrase(value, password)
        }
        (AnyConnectMcaPrivateKey::Der(value), None) => {
            PKey::private_key_from_der(value)
                .or_else(|_| PKey::private_key_from_pkcs8(value))
        }
    };
    result.map_err(AnyConnectMcaError::InvalidPrivateKey)
}

fn marshal_certificates(
    certificates: &[X509],
    private_key: &PKey<Private>,
) -> Result<Vec<u8>, AnyConnectMcaError> {
    let mut additional = Stack::new().map_err(AnyConnectMcaError::Pkcs7)?;
    for certificate in &certificates[1..] {
        additional
            .push(certificate.clone())
            .map_err(AnyConnectMcaError::Pkcs7)?;
    }
    let flags = Pkcs7Flags::NOSIGS | Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY;
    Pkcs7::sign(&certificates[0], private_key, &additional, &[], flags)
        .and_then(|value| value.to_der())
        .map_err(AnyConnectMcaError::Pkcs7)
}

fn sign_challenge(
    private_key: &PKey<Private>,
    offered_methods: &[String],
    challenge: &[u8],
) -> Result<(&'static str, Vec<u8>), AnyConnectMcaError> {
    type DigestFactory = fn() -> MessageDigest;
    const HASHES: [(&str, DigestFactory); 3] = [
        ("sha512", MessageDigest::sha512),
        ("sha384", MessageDigest::sha384),
        ("sha256", MessageDigest::sha256),
    ];
    for (name, digest) in HASHES {
        if !offered_methods
            .iter()
            .any(|offered| offered.trim().eq_ignore_ascii_case(name))
        {
            continue;
        }
        let mut signer =
            Signer::new(digest(), private_key).map_err(|source| {
                AnyConnectMcaError::Sign {
                    algorithm: name,
                    source,
                }
            })?;
        signer.update(challenge).map_err(|source| {
            AnyConnectMcaError::Sign {
                algorithm: name,
                source,
            }
        })?;
        let signature = signer.sign_to_vec().map_err(|source| {
            AnyConnectMcaError::Sign {
                algorithm: name,
                source,
            }
        })?;
        let mut verifier =
            Verifier::new(digest(), private_key).map_err(|source| {
                AnyConnectMcaError::Verify {
                    algorithm: name,
                    source,
                }
            })?;
        verifier.update(challenge).map_err(|source| {
            AnyConnectMcaError::Verify {
                algorithm: name,
                source,
            }
        })?;
        if !verifier.verify(&signature).map_err(|source| {
            AnyConnectMcaError::Verify {
                algorithm: name,
                source,
            }
        })? {
            return Err(AnyConnectMcaError::InvalidSignature(name));
        }
        return Ok((name, signature));
    }
    Err(AnyConnectMcaError::HashNegotiation(
        offered_methods.join(", "),
    ))
}

fn wrapped_base64(content: &[u8]) -> String {
    let encoded = STANDARD.encode(content);
    encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
        sign::Verifier,
        x509::{X509, X509NameBuilder},
    };
    use quick_xml::{Reader, events::Event};

    use super::*;

    fn certificate_and_key(ec: bool) -> (Vec<u8>, Vec<u8>) {
        let key = if ec {
            let group =
                EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
        } else {
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
        };
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "MCA test").unwrap();
        let name = name.build();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        let serial = serial.to_asn1_integer().unwrap();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        (
            builder.build().to_der().unwrap(),
            key.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    fn form() -> AnyConnectAuthForm {
        AnyConnectAuthForm {
            raw_response: b"<config-auth><auth><multiple-cert-auth hash-algorithm=\"sha256,sha512\"/></auth></config-auth>".to_vec(),
            multiple_certificate_hash_methods: vec!["sha256".into(), " SHA512 ".into()],
            opaque: Some(super::super::AnyConnectOpaque {
                name: "opaque".into(),
                attributes: vec![("id".into(), "7".into())],
                inner_xml: "<t>state</t>".into(),
            }),
            ..Default::default()
        }
    }

    fn identity(certificate: Vec<u8>, key: Vec<u8>) -> AnyConnectMcaIdentity {
        AnyConnectMcaIdentity {
            certificates_der: vec![certificate],
            private_key: AnyConnectMcaPrivateKey::Pem(key),
            private_key_password: None,
        }
    }

    fn xml_values(xml: &[u8]) -> (String, String, String) {
        let mut reader = Reader::from_reader(xml);
        let mut current = Vec::new();
        let mut hash = String::new();
        let mut certificate = String::new();
        let mut signature = String::new();
        loop {
            match reader.read_event().unwrap() {
                Event::Start(start) => {
                    current = start.name().as_ref().to_vec();
                    if current == b"client-cert-auth-signature" {
                        for attribute in start.attributes() {
                            let attribute = attribute.unwrap();
                            if attribute.key.as_ref()
                                == b"hash-algorithm-chosen"
                            {
                                hash = std::str::from_utf8(
                                    attribute.value.as_ref(),
                                )
                                .unwrap()
                                .to_owned();
                            }
                        }
                    }
                }
                Event::Text(text) if current == b"client-cert" => {
                    certificate = text.decode().unwrap().into_owned();
                }
                Event::Text(text)
                    if current == b"client-cert-auth-signature" =>
                {
                    signature = text.decode().unwrap().into_owned();
                }
                Event::Eof => break,
                _ => {}
            }
        }
        (hash, certificate, signature)
    }

    #[test]
    fn rsa_response_prefers_sha512_and_contains_degenerate_pkcs7() {
        let (certificate, key) = certificate_and_key(false);
        let response = build_anyconnect_mca_response(
            &AnyConnectAuthClientIdentity {
                version: "5.1".into(),
                reported_os: "linux-64".into(),
                multiple_certificate_authentication: true,
                ..Default::default()
            },
            Some(&identity(certificate.clone(), key)),
            &form(),
        )
        .unwrap();
        let xml = String::from_utf8_lossy(&response);
        assert!(xml.contains("cert-store=\"1M\""));
        assert!(xml.contains("<opaque id=\"7\"><t>state</t></opaque>"));
        let (hash, encoded_pkcs7, encoded_signature) = xml_values(&response);
        assert_eq!(hash, "sha512");
        assert!(encoded_pkcs7.lines().all(|line| line.len() <= 64));
        let der = STANDARD.decode(encoded_pkcs7.replace('\n', "")).unwrap();
        let pkcs7 = Pkcs7::from_der(&der).unwrap();
        let certificates = pkcs7.signed().unwrap().certificates().unwrap();
        assert_eq!(certificates.len(), 1);
        assert_eq!(certificates[0].to_der().unwrap(), certificate);
        let public_key = certificates[0].public_key().unwrap();
        let mut verifier =
            Verifier::new(MessageDigest::sha512(), &public_key).unwrap();
        verifier.update(&form().raw_response).unwrap();
        let signature = STANDARD
            .decode(encoded_signature.replace('\n', ""))
            .unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }

    #[test]
    fn ecdsa_response_uses_der_signature() {
        let (certificate, key) = certificate_and_key(true);
        let response = build_anyconnect_mca_response(
            &AnyConnectAuthClientIdentity::default(),
            Some(&identity(certificate, key)),
            &AnyConnectAuthForm {
                multiple_certificate_hash_methods: vec!["sha256".into()],
                ..form()
            },
        )
        .unwrap();
        let (hash, _, signature) = xml_values(&response);
        assert_eq!(hash, "sha256");
        assert_eq!(
            STANDARD.decode(signature.replace('\n', "")).unwrap()[0],
            0x30
        );
    }

    #[test]
    fn rejects_no_common_hash_and_key_mismatch() {
        let (certificate, key) = certificate_and_key(false);
        let mut request = form();
        request.multiple_certificate_hash_methods = vec!["sha1".into()];
        assert!(matches!(
            build_anyconnect_mca_response(
                &AnyConnectAuthClientIdentity::default(),
                Some(&identity(certificate.clone(), key)),
                &request,
            ),
            Err(AnyConnectMcaError::HashNegotiation(_))
        ));
        let (_, other_key) = certificate_and_key(false);
        assert!(matches!(
            build_anyconnect_mca_response(
                &AnyConnectAuthClientIdentity::default(),
                Some(&identity(certificate, other_key)),
                &form(),
            ),
            Err(AnyConnectMcaError::KeyMismatch)
        ));
    }
}
