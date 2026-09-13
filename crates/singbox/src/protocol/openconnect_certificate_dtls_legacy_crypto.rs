//! TLS 1.0 RSA and ECDHE_RSA key exchange for certificate DTLS 1.0.

use md5::{Digest as _, Md5};
use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    error::ErrorStack,
    memcmp,
    nid::Nid,
    pkey::{PKey, Private, Public},
    rsa::Padding,
    x509::X509,
};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha1_11::Sha1;
use thiserror::Error;

use super::{CERTIFICATE_DTLS10_VERSION, CertificateDtls10CipherSuite};

#[derive(Clone, PartialEq, Eq)]
pub struct CertificateDtls10KeyExchange {
    pub pre_master_secret: Vec<u8>,
    pub client_key_exchange: Vec<u8>,
}

impl std::fmt::Debug for CertificateDtls10KeyExchange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertificateDtls10KeyExchange")
            .field("pre_master_secret", &"[REDACTED]")
            .field("client_key_exchange", &self.client_key_exchange)
            .finish()
    }
}

impl Drop for CertificateDtls10KeyExchange {
    fn drop(&mut self) {
        self.pre_master_secret.fill(0);
        self.client_key_exchange.fill(0);
    }
}

#[derive(Debug, Error)]
pub enum CertificateDtls10CryptoError {
    #[error("parse certificate DTLS 1.0 server certificate: {0}")]
    Certificate(#[source] ErrorStack),
    #[error("certificate DTLS 1.0 requires an RSA server certificate")]
    RsaCertificateRequired,
    #[error("invalid certificate DTLS 1.0 ECDHE ServerKeyExchange")]
    InvalidServerKeyExchange,
    #[error("certificate DTLS 1.0 server selected unoffered curve {0}")]
    UnofferedCurve(u16),
    #[error("unsupported certificate DTLS 1.0 curve {0}")]
    UnsupportedCurve(u16),
    #[error("certificate DTLS 1.0 ECDHE ServerKeyExchange signature failed")]
    InvalidServerSignature,
    #[error("certificate DTLS 1.0 cryptographic operation failed: {0}")]
    Crypto(#[from] ErrorStack),
    #[error("generate certificate DTLS 1.0 secret: {0}")]
    Random(#[from] getrandom::Error),
    #[error("certificate DTLS 1.0 RSA ciphertext is too large")]
    CiphertextTooLarge,
    #[error("certificate DTLS 1.0 ECDHE public key is too large")]
    PublicKeyTooLarge,
    #[error("verify certificate DTLS 1.0 server certificate: {0}")]
    CertificateVerification(String),
    #[error("certificate DTLS 1.0 client identity has no certificate")]
    EmptyClientCertificate,
    #[error("certificate DTLS 1.0 client identity requires an RSA private key")]
    RsaClientKeyRequired,
    #[error(
        "certificate DTLS 1.0 client certificate does not match its private key"
    )]
    ClientKeyMismatch,
    #[error("certificate DTLS 1.0 client signature is too large")]
    SignatureTooLarge,
}

#[derive(Clone)]
pub struct CertificateDtls10ClientIdentity {
    pub certificate_chain: Vec<Vec<u8>>,
    pub private_key: PKey<Private>,
}

impl std::fmt::Debug for CertificateDtls10ClientIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertificateDtls10ClientIdentity")
            .field("certificate_chain", &self.certificate_chain)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl CertificateDtls10ClientIdentity {
    pub fn new(
        certificate_chain: Vec<Vec<u8>>,
        private_key: PKey<Private>,
    ) -> Result<Self, CertificateDtls10CryptoError> {
        let leaf = certificate_chain
            .first()
            .ok_or(CertificateDtls10CryptoError::EmptyClientCertificate)?;
        let certificate = X509::from_der(leaf)
            .map_err(CertificateDtls10CryptoError::Certificate)?;
        let public_key = certificate.public_key()?;
        private_key
            .rsa()
            .map_err(|_| CertificateDtls10CryptoError::RsaClientKeyRequired)?;
        if !public_key.public_eq(&private_key) {
            return Err(CertificateDtls10CryptoError::ClientKeyMismatch);
        }
        Ok(Self {
            certificate_chain,
            private_key,
        })
    }

    pub fn matches_acceptable_ca(&self, acceptable_cas: &[Vec<u8>]) -> bool {
        if acceptable_cas.is_empty() {
            return true;
        }
        self.certificate_chain.iter().any(|encoded| {
            X509::from_der(encoded)
                .ok()
                .and_then(|certificate| certificate.issuer_name().to_der().ok())
                .is_some_and(|issuer| acceptable_cas.contains(&issuer))
        })
    }

    pub fn sign_transcript(
        &self,
        transcript: &[u8],
    ) -> Result<Vec<u8>, CertificateDtls10CryptoError> {
        let rsa = self
            .private_key
            .rsa()
            .map_err(|_| CertificateDtls10CryptoError::RsaClientKeyRequired)?;
        let digest = legacy_md5_sha1(transcript);
        let mut signature = vec![0_u8; rsa.size() as usize];
        let length =
            rsa.private_encrypt(&digest, &mut signature, Padding::PKCS1)?;
        signature.truncate(length);
        let length = u16::try_from(signature.len())
            .map_err(|_| CertificateDtls10CryptoError::SignatureTooLarge)?;
        let mut body = Vec::with_capacity(2 + signature.len());
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(&signature);
        signature.fill(0);
        Ok(body)
    }
}

pub fn verify_certificate_dtls10_server_chain(
    raw_certificates: &[Vec<u8>],
    roots: &RootCertStore,
    server_name: &str,
    insecure_skip_verify: bool,
) -> Result<(), CertificateDtls10CryptoError> {
    let Some((leaf, intermediates)) = raw_certificates.split_first() else {
        return Err(CertificateDtls10CryptoError::CertificateVerification(
            "empty certificate chain".into(),
        ));
    };
    X509::from_der(leaf).map_err(CertificateDtls10CryptoError::Certificate)?;
    if insecure_skip_verify {
        return Ok(());
    }
    let server_name =
        ServerName::try_from(server_name.to_owned()).map_err(|error| {
            CertificateDtls10CryptoError::CertificateVerification(
                error.to_string(),
            )
        })?;
    let verifier = WebPkiServerVerifier::builder(roots.clone().into())
        .build()
        .map_err(|error| {
            CertificateDtls10CryptoError::CertificateVerification(
                error.to_string(),
            )
        })?;
    let leaf = CertificateDer::from(leaf.clone());
    let intermediates: Vec<_> = intermediates
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect();
    verifier
        .verify_server_cert(
            &leaf,
            &intermediates,
            &server_name,
            &[],
            UnixTime::now(),
        )
        .map_err(|error| {
            CertificateDtls10CryptoError::CertificateVerification(
                error.to_string(),
            )
        })?;
    Ok(())
}

/// Build the TLS 1.0 ClientKeyExchange and its premaster secret.
///
/// ECDHE_RSA validates the legacy RSA MD5+SHA1 signature over both randoms and
/// the named-curve parameters before deriving the shared secret. Plain RSA
/// encrypts a fresh 48-byte DTLS-version-prefixed secret with PKCS#1 v1.5.
pub fn build_certificate_dtls10_key_exchange(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    leaf_certificate_der: &[u8],
    server_key_exchange: &[u8],
    suite: CertificateDtls10CipherSuite,
    offered_curves: &[u16],
) -> Result<CertificateDtls10KeyExchange, CertificateDtls10CryptoError> {
    let certificate = X509::from_der(leaf_certificate_der)
        .map_err(CertificateDtls10CryptoError::Certificate)?;
    let public_key = certificate.public_key()?;
    let rsa = public_key
        .rsa()
        .map_err(|_| CertificateDtls10CryptoError::RsaCertificateRequired)?;
    if !suite.ecdhe {
        if !server_key_exchange.is_empty() {
            return Err(CertificateDtls10CryptoError::InvalidServerKeyExchange);
        }
        let mut pre_master_secret = vec![0_u8; 48];
        pre_master_secret[..2]
            .copy_from_slice(&CERTIFICATE_DTLS10_VERSION.to_be_bytes());
        getrandom::fill(&mut pre_master_secret[2..])?;
        let mut encrypted = vec![0_u8; rsa.size() as usize];
        let length = rsa.public_encrypt(
            &pre_master_secret,
            &mut encrypted,
            Padding::PKCS1,
        )?;
        encrypted.truncate(length);
        let encrypted_length = u16::try_from(encrypted.len())
            .map_err(|_| CertificateDtls10CryptoError::CiphertextTooLarge)?;
        let mut client_key_exchange = Vec::with_capacity(2 + encrypted.len());
        client_key_exchange.extend_from_slice(&encrypted_length.to_be_bytes());
        client_key_exchange.extend_from_slice(&encrypted);
        encrypted.fill(0);
        return Ok(CertificateDtls10KeyExchange {
            pre_master_secret,
            client_key_exchange,
        });
    }

    if server_key_exchange.len() < 6 || server_key_exchange[0] != 3 {
        return Err(CertificateDtls10CryptoError::InvalidServerKeyExchange);
    }
    let curve_id =
        u16::from_be_bytes([server_key_exchange[1], server_key_exchange[2]]);
    if !offered_curves.contains(&curve_id) {
        return Err(CertificateDtls10CryptoError::UnofferedCurve(curve_id));
    }
    let group = EcGroup::from_curve_name(curve_nid(curve_id)?)?;
    let public_length = usize::from(server_key_exchange[3]);
    let parameters_length = 4_usize
        .checked_add(public_length)
        .ok_or(CertificateDtls10CryptoError::InvalidServerKeyExchange)?;
    if public_length == 0 || server_key_exchange.len() < parameters_length + 2 {
        return Err(CertificateDtls10CryptoError::InvalidServerKeyExchange);
    }
    let signature_length = usize::from(u16::from_be_bytes([
        server_key_exchange[parameters_length],
        server_key_exchange[parameters_length + 1],
    ]));
    if signature_length == 0
        || server_key_exchange.len() != parameters_length + 2 + signature_length
    {
        return Err(CertificateDtls10CryptoError::InvalidServerKeyExchange);
    }
    let mut signed_input = Vec::with_capacity(64 + parameters_length);
    signed_input.extend_from_slice(client_random);
    signed_input.extend_from_slice(server_random);
    signed_input.extend_from_slice(&server_key_exchange[..parameters_length]);
    let digest = legacy_md5_sha1(&signed_input);
    signed_input.fill(0);
    let signature = &server_key_exchange[parameters_length + 2..];
    let mut recovered = vec![0_u8; rsa.size() as usize];
    let recovered_length = rsa
        .public_decrypt(signature, &mut recovered, Padding::PKCS1)
        .map_err(|_| CertificateDtls10CryptoError::InvalidServerSignature)?;
    recovered.truncate(recovered_length);
    if !memcmp::eq(&recovered, &digest) {
        recovered.fill(0);
        return Err(CertificateDtls10CryptoError::InvalidServerSignature);
    }
    recovered.fill(0);

    let mut context = BigNumContext::new()?;
    let peer_point = EcPoint::from_bytes(
        &group,
        &server_key_exchange[4..parameters_length],
        &mut context,
    )?;
    let peer_ec_key = EcKey::from_public_key(&group, &peer_point)?;
    let peer_key: PKey<Public> = PKey::from_ec_key(peer_ec_key)?;
    let client_ec_key = EcKey::generate(&group)?;
    let client_public = client_ec_key.public_key().to_bytes(
        &group,
        PointConversionForm::UNCOMPRESSED,
        &mut context,
    )?;
    let public_length = u8::try_from(client_public.len())
        .map_err(|_| CertificateDtls10CryptoError::PublicKeyTooLarge)?;
    let client_key = PKey::from_ec_key(client_ec_key)?;
    let mut deriver = Deriver::new(&client_key)?;
    deriver.set_peer(&peer_key)?;
    let pre_master_secret = deriver.derive_to_vec()?;
    let mut client_key_exchange = Vec::with_capacity(1 + client_public.len());
    client_key_exchange.push(public_length);
    client_key_exchange.extend_from_slice(&client_public);
    Ok(CertificateDtls10KeyExchange {
        pre_master_secret,
        client_key_exchange,
    })
}

pub fn certificate_dtls10_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    super::tls10_prf(pre_master_secret, "master secret", &seed, 48)
}

pub fn certificate_dtls10_finished(
    master_secret: &[u8],
    label: &str,
    transcript: &[u8],
) -> Vec<u8> {
    super::tls10_prf(master_secret, label, &legacy_md5_sha1(transcript), 12)
}

fn legacy_md5_sha1(content: &[u8]) -> Vec<u8> {
    let mut digest = Md5::digest(content).to_vec();
    digest.extend_from_slice(&Sha1::digest(content));
    digest
}

fn curve_nid(curve_id: u16) -> Result<Nid, CertificateDtls10CryptoError> {
    match curve_id {
        23 => Ok(Nid::X9_62_PRIME256V1),
        24 => Ok(Nid::SECP384R1),
        25 => Ok(Nid::SECP521R1),
        _ => Err(CertificateDtls10CryptoError::UnsupportedCurve(curve_id)),
    }
}

#[cfg(test)]
mod tests {
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::{PKey, Private},
        rsa::Rsa,
        x509::{X509NameBuilder, extension::SubjectAlternativeName},
    };

    use super::*;

    fn certificate() -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "vpn.example").unwrap();
        let name = name.build();
        let mut serial = BigNum::new().unwrap();
        serial
            .rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .unwrap();
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
        let san = SubjectAlternativeName::new()
            .dns("vpn.example")
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(san).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    #[test]
    fn rsa_key_exchange_decrypts_to_version_prefixed_secret() {
        let (certificate, key) = certificate();
        let exchange = build_certificate_dtls10_key_exchange(
            &[1; 32],
            &[2; 32],
            &certificate.to_der().unwrap(),
            &[],
            CertificateDtls10CipherSuite::from_id(
                super::super::TLS_RSA_WITH_AES_128_CBC_SHA,
            )
            .unwrap(),
            &[23],
        )
        .unwrap();
        let encrypted_length = usize::from(u16::from_be_bytes([
            exchange.client_key_exchange[0],
            exchange.client_key_exchange[1],
        ]));
        assert_eq!(encrypted_length, exchange.client_key_exchange.len() - 2);
        let mut decrypted = vec![0; key.rsa().unwrap().size() as usize];
        let length = key
            .rsa()
            .unwrap()
            .private_decrypt(
                &exchange.client_key_exchange[2..],
                &mut decrypted,
                Padding::PKCS1,
            )
            .unwrap();
        decrypted.truncate(length);
        assert_eq!(decrypted, exchange.pre_master_secret);
        assert_eq!(&decrypted[..2], &[0xfe, 0xff]);
    }

    #[test]
    fn ecdhe_rsa_exchange_verifies_signature_and_derives_same_secret() {
        let (certificate, rsa_key) = certificate();
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let server_ec = EcKey::generate(&group).unwrap();
        let mut context = BigNumContext::new().unwrap();
        let server_public = server_ec
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut context)
            .unwrap();
        let client_random = [1; 32];
        let server_random = [2; 32];
        let mut key_exchange = vec![3, 0, 23, server_public.len() as u8];
        key_exchange.extend_from_slice(&server_public);
        let mut signed = Vec::new();
        signed.extend_from_slice(&client_random);
        signed.extend_from_slice(&server_random);
        signed.extend_from_slice(&key_exchange);
        let digest = legacy_md5_sha1(&signed);
        let rsa = rsa_key.rsa().unwrap();
        let mut signature = vec![0; rsa.size() as usize];
        let signature_length = rsa
            .private_encrypt(&digest, &mut signature, Padding::PKCS1)
            .unwrap();
        signature.truncate(signature_length);
        key_exchange.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        key_exchange.extend_from_slice(&signature);
        let exchange = build_certificate_dtls10_key_exchange(
            &client_random,
            &server_random,
            &certificate.to_der().unwrap(),
            &key_exchange,
            CertificateDtls10CipherSuite::from_id(
                super::super::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            )
            .unwrap(),
            &[23],
        )
        .unwrap();
        let client_point = EcPoint::from_bytes(
            &group,
            &exchange.client_key_exchange[1..],
            &mut context,
        )
        .unwrap();
        let client_public = PKey::from_ec_key(
            EcKey::from_public_key(&group, &client_point).unwrap(),
        )
        .unwrap();
        let server_key = PKey::from_ec_key(server_ec).unwrap();
        let mut deriver = Deriver::new(&server_key).unwrap();
        deriver.set_peer(&client_public).unwrap();
        assert_eq!(
            deriver.derive_to_vec().unwrap(),
            exchange.pre_master_secret
        );
    }

    #[test]
    fn ecdhe_rejects_tampered_signature_and_unoffered_curve() {
        let (certificate, _) = certificate();
        let suite = CertificateDtls10CipherSuite::from_id(
            super::super::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        )
        .unwrap();
        let malformed = [3, 0, 23, 1, 4, 0, 1, 0];
        assert!(matches!(
            build_certificate_dtls10_key_exchange(
                &[1; 32],
                &[2; 32],
                &certificate.to_der().unwrap(),
                &malformed,
                suite,
                &[24],
            ),
            Err(CertificateDtls10CryptoError::UnofferedCurve(23))
        ));
    }

    #[test]
    fn master_secret_and_finished_have_tls10_lengths() {
        let master =
            certificate_dtls10_master_secret(&[3; 48], &[1; 32], &[2; 32]);
        assert_eq!(master.len(), 48);
        assert_eq!(
            certificate_dtls10_finished(&master, "client finished", b"flight")
                .len(),
            12
        );
    }

    #[test]
    fn client_identity_matches_ca_and_signs_legacy_transcript() {
        let (certificate, key) = certificate();
        let issuer = certificate.issuer_name().to_der().unwrap();
        let identity = CertificateDtls10ClientIdentity::new(
            vec![certificate.to_der().unwrap()],
            key.clone(),
        )
        .unwrap();
        assert!(identity.matches_acceptable_ca(&[issuer]));
        assert!(!identity.matches_acceptable_ca(&[b"different".to_vec()]));
        let transcript = b"certificate handshake transcript";
        let body = identity.sign_transcript(transcript).unwrap();
        let signature_length =
            usize::from(u16::from_be_bytes([body[0], body[1]]));
        assert_eq!(signature_length, body.len() - 2);
        let rsa = key.rsa().unwrap();
        let mut recovered = vec![0_u8; rsa.size() as usize];
        let length = rsa
            .public_decrypt(&body[2..], &mut recovered, Padding::PKCS1)
            .unwrap();
        recovered.truncate(length);
        assert_eq!(recovered, legacy_md5_sha1(transcript));
    }
}
