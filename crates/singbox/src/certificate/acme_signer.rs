//! ACME account-key parsing and JOSE signing beyond instant-acme's P-256 key.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    bn::{BigNum, BigNumContext, BigNumRef},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private},
    sign::Signer,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Algorithm {
    Rs256,
    Es256,
    Es384,
    Es512,
    EdDsa,
}

impl Algorithm {
    fn jose_name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::EdDsa => "EdDSA",
        }
    }

    fn digest(self) -> Option<MessageDigest> {
        match self {
            Self::Rs256 | Self::Es256 => Some(MessageDigest::sha256()),
            Self::Es384 => Some(MessageDigest::sha384()),
            Self::Es512 => Some(MessageDigest::sha512()),
            Self::EdDsa => None,
        }
    }

    fn coordinate_size(self) -> Option<usize> {
        match self {
            Self::Es256 => Some(32),
            Self::Es384 => Some(48),
            Self::Es512 => Some(66),
            _ => None,
        }
    }
}

/// An OpenSSL-backed ACME account signer matching the key types accepted by
/// certmagic's `PEMDecodePrivateKey`: RSA, NIST ECDSA, and Ed25519.
pub(super) struct AcmeAccountSigner {
    key: PKey<Private>,
    algorithm: Algorithm,
    jwk: Value,
    thumbprint: String,
    pkcs8: Vec<u8>,
}

impl AcmeAccountSigner {
    pub(super) fn from_pem(encoded: &str) -> Result<Self, BoxError> {
        let key = PKey::private_key_from_pem(encoded.as_bytes())?;
        Self::from_key(key)
    }

    pub(super) fn from_pkcs8(encoded: &[u8]) -> Result<Self, BoxError> {
        let key = PKey::private_key_from_der(encoded)?;
        Self::from_key(key)
    }

    fn from_key(key: PKey<Private>) -> Result<Self, BoxError> {
        let (algorithm, jwk, canonical_thumbprint) = match key.id() {
            Id::RSA => {
                let rsa = key.rsa()?;
                let exponent = base64_integer(rsa.e());
                let modulus = base64_integer(rsa.n());
                (
                    Algorithm::Rs256,
                    json!({
                        "e": exponent,
                        "kty": "RSA",
                        "n": modulus,
                    }),
                    format!(
                        "{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}",
                        base64_integer(rsa.e()),
                        base64_integer(rsa.n()),
                    ),
                )
            }
            Id::EC => {
                let ec = key.ec_key()?;
                let (algorithm, curve) = match ec.group().curve_name() {
                    Some(Nid::X9_62_PRIME256V1) => (Algorithm::Es256, "P-256"),
                    Some(Nid::SECP384R1) => (Algorithm::Es384, "P-384"),
                    Some(Nid::SECP521R1) => (Algorithm::Es512, "P-521"),
                    curve => {
                        return Err(format!(
                            "unsupported ACME ECDSA account-key curve: {curve:?}"
                        )
                        .into());
                    }
                };
                let coordinate_size =
                    algorithm.coordinate_size().expect("ECDSA coordinate size");
                let mut context = BigNumContext::new()?;
                let mut x = BigNum::new()?;
                let mut y = BigNum::new()?;
                ec.public_key().affine_coordinates_gfp(
                    ec.group(),
                    &mut x,
                    &mut y,
                    &mut context,
                )?;
                let x = URL_SAFE_NO_PAD
                    .encode(padded_integer(&x, coordinate_size)?);
                let y = URL_SAFE_NO_PAD
                    .encode(padded_integer(&y, coordinate_size)?);
                (
                    algorithm,
                    json!({
                        "crv": curve,
                        "kty": "EC",
                        "x": x,
                        "y": y,
                    }),
                    format!(
                        "{{\"crv\":\"{curve}\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}"
                    ),
                )
            }
            Id::ED25519 => {
                let public = URL_SAFE_NO_PAD.encode(key.raw_public_key()?);
                (
                    Algorithm::EdDsa,
                    json!({
                        "crv": "Ed25519",
                        "kty": "OKP",
                        "x": public,
                    }),
                    format!(
                        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{public}\"}}"
                    ),
                )
            }
            kind => {
                return Err(format!(
                    "unsupported ACME account-key type: {}",
                    kind.as_raw()
                )
                .into());
            }
        };
        let thumbprint = URL_SAFE_NO_PAD
            .encode(Sha256::digest(canonical_thumbprint.as_bytes()));
        let pkcs8 = key.private_key_to_pkcs8()?;
        Ok(Self {
            key,
            algorithm,
            jwk,
            thumbprint,
            pkcs8,
        })
    }

    pub(super) fn algorithm(&self) -> &'static str {
        self.algorithm.jose_name()
    }

    pub(super) fn jwk(&self) -> &Value {
        &self.jwk
    }

    pub(super) fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    pub(super) fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    pub(super) fn is_p256(&self) -> bool {
        self.algorithm == Algorithm::Es256
    }

    pub(super) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, BoxError> {
        let signature = match self.algorithm.digest() {
            Some(digest) => {
                let mut signer = Signer::new(digest, &self.key)?;
                signer.update(message)?;
                signer.sign_to_vec()?
            }
            None => {
                let mut signer = Signer::new_without_digest(&self.key)?;
                signer.sign_oneshot_to_vec(message)?
            }
        };
        let Some(size) = self.algorithm.coordinate_size() else {
            return Ok(signature);
        };
        let signature = EcdsaSig::from_der(&signature)?;
        let mut jose = padded_integer(signature.r(), size)?;
        jose.extend_from_slice(&padded_integer(signature.s(), size)?);
        Ok(jose)
    }
}

fn base64_integer(value: &BigNumRef) -> String {
    URL_SAFE_NO_PAD.encode(value.to_vec())
}

fn padded_integer(value: &BigNumRef, size: usize) -> Result<Vec<u8>, BoxError> {
    let value = value.to_vec();
    if value.len() > size {
        return Err(format!(
            "JOSE integer is {} bytes, expected at most {size}",
            value.len()
        )
        .into());
    }
    let mut padded = vec![0; size - value.len()];
    padded.extend_from_slice(&value);
    Ok(padded)
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use openssl::{
        bn::BigNum,
        ec::{EcGroup, EcKey},
        ecdsa::EcdsaSig,
        hash::MessageDigest,
        nid::Nid,
        pkey::{Id, PKey},
        rsa::Rsa,
        sign::Verifier,
    };

    use super::AcmeAccountSigner;

    #[test]
    fn signs_all_account_key_algorithms_with_jose_wire_shapes() {
        let keys = [
            PKey::from_ec_key(
                EcKey::generate(
                    &EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
            PKey::from_ec_key(
                EcKey::generate(
                    &EcGroup::from_curve_name(Nid::SECP384R1).unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
            PKey::from_ec_key(
                EcKey::generate(
                    &EcGroup::from_curve_name(Nid::SECP521R1).unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            PKey::generate_ed25519().unwrap(),
        ];
        let expected = [
            ("ES256", "EC", 64),
            ("ES384", "EC", 96),
            ("ES512", "EC", 132),
            ("RS256", "RSA", 256),
            ("EdDSA", "OKP", 64),
        ];
        for (key, (algorithm, key_type, signature_size)) in
            keys.into_iter().zip(expected)
        {
            let signer = AcmeAccountSigner::from_pem(
                &String::from_utf8(key.private_key_to_pem_pkcs8().unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(signer.algorithm(), algorithm);
            assert_eq!(signer.jwk()["kty"], key_type);
            assert_eq!(signer.thumbprint().len(), 43);
            let signature = signer.sign(b"protected.payload").unwrap();
            assert_eq!(signature.len(), signature_size);
            if key_type == "EC" {
                let size = signature.len() / 2;
                let der = EcdsaSig::from_private_components(
                    BigNum::from_slice(&signature[..size]).unwrap(),
                    BigNum::from_slice(&signature[size..]).unwrap(),
                )
                .unwrap()
                .to_der()
                .unwrap();
                let digest = match algorithm {
                    "ES256" => MessageDigest::sha256(),
                    "ES384" => MessageDigest::sha384(),
                    "ES512" => MessageDigest::sha512(),
                    _ => unreachable!(),
                };
                let mut verifier = Verifier::new(digest, &key).unwrap();
                verifier.update(b"protected.payload").unwrap();
                assert!(verifier.verify(&der).unwrap());
            }
            let restored =
                AcmeAccountSigner::from_pkcs8(signer.pkcs8()).unwrap();
            assert_eq!(restored.algorithm(), algorithm);
            assert_eq!(restored.thumbprint(), signer.thumbprint());
        }
    }

    #[test]
    fn rsa_and_ed25519_signatures_verify_and_ec_uses_raw_jose_format() {
        for key in [
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            PKey::generate_ed25519().unwrap(),
        ] {
            let signer = AcmeAccountSigner::from_pkcs8(
                &key.private_key_to_pkcs8().unwrap(),
            )
            .unwrap();
            let signature = signer.sign(b"signed input").unwrap();
            let verified = if key.id() == Id::ED25519 {
                let mut verifier = Verifier::new_without_digest(&key).unwrap();
                verifier
                    .verify_oneshot(&signature, b"signed input")
                    .unwrap()
            } else {
                let mut verifier =
                    Verifier::new(openssl::hash::MessageDigest::sha256(), &key)
                        .unwrap();
                verifier.update(b"signed input").unwrap();
                verifier.verify(&signature).unwrap()
            };
            assert!(verified);
        }

        let ec = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap())
                .unwrap(),
        )
        .unwrap();
        let signer =
            AcmeAccountSigner::from_pkcs8(&ec.private_key_to_pkcs8().unwrap())
                .unwrap();
        let raw = signer.sign(b"signed input").unwrap();
        assert_eq!(raw.len(), 96);
        assert!(URL_SAFE_NO_PAD.encode(raw).len() > 100);
    }
}
