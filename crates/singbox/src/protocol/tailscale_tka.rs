//! Tailscale tailnet-lock node-key signature compatibility.
//!
//! The CBOR representation follows `tka.NodeKeySignature`: integer map keys,
//! byte strings, CTAP2-canonical field order, and a BLAKE2s-256 digest with the
//! signature field omitted. Ed25519 is delegated to the audited dalek crate.

use std::{fmt, str::FromStr};

use blake2::{Blake2s256, Digest as _};
use ed25519_dalek::{Signer as _, SigningKey};
use minicbor::{Decode, Decoder, Encode, Encoder, bytes::ByteVec};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use zeroize::Zeroize;

use super::tailscale_control_types::{
    TailscaleNetworkLockPublicKey, TailscaleNodePublicKey,
};

const NETWORK_LOCK_PRIVATE_PREFIX: &str = "nlpriv:";
const NODE_PUBLIC_BINARY_PREFIX: &[u8; 2] = b"np";
const ED25519_PRIVATE_KEY_LENGTH: usize = 64;
const MAXIMUM_PREVIOUS_NODE_KEYS: usize = 15;

#[derive(Debug, Error)]
pub enum TailscaleTkaError {
    #[error("invalid Tailscale network-lock private key")]
    InvalidPrivateKey,
    #[error("Tailscale network-lock private key must not be all zero")]
    ZeroPrivateKey,
    #[error("Tailscale TKA signature CBOR failed: {0}")]
    Cbor(String),
    #[error("Tailscale TKA signature has invalid kind {0}")]
    InvalidSignatureKind(u8),
    #[error("Tailscale TKA rotation signature is missing its nested signature")]
    MissingNestedSignature,
    #[error("Tailscale TKA signature is missing its node public key")]
    MissingNodeKey,
    #[error("Tailscale random source failed: {0}")]
    Random(String),
}

/// The node-owned Ed25519 rotation key used by tailnet lock. Text encoding is
/// byte-for-byte compatible with Tailscale's `key.NLPrivate` (`nlpriv:` plus
/// the 64-byte Ed25519 keypair in hexadecimal).
#[derive(Clone)]
pub struct TailscaleNetworkLockPrivateKey([u8; ED25519_PRIVATE_KEY_LENGTH]);

impl TailscaleNetworkLockPrivateKey {
    pub fn generate() -> Result<Self, TailscaleTkaError> {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|error| TailscaleTkaError::Random(error.to_string()))?;
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self(signing.to_keypair_bytes()))
    }

    pub fn from_bytes(
        bytes: [u8; ED25519_PRIVATE_KEY_LENGTH],
    ) -> Result<Self, TailscaleTkaError> {
        if bytes == [0; ED25519_PRIVATE_KEY_LENGTH] {
            return Err(TailscaleTkaError::ZeroPrivateKey);
        }
        SigningKey::from_keypair_bytes(&bytes)
            .map_err(|_| TailscaleTkaError::InvalidPrivateKey)?;
        Ok(Self(bytes))
    }

    pub fn expose_secret(&self) -> [u8; ED25519_PRIVATE_KEY_LENGTH] {
        self.0
    }

    pub fn public_key(&self) -> TailscaleNetworkLockPublicKey {
        let signing = SigningKey::from_keypair_bytes(&self.0)
            .expect("validated Tailscale network-lock private key");
        TailscaleNetworkLockPublicKey::from_bytes(
            signing.verifying_key().to_bytes(),
        )
    }

    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        let signing = SigningKey::from_keypair_bytes(&self.0)
            .expect("validated Tailscale network-lock private key");
        signing.sign(digest).to_bytes().to_vec()
    }
}

impl Drop for TailscaleNetworkLockPrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for TailscaleNetworkLockPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TailscaleNetworkLockPrivateKey([REDACTED])")
    }
}

impl fmt::Display for TailscaleNetworkLockPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{NETWORK_LOCK_PRIVATE_PREFIX}{}",
            hex::encode(self.0)
        )
    }
}

impl FromStr for TailscaleNetworkLockPrivateKey {
    type Err = TailscaleTkaError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value
            .strip_prefix(NETWORK_LOCK_PRIVATE_PREFIX)
            .ok_or(TailscaleTkaError::InvalidPrivateKey)?;
        let mut key = [0_u8; ED25519_PRIVATE_KEY_LENGTH];
        hex::decode_to_slice(value, &mut key)
            .map_err(|_| TailscaleTkaError::InvalidPrivateKey)?;
        Self::from_bytes(key)
    }
}

impl Serialize for TailscaleNetworkLockPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TailscaleNetworkLockPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleNodeKeySignature {
    pub kind: u8,
    pub node_key: Option<ByteVec>,
    pub key_id: Option<ByteVec>,
    pub signature: Option<ByteVec>,
    pub nested: Option<Box<TailscaleNodeKeySignature>>,
    pub wrapping_public_key: Option<ByteVec>,
}

impl<C> Encode<C> for TailscaleNodeKeySignature {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let fields = 1
            + usize::from(self.node_key.is_some())
            + usize::from(self.key_id.is_some())
            + usize::from(self.signature.is_some())
            + usize::from(self.nested.is_some())
            + usize::from(self.wrapping_public_key.is_some());
        encoder.map(fields as u64)?.u8(1)?.u8(self.kind)?;
        if let Some(value) = &self.node_key {
            encoder.u8(2)?.bytes(value)?;
        }
        if let Some(value) = &self.key_id {
            encoder.u8(3)?.bytes(value)?;
        }
        if let Some(value) = &self.signature {
            encoder.u8(4)?.bytes(value)?;
        }
        if let Some(value) = &self.nested {
            encoder.u8(5)?;
            value.encode(encoder, context)?;
        }
        if let Some(value) = &self.wrapping_public_key {
            encoder.u8(6)?.bytes(value)?;
        }
        Ok(())
    }
}

impl<'bytes, C> Decode<'bytes, C> for TailscaleNodeKeySignature {
    fn decode(
        decoder: &mut Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let length = decoder.map()?;
        let mut remaining = length.unwrap_or(u64::MAX);
        let mut signature = Self {
            kind: 0,
            node_key: None,
            key_id: None,
            signature: None,
            nested: None,
            wrapping_public_key: None,
        };
        while remaining > 0 {
            if length.is_none()
                && decoder.datatype()? == minicbor::data::Type::Break
            {
                decoder.skip()?;
                break;
            }
            match decoder.u8()? {
                1 => signature.kind = decoder.u8()?,
                2 => {
                    signature.node_key = Some(decoder.bytes()?.to_vec().into())
                }
                3 => signature.key_id = Some(decoder.bytes()?.to_vec().into()),
                4 => {
                    signature.signature = Some(decoder.bytes()?.to_vec().into())
                }
                5 => {
                    signature.nested = Some(Box::new(
                        <Self as Decode<C>>::decode(decoder, _context)?,
                    ));
                }
                6 => {
                    signature.wrapping_public_key =
                        Some(decoder.bytes()?.to_vec().into());
                }
                _ => decoder.skip()?,
            }
            remaining -= 1;
        }
        Ok(signature)
    }
}

impl TailscaleNodeKeySignature {
    pub const KIND_DIRECT: u8 = 1;
    pub const KIND_ROTATION: u8 = 2;
    pub const KIND_CREDENTIAL: u8 = 3;

    pub fn decode(bytes: &[u8]) -> Result<Self, TailscaleTkaError> {
        let signature: Self = minicbor::decode(bytes)
            .map_err(|error| TailscaleTkaError::Cbor(error.to_string()))?;
        signature.validate(0)?;
        Ok(signature)
    }

    pub fn encode(&self) -> Result<Vec<u8>, TailscaleTkaError> {
        minicbor::to_vec(self)
            .map_err(|error| TailscaleTkaError::Cbor(error.to_string()))
    }

    pub fn signature_hash(&self) -> Result<[u8; 32], TailscaleTkaError> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        let encoded = unsigned.encode()?;
        Ok(Blake2s256::digest(encoded).into())
    }

    fn validate(&self, depth: usize) -> Result<(), TailscaleTkaError> {
        if depth >= 16 {
            return Err(TailscaleTkaError::Cbor(
                "signature nesting exceeds 16 levels".into(),
            ));
        }
        if !matches!(
            self.kind,
            Self::KIND_DIRECT | Self::KIND_ROTATION | Self::KIND_CREDENTIAL
        ) {
            return Err(TailscaleTkaError::InvalidSignatureKind(self.kind));
        }
        if self.kind == Self::KIND_ROTATION && self.nested.is_none() {
            return Err(TailscaleTkaError::MissingNestedSignature);
        }
        if self.kind != Self::KIND_CREDENTIAL && self.node_key.is_none() {
            return Err(TailscaleTkaError::MissingNodeKey);
        }
        if let Some(nested) = &self.nested {
            nested.validate(depth + 1)?;
        }
        Ok(())
    }
}

/// Re-sign an existing node-key signature for a replacement WireGuard node
/// key, matching `tka.ResignNKS`. Rotation chains are trimmed before they
/// would exceed Tailscale's 16-level CBOR nesting limit.
pub fn resign_tailscale_node_key_signature(
    private_key: &TailscaleNetworkLockPrivateKey,
    node_key: TailscaleNodePublicKey,
    old_signature: &[u8],
) -> Result<Vec<u8>, TailscaleTkaError> {
    let mut old = TailscaleNodeKeySignature::decode(old_signature)?;
    let mut node_key_binary = Vec::with_capacity(34);
    node_key_binary.extend_from_slice(NODE_PUBLIC_BINARY_PREFIX);
    node_key_binary.extend_from_slice(node_key.as_bytes());
    if old
        .node_key
        .as_ref()
        .is_some_and(|key| key.as_slice() == node_key_binary)
    {
        return Ok(old_signature.to_vec());
    }
    old = trim_rotation_chain(old, private_key)?;
    let mut rotated = TailscaleNodeKeySignature {
        kind: TailscaleNodeKeySignature::KIND_ROTATION,
        node_key: Some(node_key_binary.into()),
        key_id: None,
        signature: None,
        nested: Some(Box::new(old)),
        wrapping_public_key: None,
    };
    rotated.signature =
        Some(private_key.sign(&rotated.signature_hash()?).into());
    rotated.encode()
}

fn trim_rotation_chain(
    signature: TailscaleNodeKeySignature,
    private_key: &TailscaleNetworkLockPrivateKey,
) -> Result<TailscaleNodeKeySignature, TailscaleTkaError> {
    if signature.kind != TailscaleNodeKeySignature::KIND_ROTATION {
        return Ok(signature);
    }
    let mut previous = Vec::new();
    if let Some(node_key) = &signature.node_key {
        previous.push(node_key.clone());
    }
    let mut cursor = signature.nested.as_deref();
    let mut initial = None;
    while let Some(nested) = cursor {
        if let Some(node_key) = &nested.node_key {
            previous.push(node_key.clone());
        }
        if nested.kind != TailscaleNodeKeySignature::KIND_ROTATION {
            initial = Some(nested.clone());
            break;
        }
        cursor = nested.nested.as_deref();
    }
    if previous.len() <= MAXIMUM_PREVIOUS_NODE_KEYS {
        return Ok(signature);
    }
    let mut result =
        initial.ok_or(TailscaleTkaError::MissingNestedSignature)?;
    for index in (0..=(MAXIMUM_PREVIOUS_NODE_KEYS - 2)).rev() {
        let mut wrapper = TailscaleNodeKeySignature {
            kind: TailscaleNodeKeySignature::KIND_ROTATION,
            node_key: Some(previous[index].clone()),
            key_id: None,
            signature: None,
            nested: Some(Box::new(result)),
            wrapping_public_key: None,
        };
        wrapper.signature =
            Some(private_key.sign(&wrapper.signature_hash()?).into());
        result = wrapper;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_lock_private_key_round_trips_and_redacts() {
        let key = TailscaleNetworkLockPrivateKey::generate().unwrap();
        assert_eq!(
            key.to_string()
                .parse::<TailscaleNetworkLockPrivateKey>()
                .unwrap()
                .public_key(),
            key.public_key()
        );
        assert!(
            !format!("{key:?}").contains(&hex::encode(key.expose_secret()))
        );
    }

    #[test]
    fn resign_matches_pinned_go_tailscale_oracle() {
        let private: TailscaleNetworkLockPrivateKey = concat!(
            "nlpriv:",
            "000102030405060708090a0b0c0d0e0f",
            "101112131415161718191a1b1c1d1e1f",
            "03a107bff3ce10be1d70dd18e74bc099",
            "67e4d6309ba50d5f1ddc8664125531b8"
        )
        .parse()
        .unwrap();
        let old = hex::decode("a401010258226e70000000000000000000000000000000000000000000000000000000000000001103582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b804584087f274c3d64ba3a422e478d266a9a30313cfe0eb669f56047835fb0728641ff716b09bc1401a0350aa4ec9056529164abf4757999a029105a109cd404af4fb0e")
        .unwrap();
        let expected = hex::decode("a401020258226e70000000000000000000000000000000000000000000000000000000000000002204584022cbf10da89455e8b738eb4af03b8b1e40f7bdb4701ffe6747632d285757ed2c46abb38741e71359e78c51a1cd3eaaf2cd62b11f7fc038a1a0e37538c2acce0e05a401010258226e70000000000000000000000000000000000000000000000000000000000000001103582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b804584087f274c3d64ba3a422e478d266a9a30313cfe0eb669f56047835fb0728641ff716b09bc1401a0350aa4ec9056529164abf4757999a029105a109cd404af4fb0e")
        .unwrap();
        let mut new_node = [0_u8; 32];
        new_node[31] = 0x22;
        let actual = resign_tailscale_node_key_signature(
            &private,
            TailscaleNodePublicKey::from_bytes(new_node),
            &old,
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            TailscaleNodeKeySignature::decode(&actual)
                .unwrap()
                .encode()
                .unwrap(),
            expected
        );
    }
}
