//! Shadowsocks 2022 Extensible Identity Header relay support.
//!
//! A relay authenticates the outer identity key, removes the EIH block and
//! forwards the still-encrypted stream or datagram to the selected downstream
//! Shadowsocks server. Payload plaintext is never exposed at the relay.

use std::io;

use aes::{
    Aes128, Aes256,
    cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::{adapter, common::network::SocksAddr};

const EIH_LENGTH: usize = 16;
const IDENTITY_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayKind {
    Aes128,
    Aes256,
}

impl RelayKind {
    fn parse(method: &str) -> io::Result<Self> {
        match method {
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256),
            _ => Err(invalid_input(format!(
                "Shadowsocks relay requires a 2022 AES method, got {method}"
            ))),
        }
    }

    const fn key_length(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }
}

#[derive(Clone)]
struct RelayUser {
    name: String,
    key: Vec<u8>,
    identity_hash: [u8; EIH_LENGTH],
    destination: SocksAddr,
}

#[derive(Debug)]
pub struct RelayPacket {
    pub user_index: usize,
    pub user: String,
    pub destination: SocksAddr,
    pub session_id: u64,
    pub payload: Vec<u8>,
}

/// Server-side AEAD-2022 EIH relay transformer.
#[derive(Clone)]
pub struct ShadowsocksRelayServer {
    kind: RelayKind,
    identity_key: Vec<u8>,
    users: Vec<RelayUser>,
}

impl ShadowsocksRelayServer {
    pub fn new(
        method: &str,
        password: &str,
        destinations: impl IntoIterator<Item = (String, String, SocksAddr)>,
    ) -> io::Result<Self> {
        let kind = RelayKind::parse(method)?;
        let identity_key = decode_key(password, kind.key_length(), "relay")?;
        let users = destinations
            .into_iter()
            .enumerate()
            .map(|(index, (name, password, destination))| {
                let key =
                    decode_key(&password, kind.key_length(), "destination")?;
                let hash = blake3::hash(&key);
                let mut identity_hash = [0_u8; EIH_LENGTH];
                identity_hash.copy_from_slice(&hash.as_bytes()[..EIH_LENGTH]);
                Ok(RelayUser {
                    name: if name.is_empty() {
                        index.to_string()
                    } else {
                        name
                    },
                    key,
                    identity_hash,
                    destination,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        if users.is_empty() {
            return Err(invalid_input(
                "no Shadowsocks relay destinations configured",
            ));
        }
        Ok(Self {
            kind,
            identity_key,
            users,
        })
    }

    pub async fn accept_stream<S>(
        &self,
        mut stream: S,
    ) -> io::Result<(String, SocksAddr, adapter::Stream)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let salt_length = self.kind.key_length();
        let mut header = vec![0_u8; salt_length + EIH_LENGTH];
        stream.read_exact(&mut header).await?;
        let salt = &header[..salt_length];
        let mut encrypted_identity = [0_u8; EIH_LENGTH];
        encrypted_identity.copy_from_slice(&header[salt_length..]);
        let identity_subkey =
            identity_subkey(&self.identity_key, salt, self.kind.key_length());
        decrypt_block(self.kind, &identity_subkey, &mut encrypted_identity)?;
        let (_, user) = self.find_user(&encrypted_identity)?;
        let relayed = adapter::replay_stream(
            Box::new(stream),
            header[..salt_length].to_vec(),
        );
        Ok((user.name.clone(), user.destination.clone(), relayed))
    }

    pub fn transform_packet(&self, packet: &[u8]) -> io::Result<RelayPacket> {
        if packet.len() <= EIH_LENGTH * 2 {
            return Err(invalid_data("truncated Shadowsocks relay packet"));
        }
        let mut packet_header = [0_u8; EIH_LENGTH];
        packet_header.copy_from_slice(&packet[..EIH_LENGTH]);
        decrypt_block(self.kind, &self.identity_key, &mut packet_header)?;

        let mut identity = [0_u8; EIH_LENGTH];
        identity.copy_from_slice(&packet[EIH_LENGTH..EIH_LENGTH * 2]);
        decrypt_block(self.kind, &self.identity_key, &mut identity)?;
        for (byte, header_byte) in identity.iter_mut().zip(packet_header) {
            *byte ^= header_byte;
        }
        let (user_index, user) = self.find_user(&identity)?;

        let session_id = u64::from_be_bytes(
            packet_header[..8]
                .try_into()
                .expect("fixed Shadowsocks session ID"),
        );
        encrypt_block(self.kind, &user.key, &mut packet_header)?;
        let mut payload = Vec::with_capacity(packet.len() - EIH_LENGTH);
        payload.extend_from_slice(&packet_header);
        payload.extend_from_slice(&packet[EIH_LENGTH * 2..]);
        Ok(RelayPacket {
            user_index,
            user: user.name.clone(),
            destination: user.destination.clone(),
            session_id,
            payload,
        })
    }

    fn find_user(
        &self,
        identity_hash: &[u8; EIH_LENGTH],
    ) -> io::Result<(usize, &RelayUser)> {
        self.users
            .iter()
            .enumerate()
            .find(|(_, user)| user.identity_hash == *identity_hash)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unknown Shadowsocks relay destination",
                )
            })
    }
}

fn decode_key(
    encoded: &str,
    length: usize,
    label: &str,
) -> io::Result<Vec<u8>> {
    if encoded.is_empty() {
        return Err(invalid_input(format!("missing Shadowsocks {label} key")));
    }
    let key = STANDARD.decode(encoded).map_err(|error| {
        invalid_input(format!("invalid Shadowsocks {label} key: {error}"))
    })?;
    if key.len() < length {
        return Err(invalid_input(format!(
            "Shadowsocks {label} key is too short: expected {length}, got {}",
            key.len()
        )));
    }
    if key.len() == length {
        Ok(key)
    } else {
        Ok(Sha256::digest(key)[..length].to_vec())
    }
}

fn identity_subkey(identity_key: &[u8], salt: &[u8], length: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(identity_key.len() + salt.len());
    material.extend_from_slice(identity_key);
    material.extend_from_slice(salt);
    blake3::derive_key(IDENTITY_SUBKEY_CONTEXT, &material)[..length].to_vec()
}

fn decrypt_block(
    kind: RelayKind,
    key: &[u8],
    block: &mut [u8; EIH_LENGTH],
) -> io::Result<()> {
    match kind {
        RelayKind::Aes128 => {
            let cipher = Aes128::new_from_slice(key)
                .map_err(|_| invalid_input("invalid AES-128 relay key"))?;
            let mut value = Block::<Aes128>::from(*block);
            cipher.decrypt_block(&mut value);
            *block = value.into();
        }
        RelayKind::Aes256 => {
            let cipher = Aes256::new_from_slice(key)
                .map_err(|_| invalid_input("invalid AES-256 relay key"))?;
            let mut value = Block::<Aes256>::from(*block);
            cipher.decrypt_block(&mut value);
            *block = value.into();
        }
    }
    Ok(())
}

fn encrypt_block(
    kind: RelayKind,
    key: &[u8],
    block: &mut [u8; EIH_LENGTH],
) -> io::Result<()> {
    match kind {
        RelayKind::Aes128 => {
            let cipher = Aes128::new_from_slice(key)
                .map_err(|_| invalid_input("invalid AES-128 relay key"))?;
            let mut value = Block::<Aes128>::from(*block);
            cipher.encrypt_block(&mut value);
            *block = value.into();
        }
        RelayKind::Aes256 => {
            let cipher = Aes256::new_from_slice(key)
                .map_err(|_| invalid_input("invalid AES-256 relay key"))?;
            let mut value = Block::<Aes256>::from(*block);
            cipher.encrypt_block(&mut value);
            *block = value.into();
        }
    }
    Ok(())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
