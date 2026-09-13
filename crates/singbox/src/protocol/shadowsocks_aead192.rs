//! Shadowsocks legacy AEAD `aes-192-gcm` compatibility.
//!
//! `shadowsocks-crypto` intentionally omits this upstream sing-shadowsocks
//! method, so the small missing cipher/wire layer lives here while the other
//! methods continue to use the mature crate.

use std::{
    collections::{HashSet, VecDeque},
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{
    AesGcm,
    aead::{Aead, KeyInit, consts::U12},
};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hkdf::Hkdf;
use md5::{Digest as _, Md5};
use sha1_11::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common::network::SocksAddr;

pub const SALT_LENGTH: usize = 24;
pub const TAG_LENGTH: usize = 16;
pub const MAX_PAYLOAD_LENGTH: usize = 0x3fff;
const SUBKEY_INFO: &[u8] = b"ss-subkey";

type Aes192Gcm = AesGcm<Aes192, U12>;

#[derive(Clone)]
pub struct Aes192GcmMethod {
    key: [u8; SALT_LENGTH],
    replay: Option<Arc<Mutex<ReplayCache>>>,
}

#[derive(Default)]
struct ReplayCache {
    salts: HashSet<[u8; SALT_LENGTH]>,
    order: VecDeque<[u8; SALT_LENGTH]>,
}

impl Aes192GcmMethod {
    pub fn new(password: &str) -> io::Result<Self> {
        if password.is_empty() {
            return Err(invalid_input("missing Shadowsocks password"));
        }
        Ok(Self {
            key: evp_bytes_to_key(password.as_bytes()),
            replay: None,
        })
    }

    pub fn new_server(password: &str) -> io::Result<Self> {
        let mut method = Self::new(password)?;
        method.replay = Some(Arc::new(Mutex::new(ReplayCache::default())));
        Ok(method)
    }

    pub fn key(&self) -> &[u8; SALT_LENGTH] {
        &self.key
    }

    pub fn seal_packet(
        &self,
        salt: &[u8; SALT_LENGTH],
        destination: &SocksAddr,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut plaintext = encode_address(destination)?;
        plaintext.extend_from_slice(payload);
        let mut cipher = AeadCipher::new(&self.key, salt)?;
        let sealed = cipher.seal(&plaintext)?;
        let mut packet = Vec::with_capacity(SALT_LENGTH + sealed.len());
        packet.extend_from_slice(salt);
        packet.extend_from_slice(&sealed);
        Ok(packet)
    }

    pub fn open_packet(
        &self,
        packet: &[u8],
    ) -> io::Result<(SocksAddr, Vec<u8>)> {
        if packet.len() < SALT_LENGTH + TAG_LENGTH + 1 {
            return Err(invalid_data("truncated Shadowsocks AEAD packet"));
        }
        let salt: &[u8; SALT_LENGTH] = packet[..SALT_LENGTH]
            .try_into()
            .expect("fixed Shadowsocks salt");
        self.check_replay(salt)?;
        let mut cipher = AeadCipher::new(&self.key, salt)?;
        let plaintext = cipher.open(&packet[SALT_LENGTH..])?;
        let (destination, address_length) = decode_address(&plaintext)?;
        Ok((destination, plaintext[address_length..].to_vec()))
    }

    pub fn wrap_client_stream(
        &self,
        raw: crate::adapter::Stream,
        destination: SocksAddr,
    ) -> crate::adapter::Stream {
        let key = self.key;
        let (application, bridge) = tokio::io::duplex(64 * 1024);
        let (mut application_reader, mut application_writer) =
            tokio::io::split(bridge);
        let (mut raw_reader, mut raw_writer) = tokio::io::split(raw);
        tokio::spawn(async move {
            if decrypt_stream(&mut raw_reader, &mut application_writer, key)
                .await
                .is_err()
            {
                let _ = application_writer.shutdown().await;
            }
        });
        tokio::spawn(async move {
            let result = async {
                let salt = random_salt()?;
                raw_writer.write_all(&salt).await?;
                let mut cipher = AeadCipher::new(&key, &salt)?;
                let address = encode_address(&destination)?;
                let first_capacity =
                    MAX_PAYLOAD_LENGTH.checked_sub(address.len()).ok_or_else(
                        || invalid_input("Shadowsocks address is too long"),
                    )?;
                let mut first = vec![0_u8; first_capacity];
                let size = application_reader.read(&mut first).await?;
                if size == 0 {
                    return Ok::<(), io::Error>(());
                }
                let mut payload = address;
                payload.extend_from_slice(&first[..size]);
                write_chunk(&mut raw_writer, &mut cipher, &payload).await?;
                let mut buffer = vec![0_u8; MAX_PAYLOAD_LENGTH];
                loop {
                    let size = application_reader.read(&mut buffer).await?;
                    if size == 0 {
                        break;
                    }
                    write_chunk(&mut raw_writer, &mut cipher, &buffer[..size])
                        .await?;
                }
                Ok(())
            }
            .await;
            let _ = raw_writer.shutdown().await;
            let _ = result;
        });
        Box::new(application)
    }

    pub async fn accept_stream<S>(
        &self,
        mut raw: S,
    ) -> io::Result<(SocksAddr, crate::adapter::Stream)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut salt = [0_u8; SALT_LENGTH];
        raw.read_exact(&mut salt).await?;
        self.check_replay(&salt)?;
        let mut decrypt_cipher = AeadCipher::new(&self.key, &salt)?;
        let first = read_chunk(&mut raw, &mut decrypt_cipher).await?;
        let (destination, address_length) = decode_address(&first)?;
        let initial_payload = first[address_length..].to_vec();
        let key = self.key;
        let (application, bridge) = tokio::io::duplex(64 * 1024);
        let (mut application_reader, mut application_writer) =
            tokio::io::split(bridge);
        let (mut raw_reader, mut raw_writer) = tokio::io::split(raw);
        tokio::spawn(async move {
            if !initial_payload.is_empty()
                && application_writer
                    .write_all(&initial_payload)
                    .await
                    .is_err()
            {
                return;
            }
            while let Ok(payload) =
                read_chunk(&mut raw_reader, &mut decrypt_cipher).await
            {
                if application_writer.write_all(&payload).await.is_err() {
                    break;
                }
            }
            let _ = application_writer.shutdown().await;
        });
        tokio::spawn(async move {
            let result = async {
                let salt = random_salt()?;
                raw_writer.write_all(&salt).await?;
                let mut cipher = AeadCipher::new(&key, &salt)?;
                let mut buffer = vec![0_u8; MAX_PAYLOAD_LENGTH];
                loop {
                    let size = application_reader.read(&mut buffer).await?;
                    if size == 0 {
                        break;
                    }
                    write_chunk(&mut raw_writer, &mut cipher, &buffer[..size])
                        .await?;
                }
                Ok::<(), io::Error>(())
            }
            .await;
            let _ = raw_writer.shutdown().await;
            let _ = result;
        });
        Ok((destination, Box::new(application)))
    }

    fn check_replay(&self, salt: &[u8; SALT_LENGTH]) -> io::Result<()> {
        let Some(cache) = &self.replay else {
            return Ok(());
        };
        let mut cache = cache.lock().map_err(|_| {
            io::Error::other("Shadowsocks replay cache poisoned")
        })?;
        if !cache.salts.insert(*salt) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "replayed Shadowsocks AEAD salt",
            ));
        }
        cache.order.push_back(*salt);
        if cache.order.len() > 16_384
            && let Some(expired) = cache.order.pop_front()
        {
            cache.salts.remove(&expired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyAeadKind {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl LegacyAeadKind {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-192-gcm" => Ok(Self::Aes192Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305),
            "xchacha20-ietf-poly1305" => Ok(Self::XChaCha20Poly1305),
            _ => Err(invalid_input(format!(
                "unsupported legacy Shadowsocks AEAD method: {value}"
            ))),
        }
    }

    const fn key_length(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes192Gcm => 24,
            Self::Aes256Gcm
            | Self::ChaCha20Poly1305
            | Self::XChaCha20Poly1305 => 32,
        }
    }

    const fn nonce_length(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => 24,
            _ => 12,
        }
    }
}

#[derive(Clone)]
struct LegacyAeadMethod {
    kind: LegacyAeadKind,
    key: Vec<u8>,
}

impl LegacyAeadMethod {
    fn new(kind: LegacyAeadKind, password: &str) -> io::Result<Self> {
        if password.is_empty() {
            return Err(invalid_input("missing Shadowsocks user password"));
        }
        Ok(Self {
            kind,
            key: evp_bytes_to_key_len(password.as_bytes(), kind.key_length()),
        })
    }

    fn cipher(&self, salt: &[u8]) -> io::Result<LegacyCipher> {
        let hkdf = Hkdf::<Sha1>::new(Some(salt), &self.key);
        let mut subkey = vec![0_u8; self.kind.key_length()];
        hkdf.expand(SUBKEY_INFO, &mut subkey)
            .map_err(|_| invalid_input("invalid Shadowsocks HKDF length"))?;
        LegacyCipher::new(self.kind, &subkey)
    }

    fn seal_packet(
        &self,
        salt: &[u8],
        destination: &SocksAddr,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut plaintext = encode_address(destination)?;
        plaintext.extend_from_slice(payload);
        let mut cipher = self.cipher(salt)?;
        let sealed = cipher.seal(&plaintext)?;
        let mut packet = Vec::with_capacity(salt.len() + sealed.len());
        packet.extend_from_slice(salt);
        packet.extend_from_slice(&sealed);
        Ok(packet)
    }
}

/// Legacy AEAD multi-user server used when `users` is configured. The user is
/// selected by authenticating the first TCP length chunk or complete UDP packet,
/// exactly as sing-shadowsocks' `MultiService` does.
#[derive(Clone)]
pub struct MultiLegacyAeadServer {
    kind: LegacyAeadKind,
    users: Arc<Vec<(String, LegacyAeadMethod)>>,
    replay: Arc<Mutex<VariableReplayCache>>,
}

#[derive(Default)]
struct VariableReplayCache {
    salts: HashSet<Vec<u8>>,
    order: VecDeque<Vec<u8>>,
}

impl MultiLegacyAeadServer {
    pub fn new(
        method: &str,
        users: impl IntoIterator<Item = (String, String)>,
    ) -> io::Result<Self> {
        let kind = LegacyAeadKind::parse(method)?;
        let users = users
            .into_iter()
            .map(|(name, password)| {
                LegacyAeadMethod::new(kind, &password)
                    .map(|method| (name, method))
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            kind,
            users: Arc::new(users),
            replay: Arc::new(Mutex::new(VariableReplayCache::default())),
        })
    }

    pub async fn accept_stream<S>(
        &self,
        mut raw: S,
    ) -> io::Result<(String, SocksAddr, crate::adapter::Stream)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let salt_length = self.kind.key_length();
        let mut salt = vec![0_u8; salt_length];
        raw.read_exact(&mut salt).await?;
        self.check_replay(&salt)?;
        let mut sealed_length = [0_u8; 2 + TAG_LENGTH];
        raw.read_exact(&mut sealed_length).await?;
        let mut selected = None;
        for (index, (_, method)) in self.users.iter().enumerate() {
            let mut cipher = method.cipher(&salt)?;
            let Ok(length) = cipher.open(&sealed_length) else {
                continue;
            };
            let Ok(length) = <[u8; 2]>::try_from(length.as_slice()) else {
                continue;
            };
            let length = usize::from(u16::from_be_bytes(length));
            if length <= MAX_PAYLOAD_LENGTH {
                selected = Some((index, method.clone(), cipher, length));
                break;
            }
        }
        let (index, method, mut decrypt_cipher, length) =
            selected.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unknown Shadowsocks user",
                )
            })?;
        let mut sealed_payload = vec![0_u8; length + TAG_LENGTH];
        raw.read_exact(&mut sealed_payload).await?;
        let first = decrypt_cipher.open(&sealed_payload)?;
        let (destination, address_length) = decode_address(&first)?;
        let initial_payload = first[address_length..].to_vec();
        let user = self.users[index].0.clone();
        let (application, bridge) = tokio::io::duplex(64 * 1024);
        let (mut application_reader, mut application_writer) =
            tokio::io::split(bridge);
        let (mut raw_reader, mut raw_writer) = tokio::io::split(raw);
        tokio::spawn(async move {
            if !initial_payload.is_empty()
                && application_writer
                    .write_all(&initial_payload)
                    .await
                    .is_err()
            {
                return;
            }
            while let Ok(payload) =
                read_legacy_chunk(&mut raw_reader, &mut decrypt_cipher).await
            {
                if application_writer.write_all(&payload).await.is_err() {
                    break;
                }
            }
            let _ = application_writer.shutdown().await;
        });
        tokio::spawn(async move {
            let result = async {
                let salt = random_salt_vec(method.kind.key_length())?;
                raw_writer.write_all(&salt).await?;
                let mut cipher = method.cipher(&salt)?;
                let mut buffer = vec![0_u8; MAX_PAYLOAD_LENGTH];
                loop {
                    let size = application_reader.read(&mut buffer).await?;
                    if size == 0 {
                        break;
                    }
                    write_legacy_chunk(
                        &mut raw_writer,
                        &mut cipher,
                        &buffer[..size],
                    )
                    .await?;
                }
                Ok::<(), io::Error>(())
            }
            .await;
            let _ = raw_writer.shutdown().await;
            let _ = result;
        });
        Ok((user, destination, Box::new(application)))
    }

    pub fn open_packet(
        &self,
        packet: &[u8],
    ) -> io::Result<(usize, String, SocksAddr, Vec<u8>)> {
        let salt_length = self.kind.key_length();
        if packet.len() < salt_length + TAG_LENGTH + 1 {
            return Err(invalid_data("truncated Shadowsocks AEAD packet"));
        }
        let salt = &packet[..salt_length];
        self.check_replay(salt)?;
        for (index, (user, method)) in self.users.iter().enumerate() {
            let mut cipher = method.cipher(salt)?;
            let Ok(plaintext) = cipher.open(&packet[salt_length..]) else {
                continue;
            };
            let (destination, address_length) = decode_address(&plaintext)?;
            return Ok((
                index,
                user.clone(),
                destination,
                plaintext[address_length..].to_vec(),
            ));
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unknown Shadowsocks user",
        ))
    }

    pub fn seal_packet(
        &self,
        user: usize,
        destination: &SocksAddr,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let (_, method) = self
            .users
            .get(user)
            .ok_or_else(|| invalid_input("invalid Shadowsocks user index"))?;
        let salt = random_salt_vec(self.kind.key_length())?;
        method.seal_packet(&salt, destination, payload)
    }

    fn check_replay(&self, salt: &[u8]) -> io::Result<()> {
        let mut replay = self.replay.lock().map_err(|_| {
            io::Error::other("Shadowsocks replay cache poisoned")
        })?;
        if !replay.salts.insert(salt.to_vec()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "replayed Shadowsocks AEAD salt",
            ));
        }
        replay.order.push_back(salt.to_vec());
        if replay.order.len() > 16_384
            && let Some(expired) = replay.order.pop_front()
        {
            replay.salts.remove(&expired);
        }
        Ok(())
    }
}

enum LegacyCipherKind {
    Aes128(AesGcm<Aes128, U12>),
    Aes192(AesGcm<Aes192, U12>),
    Aes256(AesGcm<Aes256, U12>),
    ChaCha(ChaCha20Poly1305),
    XChaCha(XChaCha20Poly1305),
}

struct LegacyCipher {
    cipher: LegacyCipherKind,
    nonce: Vec<u8>,
}

impl LegacyCipher {
    fn new(kind: LegacyAeadKind, key: &[u8]) -> io::Result<Self> {
        let cipher = match kind {
            LegacyAeadKind::Aes128Gcm => LegacyCipherKind::Aes128(
                AesGcm::<Aes128, U12>::new_from_slice(key)
                    .map_err(|_| invalid_input("invalid AES-128-GCM key"))?,
            ),
            LegacyAeadKind::Aes192Gcm => LegacyCipherKind::Aes192(
                AesGcm::<Aes192, U12>::new_from_slice(key)
                    .map_err(|_| invalid_input("invalid AES-192-GCM key"))?,
            ),
            LegacyAeadKind::Aes256Gcm => LegacyCipherKind::Aes256(
                AesGcm::<Aes256, U12>::new_from_slice(key)
                    .map_err(|_| invalid_input("invalid AES-256-GCM key"))?,
            ),
            LegacyAeadKind::ChaCha20Poly1305 => LegacyCipherKind::ChaCha(
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| {
                    invalid_input("invalid ChaCha20-Poly1305 key")
                })?,
            ),
            LegacyAeadKind::XChaCha20Poly1305 => LegacyCipherKind::XChaCha(
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| {
                    invalid_input("invalid XChaCha20-Poly1305 key")
                })?,
            ),
        };
        Ok(Self {
            cipher,
            nonce: vec![0; kind.nonce_length()],
        })
    }

    fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let output = match &self.cipher {
            LegacyCipherKind::Aes128(cipher) => {
                let nonce: [u8; 12] = self.nonce.as_slice().try_into().unwrap();
                cipher.encrypt((&nonce).into(), plaintext)
            }
            LegacyCipherKind::Aes192(cipher) => {
                let nonce: [u8; 12] = self.nonce.as_slice().try_into().unwrap();
                cipher.encrypt((&nonce).into(), plaintext)
            }
            LegacyCipherKind::Aes256(cipher) => {
                let nonce: [u8; 12] = self.nonce.as_slice().try_into().unwrap();
                cipher.encrypt((&nonce).into(), plaintext)
            }
            LegacyCipherKind::ChaCha(cipher) => {
                let nonce: [u8; 12] = self.nonce.as_slice().try_into().unwrap();
                cipher.encrypt((&nonce).into(), plaintext)
            }
            LegacyCipherKind::XChaCha(cipher) => {
                let nonce: [u8; 24] = self.nonce.as_slice().try_into().unwrap();
                cipher.encrypt((&nonce).into(), plaintext)
            }
        }
        .map_err(|_| invalid_data("Shadowsocks AEAD encryption failed"))?;
        increment_nonce(&mut self.nonce);
        Ok(output)
    }

    fn open(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let output = match &self.cipher {
            LegacyCipherKind::Aes128(cipher) => {
                let nonce: [u8; 12] = self.nonce.as_slice().try_into().unwrap();
                cipher.decrypt((&nonce).into(), ciphertext)
            }
            LegacyCipherKind::Aes192(cipher) => {
                let nonce: [u8; 12] = self.nonce.as_slice().try_into().unwrap();
                cipher.decrypt((&nonce).into(), ciphertext)
            }
            LegacyCipherKind::Aes256(cipher) => {
                let nonce: [u8; 12] = self.nonce.as_slice().try_into().unwrap();
                cipher.decrypt((&nonce).into(), ciphertext)
            }
            LegacyCipherKind::ChaCha(cipher) => {
                let nonce: [u8; 12] = self.nonce.as_slice().try_into().unwrap();
                cipher.decrypt((&nonce).into(), ciphertext)
            }
            LegacyCipherKind::XChaCha(cipher) => {
                let nonce: [u8; 24] = self.nonce.as_slice().try_into().unwrap();
                cipher.decrypt((&nonce).into(), ciphertext)
            }
        }
        .map_err(|_| invalid_data("invalid Shadowsocks AEAD tag"))?;
        increment_nonce(&mut self.nonce);
        Ok(output)
    }
}

async fn read_legacy_chunk<R>(
    reader: &mut R,
    cipher: &mut LegacyCipher,
) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut sealed_length = [0_u8; 2 + TAG_LENGTH];
    reader.read_exact(&mut sealed_length).await?;
    let length = cipher.open(&sealed_length)?;
    let length = usize::from(u16::from_be_bytes(
        length
            .as_slice()
            .try_into()
            .map_err(|_| invalid_data("invalid Shadowsocks chunk length"))?,
    ));
    if length > MAX_PAYLOAD_LENGTH {
        return Err(invalid_data("Shadowsocks AEAD chunk is too large"));
    }
    let mut sealed_payload = vec![0_u8; length + TAG_LENGTH];
    reader.read_exact(&mut sealed_payload).await?;
    cipher.open(&sealed_payload)
}

async fn write_legacy_chunk<W>(
    writer: &mut W,
    cipher: &mut LegacyCipher,
    payload: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_PAYLOAD_LENGTH {
        return Err(invalid_input("Shadowsocks AEAD chunk is too large"));
    }
    let length = cipher.seal(&(payload.len() as u16).to_be_bytes())?;
    let payload = cipher.seal(payload)?;
    writer.write_all(&length).await?;
    writer.write_all(&payload).await?;
    writer.flush().await
}

struct AeadCipher {
    cipher: Aes192Gcm,
    nonce: [u8; 12],
}

impl AeadCipher {
    fn new(
        master_key: &[u8; SALT_LENGTH],
        salt: &[u8; SALT_LENGTH],
    ) -> io::Result<Self> {
        let hkdf = Hkdf::<Sha1>::new(Some(salt), master_key);
        let mut subkey = [0_u8; SALT_LENGTH];
        hkdf.expand(SUBKEY_INFO, &mut subkey)
            .map_err(|_| invalid_input("invalid Shadowsocks HKDF length"))?;
        let cipher = Aes192Gcm::new_from_slice(&subkey)
            .map_err(|_| invalid_input("invalid AES-192-GCM key"))?;
        Ok(Self {
            cipher,
            nonce: [0; 12],
        })
    }

    fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let output = self
            .cipher
            .encrypt((&self.nonce).into(), plaintext)
            .map_err(|_| invalid_data("Shadowsocks AEAD encryption failed"))?;
        increment_nonce(&mut self.nonce);
        Ok(output)
    }

    fn open(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let output = self
            .cipher
            .decrypt((&self.nonce).into(), ciphertext)
            .map_err(|_| invalid_data("invalid Shadowsocks AEAD tag"))?;
        increment_nonce(&mut self.nonce);
        Ok(output)
    }
}

async fn write_chunk<W>(
    writer: &mut W,
    cipher: &mut AeadCipher,
    payload: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_PAYLOAD_LENGTH {
        return Err(invalid_input("Shadowsocks AEAD chunk is too large"));
    }
    let sealed_length = cipher.seal(&(payload.len() as u16).to_be_bytes())?;
    let sealed_payload = cipher.seal(payload)?;
    writer.write_all(&sealed_length).await?;
    writer.write_all(&sealed_payload).await?;
    writer.flush().await
}

async fn read_chunk<R>(
    reader: &mut R,
    cipher: &mut AeadCipher,
) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut sealed_length = [0_u8; 2 + TAG_LENGTH];
    reader.read_exact(&mut sealed_length).await?;
    let length = cipher.open(&sealed_length)?;
    let length = u16::from_be_bytes(
        length
            .as_slice()
            .try_into()
            .map_err(|_| invalid_data("invalid Shadowsocks chunk length"))?,
    ) as usize;
    if length > MAX_PAYLOAD_LENGTH {
        return Err(invalid_data("Shadowsocks AEAD chunk is too large"));
    }
    let mut sealed_payload = vec![0_u8; length + TAG_LENGTH];
    reader.read_exact(&mut sealed_payload).await?;
    cipher.open(&sealed_payload)
}

async fn decrypt_stream<R, W>(
    reader: &mut R,
    writer: &mut W,
    key: [u8; SALT_LENGTH],
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut salt = [0_u8; SALT_LENGTH];
    reader.read_exact(&mut salt).await?;
    let mut cipher = AeadCipher::new(&key, &salt)?;
    loop {
        let payload = read_chunk(reader, &mut cipher).await?;
        writer.write_all(&payload).await?;
    }
}

pub fn encode_address(destination: &SocksAddr) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    match destination {
        SocksAddr::Ip(address) => match address.ip() {
            IpAddr::V4(ip) => {
                output.push(0x01);
                output.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                output.push(0x04);
                output.extend_from_slice(&ip.octets());
            }
        },
        SocksAddr::Domain { host, .. } => {
            let length = u8::try_from(host.len()).map_err(|_| {
                invalid_input("Shadowsocks domain is longer than 255 bytes")
            })?;
            output.push(0x03);
            output.push(length);
            output.extend_from_slice(host.as_bytes());
        }
    }
    output.extend_from_slice(&destination.port().to_be_bytes());
    Ok(output)
}

pub fn decode_address(data: &[u8]) -> io::Result<(SocksAddr, usize)> {
    let (host, address_length) = match data.first().copied() {
        Some(0x01) if data.len() >= 7 => (
            std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4])
                .to_string(),
            5,
        ),
        Some(0x04) if data.len() >= 19 => {
            let octets: [u8; 16] = data[1..17].try_into().expect("fixed IPv6");
            (std::net::Ipv6Addr::from(octets).to_string(), 17)
        }
        Some(0x03) if data.len() >= 2 => {
            let length = usize::from(data[1]);
            if data.len() < 2 + length + 2 {
                return Err(invalid_data(
                    "truncated Shadowsocks domain address",
                ));
            }
            let host = std::str::from_utf8(&data[2..2 + length])
                .map_err(|_| invalid_data("invalid Shadowsocks domain UTF-8"))?
                .to_owned();
            (host, 2 + length)
        }
        Some(0x01 | 0x04) => {
            return Err(invalid_data("truncated Shadowsocks IP address"));
        }
        Some(kind) => {
            return Err(invalid_data(format!(
                "unsupported Shadowsocks address type: {kind}"
            )));
        }
        None => return Err(invalid_data("missing Shadowsocks address")),
    };
    let end = address_length + 2;
    if data.len() < end {
        return Err(invalid_data("truncated Shadowsocks address port"));
    }
    let port = u16::from_be_bytes(
        data[address_length..end].try_into().expect("fixed port"),
    );
    Ok((SocksAddr::new(host, port), end))
}

fn evp_bytes_to_key(password: &[u8]) -> [u8; SALT_LENGTH] {
    evp_bytes_to_key_len(password, SALT_LENGTH)
        .try_into()
        .expect("fixed AES-192 key length")
}

fn evp_bytes_to_key_len(password: &[u8], length: usize) -> Vec<u8> {
    let mut key = vec![0_u8; length];
    let mut written = 0;
    let mut previous = Vec::new();
    while written < key.len() {
        let mut digest = Md5::new();
        digest.update(&previous);
        digest.update(password);
        previous = digest.finalize().to_vec();
        let size = (key.len() - written).min(previous.len());
        key[written..written + size].copy_from_slice(&previous[..size]);
        written += size;
    }
    key
}

fn random_salt() -> io::Result<[u8; SALT_LENGTH]> {
    let mut salt = [0_u8; SALT_LENGTH];
    getrandom::fill(&mut salt).map_err(io::Error::other)?;
    Ok(salt)
}

fn random_salt_vec(length: usize) -> io::Result<Vec<u8>> {
    let mut salt = vec![0_u8; length];
    getrandom::fill(&mut salt).map_err(io::Error::other)?;
    Ok(salt)
}

fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_METHODS: [&str; 5] = [
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
    ];

    #[test]
    fn derives_upstream_evp_key_and_round_trips_udp() {
        let method = Aes192GcmMethod::new("password").unwrap();
        assert_eq!(
            hex::encode(method.key()),
            "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374a"
        );
        let salt = [0x11; SALT_LENGTH];
        let destination = SocksAddr::new("target.example", 443);
        let packet =
            method.seal_packet(&salt, &destination, b"payload").unwrap();
        let (decoded, payload) = method.open_packet(&packet).unwrap();
        assert_eq!(decoded, destination);
        assert_eq!(payload, b"payload");
        assert!(method.open_packet(&packet[..packet.len() - 1]).is_err());
    }

    #[test]
    fn server_rejects_replayed_salts_across_packets() {
        let client = Aes192GcmMethod::new("password").unwrap();
        let server = Aes192GcmMethod::new_server("password").unwrap();
        let salt = [0x22; SALT_LENGTH];
        let packet = client
            .seal_packet(&salt, &SocksAddr::new("127.0.0.1", 53), b"dns")
            .unwrap();
        assert!(server.open_packet(&packet).is_ok());
        let error = server.open_packet(&packet).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn decodes_fixed_go_sing_shadowsocks_udp_fixture() {
        // Emitted by github.com/sagernet/sing-shadowsocks@v0.2.8 with
        // shadowaead.New("aes-192-gcm", nil, "password").
        let packet = hex::decode(concat!(
            "6540407eb854b6896f9b7f03453a75744e29f01ee6827c8c",
            "99d22036f4f9c85ad4d37c3865b1d68a1ef990b19badf5c0",
            "c7d9cfe5a401d46e550eb7976eab11870a"
        ))
        .unwrap();
        let method = Aes192GcmMethod::new("password").unwrap();
        let (destination, payload) = method.open_packet(&packet).unwrap();
        assert_eq!(destination, SocksAddr::new("target.example", 443));
        assert_eq!(payload, b"payload");
    }

    #[tokio::test]
    async fn decodes_fixed_go_sing_shadowsocks_tcp_fixture() {
        let wire_bytes = hex::decode(concat!(
            "7956c0219c63da5a054c5d3881c43ce35d18374e5e0071d9",
            "d5496c500f55543040e4b16b9889fc8d64240a7c9a8b9d84",
            "a469988ee18fe4e8249f006ec089804bf8e55a7c1e3882543e",
            "0bd4a53650d37bd278e6"
        ))
        .unwrap();
        let method = Aes192GcmMethod::new_server("password").unwrap();
        let (mut wire, incoming) = tokio::io::duplex(1024);
        wire.write_all(&wire_bytes).await.unwrap();
        let (destination, mut stream) =
            method.accept_stream(incoming).await.unwrap();
        assert_eq!(destination, SocksAddr::new("target.example", 443));
        let mut payload = [0_u8; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
    }

    #[tokio::test]
    async fn client_and_server_streams_interoperate() {
        let method = Aes192GcmMethod::new("secret").unwrap();
        let destination = SocksAddr::new("target.example", 8443);
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mut client =
            method.wrap_client_stream(Box::new(client), destination.clone());
        let server_method = method.clone();
        let task = tokio::spawn(async move {
            let (accepted, mut server) =
                server_method.accept_stream(server).await.unwrap();
            assert_eq!(accepted, destination);
            let mut request = [0_u8; 7];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"request");
            server.write_all(b"response").await.unwrap();
        });
        client.write_all(b"request").await.unwrap();
        let mut response = [0_u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn legacy_multi_user_authenticates_all_supported_methods() {
        for (method_index, method_name) in LEGACY_METHODS.iter().enumerate() {
            let kind = LegacyAeadKind::parse(method_name).unwrap();
            let bob = LegacyAeadMethod::new(kind, "bob-secret").unwrap();
            let server = MultiLegacyAeadServer::new(
                method_name,
                [
                    ("alice".to_owned(), "alice-secret".to_owned()),
                    ("bob".to_owned(), "bob-secret".to_owned()),
                ],
            )
            .unwrap();
            let destination = SocksAddr::new("target.example", 8443);
            let salt = vec![0x31 + method_index as u8; kind.key_length()];
            let mut cipher = bob.cipher(&salt).unwrap();
            let mut first = encode_address(&destination).unwrap();
            first.extend_from_slice(b"request");
            let mut wire_bytes = salt;
            wire_bytes.extend_from_slice(
                &cipher.seal(&(first.len() as u16).to_be_bytes()).unwrap(),
            );
            wire_bytes.extend_from_slice(&cipher.seal(&first).unwrap());

            let (mut client_raw, server_raw) = tokio::io::duplex(4096);
            client_raw.write_all(&wire_bytes).await.unwrap();
            let (user, accepted, mut application) =
                server.accept_stream(server_raw).await.unwrap();
            assert_eq!(user, "bob", "method {method_name}");
            assert_eq!(accepted, destination, "method {method_name}");
            let mut request = [0_u8; 7];
            application.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"request", "method {method_name}");

            application.write_all(b"response").await.unwrap();
            let mut response_salt = vec![0_u8; kind.key_length()];
            client_raw.read_exact(&mut response_salt).await.unwrap();
            let mut response_cipher = bob.cipher(&response_salt).unwrap();
            let response =
                read_legacy_chunk(&mut client_raw, &mut response_cipher)
                    .await
                    .unwrap();
            assert_eq!(response, b"response", "method {method_name}");
        }
    }

    #[test]
    fn legacy_multi_user_udp_authenticates_and_encrypts_all_methods() {
        for (method_index, method_name) in LEGACY_METHODS.iter().enumerate() {
            let kind = LegacyAeadKind::parse(method_name).unwrap();
            let alice = LegacyAeadMethod::new(kind, "alice-secret").unwrap();
            let bob = LegacyAeadMethod::new(kind, "bob-secret").unwrap();
            let server = MultiLegacyAeadServer::new(
                method_name,
                [
                    ("alice".to_owned(), "alice-secret".to_owned()),
                    ("bob".to_owned(), "bob-secret".to_owned()),
                ],
            )
            .unwrap();
            let destination = SocksAddr::new("1.1.1.1", 53);
            let salt = vec![0x41 + method_index as u8; kind.key_length()];
            let packet =
                bob.seal_packet(&salt, &destination, b"query").unwrap();
            let (index, user, decoded, payload) =
                server.open_packet(&packet).unwrap();
            assert_eq!(index, 1, "method {method_name}");
            assert_eq!(user, "bob", "method {method_name}");
            assert_eq!(decoded, destination, "method {method_name}");
            assert_eq!(payload, b"query", "method {method_name}");

            let response =
                server.seal_packet(index, &destination, b"answer").unwrap();
            let response_salt_length = kind.key_length();
            let response_salt = &response[..response_salt_length];
            let mut response_cipher = bob.cipher(response_salt).unwrap();
            let plaintext = response_cipher
                .open(&response[response_salt_length..])
                .unwrap();
            let (source, address_length) = decode_address(&plaintext).unwrap();
            assert_eq!(source, destination, "method {method_name}");
            assert_eq!(&plaintext[address_length..], b"answer");

            let wrong_salt = vec![0x51 + method_index as u8; kind.key_length()];
            let wrong = alice
                .seal_packet(&wrong_salt, &destination, b"wrong user")
                .unwrap();
            let (wrong_index, wrong_user, _, _) =
                server.open_packet(&wrong).unwrap();
            assert_eq!(wrong_index, 0);
            assert_eq!(wrong_user, "alice");
        }
    }
}
