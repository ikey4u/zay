//! Persistent Tailscale node credentials and control request construction.
//!
//! The on-disk JSON intentionally matches Tailscale's `control/tsp.NodeFile`
//! format so credentials can be inspected and moved with upstream tooling.
//! Disco keys are deliberately runtime-only, matching magicsock's lifecycle.

use std::{
    collections::BTreeMap,
    fmt, io,
    path::{Path, PathBuf},
    str::FromStr,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use tokio::io::AsyncWriteExt as _;
use zeroize::Zeroize;

use super::{
    tailscale::tailscale_node_public_key,
    tailscale_control_types::{
        TailscaleDiscoPublicKey, TailscaleHostinfo, TailscaleMachinePublicKey,
        TailscaleMapRequest, TailscaleNodePublicKey, TailscaleRegisterRequest,
        TailscaleRegisterResponseAuth,
    },
    tailscale_disco::tailscale_disco_public_key,
    tailscale_tka::{TailscaleNetworkLockPrivateKey, TailscaleTkaError},
    tailscale_tka_authority::{
        TailscaleTkaAuthority, TailscaleTkaAuthorityError,
    },
};

pub const TAILSCALE_DEFAULT_CONTROL_URL: &str =
    "https://controlplane.tailscale.com";
pub const TAILSCALE_NODE_FILE_NAME: &str = "tailscale-node.json";
pub const TAILSCALE_TKA_FILE_NAME: &str = "tailscale-tka.json";
const PRIVATE_KEY_PREFIX: &str = "privkey:";

/// A Tailscale X25519 private key. Debug output is always redacted and owned
/// values are zeroed on drop.
#[derive(Clone)]
pub struct TailscalePrivateKey([u8; 32]);

impl TailscalePrivateKey {
    pub fn generate() -> Result<Self, TailscaleStateError> {
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key)
            .map_err(|error| TailscaleStateError::Random(error.to_string()))?;
        clamp_x25519(&mut key);
        Ok(Self(key))
    }

    pub fn from_bytes(key: [u8; 32]) -> Result<Self, TailscaleStateError> {
        if key == [0; 32] {
            return Err(TailscaleStateError::ZeroPrivateKey);
        }
        Ok(Self(key))
    }

    pub fn expose_secret(&self) -> [u8; 32] {
        self.0
    }

    pub fn public_bytes(&self) -> Result<[u8; 32], TailscaleStateError> {
        tailscale_node_public_key(self.0)
            .map_err(|error| TailscaleStateError::Key(error.to_string()))
    }

    pub fn node_public_key(
        &self,
    ) -> Result<TailscaleNodePublicKey, TailscaleStateError> {
        Ok(TailscaleNodePublicKey::from_bytes(self.public_bytes()?))
    }

    pub fn machine_public_key(
        &self,
    ) -> Result<TailscaleMachinePublicKey, TailscaleStateError> {
        Ok(TailscaleMachinePublicKey::from_bytes(self.public_bytes()?))
    }

    pub fn disco_public_key(
        &self,
    ) -> Result<TailscaleDiscoPublicKey, TailscaleStateError> {
        let public = tailscale_disco_public_key(self.0)
            .map_err(|error| TailscaleStateError::Key(error.to_string()))?;
        Ok(TailscaleDiscoPublicKey::from_bytes(public))
    }
}

impl Drop for TailscalePrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for TailscalePrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TailscalePrivateKey([REDACTED])")
    }
}

impl fmt::Display for TailscalePrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{PRIVATE_KEY_PREFIX}{}", hex::encode(self.0))
    }
}

impl FromStr for TailscalePrivateKey {
    type Err = TailscaleStateError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value
            .strip_prefix(PRIVATE_KEY_PREFIX)
            .ok_or(TailscaleStateError::InvalidPrivateKey)?;
        let mut key = [0_u8; 32];
        hex::decode_to_slice(value, &mut key)
            .map_err(|_| TailscaleStateError::InvalidPrivateKey)?;
        Self::from_bytes(key)
    }
}

impl Serialize for TailscalePrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TailscalePrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// JSON-compatible equivalent of Tailscale's `control/tsp.NodeFile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleNodeFile {
    pub node_key: TailscalePrivateKey,
    pub machine_key: TailscalePrivateKey,
    pub server_url: String,
    pub server_key: TailscaleMachinePublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleTkaState {
    pub network_lock_key: TailscaleNetworkLockPrivateKey,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "base64_byte_arrays"
    )]
    pub authority_aums: Vec<Vec<u8>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub authority_aum_created_unix: BTreeMap<String, i64>,
}

impl TailscaleTkaState {
    pub fn authority(
        &self,
    ) -> Result<Option<TailscaleTkaAuthority>, TailscaleStateError> {
        if self.authority_aums.is_empty() {
            return Ok(None);
        }
        Ok(Some(TailscaleTkaAuthority::from_archive_with_commit_times(
            &self.authority_aums,
            &self.authority_aum_created_unix,
        )?))
    }

    pub fn set_authority(
        &mut self,
        authority: Option<&TailscaleTkaAuthority>,
    ) -> Result<(), TailscaleStateError> {
        self.authority_aums = authority
            .map(TailscaleTkaAuthority::archive)
            .transpose()?
            .unwrap_or_default();
        self.authority_aum_created_unix = authority
            .map(TailscaleTkaAuthority::commit_times_unix)
            .unwrap_or_default();
        Ok(())
    }
}

/// Pending node-key replacement. The old identity remains active until the
/// control server accepts the request and [`TailscaleNodeStateStore::commit_rotation`]
/// persists the replacement atomically.
#[derive(Debug, Clone)]
pub struct TailscaleNodeKeyRotation {
    old_node_key: TailscaleNodePublicKey,
    new_node_key: TailscalePrivateKey,
}

impl TailscaleNodeKeyRotation {
    pub fn old_node_key(&self) -> TailscaleNodePublicKey {
        self.old_node_key
    }

    pub fn new_node_key(&self) -> TailscaleNodePublicKey {
        self.new_node_key
            .node_public_key()
            .expect("validated Tailscale node private key")
    }

    pub fn new_private_key(&self) -> [u8; 32] {
        self.new_node_key.expose_secret()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_request(
        &self,
        version: u32,
        auth_key: impl Into<String>,
        ephemeral: bool,
        followup: impl Into<String>,
        node_key_signature: Option<Vec<u8>>,
        hostinfo: Option<TailscaleHostinfo>,
    ) -> TailscaleRegisterRequest {
        let auth_key = auth_key.into();
        TailscaleRegisterRequest {
            version,
            old_node_key: self.old_node_key,
            node_key: self.new_node_key(),
            auth: (!auth_key.is_empty()).then_some(
                TailscaleRegisterResponseAuth {
                    auth_key,
                    ..Default::default()
                },
            ),
            followup: followup.into(),
            ephemeral,
            node_key_signature,
            hostinfo,
            ..Default::default()
        }
    }
}

impl TailscaleNodeFile {
    pub fn generate(
        server_url: impl Into<String>,
        server_key: TailscaleMachinePublicKey,
    ) -> Result<Self, TailscaleStateError> {
        let node_file = Self {
            node_key: TailscalePrivateKey::generate()?,
            machine_key: TailscalePrivateKey::generate()?,
            server_url: normalize_control_url(&server_url.into())?,
            server_key,
        };
        node_file.validate()?;
        Ok(node_file)
    }

    pub fn validate(&self) -> Result<(), TailscaleStateError> {
        normalize_control_url(&self.server_url)?;
        if self.server_key.is_zero() {
            return Err(TailscaleStateError::ZeroServerKey);
        }
        if self.node_key.expose_secret() == [0; 32]
            || self.machine_key.expose_secret() == [0; 32]
        {
            return Err(TailscaleStateError::ZeroPrivateKey);
        }
        Ok(())
    }

    pub fn begin_node_key_rotation(
        &self,
    ) -> Result<TailscaleNodeKeyRotation, TailscaleStateError> {
        Ok(TailscaleNodeKeyRotation {
            old_node_key: self.node_key.node_public_key()?,
            new_node_key: TailscalePrivateKey::generate()?,
        })
    }

    pub fn register_request(
        &self,
        version: u32,
        auth_key: impl Into<String>,
        ephemeral: bool,
        hostinfo: Option<TailscaleHostinfo>,
    ) -> Result<TailscaleRegisterRequest, TailscaleStateError> {
        let auth_key = auth_key.into();
        Ok(TailscaleRegisterRequest {
            version,
            node_key: self.node_key.node_public_key()?,
            auth: (!auth_key.is_empty()).then_some(
                TailscaleRegisterResponseAuth {
                    auth_key,
                    ..Default::default()
                },
            ),
            ephemeral,
            hostinfo,
            ..Default::default()
        })
    }

    pub fn map_request(
        &self,
        version: u32,
        disco_key: TailscaleDiscoPublicKey,
        hostinfo: Option<TailscaleHostinfo>,
        endpoints: Vec<String>,
    ) -> Result<TailscaleMapRequest, TailscaleStateError> {
        Ok(TailscaleMapRequest {
            version,
            compress: "zstd".into(),
            keep_alive: true,
            node_key: self.node_key.node_public_key()?,
            disco_key,
            stream: true,
            hostinfo,
            endpoints,
            ..Default::default()
        })
    }
}

#[derive(Debug, Clone)]
pub struct TailscaleNodeStateStore {
    path: PathBuf,
}

impl TailscaleNodeStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn from_directory(directory: impl AsRef<Path>) -> Self {
        Self::new(directory.as_ref().join(TAILSCALE_NODE_FILE_NAME))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn tka_path(&self) -> PathBuf {
        self.path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(TAILSCALE_TKA_FILE_NAME)
    }

    pub async fn load(&self) -> Result<TailscaleNodeFile, TailscaleStateError> {
        let bytes = tokio::fs::read(&self.path).await?;
        let node_file: TailscaleNodeFile = serde_json::from_slice(&bytes)?;
        node_file.validate()?;
        Ok(node_file)
    }

    pub async fn save(
        &self,
        node_file: &TailscaleNodeFile,
    ) -> Result<(), TailscaleStateError> {
        node_file.validate()?;
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        tokio::fs::create_dir_all(parent).await?;
        restrict_directory_permissions(parent).await?;

        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix)
            .map_err(|error| TailscaleStateError::Random(error.to_string()))?;
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(TAILSCALE_NODE_FILE_NAME);
        let temporary =
            parent.join(format!(".{file_name}.{}.tmp", hex::encode(suffix)));
        let body = serde_json::to_vec_pretty(node_file)?;
        let result = async {
            let mut options = tokio::fs::OpenOptions::new();
            options.write(true).create_new(true);
            set_private_file_mode(&mut options);
            let mut file = options.open(&temporary).await?;
            file.write_all(&body).await?;
            file.write_all(b"\n").await?;
            file.sync_all().await?;
            drop(file);
            tokio::fs::rename(&temporary, &self.path).await?;
            restrict_file_permissions(&self.path).await?;
            Ok::<_, io::Error>(())
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
        }
        result?;
        Ok(())
    }

    pub async fn commit_rotation(
        &self,
        node_file: &mut TailscaleNodeFile,
        rotation: TailscaleNodeKeyRotation,
    ) -> Result<(), TailscaleStateError> {
        if node_file.node_key.node_public_key()? != rotation.old_node_key {
            return Err(TailscaleStateError::StaleNodeKeyRotation);
        }
        let mut updated = node_file.clone();
        updated.node_key = rotation.new_node_key;
        self.save(&updated).await?;
        *node_file = updated;
        Ok(())
    }

    pub async fn load_or_create(
        &self,
        server_url: &str,
        server_key: TailscaleMachinePublicKey,
    ) -> Result<TailscaleNodeFile, TailscaleStateError> {
        let expected_url = normalize_control_url(server_url)?;
        match self.load().await {
            Ok(node_file) => {
                if node_file.server_url != expected_url
                    || node_file.server_key != server_key
                {
                    return Err(TailscaleStateError::ControlServerMismatch);
                }
                Ok(node_file)
            }
            Err(TailscaleStateError::Io(error))
                if error.kind() == io::ErrorKind::NotFound =>
            {
                let node_file =
                    TailscaleNodeFile::generate(expected_url, server_key)?;
                self.save(&node_file).await?;
                Ok(node_file)
            }
            Err(error) => Err(error),
        }
    }

    pub async fn load_or_create_tka(
        &self,
    ) -> Result<TailscaleTkaState, TailscaleStateError> {
        let path = self.tka_path();
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let mut state: TailscaleTkaState =
                    serde_json::from_slice(&bytes)?;
                let authority = state.authority()?;
                let normalized_commit_times = authority
                    .as_ref()
                    .map(TailscaleTkaAuthority::commit_times_unix)
                    .unwrap_or_default();
                if state.authority_aum_created_unix != normalized_commit_times {
                    state.set_authority(authority.as_ref())?;
                    self.save_tka(&state).await?;
                }
                Ok(state)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let state = TailscaleTkaState {
                    network_lock_key: TailscaleNetworkLockPrivateKey::generate(
                    )?,
                    authority_aums: Vec::new(),
                    authority_aum_created_unix: BTreeMap::new(),
                };
                self.save_tka(&state).await?;
                Ok(state)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn save_tka(
        &self,
        state: &TailscaleTkaState,
    ) -> Result<(), TailscaleStateError> {
        state.authority()?;
        let path = self.tka_path();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        tokio::fs::create_dir_all(parent).await?;
        restrict_directory_permissions(parent).await?;
        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix)
            .map_err(|error| TailscaleStateError::Random(error.to_string()))?;
        let temporary = parent.join(format!(
            ".{TAILSCALE_TKA_FILE_NAME}.{}.tmp",
            hex::encode(suffix)
        ));
        let body = serde_json::to_vec_pretty(state)?;
        let result = async {
            let mut options = tokio::fs::OpenOptions::new();
            options.write(true).create_new(true);
            set_private_file_mode(&mut options);
            let mut file = options.open(&temporary).await?;
            file.write_all(&body).await?;
            file.write_all(b"\n").await?;
            file.sync_all().await?;
            drop(file);
            tokio::fs::rename(&temporary, &path).await?;
            restrict_file_permissions(&path).await
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
        }
        result?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum TailscaleStateError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid Tailscale node file JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid Tailscale private key")]
    InvalidPrivateKey,
    #[error("Tailscale private key cannot be zero")]
    ZeroPrivateKey,
    #[error("Tailscale control server key cannot be zero")]
    ZeroServerKey,
    #[error("invalid Tailscale control URL: {0}")]
    InvalidControlUrl(String),
    #[error(
        "stored Tailscale credentials belong to a different control server"
    )]
    ControlServerMismatch,
    #[error("Tailscale node-key rotation no longer matches active identity")]
    StaleNodeKeyRotation,
    #[error("Tailscale key operation failed: {0}")]
    Key(String),
    #[error("operating-system randomness failed: {0}")]
    Random(String),
    #[error(transparent)]
    Tka(#[from] TailscaleTkaError),
    #[error(transparent)]
    TkaAuthority(#[from] TailscaleTkaAuthorityError),
}

mod base64_byte_arrays {
    use super::*;

    pub fn serialize<S>(
        arrays: &[Vec<u8>],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        arrays
            .iter()
            .map(|bytes| STANDARD.encode(bytes))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|value| {
                STANDARD.decode(value).map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

fn normalize_control_url(value: &str) -> Result<String, TailscaleStateError> {
    let value = if value.is_empty() {
        TAILSCALE_DEFAULT_CONTROL_URL
    } else {
        value
    };
    let mut url = url::Url::parse(value).map_err(|error| {
        TailscaleStateError::InvalidControlUrl(error.to_string())
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(TailscaleStateError::InvalidControlUrl(
            "expected an http(s) URL with a host".into(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(TailscaleStateError::InvalidControlUrl(
            "query and fragment are not allowed".into(),
        ));
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(TailscaleStateError::InvalidControlUrl(
            "base URL must not contain a path".into(),
        ));
    }
    url.set_path("");
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn clamp_x25519(key: &mut [u8; 32]) {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
}

#[cfg(unix)]
fn set_private_file_mode(options: &mut tokio::fs::OpenOptions) {
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_file_mode(_options: &mut tokio::fs::OpenOptions) {}

#[cfg(unix)]
async fn restrict_file_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
}

#[cfg(not(unix))]
async fn restrict_file_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
async fn restrict_directory_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .await
}

#[cfg(not(unix))]
async fn restrict_directory_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_key(byte: u8) -> TailscaleMachinePublicKey {
        TailscaleMachinePublicKey::from_bytes([byte; 32])
    }

    #[test]
    fn private_key_uses_upstream_text_format_and_redacted_debug() {
        let key = TailscalePrivateKey::from_bytes([7; 32]).unwrap();
        let encoded = serde_json::to_string(&key).unwrap();
        assert!(encoded.starts_with("\"privkey:"));
        assert_eq!(
            serde_json::from_str::<TailscalePrivateKey>(&encoded)
                .unwrap()
                .expose_secret(),
            key.expose_secret()
        );
        assert_eq!(format!("{key:?}"), "TailscalePrivateKey([REDACTED])");
    }

    #[tokio::test]
    async fn node_file_round_trips_atomically_with_private_permissions() {
        let temporary = tempfile::tempdir().unwrap();
        let store = TailscaleNodeStateStore::from_directory(temporary.path());
        let created = store
            .load_or_create("https://control.example/", server_key(9))
            .await
            .unwrap();
        let loaded = store.load().await.unwrap();
        assert_eq!(loaded.server_url, "https://control.example");
        assert_eq!(
            loaded.node_key.expose_secret(),
            created.node_key.expose_secret()
        );
        assert_eq!(
            loaded.machine_key.expose_secret(),
            created.machine_key.expose_secret()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(store.path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(matches!(
            store
                .load_or_create("https://other.example", server_key(9))
                .await,
            Err(TailscaleStateError::ControlServerMismatch)
        ));

        let tka = store.load_or_create_tka().await.unwrap();
        let loaded_tka = store.load_or_create_tka().await.unwrap();
        assert_eq!(
            tka.network_lock_key.public_key(),
            loaded_tka.network_lock_key.public_key()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(store.tka_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn builds_register_and_streaming_map_requests() {
        let node_file = TailscaleNodeFile {
            node_key: TailscalePrivateKey::from_bytes([1; 32]).unwrap(),
            machine_key: TailscalePrivateKey::from_bytes([2; 32]).unwrap(),
            server_url: "https://control.example".into(),
            server_key: server_key(3),
        };
        let hostinfo = TailscaleHostinfo {
            hostname: "rust-node".into(),
            ..Default::default()
        };
        let register = node_file
            .register_request(
                142,
                "tskey-auth-test",
                true,
                Some(hostinfo.clone()),
            )
            .unwrap();
        assert_eq!(register.version, 142);
        assert!(register.ephemeral);
        assert_eq!(register.auth.unwrap().auth_key, "tskey-auth-test");
        let disco = TailscalePrivateKey::from_bytes([4; 32])
            .unwrap()
            .disco_public_key()
            .unwrap();
        let map = node_file
            .map_request(
                142,
                disco,
                Some(hostinfo),
                vec!["192.0.2.1:41641".into()],
            )
            .unwrap();
        assert_eq!(map.compress, "zstd");
        assert!(map.keep_alive && map.stream);
        assert_eq!(map.endpoints, vec!["192.0.2.1:41641"]);
    }

    #[tokio::test]
    async fn node_key_rotation_keeps_old_identity_until_atomic_commit() {
        let temporary = tempfile::tempdir().unwrap();
        let store = TailscaleNodeStateStore::from_directory(temporary.path());
        let mut node_file = TailscaleNodeFile {
            node_key: TailscalePrivateKey::from_bytes([1; 32]).unwrap(),
            machine_key: TailscalePrivateKey::from_bytes([2; 32]).unwrap(),
            server_url: "https://control.example".into(),
            server_key: server_key(3),
        };
        store.save(&node_file).await.unwrap();
        let old_private = node_file.node_key.expose_secret();
        let rotation = node_file.begin_node_key_rotation().unwrap();
        let request = rotation.register_request(
            142,
            "tskey-auth-test",
            false,
            "https://login.example/followup",
            Some(vec![1, 2, 3]),
            None,
        );
        assert_eq!(request.old_node_key, rotation.old_node_key());
        assert_eq!(request.node_key, rotation.new_node_key());
        assert_eq!(request.followup, "https://login.example/followup");
        assert_eq!(request.node_key_signature, Some(vec![1, 2, 3]));
        assert_eq!(node_file.node_key.expose_secret(), old_private);
        assert_eq!(
            store.load().await.unwrap().node_key.expose_secret(),
            old_private
        );

        let new_private = rotation.new_private_key();
        store
            .commit_rotation(&mut node_file, rotation)
            .await
            .unwrap();
        assert_eq!(node_file.node_key.expose_secret(), new_private);
        assert_eq!(
            store.load().await.unwrap().node_key.expose_secret(),
            new_private
        );

        let stale = TailscaleNodeKeyRotation {
            old_node_key: TailscalePrivateKey::from_bytes([9; 32])
                .unwrap()
                .node_public_key()
                .unwrap(),
            new_node_key: TailscalePrivateKey::from_bytes([8; 32]).unwrap(),
        };
        assert!(matches!(
            store.commit_rotation(&mut node_file, stale).await,
            Err(TailscaleStateError::StaleNodeKeyRotation)
        ));
        assert_eq!(node_file.node_key.expose_secret(), new_private);
    }
}
