//! Taildrop file-transfer client over a peer's in-tailnet HTTP PeerAPI.

use std::{
    collections::{HashMap, HashSet},
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use futures_util::TryStreamExt as _;
use http_body_util::{BodyExt as _, Empty, Full, StreamBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    client::conn::http1,
};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncSeek, AsyncSeekExt as _,
    AsyncWriteExt as _, ReadBuf, SeekFrom,
};
use tokio::sync::{Mutex, broadcast};
use tokio_util::io::{ReaderStream, StreamReader};
use tokio_util::sync::CancellationToken;

use crate::{adapter::Dialer, common::network::SocksAddr};

use super::tailscale_control_types::{TailscaleNetmapState, TailscaleNode};

pub const TAILSCALE_TAILDROP_BLOCK_SIZE: usize = 64 << 10;
pub const TAILSCALE_TAILDROP_PARTIAL_SUFFIX: &str = ".partial";
pub const TAILSCALE_TAILDROP_DELETED_SUFFIX: &str = ".deleted";
pub const TAILSCALE_TAILDROP_DELETE_DELAY: Duration = Duration::from_secs(3600);
pub const TAILSCALE_TAILDROP_DELETE_RETRY_DELAY: Duration =
    Duration::from_secs(5);
pub const TAILSCALE_TAILDROP_REJECT_DRAIN_TIMEOUT: Duration =
    Duration::from_secs(3);
pub const TAILSCALE_TAILDROP_NOTIFICATION_TYPE_ID: u32 = 11;
pub const TAILSCALE_TAILDROP_NOTIFICATION_TYPE_NAME: &str =
    "Taildrop Notifications";
pub const TAILSCALE_TAILDROP_NOTIFICATION_TITLE: &str = "Taildrop";
pub const TAILSCALE_CAPABILITY_FILE_SHARING: &str =
    "https://tailscale.com/cap/file-sharing";
pub const TAILSCALE_PEER_CAPABILITY_FILE_SHARING_TARGET: &str =
    "https://tailscale.com/cap/file-sharing-target";
pub const TAILSCALE_PEER_CAPABILITY_FILE_SHARING_SEND: &str =
    "https://tailscale.com/cap/file-send";

#[derive(Debug, Error)]
pub enum TailscaleTaildropError {
    #[error("taildrop: invalid filename")]
    InvalidFileName,
    #[error("taildrop: not connected to the tailnet")]
    NotConnected,
    #[error("taildrop: file sharing not enabled by Tailscale admin")]
    FileSharingDisabled,
    #[error("taildrop: peer not found: {0}")]
    PeerNotFound(String),
    #[error("taildrop: peer cannot receive files")]
    PeerCannotReceive,
    #[error("taildrop: peer is not a permitted file target")]
    PeerNotPermitted,
    #[error("taildrop: peer does not support peer API")]
    PeerApiUnavailable,
    #[error("taildrop: peer responded HTTP {status}: {message}")]
    PeerResponse { status: u16, message: String },
    #[error("taildrop: file already exists")]
    FileExists,
    #[error("taildrop: canceled by receiver")]
    Canceled,
    #[error(
        "taildrop: offset {offset} out of range for {size}-byte partial file"
    )]
    OffsetOutOfRange { offset: u64, size: u64 },
    #[error("taildrop: copied {actual} bytes, expected {expected}")]
    LengthMismatch { actual: u64, expected: u64 },
    #[error("taildrop: too many rename attempts for {0}")]
    TooManyRenameAttempts(String),
    #[error("taildrop: receiver is closed")]
    Closed,
    #[error("taildrop: HTTP failed: {0}")]
    Http(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleTaildropBlockChecksum {
    pub checksum: String,
    #[serde(rename = "algo")]
    pub algorithm: String,
    pub size: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleTaildropTarget {
    pub stable_id: String,
    pub name: String,
    pub destination: std::net::SocketAddr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleTaildropPeerAccess {
    pub stable_id: String,
    pub name: String,
    pub unsigned_peer_api_only: bool,
    pub self_untagged: bool,
    pub peer_capabilities: HashSet<String>,
    pub self_file_sharing_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleTaildropFile {
    pub name: String,
    pub size: u64,
    pub sender_name: String,
    pub modified_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleTaildropReceivingFile {
    pub name: String,
    /// `-1` means that the sender did not declare a content length.
    pub size: i64,
    pub received_bytes: u64,
    pub sender_id: String,
    pub sender_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleTaildropInbox {
    pub files: Vec<TailscaleTaildropFile>,
    pub receiving: Vec<TailscaleTaildropReceivingFile>,
}

/// Semantic Taildrop notification events for the embedding application.
///
/// The library deliberately does not display platform notifications itself.
/// zay can localize and present these events using
/// [`TAILSCALE_TAILDROP_NOTIFICATION_TYPE_ID`] and related metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleTaildropEvent {
    IncomingStarted {
        file_name: String,
        sender_id: String,
        sender_name: String,
        total_size: Option<u64>,
    },
    FileReceived {
        file_name: String,
        sender_id: String,
        sender_name: String,
        size: u64,
    },
    IncomingStopped {
        file_name: String,
        sender_id: String,
    },
}

impl TailscaleTaildropEvent {
    /// The upstream notification name, before the endpoint tag is prefixed.
    pub fn notification_name(&self) -> String {
        match self {
            Self::IncomingStarted {
                file_name,
                sender_id,
                ..
            }
            | Self::IncomingStopped {
                file_name,
                sender_id,
            } => format!("receiving/{sender_id}/{file_name}"),
            Self::FileReceived { file_name, .. } => file_name.clone(),
        }
    }

    /// Build the exact upstream platform notification identifier.
    pub fn notification_identifier(&self, endpoint_tag: &str) -> String {
        format!("taildrop/{endpoint_tag}/{}", self.notification_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TaildropIncomingKey {
    sender_id: String,
    name: String,
}

struct TaildropIncoming {
    sender_name: String,
    started: SystemTime,
    size: i64,
    copied: AtomicU64,
    cancellation: CancellationToken,
}

#[derive(Default)]
struct TaildropReceiverState {
    closed: bool,
    incoming: HashMap<TaildropIncomingKey, Arc<TaildropIncoming>>,
    sender_names: HashMap<String, String>,
    unread_files: HashSet<String>,
}

struct TailscaleTaildropReceiverInner {
    directory: PathBuf,
    state: Mutex<TaildropReceiverState>,
    rename: Mutex<()>,
    updates: broadcast::Sender<()>,
    events: broadcast::Sender<TailscaleTaildropEvent>,
}

/// Persistent Taildrop inbox and resumable incoming-transfer manager.
///
/// The receiver stores an upload as `{name}.{sender_id}.partial`, so two peers
/// cannot resume or overwrite one another's transfer.  Completed files are
/// atomically renamed into the inbox and conflicting names follow Tailscale's
/// `name (N).ext` convention.
#[derive(Clone)]
pub struct TailscaleTaildropReceiver {
    inner: Arc<TailscaleTaildropReceiverInner>,
}

impl TailscaleTaildropReceiver {
    pub fn from_directory(directory: impl Into<PathBuf>) -> Self {
        let (updates, _) = broadcast::channel(1);
        let (events, _) = broadcast::channel(64);
        Self {
            inner: Arc::new(TailscaleTaildropReceiverInner {
                directory: directory.into(),
                state: Mutex::new(TaildropReceiverState::default()),
                rename: Mutex::new(()),
                updates,
                events,
            }),
        }
    }

    pub async fn new(
        directory: impl Into<PathBuf>,
    ) -> Result<Self, TailscaleTaildropError> {
        let receiver = Self::from_directory(directory);
        receiver.start().await?;
        Ok(receiver)
    }

    pub async fn start(&self) -> Result<(), TailscaleTaildropError> {
        tokio::fs::create_dir_all(&self.inner.directory).await?;
        self.inner.state.lock().await.closed = false;
        self.remove_expired_artifacts().await?;
        Ok(())
    }

    pub fn directory(&self) -> &Path {
        &self.inner.directory
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.inner.updates.subscribe()
    }

    pub fn subscribe_events(
        &self,
    ) -> broadcast::Receiver<TailscaleTaildropEvent> {
        self.inner.events.subscribe()
    }

    pub async fn close(&self) {
        let mut state = self.inner.state.lock().await;
        state.closed = true;
        for incoming in state.incoming.values() {
            incoming.cancellation.cancel();
        }
        drop(state);
        self.notify();
    }

    pub async fn put_file<R>(
        &self,
        sender_id: &str,
        sender_name: &str,
        base_name: &str,
        mut content: R,
        offset: u64,
        declared_length: Option<u64>,
    ) -> Result<String, TailscaleTaildropError>
    where
        R: AsyncRead + Unpin,
    {
        validate_tailscale_taildrop_file_name(base_name)?;
        validate_tailscale_taildrop_file_name(sender_id).map_err(|_| {
            TailscaleTaildropError::Http("invalid peer identity".into())
        })?;
        let key = TaildropIncomingKey {
            sender_id: sender_id.into(),
            name: base_name.into(),
        };
        let total_size = declared_length
            .and_then(|length| offset.checked_add(length))
            .and_then(|size| i64::try_from(size).ok());
        let incoming = Arc::new(TaildropIncoming {
            sender_name: sender_name.into(),
            started: SystemTime::now(),
            size: total_size.unwrap_or(-1),
            copied: AtomicU64::new(offset),
            cancellation: CancellationToken::new(),
        });
        {
            let mut state = self.inner.state.lock().await;
            if state.closed {
                return Err(TailscaleTaildropError::Closed);
            }
            if state.incoming.contains_key(&key) {
                return Err(TailscaleTaildropError::FileExists);
            }
            state.incoming.insert(key.clone(), incoming.clone());
        }
        self.notify();
        self.send_event(TailscaleTaildropEvent::IncomingStarted {
            file_name: base_name.into(),
            sender_id: sender_id.into(),
            sender_name: sender_name.into(),
            total_size: total_size.map(|size| size as u64),
        });

        let partial_name = partial_file_name(base_name, sender_id);
        let partial_path = self.inner.directory.join(&partial_name);
        let result = self
            .write_partial(
                &partial_path,
                &incoming,
                &mut content,
                offset,
                declared_length,
            )
            .await;
        let result = match result {
            Ok(()) => {
                match self.rename_partial(&partial_path, base_name).await {
                    Ok(final_name) => {
                        let mut state = self.inner.state.lock().await;
                        state
                            .sender_names
                            .insert(final_name.clone(), sender_name.into());
                        state.unread_files.insert(final_name.clone());
                        drop(state);
                        self.notify();
                        let size = tokio::fs::metadata(
                            self.inner.directory.join(&final_name),
                        )
                        .await
                        .map(|metadata| metadata.len())
                        .unwrap_or_else(|_| {
                            total_size.map(|size| size as u64).unwrap_or(offset)
                        });
                        self.send_event(TailscaleTaildropEvent::FileReceived {
                            file_name: final_name.clone(),
                            sender_id: sender_id.into(),
                            sender_name: sender_name.into(),
                            size,
                        });
                        Ok(final_name)
                    }
                    Err(error) => Err(error),
                }
            }
            Err(TailscaleTaildropError::Canceled) => {
                let _ = tokio::fs::remove_file(&partial_path).await;
                Err(TailscaleTaildropError::Canceled)
            }
            Err(error) => Err(error),
        };
        self.inner.state.lock().await.incoming.remove(&key);
        if result.is_err()
            && !matches!(&result, Err(TailscaleTaildropError::Canceled))
        {
            self.schedule_artifact_delete(
                partial_path,
                Some(key.clone()),
                TAILSCALE_TAILDROP_DELETE_DELAY,
            );
        }
        self.notify();
        self.send_event(TailscaleTaildropEvent::IncomingStopped {
            file_name: base_name.into(),
            sender_id: sender_id.into(),
        });
        result
    }

    async fn write_partial<R: AsyncRead + Unpin>(
        &self,
        partial_path: &Path,
        incoming: &TaildropIncoming,
        content: &mut R,
        offset: u64,
        declared_length: Option<u64>,
    ) -> Result<(), TailscaleTaildropError> {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(partial_path)
            .await?;
        if offset == 0 {
            file.set_len(0).await?;
        } else {
            let current_size = file.metadata().await?.len();
            if offset > current_size {
                return Err(TailscaleTaildropError::OffsetOutOfRange {
                    offset,
                    size: current_size,
                });
            }
            file.seek(SeekFrom::Start(offset)).await?;
            file.set_len(offset).await?;
        }

        let mut copied = 0_u64;
        let mut buffer = vec![0_u8; TAILSCALE_TAILDROP_BLOCK_SIZE];
        loop {
            let count = tokio::select! {
                _ = incoming.cancellation.cancelled() => {
                    return Err(TailscaleTaildropError::Canceled);
                }
                result = content.read(&mut buffer) => result?,
            };
            if count == 0 {
                break;
            }
            file.write_all(&buffer[..count]).await?;
            copied = copied.saturating_add(count as u64);
            incoming
                .copied
                .store(offset.saturating_add(copied), Ordering::Relaxed);
            self.notify();
        }
        file.flush().await?;
        if let Some(expected) = declared_length
            && copied != expected
        {
            return Err(TailscaleTaildropError::LengthMismatch {
                actual: copied,
                expected,
            });
        }
        Ok(())
    }

    pub async fn cancel_receiving(
        &self,
        sender_id: &str,
        base_name: &str,
    ) -> Result<(), TailscaleTaildropError> {
        validate_tailscale_taildrop_file_name(base_name)?;
        let key = TaildropIncomingKey {
            sender_id: sender_id.into(),
            name: base_name.into(),
        };
        if let Some(incoming) = self.inner.state.lock().await.incoming.get(&key)
        {
            incoming.cancellation.cancel();
        }
        Ok(())
    }

    pub async fn partial_file_names(
        &self,
        sender_id: &str,
    ) -> Result<Vec<String>, TailscaleTaildropError> {
        validate_tailscale_taildrop_file_name(sender_id).map_err(|_| {
            TailscaleTaildropError::Http("invalid peer identity".into())
        })?;
        let suffix = format!(".{sender_id}{TAILSCALE_TAILDROP_PARTIAL_SUFFIX}");
        let mut entries = tokio::fs::read_dir(&self.inner.directory).await?;
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type().await?.is_file() && name.ends_with(&suffix) {
                names.push(name);
            }
        }
        names.sort();
        Ok(names)
    }

    pub async fn partial_checksums(
        &self,
        sender_id: &str,
        base_name: &str,
    ) -> Result<Vec<TailscaleTaildropBlockChecksum>, TailscaleTaildropError>
    {
        validate_tailscale_taildrop_file_name(base_name)?;
        validate_tailscale_taildrop_file_name(sender_id).map_err(|_| {
            TailscaleTaildropError::Http("invalid peer identity".into())
        })?;
        let path = self
            .inner
            .directory
            .join(partial_file_name(base_name, sender_id));
        let mut file = match tokio::fs::File::open(path).await {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        };
        let mut checksums = Vec::new();
        let mut block = vec![0_u8; TAILSCALE_TAILDROP_BLOCK_SIZE];
        loop {
            let count = file.read(&mut block).await?;
            if count == 0 {
                break;
            }
            checksums.push(TailscaleTaildropBlockChecksum {
                checksum: hex::encode(Sha256::digest(&block[..count])),
                algorithm: "sha256".into(),
                size: count as i64,
            });
        }
        Ok(checksums)
    }

    pub async fn inbox(
        &self,
    ) -> Result<TailscaleTaildropInbox, TailscaleTaildropError> {
        let mut entries = tokio::fs::read_dir(&self.inner.directory).await?;
        let mut disk_entries = Vec::new();
        let mut deleted = HashSet::new();
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(base) =
                name.strip_suffix(TAILSCALE_TAILDROP_DELETED_SUFFIX)
            {
                deleted.insert(base.to_owned());
            }
            disk_entries.push((name, entry.metadata().await?));
        }
        let mut state = self.inner.state.lock().await;
        let disk_names = disk_entries
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<HashSet<_>>();
        state
            .sender_names
            .retain(|name, _| disk_names.contains(name.as_str()));
        state
            .unread_files
            .retain(|name| disk_names.contains(name.as_str()));
        let mut files = Vec::new();
        for (name, metadata) in disk_entries {
            if name.ends_with(TAILSCALE_TAILDROP_PARTIAL_SUFFIX)
                || name.ends_with(TAILSCALE_TAILDROP_DELETED_SUFFIX)
                || deleted.contains(&name)
            {
                continue;
            }
            files.push(TailscaleTaildropFile {
                sender_name: state
                    .sender_names
                    .get(&name)
                    .cloned()
                    .unwrap_or_default(),
                modified_at: system_time_unix(metadata.modified()?),
                size: metadata.len(),
                name,
            });
        }
        files.sort_by(|left, right| {
            right
                .modified_at
                .cmp(&left.modified_at)
                .then_with(|| left.name.cmp(&right.name))
        });
        let mut receiving = state
            .incoming
            .iter()
            .map(|(key, incoming)| {
                (
                    incoming.started,
                    TailscaleTaildropReceivingFile {
                        name: key.name.clone(),
                        size: incoming.size,
                        received_bytes: incoming.copied.load(Ordering::Relaxed),
                        sender_id: key.sender_id.clone(),
                        sender_name: incoming.sender_name.clone(),
                    },
                )
            })
            .collect::<Vec<_>>();
        receiving.sort_by_key(|(started, _)| *started);
        Ok(TailscaleTaildropInbox {
            files,
            receiving: receiving.into_iter().map(|(_, file)| file).collect(),
        })
    }

    pub async fn mark_inbox_read(&self) {
        self.inner.state.lock().await.unread_files.clear();
        self.notify();
    }

    pub async fn unread_file_count(&self) -> usize {
        self.inner.state.lock().await.unread_files.len()
    }

    pub async fn waiting_file_count(
        &self,
    ) -> Result<usize, TailscaleTaildropError> {
        Ok(self.inbox().await?.files.len())
    }

    pub async fn receiving_file_count(&self) -> usize {
        self.inner.state.lock().await.incoming.len()
    }

    pub async fn open_file(
        &self,
        base_name: &str,
    ) -> Result<(tokio::fs::File, u64), TailscaleTaildropError> {
        validate_tailscale_taildrop_file_name(base_name)?;
        if tokio::fs::try_exists(
            self.inner.directory.join(format!(
                "{base_name}{TAILSCALE_TAILDROP_DELETED_SUFFIX}"
            )),
        )
        .await?
        {
            return Err(
                io::Error::new(io::ErrorKind::NotFound, base_name).into()
            );
        }
        let file =
            tokio::fs::File::open(self.inner.directory.join(base_name)).await?;
        let size = file.metadata().await?.len();
        Ok((file, size))
    }

    pub async fn delete_file(
        &self,
        base_name: &str,
    ) -> Result<(), TailscaleTaildropError> {
        validate_tailscale_taildrop_file_name(base_name)?;
        let path = self.inner.directory.join(base_name);
        #[cfg(windows)]
        self.delete_file_windows(&path, base_name).await?;
        #[cfg(not(windows))]
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut state = self.inner.state.lock().await;
        state.sender_names.remove(base_name);
        state.unread_files.remove(base_name);
        drop(state);
        self.notify();
        Ok(())
    }

    #[cfg(windows)]
    async fn delete_file_windows(
        &self,
        path: &Path,
        base_name: &str,
    ) -> Result<(), TailscaleTaildropError> {
        use rand::Rng as _;

        let started_at = tokio::time::Instant::now();
        let mut failures = 0_u32;
        loop {
            match tokio::fs::remove_file(path).await {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(());
                }
                Err(error) => {
                    if started_at.elapsed()
                        >= TAILSCALE_TAILDROP_DELETE_RETRY_DELAY
                    {
                        let marker = self.inner.directory.join(format!(
                            "{base_name}{TAILSCALE_TAILDROP_DELETED_SUFFIX}"
                        ));
                        tokio::fs::File::create(&marker).await.map_err(
                            |marker_error| {
                                io::Error::new(
                                    marker_error.kind(),
                                    format!(
                                        "{error}; create Taildrop deletion marker: {marker_error}"
                                    ),
                                )
                            },
                        )?;
                        self.schedule_artifact_delete(
                            marker,
                            None,
                            TAILSCALE_TAILDROP_DELETE_DELAY,
                        );
                        return Ok(());
                    }
                    if self.inner.state.lock().await.closed {
                        return Err(error.into());
                    }
                    failures = failures.saturating_add(1);
                    let jitter = rand::thread_rng().gen_range(0.5..1.5);
                    tokio::time::sleep(taildrop_delete_backoff(
                        failures, jitter,
                    ))
                    .await;
                }
            }
        }
    }

    pub async fn remove_expired_artifacts(
        &self,
    ) -> Result<(), TailscaleTaildropError> {
        let mut entries = tokio::fs::read_dir(&self.inner.directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !entry.file_type().await?.is_file()
                || (!name.ends_with(TAILSCALE_TAILDROP_PARTIAL_SUFFIX)
                    && !name.ends_with(TAILSCALE_TAILDROP_DELETED_SUFFIX))
            {
                continue;
            }
            let modified = entry.metadata().await?.modified()?;
            let age = modified.elapsed().unwrap_or_default();
            if age < TAILSCALE_TAILDROP_DELETE_DELAY {
                let key = parse_partial_key(&name);
                self.schedule_artifact_delete(
                    entry.path(),
                    key,
                    TAILSCALE_TAILDROP_DELETE_DELAY - age,
                );
                continue;
            }
            if let Some(base_name) =
                name.strip_suffix(TAILSCALE_TAILDROP_DELETED_SUFFIX)
            {
                let _ = tokio::fs::remove_file(
                    self.inner.directory.join(base_name),
                )
                .await;
            }
            let _ = tokio::fs::remove_file(entry.path()).await;
        }
        Ok(())
    }

    fn schedule_artifact_delete(
        &self,
        path: PathBuf,
        incoming_key: Option<TaildropIncomingKey>,
        mut delay: Duration,
    ) {
        let inner = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(delay).await;
                let Some(inner) = inner.upgrade() else {
                    return;
                };
                let state = inner.state.lock().await;
                if state.closed {
                    return;
                }
                let active = incoming_key
                    .as_ref()
                    .is_some_and(|key| state.incoming.contains_key(key));
                drop(state);
                if active {
                    delay = TAILSCALE_TAILDROP_DELETE_DELAY;
                    continue;
                }
                if let Some(name) = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| {
                        name.strip_suffix(TAILSCALE_TAILDROP_DELETED_SUFFIX)
                    })
                {
                    let _ = tokio::fs::remove_file(inner.directory.join(name))
                        .await;
                }
                let _ = tokio::fs::remove_file(path).await;
                return;
            }
        });
    }

    async fn rename_partial(
        &self,
        partial_path: &Path,
        base_name: &str,
    ) -> Result<String, TailscaleTaildropError> {
        let _guard = self.inner.rename.lock().await;
        let partial_size = tokio::fs::metadata(partial_path).await?.len();
        let mut final_name = base_name.to_owned();
        for _ in 0..10 {
            let final_path = self.inner.directory.join(&final_name);
            match tokio::fs::metadata(&final_path).await {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    tokio::fs::rename(partial_path, final_path).await?;
                    return Ok(final_name);
                }
                Err(error) => return Err(error.into()),
                Ok(metadata) => {
                    if metadata.len() == partial_size
                        && files_identical(partial_path, &final_path).await?
                    {
                        tokio::fs::remove_file(partial_path).await?;
                        return Ok(final_name);
                    }
                }
            }
            final_name = next_taildrop_file_name(&final_name);
        }
        Err(TailscaleTaildropError::TooManyRenameAttempts(
            base_name.into(),
        ))
    }

    fn notify(&self) {
        let _ = self.inner.updates.send(());
    }

    fn send_event(&self, event: TailscaleTaildropEvent) {
        let _ = self.inner.events.send(event);
    }
}

fn partial_file_name(base_name: &str, sender_id: &str) -> String {
    format!("{base_name}.{sender_id}{TAILSCALE_TAILDROP_PARTIAL_SUFFIX}")
}

fn parse_partial_key(name: &str) -> Option<TaildropIncomingKey> {
    let name = name.strip_suffix(TAILSCALE_TAILDROP_PARTIAL_SUFFIX)?;
    let (base_name, sender_id) = name.rsplit_once('.')?;
    (!base_name.is_empty() && !sender_id.is_empty()).then(|| {
        TaildropIncomingKey {
            sender_id: sender_id.into(),
            name: base_name.into(),
        }
    })
}

fn system_time_unix(value: SystemTime) -> i64 {
    value
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn next_taildrop_file_name(name: &str) -> String {
    static EXTENSION: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| {
            regex::Regex::new(r"(\.[a-zA-Z0-9]{0,3}[a-zA-Z][a-zA-Z0-9]{0,3})*$")
                .unwrap()
        });
    static NUMBER: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r" \([0-9]+\)").unwrap());
    let without_leading_dot = name.strip_prefix('.').unwrap_or(name);
    let extension = EXTENSION
        .find(without_leading_dot)
        .map(|value| value.as_str())
        .unwrap_or("");
    let stem_length = name.len().saturating_sub(extension.len());
    let mut stem = &name[..stem_length];
    let mut sequence = 0_u64;
    if NUMBER.is_match(stem)
        && let Some(separator) = stem.rfind(" (")
        && let Some(number) = stem[separator + 2..].strip_suffix(')')
        && let Ok(parsed) = number.parse::<u64>()
        && parsed > 0
    {
        sequence = parsed;
        stem = &stem[..separator];
    }
    format!("{stem} ({}){extension}", sequence.saturating_add(1))
}

async fn files_identical(
    left: &Path,
    right: &Path,
) -> Result<bool, TailscaleTaildropError> {
    async fn checksum(path: &Path) -> io::Result<[u8; 32]> {
        let mut file = tokio::fs::File::open(path).await?;
        let mut hash = Sha256::new();
        let mut buffer = vec![0_u8; TAILSCALE_TAILDROP_BLOCK_SIZE];
        loop {
            let count = file.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        Ok(hash.finalize().into())
    }
    Ok(checksum(left).await? == checksum(right).await?)
}

/// Handle one `/v0/put/` PeerAPI request without coupling the library to a
/// particular listener implementation.
pub async fn handle_tailscale_taildrop_request<B>(
    receiver: &TailscaleTaildropReceiver,
    peer: &TailscaleTaildropPeerAccess,
    request: Request<B>,
) -> Response<Full<Bytes>>
where
    B: hyper::body::Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: std::fmt::Display,
{
    if peer.unsigned_peer_api_only
        || !(peer.self_untagged
            || peer
                .peer_capabilities
                .contains(TAILSCALE_PEER_CAPABILITY_FILE_SHARING_SEND))
    {
        return taildrop_response(
            StatusCode::FORBIDDEN,
            "Taildrop access denied\n",
        );
    }
    if !peer.self_file_sharing_enabled {
        return taildrop_response(
            StatusCode::FORBIDDEN,
            "file sharing not enabled by Tailscale admin\n",
        );
    }
    if validate_tailscale_taildrop_file_name(&peer.stable_id).is_err() {
        return taildrop_response(
            StatusCode::FORBIDDEN,
            "invalid peer identity\n",
        );
    }

    let Some(escaped_name) = request.uri().path().strip_prefix("/v0/put/")
    else {
        return taildrop_response(StatusCode::BAD_REQUEST, "invalid path\n");
    };
    let base_name = match percent_encoding::percent_decode_str(escaped_name)
        .decode_utf8()
    {
        Ok(name) => name.into_owned(),
        Err(_) => {
            return taildrop_response(
                StatusCode::BAD_REQUEST,
                "taildrop: invalid filename\n",
            );
        }
    };

    match *request.method() {
        Method::GET if escaped_name.is_empty() => {
            match receiver.partial_file_names(&peer.stable_id).await {
                Ok(names) => match serde_json::to_string(&names) {
                    Ok(body) => taildrop_response(StatusCode::OK, body + "\n"),
                    Err(error) => taildrop_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        error.to_string(),
                    ),
                },
                Err(error) => taildrop_receiver_error_response(error, false),
            }
        }
        Method::GET => {
            match receiver
                .partial_checksums(&peer.stable_id, &base_name)
                .await
            {
                Ok(checksums) => {
                    let mut body = String::new();
                    for checksum in checksums {
                        match serde_json::to_string(&checksum) {
                            Ok(line) => {
                                body.push_str(&line);
                                body.push('\n');
                            }
                            Err(error) => {
                                return taildrop_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    error.to_string(),
                                );
                            }
                        }
                    }
                    taildrop_response(StatusCode::OK, body)
                }
                Err(error) => taildrop_receiver_error_response(error, false),
            }
        }
        Method::PUT => {
            let request_version = request.version();
            let offset = match parse_taildrop_range(request.headers()) {
                Ok(offset) => offset,
                Err(()) => {
                    return taildrop_response(
                        StatusCode::BAD_REQUEST,
                        "invalid Range header\n",
                    );
                }
            };
            let declared_length =
                match request.headers().get(hyper::header::CONTENT_LENGTH) {
                    Some(value) => match value
                        .to_str()
                        .ok()
                        .and_then(|value| value.parse::<u64>().ok())
                    {
                        Some(value) => Some(value),
                        None => {
                            return taildrop_response(
                                StatusCode::BAD_REQUEST,
                                "invalid Content-Length header\n",
                            );
                        }
                    },
                    None => None,
                };
            let body =
                request.into_body().into_data_stream().map_err(|error| {
                    io::Error::other(format!(
                        "Taildrop request body failed: {error}"
                    ))
                });
            let mut reader = StreamReader::new(body);
            let result = receiver
                .put_file(
                    &peer.stable_id,
                    &peer.name,
                    &base_name,
                    &mut reader,
                    offset,
                    declared_length,
                )
                .await;
            match result {
                Ok(_) => taildrop_response(StatusCode::OK, "{}\n"),
                Err(error) => {
                    // Match net/http's PeerAPI behavior: return a complete
                    // rejection response immediately, while retaining the
                    // request body long enough for the sender to receive it
                    // instead of seeing a connection reset.
                    spawn_taildrop_reject_drain(reader);
                    taildrop_receiver_error_response(
                        error,
                        matches!(
                            request_version,
                            hyper::Version::HTTP_10 | hyper::Version::HTTP_11
                        ),
                    )
                }
            }
        }
        _ => taildrop_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "expected method GET or PUT\n",
        ),
    }
}

fn parse_taildrop_range(headers: &hyper::HeaderMap) -> Result<u64, ()> {
    let Some(value) = headers.get(hyper::header::RANGE) else {
        return Ok(0);
    };
    let value = value.to_str().map_err(|_| ())?;
    let offset = value
        .strip_prefix("bytes=")
        .and_then(|value| value.strip_suffix('-'))
        .filter(|value| !value.is_empty() && !value.contains(','))
        .ok_or(())?;
    offset.parse().map_err(|_| ())
}

fn taildrop_receiver_error_response(
    error: TailscaleTaildropError,
    close_connection: bool,
) -> Response<Full<Bytes>> {
    let status = match error {
        TailscaleTaildropError::InvalidFileName => StatusCode::BAD_REQUEST,
        TailscaleTaildropError::FileExists => StatusCode::CONFLICT,
        TailscaleTaildropError::Canceled => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
        "taildrop: receive failed\n".to_owned()
    } else {
        format!("{error}\n")
    };
    let mut response = taildrop_response(status, message);
    if close_connection {
        response.headers_mut().insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("close"),
        );
    }
    response
}

fn taildrop_response(
    status: StatusCode,
    body: impl Into<Bytes>,
) -> Response<Full<Bytes>> {
    let body = body.into();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(hyper::header::CONTENT_LENGTH, body.len())
        .body(Full::new(body))
        .expect("static Taildrop response is valid")
}

fn spawn_taildrop_reject_drain<R>(mut reader: R)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let drain = async {
            let mut sink = tokio::io::sink();
            tokio::io::copy(&mut reader, &mut sink).await
        };
        let _ = tokio::time::timeout(
            TAILSCALE_TAILDROP_REJECT_DRAIN_TIMEOUT,
            drain,
        )
        .await;
    });
}

#[cfg(any(windows, test))]
fn taildrop_delete_backoff(failures: u32, jitter: f64) -> Duration {
    let failures = u64::from(failures);
    let milliseconds = failures
        .saturating_mul(failures)
        .saturating_mul(10)
        .min(1_000);
    Duration::from_millis(milliseconds).mul_f64(jitter.clamp(0.5, 1.5))
}

pub fn validate_tailscale_taildrop_file_name(
    name: &str,
) -> Result<(), TailscaleTaildropError> {
    if name.is_empty()
        || name == "."
        || name.len() > 255
        || name.contains('\0')
        || name.ends_with(".partial")
        || name.ends_with(".deleted")
        || std::path::Path::new(name)
            .file_name()
            .and_then(|value| value.to_str())
            != Some(name)
        || name == ".."
    {
        return Err(TailscaleTaildropError::InvalidFileName);
    }
    Ok(())
}

pub fn tailscale_taildrop_targets(
    netmap: &TailscaleNetmapState,
) -> Result<Vec<TailscaleTaildropTarget>, TailscaleTaildropError> {
    let self_node = taildrop_self(netmap)?;
    Ok(netmap
        .peers
        .values()
        .filter_map(|peer| taildrop_target(self_node, peer).ok())
        .collect())
}

fn taildrop_self(
    netmap: &TailscaleNetmapState,
) -> Result<&TailscaleNode, TailscaleTaildropError> {
    let self_node = netmap
        .node
        .as_ref()
        .ok_or(TailscaleTaildropError::NotConnected)?;
    if !has_capability(self_node, TAILSCALE_CAPABILITY_FILE_SHARING) {
        return Err(TailscaleTaildropError::FileSharingDisabled);
    }
    Ok(self_node)
}

fn taildrop_target(
    self_node: &TailscaleNode,
    peer: &TailscaleNode,
) -> Result<TailscaleTaildropTarget, TailscaleTaildropError> {
    if peer.hostinfo.as_ref().is_some_and(|host| host.os == "tvOS") {
        return Err(TailscaleTaildropError::PeerCannotReceive);
    }
    if self_node.user != peer.user
        && !has_capability(peer, TAILSCALE_PEER_CAPABILITY_FILE_SHARING_TARGET)
    {
        return Err(TailscaleTaildropError::PeerNotPermitted);
    }
    let destination = peer_api_destination(peer)
        .ok_or(TailscaleTaildropError::PeerApiUnavailable)?;
    Ok(TailscaleTaildropTarget {
        stable_id: peer.stable_id.clone(),
        name: peer.name.clone(),
        destination,
    })
}

pub async fn send_tailscale_taildrop_file<R>(
    dialer: Arc<dyn Dialer>,
    netmap: &TailscaleNetmapState,
    peer_stable_id: &str,
    file_name: &str,
    size: u64,
    mut content: R,
    progress: Option<Arc<dyn Fn(u64) + Send + Sync>>,
) -> Result<(), TailscaleTaildropError>
where
    R: AsyncRead + AsyncSeek + Unpin + Send + 'static,
{
    validate_tailscale_taildrop_file_name(file_name)?;
    let self_node = taildrop_self(netmap)?;
    let peer = netmap
        .peers
        .values()
        .find(|peer| peer.stable_id == peer_stable_id)
        .ok_or_else(|| {
            TailscaleTaildropError::PeerNotFound(peer_stable_id.into())
        })?;
    let target = taildrop_target(self_node, peer)?;
    let path = taildrop_put_path(file_name)?;
    let offset =
        probe_resume(&dialer, target.destination, &path, &mut content, size)
            .await;
    content.seek(SeekFrom::Start(offset)).await?;
    if let Some(progress) = &progress {
        progress(offset);
    }

    let stream = dialer.dial_tcp(&SocksAddr::Ip(target.destination)).await?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(http_error)?;
    let driver = tokio::spawn(connection);
    let reader = TaildropProgressReader {
        inner: content,
        transferred: offset,
        progress,
    };
    let body = StreamBody::new(ReaderStream::new(reader).map_ok(Frame::data));
    let mut builder = Request::builder()
        .method(Method::PUT)
        .uri(&path)
        .header("host", host_header(target.destination))
        .header("content-length", size.saturating_sub(offset).to_string())
        .header("connection", "close");
    if offset > 0 {
        builder = builder.header("range", format!("bytes={offset}-"));
    }
    let response = sender
        .send_request(builder.body(body).map_err(http_error)?)
        .await
        .map_err(http_error)?;
    let status = response.status();
    let response_body = collect_bounded(response, 1024).await?;
    driver.abort();
    if status != hyper::StatusCode::OK {
        return Err(TailscaleTaildropError::PeerResponse {
            status: status.as_u16(),
            message: String::from_utf8_lossy(&response_body).trim().into(),
        });
    }
    Ok(())
}

async fn probe_resume<R: AsyncRead + AsyncSeek + Unpin>(
    dialer: &Arc<dyn Dialer>,
    destination: std::net::SocketAddr,
    path: &str,
    content: &mut R,
    size: u64,
) -> u64 {
    let result = async {
        let stream = dialer.dial_tcp(&SocksAddr::Ip(destination)).await?;
        let (mut sender, connection) =
            http1::handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
                .await
                .map_err(http_error)?;
        let driver = tokio::spawn(connection);
        let request = Request::get(path)
            .header("host", host_header(destination))
            .header("connection", "close")
            .body(Empty::new())
            .map_err(http_error)?;
        let response =
            sender.send_request(request).await.map_err(http_error)?;
        if response.status() != hyper::StatusCode::OK {
            driver.abort();
            return Ok::<u64, TailscaleTaildropError>(0);
        }
        let body = collect_bounded(response, 16 << 20).await?;
        driver.abort();
        let mut offset = 0_u64;
        for line in body
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let checksum: TailscaleTaildropBlockChecksum =
                serde_json::from_slice(line).map_err(|error| {
                    TailscaleTaildropError::Http(error.to_string())
                })?;
            if checksum.algorithm != "sha256"
                || checksum.size <= 0
                || checksum.size as usize > TAILSCALE_TAILDROP_BLOCK_SIZE
                || offset.saturating_add(checksum.size as u64) > size
            {
                break;
            }
            let mut block = vec![0_u8; checksum.size as usize];
            if content.read_exact(&mut block).await.is_err() {
                break;
            }
            if hex::encode(Sha256::digest(&block)) != checksum.checksum {
                break;
            }
            offset += checksum.size as u64;
        }
        Ok(offset)
    }
    .await;
    result.unwrap_or(0)
}

async fn collect_bounded(
    response: hyper::Response<Incoming>,
    maximum: usize,
) -> Result<Vec<u8>, TailscaleTaildropError> {
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(http_error)?;
        if let Some(data) = frame.data_ref() {
            if bytes.len().saturating_add(data.len()) > maximum {
                return Err(TailscaleTaildropError::Http(
                    "response body too large".into(),
                ));
            }
            bytes.extend_from_slice(data);
        }
    }
    Ok(bytes)
}

fn taildrop_put_path(
    file_name: &str,
) -> Result<String, TailscaleTaildropError> {
    let mut url = url::Url::parse("http://peer.invalid/v0/put")
        .map_err(|error| TailscaleTaildropError::Http(error.to_string()))?;
    url.path_segments_mut()
        .map_err(|_| TailscaleTaildropError::InvalidFileName)?
        .push(file_name);
    Ok(url.path().into())
}

fn peer_api_destination(peer: &TailscaleNode) -> Option<std::net::SocketAddr> {
    let host = peer.hostinfo.as_ref()?;
    for (protocol, want_v4) in [("peerapi4", true), ("peerapi6", false)] {
        let Some(port) = host
            .services
            .iter()
            .find(|service| service.protocol == protocol)
            .map(|service| service.port)
        else {
            continue;
        };
        if port == 0 {
            continue;
        }
        for address in &peer.addresses {
            let Some(ip) = address
                .split('/')
                .next()
                .and_then(|value| value.parse::<std::net::IpAddr>().ok())
            else {
                continue;
            };
            if ip.is_ipv4() == want_v4 {
                return Some((ip, port).into());
            }
        }
    }
    None
}

fn has_capability(node: &TailscaleNode, capability: &str) -> bool {
    node.capabilities.iter().any(|value| value == capability)
        || node.capability_map.contains_key(capability)
}

fn host_header(destination: std::net::SocketAddr) -> String {
    destination.to_string()
}

fn http_error(error: impl std::fmt::Display) -> TailscaleTaildropError {
    TailscaleTaildropError::Http(error.to_string())
}

struct TaildropProgressReader<R> {
    inner: R,
    transferred: u64,
    progress: Option<Arc<dyn Fn(u64) + Send + Sync>>,
}

impl<R: AsyncRead + Unpin> AsyncRead for TaildropProgressReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                self.transferred += (buffer.filled().len() - before) as u64;
                if let Some(progress) = &self.progress {
                    progress(self.transferred);
                }
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    };

    use crate::protocol::tailscale_control_types::{
        TailscaleHostinfo, TailscaleService,
    };
    use crate::{
        option::DirectOutboundOptions, protocol::direct::DirectOutbound,
    };

    #[test]
    fn delete_retry_backoff_matches_upstream_quadratic_bounds() {
        assert_eq!(taildrop_delete_backoff(1, 1.0), Duration::from_millis(10));
        assert_eq!(taildrop_delete_backoff(2, 1.0), Duration::from_millis(40));
        assert_eq!(taildrop_delete_backoff(100, 1.0), Duration::from_secs(1));
        assert_eq!(
            taildrop_delete_backoff(100, 0.0),
            Duration::from_millis(500)
        );
        assert_eq!(
            taildrop_delete_backoff(100, 2.0),
            Duration::from_millis(1500)
        );
        assert_eq!(
            TAILSCALE_TAILDROP_DELETE_RETRY_DELAY,
            Duration::from_secs(5)
        );
        assert_eq!(
            TAILSCALE_TAILDROP_REJECT_DRAIN_TIMEOUT,
            Duration::from_secs(3)
        );
    }

    #[test]
    fn filenames_and_url_path_match_taildrop_contract() {
        for valid in ["file.txt", ".hidden", "报告 1.pdf"] {
            validate_tailscale_taildrop_file_name(valid).unwrap();
        }
        for invalid in [".", "..", "a/b", "x.partial", "x.deleted", "a\0b"] {
            assert!(validate_tailscale_taildrop_file_name(invalid).is_err());
        }
        assert_eq!(
            taildrop_put_path("报告 1.pdf").unwrap(),
            "/v0/put/%E6%8A%A5%E5%91%8A%201.pdf"
        );
    }

    #[test]
    fn target_policy_uses_tailcfg_capabilities_and_peerapi_service() {
        let mut netmap = TailscaleNetmapState {
            node: Some(TailscaleNode {
                user: 7,
                capabilities: vec![TAILSCALE_CAPABILITY_FILE_SHARING.into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        netmap.peers.insert(
            1,
            TailscaleNode {
                stable_id: "peer-1".into(),
                name: "peer.example".into(),
                user: 7,
                addresses: vec!["100.64.0.2/32".into()],
                hostinfo: Some(TailscaleHostinfo {
                    services: vec![TailscaleService {
                        protocol: "peerapi4".into(),
                        port: 41112,
                        description: String::new(),
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let targets = tailscale_taildrop_targets(&netmap).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].destination,
            "100.64.0.2:41112".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn sender_resumes_matching_sha256_blocks_and_streams_the_suffix() {
        async fn read_header(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
            }
            header
        }

        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut probe, _) = listener.accept().await.unwrap();
            let header =
                String::from_utf8(read_header(&mut probe).await).unwrap();
            assert!(header.starts_with("GET /v0/put/file.txt HTTP/1.1"));
            let checksum = TailscaleTaildropBlockChecksum {
                checksum: hex::encode(Sha256::digest(b"abc")),
                algorithm: "sha256".into(),
                size: 3,
            };
            let body =
                format!("{}\n", serde_json::to_string(&checksum).unwrap());
            probe
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            drop(probe);

            let (mut upload, _) = listener.accept().await.unwrap();
            let header =
                String::from_utf8(read_header(&mut upload).await).unwrap();
            assert!(header.starts_with("PUT /v0/put/file.txt HTTP/1.1"));
            assert!(header.to_ascii_lowercase().contains("range: bytes=3-"));
            assert!(header.to_ascii_lowercase().contains("content-length: 3"));
            let mut body = [0_u8; 3];
            upload.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"def");
            upload
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{}\n")
                .await
                .unwrap();
        });

        let mut netmap = TailscaleNetmapState {
            node: Some(TailscaleNode {
                user: 7,
                capabilities: vec![TAILSCALE_CAPABILITY_FILE_SHARING.into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        netmap.peers.insert(
            1,
            TailscaleNode {
                stable_id: "peer-1".into(),
                user: 7,
                addresses: vec!["127.0.0.1/32".into()],
                hostinfo: Some(TailscaleHostinfo {
                    services: vec![TailscaleService {
                        protocol: "peerapi4".into(),
                        port,
                        description: String::new(),
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let progress = Arc::new(Mutex::new(Vec::new()));
        let captured = progress.clone();
        send_tailscale_taildrop_file(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            &netmap,
            "peer-1",
            "file.txt",
            6,
            std::io::Cursor::new(b"abcdef".to_vec()),
            Some(Arc::new(move |sent| captured.lock().unwrap().push(sent))),
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(progress.lock().unwrap().last().copied(), Some(6));
    }

    #[test]
    fn conflicting_names_follow_upstream_sequence_and_extension_rules() {
        assert_eq!(next_taildrop_file_name("file.txt"), "file (1).txt");
        assert_eq!(next_taildrop_file_name("file (3).txt"), "file (4).txt");
        assert_eq!(
            next_taildrop_file_name("archive.tar.gz"),
            "archive (1).tar.gz"
        );
        assert_eq!(next_taildrop_file_name(".hidden"), ".hidden (1)");
        assert_eq!(
            parse_partial_key("report.peer-1.partial"),
            Some(TaildropIncomingKey {
                sender_id: "peer-1".into(),
                name: "report".into(),
            })
        );
    }

    #[tokio::test]
    async fn receiver_runtime_cleanup_respects_close() {
        let directory = tempfile::tempdir().unwrap();
        let receiver = TailscaleTaildropReceiver::new(directory.path())
            .await
            .unwrap();
        let expired = directory.path().join("expired.peer-1.partial");
        tokio::fs::write(&expired, b"old").await.unwrap();
        receiver.schedule_artifact_delete(
            expired.clone(),
            None,
            Duration::from_millis(1),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!tokio::fs::try_exists(&expired).await.unwrap());

        let retained = directory.path().join("retained.peer-1.partial");
        tokio::fs::write(&retained, b"partial").await.unwrap();
        receiver.close().await;
        receiver.schedule_artifact_delete(
            retained.clone(),
            None,
            Duration::from_millis(1),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(tokio::fs::try_exists(retained).await.unwrap());
    }

    #[tokio::test]
    async fn receiver_emits_host_notification_lifecycle() {
        let directory = tempfile::tempdir().unwrap();
        let receiver = TailscaleTaildropReceiver::new(directory.path())
            .await
            .unwrap();
        let mut events = receiver.subscribe_events();

        assert_eq!(
            receiver
                .put_file(
                    "peer-1",
                    "Alice",
                    "report.txt",
                    std::io::Cursor::new(b"hello"),
                    0,
                    Some(5),
                )
                .await
                .unwrap(),
            "report.txt"
        );

        let started = events.recv().await.unwrap();
        assert_eq!(
            started,
            TailscaleTaildropEvent::IncomingStarted {
                file_name: "report.txt".into(),
                sender_id: "peer-1".into(),
                sender_name: "Alice".into(),
                total_size: Some(5),
            }
        );
        assert_eq!(
            started.notification_identifier("home node"),
            "taildrop/home node/receiving/peer-1/report.txt"
        );
        assert_eq!(
            events.recv().await.unwrap(),
            TailscaleTaildropEvent::FileReceived {
                file_name: "report.txt".into(),
                sender_id: "peer-1".into(),
                sender_name: "Alice".into(),
                size: 5,
            }
        );
        assert_eq!(
            events.recv().await.unwrap(),
            TailscaleTaildropEvent::IncomingStopped {
                file_name: "report.txt".into(),
                sender_id: "peer-1".into(),
            }
        );
        assert_eq!(TAILSCALE_TAILDROP_NOTIFICATION_TYPE_ID, 11);
        assert_eq!(
            TAILSCALE_TAILDROP_NOTIFICATION_TYPE_NAME,
            "Taildrop Notifications"
        );
        assert_eq!(TAILSCALE_TAILDROP_NOTIFICATION_TITLE, "Taildrop");
    }

    #[tokio::test]
    async fn receiver_resumes_deduplicates_renames_and_tracks_inbox() {
        let directory = tempfile::tempdir().unwrap();
        let receiver = TailscaleTaildropReceiver::new(directory.path())
            .await
            .unwrap();

        let error = receiver
            .put_file(
                "peer-1",
                "Alice",
                "file.txt",
                std::io::Cursor::new(b"abc"),
                0,
                Some(6),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            TailscaleTaildropError::LengthMismatch {
                actual: 3,
                expected: 6
            }
        ));
        let checksums = receiver
            .partial_checksums("peer-1", "file.txt")
            .await
            .unwrap();
        assert_eq!(checksums.len(), 1);
        assert_eq!(checksums[0].size, 3);
        assert_eq!(checksums[0].checksum, hex::encode(Sha256::digest(b"abc")));

        assert_eq!(
            receiver
                .put_file(
                    "peer-1",
                    "Alice",
                    "file.txt",
                    std::io::Cursor::new(b"def"),
                    3,
                    Some(3),
                )
                .await
                .unwrap(),
            "file.txt"
        );
        assert_eq!(
            tokio::fs::read(directory.path().join("file.txt"))
                .await
                .unwrap(),
            b"abcdef"
        );
        assert_eq!(receiver.unread_file_count().await, 1);

        assert_eq!(
            receiver
                .put_file(
                    "peer-2",
                    "Bob",
                    "file.txt",
                    std::io::Cursor::new(b"abcdef"),
                    0,
                    Some(6),
                )
                .await
                .unwrap(),
            "file.txt"
        );
        assert_eq!(
            receiver
                .put_file(
                    "peer-3",
                    "Carol",
                    "file.txt",
                    std::io::Cursor::new(b"different"),
                    0,
                    Some(9),
                )
                .await
                .unwrap(),
            "file (1).txt"
        );
        let inbox = receiver.inbox().await.unwrap();
        assert_eq!(
            inbox
                .files
                .iter()
                .map(|file| file.name.as_str())
                .collect::<HashSet<_>>(),
            HashSet::from(["file.txt", "file (1).txt"])
        );
        assert_eq!(receiver.unread_file_count().await, 2);
        receiver.mark_inbox_read().await;
        assert_eq!(receiver.unread_file_count().await, 0);
        let (mut file, size) =
            receiver.open_file("file (1).txt").await.unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).await.unwrap();
        assert_eq!(size, 9);
        assert_eq!(contents, b"different");
        receiver.delete_file("file (1).txt").await.unwrap();
        assert!(receiver.open_file("file (1).txt").await.is_err());
    }

    #[tokio::test]
    async fn receiver_cancellation_removes_partial_file() {
        let directory = tempfile::tempdir().unwrap();
        let receiver = TailscaleTaildropReceiver::new(directory.path())
            .await
            .unwrap();
        let (reader, _writer) = tokio::io::duplex(16);
        let running_receiver = receiver.clone();
        let upload = tokio::spawn(async move {
            running_receiver
                .put_file("peer-1", "Alice", "large.bin", reader, 0, None)
                .await
        });
        for _ in 0..20 {
            if receiver.receiving_file_count().await == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        receiver
            .cancel_receiving("peer-1", "large.bin")
            .await
            .unwrap();
        assert!(matches!(
            upload.await.unwrap(),
            Err(TailscaleTaildropError::Canceled)
        ));
        assert!(
            !tokio::fs::try_exists(
                directory.path().join("large.bin.peer-1.partial")
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn peer_api_handler_enforces_access_and_resumes_put() {
        let directory = tempfile::tempdir().unwrap();
        let receiver = TailscaleTaildropReceiver::new(directory.path())
            .await
            .unwrap();
        let mut peer = TailscaleTaildropPeerAccess {
            stable_id: "peer-1".into(),
            name: "Alice".into(),
            self_untagged: true,
            self_file_sharing_enabled: true,
            ..Default::default()
        };
        receiver
            .put_file(
                "peer-1",
                "Alice",
                "file.txt",
                std::io::Cursor::new(b"abc"),
                0,
                Some(6),
            )
            .await
            .unwrap_err();

        let response = handle_tailscale_taildrop_request(
            &receiver,
            &peer,
            Request::get("/v0/put/file.txt")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let checksum: TailscaleTaildropBlockChecksum =
            serde_json::from_slice(body.strip_suffix(b"\n").unwrap()).unwrap();
        assert_eq!(checksum.checksum, hex::encode(Sha256::digest(b"abc")));

        let response = handle_tailscale_taildrop_request(
            &receiver,
            &peer,
            Request::put("/v0/put/file.txt")
                .header("range", "bytes=3-")
                .header("content-length", "3")
                .body(Full::new(Bytes::from_static(b"def")))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            tokio::fs::read(directory.path().join("file.txt"))
                .await
                .unwrap(),
            b"abcdef"
        );

        peer.self_untagged = false;
        let response = handle_tailscale_taildrop_request(
            &receiver,
            &peer,
            Request::get("/v0/put/")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        peer.peer_capabilities
            .insert(TAILSCALE_PEER_CAPABILITY_FILE_SHARING_SEND.into());
        let response = handle_tailscale_taildrop_request(
            &receiver,
            &peer,
            Request::put("/v0/put/second.txt")
                .header("range", "bytes=0-1")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejected_put_returns_complete_response_and_drains_body() {
        let directory = tempfile::tempdir().unwrap();
        let receiver = TailscaleTaildropReceiver::new(directory.path())
            .await
            .unwrap();
        let peer = TailscaleTaildropPeerAccess {
            stable_id: "peer-1".into(),
            name: "Alice".into(),
            self_untagged: true,
            self_file_sharing_enabled: true,
            ..Default::default()
        };

        let (blocked_reader, _blocked_writer) = tokio::io::duplex(16);
        let blocked_receiver = receiver.clone();
        let blocked_upload = tokio::spawn(async move {
            blocked_receiver
                .put_file(
                    "peer-1",
                    "Alice",
                    "busy.txt",
                    blocked_reader,
                    0,
                    None,
                )
                .await
        });
        for _ in 0..100 {
            if receiver.receiving_file_count().await == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(receiver.receiving_file_count().await, 1);

        let polls = Arc::new(AtomicUsize::new(0));
        let body_polls = polls.clone();
        let stream = futures_util::stream::poll_fn(move |_| {
            let index = body_polls.fetch_add(1, AtomicOrdering::Relaxed);
            Poll::Ready(if index < 2 {
                Some(Ok::<_, std::convert::Infallible>(Frame::data(
                    Bytes::from_static(b"still uploading"),
                )))
            } else {
                None
            })
        });
        let response = handle_tailscale_taildrop_request(
            &receiver,
            &peer,
            Request::put("/v0/put/busy.txt")
                .body(StreamBody::new(stream))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.headers().get(hyper::header::CONNECTION).unwrap(),
            "close"
        );
        let declared_length = response
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(declared_length, body.len());
        assert_eq!(body, "taildrop: file already exists\n");

        tokio::time::timeout(Duration::from_secs(1), async {
            while polls.load(AtomicOrdering::Relaxed) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("rejected request body was not drained");

        receiver
            .cancel_receiving("peer-1", "busy.txt")
            .await
            .unwrap();
        assert!(matches!(
            blocked_upload.await.unwrap(),
            Err(TailscaleTaildropError::Canceled)
        ));
    }
}
