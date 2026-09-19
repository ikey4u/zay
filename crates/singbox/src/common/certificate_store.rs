//! Reloadable process-wide TLS trust store.

use std::{
    fs,
    io::{self, BufReader},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use rustls::{RootCertStore, pki_types::CertificateDer};
use sha2::{Digest, Sha256};
use tokio::{sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    common::lifecycle::{
        Lifecycle, LifecycleError, LifecycleFuture, StartStage,
    },
    option::{CertificateOptions, CertificateStoreKind},
};

pub(crate) const MOZILLA_ROOTS: &[u8] =
    include_bytes!("../../assets/certificates/mozilla.pem");
const CHROME_ROOTS: &[u8] =
    include_bytes!("../../assets/certificates/chrome.pem");
const RELOAD_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, thiserror::Error)]
pub enum CertificateStoreError {
    #[error("unknown or unusable system certificate store: {0}")]
    System(String),
    #[error("read certificate file {path:?}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("read certificate directory {path:?}: {source}")]
    ReadDirectory { path: PathBuf, source: io::Error },
    #[error("invalid certificate PEM in {source_name}")]
    InvalidPem { source_name: String },
    #[error("certificate store lock is poisoned")]
    Poisoned,
}

#[derive(Clone)]
pub struct CertificateStore {
    inner: Arc<CertificateStoreInner>,
}

impl std::fmt::Debug for CertificateStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertificateStore")
            .field("kind", &self.inner.kind)
            .field("generation", &self.generation())
            .finish()
    }
}

impl PartialEq for CertificateStore {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for CertificateStore {}

struct CertificateStoreInner {
    kind: CertificateStoreKind,
    inline: Vec<String>,
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
    state: RwLock<CertificateStoreSnapshot>,
    generation: watch::Sender<u64>,
    cancellation: CancellationToken,
    task: Mutex<Option<JoinHandle<()>>>,
}

struct CertificateStoreSnapshot {
    roots: Arc<RootCertStore>,
    apple_anchors: Arc<Vec<CertificateDer<'static>>>,
    fingerprint: [u8; 32],
    generation: u64,
}

impl CertificateStore {
    pub fn new(
        options: &CertificateOptions,
        base_path: &Path,
    ) -> Result<Self, CertificateStoreError> {
        let resolve = |path: &str| {
            let path = Path::new(path);
            if path.is_absolute() {
                path.to_owned()
            } else {
                base_path.join(path)
            }
        };
        let files: Vec<PathBuf> = options
            .certificate_path
            .as_slice()
            .iter()
            .map(|path| resolve(path))
            .collect();
        let directories: Vec<PathBuf> = options
            .certificate_directory_path
            .as_slice()
            .iter()
            .map(|path| resolve(path))
            .collect();
        let initial = build_snapshot(
            options.store,
            options.certificate.as_slice(),
            &files,
            &directories,
            0,
        )?;
        let (generation, _) = watch::channel(0);
        Ok(Self {
            inner: Arc::new(CertificateStoreInner {
                kind: options.store,
                inline: options.certificate.as_slice().to_vec(),
                files,
                directories,
                state: RwLock::new(initial),
                generation,
                cancellation: CancellationToken::new(),
                task: Mutex::new(None),
            }),
        })
    }

    pub fn kind(&self) -> CertificateStoreKind {
        self.inner.kind
    }

    pub fn exclusive_anchors(&self) -> bool {
        self.inner.kind.exclusive_anchors()
    }

    pub fn root_store(
        &self,
    ) -> Result<Arc<RootCertStore>, CertificateStoreError> {
        self.inner
            .state
            .read()
            .map(|state| state.roots.clone())
            .map_err(|_| CertificateStoreError::Poisoned)
    }

    /// DER anchors supplied to Security.framework in addition to its system
    /// roots. For an exclusive Mozilla/Chrome/none store, callers must set
    /// `SecTrustSetAnchorCertificatesOnly` accordingly.
    pub fn apple_anchors(
        &self,
    ) -> Result<Arc<Vec<CertificateDer<'static>>>, CertificateStoreError> {
        self.inner
            .state
            .read()
            .map(|state| state.apple_anchors.clone())
            .map_err(|_| CertificateStoreError::Poisoned)
    }

    pub fn generation(&self) -> u64 {
        self.inner
            .state
            .read()
            .map(|state| state.generation)
            .unwrap_or_default()
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner.generation.subscribe()
    }

    /// Atomically reload all configured files and directories. A failed
    /// reload leaves the last usable generation active.
    pub fn reload(&self) -> Result<bool, CertificateStoreError> {
        let next_generation = self.generation().saturating_add(1);
        let next = build_snapshot(
            self.inner.kind,
            &self.inner.inline,
            &self.inner.files,
            &self.inner.directories,
            next_generation,
        )?;
        let mut state = self
            .inner
            .state
            .write()
            .map_err(|_| CertificateStoreError::Poisoned)?;
        if state.fingerprint == next.fingerprint {
            return Ok(false);
        }
        let generation = next.generation;
        *state = next;
        drop(state);
        self.inner.generation.send_replace(generation);
        Ok(true)
    }

    fn has_watched_paths(&self) -> bool {
        !self.inner.files.is_empty() || !self.inner.directories.is_empty()
    }
}

impl Lifecycle for CertificateStore {
    fn name(&self) -> &str {
        "certificate"
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start || !self.has_watched_paths() {
                return Ok(());
            }
            let mut task =
                self.inner.task.lock().map_err(|_| LifecycleError::Start {
                    component: self.name().into(),
                    stage,
                    message: "certificate watcher lock is poisoned".into(),
                })?;
            if task.is_some() {
                return Ok(());
            }
            let store = self.clone();
            let cancellation = self.inner.cancellation.clone();
            *task = Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(RELOAD_INTERVAL);
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = interval.tick() => {
                            let _ = store.reload();
                        }
                    }
                }
            }));
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.inner.cancellation.cancel();
            let task = self
                .inner
                .task
                .lock()
                .map_err(|_| LifecycleError::Close {
                    component: self.name().into(),
                    message: "certificate watcher lock is poisoned".into(),
                })?
                .take();
            if let Some(task) = task {
                let _ = task.await;
            }
            Ok(())
        })
    }
}

fn build_snapshot(
    kind: CertificateStoreKind,
    inline: &[String],
    files: &[PathBuf],
    directories: &[PathBuf],
    generation: u64,
) -> Result<CertificateStoreSnapshot, CertificateStoreError> {
    let mut roots = RootCertStore::empty();
    let mut apple_anchors = Vec::new();
    match kind {
        CertificateStoreKind::System => {
            let native = rustls_native_certs::load_native_certs();
            if native.certs.is_empty() && !native.errors.is_empty() {
                return Err(CertificateStoreError::System(format!(
                    "{:?}",
                    native.errors
                )));
            }
            add_system_der_certificates(
                &mut roots,
                &mut apple_anchors,
                native.certs,
                cfg!(target_vendor = "apple").then_some(MOZILLA_ROOTS),
            )?;
        }
        CertificateStoreKind::Mozilla => add_pem_source(
            &mut roots,
            &mut apple_anchors,
            MOZILLA_ROOTS,
            "included Mozilla roots",
            true,
        )?,
        CertificateStoreKind::Chrome => add_pem_source(
            &mut roots,
            &mut apple_anchors,
            CHROME_ROOTS,
            "included Chrome roots",
            true,
        )?,
        CertificateStoreKind::None => {}
    }
    for (index, certificate) in inline.iter().enumerate() {
        add_pem_source(
            &mut roots,
            &mut apple_anchors,
            certificate.as_bytes(),
            &format!("certificate[{index}]"),
            true,
        )?;
    }
    for path in files {
        let bytes =
            fs::read(path).map_err(|source| CertificateStoreError::Read {
                path: path.clone(),
                source,
            })?;
        add_pem_source(
            &mut roots,
            &mut apple_anchors,
            &bytes,
            &path.display().to_string(),
            true,
        )?;
    }
    let mut first_directory_error = None;
    for directory in directories {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                if first_directory_error.is_none() {
                    first_directory_error =
                        Some(CertificateStoreError::ReadDirectory {
                            path: directory.clone(),
                            source,
                        });
                }
                continue;
            }
        };
        for entry in entries.flatten() {
            if same_directory_symlink(&entry.path()) {
                continue;
            }
            let path = entry.path();
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let _ = add_pem_source(
                &mut roots,
                &mut apple_anchors,
                &bytes,
                &path.display().to_string(),
                false,
            );
        }
    }
    if let Some(error) = first_directory_error {
        return Err(error);
    }
    let fingerprint = fingerprint(kind, &roots, &apple_anchors);
    Ok(CertificateStoreSnapshot {
        roots: Arc::new(roots),
        apple_anchors: Arc::new(apple_anchors),
        fingerprint,
        generation,
    })
}

fn add_pem_source(
    roots: &mut RootCertStore,
    apple_anchors: &mut Vec<CertificateDer<'static>>,
    bytes: &[u8],
    source_name: &str,
    strict: bool,
) -> Result<(), CertificateStoreError> {
    let certificates = rustls_pemfile::certs(&mut BufReader::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CertificateStoreError::InvalidPem {
            source_name: source_name.into(),
        })?;
    if certificates.is_empty() {
        return Err(CertificateStoreError::InvalidPem {
            source_name: source_name.into(),
        });
    }
    let (accepted, rejected) =
        roots.add_parsable_certificates(certificates.iter().cloned());
    if accepted == 0 || (strict && rejected != 0) {
        return Err(CertificateStoreError::InvalidPem {
            source_name: source_name.into(),
        });
    }
    apple_anchors.extend(certificates);
    Ok(())
}

fn add_der_certificates(
    roots: &mut RootCertStore,
    anchors: &mut Vec<CertificateDer<'static>>,
    certificates: Vec<CertificateDer<'static>>,
    source_name: &str,
    strict: bool,
) -> Result<(), CertificateStoreError> {
    let mut accepted = 0;
    let mut rejected = 0;
    for certificate in certificates {
        let (certificate_accepted, certificate_rejected) = roots
            .add_parsable_certificates(std::iter::once(certificate.clone()));
        accepted += certificate_accepted;
        rejected += certificate_rejected;
        if certificate_accepted != 0 {
            anchors.push(certificate);
        }
    }
    if accepted == 0 || (strict && rejected != 0) {
        return Err(CertificateStoreError::InvalidPem {
            source_name: source_name.into(),
        });
    }
    Ok(())
}

fn add_system_der_certificates(
    roots: &mut RootCertStore,
    anchors: &mut Vec<CertificateDer<'static>>,
    certificates: Vec<CertificateDer<'static>>,
    fallback_pem: Option<&[u8]>,
) -> Result<(), CertificateStoreError> {
    match add_der_certificates(
        roots,
        anchors,
        certificates,
        "system store",
        false,
    ) {
        Ok(()) => Ok(()),
        Err(error) => {
            let Some(fallback_pem) = fallback_pem else {
                return Err(error);
            };
            add_pem_source(
                roots,
                anchors,
                fallback_pem,
                "included Mozilla fallback roots",
                true,
            )
        }
    }
}

fn same_directory_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .ok()
        .is_some_and(|metadata| metadata.file_type().is_symlink())
        && fs::read_link(path).ok().is_some_and(|target| {
            target.components().count() == 1 && !target.is_absolute()
        })
}

fn fingerprint(
    kind: CertificateStoreKind,
    roots: &RootCertStore,
    apple_anchors: &[CertificateDer<'static>],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update([kind as u8]);
    for subject in roots.subjects() {
        digest.update((subject.as_ref().len() as u64).to_be_bytes());
        digest.update(subject.as_ref());
    }
    for certificate in apple_anchors {
        digest.update((certificate.as_ref().len() as u64).to_be_bytes());
        digest.update(certificate.as_ref());
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use rcgen::generate_simple_self_signed;

    use super::*;
    use crate::option::Listable;

    #[test]
    fn typed_options_match_upstream_listable_shape() {
        let options: CertificateOptions = serde_json::from_str(
            r#"{
                "store": "none",
                "certificate": "inline",
                "certificate_path": ["one.pem", "two.pem"],
                "certificate_directory_path": "roots"
            }"#,
        )
        .unwrap();
        assert_eq!(options.store, CertificateStoreKind::None);
        assert_eq!(options.certificate.as_slice(), &["inline"]);
        assert_eq!(options.certificate_path.as_slice().len(), 2);
        assert_eq!(options.certificate_directory_path.as_slice(), &["roots"]);
    }

    #[test]
    fn reload_is_atomic_and_preserves_last_good_generation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("root.pem");
        let first =
            generate_simple_self_signed(vec!["first.test".into()]).unwrap();
        fs::write(&path, first.cert.pem()).unwrap();
        let options = CertificateOptions {
            store: CertificateStoreKind::None,
            certificate_path: Listable(vec!["root.pem".into()]),
            ..Default::default()
        };
        let store = CertificateStore::new(&options, directory.path()).unwrap();
        let initial_subjects = store.root_store().unwrap().subjects().len();
        assert_eq!(initial_subjects, 1);
        fs::write(&path, "not a certificate").unwrap();
        assert!(store.reload().is_err());
        assert_eq!(store.generation(), 0);
        assert_eq!(store.root_store().unwrap().subjects().len(), 1);

        let second =
            generate_simple_self_signed(vec!["second.test".into()]).unwrap();
        fs::write(&path, second.cert.pem()).unwrap();
        assert!(store.reload().unwrap());
        assert_eq!(store.generation(), 1);
        assert_eq!(store.root_store().unwrap().subjects().len(), 1);
    }

    #[test]
    fn bundled_and_none_store_exclusivity_matches_upstream() {
        let none = CertificateStore::new(
            &CertificateOptions {
                store: CertificateStoreKind::None,
                ..Default::default()
            },
            Path::new("."),
        )
        .unwrap();
        assert!(none.exclusive_anchors());
        assert!(none.root_store().unwrap().is_empty());

        let mozilla = CertificateStore::new(
            &CertificateOptions {
                store: CertificateStoreKind::Mozilla,
                ..Default::default()
            },
            Path::new("."),
        )
        .unwrap();
        assert!(mozilla.exclusive_anchors());
        assert!(!mozilla.root_store().unwrap().is_empty());
        assert!(!mozilla.apple_anchors().unwrap().is_empty());
    }

    #[test]
    fn lenient_der_store_skips_bad_system_entries() {
        let certificate =
            generate_simple_self_signed(vec!["system-root.test".into()])
                .unwrap();
        let valid = CertificateDer::from(certificate.cert.der().to_vec());
        let invalid = CertificateDer::from(vec![0xde, 0xad, 0xbe, 0xef]);
        let mut roots = RootCertStore::empty();
        let mut anchors = Vec::new();

        add_der_certificates(
            &mut roots,
            &mut anchors,
            vec![invalid, valid.clone()],
            "system store",
            false,
        )
        .unwrap();

        assert_eq!(roots.subjects().len(), 1);
        assert_eq!(anchors.as_slice(), &[valid]);
    }

    #[test]
    fn system_store_can_fall_back_when_platform_has_no_usable_roots() {
        let fallback =
            generate_simple_self_signed(vec!["fallback-root.test".into()])
                .unwrap();
        let mut roots = RootCertStore::empty();
        let mut anchors = Vec::new();

        add_system_der_certificates(
            &mut roots,
            &mut anchors,
            vec![CertificateDer::from(vec![0xde, 0xad, 0xbe, 0xef])],
            Some(fallback.cert.pem().as_bytes()),
        )
        .unwrap();

        assert_eq!(roots.subjects().len(), 1);
        assert_eq!(anchors.len(), 1);
    }
}
