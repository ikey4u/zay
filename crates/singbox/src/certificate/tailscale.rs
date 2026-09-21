//! Tailscale-managed TLS certificates.
//!
//! Tailscale does not issue certificates itself. The node is an RFC 8555
//! client for Let's Encrypt and uses the authenticated `/machine/set-dns`
//! control RPC solely to publish DNS-01 TXT records. This service keeps that
//! network work out of rustls' synchronous certificate resolver.

use std::{
    collections::{BTreeSet, HashMap},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier,
    ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use rand::Rng as _;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier as _},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use x509_parser::extensions::GeneralName;

use super::{CertificateHttpClient, CertificateProviderError};
use crate::{
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        ntp::NtpClock,
        tls::certified_key_from_pem,
    },
    endpoint::tailscale::TailscaleCertificateEndpoint,
};

const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const RETRY_INTERVAL: Duration = Duration::from_secs(60);
const CERTIFICATE_POLL_TIMEOUT: Duration = Duration::from_secs(90);

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Default)]
struct TailscaleCertificateResolver {
    allowed: RwLock<Vec<String>>,
    certificates: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl TailscaleCertificateResolver {
    fn set_allowed(&self, domains: Vec<String>) {
        self.certificates
            .write()
            .expect("Tailscale certificate resolver lock poisoned")
            .retain(|domain, _| domains.contains(domain));
        *self
            .allowed
            .write()
            .expect("Tailscale certificate resolver lock poisoned") = domains;
    }

    fn set(&self, domain: String, certificate: Arc<CertifiedKey>) {
        self.certificates
            .write()
            .expect("Tailscale certificate resolver lock poisoned")
            .insert(domain, certificate);
    }

    fn certificate_for_name(
        &self,
        server_name: &str,
    ) -> Option<Arc<CertifiedKey>> {
        let server_name =
            server_name.trim_end_matches('.').to_ascii_lowercase();
        let allowed = self
            .allowed
            .read()
            .expect("Tailscale certificate resolver lock poisoned");
        let domain = if allowed.iter().any(|domain| domain == &server_name) {
            server_name
        } else if !server_name.contains('.') {
            let prefix = format!("{server_name}.");
            allowed
                .iter()
                .find(|domain| domain.starts_with(&prefix))?
                .clone()
        } else {
            return None;
        };
        self.certificates
            .read()
            .expect("Tailscale certificate resolver lock poisoned")
            .get(&domain)
            .cloned()
    }
}

impl ResolvesServerCert for TailscaleCertificateResolver {
    fn resolve(
        &self,
        client_hello: ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        self.certificate_for_name(client_hello.server_name()?)
    }
}

pub(super) type EndpointBinding =
    Arc<RwLock<Option<TailscaleCertificateEndpoint>>>;

pub(super) struct TailscaleCertificateProviderService {
    name: String,
    endpoint_tag: String,
    endpoint: EndpointBinding,
    resolver: Arc<TailscaleCertificateResolver>,
    http: CertificateHttpClient,
    clock: Option<NtpClock>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl TailscaleCertificateProviderService {
    pub(super) fn new(
        tag: &str,
        endpoint_tag: String,
        http: CertificateHttpClient,
        clock: Option<NtpClock>,
    ) -> Result<
        (Self, Arc<dyn ResolvesServerCert>, EndpointBinding),
        CertificateProviderError,
    > {
        if endpoint_tag.is_empty() {
            return Err(CertificateProviderError::InvalidTailscale(
                "missing tailscale endpoint tag".into(),
            ));
        }
        let resolver = Arc::new(TailscaleCertificateResolver::default());
        let endpoint = Arc::new(RwLock::new(None));
        Ok((
            Self {
                name: format!("certificate-provider/tailscale[{tag}]"),
                endpoint_tag,
                endpoint: endpoint.clone(),
                resolver: resolver.clone(),
                http,
                clock,
                cancellation: CancellationToken::new(),
                task: None,
            },
            resolver,
            endpoint,
        ))
    }
}

impl Lifecycle for TailscaleCertificateProviderService {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start || self.task.is_some() {
                return Ok(());
            }
            let endpoint = self
                .endpoint
                .read()
                .expect("Tailscale certificate endpoint lock poisoned")
                .clone()
                .ok_or_else(|| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: format!(
                        "Tailscale endpoint not found: {}",
                        self.endpoint_tag
                    ),
                })?;
            let directory = endpoint.state_directory().join("certs");
            tokio::fs::create_dir_all(&directory)
                .await
                .map_err(|error| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: format!(
                        "create Tailscale certificate directory: {error}"
                    ),
                })?;
            set_directory_permissions(&directory)
                .await
                .map_err(|error| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: format!(
                        "protect Tailscale certificate directory: {error}"
                    ),
                })?;
            self.cancellation = CancellationToken::new();
            let worker = TailscaleCertificateWorker {
                endpoint,
                resolver: self.resolver.clone(),
                http: self.http.clone(),
                clock: self.clock.clone(),
                directory,
                cancellation: self.cancellation.clone(),
                renew_at: Mutex::new(HashMap::new()),
            };
            self.task = Some(tokio::spawn(worker.run()));
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            if let Some(mut task) = self.task.take()
                && tokio::time::timeout(Duration::from_secs(10), &mut task)
                    .await
                    .is_err()
            {
                task.abort();
                let _ = task.await;
            }
            Ok(())
        })
    }
}

struct TailscaleCertificateWorker {
    endpoint: TailscaleCertificateEndpoint,
    resolver: Arc<TailscaleCertificateResolver>,
    http: CertificateHttpClient,
    clock: Option<NtpClock>,
    directory: PathBuf,
    cancellation: CancellationToken,
    renew_at: Mutex<HashMap<String, SystemTime>>,
}

impl TailscaleCertificateWorker {
    async fn run(self) {
        let mut netmap = self.endpoint.netmap_receiver();
        let mut control = self.endpoint.control_receiver();
        let mut delay = Duration::ZERO;
        loop {
            if !delay.is_zero() {
                tokio::select! {
                    _ = self.cancellation.cancelled() => break,
                    changed = netmap.changed() => {
                        if changed.is_err() { break; }
                    }
                    changed = control.changed() => {
                        if changed.is_err() { break; }
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            if self.cancellation.is_cancelled() {
                break;
            }
            delay = match self.reconcile(&netmap, &control).await {
                Ok(()) => CHECK_INTERVAL,
                Err(error) => {
                    tracing::error!(%error, "Tailscale certificate provider failed");
                    RETRY_INTERVAL
                }
            };
        }
    }

    async fn reconcile(
        &self,
        netmap: &tokio::sync::watch::Receiver<
            Option<Arc<crate::protocol::tailscale_control_types::TailscaleNetmapState>>,
        >,
        control: &tokio::sync::watch::Receiver<
            Option<
                Arc<crate::endpoint::tailscale::TailscaleCertificateControl>,
            >,
        >,
    ) -> Result<(), BoxError> {
        let Some(netmap) = netmap.borrow().clone() else {
            self.resolver.set_allowed(Vec::new());
            return Ok(());
        };
        let domains = normalized_certificate_domains(
            netmap
                .dns_config
                .as_ref()
                .map(|dns| dns.certificate_domains.as_slice())
                .unwrap_or_default(),
        )?;
        self.resolver.set_allowed(domains.clone());
        let now = self.now();
        let control = control.borrow().clone();
        for domain in domains {
            let cached = self.load_cached(&domain, now).await;
            let should_issue = match cached {
                Ok(cached) => {
                    let renew = self.should_renew(&domain, &cached, now).await;
                    self.resolver.set(domain.clone(), cached.certificate);
                    renew
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => true,
                Err(error) => {
                    tracing::warn!(%error, %domain, "ignore invalid cached Tailscale certificate");
                    true
                }
            };
            if should_issue && let Some(control) = control.as_ref() {
                self.issue_and_store(&domain, control.clone()).await?;
            }
        }
        Ok(())
    }

    fn now(&self) -> SystemTime {
        self.clock
            .as_ref()
            .map(NtpClock::now)
            .unwrap_or_else(SystemTime::now)
    }

    async fn load_cached(
        &self,
        domain: &str,
        now: SystemTime,
    ) -> io::Result<CachedCertificate> {
        let (certificate, private_key) = tokio::try_join!(
            tokio::fs::read(certificate_path(&self.directory, domain)),
            tokio::fs::read(private_key_path(&self.directory, domain)),
        )?;
        let validity = certificate_validity(&certificate, domain, now)?;
        let certified = certified_key_from_pem(&certificate, &private_key)
            .map_err(io::Error::other)?;
        Ok(CachedCertificate {
            certificate: certified,
            renew_at: validity.renew_at,
            leaf_der: validity.leaf_der,
        })
    }

    async fn should_renew(
        &self,
        domain: &str,
        cached: &CachedCertificate,
        now: SystemTime,
    ) -> bool {
        if let Some(renew_at) = self
            .renew_at
            .lock()
            .expect("Tailscale certificate renewal lock poisoned")
            .get(domain)
            .copied()
        {
            return now >= renew_at;
        }
        let ari = async {
            let account = self.cached_account().await?;
            let identifier = CertificateIdentifier::try_from(&cached.leaf_der)?;
            let (information, _) = account.renewal_info(&identifier).await?;
            let start = information.suggested_window.start.unix_timestamp();
            let end = information.suggested_window.end.unix_timestamp();
            if start < 0 || end <= start {
                return Err::<SystemTime, BoxError>(
                    "ACME ARI returned an invalid suggested window".into(),
                );
            }
            let offset = rand::thread_rng().gen_range(0..(end - start));
            Ok(UNIX_EPOCH + Duration::from_secs((start + offset) as u64))
        }
        .await;
        let renew_at = match ari {
            Ok(renew_at) => renew_at,
            Err(error) => {
                tracing::debug!(%error, %domain, "ACME ARI unavailable; use two-thirds certificate lifetime");
                cached.renew_at
            }
        };
        self.renew_at
            .lock()
            .expect("Tailscale certificate renewal lock poisoned")
            .insert(domain.to_owned(), renew_at);
        now >= renew_at
    }

    async fn issue_and_store(
        &self,
        domain: &str,
        control: Arc<crate::endpoint::tailscale::TailscaleCertificateControl>,
    ) -> Result<(), BoxError> {
        let lock_path = self.directory.join(".lock");
        let _lock = tokio::task::spawn_blocking(move || {
            let mut lock = fslock::LockFile::open(&lock_path)?;
            lock.lock()?;
            Ok::<_, io::Error>(lock)
        })
        .await??;
        if let Ok(cached) = self.load_cached(domain, self.now()).await
            && !self.should_renew(domain, &cached, self.now()).await
        {
            self.resolver.set(domain.to_owned(), cached.certificate);
            return Ok(());
        }

        let account = self.account().await?;
        let identifier = Identifier::Dns(domain.to_owned());
        let mut order =
            account.new_order(&NewOrder::new(&[identifier])).await?;
        let challenge_result: Result<(), BoxError> = tokio::select! {
            _ = self.cancellation.cancelled() => Err("Tailscale certificate issuance cancelled".into()),
            result = async {
                let mut authorizations = order.authorizations();
                while let Some(authorization) = authorizations.next().await {
                    let mut authorization = authorization?;
                    if authorization.status == AuthorizationStatus::Valid {
                        continue;
                    }
                    let mut challenge = authorization
                        .challenge(ChallengeType::Dns01)
                        .ok_or("ACME server did not offer DNS-01")?;
                    let value = challenge.key_authorization().dns_value();
                    control
                        .set_dns(format!("_acme-challenge.{domain}"), value)
                        .await
                        .map_err(|error| -> BoxError { error.into() })?;
                    challenge.set_ready().await?;
                }
                match order.poll_ready(&RetryPolicy::default()).await? {
                    OrderStatus::Ready => Ok(()),
                    status => Err(format!("ACME order became {status:?}").into()),
                }
            } => result,
        };
        challenge_result?;

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let params = CertificateParams::new(vec![domain.to_owned()])?;
        let csr = params.serialize_request(&key)?;
        order.finalize_csr(csr.der()).await?;
        let certificate = order
            .poll_certificate(
                &RetryPolicy::default().timeout(CERTIFICATE_POLL_TIMEOUT),
            )
            .await?;
        let private_key = key.serialize_pem();
        let certified = certified_key_from_pem(
            certificate.as_bytes(),
            private_key.as_bytes(),
        )
        .map_err(io::Error::other)?;
        write_atomic(
            &private_key_path(&self.directory, domain),
            private_key.as_bytes(),
            0o600,
        )
        .await?;
        write_atomic(
            &certificate_path(&self.directory, domain),
            certificate.as_bytes(),
            0o644,
        )
        .await?;
        self.resolver.set(domain.to_owned(), certified);
        self.renew_at
            .lock()
            .expect("Tailscale certificate renewal lock poisoned")
            .remove(domain);
        Ok(())
    }

    async fn cached_account(&self) -> Result<Account, BoxError> {
        let encoded =
            tokio::fs::read(self.directory.join("acme-account.json")).await?;
        let credentials: AccountCredentials = serde_json::from_slice(&encoded)?;
        Ok(Account::builder_with_http(Box::new(self.http.clone()))
            .from_credentials(credentials)
            .await?)
    }

    async fn account(&self) -> Result<Account, BoxError> {
        let path = self.directory.join("acme-account.json");
        if let Ok(encoded) = tokio::fs::read(&path).await {
            let credentials: AccountCredentials =
                serde_json::from_slice(&encoded)?;
            return Ok(Account::builder_with_http(Box::new(self.http.clone()))
                .from_credentials(credentials)
                .await?);
        }
        let (account, credentials) =
            Account::builder_with_http(Box::new(self.http.clone()))
                .create(
                    &NewAccount {
                        contact: &[],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    LetsEncrypt::Production.url().to_owned(),
                    None,
                )
                .await?;
        write_atomic(&path, &serde_json::to_vec_pretty(&credentials)?, 0o600)
            .await?;
        Ok(account)
    }
}

struct CachedCertificate {
    certificate: Arc<CertifiedKey>,
    renew_at: SystemTime,
    leaf_der: CertificateDer<'static>,
}

struct CertificateValidity {
    renew_at: SystemTime,
    leaf_der: CertificateDer<'static>,
}

fn normalized_certificate_domains(
    domains: &[String],
) -> Result<Vec<String>, BoxError> {
    let mut normalized = BTreeSet::new();
    for domain in domains {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if !valid_looking_domain(&domain) {
            return Err(format!(
                "invalid Tailscale certificate domain {domain:?}"
            )
            .into());
        }
        normalized.insert(domain);
    }
    Ok(normalized.into_iter().collect())
}

fn valid_looking_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.contains('.')
        && !domain.contains("..")
        && !domain.contains([':', '/', '\\', '\0'])
}

fn certificate_validity(
    certificate_pem: &[u8],
    domain: &str,
    now: SystemTime,
) -> io::Result<CertificateValidity> {
    let certificates = pem::parse_many(certificate_pem)
        .map_err(io::Error::other)?
        .into_iter()
        .filter(|value| value.tag() == "CERTIFICATE")
        .map(|value| CertificateDer::from(value.into_contents()))
        .collect::<Vec<_>>();
    let leaf = certificates
        .first()
        .ok_or_else(|| io::Error::other("certificate chain is empty"))?;
    let roots = RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    );
    verify_certificate_chain(&certificates, domain, now, Arc::new(roots))?;
    let (_, certificate) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(io::Error::other)?;
    let names = certificate
        .subject_alternative_name()
        .map_err(io::Error::other)?
        .into_iter()
        .flat_map(|san| san.value.general_names.iter())
        .filter_map(|name| match name {
            GeneralName::DNSName(name) => Some(*name),
            _ => None,
        })
        .collect::<Vec<_>>();
    if !names.iter().any(|name| name.eq_ignore_ascii_case(domain)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate does not cover the Tailscale domain",
        ));
    }
    let not_before = timestamp_to_system_time(
        certificate.validity().not_before.timestamp(),
    )?;
    let not_after =
        timestamp_to_system_time(certificate.validity().not_after.timestamp())?;
    if now < not_before || now >= not_after {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Tailscale certificate is not currently valid",
        ));
    }
    let lifetime = not_after
        .duration_since(not_before)
        .map_err(io::Error::other)?;
    let renew_at = not_before + lifetime.mul_f64(2.0 / 3.0);
    Ok(CertificateValidity {
        renew_at,
        leaf_der: leaf.clone(),
    })
}

fn verify_certificate_chain(
    certificates: &[CertificateDer<'static>],
    domain: &str,
    now: SystemTime,
    roots: Arc<RootCertStore>,
) -> io::Result<()> {
    let leaf = certificates
        .first()
        .ok_or_else(|| io::Error::other("certificate chain is empty"))?;
    let server_name =
        ServerName::try_from(domain.to_owned()).map_err(io::Error::other)?;
    let now = now
        .duration_since(UNIX_EPOCH)
        .map(UnixTime::since_unix_epoch)
        .map_err(io::Error::other)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = WebPkiServerVerifier::builder_with_provider(roots, provider)
        .build()
        .map_err(io::Error::other)?;
    verifier
        .verify_server_cert(leaf, &certificates[1..], &server_name, &[], now)
        .map_err(io::Error::other)?;
    Ok(())
}

fn timestamp_to_system_time(timestamp: i64) -> io::Result<SystemTime> {
    let seconds = u64::try_from(timestamp).map_err(|_| {
        io::Error::other("certificate time predates Unix epoch")
    })?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

fn certificate_path(directory: &Path, domain: &str) -> PathBuf {
    directory.join(format!("{domain}.crt"))
}

fn private_key_path(directory: &Path, domain: &str) -> PathBuf {
    directory.join(format!("{domain}.key"))
}

async fn write_atomic(path: &Path, value: &[u8], mode: u32) -> io::Result<()> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            io::Error::other("invalid Tailscale certificate path")
        })?;
    let temporary = path
        .with_file_name(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    tokio::fs::write(&temporary, value).await?;
    set_file_permissions(&temporary, mode).await?;
    if let Err(error) = tokio::fs::rename(&temporary, path).await {
        if error.kind() != io::ErrorKind::AlreadyExists {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error);
        }
        tokio::fs::remove_file(path).await?;
        tokio::fs::rename(&temporary, path).await?;
    }
    Ok(())
}

#[cfg(unix)]
async fn set_directory_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .await
}

#[cfg(not(unix))]
async fn set_directory_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
async fn set_file_permissions(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .await
}

#[cfg(not(unix))]
async fn set_file_permissions(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::SystemTime};

    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    use super::{
        TailscaleCertificateResolver, certificate_validity,
        normalized_certificate_domains, verify_certificate_chain,
    };
    use crate::common::tls::certified_key_from_pem;

    #[test]
    fn validates_and_normalizes_control_certificate_domains() {
        assert_eq!(
            normalized_certificate_domains(&[
                "B.ts.net.".into(),
                "a.ts.net".into(),
                "a.ts.net".into(),
            ])
            .unwrap(),
            ["a.ts.net", "b.ts.net"]
        );
        for invalid in
            ["", "single", "../escape.ts.net", "a..ts.net", "a/b.ts.net"]
        {
            assert!(normalized_certificate_domains(&[invalid.into()]).is_err());
        }
    }

    #[test]
    fn resolver_is_sni_scoped_and_expands_bare_labels() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let certificate =
            CertificateParams::new(vec!["node.tail.ts.net".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
        let certified = certified_key_from_pem(
            certificate.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let resolver = TailscaleCertificateResolver::default();
        resolver.set_allowed(vec!["node.tail.ts.net".into()]);
        resolver.set("node.tail.ts.net".into(), certified.clone());
        assert!(Arc::ptr_eq(
            &resolver.certificate_for_name("node.tail.ts.net").unwrap(),
            &certified
        ));
        assert!(resolver.certificate_for_name("node").is_some());
        assert!(resolver.certificate_for_name("other.tail.ts.net").is_none());
        resolver.set_allowed(vec!["other.tail.ts.net".into()]);
        assert!(resolver.certificate_for_name("node.tail.ts.net").is_none());
    }

    #[test]
    fn cached_certificate_requires_matching_san_and_current_validity() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let certificate =
            CertificateParams::new(vec!["node.tail.ts.net".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
        let encoded = certificate.pem();
        let certificate_der = certificate.der().clone();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate_der.clone()).unwrap();
        assert!(
            verify_certificate_chain(
                std::slice::from_ref(&certificate_der),
                "node.tail.ts.net",
                SystemTime::now(),
                Arc::new(roots.clone()),
            )
            .is_ok()
        );
        assert!(
            verify_certificate_chain(
                &[certificate_der],
                "other.tail.ts.net",
                SystemTime::now(),
                Arc::new(roots),
            )
            .is_err()
        );
        assert!(
            certificate_validity(
                encoded.as_bytes(),
                "node.tail.ts.net",
                SystemTime::now(),
            )
            .is_err()
        );
    }
}
