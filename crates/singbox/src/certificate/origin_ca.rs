//! Cloudflare Origin CA certificate acquisition and renewal.

use std::{
    collections::BTreeSet,
    io,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair,
    PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256, RsaKeySize,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use x509_parser::{extensions::GeneralName, public_key::PublicKey};

use crate::{
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        tls::{DynamicCertificateResolver, certified_key_from_pem},
    },
    option::CloudflareOriginCaCertificateProviderOptions,
};

use super::{CertificateHttpClient, CertificateProviderError};

const CLOUDFLARE_ORIGIN_CA_ENDPOINT: &str =
    "https://api.cloudflare.com/client/v4/certificates";
const DEFAULT_VALIDITY: u16 = 5475;
const DEFAULT_RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const MIN_RETRY: Duration = Duration::from_secs(60);
const MAX_RETRY: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RequestType {
    OriginRsa,
    OriginEcc,
}

impl RequestType {
    fn parse(value: &str) -> Result<Self, CertificateProviderError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "origin-rsa" => Ok(Self::OriginRsa),
            "origin-ecc" => Ok(Self::OriginEcc),
            value => Err(CertificateProviderError::InvalidOriginCa(format!(
                "unsupported request type: {value}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::OriginRsa => "origin-rsa",
            Self::OriginEcc => "origin-ecc",
        }
    }
}

#[derive(Debug, Clone)]
struct LeafInfo {
    not_before: SystemTime,
    not_after: SystemTime,
    hostnames: Vec<String>,
    key_type: RequestType,
}

struct OriginCaCore {
    resolver: Arc<DynamicCertificateResolver>,
    current_leaf: RwLock<Option<LeafInfo>>,
    issue_lock: Mutex<()>,
    http: CertificateHttpClient,
    endpoint: String,
    data_directory: PathBuf,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    lock_path: PathBuf,
    api_token: String,
    origin_ca_key: String,
    domains: Vec<String>,
    request_type: RequestType,
    requested_validity: u16,
}

pub(super) struct OriginCaProviderService {
    name: String,
    core: Arc<OriginCaCore>,
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl OriginCaProviderService {
    pub(super) fn new(
        tag: &str,
        options: CloudflareOriginCaCertificateProviderOptions,
        base_path: &Path,
        http: CertificateHttpClient,
    ) -> Result<
        (Self, Arc<dyn rustls::server::ResolvesServerCert>),
        CertificateProviderError,
    > {
        Self::new_with_endpoint(
            tag,
            options,
            base_path,
            http,
            CLOUDFLARE_ORIGIN_CA_ENDPOINT,
        )
    }

    fn new_with_endpoint(
        tag: &str,
        options: CloudflareOriginCaCertificateProviderOptions,
        base_path: &Path,
        http: CertificateHttpClient,
        endpoint: &str,
    ) -> Result<
        (Self, Arc<dyn rustls::server::ResolvesServerCert>),
        CertificateProviderError,
    > {
        let domains = normalize_hostnames(options.domain.as_slice())?;
        if domains.is_empty() {
            return Err(CertificateProviderError::InvalidOriginCa(
                "missing domain".into(),
            ));
        }
        let api_token = options.api_token.trim().to_owned();
        let origin_ca_key = options.origin_ca_key.trim().to_owned();
        match (api_token.is_empty(), origin_ca_key.is_empty()) {
            (true, true) => {
                return Err(CertificateProviderError::InvalidOriginCa(
                    "api_token or origin_ca_key is required".into(),
                ));
            }
            (false, false) => {
                return Err(CertificateProviderError::InvalidOriginCa(
                    "api_token and origin_ca_key are mutually exclusive".into(),
                ));
            }
            _ => {}
        }
        let request_type = RequestType::parse(&options.request_type)?;
        let requested_validity = if options.requested_validity == 0 {
            DEFAULT_VALIDITY
        } else {
            options.requested_validity
        };
        if !matches!(requested_validity, 7 | 30 | 90 | 365 | 730 | 1095 | 5475)
        {
            return Err(CertificateProviderError::InvalidOriginCa(format!(
                "unsupported requested validity: {requested_validity}"
            )));
        }
        let data_directory = if options.data_directory.is_empty() {
            base_path.join("cloudflare-origin-ca")
        } else {
            let path = PathBuf::from(options.data_directory);
            if path.is_absolute() {
                path
            } else {
                base_path.join(path)
            }
        };
        let mut digest = Sha256::new();
        digest.update(request_type.as_str());
        for domain in &domains {
            digest.update([0]);
            digest.update(domain);
        }
        let cache_key = hex::encode(digest.finalize());
        let certificate_path = data_directory.join(format!("{cache_key}.crt"));
        let private_key_path = data_directory.join(format!("{cache_key}.key"));
        let lock_path = data_directory.join(format!("{cache_key}.lock"));
        let resolver = Arc::new(DynamicCertificateResolver::new());
        let core = Arc::new(OriginCaCore {
            resolver: resolver.clone(),
            current_leaf: RwLock::new(None),
            issue_lock: Mutex::new(()),
            http,
            endpoint: endpoint.into(),
            data_directory,
            certificate_path,
            private_key_path,
            lock_path,
            api_token,
            origin_ca_key,
            domains,
            request_type,
            requested_validity,
        });
        Ok((
            Self {
                name: format!(
                    "certificate-provider/cloudflare-origin-ca[{tag}]"
                ),
                core,
                cancellation: CancellationToken::new(),
                task: None,
            },
            resolver,
        ))
    }
}

impl Lifecycle for OriginCaProviderService {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage == StartStage::Initialize {
                tokio::fs::create_dir_all(&self.core.data_directory)
                    .await
                    .map_err(|error| LifecycleError::Start {
                        component: self.name.clone(),
                        stage,
                        message: format!("create data directory: {error}"),
                    })?;
                return Ok(());
            }
            if stage != StartStage::Start || self.task.is_some() {
                return Ok(());
            }
            let cached = match self.core.load_cached().await {
                Ok(cached) => cached,
                Err(error) => {
                    tracing::warn!(%error, "load cached Cloudflare Origin CA certificate");
                    false
                }
            };
            if !cached {
                self.core.issue_and_store().await.map_err(|error| {
                    LifecycleError::Start {
                        component: self.name.clone(),
                        stage,
                        message: error.to_string(),
                    }
                })?;
            } else if self.core.should_renew(SystemTime::now())
                && let Err(error) = self.core.issue_and_store().await
            {
                tracing::warn!(%error, "renew cached Cloudflare Origin CA certificate");
            }
            let core = self.core.clone();
            let cancellation = self.cancellation.clone();
            self.task = Some(tokio::spawn(async move {
                core.refresh_loop(cancellation).await;
            }));
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
            Ok(())
        })
    }
}

impl OriginCaCore {
    async fn load_cached(&self) -> io::Result<bool> {
        let certificate = match tokio::fs::read(&self.certificate_path).await {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let private_key = match tokio::fs::read(&self.private_key_path).await {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let Some((key, leaf)) =
            self.validated_key_pair(&certificate, &private_key)
        else {
            return Ok(false);
        };
        if SystemTime::now() > leaf.not_after {
            return Ok(false);
        }
        self.publish(key, leaf);
        Ok(true)
    }

    async fn issue_and_store(&self) -> io::Result<()> {
        let _guard = self.issue_lock.lock().await;
        let lock_path = self.lock_path.clone();
        let _storage_lock = tokio::task::spawn_blocking(move || {
            let mut lock =
                fslock::LockFile::open(&lock_path).map_err(io::Error::other)?;
            lock.lock().map_err(io::Error::other)?;
            Ok::<_, io::Error>(lock)
        })
        .await
        .map_err(io::Error::other)??;
        if self.load_cached().await? && !self.should_renew(SystemTime::now()) {
            return Ok(());
        }
        let (certificate, private_key, key, leaf) =
            self.request_certificate().await?;
        write_atomic(&self.private_key_path, &private_key).await?;
        write_atomic(&self.certificate_path, &certificate).await?;
        let expires = leaf
            .not_after
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs())
            .unwrap_or_default();
        self.publish(key, leaf);
        tracing::info!(expires, "updated Cloudflare Origin CA certificate");
        Ok(())
    }

    async fn request_certificate(
        &self,
    ) -> io::Result<(Vec<u8>, Vec<u8>, Arc<rustls::sign::CertifiedKey>, LeafInfo)>
    {
        let key = match self.request_type {
            RequestType::OriginRsa => {
                KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
            }
            RequestType::OriginEcc => {
                KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            }
        }
        .map_err(io::Error::other)?;
        let private_key = key.serialize_pem().into_bytes();
        let mut params = CertificateParams::new(self.domains.clone())
            .map_err(io::Error::other)?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, self.domains[0].clone());
        params.distinguished_name = distinguished_name;
        let csr = params
            .serialize_request(&key)
            .and_then(|csr| csr.pem())
            .map_err(io::Error::other)?;
        let request = OriginCaRequest {
            csr,
            hostnames: &self.domains,
            request_type: self.request_type.as_str(),
            requested_validity: self.requested_validity,
        };
        let body = serde_json::to_vec(&request).map_err(io::Error::other)?;
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("application/json"));
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/json"),
        );
        if !self.api_token.is_empty() {
            headers.insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {}", self.api_token))
                    .map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidInput, error)
                    })?,
            );
        } else {
            headers.insert(
                "x-auth-user-service-key",
                HeaderValue::from_str(&self.origin_ca_key).map_err(
                    |error| io::Error::new(io::ErrorKind::InvalidInput, error),
                )?,
            );
        }
        let response = self
            .http
            .request(Method::POST, &self.endpoint, &headers, Bytes::from(body))
            .await
            .map_err(|error| {
                io::Error::other(format!(
                    "request certificate from Cloudflare: {error}"
                ))
            })?;
        let envelope: Option<OriginCaResponse> =
            serde_json::from_slice(&response.body).ok();
        if !response.status.is_success()
            || !envelope.as_ref().is_some_and(|value| value.success)
        {
            return Err(build_origin_ca_error(
                response.status,
                envelope.as_ref().map(|value| value.errors.as_slice()),
                &response.body,
            ));
        }
        let certificate = envelope
            .and_then(|value| value.result.map(|result| result.certificate))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Cloudflare Origin CA response is missing certificate data",
                )
            })?
            .into_bytes();
        let (key, leaf) = self
            .validated_key_pair(&certificate, &private_key)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "issued Cloudflare Origin CA certificate does not match requested hostnames or key type",
                )
            })?;
        Ok((certificate, private_key, key, leaf))
    }

    fn validated_key_pair(
        &self,
        certificate: &[u8],
        private_key: &[u8],
    ) -> Option<(Arc<rustls::sign::CertifiedKey>, LeafInfo)> {
        let key = certified_key_from_pem(certificate, private_key).ok()?;
        let leaf = parse_leaf(certificate).ok()?;
        if leaf.hostnames != self.domains || leaf.key_type != self.request_type
        {
            return None;
        }
        Some((key, leaf))
    }

    fn publish(&self, key: Arc<rustls::sign::CertifiedKey>, leaf: LeafInfo) {
        self.resolver.set(key);
        *self
            .current_leaf
            .write()
            .expect("Origin CA leaf lock poisoned") = Some(leaf);
    }

    fn should_renew(&self, now: SystemTime) -> bool {
        self.current_leaf
            .read()
            .expect("Origin CA leaf lock poisoned")
            .as_ref()
            .is_none_or(|leaf| {
                now >= leaf
                    .not_after
                    .checked_sub(effective_renew_before(leaf))
                    .unwrap_or(leaf.not_before)
            })
    }

    fn next_wait(&self) -> Duration {
        let now = SystemTime::now();
        self.current_leaf
            .read()
            .expect("Origin CA leaf lock poisoned")
            .as_ref()
            .and_then(|leaf| {
                leaf.not_after
                    .checked_sub(effective_renew_before(leaf))
                    .and_then(|renew_at| renew_at.duration_since(now).ok())
            })
            .unwrap_or(MIN_RETRY)
            .max(MIN_RETRY)
    }

    fn retry_wait(&self) -> Duration {
        let now = SystemTime::now();
        let remaining = self
            .current_leaf
            .read()
            .expect("Origin CA leaf lock poisoned")
            .as_ref()
            .and_then(|leaf| leaf.not_after.duration_since(now).ok());
        match remaining {
            None => MIN_RETRY,
            Some(remaining) if remaining <= MIN_RETRY => MIN_RETRY,
            Some(remaining) if remaining < MAX_RETRY => {
                (remaining / 2).max(MIN_RETRY)
            }
            Some(_) => MAX_RETRY,
        }
    }

    async fn refresh_loop(&self, cancellation: CancellationToken) {
        let mut retry = None;
        loop {
            let wait = retry.unwrap_or_else(|| self.next_wait());
            tokio::select! {
                _ = cancellation.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
            }
            match self.issue_and_store().await {
                Ok(()) => retry = None,
                Err(error) => {
                    tracing::error!(%error, "renew Cloudflare Origin CA certificate");
                    retry = Some(self.retry_wait());
                }
            }
        }
    }
}

fn effective_renew_before(leaf: &LeafInfo) -> Duration {
    leaf.not_after
        .duration_since(leaf.not_before)
        .unwrap_or_default()
        .div_f64(3.0)
        .min(DEFAULT_RENEW_BEFORE)
}

fn normalize_hostnames(
    hostnames: &[String],
) -> Result<Vec<String>, CertificateProviderError> {
    let mut normalized = BTreeSet::new();
    for hostname in hostnames {
        let hostname =
            hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        if hostname.is_empty() {
            return Err(CertificateProviderError::InvalidOriginCa(
                "hostname is empty".into(),
            ));
        }
        if IpAddr::from_str(&hostname).is_ok() {
            return Err(CertificateProviderError::InvalidOriginCa(format!(
                "hostname cannot be an IP address: {hostname}"
            )));
        }
        if hostname.contains('*') {
            let Some(suffix) = hostname.strip_prefix("*.") else {
                return Err(CertificateProviderError::InvalidOriginCa(
                    format!("invalid wildcard hostname: {hostname}"),
                ));
            };
            if suffix.contains('*') {
                return Err(CertificateProviderError::InvalidOriginCa(
                    format!("invalid wildcard hostname: {hostname}"),
                ));
            }
            if !suffix.contains('.') {
                return Err(CertificateProviderError::InvalidOriginCa(
                    format!(
                        "wildcard hostname must cover a multi-label domain: {hostname}"
                    ),
                ));
            }
        }
        normalized.insert(hostname);
    }
    Ok(normalized.into_iter().collect())
}

fn parse_leaf(certificate_pem: &[u8]) -> io::Result<LeafInfo> {
    let pem = pem::parse_many(certificate_pem)
        .map_err(io::Error::other)?
        .into_iter()
        .find(|value| value.tag() == "CERTIFICATE")
        .ok_or_else(|| io::Error::other("certificate chain is empty"))?;
    let (_, certificate) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(io::Error::other)?;
    let mut hostnames = Vec::new();
    if let Some(san) = certificate
        .subject_alternative_name()
        .map_err(io::Error::other)?
    {
        hostnames.extend(san.value.general_names.iter().filter_map(|name| {
            match name {
                GeneralName::DNSName(value) => Some((*value).to_owned()),
                _ => None,
            }
        }));
    }
    if hostnames.is_empty()
        && let Some(common_name) = certificate
            .subject()
            .iter_common_name()
            .next()
            .and_then(|value| value.as_str().ok())
    {
        hostnames.push(common_name.to_owned());
    }
    let hostnames = normalize_hostnames(&hostnames)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let key_type = match certificate
        .public_key()
        .parsed()
        .map_err(io::Error::other)?
    {
        PublicKey::RSA(_) => RequestType::OriginRsa,
        PublicKey::EC(_) => RequestType::OriginEcc,
        _ => {
            return Err(io::Error::other("unsupported certificate public key"));
        }
    };
    Ok(LeafInfo {
        not_before: timestamp_to_system_time(
            certificate.validity().not_before.timestamp(),
        )?,
        not_after: timestamp_to_system_time(
            certificate.validity().not_after.timestamp(),
        )?,
        hostnames,
        key_type,
    })
}

fn timestamp_to_system_time(timestamp: i64) -> io::Result<SystemTime> {
    let seconds = u64::try_from(timestamp).map_err(|_| {
        io::Error::other("certificate time predates Unix epoch")
    })?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

async fn write_atomic(path: &Path, value: &[u8]) -> io::Result<()> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::other("invalid cache path"))?;
    let temporary = path
        .with_file_name(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    tokio::fs::write(&temporary, value).await?;
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

fn build_origin_ca_error(
    status: StatusCode,
    errors: Option<&[OriginCaResponseError]>,
    body: &[u8],
) -> io::Error {
    let messages = errors
        .unwrap_or_default()
        .iter()
        .filter(|error| !error.message.is_empty())
        .map(|error| {
            if error.code == 0 {
                error.message.clone()
            } else {
                format!("{} (code {})", error.message, error.code)
            }
        })
        .collect::<Vec<_>>();
    let detail = if messages.is_empty() {
        String::from_utf8_lossy(body).trim().to_owned()
    } else {
        messages.join(", ")
    };
    let suffix = if detail.is_empty() {
        String::new()
    } else {
        format!(" {detail}")
    };
    io::Error::other(format!(
        "Cloudflare Origin CA request failed: HTTP {}{suffix}",
        status.as_u16()
    ))
}

#[derive(Serialize)]
struct OriginCaRequest<'a> {
    csr: String,
    hostnames: &'a [String],
    request_type: &'static str,
    requested_validity: u16,
}

#[derive(Deserialize)]
struct OriginCaResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<OriginCaResponseError>,
    result: Option<OriginCaResponseResult>,
}

#[derive(Deserialize)]
struct OriginCaResponseError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct OriginCaResponseResult {
    certificate: String,
}

#[cfg(test)]
mod tests {
    use super::{
        LeafInfo, OriginCaProviderService, RequestType, effective_renew_before,
        normalize_hostnames,
    };
    use crate::{
        certificate::CertificateHttpClient,
        common::lifecycle::{Lifecycle, StartStage},
        option::{
            CloudflareOriginCaCertificateProviderOptions,
            DirectOutboundOptions, HttpClientOptions,
        },
        protocol::direct::DirectOutbound,
    };
    use http_body_util::{BodyExt as _, Full};
    use hyper::{Request, Response, body::Incoming, service::service_fn};
    use hyper_util::rt::TokioIo;
    use openssl::{
        asn1::{Asn1Integer, Asn1Time},
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509, X509Req, extension::SubjectAlternativeName},
    };
    use serde_json::Value;
    use std::{
        convert::Infallible,
        sync::Arc,
        time::{Duration, UNIX_EPOCH},
    };
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    #[test]
    fn normalizes_and_validates_origin_hostnames() {
        let hostnames = normalize_hostnames(&[
            " B.Example.COM. ".into(),
            "*.a.example.com".into(),
            "b.example.com".into(),
        ])
        .unwrap();
        assert_eq!(hostnames, ["*.a.example.com", "b.example.com"]);
        for invalid in ["", "127.0.0.1", "*example.com", "*.localhost"] {
            assert!(normalize_hostnames(&[invalid.into()]).is_err());
        }
    }

    #[test]
    fn renews_at_one_third_lifetime_capped_at_thirty_days() {
        let short = LeafInfo {
            not_before: UNIX_EPOCH,
            not_after: UNIX_EPOCH + Duration::from_secs(9 * 24 * 60 * 60),
            hostnames: Vec::new(),
            key_type: RequestType::OriginEcc,
        };
        assert_eq!(
            effective_renew_before(&short),
            Duration::from_secs(3 * 24 * 60 * 60)
        );
        let long = LeafInfo {
            not_after: UNIX_EPOCH + Duration::from_secs(365 * 24 * 60 * 60),
            ..short
        };
        assert_eq!(
            effective_renew_before(&long),
            Duration::from_secs(30 * 24 * 60 * 60)
        );
    }

    #[tokio::test]
    async fn obtains_publishes_and_reuses_an_origin_ca_certificate() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|request: Request<Incoming>| async move {
                        assert_eq!(
                            request.headers()["authorization"],
                            "Bearer test-token"
                        );
                        let body = request.into_body().collect().await.unwrap();
                        let request: Value =
                            serde_json::from_slice(&body.to_bytes()).unwrap();
                        assert_eq!(request["request_type"], "origin-ecc");
                        assert_eq!(request["requested_validity"], 365);
                        let domains = request["hostnames"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|value| value.as_str().unwrap().to_owned())
                            .collect::<Vec<_>>();
                        let certificate = sign_csr(
                            request["csr"].as_str().unwrap(),
                            &domains,
                        );
                        let response = serde_json::to_vec(&serde_json::json!({
                            "success": true,
                            "errors": [],
                            "result": { "certificate": certificate },
                        }))
                        .unwrap();
                        Ok::<_, Infallible>(Response::new(Full::new(
                            bytes::Bytes::from(response),
                        )))
                    }),
                )
                .await
                .unwrap();
        });
        let temporary = TempDir::new().unwrap();
        let options = CloudflareOriginCaCertificateProviderOptions {
            domain: crate::option::Listable(vec![
                "origin.example".into(),
                "*.service.example".into(),
            ]),
            api_token: "test-token".into(),
            request_type: "origin-ecc".into(),
            requested_validity: 365,
            ..Default::default()
        };
        let http = CertificateHttpClient::new(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            HttpClientOptions::default(),
        );
        let (mut service, _resolver) =
            OriginCaProviderService::new_with_endpoint(
                "test",
                options.clone(),
                temporary.path(),
                http.clone(),
                &format!("http://{address}/certificates"),
            )
            .unwrap();
        service.start(StartStage::Initialize).await.unwrap();
        service.start(StartStage::Start).await.unwrap();
        assert!(service.core.resolver.has_certificate());
        service.close().await.unwrap();
        server.await.unwrap();

        // The same provider starts from the persistent cache without making a
        // second API request (the test server has already exited).
        let (mut cached, _) = OriginCaProviderService::new_with_endpoint(
            "cached",
            options,
            temporary.path(),
            http,
            &format!("http://{address}/certificates"),
        )
        .unwrap();
        cached.start(StartStage::Initialize).await.unwrap();
        cached.start(StartStage::Start).await.unwrap();
        assert!(cached.core.resolver.has_certificate());
        cached.close().await.unwrap();
    }

    fn sign_csr(csr: &str, domains: &[String]) -> String {
        let request = X509Req::from_pem(csr.as_bytes()).unwrap();
        assert!(request.verify(&request.public_key().unwrap()).unwrap());
        let signer = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        let serial =
            Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap();
        certificate.set_serial_number(&serial).unwrap();
        certificate
            .set_subject_name(request.subject_name())
            .unwrap();
        certificate.set_issuer_name(request.subject_name()).unwrap();
        certificate
            .set_pubkey(&request.public_key().unwrap())
            .unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        let mut san = SubjectAlternativeName::new();
        for domain in domains {
            san.dns(domain);
        }
        let extension =
            san.build(&certificate.x509v3_context(None, None)).unwrap();
        certificate.append_extension(extension).unwrap();
        certificate.sign(&signer, MessageDigest::sha256()).unwrap();
        String::from_utf8(certificate.build().to_pem().unwrap()).unwrap()
    }
}
