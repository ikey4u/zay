//! Advanced ACME issuance using `instant-acme`.

use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType,
    ExternalAccountKey, Identifier, Key, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy, ZeroSsl,
};
use rcgen::{
    CertificateParams, CustomExtension, KeyPair, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256, RsaKeySize,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use crate::{
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        tls::{DynamicCertificateResolver, certified_key_from_pem},
    },
    option::{
        AcmeCertificateProviderOptions, AcmeExternalAccountOptions, AcmeKeyType,
    },
};

use super::{
    CertificateHttpClient, CertificateProviderError,
    acme_custom::AcmeSession,
    acme_dns::{Dns01Solver, ProvisionedRecord},
    acme_signer::AcmeAccountSigner,
};

const RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const RETRY_MIN: Duration = Duration::from_secs(60);
const RETRY_MAX: Duration = Duration::from_secs(60 * 60);
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const ZEROSSL_EAB_ENDPOINT: &str =
    "https://api.zerossl.com/acme/eab-credentials-email";

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(serde::Deserialize, serde::Serialize)]
struct CustomAccountCredentials {
    format: String,
    id: String,
    directory: String,
    key_pkcs8: String,
}

struct AdvancedAcmeCore {
    resolver: Arc<DynamicCertificateResolver>,
    http: CertificateHttpClient,
    directory_url: String,
    email: String,
    account_key: Option<Vec<u8>>,
    external_account: Option<AcmeExternalAccountOptions>,
    domains: Vec<String>,
    key_type: AcmeKeyType,
    profile: String,
    account_path: PathBuf,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    lock_path: PathBuf,
    http01: Arc<RwLock<HashMap<String, String>>>,
    dns01: Option<Dns01Solver>,
    use_tls_alpn: bool,
}

pub(super) struct AdvancedAcmeProviderService {
    name: String,
    core: Arc<AdvancedAcmeCore>,
    http01_port: u16,
    tls_alpn_port: Option<u16>,
    cancellation: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl AdvancedAcmeProviderService {
    pub(super) fn new(
        tag: &str,
        options: AcmeCertificateProviderOptions,
        base_path: &Path,
        http: CertificateHttpClient,
    ) -> Result<
        (Self, Arc<dyn rustls::server::ResolvesServerCert>, bool),
        CertificateProviderError,
    > {
        validate_options(&options)?;
        let use_tls_alpn = options.dns01_challenge.is_none()
            && !options.disable_tls_alpn_challenge;
        let directory_url = match options.provider.as_str() {
            "" | "letsencrypt" => LetsEncrypt::Production.url().to_owned(),
            "zerossl" => ZeroSsl::Production.url().to_owned(),
            provider => provider.to_owned(),
        };
        let data_directory = if options.data_directory.is_empty() {
            base_path.join("acme")
        } else {
            let path = PathBuf::from(&options.data_directory);
            if path.is_absolute() {
                path
            } else {
                base_path.join(path)
            }
        };
        let mut digest = Sha256::new();
        digest.update(&directory_url);
        digest.update([0]);
        digest.update(options.email.trim());
        digest.update([0]);
        digest.update(options.key_type.as_str());
        digest.update([0]);
        digest.update(&options.profile);
        for domain in options.domain.as_slice() {
            digest.update([0]);
            digest.update(domain);
        }
        let cache_key = hex::encode(digest.finalize());
        let resolver = Arc::new(DynamicCertificateResolver::new());
        let dns01 = options
            .dns01_challenge
            .map(|options| Dns01Solver::new(options, http.clone()))
            .transpose()?;
        let core = Arc::new(AdvancedAcmeCore {
            resolver: resolver.clone(),
            http,
            directory_url,
            email: options.email.trim().to_owned(),
            account_key: super::normalize_acme_account_key(
                &options.account_key,
            )?,
            external_account: options.external_account,
            domains: options.domain.0,
            key_type: options.key_type,
            profile: options.profile,
            account_path: data_directory
                .join(format!("{cache_key}.account.json")),
            certificate_path: data_directory.join(format!("{cache_key}.crt")),
            private_key_path: data_directory.join(format!("{cache_key}.key")),
            lock_path: data_directory.join(format!("{cache_key}.lock")),
            http01: Arc::new(RwLock::new(HashMap::new())),
            dns01,
            use_tls_alpn,
        });
        Ok((
            Self {
                name: format!("certificate-provider/acme[{tag}]"),
                core,
                http01_port: if options.alternative_http_port == 0 {
                    80
                } else {
                    options.alternative_http_port
                },
                tls_alpn_port: (use_tls_alpn
                    && options.alternative_tls_port != 0)
                    .then_some(options.alternative_tls_port),
                cancellation: CancellationToken::new(),
                tasks: Vec::new(),
            },
            resolver,
            use_tls_alpn,
        ))
    }
}

impl Lifecycle for AdvancedAcmeProviderService {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            match stage {
                StartStage::Initialize => {
                    if let Some(parent) = self.core.account_path.parent() {
                        tokio::fs::create_dir_all(parent).await.map_err(
                            |error| LifecycleError::Start {
                                component: self.name.clone(),
                                stage,
                                message: format!(
                                    "create ACME data directory: {error}"
                                ),
                            },
                        )?;
                    }
                    if let Err(error) =
                        self.core.load_cached_certificate().await
                    {
                        tracing::warn!(%error, "ignore invalid cached ACME certificate");
                    }
                }
                StartStage::Start if self.tasks.is_empty() => {
                    if self.core.dns01.is_none() && !self.core.use_tls_alpn {
                        let listeners = super::bind_http01_listeners(
                            self.http01_port,
                        )
                        .map_err(|error| LifecycleError::Start {
                            component: self.name.clone(),
                            stage,
                            message: format!(
                                "bind ACME HTTP-01 listener on port {}: {error}",
                                self.http01_port
                            ),
                        })?;
                        for listener in listeners {
                            let values = self.core.http01.clone();
                            let cancellation = self.cancellation.clone();
                            self.tasks.push(tokio::spawn(async move {
                                run_http01_listener(
                                    listener,
                                    values,
                                    cancellation,
                                )
                                .await;
                            }));
                        }
                    }
                    if let Some(port) = self.tls_alpn_port {
                        let listeners = super::bind_http01_listeners(port)
                            .map_err(|error| LifecycleError::Start {
                                component: self.name.clone(),
                                stage,
                                message: format!(
                                    "bind ACME TLS-ALPN-01 listener on port {port}: {error}"
                                ),
                            })?;
                        let config = tls_alpn_server_config(
                            self.core.resolver.clone(),
                        )
                        .map_err(|error| LifecycleError::Start {
                            component: self.name.clone(),
                            stage,
                            message: format!(
                                "configure ACME TLS-ALPN-01 listener: {error}"
                            ),
                        })?;
                        for listener in listeners {
                            let config = config.clone();
                            let cancellation = self.cancellation.clone();
                            self.tasks.push(tokio::spawn(async move {
                                run_tls_alpn_listener(
                                    listener,
                                    config,
                                    cancellation,
                                )
                                .await;
                            }));
                        }
                    }
                    let core = self.core.clone();
                    let cancellation = self.cancellation.clone();
                    self.tasks.push(tokio::spawn(async move {
                        run_renewal_loop(core, cancellation).await;
                    }));
                }
                _ => {}
            }
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            for mut task in self.tasks.drain(..) {
                if tokio::time::timeout(Duration::from_secs(10), &mut task)
                    .await
                    .is_err()
                {
                    task.abort();
                    let _ = task.await;
                }
            }
            self.core
                .http01
                .write()
                .expect("ACME HTTP-01 lock poisoned")
                .clear();
            Ok(())
        })
    }
}

impl AdvancedAcmeCore {
    async fn load_cached_certificate(&self) -> io::Result<()> {
        let (certificate, private_key) = tokio::try_join!(
            tokio::fs::read(&self.certificate_path),
            tokio::fs::read(&self.private_key_path),
        )?;
        if !certificate_valid_for(&certificate, Duration::ZERO) {
            return Err(io::Error::other(
                "cached ACME certificate is expired or invalid",
            ));
        }
        let certified = certified_key_from_pem(&certificate, &private_key)
            .map_err(io::Error::other)?;
        self.resolver.set(certified);
        Ok(())
    }

    async fn account(&self) -> Result<Account, BoxError> {
        if let Ok(encoded) = tokio::fs::read(&self.account_path).await {
            let credentials: AccountCredentials =
                serde_json::from_slice(&encoded)?;
            if self.account_key.as_ref().is_none_or(|configured| {
                credentials.private_key().secret_pkcs8_der() == configured
            }) {
                return Ok(Account::builder_with_http(Box::new(
                    self.http.clone(),
                ))
                .from_credentials(credentials)
                .await?);
            }
        }

        let external_account = match self.external_account.as_ref() {
            Some(options) => Some(parse_external_account(options)?),
            None if self.directory_url == ZeroSsl::Production.url()
                && self.account_key.is_none() =>
            {
                Some(self.fetch_zerossl_eab().await?)
            }
            None => None,
        };
        let builder = Account::builder_with_http(Box::new(self.http.clone()));
        let (account, credentials) = if let Some(key) = &self.account_key {
            let key_der = PrivatePkcs8KeyDer::from(key.clone());
            let key_pair = Key::from_pkcs8_der(key_der.clone_key())?;
            builder
                .from_key(
                    (key_pair, PrivateKeyDer::Pkcs8(key_der)),
                    self.directory_url.clone(),
                )
                .await?
        } else {
            let contacts = (!self.email.is_empty())
                .then(|| format!("mailto:{}", self.email))
                .into_iter()
                .collect::<Vec<_>>();
            let contact_refs =
                contacts.iter().map(String::as_str).collect::<Vec<_>>();
            builder
                .create(
                    &NewAccount {
                        contact: &contact_refs,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    self.directory_url.clone(),
                    external_account.as_ref(),
                )
                .await?
        };
        write_file_atomic(
            &self.account_path,
            &serde_json::to_vec_pretty(&credentials)?,
        )
        .await?;
        Ok(account)
    }

    async fn fetch_zerossl_eab(&self) -> Result<ExternalAccountKey, BoxError> {
        if self.email.is_empty() {
            return Err(
                "email is required to generate ZeroSSL EAB credentials".into(),
            );
        }
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("email", &self.email)
            .finish();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let response = self
            .http
            .request(
                http::Method::POST,
                ZEROSSL_EAB_ENDPOINT,
                &headers,
                Bytes::from(body),
            )
            .await?;
        #[derive(serde::Deserialize)]
        struct Response {
            #[serde(default)]
            success: bool,
            #[serde(default)]
            eab_kid: String,
            #[serde(default)]
            eab_hmac_key: String,
        }
        let value: Response = serde_json::from_slice(&response.body)?;
        if !response.status.is_success()
            || !value.success
            || value.eab_kid.is_empty()
            || value.eab_hmac_key.is_empty()
        {
            return Err(format!(
                "failed getting ZeroSSL EAB credentials: HTTP {}",
                response.status
            )
            .into());
        }
        let mac = decode_eab_mac(&value.eab_hmac_key)?;
        Ok(ExternalAccountKey::new(value.eab_kid, &mac))
    }

    async fn issue_and_store(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<(), BoxError> {
        let lock_path = self.lock_path.clone();
        let _storage_lock = tokio::task::spawn_blocking(move || {
            let mut lock = fslock::LockFile::open(&lock_path)?;
            lock.lock()?;
            Ok::<_, io::Error>(lock)
        })
        .await??;
        if cached_certificate_is_fresh(&self.certificate_path).await {
            self.load_cached_certificate().await?;
            return Ok(());
        }
        if let Some(key) = &self.account_key {
            let signer = AcmeAccountSigner::from_pkcs8(key)?;
            if !signer.is_p256() {
                return self
                    .issue_with_custom_account(cancellation, signer)
                    .await;
            }
        }
        let account = self.account().await?;
        let identifiers = self
            .domains
            .iter()
            .map(|domain| match domain.parse::<IpAddr>() {
                Ok(address) => Identifier::Ip(address),
                Err(_) => Identifier::Dns(domain.clone()),
            })
            .collect::<Vec<_>>();
        let mut request = NewOrder::new(&identifiers);
        if !self.profile.is_empty() {
            request = request.profile(&self.profile);
        } else if self.directory_url == LetsEncrypt::Production.url()
            && identifiers
                .iter()
                .any(|identifier| matches!(identifier, Identifier::Ip(_)))
        {
            request = request.profile("shortlived");
        }
        let mut order = account.new_order(&request).await?;
        let mut dns_records: Vec<ProvisionedRecord> = Vec::new();
        let challenge_result: Result<(), BoxError> = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                Err("ACME issuance cancelled".into())
            }
            result = async {
                let mut authorizations = order.authorizations();
                while let Some(authorization) = authorizations.next().await {
                    let mut authorization = authorization?;
                    if authorization.status == AuthorizationStatus::Valid {
                        continue;
                    }
                    if let Some(solver) = &self.dns01 {
                        let domain = authorization.identifier().to_string();
                        let mut challenge = authorization
                            .challenge(ChallengeType::Dns01)
                            .ok_or("ACME server did not offer DNS-01")?;
                        let name = solver.record_name(&domain);
                        let value = challenge.key_authorization().dns_value();
                        let record = solver.present(&name, &value).await?;
                        dns_records.push(record);
                        solver.wait(&name, &value).await?;
                        challenge.set_ready().await?;
                    } else if self.use_tls_alpn {
                        let domain = authorization.identifier().to_string();
                        let mut challenge = authorization
                            .challenge(ChallengeType::TlsAlpn01)
                            .ok_or("ACME server did not offer TLS-ALPN-01")?;
                        let key_authorization = challenge.key_authorization();
                        let certified = generate_tls_alpn_certificate(
                            &domain,
                            key_authorization.digest().as_ref(),
                        )?;
                        self.resolver
                            .set_acme_tls_alpn(domain, certified);
                        challenge.set_ready().await?;
                    } else {
                        let mut challenge = authorization
                            .challenge(ChallengeType::Http01)
                            .ok_or("ACME server did not offer HTTP-01")?;
                        let token = challenge.token.clone();
                        let value = challenge
                            .key_authorization()
                            .as_str()
                            .to_owned();
                        self.http01
                            .write()
                            .expect("ACME HTTP-01 lock poisoned")
                            .insert(token, value);
                        challenge.set_ready().await?;
                    }
                }
                match order.poll_ready(&RetryPolicy::default()).await? {
                    OrderStatus::Ready => Ok(()),
                    status => {
                        Err(format!("ACME order became {status:?}").into())
                    }
                }
            }
            => result,
        };
        self.http01
            .write()
            .expect("ACME HTTP-01 lock poisoned")
            .clear();
        self.resolver.clear_acme_tls_alpn();
        if let Some(solver) = &self.dns01 {
            for record in dns_records.drain(..).rev() {
                if let Err(error) = solver.cleanup(record).await {
                    tracing::warn!(%error, "clean up ACME DNS-01 record");
                }
            }
        }
        challenge_result?;

        let key = generate_certificate_key(self.key_type)?;
        let params = CertificateParams::new(self.domains.clone())?;
        let csr = params.serialize_request(&key)?;
        order.finalize_csr(csr.der()).await?;
        let certificate = order
            .poll_certificate(
                &RetryPolicy::default().timeout(Duration::from_secs(90)),
            )
            .await?;
        let private_key = key.serialize_pem();
        let certified = certified_key_from_pem(
            certificate.as_bytes(),
            private_key.as_bytes(),
        )
        .map_err(io::Error::other)?;
        write_file_atomic(&self.private_key_path, private_key.as_bytes())
            .await?;
        write_file_atomic(&self.certificate_path, certificate.as_bytes())
            .await?;
        self.resolver.set(certified);
        Ok(())
    }

    async fn issue_with_custom_account(
        &self,
        cancellation: &CancellationToken,
        signer: AcmeAccountSigner,
    ) -> Result<(), BoxError> {
        let key_pkcs8 = signer.pkcs8().to_vec();
        let mut session = AcmeSession::connect(
            self.http.clone(),
            &self.directory_url,
            signer,
        )
        .await?;
        let cached_account = tokio::fs::read(&self.account_path)
            .await
            .ok()
            .and_then(|encoded| {
                serde_json::from_slice::<CustomAccountCredentials>(&encoded)
                    .ok()
            })
            .filter(|credentials| {
                credentials.format == "zay-openssl-acme-account-v1"
                    && credentials.directory == self.directory_url
                    && general_purpose::URL_SAFE_NO_PAD
                        .decode(&credentials.key_pkcs8)
                        .is_ok_and(|cached| cached == key_pkcs8)
            });
        if let Some(credentials) = cached_account {
            session.set_account_url(credentials.id);
        } else {
            let id = session.lookup_existing_account().await?;
            let credentials = CustomAccountCredentials {
                format: "zay-openssl-acme-account-v1".into(),
                id,
                directory: self.directory_url.clone(),
                key_pkcs8: general_purpose::URL_SAFE_NO_PAD.encode(&key_pkcs8),
            };
            write_file_atomic(
                &self.account_path,
                &serde_json::to_vec_pretty(&credentials)?,
            )
            .await?;
        }

        let identifiers = self
            .domains
            .iter()
            .map(|domain| match domain.parse::<IpAddr>() {
                Ok(address) => serde_json::json!({
                    "type": "ip",
                    "value": address.to_string(),
                }),
                Err(_) => serde_json::json!({
                    "type": "dns",
                    "value": domain,
                }),
            })
            .collect::<Vec<_>>();
        let profile = if !self.profile.is_empty() {
            Some(self.profile.as_str())
        } else if self.directory_url == LetsEncrypt::Production.url()
            && self
                .domains
                .iter()
                .any(|domain| domain.parse::<IpAddr>().is_ok())
        {
            Some("shortlived")
        } else {
            None
        };
        let mut request = serde_json::json!({"identifiers": identifiers});
        if let Some(profile) = profile {
            request["profile"] = serde_json::Value::String(profile.into());
        }
        let new_order_url = session.new_order_url().to_owned();
        let response = session
            .post(&new_order_url, Some(&request))
            .await?
            .ensure_success("create ACME order")?;
        let order_url = response.location()?;
        let mut order = response.json()?;

        let mut dns_records: Vec<ProvisionedRecord> = Vec::new();
        let challenge_result: Result<(), BoxError> = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                Err("ACME issuance cancelled".into())
            }
            result = async {
                let authorizations = json_string_array(
                    &order,
                    "authorizations",
                )?;
                for authorization_url in authorizations {
                    let response = session
                        .post(&authorization_url, None)
                        .await?
                        .ensure_success("fetch ACME authorization")?;
                    let authorization = response.json()?;
                    if json_string(&authorization, "status")? == "valid" {
                        continue;
                    }
                    let identifier = authorization
                        .get("identifier")
                        .ok_or("ACME authorization is missing identifier")?;
                    let mut domain = json_string(identifier, "value")?.to_owned();
                    if authorization
                        .get("wildcard")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                    {
                        domain = format!("*.{domain}");
                    }
                    let challenge_type = if self.dns01.is_some() {
                        "dns-01"
                    } else if self.use_tls_alpn {
                        "tls-alpn-01"
                    } else {
                        "http-01"
                    };
                    let challenge = authorization
                        .get("challenges")
                        .and_then(serde_json::Value::as_array)
                        .and_then(|challenges| {
                            challenges.iter().find(|challenge| {
                                challenge.get("type").and_then(
                                    serde_json::Value::as_str,
                                ) == Some(challenge_type)
                            })
                        })
                        .ok_or_else(|| {
                            format!(
                                "ACME server did not offer {challenge_type}"
                            )
                        })?;
                    let token = json_string(challenge, "token")?;
                    let challenge_url = json_string(challenge, "url")?.to_owned();
                    let key_authorization =
                        format!("{token}.{}", session.thumbprint());
                    if let Some(solver) = &self.dns01 {
                        let name = solver.record_name(&domain);
                        let value = general_purpose::URL_SAFE_NO_PAD.encode(
                            Sha256::digest(key_authorization.as_bytes()),
                        );
                        let record = solver.present(&name, &value).await?;
                        dns_records.push(record);
                        solver.wait(&name, &value).await?;
                    } else if self.use_tls_alpn {
                        let digest = Sha256::digest(key_authorization.as_bytes());
                        let certified = generate_tls_alpn_certificate(
                            &domain,
                            digest.as_ref(),
                        )?;
                        self.resolver.set_acme_tls_alpn(domain, certified);
                    } else {
                        self.http01
                            .write()
                            .expect("ACME HTTP-01 lock poisoned")
                            .insert(token.to_owned(), key_authorization);
                    }
                    session
                        .post(&challenge_url, Some(&serde_json::json!({})))
                        .await?
                        .ensure_success("mark ACME challenge ready")?;
                }
                order = poll_custom_order(
                    &mut session,
                    &order_url,
                    false,
                    cancellation,
                )
                .await?;
                Ok(())
            }
            => result,
        };
        self.http01
            .write()
            .expect("ACME HTTP-01 lock poisoned")
            .clear();
        self.resolver.clear_acme_tls_alpn();
        if let Some(solver) = &self.dns01 {
            for record in dns_records.drain(..).rev() {
                if let Err(error) = solver.cleanup(record).await {
                    tracing::warn!(%error, "clean up ACME DNS-01 record");
                }
            }
        }
        challenge_result?;

        let finalize_url = json_string(&order, "finalize")?.to_owned();
        let key = generate_certificate_key(self.key_type)?;
        let params = CertificateParams::new(self.domains.clone())?;
        let csr = params.serialize_request(&key)?;
        session
            .post(
                &finalize_url,
                Some(&serde_json::json!({
                    "csr": general_purpose::URL_SAFE_NO_PAD.encode(csr.der()),
                })),
            )
            .await?
            .ensure_success("finalize ACME order")?;
        let order =
            poll_custom_order(&mut session, &order_url, true, cancellation)
                .await?;
        let certificate_url = json_string(&order, "certificate")?.to_owned();
        let certificate = session
            .post(&certificate_url, None)
            .await?
            .ensure_success("download ACME certificate")?
            .body;
        let private_key = key.serialize_pem();
        let certified =
            certified_key_from_pem(&certificate, private_key.as_bytes())
                .map_err(io::Error::other)?;
        write_file_atomic(&self.private_key_path, private_key.as_bytes())
            .await?;
        write_file_atomic(&self.certificate_path, &certificate).await?;
        self.resolver.set(certified);
        Ok(())
    }
}

async fn poll_custom_order(
    session: &mut AcmeSession,
    order_url: &str,
    require_certificate: bool,
    cancellation: &CancellationToken,
) -> Result<serde_json::Value, BoxError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let response = session
            .post(order_url, None)
            .await?
            .ensure_success("poll ACME order")?;
        let delay = response.retry_delay();
        let order = response.json()?;
        match json_string(&order, "status")? {
            "valid"
                if !require_certificate
                    || order.get("certificate").is_some() =>
            {
                return Ok(order);
            }
            "ready" if !require_certificate => return Ok(order),
            "invalid" => return Err("ACME order became invalid".into()),
            "pending" | "processing" | "ready" => {}
            status => {
                return Err(
                    format!("unknown ACME order status: {status}").into()
                );
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("timed out polling ACME order".into());
        }
        tokio::select! {
            _ = cancellation.cancelled() => {
                return Err("ACME issuance cancelled".into());
            }
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

fn json_string<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, BoxError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("ACME response is missing {field}").into())
}

fn json_string_array(
    value: &serde_json::Value,
    field: &str,
) -> Result<Vec<String>, BoxError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| -> BoxError {
            format!("ACME response is missing {field}").into()
        })?
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| -> BoxError {
                format!("ACME {field} must contain URLs").into()
            })
        })
        .collect()
}

async fn run_renewal_loop(
    core: Arc<AdvancedAcmeCore>,
    cancellation: CancellationToken,
) {
    let mut retry = RETRY_MIN;
    loop {
        let delay = match cached_certificate_is_fresh(&core.certificate_path)
            .await
        {
            true => CHECK_INTERVAL,
            false => match core.issue_and_store(&cancellation).await {
                Ok(()) => {
                    retry = RETRY_MIN;
                    CHECK_INTERVAL
                }
                Err(error) => {
                    tracing::error!(%error, "advanced ACME provider failed");
                    let delay = retry;
                    retry = retry.saturating_mul(2).min(RETRY_MAX);
                    delay
                }
            },
        };
        tokio::select! {
            _ = cancellation.cancelled() => break,
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

async fn cached_certificate_is_fresh(path: &Path) -> bool {
    let Ok(encoded) = tokio::fs::read(path).await else {
        return false;
    };
    certificate_valid_for(&encoded, RENEW_BEFORE)
}

fn certificate_valid_for(encoded: &[u8], minimum: Duration) -> bool {
    let Ok(block) = pem::parse(encoded) else {
        return false;
    };
    let Ok((_, certificate)) =
        x509_parser::parse_x509_certificate(block.contents())
    else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    certificate.validity().not_after.timestamp() - now
        > minimum.as_secs() as i64
}

fn generate_certificate_key(
    key_type: AcmeKeyType,
) -> Result<KeyPair, rcgen::Error> {
    match key_type {
        AcmeKeyType::Default | AcmeKeyType::P256 => {
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        }
        AcmeKeyType::Ed25519 => KeyPair::generate_for(&PKCS_ED25519),
        AcmeKeyType::P384 => KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384),
        AcmeKeyType::Rsa2048 => {
            KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
        }
        AcmeKeyType::Rsa4096 => {
            KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_4096)
        }
    }
}

fn generate_tls_alpn_certificate(
    domain: &str,
    key_authorization_digest: &[u8],
) -> Result<Arc<rustls::sign::CertifiedKey>, BoxError> {
    let mut params = CertificateParams::new(vec![domain.to_owned()])?;
    params.custom_extensions = vec![CustomExtension::new_acme_identifier(
        key_authorization_digest,
    )];
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let certificate = params.self_signed(&key)?;
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let signing_key =
        rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key)?;
    Ok(Arc::new(rustls::sign::CertifiedKey::new(
        vec![certificate.der().clone()],
        signing_key,
    )))
}

fn parse_external_account(
    options: &AcmeExternalAccountOptions,
) -> Result<ExternalAccountKey, BoxError> {
    if options.key_id.is_empty() || options.mac_key.is_empty() {
        return Err("external_account requires key_id and mac_key".into());
    }
    let mac = decode_eab_mac(&options.mac_key)?;
    Ok(ExternalAccountKey::new(options.key_id.clone(), &mac))
}

fn decode_eab_mac(value: &str) -> Result<Vec<u8>, BoxError> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| general_purpose::URL_SAFE.decode(value))
        .or_else(|_| general_purpose::STANDARD.decode(value))
        .map_err(Into::into)
}

fn validate_options(
    options: &AcmeCertificateProviderOptions,
) -> Result<(), CertificateProviderError> {
    if options.domain.as_slice().is_empty() {
        return Err(CertificateProviderError::InvalidAcme(
            "missing domain".into(),
        ));
    }
    match options.provider.as_str() {
        "" | "letsencrypt" | "zerossl" => {}
        provider if provider.starts_with("https://") => {}
        provider => {
            return Err(CertificateProviderError::InvalidAcme(format!(
                "unsupported ACME provider: {provider}"
            )));
        }
    }
    if options.disable_http_challenge
        && options.disable_tls_alpn_challenge
        && options.dns01_challenge.is_none()
    {
        return Err(CertificateProviderError::InvalidAcme(
            "HTTP-01 and TLS-ALPN-01 challenges cannot both be disabled".into(),
        ));
    }
    if let Some(external_account) = &options.external_account
        && (external_account.key_id.is_empty()
            || external_account.mac_key.is_empty())
    {
        return Err(CertificateProviderError::InvalidAcme(
            "external_account requires key_id and mac_key".into(),
        ));
    }
    if options.provider == "zerossl"
        && options.external_account.is_none()
        && options.account_key.trim().is_empty()
        && options.email.trim().is_empty()
    {
        return Err(CertificateProviderError::InvalidAcme(
            "email is required to use the ZeroSSL ACME endpoint without external_account or account_key"
                .into(),
        ));
    }
    Ok(())
}

async fn write_file_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::other("invalid ACME cache path"))?;
    let temporary = path
        .with_file_name(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    tokio::fs::write(&temporary, bytes).await?;
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

async fn run_http01_listener(
    listener: tokio::net::TcpListener,
    values: Arc<RwLock<HashMap<String, String>>>,
    cancellation: CancellationToken,
) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _)) = accepted else {
            break;
        };
        let values = values.clone();
        connections.spawn(async move {
            let service = hyper::service::service_fn(move |request| {
                let values = values.clone();
                async move {
                    let value = request
                        .uri()
                        .path()
                        .strip_prefix("/.well-known/acme-challenge/")
                        .filter(|_| request.method() == http::Method::GET)
                        .and_then(|token| {
                            values
                                .read()
                                .expect("ACME HTTP-01 lock poisoned")
                                .get(token)
                                .cloned()
                        });
                    let response = match value {
                        Some(value) => hyper::Response::new(
                            http_body_util::Full::new(Bytes::from(value)),
                        ),
                        None => hyper::Response::builder()
                            .status(http::StatusCode::NOT_FOUND)
                            .body(http_body_util::Full::new(Bytes::new()))
                            .expect("valid ACME HTTP-01 response"),
                    };
                    Ok::<_, std::convert::Infallible>(response)
                }
            });
            if let Err(error) = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(%error, "ACME HTTP-01 connection failed");
            }
        });
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

fn tls_alpn_server_config(
    resolver: Arc<DynamicCertificateResolver>,
) -> Result<Arc<rustls::ServerConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    Ok(Arc::new(config))
}

async fn run_tls_alpn_listener(
    listener: tokio::net::TcpListener,
    config: Arc<rustls::ServerConfig>,
    cancellation: CancellationToken,
) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _)) = accepted else {
            break;
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
        connections.spawn(async move {
            if let Err(error) = acceptor.accept(stream).await {
                tracing::debug!(
                    %error,
                    "ACME TLS-ALPN-01 connection failed"
                );
            }
        });
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, sync::Arc};

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use http_body_util::{BodyExt as _, Full};
    use hyper::{Request, Response, body::Incoming, service::service_fn};
    use hyper_util::rt::TokioIo;
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        pkey::{PKey, Private},
        rsa::Rsa,
        x509::{X509, X509NameBuilder, X509Req},
    };
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    use super::{
        AcmeAccountSigner, AdvancedAcmeCore, decode_eab_mac,
        generate_certificate_key, generate_tls_alpn_certificate,
        run_tls_alpn_listener, tls_alpn_server_config,
    };
    use crate::{
        common::tls::DynamicCertificateResolver,
        option::{
            AcmeExternalAccountOptions, AcmeKeyType, DirectOutboundOptions,
            HttpClientOptions,
        },
        protocol::direct::DirectOutbound,
    };

    #[test]
    fn accepts_url_safe_eab_keys_and_all_certificate_key_types() {
        assert_eq!(decode_eab_mac("AQIDBA").unwrap(), [1, 2, 3, 4]);
        for key_type in [
            AcmeKeyType::Ed25519,
            AcmeKeyType::P256,
            AcmeKeyType::P384,
            AcmeKeyType::Rsa2048,
            AcmeKeyType::Rsa4096,
        ] {
            generate_certificate_key(key_type).unwrap();
        }
    }

    #[test]
    fn tls_alpn_certificate_contains_critical_acme_identifier() {
        let digest = [0x42; 32];
        let certified =
            generate_tls_alpn_certificate("example.com", &digest).unwrap();
        let (_, certificate) =
            x509_parser::parse_x509_certificate(certified.cert[0].as_ref())
                .unwrap();
        let extension = certificate
            .extensions()
            .iter()
            .find(|extension| {
                extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31"
            })
            .expect("acmeIdentifier extension");
        assert!(extension.critical);
        assert_eq!(
            extension.value,
            [&[0x04, 0x20], digest.as_slice()].concat()
        );
    }

    #[tokio::test]
    async fn alternative_tls_alpn_listener_releases_its_port() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let listeners = super::super::bind_http01_listeners(port).unwrap();
        let resolver = std::sync::Arc::new(
            crate::common::tls::DynamicCertificateResolver::new(),
        );
        let config = tls_alpn_server_config(resolver).unwrap();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(run_tls_alpn_listener(
            listeners.into_iter().next().unwrap(),
            config,
            task_cancellation,
        ));
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        drop(stream);
        cancellation.cancel();
        task.await.unwrap();
        std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    }

    #[tokio::test]
    async fn advanced_http01_completes_a_mock_acme_issuance() {
        let account_key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        run_mock_acme_issuance(account_key.serialize_pem(), "ES256").await;
    }

    #[tokio::test]
    async fn non_p256_account_key_completes_a_mock_acme_issuance() {
        let account_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let account_key =
            String::from_utf8(account_key.private_key_to_pem_pkcs8().unwrap())
                .unwrap();
        run_mock_acme_issuance(account_key, "RS256").await;
    }

    async fn run_mock_acme_issuance(
        account_key_pem: String,
        expected_account_algorithm: &'static str,
    ) {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{address}");
        let http01 =
            Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let state = Arc::new(std::sync::Mutex::new(MockAcmeState::new(
            expected_account_algorithm,
        )));
        let shutdown = tokio_util::sync::CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let server_base = base_url.clone();
        let server_state = state.clone();
        let server_http01 = http01.clone();
        let server = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = server_shutdown.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, _)) = accepted else {
                    break;
                };
                let base_url = server_base.clone();
                let state = server_state.clone();
                let http01 = server_http01.clone();
                tokio::spawn(async move {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(move |request| {
                                mock_acme_request(
                                    request,
                                    base_url.clone(),
                                    state.clone(),
                                    http01.clone(),
                                )
                            }),
                        )
                        .await
                        .unwrap();
                });
            }
        });

        let cache_directory = std::env::temp_dir()
            .join(format!("zay-singbox-acme-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&cache_directory).await.unwrap();
        let resolver = Arc::new(DynamicCertificateResolver::new());
        let account_key = AcmeAccountSigner::from_pem(&account_key_pem)
            .unwrap()
            .pkcs8()
            .to_vec();
        let core = AdvancedAcmeCore {
            resolver: resolver.clone(),
            http: direct_http_client(),
            directory_url: format!("{base_url}/directory"),
            email: "test@example.com".into(),
            account_key: Some(account_key),
            external_account: Some(AcmeExternalAccountOptions {
                key_id: "unused-for-existing-account".into(),
                mac_key: "AQIDBA".into(),
            }),
            domains: vec!["service.example.com".into()],
            key_type: AcmeKeyType::Ed25519,
            profile: "shortlived".into(),
            account_path: cache_directory.join("account.json"),
            certificate_path: cache_directory.join("certificate.pem"),
            private_key_path: cache_directory.join("private-key.pem"),
            lock_path: cache_directory.join("certificate.lock"),
            http01,
            dns01: None,
            use_tls_alpn: false,
        };
        core.issue_and_store(&tokio_util::sync::CancellationToken::new())
            .await
            .unwrap();
        assert!(resolver.has_certificate());
        assert!(tokio::fs::try_exists(&core.account_path).await.unwrap());
        assert!(tokio::fs::try_exists(&core.certificate_path).await.unwrap());
        assert!(tokio::fs::try_exists(&core.private_key_path).await.unwrap());
        {
            let state = state.lock().unwrap();
            assert!(state.challenge_observed);
            assert!(state.certificate.is_some());
            assert_eq!(state.account_requests, 1);
        }
        assert!(core.http01.read().unwrap().is_empty());

        tokio::fs::remove_file(&core.certificate_path)
            .await
            .unwrap();
        tokio::fs::remove_file(&core.private_key_path)
            .await
            .unwrap();
        {
            let mut state = state.lock().unwrap();
            state.certificate = None;
            state.challenge_observed = false;
        }
        core.issue_and_store(&tokio_util::sync::CancellationToken::new())
            .await
            .unwrap();
        {
            let state = state.lock().unwrap();
            assert!(state.challenge_observed);
            assert!(state.certificate.is_some());
            assert_eq!(state.account_requests, 1);
        }

        shutdown.cancel();
        server.await.unwrap();
        tokio::fs::remove_dir_all(cache_directory).await.unwrap();
    }

    struct MockAcmeState {
        ca_key: PKey<Private>,
        ca_certificate: X509,
        certificate: Option<String>,
        challenge_observed: bool,
        expected_account_algorithm: &'static str,
        account_requests: usize,
    }

    impl MockAcmeState {
        fn new(expected_account_algorithm: &'static str) -> Self {
            let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
            let mut name = X509NameBuilder::new().unwrap();
            name.append_entry_by_text("CN", "singbox mock ACME CA")
                .unwrap();
            let name = name.build();
            let mut builder = X509::builder().unwrap();
            builder.set_version(2).unwrap();
            let serial = certificate_serial();
            builder.set_serial_number(&serial).unwrap();
            builder.set_subject_name(&name).unwrap();
            builder.set_issuer_name(&name).unwrap();
            builder.set_pubkey(&ca_key).unwrap();
            builder
                .set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            builder
                .set_not_after(&Asn1Time::days_from_now(365).unwrap())
                .unwrap();
            builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
            let ca_certificate = builder.build();
            Self {
                ca_key,
                ca_certificate,
                certificate: None,
                challenge_observed: false,
                expected_account_algorithm,
                account_requests: 0,
            }
        }
    }

    async fn mock_acme_request(
        request: Request<Incoming>,
        base_url: String,
        state: Arc<std::sync::Mutex<MockAcmeState>>,
        http01: Arc<
            std::sync::RwLock<std::collections::HashMap<String, String>>,
        >,
    ) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let body = request.into_body().collect().await.unwrap().to_bytes();
        let payload = if method == http::Method::POST {
            let envelope: serde_json::Value =
                serde_json::from_slice(&body).unwrap();
            let protected = serde_json::from_slice::<serde_json::Value>(
                &URL_SAFE_NO_PAD
                    .decode(envelope["protected"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
            if path == "/account" {
                assert_eq!(
                    protected["alg"],
                    state.lock().unwrap().expected_account_algorithm
                );
            }
            let encoded = envelope["payload"].as_str().unwrap();
            if encoded.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_slice(
                    &URL_SAFE_NO_PAD.decode(encoded).unwrap(),
                )
                .unwrap()
            }
        } else {
            serde_json::Value::Null
        };
        let mut status = http::StatusCode::OK;
        let mut location = None;
        let response = match (method, path.as_str()) {
            (http::Method::GET, "/directory") => serde_json::json!({
                "newNonce": format!("{base_url}/nonce"),
                "newAccount": format!("{base_url}/account"),
                "newOrder": format!("{base_url}/order"),
                "meta": {"profiles": {"shortlived": "test profile"}}
            })
            .to_string(),
            (http::Method::HEAD, "/nonce") => String::new(),
            (http::Method::POST, "/account") => {
                assert_eq!(payload["onlyReturnExisting"], true);
                assert!(payload.get("externalAccountBinding").is_none());
                state.lock().unwrap().account_requests += 1;
                status = http::StatusCode::CREATED;
                location = Some(format!("{base_url}/account/1"));
                "{}".into()
            }
            (http::Method::POST, "/order") => {
                assert_eq!(payload["profile"], "shortlived");
                status = http::StatusCode::CREATED;
                location = Some(format!("{base_url}/order/1"));
                mock_order(&base_url, "pending", false)
            }
            (http::Method::POST, "/authorization/1") => serde_json::json!({
                "identifier": {
                    "type":"dns",
                    "value":"service.example.com"
                },
                "status":"pending",
                "challenges":[{
                    "type":"http-01",
                    "url":format!("{base_url}/challenge/1"),
                    "token":"challenge-token",
                    "status":"pending"
                }]
            })
            .to_string(),
            (http::Method::POST, "/challenge/1") => {
                let values = http01.read().unwrap();
                let value = values.get("challenge-token").unwrap();
                assert!(value.starts_with("challenge-token."));
                drop(values);
                state.lock().unwrap().challenge_observed = true;
                serde_json::json!({
                    "type":"http-01",
                    "url":format!("{base_url}/challenge/1"),
                    "token":"challenge-token",
                    "status":"processing"
                })
                .to_string()
            }
            (http::Method::POST, "/order/1") => {
                let finalized = state.lock().unwrap().certificate.is_some();
                mock_order(
                    &base_url,
                    if finalized { "valid" } else { "ready" },
                    finalized,
                )
            }
            (http::Method::POST, "/finalize/1") => {
                let csr = URL_SAFE_NO_PAD
                    .decode(payload["csr"].as_str().unwrap())
                    .unwrap();
                let csr = X509Req::from_der(&csr).unwrap();
                let mut state = state.lock().unwrap();
                let mut builder = X509::builder().unwrap();
                builder.set_version(2).unwrap();
                let serial = certificate_serial();
                builder.set_serial_number(&serial).unwrap();
                builder.set_subject_name(csr.subject_name()).unwrap();
                builder
                    .set_issuer_name(state.ca_certificate.subject_name())
                    .unwrap();
                builder.set_pubkey(&csr.public_key().unwrap()).unwrap();
                builder
                    .set_not_before(&Asn1Time::days_from_now(0).unwrap())
                    .unwrap();
                builder
                    .set_not_after(&Asn1Time::days_from_now(90).unwrap())
                    .unwrap();
                builder
                    .sign(&state.ca_key, MessageDigest::sha256())
                    .unwrap();
                let certificate = builder.build();
                state.certificate = Some(format!(
                    "{}{}",
                    String::from_utf8(certificate.to_pem().unwrap()).unwrap(),
                    String::from_utf8(state.ca_certificate.to_pem().unwrap())
                        .unwrap()
                ));
                mock_order(&base_url, "processing", true)
            }
            (http::Method::POST, "/certificate/1") => {
                state.lock().unwrap().certificate.clone().unwrap()
            }
            _ => panic!("unexpected mock ACME request {path}"),
        };
        let mut builder = Response::builder()
            .status(status)
            .header("replay-nonce", uuid::Uuid::new_v4().to_string());
        if let Some(location) = location {
            builder = builder.header(http::header::LOCATION, location);
        }
        Ok(builder
            .body(Full::new(bytes::Bytes::from(response)))
            .unwrap())
    }

    fn mock_order(base_url: &str, status: &str, finalized: bool) -> String {
        let mut order = serde_json::json!({
            "status": status,
            "authorizations": [format!("{base_url}/authorization/1")],
            "finalize": format!("{base_url}/finalize/1")
        });
        if finalized {
            order["certificate"] =
                serde_json::Value::String(format!("{base_url}/certificate/1"));
        }
        order.to_string()
    }

    fn direct_http_client() -> super::CertificateHttpClient {
        super::CertificateHttpClient::new(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            HttpClientOptions::default(),
        )
    }

    fn certificate_serial() -> openssl::asn1::Asn1Integer {
        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
        serial.to_asn1_integer().unwrap()
    }
}
