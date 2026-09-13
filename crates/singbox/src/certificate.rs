//! Managed TLS certificate providers.
//!
//! Providers are ordinary lifecycle components.  Their rustls resolver is
//! wired into inbound TLS configurations during runtime construction, while
//! acquisition and renewal are driven only after the runtime starts.

use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use futures_util::StreamExt as _;
use rustls::server::ResolvesServerCert;
use rustls_acme::{
    AccountCache, AcmeConfig, AcmeState, ResolvesServerCertAcme, UseChallenge,
    caches::DirCache,
};
use tokio_util::sync::CancellationToken;

use crate::{
    common::{
        certificate_store::{CertificateStore, CertificateStoreError},
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        ntp::NtpClock,
    },
    constant,
    endpoint::tailscale::TailscaleEndpointHandle,
    option::{
        AcmeCertificateProviderOptions, CertificateProviderOptions,
        CloudflareOriginCaCertificateProviderOptions, HttpClientOptions,
        HttpClientReference, InboundTlsOptions, Options,
        TailscaleCertificateProviderOptions,
    },
    outbound::OutboundManager,
};

mod acme;
mod acme_custom;
mod acme_dns;
mod acme_signer;
mod http_client;
mod origin_ca;
mod tailscale;

use acme::AdvancedAcmeProviderService;
use http_client::CertificateHttpClient;
use origin_ca::OriginCaProviderService;
use tailscale::{EndpointBinding, TailscaleCertificateProviderService};

#[derive(Debug, thiserror::Error)]
pub enum CertificateProviderError {
    #[error(transparent)]
    CertificateStore(#[from] CertificateStoreError),
    #[error("decode certificate provider {tag:?}: {message}")]
    Decode { tag: String, message: String },
    #[error("duplicate certificate provider tag: {0}")]
    Duplicate(String),
    #[error("certificate provider not found: {0}")]
    NotFound(String),
    #[error("unsupported certificate provider type: {0}")]
    UnsupportedType(String),
    #[error("invalid ACME certificate provider: {0}")]
    InvalidAcme(String),
    #[error("invalid Cloudflare Origin CA certificate provider: {0}")]
    InvalidOriginCa(String),
    #[error("invalid Tailscale certificate provider: {0}")]
    InvalidTailscale(String),
    #[error("configure certificate provider HTTP client: {0}")]
    HttpClient(String),
}

struct ManagedProvider {
    resolver: Arc<dyn ResolvesServerCert>,
    lifecycle: Box<dyn Lifecycle>,
    acme_tls_alpn: bool,
}

/// Registry and lifecycle owner for shared and inline certificate providers.
pub struct CertificateProviderManager {
    providers: HashMap<String, ManagedProvider>,
    order: Vec<String>,
    next_inline_id: usize,
    base_path: PathBuf,
    http_outbounds: Option<Arc<OutboundManager>>,
    http_clients: Vec<crate::option::HttpClient>,
    default_http_client: String,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
    tailscale_bindings: Vec<(String, EndpointBinding)>,
}

impl CertificateProviderManager {
    pub fn from_options(
        options: &Options,
        base_path: &Path,
    ) -> Result<Self, CertificateProviderError> {
        let certificate_store = CertificateStore::new(
            &options.certificate.clone().unwrap_or_default(),
            base_path,
        )?;
        Self::from_options_inner(
            options,
            base_path,
            None,
            None,
            Some(certificate_store),
        )
    }

    pub(crate) fn from_runtime_options(
        options: &Options,
        base_path: &Path,
        outbounds: Arc<OutboundManager>,
        default_http_client: &str,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<CertificateStore>,
    ) -> Result<Self, CertificateProviderError> {
        Self::from_options_inner(
            options,
            base_path,
            Some((outbounds, default_http_client)),
            ntp_clock,
            certificate_store,
        )
    }

    fn from_options_inner(
        options: &Options,
        base_path: &Path,
        http_environment: Option<(Arc<OutboundManager>, &str)>,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<CertificateStore>,
    ) -> Result<Self, CertificateProviderError> {
        let mut manager = Self {
            providers: HashMap::new(),
            order: Vec::new(),
            next_inline_id: 0,
            base_path: base_path.to_owned(),
            http_outbounds: http_environment
                .as_ref()
                .map(|(outbounds, _)| outbounds.clone()),
            http_clients: options.http_clients.clone(),
            default_http_client: http_environment
                .as_ref()
                .map(|(_, default)| (*default).to_owned())
                .unwrap_or_default(),
            ntp_clock,
            certificate_store,
            tailscale_bindings: Vec::new(),
        };
        for (index, provider) in
            options.certificate_providers.iter().enumerate()
        {
            let tag = if provider.tag.is_empty() {
                index.to_string()
            } else {
                provider.tag.clone()
            };
            match provider.kind.as_str() {
                constant::TYPE_ACME => {
                    let options = provider.decode().map_err(|error| {
                        CertificateProviderError::Decode {
                            tag: tag.clone(),
                            message: error.to_string(),
                        }
                    })?;
                    let http = if uses_advanced_acme(&options) {
                        Some(manager.resolve_http_client(
                            options.http_client.as_ref(),
                        )?)
                    } else {
                        None
                    };
                    manager.register_acme(tag, options, http)?;
                }
                constant::TYPE_CLOUDFLARE_ORIGIN_CA => {
                    let provider_options: CloudflareOriginCaCertificateProviderOptions =
                        provider.decode().map_err(|error| {
                            CertificateProviderError::Decode {
                                tag: tag.clone(),
                                message: error.to_string(),
                            }
                        })?;
                    let http = manager.resolve_http_client(
                        provider_options.http_client.as_ref(),
                    )?;
                    manager.register_origin_ca(tag, provider_options, http)?;
                }
                constant::TYPE_TAILSCALE => {
                    let provider_options: TailscaleCertificateProviderOptions =
                        provider.decode().map_err(|error| {
                            CertificateProviderError::Decode {
                                tag: tag.clone(),
                                message: error.to_string(),
                            }
                        })?;
                    let http = manager.resolve_tailscale_http_client()?;
                    manager.register_tailscale(tag, provider_options, http)?;
                }
                kind => {
                    return Err(CertificateProviderError::UnsupportedType(
                        kind.to_owned(),
                    ));
                }
            }
        }
        Ok(manager)
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Resolve and attach the provider configured by one inbound TLS block.
    pub(crate) fn configure_tls(
        &mut self,
        tls: Option<&mut InboundTlsOptions>,
        owner: &str,
    ) -> Result<(), CertificateProviderError> {
        let Some(tls) = tls else {
            return Ok(());
        };
        tls.ntp_clock = self.ntp_clock.clone();
        if tls.certificate_provider.is_some() && tls.acme.is_some() {
            return Err(CertificateProviderError::InvalidAcme(
                "certificate_provider and acme are mutually exclusive".into(),
            ));
        }
        let provider = match tls.certificate_provider.clone() {
            Some(CertificateProviderOptions::Reference(tag)) => {
                let provider = self.providers.get(&tag).ok_or_else(|| {
                    CertificateProviderError::NotFound(tag.clone())
                })?;
                Some((provider.resolver.clone(), provider.acme_tls_alpn))
            }
            Some(CertificateProviderOptions::Inline(mut fields)) => {
                let kind = fields
                    .remove("type")
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .ok_or_else(|| CertificateProviderError::Decode {
                        tag: owner.to_owned(),
                        message: "missing certificate provider type".into(),
                    })?;
                let tag = format!("__inline/{owner}/{}", self.next_inline_id);
                self.next_inline_id += 1;
                match kind.as_str() {
                    constant::TYPE_ACME => {
                        let options = serde_json::from_value(
                            serde_json::Value::Object(fields),
                        )
                        .map_err(|error| CertificateProviderError::Decode {
                            tag: owner.to_owned(),
                            message: error.to_string(),
                        })?;
                        let http = if uses_advanced_acme(&options) {
                            Some(self.resolve_http_client(
                                options.http_client.as_ref(),
                            )?)
                        } else {
                            None
                        };
                        self.register_acme(tag.clone(), options, http)?;
                    }
                    constant::TYPE_CLOUDFLARE_ORIGIN_CA => {
                        let options: CloudflareOriginCaCertificateProviderOptions =
                            serde_json::from_value(
                                serde_json::Value::Object(fields),
                            )
                            .map_err(|error| {
                                CertificateProviderError::Decode {
                                    tag: owner.to_owned(),
                                    message: error.to_string(),
                                }
                            })?;
                        let http = self.resolve_http_client(
                            options.http_client.as_ref(),
                        )?;
                        self.register_origin_ca(tag.clone(), options, http)?;
                    }
                    constant::TYPE_TAILSCALE => {
                        let options: TailscaleCertificateProviderOptions =
                            serde_json::from_value(serde_json::Value::Object(
                                fields,
                            ))
                            .map_err(|error| {
                                CertificateProviderError::Decode {
                                    tag: owner.to_owned(),
                                    message: error.to_string(),
                                }
                            })?;
                        let http = self.resolve_http_client(None)?;
                        self.register_tailscale(tag.clone(), options, http)?;
                    }
                    kind => {
                        return Err(CertificateProviderError::UnsupportedType(
                            kind.to_owned(),
                        ));
                    }
                }
                let provider = self
                    .providers
                    .get(&tag)
                    .expect("inline provider was just registered");
                Some((provider.resolver.clone(), provider.acme_tls_alpn))
            }
            None => {
                let Some(acme) = tls.acme.clone() else {
                    return Ok(());
                };
                let tag =
                    format!("__legacy-acme/{owner}/{}", self.next_inline_id);
                self.next_inline_id += 1;
                let http = if uses_advanced_acme(&acme) {
                    Some(self.resolve_http_client(acme.http_client.as_ref())?)
                } else {
                    None
                };
                self.register_acme(tag.clone(), acme, http)?;
                let provider = self
                    .providers
                    .get(&tag)
                    .expect("legacy ACME provider was just registered");
                Some((provider.resolver.clone(), provider.acme_tls_alpn))
            }
        };
        if let Some((resolver, acme_tls_alpn)) = provider {
            tls.certificate_resolver.0 = Some(resolver);
            tls.certificate_resolver.1 = acme_tls_alpn;
        }
        Ok(())
    }

    fn register_acme(
        &mut self,
        tag: String,
        options: AcmeCertificateProviderOptions,
        http: Option<CertificateHttpClient>,
    ) -> Result<(), CertificateProviderError> {
        if self.providers.contains_key(&tag) {
            return Err(CertificateProviderError::Duplicate(tag));
        }
        let (lifecycle, resolver, acme_tls_alpn): (
            Box<dyn Lifecycle>,
            Arc<dyn ResolvesServerCert>,
            bool,
        ) = if let Some(http) = http {
            let (service, resolver, acme_tls_alpn) =
                AdvancedAcmeProviderService::new(
                    &tag,
                    options,
                    &self.base_path,
                    http,
                )?;
            (Box::new(service), resolver, acme_tls_alpn)
        } else {
            let (service, resolver, acme_tls_alpn) =
                AcmeProviderService::new(&tag, options, &self.base_path)?;
            (Box::new(service), resolver, acme_tls_alpn)
        };
        self.order.push(tag.clone());
        self.providers.insert(
            tag,
            ManagedProvider {
                resolver,
                lifecycle,
                acme_tls_alpn,
            },
        );
        Ok(())
    }

    fn register_origin_ca(
        &mut self,
        tag: String,
        options: CloudflareOriginCaCertificateProviderOptions,
        http: CertificateHttpClient,
    ) -> Result<(), CertificateProviderError> {
        if self.providers.contains_key(&tag) {
            return Err(CertificateProviderError::Duplicate(tag));
        }
        let (service, resolver) =
            OriginCaProviderService::new(&tag, options, &self.base_path, http)?;
        self.order.push(tag.clone());
        self.providers.insert(
            tag,
            ManagedProvider {
                resolver,
                lifecycle: Box::new(service),
                acme_tls_alpn: false,
            },
        );
        Ok(())
    }

    fn register_tailscale(
        &mut self,
        tag: String,
        options: TailscaleCertificateProviderOptions,
        http: CertificateHttpClient,
    ) -> Result<(), CertificateProviderError> {
        if self.providers.contains_key(&tag) {
            return Err(CertificateProviderError::Duplicate(tag));
        }
        let endpoint_tag = options.endpoint.clone();
        let (service, resolver, binding) =
            TailscaleCertificateProviderService::new(
                &tag,
                options.endpoint,
                http,
                self.ntp_clock.clone(),
            )?;
        self.tailscale_bindings.push((endpoint_tag, binding));
        self.order.push(tag.clone());
        self.providers.insert(
            tag,
            ManagedProvider {
                resolver,
                lifecycle: Box::new(service),
                acme_tls_alpn: false,
            },
        );
        Ok(())
    }

    pub(crate) fn bind_tailscale_endpoints(
        &mut self,
        endpoints: &HashMap<String, TailscaleEndpointHandle>,
    ) -> Result<(), CertificateProviderError> {
        for (tag, binding) in &self.tailscale_bindings {
            let endpoint = endpoints.get(tag).ok_or_else(|| {
                CertificateProviderError::InvalidTailscale(format!(
                    "endpoint not found: {tag}"
                ))
            })?;
            *binding
                .write()
                .expect("Tailscale certificate endpoint lock poisoned") =
                Some(endpoint.certificate_endpoint());
        }
        Ok(())
    }

    fn resolve_http_client(
        &self,
        reference: Option<&HttpClientReference>,
    ) -> Result<CertificateHttpClient, CertificateProviderError> {
        let outbounds = self.http_outbounds.as_ref().ok_or_else(|| {
            CertificateProviderError::HttpClient(
                "certificate provider requires a runtime outbound manager"
                    .into(),
            )
        })?;
        let clients: HashMap<_, _> = self
            .http_clients
            .iter()
            .map(|client| (client.tag.as_str(), &client.options))
            .collect();
        let default_tag = if self.default_http_client.is_empty() {
            self.http_clients
                .first()
                .map(|client| client.tag.as_str())
                .unwrap_or("")
        } else {
            &self.default_http_client
        };
        let explicit = reference.filter(|reference| match reference {
            HttpClientReference::Tag(tag) => !tag.is_empty(),
            HttpClientReference::Inline(options) => !options.is_empty(),
        });
        let (mut client, default_outbound) = match explicit {
            Some(HttpClientReference::Tag(tag)) => (
                clients.get(tag.as_str()).copied().cloned().ok_or_else(
                    || {
                        CertificateProviderError::HttpClient(format!(
                            "http_client not found: {tag}"
                        ))
                    },
                )?,
                false,
            ),
            Some(HttpClientReference::Inline(client)) => {
                (client.as_ref().clone(), false)
            }
            None if !default_tag.is_empty() => (
                clients.get(default_tag).copied().cloned().ok_or_else(
                    || {
                        CertificateProviderError::HttpClient(format!(
                            "default http_client not found: {default_tag}"
                        ))
                    },
                )?,
                false,
            ),
            None => (HttpClientOptions::default(), true),
        };
        client
            .tls
            .get_or_insert_with(Default::default)
            .set_runtime_context(
                self.ntp_clock.clone(),
                self.certificate_store.clone(),
            );
        let dialer = outbounds
            .http_client_dialer(&client.dialer, default_outbound)
            .map_err(|error| {
                CertificateProviderError::HttpClient(error.to_string())
            })?;
        Ok(CertificateHttpClient::new_with_clock(
            dialer,
            client,
            self.ntp_clock.clone(),
        ))
    }

    /// The upstream Tailscale certificate provider creates a standalone
    /// `dialer.NewWithOptions` with empty dialer options. It deliberately does
    /// not inherit the configured default HTTP client: local-tailscaled owns
    /// its own socket path while any remote request uses the ordinary direct
    /// DNS-router path.
    fn resolve_tailscale_http_client(
        &self,
    ) -> Result<CertificateHttpClient, CertificateProviderError> {
        let outbounds = self.http_outbounds.as_ref().ok_or_else(|| {
            CertificateProviderError::HttpClient(
                "Tailscale certificate provider requires a runtime outbound manager"
                    .into(),
            )
        })?;
        let mut client = HttpClientOptions::default();
        client
            .tls
            .get_or_insert_with(Default::default)
            .set_runtime_context(
                self.ntp_clock.clone(),
                self.certificate_store.clone(),
            );
        let dialer = outbounds
            .http_client_dialer(&client.dialer, false)
            .map_err(|error| {
                CertificateProviderError::HttpClient(error.to_string())
            })?;
        Ok(CertificateHttpClient::new_with_clock(
            dialer,
            client,
            self.ntp_clock.clone(),
        ))
    }
}

fn uses_advanced_acme(options: &AcmeCertificateProviderOptions) -> bool {
    options.provider == "zerossl"
        || options.external_account.is_some()
        || options.dns01_challenge.is_some()
        || options.alternative_tls_port != 0
        || (!options.account_key.trim().is_empty()
            && acme_signer::AcmeAccountSigner::from_pem(&options.account_key)
                .is_ok_and(|key| !key.is_p256()))
        || !matches!(
            options.key_type,
            crate::option::AcmeKeyType::Default
                | crate::option::AcmeKeyType::P256
        )
        || !options.profile.is_empty()
        || options.http_client.is_some()
}

impl Lifecycle for CertificateProviderManager {
    fn name(&self) -> &str {
        "certificate-provider-manager"
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            for tag in &self.order {
                self.providers
                    .get_mut(tag)
                    .expect("registered provider disappeared")
                    .lifecycle
                    .start(stage)
                    .await?;
            }
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            let mut errors = Vec::new();
            for tag in self.order.iter().rev() {
                if let Err(error) = self
                    .providers
                    .get_mut(tag)
                    .expect("registered provider disappeared")
                    .lifecycle
                    .close()
                    .await
                {
                    errors.push(error.to_string());
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(LifecycleError::Close {
                    component: self.name().into(),
                    message: errors.join("; "),
                })
            }
        })
    }
}

type RustlsAcmeState = AcmeState<io::Error, io::Error>;

struct FixedAccountCache {
    key: Vec<u8>,
}

#[async_trait]
impl AccountCache for FixedAccountCache {
    type EA = io::Error;

    async fn load_account(
        &self,
        _contact: &[String],
        _directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        Ok(Some(self.key.clone()))
    }

    async fn store_account(
        &self,
        _contact: &[String],
        _directory_url: &str,
        _account: &[u8],
    ) -> Result<(), Self::EA> {
        Ok(())
    }
}

struct AcmeProviderService {
    name: String,
    // AcmeState is Send but intentionally not Sync while it contains
    // in-flight futures. The lifecycle owns it exclusively; the mutex only
    // satisfies the runtime's Sync component contract until Start moves it.
    state: Mutex<Option<RustlsAcmeState>>,
    task: Option<tokio::task::JoinHandle<()>>,
    http01_resolver: Option<Arc<ResolvesServerCertAcme>>,
    http01_port: u16,
    http01_cancellation: CancellationToken,
    http01_tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl AcmeProviderService {
    fn new(
        tag: &str,
        options: AcmeCertificateProviderOptions,
        base_path: &Path,
    ) -> Result<
        (Self, Arc<dyn ResolvesServerCert>, bool),
        CertificateProviderError,
    > {
        validate_acme_options(&options)?;
        let account_key = normalize_acme_account_key(&options.account_key)?;
        let use_http01 = options.disable_tls_alpn_challenge;
        let domains = options.domain.0;
        let cache = if options.data_directory.is_empty() {
            base_path.join("acme")
        } else {
            let path = PathBuf::from(options.data_directory);
            if path.is_absolute() {
                path
            } else {
                base_path.join(path)
            }
        };
        let config = AcmeConfig::new(domains);
        let mut config = match account_key {
            Some(key) => config
                .cache_compose(DirCache::new(cache), FixedAccountCache { key }),
            None => config.cache(DirCache::new(cache)),
        };
        config = match options.provider.as_str() {
            "" | "letsencrypt" => config.directory_lets_encrypt(true),
            provider => config.directory(provider),
        };
        if !options.email.trim().is_empty() {
            config =
                config.contact_push(format!("mailto:{}", options.email.trim()));
        }
        if use_http01 {
            config = config.challenge_type(UseChallenge::Http01);
        }
        let state = config.state();
        let resolver = state.resolver();
        Ok((
            Self {
                name: format!("certificate-provider/acme[{tag}]"),
                state: Mutex::new(Some(state)),
                task: None,
                http01_resolver: use_http01.then(|| resolver.clone()),
                http01_port: if options.alternative_http_port == 0 {
                    80
                } else {
                    options.alternative_http_port
                },
                http01_cancellation: CancellationToken::new(),
                http01_tasks: Vec::new(),
            },
            resolver,
            !use_http01,
        ))
    }
}

impl Lifecycle for AcmeProviderService {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start || self.task.is_some() {
                return Ok(());
            }
            if let Some(resolver) = self.http01_resolver.clone() {
                let listeners = bind_http01_listeners(self.http01_port)
                    .map_err(|error| LifecycleError::Start {
                        component: self.name.clone(),
                        stage,
                        message: format!(
                            "bind ACME HTTP-01 listener on port {}: {error}",
                            self.http01_port
                        ),
                    })?;
                for listener in listeners {
                    let resolver = resolver.clone();
                    let cancellation = self.http01_cancellation.clone();
                    self.http01_tasks.push(tokio::spawn(async move {
                        run_http01_listener(listener, resolver, cancellation)
                            .await;
                    }));
                }
            }
            let mut state = self
                .state
                .lock()
                .expect("ACME state lock poisoned")
                .take()
                .ok_or_else(|| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: "ACME state is unavailable".into(),
                })?;
            self.task = Some(tokio::spawn(async move {
                while let Some(event) = state.next().await {
                    match event {
                        Ok(event) => tracing::info!(?event, "ACME event"),
                        Err(error) => {
                            tracing::error!(?error, "ACME provider error")
                        }
                    }
                }
            }));
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if let Some(task) = self.task.take() {
                task.abort();
                let _ = task.await;
            }
            self.http01_cancellation.cancel();
            for task in self.http01_tasks.drain(..) {
                let _ = task.await;
            }
            Ok(())
        })
    }
}

fn validate_acme_options(
    options: &AcmeCertificateProviderOptions,
) -> Result<(), CertificateProviderError> {
    if options.domain.as_slice().is_empty() {
        return Err(CertificateProviderError::InvalidAcme(
            "missing domain".into(),
        ));
    }
    match options.provider.as_str() {
        "" | "letsencrypt" => {}
        "zerossl" => {
            return Err(CertificateProviderError::InvalidAcme(
                "ZeroSSL requires external-account binding, which rustls-acme does not expose"
                    .into(),
            ));
        }
        provider if provider.starts_with("https://") => {}
        provider => {
            return Err(CertificateProviderError::InvalidAcme(format!(
                "unsupported ACME provider: {provider}"
            )));
        }
    }
    if options.external_account.is_some() {
        return Err(CertificateProviderError::InvalidAcme(
            "external_account is not supported by rustls-acme".into(),
        ));
    }
    if options.dns01_challenge.is_some() {
        return Err(CertificateProviderError::InvalidAcme(
            "dns01_challenge is not supported by rustls-acme".into(),
        ));
    }
    if !matches!(
        options.key_type,
        crate::option::AcmeKeyType::Default | crate::option::AcmeKeyType::P256
    ) {
        return Err(CertificateProviderError::InvalidAcme(format!(
            "key_type {:?} is not supported by rustls-acme",
            options.key_type
        )));
    }
    if !options.profile.is_empty() {
        return Err(CertificateProviderError::InvalidAcme(
            "profile is not supported by rustls-acme".into(),
        ));
    }
    if options.http_client.is_some() {
        return Err(CertificateProviderError::InvalidAcme(
            "custom http_client routing is not connected yet".into(),
        ));
    }
    if options.disable_http_challenge && options.disable_tls_alpn_challenge {
        return Err(CertificateProviderError::InvalidAcme(
            "HTTP-01 and TLS-ALPN-01 challenges cannot both be disabled".into(),
        ));
    }
    if options.alternative_tls_port != 0 {
        return Err(CertificateProviderError::InvalidAcme(
            "alternative TLS-ALPN-01 challenge ports are not connected yet"
                .into(),
        ));
    }
    Ok(())
}

fn normalize_acme_account_key(
    account_key: &str,
) -> Result<Option<Vec<u8>>, CertificateProviderError> {
    if account_key.is_empty() {
        return Ok(None);
    }
    let signer = acme_signer::AcmeAccountSigner::from_pem(account_key)
        .map_err(|error| {
            CertificateProviderError::InvalidAcme(format!(
                "decode account_key: {error}"
            ))
        })?;
    Ok(Some(signer.pkcs8().to_vec()))
}

async fn run_http01_listener(
    listener: tokio::net::TcpListener,
    resolver: Arc<ResolvesServerCertAcme>,
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
        let resolver = resolver.clone();
        connections.spawn(async move {
            let service = hyper::service::service_fn(move |request| {
                let resolver = resolver.clone();
                async move {
                    let token = request
                        .uri()
                        .path()
                        .strip_prefix("/.well-known/acme-challenge/");
                    let key_authorization = token
                        .and_then(|token| resolver.get_http_01_key_auth(token));
                    let response = match key_authorization {
                        Some(value)
                            if request.method() == hyper::Method::GET =>
                        {
                            hyper::Response::new(http_body_util::Full::new(
                                bytes::Bytes::from(value),
                            ))
                        }
                        _ => hyper::Response::builder()
                            .status(hyper::StatusCode::NOT_FOUND)
                            .body(
                                http_body_util::Full::new(bytes::Bytes::new()),
                            )
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

fn bind_http01_listeners(
    port: u16,
) -> io::Result<Vec<tokio::net::TcpListener>> {
    use socket2::{Domain, Protocol, Socket, Type};

    fn bind(
        domain: Domain,
        address: std::net::SocketAddr,
        dual_stack: bool,
    ) -> io::Result<tokio::net::TcpListener> {
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        if dual_stack {
            socket.set_only_v6(false)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        socket.listen(1024)?;
        tokio::net::TcpListener::from_std(socket.into())
    }

    let ipv6 =
        std::net::SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port);
    if let Ok(listener) = bind(Domain::IPV6, ipv6, true) {
        return Ok(vec![listener]);
    }
    let ipv4 =
        std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port);
    bind(Domain::IPV4, ipv4, false).map(|listener| vec![listener])
}

#[cfg(test)]
mod tests {
    use super::{
        CertificateProviderManager, normalize_acme_account_key,
        uses_advanced_acme, validate_acme_options,
    };
    use crate::{
        option::{
            AcmeCertificateProviderOptions, CertificateProviderOptions,
            InboundTlsOptions, Options,
        },
        outbound::OutboundManager,
        service::Box as ServiceBox,
    };
    use p256::pkcs8::DecodePrivateKey as _;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[test]
    fn acme_account_key_normalizes_p256_and_routes_rsa_to_advanced() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .unwrap();
        let key_pem = key.serialize_pem();
        let normalized = normalize_acme_account_key(&key_pem)
            .unwrap()
            .expect("configured account key");
        assert!(p256::SecretKey::from_pkcs8_der(&normalized).is_ok());

        let options: Options = serde_json::from_value(serde_json::json!({
            "certificate_providers": [{
                "type": "acme",
                "tag": "account-key",
                "domain": "invalid.example",
                "account_key": key_pem
            }]
        }))
        .unwrap();
        CertificateProviderManager::from_options(&options, Path::new("."))
            .unwrap();

        let rsa = openssl::pkey::PKey::from_rsa(
            openssl::rsa::Rsa::generate(2048).unwrap(),
        )
        .unwrap();
        let rsa_pem =
            String::from_utf8(rsa.private_key_to_pem_pkcs8().unwrap()).unwrap();
        let rsa_options: AcmeCertificateProviderOptions =
            serde_json::from_value(serde_json::json!({
                "domain": "advanced.example",
                "account_key": rsa_pem,
            }))
            .unwrap();
        assert!(uses_advanced_acme(&rsa_options));
        assert!(normalize_acme_account_key(&rsa_pem).unwrap().is_some());

        let error = normalize_acme_account_key(
            "-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n",
        )
        .unwrap_err();
        assert!(error.to_string().contains("decode account_key"));
    }

    #[test]
    fn attaches_shared_inline_and_legacy_acme_resolvers() {
        let options: Options = serde_json::from_str(
            r#"{"certificate_providers":[{"type":"acme","tag":"shared","domain":"shared.example"}]}"#,
        )
        .unwrap();
        let mut manager =
            CertificateProviderManager::from_options(&options, Path::new("."))
                .unwrap();

        let mut shared = InboundTlsOptions {
            enabled: true,
            certificate_provider: Some(CertificateProviderOptions::Reference(
                "shared".into(),
            )),
            ..Default::default()
        };
        manager
            .configure_tls(Some(&mut shared), "inbound/shared")
            .unwrap();
        assert!(shared.certificate_resolver.0.is_some());
        assert!(shared.certificate_resolver.1);

        let mut inline: InboundTlsOptions = serde_json::from_str(
            r#"{"enabled":true,"certificate_provider":{"type":"acme","domain":"inline.example"}}"#,
        )
        .unwrap();
        manager
            .configure_tls(Some(&mut inline), "inbound/inline")
            .unwrap();
        assert!(inline.certificate_resolver.0.is_some());

        let mut legacy: InboundTlsOptions = serde_json::from_str(
            r#"{"enabled":true,"acme":{"domain":"legacy.example"}}"#,
        )
        .unwrap();
        manager
            .configure_tls(Some(&mut legacy), "inbound/legacy")
            .unwrap();
        assert!(legacy.certificate_resolver.0.is_some());
        assert_eq!(manager.order.len(), 3);
    }

    #[tokio::test]
    async fn manager_lifecycle_can_start_and_cancel_acme_driver() {
        let directory = tempfile::tempdir().unwrap();
        let options: Options = serde_json::from_str(
            r#"{"certificate_providers":[{"type":"acme","tag":"shared","domain":"invalid.example"}]}"#,
        )
        .unwrap();
        let manager = CertificateProviderManager::from_options(
            &options,
            directory.path(),
        )
        .unwrap();
        let mut service = ServiceBox::builder(Options::default())
            .component(manager)
            .build()
            .unwrap();
        service.start().await.unwrap();
        service.close().await.unwrap();
    }

    #[tokio::test]
    async fn http01_listener_follows_provider_lifecycle() {
        let directory = tempfile::tempdir().unwrap();
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let options: Options = serde_json::from_value(serde_json::json!({
            "certificate_providers": [{
                "type": "acme",
                "tag": "http01",
                "domain": "invalid.example",
                "disable_tls_alpn_challenge": true,
                "alternative_http_port": port
            }]
        }))
        .unwrap();
        let manager = CertificateProviderManager::from_options(
            &options,
            directory.path(),
        )
        .unwrap();
        let mut service = ServiceBox::builder(Options::default())
            .component(manager)
            .build()
            .unwrap();
        service.start().await.unwrap();

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream
            .write_all(
                b"GET /.well-known/acme-challenge/missing HTTP/1.1\r\nHost: invalid.example\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\n"));

        service.close().await.unwrap();
        std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    }

    #[test]
    fn attaches_shared_and_inline_origin_ca_resolvers() {
        let options: Options = serde_json::from_str(
            r#"{
                "certificate_providers":[{
                    "type":"cloudflare-origin-ca",
                    "tag":"shared",
                    "domain":"shared.example",
                    "api_token":"secret"
                }],
                "outbounds":[{"type":"direct","tag":"direct"}]
            }"#,
        )
        .unwrap();
        let outbounds =
            Arc::new(OutboundManager::from_options(&options, "").unwrap());
        let mut manager = CertificateProviderManager::from_runtime_options(
            &options,
            Path::new("."),
            outbounds,
            "",
            None,
            None,
        )
        .unwrap();

        let mut shared = InboundTlsOptions {
            enabled: true,
            certificate_provider: Some(CertificateProviderOptions::Reference(
                "shared".into(),
            )),
            ..Default::default()
        };
        manager
            .configure_tls(Some(&mut shared), "inbound/shared")
            .unwrap();
        assert!(shared.certificate_resolver.0.is_some());
        assert!(!shared.certificate_resolver.1);

        let mut inline: InboundTlsOptions = serde_json::from_str(
            r#"{
                "enabled":true,
                "certificate_provider":{
                    "type":"cloudflare-origin-ca",
                    "domain":"inline.example",
                    "origin_ca_key":"secret"
                }
            }"#,
        )
        .unwrap();
        manager
            .configure_tls(Some(&mut inline), "inbound/inline")
            .unwrap();
        assert!(inline.certificate_resolver.0.is_some());
        assert!(!inline.certificate_resolver.1);
        assert_eq!(manager.order.len(), 2);
    }

    #[test]
    fn tailscale_provider_ignores_the_default_http_client() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {
                "servers": [{"type": "hosts", "tag": "hosts"}],
                "final": "hosts"
            },
            "http_clients": [{
                "tag": "broken-default",
                "detour": "missing-outbound"
            }],
            "route": {"default_http_client": "broken-default"},
            "certificate_providers": [{
                "type": "tailscale",
                "tag": "tailnet-cert",
                "endpoint": "tailnet"
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap();
        let outbounds =
            Arc::new(OutboundManager::from_options(&options, "").unwrap());

        let manager = CertificateProviderManager::from_runtime_options(
            &options,
            Path::new("."),
            outbounds,
            "broken-default",
            None,
            None,
        )
        .unwrap();

        assert_eq!(manager.order, ["tailnet-cert"]);
    }

    #[test]
    fn attaches_advanced_acme_resolver_for_eab_profile_and_key_type() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let options: Options = serde_json::from_value(serde_json::json!({
            "certificate_providers": [{
                "type": "acme",
                "tag": "advanced",
                "domain": "advanced.example",
                "provider": "https://acme.invalid/directory",
                "external_account": {
                    "key_id": "kid",
                    "mac_key": "AQIDBA"
                },
                "profile": "shortlived",
                "key_type": "ed25519",
                "alternative_http_port": port,
                "http_client": {}
            }],
            "outbounds": [{"type":"direct","tag":"direct"}]
        }))
        .unwrap();
        let outbounds =
            Arc::new(OutboundManager::from_options(&options, "").unwrap());
        let mut manager = CertificateProviderManager::from_runtime_options(
            &options,
            Path::new("."),
            outbounds,
            "",
            None,
            None,
        )
        .unwrap();
        let mut tls = InboundTlsOptions {
            enabled: true,
            certificate_provider: Some(CertificateProviderOptions::Reference(
                "advanced".into(),
            )),
            ..Default::default()
        };
        manager
            .configure_tls(Some(&mut tls), "inbound/advanced")
            .unwrap();
        assert!(tls.certificate_resolver.0.is_some());
        assert!(tls.certificate_resolver.1);
    }

    #[test]
    fn alternative_tls_port_selects_advanced_acme_backend() {
        let options: AcmeCertificateProviderOptions = serde_json::from_str(
            r#"{"domain":"advanced.example","alternative_tls_port":8443}"#,
        )
        .unwrap();
        assert!(uses_advanced_acme(&options));
        validate_acme_options(&options).unwrap_err();
    }

    use std::path::Path;
}
