//! gRPC control-plane compatibility with the upstream sing-box daemon API.

mod locale;
mod log_ring;
mod server;
mod started_service;

use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use thiserror::Error;
use tonic::{
    Code, Request, Status,
    metadata::{Ascii, MetadataValue},
    service::Interceptor,
    transport::{Channel, ClientTlsConfig, Endpoint},
};
use url::{Host, Url};

pub use locale::{
    SelectedLocale, apply_request_locale, request_locale, select_locale,
};
pub use log_ring::LogRing;
pub use server::{DaemonServerError, serve_started_with_shutdown};
pub use started_service::{
    DAEMON_API_VERSION, GO_ZERO_TIME_UNIX_MILLIS, StartedDaemonService,
    StartedServiceOptions,
};

/// Generated directly from the pinned upstream daemon protobuf definitions.
pub mod proto {
    tonic::include_proto!("daemon");

    /// Descriptor for gRPC reflection and cross-language schema checks.
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("singbox_daemon_descriptor");
}

/// Configuration accepted by the upstream remote daemon client.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RemoteClientOptions {
    pub server_url: String,
    pub secret: String,
}

/// Parsed target used to configure a Tonic channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteTarget {
    pub authority: String,
    pub server_name: String,
    pub tls: bool,
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("missing server URL")]
    MissingServerUrl,
    #[error("invalid server URL {url:?}: {source}")]
    InvalidServerUrl {
        url: String,
        #[source]
        source: url::ParseError,
    },
    #[error("invalid server URL scheme {scheme:?}, expected http or https")]
    InvalidServerUrlScheme { scheme: String },
    #[error("missing host in server URL {0:?}")]
    MissingServerHost(String),
    #[error("invalid authorization metadata: {0}")]
    InvalidAuthorizationMetadata(
        #[from] tonic::metadata::errors::InvalidMetadataValue,
    ),
    #[error("invalid locale metadata: {0}")]
    InvalidLocaleMetadata(tonic::metadata::errors::InvalidMetadataValue),
    #[error("invalid gRPC endpoint: {0}")]
    InvalidEndpoint(#[from] tonic::transport::Error),
}

impl RemoteClientOptions {
    /// Match Go's `RemoteClientOptions.ServerTarget`, including default ports
    /// and bracketed IPv6 authorities.
    pub fn server_target(&self) -> Result<RemoteTarget, DaemonError> {
        if self.server_url.is_empty() {
            return Err(DaemonError::MissingServerUrl);
        }
        let url = Url::parse(&self.server_url).map_err(|source| {
            DaemonError::InvalidServerUrl {
                url: self.server_url.clone(),
                source,
            }
        })?;
        let tls = match url.scheme() {
            "http" => false,
            "https" => true,
            scheme => {
                return Err(DaemonError::InvalidServerUrlScheme {
                    scheme: scheme.to_owned(),
                });
            }
        };
        let authority_source = self
            .server_url
            .split_once("://")
            .map(|(_, remainder)| remainder)
            .unwrap_or_default()
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        if authority_source.is_empty() {
            return Err(DaemonError::MissingServerHost(
                self.server_url.clone(),
            ));
        }
        let (host, is_ipv6) = match url.host().ok_or_else(|| {
            DaemonError::MissingServerHost(self.server_url.clone())
        })? {
            Host::Domain(host) => (host.to_owned(), false),
            Host::Ipv4(host) => (host.to_string(), false),
            Host::Ipv6(host) => (host.to_string(), true),
        };
        let port = url.port().unwrap_or(if tls { 443 } else { 80 });
        let authority = if is_ipv6 {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        Ok(RemoteTarget {
            authority,
            server_name: host,
            tls,
        })
    }

    /// Build a lazy HTTP/2 channel with the same TLS hostname/default-port
    /// behavior as the Go daemon client.
    pub fn channel(&self) -> Result<Channel, DaemonError> {
        let target = self.server_target()?;
        let scheme = if target.tls { "https" } else { "http" };
        let mut endpoint =
            Endpoint::from_shared(format!("{scheme}://{}", target.authority))?;
        if target.tls {
            endpoint = endpoint.tls_config(
                ClientTlsConfig::new().domain_name(target.server_name),
            )?;
        }
        Ok(endpoint.connect_lazy())
    }

    pub fn auth_interceptor(
        &self,
    ) -> Result<ClientAuthInterceptor, DaemonError> {
        ClientAuthInterceptor::new(&self.secret)
    }

    pub fn auth_interceptor_with_locale(
        &self,
        locale: &str,
    ) -> Result<ClientAuthInterceptor, DaemonError> {
        ClientAuthInterceptor::new_with_locale(&self.secret, locale)
    }
}

/// Adds the upstream `authorization: Bearer …` request metadata.
#[derive(Clone, Debug)]
pub struct ClientAuthInterceptor {
    authorization: Option<MetadataValue<Ascii>>,
    accept_language: MetadataValue<Ascii>,
}

impl ClientAuthInterceptor {
    pub fn new(secret: &str) -> Result<Self, DaemonError> {
        Self::new_with_locale(secret, "en")
    }

    pub fn new_with_locale(
        secret: &str,
        locale: &str,
    ) -> Result<Self, DaemonError> {
        let authorization = if secret.is_empty() {
            None
        } else {
            Some(format!("Bearer {secret}").parse()?)
        };
        let accept_language =
            locale.parse().map_err(DaemonError::InvalidLocaleMetadata)?;
        Ok(Self {
            authorization,
            accept_language,
        })
    }
}

impl Interceptor for ClientAuthInterceptor {
    fn call(
        &mut self,
        mut request: Request<()>,
    ) -> Result<Request<()>, Status> {
        if let Some(authorization) = &self.authorization {
            request
                .metadata_mut()
                .insert("authorization", authorization.clone());
        }
        request
            .metadata_mut()
            .insert("accept-language", self.accept_language.clone());
        Ok(request)
    }
}

/// Applies the same bearer check to generated unary and streaming services.
#[derive(Clone, Debug)]
pub struct ServerAuthInterceptor {
    secret: Arc<str>,
}

impl ServerAuthInterceptor {
    pub fn new(secret: impl Into<Arc<str>>) -> Self {
        Self {
            secret: secret.into(),
        }
    }
}

impl Interceptor for ServerAuthInterceptor {
    fn call(
        &mut self,
        mut request: Request<()>,
    ) -> Result<Request<()>, Status> {
        authenticate(&request, &self.secret)?;
        apply_request_locale(&mut request);
        Ok(request)
    }
}

/// Server-side bearer check shared by unary and streaming handlers.
pub fn authenticate<T>(
    request: &Request<T>,
    secret: &str,
) -> Result<(), Status> {
    if secret.is_empty() {
        return Ok(());
    }
    let Some(authorization) = request.metadata().get("authorization") else {
        return Err(Status::new(
            Code::Unauthenticated,
            "missing authorization",
        ));
    };
    let expected = format!("Bearer {secret}");
    if authorization.as_bytes() != expected.as_bytes() {
        return Err(Status::new(
            Code::Unauthenticated,
            "invalid authorization",
        ));
    }
    Ok(())
}

#[async_trait]
pub trait ManagedHandler: Send + Sync + 'static {
    async fn service_stop(&self) -> Result<(), Status>;
    async fn service_reload(&self) -> Result<(), Status>;
    async fn system_proxy_status(
        &self,
    ) -> Result<proto::SystemProxyStatus, Status>;
    async fn set_system_proxy_enabled(
        &self,
        enabled: bool,
    ) -> Result<(), Status>;
    async fn trigger_native_crash(&self) -> Result<(), Status>;
}

#[async_trait]
pub trait OomRecorder: Send + Sync + 'static {
    async fn write_report(&self) -> Result<(), Status>;
}

pub struct ManagedServiceOptions {
    pub handler: Arc<dyn ManagedHandler>,
    pub debug: bool,
    pub oom_recorder: Option<Arc<dyn OomRecorder>>,
}

/// Native implementation of the upstream `daemon.ManagedService` RPCs.
pub struct ManagedDaemonService {
    handler: Arc<dyn ManagedHandler>,
    debug: bool,
    oom_recorder: Option<Arc<dyn OomRecorder>>,
}

impl ManagedDaemonService {
    pub fn new(options: ManagedServiceOptions) -> Self {
        Self {
            handler: options.handler,
            debug: options.debug,
            oom_recorder: options.oom_recorder,
        }
    }
}

#[async_trait]
impl proto::managed_service_server::ManagedService for ManagedDaemonService {
    async fn stop_service(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<()>, Status> {
        self.handler.service_stop().await?;
        Ok(tonic::Response::new(()))
    }

    async fn reload_service(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<()>, Status> {
        self.handler.service_reload().await?;
        Ok(tonic::Response::new(()))
    }

    async fn get_system_proxy_status(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<proto::SystemProxyStatus>, Status> {
        Ok(tonic::Response::new(
            self.handler.system_proxy_status().await?,
        ))
    }

    async fn set_system_proxy_enabled(
        &self,
        request: Request<proto::SetSystemProxyEnabledRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        self.handler
            .set_system_proxy_enabled(request.into_inner().enabled)
            .await?;
        Ok(tonic::Response::new(()))
    }

    async fn trigger_debug_crash(
        &self,
        request: Request<proto::DebugCrashRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        use proto::debug_crash_request::Type;

        if !self.debug {
            return Err(Status::permission_denied(
                "debug crash trigger unavailable",
            ));
        }
        match Type::try_from(request.into_inner().r#type) {
            Ok(Type::Go) => {
                std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_millis(200));
                    std::process::abort();
                });
            }
            Ok(Type::Native) => self.handler.trigger_native_crash().await?,
            Err(_) => {
                return Err(Status::invalid_argument(
                    "unknown debug crash type",
                ));
            }
        }
        Ok(tonic::Response::new(()))
    }

    async fn trigger_oom_report(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<()>, Status> {
        let recorder = self
            .oom_recorder
            .as_ref()
            .ok_or_else(|| Status::unavailable("OOM recorder not available"))?;
        recorder.write_report().await?;
        Ok(tonic::Response::new(()))
    }
}

impl fmt::Display for RemoteTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.authority)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use prost::Message as _;
    use tokio::{net::TcpListener, sync::oneshot};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::service::Interceptor as _;

    use super::{
        ManagedDaemonService, ManagedHandler, ManagedServiceOptions,
        OomRecorder, RemoteClientOptions, ServerAuthInterceptor, authenticate,
        proto::{
            DebugCrashRequest, SetSystemProxyEnabledRequest, SystemProxyStatus,
            Version, debug_crash_request,
            managed_service_client::ManagedServiceClient,
            managed_service_server::ManagedServiceServer,
        },
    };

    #[derive(Default)]
    struct TestManagedHandler {
        stops: AtomicUsize,
        reloads: AtomicUsize,
        proxy_enabled: AtomicBool,
        native_crashes: AtomicUsize,
    }

    #[async_trait]
    impl ManagedHandler for TestManagedHandler {
        async fn service_stop(&self) -> Result<(), tonic::Status> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn service_reload(&self) -> Result<(), tonic::Status> {
            self.reloads.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn system_proxy_status(
            &self,
        ) -> Result<SystemProxyStatus, tonic::Status> {
            Ok(SystemProxyStatus {
                available: true,
                enabled: self.proxy_enabled.load(Ordering::SeqCst),
            })
        }

        async fn set_system_proxy_enabled(
            &self,
            enabled: bool,
        ) -> Result<(), tonic::Status> {
            self.proxy_enabled.store(enabled, Ordering::SeqCst);
            Ok(())
        }

        async fn trigger_native_crash(&self) -> Result<(), tonic::Status> {
            self.native_crashes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct TestOomRecorder(AtomicUsize);

    #[async_trait]
    impl OomRecorder for TestOomRecorder {
        async fn write_report(&self) -> Result<(), tonic::Status> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn daemon_proto_wire_matches_upstream_field_numbers() {
        let version = Version {
            version: "1.12.0".into(),
            api_version: 7,
        };
        assert_eq!(
            version.encode_to_vec(),
            b"\x0a\x06\x31\x2e\x31\x32\x2e\x30\x10\x07"
        );
        assert_eq!(
            SystemProxyStatus {
                available: true,
                enabled: true,
            }
            .encode_to_vec(),
            b"\x08\x01\x10\x01"
        );
    }

    #[test]
    fn remote_target_matches_upstream_url_and_default_port_rules() {
        for (url, authority, server_name, tls) in [
            ("http://example.com", "example.com:80", "example.com", false),
            (
                "https://example.com/api",
                "example.com:443",
                "example.com",
                true,
            ),
            (
                "https://example.com:8443",
                "example.com:8443",
                "example.com",
                true,
            ),
            ("http://[::1]", "[::1]:80", "[::1]", false),
        ] {
            let target = RemoteClientOptions {
                server_url: url.into(),
                secret: String::new(),
            }
            .server_target()
            .unwrap();
            assert_eq!(target.authority, authority);
            assert_eq!(
                target.server_name,
                server_name.trim_matches(['[', ']'])
            );
            assert_eq!(target.tls, tls);
        }
    }

    #[test]
    fn remote_target_rejects_the_same_invalid_url_classes_as_upstream() {
        for url in ["", "unix:///tmp/control.sock", "http:///missing-host"] {
            assert!(
                RemoteClientOptions {
                    server_url: url.into(),
                    secret: String::new(),
                }
                .server_target()
                .is_err(),
                "accepted {url:?}"
            );
        }
    }

    #[test]
    fn bearer_metadata_is_added_and_authenticated_exactly() {
        let options = RemoteClientOptions {
            server_url: "http://127.0.0.1".into(),
            secret: "secret".into(),
        };
        let request = options
            .auth_interceptor()
            .unwrap()
            .call(tonic::Request::new(()))
            .unwrap();
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer secret"
        );
        authenticate(&request, "secret").unwrap();
        let error = authenticate(&request, "other").unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(error.message(), "invalid authorization");

        let missing = tonic::Request::new(());
        let error = authenticate(&missing, "secret").unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(error.message(), "missing authorization");
        authenticate(&missing, "").unwrap();
    }

    #[tokio::test]
    async fn managed_service_grpc_auth_and_handlers_interoperate() {
        let handler = Arc::new(TestManagedHandler::default());
        let oom_recorder = Arc::new(TestOomRecorder(AtomicUsize::new(0)));
        let service = ManagedDaemonService::new(ManagedServiceOptions {
            handler: handler.clone(),
            debug: true,
            oom_recorder: Some(oom_recorder.clone()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(ManagedServiceServer::with_interceptor(
                    service,
                    ServerAuthInterceptor::new("daemon secret"),
                ))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    async move {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
                .unwrap();
        });

        let options = RemoteClientOptions {
            server_url: format!("http://{address}"),
            secret: "daemon secret".into(),
        };
        let mut client = ManagedServiceClient::with_interceptor(
            options.channel().unwrap(),
            options.auth_interceptor().unwrap(),
        );
        let status = client
            .get_system_proxy_status(())
            .await
            .unwrap()
            .into_inner();
        assert!(status.available);
        assert!(!status.enabled);
        client
            .set_system_proxy_enabled(SetSystemProxyEnabledRequest {
                enabled: true,
            })
            .await
            .unwrap();
        assert!(handler.proxy_enabled.load(Ordering::SeqCst));
        client.reload_service(()).await.unwrap();
        client.stop_service(()).await.unwrap();
        assert_eq!(handler.reloads.load(Ordering::SeqCst), 1);
        assert_eq!(handler.stops.load(Ordering::SeqCst), 1);
        client
            .trigger_debug_crash(DebugCrashRequest {
                r#type: debug_crash_request::Type::Native.into(),
            })
            .await
            .unwrap();
        assert_eq!(handler.native_crashes.load(Ordering::SeqCst), 1);
        client.trigger_oom_report(()).await.unwrap();
        assert_eq!(oom_recorder.0.load(Ordering::SeqCst), 1);

        let mut unauthorized = ManagedServiceClient::new(
            RemoteClientOptions {
                server_url: format!("http://{address}"),
                secret: String::new(),
            }
            .channel()
            .unwrap(),
        );
        let error = unauthorized.get_system_proxy_status(()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(error.message(), "missing authorization");

        let _ = shutdown_tx.send(());
        server.await.unwrap();
    }
}
