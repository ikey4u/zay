//! Reconnecting Tailscale registration and streaming netmap supervisor.
//!
//! Transport establishment is injected so the same lifecycle can run over a
//! direct TLS socket, a configured detour, or an in-memory compatibility
//! server. The supervisor owns the upstream register/map ordering, resumable
//! map session cursor, bounded frame decoder and exponential reconnect loop.

use std::{
    io,
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    sync::{broadcast, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use super::{
    tailscale_control::{
        TailscaleControlError, TailscaleControlHttp2Client,
        TailscaleControlServerKeys, TailscaleMapFrameDecoder,
        connect_tailscale_control, parse_tailscale_control_server_keys,
        start_tailscale_control_http2, tailscale_control_key_path,
    },
    tailscale_control_types::{
        TAILSCALE_MAP_COMPRESSED_FRAME_LIMIT,
        TAILSCALE_MAP_DECODED_FRAME_LIMIT, TailscaleMapRequest,
        TailscaleMapResponse, TailscaleNetmapState, TailscaleNetmapUpdate,
        TailscaleNodePublicKey, TailscaleRegisterRequest,
        TailscaleRegisterResponse, TailscaleSetDnsRequest,
        TailscaleTkaBootstrapRequest, TailscaleTkaBootstrapResponse,
        TailscaleTkaInfo, TailscaleTkaSyncOfferRequest,
        TailscaleTkaSyncOfferResponse, TailscaleTkaSyncSendRequest,
        TailscaleTkaSyncSendResponse,
    },
    tailscale_wireguard::TailscaleWireGuardHandle,
};
use crate::{
    adapter::{Dialer, Stream},
    common::{
        http::{DownloadOptions, download_with_options},
        network::SocksAddr,
        tls::{ClientTlsDialer, build_client_config},
    },
    option::OutboundTlsOptions,
};

const EVENT_QUEUE_DEPTH: usize = 32;
const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const DEFAULT_MAXIMUM_BACKOFF: Duration = Duration::from_secs(30);

#[async_trait]
pub trait TailscaleControlMapStream: Send {
    async fn next_chunk(
        &mut self,
    ) -> Result<Option<Vec<u8>>, TailscaleControlError>;
}

#[async_trait]
pub trait TailscaleControlSession: Send {
    async fn register(
        &mut self,
        request: &TailscaleRegisterRequest,
    ) -> Result<TailscaleRegisterResponse, TailscaleControlError>;

    async fn start_map(
        &mut self,
        request: &TailscaleMapRequest,
    ) -> Result<Box<dyn TailscaleControlMapStream>, TailscaleControlError>;

    async fn tka_bootstrap(
        &mut self,
        _request: &TailscaleTkaBootstrapRequest,
    ) -> Result<TailscaleTkaBootstrapResponse, TailscaleControlError> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Tailscale control session does not implement TKA bootstrap",
        )
        .into())
    }

    async fn tka_sync_offer(
        &mut self,
        _request: &TailscaleTkaSyncOfferRequest,
    ) -> Result<TailscaleTkaSyncOfferResponse, TailscaleControlError> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Tailscale control session does not implement TKA sync offer",
        )
        .into())
    }

    async fn tka_sync_send(
        &mut self,
        _request: &TailscaleTkaSyncSendRequest,
    ) -> Result<TailscaleTkaSyncSendResponse, TailscaleControlError> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Tailscale control session does not implement TKA sync send",
        )
        .into())
    }
}

#[async_trait]
pub trait TailscaleTkaSynchronizer: Send + Sync {
    /// Returns true when the map request's advertised TKA head changed and the
    /// streaming map RPC should be restarted.
    async fn synchronize(
        &self,
        session: &mut dyn TailscaleControlSession,
        control: &TailscaleTkaInfo,
        map_request: &mut TailscaleMapRequest,
    ) -> Result<bool, TailscaleControlError>;
}

#[async_trait]
pub trait TailscaleControlConnector: Send + Sync {
    async fn connect(
        &self,
    ) -> Result<Box<dyn TailscaleControlSession>, TailscaleControlError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleControlBootstrap {
    pub authority: String,
    pub destination: SocksAddr,
    pub tls: bool,
    pub server_keys: TailscaleControlServerKeys,
}

impl TailscaleControlBootstrap {
    pub fn control_public_key(
        &self,
    ) -> Result<[u8; 32], TailscaleControlError> {
        if self.server_keys.public_key != [0; 32] {
            return Ok(self.server_keys.public_key);
        }
        self.server_keys
            .legacy_public_key
            .ok_or(TailscaleControlError::ZeroKey)
    }
}

/// Resolve the control URL and retrieve its Noise machine key over the
/// caller's normal outbound dialer. HTTPS certificate policy is inherited
/// from the shared library HTTP client.
pub async fn bootstrap_tailscale_control(
    dialer: Arc<dyn Dialer>,
    control_url: &str,
    capability_version: u32,
) -> Result<TailscaleControlBootstrap, TailscaleControlError> {
    bootstrap_tailscale_control_with_tls_options(
        dialer,
        control_url,
        capability_version,
        None,
    )
    .await
}

pub async fn bootstrap_tailscale_control_with_tls_options(
    dialer: Arc<dyn Dialer>,
    control_url: &str,
    capability_version: u32,
    tls_options: Option<&OutboundTlsOptions>,
) -> Result<TailscaleControlBootstrap, TailscaleControlError> {
    let mut url = url::Url::parse(control_url).map_err(|error| {
        TailscaleControlError::InvalidHttpRequest(error.to_string())
    })?;
    let tls = match url.scheme() {
        "https" => true,
        "http" => false,
        scheme => {
            return Err(TailscaleControlError::InvalidHttpRequest(format!(
                "unsupported control URL scheme {scheme:?}"
            )));
        }
    };
    let host = url.host_str().ok_or_else(|| {
        TailscaleControlError::InvalidHttpRequest(
            "control URL has no host".into(),
        )
    })?;
    let port = url.port_or_known_default().ok_or_else(|| {
        TailscaleControlError::InvalidHttpRequest(
            "control URL has no port".into(),
        )
    })?;
    let authority_host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let authority = match url.port() {
        Some(port) => format!("{authority_host}:{port}"),
        None => authority_host,
    };
    let destination = SocksAddr::new(host, port);
    let key_path = tailscale_control_key_path(capability_version);
    let (path, query) = key_path.split_once('?').unwrap_or((&key_path, ""));
    url.set_path(path);
    url.set_query((!query.is_empty()).then_some(query));
    url.set_fragment(None);
    let response = download_with_options(
        dialer,
        url.as_str(),
        &hyper::HeaderMap::new(),
        &DownloadOptions {
            client: crate::option::HttpClientOptions {
                tls: tls_options.cloned(),
                ..Default::default()
            },
        },
    )
    .await?;
    if response.status != hyper::StatusCode::OK {
        return Err(TailscaleControlError::ControlHttpStatus {
            status: response.status.as_u16(),
            message: String::from_utf8_lossy(&response.body)
                .trim()
                .chars()
                .take(200)
                .collect(),
        });
    }
    let server_keys = parse_tailscale_control_server_keys(&response.body)?;
    Ok(TailscaleControlBootstrap {
        authority,
        destination,
        tls,
        server_keys,
    })
}

/// Production TS2021 connector. `stream_dialer` must already apply TLS when
/// the bootstrap result has `tls=true`; keeping that wrapper explicit lets
/// zay reuse its selected roots, ECH policy, detour and time source.
#[derive(Clone)]
pub struct TailscaleTs2021DialConnector {
    pub stream_dialer: Arc<dyn Dialer>,
    pub destination: SocksAddr,
    pub authority: String,
    pub machine_private_key: [u8; 32],
    pub control_public_key: [u8; 32],
    pub protocol_version: u16,
    pub load_balancer_keys: Vec<String>,
}

impl TailscaleTs2021DialConnector {
    pub async fn connect_http2_client(
        &self,
    ) -> Result<TailscaleControlHttp2Client, TailscaleControlError> {
        let stream: Stream =
            self.stream_dialer.dial_tcp(&self.destination).await?;
        let stream = connect_tailscale_control(
            stream,
            &self.authority,
            self.machine_private_key,
            self.control_public_key,
            self.protocol_version,
        )
        .await?;
        let (_, client) = start_tailscale_control_http2(stream).await?;
        Ok(client)
    }

    /// Publish one DNS-01 TXT record over a fresh authenticated TS2021
    /// connection. A fresh connection mirrors Tailscale's LocalBackend
    /// `SetDNS` path and avoids contending with the long-lived map stream.
    pub async fn set_dns(
        &self,
        node_key: TailscaleNodePublicKey,
        name: String,
        value: String,
    ) -> Result<(), TailscaleControlError> {
        let mut client = self.connect_http2_client().await?;
        let keys = self
            .load_balancer_keys
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        client
            .set_dns(
                &self.authority,
                &TailscaleSetDnsRequest {
                    version: u32::from(self.protocol_version),
                    node_key,
                    name,
                    record_type: "TXT".into(),
                    value,
                },
                &keys,
            )
            .await?;
        Ok(())
    }
}

/// Build a TS2021 connector from a bootstrap result, automatically applying
/// TLS for HTTPS control servers while preserving the caller's dialer/detour.
pub fn build_tailscale_control_connector(
    dialer: Arc<dyn Dialer>,
    bootstrap: &TailscaleControlBootstrap,
    machine_private_key: [u8; 32],
    protocol_version: u16,
    load_balancer_keys: Vec<String>,
    tls_options: Option<&OutboundTlsOptions>,
) -> Result<TailscaleTs2021DialConnector, TailscaleControlError> {
    let stream_dialer: Arc<dyn Dialer> = if bootstrap.tls {
        let mut options = tls_options.cloned().unwrap_or_default();
        options.enabled = true;
        let tls =
            build_client_config(&bootstrap.destination.host(), &options, &[])
                .map_err(|error| {
                TailscaleControlError::InvalidHttpRequest(error.to_string())
            })?;
        Arc::new(ClientTlsDialer::new(dialer, tls))
    } else {
        dialer
    };
    Ok(TailscaleTs2021DialConnector {
        stream_dialer,
        destination: bootstrap.destination.clone(),
        authority: bootstrap.authority.clone(),
        machine_private_key,
        control_public_key: bootstrap.control_public_key()?,
        protocol_version,
        load_balancer_keys,
    })
}

#[async_trait]
impl TailscaleControlConnector for TailscaleTs2021DialConnector {
    async fn connect(
        &self,
    ) -> Result<Box<dyn TailscaleControlSession>, TailscaleControlError> {
        let client = self.connect_http2_client().await?;
        Ok(Box::new(TailscaleHttp2ControlSession::new(
            client,
            self.authority.clone(),
            self.load_balancer_keys.clone(),
        )))
    }
}

/// Consumer invoked after every ordered batch of map responses.
#[async_trait]
pub trait TailscaleNetmapConsumer: Send + Sync {
    async fn apply_netmap(
        &self,
        netmap: &TailscaleNetmapState,
    ) -> Result<(), String>;
}

#[async_trait]
impl TailscaleNetmapConsumer for TailscaleWireGuardHandle {
    async fn apply_netmap(
        &self,
        netmap: &TailscaleNetmapState,
    ) -> Result<(), String> {
        self.set_netmap(netmap)
            .await
            .map_err(|error| error.to_string())
    }
}

/// Adapter from the authenticated TS2021 HTTP/2 client to the supervisor's
/// reconnectable logical session interface.
pub struct TailscaleHttp2ControlSession {
    client: TailscaleControlHttp2Client,
    authority: String,
    load_balancer_keys: Vec<String>,
}

impl TailscaleHttp2ControlSession {
    pub fn new(
        client: TailscaleControlHttp2Client,
        authority: impl Into<String>,
        load_balancer_keys: Vec<String>,
    ) -> Self {
        Self {
            client,
            authority: authority.into(),
            load_balancer_keys,
        }
    }
}

#[async_trait]
impl TailscaleControlSession for TailscaleHttp2ControlSession {
    async fn register(
        &mut self,
        request: &TailscaleRegisterRequest,
    ) -> Result<TailscaleRegisterResponse, TailscaleControlError> {
        let authority = self.authority.clone();
        let keys = self.load_balancer_keys.clone();
        let keys = keys.iter().map(String::as_str).collect::<Vec<_>>();
        self.client.register(&authority, request, &keys).await
    }

    async fn start_map(
        &mut self,
        request: &TailscaleMapRequest,
    ) -> Result<Box<dyn TailscaleControlMapStream>, TailscaleControlError> {
        let authority = self.authority.clone();
        let keys = self.load_balancer_keys.clone();
        let keys = keys.iter().map(String::as_str).collect::<Vec<_>>();
        let response =
            self.client.start_map(&authority, request, &keys).await?;
        Ok(Box::new(TailscaleHyperMapStream(response.into_body())))
    }

    async fn tka_bootstrap(
        &mut self,
        request: &TailscaleTkaBootstrapRequest,
    ) -> Result<TailscaleTkaBootstrapResponse, TailscaleControlError> {
        let authority = self.authority.clone();
        let keys = self.load_balancer_keys.clone();
        let keys = keys.iter().map(String::as_str).collect::<Vec<_>>();
        self.client.tka_bootstrap(&authority, request, &keys).await
    }

    async fn tka_sync_offer(
        &mut self,
        request: &TailscaleTkaSyncOfferRequest,
    ) -> Result<TailscaleTkaSyncOfferResponse, TailscaleControlError> {
        let authority = self.authority.clone();
        let keys = self.load_balancer_keys.clone();
        let keys = keys.iter().map(String::as_str).collect::<Vec<_>>();
        self.client.tka_sync_offer(&authority, request, &keys).await
    }

    async fn tka_sync_send(
        &mut self,
        request: &TailscaleTkaSyncSendRequest,
    ) -> Result<TailscaleTkaSyncSendResponse, TailscaleControlError> {
        let authority = self.authority.clone();
        let keys = self.load_balancer_keys.clone();
        let keys = keys.iter().map(String::as_str).collect::<Vec<_>>();
        self.client.tka_sync_send(&authority, request, &keys).await
    }
}

struct TailscaleHyperMapStream(Incoming);

#[async_trait]
impl TailscaleControlMapStream for TailscaleHyperMapStream {
    async fn next_chunk(
        &mut self,
    ) -> Result<Option<Vec<u8>>, TailscaleControlError> {
        loop {
            let Some(frame) = self.0.frame().await else {
                return Ok(None);
            };
            let frame = frame.map_err(|error| {
                TailscaleControlError::Http2(error.to_string())
            })?;
            if let Some(data) = frame.data_ref() {
                if data.is_empty() {
                    continue;
                }
                return Ok(Some(data.to_vec()));
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleControlSupervisorOptions {
    pub initial_backoff: Duration,
    pub maximum_backoff: Duration,
    pub maximum_compressed_frame: usize,
    pub maximum_decoded_frame: usize,
}

impl Default for TailscaleControlSupervisorOptions {
    fn default() -> Self {
        Self {
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
            maximum_backoff: DEFAULT_MAXIMUM_BACKOFF,
            maximum_compressed_frame: TAILSCALE_MAP_COMPRESSED_FRAME_LIMIT,
            maximum_decoded_frame: TAILSCALE_MAP_DECODED_FRAME_LIMIT,
        }
    }
}

impl TailscaleControlSupervisorOptions {
    fn normalized(&self) -> Self {
        let initial_backoff = if self.initial_backoff.is_zero() {
            DEFAULT_INITIAL_BACKOFF
        } else {
            self.initial_backoff
        };
        Self {
            initial_backoff,
            maximum_backoff: self.maximum_backoff.max(initial_backoff),
            maximum_compressed_frame: if self.maximum_compressed_frame == 0 {
                TAILSCALE_MAP_COMPRESSED_FRAME_LIMIT
            } else {
                self.maximum_compressed_frame
            },
            maximum_decoded_frame: if self.maximum_decoded_frame == 0 {
                TAILSCALE_MAP_DECODED_FRAME_LIMIT
            } else {
                self.maximum_decoded_frame
            },
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleControlSupervisorStatus {
    pub connected: bool,
    pub generation: u64,
    pub machine_authorized: bool,
    pub node_key_expired: bool,
    pub auth_url: String,
    pub map_session_handle: String,
    pub map_sequence: i64,
    pub peers: usize,
    pub reconnects: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TailscaleControlSupervisorEvent {
    Registered {
        generation: u64,
        machine_authorized: bool,
        auth_url: String,
    },
    MapConnected {
        generation: u64,
        resumed_session: bool,
    },
    Netmap {
        generation: u64,
        update: TailscaleNetmapUpdate,
        state: Box<TailscaleNetmapState>,
    },
    Disconnected {
        generation: u64,
        error: String,
        retry_in: Duration,
    },
    /// A process-level control command surfaced to the embedding application.
    /// The library never exits the zay process or disables its logging itself.
    DebugCommand {
        generation: u64,
        exit_code: Option<i32>,
        disable_log_tail: bool,
        sleep: Duration,
    },
    /// The active node identity must be replaced before a map stream can be
    /// trusted. A signature returned by control must be re-signed for the new
    /// node key when tailnet lock is active.
    NodeKeyRotationRequired {
        generation: u64,
        node_key_signature: Option<Vec<u8>>,
    },
}

pub struct TailscaleControlSupervisor {
    status: Arc<RwLock<TailscaleControlSupervisorStatus>>,
    events: broadcast::Sender<TailscaleControlSupervisorEvent>,
    endpoints: watch::Sender<(Vec<String>, Vec<i32>)>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl TailscaleControlSupervisor {
    pub fn spawn(
        connector: Arc<dyn TailscaleControlConnector>,
        consumer: Arc<dyn TailscaleNetmapConsumer>,
        register_request: TailscaleRegisterRequest,
        map_request: TailscaleMapRequest,
        options: TailscaleControlSupervisorOptions,
    ) -> Self {
        Self::spawn_with_tka(
            connector,
            consumer,
            register_request,
            map_request,
            options,
            None,
        )
    }

    pub fn spawn_with_tka(
        connector: Arc<dyn TailscaleControlConnector>,
        consumer: Arc<dyn TailscaleNetmapConsumer>,
        register_request: TailscaleRegisterRequest,
        mut map_request: TailscaleMapRequest,
        options: TailscaleControlSupervisorOptions,
        tka: Option<Arc<dyn TailscaleTkaSynchronizer>>,
    ) -> Self {
        let options = options.normalized();
        map_request.stream = true;
        if map_request.compress.is_empty() {
            map_request.compress = "zstd".into();
        }
        let status =
            Arc::new(RwLock::new(TailscaleControlSupervisorStatus::default()));
        let (events, _) = broadcast::channel(EVENT_QUEUE_DEPTH);
        let (endpoints, endpoint_updates) = watch::channel((
            map_request.endpoints.clone(),
            map_request.endpoint_types.clone(),
        ));
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run_supervisor(
            connector,
            consumer,
            register_request,
            map_request,
            options,
            tka,
            status.clone(),
            events.clone(),
            endpoint_updates,
            cancellation.clone(),
        ));
        Self {
            status,
            events,
            endpoints,
            cancellation,
            task: Some(task),
        }
    }

    pub fn status(&self) -> TailscaleControlSupervisorStatus {
        self.status
            .read()
            .map(|status| status.clone())
            .unwrap_or_default()
    }

    pub fn subscribe(
        &self,
    ) -> broadcast::Receiver<TailscaleControlSupervisorEvent> {
        self.events.subscribe()
    }

    /// Publish a newly discovered endpoint set and restart the streaming map
    /// request immediately so control and peers receive the updated candidates.
    pub fn update_endpoints(
        &self,
        endpoints: Vec<String>,
        endpoint_types: Vec<i32>,
    ) -> io::Result<()> {
        if endpoints.len() != endpoint_types.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Tailscale endpoint/type lengths differ",
            ));
        }
        self.endpoints
            .send((endpoints, endpoint_types))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Tailscale control supervisor is closed",
                )
            })
    }

    pub async fn close(mut self) -> io::Result<()> {
        self.cancellation.cancel();
        self.task
            .take()
            .expect("Tailscale control supervisor task is present")
            .await
            .map_err(|error| {
                io::Error::other(format!(
                    "Tailscale control supervisor task failed: {error}"
                ))
            })
    }
}

impl Drop for TailscaleControlSupervisor {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_supervisor(
    connector: Arc<dyn TailscaleControlConnector>,
    consumer: Arc<dyn TailscaleNetmapConsumer>,
    mut register_request: TailscaleRegisterRequest,
    mut map_request: TailscaleMapRequest,
    options: TailscaleControlSupervisorOptions,
    tka: Option<Arc<dyn TailscaleTkaSynchronizer>>,
    status: Arc<RwLock<TailscaleControlSupervisorStatus>>,
    events: broadcast::Sender<TailscaleControlSupervisorEvent>,
    mut endpoint_updates: watch::Receiver<(Vec<String>, Vec<i32>)>,
    cancellation: CancellationToken,
) {
    let mut state = TailscaleNetmapState::default();
    let mut generation = 0_u64;
    let mut backoff = options.initial_backoff;
    loop {
        let result = tokio::select! {
            _ = cancellation.cancelled() => break,
            result = connector.connect() => result,
        };
        let mut session = match result {
            Ok(session) => session,
            Err(error) => {
                disconnected(
                    &status,
                    &events,
                    generation,
                    error.to_string(),
                    backoff,
                );
                if !sleep_or_cancel(backoff, &cancellation).await {
                    break;
                }
                backoff = next_backoff(backoff, options.maximum_backoff);
                continue;
            }
        };
        generation = generation.saturating_add(1);
        let registration_error = loop {
            let registration = tokio::select! {
                _ = cancellation.cancelled() => return,
                result = session.register(&register_request) => result,
            };
            let registration = match registration {
                Ok(response) => response,
                Err(error) => break Some(error.to_string()),
            };
            update_status(&status, |status| {
                status.generation = generation;
                status.machine_authorized = registration.machine_authorized;
                status.auth_url = registration.auth_url.clone();
                status.last_error = None;
            });
            let _ = events.send(TailscaleControlSupervisorEvent::Registered {
                generation,
                machine_authorized: registration.machine_authorized,
                auth_url: registration.auth_url.clone(),
            });
            if !registration.error.is_empty() {
                break Some(registration.error);
            }
            let rotation_required = registration.node_key_expired
                || registration.node_key_signature.is_some();
            update_status(&status, |status| {
                status.node_key_expired = rotation_required;
            });
            if rotation_required {
                let _ = events.send(
                    TailscaleControlSupervisorEvent::NodeKeyRotationRequired {
                        generation,
                        node_key_signature: registration.node_key_signature,
                    },
                );
                break Some("Tailscale node key rotation is required".into());
            }
            if registration.machine_authorized {
                register_request.followup.clear();
                break None;
            }
            if registration.auth_url.is_empty() {
                break Some("machine is not authorized".to_owned());
            }

            // WaitLoginURL is another register RPC carrying the URL returned
            // by the previous response. It normally long-polls. A server that
            // immediately repeats the same URL is rate-limited locally to
            // avoid a tight loop while the user is in the browser.
            if register_request.followup == registration.auth_url
                && !sleep_or_cancel(options.initial_backoff, &cancellation)
                    .await
            {
                return;
            }
            register_request.followup = registration.auth_url;
        };
        if let Some(error) = registration_error {
            disconnected(&status, &events, generation, error, backoff);
            if !sleep_or_cancel(backoff, &cancellation).await {
                break;
            }
            backoff = next_backoff(backoff, options.maximum_backoff);
            continue;
        }

        map_request.map_session_handle = state.map_session_handle.clone();
        map_request.map_session_seq = state.sequence;
        let resumed_session = !map_request.map_session_handle.is_empty();
        let map = tokio::select! {
            _ = cancellation.cancelled() => break,
            result = session.start_map(&map_request) => result,
        };
        let mut map = match map {
            Ok(map) => map,
            Err(error) => {
                disconnected(
                    &status,
                    &events,
                    generation,
                    error.to_string(),
                    backoff,
                );
                if !sleep_or_cancel(backoff, &cancellation).await {
                    break;
                }
                backoff = next_backoff(backoff, options.maximum_backoff);
                continue;
            }
        };
        backoff = options.initial_backoff;
        update_status(&status, |status| {
            status.connected = true;
            status.generation = generation;
            status.last_error = None;
        });
        let _ = events.send(TailscaleControlSupervisorEvent::MapConnected {
            generation,
            resumed_session,
        });
        let mut decoder = TailscaleMapFrameDecoder::new(
            options.maximum_compressed_frame,
            options.maximum_decoded_frame,
        );
        let disconnect_error = 'map: loop {
            let chunk = tokio::select! {
                _ = cancellation.cancelled() => return,
                changed = endpoint_updates.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    let (endpoints, endpoint_types) = endpoint_updates.borrow_and_update().clone();
                    map_request.endpoints = endpoints;
                    map_request.endpoint_types = endpoint_types;
                    break 'map None;
                }
                result = map.next_chunk() => result,
            };
            let chunk = match chunk {
                Ok(Some(chunk)) => chunk,
                Ok(None) => {
                    let message = if decoder.buffered_len() == 0 {
                        "map stream closed".to_owned()
                    } else {
                        format!(
                            "map stream closed with {} buffered bytes",
                            decoder.buffered_len()
                        )
                    };
                    break Some(message);
                }
                Err(error) => break Some(error.to_string()),
            };
            let responses =
                match decoder.push_typed::<TailscaleMapResponse>(&chunk) {
                    Ok(responses) => responses,
                    Err(error) => break Some(error.to_string()),
                };
            for response in responses {
                if let Some(debug) = &response.debug {
                    let sleep = debug_sleep_duration(debug.sleep_seconds);
                    let _ = events.send(
                        TailscaleControlSupervisorEvent::DebugCommand {
                            generation,
                            exit_code: debug.exit_code,
                            disable_log_tail: debug.disable_log_tail,
                            sleep,
                        },
                    );
                    if !sleep.is_zero()
                        && !sleep_or_cancel(sleep, &cancellation).await
                    {
                        return;
                    }
                }
                if let (Some(tka), Some(tka_info)) =
                    (tka.as_ref(), response.tka_info.as_ref())
                {
                    let changed = match tka
                        .synchronize(
                            session.as_mut(),
                            tka_info,
                            &mut map_request,
                        )
                        .await
                    {
                        Ok(changed) => changed,
                        Err(error) => break 'map Some(error.to_string()),
                    };
                    if changed {
                        break 'map None;
                    }
                }
                let now = OffsetDateTime::now_utc()
                    .format(&Rfc3339)
                    .unwrap_or_default();
                let update = state.apply(response, &now);
                if update.keep_alive {
                    continue;
                }
                if let Err(error) = consumer.apply_netmap(&state).await {
                    break 'map Some(error);
                }
                update_status(&status, |status| {
                    status.map_session_handle =
                        state.map_session_handle.clone();
                    status.map_sequence = state.sequence;
                    status.peers = state.peers.len();
                    status.last_error = None;
                });
                let _ = events.send(TailscaleControlSupervisorEvent::Netmap {
                    generation,
                    update,
                    state: Box::new(state.clone()),
                });
            }
        };
        let Some(disconnect_error) = disconnect_error else {
            update_status(&status, |status| status.connected = false);
            continue;
        };
        disconnected(&status, &events, generation, disconnect_error, backoff);
        if !sleep_or_cancel(backoff, &cancellation).await {
            break;
        }
        backoff = next_backoff(backoff, options.maximum_backoff);
    }
}

fn disconnected(
    status: &RwLock<TailscaleControlSupervisorStatus>,
    events: &broadcast::Sender<TailscaleControlSupervisorEvent>,
    generation: u64,
    error: String,
    retry_in: Duration,
) {
    update_status(status, |status| {
        status.connected = false;
        status.reconnects = status.reconnects.saturating_add(1);
        status.last_error = Some(error.clone());
    });
    let _ = events.send(TailscaleControlSupervisorEvent::Disconnected {
        generation,
        error,
        retry_in,
    });
}

async fn sleep_or_cancel(
    duration: Duration,
    cancellation: &CancellationToken,
) -> bool {
    tokio::select! {
        _ = cancellation.cancelled() => false,
        _ = tokio::time::sleep(duration) => true,
    }
}

fn next_backoff(current: Duration, maximum: Duration) -> Duration {
    current.saturating_mul(2).min(maximum)
}

fn debug_sleep_duration(seconds: f64) -> Duration {
    const MAXIMUM: Duration = Duration::from_secs(5 * 60);
    Duration::try_from_secs_f64(seconds)
        .unwrap_or_default()
        .min(MAXIMUM)
}

fn update_status(
    status: &RwLock<TailscaleControlSupervisorStatus>,
    update: impl FnOnce(&mut TailscaleControlSupervisorStatus),
) {
    if let Ok(mut status) = status.write() {
        update(&mut status);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::{
        option::DirectOutboundOptions,
        protocol::{
            direct::DirectOutbound,
            tailscale_control_types::{
                TailscaleDiscoPublicKey, TailscaleNode, TailscaleNodePublicKey,
            },
        },
    };

    struct MemoryMapStream {
        chunks: Vec<Vec<u8>>,
    }

    #[async_trait]
    impl TailscaleControlMapStream for MemoryMapStream {
        async fn next_chunk(
            &mut self,
        ) -> Result<Option<Vec<u8>>, TailscaleControlError> {
            if self.chunks.is_empty() {
                Ok(None)
            } else {
                Ok(Some(self.chunks.remove(0)))
            }
        }
    }

    struct MemorySession {
        map: Option<Vec<Vec<u8>>>,
        cursors: Arc<Mutex<Vec<(String, i64)>>>,
    }

    #[async_trait]
    impl TailscaleControlSession for MemorySession {
        async fn register(
            &mut self,
            _request: &TailscaleRegisterRequest,
        ) -> Result<TailscaleRegisterResponse, TailscaleControlError> {
            Ok(TailscaleRegisterResponse {
                machine_authorized: true,
                ..Default::default()
            })
        }

        async fn start_map(
            &mut self,
            request: &TailscaleMapRequest,
        ) -> Result<Box<dyn TailscaleControlMapStream>, TailscaleControlError>
        {
            self.cursors.lock().unwrap().push((
                request.map_session_handle.clone(),
                request.map_session_seq,
            ));
            Ok(Box::new(MemoryMapStream {
                chunks: self.map.take().unwrap_or_default(),
            }))
        }
    }

    struct MemoryConnector {
        attempts: AtomicUsize,
        frames: Vec<Vec<u8>>,
        cursors: Arc<Mutex<Vec<(String, i64)>>>,
    }

    #[async_trait]
    impl TailscaleControlConnector for MemoryConnector {
        async fn connect(
            &self,
        ) -> Result<Box<dyn TailscaleControlSession>, TailscaleControlError>
        {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                return Err(TailscaleControlError::Io(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "first dial fails",
                )));
            }
            Ok(Box::new(MemorySession {
                map: Some(self.frames.clone()),
                cursors: self.cursors.clone(),
            }))
        }
    }

    #[derive(Default)]
    struct RecordingConsumer {
        states: Mutex<Vec<TailscaleNetmapState>>,
    }

    #[async_trait]
    impl TailscaleNetmapConsumer for RecordingConsumer {
        async fn apply_netmap(
            &self,
            netmap: &TailscaleNetmapState,
        ) -> Result<(), String> {
            self.states.lock().unwrap().push(netmap.clone());
            Ok(())
        }
    }

    fn map_frame(response: &TailscaleMapResponse) -> Vec<u8> {
        let json = serde_json::to_vec(response).unwrap();
        let compressed = zstd::bulk::compress(&json, 1).unwrap();
        let mut frame = Vec::with_capacity(4 + compressed.len());
        frame.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        frame.extend_from_slice(&compressed);
        frame
    }

    #[tokio::test]
    async fn bootstrap_fetches_modern_control_key_and_preserves_authority() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert_eq!(
                request.lines().next(),
                Some("GET /key?v=142 HTTP/1.1"),
                "unexpected bootstrap request: {request:?}"
            );
            let body = format!(
                "{{\"publicKey\":\"mkey:{}\"}}",
                hex::encode([9_u8; 32])
            );
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let bootstrap = bootstrap_tailscale_control(
            dialer,
            &format!("http://{address}/ignored"),
            142,
        )
        .await
        .unwrap();
        assert_eq!(bootstrap.authority, address.to_string());
        assert_eq!(bootstrap.destination, address.into());
        assert!(!bootstrap.tls);
        assert_eq!(bootstrap.control_public_key().unwrap(), [9; 32]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn reconnects_registers_applies_map_and_resumes_cursor() {
        let peer = TailscaleNode {
            id: 2,
            key: TailscaleNodePublicKey::from_bytes([2; 32]),
            disco_key: TailscaleDiscoPublicKey::from_bytes([3; 32]),
            allowed_ips: vec!["100.64.0.2/32".into()],
            endpoints: vec!["192.0.2.2:41641".into()],
            ..Default::default()
        };
        let response = TailscaleMapResponse {
            map_session_handle: "session-a".into(),
            sequence: 7,
            peers: Some(vec![peer]),
            ..Default::default()
        };
        let cursors = Arc::new(Mutex::new(Vec::new()));
        let connector = Arc::new(MemoryConnector {
            attempts: AtomicUsize::new(0),
            frames: vec![map_frame(&response)],
            cursors: cursors.clone(),
        });
        let consumer = Arc::new(RecordingConsumer::default());
        let supervisor = TailscaleControlSupervisor::spawn(
            connector.clone(),
            consumer.clone(),
            TailscaleRegisterRequest::default(),
            TailscaleMapRequest::default(),
            TailscaleControlSupervisorOptions {
                initial_backoff: Duration::from_millis(5),
                maximum_backoff: Duration::from_millis(10),
                ..Default::default()
            },
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if supervisor.status().map_sequence == 7
                    && cursors.lock().unwrap().len() >= 2
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(connector.attempts.load(Ordering::SeqCst) >= 3);
        assert_eq!(consumer.states.lock().unwrap()[0].peers.len(), 1);
        assert_eq!(cursors.lock().unwrap()[0], (String::new(), 0));
        assert_eq!(cursors.lock().unwrap()[1], ("session-a".into(), 7));
        assert_eq!(supervisor.status().peers, 1);
        supervisor.close().await.unwrap();
    }

    #[tokio::test]
    async fn endpoint_update_restarts_map_without_backoff() {
        type EndpointRequests = Arc<Mutex<Vec<(Vec<String>, Vec<i32>)>>>;

        struct PendingMapStream;
        #[async_trait]
        impl TailscaleControlMapStream for PendingMapStream {
            async fn next_chunk(
                &mut self,
            ) -> Result<Option<Vec<u8>>, TailscaleControlError> {
                std::future::pending().await
            }
        }
        struct EndpointSession {
            requests: EndpointRequests,
        }
        #[async_trait]
        impl TailscaleControlSession for EndpointSession {
            async fn register(
                &mut self,
                _request: &TailscaleRegisterRequest,
            ) -> Result<TailscaleRegisterResponse, TailscaleControlError>
            {
                Ok(TailscaleRegisterResponse {
                    machine_authorized: true,
                    ..Default::default()
                })
            }

            async fn start_map(
                &mut self,
                request: &TailscaleMapRequest,
            ) -> Result<Box<dyn TailscaleControlMapStream>, TailscaleControlError>
            {
                self.requests.lock().unwrap().push((
                    request.endpoints.clone(),
                    request.endpoint_types.clone(),
                ));
                Ok(Box::new(PendingMapStream))
            }
        }
        struct EndpointConnector {
            requests: EndpointRequests,
        }
        #[async_trait]
        impl TailscaleControlConnector for EndpointConnector {
            async fn connect(
                &self,
            ) -> Result<Box<dyn TailscaleControlSession>, TailscaleControlError>
            {
                Ok(Box::new(EndpointSession {
                    requests: self.requests.clone(),
                }))
            }
        }

        let requests = Arc::new(Mutex::new(Vec::new()));
        let supervisor = TailscaleControlSupervisor::spawn(
            Arc::new(EndpointConnector {
                requests: requests.clone(),
            }),
            Arc::new(RecordingConsumer::default()),
            TailscaleRegisterRequest::default(),
            TailscaleMapRequest::default(),
            TailscaleControlSupervisorOptions {
                initial_backoff: Duration::from_secs(60),
                maximum_backoff: Duration::from_secs(60),
                ..Default::default()
            },
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while requests.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        supervisor
            .update_endpoints(vec!["198.51.100.7:41641".into()], vec![2])
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while requests.lock().unwrap().len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            requests.lock().unwrap()[1],
            (vec!["198.51.100.7:41641".into()], vec![2])
        );
        assert_eq!(supervisor.status().reconnects, 0);
        supervisor.close().await.unwrap();
    }

    #[tokio::test]
    async fn follows_authorization_url_on_the_same_control_session() {
        use std::collections::VecDeque;

        struct PendingMapStream;
        #[async_trait]
        impl TailscaleControlMapStream for PendingMapStream {
            async fn next_chunk(
                &mut self,
            ) -> Result<Option<Vec<u8>>, TailscaleControlError> {
                std::future::pending().await
            }
        }

        struct FollowupSession {
            requests: Arc<Mutex<Vec<TailscaleRegisterRequest>>>,
            responses: Arc<Mutex<VecDeque<TailscaleRegisterResponse>>>,
        }
        #[async_trait]
        impl TailscaleControlSession for FollowupSession {
            async fn register(
                &mut self,
                request: &TailscaleRegisterRequest,
            ) -> Result<TailscaleRegisterResponse, TailscaleControlError>
            {
                self.requests.lock().unwrap().push(request.clone());
                Ok(self.responses.lock().unwrap().pop_front().unwrap())
            }

            async fn start_map(
                &mut self,
                _request: &TailscaleMapRequest,
            ) -> Result<Box<dyn TailscaleControlMapStream>, TailscaleControlError>
            {
                Ok(Box::new(PendingMapStream))
            }
        }

        struct FollowupConnector {
            connects: Arc<AtomicUsize>,
            requests: Arc<Mutex<Vec<TailscaleRegisterRequest>>>,
            responses: Arc<Mutex<VecDeque<TailscaleRegisterResponse>>>,
        }
        #[async_trait]
        impl TailscaleControlConnector for FollowupConnector {
            async fn connect(
                &self,
            ) -> Result<Box<dyn TailscaleControlSession>, TailscaleControlError>
            {
                self.connects.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(FollowupSession {
                    requests: self.requests.clone(),
                    responses: self.responses.clone(),
                }))
            }
        }

        let login_url = "https://login.example/followup";
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(VecDeque::from([
            TailscaleRegisterResponse {
                auth_url: login_url.into(),
                ..Default::default()
            },
            TailscaleRegisterResponse {
                machine_authorized: true,
                ..Default::default()
            },
        ])));
        let connects = Arc::new(AtomicUsize::new(0));
        let supervisor = TailscaleControlSupervisor::spawn(
            Arc::new(FollowupConnector {
                connects: connects.clone(),
                requests: requests.clone(),
                responses,
            }),
            Arc::new(RecordingConsumer::default()),
            TailscaleRegisterRequest::default(),
            TailscaleMapRequest::default(),
            TailscaleControlSupervisorOptions::default(),
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while !supervisor.status().connected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        {
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert!(requests[0].followup.is_empty());
            assert_eq!(requests[1].followup, login_url);
        }
        assert_eq!(connects.load(Ordering::SeqCst), 1);
        assert!(supervisor.status().machine_authorized);
        supervisor.close().await.unwrap();
    }

    #[tokio::test]
    async fn reports_node_key_rotation_before_starting_map() {
        struct ExpiredConnector;
        struct ExpiredSession;
        #[async_trait]
        impl TailscaleControlConnector for ExpiredConnector {
            async fn connect(
                &self,
            ) -> Result<Box<dyn TailscaleControlSession>, TailscaleControlError>
            {
                Ok(Box::new(ExpiredSession))
            }
        }
        #[async_trait]
        impl TailscaleControlSession for ExpiredSession {
            async fn register(
                &mut self,
                _request: &TailscaleRegisterRequest,
            ) -> Result<TailscaleRegisterResponse, TailscaleControlError>
            {
                Ok(TailscaleRegisterResponse {
                    node_key_signature: Some(vec![1, 2, 3]),
                    ..Default::default()
                })
            }

            async fn start_map(
                &mut self,
                _request: &TailscaleMapRequest,
            ) -> Result<Box<dyn TailscaleControlMapStream>, TailscaleControlError>
            {
                panic!("expired identity must not start map")
            }
        }

        let supervisor = TailscaleControlSupervisor::spawn(
            Arc::new(ExpiredConnector),
            Arc::new(RecordingConsumer::default()),
            TailscaleRegisterRequest::default(),
            TailscaleMapRequest::default(),
            TailscaleControlSupervisorOptions {
                initial_backoff: Duration::from_secs(60),
                maximum_backoff: Duration::from_secs(60),
                ..Default::default()
            },
        );
        let mut events = supervisor.subscribe();
        let signature = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(
                    TailscaleControlSupervisorEvent::NodeKeyRotationRequired {
                        node_key_signature,
                        ..
                    },
                ) = events.recv().await
                {
                    break node_key_signature;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(signature, Some(vec![1, 2, 3]));
        assert!(supervisor.status().node_key_expired);
        supervisor.close().await.unwrap();
    }

    #[tokio::test]
    async fn reports_authorization_url_without_starting_map() {
        struct UnauthorizedConnector;
        struct UnauthorizedSession;
        #[async_trait]
        impl TailscaleControlConnector for UnauthorizedConnector {
            async fn connect(
                &self,
            ) -> Result<Box<dyn TailscaleControlSession>, TailscaleControlError>
            {
                Ok(Box::new(UnauthorizedSession))
            }
        }
        #[async_trait]
        impl TailscaleControlSession for UnauthorizedSession {
            async fn register(
                &mut self,
                _request: &TailscaleRegisterRequest,
            ) -> Result<TailscaleRegisterResponse, TailscaleControlError>
            {
                Ok(TailscaleRegisterResponse {
                    auth_url: "https://login.example/a".into(),
                    ..Default::default()
                })
            }
            async fn start_map(
                &mut self,
                _request: &TailscaleMapRequest,
            ) -> Result<Box<dyn TailscaleControlMapStream>, TailscaleControlError>
            {
                panic!("unauthorized session must not start map")
            }
        }

        let supervisor = TailscaleControlSupervisor::spawn(
            Arc::new(UnauthorizedConnector),
            Arc::new(RecordingConsumer::default()),
            TailscaleRegisterRequest::default(),
            TailscaleMapRequest::default(),
            TailscaleControlSupervisorOptions {
                initial_backoff: Duration::from_secs(60),
                maximum_backoff: Duration::from_secs(60),
                ..Default::default()
            },
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if supervisor.status().auth_url == "https://login.example/a" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!supervisor.status().machine_authorized);
        supervisor.close().await.unwrap();
    }

    #[test]
    fn debug_sleep_is_sanitized_and_capped_like_upstream() {
        assert_eq!(debug_sleep_duration(-1.0), Duration::ZERO);
        assert_eq!(debug_sleep_duration(f64::NAN), Duration::ZERO);
        assert_eq!(debug_sleep_duration(1.5), Duration::from_millis(1500));
        assert_eq!(debug_sleep_duration(600.0), Duration::from_secs(5 * 60));
    }
}
