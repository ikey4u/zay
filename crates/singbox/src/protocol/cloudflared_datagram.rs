//! Cloudflare Tunnel UDP session multiplexing over QUIC datagrams.
//!
//! Datagram v2 creates sessions through the incoming Cap'n Proto RPC stream
//! and appends the session UUID plus type byte to every payload. Datagram v3
//! creates sessions in-band, prefixes payloads with a request ID, and keeps a
//! shared session alive while it migrates between HA edge connections.

use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{
        Arc, Mutex as StdMutex, RwLock as StdRwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio_util::{compat::TokioAsyncReadCompatExt, sync::CancellationToken};
use uuid::Uuid;

use super::{
    cloudflared::{
        CLOUDFLARED_MAX_V3_UDP_PAYLOAD, CLOUDFLARED_V3_DEFAULT_IDLE_TIMEOUT,
        CloudflaredConfigurationApplier, CloudflaredDatagramV2Type,
        CloudflaredDatagramV3Type, CloudflaredError,
        CloudflaredIncomingDatagramVersion, CloudflaredIncomingRpcServer,
        CloudflaredUdpRegistration, CloudflaredUdpSessionHandler,
        cloudflared_incoming_rpc, decode_cloudflared_datagram_v2,
        decode_cloudflared_datagram_v2_udp,
        decode_cloudflared_datagram_v3_payload,
        decode_cloudflared_datagram_v3_registration,
        encode_cloudflared_datagram_v2_udp,
        encode_cloudflared_datagram_v3_payload,
        encode_cloudflared_datagram_v3_registration_response,
    },
    cloudflared_icmp::CloudflaredIcmpBridge,
    cloudflared_ingress::CloudflaredConfigManager,
    cloudflared_quic::{
        CLOUDFLARED_REGISTRATION_TIMEOUT, CloudflaredQuicDatagramSender,
        CloudflaredQuicStream,
    },
};
use crate::{
    adapter::{Dialer, PacketConnection, Stream},
    cloudflared_tunnelrpc_capnp as tunnelrpc,
    common::network::SocksAddr,
};

pub const CLOUDFLARED_DATAGRAM_V2_QUEUE_SIZE: usize = 256;
pub const CLOUDFLARED_DATAGRAM_V3_QUEUE_SIZE: usize = 512;
pub const CLOUDFLARED_V3_RESPONSE_OK: u8 = 0x00;
pub const CLOUDFLARED_V3_RESPONSE_DESTINATION_UNREACHABLE: u8 = 0x01;
pub const CLOUDFLARED_V3_RESPONSE_UNABLE_TO_BIND_SOCKET: u8 = 0x02;
pub const CLOUDFLARED_V3_RESPONSE_TOO_MANY_ACTIVE_FLOWS: u8 = 0x03;
pub const CLOUDFLARED_V3_RESPONSE_ERROR_WITH_MESSAGE: u8 = 0xff;

#[async_trait]
pub trait CloudflaredDatagramTransport: Send + Sync + 'static {
    fn connection_id(&self) -> usize;

    fn datagram_version(&self) -> CloudflaredIncomingDatagramVersion;

    fn send_datagram(&self, datagram: Bytes) -> Result<(), CloudflaredError>;

    async fn open_rpc_stream(&self) -> Result<Stream, CloudflaredError>;

    async fn closed(&self);
}

#[async_trait]
impl CloudflaredDatagramTransport for CloudflaredQuicDatagramSender {
    fn connection_id(&self) -> usize {
        self.connection_id()
    }

    fn datagram_version(&self) -> CloudflaredIncomingDatagramVersion {
        self.datagram_version()
    }

    fn send_datagram(&self, datagram: Bytes) -> Result<(), CloudflaredError> {
        self.send_datagram(datagram)
    }

    async fn open_rpc_stream(&self) -> Result<Stream, CloudflaredError> {
        Ok(Box::new(self.open_rpc_stream().await?) as Stream)
    }

    async fn closed(&self) {
        self.wait_closed().await;
    }
}

struct DatagramSession {
    destination: SocksAddr,
    close_after_idle: Duration,
    incoming: mpsc::Sender<Vec<u8>>,
    cancellation: CancellationToken,
    last_active: StdMutex<Instant>,
    sender: StdRwLock<Arc<dyn CloudflaredDatagramTransport>>,
    connection_id: AtomicUsize,
    remote_closed: AtomicBool,
    close_reason: StdMutex<String>,
}

impl DatagramSession {
    fn new(
        destination: SocksAddr,
        close_after_idle: Duration,
        incoming: mpsc::Sender<Vec<u8>>,
        sender: Arc<dyn CloudflaredDatagramTransport>,
    ) -> Self {
        Self {
            destination,
            close_after_idle,
            incoming,
            cancellation: CancellationToken::new(),
            last_active: StdMutex::new(Instant::now()),
            connection_id: AtomicUsize::new(sender.connection_id()),
            sender: StdRwLock::new(sender),
            remote_closed: AtomicBool::new(false),
            close_reason: StdMutex::new(String::new()),
        }
    }

    fn enqueue(&self, payload: &[u8]) {
        let _ = self.incoming.try_send(payload.to_vec());
    }

    fn mark_active(&self) {
        *self
            .last_active
            .lock()
            .expect("cloudflared datagram activity lock poisoned") =
            Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.last_active
            .lock()
            .expect("cloudflared datagram activity lock poisoned")
            .elapsed()
    }

    fn sender(&self) -> Arc<dyn CloudflaredDatagramTransport> {
        self.sender
            .read()
            .expect("cloudflared datagram sender lock poisoned")
            .clone()
    }

    fn migrate(&self, sender: Arc<dyn CloudflaredDatagramTransport>) {
        self.connection_id
            .store(sender.connection_id(), Ordering::Release);
        *self
            .sender
            .write()
            .expect("cloudflared datagram sender lock poisoned") = sender;
        self.mark_active();
    }

    fn connection_id(&self) -> usize {
        self.connection_id.load(Ordering::Acquire)
    }

    fn close(&self, reason: impl Into<String>) {
        let mut close_reason = self
            .close_reason
            .lock()
            .expect("cloudflared datagram close-reason lock poisoned");
        if close_reason.is_empty() {
            *close_reason = reason.into();
        }
        drop(close_reason);
        self.cancellation.cancel();
    }

    fn close_from_edge(&self, message: &str) {
        self.remote_closed.store(true, Ordering::Release);
        self.close(if message.is_empty() {
            "unregistered by edge"
        } else {
            message
        });
    }

    fn close_reason(&self) -> String {
        let reason = self
            .close_reason
            .lock()
            .expect("cloudflared datagram close-reason lock poisoned");
        if reason.is_empty() {
            "session closed".into()
        } else {
            reason.clone()
        }
    }
}

struct ActiveDatagramFlow(Arc<AtomicU64>);

impl Drop for ActiveDatagramFlow {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V3RegistrationError {
    TooManyActiveFlows,
    UnableToBind,
}

/// UDP session state shared by every QUIC connection owned by one tunnel.
pub struct CloudflaredDatagramService {
    config: Arc<CloudflaredConfigManager>,
    dialer: Arc<dyn Dialer>,
    active_flows: Arc<AtomicU64>,
    icmp: CloudflaredIcmpBridge,
    v2_sessions: Mutex<HashMap<(usize, Uuid), Arc<DatagramSession>>>,
    v3_sessions: Mutex<HashMap<[u8; 16], Arc<DatagramSession>>>,
    watched_connections: StdMutex<HashSet<usize>>,
}

impl CloudflaredDatagramService {
    pub fn new(
        config: Arc<CloudflaredConfigManager>,
        dialer: Arc<dyn Dialer>,
        active_flows: Arc<AtomicU64>,
    ) -> Self {
        Self {
            config,
            icmp: CloudflaredIcmpBridge::new(dialer.clone()),
            dialer,
            active_flows,
            v2_sessions: Mutex::new(HashMap::new()),
            v3_sessions: Mutex::new(HashMap::new()),
            watched_connections: StdMutex::new(HashSet::new()),
        }
    }

    pub async fn v2_session_count(&self) -> usize {
        self.v2_sessions.lock().await.len()
    }

    pub async fn v3_session_count(&self) -> usize {
        self.v3_sessions.lock().await.len()
    }

    pub async fn close(&self) {
        let v2 = {
            let mut sessions = self.v2_sessions.lock().await;
            sessions
                .drain()
                .map(|(_, session)| session)
                .collect::<Vec<_>>()
        };
        let v3 = {
            let mut sessions = self.v3_sessions.lock().await;
            sessions
                .drain()
                .map(|(_, session)| session)
                .collect::<Vec<_>>()
        };
        for session in v2.into_iter().chain(v3) {
            session.close("service closed");
        }
    }

    pub async fn serve_rpc_stream(
        self: &Arc<Self>,
        stream: CloudflaredQuicStream,
        sender: CloudflaredQuicDatagramSender,
    ) {
        let version = sender.datagram_version();
        let transport: Arc<dyn CloudflaredDatagramTransport> = Arc::new(sender);
        self.watch_transport(transport.clone());
        let configuration: Arc<dyn CloudflaredConfigurationApplier> =
            self.config.clone();
        let server = match version {
            CloudflaredIncomingDatagramVersion::V2 => {
                CloudflaredIncomingRpcServer::datagram_v2(
                    configuration,
                    Arc::new(V2RpcHandler {
                        service: self.clone(),
                        transport,
                    }),
                )
            }
            CloudflaredIncomingDatagramVersion::V3 => {
                CloudflaredIncomingRpcServer::datagram_v3(configuration)
            }
        };
        let rpc =
            tokio::task::spawn_local(cloudflared_incoming_rpc(stream, server));
        let _ = rpc.await;
    }

    pub async fn handle_datagram(
        self: &Arc<Self>,
        datagram: Bytes,
        sender: CloudflaredQuicDatagramSender,
    ) {
        let transport: Arc<dyn CloudflaredDatagramTransport> = Arc::new(sender);
        self.handle_datagram_with_transport(datagram, transport)
            .await;
    }

    async fn handle_datagram_with_transport(
        self: &Arc<Self>,
        datagram: Bytes,
        transport: Arc<dyn CloudflaredDatagramTransport>,
    ) {
        self.watch_transport(transport.clone());
        match transport.datagram_version() {
            CloudflaredIncomingDatagramVersion::V2 => {
                self.handle_v2_datagram(&datagram, transport).await;
            }
            CloudflaredIncomingDatagramVersion::V3 => {
                self.handle_v3_datagram(&datagram, transport).await;
            }
        }
    }

    fn watch_transport(
        self: &Arc<Self>,
        transport: Arc<dyn CloudflaredDatagramTransport>,
    ) {
        let connection_id = transport.connection_id();
        if !self
            .watched_connections
            .lock()
            .expect("cloudflared connection-watch lock poisoned")
            .insert(connection_id)
        {
            return;
        }
        let service = Arc::downgrade(self);
        tokio::task::spawn_local(async move {
            transport.closed().await;
            if let Some(service) = service.upgrade() {
                service.connection_closed(connection_id).await;
            }
        });
    }

    async fn connection_closed(&self, connection_id: usize) {
        self.watched_connections
            .lock()
            .expect("cloudflared connection-watch lock poisoned")
            .remove(&connection_id);
        let v2 = {
            let mut sessions = self.v2_sessions.lock().await;
            let keys = sessions
                .keys()
                .filter(|(id, _)| *id == connection_id)
                .copied()
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| sessions.remove(&key))
                .collect::<Vec<_>>()
        };
        for session in v2 {
            session.close("connection closed");
        }

        let v3 = {
            let mut sessions = self.v3_sessions.lock().await;
            let keys = sessions
                .iter()
                .filter_map(|(request_id, session)| {
                    (session.connection_id() == connection_id)
                        .then_some(*request_id)
                })
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| sessions.remove(&key))
                .collect::<Vec<_>>()
        };
        for session in v3 {
            session.close("connection closed");
        }
    }

    fn acquire_flow(&self) -> Option<ActiveDatagramFlow> {
        let limit = self.config.snapshot().warp_routing.max_active_flows;
        let previous = self.active_flows.fetch_add(1, Ordering::AcqRel);
        if limit != 0 && previous >= limit {
            self.active_flows.fetch_sub(1, Ordering::AcqRel);
            None
        } else {
            Some(ActiveDatagramFlow(self.active_flows.clone()))
        }
    }

    async fn register_v2(
        self: &Arc<Self>,
        registration: CloudflaredUdpRegistration,
        transport: Arc<dyn CloudflaredDatagramTransport>,
    ) -> Result<Vec<u8>, String> {
        let key = (transport.connection_id(), registration.session_id);
        let mut sessions = self.v2_sessions.lock().await;
        if sessions.contains_key(&key) {
            return Ok(Vec::new());
        }
        let flow = self
            .acquire_flow()
            .ok_or_else(|| "too many active flows".to_owned())?;
        let origin = self
            .dialer
            .listen_udp(&registration.destination.into())
            .await
            .map_err(|error| error.to_string())?;
        let close_after_idle =
            v2_idle_duration(registration.close_after_idle_nanos);
        let (incoming, receiver) =
            mpsc::channel(CLOUDFLARED_DATAGRAM_V2_QUEUE_SIZE);
        let session = Arc::new(DatagramSession::new(
            registration.destination.into(),
            close_after_idle,
            incoming,
            transport,
        ));
        sessions.insert(key, session.clone());
        drop(sessions);

        let service = self.clone();
        tokio::task::spawn_local(async move {
            service
                .run_v2_session(key, session, origin, receiver, flow)
                .await;
        });
        Ok(Vec::new())
    }

    async fn unregister_v2(
        &self,
        connection_id: usize,
        session_id: Uuid,
        message: &str,
    ) {
        if let Some(session) = self
            .v2_sessions
            .lock()
            .await
            .remove(&(connection_id, session_id))
        {
            session.close_from_edge(message);
        }
    }

    async fn handle_v2_datagram(
        &self,
        datagram: &[u8],
        transport: Arc<dyn CloudflaredDatagramTransport>,
    ) {
        let Ok(datagram) = decode_cloudflared_datagram_v2(datagram) else {
            return;
        };
        if matches!(
            datagram.datagram_type,
            CloudflaredDatagramV2Type::Ip
                | CloudflaredDatagramV2Type::IpWithTrace
        ) {
            let _ = self
                .icmp
                .handle_v2(
                    datagram.datagram_type,
                    datagram.payload,
                    transport.as_ref(),
                )
                .await;
            return;
        }
        if datagram.datagram_type != CloudflaredDatagramV2Type::Udp {
            return;
        }
        let Ok((session_id, payload)) =
            decode_cloudflared_datagram_v2_udp(datagram.payload)
        else {
            return;
        };
        if let Some(session) = self
            .v2_sessions
            .lock()
            .await
            .get(&(transport.connection_id(), session_id))
            .cloned()
        {
            session.enqueue(payload);
        }
    }

    async fn run_v2_session(
        self: Arc<Self>,
        key: (usize, Uuid),
        session: Arc<DatagramSession>,
        origin: Box<dyn PacketConnection>,
        receiver: mpsc::Receiver<Vec<u8>>,
        _flow: ActiveDatagramFlow,
    ) {
        let origin: Arc<dyn PacketConnection> = Arc::from(origin);
        run_udp_session(
            session.clone(),
            origin,
            receiver,
            DatagramWire::V2(key.1),
        )
        .await;
        let mut sessions = self.v2_sessions.lock().await;
        if sessions
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, &session))
        {
            sessions.remove(&key);
        }
        drop(sessions);
        if !session.remote_closed.load(Ordering::Acquire) {
            let _ = unregister_remote_v2(
                session.sender(),
                key.1,
                &session.close_reason(),
            )
            .await;
        }
    }

    async fn handle_v3_datagram(
        self: &Arc<Self>,
        datagram: &[u8],
        transport: Arc<dyn CloudflaredDatagramTransport>,
    ) {
        match datagram.first().copied() {
            Some(value)
                if value == CloudflaredDatagramV3Type::Registration as u8 =>
            {
                self.handle_v3_registration(datagram, transport).await;
            }
            Some(value)
                if value == CloudflaredDatagramV3Type::Payload as u8 =>
            {
                let Ok((request_id, payload)) =
                    decode_cloudflared_datagram_v3_payload(datagram)
                else {
                    return;
                };
                if let Some(session) =
                    self.v3_sessions.lock().await.get(&request_id).cloned()
                {
                    session.enqueue(payload);
                }
            }
            Some(value) if value == CloudflaredDatagramV3Type::Icmp as u8 => {
                let _ = self
                    .icmp
                    .handle_v3(&datagram[1..], transport.as_ref())
                    .await;
            }
            // Unexpected registration responses are deliberately ignored.
            _ => {}
        }
    }

    async fn handle_v3_registration(
        self: &Arc<Self>,
        datagram: &[u8],
        transport: Arc<dyn CloudflaredDatagramTransport>,
    ) {
        // Type + flags/port/idle/request ID. The Go implementation silently
        // drops frames that cannot identify a request.
        let Some(header) = datagram.get(..22) else {
            return;
        };
        let flags = header[1];
        let request_id: [u8; 16] = header[6..22]
            .try_into()
            .expect("fixed cloudflared request ID");
        let address_length = if flags & 0x01 != 0 { 16 } else { 4 };
        if datagram.len() < 22 + address_length {
            let family = if address_length == 16 { "IPv6" } else { "IPv4" };
            send_v3_registration_response(
                transport.as_ref(),
                request_id,
                CLOUDFLARED_V3_RESPONSE_ERROR_WITH_MESSAGE,
                &format!("registration too short for {family}"),
            );
            return;
        }
        let registration =
            match decode_cloudflared_datagram_v3_registration(datagram) {
                Ok(registration) => registration,
                Err(CloudflaredError::InvalidRegistrationDestination) => {
                    send_v3_registration_response(
                        transport.as_ref(),
                        request_id,
                        CLOUDFLARED_V3_RESPONSE_DESTINATION_UNREACHABLE,
                        "",
                    );
                    return;
                }
                Err(_) => return,
            };
        let bundled_payload = registration.bundled_payload.to_vec();
        match self
            .register_v3(
                registration.request_id,
                registration.destination.into(),
                registration.close_after_idle,
                transport.clone(),
            )
            .await
        {
            Ok(session) => {
                send_v3_registration_response(
                    transport.as_ref(),
                    registration.request_id,
                    CLOUDFLARED_V3_RESPONSE_OK,
                    "",
                );
                if !bundled_payload.is_empty() {
                    session.enqueue(&bundled_payload);
                }
            }
            Err(V3RegistrationError::TooManyActiveFlows) => {
                send_v3_registration_response(
                    transport.as_ref(),
                    registration.request_id,
                    CLOUDFLARED_V3_RESPONSE_TOO_MANY_ACTIVE_FLOWS,
                    "",
                );
            }
            Err(V3RegistrationError::UnableToBind) => {
                send_v3_registration_response(
                    transport.as_ref(),
                    registration.request_id,
                    CLOUDFLARED_V3_RESPONSE_UNABLE_TO_BIND_SOCKET,
                    "",
                );
            }
        }
    }

    async fn register_v3(
        self: &Arc<Self>,
        request_id: [u8; 16],
        destination: SocksAddr,
        close_after_idle: Duration,
        transport: Arc<dyn CloudflaredDatagramTransport>,
    ) -> Result<Arc<DatagramSession>, V3RegistrationError> {
        let mut sessions = self.v3_sessions.lock().await;
        if let Some(session) = sessions.get(&request_id).cloned() {
            session.migrate(transport);
            return Ok(session);
        }
        let flow = self
            .acquire_flow()
            .ok_or(V3RegistrationError::TooManyActiveFlows)?;
        let origin = self
            .dialer
            .listen_udp(&destination)
            .await
            .map_err(|_| V3RegistrationError::UnableToBind)?;
        let (incoming, receiver) =
            mpsc::channel(CLOUDFLARED_DATAGRAM_V3_QUEUE_SIZE);
        let session = Arc::new(DatagramSession::new(
            destination,
            close_after_idle,
            incoming,
            transport,
        ));
        sessions.insert(request_id, session.clone());
        drop(sessions);

        let service = self.clone();
        let task_session = session.clone();
        tokio::task::spawn_local(async move {
            service
                .run_v3_session(
                    request_id,
                    task_session,
                    origin,
                    receiver,
                    flow,
                )
                .await;
        });
        Ok(session)
    }

    async fn run_v3_session(
        self: Arc<Self>,
        request_id: [u8; 16],
        session: Arc<DatagramSession>,
        origin: Box<dyn PacketConnection>,
        receiver: mpsc::Receiver<Vec<u8>>,
        _flow: ActiveDatagramFlow,
    ) {
        let origin: Arc<dyn PacketConnection> = Arc::from(origin);
        run_udp_session(
            session.clone(),
            origin,
            receiver,
            DatagramWire::V3(request_id),
        )
        .await;
        let mut sessions = self.v3_sessions.lock().await;
        if sessions
            .get(&request_id)
            .is_some_and(|current| Arc::ptr_eq(current, &session))
        {
            sessions.remove(&request_id);
        }
    }
}

struct V2RpcHandler {
    service: Arc<CloudflaredDatagramService>,
    transport: Arc<dyn CloudflaredDatagramTransport>,
}

#[async_trait]
impl CloudflaredUdpSessionHandler for V2RpcHandler {
    async fn register_udp_session(
        &self,
        registration: CloudflaredUdpRegistration,
    ) -> Result<Vec<u8>, String> {
        self.service
            .register_v2(registration, self.transport.clone())
            .await
    }

    async fn unregister_udp_session(&self, session_id: Uuid, message: &str) {
        self.service
            .unregister_v2(self.transport.connection_id(), session_id, message)
            .await;
    }
}

enum DatagramWire {
    V2(Uuid),
    V3([u8; 16]),
}

async fn run_udp_session(
    session: Arc<DatagramSession>,
    origin: Arc<dyn PacketConnection>,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    wire: DatagramWire,
) {
    let tick_interval = idle_tick_interval(session.close_after_idle);
    let mut ticker = tokio::time::interval(tick_interval);
    ticker.tick().await;
    let mut response = vec![0_u8; u16::MAX as usize + 1];
    loop {
        tokio::select! {
            _ = session.cancellation.cancelled() => break,
            _ = ticker.tick() => {
                if session.idle_for() >= session.close_after_idle {
                    session.close("idle timeout");
                }
            }
            payload = incoming.recv() => {
                let Some(payload) = payload else {
                    session.close("session input closed");
                    continue;
                };
                match origin.send_to(&payload, &session.destination).await {
                    Ok(_) => session.mark_active(),
                    Err(error)
                        if matches!(wire, DatagramWire::V3(_))
                            && error.kind() == io::ErrorKind::TimedOut => {}
                    Err(error) => session.close(error.to_string()),
                }
            }
            result = origin.recv_from(&mut response) => {
                match result {
                    Ok((length, _)) => {
                        if matches!(wire, DatagramWire::V3(_))
                            && length > CLOUDFLARED_MAX_V3_UDP_PAYLOAD
                        {
                            continue;
                        }
                        session.mark_active();
                        let sender = session.sender();
                        let encoded = match wire {
                            DatagramWire::V2(session_id) => {
                                Ok(encode_cloudflared_datagram_v2_udp(
                                    session_id,
                                    &response[..length],
                                ))
                            }
                            DatagramWire::V3(request_id) => {
                                encode_cloudflared_datagram_v3_payload(
                                    request_id,
                                    &response[..length],
                                )
                            }
                        };
                        match encoded.and_then(|frame| {
                            sender.send_datagram(Bytes::from(frame))
                        }) {
                            Ok(()) => {}
                            Err(error) if matches!(wire, DatagramWire::V2(_)) => {
                                let _ = error;
                            }
                            Err(error) => session.close(error.to_string()),
                        }
                    }
                    Err(error) => session.close(error.to_string()),
                }
            }
        }
    }
}

fn v2_idle_duration(nanos: i64) -> Duration {
    if nanos == 0 {
        CLOUDFLARED_V3_DEFAULT_IDLE_TIMEOUT
    } else if nanos < 0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(nanos as u64)
    }
}

fn idle_tick_interval(close_after_idle: Duration) -> Duration {
    let half = close_after_idle / 2;
    if half.is_zero() || half > Duration::from_secs(10) {
        Duration::from_secs(1)
    } else {
        half
    }
}

fn send_v3_registration_response(
    transport: &dyn CloudflaredDatagramTransport,
    request_id: [u8; 16],
    response_type: u8,
    error_message: &str,
) {
    if let Ok(response) = encode_cloudflared_datagram_v3_registration_response(
        request_id,
        response_type,
        error_message,
    ) {
        let _ = transport.send_datagram(Bytes::from(response));
    }
}

async fn unregister_remote_v2(
    transport: Arc<dyn CloudflaredDatagramTransport>,
    session_id: Uuid,
    message: &str,
) -> Result<(), CloudflaredError> {
    let stream = transport.open_rpc_stream().await?;
    let (reader, writer) = futures::io::AsyncReadExt::split(stream.compat());
    let network = Box::new(capnp_rpc::twoparty::VatNetwork::new(
        futures::io::BufReader::new(reader),
        futures::io::BufWriter::new(writer),
        capnp_rpc::rpc_twoparty_capnp::Side::Client,
        capnp::message::ReaderOptions::new(),
    ));
    let mut rpc = capnp_rpc::RpcSystem::new(network, None);
    let client = rpc.bootstrap::<tunnelrpc::session_manager::Client>(
        capnp_rpc::rpc_twoparty_capnp::Side::Server,
    );
    let rpc_task = tokio::task::spawn_local(rpc);
    let result =
        tokio::time::timeout(CLOUDFLARED_REGISTRATION_TIMEOUT, async {
            let mut request = client.unregister_udp_session_request();
            request.get().set_session_id(session_id.as_bytes());
            request.get().set_message(message);
            request
                .send()
                .promise
                .await
                .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|_| {
            CloudflaredError::Transport(
                "unregister UDP session timed out".into(),
            )
        })?;
    rpc_task.abort();
    result
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU8;

    use super::*;
    use crate::adapter::{DialFuture, PacketFuture, PacketStream};

    type CapturedPacket = (Vec<u8>, SocksAddr);
    type MemoryPacketParts = (
        PacketStream,
        mpsc::UnboundedReceiver<CapturedPacket>,
        mpsc::UnboundedSender<CapturedPacket>,
    );

    struct MemoryDialer {
        packets: StdMutex<Vec<PacketStream>>,
    }

    impl Dialer for MemoryDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async {
                Err(io::Error::new(io::ErrorKind::Unsupported, "TCP not used"))
            })
        }

        fn listen_udp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> PacketFuture<'a, PacketStream> {
            Box::pin(async move {
                self.packets
                    .lock()
                    .expect("packet dialer lock poisoned")
                    .pop()
                    .ok_or_else(|| io::Error::other("no packet connection"))
            })
        }
    }

    struct MemoryPacket {
        writes: mpsc::UnboundedSender<(Vec<u8>, SocksAddr)>,
        reads: Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocksAddr)>>,
    }

    impl PacketConnection for MemoryPacket {
        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            destination: &'a SocksAddr,
        ) -> PacketFuture<'a, usize> {
            Box::pin(async move {
                self.writes
                    .send((data.to_vec(), destination.clone()))
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "closed")
                    })?;
                Ok(data.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            data: &'a mut [u8],
        ) -> PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(async move {
                let (packet, source) =
                    self.reads.lock().await.recv().await.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "closed")
                    })?;
                data[..packet.len()].copy_from_slice(&packet);
                Ok((packet.len(), source))
            })
        }
    }

    struct MockTransport {
        id: usize,
        version: CloudflaredIncomingDatagramVersion,
        sent: StdMutex<Vec<Vec<u8>>>,
        closed: CancellationToken,
        fail_send: AtomicBool,
        open_count: AtomicU8,
    }

    impl MockTransport {
        fn new(id: usize, version: CloudflaredIncomingDatagramVersion) -> Self {
            Self {
                id,
                version,
                sent: StdMutex::new(Vec::new()),
                closed: CancellationToken::new(),
                fail_send: AtomicBool::new(false),
                open_count: AtomicU8::new(0),
            }
        }

        fn take_sent(&self) -> Vec<Vec<u8>> {
            std::mem::take(
                &mut *self.sent.lock().expect("transport lock poisoned"),
            )
        }
    }

    #[async_trait]
    impl CloudflaredDatagramTransport for MockTransport {
        fn connection_id(&self) -> usize {
            self.id
        }

        fn datagram_version(&self) -> CloudflaredIncomingDatagramVersion {
            self.version
        }

        fn send_datagram(
            &self,
            datagram: Bytes,
        ) -> Result<(), CloudflaredError> {
            if self.fail_send.load(Ordering::Acquire) {
                return Err(CloudflaredError::Transport("send failed".into()));
            }
            self.sent
                .lock()
                .expect("transport lock poisoned")
                .push(datagram.to_vec());
            Ok(())
        }

        async fn open_rpc_stream(&self) -> Result<Stream, CloudflaredError> {
            self.open_count.fetch_add(1, Ordering::AcqRel);
            Err(CloudflaredError::Transport("connection closed".into()))
        }

        async fn closed(&self) {
            self.closed.cancelled().await;
        }
    }

    fn memory_packet() -> MemoryPacketParts {
        let (write_sender, write_receiver) = mpsc::unbounded_channel();
        let (read_sender, read_receiver) = mpsc::unbounded_channel();
        (
            Box::new(MemoryPacket {
                writes: write_sender,
                reads: Mutex::new(read_receiver),
            }),
            write_receiver,
            read_sender,
        )
    }

    fn service(
        packets: Vec<PacketStream>,
    ) -> (Arc<CloudflaredDatagramService>, Arc<AtomicU64>) {
        let config = Arc::new(CloudflaredConfigManager::new());
        let active = Arc::new(AtomicU64::new(0));
        let service = Arc::new(CloudflaredDatagramService::new(
            config,
            Arc::new(MemoryDialer {
                packets: StdMutex::new(packets),
            }),
            active.clone(),
        ));
        (service, active)
    }

    async fn wait_until(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("condition timed out");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn v2_rpc_session_routes_udp_both_directions_and_remote_close() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (packet, mut origin_writes, origin_reads) = memory_packet();
                let (service, active) = service(vec![packet]);
                let transport = Arc::new(MockTransport::new(
                    7,
                    CloudflaredIncomingDatagramVersion::V2,
                ));
                let session_id = Uuid::from_u128(9);
                service
                    .register_v2(
                        CloudflaredUdpRegistration {
                            session_id,
                            destination: "192.0.2.1:53".parse().unwrap(),
                            close_after_idle_nanos: 5_000_000_000,
                            trace_context: String::new(),
                        },
                        transport.clone(),
                    )
                    .await
                    .unwrap();
                assert_eq!(active.load(Ordering::Acquire), 1);

                service
                    .handle_v2_datagram(
                        &encode_cloudflared_datagram_v2_udp(
                            session_id,
                            b"edge packet",
                        ),
                        transport.clone(),
                    )
                    .await;
                let (payload, destination) =
                    origin_writes.recv().await.unwrap();
                assert_eq!(payload, b"edge packet");
                assert_eq!(destination, SocksAddr::new("192.0.2.1", 53));

                origin_reads
                    .send((
                        b"origin packet".to_vec(),
                        SocksAddr::new("192.0.2.1", 53),
                    ))
                    .unwrap();
                wait_until(|| !transport.sent.lock().unwrap().is_empty()).await;
                let sent = transport.take_sent();
                let frame = decode_cloudflared_datagram_v2(&sent[0]).unwrap();
                let (reply_session, payload) =
                    decode_cloudflared_datagram_v2_udp(frame.payload).unwrap();
                assert_eq!(reply_session, session_id);
                assert_eq!(payload, b"origin packet");

                service.unregister_v2(7, session_id, "edge close").await;
                wait_until(|| active.load(Ordering::Acquire) == 0).await;
                assert_eq!(service.v2_session_count().await, 0);
                assert_eq!(transport.open_count.load(Ordering::Acquire), 0);
            })
            .await;
    }

    fn v3_registration(
        request_id: [u8; 16],
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame =
            vec![CloudflaredDatagramV3Type::Registration as u8, flags];
        frame.extend_from_slice(&53_u16.to_be_bytes());
        frame.extend_from_slice(&30_u16.to_be_bytes());
        frame.extend_from_slice(&request_id);
        frame.extend_from_slice(&[192, 0, 2, 8]);
        frame.extend_from_slice(payload);
        frame
    }

    #[tokio::test(flavor = "current_thread")]
    async fn v3_session_migrates_between_connections_and_keeps_origin() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (packet, mut origin_writes, origin_reads) = memory_packet();
                let (service, active) = service(vec![packet]);
                let first = Arc::new(MockTransport::new(
                    1,
                    CloudflaredIncomingDatagramVersion::V3,
                ));
                let second = Arc::new(MockTransport::new(
                    2,
                    CloudflaredIncomingDatagramVersion::V3,
                ));
                let request_id = [0x44; 16];
                service
                    .handle_datagram_with_transport(
                        Bytes::from(v3_registration(
                            request_id, 0x04, b"bundled",
                        )),
                        first.clone(),
                    )
                    .await;
                assert_eq!(active.load(Ordering::Acquire), 1);
                assert_eq!(first.take_sent()[0][1], CLOUDFLARED_V3_RESPONSE_OK);
                assert_eq!(origin_writes.recv().await.unwrap().0, b"bundled");

                service
                    .handle_datagram_with_transport(
                        Bytes::from(v3_registration(request_id, 0, b"")),
                        second.clone(),
                    )
                    .await;
                assert_eq!(
                    second.take_sent()[0][1],
                    CLOUDFLARED_V3_RESPONSE_OK
                );
                first.closed.cancel();
                tokio::task::yield_now().await;
                assert_eq!(service.v3_session_count().await, 1);

                origin_reads
                    .send((b"reply".to_vec(), SocksAddr::new("192.0.2.8", 53)))
                    .unwrap();
                wait_until(|| !second.sent.lock().unwrap().is_empty()).await;
                let reply = second.take_sent();
                assert_eq!(
                    decode_cloudflared_datagram_v3_payload(&reply[0]).unwrap(),
                    (request_id, b"reply".as_slice())
                );

                let payload = encode_cloudflared_datagram_v3_payload(
                    request_id,
                    b"after migration",
                )
                .unwrap();
                service
                    .handle_datagram_with_transport(
                        Bytes::from(payload),
                        second.clone(),
                    )
                    .await;
                assert_eq!(
                    origin_writes.recv().await.unwrap().0,
                    b"after migration"
                );
                second.closed.cancel();
                wait_until(|| active.load(Ordering::Acquire) == 0).await;
                assert_eq!(service.v3_session_count().await, 0);
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn v3_registration_reports_invalid_destination_and_flow_limit() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (packet, _origin_writes, _origin_reads) = memory_packet();
                let config = Arc::new(CloudflaredConfigManager::new());
                config.apply(
                    1,
                    br#"{"ingress":[{"service":"http_status:503"}],"warp-routing":{"enabled":true,"maxActiveFlows":1}}"#,
                );
                let active = Arc::new(AtomicU64::new(1));
                let service = Arc::new(CloudflaredDatagramService::new(
                    config,
                    Arc::new(MemoryDialer {
                        packets: StdMutex::new(vec![packet]),
                    }),
                    active,
                ));
                let transport = Arc::new(MockTransport::new(
                    3,
                    CloudflaredIncomingDatagramVersion::V3,
                ));
                let request_id = [0x55; 16];
                let mut invalid = v3_registration(request_id, 0, b"");
                invalid[2] = 0;
                invalid[3] = 0;
                service
                    .handle_datagram_with_transport(
                        Bytes::from(invalid),
                        transport.clone(),
                    )
                    .await;
                assert_eq!(
                    transport.take_sent()[0][1],
                    CLOUDFLARED_V3_RESPONSE_DESTINATION_UNREACHABLE
                );

                service
                    .handle_datagram_with_transport(
                        Bytes::from(v3_registration(request_id, 0, b"")),
                        transport.clone(),
                    )
                    .await;
                assert_eq!(
                    transport.take_sent()[0][1],
                    CLOUDFLARED_V3_RESPONSE_TOO_MANY_ACTIVE_FLOWS
                );
            })
            .await;
    }
}
