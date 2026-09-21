//! Socket-owning Tailscale disco and direct WireGuard path actor.
//!
//! The actor joins the authenticated disco codec, peer path-quality state and
//! multi-region DERP manager without imposing a process or CLI boundary. A
//! caller may bind a native UDP socket or inject any singbox packet dialer.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::MissedTickBehavior,
};
use tokio_util::sync::CancellationToken;

use super::{
    tailscale::{
        TAILSCALE_DERP_KEY_LENGTH, TAILSCALE_DERP_MAX_PACKET_SIZE,
        TailscaleDerpError, TailscaleDerpReceivedMessage,
    },
    tailscale_derp_manager::{TailscaleDerpManager, TailscaleDerpManagerEvent},
    tailscale_derp_supervisor::{
        TailscaleDerpConnector, TailscaleDerpRegionEvent,
    },
    tailscale_disco::{
        TAILSCALE_DISCO_KEY_LENGTH, TailscaleDiscoCallMeMaybe,
        TailscaleDiscoError, TailscaleDiscoMessage, TailscaleDiscoPacket,
        TailscaleDiscoPing, TailscaleDiscoPong,
        looks_like_tailscale_disco_packet, open_tailscale_disco_packet,
        seal_tailscale_disco_packet, tailscale_disco_public_key,
    },
    tailscale_path::{
        TAILSCALE_PATH_HEARTBEAT_INTERVAL, TAILSCALE_PATH_SAFE_WIRE_MTU,
        TAILSCALE_PATH_SESSION_ACTIVE_TIMEOUT, TailscaleDiscoTransactionId,
        TailscalePathEndpointSnapshot, TailscalePathQuality,
        TailscalePeerPathState,
    },
};
use crate::{
    adapter::{PacketConnection, PacketFuture},
    common::{
        network::SocksAddr,
        stun::{
            TransactionId, build_binding_request_message,
            mapped_address_from_response, transaction_id_from_message,
        },
    },
};

const COMMAND_QUEUE_DEPTH: usize = 32;
const EVENT_QUEUE_DEPTH: usize = 32;
const DERP_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Error)]
pub enum TailscaleDiscoSocketError {
    #[error("Tailscale disco socket I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Disco(#[from] TailscaleDiscoError),
    #[error(transparent)]
    Derp(#[from] TailscaleDerpError),
    #[error("unknown Tailscale peer")]
    UnknownPeer,
    #[error("Tailscale disco socket command queue is full")]
    CommandQueueFull,
    #[error("Tailscale disco socket is closed")]
    Closed,
    #[error("Tailscale packet has no usable direct or DERP path")]
    NoPath,
    #[error("Tailscale disco socket has no DERP manager")]
    NoDerpManager,
    #[error("Tailscale packet is larger than the DERP maximum")]
    PacketTooLarge,
    #[error("Tailscale STUN binding timed out")]
    StunTimeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDiscoPeer {
    pub node_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    pub disco_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
    pub home_derp_region: Option<u32>,
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDiscoSocketOptions {
    pub node_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    pub disco_private_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
    pub advertised_endpoints: Vec<SocketAddr>,
    pub heartbeat_interval: Duration,
    pub derp_event_poll_interval: Duration,
}

impl TailscaleDiscoSocketOptions {
    pub fn new(
        node_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
        disco_private_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
    ) -> Self {
        Self {
            node_key,
            disco_private_key,
            advertised_endpoints: Vec::new(),
            heartbeat_interval: TAILSCALE_PATH_HEARTBEAT_INTERVAL,
            derp_event_poll_interval: DERP_EVENT_POLL_INTERVAL,
        }
    }

    fn normalized(mut self) -> Self {
        if self.heartbeat_interval.is_zero() {
            self.heartbeat_interval = TAILSCALE_PATH_HEARTBEAT_INTERVAL;
        }
        if self.derp_event_poll_interval.is_zero() {
            self.derp_event_poll_interval = DERP_EVENT_POLL_INTERVAL;
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscalePacketPath {
    Direct(SocketAddr),
    Derp { region_id: u32 },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscalePacketSendOutcome {
    pub sent_direct: bool,
    pub derp_region: Option<u32>,
    pub discovery_started: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscalePeerPathSnapshot {
    pub peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
    pub best: Option<TailscalePathQuality>,
    pub trust_best_until: Option<Instant>,
    pub endpoints: Vec<TailscalePathEndpointSnapshot>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleDiscoSocketStatus {
    pub peers: usize,
    pub sent_direct_packets: u64,
    pub sent_derp_packets: u64,
    pub received_direct_packets: u64,
    pub received_derp_packets: u64,
    pub dropped_events: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleDiscoSocketEvent {
    WireguardPacket {
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
        packet: Vec<u8>,
        path: TailscalePacketPath,
    },
    DiscoMessage {
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
        message: TailscaleDiscoMessage,
        path: TailscalePacketPath,
    },
    PathChanged {
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
        best: Option<TailscalePathQuality>,
    },
    Derp(TailscaleDerpManagerEvent),
    Error(String),
}

enum SocketCommand {
    SetPeer(TailscaleDiscoPeer),
    RemovePeer([u8; TAILSCALE_DERP_KEY_LENGTH]),
    SetAdvertisedEndpoints(Vec<SocketAddr>),
    StunBinding {
        server: SocketAddr,
        transaction_id: TransactionId,
        result: oneshot::Sender<Result<SocketAddr, TailscaleDiscoSocketError>>,
    },
    Probe([u8; TAILSCALE_DERP_KEY_LENGTH]),
    ConnectivityChanged,
    SetDerpRegion {
        region_id: u32,
        connector: Arc<dyn TailscaleDerpConnector>,
        result: oneshot::Sender<Result<(), TailscaleDiscoSocketError>>,
    },
    RemoveDerpRegion {
        region_id: u32,
        result: oneshot::Sender<Result<(), TailscaleDiscoSocketError>>,
    },
    SetHomeDerpRegion {
        region_id: Option<u32>,
        result: oneshot::Sender<Result<(), TailscaleDiscoSocketError>>,
    },
    SendWireguard {
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
        packet: Vec<u8>,
        result: oneshot::Sender<
            Result<TailscalePacketSendOutcome, TailscaleDiscoSocketError>,
        >,
    },
    PeerPath {
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
        result: oneshot::Sender<Option<TailscalePeerPathSnapshot>>,
    },
}

struct PeerRuntime {
    config: TailscaleDiscoPeer,
    paths: TailscalePeerPathState,
    last_external_send: Option<Instant>,
}

pub struct TailscaleDiscoSocket {
    commands: mpsc::Sender<SocketCommand>,
    events: mpsc::Receiver<TailscaleDiscoSocketEvent>,
    status: Arc<RwLock<TailscaleDiscoSocketStatus>>,
    local_addr: Option<SocketAddr>,
    local_addrs: Vec<SocketAddr>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct TailscaleDiscoSocketHandle {
    commands: mpsc::Sender<SocketCommand>,
    status: Arc<RwLock<TailscaleDiscoSocketStatus>>,
    local_addr: Option<SocketAddr>,
    local_addrs: Vec<SocketAddr>,
}

struct PendingStunBinding {
    server: SocketAddr,
    result: oneshot::Sender<Result<SocketAddr, TailscaleDiscoSocketError>>,
}

impl TailscaleDiscoSocket {
    pub async fn bind(
        bind: SocketAddr,
        derp_manager: Option<TailscaleDerpManager>,
        options: TailscaleDiscoSocketOptions,
    ) -> Result<Self, TailscaleDiscoSocketError> {
        let packet = Arc::new(TokioUdpPacketConnection {
            socket: UdpSocket::bind(bind).await?,
        });
        Self::spawn(packet, derp_manager, options)
    }

    /// Bind separate IPv4 and IPv6-only sockets on one UDP port. IPv6 is an
    /// optional capability so hosts without an IPv6 stack retain IPv4 service.
    pub async fn bind_dual_stack(
        port: u16,
        derp_manager: Option<TailscaleDerpManager>,
        options: TailscaleDiscoSocketOptions,
    ) -> Result<Self, TailscaleDiscoSocketError> {
        let ipv4 =
            UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
        let port = ipv4.local_addr()?.port();
        let ipv6 = bind_ipv6_udp(port).ok();
        let mut local_addrs = vec![ipv4.local_addr()?];
        if let Some(ipv6) = &ipv6 {
            local_addrs.push(ipv6.local_addr()?);
        }
        let packet = Arc::new(TokioDualStackUdpPacketConnection { ipv4, ipv6 });
        Self::spawn_with_local_addrs(packet, derp_manager, options, local_addrs)
    }

    pub fn spawn(
        packet: Arc<dyn PacketConnection>,
        derp_manager: Option<TailscaleDerpManager>,
        options: TailscaleDiscoSocketOptions,
    ) -> Result<Self, TailscaleDiscoSocketError> {
        let local_addr = packet.local_addr()?;
        let local_addrs = local_addr.into_iter().collect();
        Self::spawn_with_local_addrs(packet, derp_manager, options, local_addrs)
    }

    fn spawn_with_local_addrs(
        packet: Arc<dyn PacketConnection>,
        derp_manager: Option<TailscaleDerpManager>,
        options: TailscaleDiscoSocketOptions,
        local_addrs: Vec<SocketAddr>,
    ) -> Result<Self, TailscaleDiscoSocketError> {
        tailscale_disco_public_key(options.disco_private_key)?;
        if options.node_key == [0; TAILSCALE_DERP_KEY_LENGTH] {
            return Err(TailscaleDiscoSocketError::UnknownPeer);
        }
        let options = options.normalized();
        let local_addr = local_addrs.first().copied();
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE_DEPTH);
        let status =
            Arc::new(RwLock::new(TailscaleDiscoSocketStatus::default()));
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run_socket(
            packet,
            derp_manager,
            options,
            commands_rx,
            events_tx,
            status.clone(),
            cancellation.clone(),
        ));
        Ok(Self {
            commands: commands_tx,
            events: events_rx,
            status,
            local_addr,
            local_addrs,
            cancellation,
            task: Some(task),
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local_addrs
    }

    pub fn handle(&self) -> TailscaleDiscoSocketHandle {
        TailscaleDiscoSocketHandle {
            commands: self.commands.clone(),
            status: self.status.clone(),
            local_addr: self.local_addr,
            local_addrs: self.local_addrs.clone(),
        }
    }

    pub fn set_peer(
        &self,
        peer: TailscaleDiscoPeer,
    ) -> Result<(), TailscaleDiscoSocketError> {
        validate_peer(&peer)?;
        self.try_command(SocketCommand::SetPeer(peer))
    }

    /// Queue a peer update with bounded backpressure.
    ///
    /// This form is intended for full netmap replacement, where a tailnet can
    /// legitimately contain more peers than the actor's short burst queue.
    pub async fn set_peer_async(
        &self,
        peer: TailscaleDiscoPeer,
    ) -> Result<(), TailscaleDiscoSocketError> {
        validate_peer(&peer)?;
        self.commands
            .send(SocketCommand::SetPeer(peer))
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)
    }

    pub fn remove_peer(
        &self,
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
    ) -> Result<(), TailscaleDiscoSocketError> {
        self.try_command(SocketCommand::RemovePeer(peer))
    }

    /// Queue a peer removal with bounded backpressure.
    pub async fn remove_peer_async(
        &self,
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
    ) -> Result<(), TailscaleDiscoSocketError> {
        self.commands
            .send(SocketCommand::RemovePeer(peer))
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)
    }

    pub fn set_advertised_endpoints(
        &self,
        endpoints: Vec<SocketAddr>,
    ) -> Result<(), TailscaleDiscoSocketError> {
        self.try_command(SocketCommand::SetAdvertisedEndpoints(endpoints))
    }

    pub fn probe_peer(
        &self,
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
    ) -> Result<(), TailscaleDiscoSocketError> {
        self.try_command(SocketCommand::Probe(peer))
    }

    /// Queue a discovery probe with bounded backpressure.
    pub async fn probe_peer_async(
        &self,
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
    ) -> Result<(), TailscaleDiscoSocketError> {
        self.commands
            .send(SocketCommand::Probe(peer))
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)
    }

    pub fn note_connectivity_change(
        &self,
    ) -> Result<(), TailscaleDiscoSocketError> {
        self.try_command(SocketCommand::ConnectivityChanged)
    }

    pub async fn set_derp_region(
        &self,
        region_id: u32,
        connector: Arc<dyn TailscaleDerpConnector>,
    ) -> Result<(), TailscaleDiscoSocketError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(SocketCommand::SetDerpRegion {
                region_id,
                connector,
                result: result_tx,
            })
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)?;
        result_rx
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)?
    }

    pub async fn remove_derp_region(
        &self,
        region_id: u32,
    ) -> Result<(), TailscaleDiscoSocketError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(SocketCommand::RemoveDerpRegion {
                region_id,
                result: result_tx,
            })
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)?;
        result_rx
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)?
    }

    pub async fn set_home_derp_region(
        &self,
        region_id: Option<u32>,
    ) -> Result<(), TailscaleDiscoSocketError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(SocketCommand::SetHomeDerpRegion {
                region_id,
                result: result_tx,
            })
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)?;
        result_rx
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)?
    }

    pub async fn send_wireguard(
        &self,
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
        packet: &[u8],
    ) -> Result<TailscalePacketSendOutcome, TailscaleDiscoSocketError> {
        if packet.len() > TAILSCALE_DERP_MAX_PACKET_SIZE {
            return Err(TailscaleDiscoSocketError::PacketTooLarge);
        }
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(SocketCommand::SendWireguard {
                peer,
                packet: packet.to_vec(),
                result: result_tx,
            })
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)?;
        result_rx
            .await
            .unwrap_or(Err(TailscaleDiscoSocketError::Closed))
    }

    pub async fn peer_path(
        &self,
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
    ) -> Result<Option<TailscalePeerPathSnapshot>, TailscaleDiscoSocketError>
    {
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(SocketCommand::PeerPath {
                peer,
                result: result_tx,
            })
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)?;
        result_rx
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)
    }

    pub async fn next_event(&mut self) -> Option<TailscaleDiscoSocketEvent> {
        self.events.recv().await
    }

    pub fn status(&self) -> TailscaleDiscoSocketStatus {
        self.status
            .read()
            .map(|status| status.clone())
            .unwrap_or_default()
    }

    pub async fn close(mut self) -> Result<(), TailscaleDiscoSocketError> {
        self.cancellation.cancel();
        self.task
            .take()
            .expect("Tailscale disco socket task is present")
            .await
            .map_err(|error| {
                TailscaleDiscoSocketError::Io(io::Error::other(format!(
                    "Tailscale disco socket task failed: {error}"
                )))
            })
    }

    fn try_command(
        &self,
        command: SocketCommand,
    ) -> Result<(), TailscaleDiscoSocketError> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    TailscaleDiscoSocketError::CommandQueueFull
                }
                mpsc::error::TrySendError::Closed(_) => {
                    TailscaleDiscoSocketError::Closed
                }
            })
    }
}

impl TailscaleDiscoSocketHandle {
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local_addrs
    }

    pub fn set_advertised_endpoints(
        &self,
        endpoints: Vec<SocketAddr>,
    ) -> Result<(), TailscaleDiscoSocketError> {
        self.commands
            .try_send(SocketCommand::SetAdvertisedEndpoints(endpoints))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    TailscaleDiscoSocketError::CommandQueueFull
                }
                mpsc::error::TrySendError::Closed(_) => {
                    TailscaleDiscoSocketError::Closed
                }
            })
    }

    pub async fn stun_binding(
        &self,
        server: SocketAddr,
        timeout: Duration,
    ) -> Result<SocketAddr, TailscaleDiscoSocketError> {
        let mut transaction_id = [0_u8; 12];
        getrandom::fill(&mut transaction_id).map_err(io::Error::other)?;
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(SocketCommand::StunBinding {
                server,
                transaction_id,
                result: result_tx,
            })
            .await
            .map_err(|_| TailscaleDiscoSocketError::Closed)?;
        tokio::time::timeout(timeout, result_rx)
            .await
            .map_err(|_| TailscaleDiscoSocketError::StunTimeout)?
            .map_err(|_| TailscaleDiscoSocketError::Closed)?
    }

    pub fn status(&self) -> TailscaleDiscoSocketStatus {
        self.status
            .read()
            .map(|status| status.clone())
            .unwrap_or_default()
    }
}

impl Drop for TailscaleDiscoSocket {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn validate_peer(
    peer: &TailscaleDiscoPeer,
) -> Result<(), TailscaleDiscoSocketError> {
    if peer.node_key == [0; TAILSCALE_DERP_KEY_LENGTH]
        || (peer.disco_key == [0; TAILSCALE_DISCO_KEY_LENGTH]
            && peer.endpoints.is_empty())
    {
        return Err(TailscaleDiscoSocketError::UnknownPeer);
    }
    Ok(())
}

async fn run_socket(
    packet: Arc<dyn PacketConnection>,
    mut derp_manager: Option<TailscaleDerpManager>,
    options: TailscaleDiscoSocketOptions,
    mut commands: mpsc::Receiver<SocketCommand>,
    events: mpsc::Sender<TailscaleDiscoSocketEvent>,
    status: Arc<RwLock<TailscaleDiscoSocketStatus>>,
    cancellation: CancellationToken,
) {
    let mut peers = HashMap::<[u8; 32], PeerRuntime>::new();
    let mut nodes_by_disco = HashMap::<[u8; 32], HashSet<[u8; 32]>>::new();
    let mut peer_by_endpoint = HashMap::<SocketAddr, [u8; 32]>::new();
    let mut advertised_endpoints = options.advertised_endpoints.clone();
    let mut pending_stun = HashMap::<TransactionId, PendingStunBinding>::new();
    let mut buffer = vec![0_u8; TAILSCALE_DERP_MAX_PACKET_SIZE];
    let mut heartbeat = tokio::time::interval(options.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let mut derp_poll = tokio::time::interval(options.derp_event_poll_interval);
    derp_poll.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            command = commands.recv() => {
                let Some(command) = command else { break };
                handle_command(
                    command,
                    packet.as_ref(),
                    derp_manager.as_ref(),
                    &options,
                    &mut peers,
                    &mut nodes_by_disco,
                    &mut peer_by_endpoint,
                    &mut advertised_endpoints,
                    &mut pending_stun,
                    &events,
                    &status,
                ).await;
            }
            received = packet.recv_from(&mut buffer) => {
                match received {
                    Ok((size, SocksAddr::Ip(source))) => {
                        handle_direct_packet(
                            &buffer[..size],
                            source,
                            packet.as_ref(),
                            derp_manager.as_ref(),
                            &options,
                            &mut peers,
                            &nodes_by_disco,
                            &mut peer_by_endpoint,
                            &mut pending_stun,
                            &events,
                            &status,
                            &cancellation,
                        ).await;
                    }
                    Ok((_size, SocksAddr::Domain { .. })) => {}
                    Err(error) => {
                        record_error(&status, &events, error.to_string());
                    }
                }
            }
            _ = derp_poll.tick(), if derp_manager.is_some() => {
                if let Some(manager) = derp_manager.as_mut() {
                    while let Some(event) = manager.try_next_event() {
                        handle_derp_event(
                            event,
                            packet.as_ref(),
                            manager,
                            &options,
                            &mut peers,
                            &nodes_by_disco,
                            &mut peer_by_endpoint,
                            &events,
                            &status,
                            &cancellation,
                        ).await;
                    }
                }
            }
            _ = heartbeat.tick() => {
                pending_stun.retain(|_, pending| !pending.result.is_closed());
                handle_heartbeat(
                    packet.as_ref(),
                    derp_manager.as_ref(),
                    &options,
                    &mut peers,
                    &advertised_endpoints,
                    &events,
                    &status,
                ).await;
            }
        }
    }
    if let Some(manager) = derp_manager {
        let _ = manager.close().await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_command(
    command: SocketCommand,
    packet: &dyn PacketConnection,
    derp_manager: Option<&TailscaleDerpManager>,
    options: &TailscaleDiscoSocketOptions,
    peers: &mut HashMap<[u8; 32], PeerRuntime>,
    nodes_by_disco: &mut HashMap<[u8; 32], HashSet<[u8; 32]>>,
    peer_by_endpoint: &mut HashMap<SocketAddr, [u8; 32]>,
    advertised_endpoints: &mut Vec<SocketAddr>,
    pending_stun: &mut HashMap<TransactionId, PendingStunBinding>,
    events: &mpsc::Sender<TailscaleDiscoSocketEvent>,
    status: &RwLock<TailscaleDiscoSocketStatus>,
) {
    match command {
        SocketCommand::SetPeer(config) => {
            let now = Instant::now();
            let old = peers.remove(&config.node_key);
            if let Some(old) = old.as_ref()
                && let Some(nodes) =
                    nodes_by_disco.get_mut(&old.config.disco_key)
            {
                nodes.remove(&config.node_key);
                if nodes.is_empty() {
                    nodes_by_disco.remove(&old.config.disco_key);
                }
            }
            let preserve_paths = old
                .as_ref()
                .is_some_and(|old| old.config.disco_key == config.disco_key);
            if old.is_some()
                && (!preserve_paths
                    || config.disco_key == [0; TAILSCALE_DISCO_KEY_LENGTH])
            {
                peer_by_endpoint.retain(|_, mapped| *mapped != config.node_key);
            }
            let (mut paths, last_external_send) = match old {
                Some(old) if preserve_paths => {
                    (old.paths, old.last_external_send)
                }
                _ => {
                    (TailscalePeerPathState::new(config.home_derp_region), None)
                }
            };
            paths.set_derp_region(config.home_derp_region);
            paths.update_netmap_endpoints(&config.endpoints, now);
            if config.disco_key == [0; TAILSCALE_DISCO_KEY_LENGTH] {
                for endpoint in &config.endpoints {
                    peer_by_endpoint.insert(*endpoint, config.node_key);
                }
            } else {
                nodes_by_disco
                    .entry(config.disco_key)
                    .or_default()
                    .insert(config.node_key);
            }
            peers.insert(
                config.node_key,
                PeerRuntime {
                    config,
                    paths,
                    last_external_send,
                },
            );
            refresh_peer_count(status, peers.len());
        }
        SocketCommand::RemovePeer(peer) => {
            remove_peer_indexes(peer, peers, nodes_by_disco, peer_by_endpoint);
            refresh_peer_count(status, peers.len());
        }
        SocketCommand::SetAdvertisedEndpoints(endpoints) => {
            *advertised_endpoints = endpoints;
        }
        SocketCommand::StunBinding {
            server,
            transaction_id,
            result,
        } => {
            let request = build_binding_request_message(transaction_id);
            match packet.send_to(&request, &server.into()).await {
                Ok(_) => {
                    pending_stun.insert(
                        transaction_id,
                        PendingStunBinding { server, result },
                    );
                }
                Err(error) => {
                    let _ = result.send(Err(error.into()));
                }
            }
        }
        SocketCommand::Probe(peer) => {
            if peers.contains_key(&peer) {
                start_discovery(
                    peer,
                    packet,
                    derp_manager,
                    options,
                    peers,
                    advertised_endpoints,
                    status,
                )
                .await;
            }
        }
        SocketCommand::ConnectivityChanged => {
            peer_by_endpoint.clear();
            for peer in peers.values_mut() {
                peer.paths.note_connectivity_change();
            }
        }
        SocketCommand::SetDerpRegion {
            region_id,
            connector,
            result,
        } => {
            let response = derp_manager
                .ok_or(TailscaleDiscoSocketError::NoDerpManager)
                .and_then(|manager| {
                    manager.set_region(region_id, connector).map_err(Into::into)
                });
            let _ = result.send(response);
        }
        SocketCommand::RemoveDerpRegion { region_id, result } => {
            let response = derp_manager
                .ok_or(TailscaleDiscoSocketError::NoDerpManager)
                .and_then(|manager| {
                    manager.remove_region(region_id).map_err(Into::into)
                });
            let _ = result.send(response);
        }
        SocketCommand::SetHomeDerpRegion { region_id, result } => {
            let response = derp_manager
                .ok_or(TailscaleDiscoSocketError::NoDerpManager)
                .and_then(|manager| {
                    manager.set_home_region(region_id).map_err(Into::into)
                });
            let _ = result.send(response);
        }
        SocketCommand::SendWireguard {
            peer,
            packet: payload,
            result,
        } => {
            let outcome = send_wireguard_packet(
                peer,
                &payload,
                packet,
                derp_manager,
                options,
                peers,
                advertised_endpoints,
                events,
                status,
            )
            .await;
            let _ = result.send(outcome);
        }
        SocketCommand::PeerPath { peer, result } => {
            let snapshot =
                peers.get(&peer).map(|runtime| TailscalePeerPathSnapshot {
                    peer,
                    best: runtime.paths.best().cloned(),
                    trust_best_until: runtime.paths.trust_best_until(),
                    endpoints: runtime.paths.endpoint_snapshots(),
                });
            let _ = result.send(snapshot);
        }
    }
}

fn remove_peer_indexes(
    peer: [u8; 32],
    peers: &mut HashMap<[u8; 32], PeerRuntime>,
    nodes_by_disco: &mut HashMap<[u8; 32], HashSet<[u8; 32]>>,
    peer_by_endpoint: &mut HashMap<SocketAddr, [u8; 32]>,
) {
    if let Some(old) = peers.remove(&peer) {
        if let Some(nodes) = nodes_by_disco.get_mut(&old.config.disco_key) {
            nodes.remove(&peer);
            if nodes.is_empty() {
                nodes_by_disco.remove(&old.config.disco_key);
            }
        }
        peer_by_endpoint.retain(|_, mapped| *mapped != peer);
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_wireguard_packet(
    peer: [u8; 32],
    payload: &[u8],
    packet: &dyn PacketConnection,
    derp_manager: Option<&TailscaleDerpManager>,
    options: &TailscaleDiscoSocketOptions,
    peers: &mut HashMap<[u8; 32], PeerRuntime>,
    advertised_endpoints: &[SocketAddr],
    events: &mpsc::Sender<TailscaleDiscoSocketEvent>,
    status: &RwLock<TailscaleDiscoSocketStatus>,
) -> Result<TailscalePacketSendOutcome, TailscaleDiscoSocketError> {
    let now = Instant::now();
    let Some(runtime) = peers.get_mut(&peer) else {
        return Err(TailscaleDiscoSocketError::UnknownPeer);
    };
    runtime.last_external_send = Some(now);
    if runtime.config.disco_key == [0; TAILSCALE_DISCO_KEY_LENGTH] {
        let endpoints = runtime.config.endpoints.clone();
        let home_derp_region = runtime.config.home_derp_region;
        let mut outcome = TailscalePacketSendOutcome::default();
        let mut last_error = None;
        for endpoint in endpoints {
            match packet.send_to(payload, &endpoint.into()).await {
                Ok(size) if size == payload.len() => {
                    outcome.sent_direct = true;
                    bump_status(status, |status| {
                        status.sent_direct_packets += 1
                    });
                    break;
                }
                Ok(_) => {
                    last_error = Some("partial direct UDP datagram".into())
                }
                Err(error) => last_error = Some(error.to_string()),
            }
        }
        if let Some(manager) = derp_manager
            && home_derp_region.is_some()
        {
            match manager.send_packet(peer, home_derp_region, payload).await {
                Ok(region_id) => {
                    outcome.derp_region = Some(region_id);
                    bump_status(status, |status| status.sent_derp_packets += 1);
                }
                Err(error) => last_error = Some(error.to_string()),
            }
        }
        if outcome.sent_direct || outcome.derp_region.is_some() {
            return Ok(outcome);
        }
        if let Some(error) = last_error {
            record_error(status, events, error.clone());
            return Err(TailscaleDiscoSocketError::Io(io::Error::other(error)));
        }
        return Err(TailscaleDiscoSocketError::NoPath);
    }
    let send_path = runtime.paths.send_path(now);
    let home_derp_region = runtime.config.home_derp_region;
    let mut outcome = TailscalePacketSendOutcome::default();
    let mut last_error = None;

    if let Some(direct) = send_path.udp {
        match packet.send_to(payload, &direct.endpoint.into()).await {
            Ok(size) if size == payload.len() => {
                outcome.sent_direct = true;
                bump_status(status, |status| status.sent_direct_packets += 1);
            }
            Ok(_) => {
                runtime.paths.note_bad_endpoint(direct.endpoint);
                last_error = Some("partial direct UDP datagram".to_string());
            }
            Err(error) => {
                runtime.paths.note_bad_endpoint(direct.endpoint);
                last_error = Some(error.to_string());
            }
        }
    }
    if send_path.derp_region.is_some()
        && let Some(manager) = derp_manager
    {
        match manager.send_packet(peer, home_derp_region, payload).await {
            Ok(region_id) => {
                outcome.derp_region = Some(region_id);
                bump_status(status, |status| status.sent_derp_packets += 1);
            }
            Err(error) => last_error = Some(error.to_string()),
        }
    }

    if send_path.derp_region.is_some() {
        outcome.discovery_started = true;
        start_discovery(
            peer,
            packet,
            derp_manager,
            options,
            peers,
            advertised_endpoints,
            status,
        )
        .await;
    }
    if outcome.sent_direct || outcome.derp_region.is_some() {
        return Ok(outcome);
    }
    if let Some(error) = last_error {
        record_error(status, events, error.clone());
        return Err(TailscaleDiscoSocketError::Io(io::Error::other(error)));
    }
    Err(TailscaleDiscoSocketError::NoPath)
}

async fn start_discovery(
    peer: [u8; 32],
    packet: &dyn PacketConnection,
    derp_manager: Option<&TailscaleDerpManager>,
    options: &TailscaleDiscoSocketOptions,
    peers: &mut HashMap<[u8; 32], PeerRuntime>,
    advertised_endpoints: &[SocketAddr],
    status: &RwLock<TailscaleDiscoSocketStatus>,
) {
    let now = Instant::now();
    let Some(runtime) = peers.get_mut(&peer) else {
        return;
    };
    let disco_key = runtime.config.disco_key;
    if disco_key == [0; TAILSCALE_DISCO_KEY_LENGTH] {
        return;
    }
    let home_derp_region = runtime.config.home_derp_region;
    let candidates = runtime.paths.discovery_candidates(now);
    let mut probes = Vec::with_capacity(candidates.len());
    for endpoint in candidates {
        let mut transaction_id = [0_u8; 12];
        if getrandom::fill(&mut transaction_id).is_err() {
            continue;
        }
        let quality = TailscalePathQuality::direct(
            endpoint,
            Duration::ZERO,
            TAILSCALE_PATH_SAFE_WIRE_MTU,
        );
        runtime.paths.begin_ping(transaction_id, quality, now);
        probes.push((transaction_id, endpoint));
    }

    for (transaction_id, endpoint) in probes {
        let message = TailscaleDiscoMessage::Ping(TailscaleDiscoPing {
            transaction_id,
            node_key: Some(options.node_key),
            padding: 0,
        });
        let sent = send_direct_disco(
            packet,
            options.disco_private_key,
            disco_key,
            endpoint,
            &message,
        )
        .await;
        if sent.is_err()
            && let Some(runtime) = peers.get_mut(&peer)
        {
            runtime.paths.forget_ping(transaction_id);
        }
    }

    if !advertised_endpoints.is_empty()
        && let Some(manager) = derp_manager
    {
        let message =
            TailscaleDiscoMessage::CallMeMaybe(TailscaleDiscoCallMeMaybe {
                endpoints: advertised_endpoints.to_vec(),
            });
        match seal_tailscale_disco_packet(
            options.disco_private_key,
            disco_key,
            &message,
        ) {
            Ok(payload) => {
                if manager
                    .send_packet(peer, home_derp_region, &payload)
                    .await
                    .is_ok()
                {
                    bump_status(status, |status| status.sent_derp_packets += 1);
                }
            }
            Err(error) => record_status_error(status, error.to_string()),
        }
    }
}

async fn send_direct_disco(
    packet: &dyn PacketConnection,
    private_key: [u8; 32],
    peer_disco_key: [u8; 32],
    destination: SocketAddr,
    message: &TailscaleDiscoMessage,
) -> Result<(), TailscaleDiscoSocketError> {
    let payload =
        seal_tailscale_disco_packet(private_key, peer_disco_key, message)?;
    let sent = packet.send_to(&payload, &destination.into()).await?;
    if sent != payload.len() {
        return Err(TailscaleDiscoSocketError::Io(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial Tailscale disco UDP datagram",
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_direct_packet(
    payload: &[u8],
    source: SocketAddr,
    packet: &dyn PacketConnection,
    derp_manager: Option<&TailscaleDerpManager>,
    options: &TailscaleDiscoSocketOptions,
    peers: &mut HashMap<[u8; 32], PeerRuntime>,
    nodes_by_disco: &HashMap<[u8; 32], HashSet<[u8; 32]>>,
    peer_by_endpoint: &mut HashMap<SocketAddr, [u8; 32]>,
    pending_stun: &mut HashMap<TransactionId, PendingStunBinding>,
    events: &mpsc::Sender<TailscaleDiscoSocketEvent>,
    status: &RwLock<TailscaleDiscoSocketStatus>,
    cancellation: &CancellationToken,
) {
    if let Some(transaction_id) = transaction_id_from_message(payload)
        && pending_stun
            .get(&transaction_id)
            .is_some_and(|pending| pending.server == source)
        && let Some(pending) = pending_stun.remove(&transaction_id)
    {
        let result = mapped_address_from_response(payload, transaction_id)
            .map_err(TailscaleDiscoSocketError::from);
        let _ = pending.result.send(result);
        return;
    }
    if !looks_like_tailscale_disco_packet(payload) {
        let Some(peer) = peer_by_endpoint.get(&source).copied() else {
            return;
        };
        bump_status(status, |status| status.received_direct_packets += 1);
        emit(
            events,
            TailscaleDiscoSocketEvent::WireguardPacket {
                peer,
                packet: payload.to_vec(),
                path: TailscalePacketPath::Direct(source),
            },
            cancellation,
            status,
        )
        .await;
        return;
    }
    let opened =
        match open_tailscale_disco_packet(options.disco_private_key, payload) {
            Ok(opened) => opened,
            Err(error) => {
                record_error(status, events, error.to_string());
                return;
            }
        };
    handle_disco_message(
        opened,
        TailscalePacketPath::Direct(source),
        None,
        packet,
        derp_manager,
        options,
        peers,
        nodes_by_disco,
        peer_by_endpoint,
        events,
        status,
        cancellation,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_derp_event(
    event: TailscaleDerpManagerEvent,
    packet: &dyn PacketConnection,
    derp_manager: &TailscaleDerpManager,
    options: &TailscaleDiscoSocketOptions,
    peers: &mut HashMap<[u8; 32], PeerRuntime>,
    nodes_by_disco: &HashMap<[u8; 32], HashSet<[u8; 32]>>,
    peer_by_endpoint: &mut HashMap<SocketAddr, [u8; 32]>,
    events: &mpsc::Sender<TailscaleDiscoSocketEvent>,
    status: &RwLock<TailscaleDiscoSocketStatus>,
    cancellation: &CancellationToken,
) {
    if let TailscaleDerpManagerEvent::Region(
        TailscaleDerpRegionEvent::Message {
            region_id,
            message: TailscaleDerpReceivedMessage::Packet(received),
            ..
        },
    ) = &event
    {
        bump_status(status, |status| status.received_derp_packets += 1);
        if looks_like_tailscale_disco_packet(&received.packet) {
            match open_tailscale_disco_packet(
                options.disco_private_key,
                &received.packet,
            ) {
                Ok(opened) => {
                    handle_disco_message(
                        opened,
                        TailscalePacketPath::Derp {
                            region_id: *region_id,
                        },
                        Some(received.peer),
                        packet,
                        Some(derp_manager),
                        options,
                        peers,
                        nodes_by_disco,
                        peer_by_endpoint,
                        events,
                        status,
                        cancellation,
                    )
                    .await;
                }
                Err(error) => record_error(status, events, error.to_string()),
            }
        } else if peers.contains_key(&received.peer) {
            emit(
                events,
                TailscaleDiscoSocketEvent::WireguardPacket {
                    peer: received.peer,
                    packet: received.packet.clone(),
                    path: TailscalePacketPath::Derp {
                        region_id: *region_id,
                    },
                },
                cancellation,
                status,
            )
            .await;
        }
    }
    emit(
        events,
        TailscaleDiscoSocketEvent::Derp(event),
        cancellation,
        status,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_disco_message(
    opened: TailscaleDiscoPacket,
    path: TailscalePacketPath,
    derp_peer: Option<[u8; 32]>,
    packet: &dyn PacketConnection,
    derp_manager: Option<&TailscaleDerpManager>,
    options: &TailscaleDiscoSocketOptions,
    peers: &mut HashMap<[u8; 32], PeerRuntime>,
    nodes_by_disco: &HashMap<[u8; 32], HashSet<[u8; 32]>>,
    peer_by_endpoint: &mut HashMap<SocketAddr, [u8; 32]>,
    events: &mpsc::Sender<TailscaleDiscoSocketEvent>,
    status: &RwLock<TailscaleDiscoSocketStatus>,
    cancellation: &CancellationToken,
) {
    let via_derp = matches!(path, TailscalePacketPath::Derp { .. });
    let peer = match &opened.message {
        TailscaleDiscoMessage::Ping(ping) => resolve_ping_peer(
            opened.sender_public_key,
            ping,
            derp_peer,
            peers,
            nodes_by_disco,
        ),
        TailscaleDiscoMessage::Pong(pong) => resolve_pong_peer(
            opened.sender_public_key,
            pong.transaction_id,
            peers,
            nodes_by_disco,
        ),
        _ => derp_peer.filter(|peer| {
            peers.get(peer).is_some_and(|runtime| {
                runtime.config.disco_key == opened.sender_public_key
            })
        }),
    };
    let Some(peer) = peer else {
        return;
    };

    match &opened.message {
        TailscaleDiscoMessage::Ping(ping) => {
            if let TailscalePacketPath::Direct(source) = path {
                let Some(runtime) = peers.get_mut(&peer) else {
                    return;
                };
                if runtime.paths.add_candidate_endpoint(
                    source,
                    ping.transaction_id,
                    Instant::now(),
                ) {
                    return;
                }
                peer_by_endpoint.insert(source, peer);
                let pong = TailscaleDiscoMessage::Pong(TailscaleDiscoPong {
                    transaction_id: ping.transaction_id,
                    source,
                });
                let _ = send_direct_disco(
                    packet,
                    options.disco_private_key,
                    opened.sender_public_key,
                    source,
                    &pong,
                )
                .await;
            } else if let Some(manager) = derp_manager {
                let pong = TailscaleDiscoMessage::Pong(TailscaleDiscoPong {
                    transaction_id: ping.transaction_id,
                    source: derp_magic_address(derp_region(&path)),
                });
                if let Ok(payload) = seal_tailscale_disco_packet(
                    options.disco_private_key,
                    opened.sender_public_key,
                    &pong,
                ) && let Some(runtime) = peers.get(&peer)
                    && manager
                        .send_packet(
                            peer,
                            runtime.config.home_derp_region,
                            &payload,
                        )
                        .await
                        .is_ok()
                {
                    bump_status(status, |status| status.sent_derp_packets += 1);
                }
            }
        }
        TailscaleDiscoMessage::Pong(pong) => {
            let before = peers
                .get(&peer)
                .and_then(|runtime| runtime.paths.best().cloned());
            let from = match path {
                TailscalePacketPath::Direct(source) => source,
                TailscalePacketPath::Derp { region_id } => {
                    derp_magic_address(region_id)
                }
            };
            if let Some(runtime) = peers.get_mut(&peer) {
                let outcome = runtime.paths.record_pong(
                    pong.transaction_id,
                    from,
                    pong.source,
                    via_derp,
                    Instant::now(),
                );
                if outcome.is_some() && !via_derp {
                    peer_by_endpoint.insert(from, peer);
                }
                let after = runtime.paths.best().cloned();
                if before != after {
                    emit(
                        events,
                        TailscaleDiscoSocketEvent::PathChanged {
                            peer,
                            best: after,
                        },
                        cancellation,
                        status,
                    )
                    .await;
                }
            }
        }
        TailscaleDiscoMessage::CallMeMaybe(call) if via_derp => {
            if let Some(runtime) = peers.get_mut(&peer) {
                let now = Instant::now();
                let candidates =
                    runtime.paths.handle_call_me_maybe(&call.endpoints, now);
                let disco_key = runtime.config.disco_key;
                for endpoint in candidates {
                    let mut transaction_id = [0_u8; 12];
                    if getrandom::fill(&mut transaction_id).is_err() {
                        continue;
                    }
                    let quality = TailscalePathQuality::direct(
                        endpoint,
                        Duration::ZERO,
                        TAILSCALE_PATH_SAFE_WIRE_MTU,
                    );
                    runtime.paths.begin_ping(transaction_id, quality, now);
                    let ping =
                        TailscaleDiscoMessage::Ping(TailscaleDiscoPing {
                            transaction_id,
                            node_key: Some(options.node_key),
                            padding: 0,
                        });
                    if send_direct_disco(
                        packet,
                        options.disco_private_key,
                        disco_key,
                        endpoint,
                        &ping,
                    )
                    .await
                    .is_err()
                    {
                        runtime.paths.forget_ping(transaction_id);
                    }
                }
            }
        }
        TailscaleDiscoMessage::CallMeMaybe(_) => return,
        _ => {}
    }

    emit(
        events,
        TailscaleDiscoSocketEvent::DiscoMessage {
            peer,
            message: opened.message,
            path,
        },
        cancellation,
        status,
    )
    .await;
}

fn resolve_ping_peer(
    disco_key: [u8; 32],
    ping: &TailscaleDiscoPing,
    derp_peer: Option<[u8; 32]>,
    peers: &HashMap<[u8; 32], PeerRuntime>,
    nodes_by_disco: &HashMap<[u8; 32], HashSet<[u8; 32]>>,
) -> Option<[u8; 32]> {
    if let Some(peer) = derp_peer
        && peers
            .get(&peer)
            .is_some_and(|runtime| runtime.config.disco_key == disco_key)
    {
        return Some(peer);
    }
    if let Some(peer) = ping.node_key
        && peers
            .get(&peer)
            .is_some_and(|runtime| runtime.config.disco_key == disco_key)
    {
        return Some(peer);
    }
    let nodes = nodes_by_disco.get(&disco_key)?;
    (nodes.len() == 1).then(|| *nodes.iter().next().expect("one disco peer"))
}

fn resolve_pong_peer(
    disco_key: [u8; 32],
    transaction_id: TailscaleDiscoTransactionId,
    peers: &mut HashMap<[u8; 32], PeerRuntime>,
    nodes_by_disco: &HashMap<[u8; 32], HashSet<[u8; 32]>>,
) -> Option<[u8; 32]> {
    let nodes = nodes_by_disco.get(&disco_key)?;
    nodes.iter().copied().find(|peer| {
        peers.get(peer).is_some_and(|runtime| {
            runtime.paths.has_pending_ping(transaction_id)
        })
    })
}

async fn handle_heartbeat(
    packet: &dyn PacketConnection,
    derp_manager: Option<&TailscaleDerpManager>,
    options: &TailscaleDiscoSocketOptions,
    peers: &mut HashMap<[u8; 32], PeerRuntime>,
    advertised_endpoints: &[SocketAddr],
    events: &mpsc::Sender<TailscaleDiscoSocketEvent>,
    status: &RwLock<TailscaleDiscoSocketStatus>,
) {
    let now = Instant::now();
    let active = peers
        .iter_mut()
        .filter_map(|(peer, runtime)| {
            runtime.paths.expire_pings(now);
            runtime.last_external_send.and_then(|last_send| {
                (now.checked_duration_since(last_send).unwrap_or_default()
                    <= TAILSCALE_PATH_SESSION_ACTIVE_TIMEOUT)
                    .then_some(*peer)
            })
        })
        .collect::<Vec<_>>();

    for peer in active {
        let heartbeat_path = peers
            .get(&peer)
            .and_then(|runtime| runtime.paths.best().cloned());
        if let Some(target) = heartbeat_path {
            let mut transaction_id = [0_u8; 12];
            if getrandom::fill(&mut transaction_id).is_ok() {
                let (disco_key, destination) = {
                    let runtime =
                        peers.get_mut(&peer).expect("active peer exists");
                    runtime.paths.begin_ping(
                        transaction_id,
                        target.clone(),
                        now,
                    );
                    (runtime.config.disco_key, target.endpoint)
                };
                let ping = TailscaleDiscoMessage::Ping(TailscaleDiscoPing {
                    transaction_id,
                    node_key: Some(options.node_key),
                    padding: 0,
                });
                if send_direct_disco(
                    packet,
                    options.disco_private_key,
                    disco_key,
                    destination,
                    &ping,
                )
                .await
                .is_err()
                    && let Some(runtime) = peers.get_mut(&peer)
                {
                    runtime.paths.forget_ping(transaction_id);
                }
            }
        }
        let wants_full = peers
            .get(&peer)
            .is_some_and(|runtime| runtime.paths.wants_full_ping(now));
        if wants_full {
            start_discovery(
                peer,
                packet,
                derp_manager,
                options,
                peers,
                advertised_endpoints,
                status,
            )
            .await;
        }
    }
    let _ = events;
}

async fn emit(
    events: &mpsc::Sender<TailscaleDiscoSocketEvent>,
    event: TailscaleDiscoSocketEvent,
    cancellation: &CancellationToken,
    status: &RwLock<TailscaleDiscoSocketStatus>,
) {
    let delivered = tokio::select! {
        biased;
        _ = cancellation.cancelled() => false,
        result = events.send(event) => result.is_ok(),
    };
    if !delivered {
        bump_status(status, |status| status.dropped_events += 1);
    }
}

fn record_error(
    status: &RwLock<TailscaleDiscoSocketStatus>,
    events: &mpsc::Sender<TailscaleDiscoSocketEvent>,
    error: String,
) {
    record_status_error(status, error.clone());
    let _ = events.try_send(TailscaleDiscoSocketEvent::Error(error));
}

fn record_status_error(
    status: &RwLock<TailscaleDiscoSocketStatus>,
    error: String,
) {
    bump_status(status, |status| status.last_error = Some(error));
}

fn refresh_peer_count(
    status: &RwLock<TailscaleDiscoSocketStatus>,
    peers: usize,
) {
    bump_status(status, |status| status.peers = peers);
}

fn bump_status(
    status: &RwLock<TailscaleDiscoSocketStatus>,
    update: impl FnOnce(&mut TailscaleDiscoSocketStatus),
) {
    if let Ok(mut status) = status.write() {
        update(&mut status);
    }
}

fn derp_region(path: &TailscalePacketPath) -> u32 {
    match path {
        TailscalePacketPath::Derp { region_id } => *region_id,
        TailscalePacketPath::Direct(_) => 0,
    }
}

fn derp_magic_address(region_id: u32) -> SocketAddr {
    SocketAddr::new(
        "127.3.3.40".parse().expect("DERP magic IP"),
        region_id as u16,
    )
}

struct TokioUdpPacketConnection {
    socket: UdpSocket,
}

struct TokioDualStackUdpPacketConnection {
    ipv4: UdpSocket,
    ipv6: Option<UdpSocket>,
}

fn bind_ipv6_udp(port: u16) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::from(([0_u16; 8], port)).into())?;
    UdpSocket::from_std(socket.into())
}

impl PacketConnection for TokioDualStackUdpPacketConnection {
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.ipv4.local_addr().map(Some)
    }

    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let SocksAddr::Ip(destination) = destination else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Tailscale direct UDP destination must be an IP address",
                ));
            };
            if destination.is_ipv6() {
                let ipv6 = self.ipv6.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "Tailscale IPv6 UDP socket is unavailable",
                    )
                })?;
                ipv6.send_to(data, destination).await
            } else {
                self.ipv4.send_to(data, destination).await
            }
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let Some(ipv6) = &self.ipv6 else {
                return self
                    .ipv4
                    .recv_from(data)
                    .await
                    .map(|(size, source)| (size, source.into()));
            };
            loop {
                let socket = tokio::select! {
                    ready = self.ipv4.readable() => {
                        ready?;
                        &self.ipv4
                    }
                    ready = ipv6.readable() => {
                        ready?;
                        ipv6
                    }
                };
                match socket.try_recv_from(data) {
                    Ok((size, source)) => return Ok((size, source.into())),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    }
                    Err(error) => return Err(error),
                }
            }
        })
    }
}

impl PacketConnection for TokioUdpPacketConnection {
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.socket.local_addr().map(Some)
    }

    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let SocksAddr::Ip(destination) = destination else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Tailscale direct UDP destination must be an IP address",
                ));
            };
            self.socket.send_to(data, destination).await
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            self.socket
                .recv_from(data)
                .await
                .map(|(size, source)| (size, source.into()))
        })
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use tokio::io::AsyncReadExt as _;

    use super::*;
    use crate::{
        adapter::Stream,
        protocol::{
            tailscale::{
                TAILSCALE_DERP_FRAME_CLIENT_INFO,
                TAILSCALE_DERP_FRAME_RECV_PACKET,
                TAILSCALE_DERP_FRAME_SEND_PACKET, TailscaleDerpClient,
                TailscaleDerpConnectOptions, read_tailscale_derp_frame,
                tailscale_node_public_key, write_tailscale_derp_frame,
            },
            tailscale_derp_manager::TailscaleDerpManagerOptions,
            tailscale_derp_supervisor::{
                TailscaleDerpConnector, TailscaleDerpRegionSupervisorOptions,
            },
        },
    };

    fn stun_success_response(
        transaction_id: TransactionId,
        mapped: SocketAddr,
    ) -> Vec<u8> {
        let SocketAddr::V4(mapped) = mapped else {
            panic!("test response requires IPv4");
        };
        let mut response = vec![0_u8; 32];
        response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
        response[2..4].copy_from_slice(&12_u16.to_be_bytes());
        response[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
        response[8..20].copy_from_slice(&transaction_id);
        response[20..22].copy_from_slice(&0x0020_u16.to_be_bytes());
        response[22..24].copy_from_slice(&8_u16.to_be_bytes());
        response[25] = 1;
        let port = mapped.port() ^ (0x2112_a442_u32 >> 16) as u16;
        response[26..28].copy_from_slice(&port.to_be_bytes());
        let address = u32::from(*mapped.ip()) ^ 0x2112_a442;
        response[28..32].copy_from_slice(&address.to_be_bytes());
        response
    }

    #[tokio::test]
    async fn stun_binding_uses_the_live_disco_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut request = [0_u8; 128];
            let (size, source) = server.recv_from(&mut request).await.unwrap();
            let transaction_id =
                transaction_id_from_message(&request[..size]).unwrap();
            let mapped: SocketAddr = "198.51.100.7:41641".parse().unwrap();
            server
                .send_to(&stun_success_response(transaction_id, mapped), source)
                .await
                .unwrap();
        });
        let socket = TailscaleDiscoSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
            TailscaleDiscoSocketOptions::new([1; 32], [2; 32]),
        )
        .await
        .unwrap();
        let local_addr = socket.local_addr().unwrap();
        let mapped = socket
            .handle()
            .stun_binding(server_addr, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(mapped, "198.51.100.7:41641".parse::<SocketAddr>().unwrap());
        assert_eq!(socket.local_addr(), Some(local_addr));
        socket.close().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn wireguard_only_peer_uses_static_direct_endpoint() {
        let socket_a = TailscaleDiscoSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
            TailscaleDiscoSocketOptions::new([11; 32], [12; 32]),
        )
        .await
        .unwrap();
        let mut socket_b = TailscaleDiscoSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
            TailscaleDiscoSocketOptions::new([21; 32], [22; 32]),
        )
        .await
        .unwrap();
        let address_a = socket_a.local_addr().unwrap();
        let address_b = socket_b.local_addr().unwrap();
        socket_a
            .set_peer(TailscaleDiscoPeer {
                node_key: [21; 32],
                disco_key: [0; 32],
                home_derp_region: None,
                endpoints: vec![address_b],
            })
            .unwrap();
        socket_b
            .set_peer(TailscaleDiscoPeer {
                node_key: [11; 32],
                disco_key: [0; 32],
                home_derp_region: None,
                endpoints: vec![address_a],
            })
            .unwrap();
        let payload = vec![4_u8, 0, 0, 0, 1, 2, 3, 4];
        let outcome =
            socket_a.send_wireguard([21; 32], &payload).await.unwrap();
        assert!(outcome.sent_direct);
        assert!(!outcome.discovery_started);
        let event =
            tokio::time::timeout(Duration::from_secs(1), socket_b.next_event())
                .await
                .unwrap()
                .unwrap();
        assert!(matches!(
            event,
            TailscaleDiscoSocketEvent::WireguardPacket {
                peer,
                packet,
                path: TailscalePacketPath::Direct(source),
            } if peer == [11; 32] && packet == payload && source == address_a
        ));
        socket_a.close().await.unwrap();
        socket_b.close().await.unwrap();
    }

    #[tokio::test]
    async fn dual_stack_socket_sends_and_receives_ipv6() {
        let mut socket = TailscaleDiscoSocket::bind_dual_stack(
            0,
            None,
            TailscaleDiscoSocketOptions::new([31; 32], [32; 32]),
        )
        .await
        .unwrap();
        assert!(socket.local_addrs().iter().any(SocketAddr::is_ipv4));
        let Some(ipv6_local) = socket
            .local_addrs()
            .iter()
            .find(|address| address.is_ipv6())
            .copied()
        else {
            socket.close().await.unwrap();
            return;
        };
        let remote = UdpSocket::bind("[::1]:0").await.unwrap();
        let remote_addr = remote.local_addr().unwrap();
        socket
            .set_peer(TailscaleDiscoPeer {
                node_key: [41; 32],
                disco_key: [0; 32],
                home_derp_region: None,
                endpoints: vec![remote_addr],
            })
            .unwrap();
        let sent = vec![4_u8, 1, 2, 3];
        assert!(
            socket
                .send_wireguard([41; 32], &sent)
                .await
                .unwrap()
                .sent_direct
        );
        let mut received = [0_u8; 64];
        let (size, source) = tokio::time::timeout(
            Duration::from_secs(1),
            remote.recv_from(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&received[..size], sent);
        assert_eq!(source.port(), ipv6_local.port());
        let reply = [4_u8, 9, 8, 7];
        remote
            .send_to(
                &reply,
                SocketAddr::new("::1".parse().unwrap(), ipv6_local.port()),
            )
            .await
            .unwrap();
        let event =
            tokio::time::timeout(Duration::from_secs(1), socket.next_event())
                .await
                .unwrap()
                .unwrap();
        assert!(matches!(
            event,
            TailscaleDiscoSocketEvent::WireguardPacket {
                peer,
                packet,
                path: TailscalePacketPath::Direct(path_source),
            } if peer == [41; 32] && packet == reply && path_source == remote_addr
        ));
        socket.close().await.unwrap();
    }

    struct NeverPacketConnection;

    impl PacketConnection for NeverPacketConnection {
        fn send_to<'a>(
            &'a self,
            _data: &'a [u8],
            _destination: &'a SocksAddr,
        ) -> PacketFuture<'a, usize> {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::NetworkUnreachable,
                    "direct UDP disabled",
                ))
            })
        }

        fn recv_from<'a>(
            &'a self,
            _data: &'a mut [u8],
        ) -> PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(std::future::pending())
        }
    }

    struct TestDerpConnector {
        servers: mpsc::UnboundedSender<tokio::io::DuplexStream>,
        server_public_key: [u8; 32],
    }

    #[async_trait]
    impl TailscaleDerpConnector for TestDerpConnector {
        async fn connect(
            &self,
            _region_id: u32,
        ) -> Result<TailscaleDerpClient<Stream>, TailscaleDerpError> {
            let (client, server) = tokio::io::duplex(8192);
            self.servers.send(server).unwrap();
            let mut options = TailscaleDerpConnectOptions::new("derp.test");
            options.known_server_public_key = Some(self.server_public_key);
            TailscaleDerpClient::connect(
                Box::new(client) as Stream,
                [41; 32],
                options,
            )
            .await
        }
    }

    async fn consume_fast_start(server: &mut tokio::io::DuplexStream) {
        let mut suffix = [0_u8; 4];
        loop {
            suffix.rotate_left(1);
            suffix[3] = server.read_u8().await.unwrap();
            if suffix == *b"\r\n\r\n" {
                break;
            }
        }
        assert_eq!(
            read_tailscale_derp_frame(server, 256 << 10)
                .await
                .unwrap()
                .frame_type,
            TAILSCALE_DERP_FRAME_CLIENT_INFO,
        );
    }

    #[tokio::test]
    async fn dynamic_derp_configuration_requires_and_reaches_manager() {
        let actor_without_manager = TailscaleDiscoSocket::spawn(
            Arc::new(NeverPacketConnection),
            None,
            TailscaleDiscoSocketOptions::new([1; 32], [2; 32]),
        )
        .unwrap();
        assert!(matches!(
            actor_without_manager.set_home_derp_region(Some(7)).await,
            Err(TailscaleDiscoSocketError::NoDerpManager)
        ));
        actor_without_manager.close().await.unwrap();

        let manager =
            TailscaleDerpManager::spawn(TailscaleDerpManagerOptions::default());
        let actor = TailscaleDiscoSocket::spawn(
            Arc::new(NeverPacketConnection),
            Some(manager),
            TailscaleDiscoSocketOptions::new([3; 32], [4; 32]),
        )
        .unwrap();
        let (servers, _server_rx) = mpsc::unbounded_channel();
        let connector = Arc::new(TestDerpConnector {
            servers,
            server_public_key: tailscale_node_public_key([5; 32]).unwrap(),
        });
        actor.set_derp_region(7, connector).await.unwrap();
        actor.set_home_derp_region(Some(7)).await.unwrap();
        actor.remove_derp_region(7).await.unwrap();
        actor.close().await.unwrap();
    }

    async fn next_path_change(
        socket: &mut TailscaleDiscoSocket,
    ) -> ([u8; 32], TailscalePathQuality) {
        loop {
            let event = tokio::time::timeout(
                Duration::from_secs(2),
                socket.next_event(),
            )
            .await
            .expect("path discovery timed out")
            .expect("socket event stream closed");
            if let TailscaleDiscoSocketEvent::PathChanged {
                peer,
                best: Some(best),
            } = event
            {
                return (peer, best);
            }
        }
    }

    #[tokio::test]
    async fn two_udp_actors_discover_and_carry_wireguard_packets() {
        let node_a = [11; 32];
        let node_b = [12; 32];
        let disco_private_a = [21; 32];
        let disco_private_b = [22; 32];
        let disco_a = tailscale_disco_public_key(disco_private_a).unwrap();
        let disco_b = tailscale_disco_public_key(disco_private_b).unwrap();
        let mut a = TailscaleDiscoSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
            TailscaleDiscoSocketOptions::new(node_a, disco_private_a),
        )
        .await
        .unwrap();
        let mut b = TailscaleDiscoSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
            TailscaleDiscoSocketOptions::new(node_b, disco_private_b),
        )
        .await
        .unwrap();
        let addr_a = a.local_addr().unwrap();
        let addr_b = b.local_addr().unwrap();
        a.set_peer(TailscaleDiscoPeer {
            node_key: node_b,
            disco_key: disco_b,
            home_derp_region: None,
            endpoints: vec![addr_b],
        })
        .unwrap();
        b.set_peer(TailscaleDiscoPeer {
            node_key: node_a,
            disco_key: disco_a,
            home_derp_region: None,
            endpoints: vec![addr_a],
        })
        .unwrap();

        a.probe_peer(node_b).unwrap();
        let (peer, best) = next_path_change(&mut a).await;
        assert_eq!(peer, node_b);
        assert_eq!(best.endpoint, addr_b);
        assert_eq!(
            a.peer_path(node_b).await.unwrap().unwrap().best,
            Some(best.clone())
        );
        a.set_peer(TailscaleDiscoPeer {
            node_key: node_b,
            disco_key: disco_b,
            home_derp_region: Some(9),
            endpoints: vec![addr_b],
        })
        .unwrap();
        assert_eq!(
            a.peer_path(node_b).await.unwrap().unwrap().best,
            Some(best)
        );

        let outcome =
            a.send_wireguard(node_b, b"wireguard-data").await.unwrap();
        assert!(outcome.sent_direct);
        assert_eq!(outcome.derp_region, None);

        loop {
            let event =
                tokio::time::timeout(Duration::from_secs(2), b.next_event())
                    .await
                    .expect("WireGuard delivery timed out")
                    .expect("socket event stream closed");
            if let TailscaleDiscoSocketEvent::WireguardPacket {
                peer,
                packet,
                path,
            } = event
            {
                assert_eq!(peer, node_a);
                assert_eq!(packet, b"wireguard-data");
                assert_eq!(path, TailscalePacketPath::Direct(addr_a));
                break;
            }
        }
        assert_eq!(a.status().sent_direct_packets, 1);
        assert_eq!(b.status().received_direct_packets, 1);
        a.close().await.unwrap();
        b.close().await.unwrap();
    }

    #[tokio::test]
    async fn unknown_and_oversize_sends_fail_closed() {
        let socket = TailscaleDiscoSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
            TailscaleDiscoSocketOptions::new([31; 32], [32; 32]),
        )
        .await
        .unwrap();
        assert!(matches!(
            socket.send_wireguard([33; 32], b"unknown").await,
            Err(TailscaleDiscoSocketError::UnknownPeer)
        ));
        assert!(matches!(
            socket
                .send_wireguard(
                    [33; 32],
                    &vec![0; TAILSCALE_DERP_MAX_PACKET_SIZE + 1]
                )
                .await,
            Err(TailscaleDiscoSocketError::PacketTooLarge)
        ));
        socket.close().await.unwrap();
    }

    #[tokio::test]
    async fn actor_routes_wireguard_packets_through_derp_manager() {
        let (server_tx, mut server_rx) = mpsc::unbounded_channel();
        let connector = Arc::new(TestDerpConnector {
            servers: server_tx,
            server_public_key: tailscale_node_public_key([42; 32]).unwrap(),
        });
        let manager =
            TailscaleDerpManager::spawn(TailscaleDerpManagerOptions {
                region_event_poll_interval: Duration::from_millis(1),
                region_supervisor: TailscaleDerpRegionSupervisorOptions {
                    initial_backoff: Duration::from_millis(1),
                    maximum_backoff: Duration::from_millis(2),
                },
                ..Default::default()
            });
        manager.set_region(1, connector).unwrap();
        manager.set_home_region(Some(1)).unwrap();

        let node = [43; 32];
        let remote_disco = tailscale_disco_public_key([44; 32]).unwrap();
        let mut actor = TailscaleDiscoSocket::spawn(
            Arc::new(NeverPacketConnection),
            Some(manager),
            TailscaleDiscoSocketOptions::new([45; 32], [46; 32]),
        )
        .unwrap();
        actor
            .set_peer(TailscaleDiscoPeer {
                node_key: node,
                disco_key: remote_disco,
                home_derp_region: Some(1),
                endpoints: Vec::new(),
            })
            .unwrap();

        let mut server = server_rx.recv().await.unwrap();
        consume_fast_start(&mut server).await;
        let outcome = actor.send_wireguard(node, b"outgoing").await.unwrap();
        assert_eq!(outcome.derp_region, Some(1));
        loop {
            let frame =
                read_tailscale_derp_frame(&mut server, 1024).await.unwrap();
            if frame.frame_type == TAILSCALE_DERP_FRAME_SEND_PACKET {
                assert_eq!(&frame.payload[..32], &node);
                assert_eq!(&frame.payload[32..], b"outgoing");
                break;
            }
        }

        let mut incoming = node.to_vec();
        incoming.extend_from_slice(b"incoming");
        write_tailscale_derp_frame(
            &mut server,
            TAILSCALE_DERP_FRAME_RECV_PACKET,
            &incoming,
            1024,
        )
        .await
        .unwrap();
        loop {
            let event = tokio::time::timeout(
                Duration::from_secs(2),
                actor.next_event(),
            )
            .await
            .expect("DERP receive timed out")
            .expect("actor event stream closed");
            if let TailscaleDiscoSocketEvent::WireguardPacket {
                peer,
                packet,
                path,
            } = event
            {
                assert_eq!(peer, node);
                assert_eq!(packet, b"incoming");
                assert_eq!(path, TailscalePacketPath::Derp { region_id: 1 });
                break;
            }
        }

        let actor_disco = tailscale_disco_public_key([46; 32]).unwrap();
        let ping = seal_tailscale_disco_packet(
            [44; 32],
            actor_disco,
            &TailscaleDiscoMessage::Ping(TailscaleDiscoPing {
                transaction_id: [47; 12],
                node_key: Some(node),
                padding: 0,
            }),
        )
        .unwrap();
        let mut incoming_ping = node.to_vec();
        incoming_ping.extend_from_slice(&ping);
        write_tailscale_derp_frame(
            &mut server,
            TAILSCALE_DERP_FRAME_RECV_PACKET,
            &incoming_ping,
            2048,
        )
        .await
        .unwrap();
        loop {
            let frame =
                read_tailscale_derp_frame(&mut server, 2048).await.unwrap();
            if frame.frame_type != TAILSCALE_DERP_FRAME_SEND_PACKET {
                continue;
            }
            let pong =
                open_tailscale_disco_packet([44; 32], &frame.payload[32..])
                    .unwrap();
            let TailscaleDiscoMessage::Pong(pong) = pong.message else {
                panic!("actor did not answer DERP disco Ping with Pong");
            };
            assert_eq!(pong.transaction_id, [47; 12]);
            assert_eq!(pong.source, derp_magic_address(1));
            break;
        }
        assert_eq!(actor.status().sent_derp_packets, 2);
        assert_eq!(actor.status().received_derp_packets, 2);
        actor.close().await.unwrap();
    }
}
