//! Dynamic WireGuard engine carried by the Tailscale disco/DERP actor.
//!
//! Tailscale node keys are WireGuard NoiseIK keys. This actor reuses the
//! crate's audited BoringTun peer state machine, but obtains peer endpoints
//! and allowed prefixes from streamed control-plane netmaps. It deliberately
//! exposes decrypted IP packets rather than imposing a CLI or process
//! boundary; a userspace or platform network can be layered above it.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};

use boringtun::noise::Tunn;
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::MissedTickBehavior,
};
use tokio_util::sync::CancellationToken;

use crate::endpoint::wireguard::{WireGuardAction, WireGuardPeerTunnel};

use super::{
    tailscale_control_types::{TailscaleNetmapState, TailscaleNode},
    tailscale_derp_supervisor::TailscaleDerpConnector,
    tailscale_disco_socket::{
        TailscaleDiscoPeer, TailscaleDiscoSocket, TailscaleDiscoSocketError,
        TailscaleDiscoSocketEvent, TailscaleDiscoSocketStatus,
        TailscalePacketPath,
    },
};

const COMMAND_QUEUE_DEPTH: usize = 32;
const EVENT_QUEUE_DEPTH: usize = 32;
const DEFAULT_WIREGUARD_MTU: usize = 1280;
const DEFAULT_TIMER_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Error)]
pub enum TailscaleWireGuardError {
    #[error("invalid Tailscale WireGuard configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid IP packet for Tailscale WireGuard")]
    InvalidIpPacket,
    #[error("no Tailscale WireGuard peer routes {0}")]
    NoRoute(IpAddr),
    #[error("unknown Tailscale WireGuard peer")]
    UnknownPeer,
    #[error("Tailscale WireGuard packet exceeds MTU {0}")]
    PacketTooLarge(usize),
    #[error("Tailscale WireGuard command queue is full")]
    CommandQueueFull,
    #[error("Tailscale WireGuard engine is closed")]
    Closed,
    #[error(transparent)]
    Transport(#[from] TailscaleDiscoSocketError),
    #[error("Tailscale WireGuard engine failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleWireGuardOptions {
    pub private_key: [u8; 32],
    pub mtu: usize,
    pub persistent_keepalive_interval: u16,
    pub timer_interval: Duration,
}

impl TailscaleWireGuardOptions {
    pub fn new(private_key: [u8; 32]) -> Self {
        Self {
            private_key,
            mtu: DEFAULT_WIREGUARD_MTU,
            persistent_keepalive_interval: 0,
            timer_interval: DEFAULT_TIMER_INTERVAL,
        }
    }

    fn normalized(mut self) -> Result<Self, TailscaleWireGuardError> {
        if self.private_key == [0; 32] {
            return Err(TailscaleWireGuardError::InvalidConfiguration(
                "node private key is zero".into(),
            ));
        }
        if self.mtu == 0 {
            self.mtu = DEFAULT_WIREGUARD_MTU;
        }
        if self.timer_interval.is_zero() {
            self.timer_interval = DEFAULT_TIMER_INTERVAL;
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleWireGuardPeer {
    pub node_key: [u8; 32],
    pub disco_key: [u8; 32],
    pub home_derp_region: Option<u32>,
    pub endpoints: Vec<SocketAddr>,
    pub allowed_ips: Vec<ipnet::IpNet>,
}

impl TailscaleWireGuardPeer {
    /// Convert one control-plane node into data-plane configuration.
    /// Expired nodes are intentionally omitted. Legacy WireGuard-only nodes
    /// without a disco key use their static direct endpoints and DERP route.
    pub fn from_node(
        node: &TailscaleNode,
    ) -> Result<Option<Self>, TailscaleWireGuardError> {
        if node.expired {
            return Ok(None);
        }
        if node.key.is_zero() {
            return Err(invalid_peer(node, "node key is zero"));
        }
        let prefixes = if node.allowed_ips.is_empty() {
            &node.addresses
        } else {
            &node.allowed_ips
        };
        if prefixes.is_empty() {
            return Err(invalid_peer(node, "allowed IP list is empty"));
        }
        let allowed_ips = prefixes
            .iter()
            .map(|prefix| {
                prefix.parse().map_err(|_| {
                    invalid_peer(node, format!("invalid allowed IP {prefix:?}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let endpoints = node
            .endpoints
            .iter()
            .map(|endpoint| {
                endpoint.parse().map_err(|_| {
                    invalid_peer(node, format!("invalid endpoint {endpoint:?}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if node.disco_key.is_zero() && endpoints.is_empty() {
            return Err(invalid_peer(
                node,
                "WireGuard-only peer has no direct endpoint",
            ));
        }
        Ok(Some(Self {
            node_key: *node.key.as_bytes(),
            disco_key: *node.disco_key.as_bytes(),
            home_derp_region: u32::try_from(node.home_derp)
                .ok()
                .filter(|id| *id != 0),
            endpoints,
            allowed_ips,
        }))
    }

    fn disco_peer(&self) -> TailscaleDiscoPeer {
        TailscaleDiscoPeer {
            node_key: self.node_key,
            disco_key: self.disco_key,
            home_derp_region: self.home_derp_region,
            endpoints: self.endpoints.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleWireGuardEvent {
    IpPacket {
        peer: [u8; 32],
        source: IpAddr,
        packet: Vec<u8>,
        path: TailscalePacketPath,
    },
    Transport(TailscaleDiscoSocketEvent),
    Error(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleWireGuardStatus {
    pub peers: usize,
    pub encrypted_packets_sent: u64,
    pub encrypted_packets_received: u64,
    pub ip_packets_sent: u64,
    pub ip_packets_received: u64,
    pub dropped_source_packets: u64,
    pub last_error: Option<String>,
    pub transport: TailscaleDiscoSocketStatus,
}

enum EngineCommand {
    ReplacePeers {
        peers: Vec<TailscaleWireGuardPeer>,
        result: oneshot::Sender<Result<(), TailscaleWireGuardError>>,
    },
    SendIp {
        packet: Vec<u8>,
        result: oneshot::Sender<Result<usize, TailscaleWireGuardError>>,
    },
    Probe([u8; 32]),
    ConnectivityChanged,
    SetDerpRegion {
        region_id: u32,
        connector: Arc<dyn TailscaleDerpConnector>,
        result: oneshot::Sender<Result<(), TailscaleWireGuardError>>,
    },
    RemoveDerpRegion {
        region_id: u32,
        result: oneshot::Sender<Result<(), TailscaleWireGuardError>>,
    },
    SetHomeDerpRegion {
        region_id: Option<u32>,
        result: oneshot::Sender<Result<(), TailscaleWireGuardError>>,
    },
}

struct PeerRuntime {
    config: TailscaleWireGuardPeer,
    tunnel: WireGuardPeerTunnel,
}

pub struct TailscaleWireGuardEngine {
    commands: mpsc::Sender<EngineCommand>,
    events: mpsc::Receiver<TailscaleWireGuardEvent>,
    status: Arc<RwLock<TailscaleWireGuardStatus>>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

/// Cloneable control surface for an engine whose event stream is owned by a
/// userspace or platform network.
#[derive(Clone)]
pub struct TailscaleWireGuardHandle {
    commands: mpsc::Sender<EngineCommand>,
    status: Arc<RwLock<TailscaleWireGuardStatus>>,
}

impl TailscaleWireGuardEngine {
    pub fn spawn(
        socket: TailscaleDiscoSocket,
        options: TailscaleWireGuardOptions,
    ) -> Result<Self, TailscaleWireGuardError> {
        let options = options.normalized()?;
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE_DEPTH);
        let status = Arc::new(RwLock::new(TailscaleWireGuardStatus {
            transport: socket.status(),
            ..Default::default()
        }));
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run_engine(
            socket,
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
            cancellation,
            task: Some(task),
        })
    }

    pub async fn set_peers(
        &self,
        peers: Vec<TailscaleWireGuardPeer>,
    ) -> Result<(), TailscaleWireGuardError> {
        self.handle().set_peers(peers).await
    }

    pub async fn set_netmap(
        &self,
        netmap: &TailscaleNetmapState,
    ) -> Result<(), TailscaleWireGuardError> {
        self.handle().set_netmap(netmap).await
    }

    pub async fn send_ip_packet(
        &self,
        packet: &[u8],
    ) -> Result<usize, TailscaleWireGuardError> {
        self.handle().send_ip_packet(packet).await
    }

    pub fn probe_peer(
        &self,
        peer: [u8; 32],
    ) -> Result<(), TailscaleWireGuardError> {
        self.handle().probe_peer(peer)
    }

    pub fn note_connectivity_change(
        &self,
    ) -> Result<(), TailscaleWireGuardError> {
        self.handle().note_connectivity_change()
    }

    pub fn handle(&self) -> TailscaleWireGuardHandle {
        TailscaleWireGuardHandle {
            commands: self.commands.clone(),
            status: self.status.clone(),
        }
    }

    pub async fn next_event(&mut self) -> Option<TailscaleWireGuardEvent> {
        self.events.recv().await
    }

    pub fn status(&self) -> TailscaleWireGuardStatus {
        self.handle().status()
    }

    pub async fn close(mut self) -> Result<(), TailscaleWireGuardError> {
        self.cancellation.cancel();
        self.task
            .take()
            .expect("Tailscale WireGuard engine task is present")
            .await
            .map_err(|error| {
                io::Error::other(format!("engine task failed: {error}"))
            })?;
        Ok(())
    }
}

impl TailscaleWireGuardHandle {
    pub async fn set_peers(
        &self,
        peers: Vec<TailscaleWireGuardPeer>,
    ) -> Result<(), TailscaleWireGuardError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(EngineCommand::ReplacePeers {
                peers,
                result: result_tx,
            })
            .await
            .map_err(|_| TailscaleWireGuardError::Closed)?;
        result_rx
            .await
            .map_err(|_| TailscaleWireGuardError::Closed)?
    }

    pub async fn set_netmap(
        &self,
        netmap: &TailscaleNetmapState,
    ) -> Result<(), TailscaleWireGuardError> {
        let peers = netmap
            .peers
            .values()
            .filter_map(|node| {
                TailscaleWireGuardPeer::from_node(node).transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.set_peers(peers).await
    }

    pub async fn send_ip_packet(
        &self,
        packet: &[u8],
    ) -> Result<usize, TailscaleWireGuardError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(EngineCommand::SendIp {
                packet: packet.to_vec(),
                result: result_tx,
            })
            .await
            .map_err(|_| TailscaleWireGuardError::Closed)?;
        result_rx
            .await
            .map_err(|_| TailscaleWireGuardError::Closed)?
    }

    pub fn probe_peer(
        &self,
        peer: [u8; 32],
    ) -> Result<(), TailscaleWireGuardError> {
        self.try_command(EngineCommand::Probe(peer))
    }

    pub fn note_connectivity_change(
        &self,
    ) -> Result<(), TailscaleWireGuardError> {
        self.try_command(EngineCommand::ConnectivityChanged)
    }

    pub async fn set_derp_region(
        &self,
        region_id: u32,
        connector: Arc<dyn TailscaleDerpConnector>,
    ) -> Result<(), TailscaleWireGuardError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(EngineCommand::SetDerpRegion {
                region_id,
                connector,
                result: result_tx,
            })
            .await
            .map_err(|_| TailscaleWireGuardError::Closed)?;
        result_rx
            .await
            .map_err(|_| TailscaleWireGuardError::Closed)?
    }

    pub async fn remove_derp_region(
        &self,
        region_id: u32,
    ) -> Result<(), TailscaleWireGuardError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(EngineCommand::RemoveDerpRegion {
                region_id,
                result: result_tx,
            })
            .await
            .map_err(|_| TailscaleWireGuardError::Closed)?;
        result_rx
            .await
            .map_err(|_| TailscaleWireGuardError::Closed)?
    }

    pub async fn set_home_derp_region(
        &self,
        region_id: Option<u32>,
    ) -> Result<(), TailscaleWireGuardError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(EngineCommand::SetHomeDerpRegion {
                region_id,
                result: result_tx,
            })
            .await
            .map_err(|_| TailscaleWireGuardError::Closed)?;
        result_rx
            .await
            .map_err(|_| TailscaleWireGuardError::Closed)?
    }

    pub fn status(&self) -> TailscaleWireGuardStatus {
        self.status
            .read()
            .map(|status| status.clone())
            .unwrap_or_default()
    }

    fn try_command(
        &self,
        command: EngineCommand,
    ) -> Result<(), TailscaleWireGuardError> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    TailscaleWireGuardError::CommandQueueFull
                }
                mpsc::error::TrySendError::Closed(_) => {
                    TailscaleWireGuardError::Closed
                }
            })
    }
}

impl Drop for TailscaleWireGuardEngine {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

async fn run_engine(
    mut socket: TailscaleDiscoSocket,
    options: TailscaleWireGuardOptions,
    mut commands: mpsc::Receiver<EngineCommand>,
    events: mpsc::Sender<TailscaleWireGuardEvent>,
    status: Arc<RwLock<TailscaleWireGuardStatus>>,
    cancellation: CancellationToken,
) {
    let mut peers = BTreeMap::<[u8; 32], PeerRuntime>::new();
    let mut next_index = 1_u32;
    let mut timer = tokio::time::interval(options.timer_interval);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            command = commands.recv() => {
                let Some(command) = command else { break };
                handle_command(
                    command,
                    &socket,
                    &options,
                    &mut peers,
                    &mut next_index,
                    &events,
                    &status,
                    &cancellation,
                ).await;
            }
            event = socket.next_event() => {
                let Some(event) = event else { break };
                if let Err(error) = handle_transport_event(
                    event,
                    &socket,
                    &peers,
                    &events,
                    &status,
                    &cancellation,
                ).await {
                    record_error(&status, &events, error.to_string());
                }
            }
            _ = timer.tick() => {
                for (peer, runtime) in &peers {
                    match runtime.tunnel.update_timers() {
                        Ok(action) => {
                            if let Err(error) = deliver_action(
                                *peer,
                                runtime,
                                action,
                                None,
                                &socket,
                                &events,
                                &status,
                                &cancellation,
                                false,
                            ).await {
                                record_error(&status, &events, error.to_string());
                            }
                        }
                        Err(error) => record_error(&status, &events, error.to_string()),
                    }
                }
            }
        }
        update_transport_status(&status, socket.status());
    }
    let _ = socket.close().await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_command(
    command: EngineCommand,
    socket: &TailscaleDiscoSocket,
    options: &TailscaleWireGuardOptions,
    peers: &mut BTreeMap<[u8; 32], PeerRuntime>,
    next_index: &mut u32,
    events: &mpsc::Sender<TailscaleWireGuardEvent>,
    status: &RwLock<TailscaleWireGuardStatus>,
    cancellation: &CancellationToken,
) {
    match command {
        EngineCommand::ReplacePeers {
            peers: configured,
            result,
        } => {
            let response = replace_peers(
                configured, socket, options, peers, next_index, status,
            )
            .await;
            let _ = result.send(response);
        }
        EngineCommand::SendIp { packet, result } => {
            let response = send_ip_packet(
                &packet,
                socket,
                options,
                peers,
                events,
                status,
                cancellation,
            )
            .await;
            let _ = result.send(response);
        }
        EngineCommand::Probe(peer) => {
            if let Err(error) = socket.probe_peer_async(peer).await {
                record_error(status, events, error.to_string());
            }
        }
        EngineCommand::ConnectivityChanged => {
            if let Err(error) = socket.note_connectivity_change() {
                record_error(status, events, error.to_string());
            }
        }
        EngineCommand::SetDerpRegion {
            region_id,
            connector,
            result,
        } => {
            let _ = result.send(
                socket
                    .set_derp_region(region_id, connector)
                    .await
                    .map_err(Into::into),
            );
        }
        EngineCommand::RemoveDerpRegion { region_id, result } => {
            let _ = result.send(
                socket
                    .remove_derp_region(region_id)
                    .await
                    .map_err(Into::into),
            );
        }
        EngineCommand::SetHomeDerpRegion { region_id, result } => {
            let _ = result.send(
                socket
                    .set_home_derp_region(region_id)
                    .await
                    .map_err(Into::into),
            );
        }
    }
}

async fn replace_peers(
    configured: Vec<TailscaleWireGuardPeer>,
    socket: &TailscaleDiscoSocket,
    options: &TailscaleWireGuardOptions,
    peers: &mut BTreeMap<[u8; 32], PeerRuntime>,
    next_index: &mut u32,
    status: &RwLock<TailscaleWireGuardStatus>,
) -> Result<(), TailscaleWireGuardError> {
    let mut seen = BTreeSet::new();
    for peer in &configured {
        validate_configured_peer(peer)?;
        if !seen.insert(peer.node_key) {
            return Err(TailscaleWireGuardError::InvalidConfiguration(
                "duplicate peer node key".into(),
            ));
        }
    }

    let removed = peers
        .keys()
        .filter(|peer| !seen.contains(*peer))
        .copied()
        .collect::<Vec<_>>();
    for peer in &configured {
        socket.set_peer_async(peer.disco_peer()).await?;
    }
    for peer in &removed {
        socket.remove_peer_async(*peer).await?;
    }

    let mut previous = std::mem::take(peers);
    for config in configured {
        let runtime =
            if let Some(mut runtime) = previous.remove(&config.node_key) {
                runtime.config = config;
                runtime
            } else {
                let index = *next_index;
                *next_index = next_index.checked_add(1).ok_or_else(|| {
                    TailscaleWireGuardError::InvalidConfiguration(
                        "peer receiver index space exhausted".into(),
                    )
                })?;
                PeerRuntime {
                    tunnel: WireGuardPeerTunnel::new(
                        options.private_key,
                        config.node_key,
                        None,
                        options.persistent_keepalive_interval,
                        index,
                    ),
                    config,
                }
            };
        peers.insert(runtime.config.node_key, runtime);
    }
    update_status(status, |status| status.peers = peers.len());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_ip_packet(
    packet: &[u8],
    socket: &TailscaleDiscoSocket,
    options: &TailscaleWireGuardOptions,
    peers: &BTreeMap<[u8; 32], PeerRuntime>,
    events: &mpsc::Sender<TailscaleWireGuardEvent>,
    status: &RwLock<TailscaleWireGuardStatus>,
    cancellation: &CancellationToken,
) -> Result<usize, TailscaleWireGuardError> {
    if packet.len() > options.mtu {
        return Err(TailscaleWireGuardError::PacketTooLarge(options.mtu));
    }
    let destination = Tunn::dst_address(packet)
        .ok_or(TailscaleWireGuardError::InvalidIpPacket)?;
    let (peer, runtime) = peer_for_destination(peers, destination)
        .ok_or(TailscaleWireGuardError::NoRoute(destination))?;
    let action = runtime.tunnel.encapsulate(packet)?;
    deliver_action(
        peer,
        runtime,
        action,
        None,
        socket,
        events,
        status,
        cancellation,
        false,
    )
    .await?;
    update_status(status, |status| status.ip_packets_sent += 1);
    Ok(packet.len())
}

fn peer_for_destination(
    peers: &BTreeMap<[u8; 32], PeerRuntime>,
    destination: IpAddr,
) -> Option<([u8; 32], &PeerRuntime)> {
    peers
        .iter()
        .filter_map(|(key, runtime)| {
            runtime
                .config
                .allowed_ips
                .iter()
                .filter(|prefix| prefix.contains(&destination))
                .map(ipnet::IpNet::prefix_len)
                .max()
                .map(|prefix| (prefix, *key, runtime))
        })
        .max_by_key(|(prefix, key, _)| (*prefix, *key))
        .map(|(_, key, runtime)| (key, runtime))
}

async fn handle_transport_event(
    event: TailscaleDiscoSocketEvent,
    socket: &TailscaleDiscoSocket,
    peers: &BTreeMap<[u8; 32], PeerRuntime>,
    events: &mpsc::Sender<TailscaleWireGuardEvent>,
    status: &RwLock<TailscaleWireGuardStatus>,
    cancellation: &CancellationToken,
) -> Result<(), TailscaleWireGuardError> {
    let TailscaleDiscoSocketEvent::WireguardPacket { peer, packet, path } =
        event
    else {
        emit(
            events,
            TailscaleWireGuardEvent::Transport(event),
            cancellation,
        )
        .await?;
        return Ok(());
    };
    let Some(runtime) = peers.get(&peer) else {
        return Err(TailscaleWireGuardError::UnknownPeer);
    };
    update_status(status, |status| status.encrypted_packets_received += 1);
    let source = match path {
        TailscalePacketPath::Direct(address) => Some(address.ip()),
        TailscalePacketPath::Derp { .. } => None,
    };
    let action = runtime.tunnel.decapsulate(source, &packet)?;
    deliver_action(
        peer,
        runtime,
        action,
        Some(path),
        socket,
        events,
        status,
        cancellation,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn deliver_action(
    peer: [u8; 32],
    runtime: &PeerRuntime,
    mut action: WireGuardAction,
    path: Option<TailscalePacketPath>,
    socket: &TailscaleDiscoSocket,
    events: &mpsc::Sender<TailscaleWireGuardEvent>,
    status: &RwLock<TailscaleWireGuardStatus>,
    cancellation: &CancellationToken,
    drain_queued: bool,
) -> Result<(), TailscaleWireGuardError> {
    loop {
        match action {
            WireGuardAction::WriteToNetwork(packet) => {
                socket.send_wireguard(peer, &packet).await?;
                update_status(status, |status| {
                    status.encrypted_packets_sent += 1
                });
            }
            WireGuardAction::WriteToTunnelV4(packet, source)
            | WireGuardAction::WriteToTunnelV6(packet, source) => {
                if !runtime
                    .config
                    .allowed_ips
                    .iter()
                    .any(|prefix| prefix.contains(&source))
                {
                    update_status(status, |status| {
                        status.dropped_source_packets += 1
                    });
                } else {
                    let path = path.clone().ok_or_else(|| {
                        io::Error::other(
                            "unexpected WireGuard tunnel packet from local action",
                        )
                    })?;
                    emit(
                        events,
                        TailscaleWireGuardEvent::IpPacket {
                            peer,
                            source,
                            packet,
                            path,
                        },
                        cancellation,
                    )
                    .await?;
                    update_status(status, |status| {
                        status.ip_packets_received += 1
                    });
                }
            }
            WireGuardAction::Done => return Ok(()),
        }
        if !drain_queued {
            return Ok(());
        }
        action = runtime.tunnel.decapsulate(None, &[])?;
    }
}

async fn emit(
    events: &mpsc::Sender<TailscaleWireGuardEvent>,
    event: TailscaleWireGuardEvent,
    cancellation: &CancellationToken,
) -> Result<(), TailscaleWireGuardError> {
    tokio::select! {
        _ = cancellation.cancelled() => Err(TailscaleWireGuardError::Closed),
        result = events.send(event) => result.map_err(|_| TailscaleWireGuardError::Closed),
    }
}

fn validate_configured_peer(
    peer: &TailscaleWireGuardPeer,
) -> Result<(), TailscaleWireGuardError> {
    if peer.node_key == [0; 32] {
        return Err(TailscaleWireGuardError::InvalidConfiguration(
            "peer node key is zero".into(),
        ));
    }
    if peer.disco_key == [0; 32] && peer.endpoints.is_empty() {
        return Err(TailscaleWireGuardError::InvalidConfiguration(
            "WireGuard-only peer has no direct endpoint".into(),
        ));
    }
    if peer.allowed_ips.is_empty() {
        return Err(TailscaleWireGuardError::InvalidConfiguration(
            "peer allowed IP list is empty".into(),
        ));
    }
    Ok(())
}

fn invalid_peer(
    node: &TailscaleNode,
    message: impl AsRef<str>,
) -> TailscaleWireGuardError {
    TailscaleWireGuardError::InvalidConfiguration(format!(
        "peer {} (ID {}): {}",
        node.name,
        node.id,
        message.as_ref()
    ))
}

fn record_error(
    status: &RwLock<TailscaleWireGuardStatus>,
    events: &mpsc::Sender<TailscaleWireGuardEvent>,
    error: String,
) {
    update_status(status, |status| status.last_error = Some(error.clone()));
    let _ = events.try_send(TailscaleWireGuardEvent::Error(error));
}

fn update_transport_status(
    status: &RwLock<TailscaleWireGuardStatus>,
    transport: TailscaleDiscoSocketStatus,
) {
    update_status(status, |status| status.transport = transport);
}

fn update_status(
    status: &RwLock<TailscaleWireGuardStatus>,
    update: impl FnOnce(&mut TailscaleWireGuardStatus),
) {
    if let Ok(mut status) = status.write() {
        update(&mut status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use boringtun::x25519::{PublicKey, StaticSecret};

    use crate::protocol::{
        tailscale_control_types::{
            TailscaleDiscoPublicKey, TailscaleNodePublicKey,
        },
        tailscale_disco::tailscale_disco_public_key,
        tailscale_disco_socket::TailscaleDiscoSocketOptions,
    };

    fn node_keys(seed: u8) -> ([u8; 32], [u8; 32]) {
        let private = [seed; 32];
        let public = PublicKey::from(&StaticSecret::from(private)).to_bytes();
        (private, public)
    }

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        vec![
            0x45,
            0,
            0,
            24,
            0,
            0,
            0,
            0,
            64,
            17,
            0,
            0,
            source[0],
            source[1],
            source[2],
            source[3],
            destination[0],
            destination[1],
            destination[2],
            destination[3],
            b'p',
            b'i',
            b'n',
            b'g',
        ]
    }

    fn peer(
        node_key: [u8; 32],
        disco_key: [u8; 32],
        endpoint: SocketAddr,
        allowed_ip: &str,
    ) -> TailscaleWireGuardPeer {
        TailscaleWireGuardPeer {
            node_key,
            disco_key,
            home_derp_region: None,
            endpoints: vec![endpoint],
            allowed_ips: vec![allowed_ip.parse().unwrap()],
        }
    }

    async fn wait_direct_path(
        engine: &mut TailscaleWireGuardEngine,
        peer: [u8; 32],
    ) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(TailscaleWireGuardEvent::Transport(
                    TailscaleDiscoSocketEvent::PathChanged {
                        peer: changed,
                        best: Some(_),
                    },
                )) = engine.next_event().await
                    && changed == peer
                {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn netmap_peer_conversion_is_strict_and_omits_expired_nodes() {
        let mut node = TailscaleNode {
            id: 7,
            name: "peer.tailnet".into(),
            key: TailscaleNodePublicKey::from_bytes([1; 32]),
            disco_key: TailscaleDiscoPublicKey::from_bytes([2; 32]),
            allowed_ips: vec![
                "100.64.0.7/32".into(),
                "fd7a:115c:a1e0::7/128".into(),
            ],
            endpoints: vec!["192.0.2.7:41641".into()],
            home_derp: 12,
            ..Default::default()
        };
        let peer = TailscaleWireGuardPeer::from_node(&node).unwrap().unwrap();
        assert_eq!(peer.home_derp_region, Some(12));
        assert_eq!(peer.allowed_ips.len(), 2);
        assert_eq!(
            peer.endpoints,
            ["192.0.2.7:41641".parse::<SocketAddr>().unwrap()]
        );

        node.expired = true;
        assert!(TailscaleWireGuardPeer::from_node(&node).unwrap().is_none());
        node.expired = false;
        node.allowed_ips = vec!["not-a-prefix".into()];
        assert!(TailscaleWireGuardPeer::from_node(&node).is_err());

        node.allowed_ips = vec!["100.64.0.7/32".into()];
        node.disco_key = TailscaleDiscoPublicKey::default();
        let legacy = TailscaleWireGuardPeer::from_node(&node).unwrap().unwrap();
        assert_eq!(legacy.disco_key, [0; 32]);
        node.endpoints.clear();
        assert!(TailscaleWireGuardPeer::from_node(&node).is_err());
        assert!(validate_configured_peer(&legacy).is_ok());
    }

    #[tokio::test]
    async fn two_engines_handshake_and_exchange_ip_over_direct_disco_path() {
        let (private_a, node_a) = node_keys(61);
        let (private_b, node_b) = node_keys(62);
        let disco_private_a = [63; 32];
        let disco_private_b = [64; 32];
        let disco_a = tailscale_disco_public_key(disco_private_a).unwrap();
        let disco_b = tailscale_disco_public_key(disco_private_b).unwrap();

        let socket_a = TailscaleDiscoSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
            TailscaleDiscoSocketOptions::new(node_a, disco_private_a),
        )
        .await
        .unwrap();
        let address_a = socket_a.local_addr().unwrap();
        let socket_b = TailscaleDiscoSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
            TailscaleDiscoSocketOptions::new(node_b, disco_private_b),
        )
        .await
        .unwrap();
        let address_b = socket_b.local_addr().unwrap();

        let mut engine_a = TailscaleWireGuardEngine::spawn(
            socket_a,
            TailscaleWireGuardOptions::new(private_a),
        )
        .unwrap();
        let mut engine_b = TailscaleWireGuardEngine::spawn(
            socket_b,
            TailscaleWireGuardOptions::new(private_b),
        )
        .unwrap();
        engine_a
            .set_peers(vec![peer(node_b, disco_b, address_b, "100.64.0.2/32")])
            .await
            .unwrap();
        engine_b
            .set_peers(vec![peer(node_a, disco_a, address_a, "100.64.0.1/32")])
            .await
            .unwrap();
        engine_a.probe_peer(node_b).unwrap();
        engine_b.probe_peer(node_a).unwrap();
        wait_direct_path(&mut engine_a, node_b).await;
        wait_direct_path(&mut engine_b, node_a).await;

        let packet = ipv4_packet([100, 64, 0, 1], [100, 64, 0, 2]);
        assert_eq!(
            engine_a.send_ip_packet(&packet).await.unwrap(),
            packet.len()
        );
        let received = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(TailscaleWireGuardEvent::IpPacket {
                    peer,
                    source,
                    packet,
                    path,
                }) = engine_b.next_event().await
                {
                    break (peer, source, packet, path);
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(received.0, node_a);
        assert_eq!(received.1, "100.64.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(received.2, packet);
        assert!(matches!(received.3, TailscalePacketPath::Direct(_)));
        assert_eq!(engine_a.status().ip_packets_sent, 1);
        assert_eq!(engine_b.status().ip_packets_received, 1);

        engine_a.close().await.unwrap();
        engine_b.close().await.unwrap();
    }
}
