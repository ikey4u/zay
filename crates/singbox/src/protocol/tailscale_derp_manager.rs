//! Multi-region DERP routing and stale-connection management.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::MissedTickBehavior,
};
use tokio_util::sync::CancellationToken;

use super::{
    tailscale::{
        TAILSCALE_DERP_KEY_LENGTH, TAILSCALE_DERP_MAX_PACKET_SIZE,
        TailscaleDerpError,
    },
    tailscale_derp_supervisor::{
        TailscaleDerpConnector, TailscaleDerpRegionEvent,
        TailscaleDerpRegionSupervisor, TailscaleDerpRegionSupervisorOptions,
    },
};

pub const TAILSCALE_DERP_INACTIVE_CLEANUP_TIME: Duration =
    Duration::from_secs(60);
pub const TAILSCALE_DERP_CLEAN_STALE_INTERVAL: Duration =
    Duration::from_secs(15);
const REGION_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDerpManagerOptions {
    pub inactive_cleanup_time: Duration,
    pub clean_stale_interval: Duration,
    pub region_event_poll_interval: Duration,
    pub region_supervisor: TailscaleDerpRegionSupervisorOptions,
}

impl Default for TailscaleDerpManagerOptions {
    fn default() -> Self {
        Self {
            inactive_cleanup_time: TAILSCALE_DERP_INACTIVE_CLEANUP_TIME,
            clean_stale_interval: TAILSCALE_DERP_CLEAN_STALE_INTERVAL,
            region_event_poll_interval: REGION_EVENT_POLL_INTERVAL,
            region_supervisor: TailscaleDerpRegionSupervisorOptions::default(),
        }
    }
}

impl TailscaleDerpManagerOptions {
    fn normalized(&self) -> Self {
        let defaults = Self::default();
        Self {
            inactive_cleanup_time: if self.inactive_cleanup_time.is_zero() {
                defaults.inactive_cleanup_time
            } else {
                self.inactive_cleanup_time
            },
            clean_stale_interval: if self.clean_stale_interval.is_zero() {
                defaults.clean_stale_interval
            } else {
                self.clean_stale_interval
            },
            region_event_poll_interval: if self
                .region_event_poll_interval
                .is_zero()
            {
                defaults.region_event_poll_interval
            } else {
                self.region_event_poll_interval
            },
            region_supervisor: self.region_supervisor.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleDerpManagerStatus {
    pub home_region: Option<u32>,
    pub registered_regions: usize,
    pub active_regions: usize,
    pub last_selected_region: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleDerpManagerEvent {
    Region(TailscaleDerpRegionEvent),
    StaleRegionClosed { region_id: u32 },
}

enum ManagerCommand {
    SetRegion {
        region_id: u32,
        connector: Arc<dyn TailscaleDerpConnector>,
    },
    RemoveRegion(u32),
    SetHomeRegion(Option<u32>),
    SendPacket {
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
        peer_home_region: Option<u32>,
        packet: Vec<u8>,
        result: oneshot::Sender<Result<u32, TailscaleDerpError>>,
    },
}

struct RegionEntry {
    connector: Arc<dyn TailscaleDerpConnector>,
    supervisor: Option<TailscaleDerpRegionSupervisor>,
    last_write: Instant,
}

pub struct TailscaleDerpManager {
    commands: mpsc::Sender<ManagerCommand>,
    events: mpsc::Receiver<TailscaleDerpManagerEvent>,
    status: Arc<RwLock<TailscaleDerpManagerStatus>>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl TailscaleDerpManager {
    pub fn spawn(options: TailscaleDerpManagerOptions) -> Self {
        let (commands_tx, commands_rx) = mpsc::channel(32);
        let (events_tx, events_rx) = mpsc::channel(32);
        let status =
            Arc::new(RwLock::new(TailscaleDerpManagerStatus::default()));
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run_manager(
            options.normalized(),
            commands_rx,
            events_tx,
            status.clone(),
            cancellation.clone(),
        ));
        Self {
            commands: commands_tx,
            events: events_rx,
            status,
            cancellation,
            task: Some(task),
        }
    }

    pub fn set_region(
        &self,
        region_id: u32,
        connector: Arc<dyn TailscaleDerpConnector>,
    ) -> Result<(), TailscaleDerpError> {
        self.try_command(ManagerCommand::SetRegion {
            region_id,
            connector,
        })
    }

    pub fn remove_region(
        &self,
        region_id: u32,
    ) -> Result<(), TailscaleDerpError> {
        self.try_command(ManagerCommand::RemoveRegion(region_id))
    }

    pub fn set_home_region(
        &self,
        region_id: Option<u32>,
    ) -> Result<(), TailscaleDerpError> {
        self.try_command(ManagerCommand::SetHomeRegion(region_id))
    }

    /// Queue a packet using magicsock's DERP order: an already-connected peer
    /// home region, then the newest learned reverse path, then a lazy
    /// connection to the peer home region.
    pub async fn send_packet(
        &self,
        peer: [u8; TAILSCALE_DERP_KEY_LENGTH],
        peer_home_region: Option<u32>,
        packet: &[u8],
    ) -> Result<u32, TailscaleDerpError> {
        if packet.len() > TAILSCALE_DERP_MAX_PACKET_SIZE {
            return Err(TailscaleDerpError::PacketTooLarge);
        }
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(ManagerCommand::SendPacket {
                peer,
                peer_home_region,
                packet: packet.to_vec(),
                result: result_tx,
            })
            .await
            .map_err(|_| TailscaleDerpError::SessionClosed)?;
        result_rx
            .await
            .unwrap_or(Err(TailscaleDerpError::SessionClosed))
    }

    pub async fn next_event(&mut self) -> Option<TailscaleDerpManagerEvent> {
        self.events.recv().await
    }

    pub fn try_next_event(&mut self) -> Option<TailscaleDerpManagerEvent> {
        self.events.try_recv().ok()
    }

    pub fn status(&self) -> TailscaleDerpManagerStatus {
        self.status
            .read()
            .map(|value| value.clone())
            .unwrap_or_default()
    }

    pub async fn close(mut self) -> Result<(), TailscaleDerpError> {
        self.cancellation.cancel();
        self.task
            .take()
            .expect("manager task is present")
            .await
            .map_err(|error| {
                TailscaleDerpError::Io(std::io::Error::other(format!(
                    "DERP manager task failed: {error}"
                )))
            })
    }

    fn try_command(
        &self,
        command: ManagerCommand,
    ) -> Result<(), TailscaleDerpError> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    TailscaleDerpError::WriteQueueFull
                }
                mpsc::error::TrySendError::Closed(_) => {
                    TailscaleDerpError::SessionClosed
                }
            })
    }
}

impl Drop for TailscaleDerpManager {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

async fn run_manager(
    options: TailscaleDerpManagerOptions,
    mut commands: mpsc::Receiver<ManagerCommand>,
    events: mpsc::Sender<TailscaleDerpManagerEvent>,
    status: Arc<RwLock<TailscaleDerpManagerStatus>>,
    cancellation: CancellationToken,
) {
    let mut regions = HashMap::<u32, RegionEntry>::new();
    let mut home_region = None;
    let mut event_poll =
        tokio::time::interval(options.region_event_poll_interval);
    event_poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut cleanup = tokio::time::interval(options.clean_stale_interval);
    cleanup.set_missed_tick_behavior(MissedTickBehavior::Delay);
    cleanup.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            command = commands.recv() => {
                let Some(command) = command else { break };
                handle_command(
                    command,
                    &mut regions,
                    &mut home_region,
                    &options,
                    &status,
                ).await;
            }
            _ = event_poll.tick() => {
                if !forward_region_events(&mut regions, &events, &cancellation).await {
                    break;
                }
            }
            _ = cleanup.tick() => {
                clean_stale_regions(
                    &mut regions,
                    home_region,
                    options.inactive_cleanup_time,
                    &events,
                ).await;
                refresh_status(&status, home_region, &regions, None);
            }
        }
    }
    for (_, mut entry) in regions {
        if let Some(supervisor) = entry.supervisor.take() {
            let _ = supervisor.close().await;
        }
    }
}

async fn handle_command(
    command: ManagerCommand,
    regions: &mut HashMap<u32, RegionEntry>,
    home_region: &mut Option<u32>,
    options: &TailscaleDerpManagerOptions,
    status: &RwLock<TailscaleDerpManagerStatus>,
) {
    match command {
        ManagerCommand::SetRegion {
            region_id,
            connector,
        } => {
            if let Some(mut old) = regions.remove(&region_id)
                && let Some(supervisor) = old.supervisor.take()
            {
                let _ = supervisor.close().await;
            }
            regions.insert(
                region_id,
                RegionEntry {
                    connector,
                    supervisor: None,
                    last_write: Instant::now(),
                },
            );
            if *home_region == Some(region_id) {
                ensure_region(regions, region_id, options, true);
            }
            refresh_status(status, *home_region, regions, None);
        }
        ManagerCommand::RemoveRegion(region_id) => {
            if let Some(mut old) = regions.remove(&region_id)
                && let Some(supervisor) = old.supervisor.take()
            {
                let _ = supervisor.close().await;
            }
            if *home_region == Some(region_id) {
                *home_region = None;
            }
            refresh_status(status, *home_region, regions, None);
        }
        ManagerCommand::SetHomeRegion(new_home) => {
            if *home_region != new_home {
                if let Some(old_home) = *home_region
                    && let Some(supervisor) = regions
                        .get(&old_home)
                        .and_then(|entry| entry.supervisor.as_ref())
                {
                    let _ = supervisor.try_note_preferred(false);
                }
                *home_region = new_home;
                if let Some(new_home) = new_home {
                    ensure_region(regions, new_home, options, true);
                }
            }
            refresh_status(status, *home_region, regions, None);
        }
        ManagerCommand::SendPacket {
            peer,
            peer_home_region,
            packet,
            result,
        } => {
            let selected = select_region(regions, &peer, peer_home_region)
                .or(peer_home_region
                    .filter(|region| regions.contains_key(region)))
                .or_else(|| {
                    home_region.filter(|region| regions.contains_key(region))
                });
            let outcome = if let Some(region_id) = selected {
                ensure_region(
                    regions,
                    region_id,
                    options,
                    *home_region == Some(region_id),
                );
                let entry = regions
                    .get_mut(&region_id)
                    .expect("selected region exists");
                let send = entry
                    .supervisor
                    .as_ref()
                    .expect("selected region is active")
                    .try_send_packet(peer, &packet);
                if send.is_ok() {
                    entry.last_write = Instant::now();
                    refresh_status(
                        status,
                        *home_region,
                        regions,
                        Some(region_id),
                    );
                }
                send.map(|()| region_id)
            } else {
                Err(TailscaleDerpError::UnknownRegion(
                    peer_home_region.unwrap_or(0),
                ))
            };
            let _ = result.send(outcome);
        }
    }
}

fn ensure_region(
    regions: &mut HashMap<u32, RegionEntry>,
    region_id: u32,
    options: &TailscaleDerpManagerOptions,
    preferred: bool,
) {
    let Some(entry) = regions.get_mut(&region_id) else {
        return;
    };
    if entry.supervisor.is_none() {
        entry.supervisor = Some(TailscaleDerpRegionSupervisor::spawn(
            region_id,
            entry.connector.clone(),
            options.region_supervisor.clone(),
        ));
    }
    if let Some(supervisor) = entry.supervisor.as_ref() {
        let _ = supervisor.try_note_preferred(preferred);
    }
}

fn select_region(
    regions: &HashMap<u32, RegionEntry>,
    peer: &[u8; TAILSCALE_DERP_KEY_LENGTH],
    peer_home_region: Option<u32>,
) -> Option<u32> {
    if let Some(region_id) = peer_home_region
        && regions
            .get(&region_id)
            .and_then(|entry| entry.supervisor.as_ref())
            .is_some_and(|supervisor| supervisor.status().connected)
    {
        return Some(region_id);
    }
    regions
        .iter()
        .filter_map(|(region_id, entry)| {
            let supervisor = entry.supervisor.as_ref()?;
            supervisor.status().connected.then_some((
                *region_id,
                supervisor.reverse_route_last_seen(peer)?,
            ))
        })
        .max_by_key(|(_, seen)| *seen)
        .map(|(region_id, _)| region_id)
}

async fn forward_region_events(
    regions: &mut HashMap<u32, RegionEntry>,
    events: &mpsc::Sender<TailscaleDerpManagerEvent>,
    cancellation: &CancellationToken,
) -> bool {
    for entry in regions.values_mut() {
        while let Some(event) = entry
            .supervisor
            .as_mut()
            .and_then(TailscaleDerpRegionSupervisor::try_next_event)
        {
            let send = events.send(TailscaleDerpManagerEvent::Region(event));
            if !tokio::select! {
                biased;
                _ = cancellation.cancelled() => false,
                result = send => result.is_ok(),
            } {
                return false;
            }
        }
    }
    true
}

async fn clean_stale_regions(
    regions: &mut HashMap<u32, RegionEntry>,
    home_region: Option<u32>,
    inactive: Duration,
    events: &mpsc::Sender<TailscaleDerpManagerEvent>,
) {
    let stale = regions
        .iter()
        .filter_map(|(region_id, entry)| {
            (*region_id != home_region.unwrap_or(0)
                && entry.supervisor.is_some()
                && entry.last_write.elapsed() >= inactive)
                .then_some(*region_id)
        })
        .collect::<Vec<_>>();
    for region_id in stale {
        if let Some(supervisor) = regions
            .get_mut(&region_id)
            .and_then(|entry| entry.supervisor.take())
        {
            let _ = supervisor.close().await;
            let _ =
                events.try_send(TailscaleDerpManagerEvent::StaleRegionClosed {
                    region_id,
                });
        }
    }
}

fn refresh_status(
    status: &RwLock<TailscaleDerpManagerStatus>,
    home_region: Option<u32>,
    regions: &HashMap<u32, RegionEntry>,
    selected: Option<u32>,
) {
    if let Ok(mut status) = status.write() {
        status.home_region = home_region;
        status.registered_regions = regions.len();
        status.active_regions = regions
            .values()
            .filter(|entry| entry.supervisor.is_some())
            .count();
        if selected.is_some() {
            status.last_selected_region = selected;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use tokio::io::AsyncReadExt as _;

    use super::*;
    use crate::{
        adapter::Stream,
        protocol::tailscale::{
            TAILSCALE_DERP_FRAME_CLIENT_INFO, TAILSCALE_DERP_FRAME_RECV_PACKET,
            TAILSCALE_DERP_FRAME_SEND_PACKET, TailscaleDerpClient,
            TailscaleDerpConnectOptions, read_tailscale_derp_frame,
            tailscale_node_public_key, write_tailscale_derp_frame,
        },
    };

    struct TestConnector {
        connections: AtomicUsize,
        servers: mpsc::UnboundedSender<tokio::io::DuplexStream>,
        server_public_key: [u8; 32],
    }

    #[async_trait]
    impl TailscaleDerpConnector for TestConnector {
        async fn connect(
            &self,
            _region_id: u32,
        ) -> Result<TailscaleDerpClient<Stream>, TailscaleDerpError> {
            self.connections.fetch_add(1, Ordering::SeqCst);
            let (client, server) = tokio::io::duplex(8192);
            self.servers.send(server).unwrap();
            let mut options = TailscaleDerpConnectOptions::new("derp.test");
            options.known_server_public_key = Some(self.server_public_key);
            TailscaleDerpClient::connect(
                Box::new(client) as Stream,
                [81; 32],
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

    async fn read_sent_packet(
        server: &mut tokio::io::DuplexStream,
    ) -> crate::protocol::tailscale::TailscaleDerpFrame {
        loop {
            let frame = read_tailscale_derp_frame(server, 1024).await.unwrap();
            if frame.frame_type == TAILSCALE_DERP_FRAME_SEND_PACKET {
                return frame;
            }
        }
    }

    #[tokio::test]
    async fn selects_home_then_reverse_route_and_cleans_stale_region() {
        let (one_tx, mut one_rx) = mpsc::unbounded_channel();
        let (two_tx, mut two_rx) = mpsc::unbounded_channel();
        let one = Arc::new(TestConnector {
            connections: AtomicUsize::new(0),
            servers: one_tx,
            server_public_key: tailscale_node_public_key([82; 32]).unwrap(),
        });
        let two = Arc::new(TestConnector {
            connections: AtomicUsize::new(0),
            servers: two_tx,
            server_public_key: tailscale_node_public_key([83; 32]).unwrap(),
        });
        let mut manager =
            TailscaleDerpManager::spawn(TailscaleDerpManagerOptions {
                inactive_cleanup_time: Duration::from_millis(25),
                clean_stale_interval: Duration::from_millis(5),
                region_event_poll_interval: Duration::from_millis(1),
                region_supervisor: TailscaleDerpRegionSupervisorOptions {
                    initial_backoff: Duration::from_millis(1),
                    maximum_backoff: Duration::from_millis(2),
                },
            });
        manager.set_region(1, one.clone()).unwrap();
        manager.set_region(2, two.clone()).unwrap();
        manager.set_home_region(Some(1)).unwrap();
        let mut server_one = one_rx.recv().await.unwrap();
        consume_fast_start(&mut server_one).await;

        let peer = [84_u8; 32];
        let mut incoming = peer.to_vec();
        incoming.extend_from_slice(b"hello");
        write_tailscale_derp_frame(
            &mut server_one,
            TAILSCALE_DERP_FRAME_RECV_PACKET,
            &incoming,
            1024,
        )
        .await
        .unwrap();
        loop {
            if matches!(
                manager.next_event().await,
                Some(TailscaleDerpManagerEvent::Region(
                    TailscaleDerpRegionEvent::Message { .. }
                ))
            ) {
                break;
            }
        }

        assert_eq!(
            manager.send_packet(peer, Some(2), b"reply").await.unwrap(),
            1
        );
        let reverse = read_sent_packet(&mut server_one).await;
        assert_eq!(&reverse.payload[32..], b"reply");

        let other_peer = [85_u8; 32];
        assert_eq!(
            manager
                .send_packet(other_peer, Some(2), b"home")
                .await
                .unwrap(),
            2,
        );
        let mut server_two = two_rx.recv().await.unwrap();
        consume_fast_start(&mut server_two).await;
        let home = read_sent_packet(&mut server_two).await;
        assert_eq!(&home.payload[32..], b"home");

        loop {
            if matches!(
                manager.next_event().await,
                Some(TailscaleDerpManagerEvent::StaleRegionClosed {
                    region_id: 2
                })
            ) {
                break;
            }
        }
        assert_eq!(manager.status().active_regions, 1);
        assert_eq!(manager.status().home_region, Some(1));
        assert_eq!(one.connections.load(Ordering::SeqCst), 1);
        assert_eq!(two.connections.load(Ordering::SeqCst), 1);
        manager.close().await.unwrap();
    }
}
