//! Reconnecting DERP region supervision for the embedded Tailscale endpoint.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{Dialer, Stream},
    common::network::SocksAddr,
};

use super::tailscale::{
    TAILSCALE_DERP_KEY_LENGTH, TAILSCALE_DERP_RECEIVE_QUEUE_DEPTH,
    TAILSCALE_DERP_WRITE_QUEUE_DEPTH, TailscaleDerpClient,
    TailscaleDerpConnectOptions, TailscaleDerpError,
    TailscaleDerpReceivedMessage, dial_tailscale_derp,
};

const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const DEFAULT_MAXIMUM_BACKOFF: Duration = Duration::from_secs(5);

#[async_trait]
pub trait TailscaleDerpConnector: Send + Sync {
    async fn connect(
        &self,
        region_id: u32,
    ) -> Result<TailscaleDerpClient<Stream>, TailscaleDerpError>;
}

/// Connector for one DERP node through any sing-box dialer. Wrapping the
/// dialer with `ClientTlsDialer` keeps TLS policy and detours in the host.
pub struct TailscaleDerpDialConnector {
    pub dialer: Arc<dyn Dialer>,
    pub destination: SocksAddr,
    pub private_key: [u8; TAILSCALE_DERP_KEY_LENGTH],
    pub options: TailscaleDerpConnectOptions,
}

#[async_trait]
impl TailscaleDerpConnector for TailscaleDerpDialConnector {
    async fn connect(
        &self,
        _region_id: u32,
    ) -> Result<TailscaleDerpClient<Stream>, TailscaleDerpError> {
        dial_tailscale_derp(
            self.dialer.as_ref(),
            &self.destination,
            self.private_key,
            self.options.clone(),
        )
        .await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDerpRegionSupervisorOptions {
    pub initial_backoff: Duration,
    pub maximum_backoff: Duration,
}

impl Default for TailscaleDerpRegionSupervisorOptions {
    fn default() -> Self {
        Self {
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
            maximum_backoff: DEFAULT_MAXIMUM_BACKOFF,
        }
    }
}

impl TailscaleDerpRegionSupervisorOptions {
    fn normalized(&self) -> Self {
        let initial_backoff = if self.initial_backoff.is_zero() {
            DEFAULT_INITIAL_BACKOFF
        } else {
            self.initial_backoff
        };
        Self {
            initial_backoff,
            maximum_backoff: self.maximum_backoff.max(initial_backoff),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleDerpRegionStatus {
    pub connected: bool,
    pub generation: u64,
    pub reverse_routes: usize,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleDerpRegionEvent {
    Connected {
        region_id: u32,
        generation: u64,
    },
    Disconnected {
        region_id: u32,
        generation: u64,
        error: String,
        retry_in: Duration,
    },
    Message {
        region_id: u32,
        generation: u64,
        message: TailscaleDerpReceivedMessage,
    },
    WriteDropped {
        region_id: u32,
        generation: u64,
        error: String,
    },
}

enum TailscaleDerpRegionCommand {
    Packet {
        destination: [u8; TAILSCALE_DERP_KEY_LENGTH],
        packet: Vec<u8>,
    },
    Ping([u8; 8]),
    Preferred(bool),
}

pub struct TailscaleDerpRegionSupervisor {
    commands: mpsc::Sender<TailscaleDerpRegionCommand>,
    events: mpsc::Receiver<TailscaleDerpRegionEvent>,
    status: Arc<RwLock<TailscaleDerpRegionStatus>>,
    routes: Arc<RwLock<HashMap<[u8; TAILSCALE_DERP_KEY_LENGTH], Instant>>>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl TailscaleDerpRegionSupervisor {
    pub fn spawn(
        region_id: u32,
        connector: Arc<dyn TailscaleDerpConnector>,
        options: TailscaleDerpRegionSupervisorOptions,
    ) -> Self {
        let options = options.normalized();
        let (command_tx, command_rx) =
            mpsc::channel(TAILSCALE_DERP_WRITE_QUEUE_DEPTH);
        let (event_tx, event_rx) =
            mpsc::channel(TAILSCALE_DERP_RECEIVE_QUEUE_DEPTH);
        let status =
            Arc::new(RwLock::new(TailscaleDerpRegionStatus::default()));
        let routes = Arc::new(RwLock::new(HashMap::new()));
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run_region_supervisor(
            region_id,
            connector,
            options,
            command_rx,
            event_tx,
            status.clone(),
            routes.clone(),
            cancellation.clone(),
        ));
        Self {
            commands: command_tx,
            events: event_rx,
            status,
            routes,
            cancellation,
            task: Some(task),
        }
    }

    pub fn try_send_packet(
        &self,
        destination: [u8; TAILSCALE_DERP_KEY_LENGTH],
        packet: &[u8],
    ) -> Result<(), TailscaleDerpError> {
        if packet.len() > super::tailscale::TAILSCALE_DERP_MAX_PACKET_SIZE {
            return Err(TailscaleDerpError::PacketTooLarge);
        }
        self.try_send(TailscaleDerpRegionCommand::Packet {
            destination,
            packet: packet.to_vec(),
        })
    }

    pub fn try_send_ping(
        &self,
        payload: [u8; 8],
    ) -> Result<(), TailscaleDerpError> {
        self.try_send(TailscaleDerpRegionCommand::Ping(payload))
    }

    pub fn try_note_preferred(
        &self,
        preferred: bool,
    ) -> Result<(), TailscaleDerpError> {
        self.try_send(TailscaleDerpRegionCommand::Preferred(preferred))
    }

    pub async fn next_event(&mut self) -> Option<TailscaleDerpRegionEvent> {
        self.events.recv().await
    }

    pub fn try_next_event(&mut self) -> Option<TailscaleDerpRegionEvent> {
        self.events.try_recv().ok()
    }

    pub fn status(&self) -> TailscaleDerpRegionStatus {
        self.status
            .read()
            .map(|status| status.clone())
            .unwrap_or_default()
    }

    pub fn has_reverse_route(
        &self,
        peer: &[u8; TAILSCALE_DERP_KEY_LENGTH],
    ) -> bool {
        self.routes
            .read()
            .is_ok_and(|routes| routes.contains_key(peer))
    }

    pub fn reverse_route_last_seen(
        &self,
        peer: &[u8; TAILSCALE_DERP_KEY_LENGTH],
    ) -> Option<Instant> {
        self.routes.read().ok()?.get(peer).copied()
    }

    pub async fn close(mut self) -> Result<(), TailscaleDerpError> {
        self.cancellation.cancel();
        self.task
            .take()
            .expect("supervisor task is present")
            .await
            .map_err(|error| {
                TailscaleDerpError::Io(std::io::Error::other(format!(
                    "DERP region supervisor task failed: {error}"
                )))
            })
    }

    fn try_send(
        &self,
        command: TailscaleDerpRegionCommand,
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

impl Drop for TailscaleDerpRegionSupervisor {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_region_supervisor(
    region_id: u32,
    connector: Arc<dyn TailscaleDerpConnector>,
    options: TailscaleDerpRegionSupervisorOptions,
    mut commands: mpsc::Receiver<TailscaleDerpRegionCommand>,
    events: mpsc::Sender<TailscaleDerpRegionEvent>,
    status: Arc<RwLock<TailscaleDerpRegionStatus>>,
    routes: Arc<RwLock<HashMap<[u8; TAILSCALE_DERP_KEY_LENGTH], Instant>>>,
    cancellation: CancellationToken,
) {
    let mut generation = 0_u64;
    let mut backoff = options.initial_backoff;
    let mut preferred = false;
    loop {
        let connect = connector.connect(region_id);
        let client = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            result = connect => match result {
                Ok(client) => client,
                Err(error) => {
                    let description = error.to_string();
                    update_disconnected_status(&status, generation, &description);
                    let _ = events.try_send(TailscaleDerpRegionEvent::Disconnected {
                        region_id,
                        generation,
                        error: description,
                        retry_in: backoff,
                    });
                    if !wait_for_retry(&cancellation, backoff).await {
                        return;
                    }
                    backoff = backoff.saturating_mul(2).min(options.maximum_backoff);
                    continue;
                }
            },
        };

        generation = generation.saturating_add(1);
        backoff = options.initial_backoff;
        if let Ok(mut current) = status.write() {
            current.connected = true;
            current.generation = generation;
            current.last_error = None;
        }
        let _ = events.try_send(TailscaleDerpRegionEvent::Connected {
            region_id,
            generation,
        });
        let mut session = client.into_session();
        if preferred {
            let _ = session.try_note_preferred(true);
        }

        let disconnect_error = loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    let _ = session.close().await;
                    clear_routes(&routes, &status);
                    return;
                }
                command = commands.recv() => {
                    let Some(command) = command else {
                        let _ = session.close().await;
                        clear_routes(&routes, &status);
                        return;
                    };
                    let result = match command {
                        TailscaleDerpRegionCommand::Packet { destination, packet } => {
                            session.try_send_packet(destination, &packet)
                        }
                        TailscaleDerpRegionCommand::Ping(payload) => {
                            session.try_send_ping(payload)
                        }
                        TailscaleDerpRegionCommand::Preferred(value) => {
                            preferred = value;
                            session.try_note_preferred(value)
                        }
                    };
                    if let Err(error) = result {
                        if matches!(error, TailscaleDerpError::SessionClosed) {
                            break error.to_string();
                        }
                        let _ = events.try_send(TailscaleDerpRegionEvent::WriteDropped {
                            region_id,
                            generation,
                            error: error.to_string(),
                        });
                    }
                }
                event = session.next_event() => match event {
                    Some(Ok(message)) => {
                        update_routes(&routes, &status, &message);
                        let event = TailscaleDerpRegionEvent::Message {
                            region_id,
                            generation,
                            message,
                        };
                        let delivered = tokio::select! {
                            biased;
                            _ = cancellation.cancelled() => false,
                            result = events.send(event) => result.is_ok(),
                        };
                        if !delivered {
                            let _ = session.close().await;
                            clear_routes(&routes, &status);
                            return;
                        }
                    }
                    Some(Err(error)) => break error.to_string(),
                    None => break "DERP session closed".into(),
                }
            }
        };

        let _ = session.close().await;
        clear_routes(&routes, &status);
        update_disconnected_status(&status, generation, &disconnect_error);
        let _ = events.try_send(TailscaleDerpRegionEvent::Disconnected {
            region_id,
            generation,
            error: disconnect_error,
            retry_in: backoff,
        });
        if !wait_for_retry(&cancellation, backoff).await {
            return;
        }
        backoff = backoff.saturating_mul(2).min(options.maximum_backoff);
    }
}

fn update_routes(
    routes: &RwLock<HashMap<[u8; TAILSCALE_DERP_KEY_LENGTH], Instant>>,
    status: &RwLock<TailscaleDerpRegionStatus>,
    message: &TailscaleDerpReceivedMessage,
) {
    let changed = if let Ok(mut routes) = routes.write() {
        match message {
            TailscaleDerpReceivedMessage::Packet(packet) => {
                routes.insert(packet.peer, Instant::now()).is_none()
            }
            TailscaleDerpReceivedMessage::PeerGone { peer, .. } => {
                routes.remove(peer).is_some()
            }
            _ => false,
        }
        .then_some(routes.len())
    } else {
        None
    };
    if let Some(count) = changed
        && let Ok(mut status) = status.write()
    {
        status.reverse_routes = count;
    }
}

fn clear_routes(
    routes: &RwLock<HashMap<[u8; TAILSCALE_DERP_KEY_LENGTH], Instant>>,
    status: &RwLock<TailscaleDerpRegionStatus>,
) {
    if let Ok(mut routes) = routes.write() {
        routes.clear();
    }
    if let Ok(mut status) = status.write() {
        status.reverse_routes = 0;
    }
}

fn update_disconnected_status(
    status: &RwLock<TailscaleDerpRegionStatus>,
    generation: u64,
    error: &str,
) {
    if let Ok(mut status) = status.write() {
        status.connected = false;
        status.generation = generation;
        status.last_error = Some(error.into());
    }
}

async fn wait_for_retry(
    cancellation: &CancellationToken,
    duration: Duration,
) -> bool {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => false,
        _ = tokio::time::sleep(duration) => true,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::protocol::tailscale::{
        TAILSCALE_DERP_FRAME_CLIENT_INFO, TAILSCALE_DERP_FRAME_PING,
        TAILSCALE_DERP_FRAME_PONG, TAILSCALE_DERP_FRAME_RECV_PACKET,
        TAILSCALE_DERP_FRAME_SEND_PACKET, TailscaleDerpFrame,
        read_tailscale_derp_frame, tailscale_node_public_key,
        write_tailscale_derp_frame,
    };

    struct TestConnector {
        attempts: AtomicUsize,
        servers: mpsc::UnboundedSender<tokio::io::DuplexStream>,
        server_public_key: [u8; 32],
    }

    #[async_trait]
    impl TailscaleDerpConnector for TestConnector {
        async fn connect(
            &self,
            _region_id: u32,
        ) -> Result<TailscaleDerpClient<Stream>, TailscaleDerpError> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(TailscaleDerpError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "first attempt",
                )));
            }
            let (client, server) = tokio::io::duplex(8192);
            self.servers.send(server).unwrap();
            let mut options = TailscaleDerpConnectOptions::new("derp.test");
            options.known_server_public_key = Some(self.server_public_key);
            TailscaleDerpClient::connect(
                Box::new(client) as Stream,
                [71; 32],
                options,
            )
            .await
        }
    }

    async fn read_fast_start(
        server: &mut tokio::io::DuplexStream,
    ) -> TailscaleDerpFrame {
        let mut suffix = [0_u8; 4];
        loop {
            suffix.rotate_left(1);
            suffix[3] = server.read_u8().await.unwrap();
            if suffix == *b"\r\n\r\n" {
                break;
            }
        }
        read_tailscale_derp_frame(server, 256 << 10).await.unwrap()
    }

    #[tokio::test]
    async fn reconnects_tracks_generation_routes_and_auto_pongs() {
        let (server_tx, mut server_rx) = mpsc::unbounded_channel();
        let connector = Arc::new(TestConnector {
            attempts: AtomicUsize::new(0),
            servers: server_tx,
            server_public_key: tailscale_node_public_key([72; 32]).unwrap(),
        });
        let mut supervisor = TailscaleDerpRegionSupervisor::spawn(
            7,
            connector.clone(),
            TailscaleDerpRegionSupervisorOptions {
                initial_backoff: Duration::from_millis(1),
                maximum_backoff: Duration::from_millis(2),
            },
        );

        assert!(matches!(
            supervisor.next_event().await,
            Some(TailscaleDerpRegionEvent::Disconnected {
                region_id: 7,
                generation: 0,
                ..
            })
        ));
        let mut server = server_rx.recv().await.unwrap();
        assert_eq!(
            read_fast_start(&mut server).await.frame_type,
            TAILSCALE_DERP_FRAME_CLIENT_INFO
        );
        assert!(matches!(
            supervisor.next_event().await,
            Some(TailscaleDerpRegionEvent::Connected {
                region_id: 7,
                generation: 1,
            })
        ));

        supervisor.try_send_packet([73; 32], b"outgoing").unwrap();
        write_tailscale_derp_frame(
            &mut server,
            TAILSCALE_DERP_FRAME_PING,
            b"12345678",
            8,
        )
        .await
        .unwrap();
        let source = [74_u8; 32];
        let mut incoming = source.to_vec();
        incoming.extend_from_slice(b"incoming");
        write_tailscale_derp_frame(
            &mut server,
            TAILSCALE_DERP_FRAME_RECV_PACKET,
            &incoming,
            1024,
        )
        .await
        .unwrap();

        let mut saw_send = false;
        let mut saw_pong = false;
        while !saw_send || !saw_pong {
            let frame =
                read_tailscale_derp_frame(&mut server, 1024).await.unwrap();
            saw_send |= frame.frame_type == TAILSCALE_DERP_FRAME_SEND_PACKET;
            saw_pong |= frame.frame_type == TAILSCALE_DERP_FRAME_PONG;
        }
        assert!(matches!(
            supervisor.next_event().await,
            Some(TailscaleDerpRegionEvent::Message {
                generation: 1,
                message: TailscaleDerpReceivedMessage::Packet(_),
                ..
            })
        ));
        assert!(supervisor.has_reverse_route(&source));
        assert_eq!(supervisor.status().reverse_routes, 1);

        drop(server);
        assert!(matches!(
            supervisor.next_event().await,
            Some(TailscaleDerpRegionEvent::Disconnected { generation: 1, .. })
        ));
        assert!(!supervisor.has_reverse_route(&source));
        let mut second_server = server_rx.recv().await.unwrap();
        assert_eq!(
            read_fast_start(&mut second_server).await.frame_type,
            TAILSCALE_DERP_FRAME_CLIENT_INFO
        );
        assert!(matches!(
            supervisor.next_event().await,
            Some(TailscaleDerpRegionEvent::Connected { generation: 2, .. })
        ));
        assert!(connector.attempts.load(Ordering::SeqCst) >= 3);
        supervisor.close().await.unwrap();
        second_server.shutdown().await.unwrap();
    }
}
