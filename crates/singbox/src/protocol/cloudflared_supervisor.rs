//! Cloudflare Tunnel HA connection rotation, retry and protocol fallback.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use rand::Rng as _;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use super::{
    cloudflared::{
        CloudflaredEdgeAddress, CloudflaredError, CloudflaredProtocolSelection,
        CloudflaredTransportProtocol,
    },
    cloudflared_quic::{CloudflaredQuicHandler, CloudflaredQuicSession},
};

pub const CLOUDFLARED_PROTOCOL_RETRY_LIMIT: u8 = 5;
pub const CLOUDFLARED_RETRY_BASE: Duration = Duration::from_secs(1);
pub const CLOUDFLARED_RETRY_MAX: Duration = Duration::from_secs(120);
pub const CLOUDFLARED_FIRST_CONNECTION_READY_TIMEOUT: Duration =
    Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudflaredConnectionAttempt {
    pub connection_index: u8,
    pub edge: CloudflaredEdgeAddress,
    pub protocol: CloudflaredTransportProtocol,
    pub previous_attempts: u8,
}

#[async_trait(?Send)]
pub trait CloudflaredManagedConnection: 'static {
    async fn serve(
        self: Box<Self>,
        cancellation: CancellationToken,
        ready: Arc<tokio::sync::Notify>,
    ) -> Result<(), CloudflaredError>;
}

#[async_trait(?Send)]
pub trait CloudflaredConnectionFactory: Send + Sync + 'static {
    async fn connect(
        &self,
        attempt: CloudflaredConnectionAttempt,
    ) -> Result<Box<dyn CloudflaredManagedConnection>, CloudflaredError>;
}

pub struct CloudflaredQuicManagedConnection {
    session: CloudflaredQuicSession,
    connection_index: u8,
    handler: Arc<dyn CloudflaredQuicHandler>,
}

impl CloudflaredQuicManagedConnection {
    pub fn new(
        session: CloudflaredQuicSession,
        connection_index: u8,
        handler: Arc<dyn CloudflaredQuicHandler>,
    ) -> Self {
        Self {
            session,
            connection_index,
            handler,
        }
    }
}

#[async_trait(?Send)]
impl CloudflaredManagedConnection for CloudflaredQuicManagedConnection {
    async fn serve(
        self: Box<Self>,
        cancellation: CancellationToken,
        ready: Arc<tokio::sync::Notify>,
    ) -> Result<(), CloudflaredError> {
        ready.notify_one();
        self.session
            .serve(self.connection_index, self.handler, cancellation)
            .await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflaredSupervisorEvent {
    Connected {
        connection_index: u8,
        edge: CloudflaredEdgeAddress,
        protocol: CloudflaredTransportProtocol,
    },
    Retrying {
        connection_index: u8,
        edge: CloudflaredEdgeAddress,
        protocol: CloudflaredTransportProtocol,
        previous_attempts: u8,
        delay: Duration,
        error: String,
    },
    ProtocolFallback {
        connection_index: u8,
        from: CloudflaredTransportProtocol,
        to: CloudflaredTransportProtocol,
        error: String,
    },
    PermanentFailure {
        connection_index: u8,
        error: String,
    },
}

pub struct CloudflaredHaSupervisor {
    edges: Vec<CloudflaredEdgeAddress>,
    ha_connections: usize,
    selection: CloudflaredProtocolSelection,
    factory: Arc<dyn CloudflaredConnectionFactory>,
    events: broadcast::Sender<CloudflaredSupervisorEvent>,
}

#[derive(Clone)]
struct ConnectionSupervisorContext {
    edges: Vec<CloudflaredEdgeAddress>,
    selection: CloudflaredProtocolSelection,
    factory: Arc<dyn CloudflaredConnectionFactory>,
    events: broadcast::Sender<CloudflaredSupervisorEvent>,
    cancellation: CancellationToken,
}

impl CloudflaredHaSupervisor {
    pub fn new(
        edges: Vec<CloudflaredEdgeAddress>,
        requested_ha_connections: usize,
        selection: CloudflaredProtocolSelection,
        factory: Arc<dyn CloudflaredConnectionFactory>,
    ) -> Result<Self, CloudflaredError> {
        if edges.is_empty() {
            return Err(CloudflaredError::EdgeDiscovery(
                "no edge addresses found".into(),
            ));
        }
        let requested_ha_connections = requested_ha_connections.max(1);
        let ha_connections = requested_ha_connections.min(edges.len());
        let (events, _) = broadcast::channel(64);
        Ok(Self {
            edges,
            ha_connections,
            selection,
            factory,
            events,
        })
    }

    pub const fn ha_connections(&self) -> usize {
        self.ha_connections
    }

    pub fn subscribe(&self) -> broadcast::Receiver<CloudflaredSupervisorEvent> {
        self.events.subscribe()
    }

    /// Runs all HA slots until the embedding application cancels the token.
    ///
    /// Cap'n Proto registration futures are local, so call this inside a
    /// Tokio [`tokio::task::LocalSet`].
    pub async fn run(
        &self,
        cancellation: CancellationToken,
    ) -> Result<(), CloudflaredError> {
        let all_connections = cancellation.child_token();
        let mut tasks = tokio::task::JoinSet::new();
        let context = ConnectionSupervisorContext {
            edges: self.edges.clone(),
            selection: self.selection,
            factory: Arc::clone(&self.factory),
            events: self.events.clone(),
            cancellation: all_connections.clone(),
        };
        for connection_index in 0..self.ha_connections {
            let ready = Arc::new(tokio::sync::Notify::new());
            tasks.spawn_local(supervise_connection(
                connection_index as u8,
                context.clone(),
                Arc::clone(&ready),
            ));
            tokio::select! {
                () = ready.notified() => {}
                () = tokio::time::sleep(
                    CLOUDFLARED_FIRST_CONNECTION_READY_TIMEOUT,
                ) => {}
                () = cancellation.cancelled() => break,
            }
        }

        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error @ CloudflaredError::NonRemoteManagedTunnel)) => {
                    all_connections.cancel();
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Err(error);
                }
                Ok(Err(error)) => {
                    all_connections.cancel();
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Err(error);
                }
                Err(error) => {
                    all_connections.cancel();
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Err(CloudflaredError::Transport(format!(
                        "cloudflared supervisor task failed: {error}"
                    )));
                }
            }
        }
        Ok(())
    }
}

async fn supervise_connection(
    connection_index: u8,
    context: ConnectionSupervisorContext,
    ready: Arc<tokio::sync::Notify>,
) -> Result<(), CloudflaredError> {
    let ConnectionSupervisorContext {
        edges,
        selection,
        factory,
        events,
        cancellation,
    } = context;
    let mut edge_index =
        cloudflared_initial_edge_index(connection_index, edges.len());
    let mut protocol = selection.current;
    let mut previous_attempts = 0_u8;
    loop {
        if cancellation.is_cancelled() {
            return Ok(());
        }
        let edge = edges[edge_index];
        let attempt = CloudflaredConnectionAttempt {
            connection_index,
            edge,
            protocol,
            previous_attempts,
        };
        let connection_ready = Arc::new(tokio::sync::Notify::new());
        let result = match factory.connect(attempt).await {
            Ok(connection) => {
                previous_attempts = 0;
                let serve = connection
                    .serve(cancellation.clone(), Arc::clone(&connection_ready));
                tokio::pin!(serve);
                tokio::select! {
                    result = &mut serve => result,
                    () = connection_ready.notified() => {
                        let _ = events.send(
                            CloudflaredSupervisorEvent::Connected {
                                connection_index,
                                edge,
                                protocol,
                            },
                        );
                        ready.notify_one();
                        serve.await
                    }
                }
            }
            Err(error) => Err(error),
        };
        let error = match result {
            Ok(()) if cancellation.is_cancelled() => return Ok(()),
            Ok(()) => return Ok(()),
            Err(CloudflaredError::NonRemoteManagedTunnel) => {
                let _ =
                    events.send(CloudflaredSupervisorEvent::PermanentFailure {
                        connection_index,
                        error: CloudflaredError::NonRemoteManagedTunnel
                            .to_string(),
                    });
                return Err(CloudflaredError::NonRemoteManagedTunnel);
            }
            Err(
                error @ CloudflaredError::Registration {
                    should_retry: false,
                    ..
                },
            ) => {
                let _ =
                    events.send(CloudflaredSupervisorEvent::PermanentFailure {
                        connection_index,
                        error: error.to_string(),
                    });
                return Ok(());
            }
            Err(error) => error,
        };

        previous_attempts = previous_attempts
            .saturating_add(1)
            .min(CLOUDFLARED_PROTOCOL_RETRY_LIMIT);
        let backoff_attempts = previous_attempts;
        edge_index = cloudflared_rotate_edge_index(edge_index, edges.len());
        if protocol == CloudflaredTransportProtocol::Quic
            && (backoff_attempts >= CLOUDFLARED_PROTOCOL_RETRY_LIMIT
                || cloudflared_quic_is_broken(&error))
            && let Some(fallback) = selection.fallback
            && fallback != protocol
        {
            let from = protocol;
            protocol = fallback;
            previous_attempts = 0;
            let _ = events.send(CloudflaredSupervisorEvent::ProtocolFallback {
                connection_index,
                from,
                to: fallback,
                error: error.to_string(),
            });
        }
        let delay = match &error {
            CloudflaredError::Registration {
                retry_after,
                should_retry: true,
                ..
            } if !retry_after.is_zero() => *retry_after,
            _ => cloudflared_retry_backoff(backoff_attempts),
        };
        let _ = events.send(CloudflaredSupervisorEvent::Retrying {
            connection_index,
            edge,
            protocol,
            previous_attempts,
            delay,
            error: error.to_string(),
        });
        tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            () = tokio::time::sleep(delay) => {}
        }
    }
}

pub const fn cloudflared_initial_edge_index(
    connection_index: u8,
    size: usize,
) -> usize {
    if size <= 1 {
        0
    } else {
        connection_index as usize % size
    }
}

pub const fn cloudflared_rotate_edge_index(
    current: usize,
    size: usize,
) -> usize {
    if size <= 1 { 0 } else { (current + 1) % size }
}

pub fn cloudflared_retry_backoff(retries: u8) -> Duration {
    let multiplier = 1_u64 << retries.min(7);
    let full =
        (CLOUDFLARED_RETRY_BASE * multiplier as u32).min(CLOUDFLARED_RETRY_MAX);
    let half = full / 2;
    let jitter = rand::thread_rng().gen_range(Duration::ZERO..half);
    half + jitter
}

pub fn cloudflared_quic_is_broken(error: &CloudflaredError) -> bool {
    match error {
        CloudflaredError::Transport(message) => {
            let message = message.to_ascii_lowercase();
            message.contains("idle timeout")
                || message.contains("operation not permitted")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    struct WaitingConnection;

    #[async_trait(?Send)]
    impl CloudflaredManagedConnection for WaitingConnection {
        async fn serve(
            self: Box<Self>,
            cancellation: CancellationToken,
            ready: Arc<tokio::sync::Notify>,
        ) -> Result<(), CloudflaredError> {
            ready.notify_one();
            cancellation.cancelled().await;
            Ok(())
        }
    }

    #[derive(Default)]
    struct RetryFactory {
        attempts: AtomicUsize,
        recorded: Mutex<Vec<CloudflaredConnectionAttempt>>,
        changed: tokio::sync::Notify,
    }

    #[async_trait(?Send)]
    impl CloudflaredConnectionFactory for RetryFactory {
        async fn connect(
            &self,
            attempt: CloudflaredConnectionAttempt,
        ) -> Result<Box<dyn CloudflaredManagedConnection>, CloudflaredError>
        {
            self.recorded.lock().unwrap().push(attempt);
            let number = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            self.changed.notify_waiters();
            if number <= 5 {
                Err(CloudflaredError::Registration {
                    cause: "retry".into(),
                    retry_after: Duration::from_millis(1),
                    should_retry: true,
                })
            } else {
                Ok(Box::new(WaitingConnection))
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rotates_edges_and_falls_back_after_five_retries() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let edges = vec![
                    CloudflaredEdgeAddress {
                        address: "192.0.2.1:7844".parse().unwrap(),
                        ip_version: 4,
                    },
                    CloudflaredEdgeAddress {
                        address: "192.0.2.2:7844".parse().unwrap(),
                        ip_version: 4,
                    },
                ];
                let factory = Arc::new(RetryFactory::default());
                let supervisor = Arc::new(
                    CloudflaredHaSupervisor::new(
                        edges,
                        1,
                        CloudflaredProtocolSelection::new("auto", false)
                            .unwrap(),
                        factory.clone(),
                    )
                    .unwrap(),
                );
                let cancellation = CancellationToken::new();
                let task_supervisor = Arc::clone(&supervisor);
                let task_cancellation = cancellation.clone();
                let run_task = tokio::task::spawn_local(async move {
                    task_supervisor.run(task_cancellation).await
                });
                tokio::time::timeout(Duration::from_secs(1), async {
                    while factory.attempts.load(Ordering::SeqCst) < 6 {
                        factory.changed.notified().await;
                    }
                })
                .await
                .unwrap();
                cancellation.cancel();
                run_task.await.unwrap().unwrap();

                let attempts = factory.recorded.lock().unwrap();
                assert_eq!(attempts.len(), 6);
                assert_eq!(
                    attempts[0].edge.address.ip(),
                    "192.0.2.1".parse::<std::net::IpAddr>().unwrap()
                );
                assert_eq!(
                    attempts[1].edge.address.ip(),
                    "192.0.2.2".parse::<std::net::IpAddr>().unwrap()
                );
                assert_eq!(
                    attempts[4].protocol,
                    CloudflaredTransportProtocol::Quic
                );
                assert_eq!(
                    attempts[5].protocol,
                    CloudflaredTransportProtocol::Http2
                );
                assert_eq!(attempts[5].previous_attempts, 0);
            })
            .await;
    }

    #[test]
    fn helpers_match_upstream_bounds_and_ha_cap() {
        assert_eq!(cloudflared_initial_edge_index(3, 2), 1);
        assert_eq!(cloudflared_rotate_edge_index(1, 3), 2);
        for _ in 0..32 {
            let delay = cloudflared_retry_backoff(20);
            assert!(delay >= CLOUDFLARED_RETRY_MAX / 2);
            assert!(delay < CLOUDFLARED_RETRY_MAX);
        }
        assert!(cloudflared_quic_is_broken(&CloudflaredError::Transport(
            "idle timeout".into()
        )));
        let supervisor = CloudflaredHaSupervisor::new(
            vec![
                CloudflaredEdgeAddress {
                    address: "192.0.2.1:7844".parse().unwrap(),
                    ip_version: 4,
                },
                CloudflaredEdgeAddress {
                    address: "192.0.2.2:7844".parse().unwrap(),
                    ip_version: 4,
                },
            ],
            4,
            CloudflaredProtocolSelection::new("auto", false).unwrap(),
            Arc::new(RetryFactory::default()),
        )
        .unwrap();
        assert_eq!(supervisor.ha_connections(), 2);
    }
}
