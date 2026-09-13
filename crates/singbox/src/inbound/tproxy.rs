//! Linux transparent-proxy inbound.

use std::{
    collections::HashMap, io, net::SocketAddr, sync::Arc, time::Instant,
};

use n0_watcher::Watcher as _;
use tokio::{
    net::TcpListener,
    sync::Mutex,
    task::{JoinHandle, JoinSet},
    time::MissedTickBehavior,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::PacketConnection,
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::{Network, SocksAddr},
        network_monitor::DirectInterfaceClassifier,
        redir::{
            TransparentUdpSocket, send_transparent_udp,
            transparent_tcp_listener, transparent_udp_socket,
        },
        udp_nat::{UdpNatFilter, UdpNatFilterSession, udp_nat_max},
    },
    inbound::{
        PacketDestinationNat, PacketSniffSessions,
        hijack_dns_packet_with_context, redirect::handle_connection,
        socks::restore_fake_ip,
    },
    option::{Network as OptionNetwork, TProxyInboundOptions, UdpNatBehavior},
    outbound::OutboundManager,
    route::{Action, Metadata, Router},
};

#[derive(Debug, thiserror::Error)]
pub enum TProxyInboundError {
    #[error("invalid TProxy inbound configuration: {0}")]
    Invalid(String),
}

pub struct TProxyInbound {
    name: String,
    tag: String,
    options: TProxyInboundOptions,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    tasks: Vec<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

impl TProxyInbound {
    pub fn new(
        tag: impl Into<String>,
        options: TProxyInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, TProxyInboundError> {
        let networks = options.network.build();
        if !networks.contains(&OptionNetwork::Tcp)
            && !networks.contains(&OptionNetwork::Udp)
        {
            return Err(TProxyInboundError::Invalid(
                "network must include tcp or udp".into(),
            ));
        }
        let tag = tag.into();
        Ok(Self {
            name: format!("inbound/tproxy[{tag}]"),
            tag,
            options,
            router,
            outbounds,
            cancellation: CancellationToken::new(),
            tasks: Vec::new(),
            local_addr: None,
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    async fn bind(&mut self) -> io::Result<()> {
        let address = SocketAddr::new(
            self.options
                .listen
                .listen
                .map(|address| address.0)
                .unwrap_or(std::net::Ipv4Addr::LOCALHOST.into()),
            self.options.listen.listen_port,
        );
        let networks = self.options.network.build();
        let tcp_enabled = networks.contains(&OptionNetwork::Tcp);
        let udp_enabled = networks.contains(&OptionNetwork::Udp);
        let mut port = address.port();
        let listener = if tcp_enabled {
            let listener =
                TcpListener::from_std(transparent_tcp_listener(address)?)?;
            let local = listener.local_addr()?;
            port = local.port();
            self.local_addr = Some(local);
            Some(listener)
        } else {
            None
        };
        let udp_socket = if udp_enabled {
            let socket =
                transparent_udp_socket(SocketAddr::new(address.ip(), port))?;
            self.local_addr.get_or_insert(socket.local_addr()?);
            Some(Arc::new(socket))
        } else {
            None
        };
        if let Some(listener) = listener {
            self.tasks.push(tokio::spawn(accept_loop(
                listener,
                self.cancellation.clone(),
                self.tag.clone(),
                self.router.clone(),
                self.outbounds.clone(),
            )));
        }
        if let Some(socket) = udp_socket {
            let udp_timeout = self
                .options
                .listen
                .udp_timeout
                .0
                .as_std()
                .filter(|duration| !duration.is_zero())
                .unwrap_or(crate::constant::UDP_TIMEOUT);
            self.tasks.push(tokio::spawn(udp_loop(
                socket,
                self.cancellation.clone(),
                self.tag.clone(),
                self.router.clone(),
                self.outbounds.clone(),
                udp_timeout,
                self.options.udp_mapping,
                self.options.udp_filtering,
                self.options.udp_nat_max,
            )));
        }
        Ok(())
    }
}

impl Lifecycle for TProxyInbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage == StartStage::Start {
                self.bind().await.map_err(|error| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: error.to_string(),
                })?;
            }
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            for task in self.tasks.drain(..) {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        return Err(LifecycleError::Close {
                            component: self.name.clone(),
                            message: error.to_string(),
                        });
                    }
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => {
                        return Err(LifecycleError::Close {
                            component: self.name.clone(),
                            message: error.to_string(),
                        });
                    }
                }
            }
            Ok(())
        })
    }
}

async fn accept_loop(
    listener: TcpListener,
    cancellation: CancellationToken,
    tag: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, source) = accepted?;
                let destination = stream.local_addr()?.into();
                let tag = tag.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                connections.spawn(async move {
                    handle_connection(
                        stream,
                        source,
                        destination,
                        &tag,
                        &router,
                        &outbounds,
                    )
                    .await
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn udp_loop(
    socket: Arc<TransparentUdpSocket>,
    cancellation: CancellationToken,
    tag: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    mapping: UdpNatBehavior,
    filtering: UdpNatBehavior,
    configured_max: u32,
) -> io::Result<()> {
    let origin_destination = socket.local_addr()?;
    let mut data = vec![0_u8; 65_535];
    let mut sniff_sessions =
        PacketSniffSessions::<(SocketAddr, SocketAddr)>::new(udp_timeout);
    let max_sessions = udp_nat_max(configured_max);
    let nat_filter = UdpNatFilter::new(mapping, filtering, max_sessions);
    let mut sessions = HashMap::<NatKey, NatSession>::new();
    let mut network_watcher =
        match crate::common::network_monitor::NetworkMonitor::new().await {
            Ok(monitor) => {
                let watcher = monitor.interface_state();
                let classifier = DirectInterfaceClassifier::from_system();
                Some((monitor, classifier, watcher))
            }
            Err(_) => None,
        };
    let mut expiry = tokio::time::interval(
        udp_timeout
            .min(std::time::Duration::from_secs(1))
            .max(std::time::Duration::from_millis(10)),
    );
    expiry.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        let packet = tokio::select! {
            _ = cancellation.cancelled() => break,
            update = async {
                match network_watcher.as_mut() {
                    Some((_, _, watcher)) => watcher.updated().await.ok(),
                    None => std::future::pending().await,
                }
            } => {
                if update.is_none() {
                    network_watcher = None;
                    continue;
                }
                if let Some((_, classifier, _)) = network_watcher.as_mut() {
                    *classifier = DirectInterfaceClassifier::from_system();
                    purge_unavailable_nat_sessions(
                        &mut sessions,
                        classifier,
                    );
                }
                continue;
            }
            _ = expiry.tick() => {
                expire_nat_sessions(&mut sessions, Instant::now());
                continue;
            }
            packet = socket.recv_from(&mut data) => packet?,
        };
        let client_destination = SocksAddr::from(packet.destination);
        let now = Instant::now();
        expire_nat_sessions(&mut sessions, now);
        let direct_interface =
            network_watcher.as_ref().and_then(|(_, classifier, _)| {
                classifier.classify(&client_destination)
            });
        let key = NatKey::new(
            mapping,
            packet.source,
            &client_destination,
            direct_interface,
        );
        if let Some(session) = sessions.get_mut(&key) {
            session.updated_at = now;
            let Ok((destination, _)) =
                restore_fake_ip(client_destination.clone(), &outbounds)
            else {
                continue;
            };
            let destination = session
                .destination_nat
                .lock()
                .await
                .translate_destination(destination, client_destination.clone());
            session.filter.record(&client_destination);
            let _ = session
                .connection
                .send_to(&data[..packet.length], &destination)
                .await;
            continue;
        }
        let mut metadata = Metadata {
            inbound: tag.clone(),
            source: Some(packet.source.into()),
            destination: Some(client_destination.clone()),
            origin_destination: Some(origin_destination.into()),
            network: Some(Network::Udp),
            ..Metadata::default()
        };
        let Ok(decision) = sniff_sessions
            .route(
                (packet.source, packet.destination),
                &data[..packet.length],
                &mut metadata,
                &router,
                &outbounds,
            )
            .await
        else {
            continue;
        };
        if matches!(decision.action(), Some(Action::Reject { .. })) {
            continue;
        }
        if matches!(decision.action(), Some(Action::HijackDns)) {
            if let Ok(response) = hijack_dns_packet_with_context(
                &data[..packet.length],
                &outbounds,
                &metadata,
            )
            .await
            {
                let _ = send_transparent_udp(
                    packet.destination,
                    packet.source,
                    &response,
                );
            }
            continue;
        }
        let route_original = metadata
            .destination
            .clone()
            .unwrap_or_else(|| client_destination.clone());
        let routed_destination = decision.destination(&route_original);
        let connection_options = decision.connection_options();
        let effective_udp_timeout =
            connection_options.udp_timeout.unwrap_or(udp_timeout);
        if sessions.len() >= max_sessions
            && let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.updated_at)
                .map(|(key, _)| key.clone())
            && let Some(session) = sessions.remove(&oldest)
        {
            session.cancellation.cancel();
        }
        let dialer = if matches!(decision.action(), Some(Action::Direct)) {
            outbounds.direct()
        } else if let Some(dialer) = outbounds.select(decision.outbound()) {
            dialer
        } else {
            continue;
        };
        let Ok(outgoing) = dialer
            .listen_udp_with_options(
                &routed_destination,
                &connection_options.network,
            )
            .await
        else {
            continue;
        };
        let connection: Arc<dyn PacketConnection> = Arc::from(outgoing);
        let filter = nat_filter.open(&client_destination);
        let destination_nat = Arc::new(Mutex::new(PacketDestinationNat::new(
            route_original.clone(),
            routed_destination,
        )));
        let destination = destination_nat
            .lock()
            .await
            .translate_destination(route_original, client_destination);
        let session_cancellation = cancellation.child_token();
        spawn_udp_response_relay(
            connection.clone(),
            filter.clone(),
            destination_nat.clone(),
            packet.source,
            packet.destination,
            session_cancellation.clone(),
        );
        sessions.insert(
            key,
            NatSession {
                connection: connection.clone(),
                filter,
                destination_nat,
                cancellation: session_cancellation,
                direct_interface,
                updated_at: now,
                timeout: effective_udp_timeout,
            },
        );
        if connection
            .send_to(&data[..packet.length], &destination)
            .await
            .is_err()
        {
            continue;
        }
    }
    for (_, session) in sessions {
        session.cancellation.cancel();
    }
    Ok(())
}

fn purge_unavailable_nat_sessions(
    sessions: &mut HashMap<NatKey, NatSession>,
    classifier: &DirectInterfaceClassifier,
) {
    sessions.retain(|_, session| {
        let available = session
            .direct_interface
            .is_none_or(|index| classifier.contains_interface(index));
        if !available {
            session.cancellation.cancel();
        }
        available
    });
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum NatKey {
    Endpoint(SocketAddr, Option<u32>),
    Address(SocketAddr, String),
    AddressAndPort(SocketAddr, SocksAddr),
}

impl NatKey {
    fn new(
        mapping: UdpNatBehavior,
        source: SocketAddr,
        destination: &SocksAddr,
        direct_interface: Option<u32>,
    ) -> Self {
        match mapping {
            UdpNatBehavior::EndpointIndependent => {
                Self::Endpoint(source, direct_interface)
            }
            UdpNatBehavior::AddressDependent => {
                Self::Address(source, destination.host())
            }
            UdpNatBehavior::AddressAndPortDependent => {
                Self::AddressAndPort(source, destination.clone())
            }
        }
    }
}

struct NatSession {
    connection: Arc<dyn PacketConnection>,
    filter: UdpNatFilterSession,
    destination_nat: Arc<Mutex<PacketDestinationNat>>,
    cancellation: CancellationToken,
    direct_interface: Option<u32>,
    updated_at: Instant,
    timeout: std::time::Duration,
}

fn expire_nat_sessions(
    sessions: &mut HashMap<NatKey, NatSession>,
    now: Instant,
) {
    sessions.retain(|_, session| {
        let alive = now.duration_since(session.updated_at) <= session.timeout;
        if !alive {
            session.cancellation.cancel();
        }
        alive
    });
}

fn spawn_udp_response_relay(
    connection: Arc<dyn PacketConnection>,
    filter: UdpNatFilterSession,
    destination_nat: Arc<Mutex<PacketDestinationNat>>,
    client: SocketAddr,
    original_destination: SocketAddr,
    cancellation: CancellationToken,
) {
    tokio::spawn(async move {
        let mut response = vec![0_u8; 65_535];
        loop {
            let received = tokio::select! {
                _ = cancellation.cancelled() => break,
                received = connection.recv_from(&mut response) => received,
            };
            let Ok((length, response_source)) = received else {
                break;
            };
            let response_source = destination_nat
                .lock()
                .await
                .translate_source(response_source);
            if !filter.allows(&response_source) {
                continue;
            }
            let source = match response_source {
                SocksAddr::Ip(source) => source,
                SocksAddr::Domain { .. } => original_destination,
            };
            let _ = send_transparent_udp(source, client, &response[..length]);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::NatKey;
    use crate::{common::network::SocksAddr, option::UdpNatBehavior};

    #[test]
    fn nat_mapping_keys_follow_rfc4787_dependency_levels() {
        let source = "192.0.2.1:1234".parse().unwrap();
        let first = SocksAddr::new("198.51.100.1", 53);
        let same_address = SocksAddr::new("198.51.100.1", 5353);
        let second = SocksAddr::new("198.51.100.2", 53);
        assert_eq!(
            NatKey::new(
                UdpNatBehavior::EndpointIndependent,
                source,
                &first,
                None
            ),
            NatKey::new(
                UdpNatBehavior::EndpointIndependent,
                source,
                &second,
                None
            )
        );
        assert_eq!(
            NatKey::new(UdpNatBehavior::AddressDependent, source, &first, None),
            NatKey::new(
                UdpNatBehavior::AddressDependent,
                source,
                &same_address,
                None
            )
        );
        assert_ne!(
            NatKey::new(
                UdpNatBehavior::AddressAndPortDependent,
                source,
                &first,
                None
            ),
            NatKey::new(
                UdpNatBehavior::AddressAndPortDependent,
                source,
                &same_address,
                None
            )
        );
        assert_ne!(
            NatKey::new(
                UdpNatBehavior::EndpointIndependent,
                source,
                &first,
                Some(3)
            ),
            NatKey::new(
                UdpNatBehavior::EndpointIndependent,
                source,
                &first,
                Some(7)
            )
        );
    }
}
