//! OS TUN bridge for endpoint `system` modes.
//!
//! The endpoint owns encryption and its userspace stack. This component owns
//! only the privileged operating-system interface, its transactional routes,
//! and the raw-IP pump between that interface and an [`IpPacketPort`].

use std::{io, net::IpAddr, sync::Arc};

use network_interface::{NetworkInterface, NetworkInterfaceConfig as _};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::mpsc,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "linux")]
use super::tun_route_linux::{
    DEFAULT_ROUTE_TABLE, DEFAULT_RULE_PRIORITY, LinuxPolicyOptions,
    LinuxTunLease,
};
#[cfg(target_os = "windows")]
use super::tun_route_windows::{
    WindowsTunInterfaceOptions, WindowsTunLease, WindowsTunPolicy,
};
use super::{tun::create_tun_device, tun_route::TunRoutePlan};
#[cfg(target_os = "macos")]
use super::{
    tun_route::TunRouteLease,
    tun_route_darwin::{DarwinRouteBackend, configure_additional_addresses},
};
use crate::{
    adapter::{IpPacketPort, IpPacketReturn},
    common::lifecycle::{
        Lifecycle, LifecycleError, LifecycleFuture, StartStage,
    },
};

const PACKET_QUEUE_DEPTH: usize = 256;

/// Allocate the first unused conventional endpoint interface name.
pub(crate) fn calculate_interface_name(prefix: &str) -> io::Result<String> {
    let interfaces = NetworkInterface::show().map_err(io::Error::other)?;
    for index in 0..u16::MAX {
        let candidate = format!("{prefix}{index}");
        if interfaces.iter().all(|item| item.name != candidate) {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        format!("no unused {prefix} interface name"),
    ))
}

struct SystemInterfaceReturn {
    output: mpsc::Sender<Vec<u8>>,
    local_addresses: Vec<ipnet::IpNet>,
}

impl SystemInterfaceReturn {
    fn is_local_destination(&self, packet: &[u8]) -> bool {
        packet_destination(packet).is_some_and(|destination| {
            self.local_addresses
                .iter()
                .any(|prefix| prefix.contains(&destination))
        })
    }
}

impl IpPacketReturn for SystemInterfaceReturn {
    fn return_packets(&self, packets: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut unconsumed = Vec::new();
        for packet in packets {
            if !self.is_local_destination(&packet) {
                unconsumed.push(packet);
                continue;
            }
            // Once classified for the kernel interface, queue pressure means
            // packet loss rather than accidental delivery to the userspace
            // flow stack. This matches an ordinary bounded TUN write queue.
            let _ = self.output.try_send(packet);
        }
        unconsumed
    }
}

pub(crate) struct EndpointSystemInterface {
    name: String,
    requested_name: String,
    mtu: u16,
    addresses: Vec<ipnet::IpNet>,
    routes: Vec<ipnet::IpNet>,
    packet_port: Arc<dyn IpPacketPort>,
    cancellation: CancellationToken,
    tasks: Vec<JoinHandle<io::Result<()>>>,
    return_path: Option<Arc<SystemInterfaceReturn>>,
    #[cfg(target_os = "macos")]
    route_lease: Option<TunRouteLease<DarwinRouteBackend>>,
    #[cfg(target_os = "linux")]
    route_lease: Option<LinuxTunLease>,
    #[cfg(target_os = "windows")]
    route_lease: Option<WindowsTunLease>,
}

type SystemInterfaceFactory =
    dyn Fn() -> io::Result<EndpointSystemInterface> + Send + Sync;

/// Delays system-interface construction until the preceding VPN endpoint has
/// completed negotiation and published its assigned addresses and MTU.
pub(crate) struct DeferredEndpointSystemInterface {
    name: String,
    factory: Arc<SystemInterfaceFactory>,
    wait_for_initial_configuration: bool,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl DeferredEndpointSystemInterface {
    pub(crate) fn new(
        tag: &str,
        factory: impl Fn() -> io::Result<EndpointSystemInterface>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            name: format!("endpoint/deferred-system-interface[{tag}]"),
            factory: Arc::new(factory),
            wait_for_initial_configuration: false,
            cancellation: CancellationToken::new(),
            task: None,
        }
    }

    /// Start without blocking the Runtime while an interactive control plane
    /// is still obtaining its first network map.
    pub(crate) fn new_background(
        tag: &str,
        factory: impl Fn() -> io::Result<EndpointSystemInterface>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            name: format!("endpoint/deferred-system-interface[{tag}]"),
            factory: Arc::new(factory),
            wait_for_initial_configuration: true,
            cancellation: CancellationToken::new(),
            task: None,
        }
    }
}

impl Lifecycle for DeferredEndpointSystemInterface {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start {
                return Ok(());
            }
            self.cancellation = CancellationToken::new();
            let cancellation = self.cancellation.clone();
            let factory = self.factory.clone();
            let initial = if self.wait_for_initial_configuration {
                None
            } else {
                let mut interface = (self.factory)().map_err(|error| {
                    LifecycleError::Start {
                        component: self.name.clone(),
                        stage,
                        message: error.to_string(),
                    }
                })?;
                interface.start(stage).await?;
                Some(interface)
            };
            self.task = Some(tokio::spawn(monitor_configuration(
                factory,
                cancellation,
                initial,
            )));
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            if let Some(task) = self.task.take() {
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

async fn monitor_configuration(
    factory: Arc<SystemInterfaceFactory>,
    cancellation: CancellationToken,
    mut interface: Option<EndpointSystemInterface>,
) -> io::Result<()> {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            _ = interval.tick() => {
                let Ok(mut updated) = factory() else {
                    // Negotiated state can be momentarily absent while a
                    // tunnel reconnects. Keep the last usable interface.
                    continue;
                };
                if interface
                    .as_ref()
                    .is_some_and(|current| current.same_configuration(&updated))
                {
                    continue;
                }
                if let Some(mut current) = interface.take()
                    && let Err(error) = current.close().await
                {
                    tracing::warn!(%error, "close stale endpoint system interface");
                }
                match updated.start(StartStage::Start).await {
                    Ok(()) => interface = Some(updated),
                    Err(error) => {
                        tracing::warn!(%error, "apply endpoint system interface configuration");
                    }
                }
            }
        }
    }
    if let Some(mut interface) = interface {
        interface.close().await.map_err(io::Error::other)?;
    }
    Ok(())
}

impl EndpointSystemInterface {
    pub(crate) fn new(
        tag: &str,
        requested_name: String,
        mtu: usize,
        addresses: Vec<ipnet::IpNet>,
        routes: Vec<ipnet::IpNet>,
        packet_port: Arc<dyn IpPacketPort>,
    ) -> io::Result<Self> {
        if addresses.is_empty() {
            return Err(invalid("system interface requires an address"));
        }
        let mtu = u16::try_from(mtu).map_err(|_| {
            invalid(format!("system interface MTU is too large: {mtu}"))
        })?;
        if mtu < 576 {
            return Err(invalid(format!(
                "system interface MTU must be at least 576: {mtu}"
            )));
        }
        Ok(Self {
            name: format!("endpoint/system-interface[{tag}]"),
            requested_name,
            mtu,
            addresses,
            routes,
            packet_port,
            cancellation: CancellationToken::new(),
            tasks: Vec::new(),
            return_path: None,
            route_lease: None,
        })
    }

    fn same_configuration(&self, other: &Self) -> bool {
        self.requested_name == other.requested_name
            && self.mtu == other.mtu
            && self.addresses == other.addresses
            && self.routes == other.routes
            && Arc::ptr_eq(&self.packet_port, &other.packet_port)
    }

    async fn open(&mut self) -> io::Result<()> {
        let primary_ipv4 = self
            .addresses
            .iter()
            .find(|prefix| prefix.addr().is_ipv4())
            .copied();
        let primary = primary_ipv4
            .or_else(|| self.addresses.first().copied())
            .expect("addresses validated by constructor");
        let (device, interface_name) = create_tun_device(
            Some(primary),
            self.mtu,
            self.requested_name.clone(),
            String::new(),
        )
        .await?;
        if interface_name.is_empty() {
            return Err(io::Error::other(
                "created endpoint TUN has no interface name",
            ));
        }
        let plan = TunRoutePlan::from_routes(self.routes.clone());

        #[cfg(target_os = "macos")]
        {
            configure_additional_addresses(
                &interface_name,
                &self.addresses,
                primary_ipv4,
            )?;
            let backend = DarwinRouteBackend::new(&self.addresses);
            let mut lease = TunRouteLease::new(backend);
            lease.install(&plan).await?;
            self.route_lease = Some(lease);
        }
        #[cfg(target_os = "linux")]
        {
            let policy = LinuxPolicyOptions::from_options(&Default::default())
                .map_err(invalid)?;
            self.route_lease = Some(
                LinuxTunLease::install(
                    &interface_name,
                    &self.addresses,
                    primary_ipv4,
                    &plan,
                    DEFAULT_ROUTE_TABLE,
                    DEFAULT_RULE_PRIORITY,
                    false,
                    &policy,
                    &[],
                    false,
                    0,
                    0,
                    0,
                    "",
                )
                .await?,
            );
        }
        #[cfg(target_os = "windows")]
        {
            self.route_lease = Some(
                WindowsTunLease::install(
                    interface_name,
                    &self.addresses,
                    primary_ipv4,
                    &plan,
                    WindowsTunPolicy {
                        interface_options: Some(WindowsTunInterfaceOptions {
                            mtu: self.mtu,
                            auto_route: true,
                        }),
                        ..Default::default()
                    },
                )
                .await?,
            );
        }

        let (return_tx, mut return_rx) = mpsc::channel(PACKET_QUEUE_DEPTH);
        let return_path = Arc::new(SystemInterfaceReturn {
            output: return_tx,
            local_addresses: self.addresses.clone(),
        });
        let erased: Arc<dyn IpPacketReturn> = return_path.clone();
        self.packet_port.attach_return(Arc::downgrade(&erased))?;
        self.return_path = Some(return_path);

        let (mut read_device, mut write_device) = tokio::io::split(device);
        let read_cancellation = self.cancellation.clone();
        let read_port = self.packet_port.clone();
        let mtu = usize::from(self.mtu);
        self.tasks.push(tokio::spawn(async move {
            let mut packet = vec![0_u8; mtu];
            loop {
                let size = tokio::select! {
                    _ = read_cancellation.cancelled() => break,
                    result = read_device.read(&mut packet) => result?,
                };
                if size != 0 {
                    read_port
                        .write_packets(vec![packet[..size].to_vec()])
                        .await?;
                }
            }
            Ok(())
        }));

        let write_cancellation = self.cancellation.clone();
        self.tasks.push(tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = write_cancellation.cancelled() => break,
                    packet = return_rx.recv() => match packet {
                        Some(packet) => packet,
                        None => break,
                    },
                };
                write_device.write_all(&packet).await?;
            }
            Ok(())
        }));
        Ok(())
    }
}

impl Lifecycle for EndpointSystemInterface {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage == StartStage::Start {
                self.open().await.map_err(|error| LifecycleError::Start {
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
            if let Some(return_path) = self.return_path.take() {
                let erased: Arc<dyn IpPacketReturn> = return_path;
                self.packet_port.detach_return(&Arc::downgrade(&erased));
            }
            let mut errors = Vec::new();
            for task in self.tasks.drain(..) {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => errors.push(error.to_string()),
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => errors.push(error.to_string()),
                }
            }
            #[cfg(target_os = "macos")]
            if let Some(mut lease) = self.route_lease.take()
                && let Err(error) = lease.close().await
            {
                errors.push(error.to_string());
            }
            #[cfg(target_os = "linux")]
            if let Some(lease) = self.route_lease.take()
                && let Err(error) = lease.close().await
            {
                errors.push(error.to_string());
            }
            #[cfg(target_os = "windows")]
            if let Some(lease) = self.route_lease.take()
                && let Err(error) = lease.close().await
            {
                errors.push(error.to_string());
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(LifecycleError::Close {
                    component: self.name.clone(),
                    message: errors.join("; "),
                })
            }
        })
    }
}

fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => Some(IpAddr::V4(
            packet[16..20]
                .try_into()
                .ok()
                .map(u32::from_be_bytes)?
                .into(),
        )),
        Some(6) if packet.len() >= 40 => Some(IpAddr::V6(
            packet[24..40]
                .try_into()
                .ok()
                .map(u128::from_be_bytes)?
                .into(),
        )),
        _ => None,
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    #[test]
    fn system_return_sends_local_destinations_to_kernel() {
        let (tx, mut rx) = mpsc::channel(2);
        let path = SystemInterfaceReturn {
            output: tx,
            local_addresses: vec!["10.0.0.1/24".parse().unwrap()],
        };
        let remote = ipv4_packet([8, 8, 8, 8]);
        let local = ipv4_packet([10, 0, 0, 2]);
        let unconsumed =
            path.return_packets(vec![remote.clone(), local.clone()]);
        assert_eq!(unconsumed, vec![remote]);
        assert_eq!(rx.try_recv().unwrap(), local);
    }

    #[test]
    fn packet_destination_reads_both_ip_families() {
        assert_eq!(
            packet_destination(&ipv4_packet([192, 0, 2, 1])),
            Some("192.0.2.1".parse().unwrap())
        );
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x60;
        packet[24..40].copy_from_slice(
            &u128::from_be_bytes(
                "2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            )
            .to_be_bytes(),
        );
        assert_eq!(
            packet_destination(&packet),
            Some("2001:db8::1".parse().unwrap())
        );
    }
}
