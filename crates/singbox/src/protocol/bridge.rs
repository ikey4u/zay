//! L3 bridge outbound.
//!
//! Unlike ordinary outbounds, bridge only exposes an [`IpPacketPort`]. The
//! endpoint flow dispatcher applies source NAT before handing packets to this
//! port; the native backend forwards them through a dedicated TUN and returns
//! kernel-NATed replies through the attached return paths.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::{mpsc, oneshot};

use network_interface::{NetworkInterface, NetworkInterfaceConfig};

use crate::{
    adapter::{
        DialFuture, Dialer, IpPacketPort, IpPacketReturn, PacketFuture,
        PacketStream,
    },
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::SocksAddr,
    },
    option::BridgeOutboundOptions,
};

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
mod windows;

const MAX_INSTANCES: usize = 254;
const IPV4_BASE: u32 = u32::from_be_bytes([192, 0, 2, 1]);
const IPV6_BASE: u128 = u128::from_be_bytes([
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);

static INSTANCE_INDICES: OnceLock<Mutex<[bool; MAX_INSTANCES]>> =
    OnceLock::new();

struct IndexLease(usize);

impl IndexLease {
    fn allocate() -> io::Result<Self> {
        let mut indices = INSTANCE_INDICES
            .get_or_init(|| Mutex::new([false; MAX_INSTANCES]))
            .lock()
            .map_err(|_| io::Error::other("bridge index lock poisoned"))?;
        let index = indices.iter().position(|used| !used).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "too many bridge outbounds: limit is 254",
            )
        })?;
        indices[index] = true;
        Ok(Self(index))
    }
}

impl Drop for IndexLease {
    fn drop(&mut self) {
        if let Ok(mut indices) = INSTANCE_INDICES
            .get_or_init(|| Mutex::new([false; MAX_INSTANCES]))
            .lock()
        {
            indices[self.0] = false;
        }
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct BridgeWrite {
    pub(crate) packets: Vec<Vec<u8>>,
    pub(crate) result: oneshot::Sender<io::Result<()>>,
}

pub(crate) struct RunningBridge {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) writes: mpsc::Sender<BridgeWrite>,
    #[cfg(target_os = "macos")]
    pub(crate) backend: darwin::DarwinBridge,
    #[cfg(target_os = "linux")]
    pub(crate) backend: linux::LinuxBridge,
    #[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
    pub(crate) backend: windows::WindowsBridge,
}

/// Flow-only bridge outbound registered alongside ordinary dialers.
pub struct BridgeOutbound {
    tag: String,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    options: BridgeOutboundOptions,
    _index: IndexLease,
    ipv4_port: IpAddr,
    ipv6_port: IpAddr,
    ipv6_active: AtomicBool,
    effective_mtu: AtomicUsize,
    selector_start: AtomicU16,
    self_port: OnceLock<Weak<dyn IpPacketPort>>,
    return_paths: Mutex<Vec<Weak<dyn IpPacketReturn>>>,
    local_addresses: Mutex<Option<(Instant, Vec<IpAddr>)>>,
    writes: Mutex<Option<mpsc::Sender<BridgeWrite>>>,
    running: tokio::sync::Mutex<Option<RunningBridge>>,
}

impl BridgeOutbound {
    pub fn new(
        tag: impl Into<String>,
        options: BridgeOutboundOptions,
    ) -> io::Result<Arc<Self>> {
        let index = IndexLease::allocate()?;
        let ipv4_port = IpAddr::V4(Ipv4Addr::from(
            IPV4_BASE + u32::try_from(index.0).expect("bridge index fits u32"),
        ));
        let ipv6_port = IpAddr::V6(Ipv6Addr::from(
            IPV6_BASE
                + u128::try_from(index.0).expect("bridge index fits u128"),
        ));
        let outbound = Arc::new(Self {
            tag: tag.into(),
            options,
            _index: index,
            ipv4_port,
            ipv6_port,
            ipv6_active: AtomicBool::new(true),
            effective_mtu: AtomicUsize::new(if cfg!(target_os = "macos") {
                2016
            } else if cfg!(target_os = "linux") {
                65_535
            } else {
                0
            }),
            selector_start: AtomicU16::new(0),
            self_port: OnceLock::new(),
            return_paths: Mutex::new(Vec::new()),
            local_addresses: Mutex::new(None),
            writes: Mutex::new(None),
            running: tokio::sync::Mutex::new(None),
        });
        let port: Arc<dyn IpPacketPort> = outbound.clone();
        let _ = outbound.self_port.set(Arc::downgrade(&port));
        Ok(outbound)
    }

    async fn start(self: &Arc<Self>) -> io::Result<()> {
        #[cfg(not(any(
            target_os = "macos",
            target_os = "linux",
            all(windows, any(target_arch = "x86_64", target_arch = "x86"))
        )))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native bridge backend is not ported on this platform yet",
            ))
        }
        #[cfg(any(
            target_os = "macos",
            target_os = "linux",
            all(windows, any(target_arch = "x86_64", target_arch = "x86"))
        ))]
        {
            let mut running = self.running.lock().await;
            if running.is_some() {
                return Ok(());
            }
            #[cfg(target_os = "macos")]
            let next = darwin::start(self.clone()).await?;
            #[cfg(target_os = "linux")]
            let next = linux::start(self.clone()).await?;
            #[cfg(all(
                windows,
                any(target_arch = "x86_64", target_arch = "x86")
            ))]
            let next = windows::start(self.clone()).await?;
            *self.writes.lock().map_err(|_| {
                io::Error::other("bridge write lock poisoned")
            })? = Some(next.writes.clone());
            *running = Some(next);
            Ok(())
        }
    }

    async fn close(&self) -> io::Result<()> {
        self.writes
            .lock()
            .map_err(|_| io::Error::other("bridge write lock poisoned"))?
            .take();
        let Some(running) = self.running.lock().await.take() else {
            return Ok(());
        };
        #[cfg(any(
            target_os = "macos",
            target_os = "linux",
            all(windows, any(target_arch = "x86_64", target_arch = "x86"))
        ))]
        {
            running.backend.close().await
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "linux",
            all(windows, any(target_arch = "x86_64", target_arch = "x86"))
        )))]
        {
            let _ = running;
            Ok(())
        }
    }

    pub(crate) fn tag(&self) -> &str {
        &self.tag
    }

    pub(crate) fn preferred_address_for_pre_match(
        &self,
        address: IpAddr,
    ) -> bool {
        let Ok(mut cache) = self.local_addresses.lock() else {
            return false;
        };
        let now = Instant::now();
        if cache.as_ref().is_none_or(|(updated, _)| {
            now.duration_since(*updated) >= Duration::from_secs(1)
        }) {
            let Ok(interfaces) = NetworkInterface::show() else {
                return false;
            };
            *cache = Some((
                now,
                interfaces
                    .into_iter()
                    .flat_map(|interface| {
                        interface.addr.into_iter().map(|address| address.ip())
                    })
                    .collect(),
            ));
        }
        bridge_prefers_address(
            address,
            cache
                .as_ref()
                .map(|(_, addresses)| addresses.iter().copied())
                .into_iter()
                .flatten(),
        )
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "linux",
        all(windows, any(target_arch = "x86_64", target_arch = "x86"))
    ))]
    pub(crate) fn options(&self) -> &BridgeOutboundOptions {
        &self.options
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "linux",
        all(windows, any(target_arch = "x86_64", target_arch = "x86"))
    ))]
    pub(crate) fn set_ipv6_active(&self, active: bool) {
        self.ipv6_active.store(active, Ordering::Release);
    }

    #[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
    pub(crate) fn set_effective_mtu(&self, mtu: usize) {
        self.effective_mtu.store(mtu, Ordering::Release);
    }

    #[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
    pub(crate) fn set_selector_start(&self, start: u16) {
        self.selector_start.store(start, Ordering::Release);
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "linux",
        all(windows, any(target_arch = "x86_64", target_arch = "x86"))
    ))]
    pub(crate) fn deliver_return(&self, mut packet: Vec<u8>) {
        crate::endpoint::flow_dispatch::fix_return_checksum(&mut packet);
        let paths = match self.return_paths.lock() {
            Ok(mut paths) => {
                paths.retain(|path| path.strong_count() != 0);
                paths.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
            }
            Err(_) => return,
        };
        let mut packets = vec![packet];
        let mut headroom = 0;
        for path in paths {
            if packets.is_empty() {
                break;
            }
            let next_headroom = path.return_headroom();
            if next_headroom != headroom {
                packets = packets
                    .into_iter()
                    .map(|packet| {
                        let payload =
                            packet.get(headroom..).unwrap_or_default();
                        let mut next = vec![0; next_headroom + payload.len()];
                        next[next_headroom..].copy_from_slice(payload);
                        next
                    })
                    .collect();
                headroom = next_headroom;
            }
            packets = path.return_packets(packets);
        }
    }
}

fn bridge_prefers_address(
    address: IpAddr,
    local_addresses: impl IntoIterator<Item = IpAddr>,
) -> bool {
    let address = match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    };
    !address.is_loopback()
        && !address.is_unspecified()
        && !local_addresses.into_iter().any(|local| local == address)
}

impl Dialer for BridgeOutbound {
    fn dial_tcp<'a>(&'a self, _destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only L3 traffic is supported by bridge",
            ))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only L3 traffic is supported by bridge",
            ))
        })
    }

    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        self.self_port.get()?.upgrade()
    }
}

impl IpPacketPort for BridgeOutbound {
    fn port_addresses(&self) -> (Option<IpAddr>, Option<IpAddr>) {
        (
            Some(self.ipv4_port),
            self.ipv6_active
                .load(Ordering::Acquire)
                .then_some(self.ipv6_port),
        )
    }

    fn port_mtu(&self) -> usize {
        self.effective_mtu.load(Ordering::Acquire)
    }

    fn port_selector_range(&self) -> (u16, u16) {
        let start = self.selector_start.load(Ordering::Acquire);
        if start == 0 { (0, 0) } else { (start, 1024) }
    }

    fn attach_return(
        &self,
        return_path: Weak<dyn IpPacketReturn>,
    ) -> io::Result<()> {
        let mut paths = self
            .return_paths
            .lock()
            .map_err(|_| io::Error::other("bridge return lock poisoned"))?;
        paths.retain(|path| path.strong_count() != 0);
        if !paths.iter().any(|path| Weak::ptr_eq(path, &return_path)) {
            paths.push(return_path);
        }
        Ok(())
    }

    fn detach_return(&self, return_path: &Weak<dyn IpPacketReturn>) {
        if let Ok(mut paths) = self.return_paths.lock() {
            paths.retain(|path| !Weak::ptr_eq(path, return_path));
        }
    }

    fn write_packets<'a>(
        &'a self,
        packets: Vec<Vec<u8>>,
    ) -> PacketFuture<'a, ()> {
        Box::pin(async move {
            let sender = self
                .writes
                .lock()
                .map_err(|_| io::Error::other("bridge write lock poisoned"))?
                .clone()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "bridge is not started",
                    )
                })?;
            let (result_tx, result_rx) = oneshot::channel();
            sender
                .send(BridgeWrite {
                    packets,
                    result: result_tx,
                })
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "bridge is closed",
                    )
                })?;
            result_rx.await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "bridge is closed")
            })?
        })
    }
}

/// One lifecycle component owns all bridge outbounds in registry order.
pub(crate) struct BridgeOutboundService {
    bridges: Vec<Arc<BridgeOutbound>>,
}

impl BridgeOutboundService {
    pub(crate) fn new(bridges: Vec<Arc<BridgeOutbound>>) -> Self {
        Self { bridges }
    }
}

impl Lifecycle for BridgeOutboundService {
    fn name(&self) -> &str {
        "outbound/bridge"
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start {
                return Ok(());
            }
            for bridge in &self.bridges {
                bridge.start().await.map_err(|error| {
                    LifecycleError::Start {
                        component: format!("outbound/bridge/{}", bridge.tag()),
                        stage,
                        message: error.to_string(),
                    }
                })?;
            }
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            let mut errors = Vec::new();
            for bridge in self.bridges.iter().rev() {
                if let Err(error) = bridge.close().await {
                    errors.push(format!("{}: {error}", bridge.tag()));
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(LifecycleError::Close {
                    component: self.name().into(),
                    message: errors.join("; "),
                })
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_indices_produce_upstream_port_addresses() {
        let first =
            BridgeOutbound::new("a", BridgeOutboundOptions::default()).unwrap();
        let second =
            BridgeOutbound::new("b", BridgeOutboundOptions::default()).unwrap();
        let (Some(IpAddr::V4(first4)), Some(IpAddr::V6(first6))) =
            first.port_addresses()
        else {
            panic!("bridge must expose both address families");
        };
        let (Some(IpAddr::V4(second4)), Some(IpAddr::V6(second6))) =
            second.port_addresses()
        else {
            panic!("bridge must expose both address families");
        };
        assert_eq!(u32::from(second4), u32::from(first4) + 1);
        assert_eq!(u128::from(second6), u128::from(first6) + 1);
        assert_eq!(first4.octets()[..3], [192, 0, 2]);
        assert_eq!(first6.segments()[..4], [0x2001, 0x0db8, 0, 0]);
    }

    #[test]
    fn bridge_pre_match_excludes_host_addresses() {
        let local = "192.0.2.8".parse().unwrap();
        assert!(!bridge_prefers_address(
            local,
            [local, "2001:db8::8".parse().unwrap()]
        ));
        assert!(!bridge_prefers_address(
            "127.0.0.1".parse().unwrap(),
            std::iter::empty()
        ));
        assert!(!bridge_prefers_address(
            "::ffff:127.0.0.1".parse().unwrap(),
            std::iter::empty()
        ));
        assert!(!bridge_prefers_address(
            "::".parse().unwrap(),
            std::iter::empty()
        ));
        assert!(bridge_prefers_address(
            "198.51.100.9".parse().unwrap(),
            [local]
        ));
    }

    #[tokio::test]
    async fn bridge_rejects_l4_and_writes_before_start() {
        let bridge =
            BridgeOutbound::new("bridge-out", BridgeOutboundOptions::default())
                .unwrap();
        let error =
            match bridge.dial_tcp(&SocksAddr::new("example.com", 443)).await {
                Ok(_) => panic!("bridge accepted an L4 stream"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            bridge
                .write_packets(vec![vec![0x45; 20]])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }
}
