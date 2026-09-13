//! Cross-platform network change monitoring with the Windows interface event
//! that the upstream `sing-tun` monitor relies on.

use std::{io, net::IpAddr};

use super::network::SocksAddr;

/// A network monitor whose state updates are debounced and reduced to actual
/// interface-state deltas by `netwatch`.
///
/// On Windows, `netwatch` already listens for route and unicast-address
/// changes.  A metric, connectivity, or operational-state update can arrive
/// solely through `NotifyIpInterfaceChange`, however.  The pinned Go
/// `sing-tun` backend registers that callback, so this wrapper feeds the same
/// event into `netwatch`'s existing refresh/debounce actor.
#[derive(Debug)]
pub(crate) struct NetworkMonitor {
    inner: std::sync::Arc<netwatch::netmon::Monitor>,
    #[cfg(windows)]
    _interface_changes: windows::InterfaceChangeMonitor,
}

impl NetworkMonitor {
    pub(crate) async fn new() -> io::Result<Self> {
        let inner = std::sync::Arc::new(
            netwatch::netmon::Monitor::new()
                .await
                .map_err(|error| io::Error::other(error.to_string()))?,
        );
        #[cfg(windows)]
        let interface_changes =
            windows::InterfaceChangeMonitor::new(inner.clone())?;
        Ok(Self {
            inner,
            #[cfg(windows)]
            _interface_changes: interface_changes,
        })
    }

    pub(crate) fn interface_state(
        &self,
    ) -> n0_watcher::Direct<netwatch::netmon::State> {
        self.inner.interface_state()
    }
}

/// Classify directly connected destinations by the longest interface prefix.
///
/// Upstream `sing-tun` includes the physical interface index in
/// endpoint-independent UDP NAT keys so one client endpoint cannot reuse an
/// outbound socket across two local links. `netwatch` intentionally keeps the
/// OS index and flags private, so refreshes use the already-shared `netdev`
/// inventory to preserve the exact upstream index and to exclude loopback,
/// point-to-point, and non-broadcast interfaces.
#[derive(Debug, Default)]
pub(crate) struct DirectInterfaceClassifier {
    entries: Vec<(ipnet::IpNet, u32)>,
}

impl DirectInterfaceClassifier {
    pub(crate) fn from_system() -> Self {
        Self::from_interfaces(netdev::get_interfaces())
    }

    fn from_interfaces(
        interfaces: impl IntoIterator<Item = netdev::Interface>,
    ) -> Self {
        let mut entries = interfaces
            .into_iter()
            .filter(|interface| {
                interface.is_up()
                    && !interface.is_loopback()
                    && !interface.is_point_to_point()
                    && interface.is_broadcast()
            })
            .flat_map(|interface| {
                let index = interface.index;
                interface
                    .ipv4
                    .into_iter()
                    .map(ipnet::IpNet::V4)
                    .chain(interface.ipv6.into_iter().map(ipnet::IpNet::V6))
                    .filter(|network| is_global_unicast(network.addr()))
                    .map(move |network| (network.trunc(), index))
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|(network, _)| {
            std::cmp::Reverse(network.prefix_len())
        });
        Self { entries }
    }

    pub(crate) fn classify(&self, destination: &SocksAddr) -> Option<u32> {
        let SocksAddr::Ip(destination) = destination else {
            return None;
        };
        let address = canonical_ip(destination.ip());
        self.entries
            .iter()
            .find(|(network, _)| network.contains(&address))
            .map(|(_, index)| *index)
    }

    pub(crate) fn contains_interface(&self, index: u32) -> bool {
        self.entries
            .iter()
            .any(|(_, interface_index)| *interface_index == index)
    }
}

fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

fn is_global_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_multicast()
                && !address.is_broadcast()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_unicast_link_local()
                && !address.is_multicast()
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::{ffi::c_void, io, ptr, sync::Arc};

    use tokio::{sync::mpsc, task::JoinHandle};
    use windows_sys::Win32::{
        Foundation::{ERROR_SUCCESS, HANDLE},
        NetworkManagement::IpHelper::{
            CancelMibChangeNotify2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
            NotifyIpInterfaceChange,
        },
        Networking::WinSock::AF_UNSPEC,
    };

    #[derive(Debug)]
    pub(super) struct InterfaceChangeMonitor {
        handle: HANDLE,
        task: JoinHandle<()>,
        // The callback context must remain at a stable address until Windows
        // confirms cancellation in Drop.
        sender: Box<mpsc::UnboundedSender<()>>,
    }

    // SAFETY: `handle` is an opaque cancellation token and `sender` is safe to
    // call from arbitrary Windows callback threads.  Drop cancels callbacks
    // before releasing the boxed context.
    unsafe impl Send for InterfaceChangeMonitor {}
    unsafe impl Sync for InterfaceChangeMonitor {}

    impl InterfaceChangeMonitor {
        pub(super) fn new(
            monitor: Arc<netwatch::netmon::Monitor>,
        ) -> io::Result<Self> {
            let (sender, mut receiver) = mpsc::unbounded_channel();
            let sender = Box::new(sender);
            let mut handle = ptr::null_mut();
            // SAFETY: the boxed sender has a stable address and remains owned
            // by this value until after CancelMibChangeNotify2 returns.
            let status = unsafe {
                NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(interface_change_callback),
                    sender.as_ref() as *const _ as *const c_void,
                    false,
                    &mut handle,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            let task = tokio::spawn(async move {
                while receiver.recv().await.is_some() {
                    if monitor.network_change().await.is_err() {
                        break;
                    }
                }
            });
            Ok(Self {
                handle,
                task,
                sender,
            })
        }
    }

    impl Drop for InterfaceChangeMonitor {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                // SAFETY: this handle came from NotifyIpInterfaceChange and is
                // canceled exactly once before its callback context is freed.
                let _ = unsafe { CancelMibChangeNotify2(self.handle) };
                self.handle = ptr::null_mut();
            }
            self.task.abort();
            // Keep an explicit read so the context field cannot accidentally
            // become an apparently-unused lifetime guard.
            let _ = &self.sender;
        }
    }

    unsafe extern "system" fn interface_change_callback(
        context: *const c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        _notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        if context.is_null() {
            return;
        }
        // SAFETY: registration passes a boxed sender as context and Drop waits
        // for callback cancellation before releasing it.
        let sender = unsafe { &*(context as *const mpsc::UnboundedSender<()>) };
        let _ = sender.send(());
    }
}

#[cfg(test)]
mod tests {
    use n0_watcher::Watcher as _;

    use super::{DirectInterfaceClassifier, NetworkMonitor};
    use crate::common::network::SocksAddr;

    #[test]
    fn direct_interface_classifier_uses_longest_prefix_and_unmaps_ipv4() {
        let classifier = DirectInterfaceClassifier {
            entries: vec![
                ("10.1.0.0/16".parse().unwrap(), 7),
                ("10.0.0.0/8".parse().unwrap(), 3),
            ],
        };
        assert_eq!(
            classifier.classify(&SocksAddr::new("10.1.2.3", 53)),
            Some(7)
        );
        assert_eq!(
            classifier.classify(&SocksAddr::new("::ffff:10.1.2.3", 53)),
            Some(7)
        );
        assert_eq!(
            classifier.classify(&SocksAddr::new("example.com", 53)),
            None
        );
        assert!(classifier.contains_interface(3));
        assert!(classifier.contains_interface(7));
        assert!(!classifier.contains_interface(9));
    }

    #[test]
    fn direct_interface_classifier_keeps_only_up_broadcast_interfaces() {
        const IFF_UP: u32 = 0x1;
        const IFF_BROADCAST: u32 = 0x2;
        const IFF_LOOPBACK: u32 = 0x8;
        const IFF_POINT_TO_POINT: u32 = 0x10;

        let interface = |index, flags, address: &str| {
            let mut interface = netdev::Interface::dummy();
            interface.index = index;
            interface.flags = flags;
            interface.ipv4 = vec![address.parse().unwrap()];
            interface
        };
        let classifier = DirectInterfaceClassifier::from_interfaces([
            interface(2, IFF_UP | IFF_BROADCAST, "10.1.0.2/16"),
            interface(3, IFF_UP | IFF_POINT_TO_POINT, "10.2.0.2/16"),
            interface(4, IFF_UP | IFF_LOOPBACK, "10.3.0.2/16"),
            interface(5, IFF_BROADCAST, "10.4.0.2/16"),
        ]);

        assert_eq!(
            classifier.classify(&SocksAddr::new("10.1.2.3", 53)),
            Some(2)
        );
        assert_eq!(classifier.classify(&SocksAddr::new("10.2.2.3", 53)), None);
        assert_eq!(classifier.classify(&SocksAddr::new("10.3.2.3", 53)), None);
        assert_eq!(classifier.classify(&SocksAddr::new("10.4.2.3", 53)), None);
    }

    #[tokio::test]
    async fn exposes_the_initial_interface_state() {
        let monitor = NetworkMonitor::new().await.unwrap();
        let mut watcher = monitor.interface_state();
        let state = watcher.get();
        assert!(
            state
                .interfaces
                .values()
                .all(|interface| !interface.name().is_empty())
        );
    }
}
