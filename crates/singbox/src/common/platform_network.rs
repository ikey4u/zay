//! Route-level dialer defaults and runtime-scoped mobile network selection.

use std::io;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::{net::SocketAddr, sync::Arc};

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use n0_watcher::Watcher as _;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use tokio::sync::OnceCell;

use crate::{
    constant::InterfaceType,
    option::{
        AbstractDialerOptions, DomainResolveOptions, FwMark, RouteOptions,
    },
};
#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "macos",
    test
))]
use crate::{
    constant::NetworkStrategy,
    option::{
        Duration as OptionDuration, InterfaceType as OptionInterfaceType,
        Listable, NetworkStrategy as OptionNetworkStrategy,
    },
};

/// Route-level defaults inherited by every dialer when the individual dialer
/// has not supplied the corresponding option.
#[derive(Debug, Clone, Default)]
pub(crate) struct RouteDialerDefaults {
    pub default_interface: String,
    pub routing_mark: FwMark,
    pub domain_resolver: Option<DomainResolveOptions>,
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub auto_detect_interface: Option<Arc<AutoDetectInterfaceProvider>>,
}

impl RouteDialerDefaults {
    pub fn from_route_options(route: &RouteOptions) -> Self {
        Self {
            default_interface: route.default_interface.clone(),
            routing_mark: route.default_mark,
            domain_resolver: route.default_domain_resolver.clone(),
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            auto_detect_interface: route
                .auto_detect_interface
                .then(|| Arc::new(AutoDetectInterfaceProvider::default())),
        }
    }

    pub fn apply(&self, options: &mut AbstractDialerOptions) {
        let has_explicit_bind = !options.bind_interface.is_empty()
            || options.inet4_bind_address.is_some()
            || options.inet6_bind_address.is_some();
        if !has_explicit_bind && !self.default_interface.is_empty() {
            options.bind_interface.clone_from(&self.default_interface);
        }
        if options.routing_mark.0 == 0 {
            options.routing_mark = self.routing_mark;
        }
        if options.domain_resolver.is_none() {
            options.domain_resolver = self.domain_resolver.clone();
        }
    }
}

/// Runtime-scoped desktop default-interface monitor.
///
/// The monitor is initialized on the first dial because runtime construction is
/// synchronous.  All dialers produced by one runtime share this value through
/// [`RouteDialerDefaults`], while every dial reads the watcher's current state.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[derive(Debug, Default)]
pub(crate) struct AutoDetectInterfaceProvider {
    monitor: OnceCell<crate::common::network_monitor::NetworkMonitor>,
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
impl AutoDetectInterfaceProvider {
    pub async fn interface_for(
        &self,
        destination: SocketAddr,
    ) -> io::Result<String> {
        let monitor = self
            .monitor
            .get_or_try_init(|| async {
                crate::common::network_monitor::NetworkMonitor::new().await
            })
            .await?;
        let mut watcher = monitor.interface_state();
        let state = watcher.get();

        if let Some(source) = routed_source_address(destination)
            && let Some(interface) = state.interfaces.values().find(|item| {
                item.is_up()
                    && item.addrs().any(|address| address.addr() == source)
            })
        {
            return Ok(interface.name().to_owned());
        }
        state.default_route_interface.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no route to {destination}"),
            )
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn routed_source_address(destination: SocketAddr) -> Option<std::net::IpAddr> {
    let bind = if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    let destination = if destination.port() == 0 {
        SocketAddr::new(destination.ip(), 9)
    } else {
        destination
    };
    socket.connect(destination).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

#[derive(Debug, Clone, Default)]
#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "macos",
    test
))]
pub(crate) struct PlatformNetworkDefaults {
    pub auto_detect_interface: bool,
    pub default_interface: String,
    pub network_strategy: Option<OptionNetworkStrategy>,
    pub network_type: Listable<OptionInterfaceType>,
    pub fallback_network_type: Listable<OptionInterfaceType>,
    pub fallback_delay: OptionDuration,
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "macos",
    test
))]
impl PlatformNetworkDefaults {
    pub fn from_route_options(route: &RouteOptions) -> io::Result<Self> {
        let defaults = Self {
            auto_detect_interface: route.auto_detect_interface,
            default_interface: route.default_interface.clone(),
            network_strategy: route.default_network_strategy,
            network_type: route.default_network_type.clone(),
            fallback_network_type: route.default_fallback_network_type.clone(),
            fallback_delay: route.default_fallback_delay,
        };
        let has_network_defaults = defaults.network_strategy.is_some()
            || !defaults.network_type.as_slice().is_empty()
            || !defaults.fallback_network_type.as_slice().is_empty()
            || defaults
                .fallback_delay
                .as_std()
                .is_some_and(|delay| !delay.is_zero());
        if has_network_defaults && !defaults.auto_detect_interface {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "route.auto_detect_interface is required by default_network_strategy",
            ));
        }
        if !defaults.default_interface.is_empty() && has_network_defaults {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "route.default_network_strategy conflicts with route.default_interface",
            ));
        }
        Ok(defaults)
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn requires_provider(&self) -> bool {
        self.auto_detect_interface && self.default_interface.is_empty()
    }

    pub fn apply(&self, options: &mut AbstractDialerOptions) {
        let disables_default_bind = !options.bind_interface.is_empty()
            || options.inet4_bind_address.is_some()
            || options.inet6_bind_address.is_some();
        if disables_default_bind {
            return;
        }
        if !self.default_interface.is_empty() {
            options.bind_interface = self.default_interface.clone();
            return;
        }
        if !self.auto_detect_interface {
            return;
        }
        if options.network_strategy.is_none()
            && options.network_type.as_slice().is_empty()
            && options.fallback_network_type.as_slice().is_empty()
        {
            options.network_strategy = self
                .network_strategy
                .or(Some(OptionNetworkStrategy(NetworkStrategy::Default)));
            options.network_type = self.network_type.clone();
            options.fallback_network_type = self.fallback_network_type.clone();
        }
        if options
            .fallback_delay
            .as_std()
            .is_none_or(|delay| delay.is_zero())
        {
            options.fallback_delay = self.fallback_delay;
        }
    }
}

/// One host network that can carry an outbound socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformNetworkInterface {
    /// Opaque stable identifier understood by the provider.
    pub id: String,
    pub name: String,
    pub index: u32,
    pub interface_type: InterfaceType,
    pub is_default: bool,
    /// Marks the application's own TUN interface, which must never be selected
    /// as an underlay.
    pub is_own: bool,
}

/// A borrowed socket passed to [`PlatformNetworkProvider::bind_socket`].
/// The numeric handle is valid only for the duration of the callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformSocket {
    pub raw_handle: i64,
    pub ipv6: bool,
}

/// Host bridge for Android `Network.bindSocket` and Apple per-interface
/// binding. Implementations must not retain the borrowed socket handle.
pub trait PlatformNetworkProvider: Send + Sync {
    /// Return the currently available physical networks. The library calls
    /// this for each new connection so network changes do not require a
    /// process-global cache.
    fn network_interfaces(&self) -> io::Result<Vec<PlatformNetworkInterface>>;

    /// Bind a newly-created socket before connect/listen.
    fn bind_socket(
        &self,
        socket: PlatformSocket,
        interface: &PlatformNetworkInterface,
    ) -> io::Result<()>;
}

#[derive(Debug, Clone)]
#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "macos",
    test
))]
pub(crate) struct PlatformNetworkSelection {
    pub primary: Vec<PlatformNetworkInterface>,
    pub fallback: Vec<PlatformNetworkInterface>,
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "macos",
    test
))]
pub(crate) fn select_platform_networks(
    options: &AbstractDialerOptions,
    interfaces: Vec<PlatformNetworkInterface>,
) -> io::Result<PlatformNetworkSelection> {
    let interfaces = interfaces
        .into_iter()
        .filter(|interface| !interface.is_own)
        .collect::<Vec<_>>();
    let strategy = options
        .network_strategy
        .map(|strategy| strategy.0)
        .unwrap_or(NetworkStrategy::Default);
    let primary_types = options
        .network_type
        .as_slice()
        .iter()
        .map(|interface_type| interface_type.0)
        .collect::<Vec<_>>();
    let fallback_types = options
        .fallback_network_type
        .as_slice()
        .iter()
        .map(|interface_type| interface_type.0)
        .collect::<Vec<_>>();
    let matches = |interface: &&PlatformNetworkInterface,
                   types: &[InterfaceType]| {
        types.is_empty() || types.contains(&interface.interface_type)
    };

    let (primary, fallback) = match strategy {
        NetworkStrategy::Default => {
            let primary = if primary_types.is_empty() {
                let defaults = interfaces
                    .iter()
                    .filter(|interface| interface.is_default)
                    .cloned()
                    .collect::<Vec<_>>();
                if defaults.is_empty() {
                    interfaces.clone()
                } else {
                    defaults
                }
            } else {
                interfaces
                    .iter()
                    .filter(|interface| matches(interface, &primary_types))
                    .cloned()
                    .collect()
            };
            (primary, Vec::new())
        }
        NetworkStrategy::Hybrid => (
            interfaces
                .iter()
                .filter(|interface| matches(interface, &primary_types))
                .cloned()
                .collect(),
            Vec::new(),
        ),
        NetworkStrategy::Fallback => {
            let primary = if primary_types.is_empty() {
                let defaults = interfaces
                    .iter()
                    .filter(|interface| interface.is_default)
                    .cloned()
                    .collect::<Vec<_>>();
                if defaults.is_empty() {
                    interfaces.clone()
                } else {
                    defaults
                }
            } else {
                interfaces
                    .iter()
                    .filter(|interface| matches(interface, &primary_types))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            let fallback = if fallback_types.is_empty() {
                interfaces
                    .iter()
                    .filter(|interface| {
                        !primary.iter().any(|primary| {
                            primary.index == interface.index
                                && primary.id == interface.id
                        })
                    })
                    .cloned()
                    .collect()
            } else {
                interfaces
                    .iter()
                    .filter(|interface| matches(interface, &fallback_types))
                    .cloned()
                    .collect()
            };
            (primary, fallback)
        }
    };
    if primary.is_empty() && fallback.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no available network interface matches the requested network strategy",
        ));
    }
    Ok(PlatformNetworkSelection { primary, fallback })
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    use std::{net::SocketAddr, sync::Arc};

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    use network_interface::{NetworkInterface, NetworkInterfaceConfig as _};
    use serde_json::json;

    use super::{
        PlatformNetworkDefaults, PlatformNetworkInterface, RouteDialerDefaults,
        select_platform_networks,
    };
    use crate::{constant::InterfaceType, option::AbstractDialerOptions};

    fn interface(
        id: &str,
        interface_type: InterfaceType,
        is_default: bool,
        is_own: bool,
    ) -> PlatformNetworkInterface {
        PlatformNetworkInterface {
            id: id.into(),
            name: id.into(),
            index: id.len() as u32,
            interface_type,
            is_default,
            is_own,
        }
    }

    #[test]
    fn route_dialer_defaults_fill_only_unspecified_fields() {
        let route: crate::option::RouteOptions =
            serde_json::from_value(json!({
                "default_interface": "en0",
                "default_mark": "0xca6c",
                "default_domain_resolver": {
                    "server": "dns-default",
                    "strategy": "prefer_ipv6"
                }
            }))
            .unwrap();
        let defaults = RouteDialerDefaults::from_route_options(&route);
        let mut inherited = AbstractDialerOptions::default();
        defaults.apply(&mut inherited);
        assert_eq!(inherited.bind_interface, "en0");
        assert_eq!(inherited.routing_mark.0, 0xca6c);
        assert_eq!(
            inherited.domain_resolver.as_ref().unwrap().server,
            "dns-default"
        );

        let mut explicit: AbstractDialerOptions =
            serde_json::from_value(json!({
                "bind_interface": "en1",
                "routing_mark": "0x1234",
                "domain_resolver": "dns-explicit"
            }))
            .unwrap();
        defaults.apply(&mut explicit);
        assert_eq!(explicit.bind_interface, "en1");
        assert_eq!(explicit.routing_mark.0, 0x1234);
        assert_eq!(
            explicit.domain_resolver.as_ref().unwrap().server,
            "dns-explicit"
        );

        let mut address_bound: AbstractDialerOptions =
            serde_json::from_value(json!({"inet4_bind_address": "127.0.0.1"}))
                .unwrap();
        defaults.apply(&mut address_bound);
        assert!(address_bound.bind_interface.is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn route_auto_detect_monitor_is_runtime_scoped_and_shared() {
        let route: crate::option::RouteOptions =
            serde_json::from_value(json!({"auto_detect_interface": true}))
                .unwrap();
        let defaults = RouteDialerDefaults::from_route_options(&route);
        let cloned = defaults.clone();
        assert!(Arc::ptr_eq(
            defaults.auto_detect_interface.as_ref().unwrap(),
            cloned.auto_detect_interface.as_ref().unwrap(),
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[tokio::test]
    async fn auto_detect_monitor_resolves_the_kernel_loopback_route() {
        let provider = super::AutoDetectInterfaceProvider::default();
        let destination: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let name = provider.interface_for(destination).await.unwrap();
        let interfaces = NetworkInterface::show().unwrap();
        assert!(interfaces.iter().any(|interface| {
            interface.name == name
                && interface
                    .addr
                    .iter()
                    .any(|address| address.ip() == destination.ip())
        }));
    }

    fn interfaces() -> Vec<PlatformNetworkInterface> {
        vec![
            interface("wifi", InterfaceType::Wifi, true, false),
            interface("cellular", InterfaceType::Cellular, false, false),
            interface("tun", InterfaceType::Other, false, true),
        ]
    }

    #[test]
    fn default_selects_default_and_excludes_own_tun() {
        let selected = select_platform_networks(
            &AbstractDialerOptions::default(),
            interfaces(),
        )
        .unwrap();
        assert_eq!(selected.primary[0].id, "wifi");
        assert!(selected.fallback.is_empty());
    }

    #[test]
    fn fallback_uses_remaining_physical_networks() {
        let options: AbstractDialerOptions = serde_json::from_value(json!({
            "network_strategy": "fallback",
            "network_type": "wifi"
        }))
        .unwrap();
        let selected =
            select_platform_networks(&options, interfaces()).unwrap();
        assert_eq!(selected.primary[0].id, "wifi");
        assert_eq!(selected.fallback[0].id, "cellular");
    }

    #[test]
    fn hybrid_filters_and_races_all_matching_interfaces() {
        let options: AbstractDialerOptions = serde_json::from_value(json!({
            "network_strategy": "hybrid",
            "network_type": ["wifi", "cellular"]
        }))
        .unwrap();
        let selected =
            select_platform_networks(&options, interfaces()).unwrap();
        assert_eq!(
            selected
                .primary
                .iter()
                .map(|interface| interface.id.as_str())
                .collect::<Vec<_>>(),
            ["wifi", "cellular"]
        );
        assert!(selected.fallback.is_empty());
    }

    #[test]
    fn route_defaults_require_auto_detection_and_apply_to_dialers() {
        let invalid: crate::option::RouteOptions =
            serde_json::from_value(json!({
                "default_network_strategy": "fallback"
            }))
            .unwrap();
        assert!(PlatformNetworkDefaults::from_route_options(&invalid).is_err());

        let route: crate::option::RouteOptions =
            serde_json::from_value(json!({
                "auto_detect_interface": true,
                "default_network_strategy": "fallback",
                "default_network_type": "wifi",
                "default_fallback_network_type": "cellular",
                "default_fallback_delay": "450ms"
            }))
            .unwrap();
        let defaults =
            PlatformNetworkDefaults::from_route_options(&route).unwrap();
        let mut options = AbstractDialerOptions::default();
        defaults.apply(&mut options);
        assert_eq!(
            options.network_strategy.unwrap().0,
            crate::constant::NetworkStrategy::Fallback
        );
        assert_eq!(options.network_type.as_slice()[0].0, InterfaceType::Wifi);
        assert_eq!(
            options.fallback_network_type.as_slice()[0].0,
            InterfaceType::Cellular
        );
        assert_eq!(
            options.fallback_delay.as_std().unwrap(),
            std::time::Duration::from_millis(450)
        );
    }

    #[test]
    fn default_interface_conflicts_with_default_network_strategy() {
        let route: crate::option::RouteOptions =
            serde_json::from_value(json!({
                "auto_detect_interface": true,
                "default_interface": "en0",
                "default_network_strategy": "hybrid"
            }))
            .unwrap();
        assert!(PlatformNetworkDefaults::from_route_options(&route).is_err());
    }
}
