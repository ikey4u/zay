//! System TUN inbound backed by the existing smoltcp flow router.
//!
//! This first native slice deliberately requires externally managed routes.
//! Route installation is transactional platform state and must not be treated
//! as active until its add/rollback paths have been implemented and tested.

#[cfg(target_os = "macos")]
use std::os::fd::IntoRawFd as _;
#[cfg(any(target_os = "android", target_os = "ios"))]
use std::os::fd::{IntoRawFd as _, OwnedFd};
use std::{io, net::IpAddr, sync::Arc};

#[cfg(target_os = "linux")]
use futures_util::{StreamExt as _, stream};
#[cfg(target_os = "linux")]
use tokio::sync::Mutex;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    task::JoinHandle,
};
#[cfg(target_os = "linux")]
use tokio_stream::wrappers::WatchStream;
use tokio_util::sync::CancellationToken;
use tun::{AbstractDevice as _, Configuration, Layer};

#[cfg(target_os = "linux")]
use super::tun_auto_redirect_linux::{
    LinuxAutoRedirectLease, validate_filter_options,
};
#[cfg(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_os = "android",
    target_os = "ios",
    test
))]
use super::tun_route::{TunRoutePlan, TunRoutePlatform};
#[cfg(target_os = "linux")]
use super::tun_route_linux::{
    DEFAULT_AUTO_REDIRECT_FALLBACK_RULE_PRIORITY, DEFAULT_ROUTE_TABLE,
    DEFAULT_RULE_PRIORITY, LinuxPolicyOptions, LinuxTunLease,
};
#[cfg(target_os = "windows")]
use super::tun_route_windows::{
    WindowsTunInterfaceOptions, WindowsTunLease, WindowsTunPolicy,
};
#[cfg(target_os = "macos")]
use super::{
    tun_route::TunRouteLease,
    tun_route_darwin::{
        DarwinRouteBackend, configure_additional_addresses,
        configure_utun_interface, flush_dns_cache, open_utun,
    },
};
use crate::{
    common::lifecycle::{
        Lifecycle, LifecycleError, LifecycleFuture, StartStage,
    },
    endpoint::{
        tokio_smoltcp::{
            BufferSize, Net, NetConfig,
            channel_device::ChannelDevice,
            smoltcp::{
                iface::Config as SmoltcpInterfaceConfig,
                phy::{DeviceCapabilities, Medium},
                wire::{HardwareAddress, IpAddress, IpCidr},
            },
        },
        userspace_router::UserspaceEndpointRouter,
    },
    option::TunInboundOptions,
    outbound::OutboundManager,
    route::Router,
};

const DEFAULT_TUN_MTU: u32 = 65_535;
const MIN_TUN_MTU: u32 = 576;
#[cfg(target_os = "linux")]
const DEFAULT_AUTO_REDIRECT_INPUT_MARK: u32 = 0x2023;
#[cfg(target_os = "linux")]
const DEFAULT_AUTO_REDIRECT_OUTPUT_MARK: u32 = 0x2024;
#[cfg(target_os = "linux")]
const DEFAULT_AUTO_REDIRECT_RESET_MARK: u32 = 0x2025;
#[cfg(target_os = "linux")]
const DEFAULT_AUTO_REDIRECT_NFQUEUE: u16 = 100;

#[derive(Debug, thiserror::Error)]
pub enum TunInboundError {
    #[error("invalid TUN inbound configuration: {0}")]
    Invalid(String),
    #[error("unsupported TUN inbound configuration: {0}")]
    Unsupported(String),
}

/// Host bridge used by mobile embedding applications to supply the TUN file
/// descriptor created by Android `VpnService` or Apple `NEPacketTunnelProvider`.
/// The returned descriptor is transferred to the singbox runtime and closed
/// when the TUN inbound stops.
#[cfg(any(target_os = "android", target_os = "ios", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunDeviceRequest {
    /// Inbound tag that owns this device.
    pub tag: String,
    /// Original schema-level options for host-specific settings such as
    /// Android application selection.
    pub options: TunInboundOptions,
    /// Effective MTU after applying the upstream mobile default.
    pub mtu: u16,
    /// Addresses to assign to the platform TUN interface.
    pub addresses: Vec<ipnet::IpNet>,
    /// Effective routes after expanding route rule-sets and subtracting all
    /// exclusions. These are ready to pass to the host platform API.
    pub routes: Vec<ipnet::IpNet>,
    /// Effective DNS server addresses, filtered to configured address
    /// families. An empty vector means that platform DNS is disabled.
    pub dns_servers: Vec<IpAddr>,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub trait TunFileDescriptorProvider: Send + Sync {
    fn open_tun(&self, request: &TunDeviceRequest) -> io::Result<OwnedFd>;

    /// Apply host-owned settings such as the platform HTTP proxy after the
    /// descriptor has been attached successfully.
    fn process_platform_options(
        &self,
        _tag: &str,
        options: &crate::option::TunPlatformOptions,
    ) -> io::Result<()> {
        if options.http_proxy.is_some() {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the TUN provider does not implement platform HTTP proxy options",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
struct TunConfig {
    mtu: u16,
    addresses: Vec<ipnet::IpNet>,
    local_addresses: Vec<ipnet::IpNet>,
    dns_hijack_addresses: Vec<IpAddr>,
    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "android",
        target_os = "ios",
        test
    ))]
    dns_server_addresses: Vec<IpAddr>,
    #[cfg(target_os = "linux")]
    linux_policy: LinuxPolicyOptions,
}

impl TunConfig {
    #[cfg(test)]
    fn from_options(
        options: &TunInboundOptions,
    ) -> Result<Self, TunInboundError> {
        Self::from_options_with_external_device(options, false)
    }

    fn from_options_with_external_device(
        options: &TunInboundOptions,
        external_device: bool,
    ) -> Result<Self, TunInboundError> {
        if options.gso {
            return Err(TunInboundError::Invalid(
                "GSO option in tun is deprecated in sing-box 1.11.0 and removed in sing-box 1.12.0"
                    .into(),
            ));
        }
        if !options.inet4_address.as_slice().is_empty()
            || !options.inet6_address.as_slice().is_empty()
            || !options.inet4_route_address.as_slice().is_empty()
            || !options.inet6_route_address.as_slice().is_empty()
            || !options.inet4_route_exclude_address.as_slice().is_empty()
            || !options.inet6_route_exclude_address.as_slice().is_empty()
        {
            return Err(TunInboundError::Invalid(
                "legacy tun address fields are deprecated in sing-box 1.10.0 and removed in sing-box 1.12.0"
                    .into(),
            ));
        }
        if options.endpoint_independent_nat {
            return Err(TunInboundError::Invalid(
                "endpoint_independent_nat was removed; use udp_mapping and udp_filtering"
                    .into(),
            ));
        }
        if options.auto_redirect && !options.auto_route {
            return Err(TunInboundError::Invalid(
                "`auto_route` is required by `auto_redirect`".into(),
            ));
        }
        #[cfg(not(target_os = "linux"))]
        if options.auto_redirect {
            return Err(TunInboundError::Unsupported(
                "auto_redirect is only available on Linux".into(),
            ));
        }
        #[cfg(target_os = "linux")]
        if options.auto_redirect {
            validate_filter_options(
                options.include_interface.as_slice(),
                options.exclude_interface.as_slice(),
                options.include_mac_address.as_slice(),
                options.exclude_mac_address.as_slice(),
            )
            .map_err(|error| TunInboundError::Invalid(error.to_string()))?;
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "windows",
            target_os = "android",
            target_os = "ios"
        )))]
        if options.auto_route {
            return Err(TunInboundError::Unsupported(
                "auto_route platform route installation is not ported on this operating system yet"
                    .into(),
            ));
        }
        #[cfg(not(target_os = "linux"))]
        if !options.netns.is_empty() {
            return Err(TunInboundError::Unsupported(
                "`netns` is only supported on Linux".into(),
            ));
        }
        if options.platform.is_some() && !external_device {
            return Err(TunInboundError::Unsupported(
                "platform-owned TUN options are not available in the desktop runtime"
                    .into(),
            ));
        }
        let dns_mode = if options.dns_mode.is_empty() {
            "hijack"
        } else {
            &options.dns_mode
        };
        if !matches!(dns_mode, "disabled" | "native" | "hijack") {
            return Err(TunInboundError::Invalid(format!(
                "unknown TUN DNS mode: {dns_mode}"
            )));
        }
        if !matches!(options.stack.as_str(), "" | "gvisor" | "system" | "mixed")
        {
            return Err(TunInboundError::Invalid(format!(
                "unknown TUN stack: {}",
                options.stack
            )));
        }
        if options.address.as_slice().is_empty() {
            return Err(TunInboundError::Invalid(
                "at least one TUN address is required".into(),
            ));
        }
        let mtu = if options.mtu == 0 {
            #[cfg(target_os = "android")]
            let default_mtu = if external_device {
                9_000
            } else {
                DEFAULT_TUN_MTU
            };
            #[cfg(target_os = "ios")]
            let default_mtu = if external_device {
                4_064
            } else {
                DEFAULT_TUN_MTU
            };
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            let default_mtu = DEFAULT_TUN_MTU;
            default_mtu
        } else {
            options.mtu
        };
        if !(MIN_TUN_MTU..=u16::MAX.into()).contains(&mtu) {
            return Err(TunInboundError::Invalid(format!(
                "MTU must be between {MIN_TUN_MTU} and {}",
                u16::MAX
            )));
        }
        let addresses = options
            .address
            .as_slice()
            .iter()
            .map(|prefix| prefix.0)
            .collect::<Vec<_>>();
        if matches!(options.stack.as_str(), "system" | "mixed") {
            for ipv6 in [false, true] {
                if let Some(network) = addresses
                    .iter()
                    .find(|network| network.addr().is_ipv6() == ipv6)
                    && next_address(network.addr())
                        .is_none_or(|address| !network.contains(&address))
                {
                    return Err(TunInboundError::Invalid(format!(
                        "need one more {} address in first prefix for {} stack",
                        if ipv6 { "IPv6" } else { "IPv4" },
                        options.stack
                    )));
                }
            }
        }
        let mut local_addresses = addresses.clone();
        local_addresses.extend(
            options
                .loopback_address
                .as_slice()
                .iter()
                .map(|address| ipnet::IpNet::from(address.0)),
        );
        let dns_hijack_addresses = if dns_mode == "hijack"
            && options.dns_address.as_slice().is_empty()
        {
            derived_dns_addresses(&addresses)
        } else {
            Vec::new()
        };
        #[cfg(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "android",
            target_os = "ios",
            test
        ))]
        let dns_server_addresses = if dns_mode == "disabled" {
            Vec::new()
        } else if options.dns_address.as_slice().is_empty() {
            derived_dns_addresses(&addresses)
        } else {
            options
                .dns_address
                .as_slice()
                .iter()
                .map(|address| address.0)
                .filter(|address| {
                    addresses.iter().any(|prefix| {
                        prefix.addr().is_ipv4() == address.is_ipv4()
                    })
                })
                .collect()
        };
        #[cfg(target_os = "linux")]
        let linux_policy = LinuxPolicyOptions::from_options(options)
            .map_err(TunInboundError::Invalid)?;
        Ok(Self {
            mtu: mtu as u16,
            addresses,
            local_addresses,
            dns_hijack_addresses,
            #[cfg(any(
                target_os = "linux",
                target_os = "windows",
                target_os = "android",
                target_os = "ios",
                test
            ))]
            dns_server_addresses,
            #[cfg(target_os = "linux")]
            linux_policy,
        })
    }
}

pub struct TunInbound {
    name: String,
    tag: String,
    options: TunInboundOptions,
    config: TunConfig,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    net: Option<Arc<Net>>,
    flow_router: Option<Arc<UserspaceEndpointRouter>>,
    tasks: Vec<JoinHandle<io::Result<()>>>,
    interface_name: Option<String>,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    tun_provider: Option<Arc<dyn TunFileDescriptorProvider>>,
    #[cfg(target_os = "macos")]
    route_lease: Option<TunRouteLease<DarwinRouteBackend>>,
    #[cfg(target_os = "linux")]
    route_lease: Option<LinuxTunLease>,
    #[cfg(target_os = "windows")]
    route_lease: Option<WindowsTunLease>,
    #[cfg(target_os = "linux")]
    auto_redirect_lease: Option<Arc<Mutex<LinuxAutoRedirectLease>>>,
}

impl TunInbound {
    pub fn new(
        tag: impl Into<String>,
        options: TunInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, TunInboundError> {
        Self::new_inner(
            tag.into(),
            options,
            router,
            outbounds,
            #[cfg(any(target_os = "android", target_os = "ios"))]
            None,
        )
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn new_with_provider(
        tag: impl Into<String>,
        options: TunInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        provider: Arc<dyn TunFileDescriptorProvider>,
    ) -> Result<Self, TunInboundError> {
        Self::new_inner(tag.into(), options, router, outbounds, Some(provider))
    }

    fn new_inner(
        tag: String,
        options: TunInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        #[cfg(any(target_os = "android", target_os = "ios"))]
        tun_provider: Option<Arc<dyn TunFileDescriptorProvider>>,
    ) -> Result<Self, TunInboundError> {
        for tag in options.route_address_set.as_slice() {
            if !router.has_rule_set(tag) {
                return Err(TunInboundError::Invalid(format!(
                    "parse route_address_set: rule-set not found: {tag}"
                )));
            }
        }
        for tag in options.route_exclude_address_set.as_slice() {
            if !router.has_rule_set(tag) {
                return Err(TunInboundError::Invalid(format!(
                    "parse route_exclude_address_set: rule-set not found: {tag}"
                )));
            }
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let external_device = tun_provider.is_some();
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let external_device = false;
        let config = TunConfig::from_options_with_external_device(
            &options,
            external_device,
        )?;
        Ok(Self {
            name: format!("inbound/tun[{tag}]"),
            tag,
            options,
            config,
            router,
            outbounds,
            cancellation: CancellationToken::new(),
            net: None,
            flow_router: None,
            tasks: Vec::new(),
            interface_name: None,
            #[cfg(any(target_os = "android", target_os = "ios"))]
            tun_provider,
            #[cfg(target_os = "macos")]
            route_lease: None,
            #[cfg(target_os = "linux")]
            route_lease: None,
            #[cfg(target_os = "windows")]
            route_lease: None,
            #[cfg(target_os = "linux")]
            auto_redirect_lease: None,
        })
    }

    pub fn interface_name(&self) -> Option<&str> {
        self.interface_name.as_deref()
    }

    async fn open(&mut self) -> io::Result<()> {
        #[cfg(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "windows",
            target_os = "android",
            target_os = "ios"
        ))]
        let route_plan = resolve_rule_set_route_plan(
            &self.router,
            &self.options,
            TunRoutePlatform::current(),
            cfg!(target_os = "ios"),
        )?;
        let primary_ipv4 = self
            .config
            .addresses
            .iter()
            .find(|prefix| prefix.addr().is_ipv4())
            .copied();
        #[cfg(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "windows"
        ))]
        let device_primary =
            primary_ipv4.or_else(|| self.config.addresses.first().copied());
        #[cfg(not(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "windows"
        )))]
        let device_primary = primary_ipv4;
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let raw_fd = {
            let provider = self.tun_provider.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "mobile TUN requires a TunFileDescriptorProvider",
                )
            })?;
            let request = TunDeviceRequest {
                tag: self.tag.clone(),
                options: self.options.clone(),
                mtu: self.config.mtu,
                addresses: self.config.addresses.clone(),
                routes: route_plan.routes().to_vec(),
                dns_servers: self.config.dns_server_addresses.clone(),
            };
            Some(provider.open_tun(&request)?)
        };
        let device = create_tun_device(
            device_primary,
            self.config.mtu,
            self.options.interface_name.clone(),
            self.options.netns.clone(),
            #[cfg(any(target_os = "android", target_os = "ios"))]
            raw_fd,
        )
        .await?;
        let (device, interface_name) = device;
        self.interface_name =
            (!interface_name.is_empty()).then_some(interface_name);
        #[cfg(any(target_os = "android", target_os = "ios"))]
        if let Some(platform_options) = self.options.platform.as_ref() {
            self.tun_provider
                .as_ref()
                .expect("mobile TUN provider checked above")
                .process_platform_options(&self.tag, platform_options)?;
        }
        #[cfg(target_os = "macos")]
        configure_additional_addresses(
            self.interface_name.as_deref().expect("interface name set"),
            &self.config.addresses,
            primary_ipv4,
        )?;

        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = usize::from(self.config.mtu);
        capabilities.medium = Medium::Ip;
        let (channel, ingress, egress, mut output, icmp_errors) =
            ChannelDevice::new(capabilities);
        let addresses: Vec<IpCidr> = self
            .config
            .addresses
            .iter()
            .map(|prefix| prefix.to_string().parse())
            .collect::<Result<_, _>>()
            .map_err(|()| invalid("invalid smoltcp TUN address"))?;
        let gateways = addresses
            .iter()
            .map(IpCidr::address)
            .collect::<Vec<IpAddress>>();
        let mut net_config = NetConfig::new(
            SmoltcpInterfaceConfig::new(HardwareAddress::Ip),
            addresses,
            gateways,
            Some(BufferSize {
                tcp_rx_size: 128 * 1024,
                tcp_tx_size: 128 * 1024,
                udp_rx_size: 128 * 1024,
                udp_tx_size: 128 * 1024,
                udp_rx_meta_size: 256,
                udp_tx_meta_size: 256,
            }),
        );
        net_config.icmp_errors = Some(icmp_errors);
        let net = Arc::new(Net::new(channel, net_config)?);
        let udp_timeout = self
            .options
            .udp_timeout
            .0
            .as_std()
            .filter(|timeout| !timeout.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        let flow_router = UserspaceEndpointRouter::new(
            &net,
            egress,
            &self.tag,
            self.config.local_addresses.clone(),
            false,
            self.config.dns_hijack_addresses.clone(),
            self.router.clone(),
            self.outbounds.clone(),
            udp_timeout,
            self.options.udp_mapping,
            self.options.udp_filtering,
            self.options.udp_nat_max,
            usize::from(self.config.mtu),
        );

        #[cfg(target_os = "macos")]
        if !route_plan.routes().is_empty() {
            let backend = DarwinRouteBackend::new(&self.config.addresses);
            let mut lease = TunRouteLease::new(backend);
            lease.install(&route_plan).await?;
            self.route_lease = Some(lease);
            flush_dns_cache();
        }

        #[cfg(target_os = "linux")]
        {
            let table = linux_route_index(
                self.options.iproute2_table_index,
                "iproute2_table_index",
                DEFAULT_ROUTE_TABLE,
            )?;
            let priority = linux_route_index(
                self.options.iproute2_rule_index,
                "iproute2_rule_index",
                DEFAULT_RULE_PRIORITY,
            )?;
            let input_mark = if self.options.auto_redirect_input_mark.0 == 0 {
                DEFAULT_AUTO_REDIRECT_INPUT_MARK
            } else {
                self.options.auto_redirect_input_mark.0
            };
            let output_mark = if self.options.auto_redirect_output_mark.0 == 0 {
                DEFAULT_AUTO_REDIRECT_OUTPUT_MARK
            } else {
                self.options.auto_redirect_output_mark.0
            };
            let fallback_rule_priority = if self.options.auto_redirect {
                linux_route_index(
                    self.options.auto_redirect_iproute2_fallback_rule_index,
                    "auto_redirect_iproute2_fallback_rule_index",
                    DEFAULT_AUTO_REDIRECT_FALLBACK_RULE_PRIORITY,
                )?
            } else {
                DEFAULT_AUTO_REDIRECT_FALLBACK_RULE_PRIORITY
            };
            self.route_lease = Some(
                LinuxTunLease::install(
                    self.interface_name.as_deref().expect("interface name set"),
                    &self.config.addresses,
                    primary_ipv4,
                    &route_plan,
                    table,
                    priority,
                    self.options.auto_route,
                    &self.config.linux_policy,
                    &self.config.dns_server_addresses,
                    self.options.auto_redirect,
                    input_mark,
                    output_mark,
                    fallback_rule_priority,
                    &self.options.netns,
                )
                .await?,
            );
            if self.options.auto_redirect {
                let redirect_routes = resolve_auto_redirect_route_plan(
                    &self.router,
                    &self.options,
                )?
                .into_routes();
                let reset_mark = if self.options.auto_redirect_reset_mark.0 == 0
                {
                    DEFAULT_AUTO_REDIRECT_RESET_MARK
                } else {
                    self.options.auto_redirect_reset_mark.0
                };
                let nfqueue = if self.options.auto_redirect_nfqueue == 0 {
                    DEFAULT_AUTO_REDIRECT_NFQUEUE
                } else {
                    self.options.auto_redirect_nfqueue
                };
                let redirect = LinuxAutoRedirectLease::install(
                    "sing-box".into(),
                    self.interface_name
                        .as_deref()
                        .expect("interface name set")
                        .to_owned(),
                    input_mark,
                    output_mark,
                    reset_mark,
                    nfqueue,
                    redirect_routes,
                    &self.config.addresses,
                    self.config.linux_policy.include_uids.clone(),
                    self.config.linux_policy.exclude_uids.clone(),
                    self.options.include_interface.as_slice().to_vec(),
                    self.options.exclude_interface.as_slice().to_vec(),
                    self.options.include_mac_address.as_slice().to_vec(),
                    self.options.exclude_mac_address.as_slice().to_vec(),
                    self.options.exclude_mptcp,
                    self.tag.clone(),
                    self.router.clone(),
                    self.outbounds.clone(),
                    &self.options.netns,
                )
                .await;
                match redirect {
                    Ok(lease) => {
                        self.auto_redirect_lease =
                            Some(Arc::new(Mutex::new(lease)));
                    }
                    Err(error) => {
                        if let Some(route_lease) = self.route_lease.take() {
                            let _ = route_lease.close().await;
                        }
                        return Err(error);
                    }
                }
            }

            if let Some(auto_redirect) = self.auto_redirect_lease.as_ref()
                && (!self.options.route_address_set.as_slice().is_empty()
                    || !self
                        .options
                        .route_exclude_address_set
                        .as_slice()
                        .is_empty())
            {
                let subscriptions = self
                    .options
                    .route_address_set
                    .as_slice()
                    .iter()
                    .chain(self.options.route_exclude_address_set.as_slice())
                    .filter_map(|tag| self.router.rule_set(tag))
                    .map(|rule_set| {
                        WatchStream::from_changes(rule_set.subscribe())
                    })
                    .collect::<Vec<_>>();
                let mut updates = stream::select_all(subscriptions);
                let router = self.router.clone();
                let options = self.options.clone();
                let auto_redirect = auto_redirect.clone();
                let cancellation = self.cancellation.clone();
                self.tasks.push(tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = cancellation.cancelled() => break,
                            update = updates.next() => {
                                if update.is_none() {
                                    break;
                                }
                                let plan = resolve_auto_redirect_route_plan(
                                    &router,
                                    &options,
                                )?;
                                if let Err(error) = auto_redirect
                                    .lock()
                                    .await
                                    .update_routes(plan.into_routes())
                                    .await
                                {
                                    tracing::warn!(
                                        %error,
                                        "update auto-redirect route rule-sets"
                                    );
                                }
                            }
                        }
                    }
                    Ok(())
                }));
            }
        }

        #[cfg(target_os = "windows")]
        {
            // sing-tun's Windows Start method is a no-op without auto_route,
            // even when explicit route_address entries produced a plan.
            let empty_route_plan = TunRoutePlan::from_routes(Vec::new());
            let windows_route_plan = windows_tun_route_plan(
                self.options.auto_route,
                &route_plan,
                &empty_route_plan,
            );
            let dns_servers = if self.options.auto_route {
                self.config.dns_server_addresses.as_slice()
            } else {
                &[]
            };
            self.route_lease = Some(
                WindowsTunLease::install(
                    self.interface_name.as_deref().expect("interface name set"),
                    &self.config.addresses,
                    primary_ipv4,
                    windows_route_plan,
                    WindowsTunPolicy {
                        dns_servers,
                        strict_route: self.options.auto_route
                            && self.options.strict_route,
                        block_dns: matches!(
                            self.options.dns_mode.as_str(),
                            "" | "hijack"
                        ),
                        flush_dns_cache: self.options.auto_route,
                        interface_options: Some(WindowsTunInterfaceOptions {
                            mtu: self.config.mtu,
                            auto_route: self.options.auto_route,
                        }),
                    },
                )
                .await?,
            );
        }

        let (mut read_device, mut write_device) = tokio::io::split(device);
        let read_cancellation = self.cancellation.clone();
        let read_router = flow_router.clone();
        let mtu = usize::from(self.config.mtu);
        self.tasks.push(tokio::spawn(async move {
            let mut packet = vec![0_u8; mtu];
            loop {
                let size = tokio::select! {
                    _ = read_cancellation.cancelled() => break,
                    result = read_device.read(&mut packet) => result?,
                };
                if size == 0 {
                    continue;
                }
                let data = &packet[..size];
                if !read_router.prepare_packet(data).await? {
                    continue;
                }
                if ingress.send(Ok(data.to_vec())).await.is_err() {
                    break;
                }
            }
            Ok(())
        }));

        let write_cancellation = self.cancellation.clone();
        self.tasks.push(tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = write_cancellation.cancelled() => break,
                    packet = output.recv() => match packet {
                        Some(packet) => packet,
                        None => break,
                    },
                };
                write_device.write_all(&packet).await?;
            }
            Ok(())
        }));

        self.net = Some(net);
        self.flow_router = Some(flow_router);
        Ok(())
    }
}

pub(crate) async fn create_tun_device(
    primary: Option<ipnet::IpNet>,
    mtu: u16,
    interface_name: String,
    network_namespace: String,
    #[cfg(any(target_os = "android", target_os = "ios"))] raw_fd: Option<
        OwnedFd,
    >,
) -> io::Result<(tun::AsyncDevice, String)> {
    #[cfg(target_os = "macos")]
    let (raw_utun, known_interface_name) =
        if primary.is_some_and(|primary| primary.addr().is_ipv6()) {
            let (fd, name) = open_utun(&interface_name)?;
            (Some(fd), Some(name))
        } else {
            (None, None)
        };
    let create = move || {
        let mut device_config = Configuration::default();
        device_config.layer(Layer::L3).mtu(mtu).up();
        if let Some(primary) = primary.filter(|primary| {
            primary.addr().is_ipv4()
                || cfg!(any(target_os = "android", target_os = "ios"))
        }) {
            device_config
                .address(primary.addr())
                .netmask(primary.netmask());
            if let Some(destination) = next_address(primary.addr())
                && primary.contains(&destination)
            {
                device_config.destination(destination);
            }
        }
        if !interface_name.is_empty() {
            device_config.tun_name(&interface_name);
        }
        #[cfg(target_os = "ios")]
        device_config.platform_config(|platform| {
            // NEPacketTunnelFlow's public readPackets/writePackets API carries
            // bare IP packets. The iOS host bridges it through a SOCK_DGRAM
            // socketpair, so the private utun 4-byte packet-info prefix is not
            // present and must not be synthesized by rust-tun.
            platform.packet_information(false);
        });
        #[cfg(any(target_os = "android", target_os = "ios"))]
        if let Some(raw_fd) = raw_fd {
            device_config
                .raw_fd(raw_fd.into_raw_fd())
                .close_fd_on_drop(true);
        }
        #[cfg(target_os = "macos")]
        if let Some(raw_fd) = raw_utun {
            device_config
                .raw_fd(raw_fd.into_raw_fd())
                .close_fd_on_drop(true);
        }
        #[cfg(target_os = "windows")]
        device_config.platform_config(|platform| {
            if primary.is_some_and(|primary| primary.addr().is_ipv6()) {
                platform.skip_config(true);
            }
        });
        let device =
            tun::create_as_async(&device_config).map_err(io::Error::from)?;
        #[cfg(target_os = "macos")]
        let interface_name = if let Some(interface_name) = known_interface_name
        {
            configure_utun_interface(&interface_name, mtu)?;
            interface_name
        } else {
            device.tun_name().map_err(io::Error::from)?
        };
        #[cfg(not(target_os = "macos"))]
        let interface_name = device.tun_name().map_err(io::Error::from)?;
        Ok((device, interface_name))
    };
    #[cfg(target_os = "linux")]
    {
        crate::common::socket::with_network_namespace(
            &network_namespace,
            create,
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = network_namespace;
        create()
    }
}

impl Lifecycle for TunInbound {
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
            let mut errors = Vec::new();
            for task in self.tasks.drain(..) {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => errors.push(error.to_string()),
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => errors.push(error.to_string()),
                }
            }
            self.flow_router.take();
            self.net.take();
            #[cfg(target_os = "macos")]
            if let Some(mut route_lease) = self.route_lease.take()
                && let Err(error) = route_lease.close().await
            {
                errors.push(error.to_string());
            }
            #[cfg(target_os = "macos")]
            flush_dns_cache();
            #[cfg(target_os = "linux")]
            if let Some(auto_redirect) = self.auto_redirect_lease.take()
                && let Err(error) = auto_redirect.lock().await.close().await
            {
                errors.push(error.to_string());
            }
            #[cfg(target_os = "linux")]
            if let Some(route_lease) = self.route_lease.take()
                && let Err(error) = route_lease.close().await
            {
                errors.push(error.to_string());
            }
            #[cfg(target_os = "windows")]
            if let Some(route_lease) = self.route_lease.take()
                && let Err(error) = route_lease.close().await
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

#[cfg(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_os = "android",
    target_os = "ios",
    test
))]
fn resolve_rule_set_route_plan(
    router: &Router,
    options: &TunInboundOptions,
    platform: TunRoutePlatform,
    under_network_extension: bool,
) -> io::Result<TunRoutePlan> {
    if platform == TunRoutePlatform::Linux && options.auto_redirect {
        return Ok(TunRoutePlan::from_options_with_resolved_rule_sets(
            options,
            platform,
            false,
            &[],
            &[],
        ));
    }
    let includes = router
        .rule_set_destination_prefixes(options.route_address_set.as_slice())
        .map_err(|error| invalid(error.to_string()))?;
    let excludes = router
        .rule_set_destination_prefixes(
            options.route_exclude_address_set.as_slice(),
        )
        .map_err(|error| invalid(error.to_string()))?;
    Ok(TunRoutePlan::from_options_with_resolved_rule_sets(
        options,
        platform,
        under_network_extension,
        &includes,
        &excludes,
    ))
}

#[cfg(target_os = "linux")]
fn resolve_auto_redirect_route_plan(
    router: &Router,
    options: &TunInboundOptions,
) -> io::Result<TunRoutePlan> {
    let includes = router
        .rule_set_destination_prefixes(options.route_address_set.as_slice())
        .map_err(|error| invalid(error.to_string()))?;
    let excludes = router
        .rule_set_destination_prefixes(
            options.route_exclude_address_set.as_slice(),
        )
        .map_err(|error| invalid(error.to_string()))?;
    Ok(
        TunRoutePlan::from_auto_redirect_options_with_resolved_rule_sets(
            options, &includes, &excludes,
        ),
    )
}

fn next_address(address: IpAddr) -> Option<IpAddr> {
    match address {
        IpAddr::V4(address) => u32::from(address)
            .checked_add(1)
            .map(std::net::Ipv4Addr::from)
            .map(IpAddr::V4),
        IpAddr::V6(address) => u128::from(address)
            .checked_add(1)
            .map(std::net::Ipv6Addr::from)
            .map(IpAddr::V6),
    }
}

fn derived_dns_addresses(addresses: &[ipnet::IpNet]) -> Vec<IpAddr> {
    [false, true]
        .into_iter()
        .filter_map(|ipv6| {
            let network = addresses
                .iter()
                .find(|network| network.addr().is_ipv6() == ipv6)?;
            let address = next_address(network.addr())?;
            network.contains(&address).then_some(address)
        })
        .collect()
}

#[cfg(any(target_os = "windows", test))]
fn windows_tun_route_plan<'a>(
    auto_route: bool,
    planned: &'a TunRoutePlan,
    empty: &'a TunRoutePlan,
) -> &'a TunRoutePlan {
    if auto_route { planned } else { empty }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(target_os = "linux")]
fn linux_route_index(value: i32, name: &str, default: u32) -> io::Result<u32> {
    if value == 0 {
        return Ok(default);
    }
    u32::try_from(value)
        .map_err(|_| invalid(format!("{name} must be positive")))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{TunConfig, TunRoutePlatform};
    use crate::{option::TunInboundOptions, route::Router};

    fn supported_options() -> TunInboundOptions {
        serde_json::from_value(json!({
            "interface_name": "tun-test",
            "address": ["10.14.14.9/30", "fdfe:dcba:9876::1/126"],
            "dns_mode": "disabled",
            "stack": "gvisor",
            "udp_timeout": "30s",
            "udp_mapping": "address_dependent",
            "udp_filtering": "address_and_port_dependent",
            "udp_nat_max": 512
        }))
        .unwrap()
    }

    #[test]
    fn normalizes_supported_userspace_tun_configuration() {
        let config = TunConfig::from_options(&supported_options()).unwrap();
        assert_eq!(config.mtu, u16::MAX);
        assert_eq!(config.addresses.len(), 2);
        assert!(config.dns_hijack_addresses.is_empty());
    }

    #[test]
    fn external_tun_accepts_ipv6_only_and_platform_options() {
        let options: TunInboundOptions = serde_json::from_value(json!({
            "address": "fdfe:dcba:9876::1/126",
            "dns_mode": "disabled",
            "stack": "gvisor",
            "platform": {
                "http_proxy": {
                    "enabled": true,
                    "server": "127.0.0.1",
                    "server_port": 8080
                }
            }
        }))
        .unwrap();
        let config =
            TunConfig::from_options_with_external_device(&options, true)
                .unwrap();
        assert_eq!(config.addresses.len(), 1);
        assert!(config.addresses[0].addr().is_ipv6());
    }

    #[test]
    fn desktop_tun_accepts_ipv6_only_address() {
        let options: TunInboundOptions = serde_json::from_value(json!({
            "address": "fdfe:dcba:9876::1/126",
            "dns_mode": "disabled",
            "stack": "gvisor"
        }))
        .unwrap();
        let config = TunConfig::from_options(&options).unwrap();
        assert_eq!(config.addresses.len(), 1);
        assert!(config.addresses[0].addr().is_ipv6());
    }

    #[test]
    fn windows_skips_all_routes_when_auto_route_is_disabled() {
        let planned = super::TunRoutePlan::from_options(
            &serde_json::from_value(json!({
                "address": "10.14.14.9/30",
                "route_address": "192.0.2.0/24"
            }))
            .unwrap(),
            TunRoutePlatform::Windows,
            false,
        )
        .unwrap();
        assert_eq!(planned.routes().len(), 1);
        let empty = super::TunRoutePlan::from_options(
            &serde_json::from_value(json!({
                "address": "10.14.14.9/30"
            }))
            .unwrap(),
            TunRoutePlatform::Windows,
            false,
        )
        .unwrap();
        assert!(
            super::windows_tun_route_plan(false, &planned, &empty)
                .routes()
                .is_empty()
        );
        assert_eq!(
            super::windows_tun_route_plan(true, &planned, &empty).routes(),
            planned.routes()
        );
    }

    #[test]
    fn empty_dns_mode_defaults_to_hijack_with_next_addresses() {
        let mut options = supported_options();
        options.dns_mode.clear();
        let config = TunConfig::from_options(&options).unwrap();
        assert_eq!(
            config.dns_hijack_addresses,
            [
                "10.14.14.10".parse::<std::net::IpAddr>().unwrap(),
                "fdfe:dcba:9876::2".parse::<std::net::IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn native_dns_does_not_enable_internal_hijack() {
        let mut options = supported_options();
        options.dns_mode = "native".into();
        let config = TunConfig::from_options(&options).unwrap();
        assert!(config.dns_hijack_addresses.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_dns_uses_explicit_servers_without_enabling_hijack() {
        let mut options = supported_options();
        options.dns_mode = "native".into();
        options.dns_address =
            serde_json::from_value(json!(["10.14.14.10", "fdfe:dcba:9876::2"]))
                .unwrap();
        let config = TunConfig::from_options(&options).unwrap();
        assert!(config.dns_hijack_addresses.is_empty());
        assert_eq!(
            config.dns_server_addresses,
            [
                "10.14.14.10".parse::<std::net::IpAddr>().unwrap(),
                "fdfe:dcba:9876::2".parse::<std::net::IpAddr>().unwrap()
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn auto_redirect_accepts_uid_interface_and_mac_filters() {
        let mut options = supported_options();
        options.auto_route = true;
        options.auto_redirect = true;
        options.include_uid_range =
            serde_json::from_value(json!(["1000:2000"])).unwrap();
        options.exclude_uid = serde_json::from_value(json!([1500])).unwrap();
        options.include_interface =
            serde_json::from_value(json!(["eth0", "wlan0"])).unwrap();
        options.include_mac_address = serde_json::from_value(json!([
            "00:11:22:33:44:55",
            "0011.2233.4466"
        ]))
        .unwrap();
        options.exclude_mptcp = true;
        let config = TunConfig::from_options(&options).unwrap();
        assert_eq!(config.linux_policy.excluded_uids.len(), 3);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn auto_redirect_rejects_invalid_mac_before_opening_tun() {
        let mut options = supported_options();
        options.auto_route = true;
        options.auto_redirect = true;
        options.include_mac_address =
            serde_json::from_value(json!(["not-a-mac"])).unwrap();
        assert!(TunConfig::from_options(&options).is_err());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn resolves_rule_set_prefixes_for_runtime_route_refresh() {
        let router = Router::from_json_with_rule_sets(
            &[],
            "direct",
            &[
                json!({
                    "type":"inline",
                    "tag":"included",
                    "rules":[{"ip_cidr":"10.20.0.0/16"}]
                }),
                json!({
                    "type":"inline",
                    "tag":"excluded",
                    "rules":[{"ip_cidr":"10.20.30.0/24"}]
                }),
            ],
            std::path::Path::new("."),
        )
        .unwrap();
        let mut options = supported_options();
        options.route_address_set =
            serde_json::from_value(json!(["included"])).unwrap();
        options.route_exclude_address_set =
            serde_json::from_value(json!(["excluded"])).unwrap();
        let plan = super::resolve_rule_set_route_plan(
            &router,
            &options,
            TunRoutePlatform::Linux,
            false,
        )
        .unwrap();
        assert!(plan.contains("10.20.1.1".parse().unwrap()));
        assert!(!plan.contains("10.20.30.1".parse().unwrap()));
    }

    #[test]
    fn mobile_request_uses_effective_dns_and_resolved_routes() {
        let router = Router::from_json_with_rule_sets(
            &[],
            "direct",
            &[
                json!({
                    "type":"inline",
                    "tag":"included",
                    "rules":[{"ip_cidr":"10.20.0.0/16"}]
                }),
                json!({
                    "type":"inline",
                    "tag":"excluded",
                    "rules":[{"ip_cidr":"10.20.30.0/24"}]
                }),
            ],
            std::path::Path::new("."),
        )
        .unwrap();
        let mut options = supported_options();
        options.dns_mode = "native".into();
        options.route_address_set =
            serde_json::from_value(json!(["included"])).unwrap();
        options.route_exclude_address_set =
            serde_json::from_value(json!(["excluded"])).unwrap();
        let config =
            TunConfig::from_options_with_external_device(&options, true)
                .unwrap();
        let route_plan = super::resolve_rule_set_route_plan(
            &router,
            &options,
            TunRoutePlatform::Other,
            false,
        )
        .unwrap();
        let request = super::TunDeviceRequest {
            tag: "mobile".into(),
            options,
            mtu: config.mtu,
            addresses: config.addresses,
            routes: route_plan.into_routes(),
            dns_servers: config.dns_server_addresses,
        };

        assert_eq!(request.tag, "mobile");
        assert_eq!(request.mtu, u16::MAX);
        assert_eq!(
            request.dns_servers,
            [
                "10.14.14.10".parse::<std::net::IpAddr>().unwrap(),
                "fdfe:dcba:9876::2".parse::<std::net::IpAddr>().unwrap()
            ]
        );
        assert!(request.routes.iter().any(|route| {
            route.contains(&"10.20.1.1".parse::<std::net::IpAddr>().unwrap())
        }));
        assert!(!request.routes.iter().any(|route| {
            route.contains(&"10.20.30.1".parse::<std::net::IpAddr>().unwrap())
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn accepts_existing_namespace_with_auto_redirect() {
        let mut options = supported_options();
        options.netns = "/run/netns/proxy".into();
        assert!(TunConfig::from_options(&options).is_ok());

        options.auto_route = true;
        options.auto_redirect = true;
        assert!(TunConfig::from_options(&options).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn missing_namespace_fails_before_tun_device_creation() {
        let result = super::create_tun_device(
            Some("10.14.14.1/30".parse().unwrap()),
            1500,
            String::new(),
            "/definitely/missing/singbox-netns".into(),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("missing namespace unexpectedly opened a TUN"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("open network namespace"));
    }

    #[test]
    fn system_stack_uses_the_unified_userspace_data_plane() {
        let mut options = supported_options();
        options.stack = "system".into();
        options.dns_mode.clear();
        options.loopback_address =
            serde_json::from_value(json!(["10.7.0.1", "fd00::7"])).unwrap();
        let config = TunConfig::from_options(&options).unwrap();
        assert_eq!(config.local_addresses.len(), 4);
        assert_eq!(config.dns_hijack_addresses.len(), 2);
    }

    #[test]
    fn system_stack_requires_a_peer_address_in_each_first_prefix() {
        let mut options = supported_options();
        options.stack = "system".into();
        options.address =
            serde_json::from_value(json!(["10.14.14.9/32"])).unwrap();
        let error = TunConfig::from_options(&options).unwrap_err();
        assert!(error.to_string().contains("need one more IPv4 address"));
    }

    #[test]
    fn requires_auto_route_for_auto_redirect() {
        let mut options = supported_options();
        options.auto_redirect = true;
        let error = TunConfig::from_options(&options).unwrap_err();
        assert!(error.to_string().contains("auto_route` is required"));
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    )))]
    #[test]
    fn does_not_silently_accept_unimplemented_route_mutation() {
        let mut options = supported_options();
        options.auto_route = true;
        let error = TunConfig::from_options(&options).unwrap_err();
        assert!(error.to_string().contains("not ported yet"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn accepts_transactional_macos_auto_route_plan() {
        let mut options = supported_options();
        options.auto_route = true;
        let config = TunConfig::from_options(&options).unwrap();
        assert_eq!(config.addresses.len(), 2);
    }

    #[test]
    fn reports_removed_legacy_address_fields() {
        let options: TunInboundOptions = serde_json::from_value(json!({
            "inet4_address": "10.0.0.1/30",
            "dns_mode": "disabled",
            "stack": "gvisor"
        }))
        .unwrap();
        let error = TunConfig::from_options(&options).unwrap_err();
        assert!(error.to_string().contains("removed in sing-box 1.12.0"));
    }
}
