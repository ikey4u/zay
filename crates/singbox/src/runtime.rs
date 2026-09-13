//! Configuration-driven embeddable runtime.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::Path,
    sync::Arc,
};

use serde_json::Value;

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
use crate::common::platform_network::{
    PlatformNetworkDefaults, PlatformNetworkProvider,
};
#[cfg(any(target_os = "android", target_os = "ios"))]
use crate::inbound::tun::TunFileDescriptorProvider;

use crate::{
    adapter::{NeighborResolver, ProcessResolver},
    certificate::{CertificateProviderError, CertificateProviderManager},
    clash_api::{ClashApiHandle, ClashApiServer},
    common::{
        certificate_store::{CertificateStore, CertificateStoreError},
        network::SocksAddr,
        ntp::{NtpClient, NtpClock, NtpService, SystemClockWriter},
    },
    deprecated::{self, DeprecatedNote},
    endpoint::{
        openconnect::{OpenConnectEndpointHandle, OpenConnectEndpointService},
        openvpn::{OpenVpnClientEndpointHandle, OpenVpnClientEndpointService},
        openvpn_server::{
            OpenVpnServerEndpointHandle, OpenVpnServerEndpointService,
        },
        tailscale::{TailscaleEndpointHandle, TailscaleEndpointService},
        wireguard::{
            WireGuardEndpointConfig, WireGuardEndpointHandle,
            WireGuardEndpointService,
        },
    },
    inbound::{
        TcpInboundInjector,
        anytls::{AnyTlsInbound, AnyTlsInboundError, AnyTlsTcpInjector},
        cloudflared::{
            CloudflaredInbound, CloudflaredInboundError,
            CloudflaredInboundHandle,
        },
        direct::DirectInbound,
        http::{HttpInbound, HttpTcpInjector},
        hysteria::{HysteriaInbound, HysteriaInboundError},
        hysteria2::{Hysteria2Inbound, Hysteria2InboundError},
        naive::{NaiveInbound, NaiveInboundError},
        redirect::RedirectInbound,
        shadowsocks::{
            ShadowsocksInbound, ShadowsocksInboundError, ShadowsocksTcpInjector,
        },
        shadowtls::{ShadowTlsInbound, ShadowTlsInboundError},
        snell::{SnellInbound, SnellInboundError, SnellTcpInjector},
        socks::{SocksInbound, SocksTcpInjector},
        tproxy::{TProxyInbound, TProxyInboundError},
        trojan::{TrojanInbound, TrojanInboundError, TrojanTcpInjector},
        tuic::{TuicInbound, TuicInboundError},
        tun::{TunInbound, TunInboundError},
        vless::{VlessInbound, VlessInboundError, VlessTcpInjector},
        vmess::{VmessInbound, VmessInboundError, VmessTcpInjector},
    },
    log::{Factory as LogFactory, LogError, Logger},
    option::{
        AnyTlsInboundOptions, CloudflaredInboundOptions, ConfigError,
        DirectInboundOptions, DirectOutboundOptions, HttpMixedInboundOptions,
        Hysteria2InboundOptions, HysteriaInboundOptions,
        HysteriaRealmServiceOptions, NaiveInboundOptions,
        OpenConnectEndpointOptions, OpenVpnClientEndpointOptions,
        OpenVpnServerEndpointOptions, Options, RedirectInboundOptions,
        RouteOptions, RouteRuleOptions, RuleSetOptions,
        ShadowTlsInboundOptions, ShadowsocksInboundOptions,
        SnellInboundOptions, SocksInboundOptions, SsmApiServiceOptions,
        TProxyInboundOptions, TaggedOptions, TailscaleEndpointOptions,
        TrojanInboundOptions, TuicInboundOptions, TunInboundOptions,
        VMessInboundOptions, VlessInboundOptions, WireGuardEndpointOptions,
    },
    outbound::{OutboundError, OutboundManager},
    protocol::direct::DirectOutbound,
    route::{RouteError, Router},
    service::{
        Box as ServiceBox, BoxError,
        hysteria_realm::{HysteriaRealmHandle, HysteriaRealmService},
        ssm_api::{SsmApiHandle, SsmApiServer},
    },
};

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Outbound(#[from] OutboundError),
    #[error(transparent)]
    Route(#[from] RouteError),
    #[error(transparent)]
    Lifecycle(#[from] BoxError),
    #[error(transparent)]
    Log(#[from] LogError),
    #[error(transparent)]
    CertificateProvider(#[from] CertificateProviderError),
    #[error(transparent)]
    TrojanInbound(#[from] TrojanInboundError),
    #[error(transparent)]
    VlessInbound(#[from] VlessInboundError),
    #[error(transparent)]
    ShadowsocksInbound(#[from] ShadowsocksInboundError),
    #[error(transparent)]
    SnellInbound(#[from] SnellInboundError),
    #[error(transparent)]
    VmessInbound(#[from] VmessInboundError),
    #[error(transparent)]
    AnyTlsInbound(#[from] AnyTlsInboundError),
    #[error(transparent)]
    Hysteria2Inbound(#[from] Hysteria2InboundError),
    #[error(transparent)]
    HysteriaInbound(#[from] HysteriaInboundError),
    #[error(transparent)]
    TuicInbound(#[from] TuicInboundError),
    #[error(transparent)]
    NaiveInbound(#[from] NaiveInboundError),
    #[error(transparent)]
    TProxyInbound(#[from] TProxyInboundError),
    #[error(transparent)]
    TunInbound(#[from] TunInboundError),
    #[error(transparent)]
    ShadowTlsInbound(#[from] ShadowTlsInboundError),
    #[error(transparent)]
    CloudflaredInbound(#[from] CloudflaredInboundError),
    #[error("unsupported inbound type {kind:?} for tag {tag:?}")]
    UnsupportedInbound { kind: String, tag: String },
    #[error("{0}")]
    Removed(String),
    #[error("invalid route configuration: {0}")]
    InvalidRoute(String),
    #[error("configure Clash API: {0}")]
    ClashApi(std::io::Error),
    #[error("configure SSM API: {0}")]
    SsmApi(std::io::Error),
    #[error("configure Hysteria realm: {0}")]
    HysteriaRealm(std::io::Error),
    #[error("configure WireGuard endpoint: {0}")]
    WireGuardEndpoint(std::io::Error),
    #[error("configure OpenVPN client endpoint: {0}")]
    OpenVpnClientEndpoint(std::io::Error),
    #[error("configure OpenVPN server endpoint: {0}")]
    OpenVpnServerEndpoint(String),
    #[error("configure OpenConnect endpoint: {0}")]
    OpenConnectEndpoint(std::io::Error),
    #[error("configure Tailscale endpoint: {0}")]
    TailscaleEndpoint(std::io::Error),
    #[error("configure NTP service: {0}")]
    Ntp(String),
    #[error(transparent)]
    CertificateStore(#[from] CertificateStoreError),
    #[error("unsupported endpoint type {kind:?} for tag {tag:?}")]
    UnsupportedEndpoint { kind: String, tag: String },
    #[error("unsupported service type {kind:?} for tag {tag:?}")]
    UnsupportedService { kind: String, tag: String },
}

pub struct Runtime {
    service: ServiceBox,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    log: Arc<LogFactory>,
    clash_api: Option<ClashApiHandle>,
    ssm_api: HashMap<String, SsmApiHandle>,
    hysteria_realm: HashMap<String, HysteriaRealmHandle>,
    wireguard_endpoints: HashMap<String, WireGuardEndpointHandle>,
    openvpn_client_endpoints: HashMap<String, OpenVpnClientEndpointHandle>,
    openvpn_server_endpoints: HashMap<String, OpenVpnServerEndpointHandle>,
    openconnect_endpoints: HashMap<String, OpenConnectEndpointHandle>,
    tailscale_endpoints: HashMap<String, TailscaleEndpointHandle>,
    cloudflared_inbounds: HashMap<String, CloudflaredInboundHandle>,
    certificate_store: CertificateStore,
    ntp_clock: Option<NtpClock>,
    deprecated_warnings: Vec<DeprecatedNote>,
}

#[allow(clippy::too_many_arguments)]
fn build_tcp_inbound_injector(
    inbound: &TaggedOptions,
    tag: &str,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    ntp_clock: Option<NtpClock>,
    certificate_store: CertificateStore,
    certificate_providers: &mut CertificateProviderManager,
) -> Result<Arc<dyn TcpInboundInjector>, RuntimeError> {
    let injector: Arc<dyn TcpInboundInjector> = match inbound.kind.as_str() {
        "shadowsocks" => Arc::new(ShadowsocksTcpInjector::new_with_clock(
            tag.to_owned(),
            inbound.decode::<ShadowsocksInboundOptions>()?,
            router,
            outbounds,
            ntp_clock,
        )?),
        "vmess" => {
            let mut options = inbound.decode::<VMessInboundOptions>()?;
            certificate_providers.configure_tls(
                options.tls.as_mut(),
                &format!("inbound/vmess[{tag}]/injector"),
            )?;
            Arc::new(VmessTcpInjector::new_with_clock(
                tag.to_owned(),
                options,
                router,
                outbounds,
                ntp_clock,
            )?)
        }
        "trojan" => {
            let mut options = inbound.decode::<TrojanInboundOptions>()?;
            certificate_providers.configure_tls(
                options.tls.as_mut(),
                &format!("inbound/trojan[{tag}]/injector"),
            )?;
            Arc::new(TrojanTcpInjector::new(
                tag.to_owned(),
                options,
                router,
                outbounds,
            )?)
        }
        "socks" => Arc::new(SocksTcpInjector::new(
            tag.to_owned(),
            inbound.decode::<SocksInboundOptions>()?,
            router,
            outbounds,
        )),
        "http" | "mixed" => {
            let mut options = inbound.decode::<HttpMixedInboundOptions>()?;
            certificate_providers.configure_tls(
                options.tls.as_mut(),
                &format!("inbound/{}[{tag}]/injector", inbound.kind),
            )?;
            Arc::new(
                HttpTcpInjector::new_with_runtime_context(
                    tag.to_owned(),
                    options,
                    router,
                    outbounds,
                    inbound.kind == "mixed",
                    ntp_clock,
                    Some(certificate_store),
                )
                .map_err(|error| {
                    RuntimeError::InvalidRoute(format!(
                        "configure inbound detour {tag:?}: {error}"
                    ))
                })?,
            )
        }
        "vless" => {
            let mut options = inbound.decode::<VlessInboundOptions>()?;
            certificate_providers.configure_tls(
                options.tls.as_mut(),
                &format!("inbound/vless[{tag}]/injector"),
            )?;
            Arc::new(VlessTcpInjector::new(
                tag.to_owned(),
                options,
                router,
                outbounds,
            )?)
        }
        "anytls" => {
            let mut options = inbound.decode::<AnyTlsInboundOptions>()?;
            certificate_providers.configure_tls(
                options.tls.as_mut(),
                &format!("inbound/anytls[{tag}]/injector"),
            )?;
            Arc::new(AnyTlsTcpInjector::new(
                tag.to_owned(),
                options,
                router,
                outbounds,
            )?)
        }
        "snell" => Arc::new(SnellTcpInjector::new(
            tag.to_owned(),
            inbound.decode::<SnellInboundOptions>()?,
            router,
            outbounds,
        )?),
        _ => {
            return Err(RuntimeError::InvalidRoute(format!(
                "inbound detour is not TCP injectable: {tag}"
            )));
        }
    };
    Ok(injector)
}

/// Host-owned capabilities used by an embedded runtime.
#[derive(Default)]
pub struct RuntimeHost {
    pub system_clock_writer: Option<Arc<dyn SystemClockWriter>>,
    pub neighbor_resolver: Option<Arc<dyn NeighborResolver>>,
    pub process_resolver: Option<Arc<dyn ProcessResolver>>,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub tun_provider: Option<Arc<dyn TunFileDescriptorProvider>>,
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    pub platform_network_provider: Option<Arc<dyn PlatformNetworkProvider>>,
}

/// Cloneable control handle for an embedded [`Runtime`].
///
/// The owning application decides how OS signals, service controls, or UI
/// actions map to cancellation; the library itself does not install signal
/// handlers.
#[derive(Clone)]
pub struct RuntimeHandle {
    cancellation: tokio_util::sync::CancellationToken,
}

impl RuntimeHandle {
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }
}

impl Runtime {
    pub fn from_options(options: Options) -> Result<Self, RuntimeError> {
        Self::from_options_with_system_clock_writer(options, None)
    }

    pub fn from_options_with_system_clock_writer(
        options: Options,
        system_clock_writer: Option<Arc<dyn SystemClockWriter>>,
    ) -> Result<Self, RuntimeError> {
        Self::from_options_in_with_system_clock_writer(
            options,
            Path::new("."),
            system_clock_writer,
        )
    }

    pub fn from_options_in(
        options: Options,
        base_path: &Path,
    ) -> Result<Self, RuntimeError> {
        Self::from_options_in_with_system_clock_writer(options, base_path, None)
    }

    pub fn from_options_in_with_system_clock_writer(
        options: Options,
        base_path: &Path,
        system_clock_writer: Option<Arc<dyn SystemClockWriter>>,
    ) -> Result<Self, RuntimeError> {
        Self::from_options_in_with_host(
            options,
            base_path,
            RuntimeHost {
                system_clock_writer,
                ..RuntimeHost::default()
            },
        )
    }

    /// Build a mobile runtime using a host-owned Android `VpnService` or Apple
    /// `NEPacketTunnelProvider` TUN descriptor.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn from_options_with_tun_provider(
        options: Options,
        tun_provider: Arc<dyn TunFileDescriptorProvider>,
    ) -> Result<Self, RuntimeError> {
        Self::from_options_in_with_tun_provider(
            options,
            Path::new("."),
            tun_provider,
        )
    }

    /// Path-aware variant of [`Self::from_options_with_tun_provider`].
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn from_options_in_with_tun_provider(
        options: Options,
        base_path: &Path,
        tun_provider: Arc<dyn TunFileDescriptorProvider>,
    ) -> Result<Self, RuntimeError> {
        Self::from_options_in_with_host(
            options,
            base_path,
            RuntimeHost {
                tun_provider: Some(tun_provider),
                ..RuntimeHost::default()
            },
        )
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn from_options_in_with_system_clock_writer_and_tun_provider(
        options: Options,
        base_path: &Path,
        system_clock_writer: Option<Arc<dyn SystemClockWriter>>,
        tun_provider: Arc<dyn TunFileDescriptorProvider>,
    ) -> Result<Self, RuntimeError> {
        Self::from_options_in_with_host(
            options,
            base_path,
            RuntimeHost {
                system_clock_writer,
                tun_provider: Some(tun_provider),
                ..RuntimeHost::default()
            },
        )
    }

    /// Build a mobile runtime with both a host-owned TUN descriptor and
    /// runtime-scoped physical-network selection for dialer network strategy.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn from_options_with_mobile_platform(
        options: Options,
        tun_provider: Arc<dyn TunFileDescriptorProvider>,
        platform_network_provider: Arc<dyn PlatformNetworkProvider>,
    ) -> Result<Self, RuntimeError> {
        Self::from_options_in_with_mobile_platform(
            options,
            Path::new("."),
            None,
            tun_provider,
            platform_network_provider,
        )
    }

    /// Path-aware mobile constructor that also accepts the optional privileged
    /// system-clock callback.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn from_options_in_with_mobile_platform(
        options: Options,
        base_path: &Path,
        system_clock_writer: Option<Arc<dyn SystemClockWriter>>,
        tun_provider: Arc<dyn TunFileDescriptorProvider>,
        platform_network_provider: Arc<dyn PlatformNetworkProvider>,
    ) -> Result<Self, RuntimeError> {
        Self::from_options_in_with_host(
            options,
            base_path,
            RuntimeHost {
                system_clock_writer,
                tun_provider: Some(tun_provider),
                platform_network_provider: Some(platform_network_provider),
                ..RuntimeHost::default()
            },
        )
    }

    /// Build a runtime with host-owned, runtime-scoped platform capabilities.
    pub fn from_options_with_host(
        options: Options,
        host: RuntimeHost,
    ) -> Result<Self, RuntimeError> {
        Self::from_options_in_with_host(options, Path::new("."), host)
    }

    /// Path-aware variant of [`Self::from_options_with_host`].
    pub fn from_options_in_with_host(
        mut options: Options,
        base_path: &Path,
        host: RuntimeHost,
    ) -> Result<Self, RuntimeError> {
        let RuntimeHost {
            system_clock_writer,
            mut neighbor_resolver,
            process_resolver,
            #[cfg(any(target_os = "android", target_os = "ios"))]
            tun_provider,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_provider,
        } = host;
        options.validate()?;
        options.resolve_network_namespace_references()?;
        let deprecated_warnings = deprecated::collect(&options);
        let log_options = options.log.clone().unwrap_or_default();
        let observable = options
            .experimental
            .as_ref()
            .is_some_and(|experimental| experimental.clash_api.is_some());
        let log = LogFactory::new(&log_options, observable)?;
        let route_options = route_options(options.route.as_ref())?;
        let rules = route_options.rules;
        let rule_sets = route_options.rule_sets;
        let final_outbound = route_options.final_outbound;
        let default_http_client = route_options.default_http_client;
        let dns_rules = options
            .dns
            .as_ref()
            .map(|dns| {
                dns.rules
                    .iter()
                    .map(crate::option::DnsRuleOptions::to_value)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()
            .map_err(|error| RuntimeError::InvalidRoute(error.to_string()))?
            .unwrap_or_default();
        let needs_neighbor_resolver = route_options.find_neighbor
            || contains_neighbor_rule(&rules)
            || contains_neighbor_rule(&dns_rules)
            || options
                .dns
                .as_ref()
                .is_some_and(|dns| has_local_neighbor_dns_server(&dns.servers));
        if neighbor_resolver.is_none() && needs_neighbor_resolver {
            neighbor_resolver =
                crate::common::neighbor::native_neighbor_resolver(
                    route_options.dhcp_lease_files,
                    base_path,
                );
        }
        let needs_process_resolver = route_options.find_process
            || contains_process_rule(&rules)
            || !rule_sets.is_empty()
            || contains_process_rule(&dns_rules);
        let process_resolver = process_resolver.or_else(|| {
            needs_process_resolver
                .then(crate::common::process::native_process_resolver)
                .flatten()
        });
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        let platform_network_defaults = route_options.platform_network_defaults;
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        let platform_network_provider = platform_network_provider
            .filter(|_| platform_network_defaults.auto_detect_interface);
        #[cfg(target_os = "macos")]
        let platform_network_defaults = if platform_network_provider.is_none() {
            // A non-graphical macOS host follows the regular sing-box desktop
            // path: native default-interface detection remains active and the
            // graphical-client-only strategy defaults are ignored.
            PlatformNetworkDefaults::default()
        } else {
            platform_network_defaults
        };
        #[cfg(any(target_os = "android", target_os = "ios"))]
        if platform_network_defaults.requires_provider()
            && platform_network_provider.is_none()
        {
            return Err(RuntimeError::InvalidRoute(
                "route.auto_detect_interface requires a PlatformNetworkProvider"
                    .into(),
            ));
        }
        let persistent_cache =
            OutboundManager::open_persistent_cache(&options, base_path)?;
        let certificate_store = CertificateStore::new(
            &options.certificate.clone().unwrap_or_default(),
            base_path,
        )?;
        let enabled_ntp =
            options.ntp.as_ref().filter(|options| options.enabled);
        if enabled_ntp.is_some_and(|ntp| ntp.write_to_system)
            && system_clock_writer.is_none()
        {
            return Err(RuntimeError::Ntp(
                "write_to_system requires an explicit privileged host callback implementing SystemClockWriter"
                    .into(),
            ));
        }
        let ntp_clock = enabled_ntp.map(|_| NtpClock::default());
        let rule_set_values = rule_sets
            .iter()
            .map(RuleSetOptions::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RuntimeError::InvalidRoute(error.to_string()))?;
        let mut router = Router::from_json_with_rule_sets_and_cache(
            &rules,
            final_outbound,
            &rule_set_values,
            base_path,
            persistent_cache.clone(),
        )?;
        let mut outbounds = OutboundManager::from_options_with_runtime_context(
            &options,
            final_outbound,
            base_path,
            persistent_cache,
            ntp_clock.clone(),
            Some(certificate_store.clone()),
            neighbor_resolver.clone(),
            Some(&router),
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_provider,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_defaults,
        )?;
        router.configure_direct_actions(&mut outbounds)?;
        let outbounds = Arc::new(outbounds);
        let ntp_service = match enabled_ntp {
            Some(ntp) => {
                let dialer = outbounds
                    .endpoint_dialer("ntp", &ntp.dialer)
                    .map_err(|error| RuntimeError::Ntp(error.to_string()))?;
                let client = NtpClient::new(
                    dialer,
                    SocksAddr::new(ntp.server().to_owned(), ntp.server_port()),
                );
                let service = NtpService::new_with_clock(
                    client,
                    ntp.interval_std(),
                    ntp_clock
                        .clone()
                        .expect("enabled NTP creates a shared clock"),
                );
                Some(if ntp.write_to_system {
                    service.with_system_clock_writer(
                        system_clock_writer
                            .clone()
                            .expect("write_to_system callback checked above"),
                    )
                } else {
                    service
                })
            }
            None => None,
        };
        router.configure_preferred_outbounds(&outbounds);
        router.configure_neighbor_resolver(neighbor_resolver);
        router.configure_process_resolver(process_resolver);
        router.configure_rule_set_http_clients(
            &outbounds,
            &options.http_clients,
            default_http_client,
            ntp_clock.clone(),
            Some(certificate_store.clone()),
        )?;
        if let Some(clash_api) = options
            .experimental
            .as_ref()
            .and_then(|experimental| experimental.clash_api.as_ref())
        {
            let default_mode = if clash_api.default_mode.is_empty() {
                "Rule".to_owned()
            } else {
                clash_api.default_mode.clone()
            };
            let mut modes = Vec::new();
            collect_clash_modes(&rules, &mut modes);
            collect_clash_modes(&dns_rules, &mut modes);
            modes = order_clash_modes(modes);
            if !modes
                .iter()
                .any(|mode| mode.eq_ignore_ascii_case(&default_mode))
            {
                modes.insert(0, default_mode.clone());
            }
            let current = outbounds
                .load_mode()
                .and_then(|saved| {
                    modes
                        .iter()
                        .find(|mode| mode.eq_ignore_ascii_case(&saved))
                        .cloned()
                })
                .unwrap_or(default_mode);
            outbounds.dns().set_clash_mode(Some(current.clone()));
            router.configure_clash_mode(current, modes);
        }
        let router = Arc::new(router);
        outbounds
            .dns()
            .configure_rule_set_router(&router)
            .map_err(OutboundError::Dns)?;
        let mut certificate_providers =
            CertificateProviderManager::from_runtime_options(
                &options,
                base_path,
                outbounds.clone(),
                default_http_client,
                ntp_clock.clone(),
                Some(certificate_store.clone()),
            )?;
        let mut builder = ServiceBox::builder(options.clone());
        if let Some(bridge_service) = outbounds.bridge_service() {
            builder = builder.component(bridge_service);
        }
        let mut wireguard_endpoints = HashMap::new();
        let mut openvpn_client_endpoints = HashMap::new();
        let mut openvpn_server_endpoints = HashMap::new();
        let mut openconnect_endpoints = HashMap::new();
        let mut tailscale_endpoints = HashMap::new();
        for (index, endpoint) in options.endpoints.iter().enumerate() {
            let tag = if endpoint.tag.is_empty() {
                index.to_string()
            } else {
                endpoint.tag.clone()
            };
            match endpoint.kind.as_str() {
                "wireguard" => {
                    let endpoint_options: WireGuardEndpointOptions =
                        endpoint.decode()?;
                    let system_interface_name: Option<String> =
                        if endpoint_options.system {
                            #[cfg(any(
                                target_os = "macos",
                                target_os = "linux",
                                target_os = "windows"
                            ))]
                            {
                                Some(if endpoint_options.name.is_empty() {
                                    crate::inbound::tun_system_interface::calculate_interface_name("wg")
                                    .map_err(RuntimeError::WireGuardEndpoint)?
                                } else {
                                    endpoint_options.name.clone()
                                })
                            }
                            #[cfg(not(any(
                                target_os = "macos",
                                target_os = "linux",
                                target_os = "windows"
                            )))]
                            {
                                return Err(RuntimeError::WireGuardEndpoint(
                                    std::io::Error::new(
                                        std::io::ErrorKind::Unsupported,
                                        "system WireGuard interface requires a desktop TUN platform",
                                    ),
                                ));
                            }
                        } else {
                            None
                        };
                    let dialer = outbounds.resolver_on_detour_dialer(
                        &tag,
                        &endpoint_options.dialer,
                        false,
                    )?;
                    let config = WireGuardEndpointConfig::from_options(
                        &endpoint_options,
                    )
                    .map_err(RuntimeError::WireGuardEndpoint)?;
                    let (resolver, strategy) = outbounds
                        .endpoint_destination_resolver(
                            &tag,
                            &endpoint_options.dialer,
                        )?;
                    let (service, handle) =
                        WireGuardEndpointService::new_with_resolver(
                            &tag,
                            config.clone(),
                            dialer,
                            resolver.clone(),
                            strategy,
                            router.clone(),
                            outbounds.clone(),
                        );
                    let endpoint_dialer: Arc<dyn crate::adapter::Dialer> =
                        if let Some(interface_name) =
                            system_interface_name.as_ref()
                        {
                            let mut options = DirectOutboundOptions::default();
                            options.dialer.abstract_options.bind_interface =
                                interface_name.clone();
                            Arc::new(
                                DirectOutbound::with_underlay_resolver(
                                    options, resolver, strategy,
                                )
                                .with_preference_source(handle.dialer()),
                            )
                        } else {
                            handle.dialer()
                        };
                    outbounds
                        .register_endpoint(
                            &tag,
                            &endpoint.kind,
                            endpoint_dialer,
                        )
                        .map_err(RuntimeError::WireGuardEndpoint)?;
                    builder = builder.component(service);
                    #[cfg(any(
                        target_os = "macos",
                        target_os = "linux",
                        target_os = "windows"
                    ))]
                    if let Some(interface_name) = system_interface_name {
                        let routes = wireguard_system_routes(&config);
                        let packet_port = handle.dialer().packet_port().expect(
                            "WireGuard endpoint exposes an IP packet port",
                        );
                        let system_interface =
                            crate::inbound::tun_system_interface::EndpointSystemInterface::new(
                                &tag,
                                interface_name,
                                config.mtu as usize,
                                config.addresses.clone(),
                                routes,
                                packet_port,
                            )
                            .map_err(RuntimeError::WireGuardEndpoint)?;
                        builder = builder.component(system_interface);
                    }
                    wireguard_endpoints.insert(tag, handle);
                }
                "openvpn-client" => {
                    let endpoint_options: OpenVpnClientEndpointOptions =
                        endpoint.decode()?;
                    let system_interface_name: Option<String> =
                        if endpoint_options.endpoint.system {
                            #[cfg(any(
                                target_os = "macos",
                                target_os = "linux",
                                target_os = "windows"
                            ))]
                            {
                                Some(
                                    if endpoint_options.endpoint.name.is_empty()
                                    {
                                        crate::inbound::tun_system_interface::calculate_interface_name(
                                        "ovpn",
                                    )
                                    .map_err(RuntimeError::OpenVpnClientEndpoint)?
                                    } else {
                                        endpoint_options.endpoint.name.clone()
                                    },
                                )
                            }
                            #[cfg(not(any(
                                target_os = "macos",
                                target_os = "linux",
                                target_os = "windows"
                            )))]
                            {
                                return Err(
                                    RuntimeError::OpenVpnClientEndpoint(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Unsupported,
                                            "system OpenVPN interface requires a desktop TUN platform",
                                        ),
                                    ),
                                );
                            }
                        } else {
                            None
                        };
                    let dialer = outbounds.resolver_on_detour_dialer(
                        &tag,
                        &endpoint_options.dialer,
                        endpoint_options.remote_is_domain(),
                    )?;
                    let (resolver, strategy) = outbounds
                        .endpoint_destination_resolver(
                            &tag,
                            &endpoint_options.dialer,
                        )?;
                    let (service, handle) =
                        OpenVpnClientEndpointService::new_with_resolver(
                            &tag,
                            endpoint_options.clone(),
                            base_path,
                            dialer,
                            resolver.clone(),
                            strategy,
                            router.clone(),
                            outbounds.clone(),
                        );
                    let endpoint_dialer: Arc<dyn crate::adapter::Dialer> =
                        if let Some(interface_name) =
                            system_interface_name.as_ref()
                        {
                            let mut options = DirectOutboundOptions::default();
                            options.dialer.abstract_options.bind_interface =
                                interface_name.clone();
                            Arc::new(
                                DirectOutbound::with_underlay_resolver(
                                    options, resolver, strategy,
                                )
                                .with_preference_source(handle.dialer()),
                            )
                        } else {
                            handle.dialer()
                        };
                    outbounds
                        .register_endpoint(
                            &tag,
                            &endpoint.kind,
                            endpoint_dialer.clone(),
                        )
                        .map_err(RuntimeError::OpenVpnClientEndpoint)?;
                    outbounds
                        .dns()
                        .bind_openvpn_endpoint(
                            &tag,
                            endpoint_dialer,
                            Arc::new(handle.clone()),
                        )
                        .map_err(OutboundError::Dns)?;
                    builder = builder.component(service);
                    #[cfg(any(
                        target_os = "macos",
                        target_os = "linux",
                        target_os = "windows"
                    ))]
                    if let Some(interface_name) = system_interface_name {
                        let packet_port = handle.dialer().packet_port().expect(
                            "OpenVPN client endpoint exposes an IP packet port",
                        );
                        let system_handle = handle.clone();
                        let system_tag = tag.clone();
                        let configured_mtu = endpoint_options.endpoint.mtu;
                        builder = builder.component(
                            crate::inbound::tun_system_interface::DeferredEndpointSystemInterface::new(
                                &tag,
                                move || {
                                    let configuration = system_handle
                                        .tunnel_configuration()
                                        .ok_or_else(|| std::io::Error::new(
                                            std::io::ErrorKind::NotConnected,
                                            "OpenVPN tunnel configuration is not available",
                                        ))?;
                                    let addresses = configuration
                                        .local_ipv4
                                        .iter()
                                        .chain(configuration.local_ipv6.iter())
                                        .map(|prefix| ipnet::IpNet::new(
                                            prefix.address,
                                            prefix.prefix_len,
                                        ))
                                        .collect::<Result<Vec<_>, _>>()
                                        .map_err(|error| std::io::Error::new(
                                            std::io::ErrorKind::InvalidInput,
                                            error,
                                        ))?;
                                    let mtu = if configuration.tun_mtu == 0 {
                                        if configured_mtu == 0 { 1500 } else { configured_mtu }
                                    } else {
                                        configuration.tun_mtu
                                    };
                                    crate::inbound::tun_system_interface::EndpointSystemInterface::new(
                                        &system_tag,
                                        interface_name.clone(),
                                        mtu as usize,
                                        addresses,
                                        Vec::new(),
                                        packet_port.clone(),
                                    )
                                },
                            ),
                        );
                    }
                    openvpn_client_endpoints.insert(tag, handle);
                }
                "openvpn-server" => {
                    let endpoint_options: OpenVpnServerEndpointOptions =
                        endpoint.decode()?;
                    let system_interface_name: Option<String> =
                        if endpoint_options.endpoint.system {
                            #[cfg(any(
                                target_os = "macos",
                                target_os = "linux",
                                target_os = "windows"
                            ))]
                            {
                                Some(
                                    if endpoint_options.endpoint.name.is_empty()
                                    {
                                        crate::inbound::tun_system_interface::calculate_interface_name(
                                        "ovpn",
                                    )
                                    .map_err(|error| {
                                        RuntimeError::OpenVpnServerEndpoint(
                                            error.to_string(),
                                        )
                                    })?
                                    } else {
                                        endpoint_options.endpoint.name.clone()
                                    },
                                )
                            }
                            #[cfg(not(any(
                                target_os = "macos",
                                target_os = "linux",
                                target_os = "windows"
                            )))]
                            {
                                return Err(
                                    RuntimeError::OpenVpnServerEndpoint(
                                        "system OpenVPN interface requires a desktop TUN platform"
                                            .into(),
                                    ),
                                );
                            }
                        } else {
                            None
                        };
                    let (resolver, strategy) = outbounds
                        .endpoint_destination_resolver(
                            &tag,
                            &Default::default(),
                        )?;
                    let (service, handle) =
                        OpenVpnServerEndpointService::new_with_resolver(
                            &tag,
                            endpoint_options.clone(),
                            base_path,
                            resolver.clone(),
                            strategy,
                            router.clone(),
                            outbounds.clone(),
                        )
                        .map_err(|error| {
                            RuntimeError::OpenVpnServerEndpoint(
                                error.to_string(),
                            )
                        })?;
                    let endpoint_dialer: Arc<dyn crate::adapter::Dialer> =
                        if let Some(interface_name) =
                            system_interface_name.as_ref()
                        {
                            let mut options = DirectOutboundOptions::default();
                            options.dialer.abstract_options.bind_interface =
                                interface_name.clone();
                            Arc::new(
                                DirectOutbound::with_underlay_resolver(
                                    options, resolver, strategy,
                                )
                                .with_preference_source(handle.dialer()),
                            )
                        } else {
                            handle.dialer()
                        };
                    outbounds
                        .register_endpoint(
                            &tag,
                            &endpoint.kind,
                            endpoint_dialer,
                        )
                        .map_err(|error| {
                            RuntimeError::OpenVpnServerEndpoint(
                                error.to_string(),
                            )
                        })?;
                    builder = builder.component(service);
                    #[cfg(any(
                        target_os = "macos",
                        target_os = "linux",
                        target_os = "windows"
                    ))]
                    if let Some(interface_name) = system_interface_name {
                        let addresses = endpoint_options
                            .address
                            .as_slice()
                            .iter()
                            .map(|prefix| prefix.0)
                            .collect();
                        let mtu = if endpoint_options.endpoint.mtu == 0 {
                            1500
                        } else {
                            endpoint_options.endpoint.mtu
                        };
                        let packet_port = handle.dialer().packet_port().expect(
                            "OpenVPN server endpoint exposes an IP packet port",
                        );
                        let system_interface =
                            crate::inbound::tun_system_interface::EndpointSystemInterface::new(
                                &tag,
                                interface_name,
                                mtu as usize,
                                addresses,
                                Vec::new(),
                                packet_port,
                            )
                            .map_err(|error| {
                                RuntimeError::OpenVpnServerEndpoint(
                                    error.to_string(),
                                )
                            })?;
                        builder = builder.component(system_interface);
                    }
                    openvpn_server_endpoints.insert(tag, handle);
                }
                "openconnect" => {
                    let mut endpoint_options: OpenConnectEndpointOptions =
                        endpoint.decode()?;
                    let system_interface_name: Option<String> =
                        if endpoint_options.system {
                            #[cfg(any(
                                target_os = "macos",
                                target_os = "linux",
                                target_os = "windows"
                            ))]
                            {
                                Some(if endpoint_options.name.is_empty() {
                                    crate::inbound::tun_system_interface::calculate_interface_name(
                                        "oc",
                                    )
                                    .map_err(RuntimeError::OpenConnectEndpoint)?
                                } else {
                                    endpoint_options.name.clone()
                                })
                            }
                            #[cfg(not(any(
                                target_os = "macos",
                                target_os = "linux",
                                target_os = "windows"
                            )))]
                            {
                                return Err(RuntimeError::OpenConnectEndpoint(
                                    std::io::Error::new(
                                        std::io::ErrorKind::Unsupported,
                                        "system OpenConnect interface requires a desktop TUN platform",
                                    ),
                                ));
                            }
                        } else {
                            None
                        };
                    endpoint_options.set_runtime_context(
                        ntp_clock.clone(),
                        Some(certificate_store.clone()),
                    );
                    let dialer = outbounds.resolver_on_detour_dialer(
                        &tag,
                        &endpoint_options.dialer,
                        endpoint_options.server_is_domain(),
                    )?;
                    let (resolver, strategy) = outbounds
                        .endpoint_destination_resolver(
                            &tag,
                            &endpoint_options.dialer,
                        )?;
                    let (service, handle) =
                        OpenConnectEndpointService::new_with_resolver(
                            &tag,
                            endpoint_options,
                            dialer,
                            resolver.clone(),
                            strategy,
                            router.clone(),
                            outbounds.clone(),
                        )
                        .map_err(RuntimeError::OpenConnectEndpoint)?;
                    let endpoint_dialer: Arc<dyn crate::adapter::Dialer> =
                        if let Some(interface_name) =
                            system_interface_name.as_ref()
                        {
                            let mut options = DirectOutboundOptions::default();
                            options.dialer.abstract_options.bind_interface =
                                interface_name.clone();
                            Arc::new(
                                DirectOutbound::with_underlay_resolver(
                                    options, resolver, strategy,
                                )
                                .with_preference_source(handle.dialer()),
                            )
                        } else {
                            handle.dialer()
                        };
                    outbounds
                        .register_endpoint(
                            &tag,
                            &endpoint.kind,
                            endpoint_dialer.clone(),
                        )
                        .map_err(RuntimeError::OpenConnectEndpoint)?;
                    outbounds
                        .dns()
                        .bind_openconnect_endpoint(
                            &tag,
                            endpoint_dialer,
                            handle.dns_configuration_provider(),
                        )
                        .map_err(OutboundError::Dns)?;
                    builder = builder.component(service);
                    #[cfg(any(
                        target_os = "macos",
                        target_os = "linux",
                        target_os = "windows"
                    ))]
                    if let Some(interface_name) = system_interface_name {
                        let packet_port = handle.dialer().packet_port().expect(
                            "OpenConnect endpoint exposes an IP packet port",
                        );
                        let system_handle = handle.clone();
                        let system_tag = tag.clone();
                        builder = builder.component(
                            crate::inbound::tun_system_interface::DeferredEndpointSystemInterface::new(
                                &tag,
                                move || {
                                    let configuration = system_handle
                                        .tunnel_configuration()
                                        .ok_or_else(|| std::io::Error::new(
                                            std::io::ErrorKind::NotConnected,
                                            "OpenConnect tunnel configuration is not available",
                                        ))?;
                                    crate::inbound::tun_system_interface::EndpointSystemInterface::new(
                                        &system_tag,
                                        interface_name.clone(),
                                        configuration.mtu as usize,
                                        configuration.addresses,
                                        Vec::new(),
                                        packet_port.clone(),
                                    )
                                },
                            ),
                        );
                    }
                    openconnect_endpoints.insert(tag, handle);
                }
                "tailscale" => {
                    let mut endpoint_options: TailscaleEndpointOptions =
                        endpoint.decode()?;
                    let system_interface_name: Option<String> =
                        if endpoint_options.system_interface {
                            #[cfg(any(
                                target_os = "macos",
                                target_os = "linux",
                                target_os = "windows"
                            ))]
                            {
                                Some(
                                    if endpoint_options
                                        .system_interface_name
                                        .is_empty()
                                    {
                                        crate::inbound::tun_system_interface::calculate_interface_name(
                                        "tailscale",
                                    )
                                    .map_err(RuntimeError::TailscaleEndpoint)?
                                    } else {
                                        endpoint_options
                                            .system_interface_name
                                            .clone()
                                    },
                                )
                            }
                            #[cfg(not(any(
                                target_os = "macos",
                                target_os = "linux",
                                target_os = "windows"
                            )))]
                            {
                                return Err(RuntimeError::TailscaleEndpoint(
                                    std::io::Error::new(
                                        std::io::ErrorKind::Unsupported,
                                        "system Tailscale interface requires a desktop TUN platform",
                                    ),
                                ));
                            }
                        } else {
                            None
                        };
                    endpoint_options.set_runtime_context(
                        ntp_clock.clone(),
                        Some(certificate_store.clone()),
                    );
                    let dialer = outbounds.resolver_on_detour_dialer(
                        &tag,
                        &endpoint_options.dialer,
                        true,
                    )?;
                    let system_resolver = system_interface_name
                        .as_ref()
                        .map(|_| {
                            outbounds.endpoint_destination_resolver(
                                &tag,
                                &endpoint_options.dialer,
                            )
                        })
                        .transpose()?;
                    let (service, handle) = TailscaleEndpointService::new(
                        &tag,
                        endpoint_options.clone(),
                        base_path,
                        dialer,
                        router.clone(),
                        outbounds.clone(),
                    )
                    .map_err(RuntimeError::TailscaleEndpoint)?;
                    let endpoint_dialer: Arc<dyn crate::adapter::Dialer> =
                        if let Some(interface_name) =
                            system_interface_name.as_ref()
                        {
                            let (resolver, strategy) = system_resolver
                                .expect("system resolver requested above");
                            let mut options = DirectOutboundOptions::default();
                            options.dialer.abstract_options.bind_interface =
                                interface_name.clone();
                            Arc::new(
                                DirectOutbound::with_underlay_resolver(
                                    options, resolver, strategy,
                                )
                                .with_preference_source(handle.dialer()),
                            )
                        } else {
                            handle.dialer()
                        };
                    outbounds
                        .register_endpoint(
                            &tag,
                            &endpoint.kind,
                            endpoint_dialer.clone(),
                        )
                        .map_err(RuntimeError::TailscaleEndpoint)?;
                    outbounds
                        .dns()
                        .bind_tailscale_endpoint(
                            &tag,
                            endpoint_dialer,
                            handle.dns_netmap_provider(),
                        )
                        .map_err(OutboundError::Dns)?;
                    builder = builder.component(service);
                    #[cfg(any(
                        target_os = "macos",
                        target_os = "linux",
                        target_os = "windows"
                    ))]
                    if let Some(interface_name) = system_interface_name {
                        let system_handle = handle.clone();
                        let system_tag = tag.clone();
                        let configured_mtu =
                            endpoint_options.system_interface_mtu;
                        let route_policy = crate::protocol::tailscale_derp_map::TailscaleRoutePolicy {
                                accept_routes: endpoint_options.accept_routes,
                                exit_node: endpoint_options.exit_node.clone(),
                            };
                        builder = builder.component(
                            crate::inbound::tun_system_interface::DeferredEndpointSystemInterface::new_background(
                                &tag,
                                move || {
                                    let netmap = system_handle.netmap().ok_or_else(|| {
                                        std::io::Error::new(
                                            std::io::ErrorKind::NotConnected,
                                            "Tailscale network map is not available",
                                        )
                                    })?;
                                    let node = netmap.node.as_ref().ok_or_else(|| {
                                        std::io::Error::new(
                                            std::io::ErrorKind::NotConnected,
                                            "Tailscale self node is not available",
                                        )
                                    })?;
                                    let addresses = node
                                        .addresses
                                        .iter()
                                        .map(|prefix| prefix.parse::<ipnet::IpNet>())
                                        .collect::<Result<Vec<_>, _>>()
                                        .map_err(|error| std::io::Error::new(
                                            std::io::ErrorKind::InvalidInput,
                                            error,
                                        ))?;
                                    let routed = route_policy.apply(&netmap);
                                    let routes = routed
                                        .peers
                                        .values()
                                        .flat_map(|peer| &peer.allowed_ips)
                                        .filter_map(|prefix| prefix.parse().ok())
                                        .collect();
                                    let packet_port = system_handle
                                        .dialer()
                                        .packet_port()
                                        .ok_or_else(|| std::io::Error::new(
                                            std::io::ErrorKind::NotConnected,
                                            "Tailscale packet port is not available",
                                        ))?;
                                    crate::inbound::tun_system_interface::EndpointSystemInterface::new(
                                        &system_tag,
                                        interface_name.clone(),
                                        if configured_mtu == 0 {
                                            1280
                                        } else {
                                            configured_mtu
                                        } as usize,
                                        addresses,
                                        routes,
                                        packet_port,
                                    )
                                },
                            ),
                        );
                    }
                    tailscale_endpoints.insert(tag, handle);
                }
                _ => {
                    return Err(RuntimeError::UnsupportedEndpoint {
                        kind: endpoint.kind.clone(),
                        tag,
                    });
                }
            }
        }
        router.validate_preferred_outbounds(&outbounds)?;
        outbounds
            .dns()
            .validate_openconnect_endpoints()
            .map_err(OutboundError::Dns)?;
        outbounds
            .dns()
            .validate_openvpn_endpoints()
            .map_err(OutboundError::Dns)?;
        outbounds
            .dns()
            .validate_tailscale_endpoints()
            .map_err(OutboundError::Dns)?;
        outbounds
            .dns()
            .validate_outbound_detours(&HashSet::new())
            .map_err(OutboundError::Dns)?;
        let mut managed_shadowsocks = HashMap::new();
        let mut cloudflared_inbounds = HashMap::new();
        for (index, inbound) in options.inbounds.iter().enumerate() {
            let tag = if inbound.tag.is_empty() {
                index.to_string()
            } else {
                inbound.tag.clone()
            };
            let configured_detour = inbound
                .fields
                .get("detour")
                .and_then(Value::as_str)
                .filter(|detour| !detour.is_empty());
            if let Some(detour_tag) = configured_detour {
                let detour = options.inbounds.iter().enumerate().find_map(
                    |(detour_index, candidate)| {
                        let candidate_tag = if candidate.tag.is_empty() {
                            detour_index.to_string()
                        } else {
                            candidate.tag.clone()
                        };
                        (candidate_tag == detour_tag).then_some(candidate)
                    },
                );
                let injector = match detour {
                    Some(detour)
                        if matches!(
                            detour.kind.as_str(),
                            "http"
                                | "mixed"
                                | "socks"
                                | "shadowsocks"
                                | "vmess"
                                | "vless"
                                | "trojan"
                                | "snell"
                                | "anytls"
                        ) =>
                    {
                        Some(build_tcp_inbound_injector(
                            detour,
                            detour_tag,
                            router.clone(),
                            outbounds.clone(),
                            ntp_clock.clone(),
                            certificate_store.clone(),
                            &mut certificate_providers,
                        )?)
                    }
                    _ => None,
                };
                outbounds.register_inbound_tcp_detour(
                    tag.clone(),
                    detour_tag.to_owned(),
                    detour.is_some(),
                    injector,
                );
            }
            match inbound.kind.as_str() {
                "shadowsocksr" => {
                    return Err(RuntimeError::Removed(
                        "ShadowsocksR is deprecated and removed in sing-box 1.6.0"
                            .into(),
                    ));
                }
                "socks" => {
                    let inbound_options: SocksInboundOptions =
                        inbound.decode()?;
                    builder = builder.component(SocksInbound::new(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                    ));
                }
                "direct" => {
                    let inbound_options: DirectInboundOptions =
                        inbound.decode()?;
                    builder = builder.component(DirectInbound::new(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                    ));
                }
                "http" => {
                    let mut inbound_options: HttpMixedInboundOptions =
                        inbound.decode()?;
                    certificate_providers.configure_tls(
                        inbound_options.tls.as_mut(),
                        &format!("inbound/http[{tag}]"),
                    )?;
                    builder = builder.component(
                        HttpInbound::new_with_runtime_context(
                            tag,
                            inbound_options,
                            router.clone(),
                            outbounds.clone(),
                            ntp_clock.clone(),
                            Some(certificate_store.clone()),
                        ),
                    );
                }
                "mixed" => {
                    let mut inbound_options: HttpMixedInboundOptions =
                        inbound.decode()?;
                    certificate_providers.configure_tls(
                        inbound_options.tls.as_mut(),
                        &format!("inbound/mixed[{tag}]"),
                    )?;
                    builder = builder.component(
                        HttpInbound::new_mixed_with_runtime_context(
                            tag,
                            inbound_options,
                            router.clone(),
                            outbounds.clone(),
                            ntp_clock.clone(),
                            Some(certificate_store.clone()),
                        ),
                    );
                }
                "trojan" => {
                    let mut inbound_options: TrojanInboundOptions =
                        inbound.decode()?;
                    certificate_providers.configure_tls(
                        inbound_options.tls.as_mut(),
                        &format!("inbound/trojan[{tag}]"),
                    )?;
                    builder = builder.component(TrojanInbound::new(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                    )?);
                }
                "vless" => {
                    let mut inbound_options: VlessInboundOptions =
                        inbound.decode()?;
                    certificate_providers.configure_tls(
                        inbound_options.tls.as_mut(),
                        &format!("inbound/vless[{tag}]"),
                    )?;
                    builder = builder.component(VlessInbound::new(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                    )?);
                }
                "shadowsocks" => {
                    let inbound_options: ShadowsocksInboundOptions =
                        inbound.decode()?;
                    let component = ShadowsocksInbound::new_with_clock(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                        ntp_clock.clone(),
                    )?;
                    if let Some(handle) = component.managed_handle() {
                        managed_shadowsocks
                            .insert(component.tag().to_owned(), handle);
                    }
                    builder = builder.component(component);
                }
                "shadowtls" => {
                    let inbound_options: ShadowTlsInboundOptions =
                        inbound.decode()?;
                    if inbound_options.listen.detour.is_empty() {
                        return Err(RuntimeError::InvalidRoute(format!(
                            "ShadowTLS inbound {tag:?} requires an inbound detour"
                        )));
                    }
                    builder = builder.component(ShadowTlsInbound::new(
                        tag,
                        inbound_options,
                        outbounds.clone(),
                    )?);
                }
                "vmess" => {
                    let mut inbound_options: VMessInboundOptions =
                        inbound.decode()?;
                    certificate_providers.configure_tls(
                        inbound_options.tls.as_mut(),
                        &format!("inbound/vmess[{tag}]"),
                    )?;
                    builder = builder.component(VmessInbound::new_with_clock(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                        ntp_clock.clone(),
                    )?);
                }
                "anytls" => {
                    let mut inbound_options: AnyTlsInboundOptions =
                        inbound.decode()?;
                    certificate_providers.configure_tls(
                        inbound_options.tls.as_mut(),
                        &format!("inbound/anytls[{tag}]"),
                    )?;
                    builder = builder.component(AnyTlsInbound::new(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                    )?);
                }
                "hysteria2" => {
                    let mut inbound_options: Hysteria2InboundOptions =
                        inbound.decode()?;
                    certificate_providers.configure_tls(
                        inbound_options.tls.as_mut(),
                        &format!("inbound/hysteria2[{tag}]"),
                    )?;
                    builder = builder.component(
                        Hysteria2Inbound::new_in_with_runtime_context(
                            tag,
                            inbound_options,
                            router.clone(),
                            outbounds.clone(),
                            base_path,
                            ntp_clock.clone(),
                            Some(certificate_store.clone()),
                        )?,
                    );
                }
                "hysteria" => {
                    let mut inbound_options: HysteriaInboundOptions =
                        inbound.decode()?;
                    certificate_providers.configure_tls(
                        inbound_options.tls.as_mut(),
                        &format!("inbound/hysteria[{tag}]"),
                    )?;
                    builder = builder.component(HysteriaInbound::new(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                    )?);
                }
                "tuic" => {
                    let mut inbound_options: TuicInboundOptions =
                        inbound.decode()?;
                    certificate_providers.configure_tls(
                        inbound_options.tls.as_mut(),
                        &format!("inbound/tuic[{tag}]"),
                    )?;
                    builder = builder.component(TuicInbound::new(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                    )?);
                }
                "naive" => {
                    let mut inbound_options: NaiveInboundOptions =
                        inbound.decode()?;
                    certificate_providers.configure_tls(
                        inbound_options.tls.as_mut(),
                        &format!("inbound/naive[{tag}]"),
                    )?;
                    builder = builder.component(NaiveInbound::new(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                    )?);
                }
                "redirect" => {
                    let inbound_options: RedirectInboundOptions =
                        inbound.decode()?;
                    builder = builder.component(RedirectInbound::new(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                    ));
                }
                "tproxy" => {
                    let inbound_options: TProxyInboundOptions =
                        inbound.decode()?;
                    builder = builder.component(TProxyInbound::new(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                    )?);
                }
                "tun" => {
                    let inbound_options: TunInboundOptions =
                        inbound.decode()?;
                    #[cfg(any(target_os = "android", target_os = "ios"))]
                    let component = match tun_provider.as_ref() {
                        Some(provider) => TunInbound::new_with_provider(
                            tag,
                            inbound_options,
                            router.clone(),
                            outbounds.clone(),
                            provider.clone(),
                        )?,
                        None => TunInbound::new(
                            tag,
                            inbound_options,
                            router.clone(),
                            outbounds.clone(),
                        )?,
                    };
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    let component = TunInbound::new(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                    )?;
                    builder = builder.component(component);
                }
                "snell" => {
                    let inbound_options: SnellInboundOptions =
                        inbound.decode()?;
                    builder = builder.component(SnellInbound::new(
                        tag,
                        inbound_options,
                        router.clone(),
                        outbounds.clone(),
                    )?);
                }
                "cloudflared" => {
                    let inbound_options: CloudflaredInboundOptions =
                        inbound.decode()?;
                    let control_dialer = outbounds.resolver_on_detour_dialer(
                        &format!("{tag}/control"),
                        &inbound_options.control_dialer,
                        false,
                    )?;
                    let tunnel_dialer = outbounds.resolver_on_detour_dialer(
                        &format!("{tag}/tunnel"),
                        &inbound_options.tunnel_dialer,
                        false,
                    )?;
                    let (control_resolver, control_strategy) = outbounds
                        .endpoint_destination_resolver(
                            &format!("{tag}/control"),
                            &inbound_options.control_dialer,
                        )?;
                    let (tunnel_resolver, tunnel_strategy) = outbounds
                        .endpoint_destination_resolver(
                            &format!("{tag}/tunnel"),
                            &inbound_options.tunnel_dialer,
                        )?;
                    let (component, handle) =
                        CloudflaredInbound::new_with_runtime_context(
                            tag.clone(),
                            inbound_options,
                            router.clone(),
                            outbounds.clone(),
                            control_dialer,
                            tunnel_dialer,
                            control_resolver,
                            control_strategy,
                            tunnel_resolver,
                            tunnel_strategy,
                            ntp_clock.clone(),
                            Some(certificate_store.clone()),
                        )?;
                    cloudflared_inbounds.insert(tag, handle);
                    builder = builder.component(component);
                }
                kind => {
                    return Err(RuntimeError::UnsupportedInbound {
                        kind: kind.to_owned(),
                        tag,
                    });
                }
            }
        }
        let mut ssm_api = HashMap::new();
        let mut hysteria_realm = HashMap::new();
        for (index, service) in options.services.iter().enumerate() {
            let tag = if service.tag.is_empty() {
                index.to_string()
            } else {
                service.tag.clone()
            };
            match service.kind.as_str() {
                "ssm-api" => {
                    let mut service_options: SsmApiServiceOptions =
                        service.decode()?;
                    certificate_providers.configure_tls(
                        service_options.tls.as_mut(),
                        &format!("service/ssm-api[{tag}]"),
                    )?;
                    let (component, handle) = SsmApiServer::new(
                        tag.clone(),
                        service_options,
                        &managed_shadowsocks,
                        base_path,
                    )
                    .map_err(RuntimeError::SsmApi)?;
                    ssm_api.insert(tag, handle);
                    builder = builder.component(component);
                }
                "hysteria-realm" => {
                    let mut service_options: HysteriaRealmServiceOptions =
                        service.decode()?;
                    certificate_providers.configure_tls(
                        service_options.tls.as_mut(),
                        &format!("service/hysteria-realm[{tag}]"),
                    )?;
                    let (component, handle) =
                        HysteriaRealmService::new(tag.clone(), service_options)
                            .map_err(RuntimeError::HysteriaRealm)?;
                    hysteria_realm.insert(tag, handle);
                    builder = builder.component(component);
                }
                kind => {
                    return Err(RuntimeError::UnsupportedService {
                        kind: kind.to_owned(),
                        tag,
                    });
                }
            }
        }
        certificate_providers.bind_tailscale_endpoints(&tailscale_endpoints)?;
        let clash_api = if let Some(mut options) = options
            .experimental
            .as_ref()
            .and_then(|experimental| experimental.clash_api.clone())
        {
            if !options.external_ui.is_empty()
                && Path::new(&options.external_ui).is_relative()
            {
                options.external_ui = base_path
                    .join(&options.external_ui)
                    .to_string_lossy()
                    .into_owned();
            }
            let (server, handle) = ClashApiServer::new(
                options,
                router.clone(),
                outbounds.clone(),
                log.clone(),
            )
            .map_err(RuntimeError::ClashApi)?;
            builder = builder.component(server);
            Some(handle)
        } else {
            None
        };
        if !certificate_providers.is_empty() {
            builder = builder.component_first(certificate_providers);
        }
        if let Some(ntp_service) = ntp_service {
            builder = builder.component_first(ntp_service);
        }
        builder = builder.component_first(certificate_store.clone());
        Ok(Self {
            service: builder.build()?,
            router,
            outbounds,
            log,
            clash_api,
            ssm_api,
            hysteria_realm,
            wireguard_endpoints,
            openvpn_client_endpoints,
            openvpn_server_endpoints,
            openconnect_endpoints,
            tailscale_endpoints,
            cloudflared_inbounds,
            certificate_store,
            ntp_clock,
            deprecated_warnings,
        })
    }

    pub fn options(&self) -> &Options {
        self.service.options()
    }

    pub fn handle(&self) -> RuntimeHandle {
        RuntimeHandle {
            cancellation: self.service.cancellation_token(),
        }
    }

    pub fn router(&self) -> &Router {
        &self.router
    }

    pub fn outbounds(&self) -> &OutboundManager {
        &self.outbounds
    }

    pub fn ntp_clock(&self) -> Option<&NtpClock> {
        self.ntp_clock.as_ref()
    }

    pub fn certificate_store(&self) -> &CertificateStore {
        &self.certificate_store
    }

    pub fn deprecated_warnings(&self) -> &[DeprecatedNote] {
        &self.deprecated_warnings
    }

    pub fn logger(&self) -> Logger {
        self.log.logger()
    }

    pub fn clash_mode(&self) -> Option<String> {
        self.router.clash_mode()
    }

    pub fn clash_modes(&self) -> &[String] {
        self.router.clash_modes()
    }

    pub fn clash_api_addr(&self) -> Option<SocketAddr> {
        self.clash_api.as_ref().and_then(ClashApiHandle::local_addr)
    }

    pub fn ssm_api_addr(&self, tag: &str) -> Option<SocketAddr> {
        self.ssm_api.get(tag).and_then(SsmApiHandle::local_addr)
    }

    pub fn hysteria_realm_addr(&self, tag: &str) -> Option<SocketAddr> {
        self.hysteria_realm
            .get(tag)
            .and_then(HysteriaRealmHandle::local_addr)
    }

    pub fn wireguard_endpoint(
        &self,
        tag: &str,
    ) -> Option<Arc<crate::endpoint::wireguard::WireGuardEndpoint>> {
        self.wireguard_endpoints
            .get(tag)
            .and_then(WireGuardEndpointHandle::endpoint)
    }

    pub fn openvpn_client_endpoint(
        &self,
        tag: &str,
    ) -> Option<Arc<crate::protocol::openvpn::OpenVpnConnectedClient>> {
        self.openvpn_client_endpoints
            .get(tag)
            .and_then(OpenVpnClientEndpointHandle::client)
    }

    pub fn openvpn_client_challenge_manager(
        &self,
        tag: &str,
    ) -> Option<Arc<crate::protocol::openvpn::ChallengeManager>> {
        self.openvpn_client_endpoints
            .get(tag)
            .map(OpenVpnClientEndpointHandle::challenge_manager)
    }

    pub fn openvpn_server_endpoint(
        &self,
        tag: &str,
    ) -> Option<OpenVpnServerEndpointHandle> {
        self.openvpn_server_endpoints.get(tag).cloned()
    }

    pub fn openconnect_endpoint(
        &self,
        tag: &str,
    ) -> Option<OpenConnectEndpointHandle> {
        self.openconnect_endpoints.get(tag).cloned()
    }

    pub fn tailscale_endpoint(
        &self,
        tag: &str,
    ) -> Option<TailscaleEndpointHandle> {
        self.tailscale_endpoints.get(tag).cloned()
    }

    pub fn cloudflared_inbound(
        &self,
        tag: &str,
    ) -> Option<CloudflaredInboundHandle> {
        self.cloudflared_inbounds.get(tag).cloned()
    }

    pub fn set_clash_mode(&self, mode: &str) -> bool {
        if !self.router.set_clash_mode(mode) {
            return false;
        }
        if let Some(mode) = self.router.clash_mode() {
            self.outbounds.dns().set_clash_mode(Some(mode.clone()));
            self.outbounds.dns().clear_cache();
            self.outbounds.save_mode(&mode);
        }
        true
    }

    pub async fn start(&mut self) -> Result<(), RuntimeError> {
        self.log.start()?;
        if let Err(error) = self.router.start().await {
            let _ = self.log.close();
            return Err(error.into());
        }
        if let Err(error) = self.service.start().await {
            self.router.close().await;
            let _ = self.log.close();
            return Err(error.into());
        }
        Ok(())
    }

    pub async fn close(&mut self) -> Result<(), RuntimeError> {
        let service_result = self.service.close().await;
        self.router.close().await;
        let log_result = self.log.close();
        service_result?;
        log_result?;
        Ok(())
    }

    pub async fn run_until_cancelled(&mut self) -> Result<(), RuntimeError> {
        let cancellation = self.service.cancellation_token();
        self.start().await?;
        cancellation.cancelled().await;
        self.close().await
    }
}

fn collect_clash_modes(rules: &[Value], modes: &mut Vec<String>) {
    for rule in rules {
        let Some(object) = rule.as_object() else {
            continue;
        };
        if let Some(mode) = object.get("clash_mode").and_then(Value::as_str) {
            modes.push(mode.to_owned());
        }
        if let Some(children) = object.get("rules").and_then(Value::as_array) {
            collect_clash_modes(children, modes);
        }
    }
}

fn order_clash_modes(modes: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for mode in modes.into_iter().filter(|mode| !mode.is_empty()) {
        if !unique
            .iter()
            .any(|known: &String| known.eq_ignore_ascii_case(&mode))
        {
            unique.push(mode);
        }
    }
    let predefined = ["Rule", "Global", "Direct"];
    let mut custom: Vec<_> = unique
        .iter()
        .filter(|mode| {
            !predefined
                .iter()
                .any(|known| mode.eq_ignore_ascii_case(known))
        })
        .cloned()
        .collect();
    custom.sort();
    for known in predefined {
        if let Some(mode) =
            unique.iter().find(|mode| mode.eq_ignore_ascii_case(known))
        {
            custom.push(mode.clone());
        }
    }
    custom
}

struct RuntimeRouteOptions<'a> {
    rules: Vec<Value>,
    rule_sets: &'a [RuleSetOptions],
    final_outbound: &'a str,
    default_http_client: &'a str,
    find_process: bool,
    find_neighbor: bool,
    dhcp_lease_files: &'a [String],
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    platform_network_defaults: PlatformNetworkDefaults,
}

fn route_options(
    route: Option<&RouteOptions>,
) -> Result<RuntimeRouteOptions<'_>, RuntimeError> {
    let Some(route) = route else {
        return Ok(RuntimeRouteOptions {
            rules: Vec::new(),
            rule_sets: &[],
            final_outbound: "",
            default_http_client: "",
            find_process: false,
            find_neighbor: false,
            dhcp_lease_files: &[],
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_defaults: PlatformNetworkDefaults::default(),
        });
    };
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    let platform_network_defaults =
        PlatformNetworkDefaults::from_route_options(route)
            .map_err(|error| RuntimeError::InvalidRoute(error.to_string()))?;
    Ok(RuntimeRouteOptions {
        rules: route
            .rules
            .iter()
            .map(RouteRuleOptions::to_value)
            .collect::<Result<_, _>>()
            .map_err(|error| RuntimeError::InvalidRoute(error.to_string()))?,
        rule_sets: &route.rule_set,
        final_outbound: &route.final_outbound,
        default_http_client: &route.default_http_client,
        find_process: route.find_process,
        find_neighbor: route.find_neighbor,
        dhcp_lease_files: route.dhcp_lease_files.as_slice(),
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        platform_network_defaults,
    })
}

fn contains_process_rule(values: &[Value]) -> bool {
    const PROCESS_KEYS: &[&str] = &[
        "process_name",
        "process_path",
        "process_path_regex",
        "package_name",
        "package_name_regex",
        "user",
        "user_id",
    ];
    fn contains(value: &Value) -> bool {
        match value {
            Value::Object(object) => {
                object.iter().any(|(key, value)| {
                    (PROCESS_KEYS.contains(&key.as_str())
                        && !value.is_null()
                        && !matches!(value, Value::Array(values) if values.is_empty()))
                        || contains(value)
                })
            }
            Value::Array(values) => values.iter().any(contains),
            _ => false,
        }
    }
    values.iter().any(contains)
}

fn contains_neighbor_rule(values: &[Value]) -> bool {
    const NEIGHBOR_KEYS: &[&str] = &["source_mac_address", "source_hostname"];
    fn contains(value: &Value) -> bool {
        match value {
            Value::Object(object) => object.iter().any(|(key, value)| {
                (NEIGHBOR_KEYS.contains(&key.as_str())
                    && !value.is_null()
                    && !matches!(value, Value::Array(values) if values.is_empty()))
                    || contains(value)
            }),
            Value::Array(values) => values.iter().any(contains),
            _ => false,
        }
    }
    values.iter().any(contains)
}

fn has_local_neighbor_dns_server(
    servers: &[crate::option::DnsServerOptions],
) -> bool {
    servers.iter().any(|server| {
        if server.kind != "local" {
            return false;
        }
        server.fields.get("neighbor_domain").is_some_and(|value| {
            !value.is_null()
                && !value.as_str().is_some_and(str::is_empty)
                && !value.as_array().is_some_and(Vec::is_empty)
        })
    })
}

/// The pinned WireGuard system device only enables sing-tun `AutoRoute` on
/// Darwin. Linux and Windows receive the peer prefixes in the option object,
/// but their platform start paths return before installing them while
/// `AutoRoute` is false.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn wireguard_system_routes(
    config: &WireGuardEndpointConfig,
) -> Vec<ipnet::IpNet> {
    #[cfg(target_os = "macos")]
    {
        config
            .peers
            .iter()
            .flat_map(|peer| peer.allowed_ips.iter().copied())
            .collect()
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        let _ = config;
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::Path,
        sync::Arc,
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use boringtun::x25519::{PublicKey, StaticSecret};
    use futures_util::StreamExt as _;
    use hickory_proto::{
        op::{Message, MessageType, OpCode},
        rr::{RData, Record, rdata::A},
        serialize::binary::{
            BinDecodable, BinDecoder, BinEncodable, BinEncoder,
        },
    };
    use rcgen::{
        CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream, UdpSocket},
    };

    use crate::{
        adapter::Dialer,
        common::network::SocksAddr,
        option::{OpenVpnServerEndpointOptions, Options},
        protocol::{
            direct::DirectOutbound,
            openconnect::{
                GlobalProtectEspProbe, OpenConnectEspAuthentication,
                OpenConnectEspEncryption, OpenConnectEspKeyMaterial,
                OpenConnectEspKeySet, OpenConnectEspKeySetConfig,
                PPP_MAXIMUM_WIRE_FRAME_SIZE, PppEncapsulation, PppFrameDecoder,
                PppNegotiator, PppNegotiatorOptions,
                build_fortinet_dtls_connect_request,
            },
            openvpn::{
                IncomingDataEvent, Opcode, OpenVpnActiveDataSession,
                OpenVpnClientConnector, OpenVpnDataCodec,
                OpenVpnDatagramTransport, OpenVpnIpPrefix,
                OpenVpnPacketTransport, OpenVpnStaticDataSession,
                OpenVpnStaticDataSessionOptions, Packet, PushedLocalAddress,
                PushedOptions, ServerPushAssignment,
                ServerTlsDataChannelOptions, StaticKeyDataCodec,
                TlsControlProtection, TlsServerNegotiationError,
                build_openvpn_server_security, establish_tls_server_session,
                negotiate_tls_server_data_channel, openvpn_stream_transport,
            },
            shadowsocks::ShadowsocksOutbound,
        },
        route::Metadata,
        runtime::Runtime,
    };

    #[tokio::test]
    async fn direct_rule_action_applies_its_own_socket_options() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let options: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "outbounds": [{"type":"block", "tag":"blocked"}],
            "route": {
                "final": "blocked",
                "rules": [{
                    "ip_cidr": "127.0.0.0/8",
                    "action": "direct",
                    "inet4_bind_address": "192.0.2.1",
                    "connect_timeout": "2s"
                }]
            }
        }))
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        let metadata = crate::route::Metadata {
            destination: Some(destination.into()),
            network: Some(crate::common::network::Network::Tcp),
            ..Default::default()
        };
        let decision = runtime.router.route(&metadata);
        let internal_tag = decision
            .outbound()
            .expect("configured direct action has an internal dialer");
        assert!(internal_tag.starts_with('\0'));
        let dialer = runtime.outbounds.select(Some(internal_tag)).unwrap();
        let destination = destination.into();
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            dialer.dial_tcp(&destination),
        )
        .await
        .expect("direct action dial timed out");
        let error = match result {
            Ok(_) => {
                panic!("unavailable direct action bind address was ignored")
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::AddrNotAvailable);
        assert!(!runtime.outbounds.tags().any(|tag| tag == internal_tag));
    }

    #[test]
    fn direct_rule_action_resolver_is_validated_during_runtime_build() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "route": {
                "rules": [{
                    "action": "direct",
                    "domain_resolver": "missing"
                }]
            }
        }))
        .unwrap();
        let error = Runtime::from_options(options).err().unwrap().to_string();
        assert!(
            error.contains("configure direct action at rule 0"),
            "{error}"
        );
        assert!(
            error.contains("DNS resolver \"missing\" not found"),
            "{error}"
        );
    }

    async fn api_request(
        address: std::net::SocketAddr,
        request: &str,
    ) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    async fn json_api_request(
        address: std::net::SocketAddr,
        method: &str,
        path: &str,
        body: &str,
    ) -> String {
        api_request(
            address,
            &format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        )
        .await
    }

    async fn read_http_request<S>(stream: &mut S) -> (String, Vec<u8>)
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut request = Vec::new();
        let mut tail = [0_u8; 4];
        while tail != *b"\r\n\r\n" {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
            tail.rotate_left(1);
            tail[3] = byte[0];
        }
        let headers = String::from_utf8(request).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or_default();
        let mut body = vec![0; content_length];
        stream.read_exact(&mut body).await.unwrap();
        (headers, body)
    }

    fn ipv4_udp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_length = 20 + 8 + payload.len();
        let mut packet = vec![0_u8; total_length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26]
            .copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        let checksum = packet[..20].chunks_exact(2).fold(0_u32, |sum, word| {
            sum + u32::from(u16::from_be_bytes([word[0], word[1]]))
        });
        let checksum = !((checksum & 0xffff) + (checksum >> 16)) as u16;
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn icmpv4_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
        let mut packet =
            b"\x08\x00\x00\x00\x00\x00\x00\x00runtime-icmp".to_vec();
        packet[4..6].copy_from_slice(&identifier.to_be_bytes());
        packet[6..8].copy_from_slice(&sequence.to_be_bytes());
        let checksum = internet_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn internet_checksum(data: &[u8]) -> u16 {
        let mut sum = 0_u32;
        let mut chunks = data.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(byte) = chunks.remainder().first() {
            sum += u32::from(*byte) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[tokio::test]
    async fn wireguard_endpoint_follows_runtime_lifecycle() {
        let private_key = [31_u8; 32];
        let peer_public =
            PublicKey::from(&StaticSecret::from([32_u8; 32])).to_bytes();
        let options: Options = serde_json::from_value(serde_json::json!({
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "wireguard",
                "tag": "wg",
                "address": ["10.0.0.1/32"],
                "private_key": STANDARD.encode(private_key),
                "peers": [{
                    "address": "127.0.0.1",
                    "port": 9,
                    "public_key": STANDARD.encode(peer_public),
                    "allowed_ips": ["0.0.0.0/0"]
                }]
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        assert!(runtime.wireguard_endpoint("wg").is_none());
        let wireguard_dialer = runtime.outbounds().outbound("wg").unwrap();
        let destination = crate::common::network::SocksAddr::from(
            "10.0.0.2:53".parse::<std::net::SocketAddr>().unwrap(),
        );
        assert_eq!(
            wireguard_dialer
                .dial_tcp(&destination)
                .await
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::NotConnected
        );

        runtime.start().await.unwrap();
        let endpoint = runtime.wireguard_endpoint("wg").unwrap();
        assert_eq!(endpoint.peer_count(), 1);
        assert_ne!(endpoint.peer_local_addr(0).unwrap().unwrap().port(), 0);
        assert!(
            wireguard_dialer.listen_udp(&destination).await.is_ok(),
            "WireGuard endpoint tag must be usable as a routed UDP outbound"
        );
        drop(endpoint);

        runtime.close().await.unwrap();
        assert!(runtime.wireguard_endpoint("wg").is_none());
        assert_eq!(
            wireguard_dialer
                .dial_tcp(&destination)
                .await
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::NotConnected
        );
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    ))]
    #[test]
    fn wireguard_system_mode_constructs_native_interface_lifecycle() {
        let private_key = [33_u8; 32];
        let peer_public =
            PublicKey::from(&StaticSecret::from([34_u8; 32])).to_bytes();
        let options: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "wireguard",
                "tag": "wg-system",
                "system": true,
                "name": "zay-wg-test",
                "address": ["10.77.0.1/32", "fd00:77::1/128"],
                "private_key": STANDARD.encode(private_key),
                "peers": [{
                    "address": "127.0.0.1",
                    "port": 9,
                    "public_key": STANDARD.encode(peer_public),
                    "allowed_ips": ["10.77.0.0/16", "fd00:77::/48"]
                }]
            }]
        }))
        .unwrap();
        let endpoint_options: crate::option::WireGuardEndpointOptions =
            options.endpoints[0].decode().unwrap();
        let system_config =
            crate::endpoint::wireguard::WireGuardEndpointConfig::from_options(
                &endpoint_options,
            )
            .unwrap();
        let routes = super::wireguard_system_routes(&system_config);
        #[cfg(target_os = "macos")]
        assert_eq!(
            routes,
            vec![
                "10.77.0.0/16".parse().unwrap(),
                "fd00:77::/48".parse().unwrap()
            ]
        );
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        assert!(routes.is_empty());
        let runtime = Runtime::from_options(options).unwrap();
        let dialer = runtime.outbounds().outbound("wg-system").unwrap();
        assert!(
            dialer.packet_port().is_none(),
            "system mode must expose the OS-bound dialer, not the userspace packet port"
        );
    }

    #[tokio::test]
    async fn wireguard_endpoint_routes_peer_tcp_and_udp_flows() {
        let server_private = [41_u8; 32];
        let client_private = [42_u8; 32];
        let server_public =
            PublicKey::from(&StaticSecret::from(server_private)).to_bytes();
        let client_public =
            PublicKey::from(&StaticSecret::from(client_private)).to_bytes();
        let server_reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_port = server_reservation.local_addr().unwrap().port();
        let client_reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_port = client_reservation.local_addr().unwrap().port();
        drop(server_reservation);
        drop(client_reservation);

        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_destination = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut request = [0_u8; 11];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"wg-tcp-flow");
            stream.write_all(b"wg-tcp-routed").await.unwrap();
        });
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut request = [0_u8; 64];
            let (length, source) =
                udp_target.recv_from(&mut request).await.unwrap();
            assert_eq!(&request[..length], b"wg-udp-flow");
            udp_target.send_to(b"wg-udp-routed", source).await.unwrap();
        });

        let server_options: Options =
            serde_json::from_value(serde_json::json!({
                "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {
                    "rules": [{
                        "network": "icmp",
                        "ip_cidr": "127.0.0.2/32",
                        "action": "reject"
                    }],
                    "final": "direct"
                },
                "endpoints": [{
                    "type": "wireguard",
                    "tag": "wg-server",
                    "address": "10.20.0.1/32",
                    "private_key": STANDARD.encode(server_private),
                    "listen_port": server_port,
                    "udp_timeout": "2s",
                    "peers": [{
                        "address": "127.0.0.1",
                        "port": client_port,
                        "public_key": STANDARD.encode(client_public),
                        "allowed_ips": "10.20.0.2/32"
                    }]
                }]
            }))
            .unwrap();
        let client_options: Options =
            serde_json::from_value(serde_json::json!({
                "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "endpoints": [{
                    "type": "wireguard",
                    "tag": "wg-client",
                    "address": "10.20.0.2/32",
                    "private_key": STANDARD.encode(client_private),
                    "listen_port": client_port,
                    "udp_timeout": "2s",
                    "peers": [{
                        "address": "127.0.0.1",
                        "port": server_port,
                        "public_key": STANDARD.encode(server_public),
                        "allowed_ips": "0.0.0.0/0"
                    }]
                }]
            }))
            .unwrap();
        let mut server_runtime = Runtime::from_options(server_options).unwrap();
        let mut client_runtime = Runtime::from_options(client_options).unwrap();
        server_runtime.start().await.unwrap();
        client_runtime.start().await.unwrap();
        let server_dialer =
            server_runtime.outbounds().outbound("wg-server").unwrap();
        let client_dialer =
            client_runtime.outbounds().outbound("wg-client").unwrap();

        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            client_dialer.dial_tcp(&tcp_destination.into()),
        )
        .await
        .unwrap()
        .unwrap();
        stream.write_all(b"wg-tcp-flow").await.unwrap();
        let mut tcp_response = [0_u8; 13];
        stream.read_exact(&mut tcp_response).await.unwrap();
        assert_eq!(&tcp_response, b"wg-tcp-routed");

        let udp_destination = SocksAddr::from(udp_destination);
        let packet = client_dialer.listen_udp(&udp_destination).await.unwrap();
        packet
            .send_to(b"wg-udp-flow", &udp_destination)
            .await
            .unwrap();
        let mut udp_response = [0_u8; 64];
        let (length, source) = tokio::time::timeout(
            Duration::from_secs(5),
            packet.recv_from(&mut udp_response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&udp_response[..length], b"wg-udp-routed");
        assert_eq!(source, udp_destination);

        let icmp_request = icmpv4_echo_request(0x3141, 7);
        let icmp_response = tokio::time::timeout(
            Duration::from_secs(5),
            client_dialer.exchange_icmp(
                &icmp_request,
                IpAddr::V4(Ipv4Addr::new(10, 20, 0, 2)),
                64,
                &SocksAddr::new("127.0.0.1", 0),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(icmp_response.source, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(icmp_response.packet[0], 0);
        assert_eq!(&icmp_response.packet[4..8], b"\x31\x41\x00\x07");
        assert_eq!(&icmp_response.packet[8..], b"runtime-icmp");
        assert_eq!(internet_checksum(&icmp_response.packet), 0);
        let rejected_icmp = tokio::time::timeout(
            Duration::from_secs(5),
            client_dialer.exchange_icmp(
                &icmp_request,
                IpAddr::V4(Ipv4Addr::new(10, 20, 0, 2)),
                64,
                &SocksAddr::new("127.0.0.2", 0),
            ),
        )
        .await
        .expect("reject reply timed out")
        .expect("reject reply was not delivered");
        assert_eq!(
            rejected_icmp.source,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
        );
        assert_eq!(&rejected_icmp.packet[..2], &[3, 1]);
        assert_eq!(internet_checksum(&rejected_icmp.packet), 0);
        let reverse_icmp = server_dialer
            .exchange_icmp(
                &icmpv4_echo_request(0x3142, 8),
                IpAddr::V4(Ipv4Addr::new(10, 20, 0, 1)),
                64,
                &SocksAddr::new("10.20.0.2", 0),
            )
            .await
            .unwrap();
        assert_eq!(
            reverse_icmp.source,
            IpAddr::V4(Ipv4Addr::new(10, 20, 0, 2))
        );
        assert_eq!(&reverse_icmp.packet[4..8], b"\x31\x42\x00\x08");

        tcp_echo.await.unwrap();
        udp_echo.await.unwrap();
        client_runtime.close().await.unwrap();
        server_runtime.close().await.unwrap();
    }

    #[tokio::test]
    async fn builds_openvpn_client_endpoint_and_registers_stable_dialer() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openvpn-client",
                "tag": "ovpn",
                "server": "127.0.0.1",
                "server_port": 1194,
                "network": "udp",
                "tls": {
                    "peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            }]
        }))
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        assert!(runtime.openvpn_client_endpoint("ovpn").is_none());
        let dialer = runtime.outbounds().outbound("ovpn").unwrap();
        let error = dialer
            .dial_tcp(&SocksAddr::new("192.0.2.1", 80))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn builds_openconnect_endpoint_and_registers_stable_dialer() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openconnect",
                "tag": "oc",
                "server": "vpn.example",
                "cookie": "webvpn=test",
                "no_udp": true,
                "tls": {"insecure": true}
            }]
        }))
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        let endpoint = runtime.openconnect_endpoint("oc").unwrap();
        assert!(endpoint.tunnel_configuration().is_none());
        assert!(!endpoint.dtls_active());
        let dialer = runtime.outbounds().outbound("oc").unwrap();
        let error = dialer
            .dial_tcp(&SocksAddr::new("192.0.2.1", 80))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    ))]
    #[test]
    fn dynamic_vpn_system_modes_construct_native_interface_lifecycles() {
        let openvpn: Options =
            serde_json::from_value(serde_json::json!({
                "certificate": {"store": "none"},
                "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "endpoints": [{
                    "type": "openvpn-client",
                    "tag": "ovpn-system",
                    "system": true,
                    "name": "zay-ovpn-test",
                    "server": "127.0.0.1",
                    "server_port": 1194,
                    "network": "udp",
                    "tls": {
                        "peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                }]
            }))
            .unwrap();
        let runtime = Runtime::from_options(openvpn).unwrap();
        assert!(
            runtime
                .outbounds()
                .outbound("ovpn-system")
                .unwrap()
                .packet_port()
                .is_none()
        );

        let static_key = hex::encode((0..=u8::MAX).collect::<Vec<_>>());
        let openvpn_server: Options =
            serde_json::from_value(serde_json::json!({
                "certificate": {"store": "none"},
                "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "endpoints": [{
                    "type": "openvpn-server",
                    "tag": "ovpn-server-system",
                    "system": true,
                    "name": "zay-ovpn-server-test",
                    "listen": "127.0.0.1",
                    "listen_port": 0,
                    "mode": "static_key",
                    "network": "tcp",
                    "address": "10.78.0.1/24",
                    "peer_address": "10.78.0.2",
                    "static_key": static_key,
                    "key_direction": "server",
                    "cipher": "AES-256-CBC",
                    "auth": "SHA256"
                }]
            }))
            .unwrap();
        let runtime = Runtime::from_options(openvpn_server).unwrap();
        assert!(
            runtime
                .outbounds()
                .outbound("ovpn-server-system")
                .unwrap()
                .packet_port()
                .is_none()
        );

        let openconnect: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openconnect",
                "tag": "oc-system",
                "system": true,
                "name": "zay-oc-test",
                "server": "vpn.example",
                "cookie": "webvpn=test",
                "no_udp": true,
                "tls": {"insecure": true}
            }]
        }))
        .unwrap();
        let runtime = Runtime::from_options(openconnect).unwrap();
        assert!(
            runtime
                .outbounds()
                .outbound("oc-system")
                .unwrap()
                .packet_port()
                .is_none()
        );

        let tailscale: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "tailscale",
                "tag": "ts-system",
                "system_interface": true,
                "system_interface_name": "zay-ts-test"
            }]
        }))
        .unwrap();
        let runtime = Runtime::from_options(tailscale).unwrap();
        assert!(
            runtime
                .outbounds()
                .outbound("ts-system")
                .unwrap()
                .packet_port()
                .is_none()
        );
    }

    #[test]
    fn validates_openconnect_dns_endpoint_binding_and_uniqueness() {
        let missing: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [{
                "type": "openconnect",
                "tag": "vpn-dns",
                "endpoint": "missing"
            }]},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap();
        let error = Runtime::from_options(missing).err().unwrap().to_string();
        assert!(
            error.contains("OpenConnect DNS endpoint not found"),
            "{error}"
        );

        let duplicate: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [
                {"type": "openconnect", "tag": "vpn-dns-1", "endpoint": "oc"},
                {"type": "openconnect", "tag": "vpn-dns-2", "endpoint": "oc"}
            ]},
            "route": {"default_domain_resolver": "vpn-dns-1"},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openconnect",
                "tag": "oc",
                "server": "vpn.example",
                "cookie": "webvpn=test",
                "no_udp": true,
                "tls": {"insecure": true}
            }]
        }))
        .unwrap();
        let error = Runtime::from_options(duplicate).err().unwrap().to_string();
        assert!(error.contains("only one OpenConnect DNS server"), "{error}");
    }

    #[test]
    fn validates_openvpn_dns_endpoint_binding_and_uniqueness() {
        let missing: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [{
                "type": "openvpn",
                "tag": "vpn-dns",
                "endpoint": "missing"
            }]},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap();
        let error = Runtime::from_options(missing).err().unwrap().to_string();
        assert!(error.contains("OpenVPN DNS endpoint not found"), "{error}");

        let duplicate: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [
                {"type": "openvpn", "tag": "vpn-dns-1", "endpoint": "vpn"},
                {"type": "openvpn", "tag": "vpn-dns-2", "endpoint": "vpn"}
            ]},
            "route": {"default_domain_resolver": "vpn-dns-1"},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openvpn-client",
                "tag": "vpn",
                "server": "127.0.0.1",
                "server_port": 1194,
                "network": "udp",
                "tls": {
                    "peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            }]
        }))
        .unwrap();
        let error = Runtime::from_options(duplicate).err().unwrap().to_string();
        assert!(error.contains("only one OpenVPN DNS server"), "{error}");
    }

    #[test]
    fn validates_tailscale_dns_endpoint_binding_and_uniqueness() {
        let missing: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [{
                "type": "tailscale",
                "tag": "tailnet-dns",
                "endpoint": "missing"
            }]},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap();
        let error = Runtime::from_options(missing).err().unwrap().to_string();
        assert!(
            error.contains("Tailscale DNS endpoint not found"),
            "{error}"
        );

        let duplicate: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [
                {"type": "tailscale", "tag": "tailnet-dns-1", "endpoint": "ts"},
                {"type": "tailscale", "tag": "tailnet-dns-2", "endpoint": "ts"}
            ]},
            "route": {"default_domain_resolver": "tailnet-dns-1"},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "tailscale",
                "tag": "ts",
                "state_directory": "tailscale-test"
            }]
        }))
        .unwrap();
        let error = Runtime::from_options(duplicate).err().unwrap().to_string();
        assert!(error.contains("only one Tailscale DNS server"), "{error}");
    }

    #[tokio::test]
    async fn openconnect_endpoint_starts_cstp_userspace_network_and_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certificate_pem = certificate.pem();
        let server_config = rustls::ServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    key.serialize_der(),
                ),
            ),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = Vec::new();
            let mut tail = [0_u8; 4];
            while tail != *b"\r\n\r\n" {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                tail.rotate_left(1);
                tail[3] = byte[0];
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("CONNECT /CSCOSSLC/tunnel HTTP/1.1"));
            assert!(request.contains("Cookie: webvpn=session"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nX-CSTP-MTU: 1300\r\nX-CSTP-Address: 10.88.0.2\r\nX-CSTP-Netmask: 255.255.255.0\r\nX-CSTP-Split-Include: 10.0.0.0/8\r\nX-CSTP-Split-Exclude: 10.99.0.0/16\r\nX-CSTP-DNS: 172.16.0.53\r\nX-CSTP-Default-Domain: search.example\r\nX-CSTP-Split-DNS: corp.example\r\n\r\n",
                )
                .await
                .unwrap();
            stream.flush().await.unwrap();
            let packet = crate::protocol::openconnect::read_cstp_packet(
                &mut stream,
                crate::protocol::openconnect::CSTP_MAX_PAYLOAD_SIZE,
            )
            .await
            .unwrap();
            assert_eq!(
                packet.packet_type,
                crate::protocol::openconnect::CstpPacketType::Data
            );
            assert_eq!(&packet.payload[16..20], &[172, 16, 0, 53]);
            assert_eq!(
                u16::from_be_bytes(packet.payload[22..24].try_into().unwrap()),
                53
            );
            let request =
                Message::read(&mut BinDecoder::new(&packet.payload[28..]))
                    .unwrap();
            assert_eq!(
                request.queries[0].name().to_utf8(),
                "service.corp.example."
            );
            let mut response = Message::new(
                request.metadata.id,
                MessageType::Response,
                OpCode::Query,
            );
            response.queries = request.queries.clone();
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 55))),
            ));
            let mut dns_payload = Vec::new();
            response
                .emit(&mut BinEncoder::new(&mut dns_payload))
                .unwrap();
            let source_port =
                u16::from_be_bytes(packet.payload[20..22].try_into().unwrap());
            let response_packet = ipv4_udp_packet(
                Ipv4Addr::new(172, 16, 0, 53),
                Ipv4Addr::new(10, 88, 0, 2),
                53,
                source_port,
                &dns_payload,
            );
            crate::protocol::openconnect::write_cstp_packet(
                &mut stream,
                crate::protocol::openconnect::CstpPacketType::Data,
                &response_packet,
            )
            .await
            .unwrap();
            loop {
                let packet = crate::protocol::openconnect::read_cstp_packet(
                    &mut stream,
                    crate::protocol::openconnect::CSTP_MAX_PAYLOAD_SIZE,
                )
                .await
                .unwrap();
                if packet.packet_type
                    == crate::protocol::openconnect::CstpPacketType::Disconnect
                {
                    break;
                }
                assert_eq!(
                    packet.packet_type,
                    crate::protocol::openconnect::CstpPacketType::Data,
                    "client must send data or CSTP disconnect"
                );
                if packet.payload.len() >= 24
                    && u16::from_be_bytes(
                        packet.payload[22..24].try_into().unwrap(),
                    ) == 53
                {
                    crate::protocol::openconnect::write_cstp_packet(
                        &mut stream,
                        crate::protocol::openconnect::CstpPacketType::Data,
                        &response_packet,
                    )
                    .await
                    .unwrap();
                }
            }
        });

        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {
                "servers": [{
                    "type": "openconnect",
                    "tag": "vpn-dns",
                    "endpoint": "oc",
                    "accept_default_resolvers": true,
                    "accept_search_domain": true
                }],
                "final": "vpn-dns"
            },
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {
                "rules": [{
                    "preferred_by": "oc",
                    "action": "route",
                    "outbound": "oc"
                }],
                "final": "direct"
            },
            "endpoints": [{
                "type": "openconnect",
                "tag": "oc",
                "server": format!("https://127.0.0.1:{}", address.port()),
                "cookie": "webvpn=session",
                "no_udp": true,
                "tls": {
                    "server_name": "localhost",
                    "system_trust_disabled": true,
                    "certificate_authority": certificate_pem
                }
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        let endpoint = runtime.openconnect_endpoint("oc").unwrap();
        let configuration = endpoint.tunnel_configuration().unwrap();
        assert_eq!(configuration.mtu, 1300);
        assert_eq!(
            configuration.addresses,
            vec!["10.88.0.2/24".parse().unwrap()]
        );
        assert!(
            configuration
                .routes
                .iter()
                .any(|route| route.prefix == "172.16.0.53/32".parse().unwrap())
        );
        let route_to = |destination: &str| {
            runtime
                .router()
                .route(&Metadata {
                    destination: Some(SocksAddr::new(destination, 443)),
                    ..Metadata::default()
                })
                .outbound()
                .map(str::to_owned)
        };
        assert_eq!(route_to("10.20.30.40"), Some("oc".into()));
        assert_eq!(route_to("10.99.1.1"), Some("direct".into()));
        assert_eq!(route_to("172.16.0.53"), Some("oc".into()));
        assert_eq!(route_to("host.corp.example"), Some("oc".into()));
        assert_eq!(route_to("notcorp.example"), Some("direct".into()));
        let addresses = runtime
            .outbounds()
            .dns()
            .default()
            .lookup(
                "service.corp.example",
                crate::option::DomainStrategy::Ipv4Only,
            )
            .await
            .unwrap();
        assert_eq!(addresses, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))]);
        assert!(!endpoint.dtls_active());
        runtime.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn openconnect_fortinet_endpoint_negotiates_ppp_over_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certificate_pem = certificate.pem();
        let server_config = rustls::ServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    key.serialize_der(),
                ),
            ),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (configuration_stream, _) = listener.accept().await.unwrap();
            let mut configuration_stream =
                acceptor.accept(configuration_stream).await.unwrap();
            let (headers, body) =
                read_http_request(&mut configuration_stream).await;
            let lower_headers = headers.to_ascii_lowercase();
            assert!(headers.starts_with(
                "GET /remote/fortisslvpn_xml?dual_stack=1 HTTP/1.1"
            ));
            assert!(lower_headers.contains("cookie: svpncookie=session"));
            assert!(body.is_empty());
            let configuration = br#"<sslvpn-tunnel dtls="0"><ipv4><assigned-addr ipv4="10.91.0.2"/></ipv4></sslvpn-tunnel>"#;
            configuration_stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=session; Path=/; Secure\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        configuration.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            configuration_stream.write_all(configuration).await.unwrap();
            configuration_stream.shutdown().await.unwrap();

            let (tunnel_stream, _) = listener.accept().await.unwrap();
            let mut tunnel_stream =
                acceptor.accept(tunnel_stream).await.unwrap();
            let (headers, body) = read_http_request(&mut tunnel_stream).await;
            assert!(headers.starts_with("GET /remote/sslvpn-tunnel HTTP/1.1"));
            assert!(headers.contains("Cookie: SVPNCOOKIE=session"));
            assert!(body.is_empty());

            let now = std::time::Instant::now();
            let mut peer = PppNegotiator::new(
                PppNegotiatorOptions {
                    want_ipv6: false,
                    ipv4_address: Some("10.91.0.1/32".parse().unwrap()),
                    ..Default::default()
                },
                now,
            )
            .unwrap();
            for packet in peer.start(now).unwrap() {
                tunnel_stream
                    .write_all(
                        &packet.encode(PppEncapsulation::Fortinet).unwrap(),
                    )
                    .await
                    .unwrap();
            }
            tunnel_stream.flush().await.unwrap();
            let mut decoder = PppFrameDecoder::new(PppEncapsulation::Fortinet);
            let mut buffer = vec![0_u8; PPP_MAXIMUM_WIRE_FRAME_SIZE];
            loop {
                let count = tunnel_stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                for frame in decoder.push(&buffer[..count]).unwrap() {
                    let event = peer
                        .handle_frame(&frame, std::time::Instant::now())
                        .unwrap();
                    for packet in event.outbound {
                        tunnel_stream
                            .write_all(
                                &packet
                                    .encode(PppEncapsulation::Fortinet)
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                    }
                    tunnel_stream.flush().await.unwrap();
                    if event.peer_terminated {
                        return;
                    }
                }
            }
        });

        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openconnect",
                "tag": "fortinet",
                "flavor": "fortinet",
                "server": format!("https://127.0.0.1:{}", address.port()),
                "cookie": "SVPNCOOKIE=session",
                "no_udp": true,
                "tls": {
                    "server_name": "localhost",
                    "system_trust_disabled": true,
                    "certificate_authority": certificate_pem
                }
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        let endpoint = runtime.openconnect_endpoint("fortinet").unwrap();
        let configuration = endpoint.tunnel_configuration().unwrap();
        assert_eq!(
            configuration.addresses,
            vec!["10.91.0.2/32".parse().unwrap()]
        );
        assert!(
            configuration
                .routes
                .iter()
                .any(|route| route.prefix == "0.0.0.0/0".parse().unwrap())
        );
        assert!(!endpoint.dtls_active());
        runtime.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn openconnect_fortinet_endpoint_reconnects_with_locked_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certificate_pem = certificate.pem();
        let server_config = rustls::ServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    key.serialize_der(),
                ),
            ),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (configuration_stream, _) =
                    listener.accept().await.unwrap();
                let mut configuration_stream =
                    acceptor.accept(configuration_stream).await.unwrap();
                let (headers, body) =
                    read_http_request(&mut configuration_stream).await;
                assert!(headers.starts_with(
                    "GET /remote/fortisslvpn_xml?dual_stack=1 HTTP/1.1"
                ));
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains("cookie: svpncookie=session")
                );
                assert!(body.is_empty());
                let assigned = if attempt == 0 {
                    "10.93.0.2"
                } else {
                    // A reconnect must retain the address negotiated by the
                    // first tunnel even if the repeated XML proposes another.
                    "10.93.0.99"
                };
                let configuration = format!(
                    "<sslvpn-tunnel dtls=\"0\"><auth-ses tun-connect-without-reauth=\"1\" check-src-ip=\"1\" tun-user-ses-timeout=\"30\"/><ipv4><assigned-addr ipv4=\"{assigned}\"/></ipv4></sslvpn-tunnel>"
                );
                configuration_stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=session; Path=/; Secure\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            configuration.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                configuration_stream
                    .write_all(configuration.as_bytes())
                    .await
                    .unwrap();
                configuration_stream.shutdown().await.unwrap();

                let (tunnel_stream, _) = listener.accept().await.unwrap();
                let mut tunnel_stream =
                    acceptor.accept(tunnel_stream).await.unwrap();
                let (headers, body) =
                    read_http_request(&mut tunnel_stream).await;
                assert!(
                    headers.starts_with("GET /remote/sslvpn-tunnel HTTP/1.1")
                );
                assert!(headers.contains("Cookie: SVPNCOOKIE=session"));
                assert!(body.is_empty());

                let now = std::time::Instant::now();
                let mut peer = PppNegotiator::new(
                    PppNegotiatorOptions {
                        want_ipv6: false,
                        ipv4_address: Some("10.93.0.1/32".parse().unwrap()),
                        ..Default::default()
                    },
                    now,
                )
                .unwrap();
                for packet in peer.start(now).unwrap() {
                    tunnel_stream
                        .write_all(
                            &packet.encode(PppEncapsulation::Fortinet).unwrap(),
                        )
                        .await
                        .unwrap();
                }
                tunnel_stream.flush().await.unwrap();
                let mut decoder =
                    PppFrameDecoder::new(PppEncapsulation::Fortinet);
                let mut buffer = vec![0_u8; PPP_MAXIMUM_WIRE_FRAME_SIZE];
                'session: loop {
                    let count = tunnel_stream.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    for frame in decoder.push(&buffer[..count]).unwrap() {
                        let event = peer
                            .handle_frame(&frame, std::time::Instant::now())
                            .unwrap();
                        for packet in event.outbound {
                            tunnel_stream
                                .write_all(
                                    &packet
                                        .encode(PppEncapsulation::Fortinet)
                                        .unwrap(),
                                )
                                .await
                                .unwrap();
                        }
                        tunnel_stream.flush().await.unwrap();
                        if attempt == 0 && peer.is_ready() {
                            break 'session;
                        }
                        if event.peer_terminated {
                            return;
                        }
                    }
                }
            }
        });

        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openconnect",
                "tag": "fortinet",
                "flavor": "fortinet",
                "server": format!("https://127.0.0.1:{}", address.port()),
                "cookie": "SVPNCOOKIE=session",
                "no_udp": true,
                "reconnect_timeout": "5s",
                "tls": {
                    "server_name": "localhost",
                    "system_trust_disabled": true,
                    "certificate_authority": certificate_pem
                }
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        let endpoint = runtime.openconnect_endpoint("fortinet").unwrap();
        let reconnected = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if endpoint.successful_reconnections() == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            reconnected.is_ok(),
            "Fortinet reconnect failed: {:?}",
            endpoint.last_error()
        );
        assert!(endpoint.last_error().is_none());
        assert_eq!(endpoint.userspace_stack_generation(), 1);
        assert_eq!(
            endpoint.tunnel_configuration().unwrap().addresses,
            vec!["10.93.0.2/32".parse().unwrap()]
        );
        runtime.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn openconnect_fortinet_endpoint_prefers_certificate_dtls() {
        use webrtc_util::conn::Listener as _;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certificate_pem = certificate.pem();
        let dtls_identity = dtls::crypto::Certificate {
            certificate: vec![certificate.der().clone()],
            private_key: dtls::crypto::CryptoPrivateKey::try_from(&key)
                .unwrap(),
        };
        let server_config = rustls::ServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    key.serialize_der(),
                ),
            ),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let configuration_server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let (headers, body) = read_http_request(&mut stream).await;
            assert!(headers.starts_with(
                "GET /remote/fortisslvpn_xml?dual_stack=1 HTTP/1.1"
            ));
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("cookie: svpncookie=session")
            );
            assert!(body.is_empty());
            let configuration = br#"<sslvpn-tunnel dtls="1"><ipv4><assigned-addr ipv4="10.92.0.2"/></ipv4></sslvpn-tunnel>"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=session; Path=/; Secure\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        configuration.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(configuration).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let datagram_server = tokio::spawn(async move {
            let listener = dtls::listener::listen(
                address,
                dtls::config::Config {
                    certificates: vec![dtls_identity],
                    flight_interval: Duration::from_millis(20),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let mut buffer = vec![0_u8; PPP_MAXIMUM_WIRE_FRAME_SIZE];
            let (connection, _) = listener.accept().await.unwrap();
            let count = connection.recv(&mut buffer).await.unwrap();
            assert_eq!(
                &buffer[..count],
                &build_fortinet_dtls_connect_request("session").unwrap()
            );
            let mut hello = Vec::from([0_u8, 0]);
            hello.extend_from_slice(b"GFtype\0svrhello\0handshake\0ok\0");
            let length = u16::try_from(hello.len()).unwrap();
            hello[..2].copy_from_slice(&length.to_be_bytes());
            connection.send(&hello).await.unwrap();

            let now = std::time::Instant::now();
            let mut peer = PppNegotiator::new(
                PppNegotiatorOptions {
                    want_ipv6: false,
                    ipv4_address: Some("10.92.0.1/32".parse().unwrap()),
                    ..Default::default()
                },
                now,
            )
            .unwrap();
            for packet in peer.start(now).unwrap() {
                connection
                    .send(&packet.encode(PppEncapsulation::Fortinet).unwrap())
                    .await
                    .unwrap();
            }
            loop {
                let count = connection.recv(&mut buffer).await.unwrap();
                let mut decoder =
                    PppFrameDecoder::new(PppEncapsulation::Fortinet);
                for frame in decoder.push(&buffer[..count]).unwrap() {
                    let event = peer
                        .handle_frame(&frame, std::time::Instant::now())
                        .unwrap();
                    for packet in event.outbound {
                        connection
                            .send(
                                &packet
                                    .encode(PppEncapsulation::Fortinet)
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                    }
                    if event.peer_terminated {
                        let _ = connection.close().await;
                        listener.close().await.unwrap();
                        return;
                    }
                }
                assert_eq!(decoder.discard(), 0);
            }
        });

        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openconnect",
                "tag": "fortinet",
                "flavor": "fortinet",
                "server": format!("https://127.0.0.1:{}", address.port()),
                "cookie": "SVPNCOOKIE=session",
                "tls": {
                    "server_name": "localhost",
                    "system_trust_disabled": true,
                    "certificate_authority": certificate_pem
                }
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        let endpoint = runtime.openconnect_endpoint("fortinet").unwrap();
        let configuration = endpoint.tunnel_configuration().unwrap();
        assert_eq!(
            configuration.addresses,
            vec!["10.92.0.2/32".parse().unwrap()]
        );
        assert!(endpoint.dtls_active());
        assert!(endpoint.last_dtls_error().is_none());
        runtime.close().await.unwrap();
        configuration_server.await.unwrap();
        datagram_server.await.unwrap();
    }

    #[tokio::test]
    async fn openconnect_fortinet_endpoint_performs_late_dtls_takeover() {
        use webrtc_util::conn::Listener as _;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certificate_pem = certificate.pem();
        let dtls_identity = dtls::crypto::Certificate {
            certificate: vec![certificate.der().clone()],
            private_key: dtls::crypto::CryptoPrivateKey::try_from(&key)
                .unwrap(),
        };
        let server_config = rustls::ServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    key.serialize_der(),
                ),
            ),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let tcp_server = tokio::spawn(async move {
            let (configuration_stream, _) = listener.accept().await.unwrap();
            let mut configuration_stream =
                acceptor.accept(configuration_stream).await.unwrap();
            let (headers, _) =
                read_http_request(&mut configuration_stream).await;
            assert!(headers.starts_with(
                "GET /remote/fortisslvpn_xml?dual_stack=1 HTTP/1.1"
            ));
            let configuration = br#"<sslvpn-tunnel dtls="1"><ipv4><assigned-addr ipv4="10.94.0.2"/></ipv4></sslvpn-tunnel>"#;
            configuration_stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=session; Path=/; Secure\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        configuration.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            configuration_stream.write_all(configuration).await.unwrap();
            configuration_stream.shutdown().await.unwrap();

            let (tunnel_stream, _) = listener.accept().await.unwrap();
            let mut tunnel_stream =
                acceptor.accept(tunnel_stream).await.unwrap();
            let (headers, _) = read_http_request(&mut tunnel_stream).await;
            assert!(headers.starts_with("GET /remote/sslvpn-tunnel HTTP/1.1"));
            let now = std::time::Instant::now();
            let mut peer = PppNegotiator::new(
                PppNegotiatorOptions {
                    want_ipv6: false,
                    ipv4_address: Some("10.94.0.1/32".parse().unwrap()),
                    ..Default::default()
                },
                now,
            )
            .unwrap();
            for packet in peer.start(now).unwrap() {
                tunnel_stream
                    .write_all(
                        &packet.encode(PppEncapsulation::Fortinet).unwrap(),
                    )
                    .await
                    .unwrap();
            }
            tunnel_stream.flush().await.unwrap();
            let mut decoder = PppFrameDecoder::new(PppEncapsulation::Fortinet);
            let mut buffer = vec![0_u8; PPP_MAXIMUM_WIRE_FRAME_SIZE];
            loop {
                let Ok(count) = tunnel_stream.read(&mut buffer).await else {
                    // A successful takeover retires the TLS carrier without
                    // a TLS close_notify, matching upstream's raw carrier swap.
                    return;
                };
                if count == 0 {
                    return;
                }
                for frame in decoder.push(&buffer[..count]).unwrap() {
                    let event = peer
                        .handle_frame(&frame, std::time::Instant::now())
                        .unwrap();
                    for packet in event.outbound {
                        tunnel_stream
                            .write_all(
                                &packet
                                    .encode(PppEncapsulation::Fortinet)
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                    }
                    tunnel_stream.flush().await.unwrap();
                }
            }
        });
        let datagram_server = tokio::spawn(async move {
            // The first five-second DTLS window must expire so the endpoint
            // establishes TLS and exercises the periodic late takeover path.
            tokio::time::sleep(Duration::from_secs(6)).await;
            let listener = dtls::listener::listen(
                address,
                dtls::config::Config {
                    certificates: vec![dtls_identity],
                    flight_interval: Duration::from_millis(20),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let mut buffer = vec![0_u8; PPP_MAXIMUM_WIRE_FRAME_SIZE];
            let mut accepted = None;
            for attempt in 0..2 {
                let (connection, _) = listener.accept().await.unwrap();
                let count = connection.recv(&mut buffer).await.unwrap();
                assert_eq!(
                    &buffer[..count],
                    &build_fortinet_dtls_connect_request("session").unwrap()
                );
                if attempt == 0 {
                    connection.send(b"rejected").await.unwrap();
                    let _ = connection.close().await;
                    continue;
                }
                let mut hello = Vec::from([0_u8, 0]);
                hello.extend_from_slice(b"GFtype\0svrhello\0handshake\0ok\0");
                let length = u16::try_from(hello.len()).unwrap();
                hello[..2].copy_from_slice(&length.to_be_bytes());
                connection.send(&hello).await.unwrap();
                accepted = Some(connection);
            }
            let connection =
                accepted.expect("second late DTLS attempt accepted");

            let now = std::time::Instant::now();
            let mut peer = PppNegotiator::new(
                PppNegotiatorOptions {
                    want_ipv6: false,
                    ipv4_address: Some("10.94.0.1/32".parse().unwrap()),
                    ..Default::default()
                },
                now,
            )
            .unwrap();
            for packet in peer.start(now).unwrap() {
                connection
                    .send(&packet.encode(PppEncapsulation::Fortinet).unwrap())
                    .await
                    .unwrap();
            }
            let mut sent_probe = false;
            loop {
                let count = connection.recv(&mut buffer).await.unwrap();
                let mut decoder =
                    PppFrameDecoder::new(PppEncapsulation::Fortinet);
                for frame in decoder.push(&buffer[..count]).unwrap() {
                    let event = peer
                        .handle_frame(&frame, std::time::Instant::now())
                        .unwrap();
                    for packet in event.outbound {
                        connection
                            .send(
                                &packet
                                    .encode(PppEncapsulation::Fortinet)
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                    }
                    if peer.is_ready() && !sent_probe {
                        sent_probe = true;
                        let mut ipv4 = vec![0_u8; 20];
                        ipv4[0] = 0x45;
                        let packet = peer.build_data_packet(&ipv4).unwrap();
                        connection
                            .send(
                                &packet
                                    .encode(PppEncapsulation::Fortinet)
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                    }
                    if event.peer_terminated {
                        let _ = connection.close().await;
                        listener.close().await.unwrap();
                        return;
                    }
                }
            }
        });

        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openconnect",
                "tag": "fortinet",
                "flavor": "fortinet",
                "server": format!("https://127.0.0.1:{}", address.port()),
                "cookie": "SVPNCOOKIE=session",
                "tls": {
                    "server_name": "localhost",
                    "system_trust_disabled": true,
                    "certificate_authority": certificate_pem
                }
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        let endpoint = runtime.openconnect_endpoint("fortinet").unwrap();
        assert!(!endpoint.dtls_active());
        assert!(endpoint.last_dtls_error().is_some());
        tokio::time::timeout(Duration::from_secs(15), async {
            while !endpoint.dtls_active() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert!(endpoint.last_dtls_error().is_none());
        assert_eq!(endpoint.userspace_stack_generation(), 1);
        runtime.close().await.unwrap();
        tcp_server.await.unwrap();
        datagram_server.await.unwrap();
    }

    #[tokio::test]
    async fn openconnect_globalprotect_endpoint_starts_gpst_and_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certificate_pem = certificate.pem();
        let server_config = rustls::ServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    key.serialize_der(),
                ),
            ),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (configuration_stream, _) = listener.accept().await.unwrap();
            let mut configuration_stream =
                acceptor.accept(configuration_stream).await.unwrap();
            let mut request = Vec::new();
            let mut tail = [0_u8; 4];
            while tail != *b"\r\n\r\n" {
                let mut byte = [0_u8; 1];
                configuration_stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                tail.rotate_left(1);
                tail[3] = byte[0];
            }
            let headers = String::from_utf8(request).unwrap();
            assert!(
                headers.starts_with("POST /ssl-vpn/getconfig.esp HTTP/1.1")
            );
            assert!(headers.contains("user-agent: PAN GlobalProtect"));
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            let mut body = vec![0; content_length];
            configuration_stream.read_exact(&mut body).await.unwrap();
            let body = String::from_utf8(body).unwrap();
            assert!(body.contains("&authcookie=session&user=alice"));
            let configuration = br#"<response status="success">
              <ip-address>10.89.0.2</ip-address><netmask>255.255.255.0</netmask>
              <mtu>1300</mtu><ssl-tunnel-url>/gp-tunnel</ssl-tunnel-url>
              <access-routes><member>10.0.0.0/8</member></access-routes>
              <dns><member>172.17.0.53</member></dns>
            </response>"#;
            configuration_stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        configuration.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            configuration_stream.write_all(configuration).await.unwrap();
            configuration_stream.shutdown().await.unwrap();

            let (hip_stream, _) = listener.accept().await.unwrap();
            let mut hip_stream = acceptor.accept(hip_stream).await.unwrap();
            let mut request = Vec::new();
            let mut tail = [0_u8; 4];
            while tail != *b"\r\n\r\n" {
                let mut byte = [0_u8; 1];
                hip_stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                tail.rotate_left(1);
                tail[3] = byte[0];
            }
            let headers = String::from_utf8(request).unwrap();
            assert!(
                headers
                    .starts_with("POST /ssl-vpn/hipreportcheck.esp HTTP/1.1")
            );
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            let mut body = vec![0; content_length];
            hip_stream.read_exact(&mut body).await.unwrap();
            let body = String::from_utf8(body).unwrap();
            assert!(body.starts_with(
                "client-role=global-protect-full&authcookie=session&user=alice&client-ip=10.89.0.2&md5="
            ));
            let hip_response = br#"<response status="success"><hip-report-needed>no</hip-report-needed></response>"#;
            hip_stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        hip_response.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            hip_stream.write_all(hip_response).await.unwrap();
            hip_stream.shutdown().await.unwrap();

            let (gpst_stream, _) = listener.accept().await.unwrap();
            let mut gpst_stream = acceptor.accept(gpst_stream).await.unwrap();
            let mut request = Vec::new();
            let mut tail = [0_u8; 4];
            while tail != *b"\r\n\r\n" {
                let mut byte = [0_u8; 1];
                gpst_stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                tail.rotate_left(1);
                tail[3] = byte[0];
            }
            assert_eq!(
                request,
                b"GET /gp-tunnel?authcookie=session&user=alice HTTP/1.1\r\n\r\n"
            );
            gpst_stream
                .write_all(&crate::protocol::openconnect::GPST_START_MARKER)
                .await
                .unwrap();
            gpst_stream.flush().await.unwrap();
            let mut byte = [0_u8; 1];
            assert_eq!(gpst_stream.read(&mut byte).await.unwrap(), 0);

            let (logout_stream, _) = listener.accept().await.unwrap();
            let mut logout_stream =
                acceptor.accept(logout_stream).await.unwrap();
            let mut request = Vec::new();
            let mut tail = [0_u8; 4];
            while tail != *b"\r\n\r\n" {
                let mut byte = [0_u8; 1];
                logout_stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                tail.rotate_left(1);
                tail[3] = byte[0];
            }
            let headers = String::from_utf8(request).unwrap();
            assert!(headers.starts_with("POST /ssl-vpn/logout.esp HTTP/1.1"));
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            let mut body = vec![0; content_length];
            logout_stream.read_exact(&mut body).await.unwrap();
            assert_eq!(body, b"authcookie=session&user=alice");
            let logout_response = br#"<response status="success"/>"#;
            logout_stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        logout_response.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            logout_stream.write_all(logout_response).await.unwrap();
        });

        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openconnect",
                "tag": "gp",
                "flavor": "gp",
                "server": format!("https://127.0.0.1:{}/gateway", address.port()),
                "cookie": "authcookie=session&user=alice",
                "no_udp": true,
                "tls": {
                    "server_name": "localhost",
                    "system_trust_disabled": true,
                    "certificate_authority": certificate_pem
                }
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        let endpoint = runtime.openconnect_endpoint("gp").unwrap();
        let configuration = endpoint.tunnel_configuration().unwrap();
        assert_eq!(configuration.mtu, 1300);
        assert_eq!(
            configuration.addresses,
            vec!["10.89.0.2/24".parse().unwrap()]
        );
        assert!(
            configuration
                .routes
                .iter()
                .any(|route| route.prefix == "172.17.0.53/32".parse().unwrap())
        );
        assert!(!endpoint.dtls_active());
        runtime.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn openconnect_globalprotect_endpoint_prefers_esp_and_logs_out() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = tcp_listener.local_addr().unwrap();
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = udp_socket.local_addr().unwrap().port();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certificate_pem = certificate.pem();
        let server_config = rustls::ServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    key.serialize_der(),
                ),
            ),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let tcp_server = tokio::spawn(async move {
            let (configuration_stream, _) =
                tcp_listener.accept().await.unwrap();
            let mut configuration_stream =
                acceptor.accept(configuration_stream).await.unwrap();
            let (headers, body) =
                read_http_request(&mut configuration_stream).await;
            assert!(
                headers.starts_with("POST /ssl-vpn/getconfig.esp HTTP/1.1")
            );
            assert!(
                String::from_utf8(body)
                    .unwrap()
                    .contains("&authcookie=session&user=alice")
            );
            let configuration = format!(
                r#"<response status="success">
                  <ip-address>10.90.0.2</ip-address><netmask>255.255.255.0</netmask>
                  <gw-address>10.90.0.1</gw-address><mtu>1340</mtu>
                  <ssl-tunnel-url>/gp-tunnel</ssl-tunnel-url>
                  <ipsec><udp-port>{udp_port}</udp-port>
                  <enc-algo>aes-128-cbc</enc-algo><hmac-algo>sha1</hmac-algo>
                  <c2s-spi>01020304</c2s-spi><s2c-spi>05060708</s2c-spi>
                  <ekey-c2s><bits>128</bits><val>000102030405060708090a0b0c0d0e0f</val></ekey-c2s>
                  <ekey-s2c><bits>128</bits><val>101112131415161718191a1b1c1d1e1f</val></ekey-s2c>
                  <akey-c2s><bits>160</bits><val>000102030405060708090a0b0c0d0e0f10111213</val></akey-c2s>
                  <akey-s2c><bits>160</bits><val>202122232425262728292a2b2c2d2e2f30313233</val></akey-s2c>
                  <ipsec-mode>esp-tunnel</ipsec-mode></ipsec>
                </response>"#
            );
            configuration_stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        configuration.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            configuration_stream
                .write_all(configuration.as_bytes())
                .await
                .unwrap();
            configuration_stream.shutdown().await.unwrap();

            let (hip_stream, _) = tcp_listener.accept().await.unwrap();
            let mut hip_stream = acceptor.accept(hip_stream).await.unwrap();
            let (headers, _) = read_http_request(&mut hip_stream).await;
            assert!(
                headers
                    .starts_with("POST /ssl-vpn/hipreportcheck.esp HTTP/1.1")
            );
            let response = br#"<response status="success"><hip-report-needed>no</hip-report-needed></response>"#;
            hip_stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            hip_stream.write_all(response).await.unwrap();
            hip_stream.shutdown().await.unwrap();

            let (logout_stream, _) = tcp_listener.accept().await.unwrap();
            let mut logout_stream =
                acceptor.accept(logout_stream).await.unwrap();
            let (headers, body) = read_http_request(&mut logout_stream).await;
            assert!(headers.starts_with("POST /ssl-vpn/logout.esp HTTP/1.1"));
            assert_eq!(body, b"authcookie=session&user=alice");
            let response = br#"<response status="success"/>"#;
            logout_stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            logout_stream.write_all(response).await.unwrap();
        });
        let udp_server = tokio::spawn(async move {
            let server_keys =
                OpenConnectEspKeySet::new(&OpenConnectEspKeySetConfig {
                    encryption: OpenConnectEspEncryption::Aes128Cbc,
                    authentication: OpenConnectEspAuthentication::HmacSha1_96,
                    outbound: OpenConnectEspKeyMaterial {
                        spi: 0x0506_0708,
                        encryption_key: hex::decode(
                            "101112131415161718191a1b1c1d1e1f",
                        )
                        .unwrap(),
                        authentication_key: hex::decode(
                            "202122232425262728292a2b2c2d2e2f30313233",
                        )
                        .unwrap(),
                    },
                    inbound: OpenConnectEspKeyMaterial {
                        spi: 0x0102_0304,
                        encryption_key: hex::decode(
                            "000102030405060708090a0b0c0d0e0f",
                        )
                        .unwrap(),
                        authentication_key: hex::decode(
                            "000102030405060708090a0b0c0d0e0f10111213",
                        )
                        .unwrap(),
                    },
                    disable_replay_protection: false,
                })
                .unwrap();
            let mut datagram = vec![0_u8; 2048];
            let (length, peer) = tokio::time::timeout(
                Duration::from_secs(10),
                udp_socket.recv_from(&mut datagram),
            )
            .await
            .unwrap()
            .unwrap();
            let (mut probe, _) = server_keys.open(&datagram[..length]).unwrap();
            assert_eq!(&probe[12..16], &[10, 90, 0, 2]);
            assert_eq!(&probe[16..20], &[10, 90, 0, 1]);
            probe[12..16].copy_from_slice(&[10, 90, 0, 1]);
            probe[16..20].copy_from_slice(&[10, 90, 0, 2]);
            probe[20] = 0;
            assert!(
                GlobalProtectEspProbe {
                    assigned: "10.90.0.2".parse().unwrap(),
                    magic: "10.90.0.1".parse().unwrap(),
                }
                .matches(&probe)
            );
            let reply = server_keys.seal(&probe, None).unwrap();
            udp_socket.send_to(&reply, peer).await.unwrap();
        });

        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openconnect",
                "tag": "gp",
                "flavor": "gp",
                "server": format!("https://127.0.0.1:{}/gateway", tcp_address.port()),
                "cookie": "authcookie=session&user=alice",
                "tls": {
                    "server_name": "localhost",
                    "system_trust_disabled": true,
                    "certificate_authority": certificate_pem
                }
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        let endpoint = runtime.openconnect_endpoint("gp").unwrap();
        assert!(endpoint.dtls_active());
        assert!(endpoint.last_dtls_error().is_none());
        assert_eq!(
            endpoint.tunnel_configuration().unwrap().addresses,
            vec!["10.90.0.2/24".parse().unwrap()]
        );
        runtime.close().await.unwrap();
        udp_server.await.unwrap();
        tcp_server.await.unwrap();
    }

    #[tokio::test]
    async fn openconnect_endpoint_reconnects_cstp_with_original_cookie() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let server_config = rustls::ServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    key.serialize_der(),
                ),
            ),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                let mut request = Vec::new();
                let mut tail = [0_u8; 4];
                while tail != *b"\r\n\r\n" {
                    let mut byte = [0_u8; 1];
                    stream.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    tail.rotate_left(1);
                    tail[3] = byte[0];
                }
                let request = String::from_utf8(request).unwrap();
                assert!(
                    request.starts_with("CONNECT /CSCOSSLC/tunnel HTTP/1.1")
                );
                assert!(request.contains("Cookie: webvpn=reusable"));
                let mtu = 1300;
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nX-CSTP-MTU: {mtu}\r\nX-CSTP-Address: 10.89.0.2\r\nX-CSTP-Netmask: 255.255.255.0\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
                if attempt == 0 {
                    drop(stream);
                } else {
                    let mut header = [0_u8; 8];
                    stream.read_exact(&mut header).await.unwrap();
                    assert_eq!(&header[..4], b"STF\x01");
                    assert_eq!(header[6], 5);
                }
            }
        });

        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openconnect",
                "tag": "oc",
                "server": format!("https://localhost:{}", address.port()),
                "cookie": "webvpn=reusable",
                "no_udp": true,
                "reconnect_timeout": "5s",
                "tls": {"insecure": true}
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        let endpoint = runtime.openconnect_endpoint("oc").unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if endpoint.successful_reconnections() == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(endpoint.last_error().is_none());
        assert_eq!(endpoint.userspace_stack_generation(), 1);
        assert_eq!(endpoint.tunnel_configuration().unwrap().mtu, 1300);
        runtime.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn openvpn_client_endpoint_completes_runtime_start_and_push() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_address = listener.local_addr().unwrap();
        let alternate_listener =
            TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alternate_server_address = alternate_listener.local_addr().unwrap();
        let key = KeyPair::generate().unwrap();
        let mut certificate_parameters =
            CertificateParams::new(vec!["vpn.test".into()]).unwrap();
        certificate_parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "vpn.test");
        certificate_parameters.key_usages =
            vec![KeyUsagePurpose::DigitalSignature];
        certificate_parameters.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate =
            certificate_parameters.self_signed(&key).unwrap().pem();
        let server_options: OpenVpnServerEndpointOptions =
            serde_json::from_value(serde_json::json!({
                "address": "10.8.0.1/24",
                "network": "tcp",
                "tls": {
                    "certificate": certificate,
                    "key": key.serialize_pem(),
                    "verify_client_certificate": "none"
                }
            }))
            .unwrap();
        let server_security =
            build_openvpn_server_security(&server_options, Path::new("."))
                .unwrap();
        let (server_ready, mut wait_server_ready) =
            tokio::sync::mpsc::channel(2);
        let (close_session, mut wait_close_session) =
            tokio::sync::mpsc::channel(2);
        let server_task = tokio::spawn(async move {
            for session_index in 0..8 {
                let (stream, _) = if session_index < 3 {
                    listener.accept().await.unwrap()
                } else {
                    alternate_listener.accept().await.unwrap()
                };
                let transport = openvpn_stream_transport(
                    Box::new(stream) as crate::adapter::Stream
                );
                let negotiated = negotiate_tls_server_data_channel(
                    establish_tls_server_session(
                        transport.clone(),
                        &server_security.tls_context,
                        &TlsControlProtection::default(),
                        Duration::from_secs(5),
                        false,
                    )
                    .await
                    .unwrap(),
                    ServerTlsDataChannelOptions {
                        configured_ciphers: vec!["AES-256-GCM".into()],
                        protocol: "tcp".into(),
                        pushed_options: PushedOptions {
                            topology: "subnet".into(),
                            tun_mtu: 1400,
                            auth_token: if session_index == 1 {
                                "session-token".into()
                            } else {
                                String::new()
                            },
                            ..PushedOptions::default()
                        },
                        assignment: ServerPushAssignment {
                            local_address_ipv4: Some(PushedLocalAddress {
                                prefix: OpenVpnIpPrefix {
                                    address: IpAddr::V4(Ipv4Addr::new(
                                        10, 8, 0, 2,
                                    )),
                                    prefix_len: 24,
                                },
                                peer: None,
                                raw: String::new(),
                            }),
                            ipv4_topology: "subnet".into(),
                            server_ipv4: Some(Ipv4Addr::new(10, 8, 0, 1)),
                            peer_id: Some(7),
                            ..ServerPushAssignment::default()
                        },
                        handshake_window: Duration::from_secs(5),
                        ..ServerTlsDataChannelOptions::default()
                    },
                    move |username, password| {
                        if session_index == 0 {
                            return Err(
                                "CRV1:R:initial:YWxpY2U=:Initial OTP".into(),
                            );
                        }
                        if session_index == 2 {
                            return Err(
                                "TEMP[backoff 1,advance remote]:maintenance"
                                    .into(),
                            );
                        }
                        if session_index == 4 {
                            return Err(
                                "CRV1:R:state:YWxpY2U=:Enter OTP".into(),
                            );
                        }
                        if session_index == 6 {
                            return Err("invalid credentials".into());
                        }
                        let expected_password = match session_index {
                            1 => "CRV1::initial::111111",
                            3 => "session-token",
                            5 => "CRV1::state::654321",
                            7 => "SCRV1:c2VjcmV0:MjIyMjIy",
                            _ => unreachable!(),
                        };
                        (username == "alice" && password == expected_password)
                            .then_some(())
                            .ok_or_else(|| {
                                format!(
                                    "unexpected credentials for session {session_index}"
                                )
                            })
                    },
                )
                .await;
                if matches!(session_index, 0 | 2 | 4 | 6) {
                    assert!(matches!(
                        negotiated,
                        Err(TlsServerNegotiationError::AuthenticationRejected)
                    ));
                    continue;
                }
                let negotiated = negotiated.unwrap();
                let active = OpenVpnActiveDataSession::from_server(
                    transport, negotiated, 0,
                );
                server_ready.send(session_index).await.unwrap();
                wait_close_session.recv().await.unwrap();
                active.close();
            }
        });

        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [{
                "type": "openvpn-client",
                "tag": "ovpn",
                "network": "tcp",
                "servers": [
                    {
                        "server": server_address.ip().to_string(),
                        "server_port": server_address.port()
                    },
                    {
                        "server": alternate_server_address.ip().to_string(),
                        "server_port": alternate_server_address.port()
                    }
                ],
                "username": "alice",
                "password": "secret",
                "auth_retry": "interact",
                "static_challenge": "Static OTP",
                "data_ciphers": "AES-256-GCM",
                    "tls": {
                        "server_name": "vpn.test",
                        "server_name_type": "name",
                        "certificate": certificate,
                        "remote_certificate_tls": "server"
                    }
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        let initial_challenge_manager =
            runtime.openvpn_client_challenge_manager("ovpn").unwrap();
        let initial_challenge_responder = tokio::spawn(async move {
            let mut updates = initial_challenge_manager.subscribe();
            for (message, secret) in
                [("Static OTP", "000000"), ("Initial OTP", "111111")]
            {
                let challenge = loop {
                    if let Some(challenge) = initial_challenge_manager.pending()
                    {
                        break challenge;
                    }
                    updates.changed().await.unwrap();
                };
                assert_eq!(
                    challenge.kind,
                    crate::protocol::openvpn::ChallengeKind::Secret
                );
                assert_eq!(challenge.username, "alice");
                assert_eq!(challenge.message, message);
                initial_challenge_manager
                    .complete(
                        &challenge.id,
                        crate::protocol::openvpn::ChallengeResponse {
                            secret: secret.into(),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
            }
        });
        tokio::time::timeout(Duration::from_secs(5), runtime.start())
            .await
            .unwrap()
            .unwrap();
        initial_challenge_responder.await.unwrap();
        assert_eq!(wait_server_ready.recv().await, Some(1));
        let endpoint = runtime.openvpn_client_endpoint("ovpn").unwrap();
        let configuration = endpoint.tunnel_configuration();
        assert_eq!(configuration.tun_mtu, 1400);
        assert_eq!(
            configuration.local_ipv4,
            vec![OpenVpnIpPrefix {
                address: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
                prefix_len: 24,
            }]
        );
        assert_eq!(
            configuration.route_gateway,
            Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)))
        );

        close_session.send(()).await.unwrap();
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(8),
                wait_server_ready.recv()
            )
            .await
            .unwrap(),
            Some(3)
        );
        let reconnected = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(current) = runtime.openvpn_client_endpoint("ovpn")
                    && !Arc::ptr_eq(&endpoint, &current)
                {
                    return current;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            reconnected.tunnel_configuration().local_ipv4,
            configuration.local_ipv4
        );

        let challenge_manager =
            runtime.openvpn_client_challenge_manager("ovpn").unwrap();
        let mut challenge_updates = challenge_manager.subscribe();
        close_session.send(()).await.unwrap();
        let challenge = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if let Some(challenge) = challenge_manager.pending() {
                    return challenge;
                }
                challenge_updates.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(
            challenge.kind,
            crate::protocol::openvpn::ChallengeKind::Secret
        );
        assert_eq!(challenge.username, "alice");
        assert_eq!(challenge.message, "Enter OTP");
        challenge_manager
            .complete(
                &challenge.id,
                crate::protocol::openvpn::ChallengeResponse {
                    secret: "654321".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(5),
                wait_server_ready.recv()
            )
            .await
            .unwrap(),
            Some(5)
        );
        let challenged_client =
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(current) =
                        runtime.openvpn_client_endpoint("ovpn")
                        && !Arc::ptr_eq(&reconnected, &current)
                    {
                        return current;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();

        let mut retry_updates = challenge_manager.subscribe();
        close_session.send(()).await.unwrap();
        let retry_challenge =
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(challenge) = challenge_manager.pending() {
                        return challenge;
                    }
                    retry_updates.changed().await.unwrap();
                }
            })
            .await
            .unwrap();
        assert_eq!(retry_challenge.message, "Static OTP");
        assert_eq!(retry_challenge.previous_error, "invalid credentials");
        challenge_manager
            .complete(
                &retry_challenge.id,
                crate::protocol::openvpn::ChallengeResponse {
                    secret: "222222".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(5),
                wait_server_ready.recv()
            )
            .await
            .unwrap(),
            Some(7)
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(current) =
                        runtime.openvpn_client_endpoint("ovpn")
                        && !Arc::ptr_eq(&challenged_client, &current)
                    {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .is_ok()
        );

        runtime.close().await.unwrap();
        assert!(runtime.openvpn_client_endpoint("ovpn").is_none());
        close_session.send(()).await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn openvpn_server_runtime_accepts_tcp_and_udp_clients() {
        for network in ["tcp", "udp"] {
            let key = KeyPair::generate().unwrap();
            let mut certificate_parameters =
                CertificateParams::new(vec!["vpn.test".into()]).unwrap();
            certificate_parameters
                .distinguished_name
                .push(rcgen::DnType::CommonName, "vpn.test");
            certificate_parameters.key_usages =
                vec![KeyUsagePurpose::DigitalSignature];
            certificate_parameters.extended_key_usages =
                vec![ExtendedKeyUsagePurpose::ServerAuth];
            let certificate =
                certificate_parameters.self_signed(&key).unwrap().pem();
            let options: Options = serde_json::from_value(serde_json::json!({
                "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "endpoints": [{
                    "type": "openvpn-server",
                    "tag": "ovpn-server",
                    "listen": "127.0.0.1",
                    "listen_port": 0,
                    "address": "10.8.0.1/29",
                    "network": network,
                    "users": [{"username": "alice", "password": "secret"}],
                    "data_ciphers": "AES-256-GCM",
                    "tls": {
                        "certificate": certificate,
                        "key": key.serialize_pem(),
                        "verify_client_certificate": "none"
                    }
                }]
            }))
            .unwrap();
            let mut runtime = Runtime::from_options(options).unwrap();
            let server_dialer =
                runtime.outbounds().outbound("ovpn-server").unwrap();
            assert_eq!(
                server_dialer
                    .dial_tcp(&SocksAddr::new("10.8.0.2", 80))
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                std::io::ErrorKind::NotConnected
            );
            runtime.start().await.unwrap();
            let handle =
                runtime.openvpn_server_endpoint("ovpn-server").unwrap();
            let listen_address = handle.local_addr().unwrap();

            let client_options = serde_json::from_value(serde_json::json!({
                "server": listen_address.ip().to_string(),
                "server_port": listen_address.port(),
                "network": network,
                "username": "alice",
                "password": "secret",
                "data_ciphers": "AES-256-GCM",
                "tls": {
                    "server_name": "vpn.test",
                    "server_name_type": "name",
                    "certificate": certificate,
                    "remote_certificate_tls": "server"
                }
            }))
            .unwrap();
            let connector = OpenVpnClientConnector::new(
                client_options,
                Path::new("."),
                Arc::new(DirectOutbound::new(Default::default())),
            );
            let client = Arc::new(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    connector.connect(None),
                )
                .await
                .unwrap()
                .unwrap(),
            );
            tokio::time::timeout(Duration::from_secs(2), async {
                while handle.active_clients() != 1
                    || handle.client_addresses()
                        != vec!["10.8.0.2".parse::<IpAddr>().unwrap()]
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();

            let client_supervisor_cancellation =
                tokio_util::sync::CancellationToken::new();
            let client_supervisor =
                tokio::spawn(client.clone().run_renegotiation_supervisor(
                    client_supervisor_cancellation.clone(),
                ));
            assert_eq!(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    handle.renegotiate_clients()
                )
                .await
                .unwrap(),
                vec![Ok(true)],
                "server initiated {network} renegotiation failed"
            );
            tokio::time::timeout(Duration::from_secs(2), async {
                while client.active.data_plane().session().current_key_id() == 0
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let client_renegotiation = tokio::time::timeout(
                Duration::from_secs(5),
                client.renegotiate(),
            )
            .await;
            if !matches!(client_renegotiation, Ok(Ok(true))) {
                panic!(
                    "client initiated {network} renegotiation failed: {client_renegotiation:?}; server error: {:?}; active clients: {}",
                    handle.last_error(),
                    handle.active_clients(),
                );
            }

            let destination = SocksAddr::from(
                "10.8.0.2:32123".parse::<SocketAddr>().unwrap(),
            );
            let server_udp =
                server_dialer.listen_udp(&destination).await.unwrap();
            server_udp.send_to(b"server", &destination).await.unwrap();
            let packet = tokio::time::timeout(
                Duration::from_secs(2),
                client.active.read_data_packet(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&packet[packet.len() - 6..], b"server");
            assert_eq!(&packet[16..20], &[10, 8, 0, 2]);

            let server_udp_address = server_udp.local_addr().unwrap().unwrap();
            let reply = ipv4_udp_packet(
                Ipv4Addr::new(10, 8, 0, 2),
                Ipv4Addr::new(10, 8, 0, 1),
                32123,
                server_udp_address.port(),
                b"client",
            );
            client.active.write_data_packet(&reply).await.unwrap();
            let mut payload = [0_u8; 64];
            let (length, source) = tokio::time::timeout(
                Duration::from_secs(2),
                server_udp.recv_from(&mut payload),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&payload[..length], b"client");
            assert_eq!(
                source,
                SocksAddr::from(
                    "10.8.0.2:32123".parse::<SocketAddr>().unwrap()
                )
            );

            let replacement = Arc::new(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    connector.connect(None),
                )
                .await
                .unwrap()
                .unwrap(),
            );
            tokio::time::timeout(Duration::from_secs(2), async {
                while handle.active_clients() != 1
                    || handle.client_addresses()
                        != vec!["10.8.0.2".parse::<IpAddr>().unwrap()]
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            server_udp
                .send_to(b"replacement", &destination)
                .await
                .unwrap();
            let packet = tokio::time::timeout(
                Duration::from_secs(2),
                replacement.active.read_data_packet(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&packet[packet.len() - 11..], b"replacement");
            if network == "udp" {
                // Rebind the client link to a new source port while retaining
                // its negotiated peer-id and data keys. The clear peer-id may
                // select the candidate session, but the server must not float
                // until this encrypted packet authenticates successfully.
                let roaming_socket =
                    UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let data_plane = replacement.active.data_plane();
                let peer_id = data_plane.peer_id().unwrap();
                let mut forged = vec![
                    (Opcode::DataV2.wire_value() << 3)
                        | data_plane.session().current_key_id(),
                ];
                forged.extend_from_slice(&peer_id.to_be_bytes()[1..]);
                forged.extend_from_slice(&[0_u8; 32]);
                roaming_socket
                    .send_to(&forged, listen_address)
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
                assert_eq!(handle.active_clients(), 1);
                assert!(handle.last_error().is_none());
                server_udp.send_to(b"unmoved", &destination).await.unwrap();
                let packet = tokio::time::timeout(
                    Duration::from_secs(2),
                    replacement.active.read_data_packet(),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(&packet[packet.len() - 7..], b"unmoved");

                let roaming_request = ipv4_udp_packet(
                    Ipv4Addr::new(10, 8, 0, 2),
                    Ipv4Addr::new(10, 8, 0, 1),
                    32123,
                    server_udp_address.port(),
                    b"roaming",
                );
                for packet in
                    data_plane.encode_payload(&roaming_request, 0).unwrap()
                {
                    roaming_socket
                        .send_to(&packet, listen_address)
                        .await
                        .unwrap();
                }
                let (length, source) = tokio::time::timeout(
                    Duration::from_secs(2),
                    server_udp.recv_from(&mut payload),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(&payload[..length], b"roaming");
                assert_eq!(
                    source,
                    SocksAddr::from(
                        "10.8.0.2:32123".parse::<SocketAddr>().unwrap()
                    )
                );

                server_udp.send_to(b"floated", &destination).await.unwrap();
                let floated =
                    tokio::time::timeout(Duration::from_secs(2), async {
                        loop {
                            let mut raw = vec![0_u8; 65_535];
                            let (length, _) =
                                roaming_socket.recv_from(&mut raw).await?;
                            raw.truncate(length);
                            let packet =
                                Packet::parse(&raw).map_err(|error| {
                                    std::io::Error::other(error.to_string())
                                })?;
                            match data_plane.decode_packet(&packet) {
                                Ok(IncomingDataEvent::Payload(payload)) => {
                                    break Ok::<_, std::io::Error>(payload);
                                }
                                Ok(_) => {}
                                Err(error) => {
                                    return Err(std::io::Error::other(
                                        error.to_string(),
                                    ));
                                }
                            }
                        }
                    })
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&floated[floated.len() - 7..], b"floated");
            }
            client_supervisor_cancellation.cancel();
            let _ =
                tokio::time::timeout(Duration::from_secs(2), client_supervisor)
                    .await
                    .unwrap()
                    .unwrap();
            client.active.close();
            replacement.active.close();
            tokio::time::timeout(Duration::from_secs(2), runtime.close())
                .await
                .unwrap()
                .unwrap();
            assert!(runtime.openvpn_server_endpoint("ovpn-server").is_some());
            assert_eq!(handle.active_clients(), 0);
            assert!(handle.local_addr().is_none());
        }
    }

    #[tokio::test]
    async fn openvpn_server_routes_client_tcp_and_udp_flows() {
        for network in ["tcp", "udp"] {
            let key = KeyPair::generate().unwrap();
            let mut certificate_parameters =
                CertificateParams::new(vec!["vpn.test".into()]).unwrap();
            certificate_parameters
                .distinguished_name
                .push(rcgen::DnType::CommonName, "vpn.test");
            certificate_parameters.key_usages =
                vec![KeyUsagePurpose::DigitalSignature];
            certificate_parameters.extended_key_usages =
                vec![ExtendedKeyUsagePurpose::ServerAuth];
            let certificate =
                certificate_parameters.self_signed(&key).unwrap().pem();

            let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tcp_destination = tcp_target.local_addr().unwrap();
            let tcp_echo = tokio::spawn(async move {
                let (mut stream, _) = tcp_target.accept().await.unwrap();
                let mut request = [0_u8; 12];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"vpn-tcp-flow");
                stream.write_all(b"tcp-through-router").await.unwrap();
            });
            let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_destination = udp_target.local_addr().unwrap();
            let udp_echo = tokio::spawn(async move {
                let mut request = [0_u8; 64];
                let (length, source) =
                    udp_target.recv_from(&mut request).await.unwrap();
                assert_eq!(&request[..length], b"vpn-udp-flow");
                udp_target
                    .send_to(b"udp-through-router", source)
                    .await
                    .unwrap();
            });

            let server_options: Options =
                serde_json::from_value(serde_json::json!({
                    "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
                    "outbounds": [{"type": "direct", "tag": "direct"}],
                    "route": {"final": "direct"},
                    "endpoints": [{
                        "type": "openvpn-server",
                        "tag": "ovpn-server",
                        "listen": "127.0.0.1",
                        "listen_port": 0,
                        "udp_timeout": "2s",
                        "address": "10.18.0.1/29",
                        "network": network,
                        "users": [{"username": "alice", "password": "secret"}],
                        "data_ciphers": "AES-256-GCM",
                        "push": {"redirect_gateway": true},
                        "tls": {
                            "certificate": certificate,
                            "key": key.serialize_pem(),
                            "verify_client_certificate": "none"
                        }
                    }]
                }))
                .unwrap();
            let mut server_runtime =
                Runtime::from_options(server_options).unwrap();
            server_runtime.start().await.unwrap();
            let server_address = server_runtime
                .openvpn_server_endpoint("ovpn-server")
                .unwrap()
                .local_addr()
                .unwrap();
            let server_dialer =
                server_runtime.outbounds().outbound("ovpn-server").unwrap();

            let client_options: Options =
                serde_json::from_value(serde_json::json!({
                    "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
                    "outbounds": [{"type": "direct", "tag": "direct"}],
                    "endpoints": [{
                        "type": "openvpn-client",
                        "tag": "ovpn-client",
                        "server": server_address.ip().to_string(),
                        "server_port": server_address.port(),
                        "network": network,
                        "username": "alice",
                        "password": "secret",
                        "data_ciphers": "AES-256-GCM",
                        "tls": {
                            "server_name": "vpn.test",
                            "server_name_type": "name",
                            "certificate": certificate,
                            "remote_certificate_tls": "server"
                        }
                    }]
                }))
                .unwrap();
            let mut client_runtime =
                Runtime::from_options(client_options).unwrap();
            tokio::time::timeout(
                Duration::from_secs(5),
                client_runtime.start(),
            )
            .await
            .unwrap()
            .unwrap();
            let client_dialer =
                client_runtime.outbounds().outbound("ovpn-client").unwrap();

            let mut stream = tokio::time::timeout(
                Duration::from_secs(5),
                client_dialer.dial_tcp(&tcp_destination.into()),
            )
            .await
            .unwrap()
            .unwrap();
            stream.write_all(b"vpn-tcp-flow").await.unwrap();
            let mut tcp_response = [0_u8; 18];
            stream.read_exact(&mut tcp_response).await.unwrap();
            assert_eq!(&tcp_response, b"tcp-through-router");

            let udp_destination = SocksAddr::from(udp_destination);
            let packet =
                client_dialer.listen_udp(&udp_destination).await.unwrap();
            packet
                .send_to(b"vpn-udp-flow", &udp_destination)
                .await
                .unwrap();
            let mut udp_response = [0_u8; 64];
            let (length, source) = tokio::time::timeout(
                Duration::from_secs(5),
                packet.recv_from(&mut udp_response),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&udp_response[..length], b"udp-through-router");
            assert_eq!(source, udp_destination);

            let icmp_request = icmpv4_echo_request(0x2718, 3);
            let icmp_response = tokio::time::timeout(
                Duration::from_secs(5),
                client_dialer.exchange_icmp(
                    &icmp_request,
                    IpAddr::V4(Ipv4Addr::new(10, 18, 0, 2)),
                    64,
                    &SocksAddr::new("127.0.0.1", 0),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(icmp_response.source, IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert_eq!(icmp_response.packet[0], 0);
            assert_eq!(&icmp_response.packet[4..8], b"\x27\x18\x00\x03");
            assert_eq!(&icmp_response.packet[8..], b"runtime-icmp");
            assert_eq!(internet_checksum(&icmp_response.packet), 0);
            let reverse_icmp = server_dialer
                .exchange_icmp(
                    &icmpv4_echo_request(0x2719, 4),
                    IpAddr::V4(Ipv4Addr::new(10, 18, 0, 1)),
                    64,
                    &SocksAddr::new("10.18.0.2", 0),
                )
                .await
                .unwrap();
            assert_eq!(
                reverse_icmp.source,
                IpAddr::V4(Ipv4Addr::new(10, 18, 0, 2))
            );
            assert_eq!(&reverse_icmp.packet[4..8], b"\x27\x19\x00\x04");

            tcp_echo.await.unwrap();
            udp_echo.await.unwrap();
            client_runtime.close().await.unwrap();
            server_runtime.close().await.unwrap();
        }
    }

    fn static_data_session_options(
        key: Vec<u8>,
        network: &str,
        direction: i8,
    ) -> OpenVpnStaticDataSessionOptions {
        OpenVpnStaticDataSessionOptions {
            static_key_material: key,
            key_direction: direction,
            cipher: "AES-256-CBC".into(),
            auth: "SHA256".into(),
            replay_window_size: 64,
            replay_window_time: Duration::from_secs(15),
            framing: None,
            fragment: 0,
            mss_fix: 0,
            mss_fix_mode: String::new(),
            transport_network: network.into(),
            remote_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ping_interval: Duration::ZERO,
            ping_restart: Duration::ZERO,
        }
    }

    #[tokio::test]
    async fn openvpn_static_key_server_runtime_exchanges_tcp_and_udp_data() {
        for network_name in ["tcp", "udp"] {
            let key: Vec<u8> = (0..=u8::MAX).collect();
            let client_udp = if network_name == "udp" {
                Some(Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()))
            } else {
                None
            };
            let remote_port = match &client_udp {
                Some(socket) => socket.local_addr().unwrap().port(),
                None => 0,
            };
            let mut endpoint = serde_json::json!({
                "type": "openvpn-server",
                "tag": "ovpn-static",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "mode": "static_key",
                "network": network_name,
                "address": "10.9.0.1/24",
                "peer_address": "10.9.0.2",
                "static_key": hex::encode(&key),
                "key_direction": "server",
                "cipher": "AES-256-CBC",
                "auth": "SHA256"
            });
            if network_name == "udp" {
                endpoint["remote"] = serde_json::json!("127.0.0.1");
                endpoint["remote_port"] = serde_json::json!(remote_port);
            }
            let options: Options = serde_json::from_value(serde_json::json!({
                "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "endpoints": [endpoint]
            }))
            .unwrap();
            let mut runtime = Runtime::from_options(options).unwrap();
            let server_dialer =
                runtime.outbounds().outbound("ovpn-static").unwrap();
            runtime
                .start()
                .await
                .unwrap_or_else(|error| panic!("{network_name}: {error:?}"));
            let handle =
                runtime.openvpn_server_endpoint("ovpn-static").unwrap();
            let listen_address = handle.local_addr().unwrap();

            let transport: Arc<dyn OpenVpnPacketTransport> =
                if let Some(socket) = client_udp {
                    socket.connect(listen_address).await.unwrap();
                    Arc::new(OpenVpnDatagramTransport::new(socket, 65_535))
                } else {
                    let stream =
                        TcpStream::connect(listen_address).await.unwrap();
                    openvpn_stream_transport(Box::new(stream))
                };
            let client = Arc::new(
                OpenVpnStaticDataSession::new(
                    transport,
                    static_data_session_options(key, network_name, 1),
                )
                .unwrap(),
            );
            tokio::time::timeout(Duration::from_secs(2), async {
                while handle.active_clients() != 1
                    || handle.client_addresses()
                        != vec!["10.9.0.2".parse::<IpAddr>().unwrap()]
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();

            let peer_destination = SocksAddr::from(
                "10.9.0.2:32123".parse::<SocketAddr>().unwrap(),
            );
            let server_udp =
                server_dialer.listen_udp(&peer_destination).await.unwrap();
            let server_udp_address = server_udp.local_addr().unwrap().unwrap();
            let request = ipv4_udp_packet(
                Ipv4Addr::new(10, 9, 0, 2),
                Ipv4Addr::new(10, 9, 0, 1),
                32123,
                server_udp_address.port(),
                b"client-static",
            );
            client.write_data_packet(&request).await.unwrap();
            let mut payload = [0_u8; 64];
            let (length, source) = tokio::time::timeout(
                Duration::from_secs(2),
                server_udp.recv_from(&mut payload),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&payload[..length], b"client-static");
            assert_eq!(source, peer_destination);

            server_udp
                .send_to(b"server-static", &peer_destination)
                .await
                .unwrap();
            let response = tokio::time::timeout(
                Duration::from_secs(2),
                client.read_data_packet(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&response[response.len() - 13..], b"server-static");

            client.close();
            runtime.close().await.unwrap();
            assert_eq!(handle.active_clients(), 0);
        }
    }

    #[tokio::test]
    async fn openvpn_static_key_client_runtime_exchanges_tcp_and_udp_data() {
        for network_name in ["tcp", "udp"] {
            let key: Vec<u8> = (0..=u8::MAX).collect();
            let (server_address, server_task) = if network_name == "tcp" {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let options =
                    static_data_session_options(key.clone(), network_name, 0);
                let task = tokio::spawn(async move {
                    let (stream, _) = listener.accept().await.unwrap();
                    let session = OpenVpnStaticDataSession::new(
                        openvpn_stream_transport(Box::new(stream)),
                        options,
                    )
                    .unwrap();
                    let request = session.read_data_packet().await.unwrap();
                    let source_port =
                        u16::from_be_bytes(request[20..22].try_into().unwrap());
                    assert_eq!(&request[28..], b"client-static");
                    let response = ipv4_udp_packet(
                        Ipv4Addr::new(10, 10, 0, 1),
                        Ipv4Addr::new(10, 10, 0, 2),
                        32123,
                        source_port,
                        b"server-static",
                    );
                    session.write_data_packet(&response).await.unwrap();
                });
                (address, task)
            } else {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let address = socket.local_addr().unwrap();
                let server_key = key.clone();
                let task = tokio::spawn(async move {
                    let codec = StaticKeyDataCodec::new(
                        &server_key,
                        0,
                        "AES-256-CBC",
                        "SHA256",
                        64,
                        Duration::from_secs(15),
                    )
                    .unwrap();
                    let mut raw = vec![0_u8; 65_535];
                    let (length, remote) =
                        socket.recv_from(&mut raw).await.unwrap();
                    let (_, request) =
                        codec.decode(&[], &raw[..length]).unwrap();
                    let source_port =
                        u16::from_be_bytes(request[20..22].try_into().unwrap());
                    assert_eq!(&request[28..], b"client-static");
                    let response = ipv4_udp_packet(
                        Ipv4Addr::new(10, 10, 0, 1),
                        Ipv4Addr::new(10, 10, 0, 2),
                        32123,
                        source_port,
                        b"server-static",
                    );
                    let encoded = codec.encode(1, &[], &response).unwrap();
                    socket.send_to(&encoded, remote).await.unwrap();
                });
                (address, task)
            };
            let options: Options = serde_json::from_value(serde_json::json!({
                "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "endpoints": [{
                    "type": "openvpn-client",
                    "tag": "ovpn-static-client",
                    "server": server_address.ip().to_string(),
                    "server_port": server_address.port(),
                    "mode": "static_key",
                    "network": network_name,
                    "address": "10.10.0.2/24",
                    "peer_address": "10.10.0.1",
                    "static_key": hex::encode(&key),
                    "key_direction": "client",
                    "cipher": "AES-256-CBC",
                    "auth": "SHA256"
                }]
            }))
            .unwrap();
            let mut runtime = Runtime::from_options(options).unwrap();
            let client_dialer =
                runtime.outbounds().outbound("ovpn-static-client").unwrap();
            runtime.start().await.unwrap();
            let server_destination = SocksAddr::from(
                "10.10.0.1:32123".parse::<SocketAddr>().unwrap(),
            );
            let client_udp =
                client_dialer.listen_udp(&server_destination).await.unwrap();
            client_udp
                .send_to(b"client-static", &server_destination)
                .await
                .unwrap();
            let mut response = [0_u8; 64];
            let (length, source) = tokio::time::timeout(
                Duration::from_secs(2),
                client_udp.recv_from(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&response[..length], b"server-static");
            assert_eq!(source, server_destination);
            server_task.await.unwrap();
            runtime.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn ssm_api_updates_managed_users_and_tracks_tcp_udp() {
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let shadowsocks_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_destination = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
        });
        let udp_target =
            tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut buffer = [0_u8; 16];
            let (size, source) =
                udp_target.recv_from(&mut buffer).await.unwrap();
            udp_target.send_to(&buffer[..size], source).await.unwrap();
        });
        let options: Options = serde_json::from_value(serde_json::json!({
            "inbounds": [{
                "type": "shadowsocks",
                "tag": "managed",
                "listen": "127.0.0.1",
                "listen_port": shadowsocks_port,
                "method": "aes-128-gcm",
                "managed": true,
                "udp_timeout": "5s"
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
            "services": [{
                "type": "ssm-api",
                "tag": "manager",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "servers": {"/edge": "managed"}
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        let api = runtime.ssm_api_addr("manager").unwrap();
        let added = json_api_request(
            api,
            "POST",
            "/edge/server/v1/users",
            r#"{"username":"alice","uPSK":"alice-secret"}"#,
        )
        .await;
        assert!(added.starts_with("HTTP/1.1 201"), "{added}");

        let client = ShadowsocksOutbound::new(
            Arc::new(DirectOutbound::new(Default::default())),
            SocksAddr::new("127.0.0.1", shadowsocks_port),
            "aes-128-gcm",
            "alice-secret",
        )
        .unwrap();
        let mut stream = client
            .dial_tcp(&SocksAddr::from(tcp_destination))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        let packet = client
            .listen_udp(&SocksAddr::from(udp_destination))
            .await
            .unwrap();
        packet
            .send_to(b"dns", &SocksAddr::from(udp_destination))
            .await
            .unwrap();
        let mut udp_response = [0_u8; 16];
        let (size, source) = packet.recv_from(&mut udp_response).await.unwrap();
        assert_eq!(&udp_response[..size], b"dns");
        assert_eq!(source, SocksAddr::from(udp_destination));
        tcp_echo.await.unwrap();
        udp_echo.await.unwrap();

        let stats = api_request(
            api,
            "GET /edge/server/v1/stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(stats.starts_with("HTTP/1.1 200"), "{stats}");
        let body = stats.split("\r\n\r\n").nth(1).unwrap();
        let stats: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(stats["tcpSessions"], 1);
        assert_eq!(stats["udpSessions"], 1);
        assert_eq!(stats["uplinkBytes"], 7);
        assert_eq!(stats["downlinkBytes"], 7);
        assert_eq!(stats["users"][0]["username"], "alice");
        assert_eq!(stats["users"][0]["uplinkBytes"], 7);
        assert!(stats["users"][0].get("uPSK").is_none());

        let updated = json_api_request(
            api,
            "PUT",
            "/edge/server/v1/users/alice",
            r#"{"uPSK":"new-secret"}"#,
        )
        .await;
        assert!(updated.starts_with("HTTP/1.1 204"), "{updated}");
        let user = api_request(
            api,
            "GET /edge/server/v1/users/alice HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(user.contains(r#""uPSK":"new-secret""#));
        let deleted = api_request(
            api,
            "DELETE /edge/server/v1/users/alice HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(deleted.starts_with("HTTP/1.1 204"), "{deleted}");
        runtime.close().await.unwrap();
    }

    #[tokio::test]
    async fn ssm_api_manages_aead_2022_tcp_and_udp() {
        use base64::Engine as _;

        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let shadowsocks_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_destination = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut buffer = [0_u8; 5];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
        });
        let udp_target =
            tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut buffer = [0_u8; 16];
            let (size, source) =
                udp_target.recv_from(&mut buffer).await.unwrap();
            udp_target.send_to(&buffer[..size], source).await.unwrap();
        });
        let ipsk = base64::engine::general_purpose::STANDARD.encode([7_u8; 16]);
        let upsk = base64::engine::general_purpose::STANDARD.encode([9_u8; 16]);
        let options: Options = serde_json::from_value(serde_json::json!({
            "inbounds": [{
                "type": "shadowsocks",
                "tag": "managed-2022",
                "listen": "127.0.0.1",
                "listen_port": shadowsocks_port,
                "method": "2022-blake3-aes-128-gcm",
                "password": ipsk,
                "managed": true,
                "udp_timeout": "5s"
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
            "services": [{
                "type": "ssm-api",
                "tag": "manager",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "servers": {"/": "managed-2022"}
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        let api = runtime.ssm_api_addr("manager").unwrap();
        let body =
            serde_json::json!({"username":"bob", "uPSK":upsk}).to_string();
        let added =
            json_api_request(api, "POST", "/server/v1/users", &body).await;
        assert!(added.starts_with("HTTP/1.1 201"), "{added}");

        let client = ShadowsocksOutbound::new(
            Arc::new(DirectOutbound::new(Default::default())),
            SocksAddr::new("127.0.0.1", shadowsocks_port),
            "2022-blake3-aes-128-gcm",
            &format!("{ipsk}:{upsk}"),
        )
        .unwrap();
        let mut stream = client
            .dial_tcp(&SocksAddr::from(tcp_destination))
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut response = [0_u8; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"hello");
        let packet = client
            .listen_udp(&SocksAddr::from(udp_destination))
            .await
            .unwrap();
        packet
            .send_to(b"quic", &SocksAddr::from(udp_destination))
            .await
            .unwrap();
        let mut response = [0_u8; 16];
        let (size, source) = packet.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"quic");
        assert_eq!(source, SocksAddr::from(udp_destination));
        tcp_echo.await.unwrap();
        udp_echo.await.unwrap();

        let stats = api_request(
            api,
            "GET /server/v1/stats?clear=true HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let stats: serde_json::Value =
            serde_json::from_str(stats.split("\r\n\r\n").nth(1).unwrap())
                .unwrap();
        assert_eq!(stats["uplinkBytes"], 9);
        assert_eq!(stats["downlinkBytes"], 9);
        let cleared = api_request(
            api,
            "GET /server/v1/stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let cleared: serde_json::Value =
            serde_json::from_str(cleared.split("\r\n\r\n").nth(1).unwrap())
                .unwrap();
        assert_eq!(cleared["uplinkBytes"], 0);
        assert_eq!(cleared["tcpSessions"], 0);
        runtime.close().await.unwrap();
    }

    #[tokio::test]
    async fn ssm_api_cache_matches_upstream_shape_and_restores_users_stats() {
        let directory = tempfile::tempdir().unwrap();
        let cache_path = directory.path().join("ssm-cache.json");
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let shadowsocks_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let make_options = || -> Options {
            serde_json::from_value(serde_json::json!({
                "inbounds": [{
                    "type": "shadowsocks",
                    "tag": "managed",
                    "listen": "127.0.0.1",
                    "listen_port": shadowsocks_port,
                    "reuse_addr": true,
                    "network": "tcp",
                    "method": "chacha20-ietf-poly1305",
                    "managed": true
                }],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"final": "direct"},
                "services": [{
                    "type": "ssm-api",
                    "tag": "manager",
                    "listen": "127.0.0.1",
                    "listen_port": 0,
                    "servers": {"/edge": "managed"},
                    "cache_path": cache_path
                }]
            }))
            .unwrap()
        };

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut buffer = [0_u8; 3];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
        });
        let mut runtime = Runtime::from_options(make_options()).unwrap();
        runtime.start().await.unwrap();
        let api = runtime.ssm_api_addr("manager").unwrap();
        let added = json_api_request(
            api,
            "POST",
            "/edge/server/v1/users",
            r#"{"username":"cached","uPSK":"persistent-secret"}"#,
        )
        .await;
        assert!(added.starts_with("HTTP/1.1 201"), "{added}");
        let client = ShadowsocksOutbound::new(
            Arc::new(DirectOutbound::new(Default::default())),
            SocksAddr::new("127.0.0.1", shadowsocks_port),
            "chacha20-ietf-poly1305",
            "persistent-secret",
        )
        .unwrap();
        let mut stream = client
            .dial_tcp(&SocksAddr::from(destination))
            .await
            .unwrap();
        stream.write_all(b"one").await.unwrap();
        let mut response = [0_u8; 3];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"one");
        drop(stream);
        echo.await.unwrap();
        runtime.close().await.unwrap();

        let cache: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&cache_path).unwrap())
                .unwrap();
        assert_eq!(cache["endpoints"]["/edge"]["global_uplink"], 3);
        assert_eq!(cache["endpoints"]["/edge"]["user_uplink"]["cached"], 3);
        assert_eq!(
            cache["endpoints"]["/edge"]["users"]["cached"],
            "persistent-secret"
        );
        assert!(cache["endpoints"]["/edge"].get("traffic").is_none());

        let mut restarted = Runtime::from_options(make_options()).unwrap();
        restarted.start().await.unwrap();
        let api = restarted.ssm_api_addr("manager").unwrap();
        let user = api_request(
            api,
            "GET /edge/server/v1/users/cached HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(user.starts_with("HTTP/1.1 200"), "{user}");
        assert!(user.contains(r#""uPSK":"persistent-secret""#));
        assert!(user.contains(r#""uplinkBytes":3"#));
        restarted.close().await.unwrap();
    }

    fn dashboard_archive(contents: &str) -> Vec<u8> {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file(
                "dashboard/index.html",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        std::io::Write::write_all(&mut writer, contents.as_bytes()).unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[tokio::test]
    async fn remote_rule_set_downloads_through_configured_detour() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let mut buffer = [0_u8; 1024];
                let size = stream.read(&mut buffer).await.unwrap();
                if size == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..size]);
            }
            assert!(
                String::from_utf8(request)
                    .unwrap()
                    .starts_with("GET /rules.json HTTP/1.1\r\n")
            );
            let body =
                br#"{"version":5,"rules":[{"domain":"detour.example"}]}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(body).await.unwrap();
        });
        let options: Options = serde_json::from_value(serde_json::json!({
            "outbounds":[{"type":"direct","tag":"fetch"}],
            "route":{
                "rules":[{"rule_set":"remote","outbound":"fetch"}],
                "rule_set":[{
                    "type":"remote",
                    "tag":"remote",
                    "format":"source",
                    "url":format!("http://{address}/rules.json"),
                    "download_detour":"fetch",
                    "update_interval":"1h"
                }],
                "final":"fetch"
            }
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        server.await.unwrap();
        let decision = runtime.router().route(&Metadata {
            destination: Some(SocksAddr::new("detour.example", 443)),
            ..Metadata::default()
        });
        assert_eq!(decision.outbound(), Some("fetch"));
        runtime.close().await.unwrap();
    }

    #[tokio::test]
    async fn remote_rule_set_uses_named_http_client_headers_and_detour() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let mut buffer = [0_u8; 1024];
                let size = stream.read(&mut buffer).await.unwrap();
                if size == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..size]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /named.json HTTP/1.1\r\n"));
            assert!(request.contains("x-rule-client: named\r\n"));
            let body = br#"{"version":5,"rules":[{"domain":"named.example"}]}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(body).await.unwrap();
        });
        let options: Options = serde_json::from_value(serde_json::json!({
            "http_clients":[{
                "tag":"rules-http",
                "version":1,
                "headers":{"X-Rule-Client":"named"},
                "detour":"fetch"
            }],
            "outbounds":[{
                "type":"direct",
                "tag":"fetch",
                "connect_timeout":"5s"
            }],
            "route":{
                "rules":[{"rule_set":"remote","outbound":"fetch"}],
                "rule_set":[{
                    "type":"remote",
                    "tag":"remote",
                    "format":"source",
                    "url":format!("http://{address}/named.json"),
                    "http_client":"rules-http",
                    "update_interval":"1h"
                }],
                "final":"fetch"
            }
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        server.await.unwrap();
        assert_eq!(
            runtime
                .router()
                .route(&Metadata {
                    destination: Some(SocksAddr::new("named.example", 443)),
                    ..Metadata::default()
                })
                .outbound(),
            Some("fetch")
        );
        runtime.close().await.unwrap();
    }

    #[test]
    fn builds_supported_graph_and_uses_route_final() {
        let options: Options = serde_json::from_str(r#"{
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "inbounds":[{"type":"socks","tag":"local","listen":"127.0.0.1","listen_port":1080}],
            "outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"deny"}],
            "route":{"final":"deny"}
        }"#).unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        assert_eq!(runtime.outbounds().default_tag(), "deny");
    }

    #[tokio::test]
    async fn dns_rules_match_shared_route_rule_sets() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {
                "servers": [
                    {
                        "type":"hosts",
                        "tag":"fallback",
                        "predefined":{
                            "inside.example":"192.0.2.1",
                            "outside.example":"192.0.2.1"
                        }
                    },
                    {
                        "type":"hosts",
                        "tag":"selected",
                        "predefined":{"inside.example":"192.0.2.88"}
                    }
                ],
                "rules":[{"rule_set":"internal","server":"selected"}],
                "final":"fallback"
            },
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route": {
                "rule_set":[{
                    "type":"inline",
                    "tag":"internal",
                    "rules":[{"domain_suffix":"inside.example"}]
                }],
                "final":"direct"
            }
        }))
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        let resolver = runtime.outbounds().dns().default();
        assert_eq!(
            resolver
                .lookup(
                    "inside.example",
                    crate::option::DomainStrategy::Ipv4Only,
                )
                .await
                .unwrap(),
            ["192.0.2.88".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(
            resolver
                .lookup(
                    "outside.example",
                    crate::option::DomainStrategy::Ipv4Only,
                )
                .await
                .unwrap(),
            ["192.0.2.1".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn clash_mode_routes_and_dns_switch_and_persist() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let make_options = || -> Options {
            serde_json::from_value(serde_json::json!({
                "experimental": {
                    "cache_file": {"enabled": true, "path": path},
                    "clash_api": {"default_mode": "Global"}
                },
                "dns": {
                    "servers": [
                        {"type": "hosts", "tag": "hosts"},
                        {"type": "hosts", "tag": "dns-global", "predefined": {"example.com": "192.0.2.1"}},
                        {"type": "hosts", "tag": "dns-rule", "predefined": {"example.com": "192.0.2.2"}}
                    ],
                    "rules": [
                        {"clash_mode": "Global", "server": "dns-global"},
                        {"clash_mode": "Rule", "server": "dns-rule"}
                    ],
                    "final": "hosts"
                },
                "outbounds": [
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "deny"}
                ],
                "route": {
                    "rules": [
                        {"clash_mode": "Global", "outbound": "deny"},
                        {"clash_mode": "Rule", "outbound": "direct"}
                    ],
                    "final": "deny"
                }
            }))
            .unwrap()
        };
        let runtime = Runtime::from_options(make_options()).unwrap();
        assert_eq!(runtime.clash_mode().as_deref(), Some("Global"));
        assert_eq!(
            runtime.router().route(&Metadata::default()).outbound(),
            Some("deny")
        );
        assert_eq!(
            runtime
                .outbounds()
                .dns()
                .default()
                .lookup("example.com", crate::option::DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["192.0.2.1".parse::<std::net::IpAddr>().unwrap()]
        );
        assert!(runtime.set_clash_mode("rule"));
        assert_eq!(runtime.clash_mode().as_deref(), Some("Rule"));
        assert_eq!(
            runtime.router().route(&Metadata::default()).outbound(),
            Some("direct")
        );
        assert_eq!(
            runtime
                .outbounds()
                .dns()
                .default()
                .lookup("example.com", crate::option::DomainStrategy::Ipv4Only)
                .await
                .unwrap(),
            ["192.0.2.2".parse::<std::net::IpAddr>().unwrap()]
        );
        assert!(!runtime.set_clash_mode("missing"));
        drop(runtime);

        let restarted = Runtime::from_options(make_options()).unwrap();
        assert_eq!(restarted.clash_mode().as_deref(), Some("Rule"));
    }

    #[tokio::test]
    async fn clash_api_auth_config_and_mode_switch() {
        let ui = tempfile::tempdir().unwrap();
        std::fs::write(ui.path().join("index.html"), "clash dashboard")
            .unwrap();
        let options: Options = serde_json::from_value(serde_json::json!({
            "experimental": {"clash_api": {
                "external_controller": "127.0.0.1:0",
                "external_ui": ui.path(),
                "secret": "test-secret",
                "default_mode": "Global"
            }},
            "dns": {"servers": [{"type": "hosts", "tag": "hosts", "predefined": {"example.com": "192.0.2.9"}}]},
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "deny"},
                {"type": "selector", "tag": "choose", "outbounds": ["direct", "deny"], "default": "direct"}
            ],
            "route": {
                "rules": [
                    {"clash_mode": "Global", "outbound": "deny"},
                    {"clash_mode": "Rule", "outbound": "direct"}
                ],
                "final": "deny"
            }
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        let address = runtime.clash_api_addr().unwrap();

        let unauthorized = api_request(
            address,
            "GET /configs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(unauthorized.starts_with("HTTP/1.1 401"));

        let redirected = api_request(
            address,
            "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(redirected.starts_with("HTTP/1.1 307"));
        assert!(redirected.contains("location: /ui/"));
        let dashboard = api_request(
            address,
            "GET /ui/ HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(dashboard.starts_with("HTTP/1.1 200"));
        assert!(dashboard.ends_with("clash dashboard"));

        let mut log_stream = TcpStream::connect(address).await.unwrap();
        log_stream
            .write_all(b"GET /logs?level=info HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut log_stream = BufReader::new(log_stream);
        let mut headers = Vec::new();
        loop {
            let mut line = Vec::new();
            log_stream.read_until(b'\n', &mut line).await.unwrap();
            let done = line == b"\r\n";
            headers.extend(line);
            if done {
                break;
            }
        }
        assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

        let websocket_url =
            format!("ws://{address}/logs?level=info&token=test-secret");
        let (mut websocket, _) =
            tokio_tungstenite::connect_async(websocket_url)
                .await
                .unwrap();
        runtime.logger().info("observable api log").unwrap();
        let mut chunk = vec![0_u8; 512];
        let size = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            log_stream.read(&mut chunk),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            String::from_utf8_lossy(&chunk[..size])
                .contains("observable api log")
        );
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            websocket.next(),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert!(frame.to_text().unwrap().contains("observable api log"));
        websocket.close(None).await.unwrap();

        let (mut memory_socket, _) = tokio_tungstenite::connect_async(format!(
            "ws://{address}/memory?token=test-secret"
        ))
        .await
        .unwrap();
        let memory = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            memory_socket.next(),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                memory.to_text().unwrap()
            )
            .unwrap(),
            serde_json::json!({"inuse": 0, "oslimit": 0})
        );
        memory_socket.close(None).await.unwrap();

        let mut traffic_stream = TcpStream::connect(address).await.unwrap();
        traffic_stream
            .write_all(b"GET /traffic HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut traffic_stream = BufReader::new(traffic_stream);
        loop {
            let mut line = Vec::new();
            traffic_stream.read_until(b'\n', &mut line).await.unwrap();
            if line == b"\r\n" {
                break;
            }
        }
        let target =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let (release_echo, wait_echo) = tokio::sync::oneshot::channel();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
            let _ = wait_echo.await;
        });
        let mut proxied = runtime
            .outbounds()
            .outbound("direct")
            .unwrap()
            .dial_tcp(&SocksAddr::Ip(target_address))
            .await
            .unwrap();
        proxied.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        proxied.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        let mut chunk = vec![0_u8; 512];
        let size = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            traffic_stream.read(&mut chunk),
        )
        .await
        .unwrap()
        .unwrap();
        let traffic = String::from_utf8_lossy(&chunk[..size]);
        assert!(traffic.contains("\"up\":4"), "{traffic}");
        assert!(traffic.contains("\"down\":4"), "{traffic}");

        let connections = api_request(
            address,
            "GET /connections HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n",
        )
        .await;
        let connection_body = connections.split_once("\r\n\r\n").unwrap().1;
        let connection_data: serde_json::Value =
            serde_json::from_str(connection_body).unwrap();
        assert_eq!(connection_data["connections"][0]["upload"], 4);
        assert_eq!(connection_data["connections"][0]["download"], 4);
        assert!(connection_data["memory"].as_u64().unwrap() > 0);
        let connection_id =
            connection_data["connections"][0]["id"].as_str().unwrap();
        let (mut connection_socket, _) =
            tokio_tungstenite::connect_async(format!(
                "ws://{address}/connections?interval=100&token=test-secret"
            ))
            .await
            .unwrap();
        let snapshot = connection_socket.next().await.unwrap().unwrap();
        assert!(snapshot.to_text().unwrap().contains(connection_id));
        connection_socket.close(None).await.unwrap();
        let closed = api_request(
            address,
            &format!(
                "DELETE /connections/{connection_id} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(closed.starts_with("HTTP/1.1 204"));
        let error = proxied.read(&mut [0_u8; 1]).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        let _ = release_echo.send(());
        echo.await.unwrap();

        let latency_target =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let latency_address = latency_target.local_addr().unwrap();
        let latency_server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = latency_target.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut byte = [0_u8; 1];
                    stream.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                assert!(request.starts_with(b"HEAD /generate_204 HTTP/1.1"));
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                stream
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            }
        });
        let test_url =
            format!("HTTP%3A%2F%2F{}%2Fgenerate_204", latency_address);
        let delay = api_request(
            address,
            &format!(
                "GET /proxies/direct/delay?url={test_url}&timeout=1000 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(delay.starts_with("HTTP/1.1 200"), "{delay}");
        assert!(delay.contains("\"delay\":"), "{delay}");
        let group_delay = api_request(
            address,
            &format!(
                "GET /group/choose/delay?url={test_url}&timeout=1000 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(group_delay.starts_with("HTTP/1.1 200"), "{group_delay}");
        assert!(group_delay.contains("\"direct\":"), "{group_delay}");
        latency_server.await.unwrap();

        let direct_proxy = api_request(
            address,
            "GET /proxies/direct HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(direct_proxy.contains("\"history\":[{"), "{direct_proxy}");
        assert!(direct_proxy.contains("\"delay\":"), "{direct_proxy}");

        let authorized = api_request(
            address,
            "GET /configs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(authorized.starts_with("HTTP/1.1 200"));
        assert!(authorized.contains("\"mode\":\"Global\""));
        assert!(authorized.contains("\"mode-list\":[\"Rule\",\"Global\"]"));

        let proxies = api_request(
            address,
            "GET /proxies HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(proxies.starts_with("HTTP/1.1 200"));
        assert!(proxies.contains("\"choose\""));
        assert!(proxies.contains("\"type\":\"Selector\""));

        let rules = api_request(
            address,
            "GET /rules HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(rules.starts_with("HTTP/1.1 200"));
        assert!(rules.contains("\"payload\":\"clash_mode=Global\""));
        assert!(rules.contains("\"proxy\":\"route(deny)\""));

        let dns = api_request(
            address,
            "GET /dns/query?name=example.com&type=A HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(dns.starts_with("HTTP/1.1 200"));
        assert!(dns.contains("\"Status\":0"));
        assert!(dns.contains("\"data\":\"192.0.2.9\""));

        let select_body = r#"{"name":"deny"}"#;
        let selected = api_request(
            address,
            &format!(
                "PUT /proxies/choose HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{select_body}",
                select_body.len()
            ),
        )
        .await;
        assert!(selected.starts_with("HTTP/1.1 204"));
        assert_eq!(
            runtime.outbounds().selected_group("choose").as_deref(),
            Some("deny")
        );

        let body = r#"{"mode":"rule"}"#;
        let patched = api_request(
            address,
            &format!(
                "PATCH /configs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(patched.starts_with("HTTP/1.1 204"));
        assert_eq!(runtime.clash_mode().as_deref(), Some("Rule"));
        assert_eq!(
            runtime.router().route(&Metadata::default()).outbound(),
            Some("direct")
        );
        runtime.close().await.unwrap();
    }

    #[tokio::test]
    async fn clash_api_downloads_and_upgrades_external_ui() {
        let downloads =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let download_address = downloads.local_addr().unwrap();
        let archives = [
            dashboard_archive("dashboard v1"),
            dashboard_archive("dashboard v2"),
        ];
        let server = tokio::spawn(async move {
            for archive in archives {
                let (mut stream, _) = downloads.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut byte = [0_u8; 1];
                    stream.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                assert!(request.starts_with(b"GET /dashboard.zip HTTP/1.1"));
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            archive.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                stream.write_all(&archive).await.unwrap();
            }
        });
        let ui = tempfile::tempdir().unwrap();
        let options: Options = serde_json::from_value(serde_json::json!({
            "experimental": {"clash_api": {
                "external_controller": "127.0.0.1:0",
                "external_ui": ui.path(),
                "external_ui_download_url": format!(
                    "http://{download_address}/dashboard.zip"
                )
            }},
            "outbounds": [{"type":"direct","tag":"direct"}],
            "route": {"final":"direct"}
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        assert_eq!(
            std::fs::read_to_string(ui.path().join("index.html")).unwrap(),
            "dashboard v1"
        );
        let response = api_request(
            runtime.clash_api_addr().unwrap(),
            "POST /upgrade/ui HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("\"status\":\"ok\""));
        assert_eq!(
            std::fs::read_to_string(ui.path().join("index.html")).unwrap(),
            "dashboard v2"
        );
        server.await.unwrap();
        runtime.close().await.unwrap();
    }

    #[test]
    fn rejects_deprecated_clash_api_cache_fields() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "experimental": {"clash_api": {"store_mode": true}}
        }))
        .unwrap();
        let error = Runtime::from_options(options).err().unwrap();
        assert!(error.to_string().contains("deprecated in sing-box 1.8.0"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn recognizes_tun_and_reports_the_remaining_route_boundary() {
        let options: Options = serde_json::from_str(
            r#"{
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "inbounds":[{
                "type":"tun",
                "tag":"local",
                "address":"10.14.14.9/30",
                "auto_route":true,
                "dns_mode":"disabled",
                "stack":"gvisor"
            }]
        }"#,
        )
        .unwrap();
        let error = match Runtime::from_options(options) {
            Ok(_) => panic!("unported automatic route mutation was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("auto_route platform"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn builds_macos_auto_routed_gvisor_tun_without_opening_the_device() {
        let options: Options = serde_json::from_str(
            r#"{
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "inbounds":[{
                "type":"tun",
                "tag":"local",
                "address":"10.14.14.9/30",
                "auto_route":true,
                "dns_mode":"disabled",
                "stack":"gvisor"
            }]
        }"#,
        )
        .unwrap();
        Runtime::from_options(options).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn builds_the_zay_macos_tun_shape_without_opening_the_device() {
        let options: Options = serde_json::from_str(
            r#"{
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "route":{"rules":[{"port":53,"action":"hijack-dns"}]},
            "inbounds":[{
                "type":"tun",
                "tag":"tun-in",
                "address":[
                    "10.14.14.9/30",
                    "fdfe:dcba:9876::1/126"
                ],
                "auto_route":true,
                "strict_route":false,
                "stack":"system",
                "route_exclude_address":[
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "224.0.0.0/4",
                    "255.255.255.255/32"
                ]
            }]
        }"#,
        )
        .unwrap();
        Runtime::from_options(options).unwrap();
    }

    #[test]
    fn builds_externally_routed_gvisor_tun_without_opening_the_device() {
        let options: Options = serde_json::from_str(
            r#"{
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "inbounds":[{
                "type":"tun",
                "tag":"local",
                "address":["10.14.14.9/30","fdfe:dcba:9876::1/126"],
                "dns_mode":"disabled",
                "stack":"gvisor"
            }]
        }"#,
        )
        .unwrap();
        Runtime::from_options(options).unwrap();
    }

    #[test]
    fn reports_the_upstream_shadowsocksr_removal() {
        let options: Options = serde_json::from_str(
            r#"{
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "inbounds":[{"type":"shadowsocksr","tag":"removed"}]
            }"#,
        )
        .unwrap();
        let error = match Runtime::from_options(options) {
            Ok(_) => panic!("removed ShadowsocksR inbound was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "ShadowsocksR is deprecated and removed in sing-box 1.6.0"
        );
    }

    #[test]
    fn builds_shadowtls_v3_to_shadowsocks_inbound_detour() {
        let options: Options = serde_json::from_str(
            r#"{
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "inbounds":[
                    {
                        "type":"shadowtls","tag":"shadow",
                        "listen":"127.0.0.1","listen_port":10443,
                        "detour":"ss","version":3,
                        "users":[{"name":"alice","password":"secret"}],
                        "handshake":{"server":"127.0.0.1","server_port":443}
                    },
                    {
                        "type":"shadowsocks","tag":"ss",
                        "listen":"127.0.0.1","listen_port":0,
                        "method":"aes-128-gcm","password":"inner secret"
                    }
                ]
            }"#,
        )
        .unwrap();
        Runtime::from_options(options).unwrap();
    }

    #[test]
    fn builds_shadowtls_with_each_stream_protocol_detour() {
        let detours = [
            serde_json::json!({
                "type":"http", "tag":"inner", "listen_port":0
            }),
            serde_json::json!({
                "type":"mixed", "tag":"inner", "listen_port":0
            }),
            serde_json::json!({
                "type":"socks", "tag":"inner", "listen_port":0
            }),
            serde_json::json!({
                "type":"shadowsocks", "tag":"inner", "listen_port":0,
                "method":"aes-128-gcm", "password":"inner secret"
            }),
            serde_json::json!({
                "type":"vmess", "tag":"inner", "listen_port":0,
                "users":[{"name":"alice","uuid":"00112233-4455-6677-8899-aabbccddeeff"}]
            }),
            serde_json::json!({
                "type":"vless", "tag":"inner", "listen_port":0,
                "users":[{"name":"alice","uuid":"00112233-4455-6677-8899-aabbccddeeff"}]
            }),
            serde_json::json!({
                "type":"trojan", "tag":"inner", "listen_port":0,
                "users":[{"name":"alice","password":"inner secret"}]
            }),
            serde_json::json!({
                "type":"anytls", "tag":"inner", "listen_port":0,
                "users":[{"name":"alice","password":"inner secret"}]
            }),
            serde_json::json!({
                "type":"snell", "tag":"inner", "listen_port":0,
                "version":5, "psk":"inner secret"
            }),
        ];
        for detour in detours {
            let options: Options = serde_json::from_value(serde_json::json!({
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "inbounds":[
                    {
                        "type":"shadowtls", "tag":"shadow",
                        "listen":"127.0.0.1", "listen_port":10443,
                        "detour":"inner", "version":3,
                        "users":[{"name":"alice","password":"secret"}],
                        "handshake":{"server":"127.0.0.1","server_port":443}
                    },
                    detour
                ]
            }))
            .unwrap();
            Runtime::from_options(options).unwrap();
        }
    }

    #[test]
    fn defers_non_injectable_shadowtls_detour_error_to_data_plane() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "inbounds":[
                {
                    "type":"shadowtls", "tag":"shadow",
                    "listen":"127.0.0.1", "listen_port":10443,
                    "detour":"inner", "version":3,
                    "users":[{"name":"alice","password":"secret"}],
                    "handshake":{"server":"127.0.0.1","server_port":443}
                },
                {
                    "type":"direct", "tag":"inner", "listen_port":0,
                    "override_address":"127.0.0.1", "override_port":80
                }
            ]
        }))
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        let detour = runtime
            .outbounds()
            .inbound_tcp_detour("shadow")
            .expect("ShadowTLS detour must remain visible to the data plane");
        assert_eq!(detour.target, "inner");
        assert!(detour.target_exists);
        assert!(detour.injector.is_none());
    }

    #[test]
    fn builds_general_listener_detour_with_forward_reference() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "inbounds":[
                {
                    "type":"socks", "tag":"outer",
                    "listen":"127.0.0.1", "listen_port":0,
                    "detour":"inner"
                },
                {
                    "type":"http", "tag":"inner",
                    "listen":"127.0.0.1", "listen_port":0
                }
            ],
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route":{"final":"direct"}
        }))
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        let detour = runtime
            .outbounds()
            .inbound_tcp_detour("outer")
            .expect("general listener detour must be registered");
        assert_eq!(detour.target, "inner");
        assert!(detour.target_exists);
        assert!(detour.injector.is_some());
    }

    #[test]
    fn preserves_missing_general_listener_detour_for_runtime_error() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "inbounds":[{
                "type":"socks", "tag":"outer",
                "listen":"127.0.0.1", "listen_port":0,
                "detour":"missing"
            }]
        }))
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        let detour = runtime
            .outbounds()
            .inbound_tcp_detour("outer")
            .expect("missing detour must remain visible to the data plane");
        assert_eq!(detour.target, "missing");
        assert!(!detour.target_exists);
        assert!(detour.injector.is_none());
    }

    #[test]
    fn builds_snell_v5_inbound_and_v4_outbound_graph() {
        let options: Options = serde_json::from_str(
            r#"{
                "inbounds":[{
                    "type":"snell", "tag":"server",
                    "listen":"127.0.0.1", "listen_port":0,
                    "version":5, "psk":"secret"
                }],
                "outbounds":[{
                    "type":"snell", "tag":"client",
                    "server":"127.0.0.1", "server_port":8010,
                    "version":4, "psk":"secret"
                }],
                "route":{"final":"client"}
            }"#,
        )
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        assert_eq!(runtime.outbounds().default_tag(), "client");
    }

    #[test]
    fn builds_hysteria2_tcp_udp_runtime_graph() {
        let options: Options = serde_json::from_str(
            r#"{
                "inbounds":[{
                    "type":"hysteria2", "tag":"server",
                    "listen":"127.0.0.1", "listen_port":0,
                    "users":[{"name":"alice","password":"secret"}],
                    "obfs":{"type":"salamander","password":"cover"},
                    "idle_timeout":"30s","keep_alive_period":"10s",
                    "stream_receive_window":"4MB",
                    "connection_receive_window":"16MB",
                    "max_concurrent_streams":128,
                    "initial_packet_size":1400,
                    "masquerade":{"type":"string","status_code":404,"headers":{"x-cover":"yes"},"content":"not found"},
                    "tls":{"enabled":true,"certificate":"cert.pem","key":"key.pem"}
                }],
                "outbounds":[
                {"type":"direct","tag":"quic-underlay","connect_timeout":"5s"},{
                    "type":"hysteria2", "tag":"client",
                    "server":"127.0.0.1", "server_port":443,
                    "password":"secret", "network":["tcp","udp"],
                    "obfs":{"type":"salamander","password":"cover"},
                    "idle_timeout":"30s","keep_alive_period":"10s",
                    "stream_receive_window":"4MB",
                    "connection_receive_window":"16MB",
                    "max_concurrent_streams":128,
                    "initial_packet_size":1400,
                    "detour":"quic-underlay",
                    "tls":{"enabled":true,"insecure":true,"server_name":"localhost"}
                }],
                "route":{"final":"client"}
            }"#,
        )
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        assert_eq!(runtime.outbounds().default_tag(), "client");
    }

    #[test]
    fn builds_hysteria_tcp_udp_runtime_graph() {
        let options: Options = serde_json::from_str(
            r#"{
                "inbounds":[{
                    "type":"hysteria", "tag":"server",
                    "listen":"127.0.0.1", "listen_port":0,
                    "users":[{"name":"alice","auth_str":"secret"}],
                    "up":"20 Mbps", "down":"40 Mbps",
                    "obfs":"cover", "recv_window_client":4194304,
                    "recv_window_conn":16777216,
                    "disable_mtu_discovery":true,
                    "tls":{"enabled":true,"certificate":"cert.pem","key":"key.pem"}
                }],
                "outbounds":[
                {"type":"direct","tag":"quic-underlay","connect_timeout":"5s"},{
                    "type":"hysteria", "tag":"client",
                    "server":"127.0.0.1", "server_port":443,
                    "auth_str":"secret", "network":["tcp","udp"],
                    "up":"20 Mbps", "down":"40 Mbps",
                    "obfs":"cover", "recv_window":4194304,
                    "recv_window_conn":16777216,
                    "disable_mtu_discovery":true,
                    "detour":"quic-underlay",
                    "tls":{"enabled":true,"insecure":true,"server_name":"localhost"}
                }],
                "route":{"final":"client"}
            }"#,
        )
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        assert_eq!(runtime.outbounds().default_tag(), "client");
    }

    #[test]
    fn builds_tuic_tcp_udp_runtime_graph() {
        let options: Options = serde_json::from_str(
            r#"{
                "inbounds":[{
                    "type":"tuic", "tag":"server",
                    "listen":"127.0.0.1", "listen_port":0,
                    "users":[{
                        "name":"alice",
                        "uuid":"059032a9-7d40-4a96-9bb1-36823d848068",
                        "password":"secret"
                    }],
                    "congestion_control":"bbr",
                    "zero_rtt_handshake":true,
                    "auth_timeout":"3s", "heartbeat":"10s",
                    "tls":{"enabled":true,"certificate":"cert.pem","key":"key.pem"}
                }],
                "outbounds":[
                {"type":"direct","tag":"quic-underlay","connect_timeout":"5s"},{
                    "type":"tuic", "tag":"client",
                    "server":"127.0.0.1", "server_port":443,
                    "uuid":"059032a9-7d40-4a96-9bb1-36823d848068",
                    "password":"secret", "udp_relay_mode":"quic",
                    "network":["tcp","udp"], "heartbeat":"10s",
                    "zero_rtt_handshake":true,
                    "congestion_control":"bbr",
                    "detour":"quic-underlay",
                    "tls":{"enabled":true,"insecure":true,"server_name":"localhost"}
                }],
                "route":{"final":"client"}
            }"#,
        )
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        assert_eq!(runtime.outbounds().default_tag(), "client");
    }

    #[test]
    fn builds_naive_runtime_graph() {
        let options: Options = serde_json::from_str(
            r#"{
                "inbounds":[{
                    "type":"naive", "tag":"server",
                    "listen":"127.0.0.1", "listen_port":0,
                    "network":"tcp",
                    "users":[{"username":"alice","password":"secret"}]
                }],
                "outbounds":[{
                    "type":"naive", "tag":"client",
                    "server":"proxy.example", "server_port":443,
                    "username":"alice", "password":"secret",
                    "insecure_concurrency":3,
                    "stream_receive_window":"8MB",
                    "udp_over_tcp":{"enabled":true,"version":2},
                    "tls":{"enabled":true,"server_name":"proxy.example"}
                }],
                "route":{"final":"client"}
            }"#,
        )
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        assert_eq!(runtime.outbounds().default_tag(), "client");
    }

    #[test]
    fn rejects_naive_quic_insecure_concurrency_like_cronet() {
        let options: Options = serde_json::from_str(
            r#"{
                "outbounds":[{
                    "type":"naive", "tag":"client",
                    "server":"proxy.example", "server_port":443,
                    "insecure_concurrency":2,
                    "quic":true,
                    "tls":{"enabled":true,"server_name":"proxy.example"}
                }]
            }"#,
        )
        .unwrap();
        let error = match Runtime::from_options(options) {
            Ok(_) => panic!("Naive QUIC insecure concurrency was accepted"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("insecure concurrency is not supported with QUIC")
        );
    }

    #[test]
    fn builds_redirect_runtime_graph() {
        let options: Options = serde_json::from_str(
            r#"{
                "inbounds":[{
                    "type":"redirect", "tag":"redirect-in",
                    "listen":"127.0.0.1", "listen_port":7892
                }],
                "outbounds":[{"type":"direct","tag":"direct"}],
                "route":{"final":"direct"}
            }"#,
        )
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        assert_eq!(runtime.outbounds().default_tag(), "direct");
    }

    #[test]
    fn builds_tproxy_runtime_graph() {
        let options: Options = serde_json::from_str(
            r#"{
                "inbounds":[{
                    "type":"tproxy", "tag":"tproxy-in",
                    "listen":"127.0.0.1", "listen_port":7893,
                    "network":["tcp","udp"],
                    "udp_mapping":"address_dependent",
                    "udp_filtering":"address_and_port_dependent",
                    "udp_nat_max":1024
                }],
                "outbounds":[{"type":"direct","tag":"direct"}],
                "route":{"final":"direct"}
            }"#,
        )
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        assert_eq!(runtime.outbounds().default_tag(), "direct");
    }

    #[tokio::test]
    async fn builds_and_starts_hysteria_realm_service() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "services":[{
                "type":"hysteria-realm",
                "tag":"realm",
                "listen":"127.0.0.1",
                "listen_port":0,
                "users":[{"name":"alice","token":"secret","max_realms":1}]
            }]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        runtime.start().await.unwrap();
        assert!(runtime.hysteria_realm_addr("realm").is_some());
        runtime.close().await.unwrap();
    }

    #[tokio::test]
    async fn wires_shared_acme_provider_into_inbound_tls() {
        let directory = tempfile::tempdir().unwrap();
        let options: Options = serde_json::from_value(serde_json::json!({
            "certificate_providers": [{
                "type": "acme",
                "tag": "shared",
                "domain": "invalid.example"
            }],
            "inbounds": [{
                "type": "http",
                "tag": "server",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "tls": {
                    "enabled": true,
                    "certificate_provider": "shared"
                }
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap();
        let mut runtime =
            Runtime::from_options_in(options, directory.path()).unwrap();
        runtime.start().await.unwrap();
        runtime.close().await.unwrap();
    }

    #[test]
    fn wires_tailscale_certificate_provider_to_its_endpoint() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {
                "servers": [{"type": "hosts", "tag": "hosts"}],
                "final": "hosts"
            },
            "endpoints": [{
                "type": "tailscale",
                "tag": "tailnet",
                "state_directory": "tailscale-test-state"
            }],
            "certificate_providers": [{
                "type": "tailscale",
                "tag": "tailnet-cert",
                "endpoint": "tailnet"
            }],
            "inbounds": [{
                "type": "http",
                "tag": "server",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "tls": {
                    "enabled": true,
                    "certificate_provider": "tailnet-cert"
                }
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        assert!(runtime.tailscale_endpoint("tailnet").is_some());

        let missing: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {
                "servers": [{"type": "hosts", "tag": "hosts"}],
                "final": "hosts"
            },
            "certificate_providers": [{
                "type": "tailscale",
                "tag": "tailnet-cert",
                "endpoint": "missing"
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap();
        let error = Runtime::from_options(missing).err().unwrap().to_string();
        assert!(error.contains("endpoint not found: missing"));
    }

    #[tokio::test]
    async fn embedding_handle_controls_run_and_graceful_close() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        let handle = runtime.handle();
        let cancellation = handle.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            cancellation.cancel();
        });
        runtime.run_until_cancelled().await.unwrap();
        assert!(handle.is_cancelled());
        handle.cancelled().await;
    }

    #[test]
    fn cloudflared_is_assembled_as_an_embeddable_runtime_inbound() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {
                "servers": [{"type": "hosts", "tag": "hosts"}],
                "final": "hosts"
            },
            "inbounds": [{
                "type": "cloudflared",
                "tag": "tunnel",
                "token": "eyJhIjoiYWNjb3VudDEyMyIsInQiOiI1NTBlODQwMC1lMjlhLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJzIjoiYzJWamNtVjBMVE15TFdKNWRHVnpMV3h2Ym1jdGVIZz0iLCJlIjoiZmVkIn0=",
                "ha_connections": 2,
                "protocol": "quic",
                "datagram_version": "v3",
                "control_dialer": {"detour": "direct"},
                "tunnel_dialer": {"detour": "direct"}
            }],
            "outbounds": [{
                "type": "direct",
                "tag": "direct",
                "connect_timeout": "5s"
            }],
            "route": {"final": "direct"}
        }))
        .unwrap();
        let runtime = Runtime::from_options(options).unwrap();
        let handle = runtime.cloudflared_inbound("tunnel").unwrap();
        assert_eq!(handle.active_flows(), 0);
        assert!(handle.terminal_error().is_none());
        assert!(runtime.cloudflared_inbound("missing").is_none());
    }

    #[tokio::test]
    async fn exposes_configured_ntp_clock_as_library_handle() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {
                "servers": [{"type": "hosts", "tag": "hosts"}],
                "final": "hosts"
            },
            "ntp": {
                "enabled": true,
                "server": "127.0.0.1",
                "server_port": 9,
                "interval": "1h"
            }
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        assert!(runtime.ntp_clock().is_some());
        assert!(!runtime.ntp_clock().unwrap().is_synchronized());
        runtime.start().await.unwrap();
        runtime.close().await.unwrap();
    }

    #[tokio::test]
    async fn ntp_without_detour_does_not_use_route_final() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut request = [0_u8; 512];
            let Ok(Ok((size, peer))) = tokio::time::timeout(
                Duration::from_secs(3),
                server.recv_from(&mut request),
            )
            .await
            else {
                return false;
            };
            assert_eq!(size, 48);
            let mut response = [0_u8; 48];
            response[0] = (4 << 3) | 4;
            response[1] = 1;
            response[24..32].copy_from_slice(&request[40..48]);
            response[32..40].copy_from_slice(&request[40..48]);
            response[40..48].copy_from_slice(&request[40..48]);
            server.send_to(&response, peer).await.unwrap();
            true
        });
        let options: Options = serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "ntp": {
                "enabled": true,
                "server": "127.0.0.1",
                "server_port": address.port(),
                "interval": "1h"
            },
            "outbounds": [{"type": "block", "tag": "deny"}],
            "route": {"final": "deny"}
        }))
        .unwrap();
        let mut runtime = Runtime::from_options(options).unwrap();
        let clock = runtime.ntp_clock().unwrap();
        let mut status = clock.subscribe();
        runtime.start().await.unwrap();
        let synchronized =
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if status.borrow().synchronized {
                        return true;
                    }
                    if status.changed().await.is_err() {
                        return false;
                    }
                }
            })
            .await
            .unwrap_or(false);
        runtime.close().await.unwrap();
        assert!(
            server_task.await.unwrap(),
            "NTP query did not use direct UDP"
        );
        assert!(synchronized, "NTP clock did not synchronize");
    }

    #[test]
    fn ntp_system_clock_write_requires_privileged_host_integration() {
        let options: Options = serde_json::from_value(serde_json::json!({
            "ntp": {
                "enabled": true,
                "server": "127.0.0.1",
                "write_to_system": true
            }
        }))
        .unwrap();
        let error = match Runtime::from_options(options) {
            Ok(_) => panic!("write_to_system must require host integration"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("privileged host callback"));
    }

    #[test]
    fn ntp_system_clock_write_accepts_explicit_host_callback() {
        struct NoopClockWriter;

        impl crate::common::ntp::SystemClockWriter for NoopClockWriter {
            fn set_system_time(
                &self,
                _time: std::time::SystemTime,
            ) -> std::io::Result<()> {
                Ok(())
            }
        }

        let options: Options = serde_json::from_value(serde_json::json!({
            "dns": {
                "servers": [{"type": "hosts", "tag": "hosts"}],
                "final": "hosts"
            },
            "ntp": {
                "enabled": true,
                "server": "127.0.0.1",
                "write_to_system": true
            }
        }))
        .unwrap();
        let runtime = Runtime::from_options_with_system_clock_writer(
            options,
            Some(Arc::new(NoopClockWriter)),
        )
        .unwrap();
        assert!(runtime.ntp_clock().is_some());
    }

    #[test]
    fn detects_process_rules_recursively() {
        let rules = serde_json::json!([{
            "type": "logical",
            "mode": "and",
            "rules": [{"network": "tcp"}, {"process_path_regex": ["/Applications/.+"]}]
        }]);
        assert!(super::contains_process_rule(rules.as_array().unwrap()));
        assert!(super::contains_process_rule(&[serde_json::json!({
            "user_id": 501
        })]));
    }

    #[test]
    fn ignores_absent_or_empty_process_rules() {
        assert!(!super::contains_process_rule(&[serde_json::json!({
            "network": ["tcp", "udp"],
            "process_name": [],
            "user": null
        })]));
    }

    #[test]
    fn detects_neighbor_rules_and_local_neighbor_dns() {
        let rules = serde_json::json!([{
            "type": "logical",
            "mode": "or",
            "rules": [{"network": "udp"}, {"source_hostname": ["printer"]}]
        }]);
        assert!(super::contains_neighbor_rule(rules.as_array().unwrap()));
        assert!(!super::contains_neighbor_rule(&[serde_json::json!({
            "source_mac_address": [],
            "source_hostname": null
        })]));
        let dns: crate::option::DnsOptions =
            serde_json::from_value(serde_json::json!({
                "servers": [
                    {"type": "local", "tag": "lan", "neighbor_domain": ".lan"}
                ]
            }))
            .unwrap();
        assert!(super::has_local_neighbor_dns_server(&dns.servers));
    }
}
