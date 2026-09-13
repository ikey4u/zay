//! Transactional Windows TUN address, route, DNS, and strict-route
//! configuration.

use std::{
    ffi::c_void,
    io,
    net::IpAddr,
    os::windows::ffi::OsStrExt as _,
    path::Path,
    ptr::{null, null_mut},
};

use ipnet::IpNet;
use tokio::process::Command;
use windows_sys::{
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex,
                GetIpInterfaceEntry, MIB_IPINTERFACE_ROW, SetIpInterfaceEntry,
            },
            Ndis::NET_LUID_LH,
            WindowsFilteringPlatform::{
                FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB,
                FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
                FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT16,
                FWP_UINT32, FWP_VALUE0, FWP_VALUE0_0,
                FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_REMOTE_PORT,
                FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0,
                FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER0,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER0,
                FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0,
                FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0,
            },
        },
        Networking::WinSock::{AF_INET, AF_INET6, RouterDiscoveryDisabled},
        System::SystemInformation::OSVERSIONINFOW,
    },
    core::GUID,
};

use super::tun_route::TunRoutePlan;

// windows-sys 0.61 does not expose this well-known WFP condition key.
const FWPM_CONDITION_LOCAL_INTERFACE_INDEX: GUID =
    GUID::from_u128(0x667fd755_d695_434a_8af5_d3835a1259bc);

#[link(name = "dnsapi")]
unsafe extern "system" {
    // Undocumented but stable API used by pinned sing-tun as well.
    fn DnsFlushResolverCache() -> i32;
}

#[derive(Debug)]
pub struct WindowsTunLease {
    interface: String,
    gateways: Vec<IpAddr>,
    addresses: Vec<IpNet>,
    routes: Vec<IpNet>,
    wfp_session: Option<WfpSession>,
    flush_dns_cache: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WindowsTunPolicy<'a> {
    pub dns_servers: &'a [IpAddr],
    pub strict_route: bool,
    pub block_dns: bool,
    pub flush_dns_cache: bool,
    pub interface_options: Option<WindowsTunInterfaceOptions>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WindowsTunInterfaceOptions {
    pub mtu: u16,
    pub auto_route: bool,
}

impl WindowsTunLease {
    pub async fn install(
        interface: impl Into<String>,
        configured_addresses: &[IpNet],
        primary: Option<IpNet>,
        plan: &TunRoutePlan,
        policy: WindowsTunPolicy<'_>,
    ) -> io::Result<Self> {
        let strict_route_supported =
            policy.strict_route && windows_major_version()? >= 10;
        if policy.strict_route && !strict_route_supported {
            tracing::warn!(
                "strict routing is not supported on Windows versions below 10"
            );
        }
        let mut lease = Self {
            interface: interface.into(),
            gateways: configured_addresses
                .iter()
                .filter_map(|network| next_address(network.addr()))
                .collect(),
            addresses: Vec::new(),
            routes: Vec::new(),
            wfp_session: None,
            flush_dns_cache: policy.flush_dns_cache,
        };
        for address in configured_addresses
            .iter()
            .copied()
            .filter(|address| Some(*address) != primary)
        {
            if let Err(error) = lease.add_address(address).await {
                let _ = lease.close().await;
                return Err(error);
            }
            lease.addresses.push(address);
        }
        for route in plan.routes().iter().copied() {
            if let Err(error) = lease.add_route(route).await {
                let _ = lease.close().await;
                return Err(error);
            }
            lease.routes.push(route);
        }
        if let Err(error) = configure_dns(
            &lease.interface,
            configured_addresses,
            policy.dns_servers,
        )
        .await
        {
            let _ = lease.close().await;
            return Err(error);
        }
        if !configured_addresses.is_empty() {
            let _ = disable_dns_registration(&lease.interface).await;
        }
        if let Some(interface_options) = policy.interface_options
            && let Err(error) = configure_interface_options(
                &lease.interface,
                configured_addresses,
                interface_options,
            )
        {
            let _ = lease.close().await;
            return Err(error);
        }
        if policy.flush_dns_cache
            && let Err(error) = flush_resolver_cache()
        {
            let _ = lease.close().await;
            return Err(error);
        }
        if strict_route_supported {
            match WfpSession::install(
                &lease.interface,
                configured_addresses,
                policy.block_dns,
            ) {
                Ok(session) => lease.wfp_session = Some(session),
                Err(error) => {
                    let _ = lease.close().await;
                    return Err(error);
                }
            }
        }
        Ok(lease)
    }

    pub async fn close(mut self) -> io::Result<()> {
        let mut errors = Vec::new();
        while let Some(route) = self.routes.pop() {
            if let Err(error) = self.remove_route(route).await {
                errors.push(error.to_string());
            }
        }
        while let Some(address) = self.addresses.pop() {
            if let Err(error) = self.remove_address(address).await {
                errors.push(error.to_string());
            }
        }
        // Closing a dynamic WFP session atomically removes its sublayer and
        // every strict-route filter installed underneath it.
        self.wfp_session.take();
        if self.flush_dns_cache {
            // Upstream ignores cache-flush errors during shutdown so route and
            // address rollback remains the authoritative close result.
            let _ = flush_resolver_cache();
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }

    async fn add_address(&self, address: IpNet) -> io::Result<()> {
        run_netsh(address_command("add", &self.interface, address)).await
    }

    async fn remove_address(&self, address: IpNet) -> io::Result<()> {
        run_netsh(address_command("delete", &self.interface, address)).await
    }

    async fn add_route(&self, route: IpNet) -> io::Result<()> {
        run_netsh(route_command(
            "add",
            &self.interface,
            route,
            self.gateway(route.addr())?,
        ))
        .await
    }

    async fn remove_route(&self, route: IpNet) -> io::Result<()> {
        run_netsh(route_command(
            "delete",
            &self.interface,
            route,
            self.gateway(route.addr())?,
        ))
        .await
    }

    fn gateway(&self, address: IpAddr) -> io::Result<IpAddr> {
        self.gateways
            .iter()
            .copied()
            .find(|gateway| gateway.is_ipv4() == address.is_ipv4())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("missing TUN gateway for {address}"),
                )
            })
    }
}

async fn disable_dns_registration(interface: &str) -> io::Result<()> {
    run_netsh(vec![
        "interface".into(),
        "ipv6".into(),
        "set".into(),
        "dnsservers".into(),
        format!("name={interface}"),
        "register=none".into(),
    ])
    .await
}

fn configure_interface_options(
    interface: &str,
    configured_addresses: &[IpNet],
    options: WindowsTunInterfaceOptions,
) -> io::Result<()> {
    let luid = interface_luid(interface)?;
    if configured_addresses
        .iter()
        .any(|address| address.addr().is_ipv4())
    {
        configure_interface_family(luid, AF_INET, options, true)?;
    }
    if configured_addresses
        .iter()
        .any(|address| address.addr().is_ipv6())
    {
        configure_interface_family(luid, AF_INET6, options, false)?;
    }
    Ok(())
}

fn configure_interface_family(
    luid: NET_LUID_LH,
    family: u16,
    options: WindowsTunInterfaceOptions,
    forwarding: bool,
) -> io::Result<()> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceLuid: luid,
        ..Default::default()
    };
    // SAFETY: row selects an initialized interface LUID and address family;
    // GetIpInterfaceEntry fills the remaining fields in place.
    check_windows("GetIpInterfaceEntry", unsafe {
        GetIpInterfaceEntry(&mut row)
    })?;
    row.ForwardingEnabled = forwarding;
    row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    row.DadTransmits = 0;
    row.ManagedAddressConfigurationSupported = false;
    row.OtherStatefulConfigurationSupported = false;
    row.NlMtu = u32::from(options.mtu);
    if options.auto_route {
        row.UseAutomaticMetric = false;
        row.Metric = 0;
    }
    // SAFETY: row was populated by GetIpInterfaceEntry and only documented
    // mutable interface properties were changed.
    check_windows("SetIpInterfaceEntry", unsafe {
        SetIpInterfaceEntry(&mut row)
    })
}

#[derive(Debug)]
struct WfpSession {
    handle: usize,
}

impl WfpSession {
    fn install(
        interface: &str,
        configured_addresses: &[IpNet],
        block_dns: bool,
    ) -> io::Result<Self> {
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut handle: HANDLE = null_mut();
        // SAFETY: all pointers either reference initialized local structures
        // for the duration of the call or are documented optional nulls.
        let status = unsafe {
            FwpmEngineOpen0(null(), u32::MAX, null(), &session, &mut handle)
        };
        check_wfp("FwpmEngineOpen0", status)?;
        let lease = Self {
            handle: handle as usize,
        };
        lease.install_filters(interface, configured_addresses, block_dns)?;
        Ok(lease)
    }

    fn install_filters(
        &self,
        interface: &str,
        configured_addresses: &[IpNet],
        block_dns: bool,
    ) -> io::Result<()> {
        let sublayer_key = GUID::from_u128(uuid::Uuid::new_v4().as_u128());
        let mut name = wide("sing-tun")?;
        let mut description = wide("auto-route rules")?;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: sublayer_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: description.as_mut_ptr(),
            },
            weight: u16::MAX,
            ..Default::default()
        };
        // SAFETY: the dynamic engine handle is live and sublayer pointers
        // remain valid for the whole synchronous call.
        check_wfp("FwpmSubLayerAdd0", unsafe {
            FwpmSubLayerAdd0(self.raw_handle(), &sublayer, null_mut())
        })?;

        let process_app_id = CurrentAppId::get()?;
        let mut app_condition = condition_byte_blob(
            FWPM_CONDITION_ALE_APP_ID,
            process_app_id.as_ptr(),
        );
        self.add_filter(
            sublayer_key,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            "protect ipv4",
            FWP_ACTION_PERMIT,
            13,
            Some(&mut app_condition),
            FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
        )?;
        self.add_filter(
            sublayer_key,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "protect ipv6",
            FWP_ACTION_PERMIT,
            13,
            Some(&mut app_condition),
            FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
        )?;

        let has_ipv4 = configured_addresses
            .iter()
            .any(|address| address.addr().is_ipv4());
        let has_ipv6 = configured_addresses
            .iter()
            .any(|address| address.addr().is_ipv6());
        // Keep upstream's intentional behavior: IPv4 is not globally blocked
        // when the TUN only has IPv6, while IPv6 is blocked for IPv4-only TUNs.
        if !has_ipv6 {
            self.add_filter(
                sublayer_key,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                "block ipv6",
                FWP_ACTION_BLOCK,
                12,
                None,
                0,
            )?;
        }

        let interface_index = interface_index(interface)?;
        let mut interface_condition = condition_u32(
            FWPM_CONDITION_LOCAL_INTERFACE_INDEX,
            interface_index,
        );
        if has_ipv4 {
            self.add_filter(
                sublayer_key,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                "allow ipv4",
                FWP_ACTION_PERMIT,
                11,
                Some(&mut interface_condition),
                0,
            )?;
        }
        if has_ipv6 {
            self.add_filter(
                sublayer_key,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                "allow ipv6",
                FWP_ACTION_PERMIT,
                11,
                Some(&mut interface_condition),
                0,
            )?;
        }

        if block_dns {
            let mut dns_condition =
                condition_u16(FWPM_CONDITION_IP_REMOTE_PORT, 53);
            self.add_filter(
                sublayer_key,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                "block ipv4 dns",
                FWP_ACTION_BLOCK,
                10,
                Some(&mut dns_condition),
                0,
            )?;
            self.add_filter(
                sublayer_key,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                "block ipv6 dns",
                FWP_ACTION_BLOCK,
                10,
                Some(&mut dns_condition),
                0,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn add_filter(
        &self,
        sublayer_key: GUID,
        layer_key: GUID,
        description: &str,
        action: u32,
        weight: u8,
        condition: Option<&mut FWPM_FILTER_CONDITION0>,
        flags: u32,
    ) -> io::Result<()> {
        let mut name = wide("sing-tun")?;
        let mut description = wide(description)?;
        let (num_conditions, condition_ptr) = condition
            .map_or((0, null_mut()), |condition| (1, condition as *mut _));
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: description.as_mut_ptr(),
            },
            flags,
            layerKey: layer_key,
            subLayerKey: sublayer_key,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: weight },
            },
            numFilterConditions: num_conditions,
            filterCondition: condition_ptr,
            action: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0 {
                r#type: action,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut filter_id = 0;
        // SAFETY: the engine handle is live and all filter data referenced by
        // pointers remains valid until this synchronous call returns.
        check_wfp("FwpmFilterAdd0", unsafe {
            FwpmFilterAdd0(
                self.raw_handle(),
                &filter,
                null_mut(),
                &mut filter_id,
            )
        })
    }

    fn raw_handle(&self) -> HANDLE {
        self.handle as HANDLE
    }
}

impl Drop for WfpSession {
    fn drop(&mut self) {
        if self.handle != 0 {
            // SAFETY: this handle came from FwpmEngineOpen0 and is closed once.
            let _ = unsafe { FwpmEngineClose0(self.raw_handle()) };
            self.handle = 0;
        }
    }
}

#[derive(Debug)]
struct CurrentAppId(*mut FWP_BYTE_BLOB);

impl CurrentAppId {
    fn get() -> io::Result<Self> {
        let executable = std::env::current_exe()?;
        let executable = wide_path(&executable)?;
        let mut app_id = null_mut();
        // SAFETY: executable is NUL terminated and app_id is an initialized
        // output slot owned by the filtering platform on success.
        check_wfp("FwpmGetAppIdFromFileName0", unsafe {
            FwpmGetAppIdFromFileName0(executable.as_ptr(), &mut app_id)
        })?;
        Ok(Self(app_id))
    }

    fn as_ptr(&self) -> *mut FWP_BYTE_BLOB {
        self.0
    }
}

impl Drop for CurrentAppId {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut allocation = self.0.cast::<c_void>();
            // SAFETY: this is the allocation returned by
            // FwpmGetAppIdFromFileName0 and is freed exactly once.
            unsafe { FwpmFreeMemory0(&mut allocation) };
            self.0 = null_mut();
        }
    }
}

fn condition_byte_blob(
    field: GUID,
    value: *mut FWP_BYTE_BLOB,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: value },
        },
    }
}

fn condition_u32(field: GUID, value: u32) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint32: value },
        },
    }
}

fn condition_u16(field: GUID, value: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: value },
        },
    }
}

fn interface_index(interface: &str) -> io::Result<u32> {
    let luid = interface_luid(interface)?;
    let mut index = 0;
    // SAFETY: luid was initialized by the preceding successful API call and
    // index is a valid output slot.
    let status = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    check_windows("ConvertInterfaceLuidToIndex", status)?;
    Ok(index)
}

fn interface_luid(interface: &str) -> io::Result<NET_LUID_LH> {
    let interface = wide(interface)?;
    let mut luid = NET_LUID_LH::default();
    // SAFETY: interface is NUL terminated and luid is a valid output slot.
    let status =
        unsafe { ConvertInterfaceAliasToLuid(interface.as_ptr(), &mut luid) };
    check_windows("ConvertInterfaceAliasToLuid", status)?;
    Ok(luid)
}

fn windows_major_version() -> io::Result<u32> {
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: version has the documented size and is a valid output slot.
    let status = unsafe { RtlGetVersion(&mut version) };
    if status < 0 {
        Err(io::Error::other(format!(
            "RtlGetVersion failed with NTSTATUS {:#010x}",
            status as u32
        )))
    } else {
        Ok(version.dwMajorVersion)
    }
}

fn flush_resolver_cache() -> io::Result<()> {
    // SAFETY: DnsFlushResolverCache takes no arguments and owns no resources.
    if unsafe { DnsFlushResolverCache() } != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn check_windows(operation: &str, status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{operation} failed with Windows error {status:#010x}"
        )))
    }
}

fn check_wfp(operation: &str, status: u32) -> io::Result<()> {
    check_windows(operation, status)
}

fn wide(value: &str) -> io::Result<Vec<u16>> {
    if value.encode_utf16().any(|unit| unit == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows string contains an interior NUL",
        ));
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

fn wide_path(value: &Path) -> io::Result<Vec<u16>> {
    let mut encoded = value.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains an interior NUL",
        ));
    }
    encoded.push(0);
    Ok(encoded)
}

async fn configure_dns(
    interface: &str,
    configured_addresses: &[IpNet],
    dns_servers: &[IpAddr],
) -> io::Result<()> {
    for command in dns_commands(interface, configured_addresses, dns_servers) {
        run_netsh(command).await?;
    }
    Ok(())
}

fn dns_commands(
    interface: &str,
    configured_addresses: &[IpNet],
    dns_servers: &[IpAddr],
) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    for ipv6 in [false, true] {
        if !configured_addresses
            .iter()
            .any(|address| address.addr().is_ipv6() == ipv6)
        {
            continue;
        }
        commands.push(dns_flush_command(interface, ipv6));
        commands.extend(
            dns_servers
                .iter()
                .copied()
                .filter(|server| server.is_ipv6() == ipv6)
                .map(|server| dns_add_command(interface, server)),
        );
    }
    commands
}

fn dns_flush_command(interface: &str, ipv6: bool) -> Vec<String> {
    vec![
        "interface".into(),
        if ipv6 { "ipv6" } else { "ipv4" }.into(),
        "set".into(),
        "dnsservers".into(),
        format!("name={interface}"),
        "source=static".into(),
        "address=none".into(),
        "validate=no".into(),
    ]
}

fn dns_add_command(interface: &str, server: IpAddr) -> Vec<String> {
    vec![
        "interface".into(),
        if server.is_ipv6() { "ipv6" } else { "ipv4" }.into(),
        "add".into(),
        "dnsservers".into(),
        format!("name={interface}"),
        format!("address={server}"),
        "validate=no".into(),
    ]
}

fn address_command(
    action: &str,
    interface: &str,
    address: IpNet,
) -> Vec<String> {
    let mut arguments = vec![
        "interface".into(),
        if address.addr().is_ipv4() {
            "ipv4".into()
        } else {
            "ipv6".into()
        },
        action.into(),
        "address".into(),
        format!("interface={interface}"),
        format!("address={}", address.addr()),
    ];
    if action == "add" {
        if let IpNet::V4(network) = address {
            arguments.push(format!("mask={}", network.netmask()));
        }
        arguments.push("store=active".into());
        arguments.push("skipassource=true".into());
    }
    arguments
}

fn route_command(
    action: &str,
    interface: &str,
    route: IpNet,
    gateway: IpAddr,
) -> Vec<String> {
    let mut arguments = vec![
        "interface".into(),
        if route.addr().is_ipv4() {
            "ipv4".into()
        } else {
            "ipv6".into()
        },
        action.into(),
        "route".into(),
        format!("prefix={route}"),
        format!("interface={interface}"),
        format!("nexthop={gateway}"),
        "store=active".into(),
    ];
    if action == "add" {
        arguments.push("metric=0".into());
    }
    arguments
}

async fn run_netsh(arguments: Vec<String>) -> io::Result<()> {
    let output = Command::new("netsh").args(&arguments).output().await?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let detail = if detail.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    } else {
        detail
    };
    Err(io::Error::other(format!(
        "netsh {} failed with {}: {detail}",
        arguments.join(" "),
        output.status
    )))
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

#[cfg(test)]
mod tests {
    use super::{
        address_command, dns_add_command, dns_commands, dns_flush_command,
        route_command,
    };

    #[test]
    fn builds_ipv4_address_lifecycle_commands() {
        assert_eq!(
            address_command("add", "zay tun", "10.14.14.9/30".parse().unwrap()),
            [
                "interface",
                "ipv4",
                "add",
                "address",
                "interface=zay tun",
                "address=10.14.14.9",
                "mask=255.255.255.252",
                "store=active",
                "skipassource=true",
            ]
        );
        assert_eq!(
            address_command(
                "delete",
                "zay tun",
                "10.14.14.9/30".parse().unwrap()
            ),
            [
                "interface",
                "ipv4",
                "delete",
                "address",
                "interface=zay tun",
                "address=10.14.14.9",
            ]
        );
    }

    #[test]
    fn builds_ipv6_route_lifecycle_commands() {
        assert_eq!(
            route_command(
                "add",
                "zay tun",
                "2001:db8::/32".parse().unwrap(),
                "fdfe:dcba:9876::2".parse().unwrap(),
            ),
            [
                "interface",
                "ipv6",
                "add",
                "route",
                "prefix=2001:db8::/32",
                "interface=zay tun",
                "nexthop=fdfe:dcba:9876::2",
                "store=active",
                "metric=0",
            ]
        );
        assert_eq!(
            route_command(
                "delete",
                "zay tun",
                "2001:db8::/32".parse().unwrap(),
                "fdfe:dcba:9876::2".parse().unwrap(),
            ),
            [
                "interface",
                "ipv6",
                "delete",
                "route",
                "prefix=2001:db8::/32",
                "interface=zay tun",
                "nexthop=fdfe:dcba:9876::2",
                "store=active",
            ]
        );
    }

    #[test]
    fn builds_dns_configuration_commands() {
        assert_eq!(
            dns_flush_command("zay tun", true),
            [
                "interface",
                "ipv6",
                "set",
                "dnsservers",
                "name=zay tun",
                "source=static",
                "address=none",
                "validate=no",
            ]
        );
        assert_eq!(
            dns_add_command("zay tun", "fdfe:dcba:9876::2".parse().unwrap()),
            [
                "interface",
                "ipv6",
                "add",
                "dnsservers",
                "name=zay tun",
                "address=fdfe:dcba:9876::2",
                "validate=no",
            ]
        );

        let addresses = [
            "10.14.14.9/30".parse().unwrap(),
            "fdfe:dcba:9876::1/126".parse().unwrap(),
        ];
        let servers = ["fdfe:dcba:9876::2".parse().unwrap()];
        let commands = dns_commands("zay tun", &addresses, &servers);
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[0][1], "ipv4");
        assert_eq!(commands[0][2], "set");
        assert_eq!(commands[1][1], "ipv6");
        assert_eq!(commands[1][2], "set");
        assert_eq!(commands[2][1], "ipv6");
        assert_eq!(commands[2][2], "add");
        assert!(dns_commands("zay tun", &[], &servers).is_empty());
    }
}
