//! Strongly typed OpenVPN endpoint options matching `option/openvpn.go`.

use std::{collections::HashSet, net::SocketAddr};

use serde::{Deserialize, Serialize};

use super::{
    Addr, DialerOptions, Duration, Listable, ListenOptions, Prefix,
    ServerOptions, UdpNatBehavior, UdpTimeout, User,
};

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVpnEndpointOptions {
    #[serde(default)]
    pub system: bool,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mtu: u32,
    #[serde(default)]
    pub udp_mapping: UdpNatBehavior,
    #[serde(default)]
    pub udp_filtering: UdpNatBehavior,
    #[serde(default)]
    pub udp_nat_max: u32,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVpnClientEndpointOptions {
    #[serde(flatten)]
    pub dialer: DialerOptions,
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(flatten)]
    pub endpoint: OpenVpnEndpointOptions,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub servers: Vec<OpenVpnRemoteOptions>,
    #[serde(default)]
    pub remote_random: bool,
    #[serde(default)]
    pub address: Listable<Prefix>,
    #[serde(default)]
    pub peer_address: Option<Addr>,
    #[serde(default)]
    pub peer_address_ipv6: Option<Addr>,
    #[serde(default)]
    pub topology: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub auth_retry: String,
    #[serde(default)]
    pub static_challenge: String,
    #[serde(default)]
    pub static_challenge_echo: bool,
    #[serde(default)]
    pub static_key: Listable<String>,
    #[serde(default)]
    pub static_key_path: String,
    #[serde(default)]
    pub key_direction: String,
    #[serde(default)]
    pub tls: Option<OpenVpnOutboundTlsOptions>,
    #[serde(default)]
    pub cipher: String,
    #[serde(default)]
    pub data_ciphers: Listable<String>,
    #[serde(default)]
    pub data_ciphers_fallback: String,
    #[serde(default)]
    pub auth: String,
    #[serde(default)]
    pub mss_fix: u32,
    #[serde(default)]
    pub mss_fix_disabled: bool,
    #[serde(default)]
    pub mss_fix_mode: String,
    #[serde(default)]
    pub fragment: u32,
    #[serde(default)]
    pub replay_window: u32,
    #[serde(default)]
    pub replay_window_time: Duration,
    #[serde(default)]
    pub compression: String,
    #[serde(default)]
    pub compression_lzo: String,
    #[serde(default)]
    pub allow_compression: String,
    #[serde(default)]
    pub route_no_pull: bool,
    #[serde(default)]
    pub pull_filters: Vec<OpenVpnPullFilterOptions>,
    #[serde(default)]
    pub routes: Listable<Prefix>,
    #[serde(default)]
    pub route_gateway: Option<Addr>,
    #[serde(default)]
    pub route_metric: i32,
    #[serde(default)]
    pub redirect_gateway: bool,
    #[serde(default)]
    pub redirect_gateway_flags: Listable<String>,
    #[serde(default)]
    pub redirect_private: bool,
    #[serde(default)]
    pub block_ipv6: bool,
    #[serde(default)]
    pub ping_interval: Duration,
    #[serde(default)]
    pub ping_restart: Duration,
    #[serde(default)]
    pub ping_restart_disabled: bool,
    #[serde(default)]
    pub renegotiate_interval: Duration,
    #[serde(default)]
    pub renegotiate_disabled: bool,
    #[serde(default)]
    pub renegotiate_bytes: u64,
    #[serde(default)]
    pub renegotiate_packets: u64,
    #[serde(default)]
    pub tls_timeout: Duration,
    #[serde(default)]
    pub handshake_window: Duration,
    #[serde(default)]
    pub explicit_exit_notify: u32,
    #[serde(default)]
    pub udp_timeout: UdpTimeout,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVpnServerEndpointOptions {
    #[serde(flatten)]
    pub listen: ListenOptions,
    #[serde(flatten)]
    pub endpoint: OpenVpnEndpointOptions,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub remote: String,
    #[serde(default)]
    pub remote_port: u16,
    #[serde(default)]
    pub max_clients: i32,
    pub address: Listable<Prefix>,
    #[serde(default)]
    pub peer_address: Option<Addr>,
    #[serde(default)]
    pub peer_address_ipv6: Option<Addr>,
    #[serde(default)]
    pub topology: String,
    #[serde(default)]
    pub duplicate_cn: bool,
    #[serde(default)]
    pub users: Vec<User>,
    #[serde(default)]
    pub static_key: Listable<String>,
    #[serde(default)]
    pub static_key_path: String,
    #[serde(default)]
    pub key_direction: String,
    #[serde(default)]
    pub tls: Option<OpenVpnInboundTlsOptions>,
    #[serde(default)]
    pub cipher: String,
    #[serde(default)]
    pub data_ciphers: Listable<String>,
    #[serde(default)]
    pub data_ciphers_fallback: String,
    #[serde(default)]
    pub auth: String,
    #[serde(default)]
    pub mss_fix: u32,
    #[serde(default)]
    pub mss_fix_disabled: bool,
    #[serde(default)]
    pub mss_fix_mode: String,
    #[serde(default)]
    pub replay_window: u32,
    #[serde(default)]
    pub replay_window_time: Duration,
    #[serde(default)]
    pub push: Option<OpenVpnPushOptions>,
    #[serde(default)]
    pub ping_interval: Duration,
    #[serde(default)]
    pub ping_restart: Duration,
    #[serde(default)]
    pub renegotiate_interval: Duration,
    #[serde(default)]
    pub renegotiate_disabled: bool,
    #[serde(default)]
    pub renegotiate_bytes: u64,
    #[serde(default)]
    pub renegotiate_packets: u64,
    #[serde(default)]
    pub handshake_window: Duration,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVpnRemoteOptions {
    #[serde(flatten)]
    pub server: ServerOptions,
    #[serde(default)]
    pub network: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVpnPullFilterOptions {
    pub action: String,
    pub text: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVpnOutboundTlsOptions {
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub server_name_type: String,
    #[serde(default)]
    pub certificate: Listable<String>,
    #[serde(default)]
    pub certificate_path: String,
    #[serde(default)]
    pub client_certificate: Listable<String>,
    #[serde(default)]
    pub client_certificate_path: String,
    #[serde(default)]
    pub client_key: Listable<String>,
    #[serde(default)]
    pub client_key_path: String,
    #[serde(default)]
    pub peer_fingerprint: Listable<String>,
    #[serde(default)]
    pub crl_path: String,
    #[serde(default)]
    pub remote_certificate_ku: Listable<String>,
    #[serde(default)]
    pub remote_certificate_eku: String,
    #[serde(default)]
    pub remote_certificate_tls: String,
    #[serde(default)]
    pub certificate_profile: String,
    #[serde(default)]
    pub ns_certificate_type: String,
    #[serde(default)]
    pub version_min: String,
    #[serde(default)]
    pub version_max: String,
    #[serde(default)]
    pub cipher: String,
    #[serde(default)]
    pub groups: String,
    #[serde(default)]
    pub control_wrap: Option<OpenVpnControlWrapOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVpnInboundTlsOptions {
    #[serde(default)]
    pub certificate: Listable<String>,
    #[serde(default)]
    pub certificate_path: String,
    #[serde(default)]
    pub key: Listable<String>,
    #[serde(default)]
    pub key_path: String,
    #[serde(default)]
    pub client_certificate: Listable<String>,
    #[serde(default)]
    pub client_certificate_path: String,
    #[serde(default)]
    pub verify_client_certificate: String,
    #[serde(default)]
    pub client_name: String,
    #[serde(default)]
    pub client_name_type: String,
    #[serde(default)]
    pub peer_fingerprint: Listable<String>,
    #[serde(default)]
    pub crl_path: String,
    #[serde(default)]
    pub remote_certificate_ku: Listable<String>,
    #[serde(default)]
    pub remote_certificate_eku: String,
    #[serde(default)]
    pub remote_certificate_tls: String,
    #[serde(default)]
    pub certificate_profile: String,
    #[serde(default)]
    pub ns_certificate_type: String,
    #[serde(default)]
    pub version_min: String,
    #[serde(default)]
    pub version_max: String,
    #[serde(default)]
    pub cipher: String,
    #[serde(default)]
    pub groups: String,
    #[serde(default)]
    pub control_wrap: Option<OpenVpnInboundControlWrapOptions>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVpnControlWrapOptions {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub key: Listable<String>,
    #[serde(default)]
    pub key_path: String,
    #[serde(default)]
    pub direction: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVpnInboundControlWrapOptions {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub key: Listable<String>,
    #[serde(default)]
    pub key_path: String,
    #[serde(default)]
    pub direction: String,
    #[serde(default)]
    pub force_cookie: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVpnPushOptions {
    #[serde(default)]
    pub routes: Listable<Prefix>,
    #[serde(default)]
    pub dns: Listable<Addr>,
    #[serde(default)]
    pub dns_servers: Vec<OpenVpnPushDnsServerOptions>,
    #[serde(default)]
    pub search_domains: Listable<String>,
    #[serde(default)]
    pub dhcp_options: Listable<String>,
    #[serde(default)]
    pub redirect_gateway: bool,
    #[serde(default)]
    pub redirect_gateway_flags: Listable<String>,
    #[serde(default)]
    pub block_outside_dns: bool,
    #[serde(default)]
    pub ping_interval: Duration,
    #[serde(default)]
    pub ping_restart: Duration,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVpnPushDnsServerOptions {
    pub priority: i32,
    pub addresses: Listable<String>,
    #[serde(default)]
    pub resolve_domains: Listable<String>,
    #[serde(default)]
    pub dnssec: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub sni: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVpnDnsServerOptions {
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub accept_default_resolvers: bool,
    #[serde(default)]
    pub accept_search_domain: bool,
}

/// Configuration error produced while applying sing-box and sing-openvpn's
/// OpenVPN constructor-time validation rules.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct OpenVpnOptionsError(String);

impl OpenVpnOptionsError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl OpenVpnClientEndpointOptions {
    pub(crate) fn remote_is_domain(&self) -> bool {
        (!self.server.server.is_empty() && self.server.server_is_domain())
            || self
                .servers
                .iter()
                .any(|remote| remote.server.server_is_domain())
    }

    /// Validate and normalize the parts consumed before the OpenVPN client is
    /// started. This intentionally does not read certificate/key files: the Go
    /// implementation also defers file I/O until TLS setup.
    pub fn validate(&self) -> Result<(), OpenVpnOptionsError> {
        let mode = validate_mode(&self.mode)?;
        validate_client_remotes(self)?;
        validate_topology(&self.topology)?;
        validate_data_channel(
            self.mss_fix,
            self.mss_fix_disabled,
            &self.mss_fix_mode,
            self.replay_window,
            self.replay_window_time,
        )?;
        validate_data_names(
            &self.cipher,
            self.data_ciphers.as_slice(),
            &self.data_ciphers_fallback,
            &self.auth,
        )?;
        validate_client_tunnel(self, mode == "static_key")?;
        validate_duration("ping_interval", self.ping_interval, true)?;
        validate_duration("ping_restart", self.ping_restart, true)?;
        validate_duration(
            "renegotiate_interval",
            self.renegotiate_interval,
            false,
        )?;
        validate_duration("tls_timeout", self.tls_timeout, false)?;
        validate_duration("handshake_window", self.handshake_window, false)?;
        if self.renegotiate_disabled
            && self.renegotiate_interval != Duration::ZERO
        {
            return invalid(
                "`renegotiate_interval` conflicts with `renegotiate_disabled`",
            );
        }
        if self.ping_restart_disabled && self.ping_restart != Duration::ZERO {
            return invalid(
                "`ping_restart` conflicts with `ping_restart_disabled`",
            );
        }
        for (index, filter) in self.pull_filters.iter().enumerate() {
            if !matches!(filter.action.as_str(), "accept" | "ignore" | "reject")
            {
                return invalid(format!(
                    "pull_filters[{index}].action must be accept, ignore, or reject"
                ));
            }
            if filter.text.is_empty() {
                return invalid(format!(
                    "pull_filters[{index}].text must not be empty"
                ));
            }
        }
        if self.fragment > 0 && self.fragment < 68 {
            return invalid("`fragment` must be zero or at least 68");
        }
        if self.fragment > 0 && client_uses_tcp(self) {
            return invalid("`fragment` is not supported with a TCP remote");
        }
        validate_compression(
            &self.compression,
            &self.compression_lzo,
            &self.allow_compression,
        )?;

        if mode == "static_key" {
            if self.tls.is_some() {
                return invalid(
                    "`tls` options are not supported in `static_key` mode",
                );
            }
            if !self.username.is_empty()
                || !self.password.is_empty()
                || !matches!(self.auth_retry.as_str(), "" | "none")
                || !self.static_challenge.is_empty()
                || self.static_challenge_echo
            {
                return invalid(
                    "username/password authentication is not supported in `static_key` mode",
                );
            }
            if self.route_no_pull || !self.pull_filters.is_empty() {
                return invalid(
                    "pull options are not supported in `static_key` mode",
                );
            }
            if self.renegotiate_interval != Duration::ZERO
                || self.renegotiate_disabled
                || self.renegotiate_bytes != 0
                || self.renegotiate_packets != 0
                || self.tls_timeout != Duration::ZERO
                || self.handshake_window != Duration::ZERO
            {
                return invalid(
                    "TLS timing and renegotiation options are not supported in `static_key` mode",
                );
            }
            if !self.data_ciphers.as_slice().is_empty()
                || !self.data_ciphers_fallback.is_empty()
            {
                return invalid(
                    "`data_ciphers` and `data_ciphers_fallback` are not supported in `static_key` mode; use `cipher`",
                );
            }
            require_material(
                "static_key",
                &self.static_key,
                &self.static_key_path,
            )?;
            validate_key_direction(&self.key_direction)?;
            if self.cipher.is_empty() {
                return invalid("`cipher` is required in `static_key` mode");
            }
            if !is_static_cipher(&self.cipher) {
                return invalid(format!(
                    "cipher {:?} is not supported in `static_key` mode",
                    self.cipher
                ));
            }
        } else {
            let tls = self.tls.as_ref().ok_or_else(|| {
                OpenVpnOptionsError::new("missing `tls` options")
            })?;
            if material_is_set(&self.static_key, &self.static_key_path) {
                return invalid(
                    "`static_key` and `static_key_path` are only supported in `static_key` mode",
                );
            }
            if !self.key_direction.is_empty() {
                return invalid(
                    "`key_direction` is only supported in `static_key` mode; use `tls.control_wrap.direction` for `tls_auth`",
                );
            }
            if !self.cipher.is_empty() {
                return invalid(
                    "`cipher` is only supported in `static_key` mode; use `data_ciphers` or `data_ciphers_fallback` in TLS mode",
                );
            }
            validate_client_tls(tls)?;
        }
        Ok(())
    }

    pub fn normalized_mode(&self) -> &str {
        if self.mode.is_empty() {
            "tls"
        } else {
            &self.mode
        }
    }

    pub fn normalized_network(&self) -> &str {
        if self.network.is_empty() {
            "udp"
        } else {
            &self.network
        }
    }
}

impl OpenVpnServerEndpointOptions {
    pub fn validate(&self) -> Result<(), OpenVpnOptionsError> {
        let mode = validate_mode(&self.mode)?;
        if self.address.as_slice().is_empty() {
            return invalid("missing server address");
        }
        validate_server_addresses(self.address.as_slice())?;
        validate_topology(&self.topology)?;
        let network = if self.network.is_empty() {
            "udp"
        } else {
            &self.network
        };
        if !matches!(network, "tcp" | "udp") {
            return invalid(format!("unsupported network: {network}"));
        }
        if self.max_clients < 0 {
            return invalid("`max_clients` must not be negative");
        }
        if self.max_clients >= (1 << 24) - 1 {
            return invalid("`max_clients` must be less than 16777215");
        }
        if mode == "static_key" && self.max_clients > 1 {
            return invalid(
                "`max_clients` must not exceed 1 in `static_key` mode",
            );
        }
        validate_data_channel(
            self.mss_fix,
            self.mss_fix_disabled,
            &self.mss_fix_mode,
            self.replay_window,
            self.replay_window_time,
        )?;
        validate_data_names(
            &self.cipher,
            self.data_ciphers.as_slice(),
            &self.data_ciphers_fallback,
            &self.auth,
        )?;
        validate_duration("ping_interval", self.ping_interval, true)?;
        validate_duration("ping_restart", self.ping_restart, true)?;
        validate_duration(
            "renegotiate_interval",
            self.renegotiate_interval,
            false,
        )?;
        validate_duration("handshake_window", self.handshake_window, false)?;
        if self.renegotiate_disabled
            && self.renegotiate_interval != Duration::ZERO
        {
            return invalid(
                "`renegotiate_interval` conflicts with `renegotiate_disabled`",
            );
        }

        if mode == "static_key" {
            if self.tls.is_some() {
                return invalid(
                    "`tls` options are not supported in `static_key` mode",
                );
            }
            if !self.users.is_empty() || self.duplicate_cn {
                return invalid(
                    "user authentication is not supported in `static_key` mode",
                );
            }
            if self.push.is_some() {
                return invalid(
                    "push options are not supported in `static_key` mode",
                );
            }
            if self.renegotiate_interval != Duration::ZERO
                || self.renegotiate_disabled
                || self.renegotiate_bytes != 0
                || self.renegotiate_packets != 0
                || self.handshake_window != Duration::ZERO
            {
                return invalid(
                    "TLS timing and renegotiation options are not supported in `static_key` mode",
                );
            }
            if !self.data_ciphers.as_slice().is_empty()
                || !self.data_ciphers_fallback.is_empty()
            {
                return invalid(
                    "`data_ciphers` and `data_ciphers_fallback` are not supported in `static_key` mode; use `cipher`",
                );
            }
            require_material(
                "static_key",
                &self.static_key,
                &self.static_key_path,
            )?;
            validate_key_direction(&self.key_direction)?;
            if self.cipher.is_empty() || !is_static_cipher(&self.cipher) {
                return invalid(
                    "`cipher` is required and must support static-key mode",
                );
            }
            validate_static_server_tunnel(self, network)?;
        } else {
            if material_is_set(&self.static_key, &self.static_key_path)
                || !self.key_direction.is_empty()
                || !self.cipher.is_empty()
                || !self.remote.is_empty()
                || self.remote_port != 0
                || self.peer_address.is_some()
                || self.peer_address_ipv6.is_some()
            {
                return invalid(
                    "static-key server options require `mode: static_key`",
                );
            }
            let tls = self.tls.as_ref().ok_or_else(|| {
                OpenVpnOptionsError::new("missing `tls` options")
            })?;
            validate_server_tls(tls)?;
            if let Some(push) = &self.push {
                validate_push(push)?;
            }
        }
        Ok(())
    }

    pub fn normalized_mode(&self) -> &str {
        if self.mode.is_empty() {
            "tls"
        } else {
            &self.mode
        }
    }

    pub fn normalized_network(&self) -> &str {
        if self.network.is_empty() {
            "udp"
        } else {
            &self.network
        }
    }

    pub fn normalized_topology(&self) -> &str {
        if self.topology.is_empty() {
            if self.normalized_mode() == "static_key" {
                "p2p"
            } else {
                "subnet"
            }
        } else {
            &self.topology
        }
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, OpenVpnOptionsError> {
    Err(OpenVpnOptionsError::new(message))
}

fn validate_mode(mode: &str) -> Result<&str, OpenVpnOptionsError> {
    let mode = if mode.is_empty() { "tls" } else { mode };
    if matches!(mode, "tls" | "static_key") {
        Ok(mode)
    } else {
        invalid(format!(
            "unsupported mode: {mode} (expected \"tls\" or \"static_key\")"
        ))
    }
}

fn validate_client_remotes(
    options: &OpenVpnClientEndpointOptions,
) -> Result<(), OpenVpnOptionsError> {
    if !options.server.server.is_empty() && !options.servers.is_empty() {
        return invalid("`server` conflicts with `servers`");
    }
    if options.server.server.is_empty() && options.servers.is_empty() {
        return invalid("missing `server` or `servers`");
    }
    validate_client_network(options.normalized_network())?;
    if !options.server.server.is_empty() {
        validate_remote(&options.server.server, options.server.server_port, 0)?;
    }
    for (index, remote) in options.servers.iter().enumerate() {
        validate_remote(
            &remote.server.server,
            remote.server.server_port,
            index,
        )?;
        let network = if remote.network.is_empty() {
            options.normalized_network()
        } else {
            &remote.network
        };
        validate_client_network(network)?;
    }
    Ok(())
}

fn validate_remote(
    host: &str,
    port: u16,
    index: usize,
) -> Result<(), OpenVpnOptionsError> {
    if host.is_empty()
        || host.chars().any(char::is_whitespace)
        || host.starts_with('[')
        || host.ends_with(']')
    {
        return invalid(format!("invalid remote host at index {index}"));
    }
    if port == 0 {
        return invalid(format!("empty remote port at index {index}"));
    }
    Ok(())
}

fn validate_client_network(network: &str) -> Result<(), OpenVpnOptionsError> {
    if matches!(network, "udp" | "udp4" | "udp6" | "tcp" | "tcp4" | "tcp6") {
        Ok(())
    } else {
        invalid(format!("unsupported network: {network}"))
    }
}

fn client_uses_tcp(options: &OpenVpnClientEndpointOptions) -> bool {
    if !options.server.server.is_empty() {
        return options.normalized_network().starts_with("tcp");
    }
    options.servers.iter().any(|remote| {
        let network = if remote.network.is_empty() {
            options.normalized_network()
        } else {
            &remote.network
        };
        network.starts_with("tcp")
    })
}

fn validate_topology(topology: &str) -> Result<(), OpenVpnOptionsError> {
    if matches!(topology, "" | "net30" | "p2p" | "subnet") {
        Ok(())
    } else {
        invalid(format!("invalid topology {topology}"))
    }
}

fn validate_client_tunnel(
    options: &OpenVpnClientEndpointOptions,
    require_peer: bool,
) -> Result<(), OpenVpnOptionsError> {
    if options
        .peer_address
        .is_some_and(|address| !address.0.is_ipv4())
    {
        return invalid("`peer_address` must be an IPv4 address");
    }
    if options
        .peer_address_ipv6
        .is_some_and(|address| !address.0.is_ipv6())
    {
        return invalid("`peer_address_ipv6` must be an IPv6 address");
    }
    if !matches!(
        options.auth_retry.as_str(),
        "" | "none" | "nointeract" | "interact"
    ) {
        return invalid("`auth_retry` must be none, nointeract, or interact");
    }
    if !require_peer {
        return Ok(());
    }
    let has_v4 = options
        .address
        .as_slice()
        .iter()
        .any(|prefix| prefix.0.addr().is_ipv4());
    let has_v6 = options
        .address
        .as_slice()
        .iter()
        .any(|prefix| prefix.0.addr().is_ipv6());
    if !has_v4 && !has_v6 {
        return invalid("missing `address` in `static_key` mode");
    }
    validate_peer_families(
        has_v4,
        has_v6,
        options.peer_address,
        options.peer_address_ipv6,
    )
}

fn validate_server_addresses(
    addresses: &[Prefix],
) -> Result<(), OpenVpnOptionsError> {
    let mut v4 = 0;
    let mut v6 = 0;
    for prefix in addresses {
        if prefix.0.addr().is_ipv4() {
            v4 += 1;
        } else {
            v6 += 1;
        }
    }
    if v4 > 1 {
        return invalid("multiple IPv4 server address pools are not supported");
    }
    if v6 > 1 {
        return invalid("multiple IPv6 server address pools are not supported");
    }
    Ok(())
}

fn validate_static_server_tunnel(
    options: &OpenVpnServerEndpointOptions,
    network: &str,
) -> Result<(), OpenVpnOptionsError> {
    let has_v4 = options
        .address
        .as_slice()
        .iter()
        .any(|prefix| prefix.0.addr().is_ipv4());
    let has_v6 = options
        .address
        .as_slice()
        .iter()
        .any(|prefix| prefix.0.addr().is_ipv6());
    validate_peer_families(
        has_v4,
        has_v6,
        options.peer_address,
        options.peer_address_ipv6,
    )?;
    if network == "udp" {
        if options.remote.is_empty() || options.remote_port == 0 {
            return invalid(
                "`remote` and `remote_port` are required for a UDP static-key server",
            );
        }
    } else if !options.remote.is_empty() || options.remote_port != 0 {
        return invalid(
            "`remote` and `remote_port` are only used by a UDP static-key server",
        );
    }
    Ok(())
}

fn validate_peer_families(
    has_v4: bool,
    has_v6: bool,
    peer_v4: Option<Addr>,
    peer_v6: Option<Addr>,
) -> Result<(), OpenVpnOptionsError> {
    if has_v4 && peer_v4.is_none() {
        return invalid(
            "missing `peer_address` for the IPv4 static-key tunnel",
        );
    }
    if has_v6 && peer_v6.is_none() {
        return invalid(
            "missing `peer_address_ipv6` for the IPv6 static-key tunnel",
        );
    }
    if peer_v4.is_some() && !has_v4 {
        return invalid(
            "`peer_address` requires an IPv4 tunnel `address` in `static_key` mode",
        );
    }
    if peer_v6.is_some() && !has_v6 {
        return invalid(
            "`peer_address_ipv6` requires an IPv6 tunnel `address` in `static_key` mode",
        );
    }
    Ok(())
}

fn validate_data_channel(
    mss_fix: u32,
    mss_fix_disabled: bool,
    mss_fix_mode: &str,
    replay_window: u32,
    replay_window_time: Duration,
) -> Result<(), OpenVpnOptionsError> {
    if mss_fix > 0 && mss_fix_disabled {
        return invalid("`mss_fix` conflicts with `mss_fix_disabled`");
    }
    if mss_fix_disabled && !mss_fix_mode.is_empty() {
        return invalid("`mss_fix_mode` conflicts with `mss_fix_disabled`");
    }
    if mss_fix == 0 && !mss_fix_mode.is_empty() {
        return invalid("`mss_fix_mode` requires `mss_fix`");
    }
    if !matches!(mss_fix_mode, "" | "mtu" | "fixed") {
        return invalid("`mss_fix_mode` must be mtu or fixed");
    }
    if replay_window > 65_536 {
        return invalid("`replay_window` must not exceed 65536");
    }
    let nanos = replay_window_time.as_nanos();
    if !(0..=600_000_000_000).contains(&nanos) {
        return invalid("`replay_window_time` must be between 0s and 10m");
    }
    if nanos % 1_000_000_000 != 0 {
        return invalid("`replay_window_time` must use whole seconds");
    }
    Ok(())
}

fn validate_duration(
    name: &str,
    value: Duration,
    whole_seconds: bool,
) -> Result<(), OpenVpnOptionsError> {
    let nanos = value.as_nanos();
    if nanos < 0 {
        return invalid(format!("`{name}` must not be negative"));
    }
    if nanos > 0 && nanos < 1_000_000_000 {
        return invalid(format!("`{name}` must be zero or at least 1s"));
    }
    if whole_seconds && nanos % 1_000_000_000 != 0 {
        return invalid(format!("`{name}` must use whole seconds"));
    }
    Ok(())
}

fn validate_data_names(
    cipher: &str,
    ciphers: &[String],
    fallback: &str,
    auth: &str,
) -> Result<(), OpenVpnOptionsError> {
    validate_cipher(cipher)?;
    for (index, cipher) in ciphers.iter().enumerate() {
        if cipher.is_empty() {
            return invalid(format!("data_ciphers[{index}] must not be empty"));
        }
        validate_cipher(cipher)?;
    }
    validate_cipher(fallback)?;
    if !matches!(
        auth,
        "" | "SHA1"
            | "SHA224"
            | "SHA256"
            | "SHA384"
            | "SHA512"
            | "RIPEMD160"
            | "MD5"
            | "NONE"
    ) {
        return invalid("`auth` must use a canonical OpenVPN digest name");
    }
    Ok(())
}

fn validate_cipher(cipher: &str) -> Result<(), OpenVpnOptionsError> {
    if cipher.is_empty() || is_canonical_cipher(cipher) {
        Ok(())
    } else {
        invalid(format!(
            "cipher {cipher:?} must use a canonical OpenVPN cipher name"
        ))
    }
}

fn is_canonical_cipher(cipher: &str) -> bool {
    if matches!(
        cipher,
        "BF-CBC"
            | "DES-CBC"
            | "DES-EDE-CBC"
            | "DES-EDE3-CBC"
            | "CAST5-CBC"
            | "AES-128-CBC"
            | "AES-192-CBC"
            | "AES-256-CBC"
            | "ARIA-128-CBC"
            | "ARIA-192-CBC"
            | "ARIA-256-CBC"
            | "CAMELLIA-128-CBC"
            | "CAMELLIA-192-CBC"
            | "CAMELLIA-256-CBC"
            | "SEED-CBC"
            | "SM4-CBC"
            | "AES-128-GCM"
            | "AES-192-GCM"
            | "AES-256-GCM"
            | "CHACHA20-POLY1305"
            | "NONE"
    ) {
        return true;
    }
    let base = cipher
        .strip_suffix("-CFB")
        .or_else(|| cipher.strip_suffix("-OFB"));
    base.is_some_and(|base| {
        matches!(
            base,
            "BF" | "DES"
                | "DES-EDE"
                | "DES-EDE3"
                | "CAST5"
                | "AES-128"
                | "AES-192"
                | "AES-256"
                | "ARIA-128"
                | "ARIA-192"
                | "ARIA-256"
                | "CAMELLIA-128"
                | "CAMELLIA-192"
                | "CAMELLIA-256"
                | "SEED"
                | "SM4"
        )
    })
}

fn is_static_cipher(cipher: &str) -> bool {
    matches!(
        cipher,
        "BF-CBC"
            | "DES-CBC"
            | "DES-EDE-CBC"
            | "DES-EDE3-CBC"
            | "CAST5-CBC"
            | "AES-128-CBC"
            | "AES-192-CBC"
            | "AES-256-CBC"
            | "ARIA-128-CBC"
            | "ARIA-192-CBC"
            | "ARIA-256-CBC"
            | "CAMELLIA-128-CBC"
            | "CAMELLIA-192-CBC"
            | "CAMELLIA-256-CBC"
            | "SEED-CBC"
            | "SM4-CBC"
            | "NONE"
    )
}

fn material_is_set(values: &Listable<String>, path: &str) -> bool {
    !values.as_slice().is_empty() || !path.is_empty()
}

fn validate_material(
    name: &str,
    values: &Listable<String>,
    path: &str,
) -> Result<(), OpenVpnOptionsError> {
    if !values.as_slice().is_empty() && !path.is_empty() {
        invalid(format!("`{name}` content conflicts with `{name}_path`"))
    } else {
        Ok(())
    }
}

fn require_material(
    name: &str,
    values: &Listable<String>,
    path: &str,
) -> Result<(), OpenVpnOptionsError> {
    validate_material(name, values, path)?;
    if material_is_set(values, path) {
        Ok(())
    } else {
        invalid(format!("missing `{name}` or `{name}_path`"))
    }
}

fn validate_key_direction(direction: &str) -> Result<i8, OpenVpnOptionsError> {
    match direction {
        "" => Ok(-1),
        "server" => Ok(0),
        "client" => Ok(1),
        _ => invalid(format!("unsupported key direction: {direction}")),
    }
}

fn validate_client_tls(
    tls: &OpenVpnOutboundTlsOptions,
) -> Result<(), OpenVpnOptionsError> {
    validate_material(
        "tls.certificate",
        &tls.certificate,
        &tls.certificate_path,
    )?;
    validate_material(
        "tls.client_certificate",
        &tls.client_certificate,
        &tls.client_certificate_path,
    )?;
    validate_material("tls.client_key", &tls.client_key, &tls.client_key_path)?;
    if material_is_set(&tls.client_certificate, &tls.client_certificate_path)
        != material_is_set(&tls.client_key, &tls.client_key_path)
    {
        return invalid(
            "client certificate and key must both be set or both omitted",
        );
    }
    validate_tls_common(
        &tls.server_name_type,
        tls.peer_fingerprint.as_slice(),
        tls.remote_certificate_ku.as_slice(),
        &tls.remote_certificate_eku,
        &tls.remote_certificate_tls,
        &tls.ns_certificate_type,
        &tls.version_min,
        &tls.version_max,
        &tls.certificate_profile,
        &tls.cipher,
        &tls.groups,
    )?;
    if let Some(wrap) = &tls.control_wrap {
        validate_control_wrap(
            &wrap.kind,
            &wrap.key,
            &wrap.key_path,
            &wrap.direction,
            false,
        )?;
    }
    Ok(())
}

fn validate_server_tls(
    tls: &OpenVpnInboundTlsOptions,
) -> Result<(), OpenVpnOptionsError> {
    require_material(
        "tls.certificate",
        &tls.certificate,
        &tls.certificate_path,
    )?;
    require_material("tls.key", &tls.key, &tls.key_path)?;
    validate_material(
        "tls.client_certificate",
        &tls.client_certificate,
        &tls.client_certificate_path,
    )?;
    if !matches!(
        tls.verify_client_certificate.as_str(),
        "" | "require" | "optional" | "none"
    ) {
        return invalid(
            "`tls.verify_client_certificate` must be require, optional, or none",
        );
    }
    validate_tls_common(
        &tls.client_name_type,
        tls.peer_fingerprint.as_slice(),
        tls.remote_certificate_ku.as_slice(),
        &tls.remote_certificate_eku,
        &tls.remote_certificate_tls,
        &tls.ns_certificate_type,
        &tls.version_min,
        &tls.version_max,
        &tls.certificate_profile,
        &tls.cipher,
        &tls.groups,
    )?;
    if let Some(wrap) = &tls.control_wrap {
        validate_control_wrap(
            &wrap.kind,
            &wrap.key,
            &wrap.key_path,
            &wrap.direction,
            wrap.force_cookie,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_tls_common(
    name_type: &str,
    fingerprints: &[String],
    key_usages: &[String],
    eku: &str,
    cert_tls: &str,
    ns_cert_type: &str,
    version_min: &str,
    version_max: &str,
    profile: &str,
    tls_cipher: &str,
    groups: &str,
) -> Result<(), OpenVpnOptionsError> {
    if !matches!(name_type, "" | "subject" | "name" | "name-prefix") {
        return invalid("TLS name type must be subject, name, or name-prefix");
    }
    for (index, fingerprint) in fingerprints.iter().enumerate() {
        if fingerprint.len() != 64
            || !fingerprint.bytes().all(|byte| {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            })
        {
            return invalid(format!(
                "peer_fingerprint[{index}] must be 64 lowercase hex characters"
            ));
        }
    }
    for (index, usage) in key_usages.iter().enumerate() {
        if usage.is_empty() || u64::from_str_radix(usage, 16).is_err() {
            return invalid(format!(
                "remote_certificate_ku[{index}] must be hexadecimal"
            ));
        }
    }
    if !matches!(cert_tls, "" | "server" | "client" | "none") {
        return invalid(
            "`remote_certificate_tls` must be server, client, or none",
        );
    }
    if !eku.is_empty() && !cert_tls.is_empty() {
        return invalid(
            "`remote_certificate_eku` conflicts with `remote_certificate_tls`",
        );
    }
    if !eku.is_empty() && !valid_extended_key_usage(eku) {
        return invalid(format!("unsupported `remote_certificate_eku`: {eku}"));
    }
    if !matches!(ns_cert_type, "" | "server" | "client") {
        return invalid("`ns_certificate_type` must be server or client");
    }
    if !matches!(profile, "" | "legacy" | "preferred" | "insecure" | "suiteb") {
        return invalid("unknown TLS certificate profile");
    }
    let version = |value: &str| match value {
        "" => Some(0),
        "1.0" => Some(10),
        "1.1" => Some(11),
        "1.2" => Some(12),
        "1.3" => Some(13),
        _ => None,
    };
    let min = version(version_min)
        .ok_or_else(|| OpenVpnOptionsError::new("unknown tls-version-min"))?;
    let max = version(version_max)
        .ok_or_else(|| OpenVpnOptionsError::new("unknown tls-version-max"))?;
    let min = if min == 0 { 12 } else { min };
    if max != 0 && max < min {
        return invalid("tls-version-min is bigger than tls-version-max");
    }
    validate_tls_cipher_suites(tls_cipher)?;
    validate_tls_groups(groups)?;
    Ok(())
}

fn valid_extended_key_usage(value: &str) -> bool {
    if matches!(
        value,
        "server"
            | "client"
            | "TLS Web Server Authentication"
            | "TLS Web Client Authentication"
            | "Code Signing"
            | "E-mail Protection"
            | "IPSec End System"
            | "IPSec Tunnel"
            | "IPSec User"
            | "Time Stamping"
            | "OCSP Signing"
            | "Any Extended Key Usage"
            | "Microsoft Server Gated Crypto"
            | "Netscape Server Gated Crypto"
            | "Microsoft Commercial Code Signing"
            | "Microsoft Individual Code Signing"
    ) {
        return true;
    }
    let parts: Option<Vec<u64>> = value
        .split('.')
        .map(|part| (!part.is_empty()).then(|| part.parse().ok()).flatten())
        .collect();
    let Some(parts) = parts else {
        return false;
    };
    parts.len() >= 2 && parts[0] <= 2 && (parts[0] == 2 || parts[1] <= 39)
}

fn validate_tls_cipher_suites(value: &str) -> Result<(), OpenVpnOptionsError> {
    if value.is_empty() {
        return Ok(());
    }
    for token in value.split(':') {
        if token.is_empty() || !is_tls_cipher_suite(token) {
            return invalid(format!("unsupported tls-cipher name: {token}"));
        }
    }
    Ok(())
}

fn is_tls_cipher_suite(value: &str) -> bool {
    matches!(
        value,
        "RC4-SHA"
            | "DES-CBC3-SHA"
            | "AES128-SHA"
            | "AES256-SHA"
            | "AES128-SHA256"
            | "AES128-GCM-SHA256"
            | "AES256-GCM-SHA384"
            | "ECDHE-ECDSA-AES128-SHA"
            | "ECDHE-ECDSA-AES256-SHA"
            | "ECDHE-ECDSA-RC4-SHA"
            | "ECDHE-RSA-RC4-SHA"
            | "ECDHE-RSA-DES-CBC3-SHA"
            | "ECDHE-RSA-AES128-SHA"
            | "ECDHE-RSA-AES256-SHA"
            | "ECDHE-ECDSA-AES128-SHA256"
            | "ECDHE-RSA-AES128-SHA256"
            | "ECDHE-ECDSA-AES128-GCM-SHA256"
            | "ECDHE-RSA-AES128-GCM-SHA256"
            | "ECDHE-ECDSA-AES256-GCM-SHA384"
            | "ECDHE-RSA-AES256-GCM-SHA384"
            | "ECDHE-ECDSA-CHACHA20-POLY1305"
            | "ECDHE-RSA-CHACHA20-POLY1305"
            | "TLS_RSA_WITH_RC4_128_SHA"
            | "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
            | "TLS_RSA_WITH_AES_128_CBC_SHA"
            | "TLS_RSA_WITH_AES_256_CBC_SHA"
            | "TLS_RSA_WITH_AES_128_CBC_SHA256"
            | "TLS_RSA_WITH_AES_128_GCM_SHA256"
            | "TLS_RSA_WITH_AES_256_GCM_SHA384"
            | "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
            | "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
            | "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
            | "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
            | "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
            | "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
            | "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
            | "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
            | "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
            | "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            | "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            | "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            | "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            | "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            | "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    )
}

fn validate_tls_groups(value: &str) -> Result<(), OpenVpnOptionsError> {
    if value.is_empty() {
        return Ok(());
    }
    for token in value.split(':') {
        if !matches!(
            token,
            "X25519"
                | "CURVE25519"
                | "SECP256R1"
                | "PRIME256V1"
                | "P-256"
                | "NISTP256"
                | "SECP384R1"
                | "P-384"
                | "NISTP384"
                | "SECP521R1"
                | "P-521"
                | "NISTP521"
        ) {
            return invalid(format!("unsupported tls-groups name: {token}"));
        }
    }
    Ok(())
}

fn validate_control_wrap(
    kind: &str,
    key: &Listable<String>,
    key_path: &str,
    direction: &str,
    force_cookie: bool,
) -> Result<(), OpenVpnOptionsError> {
    let configured = !kind.is_empty()
        || material_is_set(key, key_path)
        || !direction.is_empty()
        || force_cookie;
    if !configured {
        return Ok(());
    }
    require_material("tls.control_wrap.key", key, key_path)?;
    match kind {
        "tls_auth" => {
            validate_key_direction(direction)?;
            if force_cookie {
                return invalid(
                    "`force_cookie` is only supported by `tls_crypt_v2`",
                );
            }
        }
        "tls_crypt" => {
            if !direction.is_empty() {
                return invalid(
                    "control-wrap `direction` is only supported by `tls_auth`",
                );
            }
            if force_cookie {
                return invalid(
                    "`force_cookie` is only supported by `tls_crypt_v2`",
                );
            }
        }
        "tls_crypt_v2" => {
            if !direction.is_empty() {
                return invalid(
                    "control-wrap `direction` is only supported by `tls_auth`",
                );
            }
        }
        "" => return invalid("missing control wrap type"),
        _ => return invalid(format!("unknown control wrap type: {kind}")),
    }
    Ok(())
}

fn validate_compression(
    compression: &str,
    lzo: &str,
    allow: &str,
) -> Result<(), OpenVpnOptionsError> {
    if !matches!(
        compression,
        "" | "none"
            | "no"
            | "lz4"
            | "lz4-v2"
            | "stub"
            | "stub-v2"
            | "disabled"
            | "off"
            | "migrate"
            | "lzo"
    ) {
        return invalid("unsupported `compression` value");
    }
    if !matches!(
        lzo,
        "" | "none" | "no" | "yes" | "adaptive" | "asym" | "disabled" | "off"
    ) {
        return invalid("unsupported `compression_lzo` value");
    }
    if !matches!(allow, "" | "no" | "asym" | "yes") {
        return invalid("invalid `allow_compression` value");
    }
    let non_stub = if lzo.is_empty() {
        matches!(compression, "lz4" | "lz4-v2" | "lzo")
    } else {
        matches!(lzo, "yes" | "adaptive" | "asym")
    };
    if allow == "no" && non_stub {
        return invalid(
            "`allow_compression: no` conflicts with enabled compression",
        );
    }
    Ok(())
}

fn validate_push(push: &OpenVpnPushOptions) -> Result<(), OpenVpnOptionsError> {
    validate_duration("push.ping_interval", push.ping_interval, true)?;
    validate_duration("push.ping_restart", push.ping_restart, true)?;
    for (index, domain) in push.search_domains.as_slice().iter().enumerate() {
        if !valid_dns_name(domain) {
            return invalid(format!(
                "push.search_domains[{index}] contains invalid characters"
            ));
        }
    }
    let mut priorities = HashSet::new();
    for (server_index, server) in push.dns_servers.iter().enumerate() {
        if !(0..=127).contains(&server.priority) {
            return invalid(format!(
                "push.dns_servers[{server_index}].priority must be between 0 and 127"
            ));
        }
        if !priorities.insert(server.priority) {
            return invalid(format!(
                "push.dns_servers contains duplicate priority {}",
                server.priority
            ));
        }
        if server.addresses.as_slice().is_empty()
            || server.addresses.as_slice().len() > 8
        {
            return invalid(format!(
                "push.dns_servers[{server_index}] must contain 1 to 8 addresses"
            ));
        }
        for (address_index, address) in
            server.addresses.as_slice().iter().enumerate()
        {
            let valid = address.parse::<std::net::IpAddr>().is_ok()
                || address
                    .parse::<SocketAddr>()
                    .is_ok_and(|value| value.port() != 0);
            if !valid {
                return invalid(format!(
                    "invalid push.dns_servers[{server_index}].addresses[{address_index}]: {address}"
                ));
            }
        }
        for (domain_index, domain) in
            server.resolve_domains.as_slice().iter().enumerate()
        {
            if !valid_dns_name(domain) {
                return invalid(format!(
                    "push.dns_servers[{server_index}].resolve_domains[{domain_index}] contains invalid characters"
                ));
            }
        }
        if !server.sni.is_empty() && !valid_dns_name(&server.sni) {
            return invalid(format!(
                "push.dns_servers[{server_index}].sni contains invalid characters"
            ));
        }
        if !matches!(server.dnssec.as_str(), "" | "yes" | "optional" | "no") {
            return invalid(format!(
                "push.dns_servers[{server_index}].dnssec must be yes, optional, or no"
            ));
        }
        if !matches!(server.transport.as_str(), "" | "plain" | "dot" | "doh") {
            return invalid(format!(
                "push.dns_servers[{server_index}].transport must be plain, dot, or doh"
            ));
        }
    }
    Ok(())
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_alphanumeric()
                || matches!(character, '.' | '-' | '_')
                || !character.is_ascii()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_and_server_options_preserve_upstream_nested_fields() {
        let client: OpenVpnClientEndpointOptions =
            serde_json::from_value(serde_json::json!({
                "server": "vpn.example",
                "server_port": 1194,
                "network": "udp4",
                "mode": "tls",
                "username": "alice",
                "data_ciphers": ["AES-256-GCM", "CHACHA20-POLY1305"],
                "tls": {
                    "server_name": "vpn.example",
                    "certificate_path": "ca.pem",
                    "control_wrap": {
                        "type": "tls_crypt",
                        "key_path": "tc.key",
                        "direction": "client"
                    }
                },
                "routes": ["10.0.0.0/8"],
                "udp_timeout": "2m"
            }))
            .unwrap();
        assert!(client.server.server_is_domain());
        assert!(client.remote_is_domain());
        assert_eq!(client.data_ciphers.as_slice().len(), 2);
        assert_eq!(
            client
                .tls
                .as_ref()
                .unwrap()
                .control_wrap
                .as_ref()
                .unwrap()
                .kind,
            "tls_crypt"
        );

        let server: OpenVpnServerEndpointOptions =
            serde_json::from_value(serde_json::json!({
                "listen": "127.0.0.1",
                "listen_port": 1194,
                "address": ["10.8.0.1/24"],
                "users": [{"username": "alice", "password": "secret"}],
                "push": {
                    "routes": "10.0.0.0/8",
                    "dns": ["1.1.1.1"],
                    "dns_servers": [{
                        "priority": 10,
                        "addresses": ["1.1.1.1"],
                        "transport": "dot",
                        "sni": "cloudflare-dns.com"
                    }]
                }
            }))
            .unwrap();
        assert_eq!(server.users[0].username, "alice");
        assert_eq!(
            server.push.as_ref().unwrap().routes.as_slice()[0]
                .0
                .to_string(),
            "10.0.0.0/8"
        );
    }

    #[test]
    fn remote_domain_detection_checks_legacy_and_list_forms() {
        let legacy_ip: OpenVpnClientEndpointOptions =
            serde_json::from_value(serde_json::json!({
                "server": "192.0.2.1",
                "server_port": 1194
            }))
            .unwrap();
        assert!(!legacy_ip.remote_is_domain());

        let list_domain: OpenVpnClientEndpointOptions =
            serde_json::from_value(serde_json::json!({
                "servers": [{
                    "server": "vpn.example",
                    "server_port": 1194
                }]
            }))
            .unwrap();
        assert!(list_domain.remote_is_domain());
    }

    fn client(value: serde_json::Value) -> OpenVpnClientEndpointOptions {
        serde_json::from_value(value).unwrap()
    }

    fn server(value: serde_json::Value) -> OpenVpnServerEndpointOptions {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn validates_tls_client_defaults_and_material_rules() {
        let valid = client(serde_json::json!({
            "server": "vpn.example",
            "server_port": 1194,
            "tls": {"peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
        }));
        valid.validate().unwrap();
        assert_eq!(valid.normalized_mode(), "tls");
        assert_eq!(valid.normalized_network(), "udp");

        let conflicting = client(serde_json::json!({
            "server": "vpn.example",
            "server_port": 1194,
            "tls": {
                "certificate": "inline",
                "certificate_path": "ca.pem"
            }
        }));
        assert!(
            conflicting
                .validate()
                .unwrap_err()
                .to_string()
                .contains("conflicts")
        );

        let bad_wrap = client(serde_json::json!({
            "server": "vpn.example",
            "server_port": 1194,
            "tls": {"control_wrap": {
                "type": "tls_crypt",
                "key": "inline",
                "direction": "client"
            }}
        }));
        assert!(
            bad_wrap
                .validate()
                .unwrap_err()
                .to_string()
                .contains("direction")
        );
    }

    #[test]
    fn validates_static_key_client_tunnel_and_tcp_fragment() {
        let valid = client(serde_json::json!({
            "mode": "static_key",
            "server": "127.0.0.1",
            "server_port": 1194,
            "address": ["10.8.0.2/24", "fd00::2/64"],
            "peer_address": "10.8.0.1",
            "peer_address_ipv6": "fd00::1",
            "static_key": "key",
            "cipher": "AES-256-CBC"
        }));
        valid.validate().unwrap();

        let no_peer = client(serde_json::json!({
            "mode": "static_key",
            "server": "127.0.0.1",
            "server_port": 1194,
            "address": "10.8.0.2/24",
            "static_key": "key",
            "cipher": "AES-256-CBC"
        }));
        assert!(
            no_peer
                .validate()
                .unwrap_err()
                .to_string()
                .contains("peer_address")
        );

        let fragmented_tcp = client(serde_json::json!({
            "server": "vpn.example",
            "server_port": 443,
            "network": "tcp",
            "fragment": 1300,
            "tls": {"peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
        }));
        assert!(
            fragmented_tcp
                .validate()
                .unwrap_err()
                .to_string()
                .contains("fragment")
        );
    }

    #[test]
    fn validates_tls_server_push_dns_and_defaults() {
        let valid = server(serde_json::json!({
            "address": ["10.8.0.1/24", "fd00::1/64"],
            "tls": {"certificate": "cert", "key": "key"},
            "push": {"dns_servers": [{
                "priority": 10,
                "addresses": ["1.1.1.1", "[2606:4700:4700::1111]:853"],
                "resolve_domains": "example.com",
                "dnssec": "yes",
                "transport": "dot",
                "sni": "cloudflare-dns.com"
            }]}
        }));
        valid.validate().unwrap();
        assert_eq!(valid.normalized_network(), "udp");
        assert_eq!(valid.normalized_topology(), "subnet");

        let duplicate_priority = server(serde_json::json!({
            "address": "10.8.0.1/24",
            "tls": {"certificate": "cert", "key": "key"},
            "push": {"dns_servers": [
                {"priority": 1, "addresses": "1.1.1.1"},
                {"priority": 1, "addresses": "8.8.8.8"}
            ]}
        }));
        assert!(
            duplicate_priority
                .validate()
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn validates_static_key_server_transport_and_address_pools() {
        let valid = server(serde_json::json!({
            "mode": "static_key",
            "network": "udp",
            "remote": "127.0.0.1",
            "remote_port": 1194,
            "address": "10.8.0.1/24",
            "peer_address": "10.8.0.2",
            "static_key_path": "secret.key",
            "cipher": "AES-128-CBC"
        }));
        valid.validate().unwrap();
        assert_eq!(valid.normalized_topology(), "p2p");

        let duplicate_v4 = server(serde_json::json!({
            "address": ["10.8.0.1/24", "10.9.0.1/24"],
            "tls": {"certificate": "cert", "key": "key"}
        }));
        assert!(
            duplicate_v4
                .validate()
                .unwrap_err()
                .to_string()
                .contains("multiple IPv4")
        );
    }

    #[test]
    fn accepts_exact_upstream_stream_cipher_families() {
        for cipher in [
            "BF-CFB",
            "DES-OFB",
            "DES-EDE-CFB",
            "DES-EDE3-OFB",
            "CAST5-CFB",
            "AES-192-OFB",
            "ARIA-256-CFB",
            "CAMELLIA-128-OFB",
            "SEED-CFB",
            "SM4-OFB",
        ] {
            let value = client(serde_json::json!({
                "server": "vpn.example",
                "server_port": 1194,
                "data_ciphers": [cipher],
                "tls": {"peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
            }));
            value.validate().unwrap_or_else(|error| {
                panic!("{cipher} should be accepted: {error}")
            });
        }
        let invalid = client(serde_json::json!({
            "server": "vpn.example",
            "server_port": 1194,
            "data_ciphers": ["AES-128-CFB8"],
            "tls": {"peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
        }));
        assert!(invalid.validate().is_err());
    }
}
