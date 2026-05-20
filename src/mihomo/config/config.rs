//! Mihomo v1.19.25 root config — mirrors upstream `RawConfig` in `config/config.go`.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

use super::{
    cfa::ClashForAndroidConfig,
    cors::ExternalControllerCors,
    dns::DnsConfig,
    experimental::ExperimentalConfig,
    geox::GeoxUrl,
    hosts::HostsConfig,
    iptables::IptablesConfig,
    ntp::NtpConfig,
    profile::ProfileConfig,
    providers::{ProxyProviders, RuleProviders},
    proxy::Proxy,
    proxy_group::ProxyGroup,
    sniffer::SnifferConfig,
    tls::TlsConfig,
    tuic::TuicServerConfig,
    tun::TunConfig,
    tunnel::TunnelEntry,
};

/// Mihomo runtime configuration (full `RawConfig` surface for v1.19.25).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socks_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redir_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tproxy_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mixed_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ss_config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vmess_config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_tfo: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_mptcp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_auth_prefixes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lan_allowed_ips: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lan_disallowed_ips: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_lan: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unified_delay: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller_pipe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller_unix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller_tls: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller_cors: Option<ExternalControllerCors>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ui: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ui_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ui_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_doh_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnels: Option<Vec<TunnelEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_auto_update: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_update_interval: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geodata_mode: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geodata_loader: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geosite_matcher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_concurrent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub find_process_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_client_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_ua: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag_support: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive_idle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive_interval: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_keep_alive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_providers: Option<ProxyProviders>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_providers: Option<RuleProviders>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxies: Option<Vec<Proxy>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_groups: Option<Vec<ProxyGroup>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_rules: Option<IndexMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listeners: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosts: Option<HostsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ntp: Option<NtpConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun: Option<TunConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tuic_server: Option<TuicServerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iptables: Option<IptablesConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<ExperimentalConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geox_url: Option<GeoxUrl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffer: Option<SnifferConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clash_for_android: Option<ClashForAndroidConfig>,
}

/// Top-level YAML keys documented for v1.19.25 (`docs/config.yaml` + `RawConfig`).
pub const DOCUMENTED_TOP_LEVEL_KEYS: &[&str] = &[
    "port",
    "socks-port",
    "redir-port",
    "tproxy-port",
    "mixed-port",
    "ss-config",
    "vmess-config",
    "inbound-tfo",
    "inbound-mptcp",
    "authentication",
    "skip-auth-prefixes",
    "lan-allowed-ips",
    "lan-disallowed-ips",
    "allow-lan",
    "bind-address",
    "mode",
    "unified-delay",
    "log-level",
    "ipv6",
    "external-controller",
    "external-controller-pipe",
    "external-controller-unix",
    "external-controller-tls",
    "external-controller-cors",
    "external-ui",
    "external-ui-url",
    "external-ui-name",
    "external-doh-server",
    "secret",
    "interface-name",
    "routing-mark",
    "tunnels",
    "geo-auto-update",
    "geo-update-interval",
    "geodata-mode",
    "geodata-loader",
    "geosite-matcher",
    "tcp-concurrent",
    "find-process-mode",
    "global-client-fingerprint",
    "global-ua",
    "etag-support",
    "keep-alive-idle",
    "keep-alive-interval",
    "disable-keep-alive",
    "proxy-providers",
    "rule-providers",
    "proxies",
    "proxy-groups",
    "rules",
    "sub-rules",
    "listeners",
    "hosts",
    "dns",
    "ntp",
    "tun",
    "tuic-server",
    "iptables",
    "experimental",
    "profile",
    "geox-url",
    "sniffer",
    "tls",
    "clash-for-android",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_keys_deserialize_into_config() {
        let mut mapping = serde_yaml::Mapping::new();
        for key in DOCUMENTED_TOP_LEVEL_KEYS {
            mapping
                .insert(serde_yaml::Value::from(*key), serde_yaml::Value::Null);
        }
        let doc = serde_yaml::Value::Mapping(mapping);
        let cfg: Config =
            serde_yaml::from_value(doc).expect("all documented keys accepted");
        assert!(cfg.mixed_port.is_none());
    }
}
