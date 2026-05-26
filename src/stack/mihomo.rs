//! Mihomo config for `zay stack` (always-on proxy leg).

use anyhow::{Context, Result};
use indexmap::IndexMap;

use super::mesh;
use crate::{
    mihomo::{
        config::{
            config::Config,
            dns::DnsConfig,
            providers::{HealthCheck, ProviderOverride, ProxyProvider},
            proxy::Proxy,
            proxy_group::{ProxyGroup, SelectGroup, UrlTestGroup},
            tun::TunConfig,
        },
        rules,
    },
    settings::{BootstrapProxy, Settings},
};

pub fn build_config(
    settings: &Settings,
    has_mmdb: bool,
    has_geosite: bool,
    has_builtin_rules: bool,
) -> Result<String> {
    let doc = build(settings, has_mmdb, has_geosite, has_builtin_rules);
    serde_yaml::to_string(&doc).context("serializing Mihomo stack config")
}

pub fn build(
    settings: &Settings,
    has_mmdb: bool,
    _has_geosite: bool,
    has_builtin_rules: bool,
) -> Config {
    let has_subscription = !settings.subscriptions.is_empty();
    let gateway = settings.stack.gateway;

    let mut cfg = if has_subscription {
        subscription_config(settings, has_mmdb, has_builtin_rules, gateway)
    } else {
        direct_config(settings, has_mmdb, has_builtin_rules, gateway)
    };

    if settings.tun {
        cfg.tun = Some(TunConfig {
            enable: Some(true),
            stack: Some("system".into()),
            auto_route: Some(true),
            auto_detect_interface: Some(true),
            dns_hijack: Some(vec!["any:53".into()]),
            ..Default::default()
        });
        cfg.dns = Some(dns_tun());
    } else {
        cfg.dns = Some(DnsConfig {
            enable: Some(false),
            ..Default::default()
        });
    }
    apply_tun_route_excludes(&mut cfg, settings);

    if let Some(bp) = settings.bootstrap_proxy.as_ref() {
        cfg.proxies
            .get_or_insert_with(Vec::new)
            .push(Proxy::from_value(bp.proxy.clone()));
    }
    if has_builtin_rules && has_subscription {
        cfg.rule_providers = Some(rules::rule_providers_map());
    }

    cfg
}

fn apply_tun_route_excludes(cfg: &mut Config, settings: &Settings) {
    let excludes = tun_route_excludes(settings);
    if excludes.is_empty() {
        return;
    }
    cfg.tun
        .get_or_insert_with(TunConfig::default)
        .route_exclude_address = Some(excludes);
}

fn tun_route_excludes(settings: &Settings) -> Vec<String> {
    let mut excludes = Vec::new();
    excludes.extend(settings.tun_exclude_routes.iter().cloned());
    if let Some(mesh_routes) = mesh::route_exclude_addresses(settings) {
        excludes.extend(mesh_routes);
    }
    excludes.sort();
    excludes.dedup();
    excludes
}

fn direct_config(
    settings: &Settings,
    has_mmdb: bool,
    _has_builtin_rules: bool,
    _gateway: bool,
) -> Config {
    // `mode: direct` intentionally ignores rules. That is fine for host
    // gateway relay, but VM TUN mode may use mixin rules like `MATCH,Host`
    // to send traffic to the host SOCKS proxy.
    let mode = if settings.tun { "rule" } else { "direct" };

    Config {
        mixed_port: Some(settings.mixed_port),
        allow_lan: Some(settings.allow_lan),
        ipv6: Some(false),
        mode: Some(mode.into()),
        log_level: Some(settings.log_level.clone()),
        external_controller: Some(settings.external_controller.clone()),
        secret: Some(settings.api_secret.clone()),
        // Direct stack has no `Proxy` group, so avoid built-in rules that
        // reference `Proxy` (for example GFW/Telegram lists).
        rules: Some(direct_rules(settings, has_mmdb)),
        ..Default::default()
    }
}

fn subscription_config(
    settings: &Settings,
    has_mmdb: bool,
    has_builtin_rules: bool,
    gateway: bool,
) -> Config {
    let sub_uses: Vec<String> = settings.subscription_provider_ids();
    let urltest_members = urltest_member_proxies(settings);
    let select_proxies = select_group_proxies(settings);
    let mode = if gateway { "rule" } else { "rule" };

    Config {
        mixed_port: Some(settings.mixed_port),
        allow_lan: Some(settings.allow_lan),
        ipv6: Some(false),
        mode: Some(mode.into()),
        log_level: Some(settings.log_level.clone()),
        external_controller: Some(settings.external_controller.clone()),
        secret: Some(settings.api_secret.clone()),
        proxy_providers: Some(subscription_providers(
            settings,
            settings.bootstrap_proxy.as_ref(),
        )),
        proxy_groups: Some(vec![
            ProxyGroup::UrlTest(UrlTestGroup {
                name: "Auto".into(),
                proxies: Some(urltest_members),
                r#use: Some(sub_uses.clone()),
                url: Some(settings.health_check_url.clone()),
                interval: Some(300),
                tolerance: Some(100),
                lazy: Some(true),
                expected_status: None,
            }),
            ProxyGroup::Select(SelectGroup {
                name: "Proxy".into(),
                proxies: Some(select_proxies),
                r#use: Some(sub_uses),
                filter: None,
                disable_udp: None,
            }),
        ]),
        rules: Some(stack_rules(
            settings,
            has_mmdb,
            has_builtin_rules,
            gateway,
            true,
        )),
        ..Default::default()
    }
}

fn stack_rules(
    settings: &Settings,
    has_mmdb: bool,
    has_builtin_rules: bool,
    _gateway: bool,
    has_subscription: bool,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.extend(mesh::route_lines(settings));
    if has_subscription {
        lines.extend(rules::proxy_fetch_rule_lines(settings));
        if has_builtin_rules {
            lines.extend(rules::routing_rule_lines(has_mmdb));
        } else {
            lines.extend(rules::fallback_rule_lines(has_mmdb));
        }
    } else if has_builtin_rules {
        lines.extend(rules::routing_rule_lines(has_mmdb));
    } else {
        lines.extend(rules::fallback_rule_lines(has_mmdb));
    }
    lines
}

fn direct_rules(settings: &Settings, has_mmdb: bool) -> Vec<String> {
    let mut lines = mesh::route_lines(settings);
    lines.extend(rules::fallback_rule_lines(has_mmdb));
    lines
}

fn urltest_member_proxies(settings: &Settings) -> Vec<String> {
    let mut names = vec!["DIRECT".into()];
    if let Some(bp) = settings.bootstrap_proxy.as_ref() {
        names.insert(0, bp.name.clone());
    }
    names
}

fn select_group_proxies(settings: &Settings) -> Vec<String> {
    let mut names = vec!["Auto".into(), "DIRECT".into()];
    if let Some(bp) = settings.bootstrap_proxy.as_ref() {
        names.insert(0, bp.name.clone());
    }
    names
}

fn subscription_providers(
    settings: &Settings,
    bootstrap: Option<&BootstrapProxy>,
) -> IndexMap<String, ProxyProvider> {
    let mut providers = IndexMap::new();
    for (i, url) in settings.subscriptions.iter().enumerate() {
        let id = Settings::subscription_provider_id(i);
        let mut provider = ProxyProvider {
            kind: "http".into(),
            url: Some(url.clone()),
            interval: Some(settings.update_interval),
            path: Some(format!("./providers/sub{i}.yaml")),
            health_check: Some(HealthCheck {
                enable: Some(true),
                url: Some(settings.health_check_url.clone()),
                interval: Some(300),
                ..Default::default()
            }),
            ..Default::default()
        };
        if let Some(bp) = bootstrap {
            provider.proxy = Some(bp.name.clone());
        }
        provider.override_section = Some(ProviderOverride {
            additional_prefix: Some(Settings::subscription_name_prefix(i)),
            ..Default::default()
        });
        providers.insert(id, provider);
    }
    providers
}

fn dns_tun() -> DnsConfig {
    DnsConfig {
        enable: Some(true),
        listen: Some("0.0.0.0:53533".into()),
        enhanced_mode: Some("fake-ip".into()),
        fake_ip_range: Some("198.18.0.1/16".into()),
        fake_ip_filter: Some(vec![
            "*.lan".into(),
            "*.local".into(),
            "*.internal".into(),
        ]),
        default_nameserver: Some(vec![
            "114.114.114.114".into(),
            "223.5.5.5".into(),
        ]),
        nameserver: Some(vec!["114.114.114.114".into(), "223.5.5.5".into()]),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::build_config;
    use crate::settings::{MeshConfig, Settings, StackFlags};

    fn settings_with_mesh() -> Settings {
        Settings {
            subscriptions: Vec::new(),
            data_dir: PathBuf::from("/tmp/zay-test"),
            mixed_port: 17890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://www.gstatic.com/generate_204".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            external_controller: "127.0.0.1:19090".into(),
            api_secret: "secret".into(),
            mixin: None,
            bootstrap_proxy: None,
            mesh: Some(MeshConfig {
                instance_name: Some("zay".into()),
                network_name: "my-network".into(),
                network_secret: "change-me".into(),
                dhcp: None,
                ipv4: None,
                listeners: None,
                peers: None,
                proxy_networks: None,
                mesh_routes: Some(vec!["10.126.126.0/24".into()]),
            }),
            stack: StackFlags {
                mesh: true,
                gateway: false,
                tun: true,
            },
        }
    }

    #[test]
    fn mesh_routes_are_direct_and_excluded_from_mihomo_tun() {
        let yaml =
            build_config(&settings_with_mesh(), true, false, false).unwrap();

        assert!(yaml.contains("IP-CIDR,10.126.126.0/24,DIRECT,no-resolve"));
        assert!(yaml.contains("route-exclude-address:"));
        assert!(yaml.contains("- 10.126.126.0/24"));
        assert!(!yaml.contains("name: EasyTier"));
    }

    #[test]
    fn custom_tun_excludes_are_written() {
        let mut settings = settings_with_mesh();
        settings.tun_exclude_routes = vec!["11.155.134.0/24".into()];

        let yaml = build_config(&settings, true, false, false).unwrap();

        assert!(yaml.contains("- 11.155.134.0/24"));
    }
}
