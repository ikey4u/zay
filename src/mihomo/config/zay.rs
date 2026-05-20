//! Construct the default Zay [`Config`](super::Config).

use indexmap::IndexMap;

use super::{
    config::Config,
    dns::DnsConfig,
    providers::{HealthCheck, ProviderOverride, ProxyProvider},
    proxy::Proxy,
    proxy_group::{ProxyGroup, SelectGroup, UrlTestGroup},
    tun::TunConfig,
};
use crate::{
    mihomo::rules,
    settings::{BootstrapProxy, Settings},
};

pub fn build(
    settings: &Settings,
    has_mmdb: bool,
    _has_geosite: bool,
    has_builtin_rules: bool,
) -> Config {
    let sub_uses: Vec<String> = settings.subscription_provider_ids();
    let urltest_members = urltest_member_proxies(settings);
    let select_proxies = select_group_proxies(settings);

    let mut cfg = Config {
        mixed_port: Some(settings.mixed_port),
        allow_lan: Some(settings.allow_lan),
        ipv6: Some(false),
        mode: Some("rule".into()),
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
        rules: Some(rules::compose_routing_rules(
            settings,
            has_mmdb,
            has_builtin_rules,
        )),
        ..Default::default()
    };

    // Geo files live under `<data-dir>/mihomo/`; Mihomo loads them from `-d` pointing at that directory.
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
    if let Some(bp) = settings.bootstrap_proxy.as_ref() {
        cfg.proxies = Some(vec![Proxy::from_value(bp.proxy.clone())]);
    }
    if has_builtin_rules {
        cfg.rule_providers = Some(rules::rule_providers_map());
    }

    cfg
}

/// Members of the `Auto` url-test group (must not include the group name `Auto`).
fn urltest_member_proxies(settings: &Settings) -> Vec<String> {
    let mut names = vec!["DIRECT".into()];
    if let Some(bp) = settings.bootstrap_proxy.as_ref() {
        names.insert(0, bp.name.clone());
    }
    names
}

/// Static members listed under the `Proxy` select group (may reference other groups).
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
