use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use super::{mesh, rules, subscription, tun_route};
use crate::settings::Settings;

pub fn build_config(settings: &Settings, has_rules: bool) -> Result<String> {
    let doc = build_value(settings, has_rules)?;
    serde_json::to_string_pretty(&doc).context("serializing sing-box config")
}

pub fn build_value(settings: &Settings, has_rules: bool) -> Result<Value> {
    let tun_enabled = tun_route::singbox_tun_enabled(settings);
    let clash_dns = clash_dns_enabled(settings, tun_enabled, has_rules);
    let outbound_interface = (tun_enabled
        && !tun_route::tun_selective_mesh_routes(settings))
    .then(tun_route::default_route_interface)
    .flatten();

    if let Some(interface) = outbound_interface.as_deref() {
        eprintln!("proxy transports: bind physical interface → {interface}");
    }

    let mut outbounds: Vec<Value> =
        vec![tun_route::direct_outbound_json(settings, tun_enabled)];

    if let Some(bp) = &settings.bootstrap_proxy {
        if let Some(mut node) = super::clash::convert_proxy(&bp.proxy, None)? {
            if let Some(interface) = outbound_interface.as_deref() {
                tun_route::bind_outbound_to_interface(&mut node, interface);
            }
            outbounds.push(node);
        }
    }

    let mut available_member_tags: Vec<String> = Vec::new();
    if !settings.subscriptions.is_empty() {
        let nodes = subscription::load_nodes(
            settings,
            settings.bootstrap_proxy.as_ref(),
        )?;
        for node in &nodes {
            if let Some(tag) = node.get("tag").and_then(|t| t.as_str()) {
                available_member_tags.push(tag.to_string());
            }
        }
        outbounds.extend(nodes.into_iter().map(|mut node| {
            if let Some(interface) = outbound_interface.as_deref() {
                tun_route::bind_outbound_to_interface(&mut node, interface);
            }
            node
        }));
    }

    let mut member_tags = if settings.active_nodes.is_empty() {
        available_member_tags.clone()
    } else {
        available_member_tags
            .iter()
            .filter(|tag| settings.active_nodes.contains(tag))
            .cloned()
            .collect::<Vec<_>>()
    };
    if member_tags.is_empty() && !available_member_tags.is_empty() {
        if !settings.active_nodes.is_empty() {
            eprintln!(
                "warning: configured active proxy nodes are unavailable; falling back to all {} node(s)",
                available_member_tags.len()
            );
        }
        member_tags = available_member_tags;
    }

    let proxy_final = if member_tags.is_empty() {
        "direct".to_string()
    } else {
        outbounds.push(json!({
            "type": "urltest",
            "tag": "Auto",
            "outbounds": member_tags.clone(),
            "url": settings.health_check_url,
            "interval": "300s",
            "tolerance": 100
        }));
        let mut proxy_members = vec!["Auto".to_string()];
        proxy_members.extend(member_tags.clone());
        outbounds.push(json!({
            "type": "selector",
            "tag": "Proxy",
            "outbounds": proxy_members,
            "default": "Auto"
        }));
        "Proxy".to_string()
    };
    let (domain_outbounds, domain_routes) =
        build_domain_rule_groups(settings, &member_tags, &proxy_final)?;
    outbounds.extend(domain_outbounds);

    let mut endpoints = Vec::new();
    if let Some(wg) = mesh::wireguard_endpoint(settings)? {
        endpoints.push(wg);
    }

    let include_applications =
        has_rules && rules::applications_present(&settings.singbox_dir());
    let find_process = include_applications
        || tun_route::tun_full_capture_mesh_proxy(&settings);

    let mut route_rules = Vec::new();
    // EasyTier (in-process) + relay/STUN bypass before mesh/proxy rules.
    route_rules.extend(mesh::easytier_process_bypass_route_rules(settings));
    // Relay/public peer IPs must bypass TUN path (SSH + EasyTier :11010) before mesh 10.x rules.
    route_rules.extend(mesh::peer_bypass_route_rules(settings));
    // Mesh CIDRs must win before sniff / clash private rules (10.x is ip_is_private).
    route_rules.extend(mesh::mesh_route_rules(settings));
    // Mihomo `dns-hijack: any:53` — L4 port match before sniff (sing-box 1.13+; see SagerNet/sing-box#3878).
    if tun_enabled {
        route_rules.push(json!({ "port": 53, "action": "hijack-dns" }));
    }
    route_rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
    // Sniff after hijack-dns (TLS SNI / HTTP Host for connections that already have a destination).
    route_rules.extend(sniff_route_rules(settings, tun_enabled));
    route_rules.extend(domain_routes);
    if let Some(rule) = health_check_route(settings, &proxy_final) {
        route_rules.push(rule);
    }

    if has_rules {
        route_rules.extend(rules::proxy_fetch_rules(&proxy_final));
        route_rules.extend(rules::builtin_route_rules(
            &proxy_final,
            include_applications,
        ));
    } else if !settings.subscriptions.is_empty() {
        // Interim routes while clash-rules download (before fake-ip + rule-sets apply).
        route_rules.push(json!({
            "action": "route",
            "ip_is_private": true,
            "outbound": "direct"
        }));
        route_rules.push(json!({
            "action": "route",
            "outbound": proxy_final
        }));
    } else if tun_enabled {
        // Mesh CIDR rules above already win for 10.x; keep RFC1918 on direct before final fallback.
        route_rules.push(json!({
            "action": "route",
            "ip_is_private": true,
            "outbound": "direct"
        }));
        route_rules.push(json!({
            "action": "route",
            "outbound": proxy_final
        }));
    }

    // Full-capture TUN does not need a loopback HTTP/SOCKS listener. Keeping
    // the two modes exclusive avoids collisions with Clash's conventional
    // 7890 port and makes TUN health independent from a local proxy socket.
    let mut inbounds = if tun_enabled {
        Vec::new()
    } else {
        mixed_inbounds(settings)
    };

    if tun_enabled {
        let auto_route = tun_route::tun_auto_route(settings);
        let mut tun = json!({
            "type": "tun",
            "tag": "tun-in",
            "address": tun_route::tun_addresses(settings),
            "auto_route": auto_route,
            "strict_route": tun_route::tun_strict_route(settings),
            "stack": tun_route::tun_stack(settings),
            "route_exclude_address": tun_route::tun_exclude_addresses(settings)?
        });
        if let Some(addrs) = tun_route::tun_route_address(settings) {
            tun["route_address"] = json!(addrs);
        }
        if tun_route::tun_auto_redirect(settings) {
            tun["auto_redirect"] = json!(true);
        }
        inbounds.push(tun);
    }

    // Loyalsoldier blacklist: final → direct once rule-sets are loaded.
    let route_final = if has_rules {
        "direct".to_string()
    } else {
        proxy_final.clone()
    };

    let dns_resolver_tag = if clash_dns { "dns-direct" } else { "local-dns" };

    let mut route = json!({
        "rules": route_rules,
        "final": route_final,
        "auto_detect_interface": true,
        "default_domain_resolver": dns_resolver_tag
    });

    // `auto_detect_interface` initializes lazily, after the TUN routes are in
    // place. Preserve the physical interface detected before startup so DNS
    // transports and every dialer inherit the same non-TUN underlay.
    if let Some(interface) = outbound_interface.as_deref() {
        route["default_interface"] = json!(interface);
    }

    if find_process {
        route["find_process"] = json!(true);
    }
    if has_rules {
        let rule_sets = rules::rule_set_definitions(settings);
        if rule_sets.is_empty() {
            eprintln!(
                "warn: clash-rules files missing under {}; routing without rule-sets",
                settings.singbox_dir().display()
            );
        } else {
            route["rule_set"] = json!(rule_sets);
        }
    }

    let mut cache_file = json!({
        "enabled": true,
        "path": "cache.db"
    });
    if clash_dns {
        cache_file["store_fakeip"] = json!(true);
        tun_route::log_fakeip_dns_hint(settings, true);
    }

    let mut root = json!({
        "log": {
            "level": settings.log_level,
            "timestamp": true
        },
        "dns": dns_config(settings, tun_enabled, has_rules, clash_dns),
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
        "experimental": {
            "cache_file": cache_file,
            "clash_api": {
                "external_controller": "127.0.0.1:0"
            }
        }
    });

    if !endpoints.is_empty() {
        root["endpoints"] = json!(endpoints);
    }

    Ok(root)
}

fn health_check_route(settings: &Settings, proxy_tag: &str) -> Option<Value> {
    if proxy_tag == "direct" {
        return None;
    }
    let host = reqwest::Url::parse(&settings.health_check_url)
        .ok()?
        .host_str()?
        .to_string();
    Some(json!({
        "action": "route",
        "domain": [host],
        "outbound": proxy_tag
    }))
}

fn build_domain_rule_groups(
    settings: &Settings,
    member_tags: &[String],
    fallback_outbound: &str,
) -> Result<(Vec<Value>, Vec<Value>)> {
    let available: HashSet<&str> =
        member_tags.iter().map(String::as_str).collect();
    let mut names = HashSet::new();
    let mut outbounds = Vec::new();
    let mut routes = Vec::new();

    for policy in &settings.domain_rule {
        if !policy.enabled {
            continue;
        }
        let name = policy.name.trim();
        if name.is_empty() {
            bail!("proxy.domain_rule.name must not be empty");
        }
        if !names.insert(name) {
            bail!("duplicate proxy.domain_rule name {name:?}");
        }
        if policy.by_suffix.is_empty()
            && policy.host.is_empty()
            && policy.process.is_empty()
            && policy.source.is_empty()
            && policy.destination.is_empty()
        {
            bail!("proxy.domain_rule {name:?} requires at least one matcher");
        }
        if policy.outbounds.is_empty() {
            bail!("proxy.domain_rule {name:?} requires at least one outbound");
        }
        let resolved: Vec<&str> = policy
            .outbounds
            .iter()
            .map(String::as_str)
            .filter(|tag| available.contains(tag))
            .collect();
        let missing: Vec<&str> = policy
            .outbounds
            .iter()
            .map(String::as_str)
            .filter(|tag| !available.contains(tag))
            .collect();
        if !missing.is_empty() {
            eprintln!(
                "warning: proxy.domain_rule {name:?} ignores unavailable subscription node(s): {}; run `zay x service proxy list` to inspect current tags",
                missing.join(", ")
            );
        }

        if resolved.is_empty() {
            if fallback_outbound == "direct" {
                eprintln!(
                    "warning: proxy.domain_rule {name:?} has no available proxy candidate and no subscription fallback; rule disabled"
                );
                continue;
            }
            eprintln!(
                "warning: proxy.domain_rule {name:?} has no available configured candidate; falling back to {fallback_outbound:?}"
            );
            routes.push(custom_rule_route(policy, fallback_outbound)?);
            continue;
        }

        let tag = format!("domain-proxy:{name}");
        outbounds.push(json!({
            "type": "urltest",
            "tag": tag,
            "outbounds": resolved,
            "url": policy.health_check_url.as_deref().unwrap_or(&settings.health_check_url),
            "interval": format!("{}s", policy.interval.unwrap_or(300)),
            "tolerance": policy.tolerance.unwrap_or(100)
        }));
        routes
            .push(custom_rule_route(policy, &format!("domain-proxy:{name}"))?);
    }

    Ok((outbounds, routes))
}

fn custom_rule_route(
    policy: &crate::settings::DomainRuleFile,
    outbound: &str,
) -> Result<Value> {
    let mut route = serde_json::Map::new();
    route.insert("action".into(), json!("route"));
    route.insert("outbound".into(), json!(outbound));

    let mut domains = Vec::new();
    let mut suffixes = policy.by_suffix.clone();
    let mut regexes = Vec::new();
    for pattern in &policy.host {
        let pattern = pattern.trim().trim_end_matches('.');
        if let Some(suffix) = pattern.strip_prefix("*.") {
            suffixes.push(suffix.to_string());
        } else if pattern.contains('*') {
            let expression = regex::escape(pattern).replace(r"\*", ".*");
            regexes.push(format!(r"^{expression}$"));
        } else if !pattern.is_empty() {
            domains.push(pattern.to_string());
        }
    }
    if !domains.is_empty() {
        route.insert("domain".into(), json!(domains));
    }
    if !suffixes.is_empty() {
        route.insert("domain_suffix".into(), json!(suffixes));
    }
    if !regexes.is_empty() {
        route.insert("domain_regex".into(), json!(regexes));
    }

    let mut process_names = Vec::new();
    let mut process_paths = Vec::new();
    for process in &policy.process {
        let process = process.trim();
        if process.contains('/') || process.contains('\\') {
            process_paths.push(process.to_string());
        } else if !process.is_empty() {
            process_names.push(process.to_string());
        }
    }
    if !process_names.is_empty() {
        route.insert("process_name".into(), json!(process_names));
    }
    if !process_paths.is_empty() {
        route.insert("process_path".into(), json!(process_paths));
    }

    insert_endpoint_matches(&mut route, &policy.source, true)?;
    insert_endpoint_matches(&mut route, &policy.destination, false)?;
    Ok(Value::Object(route))
}

fn insert_endpoint_matches(
    route: &mut serde_json::Map<String, Value>,
    values: &[String],
    source: bool,
) -> Result<()> {
    let mut addresses = Vec::new();
    let mut ports = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if let Ok(endpoint) = value.parse::<std::net::SocketAddr>() {
            let bits = if endpoint.ip().is_ipv4() { 32 } else { 128 };
            addresses.push(format!("{}/{bits}", endpoint.ip()));
            ports.push(endpoint.port());
        } else if let Ok(address) = value.parse::<std::net::IpAddr>() {
            let bits = if address.is_ipv4() { 32 } else { 128 };
            addresses.push(format!("{address}/{bits}"));
        } else if value.contains('/') {
            addresses.push(value.to_string());
        } else if source {
            bail!(
                "source matcher {value:?} must be an IP, CIDR, or socket address"
            );
        } else {
            route
                .entry("domain")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .expect("domain match array")
                .push(json!(value));
        }
    }
    if !addresses.is_empty() {
        route.insert(
            if source { "source_ip_cidr" } else { "ip_cidr" }.into(),
            json!(addresses),
        );
    }
    if !ports.is_empty() {
        route.insert(
            if source { "source_port" } else { "port" }.into(),
            json!(ports),
        );
    }
    Ok(())
}

fn mixed_inbounds(settings: &Settings) -> Vec<Value> {
    let port = settings.mixed_port;
    if settings.allow_lan {
        return vec![json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "0.0.0.0",
            "listen_port": port
        })];
    }
    let mut inbounds = vec![json!({
        "type": "mixed",
        "tag": "mixed-in",
        "listen": "127.0.0.1",
        "listen_port": port
    })];
    // Firefox/GNOME often use "localhost" → ::1; listen there too (TUN apps should use No Proxy).
    inbounds.push(json!({
        "type": "mixed",
        "tag": "mixed-in-v6",
        "listen": "::1",
        "listen_port": port
    }));
    inbounds
}

fn sniff_inbound_tags(settings: &Settings, tun_enabled: bool) -> Vec<String> {
    if tun_enabled {
        return vec!["tun-in".into()];
    }
    if settings.allow_lan {
        vec!["mixed-in".to_string()]
    } else {
        vec!["mixed-in".to_string(), "mixed-in-v6".to_string()]
    }
}

fn sniff_route_rules(_settings: &Settings, tun_enabled: bool) -> Vec<Value> {
    if !tun_enabled {
        return Vec::new();
    }
    // Keep the intercepted IP as the dial target while enriching flow metadata
    // from HTTP Host, TLS SNI, or QUIC.  DNS reverse mapping remains a labelled
    // correlation fallback when payload sniffing cannot provide a domain.
    vec![json!({
        "action": "sniff",
        "sniffer": ["http", "tls", "quic"],
        "timeout": "2s"
    })]
}

fn clash_dns_enabled(
    settings: &Settings,
    tun_enabled: bool,
    has_rules: bool,
) -> bool {
    tun_enabled && (has_rules || !settings.subscriptions.is_empty())
}

fn dns_config(
    settings: &Settings,
    _tun_enabled: bool,
    has_rules: bool,
    clash_dns: bool,
) -> Value {
    if !clash_dns {
        return json!({
            "servers": [
                { "type": "local", "tag": "local-dns" }
            ],
            "final": "local-dns",
            "strategy": "prefer_ipv4"
        });
    }

    let dns_rules = rules::clash_dns_rules(has_rules);

    let _ = settings;
    json!({
        "servers": [
            { "type": "udp", "tag": "dns-direct", "server": "223.5.5.5" },
            { "type": "udp", "tag": "dns-direct-alt", "server": "114.114.114.114" },
            {
                "type": "fakeip",
                "tag": "fake-ip",
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18"
            }
        ],
        "rules": dns_rules,
        "final": "dns-direct",
        "strategy": "prefer_ipv4",
        "reverse_mapping": true
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::settings::{
        DomainRuleFile, MeshConfig, MeshRole, Settings, StackFlags,
    };

    fn install_cached_test_subscription(settings: &mut Settings) {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        settings.data_dir = std::env::temp_dir().join(format!(
            "zay-builder-test-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        settings.subscriptions = vec!["http://127.0.0.1:9/unavailable".into()];
        let cache = settings.subscription_cache_path(0);
        fs::create_dir_all(cache.parent().unwrap()).unwrap();
        fs::write(
            cache,
            r#"proxies:
  - name: test-node
    type: ss
    server: 192.0.2.1
    port: 8388
    cipher: aes-128-gcm
    password: test-password
  - name: backup-node
    type: ss
    server: 192.0.2.2
    port: 8389
    cipher: aes-128-gcm
    password: backup-password
"#,
        )
        .unwrap();
    }

    #[test]
    fn domain_rule_generates_restricted_urltest_and_route() {
        let settings = Settings {
            subscriptions: Vec::new(),
            active_nodes: Vec::new(),
            data_dir: PathBuf::from("/tmp/zay-singbox-test"),
            mixed_port: 17890,
            allow_lan: false,
            tun: false,
            log_level: "info".into(),
            health_check_url: "https://health.example/204".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: vec![DomainRuleFile {
                enabled: true,
                name: "cursor".into(),
                by_suffix: vec!["cursor.com".into(), "cursor.sh".into()],
                outbounds: vec!["sg-1".into(), "sg-2".into()],
                health_check_url: None,
                interval: Some(60),
                tolerance: Some(50),
                ..DomainRuleFile::default()
            }],
            mesh: None,
            stack: StackFlags::default(),
        };

        let (outbounds, routes) = build_domain_rule_groups(
            &settings,
            &["sg-1".into(), "sg-2".into()],
            "Proxy",
        )
        .unwrap();
        assert_eq!(outbounds[0]["tag"], "domain-proxy:cursor");
        assert_eq!(outbounds[0]["outbounds"], json!(["sg-1", "sg-2"]));
        assert_eq!(outbounds[0]["interval"], "60s");
        assert_eq!(routes[0]["outbound"], "domain-proxy:cursor");
        assert_eq!(
            routes[0]["domain_suffix"],
            json!(["cursor.com", "cursor.sh"])
        );
    }

    #[test]
    fn domain_rule_filters_unavailable_nodes() {
        let settings = Settings {
            subscriptions: Vec::new(),
            active_nodes: Vec::new(),
            data_dir: PathBuf::from("/tmp/zay-singbox-test"),
            mixed_port: 17890,
            allow_lan: false,
            tun: false,
            log_level: "info".into(),
            health_check_url: "https://health.example/204".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: vec![DomainRuleFile {
                enabled: true,
                name: "cursor".into(),
                by_suffix: vec!["cursor.com".into()],
                outbounds: vec!["missing".into(), "sg-1".into()],
                health_check_url: None,
                interval: None,
                tolerance: None,
                ..DomainRuleFile::default()
            }],
            mesh: None,
            stack: StackFlags::default(),
        };

        let (outbounds, routes) =
            build_domain_rule_groups(&settings, &["sg-1".into()], "Proxy")
                .unwrap();
        assert_eq!(outbounds[0]["outbounds"], json!(["sg-1"]));
        assert_eq!(routes[0]["outbound"], "domain-proxy:cursor");
    }

    #[test]
    fn domain_rule_falls_back_when_all_configured_nodes_disappear() {
        let settings = Settings {
            subscriptions: Vec::new(),
            active_nodes: Vec::new(),
            data_dir: PathBuf::from("/tmp/zay-singbox-test"),
            mixed_port: 17890,
            allow_lan: false,
            tun: false,
            log_level: "info".into(),
            health_check_url: "https://health.example/204".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: vec![DomainRuleFile {
                enabled: true,
                name: "github-fast".into(),
                by_suffix: vec!["github.com".into()],
                outbounds: vec!["renamed-node".into()],
                health_check_url: None,
                interval: None,
                tolerance: None,
                ..DomainRuleFile::default()
            }],
            mesh: None,
            stack: StackFlags::default(),
        };

        let (outbounds, routes) = build_domain_rule_groups(
            &settings,
            &["current-node".into()],
            "Proxy",
        )
        .unwrap();
        assert!(outbounds.is_empty());
        assert_eq!(routes[0]["domain_suffix"], json!(["github.com"]));
        assert_eq!(routes[0]["outbound"], "Proxy");
    }

    #[test]
    fn custom_rule_supports_connection_matchers() {
        let policy = DomainRuleFile {
            enabled: true,
            name: "selected-connection".into(),
            host: vec!["api.example.com".into(), "*.example.net".into()],
            process: vec!["curl".into(), "/usr/bin/git".into()],
            source: vec!["10.14.14.1:53000".into()],
            destination: vec!["203.0.113.8:443".into()],
            outbounds: vec!["node-a".into()],
            ..DomainRuleFile::default()
        };

        let route =
            custom_rule_route(&policy, "domain-proxy:selected-connection")
                .unwrap();
        assert_eq!(route["domain"], json!(["api.example.com"]));
        assert_eq!(route["domain_suffix"], json!(["example.net"]));
        assert_eq!(route["process_name"], json!(["curl"]));
        assert_eq!(route["process_path"], json!(["/usr/bin/git"]));
        assert_eq!(route["source_ip_cidr"], json!(["10.14.14.1/32"]));
        assert_eq!(route["source_port"], json!([53000]));
        assert_eq!(route["ip_cidr"], json!(["203.0.113.8/32"]));
        assert_eq!(route["port"], json!([443]));
    }

    #[test]
    fn mesh_excludes_routes_from_singbox_tun() {
        let mut settings = Settings {
            subscriptions: Vec::new(),
            active_nodes: Vec::new(),
            data_dir: PathBuf::from("/tmp/zay-singbox-test"),
            mixed_port: 17890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://www.gstatic.com/generate_204".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: Vec::new(),
            mesh: Some(MeshConfig {
                enabled: true,
                role: MeshRole::Node,
                name: None,
                network_name: "my-network".into(),
                network_secret: "change-me".into(),
                dhcp: None,
                ipv4: Some("10.126.126.10/24".into()),
                listeners: None,
                peers: None,
                proxy_networks: None,
                mesh_routes: Some(vec!["10.126.126.0/24".into()]),
                wireguard_listen: Some("127.0.0.1:51820".into()),
                wireguard_client_cidr: None,
                wireguard_client_address: None,
            }),
            stack: StackFlags {
                mesh: Some(MeshRole::Node),
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };
        install_cached_test_subscription(&mut settings);

        let json = build_config(&settings, false).unwrap();
        assert!(!json.contains("\"easytier-wg\""));
        assert!(!json.contains("\"type\": \"wireguard\""));
        assert!(json.contains("10.126.126.0/24"));
        assert!(json.contains("\"type\": \"tun\""));
        assert!(json.contains("\"auto_route\": true"));
        assert!(json.contains("\"route_exclude_address\""));
        // Mesh CIDR must be excluded so EasyTier edge TUN owns it.
        assert!(json.contains("10.126.126.0/24"));
        assert!(json.contains(&tun_route::tun_address(&settings)));
        assert_eq!(tun_route::tun_route_address(&settings), None);
        assert!(!json.contains("\"system\": false"));
    }

    #[test]
    fn mesh_hub_skips_singbox_tun() {
        let settings = Settings {
            subscriptions: Vec::new(),
            active_nodes: Vec::new(),
            data_dir: PathBuf::from("/tmp/zay-singbox-test"),
            mixed_port: 17890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://www.gstatic.com/generate_204".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: Vec::new(),
            mesh: Some(MeshConfig {
                enabled: true,
                role: MeshRole::Relay,
                name: None,
                network_name: "my-network".into(),
                network_secret: "change-me".into(),
                dhcp: None,
                ipv4: None,
                listeners: Some(vec![
                    "tcp://0.0.0.0:11010".into(),
                    "udp://0.0.0.0:11010".into(),
                ]),
                peers: None,
                proxy_networks: None,
                mesh_routes: None,
                wireguard_listen: None,
                wireguard_client_cidr: None,
                wireguard_client_address: None,
            }),
            stack: StackFlags {
                mesh: Some(MeshRole::Relay),
                gateway: false,
                tun: true,
                no_rules: true,
            },
        };

        let json = build_config(&settings, false).unwrap();
        assert!(!json.contains("\"type\": \"tun\""));
        assert!(!json.contains("\"easytier-wg\""));
        assert!(!json.contains("10.126.126.0/24"));
        assert!(!json.contains("\"port\": 53"));
        assert!(!json.contains("\"outbound\": \"any\""));
        assert!(json.contains("\"default_domain_resolver\": \"local-dns\""));
    }

    #[test]
    fn clash_rules_use_direct_final_blacklist() {
        let mut settings = Settings {
            subscriptions: Vec::new(),
            active_nodes: Vec::new(),
            data_dir: PathBuf::from("/tmp/zay-singbox-test"),
            mixed_port: 17890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://example.com".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: Vec::new(),
            mesh: None,
            stack: StackFlags {
                mesh: None,
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };
        install_cached_test_subscription(&mut settings);
        let with_rules = build_config(&settings, true).unwrap();
        assert!(with_rules.contains("\"final\": \"direct\""));
        assert!(with_rules.contains("\"gfw\""));
        assert!(with_rules.contains("\"geoip-cn\""));
        assert!(with_rules.contains("\"geosite-cn\""));
        assert!(with_rules.contains("\"reverse_mapping\": true"));
        assert!(with_rules.contains("\"fake-ip\""));
        assert!(with_rules.contains("\"store_fakeip\": true"));
        assert!(with_rules.contains("\"type\": \"logical\""));

        let rules = serde_json::from_str::<Value>(&with_rules).unwrap();
        let inbounds = rules["inbounds"].as_array().unwrap();
        assert!(inbounds.iter().any(|inbound| {
            inbound.get("type").and_then(Value::as_str) == Some("tun")
        }));
        assert!(!inbounds.iter().any(|inbound| {
            inbound.get("type").and_then(Value::as_str) == Some("mixed")
        }));
        let route_rules = rules["route"]["rules"].as_array().unwrap();
        let health_route = health_check_route(&settings, "Proxy").unwrap();
        assert_eq!(health_route["domain"][0], "example.com");
        assert_eq!(health_route["outbound"], "Proxy");
        let reject_idx = route_rules
            .iter()
            .position(|r| {
                r.get("action").and_then(|a| a.as_str()) == Some("reject")
            })
            .unwrap();
        let icloud_idx = route_rules
            .iter()
            .position(|r| {
                r.get("rule_set")
                    .and_then(|s| s.as_array())
                    .is_some_and(|a| {
                        a.first().and_then(|v| v.as_str()) == Some("icloud")
                    })
            })
            .unwrap();
        assert!(
            reject_idx < icloud_idx,
            "reject must precede icloud (Mihomo order)"
        );
        let gfw_idx =
            route_rules
                .iter()
                .position(|r| {
                    r.get("rule_set").and_then(|s| s.as_array()).is_some_and(
                        |a| a.iter().any(|v| v.as_str() == Some("gfw")),
                    )
                })
                .unwrap();
        let cncidr_idx = route_rules
            .iter()
            .position(|r| {
                r.get("rule_set")
                    .and_then(|s| s.as_array())
                    .is_some_and(|a| {
                        a.first().and_then(|v| v.as_str()) == Some("cncidr")
                    })
            })
            .unwrap();
        assert!(
            gfw_idx < cncidr_idx,
            "gfw must precede cncidr (blocked domains → Proxy before CN IP → direct)"
        );
        let dns_rules = rules["dns"]["rules"].as_array().unwrap();
        let gfw_dns = dns_rules.iter().any(|r| {
            r.get("rule_set")
                .and_then(|s| s.as_array())
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("gfw")))
                && r.get("server").and_then(|v| v.as_str())
                    == Some("dns-direct")
        });
        assert!(gfw_dns, "gfw DNS queries must use dns-direct, not fake-ip");

        let without_rules = build_config(&settings, false).unwrap();
        assert!(without_rules.contains("\"reverse_mapping\": true"));
    }

    #[test]
    fn active_nodes_restrict_the_auto_candidate_pool() {
        let mut settings = Settings {
            subscriptions: Vec::new(),
            active_nodes: vec!["sub0-backup-node".into()],
            data_dir: PathBuf::from("/tmp/zay-singbox-test"),
            mixed_port: 17890,
            allow_lan: false,
            tun: false,
            log_level: "info".into(),
            health_check_url: "https://example.com/generate_204".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: Vec::new(),
            mesh: None,
            stack: StackFlags::default(),
        };
        install_cached_test_subscription(&mut settings);
        let config = build_value(&settings, false).unwrap();
        let auto = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outbound| outbound["tag"] == "Auto")
            .unwrap();
        assert_eq!(auto["outbounds"], json!(["sub0-backup-node"]));
        assert!(
            config["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|outbound| outbound["tag"] == "sub0-test-node")
        );
    }
}

pub fn config_has_tun(config_json: &str) -> bool {
    serde_json::from_str::<Value>(config_json)
        .ok()
        .and_then(|v| v.get("inbounds").cloned())
        .map(|inbounds| {
            inbounds.as_array().is_some_and(|arr| {
                arr.iter().any(|ib| {
                    ib.get("type").and_then(|t| t.as_str()) == Some("tun")
                })
            })
        })
        .unwrap_or(false)
}
