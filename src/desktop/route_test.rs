use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use singbox_core::{
    common::network::{Network, SocksAddr},
    route::{Metadata, Router},
};

use crate::{
    ProxyOpts,
    settings::{self, StackFlags},
    singbox::{builder, mixin, rules, subscription},
};

#[derive(Clone, Debug, Serialize)]
pub struct RouteTest {
    pub destination: String,
    pub route: String,
    pub matched_rule: String,
    pub detail: String,
    pub note: String,
}

fn destination(raw: &str) -> Result<(SocksAddr, String)> {
    let raw = raw.trim();
    ensure!(!raw.is_empty(), "Enter a URL, domain or IP address.");
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok((SocksAddr::Ip(SocketAddr::new(ip, 443)), "tls".into()));
    }
    if let Ok(address) = raw.parse::<SocketAddr>() {
        return Ok((address.into(), String::new()));
    }
    let value = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url =
        url::Url::parse(&value).context("Enter a valid URL or IP address.")?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "Use an HTTP or HTTPS URL, domain or IP address."
    );
    let host = url
        .host_str()
        .context("The URL needs a destination host.")?;
    ensure!(
        !host.chars().any(char::is_whitespace),
        "The destination host cannot contain spaces."
    );
    Ok((
        SocksAddr::new(
            host.trim_matches(['[', ']']),
            url.port_or_known_default().unwrap_or(443),
        ),
        if url.scheme() == "http" {
            "http"
        } else {
            "tls"
        }
        .into(),
    ))
}

pub(super) fn evaluate(
    data_dir: &Path,
    config_path: &Path,
    target: &str,
) -> Result<RouteTest> {
    let (destination, protocol) = destination(target)?;
    let cli = ProxyOpts {
        data_dir: Some(data_dir.to_owned()),
        config: Some(config_path.to_owned()),
        ..Default::default()
    };
    let settings = settings::resolve_stack(&cli, StackFlags::default())?;
    let nodes = subscription::load_cached_nodes(&settings)?;
    ensure!(
        settings.subscriptions.is_empty() || !nodes.is_empty(),
        "No cached proxy nodes. Refresh the subscription before testing routing."
    );
    let inventory = super::node_inventory(nodes.clone());
    rules::ensure_embedded_rules(&settings)?;
    let base = builder::build_value_with_nodes(
        &settings,
        rules::files_present(&settings.singbox_dir()),
        nodes,
    )?;
    let config: serde_json::Value = serde_json::from_str(
        &mixin::merge_config(&base.to_string(), &settings)?,
    )?;
    let route = &config["route"];
    let route_rules = route["rules"].as_array().cloned().unwrap_or_default();
    let sets = route["rule_set"].as_array().cloned().unwrap_or_default();
    ensure!(
        !sets.iter().any(|set| set["type"] == "remote"),
        "This configuration uses remote rule sets. Routing preview needs local rule sets; no network request was made."
    );
    let router = Router::from_json_with_rule_sets(
        &route_rules,
        route["final"].as_str().unwrap_or("direct"),
        &sets,
        &settings.singbox_dir(),
    )?;
    let mode = config
        .pointer("/experimental/clash_api/default_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("rule");
    let metadata = Metadata {
        destination: Some(destination.clone()),
        network: Some(Network::Tcp),
        protocol,
        inbound: if crate::singbox::tun_route::singbox_tun_enabled(&settings) {
            "tun-in"
        } else {
            "mixed-in"
        }
        .into(),
        clash_mode: mode.into(),
        ..Default::default()
    };
    let preview = router.preview_route(&metadata);
    let outbound = preview["outbound"].as_str().unwrap_or("direct");
    let index = preview["rule_index"].as_u64().map(|i| i as usize);
    let custom = index.and_then(|i| {
        settings
            .domain_rule
            .iter()
            .filter(|p| p.enabled)
            .find(|policy| {
                builder::custom_rule_route(
                    policy,
                    route_rules[i]["outbound"].as_str().unwrap_or(""),
                )
                .ok()
                .as_ref()
                    == Some(&route_rules[i])
            })
    });
    let matched_rule = custom.map(|p| p.name.clone()).unwrap_or_else(|| {
        index
            .map(|i| format!("Rule {}", i + 1))
            .unwrap_or_else(|| "Default route".into())
    });
    let route_label = if preview["blocked"] == true {
        "Blocked".into()
    } else if preview["direct"] == true {
        "Direct".into()
    } else if preview["action"] == "hijack-dns" {
        "Local DNS".into()
    } else {
        let group = config["outbounds"].as_array().and_then(|outbounds| {
            outbounds.iter().find(|o| o["tag"] == outbound)
        });
        let selection = group
            .and_then(|o| o["default"].as_str())
            .unwrap_or(outbound);
        let name = if selection == "Auto" {
            "Automatic pool".to_owned()
        } else {
            inventory
                .iter()
                .find(|node| node.id == selection)
                .map(|node| node.name.clone())
                .unwrap_or_else(|| selection.to_owned())
        };
        format!("Proxy · {name}")
    };
    Ok(RouteTest {
        destination: destination.to_string(),
        route: route_label,
        matched_rule,
        detail: preview["rule"]
            .as_str()
            .unwrap_or("No rule matched; using the final route.")
            .into(),
        note: format!(
            "Saved configuration · {} mode · TCP preview. No connection was opened. {}",
            if mode == "rule" { "Rules" } else { mode },
            if matches!(destination, SocksAddr::Domain { .. }) {
                "DNS results and process/source rules can change a real connection’s route."
            } else {
                "Process/source rules can change a real connection’s route."
            }
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_ipv6_and_urls_without_resolving_or_retaining_credentials() {
        assert_eq!(
            destination("2001:db8::1").unwrap().0.to_string(),
            "[2001:db8::1]:443"
        );
        assert_eq!(
            destination(
                "https://name:secret@example.com:8443/path?token=secret"
            )
            .unwrap()
            .0
            .to_string(),
            "example.com:8443"
        );
        assert!(destination("file:///tmp/config").is_err());
        assert!(destination("").is_err());
    }
}
