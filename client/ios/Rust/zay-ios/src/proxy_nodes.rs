//! List proxy nodes from a subscription / URI without building full sing-box config.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::proxy_url::{OutboundSpec, resolve_proxy};

/// JSON: `{ "mode": "single"|"many", "nodes": [...], "has_auto": bool }`
pub fn list_proxy_nodes_json(proxy_url: &str) -> Result<String> {
    let resolved = resolve_proxy(proxy_url, None, false)
        .with_context(|| format!("resolving proxy_url {proxy_url}"))?;

    let (mode, nodes, has_auto) = match resolved {
        OutboundSpec::Single(ob) => {
            let node = summarize_node(&ob, true)?;
            ("single".to_string(), vec![node], false)
        }
        OutboundSpec::Many(list) => {
            if list.is_empty() {
                bail!("subscription produced no proxy nodes");
            }
            let mut nodes = Vec::new();
            for ob in &list {
                nodes.push(summarize_node(ob, false)?);
            }
            ("many".to_string(), nodes, true)
        }
    };

    let out = json!({
        "mode": mode,
        "has_auto": has_auto,
        "auto_tag": if has_auto { "Auto" } else { "" },
        "selector_tag": "Proxy",
        "nodes": nodes,
    });
    serde_json::to_string(&out).context("serialize proxy nodes")
}

fn summarize_node(ob: &Value, is_only: bool) -> Result<Value> {
    let tag = ob
        .get("tag")
        .and_then(|t| t.as_str())
        .unwrap_or(if is_only { "proxy-node" } else { "node" })
        .to_string();
    let typ = ob
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown")
        .to_string();
    let server = ob
        .get("server")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    let port = ob
        .get("server_port")
        .and_then(|t| t.as_u64())
        .or_else(|| {
            ob.get("server_port")
                .and_then(|t| t.as_i64())
                .map(|v| v as u64)
        })
        .unwrap_or(0);
    Ok(json!({
        "tag": tag,
        "type": typ,
        "server": server,
        "port": port,
        "name": tag,
    }))
}
