use std::path::PathBuf;

use async_channel::{Receiver, Sender};
use zay::{
    desktop::{Client, ProxyNode},
    settings::{DomainRuleFile, PersistentProxyFile},
};

#[derive(Clone, Copy)]
pub enum Service {
    Proxy,
    Mesh,
}

#[derive(Clone, Copy)]
pub enum ServiceAction {
    Start,
    Pause,
    Stop,
}

pub fn set_service_state(
    config: &mut PersistentProxyFile,
    service: Service,
    action: ServiceAction,
) {
    let enabled = matches!(action, ServiceAction::Start);
    let paused = matches!(action, ServiceAction::Pause);
    match service {
        Service::Proxy => {
            config.enabled = enabled;
            config.paused = paused;
        }
        Service::Mesh => {
            if let Some(mesh) = &mut config.mesh {
                mesh.enabled = enabled;
            }
            config.mesh_paused = paused;
        }
    }
}

pub enum Command {
    Start(Option<Box<PersistentProxyFile>>),
    ControlService(Box<PersistentProxyFile>, ServiceAction),
    Save(Box<PersistentProxyFile>),
    RefreshProxies,
    AddSubscription(String),
    RemoveSubscription(usize),
    TestMesh(Box<zay::settings::MeshConfig>),
    TestRoute(String),
    SelectProxies(Vec<String>),
    UpsertRule(DomainRuleFile),
    DeleteRule(String),
    RouteConnection(serde_json::Value, Option<String>),
    ProcessTraffic(&'static str),
    Shutdown,
}

pub struct Update {
    pub config: Option<PersistentProxyFile>,
    pub retry_config: Option<PersistentProxyFile>,
    pub status: String,
    pub running: bool,
    pub proxy_ready: bool,
    pub tun_active: bool,
    pub mesh: serde_json::Value,
    pub proxies: Vec<ProxyNode>,
    pub connections: serde_json::Value,
    pub process_traffic: serde_json::Value,
    pub process_traffic_error: Option<String>,
    pub logs: Vec<String>,
    pub telemetry_error: Option<String>,
    pub proxy_error: Option<String>,
    pub error: Option<String>,
    pub action_error: Option<String>,
    pub finished: bool,
    pub quit: bool,
    pub mesh_test: Option<String>,
    pub route_test: Option<zay::desktop::RouteTest>,
}

pub fn launch(
    data_dir: PathBuf,
) -> (
    Sender<Command>,
    Receiver<Update>,
    std::sync::mpsc::Receiver<()>,
) {
    let (sender, receiver) = async_channel::unbounded();
    let (events, updates) = async_channel::unbounded();
    let (finished, stopped) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime =
            tokio::runtime::Runtime::new().expect("create networking runtime");
        runtime.block_on(async move {
            let configured = data_dir.join(zay::settings::ZAY_TOML_FILE).exists();
            let mut client = match Client::new(data_dir) {
                Ok(client) => client,
                Err(error) => {
                    let _ = events.send(Update {process_traffic: serde_json::json!({}), process_traffic_error: None, connections: serde_json::json!({}), logs: vec![], telemetry_error: None, proxies: vec![], proxy_error: None, config: None, retry_config: None, status: "Unavailable".into(), running:false, proxy_ready:false, tun_active:false, mesh: serde_json::json!([]), error:Some(format!("{error:#}")), action_error:None, finished:true, quit:false, mesh_test:None, route_test:None}).await;
                    return;
                }
            };
            // Fresh installs wait for the user to enable a connection. Existing
            // enabled configurations resume automatically, with no global start button.
            let startup = async {
                let mut config = client.config()?;
                if !configured { config.enabled = false; client.save(&config)?; }
                if connections_enabled(&config) { client.start(None).await?; if config.enabled { client.sync_proxy_selection().await?; } }
                Ok::<_, anyhow::Error>(())
            }.await;
            let mut retry_config = startup.as_ref().err().and_then(|_| client.config().ok());
            let mut startup = Some(startup);
            let mut last_subscriptions = client.config().map(|c| c.subscriptions).unwrap_or_default();
            let mut proxy_error = None;
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                let mut mesh_test = None;
                let mut route_test = None;
                let (result, finished, quit) = if let Some(result) = startup.take() {
                    (result, true, false)
                } else { tokio::select! {
                    command = receiver.recv() => match command {
                        Ok(Command::Start(config)) => {
                            retry_config = config.as_deref().cloned().or_else(|| client.config().ok());
                            let result = match config {
                                Some(config) => apply_change(&mut client, &config, true).await,
                                None => client.start(None).await,
                            };
                            (result, true, false)
                        }
                        Ok(Command::Save(config)) => {
                            retry_config = Some((*config).clone());
                            (apply_change(&mut client, &config, false).await, true, false)
                        }
                        Ok(Command::ControlService(config, action)) => {
                            retry_config = Some((*config).clone());
                            let result = if !matches!(action, ServiceAction::Start) && !client.status().await.running {
                                // Stopping one service must never start or authorize
                                // another configured service after a failed startup.
                                client.save(&config)
                            } else { apply_change(&mut client, &config, false).await };
                            (result, true, false)
                        }
                        Ok(Command::TestRoute(target)) => {
                            let result = client.test_route(target).await;
                            route_test = result.as_ref().ok().cloned();
                            (result.map(|_| ()), true, false)
                        }
                        Ok(Command::TestMesh(mesh)) => {
                            let result = Client::test_mesh_connection(*mesh).await;
                            mesh_test = result.as_ref().ok().cloned();
                            (result.map(|_| ()), true, false)
                        }
                        Ok(Command::AddSubscription(url)) => {
                            let mut config = client.config().expect("loaded config");
                            if !config.subscriptions.contains(&url) { config.subscriptions.push(url); }
                            (apply_change(&mut client, &config, false).await, true, false)
                        }
                        Ok(Command::RemoveSubscription(index)) => {
                            let mut config = client.config().expect("loaded config");
                            if index < config.subscriptions.len() {
                                config.subscriptions.remove(index);
                                config.active_nodes.clear();
                            }
                            (apply_change(&mut client, &config, false).await, true, false)
                        }
                        Ok(Command::RefreshProxies) => {
                            let result = client.refresh_proxy_nodes().await.map(|_| ());
                            proxy_error = result.as_ref().err().map(|e| format!("{e:#}"));
                            (result, true, false)
                        }
                        Ok(Command::SelectProxies(ids)) => (select_proxies(&mut client, ids).await, true, false),
                        Ok(Command::UpsertRule(rule)) => {
                            let mut config = client.config().expect("loaded config");
                            if let Some(existing) = config.domain_rule.iter_mut().find(|r| r.name == rule.name) { *existing = rule; } else { config.domain_rule.insert(0, rule); }
                            (apply_change(&mut client, &config, false).await, true, false)
                        }
                        Ok(Command::DeleteRule(name)) => {
                            let mut config = client.config().expect("loaded config");
                            config.domain_rule.retain(|r| r.name != name);
                            (apply_change(&mut client, &config, false).await, true, false)
                        }
                        Ok(Command::RouteConnection(connection, target)) => (route_connection(&mut client, connection, target).await, true, false),
                        Ok(Command::ProcessTraffic(action)) => (client.set_process_traffic(action).await.map(|_| ()), true, false),
                        Ok(Command::Shutdown) | Err(_) => (client.shutdown().await, true, true),
                    },
                    _ = timer.tick() => (Ok(()), false, false),
                }};
                if finished && result.is_ok() { retry_config = None; }
                let subscriptions = client.config().map(|c| c.subscriptions).unwrap_or_default();
                if subscriptions != last_subscriptions {
                    proxy_error = if client.status().await.running && client.config().is_ok_and(|c| c.enabled) {
                        None // Applying the running proxy already refreshed its subscriptions.
                    } else {
                        client.refresh_proxy_nodes().await.err().map(|e| format!("{e:#}"))
                    };
                    last_subscriptions = subscriptions;
                }
                let proxies = match client.proxy_nodes(false).await {
                    Ok(nodes) => nodes,
                    Err(error) => { proxy_error = Some(format!("{error:#}")); Vec::new() }
                };
                let status = client.status().await;
                let mesh = client.mesh_status().await;
                let action_error = result.as_ref().err().map(|e| format!("{e:#}"));
                let error = result.err().map(|e| format!("{e:#}")).or(status.error.clone()).or_else(|| mesh.as_ref().err().map(|e| format!("{e:#}")));
                // A failed health URL must not hide live traffic: inspection is
                // most useful while the proxy reports degraded health.
                let (connections, telemetry_error) = if status.running && client.config().is_ok_and(|c| c.enabled) {
                    match client.connections().await { Ok(value) => (value, None), Err(error) => (serde_json::json!({}), Some(format!("{error:#}"))) }
                } else { (serde_json::json!({}), None) };
                let (process_traffic, process_traffic_error) = match client.process_traffic().await {
                    Ok(value) => (value, None),
                    Err(error) => (serde_json::json!({}), Some(format!("{error:#}"))),
                };
                let update = Update {
                    process_traffic, process_traffic_error, connections, telemetry_error, logs: client.recent_logs().unwrap_or_default(),
                    proxies, proxy_error: proxy_error.clone(),
                    tun_active: status.tun_active(),
                    config: client.config().ok(), retry_config: retry_config.clone(), status: format!("{:?}", status.health),
                    running: status.running, proxy_ready: status.stack.as_ref().is_some_and(|s| s.proxy_ready),
                    mesh: mesh.unwrap_or_else(|_| serde_json::json!([])), error, action_error, finished, quit, mesh_test, route_test,
                };
                if events.send(update).await.is_err() || quit { let _ = client.shutdown().await; break; }
            }
        });
        drop(runtime);
        let _ = finished.send(());
    });
    (sender, updates, stopped)
}

// Keep rejected changes out of the saved configuration, including when the
// user cancels the macOS authorization dialog. Never retry elevation silently.
async fn apply_change(
    client: &mut Client,
    config: &PersistentProxyFile,
    start: bool,
) -> anyhow::Result<()> {
    let previous = client.config()?;
    client.save(config)?;
    let result = if !connections_enabled(config) {
        client.stop().await
    } else if start || !client.status().await.running {
        client.start(None).await
    } else {
        client
            .apply(None)
            .await
            .and_then(|result| match result.error {
                Some(error) => Err(anyhow::anyhow!(error)),
                None => Ok(()),
            })
    };
    let result = match result {
        Ok(()) if config.enabled && client.status().await.running => {
            client.sync_proxy_selection().await
        }
        other => other,
    };
    finish_change(client, &previous, result)
}

fn finish_change(
    client: &Client,
    previous: &PersistentProxyFile,
    result: anyhow::Result<()>,
) -> anyhow::Result<()> {
    if let Err(error) = result {
        client.save(previous).map_err(|restore| {
            anyhow::anyhow!(
                "{error:#}; could not restore settings: {restore:#}"
            )
        })?;
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_controls_retain_settings_and_do_not_stop_the_other_service() {
        let mut config = PersistentProxyFile::default();
        config.enabled = true;
        config.tun.enabled = true;
        config.mesh = Some(serde_json::from_value(serde_json::json!({
            "enabled":true, "role":"node", "network_name":"lab", "network_secret":"fixture"
        })).unwrap());
        set_service_state(&mut config, Service::Proxy, ServiceAction::Pause);
        assert!(!config.enabled && config.paused);
        assert!(config.tun.enabled);
        assert!(config.mesh.as_ref().unwrap().enabled);
        let saved = toml::to_string(&config).unwrap();
        let mut config: PersistentProxyFile = toml::from_str(&saved).unwrap();
        assert!(config.paused);
        set_service_state(&mut config, Service::Proxy, ServiceAction::Start);
        assert!(config.enabled && !config.paused);
        set_service_state(&mut config, Service::Mesh, ServiceAction::Pause);
        assert!(config.enabled && config.mesh_paused);
        assert!(!config.mesh.as_ref().unwrap().enabled);
        set_service_state(&mut config, Service::Mesh, ServiceAction::Stop);
        assert!(!config.mesh_paused);
        assert_eq!(config.mesh.as_ref().unwrap().network_name, "lab");
        set_service_state(&mut config, Service::Mesh, ServiceAction::Start);
        assert!(config.mesh.as_ref().unwrap().enabled);
    }

    #[tokio::test]
    async fn stopped_text_edit_persists_without_starting_services() {
        let dir = std::env::temp_dir()
            .join(format!("zay-desktop-edit-{}", std::process::id()));
        let mut client = Client::new(dir.clone()).unwrap();
        let mut config = client.config().unwrap();
        config.enabled = false;
        config.mixed_port = Some(17891);
        apply_change(&mut client, &config, false).await.unwrap();
        assert_eq!(client.config().unwrap().mixed_port, Some(17891));
        assert!(!client.status().await.running);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn cached_subscription_selection_and_url_changes() {
        let dir = std::env::temp_dir()
            .join(format!("zay-desktop-nodes-{}", std::process::id()));
        let mut client = Client::new(dir.clone()).unwrap();
        let mut config = client.config().unwrap();
        config.enabled = false;
        config.subscriptions =
            vec!["https://example.invalid/subscription".into()];
        client.save(&config).unwrap();
        let providers = dir.join("singbox/providers");
        std::fs::create_dir_all(&providers).unwrap();
        std::fs::write(providers.join("sub0.yaml"), "proxies:\n  - name: Test proxy\n    type: ss\n    server: example.invalid\n    port: 443\n    cipher: aes-128-gcm\n    password: test-only\n").unwrap();
        let nodes = client.proxy_nodes(false).await.unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Test proxy");
        assert!(!serde_json::to_string(&nodes).unwrap().contains("test-only"));
        select_proxy(&mut client, Some(nodes[0].id.clone()))
            .await
            .unwrap();
        assert_eq!(
            client.config().unwrap().active_nodes,
            vec![nodes[0].id.clone()]
        );
        assert!(
            select_proxy(&mut client, Some("missing".into()))
                .await
                .is_err()
        );
        select_proxy(&mut client, None).await.unwrap();
        assert!(client.config().unwrap().active_nodes.is_empty());
        config.subscriptions[0] = "https://example.invalid/replacement".into();
        client.save(&config).unwrap();
        assert!(client.proxy_nodes(false).await.unwrap().is_empty());
        assert!(!client.status().await.running);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejected_change_restores_saved_settings() {
        let dir = std::env::temp_dir()
            .join(format!("zay-desktop-reject-{}", std::process::id()));
        let client = Client::new(dir.clone()).unwrap();
        let mut previous = client.config().unwrap();
        previous.tun.enabled = false;
        client.save(&previous).unwrap();
        let mut proposed = previous.clone();
        proposed.tun.enabled = true;
        client.save(&proposed).unwrap();
        let result = finish_change(
            &client,
            &previous,
            Err(anyhow::anyhow!("Authorization cancelled")),
        );
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        assert!(!client.config().unwrap().tun.enabled);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
async fn select_proxy(
    client: &mut Client,
    id: Option<String>,
) -> anyhow::Result<()> {
    select_proxies(client, id.into_iter().collect()).await
}

async fn select_proxies(
    client: &mut Client,
    ids: Vec<String>,
) -> anyhow::Result<()> {
    let nodes = client.proxy_nodes(false).await?;
    anyhow::ensure!(
        ids.iter().all(|id| nodes.iter().any(|node| &node.id == id)),
        "A selected proxy is unavailable. Refresh subscriptions."
    );
    let mut config = client.config()?;
    config.active_nodes = ids;
    apply_change(client, &config, false).await
}

async fn route_connection(
    client: &mut Client,
    connection: serde_json::Value,
    target: Option<String>,
) -> anyhow::Result<()> {
    let metadata = &connection["metadata"];
    let host = metadata["host"].as_str().unwrap_or("");
    let ip = metadata["destinationIP"].as_str().unwrap_or("");
    anyhow::ensure!(
        !host.is_empty() || !ip.is_empty(),
        "This connection has no routable destination"
    );
    let process = metadata["processPath"]
        .as_str()
        .filter(|v| !v.is_empty())
        .unwrap_or("");
    let name = format!(
        "Connection: {}{}",
        if host.is_empty() { ip } else { host },
        if process.is_empty() {
            String::new()
        } else {
            format!(" · {process}")
        }
    );
    let mut config = client.config()?;
    config.domain_rule.retain(|r| r.name != name);
    if let Some(target) = target {
        anyhow::ensure!(
            target == "Proxy"
                || target == "direct"
                || client
                    .proxy_nodes(false)
                    .await?
                    .iter()
                    .any(|n| n.id == target),
            "Proxy unavailable"
        );
        config.domain_rule.insert(
            0,
            DomainRuleFile {
                enabled: true,
                name,
                host: if host.is_empty() {
                    vec![]
                } else {
                    vec![host.into()]
                },
                destination: if host.is_empty() {
                    vec![format!(
                        "{ip}/{}",
                        if ip.contains(':') { 128 } else { 32 }
                    )]
                } else {
                    vec![]
                },
                process: if process.is_empty() {
                    vec![]
                } else {
                    vec![process.into()]
                },
                outbounds: vec![target],
                ..Default::default()
            },
        );
    }
    // Existing streams cannot move between remote endpoints. Reload rules and
    // reconnect; subsequent traffic for this destination uses the chosen route.
    apply_change(client, &config, false).await
}

fn connections_enabled(config: &PersistentProxyFile) -> bool {
    config.enabled || config.mesh.as_ref().is_some_and(|mesh| mesh.enabled)
}

#[cfg(test)]
mod defaults_tests {
    use super::*;

    #[tokio::test]
    async fn tun_defaults_on_and_saved_choice_survives_reopening_without_starting_services()
     {
        let dir = std::env::temp_dir()
            .join(format!("zay-tun-default-{}", std::process::id()));
        let client = Client::new(dir.clone()).unwrap();
        let mut config = client.config().unwrap();
        assert!(config.tun.enabled);
        assert!(!client.status().await.running);
        config.enabled = false;
        config.tun.enabled = false;
        client.save(&config).unwrap();
        drop(client);
        let client = Client::new(dir.clone()).unwrap();
        assert!(!client.config().unwrap().tun.enabled);
        assert!(!client.status().await.running);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod route_preview_tests {
    use super::*;

    #[tokio::test]
    async fn routing_preview_uses_saved_rules_and_cached_selection_without_starting_services()
     {
        let data = std::env::temp_dir().join(format!(
            "zay-route-preview-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let client = Client::new(data.clone()).unwrap();
        let mut config = client.config().unwrap();
        config.enabled = false;
        config.tun.enabled = false;
        config.routing_mode = "global".into();
        config.subscriptions =
            vec!["https://subscription.invalid/offline-only".into()];
        config.active_nodes = vec!["sub0-Lab B".into()];
        config.domain_rule = vec![
            DomainRuleFile {
                enabled: true,
                name: "Private lab".into(),
                host: vec!["lab.test".into()],
                outbounds: vec!["direct".into()],
                ..Default::default()
            },
            DomainRuleFile {
                enabled: true,
                name: "Lab addresses".into(),
                destination: vec!["192.0.2.0/24".into()],
                outbounds: vec!["direct".into()],
                ..Default::default()
            },
        ];
        client.save(&config).unwrap();
        let settings = zay::settings::resolve_stack(
            &zay::ProxyOpts {
                data_dir: Some(data.clone()),
                config: Some(client.config_path().to_owned()),
                ..Default::default()
            },
            zay::settings::StackFlags::default(),
        )
        .unwrap();
        let cache = settings.subscription_cache_path(0);
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::fs::write(cache, "proxies:\n  - {name: Lab A, type: http, server: 127.0.0.1, port: 17891}\n  - {name: Lab B, type: http, server: 127.0.0.1, port: 17893}\n").unwrap();
        let direct = client
            .test_route("https://user:secret@lab.test/path?token=secret".into())
            .await
            .unwrap();
        assert_eq!(direct.route, "Direct");
        assert_eq!(direct.matched_rule, "Private lab");
        assert_eq!(direct.destination, "lab.test:443");
        let proxy = client
            .test_route("https://other.test".into())
            .await
            .unwrap();
        assert_eq!(proxy.route, "Proxy · Lab B");
        assert!(proxy.detail.contains("global"));
        let ip = client.test_route("192.0.2.11".into()).await.unwrap();
        assert_eq!(ip.route, "Direct");
        assert_eq!(ip.matched_rule, "Lab addresses");
        assert!(
            client
                .test_route("file:///tmp/config".into())
                .await
                .is_err()
        );
        config.routing_mode = "direct".into();
        client.save(&config).unwrap();
        assert_eq!(
            client.test_route("other.test".into()).await.unwrap().route,
            "Direct"
        );
        config.routing_mode = "rules".into();
        client.save(&config).unwrap();
        assert_eq!(
            client.test_route("10.20.30.40".into()).await.unwrap().route,
            "Direct"
        );
        config.routing_mode = "global".into();
        config.domain_rule[0].enabled = false;
        client.save(&config).unwrap();
        assert_eq!(
            client.test_route("lab.test".into()).await.unwrap().route,
            "Proxy · Lab B"
        );
        assert_eq!(
            client
                .test_route("2001:db8::1".into())
                .await
                .unwrap()
                .destination,
            "[2001:db8::1]:443"
        );
        assert!(!client.status().await.running);
        std::fs::remove_dir_all(data).unwrap();
    }
}
