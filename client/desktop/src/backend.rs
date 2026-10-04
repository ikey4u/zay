use std::path::PathBuf;

use async_channel::{Receiver, Sender};
use zay::{desktop::Client, settings::PersistentProxyFile};

pub enum Command {
    Start(Option<Box<PersistentProxyFile>>, Option<String>),
    Save(Box<PersistentProxyFile>, Option<String>),
    Stop,
    Shutdown,
}

pub struct Update {
    pub config: Option<PersistentProxyFile>,
    pub status: String,
    pub running: bool,
    pub proxy_ready: bool,
    pub mesh: serde_json::Value,
    pub error: Option<String>,
    pub finished: bool,
    pub quit: bool,
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
            let mut client = match Client::new(data_dir) {
                Ok(client) => client,
                Err(error) => {
                    let _ = events.send(Update {config: None, status: "Unavailable".into(), running:false, proxy_ready:false, mesh: serde_json::json!([]), error:Some(format!("{error:#}")), finished:true, quit:false}).await;
                    return;
                }
            };
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(3));
            loop {
                let (result, finished, quit) = tokio::select! {
                    command = receiver.recv() => match command {
                        Ok(Command::Start(config, password)) => {
                            let saved = config.as_ref().map(|config| client.save(config)).unwrap_or(Ok(()));
                            let result = match saved {Ok(()) => client.start(password).await, Err(e) => Err(e)};
                            (result, true, false)
                        }
                        Ok(Command::Save(config, password)) => {
                            let result = match client.save(&config) {Ok(()) => client.apply(password).await.map(|_| ()), Err(e) => Err(e)};
                            (result, true, false)
                        }
                        Ok(Command::Stop) => (client.stop().await, true, false),
                        Ok(Command::Shutdown) | Err(_) => (client.shutdown().await, true, true),
                    },
                    _ = timer.tick() => (Ok(()), false, false),
                };
                let status = client.status().await;
                let mesh = client.mesh_status().await;
                let error = result.err().map(|e| format!("{e:#}")).or(status.error.clone()).or_else(|| mesh.as_ref().err().map(|e| format!("{e:#}")));
                let update = Update {
                    config: client.config().ok(), status: format!("{:?}", status.health),
                    running: status.running, proxy_ready: status.stack.as_ref().is_some_and(|s| s.proxy_ready),
                    mesh: mesh.unwrap_or_else(|_| serde_json::json!([])), error, finished, quit,
                };
                if events.send(update).await.is_err() || quit { let _ = client.shutdown().await; break; }
            }
        });
        drop(runtime);
        let _ = finished.send(());
    });
    (sender, updates, stopped)
}
