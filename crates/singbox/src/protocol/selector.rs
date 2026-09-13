//! Runtime-switchable outbound selector.

use crate::{
    adapter::{
        DialFuture, Dialer, IcmpResponse, InterruptGenerations, IpPacketPort,
        NetworkDialOptions, PacketFuture, PacketStream, interruptible_packets,
        interruptible_stream,
    },
    common::network::SocksAddr,
    dns::persistent::PersistentDnsCache,
    protocol::urltest::GroupRegistry,
};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, RwLock},
};

pub struct SelectorOutbound {
    order: Vec<String>,
    choices: HashMap<String, Arc<dyn Dialer>>,
    selected: RwLock<String>,
    tag: String,
    persistent_cache: Option<Arc<PersistentDnsCache>>,
    interrupt_exist_connections: bool,
    generations: std::sync::Mutex<InterruptGenerations>,
    updates: Option<Arc<GroupRegistry>>,
}

impl SelectorOutbound {
    pub fn new(
        order: Vec<String>,
        choices: HashMap<String, Arc<dyn Dialer>>,
        selected: String,
        interrupt_exist_connections: bool,
    ) -> io::Result<Self> {
        Self::new_with_cache(
            String::new(),
            order,
            choices,
            selected,
            interrupt_exist_connections,
            None,
        )
    }

    pub fn new_with_cache(
        tag: String,
        order: Vec<String>,
        choices: HashMap<String, Arc<dyn Dialer>>,
        selected: String,
        interrupt_exist_connections: bool,
        persistent_cache: Option<Arc<PersistentDnsCache>>,
    ) -> io::Result<Self> {
        Self::new_with_cache_and_updates(
            tag,
            order,
            choices,
            selected,
            interrupt_exist_connections,
            persistent_cache,
            None,
        )
    }

    pub(crate) fn new_with_cache_and_updates(
        tag: String,
        order: Vec<String>,
        choices: HashMap<String, Arc<dyn Dialer>>,
        selected: String,
        interrupt_exist_connections: bool,
        persistent_cache: Option<Arc<PersistentDnsCache>>,
        updates: Option<Arc<GroupRegistry>>,
    ) -> io::Result<Self> {
        if order.is_empty() {
            return Err(invalid_input("selector outbound list is empty"));
        }
        if !order.iter().all(|tag| choices.contains_key(tag)) {
            return Err(invalid_input(
                "selector is missing a constructed outbound",
            ));
        }
        if !choices.contains_key(&selected) {
            return Err(invalid_input(format!(
                "selector default outbound not found: {selected}"
            )));
        }
        let selected = persistent_cache
            .as_ref()
            .filter(|_| !tag.is_empty())
            .and_then(|cache| cache.load_selected(&tag).ok().flatten())
            .filter(|selected| choices.contains_key(selected))
            .unwrap_or(selected);
        Ok(Self {
            order,
            choices,
            selected: RwLock::new(selected),
            tag,
            persistent_cache,
            interrupt_exist_connections,
            generations: std::sync::Mutex::new(InterruptGenerations::default()),
            updates,
        })
    }

    pub fn select(&self, tag: &str) -> io::Result<()> {
        if !self.choices.contains_key(tag) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("selector outbound not found: {tag}"),
            ));
        }
        let mut selected =
            self.selected.write().expect("selector lock poisoned");
        if *selected == tag {
            return Ok(());
        }
        *selected = tag.to_owned();
        if let Some(cache) = self
            .persistent_cache
            .as_ref()
            .filter(|_| !self.tag.is_empty())
        {
            let _ = cache.save_selected(&self.tag, tag);
        }
        self.generations
            .lock()
            .expect("selector lock poisoned")
            .interrupt(self.interrupt_exist_connections);
        if let Some(updates) = &self.updates {
            updates.notify_updated();
        }
        Ok(())
    }

    pub fn selected(&self) -> String {
        self.selected
            .read()
            .expect("selector lock poisoned")
            .clone()
    }

    pub fn choices(&self) -> impl Iterator<Item = &str> {
        self.order.iter().map(String::as_str)
    }

    pub(crate) fn choice(&self, tag: &str) -> Option<Arc<dyn Dialer>> {
        self.choices.get(tag).cloned()
    }

    fn current(
        &self,
        external: bool,
    ) -> (Arc<dyn Dialer>, tokio_util::sync::CancellationToken) {
        let selected = self.selected();
        let generation = self
            .generations
            .lock()
            .expect("selector lock poisoned")
            .token(external);
        (self.choices[&selected].clone(), generation)
    }
}

impl Dialer for SelectorOutbound {
    fn icmp_flow_addresses(
        &self,
    ) -> Option<(Option<std::net::IpAddr>, Option<std::net::IpAddr>)> {
        self.current(false).0.icmp_flow_addresses()
    }

    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        self.current(false).0.packet_port()
    }

    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        let (current, generation) = self.current(false);
        Box::pin(async move {
            let stream = current.dial_tcp(destination).await?;
            Ok(interruptible_stream(stream, generation))
        })
    }

    fn dial_tcp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> DialFuture<'a> {
        let (current, generation) = self.current(options.external_connection);
        Box::pin(async move {
            let stream =
                current.dial_tcp_with_options(destination, options).await?;
            Ok(interruptible_stream(stream, generation))
        })
    }

    fn bind_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        let (current, generation) = self.current(false);
        Box::pin(async move {
            let stream = current.bind_tcp(destination).await?;
            Ok(interruptible_stream(stream, generation))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        let (current, generation) = self.current(false);
        Box::pin(async move {
            let packets = current.listen_udp(destination).await?;
            Ok(interruptible_packets(packets, generation))
        })
    }

    fn listen_udp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, PacketStream> {
        let (current, generation) = self.current(options.external_connection);
        Box::pin(async move {
            let packets = current
                .listen_udp_with_options(destination, options)
                .await?;
            Ok(interruptible_packets(packets, generation))
        })
    }

    fn exchange_icmp<'a>(
        &'a self,
        packet: &'a [u8],
        source: std::net::IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, IcmpResponse> {
        let (current, generation) = self.current(false);
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = generation.cancelled() => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "outbound group selection changed",
                )),
                result = current.exchange_icmp(packet, source, hop_limit, destination) => result,
            }
        })
    }

    fn exchange_icmp_with_options<'a>(
        &'a self,
        packet: &'a [u8],
        source: std::net::IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, IcmpResponse> {
        let (current, generation) = self.current(options.external_connection);
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = generation.cancelled() => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "outbound group selection changed",
                )),
                result = current.exchange_icmp_with_options(
                    packet, source, hop_limit, destination, options
                ) => result,
            }
        })
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        io,
        sync::{Arc, Mutex},
    };

    use super::SelectorOutbound;
    use crate::{
        adapter::{DialFuture, Dialer, NetworkDialOptions, Stream},
        common::network::SocksAddr,
        constant::NetworkStrategy,
    };
    use tokio::io::AsyncReadExt;

    struct RecordingDialer(&'static str, Arc<Mutex<Vec<&'static str>>>);

    struct NetworkRecordingDialer(Arc<Mutex<Option<NetworkDialOptions>>>);

    struct PendingDialer;

    impl Dialer for PendingDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(64);
                tokio::spawn(async move {
                    let _server = server;
                    std::future::pending::<()>().await;
                });
                Ok(Box::new(client) as Stream)
            })
        }
    }

    impl Dialer for RecordingDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async move {
                self.1.lock().unwrap().push(self.0);
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, self.0))
            })
        }
    }

    impl Dialer for NetworkRecordingDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "plain dial unexpectedly selected",
                ))
            })
        }

        fn dial_tcp_with_options<'a>(
            &'a self,
            _destination: &'a SocksAddr,
            options: &'a NetworkDialOptions,
        ) -> DialFuture<'a> {
            Box::pin(async move {
                *self.0.lock().unwrap() = Some(options.clone());
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "recorded network dial",
                ))
            })
        }
    }

    #[tokio::test]
    async fn propagates_per_connection_network_options() {
        let recorded = Arc::new(Mutex::new(None));
        let choices: HashMap<String, Arc<dyn Dialer>> = HashMap::from([(
            "direct".into(),
            Arc::new(NetworkRecordingDialer(recorded.clone()))
                as Arc<dyn Dialer>,
        )]);
        let selector = SelectorOutbound::new(
            vec!["direct".into()],
            choices,
            "direct".into(),
            false,
        )
        .unwrap();
        let expected = NetworkDialOptions {
            strategy: Some(NetworkStrategy::Hybrid),
            fallback_delay: Some(std::time::Duration::from_millis(75)),
            ..Default::default()
        };
        let _ = selector
            .dial_tcp_with_options(
                &SocksAddr::new("example.com", 443),
                &expected,
            )
            .await;
        assert_eq!(*recorded.lock().unwrap(), Some(expected));
    }

    #[tokio::test]
    async fn switches_future_connections_and_validates_selection() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let choices: HashMap<String, Arc<dyn Dialer>> = HashMap::from([
            (
                "one".into(),
                Arc::new(RecordingDialer("one", calls.clone()))
                    as Arc<dyn Dialer>,
            ),
            (
                "two".into(),
                Arc::new(RecordingDialer("two", calls.clone()))
                    as Arc<dyn Dialer>,
            ),
        ]);
        let selector = SelectorOutbound::new(
            vec!["one".into(), "two".into()],
            choices,
            "one".into(),
            false,
        )
        .unwrap();
        assert_eq!(selector.choices().collect::<Vec<_>>(), ["one", "two"]);
        let _ = selector.dial_tcp(&SocksAddr::new("example.com", 443)).await;
        selector.select("two").unwrap();
        let _ = selector.dial_tcp(&SocksAddr::new("example.com", 443)).await;
        assert_eq!(*calls.lock().unwrap(), ["one", "two"]);
        assert_eq!(selector.selected(), "two");
        assert_eq!(
            selector.select("missing").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[tokio::test]
    async fn interrupts_external_connections_when_enabled() {
        let choices: HashMap<String, Arc<dyn Dialer>> = HashMap::from([
            ("one".into(), Arc::new(PendingDialer) as Arc<dyn Dialer>),
            ("two".into(), Arc::new(PendingDialer) as Arc<dyn Dialer>),
        ]);
        let selector = SelectorOutbound::new(
            vec!["one".into(), "two".into()],
            choices,
            "one".into(),
            true,
        )
        .unwrap();
        let mut stream = selector
            .dial_tcp_with_options(
                &SocksAddr::new("example.com", 443),
                &NetworkDialOptions {
                    external_connection: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        selector.select("two").unwrap();
        let error = stream.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }

    #[tokio::test]
    async fn always_interrupts_internal_but_preserves_external_when_disabled() {
        let choices: HashMap<String, Arc<dyn Dialer>> = HashMap::from([
            ("one".into(), Arc::new(PendingDialer) as Arc<dyn Dialer>),
            ("two".into(), Arc::new(PendingDialer) as Arc<dyn Dialer>),
        ]);
        let selector = SelectorOutbound::new(
            vec!["one".into(), "two".into()],
            choices,
            "one".into(),
            false,
        )
        .unwrap();
        let destination = SocksAddr::new("example.com", 443);
        let mut internal = selector.dial_tcp(&destination).await.unwrap();
        let mut external = selector
            .dial_tcp_with_options(
                &destination,
                &NetworkDialOptions {
                    external_connection: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        selector.select("two").unwrap();

        assert_eq!(
            internal.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                external.read_u8(),
            )
            .await
            .is_err()
        );
    }
}
