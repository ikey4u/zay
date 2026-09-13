//! Transparent TCP redirect inbound.

use std::{io, net::SocketAddr, sync::Arc};

use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::Stream,
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::{Network, SocksAddr},
        redir::original_destination,
    },
    inbound::{
        TcpInboundContext, prepare_tcp_inbound_detour,
        serve_hijacked_dns_stream_with_context, sniff_and_route_stream,
    },
    option::RedirectInboundOptions,
    outbound::OutboundManager,
    route::{Action, Metadata, Router},
};

pub struct RedirectInbound {
    name: String,
    tag: String,
    options: RedirectInboundOptions,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

impl RedirectInbound {
    pub fn new(
        tag: impl Into<String>,
        options: RedirectInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Self {
        let tag = tag.into();
        Self {
            name: format!("inbound/redirect[{tag}]"),
            tag,
            options,
            router,
            outbounds,
            cancellation: CancellationToken::new(),
            task: None,
            local_addr: None,
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    async fn bind(&mut self) -> io::Result<()> {
        let address = SocketAddr::new(
            self.options
                .listen
                .listen
                .map(|address| address.0)
                .unwrap_or(std::net::Ipv4Addr::LOCALHOST.into()),
            self.options.listen.listen_port,
        );
        let listener = crate::common::socket::bind_tcp_listener(
            address,
            &self.options.listen,
        )
        .await?;
        self.local_addr = Some(listener.local_addr()?);
        self.task = Some(tokio::spawn(accept_loop(
            listener,
            self.cancellation.clone(),
            self.tag.clone(),
            self.router.clone(),
            self.outbounds.clone(),
        )));
        Ok(())
    }
}

impl Lifecycle for RedirectInbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage == StartStage::Start {
                self.bind().await.map_err(|error| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: error.to_string(),
                })?;
            }
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            if let Some(task) = self.task.take() {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        return Err(LifecycleError::Close {
                            component: self.name.clone(),
                            message: error.to_string(),
                        });
                    }
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => {
                        return Err(LifecycleError::Close {
                            component: self.name.clone(),
                            message: error.to_string(),
                        });
                    }
                }
            }
            Ok(())
        })
    }
}

async fn accept_loop(
    listener: TcpListener,
    cancellation: CancellationToken,
    tag: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, source) = accepted?;
                let tag = tag.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                connections.spawn(async move {
                    let destination = original_destination(&stream)?;
                    handle_connection(
                        stream,
                        source,
                        destination.into(),
                        &tag,
                        &router,
                        &outbounds,
                    )
                    .await
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

pub(crate) async fn handle_connection(
    client: TcpStream,
    source: SocketAddr,
    destination: SocksAddr,
    tag: &str,
    router: &Router,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination.clone()),
        origin_destination: Some(client.local_addr()?.into()),
        network: Some(Network::Tcp),
        ..Metadata::default()
    };
    if let Some(injector) =
        prepare_tcp_inbound_detour(&mut metadata, outbounds)?
    {
        return injector
            .inject(Box::new(client), TcpInboundContext { source, metadata })
            .await;
    }
    let (mut client, decision) = sniff_and_route_stream(
        Box::new(client) as Stream,
        &mut metadata,
        router,
        outbounds,
    )
    .await?;
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection rejected by route rule",
        ));
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        return serve_hijacked_dns_stream_with_context(
            client, outbounds, &metadata,
        )
        .await;
    }
    let destination = decision
        .destination(metadata.destination.as_ref().unwrap_or(&destination));
    let connection_options = decision.connection_options();
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })?
    };
    let mut remote = dialer
        .dial_tcp_with_options(&destination, &connection_options.network)
        .await?;
    remote = super::apply_routed_tcp_options(remote, &connection_options)?;
    copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}
