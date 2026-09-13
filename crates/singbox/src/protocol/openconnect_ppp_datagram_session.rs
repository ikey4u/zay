//! Asynchronous datagram carrier for the shared OpenConnect PPP negotiator.

use std::{io, sync::Arc, time::Duration};

use async_trait::async_trait;
use thiserror::Error;
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use super::{
    PPP_MAXIMUM_WIRE_FRAME_SIZE, PppEncapsulation, PppFrameDecoder,
    PppNegotiationError, PppNegotiator, PppNegotiatorOptions,
    PppOutboundPacket, TunnelConfiguration,
};

#[async_trait]
pub trait PppDatagramCarrier: Send + Sync {
    async fn send(&self, content: &[u8]) -> io::Result<usize>;
    async fn receive(&self, content: &mut [u8]) -> io::Result<usize>;
    async fn close(&self) -> io::Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppDatagramSessionOptions {
    pub negotiator: PppNegotiatorOptions,
    pub queue_length: usize,
    /// A complete PPP datagram consumed while probing the carrier.
    pub initial_datagram: Vec<u8>,
}

impl Default for PppDatagramSessionOptions {
    fn default() -> Self {
        Self {
            negotiator: PppNegotiatorOptions::default(),
            queue_length: 64,
            initial_datagram: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum PppDatagramSessionError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Negotiation(#[from] PppNegotiationError),
    #[error(transparent)]
    Frame(#[from] super::PppFrameError),
    #[error("PPP datagram carrier closed before negotiation completed")]
    ClosedDuringNegotiation,
    #[error("PPP peer terminated the link")]
    PeerTerminated,
    #[error("PPP datagram session is closed")]
    Closed,
    #[error("short PPP datagram write: wrote {written} of {expected} bytes")]
    ShortWrite { written: usize, expected: usize },
}

struct PppDatagramState {
    carrier: Arc<dyn PppDatagramCarrier>,
    negotiator: PppNegotiator,
    encapsulation: PppEncapsulation,
}

type SharedState = Arc<Mutex<Option<PppDatagramState>>>;

pub struct PppDatagramSession {
    state: SharedState,
    incoming: mpsc::Receiver<Result<Vec<u8>, PppDatagramSessionError>>,
    configuration: TunnelConfiguration,
    cancellation: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl PppDatagramSession {
    pub async fn connect(
        carrier: Arc<dyn PppDatagramCarrier>,
        options: PppDatagramSessionOptions,
    ) -> Result<Self, PppDatagramSessionError> {
        let encapsulation = options.negotiator.encapsulation;
        let timer_period = ppp_datagram_timer_period(&options.negotiator);
        let now = std::time::Instant::now();
        let mut negotiator = PppNegotiator::new(options.negotiator, now)?;
        write_datagram_packets(
            carrier.as_ref(),
            encapsulation,
            &negotiator.start(now)?,
        )
        .await?;
        let mut initial =
            Some(options.initial_datagram).filter(|v| !v.is_empty());
        let mut buffer = vec![0_u8; PPP_MAXIMUM_WIRE_FRAME_SIZE];
        while !negotiator.is_ready() {
            let datagram = if let Some(initial) = initial.take() {
                initial
            } else {
                tokio::select! {
                    read = carrier.receive(&mut buffer) => {
                        let count = read?;
                        if count == 0 {
                            return Err(PppDatagramSessionError::ClosedDuringNegotiation);
                        }
                        buffer[..count].to_vec()
                    }
                    _ = tokio::time::sleep(timer_period) => {
                        let outbound = negotiator.handle_timer(std::time::Instant::now())?;
                        write_datagram_packets(carrier.as_ref(), encapsulation, &outbound).await?;
                        continue;
                    }
                }
            };
            let frames = decode_ppp_datagram(encapsulation, &datagram)?;
            for frame in frames {
                let event = negotiator
                    .handle_frame(&frame, std::time::Instant::now())?;
                if event.peer_terminated {
                    return Err(PppDatagramSessionError::PeerTerminated);
                }
                write_datagram_packets(
                    carrier.as_ref(),
                    encapsulation,
                    &event.outbound,
                )
                .await?;
            }
        }
        let configuration = negotiator
            .configuration()
            .expect("ready negotiator has a configuration")
            .clone();
        let state = Arc::new(Mutex::new(Some(PppDatagramState {
            carrier,
            negotiator,
            encapsulation,
        })));
        let cancellation = CancellationToken::new();
        let (incoming_tx, incoming) =
            mpsc::channel(options.queue_length.max(1));
        let read_task = tokio::spawn(ppp_datagram_read_loop(
            state.clone(),
            incoming_tx.clone(),
            cancellation.clone(),
        ));
        let timer_task = tokio::spawn(ppp_datagram_timer_loop(
            state.clone(),
            incoming_tx,
            cancellation.clone(),
            timer_period,
        ));
        Ok(Self {
            state,
            incoming,
            configuration,
            cancellation,
            tasks: vec![read_task, timer_task],
        })
    }

    pub fn tunnel_configuration(&self) -> &TunnelConfiguration {
        &self.configuration
    }

    pub async fn write_data_packet(
        &self,
        payload: &[u8],
    ) -> Result<(), PppDatagramSessionError> {
        let mut state = self.state.lock().await;
        let state = state.as_mut().ok_or(PppDatagramSessionError::Closed)?;
        let packet = state.negotiator.build_data_packet(payload)?;
        write_datagram_packets(
            state.carrier.as_ref(),
            state.encapsulation,
            &[packet],
        )
        .await
    }

    pub async fn read_data_packet(
        &mut self,
    ) -> Result<Option<Vec<u8>>, PppDatagramSessionError> {
        match self.incoming.recv().await {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    pub async fn close(&mut self) -> Result<(), PppDatagramSessionError> {
        let mut first_error = None;
        if !self.cancellation.is_cancelled() {
            let mut state = self.state.lock().await;
            if let Some(state) = state.as_mut() {
                for _ in 0..3 {
                    let packet = state.negotiator.terminate_request()?;
                    if let Err(error) = write_datagram_packets(
                        state.carrier.as_ref(),
                        state.encapsulation,
                        &[packet],
                    )
                    .await
                    {
                        first_error = Some(error);
                        break;
                    }
                }
                if let Err(error) = state.carrier.close().await
                    && first_error.is_none()
                {
                    first_error = Some(error.into());
                }
            }
        }
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        self.state.lock().await.take();
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for PppDatagramSession {
    fn drop(&mut self) {
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn ppp_datagram_read_loop(
    state: SharedState,
    incoming: mpsc::Sender<Result<Vec<u8>, PppDatagramSessionError>>,
    cancellation: CancellationToken,
) {
    let carrier = {
        let guard = state.lock().await;
        let Some(state) = guard.as_ref() else { return };
        state.carrier.clone()
    };
    let mut buffer = vec![0_u8; PPP_MAXIMUM_WIRE_FRAME_SIZE];
    loop {
        let count = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = carrier.receive(&mut buffer) => match result {
                Ok(0) => {
                    cancellation.cancel();
                    return;
                }
                Ok(count) => count,
                Err(error) => {
                    send_datagram_error(&incoming, error.into()).await;
                    cancellation.cancel();
                    return;
                }
            }
        };
        let (encapsulation, frames) = {
            let guard = state.lock().await;
            let Some(state) = guard.as_ref() else { return };
            let encapsulation = state.encapsulation;
            let frames =
                match decode_ppp_datagram(encapsulation, &buffer[..count]) {
                    Ok(frames) => frames,
                    // UDP loss or corruption is isolated to this datagram.
                    Err(_) => continue,
                };
            (encapsulation, frames)
        };
        for frame in frames {
            let (carrier, event) = {
                let mut guard = state.lock().await;
                let Some(state) = guard.as_mut() else { return };
                let event = match state
                    .negotiator
                    .handle_frame(&frame, std::time::Instant::now())
                {
                    Ok(event) => event,
                    Err(error) => {
                        drop(guard);
                        send_datagram_error(&incoming, error.into()).await;
                        cancellation.cancel();
                        return;
                    }
                };
                (state.carrier.clone(), event)
            };
            if let Err(error) = write_datagram_packets(
                carrier.as_ref(),
                encapsulation,
                &event.outbound,
            )
            .await
            {
                send_datagram_error(&incoming, error).await;
                cancellation.cancel();
                return;
            }
            if event.peer_terminated {
                send_datagram_error(
                    &incoming,
                    PppDatagramSessionError::PeerTerminated,
                )
                .await;
                cancellation.cancel();
                return;
            }
            if let Some(packet) = event.delivered
                && incoming.send(Ok(packet)).await.is_err()
            {
                cancellation.cancel();
                return;
            }
        }
    }
}

async fn ppp_datagram_timer_loop(
    state: SharedState,
    incoming: mpsc::Sender<Result<Vec<u8>, PppDatagramSessionError>>,
    cancellation: CancellationToken,
    timer_period: Duration,
) {
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = tokio::time::sleep(timer_period) => {}
        }
        let (carrier, encapsulation, packets) = {
            let mut guard = state.lock().await;
            let Some(state) = guard.as_mut() else { return };
            let packets = match state
                .negotiator
                .handle_timer(std::time::Instant::now())
            {
                Ok(packets) => packets,
                Err(error) => {
                    drop(guard);
                    send_datagram_error(&incoming, error.into()).await;
                    cancellation.cancel();
                    return;
                }
            };
            (state.carrier.clone(), state.encapsulation, packets)
        };
        if let Err(error) =
            write_datagram_packets(carrier.as_ref(), encapsulation, &packets)
                .await
        {
            send_datagram_error(&incoming, error).await;
            cancellation.cancel();
            return;
        }
    }
}

fn decode_ppp_datagram(
    encapsulation: PppEncapsulation,
    datagram: &[u8],
) -> Result<Vec<Vec<u8>>, PppDatagramSessionError> {
    let mut decoder = PppFrameDecoder::new(encapsulation);
    let frames = decoder.push(datagram)?;
    if decoder.discard() != 0 {
        return Err(super::PppFrameError::ReceiveBufferTooLarge.into());
    }
    Ok(frames)
}

async fn write_datagram_packets(
    carrier: &dyn PppDatagramCarrier,
    encapsulation: PppEncapsulation,
    packets: &[PppOutboundPacket],
) -> Result<(), PppDatagramSessionError> {
    for packet in packets {
        let frame = packet.encode(encapsulation)?;
        let written = carrier.send(&frame).await?;
        if written != frame.len() {
            return Err(PppDatagramSessionError::ShortWrite {
                written,
                expected: frame.len(),
            });
        }
    }
    Ok(())
}

async fn send_datagram_error(
    incoming: &mpsc::Sender<Result<Vec<u8>, PppDatagramSessionError>>,
    error: PppDatagramSessionError,
) {
    let _ = incoming.send(Err(error)).await;
}

fn ppp_datagram_timer_period(options: &PppNegotiatorOptions) -> Duration {
    let mut period = options.negotiation_period / 4;
    if period.is_zero() || period > Duration::from_millis(250) {
        period = Duration::from_millis(250);
    }
    if !options.echo_interval.is_zero() && options.echo_interval / 4 < period {
        period = options.echo_interval / 4;
    }
    if period.is_zero() {
        Duration::from_millis(10)
    } else {
        period
    }
}

#[cfg(test)]
mod tests {
    use ipnet::Ipv4Net;

    use super::*;

    struct MemoryDatagram {
        outbound: mpsc::Sender<Vec<u8>>,
        inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    }

    #[async_trait]
    impl PppDatagramCarrier for MemoryDatagram {
        async fn send(&self, content: &[u8]) -> io::Result<usize> {
            self.outbound.send(content.to_vec()).await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "closed")
            })?;
            Ok(content.len())
        }

        async fn receive(&self, content: &mut [u8]) -> io::Result<usize> {
            let packet =
                self.inbound.lock().await.recv().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "closed")
                })?;
            if packet.len() > content.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "receive buffer too small",
                ));
            }
            content[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }

        async fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    fn memory_datagram_pair() -> (Arc<MemoryDatagram>, Arc<MemoryDatagram>) {
        let (left_tx, left_rx) = mpsc::channel(32);
        let (right_tx, right_rx) = mpsc::channel(32);
        (
            Arc::new(MemoryDatagram {
                outbound: left_tx,
                inbound: Mutex::new(right_rx),
            }),
            Arc::new(MemoryDatagram {
                outbound: right_tx,
                inbound: Mutex::new(left_rx),
            }),
        )
    }

    #[tokio::test]
    async fn two_datagram_negotiators_reach_network_phase() {
        let (client, server) = memory_datagram_pair();
        let server_task = tokio::spawn(run_peer(server));
        let mut session = PppDatagramSession::connect(
            client,
            PppDatagramSessionOptions {
                negotiator: PppNegotiatorOptions {
                    want_ipv6: false,
                    ipv4_address: Some("10.0.0.2/32".parse().unwrap()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            session.tunnel_configuration().addresses[0].to_string(),
            "10.0.0.2/32"
        );
        session.close().await.unwrap();
        server_task.await.unwrap();
    }

    async fn run_peer(carrier: Arc<MemoryDatagram>) {
        let now = std::time::Instant::now();
        let mut negotiator = PppNegotiator::new(
            PppNegotiatorOptions {
                want_ipv6: false,
                ipv4_address: Some("10.0.0.1/32".parse::<Ipv4Net>().unwrap()),
                ..Default::default()
            },
            now,
        )
        .unwrap();
        write_datagram_packets(
            carrier.as_ref(),
            PppEncapsulation::Fortinet,
            &negotiator.start(now).unwrap(),
        )
        .await
        .unwrap();
        let mut buffer = vec![0_u8; PPP_MAXIMUM_WIRE_FRAME_SIZE];
        loop {
            let count = carrier.receive(&mut buffer).await.unwrap();
            for frame in decode_ppp_datagram(
                PppEncapsulation::Fortinet,
                &buffer[..count],
            )
            .unwrap()
            {
                let event = negotiator
                    .handle_frame(&frame, std::time::Instant::now())
                    .unwrap();
                write_datagram_packets(
                    carrier.as_ref(),
                    PppEncapsulation::Fortinet,
                    &event.outbound,
                )
                .await
                .unwrap();
                if event.peer_terminated {
                    return;
                }
            }
        }
    }
}
