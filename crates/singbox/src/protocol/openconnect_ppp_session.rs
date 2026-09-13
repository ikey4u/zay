//! Asynchronous stream carrier for the shared OpenConnect PPP negotiator.

use std::{io, sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::adapter::Stream;

use super::{
    PPP_MAXIMUM_WIRE_FRAME_SIZE, PppEncapsulation, PppFrameDecoder,
    PppNegotiationError, PppNegotiationEvent, PppNegotiator,
    PppNegotiatorOptions, PppOutboundPacket, TunnelConfiguration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppStreamSessionOptions {
    pub negotiator: PppNegotiatorOptions,
    pub queue_length: usize,
    /// Bytes consumed while classifying a response-less Fortinet TLS switch.
    pub initial_payload: Vec<u8>,
}

impl Default for PppStreamSessionOptions {
    fn default() -> Self {
        Self {
            negotiator: PppNegotiatorOptions::default(),
            queue_length: 64,
            initial_payload: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum PppStreamSessionError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Negotiation(#[from] PppNegotiationError),
    #[error(transparent)]
    Frame(#[from] super::PppFrameError),
    #[error("PPP stream closed before negotiation completed")]
    ClosedDuringNegotiation,
    #[error("PPP peer terminated the link")]
    PeerTerminated,
    #[error("PPP stream session is closed")]
    Closed,
}

struct PppStreamWriter {
    writer: WriteHalf<Stream>,
    negotiator: PppNegotiator,
    encapsulation: PppEncapsulation,
}

type SharedWriter = Arc<Mutex<Option<PppStreamWriter>>>;

/// A negotiated PPP stream data channel suitable for Fortinet TLS and F5 TCP.
pub struct PppStreamSession {
    writer: SharedWriter,
    incoming: mpsc::Receiver<Result<Vec<u8>, PppStreamSessionError>>,
    configuration: TunnelConfiguration,
    cancellation: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl PppStreamSession {
    pub async fn connect(
        mut stream: Stream,
        options: PppStreamSessionOptions,
    ) -> Result<Self, PppStreamSessionError> {
        let encapsulation = options.negotiator.encapsulation;
        let timer_period = ppp_timer_period(&options.negotiator);
        let now = std::time::Instant::now();
        let mut negotiator = PppNegotiator::new(options.negotiator, now)?;
        write_outbound_packets(
            &mut stream,
            encapsulation,
            &negotiator.start(now)?,
        )
        .await?;
        let mut decoder = PppFrameDecoder::new(encapsulation);
        let mut initial_payload = options.initial_payload;
        let mut read_buffer = vec![0_u8; PPP_MAXIMUM_WIRE_FRAME_SIZE];
        while !negotiator.is_ready() {
            let frames = if !initial_payload.is_empty() {
                let content = std::mem::take(&mut initial_payload);
                decoder.push(&content)?
            } else {
                tokio::select! {
                    read = stream.read(&mut read_buffer) => {
                        let count = read?;
                        if count == 0 {
                            return Err(PppStreamSessionError::ClosedDuringNegotiation);
                        }
                        decoder.push(&read_buffer[..count])?
                    }
                    _ = tokio::time::sleep(timer_period) => {
                        let outbound = negotiator.handle_timer(std::time::Instant::now())?;
                        write_outbound_packets(&mut stream, encapsulation, &outbound).await?;
                        continue;
                    }
                }
            };
            for frame in frames {
                let event = negotiator
                    .handle_frame(&frame, std::time::Instant::now())?;
                if event.peer_terminated {
                    return Err(PppStreamSessionError::PeerTerminated);
                }
                write_outbound_packets(
                    &mut stream,
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
        let (reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(Some(PppStreamWriter {
            writer,
            negotiator,
            encapsulation,
        })));
        let cancellation = CancellationToken::new();
        let (incoming_tx, incoming) =
            mpsc::channel(options.queue_length.max(1));
        let read_task = tokio::spawn(ppp_read_loop(
            reader,
            PppFrameDecoder::new(encapsulation),
            writer.clone(),
            incoming_tx.clone(),
            cancellation.clone(),
        ));
        let timer_task = tokio::spawn(ppp_timer_loop(
            writer.clone(),
            incoming_tx,
            cancellation.clone(),
            timer_period,
        ));
        Ok(Self {
            writer,
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
    ) -> Result<(), PppStreamSessionError> {
        let mut writer = self.writer.lock().await;
        let writer = writer.as_mut().ok_or(PppStreamSessionError::Closed)?;
        let packet = writer.negotiator.build_data_packet(payload)?;
        let encapsulation = writer.encapsulation;
        let frame = packet.encode(encapsulation)?;
        writer.writer.write_all(&frame).await?;
        writer.writer.flush().await?;
        Ok(())
    }

    pub async fn read_data_packet(
        &mut self,
    ) -> Result<Option<Vec<u8>>, PppStreamSessionError> {
        match self.incoming.recv().await {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    pub async fn close(&mut self) -> Result<(), PppStreamSessionError> {
        let result = if self.cancellation.is_cancelled() {
            Ok(())
        } else {
            let mut writer = self.writer.lock().await;
            if let Some(writer) = writer.as_mut() {
                let packet = writer.negotiator.terminate_request()?;
                let frame = packet.encode(writer.encapsulation)?;
                let result = writer.writer.write_all(&frame).await;
                let _ = writer.writer.shutdown().await;
                result.map_err(PppStreamSessionError::Io)
            } else {
                Ok(())
            }
        };
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        self.writer.lock().await.take();
        result
    }
}

impl Drop for PppStreamSession {
    fn drop(&mut self) {
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn ppp_read_loop(
    mut reader: ReadHalf<Stream>,
    mut decoder: PppFrameDecoder,
    writer: SharedWriter,
    incoming: mpsc::Sender<Result<Vec<u8>, PppStreamSessionError>>,
    cancellation: CancellationToken,
) {
    let mut buffer = vec![0_u8; PPP_MAXIMUM_WIRE_FRAME_SIZE];
    loop {
        let count = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = reader.read(&mut buffer) => match result {
                Ok(0) => {
                    cancellation.cancel();
                    return;
                }
                Ok(count) => count,
                Err(error) => {
                    send_ppp_error(&incoming, error.into()).await;
                    cancellation.cancel();
                    return;
                }
            }
        };
        let frames = match decoder.push(&buffer[..count]) {
            Ok(frames) => frames,
            Err(error) => {
                send_ppp_error(&incoming, error.into()).await;
                cancellation.cancel();
                return;
            }
        };
        for frame in frames {
            let mut guard = writer.lock().await;
            let Some(writer) = guard.as_mut() else {
                cancellation.cancel();
                return;
            };
            let event = match writer
                .negotiator
                .handle_frame(&frame, std::time::Instant::now())
            {
                Ok(event) => event,
                Err(error) => {
                    drop(guard);
                    send_ppp_error(&incoming, error.into()).await;
                    cancellation.cancel();
                    return;
                }
            };
            if let Err(error) = write_event(writer, &event).await {
                drop(guard);
                send_ppp_error(&incoming, error).await;
                cancellation.cancel();
                return;
            }
            drop(guard);
            if event.peer_terminated {
                send_ppp_error(
                    &incoming,
                    PppStreamSessionError::PeerTerminated,
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

async fn ppp_timer_loop(
    writer: SharedWriter,
    incoming: mpsc::Sender<Result<Vec<u8>, PppStreamSessionError>>,
    cancellation: CancellationToken,
    timer_period: Duration,
) {
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = tokio::time::sleep(timer_period) => {}
        }
        let mut guard = writer.lock().await;
        let Some(writer) = guard.as_mut() else {
            return;
        };
        let result = async {
            let packets =
                writer.negotiator.handle_timer(std::time::Instant::now())?;
            let encapsulation = writer.encapsulation;
            write_outbound_packets(&mut writer.writer, encapsulation, &packets)
                .await
        }
        .await;
        drop(guard);
        if let Err(error) = result {
            send_ppp_error(&incoming, error).await;
            cancellation.cancel();
            return;
        }
    }
}

async fn write_event(
    writer: &mut PppStreamWriter,
    event: &PppNegotiationEvent,
) -> Result<(), PppStreamSessionError> {
    write_outbound_packets(
        &mut writer.writer,
        writer.encapsulation,
        &event.outbound,
    )
    .await
}

async fn write_outbound_packets<W>(
    writer: &mut W,
    encapsulation: PppEncapsulation,
    packets: &[PppOutboundPacket],
) -> Result<(), PppStreamSessionError>
where
    W: AsyncWrite + Unpin,
{
    for packet in packets {
        writer.write_all(&packet.encode(encapsulation)?).await?;
    }
    if !packets.is_empty() {
        writer.flush().await?;
    }
    Ok(())
}

async fn send_ppp_error(
    incoming: &mpsc::Sender<Result<Vec<u8>, PppStreamSessionError>>,
    error: PppStreamSessionError,
) {
    let _ = incoming.send(Err(error)).await;
}

fn ppp_timer_period(options: &PppNegotiatorOptions) -> Duration {
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

    #[tokio::test]
    async fn two_stream_negotiators_reach_network_phase() {
        let (client, server) = tokio::io::duplex(32 * 1024);
        let server_task = tokio::spawn(run_peer(Box::new(server)));
        let mut session = PppStreamSession::connect(
            Box::new(client),
            PppStreamSessionOptions {
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

    async fn run_peer(mut stream: Stream) {
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
        write_outbound_packets(
            &mut stream,
            PppEncapsulation::Fortinet,
            &negotiator.start(now).unwrap(),
        )
        .await
        .unwrap();
        let mut decoder = PppFrameDecoder::new(PppEncapsulation::Fortinet);
        let mut buffer = vec![0_u8; PPP_MAXIMUM_WIRE_FRAME_SIZE];
        while !negotiator.is_ready() {
            let count = stream.read(&mut buffer).await.unwrap();
            assert_ne!(count, 0);
            for frame in decoder.push(&buffer[..count]).unwrap() {
                let event = negotiator
                    .handle_frame(&frame, std::time::Instant::now())
                    .unwrap();
                write_outbound_packets(
                    &mut stream,
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
        let _ = stream.read(&mut buffer).await;
    }
}
