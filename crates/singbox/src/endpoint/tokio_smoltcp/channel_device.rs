use futures::{Sink, Stream};
use smoltcp::phy::DeviceCapabilities;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::{
    broadcast,
    mpsc::{Receiver, Sender, channel},
};
use tokio_util::sync::{PollSendError, PollSender};

use super::device::AsyncDevice;

/// A device that send and receive packets using a channel.
pub struct ChannelDevice {
    recv: Receiver<io::Result<Vec<u8>>>,
    send: PollSender<Vec<u8>>,
    caps: DeviceCapabilities,
    icmp_errors: broadcast::Sender<Vec<u8>>,
}

pub type ChannelDeviceNewRet = (
    ChannelDevice,
    Sender<io::Result<Vec<u8>>>,
    Sender<Vec<u8>>,
    Receiver<Vec<u8>>,
    broadcast::Sender<Vec<u8>>,
);

impl ChannelDevice {
    /// Make a new `ChannelDevice` with the given `recv` and `send` channels.
    ///
    /// The `caps` is used to determine the device capabilities. `DeviceCapabilities::max_transmission_unit` must be set.
    pub fn new(caps: DeviceCapabilities) -> ChannelDeviceNewRet {
        Self::new_with_capacity(caps, 1000)
    }

    /// Make a channel device with an explicit bounded packet queue capacity.
    pub fn new_with_capacity(
        caps: DeviceCapabilities,
        capacity: usize,
    ) -> ChannelDeviceNewRet {
        let capacity = capacity.max(1);
        let (tx1, rx1) = channel(capacity);
        let (tx2, rx2) = channel(capacity);
        let (icmp_errors, _) = broadcast::channel(128);
        (
            ChannelDevice {
                send: PollSender::new(tx1.clone()),
                recv: rx2,
                caps,
                icmp_errors: icmp_errors.clone(),
            },
            tx2,
            tx1,
            rx1,
            icmp_errors,
        )
    }
}

impl Stream for ChannelDevice {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let packet = self.recv.poll_recv(cx);
        if let Poll::Ready(Some(Ok(packet))) = &packet
            && is_icmp_error_packet(packet)
        {
            let _ = self.icmp_errors.send(packet.clone());
        }
        packet
    }
}

fn is_icmp_error_packet(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 28 && packet[9] == 1 => {
            let offset = usize::from(packet[0] & 0x0f) * 4;
            packet
                .get(offset)
                .is_some_and(|message_type| matches!(message_type, 3 | 11))
        }
        Some(6) if packet.len() >= 48 && packet[6] == 58 => {
            matches!(packet[40], 1..=4)
        }
        _ => false,
    }
}

fn map_err(e: PollSendError<Vec<u8>>) -> io::Error {
    io::Error::other(e)
}

impl Sink<Vec<u8>> for ChannelDevice {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send.poll_reserve(cx).map_err(map_err)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self.send.send_item(item).map_err(map_err)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send.poll_reserve(cx).map_err(map_err)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncDevice for ChannelDevice {
    fn capabilities(&self) -> &DeviceCapabilities {
        &self.caps
    }
}
