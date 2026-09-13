use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const STREAM_PACKET_MAX_LENGTH: usize = u16::MAX as usize;

/// OpenVPN's TCP transport uses an unsigned 16-bit big-endian length prefix.
pub async fn read_stream_packet<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let length = reader.read_u16().await? as usize;
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad encapsulated OpenVPN packet length from peer",
        ));
    }
    let mut packet = vec![0_u8; length];
    reader.read_exact(&mut packet).await?;
    Ok(packet)
}

pub async fn write_stream_packet<W>(
    writer: &mut W,
    packet: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if packet.is_empty() {
        return Ok(());
    }
    let length = u16::try_from(packet.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "OpenVPN packet too large")
    })?;
    writer.write_u16(length).await?;
    writer.write_all(packet).await
}

pub async fn write_stream_packets<W, I, B>(
    writer: &mut W,
    packets: I,
) -> io::Result<usize>
where
    W: AsyncWrite + Unpin,
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut written = 0;
    for packet in packets {
        write_stream_packet(writer, packet.as_ref()).await?;
        written += 1;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_multiple_packets_across_partial_reads() {
        let (mut client, mut server) = tokio::io::duplex(7);
        let writer = tokio::spawn(async move {
            write_stream_packets(
                &mut client,
                [b"first".as_slice(), b"second".as_slice()],
            )
            .await
            .unwrap()
        });
        assert_eq!(read_stream_packet(&mut server).await.unwrap(), b"first");
        assert_eq!(read_stream_packet(&mut server).await.unwrap(), b"second");
        assert_eq!(writer.await.unwrap(), 2);
    }

    #[tokio::test]
    async fn rejects_empty_peer_frame() {
        let mut input = &b"\0\0"[..];
        assert_eq!(
            read_stream_packet(&mut input).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
