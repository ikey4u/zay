use std::io;

use crate::{
    adapter::{DialFuture, Dialer, PacketFuture, PacketStream},
    common::network::SocksAddr,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct BlockOutbound;

impl Dialer for BlockOutbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("blocked connection to {destination}"),
            ))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("blocked packet connection to {destination}"),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::BlockOutbound;
    use crate::{adapter::Dialer, common::network::SocksAddr};

    #[tokio::test]
    async fn rejects_without_touching_the_network() {
        let result = BlockOutbound
            .dial_tcp(&SocksAddr::new("example.com", 443))
            .await;
        let error = match result {
            Ok(_) => panic!("block outbound unexpectedly connected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
