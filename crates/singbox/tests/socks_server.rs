#![cfg(feature = "socks")]

use std::{io, net::SocketAddr, time::Duration};

use singbox::{
    common::network::SocksAddr,
    inbound::socks::{SocksServer, SocksServerOptions},
    protocol::socks::{
        client_handshake, client_handshake4, client_udp_associate,
        decode_udp_packet, encode_udp_packet,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

async fn server() -> SocksServer {
    let mut server = SocksServer::new(SocksServerOptions {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..SocksServerOptions::default()
    })
    .unwrap();
    server.start().await.unwrap();
    server
}

#[tokio::test]
async fn socks4a_and_connection_failure_replies() {
    timeout(Duration::from_secs(5), async {
        let mut server = server().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination =
            SocksAddr::new("localhost", target.local_addr().unwrap().port());
        let mut client = TcpStream::connect(server.local_addr().unwrap())
            .await
            .unwrap();
        client_handshake4(&mut client, &destination, "")
            .await
            .unwrap();
        let (mut remote, _) = target.accept().await.unwrap();
        client.write_all(b"socks4a").await.unwrap();
        let mut payload = [0; 7];
        remote.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"socks4a");
        drop(remote);
        drop(client);

        let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = unavailable.local_addr().unwrap();
        drop(unavailable);
        let mut client = TcpStream::connect(server.local_addr().unwrap())
            .await
            .unwrap();
        let error = client_handshake(&mut client, &address.into(), None)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        server.close().await.unwrap();
    })
    .await
    .expect("SOCKS4a or refusal reply timed out");
}

#[tokio::test]
async fn udp_supports_multiple_destinations_and_address_families() {
    timeout(Duration::from_secs(5), async {
        let mut server = server().await;
        let target4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target6 = UdpSocket::bind("[::1]:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut control = TcpStream::connect(server.local_addr().unwrap())
            .await
            .unwrap();
        let relay = client_udp_associate(
            &mut control,
            &udp.local_addr().unwrap().into(),
            None,
        )
        .await
        .unwrap();
        let relay = relay.resolve().await.unwrap()[0];
        let mut packet = [0; 512];
        for target in [&target4, &target6, &target4] {
            let destination = target.local_addr().unwrap();
            let request =
                encode_udp_packet(&destination.into(), b"mixed").unwrap();
            udp.send_to(&request, relay).await.unwrap();
            let (size, source) = target.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..size], b"mixed");
            target.send_to(&packet[..size], source).await.unwrap();
            let (size, _) = udp.recv_from(&mut packet).await.unwrap();
            let (source, payload) = decode_udp_packet(&packet[..size]).unwrap();
            assert_eq!(source, destination.into());
            assert_eq!(payload, b"mixed");
        }
        // Closing the server also closes the association's TCP control.
        server.close().await.unwrap();
        assert_eq!(control.read(&mut packet).await.unwrap(), 0);
    })
    .await
    .expect("mixed-family UDP forwarding timed out");
}

#[tokio::test]
async fn ipv6_listener_and_destination() {
    timeout(Duration::from_secs(5), async {
        let mut server = SocksServer::new(SocksServerOptions {
            listen: "[::1]:0".parse().unwrap(),
            ..SocksServerOptions::default()
        })
        .unwrap();
        server.start().await.unwrap();
        let target = TcpListener::bind("[::1]:0").await.unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap())
            .await
            .unwrap();
        client_handshake(
            &mut client,
            &target.local_addr().unwrap().into(),
            None,
        )
        .await
        .unwrap();
        let (mut remote, _) = target.accept().await.unwrap();
        remote.write_all(b"ipv6").await.unwrap();
        let mut payload = [0; 4];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ipv6");
        server.close().await.unwrap();
        assert_eq!(client.read(&mut payload).await.unwrap(), 0);
    })
    .await
    .expect("IPv6 SOCKS forwarding timed out");
}

#[tokio::test]
async fn stalled_handshake_and_idle_udp_sessions_close() {
    timeout(Duration::from_secs(5), async {
        let mut server = SocksServer::new(SocksServerOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            handshake_timeout: Duration::from_millis(50),
            udp_timeout: Duration::from_millis(50),
            ..SocksServerOptions::default()
        })
        .unwrap();
        server.start().await.unwrap();
        let mut stalled = TcpStream::connect(server.local_addr().unwrap())
            .await
            .unwrap();
        let mut payload = [0; 1];
        assert_eq!(stalled.read(&mut payload).await.unwrap(), 0);

        let mut control = TcpStream::connect(server.local_addr().unwrap())
            .await
            .unwrap();
        let unspecified: SocketAddr = "0.0.0.0:0".parse().unwrap();
        client_udp_associate(&mut control, &unspecified.into(), None)
            .await
            .unwrap();
        assert_eq!(control.read(&mut payload).await.unwrap(), 0);
        server.close().await.unwrap();
    })
    .await
    .expect("idle SOCKS sessions did not close");
}
