use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    process::{Child, Command, Stdio},
    time::Duration,
};

use singbox_core::{
    common::network::SocksAddr,
    protocol::socks::{
        client_handshake, client_udp_associate, decode_udp_packet,
        encode_udp_packet,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};

struct Server {
    child: Child,
    address: SocketAddr,
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_s5"));
    command.env_remove("S5_USERNAME").env_remove("S5_PASSWORD");
    command
}

impl Server {
    async fn start(authenticated: bool) -> Self {
        let reservation = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        let mut command = command();
        command
            .args(["--listen", &address.to_string(), "--udp-timeout", "5"])
            .stdout(Stdio::null());
        if authenticated {
            command
                .env("S5_USERNAME", "alice")
                .env("S5_PASSWORD", "test-password");
        }
        drop(reservation);
        let mut server = Self {
            child: command.spawn().unwrap(),
            address,
        };
        timeout(Duration::from_secs(10), async {
            loop {
                assert!(
                    server.child.try_wait().unwrap().is_none(),
                    "s5 exited before accepting connections"
                );
                if TcpStream::connect(address).await.is_ok() {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("s5 did not start");
        server
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn echo_once(listener: TcpListener) {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut payload = [0; 4];
    socket.read_exact(&mut payload).await.unwrap();
    socket.write_all(&payload).await.unwrap();
}

#[tokio::test]
async fn tcp_udp_and_graceful_shutdown() {
    timeout(Duration::from_secs(20), async {
        let mut server = Server::start(false).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let echo = tokio::spawn(echo_once(target));
        let mut tcp = TcpStream::connect(server.address).await.unwrap();
        client_handshake(&mut tcp, &destination.into(), None)
            .await
            .unwrap();
        tcp.write_all(b"ping").await.unwrap();
        let mut payload = [0; 4];
        tcp.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        echo.await.unwrap();

        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut control = TcpStream::connect(server.address).await.unwrap();
        let relay = client_udp_associate(
            &mut control,
            &udp.local_addr().unwrap().into(),
            None,
        )
        .await
        .unwrap();
        let relay = relay.resolve().await.unwrap()[0];
        let request =
            encode_udp_packet(&destination.into(), b"datagram").unwrap();
        udp.send_to(&request, relay).await.unwrap();
        let mut packet = [0; 512];
        let (size, source) = target.recv_from(&mut packet).await.unwrap();
        assert_eq!(&packet[..size], b"datagram");
        target.send_to(&packet[..size], source).await.unwrap();
        let (size, _) = udp.recv_from(&mut packet).await.unwrap();
        let (source, payload) = decode_udp_packet(&packet[..size]).unwrap();
        assert_eq!(source, destination.into());
        assert_eq!(payload, b"datagram");

        #[cfg(unix)]
        {
            assert!(
                Command::new("kill")
                    .args(["-TERM", &server.child.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            loop {
                if let Some(status) = server.child.try_wait().unwrap() {
                    assert!(status.success(), "shutdown failed: {status}");
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(control.read(&mut packet).await.unwrap(), 0);
            assert!(TcpStream::connect(server.address).await.is_err());
        }
        #[cfg(not(unix))]
        server.child.kill().unwrap();
    })
    .await
    .expect("SOCKS forwarding or shutdown timed out");
}

#[tokio::test]
async fn authentication_and_hostname_resolution() {
    timeout(Duration::from_secs(20), async {
        let server = Server::start(true).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination =
            SocksAddr::new("localhost", target.local_addr().unwrap().port());
        for credentials in [None, Some(("alice", "wrong-password"))] {
            let mut client = TcpStream::connect(server.address).await.unwrap();
            assert!(
                client_handshake(&mut client, &destination, credentials)
                    .await
                    .is_err()
            );
        }
        let echo = tokio::spawn(echo_once(target));
        let mut client = TcpStream::connect(server.address).await.unwrap();
        client_handshake(
            &mut client,
            &destination,
            Some(("alice", "test-password")),
        )
        .await
        .unwrap();
        client.write_all(b"auth").await.unwrap();
        let mut payload = [0; 4];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"auth");
        echo.await.unwrap();
    })
    .await
    .expect("authenticated SOCKS forwarding timed out");
}

#[test]
fn rejects_invalid_arguments_and_an_occupied_listen_port() {
    for args in [
        vec!["--username", "alice"],
        vec!["--password", "test-password"],
        vec!["--username", "alice", "--password", ""],
        vec!["--listen", "127.0.0.1:0"],
        vec!["--udp-timeout", "0"],
    ] {
        let output = command().args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
    let reservation = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let output = command()
        .args(["--listen", &reservation.local_addr().unwrap().to_string()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("starting SOCKS server")
    );
}
