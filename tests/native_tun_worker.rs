#![cfg(unix)]

use std::{
    fs,
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn temporary_directory() -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "zay-native-tun-worker-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&directory).unwrap();
    directory
}

#[test]
fn hidden_worker_hosts_library_and_closes_on_sigterm() {
    let directory = temporary_directory();
    let reservation = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let config_path = directory.join("config.json");
    fs::write(
        &config_path,
        format!(
            r#"{{
              "inbounds": [{{
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": {port}
              }}],
              "outbounds": [{{"type": "direct", "tag": "direct"}}],
              "route": {{"final": "direct"}}
            }}"#
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_zay"))
        .arg("--run-tun-worker")
        .arg("--tun-worker-runtime-dir")
        .arg(&directory)
        .arg("--tun-worker-config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let stderr = child
                .stderr
                .take()
                .map(|mut stream| {
                    use std::io::Read as _;
                    let mut text = String::new();
                    let _ = stream.read_to_string(&mut text);
                    text
                })
                .unwrap_or_default();
            panic!("native TUN worker exited early with {status}: {stderr}");
        }
        assert!(Instant::now() < deadline, "native TUN worker did not start");
        thread::sleep(Duration::from_millis(25));
    }

    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("native TUN worker did not stop after SIGTERM");
        }
        thread::sleep(Duration::from_millis(25));
    };
    assert!(status.success(), "native TUN worker exited with {status}");
    assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());

    fs::remove_dir_all(directory).unwrap();
}
