# Standalone servers

`s5` reuses `crates/singbox/src/inbound/socks.rs` with singbox's `socks` feature
and default features disabled. It uses the shared SOCKS protocol, listener,
authentication, and UDP framing without linking the full routing engine.
See [the library feature guide](../../crates/singbox/README.md) for embedding
and feature isolation details.
It forwards SOCKS5 TCP CONNECT and UDP ASSOCIATE traffic directly to the
requested destination, including hostname resolution and IPv4/IPv6 targets.
The shared listener also accepts SOCKS4/4a when authentication is disabled.
SOCKS BIND is unsupported.

```sh
cargo build --release -p zay-server --bin s5
./target/release/s5                         # 127.0.0.1:1080
./target/release/s5 --listen 0.0.0.0:1080    # listen on all IPv4 interfaces
./target/release/s5 --listen '[::1]:1080'    # IPv6 loopback
```

Authentication is optional. Supply both a username and password to require it;
each must contain 1–255 bytes. Credentials can come from `S5_USERNAME` and
`S5_PASSWORD`, or from `--username` and `--password`.

```sh
S5_USERNAME=alice S5_PASSWORD=secret ./target/release/s5 --listen 0.0.0.0:1080
curl --socks5-hostname alice:secret@127.0.0.1:1080 https://example.com
```

For an unauthenticated local server:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

`--udp-timeout SECONDS` sets the UDP association idle timeout (default: 300).
UDP relay ports are allocated dynamically; clients must keep the SOCKS TCP
control connection open while using a UDP association. Ctrl+C or SIGTERM on
Unix stops the listener and closes active connections. This server requires
neither administrator privileges nor a Zay configuration file or WebUI build.
