# singbox library features

The default `full` feature provides the existing embedded engine API, routing,
DNS transports, tunnel endpoints, protocol registry, and service integrations.
Zay's desktop, WebUI, and mobile clients continue to use this default.

For a standalone direct SOCKS server, disable defaults and select `socks`:

```toml
singbox = { path = "crates/singbox", default-features = false, features = ["socks"] }
```

This exposes `inbound::socks::{SocksServer, SocksServerOptions}`,
`protocol::socks` handshake and packet helpers, `common::network::SocksAddr`,
and `option::User`. It depends only on Tokio and tokio-util. The full engine's
TLS/QUIC, crypto, Tor, tunnel, database, and RPC dependencies and build steps
are excluded. This initial split supports `full` and `socks`; individual
protocols inside the full engine do not yet have separate feature gates.

`SocksServer` forwards TCP CONNECT and UDP ASSOCIATE using the operating
system's hostname resolution. It shares authentication, framing, listener
handling, UDP client validation, and shutdown handling with the routed inbound.
It also supports unauthenticated SOCKS4/4a CONNECT. BIND is unsupported.
Handshake and destination connection timeouts default to 10 seconds, and the
UDP idle timeout defaults to 300 seconds. `close()` stops the listener and all
active connections; dropping the server also requests cancellation.

```rust
use singbox::inbound::socks::{SocksServer, SocksServerOptions};

async fn example() -> std::io::Result<()> {
    let mut server = SocksServer::new(SocksServerOptions::default())?;
    server.start().await?;
    // Wait for the embedding application's shutdown event here.
    server.close().await?;
    Ok(())
}
```

```sh
cargo test -p singbox --no-default-features --features socks
cargo test -p zay-server
```

Cargo combines dependency features across packages in one invocation. Build
`zay` and `zay-server` separately to keep the standalone build minimal. The
`macos:build:linux-x64` task does this automatically. Building the whole
workspace retains the full engine through Zay's default dependency.
