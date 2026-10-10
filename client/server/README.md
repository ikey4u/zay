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

After both listeners start, `s5` prints a terminal QR code, an HTTP configuration
URL, and a `socks5://` link. In Clash Meta for Android, use **Profiles → + →
Scan QR Code**. In Zay iOS, open the proxy URL editor and tap **Scan server QR
code**, or choose **Import QR code from photo** for a saved screenshot. Camera
scanning works on iOS 16+ devices and requests camera access on first use.
Both apps import a SOCKS5 node with TCP,
UDP, and the configured authentication credentials.
The HTTP QR payload matches [Clash Meta's profile scanner](https://github.com/MetaCubeX/ClashMetaForAndroid/blob/main/app/src/main/java/com/github/kr328/clash/NewProfileActivity.kt#L171-L179).

Choose another QR payload with `--qr FORMAT`:

| Format | Import workflow |
| --- | --- |
| `clash` (default) | Clash/Mihomo configuration URL; scan inside Clash Meta or Zay |
| `clash-import` | `clash://install-config` link; open through a system camera or browser |
| `socks` | Percent-encoded `socks5://` link for clients that accept SOCKS node links |
| `v2ray` | Base64 credential `socks://` link for v2rayNG/v2rayN-style importers |
| `shadowrocket` | Shadowrocket's base64 SOCKS node link; scan with its in-app scanner |
| `quantumult-x` | Quantumult X universal link that adds a server subscription; open with the iOS Camera app or browser (also accepts `quantumx` / `quanx`) |
| `sing-box` | Remote profile import link for sing-box graphical clients; generated profile requires sing-box 1.12+ |
| `telegram` | Telegram SOCKS proxy link; applies to Telegram traffic |
| `browser` | Page with app import links and downloadable profiles |
| `all` | Every available QR format |
| `none` | Print import links without QR codes |

```sh
./target/release/s5 --listen 0.0.0.0:1080 --advertise proxy.example.com --qr all
./target/release/s5 --listen 0.0.0.0:1080 --advertise proxy.example.com --qr shadowrocket
./target/release/s5 --listen 0.0.0.0:1080 --advertise proxy.example.com --qr quantumult-x
```

The browser page offers Clash YAML, sing-box JSON, and Xray/V2Ray SOCKS JSON
downloads, plus a native Quantumult X SOCKS server snippet when credentials can
be represented in that format. Quantumult X's import uses `add-resource` to
preserve existing resources and settings. Universal links require Quantumult X
1.0.30+; the browser page also offers a custom-scheme link for 1.0.29+.
The sing-box profile includes a TUN interface, DNS over HTTPS through
the proxy, and direct bootstrap resolution of the proxy hostname. The Xray/V2Ray
profile opens a local SOCKS listener; mobile apps can apply their own VPN settings.
Zay accepts the SOCKS node links (including Shadowrocket), Clash/sing-box and
Quantumult X app links, Quantumult X SOCKS snippets, Telegram links,
sing-box profiles, Xray SOCKS profiles, and plain or base64 node subscriptions.
When importing JSON profiles, Zay uses the proxy nodes and its own tunnel,
DNS, and routing settings.

v2ray-style links split `username:password` at the first colon, so that format
is omitted when the configured username contains a colon. The standard SOCKS
link and JSON downloads preserve those credentials. Import behavior varies
between apps: use the matching format or download the appropriate profile.
Shadowrocket's legacy QR format is omitted if either credential contains `:`
or `@`. Quantumult X's native snippet is omitted for commas, equals signs,
quotes, control characters, or surrounding whitespace in credentials, since
its documented syntax provides no escaping for them. Other formats remain
available. These two apps still require verification on a physical iPhone.
The formats follow [v2rayNG's SOCKS importer](https://github.com/2dust/v2rayNG/blob/master/V2rayNG/app/src/main/java/com/v2ray/ang/fmt/SocksFmt.kt),
[sing-box's remote profile scheme](https://sing-box.sagernet.org/clients/general/#remote),
and [Telegram's SOCKS link specification](https://core.telegram.org/api/links#socks5-proxy-links).
Quantumult X exports follow its [official URL schemes](https://github.com/crossutility/Quantumult-X/blob/master/url-scheme.md)
and [native server syntax](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf).
The Shadowrocket link layout matches the [resource parser's SOCKS conversion](https://gist.github.com/kanoshiou/cddc4f03f8c01f0b5312b9c800e54aa7#file-parser-js).

For mobile access, listen on a reachable interface and advertise the address
the phone can reach:

```sh
S5_USERNAME=alice S5_PASSWORD=secret ./target/release/s5 \
  --listen 0.0.0.0:1080 --advertise proxy.example.com --import-port 1081
```

`--advertise` accepts a hostname or IPv4/IPv6 address without a scheme or port.
Without it, `s5` uses the listener address or detects the local interface address
for a wildcard listener. Specify the public address when running behind NAT.
The phone must reach both the SOCKS port and the import HTTP port (default:
1081); `--import-port 0` chooses an available port. A loopback listener remains
local and cannot be reached by a phone.

The configuration URL contains a random token and exposes the proxy credentials
to anyone holding that URL. A new token is generated at each startup. For a
stable subscription URL, generate a token once, save it in your service's
environment, and keep `--import-port` fixed:

```sh
openssl rand -hex 32  # save this value as S5_IMPORT_TOKEN
S5_IMPORT_TOKEN='<saved-token>' ./target/release/s5 \
  --listen 0.0.0.0:1080 --advertise proxy.example.com
```

`--import-token` is also available; tokens must contain 32–64 URL-safe letters,
digits, hyphens, or underscores. Import URLs remain valid while `s5` is running.

To run `s5` as a systemd service, `s5 --help-systemd` prints a unit whose
`ExecStart=` uses the binary's current absolute path. It takes no other
options; the unit's comments list the install steps and show where to add
options and credentials:

```sh
./target/release/s5 --help-systemd | sudo tee /etc/systemd/system/s5.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now s5
journalctl -u s5 -f   # logs, including the import links
```

`--udp-timeout SECONDS` sets the UDP association idle timeout (default: 300).
`--max-connections COUNT` caps concurrent SOCKS connections (default: 1024);
further clients wait in the listen backlog. A connection uses up to four file
descriptors, so raise the descriptor limit to match (`ulimit -n`, or
`LimitNOFILE=` under systemd). Running out of descriptors delays new
connections but does not stop the listener. If either listener stops
unexpectedly, `s5` exits with an error so `Restart=on-failure` can restart it.
UDP relay ports are allocated dynamically; clients must keep the SOCKS TCP
control connection open while using a UDP association. Ctrl+C or SIGTERM on
Unix stops the listener and closes active connections. This server requires
neither administrator privileges nor a Zay configuration file or WebUI build.
