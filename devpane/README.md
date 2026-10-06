# devpane

Run `mise devpane` to start the lab matching the host OS: macOS on macOS,
Linux on Linux. The native macOS VM requires Apple Silicon; Intel Mac users
can explicitly run the Linux lab. There is no silent fallback.

Or choose the lab explicitly:

| Command | Supported host | WebUI |
| --- | --- | --- |
| `mise devpane:linux` | Linux or macOS (ARM64/x86-64; macOS 13+) | http://127.0.0.1:18787/ |
| `mise devpane:macos` | Apple Silicon macOS 13+ | http://127.0.0.1:18788/ |

Both launchers reject unsupported hosts before provisioning or stopping any lab.
The macOS lab also starts the Linux lab for its remote Mesh peer.

Isolated Zay lab. The host does not gain a TUN device and its routes stay unchanged. The fake subscription and HTTP proxy run as a native host process, outside Docker and the Colima VM. TUN and EasyTier stay in containers on Docker network `172.30.126.0/24`.

```text
browser 127.0.0.1:18787 -> zay container WebUI
zay TUN                 -> host:13128 HTTP proxy (subscription host:18090/sub)
zay EasyTier .2          -> relay:11010 -> mesh-peer .3 (HTTP :8090 over Mesh)
devpane.test            -> DNS answer 192.0.2.11, captured by TUN, then a domain rule sends it to the proxy
```

## Automatic macOS setup

On macOS 13 or newer (Intel or Apple Silicon), run `mise devpane:linux`. The launcher uses the pinned tools in the internal `devpane:colima-runtime` mise task to:

1. Install Colima, Lima, the Docker CLI, Compose, and Buildx automatically.
2. Register the Docker plugins under the ignored `devpane/.build/docker` directory.
3. Create or start the dedicated `zay-devpane` Colima VM using Apple's virtualization framework.
4. Install Rust through mise and build/start the native host subscription proxy.
5. Build and start the lab containers inside that VM.

Install mise and Xcode Command Line Tools beforehand. Rust and the container tools are managed by mise. Homebrew, Docker Desktop, and manual Colima installation are not required. The first run needs network access to download the tools, VM image, container images, and build dependencies.

The VM defaults to 4 CPUs, 8 GiB memory, and a 60 GiB data disk. Override these on initial creation with `DEVPANE_VM_CPUS`, `DEVPANE_VM_MEMORY`, and `DEVPANE_VM_DISK`. A running VM is reused. TUN and Mesh stay inside the VM; the published WebUI port is accessible from macOS.

The launcher selects the lab VM's socket explicitly and keeps Docker client configuration local to the lab. Your existing Docker context and other Colima profiles are preserved. All commands below automatically enter the same mise environment on macOS. `down`, `reset`, `logs`, and `status` do not start a stopped VM. `down` stops the containers and native proxy but leaves the VM available for reuse. To stop the VM too:

```bash
mise exec colima@0.10.3 lima@2.2.0 -- colima --profile zay-devpane stop
```

## Linux prerequisites

Use an installed, running Docker Engine with Compose and BuildKit. The launcher uses the existing engine and does not install or start Colima on Linux.

## Start

```bash
mise devpane:linux
```

Initialize repository submodules before the first build with `git submodule update --init --recursive`.

That runs `devpane/be/manage.sh up`. Mise provisions Rust, Zig, cargo-zigbuild, Node.js, protoc (including the standard `.proto` files), and CMake on the host. The host cross-compiles `zay` with its embedded WebUI and `devpane-be` for the Docker engine’s Linux architecture (ARM64 or x86-64). This also works on macOS: the output is a Linux ELF executable, not a macOS executable.

Docker only packages the completed binaries with runtime tools and starts the lab. No Rust or WebUI compilation runs in the VM. Incremental compiler outputs stay under `devpane/.build/linux-target/`; packaged binaries are in `devpane/.build/linux/{arm64,amd64}/`. Set `DEVPANE_BUILD_JOBS` to change host compiler parallelism (default 2). The native host subscription proxy is built separately with mise-managed Rust. A host C linker is needed (Xcode Command Line Tools on macOS, a C toolchain on Linux).

The first build downloads the build tools and dependencies and can take several minutes. Cargo caches subsequent host builds, and Docker caches runtime image layers. Linux Cargo outputs are kept separate from native host outputs.

| Address | Use |
| --- | --- |
| http://127.0.0.1:18787/ | Zay WebUI, no access token required |
| Host port 18090 `/sub` | Fake Clash subscription (macOS: `127.0.0.1`; Linux: Docker bridge gateway) |

The WebUI **Lab** sidebar runs `curl` / `nc` inside the container. The browser that opened the page is not on that path.

```bash
devpane/be/manage.sh logs
devpane/be/manage.sh down
devpane/be/manage.sh reset   # also deletes the saved container config
```

The seed config is `devpane/zay.toml`. The container copies it into the volume on first start. After editing the seed, run `reset` to load it again.

On Linux, the launcher uses host networking for image builds to preserve the Debian mirror DNS workaround. On macOS it uses the default build network inside Colima's Linux VM. Override either choice with `DEVPANE_BUILD_NETWORK=default mise devpane:linux` or `DEVPANE_BUILD_NETWORK=host mise devpane:linux`. Running containers stay on `172.30.126.0/24` and do not change host routes.

## Browser and terminal

The Lab panel includes a Chromium-rendered snapshot with an address bar, back/forward history, reload, and a separate connection check (HTTP status, remote IP, DNS/connect timing, and response headers). Page scripts, styles, and images load inside the Zay container. Snapshots are 1280 × 800 and are refreshed by navigation; they are not a live interactive browser session.

The container terminal is a persistent Bash PTY with command history, resize, and Ctrl+C. It runs as the container user and supports arbitrary commands, including `curl`, `ping`, `dig`, `ip`, and `traceroute`. Disconnecting closes the shell session. Browser rendering and terminal endpoints are available only in the devpane container.

The lab WebUI has no access token and is published only on `127.0.0.1`. It rejects cross-origin browser requests and non-local Host headers. Normal Zay WebUI authentication requirements are unchanged.

## Host proxy and network tests

The launcher starts the native fixture automatically and records its PID, log, and host address under `devpane/.build/`. On macOS it binds to loopback; containers reach it through Colima's `host.lima.internal` address. On Linux it binds to the Docker bridge gateway. Override Linux discovery with `DEVPANE_HOST_ADDR` and `DEVPANE_HOST_BIND` if needed. Linux requires a local Docker Engine; remote engines cannot reach this local fixture using their own bridge gateway.

The subscription advertises the host HTTP proxy on port 13128. Requests for `devpane.test` return deterministic JSON or a browser test page; other destinations are forwarded normally. The DNS fixture remains inside Docker. Existing lab configs using the former container subscription are migrated automatically, with a backup; other settings are preserved.

```bash
mise devpane:test
```

This installs Python through mise and performs network checks against the running lab: native proxy identity and subscription, explicit proxy access, DNS, transparent TUN routing, stale FakeIP rejection without losing the TUN reader, 24 simultaneous connections to one destination, direct exclusions, Mesh HTTP between virtual IPs, separate Mesh/TUN interfaces, bidirectional ICMP, and recovery after host proxy, Mesh peer, and Zay core outages. The outage checks temporarily interrupt the lab and restore services. Concurrent test runs are rejected. Tests expect the seeded lab routes and Mesh settings.

Results are saved to `devpane/.build/network-test.json`. Launcher regression tests simulate both macOS and Linux without Docker:

```bash
python3 devpane/be/test_manage.py
```

Use `devpane/be/host-proxy.sh status` to inspect the native process; its log is `devpane/.build/host-proxy.log`. `manage.sh down` and `reset` stop it along with the containers. The WebUI's Mesh preset probes the peer's HTTP service over `10.126.126.3`, so it verifies actual Mesh traffic.

### External browsing and DNS

The DNS fixture forwards external queries over certificate-verified HTTPS to AliDNS (`dns.alidns.com`, pinned to `223.5.5.5`). This keeps host VPN DNS interception from injecting FakeIPs into the container. Container applications use Zay’s TUN DNS at `10.14.14.10`. Proxied domains receive Zay FakeIPs, preserving their hostnames for resolution at the host proxy; direct domains use the HTTPS DNS fixture. This prevents incorrect public DNS answers for proxied sites from becoming fixed upstream destinations. `devpane.test` remains a local deterministic answer. The IPv4-only Docker bridge returns empty AAAA answers so Chromium does not select an IPv6 connection with no usable upstream route. Existing seeded configs are backed up before adding the lab DNS mixin; custom mixins are preserved. The exact previous seed mixin is also migrated with a `.before-lab-proxy-dns` backup.

The network suite requires all four external paths to pass: TUN → Baidu, TUN → Google, Mesh → Baidu, and Mesh → Google. Each follows HTTPS redirects, verifies certificates, requires a final HTTP 200 with the expected page content, and renders the page with Chromium. The Mesh tests use the Zay mixed proxy at `10.126.126.3:7890`, reached over the peer's EasyTier virtual address. The peer uses `mesh-peer.toml`, with its own TUN and the host subscription. No gateway ports are published to the host. Stopping the peer must break the Mesh Internet path.

All four results are recorded even if an external destination fails. Screenshots are saved as `devpane/.build/{tun,mesh}-{baidu.com,google.com}-render.png`. The native fixture also uses IPv4 upstream connections, avoiding host VPN IPv6 addresses that accept TCP but stall TLS. Chromium disables QUIC because the fixture's HTTP CONNECT proxy supports TCP only. These checks require a working Internet exit: the native fixture uses the host's existing network and does not supply a remote proxy capable of bypassing upstream restrictions. A local fixture response, successful CONNECT, or HTTP redirect alone does not count as external browsing success.

### Download a macOS VM

On an Apple Silicon Mac, run `mise setup:macosvm`. Mise installs Tart and downloads
the macOS Tahoe base image as `zay-devpane-macos`, showing progress in the terminal.
The download is approximately 27 GB and is stored under `devpane/.build/macos-vm/`.
An existing VM with that name is reused. This command only downloads the VM; it
does not build Zay, boot the guest, run tests, or change host routes or DNS.
Set `DEVPANE_VM_DOWNLOAD_CONCURRENCY` to adjust simultaneous transfers (default 4).

### Test the native macOS guest

Start the lab with `mise devpane:macos` to build on the host and provision the
guests. Then stop the persistent pane and run the test harness:

```sh
bash devpane/be/macos-pane.sh stop
mise exec python@3.13.12 -- bash devpane/be/manage.sh test-macos
```

The harness runs Zay inside the macOS VM. Browser checks currently require Google Chrome in the host's
`/Applications` directory; only the application is copied, never its profile.

The suite checks native TUN routing and system DNS, separate Mesh interfaces,
bidirectional ping, 72 concurrent requests, Baidu and Google HTTPS and rendering
over both paths, and proxy/peer/core outage recovery. Mesh requests cross the
Linux peer's virtual address. The HTTP fixture restarts with that peer because
they share a network namespace.

Results and screenshots are saved under `devpane/.build/macos/`, including
`network-test.json`. Guest DNS is restored and the guest test services are stopped
afterward; the VM remains available. Host routes, DNS, and Clash configuration
are not modified. The host subscription proxy uses the VM's virtual network
interface, and the lab relay is exposed on host loopback for an SSH forward.

### Interactive native macOS devpane

Run `mise devpane:macos` on an Apple Silicon Mac. It builds Zay and the
WebUI on the host, deploys them into the Tart macOS guest, and keeps the lab
running in the background. The existing Linux lab supplies the remote Mesh peer.

- **macOS:** http://127.0.0.1:18788/ — Lab terminal runs inside the Darwin guest;
  browser snapshots use Chrome inside that same guest.
- **Linux:** http://127.0.0.1:18787/ — remains the separate Linux container lab.
- Status: `bash devpane/be/macos-pane.sh status`
- Log: `tail -f devpane/.build/macos/devpane.log`
- Stop: `bash devpane/be/macos-pane.sh stop` — stops guest services and restores guest DNS.

The macOS WebUI listens on guest loopback and is forwarded to host loopback over
SSH. No token is needed for this local connection. Interactive lab tools require
both `ZAY_LAB=devpane-macos` and the guest-only `/etc/zay-devpane-macos` marker.
Host TUN, DNS, default routes, and Clash are unchanged. Browser provisioning copies
only the Chrome application, never the developer's browser profile. Automated
macOS tests and the persistent pane share a lock; stop the pane before running
the test harness above.

### Native GPUI desktop in its own macOS VM

Set `APPLE_SIGN_IDENTITY` in your shell to an existing Apple signing certificate,
then run `mise dev:desktop`. This builds/signs the app on the host and deploys it
to a separate `zay-desktop-macos` Tart guest. Screen Sharing opens the guest's
native desktop. The guest login and administrator password are `admin`; these
are the base image's disposable lab credentials. Test TUN, Mesh node mode, helper
installation/cancellation, and background item labeling inside that guest.

The desktop VM uses default NAT without host folder or Tart clipboard sharing.
It receives the signed application and keeps its inherited DNS settings by default.
`ZAY_DESKTOP_VM_DNS=alidns mise dev:desktop` additionally installs the repository's
small DNS lab fixture inside the guest. This opt-in forwards guest DNS queries to
AliDNS (`dns.alidns.com`) over HTTPS with IPv4 answers, avoiding a host VPN's
synthetic addresses during TUN tests.
Host routes, DNS, proxy settings, and Zay services
are untouched. The existing CLI/WebUI lab VM remains separate. Use
`mise dev:desktop:open` to reopen it, `mise dev:desktop:logs` to collect guest
helper logs under `devpane/.build/desktop-macos/`, and `mise dev:desktop:stop`
to shut it down. `mise dev:desktop:host` explicitly opts into running on the host.
