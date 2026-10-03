# devpane

Isolated Zay lab. The host does not gain a TUN device and its routes stay unchanged. The fake subscription and HTTP proxy run as a native host process, outside Docker and the Colima VM. TUN and EasyTier stay in containers on Docker network `172.30.126.0/24`.

```text
browser 127.0.0.1:18787 -> zay container WebUI
zay TUN                 -> host:13128 HTTP proxy (subscription host:18090/sub)
zay EasyTier .2          -> relay:11010 -> mesh-peer .3 (HTTP :8090 over Mesh)
devpane.test            -> DNS answer 192.0.2.11, captured by TUN, then a domain rule sends it to the proxy
```

## Automatic macOS setup

On macOS 13 or newer (Intel or Apple Silicon), run `mise devpane`. The launcher uses the pinned tools in the internal `devpane:macos` mise task to:

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
mise devpane
```

Initialize repository submodules before the first build with `git submodule update --init --recursive`.

That runs `devpane/be/manage.sh up`. Both the debug `zay` binary (WebUI embedded) and the Rust `devpane-be` lab edge are compiled inside Linux Docker build stages, then copied into the runtime images. This works on Linux and macOS, including Apple Silicon, using the Docker engine's default platform. The small native host proxy is built separately with mise-managed Rust; host Node.js and cross-compilation tools are not required. A native C linker is needed (Xcode Command Line Tools on macOS, a C toolchain on Linux).

The first build downloads the build tools and dependencies and can take several minutes. Docker caches subsequent builds; Linux build products do not overwrite host Cargo artifacts or WebUI dependencies.

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

On Linux, the launcher uses host networking for image builds to preserve the Debian mirror DNS workaround. On macOS it uses the default build network inside Colima's Linux VM. Override either choice with `DEVPANE_BUILD_NETWORK=default mise devpane` or `DEVPANE_BUILD_NETWORK=host mise devpane`. Running containers stay on `172.30.126.0/24` and do not change host routes.

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

This installs Python through mise and performs 27 checks against the running lab: native proxy identity and subscription, explicit proxy access, DNS, transparent TUN routing, stale FakeIP rejection without losing the TUN reader, direct exclusions, Mesh HTTP between virtual IPs, separate Mesh/TUN interfaces, bidirectional ICMP, and recovery after host proxy, Mesh peer, and Zay core outages. The outage checks temporarily interrupt the lab and restore services. Concurrent test runs are rejected. Tests expect the seeded lab routes and Mesh settings.

Results are saved to `devpane/.build/network-test.json`. Launcher regression tests simulate both macOS and Linux without Docker:

```bash
python3 devpane/be/test_manage.py
```

Use `devpane/be/host-proxy.sh status` to inspect the native process; its log is `devpane/.build/host-proxy.log`. `manage.sh down` and `reset` stop it along with the containers. The WebUI's Mesh preset probes the peer's HTTP service over `10.126.126.3`, so it verifies actual Mesh traffic.

### External browsing and DNS

The DNS fixture forwards external queries over certificate-verified HTTPS to AliDNS (`dns.alidns.com`, pinned to `223.5.5.5`). This keeps host VPN DNS interception from injecting FakeIPs into the container. Both the container resolver and Zay's upstream resolver use this fixture. `devpane.test` remains a local deterministic answer. The IPv4-only Docker bridge returns empty AAAA answers so Chromium does not select an IPv6 connection with no usable upstream route. Existing seeded configs are backed up before adding the lab DNS mixin; custom mixins are preserved.

The network suite also checks real Baidu DNS answers and renders `https://baidu.com` with Chromium. These checks require Internet access and can fail during upstream outages. The screenshot is saved to `devpane/.build/baidu-render.png`; a passing local fixture alone no longer counts as successful external browsing.
