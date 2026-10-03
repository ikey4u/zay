# devpane

Isolated Zay lab. The host does not gain a TUN device and its routes stay unchanged. The subscription proxy, TUN, and EasyTier all stay on Docker network `172.30.126.0/24`.

```text
browser 127.0.0.1:18787 -> zay container WebUI
zay TUN                 -> be:3128 HTTP proxy (subscription http://172.30.126.10:8090/sub)
zay EasyTier            -> relay:11010
devpane.test            -> DNS answer 192.0.2.11, captured by TUN, then a domain rule sends it to the proxy
```

## Automatic macOS setup

On macOS 13 or newer (Intel or Apple Silicon), run `mise devpane`. The launcher uses the pinned tools in the internal `devpane:macos` mise task to:

1. Install Colima, Lima, the Docker CLI, Compose, and Buildx automatically.
2. Register the Docker plugins under the ignored `devpane/.build/docker` directory.
3. Create or start the dedicated `zay-devpane` Colima VM using Apple's virtualization framework.
4. Build and start the lab containers inside that VM.

Mise is the only tool you need to install beforehand. Homebrew, Docker Desktop, and manual Colima installation are not required. The first run needs network access to download the tools, VM image, container images, and build dependencies.

The VM defaults to 4 CPUs, 8 GiB memory, and a 60 GiB data disk. Override these on initial creation with `DEVPANE_VM_CPUS`, `DEVPANE_VM_MEMORY`, and `DEVPANE_VM_DISK`. A running VM is reused. TUN and Mesh stay inside the VM; the published WebUI port is accessible from macOS.

The launcher selects the lab VM's socket explicitly and keeps Docker client configuration local to the lab. Your existing Docker context and other Colima profiles are preserved. All commands below automatically enter the same mise environment on macOS. `down`, `reset`, `logs`, and `status` do not start a stopped VM. `down` stops the containers but leaves the VM available for reuse. To stop the VM too:

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

That runs `devpane/be/manage.sh up`. Both the debug `zay` binary (WebUI embedded) and the Rust `devpane-be` lab edge are compiled inside Linux Docker build stages, then copied into the runtime images. This works on Linux and macOS, including Apple Silicon, using the Docker engine's default platform. Host Rust, Node.js, and cross-compilation tools are not required.

The first build downloads the build tools and dependencies and can take several minutes. Docker caches subsequent builds; Linux build products do not overwrite host Cargo artifacts or WebUI dependencies.

| Address | Use |
| --- | --- |
| http://127.0.0.1:18787/ | Zay WebUI, no access token required |
| http://127.0.0.1:18090/sub | Lab subscription from the host |

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
