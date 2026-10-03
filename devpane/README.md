# devpane

Isolated Zay lab. The host does not gain a TUN device and its routes stay unchanged. The subscription proxy, TUN, and EasyTier all stay on Docker network `172.30.126.0/24`.

```text
browser 127.0.0.1:18787 -> zay container WebUI
zay TUN                 -> be:3128 HTTP proxy (subscription http://172.30.126.10:8090/sub)
zay EasyTier            -> relay:11010
devpane.test            -> DNS answer 192.0.2.11, captured by TUN, then a domain rule sends it to the proxy
```

## macOS setup (Colima)

[Colima](https://colima.run/docs/installation/) runs the Linux VM for the lab. Install the Docker CLI and its plugins from Homebrew; Docker Desktop is not required or used in this setup.

```bash
brew install colima docker docker-compose docker-buildx
mkdir -p ~/.docker/cli-plugins
ln -sfn "$(brew --prefix)/opt/docker-compose/bin/docker-compose" ~/.docker/cli-plugins/docker-compose
ln -sfn "$(brew --prefix)/opt/docker-buildx/bin/docker-buildx" ~/.docker/cli-plugins/docker-buildx
colima start --runtime docker --cpu 4 --memory 8 --disk 60
docker context use colima
docker info
docker compose version
docker buildx version
```

The CPU, memory, and disk settings above allocate resources for the Rust build; adjust them for your machine. TUN and Mesh run inside Colima's Linux VM, and the published WebUI port is accessible from macOS. For subsequent sessions, start the existing VM with `colima start` before running the lab. `colima stop` stops the VM and its containers.

The launcher uses your selected Docker context. Keep `colima` selected on macOS and unset any `DOCKER_HOST` or `DOCKER_CONTEXT` override pointing to another engine.

## Start

```bash
mise devpane
```

Requires a running Linux Docker engine with Docker Compose and BuildKit. On Linux, use Docker Engine. On macOS, use Colima as described below. Initialize repository submodules before the first build with `git submodule update --init --recursive`.

That runs `devpane/be/manage.sh up`. Both the debug `zay` binary (WebUI embedded) and the Rust `devpane-be` lab edge are compiled inside Linux Docker build stages, then copied into the runtime images. This works on Linux and macOS, including Apple Silicon, using the Docker engine's default platform. Host Rust, Node.js, and cross-compilation tools are not required.

The first build downloads the build tools and dependencies and can take several minutes. Docker caches subsequent builds; Linux build products do not overwrite host Cargo artifacts or WebUI dependencies.

| Address | Use |
| --- | --- |
| http://127.0.0.1:18787/ | Zay WebUI, token `devpane-local-token` |
| http://127.0.0.1:18090/sub | Lab subscription from the host |

The WebUI **Lab** sidebar runs `curl` / `nc` inside the container. The browser that opened the page is not on that path.

```bash
devpane/be/manage.sh logs
devpane/be/manage.sh down
devpane/be/manage.sh reset   # also deletes the saved container config
```

The seed config is `devpane/zay.toml`. The container copies it into the volume on first start. After editing the seed, run `reset` to load it again.

On Linux, the launcher uses host networking for image builds to preserve the Debian mirror DNS workaround. On macOS it uses the default build network inside Colima's Linux VM. Override either choice with `DEVPANE_BUILD_NETWORK=default mise devpane` or `DEVPANE_BUILD_NETWORK=host mise devpane`. Running containers stay on `172.30.126.0/24` and do not change host routes.
