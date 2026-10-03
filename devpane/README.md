# devpane

Isolated Zay lab. The host does not gain a TUN device and its routes stay unchanged. The subscription proxy, TUN, and EasyTier all stay on Docker network `172.30.126.0/24`.

```text
browser 127.0.0.1:18787 -> zay container WebUI
zay TUN                 -> be:3128 HTTP proxy (subscription http://172.30.126.10:8090/sub)
zay EasyTier            -> relay:11010
devpane.test            -> DNS answer 192.0.2.11, captured by TUN, then a domain rule sends it to the proxy
```

## Start

```bash
mise devpane
```

Requires a running Linux Docker engine with Docker Compose and BuildKit (for example, Docker Desktop on macOS). Initialize repository submodules before the first build with `git submodule update --init --recursive`.

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

On Linux, the launcher uses host networking for image builds to preserve the Debian mirror DNS workaround. On macOS it uses Docker's default build network; Docker Desktop host networking does not need to be enabled. Override either choice with `DEVPANE_BUILD_NETWORK=default mise devpane` or `DEVPANE_BUILD_NETWORK=host mise devpane`. Running containers stay on `172.30.126.0/24` and do not change host routes.
