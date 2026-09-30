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

That runs `devpane/be/manage.sh up`. It builds the debug `zay` binary (WebUI embedded) and the Rust `devpane-be` lab edge, then starts the containers.

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

Image builds use the host network for `apt`, because Docker bridge DNS on this machine cannot resolve Debian mirrors. Running containers stay on `172.30.126.0/24` and do not change host routes.
