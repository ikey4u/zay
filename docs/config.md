# `zay x config`

`zay x config` manages the current `zay.toml` without starting the network stack.

Commands:

```bash
zay x config dump [OPTIONS]
zay x config template
zay x config set [OPTIONS] <KEY> <VALUE>
zay x config unset [OPTIONS] <KEY>
zay x config edit [OPTIONS]
```

## Config Location

`zay x config` uses the same location rules as `zay x service`:

1. `-d, --data-dir DIR` uses `DIR` as the data dir.
2. `-c, --config FILE` uses `FILE`, and the data dir is `FILE`'s parent when `--data-dir` is not provided.
3. If neither is provided, Zay uses the default config dir, usually `~/.config/zay/zay.toml`.

When both `--data-dir` and `--config` are provided, `--config` selects the `zay.toml` file and `--data-dir` selects the runtime data dir.

If `zay.toml` does not exist, `zay x config` creates the default file first.

## Dump

Print the raw `zay.toml`:

```bash
zay x config dump
zay x config dump -c ./zay.toml
zay x config dump -d ~/.config/zay
```

`dump` prints the file as stored on disk, including comments and the `[proxy].mixin` multiline string.

## Template

Print the complete default configuration without reading or creating `zay.toml`:

```bash
zay x config template > zay.toml
```

## Set

Set a TOML key using a dotted key path:

```bash
zay x config set proxy.mixed_port 7891
zay x config set proxy.log_level '"debug"'
zay x config set proxy.tun.exclude_routes '["11.155.134.0/24"]'
zay x config set proxy.mesh.network_name '"my-network"'
```

Values are parsed as TOML literals. Use shell quotes to pass strings and arrays safely:

```bash
zay x config set proxy.health_check_url '"http://cp.cloudflare.com/generate_204"'
zay x config set proxy.tun.enabled true
```

To add a sing-box JSON fragment, set `proxy.mixin` to a TOML multiline string:

```bash
zay x config set proxy.mixin "'''
{ \"log\": { \"level\": \"debug\" } }
'''"
```

For larger mixins, `zay x config edit` is usually easier.

## Unset

Remove a key:

```bash
zay x config unset proxy.tun.exclude_routes
zay x config unset proxy.mesh.network_name
```

`unset` errors if the target key does not exist.

## Edit

Open `zay.toml` in `$EDITOR`:

```bash
zay x config edit
EDITOR=vim zay x config edit
zay x config edit -c ./zay.toml
```

Use `edit` for multiline changes, especially `[proxy].mixin`.

## Domain Proxy Groups

List the current subscription node tags after starting the proxy service:

```bash
zay x service proxy list
zay x service -d ./config proxy list
```

Use those exact tags to route a domain suffix set through a dedicated `urltest`
group. This route takes precedence over generic proxy rules:

```toml
[[proxy.domain_rule]]
name = "cursor"
by_suffix = ["cursor.com", "cursor.sh"]
outbounds = [
  "proxy-01",
  "proxy-02",
]
# Optional; inherits [proxy] health_check_url when omitted.
health_check_url = "https://www.gstatic.com/generate_204"
interval = 300
tolerance = 100
```

The selected nodes are actively tested by sing-box. If a subscription update
removes or renames a configured tag, Zay logs a warning and keeps the remaining
available candidates. If every configured candidate disappeared, the domain
rule falls back to the main `Proxy`/`Auto` group so a provider-side rename does
not prevent the core and Mesh from starting. Use `zay x service proxy list` to
replace stale tags when you still need a fixed regional group.

## Key Paths

Key paths are dot-separated TOML paths:

```text
proxy.mixed_port
proxy.health_check_url
proxy.mixin
proxy.mesh.name
proxy.mesh.network_name
proxy.mesh.mesh_routes
```

`proxy.mixed_port` is used only when `[proxy.tun].enabled = false`. Full TUN
mode does not open a loopback HTTP/SOCKS listener; its health checks and rule
downloads use the system path captured by the TUN itself.

`zay x config` rejects empty paths, empty path segments, and array indexing. For example, `mesh.peers.0` is not supported; set the whole array instead:

```bash
zay x config set proxy.mesh.peers '["tcp://public.easytier.top:11010"]'
```
