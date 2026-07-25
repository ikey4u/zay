# `zay config`

`zay config` manages the current `zay.toml` without starting the network stack.

Commands:

```bash
zay config dump [OPTIONS]
zay config template
zay config set [OPTIONS] <KEY> <VALUE>
zay config unset [OPTIONS] <KEY>
zay config edit [OPTIONS]
```

## Config Location

`zay config` uses the same location rules as `zay service`:

1. `-d, --data-dir DIR` uses `DIR` as the data dir.
2. `-c, --config FILE` uses `FILE`, and the data dir is `FILE`'s parent when `--data-dir` is not provided.
3. If neither is provided, Zay uses the default config dir, usually `~/.config/zay/zay.toml`.

When both `--data-dir` and `--config` are provided, `--config` selects the `zay.toml` file and `--data-dir` selects the runtime data dir.

If `zay.toml` does not exist, `zay config` creates the default file first.

## Dump

Print the raw `zay.toml`:

```bash
zay config dump
zay config dump -c ./zay.toml
zay config dump -d ~/.config/zay
```

`dump` prints the file as stored on disk, including comments and the `[proxy].mixin` multiline string.

## Template

Print the complete default configuration without reading or creating `zay.toml`:

```bash
zay config template > zay.toml
```

## Set

Set a TOML key using a dotted key path:

```bash
zay config set proxy.mixed_port 7891
zay config set proxy.log_level '"debug"'
zay config set proxy.tun.exclude_routes '["11.155.134.0/24"]'
zay config set proxy.mesh.network_name '"my-network"'
```

Values are parsed as TOML literals. Use shell quotes to pass strings and arrays safely:

```bash
zay config set proxy.health_check_url '"http://cp.cloudflare.com/generate_204"'
zay config set proxy.tun.enabled true
```

To add a sing-box JSON fragment, set `proxy.mixin` to a TOML multiline string:

```bash
zay config set proxy.mixin "'''
{ \"log\": { \"level\": \"debug\" } }
'''"
```

For larger mixins, `zay config edit` is usually easier.

## Unset

Remove a key:

```bash
zay config unset proxy.tun.exclude_routes
zay config unset proxy.mesh.network_name
```

`unset` errors if the target key does not exist.

## Edit

Open `zay.toml` in `$EDITOR`:

```bash
zay config edit
EDITOR=vim zay config edit
zay config edit -c ./zay.toml
```

Use `edit` for multiline changes, especially `[proxy].mixin`.

## Domain Proxy Groups

List the current subscription node tags after starting the proxy service:

```bash
zay service proxy list
zay service -d ./config proxy list
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

The selected nodes are actively tested by sing-box. A subscription update that
removes or renames one of the configured tags causes service startup to fail
with a clear error rather than silently routing through another proxy.

## Key Paths

Key paths are dot-separated TOML paths:

```text
proxy.mixed_port
proxy.health_check_url
proxy.mixin
proxy.mesh.network_name
proxy.mesh.mesh_routes
```

`zay config` rejects empty paths, empty path segments, and array indexing. For example, `mesh.peers.0` is not supported; set the whole array instead:

```bash
zay config set proxy.mesh.peers '["tcp://public.easytier.top:11010"]'
```
