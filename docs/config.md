# `zay config`

`zay config` manages the current `zay.toml` without starting the network stack.

Commands:

```bash
zay config dump [OPTIONS]
zay config set [OPTIONS] <KEY> <VALUE>
zay config unset [OPTIONS] <KEY>
zay config edit [OPTIONS]
```

## Config Location

`zay config` uses the same location rules as `zay stack`:

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

`dump` prints the file as stored on disk, including comments and the `[mihomo].mixin` multiline string.

## Set

Set a TOML key using a dotted key path:

```bash
zay config set mixed_port 7891
zay config set log_level '"debug"'
zay config set tun_exclude_routes '["11.155.134.0/24"]'
zay config set mesh.network_name '"my-network"'
```

Values are parsed as TOML literals. Use shell quotes to pass strings and arrays safely:

```bash
zay config set health_check_url '"http://cp.cloudflare.com/generate_204"'
zay config set tun true
```

To update the Mihomo mixin, set `mihomo.mixin` to a TOML multiline string:

```bash
zay config set mihomo.mixin "'''
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
'''"
```

For larger mixins, `zay config edit` is usually easier.

## Unset

Remove a key:

```bash
zay config unset tun_exclude_routes
zay config unset mesh.network_name
```

`unset` errors if the target key does not exist.

## Edit

Open `zay.toml` in `$EDITOR`:

```bash
zay config edit
EDITOR=vim zay config edit
zay config edit -c ./zay.toml
```

Use `edit` for multiline changes, especially `[mihomo].mixin`.

## Key Paths

Key paths are dot-separated TOML paths:

```text
mixed_port
health_check_url
mihomo.mixin
mesh.network_name
mesh.mesh_routes
```

`zay config` rejects empty paths, empty path segments, and array indexing. For example, `mesh.peers.0` is not supported; set the whole array instead:

```bash
zay config set mesh.peers '["tcp://public.easytier.top:11010"]'
```
