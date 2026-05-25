# `zay fwd`

`zay fwd` forwards TCP streams directly or through WebSocket. It is the Zay version of the old `weconn bridge` command.

## Usage

```bash
zay fwd --to ENDPOINT --from ENDPOINT [--token TOKEN]
```

| Option | Meaning |
|--------|---------|
| `--to ENDPOINT` | Local listener where clients connect. |
| `--from ENDPOINT` | Upstream endpoint dialed for each accepted connection. |
| `--token TOKEN` | Bearer token for WebSocket authorization. |

## Endpoint Support

`--to` supports:

- `tcp://host:port`
- `ws://host:port/path`
- `http://host:port/path` (treated as WebSocket upgrade)

`--from` supports:

- `tcp://host:port`
- `ws://host:port/path`
- `wss://host:port/path`
- `http://host:port/path`
- `https://host:port/path`

Supported combinations:

| Direction | Example |
|-----------|---------|
| TCP → TCP | `--to tcp://0.0.0.0:8080 --from tcp://127.0.0.1:80` |
| TCP → WebSocket | `--to tcp://127.0.0.1:3306 --from wss://example.com/db` |
| WebSocket → TCP | `--to http://0.0.0.0:8080/ws --from tcp://127.0.0.1:3306` |

TLS server support for `--to wss://...` / `--to https://...` is not implemented.

## Examples

Direct TCP relay:

```bash
zay fwd --to tcp://0.0.0.0:8080 --from tcp://127.0.0.1:80
```

Local TCP to remote WebSocket:

```bash
zay fwd --to tcp://127.0.0.1:3306 --from wss://public.example.com/mysql
```

WebSocket listener to local TCP:

```bash
zay fwd --to http://0.0.0.0:8080/ws --from tcp://127.0.0.1:3306
```

With token auth:

```bash
zay fwd --to http://0.0.0.0:8080/ws --from tcp://127.0.0.1:3306 --token secret
```

For WebSocket listeners, the token is accepted through either:

- `Authorization: Bearer <token>`
- `?token=<token>`

## Source

Implementation lives in `src/fwd/`.
