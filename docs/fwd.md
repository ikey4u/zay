# `zay fwd`

`zay fwd` forwards TCP streams directly or through WebSocket. It is the Zay version of the old `weconn bridge` command.

## Usage

```bash
zay fwd --to ENDPOINT --from ENDPOINT [--token TOKEN] [-v]
```

| Option | Meaning |
|--------|---------|
| `--to ENDPOINT` | Local listener where clients connect. |
| `--from ENDPOINT` | Upstream endpoint dialed for each accepted connection. |
| `--token TOKEN` | Bearer token for WebSocket authorization. |
| `-v, --verbose` | Increase diagnostic logging. Repeat for more detail. |

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

Local MySQL TCP to a gateway WebSocket route:

```bash
zay fwd --to tcp://127.0.0.1:8899 --from http://public.example.com/db
mysql -h 127.0.0.1 -P 8899 -u USER -p
```

`http://public.example.com/db` is treated as a WebSocket upgrade endpoint (`ws://public.example.com/db`), not plain HTTP forwarding. If the gateway redirects `/db` to `/db/`, `zay fwd` follows the WebSocket redirect and keeps the original public origin when the redirect points at a same-host internal gateway port.

With token auth:

```bash
zay fwd --to http://0.0.0.0:8080/ws --from tcp://127.0.0.1:3306 --token secret
```

For WebSocket listeners, the token is accepted through either:

- `Authorization: Bearer <token>`
- `?token=<token>`

## Source

Implementation lives in `src/fwd/`.
