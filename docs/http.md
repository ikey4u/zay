# `zay http`

`zay http` serves static files over HTTP or HTTPS. It is a foreground command for local development and LAN sharing.

## Usage

```bash
zay http [--root DIR] [--listen ADDR] [--spa] [--cors] \
  [--cert cert.pem --key key.pem]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `--root DIR` | `.` | Directory to serve. |
| `--listen ADDR` | `127.0.0.1:8080` | Socket address to bind. |
| `--spa` | off | Serve `<root>/index.html` for unknown paths. |
| `--cors` | off | Enable permissive CORS. |
| `--cert FILE` | none | TLS certificate PEM file. |
| `--key FILE` | none | TLS private key PEM file. |

TLS requires both `--cert` and `--key`. Without them, Zay serves plain HTTP.

## Examples

Serve a directory:

```bash
zay http --root dist
```

Serve a single-page app:

```bash
zay http --root dist --spa
```

Serve on the LAN with CORS:

```bash
zay http --root public --listen 0.0.0.0:8080 --cors
```

Serve with a local certificate:

```bash
zay http --root dist --listen 127.0.0.1:8443 \
  --cert localhost.pem --key localhost-key.pem
```

## Behavior

- `--root` must exist and must be a directory.
- `--spa` requires `<root>/index.html`.
- CORS is disabled unless `--cors` is passed.
- No directory listing, upload, auth, reverse proxy, or certificate generation is provided.

## Source

Implementation lives in `src/http/`.
