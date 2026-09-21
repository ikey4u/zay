# `zay x run ssh`

`zay x run ssh` provides OpenSSH-compatible local and remote port forwarding with automatic reconnect.

## Usage

```bash
zay x run ssh [-L SPEC]... [-R SPEC]... [-J HOST]... [OPTIONS] SSH_HOST
```

At least one `-L` or `-R` forward is required.

## Forward Syntax

```text
[bind_host:]bind_port:remote_host:remote_port
```

| Option | Meaning |
|--------|---------|
| `-L, --local-forward SPEC` | Listen locally; SSH server connects to target. Repeatable. |
| `-R, --remote-forward SPEC` | Listen on SSH server; local machine connects to target. Repeatable. |
| `-J, --jump HOST` | ProxyJump host. Repeatable or comma-separated. |
| `-u, --user USER` | Override SSH username. |
| `-P, --password PASSWORD` | Password for final SSH host. |
| `-i, --identity FILE` | Private key file. |
| `-p, --port PORT` | SSH port. |
| `--strict-host-keys` | Reject unknown host keys instead of accept-new behavior. |

## Local Forwards

Listen on localhost only:

```bash
zay x run ssh -L 3307:10.0.0.5:3306 myserver
```

Listen on all interfaces:

```bash
zay x run ssh -L 0.0.0.0:8080:10.0.0.5:80 myserver
```

Use a jump host:

```bash
zay x run ssh -J bastion -L 3307:mysql.internal:3306 app-server
```

Multiple forwards:

```bash
zay x run ssh -L 3307:10.0.0.5:3306 -L 6380:10.0.0.5:6379 myserver
```

## Remote Forwards

Listen on the SSH server's localhost:

```bash
zay x run ssh -R 127.0.0.1:9000:127.0.0.1:3000 myserver
```

Listen on all interfaces on the SSH server:

```bash
zay x run ssh -R 0.0.0.0:9000:192.168.1.20:3000 myserver
```

The remote server must allow gateway ports for non-localhost remote binds.

## SSH Config

`zay x run ssh` reads standard `~/.ssh/config` entries for host aliases, user, port, identity files, and `ProxyJump`. CLI options override config values.

## Reconnect Behavior

- Local `-L` listeners stay open during reconnect.
- New clients wait while the SSH session is being rebuilt.
- ProxyJump chains are rebuilt on reconnect.

## Source

Implementation lives in `src/ssh/`.
