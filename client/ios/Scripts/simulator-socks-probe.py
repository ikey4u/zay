#!/usr/bin/env python3
"""Deterministic SOCKS5 endpoint for the iOS Simulator TUN smoke test.

The server intentionally terminates HTTP itself instead of contacting the
requested host.  Its JSON-lines log is therefore an assertion surface for the
important part of the test: singbox must restore a FakeIP destination to the
original domain and encode that domain in the SOCKS5 CONNECT request.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import socketserver
import struct
import threading
from datetime import datetime, timezone
from pathlib import Path


class ProbeLog:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    def write(self, event: dict[str, object]) -> None:
        event = {
            "time": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        line = json.dumps(event, ensure_ascii=False, sort_keys=True)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as output:
                output.write(line + "\n")
        print(line, flush=True)


class ProbeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], log: ProbeLog) -> None:
        self.probe_log = log
        super().__init__(address, ProbeHandler)


class ProbeHandler(socketserver.BaseRequestHandler):
    request: socket.socket
    server: ProbeServer

    def read_exact(self, size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = self.request.recv(remaining)
            if not chunk:
                raise ConnectionError("unexpected EOF")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def read_http_head(self) -> bytes:
        data = bytearray()
        while b"\r\n\r\n" not in data and len(data) < 64 * 1024:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def handle(self) -> None:
        try:
            version, method_count = self.read_exact(2)
            if version != 5:
                raise ValueError(f"unexpected SOCKS version {version}")
            methods = self.read_exact(method_count)
            if 0 not in methods:
                self.request.sendall(b"\x05\xff")
                return
            self.request.sendall(b"\x05\x00")

            version, command, _reserved, address_type = self.read_exact(4)
            if version != 5 or command != 1:
                raise ValueError(
                    f"expected SOCKS5 CONNECT, got version={version} command={command}"
                )
            if address_type == 1:
                target = str(ipaddress.ip_address(self.read_exact(4)))
                address_kind = "ipv4"
            elif address_type == 3:
                length = self.read_exact(1)[0]
                target = self.read_exact(length).decode("idna")
                address_kind = "domain"
            elif address_type == 4:
                target = str(ipaddress.ip_address(self.read_exact(16)))
                address_kind = "ipv6"
            else:
                raise ValueError(f"unsupported SOCKS address type {address_type}")
            port = struct.unpack("!H", self.read_exact(2))[0]

            self.server.probe_log.write(
                {
                    "event": "connect",
                    "address_kind": address_kind,
                    "target": target,
                    "port": port,
                    "client": self.client_address[0],
                }
            )
            self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")

            head = self.read_http_head()
            first_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            self.server.probe_log.write(
                {
                    "event": "http",
                    "target": target,
                    "port": port,
                    "request_line": first_line,
                }
            )
            body = json.dumps(
                {"ok": True, "target": target, "port": port},
                sort_keys=True,
            ).encode("utf-8")
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
                + body
            )
            self.request.sendall(response)
        except Exception as error:  # Keep the probe alive and make failures inspectable.
            self.server.probe_log.write(
                {
                    "event": "error",
                    "client": self.client_address[0],
                    "error": repr(error),
                }
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19080)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()

    log = ProbeLog(args.log)
    with ProbeServer((args.listen, args.port), log) as server:
        log.write(
            {
                "event": "ready",
                "listen": args.listen,
                "port": server.server_address[1],
            }
        )
        server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
