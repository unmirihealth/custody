"""The egress allowlist proxy's server process. Stdlib only, no new
dependency: a minimal HTTP forward proxy that refuses to connect
anywhere not on its allowlist. Supports CONNECT (HTTPS tunneling,
the common case) and plain HTTP forwarding (GET/POST/HEAD).

ALLOWED_HOSTS env var: comma-separated hostnames, each either an exact
match or an fnmatch-style glob (e.g. "*.example.com"). Everything else
gets a 403, logged to stdout (container logs), never silently dropped.

This is the enforcement point for docs/threat-model.md T9: a
sandboxed container that gets `allow_egress=True` with a configured
allowlist is attached ONLY to an internal (no external route) Docker
network alongside this proxy; its one and only path anywhere, including
to a host actually on the allowlist, is through here.
"""

from __future__ import annotations

import fnmatch
import os
import socket
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_raw_allowlist = os.environ.get("ALLOWED_HOSTS", "").split(",")
ALLOWED_HOSTS = [h.strip().lower() for h in _raw_allowlist if h.strip()]


def host_allowed(host: str) -> bool:
    host = host.lower()
    return any(fnmatch.fnmatch(host, pattern) for pattern in ALLOWED_HOSTS)


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stdout.write(f"{self.address_string()} - {fmt % args}\n")
        sys.stdout.flush()

    def do_CONNECT(self) -> None:  # noqa: N802 - http.server's naming convention
        host, _, port_str = self.path.partition(":")
        port = int(port_str) if port_str else 443
        if not host_allowed(host):
            self.send_error(403, f"host not allowlisted: {host}")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            self.send_error(502, f"cannot reach {host}:{port}: {exc}")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        client_sock = self.connection
        t1 = threading.Thread(target=_pipe, args=(client_sock, upstream), daemon=True)
        t2 = threading.Thread(target=_pipe, args=(upstream, client_sock), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        upstream.close()

    def _forward(self, method: str) -> None:
        url = urllib.parse.urlsplit(self.path)
        host = url.hostname or self.headers.get("Host", "").split(":")[0]
        port = url.port or 80
        if not host or not host_allowed(host):
            self.send_error(403, f"host not allowlisted: {host}")
            return
        target_path = urllib.parse.urlunsplit(("", "", url.path or "/", url.query, ""))
        body_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(body_length) if body_length else b""
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            self.send_error(502, f"cannot reach {host}:{port}: {exc}")
            return
        with upstream:
            request_line = f"{method} {target_path} HTTP/1.1\r\n".encode()
            header_lines = b"".join(
                f"{k}: {v}\r\n".encode()
                for k, v in self.headers.items()
                if k.lower() not in ("proxy-connection",)
            )
            upstream.sendall(request_line + header_lines + b"\r\n" + body)
            response = b""
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                response += chunk
        self.wfile.write(response)

    def do_GET(self) -> None:  # noqa: N802
        self._forward("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._forward("POST")

    def do_HEAD(self) -> None:  # noqa: N802
        self._forward("HEAD")


if __name__ == "__main__":
    bind_port = int(os.environ.get("PROXY_PORT", "3128"))
    print(f"egress-proxy listening on :{bind_port}, allowlist={ALLOWED_HOSTS}")
    ThreadingHTTPServer(("0.0.0.0", bind_port), ProxyHandler).serve_forever()  # noqa: S104
