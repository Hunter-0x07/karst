"""Loopback-only integration target, not a vulnerability evaluation application."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import threading
import time


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        token = self.headers.get("Authorization")
        subject = {"Bearer demo-alice": "alice", "Bearer demo-bob": "bob"}.get(token, "anonymous")
        self.server.seen.append((self.path, subject))
        if self.path == "/drop":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        headers = {}
        status = 200
        body = json.dumps({"subject": subject, "next": "/whoami"}).encode()
        if self.path == "/v1/models":
            body = b'{"data":[{"id":"qwen3.8-27b"}]}'
        if self.path in ("/redirect", "/outside"):
            status = 302
            headers["Location"] = "/whoami" if self.path == "/redirect" else self.server.outside
            body = b""
        if self.path == "/error":
            status = 500
            body = b'{"error":"test failure"}'
        if self.path == "/large":
            body = b"x" * 10000
        if self.path == "/partial":
            body = b"abc"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(100 if self.path == "/partial" else len(body)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if self.path == "/slow":
            time.sleep(1.5)
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except OSError:
            pass
        self.close_connection = True


@contextmanager
def server():
    instance = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    instance.daemon_threads = True
    instance.seen = []
    instance.outside = "http://127.0.0.1:1/"
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance, f"http://127.0.0.1:{instance.server_port}"
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def config(origin, path="/", *, identities=False):
    return {"profile": "karst-http-probe/1", "entrypoints": [origin + path],
            "origins": [{"origin": origin, "path_prefixes": ["/"]}],
            "allowed_cidrs": ["127.0.0.1/32"], "denied_cidrs": [],
            "identities": [{"name": name, "origin": origin, "bearer_env": "KARST_TEST_" + name.upper()}
                           for name in ("alice", "bob")] if identities else [],
            "limits": {"max_requests": 10, "max_response_bytes": 65536,
                       "max_total_response_bytes": 262144, "timeout_seconds": 3,
                       "wall_seconds": 20, "max_redirects": 2}}


def write_config(root, data):
    path = Path(root) / "probe.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path
