"""Real HTTP probe with per-hop scope, pinned DNS and separate identity contexts."""

import base64
import hashlib
import http.client
import ipaddress
import queue
import socket
import ssl
import threading
import time
from urllib.parse import urljoin, urlsplit

from karst.config import KarstError
from karst.store import encoded, new_id, utcnow


def resolve(host, port, timeout):
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    replies = queue.Queue(maxsize=1)
    def lookup():
        try:
            replies.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError:
            replies.put(None)
    # OS DNS calls cannot be cancelled portably. A timed-out lookup never connects.
    threading.Thread(target=lookup, daemon=True).start()
    try:
        result = replies.get(timeout=timeout)
    except queue.Empty as exc:
        raise KarstError("dns_timeout") from exc
    if not result:
        raise KarstError("dns_failed")
    return sorted({entry[4][0] for entry in result})


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self, host, port, address, timeout, tls):
        super().__init__(host, port, timeout=timeout)
        self.address = address
        self.tls = tls
        self.expires = time.monotonic() + timeout
        self.cancelled = False
        self.transport_sock = None

    def connect(self):
        if self.cancelled or time.monotonic() >= self.expires:
            raise TimeoutError("request deadline reached")
        family = socket.AF_INET6 if ":" in self.address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock = sock
        self.transport_sock = sock
        sock.settimeout(self.timeout)
        sock.connect((self.address, self.port))
        if self.tls:
            # Use the original host for SNI and certificate verification, not the pinned IP.
            self.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host, do_handshake_on_connect=False)
            self.transport_sock = self.sock
            if self.cancelled:
                raise TimeoutError("request cancelled")
            self.sock.do_handshake()


def abort(connection):
    connection.cancelled = True
    sock = connection.transport_sock
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    connection.close()


class HttpExecutor:
    def __init__(self, config, store, run_id, secrets):
        self.config = config
        self.store = store
        self.run_id = run_id
        self.secrets = secrets
        self.requests = 0
        self.response_bytes = 0
        self.deadline = time.monotonic() + config.limits.wall_seconds

    def request(self, url, identity=None):
        original_origin = self.config.check_url(url)[1]
        final = None
        seen = set()
        for hop in range(self.config.limits.max_redirects + 1):
            if url in seen:
                return self._denied(url, identity, "redirect_loop")
            seen.add(url)
            final, location = self._hop(url, identity, original_origin)
            if not location:
                return final
            if hop == self.config.limits.max_redirects:
                return self._denied(url, identity, "redirect_limit")
            url = urljoin(url, location)
        return final

    def _new(self, url, identity, state, error=None):
        data = {"tool_name": "http.probe", "tool_version": "1", "execution_state": state,
                "identity": identity.name if identity else "anonymous", "session_generation": 1,
                "identity_status": "provided_unverified" if identity else "anonymous",
                "arguments_digest": hashlib.sha256(encoded({"url": url, "method": "GET"})).hexdigest(),
                "started_at": utcnow(), "ended_at": utcnow() if error else None,
                "error": error, "evidence_refs": [], "http_status": None,
                "response_bytes": 0, "connected_ip": None}
        return self.store.put("operation", new_id("operation"), self.run_id, data)

    def _denied(self, url, identity, reason):
        return self._new(url, identity, "not_executed", {"code": reason, "retry_policy": "never"})

    def _hop(self, url, identity, original_origin):
        limits = self.config.limits
        try:
            canonical, origin, host, port, _ = self.config.check_url(url)
            if identity and (origin != identity.origin or origin != original_origin):
                raise KarstError("identity_origin_mismatch")
            if self.requests >= limits.max_requests or self.response_bytes >= limits.max_total_response_bytes:
                raise KarstError("budget_exhausted")
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise KarstError("budget_exhausted")
            addresses = resolve(host, port, min(remaining, limits.timeout_seconds))
            if not all(self.config.allows_ip(addr) for addr in addresses):
                raise KarstError("network_scope_denied")
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise KarstError("budget_exhausted")
        except KarstError as exc:
            return self._denied(url, identity, str(exc)), None

        op = self._new(canonical, identity, "running")
        data = dict(op["data"])
        self.requests += 1  # Count every admitted hop, including connection failures.
        timeout = min(remaining, limits.timeout_seconds)
        conn = PinnedConnection(host, port, addresses[0], timeout, canonical.startswith("https:"))
        timer = threading.Timer(timeout, abort, (conn,))
        timer.daemon = True
        transmitted = False
        response_received = False
        body = bytearray()
        response_headers = []
        partial = False
        expected_length = None
        location = None
        request_headers = {"User-Agent": "Karst-Core/0.0.1", "Accept-Encoding": "identity", "Connection": "close"}
        if identity:
            request_headers["Authorization"] = "Bearer " + self.secrets[identity.name]
        try:
            timer.start()
            conn.connect()
            data["connected_ip"] = conn.sock.getpeername()[0]
            p = urlsplit(canonical)
            target = p.path + ("?" + p.query if p.query else "")
            transmitted = True
            conn.request("GET", target, headers=request_headers)
            response = conn.getresponse()
            response_received = True
            data["http_status"] = response.status
            response_headers = response.getheaders()
            expected_length = response.length
            cap = min(limits.max_response_bytes, limits.max_total_response_bytes - self.response_bytes)
            while len(body) < cap:
                if time.monotonic() >= conn.expires:
                    raise TimeoutError("response deadline reached")
                chunk = response.read1(min(65536, cap - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            # If framing did not establish EOF, hitting the cap is conservatively partial.
            partial = ((expected_length is not None and len(body) < expected_length)
                       or (not response.isclosed() and response.length != 0))
            if response.status in (301, 302, 303, 307, 308):
                locations = response.headers.get_all("Location", [])
                if len(locations) == 1:
                    location = locations[0]
                elif len(locations) > 1:
                    data["error"] = {"code": "ambiguous_redirect", "retry_policy": "never"}
            data["execution_state"] = "succeeded"
        except KeyboardInterrupt:
            data["execution_state"] = "unknown" if transmitted else "failed"
            data["error"] = {"code": "interrupted", "retry_policy": "inspect_first" if transmitted else "never"}
            partial = True
            raise
        except (OSError, http.client.HTTPException, ValueError) as exc:
            data["execution_state"] = "unknown" if transmitted else "failed"
            data["error"] = {"code": "transport_" + type(exc).__name__, "retry_policy": "inspect_first" if transmitted else "never"}
            partial = True
            location = None
        finally:
            timer.cancel()
            abort(conn)
            self.response_bytes += len(body)
            data["response_bytes"] = len(body)
            data["ended_at"] = utcnow()
            if response_received:
                exchange = {"request": {"method": "GET", "url": canonical,
                                        "headers": {k: ("[REDACTED]" if k == "Authorization" else v) for k, v in request_headers.items()},
                                        "identity": data["identity"]},
                            "response": {"status": data["http_status"], "headers": response_headers,
                                         "body_base64": base64.b64encode(body).decode("ascii")},
                            "connected_ip": data["connected_ip"], "partial": partial,
                            "incomplete_reason": "capture_limit_or_transport_interruption" if partial else None}
                try:
                    evidence = self.store.save_evidence(self.run_id, op, exchange, partial=partial)
                    data["evidence_refs"] = [{"kind": "evidence", "id": evidence["id"], "version": evidence["version"]}]
                except (KarstError, OSError):
                    # Preserve execution fact; evidence failure must never trigger re-execution.
                    data["error"] = {"code": "evidence_save_failed", "retry_policy": "inspect_first"}
                    location = None
            op = self.store.put("operation", op["id"], self.run_id, data, expected_version=op["version"])
        return op, location
