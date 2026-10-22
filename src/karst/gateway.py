"""Bounded, non-streaming chat-completions adapter using the Tester message protocol.

No proxy inheritance, automatic redirects, hidden retries or persisted reasoning content.
"""

from copy import deepcopy
import hashlib
import http.client
import os
from pathlib import Path
import re
import threading
import time
from urllib.parse import urlsplit

from karst.config import KarstError, exact, parse_url, positive, strict_json
from karst.errors import GatewayError, ProtocolError
from karst.execution import PinnedConnection, abort, resolve
from karst.protocol import ModelRequest, parse_reply, response_usage, validate_request
from karst.store import encoded, new_id


def default_gateway_path(*, research=False):
    return "config/examples/research-gateway.json" if research else "config/examples/gateway.json"


def load_gateway(path):
    c = strict_json(Path(path).read_text(encoding="utf-8"))
    c = {"min_request_interval_seconds": 0, **c} if isinstance(c, dict) else c
    exact(c, ["api_base", "model", "max_tokens", "max_tokens_field", "timeout_seconds", "connect_timeout_seconds",
              "max_retries", "retry_backoff_seconds", "max_response_bytes", "temperature", "trust_env", "min_request_interval_seconds"])
    if type(c["min_request_interval_seconds"]) is not int or not 0 <= c["min_request_interval_seconds"] <= 60:
        raise KarstError("invalid gateway request interval")
    parsed = parse_url(c["api_base"].rstrip("/")+"/chat/completions")
    if urlsplit(parsed[0]).query or c["trust_env"] is not False or not isinstance(c["model"], str) or not c["model"].strip():
        raise KarstError("invalid explicit gateway endpoint/model")
    for key, maximum in {"max_tokens": 65536, "timeout_seconds": 900, "connect_timeout_seconds": 60,
                         "max_response_bytes": 2000000, "retry_backoff_seconds": 10}.items():
        positive(c[key], maximum)
    if type(c["max_retries"]) is not int or not 0 <= c["max_retries"] <= 2:
        raise KarstError("invalid gateway retry limit")
    if c["max_tokens_field"] not in ("max_tokens", "max_completion_tokens") or c["temperature"] not in (None, 0, 1):
        raise KarstError("unsupported gateway token/temperature setting")
    return c


def safe_messages(messages):
    return [{k: deepcopy(v) for k, v in message.items() if k != "reasoning_content"} for message in messages]


class Gateway:
    # One serial Runtime, including its subsequent Tasks/Runs, shares a quiet
    # interval for the same endpoint/model. No extra provider calls are made.
    _last_response_at = {}

    def __init__(self, config, store, run_id, budget, deadline, *, check=lambda: None):
        self.config, self.store, self.run_id = config, store, run_id
        self.budget, self.deadline, self.check = budget, deadline, check
        self.key = os.environ.get("TESTER_API_KEY")
        if self.key and not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,8192}", self.key):
            raise KarstError("invalid TESTER_API_KEY")
        self.last_request_id = None

    def _pace(self):
        interval = self.config.get("min_request_interval_seconds", 0)
        key = (self.config["api_base"], self.config["model"])
        while interval:
            self.check()
            now = time.monotonic()
            if now >= self.deadline:
                raise KarstError("budget_exhausted")
            last = self._last_response_at.get(key)
            if last is None:
                break
            delay = last+interval-now
            if delay <= 0:
                break
            time.sleep(min(delay, self.deadline-now, 0.1))

    def generate(self, messages, tools=None, *, tool_choice=None):
        request = ModelRequest(messages, tools, tool_choice)
        validate_request(request)
        c = self.config
        payload = {"model": c["model"], "messages": messages, "stream": False, c["max_tokens_field"]: c["max_tokens"]}
        if tools:
            payload["tools"] = tools
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice
        if c["temperature"] is not None:
            payload["temperature"] = c["temperature"]
        for attempt in range(c["max_retries"]+1):
            self.check()
            self._pace()
            self.check()
            remaining = self.deadline-time.monotonic()
            if remaining <= 0:
                raise KarstError("budget_exhausted")
            # The configured ceiling is not a minimum allocation. Use the
            # remaining task/Run allowance, also after a charged retry.
            output_left = self.budget["output_tokens"]-self.store.usage(self.run_id)["charged_or_reserved"].get("output_tokens", 0)
            if output_left <= 0:
                raise KarstError("budget_exhausted")
            output_limit = min(c["max_tokens"], output_left)
            payload[c["max_tokens_field"]] = output_limit
            raw = encoded(payload)
            if len(raw) > 524288:
                raise KarstError("model_context_limit")
            allowance = {"model_requests": 1, "input_tokens": len(raw)*2+4096, "output_tokens": output_limit}
            key = new_id("model")
            self.last_request_id = key
            self.store.reserve(self.run_id, key, allowance, self.budget)
            begin = time.monotonic()
            # Private journal contains replayable messages/tool results but no provider
            # reasoning fields or authentication headers. Feedback exports only summaries.
            self.store.audit(self.run_id, "model_start", {"request_id": key, "logical_request_id": request.request_id,
                "attempt": attempt+1, "model": c["model"], "config_digest": hashlib.sha256(encoded(c)).hexdigest(),
                "payload_sha256": hashlib.sha256(raw).hexdigest(),
                "messages": safe_messages(messages), "tools": tools, "tool_choice": tool_choice,
                "output_token_limit": output_limit})
            status = None
            usage = None
            settled = False
            try:
                try:
                    response, status = self._send(raw, min(remaining, c["timeout_seconds"]))
                finally:
                    if c.get("min_request_interval_seconds", 0):
                        self._last_response_at[(c["api_base"], c["model"])] = time.monotonic()
                # Account for valid provider usage before parsing tool arguments.
                # A truncated/invalid response still consumed a paid request.
                usage = response_usage(response)
                actual = None
                if usage and all(type(usage.get(k)) is int for k in ("prompt_tokens", "completion_tokens")):
                    actual = {"model_requests": 1, "input_tokens": usage["prompt_tokens"], "output_tokens": usage["completion_tokens"]}
                self.store.settle(self.run_id, key, actual)
                settled = True
                reply = parse_reply(response, request_id=key, model=c["model"], attempts=attempt+1,
                                    elapsed_seconds=round(time.monotonic()-begin, 6))
                if reply.is_truncated:
                    raise ProtocolError("TOKEN_LIMIT", "truncated model response is not executable")
                self.store.audit(self.run_id, "model_end", {"request_id": key, "status": "succeeded", "http_status": status,
                    "elapsed_seconds": reply.elapsed_seconds, "usage": usage, "provider_response_id": reply.provider_response_id,
                    "message": safe_messages([reply.to_assistant_message()])[0]})
                return reply
            except KeyboardInterrupt:
                if not settled:
                    self.store.settle(self.run_id, key)
                self.store.audit(self.run_id, "model_end", {"request_id": key, "status": "cancelled", "usage": None})
                raise
            except (GatewayError, OSError, http.client.HTTPException, KarstError) as exc:
                if not settled:
                    self.store.settle(self.run_id, key)
                error = exc if isinstance(exc, GatewayError) else GatewayError("provider", type(exc).__name__, "bounded gateway request failed")
                self.store.audit(self.run_id, "model_end", {"request_id": key, "status": "failed", "code": error.code,
                    "http_status": error.http_status, "elapsed_seconds": round(time.monotonic()-begin, 6), "usage": usage})
                if not error.retryable or attempt >= c["max_retries"]:
                    raise error from None
                delay = c["retry_backoff_seconds"]*(2**attempt)
                if time.monotonic()+delay >= self.deadline:
                    raise KarstError("budget_exhausted")
                time.sleep(delay)
        raise AssertionError("unreachable")

    def _send(self, raw, timeout):
        endpoint, _, host, port, _ = parse_url(self.config["api_base"].rstrip("/")+"/chat/completions")
        deadline = time.monotonic()+timeout
        addresses = resolve(host, port, min(timeout, self.config["connect_timeout_seconds"]))
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError("gateway DNS deadline")
        conn = PinnedConnection(host, port, addresses[0], min(remaining, self.config["connect_timeout_seconds"]), endpoint.startswith("https:"))
        timer = threading.Timer(remaining, abort, (conn,))
        timer.daemon = True
        response = None
        try:
            timer.start()
            conn.connect()
            conn.sock.settimeout(max(0.01, deadline-time.monotonic()))
            headers = {"Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close"}
            if self.key:
                headers["Authorization"] = "Bearer "+self.key
            conn.request("POST", urlsplit(endpoint).path, raw, headers)
            response = conn.getresponse()
            if response.status != 200:
                raise GatewayError("provider", "HTTP_ERROR", "gateway rejected request", http_status=response.status,
                                   retryable=response.status in (429, 500, 502, 503, 504))
            if "text/event-stream" in response.getheader("Content-Type", "") or response.getheader("Content-Encoding", "identity") != "identity":
                raise ProtocolError("UNSUPPORTED_ENCODING", "gateway must return uncompressed non-stream JSON")
            body = bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("gateway deadline")
                chunk = response.read1(min(65536, self.config["max_response_bytes"]+1-len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > self.config["max_response_bytes"]:
                    raise ProtocolError("RESPONSE_TOO_LARGE", "gateway response exceeds configured limit")
            # strict_json has a separate 256KiB parser cap, intentionally narrower.
            if response.length not in (None, 0):
                raise ProtocolError("TRUNCATED_BODY", "gateway response framing is incomplete")
            try:
                return strict_json(body.decode("utf-8")), response.status
            except (KarstError, UnicodeError) as exc:
                raise ProtocolError("INVALID_JSON", "gateway response is not bounded strict JSON") from exc
        finally:
            if response is not None:
                response.close()
            timer.cancel()
            abort(conn)
