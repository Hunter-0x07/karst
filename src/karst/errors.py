# Adapted from this repository, docs/mvp-v0.2@789b197296b677dffdda565462799390aa9f7e2a.
"""Small, safe errors shared by the M01 adapter and its command-line probes."""

from __future__ import annotations

from typing import Any


class GatewayError(Exception):
    """A diagnostic that never includes raw headers, request or provider bodies."""

    def __init__(
        self,
        category: str,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        request_id: str | None = None,
        http_status: int | None = None,
        attempts: int = 0,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.code = code
        self.retryable = retryable
        self.request_id = request_id
        self.http_status = http_status
        self.attempts = attempts

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "code": self.code,
            "message": str(self),
            "retryable": self.retryable,
            "request_id": self.request_id,
            "http_status": self.http_status,
            "attempts": self.attempts,
        }


class ConfigError(GatewayError):
    def __init__(self, message: str) -> None:
        super().__init__("config", "INVALID_CONFIG", message)


class RequestError(GatewayError):
    def __init__(self, message: str) -> None:
        super().__init__("validation", "INVALID_REQUEST", message)


class ProtocolError(GatewayError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__("protocol", code, message)
