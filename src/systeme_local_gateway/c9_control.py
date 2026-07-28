from __future__ import annotations

import hmac
import json
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NoReturn

from fastapi import Request

_DEFAULT_ALLOWED_HOSTS = frozenset({"127.0.0.1:8765"})
_FORBIDDEN_HEADERS = frozenset(
    {
        b"cookie",
        b"forwarded",
        b"origin",
        b"referer",
        b"sec-fetch-dest",
        b"sec-fetch-mode",
        b"sec-fetch-site",
        b"sec-fetch-user",
        b"transfer-encoding",
        b"x-forwarded-for",
        b"x-forwarded-host",
        b"x-forwarded-port",
        b"x-forwarded-proto",
        b"x-real-ip",
    }
)


class C9ControlAccessDenied(ValueError):
    """Generic denial for the private process-local C9 control plane."""


def _deny() -> NoReturn:
    raise C9ControlAccessDenied("C9 local control request denied")


def _header_values(request: Request, name: bytes) -> tuple[bytes, ...]:
    return tuple(
        value for key, value in request.scope.get("headers", ()) if bytes(key).lower() == name
    )


def _decode_ascii(value: bytes) -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        _deny()


@dataclass(frozen=True)
class C9ControlRequest:
    """Authenticated request metadata; intentionally excludes headers and secrets."""

    method: str
    path: str


class C9LocalControlGuard:
    """Fail-closed guard for endpoints that must never be reachable through MCP.

    The facade is bound to IPv4 loopback by the operator scripts. This guard adds
    independent request-level constraints: literal loopback peer, one exact Host,
    no browser/proxy state, one independent bearer token, no query string, bounded
    strict JSON, and a small process-local request budget.
    """

    def __init__(
        self,
        *,
        token: str,
        allowed_hosts: frozenset[str] = _DEFAULT_ALLOWED_HOSTS,
        max_body_bytes: int = 16 * 1024,
        requests_per_minute: int = 60,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if len(token.encode("utf-8")) < 32:
            raise ValueError("C9 control token must contain at least 32 UTF-8 bytes")
        if not allowed_hosts or any(
            host != host.lower() or not host.isascii() for host in allowed_hosts
        ):
            raise ValueError("C9 control hosts must be non-empty lowercase ASCII literals")
        if max_body_bytes < 2 or max_body_bytes > 1024 * 1024:
            raise ValueError("C9 control body limit is outside the safe range")
        if requests_per_minute < 1 or requests_per_minute > 600:
            raise ValueError("C9 control request budget is outside the safe range")
        self._token = token.encode("utf-8")
        self._allowed_hosts = allowed_hosts
        self._max_body_bytes = max_body_bytes
        self._requests_per_minute = requests_per_minute
        self._clock = monotonic_clock
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def authorize(self, request: Request) -> C9ControlRequest:
        if request.method not in {"GET", "POST"}:
            _deny()
        if request.url.query or request.scope.get("query_string", b""):
            _deny()
        client = request.client
        if client is None or client.host not in {"127.0.0.1", "::1"}:
            _deny()

        headers = tuple(
            (bytes(key).lower(), bytes(value)) for key, value in request.scope.get("headers", ())
        )
        if any(key in _FORBIDDEN_HEADERS for key, _ in headers):
            _deny()

        host_values = _header_values(request, b"host")
        authorization_values = _header_values(request, b"authorization")
        if len(host_values) != 1 or len(authorization_values) != 1:
            _deny()
        host = _decode_ascii(host_values[0]).lower()
        if host not in self._allowed_hosts:
            _deny()

        supplied = authorization_values[0]
        prefix = b"Bearer "
        if not supplied.startswith(prefix):
            _deny()
        candidate = supplied[len(prefix) :]
        if not candidate or not hmac.compare_digest(candidate, self._token):
            _deny()

        now = self._clock()
        cutoff = now - 60.0
        with self._lock:
            while self._events and self._events[0] <= cutoff:
                self._events.popleft()
            if len(self._events) >= self._requests_per_minute:
                _deny()
            self._events.append(now)
        return C9ControlRequest(method=request.method, path=request.url.path)

    async def read_json_object(self, request: Request) -> dict[str, Any]:
        if request.method != "POST":
            _deny()
        content_types = _header_values(request, b"content-type")
        content_lengths = _header_values(request, b"content-length")
        if len(content_types) != 1:
            _deny()
        if _decode_ascii(content_types[0]).lower() != "application/json":
            _deny()
        if len(content_lengths) != 1:
            _deny()
        raw_length = _decode_ascii(content_lengths[0])
        if not raw_length.isdecimal():
            _deny()
        declared_length = int(raw_length)
        if declared_length < 2 or declared_length > self._max_body_bytes:
            _deny()

        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > self._max_body_bytes:
                for index in range(len(body)):
                    body[index] = 0
                _deny()
        try:
            if not body:
                _deny()
            if len(body) != declared_length:
                _deny()
            decoded = bytes(body).decode("utf-8", errors="strict")
            value = json.loads(
                decoded,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_non_finite_json,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            _deny()
        finally:
            for index in range(len(body)):
                body[index] = 0
        if not isinstance(value, dict):
            _deny()
        return value


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


def _reject_non_finite_json(_value: str) -> NoReturn:
    raise ValueError("non-finite JSON value")
