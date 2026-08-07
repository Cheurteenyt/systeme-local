from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any

import pytest
from starlette.requests import Request

from systeme_local_gateway.c9_control import (
    C9ControlAccessDenied,
    C9LocalControlGuard,
)

TOKEN = "c9-control-token-that-is-long-and-independent"


def _request(
    *,
    method: str = "GET",
    path: str = "/_local/c9/status",
    query: bytes = b"",
    client_host: str = "127.0.0.1",
    headers: Iterable[tuple[bytes, bytes]] = (),
    body: bytes = b"",
) -> Request:
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    standard = [
        (b"host", b"127.0.0.1:8765"),
        (b"authorization", f"Bearer {TOKEN}".encode("ascii")),
    ]
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "scheme": "http",
            "method": method,
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": query,
            "headers": standard + list(headers),
            "client": (client_host, 50000),
            "server": ("127.0.0.1", 8765),
        },
        receive,
    )


def test_control_guard_accepts_only_exact_loopback_token_and_host() -> None:
    guard = C9LocalControlGuard(token=TOKEN)

    admitted = guard.authorize(_request())

    assert admitted.method == "GET"
    assert admitted.path == "/_local/c9/status"
    assert TOKEN not in repr(admitted)


@pytest.mark.parametrize(
    "candidate",
    [
        _request(client_host="192.0.2.1"),
        _request(query=b"debug=true"),
        _request(headers=[(b"host", b"127.0.0.1:8765")]),
        _request(headers=[(b"authorization", f"Bearer {TOKEN}".encode("ascii"))]),
        _request(headers=[(b"origin", b"https://example.test")]),
        _request(headers=[(b"cookie", b"session=private")]),
        _request(headers=[(b"x-forwarded-for", b"127.0.0.1")]),
        _request(
            headers=[],
            client_host="127.0.0.1",
        ),
    ],
)
def test_control_guard_rejects_ambiguous_or_browser_proxy_requests(
    candidate: Request,
) -> None:
    guard = C9LocalControlGuard(token=TOKEN)
    if candidate.scope["headers"] == [
        (b"host", b"127.0.0.1:8765"),
        (b"authorization", f"Bearer {TOKEN}".encode("ascii")),
    ]:
        candidate.scope["headers"][1] = (b"authorization", b"Bearer wrong")

    with pytest.raises(C9ControlAccessDenied, match="request denied"):
        guard.authorize(candidate)


def test_control_guard_enforces_a_process_local_request_budget() -> None:
    now = 10.0
    guard = C9LocalControlGuard(
        token=TOKEN,
        requests_per_minute=2,
        monotonic_clock=lambda: now,
    )

    guard.authorize(_request())
    guard.authorize(_request())
    with pytest.raises(C9ControlAccessDenied):
        guard.authorize(_request())


def test_control_json_is_strict_bounded_and_zero_copy_not_retained() -> None:
    guard = C9LocalControlGuard(token=TOKEN, max_body_bytes=128)
    body = b'{"operator_confirmed":true,"label":"synthetic"}'
    request = _request(
        method="POST",
        headers=[
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ],
        body=body,
    )
    guard.authorize(request)

    parsed = asyncio.run(guard.read_json_object(request))

    assert parsed == {"operator_confirmed": True, "label": "synthetic"}


@pytest.mark.parametrize(
    ("body", "extra_headers"),
    [
        (
            b'{"a":1,"a":2}',
            [(b"content-type", b"application/json"), (b"content-length", b"13")],
        ),
        (
            b'["not-an-object"]',
            [(b"content-type", b"application/json"), (b"content-length", b"17")],
        ),
        (
            b'{"value":NaN}',
            [(b"content-type", b"application/json"), (b"content-length", b"13")],
        ),
        (
            b"{}",
            [(b"content-type", b"text/plain"), (b"content-length", b"2")],
        ),
        (
            b"{}",
            [
                (b"content-type", b"application/json"),
                (b"content-type", b"application/json"),
                (b"content-length", b"2"),
            ],
        ),
    ],
)
def test_control_json_rejects_ambiguous_or_invalid_payloads(
    body: bytes,
    extra_headers: list[tuple[bytes, bytes]],
) -> None:
    guard = C9LocalControlGuard(token=TOKEN)
    request = _request(method="POST", headers=extra_headers, body=body)
    guard.authorize(request)

    with pytest.raises(C9ControlAccessDenied):
        asyncio.run(guard.read_json_object(request))


def test_control_json_rejects_streamed_body_above_limit() -> None:
    guard = C9LocalControlGuard(token=TOKEN, max_body_bytes=32)
    body = b'{"value":"' + (b"x" * 64) + b'"}'
    request = _request(
        method="POST",
        headers=[
            (b"content-type", b"application/json"),
            (b"content-length", b"2"),
        ],
        body=body,
    )
    guard.authorize(request)

    with pytest.raises(C9ControlAccessDenied):
        asyncio.run(guard.read_json_object(request))
