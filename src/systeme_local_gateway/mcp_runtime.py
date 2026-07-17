from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import secrets
import threading
import time
from collections import deque
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import uuid4

import anyio
import mcp.types as types
from fastapi import Request, Response
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.types import Message

from .auth import compute_task_signature
from .models import AgentIdentity, TaskEnvelope, TaskResult
from .task_processor import TaskProcessingError

logger = logging.getLogger(__name__)


class McpToolDefinitionProtocol(Protocol):
    name: str
    description: str

    @property
    def input_schema(self) -> dict[str, Any]: ...


class McpToolRegistryProtocol(Protocol):
    def list_tools(self) -> tuple[McpToolDefinitionProtocol, ...]: ...


class TaskProcessorProtocol(Protocol):
    def process(self, task: TaskEnvelope) -> TaskResult: ...


class McpTaskAdapter:
    """Create signed local task envelopes and map their results to MCP."""

    def __init__(
        self,
        *,
        shared_secret: str,
        task_processor: TaskProcessorProtocol,
        max_concurrency: int,
        clock: Callable[[], datetime] | None = None,
    ):
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        self._shared_secret = shared_secret
        self._task_processor = task_processor
        self._limiter = anyio.CapacityLimiter(max_concurrency)
        self._clock = clock or (lambda: datetime.now(UTC))

    def _build_task(self, name: str, arguments: dict[str, Any]) -> TaskEnvelope:
        now = self._clock()
        unsigned = TaskEnvelope(
            task_id=f"mcp_{uuid4().hex}",
            issued_at=now,
            expires_at=now + timedelta(seconds=60),
            agent=AgentIdentity(
                provider="mcp",
                model=None,
                session_id="streamable-http",
            ),
            capability=name,
            arguments=dict(arguments),
            nonce=secrets.token_urlsafe(24),
            signature="A" * 43,
        )
        return unsigned.model_copy(
            update={
                "signature": compute_task_signature(
                    unsigned,
                    self._shared_secret,
                )
            }
        )

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> types.CallToolResult:
        try:
            task = self._build_task(name, arguments)
        except Exception:
            return _tool_error("Invalid tool request")

        try:
            result = await anyio.to_thread.run_sync(
                self._task_processor.process,
                task,
                limiter=self._limiter,
            )
        except TaskProcessingError as exc:
            return _tool_error(
                exc.detail,
                metadata={
                    "systeme-local/audit-id": exc.audit_id,
                    "systeme-local/task-id": task.task_id,
                },
            )
        except Exception as exc:
            logger.error(
                "MCP task processing failed with %s",
                type(exc).__name__,
            )
            return _tool_error("Tool service unavailable")

        metadata = {
            "systeme-local/audit-id": result.audit_id,
            "systeme-local/task-id": result.task_id,
        }
        if result.status == "completed":
            output = result.model_dump(mode="json")["output"]
            text = json.dumps(
                output,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=text)],
                structuredContent=output,
                isError=False,
                _meta=metadata,
            )

        messages = {
            "denied": "Tool execution denied",
            "approval_required": "Tool requires local approval",
            "failed": "Tool execution failed",
        }
        return _tool_error(
            messages[result.status],
            metadata=metadata,
        )


class SlidingWindowRateLimiter:
    """Process-local fixed-capacity sliding window limiter."""

    def __init__(
        self,
        limit: int,
        *,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        if limit < 1:
            raise ValueError("rate limit must be positive")
        if window_seconds <= 0:
            raise ValueError("rate limit window must be positive")
        self._limit = limit
        self._window_seconds = window_seconds
        self._clock = clock
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        now = self._clock()
        cutoff = now - self._window_seconds
        with self._lock:
            while self._events and self._events[0] <= cutoff:
                self._events.popleft()
            if len(self._events) >= self._limit:
                return False
            self._events.append(now)
            return True


class McpRuntime:
    """Authenticated, loopback-only MCP Streamable HTTP runtime."""

    def __init__(
        self,
        *,
        token: str,
        shared_secret: str,
        registry: McpToolRegistryProtocol,
        task_processor: TaskProcessorProtocol,
        max_request_bytes: int,
        requests_per_minute: int,
        max_concurrency: int,
    ):
        if len(token.encode("utf-8")) < 32:
            raise ValueError("MCP token must contain at least 32 UTF-8 bytes")
        if max_request_bytes < 1:
            raise ValueError("max_request_bytes must be positive")

        self._token = token
        self._max_request_bytes = max_request_bytes
        self._rate_limiter = SlidingWindowRateLimiter(requests_per_minute)
        adapter = McpTaskAdapter(
            shared_secret=shared_secret,
            task_processor=task_processor,
            max_concurrency=max_concurrency,
        )

        server = Server(
            "systeme-local",
            version="0.1.0",
            instructions=(
                "Policy-governed local tools. Sensitive capabilities requiring "
                "approval are not exposed through this endpoint."
            ),
        )

        @server.list_tools()
        async def list_tools() -> list[types.Tool]:
            return [
                types.Tool(
                    name=tool.name,
                    description=tool.description,
                    inputSchema=tool.input_schema,
                )
                for tool in registry.list_tools()
            ]

        @server.call_tool()
        async def call_tool(
            name: str,
            arguments: dict[str, Any],
        ) -> types.CallToolResult:
            return await adapter.call_tool(name, arguments)

        transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[
                "127.0.0.1",
                "127.0.0.1:*",
                "localhost",
                "localhost:*",
                "[::1]",
                "[::1]:*",
            ],
            allowed_origins=[
                "http://127.0.0.1",
                "http://127.0.0.1:*",
                "http://localhost",
                "http://localhost:*",
                "http://[::1]",
                "http://[::1]:*",
            ],
        )
        self._session_manager = StreamableHTTPSessionManager(
            app=server,
            json_response=True,
            stateless=True,
            security_settings=transport_security,
        )

    @asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        async with self._session_manager.run():
            yield

    async def handle_http_request(self, request: Request) -> Response:
        if not _is_loopback_client(request):
            return _plain_response(403, "Forbidden")

        header_error = _validate_singleton_headers(request)
        if header_error is not None:
            return header_error

        if not _is_authorized(request, self._token):
            return _plain_response(
                401,
                "Unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not self._rate_limiter.allow():
            return _plain_response(
                429,
                "Too Many Requests",
                headers={"Retry-After": "60"},
            )

        content_length_error = _validate_content_length(
            request,
            self._max_request_bytes,
        )
        if content_length_error is not None:
            return content_length_error

        try:
            body = await _read_bounded_body(
                request,
                self._max_request_bytes,
            )
        except _RequestBodyTooLargeError:
            return _plain_response(413, "Request Entity Too Large")
        except Exception:
            return _plain_response(400, "Invalid request body")

        return await self._dispatch_to_session_manager(request, body)

    async def _dispatch_to_session_manager(
        self,
        request: Request,
        body: bytes,
    ) -> Response:
        body_sent = False
        response_start: Message | None = None
        response_chunks: list[bytes] = []

        async def receive() -> Message:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }
            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        async def send(message: Message) -> None:
            nonlocal response_start
            if message["type"] == "http.response.start":
                if response_start is not None:
                    raise RuntimeError("MCP transport sent multiple response starts")
                response_start = message
            elif message["type"] == "http.response.body":
                response_chunks.append(message.get("body", b""))

        try:
            await self._session_manager.handle_request(
                request.scope,
                receive,
                send,
            )
        except Exception as exc:
            logger.error(
                "MCP Streamable HTTP transport failed with %s",
                type(exc).__name__,
            )
            return _plain_response(500, "MCP transport failed")

        if response_start is None:
            logger.error("MCP transport returned no HTTP response")
            return _plain_response(500, "MCP transport failed")

        response = Response(
            content=b"".join(response_chunks),
            status_code=int(response_start["status"]),
        )
        response.raw_headers = list(response_start.get("headers", []))
        return response



class _RequestBodyTooLargeError(RuntimeError):
    pass


async def _read_bounded_body(
    request: Request,
    max_request_bytes: int,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_request_bytes:
            raise _RequestBodyTooLargeError
        chunks.append(chunk)
    return b"".join(chunks)

def _tool_error(
    message: str,
    *,
    metadata: dict[str, str] | None = None,
) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        isError=True,
        _meta=metadata,
    )


def _header_values(request: Request, name: bytes) -> list[str]:
    return [
        value.decode("latin-1")
        for key, value in request.scope.get("headers", [])
        if key.lower() == name
    ]


def _validate_singleton_headers(request: Request) -> Response | None:
    if len(_header_values(request, b"host")) != 1:
        return _plain_response(400, "Invalid Host header")
    if len(_header_values(request, b"origin")) > 1:
        return _plain_response(400, "Invalid Origin header")
    if len(_header_values(request, b"authorization")) != 1:
        return _plain_response(
            401,
            "Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if len(_header_values(request, b"content-length")) > 1:
        return _plain_response(400, "Invalid Content-Length")
    return None


def _is_loopback_client(request: Request) -> bool:
    if request.client is None:
        return False
    try:
        return ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        return False


def _is_authorized(request: Request, expected_token: str) -> bool:
    authorization = _header_values(request, b"authorization")[0]
    scheme, separator, credential = authorization.partition(" ")
    if separator != " " or scheme.casefold() != "bearer":
        return False
    if not credential or credential.strip() != credential:
        return False
    if any(character.isspace() for character in credential):
        return False
    return hmac.compare_digest(
        credential.encode("utf-8"),
        expected_token.encode("utf-8"),
    )


def _validate_content_length(
    request: Request,
    max_request_bytes: int,
) -> Response | None:
    values = _header_values(request, b"content-length")
    if not values:
        return None
    try:
        length = int(values[0], 10)
    except ValueError:
        return _plain_response(400, "Invalid Content-Length")
    if length < 0:
        return _plain_response(400, "Invalid Content-Length")
    if length > max_request_bytes:
        return _plain_response(413, "Request Entity Too Large")
    return None


def _plain_response(
    status_code: int,
    message: str,
    *,
    headers: dict[str, str] | None = None,
) -> Response:
    return Response(
        content=message,
        status_code=status_code,
        media_type="text/plain",
        headers=headers,
    )
