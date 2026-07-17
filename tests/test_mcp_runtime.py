from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from systeme_local_gateway.auth import compute_task_signature
from systeme_local_gateway.mcp_runtime import McpRuntime
from systeme_local_gateway.mcp_tools import McpToolRegistry
from systeme_local_gateway.models import TaskResult
from systeme_local_gateway.policy import PolicyEngine


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class RecordingProcessor:
    def __init__(self, shared_secret: str):
        self.shared_secret = shared_secret
        self.tasks = []

    def process(self, task):
        self.tasks.append(task)
        assert task.signature == compute_task_signature(
            task,
            self.shared_secret,
        )
        if task.capability != "workspace.list":
            return TaskResult(
                task_id=task.task_id,
                status="denied",
                error="capability not declared",
                audit_id=f"audit-{len(self.tasks)}",
            )
        return TaskResult(
            task_id=task.task_id,
            status="completed",
            output={"path": ".", "entries": []},
            audit_id=f"audit-{len(self.tasks)}",
        )


def _build_runtime(
    tmp_path: Path,
    *,
    requests_per_minute: int = 120,
    max_request_bytes: int = 1_048_576,
):
    tmp_path.mkdir(parents=True, exist_ok=True)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """version: 1
default: deny
capabilities:
  workspace.list:
    decision: allow
""",
        encoding="utf-8",
    )
    shared_secret = "s" * 48
    processor = RecordingProcessor(shared_secret)
    runtime = McpRuntime(
        token="t" * 48,
        shared_secret=shared_secret,
        registry=McpToolRegistry(PolicyEngine(policy_path)),
        task_processor=processor,
        max_request_bytes=max_request_bytes,
        requests_per_minute=requests_per_minute,
        max_concurrency=2,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        async with runtime.run():
            yield

    app = FastAPI(lifespan=lifespan)

    @app.api_route("/mcp", methods=["GET", "POST", "DELETE"])
    async def endpoint(request: Request):
        return await runtime.handle_http_request(request)

    return app, processor


@pytest.mark.anyio
async def test_official_client_initialize_list_and_call(
    tmp_path: Path,
) -> None:
    app, processor = _build_runtime(tmp_path)
    transport = httpx.ASGITransport(
        app=app,
        client=("127.0.0.1", 50_000),
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1",
            headers={"Authorization": f"Bearer {'t' * 48}"},
        ) as http_client:
            async with streamable_http_client(
                "http://127.0.0.1/mcp",
                http_client=http_client,
                terminate_on_close=False,
            ) as (read_stream, write_stream, _session_id):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    assert [tool.name for tool in listed.tools] == [
                        "workspace.list"
                    ]

                    result = await session.call_tool(
                        "workspace.list",
                        {"path": "."},
                    )
                    assert result.isError is False
                    assert result.structuredContent == {
                        "path": ".",
                        "entries": [],
                    }

    assert len(processor.tasks) == 1
    task = processor.tasks[0]
    assert task.agent.provider == "mcp"
    assert task.agent.session_id == "streamable-http"
    assert task.capability == "workspace.list"


@pytest.mark.anyio
async def test_sdk_rejects_extra_arguments_before_execution(
    tmp_path: Path,
) -> None:
    app, processor = _build_runtime(tmp_path)
    transport = httpx.ASGITransport(
        app=app,
        client=("127.0.0.1", 50_001),
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1",
            headers={"Authorization": f"Bearer {'t' * 48}"},
        ) as http_client:
            async with streamable_http_client(
                "http://127.0.0.1/mcp",
                http_client=http_client,
                terminate_on_close=False,
            ) as (read_stream, write_stream, _session_id):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        "workspace.list",
                        {"path": ".", "unexpected": True},
                    )
                    assert result.isError is True

    assert processor.tasks == []


@pytest.mark.anyio
async def test_unlisted_tool_reaches_fail_closed_task_processor(
    tmp_path: Path,
) -> None:
    app, processor = _build_runtime(tmp_path)
    transport = httpx.ASGITransport(
        app=app,
        client=("127.0.0.1", 50_002),
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1",
            headers={"Authorization": f"Bearer {'t' * 48}"},
        ) as http_client:
            async with streamable_http_client(
                "http://127.0.0.1/mcp",
                http_client=http_client,
                terminate_on_close=False,
            ) as (read_stream, write_stream, _session_id):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    result = await session.call_tool("unknown.tool", {})
                    assert result.isError is True

    assert len(processor.tasks) == 1
    assert processor.tasks[0].capability == "unknown.tool"


@pytest.mark.anyio
async def test_authentication_origin_and_loopback_guards(
    tmp_path: Path,
) -> None:
    app, _processor = _build_runtime(tmp_path)
    loopback_transport = httpx.ASGITransport(
        app=app,
        client=("127.0.0.1", 50_003),
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=loopback_transport,
            base_url="http://127.0.0.1",
        ) as client:
            missing = await client.post("/mcp", json={})
            assert missing.status_code == 401
            assert missing.headers["www-authenticate"] == "Bearer"

            wrong = await client.post(
                "/mcp",
                json={},
                headers={"Authorization": "Bearer wrong"},
            )
            assert wrong.status_code == 401

            hostile_origin = await client.post(
                "/mcp",
                json={},
                headers={
                    "Authorization": f"Bearer {'t' * 48}",
                    "Origin": "https://hostile.example",
                    "Accept": "application/json, text/event-stream",
                },
            )
            assert hostile_origin.status_code == 403

    remote_app, _remote_processor = _build_runtime(tmp_path / "remote")
    remote_transport = httpx.ASGITransport(
        app=remote_app,
        client=("192.0.2.10", 50_004),
    )
    async with remote_app.router.lifespan_context(remote_app):
        async with httpx.AsyncClient(
            transport=remote_transport,
            base_url="http://127.0.0.1",
            headers={"Authorization": f"Bearer {'t' * 48}"},
        ) as client:
            remote = await client.post("/mcp", json={})
            assert remote.status_code == 403


@pytest.mark.anyio
async def test_request_size_and_rate_limits(tmp_path: Path) -> None:
    size_app, _size_processor = _build_runtime(
        tmp_path / "size",
        max_request_bytes=64,
    )
    size_transport = httpx.ASGITransport(
        app=size_app,
        client=("127.0.0.1", 50_005),
    )
    async with size_app.router.lifespan_context(size_app):
        async with httpx.AsyncClient(
            transport=size_transport,
            base_url="http://127.0.0.1",
            headers={"Authorization": f"Bearer {'t' * 48}"},
        ) as client:
            oversized = await client.post(
                "/mcp",
                json={"payload": "x" * 128},
            )
            assert oversized.status_code == 413

    rate_app, _rate_processor = _build_runtime(
        tmp_path / "rate",
        requests_per_minute=1,
    )
    rate_transport = httpx.ASGITransport(
        app=rate_app,
        client=("127.0.0.1", 50_006),
    )
    headers = {
        "Authorization": f"Bearer {'t' * 48}",
        "Accept": "application/json, text/event-stream",
    }
    async with rate_app.router.lifespan_context(rate_app):
        async with httpx.AsyncClient(
            transport=rate_transport,
            base_url="http://127.0.0.1",
            headers=headers,
        ) as client:
            first = await client.post("/mcp", json={})
            assert first.status_code != 429
            limited = await client.post("/mcp", json={})
            assert limited.status_code == 429
            assert limited.headers["retry-after"] == "60"
