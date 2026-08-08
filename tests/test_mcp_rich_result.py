from __future__ import annotations

from typing import Any

import pytest
from mcp import types

from systeme_local_gateway.mcp_runtime import McpTaskAdapter
from systeme_local_gateway.models import TaskResult


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _MetadataOnlyProcessor:
    def process(self, task: object) -> TaskResult:
        task_id = str(task.task_id)
        return TaskResult(
            task_id=task_id,
            status="completed",
            output={"delivery_token": "c9_delivery_" + "a" * 32},
            audit_id="c9_audit_" + "b" * 32,
        )


class _RichRenderer:
    def __init__(self, *, fail_commit: bool = False) -> None:
        self.calls: list[dict[str, Any]] = []
        self.commits = 0
        self.aborts = 0
        self.fail_commit = fail_commit

    def prepare(
        self,
        *,
        name: str,
        arguments: dict[str, Any],
        output: dict[str, Any],
        metadata: dict[str, str],
    ) -> _PreparedRender | None:
        self.calls.append(
            {
                "name": name,
                "arguments": arguments,
                "output": output,
                "metadata": metadata,
            }
        )
        return _PreparedRender(
            renderer=self,
            result=types.CallToolResult(
                content=[
                    types.TextContent(type="text", text="Approved C9 attachment handoff."),
                    types.ImageContent(
                        type="image",
                        data="c3ludGhldGljLWltYWdl",
                        mimeType="image/png",
                    ),
                    types.EmbeddedResource(
                        type="resource",
                        resource=types.TextResourceContents(
                            uri="systeme-local://c9/document.txt",
                            mimeType="text/plain",
                            text="synthetic document",
                        ),
                    ),
                ],
                structuredContent={
                    "status": "delivered_to_mcp_transport",
                    "manifest_sha256": "c" * 64,
                },
                isError=False,
                _meta=metadata,
            ),
        )


class _PreparedRender:
    def __init__(
        self,
        *,
        renderer: _RichRenderer,
        result: types.CallToolResult,
    ) -> None:
        self._renderer = renderer
        self.result = result

    def commit(self) -> None:
        self._renderer.commits += 1
        if self._renderer.fail_commit:
            raise RuntimeError("synthetic render commit failure")

    def abort(self) -> None:
        self._renderer.aborts += 1


class _RenderAudit:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def append(self, event: dict[str, object]) -> str:
        self.events.append(event)
        return "c9_render_audit_" + "e" * 32


class _CompactRenderer:
    def __init__(self) -> None:
        self._delegate = _RichRenderer()

    @property
    def commits(self) -> int:
        return self._delegate.commits

    @property
    def aborts(self) -> int:
        return self._delegate.aborts

    def prepare(self, **_kwargs: object) -> _PreparedRender | None:
        return _PreparedRender(
            renderer=self._delegate,
            result=types.CallToolResult(
                content=[types.TextContent(type="text", text="ok")],
                structuredContent={"status": "ok"},
                isError=False,
            ),
        )


@pytest.mark.anyio
async def test_metadata_only_task_result_can_expand_to_mcp_native_content() -> None:
    renderer = _RichRenderer()
    render_audit = _RenderAudit()
    adapter = McpTaskAdapter(
        shared_secret="s" * 48,
        task_processor=_MetadataOnlyProcessor(),
        max_concurrency=1,
        result_renderer=renderer,
        render_audit_log=render_audit,
    )

    result = await adapter.call_tool(
        "systeme_local_attachment_handoff",
        {"handoff_id": "c9_handoff_" + "d" * 32, "surface": "work"},
    )

    assert result.isError is False
    assert result.structuredContent == {
        "status": "delivered_to_mcp_transport",
        "manifest_sha256": "c" * 64,
    }
    assert isinstance(result.content[0], types.TextContent)
    assert isinstance(result.content[1], types.ImageContent)
    assert isinstance(result.content[2], types.EmbeddedResource)
    assert result.meta == {
        "systeme-local/audit-id": "c9_audit_" + "b" * 32,
        "systeme-local/task-id": renderer.calls[0]["metadata"]["systeme-local/task-id"],
    }
    assert renderer.calls[0]["output"] == {"delivery_token": "c9_delivery_" + "a" * 32}
    assert renderer.calls[0]["arguments"]["surface"] == "work"
    assert render_audit.events == [
        {
            "task_id": result.meta["systeme-local/task-id"],
            "capability": "systeme_local_attachment_handoff",
            "status": "render_completed",
            "content_recorded": False,
        }
    ]
    assert renderer.commits == 1
    assert renderer.aborts == 0


class _FailingRenderer:
    def prepare(self, **_kwargs: object) -> _PreparedRender | None:
        raise RuntimeError("private attachment path must not escape")


@pytest.mark.anyio
async def test_renderer_failure_is_safe_and_does_not_leak_internal_detail() -> None:
    render_audit = _RenderAudit()
    adapter = McpTaskAdapter(
        shared_secret="s" * 48,
        task_processor=_MetadataOnlyProcessor(),
        max_concurrency=1,
        result_renderer=_FailingRenderer(),
        render_audit_log=render_audit,
    )

    result = await adapter.call_tool(
        "systeme_local_attachment_handoff",
        {"handoff_id": "c9_handoff_" + "d" * 32, "surface": "chat"},
    )

    assert result.isError is True
    assert isinstance(result.content[0], types.TextContent)
    assert result.content[0].text == "Tool response rendering failed"
    assert "private attachment path" not in result.content[0].text
    assert render_audit.events[0]["status"] == "render_failed"
    assert render_audit.events[0]["failure_type"] == "RuntimeError"


class _ConflictingMetadataRenderer(_RichRenderer):
    def prepare(self, **kwargs: object) -> _PreparedRender | None:
        prepared = super().prepare(**kwargs)
        assert prepared is not None
        prepared.result = prepared.result.model_copy(
            update={"meta": {"systeme-local/audit-id": "attacker-controlled"}}
        )
        return prepared


class _MutatingMetadataRenderer(_RichRenderer):
    def prepare(self, **kwargs: object) -> _PreparedRender | None:
        metadata = kwargs["metadata"]
        assert isinstance(metadata, dict)
        metadata["systeme-local/audit-id"] = "attacker-controlled"
        return super().prepare(**kwargs)


@pytest.mark.anyio
async def test_renderer_cannot_replace_required_audit_metadata() -> None:
    renderer = _ConflictingMetadataRenderer()
    render_audit = _RenderAudit()
    adapter = McpTaskAdapter(
        shared_secret="s" * 48,
        task_processor=_MetadataOnlyProcessor(),
        max_concurrency=1,
        result_renderer=renderer,
        render_audit_log=render_audit,
    )

    result = await adapter.call_tool(
        "systeme_local_attachment_handoff",
        {"handoff_id": "c9_handoff_" + "d" * 32, "surface": "work"},
    )

    assert result.isError is True
    assert result.meta == {
        "systeme-local/audit-id": "c9_audit_" + "b" * 32,
        "systeme-local/task-id": result.meta["systeme-local/task-id"],
    }
    assert renderer.commits == 0
    assert renderer.aborts == 1
    assert render_audit.events[0]["status"] == "render_failed"


@pytest.mark.anyio
async def test_renderer_cannot_mutate_required_audit_metadata_by_reference() -> None:
    renderer = _MutatingMetadataRenderer()
    render_audit = _RenderAudit()
    adapter = McpTaskAdapter(
        shared_secret="s" * 48,
        task_processor=_MetadataOnlyProcessor(),
        max_concurrency=1,
        result_renderer=renderer,
        render_audit_log=render_audit,
    )

    result = await adapter.call_tool(
        "systeme_local_attachment_handoff",
        {"handoff_id": "c9_handoff_" + "d" * 32, "surface": "chat"},
    )

    assert result.isError is True
    assert result.meta == {
        "systeme-local/audit-id": "c9_audit_" + "b" * 32,
        "systeme-local/task-id": result.meta["systeme-local/task-id"],
    }
    assert renderer.commits == 0
    assert renderer.aborts == 1
    assert render_audit.events[0]["status"] == "render_failed"


@pytest.mark.anyio
async def test_renderer_response_is_bounded_before_transport() -> None:
    renderer = _RichRenderer()
    render_audit = _RenderAudit()
    adapter = McpTaskAdapter(
        shared_secret="s" * 48,
        task_processor=_MetadataOnlyProcessor(),
        max_concurrency=1,
        result_renderer=renderer,
        render_audit_log=render_audit,
        max_rendered_response_bytes=64,
    )

    result = await adapter.call_tool(
        "systeme_local_attachment_handoff",
        {"handoff_id": "c9_handoff_" + "d" * 32, "surface": "work"},
    )

    assert result.isError is True
    assert isinstance(result.content[0], types.TextContent)
    assert result.content[0].text == "Tool response rendering failed"
    assert renderer.commits == 0
    assert renderer.aborts == 1
    assert render_audit.events[0]["status"] == "render_failed"


class _FailingCompletedAudit(_RenderAudit):
    def append(self, event: dict[str, object]) -> str:
        if event["status"] == "render_completed":
            raise RuntimeError("synthetic completed-audit failure")
        return super().append(event)


@pytest.mark.anyio
async def test_completed_audit_failure_aborts_committed_render() -> None:
    renderer = _CompactRenderer()
    render_audit = _FailingCompletedAudit()
    adapter = McpTaskAdapter(
        shared_secret="s" * 48,
        task_processor=_MetadataOnlyProcessor(),
        max_concurrency=1,
        result_renderer=renderer,
        render_audit_log=render_audit,
    )

    result = await adapter.call_tool(
        "systeme_local_attachment_handoff",
        {"handoff_id": "c9_handoff_" + "d" * 32, "surface": "chat"},
    )

    assert result.isError is True
    assert isinstance(result.content[0], types.TextContent)
    assert result.content[0].text == "Tool response rendering failed"
    assert renderer.commits == 1
    assert renderer.aborts == 1
    assert [event["status"] for event in render_audit.events] == ["render_failed"]


@pytest.mark.anyio
async def test_commit_failure_aborts_and_records_render_failure() -> None:
    renderer = _RichRenderer(fail_commit=True)
    render_audit = _RenderAudit()
    adapter = McpTaskAdapter(
        shared_secret="s" * 48,
        task_processor=_MetadataOnlyProcessor(),
        max_concurrency=1,
        result_renderer=renderer,
        render_audit_log=render_audit,
    )

    result = await adapter.call_tool(
        "systeme_local_attachment_handoff",
        {"handoff_id": "c9_handoff_" + "d" * 32, "surface": "work"},
    )

    assert result.isError is True
    assert renderer.commits == 1
    assert renderer.aborts == 1
    assert render_audit.events[0]["status"] == "render_failed"
    assert render_audit.events[0]["failure_type"] == "RuntimeError"
