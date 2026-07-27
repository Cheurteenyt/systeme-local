from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from secrets import token_hex
from typing import TYPE_CHECKING, cast

from fastapi import FastAPI, HTTPException, Request, Response

from .approvals import ApprovalStore
from .audit_runtime import create_configured_audit_log
from .auth import ReplayGuardUnavailableError, SQLiteReplayGuard, verify_task
from .config import settings
from .executor import CapabilityExecutor
from .models import TaskEnvelope, TaskResult
from .policy import PolicyEngine
from .task_processor import (
    PolicyEngineProtocol,
    TaskAuthenticationError,
    TaskProcessor,
    TaskServiceUnavailableError,
    TaskVerifierProtocol,
)

if TYPE_CHECKING:
    from .mcp_tools import McpToolRegistry

policy = PolicyEngine(settings.policy_file)

c0_probe = None
mcp_registry: McpToolRegistry | None = None
if settings.mcp_enabled:
    from .mcp_tools import McpToolRegistry

    if settings.provider_runtime_mode == "chatgpt_chat_c4":
        from .c4_admission import (
            RuntimeAdmissionAction,
            build_admitted_mcp_registry,
            build_current_c4_adapter_registry,
            commit_runtime_admission_request,
            create_committed_runtime_admission_controller,
        )

        if settings.provider_runtime_root is None:
            raise RuntimeError("C4 provider runtime root is missing")
        evaluated_at = datetime.now(timezone.utc)
        reviewed_registry = build_current_c4_adapter_registry()
        adapter = reviewed_registry.adapters[0]
        request = commit_runtime_admission_request(
            identity=adapter.identity,
            action=RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE,
            requested_tools=adapter.approved_tools,
            evaluated_at=evaluated_at,
            request_correlation="c4_" + token_hex(16),
        )
        controller = create_committed_runtime_admission_controller(
            root=settings.provider_runtime_root,
            c3_registry_path=(
                settings.provider_runtime_root / "governance" / "c3-capability-registry.json"
            ),
            c4_registry_path=(
                settings.provider_runtime_root / "governance" / "c4-runtime-adapters.json"
            ),
            evaluated_at=evaluated_at,
        )
        decision = controller.decide(request)
        if not decision.allowed:
            raise RuntimeError(
                f"C4 provider runtime admission denied: {decision.reason_code.value}"
            )
        mcp_registry = build_admitted_mcp_registry(
            policy=policy,
            decision=decision,
            controller=controller,
            c0_mode=settings.c0_enabled,
        )
    else:
        mcp_registry = McpToolRegistry(policy, c0_mode=settings.c0_enabled)
    if settings.c0_enabled:
        from .c0_probe import (
            C0_TOOL_NAME,
            C0ConnectivityProbe,
            C0ProbeContext,
        )

        if settings.c0_server_build_commit is None:
            raise RuntimeError("C0 is enabled without a server build commit")
        tool_names = tuple(tool.name for tool in mcp_registry.list_tools())
        if tool_names != (C0_TOOL_NAME,):
            raise RuntimeError("C0 policy must expose exactly systeme_local_connectivity_probe")
        c0_probe = C0ConnectivityProbe(
            C0ProbeContext(
                server_build_commit=settings.c0_server_build_commit,
                local_policy_sha256=policy.policy_sha256,
                tool_snapshot_sha256=mcp_registry.tool_snapshot_sha256,
            )
        )

executor = CapabilityExecutor(
    settings.workspace,
    settings.docker_image,
    policy.limits,
    sandbox_root=settings.sandbox_root,
    c0_probe=c0_probe,
)
audit_log = create_configured_audit_log(settings)
audit_log.verify()
replay_guard = SQLiteReplayGuard(
    settings.replay_db,
    settings.shared_secret,
    max_entries=settings.replay_max_entries,
)
approval_store = ApprovalStore(
    settings.approval_db,
    settings.audit_key,
    max_entries=settings.approval_max_entries,
    ttl_seconds=settings.approval_ttl_seconds,
)
task_processor = TaskProcessor(
    shared_secret=settings.shared_secret,
    replay_guard=replay_guard,
    policy=cast(PolicyEngineProtocol, policy),
    executor=executor,
    audit_log=audit_log,
    approval_store=approval_store,
    task_verifier=cast(TaskVerifierProtocol, verify_task),
    replay_unavailable_error=ReplayGuardUnavailableError,
)

mcp_runtime = None
if settings.mcp_enabled:
    if settings.mcp_token is None:
        raise RuntimeError("MCP is enabled without a configured token")
    if mcp_registry is None:
        raise RuntimeError("MCP is enabled without an admitted registry")

    from .mcp_runtime import McpRuntime, McpToolRegistryProtocol

    mcp_runtime = McpRuntime(
        token=settings.mcp_token,
        shared_secret=settings.shared_secret,
        registry=cast(McpToolRegistryProtocol, mcp_registry),
        task_processor=task_processor,
        max_request_bytes=settings.mcp_max_request_bytes,
        requests_per_minute=settings.mcp_requests_per_minute,
        max_concurrency=settings.mcp_max_concurrency,
    )


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    if mcp_runtime is None:
        yield
    else:
        async with mcp_runtime.run():
            yield


app = FastAPI(
    title="Système Local Agent Gateway",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/tasks", response_model=TaskResult)
def submit_task(task: TaskEnvelope) -> TaskResult:
    try:
        return task_processor.process(task)
    except TaskAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=exc.detail) from exc
    except TaskServiceUnavailableError as exc:
        raise HTTPException(status_code=503, detail=exc.detail) from exc


if mcp_runtime is not None:
    admitted_mcp_runtime = mcp_runtime

    @app.api_route(
        "/mcp",
        methods=["GET", "POST", "DELETE"],
        include_in_schema=False,
    )
    async def mcp_endpoint(request: Request) -> Response:
        return await admitted_mcp_runtime.handle_http_request(request)
