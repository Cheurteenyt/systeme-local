from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response

from .approvals import ApprovalStore
from .audit_runtime import create_configured_audit_log
from .auth import ReplayGuardUnavailableError, SQLiteReplayGuard, verify_task
from .config import settings
from .executor import CapabilityExecutor
from .models import TaskEnvelope, TaskResult
from .policy import PolicyEngine
from .task_processor import (
    TaskAuthenticationError,
    TaskProcessor,
    TaskServiceUnavailableError,
)

policy = PolicyEngine(settings.policy_file)
executor = CapabilityExecutor(
    settings.workspace,
    settings.docker_image,
    policy.limits,
    sandbox_root=settings.sandbox_root,
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
    policy=policy,
    executor=executor,
    audit_log=audit_log,
    approval_store=approval_store,
    task_verifier=verify_task,
    replay_unavailable_error=ReplayGuardUnavailableError,
)

mcp_runtime = None
if settings.mcp_enabled:
    if settings.mcp_token is None:
        raise RuntimeError("MCP is enabled without a configured token")

    from .mcp_runtime import McpRuntime
    from .mcp_tools import McpToolRegistry

    mcp_runtime = McpRuntime(
        token=settings.mcp_token,
        shared_secret=settings.shared_secret,
        registry=McpToolRegistry(policy),
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

    @app.api_route(
        "/mcp",
        methods=["GET", "POST", "DELETE"],
        include_in_schema=False,
    )
    async def mcp_endpoint(request: Request) -> Response:
        return await mcp_runtime.handle_http_request(request)
