from fastapi import FastAPI, HTTPException

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

app = FastAPI(title="Système Local Agent Gateway", version="0.1.0")
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