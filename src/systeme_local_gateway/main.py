from fastapi import FastAPI, HTTPException

from .audit import AuditLog
from .auth import ReplayGuard, verify_task
from .config import settings
from .executor import CapabilityExecutor
from .models import TaskEnvelope, TaskResult
from .policy import PolicyEngine

app = FastAPI(title="Système Local Agent Gateway", version="0.1.0")
policy = PolicyEngine(settings.policy_file)
executor = CapabilityExecutor(
    settings.workspace,
    settings.docker_image,
    policy.limits,
    sandbox_root=settings.sandbox_root,
)
audit_log = AuditLog(settings.audit_log, settings.audit_key)
audit_log.verify()
replay_guard = ReplayGuard()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/tasks", response_model=TaskResult)
def submit_task(task: TaskEnvelope) -> TaskResult:
    try:
        verify_task(task, settings.shared_secret, replay_guard=replay_guard)
    except ValueError as exc:
        audit_id = audit_log.append(
            {
                "task_id": task.task_id,
                "capability": task.capability,
                "status": "denied",
                "reason": str(exc),
            }
        )
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    decision = policy.evaluate(task.capability)
    if decision.decision == "deny":
        audit_id = audit_log.append(
            {
                "task_id": task.task_id,
                "capability": task.capability,
                "status": "denied",
                "reason": decision.reason,
            }
        )
        return TaskResult(
            task_id=task.task_id,
            status="denied",
            error=decision.reason,
            audit_id=audit_id,
        )

    if decision.decision == "require_approval":
        audit_id = audit_log.append(
            {
                "task_id": task.task_id,
                "capability": task.capability,
                "status": "approval_required",
                "arguments": task.arguments,
            }
        )
        return TaskResult(
            task_id=task.task_id,
            status="approval_required",
            output={"approval_token": audit_id},
            audit_id=audit_id,
        )

    try:
        output = executor.execute(task.capability, task.arguments, decision.config)
        status = "completed"
        error = None
    except Exception as exc:  # Boundary: never leak a traceback to a remote agent.
        output = {}
        status = "failed"
        error = str(exc)

    audit_id = audit_log.append(
        {
            "task_id": task.task_id,
            "agent": task.agent.model_dump(),
            "capability": task.capability,
            "status": status,
            "arguments": task.arguments,
            "output": output,
            "error": error,
        }
    )
    return TaskResult(
        task_id=task.task_id,
        status=status,
        output=output,
        error=error,
        audit_id=audit_id,
    )
