from fastapi import FastAPI, HTTPException

from .approvals import (
    ApprovalConsumedError,
    ApprovalDeniedError,
    ApprovalExpiredError,
    ApprovalMismatchError,
    ApprovalNotFoundError,
    ApprovalPendingError,
    ApprovalRecord,
    ApprovalStore,
    ApprovalStoreUnavailableError,
)
from .audit import AuditLog
from .auth import ReplayGuardUnavailableError, SQLiteReplayGuard, verify_task
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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _approval_output(record: ApprovalRecord) -> dict[str, object]:
    return {
        "approval_id": record.approval_id,
        "approval_state": record.state,
        "approval_expires_at": record.expires_at.isoformat(),
        "request_fingerprint": record.request_fingerprint,
    }


def _approval_required(
    task: TaskEnvelope,
    *,
    record: ApprovalRecord | None = None,
    reason: str | None = None,
) -> TaskResult:
    approval_id = record.approval_id if record else task.approval_id
    event: dict[str, object] = {
        "task_id": task.task_id,
        "capability": task.capability,
        "status": "approval_required",
        "arguments": task.arguments,
    }
    if approval_id is not None:
        event["approval_id"] = approval_id
    if reason is not None:
        event["reason"] = reason
    audit_id = audit_log.append(event)

    output: dict[str, object]
    if record is not None:
        output = _approval_output(record)
    else:
        output = {
            "approval_id": approval_id,
            "approval_state": "pending",
        }
    return TaskResult(
        task_id=task.task_id,
        status="approval_required",
        output=output,
        audit_id=audit_id,
    )


def _denied(task: TaskEnvelope, reason: str) -> TaskResult:
    audit_id = audit_log.append(
        {
            "task_id": task.task_id,
            "capability": task.capability,
            "status": "denied",
            "reason": reason,
            "approval_id": task.approval_id,
        }
    )
    return TaskResult(
        task_id=task.task_id,
        status="denied",
        error=reason,
        audit_id=audit_id,
    )


def _approval_unavailable(task: TaskEnvelope, exc: Exception) -> None:
    audit_log.append(
        {
            "task_id": task.task_id,
            "capability": task.capability,
            "status": "failed",
            "reason": "approval service unavailable",
        }
    )
    raise HTTPException(
        status_code=503,
        detail="approval service unavailable",
    ) from exc


@app.post("/v1/tasks", response_model=TaskResult)
def submit_task(task: TaskEnvelope) -> TaskResult:
    try:
        verify_task(task, settings.shared_secret, replay_guard=replay_guard)
    except ReplayGuardUnavailableError as exc:
        audit_log.append(
            {
                "task_id": task.task_id,
                "capability": task.capability,
                "status": "failed",
                "reason": "replay protection unavailable",
            }
        )
        raise HTTPException(
            status_code=503,
            detail="replay protection unavailable",
        ) from exc
    except ValueError as exc:
        audit_log.append(
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
        return _denied(task, decision.reason)

    if decision.decision == "require_approval":
        if task.approval_id is None:
            try:
                record = approval_store.create(task)
            except ApprovalStoreUnavailableError as exc:
                _approval_unavailable(task, exc)
            return _approval_required(task, record=record)

        try:
            record = approval_store.consume(task.approval_id, task)
        except ApprovalPendingError:
            return _approval_required(task, reason="approval is still pending")
        except (
            ApprovalNotFoundError,
            ApprovalDeniedError,
            ApprovalConsumedError,
            ApprovalExpiredError,
            ApprovalMismatchError,
        ) as exc:
            return _denied(task, str(exc))
        except ApprovalStoreUnavailableError as exc:
            _approval_unavailable(task, exc)

        audit_log.append(
            {
                "task_id": task.task_id,
                "capability": task.capability,
                "status": "approval_consumed",
                "approval_id": record.approval_id,
            }
        )
    elif task.approval_id is not None:
        return _denied(task, "approval ID is not valid for this capability")

    try:
        output = executor.execute(task.capability, task.arguments, decision.config)
        status = "completed"
        response_error = None
        audit_error = None
    except Exception as exc:  # Boundary: never leak internal details to a remote agent.
        output = {}
        status = "failed"
        response_error = "task execution failed"
        audit_error = str(exc)

    audit_id = audit_log.append(
        {
            "task_id": task.task_id,
            "agent": task.agent.model_dump(),
            "capability": task.capability,
            "status": status,
            "arguments": task.arguments,
            "output": output,
            "error": audit_error,
            "approval_id": task.approval_id,
        }
    )
    return TaskResult(
        task_id=task.task_id,
        status=status,
        output=output,
        error=response_error,
        audit_id=audit_id,
    )
