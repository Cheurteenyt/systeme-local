from __future__ import annotations

from typing import Any, NoReturn, Protocol

from .approvals import (
    ApprovalConsumedError,
    ApprovalDeniedError,
    ApprovalExpiredError,
    ApprovalMismatchError,
    ApprovalNotFoundError,
    ApprovalPendingError,
    ApprovalRecord,
    ApprovalStoreUnavailableError,
)
from .models import TaskEnvelope, TaskResult


class AuditLogProtocol(Protocol):
    def append(self, event: dict[str, object]) -> str: ...


class ApprovalStoreProtocol(Protocol):
    def create(self, task: TaskEnvelope) -> ApprovalRecord: ...

    def consume(self, approval_id: str, task: TaskEnvelope) -> ApprovalRecord: ...


class CapabilityExecutorProtocol(Protocol):
    def execute(
        self,
        capability: str,
        arguments: dict[str, Any],
        config: dict[str, Any],
    ) -> dict[str, Any]: ...


class PolicyDecisionProtocol(Protocol):
    decision: str
    reason: str
    config: dict[str, Any]


class PolicyEngineProtocol(Protocol):
    def evaluate(self, capability: str) -> PolicyDecisionProtocol: ...


class TaskVerifierProtocol(Protocol):
    def __call__(
        self,
        task: TaskEnvelope,
        shared_secret: str,
        *,
        replay_guard: object,
    ) -> None: ...


class TaskProcessingError(RuntimeError):
    """Base class for safe, audited task-processing failures."""

    def __init__(self, detail: str, audit_id: str):
        super().__init__(detail)
        self.detail = detail
        self.audit_id = audit_id


class TaskAuthenticationError(TaskProcessingError):
    """Raised after an invalid task envelope has been audited."""


class TaskServiceUnavailableError(TaskProcessingError):
    """Raised after a required local security service fails closed."""


class TaskProcessor:
    """Transport-neutral authority for task verification and execution."""

    def __init__(
        self,
        *,
        shared_secret: str,
        replay_guard: object,
        policy: PolicyEngineProtocol,
        executor: CapabilityExecutorProtocol,
        audit_log: AuditLogProtocol,
        approval_store: ApprovalStoreProtocol,
        task_verifier: TaskVerifierProtocol,
        replay_unavailable_error: type[Exception],
    ):
        self._shared_secret = shared_secret
        self._replay_guard = replay_guard
        self._policy = policy
        self._executor = executor
        self._audit_log = audit_log
        self._approval_store = approval_store
        self._task_verifier = task_verifier
        self._replay_unavailable_error = replay_unavailable_error

    def process(self, task: TaskEnvelope) -> TaskResult:
        self._verify(task)

        decision = self._policy.evaluate(task.capability)
        if decision.decision == "deny":
            return self._denied(task, decision.reason)

        if decision.decision == "require_approval":
            approval_result = self._handle_approval(task)
            if approval_result is not None:
                return approval_result
        elif task.approval_id is not None:
            return self._denied(task, "approval ID is not valid for this capability")

        return self._execute(task, decision.config)

    def _verify(self, task: TaskEnvelope) -> None:
        try:
            self._task_verifier(
                task,
                self._shared_secret,
                replay_guard=self._replay_guard,
            )
        except Exception as exc:
            if isinstance(exc, self._replay_unavailable_error):
                self._raise_unavailable(
                    task,
                    detail="replay protection unavailable",
                    exc=exc,
                )
            if isinstance(exc, ValueError):
                audit_id = self._audit_log.append(
                    {
                        "task_id": task.task_id,
                        "capability": task.capability,
                        "status": "denied",
                        "reason": str(exc),
                    }
                )
                raise TaskAuthenticationError(str(exc), audit_id) from exc
            raise

    def _handle_approval(self, task: TaskEnvelope) -> TaskResult | None:
        if task.approval_id is None:
            try:
                record = self._approval_store.create(task)
            except ApprovalStoreUnavailableError as exc:
                self._raise_unavailable(
                    task,
                    detail="approval service unavailable",
                    exc=exc,
                )
            return self._approval_required(task, record=record)

        try:
            record = self._approval_store.consume(task.approval_id, task)
        except ApprovalPendingError:
            return self._approval_required(task, reason="approval is still pending")
        except (
            ApprovalNotFoundError,
            ApprovalDeniedError,
            ApprovalConsumedError,
            ApprovalExpiredError,
            ApprovalMismatchError,
        ) as exc:
            return self._denied(task, str(exc))
        except ApprovalStoreUnavailableError as exc:
            self._raise_unavailable(
                task,
                detail="approval service unavailable",
                exc=exc,
            )

        self._audit_log.append(
            {
                "task_id": task.task_id,
                "capability": task.capability,
                "status": "approval_consumed",
                "approval_id": record.approval_id,
            }
        )
        return None

    def _execute(
        self,
        task: TaskEnvelope,
        config: dict[str, Any],
    ) -> TaskResult:
        try:
            output = self._executor.execute(
                task.capability,
                task.arguments,
                config,
            )
            status = "completed"
            response_error = None
            audit_error = None
        except Exception as exc:  # Boundary: never leak internal details remotely.
            output = {}
            status = "failed"
            response_error = "task execution failed"
            audit_error = str(exc)

        audit_id = self._audit_log.append(
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

    def _approval_required(
        self,
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
        audit_id = self._audit_log.append(event)

        if record is not None:
            output: dict[str, object] = {
                "approval_id": record.approval_id,
                "approval_state": record.state,
                "approval_expires_at": record.expires_at.isoformat(),
                "request_fingerprint": record.request_fingerprint,
            }
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

    def _denied(self, task: TaskEnvelope, reason: str) -> TaskResult:
        audit_id = self._audit_log.append(
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

    def _raise_unavailable(
        self,
        task: TaskEnvelope,
        *,
        detail: str,
        exc: Exception,
    ) -> NoReturn:
        audit_id = self._audit_log.append(
            {
                "task_id": task.task_id,
                "capability": task.capability,
                "status": "failed",
                "reason": detail,
            }
        )
        raise TaskServiceUnavailableError(detail, audit_id) from exc