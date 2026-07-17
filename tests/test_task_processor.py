from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from systeme_local_gateway.approvals import ApprovalRecord
from systeme_local_gateway.models import AgentIdentity, TaskEnvelope
from systeme_local_gateway.task_processor import (
    TaskAuthenticationError,
    TaskProcessor,
    TaskServiceUnavailableError,
)


class ReplayUnavailableError(RuntimeError):
    pass


class FakeAuditLog:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def append(self, event: dict[str, object]) -> str:
        self.events.append(event)
        return f"audit-{len(self.events)}"


class FakePolicy:
    def __init__(
        self,
        decision: str = "allow",
        *,
        reason: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.decision = decision
        self.reason = reason or f"policy decision: {decision}"
        self.config = config or {}

    def evaluate(self, _capability: str):
        return SimpleNamespace(
            decision=self.decision,
            reason=self.reason,
            config=self.config,
        )


class FakeExecutor:
    def __init__(
        self,
        *,
        output: dict[str, Any] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.output = output or {"ok": True}
        self.error = error
        self.calls: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

    def execute(
        self,
        capability: str,
        arguments: dict[str, Any],
        config: dict[str, Any],
    ) -> dict[str, Any]:
        self.calls.append((capability, arguments, config))
        if self.error is not None:
            raise self.error
        return self.output


@dataclass
class FakeApprovalStore:
    pending: ApprovalRecord
    approved: ApprovalRecord

    def create(self, _task: TaskEnvelope) -> ApprovalRecord:
        return self.pending

    def consume(self, _approval_id: str, _task: TaskEnvelope) -> ApprovalRecord:
        return self.approved


def _task(
    *,
    capability: str = "workspace.list",
    approval_id: str | None = None,
    nonce: str = "n" * 24,
) -> TaskEnvelope:
    now = datetime.now(UTC)
    return TaskEnvelope(
        task_id="task-processor-test-12345678",
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
        agent=AgentIdentity(
            provider="test",
            model="model",
            session_id="session",
        ),
        capability=capability,
        arguments={"path": "."},
        approval_id=approval_id,
        nonce=nonce,
        signature="s" * 43,
    )


def _approval_record(*, state: str) -> ApprovalRecord:
    now = datetime.now(UTC)
    return ApprovalRecord(
        approval_id="apr_" + ("a" * 24),
        request_fingerprint="f" * 64,
        task_id="task-processor-test-12345678",
        capability="workspace.write_text",
        provider="test",
        model="model",
        state=state,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        decided_at=now if state == "approved" else None,
        consumed_at=None,
    )


def _approval_store() -> FakeApprovalStore:
    return FakeApprovalStore(
        pending=_approval_record(state="pending"),
        approved=_approval_record(state="approved"),
    )


def _processor(
    *,
    verifier,
    audit_log: FakeAuditLog,
    policy: FakePolicy | None = None,
    executor: FakeExecutor | None = None,
    approval_store: FakeApprovalStore | None = None,
) -> TaskProcessor:
    return TaskProcessor(
        shared_secret="s" * 48,
        replay_guard=object(),
        policy=policy or FakePolicy(),
        executor=executor or FakeExecutor(),
        audit_log=audit_log,
        approval_store=approval_store or _approval_store(),
        task_verifier=verifier,
        replay_unavailable_error=ReplayUnavailableError,
    )


def test_executes_an_allowed_task_and_audits_the_result() -> None:
    audit_log = FakeAuditLog()
    executor = FakeExecutor(output={"entries": []})
    verifier_calls: list[TaskEnvelope] = []

    def verifier(task, _secret, *, replay_guard) -> None:
        assert replay_guard is not None
        verifier_calls.append(task)

    processor = _processor(
        verifier=verifier,
        audit_log=audit_log,
        executor=executor,
    )
    task = _task()

    result = processor.process(task)

    assert verifier_calls == [task]
    assert executor.calls == [
        ("workspace.list", {"path": "."}, {}),
    ]
    assert result.status == "completed"
    assert result.output == {"entries": []}
    assert result.audit_id == "audit-1"
    assert audit_log.events == [
        {
            "task_id": task.task_id,
            "agent": task.agent.model_dump(),
            "capability": task.capability,
            "status": "completed",
            "arguments": task.arguments,
            "output": {"entries": []},
            "error": None,
            "approval_id": None,
        }
    ]


def test_invalid_task_is_audited_and_raised_as_a_safe_domain_error() -> None:
    audit_log = FakeAuditLog()

    def verifier(_task, _secret, *, replay_guard) -> None:
        assert replay_guard is not None
        raise ValueError("invalid task signature")

    processor = _processor(
        verifier=verifier,
        audit_log=audit_log,
    )
    task = _task()

    with pytest.raises(TaskAuthenticationError) as captured:
        processor.process(task)

    assert captured.value.detail == "invalid task signature"
    assert captured.value.audit_id == "audit-1"
    assert audit_log.events == [
        {
            "task_id": task.task_id,
            "capability": task.capability,
            "status": "denied",
            "reason": "invalid task signature",
        }
    ]


def test_replay_store_failure_is_audited_and_fails_closed() -> None:
    audit_log = FakeAuditLog()

    def verifier(_task, _secret, *, replay_guard) -> None:
        assert replay_guard is not None
        raise ReplayUnavailableError("database unavailable")

    processor = _processor(
        verifier=verifier,
        audit_log=audit_log,
    )
    task = _task()

    with pytest.raises(TaskServiceUnavailableError) as captured:
        processor.process(task)

    assert captured.value.detail == "replay protection unavailable"
    assert captured.value.audit_id == "audit-1"
    assert audit_log.events == [
        {
            "task_id": task.task_id,
            "capability": task.capability,
            "status": "failed",
            "reason": "replay protection unavailable",
        }
    ]


def test_execution_error_is_redacted_but_retained_for_local_audit() -> None:
    audit_log = FakeAuditLog()
    raw_error = r"C:\private\secret.txt API_KEY=secret"
    executor = FakeExecutor(error=RuntimeError(raw_error))

    def verifier(_task, _secret, *, replay_guard) -> None:
        assert replay_guard is not None

    processor = _processor(
        verifier=verifier,
        audit_log=audit_log,
        executor=executor,
    )
    task = _task()

    result = processor.process(task)

    assert result.status == "failed"
    assert result.error == "task execution failed"
    assert raw_error not in result.model_dump_json()
    assert audit_log.events[0]["error"] == raw_error


def test_approval_request_and_consumption_use_the_same_processor() -> None:
    audit_log = FakeAuditLog()
    approval_store = _approval_store()
    executor = FakeExecutor(output={"bytes_written": 7})

    def verifier(_task, _secret, *, replay_guard) -> None:
        assert replay_guard is not None

    processor = _processor(
        verifier=verifier,
        audit_log=audit_log,
        policy=FakePolicy(decision="require_approval"),
        executor=executor,
        approval_store=approval_store,
    )

    first = processor.process(_task(capability="workspace.write_text"))

    assert first.status == "approval_required"
    assert first.output["approval_id"] == approval_store.pending.approval_id
    assert first.output["approval_state"] == "pending"
    assert executor.calls == []

    approved_task = _task(
        capability="workspace.write_text",
        approval_id=approval_store.approved.approval_id,
        nonce="m" * 24,
    )
    second = processor.process(approved_task)

    assert second.status == "completed"
    assert executor.calls == [
        ("workspace.write_text", {"path": "."}, {}),
    ]
    assert [event["status"] for event in audit_log.events] == [
        "approval_required",
        "approval_consumed",
        "completed",
    ]