from __future__ import annotations

import importlib
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from systeme_local_gateway.models import AgentIdentity, TaskEnvelope


def _task(
    *,
    nonce: str,
    approval_id: str | None = None,
) -> TaskEnvelope:
    now = datetime.now(UTC)
    return TaskEnvelope(
        task_id="approval-flow-task-12345678",
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
        agent=AgentIdentity(
            provider="test",
            model="model",
            session_id="session",
        ),
        capability="workspace.write_text",
        arguments={"path": "approved.txt", "content": "approved content"},
        approval_id=approval_id,
        nonce=nonce,
        signature="s" * 43,
    )


def test_gateway_executes_a_locally_approved_action_once(
    monkeypatch,
    tmp_path: Path,
) -> None:
    events: list[dict[str, object]] = []
    executions: list[tuple[str, dict[str, object]]] = []

    audit_module = types.ModuleType("systeme_local_gateway.audit")

    class FakeAuditLog:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def verify(self) -> None:
            pass

        def append(self, event: dict[str, object]) -> str:
            events.append(event)
            return f"audit-{len(events)}"

    audit_module.AuditLog = FakeAuditLog

    auth_module = types.ModuleType("systeme_local_gateway.auth")

    class ReplayGuardUnavailableError(RuntimeError):
        pass

    class SQLiteReplayGuard:
        def __init__(self, *_args, **_kwargs) -> None:
            self.seen: set[str] = set()

    def verify_task(task, _secret, *, replay_guard) -> None:
        if task.nonce in replay_guard.seen:
            raise ValueError("replayed task nonce")
        replay_guard.seen.add(task.nonce)

    auth_module.ReplayGuardUnavailableError = ReplayGuardUnavailableError
    auth_module.SQLiteReplayGuard = SQLiteReplayGuard
    auth_module.verify_task = verify_task

    executor_module = types.ModuleType("systeme_local_gateway.executor")

    class FakeExecutor:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def execute(self, capability, arguments, _config):
            executions.append((capability, arguments))
            return {"bytes_written": len(str(arguments["content"]).encode())}

    executor_module.CapabilityExecutor = FakeExecutor

    policy_module = types.ModuleType("systeme_local_gateway.policy")

    class FakePolicyEngine:
        def __init__(self, _path) -> None:
            self.limits = {}

        def evaluate(self, _capability):
            return SimpleNamespace(
                decision="require_approval",
                reason="policy decision: require_approval",
                config={},
            )

    policy_module.PolicyEngine = FakePolicyEngine

    monkeypatch.setitem(sys.modules, "systeme_local_gateway.audit", audit_module)
    monkeypatch.setitem(sys.modules, "systeme_local_gateway.auth", auth_module)
    monkeypatch.setitem(sys.modules, "systeme_local_gateway.executor", executor_module)
    monkeypatch.setitem(sys.modules, "systeme_local_gateway.policy", policy_module)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SLG_SHARED_SECRET", "s" * 48)
    monkeypatch.setenv("SLG_AUDIT_KEY", "a" * 48)

    sys.modules.pop("systeme_local_gateway.config", None)
    sys.modules.pop("systeme_local_gateway.main", None)
    gateway = importlib.import_module("systeme_local_gateway.main")

    original_task = _task(nonce="n" * 24)
    first = gateway.submit_task(original_task)
    assert first.status == "approval_required"
    approval_id = str(first.output["approval_id"])

    gateway.approval_store.approve(approval_id, original_task)

    second = gateway.submit_task(
        _task(nonce="m" * 24, approval_id=approval_id)
    )
    assert second.status == "completed"
    assert len(executions) == 1

    third = gateway.submit_task(
        _task(nonce="p" * 24, approval_id=approval_id)
    )
    assert third.status == "denied"
    assert third.error == "approval was already used"
    assert len(executions) == 1

    assert [event["status"] for event in events] == [
        "approval_required",
        "approval_consumed",
        "completed",
        "denied",
    ]
