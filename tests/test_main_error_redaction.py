from __future__ import annotations

import importlib
import json
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from systeme_local_gateway.models import AgentIdentity, TaskEnvelope


def _task() -> TaskEnvelope:
    now = datetime.now(UTC)
    return TaskEnvelope(
        task_id="error-redaction-task-12345678",
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
        agent=AgentIdentity(
            provider="test",
            model="model",
            session_id="session",
        ),
        capability="workspace.list",
        arguments={"path": "."},
        nonce="n" * 24,
        signature="s" * 43,
    )


def test_internal_execution_error_is_not_returned_to_remote_agent(
    monkeypatch,
    tmp_path: Path,
) -> None:
    raw_error = (
        r"C:\Users\cheur\private\credentials.txt "
        "API_KEY=super-secret-value"
    )
    events: list[dict[str, object]] = []

    audit_module = types.ModuleType("systeme_local_gateway.audit")

    class FakeAuditLog:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def verify(self) -> None:
            pass

        def append(self, event: dict[str, object]) -> str:
            events.append(event)
            return "audit-error-redaction"

    audit_module.AuditLog = FakeAuditLog

    auth_module = types.ModuleType("systeme_local_gateway.auth")

    class ReplayGuardUnavailableError(RuntimeError):
        pass

    class SQLiteReplayGuard:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

    def verify_task(_task, _secret, *, replay_guard) -> None:
        assert replay_guard is not None

    auth_module.ReplayGuardUnavailableError = ReplayGuardUnavailableError
    auth_module.SQLiteReplayGuard = SQLiteReplayGuard
    auth_module.verify_task = verify_task

    executor_module = types.ModuleType("systeme_local_gateway.executor")

    class FakeExecutor:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def execute(self, _capability, _arguments, _config):
            raise RuntimeError(raw_error)

    executor_module.CapabilityExecutor = FakeExecutor

    policy_module = types.ModuleType("systeme_local_gateway.policy")

    class FakePolicyEngine:
        def __init__(self, _path) -> None:
            self.limits = {}

        def evaluate(self, _capability):
            return SimpleNamespace(
                decision="allow",
                reason="policy decision: allow",
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
    try:
        gateway = importlib.import_module("systeme_local_gateway.main")
        result = gateway.submit_task(_task())

        assert result.status == "failed"
        assert result.error == "task execution failed"
        assert result.output == {}
        assert result.audit_id == "audit-error-redaction"
        assert raw_error not in json.dumps(result.model_dump(mode="json"))

        assert len(events) == 1
        assert events[0]["status"] == "failed"
        assert events[0]["error"] == raw_error
    finally:
        sys.modules.pop("systeme_local_gateway.main", None)
        sys.modules.pop("systeme_local_gateway.config", None)
