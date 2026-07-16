import base64
import hashlib
import hmac
import json
import runpy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systeme_local_gateway.auth import ReplayGuard, canonical_payload, verify_task
from systeme_local_gateway.models import AgentIdentity, TaskEnvelope

SECRET = "x" * 32


def signed_task(nonce: str = "n" * 24) -> TaskEnvelope:
    now = datetime.now(UTC)
    task = TaskEnvelope(
        task_id="task-12345678",
        issued_at=now,
        expires_at=now + timedelta(minutes=1),
        agent=AgentIdentity(provider="test", session_id="session"),
        capability="workspace.list",
        arguments={"path": "."},
        nonce=nonce,
        signature="placeholder-signature-that-is-long-enough-123456",
    )
    digest = hmac.new(SECRET.encode(), canonical_payload(task), hashlib.sha256).digest()
    task.signature = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return task


def test_valid_task_is_accepted() -> None:
    verify_task(signed_task(), SECRET)


def test_replay_is_rejected() -> None:
    guard = ReplayGuard()
    task = signed_task()
    verify_task(task, SECRET, replay_guard=guard)
    with pytest.raises(ValueError, match="replayed"):
        verify_task(task, SECRET, replay_guard=guard)


def test_excessive_task_lifetime_is_rejected() -> None:
    task = signed_task()
    task.expires_at = task.issued_at + timedelta(minutes=10)
    digest = hmac.new(SECRET.encode(), canonical_payload(task), hashlib.sha256).digest()
    task.signature = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    with pytest.raises(ValueError, match="lifetime"):
        verify_task(task, SECRET)


def test_optional_approval_id_preserves_legacy_signature_payload() -> None:
    task = signed_task()
    payload = json.loads(canonical_payload(task))
    assert "approval_id" not in payload

    task.approval_id = "approval-id-1234567890"
    payload_with_approval = json.loads(canonical_payload(task))
    assert payload_with_approval["approval_id"] == "approval-id-1234567890"


def test_sign_task_example_produces_a_verifiable_canonical_payload(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SLG_SHARED_SECRET", SECRET)
    monkeypatch.setenv("SLG_TASK_ID", "example-task-12345678")
    monkeypatch.setenv("SLG_TASK_CAPABILITY", "workspace.write_text")
    monkeypatch.setenv(
        "SLG_TASK_ARGUMENTS_JSON",
        '{"path":"example.txt","content":"example content"}',
    )
    monkeypatch.delenv("SLG_APPROVAL_ID", raising=False)

    script = Path(__file__).resolve().parents[1] / "examples" / "sign_task.py"
    runpy.run_path(str(script), run_name="__main__")

    task = TaskEnvelope.model_validate_json(capsys.readouterr().out)
    verify_task(task, SECRET)
    assert task.approval_id is None
