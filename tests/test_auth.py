import base64
import hashlib
import hmac
from datetime import UTC, datetime, timedelta

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
