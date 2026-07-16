from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from systeme_local_gateway.models import AgentIdentity, TaskEnvelope


def task_data() -> dict:
    now = datetime.now(UTC)
    return {
        "task_id": "task-12345678",
        "issued_at": now,
        "expires_at": now + timedelta(minutes=1),
        "agent": AgentIdentity(provider="test", session_id="session"),
        "capability": "workspace.list",
        "arguments": {"path": "."},
        "nonce": "n" * 24,
        "signature": "s" * 43,
    }


def test_task_rejects_unknown_fields() -> None:
    data = task_data()
    data["unexpected"] = True
    with pytest.raises(ValidationError, match="unexpected"):
        TaskEnvelope(**data)


def test_task_requires_timezone_aware_timestamps() -> None:
    data = task_data()
    data["issued_at"] = datetime.now()
    with pytest.raises(ValidationError, match="timezone"):
        TaskEnvelope(**data)


def test_task_requires_ordered_time_window() -> None:
    data = task_data()
    data["expires_at"] = data["issued_at"]
    with pytest.raises(ValidationError, match="expires_at"):
        TaskEnvelope(**data)


def test_task_accepts_an_opaque_approval_identifier() -> None:
    data = task_data()
    data["approval_id"] = "approval_id-1234567890"
    task = TaskEnvelope(**data)
    assert task.approval_id == "approval_id-1234567890"


def test_task_rejects_malformed_approval_identifier() -> None:
    data = task_data()
    data["approval_id"] = "contains spaces and punctuation!"
    with pytest.raises(ValidationError, match="approval_id"):
        TaskEnvelope(**data)
