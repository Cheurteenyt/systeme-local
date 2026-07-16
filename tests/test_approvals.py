from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systeme_local_gateway.approvals import (
    ApprovalConsumedError,
    ApprovalDeniedError,
    ApprovalMismatchError,
    ApprovalPendingError,
    ApprovalStore,
    ApprovalStoreUnavailableError,
    main as approvals_main,
    verify_approval_task,
)
from systeme_local_gateway.auth import canonical_payload
from systeme_local_gateway.models import AgentIdentity, TaskEnvelope

KEY = "a" * 48


def _task(
    now: datetime,
    *,
    task_id: str = "approval-task-12345678",
    arguments: dict[str, object] | None = None,
    nonce: str = "n" * 24,
    approval_id: str | None = None,
) -> TaskEnvelope:
    return TaskEnvelope(
        task_id=task_id,
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
        agent=AgentIdentity(
            provider="test",
            model="model",
            session_id="secret-session-value",
        ),
        capability="workspace.write_text",
        arguments=arguments or {"path": "result.txt", "content": "secret-content"},
        approval_id=approval_id,
        nonce=nonce,
        signature="s" * 43,
    )


def _sign_task(task: TaskEnvelope, secret: str = KEY) -> TaskEnvelope:
    digest = hmac.new(
        secret.encode("utf-8"),
        canonical_payload(task),
        hashlib.sha256,
    ).digest()
    task.signature = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return task


def test_approval_is_local_single_use_and_bound_to_action(tmp_path: Path) -> None:
    database = tmp_path / "approvals.sqlite3"
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = ApprovalStore(database, KEY, clock=lambda: now)

    original = _task(now)
    pending = store.create(original)
    assert pending.state == "pending"

    approved = store.approve(pending.approval_id, original)
    assert approved.state == "approved"

    fresh_task = _task(
        now + timedelta(seconds=1),
        nonce="m" * 24,
        approval_id=pending.approval_id,
    )
    consumed = store.consume(pending.approval_id, fresh_task)
    assert consumed.state == "consumed"

    with pytest.raises(ApprovalConsumedError, match="already used"):
        store.consume(pending.approval_id, fresh_task)


def test_pending_and_denied_requests_cannot_be_consumed(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = ApprovalStore(tmp_path / "approvals.sqlite3", KEY, clock=lambda: now)

    pending = store.create(_task(now))
    with pytest.raises(ApprovalPendingError, match="pending"):
        store.consume(pending.approval_id, _task(now, approval_id=pending.approval_id))

    store.deny(pending.approval_id)
    with pytest.raises(ApprovalDeniedError, match="denied"):
        store.consume(pending.approval_id, _task(now, approval_id=pending.approval_id))


def test_modified_action_does_not_match_approval(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = ApprovalStore(tmp_path / "approvals.sqlite3", KEY, clock=lambda: now)
    original = _task(now)
    pending = store.create(original)

    changed = _task(
        now,
        arguments={"path": "different.txt", "content": "changed"},
        approval_id=pending.approval_id,
    )
    with pytest.raises(ApprovalMismatchError, match="does not match"):
        store.approve(pending.approval_id, changed)

    store.approve(pending.approval_id, original)
    with pytest.raises(ApprovalMismatchError, match="does not match"):
        store.consume(pending.approval_id, changed)


def test_database_contains_no_raw_arguments_or_session_id(tmp_path: Path) -> None:
    database = tmp_path / "approvals.sqlite3"
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = ApprovalStore(database, KEY, clock=lambda: now)
    store.create(_task(now))

    raw = database.read_bytes()
    assert b"secret-content" not in raw
    assert b"secret-session-value" not in raw
    assert b"result.txt" not in raw


def test_duplicate_active_request_reuses_identifier(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = ApprovalStore(tmp_path / "approvals.sqlite3", KEY, clock=lambda: now)

    first = store.create(_task(now))
    second = store.create(_task(now + timedelta(seconds=1), nonce="m" * 24))
    assert second.approval_id == first.approval_id

    store.approve(first.approval_id, _task(now))
    third = store.create(_task(now + timedelta(seconds=2), nonce="p" * 24))
    assert third.approval_id == first.approval_id
    assert third.state == "approved"


def test_expired_request_is_pruned_before_capacity_check(tmp_path: Path) -> None:
    clock_value = [datetime(2026, 1, 1, tzinfo=UTC)]
    store = ApprovalStore(
        tmp_path / "approvals.sqlite3",
        KEY,
        max_entries=1,
        ttl_seconds=30,
        clock=lambda: clock_value[0],
    )

    first = store.create(_task(clock_value[0]))
    clock_value[0] += timedelta(seconds=31)
    second = store.create(
        _task(clock_value[0], task_id="approval-task-87654321", nonce="m" * 24)
    )
    assert second.approval_id != first.approval_id


def test_capacity_exhaustion_fails_closed(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = ApprovalStore(
        tmp_path / "approvals.sqlite3",
        KEY,
        max_entries=1,
        clock=lambda: now,
    )
    store.create(_task(now))

    with pytest.raises(ApprovalStoreUnavailableError, match="capacity"):
        store.create(
            _task(now, task_id="approval-task-87654321", nonce="m" * 24)
        )


def test_concurrent_consumption_succeeds_only_once(tmp_path: Path) -> None:
    database = tmp_path / "approvals.sqlite3"
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = ApprovalStore(database, KEY, clock=lambda: now)
    original = _task(now)
    pending = store.create(original)
    store.approve(pending.approval_id, original)
    barrier = threading.Barrier(2)

    def attempt(index: int) -> str:
        local = ApprovalStore(database, KEY, clock=lambda: now)
        task = _task(
            now,
            nonce=("m" if index else "p") * 24,
            approval_id=pending.approval_id,
        )
        barrier.wait(timeout=5)
        try:
            local.consume(pending.approval_id, task)
        except ApprovalConsumedError:
            return "consumed"
        return "accepted"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, range(2)))

    assert sorted(outcomes) == ["accepted", "consumed"]


def test_tampered_row_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "approvals.sqlite3"
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = ApprovalStore(database, KEY, clock=lambda: now)
    pending = store.create(_task(now))

    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "UPDATE approvals SET capability = 'workspace.read_text' "
            "WHERE approval_id = ?",
            (pending.approval_id,),
        )
        connection.commit()

    with pytest.raises(ApprovalStoreUnavailableError, match="HMAC"):
        store.verify()


def test_corrupt_database_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "approvals.sqlite3"
    database.write_bytes(b"not sqlite")

    with pytest.raises(ApprovalStoreUnavailableError, match="unavailable"):
        ApprovalStore(database, KEY)


def test_connections_are_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    real_connect = sqlite3.connect
    connections: list[sqlite3.Connection] = []

    def tracked_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        connection = real_connect(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(
        "systeme_local_gateway.approvals.sqlite3.connect",
        tracked_connect,
    )
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = ApprovalStore(tmp_path / "approvals.sqlite3", KEY, clock=lambda: now)
    original = _task(now)
    pending = store.create(original)
    store.approve(pending.approval_id, original)
    store.list_pending()
    store.verify()

    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


def test_signature_is_verified_before_local_approval() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    task = _sign_task(_task(now))
    verify_approval_task(task, KEY)

    task.signature = "z" * len(task.signature)
    with pytest.raises(ValueError, match="signature"):
        verify_approval_task(task, KEY)

    approved_envelope = _sign_task(
        _task(now, approval_id="approval-id-1234567890")
    )
    with pytest.raises(ValueError, match="original request"):
        verify_approval_task(approved_envelope, KEY)




def test_generated_approval_id_is_cli_safe(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    raw_token = "-" + ("a" * 31)
    monkeypatch.setattr(
        "systeme_local_gateway.approvals.secrets.token_urlsafe",
        lambda _size: raw_token,
    )

    store = ApprovalStore(tmp_path / "approvals.sqlite3", KEY, clock=lambda: now)
    pending = store.create(_task(now))

    assert pending.approval_id == f"apr_{raw_token}"
    assert not pending.approval_id.startswith("-")


def test_cli_accepts_legacy_leading_dash_approval_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    task = _sign_task(_task(now))
    task_file = tmp_path / "legacy-task.json"
    task_file.write_text(task.model_dump_json(), encoding="utf-8")
    legacy_id = "-" + ("b" * 31)

    monkeypatch.setattr(
        "systeme_local_gateway.approvals._APPROVAL_ID_PREFIX",
        "",
    )
    monkeypatch.setattr(
        "systeme_local_gateway.approvals.secrets.token_urlsafe",
        lambda _size: legacy_id,
    )

    store = ApprovalStore(tmp_path / "approvals.sqlite3", KEY, clock=lambda: now)
    pending = store.create(task)
    assert pending.approval_id == legacy_id

    class FakeAuditLog:
        def append(self, _event: dict[str, object]) -> str:
            return "audit-id"

    monkeypatch.setattr(
        "systeme_local_gateway.approvals._configured_components",
        lambda: (store, FakeAuditLog(), KEY),
    )

    result = approvals_main(
        [
            "approve",
            legacy_id,
            "--task-file",
            str(task_file),
            "--yes",
        ]
    )

    assert result == 0
    assert store.inspect(legacy_id, task).state == "approved"
    assert json.dumps("secret-content") in capsys.readouterr().out


def test_cli_approval_requires_and_displays_exact_signed_task(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    task = _sign_task(_task(now))
    task_file = tmp_path / "task.json"
    task_file.write_text(task.model_dump_json(), encoding="utf-8")

    store = ApprovalStore(tmp_path / "approvals.sqlite3", KEY, clock=lambda: now)
    pending = store.create(task)

    class FakeAuditLog:
        def append(self, _event: dict[str, object]) -> str:
            return "audit-id"

    monkeypatch.setattr(
        "systeme_local_gateway.approvals._configured_components",
        lambda: (store, FakeAuditLog(), KEY),
    )

    result = approvals_main(
        [
            "approve",
            pending.approval_id,
            "--task-file",
            str(task_file),
            "--yes",
        ]
    )
    assert result == 0
    output = capsys.readouterr().out
    assert json.dumps("secret-content") in output
    assert pending.request_fingerprint in output
    assert store.inspect(pending.approval_id, task).state == "approved"
