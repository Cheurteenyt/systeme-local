from __future__ import annotations

import base64
import hashlib
import hmac
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systeme_local_gateway.auth import (
    ReplayGuardUnavailableError,
    SQLiteReplayGuard,
    canonical_payload,
    verify_task,
)
from systeme_local_gateway.models import AgentIdentity, TaskEnvelope


SECRET = "s" * 48


def _signed_task(nonce: str, now: datetime) -> TaskEnvelope:
    task = TaskEnvelope(
        task_id="persistent-task-12345678",
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
        agent=AgentIdentity(provider="test", session_id="session"),
        capability="workspace.list",
        arguments={"path": "."},
        nonce=nonce,
        signature="placeholder-signature-that-is-long-enough-123456",
    )
    digest = hmac.new(SECRET.encode(), canonical_payload(task), hashlib.sha256).digest()
    task.signature = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return task


def test_replay_is_rejected_after_guard_restart(tmp_path: Path) -> None:
    database = tmp_path / "replay.sqlite3"
    now = datetime.now(UTC)
    task = _signed_task("persistent-nonce-" + "n" * 16, now)

    first_guard = SQLiteReplayGuard(database, SECRET, max_entries=10)
    verify_task(task, SECRET, replay_guard=first_guard)

    restarted_guard = SQLiteReplayGuard(database, SECRET, max_entries=10)
    with pytest.raises(ValueError, match="replayed"):
        verify_task(task, SECRET, replay_guard=restarted_guard)

    restarted_guard.verify()
    assert task.nonce.encode("utf-8") not in database.read_bytes()


def test_invalid_signature_does_not_consume_nonce(tmp_path: Path) -> None:
    database = tmp_path / "replay.sqlite3"
    now = datetime.now(UTC)
    task = _signed_task("invalid-signature-" + "n" * 16, now)
    valid_signature = task.signature
    task.signature = "z" * len(task.signature)

    guard = SQLiteReplayGuard(database, SECRET, max_entries=10)
    with pytest.raises(ValueError, match="signature"):
        verify_task(task, SECRET, replay_guard=guard)

    task.signature = valid_signature
    verify_task(task, SECRET, replay_guard=guard)


def test_expired_entries_are_pruned_before_capacity_check(tmp_path: Path) -> None:
    database = tmp_path / "replay.sqlite3"
    clock_value = [datetime(2026, 1, 1, tzinfo=UTC)]
    guard = SQLiteReplayGuard(
        database,
        SECRET,
        max_entries=1,
        clock=lambda: clock_value[0],
    )

    guard.check_and_mark("first-" + "n" * 16, clock_value[0] + timedelta(seconds=1))
    clock_value[0] += timedelta(seconds=2)
    guard.check_and_mark("second-" + "n" * 16, clock_value[0] + timedelta(seconds=30))

    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT nonce_hmac, expires_at_us FROM seen_nonces"
        ).fetchall()
    assert len(rows) == 1


def test_capacity_exhaustion_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "replay.sqlite3"
    now = datetime(2026, 1, 1, tzinfo=UTC)
    guard = SQLiteReplayGuard(
        database,
        SECRET,
        max_entries=1,
        clock=lambda: now,
    )

    guard.check_and_mark("first-" + "n" * 16, now + timedelta(minutes=1))
    with pytest.raises(ReplayGuardUnavailableError, match="capacity"):
        guard.check_and_mark("second-" + "n" * 16, now + timedelta(minutes=1))


def test_concurrent_duplicate_is_accepted_only_once(tmp_path: Path) -> None:
    database = tmp_path / "replay.sqlite3"
    now = datetime(2026, 1, 1, tzinfo=UTC)
    barrier = threading.Barrier(2)

    def attempt() -> str:
        guard = SQLiteReplayGuard(
            database,
            SECRET,
            max_entries=10,
            clock=lambda: now,
        )
        barrier.wait(timeout=5)
        try:
            guard.check_and_mark(
                "concurrent-" + "n" * 16,
                now + timedelta(minutes=1),
            )
        except ValueError:
            return "replayed"
        return "accepted"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))

    assert sorted(outcomes) == ["accepted", "replayed"]


def test_corrupt_database_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "replay.sqlite3"
    database.write_bytes(b"not a sqlite database")

    with pytest.raises(ReplayGuardUnavailableError, match="unavailable"):
        SQLiteReplayGuard(database, SECRET, max_entries=10)
