from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from systeme_local_gateway.audit_anchor import (
    AuditAnchorIntegrityError,
    AuditAnchorLockError,
    AuditAnchorNotInitializedError,
    FileAuditAnchor,
    derive_audit_log_id,
)

AUDIT_KEY = "audit-" + ("a" * 64)
ANCHOR_KEY = "anchor-" + ("b" * 64)
OTHER_KEY = "anchor-" + ("c" * 64)
GENESIS = "0" * 64


def _anchor(
    path: Path,
    *,
    key: str = ANCHOR_KEY,
    lock_timeout_seconds: float = 5.0,
) -> FileAuditAnchor:
    return FileAuditAnchor(
        path,
        key,
        derive_audit_log_id(AUDIT_KEY),
        lock_timeout_seconds=lock_timeout_seconds,
    )


def test_bootstrap_is_explicit_and_does_not_persist_the_key(
    tmp_path: Path,
) -> None:
    path = tmp_path / "anchor.jsonl"
    anchor = _anchor(path)

    with pytest.raises(
        AuditAnchorNotInitializedError,
        match="not initialized",
    ):
        anchor.verify()

    verification = anchor.bootstrap(0, GENESIS)
    assert verification.checkpoints == 1
    assert verification.records == 0
    assert path.read_bytes().endswith(b"\n")
    assert ANCHOR_KEY.encode() not in path.read_bytes()
    assert anchor.lock_path.read_bytes() == b"\0"


def test_checkpoints_are_monotonic_and_chained(tmp_path: Path) -> None:
    path = tmp_path / "anchor.jsonl"
    anchor = _anchor(path)
    first = anchor.bootstrap(0, GENESIS)
    second = anchor.append(3, "1" * 64)

    assert first.checkpoints == 1
    assert second.checkpoints == 2
    assert second.records == 3
    records = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert (
        records[1]["previous_checkpoint_hmac"]
        == records[0]["checkpoint_hmac"]
    )

    with pytest.raises(
        AuditAnchorIntegrityError,
        match="must increase",
    ):
        anchor.append(3, "2" * 64)


def test_wrong_key_and_tampering_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "anchor.jsonl"
    anchor = _anchor(path)
    anchor.bootstrap(0, GENESIS)

    with pytest.raises(
        AuditAnchorIntegrityError,
        match="checkpoint HMAC",
    ):
        _anchor(path, key=OTHER_KEY).verify()

    checkpoint = json.loads(path.read_text(encoding="utf-8"))
    checkpoint["records"] = 4
    path.write_text(json.dumps(checkpoint) + "\n", encoding="utf-8")
    with pytest.raises(
        AuditAnchorIntegrityError,
        match="checkpoint HMAC",
    ):
        anchor.verify()


def test_truncation_and_schema_changes_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "anchor.jsonl"
    anchor = _anchor(path)
    anchor.bootstrap(0, GENESIS)

    raw = path.read_text(encoding="utf-8")
    path.write_text(raw.rstrip("\n"), encoding="utf-8")
    with pytest.raises(AuditAnchorIntegrityError, match="newline"):
        anchor.verify()

    checkpoint = json.loads(raw)
    checkpoint["unexpected"] = True
    path.write_text(json.dumps(checkpoint) + "\n", encoding="utf-8")
    with pytest.raises(AuditAnchorIntegrityError, match="schema"):
        anchor.verify()


def test_wrong_audit_log_identity_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "anchor.jsonl"
    _anchor(path).bootstrap(0, GENESIS)

    other_log_id = derive_audit_log_id("other-audit-" + ("d" * 64))
    with pytest.raises(AuditAnchorIntegrityError, match="audit log ID"):
        FileAuditAnchor(path, ANCHOR_KEY, other_log_id).verify()


def test_non_regular_anchor_and_lock_paths_are_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "anchor.jsonl"
    path.mkdir()
    with pytest.raises(AuditAnchorIntegrityError, match="regular file"):
        _anchor(path).verify()

    other_path = tmp_path / "other-anchor.jsonl"
    anchor = _anchor(other_path)
    anchor.lock_path.mkdir()
    with pytest.raises(AuditAnchorLockError, match="regular file"):
        anchor.verify()


def test_invalid_initial_state_is_rejected(tmp_path: Path) -> None:
    anchor = _anchor(tmp_path / "anchor.jsonl")
    with pytest.raises(ValueError, match="genesis"):
        anchor.bootstrap(0, "1" * 64)
    with pytest.raises(ValueError, match="non-negative"):
        anchor.bootstrap(-1, GENESIS)


def test_lock_timeout_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "anchor.jsonl"
    ready_path = tmp_path / "ready"
    child_code = textwrap.dedent(
        """
        import sys
        import time
        from pathlib import Path

        from systeme_local_gateway.audit_anchor import (
            FileAuditAnchor,
            derive_audit_log_id,
        )

        anchor = FileAuditAnchor(
            Path(sys.argv[1]),
            sys.argv[2],
            derive_audit_log_id(sys.argv[3]),
        )
        with anchor._process_lock():
            Path(sys.argv[4]).write_text("ready", encoding="utf-8")
            time.sleep(10)
        """
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            child_code,
            str(path),
            ANCHOR_KEY,
            AUDIT_KEY,
            str(ready_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        deadline = time.monotonic() + 10
        while not ready_path.exists():
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                pytest.fail(
                    stderr or stdout or "lock holder stopped unexpectedly"
                )
            if time.monotonic() >= deadline:
                pytest.fail("lock holder did not become ready")
            time.sleep(0.05)

        with pytest.raises(AuditAnchorLockError, match="timed out"):
            _anchor(
                path,
                lock_timeout_seconds=0.1,
            ).verify()
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


def test_concurrent_bootstrap_creates_one_valid_checkpoint(
    tmp_path: Path,
) -> None:
    path = tmp_path / "anchor.jsonl"
    child_code = textwrap.dedent(
        """
        import sys
        from pathlib import Path

        from systeme_local_gateway.audit_anchor import (
            AuditAnchorIntegrityError,
            FileAuditAnchor,
            derive_audit_log_id,
        )

        anchor = FileAuditAnchor(
            Path(sys.argv[1]),
            sys.argv[2],
            derive_audit_log_id(sys.argv[3]),
        )
        try:
            anchor.bootstrap(0, "0" * 64)
        except AuditAnchorIntegrityError:
            print("already-initialized")
        else:
            print("initialized")
        """
    )
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                child_code,
                str(path),
                ANCHOR_KEY,
                AUDIT_KEY,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(5)
    ]

    outcomes = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 0, stderr or stdout
        outcomes.append(stdout.strip())

    assert outcomes.count("initialized") == 1
    assert outcomes.count("already-initialized") == 4
    verification = _anchor(path).verify()
    assert verification.checkpoints == 1
    assert verification.records == 0
