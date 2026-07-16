import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from systeme_local_gateway.audit import (
    AuditIntegrityError,
    AuditLockError,
    AuditLog,
    summarize_payload,
)

AUDIT_KEY = "audit-key-" + ("a" * 64)
OTHER_KEY = "audit-key-" + ("b" * 64)


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_audit_log_writes_chained_verifiable_records(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    audit = AuditLog(log_path, AUDIT_KEY)

    first_id = audit.append({"task_id": "task-12345678", "status": "completed"})
    second_id = audit.append({"task_id": "task-87654321", "status": "denied"})

    records = _records(log_path)
    verification = audit.verify()

    assert verification.records == 2
    assert records[0]["audit_id"] == first_id
    assert records[1]["audit_id"] == second_id
    assert records[0]["previous_hmac"] == "0" * 64
    assert records[1]["previous_hmac"] == records[0]["entry_hmac"]
    assert verification.last_hmac == records[1]["entry_hmac"]
    assert first_id != second_id


def test_audit_log_never_persists_raw_arguments_outputs_or_session_ids(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    audit = AuditLog(log_path, AUDIT_KEY)

    audit.append(
        {
            "task_id": "task-sensitive",
            "agent": {
                "provider": "example",
                "model": "model-1",
                "session_id": "session-secret-value",
            },
            "capability": "sandbox.run_tests",
            "status": "failed",
            "arguments": {
                "password": "hunter2",
                "command": ["python", "-c", "print('secret-command-value')"],
            },
            "output": {
                "returncode": 1,
                "stdout": "private-output-value",
                "stderr": "Bearer very-secret-token",
                "truncated": False,
                "workspace_isolated": True,
                "workspace_changes": {
                    "added": ["private-name.txt"],
                    "modified": [],
                    "deleted": [],
                    "truncated": False,
                },
            },
            "error": "password=hunter2 Bearer very-secret-token",
        }
    )

    raw_log = log_path.read_text(encoding="utf-8")
    record = _records(log_path)[0]

    for secret in (
        "hunter2",
        "session-secret-value",
        "secret-command-value",
        "private-output-value",
        "very-secret-token",
        "private-name.txt",
    ):
        assert secret not in raw_log

    assert record["agent"]["provider"] == "example"
    assert "session_id" not in record["agent"]
    assert len(record["agent"]["session_id_hmac"]) == 64
    assert "error" not in record
    assert len(record["error_summary"]["hmac_sha256"]) == 64
    assert record["arguments_summary"]["metadata"]["command_argv_items"] == 3
    output_metadata = record["output_summary"]["metadata"]
    assert output_metadata["returncode"] == 1
    assert output_metadata["workspace_isolated"] is True
    assert output_metadata["workspace_changes"]["added_count"] == 1


def test_audit_log_rejects_tampering_before_append(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    audit = AuditLog(log_path, AUDIT_KEY)
    audit.append({"task_id": "task-12345678", "status": "completed"})

    records = _records(log_path)
    records[0]["status"] = "failed"
    log_path.write_text(json.dumps(records[0]) + "\n", encoding="utf-8")

    with pytest.raises(AuditIntegrityError, match="invalid audit HMAC"):
        audit.verify()
    with pytest.raises(AuditIntegrityError, match="invalid audit HMAC"):
        audit.append({"task_id": "task-87654321", "status": "completed"})

    assert len(_records(log_path)) == 1


def test_audit_log_rejects_wrong_key_and_legacy_records(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    AuditLog(log_path, AUDIT_KEY).append(
        {"task_id": "task-12345678", "status": "completed"}
    )

    with pytest.raises(AuditIntegrityError, match="invalid audit HMAC"):
        AuditLog(log_path, OTHER_KEY).verify()

    legacy_path = tmp_path / "legacy.jsonl"
    legacy_path.write_text(
        json.dumps({"audit_id": "legacy", "sha256": "0" * 64}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(AuditIntegrityError, match="unsupported audit record version"):
        AuditLog(legacy_path, AUDIT_KEY).verify()


def test_audit_log_requires_complete_newline_terminated_records(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log_path.write_text('{"version":2}', encoding="utf-8")

    with pytest.raises(AuditIntegrityError, match="must end with a newline"):
        AuditLog(log_path, AUDIT_KEY).verify()


def test_audit_log_serializes_concurrent_process_writers(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    child_code = textwrap.dedent(
        """
        import sys
        import time
        from pathlib import Path

        from systeme_local_gateway.audit import AuditLog

        audit = AuditLog(Path(sys.argv[1]), sys.argv[2])
        original_verify = audit._verify_unlocked

        def delayed_verify():
            verification = original_verify()
            time.sleep(0.15)
            return verification

        audit._verify_unlocked = delayed_verify
        audit.append({"task_id": sys.argv[3], "status": "completed"})
        """
    )
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                child_code,
                str(log_path),
                AUDIT_KEY,
                f"concurrent-task-{index}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(6)
    ]

    for process in processes:
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 0, stderr or stdout

    verification = AuditLog(log_path, AUDIT_KEY).verify()
    assert verification.records == 6
    assert len(_records(log_path)) == 6


def test_audit_log_lock_timeout_fails_closed(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    ready_path = tmp_path / "holder-ready"
    child_code = textwrap.dedent(
        """
        import sys
        import time
        from pathlib import Path

        from systeme_local_gateway.audit import AuditLog

        audit = AuditLog(Path(sys.argv[1]), sys.argv[2])
        with audit._process_lock():
            Path(sys.argv[3]).write_text("ready", encoding="utf-8")
            time.sleep(10)
        """
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            child_code,
            str(log_path),
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
                pytest.fail(stderr or stdout or "lock holder stopped unexpectedly")
            if time.monotonic() >= deadline:
                pytest.fail("lock holder did not become ready")
            time.sleep(0.05)

        with pytest.raises(AuditLockError, match="timed out"):
            AuditLog(
                log_path,
                AUDIT_KEY,
                lock_timeout_seconds=0.1,
            ).append({"task_id": "blocked-task", "status": "completed"})
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)

    assert AuditLog(log_path, AUDIT_KEY).verify().records == 0


def test_audit_log_rejects_non_regular_lock_path(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    lock_path = tmp_path / "audit.jsonl.lock"
    lock_path.mkdir()

    with pytest.raises(AuditLockError, match="regular file"):
        AuditLog(log_path, AUDIT_KEY).verify()


def test_payload_summary_is_deterministic_and_bounded() -> None:
    key = AUDIT_KEY.encode("utf-8")
    first = summarize_payload({"b": 2, "a": 1}, key)
    second = summarize_payload({"a": 1, "b": 2}, key)

    assert first == second
    assert first["type"] == "object"
    assert first["keys"] == ["a", "b"]
    assert len(first["hmac_sha256"]) == 64
