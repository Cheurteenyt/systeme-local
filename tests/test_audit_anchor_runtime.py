from __future__ import annotations

from pathlib import Path

import pytest

from systeme_local_gateway.audit import AuditIntegrityError, AuditLog
from systeme_local_gateway.audit_anchor import (
    AuditAnchorError,
    AuditAnchorIntegrityError,
    AuditAnchorNotInitializedError,
    FileAuditAnchor,
    derive_audit_log_id,
)

AUDIT_KEY = "audit-runtime-" + ("a" * 64)
ANCHOR_KEY = "anchor-runtime-" + ("b" * 64)


def _components(
    tmp_path: Path,
) -> tuple[Path, FileAuditAnchor, AuditLog]:
    log_path = tmp_path / "audit.jsonl"
    anchor = FileAuditAnchor(
        tmp_path / "audit-anchor.jsonl",
        ANCHOR_KEY,
        derive_audit_log_id(AUDIT_KEY),
    )
    return log_path, anchor, AuditLog(
        log_path,
        AUDIT_KEY,
        anchor=anchor,
    )


def test_anchor_bootstrap_is_explicit_and_append_is_coupled(
    tmp_path: Path,
) -> None:
    log_path, anchor, audit = _components(tmp_path)

    with pytest.raises(
        AuditAnchorNotInitializedError,
        match="not initialized",
    ):
        audit.verify()
    with pytest.raises(
        AuditAnchorNotInitializedError,
        match="not initialized",
    ):
        audit.append({"task_id": "blocked", "status": "completed"})
    assert not log_path.exists()

    bootstrap = audit.bootstrap_anchor()
    assert bootstrap.records == 0
    assert bootstrap.anchor_checkpoints == 1

    audit.append({"task_id": "accepted", "status": "completed"})
    verification = audit.verify()
    anchor_verification = anchor.verify()

    assert verification.records == 1
    assert verification.anchor_checkpoints == 2
    assert anchor_verification.records == 1
    assert anchor_verification.last_hmac == verification.last_hmac


def test_external_anchor_detects_audit_log_rollback(tmp_path: Path) -> None:
    log_path, _anchor, audit = _components(tmp_path)
    unanchored = AuditLog(log_path, AUDIT_KEY)
    unanchored.append({"task_id": "first", "status": "completed"})
    unanchored.append({"task_id": "second", "status": "completed"})
    audit.bootstrap_anchor()

    first_record = log_path.read_text(encoding="utf-8").splitlines()[0]
    log_path.write_text(first_record + "\n", encoding="utf-8")

    with pytest.raises(AuditIntegrityError, match="rollback"):
        audit.verify()


def test_external_anchor_detects_same_length_divergence(
    tmp_path: Path,
) -> None:
    log_path, _anchor, audit = _components(tmp_path)
    unanchored = AuditLog(log_path, AUDIT_KEY)
    unanchored.append({"task_id": "first", "status": "completed"})
    unanchored.append({"task_id": "second", "status": "completed"})
    audit.bootstrap_anchor()

    alternate_path = tmp_path / "alternate.jsonl"
    alternate = AuditLog(alternate_path, AUDIT_KEY)
    alternate.append({"task_id": "other-first", "status": "denied"})
    alternate.append({"task_id": "other-second", "status": "failed"})
    log_path.write_bytes(alternate_path.read_bytes())

    with pytest.raises(AuditIntegrityError, match="diverges"):
        audit.verify()


def test_valid_unanchored_tail_is_reconciled_after_partial_failure(
    tmp_path: Path,
) -> None:
    log_path, anchor, audit = _components(tmp_path)
    unanchored = AuditLog(log_path, AUDIT_KEY)
    unanchored.append({"task_id": "first", "status": "completed"})
    audit.bootstrap_anchor()

    unanchored.append({"task_id": "second", "status": "completed"})
    assert anchor.verify().records == 1

    verification = audit.verify()
    anchor_verification = anchor.verify()

    assert verification.records == 2
    assert verification.anchor_checkpoints == 2
    assert anchor_verification.records == 2
    assert anchor_verification.last_hmac == verification.last_hmac


def test_anchor_write_failure_leaves_recoverable_audit_tail(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    log_path, anchor, audit = _components(tmp_path)
    audit.bootstrap_anchor()

    original_append = anchor._append_checkpoint_unlocked
    failed = False

    def fail_once(
        *,
        records: int,
        last_hmac: str,
        previous_checkpoint_hmac: str,
    ) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise AuditAnchorIntegrityError(
                "simulated anchor write failure"
            )
        original_append(
            records=records,
            last_hmac=last_hmac,
            previous_checkpoint_hmac=previous_checkpoint_hmac,
        )

    monkeypatch.setattr(
        anchor,
        "_append_checkpoint_unlocked",
        fail_once,
    )

    with pytest.raises(
        AuditAnchorIntegrityError,
        match="simulated",
    ):
        audit.append({"task_id": "partial", "status": "completed"})

    assert AuditLog(log_path, AUDIT_KEY).verify().records == 1
    assert anchor.verify().records == 0

    verification = audit.verify()
    assert verification.records == 1
    assert verification.anchor_checkpoints == 2
    assert anchor.verify().records == 1


def test_bootstrap_requires_a_configured_anchor(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl", AUDIT_KEY)
    with pytest.raises(ValueError, match="not configured"):
        audit.bootstrap_anchor()


def test_anchor_transaction_cannot_be_reused_after_unlock(
    tmp_path: Path,
) -> None:
    _log_path, anchor, _audit = _components(tmp_path)

    with anchor.transaction() as transaction:
        transaction.bootstrap(0, "0" * 64)

    with pytest.raises(AuditAnchorError, match="no longer active"):
        transaction.verify()
