from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c0_probe import C0ConnectivityProbeResponse
from systeme_local_gateway.c0_proof_check import (
    C0PendingLiveProofReceipt,
    canonical_c0_audit_record_sha256,
    canonical_c0_response_sha256,
    commit_c0_pending_live_proof_receipt,
    verify_c0_pending_live_proof_receipt,
)

CREATED_AT = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
CHECKED_AT = CREATED_AT + timedelta(minutes=5)
AUDIT_KEY = "audit-key-that-is-long-enough-for-c0-tests"
AUDIT_ID = "12345678-1234-4123-8123-123456789abc"


def _response() -> C0ConnectivityProbeResponse:
    return C0ConnectivityProbeResponse(
        probe_protocol_version="c0.v1",
        challenge_sha256="a" * 64,
        server_build_commit="b" * 40,
        local_policy_sha256="c" * 64,
        tool_snapshot_sha256="d" * 64,
        read_only=True,
        write_actions_enabled=False,
        real_evidence_access=False,
        protocol_v2_reachable=False,
        audit_correlation=AUDIT_ID,
        observed_at=CREATED_AT + timedelta(minutes=1),
    )


def _audit_record() -> dict[str, object]:
    return {
        "version": 2,
        "audit_id": AUDIT_ID,
        "timestamp": (CREATED_AT + timedelta(minutes=1)).isoformat(),
        "previous_hmac": "0" * 64,
        "capability": "systeme_local_connectivity_probe",
        "status": "completed",
        "agent": {"provider": "mcp"},
        "entry_hmac": "e" * 64,
    }


def _receipt() -> C0PendingLiveProofReceipt:
    return commit_c0_pending_live_proof_receipt(
        audit_key=AUDIT_KEY,
        challenge_created_at=CREATED_AT,
        checked_at=CHECKED_AT,
        challenge_sha256="a" * 64,
        response=_response(),
        audit_record=_audit_record(),
        audit_records_verified=1,
    )


def test_pending_receipt_is_authenticated_and_never_claims_live_success() -> None:
    receipt = verify_c0_pending_live_proof_receipt(_receipt(), audit_key=AUDIT_KEY)

    assert receipt.status == "live_call_correlated_pending_revocation"
    assert receipt.real_connection_established is False
    assert receipt.response_sha256 == canonical_c0_response_sha256(_response())
    assert receipt.audit_record_sha256 == canonical_c0_audit_record_sha256(_audit_record())
    assert len(receipt.receipt_hmac) == 64


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("challenge_sha256", "f" * 64),
        ("response_sha256", "f" * 64),
        ("audit_record_sha256", "f" * 64),
        ("audit_records_verified", 2),
        ("local_policy_sha256", "f" * 64),
        ("tool_snapshot_sha256", "f" * 64),
    ],
)
def test_pending_receipt_rejects_any_authenticated_field_drift(
    field: str,
    value: object,
) -> None:
    tampered = _receipt().model_copy(update={field: value})

    with pytest.raises(ValueError, match="HMAC mismatch"):
        verify_c0_pending_live_proof_receipt(tampered, audit_key=AUDIT_KEY)


def test_pending_receipt_rejects_wrong_key_stale_challenge_and_extra_fields() -> None:
    with pytest.raises(ValueError, match="HMAC mismatch"):
        verify_c0_pending_live_proof_receipt(
            _receipt(),
            audit_key="another-independent-audit-key-for-tests",
        )

    with pytest.raises(ValidationError, match="challenge is stale"):
        commit_c0_pending_live_proof_receipt(
            audit_key=AUDIT_KEY,
            challenge_created_at=CREATED_AT,
            checked_at=CREATED_AT + timedelta(minutes=31),
            challenge_sha256="a" * 64,
            response=_response(),
            audit_record=_audit_record(),
            audit_records_verified=1,
        )

    values = _receipt().model_dump(mode="json")
    values["unexpected"] = True
    with pytest.raises(ValidationError):
        C0PendingLiveProofReceipt.model_validate(values)
