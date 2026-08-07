from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c7_work_admission import (
    C7_POLICY_PATH,
    C7_PROFILE_PATH,
    C8LiveCycleGrant,
    canonical_sha256,
    load_policy,
    load_profile,
)
from systeme_local_gateway.c8_live_cycle import (
    C8FinalStatus,
    C8LiveCycleBundle,
    C8NegativeCheckId,
    C8NegativeOutcome,
    C8OperatorAuthorizationReceipt,
    C8TestWorkLabel,
    C8WorkCallObservation,
    C8WorkProofBundle,
    C8WorkSurfaceObservation,
    commit_final_attestation,
    commit_negative_test_receipt,
    commit_operator_authorization,
    commit_revocation_receipt,
    commit_work_correlation_receipt,
    commit_work_quota_observation,
    commit_work_surface_observation,
    commit_work_task_surface_observation,
    evaluate_c8_admission,
    issue_live_cycle_bundle,
    verify_live_cycle_bundle,
    verify_operator_authorization,
)

ROOT = Path(__file__).resolve().parents[1]
AUDIT_KEY = "c8-test-audit-key-is-longer-than-thirty-two-characters"
NOW = datetime(2026, 7, 27, 17, 0, tzinfo=UTC)
CYCLE_ID = "c8_cycle_0123456789abcdef0123456789abcdef"
GRANT_ID = "c8_fedcba9876543210fedcba9876543210"


def _profile():
    return load_profile(ROOT / C7_PROFILE_PATH)


def _policy():
    return load_policy(ROOT / C7_POLICY_PATH)


def _live_cycle() -> C8LiveCycleBundle:
    authorization = commit_operator_authorization(
        cycle_id=CYCLE_ID,
        authorized_at=NOW,
        expires_at=NOW + timedelta(hours=2),
        audit_key=AUDIT_KEY,
    )
    surface = commit_work_surface_observation(
        cycle_id=CYCLE_ID,
        observed_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=6),
        audit_key=AUDIT_KEY,
        visible_model_label=None,
        visible_reasoning_label="Très élevée",
    )
    quota = commit_work_quota_observation(
        cycle_id=CYCLE_ID,
        observed_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=6),
        audit_key=AUDIT_KEY,
    )
    return issue_live_cycle_bundle(
        authorization=authorization,
        surface_observation=surface,
        quota_observation=quota,
        profile=_profile(),
        policy=_policy(),
        grant_id=GRANT_ID,
        issued_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=20),
        audit_key=AUDIT_KEY,
    )


def _proof(
    *,
    label: C8TestWorkLabel,
    minute: int,
    suffix: str,
) -> C8WorkProofBundle:
    task_surface = commit_work_task_surface_observation(
        cycle_id=CYCLE_ID,
        grant_id=GRANT_ID,
        test_work_label=label,
        observed_at=NOW + timedelta(minutes=minute),
        expires_at=NOW + timedelta(minutes=minute + 10),
        audit_key=AUDIT_KEY,
    )
    observation = C8WorkCallObservation(
        version="1",
        source="manual_chatgpt_work",
        simulated=False,
        cycle_id=CYCLE_ID,
        grant_id=GRANT_ID,
        test_work_label=label,
        task_surface_observation_sha256=canonical_sha256(task_surface.model_dump(mode="json")),
        visible_surface="work",
        explicit_work_selected=True,
        plugin_selected=True,
        tool_name="systeme_local_connectivity_probe",
        tool_count=1,
        write_tool_count=0,
        high_risk_tool_count=0,
        positive_tool_invocation_count=1,
        challenge_sha256=suffix * 64,
        response_sha256=("b" if suffix == "a" else "c") * 64,
        server_build_commit="1" * 40,
        local_policy_sha256="2" * 64,
        tool_snapshot_sha256="3" * 64,
        audit_correlation=(
            "11111111-1111-4111-8111-111111111111"
            if suffix == "a"
            else "22222222-2222-4222-8222-222222222222"
        ),
        audit_record_sha256=("4" if suffix == "a" else "5") * 64,
        read_only=True,
        write_actions_enabled=False,
        real_evidence_access=False,
        protocol_v2_reachable=False,
        chat_invoked=False,
        automatic_chat_to_work_switch_used=False,
        existing_conversations_accessed=False,
        conversation_identifier_collected=False,
        private_browser_state_accessed=False,
        account_or_security_settings_accessed=False,
        observed_at=NOW + timedelta(minutes=minute + 1),
    )
    correlation = commit_work_correlation_receipt(
        observation=observation,
        audit_records_verified=2 if suffix == "b" else 1,
        checked_at=NOW + timedelta(minutes=minute + 2),
        audit_key=AUDIT_KEY,
    )
    return C8WorkProofBundle(
        version="1",
        task_surface_observation=task_surface,
        observation=observation,
        correlation_receipt=correlation,
    )


def _negative_outcomes() -> dict[C8NegativeCheckId, C8NegativeOutcome]:
    outcomes = {check: C8NegativeOutcome.CAPABILITY_NOT_EXPOSED for check in C8NegativeCheckId}
    for check in (
        C8NegativeCheckId.SAME_WORK_REPLAY,
        C8NegativeCheckId.CROSS_WORK_REPLAY,
        C8NegativeCheckId.UNKNOWN_FIELD,
        C8NegativeCheckId.MALFORMED_CHALLENGE,
    ):
        outcomes[check] = C8NegativeOutcome.REJECTED
    outcomes[C8NegativeCheckId.POST_REVOCATION_CALL] = (
        C8NegativeOutcome.UNREACHABLE_AFTER_REVOCATION
    )
    return outcomes


def _mutated(model: Any, **changes: Any) -> dict[str, Any]:
    value = model.model_dump(mode="json")
    value.update(changes)
    return value


def test_default_c8_state_denies_every_live_action() -> None:
    decision = evaluate_c8_admission(
        bundle=None,
        profile=_profile(),
        policy=_policy(),
        audit_key=None,
        evaluated_at=NOW,
    )

    assert decision.status is C8FinalStatus.OPERATOR_AUTHORIZATION
    assert decision.live_actions_allowed is False
    assert decision.effective_tool_count == 0
    assert decision.native_chat_gate_status == "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"
    assert decision.automatic_chat_to_work_switch_allowed is False


def test_exact_fresh_live_cycle_admits_one_work_probe() -> None:
    bundle = _live_cycle()
    decision = verify_live_cycle_bundle(
        bundle=bundle,
        root=ROOT,
        audit_key=AUDIT_KEY,
        evaluated_at=NOW + timedelta(minutes=3),
    )

    assert decision.live_actions_allowed is True
    assert decision.effective_tool_count == 1
    assert decision.cycle_id == CYCLE_ID
    assert decision.grant_id == GRANT_ID


def test_authorization_is_durable_but_bounded_and_hmac_authenticated() -> None:
    receipt = _live_cycle().authorization
    assert (
        verify_operator_authorization(
            receipt,
            audit_key=AUDIT_KEY,
            evaluated_at=NOW + timedelta(hours=1),
        )
        == receipt
    )
    with pytest.raises(ValueError, match="not active"):
        verify_operator_authorization(
            receipt,
            audit_key=AUDIT_KEY,
            evaluated_at=NOW + timedelta(hours=3),
        )
    with pytest.raises(ValueError, match="HMAC"):
        verify_operator_authorization(
            receipt,
            audit_key="wrong-audit-key-that-is-still-at-least-thirty-two",
            evaluated_at=NOW + timedelta(hours=1),
        )


def test_authorization_scope_cannot_be_weakened_or_extended() -> None:
    receipt = _live_cycle().authorization
    with pytest.raises(ValidationError):
        C8OperatorAuthorizationReceipt.model_validate(_mutated(receipt, native_chat_allowed=True))
    with pytest.raises(ValidationError):
        C8OperatorAuthorizationReceipt.model_validate(
            {**receipt.model_dump(mode="json"), "unknown_scope": True}
        )


def test_surface_observation_cannot_claim_hidden_model_identity() -> None:
    surface = _live_cycle().surface_observation
    with pytest.raises(ValidationError):
        C8WorkSurfaceObservation.model_validate(
            _mutated(
                surface,
                exact_internal_model_id_exposed=True,
                exact_internal_model_id="gpt-hidden",
            )
        )


def test_tampered_grant_or_cross_cycle_observation_fails_closed() -> None:
    bundle = _live_cycle()
    tampered_grant = _mutated(bundle.grant, authorization_hmac="0" * 64)
    tampered = C8LiveCycleBundle.model_validate(
        {
            **bundle.model_dump(mode="json"),
            "grant": tampered_grant,
        }
    )
    decision = evaluate_c8_admission(
        bundle=tampered,
        profile=_profile(),
        policy=_policy(),
        audit_key=AUDIT_KEY,
        evaluated_at=NOW + timedelta(minutes=3),
    )
    assert decision.status is C8FinalStatus.SECURITY_INVARIANT
    assert decision.live_actions_allowed is False

    with pytest.raises(ValidationError, match="different cycles"):
        C8LiveCycleBundle.model_validate(
            {
                **bundle.model_dump(mode="json"),
                "quota_observation": {
                    **bundle.quota_observation.model_dump(mode="json"),
                    "cycle_id": "c8_cycle_11111111111111111111111111111111",
                },
            }
        )


def test_stale_surface_or_quota_denies_startup() -> None:
    bundle = _live_cycle()
    decision = evaluate_c8_admission(
        bundle=bundle,
        profile=_profile(),
        policy=_policy(),
        audit_key=AUDIT_KEY,
        evaluated_at=NOW + timedelta(minutes=7),
    )
    assert decision.live_actions_allowed is False
    assert decision.status in {
        C8FinalStatus.WORK_SURFACE_AMBIGUITY,
        C8FinalStatus.WORK_QUOTA,
    }


def test_grant_schema_rejects_unknown_fields() -> None:
    grant = _live_cycle().grant
    with pytest.raises(ValidationError):
        C8LiveCycleGrant.model_validate({**grant.model_dump(mode="json"), "unexpected": True})


def test_final_attestation_requires_exactly_two_distinct_work_calls_and_revocation() -> None:
    live_cycle = _live_cycle()
    proof_a = _proof(label=C8TestWorkLabel.WORK_A, minute=3, suffix="a")
    proof_b = _proof(label=C8TestWorkLabel.WORK_B, minute=6, suffix="b")
    negative = commit_negative_test_receipt(
        cycle_id=CYCLE_ID,
        grant_id=GRANT_ID,
        outcomes=_negative_outcomes(),
        observed_at=NOW + timedelta(minutes=10),
        audit_key=AUDIT_KEY,
    )
    revocation = commit_revocation_receipt(
        cycle_id=CYCLE_ID,
        grant_id=GRANT_ID,
        verified_at=NOW + timedelta(minutes=11),
        audit_key=AUDIT_KEY,
    )

    attestation = commit_final_attestation(
        live_cycle=live_cycle,
        work_proofs=(proof_a, proof_b),
        negative_receipt=negative,
        revocation_receipt=revocation,
        audit_key=AUDIT_KEY,
        verified_at=NOW + timedelta(hours=1),
    )

    assert attestation.status == "COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"
    assert attestation.work_call_count == 2
    assert attestation.revocation_verified is True
    assert attestation.native_chat_tested is False
    assert attestation.regular_use_readiness_claimed is False
    assert attestation.exact_internal_model_id_claimed is False


def test_final_attestation_rejects_duplicate_call_and_bad_revocation_hmac() -> None:
    live_cycle = _live_cycle()
    proof_a = _proof(label=C8TestWorkLabel.WORK_A, minute=3, suffix="a")
    negative = commit_negative_test_receipt(
        cycle_id=CYCLE_ID,
        grant_id=GRANT_ID,
        outcomes=_negative_outcomes(),
        observed_at=NOW + timedelta(minutes=10),
        audit_key=AUDIT_KEY,
    )
    revocation = commit_revocation_receipt(
        cycle_id=CYCLE_ID,
        grant_id=GRANT_ID,
        verified_at=NOW + timedelta(minutes=11),
        audit_key=AUDIT_KEY,
    )
    with pytest.raises(ValueError, match="ordered Work A and Work B"):
        commit_final_attestation(
            live_cycle=live_cycle,
            work_proofs=(proof_a, proof_a),
            negative_receipt=negative,
            revocation_receipt=revocation,
            audit_key=AUDIT_KEY,
            verified_at=NOW + timedelta(minutes=12),
        )

    proof_b = _proof(label=C8TestWorkLabel.WORK_B, minute=6, suffix="b")
    bad_revocation = type(revocation).model_validate(_mutated(revocation, receipt_hmac="0" * 64))
    with pytest.raises(ValueError, match="HMAC"):
        commit_final_attestation(
            live_cycle=live_cycle,
            work_proofs=(proof_a, proof_b),
            negative_receipt=negative,
            revocation_receipt=bad_revocation,
            audit_key=AUDIT_KEY,
            verified_at=NOW + timedelta(minutes=12),
        )


def test_protocol_negatives_cannot_be_marked_unexposed() -> None:
    outcomes = _negative_outcomes()
    outcomes[C8NegativeCheckId.UNKNOWN_FIELD] = C8NegativeOutcome.NOT_SAFELY_EXPOSED
    with pytest.raises(ValidationError, match="must be rejected"):
        commit_negative_test_receipt(
            cycle_id=CYCLE_ID,
            grant_id=GRANT_ID,
            outcomes=outcomes,
            observed_at=NOW,
            audit_key=AUDIT_KEY,
        )
