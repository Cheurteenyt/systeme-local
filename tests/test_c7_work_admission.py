from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c7_work_admission import (
    C7_MAX_LIVE_CYCLE_SECONDS,
    C7_POLICY_PATH,
    C7_PROFILE_PATH,
    C7FinalStatus,
    C7ProtectedAction,
    C7ReasonCode,
    C7WorkPrelivePolicy,
    C8LiveCycleGrant,
    ChatGptWorkCapabilityProfile,
    WorkEvidenceLifecycle,
    build_current_c7_policy,
    build_current_c7_profile,
    canonical_json,
    canonical_sha256,
    committed_status,
    current_work_identity,
    evaluate_c7_prelive,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 27, 16, 0, tzinfo=timezone.utc)
AUDIT_KEY = b"c7-test-audit-key-is-at-least-thirty-two-bytes"


def _json(path: str) -> dict[str, Any]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def _mutated(model: Any, **changes: Any) -> dict[str, Any]:
    payload = model.model_dump(mode="json")
    payload.update(changes)
    return payload


def _grant(
    *,
    profile: ChatGptWorkCapabilityProfile,
    policy: C7WorkPrelivePolicy,
    audit_key: bytes = AUDIT_KEY,
    authorized_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=10),
    profile_sha256: str | None = None,
    policy_sha256: str | None = None,
) -> C8LiveCycleGrant:
    payload: dict[str, Any] = {
        "version": "1",
        "grant_id": "c8_0123456789abcdef0123456789abcdef",
        "identity": current_work_identity().model_dump(mode="json"),
        "policy_sha256": policy_sha256 or policy.policy_sha256,
        "profile_sha256": profile_sha256 or profile.profile_sha256,
        "authorized_at": authorized_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "operator_authorized": True,
        "explicit_work_request": True,
        "work_only": True,
        "visible_surface": "work",
        "work_entitlement_state": "available",
        "work_quota_state": "usable",
        "surface_observed_at": (authorized_at - timedelta(minutes=1))
        .isoformat()
        .replace("+00:00", "Z"),
        "quota_observed_at": (authorized_at - timedelta(minutes=1))
        .isoformat()
        .replace("+00:00", "Z"),
        "surface_observation_sha256": "2" * 64,
        "quota_observation_sha256": "3" * 64,
        "visible_model_observation_sha256": None,
        "exact_internal_model_id_exposed": False,
        "max_new_synthetic_work_chats": 2,
        "allowed_actions": [
            action.value for action in sorted(C7ProtectedAction, key=lambda item: item.value)
        ],
        "existing_chats_allowed": False,
        "history_allowed": False,
        "private_browser_state_allowed": False,
        "account_or_security_settings_allowed": False,
        "write_actions_allowed": False,
        "raw_secrets_allowed": False,
        "real_evidence_access_allowed": False,
        "protocol_v2_allowed": False,
    }
    grant_sha256 = canonical_sha256(payload)
    hmac_payload = {**payload, "grant_sha256": grant_sha256}
    authorization_hmac = hmac.new(
        audit_key,
        canonical_json(hmac_payload),
        hashlib.sha256,
    ).hexdigest()
    return C8LiveCycleGrant(
        **payload,
        grant_sha256=grant_sha256,
        authorization_hmac=authorization_hmac,
    )


def test_committed_profile_is_exact_generated_profile() -> None:
    committed = ChatGptWorkCapabilityProfile.model_validate(_json(C7_PROFILE_PATH))
    assert committed == build_current_c7_profile()
    assert committed.identity.native_surface == "work"
    assert committed.identity.surface_class == "agentic_work"
    assert committed.support_state.value == "supported"
    assert len(committed.sources) == 6


def test_committed_policy_is_exact_generated_policy() -> None:
    committed = C7WorkPrelivePolicy.model_validate(_json(C7_POLICY_PATH))
    assert committed == build_current_c7_policy(ROOT)
    assert committed.native_chat_gate_status == "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"
    assert committed.default_boundary.live_actions_allowed is False
    assert committed.default_boundary.effective_tool_count == 0
    assert committed.default_boundary.automatic_chat_to_work_switch_allowed is False


def test_default_committed_status_is_ready_but_denies_every_effect() -> None:
    decision = committed_status(ROOT, NOW)
    assert decision.final_status is C7FinalStatus.READY
    assert decision.reason_code is C7ReasonCode.PRELIVE_READY_GRANT_REQUIRED
    assert decision.lifecycle_state is WorkEvidenceLifecycle.CURRENT
    assert decision.operator_live_cycle_grant_present is False
    assert decision.operator_live_cycle_grant_verified is False
    assert decision.live_actions_allowed is False
    assert decision.effective_tools == ()
    assert len(decision.action_decisions) == 6
    assert not any(item.allowed for item in decision.action_decisions)


def test_work_profile_does_not_modify_native_chat_result() -> None:
    decision = committed_status(ROOT, NOW)
    assert decision.identity.native_surface == "work"
    assert decision.native_chat_gate_status == "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"
    assert decision.automatic_chat_to_work_switch_allowed is False


def test_valid_future_grant_admits_only_exact_probe() -> None:
    profile = build_current_c7_profile()
    policy = build_current_c7_policy(ROOT)
    grant = _grant(profile=profile, policy=policy)
    decision = evaluate_c7_prelive(
        profile=profile,
        policy=policy,
        evaluated_at=NOW,
        grant=grant,
        audit_key=AUDIT_KEY,
    )
    assert decision.final_status is C7FinalStatus.READY
    assert decision.reason_code is C7ReasonCode.LIVE_CYCLE_GRANT_VERIFIED
    assert decision.operator_live_cycle_grant_present is True
    assert decision.operator_live_cycle_grant_verified is True
    assert decision.live_actions_allowed is True
    assert all(item.allowed for item in decision.action_decisions)
    assert tuple(tool.name for tool in decision.effective_tools) == (
        "systeme_local_connectivity_probe",
    )
    assert decision.effective_tools[0].read_only is True
    assert decision.effective_tools[0].real_evidence_access is False
    assert decision.effective_tools[0].protocol_v2_reachable is False


@pytest.mark.parametrize("audit_key", [None, b"short", b"x" * 32])
def test_missing_short_or_wrong_hmac_key_denies_future_grant(
    audit_key: bytes | None,
) -> None:
    profile = build_current_c7_profile()
    policy = build_current_c7_policy(ROOT)
    grant = _grant(profile=profile, policy=policy)
    decision = evaluate_c7_prelive(
        profile=profile,
        policy=policy,
        evaluated_at=NOW,
        grant=grant,
        audit_key=audit_key,
    )
    assert decision.final_status is C7FinalStatus.SECURITY_INVARIANT
    assert decision.reason_code is C7ReasonCode.LIVE_CYCLE_GRANT_INVALID
    assert decision.live_actions_allowed is False
    assert decision.effective_tools == ()


def test_expired_future_grant_denies_all_actions() -> None:
    profile = build_current_c7_profile()
    policy = build_current_c7_policy(ROOT)
    grant = _grant(
        profile=profile,
        policy=policy,
        authorized_at=NOW - timedelta(minutes=15),
        expires_at=NOW - timedelta(seconds=1),
    )
    decision = evaluate_c7_prelive(
        profile=profile,
        policy=policy,
        evaluated_at=NOW,
        grant=grant,
        audit_key=AUDIT_KEY,
    )
    assert decision.final_status is C7FinalStatus.SECURITY_INVARIANT
    assert decision.live_actions_allowed is False
    assert not any(item.allowed for item in decision.action_decisions)


def test_cross_profile_or_policy_grant_is_rejected() -> None:
    profile = build_current_c7_profile()
    policy = build_current_c7_policy(ROOT)
    grant = _grant(
        profile=profile,
        policy=policy,
        profile_sha256="0" * 64,
        policy_sha256="1" * 64,
    )
    decision = evaluate_c7_prelive(
        profile=profile,
        policy=policy,
        evaluated_at=NOW,
        grant=grant,
        audit_key=AUDIT_KEY,
    )
    assert decision.final_status is C7FinalStatus.SECURITY_INVARIANT
    assert decision.effective_tools == ()


def test_grant_lifetime_is_strictly_bounded() -> None:
    profile = build_current_c7_profile()
    policy = build_current_c7_policy(ROOT)
    with pytest.raises(ValidationError, match="lifetime exceeds"):
        _grant(
            profile=profile,
            policy=policy,
            authorized_at=NOW,
            expires_at=NOW + timedelta(seconds=C7_MAX_LIVE_CYCLE_SECONDS + 1),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("existing_chats_allowed", True),
        ("history_allowed", True),
        ("private_browser_state_allowed", True),
        ("account_or_security_settings_allowed", True),
        ("write_actions_allowed", True),
        ("raw_secrets_allowed", True),
        ("real_evidence_access_allowed", True),
        ("protocol_v2_allowed", True),
        ("explicit_work_request", False),
        ("work_only", False),
        ("visible_surface", "chat"),
        ("work_entitlement_state", "unknown"),
        ("work_quota_state", "unknown"),
        ("exact_internal_model_id_exposed", True),
        ("max_new_synthetic_work_chats", 3),
    ],
)
def test_future_grant_cannot_expand_privacy_or_capability(
    field: str,
    value: Any,
) -> None:
    profile = build_current_c7_profile()
    policy = build_current_c7_policy(ROOT)
    grant = _grant(profile=profile, policy=policy)
    with pytest.raises(ValidationError):
        C8LiveCycleGrant.model_validate(_mutated(grant, **{field: value}))


def test_future_grant_cannot_drop_or_duplicate_actions() -> None:
    profile = build_current_c7_profile()
    policy = build_current_c7_policy(ROOT)
    grant = _grant(profile=profile, policy=policy)
    dropped = _mutated(grant, allowed_actions=["browser_test"])
    with pytest.raises(ValidationError, match="complete bounded action"):
        C8LiveCycleGrant.model_validate(dropped)


def test_future_grant_requires_fresh_surface_and_quota_observations() -> None:
    profile = build_current_c7_profile()
    policy = build_current_c7_policy(ROOT)
    grant = _grant(profile=profile, policy=policy)
    for field in ("surface_observed_at", "quota_observed_at"):
        payload = grant.model_dump(mode="json")
        payload[field] = (
            (grant.authorized_at - timedelta(minutes=6)).isoformat().replace("+00:00", "Z")
        )
        payload["grant_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in payload.items()
                if key not in {"grant_sha256", "authorization_hmac"}
            }
        )
        with pytest.raises(ValidationError, match="stale at authorization"):
            C8LiveCycleGrant.model_validate(payload)


def test_unknown_fields_fail_closed() -> None:
    profile = build_current_c7_profile()
    policy = build_current_c7_policy(ROOT)
    grant = _grant(profile=profile, policy=policy)
    with pytest.raises(ValidationError):
        ChatGptWorkCapabilityProfile.model_validate(
            {**profile.model_dump(mode="json"), "unknown": True}
        )
    with pytest.raises(ValidationError):
        C7WorkPrelivePolicy.model_validate({**policy.model_dump(mode="json"), "unknown": True})
    with pytest.raises(ValidationError):
        C8LiveCycleGrant.model_validate({**grant.model_dump(mode="json"), "unknown": True})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_id", "other"),
        ("native_surface", "chat"),
        ("surface_class", "conversational_chat"),
        ("capability", "different_capability"),
    ],
)
def test_work_identity_substitution_is_impossible(field: str, value: str) -> None:
    payload = current_work_identity().model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValidationError):
        type(current_work_identity()).model_validate(payload)


def test_tampered_profile_claim_or_digest_is_rejected() -> None:
    profile = build_current_c7_profile()
    payload = profile.model_dump(mode="json")
    payload["sources"][0]["canonical_claim"] += " altered"
    with pytest.raises(ValidationError, match="claim digest mismatch"):
        ChatGptWorkCapabilityProfile.model_validate(payload)

    payload = profile.model_dump(mode="json")
    payload["profile_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="profile digest mismatch"):
        ChatGptWorkCapabilityProfile.model_validate(payload)


def test_tampered_policy_dependency_or_digest_is_rejected() -> None:
    policy = build_current_c7_policy(ROOT)
    payload = policy.model_dump(mode="json")
    payload["native_chat_profile"]["sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="policy digest mismatch"):
        C7WorkPrelivePolicy.model_validate(payload)

    payload = policy.model_dump(mode="json")
    payload["native_chat_profile"]["path"] = C7_PROFILE_PATH
    payload["policy_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "policy_sha256"}
    )
    with pytest.raises(ValidationError, match="unexpected Chat profile"):
        C7WorkPrelivePolicy.model_validate(payload)


def test_revalidation_due_and_expired_profiles_block_every_action() -> None:
    profile = build_current_c7_profile()
    policy = build_current_c7_policy(ROOT)
    for instant, lifecycle in (
        (
            datetime(2026, 8, 14, 15, 42, tzinfo=timezone.utc),
            WorkEvidenceLifecycle.REVALIDATION_DUE,
        ),
        (datetime(2026, 8, 21, 15, 42, tzinfo=timezone.utc), WorkEvidenceLifecycle.EXPIRED),
    ):
        decision = evaluate_c7_prelive(
            profile=profile,
            policy=policy,
            evaluated_at=instant,
        )
        assert decision.final_status is C7FinalStatus.OFFICIAL_WORK_EVIDENCE
        assert decision.lifecycle_state is lifecycle
        assert decision.live_actions_allowed is False
        assert decision.effective_tools == ()


def test_cli_status_and_c8_gates_are_bounded_and_secret_free() -> None:
    env = {"PYTHONPATH": str(ROOT / "src")}
    status = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c7_work_admission",
            "status",
            "--as-of",
            "2026-07-27T16:00:00Z",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert status.returncode == 0
    status_payload = json.loads(status.stdout)
    assert status_payload["live_actions_allowed"] is False
    assert status_payload["effective_tools"] == []

    gates = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c7_work_admission",
            "show-c8-gates",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert gates.returncode == 0
    gates_payload = json.loads(gates.stdout)
    assert gates_payload["required_surface"] == "work"
    assert gates_payload["max_new_synthetic_work_chats"] == 2
    assert "existing_chats" in gates_payload["forbidden"]
    assert "sk-" not in gates.stdout.lower()
    assert "tunnel_" not in gates.stdout.lower()
