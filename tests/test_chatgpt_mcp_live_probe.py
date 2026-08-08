from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c0_probe import C0ConnectivityProbeResponse
from systeme_local_gateway.c0_proof_check import (
    C0PendingLiveProofReceipt,
    commit_c0_pending_live_proof_receipt,
)
from systeme_local_gateway.providers import (
    ChatGptClientSurface,
    ChatGptPlan,
    ChatGptWorkspaceRole,
    McpAccessMode,
    McpAuthenticationKind,
    McpDeploymentPhase,
    McpDeploymentRequest,
    McpReadinessCheckId,
    McpReadinessCheckState,
    McpServerLocation,
    RefreshTokenCapability,
    build_current_chatgpt_mcp_capability_profile,
    build_current_chatgpt_mcp_evidence_reconciliation_profile,
    commit_mcp_connection_readiness_observation,
    commit_mcp_readiness_check,
)
from systeme_local_gateway.providers.chatgpt_mcp_live_probe import (
    ChatGptMcpLiveProbeAttestation,
    commit_chatgpt_mcp_live_probe_attestation,
    validate_chatgpt_mcp_live_probe_attestation_time_window,
)

STARTED = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
VERIFIED = STARTED + timedelta(minutes=5)
POLICY_SHA256 = "a" * 64
TOOL_SHA256 = "b" * 64
CHALLENGE_SHA256 = "c" * 64
AUDIT_ID = "12345678-1234-4123-8123-123456789abc"
AUDIT_KEY = "independent-audit-key-for-live-probe-negative-tests"


def _observation(
    *,
    tool_count: int = 1,
    write_tool_count: int = 0,
    high_risk_tool_count: int = 0,
    unknown_check: McpReadinessCheckId | None = None,
):
    capability = build_current_chatgpt_mcp_capability_profile()
    reconciliation = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    request = McpDeploymentRequest(
        request_id="req_c0_live",
        plan=ChatGptPlan.PRO,
        role=ChatGptWorkspaceRole.MEMBER,
        client=ChatGptClientSurface.WEB,
        phase=McpDeploymentPhase.TEST,
        access_mode=McpAccessMode.READ_FETCH,
        server_location=McpServerLocation.DEVELOPER_MACHINE,
        authentication=McpAuthenticationKind.NONE,
        persistent_connectivity_required=False,
        refresh_token_capability=RefreshTokenCapability.NOT_APPLICABLE,
        developer_mode_enabled=True,
        app_configured=True,
        workspace_app_access_granted=True,
        requested_at=STARTED,
    )
    checks = []
    for check_id in McpReadinessCheckId:
        if check_id is unknown_check:
            state = McpReadinessCheckState.UNKNOWN
            evidence = None
        elif check_id is McpReadinessCheckId.REFRESH_TOKEN:
            state = McpReadinessCheckState.NOT_APPLICABLE
            evidence = None
        else:
            state = McpReadinessCheckState.VERIFIED
            evidence = sha256(check_id.value.encode("ascii")).hexdigest()
        checks.append(
            commit_mcp_readiness_check(
                check_id=check_id,
                state=state,
                checked_at=STARTED,
                evidence_sha256=evidence,
            )
        )
    observation = commit_mcp_connection_readiness_observation(
        observation_id="obs_c0_live",
        request=request,
        capability_profile_sha256=capability.profile_sha256,
        reconciliation_profile_sha256=reconciliation.profile_sha256,
        checks=tuple(checks),
        tool_snapshot_sha256=TOOL_SHA256,
        tool_count=tool_count,
        write_tool_count=write_tool_count,
        high_risk_tool_count=high_risk_tool_count,
        local_policy_sha256=POLICY_SHA256,
        observed_at=STARTED,
    )
    return capability, observation


def _response() -> C0ConnectivityProbeResponse:
    return C0ConnectivityProbeResponse(
        probe_protocol_version="c0.v1",
        challenge_sha256=CHALLENGE_SHA256,
        server_build_commit="d" * 40,
        local_policy_sha256=POLICY_SHA256,
        tool_snapshot_sha256=TOOL_SHA256,
        read_only=True,
        write_actions_enabled=False,
        real_evidence_access=False,
        protocol_v2_reachable=False,
        audit_correlation=AUDIT_ID,
        observed_at=STARTED + timedelta(minutes=1),
    )


def _audit_record() -> dict[str, object]:
    return {
        "version": 2,
        "audit_id": AUDIT_ID,
        "timestamp": (STARTED + timedelta(minutes=1)).isoformat(),
        "previous_hmac": "0" * 64,
        "capability": "systeme_local_connectivity_probe",
        "status": "completed",
        "agent": {"provider": "mcp"},
        "entry_hmac": "e" * 64,
    }


def _pending_receipt(
    response: C0ConnectivityProbeResponse,
    audit_record: dict[str, object],
) -> C0PendingLiveProofReceipt:
    return commit_c0_pending_live_proof_receipt(
        audit_key=AUDIT_KEY,
        challenge_created_at=STARTED - timedelta(minutes=1),
        checked_at=STARTED + timedelta(minutes=2),
        challenge_sha256=response.challenge_sha256,
        response=response,
        audit_record=audit_record,
        audit_records_verified=1,
    )


def _commit_fails(
    *,
    capability=None,
    reconciliation=None,
    observation=None,
    response=None,
    audit_record=None,
    pending_live_proof=None,
    pending_proof_audit_key: str = AUDIT_KEY,
    chatgpt_snapshot: str = TOOL_SHA256,
    expected_challenge: str = CHALLENGE_SHA256,
    revocation_verified: bool = True,
    audit_chain_verified: bool = True,
    expires_at: datetime = VERIFIED + timedelta(hours=1),
) -> None:
    default_capability, default_observation = _observation()
    default_reconciliation = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    selected_response = response or _response()
    selected_audit_record = audit_record or _audit_record()
    selected_pending = pending_live_proof or _pending_receipt(
        selected_response,
        selected_audit_record,
    )
    commit_chatgpt_mcp_live_probe_attestation(
        capability_profile=capability or default_capability,
        reconciliation_profile=reconciliation or default_reconciliation,
        readiness_observation=observation or default_observation,
        response=selected_response,
        audit_record=selected_audit_record,
        pending_live_proof=selected_pending,
        pending_proof_audit_key=pending_proof_audit_key,
        app_configuration_evidence_sha256="f" * 64,
        chatgpt_tool_snapshot_sha256=chatgpt_snapshot,
        revocation_evidence_sha256="1" * 64,
        expected_challenge_sha256=expected_challenge,
        started_at=STARTED,
        verified_at=VERIFIED,
        expires_at=expires_at,
        revocation_verified=revocation_verified,
        audit_chain_verified=audit_chain_verified,
    )


def test_live_attestation_schema_cannot_express_simulated_or_false_live_state() -> None:
    schema = ChatGptMcpLiveProbeAttestation.model_json_schema()

    assert schema["properties"]["source"]["const"] == "manual_chatgpt_web"
    assert schema["properties"]["simulated"]["const"] is False
    assert schema["properties"]["invocation_origin"]["const"] == "chatgpt_web_draft_plugin"
    assert schema["properties"]["audit_chain_verified"]["const"] is True
    assert schema["properties"]["revocation_verified"]["const"] is True
    assert schema["properties"]["real_connection_established"]["const"] is True


def test_revocation_is_a_hard_gate() -> None:
    with pytest.raises(ValueError, match="revocation"):
        _commit_fails(revocation_verified=False)


def test_audit_chain_verification_is_a_hard_gate() -> None:
    with pytest.raises(ValueError, match="audit chain"):
        _commit_fails(audit_chain_verified=False)


def test_authenticated_pending_live_proof_is_a_hard_gate() -> None:
    response = _response()
    audit_record = _audit_record()
    tampered = _pending_receipt(response, audit_record).model_copy(
        update={"response_sha256": "9" * 64}
    )

    with pytest.raises(ValueError, match="HMAC mismatch"):
        _commit_fails(
            response=response,
            audit_record=audit_record,
            pending_live_proof=tampered,
        )


def test_unknown_readiness_check_blocks_live_attestation() -> None:
    capability, observation = _observation(unknown_check=McpReadinessCheckId.DEVELOPER_MODE)

    with pytest.raises(ValueError, match="not complete"):
        _commit_fails(capability=capability, observation=observation)


@pytest.mark.parametrize(
    ("tool_count", "write_count", "risk_count"),
    [(0, 0, 0), (2, 0, 0), (1, 1, 0), (1, 0, 1)],
)
def test_non_exact_or_risky_tool_snapshot_blocks_live_attestation(
    tool_count: int,
    write_count: int,
    risk_count: int,
) -> None:
    capability, observation = _observation(
        tool_count=tool_count,
        write_tool_count=write_count,
        high_risk_tool_count=risk_count,
    )

    with pytest.raises(ValueError, match="exactly one"):
        _commit_fails(capability=capability, observation=observation)


def test_chatgpt_scan_digest_drift_blocks_live_attestation() -> None:
    with pytest.raises(ValueError, match="ChatGPT tool scan"):
        _commit_fails(chatgpt_snapshot="2" * 64)


def test_wrong_challenge_or_missing_audit_blocks_live_attestation() -> None:
    with pytest.raises(ValueError, match="challenge"):
        _commit_fails(expected_challenge="3" * 64)

    audit = _audit_record()
    audit["audit_id"] = "87654321-4321-4321-8321-cba987654321"
    with pytest.raises(ValueError, match="audit record"):
        _commit_fails(audit_record=audit)


def test_secret_like_audit_material_blocks_live_attestation() -> None:
    audit = _audit_record()
    audit["reason"] = "Bearer secret-material-that-must-not-pass"

    with pytest.raises(ValueError, match="secret-like"):
        _commit_fails(audit_record=audit)


def test_expired_official_profile_and_long_attestation_are_rejected() -> None:
    capability, observation = _observation()
    expired = capability.model_copy(update={"revalidate_after": VERIFIED - timedelta(seconds=1)})
    with pytest.raises(ValueError, match="profile has expired"):
        _commit_fails(capability=expired, observation=observation)

    with pytest.raises(ValidationError, match="cannot exceed 24 hours"):
        _commit_fails(expires_at=VERIFIED + timedelta(hours=25))


def test_expired_attestation_time_window_fails_without_creating_live_proof() -> None:
    with pytest.raises(ValueError, match="has expired"):
        validate_chatgpt_mcp_live_probe_attestation_time_window(
            verified_at=VERIFIED,
            expires_at=VERIFIED + timedelta(hours=1),
            evaluated_at=VERIFIED + timedelta(hours=1, seconds=1),
        )
