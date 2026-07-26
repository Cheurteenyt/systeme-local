from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..c0_probe import (
    C0_AUDIT_ID_PATTERN,
    C0_SHA256_PATTERN,
    C0_TOOL_NAME,
    C0ConnectivityProbeResponse,
)
from .chatgpt_mcp_deployment import evaluate_chatgpt_mcp_deployment
from .mcp_deployment_models import ChatGptMcpCapabilityProfile
from .mcp_deployment_models import (
    ChatGptClientSurface,
    ChatGptPlan,
    McpAccessMode,
    McpAuthenticationKind,
    McpDeploymentPhase,
    McpServerLocation,
    RefreshTokenCapability,
)
from .mcp_readiness_models import (
    ChatGptMcpEvidenceReconciliationProfile,
    McpConnectionReadinessObservation,
    McpReadinessCheckId,
    McpReadinessCheckState,
)

_ATTESTATION_DOMAIN = b"systeme-local/chatgpt-mcp-live-probe-attestation/v1\0"
_SECRET_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(cookie|refresh[_ -]?token|client[_ -]?secret)\s*[:=]"),
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _assert_secret_free(value: Any) -> None:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    if any(pattern.search(encoded) for pattern in _SECRET_PATTERNS):
        raise ValueError("live proof contains secret-like material")


class ChatGptMcpLiveProbeAttestation(BaseModel):
    """Committed proof of a manual ChatGPT Web C0 call and revocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    source: Literal["manual_chatgpt_web"]
    simulated: Literal[False]
    invocation_origin: Literal["chatgpt_web_draft_plugin"]
    official_evidence_profile_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    evidence_reconciliation_profile_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    readiness_observation_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    local_policy_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    tool_snapshot_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    chatgpt_tool_snapshot_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    app_configuration_evidence_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    challenge_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    response_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    audit_record_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    revocation_evidence_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    audit_correlation: str = Field(pattern=C0_AUDIT_ID_PATTERN)
    audit_chain_verified: Literal[True]
    scanned_tool_count: Literal[1]
    scanned_write_tool_count: Literal[0]
    scanned_high_risk_tool_count: Literal[0]
    started_at: datetime
    verified_at: datetime
    expires_at: datetime
    revocation_verified: Literal[True]
    real_connection_established: Literal[True]
    attestation_sha256: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_started_at = field_validator("started_at")(_require_aware)
    _aware_verified_at = field_validator("verified_at")(_require_aware)
    _aware_expires_at = field_validator("expires_at")(_require_aware)

    @model_validator(mode="after")
    def validate_attestation(self) -> "ChatGptMcpLiveProbeAttestation":
        if self.verified_at < self.started_at:
            raise ValueError("live verification cannot predate its start")
        if self.expires_at <= self.verified_at:
            raise ValueError("live attestation expiry must follow verification")
        if self.expires_at - self.verified_at > timedelta(hours=24):
            raise ValueError("live attestation validity cannot exceed 24 hours")
        expected = compute_chatgpt_mcp_live_probe_attestation_sha256(
            self.model_dump(mode="json", exclude={"attestation_sha256"})
        )
        if self.attestation_sha256 != expected:
            raise ValueError("live probe attestation digest mismatch")
        return self


def compute_chatgpt_mcp_live_probe_attestation_sha256(
    payload: dict[str, Any],
) -> str:
    return sha256(_ATTESTATION_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_chatgpt_mcp_live_probe_attestation(
    *,
    capability_profile: ChatGptMcpCapabilityProfile,
    reconciliation_profile: ChatGptMcpEvidenceReconciliationProfile,
    readiness_observation: McpConnectionReadinessObservation,
    response: C0ConnectivityProbeResponse,
    audit_record: dict[str, Any],
    app_configuration_evidence_sha256: str,
    chatgpt_tool_snapshot_sha256: str,
    revocation_evidence_sha256: str,
    expected_challenge_sha256: str,
    started_at: datetime,
    verified_at: datetime,
    expires_at: datetime,
    revocation_verified: bool,
    audit_chain_verified: bool,
) -> ChatGptMcpLiveProbeAttestation:
    """Fail closed unless all bounded manual-live proof elements agree."""

    started_at = _require_aware(started_at)
    verified_at = _require_aware(verified_at)
    expires_at = _require_aware(expires_at)
    if not revocation_verified:
        raise ValueError("revocation must be manually verified before attestation")
    if not audit_chain_verified:
        raise ValueError("the complete local audit chain must be verified")
    if verified_at > capability_profile.revalidate_after:
        raise ValueError("official capability evidence profile has expired")
    if verified_at > reconciliation_profile.revalidate_after:
        raise ValueError("official evidence reconciliation profile has expired")
    if readiness_observation.capability_profile_sha256 != capability_profile.profile_sha256:
        raise ValueError("readiness observation references another capability profile")
    if readiness_observation.reconciliation_profile_sha256 != reconciliation_profile.profile_sha256:
        raise ValueError("readiness observation references another reconciliation profile")

    request = readiness_observation.request
    if (
        request.client is not ChatGptClientSurface.WEB
        or request.phase is not McpDeploymentPhase.TEST
        or request.access_mode is not McpAccessMode.READ_FETCH
        or request.server_location is not McpServerLocation.DEVELOPER_MACHINE
        or request.authentication is not McpAuthenticationKind.NONE
        or request.persistent_connectivity_required
        or request.refresh_token_capability is not RefreshTokenCapability.NOT_APPLICABLE
    ):
        raise ValueError("readiness observation is outside the bounded C0 request")
    if request.plan not in (
        ChatGptPlan.PRO,
        ChatGptPlan.BUSINESS,
        ChatGptPlan.ENTERPRISE,
        ChatGptPlan.EDU,
    ):
        raise ValueError("ChatGPT plan is not eligible for C0")
    deployment = evaluate_chatgpt_mcp_deployment(
        profile=capability_profile,
        request=request,
        evaluated_at=verified_at,
    )
    if not deployment.allowed:
        raise ValueError("plan, role, client, or configuration is not eligible")

    check_states = {check.check_id: check.state for check in readiness_observation.checks}
    if set(check_states) != set(McpReadinessCheckId):
        raise ValueError("all eleven readiness checks are required")
    invalid_states = {
        check_id
        for check_id, state in check_states.items()
        if state
        not in (
            McpReadinessCheckState.VERIFIED,
            McpReadinessCheckState.NOT_APPLICABLE,
        )
    }
    if invalid_states:
        names = ", ".join(sorted(item.value for item in invalid_states))
        raise ValueError(f"readiness checks are not complete: {names}")
    not_applicable = {
        check_id
        for check_id, state in check_states.items()
        if state is McpReadinessCheckState.NOT_APPLICABLE
    }
    allowed_not_applicable = {McpReadinessCheckId.REFRESH_TOKEN}
    if request.plan is ChatGptPlan.PRO:
        allowed_not_applicable.add(McpReadinessCheckId.WORKSPACE_ACCESS)
    unexpected_not_applicable = not_applicable - allowed_not_applicable
    if unexpected_not_applicable:
        names = ", ".join(sorted(item.value for item in unexpected_not_applicable))
        raise ValueError(f"readiness checks are improperly not-applicable: {names}")
    if check_states[McpReadinessCheckId.REFRESH_TOKEN] is not McpReadinessCheckState.NOT_APPLICABLE:
        raise ValueError("C0 noauth requires refresh_token=not_applicable")
    if readiness_observation.observed_at > started_at:
        raise ValueError("readiness observation must exist before the live window")
    if started_at - readiness_observation.observed_at > timedelta(hours=1):
        raise ValueError("readiness observation is stale for the live window")

    if (
        readiness_observation.tool_count,
        readiness_observation.write_tool_count,
        readiness_observation.high_risk_tool_count,
    ) != (1, 0, 0):
        raise ValueError("C0 requires exactly one read-only, non-high-risk tool")
    if readiness_observation.local_policy_sha256 != response.local_policy_sha256:
        raise ValueError("response local policy digest does not match readiness")
    if readiness_observation.tool_snapshot_sha256 != response.tool_snapshot_sha256:
        raise ValueError("response tool snapshot digest does not match readiness")
    if chatgpt_tool_snapshot_sha256 != response.tool_snapshot_sha256:
        raise ValueError("ChatGPT tool scan does not match the local snapshot")
    if response.challenge_sha256 != expected_challenge_sha256:
        raise ValueError("response challenge digest does not match the local challenge")
    if response.observed_at < started_at or response.observed_at > verified_at:
        raise ValueError("response timestamp is outside the manual live window")

    if audit_record.get("audit_id") != response.audit_correlation:
        raise ValueError("audit record does not match response correlation")
    if audit_record.get("capability") != C0_TOOL_NAME:
        raise ValueError("audit record is not a C0 probe event")
    if audit_record.get("status") != "completed":
        raise ValueError("audit record does not show a completed probe")
    agent = audit_record.get("agent")
    if not isinstance(agent, dict) or agent.get("provider") != "mcp":
        raise ValueError("audit record is not attributed to MCP")
    if not isinstance(audit_record.get("entry_hmac"), str):
        raise ValueError("audit record lacks its chain HMAC")
    _assert_secret_free(response.model_dump(mode="json"))
    _assert_secret_free(audit_record)

    payload: dict[str, Any] = {
        "version": "1",
        "source": "manual_chatgpt_web",
        "simulated": False,
        "invocation_origin": "chatgpt_web_draft_plugin",
        "official_evidence_profile_sha256": capability_profile.profile_sha256,
        "evidence_reconciliation_profile_sha256": (reconciliation_profile.profile_sha256),
        "readiness_observation_sha256": readiness_observation.observation_sha256,
        "local_policy_sha256": response.local_policy_sha256,
        "tool_snapshot_sha256": response.tool_snapshot_sha256,
        "chatgpt_tool_snapshot_sha256": chatgpt_tool_snapshot_sha256,
        "app_configuration_evidence_sha256": app_configuration_evidence_sha256,
        "challenge_sha256": expected_challenge_sha256,
        "response_sha256": sha256(_canonical_json(response.model_dump(mode="json"))).hexdigest(),
        "audit_record_sha256": sha256(_canonical_json(audit_record)).hexdigest(),
        "revocation_evidence_sha256": revocation_evidence_sha256,
        "audit_correlation": response.audit_correlation,
        "audit_chain_verified": True,
        "scanned_tool_count": 1,
        "scanned_write_tool_count": 0,
        "scanned_high_risk_tool_count": 0,
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "verified_at": verified_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "revocation_verified": True,
        "real_connection_established": True,
    }
    return ChatGptMcpLiveProbeAttestation(
        **payload,
        attestation_sha256=compute_chatgpt_mcp_live_probe_attestation_sha256(payload),
    )


def verify_chatgpt_mcp_live_probe_attestation(
    attestation: ChatGptMcpLiveProbeAttestation,
    *,
    evaluated_at: datetime,
) -> ChatGptMcpLiveProbeAttestation:
    committed = ChatGptMcpLiveProbeAttestation.model_validate(attestation.model_dump(mode="python"))
    validate_chatgpt_mcp_live_probe_attestation_time_window(
        verified_at=committed.verified_at,
        expires_at=committed.expires_at,
        evaluated_at=evaluated_at,
    )
    return committed


def validate_chatgpt_mcp_live_probe_attestation_time_window(
    *,
    verified_at: datetime,
    expires_at: datetime,
    evaluated_at: datetime,
) -> None:
    verified_at = _require_aware(verified_at)
    expires_at = _require_aware(expires_at)
    evaluated_at = _require_aware(evaluated_at)
    if evaluated_at > expires_at:
        raise ValueError("live probe attestation has expired")
    if evaluated_at < verified_at:
        raise ValueError("live probe attestation cannot be used before verification")
