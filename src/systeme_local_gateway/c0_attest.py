from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .audit import AuditLog
from .c0_probe import (
    C0_SHA256_PATTERN,
    C0_TOOL_NAME,
    C0ConnectivityProbeResponse,
)
from .c0_proof_check import (
    C0PendingLiveProofReceipt,
    canonical_c0_audit_record_sha256,
    canonical_c0_response_sha256,
    verify_c0_pending_live_proof_receipt,
)
from .mcp_tools import McpToolRegistry
from .policy import PolicyEngine
from .providers.chatgpt_mcp_deployment import (
    build_current_chatgpt_mcp_capability_profile,
)
from .providers.chatgpt_mcp_live_probe import (
    commit_chatgpt_mcp_live_probe_attestation,
)
from .providers.chatgpt_mcp_readiness import (
    build_current_chatgpt_mcp_evidence_reconciliation_profile,
)
from .providers.mcp_deployment_models import (
    ChatGptClientSurface,
    ChatGptPlan,
    ChatGptWorkspaceRole,
    McpAccessMode,
    McpAuthenticationKind,
    McpDeploymentPhase,
    McpDeploymentRequest,
    McpServerLocation,
    RefreshTokenCapability,
)
from .providers.mcp_readiness_models import (
    McpReadinessCheckId,
    McpReadinessCheckState,
    commit_mcp_connection_readiness_observation,
    commit_mcp_readiness_check,
)


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C0 evidence timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


class C0ManualWebObservation(BaseModel):
    """Bounded operator assertion; contains no UI content or credentials."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    source: Literal["manual_chatgpt_web"]
    simulated: Literal[False]
    plan: ChatGptPlan
    role: ChatGptWorkspaceRole
    client: Literal["web"]
    transport: Literal["secure_mcp_tunnel"]
    authentication: Literal["none"]
    draft_plugin: Literal[True]
    published: Literal[False]
    tool_name: Literal["systeme_local_connectivity_probe"]
    tool_count: Literal[1]
    write_tool_count: Literal[0]
    high_risk_tool_count: Literal[0]
    tool_snapshot_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    local_policy_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    checks: dict[McpReadinessCheckId, McpReadinessCheckState]
    observed_at: datetime
    started_at: datetime

    _aware_observed_at = field_validator("observed_at")(_require_aware)
    _aware_started_at = field_validator("started_at")(_require_aware)

    @model_validator(mode="after")
    def validate_manual_observation(self) -> C0ManualWebObservation:
        if self.plan in (
            ChatGptPlan.FREE,
            ChatGptPlan.GO,
            ChatGptPlan.PLUS,
            ChatGptPlan.UNKNOWN,
        ):
            raise ValueError("manual C0 plan is ineligible or ambiguous")
        if self.role is ChatGptWorkspaceRole.UNKNOWN:
            raise ValueError("manual C0 role is unknown")
        if set(self.checks) != set(McpReadinessCheckId):
            raise ValueError("manual C0 observation requires exactly eleven checks")
        if any(
            state
            in (
                McpReadinessCheckState.FAILED,
                McpReadinessCheckState.UNKNOWN,
            )
            for state in self.checks.values()
        ):
            raise ValueError("manual C0 observation contains a blocking check")
        if (
            self.checks[McpReadinessCheckId.REFRESH_TOKEN]
            is not McpReadinessCheckState.NOT_APPLICABLE
        ):
            raise ValueError("C0 noauth requires refresh_token=not_applicable")
        allowed_not_applicable = {McpReadinessCheckId.REFRESH_TOKEN}
        if self.plan is ChatGptPlan.PRO:
            allowed_not_applicable.add(McpReadinessCheckId.WORKSPACE_ACCESS)
        observed_not_applicable = {
            check_id
            for check_id, state in self.checks.items()
            if state is McpReadinessCheckState.NOT_APPLICABLE
        }
        if not observed_not_applicable.issubset(allowed_not_applicable):
            raise ValueError("manual C0 observation misuses not_applicable")
        if self.observed_at > self.started_at:
            raise ValueError("readiness observation must precede the live window")
        if self.started_at - self.observed_at > timedelta(hours=1):
            raise ValueError("manual readiness observation is stale")
        return self


class C0RevocationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    source: Literal["manual_chatgpt_web"]
    plugin_connection_removed: Literal[True]
    runtime_api_key_revoked: Literal[True]
    tunnel_stopped: Literal[True]
    facade_stopped: Literal[True]
    post_revocation_call_failed: Literal[True]
    verified_at: datetime

    _aware_verified_at = field_validator("verified_at")(_require_aware)


def _current_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Commit a C0 live attestation from bounded manual evidence."
    )
    parser.add_argument("--manual-observation", type=Path, required=True)
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--audit-log", type=Path, required=True)
    parser.add_argument("--pending-live-proof", type=Path, required=True)
    parser.add_argument("--revocation-receipt", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        audit_key = os.environ.get("SLG_AUDIT_KEY")
        if audit_key is None or len(audit_key) < 32:
            raise ValueError("SLG_AUDIT_KEY is required")
        manual = C0ManualWebObservation.model_validate(_load_object(args.manual_observation))
        response = C0ConnectivityProbeResponse.model_validate(_load_object(args.response))
        pending = verify_c0_pending_live_proof_receipt(
            C0PendingLiveProofReceipt.model_validate(_load_object(args.pending_live_proof)),
            audit_key=audit_key,
        )
        revocation = C0RevocationReceipt.model_validate(_load_object(args.revocation_receipt))

        challenge = args.challenge.read_text(encoding="utf-8").strip()
        challenge_sha256 = hashlib.sha256(challenge.encode("ascii")).hexdigest()
        if response.challenge_sha256 != challenge_sha256:
            raise ValueError("live response does not match the local challenge")
        if response.server_build_commit != _current_commit():
            raise ValueError("live response build does not match current HEAD")
        if response.observed_at < manual.started_at:
            raise ValueError("live response predates the manual live window")
        if pending.challenge_created_at > manual.started_at:
            raise ValueError("live window predates the locally generated challenge")
        if pending.checked_at > revocation.verified_at:
            raise ValueError("pending live proof postdates revocation verification")
        if response.observed_at > revocation.verified_at:
            raise ValueError("live response postdates revocation verification")
        if revocation.verified_at > datetime.now(UTC) + timedelta(minutes=1):
            raise ValueError("revocation verification timestamp is in the future")

        policy = PolicyEngine(args.policy)
        registry = McpToolRegistry(policy, c0_mode=True)
        if [tool.name for tool in registry.list_tools()] != [C0_TOOL_NAME]:
            raise ValueError("C0 policy does not expose exactly one tool")
        if manual.local_policy_sha256 != policy.policy_sha256:
            raise ValueError("manual policy digest does not match local C0 policy")
        if manual.tool_snapshot_sha256 != registry.tool_snapshot_sha256:
            raise ValueError("manual ChatGPT tool scan does not match local C0 tools")
        if response.local_policy_sha256 != policy.policy_sha256:
            raise ValueError("live response policy digest mismatch")
        if response.tool_snapshot_sha256 != registry.tool_snapshot_sha256:
            raise ValueError("live response tool snapshot digest mismatch")
        if pending.challenge_sha256 != challenge_sha256:
            raise ValueError("pending live proof challenge digest mismatch")
        if pending.response_sha256 != canonical_c0_response_sha256(response):
            raise ValueError("pending live proof response digest mismatch")
        if pending.server_build_commit != response.server_build_commit:
            raise ValueError("pending live proof build commit mismatch")
        if pending.audit_correlation != response.audit_correlation:
            raise ValueError("pending live proof audit correlation mismatch")
        if pending.local_policy_sha256 != policy.policy_sha256:
            raise ValueError("pending live proof policy digest mismatch")
        if pending.tool_snapshot_sha256 != registry.tool_snapshot_sha256:
            raise ValueError("pending live proof tool snapshot digest mismatch")

        audit_log = AuditLog(args.audit_log, audit_key)
        audit_verification = audit_log.verify()
        records = [
            json.loads(line) for line in args.audit_log.read_text(encoding="utf-8").splitlines()
        ]
        matches = [
            record for record in records if record.get("audit_id") == response.audit_correlation
        ]
        if len(matches) != 1:
            raise ValueError("exactly one correlated audit record is required")
        audit_record = matches[0]
        if pending.audit_record_sha256 != canonical_c0_audit_record_sha256(audit_record):
            raise ValueError("pending live proof audit record digest mismatch")
        if pending.audit_records_verified != audit_verification.records:
            raise ValueError("pending live proof audit chain length mismatch")

        capability_profile = build_current_chatgpt_mcp_capability_profile()
        reconciliation_profile = build_current_chatgpt_mcp_evidence_reconciliation_profile()
        manual_digest = hashlib.sha256(_canonical_json(manual.model_dump(mode="json"))).hexdigest()
        request = McpDeploymentRequest(
            request_id="req_c0_manual_live",
            plan=manual.plan,
            role=manual.role,
            client=ChatGptClientSurface.WEB,
            phase=McpDeploymentPhase.TEST,
            access_mode=McpAccessMode.READ_FETCH,
            server_location=McpServerLocation.DEVELOPER_MACHINE,
            authentication=McpAuthenticationKind.NONE,
            persistent_connectivity_required=False,
            refresh_token_capability=RefreshTokenCapability.NOT_APPLICABLE,
            developer_mode_enabled=True,
            app_configured=True,
            workspace_app_access_granted=(
                manual.checks[McpReadinessCheckId.WORKSPACE_ACCESS]
                is McpReadinessCheckState.VERIFIED
            ),
            requested_at=manual.observed_at,
        )
        checks = tuple(
            commit_mcp_readiness_check(
                check_id=check_id,
                state=state,
                checked_at=manual.observed_at,
                evidence_sha256=(
                    manual_digest if state is McpReadinessCheckState.VERIFIED else None
                ),
            )
            for check_id, state in manual.checks.items()
        )
        observation = commit_mcp_connection_readiness_observation(
            observation_id="obs_c0_manual_live",
            request=request,
            capability_profile_sha256=capability_profile.profile_sha256,
            reconciliation_profile_sha256=reconciliation_profile.profile_sha256,
            checks=checks,
            tool_snapshot_sha256=registry.tool_snapshot_sha256,
            tool_count=1,
            write_tool_count=0,
            high_risk_tool_count=0,
            local_policy_sha256=policy.policy_sha256,
            observed_at=manual.observed_at,
        )
        revocation_digest = hashlib.sha256(
            _canonical_json(revocation.model_dump(mode="json"))
        ).hexdigest()
        attestation = commit_chatgpt_mcp_live_probe_attestation(
            capability_profile=capability_profile,
            reconciliation_profile=reconciliation_profile,
            readiness_observation=observation,
            response=response,
            audit_record=audit_record,
            pending_live_proof=pending,
            pending_proof_audit_key=audit_key,
            app_configuration_evidence_sha256=manual_digest,
            chatgpt_tool_snapshot_sha256=manual.tool_snapshot_sha256,
            revocation_evidence_sha256=revocation_digest,
            expected_challenge_sha256=challenge_sha256,
            started_at=manual.started_at,
            verified_at=revocation.verified_at,
            expires_at=revocation.verified_at + timedelta(hours=1),
            revocation_verified=True,
            audit_chain_verified=True,
        )
    except Exception as exc:
        print(
            json.dumps(
                {"status": "error", "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            attestation.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
