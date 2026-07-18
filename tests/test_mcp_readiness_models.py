from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from systeme_local_gateway.providers.chatgpt_mcp_deployment import (
    build_current_chatgpt_mcp_capability_profile,
)
from systeme_local_gateway.providers.chatgpt_mcp_readiness import (
    build_current_chatgpt_mcp_evidence_reconciliation_profile,
)
from systeme_local_gateway.providers.mcp_deployment_models import (
    ChatGptClientSurface,
    ChatGptPlan,
    ChatGptWorkspaceRole,
    McpAccessMode,
    McpAuthenticationKind,
    McpDeploymentPhase,
    McpDeploymentRequest,
    McpServerLocation,
    RefreshTokenCapability,
    commit_official_source_reference,
)
from systeme_local_gateway.providers.mcp_readiness_models import (
    McpConnectionReadinessDecision,
    McpEvidenceFindingId,
    McpEvidenceFindingStatus,
    McpEvidenceOperationalResolution,
    McpReadinessCheckId,
    McpReadinessCheckState,
    McpReadinessReason,
    McpReadinessStage,
    McpReadinessWarning,
    commit_chatgpt_mcp_evidence_reconciliation_profile,
    commit_mcp_connection_readiness_observation,
    commit_mcp_evidence_finding,
    commit_mcp_readiness_check,
)

NOW = datetime(2026, 7, 18, 15, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64


def request(**updates: object) -> McpDeploymentRequest:
    data: dict[str, object] = {
        "request_id": "req_readiness",
        "plan": ChatGptPlan.PRO,
        "role": ChatGptWorkspaceRole.MEMBER,
        "client": ChatGptClientSurface.WEB,
        "phase": McpDeploymentPhase.TEST,
        "access_mode": McpAccessMode.READ_FETCH,
        "server_location": McpServerLocation.DEVELOPER_MACHINE,
        "authentication": McpAuthenticationKind.OAUTH,
        "persistent_connectivity_required": True,
        "refresh_token_capability": RefreshTokenCapability.ISSUED,
        "developer_mode_enabled": True,
        "app_configured": False,
        "workspace_app_access_granted": False,
        "requested_at": NOW,
    }
    data.update(updates)
    return McpDeploymentRequest(**data)


def checks(
    *,
    overrides: dict[McpReadinessCheckId, McpReadinessCheckState] | None = None,
) -> tuple:
    overrides = overrides or {}
    result = []
    for check_id in McpReadinessCheckId:
        state = overrides.get(check_id, McpReadinessCheckState.UNKNOWN)
        evidence = DIGEST if state in (
            McpReadinessCheckState.VERIFIED,
            McpReadinessCheckState.FAILED,
        ) else None
        detail = "CHECK_FAILED" if state is McpReadinessCheckState.FAILED else None
        result.append(
            commit_mcp_readiness_check(
                check_id=check_id,
                state=state,
                checked_at=NOW,
                evidence_sha256=evidence,
                detail_code=detail,
            )
        )
    return tuple(result)


def observation(**updates: object):
    capability = build_current_chatgpt_mcp_capability_profile()
    reconciliation = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    data: dict[str, object] = {
        "observation_id": "obs_readiness",
        "request": request(),
        "capability_profile_sha256": capability.profile_sha256,
        "reconciliation_profile_sha256": reconciliation.profile_sha256,
        "checks": checks(),
        "tool_snapshot_sha256": None,
        "tool_count": None,
        "write_tool_count": None,
        "high_risk_tool_count": None,
        "local_policy_sha256": None,
        "observed_at": NOW,
    }
    data.update(updates)
    return commit_mcp_connection_readiness_observation(**data)


def test_reconciliation_profile_is_complete_sorted_and_digest_bound() -> None:
    profile = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    assert tuple(item.finding_id for item in profile.findings) == tuple(
        sorted(McpEvidenceFindingId, key=lambda item: item.value)
    )
    assert len(profile.sources) == 6
    with pytest.raises(ValidationError, match="digest mismatch"):
        profile.model_validate({**profile.model_dump(), "profile_id": "changed_profile"})


def test_plus_finding_is_ambiguous_and_fails_closed() -> None:
    profile = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    finding = next(
        item
        for item in profile.findings
        if item.finding_id is McpEvidenceFindingId.PLUS_CUSTOM_MCP_PLAN_SCOPE
    )
    assert finding.status is McpEvidenceFindingStatus.AMBIGUOUS
    assert finding.operational_resolution is McpEvidenceOperationalResolution.FAIL_CLOSED
    assert len(finding.source_ids) == 2


def test_ambiguous_finding_requires_two_sources() -> None:
    with pytest.raises(ValidationError, match="at least two"):
        commit_mcp_evidence_finding(
            finding_id=McpEvidenceFindingId.PLUS_CUSTOM_MCP_PLAN_SCOPE,
            status=McpEvidenceFindingStatus.AMBIGUOUS,
            operational_resolution=McpEvidenceOperationalResolution.FAIL_CLOSED,
            source_ids=("one",),
            observations=("one",),
            reviewed_at=NOW,
        )


def test_ambiguous_finding_cannot_continue_policy_evaluation() -> None:
    with pytest.raises(ValidationError, match="must fail closed"):
        commit_mcp_evidence_finding(
            finding_id=McpEvidenceFindingId.PLUS_CUSTOM_MCP_PLAN_SCOPE,
            status=McpEvidenceFindingStatus.AMBIGUOUS,
            operational_resolution=(
                McpEvidenceOperationalResolution.CONTINUE_POLICY_EVALUATION
            ),
            source_ids=("one", "two"),
            observations=("one", "two"),
            reviewed_at=NOW,
        )


def test_consistent_finding_cannot_fail_closed() -> None:
    with pytest.raises(ValidationError, match="must continue"):
        commit_mcp_evidence_finding(
            finding_id=McpEvidenceFindingId.LOCAL_SERVER_TRANSPORT,
            status=McpEvidenceFindingStatus.CONSISTENT,
            operational_resolution=McpEvidenceOperationalResolution.FAIL_CLOSED,
            source_ids=("one",),
            observations=("one",),
            reviewed_at=NOW,
        )


def test_finding_requires_sorted_unique_sources_and_observations() -> None:
    finding = commit_mcp_evidence_finding(
        finding_id=McpEvidenceFindingId.LOCAL_SERVER_TRANSPORT,
        status=McpEvidenceFindingStatus.CONSISTENT,
        operational_resolution=(
            McpEvidenceOperationalResolution.CONTINUE_POLICY_EVALUATION
        ),
        source_ids=("z", "a"),
        observations=("z", "a"),
        reviewed_at=NOW,
    )
    assert finding.source_ids == ("a", "z")
    assert finding.observations == ("a", "z")
    with pytest.raises(ValidationError, match="duplicates"):
        finding.model_validate(
            {
                **finding.model_dump(),
                "source_ids": ("a", "a"),
            }
        )


def test_finding_is_frozen_strict_and_digest_bound() -> None:
    profile = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    finding = profile.findings[0]
    with pytest.raises(ValidationError):
        finding.model_validate({**finding.model_dump(), "extra": True})
    with pytest.raises(ValidationError, match="digest mismatch"):
        finding.model_validate({**finding.model_dump(), "observations": ("changed",)})
    with pytest.raises(ValidationError):
        finding.status = McpEvidenceFindingStatus.AMBIGUOUS  # type: ignore[misc]


def test_reconciliation_revalidation_window_is_bounded() -> None:
    profile = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    with pytest.raises(ValidationError, match="within 31 days"):
        profile.model_validate(
            {
                **profile.model_dump(),
                "revalidate_after": profile.reviewed_at + timedelta(days=32),
            }
        )


def test_reconciliation_requires_complete_findings() -> None:
    profile = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    with pytest.raises(ValidationError, match="must be complete"):
        commit_chatgpt_mcp_evidence_reconciliation_profile(
            profile_id="incomplete_reconciliation",
            reviewed_at=profile.reviewed_at,
            revalidate_after=profile.revalidate_after,
            sources=profile.sources,
            findings=profile.findings[:-1],
        )


def test_reconciliation_rejects_unknown_and_unused_sources() -> None:
    profile = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    original = profile.findings[0]
    changed = commit_mcp_evidence_finding(
        finding_id=original.finding_id,
        status=original.status,
        operational_resolution=original.operational_resolution,
        source_ids=("missing",),
        observations=original.observations,
        reviewed_at=original.reviewed_at,
    )
    with pytest.raises(ValidationError, match="unknown source"):
        profile.model_validate(
            {
                **profile.model_dump(),
                "findings": (changed, *profile.findings[1:]),
            }
        )
    extra = commit_official_source_reference(
        source_id="unused_source",
        title="Unused",
        url="https://help.openai.com/en/articles/12584461",
        section="Unused",
        evidence_statement="Unused bounded statement.",
        reviewed_at=profile.reviewed_at,
    )
    with pytest.raises(ValidationError, match="must be used"):
        profile.model_validate(
            {
                **profile.model_dump(),
                "sources": tuple(
                    sorted((*profile.sources, extra), key=lambda item: item.source_id)
                ),
            }
        )


def test_reconciliation_requires_timestamp_alignment() -> None:
    profile = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    original = profile.sources[0]
    source = commit_official_source_reference(
        source_id=original.source_id,
        title=original.title,
        url=original.url,
        section=original.section,
        evidence_statement=original.evidence_statement,
        reviewed_at=profile.reviewed_at + timedelta(seconds=1),
    )
    with pytest.raises(ValidationError, match="timestamps must match"):
        profile.model_validate(
            {
                **profile.model_dump(),
                "sources": (source, *profile.sources[1:]),
            }
        )


@pytest.mark.parametrize(
    ("state", "evidence", "detail", "message"),
    [
        (McpReadinessCheckState.VERIFIED, None, None, "require evidence"),
        (McpReadinessCheckState.FAILED, DIGEST, None, "require detail_code"),
        (McpReadinessCheckState.UNKNOWN, DIGEST, None, "cannot claim evidence"),
        (McpReadinessCheckState.NOT_APPLICABLE, None, "BAD", "only failed"),
    ],
)
def test_readiness_check_contract(
    state: McpReadinessCheckState,
    evidence: str | None,
    detail: str | None,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        commit_mcp_readiness_check(
            check_id=McpReadinessCheckId.TRANSPORT,
            state=state,
            checked_at=NOW,
            evidence_sha256=evidence,
            detail_code=detail,
        )


def test_readiness_check_is_digest_bound_and_frozen() -> None:
    check = commit_mcp_readiness_check(
        check_id=McpReadinessCheckId.TRANSPORT,
        state=McpReadinessCheckState.VERIFIED,
        checked_at=NOW,
        evidence_sha256=DIGEST,
    )
    with pytest.raises(ValidationError, match="digest mismatch"):
        check.model_validate({**check.model_dump(), "evidence_sha256": "b" * 64})
    with pytest.raises(ValidationError):
        check.state = McpReadinessCheckState.FAILED  # type: ignore[misc]


def test_readiness_check_requires_timezone() -> None:
    with pytest.raises(ValueError, match="timezone"):
        commit_mcp_readiness_check(
            check_id=McpReadinessCheckId.TRANSPORT,
            state=McpReadinessCheckState.UNKNOWN,
            checked_at=NOW.replace(tzinfo=None),
        )


def test_observation_requires_every_check_exactly_once() -> None:
    with pytest.raises(ValidationError, match="every check"):
        observation(checks=checks()[:-1])
    duplicated = (*checks(), checks()[0])
    with pytest.raises(ValidationError, match="duplicates"):
        observation(checks=duplicated)


def test_observation_commit_sorts_checks() -> None:
    item = observation(checks=tuple(reversed(checks())))
    assert tuple(check.check_id for check in item.checks) == tuple(
        sorted(McpReadinessCheckId, key=lambda check_id: check_id.value)
    )


def test_observation_rejects_future_check() -> None:
    changed = list(checks())
    changed[0] = commit_mcp_readiness_check(
        check_id=changed[0].check_id,
        state=McpReadinessCheckState.UNKNOWN,
        checked_at=NOW + timedelta(seconds=1),
    )
    with pytest.raises(ValidationError, match="cannot postdate"):
        observation(checks=tuple(changed))


def test_verified_tool_snapshot_requires_digest_and_counts() -> None:
    states = {McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED}
    with pytest.raises(ValidationError, match="require digest and counts"):
        observation(checks=checks(overrides=states))


def test_unverified_tool_snapshot_cannot_carry_metadata() -> None:
    with pytest.raises(ValidationError, match="cannot carry"):
        observation(
            tool_snapshot_sha256=DIGEST,
            tool_count=1,
            write_tool_count=0,
            high_risk_tool_count=0,
        )


def test_tool_counts_must_be_coherent() -> None:
    states = {McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED}
    with pytest.raises(ValidationError, match="cannot exceed"):
        observation(
            checks=checks(overrides=states),
            tool_snapshot_sha256=DIGEST,
            tool_count=1,
            write_tool_count=2,
            high_risk_tool_count=0,
        )


def test_verified_local_policy_requires_digest() -> None:
    states = {McpReadinessCheckId.LOCAL_POLICY: McpReadinessCheckState.VERIFIED}
    with pytest.raises(ValidationError, match="requires local_policy_sha256"):
        observation(checks=checks(overrides=states))


def test_unverified_local_policy_cannot_carry_digest() -> None:
    with pytest.raises(ValidationError, match="cannot carry a policy digest"):
        observation(local_policy_sha256=DIGEST)


def test_complete_verified_snapshot_and_policy_are_accepted() -> None:
    states = {
        McpReadinessCheckId.LOCAL_POLICY: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED,
    }
    item = observation(
        checks=checks(overrides=states),
        tool_snapshot_sha256=DIGEST,
        tool_count=3,
        write_tool_count=0,
        high_risk_tool_count=0,
        local_policy_sha256="b" * 64,
    )
    assert item.real_connection_requested is False
    assert item.tool_count == 3


def test_observation_is_strict_frozen_and_digest_bound() -> None:
    item = observation()
    with pytest.raises(ValidationError):
        item.model_validate({**item.model_dump(), "password": "forbidden"})
    with pytest.raises(ValidationError, match="digest mismatch"):
        item.model_validate({**item.model_dump(), "observation_id": "changed_observation"})
    with pytest.raises(ValidationError):
        item.real_connection_requested = True  # type: ignore[misc]


def test_decision_requires_partition_of_required_checks() -> None:
    with pytest.raises(ValidationError, match="partition"):
        McpConnectionReadinessDecision(
            observation_id="obs_readiness",
            ready=False,
            stage=McpReadinessStage.BLOCKED,
            reasons=(McpReadinessReason.REQUIRED_CHECK_UNKNOWN,),
            warnings=(McpReadinessWarning.REAL_CONNECTION_NOT_ESTABLISHED,),
            required_checks=(McpReadinessCheckId.TRANSPORT,),
            verified_checks=(),
            failed_checks=(),
            unknown_checks=(),
            not_applicable_required_checks=(),
            deployment_reasons=(),
            selected_transport=None,
            capability_profile_sha256=DIGEST,
            reconciliation_profile_sha256=DIGEST,
            observation_sha256=DIGEST,
            evaluated_at=NOW,
        )


def test_ready_decision_cannot_be_blocked_or_carry_reasons() -> None:
    with pytest.raises(ValidationError, match="cannot use stage=blocked"):
        McpConnectionReadinessDecision(
            observation_id="obs_readiness",
            ready=True,
            stage=McpReadinessStage.BLOCKED,
            reasons=(),
            warnings=(),
            required_checks=(),
            verified_checks=(),
            failed_checks=(),
            unknown_checks=(),
            not_applicable_required_checks=(),
            deployment_reasons=(),
            selected_transport=None,
            capability_profile_sha256=DIGEST,
            reconciliation_profile_sha256=DIGEST,
            observation_sha256=DIGEST,
            evaluated_at=NOW,
        )


def test_blocked_decision_requires_reasons_and_no_transport() -> None:
    from systeme_local_gateway.providers.mcp_deployment_models import McpTransportKind

    with pytest.raises(ValidationError, match="require refusal reasons"):
        McpConnectionReadinessDecision(
            observation_id="obs_readiness",
            ready=False,
            stage=McpReadinessStage.BLOCKED,
            reasons=(),
            warnings=(),
            required_checks=(),
            verified_checks=(),
            failed_checks=(),
            unknown_checks=(),
            not_applicable_required_checks=(),
            deployment_reasons=(),
            selected_transport=None,
            capability_profile_sha256=DIGEST,
            reconciliation_profile_sha256=DIGEST,
            observation_sha256=DIGEST,
            evaluated_at=NOW,
        )
    with pytest.raises(ValidationError, match="cannot select a transport"):
        McpConnectionReadinessDecision(
            observation_id="obs_readiness",
            ready=False,
            stage=McpReadinessStage.BLOCKED,
            reasons=(McpReadinessReason.REQUIRED_CHECK_UNKNOWN,),
            warnings=(),
            required_checks=(),
            verified_checks=(),
            failed_checks=(),
            unknown_checks=(),
            not_applicable_required_checks=(),
            deployment_reasons=(),
            selected_transport=McpTransportKind.SECURE_MCP_TUNNEL,
            capability_profile_sha256=DIGEST,
            reconciliation_profile_sha256=DIGEST,
            observation_sha256=DIGEST,
            evaluated_at=NOW,
        )
