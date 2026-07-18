from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .chatgpt_mcp_deployment import (
    evaluate_chatgpt_mcp_deployment,
    verify_chatgpt_mcp_capability_profile,
)
from .mcp_deployment_models import (
    ChatGptMcpCapabilityProfile,
    ChatGptPlan,
    McpAccessMode,
    McpAuthenticationKind,
    McpDeploymentPhase,
    OfficialSourceReference,
    commit_official_source_reference,
)
from .mcp_readiness_models import (
    ChatGptMcpEvidenceReconciliationProfile,
    McpConnectionReadinessDecision,
    McpConnectionReadinessObservation,
    McpEvidenceFinding,
    McpEvidenceFindingId,
    McpEvidenceFindingStatus,
    McpEvidenceOperationalResolution,
    McpReadinessCheckId,
    McpReadinessCheckState,
    McpReadinessReason,
    McpReadinessStage,
    McpReadinessWarning,
    commit_chatgpt_mcp_evidence_reconciliation_profile,
    commit_mcp_evidence_finding,
)

_REVIEWED_AT = datetime(2026, 7, 18, 14, 0, tzinfo=timezone.utc)
_REVALIDATE_AFTER = _REVIEWED_AT + timedelta(days=14)


def _sources() -> tuple[OfficialSourceReference, ...]:
    return (
        commit_official_source_reference(
            source_id="openai_apps_plan_matrix_20260718",
            title="Apps in ChatGPT",
            url="https://help.openai.com/en/articles/11487775-apps-in-chatgpt",
            section="Apps capabilities by plan",
            evidence_statement=(
                "The general Apps plan matrix lists Custom (MCP) for Plus, Pro, "
                "Business and Enterprise/Edu."
            ),
            reviewed_at=_REVIEWED_AT,
        ),
        commit_official_source_reference(
            source_id="openai_mcp_developer_scope_20260718",
            title="Developer mode and MCP apps in ChatGPT",
            url="https://help.openai.com/en/articles/12584461",
            section="Availability and Pro FAQ",
            evidence_statement=(
                "The dedicated developer-mode article documents full MCP for Business and "
                "Enterprise/Edu and read/fetch MCP for Pro, without documenting a Plus "
                "developer-mode deployment path."
            ),
            reviewed_at=_REVIEWED_AT,
        ),
        commit_official_source_reference(
            source_id="openai_mcp_oauth_refresh_20260718",
            title="Developer mode and MCP apps in ChatGPT",
            url="https://help.openai.com/en/articles/12584461",
            section="OAuth and OpenID Connect refresh tokens",
            evidence_statement=(
                "Persistent OAuth or OpenID Connect connectivity requires refresh-token "
                "capability, commonly advertised with offline_access."
            ),
            reviewed_at=_REVIEWED_AT,
        ),
        commit_official_source_reference(
            source_id="openai_mcp_tool_snapshot_20260718",
            title="Developer mode and MCP apps in ChatGPT",
            url="https://help.openai.com/en/articles/12584461",
            section="Action controls and tool updates",
            evidence_statement=(
                "Approved MCP tools are reviewed as a frozen snapshot; new actions are disabled "
                "by default and changed actions are shown for review."
            ),
            reviewed_at=_REVIEWED_AT,
        ),
        commit_official_source_reference(
            source_id="openai_mcp_transport_20260718",
            title="Developer mode and MCP apps in ChatGPT",
            url="https://help.openai.com/en/articles/12584461",
            section="Local MCP server FAQ",
            evidence_statement=(
                "ChatGPT connects to remote MCP servers; private, on-premises and developer "
                "machine servers use Secure MCP Tunnel rather than direct loopback access."
            ),
            reviewed_at=_REVIEWED_AT,
        ),
        commit_official_source_reference(
            source_id="openai_mcp_write_controls_20260718",
            title="Developer mode and MCP apps in ChatGPT",
            url="https://help.openai.com/en/articles/12584461",
            section="Write-action safety controls",
            evidence_statement=(
                "Write or modify actions may require confirmation according to permissions, "
                "context and impact, while especially risky actions may be blocked."
            ),
            reviewed_at=_REVIEWED_AT,
        ),
    )


def _finding(
    finding_id: McpEvidenceFindingId,
    *,
    source_ids: tuple[str, ...],
    observations: tuple[str, ...],
    ambiguous: bool = False,
) -> McpEvidenceFinding:
    status = (
        McpEvidenceFindingStatus.AMBIGUOUS
        if ambiguous
        else McpEvidenceFindingStatus.CONSISTENT
    )
    resolution = (
        McpEvidenceOperationalResolution.FAIL_CLOSED
        if ambiguous
        else McpEvidenceOperationalResolution.CONTINUE_POLICY_EVALUATION
    )
    return commit_mcp_evidence_finding(
        finding_id=finding_id,
        status=status,
        operational_resolution=resolution,
        source_ids=source_ids,
        observations=observations,
        reviewed_at=_REVIEWED_AT,
    )


def _findings() -> tuple[McpEvidenceFinding, ...]:
    return (
        _finding(
            McpEvidenceFindingId.LOCAL_SERVER_TRANSPORT,
            source_ids=("openai_mcp_transport_20260718",),
            observations=(
                "Direct loopback access is not a supported ChatGPT MCP transport.",
                "Private or local deployments require Secure MCP Tunnel.",
            ),
        ),
        _finding(
            McpEvidenceFindingId.PERSISTENT_OAUTH_REFRESH,
            source_ids=("openai_mcp_oauth_refresh_20260718",),
            observations=(
                "Persistent authorization requires an issued refresh token.",
                "OIDC providers commonly advertise refresh capability with offline_access.",
            ),
        ),
        _finding(
            McpEvidenceFindingId.PLUS_CUSTOM_MCP_PLAN_SCOPE,
            source_ids=(
                "openai_apps_plan_matrix_20260718",
                "openai_mcp_developer_scope_20260718",
            ),
            observations=(
                "The general Apps plan matrix lists Custom (MCP) for Plus.",
                "The dedicated developer-mode article does not document a Plus deployment path.",
            ),
            ambiguous=True,
        ),
        _finding(
            McpEvidenceFindingId.TOOL_SNAPSHOT_DRIFT,
            source_ids=("openai_mcp_tool_snapshot_20260718",),
            observations=(
                "Changed actions require explicit refresh and review.",
                "New actions are disabled by default in the documented managed workflow.",
            ),
        ),
        _finding(
            McpEvidenceFindingId.WRITE_ACTION_CONTROL,
            source_ids=("openai_mcp_write_controls_20260718",),
            observations=(
                "Confirmation depends on permissions, context and impact.",
                "High-risk actions may be blocked instead of offered for confirmation.",
            ),
        ),
    )


def build_current_chatgpt_mcp_evidence_reconciliation_profile(
) -> ChatGptMcpEvidenceReconciliationProfile:
    return commit_chatgpt_mcp_evidence_reconciliation_profile(
        profile_id="chatgpt_mcp_reconciliation_20260718",
        reviewed_at=_REVIEWED_AT,
        revalidate_after=_REVALIDATE_AFTER,
        sources=_sources(),
        findings=_findings(),
    )


def verify_chatgpt_mcp_evidence_reconciliation_profile(
    profile: ChatGptMcpEvidenceReconciliationProfile,
) -> ChatGptMcpEvidenceReconciliationProfile:
    return ChatGptMcpEvidenceReconciliationProfile.model_validate(
        profile.model_dump(mode="python")
    )


def verify_mcp_connection_readiness_observation(
    observation: McpConnectionReadinessObservation,
) -> McpConnectionReadinessObservation:
    return McpConnectionReadinessObservation.model_validate(
        observation.model_dump(mode="python")
    )


def _sorted_enum_tuple(values: set) -> tuple:
    return tuple(sorted(values, key=lambda item: item.value))


def _required_checks(
    *,
    observation: McpConnectionReadinessObservation,
    requires_developer_mode: bool,
) -> tuple[set[McpReadinessCheckId], McpReadinessStage]:
    request = observation.request
    required = {
        McpReadinessCheckId.LOCAL_POLICY,
        McpReadinessCheckId.PLAN_ROLE_OBSERVATION,
        McpReadinessCheckId.TRANSPORT,
        McpReadinessCheckId.WEB_CLIENT,
    }
    if request.authentication in (
        McpAuthenticationKind.OAUTH,
        McpAuthenticationKind.OPENID_CONNECT,
    ):
        required.add(McpReadinessCheckId.AUTHENTICATION_METADATA)
        if request.persistent_connectivity_required:
            required.add(McpReadinessCheckId.REFRESH_TOKEN)
    if requires_developer_mode:
        required.add(McpReadinessCheckId.DEVELOPER_MODE)

    by_id = {check.check_id: check for check in observation.checks}
    if request.phase is McpDeploymentPhase.TEST:
        if (
            by_id[McpReadinessCheckId.APP_CONFIGURATION].state
            is McpReadinessCheckState.VERIFIED
        ):
            required.update(
                {
                    McpReadinessCheckId.ACTION_REVIEW,
                    McpReadinessCheckId.APP_CONFIGURATION,
                    McpReadinessCheckId.TOOL_SNAPSHOT,
                }
            )
            return required, McpReadinessStage.READY_TO_TEST_DRAFT
        return required, McpReadinessStage.READY_TO_CONFIGURE_DRAFT

    required.update(
        {
            McpReadinessCheckId.ACTION_REVIEW,
            McpReadinessCheckId.APP_CONFIGURATION,
            McpReadinessCheckId.TOOL_SNAPSHOT,
        }
    )
    if request.phase is McpDeploymentPhase.PUBLISH:
        return required, McpReadinessStage.READY_FOR_PUBLISH_REVIEW
    if request.plan in (
        ChatGptPlan.BUSINESS,
        ChatGptPlan.ENTERPRISE,
        ChatGptPlan.EDU,
    ):
        required.add(McpReadinessCheckId.WORKSPACE_ACCESS)
    return required, McpReadinessStage.READY_FOR_USE_REVIEW


def evaluate_chatgpt_mcp_connection_readiness(
    *,
    capability_profile: ChatGptMcpCapabilityProfile,
    reconciliation_profile: ChatGptMcpEvidenceReconciliationProfile,
    observation: McpConnectionReadinessObservation,
    evaluated_at: datetime,
) -> McpConnectionReadinessDecision:
    capability_profile = verify_chatgpt_mcp_capability_profile(capability_profile)
    reconciliation_profile = verify_chatgpt_mcp_evidence_reconciliation_profile(
        reconciliation_profile
    )
    observation = verify_mcp_connection_readiness_observation(observation)
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("evaluated_at must include a timezone")
    evaluated_at = evaluated_at.astimezone(timezone.utc)

    if observation.capability_profile_sha256 != capability_profile.profile_sha256:
        raise ValueError("readiness observation capability profile digest mismatch")
    if (
        observation.reconciliation_profile_sha256
        != reconciliation_profile.profile_sha256
    ):
        raise ValueError("readiness observation reconciliation profile digest mismatch")

    deployment = evaluate_chatgpt_mcp_deployment(
        profile=capability_profile,
        request=observation.request,
        evaluated_at=evaluated_at,
    )
    required, target_stage = _required_checks(
        observation=observation,
        requires_developer_mode=deployment.requires_developer_mode,
    )
    by_id = {check.check_id: check for check in observation.checks}
    verified: set[McpReadinessCheckId] = set()
    failed: set[McpReadinessCheckId] = set()
    unknown: set[McpReadinessCheckId] = set()
    not_applicable: set[McpReadinessCheckId] = set()
    for check_id in required:
        state = by_id[check_id].state
        if state is McpReadinessCheckState.VERIFIED:
            verified.add(check_id)
        elif state is McpReadinessCheckState.FAILED:
            failed.add(check_id)
        elif state is McpReadinessCheckState.UNKNOWN:
            unknown.add(check_id)
        else:
            not_applicable.add(check_id)

    reasons: set[McpReadinessReason] = set()
    if not deployment.allowed:
        reasons.add(McpReadinessReason.DEPLOYMENT_POLICY_REFUSED)
    if evaluated_at > reconciliation_profile.revalidate_after:
        reasons.add(McpReadinessReason.EVIDENCE_PROFILE_EXPIRED)
    if observation.observed_at < reconciliation_profile.reviewed_at:
        reasons.add(McpReadinessReason.OBSERVATION_PREDATES_EVIDENCE)
    if evaluated_at < observation.observed_at:
        reasons.add(McpReadinessReason.EVALUATION_PREDATES_OBSERVATION)
    if observation.request.plan is ChatGptPlan.PLUS:
        plus_finding = next(
            finding
            for finding in reconciliation_profile.findings
            if finding.finding_id is McpEvidenceFindingId.PLUS_CUSTOM_MCP_PLAN_SCOPE
        )
        if plus_finding.operational_resolution is McpEvidenceOperationalResolution.FAIL_CLOSED:
            reasons.add(McpReadinessReason.PLUS_PLAN_SCOPE_AMBIGUOUS)
    if failed:
        reasons.add(McpReadinessReason.REQUIRED_CHECK_FAILED)
    if unknown:
        reasons.add(McpReadinessReason.REQUIRED_CHECK_UNKNOWN)
    if not_applicable:
        reasons.add(McpReadinessReason.REQUIRED_CHECK_NOT_APPLICABLE)

    tool_required = McpReadinessCheckId.TOOL_SNAPSHOT in required
    action_review_required = McpReadinessCheckId.ACTION_REVIEW in required
    if tool_required and (
        by_id[McpReadinessCheckId.TOOL_SNAPSHOT].state
        is not McpReadinessCheckState.VERIFIED
    ):
        reasons.add(McpReadinessReason.TOOL_SNAPSHOT_REQUIRED)
    if action_review_required and (
        by_id[McpReadinessCheckId.ACTION_REVIEW].state
        is not McpReadinessCheckState.VERIFIED
    ):
        reasons.add(McpReadinessReason.ACTION_REVIEW_REQUIRED)
    if (
        observation.request.access_mode is McpAccessMode.READ_FETCH
        and observation.write_tool_count is not None
        and observation.write_tool_count > 0
    ):
        reasons.add(McpReadinessReason.READ_FETCH_SNAPSHOT_CONTAINS_WRITE_TOOLS)
    if (
        observation.high_risk_tool_count is not None
        and observation.high_risk_tool_count > 0
    ):
        reasons.add(McpReadinessReason.HIGH_RISK_TOOLS_REQUIRE_SEPARATE_REVIEW)

    warnings = {
        McpReadinessWarning.CHAT_PROJECT_ENUMERATION_UNPROVEN,
        McpReadinessWarning.REAL_CONNECTION_NOT_ESTABLISHED,
        McpReadinessWarning.TOOL_SNAPSHOT_REQUIRES_REFRESH_REVIEW,
        McpReadinessWarning.WRITE_CONFIRMATION_NOT_GUARANTEED,
    }
    if observation.request.plan is ChatGptPlan.PLUS:
        warnings.add(
            McpReadinessWarning.PLUS_GENERAL_AVAILABILITY_NOT_DEPLOYMENT_AUTHORIZATION
        )

    ready = not reasons
    return McpConnectionReadinessDecision(
        observation_id=observation.observation_id,
        ready=ready,
        stage=target_stage if ready else McpReadinessStage.BLOCKED,
        reasons=_sorted_enum_tuple(reasons),
        warnings=_sorted_enum_tuple(warnings),
        required_checks=_sorted_enum_tuple(required),
        verified_checks=_sorted_enum_tuple(verified),
        failed_checks=_sorted_enum_tuple(failed),
        unknown_checks=_sorted_enum_tuple(unknown),
        not_applicable_required_checks=_sorted_enum_tuple(not_applicable),
        deployment_reasons=deployment.reasons,
        selected_transport=deployment.selected_transport if ready else None,
        capability_profile_sha256=capability_profile.profile_sha256,
        reconciliation_profile_sha256=reconciliation_profile.profile_sha256,
        observation_sha256=observation.observation_sha256,
        evaluated_at=evaluated_at,
    )


def verify_chatgpt_mcp_connection_readiness_decision(
    *,
    capability_profile: ChatGptMcpCapabilityProfile,
    reconciliation_profile: ChatGptMcpEvidenceReconciliationProfile,
    observation: McpConnectionReadinessObservation,
    decision: McpConnectionReadinessDecision,
) -> McpConnectionReadinessDecision:
    decision = McpConnectionReadinessDecision.model_validate(
        decision.model_dump(mode="python")
    )
    expected = evaluate_chatgpt_mcp_connection_readiness(
        capability_profile=capability_profile,
        reconciliation_profile=reconciliation_profile,
        observation=observation,
        evaluated_at=decision.evaluated_at,
    )
    if decision != expected:
        raise ValueError("ChatGPT MCP connection readiness decision mismatch")
    return decision
