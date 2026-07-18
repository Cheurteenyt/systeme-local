from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from systeme_local_gateway.providers.chatgpt_mcp_deployment import (
    build_current_chatgpt_mcp_capability_profile,
)
from systeme_local_gateway.providers.chatgpt_mcp_readiness import (
    build_current_chatgpt_mcp_evidence_reconciliation_profile,
    evaluate_chatgpt_mcp_connection_readiness,
    verify_chatgpt_mcp_connection_readiness_decision,
)
from systeme_local_gateway.providers.mcp_deployment_models import (
    ChatGptClientSurface,
    ChatGptPlan,
    ChatGptWorkspaceRole,
    McpAccessMode,
    McpAuthenticationKind,
    McpDecisionReason,
    McpDeploymentPhase,
    McpDeploymentRequest,
    McpServerLocation,
    McpTransportKind,
    RefreshTokenCapability,
)
from systeme_local_gateway.providers.mcp_readiness_models import (
    McpReadinessCheckId,
    McpReadinessCheckState,
    McpReadinessReason,
    McpReadinessStage,
    McpReadinessWarning,
    commit_mcp_connection_readiness_observation,
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


def check_states_for_base_ready() -> dict[McpReadinessCheckId, McpReadinessCheckState]:
    return {
        McpReadinessCheckId.AUTHENTICATION_METADATA: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.DEVELOPER_MODE: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.LOCAL_POLICY: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.PLAN_ROLE_OBSERVATION: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.REFRESH_TOKEN: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.TRANSPORT: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.WEB_CLIENT: McpReadinessCheckState.VERIFIED,
    }


def checks(
    states: dict[McpReadinessCheckId, McpReadinessCheckState] | None = None,
    *,
    checked_at: datetime = NOW,
) -> tuple:
    states = states or {}
    result = []
    for check_id in McpReadinessCheckId:
        state = states.get(check_id, McpReadinessCheckState.UNKNOWN)
        evidence = DIGEST if state in (
            McpReadinessCheckState.VERIFIED,
            McpReadinessCheckState.FAILED,
        ) else None
        detail = "CHECK_FAILED" if state is McpReadinessCheckState.FAILED else None
        result.append(
            commit_mcp_readiness_check(
                check_id=check_id,
                state=state,
                checked_at=checked_at,
                evidence_sha256=evidence,
                detail_code=detail,
            )
        )
    return tuple(result)


def observation(
    *,
    deployment_request: McpDeploymentRequest | None = None,
    states: dict[McpReadinessCheckId, McpReadinessCheckState] | None = None,
    observed_at: datetime = NOW,
    tool_count: int | None = None,
    write_tool_count: int | None = None,
    high_risk_tool_count: int | None = None,
    capability_digest: str | None = None,
    reconciliation_digest: str | None = None,
):
    capability = build_current_chatgpt_mcp_capability_profile()
    reconciliation = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    states = states or {}
    tool_verified = (
        states.get(McpReadinessCheckId.TOOL_SNAPSHOT)
        is McpReadinessCheckState.VERIFIED
    )
    local_policy_verified = (
        states.get(McpReadinessCheckId.LOCAL_POLICY)
        is McpReadinessCheckState.VERIFIED
    )
    return commit_mcp_connection_readiness_observation(
        observation_id="obs_readiness",
        request=deployment_request or request(),
        capability_profile_sha256=capability_digest or capability.profile_sha256,
        reconciliation_profile_sha256=(
            reconciliation_digest or reconciliation.profile_sha256
        ),
        checks=checks(states, checked_at=observed_at),
        tool_snapshot_sha256=DIGEST if tool_verified else None,
        tool_count=tool_count if tool_verified else None,
        write_tool_count=write_tool_count if tool_verified else None,
        high_risk_tool_count=high_risk_tool_count if tool_verified else None,
        local_policy_sha256="b" * 64 if local_policy_verified else None,
        observed_at=observed_at,
    )


def evaluate(item, *, reconciliation=None, evaluated_at=NOW):
    return evaluate_chatgpt_mcp_connection_readiness(
        capability_profile=build_current_chatgpt_mcp_capability_profile(),
        reconciliation_profile=(
            reconciliation or build_current_chatgpt_mcp_evidence_reconciliation_profile()
        ),
        observation=item,
        evaluated_at=evaluated_at,
    )


def test_current_reconciliation_profile_is_short_lived_and_complete() -> None:
    profile = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    assert profile.revalidate_after - profile.reviewed_at == timedelta(days=14)
    assert len(profile.findings) == 5
    assert len(profile.sources) == 6


def test_pro_read_fetch_can_be_ready_to_configure_draft() -> None:
    decision = evaluate(observation(states=check_states_for_base_ready()))
    assert decision.ready is True
    assert decision.stage is McpReadinessStage.READY_TO_CONFIGURE_DRAFT
    assert decision.selected_transport is McpTransportKind.SECURE_MCP_TUNNEL
    assert decision.reasons == ()
    assert decision.real_connection_established is False
    assert decision.secrets_stored is False


def test_configured_test_requires_tool_snapshot_and_action_review() -> None:
    states = check_states_for_base_ready()
    states[McpReadinessCheckId.APP_CONFIGURATION] = McpReadinessCheckState.VERIFIED
    decision = evaluate(observation(states=states))
    assert decision.ready is False
    assert decision.stage is McpReadinessStage.BLOCKED
    assert McpReadinessReason.TOOL_SNAPSHOT_REQUIRED in decision.reasons
    assert McpReadinessReason.ACTION_REVIEW_REQUIRED in decision.reasons


def test_configured_test_with_reviewed_snapshot_is_ready_to_test() -> None:
    states = check_states_for_base_ready()
    states.update(
        {
            McpReadinessCheckId.ACTION_REVIEW: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.APP_CONFIGURATION: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED,
        }
    )
    decision = evaluate(
        observation(
            states=states,
            tool_count=4,
            write_tool_count=0,
            high_risk_tool_count=0,
        )
    )
    assert decision.ready is True
    assert decision.stage is McpReadinessStage.READY_TO_TEST_DRAFT


def test_business_admin_write_publish_can_reach_publish_review() -> None:
    states = check_states_for_base_ready()
    states.update(
        {
            McpReadinessCheckId.ACTION_REVIEW: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.APP_CONFIGURATION: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED,
        }
    )
    item = observation(
        deployment_request=request(
            plan=ChatGptPlan.BUSINESS,
            role=ChatGptWorkspaceRole.ADMIN,
            phase=McpDeploymentPhase.PUBLISH,
            access_mode=McpAccessMode.WRITE_MODIFY,
            app_configured=True,
        ),
        states=states,
        tool_count=4,
        write_tool_count=2,
        high_risk_tool_count=0,
    )
    decision = evaluate(item)
    assert decision.ready is True
    assert decision.stage is McpReadinessStage.READY_FOR_PUBLISH_REVIEW
    assert decision.deployment_reasons == (McpDecisionReason.APPROVED_WRITE_MODIFY,)


def test_managed_use_requires_workspace_access() -> None:
    states = check_states_for_base_ready()
    states.pop(McpReadinessCheckId.DEVELOPER_MODE)
    states.update(
        {
            McpReadinessCheckId.ACTION_REVIEW: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.APP_CONFIGURATION: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED,
        }
    )
    item = observation(
        deployment_request=request(
            plan=ChatGptPlan.ENTERPRISE,
            role=ChatGptWorkspaceRole.MEMBER,
            phase=McpDeploymentPhase.USE,
            app_configured=True,
            workspace_app_access_granted=True,
        ),
        states=states,
        tool_count=3,
        write_tool_count=0,
        high_risk_tool_count=0,
    )
    decision = evaluate(item)
    assert decision.ready is False
    assert McpReadinessCheckId.WORKSPACE_ACCESS in decision.unknown_checks
    assert McpReadinessReason.REQUIRED_CHECK_UNKNOWN in decision.reasons


def test_managed_use_with_workspace_access_is_ready_for_use_review() -> None:
    states = check_states_for_base_ready()
    states.pop(McpReadinessCheckId.DEVELOPER_MODE)
    states.update(
        {
            McpReadinessCheckId.ACTION_REVIEW: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.APP_CONFIGURATION: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.WORKSPACE_ACCESS: McpReadinessCheckState.VERIFIED,
        }
    )
    item = observation(
        deployment_request=request(
            plan=ChatGptPlan.ENTERPRISE,
            role=ChatGptWorkspaceRole.MEMBER,
            phase=McpDeploymentPhase.USE,
            app_configured=True,
            workspace_app_access_granted=True,
        ),
        states=states,
        tool_count=3,
        write_tool_count=0,
        high_risk_tool_count=0,
    )
    decision = evaluate(item)
    assert decision.ready is True
    assert decision.stage is McpReadinessStage.READY_FOR_USE_REVIEW


def test_plus_fails_closed_for_both_policy_and_evidence_ambiguity() -> None:
    item = observation(
        deployment_request=request(plan=ChatGptPlan.PLUS),
        states=check_states_for_base_ready(),
    )
    decision = evaluate(item)
    assert decision.ready is False
    assert McpReadinessReason.DEPLOYMENT_POLICY_REFUSED in decision.reasons
    assert McpReadinessReason.PLUS_PLAN_SCOPE_AMBIGUOUS in decision.reasons
    assert (
        McpReadinessWarning.PLUS_GENERAL_AVAILABILITY_NOT_DEPLOYMENT_AUTHORIZATION
        in decision.warnings
    )


def test_read_fetch_snapshot_with_write_tools_is_blocked() -> None:
    states = check_states_for_base_ready()
    states.update(
        {
            McpReadinessCheckId.ACTION_REVIEW: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.APP_CONFIGURATION: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED,
        }
    )
    decision = evaluate(
        observation(
            states=states,
            tool_count=3,
            write_tool_count=1,
            high_risk_tool_count=0,
        )
    )
    assert decision.ready is False
    assert (
        McpReadinessReason.READ_FETCH_SNAPSHOT_CONTAINS_WRITE_TOOLS
        in decision.reasons
    )


def test_high_risk_tools_require_a_separate_review() -> None:
    states = check_states_for_base_ready()
    states.update(
        {
            McpReadinessCheckId.ACTION_REVIEW: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.APP_CONFIGURATION: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED,
        }
    )
    decision = evaluate(
        observation(
            states=states,
            tool_count=3,
            write_tool_count=0,
            high_risk_tool_count=1,
        )
    )
    assert decision.ready is False
    assert (
        McpReadinessReason.HIGH_RISK_TOOLS_REQUIRE_SEPARATE_REVIEW
        in decision.reasons
    )


@pytest.mark.parametrize(
    "check_id",
    [
        McpReadinessCheckId.AUTHENTICATION_METADATA,
        McpReadinessCheckId.DEVELOPER_MODE,
        McpReadinessCheckId.LOCAL_POLICY,
        McpReadinessCheckId.PLAN_ROLE_OBSERVATION,
        McpReadinessCheckId.REFRESH_TOKEN,
        McpReadinessCheckId.TRANSPORT,
        McpReadinessCheckId.WEB_CLIENT,
    ],
)
def test_each_unknown_base_check_blocks_configuration(
    check_id: McpReadinessCheckId,
) -> None:
    states = check_states_for_base_ready()
    states[check_id] = McpReadinessCheckState.UNKNOWN
    decision = evaluate(observation(states=states))
    assert decision.ready is False
    assert check_id in decision.unknown_checks
    assert McpReadinessReason.REQUIRED_CHECK_UNKNOWN in decision.reasons


@pytest.mark.parametrize(
    "state,reason",
    [
        (McpReadinessCheckState.FAILED, McpReadinessReason.REQUIRED_CHECK_FAILED),
        (
            McpReadinessCheckState.NOT_APPLICABLE,
            McpReadinessReason.REQUIRED_CHECK_NOT_APPLICABLE,
        ),
    ],
)
def test_failed_or_invalid_not_applicable_required_check_blocks(
    state: McpReadinessCheckState,
    reason: McpReadinessReason,
) -> None:
    states = check_states_for_base_ready()
    states[McpReadinessCheckId.TRANSPORT] = state
    decision = evaluate(observation(states=states))
    assert decision.ready is False
    assert reason in decision.reasons


def test_no_auth_bounded_test_does_not_require_auth_or_refresh_checks() -> None:
    states = check_states_for_base_ready()
    states.pop(McpReadinessCheckId.AUTHENTICATION_METADATA)
    states.pop(McpReadinessCheckId.REFRESH_TOKEN)
    item = observation(
        deployment_request=request(
            authentication=McpAuthenticationKind.NONE,
            refresh_token_capability=RefreshTokenCapability.NOT_APPLICABLE,
            persistent_connectivity_required=False,
        ),
        states=states,
    )
    decision = evaluate(item)
    assert decision.ready is True
    assert McpReadinessCheckId.AUTHENTICATION_METADATA not in decision.required_checks
    assert McpReadinessCheckId.REFRESH_TOKEN not in decision.required_checks


def test_nonpersistent_oauth_does_not_require_refresh_check() -> None:
    states = check_states_for_base_ready()
    states.pop(McpReadinessCheckId.REFRESH_TOKEN)
    item = observation(
        deployment_request=request(persistent_connectivity_required=False),
        states=states,
    )
    decision = evaluate(item)
    assert decision.ready is True
    assert McpReadinessCheckId.REFRESH_TOKEN not in decision.required_checks


def test_deployment_policy_refusal_is_preserved() -> None:
    item = observation(
        deployment_request=request(
            require_chat_enumeration=True,
        ),
        states=check_states_for_base_ready(),
    )
    decision = evaluate(item)
    assert decision.ready is False
    assert McpReadinessReason.DEPLOYMENT_POLICY_REFUSED in decision.reasons
    assert McpDecisionReason.CHAT_ENUMERATION_UNPROVEN in decision.deployment_reasons


def test_mobile_client_is_refused_before_readiness() -> None:
    item = observation(
        deployment_request=request(client=ChatGptClientSurface.IOS),
        states=check_states_for_base_ready(),
    )
    decision = evaluate(item)
    assert decision.ready is False
    assert McpDecisionReason.WEB_CLIENT_REQUIRED in decision.deployment_reasons


def test_unknown_plan_and_role_are_refused() -> None:
    item = observation(
        deployment_request=request(
            plan=ChatGptPlan.UNKNOWN,
            role=ChatGptWorkspaceRole.UNKNOWN,
        ),
        states=check_states_for_base_ready(),
    )
    decision = evaluate(item)
    assert decision.ready is False
    assert McpDecisionReason.UNKNOWN_PLAN in decision.deployment_reasons
    assert McpDecisionReason.UNKNOWN_ROLE in decision.deployment_reasons


def test_expired_reconciliation_blocks_readiness() -> None:
    profile = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    decision = evaluate(
        observation(states=check_states_for_base_ready()),
        reconciliation=profile,
        evaluated_at=profile.revalidate_after + timedelta(seconds=1),
    )
    assert McpReadinessReason.EVIDENCE_PROFILE_EXPIRED in decision.reasons


def test_observation_predating_reconciliation_is_blocked() -> None:
    profile = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    item = observation(
        states=check_states_for_base_ready(),
        observed_at=profile.reviewed_at - timedelta(seconds=1),
    )
    decision = evaluate(item, reconciliation=profile)
    assert McpReadinessReason.OBSERVATION_PREDATES_EVIDENCE in decision.reasons


def test_evaluation_predating_observation_is_blocked() -> None:
    item = observation(states=check_states_for_base_ready())
    decision = evaluate(item, evaluated_at=NOW - timedelta(seconds=1))
    assert McpReadinessReason.EVALUATION_PREDATES_OBSERVATION in decision.reasons


def test_profile_digest_mismatches_are_rejected() -> None:
    with pytest.raises(ValueError, match="capability profile digest mismatch"):
        evaluate(observation(states=check_states_for_base_ready(), capability_digest="b" * 64))
    with pytest.raises(ValueError, match="reconciliation profile digest mismatch"):
        evaluate(
            observation(
                states=check_states_for_base_ready(),
                reconciliation_digest="b" * 64,
            )
        )


def test_evaluated_at_requires_timezone() -> None:
    with pytest.raises(ValueError, match="timezone"):
        evaluate(
            observation(states=check_states_for_base_ready()),
            evaluated_at=NOW.replace(tzinfo=None),
        )


def test_decision_reverification_rejects_tampering() -> None:
    item = observation(states=check_states_for_base_ready())
    capability = build_current_chatgpt_mcp_capability_profile()
    reconciliation = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    decision = evaluate_chatgpt_mcp_connection_readiness(
        capability_profile=capability,
        reconciliation_profile=reconciliation,
        observation=item,
        evaluated_at=NOW,
    )
    verified = verify_chatgpt_mcp_connection_readiness_decision(
        capability_profile=capability,
        reconciliation_profile=reconciliation,
        observation=item,
        decision=decision,
    )
    assert verified == decision
    tampered = decision.model_copy(update={"stage": McpReadinessStage.READY_TO_TEST_DRAFT})
    with pytest.raises(ValueError, match="decision mismatch"):
        verify_chatgpt_mcp_connection_readiness_decision(
            capability_profile=capability,
            reconciliation_profile=reconciliation,
            observation=item,
            decision=tampered,
        )


def test_ready_decision_carries_all_persistent_warnings() -> None:
    decision = evaluate(observation(states=check_states_for_base_ready()))
    assert set(decision.warnings) == {
        McpReadinessWarning.CHAT_PROJECT_ENUMERATION_UNPROVEN,
        McpReadinessWarning.REAL_CONNECTION_NOT_ESTABLISHED,
        McpReadinessWarning.TOOL_SNAPSHOT_REQUIRES_REFRESH_REVIEW,
        McpReadinessWarning.WRITE_CONFIRMATION_NOT_GUARANTEED,
    }


def test_public_remote_selects_direct_transport() -> None:
    item = observation(
        deployment_request=request(server_location=McpServerLocation.PUBLIC_REMOTE),
        states=check_states_for_base_ready(),
    )
    decision = evaluate(item)
    assert decision.ready is True
    assert decision.selected_transport is McpTransportKind.REMOTE_DIRECT


def test_blocked_decision_never_selects_transport() -> None:
    states = check_states_for_base_ready()
    states[McpReadinessCheckId.TRANSPORT] = McpReadinessCheckState.UNKNOWN
    decision = evaluate(observation(states=states))
    assert decision.ready is False
    assert decision.selected_transport is None


def test_provider_package_exports_readiness_contract() -> None:
    import systeme_local_gateway.providers as providers

    for name in (
        "ChatGptMcpEvidenceReconciliationProfile",
        "McpConnectionReadinessObservation",
        "McpConnectionReadinessDecision",
        "build_current_chatgpt_mcp_evidence_reconciliation_profile",
        "evaluate_chatgpt_mcp_connection_readiness",
        "verify_chatgpt_mcp_connection_readiness_decision",
    ):
        assert name in providers.__all__
        assert getattr(providers, name) is not None
