from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from systeme_local_gateway.providers.chatgpt_mcp_deployment import (
    build_current_chatgpt_mcp_capability_profile,
    evaluate_chatgpt_mcp_deployment,
    verify_chatgpt_mcp_capability_profile,
    verify_chatgpt_mcp_deployment_decision,
)
from systeme_local_gateway.providers.mcp_deployment_models import (
    ChatGptClientSurface,
    ChatGptPlan,
    ChatGptWorkspaceRole,
    McpAccessMode,
    McpAuthenticationKind,
    McpCapabilityId,
    McpDecisionReason,
    McpDeploymentPhase,
    McpDeploymentRequest,
    McpServerLocation,
    McpTransportKind,
    RefreshTokenCapability,
)
from systeme_local_gateway.providers.models import CapabilitySupport

NOW = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)


def request(**updates: object) -> McpDeploymentRequest:
    data: dict[str, object] = {
        "request_id": "req_mcp",
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
        "app_configured": True,
        "workspace_app_access_granted": True,
        "requested_at": NOW,
    }
    data.update(updates)
    return McpDeploymentRequest(**data)


def decide(**updates: object):
    profile = build_current_chatgpt_mcp_capability_profile()
    return evaluate_chatgpt_mcp_deployment(
        profile=profile,
        request=request(**updates),
        evaluated_at=NOW,
    )


def test_profile_is_complete_digest_bound_and_current() -> None:
    profile = build_current_chatgpt_mcp_capability_profile()
    assert len(profile.rows) == len(McpCapabilityId)
    assert profile.reviewed_at == datetime(2026, 7, 18, tzinfo=timezone.utc)
    assert profile.revalidate_after == datetime(2026, 8, 17, tzinfo=timezone.utc)
    assert verify_chatgpt_mcp_capability_profile(profile) == profile
    tampered = profile.model_copy(update={"profile_sha256": "0" * 64})
    with pytest.raises(ValueError, match="digest mismatch"):
        verify_chatgpt_mcp_capability_profile(tampered)


def test_profile_keeps_chat_and_project_enumeration_unknown() -> None:
    profile = build_current_chatgpt_mcp_capability_profile()
    rows = {row.capability: row for row in profile.rows}
    assert rows[McpCapabilityId.ENUMERATE_PERSONAL_CHATS].claim.state is CapabilitySupport.UNKNOWN
    assert rows[McpCapabilityId.ENUMERATE_PROJECTS].claim.state is CapabilitySupport.UNKNOWN
    assert (
        rows[McpCapabilityId.DIRECT_LOCAL_CONNECTION].claim.state
        is CapabilitySupport.UNSUPPORTED
    )
    assert rows[McpCapabilityId.SECURE_MCP_TUNNEL].claim.state is CapabilitySupport.SUPPORTED


def test_pro_read_fetch_on_web_uses_secure_tunnel() -> None:
    decision = decide()
    assert decision.allowed
    assert decision.reasons == (McpDecisionReason.APPROVED_READ_FETCH,)
    assert decision.selected_transport is McpTransportKind.SECURE_MCP_TUNNEL
    assert not decision.requires_admin_or_owner
    assert decision.user_selects_app_in_current_chat
    assert not decision.automatic_chat_enumeration
    assert not decision.chatgpt_account_credentials_used_by_mcp


def test_public_remote_server_uses_direct_remote_transport() -> None:
    decision = decide(server_location=McpServerLocation.PUBLIC_REMOTE)
    assert decision.allowed
    assert decision.selected_transport is McpTransportKind.REMOTE_DIRECT


@pytest.mark.parametrize("plan", [ChatGptPlan.FREE, ChatGptPlan.GO, ChatGptPlan.PLUS])
def test_noneligible_personal_plans_fail_closed(plan: ChatGptPlan) -> None:
    decision = decide(plan=plan)
    assert not decision.allowed
    assert McpDecisionReason.PLAN_NOT_ELIGIBLE in decision.reasons


def test_unknown_plan_role_client_and_location_are_explicit() -> None:
    decision = decide(
        plan=ChatGptPlan.UNKNOWN,
        role=ChatGptWorkspaceRole.UNKNOWN,
        client=ChatGptClientSurface.UNKNOWN,
        server_location=McpServerLocation.UNKNOWN,
    )
    assert decision.reasons == tuple(
        sorted(
            (
                McpDecisionReason.UNKNOWN_PLAN,
                McpDecisionReason.UNKNOWN_ROLE,
                McpDecisionReason.UNKNOWN_CLIENT,
                McpDecisionReason.UNKNOWN_SERVER_LOCATION,
            ),
            key=lambda item: item.value,
        )
    )


def test_pro_cannot_write_or_publish() -> None:
    write = decide(access_mode=McpAccessMode.WRITE_MODIFY)
    assert write.reasons == (McpDecisionReason.PRO_WRITE_UNSUPPORTED,)
    publish = decide(phase=McpDeploymentPhase.PUBLISH)
    assert publish.reasons == (McpDecisionReason.PRO_PUBLISH_UNSUPPORTED,)


@pytest.mark.parametrize(
    "role",
    [ChatGptWorkspaceRole.MEMBER, ChatGptWorkspaceRole.AUTHORIZED_DEVELOPER],
)
def test_business_testing_requires_admin_or_owner(role: ChatGptWorkspaceRole) -> None:
    decision = decide(plan=ChatGptPlan.BUSINESS, role=role)
    assert decision.reasons == (
        McpDecisionReason.BUSINESS_DEVELOPER_MODE_REQUIRES_ADMIN,
    )


@pytest.mark.parametrize("role", [ChatGptWorkspaceRole.ADMIN, ChatGptWorkspaceRole.OWNER])
def test_business_admin_or_owner_can_test_write(role: ChatGptWorkspaceRole) -> None:
    decision = decide(
        plan=ChatGptPlan.BUSINESS,
        role=role,
        access_mode=McpAccessMode.WRITE_MODIFY,
    )
    assert decision.allowed
    assert decision.reasons == (McpDecisionReason.APPROVED_WRITE_MODIFY,)
    assert decision.requires_admin_or_owner


def test_business_member_can_use_published_app_but_not_create_it() -> None:
    decision = decide(
        plan=ChatGptPlan.BUSINESS,
        role=ChatGptWorkspaceRole.MEMBER,
        phase=McpDeploymentPhase.USE,
        access_mode=McpAccessMode.WRITE_MODIFY,
    )
    assert decision.allowed
    assert not decision.requires_admin_or_owner


def test_enterprise_and_edu_testing_require_authorized_developer() -> None:
    for plan in (ChatGptPlan.ENTERPRISE, ChatGptPlan.EDU):
        member = decide(plan=plan, role=ChatGptWorkspaceRole.MEMBER)
        assert member.reasons == (
            McpDecisionReason.ENTERPRISE_EDU_DEVELOPER_NOT_AUTHORIZED,
        )
        developer = decide(plan=plan, role=ChatGptWorkspaceRole.AUTHORIZED_DEVELOPER)
        assert developer.allowed


def test_publication_requires_admin_or_owner() -> None:
    refused = decide(
        plan=ChatGptPlan.ENTERPRISE,
        role=ChatGptWorkspaceRole.AUTHORIZED_DEVELOPER,
        phase=McpDeploymentPhase.PUBLISH,
    )
    assert refused.reasons == (
        McpDecisionReason.PUBLICATION_REQUIRES_ADMIN_OR_OWNER,
    )
    approved = decide(
        plan=ChatGptPlan.ENTERPRISE,
        role=ChatGptWorkspaceRole.ADMIN,
        phase=McpDeploymentPhase.PUBLISH,
    )
    assert approved.allowed
    assert approved.requires_admin_or_owner


@pytest.mark.parametrize(
    "client",
    [ChatGptClientSurface.IOS, ChatGptClientSurface.ANDROID, ChatGptClientSurface.DESKTOP],
)
def test_custom_mcp_requires_web_client(client: ChatGptClientSurface) -> None:
    decision = decide(client=client)
    assert decision.reasons == (McpDecisionReason.WEB_CLIENT_REQUIRED,)


def test_publish_and_use_require_local_authentication_policy() -> None:
    for phase in (McpDeploymentPhase.PUBLISH, McpDeploymentPhase.USE):
        decision = decide(
            plan=ChatGptPlan.BUSINESS,
            role=ChatGptWorkspaceRole.ADMIN,
            phase=phase,
            authentication=McpAuthenticationKind.NONE,
            refresh_token_capability=RefreshTokenCapability.NOT_APPLICABLE,
        )
        assert McpDecisionReason.AUTHENTICATION_REQUIRED_BY_LOCAL_POLICY in decision.reasons


def test_oauth_persistence_requires_refresh_tokens() -> None:
    missing = decide(refresh_token_capability=RefreshTokenCapability.NOT_ISSUED)
    assert missing.reasons == (McpDecisionReason.OAUTH_REFRESH_TOKEN_REQUIRED,)
    unknown = decide(refresh_token_capability=RefreshTokenCapability.UNKNOWN)
    assert unknown.reasons == (McpDecisionReason.OAUTH_REFRESH_CAPABILITY_UNKNOWN,)
    ephemeral = decide(
        persistent_connectivity_required=False,
        refresh_token_capability=RefreshTokenCapability.NOT_ISSUED,
    )
    assert ephemeral.allowed


def test_chat_and_project_enumeration_requirements_fail_closed() -> None:
    decision = decide(require_chat_enumeration=True, require_project_enumeration=True)
    assert decision.reasons == tuple(
        sorted(
            (
                McpDecisionReason.CHAT_ENUMERATION_UNPROVEN,
                McpDecisionReason.PROJECT_ENUMERATION_UNPROVEN,
            ),
            key=lambda item: item.value,
        )
    )


def test_agent_mode_and_deep_research_write_fail_closed() -> None:
    decision = decide(require_agent_mode=True, require_deep_research_write=True)
    assert decision.reasons == tuple(
        sorted(
            (
                McpDecisionReason.AGENT_MODE_UNSUPPORTED,
                McpDecisionReason.DEEP_RESEARCH_WRITE_UNSUPPORTED,
            ),
            key=lambda item: item.value,
        )
    )


def test_expired_or_predating_evidence_is_rejected() -> None:
    profile = build_current_chatgpt_mcp_capability_profile()
    expired = evaluate_chatgpt_mcp_deployment(
        profile=profile,
        request=request(),
        evaluated_at=profile.revalidate_after + timedelta(seconds=1),
    )
    assert expired.reasons == (McpDecisionReason.PROFILE_EXPIRED,)
    predating = evaluate_chatgpt_mcp_deployment(
        profile=profile,
        request=request(requested_at=profile.reviewed_at - timedelta(seconds=1)),
        evaluated_at=NOW,
    )
    assert predating.reasons == (McpDecisionReason.REQUEST_PREDATES_PROFILE,)



def test_profile_contains_complete_plan_phase_access_grid() -> None:
    profile = build_current_chatgpt_mcp_capability_profile()
    assert len(profile.entitlements) == 42
    keys = {
        (item.plan, item.phase, item.access_mode)
        for item in profile.entitlements
    }
    expected = {
        (plan, phase, access_mode)
        for plan in ChatGptPlan
        if plan is not ChatGptPlan.UNKNOWN
        for phase in McpDeploymentPhase
        for access_mode in McpAccessMode
    }
    assert keys == expected


def test_pro_use_remains_developer_mode_but_workspace_use_does_not() -> None:
    pro = decide(phase=McpDeploymentPhase.USE)
    assert pro.allowed
    assert pro.requires_developer_mode
    business = decide(
        plan=ChatGptPlan.BUSINESS,
        role=ChatGptWorkspaceRole.MEMBER,
        phase=McpDeploymentPhase.USE,
    )
    assert business.allowed
    assert not business.requires_developer_mode


def test_test_and_publish_phases_require_developer_mode() -> None:
    test = decide()
    assert test.requires_developer_mode
    publish = decide(
        plan=ChatGptPlan.BUSINESS,
        role=ChatGptWorkspaceRole.ADMIN,
        phase=McpDeploymentPhase.PUBLISH,
    )
    assert publish.allowed
    assert publish.requires_developer_mode


def test_oidc_with_refresh_tokens_is_allowed() -> None:
    decision = decide(authentication=McpAuthenticationKind.OPENID_CONNECT)
    assert decision.allowed


def test_unknown_authentication_fails_closed() -> None:
    decision = decide(
        authentication=McpAuthenticationKind.UNKNOWN,
        refresh_token_capability=RefreshTokenCapability.UNKNOWN,
    )
    assert decision.reasons == (McpDecisionReason.AUTHENTICATION_UNKNOWN,)


def test_evaluation_cannot_precede_request() -> None:
    profile = build_current_chatgpt_mcp_capability_profile()
    req = request(requested_at=NOW + timedelta(seconds=1))
    decision = evaluate_chatgpt_mcp_deployment(
        profile=profile,
        request=req,
        evaluated_at=NOW,
    )
    assert decision.reasons == (McpDecisionReason.EVALUATION_PREDATES_REQUEST,)


def test_test_phase_may_use_no_auth_only_as_local_prepublication_exception() -> None:
    test = decide(
        authentication=McpAuthenticationKind.NONE,
        refresh_token_capability=RefreshTokenCapability.NOT_APPLICABLE,
    )
    assert test.allowed
    use = decide(
        phase=McpDeploymentPhase.USE,
        authentication=McpAuthenticationKind.NONE,
        refresh_token_capability=RefreshTokenCapability.NOT_APPLICABLE,
    )
    assert use.reasons == (
        McpDecisionReason.AUTHENTICATION_REQUIRED_BY_LOCAL_POLICY,
    )

def test_decision_verification_rejects_tampering() -> None:
    profile = build_current_chatgpt_mcp_capability_profile()
    req = request()
    decision = evaluate_chatgpt_mcp_deployment(
        profile=profile,
        request=req,
        evaluated_at=NOW,
    )
    assert verify_chatgpt_mcp_deployment_decision(
        profile=profile,
        request=req,
        decision=decision,
    ) == decision
    tampered = decision.model_copy(update={"requires_admin_or_owner": True})
    with pytest.raises(ValueError, match="decision mismatch"):
        verify_chatgpt_mcp_deployment_decision(
            profile=profile,
            request=req,
            decision=tampered,
        )


def test_mutated_request_is_revalidated_at_policy_boundary() -> None:
    profile = build_current_chatgpt_mcp_capability_profile()
    req = request()
    object.__setattr__(req, "refresh_token_capability", RefreshTokenCapability.NOT_APPLICABLE)
    with pytest.raises(Exception, match="refresh-token"):
        evaluate_chatgpt_mcp_deployment(
            profile=profile,
            request=req,
            evaluated_at=NOW,
        )


def test_required_developer_mode_must_be_enabled() -> None:
    decision = decide(developer_mode_enabled=False)
    assert decision.reasons == (McpDecisionReason.DEVELOPER_MODE_NOT_ENABLED,)


def test_use_requires_configured_app() -> None:
    decision = decide(phase=McpDeploymentPhase.USE, app_configured=False)
    assert decision.reasons == (McpDecisionReason.APP_NOT_CONFIGURED,)


def test_managed_workspace_use_requires_app_access() -> None:
    decision = decide(
        plan=ChatGptPlan.ENTERPRISE,
        role=ChatGptWorkspaceRole.MEMBER,
        phase=McpDeploymentPhase.USE,
        workspace_app_access_granted=False,
    )
    assert decision.reasons == (
        McpDecisionReason.WORKSPACE_APP_ACCESS_NOT_GRANTED,
    )


def test_published_managed_app_use_does_not_require_developer_mode() -> None:
    decision = decide(
        plan=ChatGptPlan.BUSINESS,
        role=ChatGptWorkspaceRole.MEMBER,
        phase=McpDeploymentPhase.USE,
        access_mode=McpAccessMode.WRITE_MODIFY,
        developer_mode_enabled=False,
    )
    assert decision.allowed
    assert not decision.requires_developer_mode


def test_provider_package_exports_deployment_contract() -> None:
    import systeme_local_gateway.providers as providers

    assert providers.ChatGptMcpCapabilityProfile is not None
    assert providers.evaluate_chatgpt_mcp_deployment is evaluate_chatgpt_mcp_deployment
    assert (
        providers.build_current_chatgpt_mcp_capability_profile
        is build_current_chatgpt_mcp_capability_profile
    )
