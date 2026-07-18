from __future__ import annotations

from datetime import datetime, timezone

from .mcp_deployment_models import (
    ChatGptMcpCapabilityProfile,
    ChatGptPlan,
    ChatGptWorkspaceRole,
    McpAccessMode,
    McpAuthenticationKind,
    McpCapabilityId,
    McpCapabilityMatrixRow,
    McpDecisionReason,
    McpDeploymentDecision,
    McpDeploymentPhase,
    McpDeploymentRequest,
    McpPlanEntitlement,
    McpServerLocation,
    McpTransportKind,
    OfficialSourceReference,
    RefreshTokenCapability,
    commit_chatgpt_mcp_capability_profile,
    commit_official_source_reference,
)
from .models import CapabilityClaim, CapabilityEvidence, CapabilitySupport

_REVIEWED_AT = datetime(2026, 7, 18, 0, 0, tzinfo=timezone.utc)
_REVALIDATE_AFTER = datetime(2026, 8, 17, 0, 0, tzinfo=timezone.utc)
_ALL_ROLES = tuple(
    sorted(
        (
            ChatGptWorkspaceRole.ADMIN,
            ChatGptWorkspaceRole.AUTHORIZED_DEVELOPER,
            ChatGptWorkspaceRole.MEMBER,
            ChatGptWorkspaceRole.OWNER,
        ),
        key=lambda item: item.value,
    )
)
_ADMIN_ROLES = tuple(
    sorted(
        (ChatGptWorkspaceRole.ADMIN, ChatGptWorkspaceRole.OWNER),
        key=lambda item: item.value,
    )
)
_ENTERPRISE_DEVELOPER_ROLES = tuple(
    sorted(
        (
            ChatGptWorkspaceRole.ADMIN,
            ChatGptWorkspaceRole.AUTHORIZED_DEVELOPER,
            ChatGptWorkspaceRole.OWNER,
        ),
        key=lambda item: item.value,
    )
)


def _claim(state: CapabilitySupport) -> CapabilityClaim:
    evidence = (
        CapabilityEvidence.NONE
        if state is CapabilitySupport.UNKNOWN
        else CapabilityEvidence.DOCUMENTED
    )
    return CapabilityClaim(state=state, evidence=evidence)


def _source_references() -> tuple[OfficialSourceReference, ...]:
    return (
        commit_official_source_reference(
            source_id="openai_apps_chatgpt",
            title="Apps in ChatGPT",
            url="https://help.openai.com/en/articles/11487775-apps-in-chatgpt",
            section="Apps quickstart and building a custom app",
            evidence_statement=(
                "Custom apps use MCP to let ChatGPT call approved tools; users invoke a connected "
                "app in the current chat by selecting it or mentioning it."
            ),
            reviewed_at=_REVIEWED_AT,
        ),
        commit_official_source_reference(
            source_id="openai_chatgpt_mcp",
            title="Developer mode and MCP apps in ChatGPT",
            url="https://help.openai.com/en/articles/12584461",
            section="Availability, configuration, authentication and FAQ",
            evidence_statement=(
                "Full MCP write/modify support is available on Business and Enterprise/Edu; Pro "
                "supports read/fetch MCP in developer mode; custom MCP is web-only, remote-server "
                "based, supports OAuth, and private/local servers require Secure MCP Tunnel."
            ),
            reviewed_at=_REVIEWED_AT,
        ),
        commit_official_source_reference(
            source_id="openai_chatgpt_projects",
            title="Projects in ChatGPT",
            url="https://help.openai.com/en/articles/10169521-projects-in-chatgpt",
            section="Project availability, memory and chat visibility",
            evidence_statement=(
                "Projects organize chats, files and instructions and may let project chats use "
                "project context, but the article does not document a custom MCP account-wide "
                "chat or project enumeration contract."
            ),
            reviewed_at=_REVIEWED_AT,
        ),
    )


def _matrix_rows() -> tuple[McpCapabilityMatrixRow, ...]:
    mcp = ("openai_chatgpt_mcp",)
    apps = ("openai_apps_chatgpt",)
    projects = ("openai_chatgpt_projects",)
    both = tuple(sorted(mcp + apps))
    rows = (
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.AGENT_MODE_CUSTOM_APPS,
            claim=_claim(CapabilitySupport.UNSUPPORTED),
            source_ids=mcp,
            constraints=("Agent mode does not use custom apps.",),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.AUTOMATIC_TOOL_UPDATES,
            claim=_claim(CapabilitySupport.UNSUPPORTED),
            source_ids=mcp,
            constraints=(
                "Approved tool definitions are frozen until an administrator "
                "reviews and publishes updates.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.CREATE_TEST_READ_FETCH_APP,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=mcp,
            constraints=(
                "Plan and role eligibility is defined by the committed entitlement matrix.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.CREATE_TEST_WRITE_MODIFY_APP,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=mcp,
            constraints=("Full MCP write/modify support is a beta capability.",),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.CURRENT_CHAT_APP_SELECTION,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=apps,
            constraints=(
                "The user selects or mentions the app in the current ChatGPT conversation.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.DEEP_RESEARCH_READ_FETCH,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=mcp,
            constraints=("Deep research can use custom apps only for read/fetch actions.",),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.DEEP_RESEARCH_WRITE,
            claim=_claim(CapabilitySupport.UNSUPPORTED),
            source_ids=mcp,
            constraints=("Deep research cannot use custom apps for write actions.",),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.DIRECT_LOCAL_CONNECTION,
            claim=_claim(CapabilitySupport.UNSUPPORTED),
            source_ids=mcp,
            constraints=(
                "ChatGPT connects to remote MCP servers, not directly to loopback endpoints.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.ENUMERATE_PERSONAL_CHATS,
            claim=_claim(CapabilitySupport.UNKNOWN),
            constraints=(
                "No official custom-MCP contract was found for account-wide personal "
                "chat enumeration.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.ENUMERATE_PROJECTS,
            claim=_claim(CapabilitySupport.UNKNOWN),
            constraints=(
                "No official custom-MCP contract was found for account-wide project enumeration.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.HIGH_RISK_ACTION_APPROVAL_GUARANTEE,
            claim=_claim(CapabilitySupport.UNSUPPORTED),
            source_ids=mcp,
            constraints=(
                "Some especially risky actions may be blocked rather than offered for "
                "confirmation.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.MOBILE_CLIENT,
            claim=_claim(CapabilitySupport.UNSUPPORTED),
            source_ids=mcp,
            constraints=("Custom MCP apps are currently web-only.",),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.MULTIPLE_APPS_SINGLE_PROMPT,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=mcp,
            constraints=(
                "A workspace can invoke multiple first-party and third-party apps in one prompt.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.OAUTH_AUTHORIZATION,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=mcp,
            constraints=(
                "OAuth/OIDC protects the MCP app; ChatGPT account credentials are not replayed.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.OAUTH_REFRESH,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=mcp,
            constraints=(
                "Persistent OAuth connectivity requires refresh-token issuance such as "
                "offline_access.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.PROJECT_HOST_CONTEXT,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=projects,
            constraints=(
                "Projects can contain chats, files and project instructions with bounded "
                "memory scope.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.PUBLISH_CUSTOM_APP,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=mcp,
            constraints=("Only workspace admins/owners publish custom apps.",),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.SEARCH_FETCH_TOOLS_REQUIRED,
            claim=_claim(CapabilitySupport.UNSUPPORTED),
            source_ids=mcp,
            constraints=(
                "Search and fetch tools are no longer mandatory for a connected MCP server.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.SECURE_MCP_TUNNEL,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=mcp,
            constraints=(
                "Private, on-premises and developer-machine servers use Secure MCP Tunnel.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.USE_CONFIGURED_CUSTOM_APP,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=both,
            constraints=(
                "The app must be configured and enabled before the user selects it in chat.",
            ),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.WEB_CLIENT,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=mcp,
            constraints=("Developer mode and custom MCP apps are currently web-only.",),
        ),
        McpCapabilityMatrixRow(
            capability=McpCapabilityId.WRITE_ACTION_CONFIRMATION,
            claim=_claim(CapabilitySupport.SUPPORTED),
            source_ids=mcp,
            constraints=(
                "ChatGPT may request confirmation based on permissions, context and impact.",
            ),
        ),
    )
    return tuple(sorted(rows, key=lambda item: item.capability.value))


def _supported_entitlement(
    *,
    plan: ChatGptPlan,
    phase: McpDeploymentPhase,
    access_mode: McpAccessMode,
    allowed_roles: tuple[ChatGptWorkspaceRole, ...],
    role_refusal_reason: McpDecisionReason | None,
) -> McpPlanEntitlement:
    return McpPlanEntitlement(
        plan=plan,
        phase=phase,
        access_mode=access_mode,
        claim=_claim(CapabilitySupport.SUPPORTED),
        allowed_roles=allowed_roles,
        source_ids=("openai_chatgpt_mcp",),
        role_refusal_reason=role_refusal_reason,
    )


def _unsupported_entitlement(
    *,
    plan: ChatGptPlan,
    phase: McpDeploymentPhase,
    access_mode: McpAccessMode,
    refusal_reasons: tuple[McpDecisionReason, ...],
) -> McpPlanEntitlement:
    return McpPlanEntitlement(
        plan=plan,
        phase=phase,
        access_mode=access_mode,
        claim=_claim(CapabilitySupport.UNSUPPORTED),
        source_ids=("openai_chatgpt_mcp",),
        refusal_reasons=tuple(sorted(refusal_reasons, key=lambda item: item.value)),
    )


def _entitlements() -> tuple[McpPlanEntitlement, ...]:
    rows: list[McpPlanEntitlement] = []
    for plan in (ChatGptPlan.FREE, ChatGptPlan.GO, ChatGptPlan.PLUS):
        for phase in McpDeploymentPhase:
            for access_mode in McpAccessMode:
                rows.append(
                    _unsupported_entitlement(
                        plan=plan,
                        phase=phase,
                        access_mode=access_mode,
                        refusal_reasons=(McpDecisionReason.PLAN_NOT_ELIGIBLE,),
                    )
                )

    for phase in McpDeploymentPhase:
        for access_mode in McpAccessMode:
            if phase is not McpDeploymentPhase.PUBLISH and access_mode is McpAccessMode.READ_FETCH:
                rows.append(
                    _supported_entitlement(
                        plan=ChatGptPlan.PRO,
                        phase=phase,
                        access_mode=access_mode,
                        allowed_roles=_ALL_ROLES,
                        role_refusal_reason=None,
                    )
                )
            else:
                reasons: list[McpDecisionReason] = []
                if access_mode is McpAccessMode.WRITE_MODIFY:
                    reasons.append(McpDecisionReason.PRO_WRITE_UNSUPPORTED)
                if phase is McpDeploymentPhase.PUBLISH:
                    reasons.append(McpDecisionReason.PRO_PUBLISH_UNSUPPORTED)
                rows.append(
                    _unsupported_entitlement(
                        plan=ChatGptPlan.PRO,
                        phase=phase,
                        access_mode=access_mode,
                        refusal_reasons=tuple(reasons),
                    )
                )

    for access_mode in McpAccessMode:
        rows.append(
            _supported_entitlement(
                plan=ChatGptPlan.BUSINESS,
                phase=McpDeploymentPhase.TEST,
                access_mode=access_mode,
                allowed_roles=_ADMIN_ROLES,
                role_refusal_reason=McpDecisionReason.BUSINESS_DEVELOPER_MODE_REQUIRES_ADMIN,
            )
        )
        rows.append(
            _supported_entitlement(
                plan=ChatGptPlan.BUSINESS,
                phase=McpDeploymentPhase.PUBLISH,
                access_mode=access_mode,
                allowed_roles=_ADMIN_ROLES,
                role_refusal_reason=McpDecisionReason.PUBLICATION_REQUIRES_ADMIN_OR_OWNER,
            )
        )
        rows.append(
            _supported_entitlement(
                plan=ChatGptPlan.BUSINESS,
                phase=McpDeploymentPhase.USE,
                access_mode=access_mode,
                allowed_roles=_ALL_ROLES,
                role_refusal_reason=None,
            )
        )

    for plan in (ChatGptPlan.ENTERPRISE, ChatGptPlan.EDU):
        for access_mode in McpAccessMode:
            rows.append(
                _supported_entitlement(
                    plan=plan,
                    phase=McpDeploymentPhase.TEST,
                    access_mode=access_mode,
                    allowed_roles=_ENTERPRISE_DEVELOPER_ROLES,
                    role_refusal_reason=McpDecisionReason.ENTERPRISE_EDU_DEVELOPER_NOT_AUTHORIZED,
                )
            )
            rows.append(
                _supported_entitlement(
                    plan=plan,
                    phase=McpDeploymentPhase.PUBLISH,
                    access_mode=access_mode,
                    allowed_roles=_ADMIN_ROLES,
                    role_refusal_reason=McpDecisionReason.PUBLICATION_REQUIRES_ADMIN_OR_OWNER,
                )
            )
            rows.append(
                _supported_entitlement(
                    plan=plan,
                    phase=McpDeploymentPhase.USE,
                    access_mode=access_mode,
                    allowed_roles=_ALL_ROLES,
                    role_refusal_reason=None,
                )
            )
    return tuple(
        sorted(rows, key=lambda item: (item.plan.value, item.phase.value, item.access_mode.value))
    )


def build_current_chatgpt_mcp_capability_profile() -> ChatGptMcpCapabilityProfile:
    return commit_chatgpt_mcp_capability_profile(
        profile_id="chatgpt_mcp_20260718",
        reviewed_at=_REVIEWED_AT,
        revalidate_after=_REVALIDATE_AFTER,
        sources=_source_references(),
        rows=_matrix_rows(),
        entitlements=_entitlements(),
    )


def verify_chatgpt_mcp_capability_profile(
    profile: ChatGptMcpCapabilityProfile,
) -> ChatGptMcpCapabilityProfile:
    return ChatGptMcpCapabilityProfile.model_validate(profile.model_dump(mode="python"))


def _append_reason(reasons: list[McpDecisionReason], reason: McpDecisionReason) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _sorted_reasons(reasons: list[McpDecisionReason]) -> tuple[McpDecisionReason, ...]:
    return tuple(sorted(reasons, key=lambda item: item.value))


def evaluate_chatgpt_mcp_deployment(
    *,
    profile: ChatGptMcpCapabilityProfile,
    request: McpDeploymentRequest,
    evaluated_at: datetime,
) -> McpDeploymentDecision:
    profile = verify_chatgpt_mcp_capability_profile(profile)
    request = McpDeploymentRequest.model_validate(request.model_dump(mode="python"))
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("evaluated_at must include a timezone")
    evaluated_at = evaluated_at.astimezone(timezone.utc)

    reasons: list[McpDecisionReason] = []
    if evaluated_at > profile.revalidate_after:
        _append_reason(reasons, McpDecisionReason.PROFILE_EXPIRED)
    if request.requested_at < profile.reviewed_at:
        _append_reason(reasons, McpDecisionReason.REQUEST_PREDATES_PROFILE)
    if evaluated_at < request.requested_at:
        _append_reason(reasons, McpDecisionReason.EVALUATION_PREDATES_REQUEST)

    entitlement: McpPlanEntitlement | None = None
    if request.plan is ChatGptPlan.UNKNOWN:
        _append_reason(reasons, McpDecisionReason.UNKNOWN_PLAN)
    else:
        entitlement = next(
            item
            for item in profile.entitlements
            if item.plan is request.plan
            and item.phase is request.phase
            and item.access_mode is request.access_mode
        )
        if entitlement.claim.state is CapabilitySupport.UNSUPPORTED:
            for reason in entitlement.refusal_reasons:
                _append_reason(reasons, reason)
        elif request.role is ChatGptWorkspaceRole.UNKNOWN:
            _append_reason(reasons, McpDecisionReason.UNKNOWN_ROLE)
        elif request.role not in entitlement.allowed_roles:
            if entitlement.role_refusal_reason is None:
                raise ValueError("restricted entitlement is missing a role refusal reason")
            _append_reason(reasons, entitlement.role_refusal_reason)

    if request.plan is ChatGptPlan.UNKNOWN and request.role is ChatGptWorkspaceRole.UNKNOWN:
        _append_reason(reasons, McpDecisionReason.UNKNOWN_ROLE)

    if request.client.value == "unknown":
        _append_reason(reasons, McpDecisionReason.UNKNOWN_CLIENT)
    elif request.client.value != "web":
        _append_reason(reasons, McpDecisionReason.WEB_CLIENT_REQUIRED)

    selected_transport: McpTransportKind | None = None
    if request.server_location is McpServerLocation.UNKNOWN:
        _append_reason(reasons, McpDecisionReason.UNKNOWN_SERVER_LOCATION)
    elif request.server_location is McpServerLocation.PUBLIC_REMOTE:
        selected_transport = McpTransportKind.REMOTE_DIRECT
    else:
        selected_transport = McpTransportKind.SECURE_MCP_TUNNEL

    if request.authentication is McpAuthenticationKind.UNKNOWN:
        _append_reason(reasons, McpDecisionReason.AUTHENTICATION_UNKNOWN)
    elif request.authentication is McpAuthenticationKind.NONE:
        if request.phase in (McpDeploymentPhase.PUBLISH, McpDeploymentPhase.USE):
            _append_reason(
                reasons,
                McpDecisionReason.AUTHENTICATION_REQUIRED_BY_LOCAL_POLICY,
            )
    elif request.persistent_connectivity_required:
        if request.refresh_token_capability is RefreshTokenCapability.NOT_ISSUED:
            _append_reason(reasons, McpDecisionReason.OAUTH_REFRESH_TOKEN_REQUIRED)
        elif request.refresh_token_capability is RefreshTokenCapability.UNKNOWN:
            _append_reason(reasons, McpDecisionReason.OAUTH_REFRESH_CAPABILITY_UNKNOWN)

    if request.require_chat_enumeration:
        _append_reason(reasons, McpDecisionReason.CHAT_ENUMERATION_UNPROVEN)
    if request.require_project_enumeration:
        _append_reason(reasons, McpDecisionReason.PROJECT_ENUMERATION_UNPROVEN)
    if request.require_agent_mode:
        _append_reason(reasons, McpDecisionReason.AGENT_MODE_UNSUPPORTED)
    if request.require_deep_research_write:
        _append_reason(reasons, McpDecisionReason.DEEP_RESEARCH_WRITE_UNSUPPORTED)

    requires_developer_mode = (
        request.phase is not McpDeploymentPhase.USE
        or request.plan is ChatGptPlan.PRO
    )
    if requires_developer_mode and not request.developer_mode_enabled:
        _append_reason(reasons, McpDecisionReason.DEVELOPER_MODE_NOT_ENABLED)
    if request.phase is McpDeploymentPhase.USE and not request.app_configured:
        _append_reason(reasons, McpDecisionReason.APP_NOT_CONFIGURED)
    if (
        request.phase is McpDeploymentPhase.USE
        and request.plan in (
            ChatGptPlan.BUSINESS,
            ChatGptPlan.ENTERPRISE,
            ChatGptPlan.EDU,
        )
        and not request.workspace_app_access_granted
    ):
        _append_reason(
            reasons,
            McpDecisionReason.WORKSPACE_APP_ACCESS_NOT_GRANTED,
        )

    requires_admin_or_owner = bool(
        entitlement is not None
        and entitlement.claim.state is CapabilitySupport.SUPPORTED
        and set(entitlement.allowed_roles) == set(_ADMIN_ROLES)
    )

    if reasons:
        return McpDeploymentDecision(
            request_id=request.request_id,
            allowed=False,
            reasons=_sorted_reasons(reasons),
            selected_transport=None,
            requires_developer_mode=requires_developer_mode,
            requires_admin_or_owner=requires_admin_or_owner,
            evidence_profile_sha256=profile.profile_sha256,
            evaluated_at=evaluated_at,
        )

    approval_reason = (
        McpDecisionReason.APPROVED_WRITE_MODIFY
        if request.access_mode is McpAccessMode.WRITE_MODIFY
        else McpDecisionReason.APPROVED_READ_FETCH
    )
    return McpDeploymentDecision(
        request_id=request.request_id,
        allowed=True,
        reasons=(approval_reason,),
        selected_transport=selected_transport,
        requires_developer_mode=requires_developer_mode,
        requires_admin_or_owner=requires_admin_or_owner,
        evidence_profile_sha256=profile.profile_sha256,
        evaluated_at=evaluated_at,
    )


def verify_chatgpt_mcp_deployment_decision(
    *,
    profile: ChatGptMcpCapabilityProfile,
    request: McpDeploymentRequest,
    decision: McpDeploymentDecision,
) -> McpDeploymentDecision:
    decision = McpDeploymentDecision.model_validate(decision.model_dump(mode="python"))
    expected = evaluate_chatgpt_mcp_deployment(
        profile=profile,
        request=request,
        evaluated_at=decision.evaluated_at,
    )
    if decision != expected:
        raise ValueError("ChatGPT MCP deployment decision mismatch")
    return decision
