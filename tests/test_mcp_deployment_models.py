from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from systeme_local_gateway.providers.mcp_deployment_models import (
    ChatGptClientSurface,
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
    RefreshTokenCapability,
    commit_chatgpt_mcp_capability_profile,
    commit_official_source_reference,
)
from systeme_local_gateway.providers.models import (
    CapabilityClaim,
    CapabilityEvidence,
    CapabilitySupport,
)

NOW = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
ALL_ROLES = tuple(
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


def source(**updates: object):
    data: dict[str, object] = {
        "source_id": "openai_source",
        "title": "OpenAI source",
        "url": "https://help.openai.com/en/articles/12584461",
        "section": "Availability",
        "evidence_statement": "A bounded paraphrase of the documented capability.",
        "reviewed_at": NOW,
    }
    data.update(updates)
    return commit_official_source_reference(**data)


def known_row(capability: McpCapabilityId, **updates: object) -> McpCapabilityMatrixRow:
    data: dict[str, object] = {
        "capability": capability,
        "claim": CapabilityClaim(
            state=CapabilitySupport.SUPPORTED,
            evidence=CapabilityEvidence.DOCUMENTED,
        ),
        "source_ids": ("openai_source",),
    }
    data.update(updates)
    return McpCapabilityMatrixRow(**data)


def supported_entitlement(**updates: object) -> McpPlanEntitlement:
    data: dict[str, object] = {
        "plan": ChatGptPlan.PRO,
        "phase": McpDeploymentPhase.TEST,
        "access_mode": McpAccessMode.READ_FETCH,
        "claim": CapabilityClaim(
            state=CapabilitySupport.SUPPORTED,
            evidence=CapabilityEvidence.DOCUMENTED,
        ),
        "allowed_roles": ALL_ROLES,
        "source_ids": ("openai_source",),
    }
    data.update(updates)
    return McpPlanEntitlement(**data)


def unsupported_entitlement(**updates: object) -> McpPlanEntitlement:
    data: dict[str, object] = {
        "plan": ChatGptPlan.PLUS,
        "phase": McpDeploymentPhase.TEST,
        "access_mode": McpAccessMode.READ_FETCH,
        "claim": CapabilityClaim(
            state=CapabilitySupport.UNSUPPORTED,
            evidence=CapabilityEvidence.DOCUMENTED,
        ),
        "source_ids": ("openai_source",),
        "refusal_reasons": (McpDecisionReason.PLAN_NOT_ELIGIBLE,),
    }
    data.update(updates)
    return McpPlanEntitlement(**data)


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


def test_official_source_is_frozen_strict_and_digest_bound() -> None:
    item = source()
    with pytest.raises(ValidationError):
        item.model_validate({**item.model_dump(), "extra": True})
    with pytest.raises(ValidationError, match="digest mismatch"):
        item.model_validate({**item.model_dump(), "title": "Changed"})
    with pytest.raises(ValidationError):
        item.title = "Changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "url",
    [
        "http://help.openai.com/en/articles/12584461",
        "https://example.com/en/articles/12584461",
        "https://user:pass@help.openai.com/en/articles/12584461",
        "https://help.openai.com/en/articles/12584461?tracking=1",
        "https://help.openai.com/en/articles/12584461#faq",
    ],
)
def test_official_source_rejects_noncanonical_or_nonofficial_urls(url: str) -> None:
    with pytest.raises(ValidationError):
        source(url=url)


def test_source_normalizes_equivalent_timezone_offsets() -> None:
    utc = source()
    offset = source(reviewed_at=NOW.astimezone(timezone(timedelta(hours=2))))
    assert utc.statement_sha256 == offset.statement_sha256
    assert offset.reviewed_at == NOW


def test_known_row_requires_sources_and_sorted_constraints() -> None:
    with pytest.raises(ValidationError, match="require official sources"):
        known_row(McpCapabilityId.WEB_CLIENT, source_ids=())
    with pytest.raises(ValidationError, match="constraints must be sorted"):
        known_row(
            McpCapabilityId.WEB_CLIENT,
            constraints=("z", "a"),
        )


def test_unknown_row_cannot_claim_official_sources() -> None:
    unknown = McpCapabilityMatrixRow(
        capability=McpCapabilityId.ENUMERATE_PERSONAL_CHATS,
        claim=CapabilityClaim(
            state=CapabilitySupport.UNKNOWN,
            evidence=CapabilityEvidence.NONE,
        ),
        constraints=("No official contract found.",),
    )
    assert unknown.source_ids == ()
    with pytest.raises(ValidationError, match="cannot claim official sources"):
        unknown.model_validate(
            {
                **unknown.model_dump(),
                "source_ids": ("openai_source",),
            }
        )


def test_supported_entitlement_requires_roles_and_role_reason_when_restricted() -> None:
    with pytest.raises(ValidationError, match="require allowed_roles"):
        supported_entitlement(allowed_roles=())
    with pytest.raises(ValidationError, match="require role_refusal_reason"):
        supported_entitlement(
            allowed_roles=(ChatGptWorkspaceRole.ADMIN,),
        )
    restricted = supported_entitlement(
        allowed_roles=(ChatGptWorkspaceRole.ADMIN,),
        role_refusal_reason=McpDecisionReason.PUBLICATION_REQUIRES_ADMIN_OR_OWNER,
    )
    assert restricted.allowed_roles == (ChatGptWorkspaceRole.ADMIN,)


def test_supported_entitlement_cannot_carry_refusal_reasons() -> None:
    with pytest.raises(ValidationError, match="cannot carry refusal_reasons"):
        supported_entitlement(
            refusal_reasons=(McpDecisionReason.PLAN_NOT_ELIGIBLE,),
        )


def test_unsupported_entitlement_requires_reasons_and_no_roles() -> None:
    with pytest.raises(ValidationError, match="require refusal_reasons"):
        unsupported_entitlement(refusal_reasons=())
    with pytest.raises(ValidationError, match="cannot allow roles"):
        unsupported_entitlement(allowed_roles=ALL_ROLES)


def test_entitlement_rejects_unknown_plan_and_unsorted_reasons() -> None:
    with pytest.raises(ValidationError, match="unknown plan"):
        unsupported_entitlement(plan=ChatGptPlan.UNKNOWN)
    with pytest.raises(ValidationError, match="refusal_reasons must be sorted"):
        unsupported_entitlement(
            refusal_reasons=(
                McpDecisionReason.PRO_WRITE_UNSUPPORTED,
                McpDecisionReason.PRO_PUBLISH_UNSUPPORTED,
            )
        )


def test_profile_requires_complete_capability_and_entitlement_matrices() -> None:
    item = source()
    row = known_row(McpCapabilityId.WEB_CLIENT)
    entitlement = supported_entitlement()
    with pytest.raises(ValidationError, match="capability matrix must be complete"):
        commit_chatgpt_mcp_capability_profile(
            profile_id="chatgpt_mcp_test",
            reviewed_at=NOW,
            revalidate_after=NOW + timedelta(days=30),
            sources=(item,),
            rows=(row,),
            entitlements=(entitlement,),
        )


def test_profile_rejects_excessive_revalidation_window() -> None:
    from systeme_local_gateway.providers.chatgpt_mcp_deployment import (
        build_current_chatgpt_mcp_capability_profile,
    )

    profile = build_current_chatgpt_mcp_capability_profile()
    with pytest.raises(ValidationError, match="within 31 days"):
        profile.model_validate(
            {
                **profile.model_dump(),
                "revalidate_after": profile.reviewed_at + timedelta(days=32),
            }
        )


def test_profile_rejects_unknown_source_reference_and_unused_source() -> None:
    from systeme_local_gateway.providers.chatgpt_mcp_deployment import (
        build_current_chatgpt_mcp_capability_profile,
    )

    profile = build_current_chatgpt_mcp_capability_profile()
    row = profile.rows[0].model_copy(update={"source_ids": ("missing",)})
    with pytest.raises(ValidationError, match="unknown source"):
        profile.model_validate(
            {
                **profile.model_dump(),
                "rows": (row, *profile.rows[1:]),
            }
        )
    extra_source = source(
        source_id="unused_source",
        reviewed_at=profile.reviewed_at,
    )
    with pytest.raises(ValidationError, match="must be referenced"):
        profile.model_validate(
            {
                **profile.model_dump(),
                "sources": tuple(
                    sorted(
                        (*profile.sources, extra_source),
                        key=lambda item: item.source_id,
                    )
                ),
            }
        )


def test_request_authentication_contract() -> None:
    with pytest.raises(ValidationError, match="not_applicable"):
        request(
            authentication=McpAuthenticationKind.NONE,
            refresh_token_capability=RefreshTokenCapability.UNKNOWN,
        )
    with pytest.raises(ValidationError, match="explicit refresh-token"):
        request(refresh_token_capability=RefreshTokenCapability.NOT_APPLICABLE)
    with pytest.raises(ValidationError, match="unknown authentication"):
        request(
            authentication=McpAuthenticationKind.UNKNOWN,
            refresh_token_capability=RefreshTokenCapability.ISSUED,
        )


def test_request_requires_timezone() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        request(requested_at=NOW.replace(tzinfo=None))


def test_allowed_decision_requires_transport_and_single_approval_reason() -> None:
    with pytest.raises(ValidationError, match="selected transport"):
        McpDeploymentDecision(
            request_id="req_mcp",
            allowed=True,
            reasons=(McpDecisionReason.APPROVED_READ_FETCH,),
            selected_transport=None,
            requires_developer_mode=True,
            requires_admin_or_owner=False,
            evidence_profile_sha256="a" * 64,
            evaluated_at=NOW,
        )
    with pytest.raises(ValidationError, match="cannot contain refusal"):
        McpDeploymentDecision(
            request_id="req_mcp",
            allowed=True,
            reasons=tuple(
                sorted(
                    (
                        McpDecisionReason.APPROVED_READ_FETCH,
                        McpDecisionReason.WEB_CLIENT_REQUIRED,
                    ),
                    key=lambda item: item.value,
                )
            ),
            selected_transport=McpTransportKind.SECURE_MCP_TUNNEL,
            requires_developer_mode=True,
            requires_admin_or_owner=False,
            evidence_profile_sha256="a" * 64,
            evaluated_at=NOW,
        )


def test_refused_decision_cannot_select_transport_or_approval() -> None:
    with pytest.raises(ValidationError, match="cannot select a transport"):
        McpDeploymentDecision(
            request_id="req_mcp",
            allowed=False,
            reasons=(McpDecisionReason.WEB_CLIENT_REQUIRED,),
            selected_transport=McpTransportKind.REMOTE_DIRECT,
            requires_developer_mode=True,
            requires_admin_or_owner=False,
            evidence_profile_sha256="a" * 64,
            evaluated_at=NOW,
        )
    with pytest.raises(ValidationError, match="cannot contain an approval"):
        McpDeploymentDecision(
            request_id="req_mcp",
            allowed=False,
            reasons=(McpDecisionReason.APPROVED_READ_FETCH,),
            selected_transport=None,
            requires_developer_mode=True,
            requires_admin_or_owner=False,
            evidence_profile_sha256="a" * 64,
            evaluated_at=NOW,
        )


def test_decision_reasons_must_be_sorted_and_unique() -> None:
    with pytest.raises(ValidationError, match="must be sorted"):
        McpDeploymentDecision(
            request_id="req_mcp",
            allowed=False,
            reasons=(
                McpDecisionReason.WEB_CLIENT_REQUIRED,
                McpDecisionReason.PLAN_NOT_ELIGIBLE,
            ),
            selected_transport=None,
            requires_developer_mode=True,
            requires_admin_or_owner=False,
            evidence_profile_sha256="a" * 64,
            evaluated_at=NOW,
        )


def test_profile_requires_source_review_timestamp_alignment() -> None:
    from systeme_local_gateway.providers.chatgpt_mcp_deployment import (
        build_current_chatgpt_mcp_capability_profile,
    )

    profile = build_current_chatgpt_mcp_capability_profile()
    original = profile.sources[0]
    shifted = commit_official_source_reference(
        source_id=original.source_id,
        title=original.title,
        url=original.url,
        section=original.section,
        evidence_statement=original.evidence_statement,
        reviewed_at=profile.reviewed_at + timedelta(seconds=1),
    )
    with pytest.raises(ValidationError, match="review timestamps"):
        profile.model_validate(
            {
                **profile.model_dump(),
                "sources": (shifted, *profile.sources[1:]),
            }
        )
