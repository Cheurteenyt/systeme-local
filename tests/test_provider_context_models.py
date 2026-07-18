from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from systeme_local_gateway.providers.context_models import (
    AvailabilityState,
    BindingState,
    ConversationPersistence,
    DiscoverySource,
    ExperienceKind,
    ExperienceSelectionDecision,
    PlanKind,
    ProjectMemoryScope,
    ProviderAccountProfile,
    ProviderContextCapabilities,
    ProviderConversationBinding,
    ProviderProjectBinding,
    ProviderQuotaSnapshot,
    QuotaDimension,
    QuotaState,
    QuotaUnit,
    SelectionReason,
    SyncScope,
)
from systeme_local_gateway.providers.models import (
    CapabilityClaim,
    CapabilityEvidence,
    CapabilitySupport,
)

NOW = datetime(2026, 7, 18, 10, 0, tzinfo=timezone.utc)


def unknown_context_capabilities() -> ProviderContextCapabilities:
    unknown = CapabilityClaim(
        state=CapabilitySupport.UNKNOWN,
        evidence=CapabilityEvidence.NONE,
    )
    return ProviderContextCapabilities(
        can_create_projects=unknown,
        can_enumerate_projects=unknown,
        exposes_project_id=unknown,
        can_create_conversations=unknown,
        can_enumerate_conversations=unknown,
        exposes_conversation_id=unknown,
    )


def account(**updates: object) -> ProviderAccountProfile:
    data: dict[str, object] = {
        "account_id": "acct_main",
        "provider": "chatgpt",
        "surface": "visible_account",
        "provider_account_id": "provider-account-1",
        "plan_kind": PlanKind.PAID,
        "plan_code": "plus",
        "availability": AvailabilityState.AVAILABLE,
        "profile_evidence": CapabilityEvidence.OBSERVED,
        "work_capability": CapabilityClaim(
            state=CapabilitySupport.SUPPORTED,
            evidence=CapabilityEvidence.DOCUMENTED,
        ),
        "context_capabilities": unknown_context_capabilities(),
        "revision": 1,
        "created_at": NOW,
        "updated_at": NOW,
    }
    data.update(updates)
    return ProviderAccountProfile(**data)


def test_account_is_strict_and_timezone_safe() -> None:
    with pytest.raises(ValidationError):
        ProviderAccountProfile(**account().model_dump(), unexpected=True)
    with pytest.raises(ValidationError, match="timezone"):
        account(created_at=NOW.replace(tzinfo=None))




def test_context_discovery_capabilities_remain_explicitly_unknown() -> None:
    profile = account()
    assert (
        profile.context_capabilities.can_enumerate_projects.state
        is CapabilitySupport.UNKNOWN
    )
    assert (
        profile.context_capabilities.can_enumerate_conversations.evidence
        is CapabilityEvidence.NONE
    )


def test_account_unknown_availability_requires_no_evidence() -> None:
    with pytest.raises(ValidationError, match="unknown account availability"):
        account(
            availability=AvailabilityState.UNKNOWN,
            profile_evidence=CapabilityEvidence.OBSERVED,
        )
    unknown = account(
        availability=AvailabilityState.UNKNOWN,
        profile_evidence=CapabilityEvidence.NONE,
    )
    assert unknown.availability is AvailabilityState.UNKNOWN


def test_known_account_availability_requires_evidence() -> None:
    with pytest.raises(ValidationError, match="known account availability"):
        account(profile_evidence=CapabilityEvidence.NONE)


def test_plan_kind_and_code_are_consistent() -> None:
    with pytest.raises(ValidationError, match="unknown plans"):
        account(plan_kind=PlanKind.UNKNOWN, plan_code="mystery")
    with pytest.raises(ValidationError, match="known plans require"):
        account(plan_kind=PlanKind.PAID, plan_code=None)


def test_account_revision_window_is_monotonic() -> None:
    with pytest.raises(ValidationError, match="updated_at"):
        account(updated_at=NOW - timedelta(seconds=1))


def test_quota_unknown_state_requires_no_evidence() -> None:
    snapshot = ProviderQuotaSnapshot(
        snapshot_id="quota_unknown",
        account_id="acct_main",
        dimension=QuotaDimension.WORK_AGENTIC,
        state=QuotaState.UNKNOWN,
        evidence=CapabilityEvidence.NONE,
        observed_at=NOW,
    )
    assert snapshot.unit is QuotaUnit.UNKNOWN
    with pytest.raises(ValidationError, match="unknown quota"):
        snapshot.model_copy(update={"evidence": CapabilityEvidence.OBSERVED}).model_validate(
            {**snapshot.model_dump(), "evidence": CapabilityEvidence.OBSERVED}
        )


def test_numeric_quota_requires_known_unit_and_consistent_values() -> None:
    with pytest.raises(ValidationError, match="known unit"):
        ProviderQuotaSnapshot(
            snapshot_id="quota_numeric",
            account_id="acct_main",
            dimension=QuotaDimension.WORK_AGENTIC,
            state=QuotaState.AVAILABLE,
            evidence=CapabilityEvidence.OBSERVED,
            observed_at=NOW,
            remaining_value=2,
            limit_value=10,
        )
    with pytest.raises(ValidationError, match="cannot exceed"):
        ProviderQuotaSnapshot(
            snapshot_id="quota_invalid",
            account_id="acct_main",
            dimension=QuotaDimension.WORK_AGENTIC,
            state=QuotaState.AVAILABLE,
            evidence=CapabilityEvidence.OBSERVED,
            observed_at=NOW,
            remaining_value=11,
            limit_value=10,
            unit=QuotaUnit.CREDITS,
        )


def test_quota_state_matches_numeric_remainder() -> None:
    with pytest.raises(ValidationError, match="positive remainder"):
        ProviderQuotaSnapshot(
            snapshot_id="quota_exhausted",
            account_id="acct_main",
            dimension=QuotaDimension.WORK_AGENTIC,
            state=QuotaState.EXHAUSTED,
            evidence=CapabilityEvidence.OBSERVED,
            observed_at=NOW,
            remaining_value=1,
            limit_value=10,
            unit=QuotaUnit.CREDITS,
        )
    with pytest.raises(ValidationError, match="zero remaining"):
        ProviderQuotaSnapshot(
            snapshot_id="quota_available",
            account_id="acct_main",
            dimension=QuotaDimension.WORK_AGENTIC,
            state=QuotaState.AVAILABLE,
            evidence=CapabilityEvidence.OBSERVED,
            observed_at=NOW,
            remaining_value=0,
            limit_value=10,
            unit=QuotaUnit.CREDITS,
        )


def test_quota_reset_cannot_precede_observation() -> None:
    with pytest.raises(ValidationError, match="reset_at"):
        ProviderQuotaSnapshot(
            snapshot_id="quota_reset",
            account_id="acct_main",
            dimension=QuotaDimension.WORK_AGENTIC,
            state=QuotaState.RESET_PENDING,
            evidence=CapabilityEvidence.OBSERVED,
            observed_at=NOW,
            reset_at=NOW - timedelta(seconds=1),
        )


def test_project_binding_models_memory_scope_and_window() -> None:
    project = ProviderProjectBinding(
        project_id="proj_main",
        account_id="acct_main",
        provider="chatgpt",
        surface="visible_account",
        display_name="Système Local",
        memory_scope=ProjectMemoryScope.PROJECT_ONLY,
        state=BindingState.ACTIVE,
        discovery_source=DiscoverySource.OPERATOR_CONFIRMED,
        revision=1,
        created_at=NOW,
        updated_at=NOW,
    )
    assert project.memory_scope is ProjectMemoryScope.PROJECT_ONLY
    with pytest.raises(ValidationError, match="updated_at"):
        project.model_validate({**project.model_dump(), "updated_at": NOW - timedelta(seconds=1)})


def test_temporary_conversation_cannot_belong_to_project() -> None:
    with pytest.raises(ValidationError, match="temporary conversations"):
        ProviderConversationBinding(
            conversation_id="conv_temp",
            account_id="acct_main",
            project_id="proj_main",
            provider="chatgpt",
            surface="visible_account",
            display_name="Temporary",
            experience=ExperienceKind.CHAT,
            persistence=ConversationPersistence.TEMPORARY,
            sync_scope=SyncScope.CLOUD,
            state=BindingState.ACTIVE,
            discovery_source=DiscoverySource.OPERATOR_CONFIRMED,
            revision=1,
            created_at=NOW,
            updated_at=NOW,
        )


def test_persistent_project_conversation_is_valid() -> None:
    binding = ProviderConversationBinding(
        conversation_id="conv_architecture",
        account_id="acct_main",
        project_id="proj_main",
        provider="chatgpt",
        surface="visible_account",
        display_name="Architecture générale",
        experience=ExperienceKind.CHAT,
        persistence=ConversationPersistence.PERSISTENT,
        sync_scope=SyncScope.CLOUD,
        state=BindingState.ACTIVE,
        discovery_source=DiscoverySource.OPERATOR_CONFIRMED,
        revision=1,
        created_at=NOW,
        updated_at=NOW,
    )
    assert binding.project_id == "proj_main"


def test_selection_decision_rejects_inconsistent_state() -> None:
    with pytest.raises(ValidationError, match="direct Chat decisions"):
        ExperienceSelectionDecision(
            request_id="req_auto",
            account_id="acct_main",
            selected=ExperienceKind.CHAT,
            reason=SelectionReason.DEFAULT_CHAT,
            fallback_used=True,
            user_message_code="CHAT_SELECTED_BY_DEFAULT",
            evaluated_at=NOW,
        )
    with pytest.raises(ValidationError, match="Work fallback decisions"):
        ExperienceSelectionDecision(
            request_id="req_work",
            account_id="acct_main",
            selected=ExperienceKind.WORK,
            reason=SelectionReason.WORK_QUOTA_STALE,
            fallback_used=False,
            user_message_code="WORK_QUOTA_STALE_FALLBACK_CHAT",
            evaluated_at=NOW,
        )


def test_selection_decision_forbids_automatic_credit_purchase() -> None:
    with pytest.raises(ValidationError):
        ExperienceSelectionDecision(
            request_id="req_work",
            account_id="acct_main",
            selected=ExperienceKind.WORK,
            reason=SelectionReason.WORK_AVAILABLE,
            fallback_used=False,
            automatic_credit_purchase=True,
            user_message_code="WORK_SELECTED_EXPLICITLY",
            evaluated_at=NOW,
        )
