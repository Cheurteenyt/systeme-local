from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from systeme_local_gateway.providers.context_models import (
    AvailabilityState,
    ExperienceKind,
    ExperienceRequestKind,
    ExperienceSelectionRequest,
    PlanKind,
    ProviderAccountProfile,
    ProviderContextCapabilities,
    ProviderQuotaSnapshot,
    QuotaDimension,
    QuotaState,
    SelectionReason,
)
from systeme_local_gateway.providers.context_policy import select_chatgpt_experience
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


def account(
    *,
    availability: AvailabilityState = AvailabilityState.AVAILABLE,
    work: CapabilitySupport = CapabilitySupport.SUPPORTED,
) -> ProviderAccountProfile:
    return ProviderAccountProfile(
        account_id="acct_main",
        provider="chatgpt",
        surface="visible_account",
        plan_kind=PlanKind.PAID,
        plan_code="plus",
        availability=availability,
        profile_evidence=(
            CapabilityEvidence.NONE
            if availability is AvailabilityState.UNKNOWN
            else CapabilityEvidence.OBSERVED
        ),
        work_capability=CapabilityClaim(
            state=work,
            evidence=(
                CapabilityEvidence.NONE
                if work is CapabilitySupport.UNKNOWN
                else CapabilityEvidence.DOCUMENTED
            ),
        ),
        context_capabilities=unknown_context_capabilities(),
        revision=1,
        created_at=NOW,
        updated_at=NOW,
    )


def request(kind: ExperienceRequestKind) -> ExperienceSelectionRequest:
    return ExperienceSelectionRequest(
        request_id=f"req_{kind.value}",
        account_id="acct_main",
        requested=kind,
        requested_at=NOW,
    )


def quota(state: QuotaState) -> ProviderQuotaSnapshot:
    return ProviderQuotaSnapshot(
        snapshot_id=f"quota_{state.value}",
        account_id="acct_main",
        dimension=QuotaDimension.WORK_AGENTIC,
        state=state,
        evidence=(
            CapabilityEvidence.NONE
            if state is QuotaState.UNKNOWN
            else CapabilityEvidence.OBSERVED
        ),
        observed_at=NOW,
    )


def decide(
    kind: ExperienceRequestKind,
    *,
    profile: ProviderAccountProfile | None = None,
    work_quota: ProviderQuotaSnapshot | None = None,
):
    return select_chatgpt_experience(
        account=profile or account(),
        request=request(kind),
        evaluated_at=NOW,
        work_quota=work_quota,
    )


def test_auto_always_selects_chat() -> None:
    decision = decide(
        ExperienceRequestKind.AUTO,
        work_quota=quota(QuotaState.AVAILABLE),
    )
    assert decision.selected is ExperienceKind.CHAT
    assert decision.reason is SelectionReason.DEFAULT_CHAT
    assert not decision.fallback_used


def test_explicit_chat_selects_chat() -> None:
    decision = decide(ExperienceRequestKind.CHAT)
    assert decision.selected is ExperienceKind.CHAT
    assert decision.reason is SelectionReason.EXPLICIT_CHAT


def test_explicit_work_requires_available_quota() -> None:
    decision = decide(
        ExperienceRequestKind.WORK,
        work_quota=quota(QuotaState.AVAILABLE),
    )
    assert decision.selected is ExperienceKind.WORK
    assert decision.reason is SelectionReason.WORK_AVAILABLE
    assert not decision.automatic_credit_purchase


def test_near_limit_work_remains_available_with_typed_warning() -> None:
    decision = decide(
        ExperienceRequestKind.WORK,
        work_quota=quota(QuotaState.NEAR_LIMIT),
    )
    assert decision.selected is ExperienceKind.WORK
    assert decision.reason is SelectionReason.WORK_NEAR_LIMIT
    assert decision.user_message_code == "WORK_SELECTED_NEAR_LIMIT"


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        (QuotaState.EXHAUSTED, SelectionReason.WORK_QUOTA_EXHAUSTED),
        (QuotaState.RESET_PENDING, SelectionReason.WORK_QUOTA_EXHAUSTED),
        (QuotaState.UNAVAILABLE, SelectionReason.WORK_QUOTA_UNAVAILABLE),
        (QuotaState.UNKNOWN, SelectionReason.WORK_QUOTA_UNKNOWN),
    ],
)
def test_unusable_work_quota_falls_back_to_chat(
    state: QuotaState,
    reason: SelectionReason,
) -> None:
    decision = decide(ExperienceRequestKind.WORK, work_quota=quota(state))
    assert decision.selected is ExperienceKind.CHAT
    assert decision.fallback_used
    assert decision.reason is reason


def test_missing_work_quota_falls_back_to_chat() -> None:
    decision = decide(ExperienceRequestKind.WORK)
    assert decision.selected is ExperienceKind.CHAT
    assert decision.reason is SelectionReason.WORK_QUOTA_MISSING


def test_unsupported_and_unknown_work_fall_back_to_chat() -> None:
    unsupported = decide(
        ExperienceRequestKind.WORK,
        profile=account(work=CapabilitySupport.UNSUPPORTED),
    )
    unknown = decide(
        ExperienceRequestKind.WORK,
        profile=account(work=CapabilitySupport.UNKNOWN),
    )
    assert unsupported.reason is SelectionReason.WORK_UNSUPPORTED
    assert unknown.reason is SelectionReason.WORK_UNKNOWN
    assert unsupported.selected is ExperienceKind.CHAT
    assert unknown.selected is ExperienceKind.CHAT


def test_unavailable_or_unknown_account_selects_no_experience() -> None:
    unavailable = decide(
        ExperienceRequestKind.AUTO,
        profile=account(availability=AvailabilityState.UNAVAILABLE),
    )
    unknown = decide(
        ExperienceRequestKind.AUTO,
        profile=account(availability=AvailabilityState.UNKNOWN),
    )
    assert unavailable.selected is None
    assert unavailable.reason is SelectionReason.ACCOUNT_UNAVAILABLE
    assert unknown.selected is None
    assert unknown.reason is SelectionReason.ACCOUNT_UNKNOWN


def test_selection_rejects_mismatched_account_and_quota() -> None:
    bad_request = request(ExperienceRequestKind.CHAT).model_copy(
        update={"account_id": "acct_other"}
    )
    with pytest.raises(ValueError, match="selection request"):
        select_chatgpt_experience(
            account=account(),
            request=bad_request,
            evaluated_at=NOW,
        )
    bad_quota = quota(QuotaState.AVAILABLE).model_copy(update={"account_id": "acct_other"})
    with pytest.raises(ValueError, match="quota does not belong"):
        select_chatgpt_experience(
            account=account(),
            request=request(ExperienceRequestKind.WORK),
            evaluated_at=NOW,
            work_quota=bad_quota,
        )


def test_selection_rejects_wrong_quota_dimension() -> None:
    wrong = quota(QuotaState.AVAILABLE).model_copy(
        update={"dimension": QuotaDimension.CHAT_MESSAGES}
    )
    with pytest.raises(ValueError, match="work_agentic"):
        select_chatgpt_experience(
            account=account(),
            request=request(ExperienceRequestKind.WORK),
            evaluated_at=NOW,
            work_quota=wrong,
        )


def test_selection_rejects_future_evidence() -> None:
    future_request = request(ExperienceRequestKind.CHAT).model_copy(
        update={"requested_at": NOW + timedelta(seconds=1)}
    )
    with pytest.raises(ValueError, match="before"):
        select_chatgpt_experience(
            account=account(),
            request=future_request,
            evaluated_at=NOW,
        )
    future_quota = quota(QuotaState.AVAILABLE).model_copy(
        update={"observed_at": NOW + timedelta(seconds=1)}
    )
    with pytest.raises(ValueError, match="quota observation"):
        select_chatgpt_experience(
            account=account(),
            request=request(ExperienceRequestKind.WORK),
            evaluated_at=NOW,
            work_quota=future_quota,
        )


def test_selection_rejects_naive_evaluation_time() -> None:
    with pytest.raises(ValueError, match="timezone"):
        select_chatgpt_experience(
            account=account(),
            request=request(ExperienceRequestKind.AUTO),
            evaluated_at=NOW.replace(tzinfo=None),
        )


def test_stale_work_quota_falls_back_to_chat() -> None:
    stale = quota(QuotaState.AVAILABLE).model_copy(
        update={"observed_at": NOW - timedelta(minutes=6)}
    )
    decision = select_chatgpt_experience(
        account=account(),
        request=request(ExperienceRequestKind.WORK),
        evaluated_at=NOW,
        work_quota=stale,
    )
    assert decision.selected is ExperienceKind.CHAT
    assert decision.reason is SelectionReason.WORK_QUOTA_STALE
    assert decision.fallback_used


def test_work_quota_freshness_window_must_be_positive() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        select_chatgpt_experience(
            account=account(),
            request=request(ExperienceRequestKind.WORK),
            evaluated_at=NOW,
            work_quota=quota(QuotaState.AVAILABLE),
            work_quota_max_age=timedelta(0),
        )
