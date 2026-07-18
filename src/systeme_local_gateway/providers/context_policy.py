from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .context_models import (
    AvailabilityState,
    ExperienceKind,
    ExperienceRequestKind,
    ExperienceSelectionDecision,
    ExperienceSelectionRequest,
    ProviderAccountProfile,
    ProviderQuotaSnapshot,
    QuotaDimension,
    QuotaState,
    SelectionReason,
)
from .models import CapabilitySupport


DEFAULT_WORK_QUOTA_MAX_AGE = timedelta(minutes=5)


def select_chatgpt_experience(
    *,
    account: ProviderAccountProfile,
    request: ExperienceSelectionRequest,
    evaluated_at: datetime,
    work_quota: ProviderQuotaSnapshot | None = None,
    work_quota_max_age: timedelta = DEFAULT_WORK_QUOTA_MAX_AGE,
) -> ExperienceSelectionDecision:
    evaluated_at = _require_aware(evaluated_at)
    if work_quota_max_age <= timedelta(0):
        raise ValueError("work_quota_max_age must be positive")
    if request.account_id != account.account_id:
        raise ValueError("selection request does not belong to the account")
    if request.requested_at > evaluated_at:
        raise ValueError("selection request cannot be evaluated before it was created")
    if account.updated_at > evaluated_at:
        raise ValueError("account observation cannot be newer than the decision")

    if account.availability is AvailabilityState.UNKNOWN:
        return _decision(
            request=request,
            selected=None,
            reason=SelectionReason.ACCOUNT_UNKNOWN,
            fallback=False,
            code="CHATGPT_ACCOUNT_UNKNOWN",
            evaluated_at=evaluated_at,
        )
    if account.availability is not AvailabilityState.AVAILABLE:
        return _decision(
            request=request,
            selected=None,
            reason=SelectionReason.ACCOUNT_UNAVAILABLE,
            fallback=False,
            code="CHATGPT_ACCOUNT_UNAVAILABLE",
            evaluated_at=evaluated_at,
        )

    if request.requested is ExperienceRequestKind.AUTO:
        return _decision(
            request=request,
            selected=ExperienceKind.CHAT,
            reason=SelectionReason.DEFAULT_CHAT,
            fallback=False,
            code="CHAT_SELECTED_BY_DEFAULT",
            evaluated_at=evaluated_at,
        )
    if request.requested is ExperienceRequestKind.CHAT:
        return _decision(
            request=request,
            selected=ExperienceKind.CHAT,
            reason=SelectionReason.EXPLICIT_CHAT,
            fallback=False,
            code="CHAT_SELECTED_EXPLICITLY",
            evaluated_at=evaluated_at,
        )

    if account.work_capability.state is CapabilitySupport.UNSUPPORTED:
        return _chat_fallback(
            request=request,
            reason=SelectionReason.WORK_UNSUPPORTED,
            code="WORK_UNSUPPORTED_FALLBACK_CHAT",
            evaluated_at=evaluated_at,
        )
    if account.work_capability.state is CapabilitySupport.UNKNOWN:
        return _chat_fallback(
            request=request,
            reason=SelectionReason.WORK_UNKNOWN,
            code="WORK_UNKNOWN_FALLBACK_CHAT",
            evaluated_at=evaluated_at,
        )
    if work_quota is None:
        return _chat_fallback(
            request=request,
            reason=SelectionReason.WORK_QUOTA_MISSING,
            code="WORK_QUOTA_MISSING_FALLBACK_CHAT",
            evaluated_at=evaluated_at,
        )
    if work_quota.account_id != account.account_id:
        raise ValueError("work quota does not belong to the account")
    if work_quota.dimension is not QuotaDimension.WORK_AGENTIC:
        raise ValueError("work selection requires the work_agentic quota dimension")
    if work_quota.observed_at > evaluated_at:
        raise ValueError("quota observation cannot be newer than the decision")
    if evaluated_at - work_quota.observed_at > work_quota_max_age:
        return _chat_fallback(
            request=request,
            reason=SelectionReason.WORK_QUOTA_STALE,
            code="WORK_QUOTA_STALE_FALLBACK_CHAT",
            evaluated_at=evaluated_at,
        )

    if work_quota.state is QuotaState.AVAILABLE:
        return _decision(
            request=request,
            selected=ExperienceKind.WORK,
            reason=SelectionReason.WORK_AVAILABLE,
            fallback=False,
            code="WORK_SELECTED_EXPLICITLY",
            evaluated_at=evaluated_at,
        )
    if work_quota.state is QuotaState.NEAR_LIMIT:
        return _decision(
            request=request,
            selected=ExperienceKind.WORK,
            reason=SelectionReason.WORK_NEAR_LIMIT,
            fallback=False,
            code="WORK_SELECTED_NEAR_LIMIT",
            evaluated_at=evaluated_at,
        )
    if work_quota.state in (QuotaState.EXHAUSTED, QuotaState.RESET_PENDING):
        return _chat_fallback(
            request=request,
            reason=SelectionReason.WORK_QUOTA_EXHAUSTED,
            code="WORK_QUOTA_EXHAUSTED_FALLBACK_CHAT",
            evaluated_at=evaluated_at,
        )
    if work_quota.state is QuotaState.UNAVAILABLE:
        return _chat_fallback(
            request=request,
            reason=SelectionReason.WORK_QUOTA_UNAVAILABLE,
            code="WORK_QUOTA_UNAVAILABLE_FALLBACK_CHAT",
            evaluated_at=evaluated_at,
        )
    return _chat_fallback(
        request=request,
        reason=SelectionReason.WORK_QUOTA_UNKNOWN,
        code="WORK_QUOTA_UNKNOWN_FALLBACK_CHAT",
        evaluated_at=evaluated_at,
    )


def _chat_fallback(
    *,
    request: ExperienceSelectionRequest,
    reason: SelectionReason,
    code: str,
    evaluated_at: datetime,
) -> ExperienceSelectionDecision:
    return _decision(
        request=request,
        selected=ExperienceKind.CHAT,
        reason=reason,
        fallback=True,
        code=code,
        evaluated_at=evaluated_at,
    )


def _decision(
    *,
    request: ExperienceSelectionRequest,
    selected: ExperienceKind | None,
    reason: SelectionReason,
    fallback: bool,
    code: str,
    evaluated_at: datetime,
) -> ExperienceSelectionDecision:
    return ExperienceSelectionDecision(
        request_id=request.request_id,
        account_id=request.account_id,
        selected=selected,
        reason=reason,
        fallback_used=fallback,
        user_message_code=code,
        evaluated_at=evaluated_at,
    )


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)
