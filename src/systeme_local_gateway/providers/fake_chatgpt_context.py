from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256

from .context_models import (
    AvailabilityState,
    BindingState,
    ConversationPersistence,
    DiscoverySource,
    ExperienceKind,
    PlanKind,
    ProjectMemoryScope,
    ProviderAccountProfile,
    ProviderContextCapabilities,
    ProviderConversationBinding,
    ProviderProjectBinding,
    ProviderQuotaSnapshot,
    QuotaDimension,
    QuotaState,
    SyncScope,
)
from .models import CapabilityClaim, CapabilityEvidence, CapabilitySupport


class FakeChatGptContextScenario(StrEnum):
    FREE_CHAT_ONLY = "free_chat_only"
    PAID_WORK_AVAILABLE = "paid_work_available"
    PAID_WORK_NEAR_LIMIT = "paid_work_near_limit"
    PAID_WORK_EXHAUSTED = "paid_work_exhausted"
    WORK_UNKNOWN = "work_unknown"
    MANAGED_WORK_UNAVAILABLE = "managed_work_unavailable"


@dataclass(frozen=True)
class FakeChatGptContextSnapshot:
    account: ProviderAccountProfile
    work_quota: ProviderQuotaSnapshot | None
    project: ProviderProjectBinding
    chat: ProviderConversationBinding


class DeterministicFakeChatGptContext:
    provider = "chatgpt"
    surface = "visible_account"

    def build(
        self,
        *,
        scenario: FakeChatGptContextScenario,
        observed_at: datetime,
    ) -> FakeChatGptContextSnapshot:
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        observed_at = observed_at.astimezone(timezone.utc)
        account_id = _stable_id("acct_", scenario.value)
        plan_kind, plan_code, work_support, quota_state = _scenario_values(scenario)
        account = ProviderAccountProfile(
            account_id=account_id,
            provider=self.provider,
            surface=self.surface,
            provider_account_id=_stable_id("fakeacct_", scenario.value),
            plan_kind=plan_kind,
            plan_code=plan_code,
            availability=AvailabilityState.AVAILABLE,
            profile_evidence=CapabilityEvidence.SIMULATED,
            work_capability=CapabilityClaim(
                state=work_support,
                evidence=(
                    CapabilityEvidence.NONE
                    if work_support is CapabilitySupport.UNKNOWN
                    else CapabilityEvidence.SIMULATED
                ),
            ),
            context_capabilities=_unknown_context_capabilities(),
            revision=1,
            created_at=observed_at,
            updated_at=observed_at,
        )
        quota = None
        if quota_state is not None:
            quota = ProviderQuotaSnapshot(
                snapshot_id=_stable_id("quota_", scenario.value, observed_at.isoformat()),
                account_id=account_id,
                dimension=QuotaDimension.WORK_AGENTIC,
                state=quota_state,
                evidence=(
                    CapabilityEvidence.NONE
                    if quota_state is QuotaState.UNKNOWN
                    else CapabilityEvidence.SIMULATED
                ),
                observed_at=observed_at,
            )
        project_id = _stable_id("proj_", account_id, "systeme_local")
        project = ProviderProjectBinding(
            project_id=project_id,
            account_id=account_id,
            provider=self.provider,
            surface=self.surface,
            provider_project_id=_stable_id("fakeproj_", account_id),
            display_name="Système Local",
            memory_scope=ProjectMemoryScope.PROJECT_ONLY,
            state=BindingState.ACTIVE,
            discovery_source=DiscoverySource.SIMULATED,
            revision=1,
            created_at=observed_at,
            updated_at=observed_at,
        )
        chat = ProviderConversationBinding(
            conversation_id=_stable_id("conv_", account_id, "architecture"),
            account_id=account_id,
            project_id=project_id,
            provider=self.provider,
            surface=self.surface,
            provider_conversation_id=_stable_id("fakechat_", account_id),
            display_name="Architecture générale",
            experience=ExperienceKind.CHAT,
            persistence=ConversationPersistence.PERSISTENT,
            sync_scope=SyncScope.CLOUD,
            state=BindingState.ACTIVE,
            discovery_source=DiscoverySource.SIMULATED,
            revision=1,
            created_at=observed_at,
            updated_at=observed_at,
        )
        return FakeChatGptContextSnapshot(
            account=account,
            work_quota=quota,
            project=project,
            chat=chat,
        )


def _unknown_context_capabilities() -> ProviderContextCapabilities:
    def unknown() -> CapabilityClaim:
        return CapabilityClaim(
            state=CapabilitySupport.UNKNOWN,
            evidence=CapabilityEvidence.NONE,
        )

    return ProviderContextCapabilities(
        can_create_projects=unknown(),
        can_enumerate_projects=unknown(),
        exposes_project_id=unknown(),
        can_create_conversations=unknown(),
        can_enumerate_conversations=unknown(),
        exposes_conversation_id=unknown(),
    )


def _scenario_values(
    scenario: FakeChatGptContextScenario,
) -> tuple[PlanKind, str | None, CapabilitySupport, QuotaState | None]:
    if scenario is FakeChatGptContextScenario.FREE_CHAT_ONLY:
        return PlanKind.FREE, "free", CapabilitySupport.UNSUPPORTED, None
    if scenario is FakeChatGptContextScenario.PAID_WORK_AVAILABLE:
        return PlanKind.PAID, "paid_eligible", CapabilitySupport.SUPPORTED, QuotaState.AVAILABLE
    if scenario is FakeChatGptContextScenario.PAID_WORK_NEAR_LIMIT:
        return PlanKind.PAID, "paid_eligible", CapabilitySupport.SUPPORTED, QuotaState.NEAR_LIMIT
    if scenario is FakeChatGptContextScenario.PAID_WORK_EXHAUSTED:
        return PlanKind.PAID, "paid_eligible", CapabilitySupport.SUPPORTED, QuotaState.EXHAUSTED
    if scenario is FakeChatGptContextScenario.WORK_UNKNOWN:
        return PlanKind.UNKNOWN, None, CapabilitySupport.UNKNOWN, QuotaState.UNKNOWN
    return PlanKind.MANAGED, "managed", CapabilitySupport.SUPPORTED, QuotaState.UNAVAILABLE


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "\x00".join(parts).encode("utf-8")
    return prefix + sha256(payload).hexdigest()[:24]
