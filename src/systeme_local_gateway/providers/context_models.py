from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from .models import CapabilityClaim, CapabilityEvidence, StrictModel

_ID_PATTERN = r"^[a-z][a-z0-9_]{2,127}$"
_PROVIDER_PATTERN = r"^[a-z][a-z0-9_.-]{1,63}$"
_PLAN_PATTERN = r"^[a-z][a-z0-9_.-]{1,63}$"
_MESSAGE_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{2,63}$"


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def _optional_aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return _require_aware(value)


class PlanKind(StrEnum):
    FREE = "free"
    PAID = "paid"
    MANAGED = "managed"
    UNKNOWN = "unknown"


class AvailabilityState(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class ExperienceKind(StrEnum):
    CHAT = "chat"
    WORK = "work"


class ExperienceRequestKind(StrEnum):
    AUTO = "auto"
    CHAT = "chat"
    WORK = "work"


class QuotaDimension(StrEnum):
    CHAT_MESSAGES = "chat_messages"
    WORK_AGENTIC = "work_agentic"
    FILE_UPLOAD_RATE = "file_upload_rate"
    FILE_STORAGE = "file_storage"
    PROJECT_FILE_SLOTS = "project_file_slots"


class QuotaState(StrEnum):
    AVAILABLE = "available"
    NEAR_LIMIT = "near_limit"
    EXHAUSTED = "exhausted"
    RESET_PENDING = "reset_pending"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class QuotaUnit(StrEnum):
    REQUESTS = "requests"
    FILES = "files"
    BYTES = "bytes"
    CREDITS = "credits"
    UNKNOWN = "unknown"


class ProjectMemoryScope(StrEnum):
    PROJECT_ONLY = "project_only"
    DEFAULT = "default"
    UNKNOWN = "unknown"


class BindingState(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"
    INACCESSIBLE = "inaccessible"
    UNKNOWN = "unknown"


class DiscoverySource(StrEnum):
    OPERATOR_CONFIRMED = "operator_confirmed"
    PROVIDER_RETURNED = "provider_returned"
    OFFICIAL_CONNECTOR = "official_connector"
    COMPLIANCE_API = "compliance_api"
    SHARED_REFERENCE = "shared_reference"
    SIMULATED = "simulated"


class ConversationPersistence(StrEnum):
    PERSISTENT = "persistent"
    TEMPORARY = "temporary"
    UNKNOWN = "unknown"


class SyncScope(StrEnum):
    CLOUD = "cloud"
    DEVICE_LOCAL = "device_local"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class ProviderContextCapabilities(StrictModel):
    can_create_projects: CapabilityClaim
    can_enumerate_projects: CapabilityClaim
    exposes_project_id: CapabilityClaim
    can_create_conversations: CapabilityClaim
    can_enumerate_conversations: CapabilityClaim
    exposes_conversation_id: CapabilityClaim


class SelectionReason(StrEnum):
    ACCOUNT_UNAVAILABLE = "account_unavailable"
    ACCOUNT_UNKNOWN = "account_unknown"
    DEFAULT_CHAT = "default_chat"
    EXPLICIT_CHAT = "explicit_chat"
    WORK_AVAILABLE = "work_available"
    WORK_NEAR_LIMIT = "work_near_limit"
    WORK_UNSUPPORTED = "work_unsupported"
    WORK_UNKNOWN = "work_unknown"
    WORK_QUOTA_MISSING = "work_quota_missing"
    WORK_QUOTA_EXHAUSTED = "work_quota_exhausted"
    WORK_QUOTA_UNAVAILABLE = "work_quota_unavailable"
    WORK_QUOTA_UNKNOWN = "work_quota_unknown"
    WORK_QUOTA_STALE = "work_quota_stale"


class ProviderAccountProfile(StrictModel):
    version: Literal["1"] = "1"
    account_id: str = Field(pattern=_ID_PATTERN)
    provider: str = Field(pattern=_PROVIDER_PATTERN)
    surface: str = Field(pattern=_PROVIDER_PATTERN)
    provider_account_id: str | None = Field(default=None, min_length=1, max_length=256)
    plan_kind: PlanKind
    plan_code: str | None = Field(default=None, pattern=_PLAN_PATTERN)
    availability: AvailabilityState
    profile_evidence: CapabilityEvidence
    work_capability: CapabilityClaim
    context_capabilities: ProviderContextCapabilities
    revision: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime

    _aware_created_at = field_validator("created_at")(_require_aware)
    _aware_updated_at = field_validator("updated_at")(_require_aware)

    @model_validator(mode="after")
    def validate_profile(self) -> "ProviderAccountProfile":
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        if self.availability is AvailabilityState.UNKNOWN:
            if self.profile_evidence is not CapabilityEvidence.NONE:
                raise ValueError("unknown account availability requires evidence=none")
        elif self.profile_evidence is CapabilityEvidence.NONE:
            raise ValueError("known account availability requires evidence")
        if self.plan_kind is PlanKind.UNKNOWN and self.plan_code is not None:
            raise ValueError("unknown plans cannot carry plan_code")
        if self.plan_kind is not PlanKind.UNKNOWN and self.plan_code is None:
            raise ValueError("known plans require plan_code")
        return self


class ProviderQuotaSnapshot(StrictModel):
    version: Literal["1"] = "1"
    snapshot_id: str = Field(pattern=_ID_PATTERN)
    account_id: str = Field(pattern=_ID_PATTERN)
    dimension: QuotaDimension
    state: QuotaState
    evidence: CapabilityEvidence
    observed_at: datetime
    reset_at: datetime | None = None
    remaining_value: int | None = Field(default=None, ge=0)
    limit_value: int | None = Field(default=None, ge=1)
    unit: QuotaUnit = QuotaUnit.UNKNOWN

    _aware_observed_at = field_validator("observed_at")(_require_aware)
    _aware_reset_at = field_validator("reset_at")(_optional_aware)

    @model_validator(mode="after")
    def validate_snapshot(self) -> "ProviderQuotaSnapshot":
        if self.state is QuotaState.UNKNOWN:
            if self.evidence is not CapabilityEvidence.NONE:
                raise ValueError("unknown quota state requires evidence=none")
        elif self.evidence is CapabilityEvidence.NONE:
            raise ValueError("known quota state requires evidence")
        if self.reset_at is not None and self.reset_at < self.observed_at:
            raise ValueError("reset_at must not precede observed_at")
        if self.remaining_value is not None or self.limit_value is not None:
            if self.unit is QuotaUnit.UNKNOWN:
                raise ValueError("numeric quota evidence requires a known unit")
        elif self.unit is not QuotaUnit.UNKNOWN:
            raise ValueError("quota unit requires numeric evidence")
        if (
            self.remaining_value is not None
            and self.limit_value is not None
            and self.remaining_value > self.limit_value
        ):
            raise ValueError("remaining_value cannot exceed limit_value")
        if self.state is QuotaState.EXHAUSTED and self.remaining_value not in (None, 0):
            raise ValueError("exhausted quota cannot report a positive remainder")
        if self.state in (QuotaState.AVAILABLE, QuotaState.NEAR_LIMIT) and self.remaining_value == 0:
            raise ValueError("usable quota cannot report zero remaining")
        return self


class ProviderProjectBinding(StrictModel):
    version: Literal["1"] = "1"
    project_id: str = Field(pattern=_ID_PATTERN)
    account_id: str = Field(pattern=_ID_PATTERN)
    provider: str = Field(pattern=_PROVIDER_PATTERN)
    surface: str = Field(pattern=_PROVIDER_PATTERN)
    provider_project_id: str | None = Field(default=None, min_length=1, max_length=256)
    display_name: str = Field(min_length=1, max_length=200)
    memory_scope: ProjectMemoryScope
    state: BindingState
    discovery_source: DiscoverySource
    revision: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime

    _aware_created_at = field_validator("created_at")(_require_aware)
    _aware_updated_at = field_validator("updated_at")(_require_aware)

    @model_validator(mode="after")
    def validate_window(self) -> "ProviderProjectBinding":
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        return self


class ProviderConversationBinding(StrictModel):
    version: Literal["1"] = "1"
    conversation_id: str = Field(pattern=_ID_PATTERN)
    account_id: str = Field(pattern=_ID_PATTERN)
    project_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    provider: str = Field(pattern=_PROVIDER_PATTERN)
    surface: str = Field(pattern=_PROVIDER_PATTERN)
    provider_conversation_id: str | None = Field(default=None, min_length=1, max_length=256)
    display_name: str = Field(min_length=1, max_length=200)
    experience: ExperienceKind
    persistence: ConversationPersistence
    sync_scope: SyncScope
    state: BindingState
    discovery_source: DiscoverySource
    revision: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime

    _aware_created_at = field_validator("created_at")(_require_aware)
    _aware_updated_at = field_validator("updated_at")(_require_aware)

    @model_validator(mode="after")
    def validate_binding(self) -> "ProviderConversationBinding":
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        if self.persistence is ConversationPersistence.TEMPORARY and self.project_id is not None:
            raise ValueError("temporary conversations cannot belong to a project")
        return self


class ExperienceSelectionRequest(StrictModel):
    version: Literal["1"] = "1"
    request_id: str = Field(pattern=_ID_PATTERN)
    account_id: str = Field(pattern=_ID_PATTERN)
    requested: ExperienceRequestKind = ExperienceRequestKind.AUTO
    requested_at: datetime

    _aware_requested_at = field_validator("requested_at")(_require_aware)


class ExperienceSelectionDecision(StrictModel):
    version: Literal["1"] = "1"
    request_id: str = Field(pattern=_ID_PATTERN)
    account_id: str = Field(pattern=_ID_PATTERN)
    selected: ExperienceKind | None
    reason: SelectionReason
    fallback_used: bool
    automatic_credit_purchase: Literal[False] = False
    user_message_code: str = Field(pattern=_MESSAGE_CODE_PATTERN)
    evaluated_at: datetime

    _aware_evaluated_at = field_validator("evaluated_at")(_require_aware)

    @model_validator(mode="after")
    def validate_decision(self) -> "ExperienceSelectionDecision":
        unavailable_reasons = {
            SelectionReason.ACCOUNT_UNAVAILABLE,
            SelectionReason.ACCOUNT_UNKNOWN,
        }
        direct_chat_reasons = {
            SelectionReason.DEFAULT_CHAT,
            SelectionReason.EXPLICIT_CHAT,
        }
        work_reasons = {
            SelectionReason.WORK_AVAILABLE,
            SelectionReason.WORK_NEAR_LIMIT,
        }
        fallback_reasons = {
            SelectionReason.WORK_UNSUPPORTED,
            SelectionReason.WORK_UNKNOWN,
            SelectionReason.WORK_QUOTA_MISSING,
            SelectionReason.WORK_QUOTA_EXHAUSTED,
            SelectionReason.WORK_QUOTA_UNAVAILABLE,
            SelectionReason.WORK_QUOTA_UNKNOWN,
            SelectionReason.WORK_QUOTA_STALE,
        }
        if self.reason in unavailable_reasons:
            if self.selected is not None or self.fallback_used:
                raise ValueError("unavailable accounts cannot select an experience")
        elif self.reason in direct_chat_reasons:
            if self.selected is not ExperienceKind.CHAT or self.fallback_used:
                raise ValueError("direct Chat decisions cannot be fallbacks")
        elif self.reason in work_reasons:
            if self.selected is not ExperienceKind.WORK or self.fallback_used:
                raise ValueError("Work decisions require a direct Work selection")
        elif self.reason in fallback_reasons:
            if self.selected is not ExperienceKind.CHAT or not self.fallback_used:
                raise ValueError("Work fallback decisions must select Chat")
        return self
