from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal, Sequence, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

_ID_PATTERN = r"^[a-z][a-z0-9_]{2,127}$"
_PROVIDER_PATTERN = r"^[a-z][a-z0-9_.-]{1,63}$"
_TOOL_PATTERN = r"^[a-z][a-z0-9_.-]{2,80}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ERROR_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{2,63}$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)


class CapabilitySupport(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class CapabilityEvidence(StrEnum):
    DOCUMENTED = "documented"
    OBSERVED = "observed"
    SIMULATED = "simulated"
    NONE = "none"


class CapabilityClaim(StrictModel):
    state: CapabilitySupport
    evidence: CapabilityEvidence

    @model_validator(mode="after")
    def validate_evidence(self) -> "CapabilityClaim":
        if self.state is CapabilitySupport.UNKNOWN and self.evidence is not CapabilityEvidence.NONE:
            raise ValueError("unknown capabilities must use evidence=none")
        if self.state is not CapabilitySupport.UNKNOWN and self.evidence is CapabilityEvidence.NONE:
            raise ValueError("known capabilities require evidence")
        return self


class ProviderCapabilities(StrictModel):
    provider: str = Field(pattern=_PROVIDER_PATTERN)
    surface: str = Field(pattern=_PROVIDER_PATTERN)
    profile_version: Literal["1"] = "1"
    can_initiate_turn: CapabilityClaim
    can_create_conversation: CapabilityClaim
    can_continue_conversation: CapabilityClaim
    can_enumerate_visible_chats: CapabilityClaim
    exposes_provider_conversation_id: CapabilityClaim
    exposes_terminal_response_event: CapabilityClaim
    supports_streaming: CapabilityClaim
    supports_tool_calls: CapabilityClaim
    supports_cancellation: CapabilityClaim
    supports_resume: CapabilityClaim


class AgentPrincipalRef(StrictModel):
    agent_id: str = Field(pattern=_ID_PATTERN)
    instance_id: str = Field(pattern=_ID_PATTERN)
    key_id: str = Field(pattern=_ID_PATTERN)
    verification_id: str = Field(pattern=_ID_PATTERN)


class CommittedTurn(StrictModel):
    version: Literal["1"] = "1"
    conversation_id: str = Field(pattern=_ID_PATTERN)
    turn_id: str = Field(pattern=_ID_PATTERN)
    trace_id: str = Field(pattern=_ID_PATTERN)
    idempotency_key: str = Field(pattern=_ID_PATTERN)
    principal: AgentPrincipalRef
    committed_at: datetime
    content_sha256: str = Field(pattern=_SHA256_PATTERN)
    utf8_bytes: int = Field(ge=1, le=16 * 1024 * 1024)
    part_count: int = Field(ge=1, le=128)

    _aware_committed_at = field_validator("committed_at")(_require_aware)


def commit_text_turn(
    *,
    conversation_id: str,
    turn_id: str,
    trace_id: str,
    idempotency_key: str,
    principal: AgentPrincipalRef,
    committed_at: datetime,
    parts: Sequence[str],
) -> CommittedTurn:
    if not parts:
        raise ValueError("at least one content part is required")
    if len(parts) > 128:
        raise ValueError("at most 128 content parts are allowed")

    digest = sha256(b"systeme-local:committed-turn:v1\x00")
    total_bytes = 0
    for part in parts:
        if not isinstance(part, str):
            raise TypeError("content parts must be strings")
        encoded = part.encode("utf-8")
        total_bytes += len(encoded)
        if total_bytes > 16 * 1024 * 1024:
            raise ValueError("committed turn exceeds the metadata byte limit")
        digest.update(len(encoded).to_bytes(8, byteorder="big", signed=False))
        digest.update(encoded)

    if total_bytes == 0:
        raise ValueError("committed turn must contain at least one UTF-8 byte")

    return CommittedTurn(
        conversation_id=conversation_id,
        turn_id=turn_id,
        trace_id=trace_id,
        idempotency_key=idempotency_key,
        principal=principal,
        committed_at=committed_at,
        content_sha256=digest.hexdigest(),
        utf8_bytes=total_bytes,
        part_count=len(parts),
    )


class ConversationState(StrEnum):
    ACTIVE = "active"
    CLOSED = "closed"


class ConversationHandle(StrictModel):
    conversation_id: str = Field(pattern=_ID_PATTERN)
    provider: str = Field(pattern=_PROVIDER_PATTERN)
    surface: str = Field(pattern=_PROVIDER_PATTERN)
    created_by_agent: str = Field(pattern=_ID_PATTERN)
    created_at: datetime
    updated_at: datetime
    state: ConversationState = ConversationState.ACTIVE
    provider_conversation_id: str | None = Field(default=None, min_length=1, max_length=256)

    _aware_created_at = field_validator("created_at")(_require_aware)
    _aware_updated_at = field_validator("updated_at")(_require_aware)

    @model_validator(mode="after")
    def validate_window(self) -> "ConversationHandle":
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        return self


class ProviderRun(StrictModel):
    run_id: str = Field(pattern=_ID_PATTERN)
    conversation_id: str = Field(pattern=_ID_PATTERN)
    turn_id: str = Field(pattern=_ID_PATTERN)
    trace_id: str = Field(pattern=_ID_PATTERN)
    idempotency_key: str = Field(pattern=_ID_PATTERN)
    provider: str = Field(pattern=_PROVIDER_PATTERN)
    surface: str = Field(pattern=_PROVIDER_PATTERN)
    started_at: datetime
    provider_run_id: str | None = Field(default=None, min_length=1, max_length=256)

    _aware_started_at = field_validator("started_at")(_require_aware)


class ProviderResponseStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INCOMPLETE = "incomplete"


class ToolResolutionOutcome(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied"


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class LifecycleEventBase(StrictModel):
    version: Literal["1"] = "1"
    kind: str
    event_id: str = Field(pattern=_ID_PATTERN)
    run_id: str = Field(pattern=_ID_PATTERN)
    sequence: int = Field(ge=1)
    observed_at: datetime
    provider_event_id: str | None = Field(default=None, min_length=1, max_length=256)

    _aware_observed_at = field_validator("observed_at")(_require_aware)


class ResponseStartedEvent(LifecycleEventBase):
    kind: Literal["provider_response.started"] = "provider_response.started"
    source: Literal["provider"] = "provider"
    provider_response_id: str = Field(min_length=1, max_length=256)


class OutputDigestDeltaEvent(LifecycleEventBase):
    kind: Literal["provider_response.output_digest"] = "provider_response.output_digest"
    source: Literal["provider"] = "provider"
    delta_sha256: str = Field(pattern=_SHA256_PATTERN)
    utf8_bytes: int = Field(ge=1, le=16 * 1024 * 1024)


class ToolCallRequestedEvent(LifecycleEventBase):
    kind: Literal["provider_tool_call.requested"] = "provider_tool_call.requested"
    source: Literal["provider"] = "provider"
    tool_call_id: str = Field(pattern=_ID_PATTERN)
    provider_tool_call_id: str = Field(min_length=1, max_length=256)
    tool_name: str = Field(pattern=_TOOL_PATTERN)
    arguments_sha256: str = Field(pattern=_SHA256_PATTERN)


class ToolCallResolvedEvent(LifecycleEventBase):
    kind: Literal["provider_tool_call.resolved"] = "provider_tool_call.resolved"
    source: Literal["orchestrator"] = "orchestrator"
    tool_call_id: str = Field(pattern=_ID_PATTERN)
    outcome: ToolResolutionOutcome
    result_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def require_result_digest(self) -> "ToolCallResolvedEvent":
        if self.outcome is ToolResolutionOutcome.COMPLETED and self.result_sha256 is None:
            raise ValueError("completed tool calls require result_sha256")
        return self


class ApprovalRequestedEvent(LifecycleEventBase):
    kind: Literal["approval.requested"] = "approval.requested"
    source: Literal["orchestrator"] = "orchestrator"
    approval_id: str = Field(pattern=_ID_PATTERN)
    tool_call_id: str = Field(pattern=_ID_PATTERN)


class ApprovalResolvedEvent(LifecycleEventBase):
    kind: Literal["approval.resolved"] = "approval.resolved"
    source: Literal["orchestrator"] = "orchestrator"
    approval_id: str = Field(pattern=_ID_PATTERN)
    decision: ApprovalDecision


class ResponseTerminalEvent(LifecycleEventBase):
    kind: Literal["provider_response.terminal"] = "provider_response.terminal"
    source: Literal["provider"] = "provider"
    status: ProviderResponseStatus
    error_code: str | None = Field(default=None, pattern=_ERROR_CODE_PATTERN)

    @model_validator(mode="after")
    def validate_error_code(self) -> "ResponseTerminalEvent":
        if self.status is ProviderResponseStatus.COMPLETED and self.error_code is not None:
            raise ValueError("completed responses cannot carry an error_code")
        if self.status is not ProviderResponseStatus.COMPLETED and self.error_code is None:
            raise ValueError("non-completed responses require an error_code")
        return self


class OutputValidatedEvent(LifecycleEventBase):
    kind: Literal["delegation.output_validated"] = "delegation.output_validated"
    source: Literal["orchestrator"] = "orchestrator"
    output_sha256: str = Field(pattern=_SHA256_PATTERN)
    schema_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    valid: Literal[True] = True


class AuditPersistedEvent(LifecycleEventBase):
    kind: Literal["delegation.audit_persisted"] = "delegation.audit_persisted"
    source: Literal["orchestrator"] = "orchestrator"
    audit_id: str = Field(pattern=_ID_PATTERN)
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)


LifecycleEvent: TypeAlias = Annotated[
    ResponseStartedEvent
    | OutputDigestDeltaEvent
    | ToolCallRequestedEvent
    | ToolCallResolvedEvent
    | ApprovalRequestedEvent
    | ApprovalResolvedEvent
    | ResponseTerminalEvent
    | OutputValidatedEvent
    | AuditPersistedEvent,
    Field(discriminator="kind"),
]

LIFECYCLE_EVENT_ADAPTER = TypeAdapter(LifecycleEvent)
