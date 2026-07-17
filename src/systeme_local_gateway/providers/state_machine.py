from __future__ import annotations

from datetime import datetime
from hashlib import sha256

from pydantic import Field

from .models import (
    ApprovalRequestedEvent,
    ApprovalResolvedEvent,
    AuditPersistedEvent,
    LifecycleEvent,
    OutputDigestDeltaEvent,
    OutputValidatedEvent,
    ProviderResponseStatus,
    ProviderRun,
    ResponseStartedEvent,
    ResponseTerminalEvent,
    StrictModel,
    ToolCallRequestedEvent,
    ToolCallResolvedEvent,
    ToolResolutionOutcome,
)


class LifecycleError(RuntimeError):
    """Base class for deterministic lifecycle failures."""


class EventConflictError(LifecycleError):
    pass


class EventSequenceGapError(LifecycleError):
    pass


class InvalidLifecycleTransition(LifecycleError):
    pass


class AppliedEventReceipt(StrictModel):
    sequence: int = Field(ge=1)
    event_id: str
    fingerprint: str


class ToolCallState(StrictModel):
    tool_call_id: str
    provider_tool_call_id: str
    tool_name: str
    arguments_sha256: str
    outcome: ToolResolutionOutcome | None = None
    result_sha256: str | None = None


class ProviderRunState(StrictModel):
    run: ProviderRun
    last_sequence: int = Field(default=0, ge=0)
    last_observed_at: datetime | None = None
    response_started: bool = False
    response_status: ProviderResponseStatus | None = None
    output_digests: list[str] = Field(default_factory=list)
    pending_tool_calls: dict[str, ToolCallState] = Field(default_factory=dict)
    resolved_tool_calls: dict[str, ToolCallState] = Field(default_factory=dict)
    pending_approvals: dict[str, str] = Field(default_factory=dict)
    resolved_approvals: dict[str, str] = Field(default_factory=dict)
    output_validated: bool = False
    output_sha256: str | None = None
    audit_id: str | None = None
    audit_receipt_sha256: str | None = None
    provider_event_ids: dict[str, str] = Field(default_factory=dict)
    applied_events: list[AppliedEventReceipt] = Field(default_factory=list)

    @property
    def delegation_completed(self) -> bool:
        return (
            self.response_status is ProviderResponseStatus.COMPLETED
            and not self.pending_tool_calls
            and not self.pending_approvals
            and self.output_validated
            and self.audit_id is not None
        )

    @property
    def delegation_terminal(self) -> bool:
        return (
            self.response_status is not None
            and not self.pending_tool_calls
            and not self.pending_approvals
            and self.audit_id is not None
        )


def lifecycle_event_fingerprint(event: LifecycleEvent) -> str:
    payload = event.model_dump_json(exclude_none=False, by_alias=True)
    return sha256(payload.encode("utf-8")).hexdigest()


def initial_run_state(run: ProviderRun) -> ProviderRunState:
    return ProviderRunState(run=run)


def apply_lifecycle_event(
    state: ProviderRunState,
    event: LifecycleEvent,
) -> ProviderRunState:
    if event.run_id != state.run.run_id:
        raise EventConflictError("event run_id does not match the provider run")

    fingerprint = lifecycle_event_fingerprint(event)

    if event.sequence <= state.last_sequence:
        receipt = next(
            (item for item in state.applied_events if item.sequence == event.sequence),
            None,
        )
        if (
            receipt is not None
            and receipt.event_id == event.event_id
            and receipt.fingerprint == fingerprint
        ):
            return state
        raise EventConflictError("conflicting event replay")

    if event.sequence != state.last_sequence + 1:
        raise EventSequenceGapError("event sequence contains a gap")

    if event.observed_at < state.run.started_at:
        raise InvalidLifecycleTransition("event cannot precede the provider run")
    if state.last_observed_at is not None and event.observed_at < state.last_observed_at:
        raise InvalidLifecycleTransition("event observation time cannot move backwards")

    if any(item.event_id == event.event_id for item in state.applied_events):
        raise EventConflictError("event_id has already been used")

    if (
        event.provider_event_id is not None
        and event.provider_event_id in state.provider_event_ids
    ):
        raise EventConflictError("provider_event_id has already been used")

    if state.audit_id is not None:
        raise InvalidLifecycleTransition("no new events are allowed after audit persistence")

    updated = state.model_copy(deep=True)

    if isinstance(event, ResponseStartedEvent):
        if updated.response_started or updated.response_status is not None:
            raise InvalidLifecycleTransition("response has already started")
        updated.response_started = True

    elif isinstance(event, OutputDigestDeltaEvent):
        _require_active_response(updated)
        updated.output_digests.append(event.delta_sha256)

    elif isinstance(event, ToolCallRequestedEvent):
        _require_active_response(updated)
        if (
            event.tool_call_id in updated.pending_tool_calls
            or event.tool_call_id in updated.resolved_tool_calls
        ):
            raise EventConflictError("tool_call_id has already been used")
        if any(
            item.provider_tool_call_id == event.provider_tool_call_id
            for item in (
                *updated.pending_tool_calls.values(),
                *updated.resolved_tool_calls.values(),
            )
        ):
            raise EventConflictError("provider_tool_call_id has already been used")
        updated.pending_tool_calls[event.tool_call_id] = ToolCallState(
            tool_call_id=event.tool_call_id,
            provider_tool_call_id=event.provider_tool_call_id,
            tool_name=event.tool_name,
            arguments_sha256=event.arguments_sha256,
        )

    elif isinstance(event, ApprovalRequestedEvent):
        _require_active_response(updated)
        if event.tool_call_id not in updated.pending_tool_calls:
            raise InvalidLifecycleTransition("approval requires a pending tool call")
        if event.approval_id in updated.pending_approvals or event.approval_id in updated.resolved_approvals:
            raise EventConflictError("approval_id has already been used")
        updated.pending_approvals[event.approval_id] = event.tool_call_id

    elif isinstance(event, ApprovalResolvedEvent):
        _require_active_response(updated)
        tool_call_id = updated.pending_approvals.pop(event.approval_id, None)
        if tool_call_id is None:
            raise InvalidLifecycleTransition("approval is not pending")
        updated.resolved_approvals[event.approval_id] = event.decision.value

    elif isinstance(event, ToolCallResolvedEvent):
        _require_active_response(updated)
        if event.tool_call_id in updated.pending_approvals.values():
            raise InvalidLifecycleTransition("tool call still has a pending approval")
        tool_state = updated.pending_tool_calls.pop(event.tool_call_id, None)
        if tool_state is None:
            raise InvalidLifecycleTransition("tool call is not pending")
        tool_state.outcome = event.outcome
        tool_state.result_sha256 = event.result_sha256
        updated.resolved_tool_calls[event.tool_call_id] = tool_state

    elif isinstance(event, ResponseTerminalEvent):
        _require_active_response(updated)
        if updated.pending_tool_calls or updated.pending_approvals:
            raise InvalidLifecycleTransition("response cannot terminate with pending local work")
        updated.response_status = event.status

    elif isinstance(event, OutputValidatedEvent):
        if updated.response_status is not ProviderResponseStatus.COMPLETED:
            raise InvalidLifecycleTransition("output validation requires a completed response")
        if updated.pending_tool_calls or updated.pending_approvals:
            raise InvalidLifecycleTransition("output validation requires no pending local work")
        if updated.output_validated:
            raise InvalidLifecycleTransition("output is already validated")
        updated.output_validated = True
        updated.output_sha256 = event.output_sha256

    elif isinstance(event, AuditPersistedEvent):
        if updated.response_status is None:
            raise InvalidLifecycleTransition("audit persistence requires a terminal response")
        if updated.pending_tool_calls or updated.pending_approvals:
            raise InvalidLifecycleTransition("audit persistence requires no pending local work")
        if (
            updated.response_status is ProviderResponseStatus.COMPLETED
            and not updated.output_validated
        ):
            raise InvalidLifecycleTransition("completed responses require output validation")
        updated.audit_id = event.audit_id
        updated.audit_receipt_sha256 = event.receipt_sha256

    else:  # pragma: no cover - the discriminated union is exhaustive
        raise TypeError(f"unsupported lifecycle event: {type(event)!r}")

    if event.provider_event_id is not None:
        updated.provider_event_ids[event.provider_event_id] = event.event_id

    updated.last_sequence = event.sequence
    updated.last_observed_at = event.observed_at
    updated.applied_events.append(
        AppliedEventReceipt(
            sequence=event.sequence,
            event_id=event.event_id,
            fingerprint=fingerprint,
        )
    )
    return updated


def _require_active_response(state: ProviderRunState) -> None:
    if not state.response_started:
        raise InvalidLifecycleTransition("provider response has not started")
    if state.response_status is not None:
        raise InvalidLifecycleTransition("provider response is already terminal")
