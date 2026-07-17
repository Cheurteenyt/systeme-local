from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

from systeme_local_gateway.providers import (
    ApprovalDecision,
    ApprovalRequestedEvent,
    ApprovalResolvedEvent,
    AuditPersistedEvent,
    EventConflictError,
    EventSequenceGapError,
    InvalidLifecycleTransition,
    OutputDigestDeltaEvent,
    OutputValidatedEvent,
    ProviderResponseStatus,
    ProviderRun,
    ResponseStartedEvent,
    ResponseTerminalEvent,
    ToolCallRequestedEvent,
    ToolCallResolvedEvent,
    ToolResolutionOutcome,
    apply_lifecycle_event,
    initial_run_state,
)

NOW = datetime(2026, 7, 17, 20, 30, tzinfo=timezone.utc)


def make_run() -> ProviderRun:
    return ProviderRun(
        run_id="run_test_001",
        conversation_id="slconv_test_001",
        turn_id="turn_test_001",
        trace_id="trace_test_001",
        idempotency_key="idem_test_001",
        provider="chatgpt",
        surface="deterministic_fake",
        started_at=NOW,
        provider_run_id="fake_response_001",
    )


def digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def started(run: ProviderRun, *, sequence: int = 1, event_id: str = "evt_started_001"):
    return ResponseStartedEvent(
        event_id=event_id,
        run_id=run.run_id,
        sequence=sequence,
        observed_at=NOW,
        provider_response_id="fake_response_001",
    )


def test_exact_duplicate_is_idempotent_and_conflict_fails() -> None:
    run = make_run()
    state = apply_lifecycle_event(initial_run_state(run), started(run))
    assert apply_lifecycle_event(state, started(run)) is state

    with pytest.raises(EventConflictError, match="conflicting"):
        apply_lifecycle_event(state, started(run, event_id="evt_started_conflict"))


def test_sequence_gap_fails_closed() -> None:
    run = make_run()
    with pytest.raises(EventSequenceGapError, match="gap"):
        apply_lifecycle_event(initial_run_state(run), started(run, sequence=2))


def test_delegation_completes_only_after_validation_and_audit() -> None:
    run = make_run()
    state = apply_lifecycle_event(initial_run_state(run), started(run))
    state = apply_lifecycle_event(
        state,
        OutputDigestDeltaEvent(
            event_id="evt_output_001",
            run_id=run.run_id,
            sequence=2,
            observed_at=NOW,
            delta_sha256=digest("output"),
            utf8_bytes=6,
        ),
    )
    state = apply_lifecycle_event(
        state,
        ResponseTerminalEvent(
            event_id="evt_terminal_001",
            run_id=run.run_id,
            sequence=3,
            observed_at=NOW,
            status=ProviderResponseStatus.COMPLETED,
        ),
    )
    assert not state.delegation_completed

    state = apply_lifecycle_event(
        state,
        OutputValidatedEvent(
            event_id="evt_validated_001",
            run_id=run.run_id,
            sequence=4,
            observed_at=NOW,
            output_sha256=digest("output"),
        ),
    )
    assert not state.delegation_completed

    state = apply_lifecycle_event(
        state,
        AuditPersistedEvent(
            event_id="evt_audit_001",
            run_id=run.run_id,
            sequence=5,
            observed_at=NOW,
            audit_id="audit_test_001",
            receipt_sha256=digest("receipt"),
        ),
    )
    assert state.delegation_completed
    assert state.delegation_terminal


def test_tool_and_approval_must_resolve_before_terminal() -> None:
    run = make_run()
    state = apply_lifecycle_event(initial_run_state(run), started(run))
    state = apply_lifecycle_event(
        state,
        ToolCallRequestedEvent(
            event_id="evt_tool_001",
            run_id=run.run_id,
            sequence=2,
            observed_at=NOW,
            tool_call_id="tool_test_001",
            provider_tool_call_id="provider_tool_001",
            tool_name="workspace.list",
            arguments_sha256=digest("args"),
        ),
    )
    state = apply_lifecycle_event(
        state,
        ApprovalRequestedEvent(
            event_id="evt_approval_001",
            run_id=run.run_id,
            sequence=3,
            observed_at=NOW,
            approval_id="approval_test_001",
            tool_call_id="tool_test_001",
        ),
    )

    with pytest.raises(InvalidLifecycleTransition, match="pending local work"):
        apply_lifecycle_event(
            state,
            ResponseTerminalEvent(
                event_id="evt_terminal_early",
                run_id=run.run_id,
                sequence=4,
                observed_at=NOW,
                status=ProviderResponseStatus.COMPLETED,
            ),
        )

    state = apply_lifecycle_event(
        state,
        ApprovalResolvedEvent(
            event_id="evt_approval_resolved",
            run_id=run.run_id,
            sequence=4,
            observed_at=NOW,
            approval_id="approval_test_001",
            decision=ApprovalDecision.APPROVED,
        ),
    )
    state = apply_lifecycle_event(
        state,
        ToolCallResolvedEvent(
            event_id="evt_tool_resolved",
            run_id=run.run_id,
            sequence=5,
            observed_at=NOW,
            tool_call_id="tool_test_001",
            outcome=ToolResolutionOutcome.COMPLETED,
            result_sha256=digest("result"),
        ),
    )
    state = apply_lifecycle_event(
        state,
        ResponseTerminalEvent(
            event_id="evt_terminal_final",
            run_id=run.run_id,
            sequence=6,
            observed_at=NOW,
            status=ProviderResponseStatus.COMPLETED,
        ),
    )
    assert state.response_status is ProviderResponseStatus.COMPLETED


def test_failed_response_can_be_terminal_and_audited() -> None:
    run = make_run()
    state = apply_lifecycle_event(initial_run_state(run), started(run))
    state = apply_lifecycle_event(
        state,
        ResponseTerminalEvent(
            event_id="evt_failed_001",
            run_id=run.run_id,
            sequence=2,
            observed_at=NOW,
            status=ProviderResponseStatus.FAILED,
            error_code="FAKE_FAILURE",
        ),
    )
    state = apply_lifecycle_event(
        state,
        AuditPersistedEvent(
            event_id="evt_failed_audit",
            run_id=run.run_id,
            sequence=3,
            observed_at=NOW,
            audit_id="audit_failed_001",
            receipt_sha256=digest("failed receipt"),
        ),
    )

    assert state.delegation_terminal
    assert not state.delegation_completed


def test_validation_before_terminal_is_rejected() -> None:
    run = make_run()
    state = apply_lifecycle_event(initial_run_state(run), started(run))
    with pytest.raises(InvalidLifecycleTransition, match="completed response"):
        apply_lifecycle_event(
            state,
            OutputValidatedEvent(
                event_id="evt_invalid_validation",
                run_id=run.run_id,
                sequence=2,
                observed_at=NOW,
                output_sha256=digest("output"),
            ),
        )


def test_provider_event_id_reuse_fails_closed() -> None:
    run = make_run()
    state = apply_lifecycle_event(
        initial_run_state(run),
        ResponseStartedEvent(
            event_id="evt_provider_started",
            run_id=run.run_id,
            sequence=1,
            observed_at=NOW,
            provider_event_id="provider_event_001",
            provider_response_id="fake_response_001",
        ),
    )

    with pytest.raises(EventConflictError, match="provider_event_id"):
        apply_lifecycle_event(
            state,
            OutputDigestDeltaEvent(
                event_id="evt_provider_reused",
                run_id=run.run_id,
                sequence=2,
                observed_at=NOW,
                provider_event_id="provider_event_001",
                delta_sha256=digest("output"),
                utf8_bytes=6,
            ),
        )


def test_provider_tool_call_id_reuse_fails_closed() -> None:
    run = make_run()
    state = apply_lifecycle_event(initial_run_state(run), started(run))
    state = apply_lifecycle_event(
        state,
        ToolCallRequestedEvent(
            event_id="evt_tool_first",
            run_id=run.run_id,
            sequence=2,
            observed_at=NOW,
            tool_call_id="tool_local_first",
            provider_tool_call_id="provider_tool_same",
            tool_name="workspace.list",
            arguments_sha256=digest("first"),
        ),
    )

    with pytest.raises(EventConflictError, match="provider_tool_call_id"):
        apply_lifecycle_event(
            state,
            ToolCallRequestedEvent(
                event_id="evt_tool_second",
                run_id=run.run_id,
                sequence=3,
                observed_at=NOW,
                tool_call_id="tool_local_second",
                provider_tool_call_id="provider_tool_same",
                tool_name="workspace.list",
                arguments_sha256=digest("second"),
            ),
        )


def test_event_cannot_precede_run_or_move_backwards() -> None:
    run = make_run()

    with pytest.raises(InvalidLifecycleTransition, match="precede"):
        apply_lifecycle_event(
            initial_run_state(run),
            started(run).model_copy(
                update={"observed_at": NOW - timedelta(seconds=1)}
            ),
        )

    state = apply_lifecycle_event(
        initial_run_state(run),
        started(run).model_copy(
            update={"observed_at": NOW + timedelta(seconds=1)}
        ),
    )
    with pytest.raises(InvalidLifecycleTransition, match="backwards"):
        apply_lifecycle_event(
            state,
            OutputDigestDeltaEvent(
                event_id="evt_output_backwards",
                run_id=run.run_id,
                sequence=2,
                observed_at=NOW + timedelta(microseconds=500_000),
                delta_sha256=digest("output"),
                utf8_bytes=6,
            ),
        )
