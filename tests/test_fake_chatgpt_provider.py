from __future__ import annotations

import socket
from datetime import datetime, timezone
from hashlib import sha256

import pytest

from systeme_local_gateway.providers import (
    AgentPrincipalRef,
    AppendResult,
    AuditPersistedEvent,
    CapabilitySupport,
    ConversationHandle,
    DeterministicFakeChatGptAdapter,
    FakeChatGptScenario,
    LifecycleEventStore,
    OutputValidatedEvent,
    ProviderResponseStatus,
    ToolCallResolvedEvent,
    ToolResolutionOutcome,
    apply_lifecycle_event,
    commit_text_turn,
    initial_run_state,
)

NOW = datetime(2026, 7, 17, 20, 30, tzinfo=timezone.utc)


def digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def make_conversation() -> ConversationHandle:
    return ConversationHandle(
        conversation_id="slconv_test_001",
        provider="chatgpt",
        surface="deterministic_fake",
        created_by_agent="agent_local_main",
        created_at=NOW,
        updated_at=NOW,
    )


def make_turn(*, turn_id: str = "turn_test_001", idempotency_key: str = "idem_test_001"):
    return commit_text_turn(
        conversation_id="slconv_test_001",
        turn_id=turn_id,
        trace_id="trace_test_001",
        idempotency_key=idempotency_key,
        principal=AgentPrincipalRef(
            agent_id="agent_local_main",
            instance_id="instance_windows_01",
            key_id="key_primary_01",
            verification_id="verify_turn_01",
        ),
        committed_at=NOW,
        parts=["secret prompt that must not enter the lifecycle ledger"],
    )


def test_fake_adapter_capabilities_are_explicit() -> None:
    profile = DeterministicFakeChatGptAdapter().capabilities
    assert profile.can_initiate_turn.state is CapabilitySupport.SUPPORTED
    assert profile.can_enumerate_visible_chats.state is CapabilitySupport.UNKNOWN


@pytest.mark.parametrize(
    ("scenario", "expected_status", "event_count"),
    [
        (FakeChatGptScenario.COMPLETED, ProviderResponseStatus.COMPLETED, 3),
        (FakeChatGptScenario.FAILED, ProviderResponseStatus.FAILED, 2),
        (FakeChatGptScenario.CANCELLED, ProviderResponseStatus.CANCELLED, 2),
        (FakeChatGptScenario.INCOMPLETE, ProviderResponseStatus.INCOMPLETE, 2),
    ],
)
def test_fake_scenarios_are_deterministic(scenario, expected_status, event_count) -> None:
    adapter = DeterministicFakeChatGptAdapter()
    conversation = make_conversation()
    turn = make_turn()
    first = adapter.start_run(conversation=conversation, turn=turn, scenario=scenario)
    second = adapter.start_run(conversation=conversation, turn=turn, scenario=scenario)

    assert first == second
    assert len(first.provider_events) == event_count
    assert first.provider_events[-1].status is expected_status
    assert first.conversation.provider_conversation_id is not None


def test_continued_conversation_preserves_provider_mapping() -> None:
    adapter = DeterministicFakeChatGptAdapter()
    first = adapter.start_run(
        conversation=make_conversation(),
        turn=make_turn(),
        scenario=FakeChatGptScenario.COMPLETED,
    )
    continued = adapter.start_run(
        conversation=first.conversation,
        turn=make_turn(turn_id="turn_test_002", idempotency_key="idem_test_002"),
        scenario=FakeChatGptScenario.COMPLETED,
    )

    assert continued.conversation.provider_conversation_id == first.conversation.provider_conversation_id
    assert continued.run.run_id != first.run.run_id


def test_tool_call_scenario_requires_orchestrator_resolution() -> None:
    adapter = DeterministicFakeChatGptAdapter()
    plan = adapter.start_run(
        conversation=make_conversation(),
        turn=make_turn(),
        scenario=FakeChatGptScenario.TOOL_CALL,
    )
    assert plan.waiting_tool_call_id is not None

    state = initial_run_state(plan.run)
    for event in plan.provider_events:
        state = apply_lifecycle_event(state, event)

    state = apply_lifecycle_event(
        state,
        ToolCallResolvedEvent(
            event_id="evt_fake_tool_resolved",
            run_id=plan.run.run_id,
            sequence=3,
            observed_at=NOW,
            tool_call_id=plan.waiting_tool_call_id,
            outcome=ToolResolutionOutcome.COMPLETED,
            result_sha256=digest("tool result"),
        ),
    )
    for event in adapter.continue_after_tool(
        plan=plan,
        next_sequence=4,
        tool_call_id=plan.waiting_tool_call_id,
        observed_at=NOW,
    ):
        state = apply_lifecycle_event(state, event)

    state = apply_lifecycle_event(
        state,
        OutputValidatedEvent(
            event_id="evt_fake_validated",
            run_id=plan.run.run_id,
            sequence=6,
            observed_at=NOW,
            output_sha256=digest("validated output"),
        ),
    )
    state = apply_lifecycle_event(
        state,
        AuditPersistedEvent(
            event_id="evt_fake_audit",
            run_id=plan.run.run_id,
            sequence=7,
            observed_at=NOW,
            audit_id="audit_fake_001",
            receipt_sha256=digest("receipt"),
        ),
    )
    assert state.delegation_completed


def test_fake_adapter_never_reads_network_or_credentials(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-read")

    def fail_socket(*_args, **_kwargs):
        raise AssertionError("network access is forbidden in deterministic fake adapter tests")

    monkeypatch.setattr(socket, "socket", fail_socket)
    plan = DeterministicFakeChatGptAdapter().start_run(
        conversation=make_conversation(),
        turn=make_turn(),
        scenario=FakeChatGptScenario.COMPLETED,
    )
    assert plan.run.provider_run_id is not None


def test_same_turn_keeps_run_identity_across_scenarios() -> None:
    adapter = DeterministicFakeChatGptAdapter()
    conversation = make_conversation()
    turn = make_turn()

    completed = adapter.start_run(
        conversation=conversation,
        turn=turn,
        scenario=FakeChatGptScenario.COMPLETED,
    )
    failed = adapter.start_run(
        conversation=conversation,
        turn=turn,
        scenario=FakeChatGptScenario.FAILED,
    )

    assert completed.run.run_id == failed.run.run_id
    assert completed.run.provider_run_id == failed.run.provider_run_id


def test_fake_adapter_rejects_surface_and_principal_mismatch() -> None:
    adapter = DeterministicFakeChatGptAdapter()
    turn = make_turn()

    with pytest.raises(ValueError, match="surface"):
        adapter.start_run(
            conversation=make_conversation().model_copy(
                update={"surface": "openai_responses_api"}
            ),
            turn=turn,
            scenario=FakeChatGptScenario.COMPLETED,
        )

    with pytest.raises(ValueError, match="does not own"):
        adapter.start_run(
            conversation=make_conversation().model_copy(
                update={"created_by_agent": "agent_other_main"}
            ),
            turn=turn,
            scenario=FakeChatGptScenario.COMPLETED,
        )


def test_distinct_local_conversations_get_distinct_provider_mappings() -> None:
    adapter = DeterministicFakeChatGptAdapter()
    first = adapter.start_run(
        conversation=make_conversation(),
        turn=make_turn(),
        scenario=FakeChatGptScenario.COMPLETED,
    )

    second_conversation = make_conversation().model_copy(
        update={"conversation_id": "slconv_test_002"}
    )
    second_turn = commit_text_turn(
        conversation_id="slconv_test_002",
        turn_id="turn_test_002",
        trace_id="trace_test_002",
        idempotency_key="idem_test_002",
        principal=AgentPrincipalRef(
            agent_id="agent_local_main",
            instance_id="instance_windows_01",
            key_id="key_primary_01",
            verification_id="verify_turn_02",
        ),
        committed_at=NOW,
        parts=["second metadata-only prompt"],
    )
    second = adapter.start_run(
        conversation=second_conversation,
        turn=second_turn,
        scenario=FakeChatGptScenario.COMPLETED,
    )

    assert (
        first.conversation.provider_conversation_id
        != second.conversation.provider_conversation_id
    )



def test_tool_call_scenario_recovers_from_sqlite_replay(tmp_path) -> None:
    adapter = DeterministicFakeChatGptAdapter()
    turn = make_turn()
    plan = adapter.start_run(
        conversation=make_conversation(),
        turn=turn,
        scenario=FakeChatGptScenario.TOOL_CALL,
    )
    path = tmp_path / "lifecycle.sqlite3"
    first_process = LifecycleEventStore(path)
    assert (
        first_process.register_conversation(plan.conversation)
        is AppendResult.APPENDED
    )
    assert first_process.register_turn(turn) is AppendResult.APPENDED
    assert first_process.register_run(plan.run) is AppendResult.APPENDED
    for event in plan.provider_events:
        first_process.append_event(event)

    recovered_process = LifecycleEventStore(path)
    recovered = recovered_process.replay(plan.run.run_id)
    assert plan.waiting_tool_call_id in recovered.pending_tool_calls

    recovered_process.append_event(
        ToolCallResolvedEvent(
            event_id="evt_recovered_tool_resolved",
            run_id=plan.run.run_id,
            sequence=3,
            observed_at=NOW,
            tool_call_id=plan.waiting_tool_call_id,
            outcome=ToolResolutionOutcome.COMPLETED,
            result_sha256=digest("tool result"),
        )
    )
    for event in adapter.continue_after_tool(
        plan=plan,
        next_sequence=4,
        tool_call_id=plan.waiting_tool_call_id,
        observed_at=NOW,
    ):
        recovered_process.append_event(event)
    recovered_process.append_event(
        OutputValidatedEvent(
            event_id="evt_recovered_validated",
            run_id=plan.run.run_id,
            sequence=6,
            observed_at=NOW,
            output_sha256=digest("validated output"),
        )
    )
    recovered_process.append_event(
        AuditPersistedEvent(
            event_id="evt_recovered_audit",
            run_id=plan.run.run_id,
            sequence=7,
            observed_at=NOW,
            audit_id="audit_recovered_001",
            receipt_sha256=digest("receipt"),
        )
    )

    final_process = LifecycleEventStore(path)
    assert final_process.replay(plan.run.run_id).delegation_completed
