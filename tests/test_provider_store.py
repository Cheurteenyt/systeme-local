from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

from systeme_local_gateway.providers import (
    AgentPrincipalRef,
    AppendResult,
    AuditPersistedEvent,
    ConversationHandle,
    ConversationState,
    EventConflictError,
    EventStoreCorruptError,
    EventStoreError,
    InvalidLifecycleTransition,
    LifecycleEventStore,
    OutputValidatedEvent,
    ProviderResponseStatus,
    ProviderRun,
    ResponseStartedEvent,
    ResponseTerminalEvent,
    UnsupportedSchemaVersion,
    commit_text_turn,
)

NOW = datetime(2026, 7, 17, 20, 30, tzinfo=timezone.utc)
RAW_PROMPT = "secret prompt that must not enter the lifecycle ledger"


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


def make_turn(
    *,
    turn_id: str = "turn_test_001",
    idempotency_key: str = "idem_test_001",
):
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
        parts=[RAW_PROMPT],
    )


def make_run(
    *,
    run_id: str = "run_test_001",
    turn_id: str = "turn_test_001",
    idempotency_key: str = "idem_test_001",
    provider_run_id: str = "fake_response_001",
) -> ProviderRun:
    return ProviderRun(
        run_id=run_id,
        conversation_id="slconv_test_001",
        turn_id=turn_id,
        trace_id="trace_test_001",
        idempotency_key=idempotency_key,
        provider="chatgpt",
        surface="deterministic_fake",
        started_at=NOW,
        provider_run_id=provider_run_id,
    )


def complete_events(run: ProviderRun):
    return [
        ResponseStartedEvent(
            event_id="evt_store_started",
            run_id=run.run_id,
            sequence=1,
            observed_at=NOW,
            provider_event_id="provider_evt_store_started",
            provider_response_id="fake_response_001",
        ),
        ResponseTerminalEvent(
            event_id="evt_store_terminal",
            run_id=run.run_id,
            sequence=2,
            observed_at=NOW,
            provider_event_id="provider_evt_store_terminal",
            status=ProviderResponseStatus.COMPLETED,
        ),
        OutputValidatedEvent(
            event_id="evt_store_validated",
            run_id=run.run_id,
            sequence=3,
            observed_at=NOW,
            output_sha256=digest("output"),
        ),
        AuditPersistedEvent(
            event_id="evt_store_audit",
            run_id=run.run_id,
            sequence=4,
            observed_at=NOW,
            audit_id="audit_store_001",
            receipt_sha256=digest("receipt"),
        ),
    ]


def register_foundation(
    store: LifecycleEventStore,
    conversation: ConversationHandle,
    turn,
    run: ProviderRun,
) -> None:
    assert store.register_conversation(conversation) is AppendResult.APPENDED
    assert store.register_turn(turn) is AppendResult.APPENDED
    assert store.register_run(run) is AppendResult.APPENDED


def test_sqlite_replay_matches_direct_lifecycle(tmp_path) -> None:
    conversation = make_conversation()
    turn = make_turn()
    run = make_run()
    store = LifecycleEventStore(tmp_path / "lifecycle.sqlite3")
    register_foundation(store, conversation, turn, run)

    for event in complete_events(run):
        assert store.append_event(event) is AppendResult.APPENDED

    replayed = store.replay(run.run_id)
    assert replayed.delegation_completed
    assert replayed.last_sequence == 4
    assert store.load_conversation(conversation.conversation_id) == conversation
    assert store.load_turn(turn.turn_id) == turn
    assert store.load_run(run.run_id) == run


def test_two_store_instances_accept_exact_duplicate_and_reject_conflict(
    tmp_path,
) -> None:
    conversation = make_conversation()
    turn = make_turn()
    run = make_run()
    path = tmp_path / "lifecycle.sqlite3"
    first = LifecycleEventStore(path)
    second = LifecycleEventStore(path)
    register_foundation(first, conversation, turn, run)

    assert second.register_conversation(conversation) is AppendResult.DUPLICATE
    assert second.register_turn(turn) is AppendResult.DUPLICATE
    assert second.register_run(run) is AppendResult.DUPLICATE

    event = complete_events(run)[0]
    assert first.append_event(event) is AppendResult.APPENDED
    assert second.append_event(event) is AppendResult.DUPLICATE

    conflicting = event.model_copy(update={"event_id": "evt_store_conflict"})
    with pytest.raises(EventConflictError, match="conflicting"):
        second.append_event(conflicting)


def test_invalid_transition_is_rejected_before_persistence(tmp_path) -> None:
    conversation = make_conversation()
    turn = make_turn()
    run = make_run()
    store = LifecycleEventStore(tmp_path / "lifecycle.sqlite3")
    register_foundation(store, conversation, turn, run)

    invalid = ResponseTerminalEvent(
        event_id="evt_invalid_terminal",
        run_id=run.run_id,
        sequence=1,
        observed_at=NOW,
        status=ProviderResponseStatus.FAILED,
        error_code="FAKE_FAILURE",
    )
    with pytest.raises(InvalidLifecycleTransition, match="has not started"):
        store.append_event(invalid)

    assert store.load_events(run.run_id) == []


def test_turn_and_idempotency_key_have_one_provider_run(tmp_path) -> None:
    conversation = make_conversation()
    turn = make_turn()
    first_run = make_run()
    second_run = make_run(
        run_id="run_test_002",
        provider_run_id="fake_response_002",
    )
    path = tmp_path / "lifecycle.sqlite3"
    first = LifecycleEventStore(path)
    second = LifecycleEventStore(path)
    first.register_conversation(conversation)
    first.register_turn(turn)
    first.register_run(first_run)

    with pytest.raises(EventConflictError, match="idempotency_key"):
        second.register_run(second_run)


def test_provider_run_must_match_registered_turn(tmp_path) -> None:
    conversation = make_conversation()
    turn = make_turn()
    store = LifecycleEventStore(tmp_path / "lifecycle.sqlite3")
    store.register_conversation(conversation)
    store.register_turn(turn)

    mismatched = make_run().model_copy(
        update={"trace_id": "trace_wrong_001"}
    )
    with pytest.raises(EventStoreError, match="committed turn"):
        store.register_run(mismatched)


def test_event_store_persists_metadata_but_not_raw_prompt(tmp_path) -> None:
    conversation = make_conversation()
    turn = make_turn()
    run = make_run()
    path = tmp_path / "lifecycle.sqlite3"
    store = LifecycleEventStore(path)
    register_foundation(store, conversation, turn, run)
    store.append_event(complete_events(run)[0])

    database_text = path.read_bytes().decode("latin-1")
    assert RAW_PROMPT not in database_text
    assert turn.content_sha256 in database_text


def test_payload_fingerprint_tampering_fails_closed(tmp_path) -> None:
    conversation = make_conversation()
    turn = make_turn()
    run = make_run()
    path = tmp_path / "lifecycle.sqlite3"
    store = LifecycleEventStore(path)
    register_foundation(store, conversation, turn, run)

    connection = sqlite3.connect(path)
    connection.execute(
        """
        UPDATE runs
        SET payload_json = replace(
            payload_json,
            'trace_test_001',
            'trace_tampered_001'
        )
        WHERE run_id = ?
        """,
        (run.run_id,),
    )
    connection.commit()
    connection.close()

    with pytest.raises(EventStoreCorruptError, match="fingerprint"):
        store.load_run(run.run_id)


def test_event_column_tampering_fails_closed(tmp_path) -> None:
    conversation = make_conversation()
    turn = make_turn()
    run = make_run()
    path = tmp_path / "lifecycle.sqlite3"
    store = LifecycleEventStore(path)
    register_foundation(store, conversation, turn, run)
    store.append_event(complete_events(run)[0])

    connection = sqlite3.connect(path)
    connection.execute(
        """
        UPDATE events
        SET provider_event_id = 'provider_evt_tampered'
        WHERE event_id = 'evt_store_started'
        """
    )
    connection.commit()
    connection.close()

    with pytest.raises(EventStoreCorruptError, match="columns"):
        store.load_events(run.run_id)


def test_corrupt_database_fails_closed(tmp_path) -> None:
    path = tmp_path / "corrupt.sqlite3"
    path.write_bytes(b"not a sqlite database")
    with pytest.raises(EventStoreCorruptError):
        LifecycleEventStore(path)


def test_unsupported_schema_version_fails_closed(tmp_path) -> None:
    path = tmp_path / "future.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES ('schema_version', '999')"
    )
    connection.commit()
    connection.close()

    with pytest.raises(UnsupportedSchemaVersion, match="999"):
        LifecycleEventStore(path)


@pytest.mark.parametrize(
    ("table", "column", "replacement", "load"),
    [
        (
            "conversations",
            "provider",
            "tampered",
            lambda store, conversation, _turn, _run: store.load_conversation(
                conversation.conversation_id
            ),
        ),
        (
            "turns",
            "idempotency_key",
            "idem_tampered_001",
            lambda store, _conversation, turn, _run: store.load_turn(turn.turn_id),
        ),
        (
            "runs",
            "surface",
            "tampered_surface",
            lambda store, _conversation, _turn, run: store.load_run(run.run_id),
        ),
    ],
)
def test_denormalized_column_tampering_fails_closed(
    tmp_path,
    table,
    column,
    replacement,
    load,
) -> None:
    conversation = make_conversation()
    turn = make_turn()
    run = make_run()
    path = tmp_path / "lifecycle.sqlite3"
    store = LifecycleEventStore(path)
    register_foundation(store, conversation, turn, run)

    connection = sqlite3.connect(path)
    connection.execute(
        f"UPDATE {table} SET {column} = ?",  # noqa: S608
        (replacement,),
    )
    connection.commit()
    connection.close()

    with pytest.raises(EventStoreCorruptError, match="columns"):
        load(store, conversation, turn, run)


def test_turn_requires_active_conversation_and_valid_chronology(tmp_path) -> None:
    path = tmp_path / "lifecycle.sqlite3"
    store = LifecycleEventStore(path)
    closed = make_conversation().model_copy(
        update={"state": ConversationState.CLOSED}
    )
    store.register_conversation(closed)

    with pytest.raises(EventStoreError, match="active conversation"):
        store.register_turn(make_turn())

    path2 = tmp_path / "lifecycle2.sqlite3"
    store2 = LifecycleEventStore(path2)
    later_conversation = make_conversation().model_copy(
        update={
            "created_at": NOW + timedelta(seconds=1),
            "updated_at": NOW + timedelta(seconds=1),
        }
    )
    store2.register_conversation(later_conversation)

    with pytest.raises(EventStoreError, match="precede"):
        store2.register_turn(make_turn())


def test_provider_run_cannot_precede_committed_turn(tmp_path) -> None:
    conversation = make_conversation()
    turn = make_turn()
    store = LifecycleEventStore(tmp_path / "lifecycle.sqlite3")
    store.register_conversation(conversation)
    store.register_turn(turn)

    early_run = make_run().model_copy(
        update={"started_at": NOW - timedelta(microseconds=1)}
    )
    with pytest.raises(EventStoreError, match="precede"):
        store.register_run(early_run)
