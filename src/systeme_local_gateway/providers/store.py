from __future__ import annotations

import sqlite3
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any

from .models import (
    LIFECYCLE_EVENT_ADAPTER,
    CommittedTurn,
    ConversationHandle,
    ConversationState,
    LifecycleEvent,
    ProviderRun,
)
from .state_machine import (
    EventConflictError,
    EventSequenceGapError,
    InvalidLifecycleTransition,
    ProviderRunState,
    apply_lifecycle_event,
    initial_run_state,
    lifecycle_event_fingerprint,
)

_SCHEMA_VERSION = "1"


class EventStoreError(RuntimeError):
    pass


class EventStoreCorruptError(EventStoreError):
    pass


class UnsupportedSchemaVersion(EventStoreError):
    pass


class AppendResult(StrEnum):
    APPENDED = "appended"
    DUPLICATE = "duplicate"


class LifecycleEventStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.exists() and (
            self.path.is_symlink() or not self.path.is_file()
        ):
            raise EventStoreError("event store path must be a regular file")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def register_conversation(
        self,
        conversation: ConversationHandle,
    ) -> AppendResult:
        payload = conversation.model_dump_json(exclude_none=False)
        fingerprint = _fingerprint(payload)

        with self._connect() as connection:
            self._begin(connection)
            try:
                existing = connection.execute(
                    """
                    SELECT
                        conversation_id,
                        provider,
                        surface,
                        provider_conversation_id,
                        fingerprint,
                        payload_json
                    FROM conversations
                    WHERE conversation_id = ?
                    """,
                    (conversation.conversation_id,),
                ).fetchone()
                if existing is not None:
                    stored = self._conversation_from_row(existing)
                    if stored == conversation and existing["fingerprint"] == fingerprint:
                        connection.execute("COMMIT")
                        return AppendResult.DUPLICATE
                    raise EventConflictError(
                        "conflicting conversation_id registration"
                    )

                if conversation.provider_conversation_id is not None:
                    mapping = connection.execute(
                        """
                        SELECT conversation_id
                        FROM conversations
                        WHERE provider = ?
                          AND surface = ?
                          AND provider_conversation_id = ?
                        """,
                        (
                            conversation.provider,
                            conversation.surface,
                            conversation.provider_conversation_id,
                        ),
                    ).fetchone()
                    if mapping is not None:
                        raise EventConflictError(
                            "provider conversation mapping is already registered"
                        )

                connection.execute(
                    """
                    INSERT INTO conversations(
                        conversation_id,
                        provider,
                        surface,
                        provider_conversation_id,
                        fingerprint,
                        payload_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        conversation.conversation_id,
                        conversation.provider,
                        conversation.surface,
                        conversation.provider_conversation_id,
                        fingerprint,
                        payload,
                    ),
                )
                connection.execute("COMMIT")
                return AppendResult.APPENDED
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def register_turn(self, turn: CommittedTurn) -> AppendResult:
        payload = turn.model_dump_json(exclude_none=False)
        fingerprint = _fingerprint(payload)

        with self._connect() as connection:
            self._begin(connection)
            try:
                conversation_row = connection.execute(
                    """
                    SELECT
                        conversation_id,
                        provider,
                        surface,
                        provider_conversation_id,
                        fingerprint,
                        payload_json
                    FROM conversations
                    WHERE conversation_id = ?
                    """,
                    (turn.conversation_id,),
                ).fetchone()
                if conversation_row is None:
                    raise EventStoreError(
                        "committed turn requires a registered conversation"
                    )
                conversation = self._conversation_from_row(conversation_row)
                if turn.principal.agent_id != conversation.created_by_agent:
                    raise EventStoreError(
                        "committed turn principal does not own the conversation"
                    )
                if conversation.state is not ConversationState.ACTIVE:
                    raise EventStoreError("committed turn requires an active conversation")
                if turn.committed_at < conversation.created_at:
                    raise EventStoreError("committed turn cannot precede the conversation")

                existing = connection.execute(
                    """
                    SELECT
                        turn_id,
                        conversation_id,
                        idempotency_key,
                        fingerprint,
                        payload_json
                    FROM turns
                    WHERE turn_id = ?
                    """,
                    (turn.turn_id,),
                ).fetchone()
                if existing is not None:
                    stored = self._turn_from_row(existing)
                    if stored == turn and existing["fingerprint"] == fingerprint:
                        connection.execute("COMMIT")
                        return AppendResult.DUPLICATE
                    raise EventConflictError("conflicting turn_id registration")

                idempotency_row = connection.execute(
                    """
                    SELECT turn_id
                    FROM turns
                    WHERE idempotency_key = ?
                    """,
                    (turn.idempotency_key,),
                ).fetchone()
                if idempotency_row is not None:
                    raise EventConflictError(
                        "idempotency_key is already bound to another turn"
                    )

                connection.execute(
                    """
                    INSERT INTO turns(
                        turn_id,
                        conversation_id,
                        idempotency_key,
                        fingerprint,
                        payload_json
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        turn.turn_id,
                        turn.conversation_id,
                        turn.idempotency_key,
                        fingerprint,
                        payload,
                    ),
                )
                connection.execute("COMMIT")
                return AppendResult.APPENDED
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def register_run(self, run: ProviderRun) -> AppendResult:
        payload = run.model_dump_json(exclude_none=False)
        fingerprint = _fingerprint(payload)

        with self._connect() as connection:
            self._begin(connection)
            try:
                conversation_row = connection.execute(
                    """
                    SELECT
                        conversation_id,
                        provider,
                        surface,
                        provider_conversation_id,
                        fingerprint,
                        payload_json
                    FROM conversations
                    WHERE conversation_id = ?
                    """,
                    (run.conversation_id,),
                ).fetchone()
                if conversation_row is None:
                    raise EventStoreError(
                        "provider run requires a registered conversation"
                    )
                conversation = self._conversation_from_row(conversation_row)

                turn_row = connection.execute(
                    """
                    SELECT
                        turn_id,
                        conversation_id,
                        idempotency_key,
                        fingerprint,
                        payload_json
                    FROM turns
                    WHERE turn_id = ?
                    """,
                    (run.turn_id,),
                ).fetchone()
                if turn_row is None:
                    raise EventStoreError(
                        "provider run requires a registered committed turn"
                    )
                turn = self._turn_from_row(turn_row)

                if (
                    run.conversation_id != turn.conversation_id
                    or run.trace_id != turn.trace_id
                    or run.idempotency_key != turn.idempotency_key
                ):
                    raise EventStoreError(
                        "provider run does not match its committed turn"
                    )
                if (
                    run.provider != conversation.provider
                    or run.surface != conversation.surface
                ):
                    raise EventStoreError(
                        "provider run does not match its conversation surface"
                    )
                if conversation.state is not ConversationState.ACTIVE:
                    raise EventStoreError("provider run requires an active conversation")
                if run.started_at < turn.committed_at:
                    raise EventStoreError("provider run cannot precede its committed turn")

                existing = connection.execute(
                    """
                    SELECT
                        run_id,
                        conversation_id,
                        turn_id,
                        idempotency_key,
                        provider,
                        surface,
                        provider_run_id,
                        fingerprint,
                        payload_json
                    FROM runs
                    WHERE run_id = ?
                    """,
                    (run.run_id,),
                ).fetchone()
                if existing is not None:
                    stored = self._run_from_row(existing)
                    if stored == run and existing["fingerprint"] == fingerprint:
                        connection.execute("COMMIT")
                        return AppendResult.DUPLICATE
                    raise EventConflictError("conflicting run_id registration")

                turn_binding = connection.execute(
                    """
                    SELECT run_id
                    FROM runs
                    WHERE turn_id = ? OR idempotency_key = ?
                    """,
                    (run.turn_id, run.idempotency_key),
                ).fetchone()
                if turn_binding is not None:
                    raise EventConflictError(
                        "committed turn or idempotency_key already has a provider run"
                    )

                if run.provider_run_id is not None:
                    provider_binding = connection.execute(
                        """
                        SELECT run_id
                        FROM runs
                        WHERE provider = ?
                          AND surface = ?
                          AND provider_run_id = ?
                        """,
                        (run.provider, run.surface, run.provider_run_id),
                    ).fetchone()
                    if provider_binding is not None:
                        raise EventConflictError(
                            "provider_run_id is already registered"
                        )

                connection.execute(
                    """
                    INSERT INTO runs(
                        run_id,
                        conversation_id,
                        turn_id,
                        idempotency_key,
                        provider,
                        surface,
                        provider_run_id,
                        fingerprint,
                        payload_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run.run_id,
                        run.conversation_id,
                        run.turn_id,
                        run.idempotency_key,
                        run.provider,
                        run.surface,
                        run.provider_run_id,
                        fingerprint,
                        payload,
                    ),
                )
                connection.execute("COMMIT")
                return AppendResult.APPENDED
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def append_event(self, event: LifecycleEvent) -> AppendResult:
        payload = event.model_dump_json(exclude_none=False)
        fingerprint = lifecycle_event_fingerprint(event)

        with self._connect() as connection:
            self._begin(connection)
            try:
                run_row = connection.execute(
                    """
                    SELECT
                        run_id,
                        conversation_id,
                        turn_id,
                        idempotency_key,
                        provider,
                        surface,
                        provider_run_id,
                        fingerprint,
                        payload_json
                    FROM runs
                    WHERE run_id = ?
                    """,
                    (event.run_id,),
                ).fetchone()
                if run_row is None:
                    raise EventStoreError(
                        "event requires a registered provider run"
                    )
                run = self._run_from_row(run_row)

                sequence_row = connection.execute(
                    """
                    SELECT
                        run_id,
                        sequence,
                        event_id,
                        provider_event_id,
                        fingerprint,
                        payload_json
                    FROM events
                    WHERE run_id = ? AND sequence = ?
                    """,
                    (event.run_id, event.sequence),
                ).fetchone()
                if sequence_row is not None:
                    stored = self._event_from_row(sequence_row)
                    if stored == event and sequence_row["fingerprint"] == fingerprint:
                        connection.execute("COMMIT")
                        return AppendResult.DUPLICATE
                    raise EventConflictError(
                        "conflicting event already occupies this sequence"
                    )

                id_row = connection.execute(
                    """
                    SELECT event_id
                    FROM events
                    WHERE event_id = ?
                    """,
                    (event.event_id,),
                ).fetchone()
                if id_row is not None:
                    raise EventConflictError(
                        "event_id has already been persisted"
                    )

                if event.provider_event_id is not None:
                    provider_id_row = connection.execute(
                        """
                        SELECT event_id
                        FROM events
                        WHERE run_id = ? AND provider_event_id = ?
                        """,
                        (event.run_id, event.provider_event_id),
                    ).fetchone()
                    if provider_id_row is not None:
                        raise EventConflictError(
                            "provider_event_id has already been persisted"
                        )

                rows = connection.execute(
                    """
                    SELECT
                        run_id,
                        sequence,
                        event_id,
                        provider_event_id,
                        fingerprint,
                        payload_json
                    FROM events
                    WHERE run_id = ?
                    ORDER BY sequence
                    """,
                    (event.run_id,),
                ).fetchall()
                state = initial_run_state(run)
                try:
                    for row in rows:
                        state = apply_lifecycle_event(
                            state,
                            self._event_from_row(row),
                        )
                except (
                    EventConflictError,
                    EventSequenceGapError,
                    InvalidLifecycleTransition,
                ) as exc:
                    raise EventStoreCorruptError(
                        "persisted lifecycle events contain an invalid transition"
                    ) from exc

                apply_lifecycle_event(state, event)

                connection.execute(
                    """
                    INSERT INTO events(
                        run_id,
                        sequence,
                        event_id,
                        provider_event_id,
                        fingerprint,
                        payload_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.run_id,
                        event.sequence,
                        event.event_id,
                        event.provider_event_id,
                        fingerprint,
                        payload,
                    ),
                )
                connection.execute("COMMIT")
                return AppendResult.APPENDED
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def load_conversation(
        self,
        conversation_id: str,
    ) -> ConversationHandle:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    conversation_id,
                    provider,
                    surface,
                    provider_conversation_id,
                    fingerprint,
                    payload_json
                FROM conversations
                WHERE conversation_id = ?
                """,
                (conversation_id,),
            ).fetchone()
        if row is None:
            raise KeyError(conversation_id)
        return self._conversation_from_row(row)

    def load_turn(self, turn_id: str) -> CommittedTurn:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    turn_id,
                    conversation_id,
                    idempotency_key,
                    fingerprint,
                    payload_json
                FROM turns
                WHERE turn_id = ?
                """,
                (turn_id,),
            ).fetchone()
        if row is None:
            raise KeyError(turn_id)
        return self._turn_from_row(row)

    def load_run(self, run_id: str) -> ProviderRun:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    run_id,
                    conversation_id,
                    turn_id,
                    idempotency_key,
                    provider,
                    surface,
                    provider_run_id,
                    fingerprint,
                    payload_json
                FROM runs
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
        if row is None:
            raise KeyError(run_id)
        return self._run_from_row(row)

    def load_events(self, run_id: str) -> list[LifecycleEvent]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    run_id,
                    sequence,
                    event_id,
                    provider_event_id,
                    fingerprint,
                    payload_json
                FROM events
                WHERE run_id = ?
                ORDER BY sequence
                """,
                (run_id,),
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def replay(self, run_id: str) -> ProviderRunState:
        state = initial_run_state(self.load_run(run_id))
        try:
            for event in self.load_events(run_id):
                state = apply_lifecycle_event(state, event)
        except (
            EventConflictError,
            EventSequenceGapError,
            InvalidLifecycleTransition,
        ) as exc:
            raise EventStoreCorruptError(
                "persisted lifecycle events contain an invalid transition"
            ) from exc
        return state

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                result = connection.execute("PRAGMA quick_check").fetchone()
                if result is None or result[0] != "ok":
                    raise EventStoreCorruptError(
                        "SQLite quick_check failed"
                    )

                self._begin(connection)
                try:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS metadata(
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL
                        )
                        """
                    )
                    row = connection.execute(
                        """
                        SELECT value
                        FROM metadata
                        WHERE key = 'schema_version'
                        """
                    ).fetchone()
                    if row is None:
                        connection.execute(
                            """
                            INSERT INTO metadata(key, value)
                            VALUES ('schema_version', ?)
                            """,
                            (_SCHEMA_VERSION,),
                        )
                    elif row["value"] != _SCHEMA_VERSION:
                        raise UnsupportedSchemaVersion(
                            "unsupported lifecycle schema version: "
                            f"{row['value']}"
                        )

                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS conversations(
                            conversation_id TEXT PRIMARY KEY,
                            provider TEXT NOT NULL,
                            surface TEXT NOT NULL,
                            provider_conversation_id TEXT,
                            fingerprint TEXT NOT NULL,
                            payload_json TEXT NOT NULL
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE UNIQUE INDEX IF NOT EXISTS
                        conversations_provider_mapping_unique
                        ON conversations(
                            provider,
                            surface,
                            provider_conversation_id
                        )
                        WHERE provider_conversation_id IS NOT NULL
                        """
                    )
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS turns(
                            turn_id TEXT PRIMARY KEY,
                            conversation_id TEXT NOT NULL,
                            idempotency_key TEXT NOT NULL UNIQUE,
                            fingerprint TEXT NOT NULL,
                            payload_json TEXT NOT NULL,
                            FOREIGN KEY(conversation_id)
                                REFERENCES conversations(conversation_id)
                                ON DELETE RESTRICT
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS runs(
                            run_id TEXT PRIMARY KEY,
                            conversation_id TEXT NOT NULL,
                            turn_id TEXT NOT NULL UNIQUE,
                            idempotency_key TEXT NOT NULL UNIQUE,
                            provider TEXT NOT NULL,
                            surface TEXT NOT NULL,
                            provider_run_id TEXT,
                            fingerprint TEXT NOT NULL,
                            payload_json TEXT NOT NULL,
                            FOREIGN KEY(conversation_id)
                                REFERENCES conversations(conversation_id)
                                ON DELETE RESTRICT,
                            FOREIGN KEY(turn_id)
                                REFERENCES turns(turn_id)
                                ON DELETE RESTRICT
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE UNIQUE INDEX IF NOT EXISTS
                        runs_provider_mapping_unique
                        ON runs(provider, surface, provider_run_id)
                        WHERE provider_run_id IS NOT NULL
                        """
                    )
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS events(
                            run_id TEXT NOT NULL,
                            sequence INTEGER NOT NULL CHECK(sequence >= 1),
                            event_id TEXT NOT NULL UNIQUE,
                            provider_event_id TEXT,
                            fingerprint TEXT NOT NULL,
                            payload_json TEXT NOT NULL,
                            PRIMARY KEY(run_id, sequence),
                            FOREIGN KEY(run_id)
                                REFERENCES runs(run_id)
                                ON DELETE RESTRICT
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE UNIQUE INDEX IF NOT EXISTS
                        events_provider_id_unique
                        ON events(run_id, provider_event_id)
                        WHERE provider_event_id IS NOT NULL
                        """
                    )

                    self._verify_schema(connection)
                    foreign_key_problem = connection.execute(
                        "PRAGMA foreign_key_check"
                    ).fetchone()
                    if foreign_key_problem is not None:
                        raise EventStoreCorruptError(
                            "SQLite foreign key check failed"
                        )
                    connection.execute("COMMIT")
                except Exception:
                    connection.execute("ROLLBACK")
                    raise
        except UnsupportedSchemaVersion:
            raise
        except EventStoreCorruptError:
            raise
        except sqlite3.DatabaseError as exc:
            raise EventStoreCorruptError(
                "invalid or corrupt lifecycle event store"
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=5.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        expected = {
            "metadata": {"key", "value"},
            "conversations": {
                "conversation_id",
                "provider",
                "surface",
                "provider_conversation_id",
                "fingerprint",
                "payload_json",
            },
            "turns": {
                "turn_id",
                "conversation_id",
                "idempotency_key",
                "fingerprint",
                "payload_json",
            },
            "runs": {
                "run_id",
                "conversation_id",
                "turn_id",
                "idempotency_key",
                "provider",
                "surface",
                "provider_run_id",
                "fingerprint",
                "payload_json",
            },
            "events": {
                "run_id",
                "sequence",
                "event_id",
                "provider_event_id",
                "fingerprint",
                "payload_json",
            },
        }
        for table, expected_columns in expected.items():
            rows = connection.execute(
                f"PRAGMA table_info({table})"  # noqa: S608
            ).fetchall()
            actual_columns = {str(row["name"]) for row in rows}
            if actual_columns != expected_columns:
                raise EventStoreCorruptError(
                    f"unexpected lifecycle schema for table {table}"
                )

    @staticmethod
    def _conversation_from_row(
        row: sqlite3.Row,
    ) -> ConversationHandle:
        model = LifecycleEventStore._validate_payload(
            payload=str(row["payload_json"]),
            fingerprint=str(row["fingerprint"]),
            model_name="conversation",
            validator=ConversationHandle.model_validate_json,
        )
        if (
            model.conversation_id != row["conversation_id"]
            or model.provider != row["provider"]
            or model.surface != row["surface"]
            or model.provider_conversation_id != row["provider_conversation_id"]
        ):
            raise EventStoreCorruptError(
                "conversation columns do not match its payload"
            )
        return model

    @staticmethod
    def _turn_from_row(row: sqlite3.Row) -> CommittedTurn:
        model = LifecycleEventStore._validate_payload(
            payload=str(row["payload_json"]),
            fingerprint=str(row["fingerprint"]),
            model_name="committed turn",
            validator=CommittedTurn.model_validate_json,
        )
        if (
            model.turn_id != row["turn_id"]
            or model.conversation_id != row["conversation_id"]
            or model.idempotency_key != row["idempotency_key"]
        ):
            raise EventStoreCorruptError(
                "committed turn columns do not match its payload"
            )
        return model

    @staticmethod
    def _run_from_row(row: sqlite3.Row) -> ProviderRun:
        model = LifecycleEventStore._validate_payload(
            payload=str(row["payload_json"]),
            fingerprint=str(row["fingerprint"]),
            model_name="provider run",
            validator=ProviderRun.model_validate_json,
        )
        if (
            model.run_id != row["run_id"]
            or model.conversation_id != row["conversation_id"]
            or model.turn_id != row["turn_id"]
            or model.idempotency_key != row["idempotency_key"]
            or model.provider != row["provider"]
            or model.surface != row["surface"]
            or model.provider_run_id != row["provider_run_id"]
        ):
            raise EventStoreCorruptError(
                "provider run columns do not match its payload"
            )
        return model

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> LifecycleEvent:
        payload = str(row["payload_json"])
        fingerprint = str(row["fingerprint"])
        if _fingerprint(payload) != fingerprint:
            raise EventStoreCorruptError(
                "lifecycle event fingerprint mismatch"
            )
        try:
            event = LIFECYCLE_EVENT_ADAPTER.validate_json(payload)
        except (TypeError, ValueError) as exc:
            raise EventStoreCorruptError(
                "invalid lifecycle event payload"
            ) from exc
        if (
            event.run_id != row["run_id"]
            or event.sequence != row["sequence"]
            or event.event_id != row["event_id"]
            or event.provider_event_id != row["provider_event_id"]
            or lifecycle_event_fingerprint(event) != fingerprint
        ):
            raise EventStoreCorruptError(
                "lifecycle event columns do not match its payload"
            )
        return event

    @staticmethod
    def _validate_payload(
        *,
        payload: str,
        fingerprint: str,
        model_name: str,
        validator: Any,
    ) -> Any:
        if _fingerprint(payload) != fingerprint:
            raise EventStoreCorruptError(
                f"{model_name} fingerprint mismatch"
            )
        try:
            model = validator(payload)
        except (TypeError, ValueError) as exc:
            raise EventStoreCorruptError(
                f"invalid {model_name} payload"
            ) from exc
        normalized = model.model_dump_json(exclude_none=False)
        if _fingerprint(normalized) != fingerprint:
            raise EventStoreCorruptError(
                f"{model_name} payload is not canonical"
            )
        return model


def _fingerprint(payload: str) -> str:
    return sha256(payload.encode("utf-8")).hexdigest()
