from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import sys
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from .models import TaskEnvelope

_SCHEMA_VERSION = 1
_REQUEST_HMAC_DOMAIN = b"approval-request-v1"
_ROW_HMAC_DOMAIN = b"approval-row-v1"
_DEFAULT_BUSY_TIMEOUT_SECONDS = 5.0
_APPROVAL_STATES = {"pending", "approved", "denied", "consumed"}

ApprovalState = Literal["pending", "approved", "denied", "consumed"]


class ApprovalStoreUnavailableError(RuntimeError):
    """Raised when the local approval store cannot be used safely."""


class ApprovalNotFoundError(ValueError):
    """Raised when an approval identifier is unknown."""


class ApprovalPendingError(ValueError):
    """Raised when an approval is still waiting for a local decision."""


class ApprovalDeniedError(ValueError):
    """Raised when a local operator denied an approval."""


class ApprovalConsumedError(ValueError):
    """Raised when an approval was already used."""


class ApprovalExpiredError(ValueError):
    """Raised when an approval expired before use."""


class ApprovalMismatchError(ValueError):
    """Raised when an approval does not match the resubmitted action."""


class ApprovalStateError(ValueError):
    """Raised when a local decision is incompatible with the current state."""


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    request_fingerprint: str
    task_id: str
    capability: str
    provider: str
    model: str | None
    state: ApprovalState
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None
    consumed_at: datetime | None

    def safe_dict(self) -> dict[str, object]:
        return {
            "approval_id": self.approval_id,
            "request_fingerprint": self.request_fingerprint,
            "task_id": self.task_id,
            "capability": self.capability,
            "provider": self.provider,
            "model": self.model,
            "state": self.state,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "consumed_at": self.consumed_at.isoformat() if self.consumed_at else None,
        }


@dataclass(frozen=True)
class _StoredApproval:
    approval_id: str
    request_hmac: str
    task_id: str
    capability: str
    provider: str
    model: str | None
    state: ApprovalState
    created_at_us: int
    expires_at_us: int
    decided_at_us: int | None
    consumed_at_us: int | None
    row_hmac: str


def approval_request_payload(task: TaskEnvelope) -> bytes:
    data = task.model_dump(
        mode="json",
        include={"version", "task_id", "agent", "capability", "arguments"},
    )
    return _canonical_bytes(data)


class ApprovalStore:
    """HMAC-bound, transactional local approval state."""

    def __init__(
        self,
        database_path: Path,
        key: str,
        *,
        max_entries: int = 1_000,
        ttl_seconds: int = 900,
        clock: Callable[[], datetime] | None = None,
        busy_timeout_seconds: float = _DEFAULT_BUSY_TIMEOUT_SECONDS,
    ):
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < 32:
            raise ValueError("approval key must contain at least 32 UTF-8 bytes")
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        if ttl_seconds < 30:
            raise ValueError("ttl_seconds must be at least 30")
        if busy_timeout_seconds <= 0:
            raise ValueError("busy_timeout_seconds must be positive")

        self.database_path = Path(database_path)
        self._key = key_bytes
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._busy_timeout_seconds = busy_timeout_seconds
        self._initialize()

    def verify(self) -> None:
        self._assert_safe_database_path()
        try:
            with closing(self._connect()) as connection:
                quick_check = connection.execute("PRAGMA quick_check").fetchone()
                if quick_check is None or quick_check[0] != "ok":
                    raise ApprovalStoreUnavailableError(
                        "approval database integrity check failed"
                    )

                schema_version = connection.execute(
                    "SELECT value FROM approval_metadata WHERE key = 'schema_version'"
                ).fetchone()
                if schema_version is None or schema_version[0] != str(_SCHEMA_VERSION):
                    raise ApprovalStoreUnavailableError(
                        "unsupported approval database schema"
                    )

                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(approvals)"
                    ).fetchall()
                }
                expected_columns = {
                    "approval_id",
                    "request_hmac",
                    "task_id",
                    "capability",
                    "provider",
                    "model",
                    "state",
                    "created_at_us",
                    "expires_at_us",
                    "decided_at_us",
                    "consumed_at_us",
                    "row_hmac",
                }
                if columns != expected_columns:
                    raise ApprovalStoreUnavailableError(
                        "unexpected approval database schema"
                    )

                rows = connection.execute(
                    """
                    SELECT approval_id, request_hmac, task_id, capability, provider,
                           model, state, created_at_us, expires_at_us, decided_at_us,
                           consumed_at_us, row_hmac
                    FROM approvals
                    """
                ).fetchall()
                if len(rows) > self._max_entries:
                    raise ApprovalStoreUnavailableError(
                        "approval database exceeds configured capacity"
                    )
                for row in rows:
                    stored = self._stored_from_row(row)
                    self._verify_stored(stored)
        except ApprovalStoreUnavailableError:
            raise
        except (sqlite3.DatabaseError, OSError) as exc:
            raise ApprovalStoreUnavailableError(
                "approval database is unavailable"
            ) from exc

    def create(self, task: TaskEnvelope) -> ApprovalRecord:
        now = self._clock()
        now_us = _datetime_to_microseconds(now)
        expires_at_us = _datetime_to_microseconds(
            now + timedelta(seconds=self._ttl_seconds)
        )
        request_hmac = self._request_hmac(task)

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    self._delete_expired(connection, now_us)
                    existing_row = connection.execute(
                        """
                        SELECT approval_id, request_hmac, task_id, capability, provider,
                               model, state, created_at_us, expires_at_us, decided_at_us,
                               consumed_at_us, row_hmac
                        FROM approvals
                        WHERE request_hmac = ?
                          AND state IN ('pending', 'approved')
                          AND expires_at_us > ?
                        ORDER BY created_at_us DESC
                        LIMIT 1
                        """,
                        (request_hmac, now_us),
                    ).fetchone()
                    if existing_row is not None:
                        stored = self._stored_from_row(existing_row)
                        self._verify_stored(stored)
                        connection.commit()
                        return self._record_from_stored(stored)

                    count = connection.execute(
                        "SELECT COUNT(*) FROM approvals"
                    ).fetchone()[0]
                    if count >= self._max_entries:
                        raise ApprovalStoreUnavailableError(
                            "approval store capacity exhausted"
                        )

                    stored = self._new_stored(
                        task,
                        request_hmac=request_hmac,
                        created_at_us=now_us,
                        expires_at_us=expires_at_us,
                    )
                    connection.execute(
                        """
                        INSERT INTO approvals (
                            approval_id, request_hmac, task_id, capability, provider,
                            model, state, created_at_us, expires_at_us, decided_at_us,
                            consumed_at_us, row_hmac
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        self._stored_values(stored),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
        except ApprovalStoreUnavailableError:
            raise
        except (sqlite3.DatabaseError, OSError) as exc:
            raise ApprovalStoreUnavailableError(
                "approval database is unavailable"
            ) from exc

        self._restrict_database_permissions()
        return self._record_from_stored(stored)

    def list_pending(self) -> list[ApprovalRecord]:
        now_us = _datetime_to_microseconds(self._clock())
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    self._delete_expired(connection, now_us)
                    rows = connection.execute(
                        """
                        SELECT approval_id, request_hmac, task_id, capability, provider,
                               model, state, created_at_us, expires_at_us, decided_at_us,
                               consumed_at_us, row_hmac
                        FROM approvals
                        WHERE state = 'pending'
                        ORDER BY created_at_us
                        """
                    ).fetchall()
                    records = []
                    for row in rows:
                        stored = self._stored_from_row(row)
                        self._verify_stored(stored)
                        records.append(self._record_from_stored(stored))
                    connection.commit()
                    return records
                except Exception:
                    connection.rollback()
                    raise
        except ApprovalStoreUnavailableError:
            raise
        except (sqlite3.DatabaseError, OSError) as exc:
            raise ApprovalStoreUnavailableError(
                "approval database is unavailable"
            ) from exc

    def inspect(self, approval_id: str, task: TaskEnvelope) -> ApprovalRecord:
        now_us = _datetime_to_microseconds(self._clock())
        request_hmac = self._request_hmac(task)

        try:
            with closing(self._connect()) as connection:
                stored = self._load(connection, approval_id)
                if stored.expires_at_us <= now_us:
                    raise ApprovalExpiredError("approval expired")
                if not hmac.compare_digest(stored.request_hmac, request_hmac):
                    raise ApprovalMismatchError(
                        "approval does not match submitted task"
                    )
                return self._record_from_stored(stored)
        except (
            ApprovalNotFoundError,
            ApprovalExpiredError,
            ApprovalMismatchError,
        ):
            raise
        except ApprovalStoreUnavailableError:
            raise
        except (sqlite3.DatabaseError, OSError) as exc:
            raise ApprovalStoreUnavailableError(
                "approval database is unavailable"
            ) from exc

    def approve(self, approval_id: str, task: TaskEnvelope) -> ApprovalRecord:
        return self._decide(approval_id, "approved", task=task)

    def deny(self, approval_id: str) -> ApprovalRecord:
        return self._decide(approval_id, "denied")

    def consume(self, approval_id: str, task: TaskEnvelope) -> ApprovalRecord:
        now_us = _datetime_to_microseconds(self._clock())
        request_hmac = self._request_hmac(task)

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    stored = self._load(connection, approval_id)
                    if stored.expires_at_us <= now_us:
                        raise ApprovalExpiredError("approval expired")
                    if not hmac.compare_digest(stored.request_hmac, request_hmac):
                        raise ApprovalMismatchError(
                            "approval does not match submitted task"
                        )
                    if stored.state == "pending":
                        raise ApprovalPendingError("approval is still pending")
                    if stored.state == "denied":
                        raise ApprovalDeniedError("approval was denied")
                    if stored.state == "consumed":
                        raise ApprovalConsumedError("approval was already used")

                    updated = self._replace_state(
                        stored,
                        state="consumed",
                        consumed_at_us=now_us,
                    )
                    self._update(connection, updated)
                    connection.commit()
                    return self._record_from_stored(updated)
                except Exception:
                    connection.rollback()
                    raise
        except (
            ApprovalNotFoundError,
            ApprovalPendingError,
            ApprovalDeniedError,
            ApprovalConsumedError,
            ApprovalExpiredError,
            ApprovalMismatchError,
        ):
            raise
        except ApprovalStoreUnavailableError:
            raise
        except (sqlite3.DatabaseError, OSError) as exc:
            raise ApprovalStoreUnavailableError(
                "approval database is unavailable"
            ) from exc

    def _decide(
        self,
        approval_id: str,
        decision: Literal["approved", "denied"],
        *,
        task: TaskEnvelope | None = None,
    ) -> ApprovalRecord:
        now_us = _datetime_to_microseconds(self._clock())
        request_hmac = self._request_hmac(task) if task is not None else None

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    stored = self._load(connection, approval_id)
                    if stored.expires_at_us <= now_us:
                        raise ApprovalExpiredError("approval expired")
                    if request_hmac is not None and not hmac.compare_digest(
                        stored.request_hmac, request_hmac
                    ):
                        raise ApprovalMismatchError(
                            "approval does not match submitted task"
                        )
                    if stored.state == decision:
                        connection.commit()
                        return self._record_from_stored(stored)
                    if stored.state != "pending":
                        raise ApprovalStateError(
                            f"approval is already {stored.state}"
                        )

                    updated = self._replace_state(
                        stored,
                        state=decision,
                        decided_at_us=now_us,
                    )
                    self._update(connection, updated)
                    connection.commit()
                    return self._record_from_stored(updated)
                except Exception:
                    connection.rollback()
                    raise
        except (
            ApprovalNotFoundError,
            ApprovalExpiredError,
            ApprovalMismatchError,
            ApprovalStateError,
        ):
            raise
        except ApprovalStoreUnavailableError:
            raise
        except (sqlite3.DatabaseError, OSError) as exc:
            raise ApprovalStoreUnavailableError(
                "approval database is unavailable"
            ) from exc

    def _initialize(self) -> None:
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ApprovalStoreUnavailableError(
                "approval database directory is unavailable"
            ) from exc
        self._assert_safe_database_path()

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS approval_metadata (
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS approvals (
                            approval_id TEXT PRIMARY KEY,
                            request_hmac TEXT NOT NULL
                                CHECK(length(request_hmac) = 64),
                            task_id TEXT NOT NULL,
                            capability TEXT NOT NULL,
                            provider TEXT NOT NULL,
                            model TEXT,
                            state TEXT NOT NULL
                                CHECK(state IN (
                                    'pending', 'approved', 'denied', 'consumed'
                                )),
                            created_at_us INTEGER NOT NULL,
                            expires_at_us INTEGER NOT NULL,
                            decided_at_us INTEGER,
                            consumed_at_us INTEGER,
                            row_hmac TEXT NOT NULL
                                CHECK(length(row_hmac) = 64)
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE INDEX IF NOT EXISTS approvals_request_idx
                        ON approvals(request_hmac, state, expires_at_us)
                        """
                    )
                    connection.execute(
                        """
                        CREATE INDEX IF NOT EXISTS approvals_expiry_idx
                        ON approvals(expires_at_us)
                        """
                    )

                    existing_version = connection.execute(
                        """
                        SELECT value
                        FROM approval_metadata
                        WHERE key = 'schema_version'
                        """
                    ).fetchone()
                    if existing_version is None:
                        connection.execute(
                            """
                            INSERT INTO approval_metadata (key, value)
                            VALUES ('schema_version', ?)
                            """,
                            (str(_SCHEMA_VERSION),),
                        )
                    elif existing_version[0] != str(_SCHEMA_VERSION):
                        raise ApprovalStoreUnavailableError(
                            "unsupported approval database schema"
                        )

                    self._delete_expired(
                        connection,
                        _datetime_to_microseconds(self._clock()),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
        except ApprovalStoreUnavailableError:
            raise
        except (sqlite3.DatabaseError, OSError) as exc:
            raise ApprovalStoreUnavailableError(
                "approval database is unavailable"
            ) from exc

        self._restrict_database_permissions()
        self.verify()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self._busy_timeout_seconds,
            isolation_level=None,
        )
        try:
            connection.execute(
                f"PRAGMA busy_timeout = {int(self._busy_timeout_seconds * 1000)}"
            )
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA trusted_schema = OFF")
        except Exception:
            connection.close()
            raise
        return connection

    def _load(
        self,
        connection: sqlite3.Connection,
        approval_id: str,
    ) -> _StoredApproval:
        row = connection.execute(
            """
            SELECT approval_id, request_hmac, task_id, capability, provider,
                   model, state, created_at_us, expires_at_us, decided_at_us,
                   consumed_at_us, row_hmac
            FROM approvals
            WHERE approval_id = ?
            """,
            (approval_id,),
        ).fetchone()
        if row is None:
            raise ApprovalNotFoundError("approval not found")
        stored = self._stored_from_row(row)
        self._verify_stored(stored)
        return stored

    def _update(
        self,
        connection: sqlite3.Connection,
        stored: _StoredApproval,
    ) -> None:
        connection.execute(
            """
            UPDATE approvals
            SET request_hmac = ?, task_id = ?, capability = ?, provider = ?,
                model = ?, state = ?, created_at_us = ?, expires_at_us = ?,
                decided_at_us = ?, consumed_at_us = ?, row_hmac = ?
            WHERE approval_id = ?
            """,
            (
                stored.request_hmac,
                stored.task_id,
                stored.capability,
                stored.provider,
                stored.model,
                stored.state,
                stored.created_at_us,
                stored.expires_at_us,
                stored.decided_at_us,
                stored.consumed_at_us,
                stored.row_hmac,
                stored.approval_id,
            ),
        )

    def _delete_expired(
        self,
        connection: sqlite3.Connection,
        now_us: int,
    ) -> None:
        connection.execute(
            "DELETE FROM approvals WHERE expires_at_us <= ?",
            (now_us,),
        )

    def _new_stored(
        self,
        task: TaskEnvelope,
        *,
        request_hmac: str,
        created_at_us: int,
        expires_at_us: int,
    ) -> _StoredApproval:
        fields: dict[str, object] = {
            "approval_id": secrets.token_urlsafe(24),
            "request_hmac": request_hmac,
            "task_id": task.task_id,
            "capability": task.capability,
            "provider": task.agent.provider,
            "model": task.agent.model,
            "state": "pending",
            "created_at_us": created_at_us,
            "expires_at_us": expires_at_us,
            "decided_at_us": None,
            "consumed_at_us": None,
        }
        return _StoredApproval(
            **fields,
            row_hmac=self._row_hmac(fields),
        )

    def _replace_state(
        self,
        stored: _StoredApproval,
        *,
        state: ApprovalState,
        decided_at_us: int | None = None,
        consumed_at_us: int | None = None,
    ) -> _StoredApproval:
        fields = self._stored_fields(stored)
        fields["state"] = state
        if decided_at_us is not None:
            fields["decided_at_us"] = decided_at_us
        if consumed_at_us is not None:
            fields["consumed_at_us"] = consumed_at_us
        return _StoredApproval(
            **fields,
            row_hmac=self._row_hmac(fields),
        )

    def _verify_stored(self, stored: _StoredApproval) -> None:
        if stored.state not in _APPROVAL_STATES:
            raise ApprovalStoreUnavailableError("invalid approval state")
        if stored.expires_at_us <= stored.created_at_us:
            raise ApprovalStoreUnavailableError("invalid approval timestamps")
        expected = self._row_hmac(self._stored_fields(stored))
        if not hmac.compare_digest(expected, stored.row_hmac):
            raise ApprovalStoreUnavailableError("approval record HMAC is invalid")

    def _request_hmac(self, task: TaskEnvelope) -> str:
        return _keyed_digest(
            self._key,
            _REQUEST_HMAC_DOMAIN,
            approval_request_payload(task),
        )

    def _row_hmac(self, fields: Mapping[str, object]) -> str:
        return _keyed_digest(
            self._key,
            _ROW_HMAC_DOMAIN,
            _canonical_bytes(fields),
        )

    @staticmethod
    def _stored_fields(stored: _StoredApproval) -> dict[str, object]:
        return {
            "approval_id": stored.approval_id,
            "request_hmac": stored.request_hmac,
            "task_id": stored.task_id,
            "capability": stored.capability,
            "provider": stored.provider,
            "model": stored.model,
            "state": stored.state,
            "created_at_us": stored.created_at_us,
            "expires_at_us": stored.expires_at_us,
            "decided_at_us": stored.decided_at_us,
            "consumed_at_us": stored.consumed_at_us,
        }

    @staticmethod
    def _stored_values(stored: _StoredApproval) -> tuple[object, ...]:
        return (
            stored.approval_id,
            stored.request_hmac,
            stored.task_id,
            stored.capability,
            stored.provider,
            stored.model,
            stored.state,
            stored.created_at_us,
            stored.expires_at_us,
            stored.decided_at_us,
            stored.consumed_at_us,
            stored.row_hmac,
        )

    @staticmethod
    def _stored_from_row(row: tuple[object, ...]) -> _StoredApproval:
        return _StoredApproval(
            approval_id=str(row[0]),
            request_hmac=str(row[1]),
            task_id=str(row[2]),
            capability=str(row[3]),
            provider=str(row[4]),
            model=None if row[5] is None else str(row[5]),
            state=str(row[6]),  # type: ignore[arg-type]
            created_at_us=int(row[7]),
            expires_at_us=int(row[8]),
            decided_at_us=None if row[9] is None else int(row[9]),
            consumed_at_us=None if row[10] is None else int(row[10]),
            row_hmac=str(row[11]),
        )

    @staticmethod
    def _record_from_stored(stored: _StoredApproval) -> ApprovalRecord:
        return ApprovalRecord(
            approval_id=stored.approval_id,
            request_fingerprint=stored.request_hmac[:16],
            task_id=stored.task_id,
            capability=stored.capability,
            provider=stored.provider,
            model=stored.model,
            state=stored.state,
            created_at=_microseconds_to_datetime(stored.created_at_us),
            expires_at=_microseconds_to_datetime(stored.expires_at_us),
            decided_at=(
                None
                if stored.decided_at_us is None
                else _microseconds_to_datetime(stored.decided_at_us)
            ),
            consumed_at=(
                None
                if stored.consumed_at_us is None
                else _microseconds_to_datetime(stored.consumed_at_us)
            ),
        )

    def _assert_safe_database_path(self) -> None:
        if not self.database_path.exists() and not self.database_path.is_symlink():
            return

        file_stat = self.database_path.lstat()
        if stat.S_ISLNK(file_stat.st_mode):
            raise ApprovalStoreUnavailableError(
                "approval database cannot be a symbolic link"
            )
        if not stat.S_ISREG(file_stat.st_mode):
            raise ApprovalStoreUnavailableError(
                "approval database is not a regular file"
            )

    def _restrict_database_permissions(self) -> None:
        try:
            os.chmod(self.database_path, 0o600)
        except OSError:
            pass


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _keyed_digest(key: bytes, domain: bytes, payload: bytes) -> str:
    return hmac.new(key, domain + b"\0" + payload, hashlib.sha256).hexdigest()


def _datetime_to_microseconds(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return int(value.timestamp() * 1_000_000)


def _microseconds_to_datetime(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)


def verify_approval_task(task: TaskEnvelope, secret: str) -> None:
    from .auth import canonical_payload

    if task.approval_id is not None:
        raise ValueError(
            "approval task file must contain the original request without approval_id"
        )
    digest = hmac.new(
        secret.encode("utf-8"),
        canonical_payload(task),
        hashlib.sha256,
    ).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    if not hmac.compare_digest(expected, task.signature):
        raise ValueError("invalid task signature")


def _read_task_file(path: str, *, max_bytes: int = 2_000_000) -> TaskEnvelope:
    if path == "-":
        data = sys.stdin.buffer.read(max_bytes + 1)
    else:
        data = Path(path).read_bytes()
    if len(data) > max_bytes:
        raise ValueError("approval task file exceeds size limit")
    return TaskEnvelope.model_validate_json(data)


def _request_display(task: TaskEnvelope, record: ApprovalRecord) -> dict[str, object]:
    request = task.model_dump(
        mode="json",
        include={"version", "task_id", "agent", "capability", "arguments"},
    )
    return {
        "approval": record.safe_dict(),
        "request": request,
    }


def _configured_components() -> tuple[ApprovalStore, object, str]:
    from .audit import AuditLog
    from .config import settings

    store = ApprovalStore(
        settings.approval_db,
        settings.audit_key,
        max_entries=settings.approval_max_entries,
        ttl_seconds=settings.approval_ttl_seconds,
    )
    audit_log = AuditLog(settings.audit_log, settings.audit_key)
    audit_log.verify()
    return store, audit_log, settings.shared_secret


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Manage local Système Local approval requests"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="list pending approvals")
    approve_parser = subparsers.add_parser("approve", help="approve one request")
    approve_parser.add_argument("approval_id")
    approve_parser.add_argument(
        "--task-file",
        required=True,
        help="exact original signed task JSON, or - for stdin",
    )
    approve_parser.add_argument(
        "--yes",
        action="store_true",
        help="skip the interactive approval-ID confirmation",
    )
    deny_parser = subparsers.add_parser("deny", help="deny one request")
    deny_parser.add_argument("approval_id")
    args = parser.parse_args(argv)

    try:
        store, audit_log, shared_secret = _configured_components()
        if args.command == "list":
            print(
                json.dumps(
                    [record.safe_dict() for record in store.list_pending()],
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        if args.command == "approve":
            task = _read_task_file(args.task_file)
            verify_approval_task(task, shared_secret)
            pending_record = store.inspect(args.approval_id, task)
            print(
                json.dumps(
                    _request_display(task, pending_record),
                    indent=2,
                    sort_keys=True,
                )
            )
            if not args.yes:
                try:
                    confirmation = input(
                        "Type the full approval ID to approve this exact request: "
                    ).strip()
                except EOFError as exc:
                    raise ValueError("approval confirmation was not provided") from exc
                if not hmac.compare_digest(confirmation, args.approval_id):
                    raise ValueError("approval confirmation did not match")
            record = store.approve(args.approval_id, task)
            status = "approved"
        else:
            record = store.deny(args.approval_id)
            status = "denied"

        audit_log.append(  # type: ignore[attr-defined]
            {
                "task_id": record.task_id,
                "capability": record.capability,
                "status": f"approval_{status}",
                "approval_id": record.approval_id,
            }
        )
        print(json.dumps(record.safe_dict(), indent=2, sort_keys=True))
        return 0
    except (ValueError, ApprovalStoreUnavailableError) as exc:
        print(
            json.dumps({"status": "error", "error": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
