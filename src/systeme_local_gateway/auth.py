from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import threading
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from .models import TaskEnvelope


_SCHEMA_VERSION = 1
_NONCE_HMAC_DOMAIN = b"replay-nonce-v1"
_DEFAULT_BUSY_TIMEOUT_SECONDS = 5.0


class ReplayGuardUnavailableError(RuntimeError):
    """Raised when replay protection cannot safely accept a new nonce."""


class ReplayGuardProtocol(Protocol):
    def check_and_mark(self, nonce: str, expires_at: datetime) -> None: ...


def canonical_payload(task: TaskEnvelope) -> bytes:
    data = task.model_dump(mode="json", exclude={"signature"})
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ReplayGuard:
    """Bounded in-memory replay guard used by tests and ephemeral processes."""

    def __init__(
        self,
        max_entries: int = 10_000,
        *,
        clock: Callable[[], datetime] | None = None,
    ):
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._seen: dict[str, float] = {}
        self._max_entries = max_entries
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()

    def check_and_mark(self, nonce: str, expires_at: datetime) -> None:
        now_timestamp = self._clock().timestamp()
        expires_timestamp = expires_at.timestamp()
        if expires_timestamp <= now_timestamp:
            raise ValueError("task expired")

        with self._lock:
            expired = [
                seen_nonce
                for seen_nonce, seen_expiry in self._seen.items()
                if seen_expiry <= now_timestamp
            ]
            for seen_nonce in expired:
                del self._seen[seen_nonce]

            if nonce in self._seen:
                raise ValueError("replayed task nonce")
            if len(self._seen) >= self._max_entries:
                raise ReplayGuardUnavailableError("replay guard capacity exhausted")

            self._seen[nonce] = expires_timestamp


class SQLiteReplayGuard:
    """Transactional replay guard that persists nonce fingerprints in SQLite."""

    def __init__(
        self,
        database_path: Path,
        key: str,
        max_entries: int = 10_000,
        *,
        clock: Callable[[], datetime] | None = None,
        busy_timeout_seconds: float = _DEFAULT_BUSY_TIMEOUT_SECONDS,
    ):
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < 32:
            raise ValueError("replay guard key must contain at least 32 UTF-8 bytes")
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        if busy_timeout_seconds <= 0:
            raise ValueError("busy_timeout_seconds must be positive")

        self.database_path = Path(database_path)
        self._key = key_bytes
        self._max_entries = max_entries
        self._clock = clock or (lambda: datetime.now(UTC))
        self._busy_timeout_seconds = busy_timeout_seconds
        self._initialize()

    def verify(self) -> None:
        self._assert_safe_database_path()
        try:
            with closing(self._connect()) as connection:
                quick_check = connection.execute("PRAGMA quick_check").fetchone()
                if quick_check is None or quick_check[0] != "ok":
                    raise ReplayGuardUnavailableError("replay database integrity check failed")

                schema_version = connection.execute(
                    "SELECT value FROM replay_metadata WHERE key = 'schema_version'"
                ).fetchone()
                if schema_version is None or schema_version[0] != str(_SCHEMA_VERSION):
                    raise ReplayGuardUnavailableError("unsupported replay database schema")

                columns = {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(seen_nonces)").fetchall()
                }
                if columns != {"nonce_hmac", "expires_at_us", "created_at_us"}:
                    raise ReplayGuardUnavailableError("unexpected replay database schema")

                count = connection.execute("SELECT COUNT(*) FROM seen_nonces").fetchone()[0]
                if count > self._max_entries:
                    raise ReplayGuardUnavailableError("replay database exceeds configured capacity")
        except (sqlite3.DatabaseError, OSError) as exc:
            raise ReplayGuardUnavailableError("replay database is unavailable") from exc

    def check_and_mark(self, nonce: str, expires_at: datetime) -> None:
        now_us = _datetime_to_microseconds(self._clock())
        expires_at_us = _datetime_to_microseconds(expires_at)
        if expires_at_us <= now_us:
            raise ValueError("task expired")

        nonce_hmac = self._nonce_hmac(nonce)

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.execute(
                        "DELETE FROM seen_nonces WHERE expires_at_us <= ?",
                        (now_us,),
                    )

                    existing = connection.execute(
                        "SELECT 1 FROM seen_nonces WHERE nonce_hmac = ?",
                        (nonce_hmac,),
                    ).fetchone()
                    if existing is not None:
                        raise ValueError("replayed task nonce")

                    count = connection.execute("SELECT COUNT(*) FROM seen_nonces").fetchone()[0]
                    if count >= self._max_entries:
                        raise ReplayGuardUnavailableError("replay guard capacity exhausted")

                    connection.execute(
                        """
                        INSERT INTO seen_nonces (nonce_hmac, expires_at_us, created_at_us)
                        VALUES (?, ?, ?)
                        """,
                        (nonce_hmac, expires_at_us, now_us),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
        except ValueError:
            raise
        except ReplayGuardUnavailableError:
            raise
        except (sqlite3.DatabaseError, OSError) as exc:
            raise ReplayGuardUnavailableError("replay database is unavailable") from exc

        self._restrict_database_permissions()

    def _initialize(self) -> None:
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ReplayGuardUnavailableError(
                "replay database directory is unavailable"
            ) from exc
        self._assert_safe_database_path()

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS replay_metadata (
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS seen_nonces (
                            nonce_hmac TEXT PRIMARY KEY
                                CHECK(length(nonce_hmac) = 64),
                            expires_at_us INTEGER NOT NULL,
                            created_at_us INTEGER NOT NULL
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE INDEX IF NOT EXISTS seen_nonces_expiry_idx
                        ON seen_nonces(expires_at_us)
                        """
                    )

                    existing_version = connection.execute(
                        "SELECT value FROM replay_metadata WHERE key = 'schema_version'"
                    ).fetchone()
                    if existing_version is None:
                        connection.execute(
                            """
                            INSERT INTO replay_metadata (key, value)
                            VALUES ('schema_version', ?)
                            """,
                            (str(_SCHEMA_VERSION),),
                        )
                    elif existing_version[0] != str(_SCHEMA_VERSION):
                        raise ReplayGuardUnavailableError(
                            "unsupported replay database schema"
                        )

                    connection.execute(
                        "DELETE FROM seen_nonces WHERE expires_at_us <= ?",
                        (_datetime_to_microseconds(self._clock()),),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
        except ReplayGuardUnavailableError:
            raise
        except (sqlite3.DatabaseError, OSError) as exc:
            raise ReplayGuardUnavailableError("replay database is unavailable") from exc

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

    def _assert_safe_database_path(self) -> None:
        if not self.database_path.exists() and not self.database_path.is_symlink():
            return

        file_stat = self.database_path.lstat()
        if stat.S_ISLNK(file_stat.st_mode):
            raise ReplayGuardUnavailableError("replay database cannot be a symbolic link")
        if not stat.S_ISREG(file_stat.st_mode):
            raise ReplayGuardUnavailableError("replay database is not a regular file")

    def _restrict_database_permissions(self) -> None:
        try:
            os.chmod(self.database_path, 0o600)
        except OSError:
            pass

    def _nonce_hmac(self, nonce: str) -> str:
        return hmac.new(
            self._key,
            _NONCE_HMAC_DOMAIN + b"\0" + nonce.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


def _datetime_to_microseconds(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return int(value.timestamp() * 1_000_000)


def verify_task(
    task: TaskEnvelope,
    secret: str,
    *,
    replay_guard: ReplayGuardProtocol | None = None,
    max_clock_skew_seconds: int = 60,
    max_task_lifetime_seconds: int = 300,
) -> None:
    now = datetime.now(UTC)
    lifetime_seconds = (task.expires_at - task.issued_at).total_seconds()
    if lifetime_seconds > max_task_lifetime_seconds:
        raise ValueError("task lifetime exceeds maximum")
    if task.expires_at <= now:
        raise ValueError("task expired")
    if task.issued_at.timestamp() - now.timestamp() > max_clock_skew_seconds:
        raise ValueError("task issued in the future")

    digest = hmac.new(secret.encode("utf-8"), canonical_payload(task), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    if not hmac.compare_digest(expected, task.signature):
        raise ValueError("invalid task signature")

    if replay_guard is not None:
        replay_guard.check_and_mark(task.nonce, task.expires_at)
