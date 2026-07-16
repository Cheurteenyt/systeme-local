from __future__ import annotations

import argparse
import errno
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from .audit_anchor import (
    AuditAnchorError,
    AuditAnchorTransaction,
    FileAuditAnchor,
    derive_audit_log_id,
)

if os.name == "nt":
    import msvcrt
else:
    import fcntl

_RECORD_VERSION = 2
_GENESIS_HMAC = "0" * 64
_LOCK = threading.RLock()
_DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_POLL_INTERVAL_SECONDS = 0.05
_MAX_TEXT_LENGTH = 512
_MAX_KEYS = 64

_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_URI_CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^@\s/]+@"
)
_KEY_VALUE_SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|cookie|"
    r"signature|private[_-]?key|client[_-]?secret)\b(\s*[:=]\s*)([^\s,;]+)"
)


class AuditIntegrityError(RuntimeError):
    """Raised when an audit log is malformed, legacy, or cryptographically invalid."""


class AuditLockError(RuntimeError):
    """Raised when the audit log cannot be locked safely."""

@dataclass(frozen=True)
class AuditVerification:
    records: int
    last_hmac: str
    anchor_checkpoints: int | None = None


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=str,
    ).encode("utf-8")


def _safe_text(value: object, *, limit: int = _MAX_TEXT_LENGTH) -> str:
    text = str(value)
    text = _PRIVATE_KEY_PATTERN.sub("[REDACTED PRIVATE KEY]", text)
    text = _BEARER_PATTERN.sub("Bearer [REDACTED]", text)
    text = _URI_CREDENTIAL_PATTERN.sub(r"\1[REDACTED]@", text)
    text = _KEY_VALUE_SECRET_PATTERN.sub(r"\1\2[REDACTED]", text)
    if len(text) <= limit:
        return text
    return text[:limit] + "…[truncated]"


def _type_name(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return "array"
    return type(value).__name__


def _keyed_digest(key: bytes, domain: bytes, payload: bytes) -> str:
    return hmac.new(key, domain + b"\0" + payload, hashlib.sha256).hexdigest()


def summarize_payload(value: object, key: bytes) -> dict[str, object]:
    encoded = _canonical_bytes(value)
    summary: dict[str, object] = {
        "type": _type_name(value),
        "canonical_bytes": len(encoded),
        "hmac_sha256": _keyed_digest(key, b"audit-payload-v1", encoded),
    }

    if isinstance(value, Mapping):
        keys = sorted(_safe_text(key, limit=128) for key in value)
        summary["key_count"] = len(keys)
        summary["keys"] = keys[:_MAX_KEYS]
        summary["keys_truncated"] = len(keys) > _MAX_KEYS

        metadata: dict[str, object] = {}
        for key in ("returncode", "truncated", "workspace_isolated"):
            candidate = value.get(key)
            if isinstance(candidate, (bool, int)) and not isinstance(candidate, float):
                metadata[key] = candidate

        command = value.get("command")
        if isinstance(command, Sequence) and not isinstance(
            command, (str, bytes, bytearray)
        ):
            metadata["command_argv_items"] = len(command)

        changes = value.get("workspace_changes")
        if isinstance(changes, Mapping):
            change_metadata: dict[str, object] = {}
            for key in ("added", "modified", "deleted"):
                entries = changes.get(key)
                if isinstance(entries, Sequence) and not isinstance(
                    entries, (str, bytes, bytearray)
                ):
                    change_metadata[f"{key}_count"] = len(entries)
            if isinstance(changes.get("truncated"), bool):
                change_metadata["truncated"] = changes["truncated"]
            if change_metadata:
                metadata["workspace_changes"] = change_metadata

        if metadata:
            summary["metadata"] = metadata

    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        summary["items"] = len(value)

    return summary


def project_audit_event(event: Mapping[str, object], key: bytes) -> dict[str, object]:
    projected: dict[str, object] = {}
    handled = {
        "task_id",
        "agent",
        "capability",
        "status",
        "reason",
        "arguments",
        "output",
        "error",
    }

    for field in ("task_id", "capability", "status"):
        if event.get(field) is not None:
            projected[field] = _safe_text(event[field], limit=256)

    agent = event.get("agent")
    if isinstance(agent, Mapping):
        projected_agent: dict[str, object] = {}
        if agent.get("provider") is not None:
            projected_agent["provider"] = _safe_text(agent["provider"], limit=64)
        if agent.get("model") is not None:
            projected_agent["model"] = _safe_text(agent["model"], limit=128)
        if agent.get("session_id") is not None:
            session_id = str(agent["session_id"]).encode("utf-8")
            projected_agent["session_id_hmac"] = _keyed_digest(
                key, b"audit-session-v1", session_id
            )
        if projected_agent:
            projected["agent"] = projected_agent

    if event.get("reason") is not None:
        projected["reason"] = _safe_text(event["reason"])
    if event.get("error") is not None:
        projected["error_summary"] = summarize_payload(event["error"], key)

    if "arguments" in event:
        projected["arguments_summary"] = summarize_payload(event["arguments"], key)
    if "output" in event:
        projected["output_summary"] = summarize_payload(event["output"], key)

    extras = {str(key): value for key, value in event.items() if key not in handled}
    if extras:
        projected["extra_summary"] = summarize_payload(extras, key)

    return projected


def _entry_hmac(key: bytes, record: Mapping[str, object]) -> str:
    return _keyed_digest(key, b"audit-entry-v2", _canonical_bytes(record))


def _is_lock_contention_error(exc: OSError) -> bool:
    contention_codes = {
        errno.EACCES,
        errno.EAGAIN,
        getattr(errno, "EDEADLK", -1),
    }
    return isinstance(exc, BlockingIOError) or exc.errno in contention_codes


class AuditLog:
    def __init__(
        self,
        log_path: Path,
        key: str,
        *,
        anchor: FileAuditAnchor | None = None,
        lock_timeout_seconds: float = _DEFAULT_LOCK_TIMEOUT_SECONDS,
    ):
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < 32:
            raise ValueError("audit key must contain at least 32 UTF-8 bytes")
        if lock_timeout_seconds <= 0:
            raise ValueError("audit lock timeout must be positive")
        self.log_path = log_path
        self.lock_path = self.log_path.parent / f"{self.log_path.name}.lock"
        self._key = key_bytes
        self._anchor = anchor
        self._lock_timeout_seconds = lock_timeout_seconds

    def verify(self) -> AuditVerification:
        with _LOCK:
            with self._process_lock():
                if self._anchor is None:
                    return self._verify_unlocked()
                with self._anchor.transaction() as anchor:
                    return self._verify_anchored_unlocked(anchor)

    def bootstrap_anchor(self) -> AuditVerification:
        if self._anchor is None:
            raise ValueError("audit anchoring is not configured")
        with _LOCK:
            with self._process_lock():
                with self._anchor.transaction() as anchor:
                    verification = self._verify_unlocked()
                    anchor_verification = anchor.bootstrap(
                        verification.records,
                        verification.last_hmac,
                    )
                    return AuditVerification(
                        records=verification.records,
                        last_hmac=verification.last_hmac,
                        anchor_checkpoints=anchor_verification.checkpoints,
                    )

    def append(self, event: Mapping[str, object]) -> str:
        with _LOCK:
            with self._process_lock():
                if self._anchor is None:
                    verification = self._verify_unlocked()
                    audit_id, _ = self._append_verified_unlocked(
                        event,
                        verification,
                    )
                    return audit_id

                with self._anchor.transaction() as anchor:
                    verification = self._verify_anchored_unlocked(anchor)
                    audit_id, next_verification = (
                        self._append_verified_unlocked(
                            event,
                            verification,
                        )
                    )
                    anchor.append(
                        next_verification.records,
                        next_verification.last_hmac,
                    )
                    return audit_id

    def _verify_anchored_unlocked(
        self,
        anchor: AuditAnchorTransaction,
    ) -> AuditVerification:
        anchor_verification = anchor.verify()
        verification, anchored_hmac = self._scan_unlocked(
            anchor_verification.records
        )

        if anchor_verification.records > verification.records:
            raise AuditIntegrityError(
                "audit log rollback detected against external anchor"
            )
        if anchored_hmac is None or not hmac.compare_digest(
            anchored_hmac,
            anchor_verification.last_hmac,
        ):
            raise AuditIntegrityError(
                "audit log diverges from external anchor"
            )

        if verification.records > anchor_verification.records:
            anchor_verification = anchor.append(
                verification.records,
                verification.last_hmac,
            )

        return AuditVerification(
            records=verification.records,
            last_hmac=verification.last_hmac,
            anchor_checkpoints=anchor_verification.checkpoints,
        )

    def _append_verified_unlocked(
        self,
        event: Mapping[str, object],
        verification: AuditVerification,
    ) -> tuple[str, AuditVerification]:
        audit_id = str(uuid4())
        record: dict[str, object] = {
            "version": _RECORD_VERSION,
            "audit_id": audit_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "previous_hmac": verification.last_hmac,
            **project_audit_event(event, self._key),
        }
        record["entry_hmac"] = _entry_hmac(self._key, record)

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            self.log_path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        with os.fdopen(
            descriptor,
            "a",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(_canonical_bytes(record).decode("utf-8") + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(self.log_path, 0o600)
        except OSError:
            pass

        return (
            audit_id,
            AuditVerification(
                records=verification.records + 1,
                last_hmac=str(record["entry_hmac"]),
            ),
        )

    @contextmanager
    def _process_lock(self) -> Iterator[None]:
        try:
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AuditLockError("audit lock directory is unavailable") from exc

        self._assert_safe_lock_path()
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)

        try:
            descriptor = os.open(self.lock_path, flags, 0o600)
        except OSError as exc:
            raise AuditLockError("audit lock file is unavailable") from exc

        acquired = False
        try:
            descriptor_stat = os.fstat(descriptor)
            self._verify_lock_file_identity(descriptor_stat)

            if descriptor_stat.st_size == 0:
                os.lseek(descriptor, 0, os.SEEK_SET)
                os.write(descriptor, b"\0")
                os.fsync(descriptor)

            try:
                os.chmod(self.lock_path, 0o600)
            except OSError:
                pass

            deadline = time.monotonic() + self._lock_timeout_seconds
            while True:
                try:
                    self._try_acquire_process_lock(descriptor)
                    acquired = True
                    break
                except OSError as exc:
                    if not _is_lock_contention_error(exc):
                        raise AuditLockError("audit lock acquisition failed") from exc
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise AuditLockError(
                            "audit lock acquisition timed out"
                        ) from exc
                    time.sleep(min(_LOCK_POLL_INTERVAL_SECONDS, remaining))

            self._verify_lock_file_identity(os.fstat(descriptor))
            yield
        except AuditLockError:
            raise
        except OSError as exc:
            raise AuditLockError("audit lock is unavailable") from exc
        finally:
            try:
                if acquired:
                    try:
                        self._release_process_lock(descriptor)
                    except OSError:
                        pass
            finally:
                os.close(descriptor)

    def _assert_safe_lock_path(self) -> None:
        if not self.lock_path.exists() and not self.lock_path.is_symlink():
            return

        file_stat = self.lock_path.lstat()
        if stat.S_ISLNK(file_stat.st_mode):
            raise AuditLockError("audit lock file cannot be a symbolic link")
        if not stat.S_ISREG(file_stat.st_mode):
            raise AuditLockError("audit lock path is not a regular file")

    def _verify_lock_file_identity(self, descriptor_stat: os.stat_result) -> None:
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise AuditLockError("audit lock path is not a regular file")

        path_stat = self.lock_path.lstat()
        if stat.S_ISLNK(path_stat.st_mode):
            raise AuditLockError("audit lock file cannot be a symbolic link")
        if (path_stat.st_dev, path_stat.st_ino) != (
            descriptor_stat.st_dev,
            descriptor_stat.st_ino,
        ):
            raise AuditLockError("audit lock file changed during open")

    @staticmethod
    def _try_acquire_process_lock(descriptor: int) -> None:
        if os.name == "nt":
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            return
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    @staticmethod
    def _release_process_lock(descriptor: int) -> None:
        if os.name == "nt":
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            return
        fcntl.flock(descriptor, fcntl.LOCK_UN)

    def _verify_unlocked(self) -> AuditVerification:
        verification, _ = self._scan_unlocked()
        return verification

    def _scan_unlocked(
        self,
        checkpoint_records: int | None = None,
    ) -> tuple[AuditVerification, str | None]:
        checkpoint_hmac = (
            _GENESIS_HMAC if checkpoint_records == 0 else None
        )
        if not self.log_path.exists():
            return (
                AuditVerification(
                    records=0,
                    last_hmac=_GENESIS_HMAC,
                ),
                checkpoint_hmac,
            )
        if not self.log_path.is_file():
            raise AuditIntegrityError(
                "audit log path is not a regular file"
            )
        if self.log_path.stat().st_size == 0:
            return (
                AuditVerification(
                    records=0,
                    last_hmac=_GENESIS_HMAC,
                ),
                checkpoint_hmac,
            )

        with self.log_path.open("rb") as raw_handle:
            raw_handle.seek(-1, os.SEEK_END)
            if raw_handle.read(1) != b"\n":
                raise AuditIntegrityError(
                    "audit log must end with a newline"
                )

        previous_hmac = _GENESIS_HMAC
        records = 0
        audit_ids: set[str] = set()

        with self.log_path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.rstrip("\n")
                if not line:
                    raise AuditIntegrityError(
                        f"blank audit record at line {line_number}"
                    )
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditIntegrityError(
                        f"invalid JSON audit record at line {line_number}"
                    ) from exc
                if not isinstance(record, dict):
                    raise AuditIntegrityError(
                        f"audit record at line {line_number} must be an object"
                    )
                if record.get("version") != _RECORD_VERSION:
                    raise AuditIntegrityError(
                        f"unsupported audit record version at line {line_number}"
                    )
                if record.get("previous_hmac") != previous_hmac:
                    raise AuditIntegrityError(
                        f"broken audit chain at line {line_number}"
                    )

                entry_hmac = record.get("entry_hmac")
                if not isinstance(entry_hmac, str):
                    raise AuditIntegrityError(
                        f"missing audit HMAC at line {line_number}"
                    )
                unsigned = dict(record)
                unsigned.pop("entry_hmac", None)
                expected_hmac = _entry_hmac(self._key, unsigned)
                if not hmac.compare_digest(entry_hmac, expected_hmac):
                    raise AuditIntegrityError(
                        f"invalid audit HMAC at line {line_number}"
                    )

                audit_id = record.get("audit_id")
                if not isinstance(audit_id, str) or audit_id in audit_ids:
                    raise AuditIntegrityError(
                        f"invalid or duplicate audit ID at line {line_number}"
                    )
                audit_ids.add(audit_id)
                previous_hmac = entry_hmac
                records += 1
                if records == checkpoint_records:
                    checkpoint_hmac = entry_hmac

        return (
            AuditVerification(
                records=records,
                last_hmac=previous_hmac,
            ),
            checkpoint_hmac,
        )


def append_audit(log_path: Path, key: str, event: Mapping[str, object]) -> str:
    return AuditLog(log_path, key).append(event)


def verify_audit_log(log_path: Path, key: str) -> AuditVerification:
    return AuditLog(log_path, key).verify()


def _normalized_path(path: Path) -> str:
    return os.path.normcase(os.fspath(path.resolve(strict=False)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify or initialize a Système Local audit anchor"
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("verify", "anchor-init"),
        default="verify",
    )
    parser.add_argument(
        "--log",
        type=Path,
        help="override the configured audit log path when anchoring is disabled",
    )
    args = parser.parse_args(argv)

    try:
        from .config import settings

        log_path = args.log or settings.audit_log
        if (
            args.log is not None
            and settings.audit_anchor_log is not None
            and _normalized_path(args.log)
            != _normalized_path(settings.audit_log)
        ):
            raise ValueError(
                "--log cannot be overridden while audit anchoring is configured"
            )

        anchor = None
        if settings.audit_anchor_log is not None:
            assert settings.audit_anchor_key is not None
            anchor = FileAuditAnchor(
                settings.audit_anchor_log,
                settings.audit_anchor_key,
                derive_audit_log_id(settings.audit_key),
            )

        audit_log = AuditLog(
            log_path,
            settings.audit_key,
            anchor=anchor,
        )
        if args.command == "anchor-init":
            verification = audit_log.bootstrap_anchor()
            status = "anchor_initialized"
        else:
            verification = audit_log.verify()
            status = "valid"

        payload: dict[str, object] = {
            "status": status,
            "records": verification.records,
            "last_hmac": verification.last_hmac,
        }
        if verification.anchor_checkpoints is not None:
            payload["anchor_checkpoints"] = (
                verification.anchor_checkpoints
            )
        print(json.dumps(payload, sort_keys=True))
        return 0
    except (
        AuditAnchorError,
        AuditIntegrityError,
        AuditLockError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {"status": "error", "error": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
