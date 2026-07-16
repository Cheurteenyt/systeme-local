from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
import stat
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

if os.name == "nt":
    import msvcrt
else:
    import fcntl

_ANCHOR_VERSION = 1
_ANCHOR_GENESIS_HMAC = "0" * 64
_ANCHOR_HMAC_DOMAIN = b"audit-anchor-checkpoint-v1"
_AUDIT_LOG_ID_DOMAIN = b"audit-anchor-log-id-v1"
_DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_POLL_INTERVAL_SECONDS = 0.05
_THREAD_LOCK = threading.RLock()
_EXPECTED_KEYS = {
    "version",
    "checkpoint_id",
    "timestamp",
    "audit_log_id",
    "records",
    "last_hmac",
    "previous_checkpoint_hmac",
    "checkpoint_hmac",
}


class AuditAnchorError(RuntimeError):
    """Base class for external audit-anchor failures."""


class AuditAnchorNotInitializedError(AuditAnchorError):
    """Raised when an anchor file has not been bootstrapped."""


class AuditAnchorIntegrityError(AuditAnchorError):
    """Raised when an anchor file is malformed or cryptographically invalid."""


class AuditAnchorLockError(AuditAnchorError):
    """Raised when the anchor cannot be locked safely."""


@dataclass(frozen=True)
class AuditAnchorVerification:
    checkpoints: int
    records: int
    last_hmac: str
    last_checkpoint_hmac: str


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _keyed_digest(key: bytes, domain: bytes, payload: bytes) -> str:
    return hmac.new(key, domain + b"\0" + payload, hashlib.sha256).hexdigest()


def derive_audit_log_id(audit_key: str) -> str:
    key = audit_key.encode("utf-8")
    if len(key) < 32:
        raise ValueError("audit key must contain at least 32 UTF-8 bytes")
    return _keyed_digest(key, _AUDIT_LOG_ID_DOMAIN, b"systeme-local-audit-log")


def _validate_hex_digest(value: object, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise AuditAnchorIntegrityError(f"invalid {field}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise AuditAnchorIntegrityError(f"invalid {field}") from exc
    return value


def _validate_timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise AuditAnchorIntegrityError("invalid checkpoint timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AuditAnchorIntegrityError("invalid checkpoint timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuditAnchorIntegrityError("checkpoint timestamp must include a timezone")
    return value


def _is_lock_contention_error(exc: OSError) -> bool:
    contention_codes = {
        errno.EACCES,
        errno.EAGAIN,
        getattr(errno, "EDEADLK", -1),
    }
    return isinstance(exc, BlockingIOError) or exc.errno in contention_codes


class FileAuditAnchor:
    """HMAC-chained checkpoints intended for separately protected storage."""

    def __init__(
        self,
        path: Path,
        key: str,
        audit_log_id: str,
        *,
        lock_timeout_seconds: float = _DEFAULT_LOCK_TIMEOUT_SECONDS,
    ):
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < 32:
            raise ValueError("audit anchor key must contain at least 32 UTF-8 bytes")
        if lock_timeout_seconds <= 0:
            raise ValueError("audit anchor lock timeout must be positive")
        _validate_hex_digest(audit_log_id, field="audit log ID")
        self.path = Path(path)
        self.lock_path = self.path.parent / f"{self.path.name}.lock"
        self._key = key_bytes
        self._audit_log_id = audit_log_id
        self._lock_timeout_seconds = lock_timeout_seconds

    def verify(self) -> AuditAnchorVerification:
        with _THREAD_LOCK:
            with self._process_lock():
                return self._verify_unlocked()

    def bootstrap(self, records: int, last_hmac: str) -> AuditAnchorVerification:
        self._validate_state(records, last_hmac)
        with _THREAD_LOCK:
            with self._process_lock():
                self._assert_safe_anchor_path()
                if self.path.exists() and self.path.stat().st_size != 0:
                    raise AuditAnchorIntegrityError(
                        "audit anchor is already initialized"
                    )
                self._append_checkpoint_unlocked(
                    records=records,
                    last_hmac=last_hmac,
                    previous_checkpoint_hmac=_ANCHOR_GENESIS_HMAC,
                )
                return self._verify_unlocked()

    def append(self, records: int, last_hmac: str) -> AuditAnchorVerification:
        self._validate_state(records, last_hmac)
        with _THREAD_LOCK:
            with self._process_lock():
                verification = self._verify_unlocked()
                if records <= verification.records:
                    raise AuditAnchorIntegrityError(
                        "audit anchor record count must increase"
                    )
                self._append_checkpoint_unlocked(
                    records=records,
                    last_hmac=last_hmac,
                    previous_checkpoint_hmac=verification.last_checkpoint_hmac,
                )
                return self._verify_unlocked()

    def _verify_unlocked(self) -> AuditAnchorVerification:
        self._assert_safe_anchor_path()
        if not self.path.exists() or self.path.stat().st_size == 0:
            raise AuditAnchorNotInitializedError("audit anchor is not initialized")

        with self.path.open("rb") as raw_handle:
            raw_handle.seek(-1, os.SEEK_END)
            if raw_handle.read(1) != b"\n":
                raise AuditAnchorIntegrityError(
                    "audit anchor must end with a newline"
                )

        previous_checkpoint_hmac = _ANCHOR_GENESIS_HMAC
        previous_records = -1
        checkpoints = 0
        checkpoint_ids: set[str] = set()
        last_hmac = _ANCHOR_GENESIS_HMAC

        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                checkpoint = self._decode_checkpoint(raw_line, line_number)
                checkpoint_id = self._validate_checkpoint_identity(
                    checkpoint,
                    line_number,
                    checkpoint_ids,
                )
                checkpoint_ids.add(checkpoint_id)

                records = checkpoint["records"]
                if (
                    not isinstance(records, int)
                    or isinstance(records, bool)
                    or records < 0
                ):
                    raise AuditAnchorIntegrityError(
                        f"invalid record count at line {line_number}"
                    )
                if records <= previous_records:
                    raise AuditAnchorIntegrityError(
                        f"non-monotonic record count at line {line_number}"
                    )

                current_last_hmac = _validate_hex_digest(
                    checkpoint["last_hmac"],
                    field="last audit HMAC",
                )
                if records == 0 and current_last_hmac != _ANCHOR_GENESIS_HMAC:
                    raise AuditAnchorIntegrityError(
                        "zero-record checkpoint must use the audit genesis HMAC"
                    )
                if (
                    checkpoint["previous_checkpoint_hmac"]
                    != previous_checkpoint_hmac
                ):
                    raise AuditAnchorIntegrityError(
                        f"broken audit anchor chain at line {line_number}"
                    )

                checkpoint_hmac = _validate_hex_digest(
                    checkpoint["checkpoint_hmac"],
                    field="checkpoint HMAC",
                )
                unsigned = dict(checkpoint)
                unsigned.pop("checkpoint_hmac")
                expected = _keyed_digest(
                    self._key,
                    _ANCHOR_HMAC_DOMAIN,
                    _canonical_bytes(unsigned),
                )
                if not hmac.compare_digest(checkpoint_hmac, expected):
                    raise AuditAnchorIntegrityError(
                        f"invalid checkpoint HMAC at line {line_number}"
                    )

                previous_checkpoint_hmac = checkpoint_hmac
                previous_records = records
                last_hmac = current_last_hmac
                checkpoints += 1

        return AuditAnchorVerification(
            checkpoints=checkpoints,
            records=previous_records,
            last_hmac=last_hmac,
            last_checkpoint_hmac=previous_checkpoint_hmac,
        )

    def _decode_checkpoint(
        self,
        raw_line: str,
        line_number: int,
    ) -> dict[str, object]:
        line = raw_line.rstrip("\n")
        if not line:
            raise AuditAnchorIntegrityError(
                f"blank audit anchor checkpoint at line {line_number}"
            )
        try:
            checkpoint = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditAnchorIntegrityError(
                f"invalid JSON audit anchor checkpoint at line {line_number}"
            ) from exc
        if not isinstance(checkpoint, dict):
            raise AuditAnchorIntegrityError(
                f"audit anchor checkpoint at line {line_number} must be an object"
            )
        if set(checkpoint) != _EXPECTED_KEYS:
            raise AuditAnchorIntegrityError(
                f"unexpected audit anchor schema at line {line_number}"
            )
        if checkpoint["version"] != _ANCHOR_VERSION:
            raise AuditAnchorIntegrityError(
                f"unsupported audit anchor version at line {line_number}"
            )
        return checkpoint

    def _validate_checkpoint_identity(
        self,
        checkpoint: dict[str, object],
        line_number: int,
        checkpoint_ids: set[str],
    ) -> str:
        checkpoint_id = checkpoint["checkpoint_id"]
        if not isinstance(checkpoint_id, str):
            raise AuditAnchorIntegrityError(
                f"invalid checkpoint ID at line {line_number}"
            )
        try:
            UUID(checkpoint_id)
        except ValueError as exc:
            raise AuditAnchorIntegrityError(
                f"invalid checkpoint ID at line {line_number}"
            ) from exc
        if checkpoint_id in checkpoint_ids:
            raise AuditAnchorIntegrityError(
                f"duplicate checkpoint ID at line {line_number}"
            )
        _validate_timestamp(checkpoint["timestamp"])
        if checkpoint["audit_log_id"] != self._audit_log_id:
            raise AuditAnchorIntegrityError(
                f"audit log ID mismatch at line {line_number}"
            )
        return checkpoint_id

    def _validate_state(self, records: int, last_hmac: str) -> None:
        if (
            not isinstance(records, int)
            or isinstance(records, bool)
            or records < 0
        ):
            raise ValueError(
                "anchor record count must be a non-negative integer"
            )
        _validate_hex_digest(last_hmac, field="last audit HMAC")
        if records == 0 and last_hmac != _ANCHOR_GENESIS_HMAC:
            raise ValueError(
                "zero-record checkpoint must use the audit genesis HMAC"
            )

    def _append_checkpoint_unlocked(
        self,
        *,
        records: int,
        last_hmac: str,
        previous_checkpoint_hmac: str,
    ) -> None:
        checkpoint: dict[str, object] = {
            "version": _ANCHOR_VERSION,
            "checkpoint_id": str(uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "audit_log_id": self._audit_log_id,
            "records": records,
            "last_hmac": last_hmac,
            "previous_checkpoint_hmac": previous_checkpoint_hmac,
        }
        checkpoint["checkpoint_hmac"] = _keyed_digest(
            self._key,
            _ANCHOR_HMAC_DOMAIN,
            _canonical_bytes(checkpoint),
        )
        encoded = _canonical_bytes(checkpoint) + b"\n"

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AuditAnchorIntegrityError(
                "audit anchor directory is unavailable"
            ) from exc
        self._assert_safe_anchor_path()

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise AuditAnchorIntegrityError(
                "audit anchor is unavailable"
            ) from exc

        try:
            descriptor_stat = os.fstat(descriptor)
            if not stat.S_ISREG(descriptor_stat.st_mode):
                raise AuditAnchorIntegrityError(
                    "audit anchor path is not a regular file"
                )
            path_stat = self.path.lstat()
            if stat.S_ISLNK(path_stat.st_mode):
                raise AuditAnchorIntegrityError(
                    "audit anchor cannot be a symbolic link"
                )
            if (path_stat.st_dev, path_stat.st_ino) != (
                descriptor_stat.st_dev,
                descriptor_stat.st_ino,
            ):
                raise AuditAnchorIntegrityError(
                    "audit anchor changed during open"
                )
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        except OSError as exc:
            raise AuditAnchorIntegrityError(
                "audit anchor write failed"
            ) from exc
        finally:
            os.close(descriptor)

        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @contextmanager
    def _process_lock(self) -> Iterator[None]:
        try:
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AuditAnchorLockError(
                "audit anchor lock directory is unavailable"
            ) from exc

        self._assert_safe_lock_path()
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.lock_path, flags, 0o600)
        except OSError as exc:
            raise AuditAnchorLockError(
                "audit anchor lock file is unavailable"
            ) from exc

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
                        raise AuditAnchorLockError(
                            "audit anchor lock acquisition failed"
                        ) from exc
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise AuditAnchorLockError(
                            "audit anchor lock acquisition timed out"
                        ) from exc
                    time.sleep(
                        min(_LOCK_POLL_INTERVAL_SECONDS, remaining)
                    )

            self._verify_lock_file_identity(os.fstat(descriptor))
            yield
        except AuditAnchorLockError:
            raise
        except OSError as exc:
            raise AuditAnchorLockError(
                "audit anchor lock is unavailable"
            ) from exc
        finally:
            try:
                if acquired:
                    try:
                        self._release_process_lock(descriptor)
                    except OSError:
                        pass
            finally:
                os.close(descriptor)

    def _assert_safe_anchor_path(self) -> None:
        if not self.path.exists() and not self.path.is_symlink():
            return
        file_stat = self.path.lstat()
        if stat.S_ISLNK(file_stat.st_mode):
            raise AuditAnchorIntegrityError(
                "audit anchor cannot be a symbolic link"
            )
        if not stat.S_ISREG(file_stat.st_mode):
            raise AuditAnchorIntegrityError(
                "audit anchor path is not a regular file"
            )

    def _assert_safe_lock_path(self) -> None:
        if not self.lock_path.exists() and not self.lock_path.is_symlink():
            return
        file_stat = self.lock_path.lstat()
        if stat.S_ISLNK(file_stat.st_mode):
            raise AuditAnchorLockError(
                "audit anchor lock file cannot be a symbolic link"
            )
        if not stat.S_ISREG(file_stat.st_mode):
            raise AuditAnchorLockError(
                "audit anchor lock path is not a regular file"
            )

    def _verify_lock_file_identity(
        self,
        descriptor_stat: os.stat_result,
    ) -> None:
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise AuditAnchorLockError(
                "audit anchor lock path is not a regular file"
            )
        path_stat = self.lock_path.lstat()
        if stat.S_ISLNK(path_stat.st_mode):
            raise AuditAnchorLockError(
                "audit anchor lock file cannot be a symbolic link"
            )
        if (path_stat.st_dev, path_stat.st_ino) != (
            descriptor_stat.st_dev,
            descriptor_stat.st_ino,
        ):
            raise AuditAnchorLockError(
                "audit anchor lock file changed during open"
            )

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
