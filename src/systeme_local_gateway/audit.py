from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

_RECORD_VERSION = 2
_GENESIS_HMAC = "0" * 64
_LOCK = threading.RLock()
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


@dataclass(frozen=True)
class AuditVerification:
    records: int
    last_hmac: str


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


class AuditLog:
    def __init__(self, log_path: Path, key: str):
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < 32:
            raise ValueError("audit key must contain at least 32 UTF-8 bytes")
        self.log_path = log_path
        self._key = key_bytes

    def verify(self) -> AuditVerification:
        with _LOCK:
            return self._verify_unlocked()

    def append(self, event: Mapping[str, object]) -> str:
        with _LOCK:
            verification = self._verify_unlocked()
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
            with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(_canonical_bytes(record).decode("utf-8") + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(self.log_path, 0o600)
            except OSError:
                pass
            return audit_id

    def _verify_unlocked(self) -> AuditVerification:
        if not self.log_path.exists():
            return AuditVerification(records=0, last_hmac=_GENESIS_HMAC)
        if not self.log_path.is_file():
            raise AuditIntegrityError("audit log path is not a regular file")
        if self.log_path.stat().st_size == 0:
            return AuditVerification(records=0, last_hmac=_GENESIS_HMAC)

        with self.log_path.open("rb") as raw_handle:
            raw_handle.seek(-1, os.SEEK_END)
            if raw_handle.read(1) != b"\n":
                raise AuditIntegrityError("audit log must end with a newline")

        previous_hmac = _GENESIS_HMAC
        records = 0
        audit_ids: set[str] = set()

        with self.log_path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.rstrip("\n")
                if not line:
                    raise AuditIntegrityError(f"blank audit record at line {line_number}")
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
                    raise AuditIntegrityError(f"broken audit chain at line {line_number}")

                entry_hmac = record.get("entry_hmac")
                if not isinstance(entry_hmac, str):
                    raise AuditIntegrityError(f"missing audit HMAC at line {line_number}")
                unsigned = dict(record)
                unsigned.pop("entry_hmac", None)
                expected_hmac = _entry_hmac(self._key, unsigned)
                if not hmac.compare_digest(entry_hmac, expected_hmac):
                    raise AuditIntegrityError(f"invalid audit HMAC at line {line_number}")

                audit_id = record.get("audit_id")
                if not isinstance(audit_id, str) or audit_id in audit_ids:
                    raise AuditIntegrityError(
                        f"invalid or duplicate audit ID at line {line_number}"
                    )
                audit_ids.add(audit_id)
                previous_hmac = entry_hmac
                records += 1

        return AuditVerification(records=records, last_hmac=previous_hmac)


def append_audit(log_path: Path, key: str, event: Mapping[str, object]) -> str:
    return AuditLog(log_path, key).append(event)


def verify_audit_log(log_path: Path, key: str) -> AuditVerification:
    return AuditLog(log_path, key).verify()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Système Local audit log")
    parser.add_argument("--log", type=Path, help="override the configured audit log path")
    args = parser.parse_args(argv)

    from .config import settings

    verification = verify_audit_log(args.log or settings.audit_log, settings.audit_key)
    print(
        json.dumps(
            {
                "status": "valid",
                "records": verification.records,
                "last_hmac": verification.last_hmac,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
