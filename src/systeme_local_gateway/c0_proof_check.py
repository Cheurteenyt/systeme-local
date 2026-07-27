from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .audit import AuditLog
from .c0_probe import (
    C0_AUDIT_ID_PATTERN,
    C0_GIT_COMMIT_PATTERN,
    C0_SHA256_PATTERN,
    C0_TOOL_NAME,
    C0ConnectivityProbeResponse,
)
from .mcp_tools import McpToolRegistry
from .policy import PolicyEngine

_PENDING_PROOF_DOMAIN = b"systeme-local/c0-pending-live-proof/v1\0"


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C0 pending-proof timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_c0_response_sha256(response: C0ConnectivityProbeResponse) -> str:
    return hashlib.sha256(_canonical_json(response.model_dump(mode="json"))).hexdigest()


def canonical_c0_audit_record_sha256(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(record)).hexdigest()


class C0PendingLiveProofReceipt(BaseModel):
    """Authenticated receipt for a fresh, audited call pending revocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    status: Literal["live_call_correlated_pending_revocation"]
    real_connection_established: Literal[False]
    challenge_created_at: datetime
    checked_at: datetime
    challenge_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    response_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    server_build_commit: str = Field(pattern=C0_GIT_COMMIT_PATTERN)
    audit_correlation: str = Field(pattern=C0_AUDIT_ID_PATTERN)
    audit_record_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    audit_records_verified: int = Field(ge=1)
    local_policy_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    tool_snapshot_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    receipt_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_challenge_created_at = field_validator("challenge_created_at")(_require_aware)
    _aware_checked_at = field_validator("checked_at")(_require_aware)

    @model_validator(mode="after")
    def validate_freshness_window(self) -> "C0PendingLiveProofReceipt":
        if self.checked_at < self.challenge_created_at:
            raise ValueError("C0 pending proof predates its challenge")
        if self.checked_at - self.challenge_created_at > timedelta(minutes=30):
            raise ValueError("C0 pending proof challenge is stale")
        return self


def _pending_proof_hmac(payload: dict[str, Any], audit_key: str) -> str:
    return hmac.new(
        audit_key.encode("utf-8"),
        _PENDING_PROOF_DOMAIN + _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


def commit_c0_pending_live_proof_receipt(
    *,
    audit_key: str,
    challenge_created_at: datetime,
    checked_at: datetime,
    challenge_sha256: str,
    response: C0ConnectivityProbeResponse,
    audit_record: dict[str, Any],
    audit_records_verified: int,
) -> C0PendingLiveProofReceipt:
    challenge_created_at = _require_aware(challenge_created_at)
    checked_at = _require_aware(checked_at)
    payload: dict[str, Any] = {
        "version": "1",
        "status": "live_call_correlated_pending_revocation",
        "real_connection_established": False,
        "challenge_created_at": challenge_created_at.isoformat().replace("+00:00", "Z"),
        "checked_at": checked_at.isoformat().replace("+00:00", "Z"),
        "challenge_sha256": challenge_sha256,
        "response_sha256": canonical_c0_response_sha256(response),
        "server_build_commit": response.server_build_commit,
        "audit_correlation": response.audit_correlation,
        "audit_record_sha256": canonical_c0_audit_record_sha256(audit_record),
        "audit_records_verified": audit_records_verified,
        "local_policy_sha256": response.local_policy_sha256,
        "tool_snapshot_sha256": response.tool_snapshot_sha256,
    }
    return C0PendingLiveProofReceipt(
        **payload,
        receipt_hmac=_pending_proof_hmac(payload, audit_key),
    )


def verify_c0_pending_live_proof_receipt(
    receipt: C0PendingLiveProofReceipt,
    *,
    audit_key: str,
) -> C0PendingLiveProofReceipt:
    committed = C0PendingLiveProofReceipt.model_validate(receipt.model_dump(mode="python"))
    payload = committed.model_dump(mode="json", exclude={"receipt_hmac"})
    expected = _pending_proof_hmac(payload, audit_key)
    if not hmac.compare_digest(committed.receipt_hmac, expected):
        raise ValueError("C0 pending live proof HMAC mismatch")
    return committed


def _load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a copied manual ChatGPT Web C0 response."
    )
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--audit-log", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    return parser


def _current_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        audit_key = os.environ.get("SLG_AUDIT_KEY")
        if audit_key is None or len(audit_key) < 32:
            raise ValueError("SLG_AUDIT_KEY is required")
        challenge = args.challenge.read_text(encoding="utf-8").strip()
        expected_challenge = hashlib.sha256(challenge.encode("ascii")).hexdigest()
        response = C0ConnectivityProbeResponse.model_validate(_load_json_object(args.response))
        challenge_created_at = datetime.fromtimestamp(
            args.challenge.stat().st_mtime,
            UTC,
        )
        checked_at = datetime.now(UTC)
        if checked_at - challenge_created_at > timedelta(minutes=30):
            raise ValueError("local C0 challenge is stale")
        if response.observed_at < challenge_created_at - timedelta(seconds=5):
            raise ValueError("response predates the local C0 challenge")
        if response.observed_at > checked_at + timedelta(minutes=1):
            raise ValueError("response timestamp is in the future")
        if response.challenge_sha256 != expected_challenge:
            raise ValueError("response does not match the locally generated challenge")
        if response.server_build_commit != _current_commit():
            raise ValueError("response build commit does not match current HEAD")

        policy = PolicyEngine(args.policy)
        registry = McpToolRegistry(policy, c0_mode=True)
        if [tool.name for tool in registry.list_tools()] != [C0_TOOL_NAME]:
            raise ValueError("C0 policy does not expose exactly one tool")
        if response.local_policy_sha256 != policy.policy_sha256:
            raise ValueError("response policy digest mismatch")
        if response.tool_snapshot_sha256 != registry.tool_snapshot_sha256:
            raise ValueError("response tool snapshot digest mismatch")

        audit_log = AuditLog(args.audit_log, audit_key)
        verification = audit_log.verify()
        records = [
            json.loads(line) for line in args.audit_log.read_text(encoding="utf-8").splitlines()
        ]
        matches = [
            record for record in records if record.get("audit_id") == response.audit_correlation
        ]
        if len(matches) != 1:
            raise ValueError("exactly one correlated audit record is required")
        record = matches[0]
        if record.get("capability") != C0_TOOL_NAME or record.get("status") != "completed":
            raise ValueError("correlated audit record is not a completed C0 probe")
        agent = record.get("agent")
        if not isinstance(agent, dict) or agent.get("provider") != "mcp":
            raise ValueError("correlated audit record is not attributed to MCP")

        receipt = commit_c0_pending_live_proof_receipt(
            audit_key=audit_key,
            challenge_created_at=challenge_created_at,
            checked_at=checked_at,
            challenge_sha256=expected_challenge,
            response=response,
            audit_record=record,
            audit_records_verified=verification.records,
        )
    except Exception as exc:
        print(
            json.dumps(
                {"status": "error", "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            receipt.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
