from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

C0_TOOL_NAME = "systeme_local_connectivity_probe"
C0_PROBE_PROTOCOL_VERSION: Literal["c0.v1"] = "c0.v1"
C0_CHALLENGE_PATTERN = r"^c0_[0-9a-f]{32}$"
C0_SHA256_PATTERN = r"^[0-9a-f]{64}$"
C0_GIT_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
C0_AUDIT_ID_PATTERN = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_CHALLENGE_RE = re.compile(C0_CHALLENGE_PATTERN)


class C0ConnectivityProbeResponse(BaseModel):
    """Strict, synthetic response returned by the C0 connectivity probe."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    probe_protocol_version: Literal["c0.v1"]
    challenge_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    server_build_commit: str = Field(pattern=C0_GIT_COMMIT_PATTERN)
    local_policy_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    tool_snapshot_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    read_only: Literal[True]
    write_actions_enabled: Literal[False]
    real_evidence_access: Literal[False]
    protocol_v2_reachable: Literal[False]
    audit_correlation: str = Field(pattern=C0_AUDIT_ID_PATTERN)
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def require_aware_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("C0 observed_at must be timezone-aware")
        return value.astimezone(UTC)


@dataclass(frozen=True)
class C0ProbeContext:
    server_build_commit: str
    local_policy_sha256: str
    tool_snapshot_sha256: str

    def __post_init__(self) -> None:
        if re.fullmatch(C0_GIT_COMMIT_PATTERN, self.server_build_commit) is None:
            raise ValueError("C0 server build commit must be a lowercase full Git SHA")
        for label, digest in (
            ("local policy", self.local_policy_sha256),
            ("tool snapshot", self.tool_snapshot_sha256),
        ):
            if re.fullmatch(C0_SHA256_PATTERN, digest) is None:
                raise ValueError(f"C0 {label} digest must be lowercase SHA-256")


class C0ChallengeReplayGuard:
    """Bounded, process-local replay guard for synthetic C0 challenges."""

    def __init__(self, *, max_entries: int = 1_024):
        if max_entries < 1 or max_entries > 100_000:
            raise ValueError("C0 replay guard size is outside the safe range")
        self._max_entries = max_entries
        self._digests: set[str] = set()
        self._lock = threading.Lock()

    def consume(self, challenge_sha256: str) -> None:
        with self._lock:
            if challenge_sha256 in self._digests:
                raise ValueError("C0 challenge has already been consumed")
            if len(self._digests) >= self._max_entries:
                raise ValueError("C0 replay guard capacity is exhausted")
            self._digests.add(challenge_sha256)


class C0ConnectivityProbe:
    """Generate a bounded attestation payload without reading external evidence."""

    def __init__(
        self,
        context: C0ProbeContext,
        *,
        replay_guard: C0ChallengeReplayGuard | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self._context = context
        self._replay_guard = replay_guard or C0ChallengeReplayGuard()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if set(arguments) != {"challenge"}:
            raise ValueError("C0 probe requires exactly one challenge")
        challenge = arguments.get("challenge")
        if not isinstance(challenge, str) or _CHALLENGE_RE.fullmatch(challenge) is None:
            raise ValueError("C0 challenge has an invalid format")

        challenge_sha256 = hashlib.sha256(challenge.encode("ascii")).hexdigest()
        self._replay_guard.consume(challenge_sha256)
        observed_at = self._clock()
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("C0 probe clock must return a timezone-aware timestamp")

        return {
            "probe_protocol_version": C0_PROBE_PROTOCOL_VERSION,
            "challenge_sha256": challenge_sha256,
            "server_build_commit": self._context.server_build_commit,
            "local_policy_sha256": self._context.local_policy_sha256,
            "tool_snapshot_sha256": self._context.tool_snapshot_sha256,
            "read_only": True,
            "write_actions_enabled": False,
            "real_evidence_access": False,
            "protocol_v2_reachable": False,
            "observed_at": observed_at.isoformat(),
        }


def finalize_c0_response(
    output: dict[str, Any],
    *,
    audit_correlation: str,
) -> dict[str, Any]:
    committed = C0ConnectivityProbeResponse.model_validate(
        {**output, "audit_correlation": audit_correlation}
    )
    return committed.model_dump(mode="json")


def c0_input_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "challenge": {
                "type": "string",
                "description": (
                    "Single-use synthetic challenge generated locally for this "
                    "connectivity attempt."
                ),
                "pattern": C0_CHALLENGE_PATTERN,
                "minLength": 35,
                "maxLength": 35,
            }
        },
        "required": ["challenge"],
        "additionalProperties": False,
    }


def c0_output_schema() -> dict[str, Any]:
    return C0ConnectivityProbeResponse.model_json_schema()


def c0_annotations() -> dict[str, bool]:
    return {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
