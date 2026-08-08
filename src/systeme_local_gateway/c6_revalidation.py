from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from systeme_local_gateway.c0_probe import C0_SHA256_PATTERN
from systeme_local_gateway.c3_evidence import (
    C3GateStatus,
    C3ProtectedAction,
    CandidateProfileDraft,
    CandidateSourceDraft,
    CapabilityIdentity,
    CapabilityRegistry,
    EvidenceLifecycleState,
    OfficialCapabilityProfile,
    build_current_c3_official_capability_profile,
    build_current_c3_registry,
    evaluate_c3_registry,
    evaluate_reviewed_profile,
    seal_c3_candidate_draft,
)

C6_POLICY_PATH = "governance/c6-revalidation-policy.json"
C6_C3_REGISTRY_PATH = "governance/c3-capability-registry.json"
C6_DOCS_MCP_ENDPOINT = "https://developers.openai.com/mcp"
C6_REVIEWED_AT = datetime(2026, 8, 7, 14, 42, tzinfo=UTC)
C6_REVALIDATE_AFTER = datetime(2026, 8, 21, 14, 42, tzinfo=UTC)
C6_REVALIDATION_WARNING_DAYS = 7
C6_MAX_MCP_ENVELOPE_BYTES = 262_144
C6_MAX_NORMALIZED_SOURCE_BYTES = 16_384
C6_SENSITIVE_ENVIRONMENT_VARIABLES = (
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "SLG_AUDIT_KEY",
    "SLG_MCP_TOKEN",
    "SLG_SHARED_SECRET",
)

_SOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_ANCHOR_RE = re.compile(r"^#[a-z0-9][a-z0-9-]{1,127}$")
_MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")
_ALLOWED_SOURCE_HOSTS = frozenset(
    {
        "developers.openai.com",
        "learn.chatgpt.com",
    }
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _strict_json_loads(value: str | bytes) -> Any:
    return json.loads(value, object_pairs_hook=_reject_duplicate_json_keys)


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C6 timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _parse_timestamp(value: str | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    parsed = datetime.fromisoformat(value)
    return _require_aware(parsed)


def _validate_https_url(value: str, *, allowed_hosts: frozenset[str]) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("C6 URL must be credential-free canonical HTTPS")
    host = parsed.hostname.lower()
    if host not in allowed_hosts:
        raise ValueError("C6 URL host is not approved")
    if parsed.port not in (None, 443):
        raise ValueError("C6 URL uses an unexpected port")
    return host


def normalize_official_markdown(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("C6 official document content is empty")
    if "\x00" in value:
        raise ValueError("C6 official document content contains NUL")
    normalized = unicodedata.normalize("NFC", value)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    normalized = "\n".join(line.rstrip(" \t") for line in normalized.split("\n"))
    normalized = re.sub(r"\n{3,}", "\n\n", normalized).strip()
    if not normalized:
        raise ValueError("C6 normalized official document content is empty")
    return f"{normalized}\n"


def semantic_markdown_text(value: str) -> str:
    text = _MARKDOWN_LINK_RE.sub(r"\1", value)
    text = _HTML_TAG_RE.sub(" ", text)
    text = text.replace("`", "").replace("*", "")
    return _WHITESPACE_RE.sub(" ", text).strip()


class C6PolicyLifecycle(StrEnum):
    CURRENT = "current"
    REVALIDATION_DUE = "revalidation_due"
    EXPIRED = "expired"


class C6SourceState(StrEnum):
    UNCHANGED = "unchanged"
    SOURCE_DRIFT = "source_drift"


class C6ReportState(StrEnum):
    UNCHANGED = "unchanged"
    SOURCE_DRIFT = "source_drift"


class C6FailureCode(StrEnum):
    POLICY_INVALID = "policy_invalid"
    HTTP_FAILED = "http_failed"
    RESPONSE_TOO_LARGE = "response_too_large"
    CONTENT_TYPE_INVALID = "content_type_invalid"
    SSE_INVALID = "sse_invalid"
    JSON_RPC_INVALID = "json_rpc_invalid"
    MCP_TOOL_FAILED = "mcp_tool_failed"
    DOCUMENT_INVALID = "document_invalid"


class C6SourcePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    title: str = Field(min_length=1, max_length=160)
    url: str = Field(min_length=1, max_length=512)
    anchor: str = Field(pattern=r"^#[a-z0-9][a-z0-9-]{1,127}$")
    reviewed_normalized_bytes: int = Field(ge=1, le=C6_MAX_NORMALIZED_SOURCE_BYTES)
    reviewed_content_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    required_markers: tuple[str, ...]

    @model_validator(mode="after")
    def validate_source(self) -> C6SourcePolicy:
        if _SOURCE_ID_RE.fullmatch(self.source_id) is None:
            raise ValueError("C6 source ID is invalid")
        _validate_https_url(self.url, allowed_hosts=_ALLOWED_SOURCE_HOSTS)
        if _ANCHOR_RE.fullmatch(self.anchor) is None:
            raise ValueError("C6 source anchor is invalid")
        if not self.required_markers or self.required_markers != tuple(
            sorted(set(self.required_markers))
        ):
            raise ValueError("C6 source markers must be non-empty, sorted, and unique")
        for marker in self.required_markers:
            if not marker or len(marker) > 160 or "\n" in marker or "\r" in marker:
                raise ValueError("C6 source marker is invalid")
        return self


class C6RevalidationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    profile_id: str
    identity: CapabilityIdentity
    docs_mcp_endpoint: str
    c3_registry_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    c3_profile_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    sources: tuple[C6SourcePolicy, ...]
    reviewed_at: datetime
    revalidate_after: datetime
    revalidation_warning_days: int = Field(ge=0, le=13)
    fetched_content_can_change_gate: Literal[False]
    automatic_promotion_supported: Literal[False]
    policy_sha256: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_reviewed_at = field_validator("reviewed_at")(_require_aware)
    _aware_revalidate_after = field_validator("revalidate_after")(_require_aware)

    @model_validator(mode="after")
    def validate_policy(self) -> C6RevalidationPolicy:
        _validate_https_url(
            self.docs_mcp_endpoint,
            allowed_hosts=frozenset({"developers.openai.com"}),
        )
        if self.docs_mcp_endpoint != C6_DOCS_MCP_ENDPOINT:
            raise ValueError("C6 uses only the reviewed OpenAI Docs MCP endpoint")
        if self.revalidate_after <= self.reviewed_at:
            raise ValueError("C6 policy deadline must follow review")
        if self.revalidate_after - self.reviewed_at > timedelta(days=14):
            raise ValueError("C6 policy revalidation window exceeds 14 days")
        source_ids = tuple(source.source_id for source in self.sources)
        source_routes = tuple((source.url, source.anchor) for source in self.sources)
        if len(source_ids) < 3:
            raise ValueError("C6 policy requires at least three official sources")
        if source_ids != tuple(sorted(set(source_ids))):
            raise ValueError("C6 policy source IDs must be sorted and unique")
        if len(source_routes) != len(set(source_routes)):
            raise ValueError("C6 policy source routes must be unique")
        payload = self.model_dump(mode="json", exclude={"policy_sha256"})
        if self.policy_sha256 != canonical_sha256(payload):
            raise ValueError("C6 policy digest mismatch")
        return self


class C6SourceObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str
    url: str
    anchor: str
    acquired_at: datetime
    normalized_bytes: int = Field(ge=1, le=C6_MAX_NORMALIZED_SOURCE_BYTES)
    content_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    reviewed_content_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    required_markers_present: bool
    state: C6SourceState
    raw_content_persisted: Literal[False]

    _aware_acquired_at = field_validator("acquired_at")(_require_aware)

    @model_validator(mode="after")
    def validate_observation(self) -> C6SourceObservation:
        unchanged = (
            self.content_sha256 == self.reviewed_content_sha256 and self.required_markers_present
        )
        if (self.state is C6SourceState.UNCHANGED) != unchanged:
            raise ValueError("C6 source observation state is inconsistent")
        return self


class C6OfflineStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    evaluated_at: datetime
    policy_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    policy_lifecycle: C6PolicyLifecycle
    policy_revalidate_after: datetime
    c3_registry_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    c3_profile_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    c3_lifecycle: EvidenceLifecycleState
    c3_final_status: C3GateStatus
    source_count: int = Field(ge=3)
    fetched_content_can_change_gate: Literal[False]
    automatic_promotion_supported: Literal[False]
    live_actions_allowed: Literal[False]
    action_decisions: dict[C3ProtectedAction, Literal[False]]

    _aware_evaluated_at = field_validator("evaluated_at")(_require_aware)
    _aware_policy_revalidate_after = field_validator("policy_revalidate_after")(_require_aware)

    @model_validator(mode="after")
    def validate_status(self) -> C6OfflineStatus:
        if set(self.action_decisions) != set(C3ProtectedAction):
            raise ValueError("C6 status must deny every protected action")
        if set(self.action_decisions.values()) != {False}:
            raise ValueError("C6 status cannot enable a protected action")
        return self


class C6RevalidationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    acquired_at: datetime
    policy_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    policy_lifecycle: C6PolicyLifecycle
    c3_registry_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    c3_profile_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    c3_lifecycle: EvidenceLifecycleState
    c3_final_status: C3GateStatus
    report_state: C6ReportState
    observations: tuple[C6SourceObservation, ...]
    drift_source_ids: tuple[str, ...]
    candidate_generated: bool
    candidate_profile_sha256: str | None = Field(default=None, pattern=C0_SHA256_PATTERN)
    candidate_can_change_gate: Literal[False]
    promotion_allowed: Literal[False]
    requires_independent_review: Literal[True]
    raw_content_persisted: Literal[False]
    live_actions_allowed: Literal[False]
    action_decisions: dict[C3ProtectedAction, Literal[False]]
    report_sha256: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_acquired_at = field_validator("acquired_at")(_require_aware)

    @model_validator(mode="after")
    def validate_report(self) -> C6RevalidationReport:
        if set(self.action_decisions) != set(C3ProtectedAction):
            raise ValueError("C6 report must deny every protected action")
        if set(self.action_decisions.values()) != {False}:
            raise ValueError("C6 report cannot enable a protected action")
        source_ids = tuple(item.source_id for item in self.observations)
        if source_ids != tuple(sorted(set(source_ids))):
            raise ValueError("C6 report observations must be sorted and unique")
        expected_drift = tuple(
            item.source_id for item in self.observations if item.state is C6SourceState.SOURCE_DRIFT
        )
        if self.drift_source_ids != expected_drift:
            raise ValueError("C6 report drift list is inconsistent")
        if self.report_state is C6ReportState.UNCHANGED:
            if self.drift_source_ids:
                raise ValueError("C6 unchanged report cannot contain drift")
            if not self.candidate_generated or self.candidate_profile_sha256 is None:
                raise ValueError("C6 unchanged report requires a review candidate")
        else:
            if not self.drift_source_ids:
                raise ValueError("C6 drift report requires at least one drifted source")
            if self.candidate_generated or self.candidate_profile_sha256 is not None:
                raise ValueError("C6 drift cannot generate a semantic candidate")
        payload = self.model_dump(mode="json", exclude={"report_sha256"})
        if self.report_sha256 != canonical_sha256(payload):
            raise ValueError("C6 report digest mismatch")
        return self


class C6FailureReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    failed_at: datetime
    failure_code: C6FailureCode
    source_id: str | None = None
    policy_sha256: str | None = Field(default=None, pattern=C0_SHA256_PATTERN)
    candidate_generated: Literal[False]
    candidate_can_change_gate: Literal[False]
    promotion_allowed: Literal[False]
    raw_content_persisted: Literal[False]
    live_actions_allowed: Literal[False]
    action_decisions: dict[C3ProtectedAction, Literal[False]]

    _aware_failed_at = field_validator("failed_at")(_require_aware)

    @model_validator(mode="after")
    def validate_failure(self) -> C6FailureReport:
        if set(self.action_decisions) != set(C3ProtectedAction):
            raise ValueError("C6 failure must deny every protected action")
        if set(self.action_decisions.values()) != {False}:
            raise ValueError("C6 failure cannot enable a protected action")
        return self


class C6Guidance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    objective: str
    acquisition_boundary: tuple[str, ...]
    review_boundary: tuple[str, ...]
    forbidden_actions: tuple[str, ...]


class C6AcquisitionError(RuntimeError):
    def __init__(self, code: C6FailureCode, *, source_id: str | None = None) -> None:
        super().__init__(code.value)
        self.code = code
        self.source_id = source_id


@dataclass(frozen=True)
class C6AcquisitionResult:
    report: C6RevalidationReport
    candidate: OfficialCapabilityProfile | None


FetchMarkdown = Callable[[C6SourcePolicy], str]


def _deny_all_actions() -> dict[C3ProtectedAction, Literal[False]]:
    return {action: False for action in C3ProtectedAction}


def _source_policy(
    *,
    source_id: str,
    title: str,
    url: str,
    anchor: str,
    reviewed_normalized_bytes: int,
    reviewed_content_sha256: str,
    required_markers: tuple[str, ...],
) -> C6SourcePolicy:
    return C6SourcePolicy(
        source_id=source_id,
        title=title,
        url=url,
        anchor=anchor,
        reviewed_normalized_bytes=reviewed_normalized_bytes,
        reviewed_content_sha256=reviewed_content_sha256,
        required_markers=tuple(sorted(required_markers)),
    )


def commit_c6_policy(
    *,
    profile: OfficialCapabilityProfile,
    registry: CapabilityRegistry,
    sources: tuple[C6SourcePolicy, ...],
    reviewed_at: datetime,
    revalidate_after: datetime,
) -> C6RevalidationPolicy:
    reviewed = _require_aware(reviewed_at)
    deadline = _require_aware(revalidate_after)
    partial: dict[str, Any] = {
        "version": "1",
        "profile_id": profile.profile_id,
        "identity": profile.identity.model_dump(mode="json"),
        "docs_mcp_endpoint": C6_DOCS_MCP_ENDPOINT,
        "c3_registry_sha256": registry.registry_sha256,
        "c3_profile_sha256": profile.profile_sha256,
        "sources": [
            source.model_dump(mode="json")
            for source in sorted(sources, key=lambda item: item.source_id)
        ],
        "reviewed_at": reviewed.isoformat().replace("+00:00", "Z"),
        "revalidate_after": deadline.isoformat().replace("+00:00", "Z"),
        "revalidation_warning_days": C6_REVALIDATION_WARNING_DAYS,
        "fetched_content_can_change_gate": False,
        "automatic_promotion_supported": False,
    }
    return C6RevalidationPolicy(
        **partial,
        policy_sha256=canonical_sha256(partial),
    )


def build_current_c6_policy() -> C6RevalidationPolicy:
    profile = build_current_c3_official_capability_profile()
    registry = build_current_c3_registry()
    sources = (
        _source_policy(
            source_id="plugin_connection_route",
            title="Connect and test your plugin",
            url="https://developers.openai.com/plugins/deploy/connect-chatgpt",
            anchor="#add-the-mcp-server",
            reviewed_normalized_bytes=464,
            reviewed_content_sha256=(
                "3cc37a424d4a5fe60e9f0921f253403794c717b8ece56e1ec24b423d823dc388"
            ),
            required_markers=(
                "Enter the public MCP server URL, including the /mcp path.",
                "Go to ChatGPT Plugins.",
            ),
        ),
        _source_policy(
            source_id="plugin_packaging_surface",
            title="Package your plugin",
            url="https://developers.openai.com/plugins/build/plugins",
            anchor="#create-and-test-a-plugin-locally-with-an-mcp-server",
            reviewed_normalized_bytes=2_620,
            reviewed_content_sha256=(
                "28c1bc7403d2f21cec1aeff959a0450e0e85b21e2dbc46bcaf4b3859d6065d8c"
            ),
            required_markers=(
                "Give that plugin_asdk_app... ID to @plugin-creator in Work mode in ChatGPT",
                "register the MCP server connection in ChatGPT developer mode.",
            ),
        ),
        _source_policy(
            source_id="plugin_surface_availability",
            title="Plugins",
            url="https://learn.chatgpt.com/docs/plugins",
            anchor="#overview",
            reviewed_normalized_bytes=2_682,
            reviewed_content_sha256=(
                "1a2f67b7287610eb66162b2afcc24db7cb319f68281dbc970f2f334c9f751e7e"
            ),
            required_markers=(
                "Plugins are available with ChatGPT Work on the web",
                "Plugins aren't available in Chat",
            ),
        ),
        _source_policy(
            source_id="secure_mcp_tunnel_route",
            title="Secure MCP Tunnel",
            url="https://developers.openai.com/api/docs/guides/secure-mcp-tunnels",
            anchor="#connect-from-chatgpt",
            reviewed_normalized_bytes=493,
            reviewed_content_sha256=(
                "8b80437089c00abdb8d75a777ef3208746e87c7149feb7f9c6606c4555eed1dd"
            ),
            required_markers=(
                "Go to ChatGPT Plugins",
                "choose Tunnel under Connection.",
            ),
        ),
    )
    return commit_c6_policy(
        profile=profile,
        registry=registry,
        sources=sources,
        reviewed_at=C6_REVIEWED_AT,
        revalidate_after=C6_REVALIDATE_AFTER,
    )


def _policy_lifecycle(
    policy: C6RevalidationPolicy,
    *,
    evaluated_at: datetime,
) -> C6PolicyLifecycle:
    evaluated = _require_aware(evaluated_at)
    if evaluated >= policy.revalidate_after:
        return C6PolicyLifecycle.EXPIRED
    warning_at = policy.revalidate_after - timedelta(days=policy.revalidation_warning_days)
    if evaluated >= warning_at:
        return C6PolicyLifecycle.REVALIDATION_DUE
    return C6PolicyLifecycle.CURRENT


def _load_json(path: Path) -> Any:
    return _strict_json_loads(path.read_text(encoding="utf-8"))


def _path_has_reparse_component(path: Path, *, root: Path) -> bool:
    current = path
    while True:
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(metadata.st_mode):
                return True
            attributes = getattr(metadata, "st_file_attributes", 0)
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if attributes & reparse:
                return True
        if current == root:
            return False
        if root not in current.parents:
            return True
        current = current.parent


def _assert_repository_input(*, root: Path, path: Path, parent_name: str) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve()
    expected_parent = (resolved_root / parent_name).resolve()
    if not resolved.is_file() or expected_parent not in resolved.parents:
        raise ValueError("C6 repository input escapes its reviewed directory")
    if _path_has_reparse_component(resolved, root=resolved_root):
        raise ValueError("C6 repository input uses a reparse path")
    return resolved


def load_current_c6_policy(*, root: Path, policy_path: Path) -> C6RevalidationPolicy:
    resolved_root = root.resolve()
    reviewed_path = _assert_repository_input(
        root=resolved_root,
        path=policy_path,
        parent_name="governance",
    )
    policy = C6RevalidationPolicy.model_validate(_load_json(reviewed_path))
    expected = build_current_c6_policy()
    if policy.model_dump(mode="json") != expected.model_dump(mode="json"):
        raise ValueError("C6 committed policy differs from the reviewed builder")
    return policy


def verify_c6_policy(
    *,
    root: Path,
    policy_path: Path,
    c3_registry_path: Path,
    evaluated_at: datetime,
) -> C6OfflineStatus:
    resolved_root = root.resolve()
    policy = load_current_c6_policy(root=resolved_root, policy_path=policy_path.resolve())
    _assert_repository_input(
        root=resolved_root,
        path=c3_registry_path.resolve(),
        parent_name="governance",
    )
    expected_profile = build_current_c3_official_capability_profile()
    expected_registry = build_current_c3_registry()
    if (
        policy.profile_id != expected_profile.profile_id
        or policy.identity != expected_profile.identity
        or policy.c3_profile_sha256 != expected_profile.profile_sha256
        or policy.c3_registry_sha256 != expected_registry.registry_sha256
    ):
        raise ValueError("C6 policy is not bound to the active C3 evidence")
    decision = evaluate_c3_registry(
        root=resolved_root,
        registry_path=c3_registry_path.resolve(),
        evaluated_at=_require_aware(evaluated_at),
    )
    if decision.live_actions_allowed or any(decision.action_decisions.values()):
        raise ValueError("C6 current policy unexpectedly reached an allowed C3 gate")
    return C6OfflineStatus(
        version="1",
        evaluated_at=evaluated_at,
        policy_sha256=policy.policy_sha256,
        policy_lifecycle=_policy_lifecycle(policy, evaluated_at=evaluated_at),
        policy_revalidate_after=policy.revalidate_after,
        c3_registry_sha256=expected_registry.registry_sha256,
        c3_profile_sha256=expected_profile.profile_sha256,
        c3_lifecycle=decision.lifecycle_state,
        c3_final_status=decision.final_status,
        source_count=len(policy.sources),
        fetched_content_can_change_gate=False,
        automatic_promotion_supported=False,
        live_actions_allowed=False,
        action_decisions=_deny_all_actions(),
    )


def _json_rpc_payload(source: C6SourcePolicy) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": f"c6-{source.source_id}",
        "method": "tools/call",
        "params": {
            "name": "fetch_openai_doc",
            "arguments": {
                "url": source.url,
                "anchor": source.anchor,
            },
        },
    }


def _parse_sse_json(value: bytes, *, expected_id: str) -> dict[str, Any]:
    try:
        text = value.decode("utf-8", errors="strict").replace("\r\n", "\n")
    except UnicodeDecodeError as error:
        raise C6AcquisitionError(C6FailureCode.SSE_INVALID) from error
    events: list[tuple[str, str]] = []
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        event_name = "message"
        data_lines: list[str] = []
        for line in block.split("\n"):
            if line.startswith("event:"):
                event_name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
            elif line.startswith(":"):
                continue
            elif line:
                raise C6AcquisitionError(C6FailureCode.SSE_INVALID)
        if data_lines:
            events.append((event_name, "\n".join(data_lines)))
    if len(events) != 1 or events[0][0] != "message":
        raise C6AcquisitionError(C6FailureCode.SSE_INVALID)
    try:
        envelope = _strict_json_loads(events[0][1])
    except (json.JSONDecodeError, ValueError) as error:
        raise C6AcquisitionError(C6FailureCode.JSON_RPC_INVALID) from error
    if not isinstance(envelope, dict) or envelope.get("id") != expected_id:
        raise C6AcquisitionError(C6FailureCode.JSON_RPC_INVALID)
    return envelope


def _document_from_json_rpc(envelope: dict[str, Any]) -> str:
    if envelope.get("jsonrpc") != "2.0" or "error" in envelope:
        raise C6AcquisitionError(C6FailureCode.MCP_TOOL_FAILED)
    if set(envelope) != {"jsonrpc", "id", "result"}:
        raise C6AcquisitionError(C6FailureCode.JSON_RPC_INVALID)
    result = envelope.get("result")
    if not isinstance(result, dict) or result.get("isError") is True:
        raise C6AcquisitionError(C6FailureCode.MCP_TOOL_FAILED)
    if set(result) not in ({"content"}, {"content", "isError"}):
        raise C6AcquisitionError(C6FailureCode.JSON_RPC_INVALID)
    if "isError" in result and result["isError"] is not False:
        raise C6AcquisitionError(C6FailureCode.JSON_RPC_INVALID)
    content = result.get("content")
    if (
        not isinstance(content, list)
        or len(content) != 1
        or not isinstance(content[0], dict)
        or set(content[0]) != {"type", "text"}
        or content[0].get("type") != "text"
        or not isinstance(content[0].get("text"), str)
    ):
        raise C6AcquisitionError(C6FailureCode.JSON_RPC_INVALID)
    return content[0]["text"]


class OpenAIDocsMcpClient:
    def __init__(
        self,
        *,
        endpoint: str,
        timeout_seconds: float = 20.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if endpoint != C6_DOCS_MCP_ENDPOINT:
            raise ValueError("C6 client endpoint differs from reviewed OpenAI Docs MCP")
        if not 1.0 <= timeout_seconds <= 60.0:
            raise ValueError("C6 client timeout is outside the reviewed range")
        self._endpoint = endpoint
        self._timeout = timeout_seconds
        self._transport = transport

    def fetch(self, source: C6SourcePolicy) -> str:
        request_id = f"c6-{source.source_id}"
        response_bytes = bytearray()
        try:
            with httpx.Client(
                timeout=self._timeout,
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "User-Agent": "systeme-local-c6-revalidation/1",
                },
            ) as client, client.stream(
                "POST",
                self._endpoint,
                content=canonical_json(_json_rpc_payload(source)),
            ) as response:
                if response.status_code != 200:
                    raise C6AcquisitionError(
                        C6FailureCode.HTTP_FAILED,
                        source_id=source.source_id,
                    )
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        declared_length = int(content_length)
                    except ValueError as error:
                        raise C6AcquisitionError(
                            C6FailureCode.HTTP_FAILED,
                            source_id=source.source_id,
                        ) from error
                    if declared_length < 0 or declared_length > C6_MAX_MCP_ENVELOPE_BYTES:
                        raise C6AcquisitionError(
                            C6FailureCode.RESPONSE_TOO_LARGE,
                            source_id=source.source_id,
                        )
                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )
                if content_type not in {
                    "application/json",
                    "text/event-stream",
                }:
                    raise C6AcquisitionError(
                        C6FailureCode.CONTENT_TYPE_INVALID,
                        source_id=source.source_id,
                    )
                for chunk in response.iter_bytes():
                    if len(response_bytes) + len(chunk) > C6_MAX_MCP_ENVELOPE_BYTES:
                        raise C6AcquisitionError(
                            C6FailureCode.RESPONSE_TOO_LARGE,
                            source_id=source.source_id,
                        )
                    response_bytes.extend(chunk)
        except C6AcquisitionError:
            raise
        except httpx.HTTPError as error:
            raise C6AcquisitionError(
                C6FailureCode.HTTP_FAILED,
                source_id=source.source_id,
            ) from error
        raw_response = bytes(response_bytes)
        if content_type == "text/event-stream":
            try:
                envelope = _parse_sse_json(raw_response, expected_id=request_id)
            except C6AcquisitionError as error:
                raise C6AcquisitionError(error.code, source_id=source.source_id) from error
        else:
            try:
                envelope = _strict_json_loads(raw_response)
            except (json.JSONDecodeError, ValueError) as error:
                raise C6AcquisitionError(
                    C6FailureCode.JSON_RPC_INVALID,
                    source_id=source.source_id,
                ) from error
            if not isinstance(envelope, dict) or envelope.get("id") != request_id:
                raise C6AcquisitionError(
                    C6FailureCode.JSON_RPC_INVALID,
                    source_id=source.source_id,
                )
        try:
            return _document_from_json_rpc(envelope)
        except C6AcquisitionError as error:
            raise C6AcquisitionError(error.code, source_id=source.source_id) from error


def _observation_for(
    source: C6SourcePolicy,
    *,
    markdown: str,
    acquired_at: datetime,
) -> C6SourceObservation:
    try:
        normalized = normalize_official_markdown(markdown)
    except ValueError as error:
        raise C6AcquisitionError(
            C6FailureCode.DOCUMENT_INVALID,
            source_id=source.source_id,
        ) from error
    byte_count = len(normalized.encode("utf-8"))
    if byte_count > C6_MAX_NORMALIZED_SOURCE_BYTES:
        raise C6AcquisitionError(
            C6FailureCode.DOCUMENT_INVALID,
            source_id=source.source_id,
        )
    digest = _text_sha256(normalized)
    semantic = semantic_markdown_text(normalized)
    markers_present = all(marker in semantic for marker in source.required_markers)
    state = (
        C6SourceState.UNCHANGED
        if digest == source.reviewed_content_sha256 and markers_present
        else C6SourceState.SOURCE_DRIFT
    )
    return C6SourceObservation(
        source_id=source.source_id,
        url=source.url,
        anchor=source.anchor,
        acquired_at=acquired_at,
        normalized_bytes=byte_count,
        content_sha256=digest,
        reviewed_content_sha256=source.reviewed_content_sha256,
        required_markers_present=markers_present,
        state=state,
        raw_content_persisted=False,
    )


def _candidate_from_active(
    *,
    active_profile: OfficialCapabilityProfile,
    registry: CapabilityRegistry,
    acquired_at: datetime,
) -> OfficialCapabilityProfile:
    deadline = acquired_at + timedelta(days=14)
    draft = CandidateProfileDraft(
        version="1",
        profile_id=active_profile.profile_id,
        identity=active_profile.identity,
        support_state=active_profile.support_state,
        canonical_conclusion=active_profile.canonical_conclusion,
        sources=tuple(
            CandidateSourceDraft(
                source_id=source.source_id,
                title=source.title,
                url=source.url,
                canonical_claim=source.canonical_claim,
            )
            for source in active_profile.sources
        ),
        reviewed_at=acquired_at,
        revalidate_after=deadline,
        revalidation_warning_days=active_profile.revalidation_warning_days,
    )
    return seal_c3_candidate_draft(draft, registry)


def acquire_c6_revalidation(
    *,
    root: Path,
    policy_path: Path,
    c3_registry_path: Path,
    acquired_at: datetime,
    fetch_markdown: FetchMarkdown,
) -> C6AcquisitionResult:
    acquired = _require_aware(acquired_at)
    policy = load_current_c6_policy(root=root.resolve(), policy_path=policy_path.resolve())
    verify_c6_policy(
        root=root.resolve(),
        policy_path=policy_path.resolve(),
        c3_registry_path=c3_registry_path.resolve(),
        evaluated_at=acquired,
    )
    return evaluate_c6_sources(
        policy=policy,
        active_profile=build_current_c3_official_capability_profile(),
        registry=build_current_c3_registry(),
        acquired_at=acquired,
        fetch_markdown=fetch_markdown,
    )


def evaluate_c6_sources(
    *,
    policy: C6RevalidationPolicy,
    active_profile: OfficialCapabilityProfile,
    registry: CapabilityRegistry,
    acquired_at: datetime,
    fetch_markdown: FetchMarkdown,
) -> C6AcquisitionResult:
    acquired = _require_aware(acquired_at)
    policy = C6RevalidationPolicy.model_validate(policy.model_dump(mode="python"))
    active_profile = OfficialCapabilityProfile.model_validate(
        active_profile.model_dump(mode="python")
    )
    registry = CapabilityRegistry.model_validate(registry.model_dump(mode="python"))
    if (
        policy.profile_id != active_profile.profile_id
        or policy.identity != active_profile.identity
        or policy.c3_profile_sha256 != active_profile.profile_sha256
        or policy.c3_registry_sha256 != registry.registry_sha256
    ):
        raise ValueError("C6 acquisition policy is not bound to supplied C3 evidence")
    decision = evaluate_reviewed_profile(
        active_profile,
        registry,
        evaluated_at=acquired,
    )
    if decision.live_actions_allowed or any(decision.action_decisions.values()):
        raise ValueError("C6 acquisition cannot run over an allowed C3 gate")
    observations = tuple(
        _observation_for(
            source,
            markdown=fetch_markdown(source),
            acquired_at=acquired,
        )
        for source in policy.sources
    )
    drift_ids = tuple(
        item.source_id for item in observations if item.state is C6SourceState.SOURCE_DRIFT
    )
    candidate: OfficialCapabilityProfile | None = None
    if not drift_ids:
        candidate = _candidate_from_active(
            active_profile=build_current_c3_official_capability_profile(),
            registry=build_current_c3_registry(),
            acquired_at=acquired,
        )
    partial: dict[str, Any] = {
        "version": "1",
        "acquired_at": acquired.isoformat().replace("+00:00", "Z"),
        "policy_sha256": policy.policy_sha256,
        "policy_lifecycle": _policy_lifecycle(policy, evaluated_at=acquired).value,
        "c3_registry_sha256": registry.registry_sha256,
        "c3_profile_sha256": active_profile.profile_sha256,
        "c3_lifecycle": decision.lifecycle_state.value,
        "c3_final_status": decision.final_status.value,
        "report_state": (
            C6ReportState.SOURCE_DRIFT.value if drift_ids else C6ReportState.UNCHANGED.value
        ),
        "observations": [item.model_dump(mode="json") for item in observations],
        "drift_source_ids": list(drift_ids),
        "candidate_generated": candidate is not None,
        "candidate_profile_sha256": (candidate.profile_sha256 if candidate is not None else None),
        "candidate_can_change_gate": False,
        "promotion_allowed": False,
        "requires_independent_review": True,
        "raw_content_persisted": False,
        "live_actions_allowed": False,
        "action_decisions": {action.value: False for action in C3ProtectedAction},
    }
    report = C6RevalidationReport(
        **partial,
        report_sha256=canonical_sha256(partial),
    )
    return C6AcquisitionResult(report=report, candidate=candidate)


def _safe_state_output(*, root: Path, value: Path) -> Path:
    resolved_root = root.resolve()
    state_root = (resolved_root / ".systeme-local" / "c6").resolve()
    candidate = value if value.is_absolute() else resolved_root / value
    resolved = candidate.resolve(strict=False)
    if resolved == state_root or state_root not in resolved.parents:
        raise ValueError("C6 output must stay below .systeme-local/c6")
    state_root.mkdir(parents=True, exist_ok=True)
    if _path_has_reparse_component(resolved.parent, root=resolved_root):
        raise ValueError("C6 output uses a reparse path")
    return resolved


def _atomic_write_json(path: Path, value: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            value.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def build_c6_guidance() -> C6Guidance:
    return C6Guidance(
        version="1",
        objective=(
            "Acquire bounded official documentation, detect drift, and prepare "
            "review-only evidence without changing runtime admission."
        ),
        acquisition_boundary=(
            "Use only the public read-only OpenAI Docs MCP endpoint.",
            "Fetch only reviewed HTTPS routes and bounded anchors.",
            "Normalize in memory and persist only digests, metadata, and bounded claims.",
            "Reject redirects, oversized envelopes, malformed SSE, MCP errors, and unknown fields.",
        ),
        review_boundary=(
            "An unchanged acquisition may create only a C3 candidate profile.",
            "A changed source creates no semantic candidate and requires independent review.",
            "Neither a report nor a candidate can update the reviewed C3 registry.",
            "Promotion requires a separate code review, new seal, full CI, and deliberate commit.",
        ),
        forbidden_actions=(
            "Do not create or use Runtime keys, Tunnels, Plugins, or browser sessions.",
            "Do not open ChatGPT Chat, Work, history, conversations, or settings.",
            "Do not persist fetched official document bodies in Git or logs.",
            "Do not expose a tool or permit a protected runtime action from fetched content.",
        ),
    )


def _assert_no_sensitive_process_environment() -> None:
    configured = tuple(
        name for name in C6_SENSITIVE_ENVIRONMENT_VARIABLES if os.environ.get(name, "").strip()
    )
    if configured:
        raise ValueError("C6 refuses to run with transport or runtime secrets configured")


def _json_output(value: BaseModel) -> str:
    return json.dumps(
        value.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )


def _failure_report(
    *,
    failed_at: datetime,
    code: C6FailureCode,
    source_id: str | None = None,
    policy_sha256: str | None = None,
) -> C6FailureReport:
    return C6FailureReport(
        version="1",
        failed_at=failed_at,
        failure_code=code,
        source_id=source_id,
        policy_sha256=policy_sha256,
        candidate_generated=False,
        candidate_can_change_gate=False,
        promotion_allowed=False,
        raw_content_persisted=False,
        live_actions_allowed=False,
        action_decisions=_deny_all_actions(),
    )


def _build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Acquire and govern official capability revalidation without live actions."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("official-policy")
    subparsers.add_parser("guidance")

    for name in ("verify", "acquire"):
        command = subparsers.add_parser(name)
        command.add_argument("--root", type=Path, default=root)
        command.add_argument(
            "--policy",
            type=Path,
            default=root / PurePosixPath(C6_POLICY_PATH),
        )
        command.add_argument(
            "--c3-registry",
            type=Path,
            default=root / PurePosixPath(C6_C3_REGISTRY_PATH),
        )
        command.add_argument("--as-of")
        command.add_argument("--github-annotations", action="store_true")
        command.add_argument("--expect-all-denied", action="store_true")
        if name == "acquire":
            command.add_argument("--timeout-seconds", type=float, default=20.0)
            command.add_argument("--receipt-output", type=Path)
            command.add_argument("--candidate-output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "official-policy":
        print(_json_output(build_current_c6_policy()))
        return 0
    if args.command == "guidance":
        print(_json_output(build_c6_guidance()))
        return 0

    evaluated_at = _parse_timestamp(args.as_of)
    root = args.root.resolve()
    policy_path = args.policy.resolve()
    c3_registry_path = args.c3_registry.resolve()
    if args.command == "verify":
        try:
            status = verify_c6_policy(
                root=root,
                policy_path=policy_path,
                c3_registry_path=c3_registry_path,
                evaluated_at=evaluated_at,
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            failure = _failure_report(
                failed_at=evaluated_at,
                code=C6FailureCode.POLICY_INVALID,
            )
            print(_json_output(failure))
            if args.github_annotations:
                print("::error title=C6 policy invalid::reviewed policy verification failed")
            return 4
        print(_json_output(status))
        if args.expect_all_denied and any(status.action_decisions.values()):
            return 4
        if args.github_annotations:
            if status.policy_lifecycle is C6PolicyLifecycle.REVALIDATION_DUE:
                print(
                    "::warning title=C6 official revalidation due::"
                    f"review required by {status.policy_revalidate_after.isoformat()}"
                )
            elif status.policy_lifecycle is C6PolicyLifecycle.EXPIRED:
                print(
                    "::error title=C6 official revalidation expired::"
                    "reviewed acquisition fingerprints are expired"
                )
        return 5 if status.policy_lifecycle is C6PolicyLifecycle.EXPIRED else 0

    try:
        _assert_no_sensitive_process_environment()
        policy = load_current_c6_policy(root=root, policy_path=policy_path)
        client = OpenAIDocsMcpClient(
            endpoint=policy.docs_mcp_endpoint,
            timeout_seconds=args.timeout_seconds,
        )
        result = acquire_c6_revalidation(
            root=root,
            policy_path=policy_path,
            c3_registry_path=c3_registry_path,
            acquired_at=evaluated_at,
            fetch_markdown=client.fetch,
        )
        if args.receipt_output is not None:
            _atomic_write_json(
                _safe_state_output(root=root, value=args.receipt_output),
                result.report,
            )
        if args.candidate_output is not None and result.candidate is not None:
            _atomic_write_json(
                _safe_state_output(root=root, value=args.candidate_output),
                result.candidate,
            )
    except C6AcquisitionError as error:
        failure = _failure_report(
            failed_at=evaluated_at,
            code=error.code,
            source_id=error.source_id,
        )
        print(_json_output(failure))
        if args.github_annotations:
            print(
                "::error title=C6 official acquisition failed::"
                f"{error.code.value}:{error.source_id or 'policy'}"
            )
        return 7
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        failure = _failure_report(
            failed_at=evaluated_at,
            code=C6FailureCode.POLICY_INVALID,
        )
        print(_json_output(failure))
        if args.github_annotations:
            print("::error title=C6 policy invalid::reviewed policy verification failed")
        return 4

    print(_json_output(result.report))
    if args.github_annotations:
        if result.report.report_state is C6ReportState.SOURCE_DRIFT:
            print(
                "::error title=C6 official source drift::"
                + ",".join(result.report.drift_source_ids)
            )
        elif result.report.policy_lifecycle is C6PolicyLifecycle.REVALIDATION_DUE:
            print(
                "::warning title=C6 unchanged candidate requires review::"
                f"{result.report.candidate_profile_sha256}"
            )
        elif result.report.policy_lifecycle is C6PolicyLifecycle.EXPIRED:
            print(
                "::error title=C6 official evidence expired::"
                "an unchanged candidate still requires independent promotion"
            )
    if result.report.report_state is C6ReportState.SOURCE_DRIFT:
        return 6
    if result.report.policy_lifecycle is C6PolicyLifecycle.EXPIRED:
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
