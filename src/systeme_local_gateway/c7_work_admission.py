from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .c0_probe import C0_TOOL_NAME
from .c4_admission import C4_CHATGPT_TOOL_PROTOCOL_SHA256

C7_ACCEPTED_C6_MAIN = "81bed9b81f266709fab0ea4178f98f0607c3da44"
C7_EXPECTED_BRANCH = "codex/chatgpt-work-capability-c7"
C7_PROFILE_PATH = "governance/c7-chatgpt-work-capability-profile.json"
C7_POLICY_PATH = "governance/c7-work-prelive-policy.json"
C7_C6_POLICY_PATH = "governance/c6-revalidation-policy.json"
C7_CHAT_PROFILE_PATH = "governance/c3-chatgpt-chat-capability-profile.json"
C7_REVIEWED_AT = datetime(2026, 8, 7, 15, 42, 0, tzinfo=timezone.utc)
C7_REVALIDATE_AFTER = C7_REVIEWED_AT + timedelta(days=14)
C7_REVALIDATION_WARNING_DAYS = 7
C7_MAX_LIVE_CYCLE_SECONDS = 1_200
C7_MAX_SYNTHETIC_WORK_CHATS = 2
C7_MAX_WORK_OBSERVATION_AGE_SECONDS = 300

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SOURCE_ID_PATTERN = r"^[a-z][a-z0-9_]{2,63}$"
_GRANT_ID_PATTERN = r"^c8_[0-9a-f]{32}$"
_ALLOWED_OFFICIAL_HOSTS = ("developers.openai.com", "learn.chatgpt.com")
_SECRET_SHAPES = (
    re.compile(r"(?i)sk-[a-z0-9_-]{20,}"),
    re.compile(r"(?i)tunnel_[0-9a-f]{32}"),
    re.compile(r"(?i)bearer\s+[a-z0-9._~+/-]{20,}"),
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C7 timestamps must be timezone-aware")
    normalized = value.astimezone(UTC)
    if normalized.utcoffset() != timedelta(0):
        raise ValueError("C7 timestamps must normalize to UTC")
    return normalized


def _parse_timestamp(value: str | None) -> datetime:
    if value is None:
        return datetime.now(tz=timezone.utc)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return _require_utc(datetime.fromisoformat(normalized))


def _assert_official_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as error:
        raise ValueError("C7 official source URL is malformed") from error
    if (
        parts.scheme != "https"
        or parts.hostname not in _ALLOWED_OFFICIAL_HOSTS
        or parts.username is not None
        or parts.password is not None
        or port is not None
        or parts.query
        or parts.fragment
        or not parts.path.startswith("/")
        or parts.netloc != parts.hostname
    ):
        raise ValueError("C7 official source URL is outside the reviewed allowlist")
    return value


def _assert_secret_free(value: Any) -> None:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if any(pattern.search(text) for pattern in _SECRET_SHAPES):
        raise ValueError("C7 bounded output contains a credential-shaped value")


class WorkSupportState(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNOBSERVABLE = "unobservable"


class WorkEvidenceLifecycle(StrEnum):
    CURRENT = "current"
    REVALIDATION_DUE = "revalidation_due"
    EXPIRED = "expired"
    INVALID = "invalid"


class C7FinalStatus(StrEnum):
    READY = "COMPLETE_C7_WORK_PROFILE_READY_FOR_BOUNDED_LIVE_VALIDATION"
    C6_CLOSEOUT = "BLOCKED_BY_C6_CLOSEOUT"
    OFFICIAL_WORK_EVIDENCE = "BLOCKED_BY_OFFICIAL_WORK_EVIDENCE"
    WORK_SURFACE_AMBIGUITY = "BLOCKED_BY_WORK_SURFACE_AMBIGUITY"
    SECURITY_INVARIANT = "BLOCKED_BY_SECURITY_INVARIANT"
    TEST_FAILURE = "BLOCKED_BY_TEST_FAILURE"


class C7ProtectedAction(StrEnum):
    BROWSER_TEST = "browser_test"
    CHATGPT_WORK_ACTION = "chatgpt_work_action"
    PLUGIN_CREATION = "plugin_creation"
    RUNTIME_KEY_CREATION = "runtime_key_creation"
    TOOL_SURFACE_EXPOSURE = "tool_surface_exposure"
    TUNNEL_START = "tunnel_start"


class C7ReasonCode(StrEnum):
    PRELIVE_READY_GRANT_REQUIRED = "prelive_ready_grant_required"
    LIVE_CYCLE_GRANT_VERIFIED = "live_cycle_grant_verified"
    OFFICIAL_WORK_UNSUPPORTED = "official_work_unsupported"
    OFFICIAL_WORK_UNOBSERVABLE = "official_work_unobservable"
    EVIDENCE_REVALIDATION_DUE = "evidence_revalidation_due"
    EVIDENCE_EXPIRED = "evidence_expired"
    WORK_SURFACE_IDENTITY_MISMATCH = "work_surface_identity_mismatch"
    LIVE_CYCLE_GRANT_INVALID = "live_cycle_grant_invalid"
    SECURITY_INVARIANT_FAILED = "security_invariant_failed"


class WorkCapabilityIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_id: Literal["chatgpt"]
    native_surface: Literal["work"]
    surface_class: Literal["agentic_work"]
    capability: Literal["custom_or_local_mcp_tool_invocation"]

    @property
    def key(self) -> str:
        return f"{self.provider_id}:{self.native_surface}:{self.surface_class}:{self.capability}"


class OfficialWorkSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=_SOURCE_ID_PATTERN)
    title: str = Field(min_length=1, max_length=160)
    url: str = Field(min_length=1, max_length=512)
    canonical_claim: str = Field(min_length=1, max_length=1_200)
    claim_sha256: str = Field(pattern=_SHA256_PATTERN)
    consulted_at: datetime
    revalidate_after: datetime

    _consulted_utc = field_validator("consulted_at")(_require_utc)
    _revalidate_utc = field_validator("revalidate_after")(_require_utc)

    @model_validator(mode="after")
    def validate_source(self) -> OfficialWorkSource:
        _assert_official_url(self.url)
        if self.claim_sha256 != text_sha256(self.canonical_claim):
            raise ValueError("C7 official claim digest mismatch")
        if self.revalidate_after <= self.consulted_at:
            raise ValueError("C7 source deadline must follow consultation")
        if self.revalidate_after - self.consulted_at > timedelta(days=14):
            raise ValueError("C7 source revalidation window exceeds 14 days")
        return self


class ChatGptWorkCapabilityProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    profile_id: Literal["chatgpt_work_c7_20260727"]
    identity: WorkCapabilityIdentity
    support_state: WorkSupportState
    reviewer_state: Literal["reviewed"]
    sources: tuple[OfficialWorkSource, ...]
    canonical_conclusion: str = Field(min_length=1, max_length=2_000)
    conclusion_sha256: str = Field(pattern=_SHA256_PATTERN)
    reviewed_at: datetime
    revalidate_after: datetime
    revalidation_warning_days: Literal[7]
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    profile_sha256: str = Field(pattern=_SHA256_PATTERN)

    _reviewed_utc = field_validator("reviewed_at")(_require_utc)
    _profile_revalidate_utc = field_validator("revalidate_after")(_require_utc)

    def profile_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"profile_sha256"})

    @model_validator(mode="after")
    def validate_profile(self) -> ChatGptWorkCapabilityProfile:
        if self.identity != current_work_identity():
            raise ValueError("C7 profile identity is not the exact Work tuple")
        source_ids = tuple(source.source_id for source in self.sources)
        if len(source_ids) < 5 or source_ids != tuple(sorted(set(source_ids))):
            raise ValueError("C7 sources must contain at least five sorted unique claims")
        if any(
            source.consulted_at != self.reviewed_at
            or source.revalidate_after != self.revalidate_after
            for source in self.sources
        ):
            raise ValueError("C7 source windows must equal the profile review window")
        if self.revalidate_after <= self.reviewed_at:
            raise ValueError("C7 profile deadline must follow review")
        if self.revalidate_after - self.reviewed_at > timedelta(days=14):
            raise ValueError("C7 profile revalidation window exceeds 14 days")
        if self.conclusion_sha256 != text_sha256(self.canonical_conclusion):
            raise ValueError("C7 conclusion digest mismatch")
        evidence_payload = [source.model_dump(mode="json") for source in self.sources]
        if self.evidence_sha256 != canonical_sha256(evidence_payload):
            raise ValueError("C7 evidence digest mismatch")
        if self.profile_sha256 != canonical_sha256(self.profile_payload()):
            raise ValueError("C7 profile digest mismatch")
        _assert_secret_free(self.model_dump(mode="json"))
        return self


class C7ApprovedTool(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Literal["systeme_local_connectivity_probe"]
    protocol_sha256: str = Field(pattern=_SHA256_PATTERN)
    read_only: Literal[True]
    idempotent: Literal[True]
    destructive: Literal[False]
    high_risk: Literal[False]
    real_evidence_access: Literal[False]
    protocol_v2_reachable: Literal[False]


class C7HistoricalBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(pattern=r"^governance/[a-z0-9][a-z0-9._/-]+\.json$")
    sha256: str = Field(pattern=_SHA256_PATTERN)


class C7DefaultBoundary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    automatic_chat_to_work_switch_allowed: Literal[False]
    live_actions_allowed: Literal[False]
    effective_tool_count: Literal[0]
    existing_chats_allowed: Literal[False]
    history_allowed: Literal[False]
    private_browser_state_allowed: Literal[False]
    account_or_security_settings_allowed: Literal[False]
    write_actions_allowed: Literal[False]
    raw_secrets_allowed: Literal[False]
    real_evidence_access_allowed: Literal[False]
    protocol_v2_allowed: Literal[False]


class C7FutureGrantRequirements(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    explicit_operator_authorization_required: Literal[True]
    explicit_work_request_required: Literal[True]
    hmac_required: Literal[True]
    work_surface_required: Literal[True]
    work_only: Literal[True]
    work_entitlement_observation_required: Literal[True]
    fresh_work_quota_observation_required: Literal[True]
    max_work_observation_age_seconds: Literal[300]
    exact_internal_model_id_required: Literal[False]
    max_new_synthetic_work_chats: Literal[2]
    max_live_cycle_seconds: Literal[1200]
    existing_chats_allowed: Literal[False]
    history_allowed: Literal[False]
    private_browser_state_allowed: Literal[False]
    account_or_security_settings_allowed: Literal[False]
    write_actions_allowed: Literal[False]
    raw_secrets_allowed: Literal[False]
    real_evidence_access_allowed: Literal[False]
    protocol_v2_allowed: Literal[False]


class C7WorkPrelivePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    policy_id: Literal["chatgpt_work_prelive_c7_20260727"]
    accepted_base_commit: Literal["81bed9b81f266709fab0ea4178f98f0607c3da44"]
    identity: WorkCapabilityIdentity
    work_profile: C7HistoricalBinding
    native_chat_profile: C7HistoricalBinding
    c6_revalidation_policy: C7HistoricalBinding
    native_chat_gate_status: Literal["BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"]
    approved_tool: C7ApprovedTool
    protected_actions: tuple[C7ProtectedAction, ...]
    default_boundary: C7DefaultBoundary
    future_live_cycle_grant: C7FutureGrantRequirements
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    def policy_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"policy_sha256"})

    @model_validator(mode="after")
    def validate_policy(self) -> C7WorkPrelivePolicy:
        if self.identity != current_work_identity():
            raise ValueError("C7 policy identity is not the exact Work tuple")
        if self.work_profile.path != C7_PROFILE_PATH:
            raise ValueError("C7 policy references an unexpected Work profile")
        if self.native_chat_profile.path != C7_CHAT_PROFILE_PATH:
            raise ValueError("C7 policy references an unexpected Chat profile")
        if self.c6_revalidation_policy.path != C7_C6_POLICY_PATH:
            raise ValueError("C7 policy references an unexpected C6 policy")
        expected_actions = tuple(sorted(C7ProtectedAction, key=lambda item: item.value))
        if self.protected_actions != expected_actions:
            raise ValueError("C7 policy must bind every protected action exactly once")
        if self.approved_tool.name != C0_TOOL_NAME:
            raise ValueError("C7 policy grants an unexpected tool")
        if self.approved_tool.protocol_sha256 != C4_CHATGPT_TOOL_PROTOCOL_SHA256:
            raise ValueError("C7 policy tool protocol differs from the reviewed C4 probe")
        if self.policy_sha256 != canonical_sha256(self.policy_payload()):
            raise ValueError("C7 policy digest mismatch")
        _assert_secret_free(self.model_dump(mode="json"))
        return self


class C8LiveCycleGrant(BaseModel):
    """Future C8 authorization receipt; C7 never creates one."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    grant_id: str = Field(pattern=_GRANT_ID_PATTERN)
    identity: WorkCapabilityIdentity
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    authorized_at: datetime
    expires_at: datetime
    operator_authorized: Literal[True]
    explicit_work_request: Literal[True]
    work_only: Literal[True]
    visible_surface: Literal["work"]
    work_entitlement_state: Literal["available"]
    work_quota_state: Literal["usable"]
    surface_observed_at: datetime
    quota_observed_at: datetime
    surface_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    quota_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    visible_model_observation_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    exact_internal_model_id_exposed: Literal[False]
    max_new_synthetic_work_chats: Literal[2]
    allowed_actions: tuple[C7ProtectedAction, ...]
    existing_chats_allowed: Literal[False]
    history_allowed: Literal[False]
    private_browser_state_allowed: Literal[False]
    account_or_security_settings_allowed: Literal[False]
    write_actions_allowed: Literal[False]
    raw_secrets_allowed: Literal[False]
    real_evidence_access_allowed: Literal[False]
    protocol_v2_allowed: Literal[False]
    grant_sha256: str = Field(pattern=_SHA256_PATTERN)
    authorization_hmac: str = Field(pattern=_SHA256_PATTERN)

    _authorized_utc = field_validator("authorized_at")(_require_utc)
    _expires_utc = field_validator("expires_at")(_require_utc)
    _surface_observed_utc = field_validator("surface_observed_at")(_require_utc)
    _quota_observed_utc = field_validator("quota_observed_at")(_require_utc)

    def commitment_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            exclude={"grant_sha256", "authorization_hmac"},
        )

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"authorization_hmac"})

    @model_validator(mode="after")
    def validate_grant(self) -> C8LiveCycleGrant:
        if self.identity != current_work_identity():
            raise ValueError("C8 grant is not bound to the exact Work tuple")
        expected_actions = tuple(sorted(C7ProtectedAction, key=lambda item: item.value))
        if self.allowed_actions != expected_actions:
            raise ValueError("C8 grant must bind the complete bounded action sequence")
        if self.expires_at <= self.authorized_at:
            raise ValueError("C8 grant expiry must follow authorization")
        if self.expires_at - self.authorized_at > timedelta(seconds=C7_MAX_LIVE_CYCLE_SECONDS):
            raise ValueError("C8 grant lifetime exceeds the C7 maximum")
        for name, observed_at in (
            ("surface", self.surface_observed_at),
            ("quota", self.quota_observed_at),
        ):
            if observed_at > self.authorized_at:
                raise ValueError(f"C8 {name} observation follows authorization")
            if self.authorized_at - observed_at > timedelta(
                seconds=C7_MAX_WORK_OBSERVATION_AGE_SECONDS
            ):
                raise ValueError(f"C8 {name} observation is stale at authorization")
        if self.grant_sha256 != canonical_sha256(self.commitment_payload()):
            raise ValueError("C8 grant digest mismatch")
        _assert_secret_free(self.model_dump(mode="json"))
        return self

    def verify_hmac(self, audit_key: bytes) -> bool:
        if len(audit_key) < 32:
            return False
        expected = hmac.new(
            audit_key,
            canonical_json(self.hmac_payload()),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, self.authorization_hmac)


class C7ActionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: C7ProtectedAction
    allowed: bool
    reason_code: C7ReasonCode


class C7PreliveDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    evaluated_at: datetime
    identity: WorkCapabilityIdentity
    support_state: WorkSupportState | None
    lifecycle_state: WorkEvidenceLifecycle
    final_status: C7FinalStatus
    reason_code: C7ReasonCode
    profile_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    policy_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    native_chat_gate_status: Literal["BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"]
    operator_live_cycle_grant_present: bool
    operator_live_cycle_grant_verified: bool
    automatic_chat_to_work_switch_allowed: Literal[False]
    live_actions_allowed: bool
    action_decisions: tuple[C7ActionDecision, ...]
    effective_tools: tuple[C7ApprovedTool, ...]
    decision_sha256: str = Field(pattern=_SHA256_PATTERN)

    _evaluated_utc = field_validator("evaluated_at")(_require_utc)

    def decision_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"decision_sha256"})

    @model_validator(mode="after")
    def validate_decision(self) -> C7PreliveDecision:
        expected_actions = tuple(sorted(C7ProtectedAction, key=lambda item: item.value))
        if tuple(item.action for item in self.action_decisions) != expected_actions:
            raise ValueError("C7 decision must bind every protected action")
        if self.live_actions_allowed != all(item.allowed for item in self.action_decisions):
            raise ValueError("C7 live-action summary disagrees with action decisions")
        if self.live_actions_allowed:
            if (
                not self.operator_live_cycle_grant_verified
                or self.final_status is not C7FinalStatus.READY
                or len(self.effective_tools) != 1
            ):
                raise ValueError("C7 admitted cycle lacks a verified grant or exact tool")
        elif self.effective_tools:
            raise ValueError("C7 denied/default decision must expose zero tools")
        if self.decision_sha256 != canonical_sha256(self.decision_payload()):
            raise ValueError("C7 decision digest mismatch")
        _assert_secret_free(self.model_dump(mode="json"))
        return self


def current_work_identity() -> WorkCapabilityIdentity:
    return WorkCapabilityIdentity(
        provider_id="chatgpt",
        native_surface="work",
        surface_class="agentic_work",
        capability="custom_or_local_mcp_tool_invocation",
    )


def _source(source_id: str, title: str, url: str, claim: str) -> OfficialWorkSource:
    return OfficialWorkSource(
        source_id=source_id,
        title=title,
        url=url,
        canonical_claim=claim,
        claim_sha256=text_sha256(claim),
        consulted_at=C7_REVIEWED_AT,
        revalidate_after=C7_REVALIDATE_AFTER,
    )


def build_current_c7_profile() -> ChatGptWorkCapabilityProfile:
    sources = tuple(
        sorted(
            (
                _source(
                    "chatgpt_work_surface",
                    "Get started with ChatGPT Work",
                    "https://learn.chatgpt.com/docs/get-started-with-work",
                    "The official Work guide defines ChatGPT Work as a separately "
                    "selected surface for outcome-oriented tasks and says it can use "
                    "plugins and approved tools; it does not make Work equivalent to Chat.",
                ),
                _source(
                    "mcp_work_web_route",
                    "Model Context Protocol",
                    "https://learn.chatgpt.com/docs/extend/mcp",
                    "The official MCP guide states that hosted ChatGPT Work chats use "
                    "installed plugins for remote MCP tools and that available tools are "
                    "managed through Plugins in ChatGPT Work.",
                ),
                _source(
                    "plugin_connection_route",
                    "Connect and test your plugin",
                    "https://developers.openai.com/plugins/deploy/connect-chatgpt",
                    "Official connection steps register a public HTTPS /mcp endpoint "
                    "through ChatGPT Plugins and require review of discovered tools and "
                    "metadata before use.",
                ),
                _source(
                    "plugin_packaging_surface",
                    "Package your plugin",
                    "https://developers.openai.com/plugins/build/plugins",
                    "Official local plugin authoring registers the MCP server in developer "
                    "mode and assigns plugin creation and testing to Work mode or Codex.",
                ),
                _source(
                    "plugin_surface_availability",
                    "Plugins",
                    "https://learn.chatgpt.com/docs/plugins",
                    "The official Plugins overview states that Plugins are available with "
                    "ChatGPT Work on the web, are unavailable in Chat, and may add MCP "
                    "tools to new chats.",
                ),
                _source(
                    "secure_mcp_tunnel_route",
                    "Secure MCP Tunnel",
                    "https://developers.openai.com/api/docs/guides/secure-mcp-tunnels",
                    "Official Secure MCP Tunnel guidance routes a local MCP server to "
                    "supported ChatGPT plugin setup without changing surface, tool, or "
                    "authorization policy.",
                ),
            ),
            key=lambda item: item.source_id,
        )
    )
    conclusion = (
        "Current reviewed official OpenAI documentation supports the Plugin-mediated "
        "custom or local MCP tool path on ChatGPT Work on the web. This evidence is "
        "surface-specific: it does not support native Chat, does not authorize a live "
        "cycle, and does not expose any local tool without a separate fresh operator grant."
    )
    payload: dict[str, Any] = {
        "version": "1",
        "profile_id": "chatgpt_work_c7_20260727",
        "identity": current_work_identity().model_dump(mode="json"),
        "support_state": WorkSupportState.SUPPORTED.value,
        "reviewer_state": "reviewed",
        "sources": [source.model_dump(mode="json") for source in sources],
        "canonical_conclusion": conclusion,
        "conclusion_sha256": text_sha256(conclusion),
        "reviewed_at": C7_REVIEWED_AT.isoformat().replace("+00:00", "Z"),
        "revalidate_after": C7_REVALIDATE_AFTER.isoformat().replace("+00:00", "Z"),
        "revalidation_warning_days": C7_REVALIDATION_WARNING_DAYS,
        "evidence_sha256": canonical_sha256([source.model_dump(mode="json") for source in sources]),
    }
    return ChatGptWorkCapabilityProfile(
        **payload,
        profile_sha256=canonical_sha256(payload),
    )


def _file_canonical_sha256(path: Path) -> str:
    return canonical_sha256(json.loads(path.read_text(encoding="utf-8")))


def build_current_c7_policy(root: Path) -> C7WorkPrelivePolicy:
    profile = build_current_c7_profile()
    chat_profile = root / C7_CHAT_PROFILE_PATH
    c6_policy = root / C7_C6_POLICY_PATH
    if not chat_profile.is_file() or not c6_policy.is_file():
        raise ValueError("C7 historical governance dependency is missing")
    payload: dict[str, Any] = {
        "version": "1",
        "policy_id": "chatgpt_work_prelive_c7_20260727",
        "accepted_base_commit": C7_ACCEPTED_C6_MAIN,
        "identity": current_work_identity().model_dump(mode="json"),
        "work_profile": {
            "path": C7_PROFILE_PATH,
            "sha256": profile.profile_sha256,
        },
        "native_chat_profile": {
            "path": C7_CHAT_PROFILE_PATH,
            "sha256": _file_canonical_sha256(chat_profile),
        },
        "c6_revalidation_policy": {
            "path": C7_C6_POLICY_PATH,
            "sha256": _file_canonical_sha256(c6_policy),
        },
        "native_chat_gate_status": "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE",
        "approved_tool": {
            "name": C0_TOOL_NAME,
            "protocol_sha256": C4_CHATGPT_TOOL_PROTOCOL_SHA256,
            "read_only": True,
            "idempotent": True,
            "destructive": False,
            "high_risk": False,
            "real_evidence_access": False,
            "protocol_v2_reachable": False,
        },
        "protected_actions": [
            action.value for action in sorted(C7ProtectedAction, key=lambda item: item.value)
        ],
        "default_boundary": {
            "automatic_chat_to_work_switch_allowed": False,
            "live_actions_allowed": False,
            "effective_tool_count": 0,
            "existing_chats_allowed": False,
            "history_allowed": False,
            "private_browser_state_allowed": False,
            "account_or_security_settings_allowed": False,
            "write_actions_allowed": False,
            "raw_secrets_allowed": False,
            "real_evidence_access_allowed": False,
            "protocol_v2_allowed": False,
        },
        "future_live_cycle_grant": {
            "explicit_operator_authorization_required": True,
            "explicit_work_request_required": True,
            "hmac_required": True,
            "work_surface_required": True,
            "work_only": True,
            "work_entitlement_observation_required": True,
            "fresh_work_quota_observation_required": True,
            "max_work_observation_age_seconds": C7_MAX_WORK_OBSERVATION_AGE_SECONDS,
            "exact_internal_model_id_required": False,
            "max_new_synthetic_work_chats": C7_MAX_SYNTHETIC_WORK_CHATS,
            "max_live_cycle_seconds": C7_MAX_LIVE_CYCLE_SECONDS,
            "existing_chats_allowed": False,
            "history_allowed": False,
            "private_browser_state_allowed": False,
            "account_or_security_settings_allowed": False,
            "write_actions_allowed": False,
            "raw_secrets_allowed": False,
            "real_evidence_access_allowed": False,
            "protocol_v2_allowed": False,
        },
    }
    return C7WorkPrelivePolicy(
        **payload,
        policy_sha256=canonical_sha256(payload),
    )


def lifecycle_for(
    profile: ChatGptWorkCapabilityProfile,
    evaluated_at: datetime,
) -> WorkEvidenceLifecycle:
    at = _require_utc(evaluated_at)
    if at >= profile.revalidate_after:
        return WorkEvidenceLifecycle.EXPIRED
    warning_start = profile.revalidate_after - timedelta(days=profile.revalidation_warning_days)
    if at >= warning_start:
        return WorkEvidenceLifecycle.REVALIDATION_DUE
    return WorkEvidenceLifecycle.CURRENT


def _commit_decision(payload: dict[str, Any]) -> C7PreliveDecision:
    return C7PreliveDecision(
        **payload,
        decision_sha256=canonical_sha256(payload),
    )


def evaluate_c7_prelive(
    *,
    profile: ChatGptWorkCapabilityProfile,
    policy: C7WorkPrelivePolicy,
    evaluated_at: datetime,
    grant: C8LiveCycleGrant | None = None,
    audit_key: bytes | None = None,
) -> C7PreliveDecision:
    at = _require_utc(evaluated_at)
    lifecycle = lifecycle_for(profile, at)
    status = C7FinalStatus.READY
    reason = C7ReasonCode.PRELIVE_READY_GRANT_REQUIRED
    grant_verified = False

    if profile.identity != policy.identity:
        status = C7FinalStatus.WORK_SURFACE_AMBIGUITY
        reason = C7ReasonCode.WORK_SURFACE_IDENTITY_MISMATCH
    elif profile.profile_sha256 != policy.work_profile.sha256:
        status = C7FinalStatus.SECURITY_INVARIANT
        reason = C7ReasonCode.SECURITY_INVARIANT_FAILED
    elif profile.support_state is WorkSupportState.UNSUPPORTED:
        status = C7FinalStatus.OFFICIAL_WORK_EVIDENCE
        reason = C7ReasonCode.OFFICIAL_WORK_UNSUPPORTED
    elif profile.support_state is WorkSupportState.UNOBSERVABLE:
        status = C7FinalStatus.OFFICIAL_WORK_EVIDENCE
        reason = C7ReasonCode.OFFICIAL_WORK_UNOBSERVABLE
    elif lifecycle is WorkEvidenceLifecycle.REVALIDATION_DUE:
        status = C7FinalStatus.OFFICIAL_WORK_EVIDENCE
        reason = C7ReasonCode.EVIDENCE_REVALIDATION_DUE
    elif lifecycle is WorkEvidenceLifecycle.EXPIRED:
        status = C7FinalStatus.OFFICIAL_WORK_EVIDENCE
        reason = C7ReasonCode.EVIDENCE_EXPIRED
    elif grant is not None:
        grant_verified = (
            grant.identity == policy.identity
            and grant.policy_sha256 == policy.policy_sha256
            and grant.profile_sha256 == profile.profile_sha256
            and grant.authorized_at <= at < grant.expires_at
            and at - grant.surface_observed_at
            <= timedelta(seconds=C7_MAX_WORK_OBSERVATION_AGE_SECONDS)
            and at - grant.quota_observed_at
            <= timedelta(seconds=C7_MAX_WORK_OBSERVATION_AGE_SECONDS)
            and audit_key is not None
            and grant.verify_hmac(audit_key)
        )
        if grant.identity != policy.identity:
            status = C7FinalStatus.WORK_SURFACE_AMBIGUITY
            reason = C7ReasonCode.WORK_SURFACE_IDENTITY_MISMATCH
        elif not grant_verified:
            status = C7FinalStatus.SECURITY_INVARIANT
            reason = C7ReasonCode.LIVE_CYCLE_GRANT_INVALID
        else:
            reason = C7ReasonCode.LIVE_CYCLE_GRANT_VERIFIED

    allow = status is C7FinalStatus.READY and grant_verified
    action_decisions = tuple(
        C7ActionDecision(action=action, allowed=allow, reason_code=reason)
        for action in sorted(C7ProtectedAction, key=lambda item: item.value)
    )
    effective_tools = (policy.approved_tool,) if allow else ()
    payload: dict[str, Any] = {
        "version": "1",
        "evaluated_at": at.isoformat().replace("+00:00", "Z"),
        "identity": policy.identity.model_dump(mode="json"),
        "support_state": profile.support_state.value,
        "lifecycle_state": lifecycle.value,
        "final_status": status.value,
        "reason_code": reason.value,
        "profile_sha256": profile.profile_sha256,
        "policy_sha256": policy.policy_sha256,
        "native_chat_gate_status": policy.native_chat_gate_status,
        "operator_live_cycle_grant_present": grant is not None,
        "operator_live_cycle_grant_verified": grant_verified,
        "automatic_chat_to_work_switch_allowed": False,
        "live_actions_allowed": allow,
        "action_decisions": [item.model_dump(mode="json") for item in action_decisions],
        "effective_tools": [tool.model_dump(mode="json") for tool in effective_tools],
    }
    return _commit_decision(payload)


def load_profile(path: Path) -> ChatGptWorkCapabilityProfile:
    return ChatGptWorkCapabilityProfile.model_validate_json(path.read_text(encoding="utf-8"))


def load_policy(path: Path) -> C7WorkPrelivePolicy:
    return C7WorkPrelivePolicy.model_validate_json(path.read_text(encoding="utf-8"))


def committed_status(root: Path, evaluated_at: datetime) -> C7PreliveDecision:
    profile = load_profile(root / C7_PROFILE_PATH)
    policy = load_policy(root / C7_POLICY_PATH)
    return evaluate_c7_prelive(
        profile=profile,
        policy=policy,
        evaluated_at=evaluated_at,
    )


def rendered_json(model: BaseModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="C7 ChatGPT Work pre-live admission")
    subparsers = parser.add_subparsers(dest="command", required=True)
    status = subparsers.add_parser("status", help="evaluate committed default-deny C7 state")
    status.add_argument("--as-of")
    subparsers.add_parser("render-profile", help="render the reviewed C7 Work profile")
    subparsers.add_parser("render-policy", help="render the reviewed C7 pre-live policy")
    subparsers.add_parser("show-c8-gates", help="print bounded future C8 requirements")
    args = parser.parse_args(argv)
    root = _repository_root()

    try:
        if args.command == "render-profile":
            print(rendered_json(build_current_c7_profile()), end="")
            return 0
        if args.command == "render-policy":
            print(rendered_json(build_current_c7_policy(root)), end="")
            return 0
        if args.command == "show-c8-gates":
            policy = load_policy(root / C7_POLICY_PATH)
            output = {
                "status": C7FinalStatus.READY.value,
                "c7_performs_live_actions": False,
                "required_fresh_operator_grant": True,
                "required_surface": "work",
                "explicit_work_request_required": True,
                "work_entitlement_observation_required": True,
                "fresh_work_quota_observation_required": True,
                "max_work_observation_age_seconds": (
                    policy.future_live_cycle_grant.max_work_observation_age_seconds
                ),
                "exact_internal_model_id_required": False,
                "max_new_synthetic_work_chats": (
                    policy.future_live_cycle_grant.max_new_synthetic_work_chats
                ),
                "only_eligible_tool": policy.approved_tool.name,
                "forbidden": [
                    "native_chat",
                    "automatic_chat_to_work_switch",
                    "existing_chats",
                    "history",
                    "private_browser_state",
                    "account_or_security_settings",
                    "write_actions",
                    "raw_secrets",
                    "real_evidence",
                    "protocol_v2",
                ],
            }
            _assert_secret_free(output)
            print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        decision = committed_status(root, _parse_timestamp(args.as_of))
        print(rendered_json(decision), end="")
        return 0 if decision.final_status is C7FinalStatus.READY else 1
    except (OSError, ValueError) as error:
        output = {
            "status": C7FinalStatus.SECURITY_INVARIANT.value,
            "error": str(error),
            "live_actions_allowed": False,
            "effective_tool_count": 0,
        }
        _assert_secret_free(output)
        print(json.dumps(output, ensure_ascii=False, sort_keys=True))
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
