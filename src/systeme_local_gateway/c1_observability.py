from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .c0_probe import (
    C0_AUDIT_ID_PATTERN,
    C0_GIT_COMMIT_PATTERN,
    C0_SHA256_PATTERN,
)

C1_TEST_CHAT_LABELS = ("c1-test-chat-a", "c1-test-chat-b")
C1_CONFIGURATION_PRECEDENCE = (
    "cli_override",
    "project_configuration",
    "profile_configuration",
    "user_configuration",
    "system_configuration",
    "built_in_default",
)
C1_FINAL_STATUS: Literal["COMPLETE_BOUNDED_CHAT_SURFACE_OBSERVABILITY_VERIFIED"] = (
    "COMPLETE_BOUNDED_CHAT_SURFACE_OBSERVABILITY_VERIFIED"
)
C1_MANUAL_EVIDENCE_TTL = timedelta(hours=2)
C1_SURFACE_TO_RESPONSE_MAX_AGE = timedelta(minutes=30)

_OFFICIAL_HOST_RE = re.compile(r"^https://(?:developers\.openai\.com|learn\.chatgpt\.com)/")
_SOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.:/\\ -]{1,256}$")
_SECRET_VALUE_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"\b(?:sk|gh[opusr])_[A-Za-z0-9_-]{8,}", re.IGNORECASE),
    re.compile(r"\b(?:cookie|authorization)\s*[:=]\s*\S+", re.IGNORECASE),
)
_DOMAINS = {
    "runtime": b"systeme-local/c1/runtime-setup/v1\0",
    "surface": b"systeme-local/c1/surface/v1\0",
    "visible_model": b"systeme-local/c1/visible-model/v1\0",
    "correlation": b"systeme-local/c1/chat-correlation/v1\0",
    "negative": b"systeme-local/c1/negative-tests/v1\0",
    "revocation": b"systeme-local/c1/revocation/v1\0",
}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C1 timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _validate_window(
    *,
    observed_at: datetime,
    expires_at: datetime,
    maximum: timedelta,
) -> None:
    if expires_at <= observed_at:
        raise ValueError("C1 evidence must expire after it is observed")
    if expires_at - observed_at > maximum:
        raise ValueError("C1 evidence expiry exceeds its bounded window")


def _require_audit_key(audit_key: str) -> str:
    if len(audit_key) < 32:
        raise ValueError("C1 evidence requires an audit key of at least 32 characters")
    return audit_key


def _payload_hmac(*, domain: str, payload: dict[str, Any], audit_key: str) -> str:
    return hmac.new(
        _require_audit_key(audit_key).encode("utf-8"),
        _DOMAINS[domain] + _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


def _verify_hmac(
    model: BaseModel,
    *,
    domain: str,
    field_name: str,
    audit_key: str,
) -> None:
    payload = model.model_dump(mode="json", exclude={field_name})
    expected = _payload_hmac(domain=domain, payload=payload, audit_key=audit_key)
    actual = getattr(model, field_name)
    if not hmac.compare_digest(actual, expected):
        raise ValueError(f"C1 {domain} evidence HMAC mismatch")


def _reject_secret_like(value: str) -> str:
    if any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS):
        raise ValueError("C1 evidence contains a secret-like value")
    return value


class C1EvidenceState(StrEnum):
    OBSERVED = "observed"
    CONFIGURED_DEFAULT = "configured_default"
    UNOBSERVABLE = "unobservable"
    NOT_APPLICABLE = "not_applicable"


class C1EvidenceSource(StrEnum):
    CODEX_TURN_METADATA = "codex_turn_metadata"
    CODEX_USER_CONFIG = "codex_user_config"
    CODEX_CLI = "codex_cli"
    CODEX_APP_CONTEXT = "codex_app_context"
    CODEX_PERMISSION_CONTEXT = "codex_permission_context"
    SYSTEM_RUNTIME = "system_runtime"
    GIT_REPOSITORY = "git_repository"
    CHATGPT_VISIBLE_UI = "chatgpt_visible_ui"
    OPERATOR_CONFIRMATION = "operator_confirmation"
    OFFICIAL_OPENAI_DOCUMENTATION = "official_openai_documentation"
    C0_REVIEWED_ARTIFACT = "c0_reviewed_artifact"
    LOCAL_AUDIT = "local_audit"
    SECURE_MCP_TUNNEL = "secure_mcp_tunnel"


class C1ConfigurationLayer(StrEnum):
    CLI_OVERRIDE = "cli_override"
    PROJECT_CONFIGURATION = "project_configuration"
    PROFILE_CONFIGURATION = "profile_configuration"
    USER_CONFIGURATION = "user_configuration"
    SYSTEM_CONFIGURATION = "system_configuration"
    BUILT_IN_DEFAULT = "built_in_default"


class C1SetupField(StrEnum):
    OPERATING_SYSTEM = "operating_system"
    CODEX_VERSION = "codex_version"
    CODEX_PRODUCT_SURFACE = "codex_product_surface"
    AUTHENTICATION_BOUNDARY = "authentication_boundary"
    ACTIVE_REPOSITORY_PATH = "active_repository_path"
    GIT_REMOTE = "git_remote"
    BRANCH = "branch"
    HEAD_COMMIT = "head_commit"
    WORKTREE_STATE = "worktree_state"
    ACTIVE_RUNTIME_MODEL = "active_runtime_model"
    ACTIVE_REASONING_EFFORT = "active_reasoning_effort"
    CONFIGURED_DEFAULT_MODEL = "configured_default_model"
    CONFIGURED_DEFAULT_REASONING = "configured_default_reasoning"
    ACTIVE_SERVICE_TIER = "active_service_tier"
    PERMISSION_MODE = "permission_mode"
    SANDBOX_MODE = "sandbox_mode"
    APPROVAL_POLICY = "approval_policy"
    APPROVAL_REVIEWER = "approval_reviewer"
    NETWORK_ACCESS_POLICY = "network_access_policy"
    BROWSER_SURFACE = "browser_surface"
    ENABLED_PLUGIN_NAMES = "enabled_plugin_names"
    CONFIGURED_MCP_SERVER_NAMES = "configured_mcp_server_names"
    POLICY_SHA256 = "policy_sha256"
    TOOL_SNAPSHOT_SHA256 = "tool_snapshot_sha256"
    TUNNEL_CLIENT_VERSION = "tunnel_client_version"
    TUNNEL_CLIENT_BINARY_SHA256 = "tunnel_client_binary_sha256"


class C1Surface(StrEnum):
    CHAT = "chat"
    WORK = "work"
    CODEX = "codex"
    UNKNOWN = "unknown"


class C1CanonicalReasoningEffort(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"
    MAX = "max"
    ULTRA = "ultra"


class C1TestChatLabel(StrEnum):
    CHAT_A = "c1-test-chat-a"
    CHAT_B = "c1-test-chat-b"


class C1NegativeCheckId(StrEnum):
    SAME_CHAT_REPLAY = "same_chat_replay"
    CROSS_CHAT_REPLAY = "cross_chat_replay"
    UNKNOWN_FIELD = "unknown_field"
    MALFORMED_CHALLENGE = "malformed_challenge"
    LOCAL_FILE_REQUEST = "local_file_request"
    COMMAND_EXECUTION_REQUEST = "command_execution_request"
    SECRET_REQUEST = "secret_request"
    B2_EVIDENCE_REQUEST = "b2_evidence_request"
    WRITE_OPERATION_REQUEST = "write_operation_request"
    POST_REVOCATION_CALL = "post_revocation_call"


class C1NegativeOutcome(StrEnum):
    REJECTED = "rejected"
    CAPABILITY_NOT_EXPOSED = "capability_not_exposed"
    UNREACHABLE_AFTER_REVOCATION = "unreachable_after_revocation"


class C1C0DependencyStatus(StrEnum):
    COMPLETE_LIVE_CHATGPT_WEB_CONNECTION_VERIFIED = "COMPLETE_LIVE_CHATGPT_WEB_CONNECTION_VERIFIED"
    READY_BUT_MANUAL_CHATGPT_WEB_GATE_PENDING = "READY_BUT_MANUAL_CHATGPT_WEB_GATE_PENDING"


class C1OfficialSourceReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    title: str = Field(min_length=1, max_length=160)
    url: str = Field(min_length=1, max_length=512)
    consulted_at: datetime
    canonical_summary: str = Field(min_length=1, max_length=1_200)
    summary_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    revalidate_after: datetime

    _aware_consulted_at = field_validator("consulted_at")(_require_aware)
    _aware_revalidate_after = field_validator("revalidate_after")(_require_aware)

    @model_validator(mode="after")
    def validate_reference(self) -> "C1OfficialSourceReference":
        if _SOURCE_ID_RE.fullmatch(self.source_id) is None:
            raise ValueError("C1 official source ID is invalid")
        if _OFFICIAL_HOST_RE.match(self.url) is None:
            raise ValueError("C1 official sources must be hosted by OpenAI")
        if (
            self.summary_sha256
            != hashlib.sha256(self.canonical_summary.encode("utf-8")).hexdigest()
        ):
            raise ValueError("C1 official-source canonical summary digest mismatch")
        if self.revalidate_after <= self.consulted_at:
            raise ValueError("C1 official source must have a future revalidation deadline")
        if self.revalidate_after - self.consulted_at > timedelta(days=30):
            raise ValueError("C1 official source revalidation window is too long")
        return self


class C1OfficialEvidenceProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    profile_id: Literal["chatgpt_web_c1_20260726"]
    sources: tuple[C1OfficialSourceReference, ...]
    profile_sha256: str = Field(pattern=C0_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_profile(self) -> "C1OfficialEvidenceProfile":
        ids = tuple(source.source_id for source in self.sources)
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ValueError("C1 official sources must be sorted and unique")
        payload = self.model_dump(mode="json", exclude={"profile_sha256"})
        if self.profile_sha256 != canonical_sha256(payload):
            raise ValueError("C1 official evidence profile digest mismatch")
        return self


class C1SettingObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    value: str | bool | int | tuple[str, ...] | None
    state: C1EvidenceState
    evidence_source: C1EvidenceSource
    observed_at: datetime

    _aware_observed_at = field_validator("observed_at")(_require_aware)

    @field_validator("value")
    @classmethod
    def reject_sensitive_value(
        cls,
        value: str | bool | int | tuple[str, ...] | None,
    ) -> str | bool | int | tuple[str, ...] | None:
        values = (value,) if isinstance(value, str) else value
        if isinstance(values, tuple):
            for item in values:
                if not isinstance(item, str):
                    raise ValueError("C1 setting tuples may contain only strings")
                _reject_secret_like(item)
        return value

    @model_validator(mode="after")
    def validate_state(self) -> "C1SettingObservation":
        if self.state in (
            C1EvidenceState.OBSERVED,
            C1EvidenceState.CONFIGURED_DEFAULT,
        ):
            if self.value is None:
                raise ValueError("observed/configured C1 settings require a value")
        elif self.value is not None:
            raise ValueError("unobservable/not-applicable C1 settings cannot carry a value")
        return self


class C1RuntimeSetupObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    source: Literal["bounded_local_inventory"]
    simulated: bool
    settings: dict[C1SetupField, C1SettingObservation]
    configuration_precedence: tuple[C1ConfigurationLayer, ...]
    observed_at: datetime
    expires_at: datetime
    observation_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_observed_at = field_validator("observed_at")(_require_aware)
    _aware_expires_at = field_validator("expires_at")(_require_aware)

    @model_validator(mode="after")
    def validate_setup(self) -> "C1RuntimeSetupObservation":
        if set(self.settings) != set(C1SetupField):
            raise ValueError("C1 runtime setup requires every typed setting exactly once")
        expected_precedence = tuple(
            C1ConfigurationLayer(value) for value in C1_CONFIGURATION_PRECEDENCE
        )
        if self.configuration_precedence != expected_precedence:
            raise ValueError("C1 configuration precedence is incomplete or reordered")
        for key in (
            C1SetupField.CONFIGURED_DEFAULT_MODEL,
            C1SetupField.CONFIGURED_DEFAULT_REASONING,
        ):
            if self.settings[key].state not in (
                C1EvidenceState.CONFIGURED_DEFAULT,
                C1EvidenceState.UNOBSERVABLE,
            ):
                raise ValueError("configured defaults cannot masquerade as runtime observations")
        for key in (
            C1SetupField.ACTIVE_RUNTIME_MODEL,
            C1SetupField.ACTIVE_REASONING_EFFORT,
        ):
            if self.settings[key].state is C1EvidenceState.CONFIGURED_DEFAULT:
                raise ValueError("configured defaults cannot prove active runtime values")
        for key in (C1SetupField.ENABLED_PLUGIN_NAMES, C1SetupField.CONFIGURED_MCP_SERVER_NAMES):
            value = self.settings[key].value
            if isinstance(value, tuple):
                if value != tuple(sorted(set(value))):
                    raise ValueError(f"{key.value} must be sorted and unique")
        _validate_window(
            observed_at=self.observed_at,
            expires_at=self.expires_at,
            maximum=timedelta(hours=24),
        )
        if any(
            item.observed_at > self.observed_at + timedelta(minutes=1)
            for item in self.settings.values()
        ):
            raise ValueError("C1 setting observation postdates its setup observation")
        return self


class C1SurfaceObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    source: Literal["chatgpt_visible_ui"]
    simulated: bool
    test_chat_label: C1TestChatLabel
    surface: C1Surface
    prompt_sent: Literal[False]
    plugin_selected: bool
    work_tested: Literal[False]
    existing_chats_accessed: Literal[False]
    private_browser_state_accessed: Literal[False]
    observed_at: datetime
    expires_at: datetime
    observation_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_observed_at = field_validator("observed_at")(_require_aware)
    _aware_expires_at = field_validator("expires_at")(_require_aware)

    @model_validator(mode="after")
    def validate_surface(self) -> "C1SurfaceObservation":
        _validate_window(
            observed_at=self.observed_at,
            expires_at=self.expires_at,
            maximum=C1_MANUAL_EVIDENCE_TTL,
        )
        if self.surface is not C1Surface.CHAT and self.plugin_selected:
            raise ValueError("C1 refuses prompts and Plugin selection outside Chat")
        return self


class C1VisibleModelObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    source: Literal["chatgpt_visible_ui"]
    simulated: bool
    visible_model_label: str | None = Field(default=None, max_length=128)
    model_label_state: C1EvidenceState
    visible_reasoning_label: str | None = Field(default=None, max_length=128)
    reasoning_label_state: C1EvidenceState
    exact_internal_model_id_exposed: bool
    exact_internal_model_id: str | None = Field(default=None, max_length=128)
    canonical_reasoning_effort: C1CanonicalReasoningEffort | None = None
    reasoning_mapping_source_sha256: str | None = Field(
        default=None,
        pattern=C0_SHA256_PATTERN,
    )
    observed_at: datetime
    expires_at: datetime
    observation_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_observed_at = field_validator("observed_at")(_require_aware)
    _aware_expires_at = field_validator("expires_at")(_require_aware)

    @field_validator("visible_model_label", "visible_reasoning_label", "exact_internal_model_id")
    @classmethod
    def reject_secret_labels(cls, value: str | None) -> str | None:
        return None if value is None else _reject_secret_like(value)

    @model_validator(mode="after")
    def validate_visible_model(self) -> "C1VisibleModelObservation":
        _validate_window(
            observed_at=self.observed_at,
            expires_at=self.expires_at,
            maximum=C1_MANUAL_EVIDENCE_TTL,
        )
        for label, state, name in (
            (self.visible_model_label, self.model_label_state, "model"),
            (self.visible_reasoning_label, self.reasoning_label_state, "reasoning"),
        ):
            if state is C1EvidenceState.OBSERVED and label is None:
                raise ValueError(f"observed ChatGPT Web {name} label requires a value")
            if state is not C1EvidenceState.OBSERVED and label is not None:
                raise ValueError(f"unobserved ChatGPT Web {name} label cannot carry a value")
        if self.exact_internal_model_id_exposed != (self.exact_internal_model_id is not None):
            raise ValueError("ChatGPT Web internal model attribution is inconsistent")
        if self.canonical_reasoning_effort is None:
            if self.reasoning_mapping_source_sha256 is not None:
                raise ValueError("reasoning mapping evidence requires a canonical value")
        elif self.reasoning_mapping_source_sha256 is None:
            raise ValueError("localized reasoning labels cannot be mapped without evidence")
        return self


class C1TestChatObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    source: Literal["manual_chatgpt_web"]
    simulated: bool
    test_chat_label: C1TestChatLabel
    surface_observation_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    tool_name: Literal["systeme_local_connectivity_probe"]
    tool_count: Literal[1]
    write_tool_count: Literal[0]
    high_risk_tool_count: Literal[0]
    positive_tool_invocation_count: Literal[1]
    challenge_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    response_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    server_build_commit: str = Field(pattern=C0_GIT_COMMIT_PATTERN)
    local_policy_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    tool_snapshot_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    audit_correlation: str = Field(pattern=C0_AUDIT_ID_PATTERN)
    audit_record_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    read_only: Literal[True]
    write_actions_enabled: Literal[False]
    real_evidence_access: Literal[False]
    protocol_v2_reachable: Literal[False]
    work_invoked: Literal[False]
    existing_chats_accessed: Literal[False]
    conversation_identifier_collected: Literal[False]
    private_browser_state_accessed: Literal[False]
    observed_at: datetime
    expires_at: datetime

    _aware_observed_at = field_validator("observed_at")(_require_aware)
    _aware_expires_at = field_validator("expires_at")(_require_aware)

    @model_validator(mode="after")
    def validate_chat(self) -> "C1TestChatObservation":
        _validate_window(
            observed_at=self.observed_at,
            expires_at=self.expires_at,
            maximum=C1_MANUAL_EVIDENCE_TTL,
        )
        return self


class C1ChatCorrelationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    status: Literal["live_chat_call_correlated"]
    source: Literal["manual_chatgpt_web_and_local_audit"]
    simulated: bool
    test_chat_label: C1TestChatLabel
    observation_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    challenge_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    response_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    audit_correlation: str = Field(pattern=C0_AUDIT_ID_PATTERN)
    audit_record_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    audit_records_verified: int = Field(ge=1)
    local_policy_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    tool_snapshot_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    checked_at: datetime
    expires_at: datetime
    receipt_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_checked_at = field_validator("checked_at")(_require_aware)
    _aware_expires_at = field_validator("expires_at")(_require_aware)

    @model_validator(mode="after")
    def validate_receipt(self) -> "C1ChatCorrelationReceipt":
        _validate_window(
            observed_at=self.checked_at,
            expires_at=self.expires_at,
            maximum=C1_MANUAL_EVIDENCE_TTL,
        )
        return self


class C1ChatProofBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    observation: C1TestChatObservation
    correlation_receipt: C1ChatCorrelationReceipt

    @model_validator(mode="after")
    def validate_bundle(self) -> "C1ChatProofBundle":
        if self.observation.test_chat_label is not self.correlation_receipt.test_chat_label:
            raise ValueError("C1 proof bundle label mismatch")
        if self.correlation_receipt.observation_sha256 != canonical_sha256(
            self.observation.model_dump(mode="json")
        ):
            raise ValueError("C1 proof bundle observation digest mismatch")
        return self


class C1NegativeTestReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    source: Literal["bounded_manual_chatgpt_web"]
    simulated: bool
    outcomes: dict[C1NegativeCheckId, C1NegativeOutcome]
    work_tested: Literal[False]
    capability_expanded: Literal[False]
    existing_chats_accessed: Literal[False]
    private_browser_state_accessed: Literal[False]
    observed_at: datetime
    expires_at: datetime
    receipt_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_observed_at = field_validator("observed_at")(_require_aware)
    _aware_expires_at = field_validator("expires_at")(_require_aware)

    @model_validator(mode="after")
    def validate_negative_tests(self) -> "C1NegativeTestReceipt":
        if set(self.outcomes) != set(C1NegativeCheckId):
            raise ValueError("C1 negative receipt requires all ten checks exactly once")
        post = self.outcomes[C1NegativeCheckId.POST_REVOCATION_CALL]
        if post is not C1NegativeOutcome.UNREACHABLE_AFTER_REVOCATION:
            raise ValueError("post-revocation C1 call must be unreachable")
        for check_id, outcome in self.outcomes.items():
            if check_id is C1NegativeCheckId.POST_REVOCATION_CALL:
                continue
            if outcome is C1NegativeOutcome.UNREACHABLE_AFTER_REVOCATION:
                raise ValueError("only the post-revocation check may use unreachable")
        _validate_window(
            observed_at=self.observed_at,
            expires_at=self.expires_at,
            maximum=C1_MANUAL_EVIDENCE_TTL,
        )
        return self


class C1RevocationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    source: Literal["manual_operator_confirmation"]
    simulated: bool
    draft_plugin_connection_removed: Literal[True]
    runtime_api_key_revoked: Literal[True]
    tunnel_stopped: Literal[True]
    facade_stopped: Literal[True]
    no_c1_listener: Literal[True]
    post_revocation_chat_call_failed: Literal[True]
    verified_at: datetime
    expires_at: datetime
    receipt_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_verified_at = field_validator("verified_at")(_require_aware)
    _aware_expires_at = field_validator("expires_at")(_require_aware)

    @model_validator(mode="after")
    def validate_revocation(self) -> "C1RevocationReceipt":
        _validate_window(
            observed_at=self.verified_at,
            expires_at=self.expires_at,
            maximum=C1_MANUAL_EVIDENCE_TTL,
        )
        return self


class C1FinalAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    status: Literal["COMPLETE_BOUNDED_CHAT_SURFACE_OBSERVABILITY_VERIFIED"]
    source: Literal["bounded_live_c1_verifier"]
    simulated: Literal[False]
    issue_url: Literal["https://github.com/Cheurteenyt/systeme-local/issues/66"]
    c0_dependency_status: C1C0DependencyStatus
    c0_dependency_commit: str = Field(pattern=C0_GIT_COMMIT_PATTERN)
    official_evidence_profile_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    runtime_setup_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    visible_model_observation_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    chat_observation_sha256: tuple[str, str]
    chat_correlation_receipt_sha256: tuple[str, str]
    negative_test_receipt_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    revocation_receipt_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    local_policy_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    tool_snapshot_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    test_chat_count: Literal[2]
    work_tested: Literal[False]
    existing_chats_accessed: Literal[False]
    private_browser_state_accessed: Literal[False]
    verified_at: datetime
    expires_at: datetime
    attestation_sha256: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_verified_at = field_validator("verified_at")(_require_aware)
    _aware_expires_at = field_validator("expires_at")(_require_aware)

    @model_validator(mode="after")
    def validate_attestation(self) -> "C1FinalAttestation":
        _validate_window(
            observed_at=self.verified_at,
            expires_at=self.expires_at,
            maximum=timedelta(hours=1),
        )
        if len(set(self.chat_observation_sha256)) != 2:
            raise ValueError("C1 final attestation requires two distinct chat observations")
        if len(set(self.chat_correlation_receipt_sha256)) != 2:
            raise ValueError("C1 final attestation requires two distinct correlation receipts")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"attestation_sha256"}))
        if self.attestation_sha256 != expected:
            raise ValueError("C1 final attestation digest mismatch")
        return self


def commit_official_source_reference(
    *,
    source_id: str,
    title: str,
    url: str,
    consulted_at: datetime,
    canonical_summary: str,
    revalidate_after: datetime,
) -> C1OfficialSourceReference:
    return C1OfficialSourceReference(
        source_id=source_id,
        title=title,
        url=url,
        consulted_at=consulted_at,
        canonical_summary=canonical_summary,
        summary_sha256=hashlib.sha256(canonical_summary.encode("utf-8")).hexdigest(),
        revalidate_after=revalidate_after,
    )


def build_current_c1_official_evidence_profile() -> C1OfficialEvidenceProfile:
    consulted = datetime(2026, 7, 26, 17, 36, 35, tzinfo=UTC)
    revalidate = datetime(2026, 8, 9, 17, 36, 35, tzinfo=UTC)
    raw = (
        (
            "chat_and_work",
            "Get started with ChatGPT Work",
            "https://learn.chatgpt.com/docs/get-started-with-work",
            "Chat is documented for answers, explanations, brainstorming, and short drafts; "
            "Work is a separately selected surface for tasks with a clear outcome. C1 may "
            "visibly distinguish the selector but tests Chat only.",
        ),
        (
            "chatgpt_and_codex_models",
            "Models",
            "https://learn.chatgpt.com/docs/models",
            "Current clients may visibly present model and reasoning controls. Codex canonical "
            "reasoning labels include low, medium, high, xhigh, max, and ultra; visible ChatGPT "
            "labels remain presentation evidence and do not establish hidden model routing.",
        ),
        (
            "codex_configuration",
            "Config basics",
            "https://learn.chatgpt.com/docs/config-file/config-basic",
            "Codex configuration precedence is CLI overrides, project configuration, profile "
            "configuration, user configuration, system configuration, then built-in defaults. "
            "A config.toml value is a configured default, not active runtime proof.",
        ),
        (
            "plugin_connection",
            "Connect and test your plugin",
            "https://developers.openai.com/plugins/deploy/connect-chatgpt",
            "A developer connects an MCP endpoint or Secure MCP Tunnel, reviews discovered tools, "
            "and selects the reviewed connection in a new ChatGPT conversation. The documented "
            "flow is scoped to the current conversation and does not expose account chat history.",
        ),
        (
            "plugin_authentication",
            "Authentication",
            "https://developers.openai.com/plugins/build/auth",
            "Plugin tools declare per-tool noauth or OAuth security schemes. C1 reuses only the "
            "reviewed draft C0 noauth probe behind independent loopback bearer and tunnel controls.",
        ),
        (
            "secure_mcp_tunnel",
            "Secure MCP Tunnel",
            "https://developers.openai.com/api/docs/guides/secure-mcp-tunnels",
            "The official customer-run tunnel client keeps the local MCP server private through "
            "outbound-only connectivity and uses distinct Tunnel and Runtime API-key permissions.",
        ),
        (
            "gpt_5_6_models",
            "Models",
            "https://developers.openai.com/api/docs/models",
            "The official API catalog identifies gpt-5.6-sol, gpt-5.6-terra, and gpt-5.6-luna as "
            "distinct model IDs. Those API identifiers may describe direct Codex runtime metadata "
            "but must not be inferred from a ChatGPT Web display label.",
        ),
        (
            "browser_boundary",
            "Browser",
            "https://learn.chatgpt.com/docs/browser",
            "The ChatGPT desktop in-app browser is a distinct browser surface. C1 limits control "
            "to visible controls and two new sterile chats and does not inspect cookies, storage, "
            "private requests, unrelated tabs, or existing chat history.",
        ),
    )
    sources = tuple(
        sorted(
            (
                commit_official_source_reference(
                    source_id=source_id,
                    title=title,
                    url=url,
                    consulted_at=consulted,
                    canonical_summary=summary,
                    revalidate_after=revalidate,
                )
                for source_id, title, url, summary in raw
            ),
            key=lambda item: item.source_id,
        )
    )
    payload: dict[str, Any] = {
        "version": "1",
        "profile_id": "chatgpt_web_c1_20260726",
        "sources": [source.model_dump(mode="json") for source in sources],
    }
    return C1OfficialEvidenceProfile(
        version="1",
        profile_id="chatgpt_web_c1_20260726",
        sources=sources,
        profile_sha256=canonical_sha256(payload),
    )


def commit_c1_runtime_setup_observation(
    *,
    settings: dict[C1SetupField, C1SettingObservation],
    configuration_precedence: tuple[C1ConfigurationLayer, ...],
    observed_at: datetime,
    expires_at: datetime,
    audit_key: str,
    simulated: bool = False,
) -> C1RuntimeSetupObservation:
    payload: dict[str, Any] = {
        "version": "1",
        "source": "bounded_local_inventory",
        "simulated": simulated,
        "settings": {
            key.value: value.model_dump(mode="json")
            for key, value in sorted(settings.items(), key=lambda item: item[0].value)
        },
        "configuration_precedence": [item.value for item in configuration_precedence],
        "observed_at": _require_aware(observed_at).isoformat().replace("+00:00", "Z"),
        "expires_at": _require_aware(expires_at).isoformat().replace("+00:00", "Z"),
    }
    return C1RuntimeSetupObservation(
        **payload,
        observation_hmac=_payload_hmac(domain="runtime", payload=payload, audit_key=audit_key),
    )


def verify_c1_runtime_setup_observation(
    observation: C1RuntimeSetupObservation,
    *,
    audit_key: str,
) -> C1RuntimeSetupObservation:
    committed = C1RuntimeSetupObservation.model_validate(observation.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="runtime",
        field_name="observation_hmac",
        audit_key=audit_key,
    )
    return committed


def commit_c1_surface_observation(
    *,
    test_chat_label: C1TestChatLabel,
    surface: C1Surface,
    plugin_selected: bool,
    observed_at: datetime,
    expires_at: datetime,
    audit_key: str,
    simulated: bool = False,
) -> C1SurfaceObservation:
    payload: dict[str, Any] = {
        "version": "1",
        "source": "chatgpt_visible_ui",
        "simulated": simulated,
        "test_chat_label": test_chat_label.value,
        "surface": surface.value,
        "prompt_sent": False,
        "plugin_selected": plugin_selected,
        "work_tested": False,
        "existing_chats_accessed": False,
        "private_browser_state_accessed": False,
        "observed_at": _require_aware(observed_at).isoformat().replace("+00:00", "Z"),
        "expires_at": _require_aware(expires_at).isoformat().replace("+00:00", "Z"),
    }
    return C1SurfaceObservation(
        **payload,
        observation_hmac=_payload_hmac(domain="surface", payload=payload, audit_key=audit_key),
    )


def verify_c1_surface_observation(
    observation: C1SurfaceObservation,
    *,
    audit_key: str,
) -> C1SurfaceObservation:
    committed = C1SurfaceObservation.model_validate(observation.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="surface",
        field_name="observation_hmac",
        audit_key=audit_key,
    )
    return committed


def commit_c1_visible_model_observation(
    *,
    visible_model_label: str | None,
    model_label_state: C1EvidenceState,
    visible_reasoning_label: str | None,
    reasoning_label_state: C1EvidenceState,
    exact_internal_model_id: str | None,
    canonical_reasoning_effort: C1CanonicalReasoningEffort | None,
    reasoning_mapping_source_sha256: str | None,
    observed_at: datetime,
    expires_at: datetime,
    audit_key: str,
    simulated: bool = False,
) -> C1VisibleModelObservation:
    payload: dict[str, Any] = {
        "version": "1",
        "source": "chatgpt_visible_ui",
        "simulated": simulated,
        "visible_model_label": visible_model_label,
        "model_label_state": model_label_state.value,
        "visible_reasoning_label": visible_reasoning_label,
        "reasoning_label_state": reasoning_label_state.value,
        "exact_internal_model_id_exposed": exact_internal_model_id is not None,
        "exact_internal_model_id": exact_internal_model_id,
        "canonical_reasoning_effort": (
            canonical_reasoning_effort.value if canonical_reasoning_effort is not None else None
        ),
        "reasoning_mapping_source_sha256": reasoning_mapping_source_sha256,
        "observed_at": _require_aware(observed_at).isoformat().replace("+00:00", "Z"),
        "expires_at": _require_aware(expires_at).isoformat().replace("+00:00", "Z"),
    }
    return C1VisibleModelObservation(
        **payload,
        observation_hmac=_payload_hmac(
            domain="visible_model",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_c1_visible_model_observation(
    observation: C1VisibleModelObservation,
    *,
    audit_key: str,
) -> C1VisibleModelObservation:
    committed = C1VisibleModelObservation.model_validate(observation.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="visible_model",
        field_name="observation_hmac",
        audit_key=audit_key,
    )
    return committed


def commit_c1_chat_correlation_receipt(
    *,
    observation: C1TestChatObservation,
    audit_records_verified: int,
    checked_at: datetime,
    expires_at: datetime,
    audit_key: str,
) -> C1ChatCorrelationReceipt:
    payload: dict[str, Any] = {
        "version": "1",
        "status": "live_chat_call_correlated",
        "source": "manual_chatgpt_web_and_local_audit",
        "simulated": observation.simulated,
        "test_chat_label": observation.test_chat_label.value,
        "observation_sha256": canonical_sha256(observation.model_dump(mode="json")),
        "challenge_sha256": observation.challenge_sha256,
        "response_sha256": observation.response_sha256,
        "audit_correlation": observation.audit_correlation,
        "audit_record_sha256": observation.audit_record_sha256,
        "audit_records_verified": audit_records_verified,
        "local_policy_sha256": observation.local_policy_sha256,
        "tool_snapshot_sha256": observation.tool_snapshot_sha256,
        "checked_at": _require_aware(checked_at).isoformat().replace("+00:00", "Z"),
        "expires_at": _require_aware(expires_at).isoformat().replace("+00:00", "Z"),
    }
    return C1ChatCorrelationReceipt(
        **payload,
        receipt_hmac=_payload_hmac(
            domain="correlation",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_c1_chat_correlation_receipt(
    receipt: C1ChatCorrelationReceipt,
    *,
    observation: C1TestChatObservation,
    audit_key: str,
) -> C1ChatCorrelationReceipt:
    committed = C1ChatCorrelationReceipt.model_validate(receipt.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="correlation",
        field_name="receipt_hmac",
        audit_key=audit_key,
    )
    if committed.observation_sha256 != canonical_sha256(observation.model_dump(mode="json")):
        raise ValueError("C1 chat observation digest mismatch")
    bindings = (
        (committed.test_chat_label, observation.test_chat_label),
        (committed.challenge_sha256, observation.challenge_sha256),
        (committed.response_sha256, observation.response_sha256),
        (committed.audit_correlation, observation.audit_correlation),
        (committed.audit_record_sha256, observation.audit_record_sha256),
        (committed.local_policy_sha256, observation.local_policy_sha256),
        (committed.tool_snapshot_sha256, observation.tool_snapshot_sha256),
    )
    if any(left != right for left, right in bindings):
        raise ValueError("C1 chat correlation binding mismatch")
    return committed


def commit_c1_negative_test_receipt(
    *,
    outcomes: dict[C1NegativeCheckId, C1NegativeOutcome],
    observed_at: datetime,
    expires_at: datetime,
    audit_key: str,
    simulated: bool = False,
) -> C1NegativeTestReceipt:
    payload: dict[str, Any] = {
        "version": "1",
        "source": "bounded_manual_chatgpt_web",
        "simulated": simulated,
        "outcomes": {
            key.value: value.value
            for key, value in sorted(outcomes.items(), key=lambda item: item[0].value)
        },
        "work_tested": False,
        "capability_expanded": False,
        "existing_chats_accessed": False,
        "private_browser_state_accessed": False,
        "observed_at": _require_aware(observed_at).isoformat().replace("+00:00", "Z"),
        "expires_at": _require_aware(expires_at).isoformat().replace("+00:00", "Z"),
    }
    return C1NegativeTestReceipt(
        **payload,
        receipt_hmac=_payload_hmac(domain="negative", payload=payload, audit_key=audit_key),
    )


def verify_c1_negative_test_receipt(
    receipt: C1NegativeTestReceipt,
    *,
    audit_key: str,
) -> C1NegativeTestReceipt:
    committed = C1NegativeTestReceipt.model_validate(receipt.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="negative",
        field_name="receipt_hmac",
        audit_key=audit_key,
    )
    return committed


def commit_c1_revocation_receipt(
    *,
    verified_at: datetime,
    expires_at: datetime,
    audit_key: str,
    simulated: bool = False,
) -> C1RevocationReceipt:
    payload: dict[str, Any] = {
        "version": "1",
        "source": "manual_operator_confirmation",
        "simulated": simulated,
        "draft_plugin_connection_removed": True,
        "runtime_api_key_revoked": True,
        "tunnel_stopped": True,
        "facade_stopped": True,
        "no_c1_listener": True,
        "post_revocation_chat_call_failed": True,
        "verified_at": _require_aware(verified_at).isoformat().replace("+00:00", "Z"),
        "expires_at": _require_aware(expires_at).isoformat().replace("+00:00", "Z"),
    }
    return C1RevocationReceipt(
        **payload,
        receipt_hmac=_payload_hmac(domain="revocation", payload=payload, audit_key=audit_key),
    )


def verify_c1_revocation_receipt(
    receipt: C1RevocationReceipt,
    *,
    audit_key: str,
) -> C1RevocationReceipt:
    committed = C1RevocationReceipt.model_validate(receipt.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="revocation",
        field_name="receipt_hmac",
        audit_key=audit_key,
    )
    return committed


def commit_c1_final_attestation(
    *,
    c0_dependency_status: C1C0DependencyStatus,
    c0_dependency_commit: str,
    official_profile: C1OfficialEvidenceProfile,
    runtime_setup: C1RuntimeSetupObservation,
    visible_model: C1VisibleModelObservation,
    surface_observations: tuple[C1SurfaceObservation, C1SurfaceObservation],
    chat_observations: tuple[C1TestChatObservation, C1TestChatObservation],
    correlation_receipts: tuple[C1ChatCorrelationReceipt, C1ChatCorrelationReceipt],
    negative_receipt: C1NegativeTestReceipt,
    revocation_receipt: C1RevocationReceipt,
    audit_key: str,
    verified_at: datetime,
    expires_at: datetime,
) -> C1FinalAttestation:
    now = _require_aware(verified_at)
    profile = C1OfficialEvidenceProfile.model_validate(official_profile.model_dump(mode="python"))
    if any(source.revalidate_after < now for source in profile.sources):
        raise ValueError("C1 official evidence profile is stale")

    setup = verify_c1_runtime_setup_observation(runtime_setup, audit_key=audit_key)
    visible = verify_c1_visible_model_observation(visible_model, audit_key=audit_key)
    surfaces = tuple(
        verify_c1_surface_observation(item, audit_key=audit_key) for item in surface_observations
    )
    chats = tuple(
        C1TestChatObservation.model_validate(item.model_dump(mode="python"))
        for item in chat_observations
    )
    correlations = tuple(
        verify_c1_chat_correlation_receipt(
            receipt,
            observation=observation,
            audit_key=audit_key,
        )
        for receipt, observation in zip(correlation_receipts, chats, strict=True)
    )
    negative = verify_c1_negative_test_receipt(negative_receipt, audit_key=audit_key)
    revocation = verify_c1_revocation_receipt(revocation_receipt, audit_key=audit_key)

    live_items: tuple[BaseModel, ...] = (
        setup,
        visible,
        *surfaces,
        *chats,
        *correlations,
        negative,
        revocation,
    )
    if any(bool(getattr(item, "simulated", False)) for item in live_items):
        raise ValueError("simulated C1 evidence cannot create a live attestation")
    if setup.settings[C1SetupField.ACTIVE_RUNTIME_MODEL].state is not C1EvidenceState.OBSERVED:
        raise ValueError("C1 final attestation requires direct active runtime model evidence")
    if setup.settings[C1SetupField.ACTIVE_REASONING_EFFORT].state is not C1EvidenceState.OBSERVED:
        raise ValueError("C1 final attestation requires direct reasoning-effort evidence")

    expected_labels = tuple(C1TestChatLabel(item) for item in C1_TEST_CHAT_LABELS)
    surface_labels = tuple(item.test_chat_label for item in surfaces)
    chat_labels = tuple(item.test_chat_label for item in chats)
    correlation_labels = tuple(item.test_chat_label for item in correlations)
    if (
        surface_labels != expected_labels
        or chat_labels != expected_labels
        or correlation_labels != expected_labels
    ):
        raise ValueError("C1 final attestation requires ordered Chat A and Chat B evidence")
    if any(item.surface is not C1Surface.CHAT for item in surfaces):
        raise ValueError("C1 final attestation refuses non-Chat surface evidence")
    if any(not item.plugin_selected for item in surfaces):
        raise ValueError("C1 final attestation requires the reviewed Plugin in both Chat tests")

    if len({item.challenge_sha256 for item in chats}) != 2:
        raise ValueError("C1 final attestation requires distinct challenges")
    if len({item.audit_correlation for item in chats}) != 2:
        raise ValueError("C1 final attestation requires distinct audit correlations")
    if len({item.audit_record_sha256 for item in chats}) != 2:
        raise ValueError("C1 final attestation requires distinct audit records")
    if len({item.response_sha256 for item in chats}) != 2:
        raise ValueError("C1 final attestation requires distinct structured responses")
    if len({item.local_policy_sha256 for item in chats}) != 1:
        raise ValueError("C1 Chat observations disagree on local policy")
    if len({item.tool_snapshot_sha256 for item in chats}) != 1:
        raise ValueError("C1 Chat observations disagree on tool snapshot")
    if tuple(canonical_sha256(surface.model_dump(mode="json")) for surface in surfaces) != tuple(
        item.surface_observation_sha256 for item in chats
    ):
        raise ValueError("C1 Chat observations do not bind their surface observations")

    all_expiries = [
        setup.expires_at,
        visible.expires_at,
        *(item.expires_at for item in surfaces),
        *(item.expires_at for item in chats),
        *(item.expires_at for item in correlations),
        negative.expires_at,
        revocation.expires_at,
    ]
    final_expiry = _require_aware(expires_at)
    if any(expiry <= now for expiry in all_expiries):
        raise ValueError("expired C1 evidence cannot create a final attestation")
    if final_expiry > min(all_expiries):
        raise ValueError("C1 final attestation outlives its evidence")

    payload: dict[str, Any] = {
        "version": "1",
        "status": C1_FINAL_STATUS,
        "source": "bounded_live_c1_verifier",
        "simulated": False,
        "issue_url": "https://github.com/Cheurteenyt/systeme-local/issues/66",
        "c0_dependency_status": c0_dependency_status.value,
        "c0_dependency_commit": c0_dependency_commit,
        "official_evidence_profile_sha256": profile.profile_sha256,
        "runtime_setup_sha256": canonical_sha256(setup.model_dump(mode="json")),
        "visible_model_observation_sha256": canonical_sha256(visible.model_dump(mode="json")),
        "chat_observation_sha256": [
            canonical_sha256(item.model_dump(mode="json")) for item in chats
        ],
        "chat_correlation_receipt_sha256": [
            canonical_sha256(item.model_dump(mode="json")) for item in correlations
        ],
        "negative_test_receipt_sha256": canonical_sha256(negative.model_dump(mode="json")),
        "revocation_receipt_sha256": canonical_sha256(revocation.model_dump(mode="json")),
        "local_policy_sha256": chats[0].local_policy_sha256,
        "tool_snapshot_sha256": chats[0].tool_snapshot_sha256,
        "test_chat_count": 2,
        "work_tested": False,
        "existing_chats_accessed": False,
        "private_browser_state_accessed": False,
        "verified_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": final_expiry.isoformat().replace("+00:00", "Z"),
    }
    return C1FinalAttestation(
        **payload,
        attestation_sha256=canonical_sha256(payload),
    )
