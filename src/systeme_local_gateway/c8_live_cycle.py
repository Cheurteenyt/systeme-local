from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .c0_probe import (
    C0_AUDIT_ID_PATTERN,
    C0_GIT_COMMIT_PATTERN,
    C0_SHA256_PATTERN,
)
from .c7_work_admission import (
    C7_MAX_WORK_OBSERVATION_AGE_SECONDS,
    C7_POLICY_PATH,
    C7_PROFILE_PATH,
    C7ProtectedAction,
    C7WorkPrelivePolicy,
    C8LiveCycleGrant,
    ChatGptWorkCapabilityProfile,
    canonical_json,
    canonical_sha256,
    current_work_identity,
    evaluate_c7_prelive,
    load_policy,
    load_profile,
)
from .c8_governance import verify_committed_c8_governance

C8_ACCEPTED_C7_MAIN = "e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"
C8_EXPECTED_BRANCH = "codex/chatgpt-work-live-c8"
C8_ISSUE_URL = "https://github.com/Cheurteenyt/systeme-local/issues/78"
C8_MAX_AUTHORIZATION_SECONDS = 86_400
C8_OBSERVATION_TTL = timedelta(seconds=C7_MAX_WORK_OBSERVATION_AGE_SECONDS)
C8_WORK_LABELS = ("c8-test-work-a", "c8-test-work-b")
C8_FINAL_STATUS = "COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"

_CYCLE_ID_PATTERN = r"^c8_cycle_[0-9a-f]{32}$"
_GRANT_ID_PATTERN = r"^c8_[0-9a-f]{32}$"
_DOMAIN = {
    "authorization": b"systeme-local/c8/operator-authorization/v1\0",
    "surface": b"systeme-local/c8/work-surface/v1\0",
    "quota": b"systeme-local/c8/work-quota/v1\0",
    "task_surface": b"systeme-local/c8/work-task-surface/v1\0",
    "correlation": b"systeme-local/c8/work-correlation/v1\0",
    "negative": b"systeme-local/c8/negative-tests/v1\0",
    "revocation": b"systeme-local/c8/revocation/v1\0",
}
_SECRET_PATTERNS = (
    r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}",
    r"(?i)\bsk-[A-Za-z0-9_-]{20,}",
    r"(?i)\btunnel_[0-9a-f]{32}\b",
    r"(?i)\b(?:cookie|authorization)\s*[:=]\s*\S+",
)


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C8 timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _parse_timestamp(value: str | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return _require_utc(datetime.fromisoformat(normalized))


def _timestamp(value: datetime) -> str:
    return _require_utc(value).isoformat().replace("+00:00", "Z")


def _require_audit_key(audit_key: str | bytes) -> bytes:
    encoded = audit_key.encode("utf-8") if isinstance(audit_key, str) else audit_key
    if len(encoded) < 32:
        raise ValueError("C8 evidence requires an audit key of at least 32 bytes")
    return encoded


def _commit_hmac(*, domain: str, payload: dict[str, Any], audit_key: str | bytes) -> str:
    return hmac.new(
        _require_audit_key(audit_key),
        _DOMAIN[domain] + canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


def _verify_hmac(
    model: BaseModel,
    *,
    domain: str,
    field_name: str,
    audit_key: str | bytes,
) -> None:
    payload = model.model_dump(mode="json", exclude={field_name})
    expected = _commit_hmac(domain=domain, payload=payload, audit_key=audit_key)
    if not hmac.compare_digest(str(getattr(model, field_name)), expected):
        raise ValueError(f"C8 {domain} evidence HMAC mismatch")


def _assert_secret_free(value: Any) -> None:
    import re

    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if any(re.search(pattern, text) is not None for pattern in _SECRET_PATTERNS):
        raise ValueError("C8 evidence contains a credential-shaped value")


def _validate_window(
    *,
    observed_at: datetime,
    expires_at: datetime,
    maximum: timedelta,
) -> None:
    if expires_at <= observed_at:
        raise ValueError("C8 evidence expiry must follow observation")
    if expires_at - observed_at > maximum:
        raise ValueError("C8 evidence window exceeds its maximum")


def _scope_payload() -> dict[str, Any]:
    return {
        "work_and_plugins_only": True,
        "max_new_synthetic_work_tasks": 2,
        "temporary_tunnel_and_plugin_connection_allowed": True,
        "runtime_key_operator_managed": True,
        "native_chat_allowed": False,
        "automatic_chat_to_work_switch_allowed": False,
        "history_allowed": False,
        "existing_conversations_allowed": False,
        "account_or_security_settings_allowed": False,
        "private_browser_state_allowed": False,
        "write_actions_allowed": False,
        "local_files_allowed": False,
        "command_execution_allowed": False,
        "raw_secrets_allowed": False,
        "real_evidence_access_allowed": False,
        "protocol_v2_allowed": False,
    }


C8_AUTHORIZATION_SCOPE_SHA256 = canonical_sha256(_scope_payload())


class C8FinalStatus(StrEnum):
    COMPLETE = C8_FINAL_STATUS
    C7_CLOSEOUT = "BLOCKED_BY_C7_CLOSEOUT"
    OPERATOR_AUTHORIZATION = "BLOCKED_BY_OPERATOR_AUTHORIZATION"
    WORK_ENTITLEMENT = "BLOCKED_BY_WORK_ENTITLEMENT"
    WORK_QUOTA = "BLOCKED_BY_WORK_QUOTA"
    WORK_SURFACE_AMBIGUITY = "BLOCKED_BY_WORK_SURFACE_AMBIGUITY"
    OFFICIAL_WORK_EVIDENCE = "BLOCKED_BY_OFFICIAL_WORK_EVIDENCE"
    TUNNEL_OR_PLUGIN_SETUP = "BLOCKED_BY_TUNNEL_OR_PLUGIN_SETUP"
    SECURITY_INVARIANT = "BLOCKED_BY_SECURITY_INVARIANT"
    LIVE_CORRELATION = "BLOCKED_BY_LIVE_CORRELATION"
    REVOCATION = "BLOCKED_BY_REVOCATION"
    TEST_FAILURE = "BLOCKED_BY_TEST_FAILURE"


class C8TestWorkLabel(StrEnum):
    WORK_A = "c8-test-work-a"
    WORK_B = "c8-test-work-b"


class C8NegativeCheckId(StrEnum):
    SAME_WORK_REPLAY = "same_work_replay"
    CROSS_WORK_REPLAY = "cross_work_replay"
    UNKNOWN_FIELD = "unknown_field"
    MALFORMED_CHALLENGE = "malformed_challenge"
    LOCAL_FILE_REQUEST = "local_file_request"
    COMMAND_EXECUTION_REQUEST = "command_execution_request"
    SECRET_REQUEST = "secret_request"
    REAL_EVIDENCE_REQUEST = "real_evidence_request"
    WRITE_OPERATION_REQUEST = "write_operation_request"
    PROTOCOL_V2_REQUEST = "protocol_v2_request"
    POST_REVOCATION_CALL = "post_revocation_call"


class C8NegativeOutcome(StrEnum):
    REJECTED = "rejected"
    CAPABILITY_NOT_EXPOSED = "capability_not_exposed"
    NOT_SAFELY_EXPOSED = "not_safely_exposed"
    UNREACHABLE_AFTER_REVOCATION = "unreachable_after_revocation"


class C8OperatorAuthorizationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    cycle_id: str = Field(pattern=_CYCLE_ID_PATTERN)
    source: Literal["explicit_operator_authorization"]
    simulated: Literal[False]
    operator_authorized: Literal[True]
    explicit_work_request: Literal[True]
    work_and_plugins_only: Literal[True]
    max_new_synthetic_work_tasks: Literal[2]
    temporary_tunnel_and_plugin_connection_allowed: Literal[True]
    runtime_key_operator_managed: Literal[True]
    native_chat_allowed: Literal[False]
    automatic_chat_to_work_switch_allowed: Literal[False]
    history_allowed: Literal[False]
    existing_conversations_allowed: Literal[False]
    account_or_security_settings_allowed: Literal[False]
    private_browser_state_allowed: Literal[False]
    write_actions_allowed: Literal[False]
    local_files_allowed: Literal[False]
    command_execution_allowed: Literal[False]
    raw_secrets_allowed: Literal[False]
    real_evidence_access_allowed: Literal[False]
    protocol_v2_allowed: Literal[False]
    authorization_scope_sha256: Literal[
        "266cb7910c6f3506cf664cd82dbc4d8f54649fa03b6e5b1ba8a62ca04c73fcc3"
    ]
    authorized_at: datetime
    expires_at: datetime
    authorization_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _authorized_utc = field_validator("authorized_at")(_require_utc)
    _expires_utc = field_validator("expires_at")(_require_utc)

    @model_validator(mode="after")
    def validate_authorization(self) -> C8OperatorAuthorizationReceipt:
        _validate_window(
            observed_at=self.authorized_at,
            expires_at=self.expires_at,
            maximum=timedelta(seconds=C8_MAX_AUTHORIZATION_SECONDS),
        )
        _assert_secret_free(self.model_dump(mode="json"))
        return self


class C8WorkSurfaceObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    cycle_id: str = Field(pattern=_CYCLE_ID_PATTERN)
    source: Literal["chatgpt_visible_ui"]
    simulated: Literal[False]
    visible_surface: Literal["work"]
    explicit_work_selected: Literal[True]
    automatic_chat_to_work_switch_used: Literal[False]
    plugin_surface_visible: Literal[True]
    work_entitlement_state: Literal["available"]
    prompt_sent: Literal[False]
    existing_conversations_accessed: Literal[False]
    history_accessed: Literal[False]
    account_or_security_settings_accessed: Literal[False]
    private_browser_state_accessed: Literal[False]
    visible_model_label: str | None = Field(default=None, max_length=128)
    visible_reasoning_label: str | None = Field(default=None, max_length=128)
    exact_internal_model_id_exposed: Literal[False]
    exact_internal_model_id: None = None
    observed_at: datetime
    expires_at: datetime
    observation_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _observed_utc = field_validator("observed_at")(_require_utc)
    _expires_utc = field_validator("expires_at")(_require_utc)

    @model_validator(mode="after")
    def validate_observation(self) -> C8WorkSurfaceObservation:
        _validate_window(
            observed_at=self.observed_at,
            expires_at=self.expires_at,
            maximum=C8_OBSERVATION_TTL,
        )
        _assert_secret_free(self.model_dump(mode="json"))
        return self


class C8WorkQuotaObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    cycle_id: str = Field(pattern=_CYCLE_ID_PATTERN)
    source: Literal["chatgpt_visible_ui"]
    simulated: Literal[False]
    visible_surface: Literal["work"]
    work_quota_state: Literal["usable"]
    quota_numeric_value_collected: Literal[False]
    prompt_sent: Literal[False]
    existing_conversations_accessed: Literal[False]
    history_accessed: Literal[False]
    private_browser_state_accessed: Literal[False]
    observed_at: datetime
    expires_at: datetime
    observation_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _observed_utc = field_validator("observed_at")(_require_utc)
    _expires_utc = field_validator("expires_at")(_require_utc)

    @model_validator(mode="after")
    def validate_observation(self) -> C8WorkQuotaObservation:
        _validate_window(
            observed_at=self.observed_at,
            expires_at=self.expires_at,
            maximum=C8_OBSERVATION_TTL,
        )
        _assert_secret_free(self.model_dump(mode="json"))
        return self


class C8WorkTaskSurfaceObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    cycle_id: str = Field(pattern=_CYCLE_ID_PATTERN)
    grant_id: str = Field(pattern=_GRANT_ID_PATTERN)
    test_work_label: C8TestWorkLabel
    source: Literal["chatgpt_visible_ui"]
    simulated: Literal[False]
    visible_surface: Literal["work"]
    explicit_work_selected: Literal[True]
    automatic_chat_to_work_switch_used: Literal[False]
    new_synthetic_work_task: Literal[True]
    plugin_selected: Literal[True]
    prompt_sent: Literal[False]
    existing_conversations_accessed: Literal[False]
    history_accessed: Literal[False]
    account_or_security_settings_accessed: Literal[False]
    private_browser_state_accessed: Literal[False]
    observed_at: datetime
    expires_at: datetime
    observation_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _observed_utc = field_validator("observed_at")(_require_utc)
    _expires_utc = field_validator("expires_at")(_require_utc)

    @model_validator(mode="after")
    def validate_observation(self) -> C8WorkTaskSurfaceObservation:
        _validate_window(
            observed_at=self.observed_at,
            expires_at=self.expires_at,
            maximum=timedelta(minutes=30),
        )
        _assert_secret_free(self.model_dump(mode="json"))
        return self


class C8LiveCycleBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    authorization: C8OperatorAuthorizationReceipt
    surface_observation: C8WorkSurfaceObservation
    quota_observation: C8WorkQuotaObservation
    grant: C8LiveCycleGrant

    @model_validator(mode="after")
    def validate_bindings(self) -> C8LiveCycleBundle:
        cycle_ids = {
            self.authorization.cycle_id,
            self.surface_observation.cycle_id,
            self.quota_observation.cycle_id,
        }
        if len(cycle_ids) != 1:
            raise ValueError("C8 live-cycle evidence belongs to different cycles")
        surface_sha256 = canonical_sha256(self.surface_observation.model_dump(mode="json"))
        quota_sha256 = canonical_sha256(self.quota_observation.model_dump(mode="json"))
        if self.grant.surface_observation_sha256 != surface_sha256:
            raise ValueError("C8 grant does not bind the Work surface observation")
        if self.grant.quota_observation_sha256 != quota_sha256:
            raise ValueError("C8 grant does not bind the Work quota observation")
        if self.grant.visible_model_observation_sha256 != surface_sha256:
            raise ValueError("C8 visible labels must remain bound to the surface observation")
        return self


class C8AdmissionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    evaluated_at: datetime
    status: C8FinalStatus
    live_actions_allowed: bool
    effective_tool_count: int = Field(ge=0, le=1)
    cycle_id: str | None = Field(default=None, pattern=_CYCLE_ID_PATTERN)
    grant_id: str | None = Field(default=None, pattern=_GRANT_ID_PATTERN)
    authorization_verified: bool
    surface_verified: bool
    quota_verified: bool
    c7_grant_verified: bool
    native_chat_gate_status: Literal["BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"]
    automatic_chat_to_work_switch_allowed: Literal[False]
    reason: str = Field(min_length=1, max_length=256)
    decision_sha256: str = Field(pattern=C0_SHA256_PATTERN)

    _evaluated_utc = field_validator("evaluated_at")(_require_utc)

    @model_validator(mode="after")
    def validate_decision(self) -> C8AdmissionDecision:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"decision_sha256"}))
        if self.decision_sha256 != expected:
            raise ValueError("C8 admission decision digest mismatch")
        if self.live_actions_allowed != (
            self.authorization_verified
            and self.surface_verified
            and self.quota_verified
            and self.c7_grant_verified
            and self.effective_tool_count == 1
        ):
            raise ValueError("C8 admission summary is internally inconsistent")
        return self


class C8WorkCallObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    source: Literal["manual_chatgpt_work"]
    simulated: Literal[False]
    cycle_id: str = Field(pattern=_CYCLE_ID_PATTERN)
    grant_id: str = Field(pattern=_GRANT_ID_PATTERN)
    test_work_label: C8TestWorkLabel
    task_surface_observation_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    visible_surface: Literal["work"]
    explicit_work_selected: Literal[True]
    plugin_selected: Literal[True]
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
    chat_invoked: Literal[False]
    automatic_chat_to_work_switch_used: Literal[False]
    existing_conversations_accessed: Literal[False]
    conversation_identifier_collected: Literal[False]
    private_browser_state_accessed: Literal[False]
    account_or_security_settings_accessed: Literal[False]
    observed_at: datetime

    _observed_utc = field_validator("observed_at")(_require_utc)


class C8WorkCorrelationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    status: Literal["live_work_call_correlated"]
    source: Literal["manual_chatgpt_work_and_local_audit"]
    simulated: Literal[False]
    cycle_id: str = Field(pattern=_CYCLE_ID_PATTERN)
    grant_id: str = Field(pattern=_GRANT_ID_PATTERN)
    test_work_label: C8TestWorkLabel
    observation_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    challenge_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    response_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    audit_correlation: str = Field(pattern=C0_AUDIT_ID_PATTERN)
    audit_record_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    audit_records_verified: int = Field(ge=1)
    checked_at: datetime
    receipt_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _checked_utc = field_validator("checked_at")(_require_utc)


class C8WorkProofBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    task_surface_observation: C8WorkTaskSurfaceObservation
    observation: C8WorkCallObservation
    correlation_receipt: C8WorkCorrelationReceipt

    @model_validator(mode="after")
    def validate_bundle(self) -> C8WorkProofBundle:
        receipt = self.correlation_receipt
        observation = self.observation
        surface = self.task_surface_observation
        if (
            surface.cycle_id != observation.cycle_id
            or surface.grant_id != observation.grant_id
            or surface.test_work_label is not observation.test_work_label
        ):
            raise ValueError("C8 Work task surface binding mismatch")
        if observation.task_surface_observation_sha256 != canonical_sha256(
            surface.model_dump(mode="json")
        ):
            raise ValueError("C8 Work call does not bind its task surface observation")
        if receipt.observation_sha256 != canonical_sha256(observation.model_dump(mode="json")):
            raise ValueError("C8 Work proof observation digest mismatch")
        bindings = (
            (receipt.cycle_id, observation.cycle_id),
            (receipt.grant_id, observation.grant_id),
            (receipt.test_work_label, observation.test_work_label),
            (receipt.challenge_sha256, observation.challenge_sha256),
            (receipt.response_sha256, observation.response_sha256),
            (receipt.audit_correlation, observation.audit_correlation),
            (receipt.audit_record_sha256, observation.audit_record_sha256),
        )
        if any(left != right for left, right in bindings):
            raise ValueError("C8 Work proof binding mismatch")
        return self


class C8NegativeTestReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    source: Literal["bounded_work_and_local_negative_tests"]
    simulated: Literal[False]
    cycle_id: str = Field(pattern=_CYCLE_ID_PATTERN)
    grant_id: str = Field(pattern=_GRANT_ID_PATTERN)
    outcomes: dict[C8NegativeCheckId, C8NegativeOutcome]
    capability_expanded: Literal[False]
    native_chat_tested: Literal[False]
    existing_conversations_accessed: Literal[False]
    private_browser_state_accessed: Literal[False]
    observed_at: datetime
    receipt_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _observed_utc = field_validator("observed_at")(_require_utc)

    @model_validator(mode="after")
    def validate_outcomes(self) -> C8NegativeTestReceipt:
        if set(self.outcomes) != set(C8NegativeCheckId):
            raise ValueError("C8 negative receipt requires every check exactly once")
        required_rejected = {
            C8NegativeCheckId.SAME_WORK_REPLAY,
            C8NegativeCheckId.CROSS_WORK_REPLAY,
            C8NegativeCheckId.UNKNOWN_FIELD,
            C8NegativeCheckId.MALFORMED_CHALLENGE,
        }
        if any(
            self.outcomes[check] is not C8NegativeOutcome.REJECTED for check in required_rejected
        ):
            raise ValueError("C8 protocol/replay negative tests must be rejected")
        if (
            self.outcomes[C8NegativeCheckId.POST_REVOCATION_CALL]
            is not C8NegativeOutcome.UNREACHABLE_AFTER_REVOCATION
        ):
            raise ValueError("C8 post-revocation call must be unreachable")
        for check, outcome in self.outcomes.items():
            if (
                check is not C8NegativeCheckId.POST_REVOCATION_CALL
                and outcome is C8NegativeOutcome.UNREACHABLE_AFTER_REVOCATION
            ):
                raise ValueError("only the post-revocation check may be unreachable")
        return self


class C8RevocationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    source: Literal["manual_operator_and_local_verification"]
    simulated: Literal[False]
    cycle_id: str = Field(pattern=_CYCLE_ID_PATTERN)
    grant_id: str = Field(pattern=_GRANT_ID_PATTERN)
    operator_authorization_revoked: Literal[True]
    plugin_connection_removed: Literal[True]
    runtime_api_key_revoked: Literal[True]
    tunnel_stopped: Literal[True]
    facade_stopped: Literal[True]
    no_c8_listener: Literal[True]
    process_secrets_cleared: Literal[True]
    post_revocation_work_call_failed: Literal[True]
    verified_at: datetime
    receipt_hmac: str = Field(pattern=C0_SHA256_PATTERN)

    _verified_utc = field_validator("verified_at")(_require_utc)


class C8FinalAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    status: Literal["COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"]
    source: Literal["bounded_live_c8_verifier"]
    simulated: Literal[False]
    issue_url: Literal["https://github.com/Cheurteenyt/systeme-local/issues/78"]
    accepted_c7_commit: Literal["e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"]
    native_chat_gate_status: Literal["BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"]
    cycle_id: str = Field(pattern=_CYCLE_ID_PATTERN)
    grant_id: str = Field(pattern=_GRANT_ID_PATTERN)
    authorization_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    surface_observation_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    quota_observation_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    grant_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    work_observation_sha256: tuple[str, str]
    correlation_receipt_sha256: tuple[str, str]
    negative_test_receipt_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    revocation_receipt_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    local_policy_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    tool_snapshot_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    work_call_count: Literal[2]
    native_chat_tested: Literal[False]
    existing_conversations_accessed: Literal[False]
    private_browser_state_accessed: Literal[False]
    exact_internal_model_id_claimed: Literal[False]
    regular_use_readiness_claimed: Literal[False]
    revocation_verified: Literal[True]
    verified_at: datetime
    attestation_sha256: str = Field(pattern=C0_SHA256_PATTERN)

    _verified_utc = field_validator("verified_at")(_require_utc)

    @model_validator(mode="after")
    def validate_attestation(self) -> C8FinalAttestation:
        if len(set(self.work_observation_sha256)) != 2:
            raise ValueError("C8 final attestation requires two distinct Work observations")
        if len(set(self.correlation_receipt_sha256)) != 2:
            raise ValueError("C8 final attestation requires two distinct correlation receipts")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"attestation_sha256"}))
        if self.attestation_sha256 != expected:
            raise ValueError("C8 final attestation digest mismatch")
        return self


def commit_operator_authorization(
    *,
    cycle_id: str,
    authorized_at: datetime,
    expires_at: datetime,
    audit_key: str | bytes,
) -> C8OperatorAuthorizationReceipt:
    payload: dict[str, Any] = {
        "version": "1",
        "cycle_id": cycle_id,
        "source": "explicit_operator_authorization",
        "simulated": False,
        "operator_authorized": True,
        "explicit_work_request": True,
        **_scope_payload(),
        "authorization_scope_sha256": C8_AUTHORIZATION_SCOPE_SHA256,
        "authorized_at": _timestamp(authorized_at),
        "expires_at": _timestamp(expires_at),
    }
    return C8OperatorAuthorizationReceipt(
        **payload,
        authorization_hmac=_commit_hmac(
            domain="authorization",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_operator_authorization(
    receipt: C8OperatorAuthorizationReceipt,
    *,
    audit_key: str | bytes,
    evaluated_at: datetime,
) -> C8OperatorAuthorizationReceipt:
    committed = C8OperatorAuthorizationReceipt.model_validate(receipt.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="authorization",
        field_name="authorization_hmac",
        audit_key=audit_key,
    )
    at = _require_utc(evaluated_at)
    if not committed.authorized_at <= at < committed.expires_at:
        raise ValueError("C8 operator authorization is not active")
    return committed


def commit_work_surface_observation(
    *,
    cycle_id: str,
    observed_at: datetime,
    expires_at: datetime,
    audit_key: str | bytes,
    visible_model_label: str | None = None,
    visible_reasoning_label: str | None = None,
) -> C8WorkSurfaceObservation:
    payload: dict[str, Any] = {
        "version": "1",
        "cycle_id": cycle_id,
        "source": "chatgpt_visible_ui",
        "simulated": False,
        "visible_surface": "work",
        "explicit_work_selected": True,
        "automatic_chat_to_work_switch_used": False,
        "plugin_surface_visible": True,
        "work_entitlement_state": "available",
        "prompt_sent": False,
        "existing_conversations_accessed": False,
        "history_accessed": False,
        "account_or_security_settings_accessed": False,
        "private_browser_state_accessed": False,
        "visible_model_label": visible_model_label,
        "visible_reasoning_label": visible_reasoning_label,
        "exact_internal_model_id_exposed": False,
        "exact_internal_model_id": None,
        "observed_at": _timestamp(observed_at),
        "expires_at": _timestamp(expires_at),
    }
    return C8WorkSurfaceObservation(
        **payload,
        observation_hmac=_commit_hmac(
            domain="surface",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_work_surface_observation(
    observation: C8WorkSurfaceObservation,
    *,
    audit_key: str | bytes,
    evaluated_at: datetime,
) -> C8WorkSurfaceObservation:
    committed = C8WorkSurfaceObservation.model_validate(observation.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="surface",
        field_name="observation_hmac",
        audit_key=audit_key,
    )
    at = _require_utc(evaluated_at)
    if not committed.observed_at <= at < committed.expires_at:
        raise ValueError("C8 Work surface observation is not fresh")
    return committed


def commit_work_quota_observation(
    *,
    cycle_id: str,
    observed_at: datetime,
    expires_at: datetime,
    audit_key: str | bytes,
) -> C8WorkQuotaObservation:
    payload: dict[str, Any] = {
        "version": "1",
        "cycle_id": cycle_id,
        "source": "chatgpt_visible_ui",
        "simulated": False,
        "visible_surface": "work",
        "work_quota_state": "usable",
        "quota_numeric_value_collected": False,
        "prompt_sent": False,
        "existing_conversations_accessed": False,
        "history_accessed": False,
        "private_browser_state_accessed": False,
        "observed_at": _timestamp(observed_at),
        "expires_at": _timestamp(expires_at),
    }
    return C8WorkQuotaObservation(
        **payload,
        observation_hmac=_commit_hmac(
            domain="quota",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_work_quota_observation(
    observation: C8WorkQuotaObservation,
    *,
    audit_key: str | bytes,
    evaluated_at: datetime,
) -> C8WorkQuotaObservation:
    committed = C8WorkQuotaObservation.model_validate(observation.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="quota",
        field_name="observation_hmac",
        audit_key=audit_key,
    )
    at = _require_utc(evaluated_at)
    if not committed.observed_at <= at < committed.expires_at:
        raise ValueError("C8 Work quota observation is not fresh")
    return committed


def commit_work_task_surface_observation(
    *,
    cycle_id: str,
    grant_id: str,
    test_work_label: C8TestWorkLabel,
    observed_at: datetime,
    expires_at: datetime,
    audit_key: str | bytes,
) -> C8WorkTaskSurfaceObservation:
    payload: dict[str, Any] = {
        "version": "1",
        "cycle_id": cycle_id,
        "grant_id": grant_id,
        "test_work_label": test_work_label.value,
        "source": "chatgpt_visible_ui",
        "simulated": False,
        "visible_surface": "work",
        "explicit_work_selected": True,
        "automatic_chat_to_work_switch_used": False,
        "new_synthetic_work_task": True,
        "plugin_selected": True,
        "prompt_sent": False,
        "existing_conversations_accessed": False,
        "history_accessed": False,
        "account_or_security_settings_accessed": False,
        "private_browser_state_accessed": False,
        "observed_at": _timestamp(observed_at),
        "expires_at": _timestamp(expires_at),
    }
    return C8WorkTaskSurfaceObservation(
        **payload,
        observation_hmac=_commit_hmac(
            domain="task_surface",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_work_task_surface_observation(
    observation: C8WorkTaskSurfaceObservation,
    *,
    audit_key: str | bytes,
) -> C8WorkTaskSurfaceObservation:
    committed = C8WorkTaskSurfaceObservation.model_validate(observation.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="task_surface",
        field_name="observation_hmac",
        audit_key=audit_key,
    )
    return committed


def issue_live_cycle_bundle(
    *,
    authorization: C8OperatorAuthorizationReceipt,
    surface_observation: C8WorkSurfaceObservation,
    quota_observation: C8WorkQuotaObservation,
    profile: ChatGptWorkCapabilityProfile,
    policy: C7WorkPrelivePolicy,
    grant_id: str,
    issued_at: datetime,
    expires_at: datetime,
    audit_key: str | bytes,
) -> C8LiveCycleBundle:
    at = _require_utc(issued_at)
    auth = verify_operator_authorization(
        authorization,
        audit_key=audit_key,
        evaluated_at=at,
    )
    surface = verify_work_surface_observation(
        surface_observation,
        audit_key=audit_key,
        evaluated_at=at,
    )
    quota = verify_work_quota_observation(
        quota_observation,
        audit_key=audit_key,
        evaluated_at=at,
    )
    if {auth.cycle_id, surface.cycle_id, quota.cycle_id} != {auth.cycle_id}:
        raise ValueError("C8 authorization and UI observations belong to different cycles")
    if _require_utc(expires_at) > auth.expires_at:
        raise ValueError("C8 grant cannot outlive operator authorization")

    surface_sha256 = canonical_sha256(surface.model_dump(mode="json"))
    quota_sha256 = canonical_sha256(quota.model_dump(mode="json"))
    payload: dict[str, Any] = {
        "version": "1",
        "grant_id": grant_id,
        "identity": current_work_identity().model_dump(mode="json"),
        "policy_sha256": policy.policy_sha256,
        "profile_sha256": profile.profile_sha256,
        "authorized_at": _timestamp(at),
        "expires_at": _timestamp(expires_at),
        "operator_authorized": True,
        "explicit_work_request": True,
        "work_only": True,
        "visible_surface": "work",
        "work_entitlement_state": "available",
        "work_quota_state": "usable",
        "surface_observed_at": _timestamp(surface.observed_at),
        "quota_observed_at": _timestamp(quota.observed_at),
        "surface_observation_sha256": surface_sha256,
        "quota_observation_sha256": quota_sha256,
        "visible_model_observation_sha256": surface_sha256,
        "exact_internal_model_id_exposed": False,
        "max_new_synthetic_work_chats": 2,
        "allowed_actions": [
            action.value for action in sorted(C7ProtectedAction, key=lambda item: item.value)
        ],
        "existing_chats_allowed": False,
        "history_allowed": False,
        "private_browser_state_allowed": False,
        "account_or_security_settings_allowed": False,
        "write_actions_allowed": False,
        "raw_secrets_allowed": False,
        "real_evidence_access_allowed": False,
        "protocol_v2_allowed": False,
    }
    grant_sha256 = canonical_sha256(payload)
    hmac_payload = {**payload, "grant_sha256": grant_sha256}
    grant = C8LiveCycleGrant(
        **hmac_payload,
        authorization_hmac=hmac.new(
            _require_audit_key(audit_key),
            canonical_json(hmac_payload),
            hashlib.sha256,
        ).hexdigest(),
    )
    bundle = C8LiveCycleBundle(
        version="1",
        authorization=auth,
        surface_observation=surface,
        quota_observation=quota,
        grant=grant,
    )
    decision = evaluate_c8_admission(
        bundle=bundle,
        profile=profile,
        policy=policy,
        audit_key=audit_key,
        evaluated_at=at,
    )
    if not decision.live_actions_allowed:
        raise ValueError(f"C8 grant admission failed: {decision.reason}")
    return bundle


def evaluate_c8_admission(
    *,
    bundle: C8LiveCycleBundle | None,
    profile: ChatGptWorkCapabilityProfile,
    policy: C7WorkPrelivePolicy,
    audit_key: str | bytes | None,
    evaluated_at: datetime,
) -> C8AdmissionDecision:
    at = _require_utc(evaluated_at)
    status = C8FinalStatus.OPERATOR_AUTHORIZATION
    reason = "fresh explicit C8 operator authorization is required"
    auth_ok = False
    surface_ok = False
    quota_ok = False
    grant_ok = False
    cycle_id: str | None = None
    grant_id: str | None = None

    if bundle is not None and audit_key is not None:
        cycle_id = bundle.authorization.cycle_id
        grant_id = bundle.grant.grant_id
        try:
            verify_operator_authorization(
                bundle.authorization,
                audit_key=audit_key,
                evaluated_at=at,
            )
            auth_ok = True
        except ValueError as error:
            reason = str(error)
        if auth_ok:
            try:
                verify_work_surface_observation(
                    bundle.surface_observation,
                    audit_key=audit_key,
                    evaluated_at=at,
                )
                surface_ok = True
            except ValueError as error:
                status = C8FinalStatus.WORK_SURFACE_AMBIGUITY
                reason = str(error)
        if auth_ok and surface_ok:
            try:
                verify_work_quota_observation(
                    bundle.quota_observation,
                    audit_key=audit_key,
                    evaluated_at=at,
                )
                quota_ok = True
            except ValueError as error:
                status = C8FinalStatus.WORK_QUOTA
                reason = str(error)
        if auth_ok and surface_ok and quota_ok:
            c7 = evaluate_c7_prelive(
                profile=profile,
                policy=policy,
                evaluated_at=at,
                grant=bundle.grant,
                audit_key=_require_audit_key(audit_key),
            )
            grant_ok = c7.live_actions_allowed
            if grant_ok:
                status = C8FinalStatus.COMPLETE
                reason = "C8 bounded Work-only live-cycle grant verified"
            else:
                status = C8FinalStatus.SECURITY_INVARIANT
                reason = f"C7 grant verification denied: {c7.reason_code.value}"

    allow = auth_ok and surface_ok and quota_ok and grant_ok
    payload: dict[str, Any] = {
        "version": "1",
        "evaluated_at": _timestamp(at),
        "status": status.value,
        "live_actions_allowed": allow,
        "effective_tool_count": 1 if allow else 0,
        "cycle_id": cycle_id,
        "grant_id": grant_id,
        "authorization_verified": auth_ok,
        "surface_verified": surface_ok,
        "quota_verified": quota_ok,
        "c7_grant_verified": grant_ok,
        "native_chat_gate_status": "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE",
        "automatic_chat_to_work_switch_allowed": False,
        "reason": reason,
    }
    return C8AdmissionDecision(
        **payload,
        decision_sha256=canonical_sha256(payload),
    )


def commit_work_correlation_receipt(
    *,
    observation: C8WorkCallObservation,
    audit_records_verified: int,
    checked_at: datetime,
    audit_key: str | bytes,
) -> C8WorkCorrelationReceipt:
    payload: dict[str, Any] = {
        "version": "1",
        "status": "live_work_call_correlated",
        "source": "manual_chatgpt_work_and_local_audit",
        "simulated": False,
        "cycle_id": observation.cycle_id,
        "grant_id": observation.grant_id,
        "test_work_label": observation.test_work_label.value,
        "observation_sha256": canonical_sha256(observation.model_dump(mode="json")),
        "challenge_sha256": observation.challenge_sha256,
        "response_sha256": observation.response_sha256,
        "audit_correlation": observation.audit_correlation,
        "audit_record_sha256": observation.audit_record_sha256,
        "audit_records_verified": audit_records_verified,
        "checked_at": _timestamp(checked_at),
    }
    return C8WorkCorrelationReceipt(
        **payload,
        receipt_hmac=_commit_hmac(
            domain="correlation",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_work_correlation_receipt(
    receipt: C8WorkCorrelationReceipt,
    *,
    task_surface_observation: C8WorkTaskSurfaceObservation,
    observation: C8WorkCallObservation,
    audit_key: str | bytes,
) -> C8WorkCorrelationReceipt:
    committed = C8WorkCorrelationReceipt.model_validate(receipt.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="correlation",
        field_name="receipt_hmac",
        audit_key=audit_key,
    )
    C8WorkProofBundle(
        version="1",
        task_surface_observation=task_surface_observation,
        observation=observation,
        correlation_receipt=committed,
    )
    return committed


def commit_negative_test_receipt(
    *,
    cycle_id: str,
    grant_id: str,
    outcomes: dict[C8NegativeCheckId, C8NegativeOutcome],
    observed_at: datetime,
    audit_key: str | bytes,
) -> C8NegativeTestReceipt:
    payload: dict[str, Any] = {
        "version": "1",
        "source": "bounded_work_and_local_negative_tests",
        "simulated": False,
        "cycle_id": cycle_id,
        "grant_id": grant_id,
        "outcomes": {
            key.value: value.value
            for key, value in sorted(outcomes.items(), key=lambda item: item[0].value)
        },
        "capability_expanded": False,
        "native_chat_tested": False,
        "existing_conversations_accessed": False,
        "private_browser_state_accessed": False,
        "observed_at": _timestamp(observed_at),
    }
    return C8NegativeTestReceipt(
        **payload,
        receipt_hmac=_commit_hmac(
            domain="negative",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_negative_test_receipt(
    receipt: C8NegativeTestReceipt,
    *,
    audit_key: str | bytes,
) -> C8NegativeTestReceipt:
    committed = C8NegativeTestReceipt.model_validate(receipt.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="negative",
        field_name="receipt_hmac",
        audit_key=audit_key,
    )
    return committed


def commit_revocation_receipt(
    *,
    cycle_id: str,
    grant_id: str,
    verified_at: datetime,
    audit_key: str | bytes,
) -> C8RevocationReceipt:
    payload: dict[str, Any] = {
        "version": "1",
        "source": "manual_operator_and_local_verification",
        "simulated": False,
        "cycle_id": cycle_id,
        "grant_id": grant_id,
        "operator_authorization_revoked": True,
        "plugin_connection_removed": True,
        "runtime_api_key_revoked": True,
        "tunnel_stopped": True,
        "facade_stopped": True,
        "no_c8_listener": True,
        "process_secrets_cleared": True,
        "post_revocation_work_call_failed": True,
        "verified_at": _timestamp(verified_at),
    }
    return C8RevocationReceipt(
        **payload,
        receipt_hmac=_commit_hmac(
            domain="revocation",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_revocation_receipt(
    receipt: C8RevocationReceipt,
    *,
    audit_key: str | bytes,
) -> C8RevocationReceipt:
    committed = C8RevocationReceipt.model_validate(receipt.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="revocation",
        field_name="receipt_hmac",
        audit_key=audit_key,
    )
    return committed


def commit_final_attestation(
    *,
    live_cycle: C8LiveCycleBundle,
    work_proofs: tuple[C8WorkProofBundle, C8WorkProofBundle],
    negative_receipt: C8NegativeTestReceipt,
    revocation_receipt: C8RevocationReceipt,
    audit_key: str | bytes,
    verified_at: datetime,
) -> C8FinalAttestation:
    at = _require_utc(verified_at)
    auth = live_cycle.authorization
    grant = live_cycle.grant
    proofs = tuple(
        C8WorkProofBundle.model_validate(item.model_dump(mode="python")) for item in work_proofs
    )
    task_surfaces = tuple(
        verify_work_task_surface_observation(
            proof.task_surface_observation,
            audit_key=audit_key,
        )
        for proof in proofs
    )
    correlations = tuple(
        verify_work_correlation_receipt(
            proof.correlation_receipt,
            task_surface_observation=proof.task_surface_observation,
            observation=proof.observation,
            audit_key=audit_key,
        )
        for proof in proofs
    )
    negative = verify_negative_test_receipt(negative_receipt, audit_key=audit_key)
    revocation = verify_revocation_receipt(revocation_receipt, audit_key=audit_key)

    expected_labels = tuple(C8TestWorkLabel(label) for label in C8_WORK_LABELS)
    if tuple(proof.observation.test_work_label for proof in proofs) != expected_labels:
        raise ValueError("C8 final attestation requires ordered Work A and Work B evidence")
    cycle_ids = {
        auth.cycle_id,
        live_cycle.surface_observation.cycle_id,
        live_cycle.quota_observation.cycle_id,
        *(proof.observation.cycle_id for proof in proofs),
        negative.cycle_id,
        revocation.cycle_id,
    }
    grant_ids = {
        grant.grant_id,
        *(proof.observation.grant_id for proof in proofs),
        negative.grant_id,
        revocation.grant_id,
    }
    if len(cycle_ids) != 1 or len(grant_ids) != 1:
        raise ValueError("C8 final evidence spans multiple cycles or grants")
    observations = tuple(proof.observation for proof in proofs)
    for surface, observation in zip(task_surfaces, observations, strict=True):
        if not grant.authorized_at <= surface.observed_at < grant.expires_at:
            raise ValueError("C8 Work task was opened outside the live grant window")
        if not grant.authorized_at <= observation.observed_at < grant.expires_at:
            raise ValueError("C8 Work call occurred outside the live grant window")
        if not surface.observed_at <= observation.observed_at < surface.expires_at:
            raise ValueError("C8 Work call does not follow its fresh task observation")
    if len({item.challenge_sha256 for item in observations}) != 2:
        raise ValueError("C8 requires two distinct Work challenges")
    if len({item.response_sha256 for item in observations}) != 2:
        raise ValueError("C8 requires two distinct Work responses")
    if len({item.audit_correlation for item in observations}) != 2:
        raise ValueError("C8 requires two distinct local audit correlations")
    if len({item.audit_record_sha256 for item in observations}) != 2:
        raise ValueError("C8 requires two distinct local audit records")
    if len({item.local_policy_sha256 for item in observations}) != 1:
        raise ValueError("C8 Work proofs disagree on local policy")
    if len({item.tool_snapshot_sha256 for item in observations}) != 1:
        raise ValueError("C8 Work proofs disagree on tool snapshot")
    if negative.observed_at < max(item.observed_at for item in observations):
        raise ValueError("C8 negative receipt predates the two positive Work calls")
    if revocation.verified_at < negative.observed_at or at < revocation.verified_at:
        raise ValueError("C8 revocation chronology is invalid")

    payload: dict[str, Any] = {
        "version": "1",
        "status": C8_FINAL_STATUS,
        "source": "bounded_live_c8_verifier",
        "simulated": False,
        "issue_url": C8_ISSUE_URL,
        "accepted_c7_commit": C8_ACCEPTED_C7_MAIN,
        "native_chat_gate_status": "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE",
        "cycle_id": auth.cycle_id,
        "grant_id": grant.grant_id,
        "authorization_sha256": canonical_sha256(auth.model_dump(mode="json")),
        "surface_observation_sha256": canonical_sha256(
            live_cycle.surface_observation.model_dump(mode="json")
        ),
        "quota_observation_sha256": canonical_sha256(
            live_cycle.quota_observation.model_dump(mode="json")
        ),
        "grant_sha256": grant.grant_sha256,
        "work_observation_sha256": [
            canonical_sha256(item.model_dump(mode="json")) for item in observations
        ],
        "correlation_receipt_sha256": [
            canonical_sha256(item.model_dump(mode="json")) for item in correlations
        ],
        "negative_test_receipt_sha256": canonical_sha256(negative.model_dump(mode="json")),
        "revocation_receipt_sha256": canonical_sha256(revocation.model_dump(mode="json")),
        "local_policy_sha256": observations[0].local_policy_sha256,
        "tool_snapshot_sha256": observations[0].tool_snapshot_sha256,
        "work_call_count": 2,
        "native_chat_tested": False,
        "existing_conversations_accessed": False,
        "private_browser_state_accessed": False,
        "exact_internal_model_id_claimed": False,
        "regular_use_readiness_claimed": False,
        "revocation_verified": True,
        "verified_at": _timestamp(at),
    }
    return C8FinalAttestation(
        **payload,
        attestation_sha256=canonical_sha256(payload),
    )


def load_live_cycle_bundle(path: Path) -> C8LiveCycleBundle:
    return C8LiveCycleBundle.model_validate_json(path.read_text(encoding="utf-8"))


def verify_live_cycle_bundle(
    *,
    bundle: C8LiveCycleBundle,
    root: Path,
    audit_key: str | bytes,
    evaluated_at: datetime,
) -> C8AdmissionDecision:
    verify_committed_c8_governance(root, evaluated_at=evaluated_at)
    profile = load_profile(root / C7_PROFILE_PATH)
    policy = load_policy(root / C7_POLICY_PATH)
    decision = evaluate_c8_admission(
        bundle=bundle,
        profile=profile,
        policy=policy,
        audit_key=audit_key,
        evaluated_at=evaluated_at,
    )
    if not decision.live_actions_allowed:
        raise ValueError(decision.reason)
    return decision


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


def _load_model(path: Path, model_type: type[BaseModel]) -> BaseModel:
    return model_type.model_validate_json(path.read_text(encoding="utf-8"))


def _audit_key_from_environment() -> str:
    value = os.environ.get("SLG_AUDIT_KEY")
    if value is None:
        raise ValueError("SLG_AUDIT_KEY is missing from the process environment")
    _require_audit_key(value)
    return value


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="C8 bounded ChatGPT Work live-cycle evidence")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status")
    status.add_argument("--bundle", type=Path)
    status.add_argument("--as-of")

    authorize = sub.add_parser("authorize")
    authorize.add_argument("--cycle-id", required=True)
    authorize.add_argument("--authorized-at")
    authorize.add_argument("--expires-at", required=True)
    authorize.add_argument("--confirmed-exact-scope", action="store_true")

    surface = sub.add_parser("observe-surface")
    surface.add_argument("--cycle-id", required=True)
    surface.add_argument("--observed-at")
    surface.add_argument("--visible-model-label")
    surface.add_argument("--visible-reasoning-label")

    quota = sub.add_parser("observe-quota")
    quota.add_argument("--cycle-id", required=True)
    quota.add_argument("--observed-at")

    task_surface = sub.add_parser("observe-task-surface")
    task_surface.add_argument("--cycle-id", required=True)
    task_surface.add_argument("--grant-id", required=True)
    task_surface.add_argument("--test-work", choices=("a", "b"), required=True)
    task_surface.add_argument("--observed-at")

    grant = sub.add_parser("issue-grant")
    grant.add_argument("--authorization", type=Path, required=True)
    grant.add_argument("--surface-observation", type=Path, required=True)
    grant.add_argument("--quota-observation", type=Path, required=True)
    grant.add_argument("--grant-id")
    grant.add_argument("--issued-at")
    grant.add_argument("--expires-at", required=True)

    verify = sub.add_parser("verify-bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--as-of")

    negative = sub.add_parser("commit-negative")
    negative.add_argument("--cycle-id", required=True)
    negative.add_argument("--grant-id", required=True)
    negative.add_argument("--outcome", action="append", required=True)
    negative.add_argument("--observed-at")

    revoke = sub.add_parser("commit-revocation")
    revoke.add_argument("--cycle-id", required=True)
    revoke.add_argument("--grant-id", required=True)
    revoke.add_argument("--verified-at")
    revoke.add_argument("--confirmed-complete-revocation", action="store_true")

    final = sub.add_parser("commit-final")
    final.add_argument("--live-cycle", type=Path, required=True)
    final.add_argument("--proof-a", type=Path, required=True)
    final.add_argument("--proof-b", type=Path, required=True)
    final.add_argument("--negative", type=Path, required=True)
    final.add_argument("--revocation", type=Path, required=True)
    final.add_argument("--verified-at")

    args = parser.parse_args(argv)
    root = _repository_root()
    try:
        if args.command == "status":
            verify_committed_c8_governance(
                root,
                evaluated_at=_parse_timestamp(args.as_of),
            )
            profile = load_profile(root / C7_PROFILE_PATH)
            policy = load_policy(root / C7_POLICY_PATH)
            audit_key: str | None = None
            bundle: C8LiveCycleBundle | None = None
            if args.bundle is not None:
                audit_key = _audit_key_from_environment()
                bundle = load_live_cycle_bundle(args.bundle)
            decision = evaluate_c8_admission(
                bundle=bundle,
                profile=profile,
                policy=policy,
                audit_key=audit_key,
                evaluated_at=_parse_timestamp(args.as_of),
            )
            print(rendered_json(decision), end="")
            return 0 if decision.live_actions_allowed else 3

        audit_key = _audit_key_from_environment()
        if args.command == "authorize":
            if not args.confirmed_exact_scope:
                raise ValueError("exact C8 operator scope was not explicitly confirmed")
            authorization_receipt = commit_operator_authorization(
                cycle_id=args.cycle_id,
                authorized_at=_parse_timestamp(args.authorized_at),
                expires_at=_parse_timestamp(args.expires_at),
                audit_key=audit_key,
            )
            print(rendered_json(authorization_receipt), end="")
            return 0
        if args.command == "observe-surface":
            observed_at = _parse_timestamp(args.observed_at)
            surface_observation = commit_work_surface_observation(
                cycle_id=args.cycle_id,
                observed_at=observed_at,
                expires_at=observed_at + C8_OBSERVATION_TTL,
                audit_key=audit_key,
                visible_model_label=args.visible_model_label,
                visible_reasoning_label=args.visible_reasoning_label,
            )
            print(rendered_json(surface_observation), end="")
            return 0
        if args.command == "observe-quota":
            observed_at = _parse_timestamp(args.observed_at)
            quota_observation = commit_work_quota_observation(
                cycle_id=args.cycle_id,
                observed_at=observed_at,
                expires_at=observed_at + C8_OBSERVATION_TTL,
                audit_key=audit_key,
            )
            print(rendered_json(quota_observation), end="")
            return 0
        if args.command == "observe-task-surface":
            observed_at = _parse_timestamp(args.observed_at)
            work_task_surface = commit_work_task_surface_observation(
                cycle_id=args.cycle_id,
                grant_id=args.grant_id,
                test_work_label=C8TestWorkLabel(f"c8-test-work-{args.test_work}"),
                observed_at=observed_at,
                expires_at=observed_at + timedelta(minutes=30),
                audit_key=audit_key,
            )
            print(rendered_json(work_task_surface), end="")
            return 0
        if args.command == "issue-grant":
            verify_committed_c8_governance(
                root,
                evaluated_at=_parse_timestamp(args.issued_at),
            )
            profile = load_profile(root / C7_PROFILE_PATH)
            policy = load_policy(root / C7_POLICY_PATH)
            auth = C8OperatorAuthorizationReceipt.model_validate(
                _load_model(args.authorization, C8OperatorAuthorizationReceipt)
            )
            surface_receipt = C8WorkSurfaceObservation.model_validate(
                _load_model(args.surface_observation, C8WorkSurfaceObservation)
            )
            quota_receipt = C8WorkQuotaObservation.model_validate(
                _load_model(args.quota_observation, C8WorkQuotaObservation)
            )
            cycle = issue_live_cycle_bundle(
                authorization=auth,
                surface_observation=surface_receipt,
                quota_observation=quota_receipt,
                profile=profile,
                policy=policy,
                grant_id=args.grant_id or ("c8_" + secrets.token_hex(16)),
                issued_at=_parse_timestamp(args.issued_at),
                expires_at=_parse_timestamp(args.expires_at),
                audit_key=audit_key,
            )
            print(rendered_json(cycle), end="")
            return 0
        if args.command == "verify-bundle":
            decision = verify_live_cycle_bundle(
                bundle=load_live_cycle_bundle(args.bundle),
                root=root,
                audit_key=audit_key,
                evaluated_at=_parse_timestamp(args.as_of),
            )
            print(rendered_json(decision), end="")
            return 0
        if args.command == "commit-negative":
            outcomes: dict[C8NegativeCheckId, C8NegativeOutcome] = {}
            for raw in args.outcome:
                if raw.count("=") != 1:
                    raise ValueError("C8 negative outcomes must use check=outcome")
                check_value, outcome_value = raw.split("=", 1)
                check = C8NegativeCheckId(check_value)
                if check in outcomes:
                    raise ValueError(f"duplicate C8 negative outcome: {check.value}")
                outcomes[check] = C8NegativeOutcome(outcome_value)
            negative_receipt = commit_negative_test_receipt(
                cycle_id=args.cycle_id,
                grant_id=args.grant_id,
                outcomes=outcomes,
                observed_at=_parse_timestamp(args.observed_at),
                audit_key=audit_key,
            )
            print(rendered_json(negative_receipt), end="")
            return 0
        if args.command == "commit-revocation":
            if not args.confirmed_complete_revocation:
                raise ValueError("complete C8 revocation was not explicitly confirmed")
            revocation_receipt = commit_revocation_receipt(
                cycle_id=args.cycle_id,
                grant_id=args.grant_id,
                verified_at=_parse_timestamp(args.verified_at),
                audit_key=audit_key,
            )
            print(rendered_json(revocation_receipt), end="")
            return 0
        if args.command == "commit-final":
            live_cycle = load_live_cycle_bundle(args.live_cycle)
            proof_a = C8WorkProofBundle.model_validate(_load_model(args.proof_a, C8WorkProofBundle))
            proof_b = C8WorkProofBundle.model_validate(_load_model(args.proof_b, C8WorkProofBundle))
            negative_receipt = C8NegativeTestReceipt.model_validate(
                _load_model(args.negative, C8NegativeTestReceipt)
            )
            revocation_receipt = C8RevocationReceipt.model_validate(
                _load_model(args.revocation, C8RevocationReceipt)
            )
            attestation = commit_final_attestation(
                live_cycle=live_cycle,
                work_proofs=(proof_a, proof_b),
                negative_receipt=negative_receipt,
                revocation_receipt=revocation_receipt,
                audit_key=audit_key,
                verified_at=_parse_timestamp(args.verified_at),
            )
            print(rendered_json(attestation), end="")
            return 0
        raise ValueError("unsupported C8 command")
    except (OSError, ValueError) as error:
        print(
            json.dumps(
                {
                    "status": C8FinalStatus.SECURITY_INVARIANT.value,
                    "error": str(error),
                    "live_actions_allowed": False,
                    "effective_tool_count": 0,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
