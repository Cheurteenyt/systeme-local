from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import subprocess
import unicodedata
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .c8_seal import canonical_sha256
from .c9_git import run_c9_git
from .c9_local_ai import (
    C9LocalAIReceipt,
    C9LocalAIRuntimeObservation,
    c9_local_ai_runtime_observation_sha256,
    verify_c9_local_ai_runtime_observation_authenticity,
)
from .c9_seal import verify_c9_c8_seal_exact

C9_TOOL_NAME: Final = "systeme_local_attachment_handoff"
C9_MAX_AUTHORIZATION_SECONDS = 86_400
C9_MAX_SURFACE_OBSERVATION_SECONDS = 600
C9_MAX_LIVE_CYCLE_SECONDS = 1_200

_CYCLE_PATTERN = r"^c9_cycle_[0-9a-f]{32}$"
_GRANT_PATTERN = r"^c9_grant_[0-9a-f]{32}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
_VISIBLE_LABEL_SECRET_MARKERS = (
    "api_key",
    "apikey",
    "authorization:",
    "bearer ",
    "cookie",
    "password",
    "secret",
    "sk-",
    "token",
)
_DOMAIN = {
    "authorization": b"systeme-local/c9/operator-authorization/v1\0",
    "surface": b"systeme-local/c9/surface-observation/v1\0",
    "grant": b"systeme-local/c9/live-cycle-grant/v1\0",
}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C9 timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return _utc(datetime.fromisoformat(normalized))


def _audit_key(value: str | bytes) -> bytes:
    encoded = value.encode("utf-8") if isinstance(value, str) else value
    if len(encoded) < 32:
        raise ValueError("C9 evidence requires an audit key of at least 32 bytes")
    return encoded


def _commit_hmac(
    *,
    domain: Literal["authorization", "surface", "grant"],
    payload: dict[str, Any],
    audit_key: str | bytes,
) -> str:
    return hmac.new(
        _audit_key(audit_key),
        _DOMAIN[domain]
        + json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _verify_hmac(
    model: BaseModel,
    *,
    domain: Literal["authorization", "surface", "grant"],
    field_name: str,
    audit_key: str | bytes,
) -> None:
    payload = model.model_dump(mode="json", exclude={field_name})
    expected = _commit_hmac(domain=domain, payload=payload, audit_key=audit_key)
    if not hmac.compare_digest(str(getattr(model, field_name)), expected):
        raise ValueError(f"C9 {domain} evidence HMAC mismatch")


def _window(start: datetime, end: datetime, maximum_seconds: int) -> None:
    if end <= start:
        raise ValueError("C9 evidence expiry must follow issuance")
    if end - start > timedelta(seconds=maximum_seconds):
        raise ValueError("C9 evidence window exceeds its maximum")


def _visible_label_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = unicodedata.normalize("NFC", value)
    if (
        not 1 <= len(normalized) <= 128
        or normalized != value
        or normalized != normalized.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
        or any(marker in normalized.casefold() for marker in _VISIBLE_LABEL_SECRET_MARKERS)
    ):
        raise ValueError("C9 visible UI label is non-canonical or secret-like")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class C9AdmissionStatus(StrEnum):
    READY = "READY"
    OPERATOR_AUTHORIZATION_REQUIRED = "BLOCKED_BY_OPERATOR_AUTHORIZATION"
    SURFACE_OBSERVATION_REQUIRED = "BLOCKED_BY_SURFACE_OBSERVATION"
    LOCAL_AI_REQUIRED = "BLOCKED_BY_LOCAL_AI_VERIFICATION"
    C8_SEAL_REQUIRED = "BLOCKED_BY_C8_SEAL"
    SECURITY_INVARIANT = "BLOCKED_BY_SECURITY_INVARIANT"


class C9AdmissionReason(StrEnum):
    READY = "C9_EXACT_LIVE_CYCLE_VERIFIED"
    NO_BUNDLE = "C9_LIVE_CYCLE_BUNDLE_REQUIRED"
    AUDIT_KEY_MISSING = "C9_AUDIT_KEY_REQUIRED"
    AUTHORIZATION_INVALID = "C9_OPERATOR_AUTHORIZATION_INVALID"
    SURFACE_INVALID = "C9_SURFACE_OBSERVATION_INVALID_OR_STALE"
    GRANT_INVALID = "C9_LIVE_CYCLE_GRANT_INVALID_OR_STALE"
    LOCAL_AI_INVALID = "C9_LOCAL_AI_RECEIPT_INVALID"
    C8_SEAL_INVALID = "C9_C8_SEAL_DEPENDENCY_INVALID"
    C8_ANCESTRY_INVALID = "C9_C8_TAG_TARGET_NOT_ANCESTOR_OF_HEAD"
    BINDING_INVALID = "C9_LIVE_CYCLE_BINDING_INVALID"


class C9C8AncestryError(ValueError):
    """Raised when the reviewed C8 tag is not in the current HEAD ancestry."""


class C9OperatorAuthorization(_StrictModel):
    version: Literal["1"] = "1"
    cycle_id: str = Field(pattern=_CYCLE_PATTERN)
    source: Literal["explicit_operator_authorization"]
    simulated: Literal[False]
    operator_authorized: Literal[True]
    one_synthetic_work_task_allowed: Literal[True]
    one_new_synthetic_native_chat_conversation_allowed: Literal[True]
    work_delivery_mode: Literal["plugin_mcp_rich_content"]
    native_chat_delivery_mode: Literal["operator_performed_manual_attachment_handoff"]
    work_plugin_mcp_app_required: Literal[True]
    native_chat_plugin_mcp_app_allowed: Literal[False]
    automatic_chat_to_work_switch_allowed: Literal[False]
    native_chat_manual_attachment_handoff_required: Literal[True]
    native_chat_manual_attachment_handoff_qualifies_as_success: Literal[True]
    selected_attachment_count: Literal[2]
    selected_attachment_media_types: tuple[
        Literal["image/png", "image/jpeg"],
        Literal["text/plain"],
    ]
    selected_package_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_ai_literal_loopback_required: Literal[True]
    local_ai_authentication_allowed: Literal[False]
    temporary_tunnel_allowed: Literal[True]
    temporary_plugin_connection_allowed: Literal[True]
    runtime_api_key_operator_managed: Literal[True]
    temporary_sanitized_chat_export_allowed: Literal[True]
    arbitrary_local_file_access_allowed: Literal[False]
    existing_conversations_allowed: Literal[False]
    history_allowed: Literal[False]
    account_or_security_settings_allowed: Literal[False]
    private_browser_state_allowed: Literal[False]
    write_actions_allowed: Literal[False]
    command_execution_allowed: Literal[False]
    raw_secrets_allowed: Literal[False]
    real_evidence_access_allowed: Literal[False]
    protocol_v2_allowed: Literal[False]
    c8_live_cycle_grant_reused: Literal[False]
    authorized_at: datetime
    expires_at: datetime
    authorization_hmac: str = Field(pattern=_SHA256_PATTERN)

    _authorized_utc = field_validator("authorized_at")(_utc)
    _expires_utc = field_validator("expires_at")(_utc)

    @model_validator(mode="after")
    def validate_authorization(self) -> C9OperatorAuthorization:
        _window(
            self.authorized_at,
            self.expires_at,
            C9_MAX_AUTHORIZATION_SECONDS,
        )
        return self


class C9SurfaceObservation(_StrictModel):
    version: Literal["1"] = "1"
    cycle_id: str = Field(pattern=_CYCLE_PATTERN)
    source: Literal["chatgpt_visible_ui"]
    simulated: Literal[False]
    work_surface_visible: Literal[True]
    explicit_work_selected: Literal[True]
    plugin_surface_visible: Literal[True]
    work_entitlement_available: Literal[True]
    work_quota_usable: Literal[True]
    work_plugin_mcp_app_visible: Literal[True]
    work_plugin_mcp_app_eligible: Literal[True]
    work_plugin_mcp_app_selectable: Literal[True]
    native_chat_surface_visible: Literal[True]
    explicit_native_chat_selected: Literal[True]
    native_chat_attachment_control_visible: Literal[True]
    native_chat_file_picker_visible: Literal[True]
    native_chat_manual_attachment_handoff_available: Literal[True]
    native_chat_manual_attachment_handoff_used: Literal[False]
    work_visible_model_label_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    work_visible_reasoning_label_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    native_chat_visible_model_label_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    native_chat_visible_reasoning_label_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    visible_labels_are_ui_only: Literal[True]
    exact_internal_model_id_observed: Literal[False]
    prompt_sent: Literal[False]
    existing_conversations_accessed: Literal[False]
    history_accessed: Literal[False]
    account_or_security_settings_accessed: Literal[False]
    private_browser_state_accessed: Literal[False]
    automatic_chat_to_work_switch_used: Literal[False]
    observed_at: datetime
    expires_at: datetime
    observation_hmac: str = Field(pattern=_SHA256_PATTERN)

    _observed_utc = field_validator("observed_at")(_utc)
    _expires_utc = field_validator("expires_at")(_utc)

    @model_validator(mode="after")
    def validate_observation(self) -> C9SurfaceObservation:
        _window(
            self.observed_at,
            self.expires_at,
            C9_MAX_SURFACE_OBSERVATION_SECONDS,
        )
        return self


class C9C8SealDependency(_StrictModel):
    version: Literal["1"] = "1"
    status: Literal["verified"]
    tag_target: str = Field(pattern=_COMMIT_PATTERN)
    covered_head: str = Field(pattern=_COMMIT_PATTERN)
    current_head: str = Field(pattern=_COMMIT_PATTERN)
    tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    final_attestation_sha256: str = Field(pattern=_SHA256_PATTERN)
    reviewed_outcome: Literal["COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"]
    work_call_count: Literal[2]
    revocation_verified: Literal[True]
    tag_target_ancestor_of_head: Literal[True]
    dependency_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_dependency(self) -> C9C8SealDependency:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"dependency_sha256"}))
        if self.dependency_sha256 != expected:
            raise ValueError("C9 C8 seal dependency digest mismatch")
        return self


class C9LiveCycleGrant(_StrictModel):
    version: Literal["1"] = "1"
    grant_id: str = Field(pattern=_GRANT_PATTERN)
    cycle_id: str = Field(pattern=_CYCLE_PATTERN)
    authorization_sha256: str = Field(pattern=_SHA256_PATTERN)
    surface_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    selected_package_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_ai_verified: Literal[True]
    local_ai_transport: Literal["openai_compatible_chat_completions_loopback"]
    local_ai_authentication: Literal["none"]
    local_ai_adapter_persistent_storage_used: Literal[False]
    local_ai_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_ai_runtime_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_ai_endpoint_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_ai_visible_model_label_sha256: str = Field(pattern=_SHA256_PATTERN)
    c8_tag_target: str = Field(pattern=_COMMIT_PATTERN)
    c8_covered_head: str = Field(pattern=_COMMIT_PATTERN)
    c8_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    c8_dependency_sha256: str = Field(pattern=_SHA256_PATTERN)
    repository_head_at_issue: str = Field(pattern=_COMMIT_PATTERN)
    c8_live_cycle_grant_reused: Literal[False]
    effective_tool_count: Literal[1]
    effective_tools: tuple[Literal["systeme_local_attachment_handoff"]]
    one_synthetic_work_task: Literal[True]
    one_new_synthetic_native_chat_conversation: Literal[True]
    required_work_plugin_tool_call_count: Literal[1]
    required_native_chat_plugin_tool_call_count: Literal[0]
    required_native_chat_manual_attachment_handoff_count: Literal[1]
    work_delivery_mode: Literal["plugin_mcp_rich_content"]
    native_chat_delivery_mode: Literal["operator_performed_manual_attachment_handoff"]
    work_plugin_mcp_app_required: Literal[True]
    native_chat_plugin_mcp_app_allowed: Literal[False]
    automatic_chat_to_work_switch_allowed: Literal[False]
    native_chat_manual_attachment_handoff_qualifies_as_success: Literal[True]
    issued_at: datetime
    expires_at: datetime
    grant_hmac: str = Field(pattern=_SHA256_PATTERN)

    _issued_utc = field_validator("issued_at")(_utc)
    _expires_utc = field_validator("expires_at")(_utc)

    @model_validator(mode="after")
    def validate_grant(self) -> C9LiveCycleGrant:
        _window(self.issued_at, self.expires_at, C9_MAX_LIVE_CYCLE_SECONDS)
        if self.effective_tools != (C9_TOOL_NAME,):
            raise ValueError("C9 live-cycle grant must expose exactly the handoff tool")
        return self


class C9LiveCycleBundle(_StrictModel):
    version: Literal["1"] = "1"
    authorization: C9OperatorAuthorization
    surface_observation: C9SurfaceObservation
    local_ai_runtime_observation: C9LocalAIRuntimeObservation
    grant: C9LiveCycleGrant

    @model_validator(mode="after")
    def validate_bindings(self) -> C9LiveCycleBundle:
        if {
            self.authorization.cycle_id,
            self.surface_observation.cycle_id,
            self.local_ai_runtime_observation.cycle_id,
            self.grant.cycle_id,
        } != {self.authorization.cycle_id}:
            raise ValueError("C9 evidence belongs to different cycles")
        if self.grant.authorization_sha256 != canonical_sha256(
            self.authorization.model_dump(mode="json")
        ):
            raise ValueError("C9 grant does not bind operator authorization")
        if self.grant.surface_observation_sha256 != canonical_sha256(
            self.surface_observation.model_dump(mode="json")
        ):
            raise ValueError("C9 grant does not bind surface observation")
        if (
            self.grant.selected_package_manifest_sha256
            != self.authorization.selected_package_manifest_sha256
        ):
            raise ValueError("C9 grant does not bind the selected package")
        if (
            self.grant.work_delivery_mode != self.authorization.work_delivery_mode
            or self.grant.native_chat_delivery_mode != self.authorization.native_chat_delivery_mode
            or self.grant.work_plugin_mcp_app_required
            != self.authorization.work_plugin_mcp_app_required
            or self.grant.native_chat_plugin_mcp_app_allowed
            != self.authorization.native_chat_plugin_mcp_app_allowed
            or self.grant.automatic_chat_to_work_switch_allowed
            != self.authorization.automatic_chat_to_work_switch_allowed
            or self.grant.native_chat_manual_attachment_handoff_qualifies_as_success
            != self.authorization.native_chat_manual_attachment_handoff_qualifies_as_success
        ):
            raise ValueError("C9 grant does not bind the official mixed-surface delivery contract")
        if self.grant.local_ai_runtime_observation_sha256 != (
            c9_local_ai_runtime_observation_sha256(self.local_ai_runtime_observation)
        ):
            raise ValueError("C9 grant does not bind the local AI runtime observation")
        if (
            self.grant.local_ai_endpoint_sha256 != self.local_ai_runtime_observation.endpoint_sha256
            or self.grant.local_ai_visible_model_label_sha256
            != self.local_ai_runtime_observation.visible_model_label_sha256
        ):
            raise ValueError("C9 grant does not bind the exact local AI endpoint and model")
        if not (
            self.authorization.authorized_at <= self.grant.issued_at < self.authorization.expires_at
        ):
            raise ValueError("C9 grant was not issued inside operator authorization")
        if self.grant.expires_at > self.authorization.expires_at:
            raise ValueError("C9 grant outlives operator authorization")
        if not (
            self.surface_observation.observed_at
            <= self.grant.issued_at
            < self.surface_observation.expires_at
        ):
            raise ValueError("C9 grant was not issued from a fresh surface observation")
        return self


class C9AdmissionDecision(_StrictModel):
    version: Literal["1"] = "1"
    evaluated_at: datetime
    status: C9AdmissionStatus
    reason: C9AdmissionReason
    live_actions_allowed: bool
    effective_tool_count: int = Field(ge=0, le=1)
    effective_tools: tuple[str, ...] = Field(max_length=1)
    cycle_id: str | None = Field(default=None, pattern=_CYCLE_PATTERN)
    grant_id: str | None = Field(default=None, pattern=_GRANT_PATTERN)
    authorization_verified: bool
    surface_observation_verified: bool
    local_ai_verified: bool
    c8_seal_verified: bool
    c8_tag_target_ancestor_of_head: bool
    grant_verified: bool
    c8_live_cycle_grant_reused: Literal[False]
    decision_sha256: str = Field(pattern=_SHA256_PATTERN)

    _evaluated_utc = field_validator("evaluated_at")(_utc)

    @model_validator(mode="after")
    def validate_decision(self) -> C9AdmissionDecision:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"decision_sha256"}))
        if self.decision_sha256 != expected:
            raise ValueError("C9 admission decision digest mismatch")
        allow = (
            self.authorization_verified
            and self.surface_observation_verified
            and self.local_ai_verified
            and self.c8_seal_verified
            and self.c8_tag_target_ancestor_of_head
            and self.grant_verified
            and self.effective_tool_count == 1
            and self.effective_tools == (C9_TOOL_NAME,)
        )
        if self.live_actions_allowed != allow:
            raise ValueError("C9 admission summary is internally inconsistent")
        if self.live_actions_allowed != (self.status is C9AdmissionStatus.READY):
            raise ValueError("C9 admission status contradicts its allow decision")
        return self


def commit_c9_operator_authorization(
    *,
    cycle_id: str,
    selected_package_manifest_sha256: str,
    image_media_type: Literal["image/png", "image/jpeg"],
    authorized_at: datetime,
    expires_at: datetime,
    audit_key: str | bytes,
) -> C9OperatorAuthorization:
    payload: dict[str, Any] = {
        "version": "1",
        "cycle_id": cycle_id,
        "source": "explicit_operator_authorization",
        "simulated": False,
        "operator_authorized": True,
        "one_synthetic_work_task_allowed": True,
        "one_new_synthetic_native_chat_conversation_allowed": True,
        "work_delivery_mode": "plugin_mcp_rich_content",
        "native_chat_delivery_mode": "operator_performed_manual_attachment_handoff",
        "work_plugin_mcp_app_required": True,
        "native_chat_plugin_mcp_app_allowed": False,
        "automatic_chat_to_work_switch_allowed": False,
        "native_chat_manual_attachment_handoff_required": True,
        "native_chat_manual_attachment_handoff_qualifies_as_success": True,
        "selected_attachment_count": 2,
        "selected_attachment_media_types": [image_media_type, "text/plain"],
        "selected_package_manifest_sha256": selected_package_manifest_sha256,
        "local_ai_literal_loopback_required": True,
        "local_ai_authentication_allowed": False,
        "temporary_tunnel_allowed": True,
        "temporary_plugin_connection_allowed": True,
        "runtime_api_key_operator_managed": True,
        "temporary_sanitized_chat_export_allowed": True,
        "arbitrary_local_file_access_allowed": False,
        "existing_conversations_allowed": False,
        "history_allowed": False,
        "account_or_security_settings_allowed": False,
        "private_browser_state_allowed": False,
        "write_actions_allowed": False,
        "command_execution_allowed": False,
        "raw_secrets_allowed": False,
        "real_evidence_access_allowed": False,
        "protocol_v2_allowed": False,
        "c8_live_cycle_grant_reused": False,
        "authorized_at": _timestamp(authorized_at),
        "expires_at": _timestamp(expires_at),
    }
    return C9OperatorAuthorization(
        **payload,
        authorization_hmac=_commit_hmac(
            domain="authorization",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_c9_operator_authorization(
    authorization: C9OperatorAuthorization,
    *,
    audit_key: str | bytes,
    evaluated_at: datetime,
) -> C9OperatorAuthorization:
    committed = C9OperatorAuthorization.model_validate(authorization.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="authorization",
        field_name="authorization_hmac",
        audit_key=audit_key,
    )
    at = _utc(evaluated_at)
    if not committed.authorized_at <= at < committed.expires_at:
        raise ValueError("C9 operator authorization is not active")
    return committed


def commit_c9_surface_observation(
    *,
    cycle_id: str,
    observed_at: datetime,
    expires_at: datetime,
    audit_key: str | bytes,
    work_visible_model_label: str | None = None,
    work_visible_reasoning_label: str | None = None,
    native_chat_visible_model_label: str | None = None,
    native_chat_visible_reasoning_label: str | None = None,
) -> C9SurfaceObservation:
    payload: dict[str, Any] = {
        "version": "1",
        "cycle_id": cycle_id,
        "source": "chatgpt_visible_ui",
        "simulated": False,
        "work_surface_visible": True,
        "explicit_work_selected": True,
        "plugin_surface_visible": True,
        "work_entitlement_available": True,
        "work_quota_usable": True,
        "work_plugin_mcp_app_visible": True,
        "work_plugin_mcp_app_eligible": True,
        "work_plugin_mcp_app_selectable": True,
        "native_chat_surface_visible": True,
        "explicit_native_chat_selected": True,
        "native_chat_attachment_control_visible": True,
        "native_chat_file_picker_visible": True,
        "native_chat_manual_attachment_handoff_available": True,
        "native_chat_manual_attachment_handoff_used": False,
        "work_visible_model_label_sha256": _visible_label_sha256(work_visible_model_label),
        "work_visible_reasoning_label_sha256": _visible_label_sha256(work_visible_reasoning_label),
        "native_chat_visible_model_label_sha256": _visible_label_sha256(
            native_chat_visible_model_label
        ),
        "native_chat_visible_reasoning_label_sha256": _visible_label_sha256(
            native_chat_visible_reasoning_label
        ),
        "visible_labels_are_ui_only": True,
        "exact_internal_model_id_observed": False,
        "prompt_sent": False,
        "existing_conversations_accessed": False,
        "history_accessed": False,
        "account_or_security_settings_accessed": False,
        "private_browser_state_accessed": False,
        "automatic_chat_to_work_switch_used": False,
        "observed_at": _timestamp(observed_at),
        "expires_at": _timestamp(expires_at),
    }
    return C9SurfaceObservation(
        **payload,
        observation_hmac=_commit_hmac(
            domain="surface",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_c9_surface_observation(
    observation: C9SurfaceObservation,
    *,
    audit_key: str | bytes,
    evaluated_at: datetime,
) -> C9SurfaceObservation:
    committed = C9SurfaceObservation.model_validate(observation.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="surface",
        field_name="observation_hmac",
        audit_key=audit_key,
    )
    at = _utc(evaluated_at)
    if not committed.observed_at <= at < committed.expires_at:
        raise ValueError("C9 Work MCP and native Chat manual-handoff observation is not fresh")
    return committed


def _is_git_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    completed = run_c9_git(
        root,
        "merge-base",
        "--is-ancestor",
        ancestor,
        descendant,
        accepted_returncodes=(0, 1),
        maximum_output_bytes=64 * 1024,
    )
    if completed.returncode not in (0, 1):
        raise ValueError("C9 could not verify C8 tag ancestry")
    return completed.returncode == 0


def _verified_c8_dependency(root: Path) -> C9C8SealDependency:
    verification = verify_c9_c8_seal_exact(root)
    ancestor = _is_git_ancestor(
        root,
        verification.tag_target,
        verification.current_head,
    )
    if not ancestor:
        raise C9C8AncestryError("C8 evidence tag target is not an ancestor of HEAD")
    payload: dict[str, Any] = {
        "version": "1",
        "status": "verified",
        "tag_target": verification.tag_target,
        "covered_head": verification.covered_head,
        "current_head": verification.current_head,
        "tree_sha256": verification.tree_sha256,
        "final_attestation_sha256": verification.final_attestation_sha256,
        "reviewed_outcome": verification.reviewed_outcome,
        "work_call_count": verification.work_call_count,
        "revocation_verified": verification.revocation_verified,
        "tag_target_ancestor_of_head": True,
    }
    return C9C8SealDependency(
        **payload,
        dependency_sha256=canonical_sha256(payload),
    )


def issue_c9_live_cycle_bundle(
    *,
    authorization: C9OperatorAuthorization,
    surface_observation: C9SurfaceObservation,
    grant_id: str,
    local_ai_receipt: C9LocalAIReceipt,
    local_ai_runtime_observation: C9LocalAIRuntimeObservation,
    root: Path,
    issued_at: datetime,
    expires_at: datetime,
    audit_key: str | bytes,
) -> C9LiveCycleBundle:
    at = _utc(issued_at)
    authorization = verify_c9_operator_authorization(
        authorization,
        audit_key=audit_key,
        evaluated_at=at,
    )
    observation = verify_c9_surface_observation(
        surface_observation,
        audit_key=audit_key,
        evaluated_at=at,
    )
    if authorization.cycle_id != observation.cycle_id:
        raise ValueError("C9 authorization and surface observation use different cycles")
    expiry = _utc(expires_at)
    _window(at, expiry, C9_MAX_LIVE_CYCLE_SECONDS)
    if expiry > authorization.expires_at:
        raise ValueError("C9 grant cannot outlive operator authorization")
    receipt = C9LocalAIReceipt.model_validate(local_ai_receipt.model_dump(mode="python"))
    runtime_observation = verify_c9_local_ai_runtime_observation_authenticity(
        local_ai_runtime_observation,
        audit_key=audit_key,
        evaluated_at=at,
    )
    runtime_observation_sha256 = c9_local_ai_runtime_observation_sha256(runtime_observation)
    if (
        runtime_observation.cycle_id != authorization.cycle_id
        or receipt.runtime_observation_sha256 != runtime_observation_sha256
        or receipt.endpoint_sha256 != runtime_observation.endpoint_sha256
        or receipt.visible_model_label_sha256 != runtime_observation.visible_model_label_sha256
        or receipt.adapter_persistent_storage_used
        or expiry > runtime_observation.expires_at
    ):
        raise ValueError("C9 local-AI runtime observation does not bind the receipt")
    dependency = _verified_c8_dependency(root)
    payload: dict[str, Any] = {
        "version": "1",
        "grant_id": grant_id,
        "cycle_id": authorization.cycle_id,
        "authorization_sha256": canonical_sha256(authorization.model_dump(mode="json")),
        "surface_observation_sha256": canonical_sha256(observation.model_dump(mode="json")),
        "selected_package_manifest_sha256": (authorization.selected_package_manifest_sha256),
        "local_ai_verified": True,
        "local_ai_transport": "openai_compatible_chat_completions_loopback",
        "local_ai_authentication": "none",
        "local_ai_adapter_persistent_storage_used": False,
        "local_ai_receipt_sha256": receipt.receipt_sha256,
        "local_ai_runtime_observation_sha256": runtime_observation_sha256,
        "local_ai_endpoint_sha256": runtime_observation.endpoint_sha256,
        "local_ai_visible_model_label_sha256": (runtime_observation.visible_model_label_sha256),
        "c8_tag_target": dependency.tag_target,
        "c8_covered_head": dependency.covered_head,
        "c8_tree_sha256": dependency.tree_sha256,
        "c8_dependency_sha256": dependency.dependency_sha256,
        "repository_head_at_issue": dependency.current_head,
        "c8_live_cycle_grant_reused": False,
        "effective_tool_count": 1,
        "effective_tools": [C9_TOOL_NAME],
        "one_synthetic_work_task": True,
        "one_new_synthetic_native_chat_conversation": True,
        "required_work_plugin_tool_call_count": 1,
        "required_native_chat_plugin_tool_call_count": 0,
        "required_native_chat_manual_attachment_handoff_count": 1,
        "work_delivery_mode": "plugin_mcp_rich_content",
        "native_chat_delivery_mode": "operator_performed_manual_attachment_handoff",
        "work_plugin_mcp_app_required": True,
        "native_chat_plugin_mcp_app_allowed": False,
        "automatic_chat_to_work_switch_allowed": False,
        "native_chat_manual_attachment_handoff_qualifies_as_success": True,
        "issued_at": _timestamp(at),
        "expires_at": _timestamp(expiry),
    }
    grant = C9LiveCycleGrant(
        **payload,
        grant_hmac=_commit_hmac(
            domain="grant",
            payload=payload,
            audit_key=audit_key,
        ),
    )
    bundle = C9LiveCycleBundle(
        authorization=authorization,
        surface_observation=observation,
        local_ai_runtime_observation=runtime_observation,
        grant=grant,
    )
    decision = evaluate_c9_admission(
        bundle=bundle,
        root=root,
        audit_key=audit_key,
        evaluated_at=at,
    )
    if not decision.live_actions_allowed:
        raise ValueError(f"C9 live-cycle admission failed: {decision.reason.value}")
    return bundle


def _decision(
    *,
    evaluated_at: datetime,
    status: C9AdmissionStatus,
    reason: C9AdmissionReason,
    cycle_id: str | None,
    grant_id: str | None,
    authorization_verified: bool,
    surface_observation_verified: bool,
    local_ai_verified: bool,
    c8_seal_verified: bool,
    c8_tag_target_ancestor_of_head: bool,
    grant_verified: bool,
) -> C9AdmissionDecision:
    allow = (
        authorization_verified
        and surface_observation_verified
        and local_ai_verified
        and c8_seal_verified
        and c8_tag_target_ancestor_of_head
        and grant_verified
    )
    payload: dict[str, Any] = {
        "version": "1",
        "evaluated_at": _timestamp(evaluated_at),
        "status": status.value,
        "reason": reason.value,
        "live_actions_allowed": allow,
        "effective_tool_count": 1 if allow else 0,
        "effective_tools": [C9_TOOL_NAME] if allow else [],
        "cycle_id": cycle_id,
        "grant_id": grant_id,
        "authorization_verified": authorization_verified,
        "surface_observation_verified": surface_observation_verified,
        "local_ai_verified": local_ai_verified,
        "c8_seal_verified": c8_seal_verified,
        "c8_tag_target_ancestor_of_head": c8_tag_target_ancestor_of_head,
        "grant_verified": grant_verified,
        "c8_live_cycle_grant_reused": False,
    }
    return C9AdmissionDecision(
        **payload,
        decision_sha256=canonical_sha256(payload),
    )


def evaluate_c9_admission(
    *,
    bundle: C9LiveCycleBundle | None,
    root: Path,
    audit_key: str | bytes | None,
    evaluated_at: datetime,
) -> C9AdmissionDecision:
    at = _utc(evaluated_at)
    cycle_id: str | None = None
    grant_id: str | None = None
    auth_ok = False
    surface_ok = False
    local_ai_ok = False
    c8_ok = False
    ancestry_ok = False
    grant_ok = False

    if bundle is None:
        return _decision(
            evaluated_at=at,
            status=C9AdmissionStatus.OPERATOR_AUTHORIZATION_REQUIRED,
            reason=C9AdmissionReason.NO_BUNDLE,
            cycle_id=None,
            grant_id=None,
            authorization_verified=False,
            surface_observation_verified=False,
            local_ai_verified=False,
            c8_seal_verified=False,
            c8_tag_target_ancestor_of_head=False,
            grant_verified=False,
        )
    cycle_id = getattr(bundle.authorization, "cycle_id", None)
    grant_id = getattr(bundle.grant, "grant_id", None)
    if audit_key is None:
        return _decision(
            evaluated_at=at,
            status=C9AdmissionStatus.OPERATOR_AUTHORIZATION_REQUIRED,
            reason=C9AdmissionReason.AUDIT_KEY_MISSING,
            cycle_id=cycle_id,
            grant_id=grant_id,
            authorization_verified=False,
            surface_observation_verified=False,
            local_ai_verified=False,
            c8_seal_verified=False,
            c8_tag_target_ancestor_of_head=False,
            grant_verified=False,
        )

    try:
        committed = C9LiveCycleBundle.model_validate(bundle.model_dump(mode="python"))
    except (AttributeError, ValueError):
        return _decision(
            evaluated_at=at,
            status=C9AdmissionStatus.SECURITY_INVARIANT,
            reason=C9AdmissionReason.BINDING_INVALID,
            cycle_id=cycle_id,
            grant_id=grant_id,
            authorization_verified=False,
            surface_observation_verified=False,
            local_ai_verified=False,
            c8_seal_verified=False,
            c8_tag_target_ancestor_of_head=False,
            grant_verified=False,
        )

    try:
        verify_c9_operator_authorization(
            committed.authorization,
            audit_key=audit_key,
            evaluated_at=at,
        )
        auth_ok = True
    except ValueError:
        return _decision(
            evaluated_at=at,
            status=C9AdmissionStatus.OPERATOR_AUTHORIZATION_REQUIRED,
            reason=C9AdmissionReason.AUTHORIZATION_INVALID,
            cycle_id=cycle_id,
            grant_id=grant_id,
            authorization_verified=False,
            surface_observation_verified=False,
            local_ai_verified=False,
            c8_seal_verified=False,
            c8_tag_target_ancestor_of_head=False,
            grant_verified=False,
        )

    try:
        verify_c9_surface_observation(
            committed.surface_observation,
            audit_key=audit_key,
            evaluated_at=committed.grant.issued_at,
        )
        surface_ok = True
    except ValueError:
        return _decision(
            evaluated_at=at,
            status=C9AdmissionStatus.SURFACE_OBSERVATION_REQUIRED,
            reason=C9AdmissionReason.SURFACE_INVALID,
            cycle_id=cycle_id,
            grant_id=grant_id,
            authorization_verified=auth_ok,
            surface_observation_verified=False,
            local_ai_verified=False,
            c8_seal_verified=False,
            c8_tag_target_ancestor_of_head=False,
            grant_verified=False,
        )

    try:
        runtime_observation = verify_c9_local_ai_runtime_observation_authenticity(
            committed.local_ai_runtime_observation,
            audit_key=audit_key,
            evaluated_at=at,
        )
        runtime_observation_sha256 = c9_local_ai_runtime_observation_sha256(runtime_observation)
        local_ai_ok = (
            committed.grant.local_ai_verified
            and committed.grant.local_ai_transport == "openai_compatible_chat_completions_loopback"
            and committed.grant.local_ai_authentication == "none"
            and not committed.grant.local_ai_adapter_persistent_storage_used
            and committed.grant.local_ai_runtime_observation_sha256 == runtime_observation_sha256
            and committed.grant.local_ai_endpoint_sha256 == runtime_observation.endpoint_sha256
            and committed.grant.local_ai_visible_model_label_sha256
            == runtime_observation.visible_model_label_sha256
            and re.fullmatch(
                _SHA256_PATTERN,
                committed.grant.local_ai_receipt_sha256,
            )
            is not None
        )
    except ValueError:
        local_ai_ok = False
    if not local_ai_ok:
        return _decision(
            evaluated_at=at,
            status=C9AdmissionStatus.LOCAL_AI_REQUIRED,
            reason=C9AdmissionReason.LOCAL_AI_INVALID,
            cycle_id=cycle_id,
            grant_id=grant_id,
            authorization_verified=auth_ok,
            surface_observation_verified=surface_ok,
            local_ai_verified=False,
            c8_seal_verified=False,
            c8_tag_target_ancestor_of_head=False,
            grant_verified=False,
        )

    try:
        dependency = _verified_c8_dependency(root)
        c8_ok = (
            dependency.tag_target == committed.grant.c8_tag_target
            and dependency.covered_head == committed.grant.c8_covered_head
            and dependency.tree_sha256 == committed.grant.c8_tree_sha256
            and dependency.dependency_sha256 == committed.grant.c8_dependency_sha256
            and dependency.current_head == committed.grant.repository_head_at_issue
        )
        ancestry_ok = dependency.tag_target_ancestor_of_head
    except C9C8AncestryError:
        return _decision(
            evaluated_at=at,
            status=C9AdmissionStatus.C8_SEAL_REQUIRED,
            reason=C9AdmissionReason.C8_ANCESTRY_INVALID,
            cycle_id=cycle_id,
            grant_id=grant_id,
            authorization_verified=auth_ok,
            surface_observation_verified=surface_ok,
            local_ai_verified=local_ai_ok,
            c8_seal_verified=False,
            c8_tag_target_ancestor_of_head=False,
            grant_verified=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return _decision(
            evaluated_at=at,
            status=C9AdmissionStatus.C8_SEAL_REQUIRED,
            reason=C9AdmissionReason.C8_SEAL_INVALID,
            cycle_id=cycle_id,
            grant_id=grant_id,
            authorization_verified=auth_ok,
            surface_observation_verified=surface_ok,
            local_ai_verified=local_ai_ok,
            c8_seal_verified=False,
            c8_tag_target_ancestor_of_head=False,
            grant_verified=False,
        )
    if not c8_ok or not ancestry_ok:
        return _decision(
            evaluated_at=at,
            status=C9AdmissionStatus.C8_SEAL_REQUIRED,
            reason=(
                C9AdmissionReason.C8_ANCESTRY_INVALID
                if not ancestry_ok
                else C9AdmissionReason.C8_SEAL_INVALID
            ),
            cycle_id=cycle_id,
            grant_id=grant_id,
            authorization_verified=auth_ok,
            surface_observation_verified=surface_ok,
            local_ai_verified=local_ai_ok,
            c8_seal_verified=c8_ok,
            c8_tag_target_ancestor_of_head=ancestry_ok,
            grant_verified=False,
        )

    try:
        _verify_hmac(
            committed.grant,
            domain="grant",
            field_name="grant_hmac",
            audit_key=audit_key,
        )
        if not committed.grant.issued_at <= at < committed.grant.expires_at:
            raise ValueError("C9 grant is not active")
        grant_ok = (
            committed.grant.effective_tool_count == 1
            and committed.grant.effective_tools == (C9_TOOL_NAME,)
            and committed.grant.required_work_plugin_tool_call_count == 1
            and committed.grant.required_native_chat_plugin_tool_call_count == 0
            and committed.grant.required_native_chat_manual_attachment_handoff_count == 1
            and committed.grant.work_delivery_mode == "plugin_mcp_rich_content"
            and committed.grant.native_chat_delivery_mode
            == "operator_performed_manual_attachment_handoff"
            and committed.grant.work_plugin_mcp_app_required
            and not committed.grant.native_chat_plugin_mcp_app_allowed
            and not committed.grant.automatic_chat_to_work_switch_allowed
            and committed.grant.native_chat_manual_attachment_handoff_qualifies_as_success
            and not committed.grant.c8_live_cycle_grant_reused
        )
    except ValueError:
        grant_ok = False
    if not grant_ok:
        return _decision(
            evaluated_at=at,
            status=C9AdmissionStatus.SECURITY_INVARIANT,
            reason=C9AdmissionReason.GRANT_INVALID,
            cycle_id=cycle_id,
            grant_id=grant_id,
            authorization_verified=auth_ok,
            surface_observation_verified=surface_ok,
            local_ai_verified=local_ai_ok,
            c8_seal_verified=c8_ok,
            c8_tag_target_ancestor_of_head=ancestry_ok,
            grant_verified=False,
        )

    return _decision(
        evaluated_at=at,
        status=C9AdmissionStatus.READY,
        reason=C9AdmissionReason.READY,
        cycle_id=cycle_id,
        grant_id=grant_id,
        authorization_verified=auth_ok,
        surface_observation_verified=surface_ok,
        local_ai_verified=local_ai_ok,
        c8_seal_verified=c8_ok,
        c8_tag_target_ancestor_of_head=ancestry_ok,
        grant_verified=grant_ok,
    )


def verify_c9_live_cycle_bundle(
    *,
    bundle: C9LiveCycleBundle,
    root: Path,
    audit_key: str | bytes,
    evaluated_at: datetime,
) -> C9AdmissionDecision:
    return evaluate_c9_admission(
        bundle=bundle,
        root=root,
        audit_key=audit_key,
        evaluated_at=evaluated_at,
    )


def load_c9_live_cycle_bundle(path: Path) -> C9LiveCycleBundle:
    return C9LiveCycleBundle.model_validate_json(path.read_text(encoding="utf-8"))


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
    parser = argparse.ArgumentParser(description="C9 bounded live-cycle admission")
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify-bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--as-of")
    args = parser.parse_args(argv)

    try:
        audit_key = os.environ.get("SLG_AUDIT_KEY")
        if audit_key is None:
            raise ValueError("SLG_AUDIT_KEY is required")
        bundle = load_c9_live_cycle_bundle(args.bundle)
        decision = verify_c9_live_cycle_bundle(
            bundle=bundle,
            root=_repository_root(),
            audit_key=audit_key,
            evaluated_at=_parse_timestamp(args.as_of),
        )
        print(rendered_json(decision), end="")
        return 0 if decision.live_actions_allowed else 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "status": C9AdmissionStatus.SECURITY_INVARIANT.value,
                    "reason": C9AdmissionReason.BINDING_INVALID.value,
                    "live_actions_allowed": False,
                    "effective_tool_count": 0,
                    "c8_live_cycle_grant_reused": False,
                },
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
