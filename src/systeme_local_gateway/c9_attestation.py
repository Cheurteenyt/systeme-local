from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, NoReturn, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .c9_git import c9_git_text
from .c9_handoff_runtime import (
    C9ChatConfirmationReceipt,
    C9ChatExportDescriptor,
    C9ChatPickerClaimReceipt,
    C9CoordinatorCloseReceipt,
    C9HandoffAdmission,
    C9HandoffStageReceipt,
    C9RichExecutionDescriptor,
)
from .c9_live_cycle import C9_TOOL_NAME, C9AdmissionStatus
from .c9_local_ai import (
    C9LocalAIRuntimeObservation,
    c9_local_ai_runtime_observation_sha256,
    verify_c9_local_ai_runtime_observation_authenticity,
)
from .c9_seal import verify_c9_c8_seal_exact
from .c9_synthetic_fixtures import C9SyntheticFixtureKind
from .c9_work_bridge import C9RichConsumptionReceipt, C9RichSurface

C9_FINAL_STATUS = (
    "COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_ATTACHMENTS_VERIFIED_AND_REVOKED"
)
C9_ISSUE_URL = "https://github.com/Cheurteenyt/systeme-local/issues/80"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CYCLE_PATTERN = r"^c9_cycle_[0-9a-f]{32}$"
_GRANT_PATTERN = r"^c9_grant_[0-9a-f]{32}$"
_HANDOFF_PATTERN = r"^c9_handoff_[0-9a-f]{32}$"
_WORK_TASK_PATTERN = r"^c9_work_[0-9a-f]{32}$"
_CHAT_TASK_PATTERN = r"^c9_chat_[0-9a-f]{32}$"
_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
_AUDIT_ID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_MAX_METADATA_BYTES = 2 * 1024 * 1024
_MAX_AUDIT_BYTES = 16 * 1024 * 1024

_DOMAIN = {
    "negative": b"systeme-local/c9/negative-tests/v1\0",
    "correlation": b"systeme-local/c9/rich-audit-correlation/v1\0",
    "revocation": b"systeme-local/c9/revocation/v1\0",
    "final": b"systeme-local/c9/final-attestation/v1\0",
}
_LIVE_CYCLE_DOMAIN = {
    "authorization_hmac": b"systeme-local/c9/operator-authorization/v1\0",
    "observation_hmac": b"systeme-local/c9/surface-observation/v1\0",
    "grant_hmac": b"systeme-local/c9/live-cycle-grant/v1\0",
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


def _audit_key(value: str | bytes) -> bytes:
    encoded = value.encode("utf-8") if isinstance(value, str) else value
    if len(encoded) < 32:
        raise ValueError("C9 attestation requires an audit key of at least 32 bytes")
    return encoded


def _commit_hmac(
    *,
    domain: Literal["negative", "correlation", "revocation", "final"],
    payload: dict[str, Any],
    audit_key: str | bytes,
) -> str:
    return hmac.new(
        _audit_key(audit_key),
        _DOMAIN[domain] + _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


def _verify_hmac(
    model: BaseModel,
    *,
    domain: Literal["negative", "correlation", "revocation", "final"],
    field_name: str,
    audit_key: str | bytes,
) -> None:
    payload = model.model_dump(mode="json", exclude={str(field_name)})
    expected = _commit_hmac(domain=domain, payload=payload, audit_key=audit_key)
    if not hmac.compare_digest(str(getattr(model, field_name)), expected):
        raise ValueError("C9 attestation evidence authentication failed")


def _verify_live_cycle_hmac(
    model: BaseModel,
    *,
    field_name: Literal[
        "authorization_hmac",
        "observation_hmac",
        "grant_hmac",
    ],
    audit_key: str | bytes,
) -> None:
    payload = model.model_dump(mode="json", exclude={str(field_name)})
    expected = hmac.new(
        _audit_key(audit_key),
        _LIVE_CYCLE_DOMAIN[field_name] + _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(str(getattr(model, field_name)), expected):
        raise ValueError("C9 live-cycle evidence authentication failed")


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )


class C9NegativeCheckId(StrEnum):
    WORK_REPLAY = "work_replay"
    CHAT_MANUAL_REPLAY = "chat_manual_replay"
    CROSS_MODE_REPLAY = "cross_mode_replay"
    CROSS_HANDOFF_REPLAY = "cross_handoff_replay"
    CHAT_MCP_REQUEST = "chat_mcp_request"
    MALFORMED_REQUEST = "malformed_request"
    UNKNOWN_FIELD = "unknown_field"
    UNAPPROVED_FALLBACK_USE = "unapproved_fallback_use"
    AUTOMATIC_CHAT_TO_WORK_SWITCH = "automatic_chat_to_work_switch"
    UNSAFE_FILE_REQUEST = "unsafe_file_request"
    REMOTE_LOCAL_AI_REQUEST = "remote_local_ai_request"
    AUTHENTICATED_LOCAL_AI_REQUEST = "authenticated_local_ai_request"
    COMMAND_EXECUTION_REQUEST = "command_execution_request"
    SECRET_REQUEST = "secret_request"
    WRITE_OPERATION_REQUEST = "write_operation_request"
    REAL_EVIDENCE_REQUEST = "real_evidence_request"
    PROTOCOL_V2_REQUEST = "protocol_v2_request"


class C9NegativeOutcome(StrEnum):
    REJECTED = "rejected"
    DENIED = "denied"
    CAPABILITY_NOT_EXPOSED = "capability_not_exposed"
    NON_QUALIFYING = "non_qualifying"


def _required_negative_outcomes() -> dict[C9NegativeCheckId, C9NegativeOutcome]:
    return {
        C9NegativeCheckId.WORK_REPLAY: C9NegativeOutcome.REJECTED,
        C9NegativeCheckId.CHAT_MANUAL_REPLAY: C9NegativeOutcome.REJECTED,
        C9NegativeCheckId.CROSS_MODE_REPLAY: C9NegativeOutcome.REJECTED,
        C9NegativeCheckId.CROSS_HANDOFF_REPLAY: C9NegativeOutcome.REJECTED,
        C9NegativeCheckId.CHAT_MCP_REQUEST: C9NegativeOutcome.CAPABILITY_NOT_EXPOSED,
        C9NegativeCheckId.MALFORMED_REQUEST: C9NegativeOutcome.REJECTED,
        C9NegativeCheckId.UNKNOWN_FIELD: C9NegativeOutcome.REJECTED,
        C9NegativeCheckId.UNAPPROVED_FALLBACK_USE: C9NegativeOutcome.DENIED,
        C9NegativeCheckId.AUTOMATIC_CHAT_TO_WORK_SWITCH: C9NegativeOutcome.DENIED,
        C9NegativeCheckId.UNSAFE_FILE_REQUEST: C9NegativeOutcome.DENIED,
        C9NegativeCheckId.REMOTE_LOCAL_AI_REQUEST: C9NegativeOutcome.DENIED,
        C9NegativeCheckId.AUTHENTICATED_LOCAL_AI_REQUEST: C9NegativeOutcome.DENIED,
        C9NegativeCheckId.COMMAND_EXECUTION_REQUEST: (C9NegativeOutcome.CAPABILITY_NOT_EXPOSED),
        C9NegativeCheckId.SECRET_REQUEST: C9NegativeOutcome.CAPABILITY_NOT_EXPOSED,
        C9NegativeCheckId.WRITE_OPERATION_REQUEST: (C9NegativeOutcome.CAPABILITY_NOT_EXPOSED),
        C9NegativeCheckId.REAL_EVIDENCE_REQUEST: (C9NegativeOutcome.CAPABILITY_NOT_EXPOSED),
        C9NegativeCheckId.PROTOCOL_V2_REQUEST: (C9NegativeOutcome.CAPABILITY_NOT_EXPOSED),
    }


C9_NEGATIVE_SUITE_ID: Literal["c9_bounded_negative_contract_v1"] = "c9_bounded_negative_contract_v1"
_UNSAFE_ATTACHMENT_NODEID = (
    "tests/test_c9_attachment_security.py::test_rejects_lexical_traversal_magic_mismatch_and_pdf"
)
_MANIFEST_TAMPERING_NODEID = (
    "tests/test_c9_attachment_security.py::test_manifest_tampering_and_unknown_fields_are_rejected"
)
_WORK_AND_CHAT_ONE_USE_NODEID = (
    "tests/test_c9_handoff_runtime.py::"
    "test_work_then_native_chat_manual_is_strict_and_both_halves_are_one_use"
)
_CHAT_NONCE_REPLAY_NODEID = (
    "tests/test_c9_handoff_runtime.py::"
    "test_native_chat_nonce_mismatch_consumes_proof_and_deletes_export"
)
_CHAT_MCP_UNSUPPORTED_NODEID = (
    "tests/test_c9_handoff_runtime.py::"
    "test_chat_mcp_execute_render_confirm_and_legacy_fallback_are_unsupported"
)
_FORBIDDEN_CHAT_MCP_NODEID = (
    "tests/test_c9_handoff_runtime.py::"
    "test_forbidden_chat_mcp_attempt_after_work_blocks_manual_chat_handoff"
)
_CHAT_SUBSTITUTED_CLAIM_NODEID = (
    "tests/test_c9_handoff_runtime.py::"
    "test_native_chat_rejects_substituted_picker_claim_and_deletes_export"
)
_CHAT_FREE_TEXT_NODEID = (
    "tests/test_c9_handoff_runtime.py::"
    "test_native_chat_rejects_free_text_even_when_both_nonces_are_present"
)
_CHAT_MUTATED_EXPORT_NODEID = (
    "tests/test_c9_handoff_runtime.py::"
    "test_native_chat_refuses_mutated_export_even_after_valid_nonce_response"
)
_CHAT_EXPIRED_CLAIM_NODEID = (
    "tests/test_c9_handoff_runtime.py::"
    "test_native_chat_path_claim_rejects_expired_grant_before_export_ttl"
)
_CHAT_EXPIRED_CONFIRMATION_NODEID = (
    "tests/test_c9_handoff_runtime.py::"
    "test_native_chat_confirmation_rechecks_expiry_after_picker_claim"
)
_CROSS_HANDOFF_NODEID = (
    "tests/test_c9_handoff_runtime.py::test_cross_handoff_and_expired_grant_fail_closed"
)
_STRICT_CAPABILITY_HANDLER_NODEID = (
    "tests/test_c9_handoff_runtime.py::test_capability_handler_is_strict_and_returns_only_metadata"
)
_WORK_ONLY_PROVIDER_RESPONSE_NODEID = (
    "tests/test_c9_control_api.py::test_provider_response_parser_is_strictly_work_only"
)
_STRICT_PROVIDER_RESPONSE_NODEID = (
    "tests/test_c9_control_api.py::"
    "test_provider_response_parsers_reject_duplicate_unknown_and_malformed_values"
)
_STRICT_CHAT_RESPONSE_NODEID = (
    "tests/test_c9_control_api.py::"
    "test_native_chat_response_parser_requires_exact_manual_handoff_json"
)
_CROSS_MODE_CONTROL_NODEID = (
    "tests/test_c9_control_api.py::test_control_rejects_mismatched_work_and_native_chat_receipts"
)
_CHAT_MCP_ADMISSION_NODEID = (
    "tests/test_c9_live_cycle.py::"
    "test_native_chat_manual_handoff_is_required_and_chat_mcp_cannot_be_admitted"
)
_DENIED_SCOPE_NODEID = (
    "tests/test_c9_live_cycle.py::test_exact_one_tool_schema_rejects_expansion_and_unknown_fields"
)
_EXACT_TOOL_CONTRACT_NODEID = (
    "tests/test_c9_mcp_tool.py::test_c9_tool_has_exact_work_only_input_and_truthful_annotations"
)
_EXACT_TOOL_REGISTRY_NODEID = (
    "tests/test_c9_mcp_tool.py::test_c9_registry_exposes_exactly_one_policy_admitted_tool"
)
_REMOTE_LOCAL_AI_NODEID = (
    "tests/test_c9_local_ai.py::test_endpoint_rejects_ambiguous_or_non_loopback_targets"
)
_AUTHENTICATED_LOCAL_AI_NODEID = (
    "tests/test_c9_local_ai.py::test_config_errors_hide_endpoint_input_and_forbid_auth_fields"
)
_MANUAL_EXPORT_PATH_NODEID = (
    "tests/test_c9_manual_export.py::test_rejects_path_escape_in_unvalidated_descriptor"
)
C9_NEGATIVE_SUITE_NODEIDS = (
    _UNSAFE_ATTACHMENT_NODEID,
    _MANIFEST_TAMPERING_NODEID,
    _WORK_AND_CHAT_ONE_USE_NODEID,
    _CHAT_NONCE_REPLAY_NODEID,
    _CHAT_MCP_UNSUPPORTED_NODEID,
    _FORBIDDEN_CHAT_MCP_NODEID,
    _CHAT_SUBSTITUTED_CLAIM_NODEID,
    _CHAT_FREE_TEXT_NODEID,
    _CHAT_MUTATED_EXPORT_NODEID,
    _CHAT_EXPIRED_CLAIM_NODEID,
    _CHAT_EXPIRED_CONFIRMATION_NODEID,
    _CROSS_HANDOFF_NODEID,
    _STRICT_CAPABILITY_HANDLER_NODEID,
    _WORK_ONLY_PROVIDER_RESPONSE_NODEID,
    _STRICT_PROVIDER_RESPONSE_NODEID,
    _STRICT_CHAT_RESPONSE_NODEID,
    _CROSS_MODE_CONTROL_NODEID,
    _CHAT_MCP_ADMISSION_NODEID,
    _DENIED_SCOPE_NODEID,
    _EXACT_TOOL_CONTRACT_NODEID,
    _EXACT_TOOL_REGISTRY_NODEID,
    _REMOTE_LOCAL_AI_NODEID,
    _AUTHENTICATED_LOCAL_AI_NODEID,
    _MANUAL_EXPORT_PATH_NODEID,
)


def _required_negative_evidence() -> dict[C9NegativeCheckId, tuple[str, ...]]:
    capability_not_exposed = (
        _DENIED_SCOPE_NODEID,
        _EXACT_TOOL_CONTRACT_NODEID,
        _EXACT_TOOL_REGISTRY_NODEID,
    )
    return {
        C9NegativeCheckId.WORK_REPLAY: (_WORK_AND_CHAT_ONE_USE_NODEID,),
        C9NegativeCheckId.CHAT_MANUAL_REPLAY: (
            _WORK_AND_CHAT_ONE_USE_NODEID,
            _CHAT_NONCE_REPLAY_NODEID,
        ),
        C9NegativeCheckId.CROSS_MODE_REPLAY: (
            _CROSS_MODE_CONTROL_NODEID,
            _WORK_ONLY_PROVIDER_RESPONSE_NODEID,
            _FORBIDDEN_CHAT_MCP_NODEID,
        ),
        C9NegativeCheckId.CROSS_HANDOFF_REPLAY: (_CROSS_HANDOFF_NODEID,),
        C9NegativeCheckId.CHAT_MCP_REQUEST: (
            _CHAT_MCP_ADMISSION_NODEID,
            _CHAT_MCP_UNSUPPORTED_NODEID,
            _FORBIDDEN_CHAT_MCP_NODEID,
            _EXACT_TOOL_CONTRACT_NODEID,
        ),
        C9NegativeCheckId.MALFORMED_REQUEST: (
            _STRICT_CAPABILITY_HANDLER_NODEID,
            _STRICT_PROVIDER_RESPONSE_NODEID,
            _STRICT_CHAT_RESPONSE_NODEID,
            _CHAT_FREE_TEXT_NODEID,
        ),
        C9NegativeCheckId.UNKNOWN_FIELD: (
            _MANIFEST_TAMPERING_NODEID,
            _STRICT_CAPABILITY_HANDLER_NODEID,
            _STRICT_PROVIDER_RESPONSE_NODEID,
            _STRICT_CHAT_RESPONSE_NODEID,
            _CHAT_SUBSTITUTED_CLAIM_NODEID,
        ),
        C9NegativeCheckId.UNAPPROVED_FALLBACK_USE: (
            _CROSS_MODE_CONTROL_NODEID,
            _CHAT_MCP_ADMISSION_NODEID,
            _CHAT_MCP_UNSUPPORTED_NODEID,
        ),
        C9NegativeCheckId.AUTOMATIC_CHAT_TO_WORK_SWITCH: (_DENIED_SCOPE_NODEID,),
        C9NegativeCheckId.UNSAFE_FILE_REQUEST: (
            _UNSAFE_ATTACHMENT_NODEID,
            _MANUAL_EXPORT_PATH_NODEID,
            _CHAT_MUTATED_EXPORT_NODEID,
            _CHAT_EXPIRED_CLAIM_NODEID,
            _CHAT_EXPIRED_CONFIRMATION_NODEID,
            _DENIED_SCOPE_NODEID,
        ),
        C9NegativeCheckId.REMOTE_LOCAL_AI_REQUEST: (_REMOTE_LOCAL_AI_NODEID,),
        C9NegativeCheckId.AUTHENTICATED_LOCAL_AI_REQUEST: (
            _AUTHENTICATED_LOCAL_AI_NODEID,
            _DENIED_SCOPE_NODEID,
        ),
        C9NegativeCheckId.COMMAND_EXECUTION_REQUEST: capability_not_exposed,
        C9NegativeCheckId.SECRET_REQUEST: capability_not_exposed,
        C9NegativeCheckId.WRITE_OPERATION_REQUEST: capability_not_exposed,
        C9NegativeCheckId.REAL_EVIDENCE_REQUEST: capability_not_exposed,
        C9NegativeCheckId.PROTOCOL_V2_REQUEST: capability_not_exposed,
    }


def _negative_source_paths() -> tuple[str, ...]:
    return tuple(sorted({node_id.split("::", 1)[0] for node_id in C9_NEGATIVE_SUITE_NODEIDS}))


class C9AutomatedNegativeSuiteEvidence(_StrictModel):
    version: Literal["1"] = "1"
    source: Literal["isolated_pytest_subprocess"]
    simulated: Literal[False]
    suite_id: Literal["c9_bounded_negative_contract_v1"]
    repository_head: str = Field(pattern=_COMMIT_PATTERN)
    node_ids: tuple[str, ...]
    evidence_node_ids: dict[C9NegativeCheckId, tuple[str, ...]]
    selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_sha256s: dict[str, str]
    output_sha256: str = Field(pattern=_SHA256_PATTERN)
    exit_code: Literal[0]
    passed_count: int = Field(ge=1)
    failed_count: Literal[0]
    skipped_count: Literal[0]
    warning_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_exact_suite(self) -> C9AutomatedNegativeSuiteEvidence:
        if self.node_ids != C9_NEGATIVE_SUITE_NODEIDS:
            raise ValueError("C9 automated negative suite selection is not exact")
        if self.evidence_node_ids != _required_negative_evidence():
            raise ValueError("C9 automated negative evidence mapping is not exact")
        if self.selection_sha256 != canonical_sha256(list(self.node_ids)):
            raise ValueError("C9 automated negative suite selection digest mismatch")
        if set(self.source_sha256s) != set(_negative_source_paths()):
            raise ValueError("C9 automated negative suite source set is not exact")
        if any(
            re.fullmatch(_SHA256_PATTERN, digest) is None for digest in self.source_sha256s.values()
        ):
            raise ValueError("C9 automated negative suite source digest is invalid")
        if self.passed_count < len(self.node_ids):
            raise ValueError("C9 automated negative suite pass count is incomplete")
        return self


class C9NegativeTestReceipt(_StrictModel):
    version: Literal["1"] = "1"
    source: Literal["automated_bounded_c9_negative_tests"]
    simulated: Literal[False]
    cycle_id: str = Field(pattern=_CYCLE_PATTERN)
    grant_id: str = Field(pattern=_GRANT_PATTERN)
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)
    outcomes: dict[C9NegativeCheckId, C9NegativeOutcome]
    automated_suite: C9AutomatedNegativeSuiteEvidence
    capability_expanded: Literal[False]
    work_task_count: Literal[1]
    native_chat_task_count: Literal[1]
    work_rich_mcp_call_count: Literal[1]
    native_chat_manual_handoff_count: Literal[1]
    total_rich_mcp_call_count: Literal[1]
    native_chat_delivery_mode: Literal["operator_performed_manual_attachment_handoff"]
    native_chat_plugin_invoked: Literal[False]
    native_chat_provider_audit_correlation_claimed: Literal[False]
    unapproved_fallback_used: Literal[False]
    automatic_chat_to_work_switch_used: Literal[False]
    observation_semantics: Literal["automated_offline_contract_suite_after_coordinator_close"]
    regular_arbitrary_files_tested: Literal[False]
    existing_conversations_accessed: Literal[False]
    history_accessed: Literal[False]
    private_browser_state_accessed: Literal[False]
    observed_at: datetime
    receipt_hmac: str = Field(pattern=_SHA256_PATTERN)

    _observed_utc = field_validator("observed_at")(_utc)

    @model_validator(mode="after")
    def validate_outcomes(self) -> C9NegativeTestReceipt:
        if self.outcomes != _required_negative_outcomes():
            raise ValueError("C9 negative receipt does not contain the exact bounded outcomes")
        return self


class C9RichAuditCorrelationReceipt(_StrictModel):
    version: Literal["1"] = "1"
    source: Literal["verified_local_c9_hmac_audit_log"]
    simulated: Literal[False]
    cycle_id: str = Field(pattern=_CYCLE_PATTERN)
    grant_id: str = Field(pattern=_GRANT_PATTERN)
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)
    surface: Literal[C9RichSurface.WORK]
    surface_task_id: str = Field(pattern=_WORK_TASK_PATTERN)
    capability: Literal["systeme_local_attachment_handoff"]
    handoff_admission_sha256: str = Field(pattern=_SHA256_PATTERN)
    rich_execution_sha256: str = Field(pattern=_SHA256_PATTERN)
    expansion_descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    consumption_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_id_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_processor_audit_id: str = Field(pattern=_AUDIT_ID_PATTERN)
    render_audit_id: str = Field(pattern=_AUDIT_ID_PATTERN)
    task_audit_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    render_audit_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_status: Literal["completed"]
    render_status: Literal["render_completed"]
    render_content_recorded: Literal[False]
    c9_tool_audit_record_count: Literal[2]
    native_chat_plugin_attempt_audit_record_count: Literal[0]
    audit_records_verified: int = Field(ge=2)
    audit_chain_last_hmac: str = Field(pattern=_SHA256_PATTERN)
    correlated_at: datetime
    receipt_hmac: str = Field(pattern=_SHA256_PATTERN)

    _correlated_utc = field_validator("correlated_at")(_utc)

    @model_validator(mode="after")
    def validate_correlation(self) -> C9RichAuditCorrelationReceipt:
        if self.task_processor_audit_id == self.render_audit_id:
            raise ValueError("C9 task and render audit ids must be distinct")
        if self.task_audit_record_sha256 == self.render_audit_record_sha256:
            raise ValueError("C9 task and render audit records must be distinct")
        return self


# Temporary import compatibility for downstream code while C9 remains unmerged.
C9WorkAuditCorrelationReceipt = C9RichAuditCorrelationReceipt


class C9RevocationReceipt(_StrictModel):
    version: Literal["1"] = "1"
    source: Literal["manual_operator_and_local_c9_revocation"]
    simulated: Literal[False]
    cycle_id: str = Field(pattern=_CYCLE_PATTERN)
    grant_id: str = Field(pattern=_GRANT_PATTERN)
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)
    coordinator_close_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    coordinator_closed: Literal[True]
    admission_file_removed: Literal[True]
    listener_8765_stopped: Literal[True]
    listener_8766_stopped: Literal[True]
    plugin_connection_removed: Literal[True]
    runtime_api_key_revoked: Literal[True]
    transport_secrets_cleared: Literal[True]
    runtime_secrets_cleared: Literal[True]
    control_secret_cleared: Literal[True]
    manual_export_absent: Literal[True]
    synthetic_fixtures_absent: Literal[True]
    post_revocation_work_app_call_failed: Literal[True]
    post_revocation_chat_export_and_claim_failed: Literal[True]
    post_revocation_control_call_failed: Literal[True]
    verified_at: datetime
    receipt_hmac: str = Field(pattern=_SHA256_PATTERN)

    _verified_utc = field_validator("verified_at")(_utc)


class C9FinalAttestation(_StrictModel):
    version: Literal["1"] = "1"
    status: Literal[
        "COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_ATTACHMENTS_VERIFIED_AND_REVOKED"
    ]
    source: Literal["bounded_synthetic_c9_final_verifier"]
    simulated: Literal[False]
    issue_url: Literal["https://github.com/Cheurteenyt/systeme-local/issues/80"]
    cycle_id: str = Field(pattern=_CYCLE_PATTERN)
    grant_id: str = Field(pattern=_GRANT_PATTERN)
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)
    work_task_id: str = Field(pattern=_WORK_TASK_PATTERN)
    chat_task_id: str = Field(pattern=_CHAT_TASK_PATTERN)
    c9_live_repository_head: str = Field(pattern=_COMMIT_PATTERN)
    accepted_c8_commit: str = Field(pattern=_COMMIT_PATTERN)
    c8_covered_head: str = Field(pattern=_COMMIT_PATTERN)
    c8_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    c8_final_attestation_sha256: str = Field(pattern=_SHA256_PATTERN)
    c8_dependency_sha256: str = Field(pattern=_SHA256_PATTERN)
    c8_reviewed_outcome: Literal["COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"]
    c8_revocation_verified: Literal[True]
    c8_live_cycle_grant_reused: Literal[False]
    authorization_sha256: str = Field(pattern=_SHA256_PATTERN)
    surface_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    grant_sha256: str = Field(pattern=_SHA256_PATTERN)
    stage_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    handoff_admission_sha256: str = Field(pattern=_SHA256_PATTERN)
    combined_approval_sha256: str = Field(pattern=_SHA256_PATTERN)
    work_approval_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_approval_sha256: str = Field(pattern=_SHA256_PATTERN)
    fixture_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_ai_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_ai_runtime_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    work_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_export_id: str = Field(pattern=r"^c9_export_[0-9a-f]{32}$")
    chat_export_descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_export_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_picker_claim_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    attachment_content_sha256s: tuple[str, str]
    attachment_nonce_sha256s: tuple[str, str]
    work_consumption_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_manual_confirmation_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_manual_cleanup_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    work_audit_correlation_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    work_task_audit_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    work_render_audit_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    coordinator_close_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    negative_test_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    revocation_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    work_rich_call_count: Literal[1]
    chat_manual_handoff_count: Literal[1]
    total_rich_mcp_call_count: Literal[1]
    work_rich_mcp_verified: Literal[True]
    chat_manual_visible_handoff_verified: Literal[True]
    same_sanitized_package_verified: Literal[True]
    native_chat_plugin_invoked: Literal[False]
    native_chat_provider_audit_correlation_claimed: Literal[False]
    unapproved_fallback_used: Literal[False]
    local_ai_loopback_receipt_committed: Literal[True]
    local_ai_native_runtime_observation_committed: Literal[True]
    regular_arbitrary_files_tested: Literal[False]
    regular_use_readiness_claimed: Literal[False]
    automatic_chat_to_work_switch_used: Literal[False]
    revocation_verified: Literal[True]
    verified_at: datetime
    attestation_sha256: str = Field(pattern=_SHA256_PATTERN)
    attestation_hmac: str = Field(pattern=_SHA256_PATTERN)

    _verified_utc = field_validator("verified_at")(_utc)

    @model_validator(mode="after")
    def validate_attestation(self) -> C9FinalAttestation:
        for pair in (
            self.attachment_content_sha256s,
            self.attachment_nonce_sha256s,
        ):
            if len(pair) != 2 or len(set(pair)) != 2:
                raise ValueError("C9 final attachment commitments must be two distinct hashes")
            if any(re.fullmatch(_SHA256_PATTERN, item) is None for item in pair):
                raise ValueError("C9 final attachment commitment is invalid")
        exact_evidence_hashes = (
            self.chat_export_descriptor_sha256,
            self.chat_export_sha256,
            self.chat_picker_claim_receipt_sha256,
            self.work_consumption_receipt_sha256,
            self.chat_manual_confirmation_receipt_sha256,
            self.chat_manual_cleanup_receipt_sha256,
            self.work_audit_correlation_receipt_sha256,
            self.coordinator_close_receipt_sha256,
            self.negative_test_receipt_sha256,
            self.revocation_receipt_sha256,
        )
        if len(set(exact_evidence_hashes)) != len(exact_evidence_hashes):
            raise ValueError(
                "C9 final Work, Chat, cleanup and revocation evidence must be distinct"
            )
        payload = self.model_dump(
            mode="json",
            exclude={"attestation_sha256", "attestation_hmac"},
        )
        if self.attestation_sha256 != canonical_sha256(payload):
            raise ValueError("C9 final attestation digest mismatch")
        return self


def commit_negative_test_receipt(
    *,
    cycle_id: str,
    grant_id: str,
    handoff_id: str,
    outcomes: dict[C9NegativeCheckId, C9NegativeOutcome],
    automated_suite: C9AutomatedNegativeSuiteEvidence,
    observed_at: datetime,
    audit_key: str | bytes,
) -> C9NegativeTestReceipt:
    payload: dict[str, Any] = {
        "version": "1",
        "source": "automated_bounded_c9_negative_tests",
        "simulated": False,
        "cycle_id": cycle_id,
        "grant_id": grant_id,
        "handoff_id": handoff_id,
        "outcomes": {
            check.value: outcome.value
            for check, outcome in sorted(
                outcomes.items(),
                key=lambda item: item[0].value,
            )
        },
        "automated_suite": automated_suite.model_dump(mode="json"),
        "capability_expanded": False,
        "work_task_count": 1,
        "native_chat_task_count": 1,
        "work_rich_mcp_call_count": 1,
        "native_chat_manual_handoff_count": 1,
        "total_rich_mcp_call_count": 1,
        "native_chat_delivery_mode": "operator_performed_manual_attachment_handoff",
        "native_chat_plugin_invoked": False,
        "native_chat_provider_audit_correlation_claimed": False,
        "unapproved_fallback_used": False,
        "automatic_chat_to_work_switch_used": False,
        "observation_semantics": ("automated_offline_contract_suite_after_coordinator_close"),
        "regular_arbitrary_files_tested": False,
        "existing_conversations_accessed": False,
        "history_accessed": False,
        "private_browser_state_accessed": False,
        "observed_at": _timestamp(observed_at),
    }
    return C9NegativeTestReceipt(
        **payload,
        receipt_hmac=_commit_hmac(
            domain="negative",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_negative_test_receipt(
    receipt: C9NegativeTestReceipt,
    *,
    audit_key: str | bytes,
) -> C9NegativeTestReceipt:
    committed = C9NegativeTestReceipt.model_validate(receipt.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="negative",
        field_name="receipt_hmac",
        audit_key=audit_key,
    )
    return committed


def _sha256_regular_repository_file(path: Path, *, maximum_bytes: int) -> str:
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or _is_reparse(before)
        or int(before.st_nlink) != 1
        or int(before.st_size) > maximum_bytes
    ):
        raise ValueError("C9 negative suite source is not a trusted regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not _same_file_identity(before, opened):
            raise ValueError("C9 negative suite source changed before hashing")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise ValueError("C9 negative suite source exceeds its byte limit")
            digest.update(chunk)
        after_descriptor = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = os.lstat(path)
    if not _same_file_identity(before, after_descriptor) or not _same_file_identity(
        before, after_path
    ):
        raise ValueError("C9 negative suite source changed while hashing")
    return digest.hexdigest()


def run_automated_negative_suite(
    *,
    repository_root: Path,
    metadata_root: Path,
) -> C9AutomatedNegativeSuiteEvidence:
    root = _lexical_absolute(repository_root)
    state = _lexical_absolute(metadata_root)
    if not root.is_dir() or not state.is_dir():
        raise ValueError("C9 negative suite root is unavailable")
    source_sha256s: dict[str, str] = {}
    for relative in _negative_source_paths():
        candidate = _lexical_absolute(root / relative)
        if os.path.normcase(
            os.path.commonpath((os.fspath(root), os.fspath(candidate)))
        ) != os.path.normcase(os.fspath(root)):
            raise ValueError("C9 negative suite source escapes the repository")
        source_sha256s[relative] = _sha256_regular_repository_file(
            candidate,
            maximum_bytes=2 * 1024 * 1024,
        )

    temporary_parent = Path(tempfile.mkdtemp(prefix=".negative-suite-", dir=os.fspath(state)))
    basetemp = temporary_parent / "pytest"
    command = (
        sys.executable,
        "-I",
        "-X",
        "utf8",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "--disable-warnings",
        "--tb=short",
        "-q",
        "--basetemp",
        os.fspath(basetemp),
        *C9_NEGATIVE_SUITE_NODEIDS,
    )
    child_environment = {
        name: value
        for name in (
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
        )
        if (value := os.environ.get(name))
    }
    child_environment.update(
        {
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "NO_PROXY": "127.0.0.1,localhost",
        }
    )
    completed: subprocess.CompletedProcess[bytes] | None = None
    cleanup_error: OSError | None = None
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=child_environment,
            check=False,
            capture_output=True,
            timeout=300,
        )
    finally:
        try:
            shutil.rmtree(temporary_parent)
        except OSError as exc:
            cleanup_error = exc
    if cleanup_error is not None:
        raise ValueError("C9 negative suite temporary cleanup failed")
    if completed is None:
        raise ValueError("C9 negative suite did not run")
    combined_output = completed.stdout + b"\0" + completed.stderr
    if len(combined_output) > 1024 * 1024:
        raise ValueError("C9 negative suite output exceeded its byte limit")
    decoded = combined_output.decode("utf-8", errors="strict")
    if completed.returncode != 0:
        raise ValueError("C9 automated negative suite failed")
    lowered = decoded.casefold()
    forbidden_summaries = (
        " failed",
        " error",
        " skipped",
        " xfailed",
        " xpassed",
        " deselected",
    )
    if any(summary in lowered for summary in forbidden_summaries):
        raise ValueError("C9 automated negative suite was not fully successful")
    matches = re.findall(
        r"(?m)^(\d+) passed(?:, (\d+) warnings?)? in [0-9.]+s\s*$",
        decoded,
    )
    if len(matches) != 1:
        raise ValueError("C9 automated negative suite summary is ambiguous")
    passed_count = int(matches[0][0])
    warning_count = int(matches[0][1] or "0")
    return C9AutomatedNegativeSuiteEvidence(
        source="isolated_pytest_subprocess",
        simulated=False,
        suite_id=C9_NEGATIVE_SUITE_ID,
        repository_head=_current_repository_head(root),
        node_ids=C9_NEGATIVE_SUITE_NODEIDS,
        evidence_node_ids=_required_negative_evidence(),
        selection_sha256=canonical_sha256(list(C9_NEGATIVE_SUITE_NODEIDS)),
        source_sha256s=source_sha256s,
        output_sha256=hashlib.sha256(combined_output).hexdigest(),
        exit_code=0,
        passed_count=passed_count,
        failed_count=0,
        skipped_count=0,
        warning_count=warning_count,
    )


def _audit_payload_hmac(value: object, audit_key: str | bytes) -> str:
    return hmac.new(
        _audit_key(audit_key),
        b"audit-payload-v1\0" + _canonical_json(value),
        hashlib.sha256,
    ).hexdigest()


def _record_timestamp(record: dict[str, Any]) -> datetime:
    value = record.get("timestamp")
    if not isinstance(value, str):
        raise ValueError("C9 audit record timestamp is invalid")
    return _parse_timestamp(value)


def _summary_hmac(record: dict[str, Any], field: str) -> str:
    summary = record.get(field)
    if not isinstance(summary, dict):
        raise ValueError("C9 audit record summary is missing")
    value = summary.get("hmac_sha256")
    if not isinstance(value, str) or re.fullmatch(_SHA256_PATTERN, value) is None:
        raise ValueError("C9 audit record summary authentication is invalid")
    return value


def _summary_keys(record: dict[str, Any], field: str) -> tuple[str, ...]:
    summary = record.get(field)
    if not isinstance(summary, dict):
        raise ValueError("C9 audit record summary is missing")
    keys = summary.get("keys")
    if (
        not isinstance(keys, list)
        or not all(isinstance(item, str) for item in keys)
        or summary.get("keys_truncated") is not False
    ):
        raise ValueError("C9 audit record summary keys are invalid")
    return tuple(keys)


def commit_rich_audit_correlation_receipt(
    *,
    admission: C9HandoffAdmission,
    rich_execution: C9RichExecutionDescriptor,
    consumption_receipt: C9RichConsumptionReceipt,
    audit_log_path: Path,
    metadata_root: Path,
    correlated_at: datetime,
    audit_key: str | bytes,
) -> C9RichAuditCorrelationReceipt:
    committed_admission = C9HandoffAdmission.model_validate(admission.model_dump(mode="python"))
    execution = C9RichExecutionDescriptor.model_validate(rich_execution.model_dump(mode="python"))
    consumption = C9RichConsumptionReceipt.model_validate(
        consumption_receipt.model_dump(mode="python")
    )
    grant = committed_admission.live_cycle_bundle.grant
    combined = committed_admission.combined_approval
    if execution.surface is not C9RichSurface.WORK or consumption.surface is not C9RichSurface.WORK:
        raise ValueError("C9 audit correlation is available only for the Work MCP leg")
    expected_manifest_sha256 = combined.work_manifest_sha256
    expected_approval_sha256 = combined.work_approval_sha256
    if (
        execution.handoff_id != committed_admission.handoff_id
        or execution.c9_cycle_id != grant.cycle_id
        or execution.c9_grant_id != grant.grant_id
        or execution.accepted_c8_commit != grant.c8_tag_target
        or execution.combined_approval_sha256 != combined.combined_approval_sha256
        or execution.surface_manifest_sha256 != expected_manifest_sha256
        or consumption.c9_cycle_id != grant.cycle_id
        or consumption.c9_grant_id != grant.grant_id
    ):
        raise ValueError("C9 audit correlation inputs cross evidence boundaries")
    if (
        consumption.surface is not execution.surface
        or consumption.surface_task_id != execution.surface_task_id
        or consumption.accepted_c8_commit != execution.accepted_c8_commit
        or consumption.manifest_sha256 != execution.surface_manifest_sha256
        or consumption.descriptor_sha256 != execution.expansion_descriptor_sha256
        or consumption.approval_sha256 != expected_approval_sha256
        or consumption.observed_at < execution.executed_at
    ):
        raise ValueError("C9 rich receipt does not bind its execution descriptor")

    records, last_hmac = _load_verified_audit_records(
        audit_log_path,
        metadata_root=metadata_root,
        audit_key=audit_key,
    )
    c9_tool_records = tuple(
        (index, record)
        for index, record in enumerate(records)
        if record.get("capability") == C9_TOOL_NAME
    )
    if len(c9_tool_records) != 2:
        raise ValueError(
            "C9 correlation requires exactly one Work task record and one Work render record"
        )
    task_candidates = [
        (index, record)
        for index, record in enumerate(records)
        if record.get("capability") == C9_TOOL_NAME
        and record.get("status") == "completed"
        and isinstance(record.get("task_id"), str)
        and _summary_keys(record, "output_summary")
        == tuple(sorted(C9RichExecutionDescriptor.model_fields))
        and _summary_keys(record, "arguments_summary") == ("handoff_id", "surface")
        and _summary_hmac(record, "arguments_summary")
        == _audit_payload_hmac(
            {
                "handoff_id": committed_admission.handoff_id,
                "surface": execution.surface.value,
            },
            audit_key,
        )
        and _summary_hmac(record, "output_summary")
        == _audit_payload_hmac(execution.model_dump(mode="json"), audit_key)
        and isinstance(record.get("agent"), dict)
        and record["agent"].get("provider") == "mcp"
    ]
    if len(task_candidates) != 1:
        raise ValueError("C9 requires one unique completed TaskProcessor audit record")
    task_index, task_record = task_candidates[0]
    task_id = str(task_record["task_id"])
    if any(
        record.get("task_id") == task_id
        and record.get("capability") == C9_TOOL_NAME
        and record.get("status") == "render_failed"
        for record in records
    ):
        raise ValueError("C9 renderer failure invalidates rich audit correlation")
    render_candidates = [
        (index, record)
        for index, record in enumerate(records)
        if record.get("task_id") == task_id
        and record.get("capability") == C9_TOOL_NAME
        and record.get("status") == "render_completed"
        and _summary_keys(record, "extra_summary") == ("content_recorded",)
        and _summary_hmac(record, "extra_summary")
        == _audit_payload_hmac({"content_recorded": False}, audit_key)
    ]
    if len(render_candidates) != 1:
        raise ValueError("C9 requires one unique completed renderer audit record")
    render_index, render_record = render_candidates[0]
    if {task_index, render_index} != {index for index, _ in c9_tool_records}:
        raise ValueError("C9 audit log contains an unapproved C9 tool attempt or record")
    task_time = _record_timestamp(task_record)
    render_time = _record_timestamp(render_record)
    at = _utc(correlated_at)
    if not (
        execution.executed_at <= task_time <= render_time <= consumption.observed_at <= at
        and task_index < render_index
    ):
        raise ValueError("C9 task, renderer, and rich confirmation chronology is invalid")

    task_audit_id = task_record.get("audit_id")
    render_audit_id = render_record.get("audit_id")
    if not isinstance(task_audit_id, str) or not isinstance(render_audit_id, str):
        raise ValueError("C9 audit ids are invalid")
    payload: dict[str, Any] = {
        "version": "1",
        "source": "verified_local_c9_hmac_audit_log",
        "simulated": False,
        "cycle_id": grant.cycle_id,
        "grant_id": grant.grant_id,
        "handoff_id": committed_admission.handoff_id,
        "surface": execution.surface.value,
        "surface_task_id": execution.surface_task_id,
        "capability": C9_TOOL_NAME,
        "handoff_admission_sha256": committed_admission.admission_sha256,
        "rich_execution_sha256": execution.execution_sha256,
        "expansion_descriptor_sha256": execution.expansion_descriptor_sha256,
        "manifest_sha256": execution.surface_manifest_sha256,
        "consumption_receipt_sha256": consumption.receipt_sha256,
        "task_id_sha256": hashlib.sha256(task_id.encode("utf-8")).hexdigest(),
        "task_processor_audit_id": task_audit_id,
        "render_audit_id": render_audit_id,
        "task_audit_record_sha256": canonical_sha256(task_record),
        "render_audit_record_sha256": canonical_sha256(render_record),
        "task_status": "completed",
        "render_status": "render_completed",
        "render_content_recorded": False,
        "c9_tool_audit_record_count": 2,
        "native_chat_plugin_attempt_audit_record_count": 0,
        "audit_records_verified": len(records),
        "audit_chain_last_hmac": last_hmac,
        "correlated_at": _timestamp(at),
    }
    return C9RichAuditCorrelationReceipt(
        **payload,
        receipt_hmac=_commit_hmac(
            domain="correlation",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_rich_audit_correlation_receipt(
    receipt: C9RichAuditCorrelationReceipt,
    *,
    admission: C9HandoffAdmission,
    consumption_receipt: C9RichConsumptionReceipt,
    audit_key: str | bytes,
) -> C9RichAuditCorrelationReceipt:
    committed = C9RichAuditCorrelationReceipt.model_validate(receipt.model_dump(mode="python"))
    committed_admission = C9HandoffAdmission.model_validate(admission.model_dump(mode="python"))
    consumption = C9RichConsumptionReceipt.model_validate(
        consumption_receipt.model_dump(mode="python")
    )
    _verify_hmac(
        committed,
        domain="correlation",
        field_name="receipt_hmac",
        audit_key=audit_key,
    )
    grant = committed_admission.live_cycle_bundle.grant
    if (
        committed.cycle_id != grant.cycle_id
        or committed.grant_id != grant.grant_id
        or committed.handoff_id != committed_admission.handoff_id
        or committed.surface is not consumption.surface
        or committed.surface_task_id != consumption.surface_task_id
        or committed.handoff_admission_sha256 != committed_admission.admission_sha256
        or committed.expansion_descriptor_sha256 != consumption.descriptor_sha256
        or committed.manifest_sha256 != consumption.manifest_sha256
        or committed.consumption_receipt_sha256 != consumption.receipt_sha256
        or committed.correlated_at < consumption.observed_at
    ):
        raise ValueError("C9 rich audit correlation binding is invalid")
    return committed


def commit_revocation_receipt(
    *,
    cycle_id: str,
    grant_id: str,
    close_receipt: C9CoordinatorCloseReceipt,
    listener_8765_stopped: bool,
    listener_8766_stopped: bool,
    plugin_connection_removed: bool,
    runtime_api_key_revoked: bool,
    transport_secrets_cleared: bool,
    runtime_secrets_cleared: bool,
    control_secret_cleared: bool,
    manual_export_absent: bool,
    synthetic_fixtures_absent: bool,
    post_revocation_work_app_call_failed: bool,
    post_revocation_chat_export_and_claim_failed: bool,
    post_revocation_control_call_failed: bool,
    verified_at: datetime,
    audit_key: str | bytes,
) -> C9RevocationReceipt:
    close = C9CoordinatorCloseReceipt.model_validate(close_receipt.model_dump(mode="python"))
    if (
        close.handoff_id is None
        or not close.admission_file_removed
        or close.fixture_cleanup_sha256 is None
    ):
        raise ValueError("C9 coordinator close is not complete")
    at = _utc(verified_at)
    if at < close.closed_at:
        raise ValueError("C9 revocation predates coordinator close")
    confirmations = (
        listener_8765_stopped,
        listener_8766_stopped,
        plugin_connection_removed,
        runtime_api_key_revoked,
        transport_secrets_cleared,
        runtime_secrets_cleared,
        control_secret_cleared,
        manual_export_absent,
        synthetic_fixtures_absent,
        post_revocation_work_app_call_failed,
        post_revocation_chat_export_and_claim_failed,
        post_revocation_control_call_failed,
    )
    if any(value is not True for value in confirmations):
        raise ValueError("C9 revocation requires every exact local and operator confirmation")
    payload: dict[str, Any] = {
        "version": "1",
        "source": "manual_operator_and_local_c9_revocation",
        "simulated": False,
        "cycle_id": cycle_id,
        "grant_id": grant_id,
        "handoff_id": close.handoff_id,
        "coordinator_close_receipt_sha256": close.receipt_sha256,
        "coordinator_closed": True,
        "admission_file_removed": True,
        "listener_8765_stopped": True,
        "listener_8766_stopped": True,
        "plugin_connection_removed": True,
        "runtime_api_key_revoked": True,
        "transport_secrets_cleared": True,
        "runtime_secrets_cleared": True,
        "control_secret_cleared": True,
        "manual_export_absent": True,
        "synthetic_fixtures_absent": True,
        "post_revocation_work_app_call_failed": True,
        "post_revocation_chat_export_and_claim_failed": True,
        "post_revocation_control_call_failed": True,
        "verified_at": _timestamp(at),
    }
    return C9RevocationReceipt(
        **payload,
        receipt_hmac=_commit_hmac(
            domain="revocation",
            payload=payload,
            audit_key=audit_key,
        ),
    )


def verify_revocation_receipt(
    receipt: C9RevocationReceipt,
    *,
    close_receipt: C9CoordinatorCloseReceipt,
    audit_key: str | bytes,
) -> C9RevocationReceipt:
    committed = C9RevocationReceipt.model_validate(receipt.model_dump(mode="python"))
    close = C9CoordinatorCloseReceipt.model_validate(close_receipt.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="revocation",
        field_name="receipt_hmac",
        audit_key=audit_key,
    )
    if (
        close.handoff_id is None
        or committed.handoff_id != close.handoff_id
        or committed.coordinator_close_receipt_sha256 != close.receipt_sha256
        or not close.admission_file_removed
        or close.fixture_cleanup_sha256 is None
        or committed.verified_at < close.closed_at
    ):
        raise ValueError("C9 revocation does not bind the complete coordinator close")
    return committed


def _verify_c9_live_cycle_for_final(
    admission: C9HandoffAdmission,
    *,
    audit_key: str | bytes,
) -> None:
    bundle = admission.live_cycle_bundle
    _verify_live_cycle_hmac(
        bundle.authorization,
        field_name="authorization_hmac",
        audit_key=audit_key,
    )
    _verify_live_cycle_hmac(
        bundle.surface_observation,
        field_name="observation_hmac",
        audit_key=audit_key,
    )
    _verify_live_cycle_hmac(
        bundle.grant,
        field_name="grant_hmac",
        audit_key=audit_key,
    )
    runtime_observation = verify_c9_local_ai_runtime_observation_authenticity(
        bundle.local_ai_runtime_observation,
        audit_key=audit_key,
        evaluated_at=bundle.grant.issued_at,
    )
    if (
        admission.admission_decision.status is not C9AdmissionStatus.READY
        or not admission.admission_decision.live_actions_allowed
        or admission.admission_decision.effective_tools != (C9_TOOL_NAME,)
        or bundle.grant.effective_tools != (C9_TOOL_NAME,)
        or not bundle.grant.one_synthetic_work_task
        or not bundle.grant.one_new_synthetic_native_chat_conversation
        or bundle.grant.required_work_plugin_tool_call_count != 1
        or bundle.grant.required_native_chat_plugin_tool_call_count != 0
        or bundle.grant.required_native_chat_manual_attachment_handoff_count != 1
        or bundle.grant.work_delivery_mode != "plugin_mcp_rich_content"
        or bundle.grant.native_chat_delivery_mode != "operator_performed_manual_attachment_handoff"
        or not bundle.grant.work_plugin_mcp_app_required
        or bundle.grant.native_chat_plugin_mcp_app_allowed
        or bundle.grant.automatic_chat_to_work_switch_allowed
        or not bundle.grant.native_chat_manual_attachment_handoff_qualifies_as_success
        or not bundle.surface_observation.native_chat_manual_attachment_handoff_available
        or bundle.surface_observation.native_chat_manual_attachment_handoff_used
        or bundle.surface_observation.automatic_chat_to_work_switch_used
        or bundle.grant.c8_live_cycle_grant_reused
        or bundle.grant.local_ai_runtime_observation_sha256
        != c9_local_ai_runtime_observation_sha256(runtime_observation)
        or bundle.grant.local_ai_endpoint_sha256 != runtime_observation.endpoint_sha256
        or bundle.grant.local_ai_visible_model_label_sha256
        != runtime_observation.visible_model_label_sha256
    ):
        raise ValueError("C9 final admission was not the exact one-tool fresh cycle")


def _verify_c8_dependency(
    admission: C9HandoffAdmission,
    *,
    repository_root: Path,
) -> str:
    grant = admission.live_cycle_bundle.grant
    verification = verify_c9_c8_seal_exact(repository_root)
    dependency_payload = {
        "version": "1",
        "status": "verified",
        "tag_target": grant.c8_tag_target,
        "covered_head": grant.c8_covered_head,
        "current_head": grant.repository_head_at_issue,
        "tree_sha256": grant.c8_tree_sha256,
        "final_attestation_sha256": verification.final_attestation_sha256,
        "reviewed_outcome": "COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED",
        "work_call_count": 2,
        "revocation_verified": True,
        "tag_target_ancestor_of_head": True,
    }
    if (
        verification.tag_target != grant.c8_tag_target
        or verification.covered_head != grant.c8_covered_head
        or verification.tree_sha256 != grant.c8_tree_sha256
        or not verification.revocation_verified
        or verification.work_call_count != 2
        or verification.reviewed_outcome != "COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"
        or canonical_sha256(dependency_payload) != grant.c8_dependency_sha256
    ):
        raise ValueError("C9 final C8 seal dependency is invalid")
    return str(verification.final_attestation_sha256)


def _current_repository_head(repository_root: Path) -> str:
    head = c9_git_text(repository_root, "rev-parse", "HEAD").lower()
    if re.fullmatch(_COMMIT_PATTERN, head) is None:
        raise ValueError("C9 repository HEAD is invalid")
    return head


def commit_final_attestation(
    *,
    stage_receipt: C9HandoffStageReceipt,
    admission: C9HandoffAdmission,
    local_ai_runtime_observation: C9LocalAIRuntimeObservation,
    work_receipt: C9RichConsumptionReceipt,
    work_correlation_receipt: C9RichAuditCorrelationReceipt,
    chat_export_descriptor: C9ChatExportDescriptor,
    chat_picker_claim_receipt: C9ChatPickerClaimReceipt,
    chat_receipt: C9ChatConfirmationReceipt,
    close_receipt: C9CoordinatorCloseReceipt,
    negative_receipt: C9NegativeTestReceipt,
    revocation_receipt: C9RevocationReceipt,
    repository_root: Path,
    audit_key: str | bytes,
    verified_at: datetime,
) -> C9FinalAttestation:
    stage = C9HandoffStageReceipt.model_validate(stage_receipt.model_dump(mode="python"))
    committed_admission = C9HandoffAdmission.model_validate(admission.model_dump(mode="python"))
    runtime_observation = verify_c9_local_ai_runtime_observation_authenticity(
        local_ai_runtime_observation,
        audit_key=audit_key,
        evaluated_at=stage.staged_at,
    )
    work = C9RichConsumptionReceipt.model_validate(work_receipt.model_dump(mode="python"))
    work_correlation = verify_rich_audit_correlation_receipt(
        work_correlation_receipt,
        admission=committed_admission,
        consumption_receipt=work,
        audit_key=audit_key,
    )
    chat_export = C9ChatExportDescriptor.model_validate(
        chat_export_descriptor.model_dump(mode="python")
    )
    chat_claim = C9ChatPickerClaimReceipt.model_validate(
        chat_picker_claim_receipt.model_dump(mode="python")
    )
    chat = C9ChatConfirmationReceipt.model_validate(chat_receipt.model_dump(mode="python"))
    close = C9CoordinatorCloseReceipt.model_validate(close_receipt.model_dump(mode="python"))
    negative = verify_negative_test_receipt(
        negative_receipt,
        audit_key=audit_key,
    )
    revocation = verify_revocation_receipt(
        revocation_receipt,
        close_receipt=close,
        audit_key=audit_key,
    )
    if (
        close.rich_call_count != 1
        or close.rich_confirmation_count != 1
        or not close.native_chat_manual_handoff_used
    ):
        raise ValueError(
            "C9 final evidence requires one Work rich call and one native Chat manual handoff"
        )
    _verify_c9_live_cycle_for_final(
        committed_admission,
        audit_key=audit_key,
    )
    c8_final_attestation_sha256 = _verify_c8_dependency(
        committed_admission,
        repository_root=repository_root,
    )

    combined = committed_admission.combined_approval
    bundle = committed_admission.live_cycle_bundle
    grant = bundle.grant
    decision = committed_admission.admission_decision
    c9_live_repository_head = _current_repository_head(repository_root)
    if c9_live_repository_head != grant.repository_head_at_issue:
        raise ValueError("C9 repository HEAD drifted after live admission")
    if negative.automated_suite.repository_head != c9_live_repository_head:
        raise ValueError("C9 negative suite repository HEAD does not match live C9")
    cycle_ids = {
        bundle.authorization.cycle_id,
        bundle.surface_observation.cycle_id,
        runtime_observation.cycle_id,
        grant.cycle_id,
        work.c9_cycle_id,
        chat_export.c9_cycle_id,
        chat_claim.c9_cycle_id,
        chat.c9_cycle_id,
        negative.cycle_id,
        revocation.cycle_id,
    }
    grant_ids = {
        grant.grant_id,
        work.c9_grant_id,
        chat_export.c9_grant_id,
        chat_claim.c9_grant_id,
        chat.c9_grant_id,
        negative.grant_id,
        revocation.grant_id,
    }
    handoff_ids = {
        stage.handoff_id,
        committed_admission.handoff_id,
        chat_export.handoff_id,
        chat_claim.handoff_id,
        chat.handoff_id,
        close.handoff_id,
        negative.handoff_id,
        revocation.handoff_id,
    }
    if len(cycle_ids) != 1 or len(grant_ids) != 1 or handoff_ids != {stage.handoff_id}:
        raise ValueError("C9 final evidence crosses cycle, grant, or handoff boundaries")

    if (
        stage.work_manifest_sha256 != combined.work_manifest_sha256
        or stage.chat_manifest_sha256 != combined.chat_manifest_sha256
        or stage.fixture_receipt_sha256 != combined.fixture_receipt_sha256
        or stage.local_ai_receipt_sha256 != combined.local_ai_receipt_sha256
        or stage.local_ai_runtime_observation_sha256 != combined.local_ai_runtime_observation_sha256
        or stage.work_manifest_sha256 != bundle.authorization.selected_package_manifest_sha256
        or stage.work_manifest_sha256 != grant.selected_package_manifest_sha256
        or stage.local_ai_receipt_sha256 != grant.local_ai_receipt_sha256
        or stage.local_ai_runtime_observation_sha256 != grant.local_ai_runtime_observation_sha256
        or stage.local_ai_runtime_observation_sha256
        != c9_local_ai_runtime_observation_sha256(runtime_observation)
        or runtime_observation != bundle.local_ai_runtime_observation
    ):
        raise ValueError("C9 stage, approval, local-AI, and live-cycle bindings disagree")
    if (
        work.surface is not C9RichSurface.WORK
        or work.surface_task_id != stage.work_task_id
        or work.accepted_c8_commit != grant.c8_tag_target
        or work.manifest_sha256 != stage.work_manifest_sha256
        or chat_export.chat_manifest_sha256 != stage.chat_manifest_sha256
        or chat_claim.chat_manifest_sha256 != stage.chat_manifest_sha256
        or chat.chat_manifest_sha256 != stage.chat_manifest_sha256
        or work.approval_sha256 != combined.work_approval_sha256
        or chat_export.chat_approval_sha256 != combined.chat_approval_sha256
        or chat_export.combined_approval_sha256 != combined.combined_approval_sha256
        or chat.combined_approval_sha256 != combined.combined_approval_sha256
        or chat_claim.export_id != chat_export.export_id
        or chat_claim.export_descriptor_sha256 != chat_export.descriptor_sha256
        or chat.chat_export_id != chat_export.export_id
        or chat.chat_export_descriptor_sha256 != chat_export.descriptor_sha256
        or chat.chat_picker_claim_receipt_sha256 != chat_claim.receipt_sha256
    ):
        raise ValueError("C9 Work MCP or native Chat manual proof does not bind the handoff")

    expected_attachment_ids = tuple(item.attachment_id for item in stage.attachments)
    expected_content_hashes = tuple(item.content_sha256 for item in stage.attachments)
    expected_nonce_hashes = tuple(item.nonce_sha256 for item in stage.attachments)
    if (
        tuple(item.kind for item in stage.attachments)
        != (C9SyntheticFixtureKind.IMAGE, C9SyntheticFixtureKind.TEXT)
        or work.verified_attachment_ids != expected_attachment_ids
        or work.verified_nonce_sha256s != expected_nonce_hashes
        or chat.verified_nonce_sha256s != expected_nonce_hashes
    ):
        raise ValueError("C9 proof does not preserve the exact image/text nonce order")

    positive_times = (
        work.observed_at,
        chat_export.created_at,
        chat_claim.claimed_at,
        chat.confirmed_at,
    )
    if (
        not stage.staged_at <= combined.approved_at <= committed_admission.committed_at
        or grant.issued_at != combined.approved_at
        or decision.evaluated_at != grant.issued_at
        or not chat_export.created_at <= chat_claim.claimed_at <= chat.confirmed_at
        or chat.confirmed_at >= chat_export.expires_at
        or any(moment < committed_admission.committed_at for moment in positive_times)
        or any(moment >= grant.expires_at for moment in positive_times)
        or any(moment >= combined.expires_at for moment in positive_times)
        or any(moment >= stage.expires_at for moment in positive_times)
        or close.closed_at < max(positive_times)
        or negative.observed_at < close.closed_at
        or revocation.verified_at < negative.observed_at
    ):
        raise ValueError("C9 final evidence chronology is invalid")
    at = _utc(verified_at)
    if at < max(
        revocation.verified_at,
        work_correlation.correlated_at,
    ):
        raise ValueError("C9 final verification predates its offline evidence")

    payload: dict[str, Any] = {
        "version": "1",
        "status": C9_FINAL_STATUS,
        "source": "bounded_synthetic_c9_final_verifier",
        "simulated": False,
        "issue_url": C9_ISSUE_URL,
        "cycle_id": grant.cycle_id,
        "grant_id": grant.grant_id,
        "handoff_id": stage.handoff_id,
        "work_task_id": stage.work_task_id,
        "chat_task_id": stage.chat_task_id,
        "c9_live_repository_head": c9_live_repository_head,
        "accepted_c8_commit": grant.c8_tag_target,
        "c8_covered_head": grant.c8_covered_head,
        "c8_tree_sha256": grant.c8_tree_sha256,
        "c8_final_attestation_sha256": c8_final_attestation_sha256,
        "c8_dependency_sha256": grant.c8_dependency_sha256,
        "c8_reviewed_outcome": ("COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"),
        "c8_revocation_verified": True,
        "c8_live_cycle_grant_reused": False,
        "authorization_sha256": grant.authorization_sha256,
        "surface_observation_sha256": grant.surface_observation_sha256,
        "grant_sha256": canonical_sha256(grant.model_dump(mode="json")),
        "stage_receipt_sha256": canonical_sha256(stage.model_dump(mode="json")),
        "handoff_admission_sha256": committed_admission.admission_sha256,
        "combined_approval_sha256": combined.combined_approval_sha256,
        "work_approval_sha256": combined.work_approval_sha256,
        "chat_approval_sha256": combined.chat_approval_sha256,
        "fixture_receipt_sha256": stage.fixture_receipt_sha256,
        "local_ai_receipt_sha256": stage.local_ai_receipt_sha256,
        "local_ai_runtime_observation_sha256": (stage.local_ai_runtime_observation_sha256),
        "work_manifest_sha256": stage.work_manifest_sha256,
        "chat_manifest_sha256": stage.chat_manifest_sha256,
        "chat_export_id": chat_export.export_id,
        "chat_export_descriptor_sha256": chat_export.descriptor_sha256,
        "chat_export_sha256": chat_export.export_sha256,
        "chat_picker_claim_receipt_sha256": chat_claim.receipt_sha256,
        "attachment_content_sha256s": list(expected_content_hashes),
        "attachment_nonce_sha256s": list(expected_nonce_hashes),
        "work_consumption_receipt_sha256": work.receipt_sha256,
        "chat_manual_confirmation_receipt_sha256": chat.receipt_sha256,
        "chat_manual_cleanup_receipt_sha256": chat.manual_cleanup_receipt_sha256,
        "work_audit_correlation_receipt_sha256": canonical_sha256(
            work_correlation.model_dump(mode="json")
        ),
        "work_task_audit_record_sha256": work_correlation.task_audit_record_sha256,
        "work_render_audit_record_sha256": work_correlation.render_audit_record_sha256,
        "coordinator_close_receipt_sha256": close.receipt_sha256,
        "negative_test_receipt_sha256": canonical_sha256(negative.model_dump(mode="json")),
        "revocation_receipt_sha256": canonical_sha256(revocation.model_dump(mode="json")),
        "work_rich_call_count": 1,
        "chat_manual_handoff_count": 1,
        "total_rich_mcp_call_count": 1,
        "work_rich_mcp_verified": True,
        "chat_manual_visible_handoff_verified": True,
        "same_sanitized_package_verified": True,
        "native_chat_plugin_invoked": False,
        "native_chat_provider_audit_correlation_claimed": False,
        "unapproved_fallback_used": False,
        "local_ai_loopback_receipt_committed": True,
        "local_ai_native_runtime_observation_committed": True,
        "regular_arbitrary_files_tested": False,
        "regular_use_readiness_claimed": False,
        "automatic_chat_to_work_switch_used": False,
        "revocation_verified": True,
        "verified_at": _timestamp(at),
    }
    attestation_sha256 = canonical_sha256(payload)
    authenticated_payload = {**payload, "attestation_sha256": attestation_sha256}
    return C9FinalAttestation(
        **authenticated_payload,
        attestation_hmac=_commit_hmac(
            domain="final",
            payload=authenticated_payload,
            audit_key=audit_key,
        ),
    )


def verify_final_attestation(
    attestation: C9FinalAttestation,
    *,
    audit_key: str | bytes,
) -> C9FinalAttestation:
    committed = C9FinalAttestation.model_validate(attestation.model_dump(mode="python"))
    _verify_hmac(
        committed,
        domain="final",
        field_name="attestation_hmac",
        audit_key=audit_key,
    )
    return committed


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_reparse(info: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = int(getattr(info, "st_file_attributes", 0))
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)


def _assert_confined_components(path: Path, metadata_root: Path) -> None:
    root = _lexical_absolute(metadata_root)
    target = _lexical_absolute(path)
    try:
        common = Path(os.path.commonpath((os.fspath(root), os.fspath(target))))
    except ValueError as exc:
        raise ValueError("C9 metadata path escapes its private root") from exc
    if os.path.normcase(os.fspath(common)) != os.path.normcase(os.fspath(root)):
        raise ValueError("C9 metadata path escapes its private root")
    current = Path(target.anchor)
    for component in target.parts[1:]:
        current /= component
        info = os.lstat(current)
        if _is_reparse(info):
            raise ValueError("C9 metadata path traverses a reparse point")


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_ISREG(left.st_mode)
        and stat.S_ISREG(right.st_mode)
        and int(left.st_dev) == int(right.st_dev)
        and int(left.st_ino) == int(right.st_ino)
        and int(left.st_size) == int(right.st_size)
        and int(left.st_mtime_ns) == int(right.st_mtime_ns)
        and int(left.st_nlink) == int(right.st_nlink)
    )


def _safe_read_metadata(
    path: Path,
    *,
    metadata_root: Path,
    maximum_bytes: int,
) -> bytes:
    target = _lexical_absolute(path)
    _assert_confined_components(target, metadata_root)
    before = os.lstat(target)
    if (
        not stat.S_ISREG(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum_bytes
    ):
        raise ValueError("C9 attestation metadata input is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags)
    try:
        opened = os.fstat(descriptor)
        if not _same_file_identity(before, opened):
            raise ValueError("C9 attestation metadata changed while opening")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise ValueError("C9 attestation metadata exceeds its boundary")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    _assert_confined_components(target, metadata_root)
    final = os.lstat(target)
    if (
        not _same_file_identity(before, after)
        or not _same_file_identity(before, final)
        or total != before.st_size
    ):
        raise ValueError("C9 attestation metadata changed while loading")
    return b"".join(chunks)


def _load_model(
    path: Path,
    model_type: type[_ModelT],
    *,
    metadata_root: Path,
) -> _ModelT:
    return model_type.model_validate_json(
        _safe_read_metadata(
            path,
            metadata_root=metadata_root,
            maximum_bytes=_MAX_METADATA_BYTES,
        )
    )


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate C9 audit record key")
        output[key] = value
    return output


def _load_verified_audit_records(
    path: Path,
    *,
    metadata_root: Path,
    audit_key: str | bytes,
) -> tuple[tuple[dict[str, Any], ...], str]:
    raw = _safe_read_metadata(
        path,
        metadata_root=metadata_root,
        maximum_bytes=_MAX_AUDIT_BYTES,
    )
    if not raw.endswith(b"\n"):
        raise ValueError("C9 audit log must end with one complete record")
    previous_hmac = "0" * 64
    audit_ids: set[str] = set()
    records: list[dict[str, Any]] = []
    for raw_line in raw.splitlines():
        if not raw_line:
            raise ValueError("C9 audit log contains a blank record")
        decoded = json.loads(
            raw_line,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
        if not isinstance(decoded, dict):
            raise ValueError("C9 audit record is not an object")
        record = dict(decoded)
        if record.get("version") != 2 or record.get("previous_hmac") != previous_hmac:
            raise ValueError("C9 audit chain is malformed")
        entry_hmac = record.get("entry_hmac")
        audit_id = record.get("audit_id")
        if (
            not isinstance(entry_hmac, str)
            or re.fullmatch(_SHA256_PATTERN, entry_hmac) is None
            or not isinstance(audit_id, str)
            or audit_id in audit_ids
        ):
            raise ValueError("C9 audit record identity is invalid")
        unsigned = dict(record)
        unsigned.pop("entry_hmac")
        expected = hmac.new(
            _audit_key(audit_key),
            b"audit-entry-v2\0" + _canonical_json(unsigned),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(entry_hmac, expected):
            raise ValueError("C9 audit record authentication failed")
        audit_ids.add(audit_id)
        previous_hmac = entry_hmac
        records.append(record)
    if not records:
        raise ValueError("C9 audit log is empty")
    return tuple(records), previous_hmac


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


def _audit_key_from_environment() -> str:
    value = os.environ.get("SLG_AUDIT_KEY")
    if value is None:
        raise ValueError("C9 audit key is unavailable")
    _audit_key(value)
    return value


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        raise ValueError("invalid C9 attestation command")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(description="C9 bounded final evidence attestation")
    sub = parser.add_subparsers(
        dest="command",
        required=True,
        parser_class=_SafeArgumentParser,
    )
    negative = sub.add_parser("run-negative")
    negative.add_argument("--metadata-root", type=Path, required=True)
    negative.add_argument("--admission", type=Path, required=True)
    negative.add_argument("--close", type=Path, required=True)
    negative.add_argument("--repository-root", type=Path, default=_repository_root())
    negative.add_argument("--observed-at")

    correlation = sub.add_parser("commit-rich-correlation")
    correlation.add_argument("--metadata-root", type=Path, required=True)
    correlation.add_argument("--audit-log", type=Path, required=True)
    correlation.add_argument("--admission", type=Path, required=True)
    correlation.add_argument(
        "--surface",
        required=True,
        choices=(C9RichSurface.WORK.value,),
    )
    correlation.add_argument("--execution", type=Path, required=True)
    correlation.add_argument("--receipt", type=Path, required=True)
    correlation.add_argument("--correlated-at")

    revoke = sub.add_parser("commit-revocation")
    revoke.add_argument("--metadata-root", type=Path, required=True)
    revoke.add_argument("--cycle-id", required=True)
    revoke.add_argument("--grant-id", required=True)
    revoke.add_argument("--close", type=Path, required=True)
    revoke.add_argument("--verified-at")
    revoke.add_argument("--confirmed-complete-revocation", action="store_true")
    revoke.add_argument("--confirmed-listener-8765-stopped", action="store_true")
    revoke.add_argument("--confirmed-listener-8766-stopped", action="store_true")
    revoke.add_argument("--confirmed-plugin-connection-removed", action="store_true")
    revoke.add_argument("--confirmed-runtime-api-key-revoked", action="store_true")
    revoke.add_argument("--confirmed-transport-secrets-cleared", action="store_true")
    revoke.add_argument("--confirmed-runtime-secrets-cleared", action="store_true")
    revoke.add_argument("--confirmed-control-secret-cleared", action="store_true")
    revoke.add_argument("--confirmed-manual-export-absent", action="store_true")
    revoke.add_argument("--confirmed-synthetic-fixtures-absent", action="store_true")
    revoke.add_argument(
        "--confirmed-post-revocation-work-app-call-failed",
        action="store_true",
    )
    revoke.add_argument(
        "--confirmed-post-revocation-chat-export-and-claim-failed",
        action="store_true",
    )
    revoke.add_argument(
        "--confirmed-post-revocation-control-call-failed",
        action="store_true",
    )

    final = sub.add_parser("commit-final")
    final.add_argument("--metadata-root", type=Path, required=True)
    final.add_argument("--stage", type=Path, required=True)
    final.add_argument("--admission", type=Path, required=True)
    final.add_argument(
        "--local-ai-runtime-observation",
        type=Path,
        required=True,
    )
    final.add_argument("--work", type=Path, required=True)
    final.add_argument("--work-correlation", type=Path, required=True)
    final.add_argument("--chat-export", type=Path, required=True)
    final.add_argument("--chat-picker-claim", type=Path, required=True)
    final.add_argument("--chat", type=Path, required=True)
    final.add_argument("--close", type=Path, required=True)
    final.add_argument("--negative", type=Path, required=True)
    final.add_argument("--revocation", type=Path, required=True)
    final.add_argument("--repository-root", type=Path, default=_repository_root())
    final.add_argument("--verified-at")

    verify_final = sub.add_parser("verify-final")
    verify_final.add_argument("--metadata-root", type=Path, required=True)
    verify_final.add_argument("--attestation", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        audit_key = _audit_key_from_environment()
        if args.command == "run-negative":
            admission = _load_model(
                args.admission,
                C9HandoffAdmission,
                metadata_root=args.metadata_root,
            )
            close = _load_model(
                args.close,
                C9CoordinatorCloseReceipt,
                metadata_root=args.metadata_root,
            )
            if close.handoff_id != admission.handoff_id:
                raise ValueError("C9 negative suite close receipt crosses handoff")
            observed_at = _parse_timestamp(args.observed_at)
            if observed_at < close.closed_at:
                raise ValueError("C9 negative suite predates coordinator close")
            automated_suite = run_automated_negative_suite(
                repository_root=args.repository_root,
                metadata_root=args.metadata_root,
            )
            grant = admission.live_cycle_bundle.grant
            negative_receipt = commit_negative_test_receipt(
                cycle_id=grant.cycle_id,
                grant_id=grant.grant_id,
                handoff_id=admission.handoff_id,
                outcomes=_required_negative_outcomes(),
                automated_suite=automated_suite,
                observed_at=observed_at,
                audit_key=audit_key,
            )
            print(rendered_json(negative_receipt), end="")
            return 0
        if args.command == "commit-revocation":
            if not args.confirmed_complete_revocation:
                raise ValueError("C9 complete revocation was not confirmed")
            close = _load_model(
                args.close,
                C9CoordinatorCloseReceipt,
                metadata_root=args.metadata_root,
            )
            revocation_receipt = commit_revocation_receipt(
                cycle_id=args.cycle_id,
                grant_id=args.grant_id,
                close_receipt=close,
                listener_8765_stopped=args.confirmed_listener_8765_stopped,
                listener_8766_stopped=args.confirmed_listener_8766_stopped,
                plugin_connection_removed=args.confirmed_plugin_connection_removed,
                runtime_api_key_revoked=args.confirmed_runtime_api_key_revoked,
                transport_secrets_cleared=args.confirmed_transport_secrets_cleared,
                runtime_secrets_cleared=args.confirmed_runtime_secrets_cleared,
                control_secret_cleared=args.confirmed_control_secret_cleared,
                manual_export_absent=args.confirmed_manual_export_absent,
                synthetic_fixtures_absent=args.confirmed_synthetic_fixtures_absent,
                post_revocation_work_app_call_failed=(
                    args.confirmed_post_revocation_work_app_call_failed
                ),
                post_revocation_chat_export_and_claim_failed=(
                    args.confirmed_post_revocation_chat_export_and_claim_failed
                ),
                post_revocation_control_call_failed=(
                    args.confirmed_post_revocation_control_call_failed
                ),
                verified_at=_parse_timestamp(args.verified_at),
                audit_key=audit_key,
            )
            print(rendered_json(revocation_receipt), end="")
            return 0
        if args.command == "commit-rich-correlation":
            execution = _load_model(
                args.execution,
                C9RichExecutionDescriptor,
                metadata_root=args.metadata_root,
            )
            receipt = _load_model(
                args.receipt,
                C9RichConsumptionReceipt,
                metadata_root=args.metadata_root,
            )
            requested_surface = C9RichSurface(args.surface)
            if (
                execution.surface is not requested_surface
                or receipt.surface is not requested_surface
            ):
                raise ValueError("C9 correlation command surface does not match its evidence")
            correlation_receipt = commit_rich_audit_correlation_receipt(
                admission=_load_model(
                    args.admission,
                    C9HandoffAdmission,
                    metadata_root=args.metadata_root,
                ),
                rich_execution=execution,
                consumption_receipt=receipt,
                audit_log_path=args.audit_log,
                metadata_root=args.metadata_root,
                correlated_at=_parse_timestamp(args.correlated_at),
                audit_key=audit_key,
            )
            print(rendered_json(correlation_receipt), end="")
            return 0
        if args.command == "commit-final":
            attestation = commit_final_attestation(
                stage_receipt=_load_model(
                    args.stage,
                    C9HandoffStageReceipt,
                    metadata_root=args.metadata_root,
                ),
                admission=_load_model(
                    args.admission,
                    C9HandoffAdmission,
                    metadata_root=args.metadata_root,
                ),
                local_ai_runtime_observation=_load_model(
                    args.local_ai_runtime_observation,
                    C9LocalAIRuntimeObservation,
                    metadata_root=args.metadata_root,
                ),
                work_receipt=_load_model(
                    args.work,
                    C9RichConsumptionReceipt,
                    metadata_root=args.metadata_root,
                ),
                work_correlation_receipt=_load_model(
                    args.work_correlation,
                    C9RichAuditCorrelationReceipt,
                    metadata_root=args.metadata_root,
                ),
                chat_export_descriptor=_load_model(
                    args.chat_export,
                    C9ChatExportDescriptor,
                    metadata_root=args.metadata_root,
                ),
                chat_picker_claim_receipt=_load_model(
                    args.chat_picker_claim,
                    C9ChatPickerClaimReceipt,
                    metadata_root=args.metadata_root,
                ),
                chat_receipt=_load_model(
                    args.chat,
                    C9ChatConfirmationReceipt,
                    metadata_root=args.metadata_root,
                ),
                close_receipt=_load_model(
                    args.close,
                    C9CoordinatorCloseReceipt,
                    metadata_root=args.metadata_root,
                ),
                negative_receipt=_load_model(
                    args.negative,
                    C9NegativeTestReceipt,
                    metadata_root=args.metadata_root,
                ),
                revocation_receipt=_load_model(
                    args.revocation,
                    C9RevocationReceipt,
                    metadata_root=args.metadata_root,
                ),
                repository_root=args.repository_root,
                audit_key=audit_key,
                verified_at=_parse_timestamp(args.verified_at),
            )
            print(rendered_json(attestation), end="")
            return 0
        if args.command == "verify-final":
            attestation = verify_final_attestation(
                _load_model(
                    args.attestation,
                    C9FinalAttestation,
                    metadata_root=args.metadata_root,
                ),
                audit_key=audit_key,
            )
            print(rendered_json(attestation), end="")
            return 0
        raise ValueError("unsupported C9 attestation command")
    except Exception:
        print(
            json.dumps(
                {
                    "status": "error",
                    "error": "C9_ATTESTATION_VALIDATION_FAILED",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
