from __future__ import annotations

import base64
import hmac
import json
import re
import secrets
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal, NoReturn, Protocol, TypeVar, cast

import mcp.types as mcp_types
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import c9_live_cycle
from .c9_attachment_security import (
    C9AttachmentDescriptor,
    C9AttachmentLease,
    C9AttachmentSecurity,
    C9BoundApproval,
    C9OutboundManifest,
    C9OutboundSurface,
)
from .c9_local_ai import (
    C9LocalAIConfig,
    C9LocalAIInference,
    C9LocalAIReceipt,
    C9LocalAIRuntimeContinuitySnapshot,
    C9LocalAIRuntimeObservation,
    c9_local_ai_runtime_observation_sha256,
    capture_c9_local_ai_runtime_continuity,
    run_c9_local_ai_inference,
    verify_c9_local_ai_runtime_continuity_pair,
    verify_c9_local_ai_runtime_observation,
)
from .c9_manual_export import (
    C9ManualCleanupReason,
    C9ManualCleanupReceipt,
    C9ManualExport,
)
from .c9_mcp_tool import (
    C9_ATTACHMENT_HANDOFF_TOOL_NAME,
    c9_attachment_handoff_tool,
)
from .c9_private_state import C9PrivateStateError, C9PrivateStateGuard
from .c9_synthetic_fixtures import (
    C9SyntheticFixtureHandle,
    C9SyntheticFixtureKind,
    C9SyntheticFixtureReceipt,
)
from .c9_work_bridge import (
    C9McpExpansionDescriptor,
    C9McpHostCapabilities,
    C9RichConsumptionReceipt,
    C9RichSurface,
    C9RichTaskSession,
    build_mcp_expansion_descriptor,
    promote_mcp_host_capabilities_after_live_proof,
)
from .mcp_tools import McpToolDefinition
from .providers.attachment_models import (
    AttachmentMediaFamily,
    AttachmentMediaType,
    media_family,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_HANDOFF_PATTERN = r"^c9_handoff_[0-9a-f]{32}$"
_DELIVERY_PATTERN = r"^c9_delivery_[0-9a-f]{32}$"
_WORK_TASK_PATTERN = r"^c9_work_[0-9a-f]{32}$"
_CHAT_TASK_PATTERN = r"^c9_chat_[0-9a-f]{32}$"
_RICH_TASK_PATTERN = r"^c9_(?:work|chat)_[0-9a-f]{32}$"
_CYCLE_PATTERN = r"^c9_cycle_[0-9a-f]{32}$"
_GRANT_PATTERN = r"^c9_grant_[0-9a-f]{32}$"
_NONCE_PATTERN = r"^C9[0-9A-F]{32}$"
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_APPROVAL_TTL = timedelta(minutes=10)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C9 timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _canonical_sha256(domain: bytes, payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return sha256(domain + encoded).hexdigest()


def _model_sha256(domain: bytes, model: BaseModel, field_name: str) -> str:
    return _canonical_sha256(
        domain,
        model.model_dump(mode="json", exclude={field_name}),
    )


def _reject_duplicate_chat_response_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate native-Chat response key")
        output[key] = value
    return output


def _reject_non_finite_chat_response(_value: str) -> NoReturn:
    raise ValueError("non-finite native-Chat response value")


def _parse_native_chat_manual_response(
    response_text: str,
    *,
    handoff_id: str,
    observed_image_nonce: str,
    observed_document_nonce: str,
) -> dict[str, str]:
    """Require the exact operator-visible native-Chat proof envelope."""

    if not response_text or len(response_text.encode("utf-8")) > _MAX_RESPONSE_BYTES:
        raise ValueError("native-Chat response is empty or unbounded")
    try:
        decoded = json.loads(
            response_text,
            object_pairs_hook=_reject_duplicate_chat_response_keys,
            parse_constant=_reject_non_finite_chat_response,
        )
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        raise ValueError("native-Chat response is not strict JSON") from exc
    expected_fields = {
        "delivery_mode",
        "handoff_id",
        "observed_document_nonce",
        "observed_image_nonce",
        "surface",
    }
    if (
        not isinstance(decoded, dict)
        or set(decoded) != expected_fields
        or not all(isinstance(value, str) for value in decoded.values())
    ):
        raise ValueError("native-Chat response has an invalid exact schema")
    parsed = cast(dict[str, str], decoded)
    if (
        parsed["delivery_mode"] != "operator_performed_manual_attachment_handoff"
        or parsed["surface"] != "chat"
        or not secrets.compare_digest(parsed["handoff_id"], handoff_id)
        or re.fullmatch(_NONCE_PATTERN, parsed["observed_image_nonce"]) is None
        or re.fullmatch(_NONCE_PATTERN, parsed["observed_document_nonce"]) is None
        or not secrets.compare_digest(
            parsed["observed_image_nonce"],
            observed_image_nonce,
        )
        or not secrets.compare_digest(
            parsed["observed_document_nonce"],
            observed_document_nonce,
        )
        or secrets.compare_digest(
            parsed["observed_image_nonce"],
            parsed["observed_document_nonce"],
        )
    ):
        raise ValueError("native-Chat response contains invalid proof values")
    return parsed


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )


_ModelT = TypeVar("_ModelT", bound=_StrictModel)


class C9HandoffReason(StrEnum):
    COORDINATOR_CLOSED = "coordinator_closed"
    HANDOFF_NOT_STAGED = "handoff_not_staged"
    CROSS_HANDOFF_REJECTED = "cross_handoff_rejected"
    HANDOFF_ALREADY_STAGED = "handoff_already_staged"
    HANDOFF_NOT_APPROVED = "handoff_not_approved"
    HANDOFF_ALREADY_APPROVED = "handoff_already_approved"
    HANDOFF_EXPIRED = "handoff_expired"
    MANIFEST_BINDING_MISMATCH = "manifest_binding_mismatch"
    LOCAL_AI_BINDING_MISMATCH = "local_ai_binding_mismatch"
    ADMISSION_REJECTED = "admission_rejected"
    WORK_REPLAY_REJECTED = "work_replay_rejected"
    WORK_RENDER_REPLAY_REJECTED = "work_render_replay_rejected"
    RICH_SURFACE_REPLAY_REJECTED = "rich_surface_replay_rejected"
    RICH_RENDER_REPLAY_REJECTED = "rich_render_replay_rejected"
    SURFACE_BINDING_MISMATCH = "surface_binding_mismatch"
    SURFACE_ORDER_REJECTED = "surface_order_rejected"
    UNSUPPORTED_SURFACE = "unsupported_surface"
    CHAT_REPLAY_REJECTED = "chat_replay_rejected"
    CHAT_EXPORT_NOT_CLAIMED = "chat_export_not_claimed"
    NONCE_PROOF_REJECTED = "nonce_proof_rejected"
    RESPONSE_REJECTED = "response_rejected"
    CHAT_CLEANUP_REJECTED = "chat_cleanup_rejected"
    RENDER_BINDING_MISMATCH = "render_binding_mismatch"
    ATOMIC_COMMIT_FAILED = "atomic_commit_failed"


class C9HandoffError(ValueError):
    def __init__(self, reason: C9HandoffReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _deny(reason: C9HandoffReason, message: str) -> NoReturn:
    raise C9HandoffError(reason, message)


class C9StagedAttachment(_StrictModel):
    attachment_id: str = Field(pattern=r"^c9_attachment_[0-9a-f]{32}$")
    kind: C9SyntheticFixtureKind
    media_type: AttachmentMediaType
    content_sha256: str = Field(pattern=_SHA256_PATTERN)
    nonce_sha256: str = Field(pattern=_SHA256_PATTERN)
    descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_kind(self) -> C9StagedAttachment:
        if self.kind is C9SyntheticFixtureKind.IMAGE:
            if media_family(self.media_type) is not AttachmentMediaFamily.IMAGE:
                raise ValueError("C9 staged image media type mismatch")
        elif self.media_type is not AttachmentMediaType.TEXT:
            raise ValueError("C9 staged document media type mismatch")
        return self


class C9HandoffStageReceipt(_StrictModel):
    version: Literal["1"] = "1"
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)
    work_task_id: str = Field(pattern=_WORK_TASK_PATTERN)
    chat_task_id: str = Field(pattern=_CHAT_TASK_PATTERN)
    fixture_package_id: str = Field(pattern=r"^c9_fixture_package_[0-9a-f]{32}$")
    fixture_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    work_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_ai_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_ai_runtime_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    attachments: tuple[C9StagedAttachment, C9StagedAttachment]
    staged_at: datetime
    expires_at: datetime
    stage_sha256: str = Field(pattern=_SHA256_PATTERN)

    _staged_utc = field_validator("staged_at")(_utc)
    _expires_utc = field_validator("expires_at")(_utc)

    @model_validator(mode="after")
    def validate_stage(self) -> C9HandoffStageReceipt:
        if tuple(item.kind for item in self.attachments) != (
            C9SyntheticFixtureKind.IMAGE,
            C9SyntheticFixtureKind.TEXT,
        ):
            raise ValueError("C9 stage requires image then text")
        if self.expires_at <= self.staged_at:
            raise ValueError("C9 staged package is already expired")
        if self.stage_sha256 != _model_sha256(
            b"systeme-local/c9/handoff-stage/v1\0",
            self,
            "stage_sha256",
        ):
            raise ValueError("C9 stage digest mismatch")
        return self


class C9CombinedApproval(_StrictModel):
    version: Literal["1"] = "1"
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)
    fixture_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_ai_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_ai_runtime_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    work_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    work_approval_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_approval_sha256: str = Field(pattern=_SHA256_PATTERN)
    operator_identity_sha256: str = Field(pattern=_SHA256_PATTERN)
    approved_at: datetime
    expires_at: datetime
    combined_approval_sha256: str = Field(pattern=_SHA256_PATTERN)

    _approved_utc = field_validator("approved_at")(_utc)
    _expires_utc = field_validator("expires_at")(_utc)

    @model_validator(mode="after")
    def validate_combined(self) -> C9CombinedApproval:
        if self.expires_at <= self.approved_at:
            raise ValueError("C9 combined approval is already expired")
        if self.combined_approval_sha256 != _model_sha256(
            b"systeme-local/c9/combined-approval/v1\0",
            self,
            "combined_approval_sha256",
        ):
            raise ValueError("C9 combined approval digest mismatch")
        return self


class C9HandoffAdmission(_StrictModel):
    version: Literal["1"] = "1"
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)
    combined_approval: C9CombinedApproval
    live_cycle_bundle: c9_live_cycle.C9LiveCycleBundle
    admission_decision: c9_live_cycle.C9AdmissionDecision
    committed_at: datetime
    admission_sha256: str = Field(pattern=_SHA256_PATTERN)

    _committed_utc = field_validator("committed_at")(_utc)

    @model_validator(mode="after")
    def validate_admission(self) -> C9HandoffAdmission:
        grant = self.live_cycle_bundle.grant
        if (
            self.handoff_id != self.combined_approval.handoff_id
            or grant.selected_package_manifest_sha256 != self.combined_approval.work_manifest_sha256
            or grant.local_ai_receipt_sha256 != self.combined_approval.local_ai_receipt_sha256
            or grant.local_ai_runtime_observation_sha256
            != self.combined_approval.local_ai_runtime_observation_sha256
            or self.admission_decision.cycle_id != grant.cycle_id
            or self.admission_decision.grant_id != grant.grant_id
            or not self.admission_decision.live_actions_allowed
            or self.admission_decision.effective_tools != (C9_ATTACHMENT_HANDOFF_TOOL_NAME,)
        ):
            raise ValueError("C9 admission does not bind the exact approved handoff")
        if self.admission_sha256 != _model_sha256(
            b"systeme-local/c9/handoff-admission/v1\0",
            self,
            "admission_sha256",
        ):
            raise ValueError("C9 handoff admission digest mismatch")
        return self


class C9RichExecutionDescriptor(_StrictModel):
    version: Literal["1"] = "1"
    status: Literal["pending_mcp_rich_content_render"]
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)
    surface: C9RichSurface
    surface_task_id: str = Field(pattern=_RICH_TASK_PATTERN)
    delivery_token: str = Field(pattern=_DELIVERY_PATTERN)
    c9_cycle_id: str = Field(pattern=_CYCLE_PATTERN)
    c9_grant_id: str = Field(pattern=_GRANT_PATTERN)
    accepted_c8_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    combined_approval_sha256: str = Field(pattern=_SHA256_PATTERN)
    surface_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    expansion_descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)
    lease_consumption_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    attachment_count: Literal[2]
    executed_at: datetime
    expires_at: datetime
    execution_sha256: str = Field(pattern=_SHA256_PATTERN)

    _executed_utc = field_validator("executed_at")(_utc)
    _expires_utc = field_validator("expires_at")(_utc)

    @model_validator(mode="after")
    def validate_execution(self) -> C9RichExecutionDescriptor:
        if self.expires_at <= self.executed_at:
            raise ValueError("C9 rich delivery is already expired")
        task_pattern = (
            _WORK_TASK_PATTERN if self.surface is C9RichSurface.WORK else _CHAT_TASK_PATTERN
        )
        if re.fullmatch(task_pattern, self.surface_task_id) is None:
            raise ValueError("C9 rich task id does not match its surface")
        if self.execution_sha256 != _model_sha256(
            b"systeme-local/c9/rich-execution/v1\0",
            self,
            "execution_sha256",
        ):
            raise ValueError("C9 rich execution digest mismatch")
        return self

    @property
    def work_manifest_sha256(self) -> str:
        """Compatibility accessor for Work-only correlation migration."""

        if self.surface is not C9RichSurface.WORK:
            raise AttributeError("Chat execution has no Work manifest")
        return self.surface_manifest_sha256


# Transitional import compatibility for the attestation layer while it migrates.
C9WorkExecutionDescriptor = C9RichExecutionDescriptor


class C9ChatExportDescriptor(_StrictModel):
    version: Literal["1"] = "1"
    status: Literal["ready_for_operator_file_picker"]
    delivery_mode: Literal["operator_performed_manual_attachment_handoff"]
    qualifies_as_native_chat_success: Literal[False]
    plugin_mcp_invocation_claimed: Literal[False]
    automated_attachment_claimed: Literal[False]
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)
    c9_cycle_id: str = Field(pattern=_CYCLE_PATTERN)
    c9_grant_id: str = Field(pattern=_GRANT_PATTERN)
    combined_approval_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_approval_sha256: str = Field(pattern=_SHA256_PATTERN)
    lease_consumption_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    export_id: str = Field(pattern=r"^c9_export_[0-9a-f]{32}$")
    export_sha256: str = Field(pattern=_SHA256_PATTERN)
    attachment_count: Literal[2]
    created_at: datetime
    expires_at: datetime
    descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)

    _created_utc = field_validator("created_at")(_utc)
    _expires_utc = field_validator("expires_at")(_utc)

    @model_validator(mode="after")
    def validate_export(self) -> C9ChatExportDescriptor:
        if self.expires_at <= self.created_at:
            raise ValueError("C9 Chat export is already expired")
        if self.descriptor_sha256 != _model_sha256(
            b"systeme-local/c9/chat-export-descriptor/v1\0",
            self,
            "descriptor_sha256",
        ):
            raise ValueError("C9 Chat export descriptor digest mismatch")
        return self


class C9ChatPickerClaimReceipt(_StrictModel):
    version: Literal["1"] = "1"
    status: Literal["native_chat_manual_attachment_paths_claimed"]
    qualifies_as_native_chat_success: Literal[False]
    plugin_mcp_invocation_claimed: Literal[False]
    automated_attachment_claimed: Literal[False]
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)
    c9_cycle_id: str = Field(pattern=_CYCLE_PATTERN)
    c9_grant_id: str = Field(pattern=_GRANT_PATTERN)
    export_id: str = Field(pattern=r"^c9_export_[0-9a-f]{32}$")
    export_descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    attachment_count: Literal[2]
    claimed_at: datetime
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    _claimed_utc = field_validator("claimed_at")(_utc)

    @model_validator(mode="after")
    def validate_receipt(self) -> C9ChatPickerClaimReceipt:
        if self.receipt_sha256 != _model_sha256(
            b"systeme-local/c9/chat-picker-claim/v1\0",
            self,
            "receipt_sha256",
        ):
            raise ValueError("C9 Chat picker claim receipt digest mismatch")
        return self


class C9ChatConfirmationReceipt(_StrictModel):
    version: Literal["1"] = "1"
    status: Literal["native_chat_attachments_visibly_consumed"]
    source: Literal["operator_visible_native_chat_and_local_nonce_verification"]
    delivery_mode: Literal["operator_performed_manual_attachment_handoff"]
    qualifies_as_native_chat_success: Literal[True]
    plugin_mcp_invocation_claimed: Literal[False]
    automated_attachment_claimed: Literal[False]
    operator_file_picker_used: Literal[True]
    new_synthetic_native_chat_conversation: Literal[True]
    visible_response_observed: Literal[True]
    conversation_identifier_collected: Literal[False]
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)
    c9_cycle_id: str = Field(pattern=_CYCLE_PATTERN)
    c9_grant_id: str = Field(pattern=_GRANT_PATTERN)
    combined_approval_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_export_id: str = Field(pattern=r"^c9_export_[0-9a-f]{32}$")
    chat_export_descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_picker_claim_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    verified_nonce_sha256s: tuple[str, str]
    response_sha256: str = Field(pattern=_SHA256_PATTERN)
    manual_cleanup_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    confirmed_at: datetime
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    _confirmed_utc = field_validator("confirmed_at")(_utc)

    @model_validator(mode="after")
    def validate_receipt(self) -> C9ChatConfirmationReceipt:
        if any(
            re.fullmatch(_SHA256_PATTERN, value) is None for value in self.verified_nonce_sha256s
        ):
            raise ValueError("C9 Chat nonce commitment is invalid")
        if self.receipt_sha256 != _model_sha256(
            b"systeme-local/c9/chat-confirmation/v1\0",
            self,
            "receipt_sha256",
        ):
            raise ValueError("C9 Chat confirmation digest mismatch")
        return self


class C9CoordinatorStatus(_StrictModel):
    version: Literal["1"] = "1"
    state: Literal["empty", "staged", "admitted", "closed"]
    handoff_id: str | None = Field(default=None, pattern=_HANDOFF_PATTERN)
    c9_cycle_id: str | None = Field(default=None, pattern=_CYCLE_PATTERN)
    c9_grant_id: str | None = Field(default=None, pattern=_GRANT_PATTERN)
    effective_tool_count: Literal[0, 1]
    effective_tools: tuple[str, ...] = Field(max_length=1)
    work_executed: bool
    work_rendered: bool
    work_confirmed: bool
    native_chat_mcp_invoked: Literal[False]
    rich_call_count: int = Field(ge=0, le=1)
    rich_confirmation_count: int = Field(ge=0, le=1)
    native_chat_handoff_exported: bool
    native_chat_picker_claimed: bool
    native_chat_handoff_confirmed: bool
    evaluated_at: datetime

    _evaluated_utc = field_validator("evaluated_at")(_utc)

    @model_validator(mode="after")
    def validate_status(self) -> C9CoordinatorStatus:
        expected = (C9_ATTACHMENT_HANDOFF_TOOL_NAME,) if self.effective_tool_count == 1 else ()
        if self.effective_tools != expected:
            raise ValueError("C9 status tool scope mismatch")
        return self


class C9CoordinatorCloseReceipt(_StrictModel):
    version: Literal["1"] = "1"
    status: Literal["closed"]
    handoff_id: str | None = Field(default=None, pattern=_HANDOFF_PATTERN)
    pending_deliveries_zeroed: int = Field(ge=0, le=1)
    attachment_leases_cleaned: int = Field(ge=0)
    manual_exports_cleaned: int = Field(ge=0)
    rich_call_count: int = Field(ge=0, le=1)
    rich_confirmation_count: int = Field(ge=0, le=1)
    native_chat_manual_handoff_used: bool
    fixture_cleanup_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    admission_file_removed: bool
    closed_at: datetime
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    _closed_utc = field_validator("closed_at")(_utc)

    @model_validator(mode="after")
    def validate_close(self) -> C9CoordinatorCloseReceipt:
        if self.receipt_sha256 != _model_sha256(
            b"systeme-local/c9/coordinator-close/v1\0",
            self,
            "receipt_sha256",
        ):
            raise ValueError("C9 close receipt digest mismatch")
        return self


class C9LocalAIRunnerProtocol(Protocol):
    def __call__(
        self,
        *,
        config: C9LocalAIConfig,
        image_bytes: bytes,
        image_media_type: Literal["image/png", "image/jpeg"],
        document_bytes: bytes,
        document_media_type: Literal["text/plain"],
        expected_image_nonce_sha256: str,
        expected_document_nonce_sha256: str,
    ) -> C9LocalAIInference: ...


class C9LocalAIRuntimeContinuityVerifierProtocol(Protocol):
    def __call__(
        self,
        observation: C9LocalAIRuntimeObservation,
        *,
        endpoint: str,
    ) -> C9LocalAIRuntimeContinuitySnapshot: ...


class C9ManualExportManagerProtocol(Protocol):
    def materialize(
        self,
        *,
        manifest_sha256: str,
        payloads: tuple[
            tuple[C9AttachmentDescriptor, memoryview | bytes],
            ...,
        ],
        created_at: datetime,
        ttl: timedelta = timedelta(minutes=5),
    ) -> C9ManualExport: ...

    def claim_paths(
        self,
        export_id: str,
        *,
        claimed_at: datetime,
    ) -> tuple[Path, ...]: ...

    def cleanup(
        self,
        export_id: str,
        *,
        cleaned_at: datetime,
        reason: C9ManualCleanupReason = C9ManualCleanupReason.COMPLETED,
    ) -> C9ManualCleanupReceipt: ...

    def close(
        self,
        *,
        closed_at: datetime,
    ) -> tuple[C9ManualCleanupReceipt, ...]: ...


@dataclass(repr=False)
class _PendingRichDelivery:
    handoff_id: str
    surface: C9RichSurface
    public: C9RichExecutionDescriptor
    expansion: C9McpExpansionDescriptor
    payloads: tuple[tuple[C9AttachmentDescriptor, bytearray], ...]

    def zero(self) -> None:
        for _, content in self.payloads:
            content[:] = b"\0" * len(content)


@dataclass(repr=False)
class _HandoffRecord:
    fixture: C9SyntheticFixtureHandle
    fixture_receipt: C9SyntheticFixtureReceipt
    staged: C9HandoffStageReceipt
    work_leases: tuple[C9AttachmentLease, C9AttachmentLease]
    work_manifest: C9OutboundManifest
    chat_leases: tuple[C9AttachmentLease, C9AttachmentLease]
    chat_manifest: C9OutboundManifest
    local_ai_receipt: C9LocalAIReceipt
    approved: C9HandoffAdmission | None = None
    combined_approval: C9CombinedApproval | None = None
    work_approval: C9BoundApproval | None = None
    chat_approval: C9BoundApproval | None = None
    approval_attempted: bool = False
    terminal_failure: bool = False
    rich_execution_attempted: dict[C9RichSurface, bool] = dataclass_field(
        default_factory=lambda: {surface: False for surface in C9RichSurface}
    )
    rich_executions: dict[C9RichSurface, C9RichExecutionDescriptor] = dataclass_field(
        default_factory=dict
    )
    rich_sessions: dict[C9RichSurface, C9RichTaskSession] = dataclass_field(default_factory=dict)
    pending_rich: dict[C9RichSurface, _PendingRichDelivery] = dataclass_field(default_factory=dict)
    rich_render_prepared: dict[C9RichSurface, bool] = dataclass_field(
        default_factory=lambda: {surface: False for surface in C9RichSurface}
    )
    rich_rendered: dict[C9RichSurface, bool] = dataclass_field(
        default_factory=lambda: {surface: False for surface in C9RichSurface}
    )
    rich_confirmation_attempted: dict[C9RichSurface, bool] = dataclass_field(
        default_factory=lambda: {surface: False for surface in C9RichSurface}
    )
    rich_confirmations: dict[C9RichSurface, C9RichConsumptionReceipt] = dataclass_field(
        default_factory=dict
    )
    chat_export_attempted: bool = False
    chat_export: C9ManualExport | None = None
    chat_export_descriptor: C9ChatExportDescriptor | None = None
    chat_picker_claimed: bool = False
    chat_picker_claim_receipt: C9ChatPickerClaimReceipt | None = None
    chat_confirmation_attempted: bool = False
    chat_confirmation: C9ChatConfirmationReceipt | None = None
    fixture_cleaned: bool = False


def _commit_model(
    model_type: type[_ModelT],
    *,
    payload: dict[str, object],
    digest_field: str,
    domain: bytes,
) -> _ModelT:
    constructor_payload: Any = {**payload, digest_field: "0" * 64}
    draft = model_type.model_construct(**constructor_payload)
    committed = draft.model_copy(update={digest_field: _model_sha256(domain, draft, digest_field)})
    return model_type.model_validate(committed.model_dump(mode="python"))


def _exact_fixture_metadata(
    receipt: C9SyntheticFixtureReceipt,
    kind: C9SyntheticFixtureKind,
) -> Any:
    return next(item for item in receipt.fixtures if item.kind is kind)


def _copy_payloads(
    payloads: tuple[tuple[C9AttachmentDescriptor, memoryview], ...],
) -> tuple[tuple[C9AttachmentDescriptor, bytearray], ...]:
    copied = tuple((descriptor, bytearray(content)) for descriptor, content in payloads)
    for descriptor, content in copied:
        if (
            len(content) != descriptor.sanitized_inspection.byte_size
            or sha256(content).hexdigest() != descriptor.sanitized_inspection.content_sha256
        ):
            for _, buffer in copied:
                buffer[:] = b"\0" * len(buffer)
            raise ValueError("C9 copied payload integrity mismatch")
    return copied


def _atomic_write_metadata(
    path: Path,
    model: BaseModel,
    *,
    private_state: C9PrivateStateGuard,
) -> None:
    encoded = (
        json.dumps(
            model.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    try:
        private_state.atomic_write(path, encoded)
    except C9PrivateStateError as exc:
        raise C9HandoffError(
            C9HandoffReason.ATOMIC_COMMIT_FAILED,
            "C9 metadata-only state could not be committed",
        ) from exc


class C9HandoffCoordinator:
    """One process-local C9 authority spanning Work MCP and native Chat handoff.

    Raw attachment content exists only in ``C9AttachmentSecurity``, the private
    native-Chat export manager, and one pending Work MCP delivery. Public
    return values are immutable, digest-bound metadata.
    """

    def __init__(
        self,
        *,
        security: C9AttachmentSecurity,
        local_ai_config: C9LocalAIConfig,
        local_ai_runtime_observation: C9LocalAIRuntimeObservation,
        manual_manager: C9ManualExportManagerProtocol,
        mcp_capabilities: Mapping[
            C9RichSurface | str,
            C9McpHostCapabilities,
        ],
        repository_root: Path,
        admission_file: Path,
        audit_key: str | bytes,
        clock: Callable[[], datetime] | None = None,
        local_ai_runner: C9LocalAIRunnerProtocol = run_c9_local_ai_inference,
        local_ai_runtime_continuity_verifier: (
            C9LocalAIRuntimeContinuityVerifierProtocol
        ) = capture_c9_local_ai_runtime_continuity,
        private_state_guard: C9PrivateStateGuard | None = None,
    ) -> None:
        if not repository_root.is_absolute():
            raise ValueError("C9 repository root must be absolute")
        if not admission_file.is_absolute():
            raise ValueError("C9 admission file must be absolute")
        if len(audit_key.encode("utf-8") if isinstance(audit_key, str) else audit_key) < 32:
            raise ValueError("C9 audit key must contain at least 32 bytes")
        self._audit_key = audit_key
        self._clock = clock or (lambda: datetime.now(UTC))
        self._security = security
        self._local_ai_config = C9LocalAIConfig.model_validate(
            local_ai_config.model_dump(mode="python")
        )
        self._local_ai_runtime_observation = verify_c9_local_ai_runtime_observation(
            local_ai_runtime_observation,
            endpoint=self._local_ai_config.endpoint,
            visible_model_label=self._local_ai_config.visible_model_label,
            audit_key=audit_key,
            evaluated_at=self._now(),
        )
        if self._local_ai_config.runtime_observation_sha256 != (
            c9_local_ai_runtime_observation_sha256(self._local_ai_runtime_observation)
        ):
            raise ValueError("C9 local-AI configuration does not bind its runtime")
        self._manual_manager = manual_manager
        committed_capabilities: dict[C9RichSurface, C9McpHostCapabilities] = {}
        if len(mcp_capabilities) != 1:
            raise ValueError("C9 requires exactly one Work MCP capability observation")
        candidate = mcp_capabilities.get(C9RichSurface.WORK)
        if candidate is None:
            candidate = mcp_capabilities.get(C9RichSurface.WORK.value)
        if candidate is None:
            raise ValueError("C9 Work MCP capability observation is missing")
        committed = C9McpHostCapabilities.model_validate(candidate.model_dump(mode="python"))
        if committed.surface is not C9RichSurface.WORK:
            raise ValueError("C9 capability observation must be bound to Work")
        committed_capabilities[C9RichSurface.WORK] = committed
        self._mcp_capabilities = committed_capabilities
        self._repository_root = repository_root
        self._private_state = private_state_guard or C9PrivateStateGuard.for_existing_state(
            state_directory=admission_file.parent,
            admission_file=admission_file,
        )
        if self._private_state.admission_file != admission_file:
            raise ValueError("C9 private-state guard does not bind the admission file")
        self._admission_file = admission_file
        self._execution_files = {
            C9RichSurface.WORK: admission_file.parent / "work-execution.json",
        }
        for execution_file in self._execution_files.values():
            self._private_state.validate_target(
                execution_file,
                allow_missing_leaf=True,
            )
        self._local_ai_runner = local_ai_runner
        self._local_ai_runtime_continuity_verifier = local_ai_runtime_continuity_verifier
        self._lock = threading.RLock()
        self._record: _HandoffRecord | None = None
        self._closed = False
        self._close_receipt: C9CoordinatorCloseReceipt | None = None

    def __repr__(self) -> str:
        return "C9HandoffCoordinator(metadata_only=True)"

    @property
    def local_ai_cycle_id(self) -> str:
        """Return the non-secret cycle committed by the runtime observation."""

        return self._local_ai_runtime_observation.cycle_id

    def _now(self) -> datetime:
        return _utc(self._clock())

    def _require_open(self) -> None:
        if self._closed:
            _deny(
                C9HandoffReason.COORDINATOR_CLOSED,
                "C9 handoff coordinator is closed",
            )
        if self._record is not None and self._record.terminal_failure:
            _deny(
                C9HandoffReason.HANDOFF_EXPIRED,
                "C9 handoff coordinator is terminal after a security failure",
            )

    def _record_for(self, handoff_id: str) -> _HandoffRecord:
        record = self._record
        if record is None:
            _deny(
                C9HandoffReason.HANDOFF_NOT_STAGED,
                "C9 handoff has not been staged",
            )
        if not hmac.compare_digest(record.staged.handoff_id, handoff_id):
            _deny(
                C9HandoffReason.CROSS_HANDOFF_REJECTED,
                "C9 operation targets another handoff",
            )
        return record

    def stage(
        self,
        *,
        fixture: C9SyntheticFixtureHandle,
        purpose: str,
        staged_at: datetime | None = None,
        lease_ttl: timedelta = timedelta(minutes=10),
    ) -> C9HandoffStageReceipt:
        with self._lock:
            self._require_open()
            if self._record is not None:
                _deny(
                    C9HandoffReason.HANDOFF_ALREADY_STAGED,
                    "C9 admits exactly one synthetic handoff",
                )
            at = _utc(staged_at) if staged_at is not None else self._now()
            runtime_observation = verify_c9_local_ai_runtime_observation(
                self._local_ai_runtime_observation,
                endpoint=self._local_ai_config.endpoint,
                visible_model_label=self._local_ai_config.visible_model_label,
                audit_key=self._audit_key,
                evaluated_at=at,
            )
            runtime_observation_sha256 = c9_local_ai_runtime_observation_sha256(runtime_observation)
            fixture_receipt = C9SyntheticFixtureReceipt.model_validate(
                fixture.receipt.model_dump(mode="python")
            )
            image_metadata = _exact_fixture_metadata(
                fixture_receipt,
                C9SyntheticFixtureKind.IMAGE,
            )
            text_metadata = _exact_fixture_metadata(
                fixture_receipt,
                C9SyntheticFixtureKind.TEXT,
            )
            try:
                image_lease = self._security.select_file(
                    fixture.png_path,
                    operator_confirmed=True,
                    selected_at=at,
                    lease_ttl=lease_ttl,
                    declared_media_type=image_metadata.media_type,
                )
                text_lease = self._security.select_file(
                    fixture.text_path,
                    operator_confirmed=True,
                    selected_at=at,
                    lease_ttl=lease_ttl,
                    declared_media_type=text_metadata.media_type,
                )
                work_leases = (image_lease, text_lease)
                if (
                    image_lease.descriptor.source_content_sha256 != image_metadata.content_sha256
                    or text_lease.descriptor.source_content_sha256 != text_metadata.content_sha256
                ):
                    _deny(
                        C9HandoffReason.MANIFEST_BINDING_MISMATCH,
                        "C9 selected content does not match the synthetic fixture receipt",
                    )
                work_manifest = self._security.create_outbound_manifest(
                    tuple(item.lease_id for item in work_leases),
                    surface=C9OutboundSurface.CHATGPT_WORK,
                    purpose=purpose,
                    created_at=at,
                )

                def inspect(
                    payloads: tuple[
                        tuple[C9AttachmentDescriptor, memoryview],
                        ...,
                    ],
                ) -> C9LocalAIInference:
                    image = next(
                        item
                        for item in payloads
                        if media_family(item[0].media_type) is AttachmentMediaFamily.IMAGE
                    )
                    document = next(
                        item for item in payloads if item[0].media_type is AttachmentMediaType.TEXT
                    )
                    continuity_before = self._local_ai_runtime_continuity_verifier(
                        self._local_ai_runtime_observation,
                        endpoint=self._local_ai_config.endpoint,
                    )
                    try:
                        return self._local_ai_runner(
                            config=self._local_ai_config,
                            image_bytes=bytes(image[1]),
                            image_media_type=cast(
                                Literal["image/png", "image/jpeg"],
                                image[0].media_type.value,
                            ),
                            document_bytes=bytes(document[1]),
                            document_media_type="text/plain",
                            expected_image_nonce_sha256=image_metadata.nonce_sha256,
                            expected_document_nonce_sha256=text_metadata.nonce_sha256,
                        )
                    finally:
                        continuity_after = self._local_ai_runtime_continuity_verifier(
                            self._local_ai_runtime_observation,
                            endpoint=self._local_ai_config.endpoint,
                        )
                        verify_c9_local_ai_runtime_continuity_pair(
                            continuity_before,
                            continuity_after,
                        )

                inference = self._security.inspect_manifest_payloads(
                    work_manifest,
                    inspected_at=at,
                    inspector=inspect,
                )
                local_receipt = C9LocalAIReceipt.model_validate(
                    inference.receipt.model_dump(mode="python")
                )
                if (
                    local_receipt.expected_image_nonce_sha256 != image_metadata.nonce_sha256
                    or local_receipt.expected_document_nonce_sha256 != text_metadata.nonce_sha256
                    or local_receipt.runtime_observation_sha256 != runtime_observation_sha256
                    or local_receipt.image_sha256
                    != image_lease.descriptor.sanitized_inspection.content_sha256
                    or local_receipt.document_sha256
                    != text_lease.descriptor.sanitized_inspection.content_sha256
                ):
                    _deny(
                        C9HandoffReason.LOCAL_AI_BINDING_MISMATCH,
                        "C9 local-AI receipt does not bind the staged package",
                    )
                cloned, chat_manifest = self._security.clone_manifest_leases(
                    work_manifest,
                    target_surface=C9OutboundSurface.CHATGPT_CHAT_MANUAL,
                    cloned_at=at,
                    lease_ttl=lease_ttl,
                )
                if len(cloned) != 2:
                    raise ValueError("C9 cloned lease count mismatch")
                chat_leases = (cloned[0], cloned[1])
                if chat_manifest.attachments != work_manifest.attachments:
                    _deny(
                        C9HandoffReason.MANIFEST_BINDING_MISMATCH,
                        "C9 native Chat manual clone does not bind the Work package",
                    )
                handoff_id = f"c9_handoff_{secrets.token_hex(16)}"
                attachments = (
                    C9StagedAttachment(
                        attachment_id=image_lease.descriptor.attachment_id,
                        kind=C9SyntheticFixtureKind.IMAGE,
                        media_type=image_lease.descriptor.media_type,
                        content_sha256=(image_lease.descriptor.sanitized_inspection.content_sha256),
                        nonce_sha256=image_metadata.nonce_sha256,
                        descriptor_sha256=image_lease.descriptor.descriptor_sha256,
                    ),
                    C9StagedAttachment(
                        attachment_id=text_lease.descriptor.attachment_id,
                        kind=C9SyntheticFixtureKind.TEXT,
                        media_type=text_lease.descriptor.media_type,
                        content_sha256=(text_lease.descriptor.sanitized_inspection.content_sha256),
                        nonce_sha256=text_metadata.nonce_sha256,
                        descriptor_sha256=text_lease.descriptor.descriptor_sha256,
                    ),
                )
                payload: dict[str, object] = {
                    "version": "1",
                    "handoff_id": handoff_id,
                    "work_task_id": f"c9_work_{secrets.token_hex(16)}",
                    "chat_task_id": f"c9_chat_{secrets.token_hex(16)}",
                    "fixture_package_id": fixture_receipt.package_id,
                    "fixture_receipt_sha256": fixture_receipt.receipt_sha256,
                    "work_manifest_sha256": work_manifest.manifest_sha256,
                    "chat_manifest_sha256": chat_manifest.manifest_sha256,
                    "local_ai_receipt_sha256": local_receipt.receipt_sha256,
                    "local_ai_runtime_observation_sha256": (runtime_observation_sha256),
                    "attachments": attachments,
                    "staged_at": at,
                    "expires_at": min(
                        work_manifest.expires_at,
                        chat_manifest.expires_at,
                    ),
                }
                staged = _commit_model(
                    C9HandoffStageReceipt,
                    payload=payload,
                    digest_field="stage_sha256",
                    domain=b"systeme-local/c9/handoff-stage/v1\0",
                )
                assert isinstance(staged, C9HandoffStageReceipt)
                self._record = _HandoffRecord(
                    fixture=fixture,
                    fixture_receipt=fixture_receipt,
                    staged=staged,
                    work_leases=work_leases,
                    work_manifest=work_manifest,
                    chat_leases=chat_leases,
                    chat_manifest=chat_manifest,
                    local_ai_receipt=local_receipt,
                )
                return staged
            except Exception:
                try:
                    self._security.cancel_all(cancelled_at=at)
                finally:
                    fixture.cleanup(cleaned_at=at)
                raise

    def refresh_mcp_capabilities(
        self,
        capabilities: C9McpHostCapabilities,
        *,
        evaluated_at: datetime | None = None,
    ) -> C9McpHostCapabilities:
        """Install one fresh metadata-only capability observation for its surface."""

        with self._lock:
            self._require_open()
            record = self._record
            if record is not None and record.approved is not None:
                _deny(
                    C9HandoffReason.HANDOFF_ALREADY_APPROVED,
                    "C9 capabilities cannot change after combined approval",
                )
            at = _utc(evaluated_at) if evaluated_at is not None else self._now()
            committed = C9McpHostCapabilities.model_validate(capabilities.model_dump(mode="python"))
            if committed.surface is not C9RichSurface.WORK:
                _deny(
                    C9HandoffReason.UNSUPPORTED_SURFACE,
                    "C9 exposes MCP rich content only on ChatGPT Work",
                )
            if not committed.observed_at <= at < committed.expires_at:
                _deny(
                    C9HandoffReason.HANDOFF_EXPIRED,
                    "C9 MCP content capability observation is not fresh",
                )
            self._mcp_capabilities[committed.surface] = committed
            return committed

    def approve_handoff(
        self,
        *,
        handoff_id: str,
        operator_confirmed: bool,
        operator_identity: str,
        authorization: c9_live_cycle.C9OperatorAuthorization,
        surface_observation: c9_live_cycle.C9SurfaceObservation,
        grant_id: str,
        approved_at: datetime | None = None,
        approval_ttl: timedelta = _MAX_APPROVAL_TTL,
    ) -> C9HandoffAdmission:
        with self._lock:
            self._require_open()
            record = self._record_for(handoff_id)
            if record.approval_attempted:
                _deny(
                    C9HandoffReason.HANDOFF_ALREADY_APPROVED,
                    "C9 combined approval is one-use",
                )
            record.approval_attempted = True
            at = _utc(approved_at) if approved_at is not None else self._now()
            try:
                if not operator_confirmed:
                    _deny(
                        C9HandoffReason.HANDOFF_NOT_APPROVED,
                        "C9 requires one explicit combined approval",
                    )
                committed_authorization = c9_live_cycle.C9OperatorAuthorization.model_validate(
                    authorization.model_dump(mode="python")
                )
                committed_surface = c9_live_cycle.C9SurfaceObservation.model_validate(
                    surface_observation.model_dump(mode="python")
                )
                if (
                    committed_authorization.selected_package_manifest_sha256
                    != record.work_manifest.manifest_sha256
                    or committed_authorization.cycle_id != committed_surface.cycle_id
                ):
                    _deny(
                        C9HandoffReason.MANIFEST_BINDING_MISMATCH,
                        "C9 authorization does not bind the staged package and cycle",
                    )
                if any(
                    not capability.observed_at <= at < capability.expires_at
                    for capability in self._mcp_capabilities.values()
                ):
                    _deny(
                        C9HandoffReason.HANDOFF_EXPIRED,
                        "The C9 Work MCP capability observation is not fresh",
                    )
                ttl = min(approval_ttl, _MAX_APPROVAL_TTL)
                if ttl <= timedelta(0):
                    raise ValueError("C9 approval TTL must be positive")
                work_approval = self._security.approve_manifest(
                    record.work_manifest,
                    operator_confirmed=True,
                    operator_identity=operator_identity,
                    approved_at=at,
                    approval_ttl=ttl,
                )
                chat_approval = self._security.approve_manifest(
                    record.chat_manifest,
                    operator_confirmed=True,
                    operator_identity=operator_identity,
                    approved_at=at,
                    approval_ttl=ttl,
                )
                combined_payload: dict[str, object] = {
                    "version": "1",
                    "handoff_id": record.staged.handoff_id,
                    "fixture_receipt_sha256": (record.fixture_receipt.receipt_sha256),
                    "local_ai_receipt_sha256": (record.local_ai_receipt.receipt_sha256),
                    "local_ai_runtime_observation_sha256": (
                        record.local_ai_receipt.runtime_observation_sha256
                    ),
                    "work_manifest_sha256": record.work_manifest.manifest_sha256,
                    "work_approval_sha256": work_approval.approval_sha256,
                    "chat_manifest_sha256": record.chat_manifest.manifest_sha256,
                    "chat_approval_sha256": chat_approval.approval_sha256,
                    "operator_identity_sha256": sha256(
                        operator_identity.encode("utf-8")
                    ).hexdigest(),
                    "approved_at": at,
                    "expires_at": min(
                        work_approval.expires_at,
                        chat_approval.expires_at,
                    ),
                }
                combined = _commit_model(
                    C9CombinedApproval,
                    payload=combined_payload,
                    digest_field="combined_approval_sha256",
                    domain=b"systeme-local/c9/combined-approval/v1\0",
                )
                assert isinstance(combined, C9CombinedApproval)
                grant_expiry = min(
                    at + timedelta(seconds=c9_live_cycle.C9_MAX_LIVE_CYCLE_SECONDS),
                    combined.expires_at,
                    committed_authorization.expires_at,
                    self._local_ai_runtime_observation.expires_at,
                )
                bundle = c9_live_cycle.issue_c9_live_cycle_bundle(
                    authorization=committed_authorization,
                    surface_observation=committed_surface,
                    grant_id=grant_id,
                    local_ai_receipt=record.local_ai_receipt,
                    local_ai_runtime_observation=(self._local_ai_runtime_observation),
                    root=self._repository_root,
                    issued_at=at,
                    expires_at=grant_expiry,
                    audit_key=self._audit_key,
                )
                decision = c9_live_cycle.verify_c9_live_cycle_bundle(
                    bundle=bundle,
                    root=self._repository_root,
                    audit_key=self._audit_key,
                    evaluated_at=at,
                )
                if (
                    not decision.live_actions_allowed
                    or decision.effective_tools != (C9_ATTACHMENT_HANDOFF_TOOL_NAME,)
                    or bundle.grant.c8_live_cycle_grant_reused
                ):
                    _deny(
                        C9HandoffReason.ADMISSION_REJECTED,
                        "C9 live-cycle admission rejected the exact handoff",
                    )
                admission_payload: dict[str, object] = {
                    "version": "1",
                    "handoff_id": record.staged.handoff_id,
                    "combined_approval": combined,
                    "live_cycle_bundle": bundle,
                    "admission_decision": decision,
                    "committed_at": at,
                }
                admission = _commit_model(
                    C9HandoffAdmission,
                    payload=admission_payload,
                    digest_field="admission_sha256",
                    domain=b"systeme-local/c9/handoff-admission/v1\0",
                )
                assert isinstance(admission, C9HandoffAdmission)
                _atomic_write_metadata(
                    self._admission_file,
                    admission,
                    private_state=self._private_state,
                )
                record.work_approval = work_approval
                record.chat_approval = chat_approval
                record.combined_approval = combined
                record.approved = admission
                return admission
            except Exception:
                record.terminal_failure = True
                try:
                    self._security.cancel_all(cancelled_at=at)
                finally:
                    record.fixture.cleanup(cleaned_at=at)
                    record.fixture_cleaned = True
                raise

    def status(self, *, evaluated_at: datetime | None = None) -> C9CoordinatorStatus:
        with self._lock:
            at = _utc(evaluated_at) if evaluated_at is not None else self._now()
            record = self._record
            enabled = self._tool_enabled(at)
            if self._closed:
                state: Literal["empty", "staged", "admitted", "closed"] = "closed"
            elif record is None:
                state = "empty"
            elif record.approved is None:
                state = "staged"
            else:
                state = "admitted"
            grant = record.approved.live_cycle_bundle.grant if record and record.approved else None
            return C9CoordinatorStatus(
                state=state,
                handoff_id=record.staged.handoff_id if record else None,
                c9_cycle_id=grant.cycle_id if grant else None,
                c9_grant_id=grant.grant_id if grant else None,
                effective_tool_count=1 if enabled else 0,
                effective_tools=((C9_ATTACHMENT_HANDOFF_TOOL_NAME,) if enabled else ()),
                work_executed=bool(record and C9RichSurface.WORK in record.rich_executions),
                work_rendered=bool(record and record.rich_rendered[C9RichSurface.WORK]),
                work_confirmed=bool(record and C9RichSurface.WORK in record.rich_confirmations),
                native_chat_mcp_invoked=False,
                rich_call_count=(len(record.rich_executions) if record is not None else 0),
                rich_confirmation_count=(
                    len(record.rich_confirmations) if record is not None else 0
                ),
                native_chat_handoff_exported=bool(record and record.chat_export is not None),
                native_chat_picker_claimed=bool(record and record.chat_picker_claimed),
                native_chat_handoff_confirmed=bool(record and record.chat_confirmation is not None),
                evaluated_at=at,
            )

    def _tool_enabled(self, at: datetime) -> bool:
        record = self._record
        if (
            self._closed
            or record is None
            or record.approved is None
            or record.combined_approval is None
            or record.terminal_failure
            or record.rich_execution_attempted[C9RichSurface.WORK]
        ):
            return False
        grant = record.approved.live_cycle_bundle.grant
        work_capability = self._mcp_capabilities[C9RichSurface.WORK]
        return (
            grant.issued_at <= at < grant.expires_at
            and at < record.combined_approval.expires_at
            and work_capability.observed_at <= at < work_capability.expires_at
        )

    def tool_enabled(self, *, evaluated_at: datetime | None = None) -> bool:
        with self._lock:
            at = _utc(evaluated_at) if evaluated_at is not None else self._now()
            return self._tool_enabled(at)

    def execute_rich_handoff(
        self,
        handoff_id: str,
        *,
        surface: C9RichSurface,
        executed_at: datetime | None = None,
    ) -> C9RichExecutionDescriptor:
        with self._lock:
            self._require_open()
            record = self._record_for(handoff_id)
            committed_surface = C9RichSurface(surface)
            if committed_surface is not C9RichSurface.WORK:
                record.terminal_failure = True
                _deny(
                    C9HandoffReason.UNSUPPORTED_SURFACE,
                    "C9 Plugin/MCP attachment delivery is supported only on Work; "
                    "the forbidden surface attempt terminated this cycle",
                )
            at = _utc(executed_at) if executed_at is not None else self._now()
            if record.rich_execution_attempted[committed_surface]:
                _deny(
                    C9HandoffReason.RICH_SURFACE_REPLAY_REJECTED,
                    f"C9 {committed_surface.value} handoff was already attempted",
                )
            if not self._tool_enabled(at):
                _deny(C9HandoffReason.HANDOFF_EXPIRED, "C9 rich handoff is not active")
            capability = self._mcp_capabilities[committed_surface]
            if not capability.observed_at <= at < capability.expires_at:
                _deny(
                    C9HandoffReason.HANDOFF_EXPIRED,
                    f"C9 {committed_surface.value} capability observation is not fresh",
                )
            record.rich_execution_attempted[committed_surface] = True
            admission = record.approved
            combined = record.combined_approval
            surface_approval = record.work_approval
            surface_manifest = record.work_manifest
            surface_leases = record.work_leases
            surface_task_id = record.staged.work_task_id
            if admission is None or combined is None or surface_approval is None:
                record.terminal_failure = True
                _deny(
                    C9HandoffReason.HANDOFF_NOT_APPROVED,
                    "C9 rich handoff lacks verified surface approval",
                )
            grant = admission.live_cycle_bundle.grant
            proof_hashes = {
                item.attachment_id: item.nonce_sha256 for item in record.staged.attachments
            }
            expansion = build_mcp_expansion_descriptor(
                descriptor_id=f"c9_delivery_{secrets.token_hex(16)}",
                accepted_c8_commit=grant.c8_tag_target,
                c9_cycle_id=grant.cycle_id,
                c9_grant_id=grant.grant_id,
                surface=committed_surface,
                surface_task_id=surface_task_id,
                capabilities=capability,
                manifest=surface_manifest,
                approval=surface_approval,
                leases=surface_leases,
                proof_nonce_sha256s=proof_hashes,
                created_at=at,
            )
            session = C9RichTaskSession(
                surface=committed_surface,
                surface_task_id=surface_task_id,
            )
            session.stage(
                descriptor=expansion,
                manifest=surface_manifest,
                approval=surface_approval,
                leases=surface_leases,
                staged_at=at,
            )
            pending_payloads: (
                tuple[
                    tuple[C9AttachmentDescriptor, bytearray],
                    ...,
                ]
                | None
            ) = None

            def consume(
                payloads: tuple[
                    tuple[C9AttachmentDescriptor, memoryview],
                    ...,
                ],
            ) -> tuple[tuple[C9AttachmentDescriptor, bytearray], ...]:
                return _copy_payloads(payloads)

            try:
                pending_payloads, consumption = self._security.consume_manifest(
                    surface_manifest,
                    surface_approval,
                    consumed_at=at,
                    consumer=consume,
                )
                delivery_token = f"c9_delivery_{secrets.token_hex(16)}"
                execution_payload: dict[str, object] = {
                    "version": "1",
                    "status": "pending_mcp_rich_content_render",
                    "handoff_id": record.staged.handoff_id,
                    "surface": committed_surface,
                    "surface_task_id": surface_task_id,
                    "delivery_token": delivery_token,
                    "c9_cycle_id": grant.cycle_id,
                    "c9_grant_id": grant.grant_id,
                    "accepted_c8_commit": grant.c8_tag_target,
                    "combined_approval_sha256": (combined.combined_approval_sha256),
                    "surface_manifest_sha256": surface_manifest.manifest_sha256,
                    "expansion_descriptor_sha256": (expansion.descriptor_sha256),
                    "lease_consumption_receipt_sha256": (consumption.receipt_sha256),
                    "attachment_count": 2,
                    "executed_at": at,
                    "expires_at": min(
                        expansion.expires_at,
                        grant.expires_at,
                    ),
                }
                execution = _commit_model(
                    C9RichExecutionDescriptor,
                    payload=execution_payload,
                    digest_field="execution_sha256",
                    domain=b"systeme-local/c9/rich-execution/v1\0",
                )
                assert isinstance(execution, C9RichExecutionDescriptor)
                assert pending_payloads is not None
                _atomic_write_metadata(
                    self._execution_files[committed_surface],
                    execution,
                    private_state=self._private_state,
                )
                pending = _PendingRichDelivery(
                    handoff_id=record.staged.handoff_id,
                    surface=committed_surface,
                    public=execution,
                    expansion=expansion,
                    payloads=pending_payloads,
                )
                record.rich_sessions[committed_surface] = session
                record.rich_executions[committed_surface] = execution
                record.pending_rich[committed_surface] = pending
                self._cleanup_fixture_if_consumed(record, at)
                return execution
            except Exception:
                if pending_payloads is not None:
                    for _, content in pending_payloads:
                        content[:] = b"\0" * len(content)
                record.terminal_failure = True
                raise

    def execute_work_handoff(
        self,
        handoff_id: str,
        *,
        executed_at: datetime | None = None,
    ) -> C9RichExecutionDescriptor:
        """Compatibility wrapper; the MCP handler uses ``execute_rich_handoff``."""

        return self.execute_rich_handoff(
            handoff_id,
            surface=C9RichSurface.WORK,
            executed_at=executed_at,
        )

    def _prepare_rich_render(
        self,
        *,
        handoff_id: str,
        surface: C9RichSurface,
        delivery_token: str,
        rendered_at: datetime,
    ) -> _PendingRichDelivery:
        with self._lock:
            self._require_open()
            record = self._record_for(handoff_id)
            committed_surface = C9RichSurface(surface)
            if committed_surface is not C9RichSurface.WORK:
                _deny(
                    C9HandoffReason.UNSUPPORTED_SURFACE,
                    "C9 rich-content rendering is supported only on Work",
                )
            pending = record.pending_rich.get(committed_surface)
            if (
                pending is None
                or record.rich_render_prepared[committed_surface]
                or record.rich_rendered[committed_surface]
            ):
                _deny(
                    C9HandoffReason.RICH_RENDER_REPLAY_REJECTED,
                    "C9 rich content was already prepared or committed",
                )
            if (
                not hmac.compare_digest(
                    pending.public.delivery_token,
                    delivery_token,
                )
                or not hmac.compare_digest(pending.handoff_id, handoff_id)
                or pending.surface is not committed_surface
            ):
                _deny(
                    C9HandoffReason.RENDER_BINDING_MISMATCH,
                    "C9 renderer token does not bind the handoff",
                )
            if rendered_at >= pending.public.expires_at:
                pending.zero()
                record.pending_rich.pop(committed_surface, None)
                record.terminal_failure = True
                _deny(
                    C9HandoffReason.HANDOFF_EXPIRED,
                    "C9 rich-content delivery expired",
                )
            record.rich_render_prepared[committed_surface] = True
            return pending

    def _complete_rich_render(
        self,
        *,
        handoff_id: str,
        surface: C9RichSurface,
        delivery_token: str,
    ) -> None:
        with self._lock:
            self._require_open()
            record = self._record_for(handoff_id)
            committed_surface = C9RichSurface(surface)
            if committed_surface is not C9RichSurface.WORK:
                _deny(
                    C9HandoffReason.UNSUPPORTED_SURFACE,
                    "C9 rich-content rendering is supported only on Work",
                )
            execution = record.rich_executions.get(committed_surface)
            pending = record.pending_rich.get(committed_surface)
            if (
                execution is None
                or pending is None
                or not record.rich_render_prepared[committed_surface]
                or record.rich_rendered[committed_surface]
                or execution.surface is not committed_surface
                or pending.surface is not committed_surface
                or not hmac.compare_digest(
                    execution.delivery_token,
                    delivery_token,
                )
                or not hmac.compare_digest(
                    pending.public.delivery_token,
                    delivery_token,
                )
            ):
                _deny(
                    C9HandoffReason.RENDER_BINDING_MISMATCH,
                    "C9 rendered result does not bind the pending delivery",
                )
            record.pending_rich.pop(committed_surface, None)
            record.rich_render_prepared[committed_surface] = False
            record.rich_rendered[committed_surface] = True

    def _fail_rich_render(
        self,
        *,
        handoff_id: str,
        surface: C9RichSurface,
        delivery_token: str,
    ) -> None:
        with self._lock:
            record = self._record_for(handoff_id)
            committed_surface = C9RichSurface(surface)
            if committed_surface is not C9RichSurface.WORK:
                _deny(
                    C9HandoffReason.UNSUPPORTED_SURFACE,
                    "C9 rich-content rendering is supported only on Work",
                )
            execution = record.rich_executions.get(committed_surface)
            if execution is not None and hmac.compare_digest(
                execution.delivery_token,
                delivery_token,
            ):
                pending = record.pending_rich.get(committed_surface)
                if pending is not None and hmac.compare_digest(
                    pending.public.delivery_token,
                    delivery_token,
                ):
                    pending.zero()
                    record.pending_rich.pop(committed_surface, None)
                record.rich_render_prepared[committed_surface] = False
                record.terminal_failure = True
                record.rich_rendered[committed_surface] = False

    def confirm_rich_surface(
        self,
        *,
        handoff_id: str,
        surface: C9RichSurface,
        surface_task_id: str,
        descriptor_sha256: str,
        manifest_sha256: str,
        observed_nonces: Mapping[str, str],
        response_text: str,
        confirmed_at: datetime | None = None,
    ) -> C9RichConsumptionReceipt:
        with self._lock:
            self._require_open()
            record = self._record_for(handoff_id)
            committed_surface = C9RichSurface(surface)
            if committed_surface is not C9RichSurface.WORK:
                _deny(
                    C9HandoffReason.UNSUPPORTED_SURFACE,
                    "C9 rich-content confirmation is supported only on Work",
                )
            if record.rich_confirmation_attempted[committed_surface]:
                _deny(
                    C9HandoffReason.RICH_SURFACE_REPLAY_REJECTED,
                    f"C9 {committed_surface.value} proof was already attempted",
                )
            record.rich_confirmation_attempted[committed_surface] = True
            at = _utc(confirmed_at) if confirmed_at is not None else self._now()
            session = record.rich_sessions.get(committed_surface)
            execution = record.rich_executions.get(committed_surface)
            expected_task_id = record.staged.work_task_id
            expected_manifest_sha256 = record.work_manifest.manifest_sha256
            if not record.rich_rendered[committed_surface] or session is None or execution is None:
                record.terminal_failure = True
                _deny(
                    C9HandoffReason.RICH_SURFACE_REPLAY_REJECTED,
                    f"C9 {committed_surface.value} rich content has not been rendered",
                )
            if (
                surface_task_id != expected_task_id
                or manifest_sha256 != expected_manifest_sha256
                or execution.surface_task_id != expected_task_id
                or execution.surface_manifest_sha256 != expected_manifest_sha256
            ):
                record.terminal_failure = True
                _deny(
                    C9HandoffReason.SURFACE_BINDING_MISMATCH,
                    "C9 rich response does not bind its exact surface task and manifest",
                )
            try:
                receipt = session.verify_and_consume(
                    surface_task_id=surface_task_id,
                    descriptor_sha256=descriptor_sha256,
                    observed_nonces=observed_nonces,
                    response_text=response_text,
                    observed_at=at,
                )
            except Exception:
                record.terminal_failure = True
                raise
            record.rich_confirmations[committed_surface] = receipt
            capability = self._mcp_capabilities[committed_surface]
            self._mcp_capabilities[committed_surface] = (
                promote_mcp_host_capabilities_after_live_proof(
                    capabilities=capability,
                    receipt=receipt,
                    promoted_at=at,
                    expires_at=capability.expires_at,
                )
            )
            return receipt

    def confirm_work(
        self,
        *,
        handoff_id: str,
        descriptor_sha256: str,
        observed_nonces: Mapping[str, str],
        response_text: str,
        confirmed_at: datetime | None = None,
    ) -> C9RichConsumptionReceipt:
        """Compatibility wrapper for the existing Work control endpoint."""

        record = self._record_for(handoff_id)
        return self.confirm_rich_surface(
            handoff_id=handoff_id,
            surface=C9RichSurface.WORK,
            surface_task_id=record.staged.work_task_id,
            descriptor_sha256=descriptor_sha256,
            manifest_sha256=record.work_manifest.manifest_sha256,
            observed_nonces=observed_nonces,
            response_text=response_text,
            confirmed_at=confirmed_at,
        )

    def prepare_native_chat_handoff(
        self,
        *,
        handoff_id: str,
        created_at: datetime | None = None,
        ttl: timedelta = timedelta(minutes=5),
    ) -> C9ChatExportDescriptor:
        """Materialize the approved package for one visible operator file-picker use.

        This prepares the only eligible native-Chat path. It is not an MCP
        call, cannot run until the Work rich-content receipt is confirmed, and
        does not qualify as success until visible Chat confirmation succeeds.
        """

        with self._lock:
            self._require_open()
            record = self._record_for(handoff_id)
            if record.chat_export_attempted:
                _deny(
                    C9HandoffReason.CHAT_REPLAY_REJECTED,
                    "C9 native Chat handoff export is one-use",
                )
            at = _utc(created_at) if created_at is not None else self._now()
            admission = record.approved
            combined = record.combined_approval
            chat_approval = record.chat_approval
            if admission is None or combined is None or chat_approval is None:
                _deny(
                    C9HandoffReason.HANDOFF_NOT_APPROVED,
                    "C9 native Chat handoff lacks the combined approval",
                )
            if C9RichSurface.WORK not in record.rich_confirmations:
                _deny(
                    C9HandoffReason.SURFACE_ORDER_REJECTED,
                    "C9 native Chat handoff requires the confirmed Work proof first",
                )
            record.chat_export_attempted = True
            if at >= admission.live_cycle_bundle.grant.expires_at or at >= combined.expires_at:
                _deny(
                    C9HandoffReason.HANDOFF_EXPIRED,
                    "C9 native Chat handoff approval is expired",
                )

            def materialize(
                payloads: tuple[
                    tuple[C9AttachmentDescriptor, memoryview],
                    ...,
                ],
            ) -> C9ManualExport:
                return self._manual_manager.materialize(
                    manifest_sha256=record.chat_manifest.manifest_sha256,
                    payloads=payloads,
                    created_at=at,
                    ttl=ttl,
                )

            try:
                export, consumption = self._security.consume_manifest(
                    record.chat_manifest,
                    chat_approval,
                    consumed_at=at,
                    consumer=materialize,
                )
                grant = admission.live_cycle_bundle.grant
                descriptor_payload: dict[str, object] = {
                    "version": "1",
                    "status": "ready_for_operator_file_picker",
                    "delivery_mode": "operator_performed_manual_attachment_handoff",
                    "qualifies_as_native_chat_success": False,
                    "plugin_mcp_invocation_claimed": False,
                    "automated_attachment_claimed": False,
                    "handoff_id": record.staged.handoff_id,
                    "c9_cycle_id": grant.cycle_id,
                    "c9_grant_id": grant.grant_id,
                    "combined_approval_sha256": (combined.combined_approval_sha256),
                    "chat_manifest_sha256": (record.chat_manifest.manifest_sha256),
                    "chat_approval_sha256": chat_approval.approval_sha256,
                    "lease_consumption_receipt_sha256": (consumption.receipt_sha256),
                    "export_id": export.export_id,
                    "export_sha256": export.export_sha256,
                    "attachment_count": 2,
                    "created_at": at,
                    "expires_at": min(
                        export.expires_at,
                        grant.expires_at,
                    ),
                }
                descriptor = _commit_model(
                    C9ChatExportDescriptor,
                    payload=descriptor_payload,
                    digest_field="descriptor_sha256",
                    domain=b"systeme-local/c9/chat-export-descriptor/v1\0",
                )
                assert isinstance(descriptor, C9ChatExportDescriptor)
                record.chat_export = export
                record.chat_export_descriptor = descriptor
                self._cleanup_fixture_if_consumed(record, at)
                return descriptor
            except Exception:
                record.terminal_failure = True
                raise

    def prepare_manual_fallback(
        self,
        *,
        handoff_id: str,
        operator_confirmed_fallback: bool,
        operator_identity: str,
        created_at: datetime | None = None,
        ttl: timedelta = timedelta(minutes=5),
    ) -> C9ChatExportDescriptor:
        """Reject the obsolete fallback API.

        Native Chat is now an explicitly approved manual handoff destination,
        not a fallback that can be promoted after the fact.
        """

        del operator_confirmed_fallback, operator_identity, created_at, ttl
        self._record_for(handoff_id)
        _deny(
            C9HandoffReason.UNSUPPORTED_SURFACE,
            "C9 manual fallback API was replaced by the approved native Chat handoff",
        )

    def prepare_chat_export(
        self,
        *,
        handoff_id: str,
        created_at: datetime | None = None,
        ttl: timedelta = timedelta(minutes=5),
    ) -> C9ChatExportDescriptor:
        """Compatibility wrapper for the approved native-Chat handoff."""

        return self.prepare_native_chat_handoff(
            handoff_id=handoff_id,
            created_at=created_at,
            ttl=ttl,
        )

    @staticmethod
    def _chat_export_deadline(record: _HandoffRecord) -> datetime:
        export = record.chat_export
        descriptor = record.chat_export_descriptor
        admission = record.approved
        combined = record.combined_approval
        if export is None or descriptor is None or admission is None or combined is None:
            _deny(
                C9HandoffReason.CHAT_EXPORT_NOT_CLAIMED,
                "C9 native Chat export lacks its exact authorization binding",
            )
        return min(
            export.expires_at,
            descriptor.expires_at,
            admission.live_cycle_bundle.grant.expires_at,
            combined.expires_at,
            record.staged.expires_at,
        )

    def _expire_chat_export(
        self,
        record: _HandoffRecord,
        *,
        at: datetime,
    ) -> NoReturn:
        export = record.chat_export
        if export is None:  # pragma: no cover - caller establishes the export
            _deny(
                C9HandoffReason.CHAT_EXPORT_NOT_CLAIMED,
                "C9 native Chat export is unavailable",
            )
        record.terminal_failure = True
        self._manual_manager.cleanup(
            export.export_id,
            cleaned_at=at,
            reason=C9ManualCleanupReason.EXPIRED,
        )
        _deny(
            C9HandoffReason.HANDOFF_EXPIRED,
            "C9 native Chat export or its authorization expired",
        )

    def claim_native_chat_handoff_paths(
        self,
        *,
        handoff_id: str,
        export_id: str,
        claimed_at: datetime | None = None,
    ) -> tuple[Path, ...]:
        with self._lock:
            self._require_open()
            record = self._record_for(handoff_id)
            at = _utc(claimed_at) if claimed_at is not None else self._now()
            if (
                record.chat_export is None
                or record.chat_export_descriptor is None
                or not hmac.compare_digest(
                    record.chat_export.export_id,
                    export_id,
                )
            ):
                _deny(
                    C9HandoffReason.CROSS_HANDOFF_REJECTED,
                    "C9 Chat export identifier does not bind the handoff",
                )
            if at >= self._chat_export_deadline(record):
                self._expire_chat_export(record, at=at)
            paths = self._manual_manager.claim_paths(
                export_id,
                claimed_at=at,
            )
            admission = record.approved
            descriptor = record.chat_export_descriptor
            if admission is None or descriptor is None:
                record.terminal_failure = True
                self._manual_manager.cleanup(
                    export_id,
                    cleaned_at=at,
                    reason=C9ManualCleanupReason.CANCELLED,
                )
                _deny(
                    C9HandoffReason.CHAT_EXPORT_NOT_CLAIMED,
                    "C9 Chat picker claim lost its exact admission binding",
                )
            grant = admission.live_cycle_bundle.grant
            claim = _commit_model(
                C9ChatPickerClaimReceipt,
                payload={
                    "version": "1",
                    "status": "native_chat_manual_attachment_paths_claimed",
                    "qualifies_as_native_chat_success": False,
                    "plugin_mcp_invocation_claimed": False,
                    "automated_attachment_claimed": False,
                    "handoff_id": record.staged.handoff_id,
                    "c9_cycle_id": grant.cycle_id,
                    "c9_grant_id": grant.grant_id,
                    "export_id": export_id,
                    "export_descriptor_sha256": descriptor.descriptor_sha256,
                    "chat_manifest_sha256": record.chat_manifest.manifest_sha256,
                    "attachment_count": 2,
                    "claimed_at": at,
                },
                digest_field="receipt_sha256",
                domain=b"systeme-local/c9/chat-picker-claim/v1\0",
            )
            assert isinstance(claim, C9ChatPickerClaimReceipt)
            record.chat_picker_claimed = True
            record.chat_picker_claim_receipt = claim
            return paths

    def native_chat_picker_claim_receipt(
        self,
        *,
        handoff_id: str,
    ) -> C9ChatPickerClaimReceipt:
        with self._lock:
            record = self._record_for(handoff_id)
            receipt = record.chat_picker_claim_receipt
            if not record.chat_picker_claimed or receipt is None:
                _deny(
                    C9HandoffReason.CHAT_EXPORT_NOT_CLAIMED,
                    "C9 native Chat picker claim receipt is unavailable",
                )
            return receipt

    def claim_chat_export_paths(
        self,
        *,
        handoff_id: str,
        export_id: str,
        claimed_at: datetime | None = None,
    ) -> tuple[Path, ...]:
        """Compatibility wrapper for the approved native-Chat handoff."""

        return self.claim_native_chat_handoff_paths(
            handoff_id=handoff_id,
            export_id=export_id,
            claimed_at=claimed_at,
        )

    def confirm_native_chat_handoff(
        self,
        *,
        handoff_id: str,
        chat_picker_claim_receipt_sha256: str,
        observed_image_nonce: str,
        observed_document_nonce: str,
        response_text: str,
        confirmed_at: datetime | None = None,
    ) -> C9ChatConfirmationReceipt:
        with self._lock:
            self._require_open()
            record = self._record_for(handoff_id)
            if record.chat_confirmation_attempted:
                _deny(
                    C9HandoffReason.CHAT_REPLAY_REJECTED,
                    "C9 native Chat proof was already attempted",
                )
            record.chat_confirmation_attempted = True
            at = _utc(confirmed_at) if confirmed_at is not None else self._now()
            export = record.chat_export
            export_descriptor = record.chat_export_descriptor
            picker_claim = record.chat_picker_claim_receipt
            admission = record.approved
            combined = record.combined_approval
            if (
                export is None
                or export_descriptor is None
                or picker_claim is None
                or admission is None
                or combined is None
                or not record.chat_picker_claimed
            ):
                _deny(
                    C9HandoffReason.CHAT_EXPORT_NOT_CLAIMED,
                    "C9 native Chat export has not been claimed",
                )
            if re.fullmatch(_SHA256_PATTERN, chat_picker_claim_receipt_sha256) is None:
                record.terminal_failure = True
                self._manual_manager.cleanup(
                    export.export_id,
                    cleaned_at=at,
                    reason=C9ManualCleanupReason.CANCELLED,
                )
                _deny(
                    C9HandoffReason.CHAT_EXPORT_NOT_CLAIMED,
                    "C9 native Chat picker claim receipt is invalid",
                )
            if not hmac.compare_digest(
                picker_claim.receipt_sha256,
                chat_picker_claim_receipt_sha256,
            ):
                record.terminal_failure = True
                self._manual_manager.cleanup(
                    export.export_id,
                    cleaned_at=at,
                    reason=C9ManualCleanupReason.CANCELLED,
                )
                _deny(
                    C9HandoffReason.CROSS_HANDOFF_REJECTED,
                    "C9 native Chat confirmation targets another picker claim",
                )
            if at >= self._chat_export_deadline(record):
                self._expire_chat_export(record, at=at)
            try:
                parsed_response = _parse_native_chat_manual_response(
                    response_text,
                    handoff_id=handoff_id,
                    observed_image_nonce=observed_image_nonce,
                    observed_document_nonce=observed_document_nonce,
                )
            except ValueError:
                self._manual_manager.cleanup(
                    export.export_id,
                    cleaned_at=at,
                    reason=C9ManualCleanupReason.CANCELLED,
                )
                _deny(
                    C9HandoffReason.RESPONSE_REJECTED,
                    "C9 native Chat response failed its exact proof schema",
                )
            valid_image = record.fixture.verify_observed_nonce(
                C9SyntheticFixtureKind.IMAGE,
                parsed_response["observed_image_nonce"],
            )
            valid_document = record.fixture.verify_observed_nonce(
                C9SyntheticFixtureKind.TEXT,
                parsed_response["observed_document_nonce"],
            )
            if not valid_image or not valid_document:
                self._manual_manager.cleanup(
                    export.export_id,
                    cleaned_at=at,
                    reason=C9ManualCleanupReason.CANCELLED,
                )
                _deny(
                    C9HandoffReason.NONCE_PROOF_REJECTED,
                    "C9 native Chat did not prove the exact synthetic package",
                )
            cleanup = self._manual_manager.cleanup(
                export.export_id,
                cleaned_at=at,
                reason=C9ManualCleanupReason.COMPLETED,
            )
            if (
                cleanup.reason is not C9ManualCleanupReason.COMPLETED
                or not cleanup.integrity_verified_before_delete
                or not cleanup.all_entries_removed
            ):
                record.terminal_failure = True
                _deny(
                    C9HandoffReason.CHAT_CLEANUP_REJECTED,
                    "C9 native Chat export cleanup was not complete and integral",
                )
            nonce_hashes = (
                sha256(parsed_response["observed_image_nonce"].encode("utf-8")).hexdigest(),
                sha256(parsed_response["observed_document_nonce"].encode("utf-8")).hexdigest(),
            )
            grant = admission.live_cycle_bundle.grant
            payload: dict[str, object] = {
                "version": "1",
                "status": "native_chat_attachments_visibly_consumed",
                "source": "operator_visible_native_chat_and_local_nonce_verification",
                "delivery_mode": "operator_performed_manual_attachment_handoff",
                "qualifies_as_native_chat_success": True,
                "plugin_mcp_invocation_claimed": False,
                "automated_attachment_claimed": False,
                "operator_file_picker_used": True,
                "new_synthetic_native_chat_conversation": True,
                "visible_response_observed": True,
                "conversation_identifier_collected": False,
                "handoff_id": record.staged.handoff_id,
                "c9_cycle_id": grant.cycle_id,
                "c9_grant_id": grant.grant_id,
                "combined_approval_sha256": (combined.combined_approval_sha256),
                "chat_manifest_sha256": (record.chat_manifest.manifest_sha256),
                "chat_export_id": export.export_id,
                "chat_export_descriptor_sha256": export_descriptor.descriptor_sha256,
                "chat_picker_claim_receipt_sha256": picker_claim.receipt_sha256,
                "verified_nonce_sha256s": nonce_hashes,
                "response_sha256": sha256(response_text.encode("utf-8")).hexdigest(),
                "manual_cleanup_receipt_sha256": cleanup.receipt_sha256,
                "confirmed_at": at,
            }
            receipt = _commit_model(
                C9ChatConfirmationReceipt,
                payload=payload,
                digest_field="receipt_sha256",
                domain=b"systeme-local/c9/chat-confirmation/v1\0",
            )
            assert isinstance(receipt, C9ChatConfirmationReceipt)
            record.chat_confirmation = receipt
            return receipt

    def confirm_manual_fallback(
        self,
        *,
        handoff_id: str,
        observed_image_nonce: str,
        observed_document_nonce: str,
        response_text: str,
        confirmed_at: datetime | None = None,
    ) -> C9ChatConfirmationReceipt:
        """Reject the obsolete fallback confirmation API."""

        del observed_image_nonce, observed_document_nonce, response_text, confirmed_at
        self._record_for(handoff_id)
        _deny(
            C9HandoffReason.UNSUPPORTED_SURFACE,
            "C9 manual fallback confirmation was replaced by native Chat handoff proof",
        )

    def confirm_chat(
        self,
        *,
        handoff_id: str,
        chat_picker_claim_receipt_sha256: str,
        observed_image_nonce: str,
        observed_document_nonce: str,
        response_text: str,
        confirmed_at: datetime | None = None,
    ) -> C9ChatConfirmationReceipt:
        """Compatibility wrapper for the approved native-Chat proof."""

        return self.confirm_native_chat_handoff(
            handoff_id=handoff_id,
            chat_picker_claim_receipt_sha256=chat_picker_claim_receipt_sha256,
            observed_image_nonce=observed_image_nonce,
            observed_document_nonce=observed_document_nonce,
            response_text=response_text,
            confirmed_at=confirmed_at,
        )

    def _cleanup_fixture_if_consumed(
        self,
        record: _HandoffRecord,
        at: datetime,
    ) -> None:
        if (
            not record.fixture_cleaned
            and C9RichSurface.WORK in record.rich_executions
            and record.chat_export is not None
        ):
            record.fixture.cleanup(cleaned_at=at)
            record.fixture_cleaned = True

    def close(
        self,
        *,
        closed_at: datetime | None = None,
    ) -> C9CoordinatorCloseReceipt:
        with self._lock:
            if self._close_receipt is not None:
                return self._close_receipt
            at = _utc(closed_at) if closed_at is not None else self._now()
            self._closed = True
            record = self._record
            pending_count = 0
            if record is not None:
                for pending in tuple(record.pending_rich.values()):
                    pending.zero()
                    pending_count += 1
                record.pending_rich.clear()
            attachment_cleanups = self._security.close(closed_at=at)
            manual_cleanups = self._manual_manager.close(closed_at=at)
            fixture_cleanup_sha256: str | None = None
            if record is not None:
                fixture_cleanup = record.fixture.cleanup(cleaned_at=at)
                fixture_cleanup_sha256 = fixture_cleanup.cleanup_sha256
                record.fixture_cleaned = True
            admission_removed = False
            try:
                admission_removed = self._private_state.unlink_regular(
                    self._admission_file,
                    missing_ok=True,
                )
            except C9PrivateStateError as exc:
                raise C9HandoffError(
                    C9HandoffReason.ATOMIC_COMMIT_FAILED,
                    "C9 admission metadata could not be removed",
                ) from exc
            payload: dict[str, object] = {
                "version": "1",
                "status": "closed",
                "handoff_id": record.staged.handoff_id if record else None,
                "pending_deliveries_zeroed": pending_count,
                "attachment_leases_cleaned": len(attachment_cleanups),
                "manual_exports_cleaned": len(manual_cleanups),
                "rich_call_count": (len(record.rich_executions) if record is not None else 0),
                "rich_confirmation_count": (
                    len(record.rich_confirmations) if record is not None else 0
                ),
                "native_chat_manual_handoff_used": bool(
                    record and record.chat_confirmation is not None
                ),
                "fixture_cleanup_sha256": fixture_cleanup_sha256,
                "admission_file_removed": admission_removed,
                "closed_at": at,
            }
            receipt = _commit_model(
                C9CoordinatorCloseReceipt,
                payload=payload,
                digest_field="receipt_sha256",
                domain=b"systeme-local/c9/coordinator-close/v1\0",
            )
            assert isinstance(receipt, C9CoordinatorCloseReceipt)
            self._close_receipt = receipt
            return receipt


class C9DynamicMcpRegistry:
    """Expose no tool before admission and one Work-only rich tool while live."""

    def __init__(self, coordinator: C9HandoffCoordinator) -> None:
        self._coordinator = coordinator
        self._tool = c9_attachment_handoff_tool()

    def list_tools(self) -> tuple[McpToolDefinition, ...]:
        return (self._tool,) if self._coordinator.tool_enabled() else ()

    def get_tool(self, name: str) -> McpToolDefinition | None:
        if name != C9_ATTACHMENT_HANDOFF_TOOL_NAME:
            return None
        tools = self.list_tools()
        return tools[0] if tools else None

    def protocol_tools(self) -> list[dict[str, Any]]:
        return [tool.protocol_dict() for tool in self.list_tools()]

    @property
    def tool_snapshot_sha256(self) -> str:
        return sha256(
            json.dumps(
                self.protocol_tools(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()


class C9HandoffCapabilityHandler:
    """Strict ``CapabilityExecutor`` adapter returning metadata only."""

    def __init__(self, coordinator: C9HandoffCoordinator) -> None:
        self._coordinator = coordinator

    def __call__(
        self,
        arguments: dict[str, Any],
        _config: dict[str, Any],
    ) -> dict[str, Any]:
        if (
            set(arguments) != {"handoff_id", "surface"}
            or not isinstance(arguments.get("handoff_id"), str)
            or not isinstance(arguments.get("surface"), str)
        ):
            _deny(
                C9HandoffReason.CROSS_HANDOFF_REJECTED,
                "C9 capability requires one opaque handoff id and one exact surface",
            )
        handoff_id = str(arguments["handoff_id"])
        if re.fullmatch(_HANDOFF_PATTERN, handoff_id) is None:
            _deny(
                C9HandoffReason.CROSS_HANDOFF_REJECTED,
                "C9 capability handoff id is invalid",
            )
        try:
            surface = C9RichSurface(str(arguments["surface"]))
        except ValueError:
            _deny(
                C9HandoffReason.SURFACE_BINDING_MISMATCH,
                "C9 capability surface is invalid",
            )
        return self._coordinator.execute_rich_handoff(
            handoff_id,
            surface=surface,
        ).model_dump(mode="json")


def _build_mcp_result(
    *,
    pending: _PendingRichDelivery,
    output: C9RichExecutionDescriptor,
    metadata: dict[str, str],
) -> mcp_types.CallToolResult:
    image_descriptor, image_content = next(
        item
        for item in pending.payloads
        if media_family(item[0].media_type) is AttachmentMediaFamily.IMAGE
    )
    document_descriptor, document_content = next(
        item for item in pending.payloads if item[0].media_type is AttachmentMediaType.TEXT
    )
    document_item = next(
        item
        for item in pending.expansion.items
        if item.attachment_id == document_descriptor.attachment_id
    )
    if document_item.embedded_resource_uri is None:
        raise ValueError("C9 document resource URI is missing")
    text = bytes(document_content).decode("utf-8", errors="strict")
    return mcp_types.CallToolResult(
        content=[
            mcp_types.TextContent(
                type="text",
                text="Approved C9 synthetic attachment handoff.",
            ),
            mcp_types.ImageContent(
                type="image",
                data=base64.b64encode(image_content).decode("ascii"),
                mimeType=image_descriptor.media_type.value,
            ),
            mcp_types.EmbeddedResource(
                type="resource",
                resource=mcp_types.TextResourceContents.model_validate(
                    {
                        "uri": document_item.embedded_resource_uri,
                        "mimeType": "text/plain",
                        "text": text,
                    }
                ),
            ),
        ],
        structuredContent=output.model_dump(mode="json"),
        isError=False,
        _meta=dict(metadata),
    )


@dataclass(repr=False)
class _C9PreparedRichRender:
    coordinator: C9HandoffCoordinator
    handoff_id: str
    surface: C9RichSurface
    delivery_token: str
    pending: _PendingRichDelivery
    result: mcp_types.CallToolResult
    _state: Literal["prepared", "committed", "aborted"] = "prepared"

    def commit(self) -> None:
        if self._state != "prepared":
            raise RuntimeError("C9 prepared rich render is no longer committable")
        try:
            self.coordinator._complete_rich_render(
                handoff_id=self.handoff_id,
                surface=self.surface,
                delivery_token=self.delivery_token,
            )
        except Exception:
            self.coordinator._fail_rich_render(
                handoff_id=self.handoff_id,
                surface=self.surface,
                delivery_token=self.delivery_token,
            )
            self.pending.zero()
            self._state = "aborted"
            raise
        self.pending.zero()
        self._state = "committed"

    def abort(self) -> None:
        if self._state == "aborted":
            return
        self.coordinator._fail_rich_render(
            handoff_id=self.handoff_id,
            surface=self.surface,
            delivery_token=self.delivery_token,
        )
        self.pending.zero()
        self._state = "aborted"


class C9HandoffRenderer:
    """Prepare one-use rich content without committing delivery prematurely."""

    def __init__(
        self,
        coordinator: C9HandoffCoordinator,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._coordinator = coordinator
        self._clock = clock or (lambda: datetime.now(UTC))

    def prepare(
        self,
        *,
        name: str,
        arguments: dict[str, Any],
        output: dict[str, Any],
        metadata: dict[str, str],
    ) -> _C9PreparedRichRender | None:
        if name != C9_ATTACHMENT_HANDOFF_TOOL_NAME:
            return None
        if (
            set(arguments) != {"handoff_id", "surface"}
            or not isinstance(arguments.get("handoff_id"), str)
            or not isinstance(arguments.get("surface"), str)
        ):
            _deny(
                C9HandoffReason.RENDER_BINDING_MISMATCH,
                "C9 renderer arguments are invalid",
            )
        committed = C9RichExecutionDescriptor.model_validate(output)
        handoff_id = str(arguments["handoff_id"])
        try:
            surface = C9RichSurface(str(arguments["surface"]))
        except ValueError:
            _deny(
                C9HandoffReason.SURFACE_BINDING_MISMATCH,
                "C9 renderer surface is invalid",
            )
        if surface is not C9RichSurface.WORK:
            _deny(
                C9HandoffReason.UNSUPPORTED_SURFACE,
                "C9 renderer accepts only ChatGPT Work output",
            )
        if (
            not hmac.compare_digest(committed.handoff_id, handoff_id)
            or committed.surface is not surface
        ):
            _deny(
                C9HandoffReason.RENDER_BINDING_MISMATCH,
                "C9 renderer output targets another handoff",
            )
        pending = self._coordinator._prepare_rich_render(
            handoff_id=handoff_id,
            surface=surface,
            delivery_token=committed.delivery_token,
            rendered_at=_utc(self._clock()),
        )
        try:
            if pending.public != committed:
                _deny(
                    C9HandoffReason.RENDER_BINDING_MISMATCH,
                    "C9 renderer output does not bind pending content",
                )
            result = _build_mcp_result(
                pending=pending,
                output=committed,
                metadata=metadata,
            )
            return _C9PreparedRichRender(
                coordinator=self._coordinator,
                handoff_id=handoff_id,
                surface=surface,
                delivery_token=committed.delivery_token,
                pending=pending,
                result=result,
            )
        except Exception:
            self._coordinator._fail_rich_render(
                handoff_id=handoff_id,
                surface=surface,
                delivery_token=committed.delivery_token,
            )
            raise
