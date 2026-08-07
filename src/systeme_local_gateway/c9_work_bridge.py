from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .c7_work_admission import canonical_sha256
from .c9_attachment_security import (
    C9AttachmentLease,
    C9BoundApproval,
    C9OutboundManifest,
    C9OutboundSurface,
)
from .providers.attachment_models import (
    AttachmentMediaFamily,
    AttachmentMediaType,
    media_family,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_GIT_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
_C9_CYCLE_PATTERN = r"^c9_cycle_[0-9a-f]{32}$"
_C9_GRANT_PATTERN = r"^c9_grant_[0-9a-f]{32}$"
_C9_WORK_TASK_PATTERN = r"^c9_work_[0-9a-f]{32}$"
_C9_CHAT_TASK_PATTERN = r"^c9_chat_[0-9a-f]{32}$"
_C9_RICH_TASK_PATTERN = r"^c9_(?:work|chat)_[0-9a-f]{32}$"
_C9_APPROVAL_PATTERN = r"^c9_approval_[0-9a-f]{32}$"
_C9_MANIFEST_PATTERN = r"^c9_manifest_[0-9a-f]{32}$"
_C9_ATTACHMENT_PATTERN = r"^c9_attachment_[0-9a-f]{32}$"
_C9_LEASE_PATTERN = r"^c9_lease_[0-9a-f]{64}$"
_C9_DESCRIPTOR_PATTERN = r"^c9_delivery_[0-9a-f]{32}$"
_MAX_CAPABILITY_OBSERVATION = timedelta(minutes=10)
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_NONCE_BYTES = 256

_SECRET_SHAPES = (
    re.compile(r"(?i)\bsk-[a-z0-9_-]{20,}"),
    re.compile(r"(?i)\btunnel_[0-9a-f]{32}\b"),
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/-]{20,}"),
    re.compile(r"(?i)\b(?:cookie|authorization)\s*[:=]\s*\S+"),
)


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C9 timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _require_utc(value).isoformat().replace("+00:00", "Z")


def _assert_window(start: datetime, end: datetime, maximum: timedelta) -> None:
    if end <= start:
        raise ValueError("C9 expiry must follow issuance")
    if end - start > maximum:
        raise ValueError("C9 evidence window exceeds its maximum")


def _assert_secret_free(value: Any) -> None:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if any(pattern.search(encoded) for pattern in _SECRET_SHAPES):
        raise ValueError("C9 metadata contains a credential-shaped value")


class C9StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class C9RichSurface(StrEnum):
    WORK = "work"
    CHAT = "chat"

    @property
    def outbound_surface(self) -> C9OutboundSurface:
        return (
            C9OutboundSurface.CHATGPT_WORK
            if self is C9RichSurface.WORK
            else C9OutboundSurface.CHATGPT_CHAT
        )

    @property
    def task_pattern(self) -> str:
        return _C9_WORK_TASK_PATTERN if self is C9RichSurface.WORK else _C9_CHAT_TASK_PATTERN


def _resolve_rich_task(
    *,
    surface: C9RichSurface,
    surface_task_id: str | None,
    work_task_id: str | None,
) -> str:
    if work_task_id is not None:
        if surface is not C9RichSurface.WORK:
            raise ValueError("legacy work_task_id cannot target Chat")
        if surface_task_id is not None and surface_task_id != work_task_id:
            raise ValueError("conflicting C9 surface task identifiers")
        surface_task_id = work_task_id
    if surface_task_id is None or re.fullmatch(surface.task_pattern, surface_task_id) is None:
        raise ValueError(f"invalid C9 {surface.value} task id")
    return surface_task_id


class C9WorkBridgeReason(StrEnum):
    READY = "READY"
    CAPABILITY_OBSERVATION_STALE = "MCP_CONTENT_CAPABILITY_OBSERVATION_STALE"
    CALL_TOOL_RESULT_CONTENT_UNPROVEN = "MCP_CALL_TOOL_RESULT_CONTENT_UNPROVEN"
    IMAGE_CONTENT_UNPROVEN = "MCP_IMAGE_CONTENT_UNPROVEN"
    EMBEDDED_TEXT_RESOURCE_UNPROVEN = "MCP_EMBEDDED_TEXT_RESOURCE_UNPROVEN"
    MANIFEST_SURFACE_MISMATCH = "OUTBOUND_MANIFEST_RICH_SURFACE_MISMATCH"
    MANIFEST_NOT_WORK = "OUTBOUND_MANIFEST_RICH_SURFACE_MISMATCH"
    UNSUPPORTED_ATTACHMENT_SET = "UNSUPPORTED_C9_ATTACHMENT_SET"
    MANIFEST_EXPIRED = "OUTBOUND_MANIFEST_EXPIRED"
    APPROVAL_EXPIRED = "OPERATOR_APPROVAL_EXPIRED"
    APPROVAL_FILE_SET_MISMATCH = "OPERATOR_APPROVED_FILE_SET_MISMATCH"
    LEASE_SET_MISMATCH = "APPROVED_LEASE_SET_MISMATCH"
    LEASE_EXPIRED = "APPROVED_LEASE_EXPIRED"
    DESCRIPTOR_BINDING_MISMATCH = "MCP_EXPANSION_DESCRIPTOR_BINDING_MISMATCH"
    CROSS_TASK_REJECTED = "CROSS_RICH_SURFACE_TASK_REJECTED"
    REPLAY_REJECTED = "RICH_SURFACE_TRANSFER_REPLAY_REJECTED"
    TRANSFER_NOT_STAGED = "RICH_SURFACE_TRANSFER_NOT_STAGED"
    RESPONSE_FILE_SET_MISMATCH = "RICH_SURFACE_RESPONSE_FILE_SET_MISMATCH"
    NONCE_PROOF_INVALID = "RICH_SURFACE_RESPONSE_NONCE_PROOF_INVALID"
    CHAT_MCP_UNSUPPORTED = "CHAT_MCP_SURFACE_NOT_OFFICIALLY_SUPPORTED"


class C9WorkBridgeError(ValueError):
    def __init__(self, reason: C9WorkBridgeReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _deny(reason: C9WorkBridgeReason, message: str) -> NoReturn:
    raise C9WorkBridgeError(reason, message)


class C9CapabilityEvidence(StrEnum):
    UNPROVEN = "unproven"
    DOCUMENTED_ONLY = "documented_only"
    DOCUMENTED_AND_LOCAL_SERVER_VALIDATED = "documented_and_local_server_validated"
    DOCUMENTED_AND_RUNTIME_OBSERVED = "documented_and_runtime_observed"


class C9McpContentType(StrEnum):
    IMAGE_CONTENT = "mcp_image_content"
    EMBEDDED_TEXT_RESOURCE = "mcp_embedded_text_resource"


class C9McpHostCapabilities(C9StrictModel):
    """Runtime evidence for the exact standard MCP content types C9 needs.

    ``window.openai`` file features are diagnostic only. C9 never fabricates a
    server-side ChatGPT file reference from those widget-only APIs.
    """

    version: Literal["1"] = "1"
    source: Literal["official_mcp_schema_local_server_and_surface_runtime_evidence"]
    surface: C9RichSurface
    call_tool_result_content: C9CapabilityEvidence
    image_content: C9CapabilityEvidence
    embedded_text_resource: C9CapabilityEvidence
    window_openai_upload_file_available: bool
    window_openai_image_ids_available: bool
    observed_at: datetime
    expires_at: datetime
    runtime_proof_receipt_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    capability_sha256: str = Field(pattern=_SHA256_PATTERN)

    _observed_utc = field_validator("observed_at")(_require_utc)
    _expires_utc = field_validator("expires_at")(_require_utc)

    @model_validator(mode="after")
    def validate_capability(self) -> C9McpHostCapabilities:
        if self.surface is not C9RichSurface.WORK:
            raise ValueError("C9 MCP host capability evidence is Work-only")
        _assert_window(self.observed_at, self.expires_at, _MAX_CAPABILITY_OBSERVATION)
        evidence = (
            self.call_tool_result_content,
            self.image_content,
            self.embedded_text_resource,
        )
        runtime_observed = tuple(
            item is C9CapabilityEvidence.DOCUMENTED_AND_RUNTIME_OBSERVED for item in evidence
        )
        if any(runtime_observed) and not all(runtime_observed):
            raise ValueError("C9 runtime content observation must cover every rich content type")
        if all(runtime_observed) != (self.runtime_proof_receipt_sha256 is not None):
            raise ValueError("C9 runtime content observation requires its live surface receipt")
        payload = self.model_dump(mode="json", exclude={"capability_sha256"})
        if self.capability_sha256 != canonical_sha256(payload):
            raise ValueError("C9 MCP capability observation digest mismatch")
        _assert_secret_free(payload)
        return self


def commit_mcp_host_capabilities(
    *,
    surface: C9RichSurface,
    call_tool_result_content: C9CapabilityEvidence,
    image_content: C9CapabilityEvidence,
    embedded_text_resource: C9CapabilityEvidence,
    window_openai_upload_file_available: bool,
    window_openai_image_ids_available: bool,
    observed_at: datetime,
    expires_at: datetime,
    runtime_proof_receipt_sha256: str | None = None,
) -> C9McpHostCapabilities:
    if C9RichSurface(surface) is not C9RichSurface.WORK:
        raise ValueError("C9 MCP host capability evidence is Work-only")
    payload: dict[str, Any] = {
        "version": "1",
        "source": "official_mcp_schema_local_server_and_surface_runtime_evidence",
        "surface": C9RichSurface(surface).value,
        "call_tool_result_content": call_tool_result_content.value,
        "image_content": image_content.value,
        "embedded_text_resource": embedded_text_resource.value,
        "window_openai_upload_file_available": window_openai_upload_file_available,
        "window_openai_image_ids_available": window_openai_image_ids_available,
        "observed_at": _timestamp(observed_at),
        "expires_at": _timestamp(expires_at),
        "runtime_proof_receipt_sha256": runtime_proof_receipt_sha256,
    }
    return C9McpHostCapabilities(
        **payload,
        capability_sha256=canonical_sha256(payload),
    )


def _revalidate_capabilities(
    capabilities: C9McpHostCapabilities,
) -> C9McpHostCapabilities:
    try:
        return C9McpHostCapabilities.model_validate(capabilities.model_dump(mode="python"))
    except (AttributeError, ValueError) as error:
        _deny(
            C9WorkBridgeReason.CALL_TOOL_RESULT_CONTENT_UNPROVEN,
            f"C9 MCP capability evidence is invalid: {error}",
        )


def _revalidate_manifest_and_approval(
    manifest: C9OutboundManifest,
    approval: C9BoundApproval,
) -> tuple[C9OutboundManifest, C9BoundApproval]:
    try:
        committed_manifest = C9OutboundManifest.model_validate(manifest.model_dump(mode="python"))
        committed_approval = C9BoundApproval.model_validate(approval.model_dump(mode="python"))
    except (AttributeError, ValueError) as error:
        _deny(
            C9WorkBridgeReason.APPROVAL_FILE_SET_MISMATCH,
            f"C9 authoritative manifest or approval is invalid: {error}",
        )
    return committed_manifest, committed_approval


def _approval_matches_manifest(
    manifest: C9OutboundManifest,
    approval: C9BoundApproval,
) -> bool:
    return (
        approval.manifest_id == manifest.manifest_id
        and approval.manifest_sha256 == manifest.manifest_sha256
        and approval.lease_ids == manifest.lease_ids
    )


def _supports_exact_rich_attachment_set(manifest: C9OutboundManifest) -> bool:
    if manifest.attachment_count != 2 or len(manifest.attachments) != 2:
        return False
    families = tuple(media_family(item.media_type) for item in manifest.attachments)
    if families.count(AttachmentMediaFamily.IMAGE) != 1:
        return False
    documents = tuple(
        item
        for item in manifest.attachments
        if media_family(item.media_type) is AttachmentMediaFamily.DOCUMENT
    )
    return len(documents) == 1 and documents[0].media_type is AttachmentMediaType.TEXT


class C9WorkBridgeDecision(C9StrictModel):
    version: Literal["1"] = "1"
    evaluated_at: datetime
    allowed: bool
    reason: C9WorkBridgeReason
    accepted_c8_commit: str = Field(pattern=_GIT_COMMIT_PATTERN)
    c9_cycle_id: str = Field(pattern=_C9_CYCLE_PATTERN)
    c9_grant_id: str = Field(pattern=_C9_GRANT_PATTERN)
    surface: C9RichSurface
    surface_task_id: str = Field(pattern=_C9_RICH_TASK_PATTERN)
    manifest_id: str = Field(pattern=_C9_MANIFEST_PATTERN)
    approval_id: str = Field(pattern=_C9_APPROVAL_PATTERN)
    widget_file_api_used: Literal[False]
    preflight_rich_probe_used: Literal[False]

    _evaluated_utc = field_validator("evaluated_at")(_require_utc)

    @model_validator(mode="after")
    def validate_surface_task(self) -> C9WorkBridgeDecision:
        if re.fullmatch(self.surface.task_pattern, self.surface_task_id) is None:
            raise ValueError("C9 bridge decision task id does not match its surface")
        return self

    @property
    def work_task_id(self) -> str:
        """Compatibility accessor for Work-only callers during C9 migration."""

        if self.surface is not C9RichSurface.WORK:
            raise AttributeError("Chat bridge decisions do not have a Work task id")
        return self.surface_task_id


def evaluate_work_bridge(
    *,
    capabilities: C9McpHostCapabilities,
    manifest: C9OutboundManifest,
    approval: C9BoundApproval,
    accepted_c8_commit: str,
    c9_cycle_id: str,
    c9_grant_id: str,
    evaluated_at: datetime,
    surface: C9RichSurface = C9RichSurface.WORK,
    surface_task_id: str | None = None,
    work_task_id: str | None = None,
) -> C9WorkBridgeDecision:
    committed_surface = C9RichSurface(surface)
    if committed_surface is not C9RichSurface.WORK:
        _deny(
            C9WorkBridgeReason.CHAT_MCP_UNSUPPORTED,
            "C9 official MCP rich-content delivery is available only in ChatGPT Work",
        )
    committed_task_id = _resolve_rich_task(
        surface=committed_surface,
        surface_task_id=surface_task_id,
        work_task_id=work_task_id,
    )
    committed_capabilities = _revalidate_capabilities(capabilities)
    committed_manifest, committed_approval = _revalidate_manifest_and_approval(
        manifest,
        approval,
    )
    at = _require_utc(evaluated_at)
    reason = C9WorkBridgeReason.READY
    if not (committed_capabilities.observed_at <= at < committed_capabilities.expires_at):
        reason = C9WorkBridgeReason.CAPABILITY_OBSERVATION_STALE
    elif committed_capabilities.surface is not committed_surface:
        reason = C9WorkBridgeReason.CALL_TOOL_RESULT_CONTENT_UNPROVEN
    elif committed_manifest.surface is not committed_surface.outbound_surface:
        reason = C9WorkBridgeReason.MANIFEST_SURFACE_MISMATCH
    elif not _approval_matches_manifest(committed_manifest, committed_approval):
        reason = C9WorkBridgeReason.APPROVAL_FILE_SET_MISMATCH
    elif not _supports_exact_rich_attachment_set(committed_manifest):
        reason = C9WorkBridgeReason.UNSUPPORTED_ATTACHMENT_SET
    elif not committed_manifest.created_at <= at < committed_manifest.expires_at:
        reason = C9WorkBridgeReason.MANIFEST_EXPIRED
    elif not committed_approval.approved_at <= at < committed_approval.expires_at:
        reason = C9WorkBridgeReason.APPROVAL_EXPIRED
    admissible = {
        C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED,
        C9CapabilityEvidence.DOCUMENTED_AND_RUNTIME_OBSERVED,
    }
    if reason is C9WorkBridgeReason.READY:
        if committed_capabilities.call_tool_result_content not in admissible:
            reason = C9WorkBridgeReason.CALL_TOOL_RESULT_CONTENT_UNPROVEN
        elif committed_capabilities.image_content not in admissible:
            reason = C9WorkBridgeReason.IMAGE_CONTENT_UNPROVEN
        elif committed_capabilities.embedded_text_resource not in admissible:
            reason = C9WorkBridgeReason.EMBEDDED_TEXT_RESOURCE_UNPROVEN
    return C9WorkBridgeDecision(
        evaluated_at=at,
        allowed=reason is C9WorkBridgeReason.READY,
        reason=reason,
        accepted_c8_commit=accepted_c8_commit,
        c9_cycle_id=c9_cycle_id,
        c9_grant_id=c9_grant_id,
        surface=committed_surface,
        surface_task_id=committed_task_id,
        manifest_id=committed_manifest.manifest_id,
        approval_id=committed_approval.approval_id,
        widget_file_api_used=False,
        preflight_rich_probe_used=False,
    )


class C9McpExpansionItem(C9StrictModel):
    attachment_id: str = Field(pattern=_C9_ATTACHMENT_PATTERN)
    ordinal: int = Field(ge=0, le=1)
    lease_id: str = Field(pattern=_C9_LEASE_PATTERN)
    lease_sha256: str = Field(pattern=_SHA256_PATTERN)
    descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)
    display_name: str = Field(min_length=1, max_length=240)
    media_type: AttachmentMediaType
    byte_size: int = Field(ge=1)
    content_sha256: str = Field(pattern=_SHA256_PATTERN)
    proof_nonce_sha256: str = Field(pattern=_SHA256_PATTERN)
    mcp_content_type: C9McpContentType
    embedded_resource_uri: str | None = Field(default=None, max_length=384)

    @model_validator(mode="after")
    def validate_expansion_item(self) -> C9McpExpansionItem:
        family = media_family(self.media_type)
        if family is AttachmentMediaFamily.IMAGE:
            if self.mcp_content_type is not C9McpContentType.IMAGE_CONTENT:
                raise ValueError("C9 image must expand to MCP ImageContent")
            if self.embedded_resource_uri is not None:
                raise ValueError("C9 ImageContent cannot carry a resource URI")
        else:
            if self.media_type is not AttachmentMediaType.TEXT:
                raise ValueError("C9 embedded resource must be UTF-8 text")
            if self.mcp_content_type is not C9McpContentType.EMBEDDED_TEXT_RESOURCE:
                raise ValueError("C9 document must expand to an MCP embedded text resource")
            expected_uri = f"systeme-local://c9/{self.lease_id}/{self.attachment_id}"
            if self.embedded_resource_uri != expected_uri:
                raise ValueError("C9 embedded resource URI is not bound to its lease")
        return self


class C9McpExpansionDescriptor(C9StrictModel):
    """Metadata-only instruction for post-audit expansion by McpTaskAdapter."""

    version: Literal["1"] = "1"
    descriptor_id: str = Field(pattern=_C9_DESCRIPTOR_PATTERN)
    accepted_c8_commit: str = Field(pattern=_GIT_COMMIT_PATTERN)
    c9_cycle_id: str = Field(pattern=_C9_CYCLE_PATTERN)
    c9_grant_id: str = Field(pattern=_C9_GRANT_PATTERN)
    surface: C9RichSurface
    surface_task_id: str = Field(pattern=_C9_RICH_TASK_PATTERN)
    capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    approval_id: str = Field(pattern=_C9_APPROVAL_PATTERN)
    approval_sha256: str = Field(pattern=_SHA256_PATTERN)
    manifest_id: str = Field(pattern=_C9_MANIFEST_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    items: tuple[C9McpExpansionItem, C9McpExpansionItem]
    widget_upload_file_used: Literal[False]
    widget_image_ids_used: Literal[False]
    preflight_rich_probe_used: Literal[False]
    manual_fallback_used: Literal[False]
    created_at: datetime
    expires_at: datetime
    descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)

    _created_utc = field_validator("created_at")(_require_utc)
    _expires_utc = field_validator("expires_at")(_require_utc)

    @model_validator(mode="after")
    def validate_descriptor(self) -> C9McpExpansionDescriptor:
        if self.surface is not C9RichSurface.WORK:
            raise ValueError("C9 MCP expansion descriptors are Work-only")
        if self.expires_at <= self.created_at:
            raise ValueError("C9 expansion descriptor must have a future expiry")
        if tuple(item.ordinal for item in self.items) != (0, 1):
            raise ValueError("C9 expansion items must retain manifest order")
        if len({item.attachment_id for item in self.items}) != 2:
            raise ValueError("C9 expansion attachment ids must be unique")
        if len({item.lease_id for item in self.items}) != 2:
            raise ValueError("C9 expansion lease ids must be unique")
        if {item.mcp_content_type for item in self.items} != {
            C9McpContentType.IMAGE_CONTENT,
            C9McpContentType.EMBEDDED_TEXT_RESOURCE,
        }:
            raise ValueError("C9 descriptor requires ImageContent and embedded text resource")
        if re.fullmatch(self.surface.task_pattern, self.surface_task_id) is None:
            raise ValueError("C9 expansion task id does not match its surface")
        payload = self.model_dump(mode="json", exclude={"descriptor_sha256"})
        if self.descriptor_sha256 != canonical_sha256(payload):
            raise ValueError("C9 expansion descriptor digest mismatch")
        _assert_secret_free(payload)
        return self


def _revalidate_exact_leases(
    *,
    leases: tuple[C9AttachmentLease, C9AttachmentLease],
    manifest: C9OutboundManifest,
    evaluated_at: datetime,
) -> tuple[C9AttachmentLease, C9AttachmentLease]:
    try:
        committed = tuple(
            C9AttachmentLease.model_validate(item.model_dump(mode="python")) for item in leases
        )
    except (AttributeError, ValueError) as error:
        _deny(C9WorkBridgeReason.LEASE_SET_MISMATCH, f"C9 lease is invalid: {error}")
    if len(committed) != 2:
        _deny(
            C9WorkBridgeReason.LEASE_SET_MISMATCH,
            "C9 bridge requires exactly two authoritative leases",
        )
    if tuple(item.lease_id for item in committed) != manifest.lease_ids:
        _deny(
            C9WorkBridgeReason.LEASE_SET_MISMATCH,
            "C9 lease order does not match the authoritative manifest",
        )
    if tuple(item.descriptor for item in committed) != manifest.attachments:
        _deny(
            C9WorkBridgeReason.LEASE_SET_MISMATCH,
            "C9 lease descriptors do not match the authoritative manifest",
        )
    at = _require_utc(evaluated_at)
    if any(not item.created_at <= at < item.expires_at for item in committed):
        _deny(C9WorkBridgeReason.LEASE_EXPIRED, "C9 approved lease is not active")
    return committed


def build_mcp_expansion_descriptor(
    *,
    descriptor_id: str,
    accepted_c8_commit: str,
    c9_cycle_id: str,
    c9_grant_id: str,
    capabilities: C9McpHostCapabilities,
    manifest: C9OutboundManifest,
    approval: C9BoundApproval,
    leases: tuple[C9AttachmentLease, C9AttachmentLease],
    proof_nonce_sha256s: Mapping[str, str],
    created_at: datetime,
    surface: C9RichSurface = C9RichSurface.WORK,
    surface_task_id: str | None = None,
    work_task_id: str | None = None,
) -> C9McpExpansionDescriptor:
    committed_surface = C9RichSurface(surface)
    committed_task_id = _resolve_rich_task(
        surface=committed_surface,
        surface_task_id=surface_task_id,
        work_task_id=work_task_id,
    )
    committed_capabilities = _revalidate_capabilities(capabilities)
    committed_manifest, committed_approval = _revalidate_manifest_and_approval(
        manifest,
        approval,
    )
    decision = evaluate_work_bridge(
        capabilities=committed_capabilities,
        manifest=committed_manifest,
        approval=committed_approval,
        accepted_c8_commit=accepted_c8_commit,
        c9_cycle_id=c9_cycle_id,
        c9_grant_id=c9_grant_id,
        evaluated_at=created_at,
        surface=committed_surface,
        surface_task_id=committed_task_id,
    )
    if not decision.allowed:
        _deny(decision.reason, f"C9 rich bridge denied: {decision.reason.value}")
    committed_leases = _revalidate_exact_leases(
        leases=leases,
        manifest=committed_manifest,
        evaluated_at=created_at,
    )
    expected_attachment_ids = tuple(item.attachment_id for item in committed_manifest.attachments)
    if set(proof_nonce_sha256s) != set(expected_attachment_ids):
        _deny(
            C9WorkBridgeReason.RESPONSE_FILE_SET_MISMATCH,
            "C9 nonce commitments must match the authoritative manifest exactly",
        )
    if any(re.fullmatch(_SHA256_PATTERN, value) is None for value in proof_nonce_sha256s.values()):
        _deny(
            C9WorkBridgeReason.NONCE_PROOF_INVALID,
            "C9 proof nonce commitments must be lowercase SHA-256 values",
        )

    items = tuple(
        C9McpExpansionItem(
            attachment_id=descriptor.attachment_id,
            ordinal=ordinal,
            lease_id=lease.lease_id,
            lease_sha256=lease.lease_sha256,
            descriptor_sha256=descriptor.descriptor_sha256,
            display_name=descriptor.display_name,
            media_type=descriptor.media_type,
            byte_size=descriptor.sanitized_inspection.byte_size,
            content_sha256=descriptor.sanitized_inspection.content_sha256,
            proof_nonce_sha256=proof_nonce_sha256s[descriptor.attachment_id],
            mcp_content_type=(
                C9McpContentType.IMAGE_CONTENT
                if media_family(descriptor.media_type) is AttachmentMediaFamily.IMAGE
                else C9McpContentType.EMBEDDED_TEXT_RESOURCE
            ),
            embedded_resource_uri=(
                None
                if media_family(descriptor.media_type) is AttachmentMediaFamily.IMAGE
                else f"systeme-local://c9/{lease.lease_id}/{descriptor.attachment_id}"
            ),
        )
        for ordinal, (lease, descriptor) in enumerate(
            zip(
                committed_leases,
                committed_manifest.attachments,
                strict=True,
            )
        )
    )
    expires_at = min(
        committed_capabilities.expires_at,
        committed_manifest.expires_at,
        committed_approval.expires_at,
        *(item.expires_at for item in committed_leases),
    )
    payload: dict[str, Any] = {
        "version": "1",
        "descriptor_id": descriptor_id,
        "accepted_c8_commit": accepted_c8_commit,
        "c9_cycle_id": c9_cycle_id,
        "c9_grant_id": c9_grant_id,
        "surface": committed_surface.value,
        "surface_task_id": committed_task_id,
        "capability_sha256": committed_capabilities.capability_sha256,
        "approval_id": committed_approval.approval_id,
        "approval_sha256": committed_approval.approval_sha256,
        "manifest_id": committed_manifest.manifest_id,
        "manifest_sha256": committed_manifest.manifest_sha256,
        "items": [item.model_dump(mode="json") for item in items],
        "widget_upload_file_used": False,
        "widget_image_ids_used": False,
        "preflight_rich_probe_used": False,
        "manual_fallback_used": False,
        "created_at": _timestamp(created_at),
        "expires_at": _timestamp(expires_at),
    }
    return C9McpExpansionDescriptor(
        **payload,
        descriptor_sha256=canonical_sha256(payload),
    )


class C9RichConsumptionReceipt(C9StrictModel):
    version: Literal["1"] = "1"
    status: Literal["work_attachments_visibly_consumed"]
    accepted_c8_commit: str = Field(pattern=_GIT_COMMIT_PATTERN)
    c9_cycle_id: str = Field(pattern=_C9_CYCLE_PATTERN)
    c9_grant_id: str = Field(pattern=_C9_GRANT_PATTERN)
    surface: C9RichSurface
    surface_task_id: str = Field(pattern=_C9_RICH_TASK_PATTERN)
    capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    approval_sha256: str = Field(pattern=_SHA256_PATTERN)
    descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    verified_attachment_ids: tuple[str, str]
    verified_nonce_sha256s: tuple[str, str]
    response_sha256: str = Field(pattern=_SHA256_PATTERN)
    observed_at: datetime
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    _observed_utc = field_validator("observed_at")(_require_utc)

    @model_validator(mode="after")
    def validate_receipt(self) -> C9RichConsumptionReceipt:
        if self.surface is not C9RichSurface.WORK:
            raise ValueError("C9 MCP rich-content receipts are Work-only")
        expected_status = f"{self.surface.value}_attachments_visibly_consumed"
        if self.status != expected_status:
            raise ValueError("C9 rich consumption status does not match its surface")
        if re.fullmatch(self.surface.task_pattern, self.surface_task_id) is None:
            raise ValueError("C9 rich consumption task id does not match its surface")
        payload = self.model_dump(mode="json", exclude={"receipt_sha256"})
        if self.receipt_sha256 != canonical_sha256(payload):
            raise ValueError("C9 rich consumption receipt digest mismatch")
        _assert_secret_free(payload)
        return self

    @property
    def work_task_id(self) -> str:
        """Compatibility accessor for the existing Work correlation verifier."""

        if self.surface is not C9RichSurface.WORK:
            raise AttributeError("Chat receipts do not have a Work task id")
        return self.surface_task_id


# Transitional import compatibility while attestation/seal migrate to the
# surface-neutral name. This is the same strict model, not a relaxed wrapper.
C9WorkConsumptionReceipt = C9RichConsumptionReceipt


def promote_mcp_host_capabilities_after_live_proof(
    *,
    capabilities: C9McpHostCapabilities,
    receipt: C9RichConsumptionReceipt,
    promoted_at: datetime,
    expires_at: datetime,
) -> C9McpHostCapabilities:
    """Promote one surface's local validation after that surface's live proof."""

    committed_capabilities = _revalidate_capabilities(capabilities)
    try:
        committed_receipt = C9RichConsumptionReceipt.model_validate(
            receipt.model_dump(mode="python")
        )
    except (AttributeError, ValueError) as error:
        _deny(
            C9WorkBridgeReason.DESCRIPTOR_BINDING_MISMATCH,
            f"C9 live surface receipt is invalid: {error}",
        )
    initial_evidence = (
        committed_capabilities.call_tool_result_content,
        committed_capabilities.image_content,
        committed_capabilities.embedded_text_resource,
    )
    if any(
        item is not C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED
        for item in initial_evidence
    ):
        _deny(
            C9WorkBridgeReason.REPLAY_REJECTED,
            "C9 capability promotion requires one unpromoted local-server admission",
        )
    if committed_receipt.capability_sha256 != committed_capabilities.capability_sha256:
        _deny(
            C9WorkBridgeReason.DESCRIPTOR_BINDING_MISMATCH,
            "C9 live proof does not bind the admitted MCP capability evidence",
        )
    if committed_receipt.surface is not committed_capabilities.surface:
        _deny(
            C9WorkBridgeReason.DESCRIPTOR_BINDING_MISMATCH,
            "C9 live proof belongs to another rich surface",
        )
    at = _require_utc(promoted_at)
    if at < committed_receipt.observed_at:
        raise ValueError("C9 capability promotion cannot predate its live proof")
    return commit_mcp_host_capabilities(
        surface=committed_capabilities.surface,
        call_tool_result_content=C9CapabilityEvidence.DOCUMENTED_AND_RUNTIME_OBSERVED,
        image_content=C9CapabilityEvidence.DOCUMENTED_AND_RUNTIME_OBSERVED,
        embedded_text_resource=C9CapabilityEvidence.DOCUMENTED_AND_RUNTIME_OBSERVED,
        window_openai_upload_file_available=(
            committed_capabilities.window_openai_upload_file_available
        ),
        window_openai_image_ids_available=(
            committed_capabilities.window_openai_image_ids_available
        ),
        observed_at=at,
        expires_at=expires_at,
        runtime_proof_receipt_sha256=committed_receipt.receipt_sha256,
    )


def _descriptor_matches_authoritative_inputs(
    *,
    descriptor: C9McpExpansionDescriptor,
    manifest: C9OutboundManifest,
    approval: C9BoundApproval,
    leases: tuple[C9AttachmentLease, C9AttachmentLease],
) -> bool:
    if not (
        descriptor.approval_id == approval.approval_id
        and descriptor.approval_sha256 == approval.approval_sha256
        and descriptor.manifest_id == manifest.manifest_id
        and descriptor.manifest_sha256 == manifest.manifest_sha256
    ):
        return False
    for item, lease, attachment in zip(
        descriptor.items,
        leases,
        manifest.attachments,
        strict=True,
    ):
        inspection = attachment.sanitized_inspection
        if not (
            item.attachment_id == attachment.attachment_id
            and item.lease_id == lease.lease_id
            and item.lease_sha256 == lease.lease_sha256
            and item.descriptor_sha256 == attachment.descriptor_sha256
            and item.display_name == attachment.display_name
            and item.media_type is attachment.media_type
            and item.byte_size == inspection.byte_size
            and item.content_sha256 == inspection.content_sha256
        ):
            return False
    return True


class C9RichTaskSession:
    """Process-local anti-replay guard for one authoritative rich transfer."""

    def __init__(
        self,
        *,
        surface: C9RichSurface,
        surface_task_id: str,
    ) -> None:
        self._surface = C9RichSurface(surface)
        if re.fullmatch(self._surface.task_pattern, surface_task_id) is None:
            raise ValueError(f"invalid C9 {self._surface.value} task id")
        self._surface_task_id = surface_task_id
        self._descriptor: C9McpExpansionDescriptor | None = None
        self._consumed = False

    def stage(
        self,
        *,
        descriptor: C9McpExpansionDescriptor,
        manifest: C9OutboundManifest,
        approval: C9BoundApproval,
        leases: tuple[C9AttachmentLease, C9AttachmentLease],
        staged_at: datetime,
    ) -> None:
        at = _require_utc(staged_at)
        try:
            committed_descriptor = C9McpExpansionDescriptor.model_validate(
                descriptor.model_dump(mode="python")
            )
        except (AttributeError, ValueError) as error:
            _deny(
                C9WorkBridgeReason.DESCRIPTOR_BINDING_MISMATCH,
                f"C9 descriptor is invalid: {error}",
            )
        if (
            committed_descriptor.surface is not self._surface
            or committed_descriptor.surface_task_id != self._surface_task_id
        ):
            _deny(C9WorkBridgeReason.CROSS_TASK_REJECTED, "C9 descriptor targets another task")
        if self._descriptor is not None:
            _deny(C9WorkBridgeReason.REPLAY_REJECTED, "C9 rich task already has a transfer")
        committed_manifest, committed_approval = _revalidate_manifest_and_approval(
            manifest,
            approval,
        )
        if committed_manifest.surface is not self._surface.outbound_surface:
            _deny(
                C9WorkBridgeReason.MANIFEST_SURFACE_MISMATCH,
                "C9 manifest does not target the declared rich surface",
            )
        if not _approval_matches_manifest(committed_manifest, committed_approval):
            _deny(
                C9WorkBridgeReason.APPROVAL_FILE_SET_MISMATCH,
                "C9 approval does not bind the authoritative manifest",
            )
        if not _supports_exact_rich_attachment_set(committed_manifest):
            _deny(
                C9WorkBridgeReason.UNSUPPORTED_ATTACHMENT_SET,
                "C9 rich proof requires exactly one image and one UTF-8 text document",
            )
        if not committed_manifest.created_at <= at < committed_manifest.expires_at:
            _deny(C9WorkBridgeReason.MANIFEST_EXPIRED, "C9 manifest is not active")
        if not committed_approval.approved_at <= at < committed_approval.expires_at:
            _deny(C9WorkBridgeReason.APPROVAL_EXPIRED, "C9 approval is not active")
        committed_leases = _revalidate_exact_leases(
            leases=leases,
            manifest=committed_manifest,
            evaluated_at=at,
        )
        if not committed_descriptor.created_at <= at < committed_descriptor.expires_at:
            _deny(C9WorkBridgeReason.APPROVAL_EXPIRED, "C9 descriptor is not active")
        if not _descriptor_matches_authoritative_inputs(
            descriptor=committed_descriptor,
            manifest=committed_manifest,
            approval=committed_approval,
            leases=committed_leases,
        ):
            _deny(
                C9WorkBridgeReason.DESCRIPTOR_BINDING_MISMATCH,
                "C9 descriptor does not match the authoritative manifest and leases",
            )
        self._descriptor = committed_descriptor

    def verify_and_consume(
        self,
        *,
        surface_task_id: str,
        descriptor_sha256: str,
        observed_nonces: Mapping[str, str],
        response_text: str,
        observed_at: datetime,
    ) -> C9RichConsumptionReceipt:
        at = _require_utc(observed_at)
        if surface_task_id != self._surface_task_id:
            _deny(C9WorkBridgeReason.CROSS_TASK_REJECTED, "C9 response belongs to another task")
        if self._descriptor is None:
            _deny(C9WorkBridgeReason.TRANSFER_NOT_STAGED, "C9 transfer has not been staged")
        if self._consumed:
            _deny(C9WorkBridgeReason.REPLAY_REJECTED, "C9 response proof was already consumed")
        descriptor = self._descriptor
        if not descriptor.created_at <= at < descriptor.expires_at:
            _deny(C9WorkBridgeReason.APPROVAL_EXPIRED, "C9 response proof is outside approval")
        if descriptor_sha256 != descriptor.descriptor_sha256:
            _deny(
                C9WorkBridgeReason.DESCRIPTOR_BINDING_MISMATCH,
                "C9 response references another descriptor",
            )
        expected_ids = tuple(item.attachment_id for item in descriptor.items)
        if set(observed_nonces) != set(expected_ids):
            _deny(
                C9WorkBridgeReason.RESPONSE_FILE_SET_MISMATCH,
                "C9 response must prove the exact approved attachment set",
            )
        if any(
            not nonce or len(nonce.encode("utf-8")) > _MAX_NONCE_BYTES
            for nonce in observed_nonces.values()
        ):
            _deny(C9WorkBridgeReason.NONCE_PROOF_INVALID, "C9 response nonce is unbounded")
        observed_hashes = tuple(
            hashlib.sha256(observed_nonces[attachment_id].encode("utf-8")).hexdigest()
            for attachment_id in expected_ids
        )
        expected_hashes = tuple(item.proof_nonce_sha256 for item in descriptor.items)
        if observed_hashes != expected_hashes:
            _deny(
                C9WorkBridgeReason.NONCE_PROOF_INVALID,
                "C9 rich response did not reproduce the attachment proof nonces",
            )
        if (
            not response_text
            or len(response_text.encode("utf-8")) > _MAX_RESPONSE_BYTES
            or any(nonce not in response_text for nonce in observed_nonces.values())
        ):
            _deny(
                C9WorkBridgeReason.NONCE_PROOF_INVALID,
                "C9 rich response text does not contain every reproduced proof nonce",
            )

        payload: dict[str, Any] = {
            "version": "1",
            "status": f"{self._surface.value}_attachments_visibly_consumed",
            "accepted_c8_commit": descriptor.accepted_c8_commit,
            "c9_cycle_id": descriptor.c9_cycle_id,
            "c9_grant_id": descriptor.c9_grant_id,
            "surface": self._surface.value,
            "surface_task_id": surface_task_id,
            "capability_sha256": descriptor.capability_sha256,
            "approval_sha256": descriptor.approval_sha256,
            "descriptor_sha256": descriptor.descriptor_sha256,
            "manifest_sha256": descriptor.manifest_sha256,
            "verified_attachment_ids": list(expected_ids),
            "verified_nonce_sha256s": list(observed_hashes),
            "response_sha256": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
            "observed_at": _timestamp(at),
        }
        receipt = C9RichConsumptionReceipt(
            **payload,
            receipt_sha256=canonical_sha256(payload),
        )
        self._consumed = True
        return receipt


class C9OneWorkTaskSession:
    """Compatibility wrapper for existing Work-only callers."""

    def __init__(self, *, work_task_id: str) -> None:
        self._session = C9RichTaskSession(
            surface=C9RichSurface.WORK,
            surface_task_id=work_task_id,
        )

    def stage(
        self,
        *,
        descriptor: C9McpExpansionDescriptor,
        manifest: C9OutboundManifest,
        approval: C9BoundApproval,
        leases: tuple[C9AttachmentLease, C9AttachmentLease],
        staged_at: datetime,
    ) -> None:
        self._session.stage(
            descriptor=descriptor,
            manifest=manifest,
            approval=approval,
            leases=leases,
            staged_at=staged_at,
        )

    def verify_and_consume(
        self,
        *,
        work_task_id: str,
        descriptor_sha256: str,
        observed_nonces: Mapping[str, str],
        response_text: str,
        observed_at: datetime,
    ) -> C9RichConsumptionReceipt:
        return self._session.verify_and_consume(
            surface_task_id=work_task_id,
            descriptor_sha256=descriptor_sha256,
            observed_nonces=observed_nonces,
            response_text=response_text,
            observed_at=observed_at,
        )


class C9ChatDeliveryClassification(C9StrictModel):
    version: Literal["1"] = "1"
    surface: Literal["native_chat"]
    delivery_mode: Literal["operator_performed_manual_attachment_handoff"]
    custom_mcp_app_invoked: Literal[False]
    manual_attachment_handoff_allowed: Literal[True]
    primary_c9_success_eligible: Literal[True]
    reason: Literal["OFFICIAL_NATIVE_CHAT_MANUAL_ATTACHMENT_HANDOFF"]


def classify_chat_delivery() -> C9ChatDeliveryClassification:
    """Classify the only supported C9 delivery path for normal ChatGPT Chat."""

    return C9ChatDeliveryClassification(
        surface="native_chat",
        delivery_mode="operator_performed_manual_attachment_handoff",
        custom_mcp_app_invoked=False,
        manual_attachment_handoff_allowed=True,
        primary_c9_success_eligible=True,
        reason="OFFICIAL_NATIVE_CHAT_MANUAL_ATTACHMENT_HANDOFF",
    )


def classify_native_chat_delivery() -> C9ChatDeliveryClassification:
    """Compatibility name for the bounded native-Chat manual handoff."""

    return classify_chat_delivery()
