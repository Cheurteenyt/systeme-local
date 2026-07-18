from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
from typing import Literal
from unicodedata import category, normalize

from pydantic import Field, field_validator, model_validator

from .context_models import ProviderQuotaSnapshot
from .models import (
    AgentPrincipalRef,
    CapabilityClaim,
    CapabilitySupport,
    StrictModel,
)

_ID_PATTERN = r"^[a-z][a-z0-9_]{2,127}$"
_PROVIDER_PATTERN = r"^[a-z][a-z0-9_.-]{1,63}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_IDEMPOTENCY_PATTERN = r"^[a-z][a-z0-9_]{2,127}$"

MAX_INSPECTION_BYTES = 64 * 1024 * 1024
MAX_ATTACHMENTS_PER_MANIFEST = 64
MAX_DISPLAY_NAME_UTF8_BYTES = 240


def normalize_utc_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def _require_aware(value: datetime) -> datetime:
    return normalize_utc_timestamp(value)


def _frame_text(digest: object, value: str) -> None:
    encoded = value.encode("utf-8")
    digest.update(len(encoded).to_bytes(8, byteorder="big", signed=False))
    digest.update(encoded)


def _frame_int(digest: object, value: int) -> None:
    if value < 0:
        raise ValueError("framed integers must be non-negative")
    digest.update(value.to_bytes(8, byteorder="big", signed=False))


class AttachmentMediaType(StrEnum):
    PNG = "image/png"
    JPEG = "image/jpeg"
    PDF = "application/pdf"
    TEXT = "text/plain"
    JSON = "application/json"


class AttachmentMediaFamily(StrEnum):
    IMAGE = "image"
    DOCUMENT = "document"


def media_family(media_type: AttachmentMediaType) -> AttachmentMediaFamily:
    if media_type in (AttachmentMediaType.PNG, AttachmentMediaType.JPEG):
        return AttachmentMediaFamily.IMAGE
    return AttachmentMediaFamily.DOCUMENT


class AttachmentRole(StrEnum):
    SCREENSHOT = "screenshot"
    INPUT_DOCUMENT = "input_document"
    REFERENCE = "reference"
    DATA = "data"
    OTHER = "other"


class AttachmentSource(StrEnum):
    OPERATOR_SELECTED = "operator_selected"
    AGENT_GENERATED = "agent_generated"
    TOOL_OUTPUT = "tool_output"
    SIMULATED = "simulated"


class AttachmentQuotaRequirement(StrEnum):
    NONE = "none"
    FRESH_UPLOAD_QUOTA = "fresh_upload_quota"


class AttachmentTransferStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    REJECTED = "rejected"
    AMBIGUOUS = "ambiguous"


class AttachmentRetryDirective(StrEnum):
    DO_NOT_RETRY = "do_not_retry"
    SAFE_RETRY = "safe_retry"
    RECONCILE_REQUIRED = "reconcile_required"


class AttachmentInspection(StrictModel):
    version: Literal["1"] = "1"
    media_type: AttachmentMediaType
    content_sha256: str = Field(pattern=_SHA256_PATTERN)
    byte_size: int = Field(ge=1, le=MAX_INSPECTION_BYTES)
    image_width: int | None = Field(default=None, ge=1, le=1_000_000)
    image_height: int | None = Field(default=None, ge=1, le=1_000_000)
    inspected_at: datetime

    _aware_inspected_at = field_validator("inspected_at")(_require_aware)

    @model_validator(mode="after")
    def validate_dimensions(self) -> "AttachmentInspection":
        family = media_family(self.media_type)
        if family is AttachmentMediaFamily.IMAGE:
            if self.image_width is None or self.image_height is None:
                raise ValueError("image attachments require width and height")
        elif self.image_width is not None or self.image_height is not None:
            raise ValueError("non-image attachments cannot carry dimensions")
        return self


class CommittedAttachment(StrictModel):
    version: Literal["1"] = "1"
    attachment_id: str = Field(pattern=_ID_PATTERN)
    conversation_id: str = Field(pattern=_ID_PATTERN)
    turn_id: str = Field(pattern=_ID_PATTERN)
    trace_id: str = Field(pattern=_ID_PATTERN)
    ordinal: int = Field(ge=0, lt=MAX_ATTACHMENTS_PER_MANIFEST)
    display_name: str = Field(min_length=1, max_length=240)
    role: AttachmentRole
    source: AttachmentSource
    inspection: AttachmentInspection
    committed_at: datetime
    metadata_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_committed_at = field_validator("committed_at")(_require_aware)

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        return validate_attachment_display_name(value)

    @model_validator(mode="after")
    def validate_commitment(self) -> "CommittedAttachment":
        if self.committed_at < self.inspection.inspected_at:
            raise ValueError("committed_at must not precede inspected_at")
        expected = attachment_metadata_sha256(
            attachment_id=self.attachment_id,
            conversation_id=self.conversation_id,
            turn_id=self.turn_id,
            trace_id=self.trace_id,
            ordinal=self.ordinal,
            display_name=self.display_name,
            role=self.role,
            source=self.source,
            inspection=self.inspection,
            committed_at=self.committed_at,
        )
        if self.metadata_sha256 != expected:
            raise ValueError("attachment metadata digest mismatch")
        return self


class AttachmentManifest(StrictModel):
    version: Literal["1"] = "1"
    manifest_id: str = Field(pattern=_ID_PATTERN)
    conversation_id: str = Field(pattern=_ID_PATTERN)
    turn_id: str = Field(pattern=_ID_PATTERN)
    trace_id: str = Field(pattern=_ID_PATTERN)
    principal: AgentPrincipalRef
    turn_content_sha256: str = Field(pattern=_SHA256_PATTERN)
    attachment_count: int = Field(ge=1, le=MAX_ATTACHMENTS_PER_MANIFEST)
    total_bytes: int = Field(ge=1, le=MAX_ATTACHMENTS_PER_MANIFEST * MAX_INSPECTION_BYTES)
    attachments: tuple[CommittedAttachment, ...] = Field(
        min_length=1,
        max_length=MAX_ATTACHMENTS_PER_MANIFEST,
    )
    committed_at: datetime
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_committed_at = field_validator("committed_at")(_require_aware)

    @model_validator(mode="after")
    def validate_manifest(self) -> "AttachmentManifest":
        if self.attachment_count != len(self.attachments):
            raise ValueError("attachment_count does not match attachments")
        if self.total_bytes != sum(item.inspection.byte_size for item in self.attachments):
            raise ValueError("total_bytes does not match attachments")
        if [item.ordinal for item in self.attachments] != list(range(len(self.attachments))):
            raise ValueError("attachment ordinals must be contiguous from zero")
        if len({item.attachment_id for item in self.attachments}) != len(self.attachments):
            raise ValueError("duplicate attachment_id in manifest")
        if len({item.inspection.content_sha256 for item in self.attachments}) != len(
            self.attachments
        ):
            raise ValueError("duplicate attachment content in manifest")
        for item in self.attachments:
            if item.conversation_id != self.conversation_id:
                raise ValueError("attachment conversation binding mismatch")
            if item.turn_id != self.turn_id:
                raise ValueError("attachment turn binding mismatch")
            if item.trace_id != self.trace_id:
                raise ValueError("attachment trace binding mismatch")
            if item.committed_at > self.committed_at:
                raise ValueError("manifest cannot precede an attachment commit")
        expected = attachment_manifest_sha256(
            manifest_id=self.manifest_id,
            conversation_id=self.conversation_id,
            turn_id=self.turn_id,
            trace_id=self.trace_id,
            principal=self.principal,
            turn_content_sha256=self.turn_content_sha256,
            attachments=self.attachments,
            committed_at=self.committed_at,
        )
        if self.manifest_sha256 != expected:
            raise ValueError("attachment manifest digest mismatch")
        return self


class AttachmentCapabilityProfile(StrictModel):
    version: Literal["1"] = "1"
    profile_id: str = Field(pattern=_ID_PATTERN)
    revision: int = Field(ge=1)
    provider: str = Field(pattern=_PROVIDER_PATTERN)
    surface: str = Field(pattern=_PROVIDER_PATTERN)
    support: CapabilityClaim
    supported_media_types: tuple[AttachmentMediaType, ...] = Field(max_length=16)
    max_file_bytes: int = Field(ge=0, le=MAX_INSPECTION_BYTES)
    max_batch_bytes: int = Field(ge=0, le=MAX_ATTACHMENTS_PER_MANIFEST * MAX_INSPECTION_BYTES)
    max_manifest_bytes: int = Field(
        ge=0,
        le=MAX_ATTACHMENTS_PER_MANIFEST * MAX_INSPECTION_BYTES,
    )
    max_files_per_batch: int = Field(ge=0, le=MAX_ATTACHMENTS_PER_MANIFEST)
    max_files_per_manifest: int = Field(ge=0, le=MAX_ATTACHMENTS_PER_MANIFEST)
    max_batches_per_manifest: int = Field(ge=0, le=MAX_ATTACHMENTS_PER_MANIFEST)
    max_image_width: int = Field(ge=0, le=1_000_000)
    max_image_height: int = Field(ge=0, le=1_000_000)
    max_image_pixels: int = Field(ge=0, le=1_000_000_000_000)
    allows_mixed_media: bool
    quota_requirement: AttachmentQuotaRequirement
    observed_at: datetime
    profile_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_observed_at = field_validator("observed_at")(_require_aware)

    @model_validator(mode="after")
    def validate_profile(self) -> "AttachmentCapabilityProfile":
        unique_media = set(self.supported_media_types)
        if len(unique_media) != len(self.supported_media_types):
            raise ValueError("supported_media_types must be unique")
        if self.support.state is CapabilitySupport.SUPPORTED:
            positive = (
                self.max_file_bytes,
                self.max_batch_bytes,
                self.max_manifest_bytes,
                self.max_files_per_batch,
                self.max_files_per_manifest,
                self.max_batches_per_manifest,
            )
            if any(value <= 0 for value in positive):
                raise ValueError("supported attachment profiles require positive limits")
            if not self.supported_media_types:
                raise ValueError("supported attachment profiles require media types")
            if self.max_file_bytes > self.max_batch_bytes:
                raise ValueError("max_file_bytes cannot exceed max_batch_bytes")
            if self.max_batch_bytes > self.max_manifest_bytes:
                raise ValueError("max_batch_bytes cannot exceed max_manifest_bytes")
            if self.max_files_per_batch > self.max_files_per_manifest:
                raise ValueError("batch file limit cannot exceed manifest file limit")
            supports_images = any(
                media_family(item) is AttachmentMediaFamily.IMAGE
                for item in self.supported_media_types
            )
            if supports_images:
                if (
                    self.max_image_width <= 0
                    or self.max_image_height <= 0
                    or self.max_image_pixels <= 0
                ):
                    raise ValueError("image support requires positive dimension limits")
            elif (
                self.max_image_width
                or self.max_image_height
                or self.max_image_pixels
            ):
                raise ValueError("profiles without image media must use zero image limits")
        else:
            if (
                self.supported_media_types
                or self.max_file_bytes
                or self.max_batch_bytes
                or self.max_manifest_bytes
                or self.max_files_per_batch
                or self.max_files_per_manifest
                or self.max_batches_per_manifest
                or self.max_image_width
                or self.max_image_height
                or self.max_image_pixels
                or self.allows_mixed_media
                or self.quota_requirement is not AttachmentQuotaRequirement.NONE
            ):
                raise ValueError("non-supported profiles must not advertise limits")
        expected = attachment_capability_profile_sha256(
            profile_id=self.profile_id,
            revision=self.revision,
            provider=self.provider,
            surface=self.surface,
            support=self.support,
            supported_media_types=self.supported_media_types,
            max_file_bytes=self.max_file_bytes,
            max_batch_bytes=self.max_batch_bytes,
            max_manifest_bytes=self.max_manifest_bytes,
            max_files_per_batch=self.max_files_per_batch,
            max_files_per_manifest=self.max_files_per_manifest,
            max_batches_per_manifest=self.max_batches_per_manifest,
            max_image_width=self.max_image_width,
            max_image_height=self.max_image_height,
            max_image_pixels=self.max_image_pixels,
            allows_mixed_media=self.allows_mixed_media,
            quota_requirement=self.quota_requirement,
            observed_at=self.observed_at,
        )
        if self.profile_sha256 != expected:
            raise ValueError("attachment capability profile digest mismatch")
        return self


class AttachmentBatch(StrictModel):
    version: Literal["1"] = "1"
    batch_id: str = Field(pattern=_ID_PATTERN)
    batch_index: int = Field(ge=0, lt=MAX_ATTACHMENTS_PER_MANIFEST)
    attachment_ids: tuple[str, ...] = Field(
        min_length=1,
        max_length=MAX_ATTACHMENTS_PER_MANIFEST,
    )
    total_bytes: int = Field(ge=1)
    media_families: tuple[AttachmentMediaFamily, ...] = Field(min_length=1, max_length=2)

    @model_validator(mode="after")
    def validate_batch(self) -> "AttachmentBatch":
        if len(set(self.attachment_ids)) != len(self.attachment_ids):
            raise ValueError("duplicate attachment_id in batch")
        if len(set(self.media_families)) != len(self.media_families):
            raise ValueError("duplicate media family in batch")
        return self


class AttachmentBatchPlan(StrictModel):
    version: Literal["1"] = "1"
    plan_id: str = Field(pattern=_ID_PATTERN)
    account_id: str = Field(pattern=_ID_PATTERN)
    manifest_id: str = Field(pattern=_ID_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider: str = Field(pattern=_PROVIDER_PATTERN)
    surface: str = Field(pattern=_PROVIDER_PATTERN)
    capability_profile_id: str = Field(pattern=_ID_PATTERN)
    capability_profile_revision: int = Field(ge=1)
    capability_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    upload_quota_snapshot_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    upload_quota_observed_at: datetime | None = None
    upload_quota_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    ordered_attachment_ids: tuple[str, ...] = Field(
        min_length=1,
        max_length=MAX_ATTACHMENTS_PER_MANIFEST,
    )
    attachment_count: int = Field(ge=1, le=MAX_ATTACHMENTS_PER_MANIFEST)
    total_bytes: int = Field(ge=1)
    batches: tuple[AttachmentBatch, ...] = Field(
        min_length=1,
        max_length=MAX_ATTACHMENTS_PER_MANIFEST,
    )
    planned_at: datetime
    plan_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_planned_at = field_validator("planned_at")(_require_aware)
    _aware_upload_quota_observed_at = field_validator("upload_quota_observed_at")(
        lambda value: None if value is None else _require_aware(value)
    )

    @model_validator(mode="after")
    def validate_plan(self) -> "AttachmentBatchPlan":
        quota_fields = (
            self.upload_quota_snapshot_id,
            self.upload_quota_observed_at,
            self.upload_quota_sha256,
        )
        if any(value is None for value in quota_fields) and any(
            value is not None for value in quota_fields
        ):
            raise ValueError("upload quota id, observation time and digest must appear together")
        if self.attachment_count != len(self.ordered_attachment_ids):
            raise ValueError("attachment_count does not match ordered_attachment_ids")
        if len(set(self.ordered_attachment_ids)) != len(self.ordered_attachment_ids):
            raise ValueError("ordered_attachment_ids must be unique")
        if [batch.batch_index for batch in self.batches] != list(range(len(self.batches))):
            raise ValueError("batch indices must be contiguous from zero")
        flattened = tuple(
            attachment_id
            for batch in self.batches
            for attachment_id in batch.attachment_ids
        )
        if flattened != self.ordered_attachment_ids:
            raise ValueError("batches must preserve the full attachment order")
        if self.total_bytes != sum(batch.total_bytes for batch in self.batches):
            raise ValueError("plan total_bytes does not match batches")
        expected = attachment_plan_sha256(
            plan_id=self.plan_id,
            account_id=self.account_id,
            manifest_id=self.manifest_id,
            manifest_sha256=self.manifest_sha256,
            provider=self.provider,
            surface=self.surface,
            capability_profile_id=self.capability_profile_id,
            capability_profile_revision=self.capability_profile_revision,
            capability_profile_sha256=self.capability_profile_sha256,
            upload_quota_snapshot_id=self.upload_quota_snapshot_id,
            upload_quota_observed_at=self.upload_quota_observed_at,
            upload_quota_sha256=self.upload_quota_sha256,
            ordered_attachment_ids=self.ordered_attachment_ids,
            batches=self.batches,
            planned_at=self.planned_at,
        )
        if self.plan_sha256 != expected:
            raise ValueError("attachment plan digest mismatch")
        return self


class AttachmentBatchReceipt(StrictModel):
    version: Literal["1"] = "1"
    receipt_id: str = Field(pattern=_ID_PATTERN)
    plan_id: str = Field(pattern=_ID_PATTERN)
    batch_id: str = Field(pattern=_ID_PATTERN)
    batch_index: int = Field(ge=0, lt=MAX_ATTACHMENTS_PER_MANIFEST)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY_PATTERN)
    status: AttachmentTransferStatus
    accepted_attachment_ids: tuple[str, ...] = Field(max_length=MAX_ATTACHMENTS_PER_MANIFEST)
    provider_upload_ids: tuple[str, ...] = Field(max_length=MAX_ATTACHMENTS_PER_MANIFEST)
    acceptance_known: bool
    retry_directive: AttachmentRetryDirective
    error_code: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    observed_at: datetime
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_observed_at = field_validator("observed_at")(_require_aware)

    @model_validator(mode="after")
    def validate_receipt(self) -> "AttachmentBatchReceipt":
        if len(self.accepted_attachment_ids) != len(self.provider_upload_ids):
            raise ValueError("accepted attachments require matching provider upload ids")
        if len(set(self.accepted_attachment_ids)) != len(self.accepted_attachment_ids):
            raise ValueError("accepted attachment ids must be unique")
        if len(set(self.provider_upload_ids)) != len(self.provider_upload_ids):
            raise ValueError("provider upload ids must be unique")
        if self.status is AttachmentTransferStatus.COMPLETED:
            if not self.acceptance_known or self.error_code is not None:
                raise ValueError("completed receipts require known acceptance and no error")
            if self.retry_directive is not AttachmentRetryDirective.DO_NOT_RETRY:
                raise ValueError("completed receipts cannot request retry")
        elif self.status is AttachmentTransferStatus.AMBIGUOUS:
            if self.acceptance_known or self.accepted_attachment_ids:
                raise ValueError("ambiguous receipts cannot assert accepted attachments")
            if self.retry_directive is not AttachmentRetryDirective.RECONCILE_REQUIRED:
                raise ValueError("ambiguous receipts require reconciliation")
            if self.error_code is None:
                raise ValueError("ambiguous receipts require an error code")
        elif self.status is AttachmentTransferStatus.PARTIAL:
            if not self.acceptance_known or not self.accepted_attachment_ids:
                raise ValueError("partial receipts require known non-empty acceptance")
            if self.retry_directive is not AttachmentRetryDirective.DO_NOT_RETRY:
                raise ValueError("partial receipts cannot authorize blind retry")
            if self.error_code is None:
                raise ValueError("partial receipts require an error code")
        elif self.status is AttachmentTransferStatus.CANCELLED:
            if not self.acceptance_known or self.accepted_attachment_ids:
                raise ValueError("cancelled receipts require known zero acceptance")
            if self.retry_directive is not AttachmentRetryDirective.SAFE_RETRY:
                raise ValueError("cancelled receipts require safe_retry")
            if self.error_code is None:
                raise ValueError("cancelled receipts require an error code")
        elif self.status is AttachmentTransferStatus.REJECTED:
            if not self.acceptance_known or self.accepted_attachment_ids:
                raise ValueError("rejected receipts require known zero acceptance")
            if self.retry_directive is not AttachmentRetryDirective.DO_NOT_RETRY:
                raise ValueError("rejected receipts cannot authorize retry")
            if self.error_code is None:
                raise ValueError("rejected receipts require an error code")
        expected = attachment_receipt_sha256(
            receipt_id=self.receipt_id,
            plan_id=self.plan_id,
            batch_id=self.batch_id,
            batch_index=self.batch_index,
            idempotency_key=self.idempotency_key,
            status=self.status,
            accepted_attachment_ids=self.accepted_attachment_ids,
            provider_upload_ids=self.provider_upload_ids,
            acceptance_known=self.acceptance_known,
            retry_directive=self.retry_directive,
            error_code=self.error_code,
            observed_at=self.observed_at,
        )
        if self.receipt_sha256 != expected:
            raise ValueError("attachment receipt digest mismatch")
        return self


def validate_attachment_display_name(value: str) -> str:
    if value != normalize("NFC", value):
        raise ValueError("attachment display names must be NFC-normalized")
    if value in {".", ".."}:
        raise ValueError("attachment display names cannot be dot segments")
    if value.endswith((" ", ".")):
        raise ValueError("attachment display names cannot end in space or dot")
    if any(character in value for character in '/\\:*?"<>|'):
        raise ValueError("attachment display names cannot contain filesystem metacharacters")
    if any(category(character).startswith("C") for character in value):
        raise ValueError("attachment display names cannot contain control or format characters")
    if len(value.encode("utf-8")) > MAX_DISPLAY_NAME_UTF8_BYTES:
        raise ValueError("attachment display name exceeds UTF-8 byte limit")
    stem = value.split(".", 1)[0].rstrip(" .").casefold()
    reserved = {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
    if stem in reserved:
        raise ValueError("attachment display name uses a reserved Windows device name")
    return value


def attachment_metadata_sha256(
    *,
    attachment_id: str,
    conversation_id: str,
    turn_id: str,
    trace_id: str,
    ordinal: int,
    display_name: str,
    role: AttachmentRole,
    source: AttachmentSource,
    inspection: AttachmentInspection,
    committed_at: datetime,
) -> str:
    committed_at = normalize_utc_timestamp(committed_at)
    inspected_at = normalize_utc_timestamp(inspection.inspected_at)
    digest = sha256(b"systeme-local:committed-attachment:v1\x00")
    for value in (
        attachment_id,
        conversation_id,
        turn_id,
        trace_id,
        display_name,
        role.value,
        source.value,
        inspection.media_type.value,
        inspection.content_sha256,
        inspected_at.isoformat(),
        committed_at.isoformat(),
    ):
        _frame_text(digest, value)
    for value in (
        ordinal,
        inspection.byte_size,
        inspection.image_width or 0,
        inspection.image_height or 0,
    ):
        _frame_int(digest, value)
    return digest.hexdigest()


def attachment_manifest_sha256(
    *,
    manifest_id: str,
    conversation_id: str,
    turn_id: str,
    trace_id: str,
    principal: AgentPrincipalRef,
    turn_content_sha256: str,
    attachments: tuple[CommittedAttachment, ...],
    committed_at: datetime,
) -> str:
    committed_at = normalize_utc_timestamp(committed_at)
    digest = sha256(b"systeme-local:attachment-manifest:v1\x00")
    for value in (
        manifest_id,
        conversation_id,
        turn_id,
        trace_id,
        principal.agent_id,
        principal.instance_id,
        principal.key_id,
        principal.verification_id,
        turn_content_sha256,
        committed_at.isoformat(),
    ):
        _frame_text(digest, value)
    _frame_int(digest, len(attachments))
    for item in attachments:
        _frame_text(digest, item.metadata_sha256)
    return digest.hexdigest()



def attachment_capability_profile_sha256(
    *,
    profile_id: str,
    revision: int,
    provider: str,
    surface: str,
    support: CapabilityClaim,
    supported_media_types: tuple[AttachmentMediaType, ...],
    max_file_bytes: int,
    max_batch_bytes: int,
    max_manifest_bytes: int,
    max_files_per_batch: int,
    max_files_per_manifest: int,
    max_batches_per_manifest: int,
    max_image_width: int,
    max_image_height: int,
    max_image_pixels: int,
    allows_mixed_media: bool,
    quota_requirement: AttachmentQuotaRequirement,
    observed_at: datetime,
) -> str:
    observed_at = normalize_utc_timestamp(observed_at)
    digest = sha256(b"systeme-local:attachment-capability-profile:v1\x00")
    for value in (
        profile_id,
        provider,
        surface,
        support.state.value,
        support.evidence.value,
        quota_requirement.value,
        observed_at.isoformat(),
    ):
        _frame_text(digest, value)
    _frame_int(digest, revision)
    _frame_int(digest, len(supported_media_types))
    for media_type in supported_media_types:
        _frame_text(digest, media_type.value)
    for value in (
        max_file_bytes,
        max_batch_bytes,
        max_manifest_bytes,
        max_files_per_batch,
        max_files_per_manifest,
        max_batches_per_manifest,
        max_image_width,
        max_image_height,
        max_image_pixels,
        1 if allows_mixed_media else 0,
    ):
        _frame_int(digest, value)
    return digest.hexdigest()


def commit_attachment_capability_profile(
    *,
    profile_id: str,
    revision: int,
    provider: str,
    surface: str,
    support: CapabilityClaim,
    supported_media_types: tuple[AttachmentMediaType, ...],
    max_file_bytes: int,
    max_batch_bytes: int,
    max_manifest_bytes: int,
    max_files_per_batch: int,
    max_files_per_manifest: int,
    max_batches_per_manifest: int,
    max_image_width: int,
    max_image_height: int,
    max_image_pixels: int,
    allows_mixed_media: bool,
    quota_requirement: AttachmentQuotaRequirement,
    observed_at: datetime,
) -> AttachmentCapabilityProfile:
    observed_at = normalize_utc_timestamp(observed_at)
    digest = attachment_capability_profile_sha256(
        profile_id=profile_id,
        revision=revision,
        provider=provider,
        surface=surface,
        support=support,
        supported_media_types=supported_media_types,
        max_file_bytes=max_file_bytes,
        max_batch_bytes=max_batch_bytes,
        max_manifest_bytes=max_manifest_bytes,
        max_files_per_batch=max_files_per_batch,
        max_files_per_manifest=max_files_per_manifest,
        max_batches_per_manifest=max_batches_per_manifest,
        max_image_width=max_image_width,
        max_image_height=max_image_height,
        max_image_pixels=max_image_pixels,
        allows_mixed_media=allows_mixed_media,
        quota_requirement=quota_requirement,
        observed_at=observed_at,
    )
    return AttachmentCapabilityProfile(
        profile_id=profile_id,
        revision=revision,
        provider=provider,
        surface=surface,
        support=support,
        supported_media_types=supported_media_types,
        max_file_bytes=max_file_bytes,
        max_batch_bytes=max_batch_bytes,
        max_manifest_bytes=max_manifest_bytes,
        max_files_per_batch=max_files_per_batch,
        max_files_per_manifest=max_files_per_manifest,
        max_batches_per_manifest=max_batches_per_manifest,
        max_image_width=max_image_width,
        max_image_height=max_image_height,
        max_image_pixels=max_image_pixels,
        allows_mixed_media=allows_mixed_media,
        quota_requirement=quota_requirement,
        observed_at=observed_at,
        profile_sha256=digest,
    )



def attachment_quota_snapshot_sha256(snapshot: ProviderQuotaSnapshot) -> str:
    observed_at = normalize_utc_timestamp(snapshot.observed_at)
    reset_at = (
        None
        if snapshot.reset_at is None
        else normalize_utc_timestamp(snapshot.reset_at)
    )
    digest = sha256(b"systeme-local:attachment-quota-snapshot:v1\x00")
    for value in (
        snapshot.version,
        snapshot.snapshot_id,
        snapshot.account_id,
        snapshot.dimension.value,
        snapshot.state.value,
        snapshot.evidence.value,
        snapshot.unit.value,
        observed_at.isoformat(),
        "" if reset_at is None else reset_at.isoformat(),
    ):
        _frame_text(digest, value)
    for value in (
        1 if reset_at is not None else 0,
        1 if snapshot.remaining_value is not None else 0,
        0 if snapshot.remaining_value is None else snapshot.remaining_value,
        1 if snapshot.limit_value is not None else 0,
        0 if snapshot.limit_value is None else snapshot.limit_value,
    ):
        _frame_int(digest, value)
    return digest.hexdigest()

def attachment_plan_sha256(
    *,
    plan_id: str,
    account_id: str,
    manifest_id: str,
    manifest_sha256: str,
    provider: str,
    surface: str,
    capability_profile_id: str,
    capability_profile_revision: int,
    capability_profile_sha256: str,
    upload_quota_snapshot_id: str | None,
    upload_quota_observed_at: datetime | None,
    upload_quota_sha256: str | None,
    ordered_attachment_ids: tuple[str, ...],
    batches: tuple[AttachmentBatch, ...],
    planned_at: datetime,
) -> str:
    planned_at = normalize_utc_timestamp(planned_at)
    if upload_quota_observed_at is not None:
        upload_quota_observed_at = normalize_utc_timestamp(upload_quota_observed_at)
    digest = sha256(b"systeme-local:attachment-batch-plan:v1\x00")
    for value in (
        plan_id,
        account_id,
        manifest_id,
        manifest_sha256,
        provider,
        surface,
        capability_profile_id,
        capability_profile_sha256,
        upload_quota_snapshot_id or "",
        "" if upload_quota_observed_at is None else upload_quota_observed_at.isoformat(),
        upload_quota_sha256 or "",
        planned_at.isoformat(),
    ):
        _frame_text(digest, value)
    _frame_int(digest, capability_profile_revision)
    _frame_int(digest, len(ordered_attachment_ids))
    for attachment_id in ordered_attachment_ids:
        _frame_text(digest, attachment_id)
    _frame_int(digest, len(batches))
    for batch in batches:
        _frame_text(digest, batch.batch_id)
        _frame_int(digest, batch.batch_index)
        _frame_int(digest, batch.total_bytes)
        for attachment_id in batch.attachment_ids:
            _frame_text(digest, attachment_id)
        for family in batch.media_families:
            _frame_text(digest, family.value)
    return digest.hexdigest()


def attachment_receipt_sha256(
    *,
    receipt_id: str,
    plan_id: str,
    batch_id: str,
    batch_index: int,
    idempotency_key: str,
    status: AttachmentTransferStatus,
    accepted_attachment_ids: tuple[str, ...],
    provider_upload_ids: tuple[str, ...],
    acceptance_known: bool,
    retry_directive: AttachmentRetryDirective,
    error_code: str | None,
    observed_at: datetime,
) -> str:
    observed_at = normalize_utc_timestamp(observed_at)
    digest = sha256(b"systeme-local:attachment-batch-receipt:v1\x00")
    for value in (
        receipt_id,
        plan_id,
        batch_id,
        idempotency_key,
        status.value,
        retry_directive.value,
        error_code or "",
        observed_at.isoformat(),
    ):
        _frame_text(digest, value)
    _frame_int(digest, batch_index)
    _frame_int(digest, 1 if acceptance_known else 0)
    _frame_int(digest, len(accepted_attachment_ids))
    for attachment_id, upload_id in zip(
        accepted_attachment_ids,
        provider_upload_ids,
        strict=True,
    ):
        _frame_text(digest, attachment_id)
        _frame_text(digest, upload_id)
    return digest.hexdigest()
