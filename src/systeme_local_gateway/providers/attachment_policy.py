from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import NoReturn

from pydantic import ValidationError

from .attachment_models import (
    AttachmentBatch,
    AttachmentBatchPlan,
    AttachmentCapabilityProfile,
    AttachmentManifest,
    AttachmentMediaFamily,
    AttachmentQuotaRequirement,
    CommittedAttachment,
    attachment_plan_sha256,
    attachment_quota_snapshot_sha256,
    media_family,
    normalize_utc_timestamp,
)
from .context_models import ProviderQuotaSnapshot, QuotaDimension, QuotaState
from .models import CapabilitySupport


class AttachmentPlanningReason(StrEnum):
    SUPPORT_UNKNOWN = "support_unknown"
    SUPPORT_UNSUPPORTED = "support_unsupported"
    PROFILE_FROM_FUTURE = "profile_from_future"
    MANIFEST_INTEGRITY_INVALID = "manifest_integrity_invalid"
    PROFILE_INTEGRITY_INVALID = "profile_integrity_invalid"
    PLAN_INTEGRITY_INVALID = "plan_integrity_invalid"
    QUOTA_INTEGRITY_INVALID = "quota_integrity_invalid"
    PLAN_BEFORE_MANIFEST = "plan_before_manifest"
    PLAN_ACCOUNT_MISMATCH = "plan_account_mismatch"
    MEDIA_UNSUPPORTED = "media_unsupported"
    FILE_TOO_LARGE = "file_too_large"
    MANIFEST_TOO_LARGE = "manifest_too_large"
    TOO_MANY_FILES = "too_many_files"
    IMAGE_WIDTH_EXCEEDED = "image_width_exceeded"
    IMAGE_HEIGHT_EXCEEDED = "image_height_exceeded"
    IMAGE_PIXELS_EXCEEDED = "image_pixels_exceeded"
    QUOTA_MISSING = "quota_missing"
    QUOTA_ACCOUNT_MISMATCH = "quota_account_mismatch"
    QUOTA_DIMENSION_MISMATCH = "quota_dimension_mismatch"
    QUOTA_FROM_FUTURE = "quota_from_future"
    QUOTA_STALE = "quota_stale"
    QUOTA_UNKNOWN = "quota_unknown"
    QUOTA_EXHAUSTED = "quota_exhausted"
    QUOTA_UNAVAILABLE = "quota_unavailable"
    QUOTA_RESET_PENDING = "quota_reset_pending"
    TOO_MANY_BATCHES = "too_many_batches"
    PLAN_BINDING_MISMATCH = "plan_binding_mismatch"
    PLAN_CONTENT_MISMATCH = "plan_content_mismatch"


class AttachmentPlanningError(ValueError):
    def __init__(
        self,
        reason: AttachmentPlanningReason,
        message: str,
        *,
        attachment_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.attachment_id = attachment_id


def _planning_error(
    reason: AttachmentPlanningReason,
    message: str,
    *,
    attachment_id: str | None = None,
) -> NoReturn:
    raise AttachmentPlanningError(reason, message, attachment_id=attachment_id)


def plan_attachment_batches(
    *,
    plan_id: str,
    account_id: str,
    manifest: AttachmentManifest,
    profile: AttachmentCapabilityProfile,
    planned_at: datetime,
    upload_quota: ProviderQuotaSnapshot | None = None,
    quota_max_age: timedelta = timedelta(minutes=5),
) -> AttachmentBatchPlan:
    planned_at = normalize_utc_timestamp(planned_at)
    if quota_max_age <= timedelta(0):
        raise ValueError("quota_max_age must be positive")
    _validate_model_integrity(
        model=manifest,
        model_type=AttachmentManifest,
        reason=AttachmentPlanningReason.MANIFEST_INTEGRITY_INVALID,
        message="attachment manifest integrity validation failed",
    )
    _validate_model_integrity(
        model=profile,
        model_type=AttachmentCapabilityProfile,
        reason=AttachmentPlanningReason.PROFILE_INTEGRITY_INVALID,
        message="attachment capability profile integrity validation failed",
    )
    _validate_profile_support(profile=profile, evaluated_at=planned_at)
    if planned_at < manifest.committed_at:
        _planning_error(
            AttachmentPlanningReason.PLAN_BEFORE_MANIFEST,
            "attachment planning cannot precede manifest commitment",
        )

    if manifest.attachment_count > profile.max_files_per_manifest:
        _planning_error(
            AttachmentPlanningReason.TOO_MANY_FILES,
            "attachment manifest exceeds the provider file-count limit",
        )
    if manifest.total_bytes > profile.max_manifest_bytes:
        _planning_error(
            AttachmentPlanningReason.MANIFEST_TOO_LARGE,
            "attachment manifest exceeds the provider byte limit",
        )

    effective_upload_quota = (
        upload_quota
        if profile.quota_requirement
        is AttachmentQuotaRequirement.FRESH_UPLOAD_QUOTA
        else None
    )
    if effective_upload_quota is not None:
        _validate_model_integrity(
            model=effective_upload_quota,
            model_type=ProviderQuotaSnapshot,
            reason=AttachmentPlanningReason.QUOTA_INTEGRITY_INVALID,
            message="upload quota snapshot integrity validation failed",
        )
    _validate_quota(
        account_id=account_id,
        profile=profile,
        planned_at=planned_at,
        upload_quota=effective_upload_quota,
        quota_max_age=quota_max_age,
    )
    upload_quota_sha256 = (
        None
        if effective_upload_quota is None
        else attachment_quota_snapshot_sha256(effective_upload_quota)
    )

    batches: list[AttachmentBatch] = []
    current_ids: list[str] = []
    current_bytes = 0
    current_families: list[AttachmentMediaFamily] = []

    def flush() -> None:
        nonlocal current_ids, current_bytes, current_families
        if not current_ids:
            return
        batch_index = len(batches)
        batch_id = _stable_id(
            "attbatch_",
            plan_id,
            manifest.manifest_sha256,
            str(batch_index),
            *current_ids,
        )
        batches.append(
            AttachmentBatch(
                batch_id=batch_id,
                batch_index=batch_index,
                attachment_ids=tuple(current_ids),
                total_bytes=current_bytes,
                media_families=tuple(current_families),
            )
        )
        current_ids = []
        current_bytes = 0
        current_families = []

    for attachment in manifest.attachments:
        family = _validate_attachment_against_profile(
            attachment=attachment,
            profile=profile,
        )
        inspection = attachment.inspection

        exceeds_count = len(current_ids) + 1 > profile.max_files_per_batch
        exceeds_bytes = current_bytes + inspection.byte_size > profile.max_batch_bytes
        changes_family = (
            not profile.allows_mixed_media
            and current_families
            and family not in current_families
        )

        if exceeds_count or exceeds_bytes or changes_family:
            flush()

        current_ids.append(attachment.attachment_id)
        current_bytes += inspection.byte_size
        if family not in current_families:
            current_families.append(family)

    flush()

    if len(batches) > profile.max_batches_per_manifest:
        _planning_error(
            AttachmentPlanningReason.TOO_MANY_BATCHES,
            "deterministic batching exceeds the provider batch-count limit",
        )

    ordered_attachment_ids = tuple(item.attachment_id for item in manifest.attachments)
    batch_tuple = tuple(batches)
    digest = attachment_plan_sha256(
        plan_id=plan_id,
        account_id=account_id,
        manifest_id=manifest.manifest_id,
        manifest_sha256=manifest.manifest_sha256,
        provider=profile.provider,
        surface=profile.surface,
        capability_profile_id=profile.profile_id,
        capability_profile_revision=profile.revision,
        capability_profile_sha256=profile.profile_sha256,
        upload_quota_snapshot_id=(
            None
            if effective_upload_quota is None
            else effective_upload_quota.snapshot_id
        ),
        upload_quota_observed_at=(
            None
            if effective_upload_quota is None
            else effective_upload_quota.observed_at
        ),
        upload_quota_sha256=upload_quota_sha256,
        ordered_attachment_ids=ordered_attachment_ids,
        batches=batch_tuple,
        planned_at=planned_at,
    )
    return AttachmentBatchPlan(
        plan_id=plan_id,
        account_id=account_id,
        manifest_id=manifest.manifest_id,
        manifest_sha256=manifest.manifest_sha256,
        provider=profile.provider,
        surface=profile.surface,
        capability_profile_id=profile.profile_id,
        capability_profile_revision=profile.revision,
        capability_profile_sha256=profile.profile_sha256,
        upload_quota_snapshot_id=(
            None
            if effective_upload_quota is None
            else effective_upload_quota.snapshot_id
        ),
        upload_quota_observed_at=(
            None
            if effective_upload_quota is None
            else effective_upload_quota.observed_at
        ),
        upload_quota_sha256=upload_quota_sha256,
        ordered_attachment_ids=ordered_attachment_ids,
        attachment_count=manifest.attachment_count,
        total_bytes=manifest.total_bytes,
        batches=batch_tuple,
        planned_at=planned_at,
        plan_sha256=digest,
    )



def verify_attachment_batch_plan(
    *,
    plan: AttachmentBatchPlan,
    account_id: str,
    manifest: AttachmentManifest,
    profile: AttachmentCapabilityProfile,
    upload_quota: ProviderQuotaSnapshot | None = None,
    quota_max_age: timedelta = timedelta(minutes=5),
) -> None:
    if quota_max_age <= timedelta(0):
        raise ValueError("quota_max_age must be positive")
    _validate_model_integrity(
        model=plan,
        model_type=AttachmentBatchPlan,
        reason=AttachmentPlanningReason.PLAN_INTEGRITY_INVALID,
        message="attachment batch plan integrity validation failed",
    )
    _validate_model_integrity(
        model=manifest,
        model_type=AttachmentManifest,
        reason=AttachmentPlanningReason.MANIFEST_INTEGRITY_INVALID,
        message="attachment manifest integrity validation failed",
    )
    _validate_model_integrity(
        model=profile,
        model_type=AttachmentCapabilityProfile,
        reason=AttachmentPlanningReason.PROFILE_INTEGRITY_INVALID,
        message="attachment capability profile integrity validation failed",
    )
    _validate_profile_support(profile=profile, evaluated_at=plan.planned_at)
    if plan.planned_at < manifest.committed_at:
        _planning_error(
            AttachmentPlanningReason.PLAN_BEFORE_MANIFEST,
            "attachment plan predates manifest commitment",
        )
    if plan.account_id != account_id:
        _planning_error(
            AttachmentPlanningReason.PLAN_ACCOUNT_MISMATCH,
            "attachment plan belongs to another account",
        )
    if (
        plan.manifest_id != manifest.manifest_id
        or plan.manifest_sha256 != manifest.manifest_sha256
        or plan.provider != profile.provider
        or plan.surface != profile.surface
        or plan.capability_profile_id != profile.profile_id
        or plan.capability_profile_revision != profile.revision
        or plan.capability_profile_sha256 != profile.profile_sha256
    ):
        _planning_error(
            AttachmentPlanningReason.PLAN_BINDING_MISMATCH,
            "attachment plan does not match its manifest or capability profile",
        )

    if (
        plan.attachment_count != manifest.attachment_count
        or plan.total_bytes != manifest.total_bytes
    ):
        _planning_error(
            AttachmentPlanningReason.PLAN_CONTENT_MISMATCH,
            "attachment plan totals do not match the manifest",
        )
    if manifest.attachment_count > profile.max_files_per_manifest:
        _planning_error(
            AttachmentPlanningReason.PLAN_CONTENT_MISMATCH,
            "attachment plan exceeds the committed manifest file limit",
        )
    if manifest.total_bytes > profile.max_manifest_bytes:
        _planning_error(
            AttachmentPlanningReason.PLAN_CONTENT_MISMATCH,
            "attachment plan exceeds the committed manifest byte limit",
        )
    if len(plan.batches) > profile.max_batches_per_manifest:
        _planning_error(
            AttachmentPlanningReason.PLAN_CONTENT_MISMATCH,
            "attachment plan exceeds the committed batch-count limit",
        )

    if profile.quota_requirement is AttachmentQuotaRequirement.FRESH_UPLOAD_QUOTA:
        if upload_quota is None:
            _planning_error(
                AttachmentPlanningReason.QUOTA_MISSING,
                "plan verification requires the committed upload quota snapshot",
            )
        assert upload_quota is not None
        _validate_model_integrity(
            model=upload_quota,
            model_type=ProviderQuotaSnapshot,
            reason=AttachmentPlanningReason.QUOTA_INTEGRITY_INVALID,
            message="upload quota snapshot integrity validation failed",
        )
        if (
            plan.upload_quota_snapshot_id != upload_quota.snapshot_id
            or plan.upload_quota_observed_at != upload_quota.observed_at
            or plan.upload_quota_sha256
            != attachment_quota_snapshot_sha256(upload_quota)
        ):
            _planning_error(
                AttachmentPlanningReason.PLAN_BINDING_MISMATCH,
                "attachment plan quota evidence does not match the supplied snapshot",
            )
        _validate_quota(
            account_id=plan.account_id,
            profile=profile,
            planned_at=plan.planned_at,
            upload_quota=upload_quota,
            quota_max_age=quota_max_age,
        )
    elif (
        plan.upload_quota_snapshot_id is not None
        or plan.upload_quota_observed_at is not None
        or plan.upload_quota_sha256 is not None
    ):
        _planning_error(
            AttachmentPlanningReason.PLAN_BINDING_MISMATCH,
            "attachment plan carries quota evidence not required by the profile",
        )

    by_id = {item.attachment_id: item for item in manifest.attachments}
    if tuple(by_id) != plan.ordered_attachment_ids:
        _planning_error(
            AttachmentPlanningReason.PLAN_CONTENT_MISMATCH,
            "attachment plan order does not match the manifest",
        )

    for batch in plan.batches:
        expected_bytes = 0
        expected_families: list[AttachmentMediaFamily] = []
        for attachment_id in batch.attachment_ids:
            attachment = by_id.get(attachment_id)
            if attachment is None:
                _planning_error(
                    AttachmentPlanningReason.PLAN_CONTENT_MISMATCH,
                    "attachment plan references an unknown attachment",
                    attachment_id=attachment_id,
                )
            assert attachment is not None
            family = _validate_attachment_against_profile(
                attachment=attachment,
                profile=profile,
            )
            expected_bytes += attachment.inspection.byte_size
            if family not in expected_families:
                expected_families.append(family)
        expected_batch_id = _stable_id(
            "attbatch_",
            plan.plan_id,
            manifest.manifest_sha256,
            str(batch.batch_index),
            *batch.attachment_ids,
        )
        if batch.batch_id != expected_batch_id:
            _planning_error(
                AttachmentPlanningReason.PLAN_CONTENT_MISMATCH,
                "attachment batch identifier is not deterministic",
            )
        if batch.total_bytes != expected_bytes:
            _planning_error(
                AttachmentPlanningReason.PLAN_CONTENT_MISMATCH,
                "attachment batch byte total does not match the manifest",
            )
        if batch.media_families != tuple(expected_families):
            _planning_error(
                AttachmentPlanningReason.PLAN_CONTENT_MISMATCH,
                "attachment batch media families do not match the manifest",
            )
        if len(batch.attachment_ids) > profile.max_files_per_batch:
            _planning_error(
                AttachmentPlanningReason.PLAN_CONTENT_MISMATCH,
                "attachment batch exceeds the committed file-count limit",
            )
        if batch.total_bytes > profile.max_batch_bytes:
            _planning_error(
                AttachmentPlanningReason.PLAN_CONTENT_MISMATCH,
                "attachment batch exceeds the committed byte limit",
            )
        if not profile.allows_mixed_media and len(batch.media_families) > 1:
            _planning_error(
                AttachmentPlanningReason.PLAN_CONTENT_MISMATCH,
                "attachment batch violates the committed mixed-media policy",
            )




def _validate_model_integrity(
    *,
    model: object,
    model_type: type,
    reason: AttachmentPlanningReason,
    message: str,
) -> None:
    try:
        model_type.model_validate(model.model_dump(mode="python"))
    except (AttributeError, ValidationError) as exc:
        raise AttachmentPlanningError(reason, message) from exc

def _validate_profile_support(
    *,
    profile: AttachmentCapabilityProfile,
    evaluated_at: datetime,
) -> None:
    if profile.support.state is CapabilitySupport.UNKNOWN:
        _planning_error(
            AttachmentPlanningReason.SUPPORT_UNKNOWN,
            "attachment support is unknown for this provider surface",
        )
    if profile.support.state is CapabilitySupport.UNSUPPORTED:
        _planning_error(
            AttachmentPlanningReason.SUPPORT_UNSUPPORTED,
            "attachment support is unavailable for this provider surface",
        )
    if profile.observed_at > evaluated_at:
        _planning_error(
            AttachmentPlanningReason.PROFILE_FROM_FUTURE,
            "attachment capability profile cannot come from the future",
        )


def _validate_attachment_against_profile(
    *,
    attachment: CommittedAttachment,
    profile: AttachmentCapabilityProfile,
) -> AttachmentMediaFamily:
    inspection = attachment.inspection
    attachment_id = attachment.attachment_id
    if inspection.media_type not in profile.supported_media_types:
        _planning_error(
            AttachmentPlanningReason.MEDIA_UNSUPPORTED,
            f"unsupported attachment media type: {inspection.media_type}",
            attachment_id=attachment_id,
        )
    if inspection.byte_size > profile.max_file_bytes:
        _planning_error(
            AttachmentPlanningReason.FILE_TOO_LARGE,
            "attachment exceeds the provider per-file byte limit",
            attachment_id=attachment_id,
        )
    if inspection.byte_size > profile.max_batch_bytes:
        _planning_error(
            AttachmentPlanningReason.FILE_TOO_LARGE,
            "single attachment exceeds the provider batch byte limit",
            attachment_id=attachment_id,
        )

    family = media_family(inspection.media_type)
    if family is AttachmentMediaFamily.IMAGE:
        width = inspection.image_width
        height = inspection.image_height
        assert width is not None and height is not None
        if width > profile.max_image_width:
            _planning_error(
                AttachmentPlanningReason.IMAGE_WIDTH_EXCEEDED,
                "image width exceeds the provider limit",
                attachment_id=attachment_id,
            )
        if height > profile.max_image_height:
            _planning_error(
                AttachmentPlanningReason.IMAGE_HEIGHT_EXCEEDED,
                "image height exceeds the provider limit",
                attachment_id=attachment_id,
            )
        if width * height > profile.max_image_pixels:
            _planning_error(
                AttachmentPlanningReason.IMAGE_PIXELS_EXCEEDED,
                "image pixel count exceeds the provider limit",
                attachment_id=attachment_id,
            )
    return family


def _validate_quota(
    *,
    account_id: str,
    profile: AttachmentCapabilityProfile,
    planned_at: datetime,
    upload_quota: ProviderQuotaSnapshot | None,
    quota_max_age: timedelta,
) -> None:
    if profile.quota_requirement is AttachmentQuotaRequirement.NONE:
        return
    if upload_quota is None:
        _planning_error(
            AttachmentPlanningReason.QUOTA_MISSING,
            "fresh file-upload quota evidence is required",
        )
    assert upload_quota is not None
    if upload_quota.account_id != account_id:
        _planning_error(
            AttachmentPlanningReason.QUOTA_ACCOUNT_MISMATCH,
            "upload quota belongs to another account",
        )
    if upload_quota.dimension is not QuotaDimension.FILE_UPLOAD_RATE:
        _planning_error(
            AttachmentPlanningReason.QUOTA_DIMENSION_MISMATCH,
            "quota dimension must be file_upload_rate",
        )
    if upload_quota.observed_at > planned_at:
        _planning_error(
            AttachmentPlanningReason.QUOTA_FROM_FUTURE,
            "quota observation cannot come from the future",
        )
    if planned_at - upload_quota.observed_at > quota_max_age:
        _planning_error(
            AttachmentPlanningReason.QUOTA_STALE,
            "upload quota observation is stale",
        )
    state_to_reason = {
        QuotaState.UNKNOWN: AttachmentPlanningReason.QUOTA_UNKNOWN,
        QuotaState.EXHAUSTED: AttachmentPlanningReason.QUOTA_EXHAUSTED,
        QuotaState.UNAVAILABLE: AttachmentPlanningReason.QUOTA_UNAVAILABLE,
        QuotaState.RESET_PENDING: AttachmentPlanningReason.QUOTA_RESET_PENDING,
    }
    if upload_quota.state in state_to_reason:
        _planning_error(
            state_to_reason[upload_quota.state],
            f"upload quota state is not usable: {upload_quota.state}",
        )
    if upload_quota.state not in (QuotaState.AVAILABLE, QuotaState.NEAR_LIMIT):
        raise AssertionError(f"unhandled upload quota state: {upload_quota.state}")


def _stable_id(prefix: str, *parts: str) -> str:
    digest = sha256(b"systeme-local:attachment-stable-id:v1\x00")
    for part in parts:
        encoded = part.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return prefix + digest.hexdigest()[:24]
