from __future__ import annotations

from datetime import timedelta, timezone

import pytest
from pydantic import ValidationError

from systeme_local_gateway.providers.attachment_models import (
    AttachmentBatch,
    AttachmentCapabilityProfile,
    AttachmentInspection,
    AttachmentMediaFamily,
    AttachmentMediaType,
    AttachmentQuotaRequirement,
    AttachmentRetryDirective,
    AttachmentTransferStatus,
    CommittedAttachment,
    attachment_quota_snapshot_sha256,
    commit_attachment_capability_profile,
    validate_attachment_display_name,
)

from systeme_local_gateway.providers.models import (
    CapabilityClaim,
    CapabilityEvidence,
    CapabilitySupport,
)

from conftest import NOW


@pytest.mark.parametrize(
    "name",
    [
        "file.txt",
        "capture écran.png",
        "résumé.json",
        "a" * 200,
    ],
)
def test_display_name_accepts_safe_values(name):
    assert validate_attachment_display_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        ".",
        "..",
        "a/b.txt",
        r"a\b.txt",
        "file.",
        "file ",
        "CON",
        "nul.txt",
        "COM1.log",
        "LPT9",
        "bad\x00name",
        "bad\nname",
        "bad:name.txt",
        "bad?name.txt",
        "abc\u202edef.txt",
        "e\u0301.txt",
    ],
)
def test_display_name_rejects_ambiguous_or_unsafe_values(name):
    with pytest.raises(ValueError):
        validate_attachment_display_name(name)


def test_display_name_rejects_utf8_byte_overflow():
    with pytest.raises(ValueError):
        validate_attachment_display_name("é" * 121)


@pytest.mark.parametrize("media_type", [AttachmentMediaType.PNG, AttachmentMediaType.JPEG])
def test_image_inspection_requires_dimensions(media_type):
    with pytest.raises(ValidationError):
        AttachmentInspection(
            media_type=media_type,
            content_sha256="0" * 64,
            byte_size=10,
            inspected_at=NOW,
        )


@pytest.mark.parametrize(
    "media_type",
    [AttachmentMediaType.PDF, AttachmentMediaType.TEXT, AttachmentMediaType.JSON],
)
def test_non_image_inspection_rejects_dimensions(media_type):
    with pytest.raises(ValidationError):
        AttachmentInspection(
            media_type=media_type,
            content_sha256="0" * 64,
            byte_size=10,
            image_width=1,
            image_height=1,
            inspected_at=NOW,
        )


def test_committed_attachment_rejects_metadata_digest_tampering(attachment_committed_items):
    payload = attachment_committed_items[0].model_dump()
    payload["display_name"] = "changed.png"
    with pytest.raises(ValidationError, match="metadata digest mismatch"):
        CommittedAttachment.model_validate(payload)


def test_committed_attachment_rejects_commit_before_inspection(attachment_committed_items):
    payload = attachment_committed_items[0].model_dump()
    payload["committed_at"] = NOW - timedelta(seconds=1)
    with pytest.raises(ValidationError, match="must not precede"):
        CommittedAttachment.model_validate(payload)


def test_supported_profile_requires_positive_limits():
    with pytest.raises(ValidationError, match="positive limits"):
        commit_attachment_capability_profile(
            profile_id="attachment_profile_invalid",
            revision=1,
            provider="chatgpt",
            surface="fake",
            support=CapabilityClaim(
                state=CapabilitySupport.SUPPORTED,
                evidence=CapabilityEvidence.SIMULATED,
            ),
            supported_media_types=(AttachmentMediaType.PNG,),
            max_file_bytes=0,
            max_batch_bytes=0,
            max_manifest_bytes=0,
            max_files_per_batch=0,
            max_files_per_manifest=0,
            max_batches_per_manifest=0,
            max_image_width=0,
            max_image_height=0,
            max_image_pixels=0,
            allows_mixed_media=False,
            quota_requirement=AttachmentQuotaRequirement.NONE,
            observed_at=NOW,
        )


def test_supported_profile_rejects_duplicate_media_types(attachment_supported_profile):
    payload = attachment_supported_profile.model_dump()
    payload["supported_media_types"] = ["image/png", "image/png"]
    with pytest.raises(ValidationError, match="must be unique"):
        AttachmentCapabilityProfile.model_validate(payload)


def test_document_only_profile_requires_zero_image_limits():
    with pytest.raises(ValidationError, match="zero image limits"):
        commit_attachment_capability_profile(
            profile_id="attachment_profile_docs",
            revision=1,
            provider="chatgpt",
            surface="fake",
            support=CapabilityClaim(
                state=CapabilitySupport.SUPPORTED,
                evidence=CapabilityEvidence.SIMULATED,
            ),
            supported_media_types=(AttachmentMediaType.TEXT,),
            max_file_bytes=100,
            max_batch_bytes=100,
            max_manifest_bytes=100,
            max_files_per_batch=1,
            max_files_per_manifest=1,
            max_batches_per_manifest=1,
            max_image_width=1,
            max_image_height=1,
            max_image_pixels=1,
            allows_mixed_media=False,
            quota_requirement=AttachmentQuotaRequirement.NONE,
            observed_at=NOW,
        )


def test_non_supported_profile_rejects_advertised_limits():
    with pytest.raises(ValidationError, match="must not advertise"):
        commit_attachment_capability_profile(
            profile_id="attachment_profile_unknown",
            revision=1,
            provider="chatgpt",
            surface="unknown",
            support=CapabilityClaim(
                state=CapabilitySupport.UNKNOWN,
                evidence=CapabilityEvidence.NONE,
            ),
            supported_media_types=(AttachmentMediaType.PNG,),
            max_file_bytes=1,
            max_batch_bytes=1,
            max_manifest_bytes=1,
            max_files_per_batch=1,
            max_files_per_manifest=1,
            max_batches_per_manifest=1,
            max_image_width=1,
            max_image_height=1,
            max_image_pixels=1,
            allows_mixed_media=False,
            quota_requirement=AttachmentQuotaRequirement.NONE,
            observed_at=NOW,
        )


def test_capability_profile_digest_detects_tampering(attachment_supported_profile):
    payload = attachment_supported_profile.model_dump()
    payload["max_file_bytes"] -= 1
    with pytest.raises(ValidationError, match="profile digest mismatch"):
        AttachmentCapabilityProfile.model_validate(payload)


def test_batch_rejects_duplicate_attachment_ids():
    with pytest.raises(ValidationError, match="duplicate attachment_id"):
        AttachmentBatch(
            batch_id="batch_main",
            batch_index=0,
            attachment_ids=("attachment_1", "attachment_1"),
            total_bytes=2,
            media_families=(AttachmentMediaFamily.IMAGE,),
        )


def test_batch_rejects_duplicate_media_families():
    with pytest.raises(ValidationError, match="duplicate media family"):
        AttachmentBatch(
            batch_id="batch_main",
            batch_index=0,
            attachment_ids=("attachment_1",),
            total_bytes=2,
            media_families=(
                AttachmentMediaFamily.IMAGE,
                AttachmentMediaFamily.IMAGE,
            ),
        )


@pytest.mark.parametrize(
    ("status", "acceptance_known", "directive", "error_code"),
    [
        (
            AttachmentTransferStatus.COMPLETED,
            False,
            AttachmentRetryDirective.DO_NOT_RETRY,
            None,
        ),
        (
            AttachmentTransferStatus.AMBIGUOUS,
            True,
            AttachmentRetryDirective.RECONCILE_REQUIRED,
            "ERR_CODE",
        ),
        (
            AttachmentTransferStatus.REJECTED,
            False,
            AttachmentRetryDirective.DO_NOT_RETRY,
            "ERR_CODE",
        ),
    ],
)
def test_receipt_consistency_rules(
    status,
    acceptance_known,
    directive,
    error_code,
):
    from systeme_local_gateway.providers.attachment_models import AttachmentBatchReceipt

    with pytest.raises(ValidationError):
        AttachmentBatchReceipt(
            receipt_id="receipt_main",
            plan_id="plan_main",
            batch_id="batch_main",
            batch_index=0,
            idempotency_key="idem_main",
            status=status,
            accepted_attachment_ids=(),
            provider_upload_ids=(),
            acceptance_known=acceptance_known,
            retry_directive=directive,
            error_code=error_code,
            observed_at=NOW,
            receipt_sha256="0" * 64,
        )


@pytest.mark.parametrize(
    ("status", "accepted", "directive"),
    [
        (
            AttachmentTransferStatus.PARTIAL,
            ("attachment_1",),
            AttachmentRetryDirective.SAFE_RETRY,
        ),
        (
            AttachmentTransferStatus.CANCELLED,
            (),
            AttachmentRetryDirective.DO_NOT_RETRY,
        ),
        (
            AttachmentTransferStatus.REJECTED,
            (),
            AttachmentRetryDirective.SAFE_RETRY,
        ),
    ],
)
def test_non_completed_receipt_directives_are_status_specific(
    status,
    accepted,
    directive,
):
    from systeme_local_gateway.providers.attachment_models import (
        AttachmentBatchReceipt,
        attachment_receipt_sha256,
    )

    uploads = tuple(f"upload_{index}" for index, _ in enumerate(accepted))
    digest = attachment_receipt_sha256(
        receipt_id="receipt_status",
        plan_id="plan_main",
        batch_id="batch_main",
        batch_index=0,
        idempotency_key="idem_status",
        status=status,
        accepted_attachment_ids=accepted,
        provider_upload_ids=uploads,
        acceptance_known=True,
        retry_directive=directive,
        error_code="STATUS_ERROR",
        observed_at=NOW,
    )
    with pytest.raises(ValidationError):
        AttachmentBatchReceipt(
            receipt_id="receipt_status",
            plan_id="plan_main",
            batch_id="batch_main",
            batch_index=0,
            idempotency_key="idem_status",
            status=status,
            accepted_attachment_ids=accepted,
            provider_upload_ids=uploads,
            acceptance_known=True,
            retry_directive=directive,
            error_code="STATUS_ERROR",
            observed_at=NOW,
            receipt_sha256=digest,
        )


def test_models_forbid_extra_fields(attachment_committed_items):
    payload = attachment_committed_items[0].model_dump()
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        CommittedAttachment.model_validate(payload)


def test_receipt_rejects_duplicate_provider_upload_ids():
    from systeme_local_gateway.providers.attachment_models import (
        AttachmentBatchReceipt,
        attachment_receipt_sha256,
    )

    digest = attachment_receipt_sha256(
        receipt_id="receipt_duplicate_upload",
        plan_id="plan_main",
        batch_id="batch_main",
        batch_index=0,
        idempotency_key="idem_duplicate_upload",
        status=AttachmentTransferStatus.COMPLETED,
        accepted_attachment_ids=("attachment_0", "attachment_1"),
        provider_upload_ids=("upload_same", "upload_same"),
        acceptance_known=True,
        retry_directive=AttachmentRetryDirective.DO_NOT_RETRY,
        error_code=None,
        observed_at=NOW,
    )
    with pytest.raises(ValidationError, match="provider upload ids must be unique"):
        AttachmentBatchReceipt(
            receipt_id="receipt_duplicate_upload",
            plan_id="plan_main",
            batch_id="batch_main",
            batch_index=0,
            idempotency_key="idem_duplicate_upload",
            status=AttachmentTransferStatus.COMPLETED,
            accepted_attachment_ids=("attachment_0", "attachment_1"),
            provider_upload_ids=("upload_same", "upload_same"),
            acceptance_known=True,
            retry_directive=AttachmentRetryDirective.DO_NOT_RETRY,
            error_code=None,
            observed_at=NOW,
            receipt_sha256=digest,
        )


def test_quota_snapshot_digest_is_canonical_across_timezone_offsets():
    from systeme_local_gateway.providers.context_models import (
        ProviderQuotaSnapshot,
        QuotaDimension,
        QuotaState,
        QuotaUnit,
    )

    snapshot = ProviderQuotaSnapshot(
        snapshot_id="quota_digest",
        account_id="account_main",
        dimension=QuotaDimension.FILE_UPLOAD_RATE,
        state=QuotaState.AVAILABLE,
        evidence=CapabilityEvidence.SIMULATED,
        observed_at=NOW,
        remaining_value=10,
        limit_value=20,
        unit=QuotaUnit.REQUESTS,
    )
    plus_two = timezone(timedelta(hours=2))
    equivalent = snapshot.model_copy(
        update={"observed_at": NOW.astimezone(plus_two)}
    )
    assert attachment_quota_snapshot_sha256(snapshot) == (
        attachment_quota_snapshot_sha256(equivalent)
    )
