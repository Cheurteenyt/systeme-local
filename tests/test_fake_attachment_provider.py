from __future__ import annotations

from datetime import timedelta

import pytest

from systeme_local_gateway.providers.attachment_models import (
    AttachmentBatchReceipt,
    AttachmentRetryDirective,
    attachment_receipt_sha256,
    AttachmentTransferStatus,
)
from systeme_local_gateway.providers.attachment_policy import plan_attachment_batches
from systeme_local_gateway.providers.fake_attachment_provider import (
    AttachmentIdempotencyConflictError,
    DeterministicFakeAttachmentProvider,
    FakeAttachmentScenario,
    verify_attachment_batch_receipt,
)

from conftest import NOW


@pytest.fixture
def plan(attachment_manifest, attachment_supported_profile):
    return plan_attachment_batches(
        plan_id="plan_main",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW,
    )


@pytest.mark.parametrize(
    ("scenario", "status", "known", "directive", "error_code"),
    [
        (
            FakeAttachmentScenario.COMPLETED,
            AttachmentTransferStatus.COMPLETED,
            True,
            AttachmentRetryDirective.DO_NOT_RETRY,
            None,
        ),
        (
            FakeAttachmentScenario.PARTIAL,
            AttachmentTransferStatus.PARTIAL,
            True,
            AttachmentRetryDirective.DO_NOT_RETRY,
            "FAKE_PARTIAL_ACCEPTANCE",
        ),
        (
            FakeAttachmentScenario.CANCELLED,
            AttachmentTransferStatus.CANCELLED,
            True,
            AttachmentRetryDirective.SAFE_RETRY,
            "FAKE_CANCELLED_BEFORE_ACCEPTANCE",
        ),
        (
            FakeAttachmentScenario.REJECTED,
            AttachmentTransferStatus.REJECTED,
            True,
            AttachmentRetryDirective.DO_NOT_RETRY,
            "FAKE_PROVIDER_REJECTION",
        ),
        (
            FakeAttachmentScenario.AMBIGUOUS,
            AttachmentTransferStatus.AMBIGUOUS,
            False,
            AttachmentRetryDirective.RECONCILE_REQUIRED,
            "FAKE_ACCEPTANCE_UNKNOWN",
        ),
    ],
)
def test_fake_scenarios(
    plan,
    scenario,
    status,
    known,
    directive,
    error_code,
):
    provider = DeterministicFakeAttachmentProvider()
    receipt = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="upload_idem",
        scenario=scenario,
        observed_at=NOW,
    )
    assert receipt.status is status
    assert receipt.acceptance_known is known
    assert receipt.retry_directive is directive
    assert receipt.error_code == error_code
    assert len(receipt.receipt_sha256) == 64


def test_completed_accepts_every_attachment_in_batch(plan):
    provider = DeterministicFakeAttachmentProvider()
    receipt = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="upload_idem",
        scenario=FakeAttachmentScenario.COMPLETED,
        observed_at=NOW,
    )
    assert receipt.accepted_attachment_ids == plan.batches[0].attachment_ids
    assert len(receipt.provider_upload_ids) == len(plan.batches[0].attachment_ids)


def test_partial_accepts_a_known_prefix(plan):
    provider = DeterministicFakeAttachmentProvider()
    receipt = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="upload_idem",
        scenario=FakeAttachmentScenario.PARTIAL,
        observed_at=NOW,
    )
    assert receipt.accepted_attachment_ids
    assert plan.batches[0].attachment_ids[: len(receipt.accepted_attachment_ids)] == (
        receipt.accepted_attachment_ids
    )


def test_ambiguous_never_claims_acceptance_or_safe_retry(plan):
    provider = DeterministicFakeAttachmentProvider()
    receipt = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="upload_idem",
        scenario=FakeAttachmentScenario.AMBIGUOUS,
        observed_at=NOW,
    )
    assert receipt.accepted_attachment_ids == ()
    assert receipt.provider_upload_ids == ()
    assert receipt.retry_directive is AttachmentRetryDirective.RECONCILE_REQUIRED


def test_receipt_canonicalizes_timezone_offsets(plan):
    from datetime import timezone

    plus_two = timezone(timedelta(hours=2))
    provider = DeterministicFakeAttachmentProvider()
    receipt = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="upload_tz",
        scenario=FakeAttachmentScenario.COMPLETED,
        observed_at=NOW.astimezone(plus_two),
    )
    assert receipt.observed_at == NOW


def test_same_idempotency_key_returns_same_receipt(plan):
    provider = DeterministicFakeAttachmentProvider()
    first = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="upload_idem",
        scenario=FakeAttachmentScenario.COMPLETED,
        observed_at=NOW,
    )
    second = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="upload_idem",
        scenario=FakeAttachmentScenario.AMBIGUOUS,
        observed_at=NOW + timedelta(seconds=10),
    )
    assert second == first


def test_idempotency_key_conflicts_across_batches(plan):
    provider = DeterministicFakeAttachmentProvider()
    provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="upload_idem",
        scenario=FakeAttachmentScenario.COMPLETED,
        observed_at=NOW,
    )
    with pytest.raises(AttachmentIdempotencyConflictError):
        provider.submit_batch(
            plan=plan,
            batch_index=1,
            idempotency_key="upload_idem",
            scenario=FakeAttachmentScenario.COMPLETED,
            observed_at=NOW,
        )


def test_batch_index_is_bounded(plan):
    provider = DeterministicFakeAttachmentProvider()
    with pytest.raises(ValueError, match="outside"):
        provider.submit_batch(
            plan=plan,
            batch_index=99,
            idempotency_key="upload_idem",
            scenario=FakeAttachmentScenario.COMPLETED,
            observed_at=NOW,
        )


def test_provider_has_no_transport_attributes():
    provider = DeterministicFakeAttachmentProvider()
    assert not hasattr(provider, "client")
    assert not hasattr(provider, "session")
    assert not hasattr(provider, "socket")


def test_verify_completed_receipt_against_plan(plan):
    provider = DeterministicFakeAttachmentProvider()
    receipt = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="upload_idem",
        scenario=FakeAttachmentScenario.COMPLETED,
        observed_at=NOW,
    )
    verify_attachment_batch_receipt(receipt=receipt, plan=plan)


def test_verify_receipt_rejects_other_plan(plan, attachment_manifest, attachment_supported_profile):
    provider = DeterministicFakeAttachmentProvider()
    receipt = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="upload_idem",
        scenario=FakeAttachmentScenario.COMPLETED,
        observed_at=NOW,
    )
    other = plan_attachment_batches(
        plan_id="plan_other",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW,
    )
    with pytest.raises(ValueError, match="does not belong"):
        verify_attachment_batch_receipt(receipt=receipt, plan=other)


def test_verify_receipt_detects_recomputed_semantic_tampering(plan):
    from systeme_local_gateway.providers.attachment_models import (
        AttachmentBatchReceipt,
        AttachmentRetryDirective,
        AttachmentTransferStatus,
        attachment_receipt_sha256,
    )

    batch = plan.batches[0]
    provider = DeterministicFakeAttachmentProvider()
    baseline_partial = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="idem_tampered",
        scenario=FakeAttachmentScenario.PARTIAL,
        observed_at=NOW,
    )
    completed = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="idem_complete_mapping",
        scenario=FakeAttachmentScenario.COMPLETED,
        observed_at=NOW,
    )
    accepted = (batch.attachment_ids[-1],)
    uploads = (completed.provider_upload_ids[-1],)
    digest = attachment_receipt_sha256(
        receipt_id=baseline_partial.receipt_id,
        plan_id=plan.plan_id,
        batch_id=batch.batch_id,
        batch_index=0,
        idempotency_key="idem_tampered",
        status=AttachmentTransferStatus.PARTIAL,
        accepted_attachment_ids=accepted,
        provider_upload_ids=uploads,
        acceptance_known=True,
        retry_directive=AttachmentRetryDirective.DO_NOT_RETRY,
        error_code="FAKE_PARTIAL_ACCEPTANCE",
        observed_at=NOW,
    )
    receipt = AttachmentBatchReceipt(
        receipt_id=baseline_partial.receipt_id,
        plan_id=plan.plan_id,
        batch_id=batch.batch_id,
        batch_index=0,
        idempotency_key="idem_tampered",
        status=AttachmentTransferStatus.PARTIAL,
        accepted_attachment_ids=accepted,
        provider_upload_ids=uploads,
        acceptance_known=True,
        retry_directive=AttachmentRetryDirective.DO_NOT_RETRY,
        error_code="FAKE_PARTIAL_ACCEPTANCE",
        observed_at=NOW,
        receipt_sha256=digest,
    )
    with pytest.raises(ValueError, match="stable batch prefix"):
        verify_attachment_batch_receipt(receipt=receipt, plan=plan)


def test_receipt_digest_detects_tampering(plan):
    provider = DeterministicFakeAttachmentProvider()
    receipt = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="upload_idem",
        scenario=FakeAttachmentScenario.COMPLETED,
        observed_at=NOW,
    )
    payload = receipt.model_dump()
    payload["receipt_sha256"] = "0" * 64
    from pydantic import ValidationError
    from systeme_local_gateway.providers.attachment_models import AttachmentBatchReceipt

    with pytest.raises(ValidationError, match="receipt digest mismatch"):
        AttachmentBatchReceipt.model_validate(payload)


def test_fake_provider_rejects_other_surface(
    attachment_manifest,
    attachment_supported_profile,
):
    from systeme_local_gateway.providers.attachment_models import (
        commit_attachment_capability_profile,
    )

    profile = commit_attachment_capability_profile(
        profile_id="attachment_profile_other_surface",
        revision=1,
        provider="chatgpt",
        surface="other_surface",
        support=attachment_supported_profile.support,
        supported_media_types=attachment_supported_profile.supported_media_types,
        max_file_bytes=attachment_supported_profile.max_file_bytes,
        max_batch_bytes=attachment_supported_profile.max_batch_bytes,
        max_manifest_bytes=attachment_supported_profile.max_manifest_bytes,
        max_files_per_batch=attachment_supported_profile.max_files_per_batch,
        max_files_per_manifest=attachment_supported_profile.max_files_per_manifest,
        max_batches_per_manifest=attachment_supported_profile.max_batches_per_manifest,
        max_image_width=attachment_supported_profile.max_image_width,
        max_image_height=attachment_supported_profile.max_image_height,
        max_image_pixels=attachment_supported_profile.max_image_pixels,
        allows_mixed_media=attachment_supported_profile.allows_mixed_media,
        quota_requirement=attachment_supported_profile.quota_requirement,
        observed_at=attachment_supported_profile.observed_at,
    )
    other_plan = plan_attachment_batches(
        plan_id="plan_other_surface",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=profile,
        planned_at=NOW,
    )
    provider = DeterministicFakeAttachmentProvider()
    with pytest.raises(ValueError, match="another provider surface"):
        provider.submit_batch(
            plan=other_plan,
            batch_index=0,
            idempotency_key="idem_other_surface",
            scenario=FakeAttachmentScenario.COMPLETED,
            observed_at=NOW,
        )


def test_fake_provider_rejects_receipt_time_before_plan(plan):
    provider = DeterministicFakeAttachmentProvider()
    with pytest.raises(ValueError, match="cannot precede"):
        provider.submit_batch(
            plan=plan,
            batch_index=0,
            idempotency_key="idem_before_plan",
            scenario=FakeAttachmentScenario.COMPLETED,
            observed_at=NOW - timedelta(microseconds=1),
        )


def test_fake_provider_detects_in_memory_plan_drift(plan):
    plan.total_bytes += 1
    provider = DeterministicFakeAttachmentProvider()
    with pytest.raises(ValueError, match="plan integrity"):
        provider.submit_batch(
            plan=plan,
            batch_index=0,
            idempotency_key="idem_plan_drift",
            scenario=FakeAttachmentScenario.COMPLETED,
            observed_at=NOW,
        )


def test_verify_receipt_detects_in_memory_receipt_drift(plan):
    provider = DeterministicFakeAttachmentProvider()
    receipt = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="idem_receipt_drift",
        scenario=FakeAttachmentScenario.COMPLETED,
        observed_at=NOW,
    )
    receipt.error_code = "DRIFTED"
    with pytest.raises(ValueError, match="receipt integrity"):
        verify_attachment_batch_receipt(receipt=receipt, plan=plan)


def test_verify_receipt_rejects_time_before_plan(plan):
    provider = DeterministicFakeAttachmentProvider()
    receipt = provider.submit_batch(
        plan=plan,
        batch_index=0,
        idempotency_key="idem_receipt_time",
        scenario=FakeAttachmentScenario.COMPLETED,
        observed_at=NOW,
    )
    payload = receipt.model_dump()
    payload["observed_at"] = NOW - timedelta(microseconds=1)
    payload["receipt_sha256"] = attachment_receipt_sha256(
        receipt_id=receipt.receipt_id,
        plan_id=receipt.plan_id,
        batch_id=receipt.batch_id,
        batch_index=receipt.batch_index,
        idempotency_key=receipt.idempotency_key,
        status=receipt.status,
        accepted_attachment_ids=receipt.accepted_attachment_ids,
        provider_upload_ids=receipt.provider_upload_ids,
        acceptance_known=receipt.acceptance_known,
        retry_directive=receipt.retry_directive,
        error_code=receipt.error_code,
        observed_at=payload["observed_at"],
    )
    earlier = AttachmentBatchReceipt.model_validate(payload)
    with pytest.raises(ValueError, match="predates"):
        verify_attachment_batch_receipt(receipt=earlier, plan=plan)
