from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from systeme_local_gateway.providers.attachment_models import (
    AttachmentCapabilityProfile,
    AttachmentQuotaRequirement,
    attachment_quota_snapshot_sha256,
    commit_attachment_capability_profile,
)
from systeme_local_gateway.providers.attachment_policy import (
    AttachmentPlanningError,
    AttachmentPlanningReason,
    plan_attachment_batches,
    verify_attachment_batch_plan,
)
from systeme_local_gateway.providers.context_models import (
    ProviderQuotaSnapshot,
    QuotaDimension,
    QuotaState,
    QuotaUnit,
)
from systeme_local_gateway.providers.models import (
    CapabilityClaim,
    CapabilityEvidence,
    CapabilitySupport,
)

from conftest import NOW


def quota(*, account_id="account_main", state=QuotaState.AVAILABLE, age=0):
    evidence = CapabilityEvidence.NONE if state is QuotaState.UNKNOWN else CapabilityEvidence.SIMULATED
    return ProviderQuotaSnapshot(
        snapshot_id="quota_main",
        account_id=account_id,
        dimension=QuotaDimension.FILE_UPLOAD_RATE,
        state=state,
        evidence=evidence,
        observed_at=NOW - timedelta(seconds=age),
        remaining_value=10 if state in (QuotaState.AVAILABLE, QuotaState.NEAR_LIMIT) else None,
        limit_value=20 if state in (QuotaState.AVAILABLE, QuotaState.NEAR_LIMIT) else None,
        unit=QuotaUnit.REQUESTS if state in (QuotaState.AVAILABLE, QuotaState.NEAR_LIMIT) else QuotaUnit.UNKNOWN,
    )



def profile_with(profile, **updates):
    values = {
        "profile_id": profile.profile_id,
        "revision": profile.revision,
        "provider": profile.provider,
        "surface": profile.surface,
        "support": profile.support,
        "supported_media_types": profile.supported_media_types,
        "max_file_bytes": profile.max_file_bytes,
        "max_batch_bytes": profile.max_batch_bytes,
        "max_manifest_bytes": profile.max_manifest_bytes,
        "max_files_per_batch": profile.max_files_per_batch,
        "max_files_per_manifest": profile.max_files_per_manifest,
        "max_batches_per_manifest": profile.max_batches_per_manifest,
        "max_image_width": profile.max_image_width,
        "max_image_height": profile.max_image_height,
        "max_image_pixels": profile.max_image_pixels,
        "allows_mixed_media": profile.allows_mixed_media,
        "quota_requirement": profile.quota_requirement,
        "observed_at": profile.observed_at,
    }
    values.update(updates)
    return commit_attachment_capability_profile(**values)


def test_plan_rejects_profile_from_future(attachment_manifest, attachment_supported_profile):
    profile = profile_with(
        attachment_supported_profile,
        observed_at=NOW + timedelta(seconds=1),
    )
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_future_profile",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=profile,
            planned_at=NOW,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.PROFILE_FROM_FUTURE


def test_plan_ignores_unsolicited_quota_when_profile_requires_none(
    attachment_manifest,
    attachment_supported_profile,
):
    plan = plan_attachment_batches(
        plan_id="plan_no_quota",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW,
        upload_quota=quota(account_id="account_other", age=999),
    )
    assert plan.upload_quota_snapshot_id is None
    assert plan.upload_quota_observed_at is None
    assert plan.upload_quota_sha256 is None


def test_plan_preserves_order_and_splits_by_count(attachment_manifest, attachment_supported_profile):
    plan = plan_attachment_batches(
        plan_id="plan_main",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW,
    )
    assert plan.ordered_attachment_ids == tuple(
        item.attachment_id for item in attachment_manifest.attachments
    )
    assert [batch.attachment_ids for batch in plan.batches] == [
        ("attachment_0", "attachment_1"),
        ("attachment_2",),
    ]
    assert plan.total_bytes == attachment_manifest.total_bytes


def test_plan_canonicalizes_timezone_offsets(attachment_manifest, attachment_supported_profile):
    from datetime import timezone

    plus_two = timezone(timedelta(hours=2))
    plan = plan_attachment_batches(
        plan_id="plan_tz",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW.astimezone(plus_two),
    )
    assert plan.planned_at == NOW


def test_plan_is_deterministic(attachment_manifest, attachment_supported_profile):
    first = plan_attachment_batches(
        plan_id="plan_main",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW,
    )
    second = plan_attachment_batches(
        plan_id="plan_main",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW,
    )
    assert first == second


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        (CapabilitySupport.UNKNOWN, AttachmentPlanningReason.SUPPORT_UNKNOWN),
        (CapabilitySupport.UNSUPPORTED, AttachmentPlanningReason.SUPPORT_UNSUPPORTED),
    ],
)
def test_plan_rejects_non_supported_profiles(attachment_manifest, state, reason):
    profile = commit_attachment_capability_profile(
        profile_id="attachment_profile_unknown",
        revision=1,
        provider="chatgpt",
        surface="surface_unknown",
        support=CapabilityClaim(
            state=state,
            evidence=(
                CapabilityEvidence.NONE
                if state is CapabilitySupport.UNKNOWN
                else CapabilityEvidence.SIMULATED
            ),
        ),
        supported_media_types=(),
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
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_main",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=profile,
            planned_at=NOW,
        )
    assert exc_info.value.reason is reason


def test_plan_rejects_unsupported_media(attachment_manifest, attachment_supported_profile):
    profile = profile_with(
        attachment_supported_profile,
        supported_media_types=(attachment_supported_profile.supported_media_types[0],),
    )
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_main",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=profile,
            planned_at=NOW,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.MEDIA_UNSUPPORTED
    assert exc_info.value.attachment_id == "attachment_1"


def test_plan_rejects_manifest_file_count(attachment_manifest, attachment_supported_profile):
    profile = profile_with(
        attachment_supported_profile,
        max_files_per_manifest=2,
        max_files_per_batch=2,
    )
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_main",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=profile,
            planned_at=NOW,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.TOO_MANY_FILES


def test_plan_rejects_manifest_bytes(attachment_manifest, attachment_supported_profile):
    reduced_manifest_bytes = attachment_manifest.total_bytes - 1
    profile = profile_with(
        attachment_supported_profile,
        max_manifest_bytes=reduced_manifest_bytes,
        max_batch_bytes=min(attachment_supported_profile.max_batch_bytes, reduced_manifest_bytes),
        max_file_bytes=min(attachment_supported_profile.max_file_bytes, reduced_manifest_bytes),
    )
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_main",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=profile,
            planned_at=NOW,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.MANIFEST_TOO_LARGE


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("max_image_width", 9, AttachmentPlanningReason.IMAGE_WIDTH_EXCEEDED),
        ("max_image_height", 19, AttachmentPlanningReason.IMAGE_HEIGHT_EXCEEDED),
        ("max_image_pixels", 199, AttachmentPlanningReason.IMAGE_PIXELS_EXCEEDED),
    ],
)
def test_plan_enforces_image_limits(attachment_manifest, attachment_supported_profile, field, value, reason):
    profile = profile_with(attachment_supported_profile, **{field: value})
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_main",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=profile,
            planned_at=NOW,
        )
    assert exc_info.value.reason is reason
    assert exc_info.value.attachment_id == "attachment_0"


def test_plan_splits_when_mixed_media_is_forbidden(attachment_manifest, attachment_supported_profile):
    profile = profile_with(
        attachment_supported_profile,
        allows_mixed_media=False,
        max_files_per_batch=10,
    )
    plan = plan_attachment_batches(
        plan_id="plan_main",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=profile,
        planned_at=NOW,
    )
    assert [batch.attachment_ids for batch in plan.batches] == [
        ("attachment_0",),
        ("attachment_1", "attachment_2"),
    ]


def test_plan_rejects_too_many_batches(attachment_manifest, attachment_supported_profile):
    profile = profile_with(
        attachment_supported_profile,
        max_files_per_batch=1,
        max_batches_per_manifest=2,
    )
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_main",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=profile,
            planned_at=NOW,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.TOO_MANY_BATCHES


def quota_profile(attachment_supported_profile):
    return profile_with(
        attachment_supported_profile,
        quota_requirement=AttachmentQuotaRequirement.FRESH_UPLOAD_QUOTA,
    )


def test_required_quota_accepts_fresh_available(attachment_manifest, attachment_supported_profile):
    plan = plan_attachment_batches(
        plan_id="plan_main",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=quota_profile(attachment_supported_profile),
        planned_at=NOW,
        upload_quota=quota(),
    )
    assert plan.attachment_count == attachment_manifest.attachment_count


@pytest.mark.parametrize(
    ("snapshot", "planned_at", "reason"),
    [
        (None, NOW, AttachmentPlanningReason.QUOTA_MISSING),
        (quota(account_id="account_other"), NOW, AttachmentPlanningReason.QUOTA_ACCOUNT_MISMATCH),
        (quota(age=301), NOW, AttachmentPlanningReason.QUOTA_STALE),
        (quota(state=QuotaState.UNKNOWN), NOW, AttachmentPlanningReason.QUOTA_UNKNOWN),
        (quota(state=QuotaState.EXHAUSTED), NOW, AttachmentPlanningReason.QUOTA_EXHAUSTED),
        (quota(state=QuotaState.UNAVAILABLE), NOW, AttachmentPlanningReason.QUOTA_UNAVAILABLE),
        (quota(state=QuotaState.RESET_PENDING), NOW, AttachmentPlanningReason.QUOTA_RESET_PENDING),
        (quota(age=-1), NOW, AttachmentPlanningReason.QUOTA_FROM_FUTURE),
    ],
)
def test_required_quota_failures(attachment_manifest, attachment_supported_profile, snapshot, planned_at, reason):
    profile = quota_profile(attachment_supported_profile)
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_main",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=profile,
            planned_at=planned_at,
            upload_quota=snapshot,
        )
    assert exc_info.value.reason is reason


def test_required_quota_rejects_wrong_dimension(attachment_manifest, attachment_supported_profile):
    snapshot = quota().model_copy(update={"dimension": QuotaDimension.FILE_STORAGE})
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_main",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=quota_profile(attachment_supported_profile),
            planned_at=NOW,
            upload_quota=snapshot,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.QUOTA_DIMENSION_MISMATCH


def test_quota_window_must_be_positive(attachment_manifest, attachment_supported_profile):
    with pytest.raises(ValueError, match="must be positive"):
        plan_attachment_batches(
            plan_id="plan_main",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=attachment_supported_profile,
            planned_at=NOW,
            quota_max_age=timedelta(0),
        )


def test_verify_required_quota_plan_requires_same_snapshot(attachment_manifest, attachment_supported_profile):
    profile = quota_profile(attachment_supported_profile)
    snapshot = quota()
    plan = plan_attachment_batches(
        plan_id="plan_quota_verify",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=profile,
        planned_at=NOW,
        upload_quota=snapshot,
    )
    with pytest.raises(AttachmentPlanningError) as exc_info:
        verify_attachment_batch_plan(
            account_id="account_main",
            plan=plan,
            manifest=attachment_manifest,
            profile=profile,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.QUOTA_MISSING

    other = snapshot.model_copy(update={"snapshot_id": "quota_other"})
    with pytest.raises(AttachmentPlanningError) as exc_info:
        verify_attachment_batch_plan(
            account_id="account_main",
            plan=plan,
            manifest=attachment_manifest,
            profile=profile,
            upload_quota=other,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.PLAN_BINDING_MISMATCH

    verify_attachment_batch_plan(
        account_id="account_main",
        plan=plan,
        manifest=attachment_manifest,
        profile=profile,
        upload_quota=snapshot,
    )


def test_verify_plan_accepts_exact_plan(attachment_manifest, attachment_supported_profile):
    plan = plan_attachment_batches(
        plan_id="plan_main",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW,
    )
    verify_attachment_batch_plan(
        account_id="account_main",
        plan=plan,
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
    )


def test_verify_plan_rejects_other_profile(attachment_manifest, attachment_supported_profile):
    plan = plan_attachment_batches(
        plan_id="plan_main",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW,
    )
    other_payload = attachment_supported_profile.model_dump()
    other_payload["profile_id"] = "attachment_profile_other"
    from systeme_local_gateway.providers.attachment_models import (
        attachment_capability_profile_sha256,
    )

    other_payload["profile_sha256"] = attachment_capability_profile_sha256(
        profile_id=other_payload["profile_id"],
        revision=other_payload["revision"],
        provider=other_payload["provider"],
        surface=other_payload["surface"],
        support=attachment_supported_profile.support,
        supported_media_types=attachment_supported_profile.supported_media_types,
        max_file_bytes=other_payload["max_file_bytes"],
        max_batch_bytes=other_payload["max_batch_bytes"],
        max_manifest_bytes=other_payload["max_manifest_bytes"],
        max_files_per_batch=other_payload["max_files_per_batch"],
        max_files_per_manifest=other_payload["max_files_per_manifest"],
        max_batches_per_manifest=other_payload["max_batches_per_manifest"],
        max_image_width=other_payload["max_image_width"],
        max_image_height=other_payload["max_image_height"],
        max_image_pixels=other_payload["max_image_pixels"],
        allows_mixed_media=other_payload["allows_mixed_media"],
        quota_requirement=attachment_supported_profile.quota_requirement,
        observed_at=attachment_supported_profile.observed_at,
    )
    other = AttachmentCapabilityProfile.model_validate(other_payload)
    with pytest.raises(AttachmentPlanningError) as exc_info:
        verify_attachment_batch_plan(
            account_id="account_main",
            plan=plan,
            manifest=attachment_manifest,
            profile=other,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.PLAN_BINDING_MISMATCH


def test_verify_plan_detects_semantic_tampering_with_recomputed_digest(
    attachment_manifest,
    attachment_supported_profile,
):
    from systeme_local_gateway.providers.attachment_models import (
        AttachmentBatchPlan,
        attachment_plan_sha256,
    )

    plan = plan_attachment_batches(
        plan_id="plan_main",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW,
    )
    payload = plan.model_dump()
    payload["batches"][0]["media_families"] = ["document", "image"]
    batch_models = tuple(
        __import__(
            "systeme_local_gateway.providers.attachment_models",
            fromlist=["AttachmentBatch"],
        ).AttachmentBatch.model_validate(batch)
        for batch in payload["batches"]
    )
    payload["plan_sha256"] = attachment_plan_sha256(
        plan_id=plan.plan_id,
        account_id=plan.account_id,
        manifest_id=plan.manifest_id,
        manifest_sha256=plan.manifest_sha256,
        provider=plan.provider,
        surface=plan.surface,
        capability_profile_id=plan.capability_profile_id,
        capability_profile_revision=plan.capability_profile_revision,
        capability_profile_sha256=plan.capability_profile_sha256,
        upload_quota_snapshot_id=plan.upload_quota_snapshot_id,
        upload_quota_observed_at=plan.upload_quota_observed_at,
        upload_quota_sha256=plan.upload_quota_sha256,
        ordered_attachment_ids=plan.ordered_attachment_ids,
        batches=batch_models,
        planned_at=plan.planned_at,
    )
    tampered = AttachmentBatchPlan.model_validate(payload)
    with pytest.raises(AttachmentPlanningError) as exc_info:
        verify_attachment_batch_plan(
            account_id="account_main",
            plan=tampered,
            manifest=attachment_manifest,
            profile=attachment_supported_profile,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.PLAN_CONTENT_MISMATCH


def test_plan_digest_detects_tampering(attachment_manifest, attachment_supported_profile):
    plan = plan_attachment_batches(
        plan_id="plan_main",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW,
    )
    payload = plan.model_dump()
    payload["plan_sha256"] = "0" * 64
    from systeme_local_gateway.providers.attachment_models import AttachmentBatchPlan

    with pytest.raises(ValidationError, match="plan digest mismatch"):
        AttachmentBatchPlan.model_validate(payload)


def test_plan_rejects_time_before_manifest(attachment_manifest, attachment_supported_profile):
    planned_at = NOW - timedelta(seconds=1)
    profile = profile_with(
        attachment_supported_profile,
        observed_at=planned_at - timedelta(seconds=1),
    )
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_before_manifest",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=profile,
            planned_at=planned_at,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.PLAN_BEFORE_MANIFEST


def test_required_quota_is_bound_by_exact_digest(
    attachment_manifest,
    attachment_supported_profile,
):
    snapshot = quota()
    profile = quota_profile(attachment_supported_profile)
    plan = plan_attachment_batches(
        plan_id="plan_quota_digest",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=profile,
        planned_at=NOW,
        upload_quota=snapshot,
    )
    assert plan.upload_quota_sha256 == attachment_quota_snapshot_sha256(snapshot)

    changed = quota(state=QuotaState.NEAR_LIMIT)
    with pytest.raises(AttachmentPlanningError) as exc_info:
        verify_attachment_batch_plan(
            account_id="account_main",
            plan=plan,
            manifest=attachment_manifest,
            profile=profile,
            upload_quota=changed,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.PLAN_BINDING_MISMATCH


def test_verify_plan_rejects_other_account(
    attachment_manifest,
    attachment_supported_profile,
):
    plan = plan_attachment_batches(
        plan_id="plan_account",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW,
    )
    with pytest.raises(AttachmentPlanningError) as exc_info:
        verify_attachment_batch_plan(
            account_id="account_other",
            plan=plan,
            manifest=attachment_manifest,
            profile=attachment_supported_profile,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.PLAN_ACCOUNT_MISMATCH


def test_plan_detects_in_memory_manifest_drift(
    attachment_manifest,
    attachment_supported_profile,
):
    attachment_manifest.total_bytes += 1
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_manifest_drift",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=attachment_supported_profile,
            planned_at=NOW,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.MANIFEST_INTEGRITY_INVALID


def test_plan_detects_in_memory_profile_drift(
    attachment_manifest,
    attachment_supported_profile,
):
    attachment_supported_profile.max_file_bytes -= 1
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_profile_drift",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=attachment_supported_profile,
            planned_at=NOW,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.PROFILE_INTEGRITY_INVALID


def test_plan_detects_invalid_in_memory_quota(
    attachment_manifest,
    attachment_supported_profile,
):
    snapshot = quota()
    snapshot.remaining_value = 999
    with pytest.raises(AttachmentPlanningError) as exc_info:
        plan_attachment_batches(
            plan_id="plan_quota_drift",
            account_id="account_main",
            manifest=attachment_manifest,
            profile=quota_profile(attachment_supported_profile),
            planned_at=NOW,
            upload_quota=snapshot,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.QUOTA_INTEGRITY_INVALID


def test_verify_plan_detects_in_memory_plan_drift(
    attachment_manifest,
    attachment_supported_profile,
):
    plan = plan_attachment_batches(
        plan_id="plan_drift",
        account_id="account_main",
        manifest=attachment_manifest,
        profile=attachment_supported_profile,
        planned_at=NOW,
    )
    plan.total_bytes += 1
    with pytest.raises(AttachmentPlanningError) as exc_info:
        verify_attachment_batch_plan(
            account_id="account_main",
            plan=plan,
            manifest=attachment_manifest,
            profile=attachment_supported_profile,
        )
    assert exc_info.value.reason is AttachmentPlanningReason.PLAN_INTEGRITY_INVALID
