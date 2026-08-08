from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from hashlib import sha256

from pydantic import ValidationError

from .attachment_models import (
    AttachmentBatchPlan,
    AttachmentBatchReceipt,
    AttachmentRetryDirective,
    AttachmentTransferStatus,
    attachment_receipt_sha256,
    normalize_utc_timestamp,
)


class FakeAttachmentScenario(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    REJECTED = "rejected"
    AMBIGUOUS = "ambiguous"


class AttachmentIdempotencyConflictError(RuntimeError):
    pass


class DeterministicFakeAttachmentProvider:
    provider = "chatgpt"
    surface = "deterministic_fake_attachment"

    def __init__(self) -> None:
        self._receipts: dict[str, tuple[str, AttachmentBatchReceipt]] = {}

    def submit_batch(
        self,
        *,
        plan: AttachmentBatchPlan,
        batch_index: int,
        idempotency_key: str,
        scenario: FakeAttachmentScenario,
        observed_at: datetime,
    ) -> AttachmentBatchReceipt:
        observed_at = normalize_utc_timestamp(observed_at)
        _validate_model_integrity(plan, AttachmentBatchPlan, "attachment plan integrity invalid")
        if plan.provider != self.provider or plan.surface != self.surface:
            raise ValueError("attachment plan targets another provider surface")
        if observed_at < plan.planned_at:
            raise ValueError("attachment receipt cannot precede plan creation")
        try:
            batch = plan.batches[batch_index]
        except IndexError as exc:
            raise ValueError("batch_index is outside the attachment plan") from exc
        if batch.batch_index != batch_index:
            raise ValueError("attachment plan batch index is inconsistent")

        payload_digest = _batch_payload_digest(plan=plan, batch_index=batch_index)
        previous = self._receipts.get(idempotency_key)
        if previous is not None:
            previous_digest, receipt = previous
            if previous_digest != payload_digest:
                raise AttachmentIdempotencyConflictError(
                    "idempotency key was already used for another attachment batch"
                )
            return receipt

        accepted_ids: tuple[str, ...]
        acceptance_known: bool
        retry_directive: AttachmentRetryDirective
        status: AttachmentTransferStatus
        error_code: str | None

        if scenario is FakeAttachmentScenario.COMPLETED:
            accepted_ids = batch.attachment_ids
            acceptance_known = True
            retry_directive = AttachmentRetryDirective.DO_NOT_RETRY
            status = AttachmentTransferStatus.COMPLETED
            error_code = None
        elif scenario is FakeAttachmentScenario.PARTIAL:
            accepted_count = max(1, len(batch.attachment_ids) // 2)
            accepted_ids = batch.attachment_ids[:accepted_count]
            acceptance_known = True
            retry_directive = AttachmentRetryDirective.DO_NOT_RETRY
            status = AttachmentTransferStatus.PARTIAL
            error_code = "FAKE_PARTIAL_ACCEPTANCE"
        elif scenario is FakeAttachmentScenario.CANCELLED:
            accepted_ids = ()
            acceptance_known = True
            retry_directive = AttachmentRetryDirective.SAFE_RETRY
            status = AttachmentTransferStatus.CANCELLED
            error_code = "FAKE_CANCELLED_BEFORE_ACCEPTANCE"
        elif scenario is FakeAttachmentScenario.REJECTED:
            accepted_ids = ()
            acceptance_known = True
            retry_directive = AttachmentRetryDirective.DO_NOT_RETRY
            status = AttachmentTransferStatus.REJECTED
            error_code = "FAKE_PROVIDER_REJECTION"
        elif scenario is FakeAttachmentScenario.AMBIGUOUS:
            accepted_ids = ()
            acceptance_known = False
            retry_directive = AttachmentRetryDirective.RECONCILE_REQUIRED
            status = AttachmentTransferStatus.AMBIGUOUS
            error_code = "FAKE_ACCEPTANCE_UNKNOWN"
        else:  # pragma: no cover - enum exhaustiveness
            raise AssertionError(f"unhandled fake attachment scenario: {scenario}")

        provider_upload_ids = tuple(
            _stable_id(
                "fakeupload_",
                plan.plan_sha256,
                batch.batch_id,
                attachment_id,
            )
            for attachment_id in accepted_ids
        )
        receipt_id = _stable_id(
            "attreceipt_",
            plan.plan_sha256,
            batch.batch_id,
            idempotency_key,
        )
        receipt_digest = attachment_receipt_sha256(
            receipt_id=receipt_id,
            plan_id=plan.plan_id,
            batch_id=batch.batch_id,
            batch_index=batch_index,
            idempotency_key=idempotency_key,
            status=status,
            accepted_attachment_ids=accepted_ids,
            provider_upload_ids=provider_upload_ids,
            acceptance_known=acceptance_known,
            retry_directive=retry_directive,
            error_code=error_code,
            observed_at=observed_at,
        )
        receipt = AttachmentBatchReceipt(
            receipt_id=receipt_id,
            plan_id=plan.plan_id,
            batch_id=batch.batch_id,
            batch_index=batch_index,
            idempotency_key=idempotency_key,
            status=status,
            accepted_attachment_ids=accepted_ids,
            provider_upload_ids=provider_upload_ids,
            acceptance_known=acceptance_known,
            retry_directive=retry_directive,
            error_code=error_code,
            observed_at=observed_at,
            receipt_sha256=receipt_digest,
        )
        self._receipts[idempotency_key] = (payload_digest, receipt)
        return receipt



def verify_attachment_batch_receipt(
    *,
    receipt: AttachmentBatchReceipt,
    plan: AttachmentBatchPlan,
) -> None:
    _validate_model_integrity(plan, AttachmentBatchPlan, "attachment plan integrity invalid")
    _validate_model_integrity(
        receipt,
        AttachmentBatchReceipt,
        "attachment receipt integrity invalid",
    )
    if receipt.observed_at < plan.planned_at:
        raise ValueError("attachment receipt predates the attachment plan")
    try:
        batch = plan.batches[receipt.batch_index]
    except IndexError as exc:
        raise ValueError("receipt batch index is outside the attachment plan") from exc
    if receipt.plan_id != plan.plan_id or receipt.batch_id != batch.batch_id:
        raise ValueError("receipt does not belong to the attachment plan batch")
    expected_receipt_id = _stable_id(
        "attreceipt_",
        plan.plan_sha256,
        batch.batch_id,
        receipt.idempotency_key,
    )
    if receipt.receipt_id != expected_receipt_id:
        raise ValueError("receipt identifier is not deterministic")
    accepted = receipt.accepted_attachment_ids
    if any(attachment_id not in batch.attachment_ids for attachment_id in accepted):
        raise ValueError("receipt accepts an attachment outside the batch")
    expected_upload_ids = tuple(
        _stable_id(
            "fakeupload_",
            plan.plan_sha256,
            batch.batch_id,
            attachment_id,
        )
        for attachment_id in accepted
    )
    if receipt.provider_upload_ids != expected_upload_ids:
        raise ValueError("receipt provider upload identifiers are not deterministic")
    if receipt.status is AttachmentTransferStatus.COMPLETED:
        if accepted != batch.attachment_ids:
            raise ValueError("completed receipt must accept the entire batch")
    elif receipt.status is AttachmentTransferStatus.PARTIAL:
        if not accepted or accepted == batch.attachment_ids:
            raise ValueError("partial receipt must accept a non-empty proper prefix")
        if accepted != batch.attachment_ids[: len(accepted)]:
            raise ValueError("partial receipt must accept a stable batch prefix")
    elif receipt.status in (
        AttachmentTransferStatus.CANCELLED,
        AttachmentTransferStatus.REJECTED,
        AttachmentTransferStatus.AMBIGUOUS,
    ):
        if accepted:
            raise ValueError("non-accepting receipt cannot list accepted attachments")



def _validate_model_integrity(model: object, model_type: type, message: str) -> None:
    try:
        model_type.model_validate(model.model_dump(mode="python"))
    except (AttributeError, ValidationError) as exc:
        raise ValueError(message) from exc

def _batch_payload_digest(*, plan: AttachmentBatchPlan, batch_index: int) -> str:
    batch = plan.batches[batch_index]
    digest = sha256(b"systeme-local:fake-attachment-batch-payload:v1\x00")
    for value in (
        plan.plan_sha256,
        batch.batch_id,
        str(batch.batch_index),
        *batch.attachment_ids,
    ):
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _stable_id(prefix: str, *parts: str) -> str:
    digest = sha256(b"systeme-local:fake-attachment-id:v1\x00")
    for part in parts:
        encoded = part.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return prefix + digest.hexdigest()[:24]
