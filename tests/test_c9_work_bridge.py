from __future__ import annotations

import hashlib
import json
import struct
import zlib
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import pytest
from _pytest.tmpdir import TempPathFactory
from pydantic import ValidationError

from systeme_local_gateway.c9_attachment_security import (
    C9AttachmentLease,
    C9AttachmentSecurity,
    C9BoundApproval,
    C9OutboundManifest,
    C9OutboundSurface,
)
from systeme_local_gateway.c9_work_bridge import (
    C9CapabilityEvidence,
    C9McpContentType,
    C9McpExpansionDescriptor,
    C9McpHostCapabilities,
    C9OneWorkTaskSession,
    C9RichSurface,
    C9WorkBridgeError,
    C9WorkBridgeReason,
    build_mcp_expansion_descriptor,
    classify_chat_delivery,
    classify_native_chat_delivery,
    commit_mcp_host_capabilities,
    evaluate_work_bridge,
    promote_mcp_host_capabilities_after_live_proof,
)

from conftest import NOW, png_chunk

ACCEPTED_C8_COMMIT = "e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"
C9_CYCLE_ID = "c9_cycle_" + "a" * 32
C9_GRANT_ID = "c9_grant_" + "b" * 32
WORK_TASK_ID = "c9_work_" + "c" * 32
DESCRIPTOR_ID = "c9_delivery_" + "e" * 32
IMAGE_NONCE = "c9-image-proof-3f7d"
DOCUMENT_NONCE = "c9-document-proof-91ac"


@dataclass(frozen=True)
class _Transfer:
    store: C9AttachmentSecurity
    leases: tuple[C9AttachmentLease, C9AttachmentLease]
    manifest: C9OutboundManifest
    approval: C9BoundApproval


def _valid_png() -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00\xff")
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", pixels)
        + png_chunk(b"IEND", b"")
    )


@pytest.fixture(scope="module")
def transfer(tmp_path_factory: TempPathFactory) -> _Transfer:
    tmp_path: Path = tmp_path_factory.mktemp("c9-work-bridge")
    image_path = tmp_path / "c9-proof.png"
    document_path = tmp_path / "c9-proof.txt"
    image_path.write_bytes(_valid_png())
    document_path.write_text(
        f"Bound proof nonces: {IMAGE_NONCE} and {DOCUMENT_NONCE}.\n",
        encoding="utf-8",
    )
    store = C9AttachmentSecurity()
    leases = (
        store.select_file(
            image_path,
            operator_confirmed=True,
            selected_at=NOW,
        ),
        store.select_file(
            document_path,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )
    manifest = store.create_outbound_manifest(
        tuple(item.lease_id for item in leases),
        surface=C9OutboundSurface.CHATGPT_WORK,
        purpose="C9 one-task rich MCP Work proof",
        created_at=NOW + timedelta(seconds=1),
    )
    approval = store.approve_manifest(
        manifest,
        operator_confirmed=True,
        operator_identity="c9-test-operator",
        approved_at=NOW + timedelta(seconds=2),
        approval_ttl=timedelta(minutes=3),
    )
    return _Transfer(
        store=store,
        leases=leases,
        manifest=manifest,
        approval=approval,
    )


def _capabilities(
    *,
    surface: C9RichSurface = C9RichSurface.WORK,
    result: C9CapabilityEvidence = (C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED),
    image: C9CapabilityEvidence = (C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED),
    document: C9CapabilityEvidence = (C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED),
    upload_file: bool = False,
    image_ids: bool = False,
) -> C9McpHostCapabilities:
    return commit_mcp_host_capabilities(
        surface=surface,
        call_tool_result_content=result,
        image_content=image,
        embedded_text_resource=document,
        window_openai_upload_file_available=upload_file,
        window_openai_image_ids_available=image_ids,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


def _proof_hashes(transfer: _Transfer) -> dict[str, str]:
    return {
        transfer.manifest.attachments[0].attachment_id: hashlib.sha256(
            IMAGE_NONCE.encode()
        ).hexdigest(),
        transfer.manifest.attachments[1].attachment_id: hashlib.sha256(
            DOCUMENT_NONCE.encode()
        ).hexdigest(),
    }


def _descriptor(
    transfer: _Transfer,
    *,
    capabilities: C9McpHostCapabilities | None = None,
) -> C9McpExpansionDescriptor:
    return build_mcp_expansion_descriptor(
        descriptor_id=DESCRIPTOR_ID,
        accepted_c8_commit=ACCEPTED_C8_COMMIT,
        c9_cycle_id=C9_CYCLE_ID,
        c9_grant_id=C9_GRANT_ID,
        work_task_id=WORK_TASK_ID,
        capabilities=capabilities or _capabilities(upload_file=True, image_ids=True),
        manifest=transfer.manifest,
        approval=transfer.approval,
        leases=transfer.leases,
        proof_nonce_sha256s=_proof_hashes(transfer),
        created_at=NOW + timedelta(seconds=3),
    )


def _staged_session(
    transfer: _Transfer,
    descriptor: C9McpExpansionDescriptor,
) -> C9OneWorkTaskSession:
    session = C9OneWorkTaskSession(work_task_id=WORK_TASK_ID)
    session.stage(
        descriptor=descriptor,
        manifest=transfer.manifest,
        approval=transfer.approval,
        leases=transfer.leases,
        staged_at=NOW + timedelta(seconds=4),
    )
    return session


def _observed_nonces(transfer: _Transfer) -> dict[str, str]:
    return {
        transfer.manifest.attachments[0].attachment_id: IMAGE_NONCE,
        transfer.manifest.attachments[1].attachment_id: DOCUMENT_NONCE,
    }


def test_descriptor_uses_authoritative_security_models_and_is_metadata_only(
    transfer: _Transfer,
) -> None:
    descriptor = _descriptor(transfer)

    assert tuple(item.mcp_content_type for item in descriptor.items) == (
        C9McpContentType.IMAGE_CONTENT,
        C9McpContentType.EMBEDDED_TEXT_RESOURCE,
    )
    assert descriptor.items[0].embedded_resource_uri is None
    assert descriptor.items[1].embedded_resource_uri == (
        "systeme-local://c9/"
        + descriptor.items[1].lease_id
        + "/"
        + descriptor.items[1].attachment_id
    )
    assert all(len(item.lease_id.removeprefix("c9_lease_")) == 64 for item in descriptor.items)
    assert descriptor.approval_id == transfer.approval.approval_id
    assert descriptor.approval_sha256 == transfer.approval.approval_sha256
    assert descriptor.manifest_id == transfer.manifest.manifest_id
    assert descriptor.manifest_sha256 == transfer.manifest.manifest_sha256
    assert descriptor.widget_upload_file_used is False
    assert descriptor.widget_image_ids_used is False
    assert descriptor.preflight_rich_probe_used is False
    assert descriptor.manual_fallback_used is False
    assert descriptor.surface is C9RichSurface.WORK
    assert descriptor.surface_task_id == WORK_TASK_ID

    serialized = descriptor.model_dump(mode="json")
    forbidden_keys = {
        "data",
        "blob",
        "text",
        "bytes",
        "path",
        "download_url",
        "file_id",
        "authorization",
        "cookie",
        "source_content_sha256",
        "source_byte_size",
    }

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                assert key not in forbidden_keys
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(serialized)
    encoded = json.dumps(serialized)
    assert IMAGE_NONCE not in encoded
    assert DOCUMENT_NONCE not in encoded


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("result", C9WorkBridgeReason.CALL_TOOL_RESULT_CONTENT_UNPROVEN),
        ("image", C9WorkBridgeReason.IMAGE_CONTENT_UNPROVEN),
        ("document", C9WorkBridgeReason.EMBEDDED_TEXT_RESOURCE_UNPROVEN),
    ],
)
def test_bridge_fails_closed_when_documented_local_support_is_missing(
    field: str,
    reason: C9WorkBridgeReason,
    transfer: _Transfer,
) -> None:
    values = {
        "result": C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED,
        "image": C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED,
        "document": C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED,
    }
    values[field] = C9CapabilityEvidence.DOCUMENTED_ONLY
    decision = evaluate_work_bridge(
        capabilities=_capabilities(
            result=values["result"],
            image=values["image"],
            document=values["document"],
        ),
        manifest=transfer.manifest,
        approval=transfer.approval,
        accepted_c8_commit=ACCEPTED_C8_COMMIT,
        c9_cycle_id=C9_CYCLE_ID,
        c9_grant_id=C9_GRANT_ID,
        work_task_id=WORK_TASK_ID,
        evaluated_at=NOW + timedelta(seconds=3),
    )

    assert decision.allowed is False
    assert decision.reason is reason
    assert decision.widget_file_api_used is False
    assert decision.preflight_rich_probe_used is False


def test_widget_file_features_do_not_substitute_for_standard_mcp_content(
    transfer: _Transfer,
) -> None:
    capabilities = _capabilities(
        result=C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED,
        image=C9CapabilityEvidence.DOCUMENTED_ONLY,
        document=C9CapabilityEvidence.DOCUMENTED_ONLY,
        upload_file=True,
        image_ids=True,
    )
    with pytest.raises(C9WorkBridgeError) as caught:
        _descriptor(transfer, capabilities=capabilities)
    assert caught.value.reason is C9WorkBridgeReason.IMAGE_CONTENT_UNPROVEN


def test_stale_capability_observation_denies_transfer(transfer: _Transfer) -> None:
    decision = evaluate_work_bridge(
        capabilities=_capabilities(),
        manifest=transfer.manifest,
        approval=transfer.approval,
        accepted_c8_commit=ACCEPTED_C8_COMMIT,
        c9_cycle_id=C9_CYCLE_ID,
        c9_grant_id=C9_GRANT_ID,
        work_task_id=WORK_TASK_ID,
        evaluated_at=NOW + timedelta(minutes=6),
    )
    assert decision.reason is C9WorkBridgeReason.CAPABILITY_OBSERVATION_STALE
    assert decision.allowed is False


def test_authoritative_approval_must_bind_exact_manifest(transfer: _Transfer) -> None:
    second_manifest = transfer.store.create_outbound_manifest(
        tuple(item.lease_id for item in transfer.leases),
        surface=C9OutboundSurface.CHATGPT_WORK,
        purpose="different exact manifest",
        created_at=NOW + timedelta(seconds=1),
    )
    second_approval = transfer.store.approve_manifest(
        second_manifest,
        operator_confirmed=True,
        operator_identity="c9-test-operator",
        approved_at=NOW + timedelta(seconds=2),
    )
    decision = evaluate_work_bridge(
        capabilities=_capabilities(),
        manifest=transfer.manifest,
        approval=second_approval,
        accepted_c8_commit=ACCEPTED_C8_COMMIT,
        c9_cycle_id=C9_CYCLE_ID,
        c9_grant_id=C9_GRANT_ID,
        work_task_id=WORK_TASK_ID,
        evaluated_at=NOW + timedelta(seconds=3),
    )
    assert decision.allowed is False
    assert decision.reason is C9WorkBridgeReason.APPROVAL_FILE_SET_MISMATCH


def test_work_bridge_requires_exactly_one_image_and_one_text(
    transfer: _Transfer,
) -> None:
    image_only_manifest = transfer.store.create_outbound_manifest(
        (transfer.leases[0].lease_id,),
        surface=C9OutboundSurface.CHATGPT_WORK,
        purpose="unsupported image-only set",
        created_at=NOW + timedelta(seconds=1),
    )
    image_only_approval = transfer.store.approve_manifest(
        image_only_manifest,
        operator_confirmed=True,
        operator_identity="c9-test-operator",
        approved_at=NOW + timedelta(seconds=2),
    )
    decision = evaluate_work_bridge(
        capabilities=_capabilities(),
        manifest=image_only_manifest,
        approval=image_only_approval,
        accepted_c8_commit=ACCEPTED_C8_COMMIT,
        c9_cycle_id=C9_CYCLE_ID,
        c9_grant_id=C9_GRANT_ID,
        work_task_id=WORK_TASK_ID,
        evaluated_at=NOW + timedelta(seconds=3),
    )
    assert decision.allowed is False
    assert decision.reason is C9WorkBridgeReason.UNSUPPORTED_ATTACHMENT_SET


def test_manual_chat_manifest_cannot_enter_work_bridge(transfer: _Transfer) -> None:
    manual_manifest = transfer.store.create_outbound_manifest(
        tuple(item.lease_id for item in transfer.leases),
        surface=C9OutboundSurface.CHATGPT_CHAT_MANUAL,
        purpose="manual Chat attachment only",
        created_at=NOW + timedelta(seconds=1),
    )
    manual_approval = transfer.store.approve_manifest(
        manual_manifest,
        operator_confirmed=True,
        operator_identity="c9-test-operator",
        approved_at=NOW + timedelta(seconds=2),
    )
    decision = evaluate_work_bridge(
        capabilities=_capabilities(),
        manifest=manual_manifest,
        approval=manual_approval,
        accepted_c8_commit=ACCEPTED_C8_COMMIT,
        c9_cycle_id=C9_CYCLE_ID,
        c9_grant_id=C9_GRANT_ID,
        work_task_id=WORK_TASK_ID,
        evaluated_at=NOW + timedelta(seconds=3),
    )
    assert decision.allowed is False
    assert decision.reason is C9WorkBridgeReason.MANIFEST_NOT_WORK


def test_descriptor_rejects_lease_or_nonce_set_mismatch(transfer: _Transfer) -> None:
    with pytest.raises(C9WorkBridgeError) as lease_error:
        build_mcp_expansion_descriptor(
            descriptor_id=DESCRIPTOR_ID,
            accepted_c8_commit=ACCEPTED_C8_COMMIT,
            c9_cycle_id=C9_CYCLE_ID,
            c9_grant_id=C9_GRANT_ID,
            work_task_id=WORK_TASK_ID,
            capabilities=_capabilities(),
            manifest=transfer.manifest,
            approval=transfer.approval,
            leases=(transfer.leases[1], transfer.leases[0]),
            proof_nonce_sha256s=_proof_hashes(transfer),
            created_at=NOW + timedelta(seconds=3),
        )
    assert lease_error.value.reason is C9WorkBridgeReason.LEASE_SET_MISMATCH

    with pytest.raises(C9WorkBridgeError) as nonce_error:
        build_mcp_expansion_descriptor(
            descriptor_id=DESCRIPTOR_ID,
            accepted_c8_commit=ACCEPTED_C8_COMMIT,
            c9_cycle_id=C9_CYCLE_ID,
            c9_grant_id=C9_GRANT_ID,
            work_task_id=WORK_TASK_ID,
            capabilities=_capabilities(),
            manifest=transfer.manifest,
            approval=transfer.approval,
            leases=transfer.leases,
            proof_nonce_sha256s={transfer.manifest.attachments[0].attachment_id: "1" * 64},
            created_at=NOW + timedelta(seconds=3),
        )
    assert nonce_error.value.reason is C9WorkBridgeReason.RESPONSE_FILE_SET_MISMATCH


def test_authoritative_and_descriptor_digest_tampering_is_rejected(
    transfer: _Transfer,
) -> None:
    tampered_approval = transfer.approval.model_copy(update={"manifest_sha256": "9" * 64})
    with pytest.raises(C9WorkBridgeError) as authoritative_error:
        evaluate_work_bridge(
            capabilities=_capabilities(),
            manifest=transfer.manifest,
            approval=tampered_approval,
            accepted_c8_commit=ACCEPTED_C8_COMMIT,
            c9_cycle_id=C9_CYCLE_ID,
            c9_grant_id=C9_GRANT_ID,
            work_task_id=WORK_TASK_ID,
            evaluated_at=NOW + timedelta(seconds=3),
        )
    assert authoritative_error.value.reason is C9WorkBridgeReason.APPROVAL_FILE_SET_MISMATCH

    descriptor = _descriptor(transfer)
    with pytest.raises(ValidationError, match="descriptor digest"):
        C9McpExpansionDescriptor.model_validate(
            {**descriptor.model_dump(mode="json"), "manifest_sha256": "8" * 64}
        )


def test_capability_observation_forbids_unknown_fields() -> None:
    capability = _capabilities()
    with pytest.raises(ValidationError):
        C9McpHostCapabilities.model_validate(
            {**capability.model_dump(mode="json"), "invented_file_reference": True}
        )


def test_first_and_only_work_call_promotes_local_support_to_runtime_observed(
    transfer: _Transfer,
) -> None:
    initial = _capabilities()
    decision = evaluate_work_bridge(
        capabilities=initial,
        manifest=transfer.manifest,
        approval=transfer.approval,
        accepted_c8_commit=ACCEPTED_C8_COMMIT,
        c9_cycle_id=C9_CYCLE_ID,
        c9_grant_id=C9_GRANT_ID,
        work_task_id=WORK_TASK_ID,
        evaluated_at=NOW + timedelta(seconds=3),
    )
    assert decision.allowed is True
    assert decision.preflight_rich_probe_used is False

    descriptor = _descriptor(transfer, capabilities=initial)
    assert descriptor.preflight_rich_probe_used is False
    session = _staged_session(transfer, descriptor)
    receipt = session.verify_and_consume(
        work_task_id=WORK_TASK_ID,
        descriptor_sha256=descriptor.descriptor_sha256,
        observed_nonces=_observed_nonces(transfer),
        response_text=f"Observed {IMAGE_NONCE} and {DOCUMENT_NONCE}.",
        observed_at=NOW + timedelta(seconds=5),
    )
    promoted = promote_mcp_host_capabilities_after_live_proof(
        capabilities=initial,
        receipt=receipt,
        promoted_at=NOW + timedelta(seconds=6),
        expires_at=NOW + timedelta(minutes=5),
    )

    assert promoted.call_tool_result_content is (
        C9CapabilityEvidence.DOCUMENTED_AND_RUNTIME_OBSERVED
    )
    assert promoted.image_content is C9CapabilityEvidence.DOCUMENTED_AND_RUNTIME_OBSERVED
    assert promoted.embedded_text_resource is (C9CapabilityEvidence.DOCUMENTED_AND_RUNTIME_OBSERVED)
    assert promoted.runtime_proof_receipt_sha256 == receipt.receipt_sha256
    with pytest.raises(C9WorkBridgeError) as replay:
        session.verify_and_consume(
            work_task_id=WORK_TASK_ID,
            descriptor_sha256=descriptor.descriptor_sha256,
            observed_nonces=_observed_nonces(transfer),
            response_text=f"Observed {IMAGE_NONCE} and {DOCUMENT_NONCE}.",
            observed_at=NOW + timedelta(seconds=7),
        )
    assert replay.value.reason is C9WorkBridgeReason.REPLAY_REJECTED


def test_nonce_receipt_does_not_persist_raw_nonce_values(transfer: _Transfer) -> None:
    descriptor = _descriptor(transfer)
    receipt = _staged_session(transfer, descriptor).verify_and_consume(
        work_task_id=WORK_TASK_ID,
        descriptor_sha256=descriptor.descriptor_sha256,
        observed_nonces=_observed_nonces(transfer),
        response_text=f"Observed {IMAGE_NONCE} and {DOCUMENT_NONCE}.",
        observed_at=NOW + timedelta(seconds=5),
    )

    assert receipt.status == "work_attachments_visibly_consumed"
    assert receipt.verified_attachment_ids == tuple(
        item.attachment_id for item in transfer.manifest.attachments
    )
    serialized = json.dumps(receipt.model_dump(mode="json"))
    assert IMAGE_NONCE not in serialized
    assert DOCUMENT_NONCE not in serialized


def test_staging_replay_and_cross_task_are_rejected(transfer: _Transfer) -> None:
    descriptor = _descriptor(transfer)
    session = _staged_session(transfer, descriptor)
    with pytest.raises(C9WorkBridgeError) as replay:
        session.stage(
            descriptor=descriptor,
            manifest=transfer.manifest,
            approval=transfer.approval,
            leases=transfer.leases,
            staged_at=NOW + timedelta(seconds=4),
        )
    assert replay.value.reason is C9WorkBridgeReason.REPLAY_REJECTED

    with pytest.raises(C9WorkBridgeError) as cross_task:
        session.verify_and_consume(
            work_task_id="c9_work_" + "f" * 32,
            descriptor_sha256=descriptor.descriptor_sha256,
            observed_nonces={},
            response_text="no",
            observed_at=NOW + timedelta(seconds=5),
        )
    assert cross_task.value.reason is C9WorkBridgeReason.CROSS_TASK_REJECTED


def test_wrong_partial_or_invisible_nonce_proof_fails_closed(
    transfer: _Transfer,
) -> None:
    descriptor = _descriptor(transfer)
    session = _staged_session(transfer, descriptor)
    with pytest.raises(C9WorkBridgeError) as partial:
        session.verify_and_consume(
            work_task_id=WORK_TASK_ID,
            descriptor_sha256=descriptor.descriptor_sha256,
            observed_nonces={transfer.manifest.attachments[0].attachment_id: IMAGE_NONCE},
            response_text="partial",
            observed_at=NOW + timedelta(seconds=5),
        )
    assert partial.value.reason is C9WorkBridgeReason.RESPONSE_FILE_SET_MISMATCH

    with pytest.raises(C9WorkBridgeError) as wrong:
        session.verify_and_consume(
            work_task_id=WORK_TASK_ID,
            descriptor_sha256=descriptor.descriptor_sha256,
            observed_nonces={
                transfer.manifest.attachments[0].attachment_id: IMAGE_NONCE,
                transfer.manifest.attachments[1].attachment_id: "wrong-document-proof",
            },
            response_text="wrong",
            observed_at=NOW + timedelta(seconds=5),
        )
    assert wrong.value.reason is C9WorkBridgeReason.NONCE_PROOF_INVALID

    with pytest.raises(C9WorkBridgeError) as invisible:
        session.verify_and_consume(
            work_task_id=WORK_TASK_ID,
            descriptor_sha256=descriptor.descriptor_sha256,
            observed_nonces=_observed_nonces(transfer),
            response_text="I consumed both attachments.",
            observed_at=NOW + timedelta(seconds=5),
        )
    assert invisible.value.reason is C9WorkBridgeReason.NONCE_PROOF_INVALID


def test_response_after_authoritative_expiry_is_rejected(transfer: _Transfer) -> None:
    descriptor = _descriptor(transfer)
    session = _staged_session(transfer, descriptor)
    with pytest.raises(C9WorkBridgeError) as caught:
        session.verify_and_consume(
            work_task_id=WORK_TASK_ID,
            descriptor_sha256=descriptor.descriptor_sha256,
            observed_nonces=_observed_nonces(transfer),
            response_text=f"Observed {IMAGE_NONCE} and {DOCUMENT_NONCE}.",
            observed_at=NOW + timedelta(minutes=4),
        )
    assert caught.value.reason is C9WorkBridgeReason.APPROVAL_EXPIRED


def test_native_chat_is_manual_and_qualifying_without_mcp_claims() -> None:
    delivery = classify_chat_delivery()
    assert delivery == classify_native_chat_delivery()
    assert delivery.delivery_mode == "operator_performed_manual_attachment_handoff"
    assert delivery.custom_mcp_app_invoked is False
    assert delivery.manual_attachment_handoff_allowed is True
    assert delivery.primary_c9_success_eligible is True
    assert delivery.reason == "OFFICIAL_NATIVE_CHAT_MANUAL_ATTACHMENT_HANDOFF"


def test_chat_mcp_capability_and_bridge_are_fail_closed(
    transfer: _Transfer,
) -> None:
    with pytest.raises(ValueError, match="Work-only"):
        _capabilities(surface=C9RichSurface.CHAT)

    with pytest.raises(C9WorkBridgeError) as bridge_error:
        evaluate_work_bridge(
            capabilities=_capabilities(),
            manifest=transfer.manifest,
            approval=transfer.approval,
            accepted_c8_commit=ACCEPTED_C8_COMMIT,
            c9_cycle_id=C9_CYCLE_ID,
            c9_grant_id=C9_GRANT_ID,
            surface=C9RichSurface.CHAT,
            surface_task_id="c9_chat_" + "d" * 32,
            evaluated_at=NOW + timedelta(seconds=4),
        )
    assert bridge_error.value.reason is C9WorkBridgeReason.CHAT_MCP_UNSUPPORTED

    with pytest.raises(C9WorkBridgeError) as descriptor_error:
        build_mcp_expansion_descriptor(
            descriptor_id="c9_delivery_" + "f" * 32,
            accepted_c8_commit=ACCEPTED_C8_COMMIT,
            c9_cycle_id=C9_CYCLE_ID,
            c9_grant_id=C9_GRANT_ID,
            surface=C9RichSurface.CHAT,
            surface_task_id="c9_chat_" + "d" * 32,
            capabilities=_capabilities(),
            manifest=transfer.manifest,
            approval=transfer.approval,
            leases=transfer.leases,
            proof_nonce_sha256s=_proof_hashes(transfer),
            created_at=NOW + timedelta(seconds=4),
        )
    assert descriptor_error.value.reason is C9WorkBridgeReason.CHAT_MCP_UNSUPPORTED
