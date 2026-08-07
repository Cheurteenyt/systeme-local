from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import ValidationError
from pydantic_core import to_jsonable_python

from systeme_local_gateway import c9_attestation, c9_live_cycle
from systeme_local_gateway.audit import AuditLog
from systeme_local_gateway.c9_attestation import (
    C9_FINAL_STATUS,
    C9_NEGATIVE_SUITE_NODEIDS,
    C9AutomatedNegativeSuiteEvidence,
    C9FinalAttestation,
    C9NegativeCheckId,
    C9NegativeOutcome,
    C9NegativeTestReceipt,
    C9RevocationReceipt,
    C9RichAuditCorrelationReceipt,
    canonical_sha256,
    commit_final_attestation,
    commit_negative_test_receipt,
    commit_revocation_receipt,
    commit_rich_audit_correlation_receipt,
    verify_final_attestation,
    verify_negative_test_receipt,
    verify_revocation_receipt,
    verify_rich_audit_correlation_receipt,
)
from systeme_local_gateway.c9_handoff_runtime import (
    C9ChatConfirmationReceipt,
    C9ChatExportDescriptor,
    C9ChatPickerClaimReceipt,
    C9CombinedApproval,
    C9CoordinatorCloseReceipt,
    C9HandoffAdmission,
    C9HandoffStageReceipt,
    C9StagedAttachment,
    C9RichExecutionDescriptor,
)
from systeme_local_gateway.c9_live_cycle import (
    C9AdmissionDecision,
    C9AdmissionReason,
    C9AdmissionStatus,
    C9LiveCycleBundle,
    C9LiveCycleGrant,
    commit_c9_operator_authorization,
    commit_c9_surface_observation,
)
from systeme_local_gateway.c9_local_ai import (
    C9LocalAIProviderKind,
    C9LocalAIRuntimeObservation,
    c9_local_ai_runtime_observation_sha256,
    commit_c9_local_ai_runtime_observation,
)
from systeme_local_gateway.c9_synthetic_fixtures import C9SyntheticFixtureKind
from systeme_local_gateway.c9_work_bridge import C9RichConsumptionReceipt, C9RichSurface
from systeme_local_gateway.providers.attachment_models import AttachmentMediaType

AUDIT_KEY = "c9-attestation-test-audit-key-000000000000"
OTHER_AUDIT_KEY = "other-c9-attestation-audit-key-00000000"
START = datetime(2026, 7, 28, 8, 0, tzinfo=UTC)
CYCLE_ID = "c9_cycle_" + "1" * 32
GRANT_ID = "c9_grant_" + "2" * 32
HANDOFF_ID = "c9_handoff_" + "3" * 32
WORK_TASK_ID = "c9_work_" + "4" * 32
CHAT_TASK_ID = "c9_chat_" + "e" * 32
C8_TAG_TARGET = "5" * 40
C8_COVERED_HEAD = "6" * 40
C8_TREE_SHA256 = "7" * 64
C8_FINAL_SHA256 = "8" * 64
C9_HEAD = "9" * 40
REVOCATION_CONFIRMATIONS = {
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
}


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        to_jsonable_python(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _domain_sha(domain: bytes, payload: dict[str, Any]) -> str:
    return hashlib.sha256(domain + _canonical_json(payload)).hexdigest()


def _external_hmac(domain: bytes, payload: dict[str, Any]) -> str:
    return hmac.new(
        AUDIT_KEY.encode("utf-8"),
        domain + _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


def _required_outcomes() -> dict[C9NegativeCheckId, C9NegativeOutcome]:
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
        C9NegativeCheckId.AUTHENTICATED_LOCAL_AI_REQUEST: (C9NegativeOutcome.DENIED),
        C9NegativeCheckId.COMMAND_EXECUTION_REQUEST: (C9NegativeOutcome.CAPABILITY_NOT_EXPOSED),
        C9NegativeCheckId.SECRET_REQUEST: C9NegativeOutcome.CAPABILITY_NOT_EXPOSED,
        C9NegativeCheckId.WRITE_OPERATION_REQUEST: (C9NegativeOutcome.CAPABILITY_NOT_EXPOSED),
        C9NegativeCheckId.REAL_EVIDENCE_REQUEST: (C9NegativeOutcome.CAPABILITY_NOT_EXPOSED),
        C9NegativeCheckId.PROTOCOL_V2_REQUEST: (C9NegativeOutcome.CAPABILITY_NOT_EXPOSED),
    }


def _automated_negative_evidence(
    *,
    repository_head: str = C9_HEAD,
) -> C9AutomatedNegativeSuiteEvidence:
    source_paths = sorted({node_id.split("::", 1)[0] for node_id in C9_NEGATIVE_SUITE_NODEIDS})
    return C9AutomatedNegativeSuiteEvidence(
        source="isolated_pytest_subprocess",
        simulated=False,
        suite_id="c9_bounded_negative_contract_v1",
        repository_head=repository_head,
        node_ids=C9_NEGATIVE_SUITE_NODEIDS,
        evidence_node_ids=c9_attestation._required_negative_evidence(),
        selection_sha256=canonical_sha256(list(C9_NEGATIVE_SUITE_NODEIDS)),
        source_sha256s={path: _sha(path) for path in source_paths},
        output_sha256=_sha("automated-negative-output"),
        exit_code=0,
        passed_count=len(C9_NEGATIVE_SUITE_NODEIDS) + 4,
        failed_count=0,
        skipped_count=0,
        warning_count=0,
    )


def _commit_runtime_model(
    model_type: type[Any],
    *,
    payload: dict[str, Any],
    digest_field: str,
    domain: bytes,
) -> Any:
    return model_type(
        **payload,
        **{digest_field: _domain_sha(domain, payload)},
    )


def _fixture_evidence() -> tuple[
    C9HandoffStageReceipt,
    C9HandoffAdmission,
    C9RichConsumptionReceipt,
    C9RichAuditCorrelationReceipt,
    C9ChatExportDescriptor,
    C9ChatPickerClaimReceipt,
    C9ChatConfirmationReceipt,
    C9CoordinatorCloseReceipt,
    C9NegativeTestReceipt,
    C9RevocationReceipt,
]:
    work_manifest_sha256 = _sha("work-manifest")
    chat_manifest_sha256 = _sha("chat-manifest")
    fixture_receipt_sha256 = _sha("fixture-receipt")
    local_ai_receipt_sha256 = _sha("local-ai-receipt")
    runtime_observation = commit_c9_local_ai_runtime_observation(
        cycle_id=CYCLE_ID,
        provider_kind=C9LocalAIProviderKind.OTHER_REVIEWED_NATIVE,
        product_name="Reviewed test-native runtime",
        product_version="1.0",
        listening_pid=os.getpid(),
        executable_path=Path(sys.executable).resolve(),
        endpoint="http://127.0.0.1:11434/v1/chat/completions",
        visible_model_label="reviewed-test-model",
        runtime_request_logging_disabled=True,
        runtime_request_persistence_disabled=True,
        operator_confirmed_native_runtime=True,
        operator_confirmed_runtime_privacy_settings=True,
        observed_at=START - timedelta(minutes=1),
        expires_at=START + timedelta(minutes=10),
        audit_key=AUDIT_KEY,
    )
    runtime_observation_sha256 = c9_local_ai_runtime_observation_sha256(runtime_observation)
    image_nonce_sha256 = _sha("image-nonce")
    document_nonce_sha256 = _sha("document-nonce")
    image_attachment_id = "c9_attachment_" + "a" * 32
    document_attachment_id = "c9_attachment_" + "b" * 32

    stage_payload: dict[str, Any] = {
        "version": "1",
        "handoff_id": HANDOFF_ID,
        "work_task_id": WORK_TASK_ID,
        "chat_task_id": CHAT_TASK_ID,
        "fixture_package_id": "c9_fixture_package_" + "c" * 32,
        "fixture_receipt_sha256": fixture_receipt_sha256,
        "work_manifest_sha256": work_manifest_sha256,
        "chat_manifest_sha256": chat_manifest_sha256,
        "local_ai_receipt_sha256": local_ai_receipt_sha256,
        "local_ai_runtime_observation_sha256": (runtime_observation_sha256),
        "attachments": (
            C9StagedAttachment(
                attachment_id=image_attachment_id,
                kind=C9SyntheticFixtureKind.IMAGE,
                media_type=AttachmentMediaType.PNG,
                content_sha256=_sha("image-content"),
                nonce_sha256=image_nonce_sha256,
                descriptor_sha256=_sha("image-descriptor"),
            ),
            C9StagedAttachment(
                attachment_id=document_attachment_id,
                kind=C9SyntheticFixtureKind.TEXT,
                media_type=AttachmentMediaType.TEXT,
                content_sha256=_sha("document-content"),
                nonce_sha256=document_nonce_sha256,
                descriptor_sha256=_sha("document-descriptor"),
            ),
        ),
        "staged_at": START,
        "expires_at": START + timedelta(minutes=10),
    }
    stage = _commit_runtime_model(
        C9HandoffStageReceipt,
        payload=stage_payload,
        digest_field="stage_sha256",
        domain=b"systeme-local/c9/handoff-stage/v1\0",
    )

    authorization = commit_c9_operator_authorization(
        cycle_id=CYCLE_ID,
        selected_package_manifest_sha256=work_manifest_sha256,
        image_media_type="image/png",
        authorized_at=START,
        expires_at=START + timedelta(hours=1),
        audit_key=AUDIT_KEY,
    )
    surface = commit_c9_surface_observation(
        cycle_id=CYCLE_ID,
        observed_at=START,
        expires_at=START + timedelta(minutes=10),
        audit_key=AUDIT_KEY,
    )
    c8_dependency_payload = {
        "version": "1",
        "status": "verified",
        "tag_target": C8_TAG_TARGET,
        "covered_head": C8_COVERED_HEAD,
        "current_head": C9_HEAD,
        "tree_sha256": C8_TREE_SHA256,
        "final_attestation_sha256": C8_FINAL_SHA256,
        "reviewed_outcome": "COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED",
        "work_call_count": 2,
        "revocation_verified": True,
        "tag_target_ancestor_of_head": True,
    }
    grant_payload: dict[str, Any] = {
        "version": "1",
        "grant_id": GRANT_ID,
        "cycle_id": CYCLE_ID,
        "authorization_sha256": canonical_sha256(authorization.model_dump(mode="json")),
        "surface_observation_sha256": canonical_sha256(surface.model_dump(mode="json")),
        "selected_package_manifest_sha256": work_manifest_sha256,
        "local_ai_verified": True,
        "local_ai_transport": "openai_compatible_chat_completions_loopback",
        "local_ai_authentication": "none",
        "local_ai_adapter_persistent_storage_used": False,
        "local_ai_receipt_sha256": local_ai_receipt_sha256,
        "local_ai_runtime_observation_sha256": (runtime_observation_sha256),
        "local_ai_endpoint_sha256": runtime_observation.endpoint_sha256,
        "local_ai_visible_model_label_sha256": (runtime_observation.visible_model_label_sha256),
        "c8_tag_target": C8_TAG_TARGET,
        "c8_covered_head": C8_COVERED_HEAD,
        "c8_tree_sha256": C8_TREE_SHA256,
        "c8_dependency_sha256": canonical_sha256(c8_dependency_payload),
        "repository_head_at_issue": C9_HEAD,
        "c8_live_cycle_grant_reused": False,
        "effective_tool_count": 1,
        "effective_tools": [c9_live_cycle.C9_TOOL_NAME],
        "one_synthetic_work_task": True,
        "one_new_synthetic_native_chat_conversation": True,
        "required_work_plugin_tool_call_count": 1,
        "required_native_chat_plugin_tool_call_count": 0,
        "required_native_chat_manual_attachment_handoff_count": 1,
        "work_delivery_mode": "plugin_mcp_rich_content",
        "native_chat_delivery_mode": "operator_performed_manual_attachment_handoff",
        "work_plugin_mcp_app_required": True,
        "native_chat_plugin_mcp_app_allowed": False,
        "automatic_chat_to_work_switch_allowed": False,
        "native_chat_manual_attachment_handoff_qualifies_as_success": True,
        "issued_at": START + timedelta(minutes=1),
        "expires_at": START + timedelta(minutes=9),
    }
    grant = C9LiveCycleGrant(
        **grant_payload,
        grant_hmac=_external_hmac(
            b"systeme-local/c9/live-cycle-grant/v1\0",
            C9LiveCycleGrant(
                **grant_payload,
                grant_hmac="0" * 64,
            ).model_dump(mode="json", exclude={"grant_hmac"}),
        ),
    )
    bundle = C9LiveCycleBundle(
        authorization=authorization,
        surface_observation=surface,
        local_ai_runtime_observation=runtime_observation,
        grant=grant,
    )
    decision_payload: dict[str, Any] = {
        "version": "1",
        "evaluated_at": START + timedelta(minutes=1),
        "status": C9AdmissionStatus.READY,
        "reason": C9AdmissionReason.READY,
        "live_actions_allowed": True,
        "effective_tool_count": 1,
        "effective_tools": (c9_live_cycle.C9_TOOL_NAME,),
        "cycle_id": CYCLE_ID,
        "grant_id": GRANT_ID,
        "authorization_verified": True,
        "surface_observation_verified": True,
        "local_ai_verified": True,
        "c8_seal_verified": True,
        "c8_tag_target_ancestor_of_head": True,
        "grant_verified": True,
        "c8_live_cycle_grant_reused": False,
    }
    decision = C9AdmissionDecision(
        **decision_payload,
        decision_sha256=canonical_sha256(to_jsonable_python(decision_payload)),
    )
    combined_payload: dict[str, Any] = {
        "version": "1",
        "handoff_id": HANDOFF_ID,
        "fixture_receipt_sha256": fixture_receipt_sha256,
        "local_ai_receipt_sha256": local_ai_receipt_sha256,
        "local_ai_runtime_observation_sha256": (runtime_observation_sha256),
        "work_manifest_sha256": work_manifest_sha256,
        "work_approval_sha256": _sha("work-approval"),
        "chat_manifest_sha256": chat_manifest_sha256,
        "chat_approval_sha256": _sha("chat-approval"),
        "operator_identity_sha256": _sha("operator"),
        "approved_at": START + timedelta(minutes=1),
        "expires_at": START + timedelta(minutes=9),
    }
    combined = _commit_runtime_model(
        C9CombinedApproval,
        payload=combined_payload,
        digest_field="combined_approval_sha256",
        domain=b"systeme-local/c9/combined-approval/v1\0",
    )
    admission_payload: dict[str, Any] = {
        "version": "1",
        "handoff_id": HANDOFF_ID,
        "combined_approval": combined,
        "live_cycle_bundle": bundle,
        "admission_decision": decision,
        "committed_at": START + timedelta(minutes=1),
    }
    admission = _commit_runtime_model(
        C9HandoffAdmission,
        payload=admission_payload,
        digest_field="admission_sha256",
        domain=b"systeme-local/c9/handoff-admission/v1\0",
    )

    work_payload: dict[str, Any] = {
        "version": "1",
        "status": "work_attachments_visibly_consumed",
        "accepted_c8_commit": C8_TAG_TARGET,
        "c9_cycle_id": CYCLE_ID,
        "c9_grant_id": GRANT_ID,
        "surface": "work",
        "surface_task_id": WORK_TASK_ID,
        "capability_sha256": _sha("work-capabilities"),
        "approval_sha256": combined.work_approval_sha256,
        "descriptor_sha256": _sha("work-expansion"),
        "manifest_sha256": work_manifest_sha256,
        "verified_attachment_ids": (
            image_attachment_id,
            document_attachment_id,
        ),
        "verified_nonce_sha256s": (
            image_nonce_sha256,
            document_nonce_sha256,
        ),
        "response_sha256": _sha("work-response"),
        "observed_at": START + timedelta(minutes=2),
    }
    work = C9RichConsumptionReceipt(
        **work_payload,
        receipt_sha256=canonical_sha256(to_jsonable_python(work_payload)),
    )
    correlation_payload: dict[str, Any] = {
        "version": "1",
        "source": "verified_local_c9_hmac_audit_log",
        "simulated": False,
        "cycle_id": CYCLE_ID,
        "grant_id": GRANT_ID,
        "handoff_id": HANDOFF_ID,
        "surface": "work",
        "surface_task_id": WORK_TASK_ID,
        "capability": c9_live_cycle.C9_TOOL_NAME,
        "handoff_admission_sha256": admission.admission_sha256,
        "rich_execution_sha256": _sha("work-execution"),
        "expansion_descriptor_sha256": work.descriptor_sha256,
        "manifest_sha256": work_manifest_sha256,
        "consumption_receipt_sha256": work.receipt_sha256,
        "task_id_sha256": _sha("task-id"),
        "task_processor_audit_id": "11111111-1111-4111-8111-111111111111",
        "render_audit_id": "22222222-2222-4222-8222-222222222222",
        "task_audit_record_sha256": _sha("task-audit-record"),
        "render_audit_record_sha256": _sha("render-audit-record"),
        "task_status": "completed",
        "render_status": "render_completed",
        "render_content_recorded": False,
        "c9_tool_audit_record_count": 2,
        "native_chat_plugin_attempt_audit_record_count": 0,
        "audit_records_verified": 2,
        "audit_chain_last_hmac": _sha("audit-chain-last"),
        "correlated_at": START + timedelta(minutes=2, seconds=30),
    }
    correlation = C9RichAuditCorrelationReceipt(
        **correlation_payload,
        receipt_hmac=_external_hmac(
            b"systeme-local/c9/rich-audit-correlation/v1\0",
            C9RichAuditCorrelationReceipt(
                **correlation_payload,
                receipt_hmac="0" * 64,
            ).model_dump(mode="json", exclude={"receipt_hmac"}),
        ),
    )
    export_id = "c9_export_" + "d" * 32
    chat_export_payload: dict[str, Any] = {
        "version": "1",
        "status": "ready_for_operator_file_picker",
        "delivery_mode": "operator_performed_manual_attachment_handoff",
        "qualifies_as_native_chat_success": False,
        "plugin_mcp_invocation_claimed": False,
        "automated_attachment_claimed": False,
        "handoff_id": HANDOFF_ID,
        "c9_cycle_id": CYCLE_ID,
        "c9_grant_id": GRANT_ID,
        "combined_approval_sha256": combined.combined_approval_sha256,
        "chat_manifest_sha256": chat_manifest_sha256,
        "chat_approval_sha256": combined.chat_approval_sha256,
        "lease_consumption_receipt_sha256": _sha("chat-lease-consumption"),
        "export_id": export_id,
        "export_sha256": _sha("chat-export"),
        "attachment_count": 2,
        "created_at": START + timedelta(minutes=3),
        "expires_at": START + timedelta(minutes=8),
    }
    chat_export = _commit_runtime_model(
        C9ChatExportDescriptor,
        payload=chat_export_payload,
        digest_field="descriptor_sha256",
        domain=b"systeme-local/c9/chat-export-descriptor/v1\0",
    )
    chat_claim_payload: dict[str, Any] = {
        "version": "1",
        "status": "native_chat_manual_attachment_paths_claimed",
        "qualifies_as_native_chat_success": False,
        "plugin_mcp_invocation_claimed": False,
        "automated_attachment_claimed": False,
        "handoff_id": HANDOFF_ID,
        "c9_cycle_id": CYCLE_ID,
        "c9_grant_id": GRANT_ID,
        "export_id": export_id,
        "export_descriptor_sha256": chat_export.descriptor_sha256,
        "chat_manifest_sha256": chat_manifest_sha256,
        "attachment_count": 2,
        "claimed_at": START + timedelta(minutes=3, seconds=10),
    }
    chat_claim = _commit_runtime_model(
        C9ChatPickerClaimReceipt,
        payload=chat_claim_payload,
        digest_field="receipt_sha256",
        domain=b"systeme-local/c9/chat-picker-claim/v1\0",
    )
    chat_payload: dict[str, Any] = {
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
        "handoff_id": HANDOFF_ID,
        "c9_cycle_id": CYCLE_ID,
        "c9_grant_id": GRANT_ID,
        "combined_approval_sha256": combined.combined_approval_sha256,
        "chat_manifest_sha256": chat_manifest_sha256,
        "chat_export_id": export_id,
        "chat_export_descriptor_sha256": chat_export.descriptor_sha256,
        "chat_picker_claim_receipt_sha256": chat_claim.receipt_sha256,
        "verified_nonce_sha256s": (
            image_nonce_sha256,
            document_nonce_sha256,
        ),
        "response_sha256": _sha("chat-response"),
        "manual_cleanup_receipt_sha256": _sha("chat-cleanup"),
        "confirmed_at": START + timedelta(minutes=3, seconds=30),
    }
    chat = _commit_runtime_model(
        C9ChatConfirmationReceipt,
        payload=chat_payload,
        digest_field="receipt_sha256",
        domain=b"systeme-local/c9/chat-confirmation/v1\0",
    )
    close_payload: dict[str, Any] = {
        "version": "1",
        "status": "closed",
        "handoff_id": HANDOFF_ID,
        "pending_deliveries_zeroed": 0,
        "attachment_leases_cleaned": 0,
        "manual_exports_cleaned": 0,
        "rich_call_count": 1,
        "rich_confirmation_count": 1,
        "native_chat_manual_handoff_used": True,
        "fixture_cleanup_sha256": _sha("fixture-cleanup"),
        "admission_file_removed": True,
        "closed_at": START + timedelta(minutes=4),
    }
    close = _commit_runtime_model(
        C9CoordinatorCloseReceipt,
        payload=close_payload,
        digest_field="receipt_sha256",
        domain=b"systeme-local/c9/coordinator-close/v1\0",
    )
    negative = commit_negative_test_receipt(
        cycle_id=CYCLE_ID,
        grant_id=GRANT_ID,
        handoff_id=HANDOFF_ID,
        outcomes=_required_outcomes(),
        automated_suite=_automated_negative_evidence(),
        observed_at=START + timedelta(minutes=5),
        audit_key=AUDIT_KEY,
    )
    revocation = commit_revocation_receipt(
        cycle_id=CYCLE_ID,
        grant_id=GRANT_ID,
        close_receipt=close,
        **REVOCATION_CONFIRMATIONS,
        verified_at=START + timedelta(minutes=6),
        audit_key=AUDIT_KEY,
    )
    return (
        stage,
        admission,
        work,
        correlation,
        chat_export,
        chat_claim,
        chat,
        close,
        negative,
        revocation,
    )


def _patch_c8_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        c9_attestation,
        "verify_c9_c8_seal_exact",
        lambda _root: SimpleNamespace(
            tag_target=C8_TAG_TARGET,
            covered_head=C8_COVERED_HEAD,
            tree_sha256=C8_TREE_SHA256,
            final_attestation_sha256=C8_FINAL_SHA256,
            revocation_verified=True,
            work_call_count=2,
            reviewed_outcome=("COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"),
        ),
    )
    monkeypatch.setattr(
        c9_attestation,
        "_current_repository_head",
        lambda _root: C9_HEAD,
    )


def _execution_from_evidence(
    evidence: tuple[
        C9HandoffStageReceipt,
        C9HandoffAdmission,
        C9RichConsumptionReceipt,
        C9RichAuditCorrelationReceipt,
        C9ChatExportDescriptor,
        C9ChatPickerClaimReceipt,
        C9ChatConfirmationReceipt,
        C9CoordinatorCloseReceipt,
        C9NegativeTestReceipt,
        C9RevocationReceipt,
    ],
    *,
    surface: C9RichSurface = C9RichSurface.WORK,
) -> C9RichExecutionDescriptor:
    stage, admission = evidence[:2]
    receipt = evidence[2]
    grant = admission.live_cycle_bundle.grant
    task_id = stage.work_task_id if surface is C9RichSurface.WORK else stage.chat_task_id
    manifest_sha256 = (
        stage.work_manifest_sha256 if surface is C9RichSurface.WORK else stage.chat_manifest_sha256
    )
    payload: dict[str, Any] = {
        "version": "1",
        "status": "pending_mcp_rich_content_render",
        "handoff_id": stage.handoff_id,
        "surface": surface.value,
        "surface_task_id": task_id,
        "delivery_token": "c9_delivery_" + ("d" if surface is C9RichSurface.WORK else "e") * 32,
        "c9_cycle_id": grant.cycle_id,
        "c9_grant_id": grant.grant_id,
        "accepted_c8_commit": grant.c8_tag_target,
        "combined_approval_sha256": (admission.combined_approval.combined_approval_sha256),
        "surface_manifest_sha256": manifest_sha256,
        "expansion_descriptor_sha256": (
            receipt.descriptor_sha256 if surface is C9RichSurface.WORK else _sha("chat-expansion")
        ),
        "lease_consumption_receipt_sha256": _sha(f"{surface.value}-lease-consumption"),
        "attachment_count": 2,
        "executed_at": START
        + timedelta(
            minutes=1 if surface is C9RichSurface.WORK else 2,
            seconds=30,
        ),
        "expires_at": START + timedelta(minutes=9),
    }
    return cast(
        C9RichExecutionDescriptor,
        _commit_runtime_model(
            C9RichExecutionDescriptor,
            payload=payload,
            digest_field="execution_sha256",
            domain=b"systeme-local/c9/rich-execution/v1\0",
        ),
    )


def _commit_final(
    monkeypatch: pytest.MonkeyPatch,
    evidence: tuple[
        C9HandoffStageReceipt,
        C9HandoffAdmission,
        C9RichConsumptionReceipt,
        C9RichAuditCorrelationReceipt,
        C9ChatExportDescriptor,
        C9ChatPickerClaimReceipt,
        C9ChatConfirmationReceipt,
        C9CoordinatorCloseReceipt,
        C9NegativeTestReceipt,
        C9RevocationReceipt,
    ],
    *,
    verified_at: datetime = START + timedelta(minutes=7),
    runtime_observation: C9LocalAIRuntimeObservation | None = None,
) -> C9FinalAttestation:
    _patch_c8_verification(monkeypatch)
    (
        stage,
        admission,
        work,
        work_correlation,
        chat_export,
        chat_claim,
        chat,
        close,
        negative,
        revocation,
    ) = evidence
    return commit_final_attestation(
        stage_receipt=stage,
        admission=admission,
        local_ai_runtime_observation=(
            runtime_observation or admission.live_cycle_bundle.local_ai_runtime_observation
        ),
        work_receipt=work,
        work_correlation_receipt=work_correlation,
        chat_export_descriptor=chat_export,
        chat_picker_claim_receipt=chat_claim,
        chat_receipt=chat,
        close_receipt=close,
        negative_receipt=negative,
        revocation_receipt=revocation,
        repository_root=Path("."),
        audit_key=AUDIT_KEY,
        verified_at=verified_at,
    )


def test_negative_receipt_requires_exact_bounded_outcomes_and_hmac() -> None:
    receipt = commit_negative_test_receipt(
        cycle_id=CYCLE_ID,
        grant_id=GRANT_ID,
        handoff_id=HANDOFF_ID,
        outcomes=_required_outcomes(),
        automated_suite=_automated_negative_evidence(),
        observed_at=START,
        audit_key=AUDIT_KEY,
    )
    assert verify_negative_test_receipt(receipt, audit_key=AUDIT_KEY) == receipt
    assert receipt.outcomes[C9NegativeCheckId.CHAT_MCP_REQUEST] is (
        C9NegativeOutcome.CAPABILITY_NOT_EXPOSED
    )
    assert receipt.work_rich_mcp_call_count == 1
    assert receipt.native_chat_manual_handoff_count == 1
    assert receipt.total_rich_mcp_call_count == 1
    assert receipt.native_chat_plugin_invoked is False
    assert receipt.automated_suite.exit_code == 0
    assert receipt.automated_suite.failed_count == 0

    incomplete = _required_outcomes()
    incomplete.pop(C9NegativeCheckId.SECRET_REQUEST)
    with pytest.raises(ValidationError):
        commit_negative_test_receipt(
            cycle_id=CYCLE_ID,
            grant_id=GRANT_ID,
            handoff_id=HANDOFF_ID,
            outcomes=incomplete,
            automated_suite=_automated_negative_evidence(),
            observed_at=START,
            audit_key=AUDIT_KEY,
        )
    with pytest.raises(ValueError, match="authentication"):
        verify_negative_test_receipt(receipt, audit_key=OTHER_AUDIT_KEY)

    replay_accepted = _required_outcomes()
    replay_accepted[C9NegativeCheckId.WORK_REPLAY] = C9NegativeOutcome.DENIED
    with pytest.raises(ValidationError):
        commit_negative_test_receipt(
            cycle_id=CYCLE_ID,
            grant_id=GRANT_ID,
            handoff_id=HANDOFF_ID,
            outcomes=replay_accepted,
            automated_suite=_automated_negative_evidence(),
            observed_at=START,
            audit_key=AUDIT_KEY,
        )


def test_negative_receipt_tampering_is_rejected() -> None:
    receipt = _fixture_evidence()[8]
    tampered = receipt.model_copy(update={"observed_at": START + timedelta(days=1)})
    with pytest.raises(ValueError, match="authentication"):
        verify_negative_test_receipt(tampered, audit_key=AUDIT_KEY)


def test_automated_negative_suite_refuses_selection_or_source_drift() -> None:
    evidence = _automated_negative_evidence()
    with pytest.raises(ValidationError, match="selection is not exact"):
        C9AutomatedNegativeSuiteEvidence.model_validate(
            {
                **evidence.model_dump(mode="python"),
                "node_ids": evidence.node_ids[:-1],
            }
        )
    with pytest.raises(ValidationError, match="source set is not exact"):
        C9AutomatedNegativeSuiteEvidence.model_validate(
            {
                **evidence.model_dump(mode="python"),
                "source_sha256s": {"tests/not-the-suite.py": _sha("wrong")},
            }
        )
    drifted_mapping = dict(evidence.evidence_node_ids)
    drifted_mapping[C9NegativeCheckId.CROSS_MODE_REPLAY] = drifted_mapping[
        C9NegativeCheckId.CROSS_HANDOFF_REPLAY
    ]
    with pytest.raises(ValidationError, match="evidence mapping is not exact"):
        C9AutomatedNegativeSuiteEvidence.model_validate(
            {
                **evidence.model_dump(mode="python"),
                "evidence_node_ids": drifted_mapping,
            }
        )


def test_automated_negative_mapping_covers_exact_hybrid_surface_contract() -> None:
    mapping = c9_attestation._required_negative_evidence()
    by_test_name = {node_id.split("::", 1)[1]: node_id for node_id in C9_NEGATIVE_SUITE_NODEIDS}
    rich_replay = by_test_name[
        "test_work_then_native_chat_manual_is_strict_and_both_halves_are_one_use"
    ]
    chat_mcp_unsupported = by_test_name[
        "test_chat_mcp_execute_render_confirm_and_legacy_fallback_are_unsupported"
    ]
    cross_mode = by_test_name["test_control_rejects_mismatched_work_and_native_chat_receipts"]
    work_only_response = by_test_name["test_provider_response_parser_is_strictly_work_only"]
    cross_handoff = by_test_name["test_cross_handoff_and_expired_grant_fail_closed"]
    strict_handler = by_test_name["test_capability_handler_is_strict_and_returns_only_metadata"]
    strict_provider_response = by_test_name[
        "test_provider_response_parsers_reject_duplicate_unknown_and_malformed_values"
    ]
    denied_scope = by_test_name["test_exact_one_tool_schema_rejects_expansion_and_unknown_fields"]
    capability_not_exposed = (
        denied_scope,
        by_test_name["test_c9_tool_has_exact_work_only_input_and_truthful_annotations"],
        by_test_name["test_c9_registry_exposes_exactly_one_policy_admitted_tool"],
    )

    assert set(mapping) == set(C9NegativeCheckId)
    assert {node_id for node_ids in mapping.values() for node_id in node_ids} == set(
        C9_NEGATIVE_SUITE_NODEIDS
    )
    assert mapping[C9NegativeCheckId.WORK_REPLAY] == (rich_replay,)
    assert rich_replay in mapping[C9NegativeCheckId.CHAT_MANUAL_REPLAY]
    assert mapping[C9NegativeCheckId.CROSS_MODE_REPLAY][:2] == (
        cross_mode,
        work_only_response,
    )
    assert mapping[C9NegativeCheckId.CROSS_HANDOFF_REPLAY] == (cross_handoff,)
    assert mapping[C9NegativeCheckId.MALFORMED_REQUEST][:2] == (
        strict_handler,
        strict_provider_response,
    )
    assert (
        by_test_name["test_native_chat_response_parser_requires_exact_manual_handoff_json"]
        in mapping[C9NegativeCheckId.MALFORMED_REQUEST]
    )
    assert chat_mcp_unsupported in mapping[C9NegativeCheckId.CHAT_MCP_REQUEST]
    assert chat_mcp_unsupported in mapping[C9NegativeCheckId.UNAPPROVED_FALLBACK_USE]
    assert mapping[C9NegativeCheckId.AUTOMATIC_CHAT_TO_WORK_SWITCH] == (denied_scope,)
    for check in (
        C9NegativeCheckId.COMMAND_EXECUTION_REQUEST,
        C9NegativeCheckId.SECRET_REQUEST,
        C9NegativeCheckId.WRITE_OPERATION_REQUEST,
        C9NegativeCheckId.REAL_EVIDENCE_REQUEST,
        C9NegativeCheckId.PROTOCOL_V2_REQUEST,
    ):
        assert mapping[check] == capability_not_exposed


def test_revocation_binds_complete_coordinator_close() -> None:
    close = _fixture_evidence()[7]
    receipt = commit_revocation_receipt(
        cycle_id=CYCLE_ID,
        grant_id=GRANT_ID,
        close_receipt=close,
        **REVOCATION_CONFIRMATIONS,
        verified_at=START + timedelta(minutes=6),
        audit_key=AUDIT_KEY,
    )
    assert (
        verify_revocation_receipt(
            receipt,
            close_receipt=close,
            audit_key=AUDIT_KEY,
        )
        == receipt
    )
    assert receipt.listener_8765_stopped and receipt.listener_8766_stopped
    assert receipt.manual_export_absent and receipt.synthetic_fixtures_absent

    other_close_payload = close.model_dump(
        mode="python",
        exclude={"receipt_sha256"},
    )
    other_close_payload["closed_at"] = close.closed_at + timedelta(seconds=1)
    other_close = _commit_runtime_model(
        C9CoordinatorCloseReceipt,
        payload=other_close_payload,
        digest_field="receipt_sha256",
        domain=b"systeme-local/c9/coordinator-close/v1\0",
    )
    with pytest.raises(ValueError, match="does not bind"):
        verify_revocation_receipt(
            receipt,
            close_receipt=other_close,
            audit_key=AUDIT_KEY,
        )
    incomplete = dict(REVOCATION_CONFIRMATIONS)
    incomplete["runtime_api_key_revoked"] = False
    with pytest.raises(ValueError, match="every exact"):
        commit_revocation_receipt(
            cycle_id=CYCLE_ID,
            grant_id=GRANT_ID,
            close_receipt=close,
            **incomplete,
            verified_at=START + timedelta(minutes=6),
            audit_key=AUDIT_KEY,
        )


def test_rich_correlation_verifies_task_and_render_audit_chain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evidence = _fixture_evidence()
    _, admission, work = evidence[:3]
    execution = _execution_from_evidence(evidence)
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path, AUDIT_KEY)
    task_id = "c9-mcp-task-00000001"
    task_audit_id = audit.append(
        {
            "task_id": task_id,
            "agent": {
                "provider": "mcp",
                "model": None,
                "session_id": "c9-test-session",
            },
            "capability": c9_live_cycle.C9_TOOL_NAME,
            "status": "completed",
            "arguments": {"handoff_id": HANDOFF_ID, "surface": "work"},
            "output": execution.model_dump(mode="json"),
            "approval_id": None,
        }
    )
    render_audit_id = audit.append(
        {
            "task_id": task_id,
            "capability": c9_live_cycle.C9_TOOL_NAME,
            "status": "render_completed",
            "content_recorded": False,
        }
    )

    def fixed_record_timestamp(record: dict[str, Any]) -> datetime:
        if record["audit_id"] == task_audit_id:
            return START + timedelta(minutes=1, seconds=31)
        assert record["audit_id"] == render_audit_id
        return START + timedelta(minutes=1, seconds=32)

    monkeypatch.setattr(
        c9_attestation,
        "_record_timestamp",
        fixed_record_timestamp,
    )
    receipt = commit_rich_audit_correlation_receipt(
        admission=admission,
        rich_execution=execution,
        consumption_receipt=work,
        audit_log_path=audit_path,
        metadata_root=tmp_path,
        correlated_at=START + timedelta(minutes=2, seconds=30),
        audit_key=AUDIT_KEY,
    )
    assert receipt.task_processor_audit_id == task_audit_id
    assert receipt.render_audit_id == render_audit_id
    assert receipt.render_content_recorded is False
    assert (
        verify_rich_audit_correlation_receipt(
            receipt,
            admission=admission,
            consumption_receipt=work,
            audit_key=AUDIT_KEY,
        )
        == receipt
    )
    serialized = receipt.model_dump_json()
    assert execution.delivery_token not in serialized
    assert task_id not in serialized


def test_rich_correlation_rejects_chat_surface_before_reading_audit(
    tmp_path: Path,
) -> None:
    evidence = _fixture_evidence()
    admission = evidence[1]
    work = evidence[2]
    execution = _execution_from_evidence(evidence, surface=C9RichSurface.CHAT)
    with pytest.raises(ValueError, match="only for the Work"):
        commit_rich_audit_correlation_receipt(
            admission=admission,
            rich_execution=execution,
            consumption_receipt=work,
            audit_log_path=tmp_path / "must-not-be-read.jsonl",
            metadata_root=tmp_path,
            correlated_at=START + timedelta(minutes=3),
            audit_key=AUDIT_KEY,
        )


@pytest.mark.parametrize(
    "extra_kind",
    ("failed_chat", "replayed_work", "wrong_handoff", "extra_render"),
)
def test_rich_correlation_rejects_every_extra_c9_tool_record(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    extra_kind: str,
) -> None:
    evidence = _fixture_evidence()
    _, admission, work = evidence[:3]
    execution = _execution_from_evidence(evidence)
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path, AUDIT_KEY)
    task_id = "c9-mcp-task-00000001"
    audit.append(
        {
            "task_id": task_id,
            "agent": {"provider": "mcp", "model": None, "session_id": "c9-test-session"},
            "capability": c9_live_cycle.C9_TOOL_NAME,
            "status": "completed",
            "arguments": {"handoff_id": HANDOFF_ID, "surface": "work"},
            "output": execution.model_dump(mode="json"),
            "approval_id": None,
        }
    )
    audit.append(
        {
            "task_id": task_id,
            "capability": c9_live_cycle.C9_TOOL_NAME,
            "status": "render_completed",
            "content_recorded": False,
        }
    )
    extras: dict[str, dict[str, Any]] = {
        "failed_chat": {
            "task_id": "c9-mcp-task-forbidden-chat",
            "capability": c9_live_cycle.C9_TOOL_NAME,
            "status": "failed",
            "arguments": {"handoff_id": HANDOFF_ID, "surface": "chat"},
            "failure_type": "UnsupportedSurface",
        },
        "replayed_work": {
            "task_id": "c9-mcp-task-work-replay",
            "capability": c9_live_cycle.C9_TOOL_NAME,
            "status": "completed",
            "arguments": {"handoff_id": HANDOFF_ID, "surface": "work"},
            "output": execution.model_dump(mode="json"),
        },
        "wrong_handoff": {
            "task_id": "c9-mcp-task-wrong-handoff",
            "capability": c9_live_cycle.C9_TOOL_NAME,
            "status": "failed",
            "arguments": {
                "handoff_id": "c9_handoff_" + ("f" * 32),
                "surface": "work",
            },
            "failure_type": "CrossHandoff",
        },
        "extra_render": {
            "task_id": "c9-mcp-task-extra-render",
            "capability": c9_live_cycle.C9_TOOL_NAME,
            "status": "render_completed",
            "content_recorded": False,
        },
    }
    audit.append(extras[extra_kind])
    monkeypatch.setattr(
        c9_attestation,
        "_record_timestamp",
        lambda _record: START + timedelta(minutes=2),
    )
    with pytest.raises(ValueError, match="exactly one Work task record"):
        commit_rich_audit_correlation_receipt(
            admission=admission,
            rich_execution=execution,
            consumption_receipt=work,
            audit_log_path=audit_path,
            metadata_root=tmp_path,
            correlated_at=START + timedelta(minutes=3),
            audit_key=AUDIT_KEY,
        )


def test_rich_correlation_rejects_any_render_failure_for_the_same_task(
    tmp_path: Path,
) -> None:
    evidence = _fixture_evidence()
    _, admission, work = evidence[:3]
    execution = _execution_from_evidence(evidence)
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path, AUDIT_KEY)
    task_id = "c9-mcp-task-00000002"
    audit.append(
        {
            "task_id": task_id,
            "agent": {
                "provider": "mcp",
                "model": None,
                "session_id": "c9-test-session",
            },
            "capability": c9_live_cycle.C9_TOOL_NAME,
            "status": "completed",
            "arguments": {"handoff_id": HANDOFF_ID, "surface": "work"},
            "output": execution.model_dump(mode="json"),
            "approval_id": None,
        }
    )
    audit.append(
        {
            "task_id": task_id,
            "capability": c9_live_cycle.C9_TOOL_NAME,
            "status": "render_completed",
            "content_recorded": False,
        }
    )
    audit.append(
        {
            "task_id": task_id,
            "capability": c9_live_cycle.C9_TOOL_NAME,
            "status": "render_failed",
            "content_recorded": False,
            "failure_type": "CancelledError",
        }
    )

    with pytest.raises(ValueError, match="exactly one Work task record"):
        commit_rich_audit_correlation_receipt(
            admission=admission,
            rich_execution=execution,
            consumption_receipt=work,
            audit_log_path=audit_path,
            metadata_root=tmp_path,
            correlated_at=START + timedelta(minutes=2, seconds=30),
            audit_key=AUDIT_KEY,
        )


def test_rich_correlation_rejects_tampered_audit_chain(
    tmp_path: Path,
) -> None:
    evidence = _fixture_evidence()
    _, admission, work = evidence[:3]
    execution = _execution_from_evidence(evidence)
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path, AUDIT_KEY)
    audit.append(
        {
            "task_id": "c9-mcp-task-00000001",
            "agent": {
                "provider": "mcp",
                "session_id": "c9-test-session",
            },
            "capability": c9_live_cycle.C9_TOOL_NAME,
            "status": "completed",
            "arguments": {"handoff_id": HANDOFF_ID, "surface": "work"},
            "output": execution.model_dump(mode="json"),
        }
    )
    raw = audit_path.read_bytes()
    audit_path.write_bytes(raw.replace(b'"completed"', b'"tampered"', 1))
    with pytest.raises(ValueError, match="authentication"):
        commit_rich_audit_correlation_receipt(
            admission=admission,
            rich_execution=execution,
            consumption_receipt=work,
            audit_log_path=audit_path,
            metadata_root=tmp_path,
            correlated_at=START + timedelta(minutes=2, seconds=30),
            audit_key=AUDIT_KEY,
        )


def test_final_attestation_correlates_work_mcp_and_manual_native_chat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation = _commit_final(monkeypatch, _fixture_evidence())
    assert attestation.status == C9_FINAL_STATUS
    assert attestation.c9_live_repository_head == C9_HEAD
    assert attestation.work_rich_call_count == 1
    assert attestation.chat_manual_handoff_count == 1
    assert attestation.total_rich_mcp_call_count == 1
    assert attestation.work_rich_mcp_verified
    assert attestation.chat_manual_visible_handoff_verified
    assert attestation.same_sanitized_package_verified
    assert not attestation.native_chat_plugin_invoked
    assert not attestation.native_chat_provider_audit_correlation_claimed
    assert not attestation.unapproved_fallback_used
    assert attestation.chat_export_id == _fixture_evidence()[4].export_id
    assert not attestation.regular_arbitrary_files_tested
    assert not attestation.automatic_chat_to_work_switch_used
    assert verify_final_attestation(attestation, audit_key=AUDIT_KEY) == attestation

    rendered = attestation.model_dump_json()
    assert "image_nonce" not in rendered
    assert "document_nonce" not in rendered
    assert "fixture_path" not in rendered
    assert "runtime_api_key" not in rendered
    assert "sk-" not in rendered


def test_final_attestation_rejects_repository_head_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = _fixture_evidence()
    _patch_c8_verification(monkeypatch)
    monkeypatch.setattr(
        c9_attestation,
        "_current_repository_head",
        lambda _root: "a" * 40,
    )
    (
        stage,
        admission,
        work,
        work_correlation,
        chat_export,
        chat_claim,
        chat,
        close,
        negative,
        revocation,
    ) = evidence
    with pytest.raises(ValueError, match="HEAD drifted"):
        commit_final_attestation(
            stage_receipt=stage,
            admission=admission,
            local_ai_runtime_observation=(admission.live_cycle_bundle.local_ai_runtime_observation),
            work_receipt=work,
            work_correlation_receipt=work_correlation,
            chat_export_descriptor=chat_export,
            chat_picker_claim_receipt=chat_claim,
            chat_receipt=chat,
            close_receipt=close,
            negative_receipt=negative,
            revocation_receipt=revocation,
            repository_root=Path("."),
            audit_key=AUDIT_KEY,
            verified_at=START + timedelta(minutes=7),
        )


def test_final_attestation_rejects_negative_suite_from_another_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = list(_fixture_evidence())
    negative = evidence[8]
    assert isinstance(negative, C9NegativeTestReceipt)
    other_suite = _automated_negative_evidence(repository_head="a" * 40)
    evidence[8] = commit_negative_test_receipt(
        cycle_id=CYCLE_ID,
        grant_id=GRANT_ID,
        handoff_id=HANDOFF_ID,
        outcomes=_required_outcomes(),
        automated_suite=other_suite,
        observed_at=negative.observed_at,
        audit_key=AUDIT_KEY,
    )
    with pytest.raises(ValueError, match="negative suite repository HEAD"):
        _commit_final(monkeypatch, tuple(evidence))  # type: ignore[arg-type]


def test_final_attestation_rejects_cross_cycle_work_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = list(_fixture_evidence())
    work = evidence[2]
    assert isinstance(work, C9RichConsumptionReceipt)
    payload = work.model_dump(mode="python", exclude={"receipt_sha256"})
    payload["c9_cycle_id"] = "c9_cycle_" + "d" * 32
    evidence[2] = C9RichConsumptionReceipt(
        **payload,
        receipt_sha256=canonical_sha256(to_jsonable_python(payload)),
    )
    with pytest.raises(ValueError):
        _commit_final(monkeypatch, tuple(evidence))  # type: ignore[arg-type]


def test_final_attestation_rejects_cross_cycle_chat_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = list(_fixture_evidence())
    chat = evidence[6]
    assert isinstance(chat, C9ChatConfirmationReceipt)
    payload = chat.model_dump(mode="python", exclude={"receipt_sha256"})
    payload["c9_cycle_id"] = "c9_cycle_" + "e" * 32
    evidence[6] = _commit_runtime_model(
        C9ChatConfirmationReceipt,
        payload=payload,
        digest_field="receipt_sha256",
        domain=b"systeme-local/c9/chat-confirmation/v1\0",
    )
    with pytest.raises(ValueError, match="crosses cycle"):
        _commit_final(monkeypatch, tuple(evidence))  # type: ignore[arg-type]


@pytest.mark.parametrize("evidence_index", (4, 5), ids=("export", "picker-claim"))
def test_final_attestation_rejects_substituted_chat_export_or_claim(
    monkeypatch: pytest.MonkeyPatch,
    evidence_index: int,
) -> None:
    evidence = list(_fixture_evidence())
    if evidence_index == 4:
        export = evidence[4]
        assert isinstance(export, C9ChatExportDescriptor)
        payload = export.model_dump(mode="python", exclude={"descriptor_sha256"})
        payload["export_sha256"] = _sha("substituted-export")
        evidence[4] = _commit_runtime_model(
            C9ChatExportDescriptor,
            payload=payload,
            digest_field="descriptor_sha256",
            domain=b"systeme-local/c9/chat-export-descriptor/v1\0",
        )
    else:
        claim = evidence[5]
        assert isinstance(claim, C9ChatPickerClaimReceipt)
        payload = claim.model_dump(mode="python", exclude={"receipt_sha256"})
        payload["claimed_at"] = claim.claimed_at + timedelta(seconds=1)
        evidence[5] = _commit_runtime_model(
            C9ChatPickerClaimReceipt,
            payload=payload,
            digest_field="receipt_sha256",
            domain=b"systeme-local/c9/chat-picker-claim/v1\0",
        )
    with pytest.raises(ValueError, match="does not bind"):
        _commit_final(monkeypatch, tuple(evidence))  # type: ignore[arg-type]


def test_final_attestation_rejects_nonce_order_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = list(_fixture_evidence())
    work = evidence[2]
    assert isinstance(work, C9RichConsumptionReceipt)
    payload = work.model_dump(mode="python", exclude={"receipt_sha256"})
    payload["verified_nonce_sha256s"] = tuple(reversed(work.verified_nonce_sha256s))
    evidence[2] = C9RichConsumptionReceipt(
        **payload,
        receipt_sha256=canonical_sha256(to_jsonable_python(payload)),
    )
    with pytest.raises(ValueError):
        _commit_final(monkeypatch, tuple(evidence))  # type: ignore[arg-type]


def test_final_attestation_requires_confirmed_manual_native_chat_handoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = list(_fixture_evidence())
    close = evidence[7]
    assert isinstance(close, C9CoordinatorCloseReceipt)
    close_payload = close.model_dump(mode="python", exclude={"receipt_sha256"})
    close_payload["native_chat_manual_handoff_used"] = False
    tainted_close = _commit_runtime_model(
        C9CoordinatorCloseReceipt,
        payload=close_payload,
        digest_field="receipt_sha256",
        domain=b"systeme-local/c9/coordinator-close/v1\0",
    )
    evidence[7] = tainted_close
    evidence[9] = commit_revocation_receipt(
        cycle_id=CYCLE_ID,
        grant_id=GRANT_ID,
        close_receipt=tainted_close,
        **REVOCATION_CONFIRMATIONS,
        verified_at=START + timedelta(minutes=6),
        audit_key=AUDIT_KEY,
    )
    with pytest.raises(ValueError, match="one native Chat manual handoff"):
        _commit_final(monkeypatch, tuple(evidence))  # type: ignore[arg-type]


def test_final_attestation_does_not_require_live_evidence_to_remain_fresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation = _commit_final(
        monkeypatch,
        _fixture_evidence(),
        verified_at=START + timedelta(days=365),
    )
    assert attestation.verified_at == START + timedelta(days=365)


def test_final_attestation_hmac_rejects_tamper_and_wrong_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation = _commit_final(monkeypatch, _fixture_evidence())
    with pytest.raises(ValueError, match="authentication"):
        verify_final_attestation(attestation, audit_key=OTHER_AUDIT_KEY)
    tampered = attestation.model_copy(
        update={"verified_at": attestation.verified_at + timedelta(seconds=1)}
    )
    with pytest.raises((ValidationError, ValueError)):
        verify_final_attestation(tampered, audit_key=AUDIT_KEY)


def test_final_attestation_rejects_legacy_dual_mcp_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation = _commit_final(monkeypatch, _fixture_evidence())
    payload = attestation.model_dump(mode="python")
    payload["status"] = "COMPLETE_C9_WORK_AND_CHAT_RICH_MCP_ATTACHMENTS_CORRELATED_AND_REVOKED"
    with pytest.raises(ValidationError):
        C9FinalAttestation.model_validate(payload)


def test_final_attestation_requires_exact_authenticated_runtime_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = _fixture_evidence()
    observation = evidence[1].live_cycle_bundle.local_ai_runtime_observation
    tampered = observation.model_copy(update={"product_version": "tampered"})
    with pytest.raises(ValueError, match="authentication"):
        _commit_final(
            monkeypatch,
            evidence,
            runtime_observation=tampered,
        )

    expired = commit_c9_local_ai_runtime_observation(
        cycle_id=CYCLE_ID,
        provider_kind=C9LocalAIProviderKind.OTHER_REVIEWED_NATIVE,
        product_name="Reviewed test-native runtime",
        product_version="1.0",
        listening_pid=os.getpid(),
        executable_path=Path(sys.executable).resolve(),
        endpoint="http://127.0.0.1:11434/v1/chat/completions",
        visible_model_label="reviewed-test-model",
        runtime_request_logging_disabled=True,
        runtime_request_persistence_disabled=True,
        operator_confirmed_native_runtime=True,
        operator_confirmed_runtime_privacy_settings=True,
        observed_at=START - timedelta(minutes=2),
        expires_at=START,
        audit_key=AUDIT_KEY,
    )
    with pytest.raises(ValueError, match="not fresh"):
        _commit_final(
            monkeypatch,
            evidence,
            runtime_observation=expired,
        )


def test_final_cli_requires_runtime_observation_metadata_file(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)
    result = c9_attestation.main(
        [
            "commit-final",
            "--metadata-root",
            str(Path.cwd()),
            "--stage",
            "stage.json",
            "--admission",
            "admission.json",
            "--work",
            "work.json",
            "--work-correlation",
            "correlation.json",
            "--chat-export",
            "chat-export.json",
            "--chat-picker-claim",
            "chat-picker-claim.json",
            "--chat",
            "chat.json",
            "--close",
            "close.json",
            "--negative",
            "negative.json",
            "--revocation",
            "revocation.json",
        ]
    )
    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "status": "error",
        "error": "C9_ATTESTATION_VALIDATION_FAILED",
    }


def test_verify_final_cli_authenticates_exact_attestation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    attestation = _commit_final(monkeypatch, _fixture_evidence())
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)
    monkeypatch.setattr(
        c9_attestation,
        "_load_model",
        lambda *_args, **_kwargs: attestation,
    )
    result = c9_attestation.main(
        [
            "verify-final",
            "--metadata-root",
            str(Path.cwd()),
            "--attestation",
            "attestation.json",
        ]
    )
    captured = capsys.readouterr()
    assert result == 0
    assert json.loads(captured.out)["attestation_sha256"] == (attestation.attestation_sha256)
    assert captured.err == ""


def test_strict_receipts_reject_unknown_fields() -> None:
    receipt = _fixture_evidence()[8]
    payload = receipt.model_dump(mode="python")
    payload["raw_nonce"] = "must-never-load"
    with pytest.raises(ValidationError):
        C9NegativeTestReceipt.model_validate(payload)


def test_cli_errors_are_generic_and_do_not_echo_input(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SLG_AUDIT_KEY", raising=False)
    secret_path = r"C:\private" + "\\sk-" + "synthetic-redaction-probe.json"
    result = c9_attestation.main(
        [
            "commit-final",
            "--stage",
            secret_path,
        ]
    )
    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "status": "error",
        "error": "C9_ATTESTATION_VALIDATION_FAILED",
    }
    assert "private" not in captured.err
    assert "sk-" not in captured.err


def test_metadata_loader_rejects_hardlinks_and_root_escape(
    tmp_path: Path,
) -> None:
    original = tmp_path / "receipt.json"
    original.write_text('{"version":"1"}\n', encoding="utf-8")
    hardlink = tmp_path / "receipt-link.json"
    os.link(original, hardlink)
    with pytest.raises(ValueError, match="unsafe"):
        c9_attestation._safe_read_metadata(
            original,
            metadata_root=tmp_path,
            maximum_bytes=1024,
        )

    outside = tmp_path.parent / "outside-c9-attestation.json"
    outside.write_text('{"version":"1"}\n', encoding="utf-8")
    try:
        with pytest.raises(ValueError, match="escapes"):
            c9_attestation._safe_read_metadata(
                outside,
                metadata_root=tmp_path,
                maximum_bytes=1024,
            )
    finally:
        outside.unlink(missing_ok=True)
