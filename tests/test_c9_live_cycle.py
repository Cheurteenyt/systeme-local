from __future__ import annotations

import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import systeme_local_gateway.c9_live_cycle as live
from systeme_local_gateway.c9_live_cycle import (
    C9_TOOL_NAME,
    C9AdmissionReason,
    C9AdmissionStatus,
    C9C8SealDependency,
    C9LiveCycleBundle,
    C9LiveCycleGrant,
    C9OperatorAuthorization,
    C9SurfaceObservation,
    commit_c9_operator_authorization,
    commit_c9_surface_observation,
    evaluate_c9_admission,
    issue_c9_live_cycle_bundle,
    verify_c9_live_cycle_bundle,
)
from systeme_local_gateway.c9_local_ai import (
    C9LocalAIProviderKind,
    C9LocalAIReceipt,
    C9LocalAIRuntimeObservation,
    c9_local_ai_runtime_observation_sha256,
    commit_c9_local_ai_runtime_observation,
)

ROOT = Path(__file__).resolve().parents[1]
AUDIT_KEY = "c9-test-audit-key-is-longer-than-thirty-two-characters"
WRONG_KEY = "c9-wrong-audit-key-is-also-longer-than-thirty-two"
NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
CYCLE_ID = "c9_cycle_" + "a" * 32
GRANT_ID = "c9_grant_" + "b" * 32
MANIFEST_SHA256 = "c" * 64
LOCAL_AI_ENDPOINT = "http://127.0.0.1:11434/v1/chat/completions"
LOCAL_AI_MODEL = "reviewed-test-model"
WORK_VISIBLE_MODEL = "GPT-5.6 Sol"
WORK_VISIBLE_REASONING = "Minimal"
CHAT_VISIBLE_MODEL = "GPT-5.6 Sol"
CHAT_VISIBLE_REASONING = "Très élevée"


def _dependency(
    *,
    tag_target: str = "1" * 40,
    current_head: str = "3" * 40,
    ancestor: bool = True,
) -> C9C8SealDependency:
    payload = {
        "version": "1",
        "status": "verified",
        "tag_target": tag_target,
        "covered_head": "2" * 40,
        "current_head": current_head,
        "tree_sha256": "4" * 64,
        "final_attestation_sha256": "5" * 64,
        "reviewed_outcome": "COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED",
        "work_call_count": 2,
        "revocation_verified": True,
        "tag_target_ancestor_of_head": ancestor,
    }
    return C9C8SealDependency(
        **payload,
        dependency_sha256=live.canonical_sha256(payload),
    )


def _patch_dependency(
    monkeypatch: pytest.MonkeyPatch,
    dependency: C9C8SealDependency | None = None,
) -> C9C8SealDependency:
    value = dependency or _dependency()
    monkeypatch.setattr(live, "_verified_c8_dependency", lambda _root: value)
    return value


def _authorization(
    *,
    authorized_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(hours=1),
    audit_key: str = AUDIT_KEY,
) -> C9OperatorAuthorization:
    return commit_c9_operator_authorization(
        cycle_id=CYCLE_ID,
        selected_package_manifest_sha256=MANIFEST_SHA256,
        image_media_type="image/png",
        authorized_at=authorized_at,
        expires_at=expires_at,
        audit_key=audit_key,
    )


def _observation(
    *,
    observed_at: datetime = NOW - timedelta(seconds=30),
    expires_at: datetime = NOW + timedelta(minutes=5),
    audit_key: str = AUDIT_KEY,
    with_visible_labels: bool = True,
) -> C9SurfaceObservation:
    return commit_c9_surface_observation(
        cycle_id=CYCLE_ID,
        observed_at=observed_at,
        expires_at=expires_at,
        audit_key=audit_key,
        work_visible_model_label=(WORK_VISIBLE_MODEL if with_visible_labels else None),
        work_visible_reasoning_label=(WORK_VISIBLE_REASONING if with_visible_labels else None),
        native_chat_visible_model_label=(CHAT_VISIBLE_MODEL if with_visible_labels else None),
        native_chat_visible_reasoning_label=(
            CHAT_VISIBLE_REASONING if with_visible_labels else None
        ),
    )


def _runtime_observation(
    *,
    observed_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=19),
    audit_key: str = AUDIT_KEY,
) -> C9LocalAIRuntimeObservation:
    return commit_c9_local_ai_runtime_observation(
        cycle_id=CYCLE_ID,
        provider_kind=C9LocalAIProviderKind.OTHER_REVIEWED_NATIVE,
        product_name="Reviewed test-native runtime",
        product_version="1.0",
        listening_pid=os.getpid(),
        executable_path=Path(sys.executable).resolve(),
        endpoint=LOCAL_AI_ENDPOINT,
        visible_model_label=LOCAL_AI_MODEL,
        runtime_request_logging_disabled=True,
        runtime_request_persistence_disabled=True,
        operator_confirmed_native_runtime=True,
        operator_confirmed_runtime_privacy_settings=True,
        observed_at=observed_at,
        expires_at=expires_at,
        audit_key=audit_key,
    )


def _local_ai_receipt(
    runtime_observation: C9LocalAIRuntimeObservation,
) -> C9LocalAIReceipt:
    runtime_sha256 = c9_local_ai_runtime_observation_sha256(runtime_observation)
    payload = {
        "version": "1",
        "transport": "openai_compatible_chat_completions_loopback",
        "authentication": "none",
        "proxy_environment_used": False,
        "adapter_persistent_storage_used": False,
        "runtime_observation_sha256": runtime_sha256,
        "endpoint_sha256": runtime_observation.endpoint_sha256,
        "visible_model_label_sha256": (runtime_observation.visible_model_label_sha256),
        "capabilities_sha256": hashlib.sha256(b"capabilities").hexdigest(),
        "image_media_type": "image/png",
        "image_byte_count": 100,
        "image_sha256": hashlib.sha256(b"image").hexdigest(),
        "document_media_type": "text/plain",
        "document_byte_count": 100,
        "document_sha256": hashlib.sha256(b"document").hexdigest(),
        "request_byte_count": 200,
        "request_sha256": hashlib.sha256(b"request").hexdigest(),
        "response_byte_count": 100,
        "response_sha256": hashlib.sha256(b"response").hexdigest(),
        "expected_image_nonce_sha256": hashlib.sha256(b"image-nonce").hexdigest(),
        "expected_document_nonce_sha256": hashlib.sha256(b"document-nonce").hexdigest(),
        "nonce_hashes_verified": True,
        "started_at": ((NOW - timedelta(seconds=10)).isoformat().replace("+00:00", "Z")),
        "completed_at": ((NOW - timedelta(seconds=9)).isoformat().replace("+00:00", "Z")),
        "elapsed_milliseconds": 1_000,
    }
    return C9LocalAIReceipt(
        **payload,
        receipt_sha256=live.canonical_sha256(payload),
    )


def _bundle(
    monkeypatch: pytest.MonkeyPatch,
    *,
    dependency: C9C8SealDependency | None = None,
) -> C9LiveCycleBundle:
    _patch_dependency(monkeypatch, dependency)
    runtime_observation = _runtime_observation()
    return issue_c9_live_cycle_bundle(
        authorization=_authorization(),
        surface_observation=_observation(),
        grant_id=GRANT_ID,
        local_ai_receipt=_local_ai_receipt(runtime_observation),
        local_ai_runtime_observation=runtime_observation,
        root=ROOT,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
        audit_key=AUDIT_KEY,
    )


def test_exact_c9_scope_admits_one_handoff_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)
    decision = verify_c9_live_cycle_bundle(
        bundle=bundle,
        root=ROOT,
        audit_key=AUDIT_KEY,
        evaluated_at=NOW + timedelta(minutes=1),
    )

    assert decision.status is C9AdmissionStatus.READY
    assert decision.reason is C9AdmissionReason.READY
    assert decision.live_actions_allowed is True
    assert decision.effective_tool_count == 1
    assert decision.effective_tools == (C9_TOOL_NAME,)
    assert decision.c8_live_cycle_grant_reused is False
    assert bundle.grant.one_synthetic_work_task is True
    assert bundle.grant.one_new_synthetic_native_chat_conversation is True
    assert bundle.authorization.one_new_synthetic_native_chat_conversation_allowed is True
    assert bundle.grant.required_work_plugin_tool_call_count == 1
    assert bundle.grant.required_native_chat_plugin_tool_call_count == 0
    assert bundle.grant.required_native_chat_manual_attachment_handoff_count == 1
    assert bundle.authorization.work_delivery_mode == "plugin_mcp_rich_content"
    assert (
        bundle.authorization.native_chat_delivery_mode
        == "operator_performed_manual_attachment_handoff"
    )
    assert bundle.authorization.work_plugin_mcp_app_required
    assert bundle.authorization.native_chat_plugin_mcp_app_allowed is False
    assert bundle.authorization.automatic_chat_to_work_switch_allowed is False
    assert bundle.authorization.native_chat_manual_attachment_handoff_required is True
    assert bundle.authorization.native_chat_manual_attachment_handoff_qualifies_as_success is True
    assert bundle.authorization.selected_attachment_count == 2
    assert bundle.authorization.local_ai_literal_loopback_required is True
    assert bundle.authorization.temporary_tunnel_allowed is True
    assert bundle.authorization.temporary_plugin_connection_allowed is True
    assert bundle.authorization.runtime_api_key_operator_managed is True
    assert bundle.surface_observation.work_plugin_mcp_app_visible is True
    assert bundle.surface_observation.work_plugin_mcp_app_eligible is True
    assert bundle.surface_observation.work_plugin_mcp_app_selectable is True
    assert bundle.surface_observation.native_chat_attachment_control_visible is True
    assert bundle.surface_observation.native_chat_file_picker_visible is True
    assert bundle.surface_observation.native_chat_manual_attachment_handoff_available is True
    assert bundle.surface_observation.native_chat_manual_attachment_handoff_used is False


def test_default_state_is_fail_closed() -> None:
    decision = evaluate_c9_admission(
        bundle=None,
        root=ROOT,
        audit_key=None,
        evaluated_at=NOW,
    )

    assert decision.live_actions_allowed is False
    assert decision.effective_tools == ()
    assert decision.reason is C9AdmissionReason.NO_BUNDLE


def test_wrong_audit_key_and_hmac_tampering_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)
    wrong_key = evaluate_c9_admission(
        bundle=bundle,
        root=ROOT,
        audit_key=WRONG_KEY,
        evaluated_at=NOW + timedelta(minutes=1),
    )
    assert wrong_key.live_actions_allowed is False
    assert wrong_key.reason is C9AdmissionReason.AUTHORIZATION_INVALID

    tampered_authorization = bundle.authorization.model_copy(
        update={"authorization_hmac": "0" * 64}
    )
    tampered_bundle = C9LiveCycleBundle.model_construct(
        version="1",
        authorization=tampered_authorization,
        surface_observation=bundle.surface_observation,
        local_ai_runtime_observation=bundle.local_ai_runtime_observation,
        grant=bundle.grant,
    )
    tampered = evaluate_c9_admission(
        bundle=tampered_bundle,
        root=ROOT,
        audit_key=AUDIT_KEY,
        evaluated_at=NOW + timedelta(minutes=1),
    )
    assert tampered.live_actions_allowed is False
    assert tampered.reason is C9AdmissionReason.BINDING_INVALID


def test_stale_surface_cannot_issue_and_expired_grant_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_dependency(monkeypatch)
    stale = _observation(
        observed_at=NOW - timedelta(minutes=10),
        expires_at=NOW - timedelta(minutes=1),
    )
    runtime_observation = _runtime_observation()
    with pytest.raises(ValueError, match="not fresh"):
        issue_c9_live_cycle_bundle(
            authorization=_authorization(),
            surface_observation=stale,
            grant_id=GRANT_ID,
            local_ai_receipt=_local_ai_receipt(runtime_observation),
            local_ai_runtime_observation=runtime_observation,
            root=ROOT,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=15),
            audit_key=AUDIT_KEY,
        )

    bundle = _bundle(monkeypatch)
    expired = evaluate_c9_admission(
        bundle=bundle,
        root=ROOT,
        audit_key=AUDIT_KEY,
        evaluated_at=NOW + timedelta(minutes=16),
    )
    assert expired.live_actions_allowed is False
    assert expired.reason is C9AdmissionReason.GRANT_INVALID


def test_grant_cannot_exceed_twenty_minutes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_dependency(monkeypatch)
    runtime_observation = _runtime_observation()
    with pytest.raises(ValueError, match="exceeds"):
        issue_c9_live_cycle_bundle(
            authorization=_authorization(),
            surface_observation=_observation(),
            grant_id=GRANT_ID,
            local_ai_receipt=_local_ai_receipt(runtime_observation),
            local_ai_runtime_observation=runtime_observation,
            root=ROOT,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=20, seconds=1),
            audit_key=AUDIT_KEY,
        )


def test_c8_dependency_mismatch_and_ancestry_failure_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _dependency()
    bundle = _bundle(monkeypatch, dependency=original)

    _patch_dependency(monkeypatch, _dependency(tag_target="9" * 40))
    mismatch = evaluate_c9_admission(
        bundle=bundle,
        root=ROOT,
        audit_key=AUDIT_KEY,
        evaluated_at=NOW + timedelta(minutes=1),
    )
    assert mismatch.live_actions_allowed is False
    assert mismatch.reason is C9AdmissionReason.C8_SEAL_INVALID

    def reject_ancestry(_root: Path) -> C9C8SealDependency:
        raise live.C9C8AncestryError("not an ancestor")

    monkeypatch.setattr(live, "_verified_c8_dependency", reject_ancestry)
    ancestry = evaluate_c9_admission(
        bundle=bundle,
        root=ROOT,
        audit_key=AUDIT_KEY,
        evaluated_at=NOW + timedelta(minutes=1),
    )
    assert ancestry.live_actions_allowed is False
    assert ancestry.reason is C9AdmissionReason.C8_ANCESTRY_INVALID


def test_c8_dependency_calls_seal_verifier_and_checks_tag_ancestry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Path, str, str]] = []
    verification = SimpleNamespace(
        tag_target="1" * 40,
        covered_head="2" * 40,
        current_head="3" * 40,
        tree_sha256="4" * 64,
        final_attestation_sha256="5" * 64,
        reviewed_outcome="COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED",
        work_call_count=2,
        revocation_verified=True,
    )
    monkeypatch.setattr(
        live,
        "verify_c9_c8_seal_exact",
        lambda root: verification,
    )

    def ancestor(root: Path, tag_target: str, current_head: str) -> bool:
        calls.append((root, tag_target, current_head))
        return True

    monkeypatch.setattr(live, "_is_git_ancestor", ancestor)
    dependency = live._verified_c8_dependency(ROOT)

    assert dependency.tag_target_ancestor_of_head is True
    assert calls == [(ROOT, verification.tag_target, verification.current_head)]

    monkeypatch.setattr(live, "_is_git_ancestor", lambda *_args: False)
    with pytest.raises(ValueError, match="not an ancestor"):
        live._verified_c8_dependency(ROOT)


def test_exact_one_tool_schema_rejects_expansion_and_unknown_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)
    grant_payload = bundle.grant.model_dump(mode="json")
    grant_payload["effective_tools"] = [
        C9_TOOL_NAME,
        "workspace.read_text",
    ]
    grant_payload["effective_tool_count"] = 2
    with pytest.raises(ValidationError):
        C9LiveCycleGrant.model_validate(grant_payload)

    authorization_payload = bundle.authorization.model_dump(mode="json")
    authorization_payload["c8_live_grant"] = {"grant_id": "forbidden"}
    with pytest.raises(ValidationError):
        C9OperatorAuthorization.model_validate(authorization_payload)

    for forbidden_flag in (
        "automatic_chat_to_work_switch_allowed",
        "local_ai_authentication_allowed",
        "arbitrary_local_file_access_allowed",
        "write_actions_allowed",
        "command_execution_allowed",
        "raw_secrets_allowed",
        "real_evidence_access_allowed",
        "protocol_v2_allowed",
    ):
        authorization_payload = bundle.authorization.model_dump(mode="json")
        authorization_payload[forbidden_flag] = True
        with pytest.raises(ValidationError):
            C9OperatorAuthorization.model_validate(authorization_payload)

    surface_payload = bundle.surface_observation.model_dump(mode="json")
    surface_payload["automatic_chat_to_work_switch_used"] = True
    with pytest.raises(ValidationError):
        C9SurfaceObservation.model_validate(surface_payload)


def test_native_chat_manual_handoff_is_required_and_chat_mcp_cannot_be_admitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)

    authorization_payload = bundle.authorization.model_dump(mode="json")
    authorization_payload["native_chat_manual_attachment_handoff_qualifies_as_success"] = False
    with pytest.raises(ValidationError):
        C9OperatorAuthorization.model_validate(authorization_payload)

    surface_payload = bundle.surface_observation.model_dump(mode="json")
    surface_payload["native_chat_manual_attachment_handoff_available"] = False
    with pytest.raises(ValidationError):
        C9SurfaceObservation.model_validate(surface_payload)

    surface_payload = bundle.surface_observation.model_dump(mode="json")
    surface_payload["native_chat_plugin_mcp_app_selectable"] = True
    with pytest.raises(ValidationError):
        C9SurfaceObservation.model_validate(surface_payload)

    grant_payload = bundle.grant.model_dump(mode="json")
    grant_payload["native_chat_delivery_mode"] = "plugin_mcp_rich_content"
    with pytest.raises(ValidationError):
        C9LiveCycleGrant.model_validate(grant_payload)

    grant_payload = bundle.grant.model_dump(mode="json")
    grant_payload["required_native_chat_plugin_tool_call_count"] = 1
    with pytest.raises(ValidationError):
        C9LiveCycleGrant.model_validate(grant_payload)


def test_visible_surface_labels_are_optional_hashed_ui_evidence_only() -> None:
    observed = _observation()

    assert (
        observed.work_visible_model_label_sha256
        == hashlib.sha256(WORK_VISIBLE_MODEL.encode("utf-8")).hexdigest()
    )
    assert (
        observed.work_visible_reasoning_label_sha256
        == hashlib.sha256(WORK_VISIBLE_REASONING.encode("utf-8")).hexdigest()
    )
    assert (
        observed.native_chat_visible_model_label_sha256
        == hashlib.sha256(CHAT_VISIBLE_MODEL.encode("utf-8")).hexdigest()
    )
    assert (
        observed.native_chat_visible_reasoning_label_sha256
        == hashlib.sha256(CHAT_VISIBLE_REASONING.encode("utf-8")).hexdigest()
    )
    assert observed.visible_labels_are_ui_only is True
    assert observed.exact_internal_model_id_observed is False
    serialized = observed.model_dump_json()
    for raw_label in (
        WORK_VISIBLE_MODEL,
        WORK_VISIBLE_REASONING,
        CHAT_VISIBLE_MODEL,
        CHAT_VISIBLE_REASONING,
    ):
        assert raw_label not in serialized

    absent = _observation(with_visible_labels=False)
    assert absent.work_visible_model_label_sha256 is None
    assert absent.work_visible_reasoning_label_sha256 is None
    assert absent.native_chat_visible_model_label_sha256 is None
    assert absent.native_chat_visible_reasoning_label_sha256 is None

    with pytest.raises(ValueError, match="secret-like"):
        commit_c9_surface_observation(
            cycle_id=CYCLE_ID,
            observed_at=NOW - timedelta(seconds=30),
            expires_at=NOW + timedelta(minutes=5),
            audit_key=AUDIT_KEY,
            native_chat_visible_model_label="Bearer synthetic-secret",
        )


def test_metadata_models_contain_no_paths_content_or_runtime_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)
    serialized = bundle.model_dump_json().casefold()

    for forbidden in (
        "control_plane_api_key",
        "control_plane_tunnel_id",
        "authorization: bearer",
        "cookie",
        "source_path",
        "sanitized_bytes",
        "file_content",
        "c8_grant_id",
    ):
        assert forbidden not in serialized
    for raw_label in (
        WORK_VISIBLE_MODEL.casefold(),
        WORK_VISIBLE_REASONING.casefold(),
        CHAT_VISIBLE_REASONING.casefold(),
    ):
        assert raw_label not in serialized
    assert bundle.grant.c8_live_cycle_grant_reused is False


def test_model_tampering_and_cross_cycle_binding_fail_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)
    with pytest.raises(ValidationError, match="HMAC|tool"):
        C9LiveCycleGrant.model_validate(
            {
                **bundle.grant.model_dump(mode="json"),
                "grant_hmac": "0" * 64,
                "effective_tools": [],
            }
        )

    other_surface = bundle.surface_observation.model_copy(
        update={"cycle_id": "c9_cycle_" + "f" * 32}
    )
    with pytest.raises(ValidationError, match="different cycles"):
        C9LiveCycleBundle.model_validate(
            {
                "version": "1",
                "authorization": bundle.authorization.model_dump(mode="json"),
                "surface_observation": other_surface.model_dump(mode="json"),
                "local_ai_runtime_observation": (
                    bundle.local_ai_runtime_observation.model_dump(mode="json")
                ),
                "grant": bundle.grant.model_dump(mode="json"),
            }
        )


def test_runtime_observation_is_required_and_hmac_tampering_denies_live_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)
    missing = bundle.model_dump(mode="json")
    missing.pop("local_ai_runtime_observation")
    with pytest.raises(ValidationError):
        C9LiveCycleBundle.model_validate(missing)

    tampered_observation = bundle.local_ai_runtime_observation.model_copy(
        update={"product_version": "fake-http-only"}
    )
    tampered_bundle = C9LiveCycleBundle.model_construct(
        version="1",
        authorization=bundle.authorization,
        surface_observation=bundle.surface_observation,
        local_ai_runtime_observation=tampered_observation,
        grant=bundle.grant,
    )
    decision = evaluate_c9_admission(
        bundle=tampered_bundle,
        root=ROOT,
        audit_key=AUDIT_KEY,
        evaluated_at=NOW + timedelta(minutes=1),
    )
    assert decision.live_actions_allowed is False
    assert decision.reason is C9AdmissionReason.BINDING_INVALID


def test_expired_native_runtime_observation_denies_even_with_http_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)
    decision = evaluate_c9_admission(
        bundle=bundle,
        root=ROOT,
        audit_key=AUDIT_KEY,
        evaluated_at=bundle.local_ai_runtime_observation.expires_at,
    )
    assert decision.live_actions_allowed is False
    assert decision.reason is C9AdmissionReason.LOCAL_AI_INVALID


def test_issue_rejects_receipt_with_unbound_fake_runtime_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_dependency(monkeypatch)
    runtime_observation = _runtime_observation()
    receipt_payload = _local_ai_receipt(runtime_observation).model_dump(mode="json")
    receipt_payload["runtime_observation_sha256"] = "f" * 64
    receipt_payload["receipt_sha256"] = live.canonical_sha256(
        {key: value for key, value in receipt_payload.items() if key != "receipt_sha256"}
    )
    fake_transport_receipt = C9LocalAIReceipt.model_validate(receipt_payload)

    with pytest.raises(ValueError, match="does not bind"):
        issue_c9_live_cycle_bundle(
            authorization=_authorization(),
            surface_observation=_observation(),
            grant_id=GRANT_ID,
            local_ai_receipt=fake_transport_receipt,
            local_ai_runtime_observation=runtime_observation,
            root=ROOT,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=15),
            audit_key=AUDIT_KEY,
        )
