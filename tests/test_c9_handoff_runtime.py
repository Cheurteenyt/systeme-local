from __future__ import annotations

import hmac
import json
import os
import sys
import threading
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

import mcp.types as mcp_types
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from systeme_local_gateway import c9_handoff_runtime as runtime
from systeme_local_gateway import c9_live_cycle, c9_local_ai
from systeme_local_gateway import c9_synthetic_fixtures as synthetic
from systeme_local_gateway.audit import AuditLog
from systeme_local_gateway.auth import compute_task_signature
from systeme_local_gateway.c9_attachment_security import (
    C9AttachmentSecurity,
    C9AttachmentSecurityError,
    C9AttachmentSecurityReason,
)
from systeme_local_gateway.c9_control import C9LocalControlGuard
from systeme_local_gateway.c9_control_api import (
    C9LocalControlPlane,
    build_c9_control_router,
)
from systeme_local_gateway.c9_handoff_runtime import (
    C9ChatExportDescriptor,
    C9DynamicMcpRegistry,
    C9HandoffAdmission,
    C9HandoffCapabilityHandler,
    C9HandoffCoordinator,
    C9HandoffError,
    C9HandoffReason,
    C9HandoffRenderer,
    C9HandoffStageReceipt,
    C9RichExecutionDescriptor,
    C9WorkExecutionDescriptor,
)
from systeme_local_gateway.c9_local_ai import (
    C9LocalAICapabilities,
    C9LocalAIConfig,
    C9LocalAIError,
    C9LocalAIErrorCode,
    C9LocalAIInference,
    C9LocalAIOutput,
    C9LocalAIReceipt,
    C9LocalAIRuntimeContinuitySnapshot,
    C9LocalAIRuntimeObservation,
)
from systeme_local_gateway.c9_manual_export import (
    C9ManualExportError,
    C9ManualExportManager,
    C9ManualExportReason,
)
from systeme_local_gateway.c9_synthetic_fixtures import (
    C9SyntheticFixtureKind,
    generate_c9_synthetic_fixtures,
)
from systeme_local_gateway.c9_work_bridge import (
    C9CapabilityEvidence,
    C9McpHostCapabilities,
    C9RichSurface,
    commit_mcp_host_capabilities,
)
from systeme_local_gateway.executor import CapabilityExecutor
from systeme_local_gateway.mcp_runtime import McpTaskAdapter
from systeme_local_gateway.models import TaskEnvelope
from systeme_local_gateway.policy import PolicyEngine
from systeme_local_gateway.task_processor import TaskProcessor

NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
IMAGE_NONCE = "C9" + "A" * 32
DOCUMENT_NONCE = "C9" + "B" * 32
AUDIT_KEY = "c9-runtime-audit-key-" + "x" * 40
OPERATOR_IDENTITY = "c9 synthetic test operator"
CONTROL_TOKEN = "c9-runtime-control-test-token-" + "t" * 40
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Clock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class _FakeLocalAIRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: Any) -> C9LocalAIInference:
        image = bytes(kwargs["image_bytes"])
        document = bytes(kwargs["document_bytes"])
        image_hash = str(kwargs["expected_image_nonce_sha256"])
        document_hash = str(kwargs["expected_document_nonce_sha256"])
        assert image_hash == sha256(IMAGE_NONCE.encode()).hexdigest()
        assert document_hash == sha256(DOCUMENT_NONCE.encode()).hexdigest()
        assert kwargs["document_media_type"] == "text/plain"
        self.calls.append(
            {
                "image_sha256": sha256(image).hexdigest(),
                "document_sha256": sha256(document).hexdigest(),
                "expected_image_nonce_sha256": image_hash,
                "expected_document_nonce_sha256": document_hash,
            }
        )
        config = kwargs["config"]
        assert isinstance(config, C9LocalAIConfig)
        payload: dict[str, object] = {
            "version": "1",
            "transport": "openai_compatible_chat_completions_loopback",
            "authentication": "none",
            "proxy_environment_used": False,
            "adapter_persistent_storage_used": False,
            "runtime_observation_sha256": config.runtime_observation_sha256,
            "endpoint_sha256": sha256(config.endpoint.encode()).hexdigest(),
            "visible_model_label_sha256": sha256(config.visible_model_label.encode()).hexdigest(),
            "capabilities_sha256": c9_local_ai._canonical_sha256(
                config.capabilities.model_dump(mode="json")
            ),
            "image_media_type": kwargs["image_media_type"],
            "image_byte_count": len(image),
            "image_sha256": sha256(image).hexdigest(),
            "document_media_type": "text/plain",
            "document_byte_count": len(document),
            "document_sha256": sha256(document).hexdigest(),
            "request_byte_count": len(image) + len(document),
            "request_sha256": sha256(image + document).hexdigest(),
            "response_byte_count": 64,
            "response_sha256": "c" * 64,
            "expected_image_nonce_sha256": image_hash,
            "expected_document_nonce_sha256": document_hash,
            "nonce_hashes_verified": True,
            "started_at": NOW.isoformat().replace("+00:00", "Z"),
            "completed_at": NOW.isoformat().replace("+00:00", "Z"),
            "elapsed_milliseconds": 0,
        }
        receipt = C9LocalAIReceipt.model_validate(
            {
                **payload,
                "receipt_sha256": c9_local_ai._canonical_sha256(payload),
            }
        )
        return C9LocalAIInference._from_verified(
            output=C9LocalAIOutput(
                version="1",
                image_nonce=IMAGE_NONCE,
                document_nonce=DOCUMENT_NONCE,
            ),
            receipt=receipt,
        )


class _FakeRuntimeContinuityVerifier:
    def __init__(self, *, takeover_after_inference: bool = False) -> None:
        self.takeover_after_inference = takeover_after_inference
        self.calls: list[tuple[int, str]] = []

    def __call__(
        self,
        observation: C9LocalAIRuntimeObservation,
        *,
        endpoint: str,
    ) -> C9LocalAIRuntimeContinuitySnapshot:
        self.calls.append((observation.listening_pid, endpoint))
        listening_pid = observation.listening_pid
        if self.takeover_after_inference and len(self.calls) == 2:
            listening_pid += 1
        return C9LocalAIRuntimeContinuitySnapshot(
            listening_pid=listening_pid,
            process_create_time=1.0,
            executable_basename=observation.executable_basename,
            executable_sha256=observation.executable_sha256,
            endpoint_sha256=observation.endpoint_sha256,
        )


def _dependency() -> c9_live_cycle.C9C8SealDependency:
    payload = {
        "version": "1",
        "status": "verified",
        "tag_target": "1" * 40,
        "covered_head": "2" * 40,
        "current_head": "3" * 40,
        "tree_sha256": "4" * 64,
        "final_attestation_sha256": "5" * 64,
        "reviewed_outcome": "COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED",
        "work_call_count": 2,
        "revocation_verified": True,
        "tag_target_ancestor_of_head": True,
    }
    return c9_live_cycle.C9C8SealDependency.model_validate(
        {
            **payload,
            "dependency_sha256": c9_live_cycle.canonical_sha256(payload),
        }
    )


def _capabilities(surface: C9RichSurface) -> C9McpHostCapabilities:
    evidence = C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED
    return commit_mcp_host_capabilities(
        surface=surface,
        call_tool_result_content=evidence,
        image_content=evidence,
        embedded_text_resource=evidence,
        window_openai_upload_file_available=False,
        window_openai_image_ids_available=False,
        observed_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=9),
    )


def _patch_nonces(monkeypatch: pytest.MonkeyPatch) -> None:
    def fixed(excluding: str | None = None) -> str:
        return IMAGE_NONCE if excluding is None else DOCUMENT_NONCE

    monkeypatch.setattr(synthetic, "_new_nonce", fixed)


def _prepared(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    runtime_continuity_verifier: _FakeRuntimeContinuityVerifier | None = None,
) -> tuple[
    C9HandoffCoordinator,
    C9DynamicMcpRegistry,
    C9HandoffRenderer,
    C9HandoffStageReceipt,
    _Clock,
    Path,
]:
    _patch_nonces(monkeypatch)
    dependency = _dependency()
    monkeypatch.setattr(
        c9_live_cycle,
        "_verified_c8_dependency",
        lambda _root: dependency,
    )
    fixture_root = (tmp_path / "fixtures").resolve()
    fixture_root.mkdir(mode=0o700, parents=True)
    fixture = generate_c9_synthetic_fixtures(
        fixture_root,
        generated_at=NOW,
    )
    manual_root = (tmp_path / "manual").resolve()
    admission_file = (tmp_path / "admission.json").resolve()
    runner = _FakeLocalAIRunner()
    clock = _Clock()
    runtime_observation = c9_local_ai.commit_c9_local_ai_runtime_observation(
        cycle_id="c9_cycle_" + "a" * 32,
        provider_kind=(c9_local_ai.C9LocalAIProviderKind.OTHER_REVIEWED_NATIVE),
        product_name="Reviewed test-native runtime",
        product_version="1.0",
        listening_pid=os.getpid(),
        executable_path=Path(sys.executable).resolve(),
        endpoint="http://127.0.0.1:11434/v1/chat/completions",
        visible_model_label="local-synthetic-test",
        runtime_request_logging_disabled=True,
        runtime_request_persistence_disabled=True,
        operator_confirmed_native_runtime=True,
        operator_confirmed_runtime_privacy_settings=True,
        observed_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=9),
        audit_key=AUDIT_KEY,
    )
    runtime_observation_sha256 = c9_local_ai.c9_local_ai_runtime_observation_sha256(
        runtime_observation
    )
    verifier = runtime_continuity_verifier or _FakeRuntimeContinuityVerifier()
    coordinator = C9HandoffCoordinator(
        security=C9AttachmentSecurity(),
        local_ai_config=C9LocalAIConfig(
            endpoint="http://127.0.0.1:11434/v1/chat/completions",
            visible_model_label="local-synthetic-test",
            runtime_observation_sha256=runtime_observation_sha256,
            capabilities=C9LocalAICapabilities(
                image_input=True,
                utf8_document_input=True,
                structured_json_output=True,
            ),
        ),
        local_ai_runtime_observation=runtime_observation,
        manual_manager=C9ManualExportManager(
            manual_root,
            started_at=NOW,
        ),
        mcp_capabilities={
            C9RichSurface.WORK: _capabilities(C9RichSurface.WORK),
        },
        repository_root=ROOT,
        admission_file=admission_file,
        audit_key=AUDIT_KEY,
        clock=clock,
        local_ai_runner=runner,
        local_ai_runtime_continuity_verifier=verifier,
    )
    registry = C9DynamicMcpRegistry(coordinator)
    renderer = C9HandoffRenderer(coordinator, clock=clock)
    assert registry.list_tools() == ()
    staged = coordinator.stage(
        fixture=fixture,
        purpose="C9 synthetic image and UTF-8 document handoff",
        staged_at=NOW,
    )
    assert len(runner.calls) == 1
    assert len(verifier.calls) == 2
    assert registry.list_tools() == ()
    return coordinator, registry, renderer, staged, clock, admission_file


def _approve(
    coordinator: C9HandoffCoordinator,
    staged: C9HandoffStageReceipt,
) -> C9HandoffAdmission:
    authorization = c9_live_cycle.commit_c9_operator_authorization(
        cycle_id="c9_cycle_" + "a" * 32,
        selected_package_manifest_sha256=staged.work_manifest_sha256,
        image_media_type="image/png",
        authorized_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
        audit_key=AUDIT_KEY,
    )
    observation = c9_live_cycle.commit_c9_surface_observation(
        cycle_id=authorization.cycle_id,
        observed_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=9),
        audit_key=AUDIT_KEY,
    )
    return coordinator.approve_handoff(
        handoff_id=staged.handoff_id,
        operator_confirmed=True,
        operator_identity=OPERATOR_IDENTITY,
        authorization=authorization,
        surface_observation=observation,
        grant_id="c9_grant_" + "b" * 32,
        approved_at=NOW,
    )


def _nonce_mapping(staged: C9HandoffStageReceipt) -> dict[str, str]:
    return {
        item.attachment_id: (
            IMAGE_NONCE if item.kind is C9SyntheticFixtureKind.IMAGE else DOCUMENT_NONCE
        )
        for item in staged.attachments
    }


def _native_chat_response(
    handoff_id: str,
    *,
    image_nonce: str = IMAGE_NONCE,
    document_nonce: str = DOCUMENT_NONCE,
) -> str:
    return json.dumps(
        {
            "delivery_mode": "operator_performed_manual_attachment_handoff",
            "handoff_id": handoff_id,
            "observed_document_nonce": document_nonce,
            "observed_image_nonce": image_nonce,
            "surface": "chat",
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _confirm_work(
    coordinator: C9HandoffCoordinator,
    staged: C9HandoffStageReceipt,
    execution: C9RichExecutionDescriptor,
) -> None:
    coordinator.confirm_rich_surface(
        handoff_id=staged.handoff_id,
        surface=C9RichSurface.WORK,
        surface_task_id=staged.work_task_id,
        descriptor_sha256=execution.expansion_descriptor_sha256,
        manifest_sha256=staged.work_manifest_sha256,
        observed_nonces=_nonce_mapping(staged),
        response_text=f"Observed {IMAGE_NONCE} and {DOCUMENT_NONCE}.",
        confirmed_at=NOW,
    )


def _render_work(
    coordinator: C9HandoffCoordinator,
    renderer: C9HandoffRenderer,
    staged: C9HandoffStageReceipt,
) -> tuple[C9RichExecutionDescriptor, mcp_types.CallToolResult]:
    execution = coordinator.execute_rich_handoff(
        staged.handoff_id,
        surface=C9RichSurface.WORK,
        executed_at=NOW,
    )
    prepared = renderer.prepare(
        name="systeme_local_attachment_handoff",
        arguments={"handoff_id": staged.handoff_id, "surface": "work"},
        output=execution.model_dump(mode="json"),
        metadata={"systeme-local/audit-id": "audit-metadata-only"},
    )
    assert prepared is not None
    assert coordinator.status(evaluated_at=NOW).work_rendered is False
    rendered = prepared.result
    prepared.commit()
    return execution, rendered


def _work_flow(
    coordinator: C9HandoffCoordinator,
    renderer: C9HandoffRenderer,
    staged: C9HandoffStageReceipt,
) -> tuple[C9RichExecutionDescriptor, mcp_types.CallToolResult]:
    execution, rendered = _render_work(coordinator, renderer, staged)
    _confirm_work(coordinator, staged, execution)
    return execution, rendered


def _prepare_native_chat_handoff(
    coordinator: C9HandoffCoordinator,
    staged: C9HandoffStageReceipt,
    *,
    ttl: timedelta = timedelta(minutes=5),
) -> C9ChatExportDescriptor:
    return coordinator.prepare_native_chat_handoff(
        handoff_id=staged.handoff_id,
        created_at=NOW,
        ttl=ttl,
    )


def _picker_claim_sha256(
    coordinator: C9HandoffCoordinator,
    staged: C9HandoffStageReceipt,
) -> str:
    return coordinator.native_chat_picker_claim_receipt(
        handoff_id=staged.handoff_id,
    ).receipt_sha256


def test_stage_checks_runtime_continuity_immediately_around_inference(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    verifier = _FakeRuntimeContinuityVerifier()

    _prepared(
        monkeypatch,
        tmp_path,
        runtime_continuity_verifier=verifier,
    )

    assert verifier.calls == [
        (
            os.getpid(),
            "http://127.0.0.1:11434/v1/chat/completions",
        ),
        (
            os.getpid(),
            "http://127.0.0.1:11434/v1/chat/completions",
        ),
    ]


def test_runtime_takeover_after_inference_fails_closed_and_cleans_fixtures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    verifier = _FakeRuntimeContinuityVerifier(
        takeover_after_inference=True,
    )

    with pytest.raises(C9AttachmentSecurityError) as error:
        _prepared(
            monkeypatch,
            tmp_path,
            runtime_continuity_verifier=verifier,
        )

    assert error.value.reason is C9AttachmentSecurityReason.LOCAL_INSPECTION_FAILED
    continuity_error = error.value.__cause__
    assert isinstance(continuity_error, C9LocalAIError)
    assert continuity_error.code is C9LocalAIErrorCode.RUNTIME_CONTINUITY_FAILED
    assert str(error.value) == "C9 local readonly inspection failed"
    assert len(verifier.calls) == 2
    assert not any((tmp_path / "fixtures").iterdir())


def test_registry_is_zero_before_grant_and_exactly_one_after_combined_approval(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, registry, _, staged, _, admission_file = _prepared(
        monkeypatch,
        tmp_path,
    )
    admission = _approve(coordinator, staged)

    assert coordinator._record is not None
    assert len(coordinator._record.work_leases) == 2
    assert len(coordinator._record.chat_leases) == 2
    assert coordinator._record.chat_export is None
    assert coordinator._record.chat_export_descriptor is None
    assert coordinator._record.chat_confirmation is None
    assert "manual_fallback" not in staged.model_dump_json()
    assert "manual_fallback" not in admission.combined_approval.model_dump_json()
    assert tuple(tool.name for tool in registry.list_tools()) == (
        "systeme_local_attachment_handoff",
    )
    assert registry.protocol_tools()[0]["inputSchema"]["required"] == [
        "handoff_id",
        "surface",
    ]
    assert admission.combined_approval.work_approval_sha256 != (
        admission.combined_approval.chat_approval_sha256
    )
    assert (
        admission.live_cycle_bundle.grant.selected_package_manifest_sha256
        == staged.work_manifest_sha256
    )
    assert admission.live_cycle_bundle.grant.c8_tag_target == "1" * 40
    assert admission.live_cycle_bundle.grant.c8_live_cycle_grant_reused is False
    committed = C9HandoffAdmission.model_validate_json(admission_file.read_text(encoding="utf-8"))
    assert committed == admission


def test_work_execution_descriptor_is_atomically_persisted_before_return(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, registry, _, staged, _, admission_file = _prepared(
        monkeypatch,
        tmp_path,
    )
    _approve(coordinator, staged)

    execution = coordinator.execute_work_handoff(
        staged.handoff_id,
        executed_at=NOW,
    )

    execution_file = admission_file.parent / "work-execution.json"
    committed = C9WorkExecutionDescriptor.model_validate_json(
        execution_file.read_text(encoding="utf-8")
    )
    assert committed == execution
    assert execution.surface is C9RichSurface.WORK
    assert registry.list_tools() == ()
    serialized = execution_file.read_text(encoding="utf-8")
    assert IMAGE_NONCE not in serialized
    assert DOCUMENT_NONCE not in serialized


def test_existing_work_execution_file_fails_terminal_and_zeroizes_buffers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, registry, _, staged, _, admission_file = _prepared(
        monkeypatch,
        tmp_path,
    )
    _approve(coordinator, staged)
    execution_file = admission_file.parent / "work-execution.json"
    execution_file.write_text('{"collision":true}\n', encoding="utf-8")
    captured: list[bytearray] = []
    original_copy = runtime._copy_payloads

    def capture(
        payloads: tuple[
            tuple[runtime.C9AttachmentDescriptor, memoryview],
            ...,
        ],
    ) -> tuple[tuple[runtime.C9AttachmentDescriptor, bytearray], ...]:
        copied = original_copy(payloads)
        captured.extend(content for _, content in copied)
        return copied

    monkeypatch.setattr(runtime, "_copy_payloads", capture)

    with pytest.raises(C9HandoffError) as raised:
        coordinator.execute_work_handoff(
            staged.handoff_id,
            executed_at=NOW,
        )

    assert raised.value.reason is C9HandoffReason.ATOMIC_COMMIT_FAILED
    assert captured
    assert all(not any(content) for content in captured)
    assert coordinator._record is not None
    assert coordinator._record.terminal_failure is True
    assert C9RichSurface.WORK not in coordinator._record.pending_rich
    assert registry.list_tools() == ()
    assert execution_file.read_text(encoding="utf-8") == '{"collision":true}\n'


def test_combined_binding_rejects_wrong_selected_manifest_and_tampering(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, _, _, staged, _, _ = _prepared(monkeypatch, tmp_path)
    wrong = c9_live_cycle.commit_c9_operator_authorization(
        cycle_id="c9_cycle_" + "a" * 32,
        selected_package_manifest_sha256="f" * 64,
        image_media_type="image/png",
        authorized_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
        audit_key=AUDIT_KEY,
    )
    observation = c9_live_cycle.commit_c9_surface_observation(
        cycle_id=wrong.cycle_id,
        observed_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=9),
        audit_key=AUDIT_KEY,
    )

    with pytest.raises(
        C9HandoffError,
        match="authorization",
    ) as raised:
        coordinator.approve_handoff(
            handoff_id=staged.handoff_id,
            operator_confirmed=True,
            operator_identity=OPERATOR_IDENTITY,
            authorization=wrong,
            surface_observation=observation,
            grant_id="c9_grant_" + "b" * 32,
            approved_at=NOW,
        )
    assert raised.value.reason is C9HandoffReason.MANIFEST_BINDING_MISMATCH

    coordinator2, _, _, staged2, _, _ = _prepared(
        monkeypatch,
        tmp_path / "second",
    )
    admission = _approve(coordinator2, staged2)
    payload = admission.model_dump(mode="python")
    payload["combined_approval"]["work_manifest_sha256"] = "e" * 64
    with pytest.raises(ValidationError, match="digest|bind"):
        C9HandoffAdmission.model_validate(payload)


def test_work_then_native_chat_manual_is_strict_and_both_halves_are_one_use(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, registry, renderer, staged, _, _ = _prepared(
        monkeypatch,
        tmp_path,
    )
    _approve(coordinator, staged)

    with pytest.raises(C9HandoffError) as out_of_order:
        _prepare_native_chat_handoff(coordinator, staged)
    assert out_of_order.value.reason is C9HandoffReason.SURFACE_ORDER_REJECTED

    work_execution, work_rendered = _work_flow(coordinator, renderer, staged)
    assert [type(item) for item in work_rendered.content] == [
        mcp_types.TextContent,
        mcp_types.ImageContent,
        mcp_types.EmbeddedResource,
    ]
    assert work_rendered.structuredContent == work_execution.model_dump(mode="json")
    assert registry.list_tools() == ()
    assert (
        coordinator._mcp_capabilities[C9RichSurface.WORK].call_tool_result_content
        is C9CapabilityEvidence.DOCUMENTED_AND_RUNTIME_OBSERVED
    )

    exported = _prepare_native_chat_handoff(coordinator, staged)
    assert exported.delivery_mode == "operator_performed_manual_attachment_handoff"
    assert exported.qualifies_as_native_chat_success is False
    assert exported.plugin_mcp_invocation_claimed is False
    assert exported.automated_attachment_claimed is False
    with pytest.raises(C9HandoffError) as export_replay:
        _prepare_native_chat_handoff(coordinator, staged)
    assert export_replay.value.reason is C9HandoffReason.CHAT_REPLAY_REJECTED

    paths = coordinator.claim_native_chat_handoff_paths(
        handoff_id=staged.handoff_id,
        export_id=exported.export_id,
        claimed_at=NOW,
    )
    assert len(paths) == 2
    assert all(path.is_file() for path in paths)
    with pytest.raises(C9ManualExportError) as claim_replay:
        coordinator.claim_native_chat_handoff_paths(
            handoff_id=staged.handoff_id,
            export_id=exported.export_id,
            claimed_at=NOW,
        )
    assert claim_replay.value.reason is C9ManualExportReason.EXPORT_REPLAY

    response_text = _native_chat_response(staged.handoff_id)
    chat_receipt = coordinator.confirm_native_chat_handoff(
        handoff_id=staged.handoff_id,
        chat_picker_claim_receipt_sha256=_picker_claim_sha256(coordinator, staged),
        observed_image_nonce=IMAGE_NONCE,
        observed_document_nonce=DOCUMENT_NONCE,
        response_text=response_text,
        confirmed_at=NOW,
    )
    assert chat_receipt.status == "native_chat_attachments_visibly_consumed"
    assert chat_receipt.delivery_mode == "operator_performed_manual_attachment_handoff"
    assert chat_receipt.qualifies_as_native_chat_success is True
    assert chat_receipt.plugin_mcp_invocation_claimed is False
    assert chat_receipt.automated_attachment_claimed is False
    assert chat_receipt.chat_export_id == exported.export_id
    assert chat_receipt.chat_export_descriptor_sha256 == exported.descriptor_sha256
    assert chat_receipt.chat_picker_claim_receipt_sha256 == _picker_claim_sha256(
        coordinator,
        staged,
    )
    assert all(not path.exists() for path in paths)
    with pytest.raises(C9HandoffError) as confirmation_replay:
        coordinator.confirm_native_chat_handoff(
            handoff_id=staged.handoff_id,
            chat_picker_claim_receipt_sha256=_picker_claim_sha256(coordinator, staged),
            observed_image_nonce=IMAGE_NONCE,
            observed_document_nonce=DOCUMENT_NONCE,
            response_text=response_text,
            confirmed_at=NOW,
        )
    assert confirmation_replay.value.reason is C9HandoffReason.CHAT_REPLAY_REJECTED

    status = coordinator.status(evaluated_at=NOW)
    assert status.work_confirmed is True
    assert status.native_chat_mcp_invoked is False
    assert status.native_chat_handoff_exported is True
    assert status.native_chat_picker_claimed is True
    assert status.native_chat_handoff_confirmed is True
    assert status.rich_confirmation_count == 1
    assert status.rich_call_count == 1

    with pytest.raises(C9HandoffError) as work_replay:
        coordinator.execute_work_handoff(staged.handoff_id, executed_at=NOW)
    assert work_replay.value.reason is C9HandoffReason.RICH_SURFACE_REPLAY_REJECTED
    with pytest.raises(C9HandoffError) as render_replay:
        renderer.prepare(
            name="systeme_local_attachment_handoff",
            arguments={"handoff_id": staged.handoff_id, "surface": "work"},
            output=work_execution.model_dump(mode="json"),
            metadata={},
        )
    assert render_replay.value.reason is C9HandoffReason.RICH_RENDER_REPLAY_REJECTED
    close = coordinator.close(closed_at=NOW)
    assert close.rich_call_count == 1
    assert close.rich_confirmation_count == 1
    assert close.native_chat_manual_handoff_used is True


def test_chat_mcp_execute_render_confirm_and_legacy_fallback_are_unsupported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, registry, renderer, staged, _, _ = _prepared(
        monkeypatch,
        tmp_path,
    )
    _approve(coordinator, staged)

    with pytest.raises(C9HandoffError) as direct_chat:
        coordinator.execute_rich_handoff(
            staged.handoff_id,
            surface=C9RichSurface.CHAT,
            executed_at=NOW,
        )
    assert direct_chat.value.reason is C9HandoffReason.UNSUPPORTED_SURFACE
    assert registry.list_tools() == ()
    with pytest.raises(C9HandoffError) as work_after_direct_chat:
        coordinator.execute_work_handoff(
            staged.handoff_id,
            executed_at=NOW,
        )
    assert work_after_direct_chat.value.reason is C9HandoffReason.HANDOFF_EXPIRED

    coordinator, registry, renderer, staged, _, _ = _prepared(
        monkeypatch,
        tmp_path / "work-only",
    )
    _approve(coordinator, staged)
    with pytest.raises(C9HandoffError) as legacy_fallback:
        coordinator.prepare_manual_fallback(
            handoff_id=staged.handoff_id,
            operator_confirmed_fallback=True,
            operator_identity=OPERATOR_IDENTITY,
            created_at=NOW,
        )
    assert legacy_fallback.value.reason is C9HandoffReason.UNSUPPORTED_SURFACE
    assert len(registry.list_tools()) == 1

    work_execution = coordinator.execute_work_handoff(
        staged.handoff_id,
        executed_at=NOW,
    )
    assert registry.list_tools() == ()
    with pytest.raises(C9HandoffError) as chat_render:
        renderer.prepare(
            name="systeme_local_attachment_handoff",
            arguments={"handoff_id": staged.handoff_id, "surface": "chat"},
            output=work_execution.model_dump(mode="json"),
            metadata={},
        )
    assert chat_render.value.reason is C9HandoffReason.UNSUPPORTED_SURFACE
    with pytest.raises(C9HandoffError) as chat_confirmation:
        coordinator.confirm_rich_surface(
            handoff_id=staged.handoff_id,
            surface=C9RichSurface.CHAT,
            surface_task_id=staged.chat_task_id,
            descriptor_sha256=work_execution.expansion_descriptor_sha256,
            manifest_sha256=staged.chat_manifest_sha256,
            observed_nonces=_nonce_mapping(staged),
            response_text=f"Observed {IMAGE_NONCE} and {DOCUMENT_NONCE}.",
            confirmed_at=NOW,
        )
    assert chat_confirmation.value.reason is C9HandoffReason.UNSUPPORTED_SURFACE
    status = coordinator.status(evaluated_at=NOW)
    assert status.native_chat_mcp_invoked is False
    assert status.rich_call_count == 1
    assert status.rich_confirmation_count == 0

    rejected_coordinator, rejected_registry, _, rejected_stage, _, _ = _prepared(
        monkeypatch,
        tmp_path / "forbidden-chat",
    )
    _approve(rejected_coordinator, rejected_stage)
    rejected_handler = C9HandoffCapabilityHandler(rejected_coordinator)
    with pytest.raises(C9HandoffError) as handler_chat:
        rejected_handler(
            {"handoff_id": rejected_stage.handoff_id, "surface": "chat"},
            {},
        )
    assert handler_chat.value.reason is C9HandoffReason.UNSUPPORTED_SURFACE
    assert rejected_registry.list_tools() == ()
    with pytest.raises(C9HandoffError) as work_after_chat_attempt:
        rejected_coordinator.execute_work_handoff(
            rejected_stage.handoff_id,
            executed_at=NOW,
        )
    assert work_after_chat_attempt.value.reason is C9HandoffReason.HANDOFF_EXPIRED


def test_forbidden_chat_mcp_attempt_after_work_blocks_manual_chat_handoff(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, registry, renderer, staged, _, _ = _prepared(
        monkeypatch,
        tmp_path,
    )
    _approve(coordinator, staged)
    _work_flow(coordinator, renderer, staged)
    handler = C9HandoffCapabilityHandler(coordinator)

    with pytest.raises(C9HandoffError) as rejected_chat_mcp:
        handler(
            {"handoff_id": staged.handoff_id, "surface": "chat"},
            {},
        )
    assert rejected_chat_mcp.value.reason is C9HandoffReason.UNSUPPORTED_SURFACE
    assert registry.list_tools() == ()

    with pytest.raises(C9HandoffError) as blocked_manual_chat:
        _prepare_native_chat_handoff(coordinator, staged)
    assert blocked_manual_chat.value.reason is C9HandoffReason.HANDOFF_EXPIRED
    assert coordinator.status(evaluated_at=NOW).native_chat_handoff_exported is False


def test_cross_handoff_and_expired_grant_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, registry, _, staged, clock, _ = _prepared(
        monkeypatch,
        tmp_path,
    )
    _approve(coordinator, staged)
    with pytest.raises(C9HandoffError) as cross:
        coordinator.execute_rich_handoff(
            "c9_handoff_" + "f" * 32,
            surface=C9RichSurface.WORK,
            executed_at=NOW,
        )
    assert cross.value.reason is C9HandoffReason.CROSS_HANDOFF_REJECTED
    assert len(registry.list_tools()) == 1

    clock.value = NOW + timedelta(minutes=11)
    assert registry.list_tools() == ()
    with pytest.raises(C9HandoffError) as expired:
        coordinator.execute_rich_handoff(
            staged.handoff_id,
            surface=C9RichSurface.WORK,
            executed_at=clock.value,
        )
    assert expired.value.reason is C9HandoffReason.HANDOFF_EXPIRED


def test_renderer_binding_failure_does_not_consume_pending_delivery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, _, renderer, staged, _, _ = _prepared(monkeypatch, tmp_path)
    _approve(coordinator, staged)
    execution = coordinator.execute_rich_handoff(
        staged.handoff_id,
        surface=C9RichSurface.WORK,
        executed_at=NOW,
    )
    with pytest.raises(C9HandoffError) as cross:
        renderer.prepare(
            name="systeme_local_attachment_handoff",
            arguments={
                "handoff_id": "c9_handoff_" + "f" * 32,
                "surface": "work",
            },
            output=execution.model_dump(mode="json"),
            metadata={},
        )
    assert cross.value.reason is C9HandoffReason.RENDER_BINDING_MISMATCH
    prepared = renderer.prepare(
        name="systeme_local_attachment_handoff",
        arguments={"handoff_id": staged.handoff_id, "surface": "work"},
        output=execution.model_dump(mode="json"),
        metadata={},
    )
    assert prepared is not None
    assert coordinator.status(evaluated_at=NOW).work_rendered is False
    prepared.commit()
    assert coordinator.status(evaluated_at=NOW).work_rendered is True


def test_renderer_failure_zeroes_and_discards_private_pending_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, _, renderer, staged, _, _ = _prepared(monkeypatch, tmp_path)
    _approve(coordinator, staged)
    execution = coordinator.execute_rich_handoff(
        staged.handoff_id,
        surface=C9RichSurface.WORK,
        executed_at=NOW,
    )
    assert coordinator._record is not None
    pending = coordinator._record.pending_rich[C9RichSurface.WORK]
    buffers = [content for _, content in pending.payloads]
    assert all(any(content) for content in buffers)

    def fail(**_kwargs: object) -> mcp_types.CallToolResult:
        if not _kwargs:  # keeps the callable total for static analysis
            return mcp_types.CallToolResult(content=[], isError=False)
        raise RuntimeError("synthetic renderer failure")

    original_builder = runtime._build_mcp_result
    monkeypatch.setattr(runtime, "_build_mcp_result", fail)
    with pytest.raises(RuntimeError, match="synthetic renderer failure"):
        renderer.prepare(
            name="systeme_local_attachment_handoff",
            arguments={"handoff_id": staged.handoff_id, "surface": "work"},
            output=execution.model_dump(mode="json"),
            metadata={},
        )
    assert all(not any(content) for content in buffers)
    assert C9RichSurface.WORK not in coordinator._record.pending_rich
    assert coordinator.status(evaluated_at=NOW).work_rendered is False
    monkeypatch.setattr(runtime, "_build_mcp_result", original_builder)
    with pytest.raises(C9HandoffError) as replay:
        renderer.prepare(
            name="systeme_local_attachment_handoff",
            arguments={"handoff_id": staged.handoff_id, "surface": "work"},
            output=execution.model_dump(mode="json"),
            metadata={},
        )
    assert replay.value.reason is C9HandoffReason.HANDOFF_EXPIRED
    with pytest.raises(C9HandoffError):
        _confirm_work(coordinator, staged, execution)


def test_prepared_render_is_uncommitted_and_can_roll_back_after_commit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, _, renderer, staged, _, _ = _prepared(monkeypatch, tmp_path)
    _approve(coordinator, staged)
    execution = coordinator.execute_rich_handoff(
        staged.handoff_id,
        surface=C9RichSurface.WORK,
        executed_at=NOW,
    )
    assert coordinator._record is not None
    pending = coordinator._record.pending_rich[C9RichSurface.WORK]
    buffers = [content for _, content in pending.payloads]

    prepared = renderer.prepare(
        name="systeme_local_attachment_handoff",
        arguments={"handoff_id": staged.handoff_id, "surface": "work"},
        output=execution.model_dump(mode="json"),
        metadata={},
    )

    assert prepared is not None
    assert coordinator.status(evaluated_at=NOW).work_rendered is False
    assert C9RichSurface.WORK in coordinator._record.pending_rich
    assert all(any(content) for content in buffers)

    prepared.commit()
    assert coordinator.status(evaluated_at=NOW).work_rendered is True
    assert C9RichSurface.WORK not in coordinator._record.pending_rich
    assert all(not any(content) for content in buffers)

    prepared.abort()
    assert coordinator.status(evaluated_at=NOW).work_rendered is False
    with pytest.raises(C9HandoffError):
        _confirm_work(coordinator, staged, execution)


def test_native_chat_nonce_mismatch_consumes_proof_and_deletes_export(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, _, renderer, staged, _, _ = _prepared(monkeypatch, tmp_path)
    _approve(coordinator, staged)
    _work_flow(coordinator, renderer, staged)
    exported = _prepare_native_chat_handoff(coordinator, staged)
    paths = coordinator.claim_native_chat_handoff_paths(
        handoff_id=staged.handoff_id,
        export_id=exported.export_id,
        claimed_at=NOW,
    )
    with pytest.raises(C9HandoffError) as mismatch:
        coordinator.confirm_native_chat_handoff(
            handoff_id=staged.handoff_id,
            chat_picker_claim_receipt_sha256=_picker_claim_sha256(coordinator, staged),
            observed_image_nonce="C9" + "D" * 32,
            observed_document_nonce=DOCUMENT_NONCE,
            response_text=_native_chat_response(
                staged.handoff_id,
                image_nonce="C9" + "D" * 32,
            ),
            confirmed_at=NOW,
        )
    assert mismatch.value.reason is C9HandoffReason.NONCE_PROOF_REJECTED
    assert all(not path.exists() for path in paths)
    with pytest.raises(C9HandoffError) as replay:
        coordinator.confirm_native_chat_handoff(
            handoff_id=staged.handoff_id,
            chat_picker_claim_receipt_sha256=_picker_claim_sha256(coordinator, staged),
            observed_image_nonce=IMAGE_NONCE,
            observed_document_nonce=DOCUMENT_NONCE,
            response_text=_native_chat_response(staged.handoff_id),
            confirmed_at=NOW,
        )
    assert replay.value.reason is C9HandoffReason.CHAT_REPLAY_REJECTED


def test_native_chat_rejects_substituted_picker_claim_and_deletes_export(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, _, renderer, staged, _, _ = _prepared(monkeypatch, tmp_path)
    _approve(coordinator, staged)
    _work_flow(coordinator, renderer, staged)
    exported = _prepare_native_chat_handoff(coordinator, staged)
    paths = coordinator.claim_native_chat_handoff_paths(
        handoff_id=staged.handoff_id,
        export_id=exported.export_id,
        claimed_at=NOW,
    )

    with pytest.raises(C9HandoffError) as rejected:
        coordinator.confirm_native_chat_handoff(
            handoff_id=staged.handoff_id,
            chat_picker_claim_receipt_sha256="f" * 64,
            observed_image_nonce=IMAGE_NONCE,
            observed_document_nonce=DOCUMENT_NONCE,
            response_text=_native_chat_response(staged.handoff_id),
            confirmed_at=NOW,
        )

    assert rejected.value.reason is C9HandoffReason.CROSS_HANDOFF_REJECTED
    assert all(not path.exists() for path in paths)
    assert coordinator._record is not None
    assert coordinator._record.terminal_failure is True


def test_native_chat_rejects_free_text_even_when_both_nonces_are_present(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, _, renderer, staged, _, _ = _prepared(monkeypatch, tmp_path)
    _approve(coordinator, staged)
    _work_flow(coordinator, renderer, staged)
    exported = _prepare_native_chat_handoff(coordinator, staged)
    paths = coordinator.claim_native_chat_handoff_paths(
        handoff_id=staged.handoff_id,
        export_id=exported.export_id,
        claimed_at=NOW,
    )

    with pytest.raises(C9HandoffError) as rejected:
        coordinator.confirm_native_chat_handoff(
            handoff_id=staged.handoff_id,
            chat_picker_claim_receipt_sha256=_picker_claim_sha256(coordinator, staged),
            observed_image_nonce=IMAGE_NONCE,
            observed_document_nonce=DOCUMENT_NONCE,
            response_text=f"Observed {IMAGE_NONCE} and {DOCUMENT_NONCE}.",
            confirmed_at=NOW,
        )

    assert rejected.value.reason is C9HandoffReason.RESPONSE_REJECTED
    assert all(not path.exists() for path in paths)
    assert coordinator.status(evaluated_at=NOW).native_chat_handoff_confirmed is False


def test_native_chat_refuses_mutated_export_even_after_valid_nonce_response(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, _, renderer, staged, _, _ = _prepared(monkeypatch, tmp_path)
    _approve(coordinator, staged)
    _work_flow(coordinator, renderer, staged)
    exported = _prepare_native_chat_handoff(coordinator, staged)
    paths = coordinator.claim_native_chat_handoff_paths(
        handoff_id=staged.handoff_id,
        export_id=exported.export_id,
        claimed_at=NOW,
    )
    paths[0].write_bytes(b"tampered-after-picker-claim")

    with pytest.raises(C9HandoffError) as rejected:
        coordinator.confirm_native_chat_handoff(
            handoff_id=staged.handoff_id,
            chat_picker_claim_receipt_sha256=_picker_claim_sha256(coordinator, staged),
            observed_image_nonce=IMAGE_NONCE,
            observed_document_nonce=DOCUMENT_NONCE,
            response_text=_native_chat_response(staged.handoff_id),
            confirmed_at=NOW,
        )

    assert rejected.value.reason is C9HandoffReason.CHAT_CLEANUP_REJECTED
    assert all(not path.exists() for path in paths)
    assert coordinator._record is not None
    assert coordinator._record.terminal_failure is True
    assert coordinator.status(evaluated_at=NOW).native_chat_handoff_confirmed is False


def test_native_chat_path_claim_rejects_expired_grant_before_export_ttl(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, _, renderer, staged, _, _ = _prepared(monkeypatch, tmp_path)
    admission = _approve(coordinator, staged)
    _work_flow(coordinator, renderer, staged)
    exported = _prepare_native_chat_handoff(
        coordinator,
        staged,
        ttl=timedelta(minutes=10),
    )
    assert coordinator._record is not None
    private_export = coordinator._record.chat_export
    assert private_export is not None
    grant_expiry = admission.live_cycle_bundle.grant.expires_at
    assert private_export.expires_at > grant_expiry

    with pytest.raises(C9HandoffError) as expired:
        coordinator.claim_native_chat_handoff_paths(
            handoff_id=staged.handoff_id,
            export_id=exported.export_id,
            claimed_at=grant_expiry,
        )

    assert expired.value.reason is C9HandoffReason.HANDOFF_EXPIRED
    assert coordinator._record.terminal_failure is True
    assert not (tmp_path / "manual" / exported.export_id).exists()


def test_native_chat_confirmation_rechecks_expiry_after_picker_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, _, renderer, staged, _, _ = _prepared(monkeypatch, tmp_path)
    _approve(coordinator, staged)
    _work_flow(coordinator, renderer, staged)
    exported = _prepare_native_chat_handoff(
        coordinator,
        staged,
        ttl=timedelta(minutes=10),
    )
    paths = coordinator.claim_native_chat_handoff_paths(
        handoff_id=staged.handoff_id,
        export_id=exported.export_id,
        claimed_at=NOW,
    )
    assert coordinator._record is not None
    expires_at = coordinator._chat_export_deadline(coordinator._record)

    with pytest.raises(C9HandoffError) as expired:
        coordinator.confirm_native_chat_handoff(
            handoff_id=staged.handoff_id,
            chat_picker_claim_receipt_sha256=_picker_claim_sha256(coordinator, staged),
            observed_image_nonce=IMAGE_NONCE,
            observed_document_nonce=DOCUMENT_NONCE,
            response_text=_native_chat_response(staged.handoff_id),
            confirmed_at=expires_at,
        )

    assert expired.value.reason is C9HandoffReason.HANDOFF_EXPIRED
    assert coordinator._record.terminal_failure is True
    assert all(not path.exists() for path in paths)


def test_public_models_admission_and_repr_do_not_leak_private_material(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, _, renderer, staged, _, admission_file = _prepared(
        monkeypatch,
        tmp_path,
    )
    admission = _approve(coordinator, staged)
    execution, _ = _work_flow(coordinator, renderer, staged)
    exported = _prepare_native_chat_handoff(coordinator, staged)
    paths = coordinator.claim_native_chat_handoff_paths(
        handoff_id=staged.handoff_id,
        export_id=exported.export_id,
        claimed_at=NOW,
    )
    chat_receipt = coordinator.confirm_native_chat_handoff(
        handoff_id=staged.handoff_id,
        chat_picker_claim_receipt_sha256=_picker_claim_sha256(coordinator, staged),
        observed_image_nonce=IMAGE_NONCE,
        observed_document_nonce=DOCUMENT_NONCE,
        response_text=_native_chat_response(staged.handoff_id),
        confirmed_at=NOW,
    )
    assert all(not path.exists() for path in paths)
    status = coordinator.status(evaluated_at=NOW)
    serialized = "\n".join(
        (
            staged.model_dump_json(),
            admission.model_dump_json(),
            execution.model_dump_json(),
            exported.model_dump_json(),
            chat_receipt.model_dump_json(),
            status.model_dump_json(),
            admission_file.read_text(encoding="utf-8"),
            repr(coordinator),
        )
    )
    forbidden = (
        IMAGE_NONCE,
        DOCUMENT_NONCE,
        OPERATOR_IDENTITY,
        AUDIT_KEY,
        str(tmp_path.resolve()),
        "authorization: bearer",
        "data:image/",
        "C9 synthetic image and UTF-8 document handoff",
        "prompt_text",
    )
    for value in forbidden:
        assert value not in serialized, value
    assert "nonce_sha256" in serialized
    assert "response_sha256" not in admission_file.read_text(encoding="utf-8")


def test_close_zeroes_pending_work_and_removes_admission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, registry, _, staged, _, admission_file = _prepared(
        monkeypatch,
        tmp_path,
    )
    _approve(coordinator, staged)
    coordinator.execute_work_handoff(staged.handoff_id, executed_at=NOW)
    assert coordinator._record is not None
    pending = coordinator._record.pending_rich[C9RichSurface.WORK]
    buffers = [content for _, content in pending.payloads]

    receipt = coordinator.close(closed_at=NOW)
    assert receipt.pending_deliveries_zeroed == 1
    assert receipt.admission_file_removed is True
    assert receipt.native_chat_manual_handoff_used is False
    assert not admission_file.exists()
    assert all(not any(content) for content in buffers)
    assert registry.list_tools() == ()
    assert coordinator.close(closed_at=NOW) == receipt


def test_close_cancels_claimed_native_chat_export_after_confirmed_work(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, registry, renderer, staged, _, admission_file = _prepared(
        monkeypatch,
        tmp_path,
    )
    _approve(coordinator, staged)
    _work_flow(coordinator, renderer, staged)
    exported = _prepare_native_chat_handoff(coordinator, staged)
    paths = coordinator.claim_native_chat_handoff_paths(
        handoff_id=staged.handoff_id,
        export_id=exported.export_id,
        claimed_at=NOW,
    )

    receipt = coordinator.close(closed_at=NOW)

    assert receipt.pending_deliveries_zeroed == 0
    assert receipt.manual_exports_cleaned == 1
    assert receipt.native_chat_manual_handoff_used is False
    assert receipt.admission_file_removed is True
    assert all(not path.exists() for path in paths)
    assert not admission_file.exists()
    assert registry.list_tools() == ()


def test_capability_handler_is_strict_and_returns_only_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, registry, renderer, staged, _, _ = _prepared(
        monkeypatch,
        tmp_path,
    )
    _approve(coordinator, staged)
    handler = C9HandoffCapabilityHandler(coordinator)

    malformed_arguments = (
        {},
        {"handoff_id": staged.handoff_id},
        {"handoff_id": 1, "surface": "work"},
        {"handoff_id": "not-a-c9-handoff", "surface": "work"},
        {
            "handoff_id": staged.handoff_id,
            "surface": "work",
            "unexpected": True,
        },
    )
    for arguments in malformed_arguments:
        with pytest.raises(C9HandoffError) as invalid:
            handler(arguments, {})
        assert invalid.value.reason is C9HandoffReason.CROSS_HANDOFF_REJECTED
    with pytest.raises(C9HandoffError) as invalid_surface:
        handler(
            {"handoff_id": staged.handoff_id, "surface": "automatic"},
            {},
        )
    assert invalid_surface.value.reason is C9HandoffReason.SURFACE_BINDING_MISMATCH

    output = handler({"handoff_id": staged.handoff_id, "surface": "work"}, {})
    committed = C9WorkExecutionDescriptor.model_validate(output)
    assert registry.list_tools() == ()
    assert IMAGE_NONCE not in json.dumps(output)
    assert DOCUMENT_NONCE not in json.dumps(output)
    prepared = renderer.prepare(
        name="systeme_local_attachment_handoff",
        arguments={"handoff_id": staged.handoff_id, "surface": "work"},
        output=output,
        metadata={},
    )
    assert prepared is not None
    assert coordinator.status(evaluated_at=NOW).work_rendered is False
    prepared.commit()
    assert coordinator.status(evaluated_at=NOW).work_rendered is True
    assert committed.attachment_count == 2


def test_fresh_work_capabilities_can_be_refreshed_after_afk_before_approval(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, registry, _, staged, clock, _ = _prepared(
        monkeypatch,
        tmp_path,
    )
    resumed_at = NOW + timedelta(minutes=8, seconds=30)
    clock.value = resumed_at
    evidence = C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED
    refreshed = commit_mcp_host_capabilities(
        surface=C9RichSurface.WORK,
        call_tool_result_content=evidence,
        image_content=evidence,
        embedded_text_resource=evidence,
        window_openai_upload_file_available=False,
        window_openai_image_ids_available=False,
        observed_at=resumed_at - timedelta(seconds=5),
        expires_at=resumed_at + timedelta(minutes=9),
    )
    coordinator.refresh_mcp_capabilities(
        refreshed,
        evaluated_at=resumed_at,
    )
    with pytest.raises(ValueError, match="Work-only"):
        commit_mcp_host_capabilities(
            surface=C9RichSurface.CHAT,
            call_tool_result_content=evidence,
            image_content=evidence,
            embedded_text_resource=evidence,
            window_openai_upload_file_available=False,
            window_openai_image_ids_available=False,
            observed_at=resumed_at - timedelta(seconds=5),
            expires_at=resumed_at + timedelta(minutes=9),
        )
    authorization = c9_live_cycle.commit_c9_operator_authorization(
        cycle_id="c9_cycle_" + "a" * 32,
        selected_package_manifest_sha256=staged.work_manifest_sha256,
        image_media_type="image/png",
        authorized_at=resumed_at - timedelta(minutes=1),
        expires_at=resumed_at + timedelta(minutes=20),
        audit_key=AUDIT_KEY,
    )
    observation = c9_live_cycle.commit_c9_surface_observation(
        cycle_id=authorization.cycle_id,
        observed_at=resumed_at - timedelta(seconds=5),
        expires_at=resumed_at + timedelta(minutes=9),
        audit_key=AUDIT_KEY,
    )
    coordinator.approve_handoff(
        handoff_id=staged.handoff_id,
        operator_confirmed=True,
        operator_identity=OPERATOR_IDENTITY,
        authorization=authorization,
        surface_observation=observation,
        grant_id="c9_grant_" + "b" * 32,
        approved_at=resumed_at,
    )
    assert len(registry.list_tools()) == 1


class _NoopSandboxRunner:
    def run(
        self,
        _workspace: Path,
        _command: list[str],
        *,
        include_git: bool,
    ) -> dict[str, object]:
        raise AssertionError(
            f"C9 attachment handoff must not invoke the sandbox (include_git={include_git})"
        )


@pytest.mark.parametrize("surface", tuple(C9RichSurface), ids=lambda item: item.value)
@pytest.mark.anyio
async def test_real_task_processor_and_adapter_support_only_work_without_audit_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    surface: C9RichSurface,
) -> None:
    coordinator, registry, renderer, staged, clock, _ = _prepared(
        monkeypatch,
        tmp_path,
    )
    _approve(coordinator, staged)
    shared_secret = "c9-shared-secret-" + "s" * 40
    audit_path = tmp_path / "audit.jsonl"
    audit_log = AuditLog(audit_path, AUDIT_KEY)
    policy = PolicyEngine(ROOT / "policy.c9.yaml")
    executor = CapabilityExecutor(
        tmp_path / "workspace",
        "unused-c9-test-image",
        policy.limits,
        sandbox_runner=_NoopSandboxRunner(),
        capability_handlers={
            "systeme_local_attachment_handoff": C9HandoffCapabilityHandler(coordinator)
        },
    )

    def verify_signed_task(
        task: TaskEnvelope,
        secret: str,
        *,
        replay_guard: object,
    ) -> None:
        assert replay_guard is not None
        assert hmac.compare_digest(
            compute_task_signature(task, secret),
            task.signature,
        )

    processor = TaskProcessor(
        shared_secret=shared_secret,
        replay_guard=object(),
        policy=policy,
        executor=executor,
        audit_log=audit_log,
        approval_store=object(),  # Not reached: the C9 policy decision is allow.
        task_verifier=verify_signed_task,
        replay_unavailable_error=RuntimeError,
    )
    adapter = McpTaskAdapter(
        shared_secret=shared_secret,
        task_processor=processor,
        max_concurrency=1,
        clock=clock,
        result_renderer=renderer,
        render_audit_log=audit_log,
    )

    result = await adapter.call_tool(
        "systeme_local_attachment_handoff",
        {"handoff_id": staged.handoff_id, "surface": surface.value},
    )

    assert result.meta is not None
    assert result.meta["systeme-local/audit-id"]
    assert "systeme-local/render-audit-id" not in result.meta
    status = coordinator.status(evaluated_at=NOW)
    if surface is C9RichSurface.WORK:
        assert result.isError is False
        assert [type(item) for item in result.content] == [
            mcp_types.TextContent,
            mcp_types.ImageContent,
            mcp_types.EmbeddedResource,
        ]
        assert result.structuredContent is not None
        assert result.structuredContent["surface"] == "work"
        assert registry.list_tools() == ()
        assert status.work_rendered is True
        assert status.rich_call_count == 1
    else:
        assert result.isError is True
        assert [type(item) for item in result.content] == [mcp_types.TextContent]
        assert result.structuredContent is None
        assert registry.list_tools() == ()
        assert status.work_rendered is False
        assert status.rich_call_count == 0
        assert status.native_chat_mcp_invoked is False
    expected_audit_records = 2 if surface is C9RichSurface.WORK else 1
    assert audit_log.verify().records == expected_audit_records

    serialized_audit = audit_path.read_text(encoding="utf-8")
    for forbidden in (
        IMAGE_NONCE,
        DOCUMENT_NONCE,
        str(tmp_path.resolve()),
        "data:image/",
        "synthetic document",
    ):
        assert forbidden not in serialized_audit
    if surface is C9RichSurface.WORK:
        assert '"keys":["content_recorded"]' in serialized_audit


def test_authenticated_http_control_confirms_work_then_native_chat_manual(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coordinator, _, renderer, staged, clock, _ = _prepared(
        monkeypatch,
        tmp_path,
    )
    _approve(coordinator, staged)
    work_execution, _ = _render_work(coordinator, renderer, staged)

    control = object.__new__(C9LocalControlPlane)
    untyped_control = cast(Any, control)
    untyped_control._coordinator = coordinator
    untyped_control._clock = clock
    untyped_control._lock = threading.RLock()
    untyped_control._staged = staged
    untyped_control._native_chat_handoff_id = None

    app = FastAPI()
    app.include_router(
        build_c9_control_router(
            guard=C9LocalControlGuard(token=CONTROL_TOKEN),
            control=control,
        )
    )

    with TestClient(
        app,
        base_url="http://127.0.0.1:8765",
        client=("127.0.0.1", 55000),
        headers={"Authorization": f"Bearer {CONTROL_TOKEN}"},
    ) as client:
        provider_response = json.dumps(
            {
                "handoff_id": staged.handoff_id,
                "surface": "work",
                "surface_task_id": staged.work_task_id,
                "expansion_descriptor_sha256": (work_execution.expansion_descriptor_sha256),
                "manifest_sha256": staged.work_manifest_sha256,
                "observed_image_nonce": IMAGE_NONCE,
                "observed_document_nonce": DOCUMENT_NONCE,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        work_response = client.post(
            "/_local/c9/work/confirm",
            json={
                "handoff_id": staged.handoff_id,
                "response_text": provider_response,
            },
        )
        export_response = client.post(
            "/_local/c9/chat/export",
            json={"handoff_id": staged.handoff_id},
        )
        assert export_response.status_code == 200
        export_id = export_response.json()["export_id"]
        claim_response = client.post(
            "/_local/c9/chat/claim",
            json={
                "handoff_id": staged.handoff_id,
                "export_id": export_id,
            },
        )
        claimed_paths = tuple(Path(path) for path in claim_response.json()["paths"])
        assert all(path.is_file() for path in claimed_paths)
        chat_response = client.post(
            "/_local/c9/chat/confirm",
            json={
                "handoff_id": staged.handoff_id,
                "chat_picker_claim_receipt_sha256": _picker_claim_sha256(
                    coordinator,
                    staged,
                ),
                "observed_image_nonce": IMAGE_NONCE,
                "observed_document_nonce": DOCUMENT_NONCE,
                "response_text": _native_chat_response(staged.handoff_id),
            },
        )

    assert work_response.status_code == 200
    assert work_response.json()["status"] == "work_attachments_visibly_consumed"
    assert export_response.json()["delivery_mode"] == (
        "operator_performed_manual_attachment_handoff"
    )
    assert claim_response.status_code == 200
    assert claim_response.json()["status"] == ("native_chat_manual_attachment_paths_claimed")
    assert claim_response.json()["qualifies_as_native_chat_success"] is False
    assert claim_response.json()["receipt_sha256"] == _picker_claim_sha256(
        coordinator,
        staged,
    )
    assert chat_response.status_code == 200
    assert chat_response.json()["status"] == ("native_chat_attachments_visibly_consumed")
    assert chat_response.json()["qualifies_as_native_chat_success"] is True
    assert chat_response.json()["plugin_mcp_invocation_claimed"] is False
    assert all(not path.exists() for path in claimed_paths)
    status = coordinator.status(evaluated_at=NOW)
    assert status.work_confirmed is True
    assert status.native_chat_mcp_invoked is False
    assert status.native_chat_handoff_confirmed is True
    assert status.rich_confirmation_count == 1
