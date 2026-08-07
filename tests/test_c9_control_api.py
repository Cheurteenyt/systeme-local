from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict

from systeme_local_gateway.c9_control import C9LocalControlGuard
from systeme_local_gateway.c9_control_api import (
    C9ChatConfirmationCommand,
    C9LocalControlPlane,
    C9WorkConfirmationCommand,
    _parse_native_chat_response,
    _parse_work_response,
    build_c9_control_router,
)
from systeme_local_gateway.c9_handoff_runtime import (
    C9HandoffError,
    C9HandoffReason,
)
from systeme_local_gateway.c9_synthetic_fixtures import C9SyntheticFixtureKind

TOKEN = "c9-control-api-token-that-is-long-and-independent"
PICKER_CLAIM_RECEIPT_SHA256 = sha256(b"c9-test-picker-claim").hexdigest()


class _Result(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str


class _RichResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str
    surface: str
    surface_task_id: str
    descriptor_sha256: str
    manifest_sha256: str
    verified_nonce_sha256s: tuple[str, str]
    response_sha256: str


class _NativeChatResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str
    delivery_mode: str
    qualifies_as_native_chat_success: bool
    plugin_mcp_invocation_claimed: bool
    automated_attachment_claimed: bool
    handoff_id: str
    chat_manifest_sha256: str
    chat_export_id: str
    chat_export_descriptor_sha256: str
    chat_picker_claim_receipt_sha256: str
    verified_nonce_sha256s: tuple[str, str]
    response_sha256: str


class _FakeControl:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    def status(self) -> BaseModel:
        self.calls.append(("status", None))
        return _Result(status="empty")

    def stage(self, command: Any) -> BaseModel:
        self.calls.append(("stage", command))
        return _Result(status="staged")

    def approve(self, command: Any) -> BaseModel:
        self.calls.append(("approve", command))
        return _Result(status="admitted")

    def prepare_chat_export(self, command: Any) -> BaseModel:
        self.calls.append(("chat_export", command))
        return _Result(status="ready")

    def claim_chat_paths(self, command: Any) -> tuple[Path, ...]:
        self.calls.append(("chat_claim", command))
        return (Path("C:/private/image.png"), Path("C:/private/document.txt"))

    def confirm_work(self, command: Any) -> BaseModel:
        self.calls.append(("work_confirm", command))
        return _Result(status="work_confirmed")

    def confirm_chat(self, command: Any) -> BaseModel:
        self.calls.append(("chat_confirm", command))
        return _Result(status="chat_confirmed")

    def close(self) -> BaseModel:
        self.calls.append(("close", None))
        return _Result(status="closed")


class _FakeRichCoordinator:
    def __init__(
        self,
        *,
        corrupt_manifest: bool = False,
        corrupt_native_chat_manifest: bool = False,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.native_chat_calls: list[dict[str, Any]] = []
        self.corrupt_manifest = corrupt_manifest
        self.corrupt_native_chat_manifest = corrupt_native_chat_manifest

    def confirm_rich_surface(self, **kwargs: Any) -> BaseModel:
        self.calls.append(kwargs)
        surface = getattr(kwargs["surface"], "value", kwargs["surface"])
        manifest = "f" * 64 if self.corrupt_manifest else kwargs["manifest_sha256"]
        nonces = list(kwargs["observed_nonces"].values())
        return _RichResult(
            status=f"{surface}_attachments_visibly_consumed",
            surface=surface,
            surface_task_id=kwargs["surface_task_id"],
            descriptor_sha256=kwargs["descriptor_sha256"],
            manifest_sha256=manifest,
            verified_nonce_sha256s=(
                sha256(nonces[0].encode("utf-8")).hexdigest(),
                sha256(nonces[1].encode("utf-8")).hexdigest(),
            ),
            response_sha256=sha256(kwargs["response_text"].encode("utf-8")).hexdigest(),
        )

    def confirm_native_chat_handoff(self, **kwargs: Any) -> BaseModel:
        self.native_chat_calls.append(kwargs)
        manifest = "f" * 64 if self.corrupt_native_chat_manifest else "2" * 64
        return _NativeChatResult(
            status="native_chat_attachments_visibly_consumed",
            delivery_mode="operator_performed_manual_attachment_handoff",
            qualifies_as_native_chat_success=True,
            plugin_mcp_invocation_claimed=False,
            automated_attachment_claimed=False,
            handoff_id=kwargs["handoff_id"],
            chat_manifest_sha256=manifest,
            chat_export_id="c9_export_" + "3" * 32,
            chat_export_descriptor_sha256="4" * 64,
            chat_picker_claim_receipt_sha256=(kwargs["chat_picker_claim_receipt_sha256"]),
            verified_nonce_sha256s=(
                sha256(kwargs["observed_image_nonce"].encode("utf-8")).hexdigest(),
                sha256(kwargs["observed_document_nonce"].encode("utf-8")).hexdigest(),
            ),
            response_sha256=sha256(kwargs["response_text"].encode("utf-8")).hexdigest(),
        )


def _client(control: _FakeControl) -> TestClient:
    app = FastAPI()
    app.include_router(
        build_c9_control_router(
            guard=C9LocalControlGuard(token=TOKEN),
            control=control,  # type: ignore[arg-type]
        )
    )
    return TestClient(
        app,
        base_url="http://127.0.0.1:8765",
        client=("127.0.0.1", 55000),
        headers={"Authorization": f"Bearer {TOKEN}"},
    )


def _rich_response(
    *,
    handoff_id: str,
    surface: str,
    surface_task_id: str,
    manifest_sha256: str,
    descriptor_sha256: str = "d" * 64,
) -> str:
    return json.dumps(
        {
            "handoff_id": handoff_id,
            "surface": surface,
            "surface_task_id": surface_task_id,
            "expansion_descriptor_sha256": descriptor_sha256,
            "manifest_sha256": manifest_sha256,
            "observed_image_nonce": "C9" + "A" * 32,
            "observed_document_nonce": "C9" + "B" * 32,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _native_chat_response(
    *,
    handoff_id: str,
    image_nonce: str = "C9" + "A" * 32,
    document_nonce: str = "C9" + "B" * 32,
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


def _unit_control(
    coordinator: _FakeRichCoordinator,
) -> tuple[C9LocalControlPlane, Any]:
    handoff_id = "c9_handoff_" + "a" * 32
    staged = SimpleNamespace(
        handoff_id=handoff_id,
        work_task_id="c9_work_" + "b" * 32,
        chat_task_id="c9_chat_" + "c" * 32,
        work_manifest_sha256="1" * 64,
        chat_manifest_sha256="2" * 64,
        attachments=(
            SimpleNamespace(
                attachment_id="c9_attachment_" + "d" * 32,
                kind=C9SyntheticFixtureKind.IMAGE,
            ),
            SimpleNamespace(
                attachment_id="c9_attachment_" + "e" * 32,
                kind=C9SyntheticFixtureKind.TEXT,
            ),
        ),
    )
    control = object.__new__(C9LocalControlPlane)
    untyped_control = cast(Any, control)
    untyped_control._coordinator = coordinator
    untyped_control._clock = lambda: datetime(2026, 7, 28, tzinfo=UTC)
    untyped_control._lock = threading.RLock()
    untyped_control._staged = staged
    untyped_control._native_chat_handoff_id = handoff_id
    return control, staged


def test_status_is_authenticated_metadata_only_and_never_cached() -> None:
    control = _FakeControl()
    with _client(control) as client:
        response = client.get("/_local/c9/status")

    assert response.status_code == 200
    assert response.json() == {"status": "empty"}
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert control.calls == [("status", None)]


def test_missing_token_origin_and_query_are_indistinguishable_not_found() -> None:
    control = _FakeControl()
    with _client(control) as client:
        missing = client.get("/_local/c9/status", headers={"Authorization": ""})
        browser = client.get(
            "/_local/c9/status",
            headers={"Origin": "https://chatgpt.com"},
        )
        queried = client.get("/_local/c9/status?debug=true")

    assert {missing.status_code, browser.status_code, queried.status_code} == {404}
    assert missing.json() == browser.json() == queried.json() == {"status": "not_found"}
    assert control.calls == []


def test_stage_requires_one_exact_strict_confirmation_object() -> None:
    control = _FakeControl()
    with _client(control) as client:
        rejected = client.post(
            "/_local/c9/stage",
            json={
                "confirmed_exact_synthetic_files": True,
                "purpose": "synthetic C9 proof",
                "unexpected": "denied",
            },
        )
        accepted = client.post(
            "/_local/c9/stage",
            json={
                "confirmed_exact_synthetic_files": True,
                "purpose": "synthetic C9 proof",
            },
        )

    assert rejected.status_code == 400
    assert rejected.json() == {"status": "invalid_request"}
    assert accepted.status_code == 200
    assert accepted.json() == {"status": "staged"}
    assert [name for name, _ in control.calls] == ["stage"]


def test_typed_control_failure_exposes_only_public_reason_not_exception_message() -> None:
    class _RejectedControl(_FakeControl):
        def stage(self, command: Any) -> BaseModel:
            del command
            raise C9HandoffError(
                C9HandoffReason.RESPONSE_REJECTED,
                "SENTINEL_SECRET_INPUT_AND_PATH",
            )

    with _client(_RejectedControl()) as client:
        rejected = client.post(
            "/_local/c9/stage",
            json={
                "confirmed_exact_synthetic_files": True,
                "purpose": "synthetic C9 proof",
            },
        )

    assert rejected.status_code == 409
    assert rejected.json() == {
        "status": "rejected",
        "reason": "response_rejected",
    }
    assert "SENTINEL_SECRET" not in rejected.text


def test_approve_requires_work_app_and_native_chat_file_picker_observation() -> None:
    control = _FakeControl()
    payload = {
        "handoff_id": "c9_handoff_" + "a" * 32,
        "operator_confirmed_combined_handoff": True,
        "operator_identity": "synthetic-c9-operator",
        "confirmed_exact_c9_scope": True,
        "work_surface_visible": True,
        "explicit_work_selected": True,
        "plugin_surface_visible": True,
        "work_entitlement_available": True,
        "work_quota_usable": True,
        "work_plugin_mcp_app_visible": True,
        "work_plugin_mcp_app_eligible": True,
        "work_plugin_mcp_app_selectable": True,
        "native_chat_surface_visible": True,
        "explicit_native_chat_selected": True,
        "native_chat_attachment_control_visible": True,
        "native_chat_file_picker_visible": True,
        "native_chat_manual_attachment_handoff_available": True,
        "native_chat_manual_attachment_handoff_used": False,
        "prompt_sent": False,
        "existing_conversations_accessed": False,
        "history_accessed": False,
        "account_or_security_settings_accessed": False,
        "private_browser_state_accessed": False,
        "automatic_chat_to_work_switch_used": False,
    }
    with _client(control) as client:
        accepted = client.post("/_local/c9/approve", json=payload)
        rejected = client.post(
            "/_local/c9/approve",
            json={
                **payload,
                "native_chat_file_picker_visible": False,
            },
        )

    assert accepted.status_code == 200
    assert rejected.status_code == 400
    assert accepted.json() == {"status": "admitted"}
    assert [name for name, _ in control.calls] == ["approve"]


def test_native_chat_export_and_claim_are_bounded_nonqualifying_preparation() -> None:
    control = _FakeControl()
    handoff_id = "c9_handoff_" + "a" * 32
    with _client(control) as client:
        export = client.post(
            "/_local/c9/chat/export",
            json={"handoff_id": handoff_id},
        )
        response = client.post(
            "/_local/c9/chat/claim",
            json={
                "handoff_id": handoff_id,
                "export_id": "c9_export_" + "b" * 32,
            },
        )

    assert export.status_code == 200
    assert export.json() == {"status": "ready"}
    assert response.status_code == 200
    assert response.json() == {
        "status": "native_chat_manual_attachment_paths_claimed",
        "qualifies_as_native_chat_success": False,
        "plugin_mcp_invocation_claimed": False,
        "automated_attachment_claimed": False,
        "paths": [
            str(Path("C:/private/image.png")),
            str(Path("C:/private/document.txt")),
        ],
    }
    assert response.headers["cache-control"].startswith("no-store")
    assert [name for name, _ in control.calls] == ["chat_export", "chat_claim"]


def test_close_accepts_only_an_empty_json_object() -> None:
    control = _FakeControl()
    with _client(control) as client:
        rejected = client.post("/_local/c9/close", json={"force": True})
        accepted = client.post("/_local/c9/close", json={})

    assert rejected.status_code == 400
    assert accepted.status_code == 200
    assert accepted.json() == {"status": "closed"}
    assert [name for name, _ in control.calls] == ["close"]


def test_native_chat_confirmation_requires_two_distinct_bounded_nonces() -> None:
    control = _FakeControl()
    handoff_id = "c9_handoff_" + "a" * 32
    response_text = _native_chat_response(handoff_id=handoff_id)
    with _client(control) as client:
        accepted = client.post(
            "/_local/c9/chat/confirm",
            json={
                "handoff_id": handoff_id,
                "chat_picker_claim_receipt_sha256": (PICKER_CLAIM_RECEIPT_SHA256),
                "observed_image_nonce": "C9" + "A" * 32,
                "observed_document_nonce": "C9" + "B" * 32,
                "response_text": response_text,
            },
        )
        rejected = client.post(
            "/_local/c9/chat/confirm",
            json={
                "handoff_id": handoff_id,
                "response_text": response_text,
                "observed_image_nonce": "C9" + "A" * 32,
            },
        )
        same_nonce = client.post(
            "/_local/c9/chat/confirm",
            json={
                "handoff_id": handoff_id,
                "chat_picker_claim_receipt_sha256": (PICKER_CLAIM_RECEIPT_SHA256),
                "observed_image_nonce": "C9" + "A" * 32,
                "observed_document_nonce": "C9" + "A" * 32,
                "response_text": response_text,
            },
        )

    assert accepted.status_code == 200
    assert rejected.status_code == 400
    assert same_nonce.status_code == 400
    assert [name for name, _ in control.calls] == ["chat_confirm"]


def test_provider_response_parser_is_strictly_work_only() -> None:
    handoff_id = "c9_handoff_" + "a" * 32
    work_task_id = "c9_work_" + "b" * 32
    work_manifest = "1" * 64
    work = _rich_response(
        handoff_id=handoff_id,
        surface="work",
        surface_task_id=work_task_id,
        manifest_sha256=work_manifest,
    )
    chat = _rich_response(
        handoff_id=handoff_id,
        surface="chat",
        surface_task_id="c9_chat_" + "c" * 32,
        manifest_sha256="2" * 64,
    )

    parsed_work = _parse_work_response(
        work,
        handoff_id=handoff_id,
        expected_task_id=work_task_id,
        expected_manifest_sha256=work_manifest,
    )
    assert parsed_work.surface == "work"
    assert parsed_work.surface_task_id == work_task_id
    assert parsed_work.manifest_sha256 == work_manifest

    with pytest.raises(ValueError):
        _parse_work_response(
            chat,
            handoff_id=handoff_id,
            expected_task_id=work_task_id,
            expected_manifest_sha256=work_manifest,
        )


def test_provider_response_parsers_reject_duplicate_unknown_and_malformed_values() -> None:
    handoff_id = "c9_handoff_" + "a" * 32
    work_task_id = "c9_work_" + "c" * 32
    work_manifest = "2" * 64
    work = _rich_response(
        handoff_id=handoff_id,
        surface="work",
        surface_task_id=work_task_id,
        manifest_sha256=work_manifest,
    )

    duplicate = work[:-1] + ',"surface":"work"}'
    unknown = work[:-1] + ',"unexpected":"denied"}'
    malformed_nonce = work.replace("C9" + "B" * 32, "C9bad")
    wrong_manifest = work.replace(work_manifest, "3" * 64)
    oversized = work + (" " * (13 * 1024))
    for candidate in (
        duplicate,
        unknown,
        malformed_nonce,
        wrong_manifest,
        oversized,
    ):
        with pytest.raises(ValueError):
            _parse_work_response(
                candidate,
                handoff_id=handoff_id,
                expected_task_id=work_task_id,
                expected_manifest_sha256=work_manifest,
            )


def test_native_chat_response_parser_requires_exact_manual_handoff_json() -> None:
    handoff_id = "c9_handoff_" + "a" * 32
    image_nonce = "C9" + "A" * 32
    document_nonce = "C9" + "B" * 32
    valid = _native_chat_response(handoff_id=handoff_id)

    parsed = _parse_native_chat_response(
        valid,
        handoff_id=handoff_id,
        expected_image_nonce=image_nonce,
        expected_document_nonce=document_nonce,
    )
    assert parsed.surface == "chat"
    assert parsed.delivery_mode == "operator_performed_manual_attachment_handoff"

    candidates = (
        f"Observed {image_nonce} and {document_nonce}.",
        valid[:-1] + ',"unexpected":"denied"}',
        valid[:-1] + ',"surface":"chat"}',
        valid.replace('"surface":"chat"', '"surface":"work"'),
        valid.replace(handoff_id, "c9_handoff_" + "f" * 32),
        valid.replace(image_nonce, "C9" + "D" * 32),
        valid.replace(
            "operator_performed_manual_attachment_handoff",
            "plugin_mcp_rich_content",
        ),
    )
    for candidate in candidates:
        with pytest.raises(ValueError):
            _parse_native_chat_response(
                candidate,
                handoff_id=handoff_id,
                expected_image_nonce=image_nonce,
                expected_document_nonce=document_nonce,
            )


def test_control_confirms_one_work_mcp_call_and_one_manual_native_chat_handoff() -> None:
    coordinator = _FakeRichCoordinator()
    control, staged = _unit_control(coordinator)
    work_response = _rich_response(
        handoff_id=staged.handoff_id,
        surface="work",
        surface_task_id=staged.work_task_id,
        manifest_sha256=staged.work_manifest_sha256,
    )
    chat_response = _native_chat_response(handoff_id=staged.handoff_id)

    work = control.confirm_work(
        C9WorkConfirmationCommand(
            handoff_id=staged.handoff_id,
            response_text=work_response,
        )
    )
    chat = control.confirm_chat(
        C9ChatConfirmationCommand(
            handoff_id=staged.handoff_id,
            chat_picker_claim_receipt_sha256=PICKER_CLAIM_RECEIPT_SHA256,
            observed_image_nonce="C9" + "A" * 32,
            observed_document_nonce="C9" + "B" * 32,
            response_text=chat_response,
        )
    )

    assert work.model_dump(mode="json")["surface"] == "work"
    assert chat.model_dump(mode="json")["delivery_mode"] == (
        "operator_performed_manual_attachment_handoff"
    )
    assert [call["surface"].value for call in coordinator.calls] == ["work"]
    assert len(coordinator.native_chat_calls) == 1
    assert "surface" not in coordinator.native_chat_calls[0]


def test_control_rejects_mismatched_work_and_native_chat_receipts() -> None:
    coordinator = _FakeRichCoordinator(corrupt_manifest=True)
    control, staged = _unit_control(coordinator)
    work_response = _rich_response(
        handoff_id=staged.handoff_id,
        surface="work",
        surface_task_id=staged.work_task_id,
        manifest_sha256=staged.work_manifest_sha256,
    )
    with pytest.raises(ValueError, match="receipt binding mismatch"):
        control.confirm_work(
            C9WorkConfirmationCommand(
                handoff_id=staged.handoff_id,
                response_text=work_response,
            )
        )

    corrupt_chat = _FakeRichCoordinator(corrupt_native_chat_manifest=True)
    chat_control, chat_staged = _unit_control(corrupt_chat)
    with pytest.raises(ValueError, match="handoff receipt binding mismatch"):
        chat_control.confirm_chat(
            C9ChatConfirmationCommand(
                handoff_id=chat_staged.handoff_id,
                chat_picker_claim_receipt_sha256=PICKER_CLAIM_RECEIPT_SHA256,
                observed_image_nonce="C9" + "A" * 32,
                observed_document_nonce="C9" + "B" * 32,
                response_text=_native_chat_response(
                    handoff_id=chat_staged.handoff_id,
                ),
            )
        )
