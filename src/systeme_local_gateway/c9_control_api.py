from __future__ import annotations

import json
import logging
import re
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal, TypeVar, cast

import anyio
from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from starlette.responses import JSONResponse

from . import c9_live_cycle
from .c9_attachment_security import C9AttachmentSecurityError
from .c9_control import C9ControlAccessDenied, C9LocalControlGuard
from .c9_handoff_runtime import (
    C9ChatPickerClaimReceipt,
    C9HandoffCoordinator,
    C9HandoffError,
    C9HandoffStageReceipt,
)
from .c9_local_ai import C9LocalAIError
from .c9_manual_export import C9ManualExportError
from .c9_private_state import C9PrivateStateError, C9PrivateStateGuard
from .c9_synthetic_fixtures import (
    C9SyntheticFixtureError,
    C9SyntheticFixtureKind,
    generate_c9_synthetic_fixtures,
)
from .c9_work_bridge import (
    C9CapabilityEvidence,
    C9RichSurface,
    C9WorkBridgeError,
    commit_mcp_host_capabilities,
)

logger = logging.getLogger(__name__)
_CommandT = TypeVar("_CommandT", bound="_StrictCommand")

_HANDOFF_PATTERN = r"^c9_handoff_[0-9a-f]{32}$"
_EXPORT_PATTERN = r"^c9_export_[0-9a-f]{32}$"
_WORK_TASK_PATTERN = r"^c9_work_[0-9a-f]{32}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_NONCE_PATTERN = re.compile(r"^C9[0-9A-F]{32}$")
_MAX_PROVIDER_RESPONSE_BYTES = 12 * 1024
_RESPONSE_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


class _StrictCommand(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class C9StageCommand(_StrictCommand):
    confirmed_exact_synthetic_files: Literal[True]
    purpose: str = Field(min_length=1, max_length=1024)


class C9ApproveCommand(_StrictCommand):
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)
    operator_confirmed_combined_handoff: Literal[True]
    operator_identity: str = Field(min_length=1, max_length=256)
    confirmed_exact_c9_scope: Literal[True]
    work_surface_visible: Literal[True]
    explicit_work_selected: Literal[True]
    plugin_surface_visible: Literal[True]
    work_entitlement_available: Literal[True]
    work_quota_usable: Literal[True]
    work_plugin_mcp_app_visible: Literal[True]
    work_plugin_mcp_app_eligible: Literal[True]
    work_plugin_mcp_app_selectable: Literal[True]
    native_chat_surface_visible: Literal[True]
    explicit_native_chat_selected: Literal[True]
    native_chat_attachment_control_visible: Literal[True]
    native_chat_file_picker_visible: Literal[True]
    native_chat_manual_attachment_handoff_available: Literal[True]
    native_chat_manual_attachment_handoff_used: Literal[False]
    prompt_sent: Literal[False]
    existing_conversations_accessed: Literal[False]
    history_accessed: Literal[False]
    account_or_security_settings_accessed: Literal[False]
    private_browser_state_accessed: Literal[False]
    automatic_chat_to_work_switch_used: Literal[False]


class C9HandoffCommand(_StrictCommand):
    handoff_id: str = Field(pattern=_HANDOFF_PATTERN)


class C9NativeChatHandoffCommand(C9HandoffCommand):
    """Use the already committed combined approval for the native-Chat half."""


class C9ChatClaimCommand(C9HandoffCommand):
    export_id: str = Field(pattern=_EXPORT_PATTERN)


class C9WorkConfirmationCommand(C9HandoffCommand):
    response_text: str = Field(min_length=1, max_length=_MAX_PROVIDER_RESPONSE_BYTES)


class C9ChatConfirmationCommand(C9HandoffCommand):
    chat_picker_claim_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    observed_image_nonce: str = Field(pattern=_NONCE_PATTERN.pattern)
    observed_document_nonce: str = Field(pattern=_NONCE_PATTERN.pattern)
    response_text: str = Field(min_length=1, max_length=_MAX_PROVIDER_RESPONSE_BYTES)

    @model_validator(mode="after")
    def validate_distinct_nonces(self) -> C9ChatConfirmationCommand:
        if secrets.compare_digest(
            self.observed_image_nonce,
            self.observed_document_nonce,
        ):
            raise ValueError("C9 native Chat proof nonces must be distinct")
        return self


class C9CloseCommand(_StrictCommand):
    pass


@dataclass(frozen=True, slots=True)
class _C9ParsedWorkResponse:
    handoff_id: str
    surface: Literal["work"]
    surface_task_id: str
    expansion_descriptor_sha256: str
    manifest_sha256: str
    observed_image_nonce: str
    observed_document_nonce: str


@dataclass(frozen=True, slots=True)
class _C9ParsedNativeChatResponse:
    handoff_id: str
    surface: Literal["chat"]
    delivery_mode: Literal["operator_performed_manual_attachment_handoff"]
    observed_image_nonce: str
    observed_document_nonce: str


@dataclass(frozen=True, slots=True)
class C9ClaimedChatPaths:
    receipt: C9ChatPickerClaimReceipt
    paths: tuple[Path, ...]


def _response(payload: dict[str, Any], *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        content=payload,
        status_code=status_code,
        headers=_RESPONSE_HEADERS,
    )


def _model_response(model: BaseModel, *, status_code: int = 200) -> JSONResponse:
    return _response(model.model_dump(mode="json"), status_code=status_code)


def _safe_reason(error: Exception) -> str:
    reason = getattr(error, "reason", None)
    code = getattr(error, "code", None)
    if reason is not None:
        return str(getattr(reason, "value", reason))
    if code is not None:
        return str(getattr(code, "value", code))
    return "security_invariant"


def _reject_duplicate_response_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate provider-response key")
        output[key] = value
    return output


def _reject_non_finite_response(_value: str) -> None:
    raise ValueError("non-finite provider-response value")


def _strict_provider_response(
    response_text: str,
    *,
    handoff_id: str,
    expected_fields: frozenset[str],
) -> dict[str, str]:
    if len(response_text.encode("utf-8")) > _MAX_PROVIDER_RESPONSE_BYTES:
        raise ValueError("provider response exceeds its byte boundary")
    try:
        decoded = json.loads(
            response_text,
            object_pairs_hook=_reject_duplicate_response_keys,
            parse_constant=_reject_non_finite_response,
        )
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        raise ValueError("provider response is not strict JSON") from exc
    if (
        not isinstance(decoded, dict)
        or frozenset(decoded) != expected_fields
        or not all(isinstance(value, str) for value in decoded.values())
    ):
        raise ValueError("provider response has an invalid exact schema")
    typed = cast(dict[str, str], decoded)
    if typed["handoff_id"] != handoff_id:
        raise ValueError("provider response targets another handoff")
    return typed


def _parse_work_response(
    response_text: str,
    *,
    handoff_id: str,
    expected_task_id: str,
    expected_manifest_sha256: str,
) -> _C9ParsedWorkResponse:
    parsed = _strict_provider_response(
        response_text,
        handoff_id=handoff_id,
        expected_fields=frozenset(
            {
                "handoff_id",
                "surface",
                "surface_task_id",
                "expansion_descriptor_sha256",
                "manifest_sha256",
                "observed_image_nonce",
                "observed_document_nonce",
            }
        ),
    )
    surface = parsed["surface"]
    surface_task_id = parsed["surface_task_id"]
    descriptor = parsed["expansion_descriptor_sha256"]
    manifest = parsed["manifest_sha256"]
    image_nonce = parsed["observed_image_nonce"]
    document_nonce = parsed["observed_document_nonce"]
    if (
        surface != "work"
        or re.fullmatch(_WORK_TASK_PATTERN, surface_task_id) is None
        or not secrets.compare_digest(surface_task_id, expected_task_id)
        or re.fullmatch(_SHA256_PATTERN, descriptor) is None
        or re.fullmatch(_SHA256_PATTERN, manifest) is None
        or not secrets.compare_digest(manifest, expected_manifest_sha256)
        or _NONCE_PATTERN.fullmatch(image_nonce) is None
        or _NONCE_PATTERN.fullmatch(document_nonce) is None
        or secrets.compare_digest(image_nonce, document_nonce)
    ):
        raise ValueError("provider Work response contains invalid proof values")
    return _C9ParsedWorkResponse(
        handoff_id=handoff_id,
        surface="work",
        surface_task_id=surface_task_id,
        expansion_descriptor_sha256=descriptor,
        manifest_sha256=manifest,
        observed_image_nonce=image_nonce,
        observed_document_nonce=document_nonce,
    )


def _parse_native_chat_response(
    response_text: str,
    *,
    handoff_id: str,
    expected_image_nonce: str,
    expected_document_nonce: str,
) -> _C9ParsedNativeChatResponse:
    parsed = _strict_provider_response(
        response_text,
        handoff_id=handoff_id,
        expected_fields=frozenset(
            {
                "delivery_mode",
                "handoff_id",
                "observed_document_nonce",
                "observed_image_nonce",
                "surface",
            }
        ),
    )
    if (
        parsed["delivery_mode"] != "operator_performed_manual_attachment_handoff"
        or parsed["surface"] != "chat"
        or _NONCE_PATTERN.fullmatch(parsed["observed_image_nonce"]) is None
        or _NONCE_PATTERN.fullmatch(parsed["observed_document_nonce"]) is None
        or not secrets.compare_digest(
            parsed["observed_image_nonce"],
            expected_image_nonce,
        )
        or not secrets.compare_digest(
            parsed["observed_document_nonce"],
            expected_document_nonce,
        )
        or secrets.compare_digest(
            parsed["observed_image_nonce"],
            parsed["observed_document_nonce"],
        )
    ):
        raise ValueError("provider native-Chat response contains invalid proof values")
    return _C9ParsedNativeChatResponse(
        handoff_id=handoff_id,
        surface="chat",
        delivery_mode="operator_performed_manual_attachment_handoff",
        observed_image_nonce=parsed["observed_image_nonce"],
        observed_document_nonce=parsed["observed_document_nonce"],
    )


def _surface_stage_binding(
    staged: C9HandoffStageReceipt,
) -> tuple[str, str]:
    task_id = getattr(staged, "work_task_id", None)
    manifest_sha256 = getattr(staged, "work_manifest_sha256", None)
    if (
        not isinstance(task_id, str)
        or re.fullmatch(_WORK_TASK_PATTERN, task_id) is None
        or not isinstance(manifest_sha256, str)
        or re.fullmatch(_SHA256_PATTERN, manifest_sha256) is None
    ):
        raise ValueError("C9 staged Work binding is unavailable")
    return task_id, manifest_sha256


def _confirm_rich_surface(
    coordinator: C9HandoffCoordinator,
    *,
    parsed: _C9ParsedWorkResponse,
    observed_nonces: dict[str, str],
    response_text: str,
    confirmed_at: datetime,
) -> BaseModel:
    """Call only the Work MCP rich-content confirmation interface."""

    callback = getattr(coordinator, "confirm_rich_surface", None)
    if not callable(callback):
        raise ValueError("C9 coordinator lacks Work MCP rich-content confirmation")
    result = callback(
        handoff_id=parsed.handoff_id,
        surface=C9RichSurface.WORK,
        surface_task_id=parsed.surface_task_id,
        descriptor_sha256=parsed.expansion_descriptor_sha256,
        manifest_sha256=parsed.manifest_sha256,
        observed_nonces=observed_nonces,
        response_text=response_text,
        confirmed_at=confirmed_at,
    )
    if not isinstance(result, BaseModel):
        raise ValueError("C9 rich confirmation returned an invalid receipt")
    payload = result.model_dump(mode="json")
    expected_nonce_sha256s = [
        sha256(value.encode("utf-8")).hexdigest() for value in observed_nonces.values()
    ]
    if (
        payload.get("surface") != parsed.surface
        or payload.get("surface_task_id") != parsed.surface_task_id
        or payload.get("descriptor_sha256") != parsed.expansion_descriptor_sha256
        or payload.get("manifest_sha256") != parsed.manifest_sha256
        or payload.get("verified_nonce_sha256s") != expected_nonce_sha256s
        or payload.get("response_sha256") != sha256(response_text.encode("utf-8")).hexdigest()
    ):
        raise ValueError("C9 rich confirmation receipt binding mismatch")
    return result


def _confirm_native_chat_handoff(
    coordinator: C9HandoffCoordinator,
    *,
    command: C9ChatConfirmationCommand,
    expected_manifest_sha256: str,
    confirmed_at: datetime,
) -> BaseModel:
    callback = getattr(coordinator, "confirm_native_chat_handoff", None)
    if not callable(callback):
        raise ValueError("C9 coordinator lacks native-Chat manual handoff confirmation")
    result = callback(
        handoff_id=command.handoff_id,
        chat_picker_claim_receipt_sha256=(command.chat_picker_claim_receipt_sha256),
        observed_image_nonce=command.observed_image_nonce,
        observed_document_nonce=command.observed_document_nonce,
        response_text=command.response_text,
        confirmed_at=confirmed_at,
    )
    if not isinstance(result, BaseModel):
        raise ValueError("C9 native-Chat handoff returned an invalid receipt")
    payload = result.model_dump(mode="json")
    expected_nonce_sha256s = [
        sha256(command.observed_image_nonce.encode("utf-8")).hexdigest(),
        sha256(command.observed_document_nonce.encode("utf-8")).hexdigest(),
    ]
    if (
        payload.get("status") != "native_chat_attachments_visibly_consumed"
        or payload.get("delivery_mode") != "operator_performed_manual_attachment_handoff"
        or payload.get("qualifies_as_native_chat_success") is not True
        or payload.get("plugin_mcp_invocation_claimed") is not False
        or payload.get("automated_attachment_claimed") is not False
        or payload.get("handoff_id") != command.handoff_id
        or payload.get("chat_picker_claim_receipt_sha256")
        != command.chat_picker_claim_receipt_sha256
        or payload.get("chat_manifest_sha256") != expected_manifest_sha256
        or payload.get("verified_nonce_sha256s") != expected_nonce_sha256s
        or payload.get("response_sha256")
        != sha256(command.response_text.encode("utf-8")).hexdigest()
    ):
        raise ValueError("C9 native-Chat handoff receipt binding mismatch")
    return result


class C9LocalControlPlane:
    """Trusted loopback orchestration around one process-local C9 coordinator."""

    def __init__(
        self,
        *,
        coordinator: C9HandoffCoordinator,
        fixture_root: Path,
        private_state_guard: C9PrivateStateGuard,
        audit_key: str | bytes,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not fixture_root.is_absolute():
            raise ValueError("C9 fixture root must be absolute")
        key = audit_key.encode("utf-8") if isinstance(audit_key, str) else audit_key
        if len(key) < 32:
            raise ValueError("C9 control plane requires a bounded audit key")
        self._coordinator = coordinator
        self._fixture_root = fixture_root
        self._private_state = private_state_guard
        self._private_state.validate_target(
            fixture_root,
            allow_missing_leaf=True,
        )
        self._audit_key = audit_key
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._staged: C9HandoffStageReceipt | None = None
        self._native_chat_handoff_id: str | None = None

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("C9 control clock must be timezone-aware")
        return value.astimezone(UTC)

    def stage(self, command: C9StageCommand) -> C9HandoffStageReceipt:
        with self._lock:
            if self._staged is not None:
                raise ValueError("C9 already has a staged handoff")
            if not command.confirmed_exact_synthetic_files:
                raise ValueError("C9 exact synthetic file selection is not confirmed")
            self._private_state.ensure_directory(self._fixture_root)
            fixture = generate_c9_synthetic_fixtures(
                self._fixture_root,
                generated_at=self._now(),
            )
            try:
                staged = self._coordinator.stage(
                    fixture=fixture,
                    purpose=command.purpose,
                    staged_at=self._now(),
                    lease_ttl=timedelta(minutes=10),
                )
            except Exception:
                fixture.cleanup(cleaned_at=self._now())
                raise
            self._staged = staged
            return staged

    def approve(self, command: C9ApproveCommand) -> BaseModel:
        with self._lock:
            staged = self._staged
            if staged is None or staged.handoff_id != command.handoff_id:
                raise ValueError("C9 approve command targets another handoff")
            at = self._now()
            evidence = C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED
            capabilities = commit_mcp_host_capabilities(
                surface=C9RichSurface.WORK,
                call_tool_result_content=evidence,
                image_content=evidence,
                embedded_text_resource=evidence,
                window_openai_upload_file_available=False,
                window_openai_image_ids_available=False,
                observed_at=at,
                expires_at=at + timedelta(minutes=10),
            )
            self._coordinator.refresh_mcp_capabilities(
                capabilities,
                evaluated_at=at,
            )
            image = next(
                item for item in staged.attachments if item.kind is C9SyntheticFixtureKind.IMAGE
            )
            if image.media_type.value not in {"image/png", "image/jpeg"}:
                raise ValueError("C9 staged image media type is invalid")
            image_media_type = cast(
                Literal["image/png", "image/jpeg"],
                image.media_type.value,
            )
            authorization = c9_live_cycle.commit_c9_operator_authorization(
                cycle_id=self._coordinator.local_ai_cycle_id,
                selected_package_manifest_sha256=staged.work_manifest_sha256,
                image_media_type=image_media_type,
                authorized_at=at,
                expires_at=at + timedelta(hours=1),
                audit_key=self._audit_key,
            )
            observation = c9_live_cycle.commit_c9_surface_observation(
                cycle_id=authorization.cycle_id,
                observed_at=at,
                expires_at=at + timedelta(minutes=10),
                audit_key=self._audit_key,
            )
            return self._coordinator.approve_handoff(
                handoff_id=staged.handoff_id,
                operator_confirmed=command.operator_confirmed_combined_handoff,
                operator_identity=command.operator_identity,
                authorization=authorization,
                surface_observation=observation,
                grant_id=f"c9_grant_{secrets.token_hex(16)}",
                approved_at=at,
                approval_ttl=timedelta(minutes=10),
            )

    def prepare_chat_export(self, command: C9NativeChatHandoffCommand) -> BaseModel:
        with self._lock:
            staged = self._staged
            if staged is None or staged.handoff_id != command.handoff_id:
                raise ValueError("C9 native-Chat handoff targets another handoff")
            self._native_chat_handoff_id = command.handoff_id
            callback = getattr(self._coordinator, "prepare_native_chat_handoff", None)
            if not callable(callback):
                raise ValueError("C9 coordinator lacks native-Chat manual handoff")
            result = callback(
                handoff_id=command.handoff_id,
                created_at=self._now(),
                ttl=timedelta(minutes=10),
            )
            if not isinstance(result, BaseModel):
                raise ValueError("C9 native-Chat handoff returned an invalid descriptor")
            return result

    def claim_chat_paths(self, command: C9ChatClaimCommand) -> C9ClaimedChatPaths:
        with self._lock:
            if self._native_chat_handoff_id != command.handoff_id:
                raise ValueError("C9 native-Chat handoff was not prepared")
            callback = getattr(self._coordinator, "claim_native_chat_handoff_paths", None)
            if not callable(callback):
                raise ValueError("C9 coordinator lacks native-Chat path claiming")
            paths = callback(
                handoff_id=command.handoff_id,
                export_id=command.export_id,
                claimed_at=self._now(),
            )
            if not isinstance(paths, tuple) or not all(isinstance(path, Path) for path in paths):
                raise ValueError("C9 native-Chat path claim returned invalid paths")
            receipt = self._coordinator.native_chat_picker_claim_receipt(
                handoff_id=command.handoff_id,
            )
            return C9ClaimedChatPaths(
                receipt=receipt,
                paths=cast(tuple[Path, ...], paths),
            )

    def confirm_work(self, command: C9WorkConfirmationCommand) -> BaseModel:
        with self._lock:
            staged = self._staged
            if staged is None or staged.handoff_id != command.handoff_id:
                raise ValueError("C9 Work proof targets another handoff")
            task_id, manifest_sha256 = _surface_stage_binding(staged)
            parsed = _parse_work_response(
                command.response_text,
                handoff_id=staged.handoff_id,
                expected_task_id=task_id,
                expected_manifest_sha256=manifest_sha256,
            )
            image = next(
                item for item in staged.attachments if item.kind is C9SyntheticFixtureKind.IMAGE
            )
            document = next(
                item for item in staged.attachments if item.kind is C9SyntheticFixtureKind.TEXT
            )
            return _confirm_rich_surface(
                self._coordinator,
                parsed=parsed,
                observed_nonces={
                    image.attachment_id: parsed.observed_image_nonce,
                    document.attachment_id: parsed.observed_document_nonce,
                },
                response_text=command.response_text,
                confirmed_at=self._now(),
            )

    def confirm_chat(self, command: C9ChatConfirmationCommand) -> BaseModel:
        with self._lock:
            staged = self._staged
            if staged is None or staged.handoff_id != command.handoff_id:
                raise ValueError("C9 native Chat proof targets another handoff")
            if self._native_chat_handoff_id != command.handoff_id:
                raise ValueError("C9 native-Chat manual handoff was not prepared")
            manifest_sha256 = getattr(staged, "chat_manifest_sha256", None)
            if (
                not isinstance(manifest_sha256, str)
                or re.fullmatch(_SHA256_PATTERN, manifest_sha256) is None
            ):
                raise ValueError("C9 staged native-Chat binding is unavailable")
            _parse_native_chat_response(
                command.response_text,
                handoff_id=command.handoff_id,
                expected_image_nonce=command.observed_image_nonce,
                expected_document_nonce=command.observed_document_nonce,
            )
            return _confirm_native_chat_handoff(
                self._coordinator,
                command=command,
                expected_manifest_sha256=manifest_sha256,
                confirmed_at=self._now(),
            )

    def close(self) -> BaseModel:
        return self._coordinator.close(closed_at=self._now())

    def status(self) -> BaseModel:
        return self._coordinator.status(evaluated_at=self._now())


def build_c9_control_router(
    *,
    guard: C9LocalControlGuard,
    control: C9LocalControlPlane,
) -> APIRouter:
    router = APIRouter(include_in_schema=False)

    async def command(
        request: Request,
        model_type: type[_CommandT],
        callback: Callable[
            [_CommandT],
            BaseModel | C9ClaimedChatPaths | tuple[Path, ...],
        ],
        *,
        allow_native_chat_paths: bool = False,
    ) -> JSONResponse:
        try:
            guard.authorize(request)
            raw = await guard.read_json_object(request)
            parsed = model_type.model_validate(raw)
            result = await anyio.to_thread.run_sync(lambda: callback(parsed))
            if isinstance(result, C9ClaimedChatPaths):
                if not allow_native_chat_paths:
                    raise ValueError("C9 control route returned unexpected local paths")
                payload = result.receipt.model_dump(mode="json")
                payload["paths"] = [str(path) for path in result.paths]
                return _response(payload)
            if isinstance(result, tuple):
                if not allow_native_chat_paths:
                    raise ValueError("C9 control route returned unexpected local paths")
                return _response(
                    {
                        "status": "native_chat_manual_attachment_paths_claimed",
                        "qualifies_as_native_chat_success": False,
                        "plugin_mcp_invocation_claimed": False,
                        "automated_attachment_claimed": False,
                        "paths": [str(path) for path in result],
                    }
                )
            return _model_response(result)
        except C9ControlAccessDenied:
            return _response({"status": "not_found"}, status_code=404)
        except ValidationError:
            return _response({"status": "invalid_request"}, status_code=400)
        except (
            C9AttachmentSecurityError,
            C9HandoffError,
            C9LocalAIError,
            C9ManualExportError,
            C9PrivateStateError,
            C9SyntheticFixtureError,
            C9WorkBridgeError,
        ) as error:
            return _response(
                {"status": "rejected", "reason": _safe_reason(error)},
                status_code=409,
            )
        except Exception as error:
            logger.error("C9 local control operation failed with %s", type(error).__name__)
            return _response(
                {"status": "rejected", "reason": "security_invariant"},
                status_code=409,
            )

    @router.get("/_local/c9/status")
    async def status(request: Request) -> JSONResponse:
        try:
            guard.authorize(request)
            result = await anyio.to_thread.run_sync(control.status)
            return _model_response(result)
        except C9ControlAccessDenied:
            return _response({"status": "not_found"}, status_code=404)
        except Exception as error:
            logger.error("C9 local control status failed with %s", type(error).__name__)
            return _response(
                {"status": "rejected", "reason": "security_invariant"},
                status_code=409,
            )

    @router.post("/_local/c9/stage")
    async def stage(request: Request) -> JSONResponse:
        return await command(request, C9StageCommand, control.stage)

    @router.post("/_local/c9/approve")
    async def approve(request: Request) -> JSONResponse:
        return await command(request, C9ApproveCommand, control.approve)

    @router.post("/_local/c9/chat/export")
    async def chat_export(request: Request) -> JSONResponse:
        return await command(
            request,
            C9NativeChatHandoffCommand,
            control.prepare_chat_export,
        )

    @router.post("/_local/c9/chat/claim")
    async def chat_claim(request: Request) -> JSONResponse:
        return await command(
            request,
            C9ChatClaimCommand,
            control.claim_chat_paths,
            allow_native_chat_paths=True,
        )

    @router.post("/_local/c9/work/confirm")
    async def work_confirm(request: Request) -> JSONResponse:
        return await command(
            request,
            C9WorkConfirmationCommand,
            control.confirm_work,
        )

    @router.post("/_local/c9/chat/confirm")
    async def chat_confirm(request: Request) -> JSONResponse:
        return await command(
            request,
            C9ChatConfirmationCommand,
            control.confirm_chat,
        )

    @router.post("/_local/c9/close")
    async def close(request: Request) -> JSONResponse:
        return await command(
            request,
            C9CloseCommand,
            lambda _parsed: control.close(),
        )

    return router
