from __future__ import annotations

import argparse
import json
import re
import threading
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .c0_probe import C0_TOOL_NAME
from .c3_evidence import (
    C3_PROFILE_PATH,
    C3GateDecision,
    C3ProtectedAction,
    EvidenceLifecycleState,
    EvidenceReviewerState,
    OfficialSupportState,
    evaluate_c3_registry,
)

if TYPE_CHECKING:
    from .mcp_tools import McpToolRegistry


C4_ADAPTER_REGISTRY_PATH = "governance/c4-runtime-adapters.json"
C4_ADAPTER_REGISTRY_VERSION = "1"
C4_CHATGPT_TOOL_PROTOCOL_SHA256 = "de0389f0a2329daa8afa3ad8126eb6e3e80aba1b77ed2e0f29998c37c383c65b"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_IDENTIFIER_PATTERN = r"^[a-z][a-z0-9_]{2,63}$"
_TOOL_NAME_PATTERN = r"^[a-z][a-z0-9_.]{2,127}$"
_CORRELATION_PATTERN = r"^c4_[0-9a-f]{32}$"
_SECRET_SHAPES = (
    re.compile(r"(?i)sk-[a-z0-9_-]{20,}"),
    re.compile(r"(?i)tunnel_[0-9a-f]{32}"),
    re.compile(r"(?i)bearer\s+[a-z0-9._~+/-]{20,}"),
)


def canonical_json(value: Any) -> bytes:
    """Encode one deterministic JSON value for C4 commitments."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return sha256(canonical_json(value)).hexdigest()


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C4 timestamps must include an explicit UTC offset")
    normalized = value.astimezone(timezone.utc)
    if normalized != value:
        raise ValueError("C4 timestamps must be normalized to UTC")
    return normalized


def _parse_timestamp(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return _require_aware(datetime.fromisoformat(normalized))


def _assert_secret_free(value: Any) -> None:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    if any(pattern.search(text) for pattern in _SECRET_SHAPES):
        raise ValueError("C4 output contains a credential-shaped value")


class RuntimeAdmissionAction(StrEnum):
    RUNTIME_KEY_CREATION = "runtime_key_creation"
    TUNNEL_START = "tunnel_start"
    PLUGIN_CREATION = "plugin_creation"
    BROWSER_TEST = "browser_test"
    CHATGPT_ACTION = "chatgpt_action"
    TOOL_SURFACE_EXPOSURE = "tool_surface_exposure"


class ToolAccessMode(StrEnum):
    READ_ONLY = "read_only"
    WRITE = "write"
    HIGH_RISK = "high_risk"


class AdmissionReasonCode(StrEnum):
    ADMITTED = "admitted"
    OFFICIAL_CAPABILITY_UNSUPPORTED = "official_capability_unsupported"
    OFFICIAL_CAPABILITY_UNOBSERVABLE = "official_capability_unobservable"
    EVIDENCE_REVALIDATION_DUE = "evidence_revalidation_due"
    EVIDENCE_EXPIRED = "evidence_expired"
    EVIDENCE_SOURCE_DRIFT = "evidence_source_drift"
    EVIDENCE_INVALID = "evidence_invalid"
    EVIDENCE_CANDIDATE = "evidence_candidate"
    EVIDENCE_IDENTITY_MISMATCH = "evidence_identity_mismatch"
    EVIDENCE_TIME_MISMATCH = "evidence_time_mismatch"
    C3_ACTION_DENIED = "c3_action_denied"
    UNKNOWN_ADAPTER = "unknown_adapter"
    ADAPTER_IDENTITY_MISMATCH = "adapter_identity_mismatch"
    RUNTIME_REGISTRY_INVALID = "runtime_registry_invalid"
    ACTION_TOOL_SCOPE_INVALID = "action_tool_scope_invalid"
    TOOL_NOT_APPROVED = "tool_not_approved"
    TOOL_METADATA_MISMATCH = "tool_metadata_mismatch"
    TOOL_PRIVILEGE_EXPANSION = "tool_privilege_expansion"
    CORRELATION_REPLAY = "correlation_replay"
    CORRELATION_COLLISION = "correlation_collision"
    CORRELATION_CAPACITY_EXHAUSTED = "correlation_capacity_exhausted"


class RuntimeCapabilityIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    native_surface: str = Field(pattern=_IDENTIFIER_PATTERN)
    surface_class: str = Field(pattern=_IDENTIFIER_PATTERN)
    capability: str = Field(pattern=_IDENTIFIER_PATTERN)

    @property
    def key(self) -> str:
        return f"{self.provider_id}:{self.native_surface}:{self.surface_class}:{self.capability}"


class RuntimeToolGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=_TOOL_NAME_PATTERN)
    access_mode: ToolAccessMode
    protocol_sha256: str = Field(pattern=_SHA256_PATTERN)
    read_only: bool
    destructive: bool
    high_risk: bool

    @model_validator(mode="after")
    def validate_privilege_metadata(self) -> RuntimeToolGrant:
        if self.access_mode is ToolAccessMode.READ_ONLY:
            if not self.read_only or self.destructive or self.high_risk:
                raise ValueError("C4 read-only tool metadata is inconsistent")
        elif self.access_mode is ToolAccessMode.WRITE:
            if self.read_only or not self.destructive or self.high_risk:
                raise ValueError("C4 write tool metadata is inconsistent")
        elif self.read_only or not self.high_risk:
            raise ValueError("C4 high-risk tool metadata is inconsistent")
        return self


class C3ActionBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: C3ProtectedAction
    allowed: bool


class RuntimeProviderAdapter(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    identity: RuntimeCapabilityIdentity
    approved_tools: tuple[RuntimeToolGrant, ...]

    @model_validator(mode="after")
    def validate_tools(self) -> RuntimeProviderAdapter:
        names = tuple(tool.name for tool in self.approved_tools)
        if names != tuple(sorted(set(names))):
            raise ValueError("C4 adapter tools must be sorted and unique")
        if any(tool.access_mode is not ToolAccessMode.READ_ONLY for tool in self.approved_tools):
            raise ValueError("C4 production adapter grants must be read-only")
        return self


class RuntimeAdapterRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    adapters: tuple[RuntimeProviderAdapter, ...]
    registry_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_registry(self) -> RuntimeAdapterRegistry:
        keys = tuple(adapter.identity.key for adapter in self.adapters)
        if not keys or keys != tuple(sorted(set(keys))):
            raise ValueError("C4 runtime adapters must be sorted and unique")
        payload = self.model_dump(mode="json", exclude={"registry_sha256"})
        if canonical_sha256(payload) != self.registry_sha256:
            raise ValueError("C4 runtime adapter registry digest mismatch")
        return self


class RuntimeAdmissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    identity: RuntimeCapabilityIdentity
    action: RuntimeAdmissionAction
    requested_tools: tuple[RuntimeToolGrant, ...]
    evaluated_at: datetime
    request_correlation: str = Field(pattern=_CORRELATION_PATTERN)
    request_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_evaluated_at = field_validator("evaluated_at")(_require_aware)

    def commitment_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"request_sha256"})

    @model_validator(mode="after")
    def validate_request(self) -> RuntimeAdmissionRequest:
        names = tuple(tool.name for tool in self.requested_tools)
        if names != tuple(sorted(set(names))):
            raise ValueError("C4 requested tools must be sorted and unique")
        if canonical_sha256(self.commitment_payload()) != self.request_sha256:
            raise ValueError("C4 admission request digest mismatch")
        return self


class AdmissionEvidenceSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    identity: RuntimeCapabilityIdentity | None
    support_state: OfficialSupportState | None
    reviewer_state: EvidenceReviewerState | None
    lifecycle_state: EvidenceLifecycleState
    evaluated_at: datetime
    c3_registry_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    c3_profile_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    c3_evidence_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    c3_decision_sha256: str = Field(pattern=_SHA256_PATTERN)
    c3_reason_code: str = Field(min_length=1, max_length=96)
    action_decisions: tuple[C3ActionBinding, ...]

    _aware_evaluated_at = field_validator("evaluated_at")(_require_aware)

    @model_validator(mode="after")
    def validate_snapshot(self) -> AdmissionEvidenceSnapshot:
        actions = tuple(binding.action.value for binding in self.action_decisions)
        expected = tuple(sorted(action.value for action in C3ProtectedAction))
        if actions != expected:
            raise ValueError("C4 snapshot must bind every C3 protected action")
        if self.identity is None:
            if (
                self.lifecycle_state is not EvidenceLifecycleState.INVALID
                or self.support_state is not None
                or self.reviewer_state is not None
                or any(
                    value is not None
                    for value in (
                        self.c3_registry_sha256,
                        self.c3_profile_sha256,
                        self.c3_evidence_sha256,
                    )
                )
            ):
                raise ValueError("C4 unidentified evidence must be invalid and empty")
        else:
            digests = (
                self.c3_registry_sha256,
                self.c3_profile_sha256,
                self.c3_evidence_sha256,
            )
            if any(value is None for value in digests):
                raise ValueError("C4 identified evidence requires all C3 digests")
        return self


class RuntimeAdmissionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    request_correlation: str = Field(pattern=_CORRELATION_PATTERN)
    request_sha256: str = Field(pattern=_SHA256_PATTERN)
    identity: RuntimeCapabilityIdentity
    action: RuntimeAdmissionAction
    evaluated_at: datetime
    allowed: bool
    reason_code: AdmissionReasonCode
    support_state: OfficialSupportState | None
    reviewer_state: EvidenceReviewerState | None
    lifecycle_state: EvidenceLifecycleState
    c3_registry_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    c3_profile_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    c3_evidence_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    c3_decision_sha256: str = Field(pattern=_SHA256_PATTERN)
    c4_registry_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    requested_tools: tuple[RuntimeToolGrant, ...]
    effective_tools: tuple[RuntimeToolGrant, ...]
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_evaluated_at = field_validator("evaluated_at")(_require_aware)

    def receipt_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"receipt_sha256"})

    @model_validator(mode="after")
    def validate_decision(self) -> RuntimeAdmissionDecision:
        if canonical_sha256(self.receipt_payload()) != self.receipt_sha256:
            raise ValueError("C4 admission receipt digest mismatch")
        requested_names = tuple(tool.name for tool in self.requested_tools)
        effective_names = tuple(tool.name for tool in self.effective_tools)
        if requested_names != tuple(sorted(set(requested_names))):
            raise ValueError("C4 decision requested tools must be sorted and unique")
        if effective_names != tuple(sorted(set(effective_names))):
            raise ValueError("C4 decision effective tools must be sorted and unique")
        if self.allowed:
            if self.reason_code is not AdmissionReasonCode.ADMITTED:
                raise ValueError("C4 allowed decision requires admitted reason")
            if self.support_state is not OfficialSupportState.SUPPORTED:
                raise ValueError("C4 allowed decision requires supported evidence")
            if self.reviewer_state is not EvidenceReviewerState.REVIEWED:
                raise ValueError("C4 allowed decision requires reviewed evidence")
            if self.lifecycle_state is not EvidenceLifecycleState.CURRENT:
                raise ValueError("C4 allowed decision requires current evidence")
            if self.effective_tools != self.requested_tools:
                raise ValueError("C4 allowed decision must preserve the approved tool scope")
            if self.c4_registry_sha256 is None or any(
                value is None
                for value in (
                    self.c3_registry_sha256,
                    self.c3_profile_sha256,
                    self.c3_evidence_sha256,
                )
            ):
                raise ValueError("C4 allowed decision requires every reviewed digest")
            tool_actions = {
                RuntimeAdmissionAction.CHATGPT_ACTION,
                RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE,
            }
            if self.action in tool_actions and not self.effective_tools:
                raise ValueError("C4 allowed tool action requires an effective tool")
            if self.action not in tool_actions and self.effective_tools:
                raise ValueError("C4 allowed non-tool action cannot expose tools")
        elif self.effective_tools:
            raise ValueError("C4 denied decision must expose no effective tools")
        elif self.reason_code is AdmissionReasonCode.ADMITTED:
            raise ValueError("C4 denied decision cannot use the admitted reason")
        _assert_secret_free(self.model_dump(mode="json"))
        return self


def build_current_c4_adapter_registry() -> RuntimeAdapterRegistry:
    identity = RuntimeCapabilityIdentity(
        provider_id="chatgpt",
        native_surface="chat",
        surface_class="conversational_chat",
        capability="custom_or_local_mcp_tool_invocation",
    )
    adapter = RuntimeProviderAdapter(
        identity=identity,
        approved_tools=(
            RuntimeToolGrant(
                name=C0_TOOL_NAME,
                access_mode=ToolAccessMode.READ_ONLY,
                protocol_sha256=C4_CHATGPT_TOOL_PROTOCOL_SHA256,
                read_only=True,
                destructive=False,
                high_risk=False,
            ),
        ),
    )
    payload: dict[str, Any] = {
        "version": C4_ADAPTER_REGISTRY_VERSION,
        "adapters": [adapter.model_dump(mode="json")],
    }
    return RuntimeAdapterRegistry(
        **payload,
        registry_sha256=canonical_sha256(payload),
    )


def commit_runtime_admission_request(
    *,
    identity: RuntimeCapabilityIdentity,
    action: RuntimeAdmissionAction,
    requested_tools: tuple[RuntimeToolGrant, ...],
    evaluated_at: datetime,
    request_correlation: str,
) -> RuntimeAdmissionRequest:
    payload: dict[str, Any] = {
        "version": "1",
        "identity": identity.model_dump(mode="json"),
        "action": action.value,
        "requested_tools": [
            tool.model_dump(mode="json")
            for tool in sorted(requested_tools, key=lambda item: item.name)
        ],
        "evaluated_at": _require_aware(evaluated_at).isoformat().replace("+00:00", "Z"),
        "request_correlation": request_correlation,
    }
    return RuntimeAdmissionRequest(
        **payload,
        request_sha256=canonical_sha256(payload),
    )


def evidence_snapshot_from_c3(decision: C3GateDecision) -> AdmissionEvidenceSnapshot:
    identity = None
    if decision.identity is not None:
        identity = RuntimeCapabilityIdentity(
            provider_id=decision.identity.provider_id.value,
            native_surface=decision.identity.native_surface,
            surface_class=decision.identity.surface_class.value,
            capability=decision.identity.capability.value,
        )
    return AdmissionEvidenceSnapshot(
        identity=identity,
        support_state=decision.support_state,
        reviewer_state=decision.reviewer_state,
        lifecycle_state=decision.lifecycle_state,
        evaluated_at=decision.evaluated_at,
        c3_registry_sha256=decision.registry_sha256,
        c3_profile_sha256=decision.profile_sha256,
        c3_evidence_sha256=decision.evidence_sha256,
        c3_decision_sha256=canonical_sha256(decision.model_dump(mode="json")),
        c3_reason_code=decision.reason_code.value,
        action_decisions=tuple(
            C3ActionBinding(action=action, allowed=allowed)
            for action, allowed in sorted(
                decision.action_decisions.items(), key=lambda item: item[0].value
            )
        ),
    )


def _invalid_evidence_snapshot(
    *,
    evaluated_at: datetime,
    reason: str,
) -> AdmissionEvidenceSnapshot:
    payload = {
        "evaluated_at": _require_aware(evaluated_at).isoformat().replace("+00:00", "Z"),
        "reason": reason,
    }
    return AdmissionEvidenceSnapshot(
        identity=None,
        support_state=None,
        reviewer_state=None,
        lifecycle_state=EvidenceLifecycleState.INVALID,
        evaluated_at=evaluated_at,
        c3_registry_sha256=None,
        c3_profile_sha256=None,
        c3_evidence_sha256=None,
        c3_decision_sha256=canonical_sha256(payload),
        c3_reason_code=reason,
        action_decisions=tuple(
            C3ActionBinding(action=action, allowed=False)
            for action in sorted(C3ProtectedAction, key=lambda item: item.value)
        ),
    )


def _c3_action_for(action: RuntimeAdmissionAction) -> C3ProtectedAction:
    if action is RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE:
        return C3ProtectedAction.BROWSER_TEST
    return C3ProtectedAction(action.value)


def _commit_decision(
    *,
    request: RuntimeAdmissionRequest,
    evidence: AdmissionEvidenceSnapshot,
    c4_registry_sha256: str | None,
    allowed: bool,
    reason_code: AdmissionReasonCode,
    effective_tools: tuple[RuntimeToolGrant, ...] = (),
) -> RuntimeAdmissionDecision:
    payload: dict[str, Any] = {
        "version": "1",
        "request_correlation": request.request_correlation,
        "request_sha256": request.request_sha256,
        "identity": request.identity.model_dump(mode="json"),
        "action": request.action.value,
        "evaluated_at": request.evaluated_at.isoformat().replace("+00:00", "Z"),
        "allowed": allowed,
        "reason_code": reason_code.value,
        "support_state": (
            evidence.support_state.value if evidence.support_state is not None else None
        ),
        "reviewer_state": (
            evidence.reviewer_state.value if evidence.reviewer_state is not None else None
        ),
        "lifecycle_state": evidence.lifecycle_state.value,
        "c3_registry_sha256": evidence.c3_registry_sha256,
        "c3_profile_sha256": evidence.c3_profile_sha256,
        "c3_evidence_sha256": evidence.c3_evidence_sha256,
        "c3_decision_sha256": evidence.c3_decision_sha256,
        "c4_registry_sha256": c4_registry_sha256,
        "requested_tools": [tool.model_dump(mode="json") for tool in request.requested_tools],
        "effective_tools": [tool.model_dump(mode="json") for tool in effective_tools],
    }
    return RuntimeAdmissionDecision(
        **payload,
        receipt_sha256=canonical_sha256(payload),
    )


def _reason_for_evidence(
    evidence: AdmissionEvidenceSnapshot,
) -> AdmissionReasonCode | None:
    if evidence.reviewer_state is EvidenceReviewerState.CANDIDATE:
        return AdmissionReasonCode.EVIDENCE_CANDIDATE
    if evidence.lifecycle_state is EvidenceLifecycleState.REVALIDATION_DUE:
        return AdmissionReasonCode.EVIDENCE_REVALIDATION_DUE
    if evidence.lifecycle_state is EvidenceLifecycleState.EXPIRED:
        return AdmissionReasonCode.EVIDENCE_EXPIRED
    if evidence.lifecycle_state is EvidenceLifecycleState.SOURCE_DRIFT:
        return AdmissionReasonCode.EVIDENCE_SOURCE_DRIFT
    if evidence.lifecycle_state is EvidenceLifecycleState.INVALID:
        return AdmissionReasonCode.EVIDENCE_INVALID
    if evidence.support_state is OfficialSupportState.UNSUPPORTED:
        return AdmissionReasonCode.OFFICIAL_CAPABILITY_UNSUPPORTED
    if evidence.support_state is OfficialSupportState.UNOBSERVABLE:
        return AdmissionReasonCode.OFFICIAL_CAPABILITY_UNOBSERVABLE
    if evidence.reviewer_state is not EvidenceReviewerState.REVIEWED:
        return AdmissionReasonCode.EVIDENCE_INVALID
    if evidence.support_state is not OfficialSupportState.SUPPORTED:
        return AdmissionReasonCode.EVIDENCE_INVALID
    return None


def _adapter_for_request(
    request: RuntimeAdmissionRequest,
    registry: RuntimeAdapterRegistry,
) -> tuple[RuntimeProviderAdapter | None, AdmissionReasonCode | None]:
    exact = [
        adapter for adapter in registry.adapters if adapter.identity.key == request.identity.key
    ]
    if len(exact) == 1:
        return exact[0], None
    same_provider = [
        adapter
        for adapter in registry.adapters
        if adapter.identity.provider_id == request.identity.provider_id
    ]
    if same_provider:
        return None, AdmissionReasonCode.ADAPTER_IDENTITY_MISMATCH
    return None, AdmissionReasonCode.UNKNOWN_ADAPTER


def _validate_tool_scope(
    request: RuntimeAdmissionRequest,
    adapter: RuntimeProviderAdapter,
) -> AdmissionReasonCode | None:
    tool_actions = {
        RuntimeAdmissionAction.CHATGPT_ACTION,
        RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE,
    }
    if request.action in tool_actions:
        if not request.requested_tools:
            return AdmissionReasonCode.ACTION_TOOL_SCOPE_INVALID
    elif request.requested_tools:
        return AdmissionReasonCode.ACTION_TOOL_SCOPE_INVALID

    approved = {tool.name: tool for tool in adapter.approved_tools}
    for requested in request.requested_tools:
        expected = approved.get(requested.name)
        if expected is None:
            return AdmissionReasonCode.TOOL_NOT_APPROVED
        if requested.access_mode is not ToolAccessMode.READ_ONLY:
            return AdmissionReasonCode.TOOL_PRIVILEGE_EXPANSION
        if requested != expected:
            return AdmissionReasonCode.TOOL_METADATA_MISMATCH
    return None


def evaluate_runtime_admission(
    request: RuntimeAdmissionRequest,
    evidence: AdmissionEvidenceSnapshot,
    registry: RuntimeAdapterRegistry,
) -> RuntimeAdmissionDecision:
    """Evaluate one request without mutable replay state or repository I/O."""

    request = RuntimeAdmissionRequest.model_validate(request.model_dump(mode="python"))
    evidence = AdmissionEvidenceSnapshot.model_validate(evidence.model_dump(mode="python"))
    registry = RuntimeAdapterRegistry.model_validate(registry.model_dump(mode="python"))
    adapter, adapter_reason = _adapter_for_request(request, registry)
    if adapter_reason is not None or adapter is None:
        return _commit_decision(
            request=request,
            evidence=evidence,
            c4_registry_sha256=registry.registry_sha256,
            allowed=False,
            reason_code=adapter_reason or AdmissionReasonCode.UNKNOWN_ADAPTER,
        )
    evidence_reason = _reason_for_evidence(evidence)
    if evidence_reason is not None:
        return _commit_decision(
            request=request,
            evidence=evidence,
            c4_registry_sha256=registry.registry_sha256,
            allowed=False,
            reason_code=evidence_reason,
        )
    if evidence.identity != request.identity:
        return _commit_decision(
            request=request,
            evidence=evidence,
            c4_registry_sha256=registry.registry_sha256,
            allowed=False,
            reason_code=AdmissionReasonCode.EVIDENCE_IDENTITY_MISMATCH,
        )
    if evidence.evaluated_at != request.evaluated_at:
        return _commit_decision(
            request=request,
            evidence=evidence,
            c4_registry_sha256=registry.registry_sha256,
            allowed=False,
            reason_code=AdmissionReasonCode.EVIDENCE_TIME_MISMATCH,
        )
    c3_action = _c3_action_for(request.action)
    c3_actions = {binding.action: binding.allowed for binding in evidence.action_decisions}
    if not c3_actions[c3_action]:
        return _commit_decision(
            request=request,
            evidence=evidence,
            c4_registry_sha256=registry.registry_sha256,
            allowed=False,
            reason_code=AdmissionReasonCode.C3_ACTION_DENIED,
        )
    tool_reason = _validate_tool_scope(request, adapter)
    if tool_reason is not None:
        return _commit_decision(
            request=request,
            evidence=evidence,
            c4_registry_sha256=registry.registry_sha256,
            allowed=False,
            reason_code=tool_reason,
        )
    return _commit_decision(
        request=request,
        evidence=evidence,
        c4_registry_sha256=registry.registry_sha256,
        allowed=True,
        reason_code=AdmissionReasonCode.ADMITTED,
        effective_tools=request.requested_tools,
    )


class RuntimeAdmissionController:
    """Thread-safe single-process correlation replay guard and evaluator."""

    def __init__(
        self,
        *,
        evidence: AdmissionEvidenceSnapshot,
        registry: RuntimeAdapterRegistry,
        max_correlations: int = 10_000,
    ) -> None:
        if max_correlations < 1 or max_correlations > 1_000_000:
            raise ValueError("C4 correlation capacity is outside the safe range")
        self._evidence = AdmissionEvidenceSnapshot.model_validate(
            evidence.model_dump(mode="python")
        )
        self._registry = RuntimeAdapterRegistry.model_validate(registry.model_dump(mode="python"))
        self._seen: dict[str, str] = {}
        self._issued_tool_receipts: dict[
            str,
            tuple[str, RuntimeAdmissionDecision],
        ] = {}
        self._max_correlations = max_correlations
        self._lock = threading.Lock()

    def decide(self, request: RuntimeAdmissionRequest) -> RuntimeAdmissionDecision:
        request = RuntimeAdmissionRequest.model_validate(request.model_dump(mode="python"))
        with self._lock:
            previous = self._seen.get(request.request_correlation)
            if previous is None:
                if len(self._seen) >= self._max_correlations:
                    replay_reason = AdmissionReasonCode.CORRELATION_CAPACITY_EXHAUSTED
                else:
                    self._seen[request.request_correlation] = request.request_sha256
                    replay_reason = None
            elif previous == request.request_sha256:
                replay_reason = AdmissionReasonCode.CORRELATION_REPLAY
            else:
                replay_reason = AdmissionReasonCode.CORRELATION_COLLISION
        if replay_reason is not None:
            return _commit_decision(
                request=request,
                evidence=self._evidence,
                c4_registry_sha256=self._registry.registry_sha256,
                allowed=False,
                reason_code=replay_reason,
            )
        decision = evaluate_runtime_admission(request, self._evidence, self._registry)
        if decision.allowed and decision.effective_tools:
            with self._lock:
                self._issued_tool_receipts[decision.receipt_sha256] = (
                    decision.request_sha256,
                    decision,
                )
        return decision

    def consume_tool_authority(
        self,
        decision: RuntimeAdmissionDecision,
    ) -> tuple[RuntimeToolGrant, ...]:
        verified = RuntimeAdmissionDecision.model_validate(decision.model_dump(mode="python"))
        if not verified.allowed:
            raise RuntimeError("C4 denied admission cannot expose MCP tools")
        if verified.action not in {
            RuntimeAdmissionAction.CHATGPT_ACTION,
            RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE,
        }:
            raise RuntimeError("C4 admission action cannot expose MCP tools")
        with self._lock:
            issued = self._issued_tool_receipts.get(verified.receipt_sha256)
            if issued is None or issued[0] != verified.request_sha256 or issued[1] is not decision:
                raise RuntimeError("C4 tool authority was not issued or was already consumed")
            del self._issued_tool_receipts[verified.receipt_sha256]
        return verified.effective_tools


def _path_has_reparse_component(path: Path, *, root: Path) -> bool:
    current = path
    root_resolved = root.resolve()
    while True:
        is_junction = getattr(current, "is_junction", lambda: False)
        if current.exists() and (current.is_symlink() or is_junction()):
            return True
        if current == root_resolved:
            return False
        if root_resolved not in current.parents:
            return True
        current = current.parent


def _assert_reviewed_repository_path(*, root: Path, path: Path) -> None:
    root_resolved = root.resolve()
    if not path.exists() or not path.is_file():
        raise ValueError("C4 reviewed repository JSON is missing")
    if _path_has_reparse_component(path.absolute(), root=root_resolved):
        raise ValueError("C4 reviewed repository JSON uses a reparse path")
    resolved = path.resolve()
    if root_resolved not in resolved.parents:
        raise ValueError("C4 reviewed repository JSON escapes the repository")


def load_production_c4_registry(
    *,
    root: Path,
    registry_path: Path,
) -> RuntimeAdapterRegistry:
    root_resolved = root.resolve()
    path_resolved = registry_path.resolve()
    if root_resolved not in path_resolved.parents:
        raise ValueError("C4 runtime adapter registry escapes the repository")
    if _path_has_reparse_component(registry_path.absolute(), root=root_resolved):
        raise ValueError("C4 runtime adapter registry uses a reparse path")
    raw = json.loads(path_resolved.read_text(encoding="utf-8"))
    registry = RuntimeAdapterRegistry.model_validate(raw)
    expected = build_current_c4_adapter_registry()
    if registry.model_dump(mode="json") != expected.model_dump(mode="json"):
        raise ValueError("C4 runtime adapter registry differs from the reviewed builder")
    if tuple(adapter.identity.provider_id for adapter in registry.adapters) != ("chatgpt",):
        raise ValueError("C4 production registry contains an unreviewed provider")
    return registry


def evaluate_committed_runtime_admission(
    *,
    root: Path,
    c3_registry_path: Path,
    c4_registry_path: Path,
    request: RuntimeAdmissionRequest,
) -> RuntimeAdmissionDecision:
    try:
        _assert_reviewed_repository_path(root=root, path=c3_registry_path)
        _assert_reviewed_repository_path(
            root=root,
            path=root / C3_PROFILE_PATH,
        )
        c3_decision = evaluate_c3_registry(
            root=root,
            registry_path=c3_registry_path,
            evaluated_at=request.evaluated_at,
        )
        evidence = evidence_snapshot_from_c3(c3_decision)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        evidence = _invalid_evidence_snapshot(
            evaluated_at=request.evaluated_at,
            reason="c3_reviewed_path_invalid",
        )
    try:
        registry = load_production_c4_registry(
            root=root,
            registry_path=c4_registry_path,
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return _commit_decision(
            request=request,
            evidence=evidence,
            c4_registry_sha256=None,
            allowed=False,
            reason_code=AdmissionReasonCode.RUNTIME_REGISTRY_INVALID,
        )
    return evaluate_runtime_admission(request, evidence, registry)


def create_committed_runtime_admission_controller(
    *,
    root: Path,
    c3_registry_path: Path,
    c4_registry_path: Path,
    evaluated_at: datetime,
) -> RuntimeAdmissionController:
    """Create a stateful controller from only reviewed repository evidence."""

    try:
        _assert_reviewed_repository_path(root=root, path=c3_registry_path)
        _assert_reviewed_repository_path(
            root=root,
            path=root / C3_PROFILE_PATH,
        )
        c3_decision = evaluate_c3_registry(
            root=root,
            registry_path=c3_registry_path,
            evaluated_at=evaluated_at,
        )
        evidence = evidence_snapshot_from_c3(c3_decision)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        evidence = _invalid_evidence_snapshot(
            evaluated_at=evaluated_at,
            reason="c3_reviewed_path_invalid",
        )
    try:
        registry = load_production_c4_registry(
            root=root,
            registry_path=c4_registry_path,
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("C4 reviewed runtime adapter registry is invalid") from error
    return RuntimeAdmissionController(evidence=evidence, registry=registry)


def build_admitted_mcp_registry(
    *,
    policy: Any,
    decision: RuntimeAdmissionDecision,
    controller: RuntimeAdmissionController,
    c0_mode: bool,
) -> McpToolRegistry:
    """Construct a provider-bound MCP registry only from a valid allow receipt."""

    from .mcp_tools import McpToolRegistry

    effective_tools = controller.consume_tool_authority(decision)
    effective_names = frozenset(tool.name for tool in effective_tools)
    registry = McpToolRegistry(
        policy,
        c0_mode=c0_mode,
        effective_tool_names=effective_names,
    )
    actual = {tool.name: canonical_sha256(tool.protocol_dict()) for tool in registry.list_tools()}
    expected = {tool.name: tool.protocol_sha256 for tool in effective_tools}
    if actual != expected:
        raise RuntimeError("C4 effective MCP tool metadata differs from admission")
    return registry


def _approved_request_tools(
    registry: RuntimeAdapterRegistry,
    action: RuntimeAdmissionAction,
) -> tuple[RuntimeToolGrant, ...]:
    if action not in {
        RuntimeAdmissionAction.CHATGPT_ACTION,
        RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE,
    }:
        return ()
    return registry.adapters[0].approved_tools


def _correlation_for(action: RuntimeAdmissionAction, evaluated_at: datetime) -> str:
    seed = f"{action.value}:{evaluated_at.isoformat()}".encode("utf-8")
    return "c4_" + sha256(seed).hexdigest()[:32]


def _json_output(model: BaseModel) -> str:
    value = model.model_dump(mode="json")
    _assert_secret_free(value)
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate C4 runtime admission offline.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    registry = subparsers.add_parser("registry")
    registry.add_argument("--compact", action="store_true")

    for name in ("preflight", "matrix"):
        command = subparsers.add_parser(name)
        command.add_argument("--root", type=Path, required=True)
        command.add_argument("--c3-registry", type=Path, required=True)
        command.add_argument("--c4-registry", type=Path, required=True)
        command.add_argument("--as-of")
        if name == "preflight":
            command.add_argument(
                "--action",
                choices=[action.value for action in RuntimeAdmissionAction],
                required=True,
            )
            command.add_argument("--correlation", required=True)
            command.add_argument("--request-approved-tools", action="store_true")
        else:
            command.add_argument("--expect-all-denied", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "registry":
            registry = build_current_c4_adapter_registry()
            if args.compact:
                print(
                    json.dumps(
                        registry.model_dump(mode="json"),
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            else:
                print(_json_output(registry))
            return 0

        evaluated_at = _parse_timestamp(args.as_of)
        root = args.root.resolve()
        template_registry = build_current_c4_adapter_registry()
        identity = template_registry.adapters[0].identity

        if args.command == "preflight":
            action = RuntimeAdmissionAction(args.action)
            requested_tools = (
                _approved_request_tools(template_registry, action)
                if args.request_approved_tools
                else ()
            )
            request = commit_runtime_admission_request(
                identity=identity,
                action=action,
                requested_tools=requested_tools,
                evaluated_at=evaluated_at,
                request_correlation=args.correlation,
            )
            decision = evaluate_committed_runtime_admission(
                root=root,
                c3_registry_path=args.c3_registry,
                c4_registry_path=args.c4_registry,
                request=request,
            )
            print(_json_output(decision))
            return 0 if decision.allowed else 3

        decisions: list[RuntimeAdmissionDecision] = []
        for action in RuntimeAdmissionAction:
            request = commit_runtime_admission_request(
                identity=identity,
                action=action,
                requested_tools=_approved_request_tools(template_registry, action),
                evaluated_at=evaluated_at,
                request_correlation=_correlation_for(action, evaluated_at),
            )
            decisions.append(
                evaluate_committed_runtime_admission(
                    root=root,
                    c3_registry_path=args.c3_registry,
                    c4_registry_path=args.c4_registry,
                    request=request,
                )
            )
        payload = {
            "version": "1",
            "evaluated_at": evaluated_at.isoformat().replace("+00:00", "Z"),
            "all_actions_denied": all(not decision.allowed for decision in decisions),
            "effective_tool_count": sum(len(decision.effective_tools) for decision in decisions),
            "decisions": [decision.model_dump(mode="json") for decision in decisions],
        }
        _assert_secret_free(payload)
        print(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False))
        if args.expect_all_denied and (
            not payload["all_actions_denied"] or payload["effective_tool_count"] != 0
        ):
            return 5
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        print(
            json.dumps(
                {
                    "status": "error",
                    "error": "C4 runtime admission input or evidence is invalid",
                },
                sort_keys=True,
            )
        )
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
