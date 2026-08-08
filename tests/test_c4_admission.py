from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c0_probe import C0_TOOL_NAME
from systeme_local_gateway.c3_evidence import (
    C3ProtectedAction,
    EvidenceLifecycleState,
    EvidenceReviewerState,
    OfficialSupportState,
)
from systeme_local_gateway.c4_admission import (
    AdmissionEvidenceSnapshot,
    AdmissionReasonCode,
    C3ActionBinding,
    RuntimeAdapterRegistry,
    RuntimeAdmissionAction,
    RuntimeAdmissionController,
    RuntimeAdmissionDecision,
    RuntimeAdmissionRequest,
    RuntimeCapabilityIdentity,
    RuntimeProviderAdapter,
    RuntimeToolGrant,
    ToolAccessMode,
    build_admitted_mcp_registry,
    build_current_c4_adapter_registry,
    canonical_sha256,
    commit_runtime_admission_request,
    evaluate_committed_runtime_admission,
    evaluate_runtime_admission,
    load_production_c4_registry,
)
from systeme_local_gateway.mcp_tools import McpToolRegistry
from systeme_local_gateway.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _identity(
    *,
    provider_id: str = "chatgpt",
    native_surface: str = "chat",
) -> RuntimeCapabilityIdentity:
    return RuntimeCapabilityIdentity(
        provider_id=provider_id,
        native_surface=native_surface,
        surface_class="conversational_chat",
        capability="custom_or_local_mcp_tool_invocation",
    )


def _read_only_tool(
    *,
    name: str = C0_TOOL_NAME,
    protocol_sha256: str = ("de0389f0a2329daa8afa3ad8126eb6e3e80aba1b77ed2e0f29998c37c383c65b"),
) -> RuntimeToolGrant:
    return RuntimeToolGrant(
        name=name,
        access_mode=ToolAccessMode.READ_ONLY,
        protocol_sha256=protocol_sha256,
        read_only=True,
        destructive=False,
        high_risk=False,
    )


def _registry(
    *,
    identity: RuntimeCapabilityIdentity | None = None,
    tools: tuple[RuntimeToolGrant, ...] | None = None,
) -> RuntimeAdapterRegistry:
    adapter = RuntimeProviderAdapter(
        identity=identity or _identity(),
        approved_tools=tools if tools is not None else (_read_only_tool(),),
    )
    payload: dict[str, Any] = {
        "version": "1",
        "adapters": [adapter.model_dump(mode="json")],
    }
    return RuntimeAdapterRegistry(
        **payload,
        registry_sha256=canonical_sha256(payload),
    )


def _evidence(
    *,
    identity: RuntimeCapabilityIdentity | None = None,
    support: OfficialSupportState | None = OfficialSupportState.SUPPORTED,
    reviewer: EvidenceReviewerState | None = EvidenceReviewerState.REVIEWED,
    lifecycle: EvidenceLifecycleState = EvidenceLifecycleState.CURRENT,
    allowed_actions: bool = True,
) -> AdmissionEvidenceSnapshot:
    resolved_identity = _identity() if identity is None else identity
    return AdmissionEvidenceSnapshot(
        identity=resolved_identity,
        support_state=support,
        reviewer_state=reviewer,
        lifecycle_state=lifecycle,
        evaluated_at=NOW,
        c3_registry_sha256=SHA_A,
        c3_profile_sha256=SHA_B,
        c3_evidence_sha256=SHA_C,
        c3_decision_sha256=SHA_D,
        c3_reason_code="synthetic_test_evidence",
        action_decisions=tuple(
            C3ActionBinding(action=action, allowed=allowed_actions)
            for action in sorted(C3ProtectedAction, key=lambda item: item.value)
        ),
    )


def _request(
    action: RuntimeAdmissionAction,
    *,
    identity: RuntimeCapabilityIdentity | None = None,
    tools: tuple[RuntimeToolGrant, ...] | None = None,
    correlation: str = "c4_" + ("1" * 32),
    evaluated_at: datetime = NOW,
) -> RuntimeAdmissionRequest:
    if tools is None:
        tools = (
            (_read_only_tool(),)
            if action
            in {
                RuntimeAdmissionAction.CHATGPT_ACTION,
                RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE,
            }
            else ()
        )
    return commit_runtime_admission_request(
        identity=identity or _identity(),
        action=action,
        requested_tools=tools,
        evaluated_at=evaluated_at,
        request_correlation=correlation,
    )


def _mutated_model(
    model: RuntimeAdmissionRequest | RuntimeAdmissionDecision,
    **changes: Any,
) -> dict[str, Any]:
    value = model.model_dump(mode="json")
    value.update(changes)
    return value


def test_reviewed_production_registry_is_exact_and_single_provider() -> None:
    built = build_current_c4_adapter_registry()
    committed = load_production_c4_registry(
        root=ROOT,
        registry_path=ROOT / "governance/c4-runtime-adapters.json",
    )

    assert committed == built
    assert [adapter.identity.provider_id for adapter in committed.adapters] == ["chatgpt"]
    assert committed.registry_sha256 == (
        "c63ae8d266ba25f7871b60f4f36b659b97a4f17e6fd13fc32b7acd6dcf85c20d"
    )


@pytest.mark.parametrize("action", list(RuntimeAdmissionAction))
def test_current_chatgpt_profile_denies_every_action_and_all_tools(
    action: RuntimeAdmissionAction,
) -> None:
    request = _request(action)
    decision = evaluate_committed_runtime_admission(
        root=ROOT,
        c3_registry_path=ROOT / "governance/c3-capability-registry.json",
        c4_registry_path=ROOT / "governance/c4-runtime-adapters.json",
        request=request,
    )

    assert decision.allowed is False
    assert decision.reason_code is AdmissionReasonCode.OFFICIAL_CAPABILITY_UNSUPPORTED
    assert decision.support_state is OfficialSupportState.UNSUPPORTED
    assert decision.lifecycle_state is EvidenceLifecycleState.CURRENT
    assert decision.effective_tools == ()


@pytest.mark.parametrize(
    "action",
    [
        RuntimeAdmissionAction.RUNTIME_KEY_CREATION,
        RuntimeAdmissionAction.TUNNEL_START,
        RuntimeAdmissionAction.PLUGIN_CREATION,
        RuntimeAdmissionAction.BROWSER_TEST,
    ],
)
def test_synthetic_supported_evidence_admits_non_tool_actions(
    action: RuntimeAdmissionAction,
) -> None:
    decision = evaluate_runtime_admission(_request(action), _evidence(), _registry())

    assert decision.allowed is True
    assert decision.reason_code is AdmissionReasonCode.ADMITTED
    assert decision.effective_tools == ()


@pytest.mark.parametrize(
    "action",
    [
        RuntimeAdmissionAction.CHATGPT_ACTION,
        RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE,
    ],
)
def test_synthetic_supported_evidence_exposes_only_exact_read_only_tool(
    action: RuntimeAdmissionAction,
) -> None:
    request = _request(action)
    decision = evaluate_runtime_admission(request, _evidence(), _registry())

    assert decision.allowed is True
    assert decision.effective_tools == request.requested_tools
    assert [tool.name for tool in decision.effective_tools] == [C0_TOOL_NAME]
    assert all(tool.access_mode is ToolAccessMode.READ_ONLY for tool in decision.effective_tools)


@pytest.mark.parametrize(
    ("lifecycle", "reason"),
    [
        (
            EvidenceLifecycleState.REVALIDATION_DUE,
            AdmissionReasonCode.EVIDENCE_REVALIDATION_DUE,
        ),
        (EvidenceLifecycleState.EXPIRED, AdmissionReasonCode.EVIDENCE_EXPIRED),
        (
            EvidenceLifecycleState.SOURCE_DRIFT,
            AdmissionReasonCode.EVIDENCE_SOURCE_DRIFT,
        ),
        (EvidenceLifecycleState.INVALID, AdmissionReasonCode.EVIDENCE_INVALID),
    ],
)
def test_every_noncurrent_lifecycle_state_denies(
    lifecycle: EvidenceLifecycleState,
    reason: AdmissionReasonCode,
) -> None:
    decision = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.TUNNEL_START),
        _evidence(lifecycle=lifecycle),
        _registry(),
    )

    assert decision.allowed is False
    assert decision.reason_code is reason


@pytest.mark.parametrize(
    ("support", "reason"),
    [
        (
            OfficialSupportState.UNSUPPORTED,
            AdmissionReasonCode.OFFICIAL_CAPABILITY_UNSUPPORTED,
        ),
        (
            OfficialSupportState.UNOBSERVABLE,
            AdmissionReasonCode.OFFICIAL_CAPABILITY_UNOBSERVABLE,
        ),
    ],
)
def test_non_supported_evidence_denies(
    support: OfficialSupportState,
    reason: AdmissionReasonCode,
) -> None:
    decision = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.RUNTIME_KEY_CREATION),
        _evidence(support=support),
        _registry(),
    )

    assert decision.allowed is False
    assert decision.reason_code is reason


def test_candidate_evidence_has_no_admission_authority() -> None:
    decision = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.BROWSER_TEST),
        _evidence(reviewer=EvidenceReviewerState.CANDIDATE),
        _registry(),
    )

    assert decision.allowed is False
    assert decision.reason_code is AdmissionReasonCode.EVIDENCE_CANDIDATE


def test_c3_action_denial_is_preserved_even_with_supported_evidence() -> None:
    decision = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.PLUGIN_CREATION),
        _evidence(allowed_actions=False),
        _registry(),
    )

    assert decision.allowed is False
    assert decision.reason_code is AdmissionReasonCode.C3_ACTION_DENIED


def test_unknown_provider_and_known_provider_surface_substitution_deny() -> None:
    unknown = _identity(provider_id="synthetic_ai")
    unknown_decision = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.TUNNEL_START, identity=unknown),
        _evidence(identity=unknown),
        _registry(),
    )
    substituted = _identity(native_surface="work")
    substituted_decision = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.TUNNEL_START, identity=substituted),
        _evidence(identity=substituted),
        _registry(),
    )

    assert unknown_decision.reason_code is AdmissionReasonCode.UNKNOWN_ADAPTER
    assert substituted_decision.reason_code is AdmissionReasonCode.ADAPTER_IDENTITY_MISMATCH
    assert not unknown_decision.allowed
    assert not substituted_decision.allowed


def test_synthetic_provider_is_supported_only_by_explicit_test_registry() -> None:
    synthetic = _identity(provider_id="synthetic_ai")
    registry = _registry(identity=synthetic)
    decision = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.TUNNEL_START, identity=synthetic),
        _evidence(identity=synthetic),
        registry,
    )

    assert decision.allowed is True
    assert decision.identity.provider_id == "synthetic_ai"
    assert build_current_c4_adapter_registry().adapters[0].identity.provider_id == "chatgpt"


def test_cross_identity_evidence_substitution_denies() -> None:
    decision = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.TUNNEL_START),
        _evidence(identity=_identity(provider_id="synthetic_ai")),
        _registry(),
    )

    assert decision.allowed is False
    assert decision.reason_code is AdmissionReasonCode.EVIDENCE_IDENTITY_MISMATCH


def test_evidence_time_substitution_denies() -> None:
    request = _request(
        RuntimeAdmissionAction.TUNNEL_START,
        evaluated_at=datetime(2026, 8, 7, 12, 0, 1, tzinfo=UTC),
    )
    decision = evaluate_runtime_admission(request, _evidence(), _registry())

    assert decision.allowed is False
    assert decision.reason_code is AdmissionReasonCode.EVIDENCE_TIME_MISMATCH


def test_tool_action_requires_nonempty_scope_and_other_actions_require_empty_scope() -> None:
    empty_tool_action = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE, tools=()),
        _evidence(),
        _registry(),
    )
    scoped_key_action = evaluate_runtime_admission(
        _request(
            RuntimeAdmissionAction.RUNTIME_KEY_CREATION,
            tools=(_read_only_tool(),),
        ),
        _evidence(),
        _registry(),
    )

    assert empty_tool_action.reason_code is AdmissionReasonCode.ACTION_TOOL_SCOPE_INVALID
    assert scoped_key_action.reason_code is AdmissionReasonCode.ACTION_TOOL_SCOPE_INVALID


def test_unapproved_tool_metadata_mutation_and_privilege_expansion_deny() -> None:
    unapproved = _read_only_tool(name="workspace.read_text")
    mutated = _read_only_tool(protocol_sha256="f" * 64)
    write_tool = RuntimeToolGrant(
        name=C0_TOOL_NAME,
        access_mode=ToolAccessMode.WRITE,
        protocol_sha256=_read_only_tool().protocol_sha256,
        read_only=False,
        destructive=True,
        high_risk=False,
    )

    unapproved_decision = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.CHATGPT_ACTION, tools=(unapproved,)),
        _evidence(),
        _registry(),
    )
    mutated_decision = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.CHATGPT_ACTION, tools=(mutated,)),
        _evidence(),
        _registry(),
    )
    expanded_decision = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.CHATGPT_ACTION, tools=(write_tool,)),
        _evidence(),
        _registry(),
    )

    assert unapproved_decision.reason_code is AdmissionReasonCode.TOOL_NOT_APPROVED
    assert mutated_decision.reason_code is AdmissionReasonCode.TOOL_METADATA_MISMATCH
    assert expanded_decision.reason_code is AdmissionReasonCode.TOOL_PRIVILEGE_EXPANSION


def test_request_unknown_fields_duplicates_naive_time_and_digest_mutation_reject() -> None:
    request = _request(RuntimeAdmissionAction.CHATGPT_ACTION)
    unknown = request.model_dump(mode="json")
    unknown["secret"] = "not-allowed"
    duplicate = request.model_dump(mode="json")
    duplicate["requested_tools"] = duplicate["requested_tools"] * 2
    naive = request.model_dump(mode="json")
    naive["evaluated_at"] = "2026-07-27T12:00:00"

    with pytest.raises(ValidationError):
        RuntimeAdmissionRequest.model_validate(unknown)
    with pytest.raises(ValidationError):
        RuntimeAdmissionRequest.model_validate(duplicate)
    with pytest.raises(ValidationError):
        RuntimeAdmissionRequest.model_validate(naive)
    with pytest.raises(ValidationError, match="digest mismatch"):
        RuntimeAdmissionRequest.model_validate(_mutated_model(request, action="tunnel_start"))


def test_unvalidated_model_copy_cannot_bypass_defensive_runtime_validation() -> None:
    request = _request(RuntimeAdmissionAction.TUNNEL_START)
    unsafe = request.model_copy(update={"request_sha256": "0" * 64})
    controller = RuntimeAdmissionController(
        evidence=_evidence(),
        registry=_registry(),
    )

    with pytest.raises(ValidationError, match="digest mismatch"):
        evaluate_runtime_admission(unsafe, _evidence(), _registry())
    with pytest.raises(ValidationError, match="digest mismatch"):
        controller.decide(unsafe)


@pytest.mark.parametrize(
    "correlation",
    [
        "",
        "c4_" + ("A" * 32),
        "c4_" + ("1" * 31),
        "tunnel_" + ("1" * 32),
    ],
)
def test_invalid_correlation_formats_reject(correlation: str) -> None:
    with pytest.raises(ValidationError):
        _request(
            RuntimeAdmissionAction.TUNNEL_START,
            correlation=correlation,
        )


def test_receipt_is_deterministic_and_any_mutation_rejects() -> None:
    request = _request(RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE)
    first = evaluate_runtime_admission(request, _evidence(), _registry())
    second = evaluate_runtime_admission(request, _evidence(), _registry())

    assert first == second
    assert first.receipt_sha256 == second.receipt_sha256
    with pytest.raises(ValidationError, match="receipt digest mismatch"):
        RuntimeAdmissionDecision.model_validate(_mutated_model(first, allowed=False))


def test_self_consistent_but_semantically_invalid_decision_rejects() -> None:
    decision = evaluate_runtime_admission(
        _request(RuntimeAdmissionAction.TUNNEL_START),
        _evidence(),
        _registry(),
    )
    payload = decision.receipt_payload()
    payload["allowed"] = False
    payload["reason_code"] = AdmissionReasonCode.ADMITTED.value

    with pytest.raises(ValidationError, match="cannot use the admitted reason"):
        RuntimeAdmissionDecision(
            **payload,
            receipt_sha256=canonical_sha256(payload),
        )


def test_replay_and_correlation_collision_are_distinct_denials() -> None:
    controller = RuntimeAdmissionController(
        evidence=_evidence(),
        registry=_registry(),
    )
    request = _request(RuntimeAdmissionAction.TUNNEL_START)
    first = controller.decide(request)
    replay = controller.decide(request)
    collision = controller.decide(
        _request(
            RuntimeAdmissionAction.PLUGIN_CREATION,
            correlation=request.request_correlation,
        )
    )

    assert first.allowed is True
    assert replay.reason_code is AdmissionReasonCode.CORRELATION_REPLAY
    assert collision.reason_code is AdmissionReasonCode.CORRELATION_COLLISION
    assert not replay.allowed and not collision.allowed


def test_concurrent_same_correlation_allows_exactly_one_request() -> None:
    controller = RuntimeAdmissionController(
        evidence=_evidence(),
        registry=_registry(),
    )
    request = _request(RuntimeAdmissionAction.TUNNEL_START)

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        decisions = list(executor.map(lambda _: controller.decide(request), range(40)))

    assert sum(decision.allowed for decision in decisions) == 1
    assert (
        sum(
            decision.reason_code is AdmissionReasonCode.CORRELATION_REPLAY for decision in decisions
        )
        == 39
    )


def test_correlation_capacity_exhaustion_denies_without_eviction() -> None:
    controller = RuntimeAdmissionController(
        evidence=_evidence(),
        registry=_registry(),
        max_correlations=1,
    )
    first = controller.decide(_request(RuntimeAdmissionAction.TUNNEL_START))
    exhausted_request = _request(
        RuntimeAdmissionAction.PLUGIN_CREATION,
        correlation="c4_" + ("2" * 32),
    )
    exhausted = controller.decide(exhausted_request)
    retry = controller.decide(exhausted_request)

    assert first.allowed is True
    assert exhausted.reason_code is AdmissionReasonCode.CORRELATION_CAPACITY_EXHAUSTED
    assert retry.reason_code is AdmissionReasonCode.CORRELATION_CAPACITY_EXHAUSTED
    assert not exhausted.allowed and not retry.allowed


def test_admitted_registry_exposes_exact_tool_and_denied_receipt_cannot_build() -> None:
    policy = PolicyEngine(ROOT / "policy.c0.yaml")
    controller = RuntimeAdmissionController(
        evidence=_evidence(),
        registry=_registry(),
    )
    allowed = controller.decide(_request(RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE))
    admitted = build_admitted_mcp_registry(
        policy=policy,
        decision=allowed,
        controller=controller,
        c0_mode=True,
    )
    denied = evaluate_runtime_admission(
        _request(
            RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE,
            correlation="c4_" + ("2" * 32),
        ),
        _evidence(support=OfficialSupportState.UNSUPPORTED),
        _registry(),
    )

    assert [tool.name for tool in admitted.list_tools()] == [C0_TOOL_NAME]
    with pytest.raises(RuntimeError, match="denied admission"):
        build_admitted_mcp_registry(
            policy=policy,
            decision=denied,
            controller=controller,
            c0_mode=True,
        )


def test_admitted_registry_rejects_policy_or_protocol_mismatch(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """version: 1
default: deny
capabilities:
  workspace.list:
    decision: allow
""",
        encoding="utf-8",
    )
    controller = RuntimeAdmissionController(
        evidence=_evidence(),
        registry=_registry(),
    )
    decision = controller.decide(_request(RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE))

    with pytest.raises(RuntimeError, match="not provided by the local policy"):
        build_admitted_mcp_registry(
            policy=PolicyEngine(policy_path),
            decision=decision,
            controller=controller,
            c0_mode=True,
        )


def test_tool_authority_rejects_forgery_and_is_consumed_once() -> None:
    policy = PolicyEngine(ROOT / "policy.c0.yaml")
    controller = RuntimeAdmissionController(
        evidence=_evidence(),
        registry=_registry(),
    )
    request = _request(RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE)
    forged = evaluate_runtime_admission(request, _evidence(), _registry())

    with pytest.raises(RuntimeError, match="not issued or was already consumed"):
        build_admitted_mcp_registry(
            policy=policy,
            decision=forged,
            controller=controller,
            c0_mode=True,
        )

    other_controller = RuntimeAdmissionController(
        evidence=_evidence(),
        registry=_registry(),
    )
    issued_elsewhere = other_controller.decide(request)
    with pytest.raises(RuntimeError, match="not issued or was already consumed"):
        build_admitted_mcp_registry(
            policy=policy,
            decision=issued_elsewhere,
            controller=controller,
            c0_mode=True,
        )

    issued = controller.decide(request)
    reconstructed = RuntimeAdmissionDecision.model_validate(issued.model_dump(mode="python"))
    with pytest.raises(RuntimeError, match="not issued or was already consumed"):
        build_admitted_mcp_registry(
            policy=policy,
            decision=reconstructed,
            controller=controller,
            c0_mode=True,
        )
    admitted = build_admitted_mcp_registry(
        policy=policy,
        decision=issued,
        controller=controller,
        c0_mode=True,
    )
    assert [tool.name for tool in admitted.list_tools()] == [C0_TOOL_NAME]
    with pytest.raises(RuntimeError, match="not issued or was already consumed"):
        build_admitted_mcp_registry(
            policy=policy,
            decision=issued,
            controller=controller,
            c0_mode=True,
        )


def test_generic_registry_filter_can_only_reduce_policy_surface(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """version: 1
default: deny
capabilities:
  workspace.list:
    decision: allow
  workspace.read_text:
    decision: allow
""",
        encoding="utf-8",
    )
    policy = PolicyEngine(policy_path)
    reduced = McpToolRegistry(
        policy,
        effective_tool_names=frozenset({"workspace.list"}),
    )

    assert [tool.name for tool in reduced.list_tools()] == ["workspace.list"]
    with pytest.raises(RuntimeError, match="not provided by the local policy"):
        McpToolRegistry(
            policy,
            effective_tool_names=frozenset({"workspace.write_text"}),
        )


def test_registry_rejects_duplicate_adapter_and_unknown_fields() -> None:
    registry = _registry()
    value = registry.model_dump(mode="json")
    value["adapters"] = value["adapters"] * 2
    value["registry_sha256"] = canonical_sha256({"version": "1", "adapters": value["adapters"]})
    unknown = registry.model_dump(mode="json")
    unknown["providers"] = []

    with pytest.raises(ValidationError, match="sorted and unique"):
        RuntimeAdapterRegistry.model_validate(value)
    with pytest.raises(ValidationError):
        RuntimeAdapterRegistry.model_validate(unknown)


def test_production_registry_tamper_denies_without_falling_back(tmp_path: Path) -> None:
    c4_path = tmp_path / "c4-runtime-adapters.json"
    value = build_current_c4_adapter_registry().model_dump(mode="json")
    value["registry_sha256"] = "0" * 64
    c4_path.write_text(json.dumps(value), encoding="utf-8")

    decision = evaluate_committed_runtime_admission(
        root=ROOT,
        c3_registry_path=ROOT / "governance/c3-capability-registry.json",
        c4_registry_path=c4_path,
        request=_request(RuntimeAdmissionAction.TUNNEL_START),
    )

    assert decision.allowed is False
    assert decision.reason_code is AdmissionReasonCode.RUNTIME_REGISTRY_INVALID
    assert decision.c4_registry_sha256 is None


def test_missing_c3_reviewed_profile_denies_as_invalid_evidence(
    tmp_path: Path,
) -> None:
    governance = tmp_path / "governance"
    governance.mkdir()
    c3_path = governance / "c3-capability-registry.json"
    c4_path = governance / "c4-runtime-adapters.json"
    shutil.copyfile(ROOT / "governance/c3-capability-registry.json", c3_path)
    shutil.copyfile(ROOT / "governance/c4-runtime-adapters.json", c4_path)

    decision = evaluate_committed_runtime_admission(
        root=tmp_path,
        c3_registry_path=c3_path,
        c4_registry_path=c4_path,
        request=_request(RuntimeAdmissionAction.TUNNEL_START),
    )

    assert decision.allowed is False
    assert decision.reason_code is AdmissionReasonCode.EVIDENCE_INVALID
    assert decision.c3_registry_sha256 is None
    assert decision.c3_profile_sha256 is None


def test_reparse_runtime_registry_is_rejected(tmp_path: Path) -> None:
    linked = tmp_path / "c4-runtime-adapters.json"
    try:
        linked.symlink_to(ROOT / "governance/c4-runtime-adapters.json")
    except OSError as error:
        pytest.skip(f"symbolic links are unavailable: {error}")

    with pytest.raises(ValueError, match="reparse"):
        load_production_c4_registry(root=tmp_path, registry_path=linked)


def test_provider_bound_python_import_denies_before_runtime_initialization(
    tmp_path: Path,
) -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "SLG_SHARED_SECRET": "s" * 48,
            "SLG_AUDIT_KEY": "a" * 48,
            "SLG_MCP_TOKEN": "t" * 48,
            "SLG_MCP_ENABLED": "true",
            "SLG_C0_ENABLED": "true",
            "SLG_C0_SERVER_BUILD_COMMIT": "a" * 40,
            "SLG_PROVIDER_RUNTIME_MODE": "chatgpt_chat_c4",
            "SLG_PROVIDER_RUNTIME_ROOT": str(ROOT),
            "SLG_POLICY_FILE": str(ROOT / "policy.c0.yaml"),
            "SLG_WORKSPACE": str(ROOT),
            "SLG_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
            "SLG_REPLAY_DB": str(tmp_path / "replay.sqlite3"),
            "SLG_APPROVAL_DB": str(tmp_path / "approvals.sqlite3"),
            "SLG_SANDBOX_ROOT": str(tmp_path / "sandboxes"),
        }
    )
    result = subprocess.run(
        [sys.executable, "-c", "import systeme_local_gateway.main"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert "C4 provider runtime admission denied: official_capability_unsupported" in combined
    assert "ssssssss" not in combined
    assert "aaaaaaaa" not in combined
    assert "tttttttt" not in combined


def test_cli_matrix_is_deterministic_denied_and_secret_free() -> None:
    command = [
        sys.executable,
        "-m",
        "systeme_local_gateway.c4_admission",
        "matrix",
        "--root",
        str(ROOT),
        "--c3-registry",
        str(ROOT / "governance/c3-capability-registry.json"),
        "--c4-registry",
        str(ROOT / "governance/c4-runtime-adapters.json"),
        "--as-of",
        "2026-07-27T12:00:00Z",
    ]
    first = subprocess.run(command, capture_output=True, text=True, check=False)
    second = subprocess.run(command, capture_output=True, text=True, check=False)

    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout
    payload = json.loads(first.stdout)
    assert payload["all_actions_denied"] is True
    assert payload["effective_tool_count"] == 0
    assert len(payload["decisions"]) == len(RuntimeAdmissionAction)
    lowered = (first.stdout + first.stderr).lower()
    assert "control_plane_api_key" not in lowered
    assert "slg_shared_secret" not in lowered
    assert "bearer " not in lowered


def test_cli_invalid_registry_error_is_bounded_and_does_not_echo_path(
    tmp_path: Path,
) -> None:
    secret_shaped_path = tmp_path / ("sk-" + ("x" * 30) + ".json")
    secret_shaped_path.write_text("{}", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c4_admission",
            "preflight",
            "--root",
            str(ROOT),
            "--c3-registry",
            str(ROOT / "governance/c3-capability-registry.json"),
            "--c4-registry",
            str(secret_shaped_path),
            "--as-of",
            "2026-07-27T12:00:00Z",
            "--action",
            "tunnel_start",
            "--correlation",
            "c4_" + ("3" * 32),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 3
    payload = json.loads(result.stdout)
    assert payload["allowed"] is False
    assert payload["reason_code"] == "runtime_registry_invalid"
    assert "sk-" not in result.stdout
    assert result.stderr == ""
