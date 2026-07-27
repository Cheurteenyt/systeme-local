from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from systeme_local_gateway.audit import AuditLog
from systeme_local_gateway.c0_proof_check import canonical_c0_audit_record_sha256
from systeme_local_gateway.c1_attest import main as c1_attest_main
from systeme_local_gateway.c1_evidence import main as c1_evidence_main
from systeme_local_gateway.c1_observability import (
    C1_CONFIGURATION_PRECEDENCE,
    C1C0DependencyStatus,
    C1CanonicalReasoningEffort,
    C1ChatProofBundle,
    C1ConfigurationLayer,
    C1EvidenceSource,
    C1EvidenceState,
    C1NegativeCheckId,
    C1NegativeOutcome,
    C1RuntimeSetupObservation,
    C1SettingObservation,
    C1SetupField,
    C1Surface,
    C1SurfaceObservation,
    C1TestChatLabel,
    C1TestChatObservation,
    C1VisibleModelObservation,
    build_current_c1_official_evidence_profile,
    canonical_sha256,
    commit_c1_chat_correlation_receipt,
    commit_c1_final_attestation,
    commit_c1_negative_test_receipt,
    commit_c1_revocation_receipt,
    commit_c1_runtime_setup_observation,
    commit_c1_surface_observation,
    commit_c1_visible_model_observation,
    verify_c1_chat_correlation_receipt,
    verify_c1_runtime_setup_observation,
)
from systeme_local_gateway.mcp_tools import McpToolRegistry
from systeme_local_gateway.policy import PolicyEngine

NOW = datetime(2026, 7, 26, 17, 40, tzinfo=UTC)
AUDIT_KEY = "c1-independent-audit-key-that-is-long-enough"
COMMIT = "1" * 40
POLICY = "2" * 64
TOOLS = "3" * 64
AUDIT_A = "12345678-1234-4123-8123-123456789abc"
AUDIT_B = "22345678-1234-4234-8234-123456789abc"


def _setting(
    value: str | bool | int | tuple[str, ...] | None,
    *,
    state: C1EvidenceState = C1EvidenceState.OBSERVED,
    source: C1EvidenceSource = C1EvidenceSource.SYSTEM_RUNTIME,
) -> C1SettingObservation:
    return C1SettingObservation(
        value=value,
        state=state,
        evidence_source=source,
        observed_at=NOW,
    )


def _settings(
    *,
    model: str = "gpt-5.6-sol",
    reasoning: str = "xhigh",
) -> dict[C1SetupField, C1SettingObservation]:
    values = {field: _setting(field.value) for field in C1SetupField}
    values[C1SetupField.ACTIVE_RUNTIME_MODEL] = _setting(
        model,
        source=C1EvidenceSource.CODEX_TURN_METADATA,
    )
    values[C1SetupField.ACTIVE_REASONING_EFFORT] = _setting(
        reasoning,
        source=C1EvidenceSource.CODEX_TURN_METADATA,
    )
    values[C1SetupField.CONFIGURED_DEFAULT_MODEL] = _setting(
        "gpt-5.6-sol",
        state=C1EvidenceState.CONFIGURED_DEFAULT,
        source=C1EvidenceSource.CODEX_USER_CONFIG,
    )
    values[C1SetupField.CONFIGURED_DEFAULT_REASONING] = _setting(
        "xhigh",
        state=C1EvidenceState.CONFIGURED_DEFAULT,
        source=C1EvidenceSource.CODEX_USER_CONFIG,
    )
    values[C1SetupField.ACTIVE_SERVICE_TIER] = _setting(
        None,
        state=C1EvidenceState.UNOBSERVABLE,
        source=C1EvidenceSource.CODEX_TURN_METADATA,
    )
    values[C1SetupField.AUTHENTICATION_BOUNDARY] = _setting(
        None,
        state=C1EvidenceState.UNOBSERVABLE,
        source=C1EvidenceSource.CODEX_TURN_METADATA,
    )
    values[C1SetupField.APPROVAL_REVIEWER] = _setting(
        None,
        state=C1EvidenceState.NOT_APPLICABLE,
        source=C1EvidenceSource.CODEX_PERMISSION_CONTEXT,
    )
    values[C1SetupField.ENABLED_PLUGIN_NAMES] = _setting(("github", "sites"))
    values[C1SetupField.CONFIGURED_MCP_SERVER_NAMES] = _setting(
        ("node_repl", "openaiDeveloperDocs")
    )
    values[C1SetupField.HEAD_COMMIT] = _setting(COMMIT)
    values[C1SetupField.BRANCH] = _setting("interop/chatgpt-web-chat-observability-c1")
    values[C1SetupField.WORKTREE_STATE] = _setting("clean")
    values[C1SetupField.POLICY_SHA256] = _setting(POLICY)
    values[C1SetupField.TOOL_SNAPSHOT_SHA256] = _setting(TOOLS)
    return values


def _setup(
    *,
    model: str = "gpt-5.6-sol",
    reasoning: str = "xhigh",
    simulated: bool = False,
) -> C1RuntimeSetupObservation:
    return commit_c1_runtime_setup_observation(
        settings=_settings(model=model, reasoning=reasoning),
        configuration_precedence=tuple(
            C1ConfigurationLayer(value) for value in C1_CONFIGURATION_PRECEDENCE
        ),
        observed_at=NOW,
        expires_at=NOW + timedelta(hours=2),
        audit_key=AUDIT_KEY,
        simulated=simulated,
    )


def _surface(label: C1TestChatLabel, *, simulated: bool = False) -> C1SurfaceObservation:
    return commit_c1_surface_observation(
        test_chat_label=label,
        surface=C1Surface.CHAT,
        plugin_selected=True,
        observed_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
        audit_key=AUDIT_KEY,
        simulated=simulated,
    )


def _visible(*, simulated: bool = False) -> C1VisibleModelObservation:
    return commit_c1_visible_model_observation(
        visible_model_label="5.6 Sol",
        model_label_state=C1EvidenceState.OBSERVED,
        visible_reasoning_label="Extra High",
        reasoning_label_state=C1EvidenceState.OBSERVED,
        exact_internal_model_id=None,
        canonical_reasoning_effort=C1CanonicalReasoningEffort.XHIGH,
        reasoning_mapping_source_sha256="4" * 64,
        observed_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=50),
        audit_key=AUDIT_KEY,
        simulated=simulated,
    )


def _chat(
    label: C1TestChatLabel,
    surface: C1SurfaceObservation,
) -> C1TestChatObservation:
    is_a = label is C1TestChatLabel.CHAT_A
    return C1TestChatObservation(
        version="1",
        source="manual_chatgpt_web",
        simulated=False,
        test_chat_label=label,
        surface_observation_sha256=canonical_sha256(surface.model_dump(mode="json")),
        tool_name="systeme_local_connectivity_probe",
        tool_count=1,
        write_tool_count=0,
        high_risk_tool_count=0,
        positive_tool_invocation_count=1,
        challenge_sha256=("5" if is_a else "6") * 64,
        response_sha256=("7" if is_a else "8") * 64,
        server_build_commit=COMMIT,
        local_policy_sha256=POLICY,
        tool_snapshot_sha256=TOOLS,
        audit_correlation=AUDIT_A if is_a else AUDIT_B,
        audit_record_sha256=("9" if is_a else "a") * 64,
        read_only=True,
        write_actions_enabled=False,
        real_evidence_access=False,
        protocol_v2_reachable=False,
        work_invoked=False,
        existing_chats_accessed=False,
        conversation_identifier_collected=False,
        private_browser_state_accessed=False,
        observed_at=NOW + timedelta(minutes=5 if is_a else 6),
        expires_at=NOW + timedelta(minutes=50),
    )


def _negative(*, simulated: bool = False):
    outcomes = {
        check_id: (
            C1NegativeOutcome.UNREACHABLE_AFTER_REVOCATION
            if check_id is C1NegativeCheckId.POST_REVOCATION_CALL
            else (
                C1NegativeOutcome.REJECTED
                if check_id
                in {
                    C1NegativeCheckId.SAME_CHAT_REPLAY,
                    C1NegativeCheckId.CROSS_CHAT_REPLAY,
                    C1NegativeCheckId.UNKNOWN_FIELD,
                    C1NegativeCheckId.MALFORMED_CHALLENGE,
                }
                else C1NegativeOutcome.CAPABILITY_NOT_EXPOSED
            )
        )
        for check_id in C1NegativeCheckId
    }
    return commit_c1_negative_test_receipt(
        outcomes=outcomes,
        observed_at=NOW + timedelta(minutes=15),
        expires_at=NOW + timedelta(minutes=50),
        audit_key=AUDIT_KEY,
        simulated=simulated,
    )


def _complete_inputs(*, simulated_setup: bool = False):
    surface_a = _surface(C1TestChatLabel.CHAT_A)
    surface_b = _surface(C1TestChatLabel.CHAT_B)
    chat_a = _chat(C1TestChatLabel.CHAT_A, surface_a)
    chat_b = _chat(C1TestChatLabel.CHAT_B, surface_b)
    receipt_a = commit_c1_chat_correlation_receipt(
        observation=chat_a,
        audit_records_verified=1,
        checked_at=NOW + timedelta(minutes=7),
        expires_at=NOW + timedelta(minutes=50),
        audit_key=AUDIT_KEY,
    )
    receipt_b = commit_c1_chat_correlation_receipt(
        observation=chat_b,
        audit_records_verified=2,
        checked_at=NOW + timedelta(minutes=8),
        expires_at=NOW + timedelta(minutes=50),
        audit_key=AUDIT_KEY,
    )
    revocation = commit_c1_revocation_receipt(
        verified_at=NOW + timedelta(minutes=16),
        expires_at=NOW + timedelta(minutes=50),
        audit_key=AUDIT_KEY,
    )
    return {
        "c0_dependency_status": C1C0DependencyStatus.READY_BUT_MANUAL_CHATGPT_WEB_GATE_PENDING,
        "c0_dependency_commit": "b" * 40,
        "official_profile": build_current_c1_official_evidence_profile(),
        "runtime_setup": _setup(simulated=simulated_setup),
        "visible_model": _visible(),
        "surface_observations": (surface_a, surface_b),
        "chat_observations": (chat_a, chat_b),
        "correlation_receipts": (receipt_a, receipt_b),
        "negative_receipt": _negative(),
        "revocation_receipt": revocation,
        "audit_key": AUDIT_KEY,
        "verified_at": NOW + timedelta(minutes=17),
        "expires_at": NOW + timedelta(minutes=25),
    }


def test_official_profile_is_current_sorted_and_canonically_hashed() -> None:
    profile = build_current_c1_official_evidence_profile()

    assert len(profile.sources) == 9
    assert tuple(item.source_id for item in profile.sources) == tuple(
        sorted(item.source_id for item in profile.sources)
    )
    assert profile.profile_sha256 == canonical_sha256(
        profile.model_dump(mode="json", exclude={"profile_sha256"})
    )
    assert all(item.url.startswith("https://") for item in profile.sources)
    plugin_surface = next(
        item for item in profile.sources if item.source_id == "plugin_surface_availability"
    )
    assert plugin_surface.url == "https://learn.chatgpt.com/docs/plugins"
    assert "not available in Chat" in plugin_surface.canonical_summary


def test_runtime_setup_observes_model_and_keeps_defaults_separate() -> None:
    setup = verify_c1_runtime_setup_observation(_setup(), audit_key=AUDIT_KEY)

    runtime = setup.settings[C1SetupField.ACTIVE_RUNTIME_MODEL]
    configured = setup.settings[C1SetupField.CONFIGURED_DEFAULT_MODEL]
    assert runtime.value == "gpt-5.6-sol"
    assert runtime.state is C1EvidenceState.OBSERVED
    assert runtime.evidence_source is C1EvidenceSource.CODEX_TURN_METADATA
    assert configured.value == "gpt-5.6-sol"
    assert configured.state is C1EvidenceState.CONFIGURED_DEFAULT


@pytest.mark.parametrize("model", ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"])
def test_gpt_5_6_variants_remain_exact_and_distinct(model: str) -> None:
    setup = _setup(model=model)

    assert setup.settings[C1SetupField.ACTIVE_RUNTIME_MODEL].value == model


@pytest.mark.parametrize("reasoning", ["high", "xhigh", "max", "ultra"])
def test_reasoning_effort_keeps_canonical_values_distinct(reasoning: str) -> None:
    setup = _setup(reasoning=reasoning)

    assert setup.settings[C1SetupField.ACTIVE_REASONING_EFFORT].value == reasoning


def test_configured_default_cannot_masquerade_as_active_runtime() -> None:
    settings = _settings()
    settings[C1SetupField.ACTIVE_RUNTIME_MODEL] = _setting(
        "gpt-5.6-sol",
        state=C1EvidenceState.CONFIGURED_DEFAULT,
        source=C1EvidenceSource.CODEX_USER_CONFIG,
    )

    with pytest.raises(ValidationError, match="cannot prove active runtime"):
        commit_c1_runtime_setup_observation(
            settings=settings,
            configuration_precedence=tuple(
                C1ConfigurationLayer(value) for value in C1_CONFIGURATION_PRECEDENCE
            ),
            observed_at=NOW,
            expires_at=NOW + timedelta(hours=1),
            audit_key=AUDIT_KEY,
        )


def test_runtime_hmac_rejects_changed_model() -> None:
    setup = _setup()
    changed = setup.model_copy(
        update={
            "settings": {
                **setup.settings,
                C1SetupField.ACTIVE_RUNTIME_MODEL: _setting("gpt-5.6-terra"),
            }
        }
    )

    with pytest.raises(ValueError, match="HMAC mismatch"):
        verify_c1_runtime_setup_observation(changed, audit_key=AUDIT_KEY)


def test_chat_surface_is_verified_before_prompt_and_work_is_never_tested() -> None:
    surface = _surface(C1TestChatLabel.CHAT_A)

    assert surface.surface is C1Surface.CHAT
    assert surface.prompt_sent is False
    assert surface.plugin_selected is True
    assert surface.work_tested is False


def test_manual_surface_evidence_accepts_two_hours_but_not_more() -> None:
    surface = commit_c1_surface_observation(
        test_chat_label=C1TestChatLabel.CHAT_A,
        surface=C1Surface.CHAT,
        plugin_selected=True,
        observed_at=NOW,
        expires_at=NOW + timedelta(hours=2),
        audit_key=AUDIT_KEY,
    )

    assert surface.expires_at - surface.observed_at == timedelta(hours=2)
    with pytest.raises(ValidationError, match="bounded window"):
        commit_c1_surface_observation(
            test_chat_label=C1TestChatLabel.CHAT_A,
            surface=C1Surface.CHAT,
            plugin_selected=True,
            observed_at=NOW,
            expires_at=NOW + timedelta(hours=2, seconds=1),
            audit_key=AUDIT_KEY,
        )


@pytest.mark.parametrize("surface", [C1Surface.WORK, C1Surface.CODEX, C1Surface.UNKNOWN])
def test_non_chat_surface_refuses_plugin_selection(surface: C1Surface) -> None:
    with pytest.raises(ValidationError, match="outside Chat"):
        commit_c1_surface_observation(
            test_chat_label=C1TestChatLabel.CHAT_A,
            surface=surface,
            plugin_selected=True,
            observed_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
            audit_key=AUDIT_KEY,
        )


def test_work_tested_and_prompt_sent_cannot_become_true() -> None:
    values = _surface(C1TestChatLabel.CHAT_A).model_dump(mode="json")
    values["work_tested"] = True
    with pytest.raises(ValidationError):
        C1SurfaceObservation.model_validate(values)

    values = _surface(C1TestChatLabel.CHAT_A).model_dump(mode="json")
    values["prompt_sent"] = True
    with pytest.raises(ValidationError):
        C1SurfaceObservation.model_validate(values)


def test_localized_reasoning_label_cannot_map_without_official_evidence() -> None:
    with pytest.raises(ValidationError, match="cannot be mapped without evidence"):
        commit_c1_visible_model_observation(
            visible_model_label="5.6 Sol",
            model_label_state=C1EvidenceState.OBSERVED,
            visible_reasoning_label="Très élevé",
            reasoning_label_state=C1EvidenceState.OBSERVED,
            exact_internal_model_id=None,
            canonical_reasoning_effort=C1CanonicalReasoningEffort.XHIGH,
            reasoning_mapping_source_sha256=None,
            observed_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
            audit_key=AUDIT_KEY,
        )


def test_chatgpt_visible_label_cannot_masquerade_as_codex_runtime_evidence() -> None:
    values = _visible().model_dump(mode="json")
    values["active_runtime_model"] = "gpt-5.6-sol"

    with pytest.raises(ValidationError):
        C1VisibleModelObservation.model_validate(values)


def test_chatgpt_internal_model_remains_unclaimed_when_not_exposed() -> None:
    visible = _visible()

    assert visible.visible_model_label == "5.6 Sol"
    assert visible.exact_internal_model_id_exposed is False
    assert visible.exact_internal_model_id is None


@pytest.mark.parametrize(
    "field",
    [
        "conversation_id",
        "cookie",
        "token",
        "authorization_header",
        "browser_storage",
        "personal_chat_content",
    ],
)
def test_private_or_secret_chat_evidence_fields_are_rejected(field: str) -> None:
    surface = _surface(C1TestChatLabel.CHAT_A)
    values = _chat(C1TestChatLabel.CHAT_A, surface).model_dump(mode="json")
    values[field] = "forbidden"

    with pytest.raises(ValidationError):
        C1TestChatObservation.model_validate(values)


def test_secret_like_visible_labels_are_rejected() -> None:
    with pytest.raises(ValidationError, match="secret-like"):
        commit_c1_visible_model_observation(
            visible_model_label="Bearer definitely-secret-value",
            model_label_state=C1EvidenceState.OBSERVED,
            visible_reasoning_label=None,
            reasoning_label_state=C1EvidenceState.UNOBSERVABLE,
            exact_internal_model_id=None,
            canonical_reasoning_effort=None,
            reasoning_mapping_source_sha256=None,
            observed_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
            audit_key=AUDIT_KEY,
        )


def test_two_correlated_test_chats_create_final_attestation() -> None:
    attestation = commit_c1_final_attestation(**_complete_inputs())

    assert attestation.status == "COMPLETE_BOUNDED_CHAT_SURFACE_OBSERVABILITY_VERIFIED"
    assert attestation.test_chat_count == 2
    assert attestation.work_tested is False
    assert attestation.existing_chats_accessed is False
    assert attestation.private_browser_state_accessed is False


@pytest.mark.parametrize("count", [0, 1])
def test_zero_or_one_test_chat_is_rejected(count: int) -> None:
    values = _complete_inputs()
    values["surface_observations"] = values["surface_observations"][:count]
    values["chat_observations"] = values["chat_observations"][:count]
    values["correlation_receipts"] = values["correlation_receipts"][:count]

    with pytest.raises(ValueError, match="Chat A and Chat B"):
        commit_c1_final_attestation(**values)


def test_duplicate_challenge_is_rejected() -> None:
    values = _complete_inputs()
    chat_a, chat_b = values["chat_observations"]
    changed_b = chat_b.model_copy(update={"challenge_sha256": chat_a.challenge_sha256})
    values["chat_observations"] = (chat_a, changed_b)

    with pytest.raises(ValueError):
        commit_c1_final_attestation(**values)


def test_duplicate_audit_is_rejected() -> None:
    values = _complete_inputs()
    chat_a, chat_b = values["chat_observations"]
    changed_b = chat_b.model_copy(
        update={
            "audit_correlation": chat_a.audit_correlation,
            "audit_record_sha256": chat_a.audit_record_sha256,
        }
    )
    values["chat_observations"] = (chat_a, changed_b)

    with pytest.raises(ValueError):
        commit_c1_final_attestation(**values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("response_sha256", "b" * 64),
        ("local_policy_sha256", "c" * 64),
        ("tool_snapshot_sha256", "d" * 64),
        ("audit_record_sha256", "e" * 64),
    ],
)
def test_changed_chat_proof_binding_is_rejected(field: str, value: str) -> None:
    values = _complete_inputs()
    chat_a, _ = values["chat_observations"]
    receipt_a, _ = values["correlation_receipts"]
    changed = chat_a.model_copy(update={field: value})

    with pytest.raises(ValueError, match="binding|digest"):
        verify_c1_chat_correlation_receipt(
            receipt_a,
            observation=changed,
            audit_key=AUDIT_KEY,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("write_tool_count", 1),
        ("high_risk_tool_count", 1),
        ("write_actions_enabled", True),
        ("real_evidence_access", True),
        ("protocol_v2_reachable", True),
        ("work_invoked", True),
        ("existing_chats_accessed", True),
        ("conversation_identifier_collected", True),
        ("private_browser_state_accessed", True),
    ],
)
def test_chat_observation_rejects_capability_or_privacy_expansion(
    field: str,
    value: object,
) -> None:
    surface = _surface(C1TestChatLabel.CHAT_A)
    values = _chat(C1TestChatLabel.CHAT_A, surface).model_dump(mode="json")
    values[field] = value

    with pytest.raises(ValidationError):
        C1TestChatObservation.model_validate(values)


def test_negative_receipt_requires_every_check_and_no_capability_expansion() -> None:
    receipt = _negative()
    values = receipt.model_dump(mode="json")
    values["outcomes"].pop("secret_request")
    with pytest.raises(ValidationError, match="all ten"):
        type(receipt).model_validate(values)

    values = receipt.model_dump(mode="json")
    values["capability_expanded"] = True
    with pytest.raises(ValidationError):
        type(receipt).model_validate(values)


def test_cross_chat_replay_and_post_revocation_have_fail_closed_outcomes() -> None:
    receipt = _negative()

    assert receipt.outcomes[C1NegativeCheckId.CROSS_CHAT_REPLAY] is C1NegativeOutcome.REJECTED
    assert (
        receipt.outcomes[C1NegativeCheckId.POST_REVOCATION_CALL]
        is C1NegativeOutcome.UNREACHABLE_AFTER_REVOCATION
    )


def test_post_revocation_call_must_be_unreachable() -> None:
    outcomes = _negative().outcomes.copy()
    outcomes[C1NegativeCheckId.POST_REVOCATION_CALL] = C1NegativeOutcome.REJECTED

    with pytest.raises(ValidationError, match="must be unreachable"):
        commit_c1_negative_test_receipt(
            outcomes=outcomes,
            observed_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
            audit_key=AUDIT_KEY,
        )


def test_expired_observation_cannot_create_final_attestation() -> None:
    values = _complete_inputs()
    values["verified_at"] = NOW + timedelta(hours=2)
    values["expires_at"] = NOW + timedelta(hours=2, minutes=10)

    with pytest.raises(ValueError, match="expired"):
        commit_c1_final_attestation(**values)


def test_simulated_evidence_cannot_create_final_attestation() -> None:
    with pytest.raises(ValueError, match="simulated"):
        commit_c1_final_attestation(**_complete_inputs(simulated_setup=True))


def test_models_forbid_unknown_fields() -> None:
    for model in (
        C1RuntimeSetupObservation,
        C1SurfaceObservation,
        C1VisibleModelObservation,
        C1TestChatObservation,
    ):
        assert model.model_json_schema()["additionalProperties"] is False


def test_visible_model_cli_emits_ascii_safe_json_for_localized_labels(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)

    result = c1_evidence_main(
        [
            "visible-model",
            "--visible-reasoning-label",
            "Très élevée",
        ]
    )
    output = capsys.readouterr().out

    assert result == 0
    assert output.isascii()
    assert "\\u00e8" in output
    assert "\\u00e9" in output
    assert json.loads(output)["visible_reasoning_label"] == "Très élevée"


def test_surface_cli_uses_two_hour_manual_evidence_window(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)

    result = c1_evidence_main(
        [
            "surface",
            "--test-chat",
            "a",
            "--surface",
            "chat",
            "--plugin-selected",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    observed_at = datetime.fromisoformat(output["observed_at"].replace("Z", "+00:00"))
    expires_at = datetime.fromisoformat(output["expires_at"].replace("Z", "+00:00"))

    assert result == 0
    assert expires_at - observed_at == timedelta(hours=2)


def test_final_attestation_cli_revalidates_git_policy_and_real_audit_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = Path(__file__).resolve().parents[1]
    policy = PolicyEngine(root / "policy.c0.yaml")
    registry = McpToolRegistry(policy, c0_mode=True)
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path, AUDIT_KEY)
    ids = [
        audit.append(
            {
                "task_id": f"task-c1-{label}",
                "agent": {"provider": "mcp"},
                "capability": "systeme_local_connectivity_probe",
                "status": "completed",
            }
        )
        for label in ("a", "b")
    ]
    records = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]

    settings = _settings()
    settings[C1SetupField.POLICY_SHA256] = _setting(policy.policy_sha256)
    settings[C1SetupField.TOOL_SNAPSHOT_SHA256] = _setting(registry.tool_snapshot_sha256)
    setup = commit_c1_runtime_setup_observation(
        settings=settings,
        configuration_precedence=tuple(
            C1ConfigurationLayer(value) for value in C1_CONFIGURATION_PRECEDENCE
        ),
        observed_at=NOW,
        expires_at=NOW + timedelta(hours=2),
        audit_key=AUDIT_KEY,
    )
    surfaces = (
        _surface(C1TestChatLabel.CHAT_A),
        _surface(C1TestChatLabel.CHAT_B),
    )
    chats = []
    receipts = []
    for index, (label, surface) in enumerate(
        zip((C1TestChatLabel.CHAT_A, C1TestChatLabel.CHAT_B), surfaces, strict=True)
    ):
        chat = _chat(label, surface).model_copy(
            update={
                "local_policy_sha256": policy.policy_sha256,
                "tool_snapshot_sha256": registry.tool_snapshot_sha256,
                "audit_correlation": ids[index],
                "audit_record_sha256": canonical_c0_audit_record_sha256(records[index]),
            }
        )
        chats.append(chat)
        receipts.append(
            commit_c1_chat_correlation_receipt(
                observation=chat,
                audit_records_verified=index + 1,
                checked_at=NOW + timedelta(minutes=7 + index),
                expires_at=NOW + timedelta(minutes=50),
                audit_key=AUDIT_KEY,
            )
        )

    files = {
        "runtime": setup,
        "visible": _visible(),
        "surface_a": surfaces[0],
        "surface_b": surfaces[1],
        "proof_a": C1ChatProofBundle(
            version="1",
            observation=chats[0],
            correlation_receipt=receipts[0],
        ),
        "proof_b": C1ChatProofBundle(
            version="1",
            observation=chats[1],
            correlation_receipt=receipts[1],
        ),
        "negative": _negative(),
        "revocation": commit_c1_revocation_receipt(
            verified_at=NOW + timedelta(minutes=16),
            expires_at=NOW + timedelta(minutes=50),
            audit_key=AUDIT_KEY,
        ),
    }
    paths: dict[str, Path] = {}
    for name, model in files.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(model.model_dump(mode="json")), encoding="utf-8")
        paths[name] = path

    def fake_git(*args: str) -> str:
        if args == ("branch", "--show-current"):
            return "interop/chatgpt-web-chat-observability-c1"
        if args == ("status", "--porcelain"):
            return ""
        if args == ("rev-parse", "HEAD"):
            return COMMIT
        raise AssertionError(args)

    monkeypatch.setattr("systeme_local_gateway.c1_attest._git", fake_git)
    monkeypatch.setattr(
        "systeme_local_gateway.c1_attest.datetime",
        type(
            "FixedDateTime",
            (),
            {"now": staticmethod(lambda tz: NOW + timedelta(minutes=17))},
        ),
    )
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)
    result = c1_attest_main(
        [
            "--runtime-setup",
            str(paths["runtime"]),
            "--visible-model",
            str(paths["visible"]),
            "--surface-a",
            str(paths["surface_a"]),
            "--surface-b",
            str(paths["surface_b"]),
            "--proof-a",
            str(paths["proof_a"]),
            "--proof-b",
            str(paths["proof_b"]),
            "--negative-tests",
            str(paths["negative"]),
            "--revocation",
            str(paths["revocation"]),
            "--audit-log",
            str(audit_path),
            "--policy",
            str(root / "policy.c0.yaml"),
            "--c0-status",
            "READY_BUT_MANUAL_CHATGPT_WEB_GATE_PENDING",
        ]
    )

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "COMPLETE_BOUNDED_CHAT_SURFACE_OBSERVABILITY_VERIFIED"
    assert output["test_chat_count"] == 2
