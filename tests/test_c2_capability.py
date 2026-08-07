from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c2_capability import (
    C2_REVALIDATE_AFTER,
    C2_REVIEWED_AT,
    C2FinalStatus,
    C2LiveAction,
    C2ReasonCode,
    OfficialCapabilityProfile,
    OfficialCapabilityState,
    WebProviderId,
    WebSurfaceClass,
    build_current_c2_official_capability_profile,
    canonical_sha256,
    evaluate_c2_preflight,
    fail_closed_security_decision,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "governance/c2-official-capability-profile.json"


def _rebuilt_profile(
    *,
    state: OfficialCapabilityState,
    conclusion: str = "Synthetic state-specific conclusion for a closed unit test.",
) -> OfficialCapabilityProfile:
    current = build_current_c2_official_capability_profile()
    payload: dict[str, Any] = current.model_dump(mode="json", exclude={"profile_sha256"})
    payload["state"] = state.value
    payload["canonical_conclusion"] = conclusion
    return OfficialCapabilityProfile(
        **payload,
        profile_sha256=canonical_sha256(payload),
    )


def test_committed_c2_profile_matches_builder_byte_for_byte() -> None:
    committed = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    current = build_current_c2_official_capability_profile()

    assert committed == current.model_dump(mode="json")
    assert (
        current.profile_sha256 == "10e6780e18224bd292130ff3f2350713d06445786975afc2ac7322f64ce1742b"
    )


def test_current_profile_is_exact_chatgpt_chat_unsupported_claim() -> None:
    profile = build_current_c2_official_capability_profile()

    assert profile.surface.provider_id is WebProviderId.CHATGPT
    assert profile.surface.native_surface == "chat"
    assert profile.surface.surface_class is WebSurfaceClass.CONVERSATIONAL_CHAT
    assert profile.state is OfficialCapabilityState.UNSUPPORTED
    assert profile.reviewed_at == C2_REVIEWED_AT
    assert profile.revalidate_after == C2_REVALIDATE_AFTER
    assert "without switching to ChatGPT Work" in profile.canonical_conclusion
    assert "Plugins are explicitly unavailable in Chat" in profile.canonical_conclusion


def test_current_sources_are_sorted_unique_official_and_digest_bound() -> None:
    profile = build_current_c2_official_capability_profile()
    ids = tuple(source.source_id for source in profile.sources)

    assert ids == tuple(sorted(ids))
    assert len(ids) == len(set(ids)) == 4
    for source in profile.sources:
        assert source.url.startswith(
            ("https://developers.openai.com/", "https://learn.chatgpt.com/")
        )
        assert (
            source.summary_sha256
            == hashlib.sha256(source.canonical_summary.encode("utf-8")).hexdigest()
        )
        assert source.consulted_at == profile.reviewed_at
        assert source.revalidate_after == profile.revalidate_after


def test_current_unsupported_profile_denies_every_live_action() -> None:
    profile = build_current_c2_official_capability_profile()
    decision = evaluate_c2_preflight(
        profile,
        evaluated_at=C2_REVIEWED_AT + timedelta(minutes=1),
    )

    assert decision.final_status is C2FinalStatus.NO_OFFICIAL_CHAT_TOOL_INTERFACE
    assert decision.reason_code is C2ReasonCode.OFFICIAL_CAPABILITY_UNSUPPORTED
    assert decision.live_actions_allowed is False
    assert decision.action_decisions == {action: False for action in C2LiveAction}


def test_stale_profile_fails_closed_as_official_evidence_drift() -> None:
    decision = evaluate_c2_preflight(
        build_current_c2_official_capability_profile(),
        evaluated_at=C2_REVALIDATE_AFTER,
    )

    assert decision.final_status is C2FinalStatus.OFFICIAL_EVIDENCE_DRIFT
    assert decision.reason_code is C2ReasonCode.OFFICIAL_EVIDENCE_STALE
    assert decision.action_decisions == {action: False for action in C2LiveAction}


def test_unobservable_profile_fails_closed_as_official_evidence_drift() -> None:
    decision = evaluate_c2_preflight(
        _rebuilt_profile(state=OfficialCapabilityState.UNOBSERVABLE),
        evaluated_at=C2_REVIEWED_AT + timedelta(minutes=1),
    )

    assert decision.final_status is C2FinalStatus.OFFICIAL_EVIDENCE_DRIFT
    assert decision.reason_code is C2ReasonCode.OFFICIAL_CAPABILITY_UNOBSERVABLE
    assert decision.action_decisions == {action: False for action in C2LiveAction}


def test_supported_profile_is_the_only_state_that_allows_live_actions() -> None:
    decision = evaluate_c2_preflight(
        _rebuilt_profile(state=OfficialCapabilityState.SUPPORTED),
        evaluated_at=C2_REVIEWED_AT + timedelta(minutes=1),
    )

    assert decision.final_status is C2FinalStatus.COMPLETE
    assert decision.reason_code is C2ReasonCode.OFFICIAL_CAPABILITY_SUPPORTED
    assert decision.live_actions_allowed is True
    assert decision.action_decisions == {action: True for action in C2LiveAction}


def test_evaluation_before_review_fails_as_security_invariant() -> None:
    decision = evaluate_c2_preflight(
        build_current_c2_official_capability_profile(),
        evaluated_at=C2_REVIEWED_AT - timedelta(microseconds=1),
    )

    assert decision.final_status is C2FinalStatus.SECURITY_INVARIANT
    assert decision.action_decisions == {action: False for action in C2LiveAction}


def test_explicit_security_failure_denies_every_action_without_profile_claims() -> None:
    decision = fail_closed_security_decision(evaluated_at=C2_REVIEWED_AT)

    assert decision.profile_sha256 is None
    assert decision.capability_state is None
    assert decision.final_status is C2FinalStatus.SECURITY_INVARIANT
    assert decision.action_decisions == {action: False for action in C2LiveAction}


def test_profile_rejects_unknown_fields_and_digest_substitution() -> None:
    payload = build_current_c2_official_capability_profile().model_dump(mode="json")
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        OfficialCapabilityProfile.model_validate(payload)

    payload.pop("unexpected")
    payload["profile_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="profile digest mismatch"):
        OfficialCapabilityProfile.model_validate(payload)


def test_profile_rejects_unofficial_host_and_summary_substitution() -> None:
    payload = build_current_c2_official_capability_profile().model_dump(mode="json")
    payload["sources"][0]["url"] = "https://example.com/not-official"
    with pytest.raises(ValidationError, match="reviewed OpenAI documentation hosts"):
        OfficialCapabilityProfile.model_validate(payload)

    payload = build_current_c2_official_capability_profile().model_dump(mode="json")
    payload["sources"][0]["canonical_summary"] += " changed"
    with pytest.raises(ValidationError, match="canonical summary digest mismatch"):
        OfficialCapabilityProfile.model_validate(payload)


def test_provider_registry_claims_only_chatgpt_and_no_portability() -> None:
    assert tuple(WebProviderId) == (WebProviderId.CHATGPT,)
    assert tuple(WebSurfaceClass) == (WebSurfaceClass.CONVERSATIONAL_CHAT,)


def test_cli_preflight_emits_blocked_decision_without_live_side_effects() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c2_capability",
            "preflight",
            "--profile",
            str(PROFILE_PATH),
            "--as-of",
            "2026-08-10T01:41:00Z",
        ],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    result = json.loads(completed.stdout)

    assert completed.stderr == ""
    assert result["final_status"] == "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"
    assert result["live_actions_allowed"] is False
    assert set(result["action_decisions"].values()) == {False}


def test_cli_require_action_returns_denial_exit_code() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c2_capability",
            "require-action",
            "--profile",
            str(PROFILE_PATH),
            "--action",
            C2LiveAction.TUNNEL_START.value,
            "--as-of",
            "2026-08-10T01:41:00Z",
        ],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert completed.returncode == 3
    assert json.loads(completed.stdout)["action_decisions"]["tunnel_start"] is False
    assert completed.stderr == ""


def test_cli_malformed_profile_fails_closed_without_echoing_input(tmp_path: Path) -> None:
    malformed = tmp_path / "profile.json"
    malformed.write_text('{"secret": "must-not-be-echoed"}', encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c2_capability",
            "preflight",
            "--profile",
            str(malformed),
            "--as-of",
            "2026-08-10T01:41:00Z",
        ],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert completed.returncode == 4
    assert "must-not-be-echoed" not in completed.stdout
    assert json.loads(completed.stdout)["final_status"] == "BLOCKED_BY_SECURITY_INVARIANT"


def test_cli_rejects_valid_but_substituted_profile(tmp_path: Path) -> None:
    substituted = tmp_path / "substituted.json"
    substituted.write_text(
        json.dumps(
            _rebuilt_profile(state=OfficialCapabilityState.SUPPORTED).model_dump(mode="json")
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c2_capability",
            "preflight",
            "--profile",
            str(substituted),
            "--as-of",
            "2026-08-10T01:41:00Z",
        ],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert completed.returncode == 4
    result = json.loads(completed.stdout)
    assert result["final_status"] == "BLOCKED_BY_SECURITY_INVARIANT"
    assert set(result["action_decisions"].values()) == {False}


def test_c2_module_has_no_browser_network_or_tunnel_runtime_dependency() -> None:
    source = (ROOT / "src/systeme_local_gateway/c2_capability.py").read_text(encoding="utf-8")

    for forbidden in (
        "httpx",
        "requests",
        "playwright",
        "selenium",
        "CONTROL_PLANE_API_KEY",
        "CONTROL_PLANE_TUNNEL_ID",
        "Start-Process",
    ):
        assert forbidden not in source
