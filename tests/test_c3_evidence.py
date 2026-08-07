from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c3_evidence import (
    C3_REVALIDATE_AFTER,
    C3_REVIEWED_AT,
    C3GateStatus,
    C3ProtectedAction,
    CandidateComparisonState,
    CandidateProfileDraft,
    CapabilityRegistry,
    EvidenceLifecycleState,
    EvidenceReviewerState,
    OfficialCapabilityProfile,
    OfficialSupportState,
    WebProviderId,
    build_c3_candidate_draft_template,
    build_c3_candidate_template,
    build_current_c3_official_capability_profile,
    build_current_c3_registry,
    canonical_sha256,
    compare_c3_candidate,
    evaluate_c3_registry,
    evaluate_reviewed_profile,
    seal_c3_candidate_draft,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "governance/c3-chatgpt-chat-capability-profile.json"
REGISTRY_PATH = ROOT / "governance/c3-capability-registry.json"


def _evidence_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "identity": payload["identity"],
        "support_state": payload["support_state"],
        "canonical_conclusion": payload["canonical_conclusion"],
        "conclusion_sha256": payload["conclusion_sha256"],
        "sources": [
            {
                "source_id": source["source_id"],
                "title": source["title"],
                "url": source["url"],
                "canonical_claim": source["canonical_claim"],
                "claim_sha256": source["claim_sha256"],
            }
            for source in payload["sources"]
        ],
    }


def _rehash_profile(payload: dict[str, Any]) -> OfficialCapabilityProfile:
    for source in payload["sources"]:
        source["claim_sha256"] = hashlib.sha256(
            source["canonical_claim"].encode("utf-8")
        ).hexdigest()
    payload["conclusion_sha256"] = hashlib.sha256(
        payload["canonical_conclusion"].encode("utf-8")
    ).hexdigest()
    payload["evidence_sha256"] = canonical_sha256(_evidence_payload(payload))
    payload["profile_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "profile_sha256"}
    )
    return OfficialCapabilityProfile.model_validate(payload)


def _registry_for(profile: OfficialCapabilityProfile) -> CapabilityRegistry:
    payload = build_current_c3_registry().model_dump(mode="json")
    payload["profiles"][0]["profile_id"] = profile.profile_id
    payload["profiles"][0]["identity"] = profile.identity.model_dump(mode="json")
    payload["profiles"][0]["expected_profile_sha256"] = profile.profile_sha256
    payload["registry_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "registry_sha256"}
    )
    return CapabilityRegistry.model_validate(payload)


def _profile_with_state(state: OfficialSupportState) -> OfficialCapabilityProfile:
    payload = build_current_c3_official_capability_profile().model_dump(mode="json")
    payload["support_state"] = state.value
    payload["canonical_conclusion"] = (
        f"Synthetic {state.value} conclusion for a closed deterministic unit test."
    )
    return _rehash_profile(payload)


def _write_candidate(path: Path, profile: OfficialCapabilityProfile) -> None:
    path.write_text(
        json.dumps(profile.model_dump(mode="json"), ensure_ascii=False),
        encoding="utf-8",
    )


def _write_bundle(
    root: Path,
    *,
    registry: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
) -> Path:
    governance = root / "governance"
    governance.mkdir(parents=True)
    (governance / "c3-capability-registry.json").write_text(
        json.dumps(
            registry
            if registry is not None
            else build_current_c3_registry().model_dump(mode="json")
        ),
        encoding="utf-8",
    )
    if profile is not None:
        (governance / "c3-chatgpt-chat-capability-profile.json").write_text(
            json.dumps(profile),
            encoding="utf-8",
        )
    return governance / "c3-capability-registry.json"


def test_committed_profile_and_registry_match_reviewed_builders() -> None:
    committed_profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    committed_registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    profile = build_current_c3_official_capability_profile()
    registry = build_current_c3_registry()

    assert committed_profile == profile.model_dump(mode="json")
    assert committed_registry == registry.model_dump(mode="json")
    assert (
        profile.profile_sha256 == "478d1651fa1b275d5158ff1fd56e1775b10a48fb650b3e2baef3808d36e357bd"
    )
    assert (
        profile.evidence_sha256
        == "89f8539212d3b2ab52cbdf2fcd449a75cfe22262533f592a883359d9debe5b36"
    )
    assert (
        registry.registry_sha256
        == "eb95d8cc359b9bca6f30ae613b294dcc6247ace292ad49fab7f116a38c79631c"
    )


def test_registry_contains_only_chatgpt_and_one_exact_capability_identity() -> None:
    registry = build_current_c3_registry()

    assert tuple(WebProviderId) == (WebProviderId.CHATGPT,)
    assert len(registry.adapters) == len(registry.profiles) == 1
    assert registry.adapters[0].provider_id is WebProviderId.CHATGPT
    assert registry.adapters[0].allowed_official_hosts == (
        "developers.openai.com",
        "learn.chatgpt.com",
    )
    assert registry.profiles[0].identity.key == (
        "chatgpt:chat:conversational_chat:custom_or_local_mcp_tool_invocation"
    )


def test_current_reviewed_unsupported_profile_denies_all_actions() -> None:
    decision = evaluate_c3_registry(
        root=ROOT,
        registry_path=REGISTRY_PATH,
        evaluated_at=C3_REVIEWED_AT + timedelta(minutes=1),
    )

    assert decision.lifecycle_state is EvidenceLifecycleState.CURRENT
    assert decision.support_state is OfficialSupportState.UNSUPPORTED
    assert decision.final_status is C3GateStatus.NO_OFFICIAL_CHAT_TOOL_INTERFACE
    assert decision.live_actions_allowed is False
    assert decision.action_decisions == {action: False for action in C3ProtectedAction}


@pytest.mark.parametrize(
    ("evaluated_at", "expected"),
    [
        (C3_REVIEWED_AT - timedelta(microseconds=1), EvidenceLifecycleState.INVALID),
        (C3_REVIEWED_AT, EvidenceLifecycleState.CURRENT),
        (
            C3_REVALIDATE_AFTER - timedelta(days=7, microseconds=1),
            EvidenceLifecycleState.CURRENT,
        ),
        (
            C3_REVALIDATE_AFTER - timedelta(days=7),
            EvidenceLifecycleState.REVALIDATION_DUE,
        ),
        (
            C3_REVALIDATE_AFTER - timedelta(microseconds=1),
            EvidenceLifecycleState.REVALIDATION_DUE,
        ),
        (C3_REVALIDATE_AFTER, EvidenceLifecycleState.EXPIRED),
    ],
)
def test_lifecycle_boundaries_fail_closed(
    evaluated_at: Any,
    expected: EvidenceLifecycleState,
) -> None:
    decision = evaluate_c3_registry(
        root=ROOT,
        registry_path=REGISTRY_PATH,
        evaluated_at=evaluated_at,
    )

    assert decision.lifecycle_state is expected
    assert decision.action_decisions == {action: False for action in C3ProtectedAction}
    if expected is EvidenceLifecycleState.REVALIDATION_DUE:
        assert decision.final_status is C3GateStatus.REVALIDATION_DUE
    if expected is EvidenceLifecycleState.EXPIRED:
        assert decision.final_status is C3GateStatus.EXPIRED
    if expected is EvidenceLifecycleState.INVALID:
        assert decision.final_status is C3GateStatus.SECURITY_INVARIANT


def test_only_current_reviewed_supported_evidence_can_open_this_gate_layer() -> None:
    supported = _profile_with_state(OfficialSupportState.SUPPORTED)
    decision = evaluate_reviewed_profile(
        supported,
        _registry_for(supported),
        evaluated_at=C3_REVIEWED_AT + timedelta(minutes=1),
    )

    assert decision.final_status is C3GateStatus.READY
    assert decision.live_actions_allowed is True
    assert decision.action_decisions == {action: True for action in C3ProtectedAction}

    unobservable = _profile_with_state(OfficialSupportState.UNOBSERVABLE)
    ambiguous = evaluate_reviewed_profile(
        unobservable,
        _registry_for(unobservable),
        evaluated_at=C3_REVIEWED_AT + timedelta(minutes=1),
    )
    assert ambiguous.final_status is C3GateStatus.OFFICIAL_EVIDENCE_AMBIGUOUS
    assert ambiguous.action_decisions == {action: False for action in C3ProtectedAction}


def test_candidate_reviewer_state_can_never_enable_actions() -> None:
    candidate = build_c3_candidate_template(
        reviewed_at=C3_REVIEWED_AT + timedelta(days=1),
        revalidate_after=C3_REVALIDATE_AFTER + timedelta(days=1),
    )
    decision = evaluate_reviewed_profile(
        candidate,
        _registry_for(candidate),
        evaluated_at=candidate.reviewed_at + timedelta(minutes=1),
    )

    assert decision.lifecycle_state is EvidenceLifecycleState.INVALID
    assert decision.live_actions_allowed is False
    assert decision.action_decisions == {action: False for action in C3ProtectedAction}


def test_candidate_draft_sealing_computes_every_digest_and_remains_blocked(
    tmp_path: Path,
) -> None:
    draft = build_c3_candidate_draft_template(
        reviewed_at=C3_REVIEWED_AT + timedelta(days=1),
        revalidate_after=C3_REVALIDATE_AFTER + timedelta(days=1),
    )
    payload = draft.model_dump(mode="json")
    payload["support_state"] = OfficialSupportState.SUPPORTED.value
    payload["canonical_conclusion"] = "Changed bounded draft conclusion."
    payload["sources"][0]["canonical_claim"] = "Changed bounded draft source claim."
    changed_draft = CandidateProfileDraft.model_validate(payload)

    candidate = seal_c3_candidate_draft(
        changed_draft,
        build_current_c3_registry(),
    )
    candidate_path = tmp_path / "candidate.json"
    _write_candidate(candidate_path, candidate)
    comparison = compare_c3_candidate(
        root=ROOT,
        registry_path=REGISTRY_PATH,
        candidate_path=candidate_path,
        evaluated_at=candidate.reviewed_at + timedelta(minutes=1),
    )

    assert candidate.reviewer_state is EvidenceReviewerState.CANDIDATE
    assert (
        candidate.conclusion_sha256
        == hashlib.sha256(candidate.canonical_conclusion.encode("utf-8")).hexdigest()
    )
    assert candidate.evidence_sha256 == canonical_sha256(candidate.evidence_payload())
    assert comparison.comparison_state is CandidateComparisonState.SOURCE_DRIFT
    assert comparison.action_decisions == {action: False for action in C3ProtectedAction}


def test_candidate_draft_rejects_unknown_fields_and_unapproved_host() -> None:
    payload = build_c3_candidate_draft_template(
        reviewed_at=C3_REVIEWED_AT + timedelta(days=1),
        revalidate_after=C3_REVALIDATE_AFTER + timedelta(days=1),
    ).model_dump(mode="json")
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        CandidateProfileDraft.model_validate(payload)

    payload.pop("unexpected")
    payload["sources"][0]["url"] = "https://example.com/changed"
    draft = CandidateProfileDraft.model_validate(payload)
    with pytest.raises(ValueError, match="not approved"):
        seal_c3_candidate_draft(draft, build_current_c3_registry())


def test_profile_rejects_unknown_fields_and_digest_substitution() -> None:
    payload = build_current_c3_official_capability_profile().model_dump(mode="json")
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        OfficialCapabilityProfile.model_validate(payload)

    payload.pop("unexpected")
    payload["profile_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="profile digest mismatch"):
        OfficialCapabilityProfile.model_validate(payload)


def test_profile_rejects_claim_conclusion_and_evidence_digest_substitution() -> None:
    payload = build_current_c3_official_capability_profile().model_dump(mode="json")
    payload["sources"][0]["canonical_claim"] += " changed"
    with pytest.raises(ValidationError, match="claim digest mismatch"):
        OfficialCapabilityProfile.model_validate(payload)

    payload = build_current_c3_official_capability_profile().model_dump(mode="json")
    payload["canonical_conclusion"] += " changed"
    with pytest.raises(ValidationError, match="conclusion digest mismatch"):
        OfficialCapabilityProfile.model_validate(payload)

    payload = build_current_c3_official_capability_profile().model_dump(mode="json")
    payload["evidence_sha256"] = "0" * 64
    payload["profile_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "profile_sha256"}
    )
    with pytest.raises(ValidationError, match="evidence-set digest mismatch"):
        OfficialCapabilityProfile.model_validate(payload)


@pytest.mark.parametrize(
    "url",
    [
        "http://developers.openai.com/plugins",
        "https://user@developers.openai.com/plugins",
        "https://developers.openai.com:443/plugins",
        "https://developers.openai.com/plugins?view=chat",
        "https://developers.openai.com/plugins#chat",
        "https://DEVELOPERS.openai.com/plugins",
        "https://developers.openai.com",
    ],
)
def test_profile_rejects_noncanonical_official_urls(url: str) -> None:
    payload = build_current_c3_official_capability_profile().model_dump(mode="json")
    payload["sources"][0]["url"] = url
    with pytest.raises(ValidationError, match="canonical HTTPS|hostname"):
        _rehash_profile(payload)


def test_adapter_rejects_unapproved_or_lookalike_hosts() -> None:
    for host in (
        "https://example.com/plugins",
        "https://developers.openai.com.example.com/plugins",
    ):
        payload = build_current_c3_official_capability_profile().model_dump(mode="json")
        payload["sources"][0]["url"] = host
        profile = _rehash_profile(payload)
        decision = evaluate_reviewed_profile(
            profile,
            _registry_for(profile),
            evaluated_at=C3_REVIEWED_AT + timedelta(minutes=1),
        )
        assert decision.lifecycle_state is EvidenceLifecycleState.INVALID
        assert decision.live_actions_allowed is False


def test_profile_rejects_duplicate_sources_missing_sources_and_time_inversion() -> None:
    payload = build_current_c3_official_capability_profile().model_dump(mode="json")
    payload["sources"][1]["source_id"] = payload["sources"][0]["source_id"]
    with pytest.raises(ValidationError, match="sorted and unique"):
        _rehash_profile(payload)

    payload = build_current_c3_official_capability_profile().model_dump(mode="json")
    payload["sources"][1]["url"] = payload["sources"][0]["url"]
    with pytest.raises(ValidationError, match="URLs must be unique"):
        _rehash_profile(payload)

    payload = build_current_c3_official_capability_profile().model_dump(mode="json")
    payload["sources"] = payload["sources"][:2]
    with pytest.raises(ValidationError, match="at least three"):
        _rehash_profile(payload)

    payload = build_current_c3_official_capability_profile().model_dump(mode="json")
    payload["revalidate_after"] = payload["reviewed_at"]
    for source in payload["sources"]:
        source["revalidate_after"] = payload["reviewed_at"]
    with pytest.raises(ValidationError, match="deadline"):
        _rehash_profile(payload)


def test_registry_rejects_unknown_fields_duplicate_identity_and_path_escape() -> None:
    payload = build_current_c3_registry().model_dump(mode="json")
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        CapabilityRegistry.model_validate(payload)

    payload = build_current_c3_registry().model_dump(mode="json")
    duplicate = deepcopy(payload["profiles"][0])
    duplicate["profile_id"] = "chatgpt_chat_c3_duplicate"
    payload["profiles"].append(duplicate)
    payload["registry_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "registry_sha256"}
    )
    with pytest.raises(ValidationError, match="identities must be unique"):
        CapabilityRegistry.model_validate(payload)

    payload = build_current_c3_registry().model_dump(mode="json")
    payload["profiles"][0]["profile_path"] = "governance/../secret.json"
    payload["registry_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "registry_sha256"}
    )
    with pytest.raises(ValidationError, match="path"):
        CapabilityRegistry.model_validate(payload)


def test_closed_provider_registry_rejects_cross_provider_substitution() -> None:
    payload = build_current_c3_official_capability_profile().model_dump(mode="json")
    payload["identity"]["provider_id"] = "future_ai"
    with pytest.raises(ValidationError):
        _rehash_profile(payload)


def test_valid_active_profile_mutation_is_source_drift(tmp_path: Path) -> None:
    payload = build_current_c3_official_capability_profile().model_dump(mode="json")
    payload["support_state"] = OfficialSupportState.SUPPORTED.value
    payload["canonical_conclusion"] = "Synthetic changed conclusion for drift testing."
    mutated = _rehash_profile(payload)
    registry_path = _write_bundle(
        tmp_path,
        profile=mutated.model_dump(mode="json"),
    )

    decision = evaluate_c3_registry(
        root=tmp_path,
        registry_path=registry_path,
        evaluated_at=C3_REVIEWED_AT + timedelta(minutes=1),
    )

    assert decision.lifecycle_state is EvidenceLifecycleState.SOURCE_DRIFT
    assert decision.final_status is C3GateStatus.SOURCE_DRIFT
    assert decision.action_decisions == {action: False for action in C3ProtectedAction}


def test_valid_registry_substitution_is_security_invalid(tmp_path: Path) -> None:
    registry = build_current_c3_registry().model_dump(mode="json")
    registry["profiles"][0]["expected_profile_sha256"] = "0" * 64
    registry["registry_sha256"] = canonical_sha256(
        {key: value for key, value in registry.items() if key != "registry_sha256"}
    )
    registry_path = _write_bundle(
        tmp_path,
        registry=registry,
        profile=build_current_c3_official_capability_profile().model_dump(mode="json"),
    )

    decision = evaluate_c3_registry(
        root=tmp_path,
        registry_path=registry_path,
        evaluated_at=C3_REVIEWED_AT + timedelta(minutes=1),
    )

    assert decision.lifecycle_state is EvidenceLifecycleState.INVALID
    assert decision.final_status is C3GateStatus.SECURITY_INVARIANT
    assert decision.live_actions_allowed is False


def test_missing_or_malformed_bundle_fails_closed(tmp_path: Path) -> None:
    registry_path = _write_bundle(tmp_path)
    missing = evaluate_c3_registry(
        root=tmp_path,
        registry_path=registry_path,
        evaluated_at=C3_REVIEWED_AT + timedelta(minutes=1),
    )
    assert missing.lifecycle_state is EvidenceLifecycleState.INVALID

    registry_path.write_text('{"secret": "must-not-be-echoed"}', encoding="utf-8")
    malformed = evaluate_c3_registry(
        root=tmp_path,
        registry_path=registry_path,
        evaluated_at=C3_REVIEWED_AT + timedelta(minutes=1),
    )
    assert malformed.lifecycle_state is EvidenceLifecycleState.INVALID
    assert malformed.action_decisions == {action: False for action in C3ProtectedAction}


def test_unchanged_candidate_is_detected_but_never_promoted(tmp_path: Path) -> None:
    candidate = build_c3_candidate_template(
        reviewed_at=C3_REVIEWED_AT + timedelta(days=1),
        revalidate_after=C3_REVALIDATE_AFTER + timedelta(days=1),
    )
    candidate_path = tmp_path / "candidate.json"
    _write_candidate(candidate_path, candidate)

    comparison = compare_c3_candidate(
        root=ROOT,
        registry_path=REGISTRY_PATH,
        candidate_path=candidate_path,
        evaluated_at=candidate.reviewed_at + timedelta(minutes=1),
    )

    assert comparison.comparison_state is CandidateComparisonState.UNCHANGED
    assert comparison.changed_components == ()
    assert comparison.candidate_can_change_gate is False
    assert comparison.requires_independent_review is False
    assert comparison.action_decisions == {action: False for action in C3ProtectedAction}


@pytest.mark.parametrize(
    ("component", "expected"),
    [
        ("support", "support_state"),
        ("conclusion", "canonical_conclusion"),
        ("source", "official_sources"),
    ],
)
def test_candidate_change_is_source_drift_and_cannot_change_gate(
    tmp_path: Path,
    component: str,
    expected: str,
) -> None:
    candidate = build_c3_candidate_template(
        reviewed_at=C3_REVIEWED_AT + timedelta(days=1),
        revalidate_after=C3_REVALIDATE_AFTER + timedelta(days=1),
    )
    payload = candidate.model_dump(mode="json")
    if component == "support":
        payload["support_state"] = OfficialSupportState.SUPPORTED.value
    elif component == "conclusion":
        payload["canonical_conclusion"] = "Changed reviewed candidate conclusion."
    else:
        payload["sources"][0]["canonical_claim"] = "Changed bounded candidate claim."
    changed = _rehash_profile(payload)
    candidate_path = tmp_path / f"{component}.json"
    _write_candidate(candidate_path, changed)

    comparison = compare_c3_candidate(
        root=ROOT,
        registry_path=REGISTRY_PATH,
        candidate_path=candidate_path,
        evaluated_at=changed.reviewed_at + timedelta(minutes=1),
    )

    assert comparison.comparison_state is CandidateComparisonState.SOURCE_DRIFT
    assert expected in comparison.changed_components
    assert comparison.requires_independent_review is True
    assert comparison.action_decisions == {action: False for action in C3ProtectedAction}


@pytest.mark.parametrize("mutation", ["reviewed", "future", "profile", "reviewer"])
def test_invalid_candidate_is_rejected_without_partial_enablement(
    tmp_path: Path,
    mutation: str,
) -> None:
    candidate = build_c3_candidate_template(
        reviewed_at=C3_REVIEWED_AT + timedelta(days=1),
        revalidate_after=C3_REVALIDATE_AFTER + timedelta(days=1),
    )
    payload = candidate.model_dump(mode="json")
    evaluated_at = candidate.reviewed_at + timedelta(minutes=1)
    if mutation == "reviewed":
        payload["reviewed_at"] = C3_REVIEWED_AT.isoformat().replace("+00:00", "Z")
        payload["revalidate_after"] = C3_REVALIDATE_AFTER.isoformat().replace("+00:00", "Z")
        for source in payload["sources"]:
            source["consulted_at"] = payload["reviewed_at"]
            source["revalidate_after"] = payload["revalidate_after"]
    elif mutation == "future":
        evaluated_at = C3_REVIEWED_AT + timedelta(minutes=1)
    elif mutation == "profile":
        payload["profile_id"] = "chatgpt_chat_c3_substituted"
    else:
        payload["reviewer_state"] = EvidenceReviewerState.REVIEWED.value
    changed = _rehash_profile(payload)
    candidate_path = tmp_path / f"{mutation}.json"
    _write_candidate(candidate_path, changed)

    comparison = compare_c3_candidate(
        root=ROOT,
        registry_path=REGISTRY_PATH,
        candidate_path=candidate_path,
        evaluated_at=evaluated_at,
    )

    assert comparison.comparison_state is CandidateComparisonState.INVALID
    assert comparison.changed_components == ("validation",)
    assert comparison.action_decisions == {action: False for action in C3ProtectedAction}


def test_cli_preflight_and_every_require_action_fail_closed() -> None:
    env = {"PYTHONPATH": str(ROOT / "src")}
    preflight = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c3_evidence",
            "preflight",
            "--as-of",
            "2026-08-10T12:00:00Z",
        ],
        cwd=ROOT,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    assert preflight.returncode == 0
    assert preflight.stderr == ""
    assert (
        json.loads(preflight.stdout)["final_status"] == "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"
    )

    for action in C3ProtectedAction:
        required = subprocess.run(
            [
                sys.executable,
                "-m",
                "systeme_local_gateway.c3_evidence",
                "require-action",
                "--action",
                action.value,
                "--as-of",
                "2026-08-10T12:00:00Z",
            ],
            cwd=ROOT,
            env=env,
            check=False,
            text=True,
            capture_output=True,
        )
        assert required.returncode == 3
        assert json.loads(required.stdout)["action_decisions"][action.value] is False


def test_cli_governance_reports_due_and_fails_expired_distinctly() -> None:
    env = {"PYTHONPATH": str(ROOT / "src")}
    due = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c3_evidence",
            "governance",
            "--as-of",
            "2026-08-15T11:55:00Z",
            "--github-annotations",
        ],
        cwd=ROOT,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    assert due.returncode == 0
    assert '"lifecycle_state": "revalidation_due"' in due.stdout
    assert "::warning title=C3 evidence revalidation due::" in due.stdout

    expired = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c3_evidence",
            "governance",
            "--as-of",
            "2026-08-22T11:55:00Z",
            "--github-annotations",
        ],
        cwd=ROOT,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    assert expired.returncode == 5
    assert '"lifecycle_state": "expired"' in expired.stdout
    assert "::error title=C3 evidence governance blocked::expired" in expired.stdout


def test_cli_candidate_draft_and_sealing_are_deterministic(tmp_path: Path) -> None:
    env = {"PYTHONPATH": str(ROOT / "src")}
    draft_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c3_evidence",
            "new-candidate-draft",
            "--reviewed-at",
            "2026-08-08T11:55:00Z",
            "--revalidate-after",
            "2026-08-22T11:55:00Z",
        ],
        cwd=ROOT,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    assert draft_result.returncode == 0
    draft = json.loads(draft_result.stdout)
    assert "profile_sha256" not in draft
    assert "claim_sha256" not in draft["sources"][0]

    draft_path = tmp_path / "draft.json"
    draft_path.write_text(draft_result.stdout, encoding="utf-8")
    sealed_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c3_evidence",
            "seal-candidate",
            "--draft",
            str(draft_path),
            "--as-of",
            "2026-08-08T12:00:00Z",
        ],
        cwd=ROOT,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    assert sealed_result.returncode == 0
    sealed = json.loads(sealed_result.stdout)
    assert sealed["reviewer_state"] == "candidate"
    assert len(sealed["profile_sha256"]) == len(sealed["evidence_sha256"]) == 64
    assert all(len(source["claim_sha256"]) == 64 for source in sealed["sources"])


def test_cli_invalid_registry_does_not_echo_input(tmp_path: Path) -> None:
    registry = tmp_path / "registry.json"
    registry.write_text('{"secret": "must-not-be-echoed"}', encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.c3_evidence",
            "preflight",
            "--registry",
            str(registry),
            "--as-of",
            "2026-08-10T12:00:00Z",
        ],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        check=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 4
    assert "must-not-be-echoed" not in completed.stdout
    assert json.loads(completed.stdout)["final_status"] == "BLOCKED_BY_SECURITY_INVARIANT"


def test_c3_module_has_no_browser_network_tunnel_or_secret_dependency() -> None:
    source = (ROOT / "src/systeme_local_gateway/c3_evidence.py").read_text(encoding="utf-8")

    for forbidden in (
        "httpx",
        "requests",
        "playwright",
        "selenium",
        "CONTROL_PLANE_API_KEY",
        "CONTROL_PLANE_TUNNEL_ID",
        "SLG_SHARED_SECRET",
        "Start-Process",
    ):
        assert forbidden not in source
