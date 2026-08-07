from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c8_governance import (
    C8_POLICY_PATH,
    C8_REVALIDATION_PATH,
    C8LiveWorkPolicy,
    C8OfficialWorkRevalidation,
    C8SourceRouteState,
    build_current_c8_policy,
    build_current_c8_revalidation,
    verify_committed_c8_governance,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 27, 17, 0, tzinfo=UTC)


def _json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_committed_c8_governance_matches_reviewed_builders() -> None:
    revalidation = C8OfficialWorkRevalidation.model_validate(_json(C8_REVALIDATION_PATH))
    policy = C8LiveWorkPolicy.model_validate(_json(C8_POLICY_PATH))

    assert revalidation == build_current_c8_revalidation(ROOT)
    assert policy == build_current_c8_policy(ROOT)
    assert revalidation.support_state == "supported"
    assert policy.default_live_actions_allowed is False
    assert policy.only_eligible_tool == "systeme_local_connectivity_probe"
    assert policy.max_new_synthetic_work_tasks == 2


def test_revalidation_records_resolved_fetch_route_without_overclaim() -> None:
    receipt = build_current_c8_revalidation(ROOT)

    assert receipt.mcp_fetch_route_inconsistency_observed is False
    assert receipt.route_inconsistency_changes_support_conclusion is False
    assert not any(
        item.route_state is C8SourceRouteState.FETCH_ROUTE_INCONSISTENCY_CORROBORATED
        for item in receipt.source_checks
    )
    assert "web rollout is progressive" in receipt.current_conclusion
    assert receipt.native_chat_gate_status == "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"


def test_c8_governance_is_current_then_expires_closed() -> None:
    receipt, policy = verify_committed_c8_governance(ROOT, evaluated_at=NOW)
    assert receipt.revalidate_after.isoformat() == "2026-08-21T17:33:00+00:00"
    assert policy.authorization_required is True

    with pytest.raises(ValueError, match="expired"):
        verify_committed_c8_governance(
            ROOT,
            evaluated_at=datetime(2026, 8, 22, 17, 33, tzinfo=UTC),
        )


def test_revalidation_and_policy_reject_unknown_or_tampered_fields() -> None:
    receipt = build_current_c8_revalidation(ROOT)
    policy = build_current_c8_policy(ROOT)

    with pytest.raises(ValidationError):
        C8OfficialWorkRevalidation.model_validate(
            {**receipt.model_dump(mode="json"), "unknown": True}
        )
    with pytest.raises(ValidationError):
        C8LiveWorkPolicy.model_validate(
            {
                **policy.model_dump(mode="json"),
                "default_live_actions_allowed": True,
            }
        )


def test_all_c8_sources_are_official_https_and_bounded() -> None:
    receipt = build_current_c8_revalidation(ROOT)

    assert len(receipt.source_checks) == 7
    assert all(
        item.url.startswith(
            (
                "https://chatgpt.com/",
                "https://learn.chatgpt.com/",
                "https://developers.openai.com/",
            )
        )
        for item in receipt.source_checks
    )
    assert all(item.revalidate_after == receipt.revalidate_after for item in receipt.source_checks)
