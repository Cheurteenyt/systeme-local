from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from systeme_local_gateway.providers.context_models import (
    ExperienceKind,
    ExperienceRequestKind,
    ExperienceSelectionRequest,
    ProjectMemoryScope,
    QuotaState,
)
from systeme_local_gateway.providers.context_policy import select_chatgpt_experience
from systeme_local_gateway.providers.fake_chatgpt_context import (
    DeterministicFakeChatGptContext,
    FakeChatGptContextScenario,
)
from systeme_local_gateway.providers.models import CapabilitySupport

NOW = datetime(2026, 7, 18, 10, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("scenario", list(FakeChatGptContextScenario))
def test_fake_context_is_deterministic(
    scenario: FakeChatGptContextScenario,
) -> None:
    fake = DeterministicFakeChatGptContext()
    first = fake.build(scenario=scenario, observed_at=NOW)
    second = fake.build(scenario=scenario, observed_at=NOW)
    assert first == second
    assert first.project.memory_scope is ProjectMemoryScope.PROJECT_ONLY
    assert first.chat.experience is ExperienceKind.CHAT
    assert first.chat.project_id == first.project.project_id
    assert first.account.account_id == first.project.account_id == first.chat.account_id


def test_scenarios_have_distinct_account_ids() -> None:
    fake = DeterministicFakeChatGptContext()
    ids = {
        fake.build(scenario=scenario, observed_at=NOW).account.account_id
        for scenario in FakeChatGptContextScenario
    }
    assert len(ids) == len(FakeChatGptContextScenario)


def test_free_scenario_is_chat_only() -> None:
    snapshot = DeterministicFakeChatGptContext().build(
        scenario=FakeChatGptContextScenario.FREE_CHAT_ONLY,
        observed_at=NOW,
    )
    assert snapshot.account.work_capability.state is CapabilitySupport.UNSUPPORTED
    assert snapshot.work_quota is None


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        (FakeChatGptContextScenario.PAID_WORK_AVAILABLE, ExperienceKind.WORK),
        (FakeChatGptContextScenario.PAID_WORK_NEAR_LIMIT, ExperienceKind.WORK),
        (FakeChatGptContextScenario.PAID_WORK_EXHAUSTED, ExperienceKind.CHAT),
        (FakeChatGptContextScenario.WORK_UNKNOWN, ExperienceKind.CHAT),
        (FakeChatGptContextScenario.MANAGED_WORK_UNAVAILABLE, ExperienceKind.CHAT),
        (FakeChatGptContextScenario.FREE_CHAT_ONLY, ExperienceKind.CHAT),
    ],
)
def test_fake_scenarios_drive_chat_first_policy(
    scenario: FakeChatGptContextScenario,
    expected: ExperienceKind,
) -> None:
    snapshot = DeterministicFakeChatGptContext().build(
        scenario=scenario,
        observed_at=NOW,
    )
    decision = select_chatgpt_experience(
        account=snapshot.account,
        request=ExperienceSelectionRequest(
            request_id="req_work",
            account_id=snapshot.account.account_id,
            requested=ExperienceRequestKind.WORK,
            requested_at=NOW,
        ),
        evaluated_at=NOW,
        work_quota=snapshot.work_quota,
    )
    assert decision.selected is expected


def test_auto_request_stays_chat_even_when_work_is_available() -> None:
    snapshot = DeterministicFakeChatGptContext().build(
        scenario=FakeChatGptContextScenario.PAID_WORK_AVAILABLE,
        observed_at=NOW,
    )
    decision = select_chatgpt_experience(
        account=snapshot.account,
        request=ExperienceSelectionRequest(
            request_id="req_auto",
            account_id=snapshot.account.account_id,
            requested=ExperienceRequestKind.AUTO,
            requested_at=NOW,
        ),
        evaluated_at=NOW,
        work_quota=snapshot.work_quota,
    )
    assert decision.selected is ExperienceKind.CHAT
    assert not decision.fallback_used


def test_fake_module_contains_no_network_or_browser_imports() -> None:
    source = Path(
        "src/systeme_local_gateway/providers/fake_chatgpt_context.py"
    ).read_text(encoding="utf-8")
    forbidden = (
        "openai",
        "httpx",
        "requests",
        "urllib",
        "socket",
        "subprocess",
        "playwright",
        "selenium",
        "OPENAI_API_KEY",
    )
    lowered = source.lower()
    for token in forbidden:
        assert token.lower() not in lowered


def test_exhausted_scenario_has_explicit_quota_state() -> None:
    snapshot = DeterministicFakeChatGptContext().build(
        scenario=FakeChatGptContextScenario.PAID_WORK_EXHAUSTED,
        observed_at=NOW,
    )
    assert snapshot.work_quota is not None
    assert snapshot.work_quota.state is QuotaState.EXHAUSTED


def test_fake_context_canonicalizes_equivalent_observation_times() -> None:
    fake = DeterministicFakeChatGptContext()
    utc = fake.build(
        scenario=FakeChatGptContextScenario.PAID_WORK_AVAILABLE,
        observed_at=NOW,
    )
    offset = fake.build(
        scenario=FakeChatGptContextScenario.PAID_WORK_AVAILABLE,
        observed_at=NOW.astimezone(timezone(timedelta(hours=2))),
    )
    assert utc == offset


def test_fake_context_rejects_naive_observation_time() -> None:
    with pytest.raises(ValueError, match="timezone"):
        DeterministicFakeChatGptContext().build(
            scenario=FakeChatGptContextScenario.PAID_WORK_AVAILABLE,
            observed_at=NOW.replace(tzinfo=None),
        )


def test_fake_unknown_capability_claims_do_not_share_mutable_instances() -> None:
    snapshot = DeterministicFakeChatGptContext().build(
        scenario=FakeChatGptContextScenario.PAID_WORK_AVAILABLE,
        observed_at=NOW,
    )
    capabilities = snapshot.account.context_capabilities
    assert capabilities.can_create_projects is not capabilities.can_enumerate_projects
