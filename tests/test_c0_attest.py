from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c0_attest import (
    C0ManualWebObservation,
    C0RevocationReceipt,
)
from systeme_local_gateway.providers import (
    ChatGptPlan,
    ChatGptWorkspaceRole,
    McpReadinessCheckId,
    McpReadinessCheckState,
)

NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)


def _checks() -> dict[McpReadinessCheckId, McpReadinessCheckState]:
    return {
        check_id: (
            McpReadinessCheckState.NOT_APPLICABLE
            if check_id is McpReadinessCheckId.REFRESH_TOKEN
            else McpReadinessCheckState.VERIFIED
        )
        for check_id in McpReadinessCheckId
    }


def _manual_values() -> dict[str, object]:
    return {
        "version": "1",
        "source": "manual_chatgpt_web",
        "simulated": False,
        "plan": ChatGptPlan.PRO,
        "role": ChatGptWorkspaceRole.MEMBER,
        "client": "web",
        "transport": "secure_mcp_tunnel",
        "authentication": "none",
        "draft_plugin": True,
        "published": False,
        "tool_name": "systeme_local_connectivity_probe",
        "tool_count": 1,
        "write_tool_count": 0,
        "high_risk_tool_count": 0,
        "tool_snapshot_sha256": "a" * 64,
        "local_policy_sha256": "b" * 64,
        "checks": _checks(),
        "observed_at": NOW,
        "started_at": NOW,
    }


def test_manual_web_observation_schema_is_bounded_and_non_simulated() -> None:
    schema = C0ManualWebObservation.model_json_schema()

    assert schema["additionalProperties"] is False
    assert schema["properties"]["source"]["const"] == "manual_chatgpt_web"
    assert schema["properties"]["simulated"]["const"] is False
    assert schema["properties"]["tool_count"]["const"] == 1
    assert schema["properties"]["write_tool_count"]["const"] == 0
    assert schema["properties"]["high_risk_tool_count"]["const"] == 0


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("simulated", True, "False"),
        ("plan", ChatGptPlan.UNKNOWN, "ineligible"),
        ("plan", ChatGptPlan.PLUS, "ineligible"),
        ("role", ChatGptWorkspaceRole.UNKNOWN, "role is unknown"),
        ("tool_count", 2, "1"),
        ("published", True, "False"),
    ],
)
def test_manual_observation_rejects_unproven_or_expanded_claims(
    field: str,
    value: object,
    message: str,
) -> None:
    values = _manual_values()
    values[field] = value

    with pytest.raises(ValidationError, match=message):
        C0ManualWebObservation.model_validate(values)


def test_manual_observation_rejects_missing_unknown_or_invalid_na_checks() -> None:
    missing = _manual_values()
    checks = _checks()
    checks.pop(McpReadinessCheckId.DEVELOPER_MODE)
    missing["checks"] = checks
    with pytest.raises(ValidationError, match="exactly eleven"):
        C0ManualWebObservation.model_validate(missing)

    unknown = _manual_values()
    checks = _checks()
    checks[McpReadinessCheckId.DEVELOPER_MODE] = McpReadinessCheckState.UNKNOWN
    unknown["checks"] = checks
    with pytest.raises(ValidationError, match="blocking check"):
        C0ManualWebObservation.model_validate(unknown)

    invalid_na = _manual_values()
    checks = _checks()
    checks[McpReadinessCheckId.DEVELOPER_MODE] = McpReadinessCheckState.NOT_APPLICABLE
    invalid_na["checks"] = checks
    with pytest.raises(ValidationError, match="misuses not_applicable"):
        C0ManualWebObservation.model_validate(invalid_na)


def test_revocation_receipt_requires_every_manual_revocation_fact() -> None:
    values = {
        "version": "1",
        "source": "manual_chatgpt_web",
        "plugin_connection_removed": True,
        "runtime_api_key_revoked": True,
        "tunnel_stopped": True,
        "facade_stopped": True,
        "post_revocation_call_failed": False,
        "verified_at": NOW,
    }

    with pytest.raises(ValidationError):
        C0RevocationReceipt.model_validate(values)
