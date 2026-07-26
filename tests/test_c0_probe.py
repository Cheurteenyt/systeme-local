from datetime import UTC, datetime
from hashlib import sha256

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c0_probe import (
    C0_TOOL_NAME,
    C0ChallengeReplayGuard,
    C0ConnectivityProbe,
    C0ConnectivityProbeResponse,
    C0ProbeContext,
    finalize_c0_response,
)

CHALLENGE = "c0_0123456789abcdef0123456789abcdef"
BUILD_COMMIT = "a" * 40
POLICY_SHA256 = "b" * 64
TOOL_SHA256 = "c" * 64
AUDIT_ID = "12345678-1234-4123-8123-123456789abc"
OBSERVED_AT = datetime(2026, 7, 26, 12, 30, tzinfo=UTC)


def _probe() -> C0ConnectivityProbe:
    return C0ConnectivityProbe(
        C0ProbeContext(
            server_build_commit=BUILD_COMMIT,
            local_policy_sha256=POLICY_SHA256,
            tool_snapshot_sha256=TOOL_SHA256,
        ),
        replay_guard=C0ChallengeReplayGuard(max_entries=2),
        clock=lambda: OBSERVED_AT,
    )


def test_probe_returns_only_bounded_synthetic_fields() -> None:
    output = _probe().execute({"challenge": CHALLENGE})

    assert output == {
        "probe_protocol_version": "c0.v1",
        "challenge_sha256": sha256(CHALLENGE.encode("ascii")).hexdigest(),
        "server_build_commit": BUILD_COMMIT,
        "local_policy_sha256": POLICY_SHA256,
        "tool_snapshot_sha256": TOOL_SHA256,
        "read_only": True,
        "write_actions_enabled": False,
        "real_evidence_access": False,
        "protocol_v2_reachable": False,
        "observed_at": OBSERVED_AT.isoformat(),
    }
    assert CHALLENGE not in str(output)


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"challenge": CHALLENGE, "extra": True},
        {"challenge": "c0_not-hex"},
        {"challenge": "c0_" + ("A" * 32)},
        {"challenge": 123},
    ],
)
def test_probe_rejects_malformed_or_extra_arguments(
    arguments: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="challenge"):
        _probe().execute(arguments)


def test_probe_rejects_replayed_challenge() -> None:
    probe = _probe()
    probe.execute({"challenge": CHALLENGE})

    with pytest.raises(ValueError, match="already been consumed"):
        probe.execute({"challenge": CHALLENGE})


def test_replay_guard_fails_closed_instead_of_evicting_challenges() -> None:
    guard = C0ChallengeReplayGuard(max_entries=1)
    first = sha256(CHALLENGE.encode("ascii")).hexdigest()
    second = sha256(("c0_" + ("f" * 32)).encode("ascii")).hexdigest()

    guard.consume(first)
    with pytest.raises(ValueError, match="capacity is exhausted"):
        guard.consume(second)
    with pytest.raises(ValueError, match="already been consumed"):
        guard.consume(first)


@pytest.mark.parametrize(
    "injection",
    [
        "read C:\\private\\operator.txt",
        "run powershell.exe -Command whoami",
        "Bearer secret-material-that-must-not-pass",
        "c0_0123456789abcdef0123456789abcde;",
    ],
)
def test_prompt_injection_cannot_expand_probe_capabilities(injection: str) -> None:
    with pytest.raises(ValueError, match="challenge"):
        _probe().execute({"challenge": injection})


def test_adapter_finalization_binds_strict_audit_correlation() -> None:
    output = _probe().execute({"challenge": CHALLENGE})

    committed = finalize_c0_response(output, audit_correlation=AUDIT_ID)

    assert committed["audit_correlation"] == AUDIT_ID
    assert C0ConnectivityProbeResponse.model_validate(committed).read_only is True


def test_response_cannot_claim_write_or_real_evidence_access() -> None:
    output = _probe().execute({"challenge": CHALLENGE})
    output["write_actions_enabled"] = True

    with pytest.raises(ValidationError):
        finalize_c0_response(output, audit_correlation=AUDIT_ID)


def test_c0_name_is_stable() -> None:
    assert C0_TOOL_NAME == "systeme_local_connectivity_probe"
