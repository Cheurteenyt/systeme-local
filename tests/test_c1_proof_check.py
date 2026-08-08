from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from systeme_local_gateway.audit import AuditLog
from systeme_local_gateway.c0_probe import C0ConnectivityProbeResponse
from systeme_local_gateway.c1_observability import (
    C1Surface,
    C1TestChatLabel,
    commit_c1_surface_observation,
)
from systeme_local_gateway.c1_proof_check import main
from systeme_local_gateway.mcp_tools import McpToolRegistry
from systeme_local_gateway.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
AUDIT_KEY = "c1-proof-check-audit-key-that-is-long-enough"
COMMIT = "d" * 40
CHALLENGE = "c0_0123456789abcdef0123456789abcdef"


def _paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "surface": tmp_path / "surface-a.json",
        "response": tmp_path / "response-a.json",
        "challenge": tmp_path / "challenge-a.txt",
        "audit": tmp_path / "audit.jsonl",
    }


def _prepare(
    tmp_path: Path,
    *,
    surface: C1Surface = C1Surface.CHAT,
    simulated: bool = False,
    surface_age: timedelta = timedelta(seconds=2),
    surface_expires_in: timedelta = timedelta(minutes=20),
) -> dict[str, Path]:
    paths = _paths(tmp_path)
    now = datetime.now(timezone.utc)
    observation = commit_c1_surface_observation(
        test_chat_label=C1TestChatLabel.CHAT_A,
        surface=surface,
        plugin_selected=surface is C1Surface.CHAT,
        observed_at=now - surface_age,
        expires_at=now + surface_expires_in,
        audit_key=AUDIT_KEY,
        simulated=simulated,
    )
    paths["surface"].write_text(
        json.dumps(observation.model_dump(mode="json")),
        encoding="utf-8",
    )
    paths["challenge"].write_text(CHALLENGE, encoding="utf-8")

    policy = PolicyEngine(ROOT / "policy.c0.yaml")
    registry = McpToolRegistry(policy, c0_mode=True)
    audit_id = AuditLog(paths["audit"], AUDIT_KEY).append(
        {
            "task_id": "task-c1-proof",
            "agent": {"provider": "mcp"},
            "capability": "systeme_local_connectivity_probe",
            "status": "completed",
        }
    )
    response = C0ConnectivityProbeResponse(
        probe_protocol_version="c0.v1",
        challenge_sha256=sha256(CHALLENGE.encode("ascii")).hexdigest(),
        server_build_commit=COMMIT,
        local_policy_sha256=policy.policy_sha256,
        tool_snapshot_sha256=registry.tool_snapshot_sha256,
        read_only=True,
        write_actions_enabled=False,
        real_evidence_access=False,
        protocol_v2_reachable=False,
        audit_correlation=audit_id,
        observed_at=now,
    )
    paths["response"].write_text(
        json.dumps(response.model_dump(mode="json")),
        encoding="utf-8",
    )
    return paths


def _argv(paths: dict[str, Path]) -> list[str]:
    return [
        "--test-chat",
        "a",
        "--surface-observation",
        str(paths["surface"]),
        "--response",
        str(paths["response"]),
        "--challenge",
        str(paths["challenge"]),
        "--audit-log",
        str(paths["audit"]),
        "--policy",
        str(ROOT / "policy.c0.yaml"),
    ]


def test_c1_proof_checker_correlates_one_strict_chat_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _prepare(tmp_path)
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)
    monkeypatch.setattr(
        "systeme_local_gateway.c1_proof_check._current_commit",
        lambda: COMMIT,
    )

    assert main(_argv(paths)) == 0
    bundle = json.loads(capsys.readouterr().out)
    assert bundle["observation"]["test_chat_label"] == "c1-test-chat-a"
    assert bundle["observation"]["read_only"] is True
    assert bundle["observation"]["write_actions_enabled"] is False
    assert bundle["observation"]["real_evidence_access"] is False
    assert bundle["observation"]["protocol_v2_reachable"] is False
    assert bundle["correlation_receipt"]["status"] == "live_chat_call_correlated"
    assert CHALLENGE not in json.dumps(bundle)


def test_c1_proof_checker_keeps_surface_to_response_freshness_at_thirty_minutes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _prepare(
        tmp_path,
        surface_age=timedelta(minutes=31),
        surface_expires_in=timedelta(hours=1),
    )
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)
    monkeypatch.setattr(
        "systeme_local_gateway.c1_proof_check._current_commit",
        lambda: COMMIT,
    )

    assert main(_argv(paths)) == 1
    assert "surface observation is stale" in capsys.readouterr().err


def test_c1_proof_checker_emits_a_two_hour_bounded_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _prepare(
        tmp_path,
        surface_age=timedelta(minutes=1),
        surface_expires_in=timedelta(hours=1, minutes=59),
    )
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)
    monkeypatch.setattr(
        "systeme_local_gateway.c1_proof_check._current_commit",
        lambda: COMMIT,
    )

    assert main(_argv(paths)) == 0
    bundle = json.loads(capsys.readouterr().out)
    checked_at = datetime.fromisoformat(bundle["correlation_receipt"]["checked_at"])
    expires_at = datetime.fromisoformat(bundle["correlation_receipt"]["expires_at"])

    assert expires_at - checked_at > timedelta(hours=1)
    assert expires_at - checked_at <= timedelta(hours=2)


def test_c1_proof_checker_rejects_missing_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _prepare(tmp_path)
    paths["audit"].unlink()
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)
    monkeypatch.setattr(
        "systeme_local_gateway.c1_proof_check._current_commit",
        lambda: COMMIT,
    )

    assert main(_argv(paths)) == 1
    assert "audit" in capsys.readouterr().err.lower()


def test_c1_proof_checker_rejects_duplicated_audit_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _prepare(tmp_path)
    raw = paths["audit"].read_text(encoding="utf-8")
    paths["audit"].write_text(raw + raw, encoding="utf-8")
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)
    monkeypatch.setattr(
        "systeme_local_gateway.c1_proof_check._current_commit",
        lambda: COMMIT,
    )

    assert main(_argv(paths)) == 1
    assert capsys.readouterr().err


def test_c1_proof_checker_rejects_changed_policy_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _prepare(tmp_path)
    response = json.loads(paths["response"].read_text(encoding="utf-8"))
    response["local_policy_sha256"] = "f" * 64
    paths["response"].write_text(json.dumps(response), encoding="utf-8")
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)
    monkeypatch.setattr(
        "systeme_local_gateway.c1_proof_check._current_commit",
        lambda: COMMIT,
    )

    assert main(_argv(paths)) == 1
    assert "policy digest mismatch" in capsys.readouterr().err


@pytest.mark.parametrize("surface", [C1Surface.WORK, C1Surface.UNKNOWN])
def test_c1_proof_checker_refuses_non_chat_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    surface: C1Surface,
) -> None:
    paths = _prepare(tmp_path, surface=surface)
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)
    monkeypatch.setattr(
        "systeme_local_gateway.c1_proof_check._current_commit",
        lambda: COMMIT,
    )

    assert main(_argv(paths)) == 1
    assert "requires the Chat surface" in capsys.readouterr().err


def test_c1_proof_checker_rejects_simulated_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _prepare(tmp_path, simulated=True)
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)
    monkeypatch.setattr(
        "systeme_local_gateway.c1_proof_check._current_commit",
        lambda: COMMIT,
    )

    assert main(_argv(paths)) == 1
    assert "simulated surface evidence" in capsys.readouterr().err
