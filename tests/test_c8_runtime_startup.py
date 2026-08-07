from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from systeme_local_gateway.c7_work_admission import (
    C7_POLICY_PATH,
    C7_PROFILE_PATH,
    load_policy,
    load_profile,
)
from systeme_local_gateway.c8_live_cycle import (
    C8LiveCycleBundle,
    commit_operator_authorization,
    commit_work_quota_observation,
    commit_work_surface_observation,
    issue_live_cycle_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
AUDIT_KEY = "c8-runtime-audit-key-is-longer-than-thirty-two-characters"


def _live_cycle(now: datetime) -> C8LiveCycleBundle:
    cycle_id = "c8_cycle_abcdef0123456789abcdef0123456789"
    authorization = commit_operator_authorization(
        cycle_id=cycle_id,
        authorized_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        audit_key=AUDIT_KEY,
    )
    surface = commit_work_surface_observation(
        cycle_id=cycle_id,
        observed_at=now - timedelta(seconds=20),
        expires_at=now + timedelta(minutes=4),
        audit_key=AUDIT_KEY,
    )
    quota = commit_work_quota_observation(
        cycle_id=cycle_id,
        observed_at=now - timedelta(seconds=20),
        expires_at=now + timedelta(minutes=4),
        audit_key=AUDIT_KEY,
    )
    return issue_live_cycle_bundle(
        authorization=authorization,
        surface_observation=surface,
        quota_observation=quota,
        profile=load_profile(ROOT / C7_PROFILE_PATH),
        policy=load_policy(ROOT / C7_POLICY_PATH),
        grant_id="c8_abcdef0123456789abcdef0123456789",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        audit_key=AUDIT_KEY,
    )


def _runtime_environment(state: Path, live_cycle: Path) -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("SLG_AUDIT_ANCHOR_LOG", "SLG_AUDIT_ANCHOR_KEY"):
        environment.pop(name, None)
    environment.update(
        {
            "SLG_SHARED_SECRET": "s" * 48,
            "SLG_AUDIT_KEY": AUDIT_KEY,
            "SLG_MCP_TOKEN": "m" * 48,
            "SLG_WORKSPACE": str(ROOT),
            "SLG_POLICY_FILE": str(ROOT / "policy.c0.yaml"),
            "SLG_AUDIT_LOG": str(state / "audit.jsonl"),
            "SLG_REPLAY_DB": str(state / "replay.sqlite3"),
            "SLG_APPROVAL_DB": str(state / "approvals.sqlite3"),
            "SLG_SANDBOX_ROOT": str(state / "sandboxes"),
            "SLG_MCP_ENABLED": "true",
            "SLG_C0_ENABLED": "true",
            "SLG_C0_SERVER_BUILD_COMMIT": "1" * 40,
            "SLG_PROVIDER_RUNTIME_MODE": "chatgpt_work_c8",
            "SLG_PROVIDER_RUNTIME_ROOT": str(ROOT),
            "SLG_C8_LIVE_CYCLE_FILE": str(live_cycle),
        }
    )
    return environment


def test_c8_provider_mode_builds_only_the_admitted_probe() -> None:
    private_root = ROOT / ".systeme-local" / "c8"
    private_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=private_root) as temporary:
        state = Path(temporary)
        live_cycle_path = state / "live-cycle.json"
        live_cycle_path.write_text(
            json.dumps(_live_cycle(datetime.now(UTC)).model_dump(mode="json")),
            encoding="utf-8",
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import systeme_local_gateway.main as m;"
                    "print([tool.name for tool in m.mcp_registry.list_tools()])"
                ),
            ],
            cwd=state,
            env=_runtime_environment(state, live_cycle_path),
            check=False,
            text=True,
            capture_output=True,
        )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "['systeme_local_connectivity_probe']"


def test_c8_provider_mode_rejects_wrong_audit_key_before_runtime_construction() -> None:
    private_root = ROOT / ".systeme-local" / "c8"
    private_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=private_root) as temporary:
        state = Path(temporary)
        live_cycle_path = state / "live-cycle.json"
        live_cycle_path.write_text(
            json.dumps(_live_cycle(datetime.now(UTC)).model_dump(mode="json")),
            encoding="utf-8",
        )
        environment = _runtime_environment(state, live_cycle_path)
        environment["SLG_AUDIT_KEY"] = "wrong-runtime-audit-key-that-is-still-long-enough"
        completed = subprocess.run(
            [sys.executable, "-c", "import systeme_local_gateway.main"],
            cwd=state,
            env=environment,
            check=False,
            text=True,
            capture_output=True,
        )

    assert completed.returncode != 0
    assert "HMAC mismatch" in completed.stderr
