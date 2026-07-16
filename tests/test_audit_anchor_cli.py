from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from systeme_local_gateway.audit import AuditLog

ROOT = Path(__file__).resolve().parents[1]
AUDIT_KEY = "audit-cli-" + ("a" * 64)
ANCHOR_KEY = "anchor-cli-" + ("b" * 64)


def _environment(
    tmp_path: Path,
    *,
    anchored: bool,
) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("SLG_")
    }
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["SLG_SHARED_SECRET"] = "shared-cli-" + ("s" * 64)
    environment["SLG_AUDIT_KEY"] = AUDIT_KEY
    environment["SLG_AUDIT_LOG"] = str(tmp_path / "audit.jsonl")
    environment["SLG_WORKSPACE"] = str(tmp_path / "workspace")
    environment["SLG_POLICY_FILE"] = str(ROOT / "policy.yaml")
    environment["SLG_REPLAY_DB"] = str(tmp_path / "replay.sqlite3")
    environment["SLG_APPROVAL_DB"] = str(tmp_path / "approvals.sqlite3")
    environment["SLG_SANDBOX_ROOT"] = str(tmp_path / "sandboxes")
    if anchored:
        environment["SLG_AUDIT_ANCHOR_LOG"] = str(
            tmp_path / "external" / "audit-anchor.jsonl"
        )
        environment["SLG_AUDIT_ANCHOR_KEY"] = ANCHOR_KEY
    return environment


def _run(
    tmp_path: Path,
    environment: dict[str, str],
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.audit",
            *arguments,
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def test_anchor_cli_requires_explicit_single_bootstrap(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path, anchored=True)
    log_path = Path(environment["SLG_AUDIT_LOG"])
    AuditLog(log_path, AUDIT_KEY).append(
        {"task_id": "existing", "status": "completed"}
    )

    before = _run(tmp_path, environment)
    assert before.returncode == 1
    assert "not initialized" in before.stderr

    initialized = _run(tmp_path, environment, "anchor-init")
    assert initialized.returncode == 0, initialized.stderr
    initialized_payload = json.loads(initialized.stdout)
    assert initialized_payload["status"] == "anchor_initialized"
    assert initialized_payload["records"] == 1
    assert initialized_payload["anchor_checkpoints"] == 1

    verified = _run(tmp_path, environment)
    assert verified.returncode == 0, verified.stderr
    verified_payload = json.loads(verified.stdout)
    assert verified_payload["status"] == "valid"
    assert verified_payload["records"] == 1
    assert verified_payload["anchor_checkpoints"] == 1

    repeated = _run(tmp_path, environment, "anchor-init")
    assert repeated.returncode == 1
    assert "already initialized" in repeated.stderr

    anchor_path = Path(environment["SLG_AUDIT_ANCHOR_LOG"])
    assert ANCHOR_KEY.encode() not in anchor_path.read_bytes()


def test_anchor_init_requires_configuration(tmp_path: Path) -> None:
    environment = _environment(tmp_path, anchored=False)
    result = _run(tmp_path, environment, "anchor-init")
    assert result.returncode == 1
    assert "not configured" in result.stderr


def test_log_override_is_rejected_when_anchor_is_configured(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path, anchored=True)
    result = _run(
        tmp_path,
        environment,
        "--log",
        str(tmp_path / "other.jsonl"),
    )
    assert result.returncode == 1
    assert "cannot be overridden" in result.stderr
