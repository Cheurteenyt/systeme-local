from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from systeme_local_gateway.audit import AuditLog

ROOT = Path(__file__).resolve().parents[1]
AUDIT_KEY = "audit-activation-" + ("a" * 64)
ANCHOR_KEY = "anchor-activation-" + ("b" * 64)


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
    environment["SLG_SHARED_SECRET"] = "shared-activation-" + ("s" * 64)
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
        [sys.executable, *arguments],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def test_gateway_and_approval_cli_fail_closed_until_bootstrap(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path, anchored=True)
    log_path = Path(environment["SLG_AUDIT_LOG"])
    AuditLog(log_path, AUDIT_KEY).append(
        {"task_id": "existing", "status": "completed"}
    )

    gateway_before = _run(
        tmp_path,
        environment,
        "-c",
        "import systeme_local_gateway.main",
    )
    assert gateway_before.returncode != 0
    assert "not initialized" in gateway_before.stderr

    approvals_before = _run(
        tmp_path,
        environment,
        "-m",
        "systeme_local_gateway.approvals",
        "list",
    )
    assert approvals_before.returncode == 1
    assert "not initialized" in approvals_before.stderr

    initialized = _run(
        tmp_path,
        environment,
        "-m",
        "systeme_local_gateway.audit",
        "anchor-init",
    )
    assert initialized.returncode == 0, initialized.stderr

    gateway_after = _run(
        tmp_path,
        environment,
        "-c",
        (
            "from systeme_local_gateway.main import audit_log; "
            "print(audit_log.verify().anchor_checkpoints)"
        ),
    )
    assert gateway_after.returncode == 0, gateway_after.stderr
    assert gateway_after.stdout.strip() == "1"

    approvals_after = _run(
        tmp_path,
        environment,
        "-m",
        "systeme_local_gateway.approvals",
        "list",
    )
    assert approvals_after.returncode == 0, approvals_after.stderr
    assert approvals_after.stdout.strip() == "[]"


def test_gateway_remains_unanchored_when_configuration_is_absent(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path, anchored=False)
    result = _run(
        tmp_path,
        environment,
        "-c",
        (
            "from systeme_local_gateway.main import audit_log; "
            "print(audit_log.verify().anchor_checkpoints)"
        ),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "None"
