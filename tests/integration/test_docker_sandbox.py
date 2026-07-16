from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from systeme_local_gateway.sandbox import DockerSandboxRunner


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("SYSTEME_LOCAL_RUN_DOCKER_TESTS") != "1",
        reason="set SYSTEME_LOCAL_RUN_DOCKER_TESTS=1 to run live Docker tests",
    ),
]

IMAGE = os.environ.get("SYSTEME_LOCAL_SANDBOX_IMAGE", "systeme-local-sandbox:dev")


def _limits(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "max_task_seconds": 20,
        "memory_mb": 256,
        "cpu_count": 1,
        "max_output_bytes": 16_384,
        "max_snapshot_files": 1_000,
        "max_snapshot_bytes": 16 * 1024 * 1024,
        "max_change_entries": 100,
    }
    values.update(overrides)
    return values


def _sandbox_containers() -> set[str]:
    completed = subprocess.run(
        [
            "docker",
            "ps",
            "--all",
            "--filter",
            "name=systeme-local-",
            "--format",
            "{{.Names}}",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return {line for line in completed.stdout.splitlines() if line.strip()}


@pytest.fixture(scope="module", autouse=True)
def _docker_environment() -> None:
    subprocess.run(
        ["docker", "info"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )
    subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )


def _assert_cleaned(sandbox_root: Path, containers_before: set[str]) -> None:
    if sandbox_root.exists():
        assert not list(sandbox_root.iterdir())
    assert _sandbox_containers() == containers_before


def test_live_sandbox_isolates_workspace_and_blocks_network(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    sandbox_root = tmp_path / "sandboxes"
    workspace.mkdir()

    tracked = workspace / "tracked.txt"
    tracked.write_text("source-original", encoding="utf-8")
    (workspace / "probe.py").write_text(
        """
from __future__ import annotations

import json
import os
import socket
from pathlib import Path

Path("tracked.txt").write_text("sandbox-modified", encoding="utf-8")
Path("added.txt").write_text("sandbox-added", encoding="utf-8")

try:
    socket.create_connection(("1.1.1.1", 53), timeout=1)
except OSError:
    network_blocked = True
else:
    network_blocked = False

try:
    Path("/systeme-local-rootfs-probe").write_text("unexpected", encoding="utf-8")
except OSError:
    rootfs_blocked = True
else:
    rootfs_blocked = False

print(json.dumps({
    "uid": os.getuid(),
    "gid": os.getgid(),
    "network_blocked": network_blocked,
    "rootfs_blocked": rootfs_blocked,
}, sort_keys=True))
""".lstrip(),
        encoding="utf-8",
    )

    containers_before = _sandbox_containers()
    runner = DockerSandboxRunner(IMAGE, sandbox_root, _limits())
    result = runner.run(workspace, ["python", "probe.py"], include_git=False)

    assert result["returncode"] == 0, result
    probe = json.loads(str(result["stdout"]).strip().splitlines()[-1])
    changes = result["workspace_changes"]

    assert result["workspace_isolated"] is True
    assert tracked.read_text(encoding="utf-8") == "source-original"
    assert not (workspace / "added.txt").exists()
    assert probe["network_blocked"] is True
    assert probe["rootfs_blocked"] is True
    assert probe["uid"] != 0
    assert probe["gid"] != 0
    assert "tracked.txt" in changes["modified"]
    assert "added.txt" in changes["added"]
    assert changes["deleted"] == []
    assert changes["truncated"] is False
    _assert_cleaned(sandbox_root, containers_before)


def test_live_sandbox_bounds_output_and_cleans_timeout(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    sandbox_root = tmp_path / "sandboxes"
    workspace.mkdir()
    (workspace / "tracked.txt").write_text("source-original", encoding="utf-8")

    containers_before = _sandbox_containers()
    bounded_runner = DockerSandboxRunner(
        IMAGE,
        sandbox_root,
        _limits(max_output_bytes=1_024),
    )
    bounded = bounded_runner.run(
        workspace,
        ["python", "-c", "print('x' * 20000)"],
        include_git=False,
    )

    assert bounded["returncode"] == 0
    assert bounded["truncated"] is True
    assert len(str(bounded["stdout"]).encode("utf-8")) <= 1_024
    _assert_cleaned(sandbox_root, containers_before)

    timeout_runner = DockerSandboxRunner(
        IMAGE,
        sandbox_root,
        _limits(max_task_seconds=1),
    )
    with pytest.raises(TimeoutError, match="exceeded"):
        timeout_runner.run(
            workspace,
            ["python", "-c", "import time; time.sleep(10)"],
            include_git=False,
        )

    assert (workspace / "tracked.txt").read_text(encoding="utf-8") == "source-original"
    _assert_cleaned(sandbox_root, containers_before)
