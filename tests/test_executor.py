from pathlib import Path

import pytest

from systeme_local_gateway.c0_probe import (
    C0ConnectivityProbe,
    C0ProbeContext,
    C0_TOOL_NAME,
)
from systeme_local_gateway.executor import CapabilityExecutor


class FakeSandboxRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, list[str], bool]] = []

    def run(self, workspace: Path, command: list[str], *, include_git: bool) -> dict[str, object]:
        self.calls.append((workspace, command, include_git))
        return {"returncode": 0}


def test_test_capability_uses_snapshot_without_git(tmp_path: Path) -> None:
    fake = FakeSandboxRunner()
    executor = CapabilityExecutor(
        tmp_path,
        "image",
        {},
        sandbox_runner=fake,
    )
    command = ["python", "-m", "pytest", "-q"]

    executor.execute(
        "sandbox.run_tests",
        {"command": command},
        {"allowed_commands": [command]},
    )

    assert fake.calls == [(tmp_path.resolve(), command, False)]


def test_git_capability_includes_sanitized_git_metadata(tmp_path: Path) -> None:
    fake = FakeSandboxRunner()
    executor = CapabilityExecutor(
        tmp_path,
        "image",
        {},
        sandbox_runner=fake,
    )
    command = ["git", "status", "--short"]

    executor.execute(
        "git.diff",
        {"command": command},
        {"allowed_commands": [command]},
    )

    assert fake.calls == [(tmp_path.resolve(), command, True)]


def test_command_must_be_validated_before_sandbox(tmp_path: Path) -> None:
    fake = FakeSandboxRunner()
    executor = CapabilityExecutor(
        tmp_path,
        "image",
        {},
        sandbox_runner=fake,
    )

    with pytest.raises(ValueError, match="allowlisted"):
        executor.execute(
            "sandbox.run_tests",
            {"command": ["sh", "-c", "id"]},
            {"allowed_commands": []},
        )

    assert fake.calls == []


def test_c0_probe_is_unavailable_unless_explicitly_injected(
    tmp_path: Path,
) -> None:
    executor = CapabilityExecutor(tmp_path, "image", {})

    with pytest.raises(ValueError, match="no executor"):
        executor.execute(
            C0_TOOL_NAME,
            {"challenge": "c0_" + ("0" * 32)},
            {},
        )


def test_c0_probe_execution_does_not_touch_workspace(tmp_path: Path) -> None:
    probe = C0ConnectivityProbe(
        C0ProbeContext(
            server_build_commit="a" * 40,
            local_policy_sha256="b" * 64,
            tool_snapshot_sha256="c" * 64,
        )
    )
    executor = CapabilityExecutor(tmp_path, "image", {}, c0_probe=probe)

    output = executor.execute(
        C0_TOOL_NAME,
        {"challenge": "c0_" + ("0" * 32)},
        {},
    )

    assert output["write_actions_enabled"] is False
    assert list(tmp_path.iterdir()) == []
