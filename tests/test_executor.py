from pathlib import Path

import pytest

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
