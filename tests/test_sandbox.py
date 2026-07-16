import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import systeme_local_gateway.sandbox as sandbox_module
from systeme_local_gateway.sandbox import (
    DockerSandboxRunner,
    ProcessOutput,
    SnapshotViolation,
    WorkspaceSnapshot,
    _same_content_state,
    run_bounded_process,
)


def limits() -> dict[str, int | float]:
    return {
        "max_task_seconds": 10,
        "max_output_bytes": 32,
        "memory_mb": 128,
        "cpu_count": 1,
        "max_snapshot_files": 100,
        "max_snapshot_bytes": 1_000_000,
        "max_change_entries": 10,
    }


def test_windows_file_identity_uses_stable_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    before = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o666,
        st_size=4,
        st_mtime_ns=100,
        st_ctime_ns=200,
        st_dev=1,
        st_ino=10,
        st_file_attributes=32,
        st_birthtime_ns=50,
    )
    opened = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o444,
        st_size=4,
        st_mtime_ns=100,
        st_ctime_ns=999,
        st_dev=1,
        st_ino=10,
        st_file_attributes=128,
        st_birthtime_ns=999,
    )

    monkeypatch.setattr(sandbox_module.os, "name", "nt")

    assert sandbox_module._same_file_version(before, opened) is True
    opened.st_ino = 11
    assert sandbox_module._same_file_version(before, opened) is False
    assert _same_content_state(before, opened) is True
    opened.st_mtime_ns = 101
    assert _same_content_state(before, opened) is False


def test_workspace_snapshot_excludes_secrets_and_virtualenv(tmp_path: Path) -> None:
    source = tmp_path / "workspace"
    source.mkdir()
    (source / "kept.txt").write_text("safe", encoding="utf-8")
    (source / ".env").write_text("SECRET=1", encoding="utf-8")
    (source / ".env.example").write_text("SECRET=example", encoding="utf-8")
    (source / ".venv").mkdir()
    (source / ".venv" / "secret.txt").write_text("hidden", encoding="utf-8")

    with WorkspaceSnapshot(
        source,
        tmp_path / "sandboxes",
        include_git=False,
        max_files=100,
        max_bytes=1_000_000,
        max_change_entries=10,
    ) as snapshot:
        assert snapshot.path is not None
        assert (snapshot.path / "kept.txt").read_text(encoding="utf-8") == "safe"
        assert (snapshot.path / ".env.example").is_file()
        assert not (snapshot.path / ".env").exists()
        assert not (snapshot.path / ".venv").exists()


def test_workspace_snapshot_rejects_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "workspace"
    source.mkdir()
    target = source / "target.txt"
    target.write_text("data", encoding="utf-8")
    link = source / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")

    with pytest.raises(SnapshotViolation, match="symbolic links"):
        with WorkspaceSnapshot(
            source,
            tmp_path / "sandboxes",
            include_git=False,
            max_files=100,
            max_bytes=1_000_000,
            max_change_entries=10,
        ):
            pass


def test_docker_runner_never_mounts_original_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    original = workspace / "tracked.txt"
    original.write_text("original", encoding="utf-8")
    observed_snapshot: Path | None = None
    cleaned: list[str] = []

    def fake_process(argv: list[str], timeout: int, max_output: int) -> ProcessOutput:
        nonlocal observed_snapshot
        assert timeout == 10
        assert max_output == 32
        mount = argv[argv.index("--mount") + 1]
        source_field = next(part for part in mount.split(",") if part.startswith("source="))
        observed_snapshot = Path(source_field.removeprefix("source="))
        assert observed_snapshot != workspace
        assert str(workspace) not in argv
        assert "--pull" in argv and argv[argv.index("--pull") + 1] == "never"
        (observed_snapshot / "tracked.txt").write_text("sandbox", encoding="utf-8")
        (observed_snapshot / "added.txt").write_text("added", encoding="utf-8")
        return ProcessOutput(0, "ok", "", False)

    runner = DockerSandboxRunner(
        "example@sha256:deadbeef",
        tmp_path / "sandboxes",
        limits(),
        process_runner=fake_process,
        cleanup_runner=cleaned.append,
    )
    result = runner.run(workspace, ["python", "-m", "pytest", "-q"], include_git=False)

    assert original.read_text(encoding="utf-8") == "original"
    assert result["workspace_isolated"] is True
    assert result["workspace_changes"] == {
        "added": ["added.txt"],
        "modified": ["tracked.txt"],
        "deleted": [],
        "truncated": False,
    }
    assert len(cleaned) == 1
    assert observed_snapshot is not None
    assert not observed_snapshot.exists()


def test_bounded_process_truncates_output() -> None:
    result = run_bounded_process(
        [sys.executable, "-c", "import sys; print('x' * 100); print('y' * 100, file=sys.stderr)"],
        timeout=10,
        max_output=16,
    )

    assert result.returncode == 0
    assert len(result.stdout.encode("utf-8")) <= 16
    assert len(result.stderr.encode("utf-8")) <= 16
    assert result.truncated is True
    assert result.timed_out is False


def test_snapshot_root_must_be_outside_workspace(tmp_path: Path) -> None:
    source = tmp_path / "workspace"
    source.mkdir()

    with pytest.raises(SnapshotViolation, match="outside"):
        with WorkspaceSnapshot(
            source,
            source / ".sandboxes",
            include_git=False,
            max_files=100,
            max_bytes=1_000_000,
            max_change_entries=10,
        ):
            pass


def test_git_snapshot_copies_only_required_metadata(tmp_path: Path) -> None:
    source = tmp_path / "workspace"
    git_dir = source / ".git"
    (git_dir / "objects").mkdir(parents=True)
    (git_dir / "hooks").mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
    (git_dir / "index").write_bytes(b"index")
    (git_dir / "config").write_text("url = https://token@example.test", encoding="utf-8")
    (git_dir / "hooks" / "pre-commit").write_text("echo unsafe", encoding="utf-8")
    (git_dir / "objects" / "object").write_bytes(b"object")

    with WorkspaceSnapshot(
        source,
        tmp_path / "sandboxes",
        include_git=True,
        max_files=100,
        max_bytes=1_000_000,
        max_change_entries=10,
    ) as snapshot:
        assert snapshot.path is not None
        copied_git = snapshot.path / ".git"
        assert (copied_git / "HEAD").is_file()
        assert (copied_git / "index").is_file()
        assert (copied_git / "objects" / "object").is_file()
        assert not (copied_git / "config").exists()
        assert not (copied_git / "hooks").exists()


def test_snapshot_limits_file_count(tmp_path: Path) -> None:
    source = tmp_path / "workspace"
    source.mkdir()
    (source / "one.txt").write_text("1", encoding="utf-8")
    (source / "two.txt").write_text("2", encoding="utf-8")

    with pytest.raises(SnapshotViolation, match="file limit"):
        with WorkspaceSnapshot(
            source,
            tmp_path / "sandboxes",
            include_git=False,
            max_files=1,
            max_bytes=1_000_000,
            max_change_entries=10,
        ):
            pass


def test_snapshot_detects_growth_beyond_byte_limit(tmp_path: Path) -> None:
    source = tmp_path / "workspace"
    source.mkdir()
    (source / "small.txt").write_text("small", encoding="utf-8")

    with WorkspaceSnapshot(
        source,
        tmp_path / "sandboxes",
        include_git=False,
        max_files=100,
        max_bytes=10,
        max_change_entries=10,
    ) as snapshot:
        assert snapshot.path is not None
        (snapshot.path / "large.txt").write_text("x" * 20, encoding="utf-8")
        with pytest.raises(SnapshotViolation, match="byte limit"):
            snapshot.changes()
