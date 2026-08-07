from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import systeme_local_gateway.c9_git as c9_git


def _trusted_git_executable() -> Path:
    discovered = shutil.which("git")
    assert discovered is not None
    candidate = Path(discovered).resolve()
    if os.name == "nt" and candidate.parent.name.casefold() == "cmd":
        candidate = candidate.parent.parent / "bin" / "git.exe"
    return candidate.resolve(strict=True)


@pytest.fixture(autouse=True)
def _closed_git_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in tuple(os.environ):
        if name.upper().startswith("GIT_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(
        "SLG_C9_GIT_EXECUTABLE",
        os.fspath(_trusted_git_executable()),
    )


def test_git_helper_runs_with_closed_configuration_and_no_fsmonitor(
    tmp_path: Path,
) -> None:
    git = _trusted_git_executable()
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(
        (os.fspath(git), "init", "--quiet"),
        cwd=repository,
        check=True,
        capture_output=True,
    )
    marker = tmp_path / "fsmonitor-ran.txt"
    command = f"\"{os.fspath(Path(os.sys.executable))}\" -c \"open(r'{marker}','w').write('bad')\""
    subprocess.run(
        (os.fspath(git), "config", "core.fsmonitor", command),
        cwd=repository,
        check=True,
        capture_output=True,
    )

    result = c9_git.run_c9_git(repository, "status", "--porcelain")

    assert result.returncode == 0
    assert result.stderr == b""
    assert not marker.exists()


def test_git_helper_refuses_ambient_git_configuration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.fspath(tmp_path / "hostile.cfg"))

    with pytest.raises(c9_git.C9GitError, match=r"ambient GIT_\*"):
        c9_git.run_c9_git(tmp_path, "rev-parse", "HEAD")


def test_git_helper_refuses_global_option_and_mutating_subcommand_injection(
    tmp_path: Path,
) -> None:
    with pytest.raises(c9_git.C9GitError, match="read-only allowlist"):
        c9_git.run_c9_git(
            tmp_path,
            "-c",
            "core.fsmonitor=!hostile-command",
            "status",
        )
    with pytest.raises(c9_git.C9GitError, match="read-only allowlist"):
        c9_git.run_c9_git(tmp_path, "checkout", "--", ".")


def test_git_helper_rejects_relative_and_hardlinked_executables(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SLG_C9_GIT_EXECUTABLE", "git.exe" if os.name == "nt" else "git")
    with pytest.raises(c9_git.C9GitError, match="absolute native Git"):
        c9_git.resolve_c9_git_executable()

    executable = tmp_path / ("git.exe" if os.name == "nt" else "git")
    alias = tmp_path / "git-alias.exe"
    executable.write_bytes(b"synthetic git executable")
    executable.chmod(0o700)
    try:
        os.link(executable, alias)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")
    monkeypatch.setattr(c9_git, "_windows_acl_is_trusted", lambda *_args, **_kwargs: None)

    with pytest.raises(c9_git.C9GitError, match="singly-linked"):
        c9_git._assert_trusted_path_component(
            executable,
            executable=True,
            volume_root=False,
        )


@pytest.mark.skipif(os.name != "nt", reason="Git for Windows layout")
def test_git_for_windows_rejects_cmd_hardlink_and_accepts_bin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bin_git = _trusted_git_executable()
    cmd_git = bin_git.parent.parent / "cmd" / "git.exe"
    assert int(os.lstat(bin_git).st_nlink) == 1
    assert int(os.lstat(cmd_git).st_nlink) > 1

    monkeypatch.setenv("SLG_C9_GIT_EXECUTABLE", os.fspath(cmd_git))
    with pytest.raises(c9_git.C9GitError, match="singly-linked"):
        c9_git.resolve_c9_git_executable()

    monkeypatch.setenv("SLG_C9_GIT_EXECUTABLE", os.fspath(bin_git))
    assert c9_git.resolve_c9_git_executable() == bin_git


def test_git_helper_rejects_reparse_executable_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable = tmp_path / ("git.exe" if os.name == "nt" else "git")
    executable.write_bytes(b"synthetic git executable")
    executable.chmod(0o700)
    target_identity = (
        int(os.lstat(executable).st_dev),
        int(os.lstat(executable).st_ino),
    )
    original = c9_git._is_reparse

    def mark_executable(info: os.stat_result) -> bool:
        return (
            original(info)
            or (
                int(info.st_dev),
                int(info.st_ino),
            )
            == target_identity
        )

    monkeypatch.setattr(c9_git, "_is_reparse", mark_executable)
    monkeypatch.setattr(c9_git, "_windows_acl_is_trusted", lambda *_args, **_kwargs: None)

    with pytest.raises(c9_git.C9GitError, match="reparse"):
        c9_git._assert_trusted_path_component(
            executable,
            executable=True,
            volume_root=False,
        )


@pytest.mark.parametrize(
    ("mask", "flags", "volume_root", "should_reject"),
    (
        (0x00000002, 0, False, True),
        (0x00000004, 0, True, False),
        (0x10000000, 8, True, False),
        (0x00010000, 0, True, True),
        (0x40000000, 0, True, True),
    ),
)
def test_windows_acl_check_applies_root_and_inherit_only_semantics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mask: int,
    flags: int,
    volume_root: bool,
    should_reject: bool,
) -> None:
    class FakeAcl:
        def GetAceCount(self) -> int:
            return 1

        def GetAce(self, _index: int) -> tuple[tuple[int, int], int, str]:
            return ((0, flags), mask, "S-1-5-11")

    class FakeDescriptor:
        def GetSecurityDescriptorOwner(self) -> str:
            return "S-1-5-18"

        def GetSecurityDescriptorDacl(self) -> FakeAcl:
            return FakeAcl()

    security = SimpleNamespace(
        SE_FILE_OBJECT=1,
        OWNER_SECURITY_INFORMATION=1,
        DACL_SECURITY_INFORMATION=4,
        INHERIT_ONLY_ACE=8,
        ACCESS_ALLOWED_ACE_TYPE=0,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE=5,
        GetNamedSecurityInfo=lambda *_args: FakeDescriptor(),
        ConvertSidToStringSid=lambda value: value,
    )
    rights = SimpleNamespace(
        GENERIC_WRITE=0x40000000,
        GENERIC_ALL=0x10000000,
        DELETE=0x00010000,
        WRITE_DAC=0x00040000,
        WRITE_OWNER=0x00080000,
        FILE_DELETE_CHILD=0x00000040,
        FILE_WRITE_DATA=0x00000002,
        FILE_APPEND_DATA=0x00000004,
        FILE_WRITE_EA=0x00000010,
        FILE_WRITE_ATTRIBUTES=0x00000100,
    )

    def fake_import(name: str) -> Any:
        if name == "win32security":
            return security
        if name == "ntsecuritycon":
            return rights
        raise AssertionError(name)

    monkeypatch.setattr(c9_git.importlib, "import_module", fake_import)

    if should_reject:
        with pytest.raises(c9_git.C9GitError, match="ordinary Windows principal"):
            c9_git._windows_acl_is_trusted(tmp_path, volume_root=volume_root)
    else:
        c9_git._windows_acl_is_trusted(tmp_path, volume_root=volume_root)


def test_git_helper_enforces_combined_output_limit() -> None:
    with pytest.raises(c9_git.C9GitCommandError, match="output exceeded"):
        c9_git.run_c9_git(
            Path.cwd(),
            "rev-parse",
            "HEAD",
            maximum_output_bytes=4,
        )


def test_git_helper_accepts_only_explicit_return_codes() -> None:
    result = c9_git.run_c9_git(
        Path.cwd(),
        "merge-base",
        "--is-ancestor",
        "HEAD",
        "HEAD",
        accepted_returncodes=(0, 1),
        maximum_output_bytes=64 * 1024,
    )
    assert result.returncode == 0
