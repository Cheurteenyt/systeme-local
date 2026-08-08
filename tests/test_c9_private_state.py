from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from systeme_local_gateway.c9_private_state import (
    C9PrivatePermissions,
    C9PrivateStateError,
    C9PrivateStateGuard,
    C9PrivateStateReason,
    is_c9_reparse_point,
    reject_c9_reparse_prefix,
)


class _FakeWindowsAcl:
    def __init__(self, *, verify: bool = True) -> None:
        self.verify_result = verify
        self.applied: list[tuple[Path, bool]] = []
        self._identities: set[tuple[int, int, bool]] = set()

    def apply_owner_only(self, path: Path, *, directory: bool) -> None:
        info = os.lstat(path)
        self.applied.append((path, directory))
        self._identities.add((int(info.st_dev), int(info.st_ino), directory))

    def is_owner_only(self, path: Path, *, directory: bool) -> bool:
        info = os.lstat(path)
        identity = (int(info.st_dev), int(info.st_ino), directory)
        return self.verify_result and identity in self._identities


def _layout(tmp_path: Path) -> tuple[C9PrivateStateGuard, Path, Path]:
    repository = tmp_path / "repository"
    repository.mkdir()
    state = repository / ".systeme-local" / "c9" / "cycle"
    admission = state / "admission.json"
    guard = C9PrivateStateGuard.initialize_layout(
        provider_runtime_root=repository,
        state_directory=state,
        admission_file=admission,
    )
    return guard, state, admission


def _directory_symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")


def test_initialization_creates_only_the_reviewed_private_tree(tmp_path: Path) -> None:
    guard, state, admission = _layout(tmp_path)

    assert guard.lexical_root == tmp_path / "repository" / ".systeme-local" / "c9"
    assert guard.state_directory == state
    assert guard.admission_file == admission
    guard.verify()
    assert state.is_dir()
    assert not admission.exists()


def test_admission_must_be_a_direct_state_child(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    state = repository / ".systeme-local" / "c9" / "cycle"

    with pytest.raises(C9PrivateStateError) as raised:
        C9PrivateStateGuard.initialize_layout(
            provider_runtime_root=repository,
            state_directory=state,
            admission_file=state / "nested" / "admission.json",
        )

    assert raised.value.reason is C9PrivateStateReason.PATH_OUTSIDE_STATE
    assert not (state / "nested").exists()


def test_reparse_marker_covers_windows_junction_semantics() -> None:
    junction_like = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700,
        st_file_attributes=0x400,
    )
    regular = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700,
        st_file_attributes=0,
    )

    assert is_c9_reparse_point(junction_like)  # type: ignore[arg-type]
    assert not is_c9_reparse_point(regular)  # type: ignore[arg-type]


def test_existing_symlink_component_is_rejected_without_following_it(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked"
    _directory_symlink(link, outside)

    with pytest.raises(C9PrivateStateError) as raised:
        reject_c9_reparse_prefix(
            link / "nested" / "admission.json",
            allow_missing_tail=True,
        )

    assert raised.value.reason is C9PrivateStateReason.REPARSE_PATH_REJECTED
    assert tuple(outside.iterdir()) == ()


def test_state_symlink_to_outside_is_rejected_during_layout_initialization(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    c9_root = repository / ".systeme-local" / "c9"
    c9_root.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_state = c9_root / "cycle"
    _directory_symlink(linked_state, outside)

    with pytest.raises(C9PrivateStateError) as raised:
        C9PrivateStateGuard.initialize_layout(
            provider_runtime_root=repository,
            state_directory=linked_state,
            admission_file=linked_state / "admission.json",
        )

    assert raised.value.reason is C9PrivateStateReason.REPARSE_PATH_REJECTED
    assert tuple(outside.iterdir()) == ()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction test")
def test_windows_junction_component_is_rejected_without_traversal(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    c9_root = repository / ".systeme-local" / "c9"
    c9_root.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    junction = c9_root / "cycle"
    completed = subprocess.run(
        (
            "cmd.exe",
            "/d",
            "/c",
            "mklink",
            "/J",
            str(junction),
            str(outside),
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        pytest.skip(f"Windows junctions are unavailable: {completed.stderr}")
    try:
        with pytest.raises(C9PrivateStateError) as raised:
            C9PrivateStateGuard.initialize_layout(
                provider_runtime_root=repository,
                state_directory=junction,
                admission_file=junction / "admission.json",
            )
        assert raised.value.reason is C9PrivateStateReason.REPARSE_PATH_REJECTED
        assert tuple(outside.iterdir()) == ()
    finally:
        os.rmdir(junction)


def test_atomic_admission_write_is_exclusive_metadata_and_one_use(
    tmp_path: Path,
) -> None:
    guard, _, admission = _layout(tmp_path)
    content = b'{"status":"admitted"}\n'

    guard.atomic_write(admission, content)

    assert admission.read_bytes() == content
    info = os.lstat(admission)
    assert stat.S_ISREG(info.st_mode)
    assert not is_c9_reparse_point(info)
    assert int(info.st_nlink) == 1
    with pytest.raises(C9PrivateStateError) as replay:
        guard.atomic_write(admission, b'{"status":"replay"}\n')
    assert replay.value.reason is C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT
    assert admission.read_bytes() == content


def test_bounded_read_is_exact_and_rejects_oversize_or_hardlinks(
    tmp_path: Path,
) -> None:
    guard, _, admission = _layout(tmp_path)
    content = b'{"status":"ready"}\n'
    guard.atomic_write(admission, content)

    assert guard.read_regular(admission, max_bytes=len(content)) == content
    with pytest.raises(C9PrivateStateError) as oversized:
        guard.read_regular(admission, max_bytes=len(content) - 1)
    assert oversized.value.reason is C9PrivateStateReason.READ_FAILED

    second_link = tmp_path / "outside-admission-link.json"
    try:
        os.link(admission, second_link)
    except OSError as exc:
        pytest.skip(f"hardlinks are unavailable: {exc}")
    with pytest.raises(C9PrivateStateError) as hardlink:
        guard.read_regular(admission, max_bytes=1024)
    assert hardlink.value.reason is C9PrivateStateReason.HARD_LINK_REJECTED
    assert second_link.read_bytes() == content


def test_mock_windows_acl_covers_private_chain_directories_and_file(
    tmp_path: Path,
) -> None:
    backend = _FakeWindowsAcl()
    permissions = C9PrivatePermissions(
        platform_name="nt",
        windows_backend=backend,
    )
    repository = tmp_path / "repository"
    repository.mkdir()
    state = repository / ".systeme-local" / "c9" / "cycle"
    admission = state / "admission.json"

    guard = C9PrivateStateGuard.initialize_layout(
        provider_runtime_root=repository,
        state_directory=state,
        admission_file=admission,
        permissions=permissions,
    )
    nested = guard.ensure_directory(state / "nested")
    guard.atomic_write(admission, b'{"status":"private"}\n')

    applied_directories = {path for path, directory in backend.applied if directory}
    assert repository / ".systeme-local" in applied_directories
    assert repository / ".systeme-local" / "c9" in applied_directories
    assert state in applied_directories
    assert nested in applied_directories
    permissions.verify(admission, directory=False)
    assert guard.read_regular(admission, max_bytes=1024)


def test_mock_windows_acl_failure_is_fail_closed(tmp_path: Path) -> None:
    permissions = C9PrivatePermissions(
        platform_name="nt",
        windows_backend=_FakeWindowsAcl(verify=False),
    )
    repository = tmp_path / "repository"
    repository.mkdir()
    state = repository / ".systeme-local" / "c9"

    with pytest.raises(C9PrivateStateError) as raised:
        C9PrivateStateGuard.initialize_layout(
            provider_runtime_root=repository,
            state_directory=state,
            admission_file=state / "admission.json",
            permissions=permissions,
        )

    assert raised.value.reason is C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL test")
def test_real_windows_dacl_rejects_an_added_everyone_ace(tmp_path: Path) -> None:
    guard, state, admission = _layout(tmp_path)
    guard.atomic_write(admission, b'{"status":"private"}\n')
    completed = subprocess.run(
        (
            "icacls",
            str(state),
            "/grant",
            "*S-1-1-0:(RX)",
        ),
        check=False,
        capture_output=True,
        timeout=10,
    )
    if completed.returncode != 0:
        pytest.skip("icacls could not add the deterministic test ACE")
    try:
        with pytest.raises(C9PrivateStateError) as raised:
            guard.verify()
        assert raised.value.reason is C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED
    finally:
        C9PrivatePermissions().apply_and_verify(state, directory=True)


def test_stale_admission_symlink_is_never_unlinked_or_followed(tmp_path: Path) -> None:
    guard, _, admission = _layout(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("keep", encoding="utf-8")
    try:
        admission.symlink_to(outside)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    with pytest.raises(C9PrivateStateError) as raised:
        guard.unlink_regular(admission, missing_ok=False)

    assert raised.value.reason is C9PrivateStateReason.REPARSE_PATH_REJECTED
    assert outside.read_text(encoding="utf-8") == "keep"
    assert admission.is_symlink()


def test_stale_admission_hardlink_is_refused_and_target_survives(
    tmp_path: Path,
) -> None:
    guard, _, admission = _layout(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("keep", encoding="utf-8")
    try:
        os.link(outside, admission)
    except OSError as exc:
        pytest.skip(f"hardlinks are unavailable: {exc}")

    with pytest.raises(C9PrivateStateError) as raised:
        guard.unlink_regular(admission, missing_ok=False)

    assert raised.value.reason is C9PrivateStateReason.HARD_LINK_REJECTED
    assert outside.read_text(encoding="utf-8") == "keep"
    assert admission.exists()


def test_parent_substitution_blocks_admission_write_outside_state(
    tmp_path: Path,
) -> None:
    guard, state, admission = _layout(tmp_path)
    moved = state.with_name("cycle-moved")
    state.rename(moved)
    outside = tmp_path / "outside"
    outside.mkdir()
    _directory_symlink(state, outside)

    with pytest.raises(C9PrivateStateError) as raised:
        guard.atomic_write(admission, b'{"status":"must-not-escape"}\n')

    assert raised.value.reason in {
        C9PrivateStateReason.REPARSE_PATH_REJECTED,
        C9PrivateStateReason.DIRECTORY_IDENTITY_CHANGED,
    }
    assert not (outside / "admission.json").exists()
    assert not (moved / "admission.json").exists()


def test_parent_substitution_blocks_admission_unlink_outside_state(
    tmp_path: Path,
) -> None:
    guard, state, admission = _layout(tmp_path)
    guard.atomic_write(admission, b'{"status":"inside"}\n')
    moved = state.with_name("cycle-moved")
    state.rename(moved)
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_admission = outside / "admission.json"
    outside_admission.write_text("keep", encoding="utf-8")
    _directory_symlink(state, outside)

    with pytest.raises(C9PrivateStateError):
        guard.unlink_regular(admission, missing_ok=False)

    assert outside_admission.read_text(encoding="utf-8") == "keep"
    assert (moved / "admission.json").exists()
