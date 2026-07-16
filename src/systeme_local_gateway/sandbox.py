from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from uuid import uuid4


class SnapshotViolation(ValueError):
    """Raised when a workspace cannot be copied safely into a sandbox."""


@dataclass(frozen=True)
class ProcessOutput:
    returncode: int
    stdout: str
    stderr: str
    truncated: bool
    timed_out: bool = False


@dataclass(frozen=True)
class SnapshotChanges:
    added: list[str]
    modified: list[str]
    deleted: list[str]
    truncated: bool


def _same_content_state(first: os.stat_result, second: os.stat_result) -> bool:
    """Compare content-relevant metadata across path and handle stat views."""

    return (
        stat.S_ISREG(first.st_mode)
        and stat.S_ISREG(second.st_mode)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
    )


def _same_file_version(first: os.stat_result, second: os.stat_result) -> bool:
    """Compare two snapshots produced through the same kind of stat view.

    On POSIX, device, inode, metadata-change time, size, and modification time
    must all remain stable. On Windows, ``st_ctime`` is deprecated and other
    fields can differ between path and handle queries, so cross-view checks use
    :func:`_same_content_state`. Same-view checks still compare the file index
    and volume when Python exposes non-zero values.
    """

    if not _same_content_state(first, second):
        return False
    if os.name != "nt":
        return (
            first.st_ctime_ns == second.st_ctime_ns
            and first.st_dev == second.st_dev
            and first.st_ino == second.st_ino
        )
    if first.st_dev and second.st_dev and first.st_dev != second.st_dev:
        return False
    if first.st_ino and second.st_ino and first.st_ino != second.st_ino:
        return False
    return True


class _BoundedBuffer:
    def __init__(self, limit: int):
        self._limit = limit
        self._data = bytearray()
        self._truncated = False
        self._lock = threading.Lock()

    def append(self, chunk: bytes) -> None:
        if not chunk:
            return
        with self._lock:
            remaining = self._limit - len(self._data)
            if remaining > 0:
                self._data.extend(chunk[:remaining])
            if len(chunk) > remaining:
                self._truncated = True

    @property
    def truncated(self) -> bool:
        with self._lock:
            return self._truncated

    def text(self) -> str:
        with self._lock:
            return bytes(self._data).decode("utf-8", errors="replace")


class WorkspaceSnapshot:
    _EXCLUDED_DIR_NAMES = {
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".tox",
        ".nox",
    }
    _EXCLUDED_FILE_NAMES = {".env", ".coverage", "audit.jsonl"}
    _ALLOWED_GIT_TOP_LEVEL = {
        "HEAD",
        "index",
        "objects",
        "refs",
        "packed-refs",
        "shallow",
    }

    def __init__(
        self,
        source: Path,
        sandbox_root: Path,
        *,
        include_git: bool,
        max_files: int,
        max_bytes: int,
        max_change_entries: int,
    ):
        self.source = source.resolve()
        self.sandbox_root = sandbox_root.resolve()
        self.include_git = include_git
        self.max_files = max_files
        self.max_bytes = max_bytes
        self.max_change_entries = max_change_entries
        self.path: Path | None = None
        self._temp_dir: Path | None = None
        self._initial_manifest: dict[str, str] = {}
        self._file_count = 0
        self._byte_count = 0

    def __enter__(self) -> WorkspaceSnapshot:
        if not self.source.is_dir():
            raise SnapshotViolation("workspace source is not a directory")
        if self.sandbox_root == self.source or self.source in self.sandbox_root.parents:
            raise SnapshotViolation("sandbox root must be outside the workspace")
        self.sandbox_root.mkdir(parents=True, exist_ok=True)
        self._temp_dir = Path(
            tempfile.mkdtemp(prefix="task-", dir=str(self.sandbox_root))
        ).resolve()
        self.path = self._temp_dir / "workspace"
        self.path.mkdir()
        try:
            self._copy_directory(self.source, self.path, Path("."))
            self._initial_manifest = self._manifest(self.path)
        except Exception:
            self.cleanup()
            raise
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        if self._temp_dir is None:
            return
        shutil.rmtree(self._temp_dir, onerror=self._remove_readonly, ignore_errors=False)
        self._temp_dir = None
        self.path = None

    def changes(self) -> SnapshotChanges:
        if self.path is None:
            raise RuntimeError("snapshot is not active")
        current = self._manifest(self.path)
        initial_names = set(self._initial_manifest)
        current_names = set(current)
        added = sorted(current_names - initial_names)
        deleted = sorted(initial_names - current_names)
        modified = sorted(
            name
            for name in initial_names & current_names
            if self._initial_manifest[name] != current[name]
        )
        total = len(added) + len(modified) + len(deleted)
        truncated = total > self.max_change_entries
        return SnapshotChanges(
            added=added[: self.max_change_entries],
            modified=modified[: self.max_change_entries],
            deleted=deleted[: self.max_change_entries],
            truncated=truncated,
        )

    def _copy_directory(self, source: Path, destination: Path, relative: Path) -> None:
        with os.scandir(source) as iterator:
            entries = sorted(iterator, key=lambda item: item.name)
        for entry in entries:
            source_path = Path(entry.path)
            relative_path = relative / entry.name
            is_directory = entry.is_dir(follow_symlinks=False)

            if self._excluded(relative_path, is_directory):
                continue
            if relative_path == Path(".git") and self.include_git and not is_directory:
                raise SnapshotViolation("Git worktree metadata files are not supported")
            if entry.is_symlink():
                raise SnapshotViolation(f"symbolic links are not allowed: {relative_path}")
            if is_directory:
                target_dir = destination / entry.name
                target_dir.mkdir()
                self._copy_directory(source_path, target_dir, relative_path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise SnapshotViolation(f"special files are not allowed: {relative_path}")

            file_stat = source_path.stat(follow_symlinks=False)
            if not stat.S_ISREG(file_stat.st_mode):
                raise SnapshotViolation(f"non-regular file is not allowed: {relative_path}")
            self._file_count += 1
            if self._file_count > self.max_files:
                raise SnapshotViolation("workspace exceeds snapshot file limit")

            target_file = destination / entry.name
            copied = 0
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(source_path, flags)
            with os.fdopen(descriptor, "rb") as source_handle:
                opened_stat = os.fstat(source_handle.fileno())
                same_opened_file = (
                    _same_content_state(file_stat, opened_stat)
                    if os.name == "nt"
                    else _same_file_version(file_stat, opened_stat)
                )
                if not same_opened_file:
                    raise SnapshotViolation(
                        f"workspace changed while snapshotting: {relative_path}"
                    )
                with target_file.open("xb") as target_handle:
                    while chunk := source_handle.read(1024 * 1024):
                        copied += len(chunk)
                        self._byte_count += len(chunk)
                        if self._byte_count > self.max_bytes:
                            raise SnapshotViolation("workspace exceeds snapshot byte limit")
                        target_handle.write(chunk)
                opened_after_stat = os.fstat(source_handle.fileno())
            after_stat = source_path.stat(follow_symlinks=False)
            unchanged = (
                copied == opened_stat.st_size
                and _same_file_version(opened_stat, opened_after_stat)
                and _same_file_version(file_stat, after_stat)
            )
            if not unchanged:
                raise SnapshotViolation(f"workspace changed while snapshotting: {relative_path}")
            shutil.copystat(source_path, target_file, follow_symlinks=False)

        with os.scandir(source) as iterator:
            current_names = sorted(item.name for item in iterator)
        initial_names = sorted(entry.name for entry in entries)
        if current_names != initial_names:
            raise SnapshotViolation(f"workspace changed while snapshotting: {relative}")

    def _excluded(self, relative: Path, is_directory: bool) -> bool:
        parts = relative.parts
        name = relative.name
        if any(part in self._EXCLUDED_DIR_NAMES for part in parts):
            return True
        if not is_directory and name in self._EXCLUDED_FILE_NAMES:
            return True
        if not is_directory and name.startswith(".env.") and name not in {
            ".env.example",
            ".env.sample",
        }:
            return True
        if ".git" in parts and parts[0] != ".git":
            return True
        if parts and parts[0] == ".git":
            if not self.include_git:
                return True
            if len(parts) == 1:
                return False
            return parts[1] not in self._ALLOWED_GIT_TOP_LEVEL
        return False

    def _manifest(self, root: Path) -> dict[str, str]:
        manifest: dict[str, str] = {}
        counters = {"files": 0, "bytes": 0}
        self._manifest_directory(root, Path("."), manifest, counters)
        return manifest

    def _manifest_directory(
        self,
        directory: Path,
        relative: Path,
        manifest: dict[str, str],
        counters: dict[str, int],
    ) -> None:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda item: item.name)
        for entry in entries:
            relative_path = relative / entry.name
            if relative_path.parts and relative_path.parts[0] == ".git":
                continue
            if entry.is_symlink():
                raise SnapshotViolation(f"sandbox created a symbolic link: {relative_path}")
            if entry.is_dir(follow_symlinks=False):
                self._manifest_directory(Path(entry.path), relative_path, manifest, counters)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise SnapshotViolation(f"sandbox created a special file: {relative_path}")
            file_stat = entry.stat(follow_symlinks=False)
            counters["files"] += 1
            counters["bytes"] += file_stat.st_size
            if counters["files"] > self.max_files:
                raise SnapshotViolation("sandbox exceeds snapshot file limit")
            if counters["bytes"] > self.max_bytes:
                raise SnapshotViolation("sandbox exceeds snapshot byte limit")
            digest = hashlib.sha256()
            with Path(entry.path).open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
            manifest[relative_path.as_posix()] = digest.hexdigest()

    @staticmethod
    def _remove_readonly(function, path, exc_info) -> None:
        os.chmod(path, stat.S_IWRITE)
        function(path)


class DockerSandboxRunner:
    def __init__(
        self,
        image: str,
        sandbox_root: Path,
        limits: dict[str, object],
        *,
        process_runner: Callable[[list[str], int, int], ProcessOutput] | None = None,
        cleanup_runner: Callable[[str], None] | None = None,
    ):
        self.image = image
        self.sandbox_root = sandbox_root
        self.limits = limits
        self._process_runner = process_runner or run_bounded_process
        self._cleanup_runner = cleanup_runner or force_remove_container

    def run(
        self,
        workspace: Path,
        command: list[str],
        *,
        include_git: bool,
    ) -> dict[str, object]:
        timeout = int(self.limits.get("max_task_seconds", 120))
        memory_mb = int(self.limits.get("memory_mb", 1024))
        cpu_count = float(self.limits.get("cpu_count", 1))
        max_output = int(self.limits.get("max_output_bytes", 200_000))
        max_files = int(self.limits.get("max_snapshot_files", 50_000))
        max_bytes = int(self.limits.get("max_snapshot_bytes", 536_870_912))
        max_changes = int(self.limits.get("max_change_entries", 1_000))
        container_name = f"systeme-local-{uuid4().hex}"

        with WorkspaceSnapshot(
            workspace,
            self.sandbox_root,
            include_git=include_git,
            max_files=max_files,
            max_bytes=max_bytes,
            max_change_entries=max_changes,
        ) as snapshot:
            assert snapshot.path is not None
            snapshot_path = str(snapshot.path)
            if "," in snapshot_path:
                raise SnapshotViolation("sandbox path cannot contain a comma")
            docker_command = [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--pull",
                "never",
                "--init",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "256",
                "--cpus",
                str(cpu_count),
                "--memory",
                f"{memory_mb}m",
                "--memory-swap",
                f"{memory_mb}m",
                "--ulimit",
                "core=0:0",
                "--ulimit",
                "nofile=1024:1024",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=128m",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--user",
                prepare_sandbox_user(snapshot.path),
                "--mount",
                f"type=bind,source={snapshot_path},target=/workspace",
                "--workdir",
                "/workspace",
                self.image,
                *command,
            ]
            try:
                process = self._process_runner(docker_command, timeout, max_output)
            finally:
                self._cleanup_runner(container_name)

            if process.timed_out:
                raise TimeoutError(f"sandbox command exceeded {timeout} seconds")
            changes = snapshot.changes()
            return {
                "command": command,
                "returncode": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr,
                "truncated": process.truncated,
                "workspace_isolated": True,
                "workspace_changes": {
                    "added": changes.added,
                    "modified": changes.modified,
                    "deleted": changes.deleted,
                    "truncated": changes.truncated,
                },
            }


def prepare_sandbox_user(snapshot_path: Path) -> str:
    if os.name != "posix":
        return "10001:10001"
    uid = os.getuid()
    gid = os.getgid()
    if uid != 0:
        return f"{uid}:{gid}"

    uid = 65_532
    gid = 65_532
    for root, directories, files in os.walk(snapshot_path):
        os.chown(root, uid, gid)
        for name in directories:
            os.chown(Path(root) / name, uid, gid)
        for name in files:
            os.chown(Path(root) / name, uid, gid)
    return f"{uid}:{gid}"


def run_bounded_process(argv: list[str], timeout: int, max_output: int) -> ProcessOutput:
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("docker executable not found") from exc

    stdout_buffer = _BoundedBuffer(max_output)
    stderr_buffer = _BoundedBuffer(max_output)

    def drain(stream, buffer: _BoundedBuffer) -> None:
        try:
            while chunk := stream.read(64 * 1024):
                buffer.append(chunk)
        finally:
            stream.close()

    assert process.stdout is not None
    assert process.stderr is not None
    stdout_thread = threading.Thread(
        target=drain,
        args=(process.stdout, stdout_buffer),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain,
        args=(process.stderr, stderr_buffer),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        returncode = process.wait()
    finally:
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

    return ProcessOutput(
        returncode=returncode,
        stdout=stdout_buffer.text(),
        stderr=stderr_buffer.text(),
        truncated=stdout_buffer.truncated or stderr_buffer.truncated,
        timed_out=timed_out,
    )


def force_remove_container(container_name: str) -> None:
    try:
        subprocess.run(
            ["docker", "rm", "--force", container_name],
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return
