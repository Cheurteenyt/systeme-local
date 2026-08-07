from __future__ import annotations

import importlib
import os
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Mapping, NoReturn, Sequence

_GIT_EXECUTABLE_ENV: Final = "SLG_C9_GIT_EXECUTABLE"
_DEFAULT_TIMEOUT_SECONDS: Final = 15.0
_MAX_TIMEOUT_SECONDS: Final = 120.0
_DEFAULT_MAX_OUTPUT_BYTES: Final = 2 * 1024 * 1024
_MAX_OUTPUT_BYTES: Final = 16 * 1024 * 1024
_MAX_INPUT_BYTES: Final = 2 * 1024 * 1024
_READ_CHUNK_BYTES: Final = 64 * 1024
_ALLOWED_SUBCOMMANDS: Final = frozenset(
    {
        "cat-file",
        "diff",
        "ls-tree",
        "merge-base",
        "rev-parse",
        "status",
    }
)
_TRUSTED_WINDOWS_SIDS: Final = frozenset(
    {
        "S-1-5-18",  # LocalSystem
        "S-1-5-32-544",  # BUILTIN\Administrators
        # NT SERVICE\TrustedInstaller
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }
)


class C9GitError(ValueError):
    """Fail-closed C9 Git execution error."""


class C9GitCommandError(C9GitError):
    """A bounded Git child did not produce an explicitly accepted result."""

    def __init__(self, message: str, *, returncode: int | None = None) -> None:
        super().__init__(message)
        self.returncode = returncode


@dataclass(frozen=True)
class C9GitResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class _GitExecutableIdentity:
    device: int
    inode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


def _deny(message: str) -> NoReturn:
    raise C9GitError(message)


def _is_reparse(info: os.stat_result) -> bool:
    marker = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(info, "st_file_attributes", 0))
    return stat.S_ISLNK(info.st_mode) or bool(attributes & marker)


def _identity(info: os.stat_result) -> _GitExecutableIdentity:
    return _GitExecutableIdentity(
        device=int(info.st_dev),
        inode=int(info.st_ino),
        links=int(info.st_nlink),
        size=int(info.st_size),
        modified_ns=int(info.st_mtime_ns),
        changed_ns=int(info.st_ctime_ns),
    )


def _refuse_ambient_git_variables(environment: Mapping[str, str]) -> None:
    ambient = sorted(name for name in environment if name.upper().startswith("GIT_"))
    if ambient:
        _deny("C9 Git refuses ambient GIT_* variables")


def _windows_acl_is_trusted(path: Path, *, volume_root: bool) -> None:
    try:
        security: Any = importlib.import_module("win32security")
        rights: Any = importlib.import_module("ntsecuritycon")
        descriptor = security.GetNamedSecurityInfo(
            os.fspath(path),
            security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION,
        )
        owner = descriptor.GetSecurityDescriptorOwner()
        owner_text = security.ConvertSidToStringSid(owner)
        if owner_text not in _TRUSTED_WINDOWS_SIDS:
            _deny("C9 Git path owner is not a trusted Windows principal")
        acl = descriptor.GetSecurityDescriptorDacl()
        if acl is None:
            _deny("C9 Git path has a null Windows DACL")

        generic_write = int(getattr(rights, "GENERIC_WRITE", 0x40000000))
        generic_all = int(getattr(rights, "GENERIC_ALL", 0x10000000))
        takeover_rights = (
            int(getattr(rights, "DELETE", 0x00010000))
            | int(getattr(rights, "WRITE_DAC", 0x00040000))
            | int(getattr(rights, "WRITE_OWNER", 0x00080000))
            | int(getattr(rights, "FILE_DELETE_CHILD", 0x00000040))
            | generic_write
            | generic_all
        )
        content_write_rights = (
            int(getattr(rights, "FILE_WRITE_DATA", 0x00000002))
            | int(getattr(rights, "FILE_APPEND_DATA", 0x00000004))
            | int(getattr(rights, "FILE_WRITE_EA", 0x00000010))
            | int(getattr(rights, "FILE_WRITE_ATTRIBUTES", 0x00000100))
        )
        dangerous = takeover_rights
        if not volume_root:
            dangerous |= content_write_rights

        inherit_only = int(getattr(security, "INHERIT_ONLY_ACE", 0x08))
        allowed_types = {
            int(getattr(security, "ACCESS_ALLOWED_ACE_TYPE", 0)),
            int(getattr(security, "ACCESS_ALLOWED_OBJECT_ACE_TYPE", 5)),
        }
        for index in range(acl.GetAceCount()):
            ace = acl.GetAce(index)
            header = ace[0]
            ace_type = int(header[0])
            ace_flags = int(header[1])
            if ace_type not in allowed_types or ace_flags & inherit_only:
                continue
            mask = int(ace[1])
            sid = ace[-1]
            sid_text = security.ConvertSidToStringSid(sid)
            if sid_text not in _TRUSTED_WINDOWS_SIDS and mask & dangerous:
                _deny("C9 Git path is writable by an ordinary Windows principal")
    except C9GitError:
        raise
    except Exception as exc:
        raise C9GitError("C9 Git could not verify Windows path ACLs") from exc


def _assert_trusted_path_component(
    path: Path,
    *,
    executable: bool,
    volume_root: bool,
) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise C9GitError("C9 Git path component is unavailable") from exc
    if _is_reparse(info):
        _deny("C9 Git path cannot traverse a reparse point")
    if executable:
        if not stat.S_ISREG(info.st_mode) or int(info.st_nlink) != 1:
            _deny("C9 Git executable must be one singly-linked regular file")
    elif not stat.S_ISDIR(info.st_mode):
        _deny("C9 Git executable ancestor must be a directory")

    if os.name == "nt":
        _windows_acl_is_trusted(path, volume_root=volume_root)
    elif info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        _deny("C9 Git path cannot be group- or world-writable")
    return info


def _inspect_git_executable(path: Path) -> _GitExecutableIdentity:
    current = Path(path.anchor)
    parts = path.parts[1:]
    _assert_trusted_path_component(
        current,
        executable=False,
        volume_root=True,
    )
    for index, component in enumerate(parts):
        current /= component
        final = index == len(parts) - 1
        info = _assert_trusted_path_component(
            current,
            executable=final,
            volume_root=False,
        )
    if not parts:  # pragma: no cover - an executable cannot be a volume root
        _deny("C9 Git executable path is invalid")
    return _identity(info)


def resolve_c9_git_executable() -> Path:
    """Resolve and authenticate the exact Git executable selected by the operator."""

    _refuse_ambient_git_variables(os.environ)
    configured = os.environ.get(_GIT_EXECUTABLE_ENV)
    if configured is None or not configured:
        _deny("C9 Git requires an absolute SLG_C9_GIT_EXECUTABLE")
    if configured != configured.strip() or "\0" in configured:
        _deny("C9 Git executable path is not canonical")
    candidate = Path(configured)
    if (
        not candidate.is_absolute()
        or ".." in candidate.parts
        or candidate.name.casefold() != ("git.exe" if os.name == "nt" else "git")
    ):
        _deny("C9 Git executable path must identify absolute native Git")
    lexical = Path(os.path.abspath(os.fspath(candidate)))
    _inspect_git_executable(lexical)
    return lexical


def _closed_git_environment(executable: Path) -> dict[str, str]:
    environment = {
        name: value
        for name in ("SYSTEMROOT", "WINDIR", "COMSPEC")
        if (value := os.environ.get(name))
    }
    search = [os.fspath(executable.parent)]
    system_root = environment.get("SYSTEMROOT") or environment.get("WINDIR")
    if system_root:
        search.extend((os.path.join(system_root, "System32"), system_root))
    null_device = "NUL" if os.name == "nt" else os.devnull
    environment.update(
        {
            "PATH": os.pathsep.join(search),
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": null_device,
            "GIT_CONFIG_GLOBAL": null_device,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
        }
    )
    return environment


def _validate_git_arguments(arguments: Sequence[str]) -> tuple[str, ...]:
    if not arguments:
        _deny("C9 Git requires an explicit command")
    validated: list[str] = []
    for value in arguments:
        if not isinstance(value, str) or not value or "\0" in value:
            _deny("C9 Git arguments must be non-empty NUL-free strings")
        validated.append(value)
    if validated[0] not in _ALLOWED_SUBCOMMANDS:
        _deny("C9 Git subcommand is outside the read-only allowlist")
    if validated[0] == "diff":
        validated[1:1] = ["--no-ext-diff", "--no-textconv"]
    return tuple(validated)


def _bounded_pipe_reader(
    pipe: Any,
    *,
    output: bytearray,
    shared_count: list[int],
    maximum_bytes: int,
    lock: threading.Lock,
    overflow: threading.Event,
) -> None:
    try:
        while chunk := pipe.read(_READ_CHUNK_BYTES):
            with lock:
                remaining = maximum_bytes + 1 - shared_count[0]
                if remaining > 0:
                    output.extend(chunk[:remaining])
                shared_count[0] += len(chunk)
                if shared_count[0] > maximum_bytes:
                    overflow.set()
    finally:
        pipe.close()


def _bounded_stdin_writer(pipe: Any, content: bytes) -> None:
    try:
        pipe.write(content)
        pipe.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        pipe.close()


def run_c9_git(
    root: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    accepted_returncodes: tuple[int, ...] = (0,),
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    maximum_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
) -> C9GitResult:
    """Run one exact Git command with closed config, environment and resources."""

    _refuse_ambient_git_variables(os.environ)
    executable = resolve_c9_git_executable()
    before = _inspect_git_executable(executable)
    command_arguments = _validate_git_arguments(arguments)
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not 0 < float(timeout_seconds) <= _MAX_TIMEOUT_SECONDS
    ):
        _deny("C9 Git timeout is outside its bounded range")
    if (
        not isinstance(maximum_output_bytes, int)
        or isinstance(maximum_output_bytes, bool)
        or not 1 <= maximum_output_bytes <= _MAX_OUTPUT_BYTES
    ):
        _deny("C9 Git output limit is outside its bounded range")
    if input_bytes is not None and len(input_bytes) > _MAX_INPUT_BYTES:
        _deny("C9 Git input exceeds its byte boundary")
    if not accepted_returncodes or any(
        not isinstance(value, int) or isinstance(value, bool) for value in accepted_returncodes
    ):
        _deny("C9 Git accepted return codes are invalid")

    repository = Path(os.path.abspath(os.fspath(root)))
    if not repository.is_absolute():
        _deny("C9 Git working directory must be absolute")
    try:
        root_info = os.lstat(repository)
    except OSError as exc:
        raise C9GitError("C9 Git working directory is unavailable") from exc
    if not stat.S_ISDIR(root_info.st_mode) or _is_reparse(root_info):
        _deny("C9 Git working directory must be a non-reparse directory")

    null_device = "NUL" if os.name == "nt" else os.devnull
    command = (
        os.fspath(executable),
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={null_device}",
        "-c",
        "core.quotePath=false",
        "-c",
        "core.autocrlf=false",
        "-c",
        "credential.helper=",
        *command_arguments,
    )
    creation_flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        process = subprocess.Popen(
            command,
            cwd=repository,
            env=_closed_git_environment(executable),
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            creationflags=creation_flags,
        )
    except OSError as exc:
        raise C9GitCommandError("C9 Git process could not start") from exc
    assert process.stdout is not None
    assert process.stderr is not None

    stdout = bytearray()
    stderr = bytearray()
    shared_count = [0]
    lock = threading.Lock()
    overflow = threading.Event()
    readers = (
        threading.Thread(
            target=_bounded_pipe_reader,
            kwargs={
                "pipe": process.stdout,
                "output": stdout,
                "shared_count": shared_count,
                "maximum_bytes": maximum_output_bytes,
                "lock": lock,
                "overflow": overflow,
            },
            daemon=True,
        ),
        threading.Thread(
            target=_bounded_pipe_reader,
            kwargs={
                "pipe": process.stderr,
                "output": stderr,
                "shared_count": shared_count,
                "maximum_bytes": maximum_output_bytes,
                "lock": lock,
                "overflow": overflow,
            },
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()

    writer: threading.Thread | None = None
    if input_bytes is not None:
        assert process.stdin is not None
        writer = threading.Thread(
            target=_bounded_stdin_writer,
            args=(process.stdin, input_bytes),
            daemon=True,
        )
        writer.start()

    deadline = time.monotonic() + float(timeout_seconds)
    timed_out = False
    while process.poll() is None:
        if overflow.is_set():
            process.kill()
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            process.kill()
            break
        overflow.wait(min(0.05, remaining))
    try:
        returncode = process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - OS invariant
        process.kill()
        raise C9GitCommandError("C9 Git process did not terminate") from exc
    for reader in readers:
        reader.join(timeout=5)
    if writer is not None:
        writer.join(timeout=5)
    if any(reader.is_alive() for reader in readers) or (writer is not None and writer.is_alive()):
        raise C9GitCommandError("C9 Git pipe workers did not terminate")

    after = _inspect_git_executable(executable)
    if after != before:
        _deny("C9 Git executable identity changed during execution")
    if timed_out:
        raise C9GitCommandError("C9 Git command exceeded its timeout")
    if overflow.is_set() or shared_count[0] > maximum_output_bytes:
        raise C9GitCommandError("C9 Git output exceeded its byte boundary")
    if returncode not in accepted_returncodes:
        raise C9GitCommandError(
            "C9 Git command returned an unaccepted status",
            returncode=returncode,
        )
    return C9GitResult(
        returncode=returncode,
        stdout=bytes(stdout),
        stderr=bytes(stderr),
    )


def c9_git_bytes(root: Path, *arguments: str) -> bytes:
    return run_c9_git(root, *arguments).stdout


def c9_git_text(root: Path, *arguments: str) -> str:
    try:
        return (
            c9_git_bytes(root, *arguments)
            .decode(
                "utf-8",
                errors="strict",
            )
            .strip()
        )
    except UnicodeDecodeError as exc:
        raise C9GitError("C9 Git output is not strict UTF-8") from exc
