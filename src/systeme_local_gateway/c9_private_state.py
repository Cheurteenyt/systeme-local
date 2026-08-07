from __future__ import annotations

import importlib
import os
import secrets
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, NoReturn, Protocol


class C9PrivateStateReason(StrEnum):
    PATH_NOT_ABSOLUTE = "path_not_absolute"
    PATH_TRAVERSAL = "path_traversal"
    PATH_OUTSIDE_STATE = "path_outside_state"
    PARENT_UNAVAILABLE = "parent_unavailable"
    REPARSE_PATH_REJECTED = "reparse_path_rejected"
    DIRECTORY_IDENTITY_CHANGED = "directory_identity_changed"
    UNSAFE_FILESYSTEM_OBJECT = "unsafe_filesystem_object"
    HARD_LINK_REJECTED = "hard_link_rejected"
    PRIVATE_PERMISSIONS_FAILED = "private_permissions_failed"
    ATOMIC_WRITE_FAILED = "atomic_write_failed"
    READ_FAILED = "read_failed"
    CLEANUP_FAILED = "cleanup_failed"


class C9PrivateStateError(ValueError):
    def __init__(self, reason: C9PrivateStateReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _deny(reason: C9PrivateStateReason, message: str) -> NoReturn:
    raise C9PrivateStateError(reason, message)


@dataclass(frozen=True)
class C9DirectoryIdentity:
    device: int
    inode: int


@dataclass(frozen=True)
class C9FileIdentity:
    device: int
    inode: int
    links: int
    size: int


class C9WindowsAclBackend(Protocol):
    """Injectable Windows ACL authority used by deterministic tests."""

    def apply_owner_only(self, path: Path, *, directory: bool) -> None: ...

    def is_owner_only(self, path: Path, *, directory: bool) -> bool: ...


class _PyWin32AclBackend:
    """Set and verify one protected DACL ACE for the effective token SID."""

    def __init__(self) -> None:
        try:
            self._api: Any = importlib.import_module("win32api")
            self._security: Any = importlib.import_module("win32security")
            self._rights: Any = importlib.import_module("ntsecuritycon")
            token = self._security.OpenProcessToken(
                self._api.GetCurrentProcess(),
                self._security.TOKEN_QUERY,
            )
            try:
                self._owner_sid = self._security.GetTokenInformation(
                    token,
                    self._security.TokenUser,
                )[0]
                self._owner_sid_text = self._security.ConvertSidToStringSid(self._owner_sid)
            finally:
                token.Close()
        except Exception as exc:
            raise C9PrivateStateError(
                C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED,
                "C9 could not obtain the effective Windows token SID",
            ) from exc

    def apply_owner_only(self, path: Path, *, directory: bool) -> None:
        try:
            existing = self._security.GetNamedSecurityInfo(
                str(path),
                self._security.SE_FILE_OBJECT,
                self._security.OWNER_SECURITY_INFORMATION,
            )
            existing_owner = existing.GetSecurityDescriptorOwner()
            owner_matches = (
                self._security.ConvertSidToStringSid(existing_owner) == self._owner_sid_text
            )
            acl = self._security.ACL()
            inheritance = 0
            if directory:
                inheritance = (
                    self._security.OBJECT_INHERIT_ACE | self._security.CONTAINER_INHERIT_ACE
                )
            acl.AddAccessAllowedAceEx(
                self._security.ACL_REVISION_DS,
                inheritance,
                self._rights.FILE_ALL_ACCESS,
                self._owner_sid,
            )
            security_information = (
                self._security.DACL_SECURITY_INFORMATION
                | self._security.PROTECTED_DACL_SECURITY_INFORMATION
            )
            if not owner_matches:
                security_information |= self._security.OWNER_SECURITY_INFORMATION
            self._security.SetNamedSecurityInfo(
                str(path),
                self._security.SE_FILE_OBJECT,
                security_information,
                self._owner_sid if not owner_matches else None,
                None,
                acl,
                None,
            )
        except Exception as exc:
            raise C9PrivateStateError(
                C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED,
                "C9 could not apply the private Windows owner DACL",
            ) from exc

    def is_owner_only(self, path: Path, *, directory: bool) -> bool:
        try:
            descriptor = self._security.GetNamedSecurityInfo(
                str(path),
                self._security.SE_FILE_OBJECT,
                self._security.OWNER_SECURITY_INFORMATION
                | self._security.DACL_SECURITY_INFORMATION,
            )
            owner = descriptor.GetSecurityDescriptorOwner()
            if self._security.ConvertSidToStringSid(owner) != self._owner_sid_text:
                return False
            control, _revision = descriptor.GetSecurityDescriptorControl()
            if not control & self._security.SE_DACL_PROTECTED:
                return False
            acl = descriptor.GetSecurityDescriptorDacl()
            if acl is None or acl.GetAceCount() != 1:
                return False
            header, mask, sid = acl.GetAce(0)
            ace_type, ace_flags = header
            expected_flags = (
                self._security.OBJECT_INHERIT_ACE | self._security.CONTAINER_INHERIT_ACE
                if directory
                else 0
            )
            return bool(
                ace_type == self._security.ACCESS_ALLOWED_ACE_TYPE
                and ace_flags == expected_flags
                and mask == self._rights.FILE_ALL_ACCESS
                and self._security.ConvertSidToStringSid(sid) == self._owner_sid_text
            )
        except Exception as exc:
            raise C9PrivateStateError(
                C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED,
                "C9 could not verify the private Windows owner DACL",
            ) from exc


class C9PrivatePermissions:
    """Apply and verify owner-only permissions without trusting environment identity."""

    def __init__(
        self,
        *,
        platform_name: str | None = None,
        windows_backend: C9WindowsAclBackend | None = None,
    ) -> None:
        self._platform_name = os.name if platform_name is None else platform_name
        if self._platform_name not in {"nt", "posix"}:
            raise C9PrivateStateError(
                C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED,
                "C9 private-state permissions do not support this platform",
            )
        self._windows_backend: C9WindowsAclBackend | None
        if self._platform_name == "nt":
            self._windows_backend = windows_backend or _PyWin32AclBackend()
        elif windows_backend is not None:
            raise ValueError("Windows ACL backend is only valid for platform nt")
        else:
            self._windows_backend = None

    @property
    def platform_name(self) -> str:
        return self._platform_name

    def apply_and_verify(self, path: Path, *, directory: bool) -> None:
        before = self._inspect_object(path, directory=directory)
        if not directory and int(before.st_nlink) != 1:
            _deny(
                C9PrivateStateReason.HARD_LINK_REJECTED,
                "C9 refuses to change permissions on a multiply-linked file",
            )
        if self._platform_name == "nt":
            assert self._windows_backend is not None
            self._windows_backend.apply_owner_only(path, directory=directory)
        else:
            try:
                os.chmod(
                    path,
                    0o700 if directory else 0o600,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise C9PrivateStateError(
                    C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED,
                    "C9 could not apply private POSIX permissions",
                ) from exc
        after = self._inspect_object(path, directory=directory)
        if (
            int(after.st_dev) != int(before.st_dev)
            or int(after.st_ino) != int(before.st_ino)
            or (not directory and int(after.st_nlink) != 1)
        ):
            _deny(
                C9PrivateStateReason.DIRECTORY_IDENTITY_CHANGED,
                "C9 private object identity changed while permissions were applied",
            )
        self.verify(path, directory=directory)

    def verify(self, path: Path, *, directory: bool) -> None:
        info = self._inspect_object(path, directory=directory)
        if not directory and int(info.st_nlink) != 1:
            _deny(
                C9PrivateStateReason.HARD_LINK_REJECTED,
                "C9 private file must be singly linked",
            )
        if self._platform_name == "nt":
            assert self._windows_backend is not None
            if not self._windows_backend.is_owner_only(path, directory=directory):
                _deny(
                    C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED,
                    "C9 Windows owner or DACL is not owner-only",
                )
            return
        expected = 0o700 if directory else 0o600
        effective_uid = getattr(os, "geteuid", lambda: int(info.st_uid))()
        if stat.S_IMODE(info.st_mode) != expected or int(info.st_uid) != effective_uid:
            _deny(
                C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED,
                "C9 POSIX owner or mode is not owner-only",
            )

    @staticmethod
    def _inspect_object(path: Path, *, directory: bool) -> os.stat_result:
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise C9PrivateStateError(
                C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED,
                "C9 private object is unavailable for permission verification",
            ) from exc
        expected_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not expected_type or is_c9_reparse_point(info):
            _deny(
                C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 permission target is not the expected non-reparse object",
            )
        return info


def is_c9_reparse_point(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    marker = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(info, "st_file_attributes", 0))
    return bool(attributes & marker)


def _directory_identity(info: os.stat_result) -> C9DirectoryIdentity:
    return C9DirectoryIdentity(device=int(info.st_dev), inode=int(info.st_ino))


def _file_identity(info: os.stat_result) -> C9FileIdentity:
    return C9FileIdentity(
        device=int(info.st_dev),
        inode=int(info.st_ino),
        links=int(info.st_nlink),
        size=int(info.st_size),
    )


def _file_read_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_nlink),
        int(info.st_size),
        int(info.st_mtime_ns),
    )


def lexical_c9_path(value: str | os.PathLike[str]) -> Path:
    raw = Path(os.fspath(value))
    if not raw.is_absolute():
        _deny(
            C9PrivateStateReason.PATH_NOT_ABSOLUTE,
            "C9 private-state paths must be explicit absolute paths",
        )
    if ".." in raw.parts:
        _deny(
            C9PrivateStateReason.PATH_TRAVERSAL,
            "C9 private-state paths reject lexical parent traversal",
        )
    return Path(os.path.abspath(raw))


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _path_within(candidate: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((os.path.normcase(str(candidate)), os.path.normcase(str(root))))
    except ValueError:
        return False
    return common == os.path.normcase(str(root))


def _path_components(path: Path) -> tuple[Path, ...]:
    anchor = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    current = anchor
    components: list[Path] = [anchor]
    for part in parts:
        current = current / part
        components.append(current)
    return tuple(components)


def reject_c9_reparse_prefix(
    path: str | os.PathLike[str],
    *,
    allow_missing_tail: bool,
) -> Path:
    """Inspect every existing lexical component with ``lstat``.

    Missing trailing components may be admitted for a later guarded creation,
    but an existing symlink, junction, mount-style reparse point, or non-directory
    parent is always rejected before any mutation.
    """

    lexical = lexical_c9_path(path)
    missing = False
    components = _path_components(lexical)
    for index, candidate in enumerate(components):
        if missing:
            continue
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            if not allow_missing_tail:
                raise C9PrivateStateError(
                    C9PrivateStateReason.PARENT_UNAVAILABLE,
                    "C9 private-state path is unavailable",
                )
            missing = True
            continue
        except OSError as exc:
            raise C9PrivateStateError(
                C9PrivateStateReason.PARENT_UNAVAILABLE,
                "C9 private-state path could not be inspected",
            ) from exc
        if is_c9_reparse_point(info):
            _deny(
                C9PrivateStateReason.REPARSE_PATH_REJECTED,
                "C9 private-state paths reject symlink, junction, or reparse traversal",
            )
        if index < len(components) - 1 and not stat.S_ISDIR(info.st_mode):
            _deny(
                C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 private-state parent is not a directory",
            )
    return lexical


def _inspect_directory(path: Path) -> tuple[os.stat_result, Path]:
    reject_c9_reparse_prefix(path, allow_missing_tail=False)
    try:
        info = os.lstat(path)
    except OSError as exc:  # pragma: no cover - prefix inspection already maps this
        raise C9PrivateStateError(
            C9PrivateStateReason.PARENT_UNAVAILABLE,
            "C9 private-state directory is unavailable",
        ) from exc
    if not stat.S_ISDIR(info.st_mode) or is_c9_reparse_point(info):
        _deny(
            C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
            "C9 private-state root must be a regular directory",
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise C9PrivateStateError(
            C9PrivateStateReason.PARENT_UNAVAILABLE,
            "C9 private-state directory could not be resolved after safe inspection",
        ) from exc
    return info, resolved


def _open_directory(path: Path, expected: C9DirectoryIdentity) -> int | None:
    if os.open not in os.supports_dir_fd:
        return None
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, flags)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or is_c9_reparse_point(info)
        or _directory_identity(info) != expected
    ):
        os.close(descriptor)
        _deny(
            C9PrivateStateReason.DIRECTORY_IDENTITY_CHANGED,
            "C9 private-state directory changed while opening",
        )
    return descriptor


def _mkdir_one(
    parent: Path,
    child: Path,
    expected_parent: C9DirectoryIdentity,
    *,
    permissions: C9PrivatePermissions,
    verify_parent_permissions: bool = True,
) -> None:
    if child.parent != parent:
        raise ValueError("C9 guarded mkdir requires one direct child")
    if verify_parent_permissions:
        permissions.verify(parent, directory=True)
    descriptor = _open_directory(parent, expected_parent)
    try:
        mode = 0o777 if permissions.platform_name == "nt" else 0o700
        if descriptor is not None and os.mkdir in os.supports_dir_fd:
            os.mkdir(child.name, mode=mode, dir_fd=descriptor)
        else:
            before = os.lstat(parent)
            if _directory_identity(before) != expected_parent:
                _deny(
                    C9PrivateStateReason.DIRECTORY_IDENTITY_CHANGED,
                    "C9 private-state parent changed before mkdir",
                )
            os.mkdir(child, mode=mode)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    after_parent, _ = _inspect_directory(parent)
    if _directory_identity(after_parent) != expected_parent:
        _deny(
            C9PrivateStateReason.DIRECTORY_IDENTITY_CHANGED,
            "C9 private-state parent changed during mkdir",
        )
    child_info, _ = _inspect_directory(child)
    if is_c9_reparse_point(child_info):
        _deny(
            C9PrivateStateReason.REPARSE_PATH_REJECTED,
            "C9 created directory became a reparse point",
        )
    permissions.apply_and_verify(child, directory=True)


def _ensure_directory_tree(
    base: Path,
    target: Path,
    *,
    permissions: C9PrivatePermissions,
) -> None:
    if not _path_within(target, base):
        _deny(
            C9PrivateStateReason.PATH_OUTSIDE_STATE,
            "C9 directory creation escaped its reviewed lexical root",
        )
    base_info, _ = _inspect_directory(base)
    permissions.verify(base, directory=True)
    current = base
    current_identity = _directory_identity(base_info)
    relative = target.relative_to(base)
    for component in relative.parts:
        child = current / component
        try:
            info = os.lstat(child)
        except FileNotFoundError:
            _mkdir_one(
                current,
                child,
                current_identity,
                permissions=permissions,
            )
            info = os.lstat(child)
        if not stat.S_ISDIR(info.st_mode) or is_c9_reparse_point(info):
            _deny(
                C9PrivateStateReason.REPARSE_PATH_REJECTED,
                "C9 directory tree contains a symlink, junction, or reparse point",
            )
        permissions.apply_and_verify(child, directory=True)
        current = child
        current_identity = _directory_identity(info)


def _secure_existing_tree(
    root: Path,
    *,
    permissions: C9PrivatePermissions,
) -> None:
    """Protect one existing C9 tree without following or mutating unsafe leaves."""

    root_info, _ = _inspect_directory(root)
    permissions.apply_and_verify(root, directory=True)
    expected_root = _directory_identity(root_info)
    pending = [root]
    while pending:
        directory = pending.pop()
        reject_c9_reparse_prefix(directory, allow_missing_tail=False)
        before_directory = os.lstat(directory)
        if not stat.S_ISDIR(before_directory.st_mode) or is_c9_reparse_point(before_directory):
            _deny(
                C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 private tree contains an unsafe directory",
            )
        permissions.apply_and_verify(directory, directory=True)
        try:
            entries = tuple(os.scandir(directory))
        except OSError as exc:
            raise C9PrivateStateError(
                C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED,
                "C9 private tree could not be enumerated safely",
            ) from exc
        for entry in entries:
            child = directory / entry.name
            try:
                current = os.lstat(child)
            except OSError as exc:
                raise C9PrivateStateError(
                    C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED,
                    "C9 private tree changed during permission hardening",
                ) from exc
            # ``DirEntry.stat`` reports zero device/inode values on CPython
            # Windows, so the authoritative no-follow inspection is lstat.
            if is_c9_reparse_point(current):
                _deny(
                    C9PrivateStateReason.REPARSE_PATH_REJECTED,
                    "C9 private tree changed or contains a reparse object",
                )
            if stat.S_ISDIR(current.st_mode):
                permissions.apply_and_verify(child, directory=True)
                pending.append(child)
            elif stat.S_ISREG(current.st_mode):
                if int(current.st_nlink) != 1:
                    _deny(
                        C9PrivateStateReason.HARD_LINK_REJECTED,
                        "C9 private tree contains a multiply-linked file",
                    )
                permissions.apply_and_verify(child, directory=False)
            else:
                _deny(
                    C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                    "C9 private tree contains an unsupported filesystem object",
                )
        after_directory = os.lstat(directory)
        if _directory_identity(after_directory) != _directory_identity(before_directory):
            _deny(
                C9PrivateStateReason.DIRECTORY_IDENTITY_CHANGED,
                "C9 private directory changed during permission hardening",
            )
    if _directory_identity(os.lstat(root)) != expected_root:
        _deny(
            C9PrivateStateReason.DIRECTORY_IDENTITY_CHANGED,
            "C9 private root changed during permission hardening",
        )


class C9PrivateStateGuard:
    """Pinned authority for all process-local C9 paths and admission metadata."""

    def __init__(
        self,
        *,
        permission_root: Path,
        lexical_root: Path,
        state_directory: Path,
        admission_file: Path,
        permissions: C9PrivatePermissions,
    ) -> None:
        self._permission_root = lexical_c9_path(permission_root)
        self._root = lexical_c9_path(lexical_root)
        self._state = lexical_c9_path(state_directory)
        self._admission = lexical_c9_path(admission_file)
        self._permissions = permissions
        if not _path_within(self._root, self._permission_root):
            _deny(
                C9PrivateStateReason.PATH_OUTSIDE_STATE,
                "C9 root escaped its private permission boundary",
            )
        if not _path_within(self._state, self._root):
            _deny(
                C9PrivateStateReason.PATH_OUTSIDE_STATE,
                "C9 configured state directory escaped .systeme-local/c9",
            )
        if not _path_within(self._admission, self._state):
            _deny(
                C9PrivateStateReason.PATH_OUTSIDE_STATE,
                "C9 admission file escaped the configured state directory",
            )
        if self._admission.parent != self._state:
            _deny(
                C9PrivateStateReason.PATH_OUTSIDE_STATE,
                "C9 admission file must be one direct child of the state directory",
            )
        _secure_existing_tree(self._root, permissions=self._permissions)
        permission_info, self._resolved_permission_root = _inspect_directory(self._permission_root)
        root_info, self._resolved_root = _inspect_directory(self._root)
        state_info, self._resolved_state = _inspect_directory(self._state)
        if not _path_within(
            self._resolved_root, self._resolved_permission_root
        ) or not _path_within(self._resolved_state, self._resolved_root):
            _deny(
                C9PrivateStateReason.PATH_OUTSIDE_STATE,
                "C9 resolved state directory escaped its lexical root",
            )
        self._permission_root_identity = _directory_identity(permission_info)
        self._root_identity = _directory_identity(root_info)
        self._state_identity = _directory_identity(state_info)
        relative_state = self._state.relative_to(self._permission_root)
        protected: list[tuple[Path, C9DirectoryIdentity, Path]] = []
        current = self._permission_root
        for component in ("", *relative_state.parts):
            if component:
                current /= component
            info, resolved = _inspect_directory(current)
            self._permissions.verify(current, directory=True)
            protected.append((current, _directory_identity(info), resolved))
        self._protected_directories = tuple(protected)
        self.validate_target(self._admission, allow_missing_leaf=True)

    @classmethod
    def initialize_layout(
        cls,
        *,
        provider_runtime_root: Path,
        state_directory: Path,
        admission_file: Path,
        permissions: C9PrivatePermissions | None = None,
    ) -> C9PrivateStateGuard:
        private_permissions = permissions or C9PrivatePermissions()
        provider = lexical_c9_path(provider_runtime_root)
        provider_info, _ = _inspect_directory(provider)
        systeme_local = provider / ".systeme-local"
        try:
            os.lstat(systeme_local)
        except FileNotFoundError:
            _mkdir_one(
                provider,
                systeme_local,
                _directory_identity(provider_info),
                permissions=private_permissions,
                verify_parent_permissions=False,
            )
        private_permissions.apply_and_verify(systeme_local, directory=True)
        systeme_info, _ = _inspect_directory(systeme_local)
        c9_root = systeme_local / "c9"
        try:
            os.lstat(c9_root)
        except FileNotFoundError:
            _mkdir_one(
                systeme_local,
                c9_root,
                _directory_identity(systeme_info),
                permissions=private_permissions,
            )
        private_permissions.apply_and_verify(c9_root, directory=True)
        configured_state = lexical_c9_path(state_directory)
        if not _path_within(configured_state, c9_root):
            _deny(
                C9PrivateStateReason.PATH_OUTSIDE_STATE,
                "C9 state directory must remain inside .systeme-local/c9",
            )
        _ensure_directory_tree(
            c9_root,
            configured_state,
            permissions=private_permissions,
        )
        _secure_existing_tree(c9_root, permissions=private_permissions)
        return cls(
            permission_root=systeme_local,
            lexical_root=c9_root,
            state_directory=configured_state,
            admission_file=admission_file,
            permissions=private_permissions,
        )

    @classmethod
    def for_existing_state(
        cls,
        *,
        state_directory: Path,
        admission_file: Path,
        permissions: C9PrivatePermissions | None = None,
    ) -> C9PrivateStateGuard:
        state = lexical_c9_path(state_directory)
        private_permissions = permissions or C9PrivatePermissions()
        _secure_existing_tree(state, permissions=private_permissions)
        return cls(
            permission_root=state,
            lexical_root=state,
            state_directory=state,
            admission_file=admission_file,
            permissions=private_permissions,
        )

    @property
    def lexical_root(self) -> Path:
        return self._root

    @property
    def state_directory(self) -> Path:
        return self._state

    @property
    def admission_file(self) -> Path:
        return self._admission

    def verify(self) -> None:
        permission_info, permission_resolved = _inspect_directory(self._permission_root)
        root_info, root_resolved = _inspect_directory(self._root)
        state_info, state_resolved = _inspect_directory(self._state)
        if (
            _directory_identity(permission_info) != self._permission_root_identity
            or _directory_identity(root_info) != self._root_identity
            or _directory_identity(state_info) != self._state_identity
            or not _same_path(
                permission_resolved,
                self._resolved_permission_root,
            )
            or not _same_path(root_resolved, self._resolved_root)
            or not _same_path(state_resolved, self._resolved_state)
            or not _path_within(root_resolved, permission_resolved)
            or not _path_within(state_resolved, root_resolved)
        ):
            _deny(
                C9PrivateStateReason.DIRECTORY_IDENTITY_CHANGED,
                "C9 private-state directory identity changed",
            )
        for path, expected_identity, expected_resolved in self._protected_directories:
            info, resolved = _inspect_directory(path)
            self._permissions.verify(path, directory=True)
            if _directory_identity(info) != expected_identity or not _same_path(
                resolved, expected_resolved
            ):
                _deny(
                    C9PrivateStateReason.DIRECTORY_IDENTITY_CHANGED,
                    "C9 protected directory identity changed",
                )

    def validate_target(self, path: Path, *, allow_missing_leaf: bool) -> Path:
        target = lexical_c9_path(path)
        if not _path_within(target, self._state) or target == self._state:
            _deny(
                C9PrivateStateReason.PATH_OUTSIDE_STATE,
                "C9 private-state target escaped its configured state directory",
            )
        self.verify()
        parent = target.parent
        reject_c9_reparse_prefix(parent, allow_missing_tail=False)
        parent_info, parent_resolved = _inspect_directory(parent)
        self._permissions.verify(parent, directory=True)
        if not _path_within(parent_resolved, self._resolved_state):
            _deny(
                C9PrivateStateReason.PATH_OUTSIDE_STATE,
                "C9 resolved target parent escaped its configured state directory",
            )
        if allow_missing_leaf:
            try:
                leaf = os.lstat(target)
            except FileNotFoundError:
                return target
            if is_c9_reparse_point(leaf):
                _deny(
                    C9PrivateStateReason.REPARSE_PATH_REJECTED,
                    "C9 private-state target is a symlink, junction, or reparse point",
                )
        else:
            reject_c9_reparse_prefix(target, allow_missing_tail=False)
        if _directory_identity(os.lstat(parent)) != _directory_identity(parent_info):
            _deny(
                C9PrivateStateReason.DIRECTORY_IDENTITY_CHANGED,
                "C9 target parent changed during validation",
            )
        return target

    def ensure_directory(self, path: Path) -> Path:
        target = lexical_c9_path(path)
        if not _path_within(target, self._state):
            _deny(
                C9PrivateStateReason.PATH_OUTSIDE_STATE,
                "C9 private directory escaped the configured state directory",
            )
        self.verify()
        _ensure_directory_tree(
            self._state,
            target,
            permissions=self._permissions,
        )
        self.verify()
        return target

    def exists_regular(self, path: Path) -> bool:
        target = self.validate_target(path, allow_missing_leaf=True)
        try:
            info = os.lstat(target)
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode) or is_c9_reparse_point(info) or int(info.st_nlink) != 1:
            _deny(
                C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 private-state file is not one singly-linked regular file",
            )
        self._permissions.verify(target, directory=False)
        return True

    def unlink_regular(self, path: Path, *, missing_ok: bool) -> bool:
        target = self.validate_target(path, allow_missing_leaf=True)
        try:
            before = os.lstat(target)
        except FileNotFoundError:
            if missing_ok:
                return False
            raise C9PrivateStateError(
                C9PrivateStateReason.CLEANUP_FAILED,
                "C9 private-state file is missing",
            )
        if is_c9_reparse_point(before) or not stat.S_ISREG(before.st_mode):
            _deny(
                C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 cleanup target is not a regular file",
            )
        if int(before.st_nlink) != 1:
            _deny(
                C9PrivateStateReason.HARD_LINK_REJECTED,
                "C9 cleanup refuses a multiply-linked file",
            )
        self._permissions.verify(target, directory=False)
        parent = target.parent
        parent_info = os.lstat(parent)
        expected_parent = _directory_identity(parent_info)
        self._permissions.verify(parent, directory=True)
        descriptor = _open_directory(parent, expected_parent)
        try:
            if descriptor is not None and os.unlink in os.supports_dir_fd:
                opened = os.open(
                    target.name,
                    os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0)),
                    dir_fd=descriptor,
                )
                try:
                    inspected = os.fstat(opened)
                    if (
                        _file_identity(inspected) != _file_identity(before)
                        or int(inspected.st_nlink) != 1
                    ):
                        _deny(
                            C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                            "C9 cleanup target changed while opening",
                        )
                finally:
                    os.close(opened)
                os.unlink(target.name, dir_fd=descriptor)
            else:
                flags = os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0))
                opened = os.open(target, flags)
                try:
                    inspected = os.fstat(opened)
                    current = os.lstat(target)
                    if _file_identity(inspected) != _file_identity(before) or _file_identity(
                        current
                    ) != _file_identity(before):
                        _deny(
                            C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                            "C9 cleanup target changed while opening",
                        )
                finally:
                    os.close(opened)
                os.unlink(target)
        except C9PrivateStateError:
            raise
        except OSError as exc:
            raise C9PrivateStateError(
                C9PrivateStateReason.CLEANUP_FAILED,
                "C9 private-state cleanup failed",
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        self.verify()
        try:
            os.lstat(target)
        except FileNotFoundError:
            return True
        _deny(
            C9PrivateStateReason.CLEANUP_FAILED,
            "C9 private-state file remains after cleanup",
        )

    def read_regular(self, path: Path, *, max_bytes: int) -> bytes:
        """Read one bounded private file through a pinned, no-follow identity."""

        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
            raise ValueError("C9 private read max_bytes must be a positive integer")
        target = self.validate_target(path, allow_missing_leaf=False)
        try:
            before = os.lstat(target)
        except OSError as exc:  # pragma: no cover - validate_target maps absence
            raise C9PrivateStateError(
                C9PrivateStateReason.READ_FAILED,
                "C9 private file is unavailable",
            ) from exc
        if is_c9_reparse_point(before) or not stat.S_ISREG(before.st_mode):
            _deny(
                C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 private read target is not a regular file",
            )
        if int(before.st_nlink) != 1:
            _deny(
                C9PrivateStateReason.HARD_LINK_REJECTED,
                "C9 private read refuses a multiply-linked file",
            )
        if int(before.st_size) > max_bytes:
            _deny(
                C9PrivateStateReason.READ_FAILED,
                "C9 private file exceeds its bounded read limit",
            )
        self._permissions.verify(target, directory=False)
        parent = target.parent
        parent_info = os.lstat(parent)
        expected_parent = _directory_identity(parent_info)
        self._permissions.verify(parent, directory=True)
        descriptor_directory = _open_directory(parent, expected_parent)
        descriptor_file: int | None = None
        try:
            flags = os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0))
            flags |= int(getattr(os, "O_BINARY", 0))
            if descriptor_directory is not None and os.open in os.supports_dir_fd:
                descriptor_file = os.open(
                    target.name,
                    flags,
                    dir_fd=descriptor_directory,
                )
            else:
                descriptor_file = os.open(target, flags)
            opened = os.fstat(descriptor_file)
            current = os.lstat(target)
            if (
                _file_read_identity(opened) != _file_read_identity(before)
                or _file_read_identity(current) != _file_read_identity(before)
                or is_c9_reparse_point(current)
                or not stat.S_ISREG(current.st_mode)
                or int(current.st_nlink) != 1
            ):
                _deny(
                    C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                    "C9 private file changed while opening",
                )
            chunks: list[bytes] = []
            observed = 0
            while True:
                chunk = os.read(
                    descriptor_file,
                    min(64 * 1024, max_bytes - observed + 1),
                )
                if not chunk:
                    break
                observed += len(chunk)
                if observed > max_bytes:
                    _deny(
                        C9PrivateStateReason.READ_FAILED,
                        "C9 private file grew beyond its bounded read limit",
                    )
                chunks.append(chunk)
            after_open = os.fstat(descriptor_file)
            after_path = os.lstat(target)
            expected = _file_read_identity(before)
            if (
                _file_read_identity(after_open) != expected
                or _file_read_identity(after_path) != expected
                or observed != int(before.st_size)
            ):
                _deny(
                    C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                    "C9 private file identity changed during read",
                )
            content = b"".join(chunks)
        except C9PrivateStateError:
            raise
        except OSError as exc:
            raise C9PrivateStateError(
                C9PrivateStateReason.READ_FAILED,
                "C9 private file read failed",
            ) from exc
        finally:
            if descriptor_file is not None:
                os.close(descriptor_file)
            if descriptor_directory is not None:
                os.close(descriptor_directory)
        self.verify()
        self._permissions.verify(target, directory=False)
        if _directory_identity(os.lstat(parent)) != expected_parent:
            _deny(
                C9PrivateStateReason.DIRECTORY_IDENTITY_CHANGED,
                "C9 private read parent changed during read",
            )
        return content

    def atomic_write(self, path: Path, content: bytes) -> None:
        target = self.validate_target(path, allow_missing_leaf=True)
        if not content:
            _deny(
                C9PrivateStateReason.ATOMIC_WRITE_FAILED,
                "C9 refuses an empty metadata commit",
            )
        try:
            os.lstat(target)
        except FileNotFoundError:
            pass
        else:
            _deny(
                C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 metadata target already exists",
            )
        parent = target.parent
        parent_info = os.lstat(parent)
        expected_parent = _directory_identity(parent_info)
        temporary_name = f".{target.name}.{secrets.token_hex(16)}.tmp"
        temporary = parent / temporary_name
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        flags |= int(getattr(os, "O_BINARY", 0))
        descriptor_directory = _open_directory(parent, expected_parent)
        descriptor_file: int | None = None
        committed_identity: C9FileIdentity | None = None
        try:
            if descriptor_directory is not None and os.open in os.supports_dir_fd:
                descriptor_file = os.open(
                    temporary_name,
                    flags,
                    0o600,
                    dir_fd=descriptor_directory,
                )
            else:
                descriptor_file = os.open(temporary, flags, 0o600)
            written = 0
            view = memoryview(content)
            while written < len(view):
                count = os.write(descriptor_file, view[written:])
                if count <= 0:  # pragma: no cover - OS invariant
                    raise OSError("short C9 metadata write")
                written += count
            os.fsync(descriptor_file)
            self._permissions.apply_and_verify(temporary, directory=False)
            info = os.fstat(descriptor_file)
            if (
                not stat.S_ISREG(info.st_mode)
                or is_c9_reparse_point(info)
                or int(info.st_nlink) != 1
                or int(info.st_size) != len(content)
            ):
                _deny(
                    C9PrivateStateReason.HARD_LINK_REJECTED,
                    "C9 temporary metadata file identity is unsafe",
                )
            committed_identity = _file_identity(info)
            os.close(descriptor_file)
            descriptor_file = None
            self.verify()
            try:
                os.lstat(target)
            except FileNotFoundError:
                pass
            else:
                _deny(
                    C9PrivateStateReason.UNSAFE_FILESYSTEM_OBJECT,
                    "C9 metadata target appeared before commit",
                )
            if descriptor_directory is not None and os.replace in os.supports_dir_fd:
                os.replace(
                    temporary_name,
                    target.name,
                    src_dir_fd=descriptor_directory,
                    dst_dir_fd=descriptor_directory,
                )
            else:
                current_parent = os.lstat(parent)
                if _directory_identity(current_parent) != expected_parent:
                    _deny(
                        C9PrivateStateReason.DIRECTORY_IDENTITY_CHANGED,
                        "C9 metadata parent changed before commit",
                    )
                os.replace(temporary, target)
            self.verify()
            committed = os.lstat(target)
            if (
                is_c9_reparse_point(committed)
                or not stat.S_ISREG(committed.st_mode)
                or int(committed.st_nlink) != 1
                or _file_identity(committed) != committed_identity
            ):
                _deny(
                    C9PrivateStateReason.ATOMIC_WRITE_FAILED,
                    "C9 committed metadata identity changed",
                )
            self._permissions.verify(target, directory=False)
        except C9PrivateStateError:
            raise
        except OSError as exc:
            raise C9PrivateStateError(
                C9PrivateStateReason.ATOMIC_WRITE_FAILED,
                "C9 metadata commit failed",
            ) from exc
        finally:
            if descriptor_file is not None:
                os.close(descriptor_file)
            if descriptor_directory is not None:
                try:
                    if os.unlink in os.supports_dir_fd:
                        os.unlink(temporary_name, dir_fd=descriptor_directory)
                    else:
                        self.unlink_regular(temporary, missing_ok=True)
                except (FileNotFoundError, C9PrivateStateError, OSError):
                    pass
                os.close(descriptor_directory)
            else:
                try:
                    self.unlink_regular(temporary, missing_ok=True)
                except C9PrivateStateError:
                    pass
