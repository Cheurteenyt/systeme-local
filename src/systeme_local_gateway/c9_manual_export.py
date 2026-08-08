from __future__ import annotations

import json
import os
import re
import secrets
import stat
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal, NoReturn, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .c9_attachment_security import C9AttachmentDescriptor
from .c9_private_state import (
    C9PrivatePermissions,
    C9PrivateStateError,
)
from .providers.attachment_commit import AttachmentInspectionError, inspect_attachment_bytes
from .providers.attachment_models import (
    AttachmentMediaType,
    normalize_utc_timestamp,
    validate_attachment_display_name,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_EXPORT_ID_PATTERN = r"^c9_export_[0-9a-f]{32}$"
_CLEANUP_ID_PATTERN = r"^c9_export_cleanup_[0-9a-f]{32}$"
_ORPHAN_RECEIPT_ID_PATTERN = r"^c9_orphan_cleanup_[0-9a-f]{32}$"
_EXPORT_DIRECTORY = re.compile(_EXPORT_ID_PATTERN)
_MAX_EXPORT_TTL = timedelta(minutes=10)
_MAX_ATTACHMENTS = 2
_READ_CHUNK_SIZE = 1024 * 1024
_CREATE_ATTEMPTS = 8

_T = TypeVar("_T", bound=BaseModel)


def _utc(value: datetime) -> datetime:
    return normalize_utc_timestamp(value)


def _canonical_sha256(domain: bytes, payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(domain + encoded).hexdigest()


def _model_digest(domain: bytes, model: BaseModel, digest_field: str) -> str:
    return _canonical_sha256(
        domain,
        model.model_dump(mode="json", exclude={digest_field}),
    )


def _commit_model(
    model_type: type[_T],
    *,
    payload: dict[str, object],
    digest_field: str,
    domain: bytes,
) -> _T:
    constructor_payload: Any = {**payload, digest_field: "0" * 64}
    draft = model_type.model_construct(**constructor_payload)
    committed = draft.model_copy(update={digest_field: _model_digest(domain, draft, digest_field)})
    return model_type.model_validate(committed.model_dump(mode="python"))


class C9ManualExportReason(StrEnum):
    INVALID_STATE_ROOT = "invalid_state_root"
    ROOT_IDENTITY_CHANGED = "root_identity_changed"
    UNSAFE_FILESYSTEM_OBJECT = "unsafe_filesystem_object"
    PRIVATE_PERMISSIONS_FAILED = "private_permissions_failed"
    INVALID_TTL = "invalid_ttl"
    INVALID_MANIFEST = "invalid_manifest"
    INVALID_ATTACHMENT_SET = "invalid_attachment_set"
    PAYLOAD_INTEGRITY_CHANGED = "payload_integrity_changed"
    EXPORT_COLLISION = "export_collision"
    EXPORT_NOT_FOUND = "export_not_found"
    EXPORT_EXPIRED = "export_expired"
    EXPORT_REPLAY = "export_replay"
    CLEANUP_FAILED = "cleanup_failed"
    MANAGER_CLOSED = "manager_closed"


class C9ManualExportError(ValueError):
    def __init__(self, reason: C9ManualExportReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _deny(reason: C9ManualExportReason, message: str) -> NoReturn:
    raise C9ManualExportError(reason, message)


class C9ManualCleanupReason(StrEnum):
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    INTEGRITY_REJECTED = "integrity_rejected"
    MANAGER_CLOSED = "manager_closed"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class C9ManualExportItem(_StrictModel):
    """Public metadata for one exact sanitized file; never includes bytes or a path."""

    version: Literal["1"] = "1"
    attachment_id: str = Field(pattern=r"^c9_attachment_[0-9a-f]{32}$")
    display_name: str = Field(min_length=1, max_length=240)
    media_type: AttachmentMediaType
    content_sha256: str = Field(pattern=_SHA256_PATTERN)
    byte_size: int = Field(ge=1)
    item_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("display_name")
    @classmethod
    def _safe_name(cls, value: str) -> str:
        return validate_attachment_display_name(value)

    @model_validator(mode="after")
    def _validate_digest(self) -> C9ManualExportItem:
        expected = _model_digest(
            b"systeme-local/c9/manual-export-item/v1\0",
            self,
            "item_sha256",
        )
        if self.item_sha256 != expected:
            raise ValueError("C9 manual export item digest mismatch")
        return self


class C9ManualExport(_StrictModel):
    """Metadata-only authority for one short-lived native Chat file-picker package."""

    version: Literal["1"] = "1"
    export_id: str = Field(pattern=_EXPORT_ID_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    items: tuple[C9ManualExportItem, ...] = Field(
        min_length=_MAX_ATTACHMENTS,
        max_length=_MAX_ATTACHMENTS,
    )
    attachment_count: Literal[2]
    total_byte_size: int = Field(ge=2)
    created_at: datetime
    expires_at: datetime
    export_sha256: str = Field(pattern=_SHA256_PATTERN)

    _created_utc = field_validator("created_at")(_utc)
    _expires_utc = field_validator("expires_at")(_utc)

    @model_validator(mode="after")
    def _validate_export(self) -> C9ManualExport:
        if not self.created_at < self.expires_at:
            raise ValueError("C9 manual export expiry must follow creation")
        if self.expires_at - self.created_at > _MAX_EXPORT_TTL:
            raise ValueError("C9 manual export exceeds the ten-minute TTL ceiling")
        if self.attachment_count != len(self.items):
            raise ValueError("C9 manual export attachment count mismatch")
        if len({item.attachment_id for item in self.items}) != len(self.items):
            raise ValueError("C9 manual export attachment ids must be unique")
        if len({item.display_name.casefold() for item in self.items}) != len(self.items):
            raise ValueError("C9 manual export display names must be unique")
        if self.total_byte_size != sum(item.byte_size for item in self.items):
            raise ValueError("C9 manual export byte total mismatch")
        expected = _model_digest(
            b"systeme-local/c9/manual-export/v1\0",
            self,
            "export_sha256",
        )
        if self.export_sha256 != expected:
            raise ValueError("C9 manual export digest mismatch")
        return self


class C9ManualCleanupReceipt(_StrictModel):
    """Metadata-only evidence that an export directory was removed."""

    version: Literal["1"] = "1"
    cleanup_id: str = Field(pattern=_CLEANUP_ID_PATTERN)
    export_id: str = Field(pattern=_EXPORT_ID_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    export_sha256: str = Field(pattern=_SHA256_PATTERN)
    item_content_sha256s: tuple[str, ...] = Field(
        min_length=_MAX_ATTACHMENTS,
        max_length=_MAX_ATTACHMENTS,
    )
    expected_byte_size_released: int = Field(ge=2)
    deleted_entry_count: int = Field(ge=0)
    reason: C9ManualCleanupReason
    picker_claimed: bool
    integrity_verified_before_delete: bool
    all_entries_removed: bool
    cleaned_at: datetime
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    _cleaned_utc = field_validator("cleaned_at")(_utc)

    @model_validator(mode="after")
    def _validate_receipt(self) -> C9ManualCleanupReceipt:
        expected = _model_digest(
            b"systeme-local/c9/manual-cleanup-receipt/v1\0",
            self,
            "receipt_sha256",
        )
        if self.receipt_sha256 != expected:
            raise ValueError("C9 manual cleanup receipt digest mismatch")
        return self


class C9OrphanCleanupReceipt(_StrictModel):
    """Startup evidence for an untrusted, metadata-less orphan directory."""

    version: Literal["1"] = "1"
    receipt_id: str = Field(pattern=_ORPHAN_RECEIPT_ID_PATTERN)
    export_id: str = Field(pattern=_EXPORT_ID_PATTERN)
    removed: bool
    integrity_verifiable: Literal[False] = False
    cleaned_at: datetime
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    _cleaned_utc = field_validator("cleaned_at")(_utc)

    @model_validator(mode="after")
    def _validate_receipt(self) -> C9OrphanCleanupReceipt:
        expected = _model_digest(
            b"systeme-local/c9/manual-orphan-cleanup/v1\0",
            self,
            "receipt_sha256",
        )
        if self.receipt_sha256 != expected:
            raise ValueError("C9 manual orphan cleanup receipt digest mismatch")
        return self


@dataclass(frozen=True)
class _DirectoryIdentity:
    device: int
    inode: int


@dataclass(frozen=True)
class _FileFingerprint:
    device: int
    inode: int
    byte_size: int
    modified_ns: int
    changed_ns: int
    links: int


@dataclass(frozen=True)
class _ExportFile:
    item: C9ManualExportItem
    fingerprint: _FileFingerprint


@dataclass
class _ExportRecord:
    public: C9ManualExport
    directory_identity: _DirectoryIdentity
    files: tuple[_ExportFile, ...]
    picker_claimed: bool = False


def _is_reparse(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = int(getattr(info, "st_file_attributes", 0))
    return bool(attributes & reparse_flag)


def _directory_identity(info: os.stat_result) -> _DirectoryIdentity:
    return _DirectoryIdentity(device=int(info.st_dev), inode=int(info.st_ino))


def _reject_reparse_chain(path: Path) -> None:
    current = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    for component in parts:
        current = current / component
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise C9ManualExportError(
                C9ManualExportReason.INVALID_STATE_ROOT,
                "C9 manual export parent is unavailable",
            ) from exc
        if _is_reparse(info):
            _deny(
                C9ManualExportReason.INVALID_STATE_ROOT,
                "C9 manual export rejects symlink or reparse traversal",
            )


def _file_fingerprint(info: os.stat_result) -> _FileFingerprint:
    return _FileFingerprint(
        device=int(info.st_dev),
        inode=int(info.st_ino),
        byte_size=int(info.st_size),
        modified_ns=int(info.st_mtime_ns),
        changed_ns=int(info.st_ctime_ns),
        links=int(info.st_nlink),
    )


def _same_open_file(path_info: os.stat_result, descriptor_info: os.stat_result) -> bool:
    return (
        int(path_info.st_dev) == int(descriptor_info.st_dev)
        and int(path_info.st_ino) == int(descriptor_info.st_ino)
        and int(path_info.st_size) == int(descriptor_info.st_size)
        and int(path_info.st_mtime_ns) == int(descriptor_info.st_mtime_ns)
        and int(path_info.st_nlink) == int(descriptor_info.st_nlink)
        and stat.S_ISREG(descriptor_info.st_mode)
    )


def _safe_name(value: str) -> str:
    try:
        name = validate_attachment_display_name(value)
    except ValueError as exc:
        raise C9ManualExportError(
            C9ManualExportReason.INVALID_ATTACHMENT_SET,
            "C9 manual export contains an unsafe display name",
        ) from exc
    if Path(name).name != name or os.path.basename(name) != name:
        _deny(
            C9ManualExportReason.INVALID_ATTACHMENT_SET,
            "C9 manual export display name escapes its export directory",
        )
    return name


def _path_is_within(candidate: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((os.path.normcase(str(candidate)), os.path.normcase(str(root))))
    except ValueError:
        return False
    return common == os.path.normcase(str(root))


def _remove_tree_without_following(path: Path, *, root: Path) -> int:
    """Remove one in-root tree without ever traversing a symlink/reparse point."""

    if not _path_is_within(path, root) or path == root:
        _deny(
            C9ManualExportReason.CLEANUP_FAILED,
            "C9 cleanup target escaped the configured export root",
        )
    _reject_reparse_chain(root)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return 0
    except OSError as exc:
        raise C9ManualExportError(
            C9ManualExportReason.CLEANUP_FAILED,
            "C9 cleanup target could not be inspected",
        ) from exc

    if _is_reparse(info):
        _reject_reparse_chain(root)
        current = os.lstat(path)
        if not _is_reparse(current) or _directory_identity(current) != (_directory_identity(info)):
            _deny(
                C9ManualExportReason.CLEANUP_FAILED,
                "C9 reparse cleanup target changed before removal",
            )
        try:
            if stat.S_ISDIR(info.st_mode):
                os.rmdir(path)
            else:
                os.unlink(path)
        except OSError:
            try:
                os.unlink(path)
            except OSError as exc:
                raise C9ManualExportError(
                    C9ManualExportReason.CLEANUP_FAILED,
                    "C9 reparse-point cleanup failed",
                ) from exc
        return 1

    if stat.S_ISDIR(info.st_mode):
        removed = 0
        try:
            entries = tuple(os.scandir(path))
        except OSError as exc:
            raise C9ManualExportError(
                C9ManualExportReason.CLEANUP_FAILED,
                "C9 export directory could not be enumerated safely",
            ) from exc
        for entry in entries:
            child = path / entry.name
            if not _path_is_within(child, root):
                _deny(
                    C9ManualExportReason.CLEANUP_FAILED,
                    "C9 cleanup entry escaped the configured export root",
                )
            removed += _remove_tree_without_following(child, root=root)
        _reject_reparse_chain(root)
        current = os.lstat(path)
        if (
            not stat.S_ISDIR(current.st_mode)
            or _is_reparse(current)
            or _directory_identity(current) != _directory_identity(info)
        ):
            _deny(
                C9ManualExportReason.CLEANUP_FAILED,
                "C9 export directory changed before removal",
            )
        try:
            os.rmdir(path)
        except OSError as exc:
            raise C9ManualExportError(
                C9ManualExportReason.CLEANUP_FAILED,
                "C9 export directory could not be removed",
            ) from exc
        return removed + 1

    _reject_reparse_chain(root)
    current = os.lstat(path)
    if (
        _is_reparse(current)
        or stat.S_IFMT(current.st_mode) != stat.S_IFMT(info.st_mode)
        or int(current.st_dev) != int(info.st_dev)
        or int(current.st_ino) != int(info.st_ino)
    ):
        _deny(
            C9ManualExportReason.CLEANUP_FAILED,
            "C9 export entry changed before removal",
        )
    try:
        os.unlink(path)
    except OSError as exc:
        raise C9ManualExportError(
            C9ManualExportReason.CLEANUP_FAILED,
            "C9 export entry could not be removed",
        ) from exc
    return 1


class C9ManualExportManager:
    """Materialize an approved sanitized image+text package for native Chat.

    Public models remain metadata-only. ``claim_paths`` is deliberately a
    process-local, at-most-once escape hatch for the trusted operator/UI adapter
    that drives the native file picker.
    """

    def __init__(
        self,
        state_root: str | os.PathLike[str],
        *,
        started_at: datetime | None = None,
        platform_name: str | None = None,
        private_permissions: C9PrivatePermissions | None = None,
    ) -> None:
        self._platform_name = os.name if platform_name is None else platform_name
        if self._platform_name not in {"nt", "posix"}:
            _deny(
                C9ManualExportReason.INVALID_STATE_ROOT,
                "C9 manual export platform is unsupported",
            )
        try:
            self._private_permissions = private_permissions or C9PrivatePermissions(
                platform_name=self._platform_name
            )
        except C9PrivateStateError as exc:
            raise C9ManualExportError(
                C9ManualExportReason.PRIVATE_PERMISSIONS_FAILED,
                "C9 private permission authority is unavailable",
            ) from exc
        if self._private_permissions.platform_name != self._platform_name:
            _deny(
                C9ManualExportReason.PRIVATE_PERMISSIONS_FAILED,
                "C9 private permission authority targets another platform",
            )
        self._lock = threading.RLock()
        self._records: dict[str, _ExportRecord] = {}
        self._terminal: dict[str, C9ManualCleanupReceipt] = {}
        self._closed = False

        raw_root = Path(os.fspath(state_root))
        if not raw_root.is_absolute() or ".." in raw_root.parts:
            _deny(
                C9ManualExportReason.INVALID_STATE_ROOT,
                "C9 manual export state root must be one absolute non-traversing path",
            )
        self._root = Path(os.path.abspath(raw_root))
        parent = self._root.parent
        self._reject_reparse_chain(parent)
        parent_info = os.lstat(parent)
        if not stat.S_ISDIR(parent_info.st_mode) or _is_reparse(parent_info):
            _deny(
                C9ManualExportReason.INVALID_STATE_ROOT,
                "C9 manual export parent is not a regular directory",
            )
        parent_identity = _directory_identity(parent_info)
        try:
            # CPython gives ``0o700`` special Windows ACL semantics that add
            # SYSTEM/Administrators/OWNER RIGHTS as explicit ACEs.  Create
            # with the ordinary inherited mode on Windows, then replace the
            # DACL and verify it below.
            root_mode = 0o777 if self._platform_name == "nt" else 0o700
            os.mkdir(self._root, mode=root_mode)
        except FileExistsError:
            pass
        except OSError as exc:
            raise C9ManualExportError(
                C9ManualExportReason.INVALID_STATE_ROOT,
                "C9 manual export state root could not be created",
            ) from exc
        if _directory_identity(os.lstat(parent)) != parent_identity:
            _deny(
                C9ManualExportReason.INVALID_STATE_ROOT,
                "C9 manual export parent identity changed during root creation",
            )
        self._reject_reparse_chain(self._root)
        root_info = os.lstat(self._root)
        if not stat.S_ISDIR(root_info.st_mode) or _is_reparse(root_info):
            _deny(
                C9ManualExportReason.INVALID_STATE_ROOT,
                "C9 manual export state root is not a private regular directory",
            )
        self._apply_private_permissions(self._root, directory=True)
        root_info = os.lstat(self._root)
        self._root_identity = _directory_identity(root_info)
        self._root_resolved = self._root.resolve(strict=True)
        self._startup_cleanup_receipts = self._cleanup_startup_orphans(
            _utc(started_at or datetime.now(timezone.utc))
        )

    @property
    def startup_cleanup_receipts(self) -> tuple[C9OrphanCleanupReceipt, ...]:
        return self._startup_cleanup_receipts

    def materialize(
        self,
        *,
        manifest_sha256: str,
        payloads: tuple[tuple[C9AttachmentDescriptor, memoryview | bytes], ...],
        created_at: datetime,
        ttl: timedelta = timedelta(minutes=5),
    ) -> C9ManualExport:
        """Atomically persist exactly one sanitized image and one UTF-8 text file."""

        with self._lock:
            self._require_open()
            self._verify_root()
            at = _utc(created_at)
            if not re.fullmatch(_SHA256_PATTERN, manifest_sha256):
                _deny(
                    C9ManualExportReason.INVALID_MANIFEST,
                    "C9 manual export requires one canonical manifest digest",
                )
            if ttl <= timedelta(0) or ttl > _MAX_EXPORT_TTL:
                _deny(
                    C9ManualExportReason.INVALID_TTL,
                    "C9 manual export TTL must be positive and at most ten minutes",
                )
            committed = self._validate_payloads(payloads, inspected_at=at)
            export_id, directory, directory_identity = self._create_export_directory()
            try:
                files: list[_ExportFile] = []
                items: list[C9ManualExportItem] = []
                for descriptor, content in committed:
                    item = _commit_model(
                        C9ManualExportItem,
                        payload={
                            "version": "1",
                            "attachment_id": descriptor.attachment_id,
                            "display_name": descriptor.display_name,
                            "media_type": descriptor.media_type,
                            "content_sha256": descriptor.sanitized_inspection.content_sha256,
                            "byte_size": descriptor.sanitized_inspection.byte_size,
                        },
                        digest_field="item_sha256",
                        domain=b"systeme-local/c9/manual-export-item/v1\0",
                    )
                    file_path = directory / item.display_name
                    fingerprint = self._atomic_write(
                        file_path,
                        content=content,
                        expected_directory=directory_identity,
                    )
                    items.append(item)
                    files.append(_ExportFile(item=item, fingerprint=fingerprint))
                public = _commit_model(
                    C9ManualExport,
                    payload={
                        "version": "1",
                        "export_id": export_id,
                        "manifest_sha256": manifest_sha256,
                        "items": tuple(items),
                        "attachment_count": _MAX_ATTACHMENTS,
                        "total_byte_size": sum(item.byte_size for item in items),
                        "created_at": at,
                        "expires_at": at + ttl,
                    },
                    digest_field="export_sha256",
                    domain=b"systeme-local/c9/manual-export/v1\0",
                )
                self._records[export_id] = _ExportRecord(
                    public=public,
                    directory_identity=directory_identity,
                    files=tuple(files),
                )
                return public
            except Exception:
                _remove_tree_without_following(directory, root=self._root)
                raise

    def claim_paths(
        self,
        export_id: str,
        *,
        claimed_at: datetime,
    ) -> tuple[Path, ...]:
        """Return file-picker paths exactly once after a full integrity recheck."""

        with self._lock:
            self._require_open()
            at = _utc(claimed_at)
            record = self._active_record(export_id, at)
            if record.picker_claimed:
                _deny(
                    C9ManualExportReason.EXPORT_REPLAY,
                    "C9 manual export picker paths were already claimed",
                )
            if not self._verify_record(record):
                self._cleanup_record(
                    record,
                    reason=C9ManualCleanupReason.INTEGRITY_REJECTED,
                    cleaned_at=at,
                    integrity_verified=False,
                )
                _deny(
                    C9ManualExportReason.PAYLOAD_INTEGRITY_CHANGED,
                    "C9 manual export changed before file-picker claim",
                )
            record.picker_claimed = True
            directory = self._root / record.public.export_id
            return tuple(directory / item.display_name for item in record.public.items)

    def cleanup(
        self,
        export_id: str,
        *,
        cleaned_at: datetime,
        reason: C9ManualCleanupReason = C9ManualCleanupReason.COMPLETED,
    ) -> C9ManualCleanupReceipt:
        """Verify then delete, recording ``integrity=false`` if content drifted."""

        with self._lock:
            self._require_open()
            at = _utc(cleaned_at)
            if export_id in self._terminal:
                _deny(
                    C9ManualExportReason.EXPORT_REPLAY,
                    "C9 manual export is already terminal",
                )
            record = self._records.get(export_id)
            if record is None:
                _deny(
                    C9ManualExportReason.EXPORT_NOT_FOUND,
                    "C9 manual export does not exist",
                )
            integrity_verified = self._verify_record(record)
            return self._cleanup_record(
                record,
                reason=reason,
                cleaned_at=at,
                integrity_verified=integrity_verified,
            )

    def expire(self, *, evaluated_at: datetime) -> tuple[C9ManualCleanupReceipt, ...]:
        with self._lock:
            self._require_open()
            at = _utc(evaluated_at)
            records = tuple(
                record for record in self._records.values() if at >= record.public.expires_at
            )
            return tuple(
                self._cleanup_record(
                    record,
                    reason=C9ManualCleanupReason.EXPIRED,
                    cleaned_at=at,
                    integrity_verified=self._verify_record(record),
                )
                for record in records
            )

    def cancel_all(
        self,
        *,
        cancelled_at: datetime,
        reason: C9ManualCleanupReason = C9ManualCleanupReason.CANCELLED,
    ) -> tuple[C9ManualCleanupReceipt, ...]:
        with self._lock:
            at = _utc(cancelled_at)
            records = tuple(self._records.values())
            return tuple(
                self._cleanup_record(
                    record,
                    reason=reason,
                    cleaned_at=at,
                    integrity_verified=self._verify_record(record),
                )
                for record in records
            )

    def close(self, *, closed_at: datetime) -> tuple[C9ManualCleanupReceipt, ...]:
        with self._lock:
            if self._closed:
                return ()
            receipts = self.cancel_all(
                cancelled_at=closed_at,
                reason=C9ManualCleanupReason.MANAGER_CLOSED,
            )
            self._closed = True
            return receipts

    def terminal_receipt(self, export_id: str) -> C9ManualCleanupReceipt | None:
        with self._lock:
            return self._terminal.get(export_id)

    def _validate_payloads(
        self,
        payloads: tuple[tuple[C9AttachmentDescriptor, memoryview | bytes], ...],
        *,
        inspected_at: datetime,
    ) -> tuple[tuple[C9AttachmentDescriptor, bytes], ...]:
        if len(payloads) != _MAX_ATTACHMENTS:
            _deny(
                C9ManualExportReason.INVALID_ATTACHMENT_SET,
                "C9 native Chat export requires exactly one image and one text document",
            )
        committed: list[tuple[C9AttachmentDescriptor, bytes]] = []
        for candidate, view in payloads:
            try:
                descriptor = C9AttachmentDescriptor.model_validate(
                    candidate.model_dump(mode="python")
                )
            except (AttributeError, ValueError) as exc:
                raise C9ManualExportError(
                    C9ManualExportReason.INVALID_ATTACHMENT_SET,
                    "C9 manual export descriptor integrity validation failed",
                ) from exc
            _safe_name(descriptor.display_name)
            content = bytes(view)
            expected = descriptor.sanitized_inspection
            if len(content) != expected.byte_size or sha256(content).hexdigest() != (
                expected.content_sha256
            ):
                _deny(
                    C9ManualExportReason.PAYLOAD_INTEGRITY_CHANGED,
                    "C9 sanitized export bytes do not match their descriptor",
                )
            try:
                inspection = inspect_attachment_bytes(
                    content=content,
                    media_type=descriptor.media_type,
                    inspected_at=inspected_at,
                )
            except AttachmentInspectionError as exc:
                raise C9ManualExportError(
                    C9ManualExportReason.PAYLOAD_INTEGRITY_CHANGED,
                    "C9 sanitized export bytes failed structural inspection",
                ) from exc
            if (
                inspection.content_sha256 != expected.content_sha256
                or inspection.byte_size != expected.byte_size
                or inspection.image_width != expected.image_width
                or inspection.image_height != expected.image_height
            ):
                _deny(
                    C9ManualExportReason.PAYLOAD_INTEGRITY_CHANGED,
                    "C9 sanitized export inspection changed",
                )
            if descriptor.media_type is AttachmentMediaType.TEXT:
                try:
                    content.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:  # pragma: no cover - upstream invariant
                    raise C9ManualExportError(
                        C9ManualExportReason.INVALID_ATTACHMENT_SET,
                        "C9 native Chat document is not strict UTF-8",
                    ) from exc
            committed.append((descriptor, content))

        media_types = tuple(descriptor.media_type for descriptor, _ in committed)
        images = sum(
            media_type in (AttachmentMediaType.PNG, AttachmentMediaType.JPEG)
            for media_type in media_types
        )
        if images != 1 or media_types.count(AttachmentMediaType.TEXT) != 1:
            _deny(
                C9ManualExportReason.INVALID_ATTACHMENT_SET,
                "C9 native Chat export requires exactly one PNG/JPEG and one UTF-8 text file",
            )
        names = tuple(descriptor.display_name.casefold() for descriptor, _ in committed)
        if len(set(names)) != len(names):
            _deny(
                C9ManualExportReason.INVALID_ATTACHMENT_SET,
                "C9 native Chat export display names collide",
            )
        return tuple(committed)

    def _create_export_directory(self) -> tuple[str, Path, _DirectoryIdentity]:
        for _ in range(_CREATE_ATTEMPTS):
            self._verify_root()
            export_id = f"c9_export_{secrets.token_hex(16)}"
            directory = self._root / export_id
            if not _path_is_within(directory, self._root):
                _deny(
                    C9ManualExportReason.INVALID_STATE_ROOT,
                    "C9 generated export directory escaped its root",
                )
            try:
                directory_mode = 0o777 if self._platform_name == "nt" else 0o700
                os.mkdir(directory, mode=directory_mode)
            except FileExistsError:
                continue
            except OSError as exc:
                raise C9ManualExportError(
                    C9ManualExportReason.UNSAFE_FILESYSTEM_OBJECT,
                    "C9 export directory could not be created atomically",
                ) from exc
            try:
                self._apply_private_permissions(directory, directory=True)
                info = os.lstat(directory)
            except Exception:
                _remove_tree_without_following(directory, root=self._root)
                raise
            if not stat.S_ISDIR(info.st_mode) or _is_reparse(info):
                _remove_tree_without_following(directory, root=self._root)
                _deny(
                    C9ManualExportReason.UNSAFE_FILESYSTEM_OBJECT,
                    "C9 export directory identity is unsafe",
                )
            return export_id, directory, _directory_identity(info)
        _deny(
            C9ManualExportReason.EXPORT_COLLISION,
            "C9 could not allocate a unique export directory",
        )

    def _atomic_write(
        self,
        path: Path,
        *,
        content: bytes,
        expected_directory: _DirectoryIdentity,
    ) -> _FileFingerprint:
        if not _path_is_within(path, self._root) or path.parent == self._root:
            _deny(
                C9ManualExportReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 export file escaped its dedicated directory",
            )
        self._verify_directory(path.parent, expected_directory)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise C9ManualExportError(
                C9ManualExportReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 export file could not be created atomically",
            ) from exc
        try:
            view = memoryview(content)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:  # pragma: no cover - OS contract
                    raise OSError("zero-length write")
                written += count
            os.fsync(descriptor)
        except OSError as exc:
            raise C9ManualExportError(
                C9ManualExportReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 export file write failed",
            ) from exc
        finally:
            os.close(descriptor)
        self._apply_private_permissions(path, directory=False)
        self._verify_directory(path.parent, expected_directory)
        info = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or _is_reparse(info)
            or int(info.st_nlink) != 1
            or int(info.st_size) != len(content)
        ):
            _deny(
                C9ManualExportReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 export file identity is unsafe after creation",
            )
        return _file_fingerprint(info)

    def _active_record(self, export_id: str, at: datetime) -> _ExportRecord:
        if export_id in self._terminal:
            _deny(
                C9ManualExportReason.EXPORT_REPLAY,
                "C9 manual export is already terminal",
            )
        record = self._records.get(export_id)
        if record is None:
            _deny(
                C9ManualExportReason.EXPORT_NOT_FOUND,
                "C9 manual export does not exist",
            )
        if at >= record.public.expires_at:
            self._cleanup_record(
                record,
                reason=C9ManualCleanupReason.EXPIRED,
                cleaned_at=at,
                integrity_verified=self._verify_record(record),
            )
            _deny(
                C9ManualExportReason.EXPORT_EXPIRED,
                "C9 manual export expired before file-picker claim",
            )
        return record

    def _verify_record(self, record: _ExportRecord) -> bool:
        try:
            self._verify_root()
            directory = self._root / record.public.export_id
            self._verify_directory(directory, record.directory_identity)
            expected_names = {item.item.display_name for item in record.files}
            observed_names = {entry.name for entry in os.scandir(directory)}
            if observed_names != expected_names:
                return False
            for file_record in record.files:
                path = directory / file_record.item.display_name
                if not self._verify_file(path, file_record):
                    return False
            return True
        except (C9ManualExportError, OSError):
            return False

    def _verify_file(self, path: Path, record: _ExportFile) -> bool:
        try:
            before = os.lstat(path)
        except OSError:
            return False
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_reparse(before)
            or int(before.st_nlink) != 1
            or _file_fingerprint(before) != record.fingerprint
        ):
            return False
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            return False
        digest = sha256()
        total = 0
        try:
            opened = os.fstat(descriptor)
            if not _same_open_file(before, opened):
                return False
            while True:
                chunk = os.read(descriptor, _READ_CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > record.item.byte_size:
                    return False
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        try:
            final = os.lstat(path)
        except OSError:
            return False
        return (
            _same_open_file(before, after)
            and _file_fingerprint(final) == record.fingerprint
            and total == record.item.byte_size
            and digest.hexdigest() == record.item.content_sha256
        )

    def _cleanup_record(
        self,
        record: _ExportRecord,
        *,
        reason: C9ManualCleanupReason,
        cleaned_at: datetime,
        integrity_verified: bool,
    ) -> C9ManualCleanupReceipt:
        self._verify_root()
        directory = self._root / record.public.export_id
        deleted_entry_count = _remove_tree_without_following(directory, root=self._root)
        all_removed = not os.path.lexists(directory)
        payload: dict[str, object] = {
            "version": "1",
            "cleanup_id": f"c9_export_cleanup_{secrets.token_hex(16)}",
            "export_id": record.public.export_id,
            "manifest_sha256": record.public.manifest_sha256,
            "export_sha256": record.public.export_sha256,
            "item_content_sha256s": tuple(item.content_sha256 for item in record.public.items),
            "expected_byte_size_released": record.public.total_byte_size,
            "deleted_entry_count": deleted_entry_count,
            "reason": reason,
            "picker_claimed": record.picker_claimed,
            "integrity_verified_before_delete": integrity_verified,
            "all_entries_removed": all_removed,
            "cleaned_at": cleaned_at,
        }
        receipt = _commit_model(
            C9ManualCleanupReceipt,
            payload=payload,
            digest_field="receipt_sha256",
            domain=b"systeme-local/c9/manual-cleanup-receipt/v1\0",
        )
        self._records.pop(record.public.export_id, None)
        self._terminal[record.public.export_id] = receipt
        return receipt

    def _cleanup_startup_orphans(
        self,
        cleaned_at: datetime,
    ) -> tuple[C9OrphanCleanupReceipt, ...]:
        self._verify_root()
        receipts: list[C9OrphanCleanupReceipt] = []
        try:
            entries = tuple(os.scandir(self._root))
        except OSError as exc:
            raise C9ManualExportError(
                C9ManualExportReason.INVALID_STATE_ROOT,
                "C9 manual export state root cannot be enumerated",
            ) from exc
        for entry in entries:
            if _EXPORT_DIRECTORY.fullmatch(entry.name) is None:
                continue
            path = self._root / entry.name
            try:
                info = os.lstat(path)
            except FileNotFoundError:
                continue
            if not (_is_reparse(info) or stat.S_ISDIR(info.st_mode)):
                continue
            _remove_tree_without_following(path, root=self._root)
            payload: dict[str, object] = {
                "version": "1",
                "receipt_id": f"c9_orphan_cleanup_{secrets.token_hex(16)}",
                "export_id": entry.name,
                "removed": not os.path.lexists(path),
                "integrity_verifiable": False,
                "cleaned_at": cleaned_at,
            }
            receipts.append(
                _commit_model(
                    C9OrphanCleanupReceipt,
                    payload=payload,
                    digest_field="receipt_sha256",
                    domain=b"systeme-local/c9/manual-orphan-cleanup/v1\0",
                )
            )
        return tuple(receipts)

    def _verify_root(self) -> None:
        self._reject_reparse_chain(self._root)
        try:
            info = os.lstat(self._root)
        except OSError as exc:
            raise C9ManualExportError(
                C9ManualExportReason.ROOT_IDENTITY_CHANGED,
                "C9 manual export root disappeared",
            ) from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or _is_reparse(info)
            or _directory_identity(info) != self._root_identity
            or self._root.resolve(strict=True) != self._root_resolved
        ):
            _deny(
                C9ManualExportReason.ROOT_IDENTITY_CHANGED,
                "C9 manual export root identity changed",
            )

    def _verify_directory(self, path: Path, expected: _DirectoryIdentity) -> None:
        self._verify_root()
        if not _path_is_within(path, self._root):
            _deny(
                C9ManualExportReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 export directory escaped its root",
            )
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise C9ManualExportError(
                C9ManualExportReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 export directory disappeared",
            ) from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or _is_reparse(info)
            or _directory_identity(info) != expected
        ):
            _deny(
                C9ManualExportReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 export directory identity changed",
            )

    def _reject_reparse_chain(self, path: Path) -> None:
        _reject_reparse_chain(path)

    def _apply_private_permissions(self, path: Path, *, directory: bool) -> None:
        try:
            self._private_permissions.apply_and_verify(
                path,
                directory=directory,
            )
        except C9PrivateStateError as exc:
            raise C9ManualExportError(
                C9ManualExportReason.PRIVATE_PERMISSIONS_FAILED,
                "C9 private export permissions could not be applied and verified",
            ) from exc

    def _require_open(self) -> None:
        if self._closed:
            _deny(
                C9ManualExportReason.MANAGER_CLOSED,
                "C9 manual export manager is closed",
            )
