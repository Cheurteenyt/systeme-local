from __future__ import annotations

import json
import os
import re
import secrets
import stat
import threading
import time
import unicodedata
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Literal, NoReturn, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .providers.attachment_commit import (
    AttachmentInspectionError,
    commit_attachment,
    commit_attachment_manifest,
    inspect_attachment_bytes,
    verify_attachment_manifest,
)
from .providers.attachment_models import (
    AttachmentInspection,
    AttachmentManifest,
    AttachmentMediaType,
    AttachmentRole,
    AttachmentSource,
    normalize_utc_timestamp,
    validate_attachment_display_name,
)
from .providers.models import AgentPrincipalRef, CommittedTurn, commit_text_turn

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ATTACHMENT_ID_PATTERN = r"^c9_attachment_[0-9a-f]{32}$"
_LEASE_ID_PATTERN = r"^c9_lease_[0-9a-f]{64}$"
_MANIFEST_ID_PATTERN = r"^c9_manifest_[0-9a-f]{32}$"
_APPROVAL_ID_PATTERN = r"^c9_approval_[0-9a-f]{32}$"
_CLEANUP_ID_PATTERN = r"^c9_cleanup_[0-9a-f]{32}$"

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_SAFE_CRITICAL_CHUNKS = frozenset({b"IHDR", b"PLTE", b"IDAT", b"IEND"})
_PNG_SAFE_ANCILLARY_CHUNKS = frozenset({b"tRNS"})
_PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}

_T = TypeVar("_T")
_ModelT = TypeVar("_ModelT", bound=BaseModel)


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


class C9AttachmentSecurityReason(StrEnum):
    OPERATOR_CONFIRMATION_REQUIRED = "operator_confirmation_required"
    PATH_NOT_ABSOLUTE = "path_not_absolute"
    PATH_TRAVERSAL = "path_traversal"
    UNSAFE_FILESYSTEM_OBJECT = "unsafe_filesystem_object"
    REPARSE_POINT = "reparse_point"
    HARD_LINK = "hard_link"
    FILE_CHANGED = "file_changed"
    FILE_TOO_LARGE = "file_too_large"
    MEDIA_TYPE_UNSUPPORTED = "media_type_unsupported"
    MEDIA_TYPE_MISMATCH = "media_type_mismatch"
    IMAGE_LIMIT_EXCEEDED = "image_limit_exceeded"
    UNSAFE_PNG = "unsafe_png"
    UNSAFE_JPEG = "unsafe_jpeg"
    UNSAFE_PDF = "unsafe_pdf"
    UNSAFE_TEXT = "unsafe_text"
    INVALID_TTL = "invalid_ttl"
    LEASE_NOT_FOUND = "lease_not_found"
    LEASE_TERMINAL = "lease_terminal"
    LEASE_EXPIRED = "lease_expired"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_EXPIRED = "manifest_expired"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_EXPIRED = "approval_expired"
    PAYLOAD_INTEGRITY_CHANGED = "payload_integrity_changed"
    LOCAL_INSPECTION_FAILED = "local_inspection_failed"
    CONSUMER_FAILED = "consumer_failed"
    STORE_CLOSED = "store_closed"


class C9AttachmentSecurityError(ValueError):
    def __init__(self, reason: C9AttachmentSecurityReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _fail(reason: C9AttachmentSecurityReason, message: str) -> NoReturn:
    raise C9AttachmentSecurityError(reason, message)


class C9SanitizationAction(StrEnum):
    PNG_METADATA_STRIPPED = "png_metadata_stripped"
    JPEG_METADATA_STRIPPED = "jpeg_metadata_stripped"
    TEXT_NORMALIZED = "text_normalized"


class C9OutboundSurface(StrEnum):
    CHATGPT_WORK = "chatgpt_work"
    CHATGPT_CHAT = "chatgpt_chat"
    CHATGPT_CHAT_MANUAL = "chatgpt_chat_manual"
    CHATGPT_WORK_AND_CHAT_MANUAL = "chatgpt_work_and_chat_manual"


class C9LeaseTerminalState(StrEnum):
    CONSUMED = "consumed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    INTEGRITY_REJECTED = "integrity_rejected"
    CONSUMER_FAILED = "consumer_failed"


class C9AttachmentPolicy(BaseModel):
    """Fail-closed local policy for the first bounded C9 attachment handoff."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_image_bytes: int = Field(default=10 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)
    max_text_bytes: int = Field(default=1024 * 1024, ge=1, le=16 * 1024 * 1024)
    max_image_width: int = Field(default=8192, ge=1, le=100_000)
    max_image_height: int = Field(default=8192, ge=1, le=100_000)
    max_image_pixels: int = Field(default=33_554_432, ge=1, le=1_000_000_000)
    max_decoded_image_bytes: int = Field(
        default=64 * 1024 * 1024,
        ge=1,
        le=256 * 1024 * 1024,
    )
    max_png_chunks: int = Field(default=1024, ge=4, le=16_384)
    max_jpeg_segments: int = Field(default=512, ge=3, le=8192)
    max_text_lines: int = Field(default=100_000, ge=1, le=1_000_000)
    max_attachments_per_manifest: int = Field(default=2, ge=1, le=8)
    max_lease_seconds: int = Field(default=600, ge=1, le=3600)
    max_approval_seconds: int = Field(default=600, ge=1, le=900)


class C9AttachmentDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    attachment_id: str = Field(pattern=_ATTACHMENT_ID_PATTERN)
    display_name: str = Field(min_length=1, max_length=240)
    media_type: AttachmentMediaType
    source_content_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_byte_size: int = Field(ge=1)
    sanitized_inspection: AttachmentInspection
    sanitization_action: C9SanitizationAction
    metadata_removed: bool
    untrusted_content: Literal[True] = True
    selected_at: datetime
    descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)

    _selected_utc = field_validator("selected_at")(_utc)

    @field_validator("display_name")
    @classmethod
    def _safe_display_name(cls, value: str) -> str:
        return validate_attachment_display_name(value)

    @model_validator(mode="after")
    def _validate_descriptor(self) -> C9AttachmentDescriptor:
        if self.sanitized_inspection.media_type is not self.media_type:
            raise ValueError("C9 sanitized inspection media type mismatch")
        expected = _model_digest(
            b"systeme-local/c9/attachment-descriptor/v1\0",
            self,
            "descriptor_sha256",
        )
        if self.descriptor_sha256 != expected:
            raise ValueError("C9 attachment descriptor digest mismatch")
        return self


class C9AttachmentLease(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    lease_id: str = Field(pattern=_LEASE_ID_PATTERN)
    descriptor: C9AttachmentDescriptor
    created_at: datetime
    expires_at: datetime
    lease_sha256: str = Field(pattern=_SHA256_PATTERN)

    _created_utc = field_validator("created_at")(_utc)
    _expires_utc = field_validator("expires_at")(_utc)

    @model_validator(mode="after")
    def _validate_lease(self) -> C9AttachmentLease:
        if self.expires_at <= self.created_at:
            raise ValueError("C9 lease expiry must follow creation")
        expected = _model_digest(
            b"systeme-local/c9/attachment-lease/v1\0",
            self,
            "lease_sha256",
        )
        if self.lease_sha256 != expected:
            raise ValueError("C9 attachment lease digest mismatch")
        return self


class C9OutboundManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    manifest_id: str = Field(pattern=_MANIFEST_ID_PATTERN)
    surface: C9OutboundSurface
    purpose_sha256: str = Field(pattern=_SHA256_PATTERN)
    lease_ids: tuple[str, ...] = Field(min_length=1, max_length=8)
    attachments: tuple[C9AttachmentDescriptor, ...] = Field(min_length=1, max_length=8)
    attachment_manifest: AttachmentManifest
    attachment_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    attachment_count: int = Field(ge=1, le=8)
    total_sanitized_bytes: int = Field(ge=1)
    created_at: datetime
    expires_at: datetime
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)

    _created_utc = field_validator("created_at")(_utc)
    _expires_utc = field_validator("expires_at")(_utc)

    @model_validator(mode="after")
    def _validate_manifest(self) -> C9OutboundManifest:
        if self.expires_at <= self.created_at:
            raise ValueError("C9 outbound manifest expiry must follow creation")
        if self.attachment_count != len(self.attachments):
            raise ValueError("C9 outbound attachment count mismatch")
        if len(self.lease_ids) != len(self.attachments):
            raise ValueError("C9 outbound lease count mismatch")
        if len(set(self.lease_ids)) != len(self.lease_ids):
            raise ValueError("C9 outbound lease ids must be unique")
        if len({item.descriptor_sha256 for item in self.attachments}) != len(self.attachments):
            raise ValueError("C9 outbound descriptors must be unique")
        if self.attachment_manifest.manifest_id != self.manifest_id:
            raise ValueError("C9 outbound envelope must reuse the canonical manifest id")
        if self.attachment_manifest.manifest_sha256 != self.attachment_manifest_sha256:
            raise ValueError("C9 canonical attachment manifest digest mismatch")
        if self.attachment_manifest.attachment_count != self.attachment_count:
            raise ValueError("C9 canonical attachment manifest count mismatch")
        for descriptor, committed in zip(
            self.attachments,
            self.attachment_manifest.attachments,
            strict=True,
        ):
            inspection = descriptor.sanitized_inspection
            if (
                committed.attachment_id != descriptor.attachment_id
                or committed.display_name != descriptor.display_name
                or committed.source is not AttachmentSource.OPERATOR_SELECTED
                or committed.inspection.media_type is not descriptor.media_type
                or committed.inspection.content_sha256 != inspection.content_sha256
                or committed.inspection.byte_size != inspection.byte_size
                or committed.inspection.image_width != inspection.image_width
                or committed.inspection.image_height != inspection.image_height
            ):
                raise ValueError(
                    "C9 descriptors do not exactly bind the canonical attachment manifest"
                )
        if self.total_sanitized_bytes != sum(
            item.sanitized_inspection.byte_size for item in self.attachments
        ):
            raise ValueError("C9 outbound byte total mismatch")
        expected = _model_digest(
            b"systeme-local/c9/outbound-manifest/v1\0",
            self,
            "manifest_sha256",
        )
        if self.manifest_sha256 != expected:
            raise ValueError("C9 outbound manifest digest mismatch")
        return self


class C9BoundApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    approval_id: str = Field(pattern=_APPROVAL_ID_PATTERN)
    manifest_id: str = Field(pattern=_MANIFEST_ID_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    lease_ids: tuple[str, ...] = Field(min_length=1, max_length=8)
    operator_identity_sha256: str = Field(pattern=_SHA256_PATTERN)
    approved_at: datetime
    expires_at: datetime
    approval_sha256: str = Field(pattern=_SHA256_PATTERN)

    _approved_utc = field_validator("approved_at")(_utc)
    _expires_utc = field_validator("expires_at")(_utc)

    @model_validator(mode="after")
    def _validate_approval(self) -> C9BoundApproval:
        if self.expires_at <= self.approved_at:
            raise ValueError("C9 approval expiry must follow approval")
        if len(set(self.lease_ids)) != len(self.lease_ids):
            raise ValueError("C9 approved lease ids must be unique")
        expected = _model_digest(
            b"systeme-local/c9/bound-approval/v1\0",
            self,
            "approval_sha256",
        )
        if self.approval_sha256 != expected:
            raise ValueError("C9 bound approval digest mismatch")
        return self


class C9CleanupReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    cleanup_id: str = Field(pattern=_CLEANUP_ID_PATTERN)
    lease_id: str = Field(pattern=_LEASE_ID_PATTERN)
    descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)
    sanitized_content_sha256: str = Field(pattern=_SHA256_PATTERN)
    terminal_state: C9LeaseTerminalState
    byte_size_released: int = Field(ge=1)
    cleaned_at: datetime
    cleanup_sha256: str = Field(pattern=_SHA256_PATTERN)

    _cleaned_utc = field_validator("cleaned_at")(_utc)

    @model_validator(mode="after")
    def _validate_cleanup(self) -> C9CleanupReceipt:
        expected = _model_digest(
            b"systeme-local/c9/cleanup-receipt/v1\0",
            self,
            "cleanup_sha256",
        )
        if self.cleanup_sha256 != expected:
            raise ValueError("C9 cleanup receipt digest mismatch")
        return self


class C9ManifestConsumptionReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    manifest_id: str = Field(pattern=_MANIFEST_ID_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    approval_id: str = Field(pattern=_APPROVAL_ID_PATTERN)
    approval_sha256: str = Field(pattern=_SHA256_PATTERN)
    cleanup_receipts: tuple[C9CleanupReceipt, ...] = Field(min_length=1, max_length=8)
    consumed_at: datetime
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    _consumed_utc = field_validator("consumed_at")(_utc)

    @model_validator(mode="after")
    def _validate_consumption(self) -> C9ManifestConsumptionReceipt:
        if any(
            item.terminal_state is not C9LeaseTerminalState.CONSUMED
            for item in self.cleanup_receipts
        ):
            raise ValueError("C9 successful consumption requires consumed cleanup receipts")
        expected = _model_digest(
            b"systeme-local/c9/consumption-receipt/v1\0",
            self,
            "receipt_sha256",
        )
        if self.receipt_sha256 != expected:
            raise ValueError("C9 consumption receipt digest mismatch")
        return self


@dataclass(frozen=True)
class _FileFingerprint:
    device: int
    inode: int
    byte_size: int
    modified_ns: int
    changed_ns: int
    links: int


@dataclass
class _LeaseRecord:
    lease: C9AttachmentLease
    source_path: Path
    source_fingerprint: _FileFingerprint
    source_content_sha256: str
    sanitized_content: bytearray
    consuming: bool = False


def _fingerprint(info: os.stat_result) -> _FileFingerprint:
    return _FileFingerprint(
        device=int(info.st_dev),
        inode=int(info.st_ino),
        byte_size=int(info.st_size),
        modified_ns=int(info.st_mtime_ns),
        changed_ns=int(info.st_ctime_ns),
        links=int(info.st_nlink),
    )


def _same_open_identity(path_info: os.stat_result, descriptor_info: os.stat_result) -> bool:
    """Compare only fields with stable lstat/fstat semantics on Windows.

    CPython exposes Windows creation time as ``lstat().st_ctime_ns`` while an
    already-open descriptor may expose the last-write time in that field. The
    two calls still agree on volume/file identity, size, mtime and link count.
    Path-to-path comparisons continue to use the full fingerprint, including
    ctime, so a replacement between the two lstat calls is detected.
    """

    return (
        int(path_info.st_dev) == int(descriptor_info.st_dev)
        and int(path_info.st_ino) == int(descriptor_info.st_ino)
        and int(path_info.st_size) == int(descriptor_info.st_size)
        and int(path_info.st_mtime_ns) == int(descriptor_info.st_mtime_ns)
        and int(path_info.st_nlink) == int(descriptor_info.st_nlink)
        and stat.S_ISREG(descriptor_info.st_mode)
    )


def _is_reparse(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = int(getattr(info, "st_file_attributes", 0))
    return bool(attributes & reparse_flag)


def _safe_components(path: Path) -> None:
    if not path.is_absolute():
        _fail(
            C9AttachmentSecurityReason.PATH_NOT_ABSOLUTE,
            "C9 selection requires one exact absolute file path",
        )
    if ".." in path.parts:
        _fail(
            C9AttachmentSecurityReason.PATH_TRAVERSAL,
            "C9 selection rejects lexical parent traversal",
        )
    anchor = Path(path.anchor)
    current = anchor
    parts = path.parts[1:] if path.anchor else path.parts
    for component in parts:
        current = current / component
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise C9AttachmentSecurityError(
                C9AttachmentSecurityReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 selected filesystem object is unavailable",
            ) from exc
        if _is_reparse(info):
            _fail(
                C9AttachmentSecurityReason.REPARSE_POINT,
                "C9 selection rejects symlink or reparse-point traversal",
            )


def _read_exact_file(path: Path, *, maximum_bytes: int) -> tuple[bytes, _FileFingerprint]:
    _safe_components(path)
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        _fail(
            C9AttachmentSecurityReason.UNSAFE_FILESYSTEM_OBJECT,
            "C9 selection requires a regular file",
        )
    if before.st_nlink != 1:
        _fail(
            C9AttachmentSecurityReason.HARD_LINK,
            "C9 selection rejects multiply-linked files",
        )
    if before.st_size <= 0:
        _fail(
            C9AttachmentSecurityReason.UNSAFE_FILESYSTEM_OBJECT,
            "C9 selection requires a non-empty regular file",
        )
    if before.st_size > maximum_bytes:
        _fail(
            C9AttachmentSecurityReason.FILE_TOO_LARGE,
            "C9 selected file exceeds the bounded local policy",
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise C9AttachmentSecurityError(
            C9AttachmentSecurityReason.UNSAFE_FILESYSTEM_OBJECT,
            "C9 selected file could not be opened safely",
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if not _same_open_identity(before, opened):
            _fail(
                C9AttachmentSecurityReason.FILE_CHANGED,
                "C9 selected file identity changed while opening",
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                _fail(
                    C9AttachmentSecurityReason.FILE_TOO_LARGE,
                    "C9 selected file exceeds the bounded local policy",
                )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    _safe_components(path)
    final = os.lstat(path)
    expected = _fingerprint(before)
    if not _same_open_identity(before, after) or _fingerprint(final) != expected:
        _fail(
            C9AttachmentSecurityReason.FILE_CHANGED,
            "C9 selected file changed during bounded inspection",
        )
    return b"".join(chunks), expected


def _detect_media_type(path: Path, content: bytes) -> AttachmentMediaType:
    suffix = path.suffix.casefold()
    if content.startswith(_PNG_SIGNATURE):
        detected = AttachmentMediaType.PNG
        valid_suffixes = {".png"}
    elif content.startswith(b"\xff\xd8"):
        detected = AttachmentMediaType.JPEG
        valid_suffixes = {".jpg", ".jpeg"}
    elif re.match(rb"%PDF-(?:1\.[0-7]|2\.0)(?:\r\n|\r|\n)", content):
        _fail(
            C9AttachmentSecurityReason.MEDIA_TYPE_UNSUPPORTED,
            "C9 v1 refuses PDF because no safe PDF decoder/sanitizer is installed",
        )
    elif suffix == ".txt":
        detected = AttachmentMediaType.TEXT
        valid_suffixes = {".txt"}
    else:
        _fail(
            C9AttachmentSecurityReason.MEDIA_TYPE_UNSUPPORTED,
            "C9 selection is not a supported PNG, JPEG, PDF, or UTF-8 text file",
        )
    if suffix not in valid_suffixes:
        _fail(
            C9AttachmentSecurityReason.MEDIA_TYPE_MISMATCH,
            "C9 file extension does not match its inspected media type",
        )
    return detected


def _check_image_limits(inspection: AttachmentInspection, policy: C9AttachmentPolicy) -> None:
    width = inspection.image_width
    height = inspection.image_height
    if width is None or height is None:
        _fail(
            C9AttachmentSecurityReason.IMAGE_LIMIT_EXCEEDED,
            "C9 image inspection did not produce bounded dimensions",
        )
    if (
        width > policy.max_image_width
        or height > policy.max_image_height
        or width * height > policy.max_image_pixels
    ):
        _fail(
            C9AttachmentSecurityReason.IMAGE_LIMIT_EXCEEDED,
            "C9 image dimensions exceed the bounded local policy",
        )


def _sanitize_png(content: bytes, policy: C9AttachmentPolicy) -> tuple[bytes, bool]:
    try:
        inspection = inspect_attachment_bytes(
            content=content,
            media_type=AttachmentMediaType.PNG,
            inspected_at=datetime.now(UTC),
        )
    except AttachmentInspectionError as exc:
        raise C9AttachmentSecurityError(
            C9AttachmentSecurityReason.UNSAFE_PNG,
            "C9 PNG failed structural inspection",
        ) from exc
    _check_image_limits(inspection, policy)

    output = bytearray(_PNG_SIGNATURE)
    idat = bytearray()
    offset = len(_PNG_SIGNATURE)
    chunks = 0
    stripped = False
    saw_plte = False
    saw_trns = False
    saw_idat = False
    bit_depth = 0
    color_type = 0
    interlace = 0
    while offset < len(content):
        chunks += 1
        if chunks > policy.max_png_chunks:
            _fail(C9AttachmentSecurityReason.UNSAFE_PNG, "C9 PNG has too many chunks")
        length = int.from_bytes(content[offset : offset + 4], "big")
        chunk_type = content[offset + 4 : offset + 8]
        end = offset + 12 + length
        data = content[offset + 8 : offset + 8 + length]
        if chunk_type == b"IHDR":
            bit_depth = data[8]
            color_type = data[9]
            interlace = data[12]
            if interlace != 0:
                _fail(
                    C9AttachmentSecurityReason.UNSAFE_PNG,
                    "C9 PNG safe subset rejects interlaced images",
                )
        elif chunk_type == b"PLTE":
            if saw_plte or saw_idat:
                _fail(C9AttachmentSecurityReason.UNSAFE_PNG, "C9 PNG palette order is unsafe")
            saw_plte = True
        elif chunk_type == b"tRNS":
            if saw_trns or saw_idat:
                _fail(
                    C9AttachmentSecurityReason.UNSAFE_PNG,
                    "C9 PNG transparency order is unsafe",
                )
            saw_trns = True
        elif chunk_type == b"IDAT":
            saw_idat = True
            idat.extend(data)

        if chunk_type in _PNG_SAFE_CRITICAL_CHUNKS or chunk_type in _PNG_SAFE_ANCILLARY_CHUNKS:
            output.extend(content[offset:end])
        elif chunk_type and 65 <= chunk_type[0] <= 90:
            _fail(
                C9AttachmentSecurityReason.UNSAFE_PNG,
                "C9 PNG contains an unknown critical chunk",
            )
        else:
            stripped = True
        offset = end

    if color_type == 3 and not saw_plte:
        _fail(C9AttachmentSecurityReason.UNSAFE_PNG, "C9 indexed PNG requires a palette")
    channels = _PNG_CHANNELS[color_type]
    width = int(inspection.image_width or 0)
    height = int(inspection.image_height or 0)
    row_bytes = (width * channels * bit_depth + 7) // 8
    expected_size = height * (row_bytes + 1)
    if expected_size > policy.max_decoded_image_bytes:
        _fail(
            C9AttachmentSecurityReason.IMAGE_LIMIT_EXCEEDED,
            "C9 decoded PNG would exceed the bounded memory policy",
        )
    decompressor = zlib.decompressobj()
    try:
        inflated = decompressor.decompress(bytes(idat), expected_size + 1)
        if len(inflated) <= expected_size:
            inflated += decompressor.flush(expected_size + 1 - len(inflated))
    except zlib.error as exc:
        raise C9AttachmentSecurityError(
            C9AttachmentSecurityReason.UNSAFE_PNG,
            "C9 PNG compressed pixels are invalid",
        ) from exc
    if (
        len(inflated) != expected_size
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
    ):
        _fail(
            C9AttachmentSecurityReason.UNSAFE_PNG,
            "C9 PNG decompressed size does not match bounded dimensions",
        )
    if any(inflated[index * (row_bytes + 1)] > 4 for index in range(height)):
        _fail(C9AttachmentSecurityReason.UNSAFE_PNG, "C9 PNG contains an invalid row filter")
    return bytes(output), stripped


def _validate_dqt(payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        info = payload[offset]
        precision = info >> 4
        table_id = info & 0x0F
        if precision not in (0, 1) or table_id > 3:
            _fail(C9AttachmentSecurityReason.UNSAFE_JPEG, "C9 JPEG DQT is outside safe subset")
        table_size = 64 * (precision + 1)
        end = offset + 1 + table_size
        if end > len(payload) or not any(payload[offset + 1 : end]):
            _fail(C9AttachmentSecurityReason.UNSAFE_JPEG, "C9 JPEG DQT is malformed")
        offset = end


def _validate_dht(payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        if offset + 17 > len(payload):
            _fail(C9AttachmentSecurityReason.UNSAFE_JPEG, "C9 JPEG DHT is truncated")
        info = payload[offset]
        if info >> 4 not in (0, 1) or (info & 0x0F) > 3:
            _fail(C9AttachmentSecurityReason.UNSAFE_JPEG, "C9 JPEG DHT is outside safe subset")
        symbol_count = sum(payload[offset + 1 : offset + 17])
        end = offset + 17 + symbol_count
        if symbol_count == 0 or end > len(payload):
            _fail(C9AttachmentSecurityReason.UNSAFE_JPEG, "C9 JPEG DHT is malformed")
        offset = end


def _sanitize_jpeg(content: bytes, policy: C9AttachmentPolicy) -> tuple[bytes, bool]:
    try:
        inspection = inspect_attachment_bytes(
            content=content,
            media_type=AttachmentMediaType.JPEG,
            inspected_at=datetime.now(UTC),
        )
    except AttachmentInspectionError as exc:
        raise C9AttachmentSecurityError(
            C9AttachmentSecurityReason.UNSAFE_JPEG,
            "C9 JPEG failed structural inspection",
        ) from exc
    _check_image_limits(inspection, policy)

    output = bytearray(b"\xff\xd8")
    offset = 2
    segments = 0
    stripped = False
    saw_dqt = False
    saw_dht = False
    saw_sof = False
    while offset < len(content) - 2:
        segments += 1
        if segments > policy.max_jpeg_segments:
            _fail(C9AttachmentSecurityReason.UNSAFE_JPEG, "C9 JPEG has too many segments")
        if content[offset] != 0xFF:
            _fail(C9AttachmentSecurityReason.UNSAFE_JPEG, "C9 JPEG marker sequence is unsafe")
        marker_start = offset
        while offset < len(content) and content[offset] == 0xFF:
            offset += 1
        marker = content[offset]
        offset += 1
        if marker in range(0xD0, 0xD8) or marker in (0x00, 0x01, 0xD8, 0xD9):
            _fail(
                C9AttachmentSecurityReason.UNSAFE_JPEG,
                "C9 JPEG contains an unsafe pre-scan marker",
            )
        length = int.from_bytes(content[offset : offset + 2], "big")
        segment_end = offset + length
        payload = content[offset + 2 : segment_end]
        segment = content[marker_start:segment_end]

        if 0xE0 <= marker <= 0xEF or marker == 0xFE:
            stripped = True
        elif marker == 0xDB:
            _validate_dqt(payload)
            saw_dqt = True
            output.extend(segment)
        elif marker == 0xC4:
            _validate_dht(payload)
            saw_dht = True
            output.extend(segment)
        elif marker == 0xDD:
            if len(payload) != 2:
                _fail(C9AttachmentSecurityReason.UNSAFE_JPEG, "C9 JPEG DRI is malformed")
            output.extend(segment)
        elif marker == 0xC0:
            if saw_sof or len(payload) < 6 or payload[0] != 8 or payload[5] not in (1, 3, 4):
                _fail(
                    C9AttachmentSecurityReason.UNSAFE_JPEG,
                    "C9 JPEG requires one 8-bit baseline frame",
                )
            saw_sof = True
            output.extend(segment)
        elif marker == 0xDA:
            if not (saw_dqt and saw_dht and saw_sof):
                _fail(
                    C9AttachmentSecurityReason.UNSAFE_JPEG,
                    "C9 JPEG baseline tables or frame are missing",
                )
            if (
                len(payload) < 6
                or len(payload) != 1 + 2 * payload[0] + 3
                or payload[-3:] != b"\x00\x3f\x00"
            ):
                _fail(C9AttachmentSecurityReason.UNSAFE_JPEG, "C9 JPEG SOS is outside safe subset")
            output.extend(segment)
            scan_start = segment_end
            cursor = scan_start
            while cursor < len(content) - 1:
                if content[cursor] != 0xFF:
                    cursor += 1
                    continue
                next_byte = content[cursor + 1]
                if next_byte == 0x00 or 0xD0 <= next_byte <= 0xD7:
                    cursor += 2
                    continue
                if next_byte == 0xD9 and cursor + 2 == len(content):
                    if cursor == scan_start:
                        _fail(
                            C9AttachmentSecurityReason.UNSAFE_JPEG,
                            "C9 JPEG scan data is empty",
                        )
                    output.extend(content[scan_start:])
                    return bytes(output), stripped
                _fail(
                    C9AttachmentSecurityReason.UNSAFE_JPEG,
                    "C9 JPEG safe subset rejects multiple scans or embedded markers",
                )
            _fail(C9AttachmentSecurityReason.UNSAFE_JPEG, "C9 JPEG terminal marker is missing")
        else:
            _fail(
                C9AttachmentSecurityReason.UNSAFE_JPEG,
                "C9 JPEG segment is outside the baseline safe subset",
            )
        offset = segment_end
    _fail(C9AttachmentSecurityReason.UNSAFE_JPEG, "C9 JPEG start-of-scan is missing")


def _sanitize_text(content: bytes, policy: C9AttachmentPolicy) -> tuple[bytes, bool]:
    try:
        inspect_attachment_bytes(
            content=content,
            media_type=AttachmentMediaType.TEXT,
            inspected_at=datetime.now(UTC),
        )
        text = content.decode("utf-8", errors="strict")
    except (AttachmentInspectionError, UnicodeDecodeError) as exc:
        raise C9AttachmentSecurityError(
            C9AttachmentSecurityReason.UNSAFE_TEXT,
            "C9 text failed strict UTF-8 inspection",
        ) from exc
    normalized = text.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    normalized = unicodedata.normalize("NFC", normalized)
    if normalized.count("\n") + 1 > policy.max_text_lines:
        _fail(C9AttachmentSecurityReason.UNSAFE_TEXT, "C9 text exceeds the bounded line count")
    for character in normalized:
        if character in ("\n", "\t"):
            continue
        if unicodedata.category(character) in {"Cc", "Cf", "Cs", "Co"}:
            _fail(
                C9AttachmentSecurityReason.UNSAFE_TEXT,
                "C9 text contains control, format, surrogate, or private-use characters",
            )
    sanitized = normalized.encode("utf-8")
    if not sanitized:
        _fail(C9AttachmentSecurityReason.UNSAFE_TEXT, "C9 normalized text is empty")
    return sanitized, sanitized != content


def _sanitize(
    *,
    media_type: AttachmentMediaType,
    content: bytes,
    policy: C9AttachmentPolicy,
) -> tuple[bytes, C9SanitizationAction, bool]:
    if media_type is AttachmentMediaType.PNG:
        sanitized, removed = _sanitize_png(content, policy)
        return sanitized, C9SanitizationAction.PNG_METADATA_STRIPPED, removed
    if media_type is AttachmentMediaType.JPEG:
        sanitized, removed = _sanitize_jpeg(content, policy)
        return sanitized, C9SanitizationAction.JPEG_METADATA_STRIPPED, removed
    if media_type is AttachmentMediaType.PDF:
        _fail(
            C9AttachmentSecurityReason.MEDIA_TYPE_UNSUPPORTED,
            "C9 v1 refuses PDF because no safe PDF decoder/sanitizer is installed",
        )
    if media_type is AttachmentMediaType.TEXT:
        sanitized, removed = _sanitize_text(content, policy)
        return sanitized, C9SanitizationAction.TEXT_NORMALIZED, removed
    _fail(
        C9AttachmentSecurityReason.MEDIA_TYPE_UNSUPPORTED,
        "C9 policy supports only PNG, JPEG, PDF, and text",
    )


def _max_bytes(policy: C9AttachmentPolicy) -> int:
    return max(policy.max_image_bytes, policy.max_text_bytes)


def _media_max_bytes(media_type: AttachmentMediaType, policy: C9AttachmentPolicy) -> int:
    if media_type in (AttachmentMediaType.PNG, AttachmentMediaType.JPEG):
        return policy.max_image_bytes
    if media_type is AttachmentMediaType.TEXT:
        return policy.max_text_bytes
    return 0


def _active_ttl(ttl: timedelta, maximum_seconds: int) -> timedelta:
    if ttl <= timedelta(0) or ttl > timedelta(seconds=maximum_seconds):
        _fail(
            C9AttachmentSecurityReason.INVALID_TTL,
            "C9 expiry window is outside the bounded policy",
        )
    return ttl


def _revalidate(model_type: type[_ModelT], model: _ModelT) -> _ModelT:
    if not isinstance(model, BaseModel):
        raise TypeError("C9 integrity validation requires a Pydantic model")
    return model_type.model_validate(model.model_dump(mode="python"))


class C9AttachmentSecurity:
    """In-memory, at-most-once attachment authority.

    Raw source and sanitized bytes, plus the absolute selected path, remain only in
    private process memory. Every public model is metadata-only and digest-bound.
    """

    def __init__(self, policy: C9AttachmentPolicy | None = None) -> None:
        self.policy = policy or C9AttachmentPolicy()
        self._leases: dict[str, _LeaseRecord] = {}
        self._terminal: dict[str, C9CleanupReceipt] = {}
        self._manifest_purposes: dict[str, str] = {}
        self._lock = threading.RLock()
        self._closed = False

    def select_file(
        self,
        selected_path: str | os.PathLike[str],
        *,
        operator_confirmed: bool,
        selected_at: datetime,
        lease_ttl: timedelta = timedelta(minutes=5),
        declared_media_type: AttachmentMediaType | None = None,
    ) -> C9AttachmentLease:
        if not operator_confirmed:
            _fail(
                C9AttachmentSecurityReason.OPERATOR_CONFIRMATION_REQUIRED,
                "C9 requires explicit operator confirmation of the exact selected file",
            )
        self._require_open()
        at = _utc(selected_at)
        ttl = _active_ttl(lease_ttl, self.policy.max_lease_seconds)
        try:
            path = Path(os.fspath(selected_path))
        except TypeError as exc:
            raise C9AttachmentSecurityError(
                C9AttachmentSecurityReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 selected path has an unsupported representation",
            ) from exc
        content, fingerprint = _read_exact_file(path, maximum_bytes=_max_bytes(self.policy))
        media_type = _detect_media_type(path, content)
        if declared_media_type is not None and media_type is not declared_media_type:
            _fail(
                C9AttachmentSecurityReason.MEDIA_TYPE_MISMATCH,
                "C9 declared media type does not match inspected content",
            )
        if len(content) > _media_max_bytes(media_type, self.policy):
            _fail(
                C9AttachmentSecurityReason.FILE_TOO_LARGE,
                "C9 selected file exceeds its media-specific byte limit",
            )
        try:
            display_name = validate_attachment_display_name(path.name)
        except ValueError as exc:
            raise C9AttachmentSecurityError(
                C9AttachmentSecurityReason.UNSAFE_FILESYSTEM_OBJECT,
                "C9 selected file name is not safe for provider display",
            ) from exc
        sanitized, action, metadata_removed = _sanitize(
            media_type=media_type,
            content=content,
            policy=self.policy,
        )
        if len(sanitized) > _media_max_bytes(media_type, self.policy):
            _fail(
                C9AttachmentSecurityReason.FILE_TOO_LARGE,
                "C9 sanitized file exceeds its media-specific byte limit",
            )
        try:
            sanitized_inspection = inspect_attachment_bytes(
                content=sanitized,
                media_type=media_type,
                inspected_at=at,
            )
        except AttachmentInspectionError as exc:  # pragma: no cover - sanitizer invariant
            raise C9AttachmentSecurityError(
                C9AttachmentSecurityReason.PAYLOAD_INTEGRITY_CHANGED,
                "C9 sanitizer produced structurally invalid output",
            ) from exc
        if media_type in (AttachmentMediaType.PNG, AttachmentMediaType.JPEG):
            _check_image_limits(sanitized_inspection, self.policy)

        descriptor_payload = {
            "version": "1",
            "attachment_id": f"c9_attachment_{secrets.token_hex(16)}",
            "display_name": display_name,
            "media_type": media_type,
            "source_content_sha256": sha256(content).hexdigest(),
            "source_byte_size": len(content),
            "sanitized_inspection": sanitized_inspection,
            "sanitization_action": action,
            "metadata_removed": metadata_removed,
            "untrusted_content": True,
            "selected_at": at,
        }
        descriptor_draft = C9AttachmentDescriptor.model_construct(
            **descriptor_payload,  # type: ignore[arg-type]
            descriptor_sha256="0" * 64,
        )
        descriptor = descriptor_draft.model_copy(
            update={
                "descriptor_sha256": _model_digest(
                    b"systeme-local/c9/attachment-descriptor/v1\0",
                    descriptor_draft,
                    "descriptor_sha256",
                )
            }
        )
        descriptor = C9AttachmentDescriptor.model_validate(descriptor.model_dump(mode="python"))

        lease_payload = {
            "version": "1",
            "lease_id": f"c9_lease_{secrets.token_hex(32)}",
            "descriptor": descriptor,
            "created_at": at,
            "expires_at": at + ttl,
        }
        lease_draft = C9AttachmentLease.model_construct(
            **lease_payload,  # type: ignore[arg-type]
            lease_sha256="0" * 64,
        )
        lease = lease_draft.model_copy(
            update={
                "lease_sha256": _model_digest(
                    b"systeme-local/c9/attachment-lease/v1\0",
                    lease_draft,
                    "lease_sha256",
                )
            }
        )
        lease = C9AttachmentLease.model_validate(lease.model_dump(mode="python"))
        record = _LeaseRecord(
            lease=lease,
            source_path=path,
            source_fingerprint=fingerprint,
            source_content_sha256=descriptor.source_content_sha256,
            sanitized_content=bytearray(sanitized),
        )
        with self._lock:
            try:
                # File I/O and sanitization intentionally happen without the
                # authority lock. Revalidate the terminal state at the exact
                # mutation point so a concurrent close cannot resurrect a
                # lease or leave sanitized bytes owned by a closed store.
                self._require_open()
                self._leases[lease.lease_id] = record
            except Exception:
                record.sanitized_content[:] = b"\x00" * len(record.sanitized_content)
                raise
        return lease

    def create_outbound_manifest(
        self,
        lease_ids: tuple[str, ...],
        *,
        surface: C9OutboundSurface,
        purpose: str,
        created_at: datetime,
        committed_turn: CommittedTurn | None = None,
    ) -> C9OutboundManifest:
        self._require_open()
        at = _utc(created_at)
        if not purpose or len(purpose.encode("utf-8")) > 4096:
            _fail(
                C9AttachmentSecurityReason.MANIFEST_INVALID,
                "C9 outbound purpose must be non-empty and bounded",
            )
        if (
            not lease_ids
            or len(lease_ids) > self.policy.max_attachments_per_manifest
            or len(set(lease_ids)) != len(lease_ids)
        ):
            _fail(
                C9AttachmentSecurityReason.MANIFEST_INVALID,
                "C9 outbound manifest requires a bounded set of unique leases",
            )
        with self._lock:
            records = tuple(self._active_record(lease_id, at) for lease_id in lease_ids)
            descriptors = tuple(record.lease.descriptor for record in records)
            expires_at = min(record.lease.expires_at for record in records)
            manifest_id = f"c9_manifest_{secrets.token_hex(16)}"
            attachment_manifest = self._commit_canonical_attachment_manifest(
                records=records,
                manifest_id=manifest_id,
                purpose=purpose,
                committed_at=at,
                committed_turn=committed_turn,
            )
        payload = {
            "version": "1",
            "manifest_id": manifest_id,
            "surface": surface,
            "purpose_sha256": sha256(purpose.encode("utf-8")).hexdigest(),
            "lease_ids": lease_ids,
            "attachments": descriptors,
            "attachment_manifest": attachment_manifest,
            "attachment_manifest_sha256": attachment_manifest.manifest_sha256,
            "attachment_count": len(descriptors),
            "total_sanitized_bytes": sum(
                item.sanitized_inspection.byte_size for item in descriptors
            ),
            "created_at": at,
            "expires_at": expires_at,
        }
        draft = C9OutboundManifest.model_construct(
            **payload,  # type: ignore[arg-type]
            manifest_sha256="0" * 64,
        )
        manifest = draft.model_copy(
            update={
                "manifest_sha256": _model_digest(
                    b"systeme-local/c9/outbound-manifest/v1\0",
                    draft,
                    "manifest_sha256",
                )
            }
        )
        committed = C9OutboundManifest.model_validate(manifest.model_dump(mode="python"))
        with self._lock:
            # ``close`` may run while the immutable public manifest is being
            # hashed outside the first critical section.
            self._require_open()
            self._manifest_purposes[committed.manifest_id] = purpose
        return committed

    def approve_manifest(
        self,
        manifest: C9OutboundManifest,
        *,
        operator_confirmed: bool,
        operator_identity: str,
        approved_at: datetime,
        approval_ttl: timedelta = timedelta(minutes=2),
    ) -> C9BoundApproval:
        self._require_open()
        if not operator_confirmed:
            _fail(
                C9AttachmentSecurityReason.APPROVAL_REQUIRED,
                "C9 outbound transfer requires explicit combined operator approval",
            )
        at = _utc(approved_at)
        ttl = _active_ttl(approval_ttl, self.policy.max_approval_seconds)
        try:
            committed = _revalidate(C9OutboundManifest, manifest)
        except ValueError as exc:
            raise C9AttachmentSecurityError(
                C9AttachmentSecurityReason.MANIFEST_INVALID,
                "C9 outbound manifest integrity validation failed",
            ) from exc
        if not operator_identity or len(operator_identity.encode("utf-8")) > 1024:
            _fail(
                C9AttachmentSecurityReason.APPROVAL_INVALID,
                "C9 operator identity is missing or unbounded",
            )
        if not committed.created_at <= at < committed.expires_at:
            _fail(
                C9AttachmentSecurityReason.MANIFEST_EXPIRED,
                "C9 outbound manifest is not active",
            )
        with self._lock:
            for lease_id in committed.lease_ids:
                self._active_record(lease_id, at)
        expires_at = min(at + ttl, committed.expires_at)
        payload = {
            "version": "1",
            "approval_id": f"c9_approval_{secrets.token_hex(16)}",
            "manifest_id": committed.manifest_id,
            "manifest_sha256": committed.manifest_sha256,
            "lease_ids": committed.lease_ids,
            "operator_identity_sha256": sha256(operator_identity.encode("utf-8")).hexdigest(),
            "approved_at": at,
            "expires_at": expires_at,
        }
        draft = C9BoundApproval.model_construct(
            **payload,  # type: ignore[arg-type]
            approval_sha256="0" * 64,
        )
        approval = draft.model_copy(
            update={
                "approval_sha256": _model_digest(
                    b"systeme-local/c9/bound-approval/v1\0",
                    draft,
                    "approval_sha256",
                )
            }
        )
        return C9BoundApproval.model_validate(approval.model_dump(mode="python"))

    def inspect_manifest_payloads(
        self,
        manifest: C9OutboundManifest,
        *,
        inspected_at: datetime,
        inspector: Callable[
            [tuple[tuple[C9AttachmentDescriptor, memoryview], ...]],
            _T,
        ],
    ) -> _T:
        """Expose readonly in-memory views for local-AI inspection without consuming.

        The source and sanitized digests are checked both before and after the
        callback. Leases remain one-use and can subsequently be approved and
        consumed, but an expiry or mutation during inspection destroys them.
        """

        self._require_open()
        at = _utc(inspected_at)
        try:
            committed_manifest = _revalidate(C9OutboundManifest, manifest)
        except ValueError as exc:
            raise C9AttachmentSecurityError(
                C9AttachmentSecurityReason.MANIFEST_INVALID,
                "C9 local inspection manifest integrity validation failed",
            ) from exc
        if not committed_manifest.created_at <= at < committed_manifest.expires_at:
            _fail(
                C9AttachmentSecurityReason.MANIFEST_EXPIRED,
                "C9 local inspection manifest is not active",
            )
        with self._lock:
            records = tuple(
                self._active_record(lease_id, at) for lease_id in committed_manifest.lease_ids
            )
            if tuple(record.lease.descriptor for record in records) != (
                committed_manifest.attachments
            ):
                _fail(
                    C9AttachmentSecurityReason.MANIFEST_INVALID,
                    "C9 local inspection descriptors do not bind active leases",
                )
            try:
                for record in records:
                    self._verify_record(record, at)
            except C9AttachmentSecurityError:
                for record in records:
                    if record.lease.lease_id in self._leases:
                        self._cleanup(record, C9LeaseTerminalState.INTEGRITY_REJECTED, at)
                raise
            for record in records:
                record.consuming = True
            payloads = tuple(
                (record.lease.descriptor, memoryview(record.sanitized_content).toreadonly())
                for record in records
            )

        started = time.monotonic()
        try:
            result = inspector(payloads)
        except Exception as exc:
            with self._lock:
                for record in records:
                    if record.lease.lease_id in self._leases:
                        record.consuming = False
            raise C9AttachmentSecurityError(
                C9AttachmentSecurityReason.LOCAL_INSPECTION_FAILED,
                "C9 local readonly inspection failed",
            ) from exc
        finally:
            for _, view in payloads:
                view.release()

        completed_at = at + timedelta(seconds=max(0.0, time.monotonic() - started))
        with self._lock:
            for record in records:
                record.consuming = False
            if completed_at >= committed_manifest.expires_at:
                for record in records:
                    if record.lease.lease_id in self._leases:
                        self._cleanup(record, C9LeaseTerminalState.EXPIRED, completed_at)
                _fail(
                    C9AttachmentSecurityReason.MANIFEST_EXPIRED,
                    "C9 local inspection completed after manifest expiry",
                )
            try:
                for record in records:
                    self._verify_record(record, completed_at)
            except C9AttachmentSecurityError:
                for record in records:
                    if record.lease.lease_id in self._leases:
                        self._cleanup(
                            record,
                            C9LeaseTerminalState.INTEGRITY_REJECTED,
                            completed_at,
                        )
                raise
        return result

    def clone_manifest_leases(
        self,
        manifest: C9OutboundManifest,
        *,
        target_surface: C9OutboundSurface,
        cloned_at: datetime,
        lease_ttl: timedelta = timedelta(minutes=5),
    ) -> tuple[tuple[C9AttachmentLease, ...], C9OutboundManifest]:
        """Clone one approved package into independent one-use leases for another surface."""

        self._require_open()
        at = _utc(cloned_at)
        ttl = _active_ttl(lease_ttl, self.policy.max_lease_seconds)
        try:
            source_manifest = _revalidate(C9OutboundManifest, manifest)
        except ValueError as exc:
            raise C9AttachmentSecurityError(
                C9AttachmentSecurityReason.MANIFEST_INVALID,
                "C9 source manifest integrity validation failed",
            ) from exc
        with self._lock:
            purpose = self._manifest_purposes.get(source_manifest.manifest_id)
            if purpose is None:
                _fail(
                    C9AttachmentSecurityReason.MANIFEST_INVALID,
                    "C9 source manifest is not owned by this process authority",
                )
            records = tuple(
                self._active_record(lease_id, at) for lease_id in source_manifest.lease_ids
            )
            try:
                for record in records:
                    self._verify_record(record, at)
            except C9AttachmentSecurityError:
                for record in records:
                    if record.lease.lease_id in self._leases:
                        self._cleanup(record, C9LeaseTerminalState.INTEGRITY_REJECTED, at)
                raise
            expires_at = min(
                at + ttl,
                *(record.lease.expires_at for record in records),
            )
            clones: list[C9AttachmentLease] = []
            for record in records:
                payload = {
                    "version": "1",
                    "lease_id": f"c9_lease_{secrets.token_hex(32)}",
                    "descriptor": record.lease.descriptor,
                    "created_at": at,
                    "expires_at": expires_at,
                }
                draft = C9AttachmentLease.model_construct(
                    **payload,  # type: ignore[arg-type]
                    lease_sha256="0" * 64,
                )
                cloned = draft.model_copy(
                    update={
                        "lease_sha256": _model_digest(
                            b"systeme-local/c9/attachment-lease/v1\0",
                            draft,
                            "lease_sha256",
                        )
                    }
                )
                cloned = C9AttachmentLease.model_validate(cloned.model_dump(mode="python"))
                self._leases[cloned.lease_id] = _LeaseRecord(
                    lease=cloned,
                    source_path=record.source_path,
                    source_fingerprint=record.source_fingerprint,
                    source_content_sha256=record.source_content_sha256,
                    sanitized_content=bytearray(record.sanitized_content),
                )
                clones.append(cloned)
        clone_tuple = tuple(clones)
        try:
            cloned_manifest = self.create_outbound_manifest(
                tuple(item.lease_id for item in clone_tuple),
                surface=target_surface,
                purpose=purpose,
                created_at=at,
            )
        except Exception:
            with self._lock:
                for cloned in clone_tuple:
                    cloned_record = self._leases.get(cloned.lease_id)
                    if cloned_record is not None:
                        self._cleanup(
                            cloned_record,
                            C9LeaseTerminalState.CANCELLED,
                            at,
                        )
            raise
        if (
            cloned_manifest.attachments != source_manifest.attachments
            or cloned_manifest.purpose_sha256 != source_manifest.purpose_sha256
        ):  # pragma: no cover - construction invariant
            for cloned in clone_tuple:
                self.cancel_lease(cloned.lease_id, cancelled_at=at)
            _fail(
                C9AttachmentSecurityReason.MANIFEST_INVALID,
                "C9 cloned package identity diverged from its source",
            )
        return clone_tuple, cloned_manifest

    def consume_manifest(
        self,
        manifest: C9OutboundManifest,
        approval: C9BoundApproval,
        *,
        consumed_at: datetime,
        consumer: Callable[
            [tuple[tuple[C9AttachmentDescriptor, memoryview], ...]],
            _T,
        ],
    ) -> tuple[_T, C9ManifestConsumptionReceipt]:
        self._require_open()
        at = _utc(consumed_at)
        try:
            committed_manifest = _revalidate(C9OutboundManifest, manifest)
            committed_approval = _revalidate(C9BoundApproval, approval)
        except ValueError as exc:
            raise C9AttachmentSecurityError(
                C9AttachmentSecurityReason.APPROVAL_INVALID,
                "C9 manifest or approval integrity validation failed",
            ) from exc
        if at >= committed_manifest.expires_at:
            self._expire_specific(committed_manifest.lease_ids, at)
            _fail(
                C9AttachmentSecurityReason.MANIFEST_EXPIRED,
                "C9 outbound manifest expired before consumption",
            )
        if not committed_approval.approved_at <= at < committed_approval.expires_at:
            _fail(
                C9AttachmentSecurityReason.APPROVAL_EXPIRED,
                "C9 outbound approval is not active",
            )
        if (
            committed_approval.manifest_id != committed_manifest.manifest_id
            or committed_approval.manifest_sha256 != committed_manifest.manifest_sha256
            or committed_approval.lease_ids != committed_manifest.lease_ids
        ):
            _fail(
                C9AttachmentSecurityReason.APPROVAL_INVALID,
                "C9 outbound approval does not bind the exact manifest",
            )

        with self._lock:
            records = tuple(
                self._active_record(lease_id, at) for lease_id in committed_manifest.lease_ids
            )
            if tuple(record.lease.descriptor for record in records) != (
                committed_manifest.attachments
            ):
                _fail(
                    C9AttachmentSecurityReason.MANIFEST_INVALID,
                    "C9 outbound manifest descriptors do not bind active leases",
                )
            try:
                for record in records:
                    self._verify_record(record, at)
            except C9AttachmentSecurityError:
                for record in records:
                    if record.lease.lease_id in self._leases:
                        self._cleanup(record, C9LeaseTerminalState.INTEGRITY_REJECTED, at)
                raise
            for record in records:
                record.consuming = True
            payloads = tuple(
                (record.lease.descriptor, memoryview(record.sanitized_content).toreadonly())
                for record in records
            )

        started = time.monotonic()
        try:
            result = consumer(payloads)
        except Exception as exc:
            failed_at = at + timedelta(seconds=max(0.0, time.monotonic() - started))
            with self._lock:
                for record in records:
                    if record.lease.lease_id in self._leases:
                        self._cleanup(
                            record,
                            C9LeaseTerminalState.CONSUMER_FAILED,
                            failed_at,
                        )
            raise C9AttachmentSecurityError(
                C9AttachmentSecurityReason.CONSUMER_FAILED,
                "C9 outbound consumer failed; every lease was destroyed",
            ) from exc
        finally:
            for _, view in payloads:
                view.release()

        completed_at = at + timedelta(seconds=max(0.0, time.monotonic() - started))
        with self._lock:
            if (
                completed_at >= committed_manifest.expires_at
                or completed_at >= committed_approval.expires_at
            ):
                for record in records:
                    if record.lease.lease_id in self._leases:
                        self._cleanup(record, C9LeaseTerminalState.EXPIRED, completed_at)
                _fail(
                    (
                        C9AttachmentSecurityReason.MANIFEST_EXPIRED
                        if completed_at >= committed_manifest.expires_at
                        else C9AttachmentSecurityReason.APPROVAL_EXPIRED
                    ),
                    "C9 outbound authority expired while the consumer was running",
                )
            try:
                for record in records:
                    record.consuming = False
                    self._verify_record(record, completed_at)
            except C9AttachmentSecurityError:
                for record in records:
                    if record.lease.lease_id in self._leases:
                        self._cleanup(
                            record,
                            C9LeaseTerminalState.INTEGRITY_REJECTED,
                            completed_at,
                        )
                raise
            cleanups = tuple(
                self._cleanup(record, C9LeaseTerminalState.CONSUMED, completed_at)
                for record in records
            )
        receipt_payload = {
            "version": "1",
            "manifest_id": committed_manifest.manifest_id,
            "manifest_sha256": committed_manifest.manifest_sha256,
            "approval_id": committed_approval.approval_id,
            "approval_sha256": committed_approval.approval_sha256,
            "cleanup_receipts": cleanups,
            "consumed_at": completed_at,
        }
        draft = C9ManifestConsumptionReceipt.model_construct(
            **receipt_payload,  # type: ignore[arg-type]
            receipt_sha256="0" * 64,
        )
        receipt = draft.model_copy(
            update={
                "receipt_sha256": _model_digest(
                    b"systeme-local/c9/consumption-receipt/v1\0",
                    draft,
                    "receipt_sha256",
                )
            }
        )
        return result, C9ManifestConsumptionReceipt.model_validate(
            receipt.model_dump(mode="python")
        )

    def cancel_lease(
        self,
        lease_id: str,
        *,
        cancelled_at: datetime,
    ) -> C9CleanupReceipt:
        at = _utc(cancelled_at)
        with self._lock:
            record = self._lookup_record(lease_id)
            if record.consuming:
                _fail(
                    C9AttachmentSecurityReason.LEASE_TERMINAL,
                    "C9 lease is already being consumed",
                )
            return self._cleanup(record, C9LeaseTerminalState.CANCELLED, at)

    def expire(self, *, evaluated_at: datetime) -> tuple[C9CleanupReceipt, ...]:
        at = _utc(evaluated_at)
        with self._lock:
            expired = [
                record
                for record in self._leases.values()
                if not record.consuming and at >= record.lease.expires_at
            ]
            return tuple(
                self._cleanup(record, C9LeaseTerminalState.EXPIRED, at) for record in expired
            )

    def cancel_all(self, *, cancelled_at: datetime) -> tuple[C9CleanupReceipt, ...]:
        at = _utc(cancelled_at)
        with self._lock:
            if any(record.consuming for record in self._leases.values()):
                _fail(
                    C9AttachmentSecurityReason.LEASE_TERMINAL,
                    "C9 cannot cancel the authority while a payload callback is active",
                )
            records = tuple(self._leases.values())
            return tuple(
                self._cleanup(record, C9LeaseTerminalState.CANCELLED, at) for record in records
            )

    def close(self, *, closed_at: datetime) -> tuple[C9CleanupReceipt, ...]:
        with self._lock:
            if self._closed:
                return ()
            receipts = self.cancel_all(cancelled_at=closed_at)
            self._manifest_purposes.clear()
            self._closed = True
            return receipts

    def terminal_receipt(self, lease_id: str) -> C9CleanupReceipt | None:
        with self._lock:
            return self._terminal.get(lease_id)

    def _commit_canonical_attachment_manifest(
        self,
        *,
        records: tuple[_LeaseRecord, ...],
        manifest_id: str,
        purpose: str,
        committed_at: datetime,
        committed_turn: CommittedTurn | None,
    ) -> AttachmentManifest:
        if committed_turn is None:
            identity = secrets.token_hex(16)
            principal = AgentPrincipalRef(
                agent_id="c9_attachment_authority",
                instance_id=f"c9_instance_{identity}",
                key_id="c9_process_local",
                verification_id=f"c9_verify_{identity}",
            )
            turn = commit_text_turn(
                conversation_id=f"c9_conversation_{identity}",
                turn_id=f"c9_turn_{identity}",
                trace_id=f"c9_trace_{identity}",
                idempotency_key=f"c9_idempotency_{identity}",
                principal=principal,
                committed_at=committed_at,
                parts=(purpose,),
            )
        else:
            turn = CommittedTurn.model_validate(committed_turn.model_dump(mode="python"))
            if turn.committed_at > committed_at:
                _fail(
                    C9AttachmentSecurityReason.MANIFEST_INVALID,
                    "C9 canonical turn cannot follow manifest commitment",
                )

        committed = tuple(
            commit_attachment(
                turn=turn,
                attachment_id=record.lease.descriptor.attachment_id,
                ordinal=index,
                display_name=record.lease.descriptor.display_name,
                role=(
                    AttachmentRole.SCREENSHOT
                    if record.lease.descriptor.media_type
                    in (AttachmentMediaType.PNG, AttachmentMediaType.JPEG)
                    else AttachmentRole.INPUT_DOCUMENT
                ),
                source=AttachmentSource.OPERATOR_SELECTED,
                media_type=record.lease.descriptor.media_type,
                content=bytes(record.sanitized_content),
                inspected_at=committed_at,
                committed_at=committed_at,
            )
            for index, record in enumerate(records)
        )
        manifest = commit_attachment_manifest(
            turn=turn,
            manifest_id=manifest_id,
            attachments=committed,
            committed_at=committed_at,
        )
        verify_attachment_manifest(manifest=manifest, turn=turn)
        return manifest

    def _require_open(self) -> None:
        if self._closed:
            _fail(C9AttachmentSecurityReason.STORE_CLOSED, "C9 attachment authority is closed")

    def _lookup_record(self, lease_id: str) -> _LeaseRecord:
        if lease_id in self._terminal:
            _fail(
                C9AttachmentSecurityReason.LEASE_TERMINAL,
                "C9 lease is already terminal and cannot be replayed",
            )
        record = self._leases.get(lease_id)
        if record is None:
            _fail(C9AttachmentSecurityReason.LEASE_NOT_FOUND, "C9 lease does not exist")
        return record

    def _active_record(self, lease_id: str, at: datetime) -> _LeaseRecord:
        record = self._lookup_record(lease_id)
        if record.consuming:
            _fail(
                C9AttachmentSecurityReason.LEASE_TERMINAL,
                "C9 lease is already being consumed",
            )
        if at >= record.lease.expires_at:
            self._cleanup(record, C9LeaseTerminalState.EXPIRED, at)
            _fail(C9AttachmentSecurityReason.LEASE_EXPIRED, "C9 lease has expired")
        return record

    def _verify_record(self, record: _LeaseRecord, at: datetime) -> None:
        try:
            content, fingerprint = _read_exact_file(
                record.source_path,
                maximum_bytes=_max_bytes(self.policy),
            )
        except C9AttachmentSecurityError as exc:
            raise C9AttachmentSecurityError(
                C9AttachmentSecurityReason.FILE_CHANGED,
                "C9 selected source is no longer the approved immutable input",
            ) from exc
        if (
            fingerprint != record.source_fingerprint
            or sha256(content).hexdigest() != record.source_content_sha256
        ):
            _fail(
                C9AttachmentSecurityReason.FILE_CHANGED,
                "C9 selected source changed after approval",
            )
        descriptor = record.lease.descriptor
        payload = bytes(record.sanitized_content)
        inspection = inspect_attachment_bytes(
            content=payload,
            media_type=descriptor.media_type,
            inspected_at=at,
        )
        expected = descriptor.sanitized_inspection
        if (
            inspection.content_sha256 != expected.content_sha256
            or inspection.byte_size != expected.byte_size
            or inspection.image_width != expected.image_width
            or inspection.image_height != expected.image_height
        ):
            _fail(
                C9AttachmentSecurityReason.PAYLOAD_INTEGRITY_CHANGED,
                "C9 sanitized payload changed after approval",
            )

    def _cleanup(
        self,
        record: _LeaseRecord,
        state: C9LeaseTerminalState,
        at: datetime,
    ) -> C9CleanupReceipt:
        lease_id = record.lease.lease_id
        descriptor = record.lease.descriptor
        byte_size = len(record.sanitized_content)
        digest = descriptor.sanitized_inspection.content_sha256
        record.sanitized_content[:] = b"\x00" * byte_size
        record.consuming = False
        self._leases.pop(lease_id, None)
        payload = {
            "version": "1",
            "cleanup_id": f"c9_cleanup_{secrets.token_hex(16)}",
            "lease_id": lease_id,
            "descriptor_sha256": descriptor.descriptor_sha256,
            "sanitized_content_sha256": digest,
            "terminal_state": state,
            "byte_size_released": byte_size,
            "cleaned_at": at,
        }
        draft = C9CleanupReceipt.model_construct(
            **payload,  # type: ignore[arg-type]
            cleanup_sha256="0" * 64,
        )
        receipt = draft.model_copy(
            update={
                "cleanup_sha256": _model_digest(
                    b"systeme-local/c9/cleanup-receipt/v1\0",
                    draft,
                    "cleanup_sha256",
                )
            }
        )
        committed = C9CleanupReceipt.model_validate(receipt.model_dump(mode="python"))
        self._terminal[lease_id] = committed
        return committed

    def _expire_specific(self, lease_ids: tuple[str, ...], at: datetime) -> None:
        with self._lock:
            for lease_id in lease_ids:
                record = self._leases.get(lease_id)
                if record is not None and not record.consuming:
                    self._cleanup(record, C9LeaseTerminalState.EXPIRED, at)
