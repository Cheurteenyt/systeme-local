from __future__ import annotations

import binascii
import json
import os
import re
import secrets
import stat
import struct
import threading
import zlib
from datetime import UTC, datetime, timezone
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .providers.attachment_models import AttachmentMediaType

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PACKAGE_ID_PATTERN = r"^c9_fixture_package_[0-9a-f]{32}$"
_CLEANUP_ID_PATTERN = r"^c9_fixture_cleanup_[0-9a-f]{32}$"
_NONCE_PATTERN = r"^C9[0-9A-F]{32}$"

C9_SYNTHETIC_IMAGE_WIDTH = 896
C9_SYNTHETIC_IMAGE_HEIGHT = 144
C9_SYNTHETIC_PNG_MAX_BYTES = 1024 * 1024
C9_SYNTHETIC_TEXT_MAX_BYTES = 4096

_PNG_NAME = "c9-synthetic-proof.png"
_TEXT_NAME = "c9-synthetic-proof.txt"
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_GLYPH_SCALE = 4
_GLYPH_WIDTH = 5
_GLYPH_HEIGHT = 7
_GLYPH_GAP = _GLYPH_SCALE

# A deliberately small, reviewable 5x7 bitmap alphabet. Synthetic C9 nonces use
# only uppercase hexadecimal characters and digits, so no general text renderer
# or font parser is needed.
_FONT_5X7: dict[str, tuple[str, ...]] = {
    "0": ("01110", "10001", "10011", "10101", "11001", "10001", "01110"),
    "1": ("00100", "01100", "00100", "00100", "00100", "00100", "01110"),
    "2": ("01110", "10001", "00001", "00010", "00100", "01000", "11111"),
    "3": ("11110", "00001", "00001", "01110", "00001", "00001", "11110"),
    "4": ("00010", "00110", "01010", "10010", "11111", "00010", "00010"),
    "5": ("11111", "10000", "10000", "11110", "00001", "00001", "11110"),
    "6": ("01110", "10000", "10000", "11110", "10001", "10001", "01110"),
    "7": ("11111", "00001", "00010", "00100", "01000", "01000", "01000"),
    "8": ("01110", "10001", "10001", "01110", "10001", "10001", "01110"),
    "9": ("01110", "10001", "10001", "01111", "00001", "00001", "01110"),
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "B": ("11110", "10001", "10001", "11110", "10001", "10001", "11110"),
    "C": ("01111", "10000", "10000", "10000", "10000", "10000", "01111"),
    "D": ("11110", "10001", "10001", "10001", "10001", "10001", "11110"),
    "E": ("11111", "10000", "10000", "11110", "10000", "10000", "11111"),
    "F": ("11111", "10000", "10000", "11110", "10000", "10000", "10000"),
}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C9 synthetic fixture timestamps must include a timezone")
    return value.astimezone(UTC)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _model_digest(domain: bytes, model: BaseModel, digest_field: str) -> str:
    payload = model.model_dump(mode="json", exclude={digest_field})
    return sha256(domain + _canonical_json(payload)).hexdigest()


class C9SyntheticFixtureReason(StrEnum):
    ROOT_NOT_ABSOLUTE = "root_not_absolute"
    ROOT_NOT_PRIVATE_DIRECTORY = "root_not_private_directory"
    REPARSE_PATH_REJECTED = "reparse_path_rejected"
    CREATE_FAILED = "create_failed"
    SIZE_LIMIT_EXCEEDED = "size_limit_exceeded"
    STATE_INTEGRITY_CHANGED = "state_integrity_changed"


class C9SyntheticFixtureError(ValueError):
    def __init__(self, reason: C9SyntheticFixtureReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _fail(reason: C9SyntheticFixtureReason, message: str) -> NoReturn:
    raise C9SyntheticFixtureError(reason, message)


class C9SyntheticFixtureKind(StrEnum):
    IMAGE = "image"
    TEXT = "text"


class C9SyntheticFixtureMetadata(BaseModel):
    """Public, metadata-only commitment for one synthetic fixture."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    kind: C9SyntheticFixtureKind
    display_name: str = Field(pattern=r"^c9-synthetic-proof\.(?:png|txt)$")
    media_type: AttachmentMediaType
    content_sha256: str = Field(pattern=_SHA256_PATTERN)
    nonce_sha256: str = Field(pattern=_SHA256_PATTERN)
    byte_size: int = Field(ge=1, le=C9_SYNTHETIC_PNG_MAX_BYTES)
    image_width: int | None = Field(default=None, ge=1)
    image_height: int | None = Field(default=None, ge=1)
    generated_at: datetime
    metadata_sha256: str = Field(pattern=_SHA256_PATTERN)

    _generated_utc = field_validator("generated_at")(_utc)

    @model_validator(mode="after")
    def _validate_metadata(self) -> C9SyntheticFixtureMetadata:
        if self.kind is C9SyntheticFixtureKind.IMAGE:
            if (
                self.display_name != _PNG_NAME
                or self.media_type is not AttachmentMediaType.PNG
                or self.image_width != C9_SYNTHETIC_IMAGE_WIDTH
                or self.image_height != C9_SYNTHETIC_IMAGE_HEIGHT
                or self.byte_size > C9_SYNTHETIC_PNG_MAX_BYTES
            ):
                raise ValueError("C9 synthetic image metadata is inconsistent")
        elif (
            self.display_name != _TEXT_NAME
            or self.media_type is not AttachmentMediaType.TEXT
            or self.image_width is not None
            or self.image_height is not None
            or self.byte_size > C9_SYNTHETIC_TEXT_MAX_BYTES
        ):
            raise ValueError("C9 synthetic text metadata is inconsistent")
        expected = _model_digest(
            b"systeme-local/c9/synthetic-fixture-metadata/v1\0",
            self,
            "metadata_sha256",
        )
        if self.metadata_sha256 != expected:
            raise ValueError("C9 synthetic fixture metadata digest mismatch")
        return self


class C9SyntheticFixtureReceipt(BaseModel):
    """Public receipt. It intentionally contains no nonce, bytes or filesystem path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    package_id: str = Field(pattern=_PACKAGE_ID_PATTERN)
    fixtures: tuple[C9SyntheticFixtureMetadata, C9SyntheticFixtureMetadata]
    fixture_count: Literal[2] = 2
    total_bytes: int = Field(ge=2, le=C9_SYNTHETIC_PNG_MAX_BYTES + C9_SYNTHETIC_TEXT_MAX_BYTES)
    generated_at: datetime
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    _generated_utc = field_validator("generated_at")(_utc)

    @model_validator(mode="after")
    def _validate_receipt(self) -> C9SyntheticFixtureReceipt:
        if tuple(item.kind for item in self.fixtures) != (
            C9SyntheticFixtureKind.IMAGE,
            C9SyntheticFixtureKind.TEXT,
        ):
            raise ValueError("C9 fixture receipt requires exactly one image then one text file")
        if len({item.content_sha256 for item in self.fixtures}) != 2:
            raise ValueError("C9 synthetic fixture contents must be distinct")
        if len({item.nonce_sha256 for item in self.fixtures}) != 2:
            raise ValueError("C9 synthetic fixture nonces must be independent")
        if any(item.generated_at != self.generated_at for item in self.fixtures):
            raise ValueError("C9 synthetic fixture timestamps must match the package")
        if self.total_bytes != sum(item.byte_size for item in self.fixtures):
            raise ValueError("C9 synthetic fixture byte total mismatch")
        expected = _model_digest(
            b"systeme-local/c9/synthetic-fixture-receipt/v1\0",
            self,
            "receipt_sha256",
        )
        if self.receipt_sha256 != expected:
            raise ValueError("C9 synthetic fixture receipt digest mismatch")
        return self


class C9SyntheticCleanupReceipt(BaseModel):
    """Replay-safe public proof that the private package paths are absent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    cleanup_id: str = Field(pattern=_CLEANUP_ID_PATTERN)
    package_id: str = Field(pattern=_PACKAGE_ID_PATTERN)
    fixture_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    files_removed: int = Field(ge=0, le=2)
    fixture_files_absent: Literal[True] = True
    package_directory_absent: Literal[True] = True
    cleaned_at: datetime
    cleanup_sha256: str = Field(pattern=_SHA256_PATTERN)

    _cleaned_utc = field_validator("cleaned_at")(_utc)

    @model_validator(mode="after")
    def _validate_cleanup(self) -> C9SyntheticCleanupReceipt:
        expected = _model_digest(
            b"systeme-local/c9/synthetic-cleanup-receipt/v1\0",
            self,
            "cleanup_sha256",
        )
        if self.cleanup_sha256 != expected:
            raise ValueError("C9 synthetic cleanup receipt digest mismatch")
        return self


def _is_reparse(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = int(getattr(info, "st_file_attributes", 0))
    marker = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & marker)


def _safe_existing_directory(root: Path) -> Path:
    if not root.is_absolute():
        _fail(
            C9SyntheticFixtureReason.ROOT_NOT_ABSOLUTE,
            "C9 synthetic fixture root must be an explicit absolute path",
        )
    if ".." in root.parts:
        _fail(
            C9SyntheticFixtureReason.ROOT_NOT_PRIVATE_DIRECTORY,
            "C9 synthetic fixture root cannot contain parent traversal",
        )

    current = Path(root.anchor)
    components = root.parts[1:]
    candidates = (
        current,
        *(current.joinpath(*components[:index]) for index in range(1, len(components) + 1)),
    )
    try:
        for candidate in candidates:
            info = candidate.lstat()
            if candidate.is_symlink() or _is_reparse(info):
                _fail(
                    C9SyntheticFixtureReason.REPARSE_PATH_REJECTED,
                    "C9 synthetic fixture root cannot traverse a symlink or reparse point",
                )
    except FileNotFoundError as exc:
        raise C9SyntheticFixtureError(
            C9SyntheticFixtureReason.ROOT_NOT_PRIVATE_DIRECTORY,
            "C9 synthetic fixture root must already exist",
        ) from exc
    if not root.is_dir():
        _fail(
            C9SyntheticFixtureReason.ROOT_NOT_PRIVATE_DIRECTORY,
            "C9 synthetic fixture root must be an existing directory",
        )
    return root.resolve(strict=True)


def _new_nonce(excluding: str | None = None) -> str:
    for _ in range(16):
        value = f"C9{secrets.token_hex(16).upper()}"
        if value != excluding:
            return value
    _fail(
        C9SyntheticFixtureReason.CREATE_FAILED,
        "C9 could not generate independent synthetic nonces",
    )


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    checksum = binascii.crc32(chunk_type)
    checksum = binascii.crc32(payload, checksum) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", checksum)


def _render_nonce_pixels(nonce: str) -> bytes:
    if not re.fullmatch(_NONCE_PATTERN, nonce):
        raise ValueError("invalid C9 synthetic nonce")
    canvas = bytearray([255]) * (C9_SYNTHETIC_IMAGE_WIDTH * C9_SYNTHETIC_IMAGE_HEIGHT)
    rendered_width = len(nonce) * (_GLYPH_WIDTH * _GLYPH_SCALE + _GLYPH_GAP) - _GLYPH_GAP
    start_x = (C9_SYNTHETIC_IMAGE_WIDTH - rendered_width) // 2
    start_y = (C9_SYNTHETIC_IMAGE_HEIGHT - _GLYPH_HEIGHT * _GLYPH_SCALE) // 2
    for glyph_index, character in enumerate(nonce):
        glyph = _FONT_5X7[character]
        glyph_x = start_x + glyph_index * (_GLYPH_WIDTH * _GLYPH_SCALE + _GLYPH_GAP)
        for row_index, row in enumerate(glyph):
            for column_index, bit in enumerate(row):
                if bit != "1":
                    continue
                x = glyph_x + column_index * _GLYPH_SCALE
                y = start_y + row_index * _GLYPH_SCALE
                for scaled_y in range(y, y + _GLYPH_SCALE):
                    offset = scaled_y * C9_SYNTHETIC_IMAGE_WIDTH + x
                    canvas[offset : offset + _GLYPH_SCALE] = b"\0" * _GLYPH_SCALE
    return bytes(canvas)


def _build_png(nonce: str) -> bytes:
    pixels = _render_nonce_pixels(nonce)
    scanlines = bytearray()
    for row_index in range(C9_SYNTHETIC_IMAGE_HEIGHT):
        start = row_index * C9_SYNTHETIC_IMAGE_WIDTH
        scanlines.append(0)  # canonical PNG "None" filter
        scanlines.extend(pixels[start : start + C9_SYNTHETIC_IMAGE_WIDTH])
    ihdr = struct.pack(
        ">IIBBBBB",
        C9_SYNTHETIC_IMAGE_WIDTH,
        C9_SYNTHETIC_IMAGE_HEIGHT,
        8,  # bit depth
        0,  # grayscale
        0,  # compression
        0,  # filter
        0,  # non-interlaced
    )
    png = (
        _PNG_SIGNATURE
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(bytes(scanlines), level=9))
        + _png_chunk(b"IEND", b"")
    )
    if len(png) > C9_SYNTHETIC_PNG_MAX_BYTES:
        _fail(
            C9SyntheticFixtureReason.SIZE_LIMIT_EXCEEDED,
            "C9 synthetic PNG exceeds its fixed byte ceiling",
        )
    return png


def _build_text(nonce: str) -> bytes:
    if not re.fullmatch(_NONCE_PATTERN, nonce):
        raise ValueError("invalid C9 synthetic nonce")
    content = (f"C9 SYNTHETIC TEXT ATTACHMENT PROOF\nNONCE {nonce}\nSYNTHETIC DATA ONLY\n").encode()
    if b"\r" in content or len(content) > C9_SYNTHETIC_TEXT_MAX_BYTES:
        _fail(
            C9SyntheticFixtureReason.SIZE_LIMIT_EXCEEDED,
            "C9 synthetic text is not canonical bounded LF UTF-8",
        )
    return content


def _exclusive_write(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOINHERIT", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse(opened) or int(opened.st_nlink) != 1:
            _fail(
                C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                "C9 synthetic fixture write target identity is unsafe",
            )
        view = memoryview(content)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:  # pragma: no cover - operating-system invariant
                raise OSError("short write")
            written += count
        os.fsync(descriptor)
        completed = os.fstat(descriptor)
        if int(completed.st_size) != len(content) or int(completed.st_nlink) != 1:
            _fail(
                C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                "C9 synthetic fixture write target changed",
            )
    finally:
        os.close(descriptor)


def _fixture_metadata(
    *,
    kind: C9SyntheticFixtureKind,
    display_name: str,
    media_type: AttachmentMediaType,
    content: bytes,
    nonce: str,
    generated_at: datetime,
) -> C9SyntheticFixtureMetadata:
    payload = {
        "version": "1",
        "kind": kind,
        "display_name": display_name,
        "media_type": media_type,
        "content_sha256": sha256(content).hexdigest(),
        "nonce_sha256": sha256(nonce.encode("ascii")).hexdigest(),
        "byte_size": len(content),
        "image_width": (C9_SYNTHETIC_IMAGE_WIDTH if kind is C9SyntheticFixtureKind.IMAGE else None),
        "image_height": (
            C9_SYNTHETIC_IMAGE_HEIGHT if kind is C9SyntheticFixtureKind.IMAGE else None
        ),
        "generated_at": generated_at,
    }
    draft = C9SyntheticFixtureMetadata.model_construct(
        **payload,  # type: ignore[arg-type]
        metadata_sha256="0" * 64,
    )
    committed = draft.model_copy(
        update={
            "metadata_sha256": _model_digest(
                b"systeme-local/c9/synthetic-fixture-metadata/v1\0",
                draft,
                "metadata_sha256",
            )
        }
    )
    return C9SyntheticFixtureMetadata.model_validate(committed.model_dump(mode="python"))


class C9SyntheticFixtureHandle:
    """Private operator handle; paths never appear in its public receipt."""

    __slots__ = (
        "_cleanup_receipt",
        "_directory",
        "_directory_identity",
        "_directory_resolved",
        "_file_identities",
        "_lock",
        "_png_path",
        "_receipt",
        "_text_path",
    )

    def __init__(
        self,
        *,
        directory: Path,
        png_path: Path,
        text_path: Path,
        receipt: C9SyntheticFixtureReceipt,
    ) -> None:
        self._directory = directory
        self._png_path = png_path
        self._text_path = text_path
        self._receipt = receipt
        resolved = _safe_existing_directory(directory)
        info = directory.lstat()
        self._directory_identity = (int(info.st_dev), int(info.st_ino))
        self._directory_resolved = resolved
        identities: dict[Path, tuple[int, int]] = {}
        for path in (png_path, text_path):
            file_info = path.lstat()
            if (
                not stat.S_ISREG(file_info.st_mode)
                or _is_reparse(file_info)
                or int(file_info.st_nlink) != 1
            ):
                _fail(
                    C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                    "C9 synthetic fixture file identity is unsafe",
                )
            identities[path] = (int(file_info.st_dev), int(file_info.st_ino))
        self._file_identities = identities
        self._cleanup_receipt: C9SyntheticCleanupReceipt | None = None
        self._lock = threading.RLock()

    def __repr__(self) -> str:
        return f"C9SyntheticFixtureHandle(package_id={self._receipt.package_id!r})"

    @property
    def receipt(self) -> C9SyntheticFixtureReceipt:
        return self._receipt

    @property
    def png_path(self) -> Path:
        return self._png_path

    @property
    def text_path(self) -> Path:
        return self._text_path

    def verify_observed_nonce(
        self,
        kind: C9SyntheticFixtureKind,
        observed_nonce: str,
    ) -> bool:
        metadata = next(item for item in self._receipt.fixtures if item.kind is kind)
        return secrets.compare_digest(
            metadata.nonce_sha256,
            sha256(observed_nonce.encode("utf-8")).hexdigest(),
        )

    def cleanup(self, *, cleaned_at: datetime | None = None) -> C9SyntheticCleanupReceipt:
        with self._lock:
            if self._cleanup_receipt is not None:
                return self._cleanup_receipt
            at = _utc(cleaned_at or datetime.now(timezone.utc))
            removed = self._remove_private_paths()
            payload = {
                "version": "1",
                "cleanup_id": f"c9_fixture_cleanup_{secrets.token_hex(16)}",
                "package_id": self._receipt.package_id,
                "fixture_receipt_sha256": self._receipt.receipt_sha256,
                "files_removed": removed,
                "fixture_files_absent": True,
                "package_directory_absent": True,
                "cleaned_at": at,
            }
            draft = C9SyntheticCleanupReceipt.model_construct(
                **payload,  # type: ignore[arg-type]
                cleanup_sha256="0" * 64,
            )
            committed = draft.model_copy(
                update={
                    "cleanup_sha256": _model_digest(
                        b"systeme-local/c9/synthetic-cleanup-receipt/v1\0",
                        draft,
                        "cleanup_sha256",
                    )
                }
            )
            self._cleanup_receipt = C9SyntheticCleanupReceipt.model_validate(
                committed.model_dump(mode="python")
            )
            return self._cleanup_receipt

    def _remove_private_paths(self) -> int:
        removed = 0
        if self._directory.exists() or self._directory.is_symlink():
            resolved = _safe_existing_directory(self._directory)
            info = self._directory.lstat()
            if (
                self._directory.is_symlink()
                or _is_reparse(info)
                or (int(info.st_dev), int(info.st_ino)) != self._directory_identity
                or resolved != self._directory_resolved
            ):
                _fail(
                    C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                    "C9 synthetic package directory identity changed before cleanup",
                )
            for path in (self._png_path, self._text_path):
                if path.exists() or path.is_symlink():
                    _safe_existing_directory(self._directory)
                    file_info = path.lstat()
                    if (
                        not stat.S_ISREG(file_info.st_mode)
                        or _is_reparse(file_info)
                        or int(file_info.st_nlink) != 1
                        or (int(file_info.st_dev), int(file_info.st_ino))
                        != self._file_identities[path]
                    ):
                        _fail(
                            C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                            "C9 synthetic fixture file changed before cleanup",
                        )
                    path.unlink()
                    removed += 1
            resolved = _safe_existing_directory(self._directory)
            info = self._directory.lstat()
            if (
                resolved != self._directory_resolved
                or (int(info.st_dev), int(info.st_ino)) != self._directory_identity
                or _is_reparse(info)
            ):
                _fail(
                    C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                    "C9 synthetic package directory changed before removal",
                )
            try:
                self._directory.rmdir()
            except OSError as exc:
                raise C9SyntheticFixtureError(
                    C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                    "C9 synthetic package contains unexpected state",
                ) from exc
        if (
            self._png_path.exists()
            or self._png_path.is_symlink()
            or self._text_path.exists()
            or self._text_path.is_symlink()
            or self._directory.exists()
            or self._directory.is_symlink()
        ):  # pragma: no cover - postcondition
            _fail(
                C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                "C9 synthetic fixture cleanup postcondition failed",
            )
        return removed


def generate_c9_synthetic_fixtures(
    private_state_root: str | os.PathLike[str],
    *,
    generated_at: datetime | None = None,
) -> C9SyntheticFixtureHandle:
    """Create exactly one synthetic PNG and TXT below an existing private root."""

    root = _safe_existing_directory(Path(os.fspath(private_state_root)))
    root_info = root.lstat()
    root_identity = (int(root_info.st_dev), int(root_info.st_ino))
    root_resolved = root.resolve(strict=True)
    at = _utc(generated_at or datetime.now(timezone.utc))
    png_nonce = _new_nonce()
    text_nonce = _new_nonce(excluding=png_nonce)
    png = _build_png(png_nonce)
    text = _build_text(text_nonce)

    directory: Path | None = None
    package_id = ""
    for _ in range(16):
        package_id = f"c9_fixture_package_{secrets.token_hex(16)}"
        candidate = root / package_id
        try:
            if (
                _safe_existing_directory(root) != root_resolved
                or (int(root.lstat().st_dev), int(root.lstat().st_ino)) != root_identity
            ):
                _fail(
                    C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                    "C9 synthetic fixture root identity changed before mkdir",
                )
            os.mkdir(candidate, 0o700)
        except FileExistsError:
            continue
        candidate_info = candidate.lstat()
        if (
            not stat.S_ISDIR(candidate_info.st_mode)
            or _is_reparse(candidate_info)
            or _safe_existing_directory(root) != root_resolved
            or (int(root.lstat().st_dev), int(root.lstat().st_ino)) != root_identity
        ):
            _fail(
                C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                "C9 synthetic fixture directory identity is unsafe after mkdir",
            )
        directory = candidate
        break
    if directory is None:
        _fail(
            C9SyntheticFixtureReason.CREATE_FAILED,
            "C9 could not allocate a unique private fixture package",
        )

    png_path = directory / _PNG_NAME
    text_path = directory / _TEXT_NAME
    directory_info = directory.lstat()
    directory_identity = (int(directory_info.st_dev), int(directory_info.st_ino))
    try:
        if (
            _safe_existing_directory(directory) != directory.resolve(strict=True)
            or (int(directory.lstat().st_dev), int(directory.lstat().st_ino)) != directory_identity
        ):
            _fail(
                C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                "C9 synthetic package directory changed before write",
            )
        _exclusive_write(png_path, png)
        if (int(directory.lstat().st_dev), int(directory.lstat().st_ino)) != (directory_identity):
            _fail(
                C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                "C9 synthetic package directory changed during write",
            )
        _exclusive_write(text_path, text)
        if tuple(sorted(item.name for item in directory.iterdir())) != (_PNG_NAME, _TEXT_NAME):
            _fail(
                C9SyntheticFixtureReason.STATE_INTEGRITY_CHANGED,
                "C9 synthetic package contains unexpected files",
            )
    except Exception:
        try:
            if (
                _safe_existing_directory(directory) == directory.resolve(strict=True)
                and (int(directory.lstat().st_dev), int(directory.lstat().st_ino))
                == directory_identity
            ):
                for path in (png_path, text_path):
                    try:
                        info = path.lstat()
                    except FileNotFoundError:
                        continue
                    if (
                        stat.S_ISREG(info.st_mode)
                        and not _is_reparse(info)
                        and int(info.st_nlink) == 1
                    ):
                        path.unlink()
                directory.rmdir()
        except (C9SyntheticFixtureError, OSError):
            pass
        raise

    image_metadata = _fixture_metadata(
        kind=C9SyntheticFixtureKind.IMAGE,
        display_name=_PNG_NAME,
        media_type=AttachmentMediaType.PNG,
        content=png,
        nonce=png_nonce,
        generated_at=at,
    )
    text_metadata = _fixture_metadata(
        kind=C9SyntheticFixtureKind.TEXT,
        display_name=_TEXT_NAME,
        media_type=AttachmentMediaType.TEXT,
        content=text,
        nonce=text_nonce,
        generated_at=at,
    )
    receipt_payload = {
        "version": "1",
        "package_id": package_id,
        "fixtures": (image_metadata, text_metadata),
        "fixture_count": 2,
        "total_bytes": len(png) + len(text),
        "generated_at": at,
    }
    draft = C9SyntheticFixtureReceipt.model_construct(
        **receipt_payload,  # type: ignore[arg-type]
        receipt_sha256="0" * 64,
    )
    committed = draft.model_copy(
        update={
            "receipt_sha256": _model_digest(
                b"systeme-local/c9/synthetic-fixture-receipt/v1\0",
                draft,
                "receipt_sha256",
            )
        }
    )
    receipt = C9SyntheticFixtureReceipt.model_validate(committed.model_dump(mode="python"))
    return C9SyntheticFixtureHandle(
        directory=directory,
        png_path=png_path,
        text_path=text_path,
        receipt=receipt,
    )
