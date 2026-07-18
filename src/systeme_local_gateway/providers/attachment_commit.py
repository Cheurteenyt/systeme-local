from __future__ import annotations

import json
import re
import zlib
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from typing import NoReturn

from pydantic import ValidationError

from .attachment_models import (
    MAX_INSPECTION_BYTES,
    AttachmentInspection,
    AttachmentManifest,
    AttachmentMediaType,
    AttachmentRole,
    AttachmentSource,
    CommittedAttachment,
    attachment_manifest_sha256,
    attachment_metadata_sha256,
    normalize_utc_timestamp,
    validate_attachment_display_name,
)
from .models import CommittedTurn

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PDF_HEADER = re.compile(br"%PDF-(?:1\.[0-7]|2\.0)(?:\r\n|\r|\n)")
_PDF_EOF = re.compile(br"startxref\s+[0-9]+\s+%%EOF\s*\Z", re.DOTALL)
_JPEG_SOF_MARKERS = frozenset(
    {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }
)


class AttachmentInspectionReason(StrEnum):
    EMPTY_CONTENT = "empty_content"
    CONTENT_TOO_LARGE = "content_too_large"
    INVALID_PNG = "invalid_png"
    INVALID_JPEG = "invalid_jpeg"
    INVALID_PDF = "invalid_pdf"
    INVALID_UTF8 = "invalid_utf8"
    NUL_BYTE = "nul_byte"
    INVALID_JSON = "invalid_json"


class AttachmentVerificationReason(StrEnum):
    CONTENT_DIGEST_CHANGED = "content_digest_changed"
    BYTE_SIZE_CHANGED = "byte_size_changed"
    MEDIA_TYPE_CHANGED = "media_type_changed"
    IMAGE_DIMENSIONS_CHANGED = "image_dimensions_changed"
    TURN_BINDING_CHANGED = "turn_binding_changed"
    MANIFEST_BINDING_CHANGED = "manifest_binding_changed"
    ATTACHMENT_INTEGRITY_CHANGED = "attachment_integrity_changed"
    MANIFEST_INTEGRITY_CHANGED = "manifest_integrity_changed"
    VERIFICATION_BEFORE_COMMIT = "verification_before_commit"


class AttachmentInspectionError(ValueError):
    def __init__(self, reason: AttachmentInspectionReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class AttachmentVerificationError(ValueError):
    def __init__(self, reason: AttachmentVerificationReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _inspection_error(reason: AttachmentInspectionReason, message: str) -> NoReturn:
    raise AttachmentInspectionError(reason, message)


def inspect_attachment_bytes(
    *,
    content: bytes,
    media_type: AttachmentMediaType,
    inspected_at: datetime,
) -> AttachmentInspection:
    if not isinstance(content, bytes):
        raise TypeError("attachment content must be immutable bytes")
    byte_size = len(content)
    if byte_size == 0:
        _inspection_error(AttachmentInspectionReason.EMPTY_CONTENT, "attachment content is empty")
    if byte_size > MAX_INSPECTION_BYTES:
        _inspection_error(
            AttachmentInspectionReason.CONTENT_TOO_LARGE,
            "attachment content exceeds the local inspection ceiling",
        )

    width: int | None = None
    height: int | None = None

    if media_type is AttachmentMediaType.PNG:
        width, height = _inspect_png(content)
    elif media_type is AttachmentMediaType.JPEG:
        width, height = _inspect_jpeg(content)
    elif media_type is AttachmentMediaType.PDF:
        _inspect_pdf(content)
    elif media_type is AttachmentMediaType.TEXT:
        _inspect_text(content)
    elif media_type is AttachmentMediaType.JSON:
        _inspect_json(content)
    else:  # pragma: no cover - enum exhaustiveness
        raise AssertionError(f"unsupported attachment media type: {media_type}")

    inspected_at = normalize_utc_timestamp(inspected_at)
    return AttachmentInspection(
        media_type=media_type,
        content_sha256=sha256(content).hexdigest(),
        byte_size=byte_size,
        image_width=width,
        image_height=height,
        inspected_at=inspected_at,
    )


def commit_attachment(
    *,
    turn: CommittedTurn,
    attachment_id: str,
    ordinal: int,
    display_name: str,
    role: AttachmentRole,
    source: AttachmentSource,
    media_type: AttachmentMediaType,
    content: bytes,
    inspected_at: datetime,
    committed_at: datetime,
) -> CommittedAttachment:
    validate_attachment_display_name(display_name)
    inspected_at = normalize_utc_timestamp(inspected_at)
    committed_at = normalize_utc_timestamp(committed_at)
    if inspected_at < turn.committed_at:
        raise ValueError("attachment inspection cannot precede the committed turn")
    if committed_at < inspected_at:
        raise ValueError("attachment commit cannot precede inspection")
    inspection = inspect_attachment_bytes(
        content=content,
        media_type=media_type,
        inspected_at=inspected_at,
    )
    metadata_sha256 = attachment_metadata_sha256(
        attachment_id=attachment_id,
        conversation_id=turn.conversation_id,
        turn_id=turn.turn_id,
        trace_id=turn.trace_id,
        ordinal=ordinal,
        display_name=display_name,
        role=role,
        source=source,
        inspection=inspection,
        committed_at=committed_at,
    )
    return CommittedAttachment(
        attachment_id=attachment_id,
        conversation_id=turn.conversation_id,
        turn_id=turn.turn_id,
        trace_id=turn.trace_id,
        ordinal=ordinal,
        display_name=display_name,
        role=role,
        source=source,
        inspection=inspection,
        committed_at=committed_at,
        metadata_sha256=metadata_sha256,
    )


def verify_attachment_bytes(
    *,
    attachment: CommittedAttachment,
    content: bytes,
    verified_at: datetime,
) -> AttachmentInspection:
    _validate_attachment_integrity(attachment)
    verified_at = normalize_utc_timestamp(verified_at)
    if verified_at < attachment.committed_at:
        raise AttachmentVerificationError(
            AttachmentVerificationReason.VERIFICATION_BEFORE_COMMIT,
            "attachment verification cannot precede commitment",
        )
    inspection = inspect_attachment_bytes(
        content=content,
        media_type=attachment.inspection.media_type,
        inspected_at=verified_at,
    )
    if inspection.media_type is not attachment.inspection.media_type:
        raise AttachmentVerificationError(
            AttachmentVerificationReason.MEDIA_TYPE_CHANGED,
            "attachment media type changed after commitment",
        )
    if inspection.byte_size != attachment.inspection.byte_size:
        raise AttachmentVerificationError(
            AttachmentVerificationReason.BYTE_SIZE_CHANGED,
            "attachment byte size changed after commitment",
        )
    if inspection.content_sha256 != attachment.inspection.content_sha256:
        raise AttachmentVerificationError(
            AttachmentVerificationReason.CONTENT_DIGEST_CHANGED,
            "attachment content digest changed after commitment",
        )
    if (
        inspection.image_width != attachment.inspection.image_width
        or inspection.image_height != attachment.inspection.image_height
    ):
        raise AttachmentVerificationError(
            AttachmentVerificationReason.IMAGE_DIMENSIONS_CHANGED,
            "attachment dimensions changed after commitment",
        )
    return inspection


def commit_attachment_manifest(
    *,
    turn: CommittedTurn,
    manifest_id: str,
    attachments: tuple[CommittedAttachment, ...],
    committed_at: datetime,
) -> AttachmentManifest:
    committed_at = normalize_utc_timestamp(committed_at)
    if not attachments:
        raise ValueError("attachment manifest requires at least one attachment")
    if committed_at < turn.committed_at:
        raise ValueError("manifest commitment cannot precede the committed turn")
    for attachment in attachments:
        _validate_attachment_integrity(attachment)
        if attachment.inspection.inspected_at < turn.committed_at:
            raise AttachmentVerificationError(
                AttachmentVerificationReason.TURN_BINDING_CHANGED,
                "attachment inspection predates the committed turn",
            )
        if (
            attachment.conversation_id != turn.conversation_id
            or attachment.turn_id != turn.turn_id
            or attachment.trace_id != turn.trace_id
        ):
            raise AttachmentVerificationError(
                AttachmentVerificationReason.TURN_BINDING_CHANGED,
                "attachment does not belong to the committed turn",
            )
        if attachment.committed_at > committed_at:
            raise ValueError("manifest cannot precede attachment commitment")
    digest = attachment_manifest_sha256(
        manifest_id=manifest_id,
        conversation_id=turn.conversation_id,
        turn_id=turn.turn_id,
        trace_id=turn.trace_id,
        principal=turn.principal,
        turn_content_sha256=turn.content_sha256,
        attachments=attachments,
        committed_at=committed_at,
    )
    return AttachmentManifest(
        manifest_id=manifest_id,
        conversation_id=turn.conversation_id,
        turn_id=turn.turn_id,
        trace_id=turn.trace_id,
        principal=turn.principal,
        turn_content_sha256=turn.content_sha256,
        attachment_count=len(attachments),
        total_bytes=sum(item.inspection.byte_size for item in attachments),
        attachments=attachments,
        committed_at=committed_at,
        manifest_sha256=digest,
    )


def verify_attachment_manifest(
    *,
    manifest: AttachmentManifest,
    turn: CommittedTurn,
) -> None:
    _validate_manifest_integrity(manifest)
    if manifest.committed_at < turn.committed_at:
        raise AttachmentVerificationError(
            AttachmentVerificationReason.MANIFEST_BINDING_CHANGED,
            "attachment manifest predates the committed turn",
        )
    if any(
        item.inspection.inspected_at < turn.committed_at
        for item in manifest.attachments
    ):
        raise AttachmentVerificationError(
            AttachmentVerificationReason.MANIFEST_BINDING_CHANGED,
            "attachment inspection predates the committed turn",
        )
    if (
        manifest.conversation_id != turn.conversation_id
        or manifest.turn_id != turn.turn_id
        or manifest.trace_id != turn.trace_id
        or manifest.principal != turn.principal
        or manifest.turn_content_sha256 != turn.content_sha256
    ):
        raise AttachmentVerificationError(
            AttachmentVerificationReason.MANIFEST_BINDING_CHANGED,
            "attachment manifest does not match the committed turn",
        )



def _validate_attachment_integrity(attachment: CommittedAttachment) -> None:
    try:
        CommittedAttachment.model_validate(attachment.model_dump(mode="python"))
    except ValidationError as exc:
        raise AttachmentVerificationError(
            AttachmentVerificationReason.ATTACHMENT_INTEGRITY_CHANGED,
            "committed attachment integrity validation failed",
        ) from exc


def _validate_manifest_integrity(manifest: AttachmentManifest) -> None:
    try:
        AttachmentManifest.model_validate(manifest.model_dump(mode="python"))
    except ValidationError as exc:
        raise AttachmentVerificationError(
            AttachmentVerificationReason.MANIFEST_INTEGRITY_CHANGED,
            "attachment manifest integrity validation failed",
        ) from exc

def _inspect_png(content: bytes) -> tuple[int, int]:
    if len(content) < 8 + 12 or not content.startswith(_PNG_SIGNATURE):
        _inspection_error(AttachmentInspectionReason.INVALID_PNG, "invalid PNG signature or length")
    offset = len(_PNG_SIGNATURE)
    chunk_index = 0
    width: int | None = None
    height: int | None = None
    saw_idat = False
    saw_iend = False

    while offset < len(content):
        if len(content) - offset < 12:
            _inspection_error(AttachmentInspectionReason.INVALID_PNG, "truncated PNG chunk")
        length = int.from_bytes(content[offset : offset + 4], "big")
        chunk_type = content[offset + 4 : offset + 8]
        if len(chunk_type) != 4 or any(
            not (65 <= value <= 90 or 97 <= value <= 122) for value in chunk_type
        ):
            _inspection_error(AttachmentInspectionReason.INVALID_PNG, "invalid PNG chunk type")
        data_start = offset + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if data_end < data_start or crc_end > len(content):
            _inspection_error(AttachmentInspectionReason.INVALID_PNG, "PNG chunk length overflow")
        stored_crc = int.from_bytes(content[data_end:crc_end], "big")
        actual_crc = zlib.crc32(chunk_type)
        actual_crc = zlib.crc32(content[data_start:data_end], actual_crc) & 0xFFFFFFFF
        if stored_crc != actual_crc:
            _inspection_error(AttachmentInspectionReason.INVALID_PNG, "PNG chunk CRC mismatch")

        if chunk_index == 0:
            if chunk_type != b"IHDR" or length != 13:
                _inspection_error(
                    AttachmentInspectionReason.INVALID_PNG,
                    "PNG must begin with a 13-byte IHDR chunk",
                )
            width = int.from_bytes(content[data_start : data_start + 4], "big")
            height = int.from_bytes(content[data_start + 4 : data_start + 8], "big")
            bit_depth = content[data_start + 8]
            color_type = content[data_start + 9]
            compression = content[data_start + 10]
            filter_method = content[data_start + 11]
            interlace = content[data_start + 12]
            valid_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                width == 0
                or height == 0
                or color_type not in valid_depths
                or bit_depth not in valid_depths[color_type]
                or compression != 0
                or filter_method != 0
                or interlace not in (0, 1)
            ):
                _inspection_error(AttachmentInspectionReason.INVALID_PNG, "invalid PNG IHDR")
        elif chunk_type == b"IHDR":
            _inspection_error(AttachmentInspectionReason.INVALID_PNG, "duplicate PNG IHDR")

        if chunk_type == b"IDAT":
            saw_idat = True
        if chunk_type == b"IEND":
            if length != 0 or not saw_idat:
                _inspection_error(AttachmentInspectionReason.INVALID_PNG, "invalid PNG IEND")
            saw_iend = True
            if crc_end != len(content):
                _inspection_error(AttachmentInspectionReason.INVALID_PNG, "trailing bytes after PNG IEND")
            break

        offset = crc_end
        chunk_index += 1

    if not saw_iend or width is None or height is None:
        _inspection_error(AttachmentInspectionReason.INVALID_PNG, "incomplete PNG structure")
    return width, height


def _inspect_jpeg(content: bytes) -> tuple[int, int]:
    if len(content) < 8 or not content.startswith(b"\xff\xd8") or not content.endswith(b"\xff\xd9"):
        _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "invalid JPEG boundaries")
    offset = 2
    width: int | None = None
    height: int | None = None
    saw_sos = False
    scan_data_start: int | None = None

    while offset < len(content) - 2:
        if content[offset] != 0xFF:
            _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "invalid JPEG marker prefix")
        while offset < len(content) and content[offset] == 0xFF:
            offset += 1
        if offset >= len(content):
            _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "truncated JPEG marker")
        marker = content[offset]
        offset += 1

        if marker == 0x00:
            _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "unexpected stuffed JPEG marker")
        if marker in (*range(0xD0, 0xD8), 0x01):
            continue
        if marker in (0xD8, 0xD9):
            _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "unexpected JPEG boundary marker")
        if offset + 2 > len(content):
            _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "truncated JPEG segment length")
        segment_length = int.from_bytes(content[offset : offset + 2], "big")
        if segment_length < 2:
            _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "invalid JPEG segment length")
        segment_end = offset + segment_length
        if segment_end > len(content):
            _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "truncated JPEG segment")
        payload = content[offset + 2 : segment_end]

        if marker in _JPEG_SOF_MARKERS:
            if width is not None or height is not None:
                _inspection_error(
                    AttachmentInspectionReason.INVALID_JPEG,
                    "JPEG contains multiple SOF dimension markers",
                )
            if len(payload) < 6:
                _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "truncated JPEG SOF")
            precision = payload[0]
            height = int.from_bytes(payload[1:3], "big")
            width = int.from_bytes(payload[3:5], "big")
            components = payload[5]
            if (
                precision not in (8, 12, 16)
                or width == 0
                or height == 0
                or components == 0
                or segment_length != 8 + 3 * components
            ):
                _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "invalid JPEG SOF")
        if marker == 0xDA:
            saw_sos = True
            scan_data_start = segment_end
            break
        offset = segment_end

    if width is None or height is None:
        _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "JPEG has no bounded SOF dimensions")
    if not saw_sos or scan_data_start is None:
        _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "JPEG has no start-of-scan segment")
    if scan_data_start >= len(content) - 2:
        _inspection_error(AttachmentInspectionReason.INVALID_JPEG, "JPEG scan data is empty")
    return width, height


def _inspect_pdf(content: bytes) -> None:
    if _PDF_HEADER.match(content) is None:
        _inspection_error(AttachmentInspectionReason.INVALID_PDF, "invalid PDF header")
    tail = content[-4096:]
    if _PDF_EOF.search(tail) is None:
        _inspection_error(
            AttachmentInspectionReason.INVALID_PDF,
            "PDF tail lacks startxref and terminal EOF marker",
        )


def _inspect_text(content: bytes) -> str:
    if b"\x00" in content:
        _inspection_error(AttachmentInspectionReason.NUL_BYTE, "text attachments cannot contain NUL")
    try:
        return content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AttachmentInspectionError(
            AttachmentInspectionReason.INVALID_UTF8,
            "text attachment is not strict UTF-8",
        ) from exc


def _inspect_json(content: bytes) -> None:
    if content.startswith(b"\xef\xbb\xbf"):
        _inspection_error(AttachmentInspectionReason.INVALID_JSON, "JSON attachment cannot use UTF-8 BOM")
    text = _inspect_text(content)

    def reject_constant(value: str) -> NoReturn:
        raise ValueError(f"non-standard JSON constant: {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    decoder = json.JSONDecoder(
        parse_constant=reject_constant,
        object_pairs_hook=reject_duplicate_keys,
    )
    try:
        json_whitespace = " \t\r\n"
        stripped = text.lstrip(json_whitespace)
        value, end = decoder.raw_decode(stripped)
        del value
        leading = len(text) - len(stripped)
        end += leading
        if text[end:].strip(json_whitespace):
            raise ValueError("trailing JSON data")
    except (json.JSONDecodeError, ValueError) as exc:
        raise AttachmentInspectionError(
            AttachmentInspectionReason.INVALID_JSON,
            "JSON attachment is not one strict complete value",
        ) from exc
