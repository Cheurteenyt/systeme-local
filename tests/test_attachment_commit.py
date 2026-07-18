from __future__ import annotations

import json
import struct
from datetime import timedelta

import pytest
from pydantic import ValidationError

from systeme_local_gateway.providers.attachment_commit import (
    AttachmentInspectionError,
    AttachmentInspectionReason,
    AttachmentVerificationError,
    AttachmentVerificationReason,
    commit_attachment,
    commit_attachment_manifest,
    inspect_attachment_bytes,
    verify_attachment_bytes,
    verify_attachment_manifest,
)
from systeme_local_gateway.providers.attachment_models import (
    AttachmentManifest,
    AttachmentMediaType,
    AttachmentRole,
    AttachmentSource,
)
from systeme_local_gateway.providers.models import commit_text_turn

from conftest import NOW, make_jpeg, make_pdf, make_png, png_chunk


@pytest.mark.parametrize(
    ("media_type", "content", "width", "height"),
    [
        (AttachmentMediaType.PNG, make_png(11, 12), 11, 12),
        (AttachmentMediaType.JPEG, make_jpeg(13, 14), 13, 14),
        (AttachmentMediaType.PDF, make_pdf(), None, None),
        (AttachmentMediaType.TEXT, "héllo\n".encode(), None, None),
        (
            AttachmentMediaType.JSON,
            json.dumps({"a": [1, True, None]}, separators=(",", ":")).encode(),
            None,
            None,
        ),
    ],
)
def test_inspection_accepts_supported_structures(media_type, content, width, height):
    inspection = inspect_attachment_bytes(
        content=content,
        media_type=media_type,
        inspected_at=NOW,
    )
    assert inspection.media_type is media_type
    assert inspection.byte_size == len(content)
    assert inspection.image_width == width
    assert inspection.image_height == height
    assert len(inspection.content_sha256) == 64


def test_inspection_requires_immutable_bytes():
    with pytest.raises(TypeError, match="immutable bytes"):
        inspect_attachment_bytes(
            content=bytearray(b"x"),  # type: ignore[arg-type]
            media_type=AttachmentMediaType.TEXT,
            inspected_at=NOW,
        )


def test_inspection_rejects_empty_content():
    with pytest.raises(AttachmentInspectionError) as exc_info:
        inspect_attachment_bytes(
            content=b"",
            media_type=AttachmentMediaType.TEXT,
            inspected_at=NOW,
        )
    assert exc_info.value.reason is AttachmentInspectionReason.EMPTY_CONTENT


@pytest.mark.parametrize(
    "content",
    [
        b"not png",
        b"\x89PNG\r\n\x1a\n",
        make_png()[:-1],
        make_png() + b"x",
    ],
)
def test_png_rejects_invalid_boundaries(content):
    with pytest.raises(AttachmentInspectionError) as exc_info:
        inspect_attachment_bytes(
            content=content,
            media_type=AttachmentMediaType.PNG,
            inspected_at=NOW,
        )
    assert exc_info.value.reason is AttachmentInspectionReason.INVALID_PNG


def test_png_rejects_crc_tampering():
    content = bytearray(make_png())
    content[25] ^= 1
    with pytest.raises(AttachmentInspectionError, match="CRC mismatch"):
        inspect_attachment_bytes(
            content=bytes(content),
            media_type=AttachmentMediaType.PNG,
            inspected_at=NOW,
        )


def test_png_requires_ihdr_first():
    content = b"\x89PNG\r\n\x1a\n" + png_chunk(b"IDAT", b"\x00") + png_chunk(b"IEND", b"")
    with pytest.raises(AttachmentInspectionError, match="IHDR"):
        inspect_attachment_bytes(
            content=content,
            media_type=AttachmentMediaType.PNG,
            inspected_at=NOW,
        )


def test_png_requires_idat_before_iend():
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    content = b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", ihdr) + png_chunk(b"IEND", b"")
    with pytest.raises(AttachmentInspectionError, match="IEND"):
        inspect_attachment_bytes(
            content=content,
            media_type=AttachmentMediaType.PNG,
            inspected_at=NOW,
        )


@pytest.mark.parametrize(
    "content",
    [
        b"\xff\xd8\xff\xd9",
        make_jpeg()[:-2],
        b"\xff\xd8\xff\xc0\x00\x01\xff\xd9",
        b"\xff\xd8abc\xff\xd9",
    ],
)
def test_jpeg_rejects_malformed_content(content):
    with pytest.raises(AttachmentInspectionError) as exc_info:
        inspect_attachment_bytes(
            content=content,
            media_type=AttachmentMediaType.JPEG,
            inspected_at=NOW,
        )
    assert exc_info.value.reason is AttachmentInspectionReason.INVALID_JPEG


def test_jpeg_rejects_multiple_sof_markers():
    first = make_jpeg(2, 3)
    sof_payload = bytes([8]) + (4).to_bytes(2, "big") + (5).to_bytes(2, "big")
    sof_payload += bytes([1, 1, 0x11, 0])
    second_sof = b"\xff\xc0" + (len(sof_payload) + 2).to_bytes(2, "big") + sof_payload
    insertion = first.index(b"\xff\xda")
    content = first[:insertion] + second_sof + first[insertion:]
    with pytest.raises(AttachmentInspectionError, match="multiple SOF"):
        inspect_attachment_bytes(
            content=content,
            media_type=AttachmentMediaType.JPEG,
            inspected_at=NOW,
        )


def test_jpeg_rejects_zero_dimensions():
    sof_payload = bytes([8]) + b"\x00\x00\x00\x01" + bytes([1, 1, 0x11, 0])
    sof = b"\xff\xc0" + (len(sof_payload) + 2).to_bytes(2, "big") + sof_payload
    content = b"\xff\xd8" + sof + b"\xff\xd9"
    with pytest.raises(AttachmentInspectionError, match="invalid JPEG SOF"):
        inspect_attachment_bytes(
            content=content,
            media_type=AttachmentMediaType.JPEG,
            inspected_at=NOW,
        )


@pytest.mark.parametrize(
    "content",
    [
        b"%PDF-3.0\nstartxref\n1\n%%EOF\n",
        b"%PDF-1.7\n%%EOF\n",
        b"%PDF-1.7\nstartxref\n1\n%%EOF\ntrailing",
        b"junk%PDF-1.7\nstartxref\n1\n%%EOF\n",
    ],
)
def test_pdf_requires_supported_header_and_terminal_startxref(content):
    with pytest.raises(AttachmentInspectionError) as exc_info:
        inspect_attachment_bytes(
            content=content,
            media_type=AttachmentMediaType.PDF,
            inspected_at=NOW,
        )
    assert exc_info.value.reason is AttachmentInspectionReason.INVALID_PDF


@pytest.mark.parametrize(
    ("media_type", "content", "reason"),
    [
        (AttachmentMediaType.TEXT, b"a\x00b", AttachmentInspectionReason.NUL_BYTE),
        (AttachmentMediaType.TEXT, b"\xff", AttachmentInspectionReason.INVALID_UTF8),
        (AttachmentMediaType.JSON, b"\xef\xbb\xbf{}", AttachmentInspectionReason.INVALID_JSON),
        (AttachmentMediaType.JSON, b'{"a":1} trailing', AttachmentInspectionReason.INVALID_JSON),
        (AttachmentMediaType.JSON, b'{"a":1,"a":2}', AttachmentInspectionReason.INVALID_JSON),
        (AttachmentMediaType.JSON, b'{"a":NaN}', AttachmentInspectionReason.INVALID_JSON),
    ],
)
def test_text_and_json_fail_closed(media_type, content, reason):
    with pytest.raises(AttachmentInspectionError) as exc_info:
        inspect_attachment_bytes(
            content=content,
            media_type=media_type,
            inspected_at=NOW,
        )
    assert exc_info.value.reason is reason


def test_commit_attachment_canonicalizes_timezone_offsets(attachment_turn):
    from datetime import timezone

    plus_two = timezone(timedelta(hours=2))
    local_time = NOW.astimezone(plus_two)
    attachment = commit_attachment(
        turn=attachment_turn,
        attachment_id="attachment_tz",
        ordinal=0,
        display_name="timezone.txt",
        role=AttachmentRole.REFERENCE,
        source=AttachmentSource.SIMULATED,
        media_type=AttachmentMediaType.TEXT,
        content=b"timezone",
        inspected_at=local_time,
        committed_at=local_time,
    )
    assert attachment.inspection.inspected_at == NOW
    assert attachment.committed_at == NOW


def test_commit_attachment_binds_turn_and_metadata(attachment_turn):
    attachment = commit_attachment(
        turn=attachment_turn,
        attachment_id="attachment_main",
        ordinal=0,
        display_name="screen.png",
        role=AttachmentRole.SCREENSHOT,
        source=AttachmentSource.OPERATOR_SELECTED,
        media_type=AttachmentMediaType.PNG,
        content=make_png(20, 30),
        inspected_at=NOW,
        committed_at=NOW,
    )
    assert attachment.turn_id == attachment_turn.turn_id
    assert attachment.conversation_id == attachment_turn.conversation_id
    assert attachment.trace_id == attachment_turn.trace_id
    assert attachment.inspection.image_width == 20
    assert len(attachment.metadata_sha256) == 64


def test_commit_attachment_rejects_inspection_before_turn(attachment_turn):
    with pytest.raises(ValueError, match="cannot precede"):
        commit_attachment(
            turn=attachment_turn,
            attachment_id="attachment_main",
            ordinal=0,
            display_name="file.txt",
            role=AttachmentRole.REFERENCE,
            source=AttachmentSource.SIMULATED,
            media_type=AttachmentMediaType.TEXT,
            content=b"x",
            inspected_at=NOW - timedelta(seconds=1),
            committed_at=NOW,
        )


def test_verify_attachment_detects_size_change(attachment_turn):
    attachment = commit_attachment(
        turn=attachment_turn,
        attachment_id="attachment_main",
        ordinal=0,
        display_name="file.txt",
        role=AttachmentRole.REFERENCE,
        source=AttachmentSource.SIMULATED,
        media_type=AttachmentMediaType.TEXT,
        content=b"abc",
        inspected_at=NOW,
        committed_at=NOW,
    )
    with pytest.raises(AttachmentVerificationError) as exc_info:
        verify_attachment_bytes(
            attachment=attachment,
            content=b"abcd",
            verified_at=NOW + timedelta(seconds=1),
        )
    assert exc_info.value.reason is AttachmentVerificationReason.BYTE_SIZE_CHANGED


def test_verify_attachment_detects_same_size_digest_change(attachment_turn):
    attachment = commit_attachment(
        turn=attachment_turn,
        attachment_id="attachment_main",
        ordinal=0,
        display_name="file.txt",
        role=AttachmentRole.REFERENCE,
        source=AttachmentSource.SIMULATED,
        media_type=AttachmentMediaType.TEXT,
        content=b"abc",
        inspected_at=NOW,
        committed_at=NOW,
    )
    with pytest.raises(AttachmentVerificationError) as exc_info:
        verify_attachment_bytes(
            attachment=attachment,
            content=b"abd",
            verified_at=NOW + timedelta(seconds=1),
        )
    assert exc_info.value.reason is AttachmentVerificationReason.CONTENT_DIGEST_CHANGED


def test_manifest_preserves_order_and_totals(attachment_manifest, attachment_committed_items):
    assert attachment_manifest.attachment_count == 3
    assert attachment_manifest.attachments == attachment_committed_items
    assert attachment_manifest.total_bytes == sum(item.inspection.byte_size for item in attachment_committed_items)
    assert len(attachment_manifest.manifest_sha256) == 64


def test_manifest_rejects_duplicate_content(attachment_turn):
    first = commit_attachment(
        turn=attachment_turn,
        attachment_id="attachment_one",
        ordinal=0,
        display_name="one.txt",
        role=AttachmentRole.REFERENCE,
        source=AttachmentSource.SIMULATED,
        media_type=AttachmentMediaType.TEXT,
        content=b"same",
        inspected_at=NOW,
        committed_at=NOW,
    )
    second = commit_attachment(
        turn=attachment_turn,
        attachment_id="attachment_two",
        ordinal=1,
        display_name="two.txt",
        role=AttachmentRole.REFERENCE,
        source=AttachmentSource.SIMULATED,
        media_type=AttachmentMediaType.TEXT,
        content=b"same",
        inspected_at=NOW,
        committed_at=NOW,
    )
    with pytest.raises(ValidationError, match="duplicate attachment content"):
        commit_attachment_manifest(
            turn=attachment_turn,
            manifest_id="manifest_main",
            attachments=(first, second),
            committed_at=NOW,
        )


def test_manifest_rejects_non_contiguous_ordinals(attachment_turn, attachment_committed_items):
    payload = attachment_committed_items[1].model_dump()
    payload["ordinal"] = 3
    # Recompute through commit to avoid a metadata-digest failure masking the ordinal rule.
    second = commit_attachment(
        turn=attachment_turn,
        attachment_id="attachment_second",
        ordinal=3,
        display_name="second.txt",
        role=AttachmentRole.REFERENCE,
        source=AttachmentSource.SIMULATED,
        media_type=AttachmentMediaType.TEXT,
        content=b"second",
        inspected_at=NOW,
        committed_at=NOW,
    )
    with pytest.raises(ValidationError, match="ordinals"):
        commit_attachment_manifest(
            turn=attachment_turn,
            manifest_id="manifest_main",
            attachments=(attachment_committed_items[0], second),
            committed_at=NOW,
        )


def test_verify_attachment_manifest_detects_other_turn(attachment_turn, attachment_manifest, attachment_principal):
    other = commit_text_turn(
        conversation_id="conv_other",
        turn_id="turn_other",
        trace_id="trace_other",
        idempotency_key="turn_other_idem",
        principal=attachment_principal,
        committed_at=NOW,
        parts=("other",),
    )
    with pytest.raises(AttachmentVerificationError) as exc_info:
        verify_attachment_manifest(manifest=attachment_manifest, turn=other)
    assert exc_info.value.reason is AttachmentVerificationReason.MANIFEST_BINDING_CHANGED


def test_manifest_rejects_digest_tampering(attachment_manifest):
    payload = attachment_manifest.model_dump()
    payload["manifest_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="manifest digest mismatch"):
        AttachmentManifest.model_validate(payload)


@pytest.mark.parametrize(
    "content",
    [
        b"\x0b{}",
        b"{}\x0c",
        "\u00a0{}".encode("utf-8"),
        "{}\u00a0".encode("utf-8"),
    ],
)
def test_json_rejects_non_json_whitespace(content):
    with pytest.raises(AttachmentInspectionError) as exc_info:
        inspect_attachment_bytes(
            content=content,
            media_type=AttachmentMediaType.JSON,
            inspected_at=NOW,
        )
    assert exc_info.value.reason is AttachmentInspectionReason.INVALID_JSON


def test_jpeg_requires_start_of_scan():
    content = make_jpeg()
    without_sos = content[: content.index(b"\xff\xda")] + b"\xff\xd9"
    with pytest.raises(AttachmentInspectionError) as exc_info:
        inspect_attachment_bytes(
            content=without_sos,
            media_type=AttachmentMediaType.JPEG,
            inspected_at=NOW,
        )
    assert exc_info.value.reason is AttachmentInspectionReason.INVALID_JPEG


def test_jpeg_requires_non_empty_scan_data():
    content = make_jpeg()
    without_scan_data = content[:-4] + b"\xff\xd9"
    with pytest.raises(AttachmentInspectionError) as exc_info:
        inspect_attachment_bytes(
            content=without_scan_data,
            media_type=AttachmentMediaType.JPEG,
            inspected_at=NOW,
        )
    assert exc_info.value.reason is AttachmentInspectionReason.INVALID_JPEG


def test_verify_attachment_rejects_time_before_commit(attachment_committed_items):
    attachment = attachment_committed_items[0]
    with pytest.raises(AttachmentVerificationError) as exc_info:
        verify_attachment_bytes(
            attachment=attachment,
            content=make_png(10, 20),
            verified_at=NOW - timedelta(microseconds=1),
        )
    assert exc_info.value.reason is AttachmentVerificationReason.VERIFICATION_BEFORE_COMMIT


def test_verify_attachment_detects_in_memory_integrity_drift(attachment_committed_items):
    attachment = attachment_committed_items[0]
    attachment.inspection.byte_size += 1
    with pytest.raises(AttachmentVerificationError) as exc_info:
        verify_attachment_bytes(
            attachment=attachment,
            content=make_png(10, 20),
            verified_at=NOW,
        )
    assert exc_info.value.reason is AttachmentVerificationReason.ATTACHMENT_INTEGRITY_CHANGED


def test_verify_manifest_detects_in_memory_integrity_drift(attachment_manifest, attachment_turn):
    attachment_manifest.total_bytes += 1
    with pytest.raises(AttachmentVerificationError) as exc_info:
        verify_attachment_manifest(
            manifest=attachment_manifest,
            turn=attachment_turn,
        )
    assert exc_info.value.reason is AttachmentVerificationReason.MANIFEST_INTEGRITY_CHANGED
