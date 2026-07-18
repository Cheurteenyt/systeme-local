from __future__ import annotations

import json
import struct
import zlib
from datetime import datetime, timezone

import pytest

from systeme_local_gateway.providers.attachment_commit import (
    commit_attachment,
    commit_attachment_manifest,
)
from systeme_local_gateway.providers.attachment_models import (
    AttachmentCapabilityProfile,
    AttachmentMediaType,
    AttachmentQuotaRequirement,
    AttachmentRole,
    AttachmentSource,
    commit_attachment_capability_profile,
)
from systeme_local_gateway.providers.models import (
    AgentPrincipalRef,
    CapabilityClaim,
    CapabilityEvidence,
    CapabilitySupport,
    commit_text_turn,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)


def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type)
    crc = zlib.crc32(data, crc) & 0xFFFFFFFF
    return len(data).to_bytes(4, "big") + chunk_type + data + crc.to_bytes(4, "big")


def make_png(width: int = 2, height: int = 3) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", b"\x00")
        + png_chunk(b"IEND", b"")
    )


def make_jpeg(width: int = 4, height: int = 5) -> bytes:
    sof_payload = bytes([8]) + height.to_bytes(2, "big") + width.to_bytes(2, "big") + bytes([1])
    sof_payload += bytes([1, 0x11, 0])
    sof = b"\xff\xc0" + (len(sof_payload) + 2).to_bytes(2, "big") + sof_payload
    sos_payload = bytes([1, 1, 0, 0, 63, 0])
    sos = b"\xff\xda" + (len(sos_payload) + 2).to_bytes(2, "big") + sos_payload
    return b"\xff\xd8" + sof + sos + b"\x00\x01\xff\xd9"


def make_pdf() -> bytes:
    return b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\nstartxref\n9\n%%EOF\n"


@pytest.fixture
def attachment_principal() -> AgentPrincipalRef:
    return AgentPrincipalRef(
        agent_id="agent_main",
        instance_id="instance_main",
        key_id="key_main",
        verification_id="verify_main",
    )


@pytest.fixture
def attachment_turn(attachment_principal: AgentPrincipalRef):
    return commit_text_turn(
        conversation_id="conv_main",
        turn_id="turn_main",
        trace_id="trace_main",
        idempotency_key="turn_idempotency",
        principal=attachment_principal,
        committed_at=NOW,
        parts=("analyze attachments",),
    )


@pytest.fixture
def attachment_committed_items(attachment_turn):
    contents = (
        ("shot.png", AttachmentMediaType.PNG, make_png(10, 20), AttachmentRole.SCREENSHOT),
        ("notes.txt", AttachmentMediaType.TEXT, b"hello\n", AttachmentRole.REFERENCE),
        (
            "data.json",
            AttachmentMediaType.JSON,
            json.dumps({"ok": True}, separators=(",", ":")).encode(),
            AttachmentRole.DATA,
        ),
    )
    items = []
    for ordinal, (name, media_type, content, role) in enumerate(contents):
        items.append(
            commit_attachment(
                turn=attachment_turn,
                attachment_id=f"attachment_{ordinal}",
                ordinal=ordinal,
                display_name=name,
                role=role,
                source=AttachmentSource.SIMULATED,
                media_type=media_type,
                content=content,
                inspected_at=NOW,
                committed_at=NOW,
            )
        )
    return tuple(items)


@pytest.fixture
def attachment_manifest(attachment_turn, attachment_committed_items):
    return commit_attachment_manifest(
        turn=attachment_turn,
        manifest_id="manifest_main",
        attachments=attachment_committed_items,
        committed_at=NOW,
    )


@pytest.fixture
def attachment_supported_profile() -> AttachmentCapabilityProfile:
    return commit_attachment_capability_profile(
        profile_id="attachment_profile_main",
        revision=1,
        provider="chatgpt",
        surface="deterministic_fake_attachment",
        support=CapabilityClaim(
            state=CapabilitySupport.SUPPORTED,
            evidence=CapabilityEvidence.SIMULATED,
        ),
        supported_media_types=(
            AttachmentMediaType.PNG,
            AttachmentMediaType.JPEG,
            AttachmentMediaType.PDF,
            AttachmentMediaType.TEXT,
            AttachmentMediaType.JSON,
        ),
        max_file_bytes=1024 * 1024,
        max_batch_bytes=1024 * 1024,
        max_manifest_bytes=4 * 1024 * 1024,
        max_files_per_batch=2,
        max_files_per_manifest=10,
        max_batches_per_manifest=10,
        max_image_width=4096,
        max_image_height=4096,
        max_image_pixels=16_777_216,
        allows_mixed_media=True,
        quota_requirement=AttachmentQuotaRequirement.NONE,
        observed_at=NOW,
    )
