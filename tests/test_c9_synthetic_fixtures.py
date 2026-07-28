from __future__ import annotations

import json
import os
import struct
import zlib
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

import systeme_local_gateway.c9_synthetic_fixtures as fixtures
from systeme_local_gateway.c9_attachment_security import C9AttachmentSecurity
from systeme_local_gateway.c9_synthetic_fixtures import (
    C9SyntheticFixtureError,
    C9SyntheticFixtureKind,
    C9SyntheticFixtureReason,
    C9SyntheticFixtureReceipt,
    generate_c9_synthetic_fixtures,
)
from systeme_local_gateway.providers.attachment_commit import inspect_attachment_bytes
from systeme_local_gateway.providers.attachment_models import AttachmentMediaType

NOW = datetime(2026, 7, 28, 1, 2, 3, tzinfo=UTC)
PNG_NONCE = "C9" + "0123456789ABCDEF" * 2
TEXT_NONCE = "C9" + "FEDCBA9876543210" * 2


def _deterministic_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    values = iter(
        (
            PNG_NONCE[2:].lower(),
            TEXT_NONCE[2:].lower(),
            "2" * 32,
            "3" * 32,
        )
    )

    def token_hex(byte_count: int) -> str:
        assert byte_count == 16
        return next(values)

    monkeypatch.setattr(fixtures.secrets, "token_hex", token_hex)


def _png_chunks(content: bytes) -> tuple[tuple[bytes, bytes], ...]:
    assert content.startswith(b"\x89PNG\r\n\x1a\n")
    chunks: list[tuple[bytes, bytes]] = []
    offset = 8
    while offset < len(content):
        length = int.from_bytes(content[offset : offset + 4], "big")
        chunk_type = content[offset + 4 : offset + 8]
        payload = content[offset + 8 : offset + 8 + length]
        chunks.append((chunk_type, payload))
        offset += 12 + length
    assert offset == len(content)
    return tuple(chunks)


def _png_pixels(content: bytes) -> bytes:
    chunks = _png_chunks(content)
    assert tuple(kind for kind, _ in chunks) == (b"IHDR", b"IDAT", b"IEND")
    width, height, depth, color, compression, filtering, interlace = struct.unpack(
        ">IIBBBBB",
        chunks[0][1],
    )
    assert (width, height) == (
        fixtures.C9_SYNTHETIC_IMAGE_WIDTH,
        fixtures.C9_SYNTHETIC_IMAGE_HEIGHT,
    )
    assert (depth, color, compression, filtering, interlace) == (8, 0, 0, 0, 0)
    scanlines = zlib.decompress(chunks[1][1])
    row_bytes = width + 1
    assert len(scanlines) == height * row_bytes
    assert all(scanlines[row * row_bytes] == 0 for row in range(height))
    return b"".join(scanlines[row * row_bytes + 1 : (row + 1) * row_bytes] for row in range(height))


def _assert_visible_nonce(pixels: bytes, nonce: str) -> None:
    scale = fixtures._GLYPH_SCALE
    width = fixtures.C9_SYNTHETIC_IMAGE_WIDTH
    rendered_width = len(nonce) * (5 * scale + scale) - scale
    start_x = (width - rendered_width) // 2
    start_y = (fixtures.C9_SYNTHETIC_IMAGE_HEIGHT - 7 * scale) // 2
    for glyph_index, character in enumerate(nonce):
        glyph_x = start_x + glyph_index * (5 * scale + scale)
        for row_index, row in enumerate(fixtures._FONT_5X7[character]):
            for column_index, bit in enumerate(row):
                x = glyph_x + column_index * scale + scale // 2
                y = start_y + row_index * scale + scale // 2
                expected = 0 if bit == "1" else 255
                assert pixels[y * width + x] == expected


def test_generates_exactly_one_canonical_png_and_text_with_visible_nonces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _deterministic_tokens(monkeypatch)
    handle = generate_c9_synthetic_fixtures(tmp_path, generated_at=NOW)

    package_files = tuple(sorted(path.name for path in handle.png_path.parent.iterdir()))
    assert package_files == ("c9-synthetic-proof.png", "c9-synthetic-proof.txt")

    png_content = handle.png_path.read_bytes()
    text_content = handle.text_path.read_bytes()
    _assert_visible_nonce(_png_pixels(png_content), PNG_NONCE)
    assert text_content.decode("utf-8", errors="strict") == (
        f"C9 SYNTHETIC TEXT ATTACHMENT PROOF\nNONCE {TEXT_NONCE}\nSYNTHETIC DATA ONLY\n"
    )
    assert b"\r" not in text_content
    assert handle.verify_observed_nonce(C9SyntheticFixtureKind.IMAGE, PNG_NONCE)
    assert handle.verify_observed_nonce(C9SyntheticFixtureKind.TEXT, TEXT_NONCE)
    assert not handle.verify_observed_nonce(C9SyntheticFixtureKind.TEXT, PNG_NONCE)

    handle.cleanup(cleaned_at=NOW + timedelta(seconds=1))


def test_receipt_binds_hashes_sizes_dimensions_and_contains_no_private_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _deterministic_tokens(monkeypatch)
    handle = generate_c9_synthetic_fixtures(tmp_path, generated_at=NOW)
    receipt = handle.receipt
    image, text = receipt.fixtures

    assert image.content_sha256 == sha256(handle.png_path.read_bytes()).hexdigest()
    assert text.content_sha256 == sha256(handle.text_path.read_bytes()).hexdigest()
    assert image.byte_size == handle.png_path.stat().st_size
    assert text.byte_size == handle.text_path.stat().st_size
    assert (image.image_width, image.image_height) == (
        fixtures.C9_SYNTHETIC_IMAGE_WIDTH,
        fixtures.C9_SYNTHETIC_IMAGE_HEIGHT,
    )
    assert text.image_width is None and text.image_height is None
    assert image.nonce_sha256 == sha256(PNG_NONCE.encode("ascii")).hexdigest()
    assert text.nonce_sha256 == sha256(TEXT_NONCE.encode("ascii")).hexdigest()

    public_json = receipt.model_dump_json()
    public_repr = repr(receipt)
    serialized = public_json + public_repr
    assert PNG_NONCE not in serialized
    assert TEXT_NONCE not in serialized
    assert os.fspath(tmp_path) not in serialized
    assert os.fspath(handle.png_path) not in serialized
    assert os.fspath(handle.text_path) not in serialized
    assert "base64" not in serialized.lower()
    assert not any(
        isinstance(value, bytes)
        for fixture in receipt.model_dump(mode="python")["fixtures"]
        for value in fixture.values()
    )

    handle.cleanup(cleaned_at=NOW + timedelta(seconds=1))


def test_existing_attachment_inspector_and_security_sanitizer_accept_exact_bytes(
    tmp_path: Path,
) -> None:
    handle = generate_c9_synthetic_fixtures(tmp_path, generated_at=NOW)
    image_metadata, text_metadata = handle.receipt.fixtures
    png_content = handle.png_path.read_bytes()
    text_content = handle.text_path.read_bytes()

    png_inspection = inspect_attachment_bytes(
        content=png_content,
        media_type=AttachmentMediaType.PNG,
        inspected_at=NOW,
    )
    text_inspection = inspect_attachment_bytes(
        content=text_content,
        media_type=AttachmentMediaType.TEXT,
        inspected_at=NOW,
    )
    assert png_inspection.content_sha256 == image_metadata.content_sha256
    assert text_inspection.content_sha256 == text_metadata.content_sha256

    security = C9AttachmentSecurity()
    png_lease = security.select_file(
        handle.png_path,
        operator_confirmed=True,
        selected_at=NOW,
    )
    text_lease = security.select_file(
        handle.text_path,
        operator_confirmed=True,
        selected_at=NOW,
    )
    assert png_lease.descriptor.sanitized_inspection.content_sha256 == (
        image_metadata.content_sha256
    )
    assert text_lease.descriptor.sanitized_inspection.content_sha256 == (
        text_metadata.content_sha256
    )
    assert png_lease.descriptor.metadata_removed is False
    assert text_lease.descriptor.metadata_removed is False

    security.close(closed_at=NOW + timedelta(seconds=1))
    handle.cleanup(cleaned_at=NOW + timedelta(seconds=2))


def test_receipt_digest_rejects_hash_tampering(tmp_path: Path) -> None:
    handle = generate_c9_synthetic_fixtures(tmp_path, generated_at=NOW)
    payload = handle.receipt.model_dump(mode="python")
    payload["fixtures"][0]["content_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="digest mismatch"):
        C9SyntheticFixtureReceipt.model_validate(payload)

    handle.cleanup(cleaned_at=NOW + timedelta(seconds=1))


def test_two_packages_have_four_independent_nonce_and_content_commitments(
    tmp_path: Path,
) -> None:
    first = generate_c9_synthetic_fixtures(tmp_path, generated_at=NOW)
    second = generate_c9_synthetic_fixtures(
        tmp_path,
        generated_at=NOW + timedelta(microseconds=1),
    )

    nonce_hashes = {
        item.nonce_sha256
        for receipt in (first.receipt, second.receipt)
        for item in receipt.fixtures
    }
    content_hashes = {
        item.content_sha256
        for receipt in (first.receipt, second.receipt)
        for item in receipt.fixtures
    }
    assert len(nonce_hashes) == 4
    assert len(content_hashes) == 4
    assert first.receipt.package_id != second.receipt.package_id

    first.cleanup(cleaned_at=NOW + timedelta(seconds=1))
    second.cleanup(cleaned_at=NOW + timedelta(seconds=1))


def test_root_must_be_absolute_existing_and_not_a_reparse_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(C9SyntheticFixtureError) as relative:
        generate_c9_synthetic_fixtures(Path("relative-private-root"), generated_at=NOW)
    assert relative.value.reason is C9SyntheticFixtureReason.ROOT_NOT_ABSOLUTE

    with pytest.raises(C9SyntheticFixtureError) as absent:
        generate_c9_synthetic_fixtures(tmp_path / "absent", generated_at=NOW)
    assert absent.value.reason is C9SyntheticFixtureReason.ROOT_NOT_PRIVATE_DIRECTORY

    monkeypatch.setattr(fixtures, "_is_reparse", lambda _info: True)
    with pytest.raises(C9SyntheticFixtureError) as simulated_reparse:
        generate_c9_synthetic_fixtures(tmp_path, generated_at=NOW)
    assert simulated_reparse.value.reason is C9SyntheticFixtureReason.REPARSE_PATH_REJECTED
    monkeypatch.undo()

    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except OSError:
        return
    with pytest.raises(C9SyntheticFixtureError) as linked_error:
        generate_c9_synthetic_fixtures(linked, generated_at=NOW)
    assert linked_error.value.reason is C9SyntheticFixtureReason.REPARSE_PATH_REJECTED


def test_file_writes_use_exclusive_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_open = fixtures.os.open
    observed_flags: list[int] = []

    def checked_open(path: Path, flags: int, mode: int = 0o777) -> int:
        observed_flags.append(flags)
        return real_open(path, flags, mode)

    monkeypatch.setattr(fixtures.os, "open", checked_open)
    handle = generate_c9_synthetic_fixtures(tmp_path, generated_at=NOW)

    assert len(observed_flags) == 2
    assert all(flags & os.O_EXCL for flags in observed_flags)
    assert all(flags & os.O_CREAT for flags in observed_flags)
    assert all(flags & os.O_WRONLY for flags in observed_flags)

    handle.cleanup(cleaned_at=NOW + timedelta(seconds=1))


def test_cleanup_is_path_free_replay_safe_and_removes_only_fixture_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _deterministic_tokens(monkeypatch)
    unrelated = tmp_path / "keep.txt"
    unrelated.write_text("keep", encoding="utf-8")
    handle = generate_c9_synthetic_fixtures(tmp_path, generated_at=NOW)
    package_directory = handle.png_path.parent

    first = handle.cleanup(cleaned_at=NOW + timedelta(seconds=1))
    replay = handle.cleanup(cleaned_at=NOW + timedelta(days=1))

    assert first == replay
    assert first.files_removed == 2
    assert first.fixture_files_absent is True
    assert first.package_directory_absent is True
    assert not handle.png_path.exists()
    assert not handle.text_path.exists()
    assert not package_directory.exists()
    assert unrelated.read_text(encoding="utf-8") == "keep"

    public = first.model_dump_json() + repr(first)
    assert os.fspath(tmp_path) not in public
    assert PNG_NONCE not in public
    assert TEXT_NONCE not in public
    assert json.loads(first.model_dump_json())["package_directory_absent"] is True
