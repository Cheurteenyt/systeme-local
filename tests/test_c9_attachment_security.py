from __future__ import annotations

import json
import os
import struct
import zlib
from datetime import timedelta
from pathlib import Path
from threading import Event, Thread

import pytest
from pydantic import ValidationError

import systeme_local_gateway.c9_attachment_security as security_module
from systeme_local_gateway.c9_attachment_security import (
    C9AttachmentPolicy,
    C9AttachmentSecurity,
    C9AttachmentSecurityError,
    C9AttachmentSecurityReason,
    C9BoundApproval,
    C9LeaseTerminalState,
    C9OutboundManifest,
    C9OutboundSurface,
)
from systeme_local_gateway.providers.attachment_models import (
    AttachmentMediaType,
    AttachmentSource,
)

from conftest import NOW, png_chunk


def _png(*, width: int = 1, height: int = 1, metadata: bool = False) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    row = b"\x00" + b"\x11\x22\x33\xff" * width
    pixels = zlib.compress(row * height)
    chunks = [png_chunk(b"IHDR", ihdr)]
    if metadata:
        chunks.append(png_chunk(b"tEXt", b"Author\x00private metadata"))
    chunks.extend((png_chunk(b"IDAT", pixels), png_chunk(b"IEND", b"")))
    return b"\x89PNG\r\n\x1a\n" + b"".join(chunks)


def _jpeg(*, metadata: bool = False) -> bytes:
    dqt_payload = b"\x00" + bytes(range(1, 65))
    dqt = b"\xff\xdb" + (len(dqt_payload) + 2).to_bytes(2, "big") + dqt_payload

    counts = b"\x01" + b"\x00" * 15
    dht_payload = b"\x00" + counts + b"\x00" + b"\x10" + counts + b"\x00"
    dht = b"\xff\xc4" + (len(dht_payload) + 2).to_bytes(2, "big") + dht_payload

    sof_payload = b"\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    sof = b"\xff\xc0" + (len(sof_payload) + 2).to_bytes(2, "big") + sof_payload
    sos_payload = b"\x01\x01\x00\x00\x3f\x00"
    sos = b"\xff\xda" + (len(sos_payload) + 2).to_bytes(2, "big") + sos_payload
    app = b""
    if metadata:
        app_payload = b"Exif\x00\x00private"
        app = b"\xff\xe1" + (len(app_payload) + 2).to_bytes(2, "big") + app_payload
    return b"\xff\xd8" + app + dqt + dht + sof + sos + b"\x01\xff\xd9"


def _select_pair(
    tmp_path: Path,
    *,
    policy: C9AttachmentPolicy | None = None,
    ttl: timedelta = timedelta(minutes=5),
) -> tuple[C9AttachmentSecurity, Path, Path, tuple[str, str]]:
    image_path = tmp_path / "proof.png"
    text_path = tmp_path / "proof.txt"
    image_path.write_bytes(_png(metadata=True))
    text_path.write_bytes(b"\xef\xbb\xbfnonce\r\n")
    store = C9AttachmentSecurity(policy)
    image = store.select_file(
        image_path,
        operator_confirmed=True,
        selected_at=NOW,
        lease_ttl=ttl,
    )
    text = store.select_file(
        text_path,
        operator_confirmed=True,
        selected_at=NOW,
        lease_ttl=ttl,
    )
    return store, image_path, text_path, (image.lease_id, text.lease_id)


def _manifest_and_approval(
    store: C9AttachmentSecurity,
    lease_ids: tuple[str, ...],
    *,
    surface: C9OutboundSurface = C9OutboundSurface.CHATGPT_WORK,
    approval_ttl: timedelta = timedelta(minutes=2),
) -> tuple[C9OutboundManifest, C9BoundApproval]:
    manifest = store.create_outbound_manifest(
        lease_ids,
        surface=surface,
        purpose="C9 synthetic file and image proof",
        created_at=NOW + timedelta(seconds=1),
    )
    approval = store.approve_manifest(
        manifest,
        operator_confirmed=True,
        operator_identity="operator-test",
        approved_at=NOW + timedelta(seconds=2),
        approval_ttl=approval_ttl,
    )
    return manifest, approval


def _assert_reason(
    reason: C9AttachmentSecurityReason,
    callback,
) -> C9AttachmentSecurityError:
    with pytest.raises(C9AttachmentSecurityError) as exc_info:
        callback()
    assert exc_info.value.reason is reason
    return exc_info.value


def test_requires_explicit_operator_confirmation_and_absolute_path(tmp_path: Path):
    selected = tmp_path / "proof.txt"
    selected.write_text("nonce", encoding="utf-8")
    store = C9AttachmentSecurity()

    _assert_reason(
        C9AttachmentSecurityReason.OPERATOR_CONFIRMATION_REQUIRED,
        lambda: store.select_file(
            selected,
            operator_confirmed=False,
            selected_at=NOW,
        ),
    )
    _assert_reason(
        C9AttachmentSecurityReason.PATH_NOT_ABSOLUTE,
        lambda: store.select_file(
            Path("proof.txt"),
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )


def test_rejects_lexical_traversal_magic_mismatch_and_pdf(tmp_path: Path):
    store = C9AttachmentSecurity()
    png_as_text = tmp_path / "wrong.txt"
    png_as_text.write_bytes(_png())
    pdf = tmp_path / "proof.pdf"
    pdf.write_bytes(b"%PDF-1.7\nstartxref\n1\n%%EOF\n")

    traversal = tmp_path / "child" / ".." / "proof.txt"
    _assert_reason(
        C9AttachmentSecurityReason.PATH_TRAVERSAL,
        lambda: store.select_file(
            traversal,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )
    _assert_reason(
        C9AttachmentSecurityReason.MEDIA_TYPE_MISMATCH,
        lambda: store.select_file(
            png_as_text,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )
    _assert_reason(
        C9AttachmentSecurityReason.MEDIA_TYPE_UNSUPPORTED,
        lambda: store.select_file(
            pdf,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )


def test_rejects_hard_link_and_reparse_component(tmp_path: Path, monkeypatch):
    original = tmp_path / "original.txt"
    linked = tmp_path / "linked.txt"
    original.write_text("nonce", encoding="utf-8")
    try:
        os.link(original, linked)
    except OSError:
        pytest.skip("filesystem does not support hard links")
    store = C9AttachmentSecurity()
    _assert_reason(
        C9AttachmentSecurityReason.HARD_LINK,
        lambda: store.select_file(
            original,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )

    monkeypatch.setattr(security_module, "_is_reparse", lambda _info: True)
    _assert_reason(
        C9AttachmentSecurityReason.REPARSE_POINT,
        lambda: store.select_file(
            original,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )


def test_png_and_text_are_sanitized_and_public_models_are_metadata_only(tmp_path: Path):
    store, image_path, text_path, lease_ids = _select_pair(tmp_path)
    manifest, _ = _manifest_and_approval(store, lease_ids)

    image, text = manifest.attachments
    assert image.metadata_removed is True
    assert text.metadata_removed is True
    assert image.media_type is AttachmentMediaType.PNG
    assert text.media_type is AttachmentMediaType.TEXT
    canonical = manifest.attachment_manifest
    assert canonical.manifest_id == manifest.manifest_id
    assert canonical.manifest_sha256 == manifest.attachment_manifest_sha256
    assert [item.source for item in canonical.attachments] == [
        AttachmentSource.OPERATOR_SELECTED,
        AttachmentSource.OPERATOR_SELECTED,
    ]
    assert [item.inspection.content_sha256 for item in canonical.attachments] == [
        item.sanitized_inspection.content_sha256 for item in manifest.attachments
    ]

    serialized = json.dumps(manifest.model_dump(mode="json"), sort_keys=True)
    assert str(image_path) not in serialized
    assert str(text_path) not in serialized
    assert "private metadata" not in serialized
    assert "nonce" not in serialized


def test_png_metadata_and_text_bom_are_removed_from_consumed_payload(tmp_path: Path):
    store, _, _, lease_ids = _select_pair(tmp_path)
    manifest, approval = _manifest_and_approval(store, lease_ids)

    def consumer(payloads):
        assert all(view.readonly for _, view in payloads)
        return tuple(bytes(view) for _, view in payloads)

    payloads, receipt = store.consume_manifest(
        manifest,
        approval,
        consumed_at=NOW + timedelta(seconds=3),
        consumer=consumer,
    )
    assert b"tEXt" not in payloads[0]
    assert payloads[1] == b"nonce\n"
    assert all(
        item.terminal_state is C9LeaseTerminalState.CONSUMED for item in receipt.cleanup_receipts
    )
    for lease_id in lease_ids:
        terminal = store.terminal_receipt(lease_id)
        assert terminal is not None
        assert terminal.byte_size_released > 0


def test_jpeg_app_metadata_is_stripped(tmp_path: Path):
    selected = tmp_path / "photo.jpg"
    selected.write_bytes(_jpeg(metadata=True))
    store = C9AttachmentSecurity()
    lease = store.select_file(
        selected,
        operator_confirmed=True,
        selected_at=NOW,
    )
    manifest, approval = _manifest_and_approval(store, (lease.lease_id,))
    payload, _ = store.consume_manifest(
        manifest,
        approval,
        consumed_at=NOW + timedelta(seconds=3),
        consumer=lambda items: bytes(items[0][1]),
    )
    assert lease.descriptor.metadata_removed is True
    assert b"Exif" not in payload
    assert payload.startswith(b"\xff\xd8\xff\xdb")


def test_media_specific_size_image_dimensions_and_decoded_memory_are_bounded(
    tmp_path: Path,
):
    text_path = tmp_path / "large.txt"
    text_path.write_bytes(b"12345")
    store = C9AttachmentSecurity(C9AttachmentPolicy(max_text_bytes=4))
    _assert_reason(
        C9AttachmentSecurityReason.FILE_TOO_LARGE,
        lambda: store.select_file(
            text_path,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )

    image_path = tmp_path / "large.png"
    image_path.write_bytes(_png(width=2, height=2))
    dimension_store = C9AttachmentSecurity(
        C9AttachmentPolicy(max_image_width=1, max_image_height=2)
    )
    _assert_reason(
        C9AttachmentSecurityReason.IMAGE_LIMIT_EXCEEDED,
        lambda: dimension_store.select_file(
            image_path,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )
    memory_store = C9AttachmentSecurity(C9AttachmentPolicy(max_decoded_image_bytes=8))
    _assert_reason(
        C9AttachmentSecurityReason.IMAGE_LIMIT_EXCEEDED,
        lambda: memory_store.select_file(
            image_path,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )


def test_malformed_or_bomb_shaped_png_fails_closed(tmp_path: Path):
    malformed = tmp_path / "malformed.png"
    malformed.write_bytes(_png()[:-4])
    store = C9AttachmentSecurity()
    _assert_reason(
        C9AttachmentSecurityReason.UNSAFE_PNG,
        lambda: store.select_file(
            malformed,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )

    bomb = tmp_path / "bomb.png"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    bomb.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", zlib.compress(b"\x00" * 1024))
        + png_chunk(b"IEND", b"")
    )
    _assert_reason(
        C9AttachmentSecurityReason.UNSAFE_PNG,
        lambda: store.select_file(
            bomb,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )


def test_text_rejects_hidden_format_controls(tmp_path: Path):
    selected = tmp_path / "hidden.txt"
    selected.write_text("safe\u202eevil", encoding="utf-8")
    store = C9AttachmentSecurity()
    _assert_reason(
        C9AttachmentSecurityReason.UNSAFE_TEXT,
        lambda: store.select_file(
            selected,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )


def test_local_inspection_is_readonly_non_consuming_and_reusable_for_approval(
    tmp_path: Path,
):
    store, _, _, lease_ids = _select_pair(tmp_path)
    manifest = store.create_outbound_manifest(
        lease_ids,
        surface=C9OutboundSurface.CHATGPT_WORK_AND_CHAT_MANUAL,
        purpose="combined local AI inspection",
        created_at=NOW + timedelta(seconds=1),
    )

    def inspector(payloads):
        assert len(payloads) == 2
        assert all(view.readonly for _, view in payloads)
        with pytest.raises(TypeError):
            payloads[0][1][0] = 0
        return tuple(len(view) for _, view in payloads)

    sizes = store.inspect_manifest_payloads(
        manifest,
        inspected_at=NOW + timedelta(seconds=2),
        inspector=inspector,
    )
    assert sizes == tuple(item.sanitized_inspection.byte_size for item in manifest.attachments)
    approval = store.approve_manifest(
        manifest,
        operator_confirmed=True,
        operator_identity="operator-test",
        approved_at=NOW + timedelta(seconds=3),
    )
    _, receipt = store.consume_manifest(
        manifest,
        approval,
        consumed_at=NOW + timedelta(seconds=4),
        consumer=lambda payloads: len(payloads),
    )
    assert len(receipt.cleanup_receipts) == 2


def test_cloned_manifest_has_same_descriptors_and_new_one_use_leases(tmp_path: Path):
    store, _, _, lease_ids = _select_pair(tmp_path)
    work_manifest = store.create_outbound_manifest(
        lease_ids,
        surface=C9OutboundSurface.CHATGPT_WORK,
        purpose="same sanitized package",
        created_at=NOW + timedelta(seconds=1),
    )
    cloned_leases, chat_manifest = store.clone_manifest_leases(
        work_manifest,
        target_surface=C9OutboundSurface.CHATGPT_CHAT_MANUAL,
        cloned_at=NOW + timedelta(seconds=2),
    )
    assert chat_manifest.surface is C9OutboundSurface.CHATGPT_CHAT_MANUAL
    assert chat_manifest.attachments == work_manifest.attachments
    assert chat_manifest.purpose_sha256 == work_manifest.purpose_sha256
    assert chat_manifest.lease_ids != work_manifest.lease_ids
    assert tuple(item.lease_id for item in cloned_leases) == chat_manifest.lease_ids
    assert (
        chat_manifest.attachment_manifest.manifest_sha256
        != work_manifest.attachment_manifest.manifest_sha256
    )

    work_approval = store.approve_manifest(
        work_manifest,
        operator_confirmed=True,
        operator_identity="operator-test",
        approved_at=NOW + timedelta(seconds=3),
    )
    chat_approval = store.approve_manifest(
        chat_manifest,
        operator_confirmed=True,
        operator_identity="operator-test",
        approved_at=NOW + timedelta(seconds=3),
    )
    store.consume_manifest(
        work_manifest,
        work_approval,
        consumed_at=NOW + timedelta(seconds=4),
        consumer=lambda payloads: len(payloads),
    )
    count, _ = store.consume_manifest(
        chat_manifest,
        chat_approval,
        consumed_at=NOW + timedelta(seconds=4),
        consumer=lambda payloads: len(payloads),
    )
    assert count == 2


def test_approval_is_bound_to_exact_manifest(tmp_path: Path):
    store, _, _, lease_ids = _select_pair(tmp_path)
    first = store.create_outbound_manifest(
        lease_ids,
        surface=C9OutboundSurface.CHATGPT_WORK,
        purpose="first",
        created_at=NOW + timedelta(seconds=1),
    )
    _, second = store.clone_manifest_leases(
        first,
        target_surface=C9OutboundSurface.CHATGPT_CHAT_MANUAL,
        cloned_at=NOW + timedelta(seconds=2),
    )
    approval = store.approve_manifest(
        first,
        operator_confirmed=True,
        operator_identity="operator-test",
        approved_at=NOW + timedelta(seconds=3),
    )
    _assert_reason(
        C9AttachmentSecurityReason.APPROVAL_INVALID,
        lambda: store.consume_manifest(
            second,
            approval,
            consumed_at=NOW + timedelta(seconds=4),
            consumer=lambda payloads: len(payloads),
        ),
    )


def test_manifest_tampering_and_unknown_fields_are_rejected(tmp_path: Path):
    store, _, _, lease_ids = _select_pair(tmp_path)
    manifest, _ = _manifest_and_approval(store, lease_ids)
    payload = manifest.model_dump(mode="python")
    payload["purpose_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="digest mismatch"):
        C9OutboundManifest.model_validate(payload)
    payload = manifest.model_dump(mode="python")
    payload["absolute_path"] = "D:\\secret.txt"
    with pytest.raises(ValidationError, match="Extra inputs"):
        C9OutboundManifest.model_validate(payload)


def test_source_mutation_after_approval_is_rejected_and_destroyed(tmp_path: Path):
    store, _, text_path, lease_ids = _select_pair(tmp_path)
    manifest, approval = _manifest_and_approval(store, lease_ids)
    text_path.write_bytes(b"tamper\n")

    _assert_reason(
        C9AttachmentSecurityReason.FILE_CHANGED,
        lambda: store.consume_manifest(
            manifest,
            approval,
            consumed_at=NOW + timedelta(seconds=3),
            consumer=lambda payloads: len(payloads),
        ),
    )
    for lease_id in lease_ids:
        receipt = store.terminal_receipt(lease_id)
        assert receipt is not None
        assert receipt.terminal_state is C9LeaseTerminalState.INTEGRITY_REJECTED


def test_successful_consumption_is_at_most_once(tmp_path: Path):
    store, _, _, lease_ids = _select_pair(tmp_path)
    manifest, approval = _manifest_and_approval(store, lease_ids)
    store.consume_manifest(
        manifest,
        approval,
        consumed_at=NOW + timedelta(seconds=3),
        consumer=lambda payloads: len(payloads),
    )
    _assert_reason(
        C9AttachmentSecurityReason.LEASE_TERMINAL,
        lambda: store.consume_manifest(
            manifest,
            approval,
            consumed_at=NOW + timedelta(seconds=4),
            consumer=lambda payloads: len(payloads),
        ),
    )


def test_consumer_failure_destroys_all_leases(tmp_path: Path):
    store, _, _, lease_ids = _select_pair(tmp_path)
    manifest, approval = _manifest_and_approval(store, lease_ids)

    def fail(_payloads):
        raise RuntimeError("provider failed")

    error = _assert_reason(
        C9AttachmentSecurityReason.CONSUMER_FAILED,
        lambda: store.consume_manifest(
            manifest,
            approval,
            consumed_at=NOW + timedelta(seconds=3),
            consumer=fail,
        ),
    )
    assert "provider failed" not in str(error)
    for lease_id in lease_ids:
        receipt = store.terminal_receipt(lease_id)
        assert receipt is not None
        assert receipt.terminal_state is C9LeaseTerminalState.CONSUMER_FAILED


def test_expiration_is_rechecked_after_consumer_callback(tmp_path: Path, monkeypatch):
    store, _, _, lease_ids = _select_pair(tmp_path)
    manifest, approval = _manifest_and_approval(
        store,
        lease_ids,
        approval_ttl=timedelta(seconds=1),
    )
    ticks = iter((100.0, 102.0))
    monkeypatch.setattr(security_module.time, "monotonic", lambda: next(ticks))

    _assert_reason(
        C9AttachmentSecurityReason.APPROVAL_EXPIRED,
        lambda: store.consume_manifest(
            manifest,
            approval,
            consumed_at=NOW + timedelta(seconds=2, milliseconds=500),
            consumer=lambda payloads: len(payloads),
        ),
    )
    for lease_id in lease_ids:
        receipt = store.terminal_receipt(lease_id)
        assert receipt is not None
        assert receipt.terminal_state is C9LeaseTerminalState.EXPIRED


def test_cancel_expire_cancel_all_and_close_emit_cleanup_receipts(tmp_path: Path):
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    third = tmp_path / "third.txt"
    for index, path in enumerate((first, second, third), start=1):
        path.write_text(f"nonce-{index}", encoding="utf-8")
    store = C9AttachmentSecurity()
    lease_one = store.select_file(first, operator_confirmed=True, selected_at=NOW)
    lease_two = store.select_file(
        second,
        operator_confirmed=True,
        selected_at=NOW,
        lease_ttl=timedelta(seconds=1),
    )
    lease_three = store.select_file(third, operator_confirmed=True, selected_at=NOW)

    cancelled = store.cancel_lease(
        lease_one.lease_id,
        cancelled_at=NOW + timedelta(milliseconds=100),
    )
    assert cancelled.terminal_state is C9LeaseTerminalState.CANCELLED
    expired = store.expire(evaluated_at=NOW + timedelta(seconds=2))
    assert [item.lease_id for item in expired] == [lease_two.lease_id]
    assert expired[0].terminal_state is C9LeaseTerminalState.EXPIRED
    closed = store.close(closed_at=NOW + timedelta(seconds=3))
    assert [item.lease_id for item in closed] == [lease_three.lease_id]
    assert closed[0].terminal_state is C9LeaseTerminalState.CANCELLED
    assert store.close(closed_at=NOW + timedelta(seconds=4)) == ()

    fourth = tmp_path / "fourth.txt"
    fourth.write_text("nonce-4", encoding="utf-8")
    _assert_reason(
        C9AttachmentSecurityReason.STORE_CLOSED,
        lambda: store.select_file(
            fourth,
            operator_confirmed=True,
            selected_at=NOW + timedelta(seconds=4),
        ),
    )


def test_concurrent_close_cannot_resurrect_a_sanitized_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "concurrent.txt"
    selected.write_text("C9 concurrent close proof", encoding="utf-8")
    store = C9AttachmentSecurity()
    sanitizing = Event()
    resume = Event()
    original = security_module._sanitize

    def blocked_sanitize(*args, **kwargs):
        result = original(*args, **kwargs)
        sanitizing.set()
        if not resume.wait(timeout=5):
            raise RuntimeError("test synchronization timed out")
        return result

    monkeypatch.setattr(security_module, "_sanitize", blocked_sanitize)
    failures: list[BaseException] = []

    def select() -> None:
        try:
            store.select_file(
                selected,
                operator_confirmed=True,
                selected_at=NOW,
            )
        except BaseException as exc:  # noqa: BLE001 - thread result capture
            failures.append(exc)

    worker = Thread(target=select)
    worker.start()
    assert sanitizing.wait(timeout=5)
    assert store.close(closed_at=NOW + timedelta(seconds=1)) == ()
    resume.set()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], C9AttachmentSecurityError)
    assert failures[0].reason is C9AttachmentSecurityReason.STORE_CLOSED
    assert store.close(closed_at=NOW + timedelta(seconds=2)) == ()


def test_concurrent_close_cannot_register_a_manifest_after_terminal_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, _, lease_ids = _select_pair(tmp_path)
    hashing = Event()
    resume = Event()
    original = security_module._model_digest

    def blocked_digest(domain, model, excluded_field):
        if domain == b"systeme-local/c9/outbound-manifest/v1\0":
            hashing.set()
            if not resume.wait(timeout=5):
                raise RuntimeError("test synchronization timed out")
        return original(domain, model, excluded_field)

    monkeypatch.setattr(security_module, "_model_digest", blocked_digest)
    failures: list[BaseException] = []

    def create_manifest() -> None:
        try:
            store.create_outbound_manifest(
                lease_ids,
                surface=C9OutboundSurface.CHATGPT_WORK,
                purpose="C9 concurrent manifest close proof",
                created_at=NOW + timedelta(seconds=1),
            )
        except BaseException as exc:  # noqa: BLE001 - thread result capture
            failures.append(exc)

    worker = Thread(target=create_manifest)
    worker.start()
    assert hashing.wait(timeout=5)
    receipts = store.close(closed_at=NOW + timedelta(seconds=2))
    assert {item.lease_id for item in receipts} == set(lease_ids)
    resume.set()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], C9AttachmentSecurityError)
    assert failures[0].reason is C9AttachmentSecurityReason.STORE_CLOSED
