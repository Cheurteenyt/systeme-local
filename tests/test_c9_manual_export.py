from __future__ import annotations

import json
import os
import stat
import struct
import zlib
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import pytest

from systeme_local_gateway.c9_attachment_security import (
    C9AttachmentDescriptor,
    C9AttachmentSecurity,
    C9OutboundManifest,
    C9OutboundSurface,
)
from systeme_local_gateway.c9_manual_export import (
    C9ManualCleanupReason,
    C9ManualExport,
    C9ManualExportError,
    C9ManualExportManager,
    C9ManualExportReason,
)
from systeme_local_gateway.c9_private_state import (
    C9PrivatePermissions,
    C9PrivateStateError,
    C9PrivateStateReason,
)

from conftest import NOW, png_chunk

_MANIFEST_SHA256 = "a" * 64


def _valid_png() -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00\xff")
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", pixels)
        + png_chunk(b"IEND", b"")
    )


@dataclass(frozen=True)
class _Bundle:
    store: C9AttachmentSecurity
    manifest: C9OutboundManifest
    payloads: tuple[tuple[C9AttachmentDescriptor, bytes], ...]


def _bundle(tmp_path: Path, *, suffix: str = "") -> _Bundle:
    image_path = tmp_path / f"proof{suffix}.png"
    document_path = tmp_path / f"proof{suffix}.txt"
    image_path.write_bytes(_valid_png())
    document_path.write_text(
        "C9 native Chat proof document.\r\nUTF-8: très précis.\r\n",
        encoding="utf-8",
    )
    store = C9AttachmentSecurity()
    leases = (
        store.select_file(
            image_path,
            operator_confirmed=True,
            selected_at=NOW,
        ),
        store.select_file(
            document_path,
            operator_confirmed=True,
            selected_at=NOW,
        ),
    )
    manifest = store.create_outbound_manifest(
        tuple(item.lease_id for item in leases),
        surface=C9OutboundSurface.CHATGPT_CHAT_MANUAL,
        purpose="C9 manual native Chat image and UTF-8 document proof",
        created_at=NOW + timedelta(seconds=1),
    )
    payloads = store.inspect_manifest_payloads(
        manifest,
        inspected_at=NOW + timedelta(seconds=2),
        inspector=lambda values: tuple(
            (descriptor, bytes(content)) for descriptor, content in values
        ),
    )
    return _Bundle(store=store, manifest=manifest, payloads=payloads)


def _materialize(
    manager: C9ManualExportManager,
    bundle: _Bundle,
    *,
    created_offset: int = 3,
    ttl: timedelta = timedelta(minutes=5),
) -> C9ManualExport:
    return manager.materialize(
        manifest_sha256=bundle.manifest.manifest_sha256,
        payloads=bundle.payloads,
        created_at=NOW + timedelta(seconds=created_offset),
        ttl=ttl,
    )


def test_materializes_exact_private_payloads_and_cleans_them(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    state_root = tmp_path / "exports"
    manager = C9ManualExportManager(state_root, started_at=NOW)

    export = _materialize(manager, bundle)

    assert export.manifest_sha256 == bundle.manifest.manifest_sha256
    assert export.attachment_count == 2
    assert tuple(item.display_name for item in export.items) == (
        "proof.png",
        "proof.txt",
    )
    assert tuple(item.content_sha256 for item in export.items) == tuple(
        descriptor.sanitized_inspection.content_sha256 for descriptor, _ in bundle.payloads
    )
    assert tuple(item.byte_size for item in export.items) == tuple(
        len(content) for _, content in bundle.payloads
    )

    picker_paths = manager.claim_paths(
        export.export_id,
        claimed_at=NOW + timedelta(seconds=4),
    )
    assert tuple(path.read_bytes() for path in picker_paths) == tuple(
        content for _, content in bundle.payloads
    )
    if os.name == "posix":
        assert stat.S_IMODE(os.lstat(state_root).st_mode) == 0o700
        assert stat.S_IMODE(os.lstat(state_root / export.export_id).st_mode) == 0o700
        assert all(stat.S_IMODE(os.lstat(path).st_mode) == 0o600 for path in picker_paths)

    receipt = manager.cleanup(
        export.export_id,
        cleaned_at=NOW + timedelta(seconds=5),
    )

    assert receipt.reason is C9ManualCleanupReason.COMPLETED
    assert receipt.picker_claimed is True
    assert receipt.integrity_verified_before_delete is True
    assert receipt.all_entries_removed is True
    assert receipt.deleted_entry_count == 3
    assert not (state_root / export.export_id).exists()
    assert manager.terminal_receipt(export.export_id) == receipt


def test_public_models_and_receipts_never_serialize_paths_or_content(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path)
    state_root = tmp_path / "private-export-root"
    manager = C9ManualExportManager(state_root, started_at=NOW)
    export = _materialize(manager, bundle)
    manager.claim_paths(export.export_id, claimed_at=NOW + timedelta(seconds=4))
    receipt = manager.cleanup(export.export_id, cleaned_at=NOW + timedelta(seconds=5))

    serialized = json.dumps(
        {
            "export": export.model_dump(mode="json"),
            "receipt": receipt.model_dump(mode="json"),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    forbidden_keys = {
        "path",
        "source_path",
        "raw_path",
        "directory",
        "content",
        "bytes",
        "blob",
        "base64",
        "data",
    }

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                assert key not in forbidden_keys
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(export.model_dump(mode="json"))
    walk(receipt.model_dump(mode="json"))
    assert str(tmp_path) not in serialized
    assert bundle.payloads[1][1].decode("utf-8") not in serialized
    assert "iVBOR" not in serialized


def test_rejects_path_escape_in_unvalidated_descriptor(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    manager = C9ManualExportManager(tmp_path / "exports", started_at=NOW)
    descriptor, content = bundle.payloads[1]
    malicious = descriptor.model_copy(update={"display_name": "../outside.txt"})
    payloads = (bundle.payloads[0], (malicious, content))

    with pytest.raises(C9ManualExportError) as caught:
        manager.materialize(
            manifest_sha256=bundle.manifest.manifest_sha256,
            payloads=payloads,
            created_at=NOW + timedelta(seconds=3),
        )

    assert caught.value.reason is C9ManualExportReason.INVALID_ATTACHMENT_SET
    assert not (tmp_path / "outside.txt").exists()


def test_rejects_relative_traversing_or_symlink_state_root(tmp_path: Path) -> None:
    with pytest.raises(C9ManualExportError) as caught:
        C9ManualExportManager(Path("relative") / ".." / "exports", started_at=NOW)
    assert caught.value.reason is C9ManualExportReason.INVALID_STATE_ROOT

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked-exports"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this platform")
    with pytest.raises(C9ManualExportError) as caught:
        C9ManualExportManager(link, started_at=NOW)
    assert caught.value.reason is C9ManualExportReason.INVALID_STATE_ROOT


def test_atomic_directory_collision_retries_without_reusing_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(tmp_path)
    state_root = tmp_path / "exports"
    manager = C9ManualExportManager(state_root, started_at=NOW)
    collision = state_root / ("c9_export_" + "1" * 32)
    collision.mkdir()
    sentinel = collision / "sentinel"
    sentinel.write_text("untouched", encoding="utf-8")
    tokens = iter(("1" * 32, "2" * 32))
    monkeypatch.setattr(
        "systeme_local_gateway.c9_manual_export.secrets.token_hex",
        lambda _: next(tokens),
    )

    export = _materialize(manager, bundle)

    assert export.export_id == "c9_export_" + "2" * 32
    assert sentinel.read_text(encoding="utf-8") == "untouched"


def test_ttl_ceiling_expiry_and_replay_are_fail_closed(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    manager = C9ManualExportManager(tmp_path / "exports", started_at=NOW)

    with pytest.raises(C9ManualExportError) as caught:
        _materialize(manager, bundle, ttl=timedelta(minutes=10, microseconds=1))
    assert caught.value.reason is C9ManualExportReason.INVALID_TTL

    export = _materialize(manager, bundle, ttl=timedelta(seconds=1))
    with pytest.raises(C9ManualExportError) as caught:
        manager.claim_paths(
            export.export_id,
            claimed_at=NOW + timedelta(seconds=5),
        )
    assert caught.value.reason is C9ManualExportReason.EXPORT_EXPIRED
    receipt = manager.terminal_receipt(export.export_id)
    assert receipt is not None
    assert receipt.reason is C9ManualCleanupReason.EXPIRED
    assert not (tmp_path / "exports" / export.export_id).exists()

    with pytest.raises(C9ManualExportError) as caught:
        manager.claim_paths(
            export.export_id,
            claimed_at=NOW + timedelta(seconds=6),
        )
    assert caught.value.reason is C9ManualExportReason.EXPORT_REPLAY


def test_picker_claim_is_at_most_once_and_cleanup_is_not_replayable(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path)
    manager = C9ManualExportManager(tmp_path / "exports", started_at=NOW)
    export = _materialize(manager, bundle)
    manager.claim_paths(export.export_id, claimed_at=NOW + timedelta(seconds=4))

    with pytest.raises(C9ManualExportError) as caught:
        manager.claim_paths(export.export_id, claimed_at=NOW + timedelta(seconds=5))
    assert caught.value.reason is C9ManualExportReason.EXPORT_REPLAY

    manager.cleanup(export.export_id, cleaned_at=NOW + timedelta(seconds=6))
    with pytest.raises(C9ManualExportError) as caught:
        manager.cleanup(export.export_id, cleaned_at=NOW + timedelta(seconds=7))
    assert caught.value.reason is C9ManualExportReason.EXPORT_REPLAY


def test_cleanup_deletes_mutated_export_and_records_integrity_false(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path)
    state_root = tmp_path / "exports"
    manager = C9ManualExportManager(state_root, started_at=NOW)
    export = _materialize(manager, bundle)
    paths = manager.claim_paths(export.export_id, claimed_at=NOW + timedelta(seconds=4))
    paths[1].write_text("mutated after picker claim", encoding="utf-8")
    unexpected = state_root / export.export_id / "unexpected.bin"
    unexpected.write_bytes(b"untrusted")

    receipt = manager.cleanup(
        export.export_id,
        cleaned_at=NOW + timedelta(seconds=5),
    )

    assert receipt.integrity_verified_before_delete is False
    assert receipt.all_entries_removed is True
    assert receipt.deleted_entry_count == 4
    assert not (state_root / export.export_id).exists()


def test_cleanup_unlinks_symlink_without_touching_target(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    manager = C9ManualExportManager(tmp_path / "exports", started_at=NOW)
    export = _materialize(manager, bundle)
    paths = manager.claim_paths(export.export_id, claimed_at=NOW + timedelta(seconds=4))
    outside = tmp_path / "outside-do-not-delete.txt"
    outside.write_text("outside", encoding="utf-8")
    paths[0].unlink()
    try:
        paths[0].symlink_to(outside)
    except OSError:
        pytest.skip("file symlinks are unavailable on this platform")

    receipt = manager.cleanup(
        export.export_id,
        cleaned_at=NOW + timedelta(seconds=5),
    )

    assert receipt.integrity_verified_before_delete is False
    assert receipt.all_entries_removed is True
    assert outside.read_text(encoding="utf-8") == "outside"
    assert not paths[0].exists()


def test_hardlink_drift_is_detected_before_delete(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    manager = C9ManualExportManager(tmp_path / "exports", started_at=NOW)
    export = _materialize(manager, bundle)
    paths = manager.claim_paths(export.export_id, claimed_at=NOW + timedelta(seconds=4))
    outside_link = tmp_path / "external-hardlink.txt"
    try:
        os.link(paths[1], outside_link)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")

    receipt = manager.cleanup(
        export.export_id,
        cleaned_at=NOW + timedelta(seconds=5),
    )

    assert receipt.integrity_verified_before_delete is False
    assert receipt.all_entries_removed is True
    assert outside_link.exists()
    assert not (tmp_path / "exports" / export.export_id).exists()


def test_startup_cleanup_removes_only_well_formed_orphan_directories(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "exports"
    state_root.mkdir()
    orphan_id = "c9_export_" + "4" * 32
    orphan = state_root / orphan_id
    orphan.mkdir()
    (orphan / "old.txt").write_text("orphan", encoding="utf-8")
    unrelated = state_root / "keep-me"
    unrelated.mkdir()
    (unrelated / "state.txt").write_text("keep", encoding="utf-8")
    malformed = state_root / "c9_export_short"
    malformed.mkdir()
    matching_regular_file = state_root / ("c9_export_" + "5" * 32)
    matching_regular_file.write_text("not an orphan directory", encoding="utf-8")

    manager = C9ManualExportManager(state_root, started_at=NOW)

    assert not orphan.exists()
    assert unrelated.exists()
    assert malformed.exists()
    assert matching_regular_file.exists()
    assert len(manager.startup_cleanup_receipts) == 1
    receipt = manager.startup_cleanup_receipts[0]
    assert receipt.export_id == orphan_id
    assert receipt.removed is True
    assert receipt.integrity_verifiable is False


def test_cancel_all_and_close_remove_every_active_export(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    manager = C9ManualExportManager(tmp_path / "exports", started_at=NOW)
    first = _materialize(manager, bundle, created_offset=3)
    second = _materialize(manager, bundle, created_offset=4)

    receipts = manager.close(closed_at=NOW + timedelta(seconds=5))

    assert {receipt.export_id for receipt in receipts} == {
        first.export_id,
        second.export_id,
    }
    assert all(receipt.reason is C9ManualCleanupReason.MANAGER_CLOSED for receipt in receipts)
    assert manager.close(closed_at=NOW + timedelta(seconds=6)) == ()
    with pytest.raises(C9ManualExportError) as caught:
        _materialize(manager, bundle, created_offset=7)
    assert caught.value.reason is C9ManualExportReason.MANAGER_CLOSED


@dataclass
class _FakeWindowsAcl:
    owner_only: bool = True
    fail_apply: bool = False
    applied: list[tuple[Path, bool]] = field(default_factory=list)

    def apply_owner_only(self, path: Path, *, directory: bool) -> None:
        if self.fail_apply:
            raise C9PrivateStateError(
                C9PrivateStateReason.PRIVATE_PERMISSIONS_FAILED,
                "synthetic ACL failure",
            )
        self.applied.append((path, directory))

    def is_owner_only(self, path: Path, *, directory: bool) -> bool:
        return self.owner_only and (path, directory) in self.applied


def test_windows_effective_token_acl_covers_root_directory_and_files(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path)
    backend = _FakeWindowsAcl()
    permissions = C9PrivatePermissions(
        platform_name="nt",
        windows_backend=backend,
    )

    manager = C9ManualExportManager(
        tmp_path / "exports",
        started_at=NOW,
        platform_name="nt",
        private_permissions=permissions,
    )
    export = _materialize(manager, bundle)

    applied = set(backend.applied)
    export_root = tmp_path / "exports"
    export_directory = export_root / export.export_id
    assert (export_root, True) in applied
    assert (export_directory, True) in applied
    assert {path for path, directory in applied if not directory} == {
        export_directory / item.display_name for item in export.items
    }


def test_windows_refuses_a_dacl_with_an_explicit_non_owner_ace(
    tmp_path: Path,
) -> None:
    permissions = C9PrivatePermissions(
        platform_name="nt",
        windows_backend=_FakeWindowsAcl(owner_only=False),
    )

    with pytest.raises(C9ManualExportError) as caught:
        C9ManualExportManager(
            tmp_path / "exports",
            started_at=NOW,
            platform_name="nt",
            private_permissions=permissions,
        )
    assert caught.value.reason is C9ManualExportReason.PRIVATE_PERMISSIONS_FAILED


def test_windows_acl_failure_is_fatal(tmp_path: Path) -> None:
    permissions = C9PrivatePermissions(
        platform_name="nt",
        windows_backend=_FakeWindowsAcl(fail_apply=True),
    )

    with pytest.raises(C9ManualExportError) as caught:
        C9ManualExportManager(
            tmp_path / "exports",
            started_at=NOW,
            platform_name="nt",
            private_permissions=permissions,
        )
    assert caught.value.reason is C9ManualExportReason.PRIVATE_PERMISSIONS_FAILED
