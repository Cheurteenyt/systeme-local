from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from systeme_local_gateway import c9_attestation, c9_git, c9_seal
from systeme_local_gateway.c9_attestation import C9FinalAttestation
from systeme_local_gateway.c9_seal import (
    C9_BASE_COMMIT,
    C9_EVIDENCE_TAG,
    C9_FINAL_STATUS,
    C9_MANIFEST_PATH,
    C9_SEAL_PATH,
    C9ChangeManifest,
    canonical_sha256,
    create_c9_manifest,
    create_c9_seal,
    rendered_json,
    verify_c9_seal,
)

ROOT = Path(__file__).resolve().parents[1]
AUDIT_KEY = "c9-seal-test-audit-key-" + ("a" * 48)
DISCOVERED_GIT = shutil.which("git")
if DISCOVERED_GIT is not None:
    _git_path = Path(DISCOVERED_GIT).resolve()
    if os.name == "nt" and _git_path.parent.name.casefold() == "cmd":
        _git_path = _git_path.parent.parent / "bin" / "git.exe"
    GIT = os.fspath(_git_path.resolve(strict=True))
else:
    GIT = None


@pytest.fixture(autouse=True)
def _bind_exact_git_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    assert GIT is not None
    monkeypatch.setenv("SLG_C9_GIT_EXECUTABLE", str(Path(GIT).resolve(strict=True)))


def _git(root: Path, *args: str) -> str:
    assert GIT is not None
    completed = subprocess.run(
        (GIT, "-c", "core.autocrlf=false", "-C", str(root), *args),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _hash(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def _clone_at_c9_base(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    assert GIT is not None
    subprocess.run(
        (
            GIT,
            "clone",
            "--quiet",
            "--shared",
            "--no-checkout",
            str(ROOT),
            str(repository),
        ),
        check=True,
        capture_output=True,
    )
    _git(repository, "config", "user.name", "C9 Seal Test")
    _git(repository, "config", "user.email", "c9-seal@example.invalid")
    _git(repository, "reset", "--hard", "--quiet", C9_BASE_COMMIT)
    return repository


def test_c9_git_executable_resolution_is_absolute_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert GIT is not None
    exact = Path(GIT).resolve(strict=True)
    assert c9_git.resolve_c9_git_executable() == exact

    monkeypatch.setenv("SLG_C9_GIT_EXECUTABLE", "git")
    with pytest.raises(ValueError, match="absolute"):
        c9_git.resolve_c9_git_executable()

    monkeypatch.delenv("SLG_C9_GIT_EXECUTABLE")
    with pytest.raises(ValueError, match="require"):
        c9_git.resolve_c9_git_executable()

    monkeypatch.setenv("SLG_C9_GIT_EXECUTABLE", str(exact))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "0")
    with pytest.raises(ValueError, match=r"GIT_\*"):
        c9_git.resolve_c9_git_executable()


def test_c9_git_executable_resolution_rejects_a_reparse_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert GIT is not None
    exact = Path(GIT).resolve(strict=True)
    target = os.lstat(exact)
    original = c9_git._is_reparse

    def mark_exact_executable(info: os.stat_result) -> bool:
        same_identity = (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino)
        return same_identity or original(info)

    monkeypatch.setattr(c9_git, "_is_reparse", mark_exact_executable)
    with pytest.raises(ValueError, match="reparse"):
        c9_git.resolve_c9_git_executable()


def test_c9_seal_scripts_export_the_reviewed_git_executable() -> None:
    for name in ("New-C9Seal.ps1", "Test-C9Seal.ps1"):
        source = (ROOT / "scripts" / "c9" / name).read_text(encoding="utf-8")
        assert "Get-C9GitExecutable" in source
        assert "SLG_C9_GIT_EXECUTABLE" in source
    verification = (ROOT / "scripts" / "c9" / "Test-C9Seal.ps1").read_text(encoding="utf-8")
    assert "exact_attestation_reverified -ne $true" in verification


def test_c9_live_verification_cli_requires_the_exact_attestation() -> None:
    with pytest.raises(SystemExit):
        c9_seal._parser().parse_args(["verify"])


def _commit(root: Path, message: str, *paths: str) -> str:
    _git(root, "add", "--", *paths)
    _git(root, "commit", "--quiet", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def _final_attestation(
    *,
    repository: Path,
    live_head: str,
) -> C9FinalAttestation:
    c8 = c9_seal.verify_c9_c8_seal_exact(repository)
    dependency_payload: dict[str, object] = {
        "version": "1",
        "status": "verified",
        "tag_target": c8.tag_target,
        "covered_head": c8.covered_head,
        "current_head": live_head,
        "tree_sha256": c8.tree_sha256,
        "final_attestation_sha256": c8.final_attestation_sha256,
        "reviewed_outcome": c8.reviewed_outcome,
        "work_call_count": c8.work_call_count,
        "revocation_verified": c8.revocation_verified,
        "tag_target_ancestor_of_head": True,
    }
    payload: dict[str, object] = {
        "version": "1",
        "status": C9_FINAL_STATUS,
        "source": "bounded_synthetic_c9_final_verifier",
        "simulated": False,
        "issue_url": "https://github.com/Cheurteenyt/systeme-local/issues/80",
        "cycle_id": "c9_cycle_" + ("1" * 32),
        "grant_id": "c9_grant_" + ("2" * 32),
        "handoff_id": "c9_handoff_" + ("3" * 32),
        "work_task_id": "c9_work_" + ("4" * 32),
        "chat_task_id": "c9_chat_" + ("5" * 32),
        "c9_live_repository_head": live_head,
        "accepted_c8_commit": c8.tag_target,
        "c8_covered_head": c8.covered_head,
        "c8_tree_sha256": c8.tree_sha256,
        "c8_final_attestation_sha256": c8.final_attestation_sha256,
        "c8_dependency_sha256": canonical_sha256(dependency_payload),
        "c8_reviewed_outcome": c8.reviewed_outcome,
        "c8_revocation_verified": True,
        "c8_live_cycle_grant_reused": False,
        "authorization_sha256": _hash("authorization"),
        "surface_observation_sha256": _hash("surface"),
        "grant_sha256": _hash("grant"),
        "stage_receipt_sha256": _hash("stage"),
        "handoff_admission_sha256": _hash("admission"),
        "combined_approval_sha256": _hash("combined"),
        "work_approval_sha256": _hash("work-approval"),
        "chat_approval_sha256": _hash("chat-approval"),
        "fixture_receipt_sha256": _hash("fixture"),
        "local_ai_receipt_sha256": _hash("local-ai"),
        "local_ai_runtime_observation_sha256": _hash("runtime-observation"),
        "work_manifest_sha256": _hash("work-manifest"),
        "chat_manifest_sha256": _hash("chat-manifest"),
        "chat_export_id": "c9_export_" + ("6" * 32),
        "chat_export_descriptor_sha256": _hash("chat-export-descriptor"),
        "chat_export_sha256": _hash("chat-export"),
        "chat_picker_claim_receipt_sha256": _hash("chat-picker-claim"),
        "attachment_content_sha256s": (
            _hash("image-content"),
            _hash("document-content"),
        ),
        "attachment_nonce_sha256s": (
            _hash("image-nonce"),
            _hash("document-nonce"),
        ),
        "work_consumption_receipt_sha256": _hash("work-consumption"),
        "chat_manual_confirmation_receipt_sha256": _hash("chat-manual-confirmation"),
        "chat_manual_cleanup_receipt_sha256": _hash("chat-manual-cleanup"),
        "work_audit_correlation_receipt_sha256": _hash("work-correlation"),
        "work_task_audit_record_sha256": _hash("work-task-audit"),
        "work_render_audit_record_sha256": _hash("work-render-audit"),
        "coordinator_close_receipt_sha256": _hash("coordinator-close"),
        "negative_test_receipt_sha256": _hash("negative-tests"),
        "revocation_receipt_sha256": _hash("revocation"),
        "work_rich_call_count": 1,
        "chat_manual_handoff_count": 1,
        "total_rich_mcp_call_count": 1,
        "work_rich_mcp_verified": True,
        "chat_manual_visible_handoff_verified": True,
        "same_sanitized_package_verified": True,
        "native_chat_plugin_invoked": False,
        "native_chat_provider_audit_correlation_claimed": False,
        "unapproved_fallback_used": False,
        "local_ai_loopback_receipt_committed": True,
        "local_ai_native_runtime_observation_committed": True,
        "regular_arbitrary_files_tested": False,
        "regular_use_readiness_claimed": False,
        "automatic_chat_to_work_switch_used": False,
        "revocation_verified": True,
        "verified_at": "2026-07-28T12:00:00Z",
    }
    attestation_sha256 = c9_attestation.canonical_sha256(payload)
    authenticated = {**payload, "attestation_sha256": attestation_sha256}
    return C9FinalAttestation(
        **authenticated,
        attestation_hmac=c9_attestation._commit_hmac(
            payload=authenticated,
            domain="final",
            audit_key=AUDIT_KEY,
        ),
    )


@dataclass(frozen=True)
class _SealedFixture:
    repository: Path
    final_attestation: Path
    live_head: str
    covered_head: str
    tag_target: str


def _build_sealed_fixture(tmp_path: Path) -> _SealedFixture:
    repository = _clone_at_c9_base(tmp_path)
    fixture = repository / "c9-seal-fixture.txt"
    fixture.write_text("bounded C9 seal fixture\n", encoding="utf-8", newline="\n")
    live_head = _commit(repository, "C9 live fixture", "c9-seal-fixture.txt")

    attestation = _final_attestation(repository=repository, live_head=live_head)
    attestation_path = tmp_path / "attestation.json"
    attestation_path.write_text(
        c9_attestation.rendered_json(attestation),
        encoding="utf-8",
        newline="\n",
    )

    manifest = create_c9_manifest(
        repository,
        final_attestation_path=attestation_path,
        audit_key=AUDIT_KEY,
    )
    manifest_path = repository / C9_MANIFEST_PATH
    manifest_path.write_text(
        rendered_json(manifest),
        encoding="utf-8",
        newline="\n",
    )
    covered_head = _commit(repository, "Commit C9 live manifest", C9_MANIFEST_PATH)

    seal = create_c9_seal(repository)
    seal_path = repository / C9_SEAL_PATH
    seal_path.write_text(rendered_json(seal), encoding="utf-8", newline="\n")
    tag_target = _commit(repository, "Seal C9 live evidence", C9_SEAL_PATH)
    _git(
        repository,
        "tag",
        "-a",
        C9_EVIDENCE_TAG,
        "-m",
        "C9 live evidence seal",
        tag_target,
    )
    return _SealedFixture(
        repository=repository,
        final_attestation=attestation_path,
        live_head=live_head,
        covered_head=covered_head,
        tag_target=tag_target,
    )


@pytest.fixture(scope="module")
def sealed_fixture(tmp_path_factory: pytest.TempPathFactory) -> _SealedFixture:
    assert GIT is not None
    name = "SLG_C9_GIT_EXECUTABLE"
    prior = os.environ.get(name)
    os.environ[name] = str(Path(GIT).resolve(strict=True))
    try:
        return _build_sealed_fixture(tmp_path_factory.mktemp("c9-sealed-fixture"))
    finally:
        if prior is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = prior


def _clone_sealed_fixture(
    fixture: _SealedFixture,
    tmp_path: Path,
) -> _SealedFixture:
    repository = tmp_path / "repository"
    assert GIT is not None
    subprocess.run(
        (
            GIT,
            "clone",
            "--quiet",
            "--shared",
            str(fixture.repository),
            str(repository),
        ),
        check=True,
        capture_output=True,
    )
    _git(repository, "config", "user.name", "C9 Seal Test")
    _git(repository, "config", "user.email", "c9-seal@example.invalid")
    return _SealedFixture(
        repository=repository,
        final_attestation=fixture.final_attestation,
        live_head=fixture.live_head,
        covered_head=fixture.covered_head,
        tag_target=fixture.tag_target,
    )


def test_c9_manifest_is_derived_from_authenticated_live_attestation(
    sealed_fixture: _SealedFixture,
) -> None:
    raw_manifest = _git(
        sealed_fixture.repository,
        "show",
        f"{sealed_fixture.covered_head}:{C9_MANIFEST_PATH}",
    )
    manifest = C9ChangeManifest.model_validate_json(raw_manifest)
    attestation = C9FinalAttestation.model_validate_json(
        sealed_fixture.final_attestation.read_bytes()
    )

    assert manifest.issue == 80
    assert manifest.reviewed_outcome == C9_FINAL_STATUS
    assert manifest.live_repository_head == sealed_fixture.live_head
    assert manifest.final_attestation_sha256 == attestation.attestation_sha256
    assert manifest.final_attestation_model_sha256 == canonical_sha256(
        attestation.model_dump(mode="json")
    )
    assert manifest.accepted_c8_commit == C9_BASE_COMMIT
    assert manifest.work_rich_call_count == 1
    assert manifest.chat_manual_handoff_count == 1
    assert manifest.total_rich_mcp_call_count == 1
    assert manifest.revocation_verified is True
    assert manifest.work_rich_mcp_verified is True
    assert manifest.chat_manual_visible_handoff_verified is True
    assert manifest.same_sanitized_package_verified is True
    assert manifest.native_chat_plugin_invoked is False
    assert manifest.native_chat_provider_audit_correlation_claimed is False
    assert manifest.unapproved_fallback_used is False
    assert manifest.chat_export_descriptor_sha256 == (attestation.chat_export_descriptor_sha256)
    assert manifest.chat_picker_claim_receipt_sha256 == (
        attestation.chat_picker_claim_receipt_sha256
    )
    assert manifest.automatic_chat_to_work_switch_used is False
    assert manifest.regular_use_readiness_claimed is False
    assert manifest.raw_sensitive_evidence_versioned is False
    assert C9_MANIFEST_PATH in manifest.changed_files
    assert C9_SEAL_PATH not in manifest.changed_files


def test_c9_manifest_generation_rejects_forged_or_non_live_evidence(
    sealed_fixture: _SealedFixture,
    tmp_path: Path,
) -> None:
    attestation_path = tmp_path / "attestation.json"
    attestation_path.write_text(
        sealed_fixture.final_attestation.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="authentication"):
        create_c9_manifest(
            sealed_fixture.repository,
            final_attestation_path=attestation_path,
            audit_key="wrong-key-" + ("x" * 48),
            covered_head=sealed_fixture.live_head,
        )

    payload = json.loads(attestation_path.read_text(encoding="utf-8"))
    payload["work_rich_call_count"] = 0
    invalid_attestation_path = tmp_path / "invalid-attestation.json"
    invalid_attestation_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValidationError):
        create_c9_manifest(
            sealed_fixture.repository,
            final_attestation_path=invalid_attestation_path,
            audit_key=AUDIT_KEY,
            covered_head=sealed_fixture.live_head,
        )


def test_c9_change_manifest_rejects_unknown_duplicate_and_seal_paths(
    sealed_fixture: _SealedFixture,
) -> None:
    raw = _git(
        sealed_fixture.repository,
        "show",
        f"{sealed_fixture.covered_head}:{C9_MANIFEST_PATH}",
    )
    payload = json.loads(raw)
    payload["unknown"] = True
    with pytest.raises(ValidationError):
        C9ChangeManifest.model_validate(payload)

    payload.pop("unknown")
    payload["changed_files"].append(payload["changed_files"][-1])
    with pytest.raises(ValidationError, match="sorted and unique"):
        C9ChangeManifest.model_validate(payload)

    payload = json.loads(raw)
    payload["changed_files"].append(C9_SEAL_PATH)
    payload["changed_files"].sort()
    with pytest.raises(ValidationError, match="self-referential seal"):
        C9ChangeManifest.model_validate(payload)

    payload = json.loads(raw)
    payload["reviewed_outcome"] = (
        "COMPLETE_C9_WORK_AND_CHAT_RICH_MCP_ATTACHMENTS_CORRELATED_AND_REVOKED"
    )
    with pytest.raises(ValidationError):
        C9ChangeManifest.model_validate(payload)


def test_c9_seal_reproduces_manifest_diff_tree_c8_and_live_head(
    sealed_fixture: _SealedFixture,
) -> None:
    result = verify_c9_seal(
        sealed_fixture.repository,
        require_current_tree=True,
        require_clean=True,
        final_attestation_path=sealed_fixture.final_attestation,
        audit_key=AUDIT_KEY,
    )

    assert result.status == "verified"
    assert result.issue == 80
    assert result.live_repository_head == sealed_fixture.live_head
    assert result.covered_head == sealed_fixture.covered_head
    assert result.tag_target == sealed_fixture.tag_target
    assert result.exact_attestation_reverified is True
    assert result.accepted_c8_commit == C9_BASE_COMMIT
    assert result.reviewed_outcome == C9_FINAL_STATUS
    assert result.provider_live_actions_performed is True
    assert result.work_rich_call_count == 1
    assert result.chat_manual_handoff_count == 1
    assert result.total_rich_mcp_call_count == 1
    assert result.revocation_verified is True
    assert result.work_rich_mcp_verified is True
    assert result.chat_manual_visible_handoff_verified is True
    assert result.same_sanitized_package_verified is True
    assert result.native_chat_plugin_invoked is False
    assert result.native_chat_provider_audit_correlation_claimed is False
    assert result.unapproved_fallback_used is False
    assert result.automatic_chat_to_work_switch_used is False
    assert result.regular_use_readiness_claimed is False
    assert result.covered_changed_file_count == 2
    assert result.tree_file_count > 300
    assert result.tree_blob_bytes > 3_000_000


def test_c9_seal_rejects_a_non_annotated_tag_and_extra_seal_commit_path(
    sealed_fixture: _SealedFixture,
    tmp_path: Path,
) -> None:
    fixture = _clone_sealed_fixture(sealed_fixture, tmp_path)
    raw_seal = _git(
        fixture.repository,
        "show",
        f"{fixture.tag_target}:{C9_SEAL_PATH}",
    )
    _git(fixture.repository, "tag", "-d", C9_EVIDENCE_TAG)
    _git(fixture.repository, "tag", C9_EVIDENCE_TAG, fixture.tag_target)
    with pytest.raises(ValueError, match="annotated"):
        verify_c9_seal(fixture.repository)

    _git(fixture.repository, "tag", "-d", C9_EVIDENCE_TAG)
    _git(fixture.repository, "reset", "--hard", "--quiet", fixture.covered_head)
    extra = fixture.repository / "unexpected-seal-state.txt"
    extra.write_text("unexpected\n", encoding="utf-8")
    (fixture.repository / C9_SEAL_PATH).write_text(
        raw_seal,
        encoding="utf-8",
    )
    bad_target = _commit(
        fixture.repository,
        "Invalid multi-file C9 seal",
        C9_SEAL_PATH,
        "unexpected-seal-state.txt",
    )
    _git(
        fixture.repository,
        "tag",
        "-a",
        C9_EVIDENCE_TAG,
        "-m",
        "invalid C9 seal",
        bad_target,
    )
    with pytest.raises(ValueError, match="add only the final seal"):
        verify_c9_seal(fixture.repository)


def test_c9_seal_source_has_no_provider_or_browser_runtime_dependency() -> None:
    source = (ROOT / "src/systeme_local_gateway/c9_seal.py").read_text(encoding="utf-8")
    for forbidden in (
        "import httpx",
        "import requests",
        "import socket",
        "import webbrowser",
        "CONTROL_PLANE_API_KEY",
        "CONTROL_PLANE_TUNNEL_ID",
        "SLG_SHARED_SECRET",
        "SLG_MCP_TOKEN",
        "chatgpt.com",
    ):
        assert forbidden not in source
