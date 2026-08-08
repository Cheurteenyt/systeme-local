from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, NoReturn, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .c8_seal import (
    C8_BASE_COMMIT as C8_SEAL_BASE_COMMIT,
)
from .c8_seal import (
    C8_EVIDENCE_TAG,
    C8_FINAL_STATUS,
    C8_MANIFEST_PATH,
    C8_SEAL_PATH,
    C8ChangeManifest,
    C8ChangeSeal,
    C8SealVerification,
)
from .c9_git import run_c9_git

if TYPE_CHECKING:
    from .c9_attestation import C9FinalAttestation

C9_BASE_COMMIT: Final[Literal["bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5"]] = (
    "bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5"
)
C9_BRANCH: Final[Literal["codex/chatgpt-file-image-handoff-c9"]] = (
    "codex/chatgpt-file-image-handoff-c9"
)
C9_EVIDENCE_TAG: Final[Literal["evidence/chatgpt-file-image-handoff-c9-v1"]] = (
    "evidence/chatgpt-file-image-handoff-c9-v1"
)
C9_MANIFEST_PATH: Final[Literal["governance/c9-change-manifest.json"]] = (
    "governance/c9-change-manifest.json"
)
C9_SEAL_PATH: Final[Literal["governance/c9-change-seal.json"]] = "governance/c9-change-seal.json"
C9_ISSUE_URL: Final[Literal["https://github.com/Cheurteenyt/systeme-local/issues/80"]] = (
    "https://github.com/Cheurteenyt/systeme-local/issues/80"
)
C9_FINAL_STATUS: Final[
    Literal["COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_ATTACHMENTS_VERIFIED_AND_REVOKED"]
] = "COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_ATTACHMENTS_VERIFIED_AND_REVOKED"

_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_METADATA_BYTES = 2 * 1024 * 1024
_MAX_GIT_OUTPUT_BYTES = 16 * 1024 * 1024


class _DuplicateJSONKey(ValueError):
    pass


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return sha256(canonical_json(value)).hexdigest()


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("C9 seal metadata rejects non-finite JSON values")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(f"duplicate C9 seal metadata field: {key}")
        result[key] = value
    return result


def _strict_model_bytes(raw: bytes, model: type[_ModelT]) -> _ModelT:
    if not raw or len(raw) > _MAX_METADATA_BYTES:
        raise ValueError("C9 seal metadata is empty or exceeds its byte boundary")
    payload = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )
    return model.model_validate(payload)


def _validate_repo_path(value: str) -> str:
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\0" in value
        or ".." in Path(value).parts
        or Path(value).as_posix() != value
    ):
        raise ValueError("C9 seal path is not canonical")
    return value


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C9 seal timestamps must be timezone-aware")
    return value.astimezone(UTC)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class C9ChangeManifest(_StrictModel):
    """Versioned metadata derived only from one authenticated final attestation."""

    version: Literal["1"]
    repository: Literal["Cheurteenyt/systeme-local"]
    default_branch: Literal["main"]
    branch: Literal["codex/chatgpt-file-image-handoff-c9"]
    issue: Literal[80]
    issue_url: Literal["https://github.com/Cheurteenyt/systeme-local/issues/80"]
    base_commit: Literal["bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5"]
    merge_method: Literal["squash"]
    evidence_tag: Literal["evidence/chatgpt-file-image-handoff-c9-v1"]
    reviewed_outcome: Literal[
        "COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_ATTACHMENTS_VERIFIED_AND_REVOKED"
    ]
    implementation_status: Literal[
        "complete_live_work_rich_mcp_and_chat_manual_visible_handoff_verified_and_revoked"
    ]
    changed_files: tuple[str, ...]
    live_repository_head: str = Field(pattern=_COMMIT_PATTERN)
    final_attestation_sha256: str = Field(pattern=_SHA256_PATTERN)
    final_attestation_model_sha256: str = Field(pattern=_SHA256_PATTERN)
    final_attestation_verified_at: datetime
    cycle_id_sha256: str = Field(pattern=_SHA256_PATTERN)
    grant_id_sha256: str = Field(pattern=_SHA256_PATTERN)
    handoff_id_sha256: str = Field(pattern=_SHA256_PATTERN)
    accepted_c8_commit: Literal["bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5"]
    c8_covered_head: str = Field(pattern=_COMMIT_PATTERN)
    c8_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    c8_final_attestation_sha256: str = Field(pattern=_SHA256_PATTERN)
    c8_dependency_sha256: str = Field(pattern=_SHA256_PATTERN)
    c8_reviewed_outcome: Literal["COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"]
    c8_revocation_verified: Literal[True]
    c8_live_cycle_grant_reused: Literal[False]
    provider_live_actions_performed: Literal[True]
    work_rich_call_count: Literal[1]
    chat_manual_handoff_count: Literal[1]
    total_rich_mcp_call_count: Literal[1]
    work_rich_mcp_verified: Literal[True]
    chat_manual_visible_handoff_verified: Literal[True]
    same_sanitized_package_verified: Literal[True]
    native_chat_plugin_invoked: Literal[False]
    native_chat_provider_audit_correlation_claimed: Literal[False]
    unapproved_fallback_used: Literal[False]
    local_ai_loopback_receipt_committed: Literal[True]
    local_ai_native_runtime_observation_committed: Literal[True]
    regular_arbitrary_files_tested: Literal[False]
    regular_use_readiness_claimed: Literal[False]
    automatic_chat_to_work_switch_used: Literal[False]
    revocation_verified: Literal[True]
    raw_sensitive_evidence_versioned: Literal[False]
    chat_export_id_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_export_descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_export_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_picker_claim_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    attachment_content_sha256s: tuple[str, str]
    attachment_nonce_sha256s: tuple[str, str]
    work_consumption_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_manual_confirmation_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_manual_cleanup_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    work_audit_correlation_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    coordinator_close_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    negative_test_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    revocation_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    _verified_utc = field_validator("final_attestation_verified_at")(_aware_utc)

    @model_validator(mode="after")
    def validate_manifest(self) -> C9ChangeManifest:
        for path in self.changed_files:
            _validate_repo_path(path)
        if self.changed_files != tuple(sorted(set(self.changed_files))):
            raise ValueError("C9 manifest paths must be sorted and unique")
        if C9_MANIFEST_PATH not in self.changed_files:
            raise ValueError("C9 manifest must cover itself")
        if C9_SEAL_PATH in self.changed_files:
            raise ValueError("C9 covered head cannot contain its self-referential seal")
        for pair in (
            self.attachment_content_sha256s,
            self.attachment_nonce_sha256s,
        ):
            if len(set(pair)) != 2 or any(
                re.fullmatch(_SHA256_PATTERN, item) is None for item in pair
            ):
                raise ValueError("C9 attachment commitments require two distinct SHA-256 values")
        receipt_hashes = (
            self.chat_export_descriptor_sha256,
            self.chat_export_sha256,
            self.chat_picker_claim_receipt_sha256,
            self.work_consumption_receipt_sha256,
            self.chat_manual_confirmation_receipt_sha256,
            self.chat_manual_cleanup_receipt_sha256,
            self.work_audit_correlation_receipt_sha256,
            self.coordinator_close_receipt_sha256,
            self.negative_test_receipt_sha256,
            self.revocation_receipt_sha256,
        )
        if len(set(receipt_hashes)) != len(receipt_hashes):
            raise ValueError("C9 Work, Chat, cleanup and revocation receipts must be distinct")
        return self


class C9DiffCommitment(_StrictModel):
    algorithm: Literal["sha256-git-binary-diff-v1"]
    excluded_paths: tuple[Literal["governance/c9-change-seal.json"], ...]
    sha256: str = Field(pattern=_SHA256_PATTERN)
    bytes: int = Field(ge=1)


class C9TreeCommitment(_StrictModel):
    algorithm: Literal["sha256-framed-tree-v1"]
    excluded_paths: tuple[Literal["governance/c9-change-seal.json"], ...]
    sha256: str = Field(pattern=_SHA256_PATTERN)
    file_count: int = Field(ge=1)
    blob_bytes: int = Field(ge=1)


class C9ChangeSeal(_StrictModel):
    version: Literal["1"]
    repository: Literal["Cheurteenyt/systeme-local"]
    branch: Literal["codex/chatgpt-file-image-handoff-c9"]
    issue: Literal[80]
    issue_url: Literal["https://github.com/Cheurteenyt/systeme-local/issues/80"]
    base_commit: Literal["bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5"]
    evidence_tag: Literal["evidence/chatgpt-file-image-handoff-c9-v1"]
    covered_head: str = Field(pattern=_COMMIT_PATTERN)
    live_repository_head: str = Field(pattern=_COMMIT_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    final_attestation_sha256: str = Field(pattern=_SHA256_PATTERN)
    final_attestation_model_sha256: str = Field(pattern=_SHA256_PATTERN)
    accepted_c8_commit: Literal["bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5"]
    c8_dependency_sha256: str = Field(pattern=_SHA256_PATTERN)
    c8_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_export_descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_picker_claim_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    diff: C9DiffCommitment
    tree: C9TreeCommitment
    covered_changed_file_count: int = Field(ge=1)
    validation_status: Literal["C9_WORK_RICH_MCP_AND_CHAT_MANUAL_LIVE_EVIDENCE_SEALED"]
    reviewed_outcome: Literal[
        "COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_ATTACHMENTS_VERIFIED_AND_REVOKED"
    ]
    provider_live_actions_performed: Literal[True]
    work_rich_call_count: Literal[1]
    chat_manual_handoff_count: Literal[1]
    total_rich_mcp_call_count: Literal[1]
    work_rich_mcp_verified: Literal[True]
    chat_manual_visible_handoff_verified: Literal[True]
    same_sanitized_package_verified: Literal[True]
    native_chat_plugin_invoked: Literal[False]
    native_chat_provider_audit_correlation_claimed: Literal[False]
    unapproved_fallback_used: Literal[False]
    revocation_verified: Literal[True]
    automatic_chat_to_work_switch_used: Literal[False]
    regular_arbitrary_files_tested: Literal[False]
    regular_use_readiness_claimed: Literal[False]
    raw_sensitive_evidence_versioned: Literal[False]


class C9SealVerification(_StrictModel):
    status: Literal["verified"]
    issue: Literal[80]
    base_commit: str = Field(pattern=_COMMIT_PATTERN)
    live_repository_head: str = Field(pattern=_COMMIT_PATTERN)
    covered_head: str = Field(pattern=_COMMIT_PATTERN)
    tag_target: str = Field(pattern=_COMMIT_PATTERN)
    current_head: str = Field(pattern=_COMMIT_PATTERN)
    current_tree_required: bool
    exact_attestation_reverified: Literal[True]
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    final_attestation_sha256: str = Field(pattern=_SHA256_PATTERN)
    final_attestation_model_sha256: str = Field(pattern=_SHA256_PATTERN)
    accepted_c8_commit: str = Field(pattern=_COMMIT_PATTERN)
    c8_dependency_sha256: str = Field(pattern=_SHA256_PATTERN)
    c8_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_export_descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)
    chat_picker_claim_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    diff_sha256: str = Field(pattern=_SHA256_PATTERN)
    tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    covered_changed_file_count: int = Field(ge=1)
    tree_file_count: int = Field(ge=1)
    tree_blob_bytes: int = Field(ge=1)
    reviewed_outcome: Literal[
        "COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_ATTACHMENTS_VERIFIED_AND_REVOKED"
    ]
    provider_live_actions_performed: Literal[True]
    work_rich_call_count: Literal[1]
    chat_manual_handoff_count: Literal[1]
    total_rich_mcp_call_count: Literal[1]
    revocation_verified: Literal[True]
    work_rich_mcp_verified: Literal[True]
    chat_manual_visible_handoff_verified: Literal[True]
    same_sanitized_package_verified: Literal[True]
    native_chat_plugin_invoked: Literal[False]
    native_chat_provider_audit_correlation_claimed: Literal[False]
    unapproved_fallback_used: Literal[False]
    automatic_chat_to_work_switch_used: Literal[False]
    regular_use_readiness_claimed: Literal[False]


def _is_reparse(info: os.stat_result) -> bool:
    marker = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(info, "st_file_attributes", 0))
    return stat.S_ISLNK(info.st_mode) or bool(attributes & marker)


def _assert_safe_root(root: Path) -> Path:
    resolved = root.resolve(strict=True)
    if not (resolved / ".git").exists():
        raise ValueError("C9 seal root must be a Git worktree")
    current = Path(resolved.anchor)
    for part in resolved.parts[1:]:
        current /= part
        info = os.lstat(current)
        if _is_reparse(info):
            raise ValueError("C9 seal root cannot traverse a reparse point")
    return resolved


def _git(root: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    completed = run_c9_git(
        root,
        *args,
        input_bytes=input_bytes,
        maximum_output_bytes=_MAX_GIT_OUTPUT_BYTES,
    )
    return completed.stdout


def _git_text(root: Path, *args: str) -> str:
    return _git(root, *args).decode("utf-8", errors="strict").strip()


def _resolve_commit(root: Path, value: str) -> str:
    resolved = _git_text(root, "rev-parse", "--verify", f"{value}^{{commit}}")
    if re.fullmatch(_COMMIT_PATTERN, resolved) is None:
        raise ValueError(f"C9 Git reference {value!r} did not resolve to a commit")
    return resolved


def _assert_ancestor(root: Path, ancestor: str, descendant: str) -> None:
    completed = run_c9_git(
        root,
        "merge-base",
        "--is-ancestor",
        ancestor,
        descendant,
        accepted_returncodes=(0, 1),
        maximum_output_bytes=64 * 1024,
    )
    if completed.returncode != 0:
        raise ValueError(f"C9 ancestry mismatch: {ancestor} is not an ancestor of {descendant}")


def _load_json_at(
    root: Path,
    commit: str,
    path: str,
    model: type[_ModelT],
) -> _ModelT:
    _validate_repo_path(path)
    object_id = _git_text(root, "rev-parse", "--verify", f"{commit}:{path}")
    if re.fullmatch(_COMMIT_PATTERN, object_id) is None:
        raise ValueError("C9 metadata path did not resolve to a Git object")
    if _git_text(root, "cat-file", "-t", object_id) != "blob":
        raise ValueError("C9 metadata Git object is not a blob")
    size = int(_git_text(root, "cat-file", "-s", object_id))
    if not 0 < size <= _MAX_METADATA_BYTES:
        raise ValueError("C9 metadata Git blob exceeds its byte boundary")
    raw = _git(root, "cat-file", "blob", object_id)
    if len(raw) != size:
        raise ValueError("C9 metadata Git blob changed while loading")
    return _strict_model_bytes(raw, model)


def _changed_paths(root: Path, base: str, head: str) -> tuple[str, ...]:
    raw = _git(root, "diff", "--name-only", "-z", base, head, "--")
    paths = tuple(item.decode("utf-8", errors="strict") for item in raw.split(b"\0") if item)
    for path in paths:
        _validate_repo_path(path)
    return tuple(sorted(paths))


def compute_c9_diff_commitment(
    root: Path,
    base: str,
    head: str,
) -> C9DiffCommitment:
    root = _assert_safe_root(root)
    base_commit = _resolve_commit(root, base)
    head_commit = _resolve_commit(root, head)
    raw = _git(
        root,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        base_commit,
        head_commit,
        "--",
        ".",
        f":(exclude){C9_SEAL_PATH}",
    )
    if not raw:
        raise ValueError("C9 covered diff cannot be empty")
    return C9DiffCommitment(
        algorithm="sha256-git-binary-diff-v1",
        excluded_paths=(C9_SEAL_PATH,),
        sha256=sha256(raw).hexdigest(),
        bytes=len(raw),
    )


def _tree_entries(
    root: Path,
    commit: str,
    *,
    excluded_path: str,
) -> tuple[tuple[str, str, str], ...]:
    _validate_repo_path(excluded_path)
    raw = _git(root, "ls-tree", "-r", "-z", "--full-tree", commit)
    entries: list[tuple[str, str, str]] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, raw_path = item.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        path = raw_path.decode("utf-8", errors="strict")
        _validate_repo_path(path)
        if kind != "blob":
            raise ValueError("C9 tree contains a non-blob recursive entry")
        if path != excluded_path:
            entries.append((path, mode, object_id))
    return tuple(sorted(entries))


def _read_git_blobs(root: Path, object_ids: tuple[str, ...]) -> dict[str, bytes]:
    unique = tuple(sorted(set(object_ids)))
    if any(re.fullmatch(_COMMIT_PATTERN, object_id) is None for object_id in unique):
        raise ValueError("C9 tree contains an invalid Git object identifier")
    raw = _git(
        root,
        "cat-file",
        "--batch",
        input_bytes=b"".join(object_id.encode("ascii") + b"\n" for object_id in unique),
    )
    blobs: dict[str, bytes] = {}
    offset = 0
    for expected in unique:
        line_end = raw.find(b"\n", offset)
        if line_end < 0:
            raise ValueError("C9 Git batch response ended before its object header")
        header = raw[offset:line_end].decode("ascii", errors="strict").split(" ")
        if len(header) != 3:
            raise ValueError("C9 Git batch response has an invalid object header")
        object_id, kind, raw_size = header
        if object_id != expected or kind != "blob":
            raise ValueError("C9 Git batch response returned an unexpected object")
        size = int(raw_size)
        start = line_end + 1
        end = start + size
        if size < 0 or end >= len(raw) or raw[end : end + 1] != b"\n":
            raise ValueError("C9 Git batch response has an invalid blob boundary")
        blobs[object_id] = raw[start:end]
        offset = end + 1
    if offset != len(raw):
        raise ValueError("C9 Git batch response contains trailing data")
    return blobs


def _tree_commitment_values(
    root: Path,
    commit: str,
    *,
    excluded_path: str,
) -> tuple[str, int, int]:
    digest = sha256()
    total_bytes = 0
    entries = _tree_entries(root, commit, excluded_path=excluded_path)
    blobs = _read_git_blobs(root, tuple(object_id for _, _, object_id in entries))
    for path, mode, object_id in entries:
        blob = blobs[object_id]
        path_bytes = path.encode("utf-8")
        mode_bytes = mode.encode("ascii")
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(mode_bytes).to_bytes(8, "big"))
        digest.update(mode_bytes)
        digest.update(len(blob).to_bytes(8, "big"))
        digest.update(blob)
        total_bytes += len(blob)
    return digest.hexdigest(), len(entries), total_bytes


def compute_c9_tree_commitment(root: Path, commit: str) -> C9TreeCommitment:
    root = _assert_safe_root(root)
    resolved = _resolve_commit(root, commit)
    digest, file_count, total_bytes = _tree_commitment_values(
        root,
        resolved,
        excluded_path=C9_SEAL_PATH,
    )
    return C9TreeCommitment(
        algorithm="sha256-framed-tree-v1",
        excluded_paths=(C9_SEAL_PATH,),
        sha256=digest,
        file_count=file_count,
        blob_bytes=total_bytes,
    )


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_nlink),
        int(info.st_size),
        int(info.st_mtime_ns),
    )


def _reject_reparse_prefix(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        info = os.lstat(current)
        if _is_reparse(info):
            raise ValueError("C9 protected path cannot traverse a reparse point")


def _read_final_attestation(
    path: Path,
    *,
    audit_key: str | bytes,
) -> C9FinalAttestation:
    from .c9_attestation import C9FinalAttestation, verify_final_attestation

    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("C9 final attestation path must be absolute and non-traversing")
    lexical = Path(os.path.abspath(path))
    _reject_reparse_prefix(lexical)
    before = os.lstat(lexical)
    if (
        not stat.S_ISREG(before.st_mode)
        or _is_reparse(before)
        or int(before.st_nlink) != 1
        or not 0 < int(before.st_size) <= _MAX_METADATA_BYTES
    ):
        raise ValueError("C9 final attestation file identity is unsafe")
    flags = os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0))
    flags |= int(getattr(os, "O_BINARY", 0))
    descriptor = os.open(lexical, flags)
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise ValueError("C9 final attestation changed while opening")
        chunks = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, _MAX_METADATA_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > _MAX_METADATA_BYTES:
                raise ValueError("C9 final attestation exceeds its byte boundary")
    finally:
        os.close(descriptor)
    after = os.lstat(lexical)
    if _file_identity(after) != _file_identity(before):
        raise ValueError("C9 final attestation changed while loading")
    committed = _strict_model_bytes(bytes(chunks), C9FinalAttestation)
    chunks[:] = b"\0" * len(chunks)
    return verify_final_attestation(committed, audit_key=audit_key)


def verify_c9_c8_seal_exact(root: Path) -> C8SealVerification:
    root = _assert_safe_root(root)
    tag_object = _git_text(root, "rev-parse", "--verify", C8_EVIDENCE_TAG)
    if _git_text(root, "cat-file", "-t", tag_object) != "tag":
        raise ValueError("C8 evidence tag must be annotated")
    tag_target = _resolve_commit(root, C8_EVIDENCE_TAG)
    seal = _load_json_at(root, tag_target, C8_SEAL_PATH, C8ChangeSeal)
    parent = _resolve_commit(root, f"{tag_target}^")
    if parent != seal.covered_head:
        raise ValueError("C8 evidence tag parent is not the sealed covered head")
    tag_changes = _changed_paths(root, seal.covered_head, tag_target)
    if tag_changes != (C8_SEAL_PATH,):
        raise ValueError("C8 evidence tag commit must add only the final seal")
    manifest = _load_json_at(
        root,
        seal.covered_head,
        C8_MANIFEST_PATH,
        C8ChangeManifest,
    )
    manifest_sha = canonical_sha256(manifest.model_dump(mode="json"))
    if manifest_sha != seal.manifest_sha256:
        raise ValueError("C8 sealed manifest digest mismatch")
    if manifest.attestation_sha256 != seal.final_attestation_sha256:
        raise ValueError("C8 final attestation commitment mismatch")
    changed = _changed_paths(root, C8_SEAL_BASE_COMMIT, seal.covered_head)
    if changed != manifest.changed_files or len(changed) != seal.covered_changed_file_count:
        raise ValueError("C8 sealed changed-file set mismatch")
    diff_raw = _git(
        root,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        C8_SEAL_BASE_COMMIT,
        seal.covered_head,
        "--",
        ".",
        f":(exclude){C8_SEAL_PATH}",
    )
    if (
        not diff_raw
        or seal.diff.sha256 != sha256(diff_raw).hexdigest()
        or seal.diff.bytes != len(diff_raw)
    ):
        raise ValueError("C8 sealed diff commitment mismatch")
    covered_tree = _tree_commitment_values(
        root,
        seal.covered_head,
        excluded_path=C8_SEAL_PATH,
    )
    tagged_tree = _tree_commitment_values(
        root,
        tag_target,
        excluded_path=C8_SEAL_PATH,
    )
    sealed_tree = (
        seal.tree.sha256,
        seal.tree.file_count,
        seal.tree.blob_bytes,
    )
    if covered_tree != tagged_tree or covered_tree != sealed_tree:
        raise ValueError("C8 sealed tree commitment mismatch")
    current = _resolve_commit(root, "HEAD")
    _assert_ancestor(root, C8_SEAL_BASE_COMMIT, current)
    return C8SealVerification(
        status="verified",
        base_commit=C8_SEAL_BASE_COMMIT,
        covered_head=seal.covered_head,
        tag_target=tag_target,
        current_head=current,
        current_tree_required=False,
        manifest_sha256=seal.manifest_sha256,
        final_attestation_sha256=seal.final_attestation_sha256,
        diff_sha256=seal.diff.sha256,
        tree_sha256=seal.tree.sha256,
        covered_changed_file_count=seal.covered_changed_file_count,
        tree_file_count=seal.tree.file_count,
        tree_blob_bytes=seal.tree.blob_bytes,
        reviewed_outcome=C8_FINAL_STATUS,
        provider_live_actions_performed=True,
        work_call_count=2,
        revocation_verified=True,
        effective_tool_count=1,
    )


def _verify_c8_manifest_dependency(
    root: Path,
    manifest: C9ChangeManifest,
) -> C8SealVerification:
    from .c9_live_cycle import C9C8SealDependency

    verification = verify_c9_c8_seal_exact(root)
    if (
        manifest.accepted_c8_commit != verification.tag_target
        or manifest.c8_covered_head != verification.covered_head
        or manifest.c8_tree_sha256 != verification.tree_sha256
        or manifest.c8_final_attestation_sha256 != verification.final_attestation_sha256
        or manifest.c8_reviewed_outcome != verification.reviewed_outcome
        or not verification.revocation_verified
        or manifest.c8_live_cycle_grant_reused
    ):
        raise ValueError("C9 manifest does not bind the exact revoked C8 seal")
    if manifest.accepted_c8_commit != C9_BASE_COMMIT:
        raise ValueError("C9 accepted C8 commit differs from its exact base")
    _assert_ancestor(root, verification.tag_target, manifest.live_repository_head)
    C9C8SealDependency(
        version="1",
        status="verified",
        tag_target=verification.tag_target,
        covered_head=verification.covered_head,
        current_head=manifest.live_repository_head,
        tree_sha256=verification.tree_sha256,
        final_attestation_sha256=verification.final_attestation_sha256,
        reviewed_outcome=verification.reviewed_outcome,
        work_call_count=2,
        revocation_verified=True,
        tag_target_ancestor_of_head=True,
        dependency_sha256=manifest.c8_dependency_sha256,
    )
    return verification


def _manifest_from_attestation(
    *,
    root: Path,
    covered_head: str,
    changed_files: tuple[str, ...],
    attestation: C9FinalAttestation,
) -> C9ChangeManifest:
    if attestation.status != C9_FINAL_STATUS or attestation.simulated:
        raise ValueError("C9 final attestation does not contain the exact live outcome")
    if (
        attestation.accepted_c8_commit != C9_BASE_COMMIT
        or attestation.c8_reviewed_outcome != C8_FINAL_STATUS
        or not attestation.c8_revocation_verified
        or attestation.c8_live_cycle_grant_reused
    ):
        raise ValueError("C9 final attestation does not bind the exact revoked C8 dependency")
    live_head = _resolve_commit(root, attestation.c9_live_repository_head)
    if live_head != attestation.c9_live_repository_head:
        raise ValueError("C9 final attestation live HEAD is not canonical")
    _assert_ancestor(root, C9_BASE_COMMIT, live_head)
    _assert_ancestor(root, live_head, covered_head)
    model_sha = canonical_sha256(attestation.model_dump(mode="json"))
    return C9ChangeManifest(
        version="1",
        repository="Cheurteenyt/systeme-local",
        default_branch="main",
        branch=C9_BRANCH,
        issue=80,
        issue_url=C9_ISSUE_URL,
        base_commit=C9_BASE_COMMIT,
        merge_method="squash",
        evidence_tag=C9_EVIDENCE_TAG,
        reviewed_outcome=C9_FINAL_STATUS,
        implementation_status=(
            "complete_live_work_rich_mcp_and_chat_manual_visible_handoff_verified_and_revoked"
        ),
        changed_files=changed_files,
        live_repository_head=live_head,
        final_attestation_sha256=attestation.attestation_sha256,
        final_attestation_model_sha256=model_sha,
        final_attestation_verified_at=attestation.verified_at,
        cycle_id_sha256=sha256(attestation.cycle_id.encode("utf-8")).hexdigest(),
        grant_id_sha256=sha256(attestation.grant_id.encode("utf-8")).hexdigest(),
        handoff_id_sha256=sha256(attestation.handoff_id.encode("utf-8")).hexdigest(),
        accepted_c8_commit=C9_BASE_COMMIT,
        c8_covered_head=attestation.c8_covered_head,
        c8_tree_sha256=attestation.c8_tree_sha256,
        c8_final_attestation_sha256=attestation.c8_final_attestation_sha256,
        c8_dependency_sha256=attestation.c8_dependency_sha256,
        c8_reviewed_outcome=C8_FINAL_STATUS,
        c8_revocation_verified=True,
        c8_live_cycle_grant_reused=False,
        provider_live_actions_performed=True,
        work_rich_call_count=attestation.work_rich_call_count,
        chat_manual_handoff_count=attestation.chat_manual_handoff_count,
        total_rich_mcp_call_count=attestation.total_rich_mcp_call_count,
        work_rich_mcp_verified=attestation.work_rich_mcp_verified,
        chat_manual_visible_handoff_verified=(attestation.chat_manual_visible_handoff_verified),
        same_sanitized_package_verified=attestation.same_sanitized_package_verified,
        native_chat_plugin_invoked=attestation.native_chat_plugin_invoked,
        native_chat_provider_audit_correlation_claimed=(
            attestation.native_chat_provider_audit_correlation_claimed
        ),
        unapproved_fallback_used=attestation.unapproved_fallback_used,
        local_ai_loopback_receipt_committed=(attestation.local_ai_loopback_receipt_committed),
        local_ai_native_runtime_observation_committed=(
            attestation.local_ai_native_runtime_observation_committed
        ),
        regular_arbitrary_files_tested=attestation.regular_arbitrary_files_tested,
        regular_use_readiness_claimed=attestation.regular_use_readiness_claimed,
        automatic_chat_to_work_switch_used=(attestation.automatic_chat_to_work_switch_used),
        revocation_verified=attestation.revocation_verified,
        raw_sensitive_evidence_versioned=False,
        chat_export_id_sha256=sha256(attestation.chat_export_id.encode("utf-8")).hexdigest(),
        chat_export_descriptor_sha256=attestation.chat_export_descriptor_sha256,
        chat_export_sha256=attestation.chat_export_sha256,
        chat_picker_claim_receipt_sha256=attestation.chat_picker_claim_receipt_sha256,
        attachment_content_sha256s=attestation.attachment_content_sha256s,
        attachment_nonce_sha256s=attestation.attachment_nonce_sha256s,
        work_consumption_receipt_sha256=(attestation.work_consumption_receipt_sha256),
        chat_manual_confirmation_receipt_sha256=(
            attestation.chat_manual_confirmation_receipt_sha256
        ),
        chat_manual_cleanup_receipt_sha256=(attestation.chat_manual_cleanup_receipt_sha256),
        work_audit_correlation_receipt_sha256=(attestation.work_audit_correlation_receipt_sha256),
        coordinator_close_receipt_sha256=(attestation.coordinator_close_receipt_sha256),
        negative_test_receipt_sha256=attestation.negative_test_receipt_sha256,
        revocation_receipt_sha256=attestation.revocation_receipt_sha256,
    )


def create_c9_manifest(
    root: Path,
    *,
    final_attestation_path: Path,
    audit_key: str | bytes,
    covered_head: str = "HEAD",
) -> C9ChangeManifest:
    root = _assert_safe_root(root)
    if _git_text(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("C9 manifest generation requires a clean worktree")
    covered = _resolve_commit(root, covered_head)
    base = _resolve_commit(root, C9_BASE_COMMIT)
    _assert_ancestor(root, base, covered)
    if C9_SEAL_PATH in _changed_paths(root, base, covered):
        raise ValueError("C9 covered head already contains its self-referential seal")
    attestation = _read_final_attestation(
        final_attestation_path,
        audit_key=audit_key,
    )
    changed = tuple(
        sorted(
            {
                *_changed_paths(root, base, covered),
                C9_MANIFEST_PATH,
            }
        )
    )
    manifest = _manifest_from_attestation(
        root=root,
        covered_head=covered,
        changed_files=changed,
        attestation=attestation,
    )
    _verify_c8_manifest_dependency(root, manifest)
    return manifest


def create_c9_seal(root: Path, covered_head: str = "HEAD") -> C9ChangeSeal:
    root = _assert_safe_root(root)
    if _git_text(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("C9 seal generation requires a clean worktree")
    covered = _resolve_commit(root, covered_head)
    base = _resolve_commit(root, C9_BASE_COMMIT)
    _assert_ancestor(root, base, covered)
    manifest = _load_json_at(
        root,
        covered,
        C9_MANIFEST_PATH,
        C9ChangeManifest,
    )
    changed = _changed_paths(root, base, covered)
    if changed != manifest.changed_files:
        raise ValueError("C9 manifest does not exactly match the covered Git diff")
    _assert_ancestor(root, base, manifest.live_repository_head)
    _assert_ancestor(root, manifest.live_repository_head, covered)
    _verify_c8_manifest_dependency(root, manifest)
    manifest_sha = canonical_sha256(manifest.model_dump(mode="json"))
    return C9ChangeSeal(
        version="1",
        repository="Cheurteenyt/systeme-local",
        branch=C9_BRANCH,
        issue=80,
        issue_url=C9_ISSUE_URL,
        base_commit=C9_BASE_COMMIT,
        evidence_tag=C9_EVIDENCE_TAG,
        covered_head=covered,
        live_repository_head=manifest.live_repository_head,
        manifest_sha256=manifest_sha,
        final_attestation_sha256=manifest.final_attestation_sha256,
        final_attestation_model_sha256=manifest.final_attestation_model_sha256,
        accepted_c8_commit=manifest.accepted_c8_commit,
        c8_dependency_sha256=manifest.c8_dependency_sha256,
        c8_tree_sha256=manifest.c8_tree_sha256,
        chat_export_descriptor_sha256=manifest.chat_export_descriptor_sha256,
        chat_picker_claim_receipt_sha256=manifest.chat_picker_claim_receipt_sha256,
        diff=compute_c9_diff_commitment(root, base, covered),
        tree=compute_c9_tree_commitment(root, covered),
        covered_changed_file_count=len(changed),
        validation_status=("C9_WORK_RICH_MCP_AND_CHAT_MANUAL_LIVE_EVIDENCE_SEALED"),
        reviewed_outcome=C9_FINAL_STATUS,
        provider_live_actions_performed=True,
        work_rich_call_count=1,
        chat_manual_handoff_count=1,
        total_rich_mcp_call_count=1,
        work_rich_mcp_verified=True,
        chat_manual_visible_handoff_verified=True,
        same_sanitized_package_verified=True,
        native_chat_plugin_invoked=False,
        native_chat_provider_audit_correlation_claimed=False,
        unapproved_fallback_used=False,
        revocation_verified=True,
        automatic_chat_to_work_switch_used=False,
        regular_arbitrary_files_tested=False,
        regular_use_readiness_claimed=False,
        raw_sensitive_evidence_versioned=False,
    )


def _verify_exact_attestation(
    *,
    root: Path,
    covered_head: str,
    manifest: C9ChangeManifest,
    final_attestation_path: Path,
    audit_key: str | bytes,
) -> None:
    attestation = _read_final_attestation(
        final_attestation_path,
        audit_key=audit_key,
    )
    expected = _manifest_from_attestation(
        root=root,
        covered_head=covered_head,
        changed_files=manifest.changed_files,
        attestation=attestation,
    )
    if expected != manifest:
        raise ValueError("C9 final attestation does not exactly match the sealed manifest")


def verify_c9_seal(
    root: Path,
    *,
    require_current_tree: bool = False,
    require_clean: bool = False,
    final_attestation_path: Path | None = None,
    audit_key: str | bytes | None = None,
) -> C9SealVerification:
    root = _assert_safe_root(root)
    if require_clean and _git_text(
        root,
        "status",
        "--porcelain",
        "--untracked-files=all",
    ):
        raise ValueError("C9 final seal verification requires a clean worktree")
    if (final_attestation_path is None) != (audit_key is None):
        raise ValueError("C9 exact attestation verification requires both path and audit key")
    tag_object = _git_text(root, "rev-parse", "--verify", C9_EVIDENCE_TAG)
    if _git_text(root, "cat-file", "-t", tag_object) != "tag":
        raise ValueError("C9 evidence tag must be annotated")
    tag_target = _resolve_commit(root, C9_EVIDENCE_TAG)
    seal = _load_json_at(root, tag_target, C9_SEAL_PATH, C9ChangeSeal)
    parent = _resolve_commit(root, f"{tag_target}^")
    if parent != seal.covered_head:
        raise ValueError("C9 evidence tag parent is not the sealed covered head")
    if _changed_paths(root, seal.covered_head, tag_target) != (C9_SEAL_PATH,):
        raise ValueError("C9 evidence tag commit must add only the final seal")
    manifest = _load_json_at(
        root,
        seal.covered_head,
        C9_MANIFEST_PATH,
        C9ChangeManifest,
    )
    manifest_sha = canonical_sha256(manifest.model_dump(mode="json"))
    if manifest_sha != seal.manifest_sha256:
        raise ValueError("C9 sealed manifest digest mismatch")
    if (
        manifest.final_attestation_sha256 != seal.final_attestation_sha256
        or manifest.final_attestation_model_sha256 != seal.final_attestation_model_sha256
        or manifest.live_repository_head != seal.live_repository_head
        or manifest.accepted_c8_commit != seal.accepted_c8_commit
        or manifest.c8_dependency_sha256 != seal.c8_dependency_sha256
        or manifest.c8_tree_sha256 != seal.c8_tree_sha256
        or manifest.chat_export_descriptor_sha256 != seal.chat_export_descriptor_sha256
        or manifest.chat_picker_claim_receipt_sha256 != seal.chat_picker_claim_receipt_sha256
    ):
        raise ValueError("C9 seal does not bind its exact attestation and dependencies")
    changed = _changed_paths(root, C9_BASE_COMMIT, seal.covered_head)
    if changed != manifest.changed_files or len(changed) != seal.covered_changed_file_count:
        raise ValueError("C9 sealed changed-file set mismatch")
    _assert_ancestor(root, C9_BASE_COMMIT, manifest.live_repository_head)
    _assert_ancestor(root, manifest.live_repository_head, seal.covered_head)
    _verify_c8_manifest_dependency(root, manifest)
    diff = compute_c9_diff_commitment(
        root,
        C9_BASE_COMMIT,
        seal.covered_head,
    )
    tree = compute_c9_tree_commitment(root, seal.covered_head)
    tagged_tree = compute_c9_tree_commitment(root, tag_target)
    if diff != seal.diff or not (tree == tagged_tree == seal.tree):
        raise ValueError("C9 sealed diff or tree commitment mismatch")
    if final_attestation_path is None or audit_key is None:
        raise ValueError("C9 live seal success requires exact attestation re-verification")
    _verify_exact_attestation(
        root=root,
        covered_head=seal.covered_head,
        manifest=manifest,
        final_attestation_path=final_attestation_path,
        audit_key=audit_key,
    )
    current = _resolve_commit(root, "HEAD")
    _assert_ancestor(root, C9_BASE_COMMIT, current)
    if require_current_tree:
        current_tree = compute_c9_tree_commitment(root, current)
        if current_tree != seal.tree:
            raise ValueError("C9 current tree differs from the sealed tree")
    return C9SealVerification(
        status="verified",
        issue=80,
        base_commit=C9_BASE_COMMIT,
        live_repository_head=seal.live_repository_head,
        covered_head=seal.covered_head,
        tag_target=tag_target,
        current_head=current,
        current_tree_required=require_current_tree,
        exact_attestation_reverified=True,
        manifest_sha256=seal.manifest_sha256,
        final_attestation_sha256=seal.final_attestation_sha256,
        final_attestation_model_sha256=seal.final_attestation_model_sha256,
        accepted_c8_commit=seal.accepted_c8_commit,
        c8_dependency_sha256=seal.c8_dependency_sha256,
        c8_tree_sha256=seal.c8_tree_sha256,
        chat_export_descriptor_sha256=seal.chat_export_descriptor_sha256,
        chat_picker_claim_receipt_sha256=seal.chat_picker_claim_receipt_sha256,
        diff_sha256=seal.diff.sha256,
        tree_sha256=seal.tree.sha256,
        covered_changed_file_count=seal.covered_changed_file_count,
        tree_file_count=seal.tree.file_count,
        tree_blob_bytes=seal.tree.blob_bytes,
        reviewed_outcome=C9_FINAL_STATUS,
        provider_live_actions_performed=True,
        work_rich_call_count=1,
        chat_manual_handoff_count=1,
        total_rich_mcp_call_count=1,
        revocation_verified=True,
        work_rich_mcp_verified=True,
        chat_manual_visible_handoff_verified=True,
        same_sanitized_package_verified=True,
        native_chat_plugin_invoked=False,
        native_chat_provider_audit_correlation_claimed=False,
        unapproved_fallback_used=False,
        automatic_chat_to_work_switch_used=False,
        regular_use_readiness_claimed=False,
    )


def rendered_json(model: BaseModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _exact_output(root: Path, requested: str, expected: str) -> Path:
    candidate = Path(requested)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = Path(os.path.abspath(candidate))
    expected_path = Path(os.path.abspath(root / expected))
    if os.path.normcase(os.fspath(candidate)) != os.path.normcase(os.fspath(expected_path)):
        raise ValueError(f"C9 output must be exactly {expected}")
    if candidate.exists() or candidate.is_symlink():
        raise ValueError("C9 seal metadata output already exists; replay refused")
    return candidate


def _atomic_write(path: Path, content: bytes) -> None:
    if not content or len(content) > _MAX_METADATA_BYTES:
        raise ValueError("C9 seal output is empty or exceeds its byte boundary")
    _reject_reparse_prefix(path.parent)
    temporary = path.parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    descriptor: int | None = None
    try:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        flags |= int(getattr(os, "O_BINARY", 0))
        descriptor = os.open(temporary, flags, 0o600)
        view = memoryview(content)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("short C9 seal metadata write")
            written += count
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or _is_reparse(info)
            or int(info.st_nlink) != 1
            or int(info.st_size) != len(content)
        ):
            raise ValueError("C9 temporary seal metadata identity is unsafe")
        os.close(descriptor)
        descriptor = None
        if path.exists() or path.is_symlink():
            raise ValueError("C9 seal metadata output appeared before commit")
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _audit_key_from_environment() -> str:
    value = os.environ.get("SLG_AUDIT_KEY")
    if value is None or len(value.encode("utf-8")) < 32:
        raise ValueError("C9 manifest generation requires a process-local audit key")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="C9 reproducible live-evidence seal")
    subparsers = parser.add_subparsers(dest="command", required=True)
    manifest = subparsers.add_parser("create-manifest")
    manifest.add_argument("--final-attestation", type=Path, required=True)
    manifest.add_argument("--covered-head", default="HEAD")
    manifest.add_argument("--output", default=C9_MANIFEST_PATH)
    create = subparsers.add_parser("create")
    create.add_argument("--covered-head", default="HEAD")
    create.add_argument("--output", default=C9_SEAL_PATH)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--require-current-tree", action="store_true")
    verify.add_argument("--require-clean", action="store_true")
    verify.add_argument("--final-attestation", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = _repository_root()
    try:
        if args.command == "create-manifest":
            manifest = create_c9_manifest(
                root,
                final_attestation_path=args.final_attestation,
                audit_key=_audit_key_from_environment(),
                covered_head=args.covered_head,
            )
            output = _exact_output(root, args.output, C9_MANIFEST_PATH)
            _atomic_write(output, rendered_json(manifest).encode("utf-8"))
            print(rendered_json(manifest), end="")
            return 0
        if args.command == "create":
            seal = create_c9_seal(root, args.covered_head)
            output = _exact_output(root, args.output, C9_SEAL_PATH)
            _atomic_write(output, rendered_json(seal).encode("utf-8"))
            print(rendered_json(seal), end="")
            return 0
        result = verify_c9_seal(
            root,
            require_current_tree=args.require_current_tree,
            require_clean=args.require_clean,
            final_attestation_path=args.final_attestation,
            audit_key=_audit_key_from_environment(),
        )
        print(rendered_json(result), end="")
        return 0
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(
            json.dumps(
                {
                    "status": "error",
                    "error": str(error),
                    "seal_created": False,
                    "live_success_claimed": False,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
