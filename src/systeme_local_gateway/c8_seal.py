from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from hashlib import sha256
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

C8_BASE_COMMIT: Final[Literal["e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"]] = (
    "e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"
)
C8_BRANCH: Final[Literal["codex/chatgpt-work-live-c8"]] = "codex/chatgpt-work-live-c8"
C8_EVIDENCE_TAG: Final[Literal["evidence/chatgpt-work-live-c8-v1"]] = (
    "evidence/chatgpt-work-live-c8-v1"
)
C8_MANIFEST_PATH = "governance/c8-change-manifest.json"
C8_SEAL_PATH: Final[Literal["governance/c8-change-seal.json"]] = "governance/c8-change-seal.json"
C8_FINAL_STATUS: Final[Literal["COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"]] = (
    "COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"
)

_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


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


def _validate_repo_path(value: str) -> str:
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\0" in value
        or ".." in Path(value).parts
        or Path(value).as_posix() != value
    ):
        raise ValueError("C8 seal path is not canonical")
    return value


class C8ChangeManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    repository: Literal["Cheurteenyt/systeme-local"]
    default_branch: Literal["main"]
    branch: Literal["codex/chatgpt-work-live-c8"]
    issue: Literal[78]
    base_commit: Literal["e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"]
    merge_method: Literal["squash"]
    evidence_tag: Literal["evidence/chatgpt-work-live-c8-v1"]
    official_revalidation_id: Literal["chatgpt_work_c8_revalidation_20260727"]
    official_source_count: Literal[7]
    reviewed_outcome: Literal["COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"]
    native_chat_outcome: Literal["BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"]
    only_eligible_tool: Literal["systeme_local_connectivity_probe"]
    max_new_synthetic_work_tasks: Literal[2]
    max_live_cycle_seconds: Literal[1200]
    operator_authorization_received: Literal[True]
    implementation_status: Literal["complete_live_two_work_calls_correlated_and_revoked"]
    changed_files: tuple[str, ...]
    official_docs_review_performed: Literal[True]
    mcp_fetch_route_inconsistency_recorded: Literal[False]
    browser_actions_performed: Literal[True]
    visible_plugins_surface_confirmed: Literal[True]
    visible_work_task_surface_confirmed: Literal[True]
    visible_work_entitlement_confirmed: Literal[True]
    visible_work_quota_confirmed: Literal[True]
    latest_visible_surface_check_at: Literal["2026-07-27T23:29:05.018566Z"]
    latest_visible_surface_check_result: Literal[
        "work_composer_visible_entitlement_available_quota_usable"
    ]
    visible_model_label: Literal["GPT-5.6 Sol"]
    visible_reasoning_label: Literal["Minimal"]
    exact_internal_model_id_claimed: Literal[False]
    runtime_key_created: Literal[True]
    runtime_key_platform_revocation_confirmed: Literal[True]
    interrupted_cycle_runtime_key_revocation_confirmed_at: Literal["2026-07-27T23:16:00Z"]
    tunnel_started: Literal[True]
    plugin_connection_created: Literal[True]
    plugin_connection_removed: Literal[True]
    work_tasks_created: Literal[2]
    local_probe_calls_correlated: Literal[1]
    live_work_calls_correlated: Literal[2]
    completed_audit_records: Literal[3]
    failed_audit_records: Literal[2]
    same_work_replay: Literal["rejected"]
    cross_work_replay: Literal["rejected"]
    unknown_field: Literal["rejected"]
    malformed_challenge: Literal["rejected"]
    capability_expanded: Literal[False]
    post_revocation_call: Literal["unreachable_after_revocation"]
    revocation_verified: Literal[True]
    native_chat_tested: Literal[False]
    existing_conversations_accessed: Literal[False]
    private_browser_state_accessed: Literal[False]
    write_tool_count: Literal[0]
    high_risk_tool_count: Literal[0]
    effective_tool_count_before_grant: Literal[0]
    effective_tool_count_during_grant: Literal[1]
    regular_use_readiness_claimed: Literal[False]
    final_cleanup_performed: Literal[True]
    transient_artifacts_removed: Literal[13]
    preserved_receipt_count: Literal[11]
    process_secrets_cleared: Literal[True]
    live_connectivity_recoverable: Literal[False]
    raw_sensitive_evidence_versioned: Literal[False]
    attestation_verified_at: Literal["2026-07-27T23:59:30.947738Z"]
    attestation_sha256: str = Field(pattern=_SHA256_PATTERN)
    authorization_sha256: str = Field(pattern=_SHA256_PATTERN)
    grant_sha256: str = Field(pattern=_SHA256_PATTERN)
    correlation_receipt_sha256: tuple[str, str]
    work_observation_sha256: tuple[str, str]
    negative_test_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    revocation_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    local_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    tool_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_manifest(self) -> C8ChangeManifest:
        for path in self.changed_files:
            _validate_repo_path(path)
        if self.changed_files != tuple(sorted(set(self.changed_files))):
            raise ValueError("C8 manifest paths must be sorted and unique")
        if C8_MANIFEST_PATH not in self.changed_files:
            raise ValueError("C8 manifest must cover itself")
        if C8_SEAL_PATH in self.changed_files:
            raise ValueError("C8 covered head cannot contain its self-referential seal")
        for pair in (self.correlation_receipt_sha256, self.work_observation_sha256):
            if len(set(pair)) != 2 or any(
                re.fullmatch(_SHA256_PATTERN, item) is None for item in pair
            ):
                raise ValueError("C8 two-call commitments must contain two distinct SHA-256 values")
        return self


class C8DiffCommitment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: Literal["sha256-git-binary-diff-v1"]
    excluded_paths: tuple[Literal["governance/c8-change-seal.json"], ...]
    sha256: str = Field(pattern=_SHA256_PATTERN)
    bytes: int = Field(ge=1)


class C8TreeCommitment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: Literal["sha256-framed-tree-v1"]
    excluded_paths: tuple[Literal["governance/c8-change-seal.json"], ...]
    sha256: str = Field(pattern=_SHA256_PATTERN)
    file_count: int = Field(ge=1)
    blob_bytes: int = Field(ge=1)


class C8ChangeSeal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    repository: Literal["Cheurteenyt/systeme-local"]
    branch: Literal["codex/chatgpt-work-live-c8"]
    base_commit: Literal["e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"]
    evidence_tag: Literal["evidence/chatgpt-work-live-c8-v1"]
    covered_head: str = Field(pattern=_COMMIT_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    final_attestation_sha256: str = Field(pattern=_SHA256_PATTERN)
    diff: C8DiffCommitment
    tree: C8TreeCommitment
    covered_changed_file_count: int = Field(ge=1)
    validation_status: Literal["C8_WORK_LIVE_EVIDENCE_SEALED"]
    reviewed_outcome: Literal["COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"]
    official_docs_review_performed: Literal[True]
    browser_actions_performed: Literal[True]
    credentials_created: Literal[True]
    tunnel_started: Literal[True]
    plugin_connection_created: Literal[True]
    provider_live_actions_performed: Literal[True]
    work_call_count: Literal[2]
    revocation_verified: Literal[True]
    native_chat_tested: Literal[False]
    regular_use_readiness_claimed: Literal[False]
    effective_tool_count: Literal[1]


class C8SealVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["verified"]
    base_commit: str = Field(pattern=_COMMIT_PATTERN)
    covered_head: str = Field(pattern=_COMMIT_PATTERN)
    tag_target: str = Field(pattern=_COMMIT_PATTERN)
    current_head: str = Field(pattern=_COMMIT_PATTERN)
    current_tree_required: bool
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    final_attestation_sha256: str = Field(pattern=_SHA256_PATTERN)
    diff_sha256: str = Field(pattern=_SHA256_PATTERN)
    tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    covered_changed_file_count: int = Field(ge=1)
    tree_file_count: int = Field(ge=1)
    tree_blob_bytes: int = Field(ge=1)
    reviewed_outcome: Literal["COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"]
    provider_live_actions_performed: Literal[True]
    work_call_count: Literal[2]
    revocation_verified: Literal[True]
    effective_tool_count: Literal[1]


def _assert_safe_root(root: Path) -> Path:
    resolved = root.resolve(strict=True)
    if not (resolved / ".git").exists():
        raise ValueError("C8 seal root must be a Git worktree")
    current = Path(resolved.anchor)
    for part in resolved.parts[1:]:
        current /= part
        info = current.lstat()
        attributes = getattr(info, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if current.is_symlink() or (reparse and attributes & reparse):
            raise ValueError("C8 seal root cannot traverse a reparse point")
    return resolved


def _git(root: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        (
            "git",
            "-c",
            "core.quotePath=false",
            "-c",
            "core.autocrlf=false",
            "-C",
            os.fspath(root),
            *args,
        ),
        input=input_bytes,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout


def _git_text(root: Path, *args: str) -> str:
    return _git(root, *args).decode("utf-8", errors="strict").strip()


def _resolve_commit(root: Path, value: str) -> str:
    resolved = _git_text(root, "rev-parse", "--verify", f"{value}^{{commit}}")
    if re.fullmatch(_COMMIT_PATTERN, resolved) is None:
        raise ValueError(f"C8 Git reference {value!r} did not resolve to a commit")
    return resolved


def _assert_ancestor(root: Path, ancestor: str, descendant: str) -> None:
    completed = subprocess.run(
        ("git", "-C", os.fspath(root), "merge-base", "--is-ancestor", ancestor, descendant),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise ValueError(f"C8 ancestry mismatch: {ancestor} is not an ancestor of {descendant}")


def _load_json_at(root: Path, commit: str, path: str, model: type[BaseModel]) -> BaseModel:
    raw = _git(root, "show", f"{commit}:{path}")
    return model.model_validate_json(raw)


def _changed_paths(root: Path, base: str, head: str) -> tuple[str, ...]:
    raw = _git(root, "diff", "--name-only", "-z", base, head, "--")
    paths = tuple(item.decode("utf-8", errors="strict") for item in raw.split(b"\0") if item)
    for path in paths:
        _validate_repo_path(path)
    return tuple(sorted(paths))


def compute_c8_diff_commitment(root: Path, base: str, head: str) -> C8DiffCommitment:
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
        f":(exclude){C8_SEAL_PATH}",
    )
    if not raw:
        raise ValueError("C8 covered diff cannot be empty")
    return C8DiffCommitment(
        algorithm="sha256-git-binary-diff-v1",
        excluded_paths=(C8_SEAL_PATH,),
        sha256=sha256(raw).hexdigest(),
        bytes=len(raw),
    )


def _tree_entries(root: Path, commit: str) -> tuple[tuple[str, str, str], ...]:
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
            raise ValueError("C8 tree contains a non-blob recursive entry")
        if path != C8_SEAL_PATH:
            entries.append((path, mode, object_id))
    return tuple(sorted(entries))


def compute_c8_tree_commitment(root: Path, commit: str) -> C8TreeCommitment:
    root = _assert_safe_root(root)
    resolved = _resolve_commit(root, commit)
    digest = sha256()
    total_bytes = 0
    entries = _tree_entries(root, resolved)
    for path, mode, object_id in entries:
        blob = _git(root, "cat-file", "blob", object_id)
        path_bytes = path.encode("utf-8")
        mode_bytes = mode.encode("ascii")
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(mode_bytes).to_bytes(8, "big"))
        digest.update(mode_bytes)
        digest.update(len(blob).to_bytes(8, "big"))
        digest.update(blob)
        total_bytes += len(blob)
    return C8TreeCommitment(
        algorithm="sha256-framed-tree-v1",
        excluded_paths=(C8_SEAL_PATH,),
        sha256=digest.hexdigest(),
        file_count=len(entries),
        blob_bytes=total_bytes,
    )


def create_c8_seal(root: Path, covered_head: str = "HEAD") -> C8ChangeSeal:
    root = _assert_safe_root(root)
    covered = _resolve_commit(root, covered_head)
    base = _resolve_commit(root, C8_BASE_COMMIT)
    _assert_ancestor(root, base, covered)
    manifest_model = _load_json_at(root, covered, C8_MANIFEST_PATH, C8ChangeManifest)
    assert isinstance(manifest_model, C8ChangeManifest)
    manifest = manifest_model
    changed = _changed_paths(root, base, covered)
    if changed != manifest.changed_files:
        raise ValueError("C8 manifest does not exactly match the covered Git diff")
    manifest_sha = canonical_sha256(manifest.model_dump(mode="json"))
    return C8ChangeSeal(
        version="1",
        repository="Cheurteenyt/systeme-local",
        branch=C8_BRANCH,
        base_commit=C8_BASE_COMMIT,
        evidence_tag=C8_EVIDENCE_TAG,
        covered_head=covered,
        manifest_sha256=manifest_sha,
        final_attestation_sha256=manifest.attestation_sha256,
        diff=compute_c8_diff_commitment(root, base, covered),
        tree=compute_c8_tree_commitment(root, covered),
        covered_changed_file_count=len(changed),
        validation_status="C8_WORK_LIVE_EVIDENCE_SEALED",
        reviewed_outcome=C8_FINAL_STATUS,
        official_docs_review_performed=True,
        browser_actions_performed=True,
        credentials_created=True,
        tunnel_started=True,
        plugin_connection_created=True,
        provider_live_actions_performed=True,
        work_call_count=2,
        revocation_verified=True,
        native_chat_tested=False,
        regular_use_readiness_claimed=False,
        effective_tool_count=1,
    )


def verify_c8_seal(
    root: Path,
    *,
    require_current_tree: bool = False,
    require_clean: bool = False,
) -> C8SealVerification:
    root = _assert_safe_root(root)
    if require_clean and _git_text(root, "status", "--porcelain"):
        raise ValueError("C8 final seal verification requires a clean worktree")
    tag_object = _git_text(root, "rev-parse", "--verify", C8_EVIDENCE_TAG)
    if _git_text(root, "cat-file", "-t", tag_object) != "tag":
        raise ValueError("C8 evidence tag must be annotated")
    tag_target = _resolve_commit(root, C8_EVIDENCE_TAG)
    seal_model = _load_json_at(root, tag_target, C8_SEAL_PATH, C8ChangeSeal)
    assert isinstance(seal_model, C8ChangeSeal)
    seal = seal_model
    parent = _resolve_commit(root, f"{tag_target}^")
    if parent != seal.covered_head:
        raise ValueError("C8 evidence tag parent is not the sealed covered head")
    tag_changes = _changed_paths(root, seal.covered_head, tag_target)
    if tag_changes != (C8_SEAL_PATH,):
        raise ValueError("C8 evidence tag commit must add only the final seal")
    manifest_model = _load_json_at(root, seal.covered_head, C8_MANIFEST_PATH, C8ChangeManifest)
    assert isinstance(manifest_model, C8ChangeManifest)
    manifest = manifest_model
    manifest_sha = canonical_sha256(manifest.model_dump(mode="json"))
    if manifest_sha != seal.manifest_sha256:
        raise ValueError("C8 sealed manifest digest mismatch")
    if manifest.attestation_sha256 != seal.final_attestation_sha256:
        raise ValueError("C8 final attestation commitment mismatch")
    changed = _changed_paths(root, C8_BASE_COMMIT, seal.covered_head)
    if changed != manifest.changed_files or len(changed) != seal.covered_changed_file_count:
        raise ValueError("C8 sealed changed-file set mismatch")
    diff = compute_c8_diff_commitment(root, C8_BASE_COMMIT, seal.covered_head)
    tree = compute_c8_tree_commitment(root, seal.covered_head)
    tagged_tree = compute_c8_tree_commitment(root, tag_target)
    if diff != seal.diff or not (tree == tagged_tree == seal.tree):
        raise ValueError("C8 sealed diff or tree commitment mismatch")
    current = _resolve_commit(root, "HEAD")
    _assert_ancestor(root, C8_BASE_COMMIT, current)
    if require_current_tree:
        current_tree = compute_c8_tree_commitment(root, current)
        if current_tree != seal.tree:
            raise ValueError("C8 current tree differs from the sealed tree")
    return C8SealVerification(
        status="verified",
        base_commit=C8_BASE_COMMIT,
        covered_head=seal.covered_head,
        tag_target=tag_target,
        current_head=current,
        current_tree_required=require_current_tree,
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="C8 reproducible live-evidence seal")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--covered-head", default="HEAD")
    create.add_argument("--output", default=C8_SEAL_PATH)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--require-current-tree", action="store_true")
    verify.add_argument("--require-clean", action="store_true")
    args = parser.parse_args(argv)
    root = _repository_root()
    try:
        if args.command == "create":
            seal = create_c8_seal(root, args.covered_head)
            output = root / args.output
            if output.resolve().parent != (root / "governance").resolve():
                raise ValueError("C8 seal output must remain in governance")
            output.write_text(rendered_json(seal), encoding="utf-8", newline="\n")
            print(rendered_json(seal), end="")
            return 0
        result = verify_c8_seal(
            root,
            require_current_tree=args.require_current_tree,
            require_clean=args.require_clean,
        )
        print(rendered_json(result), end="")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(
            json.dumps(
                {
                    "status": "error",
                    "error": str(error),
                    "provider_live_actions_performed": True,
                    "work_call_count": 2,
                    "revocation_verified": True,
                    "effective_tool_count": 1,
                },
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
