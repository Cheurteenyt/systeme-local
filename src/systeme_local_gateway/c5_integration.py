from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from hashlib import sha256
from itertools import pairwise
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

C5_MANIFEST_PATH = "governance/c5-integration-manifest.json"
C5_SEAL_PATH: Final = "governance/c5-change-seal.json"
C5_EVIDENCE_TAG = "evidence/c0-c4-main-integration-v2"
C5_MAIN_BASE = "32515ac9cbb9d658b2ddcb2723ab3c0a71f2b418"
C5_ACCEPTED_MAIN_COMMIT = "418112758d8675326835d9947ccce3a1b12f6f25"
C5_INTEGRATION_BRANCH = "interop/c0-c4-main-integration-c5"
C4_SEALED_COMMIT = "3a1d2b8286773eaaf69b0b41fade978f09403adb"

_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_BRANCH_PATTERN = r"^[a-z0-9][a-z0-9._/-]{2,127}$"
_TAG_PATTERN = r"^[a-z0-9][a-z0-9._/-]{2,127}$"
_EXPECTED_GATES = ("C0", "C1", "C2", "C3", "C4")
_EXPECTED_PRS = (65, 67, 68, 70, 72)
_EXPECTED_HEADS = (
    "912d0d33e119469ff957965104cf20af5e491923",
    "2aee36fdfa3d20c23acdc75eb3348bc54536ef4f",
    "cf05e963ba30539f9b2c9ec2f5f71326cbba8399",
    "9140801e88ed44afca9481ac06288783a0d52da2",
    C4_SEALED_COMMIT,
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return sha256(canonical_json(value)).hexdigest()


class StackLayer(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    gate: Literal["C0", "C1", "C2", "C3", "C4"]
    pull_request: int = Field(ge=1)
    branch: str = Field(pattern=_BRANCH_PATTERN)
    head: str = Field(pattern=_COMMIT_PATTERN)


class IntegrationManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    repository: Literal["Cheurteenyt/systeme-local"]
    issue: Literal["https://github.com/Cheurteenyt/systeme-local/issues/73"]
    default_branch: Literal["main"]
    integration_branch: Literal["interop/c0-c4-main-integration-c5"]
    base_commit: Literal["32515ac9cbb9d658b2ddcb2723ab3c0a71f2b418"]
    merge_method: Literal["squash"]
    evidence_tag: Literal["evidence/c0-c4-main-integration-v2"]
    source_stack: tuple[StackLayer, ...]
    historical_branches_are_evidence: Literal[True]
    live_actions_permitted: Literal[False]

    @model_validator(mode="after")
    def validate_exact_stack(self) -> IntegrationManifest:
        if tuple(layer.gate for layer in self.source_stack) != _EXPECTED_GATES:
            raise ValueError("C5 source stack gates must be exactly C0 through C4")
        if tuple(layer.pull_request for layer in self.source_stack) != _EXPECTED_PRS:
            raise ValueError("C5 source stack pull requests are not exact")
        if tuple(layer.head for layer in self.source_stack) != _EXPECTED_HEADS:
            raise ValueError("C5 source stack heads are not exact")
        branches = tuple(layer.branch for layer in self.source_stack)
        if len(set(branches)) != len(branches):
            raise ValueError("C5 source stack branches must be unique")
        return self


class DiffCommitment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: Literal["sha256"]
    excluded_paths: tuple[Literal["governance/c5-change-seal.json"], ...]
    sha256: str = Field(pattern=_SHA256_PATTERN)
    bytes: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_exclusion(self) -> DiffCommitment:
        if self.excluded_paths != (C5_SEAL_PATH,):
            raise ValueError("C5 diff must exclude only its self-referential seal")
        return self


class TreeCommitment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: Literal["sha256-framed-tree-v1"]
    excluded_paths: tuple[Literal["governance/c5-change-seal.json"], ...]
    sha256: str = Field(pattern=_SHA256_PATTERN)
    file_count: int = Field(ge=1)
    blob_bytes: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_exclusion(self) -> TreeCommitment:
        if self.excluded_paths != (C5_SEAL_PATH,):
            raise ValueError("C5 tree must exclude only its self-referential seal")
        return self


class IntegrationSeal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    repository: Literal["Cheurteenyt/systeme-local"]
    issue: Literal["https://github.com/Cheurteenyt/systeme-local/issues/73"]
    integration_branch: Literal["interop/c0-c4-main-integration-c5"]
    evidence_tag: Literal["evidence/c0-c4-main-integration-v2"]
    base_commit: Literal["32515ac9cbb9d658b2ddcb2723ab3c0a71f2b418"]
    source_head: Literal["3a1d2b8286773eaaf69b0b41fade978f09403adb"]
    covered_head: str = Field(pattern=_COMMIT_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    diff: DiffCommitment
    tree: TreeCommitment
    changed_file_count: int = Field(ge=1)
    changed_files: tuple[str, ...]
    validation_status: Literal["C5_SQUASH_INTEGRATION_SEALED"]
    live_actions_performed: Literal[False]

    @model_validator(mode="after")
    def validate_changed_files(self) -> IntegrationSeal:
        if len(self.changed_files) != self.changed_file_count:
            raise ValueError("C5 changed file count mismatch")
        if self.changed_files != tuple(sorted(set(self.changed_files))):
            raise ValueError("C5 changed files must be sorted and unique")
        if C5_SEAL_PATH not in self.changed_files:
            raise ValueError("C5 changed files must include the self-excluding seal")
        return self


class IntegrationVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["verified"]
    base_commit: str = Field(pattern=_COMMIT_PATTERN)
    source_head: str = Field(pattern=_COMMIT_PATTERN)
    covered_head: str = Field(pattern=_COMMIT_PATTERN)
    tag_target: str = Field(pattern=_COMMIT_PATTERN)
    accepted_main_commit: str = Field(pattern=_COMMIT_PATTERN)
    current_head: str = Field(pattern=_COMMIT_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    diff_sha256: str = Field(pattern=_SHA256_PATTERN)
    tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    tree_file_count: int = Field(ge=1)
    tree_blob_bytes: int = Field(ge=1)
    live_actions_performed: Literal[False] = False


def _assert_safe_root(root: Path) -> Path:
    resolved = root.resolve(strict=True)
    if not (resolved / ".git").exists():
        raise ValueError("C5 root must be a Git worktree")
    current = Path(resolved.anchor)
    for part in resolved.parts[1:]:
        current /= part
        info = current.lstat()
        attributes = getattr(info, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if current.is_symlink() or (reparse and attributes & reparse):
            raise ValueError("C5 root cannot traverse a reparse point")
    return resolved


def _git(root: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ("git", "-c", "core.quotePath=false", "-C", os.fspath(root), *args),
        check=True,
        capture_output=True,
    )
    return completed.stdout


def _git_text(root: Path, *args: str) -> str:
    return _git(root, *args).decode("utf-8", errors="strict").strip()


def _load_model(path: Path, model: type[BaseModel]) -> BaseModel:
    value = json.loads(path.read_text(encoding="utf-8"))
    return model.model_validate(value)


def _resolve_commit(root: Path, value: str) -> str:
    resolved = _git_text(root, "rev-parse", "--verify", f"{value}^{{commit}}")
    if not re.fullmatch(_COMMIT_PATTERN, resolved):
        raise ValueError(f"C5 Git reference {value!r} did not resolve to a commit")
    return resolved


def _assert_ancestor(root: Path, ancestor: str, descendant: str) -> None:
    completed = subprocess.run(
        ("git", "-C", os.fspath(root), "merge-base", "--is-ancestor", ancestor, descendant),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise ValueError(f"C5 ancestry mismatch: {ancestor} is not an ancestor of {descendant}")


def _parse_tree_entries(raw: bytes) -> tuple[tuple[bytes, bytes, str], ...]:
    entries: list[tuple[bytes, bytes, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, separator, path_bytes = record.partition(b"\t")
        if not separator:
            raise ValueError("C5 received malformed git ls-tree output")
        parts = metadata.split(b" ")
        if len(parts) != 3 or parts[1] != b"blob":
            raise ValueError("C5 supports only tracked blob entries")
        path = path_bytes.decode("utf-8", errors="strict")
        if path.startswith("/") or "\\" in path or ".." in Path(path).parts:
            raise ValueError("C5 tree contains a non-canonical path")
        entries.append((parts[0], parts[2], path))
    if tuple(path for _, _, path in entries) != tuple(sorted(path for _, _, path in entries)):
        raise ValueError("C5 tree entries are not canonically sorted")
    return tuple(entries)


def _read_blobs(root: Path, object_ids: tuple[bytes, ...]) -> dict[bytes, bytes]:
    unique_ids = tuple(dict.fromkeys(object_ids))
    completed = subprocess.run(
        (
            "git",
            "-c",
            "core.quotePath=false",
            "-C",
            os.fspath(root),
            "cat-file",
            "--batch",
        ),
        input=b"\n".join(unique_ids) + b"\n",
        check=True,
        capture_output=True,
    )
    output = completed.stdout
    offset = 0
    blobs: dict[bytes, bytes] = {}
    for expected_id in unique_ids:
        header_end = output.find(b"\n", offset)
        if header_end < 0:
            raise ValueError("C5 received truncated git cat-file output")
        header = output[offset:header_end].split(b" ")
        if len(header) != 3 or header[0] != expected_id or header[1] != b"blob":
            raise ValueError("C5 received unexpected git cat-file metadata")
        try:
            size = int(header[2])
        except ValueError as exc:
            raise ValueError("C5 received an invalid git blob length") from exc
        blob_start = header_end + 1
        blob_end = blob_start + size
        if blob_end >= len(output) or output[blob_end : blob_end + 1] != b"\n":
            raise ValueError("C5 received malformed git blob framing")
        blobs[expected_id] = output[blob_start:blob_end]
        offset = blob_end + 1
    if offset != len(output):
        raise ValueError("C5 received trailing git cat-file output")
    return blobs


def compute_tree_commitment(
    root: Path,
    commit: str,
) -> TreeCommitment:
    resolved_root = _assert_safe_root(root)
    resolved_commit = _resolve_commit(resolved_root, commit)
    entries = _parse_tree_entries(
        _git(resolved_root, "ls-tree", "-rz", "--full-tree", resolved_commit)
    )
    excluded_paths = (C5_SEAL_PATH,)
    excluded = set(excluded_paths)
    blobs = _read_blobs(
        resolved_root,
        tuple(object_id for _, object_id, path in entries if path not in excluded),
    )
    digest = sha256()
    file_count = 0
    blob_bytes = 0
    for mode, object_id, path in entries:
        if path in excluded:
            continue
        path_bytes = path.encode("utf-8")
        blob = blobs[object_id]
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(mode).to_bytes(2, "big"))
        digest.update(mode)
        digest.update(len(blob).to_bytes(8, "big"))
        digest.update(blob)
        file_count += 1
        blob_bytes += len(blob)
    return TreeCommitment(
        algorithm="sha256-framed-tree-v1",
        excluded_paths=excluded_paths,
        sha256=digest.hexdigest(),
        file_count=file_count,
        blob_bytes=blob_bytes,
    )


def compute_diff_commitment(
    root: Path,
    base: str,
    head: str,
) -> DiffCommitment:
    resolved_root = _assert_safe_root(root)
    excluded_paths = (C5_SEAL_PATH,)
    exclusions = tuple(f":(exclude){path}" for path in excluded_paths)
    diff = _git(
        resolved_root,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        base,
        head,
        "--",
        ".",
        *exclusions,
    )
    return DiffCommitment(
        algorithm="sha256",
        excluded_paths=excluded_paths,
        sha256=sha256(diff).hexdigest(),
        bytes=len(diff),
    )


def verify_integration(
    root: Path,
    *,
    manifest_path: Path | None = None,
    seal_path: Path | None = None,
    require_clean: bool = False,
) -> IntegrationVerification:
    resolved_root = _assert_safe_root(root)
    manifest_file = manifest_path or resolved_root / C5_MANIFEST_PATH
    seal_file = seal_path or resolved_root / C5_SEAL_PATH
    manifest = IntegrationManifest.model_validate(
        _load_model(manifest_file.resolve(strict=True), IntegrationManifest)
    )
    seal = IntegrationSeal.model_validate(
        _load_model(seal_file.resolve(strict=True), IntegrationSeal)
    )
    manifest_digest = canonical_sha256(manifest.model_dump(mode="json"))
    if seal.manifest_sha256 != manifest_digest:
        raise ValueError("C5 manifest commitment mismatch")

    expected_chain = (manifest.base_commit, *(layer.head for layer in manifest.source_stack))
    for ancestor, descendant in pairwise(expected_chain):
        _assert_ancestor(resolved_root, ancestor, descendant)
    _assert_ancestor(resolved_root, manifest.source_stack[-1].head, seal.covered_head)

    tag_target = _resolve_commit(resolved_root, manifest.evidence_tag)
    tag_parent = _resolve_commit(resolved_root, f"{tag_target}^")
    if tag_parent != seal.covered_head:
        raise ValueError("C5 evidence tag must point to the one-file seal commit")
    post_covered = _git_text(
        resolved_root,
        "diff",
        "--name-only",
        seal.covered_head,
        tag_target,
        "--",
        ".",
    ).splitlines()
    if post_covered != [C5_SEAL_PATH]:
        raise ValueError("C5 final tag commit must add only the self-excluding seal")

    observed_diff = compute_diff_commitment(
        resolved_root,
        manifest.base_commit,
        seal.covered_head,
    )
    if observed_diff != seal.diff:
        raise ValueError("C5 aggregate diff commitment mismatch")
    covered_tree = compute_tree_commitment(resolved_root, seal.covered_head)
    tagged_tree = compute_tree_commitment(resolved_root, tag_target)
    accepted_main_commit = _resolve_commit(resolved_root, C5_ACCEPTED_MAIN_COMMIT)
    accepted_main_tree = compute_tree_commitment(resolved_root, accepted_main_commit)
    current_head = _resolve_commit(resolved_root, "HEAD")
    _assert_ancestor(resolved_root, accepted_main_commit, current_head)
    if not (covered_tree == tagged_tree == accepted_main_tree == seal.tree):
        raise ValueError("C5 accepted main commit differs from the sealed aggregate tree")

    if require_clean and _git_text(resolved_root, "status", "--porcelain=v1"):
        raise ValueError("C5 verification requires a clean worktree")

    return IntegrationVerification(
        status="verified",
        base_commit=manifest.base_commit,
        source_head=manifest.source_stack[-1].head,
        covered_head=seal.covered_head,
        tag_target=tag_target,
        accepted_main_commit=accepted_main_commit,
        current_head=current_head,
        manifest_sha256=manifest_digest,
        diff_sha256=observed_diff.sha256,
        tree_sha256=accepted_main_tree.sha256,
        tree_file_count=accepted_main_tree.file_count,
        tree_blob_bytes=accepted_main_tree.blob_bytes,
    )


def _json_output(value: BaseModel) -> str:
    return json.dumps(
        value.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--root", type=Path, default=root)
    verify.add_argument("--require-clean", action="store_true")
    tree = subparsers.add_parser("tree")
    tree.add_argument("--root", type=Path, default=root)
    tree.add_argument("--commit", required=True)
    diff = subparsers.add_parser("diff")
    diff.add_argument("--root", type=Path, default=root)
    diff.add_argument("--base", required=True)
    diff.add_argument("--head", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "verify":
            print(_json_output(verify_integration(args.root, require_clean=args.require_clean)))
        elif args.command == "tree":
            print(_json_output(compute_tree_commitment(args.root, args.commit)))
        else:
            print(_json_output(compute_diff_commitment(args.root, args.base, args.head)))
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {"status": "error", "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
