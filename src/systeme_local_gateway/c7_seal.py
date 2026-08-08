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

C7_BASE_COMMIT: Final = "81bed9b81f266709fab0ea4178f98f0607c3da44"
C7_BRANCH: Final = "codex/chatgpt-work-capability-c7"
C7_EVIDENCE_TAG: Final = "evidence/chatgpt-work-prelive-c7-v1"
C7_MANIFEST_PATH = "governance/c7-change-manifest.json"
C7_SEAL_PATH: Final = "governance/c7-change-seal.json"

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
        raise ValueError("C7 seal path is not canonical")
    return value


class C7ChangeManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    repository: Literal["Cheurteenyt/systeme-local"]
    default_branch: Literal["main"]
    branch: Literal["codex/chatgpt-work-capability-c7"]
    issue: Literal[76]
    base_commit: Literal["81bed9b81f266709fab0ea4178f98f0607c3da44"]
    merge_method: Literal["squash"]
    evidence_tag: Literal["evidence/chatgpt-work-prelive-c7-v1"]
    profile_id: Literal["chatgpt_work_c7_20260727"]
    official_source_count: Literal[6]
    reviewed_outcome: Literal["COMPLETE_C7_WORK_PROFILE_READY_FOR_BOUNDED_LIVE_VALIDATION"]
    native_chat_outcome: Literal["BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"]
    changed_files: tuple[str, ...]
    official_docs_review_performed: Literal[True]
    browser_actions_performed: Literal[False]
    credentials_created: Literal[False]
    tunnel_started: Literal[False]
    plugin_created: Literal[False]
    provider_live_actions_performed: Literal[False]
    effective_tool_count: Literal[0]

    @model_validator(mode="after")
    def validate_manifest(self) -> C7ChangeManifest:
        for path in self.changed_files:
            _validate_repo_path(path)
        if self.changed_files != tuple(sorted(set(self.changed_files))):
            raise ValueError("C7 manifest paths must be sorted and unique")
        if C7_MANIFEST_PATH not in self.changed_files:
            raise ValueError("C7 manifest must cover itself")
        if C7_SEAL_PATH in self.changed_files:
            raise ValueError("C7 covered head cannot contain its self-referential seal")
        return self


class C7DiffCommitment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: Literal["sha256-git-binary-diff-v1"]
    excluded_paths: tuple[Literal["governance/c7-change-seal.json"], ...]
    sha256: str = Field(pattern=_SHA256_PATTERN)
    bytes: int = Field(ge=1)


class C7TreeCommitment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: Literal["sha256-framed-tree-v1"]
    excluded_paths: tuple[Literal["governance/c7-change-seal.json"], ...]
    sha256: str = Field(pattern=_SHA256_PATTERN)
    file_count: int = Field(ge=1)
    blob_bytes: int = Field(ge=1)


class C7ChangeSeal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    repository: Literal["Cheurteenyt/systeme-local"]
    branch: Literal["codex/chatgpt-work-capability-c7"]
    base_commit: Literal["81bed9b81f266709fab0ea4178f98f0607c3da44"]
    evidence_tag: Literal["evidence/chatgpt-work-prelive-c7-v1"]
    covered_head: str = Field(pattern=_COMMIT_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    diff: C7DiffCommitment
    tree: C7TreeCommitment
    covered_changed_file_count: int = Field(ge=1)
    validation_status: Literal["C7_WORK_PRELIVE_ADMISSION_SEALED"]
    official_docs_review_performed: Literal[True]
    browser_actions_performed: Literal[False]
    credentials_created: Literal[False]
    tunnel_started: Literal[False]
    plugin_created: Literal[False]
    provider_live_actions_performed: Literal[False]
    effective_tool_count: Literal[0]


class C7SealVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["verified"]
    base_commit: str = Field(pattern=_COMMIT_PATTERN)
    covered_head: str = Field(pattern=_COMMIT_PATTERN)
    tag_target: str = Field(pattern=_COMMIT_PATTERN)
    current_head: str = Field(pattern=_COMMIT_PATTERN)
    current_tree_required: bool
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    diff_sha256: str = Field(pattern=_SHA256_PATTERN)
    tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    covered_changed_file_count: int = Field(ge=1)
    tree_file_count: int = Field(ge=1)
    tree_blob_bytes: int = Field(ge=1)
    provider_live_actions_performed: Literal[False]
    effective_tool_count: Literal[0]


def _assert_safe_root(root: Path) -> Path:
    resolved = root.resolve(strict=True)
    if not (resolved / ".git").exists():
        raise ValueError("C7 seal root must be a Git worktree")
    current = Path(resolved.anchor)
    for part in resolved.parts[1:]:
        current /= part
        info = current.lstat()
        attributes = getattr(info, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if current.is_symlink() or (reparse and attributes & reparse):
            raise ValueError("C7 seal root cannot traverse a reparse point")
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
        capture_output=True,
    )
    return completed.stdout


def _git_text(root: Path, *args: str) -> str:
    return _git(root, *args).decode("utf-8", errors="strict").strip()


def _resolve_commit(root: Path, value: str) -> str:
    resolved = _git_text(root, "rev-parse", "--verify", f"{value}^{{commit}}")
    if re.fullmatch(_COMMIT_PATTERN, resolved) is None:
        raise ValueError(f"C7 Git reference {value!r} did not resolve to a commit")
    return resolved


def _assert_ancestor(root: Path, ancestor: str, descendant: str) -> None:
    completed = subprocess.run(
        ("git", "-C", os.fspath(root), "merge-base", "--is-ancestor", ancestor, descendant),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise ValueError(f"C7 ancestry mismatch: {ancestor} is not an ancestor of {descendant}")


def _load_json_at(root: Path, commit: str, path: str, model: type[BaseModel]) -> BaseModel:
    raw = _git(root, "show", f"{commit}:{path}")
    return model.model_validate_json(raw)


def _changed_paths(root: Path, base: str, head: str) -> tuple[str, ...]:
    raw = _git(root, "diff", "--name-only", "-z", base, head, "--")
    paths = tuple(item.decode("utf-8", errors="strict") for item in raw.split(b"\0") if item)
    for path in paths:
        _validate_repo_path(path)
    return tuple(sorted(paths))


def compute_c7_diff_commitment(root: Path, base: str, head: str) -> C7DiffCommitment:
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
        f":(exclude){C7_SEAL_PATH}",
    )
    if not raw:
        raise ValueError("C7 covered diff cannot be empty")
    return C7DiffCommitment(
        algorithm="sha256-git-binary-diff-v1",
        excluded_paths=(C7_SEAL_PATH,),
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
            raise ValueError("C7 tree contains a non-blob recursive entry")
        if path != C7_SEAL_PATH:
            entries.append((path, mode, object_id))
    return tuple(sorted(entries))


def compute_c7_tree_commitment(root: Path, commit: str) -> C7TreeCommitment:
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
    return C7TreeCommitment(
        algorithm="sha256-framed-tree-v1",
        excluded_paths=(C7_SEAL_PATH,),
        sha256=digest.hexdigest(),
        file_count=len(entries),
        blob_bytes=total_bytes,
    )


def create_c7_seal(root: Path, covered_head: str = "HEAD") -> C7ChangeSeal:
    root = _assert_safe_root(root)
    covered = _resolve_commit(root, covered_head)
    base = _resolve_commit(root, C7_BASE_COMMIT)
    _assert_ancestor(root, base, covered)
    manifest = _load_json_at(
        root,
        covered,
        C7_MANIFEST_PATH,
        C7ChangeManifest,
    )
    assert isinstance(manifest, C7ChangeManifest)
    changed = _changed_paths(root, base, covered)
    if changed != manifest.changed_files:
        raise ValueError("C7 manifest does not exactly match the covered Git diff")
    manifest_sha = canonical_sha256(manifest.model_dump(mode="json"))
    return C7ChangeSeal(
        version="1",
        repository="Cheurteenyt/systeme-local",
        branch=C7_BRANCH,
        base_commit=C7_BASE_COMMIT,
        evidence_tag=C7_EVIDENCE_TAG,
        covered_head=covered,
        manifest_sha256=manifest_sha,
        diff=compute_c7_diff_commitment(root, base, covered),
        tree=compute_c7_tree_commitment(root, covered),
        covered_changed_file_count=len(changed),
        validation_status="C7_WORK_PRELIVE_ADMISSION_SEALED",
        official_docs_review_performed=True,
        browser_actions_performed=False,
        credentials_created=False,
        tunnel_started=False,
        plugin_created=False,
        provider_live_actions_performed=False,
        effective_tool_count=0,
    )


def verify_c7_seal(
    root: Path,
    *,
    require_current_tree: bool = False,
    require_clean: bool = False,
) -> C7SealVerification:
    root = _assert_safe_root(root)
    if require_clean and _git_text(root, "status", "--porcelain"):
        raise ValueError("C7 final seal verification requires a clean worktree")
    tag_object = _git_text(root, "rev-parse", "--verify", C7_EVIDENCE_TAG)
    if _git_text(root, "cat-file", "-t", tag_object) != "tag":
        raise ValueError("C7 evidence tag must be annotated")
    tag_target = _resolve_commit(root, C7_EVIDENCE_TAG)
    seal_model = _load_json_at(root, tag_target, C7_SEAL_PATH, C7ChangeSeal)
    assert isinstance(seal_model, C7ChangeSeal)
    seal = seal_model
    parent = _resolve_commit(root, f"{tag_target}^")
    if parent != seal.covered_head:
        raise ValueError("C7 evidence tag parent is not the sealed covered head")
    tag_changes = _changed_paths(root, seal.covered_head, tag_target)
    if tag_changes != (C7_SEAL_PATH,):
        raise ValueError("C7 evidence tag commit must add only the final seal")
    manifest_model = _load_json_at(
        root,
        seal.covered_head,
        C7_MANIFEST_PATH,
        C7ChangeManifest,
    )
    assert isinstance(manifest_model, C7ChangeManifest)
    manifest = manifest_model
    manifest_sha = canonical_sha256(manifest.model_dump(mode="json"))
    if manifest_sha != seal.manifest_sha256:
        raise ValueError("C7 sealed manifest digest mismatch")
    changed = _changed_paths(root, C7_BASE_COMMIT, seal.covered_head)
    if changed != manifest.changed_files or len(changed) != seal.covered_changed_file_count:
        raise ValueError("C7 sealed changed-file set mismatch")
    diff = compute_c7_diff_commitment(root, C7_BASE_COMMIT, seal.covered_head)
    tree = compute_c7_tree_commitment(root, seal.covered_head)
    tagged_tree = compute_c7_tree_commitment(root, tag_target)
    if diff != seal.diff or not (tree == tagged_tree == seal.tree):
        raise ValueError("C7 sealed diff or tree commitment mismatch")
    current = _resolve_commit(root, "HEAD")
    _assert_ancestor(root, C7_BASE_COMMIT, current)
    if require_current_tree:
        current_tree = compute_c7_tree_commitment(root, current)
        if current_tree != seal.tree:
            raise ValueError("C7 current tree differs from the sealed tree")
    return C7SealVerification(
        status="verified",
        base_commit=C7_BASE_COMMIT,
        covered_head=seal.covered_head,
        tag_target=tag_target,
        current_head=current,
        current_tree_required=require_current_tree,
        manifest_sha256=seal.manifest_sha256,
        diff_sha256=seal.diff.sha256,
        tree_sha256=seal.tree.sha256,
        covered_changed_file_count=seal.covered_changed_file_count,
        tree_file_count=seal.tree.file_count,
        tree_blob_bytes=seal.tree.blob_bytes,
        provider_live_actions_performed=False,
        effective_tool_count=0,
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
    parser = argparse.ArgumentParser(description="C7 reproducible change seal")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--covered-head", default="HEAD")
    create.add_argument("--output", default=C7_SEAL_PATH)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--require-current-tree", action="store_true")
    verify.add_argument("--require-clean", action="store_true")
    args = parser.parse_args(argv)
    root = _repository_root()
    try:
        if args.command == "create":
            seal = create_c7_seal(root, args.covered_head)
            output = root / args.output
            if output.resolve().parent != (root / "governance").resolve():
                raise ValueError("C7 seal output must remain in governance")
            output.write_text(rendered_json(seal), encoding="utf-8", newline="\n")
            print(rendered_json(seal), end="")
            return 0
        result = verify_c7_seal(
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
                    "provider_live_actions_performed": False,
                    "effective_tool_count": 0,
                },
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
