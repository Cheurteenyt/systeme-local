from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


C6_BASE_COMMIT = "418112758d8675326835d9947ccce3a1b12f6f25"
C6_BRANCH = "codex/chatgpt-official-revalidation-c6"
C6_EVIDENCE_TAG = "evidence/chatgpt-official-revalidation-c6-v1"
C6_MANIFEST_PATH = "governance/c6-change-manifest.json"
C6_SEAL_PATH: Final[Literal["governance/c6-change-seal.json"]] = "governance/c6-change-seal.json"

_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
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
        raise ValueError("C6 seal path is not canonical")
    return value


class C6ChangeManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    repository: Literal["Cheurteenyt/systeme-local"]
    default_branch: Literal["main"]
    branch: Literal["codex/chatgpt-official-revalidation-c6"]
    base_commit: Literal["418112758d8675326835d9947ccce3a1b12f6f25"]
    merge_method: Literal["squash"]
    evidence_tag: Literal["evidence/chatgpt-official-revalidation-c6-v1"]
    profile_id: Literal["chatgpt_chat_c3_20260727"]
    official_source_count: Literal[4]
    reviewed_outcome: Literal["BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"]
    changed_files: tuple[str, ...]
    public_docs_acquisition_performed: Literal[True]
    raw_content_persisted: Literal[False]
    automatic_promotion_performed: Literal[False]
    provider_live_actions_performed: Literal[False]

    @model_validator(mode="after")
    def validate_manifest(self) -> C6ChangeManifest:
        for path in self.changed_files:
            _validate_repo_path(path)
        if self.changed_files != tuple(sorted(set(self.changed_files))):
            raise ValueError("C6 manifest paths must be sorted and unique")
        if C6_MANIFEST_PATH not in self.changed_files:
            raise ValueError("C6 manifest must cover itself")
        if C6_SEAL_PATH in self.changed_files:
            raise ValueError("C6 covered head cannot contain its self-referential seal")
        return self


class C6DiffCommitment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: Literal["sha256-git-binary-diff-v1"]
    excluded_paths: tuple[Literal["governance/c6-change-seal.json"], ...]
    sha256: str = Field(pattern=_SHA256_PATTERN)
    bytes: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_exclusion(self) -> C6DiffCommitment:
        if self.excluded_paths != (C6_SEAL_PATH,):
            raise ValueError("C6 diff excludes only its self-referential seal")
        return self


class C6TreeCommitment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: Literal["sha256-framed-tree-v1"]
    excluded_paths: tuple[Literal["governance/c6-change-seal.json"], ...]
    sha256: str = Field(pattern=_SHA256_PATTERN)
    file_count: int = Field(ge=1)
    blob_bytes: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_exclusion(self) -> C6TreeCommitment:
        if self.excluded_paths != (C6_SEAL_PATH,):
            raise ValueError("C6 tree excludes only its self-referential seal")
        return self


class C6ChangeSeal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    repository: Literal["Cheurteenyt/systeme-local"]
    branch: Literal["codex/chatgpt-official-revalidation-c6"]
    base_commit: Literal["418112758d8675326835d9947ccce3a1b12f6f25"]
    evidence_tag: Literal["evidence/chatgpt-official-revalidation-c6-v1"]
    covered_head: str = Field(pattern=_COMMIT_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    diff: C6DiffCommitment
    tree: C6TreeCommitment
    covered_changed_file_count: int = Field(ge=1)
    validation_status: Literal["C6_OFFICIAL_REVALIDATION_SEALED"]
    public_docs_acquisition_performed: Literal[True]
    raw_content_persisted: Literal[False]
    automatic_promotion_performed: Literal[False]
    provider_live_actions_performed: Literal[False]


class C6SealVerification(BaseModel):
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


def _assert_safe_root(root: Path) -> Path:
    resolved = root.resolve(strict=True)
    if not (resolved / ".git").exists():
        raise ValueError("C6 seal root must be a Git worktree")
    current = Path(resolved.anchor)
    for part in resolved.parts[1:]:
        current /= part
        info = current.lstat()
        attributes = getattr(info, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if current.is_symlink() or (reparse and attributes & reparse):
            raise ValueError("C6 seal root cannot traverse a reparse point")
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
        raise ValueError(f"C6 Git reference {value!r} did not resolve to a commit")
    return resolved


def _assert_ancestor(root: Path, ancestor: str, descendant: str) -> None:
    completed = subprocess.run(
        (
            "git",
            "-C",
            os.fspath(root),
            "merge-base",
            "--is-ancestor",
            ancestor,
            descendant,
        ),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise ValueError(f"C6 ancestry mismatch: {ancestor} is not an ancestor of {descendant}")


def _load_worktree_model(path: Path, model: type[BaseModel]) -> BaseModel:
    return model.model_validate_json(path.read_text(encoding="utf-8"))


def _load_commit_model(
    root: Path,
    commit: str,
    path: str,
    model: type[BaseModel],
) -> BaseModel:
    raw = _git(root, "show", f"{commit}:{path}")
    return model.model_validate_json(raw.decode("utf-8", errors="strict"))


def _changed_paths(root: Path, base: str, head: str) -> tuple[str, ...]:
    raw = _git(
        root,
        "diff",
        "--name-only",
        "-z",
        "--diff-filter=ACDMRTUXB",
        base,
        head,
        "--",
        ".",
        f":(exclude){C6_SEAL_PATH}",
    )
    paths = tuple(item.decode("utf-8", errors="strict") for item in raw.split(b"\0") if item)
    for path in paths:
        _validate_repo_path(path)
    if paths != tuple(sorted(set(paths))):
        raise ValueError("C6 changed paths are not sorted and unique")
    return paths


def _parse_tree_entries(raw: bytes) -> tuple[tuple[bytes, bytes, str], ...]:
    entries: list[tuple[bytes, bytes, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, separator, path_bytes = record.partition(b"\t")
        parts = metadata.split(b" ")
        if not separator or len(parts) != 3 or parts[1] != b"blob":
            raise ValueError("C6 received malformed Git tree output")
        path = path_bytes.decode("utf-8", errors="strict")
        _validate_repo_path(path)
        entries.append((parts[0], parts[2], path))
    paths = tuple(path for _, _, path in entries)
    if paths != tuple(sorted(paths)):
        raise ValueError("C6 Git tree is not canonically sorted")
    return tuple(entries)


def _read_blobs(root: Path, object_ids: tuple[bytes, ...]) -> dict[bytes, bytes]:
    unique_ids = tuple(dict.fromkeys(object_ids))
    output = _git(
        root,
        "cat-file",
        "--batch",
        input_bytes=b"\n".join(unique_ids) + b"\n",
    )
    offset = 0
    blobs: dict[bytes, bytes] = {}
    for expected_id in unique_ids:
        header_end = output.find(b"\n", offset)
        if header_end < 0:
            raise ValueError("C6 received truncated Git blob output")
        header = output[offset:header_end].split(b" ")
        if len(header) != 3 or header[0] != expected_id or header[1] != b"blob":
            raise ValueError("C6 received unexpected Git blob metadata")
        try:
            size = int(header[2])
        except ValueError as error:
            raise ValueError("C6 received an invalid Git blob length") from error
        blob_start = header_end + 1
        blob_end = blob_start + size
        if blob_end >= len(output) or output[blob_end : blob_end + 1] != b"\n":
            raise ValueError("C6 received malformed Git blob framing")
        blobs[expected_id] = output[blob_start:blob_end]
        offset = blob_end + 1
    if offset != len(output):
        raise ValueError("C6 received trailing Git blob output")
    return blobs


def compute_c6_tree_commitment(root: Path, commit: str) -> C6TreeCommitment:
    resolved_root = _assert_safe_root(root)
    resolved_commit = _resolve_commit(resolved_root, commit)
    entries = _parse_tree_entries(
        _git(resolved_root, "ls-tree", "-rz", "--full-tree", resolved_commit)
    )
    blobs = _read_blobs(
        resolved_root,
        tuple(object_id for _, object_id, path in entries if path != C6_SEAL_PATH),
    )
    digest = sha256()
    file_count = 0
    blob_bytes = 0
    for mode, object_id, path in entries:
        if path == C6_SEAL_PATH:
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
    return C6TreeCommitment(
        algorithm="sha256-framed-tree-v1",
        excluded_paths=(C6_SEAL_PATH,),
        sha256=digest.hexdigest(),
        file_count=file_count,
        blob_bytes=blob_bytes,
    )


def compute_c6_diff_commitment(
    root: Path,
    base: str,
    head: str,
) -> C6DiffCommitment:
    resolved_root = _assert_safe_root(root)
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
        f":(exclude){C6_SEAL_PATH}",
    )
    return C6DiffCommitment(
        algorithm="sha256-git-binary-diff-v1",
        excluded_paths=(C6_SEAL_PATH,),
        sha256=sha256(diff).hexdigest(),
        bytes=len(diff),
    )


def create_c6_seal(
    root: Path,
    *,
    require_clean: bool = True,
) -> C6ChangeSeal:
    resolved_root = _assert_safe_root(root)
    if require_clean and _git_text(resolved_root, "status", "--porcelain=v1"):
        raise ValueError("C6 seal creation requires a clean worktree")
    covered_head = _resolve_commit(resolved_root, "HEAD")
    _assert_ancestor(resolved_root, C6_BASE_COMMIT, covered_head)
    if _git_text(resolved_root, "branch", "--show-current") != C6_BRANCH:
        raise ValueError("C6 seal creation requires the exact reviewed branch")
    manifest = C6ChangeManifest.model_validate(
        _load_worktree_model(
            resolved_root / C6_MANIFEST_PATH,
            C6ChangeManifest,
        )
    )
    changed_paths = _changed_paths(resolved_root, C6_BASE_COMMIT, covered_head)
    if changed_paths != manifest.changed_files:
        raise ValueError("C6 manifest does not match the covered Git diff")
    manifest_digest = canonical_sha256(manifest.model_dump(mode="json"))
    return C6ChangeSeal(
        version="1",
        repository=manifest.repository,
        branch=manifest.branch,
        base_commit=manifest.base_commit,
        evidence_tag=manifest.evidence_tag,
        covered_head=covered_head,
        manifest_sha256=manifest_digest,
        diff=compute_c6_diff_commitment(
            resolved_root,
            C6_BASE_COMMIT,
            covered_head,
        ),
        tree=compute_c6_tree_commitment(resolved_root, covered_head),
        covered_changed_file_count=len(changed_paths),
        validation_status="C6_OFFICIAL_REVALIDATION_SEALED",
        public_docs_acquisition_performed=True,
        raw_content_persisted=False,
        automatic_promotion_performed=False,
        provider_live_actions_performed=False,
    )


def verify_c6_seal(
    root: Path,
    *,
    require_current_tree: bool = False,
    require_clean: bool = False,
) -> C6SealVerification:
    resolved_root = _assert_safe_root(root)
    tag_object = _git_text(resolved_root, "rev-parse", "--verify", C6_EVIDENCE_TAG)
    if _git_text(resolved_root, "cat-file", "-t", tag_object) != "tag":
        raise ValueError("C6 evidence tag must be annotated")
    tag_target = _resolve_commit(resolved_root, C6_EVIDENCE_TAG)
    manifest = C6ChangeManifest.model_validate(
        _load_commit_model(
            resolved_root,
            tag_target,
            C6_MANIFEST_PATH,
            C6ChangeManifest,
        )
    )
    seal = C6ChangeSeal.model_validate(
        _load_commit_model(
            resolved_root,
            tag_target,
            C6_SEAL_PATH,
            C6ChangeSeal,
        )
    )
    manifest_digest = canonical_sha256(manifest.model_dump(mode="json"))
    if seal.manifest_sha256 != manifest_digest:
        raise ValueError("C6 seal manifest commitment mismatch")
    _assert_ancestor(resolved_root, C6_BASE_COMMIT, seal.covered_head)
    tag_parent = _resolve_commit(resolved_root, f"{tag_target}^")
    if tag_parent != seal.covered_head:
        raise ValueError("C6 tag must point to the one-file seal commit")
    added_paths = _git_text(
        resolved_root,
        "diff",
        "--name-only",
        seal.covered_head,
        tag_target,
        "--",
        ".",
    ).splitlines()
    if added_paths != [C6_SEAL_PATH]:
        raise ValueError("C6 final tag commit must add only its seal")
    changed_paths = _changed_paths(
        resolved_root,
        C6_BASE_COMMIT,
        seal.covered_head,
    )
    if changed_paths != manifest.changed_files:
        raise ValueError("C6 sealed manifest does not match its Git diff")
    if seal.covered_changed_file_count != len(changed_paths):
        raise ValueError("C6 sealed changed-file count mismatch")
    observed_diff = compute_c6_diff_commitment(
        resolved_root,
        C6_BASE_COMMIT,
        seal.covered_head,
    )
    covered_tree = compute_c6_tree_commitment(resolved_root, seal.covered_head)
    tagged_tree = compute_c6_tree_commitment(resolved_root, tag_target)
    if observed_diff != seal.diff:
        raise ValueError("C6 sealed binary diff commitment mismatch")
    if not (covered_tree == tagged_tree == seal.tree):
        raise ValueError("C6 sealed tree commitment mismatch")
    current_head = _resolve_commit(resolved_root, "HEAD")
    _assert_ancestor(resolved_root, C6_BASE_COMMIT, current_head)
    if require_current_tree:
        current_tree = compute_c6_tree_commitment(resolved_root, current_head)
        if current_tree != seal.tree:
            raise ValueError("C6 current tree differs from the sealed branch tree")
    if require_clean and _git_text(resolved_root, "status", "--porcelain=v1"):
        raise ValueError("C6 seal verification requires a clean worktree")
    return C6SealVerification(
        status="verified",
        base_commit=C6_BASE_COMMIT,
        covered_head=seal.covered_head,
        tag_target=tag_target,
        current_head=current_head,
        current_tree_required=require_current_tree,
        manifest_sha256=manifest_digest,
        diff_sha256=observed_diff.sha256,
        tree_sha256=covered_tree.sha256,
        covered_changed_file_count=len(changed_paths),
        tree_file_count=covered_tree.file_count,
        tree_blob_bytes=covered_tree.blob_bytes,
        provider_live_actions_performed=False,
    )


def _write_seal(root: Path, seal: C6ChangeSeal, output: Path) -> None:
    expected = (root / C6_SEAL_PATH).resolve()
    resolved_output = output.resolve()
    if resolved_output != expected:
        raise ValueError("C6 seal output must use the canonical governance path")
    payload = (
        json.dumps(
            seal.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    handle, temporary_name = tempfile.mkstemp(
        prefix=".c6-change-seal.",
        suffix=".tmp",
        dir=resolved_output.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, resolved_output)
    finally:
        temporary.unlink(missing_ok=True)


def _json_output(value: BaseModel) -> str:
    return json.dumps(
        value.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create or verify the C6 repository seal.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument(
        "--output",
        type=Path,
        default=Path(C6_SEAL_PATH),
    )
    verify = subparsers.add_parser("verify")
    verify.add_argument("--require-current-tree", action="store_true")
    verify.add_argument("--require-clean", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    root = args.root.resolve()
    try:
        if args.command == "create":
            seal = create_c6_seal(root)
            output = args.output if args.output.is_absolute() else root / args.output
            _write_seal(root, seal, output)
            print(_json_output(seal))
            return 0
        verification = verify_c6_seal(
            root,
            require_current_tree=args.require_current_tree,
            require_clean=args.require_clean,
        )
        print(_json_output(verification))
        return 0
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        print(
            json.dumps(
                {
                    "error": str(error),
                    "provider_live_actions_performed": False,
                    "status": "error",
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
