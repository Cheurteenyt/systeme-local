from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

_WOULD_REFORMAT = re.compile(r"^Would reformat:\s+(.+)$")
_IGNORED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".systeme-local",
    ".venv",
    "__pycache__",
    "target",
}


def _run_git(root: Path, arguments: list[str]) -> list[str]:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        rendered = (completed.stdout + completed.stderr).strip()
        raise RuntimeError(
            f"git {' '.join(arguments)} failed with {completed.returncode}: {rendered}"
        )
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def _normalize_relative(root: Path, raw: str) -> str:
    normalized = raw.strip().replace("\\", "/")
    candidate = (root / normalized).resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {raw}") from exc

    if any(part in _IGNORED_PARTS for part in relative.parts):
        raise ValueError(f"ignored path unexpectedly entered format governance: {raw}")
    if relative.suffix != ".py":
        raise ValueError(f"non-Python path in format governance: {raw}")
    return relative.as_posix()


def _load_baseline(root: Path, path: Path) -> set[str]:
    if not path.is_file():
        raise FileNotFoundError(f"format baseline not found: {path}")

    entries: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(_normalize_relative(root, line))

    if entries != sorted(entries):
        raise ValueError("format baseline entries must be sorted")
    if len(entries) != len(set(entries)):
        raise ValueError("format baseline contains duplicate entries")

    missing = sorted(relative for relative in entries if not (root / relative).is_file())
    if missing:
        raise ValueError("format baseline references missing files: " + ", ".join(missing))

    return set(entries)


def _current_unformatted(root: Path) -> set[str]:
    ruff = shutil.which("ruff")
    if ruff is None:
        raise RuntimeError("ruff executable not found in PATH")

    completed = subprocess.run(
        [ruff, "format", "--check", "."],
        cwd=root,
        check=False,
        text=True,
        capture_output=True,
    )
    rendered = completed.stdout + completed.stderr

    unformatted: set[str] = set()
    for raw_line in rendered.splitlines():
        match = _WOULD_REFORMAT.fullmatch(raw_line.strip())
        if match is None:
            continue
        unformatted.add(_normalize_relative(root, match.group(1)))

    if completed.returncode == 0:
        if unformatted:
            raise RuntimeError("ruff returned success while reporting unformatted files")
        return set()

    if completed.returncode != 1 or not unformatted:
        raise RuntimeError(
            "ruff format --check failed without a parseable debt set:\n" + rendered.strip()
        )

    return unformatted


def _worktree_python_paths(root: Path) -> set[str]:
    tracked = _run_git(
        root,
        ["diff", "--name-only", "--diff-filter=ACMR", "--", "*.py"],
    )
    untracked = _run_git(
        root,
        ["ls-files", "--others", "--exclude-standard", "--", "*.py"],
    )
    return {_normalize_relative(root, relative) for relative in [*tracked, *untracked]}


def _ref_python_paths(root: Path, *, base: str, head: str) -> set[str]:
    for ref in (base, head):
        _run_git(root, ["rev-parse", "--verify", f"{ref}^{{commit}}"])

    changed = _run_git(
        root,
        [
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            base,
            head,
            "--",
            "*.py",
        ],
    )
    return {_normalize_relative(root, relative) for relative in changed}


def check_format_ratchet(
    root: Path,
    *,
    baseline_path: Path,
    changed_paths: set[str],
) -> list[str]:
    baseline = _load_baseline(root, baseline_path)
    current = _current_unformatted(root)

    errors: list[str] = []

    new_debt = sorted(current - baseline)
    if new_debt:
        errors.append(
            "new Ruff formatting debt outside the approved baseline: " + ", ".join(new_debt)
        )

    touched_debt = sorted(current & changed_paths)
    if touched_debt:
        errors.append("changed Python files must be Ruff-formatted: " + ", ".join(touched_debt))

    retired = sorted(baseline - current)
    if retired:
        print(f"Formatting debt reduced for {len(retired)} baseline file(s): " + ", ".join(retired))

    print(
        "Ruff format ratchet: "
        f"{len(current)} current legacy file(s), "
        f"{len(changed_paths)} changed Python file(s), "
        f"{len(new_debt)} new debt file(s)."
    )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("governance/ruff-format-baseline.txt"),
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--worktree", action="store_true")
    mode.add_argument("--base")
    parser.add_argument("--head")

    args = parser.parse_args(argv)
    root = args.root.resolve()
    baseline_path = args.baseline if args.baseline.is_absolute() else root / args.baseline

    if args.worktree:
        if args.head is not None:
            parser.error("--head cannot be used with --worktree")
        changed_paths = _worktree_python_paths(root)
    else:
        if args.base is None or args.head is None:
            parser.error("--base and --head must be provided together")
        changed_paths = _ref_python_paths(
            root,
            base=args.base,
            head=args.head,
        )

    errors = check_format_ratchet(
        root,
        baseline_path=baseline_path,
        changed_paths=changed_paths,
    )
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
