from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ERROR_LINE = re.compile(
    r"^(?P<path>.+?):(?P<line>[0-9]+): error: "
    r"(?P<message>.+?)  \[(?P<code>[a-z0-9-]+)\]$"
)
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


@dataclass(frozen=True)
class BaselineRule:
    path: str
    code: str
    message_contains: str
    count: int


@dataclass(frozen=True)
class Diagnostic:
    path: str
    code: str
    message: str


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
    candidate = Path(raw.strip())
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()

    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {raw}") from exc

    if any(part in _IGNORED_PARTS for part in relative.parts):
        raise ValueError(f"ignored path unexpectedly entered typing governance: {raw}")
    return relative.as_posix()


def _load_baseline(
    root: Path,
    path: Path,
) -> tuple[tuple[str, ...], tuple[BaselineRule, ...]]:
    if not path.is_file():
        raise FileNotFoundError(f"typing baseline not found: {path}")

    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise ValueError("unsupported typing baseline version")

    raw_scope = raw.get("scope")
    if not isinstance(raw_scope, list) or not raw_scope:
        raise ValueError("typing baseline must define a non-empty scope")

    scope_items: list[str] = []
    for item in raw_scope:
        if not isinstance(item, str):
            raise ValueError("typing scope entries must be strings")
        scope_items.append(item.replace("\\", "/"))

    if scope_items != sorted(scope_items):
        raise ValueError("typing scope entries must be sorted")
    if len(scope_items) != len(set(scope_items)):
        raise ValueError("typing scope contains duplicates")

    for relative in scope_items:
        if not (root / relative).exists():
            raise ValueError(f"typing scope path does not exist: {relative}")

    pyproject: Any = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    configured_scope = pyproject.get("tool", {}).get("mypy", {}).get("files")
    if configured_scope != scope_items:
        raise ValueError("pyproject Mypy scope differs from governance/mypy-baseline.json")

    raw_rules = raw.get("diagnostics")
    if not isinstance(raw_rules, list):
        raise ValueError("typing baseline diagnostics must be a list")

    rules: list[BaselineRule] = []
    for item in raw_rules:
        if not isinstance(item, dict):
            raise ValueError("typing baseline rules must be objects")

        raw_path = item.get("path")
        code = item.get("code")
        message_contains = item.get("message_contains")
        count = item.get("count")

        if not isinstance(raw_path, str):
            raise ValueError("typing baseline path must be a string")
        if not isinstance(code, str) or not code:
            raise ValueError("typing baseline code must be a non-empty string")
        if not isinstance(message_contains, str) or not message_contains:
            raise ValueError("typing baseline message_contains must be a non-empty string")
        if not isinstance(count, int) or count < 1:
            raise ValueError("typing baseline count must be a positive integer")

        normalized = _normalize_relative(root, raw_path)
        if not (root / normalized).is_file():
            raise ValueError(f"typing baseline diagnostic path does not exist: {normalized}")

        rules.append(
            BaselineRule(
                path=normalized,
                code=code,
                message_contains=message_contains,
                count=count,
            )
        )

    ordered_rules = sorted(
        rules,
        key=lambda rule: (
            rule.path,
            rule.code,
            rule.message_contains,
        ),
    )
    if rules != ordered_rules:
        raise ValueError("typing baseline diagnostics must be sorted")

    keys = [(rule.path, rule.code, rule.message_contains) for rule in rules]
    if len(keys) != len(set(keys)):
        raise ValueError("typing baseline contains duplicate rules")

    return tuple(scope_items), tuple(rules)


def _current_diagnostics(
    root: Path,
    *,
    scope: tuple[str, ...],
) -> list[Diagnostic]:
    mypy = shutil.which("mypy")
    if mypy is None:
        raise RuntimeError("mypy executable not found in PATH")

    completed = subprocess.run(
        [
            mypy,
            "--no-pretty",
            "--no-error-summary",
            "--show-error-codes",
            *scope,
        ],
        cwd=root,
        check=False,
        text=True,
        capture_output=True,
    )
    rendered = completed.stdout + completed.stderr

    diagnostics: list[Diagnostic] = []
    unparsed_errors: list[str] = []

    for raw_line in rendered.splitlines():
        line = raw_line.strip()
        if ": error:" not in line:
            continue

        match = _ERROR_LINE.fullmatch(line)
        if match is None:
            unparsed_errors.append(line)
            continue

        diagnostics.append(
            Diagnostic(
                path=_normalize_relative(root, match.group("path")),
                code=match.group("code"),
                message=match.group("message"),
            )
        )

    if unparsed_errors:
        raise RuntimeError("unparsed Mypy diagnostics:\n" + "\n".join(unparsed_errors))

    if completed.returncode == 0:
        if diagnostics:
            raise RuntimeError("Mypy returned success while reporting diagnostics")
    elif completed.returncode != 1:
        raise RuntimeError("Mypy failed outside the expected diagnostic path:\n" + rendered.strip())
    elif not diagnostics:
        raise RuntimeError(
            "Mypy returned diagnostic status without parseable errors:\n" + rendered.strip()
        )

    return diagnostics


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


def _ref_python_paths(
    root: Path,
    *,
    base: str,
    head: str,
) -> set[str]:
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


def check_typing_ratchet(
    root: Path,
    *,
    baseline_path: Path,
    changed_paths: set[str],
) -> list[str]:
    scope, rules = _load_baseline(root, baseline_path)
    diagnostics = _current_diagnostics(root, scope=scope)

    matches: Counter[int] = Counter()
    new_diagnostics: list[Diagnostic] = []

    for diagnostic in diagnostics:
        matching_indices = [
            index
            for index, rule in enumerate(rules)
            if diagnostic.path == rule.path
            and diagnostic.code == rule.code
            and rule.message_contains in diagnostic.message
        ]
        if len(matching_indices) != 1:
            new_diagnostics.append(diagnostic)
            continue
        matches[matching_indices[0]] += 1

    errors: list[str] = []

    for index, rule in enumerate(rules):
        observed = matches[index]
        if observed > rule.count:
            errors.append(
                f"Mypy debt increased for {rule.path} [{rule.code}] ({observed} > {rule.count})"
            )
        elif observed < rule.count:
            print(f"Typing debt reduced for {rule.path} [{rule.code}] ({observed} < {rule.count})")

    if new_diagnostics:
        rendered = ", ".join(
            f"{item.path} [{item.code}] {item.message}" for item in new_diagnostics
        )
        errors.append("new Mypy diagnostics outside the approved baseline: " + rendered)

    touched_debt = sorted(
        {diagnostic.path for diagnostic in diagnostics if diagnostic.path in changed_paths}
    )
    if touched_debt:
        errors.append(
            "changed Python files must retire their Mypy baseline diagnostics: "
            + ", ".join(touched_debt)
        )

    approved_count = sum(min(matches[index], rule.count) for index, rule in enumerate(rules))
    print(
        "Mypy ratchet: "
        f"{approved_count} approved legacy diagnostic(s), "
        f"{len(changed_paths)} changed Python file(s), "
        f"{len(new_diagnostics)} new diagnostic(s)."
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
        default=Path("governance/mypy-baseline.json"),
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

    errors = check_typing_ratchet(
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
