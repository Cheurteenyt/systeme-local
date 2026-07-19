from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

_LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
_REFERENCE_PATTERN = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)", re.MULTILINE)
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


def _iter_markdown_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.md")
        if not any(part in _IGNORED_PARTS for part in path.parts)
    )


def _normalize_target(raw_target: str) -> str:
    target = raw_target.strip()
    if target.startswith("<") and ">" in target:
        return target[1 : target.index(">")].strip()
    if " " in target:
        target = target.split(" ", maxsplit=1)[0]
    return target.strip()


def _is_external(target: str) -> bool:
    parsed = urlsplit(target)
    return parsed.scheme in {"http", "https", "mailto"} or target.startswith("//")


def _validate_target(root: Path, document: Path, target: str) -> str | None:
    if not target or target.startswith("#") or _is_external(target):
        return None

    path_part = unquote(target.split("#", maxsplit=1)[0])
    if not path_part:
        return None
    if "\\" in path_part:
        return "relative Markdown links must use forward slashes"

    candidate = (document.parent / path_part).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return "relative link escapes the repository root"

    if not candidate.exists():
        return f"target does not exist: {path_part}"
    return None


def check_links(root: Path) -> list[str]:
    errors: list[str] = []
    for document in _iter_markdown_files(root):
        text = document.read_text(encoding="utf-8")
        targets = [
            *(_normalize_target(match.group(1)) for match in _LINK_PATTERN.finditer(text)),
            *(_normalize_target(match.group(1)) for match in _REFERENCE_PATTERN.finditer(text)),
        ]
        for target in targets:
            reason = _validate_target(root, document, target)
            if reason is not None:
                relative = document.relative_to(root).as_posix()
                errors.append(f"{relative}: {target!r}: {reason}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    errors = check_links(root)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(f"Markdown links valid across {len(_iter_markdown_files(root))} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
