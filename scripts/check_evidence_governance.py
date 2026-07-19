from __future__ import annotations

import argparse
import ast
import sys
import tomllib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Profile:
    profile_id: str
    source: Path
    document: Path
    reviewed_assignment: str
    revalidate_assignment: str
    reviewed_at: datetime
    revalidate_after: datetime
    warning_days: int


def _parse_utc(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"timestamp is not timezone-aware: {value}")
    return parsed.astimezone(timezone.utc)


def _datetime_call_from_ast(node: ast.Call) -> datetime:
    if not isinstance(node.func, ast.Name) or node.func.id != "datetime":
        raise ValueError("direct evidence timestamps must call datetime(...)")

    positional: list[int] = []
    for argument in node.args:
        if (
            not isinstance(argument, ast.Constant)
            or isinstance(argument.value, bool)
            or not isinstance(argument.value, int)
        ):
            raise ValueError("datetime positional arguments must be integer literals")
        positional.append(argument.value)

    if len(positional) < 3 or len(positional) > 6:
        raise ValueError("datetime assignment must contain 3 to 6 integer arguments")

    if len(node.keywords) != 1:
        raise ValueError("datetime assignment must define exactly tzinfo=timezone.utc")

    keyword = node.keywords[0]
    value = keyword.value
    tzinfo_is_utc = (
        keyword.arg == "tzinfo"
        and isinstance(value, ast.Attribute)
        and value.attr == "utc"
        and isinstance(value.value, ast.Name)
        and value.value.id == "timezone"
    )
    if not tzinfo_is_utc:
        raise ValueError("evidence timestamp assignment must use tzinfo=timezone.utc")

    year = positional[0]
    month = positional[1]
    day = positional[2]
    hour = positional[3] if len(positional) > 3 else 0
    minute = positional[4] if len(positional) > 4 else 0
    second = positional[5] if len(positional) > 5 else 0
    return datetime(
        year,
        month,
        day,
        hour,
        minute,
        second,
        tzinfo=timezone.utc,
    )


def _timedelta_from_ast(node: ast.AST) -> timedelta:
    if (
        not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Name)
        or node.func.id != "timedelta"
    ):
        raise ValueError("derived evidence timestamps must add timedelta(days=...)")
    if node.args or len(node.keywords) != 1:
        raise ValueError("timedelta evidence offsets must define exactly one days keyword")

    keyword = node.keywords[0]
    value = keyword.value
    if (
        keyword.arg != "days"
        or not isinstance(value, ast.Constant)
        or isinstance(value.value, bool)
        or not isinstance(value.value, int)
    ):
        raise ValueError("timedelta evidence days must be an integer literal")

    days = value.value
    if days < 1 or days > 31:
        raise ValueError("timedelta evidence days must be between 1 and 31")
    return timedelta(days=days)


def _datetime_from_ast(
    node: ast.AST,
    *,
    known_values: dict[str, datetime],
) -> datetime:
    if isinstance(node, ast.Call):
        return _datetime_call_from_ast(node)

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if not isinstance(node.left, ast.Name):
            raise ValueError("derived evidence timestamps must reference a prior assignment")
        base = known_values.get(node.left.id)
        if base is None:
            raise ValueError(
                f"derived evidence timestamp references unknown assignment: {node.left.id}"
            )
        return base + _timedelta_from_ast(node.right)

    raise ValueError(
        "evidence timestamp assignment must use datetime(...) or "
        "a prior timestamp plus timedelta(days=...)"
    )


def _read_assignments(path: Path, names: set[str]) -> dict[str, datetime]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values: dict[str, datetime] = {}

    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in names:
            values[target.id] = _datetime_from_ast(
                node.value,
                known_values=values,
            )

    missing = names - values.keys()
    if missing:
        raise ValueError(f"{path}: missing evidence assignments: {sorted(missing)}")
    return values


def _load_profiles(root: Path) -> list[Profile]:
    manifest_path = root / "governance" / "evidence-profiles.toml"
    data: dict[str, Any] = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    if data.get("version") != 1:
        raise ValueError("unsupported evidence-governance manifest version")

    raw_profiles = data.get("profiles")
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise ValueError("evidence-governance manifest must contain profiles")

    profiles: list[Profile] = []
    seen: set[str] = set()
    for raw in raw_profiles:
        if not isinstance(raw, dict):
            raise ValueError("profile entries must be TOML tables")
        profile_id = str(raw["id"])
        if profile_id in seen:
            raise ValueError(f"duplicate profile id: {profile_id}")
        seen.add(profile_id)

        source = root / str(raw["source"])
        document = root / str(raw["document"])
        if not source.is_file() or not document.is_file():
            raise ValueError(f"profile paths do not exist: {profile_id}")

        profile = Profile(
            profile_id=profile_id,
            source=source,
            document=document,
            reviewed_assignment=str(raw["reviewed_assignment"]),
            revalidate_assignment=str(raw["revalidate_assignment"]),
            reviewed_at=_parse_utc(str(raw["reviewed_at"])),
            revalidate_after=_parse_utc(str(raw["revalidate_after"])),
            warning_days=int(raw["warning_days"]),
        )
        if profile.warning_days < 0 or profile.warning_days > 31:
            raise ValueError(f"invalid warning_days for {profile_id}")
        if profile.revalidate_after <= profile.reviewed_at:
            raise ValueError(f"invalid evidence window for {profile_id}")
        profiles.append(profile)

    return sorted(profiles, key=lambda item: item.profile_id)


def _document_timestamp(timestamp: datetime) -> str:
    return timestamp.isoformat().replace("+00:00", "Z")


def check_profiles(root: Path, *, as_of: datetime, fail_within_days: int) -> list[str]:
    errors: list[str] = []
    for profile in _load_profiles(root):
        assignments = _read_assignments(
            profile.source,
            {profile.reviewed_assignment, profile.revalidate_assignment},
        )
        if assignments[profile.reviewed_assignment] != profile.reviewed_at:
            errors.append(f"{profile.profile_id}: source reviewed_at does not match manifest")
        if assignments[profile.revalidate_assignment] != profile.revalidate_after:
            errors.append(f"{profile.profile_id}: source revalidate_after does not match manifest")

        document = profile.document.read_text(encoding="utf-8")
        reviewed_date = profile.reviewed_at.isoformat().replace("+00:00", "Z")
        revalidate_date = profile.revalidate_after.isoformat().replace("+00:00", "Z")
        if reviewed_date not in document and profile.reviewed_at.date().isoformat() not in document:
            errors.append(f"{profile.profile_id}: document reviewed timestamp is missing")
        if (
            revalidate_date not in document
            and profile.revalidate_after.date().isoformat() not in document
        ):
            errors.append(f"{profile.profile_id}: document revalidation timestamp is missing")

        if as_of > profile.revalidate_after:
            errors.append(
                f"{profile.profile_id}: evidence expired at "
                f"{_document_timestamp(profile.revalidate_after)}"
            )
            continue

        effective_warning = max(profile.warning_days, fail_within_days)
        threshold = profile.revalidate_after - timedelta(days=effective_warning)
        if effective_warning > 0 and as_of >= threshold:
            errors.append(
                f"{profile.profile_id}: evidence revalidation due by "
                f"{_document_timestamp(profile.revalidate_after)}"
            )

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--as-of")
    parser.add_argument("--fail-within-days", type=int, default=0)
    args = parser.parse_args(argv)

    if args.fail_within_days < 0 or args.fail_within_days > 31:
        parser.error("--fail-within-days must be between 0 and 31")

    as_of = _parse_utc(args.as_of) if args.as_of else datetime.now(tz=timezone.utc)
    errors = check_profiles(
        args.root.resolve(),
        as_of=as_of,
        fail_within_days=args.fail_within_days,
    )
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(f"Evidence governance valid as of {_document_timestamp(as_of)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
