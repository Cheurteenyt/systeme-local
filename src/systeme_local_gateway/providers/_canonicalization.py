"""Private canonicalization and validation primitives for provider models."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import TypeVar

_StrEnumT = TypeVar("_StrEnumT", bound=StrEnum)


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _validate_sorted_unique_enum_tuple(
    values: tuple[_StrEnumT, ...],
    *,
    field_name: str,
) -> None:
    rendered: tuple[str, ...] = tuple(item.value for item in values)
    if len(rendered) != len(set(rendered)):
        raise ValueError(f"{field_name} must not contain duplicates")
    if rendered != tuple(sorted(rendered)):
        raise ValueError(f"{field_name} must be sorted")


def _validate_sorted_unique_string_tuple(
    values: tuple[str, ...],
    *,
    field_name: str,
) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must not contain duplicates")
    if values != tuple(sorted(values)):
        raise ValueError(f"{field_name} must be sorted")
