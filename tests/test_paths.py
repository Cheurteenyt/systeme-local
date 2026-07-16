from pathlib import Path

import pytest

from systeme_local_gateway.paths import resolve_inside


def test_path_traversal_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="escapes workspace"):
        resolve_inside(tmp_path, "../outside.txt")


def test_child_path_is_allowed(tmp_path: Path) -> None:
    assert resolve_inside(tmp_path, "a/b.txt") == (tmp_path / "a/b.txt").resolve()
