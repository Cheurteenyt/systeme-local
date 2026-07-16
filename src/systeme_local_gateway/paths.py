from pathlib import Path


def resolve_inside(root: Path, requested: str) -> Path:
    root = root.resolve()
    target = (root / requested).resolve()
    if target != root and root not in target.parents:
        raise ValueError("path escapes workspace")
    return target
