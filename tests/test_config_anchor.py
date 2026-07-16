from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError


def _settings_class(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SLG_SHARED_SECRET", "s" * 48)
    monkeypatch.setenv("SLG_AUDIT_KEY", "a" * 48)
    monkeypatch.delenv("SLG_AUDIT_ANCHOR_LOG", raising=False)
    monkeypatch.delenv("SLG_AUDIT_ANCHOR_KEY", raising=False)
    sys.modules.pop("systeme_local_gateway.config", None)
    module = importlib.import_module("systeme_local_gateway.config")
    return module.Settings


def _base(tmp_path: Path) -> dict[str, object]:
    return {
        "shared_secret": "s" * 48,
        "audit_key": "a" * 48,
        "audit_log": tmp_path / "audit.jsonl",
    }


def test_anchor_configuration_is_optional(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    Settings = _settings_class(monkeypatch, tmp_path)
    settings = Settings(_env_file=None, **_base(tmp_path))
    assert settings.audit_anchor_log is None
    assert settings.audit_anchor_key is None


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (
            {"audit_anchor_log": Path("anchor.jsonl")},
            "must be configured together",
        ),
        (
            {"audit_anchor_key": "b" * 48},
            "must be configured together",
        ),
    ],
)
def test_anchor_configuration_requires_path_and_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    extra: dict[str, object],
    message: str,
) -> None:
    Settings = _settings_class(monkeypatch, tmp_path)
    with pytest.raises(ValidationError, match=message):
        Settings(_env_file=None, **_base(tmp_path), **extra)


@pytest.mark.parametrize("anchor_key", ["s" * 48, "a" * 48])
def test_anchor_key_must_be_independent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    anchor_key: str,
) -> None:
    Settings = _settings_class(monkeypatch, tmp_path)
    with pytest.raises(ValidationError, match="must be different"):
        Settings(
            _env_file=None,
            **_base(tmp_path),
            audit_anchor_log=tmp_path / "anchor.jsonl",
            audit_anchor_key=anchor_key,
        )


def test_anchor_placeholder_key_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    Settings = _settings_class(monkeypatch, tmp_path)
    with pytest.raises(ValidationError, match="must be replaced"):
        Settings(
            _env_file=None,
            **_base(tmp_path),
            audit_anchor_log=tmp_path / "anchor.jsonl",
            audit_anchor_key=(
                "replace-with-third-independent-at-least-32-random-characters"
            ),
        )


@pytest.mark.parametrize(
    ("audit_name", "anchor_name"),
    [
        ("audit.jsonl", "audit.jsonl"),
        ("audit.jsonl", "audit.jsonl.lock"),
        ("anchor.jsonl.lock", "anchor.jsonl"),
    ],
)
def test_anchor_and_audit_paths_must_not_overlap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    audit_name: str,
    anchor_name: str,
) -> None:
    Settings = _settings_class(monkeypatch, tmp_path)
    with pytest.raises(ValidationError, match="must not overlap"):
        Settings(
            _env_file=None,
            shared_secret="s" * 48,
            audit_key="a" * 48,
            audit_log=tmp_path / audit_name,
            audit_anchor_log=tmp_path / anchor_name,
            audit_anchor_key="b" * 48,
        )



def test_validation_errors_hide_secret_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    Settings = _settings_class(monkeypatch, tmp_path)
    secret = "hidden-anchor-secret-" + ("x" * 48)

    with pytest.raises(ValidationError) as captured:
        Settings(
            _env_file=None,
            shared_secret=secret,
            audit_key="a" * 48,
            audit_log=tmp_path / "audit.jsonl",
            audit_anchor_log=tmp_path / "anchor.jsonl",
            audit_anchor_key=secret,
        )

    rendered = str(captured.value)
    assert secret not in rendered
    assert "input_value" not in rendered


def test_symlinked_parent_alias_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    Settings = _settings_class(monkeypatch, tmp_path)
    real_directory = tmp_path / "real"
    alias_directory = tmp_path / "alias"
    real_directory.mkdir()

    try:
        alias_directory.symlink_to(
            real_directory,
            target_is_directory=True,
        )
    except OSError:
        pytest.skip("directory symbolic links are unavailable")

    with pytest.raises(ValidationError, match="must not overlap"):
        Settings(
            _env_file=None,
            shared_secret="s" * 48,
            audit_key="a" * 48,
            audit_log=real_directory / "audit.jsonl",
            audit_anchor_log=alias_directory / "audit.jsonl",
            audit_anchor_key="b" * 48,
        )


def test_valid_anchor_configuration_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    Settings = _settings_class(monkeypatch, tmp_path)
    settings = Settings(
        _env_file=None,
        **_base(tmp_path),
        audit_anchor_log=tmp_path / "external" / "anchor.jsonl",
        audit_anchor_key="b" * 48,
    )
    assert settings.audit_anchor_log == (
        tmp_path / "external" / "anchor.jsonl"
    )
    assert settings.audit_anchor_key == "b" * 48
