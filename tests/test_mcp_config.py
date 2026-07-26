import importlib
import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

with patch.dict(
    os.environ,
    {
        "SLG_SHARED_SECRET": "s" * 48,
        "SLG_AUDIT_KEY": "a" * 48,
    },
):
    Settings = importlib.import_module("systeme_local_gateway.config").Settings


def _settings(**overrides):
    values = {
        "shared_secret": "s" * 48,
        "audit_key": "a" * 48,
        "_env_file": None,
    }
    values.update(overrides)
    return Settings(**values)


def test_mcp_is_disabled_by_default_without_a_token() -> None:
    settings = _settings()

    assert settings.mcp_enabled is False
    assert settings.mcp_token is None
    assert settings.c0_enabled is False
    assert settings.c0_server_build_commit is None


def test_enabled_mcp_requires_a_token() -> None:
    with pytest.raises(ValidationError, match="SLG_MCP_TOKEN"):
        _settings(mcp_enabled=True)


@pytest.mark.parametrize(
    ("variable", "overrides"),
    [
        (
            "SLG_SHARED_SECRET",
            {"mcp_token": "s" * 48},
        ),
        (
            "SLG_AUDIT_KEY",
            {"mcp_token": "a" * 48},
        ),
        (
            "SLG_AUDIT_ANCHOR_KEY",
            {
                "mcp_token": "n" * 48,
                "audit_anchor_log": "anchor.jsonl",
                "audit_anchor_key": "n" * 48,
            },
        ),
    ],
)
def test_mcp_token_must_be_independent(
    variable: str,
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match=variable):
        _settings(mcp_enabled=True, **overrides)


def test_placeholder_mcp_token_is_rejected() -> None:
    with pytest.raises(ValidationError, match="SLG_MCP_TOKEN"):
        _settings(
            mcp_enabled=True,
            mcp_token=("replace-with-fourth-independent-at-least-32-random-characters"),
        )


def test_c0_requires_mcp_and_full_build_commit() -> None:
    with pytest.raises(ValidationError, match="SLG_MCP_ENABLED"):
        _settings(c0_enabled=True, c0_server_build_commit="a" * 40)

    with pytest.raises(ValidationError, match="SLG_C0_SERVER_BUILD_COMMIT"):
        _settings(mcp_enabled=True, mcp_token="t" * 48, c0_enabled=True)


def test_c0_security_configuration_can_be_enabled_explicitly() -> None:
    settings = _settings(
        mcp_enabled=True,
        mcp_token="t" * 48,
        c0_enabled=True,
        c0_server_build_commit="a" * 40,
    )

    assert settings.c0_enabled is True
    assert settings.c0_server_build_commit == "a" * 40
