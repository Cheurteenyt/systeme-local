import pytest
from pydantic import ValidationError

from systeme_local_gateway.config import Settings


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
            mcp_token=(
                "replace-with-fourth-independent-at-least-32-random-characters"
            ),
        )
