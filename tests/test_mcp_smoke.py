from __future__ import annotations

import json

import pytest

from systeme_local_gateway import mcp_smoke


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://127.0.0.1:8765/mcp",
        "http://[::1]:8765/mcp",
    ],
)
def test_validated_endpoint_accepts_literal_loopback(endpoint: str) -> None:
    assert mcp_smoke._validated_endpoint(endpoint) == endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:8765/mcp",
        "http://localhost:8765/mcp",
        "http://192.0.2.1:8765/mcp",
        "http://user@127.0.0.1:8765/mcp",
        "http://127.0.0.1/mcp",
        "http://127.0.0.1:8765/other",
        "http://127.0.0.1:8765/mcp?debug=1",
    ],
)
def test_validated_endpoint_rejects_nonlocal_or_ambiguous_urls(endpoint: str) -> None:
    with pytest.raises(mcp_smoke.McpSmokeInputError):
        mcp_smoke._validated_endpoint(endpoint)


def test_read_token_requires_runtime_secret() -> None:
    with pytest.raises(mcp_smoke.McpSmokeInputError, match="required"):
        mcp_smoke._read_token({})

    with pytest.raises(mcp_smoke.McpSmokeInputError, match="placeholder"):
        mcp_smoke._read_token(
            {
                "SLG_MCP_TOKEN": (
                    "replace-with-fourth-independent-at-least-32-random-characters"
                )
            }
        )


def test_parse_arguments_json_requires_finite_object() -> None:
    assert mcp_smoke._parse_arguments_json('{"path":"."}') == {"path": "."}

    with pytest.raises(mcp_smoke.McpSmokeInputError, match="JSON object"):
        mcp_smoke._parse_arguments_json("[]")

    with pytest.raises(mcp_smoke.McpSmokeInputError, match="non-finite"):
        mcp_smoke._parse_arguments_json('{"value":NaN}')


def test_main_lists_tools_without_exposing_token(monkeypatch, capsys) -> None:
    token = "operator-smoke-" + ("t" * 48)
    monkeypatch.setenv("SLG_MCP_TOKEN", token)

    async def fake_run_smoke(**kwargs):
        assert kwargs["token"] == token
        assert kwargs["call_tool"] is None
        return {
            "status": "ok",
            "endpoint": kwargs["endpoint"],
            "tools": ["workspace.list"],
            "echo": token,
        }

    monkeypatch.setattr(mcp_smoke, "run_smoke", fake_run_smoke)

    assert mcp_smoke.main([]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["tools"] == ["workspace.list"]
    assert captured.err == ""
    assert payload["echo"] == "[REDACTED]"
    assert token not in captured.out


def test_main_requires_call_tool_for_arguments(monkeypatch, capsys) -> None:
    monkeypatch.setenv("SLG_MCP_TOKEN", "operator-smoke-" + ("t" * 48))

    assert mcp_smoke.main(["--arguments-json", "{}"]) == 1
    captured = capsys.readouterr()
    assert "requires --call-tool" in captured.err


def test_main_redacts_unexpected_client_errors(monkeypatch, capsys) -> None:
    token = "operator-smoke-" + ("x" * 48)
    monkeypatch.setenv("SLG_MCP_TOKEN", token)

    async def failing_run_smoke(**_kwargs):
        raise RuntimeError(f"unexpected transport failure with {token}")

    monkeypatch.setattr(mcp_smoke, "run_smoke", failing_run_smoke)

    assert mcp_smoke.main([]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "status": "error",
        "error": "MCP smoke check failed",
    }
    assert token not in captured.err

def test_parser_description_preserves_utf8_project_name() -> None:
    description = mcp_smoke._build_parser().description
    assert description is not None
    assert "Système Local" in description
