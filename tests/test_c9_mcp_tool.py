from pathlib import Path

from systeme_local_gateway.c9_mcp_tool import (
    C9_ATTACHMENT_HANDOFF_TOOL_NAME,
    c9_attachment_handoff_annotations,
    c9_attachment_handoff_input_schema,
    c9_attachment_handoff_output_schema,
    c9_attachment_handoff_tool,
)
from systeme_local_gateway.mcp_tools import McpToolRegistry
from systeme_local_gateway.policy import PolicyEngine


def _policy(tmp_path: Path, decision: str = "allow") -> PolicyEngine:
    path = tmp_path / "policy.c9.yaml"
    path.write_text(
        "\n".join(
            (
                "version: 1",
                "default: deny",
                "capabilities:",
                f"  {C9_ATTACHMENT_HANDOFF_TOOL_NAME}:",
                f"    decision: {decision}",
                "",
            )
        ),
        encoding="utf-8",
    )
    return PolicyEngine(path)


def test_c9_tool_has_exact_work_only_input_and_truthful_annotations() -> None:
    assert c9_attachment_handoff_input_schema() == {
        "type": "object",
        "properties": {
            "handoff_id": {
                "type": "string",
                "description": (
                    "Opaque one-use identifier for the exact locally approved "
                    "synthetic attachment package."
                ),
                "pattern": r"^c9_handoff_[0-9a-f]{32}$",
            },
            "surface": {
                "type": "string",
                "description": (
                    "The only official ChatGPT surface that can consume this "
                    "one-use MCP rich-content lease."
                ),
                "enum": ["work"],
            },
        },
        "required": ["handoff_id", "surface"],
        "additionalProperties": False,
    }
    assert c9_attachment_handoff_annotations() == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    }
    output = c9_attachment_handoff_output_schema()
    assert output["type"] == "object"
    assert output["additionalProperties"] is False
    assert output["properties"]["surface"] == {
        "type": "string",
        "const": "work",
    }
    assert output["properties"]["surface_task_id"]["pattern"] == (r"^c9_work_[0-9a-f]{32}$")
    assert output["properties"]["attachment_count"] == {
        "type": "integer",
        "const": 2,
    }
    assert set(output["required"]) == set(output["properties"])


def test_c9_registry_exposes_exactly_one_policy_admitted_tool(tmp_path: Path) -> None:
    registry = McpToolRegistry(
        _policy(tmp_path),
        additional_tools=(c9_attachment_handoff_tool(),),
        effective_tool_names=frozenset({C9_ATTACHMENT_HANDOFF_TOOL_NAME}),
    )

    tools = registry.protocol_tools()

    assert len(tools) == 1
    assert tools[0]["name"] == C9_ATTACHMENT_HANDOFF_TOOL_NAME
    assert tools[0]["inputSchema"] == c9_attachment_handoff_input_schema()
    assert tools[0]["outputSchema"] == c9_attachment_handoff_output_schema()
    assert tools[0]["annotations"] == c9_attachment_handoff_annotations()


def test_c9_tool_is_not_exposed_when_policy_denies_it(tmp_path: Path) -> None:
    registry = McpToolRegistry(
        _policy(tmp_path, decision="deny"),
        additional_tools=(c9_attachment_handoff_tool(),),
    )

    assert registry.list_tools() == ()
