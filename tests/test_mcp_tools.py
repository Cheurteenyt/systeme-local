import re
from pathlib import Path

import pytest

from systeme_local_gateway.c0_probe import C0_TOOL_NAME
from systeme_local_gateway.mcp_tools import McpToolDefinition, McpToolRegistry
from systeme_local_gateway.policy import PolicyEngine


def _write_policy(tmp_path: Path, body: str) -> PolicyEngine:
    policy = tmp_path / "policy.yaml"
    policy.write_text(body, encoding="utf-8")
    return PolicyEngine(policy)


def test_registry_is_policy_derived_and_sorted(tmp_path: Path) -> None:
    policy = _write_policy(
        tmp_path,
        """version: 1
default: deny
capabilities:
  workspace.write_text:
    decision: require_approval
  workspace.read_text:
    decision: allow
  sandbox.run_tests:
    decision: allow
    allowed_commands:
      - [python, -m, pytest, -q]
  workspace.list:
    decision: allow
  git.diff:
    decision: allow
    allowed_commands:
      - [git, status, --short]
""",
    )

    tools = McpToolRegistry(policy).list_tools()

    assert [tool.name for tool in tools] == [
        "git.diff",
        "sandbox.run_tests",
        "workspace.list",
        "workspace.read_text",
    ]


def test_registry_excludes_denied_approval_and_unknown_tools(tmp_path: Path) -> None:
    policy = _write_policy(
        tmp_path,
        """version: 1
default: deny
capabilities:
  workspace.list:
    decision: deny
  workspace.write_text:
    decision: require_approval
  custom.allowed:
    decision: allow
""",
    )

    assert McpToolRegistry(policy).list_tools() == ()


def test_command_schema_is_exact_deduplicated_and_deterministic(tmp_path: Path) -> None:
    policy = _write_policy(
        tmp_path,
        """version: 1
default: deny
capabilities:
  sandbox.run_tests:
    decision: allow
    allowed_commands:
      - [python, -m, unittest, discover]
      - [python, -m, pytest, -q]
      - [python, -m, pytest, -q]
""",
    )

    tool = McpToolRegistry(policy).get_tool("sandbox.run_tests")

    assert tool is not None
    assert tool.input_schema == {
        "type": "object",
        "properties": {
            "command": {
                "type": "array",
                "description": "Exact argv array selected from the local policy allowlist.",
                "items": {"type": "string", "minLength": 1},
                "minItems": 1,
                "maxItems": 32,
                "enum": [
                    ["python", "-m", "pytest", "-q"],
                    ["python", "-m", "unittest", "discover"],
                ],
            }
        },
        "required": ["command"],
        "additionalProperties": False,
    }


def test_command_tool_without_allowlist_is_not_exposed(tmp_path: Path) -> None:
    policy = _write_policy(
        tmp_path,
        """version: 1
default: deny
capabilities:
  git.diff:
    decision: allow
""",
    )

    assert McpToolRegistry(policy).list_tools() == ()


def test_schemas_are_strict_and_returned_as_independent_copies(tmp_path: Path) -> None:
    policy = _write_policy(
        tmp_path,
        """version: 1
default: deny
capabilities:
  workspace.read_text:
    decision: allow
""",
    )
    registry = McpToolRegistry(policy)
    tool = registry.get_tool("workspace.read_text")

    assert tool is not None
    first = tool.input_schema
    assert first["additionalProperties"] is False
    assert first["required"] == ["path"]
    first["properties"]["path"]["type"] = "integer"

    assert tool.input_schema["properties"]["path"]["type"] == "string"


def test_protocol_output_is_stable_and_mutation_safe(tmp_path: Path) -> None:
    policy = _write_policy(
        tmp_path,
        """version: 1
default: deny
capabilities:
  workspace.list:
    decision: allow
""",
    )
    registry = McpToolRegistry(policy)

    first = registry.protocol_tools()
    first[0]["inputSchema"]["properties"].clear()

    assert registry.protocol_tools() == [
        {
            "name": "workspace.list",
            "description": "List files and directories inside the configured workspace.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Workspace-relative directory path.",
                        "default": ".",
                        "maxLength": 1_024,
                    }
                },
                "additionalProperties": False,
            },
        }
    ]


def test_declared_capabilities_are_sorted_and_immutable(tmp_path: Path) -> None:
    policy = _write_policy(
        tmp_path,
        """version: 1
default: deny
capabilities:
  workspace.read_text:
    decision: allow
  sandbox.run_tests:
    decision: allow
    allowed_commands:
      - [python, -m, pytest, -q]
""",
    )

    declared = policy.declared_capabilities()

    assert [item.name for item in declared] == [
        "sandbox.run_tests",
        "workspace.read_text",
    ]
    assert declared[0].allowed_commands == (("python", "-m", "pytest", "-q"),)


def test_c0_registry_exposes_exactly_one_annotated_tool(tmp_path: Path) -> None:
    policy = _write_policy(
        tmp_path,
        f"""version: 1
default: deny
capabilities:
  {C0_TOOL_NAME}:
    decision: allow
  workspace.list:
    decision: allow
""",
    )

    registry = McpToolRegistry(policy, c0_mode=True)
    tools = registry.protocol_tools()

    assert len(tools) == 1
    assert tools[0]["name"] == C0_TOOL_NAME
    assert tools[0]["inputSchema"]["required"] == ["challenge"]
    assert tools[0]["inputSchema"]["additionalProperties"] is False
    assert tools[0]["outputSchema"]["additionalProperties"] is False
    assert tools[0]["annotations"] == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    assert re.fullmatch(r"[0-9a-f]{64}", registry.tool_snapshot_sha256)


def test_c0_registry_fails_closed_without_exact_policy_capability(
    tmp_path: Path,
) -> None:
    policy = _write_policy(
        tmp_path,
        """version: 1
default: deny
capabilities:
  workspace.list:
    decision: allow
""",
    )

    assert McpToolRegistry(policy, c0_mode=True).list_tools() == ()


def test_additional_tool_requires_exact_allowlisted_policy_capability(
    tmp_path: Path,
) -> None:
    policy = _write_policy(
        tmp_path,
        """version: 1
default: deny
capabilities:
  systeme_local_attachment_handoff:
    decision: allow
  custom.not_admitted:
    decision: deny
""",
    )
    admitted = McpToolDefinition.create(
        name="systeme_local_attachment_handoff",
        description="Return one exact approved attachment package.",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        annotations={
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    )
    denied = McpToolDefinition.create(
        name="custom.not_admitted",
        description="Must remain hidden.",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )

    tools = McpToolRegistry(
        policy,
        additional_tools=(admitted, denied),
    ).protocol_tools()

    assert tools == [admitted.protocol_dict()]


def test_additional_tool_cannot_override_builtin_or_repeat_name(tmp_path: Path) -> None:
    policy = _write_policy(
        tmp_path,
        """version: 1
default: deny
capabilities: {}
""",
    )
    built_in = McpToolDefinition.create(
        name="workspace.list",
        description="override",
        input_schema={"type": "object"},
    )
    duplicate = McpToolDefinition.create(
        name="custom.tool",
        description="duplicate",
        input_schema={"type": "object"},
    )

    with pytest.raises(ValueError, match="override built-in"):
        McpToolRegistry(policy, additional_tools=(built_in,))
    with pytest.raises(ValueError, match="must be unique"):
        McpToolRegistry(policy, additional_tools=(duplicate, duplicate))
