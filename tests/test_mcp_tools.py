from pathlib import Path

from systeme_local_gateway.mcp_tools import McpToolRegistry
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
