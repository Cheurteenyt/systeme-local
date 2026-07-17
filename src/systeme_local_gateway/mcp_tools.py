from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from .policy import DeclaredCapability

InputSchema = dict[str, Any]
SchemaBuilder = Callable[[DeclaredCapability], InputSchema | None]


class DeclaredCapabilitiesProtocol(Protocol):
    def declared_capabilities(self) -> tuple[DeclaredCapability, ...]: ...


@dataclass(frozen=True)
class McpToolDefinition:
    name: str
    description: str
    _input_schema_json: str = field(repr=False)

    @classmethod
    def create(
        cls,
        *,
        name: str,
        description: str,
        input_schema: InputSchema,
    ) -> McpToolDefinition:
        return cls(
            name=name,
            description=description,
            _input_schema_json=json.dumps(
                input_schema,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

    @property
    def input_schema(self) -> InputSchema:
        decoded = json.loads(self._input_schema_json)
        if not isinstance(decoded, dict):
            raise RuntimeError("MCP tool schema is not a JSON object")
        return decoded

    def protocol_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


@dataclass(frozen=True)
class _ToolTemplate:
    description: str
    schema_builder: SchemaBuilder


def _workspace_list_schema(_capability: DeclaredCapability) -> InputSchema:
    return {
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
    }


def _workspace_read_schema(_capability: DeclaredCapability) -> InputSchema:
    return {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Workspace-relative UTF-8 text file path.",
                "minLength": 1,
                "maxLength": 1_024,
            }
        },
        "required": ["path"],
        "additionalProperties": False,
    }


def _workspace_write_schema(_capability: DeclaredCapability) -> InputSchema:
    return {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Workspace-relative destination path.",
                "minLength": 1,
                "maxLength": 1_024,
            },
            "content": {
                "type": "string",
                "description": "UTF-8 text content to write.",
            },
        },
        "required": ["path", "content"],
        "additionalProperties": False,
    }


def _command_schema(capability: DeclaredCapability) -> InputSchema | None:
    allowed_commands = sorted(set(capability.allowed_commands))
    if not allowed_commands:
        return None
    return {
        "type": "object",
        "properties": {
            "command": {
                "type": "array",
                "description": "Exact argv array selected from the local policy allowlist.",
                "items": {"type": "string", "minLength": 1},
                "minItems": 1,
                "maxItems": 32,
                "enum": [list(command) for command in allowed_commands],
            }
        },
        "required": ["command"],
        "additionalProperties": False,
    }


_TOOL_TEMPLATES: dict[str, _ToolTemplate] = {
    "git.diff": _ToolTemplate(
        description="Inspect the configured workspace Git diff inside an isolated snapshot.",
        schema_builder=_command_schema,
    ),
    "sandbox.run_tests": _ToolTemplate(
        description="Run an allowlisted test command inside the isolated sandbox snapshot.",
        schema_builder=_command_schema,
    ),
    "workspace.list": _ToolTemplate(
        description="List files and directories inside the configured workspace.",
        schema_builder=_workspace_list_schema,
    ),
    "workspace.read_text": _ToolTemplate(
        description="Read one bounded UTF-8 text file from the configured workspace.",
        schema_builder=_workspace_read_schema,
    ),
    "workspace.write_text": _ToolTemplate(
        description="Write one bounded UTF-8 text file inside the configured workspace.",
        schema_builder=_workspace_write_schema,
    ),
}


class McpToolRegistry:
    def __init__(self, policy: DeclaredCapabilitiesProtocol):
        tools: list[McpToolDefinition] = []
        for capability in policy.declared_capabilities():
            if capability.decision != "allow":
                continue
            template = _TOOL_TEMPLATES.get(capability.name)
            if template is None:
                continue
            input_schema = template.schema_builder(capability)
            if input_schema is None:
                continue
            tools.append(
                McpToolDefinition.create(
                    name=capability.name,
                    description=template.description,
                    input_schema=input_schema,
                )
            )
        self._tools = tuple(sorted(tools, key=lambda tool: tool.name))
        self._tools_by_name = {tool.name: tool for tool in self._tools}

    def list_tools(self) -> tuple[McpToolDefinition, ...]:
        return self._tools

    def get_tool(self, name: str) -> McpToolDefinition | None:
        return self._tools_by_name.get(name)

    def protocol_tools(self) -> list[dict[str, Any]]:
        return [tool.protocol_dict() for tool in self._tools]
