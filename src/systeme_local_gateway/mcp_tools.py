from __future__ import annotations

import json
from hashlib import sha256
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from .policy import DeclaredCapability
from .c0_probe import (
    C0_TOOL_NAME,
    c0_annotations,
    c0_input_schema,
    c0_output_schema,
)

InputSchema = dict[str, Any]
OutputSchema = dict[str, Any]
Annotations = dict[str, bool]
SchemaBuilder = Callable[[DeclaredCapability], InputSchema | None]


class DeclaredCapabilitiesProtocol(Protocol):
    def declared_capabilities(self) -> tuple[DeclaredCapability, ...]: ...


@dataclass(frozen=True)
class McpToolDefinition:
    name: str
    description: str
    _input_schema_json: str = field(repr=False)
    _output_schema_json: str | None = field(default=None, repr=False)
    _annotations_json: str | None = field(default=None, repr=False)

    @classmethod
    def create(
        cls,
        *,
        name: str,
        description: str,
        input_schema: InputSchema,
        output_schema: OutputSchema | None = None,
        annotations: Annotations | None = None,
    ) -> McpToolDefinition:
        return cls(
            name=name,
            description=description,
            _input_schema_json=json.dumps(
                input_schema,
                sort_keys=True,
                separators=(",", ":"),
            ),
            _output_schema_json=(
                json.dumps(
                    output_schema,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if output_schema is not None
                else None
            ),
            _annotations_json=(
                json.dumps(
                    annotations,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if annotations is not None
                else None
            ),
        )

    @property
    def input_schema(self) -> InputSchema:
        decoded = json.loads(self._input_schema_json)
        if not isinstance(decoded, dict):
            raise RuntimeError("MCP tool schema is not a JSON object")
        return decoded

    @property
    def output_schema(self) -> OutputSchema | None:
        if self._output_schema_json is None:
            return None
        decoded = json.loads(self._output_schema_json)
        if not isinstance(decoded, dict):
            raise RuntimeError("MCP tool output schema is not a JSON object")
        return decoded

    @property
    def annotations(self) -> Annotations | None:
        if self._annotations_json is None:
            return None
        decoded = json.loads(self._annotations_json)
        if not isinstance(decoded, dict):
            raise RuntimeError("MCP tool annotations are not a JSON object")
        return decoded

    def protocol_dict(self) -> dict[str, Any]:
        tool: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }
        if self.output_schema is not None:
            tool["outputSchema"] = self.output_schema
        if self.annotations is not None:
            tool["annotations"] = self.annotations
        return tool


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
    def __init__(
        self,
        policy: DeclaredCapabilitiesProtocol,
        *,
        c0_mode: bool = False,
        effective_tool_names: frozenset[str] | None = None,
        additional_tools: tuple[McpToolDefinition, ...] = (),
    ):
        additional_by_name = {tool.name: tool for tool in additional_tools}
        if len(additional_by_name) != len(additional_tools):
            raise ValueError("additional MCP tool names must be unique")
        if set(additional_by_name) & set(_TOOL_TEMPLATES):
            raise ValueError("additional MCP tools cannot override built-in tools")
        if C0_TOOL_NAME in additional_by_name:
            raise ValueError("additional MCP tools cannot override the C0 probe")

        tools: list[McpToolDefinition] = []
        for capability in policy.declared_capabilities():
            if capability.decision != "allow":
                continue
            if c0_mode:
                if capability.name == C0_TOOL_NAME:
                    tools.append(
                        McpToolDefinition.create(
                            name=C0_TOOL_NAME,
                            description=(
                                "Return a synthetic, read-only connectivity "
                                "attestation for one locally generated challenge."
                            ),
                            input_schema=c0_input_schema(),
                            output_schema=c0_output_schema(),
                            annotations=c0_annotations(),
                        )
                    )
                continue
            template = _TOOL_TEMPLATES.get(capability.name)
            additional = additional_by_name.get(capability.name)
            if template is None and additional is None:
                continue
            if additional is not None:
                tools.append(additional)
            else:
                assert template is not None
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
        built_tools = tuple(sorted(tools, key=lambda tool: tool.name))
        if effective_tool_names is not None:
            built_names = {tool.name for tool in built_tools}
            if not effective_tool_names <= built_names:
                raise RuntimeError("effective MCP tool scope is not provided by the local policy")
            built_tools = tuple(tool for tool in built_tools if tool.name in effective_tool_names)
        self._tools = built_tools
        self._tools_by_name = {tool.name: tool for tool in self._tools}

    def list_tools(self) -> tuple[McpToolDefinition, ...]:
        return self._tools

    def get_tool(self, name: str) -> McpToolDefinition | None:
        return self._tools_by_name.get(name)

    def protocol_tools(self) -> list[dict[str, Any]]:
        return [tool.protocol_dict() for tool in self._tools]

    @property
    def tool_snapshot_sha256(self) -> str:
        encoded = json.dumps(
            self.protocol_tools(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return sha256(encoded).hexdigest()
