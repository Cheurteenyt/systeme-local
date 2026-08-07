from __future__ import annotations

from typing import Any, Final, Literal

from .mcp_tools import McpToolDefinition

C9_ATTACHMENT_HANDOFF_TOOL_NAME: Final[str] = "systeme_local_attachment_handoff"
C9_HANDOFF_ID_PATTERN: Final[str] = r"^c9_handoff_[0-9a-f]{32}$"
C9_RICH_SURFACES: Final[tuple[Literal["work"], ...]] = ("work",)
_SHA256_PATTERN: Final[str] = r"^[0-9a-f]{64}$"


def c9_attachment_handoff_input_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "handoff_id": {
                "type": "string",
                "description": (
                    "Opaque one-use identifier for the exact locally approved "
                    "synthetic attachment package."
                ),
                "pattern": C9_HANDOFF_ID_PATTERN,
            },
            "surface": {
                "type": "string",
                "description": (
                    "The only official ChatGPT surface that can consume this "
                    "one-use MCP rich-content lease."
                ),
                "enum": list(C9_RICH_SURFACES),
            },
        },
        "required": ["handoff_id", "surface"],
        "additionalProperties": False,
    }


def c9_attachment_handoff_annotations() -> dict[str, bool]:
    # One-use consumption is a local replay guard, not an external mutation.
    # The tool only returns an already approved package to the current
    # conversation; it does not create, update, delete, or contact open-world
    # resources.
    return {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    }


def c9_attachment_handoff_output_schema() -> dict[str, Any]:
    """Describe the metadata that accompanies the two native MCP content blocks."""

    properties: dict[str, Any] = {
        "version": {"type": "string", "const": "1"},
        "status": {
            "type": "string",
            "const": "pending_mcp_rich_content_render",
        },
        "handoff_id": {
            "type": "string",
            "pattern": C9_HANDOFF_ID_PATTERN,
        },
        "surface": {
            "type": "string",
            "const": "work",
        },
        "surface_task_id": {
            "type": "string",
            "pattern": r"^c9_work_[0-9a-f]{32}$",
        },
        "delivery_token": {
            "type": "string",
            "pattern": r"^c9_delivery_[0-9a-f]{32}$",
        },
        "c9_cycle_id": {
            "type": "string",
            "pattern": r"^c9_cycle_[0-9a-f]{32}$",
        },
        "c9_grant_id": {
            "type": "string",
            "pattern": r"^c9_grant_[0-9a-f]{32}$",
        },
        "accepted_c8_commit": {
            "type": "string",
            "pattern": r"^[0-9a-f]{40}$",
        },
        "combined_approval_sha256": {
            "type": "string",
            "pattern": _SHA256_PATTERN,
        },
        "surface_manifest_sha256": {
            "type": "string",
            "pattern": _SHA256_PATTERN,
        },
        "expansion_descriptor_sha256": {
            "type": "string",
            "pattern": _SHA256_PATTERN,
        },
        "lease_consumption_receipt_sha256": {
            "type": "string",
            "pattern": _SHA256_PATTERN,
        },
        "attachment_count": {"type": "integer", "const": 2},
        "executed_at": {"type": "string", "format": "date-time"},
        "expires_at": {"type": "string", "format": "date-time"},
        "execution_sha256": {
            "type": "string",
            "pattern": _SHA256_PATTERN,
        },
    }
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def c9_attachment_handoff_tool() -> McpToolDefinition:
    return McpToolDefinition.create(
        name=C9_ATTACHMENT_HANDOFF_TOOL_NAME,
        description=(
            "Consume one exact operator-approved package containing one sanitized "
            "synthetic image and one sanitized UTF-8 document, then return their "
            "actual content through standard MCP rich-content blocks in exactly "
            "one declared ChatGPT Work task. Native Chat uses a separate bounded "
            "operator-performed attachment handoff and cannot call this tool."
        ),
        input_schema=c9_attachment_handoff_input_schema(),
        output_schema=c9_attachment_handoff_output_schema(),
        annotations=c9_attachment_handoff_annotations(),
    )
