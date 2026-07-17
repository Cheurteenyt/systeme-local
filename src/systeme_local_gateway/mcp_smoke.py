from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import math
import os
import sys
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

_DEFAULT_ENDPOINT = "http://127.0.0.1:8765/mcp"
_TOKEN_ENVIRONMENT_VARIABLE = "SLG_MCP_TOKEN"
_PLACEHOLDER_TOKEN = "replace-with-fourth-independent-at-least-32-random-characters"
_READ_ONLY_TOOLS = ("workspace.list",)
_MAX_ARGUMENTS_BYTES = 65_536
_MAX_TIMEOUT_SECONDS = 60.0


class McpSmokeInputError(ValueError):
    """Raised when the local smoke-check input is unsafe or invalid."""


def _validated_endpoint(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme.lower() != "http":
        raise McpSmokeInputError("MCP smoke endpoint must use plain HTTP on loopback")
    if parts.username is not None or parts.password is not None:
        raise McpSmokeInputError("MCP smoke endpoint must not contain user information")
    if parts.hostname is None:
        raise McpSmokeInputError("MCP smoke endpoint must include a loopback address")
    try:
        address = ipaddress.ip_address(parts.hostname)
    except ValueError as exc:
        raise McpSmokeInputError(
            "MCP smoke endpoint must use a literal loopback IP address"
        ) from exc
    if not address.is_loopback:
        raise McpSmokeInputError("MCP smoke endpoint must remain on loopback")
    try:
        port = parts.port
    except ValueError as exc:
        raise McpSmokeInputError("MCP smoke endpoint contains an invalid port") from exc
    if port is None:
        raise McpSmokeInputError("MCP smoke endpoint must include an explicit port")
    if parts.path != "/mcp" or parts.query or parts.fragment:
        raise McpSmokeInputError("MCP smoke endpoint must use the exact /mcp path")
    return value


def _read_token(environment: Mapping[str, str]) -> str:
    token = environment.get(_TOKEN_ENVIRONMENT_VARIABLE)
    if token is None or token == "":
        raise McpSmokeInputError("SLG_MCP_TOKEN is required in the process environment")
    if token != token.strip() or "\r" in token or "\n" in token:
        raise McpSmokeInputError("SLG_MCP_TOKEN contains invalid whitespace")
    if not 32 <= len(token) <= 512:
        raise McpSmokeInputError("SLG_MCP_TOKEN must contain between 32 and 512 characters")
    if token == _PLACEHOLDER_TOKEN:
        raise McpSmokeInputError("SLG_MCP_TOKEN must not use the documented placeholder")
    return token


def _reject_json_constant(value: str) -> None:
    raise McpSmokeInputError(f"non-finite JSON value is not allowed: {value}")


def _parse_arguments_json(value: str) -> dict[str, Any]:
    if len(value.encode("utf-8")) > _MAX_ARGUMENTS_BYTES:
        raise McpSmokeInputError("tool arguments exceed the local smoke-check size limit")
    try:
        parsed = json.loads(value, parse_constant=_reject_json_constant)
    except json.JSONDecodeError as exc:
        raise McpSmokeInputError("tool arguments must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise McpSmokeInputError("tool arguments must be a JSON object")
    return parsed


def _validated_timeout(value: float) -> float:
    if not math.isfinite(value) or not 0 < value <= _MAX_TIMEOUT_SECONDS:
        raise McpSmokeInputError(
            f"timeout must be greater than zero and at most {_MAX_TIMEOUT_SECONDS:g} seconds"
        )
    return value


async def run_smoke(
    *,
    endpoint: str,
    token: str,
    timeout_seconds: float,
    call_tool: str | None,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=httpx.Timeout(timeout_seconds),
        follow_redirects=False,
        trust_env=False,
    ) as http_client:
        async with streamable_http_client(
            endpoint,
            http_client=http_client,
            terminate_on_close=False,
        ) as (read_stream, write_stream, _session_id):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                listed = await session.list_tools()
                tool_names = sorted(tool.name for tool in listed.tools)
                payload: dict[str, Any] = {
                    "status": "ok",
                    "endpoint": endpoint,
                    "tools": tool_names,
                }
                if call_tool is not None:
                    if call_tool not in tool_names:
                        raise McpSmokeInputError(
                            f"requested tool is not advertised: {call_tool}"
                        )
                    result = await session.call_tool(call_tool, arguments)
                    if result.isError:
                        raise McpSmokeInputError(
                            f"requested tool returned an MCP error: {call_tool}"
                        )
                    payload["call"] = {
                        "tool": call_tool,
                        "structured_content": result.structuredContent,
                    }
                return payload



def _redact_secret(value: Any, secret: str) -> Any:
    if isinstance(value, str):
        return value.replace(secret, "[REDACTED]")
    if isinstance(value, list):
        return [_redact_secret(item, secret) for item in value]
    if isinstance(value, tuple):
        return [_redact_secret(item, secret) for item in value]
    if isinstance(value, dict):
        return {
            str(_redact_secret(key, secret)): _redact_secret(item, secret)
            for key, item in value.items()
        }
    return value

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the local SystÃ¨me Local MCP endpoint with the official MCP client"
        )
    )
    parser.add_argument(
        "--url",
        default=_DEFAULT_ENDPOINT,
        help="literal loopback Streamable HTTP endpoint (default: %(default)s)",
    )
    parser.add_argument(
        "--call-tool",
        choices=_READ_ONLY_TOOLS,
        help="optionally call one explicitly selected read-only tool",
    )
    parser.add_argument(
        "--arguments-json",
        help="JSON object passed to --call-tool (default: {})",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=10.0,
        help="bounded client timeout, at most 60 seconds (default: %(default)s)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        endpoint = _validated_endpoint(args.url)
        token = _read_token(os.environ)
        timeout_seconds = _validated_timeout(args.timeout_seconds)
        if args.call_tool is None:
            if args.arguments_json is not None:
                raise McpSmokeInputError("--arguments-json requires --call-tool")
            arguments: dict[str, Any] = {}
        else:
            arguments = _parse_arguments_json(args.arguments_json or "{}")
        payload = asyncio.run(
            run_smoke(
                endpoint=endpoint,
                token=token,
                timeout_seconds=timeout_seconds,
                call_tool=args.call_tool,
                arguments=arguments,
            )
        )
    except McpSmokeInputError as exc:
        print(
            json.dumps(
                {"status": "error", "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    except Exception:
        print(
            json.dumps(
                {"status": "error", "error": "MCP smoke check failed"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    safe_payload = _redact_secret(payload, token)
    print(
        json.dumps(
            safe_payload,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
