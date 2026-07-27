from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import re
import sys
from typing import Any
from urllib.parse import urlsplit

from .c0_probe import C0_TOOL_NAME, C0ConnectivityProbeResponse
from .c0_smoke import _read_challenge
from .mcp_smoke import McpSmokeInputError, run_smoke

_LOCAL_TUNNEL_PATH = re.compile(r"^/v1/mcp/tunnel_[0-9a-f]{32}$")


def _validated_local_tunnel_endpoint(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme.lower() != "http":
        raise McpSmokeInputError("local tunnel smoke endpoint must use plain HTTP")
    if parts.username is not None or parts.password is not None:
        raise McpSmokeInputError("local tunnel smoke endpoint must not contain user information")
    if parts.hostname is None:
        raise McpSmokeInputError("local tunnel smoke endpoint requires a loopback address")
    try:
        address = ipaddress.ip_address(parts.hostname)
    except ValueError as exc:
        raise McpSmokeInputError(
            "local tunnel smoke endpoint requires a literal loopback address"
        ) from exc
    if address != ipaddress.ip_address("127.0.0.1"):
        raise McpSmokeInputError("local tunnel smoke endpoint must use IPv4 loopback")
    try:
        port = parts.port
    except ValueError as exc:
        raise McpSmokeInputError("local tunnel smoke endpoint has an invalid port") from exc
    if port is None or not 1 <= port <= 65_535:
        raise McpSmokeInputError("local tunnel smoke endpoint requires an explicit port")
    if _LOCAL_TUNNEL_PATH.fullmatch(parts.path) is None or parts.query or parts.fragment:
        raise McpSmokeInputError("local tunnel smoke endpoint has an invalid tunnel path")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Call C0 through the official tunnel-client local integration proxy."
    )
    parser.add_argument("--url", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    challenge = ""
    try:
        endpoint = _validated_local_tunnel_endpoint(args.url)
        challenge = _read_challenge()
        payload = asyncio.run(
            run_smoke(
                endpoint=endpoint,
                token=None,
                timeout_seconds=10.0,
                call_tool=C0_TOOL_NAME,
                arguments={"challenge": challenge},
            )
        )
        if payload.get("tools") != [C0_TOOL_NAME]:
            raise McpSmokeInputError("tunneled C0 endpoint did not advertise exactly one tool")
        call = payload.get("call")
        if not isinstance(call, dict):
            raise McpSmokeInputError("tunneled C0 result is missing")
        response = C0ConnectivityProbeResponse.model_validate(call.get("structured_content"))
        safe: dict[str, Any] = {
            "status": "ok",
            "endpoint": endpoint,
            "tools": [C0_TOOL_NAME],
            "response": response.model_dump(mode="json"),
            "client_authorization_sent": False,
        }
    except McpSmokeInputError as exc:
        print(
            json.dumps({"status": "error", "error": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    except Exception:
        print(
            json.dumps(
                {"status": "error", "error": "C0 local tunnel smoke check failed"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    finally:
        challenge = ""

    print(json.dumps(safe, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
