from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from typing import Any

from .c0_probe import C0_TOOL_NAME, C0ConnectivityProbeResponse
from .mcp_smoke import (
    McpSmokeInputError,
    _read_token,
    _validated_endpoint,
    run_smoke,
)

_CHALLENGE_ENVIRONMENT_VARIABLE = "SLG_C0_CHALLENGE"


def _read_challenge() -> str:
    challenge = os.environ.get(_CHALLENGE_ENVIRONMENT_VARIABLE)
    if challenge is None or len(challenge) != 35:
        raise McpSmokeInputError("SLG_C0_CHALLENGE is missing or invalid")
    if not challenge.startswith("c0_"):
        raise McpSmokeInputError("SLG_C0_CHALLENGE is missing or invalid")
    try:
        int(challenge[3:], 16)
    except ValueError as exc:
        raise McpSmokeInputError("SLG_C0_CHALLENGE is missing or invalid") from exc
    if challenge.lower() != challenge:
        raise McpSmokeInputError("SLG_C0_CHALLENGE is missing or invalid")
    return challenge


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Call and validate the local synthetic C0 MCP probe."
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8765/mcp",
        help="literal loopback C0 MCP endpoint",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    token = ""
    challenge = ""
    try:
        endpoint = _validated_endpoint(args.url)
        token = _read_token(os.environ)
        challenge = _read_challenge()
        payload = asyncio.run(
            run_smoke(
                endpoint=endpoint,
                token=token,
                timeout_seconds=10.0,
                call_tool=C0_TOOL_NAME,
                arguments={"challenge": challenge},
            )
        )
        if payload.get("tools") != [C0_TOOL_NAME]:
            raise McpSmokeInputError("C0 endpoint did not advertise exactly one tool")
        call = payload.get("call")
        if not isinstance(call, dict):
            raise McpSmokeInputError("C0 probe result is missing")
        response = C0ConnectivityProbeResponse.model_validate(call.get("structured_content"))
        expected = hashlib.sha256(challenge.encode("ascii")).hexdigest()
        if response.challenge_sha256 != expected:
            raise McpSmokeInputError("C0 response challenge digest mismatch")
        safe: dict[str, Any] = {
            "status": "ok",
            "endpoint": endpoint,
            "tools": [C0_TOOL_NAME],
            "response": response.model_dump(mode="json"),
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
                {"status": "error", "error": "C0 MCP smoke check failed"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    finally:
        token = ""
        challenge = ""

    print(json.dumps(safe, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
