from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .c0_probe import C0_TOOL_NAME, C0ConnectivityProbeResponse
from .mcp_tools import McpToolRegistry
from .policy import PolicyEngine


def _load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a copied manual ChatGPT Web C0 response."
    )
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--audit-log", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    return parser


def _current_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        audit_key = os.environ.get("SLG_AUDIT_KEY")
        if audit_key is None or len(audit_key) < 32:
            raise ValueError("SLG_AUDIT_KEY is required")
        challenge = args.challenge.read_text(encoding="utf-8").strip()
        expected_challenge = hashlib.sha256(challenge.encode("ascii")).hexdigest()
        response = C0ConnectivityProbeResponse.model_validate(_load_json_object(args.response))
        challenge_created_at = datetime.fromtimestamp(
            args.challenge.stat().st_mtime,
            UTC,
        )
        checked_at = datetime.now(UTC)
        if checked_at - challenge_created_at > timedelta(minutes=30):
            raise ValueError("local C0 challenge is stale")
        if response.observed_at < challenge_created_at - timedelta(seconds=5):
            raise ValueError("response predates the local C0 challenge")
        if response.observed_at > checked_at + timedelta(minutes=1):
            raise ValueError("response timestamp is in the future")
        if response.challenge_sha256 != expected_challenge:
            raise ValueError("response does not match the locally generated challenge")
        if response.server_build_commit != _current_commit():
            raise ValueError("response build commit does not match current HEAD")

        policy = PolicyEngine(args.policy)
        registry = McpToolRegistry(policy, c0_mode=True)
        if [tool.name for tool in registry.list_tools()] != [C0_TOOL_NAME]:
            raise ValueError("C0 policy does not expose exactly one tool")
        if response.local_policy_sha256 != policy.policy_sha256:
            raise ValueError("response policy digest mismatch")
        if response.tool_snapshot_sha256 != registry.tool_snapshot_sha256:
            raise ValueError("response tool snapshot digest mismatch")

        audit_log = AuditLog(args.audit_log, audit_key)
        verification = audit_log.verify()
        records = [
            json.loads(line) for line in args.audit_log.read_text(encoding="utf-8").splitlines()
        ]
        matches = [
            record for record in records if record.get("audit_id") == response.audit_correlation
        ]
        if len(matches) != 1:
            raise ValueError("exactly one correlated audit record is required")
        record = matches[0]
        if record.get("capability") != C0_TOOL_NAME or record.get("status") != "completed":
            raise ValueError("correlated audit record is not a completed C0 probe")
        agent = record.get("agent")
        if not isinstance(agent, dict) or agent.get("provider") != "mcp":
            raise ValueError("correlated audit record is not attributed to MCP")

        output: dict[str, Any] = {
            "status": "live_call_correlated_pending_revocation",
            "real_connection_established": False,
            "challenge_sha256": expected_challenge,
            "response_sha256": hashlib.sha256(
                json.dumps(
                    response.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest(),
            "audit_correlation": response.audit_correlation,
            "audit_record_sha256": hashlib.sha256(
                json.dumps(
                    record,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest(),
            "audit_records_verified": verification.records,
            "local_policy_sha256": response.local_policy_sha256,
            "tool_snapshot_sha256": response.tool_snapshot_sha256,
        }
    except Exception as exc:
        print(
            json.dumps(
                {"status": "error", "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
