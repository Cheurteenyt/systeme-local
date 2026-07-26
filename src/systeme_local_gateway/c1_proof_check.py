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
from .c0_probe import C0_CHALLENGE_PATTERN, C0_TOOL_NAME, C0ConnectivityProbeResponse
from .c0_proof_check import canonical_c0_audit_record_sha256, canonical_c0_response_sha256
from .c1_observability import (
    C1ChatProofBundle,
    C1Surface,
    C1SurfaceObservation,
    C1TestChatLabel,
    C1TestChatObservation,
    canonical_sha256,
    commit_c1_chat_correlation_receipt,
    verify_c1_surface_observation,
)
from .mcp_tools import McpToolRegistry
from .policy import PolicyEngine


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _current_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate one bounded ChatGPT Web C1 response and local audit record."
    )
    parser.add_argument("--test-chat", choices=("a", "b"), required=True)
    parser.add_argument("--surface-observation", type=Path, required=True)
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--audit-log", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        audit_key = os.environ.get("SLG_AUDIT_KEY")
        if audit_key is None or len(audit_key) < 32:
            raise ValueError("SLG_AUDIT_KEY is required for C1 proof correlation")

        label = C1TestChatLabel(f"c1-test-chat-{args.test_chat}")
        surface = verify_c1_surface_observation(
            C1SurfaceObservation.model_validate(_load_object(args.surface_observation)),
            audit_key=audit_key,
        )
        if surface.simulated:
            raise ValueError("simulated surface evidence cannot prove a C1 live Chat call")
        if surface.test_chat_label is not label:
            raise ValueError("C1 surface observation belongs to another test chat")
        if surface.surface is not C1Surface.CHAT:
            raise ValueError("C1 live proof requires the Chat surface")
        if not surface.plugin_selected:
            raise ValueError("C1 live proof requires the reviewed Plugin selected in Chat")

        challenge = args.challenge.read_text(encoding="utf-8").strip()
        if len(challenge) != 35 or not challenge.startswith("c0_"):
            raise ValueError("C1 reuses only the documented bounded C0 challenge format")
        import re

        if re.fullmatch(C0_CHALLENGE_PATTERN, challenge) is None:
            raise ValueError("C1 challenge has an invalid format")
        challenge_sha256 = hashlib.sha256(challenge.encode("ascii")).hexdigest()
        challenge_created_at = datetime.fromtimestamp(args.challenge.stat().st_mtime, UTC)

        response = C0ConnectivityProbeResponse.model_validate(_load_object(args.response))
        checked_at = datetime.now(UTC)
        if checked_at - challenge_created_at > timedelta(minutes=30):
            raise ValueError("C1 challenge is stale")
        if response.observed_at < challenge_created_at - timedelta(seconds=5):
            raise ValueError("C1 response predates its local challenge")
        if response.observed_at < surface.observed_at - timedelta(seconds=5):
            raise ValueError("C1 response predates its Chat surface observation")
        if response.observed_at > checked_at + timedelta(minutes=1):
            raise ValueError("C1 response timestamp is in the future")
        if response.challenge_sha256 != challenge_sha256:
            raise ValueError("C1 response does not match its local challenge")
        if response.server_build_commit != _current_commit():
            raise ValueError("C1 response build does not match current HEAD")

        policy = PolicyEngine(args.policy)
        registry = McpToolRegistry(policy, c0_mode=True)
        if [tool.name for tool in registry.list_tools()] != [C0_TOOL_NAME]:
            raise ValueError("C1 requires the exact reviewed one-tool C0 snapshot")
        if response.local_policy_sha256 != policy.policy_sha256:
            raise ValueError("C1 response policy digest mismatch")
        if response.tool_snapshot_sha256 != registry.tool_snapshot_sha256:
            raise ValueError("C1 response tool snapshot digest mismatch")

        audit_log = AuditLog(args.audit_log, audit_key)
        verification = audit_log.verify()
        records = [
            json.loads(line) for line in args.audit_log.read_text(encoding="utf-8").splitlines()
        ]
        matches = [
            record for record in records if record.get("audit_id") == response.audit_correlation
        ]
        if len(matches) != 1:
            raise ValueError("exactly one C1-correlated local audit record is required")
        audit_record = matches[0]
        if (
            audit_record.get("capability") != C0_TOOL_NAME
            or audit_record.get("status") != "completed"
        ):
            raise ValueError("C1-correlated audit record is not a completed probe")
        agent = audit_record.get("agent")
        if not isinstance(agent, dict) or agent.get("provider") != "mcp":
            raise ValueError("C1-correlated audit record is not attributed to MCP")

        expires_at = min(surface.expires_at, checked_at + timedelta(hours=1))
        observation = C1TestChatObservation(
            version="1",
            source="manual_chatgpt_web",
            simulated=False,
            test_chat_label=label,
            surface_observation_sha256=canonical_sha256(surface.model_dump(mode="json")),
            tool_name="systeme_local_connectivity_probe",
            tool_count=1,
            write_tool_count=0,
            high_risk_tool_count=0,
            positive_tool_invocation_count=1,
            challenge_sha256=challenge_sha256,
            response_sha256=canonical_c0_response_sha256(response),
            server_build_commit=response.server_build_commit,
            local_policy_sha256=response.local_policy_sha256,
            tool_snapshot_sha256=response.tool_snapshot_sha256,
            audit_correlation=response.audit_correlation,
            audit_record_sha256=canonical_c0_audit_record_sha256(audit_record),
            read_only=response.read_only,
            write_actions_enabled=response.write_actions_enabled,
            real_evidence_access=response.real_evidence_access,
            protocol_v2_reachable=response.protocol_v2_reachable,
            work_invoked=False,
            existing_chats_accessed=False,
            conversation_identifier_collected=False,
            private_browser_state_accessed=False,
            observed_at=response.observed_at,
            expires_at=expires_at,
        )
        receipt = commit_c1_chat_correlation_receipt(
            observation=observation,
            audit_records_verified=verification.records,
            checked_at=checked_at,
            expires_at=expires_at,
            audit_key=audit_key,
        )
        bundle = C1ChatProofBundle(
            version="1",
            observation=observation,
            correlation_receipt=receipt,
        )
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

    print(
        json.dumps(
            bundle.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
