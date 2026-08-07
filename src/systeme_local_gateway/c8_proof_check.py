from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .c0_probe import C0_CHALLENGE_PATTERN, C0_TOOL_NAME, C0ConnectivityProbeResponse
from .c0_proof_check import canonical_c0_audit_record_sha256, canonical_c0_response_sha256
from .c8_live_cycle import (
    C8TestWorkLabel,
    C8WorkCallObservation,
    C8WorkProofBundle,
    C8WorkTaskSurfaceObservation,
    canonical_sha256,
    commit_work_correlation_receipt,
    load_live_cycle_bundle,
    rendered_json,
    verify_live_cycle_bundle,
    verify_work_task_surface_observation,
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
        description="Validate one bounded ChatGPT Work C8 response and local audit record."
    )
    parser.add_argument("--test-work", choices=("a", "b"), required=True)
    parser.add_argument("--live-cycle", type=Path, required=True)
    parser.add_argument("--task-surface-observation", type=Path, required=True)
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--audit-log", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        audit_key = os.environ.get("SLG_AUDIT_KEY")
        if audit_key is None or len(audit_key) < 32:
            raise ValueError("SLG_AUDIT_KEY is required for C8 proof correlation")

        live_cycle = load_live_cycle_bundle(args.live_cycle)
        verify_live_cycle_bundle(
            bundle=live_cycle,
            root=args.root,
            audit_key=audit_key,
            evaluated_at=live_cycle.grant.authorized_at,
        )
        label = C8TestWorkLabel(f"c8-test-work-{args.test_work}")
        task_surface = verify_work_task_surface_observation(
            C8WorkTaskSurfaceObservation.model_validate(
                _load_object(args.task_surface_observation)
            ),
            audit_key=audit_key,
        )
        if task_surface.test_work_label is not label:
            raise ValueError("C8 task surface observation belongs to another Work task")
        if task_surface.cycle_id != live_cycle.authorization.cycle_id:
            raise ValueError("C8 task surface observation belongs to another cycle")
        if task_surface.grant_id != live_cycle.grant.grant_id:
            raise ValueError("C8 task surface observation belongs to another grant")
        if not (
            live_cycle.grant.authorized_at <= task_surface.observed_at < live_cycle.grant.expires_at
        ):
            raise ValueError("C8 Work task was not opened inside the live grant window")

        challenge = args.challenge.read_text(encoding="utf-8").strip()
        if len(challenge) != 35 or re.fullmatch(C0_CHALLENGE_PATTERN, challenge) is None:
            raise ValueError("C8 reuses only the documented bounded C0 challenge format")
        challenge_sha256 = hashlib.sha256(challenge.encode("ascii")).hexdigest()
        challenge_created_at = datetime.fromtimestamp(args.challenge.stat().st_mtime, UTC)

        response = C0ConnectivityProbeResponse.model_validate(_load_object(args.response))
        checked_at = datetime.now(UTC)
        if checked_at - challenge_created_at > timedelta(minutes=30):
            raise ValueError("C8 challenge is stale")
        if response.observed_at < challenge_created_at - timedelta(seconds=5):
            raise ValueError("C8 response predates its local challenge")
        if response.observed_at < task_surface.observed_at - timedelta(seconds=5):
            raise ValueError("C8 response predates its Work task surface observation")
        if response.observed_at >= task_surface.expires_at:
            raise ValueError("C8 Work task surface observation is stale for this response")
        if not (
            live_cycle.grant.authorized_at <= response.observed_at < live_cycle.grant.expires_at
        ):
            raise ValueError("C8 response occurred outside the live grant window")
        if response.observed_at > checked_at + timedelta(minutes=1):
            raise ValueError("C8 response timestamp is in the future")
        if response.challenge_sha256 != challenge_sha256:
            raise ValueError("C8 response does not match its local challenge")
        if response.server_build_commit != _current_commit():
            raise ValueError("C8 response build does not match current HEAD")

        policy = PolicyEngine(args.policy)
        registry = McpToolRegistry(policy, c0_mode=True)
        if [tool.name for tool in registry.list_tools()] != [C0_TOOL_NAME]:
            raise ValueError("C8 requires the exact reviewed one-tool C0 snapshot")
        if response.local_policy_sha256 != policy.policy_sha256:
            raise ValueError("C8 response policy digest mismatch")
        if response.tool_snapshot_sha256 != registry.tool_snapshot_sha256:
            raise ValueError("C8 response tool snapshot digest mismatch")

        audit_log = AuditLog(args.audit_log, audit_key)
        verification = audit_log.verify()
        records = [
            json.loads(line) for line in args.audit_log.read_text(encoding="utf-8").splitlines()
        ]
        matches = [
            record for record in records if record.get("audit_id") == response.audit_correlation
        ]
        if len(matches) != 1:
            raise ValueError("exactly one C8-correlated local audit record is required")
        audit_record = matches[0]
        if (
            audit_record.get("capability") != C0_TOOL_NAME
            or audit_record.get("status") != "completed"
        ):
            raise ValueError("C8-correlated audit record is not a completed probe")
        agent = audit_record.get("agent")
        if not isinstance(agent, dict) or agent.get("provider") != "mcp":
            raise ValueError("C8-correlated audit record is not attributed to MCP")

        observation = C8WorkCallObservation(
            version="1",
            source="manual_chatgpt_work",
            simulated=False,
            cycle_id=live_cycle.authorization.cycle_id,
            grant_id=live_cycle.grant.grant_id,
            test_work_label=label,
            task_surface_observation_sha256=canonical_sha256(task_surface.model_dump(mode="json")),
            visible_surface="work",
            explicit_work_selected=True,
            plugin_selected=True,
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
            chat_invoked=False,
            automatic_chat_to_work_switch_used=False,
            existing_conversations_accessed=False,
            conversation_identifier_collected=False,
            private_browser_state_accessed=False,
            account_or_security_settings_accessed=False,
            observed_at=response.observed_at,
        )
        receipt = commit_work_correlation_receipt(
            observation=observation,
            audit_records_verified=verification.records,
            checked_at=checked_at,
            audit_key=audit_key,
        )
        bundle = C8WorkProofBundle(
            version="1",
            task_surface_observation=task_surface,
            observation=observation,
            correlation_receipt=receipt,
        )
    except Exception as error:
        print(
            json.dumps(
                {"status": "error", "error": str(error)},
                ensure_ascii=True,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    print(rendered_json(bundle), end="")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
