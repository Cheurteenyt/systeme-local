from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .c0_probe import C0_TOOL_NAME
from .c0_proof_check import canonical_c0_audit_record_sha256
from .c1_observability import (
    C1C0DependencyStatus,
    C1ChatProofBundle,
    C1NegativeTestReceipt,
    C1RevocationReceipt,
    C1RuntimeSetupObservation,
    C1SetupField,
    C1SurfaceObservation,
    C1VisibleModelObservation,
    build_current_c1_official_evidence_profile,
    commit_c1_final_attestation,
)
from .mcp_tools import McpToolRegistry
from .policy import PolicyEngine

_C0_DEPENDENCY_COMMIT = "912d0d33e119469ff957965104cf20af5e491923"
_C1_BRANCH = "interop/chatgpt-web-chat-observability-c1"


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Commit the revocation-bound C1 live attestation.")
    parser.add_argument("--runtime-setup", type=Path, required=True)
    parser.add_argument("--visible-model", type=Path, required=True)
    parser.add_argument("--surface-a", type=Path, required=True)
    parser.add_argument("--surface-b", type=Path, required=True)
    parser.add_argument("--proof-a", type=Path, required=True)
    parser.add_argument("--proof-b", type=Path, required=True)
    parser.add_argument("--negative-tests", type=Path, required=True)
    parser.add_argument("--revocation", type=Path, required=True)
    parser.add_argument("--audit-log", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument(
        "--c0-status",
        choices=[item.value for item in C1C0DependencyStatus],
        required=True,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        audit_key = os.environ.get("SLG_AUDIT_KEY")
        if audit_key is None or len(audit_key) < 32:
            raise ValueError("SLG_AUDIT_KEY is required for C1 final attestation")
        if _git("branch", "--show-current") != _C1_BRANCH:
            raise ValueError("C1 final attestation requires the dedicated C1 branch")
        if _git("status", "--porcelain") != "":
            raise ValueError("C1 final attestation requires a clean worktree")
        current_commit = _git("rev-parse", "HEAD")

        setup = C1RuntimeSetupObservation.model_validate(_load_object(args.runtime_setup))
        visible = C1VisibleModelObservation.model_validate(_load_object(args.visible_model))
        surfaces = (
            C1SurfaceObservation.model_validate(_load_object(args.surface_a)),
            C1SurfaceObservation.model_validate(_load_object(args.surface_b)),
        )
        bundles = (
            C1ChatProofBundle.model_validate(_load_object(args.proof_a)),
            C1ChatProofBundle.model_validate(_load_object(args.proof_b)),
        )
        negative = C1NegativeTestReceipt.model_validate(_load_object(args.negative_tests))
        revocation = C1RevocationReceipt.model_validate(_load_object(args.revocation))

        if setup.settings[C1SetupField.BRANCH].value != _C1_BRANCH:
            raise ValueError("C1 runtime setup branch mismatch")
        if setup.settings[C1SetupField.HEAD_COMMIT].value != current_commit:
            raise ValueError("C1 runtime setup commit mismatch")
        if setup.settings[C1SetupField.WORKTREE_STATE].value != "clean":
            raise ValueError("C1 runtime setup did not observe a clean worktree")
        if any(bundle.observation.server_build_commit != current_commit for bundle in bundles):
            raise ValueError("C1 Chat response build does not match current HEAD")

        policy = PolicyEngine(args.policy)
        registry = McpToolRegistry(policy, c0_mode=True)
        if [tool.name for tool in registry.list_tools()] != [C0_TOOL_NAME]:
            raise ValueError("C1 policy no longer exposes the exact one-tool C0 snapshot")
        if setup.settings[C1SetupField.POLICY_SHA256].value != policy.policy_sha256:
            raise ValueError("C1 setup policy digest mismatch")
        if setup.settings[C1SetupField.TOOL_SNAPSHOT_SHA256].value != registry.tool_snapshot_sha256:
            raise ValueError("C1 setup tool snapshot digest mismatch")
        for bundle in bundles:
            if bundle.observation.local_policy_sha256 != policy.policy_sha256:
                raise ValueError("C1 Chat observation policy digest mismatch")
            if bundle.observation.tool_snapshot_sha256 != registry.tool_snapshot_sha256:
                raise ValueError("C1 Chat observation tool snapshot digest mismatch")

        audit = AuditLog(args.audit_log, audit_key)
        audit_verification = audit.verify()
        records = [
            json.loads(line) for line in args.audit_log.read_text(encoding="utf-8").splitlines()
        ]
        matched_records: list[dict[str, Any]] = []
        for bundle in bundles:
            matches = [
                record
                for record in records
                if record.get("audit_id") == bundle.observation.audit_correlation
            ]
            if len(matches) != 1:
                raise ValueError("each C1 Chat call requires exactly one local audit record")
            record = matches[0]
            if record.get("capability") != C0_TOOL_NAME or record.get("status") != "completed":
                raise ValueError("C1 final audit correlation is not a completed probe")
            if canonical_c0_audit_record_sha256(record) != bundle.observation.audit_record_sha256:
                raise ValueError("C1 final audit record digest mismatch")
            if bundle.correlation_receipt.audit_records_verified > audit_verification.records:
                raise ValueError("C1 correlation receipt claims an impossible audit-chain length")
            matched_records.append(record)
        if matched_records[0] == matched_records[1]:
            raise ValueError("C1 final attestation requires two distinct audit records")

        latest_chat = max(bundle.observation.observed_at for bundle in bundles)
        if negative.observed_at < latest_chat:
            raise ValueError("C1 negative tests must follow both positive Chat calls")
        if revocation.verified_at < latest_chat:
            raise ValueError("C1 revocation must follow both positive Chat calls")
        if abs((negative.observed_at - revocation.verified_at).total_seconds()) > 600:
            raise ValueError("C1 post-revocation evidence and receipt are not contemporaneous")

        now = datetime.now(timezone.utc)
        evidence_expiries = [
            setup.expires_at,
            visible.expires_at,
            *(item.expires_at for item in surfaces),
            *(bundle.observation.expires_at for bundle in bundles),
            *(bundle.correlation_receipt.expires_at for bundle in bundles),
            negative.expires_at,
            revocation.expires_at,
        ]
        expires_at = min(min(evidence_expiries), now + timedelta(minutes=30))
        attestation = commit_c1_final_attestation(
            c0_dependency_status=C1C0DependencyStatus(args.c0_status),
            c0_dependency_commit=_C0_DEPENDENCY_COMMIT,
            official_profile=build_current_c1_official_evidence_profile(),
            runtime_setup=setup,
            visible_model=visible,
            surface_observations=surfaces,
            chat_observations=(
                bundles[0].observation,
                bundles[1].observation,
            ),
            correlation_receipts=(
                bundles[0].correlation_receipt,
                bundles[1].correlation_receipt,
            ),
            negative_receipt=negative,
            revocation_receipt=revocation,
            audit_key=audit_key,
            verified_at=now,
            expires_at=expires_at,
        )
    except Exception as exc:
        print(
            json.dumps(
                {"status": "error", "error": str(exc)},
                ensure_ascii=True,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            attestation.model_dump(mode="json"),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
