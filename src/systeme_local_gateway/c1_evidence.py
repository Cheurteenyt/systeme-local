from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel
from .c1_observability import (
    C1_CONFIGURATION_PRECEDENCE,
    C1_MANUAL_EVIDENCE_TTL,
    C1CanonicalReasoningEffort,
    C1ConfigurationLayer,
    C1EvidenceSource,
    C1EvidenceState,
    C1NegativeCheckId,
    C1NegativeOutcome,
    C1SettingObservation,
    C1SetupField,
    C1Surface,
    C1TestChatLabel,
    build_current_c1_official_evidence_profile,
    commit_c1_negative_test_receipt,
    commit_c1_revocation_receipt,
    commit_c1_runtime_setup_observation,
    commit_c1_surface_observation,
    commit_c1_visible_model_observation,
)
from .mcp_tools import McpToolRegistry
from .policy import PolicyEngine


def _audit_key() -> str:
    value = os.environ.get("SLG_AUDIT_KEY")
    if value is None or len(value) < 32:
        raise ValueError("SLG_AUDIT_KEY is required for C1 evidence")
    return value


def _run(*command: str) -> str:
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _safe_config() -> tuple[str | None, str | None, tuple[str, ...]]:
    path = Path.home() / ".codex" / "config.toml"
    if not path.is_file():
        return None, None, ()
    with path.open("rb") as stream:
        value = tomllib.load(stream)
    model = value.get("model")
    reasoning = value.get("model_reasoning_effort")
    mcp = value.get("mcp_servers", {})
    if model is not None and not isinstance(model, str):
        raise ValueError("Codex default model has an unexpected type")
    if reasoning is not None and not isinstance(reasoning, str):
        raise ValueError("Codex default reasoning effort has an unexpected type")
    if not isinstance(mcp, dict):
        raise ValueError("Codex MCP configuration has an unexpected type")
    return model, reasoning, tuple(sorted(str(name) for name in mcp))


def _setting(
    *,
    value: str | bool | int | tuple[str, ...] | None,
    state: C1EvidenceState,
    source: C1EvidenceSource,
    observed_at: datetime,
) -> C1SettingObservation:
    return C1SettingObservation(
        value=value,
        state=state,
        evidence_source=source,
        observed_at=observed_at,
    )


def _runtime(args: argparse.Namespace) -> BaseModel:
    now = datetime.now(UTC)
    root = Path.cwd().resolve()
    default_model, default_reasoning, mcp_names = _safe_config()
    policy = PolicyEngine(root / "policy.c0.yaml")
    registry = McpToolRegistry(policy, c0_mode=True)
    manifest = json.loads(
        (root / "governance" / "c0-tunnel-client.json").read_text(encoding="utf-8")
    )
    if not isinstance(manifest, dict):
        raise ValueError("C0 tunnel-client manifest must be one object")
    worktree = "clean" if _run("git", "status", "--porcelain") == "" else "dirty"
    settings = {
        C1SetupField.OPERATING_SYSTEM: _setting(
            value=f"{platform.system()} {platform.release()} {platform.version()}",
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.SYSTEM_RUNTIME,
            observed_at=now,
        ),
        C1SetupField.CODEX_VERSION: _setting(
            value=args.codex_version,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.CODEX_CLI,
            observed_at=now,
        ),
        C1SetupField.CODEX_PRODUCT_SURFACE: _setting(
            value=args.codex_product_surface,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.CODEX_APP_CONTEXT,
            observed_at=now,
        ),
        C1SetupField.AUTHENTICATION_BOUNDARY: _setting(
            value=None,
            state=C1EvidenceState.UNOBSERVABLE,
            source=C1EvidenceSource.CODEX_TURN_METADATA,
            observed_at=now,
        ),
        C1SetupField.ACTIVE_REPOSITORY_PATH: _setting(
            value=str(root),
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.GIT_REPOSITORY,
            observed_at=now,
        ),
        C1SetupField.GIT_REMOTE: _setting(
            value=_run("git", "remote", "get-url", "origin"),
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.GIT_REPOSITORY,
            observed_at=now,
        ),
        C1SetupField.BRANCH: _setting(
            value=_run("git", "branch", "--show-current"),
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.GIT_REPOSITORY,
            observed_at=now,
        ),
        C1SetupField.HEAD_COMMIT: _setting(
            value=_run("git", "rev-parse", "HEAD"),
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.GIT_REPOSITORY,
            observed_at=now,
        ),
        C1SetupField.WORKTREE_STATE: _setting(
            value=worktree,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.GIT_REPOSITORY,
            observed_at=now,
        ),
        C1SetupField.ACTIVE_RUNTIME_MODEL: _setting(
            value=args.runtime_model,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.CODEX_TURN_METADATA,
            observed_at=now,
        ),
        C1SetupField.ACTIVE_REASONING_EFFORT: _setting(
            value=args.reasoning_effort,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.CODEX_TURN_METADATA,
            observed_at=now,
        ),
        C1SetupField.CONFIGURED_DEFAULT_MODEL: _setting(
            value=default_model,
            state=(
                C1EvidenceState.CONFIGURED_DEFAULT
                if default_model is not None
                else C1EvidenceState.UNOBSERVABLE
            ),
            source=C1EvidenceSource.CODEX_USER_CONFIG,
            observed_at=now,
        ),
        C1SetupField.CONFIGURED_DEFAULT_REASONING: _setting(
            value=default_reasoning,
            state=(
                C1EvidenceState.CONFIGURED_DEFAULT
                if default_reasoning is not None
                else C1EvidenceState.UNOBSERVABLE
            ),
            source=C1EvidenceSource.CODEX_USER_CONFIG,
            observed_at=now,
        ),
        C1SetupField.ACTIVE_SERVICE_TIER: _setting(
            value=None,
            state=C1EvidenceState.UNOBSERVABLE,
            source=C1EvidenceSource.CODEX_TURN_METADATA,
            observed_at=now,
        ),
        C1SetupField.PERMISSION_MODE: _setting(
            value=args.permission_mode,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.CODEX_PERMISSION_CONTEXT,
            observed_at=now,
        ),
        C1SetupField.SANDBOX_MODE: _setting(
            value=args.sandbox_mode,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.CODEX_TURN_METADATA,
            observed_at=now,
        ),
        C1SetupField.APPROVAL_POLICY: _setting(
            value=args.approval_policy,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.CODEX_PERMISSION_CONTEXT,
            observed_at=now,
        ),
        C1SetupField.APPROVAL_REVIEWER: _setting(
            value=None,
            state=C1EvidenceState.NOT_APPLICABLE,
            source=C1EvidenceSource.CODEX_PERMISSION_CONTEXT,
            observed_at=now,
        ),
        C1SetupField.NETWORK_ACCESS_POLICY: _setting(
            value=args.network_access_policy,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.CODEX_PERMISSION_CONTEXT,
            observed_at=now,
        ),
        C1SetupField.BROWSER_SURFACE: _setting(
            value=args.browser_surface,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.CODEX_APP_CONTEXT,
            observed_at=now,
        ),
        C1SetupField.ENABLED_PLUGIN_NAMES: _setting(
            value=tuple(sorted(set(args.enabled_plugin))),
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.CODEX_APP_CONTEXT,
            observed_at=now,
        ),
        C1SetupField.CONFIGURED_MCP_SERVER_NAMES: _setting(
            value=mcp_names,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.CODEX_USER_CONFIG,
            observed_at=now,
        ),
        C1SetupField.POLICY_SHA256: _setting(
            value=policy.policy_sha256,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.C0_REVIEWED_ARTIFACT,
            observed_at=now,
        ),
        C1SetupField.TOOL_SNAPSHOT_SHA256: _setting(
            value=registry.tool_snapshot_sha256,
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.C0_REVIEWED_ARTIFACT,
            observed_at=now,
        ),
        C1SetupField.TUNNEL_CLIENT_VERSION: _setting(
            value=str(manifest["version"]),
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.C0_REVIEWED_ARTIFACT,
            observed_at=now,
        ),
        C1SetupField.TUNNEL_CLIENT_BINARY_SHA256: _setting(
            value=str(manifest["binary_sha256"]),
            state=C1EvidenceState.OBSERVED,
            source=C1EvidenceSource.C0_REVIEWED_ARTIFACT,
            observed_at=now,
        ),
    }
    return commit_c1_runtime_setup_observation(
        settings=settings,
        configuration_precedence=tuple(
            C1ConfigurationLayer(value) for value in C1_CONFIGURATION_PRECEDENCE
        ),
        observed_at=now,
        expires_at=now + timedelta(hours=24),
        audit_key=_audit_key(),
    )


def _surface(args: argparse.Namespace) -> BaseModel:
    now = datetime.now(UTC)
    return commit_c1_surface_observation(
        test_chat_label=C1TestChatLabel(f"c1-test-chat-{args.test_chat}"),
        surface=C1Surface(args.surface),
        plugin_selected=args.plugin_selected,
        observed_at=now,
        expires_at=now + C1_MANUAL_EVIDENCE_TTL,
        audit_key=_audit_key(),
    )


def _visible_model(args: argparse.Namespace) -> BaseModel:
    now = datetime.now(UTC)
    model_state = (
        C1EvidenceState.OBSERVED
        if args.visible_model_label is not None
        else C1EvidenceState.UNOBSERVABLE
    )
    reasoning_state = (
        C1EvidenceState.OBSERVED
        if args.visible_reasoning_label is not None
        else C1EvidenceState.UNOBSERVABLE
    )
    return commit_c1_visible_model_observation(
        visible_model_label=args.visible_model_label,
        model_label_state=model_state,
        visible_reasoning_label=args.visible_reasoning_label,
        reasoning_label_state=reasoning_state,
        exact_internal_model_id=args.exact_internal_model_id,
        canonical_reasoning_effort=(
            C1CanonicalReasoningEffort(args.canonical_reasoning)
            if args.canonical_reasoning is not None
            else None
        ),
        reasoning_mapping_source_sha256=args.reasoning_mapping_source_sha256,
        observed_at=now,
        expires_at=now + C1_MANUAL_EVIDENCE_TTL,
        audit_key=_audit_key(),
    )


def _negative(args: argparse.Namespace) -> BaseModel:
    now = datetime.now(UTC)
    outcomes = {
        check_id: C1NegativeOutcome(getattr(args, check_id.value)) for check_id in C1NegativeCheckId
    }
    return commit_c1_negative_test_receipt(
        outcomes=outcomes,
        observed_at=now,
        expires_at=now + C1_MANUAL_EVIDENCE_TTL,
        audit_key=_audit_key(),
    )


def _revocation(args: argparse.Namespace) -> BaseModel:
    required = (
        args.plugin_removed,
        args.runtime_key_revoked,
        args.tunnel_stopped,
        args.facade_stopped,
        args.no_listener,
        args.post_revocation_call_failed,
    )
    if not all(required):
        raise ValueError("C1 revocation requires every explicit operator confirmation")
    now = datetime.now(UTC)
    return commit_c1_revocation_receipt(
        verified_at=now,
        expires_at=now + C1_MANUAL_EVIDENCE_TTL,
        audit_key=_audit_key(),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Commit bounded, secret-free C1 evidence.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("official-profile")

    runtime = subparsers.add_parser("runtime")
    runtime.add_argument("--runtime-model", required=True)
    runtime.add_argument("--codex-version", required=True)
    runtime.add_argument(
        "--reasoning-effort",
        required=True,
        choices=[item.value for item in C1CanonicalReasoningEffort],
    )
    runtime.add_argument("--codex-product-surface", required=True)
    runtime.add_argument("--permission-mode", required=True)
    runtime.add_argument("--sandbox-mode", required=True)
    runtime.add_argument("--approval-policy", required=True)
    runtime.add_argument("--network-access-policy", required=True)
    runtime.add_argument("--browser-surface", required=True)
    runtime.add_argument("--enabled-plugin", action="append", default=[])

    surface = subparsers.add_parser("surface")
    surface.add_argument("--test-chat", choices=("a", "b"), required=True)
    surface.add_argument("--surface", choices=[item.value for item in C1Surface], required=True)
    surface.add_argument("--plugin-selected", action="store_true")

    visible = subparsers.add_parser("visible-model")
    visible.add_argument("--visible-model-label")
    visible.add_argument("--visible-reasoning-label")
    visible.add_argument("--exact-internal-model-id")
    visible.add_argument(
        "--canonical-reasoning",
        choices=[item.value for item in C1CanonicalReasoningEffort],
    )
    visible.add_argument("--reasoning-mapping-source-sha256")

    negative = subparsers.add_parser("negative")
    choices = [item.value for item in C1NegativeOutcome]
    for check_id in C1NegativeCheckId:
        negative.add_argument(
            f"--{check_id.value.replace('_', '-')}", choices=choices, required=True
        )

    revocation = subparsers.add_parser("revocation")
    revocation.add_argument("--plugin-removed", action="store_true")
    revocation.add_argument("--runtime-key-revoked", action="store_true")
    revocation.add_argument("--tunnel-stopped", action="store_true")
    revocation.add_argument("--facade-stopped", action="store_true")
    revocation.add_argument("--no-listener", action="store_true")
    revocation.add_argument("--post-revocation-call-failed", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result: BaseModel
        if args.command == "official-profile":
            result = build_current_c1_official_evidence_profile()
        elif args.command == "runtime":
            result = _runtime(args)
        elif args.command == "surface":
            result = _surface(args)
        elif args.command == "visible-model":
            result = _visible_model(args)
        elif args.command == "negative":
            result = _negative(args)
        elif args.command == "revocation":
            result = _revocation(args)
        else:
            raise ValueError("unknown C1 evidence command")
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
            result.model_dump(mode="json"),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
