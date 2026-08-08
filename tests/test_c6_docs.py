from pathlib import Path

from systeme_local_gateway.c3_evidence import C3ProtectedAction
from systeme_local_gateway.c6_revalidation import (
    C6_DOCS_MCP_ENDPOINT,
    C6_REVALIDATE_AFTER,
    C6_REVIEWED_AT,
    build_current_c6_policy,
)

ROOT = Path(__file__).resolve().parents[1]
C6_DOC = ROOT / "docs/providers/chatgpt-web-c6-official-revalidation.md"
C6_LEDGER = ROOT / "docs/providers/chatgpt-web-c6-test-evidence.md"
C6_ADR = ROOT / "docs/adr/0013-automated-official-capability-revalidation.md"


def test_c6_authority_documents_record_exact_policy_and_denial_boundary() -> None:
    policy = build_current_c6_policy()
    documentation = C6_DOC.read_text(encoding="utf-8")
    normalized_documentation = " ".join(documentation.split())
    ledger = C6_LEDGER.read_text(encoding="utf-8")
    adr = C6_ADR.read_text(encoding="utf-8")
    normalized_adr = " ".join(adr.split())

    for marker in (
        policy.policy_sha256,
        policy.c3_registry_sha256,
        policy.c3_profile_sha256,
        C6_DOCS_MCP_ENDPOINT,
        C6_REVIEWED_AT.isoformat().replace("+00:00", "Z"),
        C6_REVALIDATE_AFTER.isoformat().replace("+00:00", "Z"),
        "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE",
        "five C3 protected-action decisions",
        "zero effective tools",
        "promotion_allowed=false",
        "raw_content_persisted",
    ):
        assert marker in normalized_documentation

    for source in policy.sources:
        assert source.source_id in normalized_documentation
        assert source.reviewed_content_sha256 in normalized_documentation
        assert f"{source.reviewed_normalized_bytes:,}" in normalized_documentation

    for marker in (
        "public Docs MCP acquisition",
        "candidate can change gate: false",
        "promotion allowed: false",
        "raw content persisted: false",
        "live actions allowed: false",
        "Initial focused result: `17 passed`",
    ):
        assert marker in ledger

    for marker in (
        "zero promotion authority",
        "public read-only OpenAI Docs MCP endpoint",
        "six denials",
        "zero effective tools",
    ):
        assert marker in normalized_adr


def test_c6_workflows_are_read_only_and_do_not_persist_candidates() -> None:
    governance = (ROOT / ".github/workflows/evidence-governance.yml").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in governance
    assert "persist-credentials: false" in governance
    assert "Acquire current official capability evidence without promotion" in governance
    assert "systeme_local_gateway.c6_revalidation" in governance
    assert "systeme_local_gateway.c6_seal" in governance
    assert "--expect-all-denied" in governance
    assert "--candidate-output" not in governance
    assert "--receipt-output" not in governance
    for forbidden in (
        "contents: write",
        "pull-requests: write",
        "issues: write",
        "actions/upload-artifact",
    ):
        assert forbidden not in governance

    assert "Check C6 official revalidation remains review only" in ci
    assert "Verify historical C6 official revalidation seal" in ci
    assert "Verify current C6 pull request tree matches its seal" in ci
    assert "--require-current-tree" in ci
    assert "2026-07-27T15:00:00Z" in ci
    assert "--expect-all-denied" in ci


def test_c6_source_and_scripts_preserve_no_live_action_boundary() -> None:
    source = (ROOT / "src/systeme_local_gateway/c6_revalidation.py").read_text(encoding="utf-8")
    scripts = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "scripts/c6").glob("*"))
        if path.is_file()
    )

    assert 'C6_DOCS_MCP_ENDPOINT = "https://developers.openai.com/mcp"' in source
    assert "trust_env=False" in source
    assert "follow_redirects=False" in source
    assert '"Authorization"' not in source
    assert '"Cookie"' not in source
    assert "automatic_promotion_supported: Literal[False]" in source
    assert "candidate_can_change_gate: Literal[False]" in source
    assert "promotion_allowed: Literal[False]" in source
    assert "raw_content_persisted: Literal[False]" in source
    assert "live_actions_allowed: Literal[False]" in source

    assert len(C3ProtectedAction) == 5

    for marker in (
        "CONTROL_PLANE_API_KEY",
        "CONTROL_PLANE_TUNNEL_ID",
        "SLG_SHARED_SECRET",
        "SLG_AUDIT_KEY",
        "SLG_MCP_TOKEN",
        "tunnel-client",
        "8765",
        "8766",
    ):
        assert marker in scripts

    for forbidden in (
        "Start-Process",
        "Start-C1Tunnel",
        "Start-C0Tunnel",
        "chatgpt.com",
    ):
        assert forbidden not in scripts
