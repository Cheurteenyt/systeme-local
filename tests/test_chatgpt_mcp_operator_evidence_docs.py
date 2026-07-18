from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]
DOC = ROOT / "docs/providers/chatgpt-mcp-operator-evidence.md"
READINESS = ROOT / "docs/providers/chatgpt-mcp-connection-readiness.md"
CONNECTIVITY = ROOT / "docs/connectivity-model.md"
CONTEXT = ROOT / "docs/provider-context-registry.md"
EXPORTS = ROOT / "src/systeme_local_gateway/providers/__init__.py"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_operator_evidence_doc_exists_and_keeps_live_connection_false() -> None:
    content = text(DOC)
    assert "real_connection_established = false" in content
    assert "secrets_stored = false" in content
    assert "no live evidence collected" in content


def test_operator_evidence_doc_lists_every_readiness_check() -> None:
    content = text(DOC)
    expected = {
        "action_review",
        "app_configuration",
        "authentication_metadata",
        "developer_mode",
        "local_policy",
        "plan_role_observation",
        "refresh_token",
        "tool_snapshot",
        "transport",
        "web_client",
        "workspace_access",
    }
    for check_id in expected:
        assert f"`{check_id}`" in content


def test_operator_evidence_doc_defines_short_lived_bundle() -> None:
    content = text(DOC)
    assert "expires no later than fifteen minutes" in content
    assert "not a durable claim" in content


def test_operator_evidence_doc_forbids_raw_sensitive_material() -> None:
    content = text(DOC)
    assert "has no fields for endpoint URLs" in content
    assert "access tokens" in content
    assert "refresh-token values" in content
    assert "client secrets" in content
    assert "private keys" in content


def test_operator_evidence_doc_defines_transport_mapping() -> None:
    content = text(DOC)
    assert "server_location = public_remote" in content
    assert "selected_transport = remote_direct" in content
    assert "selected_transport = secure_mcp_tunnel" in content


def test_operator_evidence_doc_defines_oauth_refresh_boundary() -> None:
    content = text(DOC)
    assert "refresh capability is advertised" in content
    assert "refresh tokens are actually issued" in content
    assert "stores neither metadata contents nor client credentials" in content


def test_operator_evidence_doc_defines_tool_drift_and_risk_controls() -> None:
    content = text(DOC)
    assert "server-side tool changes require refresh" in content
    assert "any high-risk tool requires a separate explicit review lot" in content
    assert "ChatGPT confirmation prompt is not a local authorization guarantee" in content


def test_operator_evidence_doc_defines_deterministic_compilation() -> None:
    content = text(DOC)
    assert "compile_chatgpt_mcp_operator_evidence_bundle" in content
    assert "evaluate_chatgpt_mcp_operator_evidence_bundle" in content
    assert "Tampered records, summaries, digests" in content


def test_operator_evidence_doc_preserves_plus_fail_closed() -> None:
    content = text(DOC)
    assert "PLUS_CUSTOM_MCP_PLAN_SCOPE" in content
    assert "remains fail-closed" in content


def test_readiness_doc_links_sealed_bundle() -> None:
    content = text(READINESS)
    assert "## Sealed operator evidence bundle" in content
    assert "chatgpt-mcp-operator-evidence.md" in content
    assert "real_connection_established=false" in content


def test_connectivity_doc_links_operator_evidence() -> None:
    content = text(CONNECTIVITY)
    assert "## Sealed operator evidence bundles" in content
    assert "providers/chatgpt-mcp-operator-evidence.md" in content
    assert "does not establish a connection" in content


def test_context_doc_keeps_bundle_outside_provider_identity() -> None:
    content = text(CONTEXT)
    assert "## Sealed operator evidence provenance" in content
    assert "does not become provider account identity" in content
    assert "Only sanitized digests may be referenced" in content


def test_provider_exports_include_operator_evidence_surface() -> None:
    content = text(EXPORTS)
    expected = {
        "McpOperatorEvidenceBundle",
        "McpOperatorEvidenceCompilation",
        "McpOperatorEvidenceEvaluation",
        "compile_chatgpt_mcp_operator_evidence_bundle",
        "evaluate_chatgpt_mcp_operator_evidence_bundle",
        "verify_chatgpt_mcp_operator_evidence_evaluation",
    }
    for name in expected:
        assert f'"{name}"' in content
