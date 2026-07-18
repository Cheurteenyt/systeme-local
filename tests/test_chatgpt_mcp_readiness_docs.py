from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/providers/chatgpt-mcp-connection-readiness.md"
DEPLOYMENT = ROOT / "docs/providers/chatgpt-mcp-deployment.md"
CONNECTIVITY = ROOT / "docs/connectivity-model.md"
CONTEXT = ROOT / "docs/provider-context-registry.md"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_readiness_doc_declares_no_real_connection() -> None:
    content = text(DOC)
    assert "real connection not implemented" in content
    assert "real_connection_established = false" in content
    assert "secrets_stored = false" in content


def test_readiness_doc_explains_plus_evidence_ambiguity() -> None:
    content = text(DOC)
    assert "general Apps plan matrix lists Custom (MCP) for Plus" in content
    assert "does not document a Plus developer-mode deployment path" in content
    assert "FAIL_CLOSED" in content


def test_readiness_doc_lists_all_check_identifiers() -> None:
    content = text(DOC)
    for marker in (
        "plan/role observation",
        "web client",
        "transport",
        "authentication metadata",
        "refresh token",
        "developer mode",
        "app configuration",
        "workspace access",
        "tool snapshot",
        "action review",
        "local policy",
    ):
        assert marker in content


def test_readiness_doc_lists_all_stages() -> None:
    content = text(DOC)
    for marker in (
        "`blocked`",
        "`ready_to_configure_draft`",
        "`ready_to_test_draft`",
        "`ready_for_publish_review`",
        "`ready_for_use_review`",
    ):
        assert marker in content


def test_readiness_doc_forbids_secret_material() -> None:
    content = text(DOC)
    for marker in (
        "passwords",
        "cookies",
        "OAuth access tokens",
        "refresh-token values",
        "client secrets",
        "private keys",
    ):
        assert marker in content


def test_readiness_doc_preserves_chat_boundary() -> None:
    content = text(DOC)
    assert "operator still chooses the ChatGPT conversation" in content
    assert "does not enumerate personal chats or projects" in content
    assert "select a chat automatically" in content


def test_readiness_doc_requires_tool_snapshot_drift_review() -> None:
    content = text(DOC)
    assert "Tool updates are never inherited automatically" in content
    assert "refresh, compare and recommit the snapshot" in content
    assert "high-risk tool blocks ordinary readiness" in content


def test_readiness_doc_contains_only_official_openai_sources() -> None:
    content = text(DOC)
    links = [
        line.split("(", 1)[1].rsplit(")", 1)[0]
        for line in content.splitlines()
        if line.startswith("- [")
    ]
    assert links
    assert all(link.startswith("https://help.openai.com/") for link in links)


def test_cross_provider_docs_link_to_readiness_contract() -> None:
    marker = "chatgpt-mcp-connection-readiness.md"
    assert marker in text(CONNECTIVITY)
    assert marker in text(CONTEXT)
    assert marker in text(DEPLOYMENT)


def test_deployment_doc_says_general_availability_is_not_authorization() -> None:
    content = text(DEPLOYMENT)
    assert "general availability mark as deployment authorization" in content
    assert "fails closed on that ambiguity" in content


def test_readiness_doc_lists_operator_facts_without_credentials() -> None:
    content = text(DOC)
    for marker in (
        "actual ChatGPT plan",
        "actual workspace role",
        "Secure MCP Tunnel readiness",
        "OAuth/OIDC metadata controlled for Système Local",
        "exact local policy digest",
    ):
        assert marker in content
    assert "ChatGPT password" not in content


def test_non_goals_forbid_live_mutations() -> None:
    content = text(DOC)
    for marker in (
        "installing or starting Secure MCP Tunnel",
        "creating OAuth/OIDC clients",
        "configuring, publishing or connecting a ChatGPT app",
        "invoking any provider action",
        "browser automation",
    ):
        assert marker in content
