from __future__ import annotations

from pathlib import Path

from systeme_local_gateway.providers.chatgpt_mcp_deployment import (
    build_current_chatgpt_mcp_capability_profile,
)
from systeme_local_gateway.providers.mcp_deployment_models import (
    McpCapabilityId,
)
from systeme_local_gateway.providers.models import CapabilitySupport

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/providers/chatgpt-mcp-deployment.md"


def test_deployment_document_records_status_and_revalidation_boundary() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "real connection not implemented" in text
    assert "Reviewed: 2026-07-18" in text
    assert "Revalidate no later than: 2026-08-17" in text


def test_deployment_document_explains_current_chat_selection() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "user opens the intended ChatGPT conversation" in text
    assert "user selects or mentions the Système Local app" in text
    assert "There is no automatic “choose the right ChatGPT chat” operation" in text


def test_deployment_document_keeps_account_discovery_unknown() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "Enumerate all personal chats through custom MCP | unknown" in text
    assert "Enumerate all projects through custom MCP | unknown" in text
    assert "Account-wide chat and project enumeration remain `unknown`" in text


def test_deployment_document_separates_authentication_contexts() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "ChatGPT app authentication and ChatGPT account authentication are separate" in text
    assert "never receives or replays the user's ChatGPT password" in text
    assert "offline_access" in text


def test_deployment_document_records_remote_and_tunnel_transport() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "ChatGPT does not connect directly to a loopback MCP endpoint" in text
    assert "Developer machine | Secure MCP Tunnel" in text
    assert "does **not** claim that the tunnel is installed" in text


def test_deployment_document_records_plan_and_role_boundaries() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "Pro | read/fetch in developer mode | unsupported | unsupported" in text
    assert "Business | admin/owner | supported in beta | admin/owner" in text
    assert "Enterprise | authorized developer, admin or owner" in text
    assert "Plus | unsupported by this profile" in text


def test_deployment_document_records_mode_and_permission_limits() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "Agent mode does not use custom apps" in text
    assert "Deep research may use custom apps for read/fetch actions only" in text
    assert "some especially risky actions may be blocked" in text
    assert "server-side tool changes are not trusted automatically" in text


def test_deployment_document_links_only_committed_official_sources() -> None:
    text = DOC.read_text(encoding="utf-8")
    profile = build_current_chatgpt_mcp_capability_profile()
    urls = {source.url for source in profile.sources}
    assert urls == {
        "https://help.openai.com/en/articles/10169521-projects-in-chatgpt",
        "https://help.openai.com/en/articles/11487775-apps-in-chatgpt",
        "https://help.openai.com/en/articles/12584461",
    }
    for url in urls:
        assert url in text


def test_document_and_profile_agree_on_unknown_enumeration() -> None:
    profile = build_current_chatgpt_mcp_capability_profile()
    rows = {row.capability: row for row in profile.rows}
    assert rows[McpCapabilityId.ENUMERATE_PERSONAL_CHATS].claim.state is CapabilitySupport.UNKNOWN
    assert rows[McpCapabilityId.ENUMERATE_PROJECTS].claim.state is CapabilitySupport.UNKNOWN


def test_document_forbids_secret_and_browser_shortcuts() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "browser automation, cookies, private endpoints or DOM scraping" in text
    assert "using the ChatGPT login as MCP authentication" in text


def test_connectivity_document_links_deployment_contract() -> None:
    text = (ROOT / "docs/connectivity-model.md").read_text(encoding="utf-8")
    assert "## Evidence-bound MCP deployment" in text
    assert "chatgpt-mcp-deployment.md" in text
    assert "MCP app authentication is not ChatGPT account authentication" in text


def test_context_registry_keeps_operator_confirmed_chat_binding() -> None:
    text = (ROOT / "docs/provider-context-registry.md").read_text(encoding="utf-8")
    assert "## ChatGPT MCP deployment evidence" in text
    assert "operator opens the intended chat" in text
    assert "account-wide chat or project enumeration" in text


def test_chatgpt_characterization_records_current_mcp_boundary() -> None:
    text = (ROOT / "docs/providers/chatgpt.md").read_text(encoding="utf-8")
    assert "## Current custom MCP deployment contract" in text
    assert "Secure MCP Tunnel" in text
    assert "ChatGPT password, browser cookie" in text
    assert "session token" in text
