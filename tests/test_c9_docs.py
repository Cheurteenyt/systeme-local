from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

C9_DOCS = (
    "README.md",
    "docs/adr/0016-bind-one-sanitized-package-to-work-mcp-and-chat-manual.md",
    "docs/architecture.md",
    "docs/connectivity-model.md",
    "docs/documentation-governance.md",
    "docs/index.md",
    "docs/provider-attachments.md",
    "docs/providers/chatgpt.md",
    "docs/providers/chatgpt-web-c9-attachment-handoff.md",
    "docs/providers/chatgpt-web-c9-test-evidence.md",
    "docs/roadmap.md",
    "docs/threat-model.md",
)


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _normalized(value: str) -> str:
    return " ".join(value.split())


def test_c9_docs_follow_the_current_no_plugins_in_normal_chat_rule() -> None:
    adr = _text("docs/adr/0016-bind-one-sanitized-package-to-work-mcp-and-chat-manual.md")
    runbook = _text("docs/providers/chatgpt-web-c9-attachment-handoff.md")
    ledger = _text("docs/providers/chatgpt-web-c9-test-evidence.md")
    provider = _text("docs/providers/chatgpt.md")

    for document in (adr, runbook, ledger):
        assert "Plugins are not available in Chat" in _normalized(document)
        assert "https://learn.chatgpt.com/docs/plugins" in document
        assert "https://developers.openai.com/plugins/reference" in document

    assert "normal Chat Plugin/MCP" in provider
    assert "Blocked by the current official rule" in provider


def test_c9_docs_require_work_rich_then_normal_chat_manual_handoff() -> None:
    adr = _text("docs/adr/0016-bind-one-sanitized-package-to-work-mcp-and-chat-manual.md")
    runbook = _text("docs/providers/chatgpt-web-c9-attachment-handoff.md")
    ledger = _text("docs/providers/chatgpt-web-c9-test-evidence.md")

    assert "The Work Plugin/MCP path admits only" in adr
    assert "owner-only, short-lived export" in adr
    assert "Work is always first. Normal Chat is always second." in runbook
    assert "normal-Chat manual handoffs:       0/1" in runbook
    assert "one rich Plugin/MCP call in Work" in ledger
    assert "one distinct visible manual file handoff in normal Chat" in ledger


def test_c9_docs_keep_work_and_chat_claims_non_interchangeable() -> None:
    adr = _text("docs/adr/0016-bind-one-sanitized-package-to-work-mcp-and-chat-manual.md")
    runbook = _text("docs/providers/chatgpt-web-c9-attachment-handoff.md")
    ledger = _text("docs/providers/chatgpt-web-c9-test-evidence.md")

    for document in (adr, runbook, ledger):
        assert "internal app ID" in document
        assert "local endpoint" in document

    assert "does **not** mean that Chat invoked an MCP tool" in adr
    assert "never be labelled" in runbook
    assert "must explicitly state that no Chat app" in ledger
    assert "same internal app on Work and Chat" in ledger


def test_c9_docs_do_not_retain_superseded_dual_rich_claims() -> None:
    combined = "\n".join(_text(path) for path in C9_DOCS)

    stale_claims = (
        "same rich Plugin/MCP tool in Work and normal Chat",
        "same-tool Work/Chat rich handoff",
        "both Work and normal Chat invoke the same read-only MCP",
        'normal Chat invokes it with `surface="chat"`',
        "normal Chat rich delivery is `0/1`",
        "manual picker fallback is non-qualifying",
        "same-tool Chat rich proof",
        "PostRevocationChatPluginMcpAppCallFailed",
        "WORK_AND_CHAT_RICH_MCP",
    )
    for stale_claim in stale_claims:
        assert stale_claim not in combined


def test_c9_docs_preserve_honest_live_pending_and_residual_risks() -> None:
    runbook = _text("docs/providers/chatgpt-web-c9-attachment-handoff.md")
    ledger = _text("docs/providers/chatgpt-web-c9-test-evidence.md")
    threat = _text("docs/threat-model.md")

    assert "acceptance and interpretation of both content shapes are live-pending" in _normalized(
        runbook
    )
    assert "live-pending" in runbook
    assert "mis-select a visually similar app" in runbook
    assert "privileged local TOCTOU" in runbook
    assert "C9 success claim | absent" in ledger
    assert "internal app identifier" in threat
    assert "manual path risks" in threat
