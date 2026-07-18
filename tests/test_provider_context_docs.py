from __future__ import annotations

from pathlib import Path


def test_provider_context_contract_is_documented() -> None:
    document = Path("docs/provider-context-registry.md").read_text(encoding="utf-8")
    required = (
        "automatic selection -> Chat",
        "Work is never selected automatically",
        "never purchases provider credits automatically",
        "can_enumerate_projects: supported | unsupported | unknown",
        "can_enumerate_conversations: supported | unsupported | unknown",
        "ProviderContextStore",
        "existing conversation may be moved into a project created later",
        "quota observation is fresh",
        "contiguous version history",
        "Next lot: multimodal attachments",
        "No attachment bytes or screenshots are stored",
    )
    for marker in required:
        assert marker in document


def test_connectivity_document_contains_context_registry_contract() -> None:
    document = Path("docs/connectivity-model.md").read_text(encoding="utf-8")
    required = (
        "## Provider account context and experience selection",
        "Automatic selection uses Chat",
        "Work is selected only after an explicit request",
        "Provider quota observations are append-only",
        "provider-context-registry.md",
    )
    for marker in required:
        assert marker in document


def test_chatgpt_document_characterizes_chat_work_and_projects() -> None:
    document = Path("docs/providers/chatgpt.md").read_text(encoding="utf-8")
    required = (
        "## Chat, Work, projects and provider context",
        "Chat is the Système Local default",
        "Work requires an explicit user request",
        "Project and chat enumeration remain `unknown`",
        "moving an eligible existing chat into a project",
        "### Phase 2 — Chat-first context registry",
        "### Phase 3 — multimodal attachment foundation",
        "https://help.openai.com/en/articles/20001275",
        "https://help.openai.com/en/articles/10169521-projects-in-chatgpt",
        "https://help.openai.com/en/articles/8555545-file-uploads-faq",
    )
    for marker in required:
        assert marker in document
