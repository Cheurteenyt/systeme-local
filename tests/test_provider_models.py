from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256

import pytest
from pydantic import ValidationError

from systeme_local_gateway.providers import (
    AgentPrincipalRef,
    CapabilityClaim,
    CapabilityEvidence,
    CapabilitySupport,
    ProviderCapabilities,
    commit_text_turn,
)

NOW = datetime(2026, 7, 17, 20, 30, tzinfo=timezone.utc)


def make_principal() -> AgentPrincipalRef:
    return AgentPrincipalRef(
        agent_id="agent_local_main",
        instance_id="instance_windows_01",
        key_id="key_primary_01",
        verification_id="verify_turn_01",
    )


def test_commit_text_turn_is_deterministic_and_metadata_only() -> None:
    principal = make_principal()
    first = commit_text_turn(
        conversation_id="slconv_test_001",
        turn_id="turn_test_001",
        trace_id="trace_test_001",
        idempotency_key="idem_test_001",
        principal=principal,
        committed_at=NOW,
        parts=["alpha", "βeta"],
    )
    second = commit_text_turn(
        conversation_id="slconv_test_001",
        turn_id="turn_test_001",
        trace_id="trace_test_001",
        idempotency_key="idem_test_001",
        principal=principal,
        committed_at=NOW,
        parts=["alpha", "βeta"],
    )

    assert first == second
    assert first.part_count == 2
    assert first.utf8_bytes == len("alphaβeta".encode("utf-8"))
    serialized = first.model_dump_json()
    assert "alpha" not in serialized
    assert "βeta" not in serialized


def test_commit_text_turn_rejects_naive_timestamp() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        commit_text_turn(
            conversation_id="slconv_test_001",
            turn_id="turn_test_001",
            trace_id="trace_test_001",
            idempotency_key="idem_test_001",
            principal=make_principal(),
            committed_at=datetime(2026, 7, 17, 20, 30),
            parts=["hello"],
        )


def test_strict_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        AgentPrincipalRef(
            agent_id="agent_local_main",
            instance_id="instance_windows_01",
            key_id="key_primary_01",
            verification_id="verify_turn_01",
            raw_prompt="must not be accepted",
        )


def test_unknown_capability_requires_no_evidence() -> None:
    with pytest.raises(ValidationError, match="unknown capabilities"):
        CapabilityClaim(
            state=CapabilitySupport.UNKNOWN,
            evidence=CapabilityEvidence.DOCUMENTED,
        )


def test_capability_profile_preserves_unknown_visible_chat_behavior() -> None:
    supported = CapabilityClaim(
        state=CapabilitySupport.SUPPORTED,
        evidence=CapabilityEvidence.SIMULATED,
    )
    unknown = CapabilityClaim(
        state=CapabilitySupport.UNKNOWN,
        evidence=CapabilityEvidence.NONE,
    )
    profile = ProviderCapabilities(
        provider="chatgpt",
        surface="deterministic_fake",
        can_initiate_turn=supported,
        can_create_conversation=supported,
        can_continue_conversation=supported,
        can_enumerate_visible_chats=unknown,
        exposes_provider_conversation_id=supported,
        exposes_terminal_response_event=supported,
        supports_streaming=supported,
        supports_tool_calls=supported,
        supports_cancellation=supported,
        supports_resume=supported,
    )

    assert profile.can_enumerate_visible_chats.state is CapabilitySupport.UNKNOWN

def test_commit_text_turn_rejects_zero_byte_content() -> None:
    with pytest.raises(ValueError, match="at least one UTF-8 byte"):
        commit_text_turn(
            conversation_id="slconv_test_001",
            turn_id="turn_test_001",
            trace_id="trace_test_001",
            idempotency_key="idem_test_001",
            principal=make_principal(),
            committed_at=NOW,
            parts=["", ""],
        )


def test_commit_text_turn_uses_domain_separation() -> None:
    committed = commit_text_turn(
        conversation_id="slconv_test_001",
        turn_id="turn_test_001",
        trace_id="trace_test_001",
        idempotency_key="idem_test_001",
        principal=make_principal(),
        committed_at=NOW,
        parts=["alpha"],
    )

    raw_length_framed = sha256()
    encoded = b"alpha"
    raw_length_framed.update(len(encoded).to_bytes(8, byteorder="big", signed=False))
    raw_length_framed.update(encoded)

    assert committed.content_sha256 != raw_length_framed.hexdigest()
