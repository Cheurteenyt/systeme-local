from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from hashlib import sha256

from .models import (
    CapabilityClaim,
    CapabilityEvidence,
    CapabilitySupport,
    CommittedTurn,
    ConversationHandle,
    OutputDigestDeltaEvent,
    ProviderCapabilities,
    ProviderResponseStatus,
    ProviderRun,
    ResponseStartedEvent,
    ResponseTerminalEvent,
    ToolCallRequestedEvent,
)


class FakeChatGptScenario(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INCOMPLETE = "incomplete"
    TOOL_CALL = "tool_call"


@dataclass(frozen=True)
class FakeChatGptPlan:
    conversation: ConversationHandle
    run: ProviderRun
    provider_events: tuple[
        ResponseStartedEvent
        | OutputDigestDeltaEvent
        | ToolCallRequestedEvent
        | ResponseTerminalEvent,
        ...,
    ]
    waiting_tool_call_id: str | None = None


class DeterministicFakeChatGptAdapter:
    provider = "chatgpt"
    surface = "deterministic_fake"

    @property
    def capabilities(self) -> ProviderCapabilities:
        supported = CapabilityClaim(
            state=CapabilitySupport.SUPPORTED,
            evidence=CapabilityEvidence.SIMULATED,
        )
        unknown = CapabilityClaim(
            state=CapabilitySupport.UNKNOWN,
            evidence=CapabilityEvidence.NONE,
        )
        return ProviderCapabilities(
            provider=self.provider,
            surface=self.surface,
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

    def start_run(
        self,
        *,
        conversation: ConversationHandle,
        turn: CommittedTurn,
        scenario: FakeChatGptScenario,
    ) -> FakeChatGptPlan:
        if conversation.conversation_id != turn.conversation_id:
            raise ValueError("turn does not belong to the conversation")
        if conversation.provider != self.provider:
            raise ValueError("conversation provider is not ChatGPT")
        if conversation.surface != self.surface:
            raise ValueError("conversation surface is not the deterministic fake")
        if turn.principal.agent_id != conversation.created_by_agent:
            raise ValueError("turn principal does not own the conversation")
        if turn.committed_at < conversation.created_at:
            raise ValueError("turn cannot precede conversation creation")
        if conversation.state.value != "active":
            raise ValueError("conversation is not active")

        provider_conversation_id = conversation.provider_conversation_id or _stable_id(
            "fakeconv_",
            conversation.conversation_id,
            conversation.created_by_agent,
        )
        mapped_conversation = conversation.model_copy(
            update={
                "provider_conversation_id": provider_conversation_id,
                "updated_at": max(conversation.updated_at, turn.committed_at),
            }
        )
        run_id = _stable_id(
            "run_",
            turn.turn_id,
            turn.idempotency_key,
            turn.content_sha256,
        )
        provider_run_id = _stable_id(
            "fakeresp_",
            provider_conversation_id,
            turn.turn_id,
            turn.content_sha256,
        )
        run = ProviderRun(
            run_id=run_id,
            conversation_id=turn.conversation_id,
            turn_id=turn.turn_id,
            trace_id=turn.trace_id,
            idempotency_key=turn.idempotency_key,
            provider=self.provider,
            surface=self.surface,
            started_at=turn.committed_at,
            provider_run_id=provider_run_id,
        )

        started = ResponseStartedEvent(
            event_id=_stable_id("evt_", run_id, "1", "started"),
            run_id=run_id,
            sequence=1,
            observed_at=turn.committed_at,
            provider_event_id=_stable_id("fakeevt_", provider_run_id, "1"),
            provider_response_id=provider_run_id,
        )

        if scenario is FakeChatGptScenario.TOOL_CALL:
            tool_call_id = _stable_id("tool_", run_id, "workspace.list")
            requested = ToolCallRequestedEvent(
                event_id=_stable_id("evt_", run_id, "2", "tool"),
                run_id=run_id,
                sequence=2,
                observed_at=turn.committed_at,
                provider_event_id=_stable_id("fakeevt_", provider_run_id, "2"),
                tool_call_id=tool_call_id,
                provider_tool_call_id=_stable_id("fakecall_", provider_run_id, "workspace.list"),
                tool_name="workspace.list",
                arguments_sha256=_digest_text('{"path":"."}'),
            )
            return FakeChatGptPlan(
                conversation=mapped_conversation,
                run=run,
                provider_events=(started, requested),
                waiting_tool_call_id=tool_call_id,
            )

        if scenario is FakeChatGptScenario.COMPLETED:
            output = OutputDigestDeltaEvent(
                event_id=_stable_id("evt_", run_id, "2", "output"),
                run_id=run_id,
                sequence=2,
                observed_at=turn.committed_at,
                provider_event_id=_stable_id("fakeevt_", provider_run_id, "2"),
                delta_sha256=_digest_text("fake completed output"),
                utf8_bytes=len("fake completed output".encode("utf-8")),
            )
            terminal = self._terminal_event(
                run=run,
                observed_at=turn.committed_at,
                sequence=3,
                status=ProviderResponseStatus.COMPLETED,
            )
            events = (started, output, terminal)
        else:
            status = ProviderResponseStatus(scenario.value)
            terminal = self._terminal_event(
                run=run,
                observed_at=turn.committed_at,
                sequence=2,
                status=status,
            )
            events = (started, terminal)

        return FakeChatGptPlan(
            conversation=mapped_conversation,
            run=run,
            provider_events=events,
        )

    def continue_after_tool(
        self,
        *,
        plan: FakeChatGptPlan,
        next_sequence: int,
        tool_call_id: str,
        observed_at: datetime,
    ) -> tuple[OutputDigestDeltaEvent, ResponseTerminalEvent]:
        if plan.waiting_tool_call_id is None:
            raise ValueError("plan is not waiting for a tool result")
        if tool_call_id != plan.waiting_tool_call_id:
            raise ValueError("tool_call_id does not match the pending fake call")
        if next_sequence < 1:
            raise ValueError("next_sequence must be positive")

        output_text = f"fake tool continuation for {tool_call_id}"
        output = OutputDigestDeltaEvent(
            event_id=_stable_id("evt_", plan.run.run_id, str(next_sequence), "tool_output"),
            run_id=plan.run.run_id,
            sequence=next_sequence,
            observed_at=observed_at,
            provider_event_id=_stable_id(
                "fakeevt_",
                str(plan.run.provider_run_id),
                str(next_sequence),
            ),
            delta_sha256=_digest_text(output_text),
            utf8_bytes=len(output_text.encode("utf-8")),
        )
        terminal = self._terminal_event(
            run=plan.run,
            observed_at=observed_at,
            sequence=next_sequence + 1,
            status=ProviderResponseStatus.COMPLETED,
        )
        return output, terminal

    @staticmethod
    def _terminal_event(
        *,
        run: ProviderRun,
        observed_at: datetime,
        sequence: int,
        status: ProviderResponseStatus,
    ) -> ResponseTerminalEvent:
        error_code = None
        if status is ProviderResponseStatus.FAILED:
            error_code = "FAKE_PROVIDER_FAILURE"
        elif status is ProviderResponseStatus.CANCELLED:
            error_code = "FAKE_CANCELLED"
        elif status is ProviderResponseStatus.INCOMPLETE:
            error_code = "FAKE_INCOMPLETE"

        return ResponseTerminalEvent(
            event_id=_stable_id("evt_", run.run_id, str(sequence), status.value),
            run_id=run.run_id,
            sequence=sequence,
            observed_at=observed_at,
            provider_event_id=_stable_id(
                "fakeevt_",
                str(run.provider_run_id),
                str(sequence),
            ),
            status=status,
            error_code=error_code,
        )


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "\x00".join(parts).encode("utf-8")
    return prefix + sha256(payload).hexdigest()[:24]


def _digest_text(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()
