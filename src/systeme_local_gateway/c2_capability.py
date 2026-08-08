from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from systeme_local_gateway.c0_probe import C0_SHA256_PATTERN

C2_BASE_COMMIT = "2aee36fdfa3d20c23acdc75eb3348bc54536ef4f"
C2_EXPECTED_BRANCH = "interop/chatgpt-web-capability-gating-c2"
C2_REVIEWED_AT = datetime(2026, 8, 7, 1, 40, 0, tzinfo=timezone.utc)
C2_REVALIDATE_AFTER = C2_REVIEWED_AT + timedelta(days=14)

_OFFICIAL_HOST_RE = re.compile(r"^https://(?:developers\.openai\.com|learn\.chatgpt\.com)/")
_SOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C2 timestamps must be timezone-aware")
    return value.astimezone(UTC)


class WebProviderId(StrEnum):
    """Closed provider identifiers implemented by the current capability registry."""

    CHATGPT = "chatgpt"


class WebSurfaceClass(StrEnum):
    """Provider-neutral surface classes without cross-provider capability claims."""

    CONVERSATIONAL_CHAT = "conversational_chat"


class OfficialCapabilityId(StrEnum):
    CUSTOM_OR_LOCAL_MCP_TOOL_INVOCATION = "custom_or_local_mcp_tool_invocation"


class OfficialCapabilityState(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNOBSERVABLE = "unobservable"


class C2LiveAction(StrEnum):
    RUNTIME_KEY_CREATION = "runtime_key_creation"
    TUNNEL_START = "tunnel_start"
    PLUGIN_CREATION = "plugin_creation"
    BROWSER_TEST = "browser_test"


class C2FinalStatus(StrEnum):
    COMPLETE = "COMPLETE_CHATGPT_CHAT_CAPABILITY_GATE_VERIFIED"
    NO_OFFICIAL_CHAT_TOOL_INTERFACE = "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"
    OFFICIAL_EVIDENCE_DRIFT = "BLOCKED_BY_OFFICIAL_EVIDENCE_DRIFT"
    SECURITY_INVARIANT = "BLOCKED_BY_SECURITY_INVARIANT"
    TEST_FAILURE = "BLOCKED_BY_TEST_FAILURE"


class C2ReasonCode(StrEnum):
    OFFICIAL_CAPABILITY_SUPPORTED = "official_capability_supported"
    OFFICIAL_CAPABILITY_UNSUPPORTED = "official_capability_unsupported"
    OFFICIAL_CAPABILITY_UNOBSERVABLE = "official_capability_unobservable"
    OFFICIAL_EVIDENCE_STALE = "official_evidence_stale"
    SECURITY_INVARIANT_FAILED = "security_invariant_failed"


class ProviderSurfaceReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_id: WebProviderId
    native_surface: Literal["chat"]
    surface_class: WebSurfaceClass


class OfficialSourceReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    title: str = Field(min_length=1, max_length=160)
    url: str = Field(min_length=1, max_length=512)
    consulted_at: datetime
    canonical_summary: str = Field(min_length=1, max_length=1_200)
    summary_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    revalidate_after: datetime

    _aware_consulted_at = field_validator("consulted_at")(_require_aware)
    _aware_revalidate_after = field_validator("revalidate_after")(_require_aware)

    @model_validator(mode="after")
    def validate_reference(self) -> OfficialSourceReference:
        if _SOURCE_ID_RE.fullmatch(self.source_id) is None:
            raise ValueError("C2 official source ID is invalid")
        if _OFFICIAL_HOST_RE.match(self.url) is None:
            raise ValueError("C2 official sources must use reviewed OpenAI documentation hosts")
        expected = hashlib.sha256(self.canonical_summary.encode("utf-8")).hexdigest()
        if self.summary_sha256 != expected:
            raise ValueError("C2 official-source canonical summary digest mismatch")
        if self.revalidate_after <= self.consulted_at:
            raise ValueError("C2 official source must have a future revalidation deadline")
        if self.revalidate_after - self.consulted_at > timedelta(days=14):
            raise ValueError("C2 official source revalidation window exceeds 14 days")
        return self


class OfficialCapabilityProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    profile_id: Literal["chatgpt_chat_c2_20260727"]
    surface: ProviderSurfaceReference
    capability: OfficialCapabilityId
    state: OfficialCapabilityState
    canonical_conclusion: str = Field(min_length=1, max_length=1_200)
    sources: tuple[OfficialSourceReference, ...]
    reviewed_at: datetime
    revalidate_after: datetime
    profile_sha256: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_reviewed_at = field_validator("reviewed_at")(_require_aware)
    _aware_revalidate_after = field_validator("revalidate_after")(_require_aware)

    @model_validator(mode="after")
    def validate_profile(self) -> OfficialCapabilityProfile:
        if self.surface != ProviderSurfaceReference(
            provider_id=WebProviderId.CHATGPT,
            native_surface="chat",
            surface_class=WebSurfaceClass.CONVERSATIONAL_CHAT,
        ):
            raise ValueError("C2 implements only the reviewed ChatGPT Chat surface")
        if self.capability is not OfficialCapabilityId.CUSTOM_OR_LOCAL_MCP_TOOL_INVOCATION:
            raise ValueError("C2 profile contains an unreviewed capability")
        if self.revalidate_after <= self.reviewed_at:
            raise ValueError("C2 profile must have a future revalidation deadline")
        if self.revalidate_after - self.reviewed_at > timedelta(days=14):
            raise ValueError("C2 profile revalidation window exceeds 14 days")

        ids = tuple(source.source_id for source in self.sources)
        if len(ids) < 3:
            raise ValueError("C2 profile requires at least three corroborating official sources")
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ValueError("C2 official sources must be sorted and unique")
        for source in self.sources:
            if source.consulted_at != self.reviewed_at:
                raise ValueError("C2 source consultation times must match the profile review")
            if source.revalidate_after != self.revalidate_after:
                raise ValueError("C2 source deadlines must match the profile deadline")

        payload = self.model_dump(mode="json", exclude={"profile_sha256"})
        if self.profile_sha256 != canonical_sha256(payload):
            raise ValueError("C2 official capability profile digest mismatch")
        return self


class C2PreflightDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    profile_id: str = Field(min_length=1, max_length=128)
    profile_sha256: str | None = Field(default=None, pattern=C0_SHA256_PATTERN)
    capability_state: OfficialCapabilityState | None
    evaluated_at: datetime
    final_status: C2FinalStatus
    reason_code: C2ReasonCode
    live_actions_allowed: bool
    action_decisions: dict[C2LiveAction, bool]

    _aware_evaluated_at = field_validator("evaluated_at")(_require_aware)

    @model_validator(mode="after")
    def validate_decision(self) -> C2PreflightDecision:
        expected_actions = set(C2LiveAction)
        if set(self.action_decisions) != expected_actions:
            raise ValueError("C2 preflight must decide every protected live action")
        decision_values = set(self.action_decisions.values())
        if self.live_actions_allowed:
            if decision_values != {True}:
                raise ValueError("C2 allowed preflight must allow every protected action")
            if self.final_status is not C2FinalStatus.COMPLETE:
                raise ValueError("C2 allowed preflight requires the complete status")
            if self.capability_state is not OfficialCapabilityState.SUPPORTED:
                raise ValueError("C2 allowed preflight requires official support")
        else:
            if decision_values != {False}:
                raise ValueError("C2 blocked preflight must deny every protected action")
            if self.final_status is C2FinalStatus.COMPLETE:
                raise ValueError("C2 blocked preflight cannot use the complete status")
        return self


def commit_official_source_reference(
    *,
    source_id: str,
    title: str,
    url: str,
    canonical_summary: str,
) -> OfficialSourceReference:
    return OfficialSourceReference(
        source_id=source_id,
        title=title,
        url=url,
        consulted_at=C2_REVIEWED_AT,
        canonical_summary=canonical_summary,
        summary_sha256=hashlib.sha256(canonical_summary.encode("utf-8")).hexdigest(),
        revalidate_after=C2_REVALIDATE_AFTER,
    )


def build_current_c2_official_capability_profile() -> OfficialCapabilityProfile:
    sources = tuple(
        sorted(
            (
                commit_official_source_reference(
                    source_id="plugin_connection_route",
                    title="Connect and test your plugin",
                    url="https://developers.openai.com/plugins/deploy/connect-chatgpt",
                    canonical_summary=(
                        "The official MCP test flow registers a server in ChatGPT developer mode "
                        "through Settings > Plugins, then selects that connection in a new "
                        "conversation. This route is governed by the Plugins surface contract; "
                        "the page does not independently establish availability in Chat."
                    ),
                ),
                commit_official_source_reference(
                    source_id="plugin_packaging_surface",
                    title="Package your plugin",
                    url="https://developers.openai.com/plugins/build/plugins",
                    canonical_summary=(
                        "The official local-plugin packaging flow assigns plugin creation to "
                        "ChatGPT Work or Codex and warns that local and repository marketplace "
                        "availability varies by surface. It does not establish a custom MCP "
                        "invocation path for Chat."
                    ),
                ),
                commit_official_source_reference(
                    source_id="plugin_surface_availability",
                    title="Plugins",
                    url="https://learn.chatgpt.com/docs/plugins",
                    canonical_summary=(
                        "The official Plugins overview states that Plugins are available with "
                        "ChatGPT Work on web or desktop and are not available in Chat. Because "
                        "Plugins can include MCP servers and add MCP tools, this explicitly "
                        "excludes the reviewed Plugin-based MCP path from Chat."
                    ),
                ),
                commit_official_source_reference(
                    source_id="secure_mcp_tunnel_route",
                    title="Secure MCP Tunnel",
                    url="https://developers.openai.com/api/docs/guides/secure-mcp-tunnels",
                    canonical_summary=(
                        "Secure MCP Tunnel is a transport for supported OpenAI products. Its "
                        "ChatGPT setup creates a developer-mode app in Settings > Plugins. "
                        "Transport support therefore does not override the separate official "
                        "statement that Plugins are unavailable in Chat."
                    ),
                ),
            ),
            key=lambda item: item.source_id,
        )
    )
    payload: dict[str, Any] = {
        "version": "1",
        "profile_id": "chatgpt_chat_c2_20260727",
        "surface": {
            "provider_id": WebProviderId.CHATGPT.value,
            "native_surface": "chat",
            "surface_class": WebSurfaceClass.CONVERSATIONAL_CHAT.value,
        },
        "capability": OfficialCapabilityId.CUSTOM_OR_LOCAL_MCP_TOOL_INVOCATION.value,
        "state": OfficialCapabilityState.UNSUPPORTED.value,
        "canonical_conclusion": (
            "No reviewed official OpenAI interface permits ChatGPT Chat to invoke a custom or "
            "local MCP tool without switching to ChatGPT Work. The only documented ChatGPT "
            "registration and invocation route is Plugin-based, and Plugins are explicitly "
            "unavailable in Chat."
        ),
        "sources": [source.model_dump(mode="json") for source in sources],
        "reviewed_at": C2_REVIEWED_AT.isoformat().replace("+00:00", "Z"),
        "revalidate_after": C2_REVALIDATE_AFTER.isoformat().replace("+00:00", "Z"),
    }
    return OfficialCapabilityProfile(
        **payload,
        profile_sha256=canonical_sha256(payload),
    )


def _all_action_decisions(value: bool) -> dict[C2LiveAction, bool]:
    return {action: value for action in C2LiveAction}


def evaluate_c2_preflight(
    profile: OfficialCapabilityProfile,
    *,
    evaluated_at: datetime,
) -> C2PreflightDecision:
    evaluated = _require_aware(evaluated_at)
    profile = OfficialCapabilityProfile.model_validate(profile.model_dump(mode="python"))

    if evaluated < profile.reviewed_at:
        return fail_closed_security_decision(
            evaluated_at=evaluated,
            reason_code=C2ReasonCode.SECURITY_INVARIANT_FAILED,
            profile_id=profile.profile_id,
            profile_sha256=profile.profile_sha256,
            capability_state=profile.state,
        )
    if evaluated >= profile.revalidate_after:
        return C2PreflightDecision(
            version="1",
            profile_id=profile.profile_id,
            profile_sha256=profile.profile_sha256,
            capability_state=profile.state,
            evaluated_at=evaluated,
            final_status=C2FinalStatus.OFFICIAL_EVIDENCE_DRIFT,
            reason_code=C2ReasonCode.OFFICIAL_EVIDENCE_STALE,
            live_actions_allowed=False,
            action_decisions=_all_action_decisions(False),
        )
    if profile.state is OfficialCapabilityState.UNSUPPORTED:
        return C2PreflightDecision(
            version="1",
            profile_id=profile.profile_id,
            profile_sha256=profile.profile_sha256,
            capability_state=profile.state,
            evaluated_at=evaluated,
            final_status=C2FinalStatus.NO_OFFICIAL_CHAT_TOOL_INTERFACE,
            reason_code=C2ReasonCode.OFFICIAL_CAPABILITY_UNSUPPORTED,
            live_actions_allowed=False,
            action_decisions=_all_action_decisions(False),
        )
    if profile.state is OfficialCapabilityState.UNOBSERVABLE:
        return C2PreflightDecision(
            version="1",
            profile_id=profile.profile_id,
            profile_sha256=profile.profile_sha256,
            capability_state=profile.state,
            evaluated_at=evaluated,
            final_status=C2FinalStatus.OFFICIAL_EVIDENCE_DRIFT,
            reason_code=C2ReasonCode.OFFICIAL_CAPABILITY_UNOBSERVABLE,
            live_actions_allowed=False,
            action_decisions=_all_action_decisions(False),
        )
    return C2PreflightDecision(
        version="1",
        profile_id=profile.profile_id,
        profile_sha256=profile.profile_sha256,
        capability_state=profile.state,
        evaluated_at=evaluated,
        final_status=C2FinalStatus.COMPLETE,
        reason_code=C2ReasonCode.OFFICIAL_CAPABILITY_SUPPORTED,
        live_actions_allowed=True,
        action_decisions=_all_action_decisions(True),
    )


def fail_closed_security_decision(
    *,
    evaluated_at: datetime,
    reason_code: C2ReasonCode = C2ReasonCode.SECURITY_INVARIANT_FAILED,
    profile_id: str = "invalid_or_unverified_profile",
    profile_sha256: str | None = None,
    capability_state: OfficialCapabilityState | None = None,
) -> C2PreflightDecision:
    return C2PreflightDecision(
        version="1",
        profile_id=profile_id,
        profile_sha256=profile_sha256,
        capability_state=capability_state,
        evaluated_at=_require_aware(evaluated_at),
        final_status=C2FinalStatus.SECURITY_INVARIANT,
        reason_code=reason_code,
        live_actions_allowed=False,
        action_decisions=_all_action_decisions(False),
    )


def load_official_capability_profile(path: Path) -> OfficialCapabilityProfile:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return OfficialCapabilityProfile.model_validate(raw)


def _parse_timestamp(value: str | None) -> datetime:
    if value is None:
        return datetime.now(tz=timezone.utc)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return _require_aware(datetime.fromisoformat(normalized))


def _json_output(value: BaseModel) -> str:
    return json.dumps(
        value.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("official-profile")

    verify = subparsers.add_parser("verify-profile")
    verify.add_argument("--profile", type=Path, required=True)

    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--profile", type=Path, required=True)
    preflight.add_argument("--as-of")

    require_action = subparsers.add_parser("require-action")
    require_action.add_argument("--profile", type=Path, required=True)
    require_action.add_argument("--action", choices=tuple(action.value for action in C2LiveAction))
    require_action.add_argument("--as-of")

    args = parser.parse_args(argv)
    if args.command == "official-profile":
        print(_json_output(build_current_c2_official_capability_profile()))
        return 0

    evaluated_at = _parse_timestamp(getattr(args, "as_of", None))
    try:
        profile = load_official_capability_profile(args.profile)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        print(_json_output(fail_closed_security_decision(evaluated_at=evaluated_at)))
        return 4

    expected = build_current_c2_official_capability_profile()
    if profile.model_dump(mode="json") != expected.model_dump(mode="json"):
        print(_json_output(fail_closed_security_decision(evaluated_at=evaluated_at)))
        return 4

    if args.command == "verify-profile":
        print(_json_output(evaluate_c2_preflight(profile, evaluated_at=evaluated_at)))
        return 0

    decision = evaluate_c2_preflight(profile, evaluated_at=evaluated_at)
    print(_json_output(decision))
    if args.command == "require-action":
        action = C2LiveAction(args.action)
        return 0 if decision.action_decisions[action] else 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
