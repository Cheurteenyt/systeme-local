from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from systeme_local_gateway.c0_probe import C0_SHA256_PATTERN

C3_BASE_COMMIT = "cf05e963ba30539f9b2c9ec2f5f71326cbba8399"
C3_EXPECTED_BRANCH = "interop/provider-capability-revalidation-c3"
C3_REVIEWED_AT = datetime(2026, 8, 7, 11, 55, 0, tzinfo=UTC)
C3_REVALIDATE_AFTER = C3_REVIEWED_AT + timedelta(days=14)
C3_REVALIDATION_WARNING_DAYS = 7
C3_PROFILE_ID = "chatgpt_chat_c3_20260727"
C3_PROFILE_PATH = "governance/c3-chatgpt-chat-capability-profile.json"

_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_PROFILE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{7,127}$")
_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_PROFILE_PATH_RE = re.compile(r"^governance/[a-z0-9][a-z0-9._/-]{1,190}\.json$")


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


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C3 timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _parse_timestamp(value: str | None) -> datetime:
    if value is None:
        return datetime.now(tz=UTC)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return _require_aware(datetime.fromisoformat(normalized))


def _validated_https_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as error:
        raise ValueError("C3 official source URL is malformed") from error
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or port is not None
        or parts.query
        or parts.fragment
        or not parts.path.startswith("/")
        or parts.netloc != parts.hostname
    ):
        raise ValueError("C3 official sources require canonical HTTPS URLs")
    if parts.hostname != parts.hostname.lower() or _HOST_RE.fullmatch(parts.hostname) is None:
        raise ValueError("C3 official source hostname is invalid")
    return parts.hostname


class WebProviderId(StrEnum):
    """Closed providers with reviewed C3 adapters."""

    CHATGPT = "chatgpt"


class WebSurfaceClass(StrEnum):
    """Comparable interaction shapes that do not imply capability portability."""

    CONVERSATIONAL_CHAT = "conversational_chat"


class OfficialCapabilityId(StrEnum):
    CUSTOM_OR_LOCAL_MCP_TOOL_INVOCATION = "custom_or_local_mcp_tool_invocation"


class OfficialSupportState(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNOBSERVABLE = "unobservable"


class EvidenceReviewerState(StrEnum):
    REVIEWED = "reviewed"
    CANDIDATE = "candidate"


class EvidenceLifecycleState(StrEnum):
    CURRENT = "current"
    REVALIDATION_DUE = "revalidation_due"
    EXPIRED = "expired"
    SOURCE_DRIFT = "source_drift"
    INVALID = "invalid"


class CandidateComparisonState(StrEnum):
    UNCHANGED = "unchanged"
    SOURCE_DRIFT = "source_drift"
    INVALID = "invalid"


class C3ProtectedAction(StrEnum):
    RUNTIME_KEY_CREATION = "runtime_key_creation"
    TUNNEL_START = "tunnel_start"
    PLUGIN_CREATION = "plugin_creation"
    BROWSER_TEST = "browser_test"
    CHATGPT_ACTION = "chatgpt_action"


class C3GateStatus(StrEnum):
    READY = "READY_FOR_SEPARATE_BOUNDED_AUTHORIZATION"
    NO_OFFICIAL_CHAT_TOOL_INTERFACE = "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"
    OFFICIAL_EVIDENCE_AMBIGUOUS = "BLOCKED_BY_OFFICIAL_EVIDENCE_AMBIGUOUS"
    REVALIDATION_DUE = "BLOCKED_BY_OFFICIAL_EVIDENCE_REVALIDATION_DUE"
    EXPIRED = "BLOCKED_BY_OFFICIAL_EVIDENCE_EXPIRED"
    SOURCE_DRIFT = "BLOCKED_BY_OFFICIAL_EVIDENCE_SOURCE_DRIFT"
    SECURITY_INVARIANT = "BLOCKED_BY_SECURITY_INVARIANT"


class C3ReasonCode(StrEnum):
    OFFICIAL_CAPABILITY_SUPPORTED = "official_capability_supported"
    OFFICIAL_CAPABILITY_UNSUPPORTED = "official_capability_unsupported"
    OFFICIAL_CAPABILITY_UNOBSERVABLE = "official_capability_unobservable"
    OFFICIAL_EVIDENCE_REVALIDATION_DUE = "official_evidence_revalidation_due"
    OFFICIAL_EVIDENCE_EXPIRED = "official_evidence_expired"
    OFFICIAL_EVIDENCE_SOURCE_DRIFT = "official_evidence_source_drift"
    SECURITY_INVARIANT_FAILED = "security_invariant_failed"


class CapabilityIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_id: WebProviderId
    native_surface: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    surface_class: WebSurfaceClass
    capability: OfficialCapabilityId

    @property
    def key(self) -> str:
        return (
            f"{self.provider_id.value}:{self.native_surface}:"
            f"{self.surface_class.value}:{self.capability.value}"
        )


class SurfaceMapping(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    native_surface: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    surface_class: WebSurfaceClass


class ProviderAdapter(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_id: WebProviderId
    allowed_official_hosts: tuple[str, ...]
    surface_mappings: tuple[SurfaceMapping, ...]
    capabilities: tuple[OfficialCapabilityId, ...]

    @model_validator(mode="after")
    def validate_adapter(self) -> ProviderAdapter:
        hosts = self.allowed_official_hosts
        if not hosts or hosts != tuple(sorted(set(hosts))):
            raise ValueError("C3 adapter hosts must be non-empty, sorted, and unique")
        for host in hosts:
            if host != host.lower() or _HOST_RE.fullmatch(host) is None:
                raise ValueError("C3 adapter contains an invalid official host")

        mapping_keys = tuple(
            (mapping.native_surface, mapping.surface_class.value)
            for mapping in self.surface_mappings
        )
        if not mapping_keys or mapping_keys != tuple(sorted(set(mapping_keys))):
            raise ValueError("C3 adapter surface mappings must be sorted and unique")

        capability_values = tuple(item.value for item in self.capabilities)
        if not capability_values or capability_values != tuple(sorted(set(capability_values))):
            raise ValueError("C3 adapter capabilities must be sorted and unique")
        return self


class OfficialSourceClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    title: str = Field(min_length=1, max_length=160)
    url: str = Field(min_length=1, max_length=512)
    canonical_claim: str = Field(min_length=1, max_length=1_200)
    claim_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    consulted_at: datetime
    revalidate_after: datetime

    _aware_consulted_at = field_validator("consulted_at")(_require_aware)
    _aware_revalidate_after = field_validator("revalidate_after")(_require_aware)

    @model_validator(mode="after")
    def validate_claim(self) -> OfficialSourceClaim:
        if _IDENTIFIER_RE.fullmatch(self.source_id) is None:
            raise ValueError("C3 official source ID is invalid")
        _validated_https_url(self.url)
        if self.claim_sha256 != _text_sha256(self.canonical_claim):
            raise ValueError("C3 official-source canonical claim digest mismatch")
        if self.revalidate_after <= self.consulted_at:
            raise ValueError("C3 official source deadline must follow consultation")
        if self.revalidate_after - self.consulted_at > timedelta(days=14):
            raise ValueError("C3 official source revalidation window exceeds 14 days")
        return self


class OfficialCapabilityProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["2"]
    profile_id: str = Field(pattern=r"^[a-z][a-z0-9_]{7,127}$")
    identity: CapabilityIdentity
    support_state: OfficialSupportState
    reviewer_state: EvidenceReviewerState
    canonical_conclusion: str = Field(min_length=1, max_length=1_200)
    conclusion_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    sources: tuple[OfficialSourceClaim, ...]
    reviewed_at: datetime
    revalidate_after: datetime
    revalidation_warning_days: int = Field(ge=0, le=13)
    evidence_sha256: str = Field(pattern=C0_SHA256_PATTERN)
    profile_sha256: str = Field(pattern=C0_SHA256_PATTERN)

    _aware_reviewed_at = field_validator("reviewed_at")(_require_aware)
    _aware_revalidate_after = field_validator("revalidate_after")(_require_aware)

    def evidence_payload(self) -> dict[str, Any]:
        return {
            "identity": self.identity.model_dump(mode="json"),
            "support_state": self.support_state.value,
            "canonical_conclusion": self.canonical_conclusion,
            "conclusion_sha256": self.conclusion_sha256,
            "sources": [
                {
                    "source_id": source.source_id,
                    "title": source.title,
                    "url": source.url,
                    "canonical_claim": source.canonical_claim,
                    "claim_sha256": source.claim_sha256,
                }
                for source in self.sources
            ],
        }

    @model_validator(mode="after")
    def validate_profile(self) -> OfficialCapabilityProfile:
        if _PROFILE_ID_RE.fullmatch(self.profile_id) is None:
            raise ValueError("C3 profile ID is invalid")
        if self.revalidate_after <= self.reviewed_at:
            raise ValueError("C3 profile deadline must follow review")
        if self.revalidate_after - self.reviewed_at > timedelta(days=14):
            raise ValueError("C3 profile revalidation window exceeds 14 days")
        if self.conclusion_sha256 != _text_sha256(self.canonical_conclusion):
            raise ValueError("C3 canonical conclusion digest mismatch")

        source_ids = tuple(source.source_id for source in self.sources)
        source_urls = tuple(source.url for source in self.sources)
        if len(source_ids) < 3:
            raise ValueError("C3 profile requires at least three official sources")
        if source_ids != tuple(sorted(source_ids)) or len(source_ids) != len(set(source_ids)):
            raise ValueError("C3 official source IDs must be sorted and unique")
        if len(source_urls) != len(set(source_urls)):
            raise ValueError("C3 official source URLs must be unique")
        for source in self.sources:
            if source.consulted_at != self.reviewed_at:
                raise ValueError("C3 source consultation must match profile review")
            if source.revalidate_after != self.revalidate_after:
                raise ValueError("C3 source deadline must match profile deadline")

        if self.evidence_sha256 != canonical_sha256(self.evidence_payload()):
            raise ValueError("C3 evidence-set digest mismatch")
        profile_payload = self.model_dump(mode="json", exclude={"profile_sha256"})
        if self.profile_sha256 != canonical_sha256(profile_payload):
            raise ValueError("C3 official capability profile digest mismatch")
        return self


class RegistryProfileEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_id: str = Field(pattern=r"^[a-z][a-z0-9_]{7,127}$")
    profile_path: str = Field(min_length=1, max_length=220)
    identity: CapabilityIdentity
    expected_profile_sha256: str = Field(pattern=C0_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_entry(self) -> RegistryProfileEntry:
        if _PROFILE_ID_RE.fullmatch(self.profile_id) is None:
            raise ValueError("C3 registry profile ID is invalid")
        if _PROFILE_PATH_RE.fullmatch(self.profile_path) is None:
            raise ValueError("C3 registry profile path is invalid")
        path = PurePosixPath(self.profile_path)
        if path.is_absolute() or ".." in path.parts or "\\" in self.profile_path:
            raise ValueError("C3 registry profile path escapes the repository")
        return self


class CapabilityRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    adapters: tuple[ProviderAdapter, ...]
    profiles: tuple[RegistryProfileEntry, ...]
    registry_sha256: str = Field(pattern=C0_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_registry(self) -> CapabilityRegistry:
        adapter_ids = tuple(adapter.provider_id.value for adapter in self.adapters)
        if adapter_ids != (WebProviderId.CHATGPT.value,):
            raise ValueError("C3 registers exactly one reviewed ChatGPT adapter")

        profile_ids = tuple(profile.profile_id for profile in self.profiles)
        identity_keys = tuple(profile.identity.key for profile in self.profiles)
        if not profile_ids or profile_ids != tuple(sorted(set(profile_ids))):
            raise ValueError("C3 registry profile IDs must be sorted and unique")
        if len(identity_keys) != len(set(identity_keys)):
            raise ValueError("C3 registry capability identities must be unique")

        adapters = {adapter.provider_id: adapter for adapter in self.adapters}
        for profile in self.profiles:
            adapter = adapters.get(profile.identity.provider_id)
            if adapter is None:
                raise ValueError("C3 registry profile has no provider adapter")
            _validate_identity_against_adapter(profile.identity, adapter)

        payload = self.model_dump(mode="json", exclude={"registry_sha256"})
        if self.registry_sha256 != canonical_sha256(payload):
            raise ValueError("C3 capability registry digest mismatch")
        return self


class C3GateDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    registry_sha256: str | None = Field(default=None, pattern=C0_SHA256_PATTERN)
    profile_id: str = Field(min_length=1, max_length=128)
    profile_sha256: str | None = Field(default=None, pattern=C0_SHA256_PATTERN)
    evidence_sha256: str | None = Field(default=None, pattern=C0_SHA256_PATTERN)
    identity: CapabilityIdentity | None
    support_state: OfficialSupportState | None
    reviewer_state: EvidenceReviewerState | None
    lifecycle_state: EvidenceLifecycleState
    evaluated_at: datetime
    final_status: C3GateStatus
    reason_code: C3ReasonCode
    live_actions_allowed: bool
    action_decisions: dict[C3ProtectedAction, bool]

    _aware_evaluated_at = field_validator("evaluated_at")(_require_aware)

    @model_validator(mode="after")
    def validate_decision(self) -> C3GateDecision:
        if set(self.action_decisions) != set(C3ProtectedAction):
            raise ValueError("C3 gate must decide every protected action")
        values = set(self.action_decisions.values())
        if self.live_actions_allowed:
            if values != {True}:
                raise ValueError("C3 allowed gate must allow every protected action")
            if self.final_status is not C3GateStatus.READY:
                raise ValueError("C3 allowed gate requires the ready status")
            if self.support_state is not OfficialSupportState.SUPPORTED:
                raise ValueError("C3 allowed gate requires official support")
            if self.lifecycle_state is not EvidenceLifecycleState.CURRENT:
                raise ValueError("C3 allowed gate requires current evidence")
            if self.reviewer_state is not EvidenceReviewerState.REVIEWED:
                raise ValueError("C3 allowed gate requires reviewed evidence")
        else:
            if values != {False}:
                raise ValueError("C3 blocked gate must deny every protected action")
            if self.final_status is C3GateStatus.READY:
                raise ValueError("C3 blocked gate cannot use the ready status")
        return self


class CandidateComparison(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    active_profile_id: str
    active_profile_sha256: str | None = Field(default=None, pattern=C0_SHA256_PATTERN)
    candidate_profile_sha256: str | None = Field(default=None, pattern=C0_SHA256_PATTERN)
    evaluated_at: datetime
    comparison_state: CandidateComparisonState
    changed_components: tuple[str, ...]
    candidate_can_change_gate: Literal[False]
    requires_independent_review: bool
    action_decisions: dict[C3ProtectedAction, bool]

    _aware_evaluated_at = field_validator("evaluated_at")(_require_aware)

    @model_validator(mode="after")
    def validate_comparison(self) -> CandidateComparison:
        if set(self.action_decisions) != set(C3ProtectedAction):
            raise ValueError("C3 comparison must decide every protected action")
        if set(self.action_decisions.values()) != {False}:
            raise ValueError("C3 candidates must deny every protected action")
        if self.comparison_state is CandidateComparisonState.UNCHANGED:
            if self.changed_components or self.requires_independent_review:
                raise ValueError("C3 unchanged comparison cannot report drift")
        else:
            if not self.requires_independent_review:
                raise ValueError("C3 non-identical candidates require independent review")
        return self


class RevalidationGuidance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    profile_id: str
    official_source_urls: tuple[str, ...]
    acquisition_boundary: tuple[str, ...]
    review_steps: tuple[str, ...]
    forbidden_actions: tuple[str, ...]


class CandidateSourceDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    title: str = Field(min_length=1, max_length=160)
    url: str = Field(min_length=1, max_length=512)
    canonical_claim: str = Field(min_length=1, max_length=1_200)

    @model_validator(mode="after")
    def validate_draft_source(self) -> CandidateSourceDraft:
        if _IDENTIFIER_RE.fullmatch(self.source_id) is None:
            raise ValueError("C3 candidate source ID is invalid")
        _validated_https_url(self.url)
        return self


class CandidateProfileDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    profile_id: str = Field(pattern=r"^[a-z][a-z0-9_]{7,127}$")
    identity: CapabilityIdentity
    support_state: OfficialSupportState
    canonical_conclusion: str = Field(min_length=1, max_length=1_200)
    sources: tuple[CandidateSourceDraft, ...]
    reviewed_at: datetime
    revalidate_after: datetime
    revalidation_warning_days: int = Field(ge=0, le=13)

    _aware_reviewed_at = field_validator("reviewed_at")(_require_aware)
    _aware_revalidate_after = field_validator("revalidate_after")(_require_aware)

    @model_validator(mode="after")
    def validate_draft(self) -> CandidateProfileDraft:
        if _PROFILE_ID_RE.fullmatch(self.profile_id) is None:
            raise ValueError("C3 candidate profile ID is invalid")
        if self.revalidate_after <= self.reviewed_at:
            raise ValueError("C3 candidate deadline must follow review")
        if self.revalidate_after - self.reviewed_at > timedelta(days=14):
            raise ValueError("C3 candidate revalidation window exceeds 14 days")
        source_ids = tuple(source.source_id for source in self.sources)
        source_urls = tuple(source.url for source in self.sources)
        if len(source_ids) < 3:
            raise ValueError("C3 candidate requires at least three official sources")
        if source_ids != tuple(sorted(source_ids)) or len(source_ids) != len(set(source_ids)):
            raise ValueError("C3 candidate source IDs must be sorted and unique")
        if len(source_urls) != len(set(source_urls)):
            raise ValueError("C3 candidate source URLs must be unique")
        return self


class _BundleError(ValueError):
    def __init__(self, message: str, *, lifecycle: EvidenceLifecycleState) -> None:
        super().__init__(message)
        self.lifecycle = lifecycle


def _validate_identity_against_adapter(
    identity: CapabilityIdentity,
    adapter: ProviderAdapter,
) -> None:
    if identity.provider_id is not adapter.provider_id:
        raise ValueError("C3 identity provider does not match its adapter")
    mapping = SurfaceMapping(
        native_surface=identity.native_surface,
        surface_class=identity.surface_class,
    )
    if mapping not in adapter.surface_mappings:
        raise ValueError("C3 identity uses an unreviewed provider surface")
    if identity.capability not in adapter.capabilities:
        raise ValueError("C3 identity uses an unreviewed provider capability")


def _validate_profile_against_adapter(
    profile: OfficialCapabilityProfile,
    adapter: ProviderAdapter,
) -> None:
    _validate_identity_against_adapter(profile.identity, adapter)
    for source in profile.sources:
        host = _validated_https_url(source.url)
        if host not in adapter.allowed_official_hosts:
            raise ValueError("C3 source host is not approved by the provider adapter")


def _build_source(
    *,
    source_id: str,
    title: str,
    url: str,
    canonical_claim: str,
    consulted_at: datetime,
    revalidate_after: datetime,
) -> OfficialSourceClaim:
    return OfficialSourceClaim(
        source_id=source_id,
        title=title,
        url=url,
        canonical_claim=canonical_claim,
        claim_sha256=_text_sha256(canonical_claim),
        consulted_at=consulted_at,
        revalidate_after=revalidate_after,
    )


def _commit_profile(
    *,
    profile_id: str,
    identity: CapabilityIdentity,
    support_state: OfficialSupportState,
    reviewer_state: EvidenceReviewerState,
    canonical_conclusion: str,
    sources: tuple[OfficialSourceClaim, ...],
    reviewed_at: datetime,
    revalidate_after: datetime,
    revalidation_warning_days: int,
) -> OfficialCapabilityProfile:
    partial: dict[str, Any] = {
        "version": "2",
        "profile_id": profile_id,
        "identity": identity.model_dump(mode="json"),
        "support_state": support_state.value,
        "reviewer_state": reviewer_state.value,
        "canonical_conclusion": canonical_conclusion,
        "conclusion_sha256": _text_sha256(canonical_conclusion),
        "sources": [source.model_dump(mode="json") for source in sources],
        "reviewed_at": reviewed_at.isoformat().replace("+00:00", "Z"),
        "revalidate_after": revalidate_after.isoformat().replace("+00:00", "Z"),
        "revalidation_warning_days": revalidation_warning_days,
    }
    evidence_payload = {
        "identity": partial["identity"],
        "support_state": partial["support_state"],
        "canonical_conclusion": partial["canonical_conclusion"],
        "conclusion_sha256": partial["conclusion_sha256"],
        "sources": [
            {
                "source_id": source.source_id,
                "title": source.title,
                "url": source.url,
                "canonical_claim": source.canonical_claim,
                "claim_sha256": source.claim_sha256,
            }
            for source in sources
        ],
    }
    partial["evidence_sha256"] = canonical_sha256(evidence_payload)
    return OfficialCapabilityProfile(
        **partial,
        profile_sha256=canonical_sha256(partial),
    )


def _build_profile(
    *,
    reviewer_state: EvidenceReviewerState,
    reviewed_at: datetime,
    revalidate_after: datetime,
) -> OfficialCapabilityProfile:
    sources = tuple(
        sorted(
            (
                _build_source(
                    source_id="plugin_connection_route",
                    title="Connect and test your plugin",
                    url="https://developers.openai.com/plugins/deploy/connect-chatgpt",
                    canonical_claim=(
                        "The official MCP evaluation route enables developer mode, registers "
                        "the server under Settings > Plugins, and selects the connection in a "
                        "new conversation. It does not independently establish availability "
                        "on the native Chat surface."
                    ),
                    consulted_at=reviewed_at,
                    revalidate_after=revalidate_after,
                ),
                _build_source(
                    source_id="plugin_packaging_surface",
                    title="Package your plugin",
                    url="https://developers.openai.com/plugins/build/plugins",
                    canonical_claim=(
                        "The official local MCP plugin workflow registers the server through "
                        "Plugins and assigns plugin creation to ChatGPT Work or Codex. It does "
                        "not document a custom or local MCP invocation path for Chat."
                    ),
                    consulted_at=reviewed_at,
                    revalidate_after=revalidate_after,
                ),
                _build_source(
                    source_id="plugin_surface_availability",
                    title="Plugins",
                    url="https://learn.chatgpt.com/docs/plugins",
                    canonical_claim=(
                        "The official Plugins overview says Plugins are available with ChatGPT "
                        "Work on web and desktop and are not available in Chat. Because Plugins "
                        "can contain MCP servers and tools, the reviewed Plugin-based MCP path "
                        "is excluded from Chat."
                    ),
                    consulted_at=reviewed_at,
                    revalidate_after=revalidate_after,
                ),
                _build_source(
                    source_id="secure_mcp_tunnel_route",
                    title="Secure MCP Tunnel",
                    url="https://developers.openai.com/api/docs/guides/secure-mcp-tunnels",
                    canonical_claim=(
                        "Secure MCP Tunnel provides transport only to supported OpenAI product "
                        "surfaces. Its ChatGPT setup creates a developer-mode app through "
                        "Settings > Plugins, so tunnel availability does not override the "
                        "separate exclusion of Plugins from Chat."
                    ),
                    consulted_at=reviewed_at,
                    revalidate_after=revalidate_after,
                ),
            ),
            key=lambda item: item.source_id,
        )
    )
    conclusion = (
        "Current reviewed official OpenAI documentation does not permit ChatGPT Chat to "
        "invoke a custom or local MCP tool without switching to ChatGPT Work. The documented "
        "ChatGPT registration path is Plugin-based, and Plugins are explicitly unavailable "
        "in Chat."
    )
    return _commit_profile(
        profile_id=C3_PROFILE_ID,
        identity=CapabilityIdentity(
            provider_id=WebProviderId.CHATGPT,
            native_surface="chat",
            surface_class=WebSurfaceClass.CONVERSATIONAL_CHAT,
            capability=OfficialCapabilityId.CUSTOM_OR_LOCAL_MCP_TOOL_INVOCATION,
        ),
        support_state=OfficialSupportState.UNSUPPORTED,
        reviewer_state=reviewer_state,
        canonical_conclusion=conclusion,
        sources=sources,
        reviewed_at=reviewed_at,
        revalidate_after=revalidate_after,
        revalidation_warning_days=C3_REVALIDATION_WARNING_DAYS,
    )


def build_current_c3_official_capability_profile() -> OfficialCapabilityProfile:
    return _build_profile(
        reviewer_state=EvidenceReviewerState.REVIEWED,
        reviewed_at=C3_REVIEWED_AT,
        revalidate_after=C3_REVALIDATE_AFTER,
    )


def build_c3_candidate_template(
    *,
    reviewed_at: datetime,
    revalidate_after: datetime,
) -> OfficialCapabilityProfile:
    reviewed = _require_aware(reviewed_at)
    deadline = _require_aware(revalidate_after)
    return _build_profile(
        reviewer_state=EvidenceReviewerState.CANDIDATE,
        reviewed_at=reviewed,
        revalidate_after=deadline,
    )


def build_c3_candidate_draft_template(
    *,
    reviewed_at: datetime,
    revalidate_after: datetime,
) -> CandidateProfileDraft:
    candidate = build_c3_candidate_template(
        reviewed_at=reviewed_at,
        revalidate_after=revalidate_after,
    )
    return CandidateProfileDraft(
        version="1",
        profile_id=candidate.profile_id,
        identity=candidate.identity,
        support_state=candidate.support_state,
        canonical_conclusion=candidate.canonical_conclusion,
        sources=tuple(
            CandidateSourceDraft(
                source_id=source.source_id,
                title=source.title,
                url=source.url,
                canonical_claim=source.canonical_claim,
            )
            for source in candidate.sources
        ),
        reviewed_at=candidate.reviewed_at,
        revalidate_after=candidate.revalidate_after,
        revalidation_warning_days=candidate.revalidation_warning_days,
    )


def build_current_c3_registry() -> CapabilityRegistry:
    profile = build_current_c3_official_capability_profile()
    adapter = ProviderAdapter(
        provider_id=WebProviderId.CHATGPT,
        allowed_official_hosts=(
            "developers.openai.com",
            "learn.chatgpt.com",
        ),
        surface_mappings=(
            SurfaceMapping(
                native_surface="chat",
                surface_class=WebSurfaceClass.CONVERSATIONAL_CHAT,
            ),
        ),
        capabilities=(OfficialCapabilityId.CUSTOM_OR_LOCAL_MCP_TOOL_INVOCATION,),
    )
    entry = RegistryProfileEntry(
        profile_id=profile.profile_id,
        profile_path=C3_PROFILE_PATH,
        identity=profile.identity,
        expected_profile_sha256=profile.profile_sha256,
    )
    payload: dict[str, Any] = {
        "version": "1",
        "adapters": [adapter.model_dump(mode="json")],
        "profiles": [entry.model_dump(mode="json")],
    }
    return CapabilityRegistry(
        **payload,
        registry_sha256=canonical_sha256(payload),
    )


def seal_c3_candidate_draft(
    draft: CandidateProfileDraft,
    registry: CapabilityRegistry,
) -> OfficialCapabilityProfile:
    registry = CapabilityRegistry.model_validate(registry.model_dump(mode="python"))
    draft = CandidateProfileDraft.model_validate(draft.model_dump(mode="python"))
    if len(registry.profiles) != 1:
        raise ValueError("C3 candidate sealing requires one active registry profile")
    active_entry = registry.profiles[0]
    if draft.profile_id != active_entry.profile_id or draft.identity != active_entry.identity:
        raise ValueError("C3 candidate draft identity does not match the active profile")
    adapter = {item.provider_id: item for item in registry.adapters}.get(draft.identity.provider_id)
    if adapter is None:
        raise ValueError("C3 candidate draft has no provider adapter")
    _validate_identity_against_adapter(draft.identity, adapter)
    sources = tuple(
        _build_source(
            source_id=source.source_id,
            title=source.title,
            url=source.url,
            canonical_claim=source.canonical_claim,
            consulted_at=draft.reviewed_at,
            revalidate_after=draft.revalidate_after,
        )
        for source in draft.sources
    )
    candidate = _commit_profile(
        profile_id=draft.profile_id,
        identity=draft.identity,
        support_state=draft.support_state,
        reviewer_state=EvidenceReviewerState.CANDIDATE,
        canonical_conclusion=draft.canonical_conclusion,
        sources=sources,
        reviewed_at=draft.reviewed_at,
        revalidate_after=draft.revalidate_after,
        revalidation_warning_days=draft.revalidation_warning_days,
    )
    _validate_profile_against_adapter(candidate, adapter)
    return candidate


def _all_action_decisions(value: bool) -> dict[C3ProtectedAction, bool]:
    return {action: value for action in C3ProtectedAction}


def _lifecycle_for_profile(
    profile: OfficialCapabilityProfile,
    *,
    evaluated_at: datetime,
) -> EvidenceLifecycleState:
    evaluated = _require_aware(evaluated_at)
    if evaluated < profile.reviewed_at:
        return EvidenceLifecycleState.INVALID
    if evaluated >= profile.revalidate_after:
        return EvidenceLifecycleState.EXPIRED
    warning_at = profile.revalidate_after - timedelta(days=profile.revalidation_warning_days)
    if evaluated >= warning_at:
        return EvidenceLifecycleState.REVALIDATION_DUE
    return EvidenceLifecycleState.CURRENT


def _decision_from_profile(
    profile: OfficialCapabilityProfile,
    registry: CapabilityRegistry,
    *,
    evaluated_at: datetime,
) -> C3GateDecision:
    lifecycle = _lifecycle_for_profile(profile, evaluated_at=evaluated_at)
    common: dict[str, Any] = {
        "version": "1",
        "registry_sha256": registry.registry_sha256,
        "profile_id": profile.profile_id,
        "profile_sha256": profile.profile_sha256,
        "evidence_sha256": profile.evidence_sha256,
        "identity": profile.identity,
        "support_state": profile.support_state,
        "reviewer_state": profile.reviewer_state,
        "lifecycle_state": lifecycle,
        "evaluated_at": _require_aware(evaluated_at),
    }
    if profile.reviewer_state is not EvidenceReviewerState.REVIEWED:
        return _invalid_decision(
            evaluated_at=evaluated_at,
            profile_id=profile.profile_id,
            lifecycle=EvidenceLifecycleState.INVALID,
        )
    if lifecycle is EvidenceLifecycleState.INVALID:
        return _invalid_decision(
            evaluated_at=evaluated_at,
            profile_id=profile.profile_id,
            lifecycle=lifecycle,
        )
    if lifecycle is EvidenceLifecycleState.EXPIRED:
        return C3GateDecision(
            **common,
            final_status=C3GateStatus.EXPIRED,
            reason_code=C3ReasonCode.OFFICIAL_EVIDENCE_EXPIRED,
            live_actions_allowed=False,
            action_decisions=_all_action_decisions(False),
        )
    if lifecycle is EvidenceLifecycleState.REVALIDATION_DUE:
        return C3GateDecision(
            **common,
            final_status=C3GateStatus.REVALIDATION_DUE,
            reason_code=C3ReasonCode.OFFICIAL_EVIDENCE_REVALIDATION_DUE,
            live_actions_allowed=False,
            action_decisions=_all_action_decisions(False),
        )
    if profile.support_state is OfficialSupportState.UNSUPPORTED:
        return C3GateDecision(
            **common,
            final_status=C3GateStatus.NO_OFFICIAL_CHAT_TOOL_INTERFACE,
            reason_code=C3ReasonCode.OFFICIAL_CAPABILITY_UNSUPPORTED,
            live_actions_allowed=False,
            action_decisions=_all_action_decisions(False),
        )
    if profile.support_state is OfficialSupportState.UNOBSERVABLE:
        return C3GateDecision(
            **common,
            final_status=C3GateStatus.OFFICIAL_EVIDENCE_AMBIGUOUS,
            reason_code=C3ReasonCode.OFFICIAL_CAPABILITY_UNOBSERVABLE,
            live_actions_allowed=False,
            action_decisions=_all_action_decisions(False),
        )
    return C3GateDecision(
        **common,
        final_status=C3GateStatus.READY,
        reason_code=C3ReasonCode.OFFICIAL_CAPABILITY_SUPPORTED,
        live_actions_allowed=True,
        action_decisions=_all_action_decisions(True),
    )


def _invalid_decision(
    *,
    evaluated_at: datetime,
    profile_id: str = "invalid_or_unverified_profile",
    lifecycle: EvidenceLifecycleState = EvidenceLifecycleState.INVALID,
) -> C3GateDecision:
    status = (
        C3GateStatus.SOURCE_DRIFT
        if lifecycle is EvidenceLifecycleState.SOURCE_DRIFT
        else C3GateStatus.SECURITY_INVARIANT
    )
    reason = (
        C3ReasonCode.OFFICIAL_EVIDENCE_SOURCE_DRIFT
        if lifecycle is EvidenceLifecycleState.SOURCE_DRIFT
        else C3ReasonCode.SECURITY_INVARIANT_FAILED
    )
    return C3GateDecision(
        version="1",
        registry_sha256=None,
        profile_id=profile_id,
        profile_sha256=None,
        evidence_sha256=None,
        identity=None,
        support_state=None,
        reviewer_state=None,
        lifecycle_state=lifecycle,
        evaluated_at=_require_aware(evaluated_at),
        final_status=status,
        reason_code=reason,
        live_actions_allowed=False,
        action_decisions=_all_action_decisions(False),
    )


def _load_json_model(path: Path, model_type: type[BaseModel]) -> BaseModel:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return model_type.model_validate(raw)


def _load_reviewed_bundle(
    *,
    root: Path,
    registry_path: Path,
) -> tuple[CapabilityRegistry, OfficialCapabilityProfile]:
    try:
        registry = CapabilityRegistry.model_validate(
            _load_json_model(registry_path, CapabilityRegistry).model_dump(mode="python")
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise _BundleError(
            "C3 capability registry is invalid",
            lifecycle=EvidenceLifecycleState.INVALID,
        ) from error

    expected_registry = build_current_c3_registry()
    if registry.model_dump(mode="json") != expected_registry.model_dump(mode="json"):
        raise _BundleError(
            "C3 committed registry differs from the reviewed builder",
            lifecycle=EvidenceLifecycleState.INVALID,
        )
    if len(registry.profiles) != 1:
        raise _BundleError(
            "C3 reviewed registry must contain exactly one active profile",
            lifecycle=EvidenceLifecycleState.INVALID,
        )

    entry = registry.profiles[0]
    profile_path = (root / PurePosixPath(entry.profile_path)).resolve()
    governance_root = (root / "governance").resolve()
    if governance_root not in profile_path.parents:
        raise _BundleError(
            "C3 profile path escapes governance",
            lifecycle=EvidenceLifecycleState.INVALID,
        )
    try:
        profile = OfficialCapabilityProfile.model_validate(
            _load_json_model(profile_path, OfficialCapabilityProfile).model_dump(mode="python")
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise _BundleError(
            "C3 active profile is invalid",
            lifecycle=EvidenceLifecycleState.INVALID,
        ) from error

    if profile.profile_sha256 != entry.expected_profile_sha256:
        raise _BundleError(
            "C3 active profile differs from the reviewed registry commitment",
            lifecycle=EvidenceLifecycleState.SOURCE_DRIFT,
        )
    if profile.profile_id != entry.profile_id or profile.identity != entry.identity:
        raise _BundleError(
            "C3 profile identity differs from the reviewed registry entry",
            lifecycle=EvidenceLifecycleState.INVALID,
        )

    adapters = {adapter.provider_id: adapter for adapter in registry.adapters}
    adapter = adapters.get(profile.identity.provider_id)
    if adapter is None:
        raise _BundleError(
            "C3 profile has no reviewed provider adapter",
            lifecycle=EvidenceLifecycleState.INVALID,
        )
    try:
        _validate_profile_against_adapter(profile, adapter)
    except ValueError as error:
        raise _BundleError(
            "C3 profile violates its provider adapter",
            lifecycle=EvidenceLifecycleState.INVALID,
        ) from error

    expected_profile = build_current_c3_official_capability_profile()
    if profile.model_dump(mode="json") != expected_profile.model_dump(mode="json"):
        raise _BundleError(
            "C3 active profile differs from the reviewed builder",
            lifecycle=EvidenceLifecycleState.SOURCE_DRIFT,
        )
    return registry, profile


def evaluate_c3_registry(
    *,
    root: Path,
    registry_path: Path,
    evaluated_at: datetime,
) -> C3GateDecision:
    try:
        registry, profile = _load_reviewed_bundle(
            root=root,
            registry_path=registry_path,
        )
    except _BundleError as error:
        return _invalid_decision(
            evaluated_at=evaluated_at,
            lifecycle=error.lifecycle,
        )
    return _decision_from_profile(
        profile,
        registry,
        evaluated_at=evaluated_at,
    )


def evaluate_reviewed_profile(
    profile: OfficialCapabilityProfile,
    registry: CapabilityRegistry,
    *,
    evaluated_at: datetime,
) -> C3GateDecision:
    """Evaluate a validated profile/registry pair without repository I/O.

    The committed CLI path adds a byte-for-byte reviewed-builder check before
    calling this contract. This function exists for deterministic adapter and
    state-machine tests; a registry entry must still bind the exact profile
    digest and identity.
    """

    try:
        registry = CapabilityRegistry.model_validate(registry.model_dump(mode="python"))
        profile = OfficialCapabilityProfile.model_validate(profile.model_dump(mode="python"))
        entries = {(entry.profile_id, entry.identity.key): entry for entry in registry.profiles}
        entry = entries[(profile.profile_id, profile.identity.key)]
        if entry.expected_profile_sha256 != profile.profile_sha256:
            return _invalid_decision(
                evaluated_at=evaluated_at,
                profile_id=profile.profile_id,
                lifecycle=EvidenceLifecycleState.SOURCE_DRIFT,
            )
        adapter = {item.provider_id: item for item in registry.adapters}[
            profile.identity.provider_id
        ]
        _validate_profile_against_adapter(profile, adapter)
    except (KeyError, ValueError, TypeError):
        return _invalid_decision(
            evaluated_at=evaluated_at,
            profile_id=profile.profile_id,
        )
    return _decision_from_profile(profile, registry, evaluated_at=evaluated_at)


def _candidate_component_changes(
    active: OfficialCapabilityProfile,
    candidate: OfficialCapabilityProfile,
) -> tuple[str, ...]:
    changes: list[str] = []
    if active.support_state is not candidate.support_state:
        changes.append("support_state")
    if (
        active.canonical_conclusion != candidate.canonical_conclusion
        or active.conclusion_sha256 != candidate.conclusion_sha256
    ):
        changes.append("canonical_conclusion")
    active_sources = [
        {
            "source_id": item.source_id,
            "title": item.title,
            "url": item.url,
            "canonical_claim": item.canonical_claim,
            "claim_sha256": item.claim_sha256,
        }
        for item in active.sources
    ]
    candidate_sources = [
        {
            "source_id": item.source_id,
            "title": item.title,
            "url": item.url,
            "canonical_claim": item.canonical_claim,
            "claim_sha256": item.claim_sha256,
        }
        for item in candidate.sources
    ]
    if active_sources != candidate_sources:
        changes.append("official_sources")
    return tuple(changes)


def compare_c3_candidate(
    *,
    root: Path,
    registry_path: Path,
    candidate_path: Path,
    evaluated_at: datetime,
) -> CandidateComparison:
    evaluated = _require_aware(evaluated_at)
    try:
        registry, active = _load_reviewed_bundle(
            root=root,
            registry_path=registry_path,
        )
        candidate = OfficialCapabilityProfile.model_validate(
            _load_json_model(candidate_path, OfficialCapabilityProfile).model_dump(mode="python")
        )
        adapter = {item.provider_id: item for item in registry.adapters}[
            candidate.identity.provider_id
        ]
        _validate_profile_against_adapter(candidate, adapter)
        if candidate.reviewer_state is not EvidenceReviewerState.CANDIDATE:
            raise ValueError("C3 comparison accepts candidate evidence only")
        if candidate.profile_id != active.profile_id or candidate.identity != active.identity:
            raise ValueError("C3 candidate identity does not match the active profile")
        if candidate.reviewed_at <= active.reviewed_at:
            raise ValueError("C3 candidate review must be newer than active evidence")
        if candidate.reviewed_at > evaluated:
            raise ValueError("C3 candidate review cannot be in the future")
        if _lifecycle_for_profile(candidate, evaluated_at=evaluated) not in {
            EvidenceLifecycleState.CURRENT,
            EvidenceLifecycleState.REVALIDATION_DUE,
        }:
            raise ValueError("C3 candidate must be current or revalidation due")
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
        _BundleError,
    ):
        return CandidateComparison(
            version="1",
            active_profile_id=C3_PROFILE_ID,
            active_profile_sha256=None,
            candidate_profile_sha256=None,
            evaluated_at=evaluated,
            comparison_state=CandidateComparisonState.INVALID,
            changed_components=("validation",),
            candidate_can_change_gate=False,
            requires_independent_review=True,
            action_decisions=_all_action_decisions(False),
        )

    changes = _candidate_component_changes(active, candidate)
    state = CandidateComparisonState.SOURCE_DRIFT if changes else CandidateComparisonState.UNCHANGED
    return CandidateComparison(
        version="1",
        active_profile_id=active.profile_id,
        active_profile_sha256=active.profile_sha256,
        candidate_profile_sha256=candidate.profile_sha256,
        evaluated_at=evaluated,
        comparison_state=state,
        changed_components=changes,
        candidate_can_change_gate=False,
        requires_independent_review=bool(changes),
        action_decisions=_all_action_decisions(False),
    )


def build_revalidation_guidance() -> RevalidationGuidance:
    profile = build_current_c3_official_capability_profile()
    return RevalidationGuidance(
        version="1",
        profile_id=profile.profile_id,
        official_source_urls=tuple(source.url for source in profile.sources),
        acquisition_boundary=(
            "Use only the OpenAI Docs interface to acquire current public documentation.",
            "Keep fetched page content outside Git; commit bounded canonical claims and digests.",
            "Treat acquisition as non-deterministic and all repository decisions as offline.",
        ),
        review_steps=(
            "Fetch every committed source and search for an explicit native Chat custom/local MCP route.",
            "Rewrite bounded canonical claims from current text; do not copy long passages.",
            "Create a candidate profile with fresh UTC review and revalidation timestamps.",
            "Run candidate comparison; any changed evidence is source_drift and remains blocked.",
            "Require independent review, full tests, a new seal, and a deliberate registry update.",
        ),
        forbidden_actions=(
            "Do not create or paste Runtime credentials.",
            "Do not create, edit, or start a Secure MCP Tunnel.",
            "Do not create a Plugin or open ChatGPT for a browser test.",
            "Do not use Work, history, existing conversations, settings, or private browser state.",
            "Do not let a candidate profile change any protected action decision.",
        ),
    )


def _json_output(value: BaseModel) -> str:
    return json.dumps(
        value.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )


def _decision_exit_code(decision: C3GateDecision) -> int:
    if decision.lifecycle_state is EvidenceLifecycleState.INVALID:
        return 4
    if decision.lifecycle_state is EvidenceLifecycleState.SOURCE_DRIFT:
        return 4
    if decision.lifecycle_state is EvidenceLifecycleState.EXPIRED:
        return 5
    return 0


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    default_registry = root / "governance" / "c3-capability-registry.json"

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("official-profile")
    subparsers.add_parser("official-registry")

    for name in ("verify-profile", "lifecycle", "preflight", "governance"):
        command = subparsers.add_parser(name)
        command.add_argument("--root", type=Path, default=root)
        command.add_argument("--registry", type=Path, default=default_registry)
        command.add_argument("--as-of")
        if name == "governance":
            command.add_argument("--github-annotations", action="store_true")

    require_action = subparsers.add_parser("require-action")
    require_action.add_argument("--root", type=Path, default=root)
    require_action.add_argument("--registry", type=Path, default=default_registry)
    require_action.add_argument(
        "--action",
        choices=tuple(action.value for action in C3ProtectedAction),
        required=True,
    )
    require_action.add_argument("--as-of")

    new_candidate_draft = subparsers.add_parser("new-candidate-draft")
    new_candidate_draft.add_argument("--reviewed-at", required=True)
    new_candidate_draft.add_argument("--revalidate-after", required=True)

    seal_candidate = subparsers.add_parser("seal-candidate")
    seal_candidate.add_argument("--root", type=Path, default=root)
    seal_candidate.add_argument("--registry", type=Path, default=default_registry)
    seal_candidate.add_argument("--draft", type=Path, required=True)
    seal_candidate.add_argument("--as-of")

    compare = subparsers.add_parser("compare-candidate")
    compare.add_argument("--root", type=Path, default=root)
    compare.add_argument("--registry", type=Path, default=default_registry)
    compare.add_argument("--candidate", type=Path, required=True)
    compare.add_argument("--as-of")

    subparsers.add_parser("revalidation-steps")

    args = parser.parse_args(argv)
    if args.command == "official-profile":
        print(_json_output(build_current_c3_official_capability_profile()))
        return 0
    if args.command == "official-registry":
        print(_json_output(build_current_c3_registry()))
        return 0
    if args.command == "new-candidate-draft":
        draft = build_c3_candidate_draft_template(
            reviewed_at=_parse_timestamp(args.reviewed_at),
            revalidate_after=_parse_timestamp(args.revalidate_after),
        )
        print(_json_output(draft))
        return 0
    if args.command == "seal-candidate":
        evaluated = _parse_timestamp(args.as_of)
        try:
            registry, active = _load_reviewed_bundle(
                root=args.root.resolve(),
                registry_path=args.registry.resolve(),
            )
            draft = CandidateProfileDraft.model_validate(
                _load_json_model(args.draft.resolve(), CandidateProfileDraft).model_dump(
                    mode="python"
                )
            )
            if draft.reviewed_at <= active.reviewed_at:
                raise ValueError("C3 candidate draft must be newer than active evidence")
            if draft.reviewed_at > evaluated:
                raise ValueError("C3 candidate draft review cannot be in the future")
            candidate = seal_c3_candidate_draft(draft, registry)
        except (
            OSError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
            _BundleError,
        ):
            print(_json_output(_invalid_decision(evaluated_at=evaluated)))
            return 4
        print(_json_output(candidate))
        return 0
    if args.command == "revalidation-steps":
        print(_json_output(build_revalidation_guidance()))
        return 0
    if args.command == "compare-candidate":
        comparison = compare_c3_candidate(
            root=args.root.resolve(),
            registry_path=args.registry.resolve(),
            candidate_path=args.candidate.resolve(),
            evaluated_at=_parse_timestamp(args.as_of),
        )
        print(_json_output(comparison))
        if comparison.comparison_state is CandidateComparisonState.INVALID:
            return 4
        if comparison.comparison_state is CandidateComparisonState.SOURCE_DRIFT:
            return 6
        return 0

    decision = evaluate_c3_registry(
        root=args.root.resolve(),
        registry_path=args.registry.resolve(),
        evaluated_at=_parse_timestamp(args.as_of),
    )
    print(_json_output(decision))
    if args.command == "governance" and args.github_annotations:
        if decision.lifecycle_state is EvidenceLifecycleState.REVALIDATION_DUE:
            print(
                "::warning title=C3 evidence revalidation due::"
                f"{decision.profile_id} must be revalidated by "
                f"{C3_REVALIDATE_AFTER.isoformat().replace('+00:00', 'Z')}"
            )
        elif decision.lifecycle_state in {
            EvidenceLifecycleState.EXPIRED,
            EvidenceLifecycleState.INVALID,
            EvidenceLifecycleState.SOURCE_DRIFT,
        }:
            print(f"::error title=C3 evidence governance blocked::{decision.lifecycle_state.value}")
    if args.command == "require-action":
        action = C3ProtectedAction(args.action)
        if _decision_exit_code(decision) != 0:
            return _decision_exit_code(decision)
        return 0 if decision.action_decisions[action] else 3
    return _decision_exit_code(decision)


if __name__ == "__main__":
    raise SystemExit(main())
