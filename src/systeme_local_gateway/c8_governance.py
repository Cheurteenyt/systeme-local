from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .c0_probe import C0_TOOL_NAME
from .c4_admission import C4_CHATGPT_TOOL_PROTOCOL_SHA256
from .c7_work_admission import (
    C7_POLICY_PATH,
    C7_PROFILE_PATH,
    WorkCapabilityIdentity,
    canonical_sha256,
    current_work_identity,
    text_sha256,
)

C8_REVALIDATION_PATH = "governance/c8-official-work-revalidation.json"
C8_POLICY_PATH = "governance/c8-live-work-policy.json"
C8_ACCEPTED_C7_MAIN = "e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"
C8_REVIEWED_AT = datetime(2026, 8, 7, 17, 33, tzinfo=timezone.utc)
C8_REVALIDATE_AFTER = C8_REVIEWED_AT + timedelta(days=14)
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SOURCE_ID_PATTERN = r"^[a-z][a-z0-9_]{2,63}$"
_ALLOWED_HOSTS = ("chatgpt.com", "developers.openai.com", "learn.chatgpt.com")


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("C8 governance timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _official_url(value: str) -> str:
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or parts.hostname not in _ALLOWED_HOSTS
        or parts.username is not None
        or parts.password is not None
        or parts.port is not None
        or parts.query
        or parts.fragment
        or parts.netloc != parts.hostname
        or not parts.path.startswith("/")
    ):
        raise ValueError("C8 official source URL is outside the reviewed allowlist")
    return value


class C8SourceRouteState(StrEnum):
    FETCHED = "fetched"
    SEARCH_INDEX_CORROBORATED = "search_index_corroborated"
    FETCH_ROUTE_INCONSISTENCY_CORROBORATED = "fetch_route_inconsistency_corroborated"


class C8OfficialSourceCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=_SOURCE_ID_PATTERN)
    title: str = Field(min_length=1, max_length=160)
    url: str = Field(min_length=1, max_length=512)
    route_state: C8SourceRouteState
    canonical_claim: str = Field(min_length=1, max_length=1_200)
    claim_sha256: str = Field(pattern=_SHA256_PATTERN)
    consulted_at: datetime
    revalidate_after: datetime

    _consulted_utc = field_validator("consulted_at")(_require_utc)
    _revalidate_utc = field_validator("revalidate_after")(_require_utc)

    @model_validator(mode="after")
    def validate_source(self) -> C8OfficialSourceCheck:
        _official_url(self.url)
        if self.claim_sha256 != text_sha256(self.canonical_claim):
            raise ValueError("C8 official claim digest mismatch")
        if self.revalidate_after <= self.consulted_at:
            raise ValueError("C8 official source deadline must follow consultation")
        if self.revalidate_after - self.consulted_at > timedelta(days=14):
            raise ValueError("C8 official source revalidation window exceeds 14 days")
        return self


class C8OfficialWorkRevalidation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    receipt_id: Literal["chatgpt_work_c8_revalidation_20260727"]
    inherited_c7_profile_path: Literal["governance/c7-chatgpt-work-capability-profile.json"]
    inherited_c7_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    identity: WorkCapabilityIdentity
    support_state: Literal["supported"]
    native_chat_gate_status: Literal["BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"]
    source_checks: tuple[C8OfficialSourceCheck, ...]
    mcp_fetch_route_inconsistency_observed: Literal[False]
    route_inconsistency_changes_support_conclusion: Literal[False]
    current_conclusion: str = Field(min_length=1, max_length=2_000)
    conclusion_sha256: str = Field(pattern=_SHA256_PATTERN)
    reviewed_at: datetime
    revalidate_after: datetime
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    _reviewed_utc = field_validator("reviewed_at")(_require_utc)
    _revalidate_utc = field_validator("revalidate_after")(_require_utc)

    @model_validator(mode="after")
    def validate_receipt(self) -> C8OfficialWorkRevalidation:
        if self.identity != current_work_identity():
            raise ValueError("C8 revalidation is not bound to exact Work identity")
        source_ids = tuple(item.source_id for item in self.source_checks)
        if len(source_ids) < 5 or source_ids != tuple(sorted(set(source_ids))):
            raise ValueError("C8 revalidation sources must be sorted and unique")
        has_route_inconsistency = any(
            item.route_state is C8SourceRouteState.FETCH_ROUTE_INCONSISTENCY_CORROBORATED
            for item in self.source_checks
        )
        if has_route_inconsistency != self.mcp_fetch_route_inconsistency_observed:
            raise ValueError("C8 revalidation route-inconsistency state is contradictory")
        if any(
            item.consulted_at != self.reviewed_at or item.revalidate_after != self.revalidate_after
            for item in self.source_checks
        ):
            raise ValueError("C8 source windows must equal the receipt window")
        if self.revalidate_after - self.reviewed_at > timedelta(days=14):
            raise ValueError("C8 revalidation receipt window exceeds 14 days")
        if self.conclusion_sha256 != text_sha256(self.current_conclusion):
            raise ValueError("C8 conclusion digest mismatch")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"receipt_sha256"}))
        if self.receipt_sha256 != expected:
            raise ValueError("C8 official revalidation receipt digest mismatch")
        return self


class C8GovernanceBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(pattern=r"^governance/[a-z0-9][a-z0-9._/-]+\.json$")
    sha256: str = Field(pattern=_SHA256_PATTERN)


class C8LiveWorkPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"]
    policy_id: Literal["chatgpt_work_live_c8_20260727"]
    accepted_c7_commit: Literal["e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"]
    identity: WorkCapabilityIdentity
    c7_profile: C8GovernanceBinding
    c7_policy: C8GovernanceBinding
    c8_official_revalidation: C8GovernanceBinding
    native_chat_gate_status: Literal["BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"]
    default_live_actions_allowed: Literal[False]
    authorization_required: Literal[True]
    work_surface_required: Literal[True]
    entitlement_required: Literal["available"]
    quota_required: Literal["usable"]
    max_observation_age_seconds: Literal[300]
    max_live_cycle_seconds: Literal[1200]
    max_new_synthetic_work_tasks: Literal[2]
    only_eligible_tool: Literal["systeme_local_connectivity_probe"]
    tool_protocol_sha256: str = Field(pattern=_SHA256_PATTERN)
    write_actions_allowed: Literal[False]
    real_evidence_access_allowed: Literal[False]
    protocol_v2_allowed: Literal[False]
    existing_conversations_allowed: Literal[False]
    private_browser_state_allowed: Literal[False]
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_policy(self) -> C8LiveWorkPolicy:
        if self.identity != current_work_identity():
            raise ValueError("C8 policy is not bound to exact Work identity")
        if self.c7_profile.path != C7_PROFILE_PATH:
            raise ValueError("C8 policy references an unexpected C7 profile")
        if self.c7_policy.path != C7_POLICY_PATH:
            raise ValueError("C8 policy references an unexpected C7 policy")
        if self.c8_official_revalidation.path != C8_REVALIDATION_PATH:
            raise ValueError("C8 policy references an unexpected revalidation receipt")
        if self.only_eligible_tool != C0_TOOL_NAME:
            raise ValueError("C8 policy grants an unexpected tool")
        if self.tool_protocol_sha256 != C4_CHATGPT_TOOL_PROTOCOL_SHA256:
            raise ValueError("C8 policy tool protocol differs from reviewed C4")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"policy_sha256"}))
        if self.policy_sha256 != expected:
            raise ValueError("C8 live Work policy digest mismatch")
        return self


def _file_canonical_sha256(path: Path) -> str:
    return canonical_sha256(json.loads(path.read_text(encoding="utf-8")))


def _source(
    source_id: str,
    title: str,
    url: str,
    route_state: C8SourceRouteState,
    claim: str,
) -> C8OfficialSourceCheck:
    return C8OfficialSourceCheck(
        source_id=source_id,
        title=title,
        url=url,
        route_state=route_state,
        canonical_claim=claim,
        claim_sha256=text_sha256(claim),
        consulted_at=C8_REVIEWED_AT,
        revalidate_after=C8_REVALIDATE_AFTER,
    )


def build_current_c8_revalidation(root: Path) -> C8OfficialWorkRevalidation:
    sources = tuple(
        sorted(
            (
                _source(
                    "admin_setup",
                    "Enterprise admin setup",
                    "https://learn.chatgpt.com/docs/enterprise/admin-setup",
                    C8SourceRouteState.SEARCH_INDEX_CORROBORATED,
                    "The current official admin guidance corroborates that Plugins are "
                    "available on ChatGPT Work on the web and recommends least-access, "
                    "non-sensitive validation.",
                ),
                _source(
                    "enterprise_apps",
                    "Apps and connectors",
                    "https://learn.chatgpt.com/docs/enterprise/apps-and-connectors",
                    C8SourceRouteState.SEARCH_INDEX_CORROBORATED,
                    "The current official enterprise guide corroborates Plugins on ChatGPT "
                    "Work on the web and their absence from native Chat, IDE, and mobile.",
                ),
                _source(
                    "mcp_work_route",
                    "Model Context Protocol",
                    "https://learn.chatgpt.com/docs/extend/mcp",
                    C8SourceRouteState.FETCHED,
                    "The current official MCP guide states that ChatGPT web can use remote "
                    "MCP-backed tools supplied by plugins. The separate Plugins page provides "
                    "the Work-only availability boundary.",
                ),
                _source(
                    "plugin_surface",
                    "Plugins",
                    "https://learn.chatgpt.com/docs/plugins",
                    C8SourceRouteState.FETCHED,
                    "The current official Plugins overview states that Plugins are available "
                    "with ChatGPT Work on the web, unavailable in Chat, IDE, and mobile, and "
                    "may add MCP tools to new chats.",
                ),
                _source(
                    "secure_tunnel",
                    "Secure MCP Tunnel",
                    "https://developers.openai.com/api/docs/guides/secure-mcp-tunnels",
                    C8SourceRouteState.FETCHED,
                    "The current official secure Tunnel guide directs an operator to Plugins, "
                    "the Tunnel connection option, and a workspace-associated tunnel ID; "
                    "Tunnels Read and Use permissions are required.",
                ),
                _source(
                    "work_admin_boundary",
                    "Work admin FAQ",
                    "https://learn.chatgpt.com/docs/enterprise/work-admin-faq",
                    C8SourceRouteState.SEARCH_INDEX_CORROBORATED,
                    "The current official Work administration guidance keeps Work, Chat, and "
                    "connected-workflow runtime boundaries separate; controls are not "
                    "interchangeable across those surfaces.",
                ),
                _source(
                    "work_rollout_surface",
                    "ChatGPT Work",
                    "https://chatgpt.com/fr-FR/work/",
                    C8SourceRouteState.FETCHED,
                    "The official ChatGPT Work product page states that Work is available for "
                    "all plans on desktop and is rolling out progressively on the web and "
                    "mobile for Plus, Pro, Business, Enterprise, and Edu. This does not prove "
                    "account-specific web access.",
                ),
            ),
            key=lambda item: item.source_id,
        )
    )
    conclusion = (
        "Current official OpenAI evidence continues to support Plugin-mediated custom or "
        "local MCP tool use on ChatGPT Work on the web. The official product page says the "
        "web rollout is progressive, so route-level support does not establish current "
        "account access or usable quota. It does not support native Chat and does not "
        "authorize a live action. C8 therefore requires separate fresh visible Work, "
        "entitlement, quota, and operator authorization evidence before exposing the single "
        "reviewed probe."
    )
    c7_profile_sha256 = _file_canonical_sha256(root / C7_PROFILE_PATH)
    payload: dict[str, Any] = {
        "version": "1",
        "receipt_id": "chatgpt_work_c8_revalidation_20260727",
        "inherited_c7_profile_path": C7_PROFILE_PATH,
        "inherited_c7_profile_sha256": c7_profile_sha256,
        "identity": current_work_identity().model_dump(mode="json"),
        "support_state": "supported",
        "native_chat_gate_status": "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE",
        "source_checks": [item.model_dump(mode="json") for item in sources],
        "mcp_fetch_route_inconsistency_observed": False,
        "route_inconsistency_changes_support_conclusion": False,
        "current_conclusion": conclusion,
        "conclusion_sha256": text_sha256(conclusion),
        "reviewed_at": C8_REVIEWED_AT.isoformat().replace("+00:00", "Z"),
        "revalidate_after": C8_REVALIDATE_AFTER.isoformat().replace("+00:00", "Z"),
    }
    return C8OfficialWorkRevalidation(
        **payload,
        receipt_sha256=canonical_sha256(payload),
    )


def build_current_c8_policy(root: Path) -> C8LiveWorkPolicy:
    revalidation = build_current_c8_revalidation(root)
    payload: dict[str, Any] = {
        "version": "1",
        "policy_id": "chatgpt_work_live_c8_20260727",
        "accepted_c7_commit": C8_ACCEPTED_C7_MAIN,
        "identity": current_work_identity().model_dump(mode="json"),
        "c7_profile": {
            "path": C7_PROFILE_PATH,
            "sha256": _file_canonical_sha256(root / C7_PROFILE_PATH),
        },
        "c7_policy": {
            "path": C7_POLICY_PATH,
            "sha256": _file_canonical_sha256(root / C7_POLICY_PATH),
        },
        "c8_official_revalidation": {
            "path": C8_REVALIDATION_PATH,
            "sha256": revalidation.receipt_sha256,
        },
        "native_chat_gate_status": "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE",
        "default_live_actions_allowed": False,
        "authorization_required": True,
        "work_surface_required": True,
        "entitlement_required": "available",
        "quota_required": "usable",
        "max_observation_age_seconds": 300,
        "max_live_cycle_seconds": 1200,
        "max_new_synthetic_work_tasks": 2,
        "only_eligible_tool": C0_TOOL_NAME,
        "tool_protocol_sha256": C4_CHATGPT_TOOL_PROTOCOL_SHA256,
        "write_actions_allowed": False,
        "real_evidence_access_allowed": False,
        "protocol_v2_allowed": False,
        "existing_conversations_allowed": False,
        "private_browser_state_allowed": False,
    }
    return C8LiveWorkPolicy(
        **payload,
        policy_sha256=canonical_sha256(payload),
    )


def load_c8_revalidation(path: Path) -> C8OfficialWorkRevalidation:
    return C8OfficialWorkRevalidation.model_validate_json(path.read_text(encoding="utf-8"))


def load_c8_policy(path: Path) -> C8LiveWorkPolicy:
    return C8LiveWorkPolicy.model_validate_json(path.read_text(encoding="utf-8"))


def verify_committed_c8_governance(
    root: Path,
    *,
    evaluated_at: datetime,
) -> tuple[C8OfficialWorkRevalidation, C8LiveWorkPolicy]:
    at = _require_utc(evaluated_at)
    revalidation = load_c8_revalidation(root / C8_REVALIDATION_PATH)
    policy = load_c8_policy(root / C8_POLICY_PATH)
    if revalidation != build_current_c8_revalidation(root):
        raise ValueError("committed C8 official revalidation differs from reviewed builder")
    if policy != build_current_c8_policy(root):
        raise ValueError("committed C8 live Work policy differs from reviewed builder")
    if at >= revalidation.revalidate_after:
        raise ValueError("C8 official Work revalidation is expired")
    if policy.c8_official_revalidation.sha256 != revalidation.receipt_sha256:
        raise ValueError("C8 policy does not bind the official revalidation")
    return revalidation, policy


def rendered_json(model: BaseModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
