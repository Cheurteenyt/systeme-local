from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import Literal
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, field_validator, model_validator
from ._canonicalization import (
    _canonical_json,
    _require_aware,
    _validate_sorted_unique_enum_tuple,
    _validate_sorted_unique_string_tuple,
)


from .models import CapabilityClaim, CapabilitySupport, StrictModel

_ID_PATTERN = r"^[a-z][a-z0-9_]{2,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ALLOWED_OFFICIAL_HOSTS = frozenset(
    {
        "help.openai.com",
        "developers.openai.com",
        "platform.openai.com",
        "openai.com",
        "www.openai.com",
    }
)
_PROFILE_DOMAIN = b"systeme-local:chatgpt-mcp-capability-profile:v1\x00"
_SOURCE_DOMAIN = b"systeme-local:openai-official-source:v1\x00"


class ChatGptPlan(StrEnum):
    FREE = "free"
    GO = "go"
    PLUS = "plus"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"
    EDU = "edu"
    UNKNOWN = "unknown"


class ChatGptWorkspaceRole(StrEnum):
    MEMBER = "member"
    AUTHORIZED_DEVELOPER = "authorized_developer"
    ADMIN = "admin"
    OWNER = "owner"
    UNKNOWN = "unknown"


class ChatGptClientSurface(StrEnum):
    WEB = "web"
    IOS = "ios"
    ANDROID = "android"
    DESKTOP = "desktop"
    UNKNOWN = "unknown"


class McpAccessMode(StrEnum):
    READ_FETCH = "read_fetch"
    WRITE_MODIFY = "write_modify"


class McpDeploymentPhase(StrEnum):
    TEST = "test"
    PUBLISH = "publish"
    USE = "use"


class McpServerLocation(StrEnum):
    PUBLIC_REMOTE = "public_remote"
    PRIVATE_NETWORK = "private_network"
    ON_PREMISES = "on_premises"
    DEVELOPER_MACHINE = "developer_machine"
    UNKNOWN = "unknown"


class McpTransportKind(StrEnum):
    REMOTE_DIRECT = "remote_direct"
    SECURE_MCP_TUNNEL = "secure_mcp_tunnel"


class McpAuthenticationKind(StrEnum):
    NONE = "none"
    OAUTH = "oauth"
    OPENID_CONNECT = "openid_connect"
    UNKNOWN = "unknown"


class RefreshTokenCapability(StrEnum):
    ISSUED = "issued"
    NOT_ISSUED = "not_issued"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class McpCapabilityId(StrEnum):
    CREATE_TEST_READ_FETCH_APP = "create_test_read_fetch_app"
    CREATE_TEST_WRITE_MODIFY_APP = "create_test_write_modify_app"
    PUBLISH_CUSTOM_APP = "publish_custom_app"
    USE_CONFIGURED_CUSTOM_APP = "use_configured_custom_app"
    WEB_CLIENT = "web_client"
    MOBILE_CLIENT = "mobile_client"
    DIRECT_LOCAL_CONNECTION = "direct_local_connection"
    SECURE_MCP_TUNNEL = "secure_mcp_tunnel"
    OAUTH_AUTHORIZATION = "oauth_authorization"
    OAUTH_REFRESH = "oauth_refresh"
    CURRENT_CHAT_APP_SELECTION = "current_chat_app_selection"
    PROJECT_HOST_CONTEXT = "project_host_context"
    ENUMERATE_PERSONAL_CHATS = "enumerate_personal_chats"
    ENUMERATE_PROJECTS = "enumerate_projects"
    AGENT_MODE_CUSTOM_APPS = "agent_mode_custom_apps"
    DEEP_RESEARCH_READ_FETCH = "deep_research_read_fetch"
    DEEP_RESEARCH_WRITE = "deep_research_write"
    MULTIPLE_APPS_SINGLE_PROMPT = "multiple_apps_single_prompt"
    SEARCH_FETCH_TOOLS_REQUIRED = "search_fetch_tools_required"
    AUTOMATIC_TOOL_UPDATES = "automatic_tool_updates"
    WRITE_ACTION_CONFIRMATION = "write_action_confirmation"
    HIGH_RISK_ACTION_APPROVAL_GUARANTEE = "high_risk_action_approval_guarantee"


class McpDecisionReason(StrEnum):
    APPROVED_READ_FETCH = "APPROVED_READ_FETCH"
    APPROVED_WRITE_MODIFY = "APPROVED_WRITE_MODIFY"
    PROFILE_EXPIRED = "PROFILE_EXPIRED"
    REQUEST_PREDATES_PROFILE = "REQUEST_PREDATES_PROFILE"
    EVALUATION_PREDATES_REQUEST = "EVALUATION_PREDATES_REQUEST"
    UNKNOWN_PLAN = "UNKNOWN_PLAN"
    PLAN_NOT_ELIGIBLE = "PLAN_NOT_ELIGIBLE"
    PRO_WRITE_UNSUPPORTED = "PRO_WRITE_UNSUPPORTED"
    PRO_PUBLISH_UNSUPPORTED = "PRO_PUBLISH_UNSUPPORTED"
    UNKNOWN_ROLE = "UNKNOWN_ROLE"
    BUSINESS_DEVELOPER_MODE_REQUIRES_ADMIN = "BUSINESS_DEVELOPER_MODE_REQUIRES_ADMIN"
    ENTERPRISE_EDU_DEVELOPER_NOT_AUTHORIZED = "ENTERPRISE_EDU_DEVELOPER_NOT_AUTHORIZED"
    PUBLICATION_REQUIRES_ADMIN_OR_OWNER = "PUBLICATION_REQUIRES_ADMIN_OR_OWNER"
    UNKNOWN_CLIENT = "UNKNOWN_CLIENT"
    WEB_CLIENT_REQUIRED = "WEB_CLIENT_REQUIRED"
    UNKNOWN_SERVER_LOCATION = "UNKNOWN_SERVER_LOCATION"
    AUTHENTICATION_UNKNOWN = "AUTHENTICATION_UNKNOWN"
    AUTHENTICATION_REQUIRED_BY_LOCAL_POLICY = "AUTHENTICATION_REQUIRED_BY_LOCAL_POLICY"
    OAUTH_REFRESH_TOKEN_REQUIRED = "OAUTH_REFRESH_TOKEN_REQUIRED"
    OAUTH_REFRESH_CAPABILITY_UNKNOWN = "OAUTH_REFRESH_CAPABILITY_UNKNOWN"
    CHAT_ENUMERATION_UNPROVEN = "CHAT_ENUMERATION_UNPROVEN"
    PROJECT_ENUMERATION_UNPROVEN = "PROJECT_ENUMERATION_UNPROVEN"
    AGENT_MODE_UNSUPPORTED = "AGENT_MODE_UNSUPPORTED"
    DEEP_RESEARCH_WRITE_UNSUPPORTED = "DEEP_RESEARCH_WRITE_UNSUPPORTED"
    DEVELOPER_MODE_NOT_ENABLED = "DEVELOPER_MODE_NOT_ENABLED"
    APP_NOT_CONFIGURED = "APP_NOT_CONFIGURED"
    WORKSPACE_APP_ACCESS_NOT_GRANTED = "WORKSPACE_APP_ACCESS_NOT_GRANTED"


class OfficialSourceReference(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    source_id: str = Field(pattern=_ID_PATTERN)
    title: str = Field(min_length=1, max_length=240)
    url: str = Field(min_length=12, max_length=512)
    section: str = Field(min_length=1, max_length=240)
    evidence_statement: str = Field(min_length=1, max_length=1200)
    reviewed_at: datetime
    statement_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_reviewed_at = field_validator("reviewed_at")(_require_aware)

    @field_validator("url")
    @classmethod
    def require_official_openai_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "https":
            raise ValueError("official source URLs must use HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("official source URLs cannot contain credentials")
        host = (parsed.hostname or "").lower()
        if host not in _ALLOWED_OFFICIAL_HOSTS:
            raise ValueError("official source URL host is not allowed")
        if parsed.query or parsed.fragment:
            raise ValueError("official source URLs cannot contain query or fragment data")
        return value

    @model_validator(mode="after")
    def verify_statement_digest(self) -> "OfficialSourceReference":
        payload = {
            "source_id": self.source_id,
            "title": self.title,
            "url": self.url,
            "section": self.section,
            "evidence_statement": self.evidence_statement,
            "reviewed_at": self.reviewed_at.isoformat().replace("+00:00", "Z"),
        }
        digest = sha256(_SOURCE_DOMAIN + _canonical_json(payload)).hexdigest()
        if digest != self.statement_sha256:
            raise ValueError("official source statement digest mismatch")
        return self


class McpCapabilityMatrixRow(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    capability: McpCapabilityId
    claim: CapabilityClaim
    source_ids: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_row(self) -> "McpCapabilityMatrixRow":
        _validate_sorted_unique_string_tuple(self.source_ids, field_name="source_ids")
        _validate_sorted_unique_string_tuple(self.constraints, field_name="constraints")
        if self.claim.state is CapabilitySupport.UNKNOWN:
            if self.source_ids:
                raise ValueError("unknown capability rows cannot claim official sources")
        elif not self.source_ids:
            raise ValueError("known capability rows require official sources")
        return self


class McpPlanEntitlement(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    plan: ChatGptPlan
    phase: McpDeploymentPhase
    access_mode: McpAccessMode
    claim: CapabilityClaim
    allowed_roles: tuple[ChatGptWorkspaceRole, ...] = ()
    source_ids: tuple[str, ...] = ()
    refusal_reasons: tuple[McpDecisionReason, ...] = ()
    role_refusal_reason: McpDecisionReason | None = None

    @model_validator(mode="after")
    def validate_entitlement(self) -> "McpPlanEntitlement":
        if self.plan is ChatGptPlan.UNKNOWN:
            raise ValueError("unknown plan is not a committed entitlement row")
        _validate_sorted_unique_enum_tuple(self.allowed_roles, field_name="allowed_roles")
        _validate_sorted_unique_string_tuple(self.source_ids, field_name="source_ids")
        _validate_sorted_unique_enum_tuple(self.refusal_reasons, field_name="refusal_reasons")
        if not self.source_ids:
            raise ValueError("entitlements require official sources")
        all_known_roles = {
            ChatGptWorkspaceRole.MEMBER,
            ChatGptWorkspaceRole.AUTHORIZED_DEVELOPER,
            ChatGptWorkspaceRole.ADMIN,
            ChatGptWorkspaceRole.OWNER,
        }
        if self.claim.state is CapabilitySupport.SUPPORTED:
            if not self.allowed_roles:
                raise ValueError("supported entitlements require allowed_roles")
            if self.refusal_reasons:
                raise ValueError("supported entitlements cannot carry refusal_reasons")
            if set(self.allowed_roles) == all_known_roles:
                if self.role_refusal_reason is not None:
                    raise ValueError("all-role entitlements cannot carry role_refusal_reason")
            elif self.role_refusal_reason is None:
                raise ValueError("restricted entitlements require role_refusal_reason")
        elif self.claim.state is CapabilitySupport.UNSUPPORTED:
            if self.allowed_roles:
                raise ValueError("unsupported entitlements cannot allow roles")
            if not self.refusal_reasons:
                raise ValueError("unsupported entitlements require refusal_reasons")
            if self.role_refusal_reason is not None:
                raise ValueError("unsupported entitlements cannot carry role_refusal_reason")
        else:
            raise ValueError("entitlement rows must be documented supported or unsupported")
        return self


class ChatGptMcpCapabilityProfile(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    profile_id: str = Field(pattern=_ID_PATTERN)
    provider: Literal["chatgpt"] = "chatgpt"
    surface: Literal["custom_mcp_app"] = "custom_mcp_app"
    lifecycle: Literal["beta"] = "beta"
    reviewed_at: datetime
    revalidate_after: datetime
    sources: tuple[OfficialSourceReference, ...] = Field(min_length=1, max_length=16)
    rows: tuple[McpCapabilityMatrixRow, ...] = Field(min_length=1, max_length=64)
    entitlements: tuple[McpPlanEntitlement, ...] = Field(min_length=1, max_length=64)
    profile_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_reviewed_at = field_validator("reviewed_at")(_require_aware)
    _aware_revalidate_after = field_validator("revalidate_after")(_require_aware)

    @model_validator(mode="after")
    def validate_profile(self) -> "ChatGptMcpCapabilityProfile":
        if self.revalidate_after <= self.reviewed_at:
            raise ValueError("revalidate_after must follow reviewed_at")
        if self.revalidate_after - self.reviewed_at > timedelta(days=31):
            raise ValueError("volatile ChatGPT profiles must be revalidated within 31 days")

        source_ids = tuple(source.source_id for source in self.sources)
        _validate_sorted_unique_string_tuple(
            source_ids,
            field_name="official source identifiers",
        )
        for source in self.sources:
            if source.reviewed_at != self.reviewed_at:
                raise ValueError("official source review timestamps must match profile reviewed_at")

        capabilities = tuple(row.capability for row in self.rows)
        _validate_sorted_unique_enum_tuple(capabilities, field_name="capability rows")
        if set(capabilities) != set(McpCapabilityId):
            missing = sorted(item.value for item in set(McpCapabilityId) - set(capabilities))
            extra = sorted(item.value for item in set(capabilities) - set(McpCapabilityId))
            raise ValueError(
                f"capability matrix must be complete; missing={missing}, extra={extra}"
            )

        entitlement_keys = tuple(
            (item.plan.value, item.phase.value, item.access_mode.value)
            for item in self.entitlements
        )
        if len(entitlement_keys) != len(set(entitlement_keys)):
            raise ValueError("plan entitlement rows must be unique")
        if entitlement_keys != tuple(sorted(entitlement_keys)):
            raise ValueError("plan entitlement rows must be sorted")
        expected_keys = {
            (plan.value, phase.value, access_mode.value)
            for plan in ChatGptPlan
            if plan is not ChatGptPlan.UNKNOWN
            for phase in McpDeploymentPhase
            for access_mode in McpAccessMode
        }
        if set(entitlement_keys) != expected_keys:
            missing_entitlement_keys = sorted(expected_keys - set(entitlement_keys))
            extra_entitlement_keys = sorted(set(entitlement_keys) - expected_keys)
            raise ValueError(
                f"plan entitlement matrix must be complete; missing={missing_entitlement_keys}, extra={extra_entitlement_keys}"
            )

        known_sources = set(source_ids)
        referenced_sources: set[str] = set()
        for row in self.rows:
            if not set(row.source_ids).issubset(known_sources):
                raise ValueError(f"capability row {row.capability} references an unknown source")
            referenced_sources.update(row.source_ids)
        for entitlement in self.entitlements:
            if not set(entitlement.source_ids).issubset(known_sources):
                raise ValueError("plan entitlement references an unknown source")
            referenced_sources.update(entitlement.source_ids)
        if referenced_sources != known_sources:
            unused = sorted(known_sources - referenced_sources)
            raise ValueError(f"official sources must be referenced; unused={unused}")

        expected = compute_chatgpt_mcp_profile_sha256(
            profile_id=self.profile_id,
            reviewed_at=self.reviewed_at,
            revalidate_after=self.revalidate_after,
            sources=self.sources,
            rows=self.rows,
            entitlements=self.entitlements,
        )
        if self.profile_sha256 != expected:
            raise ValueError("ChatGPT MCP capability profile digest mismatch")
        return self


class McpDeploymentRequest(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    request_id: str = Field(pattern=_ID_PATTERN)
    plan: ChatGptPlan
    role: ChatGptWorkspaceRole
    client: ChatGptClientSurface
    phase: McpDeploymentPhase
    access_mode: McpAccessMode
    server_location: McpServerLocation
    authentication: McpAuthenticationKind
    persistent_connectivity_required: bool = True
    refresh_token_capability: RefreshTokenCapability
    require_chat_enumeration: bool = False
    require_project_enumeration: bool = False
    require_agent_mode: bool = False
    require_deep_research_write: bool = False
    developer_mode_enabled: bool
    app_configured: bool
    workspace_app_access_granted: bool
    requested_at: datetime

    _aware_requested_at = field_validator("requested_at")(_require_aware)

    @model_validator(mode="after")
    def validate_authentication(self) -> "McpDeploymentRequest":
        if self.authentication is McpAuthenticationKind.NONE:
            if self.refresh_token_capability is not RefreshTokenCapability.NOT_APPLICABLE:
                raise ValueError(
                    "authentication=none requires refresh_token_capability=not_applicable"
                )
        elif self.authentication in (
            McpAuthenticationKind.OAUTH,
            McpAuthenticationKind.OPENID_CONNECT,
        ):
            if self.refresh_token_capability is RefreshTokenCapability.NOT_APPLICABLE:
                raise ValueError("OAuth/OIDC requires an explicit refresh-token capability")
        elif self.refresh_token_capability is not RefreshTokenCapability.UNKNOWN:
            raise ValueError("unknown authentication requires unknown refresh-token capability")
        return self


class McpDeploymentDecision(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    request_id: str = Field(pattern=_ID_PATTERN)
    allowed: bool
    reasons: tuple[McpDecisionReason, ...] = Field(min_length=1, max_length=24)
    selected_transport: McpTransportKind | None
    requires_developer_mode: bool
    requires_admin_or_owner: bool
    user_selects_app_in_current_chat: Literal[True] = True
    automatic_chat_enumeration: Literal[False] = False
    automatic_project_enumeration: Literal[False] = False
    chatgpt_account_credentials_used_by_mcp: Literal[False] = False
    evidence_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    evaluated_at: datetime

    _aware_evaluated_at = field_validator("evaluated_at")(_require_aware)

    @model_validator(mode="after")
    def validate_decision(self) -> "McpDeploymentDecision":
        _validate_sorted_unique_enum_tuple(self.reasons, field_name="decision reasons")
        approved = {
            McpDecisionReason.APPROVED_READ_FETCH,
            McpDecisionReason.APPROVED_WRITE_MODIFY,
        }
        approved_reasons = approved.intersection(self.reasons)
        if self.allowed:
            if len(approved_reasons) != 1:
                raise ValueError("allowed decisions require exactly one approval reason")
            if self.selected_transport is None:
                raise ValueError("allowed decisions require a selected transport")
            if len(self.reasons) != 1:
                raise ValueError("allowed decisions cannot contain refusal reasons")
        else:
            if approved_reasons:
                raise ValueError("refused decisions cannot contain an approval reason")
            if self.selected_transport is not None:
                raise ValueError("refused decisions cannot select a transport")
        return self


def commit_official_source_reference(
    *,
    source_id: str,
    title: str,
    url: str,
    section: str,
    evidence_statement: str,
    reviewed_at: datetime,
) -> OfficialSourceReference:
    reviewed_at = _require_aware(reviewed_at)
    payload = {
        "source_id": source_id,
        "title": title,
        "url": url,
        "section": section,
        "evidence_statement": evidence_statement,
        "reviewed_at": reviewed_at.isoformat().replace("+00:00", "Z"),
    }
    return OfficialSourceReference(
        source_id=source_id,
        title=title,
        url=url,
        section=section,
        evidence_statement=evidence_statement,
        reviewed_at=reviewed_at,
        statement_sha256=sha256(_SOURCE_DOMAIN + _canonical_json(payload)).hexdigest(),
    )


def compute_chatgpt_mcp_profile_sha256(
    *,
    profile_id: str,
    reviewed_at: datetime,
    revalidate_after: datetime,
    sources: tuple[OfficialSourceReference, ...],
    rows: tuple[McpCapabilityMatrixRow, ...],
    entitlements: tuple[McpPlanEntitlement, ...],
) -> str:
    reviewed_at = _require_aware(reviewed_at)
    revalidate_after = _require_aware(revalidate_after)
    payload = {
        "version": "1",
        "profile_id": profile_id,
        "provider": "chatgpt",
        "surface": "custom_mcp_app",
        "lifecycle": "beta",
        "reviewed_at": reviewed_at.isoformat().replace("+00:00", "Z"),
        "revalidate_after": revalidate_after.isoformat().replace("+00:00", "Z"),
        "sources": [source.model_dump(mode="json") for source in sources],
        "rows": [row.model_dump(mode="json") for row in rows],
        "entitlements": [item.model_dump(mode="json") for item in entitlements],
    }
    return sha256(_PROFILE_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_chatgpt_mcp_capability_profile(
    *,
    profile_id: str,
    reviewed_at: datetime,
    revalidate_after: datetime,
    sources: tuple[OfficialSourceReference, ...],
    rows: tuple[McpCapabilityMatrixRow, ...],
    entitlements: tuple[McpPlanEntitlement, ...],
) -> ChatGptMcpCapabilityProfile:
    sources = tuple(sorted(sources, key=lambda item: item.source_id))
    rows = tuple(sorted(rows, key=lambda item: item.capability.value))
    entitlements = tuple(
        sorted(
            entitlements,
            key=lambda item: (item.plan.value, item.phase.value, item.access_mode.value),
        )
    )
    return ChatGptMcpCapabilityProfile(
        profile_id=profile_id,
        reviewed_at=reviewed_at,
        revalidate_after=revalidate_after,
        sources=sources,
        rows=rows,
        entitlements=entitlements,
        profile_sha256=compute_chatgpt_mcp_profile_sha256(
            profile_id=profile_id,
            reviewed_at=reviewed_at,
            revalidate_after=revalidate_after,
            sources=sources,
            rows=rows,
            entitlements=entitlements,
        ),
    )
