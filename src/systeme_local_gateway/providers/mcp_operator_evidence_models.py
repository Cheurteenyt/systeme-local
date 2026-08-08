from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator
from ._canonicalization import (
    _canonical_json,
    _require_aware,
    _validate_sorted_unique_enum_tuple,
)


from .mcp_deployment_models import (
    ChatGptClientSurface,
    ChatGptPlan,
    ChatGptWorkspaceRole,
    McpAuthenticationKind,
    McpDeploymentRequest,
    McpServerLocation,
    McpTransportKind,
    RefreshTokenCapability,
)
from .mcp_readiness_models import (
    McpConnectionReadinessDecision,
    McpConnectionReadinessObservation,
    McpReadinessCheckId,
    McpReadinessCheckState,
)
from .models import StrictModel

_ID_PATTERN = r"^[a-z][a-z0-9_]{2,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_RECORD_DOMAIN = b"systeme-local:chatgpt-mcp-operator-evidence-record:v1\x00"
_TRANSPORT_DOMAIN = b"systeme-local:chatgpt-mcp-transport-evidence-summary:v1\x00"
_AUTH_DOMAIN = b"systeme-local:chatgpt-mcp-auth-evidence-summary:v1\x00"
_TOOL_DOMAIN = b"systeme-local:chatgpt-mcp-tool-review-evidence-summary:v1\x00"
_BUNDLE_DOMAIN = b"systeme-local:chatgpt-mcp-operator-evidence-bundle:v1\x00"
_COMPILATION_DOMAIN = b"systeme-local:chatgpt-mcp-operator-evidence-compilation:v1\x00"
_EVALUATION_DOMAIN = b"systeme-local:chatgpt-mcp-operator-evidence-evaluation:v1\x00"


class McpOperatorEvidenceAssertion(StrEnum):
    ACTION_REVIEW_COMPLETED = "action_review_completed"
    APP_CONFIGURATION_CONFIRMED = "app_configuration_confirmed"
    AUTHENTICATION_METADATA_SANITIZED = "authentication_metadata_sanitized"
    DEVELOPER_MODE_CONFIRMED = "developer_mode_confirmed"
    LOCAL_POLICY_PINNED = "local_policy_pinned"
    PLAN_ROLE_CONFIRMED = "plan_role_confirmed"
    REFRESH_TOKEN_CAPABILITY_CONFIRMED = "refresh_token_capability_confirmed"
    TOOL_SNAPSHOT_REVIEWED = "tool_snapshot_reviewed"
    TRANSPORT_CLASS_CONFIRMED = "transport_class_confirmed"
    WEB_CLIENT_CONFIRMED = "web_client_confirmed"
    WORKSPACE_ACCESS_CONFIRMED = "workspace_access_confirmed"


class McpOperatorEvidenceSource(StrEnum):
    NONE = "none"
    ACTION_REVIEW_SNAPSHOT = "action_review_snapshot"
    LOCAL_POLICY_SNAPSHOT = "local_policy_snapshot"
    OPERATOR_ATTESTATION = "operator_attestation"
    PUBLIC_ENDPOINT_ATTESTATION = "public_endpoint_attestation"
    SANITIZED_METADATA_DIGEST = "sanitized_metadata_digest"
    SANITIZED_UI_EXPORT_DIGEST = "sanitized_ui_export_digest"
    SECURE_TUNNEL_ATTESTATION = "secure_tunnel_attestation"
    TOOL_SCAN_SNAPSHOT = "tool_scan_snapshot"
    WORKSPACE_ADMIN_ATTESTATION = "workspace_admin_attestation"


class McpOperatorEvidenceFailureCode(StrEnum):
    ACTION_REVIEW_INCOMPLETE = "ACTION_REVIEW_INCOMPLETE"
    APP_NOT_CONFIGURED = "APP_NOT_CONFIGURED"
    AUTHENTICATION_METADATA_INVALID = "AUTHENTICATION_METADATA_INVALID"
    DEVELOPER_MODE_DISABLED = "DEVELOPER_MODE_DISABLED"
    LOCAL_POLICY_DIGEST_MISMATCH = "LOCAL_POLICY_DIGEST_MISMATCH"
    PLAN_ROLE_NOT_CONFIRMED = "PLAN_ROLE_NOT_CONFIRMED"
    REFRESH_TOKEN_CAPABILITY_MISSING = "REFRESH_TOKEN_CAPABILITY_MISSING"
    TOOL_SNAPSHOT_NOT_REVIEWED = "TOOL_SNAPSHOT_NOT_REVIEWED"
    TRANSPORT_ATTESTATION_FAILED = "TRANSPORT_ATTESTATION_FAILED"
    WEB_CLIENT_UNAVAILABLE = "WEB_CLIENT_UNAVAILABLE"
    WORKSPACE_ACCESS_NOT_GRANTED = "WORKSPACE_ACCESS_NOT_GRANTED"


_ASSERTION_BY_CHECK = {
    McpReadinessCheckId.ACTION_REVIEW: McpOperatorEvidenceAssertion.ACTION_REVIEW_COMPLETED,
    McpReadinessCheckId.APP_CONFIGURATION: (
        McpOperatorEvidenceAssertion.APP_CONFIGURATION_CONFIRMED
    ),
    McpReadinessCheckId.AUTHENTICATION_METADATA: (
        McpOperatorEvidenceAssertion.AUTHENTICATION_METADATA_SANITIZED
    ),
    McpReadinessCheckId.DEVELOPER_MODE: (McpOperatorEvidenceAssertion.DEVELOPER_MODE_CONFIRMED),
    McpReadinessCheckId.LOCAL_POLICY: McpOperatorEvidenceAssertion.LOCAL_POLICY_PINNED,
    McpReadinessCheckId.PLAN_ROLE_OBSERVATION: (McpOperatorEvidenceAssertion.PLAN_ROLE_CONFIRMED),
    McpReadinessCheckId.REFRESH_TOKEN: (
        McpOperatorEvidenceAssertion.REFRESH_TOKEN_CAPABILITY_CONFIRMED
    ),
    McpReadinessCheckId.TOOL_SNAPSHOT: (McpOperatorEvidenceAssertion.TOOL_SNAPSHOT_REVIEWED),
    McpReadinessCheckId.TRANSPORT: McpOperatorEvidenceAssertion.TRANSPORT_CLASS_CONFIRMED,
    McpReadinessCheckId.WEB_CLIENT: McpOperatorEvidenceAssertion.WEB_CLIENT_CONFIRMED,
    McpReadinessCheckId.WORKSPACE_ACCESS: (McpOperatorEvidenceAssertion.WORKSPACE_ACCESS_CONFIRMED),
}

_FAILURE_BY_CHECK = {
    McpReadinessCheckId.ACTION_REVIEW: (McpOperatorEvidenceFailureCode.ACTION_REVIEW_INCOMPLETE),
    McpReadinessCheckId.APP_CONFIGURATION: McpOperatorEvidenceFailureCode.APP_NOT_CONFIGURED,
    McpReadinessCheckId.AUTHENTICATION_METADATA: (
        McpOperatorEvidenceFailureCode.AUTHENTICATION_METADATA_INVALID
    ),
    McpReadinessCheckId.DEVELOPER_MODE: (McpOperatorEvidenceFailureCode.DEVELOPER_MODE_DISABLED),
    McpReadinessCheckId.LOCAL_POLICY: (McpOperatorEvidenceFailureCode.LOCAL_POLICY_DIGEST_MISMATCH),
    McpReadinessCheckId.PLAN_ROLE_OBSERVATION: (
        McpOperatorEvidenceFailureCode.PLAN_ROLE_NOT_CONFIRMED
    ),
    McpReadinessCheckId.REFRESH_TOKEN: (
        McpOperatorEvidenceFailureCode.REFRESH_TOKEN_CAPABILITY_MISSING
    ),
    McpReadinessCheckId.TOOL_SNAPSHOT: (McpOperatorEvidenceFailureCode.TOOL_SNAPSHOT_NOT_REVIEWED),
    McpReadinessCheckId.TRANSPORT: (McpOperatorEvidenceFailureCode.TRANSPORT_ATTESTATION_FAILED),
    McpReadinessCheckId.WEB_CLIENT: (McpOperatorEvidenceFailureCode.WEB_CLIENT_UNAVAILABLE),
    McpReadinessCheckId.WORKSPACE_ACCESS: (
        McpOperatorEvidenceFailureCode.WORKSPACE_ACCESS_NOT_GRANTED
    ),
}

_ALLOWED_SOURCES = {
    McpReadinessCheckId.ACTION_REVIEW: {
        McpOperatorEvidenceSource.ACTION_REVIEW_SNAPSHOT,
    },
    McpReadinessCheckId.APP_CONFIGURATION: {
        McpOperatorEvidenceSource.OPERATOR_ATTESTATION,
        McpOperatorEvidenceSource.SANITIZED_UI_EXPORT_DIGEST,
        McpOperatorEvidenceSource.WORKSPACE_ADMIN_ATTESTATION,
    },
    McpReadinessCheckId.AUTHENTICATION_METADATA: {
        McpOperatorEvidenceSource.SANITIZED_METADATA_DIGEST,
    },
    McpReadinessCheckId.DEVELOPER_MODE: {
        McpOperatorEvidenceSource.OPERATOR_ATTESTATION,
        McpOperatorEvidenceSource.SANITIZED_UI_EXPORT_DIGEST,
        McpOperatorEvidenceSource.WORKSPACE_ADMIN_ATTESTATION,
    },
    McpReadinessCheckId.LOCAL_POLICY: {
        McpOperatorEvidenceSource.LOCAL_POLICY_SNAPSHOT,
    },
    McpReadinessCheckId.PLAN_ROLE_OBSERVATION: {
        McpOperatorEvidenceSource.OPERATOR_ATTESTATION,
        McpOperatorEvidenceSource.SANITIZED_UI_EXPORT_DIGEST,
        McpOperatorEvidenceSource.WORKSPACE_ADMIN_ATTESTATION,
    },
    McpReadinessCheckId.REFRESH_TOKEN: {
        McpOperatorEvidenceSource.SANITIZED_METADATA_DIGEST,
    },
    McpReadinessCheckId.TOOL_SNAPSHOT: {
        McpOperatorEvidenceSource.TOOL_SCAN_SNAPSHOT,
    },
    McpReadinessCheckId.TRANSPORT: {
        McpOperatorEvidenceSource.PUBLIC_ENDPOINT_ATTESTATION,
        McpOperatorEvidenceSource.SECURE_TUNNEL_ATTESTATION,
    },
    McpReadinessCheckId.WEB_CLIENT: {
        McpOperatorEvidenceSource.OPERATOR_ATTESTATION,
        McpOperatorEvidenceSource.SANITIZED_UI_EXPORT_DIGEST,
    },
    McpReadinessCheckId.WORKSPACE_ACCESS: {
        McpOperatorEvidenceSource.SANITIZED_UI_EXPORT_DIGEST,
        McpOperatorEvidenceSource.WORKSPACE_ADMIN_ATTESTATION,
    },
}

_MAX_VALIDITY = {
    McpReadinessCheckId.ACTION_REVIEW: timedelta(minutes=30),
    McpReadinessCheckId.APP_CONFIGURATION: timedelta(hours=1),
    McpReadinessCheckId.AUTHENTICATION_METADATA: timedelta(hours=1),
    McpReadinessCheckId.DEVELOPER_MODE: timedelta(hours=1),
    McpReadinessCheckId.LOCAL_POLICY: timedelta(hours=24),
    McpReadinessCheckId.PLAN_ROLE_OBSERVATION: timedelta(hours=24),
    McpReadinessCheckId.REFRESH_TOKEN: timedelta(hours=1),
    McpReadinessCheckId.TOOL_SNAPSHOT: timedelta(minutes=30),
    McpReadinessCheckId.TRANSPORT: timedelta(minutes=15),
    McpReadinessCheckId.WEB_CLIENT: timedelta(hours=4),
    McpReadinessCheckId.WORKSPACE_ACCESS: timedelta(hours=1),
}


class McpOperatorEvidenceRecord(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    record_id: str = Field(pattern=_ID_PATTERN)
    check_id: McpReadinessCheckId
    assertion: McpOperatorEvidenceAssertion
    state: McpReadinessCheckState
    source: McpOperatorEvidenceSource
    evidence_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    failure_code: McpOperatorEvidenceFailureCode | None = None
    collector_id: str = Field(pattern=_ID_PATTERN)
    collection_session_id: str = Field(pattern=_ID_PATTERN)
    observed_at: datetime
    valid_until: datetime
    raw_evidence_stored: Literal[False] = False
    secret_material_stored: Literal[False] = False
    record_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_observed_at = field_validator("observed_at")(_require_aware)
    _aware_valid_until = field_validator("valid_until")(_require_aware)

    @model_validator(mode="after")
    def validate_record(self) -> "McpOperatorEvidenceRecord":
        if self.assertion is not _ASSERTION_BY_CHECK[self.check_id]:
            raise ValueError("operator evidence assertion does not match check_id")
        if self.valid_until <= self.observed_at:
            raise ValueError("valid_until must follow observed_at")
        if self.valid_until - self.observed_at > _MAX_VALIDITY[self.check_id]:
            raise ValueError("operator evidence validity exceeds the check freshness window")

        if self.state in (
            McpReadinessCheckState.VERIFIED,
            McpReadinessCheckState.FAILED,
        ):
            if self.source is McpOperatorEvidenceSource.NONE:
                raise ValueError("verified and failed operator evidence requires a source")
            if self.source not in _ALLOWED_SOURCES[self.check_id]:
                raise ValueError("operator evidence source is incompatible with check_id")
            if self.evidence_sha256 is None:
                raise ValueError("verified and failed operator evidence requires evidence_sha256")
        else:
            if self.source is not McpOperatorEvidenceSource.NONE:
                raise ValueError("unknown or not-applicable evidence requires source=none")
            if self.evidence_sha256 is not None:
                raise ValueError("unknown or not-applicable evidence cannot carry a digest")

        if self.state is McpReadinessCheckState.FAILED:
            if self.failure_code is not _FAILURE_BY_CHECK[self.check_id]:
                raise ValueError("failed operator evidence requires the exact typed failure code")
        elif self.failure_code is not None:
            raise ValueError("only failed operator evidence may carry failure_code")

        expected = compute_mcp_operator_evidence_record_sha256(
            record_id=self.record_id,
            check_id=self.check_id,
            assertion=self.assertion,
            state=self.state,
            source=self.source,
            evidence_sha256=self.evidence_sha256,
            failure_code=self.failure_code,
            collector_id=self.collector_id,
            collection_session_id=self.collection_session_id,
            observed_at=self.observed_at,
            valid_until=self.valid_until,
        )
        if self.record_sha256 != expected:
            raise ValueError("MCP operator evidence record digest mismatch")
        return self


class McpTransportEvidenceSummary(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    summary_id: str = Field(pattern=_ID_PATTERN)
    server_location: McpServerLocation
    selected_transport: McpTransportKind
    endpoint_origin_sha256: str = Field(pattern=_SHA256_PATTERN)
    tls_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    secure_tunnel_receipt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    public_endpoint_receipt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    observed_at: datetime
    valid_until: datetime
    endpoint_value_stored: Literal[False] = False
    secret_material_stored: Literal[False] = False
    summary_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_observed_at = field_validator("observed_at")(_require_aware)
    _aware_valid_until = field_validator("valid_until")(_require_aware)

    @model_validator(mode="after")
    def validate_summary(self) -> "McpTransportEvidenceSummary":
        if self.server_location is McpServerLocation.UNKNOWN:
            raise ValueError("transport evidence cannot use an unknown server location")
        if self.valid_until <= self.observed_at:
            raise ValueError("transport valid_until must follow observed_at")
        if self.valid_until - self.observed_at > timedelta(minutes=15):
            raise ValueError("transport evidence expires within fifteen minutes")
        if self.server_location is McpServerLocation.PUBLIC_REMOTE:
            if self.selected_transport is not McpTransportKind.REMOTE_DIRECT:
                raise ValueError("public remote evidence requires remote_direct")
            if self.public_endpoint_receipt_sha256 is None:
                raise ValueError("public remote evidence requires a public endpoint receipt")
            if self.secure_tunnel_receipt_sha256 is not None:
                raise ValueError("public remote evidence cannot carry a tunnel receipt")
        else:
            if self.selected_transport is not McpTransportKind.SECURE_MCP_TUNNEL:
                raise ValueError("private or local evidence requires secure_mcp_tunnel")
            if self.secure_tunnel_receipt_sha256 is None:
                raise ValueError("secure tunnel evidence requires a tunnel receipt")
            if self.public_endpoint_receipt_sha256 is not None:
                raise ValueError("secure tunnel evidence cannot carry a public endpoint receipt")
        expected = compute_mcp_transport_evidence_summary_sha256(
            summary_id=self.summary_id,
            server_location=self.server_location,
            selected_transport=self.selected_transport,
            endpoint_origin_sha256=self.endpoint_origin_sha256,
            tls_profile_sha256=self.tls_profile_sha256,
            secure_tunnel_receipt_sha256=self.secure_tunnel_receipt_sha256,
            public_endpoint_receipt_sha256=self.public_endpoint_receipt_sha256,
            observed_at=self.observed_at,
            valid_until=self.valid_until,
        )
        if self.summary_sha256 != expected:
            raise ValueError("MCP transport evidence summary digest mismatch")
        return self


class McpAuthenticationEvidenceSummary(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    summary_id: str = Field(pattern=_ID_PATTERN)
    authentication: McpAuthenticationKind
    issuer_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_metadata_sha256: str = Field(pattern=_SHA256_PATTERN)
    authorization_endpoint_sha256: str = Field(pattern=_SHA256_PATTERN)
    token_endpoint_sha256: str = Field(pattern=_SHA256_PATTERN)
    scopes_supported_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_capability_advertised: bool
    refresh_tokens_issued: bool
    observed_at: datetime
    valid_until: datetime
    metadata_content_stored: Literal[False] = False
    client_credentials_stored: Literal[False] = False
    summary_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_observed_at = field_validator("observed_at")(_require_aware)
    _aware_valid_until = field_validator("valid_until")(_require_aware)

    @model_validator(mode="after")
    def validate_summary(self) -> "McpAuthenticationEvidenceSummary":
        if self.authentication not in (
            McpAuthenticationKind.OAUTH,
            McpAuthenticationKind.OPENID_CONNECT,
        ):
            raise ValueError("authentication evidence requires OAuth or OpenID Connect")
        if self.valid_until <= self.observed_at:
            raise ValueError("authentication valid_until must follow observed_at")
        if self.valid_until - self.observed_at > timedelta(hours=1):
            raise ValueError("authentication evidence expires within one hour")
        if self.refresh_tokens_issued and not self.refresh_capability_advertised:
            raise ValueError("issued refresh tokens require advertised refresh capability")
        expected = compute_mcp_authentication_evidence_summary_sha256(
            summary_id=self.summary_id,
            authentication=self.authentication,
            issuer_sha256=self.issuer_sha256,
            discovery_metadata_sha256=self.discovery_metadata_sha256,
            authorization_endpoint_sha256=self.authorization_endpoint_sha256,
            token_endpoint_sha256=self.token_endpoint_sha256,
            scopes_supported_sha256=self.scopes_supported_sha256,
            refresh_capability_advertised=self.refresh_capability_advertised,
            refresh_tokens_issued=self.refresh_tokens_issued,
            observed_at=self.observed_at,
            valid_until=self.valid_until,
        )
        if self.summary_sha256 != expected:
            raise ValueError("MCP authentication evidence summary digest mismatch")
        return self


class McpToolReviewEvidenceSummary(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    summary_id: str = Field(pattern=_ID_PATTERN)
    tool_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    tool_count: int = Field(ge=0, le=1024)
    write_tool_count: int = Field(ge=0, le=1024)
    high_risk_tool_count: int = Field(ge=0, le=1024)
    action_review_sha256: str = Field(pattern=_SHA256_PATTERN)
    observed_at: datetime
    valid_until: datetime
    raw_tool_definitions_stored: Literal[False] = False
    secret_material_stored: Literal[False] = False
    summary_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_observed_at = field_validator("observed_at")(_require_aware)
    _aware_valid_until = field_validator("valid_until")(_require_aware)

    @model_validator(mode="after")
    def validate_summary(self) -> "McpToolReviewEvidenceSummary":
        if self.write_tool_count > self.tool_count:
            raise ValueError("write_tool_count cannot exceed tool_count")
        if self.high_risk_tool_count > self.tool_count:
            raise ValueError("high_risk_tool_count cannot exceed tool_count")
        if self.valid_until <= self.observed_at:
            raise ValueError("tool review valid_until must follow observed_at")
        if self.valid_until - self.observed_at > timedelta(minutes=30):
            raise ValueError("tool review evidence expires within thirty minutes")
        expected = compute_mcp_tool_review_evidence_summary_sha256(
            summary_id=self.summary_id,
            tool_snapshot_sha256=self.tool_snapshot_sha256,
            tool_count=self.tool_count,
            write_tool_count=self.write_tool_count,
            high_risk_tool_count=self.high_risk_tool_count,
            action_review_sha256=self.action_review_sha256,
            observed_at=self.observed_at,
            valid_until=self.valid_until,
        )
        if self.summary_sha256 != expected:
            raise ValueError("MCP tool review evidence summary digest mismatch")
        return self


class McpOperatorEvidenceBundle(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    bundle_id: str = Field(pattern=_ID_PATTERN)
    request: McpDeploymentRequest
    capability_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    reconciliation_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    records: tuple[McpOperatorEvidenceRecord, ...] = Field(min_length=1, max_length=32)
    transport_summary: McpTransportEvidenceSummary | None = None
    authentication_summary: McpAuthenticationEvidenceSummary | None = None
    tool_review_summary: McpToolReviewEvidenceSummary | None = None
    local_policy_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    collected_at: datetime
    expires_at: datetime
    raw_endpoint_values_stored: Literal[False] = False
    raw_metadata_documents_stored: Literal[False] = False
    raw_tool_definitions_stored: Literal[False] = False
    real_connection_established: Literal[False] = False
    secrets_stored: Literal[False] = False
    bundle_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_collected_at = field_validator("collected_at")(_require_aware)
    _aware_expires_at = field_validator("expires_at")(_require_aware)

    @model_validator(mode="after")
    def validate_bundle(self) -> "McpOperatorEvidenceBundle":
        if self.expires_at <= self.collected_at:
            raise ValueError("bundle expires_at must follow collected_at")
        if self.expires_at - self.collected_at > timedelta(minutes=15):
            raise ValueError("operator evidence bundles expire within fifteen minutes")

        check_ids = tuple(record.check_id for record in self.records)
        _validate_sorted_unique_enum_tuple(check_ids, field_name="operator evidence check ids")
        if set(check_ids) != set(McpReadinessCheckId):
            missing = sorted(item.value for item in set(McpReadinessCheckId) - set(check_ids))
            extra = sorted(item.value for item in set(check_ids) - set(McpReadinessCheckId))
            raise ValueError(
                "operator evidence bundle must contain every check exactly once; "
                f"missing={missing}, extra={extra}"
            )
        for record in self.records:
            if record.observed_at > self.collected_at:
                raise ValueError("operator evidence records cannot postdate collected_at")
            if self.expires_at > record.valid_until:
                raise ValueError("bundle expiry cannot exceed a record validity window")

        by_id = {record.check_id: record for record in self.records}
        self._validate_request_bound_records(by_id)
        self._validate_transport(by_id)
        self._validate_authentication(by_id)
        self._validate_tool_review(by_id)
        self._validate_local_policy(by_id)

        expected = compute_mcp_operator_evidence_bundle_sha256(
            bundle_id=self.bundle_id,
            request=self.request,
            capability_profile_sha256=self.capability_profile_sha256,
            reconciliation_profile_sha256=self.reconciliation_profile_sha256,
            records=self.records,
            transport_summary=self.transport_summary,
            authentication_summary=self.authentication_summary,
            tool_review_summary=self.tool_review_summary,
            local_policy_sha256=self.local_policy_sha256,
            collected_at=self.collected_at,
            expires_at=self.expires_at,
        )
        if self.bundle_sha256 != expected:
            raise ValueError("MCP operator evidence bundle digest mismatch")
        return self

    def _validate_request_bound_records(
        self,
        by_id: dict[McpReadinessCheckId, McpOperatorEvidenceRecord],
    ) -> None:
        verified = McpReadinessCheckState.VERIFIED
        failed = McpReadinessCheckState.FAILED

        plan_role = by_id[McpReadinessCheckId.PLAN_ROLE_OBSERVATION]
        if plan_role.state is verified and (
            self.request.plan is ChatGptPlan.UNKNOWN
            or self.request.role is ChatGptWorkspaceRole.UNKNOWN
        ):
            raise ValueError("verified plan/role evidence cannot bind unknown values")

        web_client = by_id[McpReadinessCheckId.WEB_CLIENT]
        if web_client.state is verified and self.request.client is not ChatGptClientSurface.WEB:
            raise ValueError("verified web-client evidence requires client=web")

        developer_mode = by_id[McpReadinessCheckId.DEVELOPER_MODE]
        if developer_mode.state is verified and not self.request.developer_mode_enabled:
            raise ValueError("verified developer-mode evidence requires the request gate")
        if developer_mode.state is failed and self.request.developer_mode_enabled:
            raise ValueError("failed developer-mode evidence conflicts with the request gate")

        app_configuration = by_id[McpReadinessCheckId.APP_CONFIGURATION]
        if app_configuration.state is verified and not self.request.app_configured:
            raise ValueError("verified app configuration requires the request gate")
        if app_configuration.state is failed and self.request.app_configured:
            raise ValueError("failed app configuration conflicts with the request gate")

        workspace_access = by_id[McpReadinessCheckId.WORKSPACE_ACCESS]
        if workspace_access.state is verified and not self.request.workspace_app_access_granted:
            raise ValueError("verified workspace access requires the request gate")
        if workspace_access.state is failed and self.request.workspace_app_access_granted:
            raise ValueError("failed workspace access conflicts with the request gate")

    def _validate_transport(
        self,
        by_id: dict[McpReadinessCheckId, McpOperatorEvidenceRecord],
    ) -> None:
        record = by_id[McpReadinessCheckId.TRANSPORT]
        verified = record.state is McpReadinessCheckState.VERIFIED
        if verified:
            if self.transport_summary is None:
                raise ValueError("verified transport evidence requires a transport summary")
            if record.evidence_sha256 != self.transport_summary.summary_sha256:
                raise ValueError("transport record must bind the transport summary digest")
            if self.transport_summary.server_location is not self.request.server_location:
                raise ValueError("transport summary server location does not match the request")
        elif self.transport_summary is not None:
            raise ValueError("unverified transport evidence cannot carry a transport summary")

    def _validate_authentication(
        self,
        by_id: dict[McpReadinessCheckId, McpOperatorEvidenceRecord],
    ) -> None:
        metadata = by_id[McpReadinessCheckId.AUTHENTICATION_METADATA]
        refresh = by_id[McpReadinessCheckId.REFRESH_TOKEN]
        auth_uses_metadata = self.request.authentication in (
            McpAuthenticationKind.OAUTH,
            McpAuthenticationKind.OPENID_CONNECT,
        )
        if not auth_uses_metadata:
            if self.authentication_summary is not None:
                raise ValueError("non-OAuth requests cannot carry authentication metadata")
            if metadata.state is not McpReadinessCheckState.NOT_APPLICABLE:
                raise ValueError(
                    "non-OAuth requests require authentication metadata not_applicable"
                )
            if refresh.state is not McpReadinessCheckState.NOT_APPLICABLE:
                raise ValueError("non-OAuth requests require refresh-token not_applicable")
            return

        metadata_verified = metadata.state is McpReadinessCheckState.VERIFIED
        if metadata_verified:
            if self.authentication_summary is None:
                raise ValueError("verified authentication metadata requires a summary")
            if metadata.evidence_sha256 != self.authentication_summary.summary_sha256:
                raise ValueError("authentication metadata record must bind the summary digest")
            if self.authentication_summary.authentication is not self.request.authentication:
                raise ValueError("authentication summary kind does not match the request")
        elif self.authentication_summary is not None:
            raise ValueError("unverified authentication metadata cannot carry a summary")

        if not self.request.persistent_connectivity_required:
            if refresh.state is not McpReadinessCheckState.NOT_APPLICABLE:
                raise ValueError("non-persistent requests require refresh-token not_applicable")
            return

        if refresh.state is McpReadinessCheckState.VERIFIED:
            if self.authentication_summary is None:
                raise ValueError("verified refresh capability requires authentication metadata")
            if refresh.evidence_sha256 != self.authentication_summary.summary_sha256:
                raise ValueError("refresh-token record must bind the authentication summary")
            if not self.authentication_summary.refresh_capability_advertised:
                raise ValueError("verified refresh evidence requires advertised capability")
            if not self.authentication_summary.refresh_tokens_issued:
                raise ValueError("verified refresh evidence requires issued refresh tokens")
            if self.request.refresh_token_capability is not RefreshTokenCapability.ISSUED:
                raise ValueError("verified refresh evidence requires request capability=issued")
        elif self.request.refresh_token_capability is RefreshTokenCapability.ISSUED:
            raise ValueError("request capability=issued requires verified refresh evidence")

    def _validate_tool_review(
        self,
        by_id: dict[McpReadinessCheckId, McpOperatorEvidenceRecord],
    ) -> None:
        tool = by_id[McpReadinessCheckId.TOOL_SNAPSHOT]
        action = by_id[McpReadinessCheckId.ACTION_REVIEW]
        tool_verified = tool.state is McpReadinessCheckState.VERIFIED
        action_verified = action.state is McpReadinessCheckState.VERIFIED
        if tool_verified or action_verified:
            if self.tool_review_summary is None:
                raise ValueError("verified tool or action evidence requires a tool review summary")
            if tool_verified and tool.evidence_sha256 != self.tool_review_summary.summary_sha256:
                raise ValueError("tool-snapshot record must bind the tool review summary")
            if action_verified and (
                action.evidence_sha256 != self.tool_review_summary.action_review_sha256
            ):
                raise ValueError("action-review record must bind action_review_sha256")
        elif self.tool_review_summary is not None:
            raise ValueError("unverified tool and action evidence cannot carry a summary")

    def _validate_local_policy(
        self,
        by_id: dict[McpReadinessCheckId, McpOperatorEvidenceRecord],
    ) -> None:
        record = by_id[McpReadinessCheckId.LOCAL_POLICY]
        verified = record.state is McpReadinessCheckState.VERIFIED
        if verified:
            if self.local_policy_sha256 is None:
                raise ValueError("verified local policy requires local_policy_sha256")
            if record.evidence_sha256 != self.local_policy_sha256:
                raise ValueError("local-policy record must bind local_policy_sha256")
        elif self.local_policy_sha256 is not None:
            raise ValueError("unverified local policy cannot carry a digest")


class McpOperatorEvidenceCompilation(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    compilation_id: str = Field(pattern=_ID_PATTERN)
    bundle_id: str = Field(pattern=_ID_PATTERN)
    bundle_sha256: str = Field(pattern=_SHA256_PATTERN)
    bundle_expires_at: datetime
    observation: McpConnectionReadinessObservation
    compiled_at: datetime
    real_connection_established: Literal[False] = False
    secrets_stored: Literal[False] = False
    compilation_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_bundle_expires_at = field_validator("bundle_expires_at")(_require_aware)
    _aware_compiled_at = field_validator("compiled_at")(_require_aware)

    @model_validator(mode="after")
    def validate_compilation(self) -> "McpOperatorEvidenceCompilation":
        if self.compiled_at > self.bundle_expires_at:
            raise ValueError("operator evidence compilation cannot use an expired bundle")
        if self.observation.observed_at > self.compiled_at:
            raise ValueError("compiled observation cannot postdate compiled_at")
        expected = compute_mcp_operator_evidence_compilation_sha256(
            compilation_id=self.compilation_id,
            bundle_id=self.bundle_id,
            bundle_sha256=self.bundle_sha256,
            bundle_expires_at=self.bundle_expires_at,
            observation=self.observation,
            compiled_at=self.compiled_at,
        )
        if self.compilation_sha256 != expected:
            raise ValueError("MCP operator evidence compilation digest mismatch")
        return self


class McpOperatorEvidenceEvaluation(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    evaluation_id: str = Field(pattern=_ID_PATTERN)
    compilation: McpOperatorEvidenceCompilation
    decision: McpConnectionReadinessDecision
    evaluated_at: datetime
    real_connection_established: Literal[False] = False
    secrets_stored: Literal[False] = False
    evaluation_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_evaluated_at = field_validator("evaluated_at")(_require_aware)

    @model_validator(mode="after")
    def validate_evaluation(self) -> "McpOperatorEvidenceEvaluation":
        if self.evaluated_at != self.decision.evaluated_at:
            raise ValueError("evaluation timestamp must match readiness decision")
        if self.compilation.observation.observation_sha256 != self.decision.observation_sha256:
            raise ValueError("evaluation decision must bind the compiled observation")
        expected = compute_mcp_operator_evidence_evaluation_sha256(
            evaluation_id=self.evaluation_id,
            compilation=self.compilation,
            decision=self.decision,
            evaluated_at=self.evaluated_at,
        )
        if self.evaluation_sha256 != expected:
            raise ValueError("MCP operator evidence evaluation digest mismatch")
        return self


def compute_mcp_operator_evidence_record_sha256(
    *,
    record_id: str,
    check_id: McpReadinessCheckId,
    assertion: McpOperatorEvidenceAssertion,
    state: McpReadinessCheckState,
    source: McpOperatorEvidenceSource,
    evidence_sha256: str | None,
    failure_code: McpOperatorEvidenceFailureCode | None,
    collector_id: str,
    collection_session_id: str,
    observed_at: datetime,
    valid_until: datetime,
) -> str:
    observed_at = _require_aware(observed_at)
    valid_until = _require_aware(valid_until)
    payload = {
        "version": "1",
        "record_id": record_id,
        "check_id": check_id.value,
        "assertion": assertion.value,
        "state": state.value,
        "source": source.value,
        "evidence_sha256": evidence_sha256,
        "failure_code": failure_code.value if failure_code is not None else None,
        "collector_id": collector_id,
        "collection_session_id": collection_session_id,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "valid_until": valid_until.isoformat().replace("+00:00", "Z"),
        "raw_evidence_stored": False,
        "secret_material_stored": False,
    }
    return sha256(_RECORD_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_mcp_operator_evidence_record(
    *,
    record_id: str,
    check_id: McpReadinessCheckId,
    state: McpReadinessCheckState,
    source: McpOperatorEvidenceSource,
    collector_id: str,
    collection_session_id: str,
    observed_at: datetime,
    valid_until: datetime,
    evidence_sha256: str | None = None,
    failure_code: McpOperatorEvidenceFailureCode | None = None,
) -> McpOperatorEvidenceRecord:
    assertion = _ASSERTION_BY_CHECK[check_id]
    return McpOperatorEvidenceRecord(
        record_id=record_id,
        check_id=check_id,
        assertion=assertion,
        state=state,
        source=source,
        evidence_sha256=evidence_sha256,
        failure_code=failure_code,
        collector_id=collector_id,
        collection_session_id=collection_session_id,
        observed_at=observed_at,
        valid_until=valid_until,
        record_sha256=compute_mcp_operator_evidence_record_sha256(
            record_id=record_id,
            check_id=check_id,
            assertion=assertion,
            state=state,
            source=source,
            evidence_sha256=evidence_sha256,
            failure_code=failure_code,
            collector_id=collector_id,
            collection_session_id=collection_session_id,
            observed_at=observed_at,
            valid_until=valid_until,
        ),
    )


def compute_mcp_transport_evidence_summary_sha256(
    *,
    summary_id: str,
    server_location: McpServerLocation,
    selected_transport: McpTransportKind,
    endpoint_origin_sha256: str,
    tls_profile_sha256: str,
    secure_tunnel_receipt_sha256: str | None,
    public_endpoint_receipt_sha256: str | None,
    observed_at: datetime,
    valid_until: datetime,
) -> str:
    observed_at = _require_aware(observed_at)
    valid_until = _require_aware(valid_until)
    payload = {
        "version": "1",
        "summary_id": summary_id,
        "server_location": server_location.value,
        "selected_transport": selected_transport.value,
        "endpoint_origin_sha256": endpoint_origin_sha256,
        "tls_profile_sha256": tls_profile_sha256,
        "secure_tunnel_receipt_sha256": secure_tunnel_receipt_sha256,
        "public_endpoint_receipt_sha256": public_endpoint_receipt_sha256,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "valid_until": valid_until.isoformat().replace("+00:00", "Z"),
        "endpoint_value_stored": False,
        "secret_material_stored": False,
    }
    return sha256(_TRANSPORT_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_mcp_transport_evidence_summary(
    *,
    summary_id: str,
    server_location: McpServerLocation,
    selected_transport: McpTransportKind,
    endpoint_origin_sha256: str,
    tls_profile_sha256: str,
    observed_at: datetime,
    valid_until: datetime,
    secure_tunnel_receipt_sha256: str | None = None,
    public_endpoint_receipt_sha256: str | None = None,
) -> McpTransportEvidenceSummary:
    return McpTransportEvidenceSummary(
        summary_id=summary_id,
        server_location=server_location,
        selected_transport=selected_transport,
        endpoint_origin_sha256=endpoint_origin_sha256,
        tls_profile_sha256=tls_profile_sha256,
        secure_tunnel_receipt_sha256=secure_tunnel_receipt_sha256,
        public_endpoint_receipt_sha256=public_endpoint_receipt_sha256,
        observed_at=observed_at,
        valid_until=valid_until,
        summary_sha256=compute_mcp_transport_evidence_summary_sha256(
            summary_id=summary_id,
            server_location=server_location,
            selected_transport=selected_transport,
            endpoint_origin_sha256=endpoint_origin_sha256,
            tls_profile_sha256=tls_profile_sha256,
            secure_tunnel_receipt_sha256=secure_tunnel_receipt_sha256,
            public_endpoint_receipt_sha256=public_endpoint_receipt_sha256,
            observed_at=observed_at,
            valid_until=valid_until,
        ),
    )


def compute_mcp_authentication_evidence_summary_sha256(
    *,
    summary_id: str,
    authentication: McpAuthenticationKind,
    issuer_sha256: str,
    discovery_metadata_sha256: str,
    authorization_endpoint_sha256: str,
    token_endpoint_sha256: str,
    scopes_supported_sha256: str,
    refresh_capability_advertised: bool,
    refresh_tokens_issued: bool,
    observed_at: datetime,
    valid_until: datetime,
) -> str:
    observed_at = _require_aware(observed_at)
    valid_until = _require_aware(valid_until)
    payload = {
        "version": "1",
        "summary_id": summary_id,
        "authentication": authentication.value,
        "issuer_sha256": issuer_sha256,
        "discovery_metadata_sha256": discovery_metadata_sha256,
        "authorization_endpoint_sha256": authorization_endpoint_sha256,
        "token_endpoint_sha256": token_endpoint_sha256,
        "scopes_supported_sha256": scopes_supported_sha256,
        "refresh_capability_advertised": refresh_capability_advertised,
        "refresh_tokens_issued": refresh_tokens_issued,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "valid_until": valid_until.isoformat().replace("+00:00", "Z"),
        "metadata_content_stored": False,
        "client_credentials_stored": False,
    }
    return sha256(_AUTH_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_mcp_authentication_evidence_summary(
    *,
    summary_id: str,
    authentication: McpAuthenticationKind,
    issuer_sha256: str,
    discovery_metadata_sha256: str,
    authorization_endpoint_sha256: str,
    token_endpoint_sha256: str,
    scopes_supported_sha256: str,
    refresh_capability_advertised: bool,
    refresh_tokens_issued: bool,
    observed_at: datetime,
    valid_until: datetime,
) -> McpAuthenticationEvidenceSummary:
    return McpAuthenticationEvidenceSummary(
        summary_id=summary_id,
        authentication=authentication,
        issuer_sha256=issuer_sha256,
        discovery_metadata_sha256=discovery_metadata_sha256,
        authorization_endpoint_sha256=authorization_endpoint_sha256,
        token_endpoint_sha256=token_endpoint_sha256,
        scopes_supported_sha256=scopes_supported_sha256,
        refresh_capability_advertised=refresh_capability_advertised,
        refresh_tokens_issued=refresh_tokens_issued,
        observed_at=observed_at,
        valid_until=valid_until,
        summary_sha256=compute_mcp_authentication_evidence_summary_sha256(
            summary_id=summary_id,
            authentication=authentication,
            issuer_sha256=issuer_sha256,
            discovery_metadata_sha256=discovery_metadata_sha256,
            authorization_endpoint_sha256=authorization_endpoint_sha256,
            token_endpoint_sha256=token_endpoint_sha256,
            scopes_supported_sha256=scopes_supported_sha256,
            refresh_capability_advertised=refresh_capability_advertised,
            refresh_tokens_issued=refresh_tokens_issued,
            observed_at=observed_at,
            valid_until=valid_until,
        ),
    )


def compute_mcp_tool_review_evidence_summary_sha256(
    *,
    summary_id: str,
    tool_snapshot_sha256: str,
    tool_count: int,
    write_tool_count: int,
    high_risk_tool_count: int,
    action_review_sha256: str,
    observed_at: datetime,
    valid_until: datetime,
) -> str:
    observed_at = _require_aware(observed_at)
    valid_until = _require_aware(valid_until)
    payload = {
        "version": "1",
        "summary_id": summary_id,
        "tool_snapshot_sha256": tool_snapshot_sha256,
        "tool_count": tool_count,
        "write_tool_count": write_tool_count,
        "high_risk_tool_count": high_risk_tool_count,
        "action_review_sha256": action_review_sha256,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "valid_until": valid_until.isoformat().replace("+00:00", "Z"),
        "raw_tool_definitions_stored": False,
        "secret_material_stored": False,
    }
    return sha256(_TOOL_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_mcp_tool_review_evidence_summary(
    *,
    summary_id: str,
    tool_snapshot_sha256: str,
    tool_count: int,
    write_tool_count: int,
    high_risk_tool_count: int,
    action_review_sha256: str,
    observed_at: datetime,
    valid_until: datetime,
) -> McpToolReviewEvidenceSummary:
    return McpToolReviewEvidenceSummary(
        summary_id=summary_id,
        tool_snapshot_sha256=tool_snapshot_sha256,
        tool_count=tool_count,
        write_tool_count=write_tool_count,
        high_risk_tool_count=high_risk_tool_count,
        action_review_sha256=action_review_sha256,
        observed_at=observed_at,
        valid_until=valid_until,
        summary_sha256=compute_mcp_tool_review_evidence_summary_sha256(
            summary_id=summary_id,
            tool_snapshot_sha256=tool_snapshot_sha256,
            tool_count=tool_count,
            write_tool_count=write_tool_count,
            high_risk_tool_count=high_risk_tool_count,
            action_review_sha256=action_review_sha256,
            observed_at=observed_at,
            valid_until=valid_until,
        ),
    )


def compute_mcp_operator_evidence_bundle_sha256(
    *,
    bundle_id: str,
    request: McpDeploymentRequest,
    capability_profile_sha256: str,
    reconciliation_profile_sha256: str,
    records: tuple[McpOperatorEvidenceRecord, ...],
    transport_summary: McpTransportEvidenceSummary | None,
    authentication_summary: McpAuthenticationEvidenceSummary | None,
    tool_review_summary: McpToolReviewEvidenceSummary | None,
    local_policy_sha256: str | None,
    collected_at: datetime,
    expires_at: datetime,
) -> str:
    collected_at = _require_aware(collected_at)
    expires_at = _require_aware(expires_at)
    payload = {
        "version": "1",
        "bundle_id": bundle_id,
        "request": request.model_dump(mode="json"),
        "capability_profile_sha256": capability_profile_sha256,
        "reconciliation_profile_sha256": reconciliation_profile_sha256,
        "records": [record.model_dump(mode="json") for record in records],
        "transport_summary": (
            transport_summary.model_dump(mode="json") if transport_summary is not None else None
        ),
        "authentication_summary": (
            authentication_summary.model_dump(mode="json")
            if authentication_summary is not None
            else None
        ),
        "tool_review_summary": (
            tool_review_summary.model_dump(mode="json") if tool_review_summary is not None else None
        ),
        "local_policy_sha256": local_policy_sha256,
        "collected_at": collected_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "raw_endpoint_values_stored": False,
        "raw_metadata_documents_stored": False,
        "raw_tool_definitions_stored": False,
        "real_connection_established": False,
        "secrets_stored": False,
    }
    return sha256(_BUNDLE_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_mcp_operator_evidence_bundle(
    *,
    bundle_id: str,
    request: McpDeploymentRequest,
    capability_profile_sha256: str,
    reconciliation_profile_sha256: str,
    records: tuple[McpOperatorEvidenceRecord, ...],
    collected_at: datetime,
    expires_at: datetime,
    transport_summary: McpTransportEvidenceSummary | None = None,
    authentication_summary: McpAuthenticationEvidenceSummary | None = None,
    tool_review_summary: McpToolReviewEvidenceSummary | None = None,
    local_policy_sha256: str | None = None,
) -> McpOperatorEvidenceBundle:
    records = tuple(sorted(records, key=lambda item: item.check_id.value))
    return McpOperatorEvidenceBundle(
        bundle_id=bundle_id,
        request=request,
        capability_profile_sha256=capability_profile_sha256,
        reconciliation_profile_sha256=reconciliation_profile_sha256,
        records=records,
        transport_summary=transport_summary,
        authentication_summary=authentication_summary,
        tool_review_summary=tool_review_summary,
        local_policy_sha256=local_policy_sha256,
        collected_at=collected_at,
        expires_at=expires_at,
        bundle_sha256=compute_mcp_operator_evidence_bundle_sha256(
            bundle_id=bundle_id,
            request=request,
            capability_profile_sha256=capability_profile_sha256,
            reconciliation_profile_sha256=reconciliation_profile_sha256,
            records=records,
            transport_summary=transport_summary,
            authentication_summary=authentication_summary,
            tool_review_summary=tool_review_summary,
            local_policy_sha256=local_policy_sha256,
            collected_at=collected_at,
            expires_at=expires_at,
        ),
    )


def compute_mcp_operator_evidence_compilation_sha256(
    *,
    compilation_id: str,
    bundle_id: str,
    bundle_sha256: str,
    bundle_expires_at: datetime,
    observation: McpConnectionReadinessObservation,
    compiled_at: datetime,
) -> str:
    bundle_expires_at = _require_aware(bundle_expires_at)
    compiled_at = _require_aware(compiled_at)
    payload = {
        "version": "1",
        "compilation_id": compilation_id,
        "bundle_id": bundle_id,
        "bundle_sha256": bundle_sha256,
        "bundle_expires_at": bundle_expires_at.isoformat().replace("+00:00", "Z"),
        "observation": observation.model_dump(mode="json"),
        "compiled_at": compiled_at.isoformat().replace("+00:00", "Z"),
        "real_connection_established": False,
        "secrets_stored": False,
    }
    return sha256(_COMPILATION_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_mcp_operator_evidence_compilation(
    *,
    compilation_id: str,
    bundle_id: str,
    bundle_sha256: str,
    bundle_expires_at: datetime,
    observation: McpConnectionReadinessObservation,
    compiled_at: datetime,
) -> McpOperatorEvidenceCompilation:
    return McpOperatorEvidenceCompilation(
        compilation_id=compilation_id,
        bundle_id=bundle_id,
        bundle_sha256=bundle_sha256,
        bundle_expires_at=bundle_expires_at,
        observation=observation,
        compiled_at=compiled_at,
        compilation_sha256=compute_mcp_operator_evidence_compilation_sha256(
            compilation_id=compilation_id,
            bundle_id=bundle_id,
            bundle_sha256=bundle_sha256,
            bundle_expires_at=bundle_expires_at,
            observation=observation,
            compiled_at=compiled_at,
        ),
    )


def compute_mcp_operator_evidence_evaluation_sha256(
    *,
    evaluation_id: str,
    compilation: McpOperatorEvidenceCompilation,
    decision: McpConnectionReadinessDecision,
    evaluated_at: datetime,
) -> str:
    evaluated_at = _require_aware(evaluated_at)
    payload = {
        "version": "1",
        "evaluation_id": evaluation_id,
        "compilation": compilation.model_dump(mode="json"),
        "decision": decision.model_dump(mode="json"),
        "evaluated_at": evaluated_at.isoformat().replace("+00:00", "Z"),
        "real_connection_established": False,
        "secrets_stored": False,
    }
    return sha256(_EVALUATION_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_mcp_operator_evidence_evaluation(
    *,
    evaluation_id: str,
    compilation: McpOperatorEvidenceCompilation,
    decision: McpConnectionReadinessDecision,
    evaluated_at: datetime,
) -> McpOperatorEvidenceEvaluation:
    return McpOperatorEvidenceEvaluation(
        evaluation_id=evaluation_id,
        compilation=compilation,
        decision=decision,
        evaluated_at=evaluated_at,
        evaluation_sha256=compute_mcp_operator_evidence_evaluation_sha256(
            evaluation_id=evaluation_id,
            compilation=compilation,
            decision=decision,
            evaluated_at=evaluated_at,
        ),
    )
