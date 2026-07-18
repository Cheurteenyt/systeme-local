from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from hashlib import sha256
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .mcp_deployment_models import (
    McpDecisionReason,
    McpDeploymentRequest,
    McpTransportKind,
    OfficialSourceReference,
)
from .models import StrictModel

_ID_PATTERN = r"^[a-z][a-z0-9_]{2,127}$"
_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{2,95}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_FINDING_DOMAIN = b"systeme-local:chatgpt-mcp-evidence-finding:v1\x00"
_RECONCILIATION_DOMAIN = b"systeme-local:chatgpt-mcp-evidence-profile:v1\x00"
_CHECK_DOMAIN = b"systeme-local:chatgpt-mcp-readiness-check:v1\x00"
_OBSERVATION_DOMAIN = b"systeme-local:chatgpt-mcp-readiness-observation:v1\x00"


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _validate_sorted_unique_enum_tuple(
    values: tuple[StrEnum, ...],
    *,
    field_name: str,
) -> None:
    rendered = tuple(item.value for item in values)
    if len(rendered) != len(set(rendered)):
        raise ValueError(f"{field_name} must not contain duplicates")
    if rendered != tuple(sorted(rendered)):
        raise ValueError(f"{field_name} must be sorted")


def _validate_sorted_unique_string_tuple(
    values: tuple[str, ...],
    *,
    field_name: str,
) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must not contain duplicates")
    if values != tuple(sorted(values)):
        raise ValueError(f"{field_name} must be sorted")


class McpEvidenceFindingId(StrEnum):
    LOCAL_SERVER_TRANSPORT = "local_server_transport"
    PERSISTENT_OAUTH_REFRESH = "persistent_oauth_refresh"
    PLUS_CUSTOM_MCP_PLAN_SCOPE = "plus_custom_mcp_plan_scope"
    TOOL_SNAPSHOT_DRIFT = "tool_snapshot_drift"
    WRITE_ACTION_CONTROL = "write_action_control"


class McpEvidenceFindingStatus(StrEnum):
    CONSISTENT = "consistent"
    AMBIGUOUS = "ambiguous"


class McpEvidenceOperationalResolution(StrEnum):
    CONTINUE_POLICY_EVALUATION = "continue_policy_evaluation"
    FAIL_CLOSED = "fail_closed"


class McpEvidenceFinding(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    finding_id: McpEvidenceFindingId
    status: McpEvidenceFindingStatus
    operational_resolution: McpEvidenceOperationalResolution
    source_ids: tuple[str, ...] = Field(min_length=1, max_length=8)
    observations: tuple[str, ...] = Field(min_length=1, max_length=8)
    reviewed_at: datetime
    finding_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_reviewed_at = field_validator("reviewed_at")(_require_aware)

    @model_validator(mode="after")
    def validate_finding(self) -> "McpEvidenceFinding":
        _validate_sorted_unique_string_tuple(
            self.source_ids,
            field_name="finding source_ids",
        )
        _validate_sorted_unique_string_tuple(
            self.observations,
            field_name="finding observations",
        )
        if self.status is McpEvidenceFindingStatus.AMBIGUOUS:
            if len(self.source_ids) < 2:
                raise ValueError("ambiguous findings require at least two official sources")
            if self.operational_resolution is not McpEvidenceOperationalResolution.FAIL_CLOSED:
                raise ValueError("ambiguous findings must fail closed")
        elif (
            self.operational_resolution
            is not McpEvidenceOperationalResolution.CONTINUE_POLICY_EVALUATION
        ):
            raise ValueError("consistent findings must continue policy evaluation")
        expected = compute_mcp_evidence_finding_sha256(
            finding_id=self.finding_id,
            status=self.status,
            operational_resolution=self.operational_resolution,
            source_ids=self.source_ids,
            observations=self.observations,
            reviewed_at=self.reviewed_at,
        )
        if self.finding_sha256 != expected:
            raise ValueError("MCP evidence finding digest mismatch")
        return self


class ChatGptMcpEvidenceReconciliationProfile(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    profile_id: str = Field(pattern=_ID_PATTERN)
    provider: Literal["chatgpt"] = "chatgpt"
    surface: Literal["custom_mcp_app"] = "custom_mcp_app"
    reviewed_at: datetime
    revalidate_after: datetime
    sources: tuple[OfficialSourceReference, ...] = Field(min_length=1, max_length=16)
    findings: tuple[McpEvidenceFinding, ...] = Field(min_length=1, max_length=16)
    profile_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_reviewed_at = field_validator("reviewed_at")(_require_aware)
    _aware_revalidate_after = field_validator("revalidate_after")(_require_aware)

    @model_validator(mode="after")
    def validate_profile(self) -> "ChatGptMcpEvidenceReconciliationProfile":
        if self.revalidate_after <= self.reviewed_at:
            raise ValueError("revalidate_after must follow reviewed_at")
        if self.revalidate_after - self.reviewed_at > timedelta(days=31):
            raise ValueError("volatile evidence reconciliations expire within 31 days")

        source_ids = tuple(source.source_id for source in self.sources)
        _validate_sorted_unique_string_tuple(
            source_ids,
            field_name="official source identifiers",
        )
        for source in self.sources:
            if source.reviewed_at != self.reviewed_at:
                raise ValueError(
                    "official source review timestamps must match reconciliation reviewed_at"
                )

        finding_ids = tuple(finding.finding_id for finding in self.findings)
        _validate_sorted_unique_enum_tuple(
            finding_ids,
            field_name="evidence finding identifiers",
        )
        if set(finding_ids) != set(McpEvidenceFindingId):
            missing = sorted(
                item.value for item in set(McpEvidenceFindingId) - set(finding_ids)
            )
            extra = sorted(
                item.value for item in set(finding_ids) - set(McpEvidenceFindingId)
            )
            raise ValueError(
                "evidence reconciliation must be complete; "
                f"missing={missing}, extra={extra}"
            )

        known_sources = set(source_ids)
        referenced_sources: set[str] = set()
        for finding in self.findings:
            if not set(finding.source_ids).issubset(known_sources):
                raise ValueError(
                    f"finding {finding.finding_id} references an unknown source"
                )
            if finding.reviewed_at != self.reviewed_at:
                raise ValueError(
                    "finding review timestamps must match reconciliation reviewed_at"
                )
            referenced_sources.update(finding.source_ids)
        if referenced_sources != known_sources:
            unused = sorted(known_sources - referenced_sources)
            raise ValueError(f"official reconciliation sources must be used; unused={unused}")

        expected = compute_chatgpt_mcp_evidence_profile_sha256(
            profile_id=self.profile_id,
            reviewed_at=self.reviewed_at,
            revalidate_after=self.revalidate_after,
            sources=self.sources,
            findings=self.findings,
        )
        if self.profile_sha256 != expected:
            raise ValueError("ChatGPT MCP evidence reconciliation digest mismatch")
        return self


class McpReadinessCheckId(StrEnum):
    ACTION_REVIEW = "action_review"
    APP_CONFIGURATION = "app_configuration"
    AUTHENTICATION_METADATA = "authentication_metadata"
    DEVELOPER_MODE = "developer_mode"
    LOCAL_POLICY = "local_policy"
    PLAN_ROLE_OBSERVATION = "plan_role_observation"
    REFRESH_TOKEN = "refresh_token"
    TOOL_SNAPSHOT = "tool_snapshot"
    TRANSPORT = "transport"
    WEB_CLIENT = "web_client"
    WORKSPACE_ACCESS = "workspace_access"


class McpReadinessCheckState(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class McpReadinessCheck(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    check_id: McpReadinessCheckId
    state: McpReadinessCheckState
    detail_code: str | None = Field(default=None, pattern=_CODE_PATTERN)
    checked_at: datetime
    evidence_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    check_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_checked_at = field_validator("checked_at")(_require_aware)

    @model_validator(mode="after")
    def validate_check(self) -> "McpReadinessCheck":
        if self.state in (
            McpReadinessCheckState.VERIFIED,
            McpReadinessCheckState.FAILED,
        ):
            if self.evidence_sha256 is None:
                raise ValueError("verified and failed checks require evidence_sha256")
        elif self.evidence_sha256 is not None:
            raise ValueError("unknown or not-applicable checks cannot claim evidence")
        if self.state is McpReadinessCheckState.FAILED and self.detail_code is None:
            raise ValueError("failed readiness checks require detail_code")
        if self.state is not McpReadinessCheckState.FAILED and self.detail_code is not None:
            raise ValueError("only failed readiness checks may carry detail_code")
        expected = compute_mcp_readiness_check_sha256(
            check_id=self.check_id,
            state=self.state,
            detail_code=self.detail_code,
            checked_at=self.checked_at,
            evidence_sha256=self.evidence_sha256,
        )
        if self.check_sha256 != expected:
            raise ValueError("MCP readiness check digest mismatch")
        return self


class McpReadinessStage(StrEnum):
    BLOCKED = "blocked"
    READY_FOR_PUBLISH_REVIEW = "ready_for_publish_review"
    READY_FOR_USE_REVIEW = "ready_for_use_review"
    READY_TO_CONFIGURE_DRAFT = "ready_to_configure_draft"
    READY_TO_TEST_DRAFT = "ready_to_test_draft"


class McpReadinessReason(StrEnum):
    ACTION_REVIEW_REQUIRED = "ACTION_REVIEW_REQUIRED"
    DEPLOYMENT_POLICY_REFUSED = "DEPLOYMENT_POLICY_REFUSED"
    EVALUATION_PREDATES_OBSERVATION = "EVALUATION_PREDATES_OBSERVATION"
    EVIDENCE_PROFILE_EXPIRED = "EVIDENCE_PROFILE_EXPIRED"
    HIGH_RISK_TOOLS_REQUIRE_SEPARATE_REVIEW = (
        "HIGH_RISK_TOOLS_REQUIRE_SEPARATE_REVIEW"
    )
    OBSERVATION_PREDATES_EVIDENCE = "OBSERVATION_PREDATES_EVIDENCE"
    PLUS_PLAN_SCOPE_AMBIGUOUS = "PLUS_PLAN_SCOPE_AMBIGUOUS"
    READ_FETCH_SNAPSHOT_CONTAINS_WRITE_TOOLS = (
        "READ_FETCH_SNAPSHOT_CONTAINS_WRITE_TOOLS"
    )
    REQUIRED_CHECK_FAILED = "REQUIRED_CHECK_FAILED"
    REQUIRED_CHECK_NOT_APPLICABLE = "REQUIRED_CHECK_NOT_APPLICABLE"
    REQUIRED_CHECK_UNKNOWN = "REQUIRED_CHECK_UNKNOWN"
    TOOL_SNAPSHOT_REQUIRED = "TOOL_SNAPSHOT_REQUIRED"


class McpReadinessWarning(StrEnum):
    CHAT_PROJECT_ENUMERATION_UNPROVEN = "CHAT_PROJECT_ENUMERATION_UNPROVEN"
    PLUS_GENERAL_AVAILABILITY_NOT_DEPLOYMENT_AUTHORIZATION = (
        "PLUS_GENERAL_AVAILABILITY_NOT_DEPLOYMENT_AUTHORIZATION"
    )
    REAL_CONNECTION_NOT_ESTABLISHED = "REAL_CONNECTION_NOT_ESTABLISHED"
    TOOL_SNAPSHOT_REQUIRES_REFRESH_REVIEW = "TOOL_SNAPSHOT_REQUIRES_REFRESH_REVIEW"
    WRITE_CONFIRMATION_NOT_GUARANTEED = "WRITE_CONFIRMATION_NOT_GUARANTEED"


class McpConnectionReadinessObservation(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    observation_id: str = Field(pattern=_ID_PATTERN)
    request: McpDeploymentRequest
    capability_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    reconciliation_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    checks: tuple[McpReadinessCheck, ...] = Field(min_length=1, max_length=32)
    tool_snapshot_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    tool_count: int | None = Field(default=None, ge=0, le=1024)
    write_tool_count: int | None = Field(default=None, ge=0, le=1024)
    high_risk_tool_count: int | None = Field(default=None, ge=0, le=1024)
    local_policy_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    observed_at: datetime
    real_connection_requested: Literal[False] = False
    observation_sha256: str = Field(pattern=_SHA256_PATTERN)

    _aware_observed_at = field_validator("observed_at")(_require_aware)

    @model_validator(mode="after")
    def validate_observation(self) -> "McpConnectionReadinessObservation":
        check_ids = tuple(check.check_id for check in self.checks)
        _validate_sorted_unique_enum_tuple(
            check_ids,
            field_name="readiness check identifiers",
        )
        if set(check_ids) != set(McpReadinessCheckId):
            missing = sorted(
                item.value for item in set(McpReadinessCheckId) - set(check_ids)
            )
            extra = sorted(item.value for item in set(check_ids) - set(McpReadinessCheckId))
            raise ValueError(
                "readiness observation must contain every check exactly once; "
                f"missing={missing}, extra={extra}"
            )
        for check in self.checks:
            if check.checked_at > self.observed_at:
                raise ValueError("readiness checks cannot postdate observed_at")

        by_id = {check.check_id: check for check in self.checks}
        tool_verified = (
            by_id[McpReadinessCheckId.TOOL_SNAPSHOT].state
            is McpReadinessCheckState.VERIFIED
        )
        tool_values = (
            self.tool_snapshot_sha256,
            self.tool_count,
            self.write_tool_count,
            self.high_risk_tool_count,
        )
        if tool_verified:
            if any(value is None for value in tool_values):
                raise ValueError("verified tool snapshots require digest and counts")
            assert self.tool_count is not None
            assert self.write_tool_count is not None
            assert self.high_risk_tool_count is not None
            if self.write_tool_count > self.tool_count:
                raise ValueError("write_tool_count cannot exceed tool_count")
            if self.high_risk_tool_count > self.tool_count:
                raise ValueError("high_risk_tool_count cannot exceed tool_count")
        elif any(value is not None for value in tool_values):
            raise ValueError("unverified tool snapshots cannot carry digest or counts")

        local_policy_verified = (
            by_id[McpReadinessCheckId.LOCAL_POLICY].state
            is McpReadinessCheckState.VERIFIED
        )
        if local_policy_verified and self.local_policy_sha256 is None:
            raise ValueError("verified local policy requires local_policy_sha256")
        if not local_policy_verified and self.local_policy_sha256 is not None:
            raise ValueError("unverified local policy cannot carry a policy digest")

        expected = compute_mcp_readiness_observation_sha256(
            observation_id=self.observation_id,
            request=self.request,
            capability_profile_sha256=self.capability_profile_sha256,
            reconciliation_profile_sha256=self.reconciliation_profile_sha256,
            checks=self.checks,
            tool_snapshot_sha256=self.tool_snapshot_sha256,
            tool_count=self.tool_count,
            write_tool_count=self.write_tool_count,
            high_risk_tool_count=self.high_risk_tool_count,
            local_policy_sha256=self.local_policy_sha256,
            observed_at=self.observed_at,
        )
        if self.observation_sha256 != expected:
            raise ValueError("MCP readiness observation digest mismatch")
        return self


class McpConnectionReadinessDecision(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    observation_id: str = Field(pattern=_ID_PATTERN)
    ready: bool
    stage: McpReadinessStage
    reasons: tuple[McpReadinessReason, ...] = Field(max_length=24)
    warnings: tuple[McpReadinessWarning, ...] = Field(max_length=16)
    required_checks: tuple[McpReadinessCheckId, ...]
    verified_checks: tuple[McpReadinessCheckId, ...]
    failed_checks: tuple[McpReadinessCheckId, ...]
    unknown_checks: tuple[McpReadinessCheckId, ...]
    not_applicable_required_checks: tuple[McpReadinessCheckId, ...]
    deployment_reasons: tuple[McpDecisionReason, ...]
    selected_transport: McpTransportKind | None
    capability_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    reconciliation_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    evaluated_at: datetime
    real_connection_established: Literal[False] = False
    secrets_stored: Literal[False] = False

    _aware_evaluated_at = field_validator("evaluated_at")(_require_aware)

    @model_validator(mode="after")
    def validate_decision(self) -> "McpConnectionReadinessDecision":
        _validate_sorted_unique_enum_tuple(self.reasons, field_name="readiness reasons")
        _validate_sorted_unique_enum_tuple(self.warnings, field_name="readiness warnings")
        _validate_sorted_unique_enum_tuple(
            self.required_checks,
            field_name="required checks",
        )
        for field_name in (
            "verified_checks",
            "failed_checks",
            "unknown_checks",
            "not_applicable_required_checks",
            "deployment_reasons",
        ):
            _validate_sorted_unique_enum_tuple(
                getattr(self, field_name),
                field_name=field_name,
            )

        required = set(self.required_checks)
        partitions = (
            set(self.verified_checks),
            set(self.failed_checks),
            set(self.unknown_checks),
            set(self.not_applicable_required_checks),
        )
        if any(not partition.issubset(required) for partition in partitions):
            raise ValueError("readiness check result sets must be subsets of required_checks")
        combined: set[McpReadinessCheckId] = set()
        for partition in partitions:
            if combined.intersection(partition):
                raise ValueError("readiness check result sets must not overlap")
            combined.update(partition)
        if combined != required:
            raise ValueError("readiness check result sets must partition required_checks")

        if self.ready:
            if self.stage is McpReadinessStage.BLOCKED:
                raise ValueError("ready decisions cannot use stage=blocked")
            if self.reasons:
                raise ValueError("ready decisions cannot carry refusal reasons")
            if self.selected_transport is None:
                raise ValueError("ready decisions require a selected transport")
            if self.failed_checks or self.unknown_checks or self.not_applicable_required_checks:
                raise ValueError("ready decisions require every required check to be verified")
        else:
            if self.stage is not McpReadinessStage.BLOCKED:
                raise ValueError("blocked decisions must use stage=blocked")
            if not self.reasons:
                raise ValueError("blocked decisions require refusal reasons")
            if self.selected_transport is not None:
                raise ValueError("blocked decisions cannot select a transport")
        return self


def compute_mcp_evidence_finding_sha256(
    *,
    finding_id: McpEvidenceFindingId,
    status: McpEvidenceFindingStatus,
    operational_resolution: McpEvidenceOperationalResolution,
    source_ids: tuple[str, ...],
    observations: tuple[str, ...],
    reviewed_at: datetime,
) -> str:
    reviewed_at = _require_aware(reviewed_at)
    payload = {
        "version": "1",
        "finding_id": finding_id.value,
        "status": status.value,
        "operational_resolution": operational_resolution.value,
        "source_ids": list(source_ids),
        "observations": list(observations),
        "reviewed_at": reviewed_at.isoformat().replace("+00:00", "Z"),
    }
    return sha256(_FINDING_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_mcp_evidence_finding(
    *,
    finding_id: McpEvidenceFindingId,
    status: McpEvidenceFindingStatus,
    operational_resolution: McpEvidenceOperationalResolution,
    source_ids: tuple[str, ...],
    observations: tuple[str, ...],
    reviewed_at: datetime,
) -> McpEvidenceFinding:
    reviewed_at = _require_aware(reviewed_at)
    source_ids = tuple(sorted(source_ids))
    observations = tuple(sorted(observations))
    return McpEvidenceFinding(
        finding_id=finding_id,
        status=status,
        operational_resolution=operational_resolution,
        source_ids=source_ids,
        observations=observations,
        reviewed_at=reviewed_at,
        finding_sha256=compute_mcp_evidence_finding_sha256(
            finding_id=finding_id,
            status=status,
            operational_resolution=operational_resolution,
            source_ids=source_ids,
            observations=observations,
            reviewed_at=reviewed_at,
        ),
    )


def compute_chatgpt_mcp_evidence_profile_sha256(
    *,
    profile_id: str,
    reviewed_at: datetime,
    revalidate_after: datetime,
    sources: tuple[OfficialSourceReference, ...],
    findings: tuple[McpEvidenceFinding, ...],
) -> str:
    reviewed_at = _require_aware(reviewed_at)
    revalidate_after = _require_aware(revalidate_after)
    payload = {
        "version": "1",
        "profile_id": profile_id,
        "provider": "chatgpt",
        "surface": "custom_mcp_app",
        "reviewed_at": reviewed_at.isoformat().replace("+00:00", "Z"),
        "revalidate_after": revalidate_after.isoformat().replace("+00:00", "Z"),
        "sources": [source.model_dump(mode="json") for source in sources],
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }
    return sha256(_RECONCILIATION_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_chatgpt_mcp_evidence_reconciliation_profile(
    *,
    profile_id: str,
    reviewed_at: datetime,
    revalidate_after: datetime,
    sources: tuple[OfficialSourceReference, ...],
    findings: tuple[McpEvidenceFinding, ...],
) -> ChatGptMcpEvidenceReconciliationProfile:
    sources = tuple(sorted(sources, key=lambda item: item.source_id))
    findings = tuple(sorted(findings, key=lambda item: item.finding_id.value))
    return ChatGptMcpEvidenceReconciliationProfile(
        profile_id=profile_id,
        reviewed_at=reviewed_at,
        revalidate_after=revalidate_after,
        sources=sources,
        findings=findings,
        profile_sha256=compute_chatgpt_mcp_evidence_profile_sha256(
            profile_id=profile_id,
            reviewed_at=reviewed_at,
            revalidate_after=revalidate_after,
            sources=sources,
            findings=findings,
        ),
    )


def compute_mcp_readiness_check_sha256(
    *,
    check_id: McpReadinessCheckId,
    state: McpReadinessCheckState,
    detail_code: str | None,
    checked_at: datetime,
    evidence_sha256: str | None,
) -> str:
    checked_at = _require_aware(checked_at)
    payload = {
        "version": "1",
        "check_id": check_id.value,
        "state": state.value,
        "detail_code": detail_code,
        "checked_at": checked_at.isoformat().replace("+00:00", "Z"),
        "evidence_sha256": evidence_sha256,
    }
    return sha256(_CHECK_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_mcp_readiness_check(
    *,
    check_id: McpReadinessCheckId,
    state: McpReadinessCheckState,
    checked_at: datetime,
    evidence_sha256: str | None = None,
    detail_code: str | None = None,
) -> McpReadinessCheck:
    checked_at = _require_aware(checked_at)
    return McpReadinessCheck(
        check_id=check_id,
        state=state,
        detail_code=detail_code,
        checked_at=checked_at,
        evidence_sha256=evidence_sha256,
        check_sha256=compute_mcp_readiness_check_sha256(
            check_id=check_id,
            state=state,
            detail_code=detail_code,
            checked_at=checked_at,
            evidence_sha256=evidence_sha256,
        ),
    )


def compute_mcp_readiness_observation_sha256(
    *,
    observation_id: str,
    request: McpDeploymentRequest,
    capability_profile_sha256: str,
    reconciliation_profile_sha256: str,
    checks: tuple[McpReadinessCheck, ...],
    tool_snapshot_sha256: str | None,
    tool_count: int | None,
    write_tool_count: int | None,
    high_risk_tool_count: int | None,
    local_policy_sha256: str | None,
    observed_at: datetime,
) -> str:
    observed_at = _require_aware(observed_at)
    payload = {
        "version": "1",
        "observation_id": observation_id,
        "request": request.model_dump(mode="json"),
        "capability_profile_sha256": capability_profile_sha256,
        "reconciliation_profile_sha256": reconciliation_profile_sha256,
        "checks": [check.model_dump(mode="json") for check in checks],
        "tool_snapshot_sha256": tool_snapshot_sha256,
        "tool_count": tool_count,
        "write_tool_count": write_tool_count,
        "high_risk_tool_count": high_risk_tool_count,
        "local_policy_sha256": local_policy_sha256,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "real_connection_requested": False,
    }
    return sha256(_OBSERVATION_DOMAIN + _canonical_json(payload)).hexdigest()


def commit_mcp_connection_readiness_observation(
    *,
    observation_id: str,
    request: McpDeploymentRequest,
    capability_profile_sha256: str,
    reconciliation_profile_sha256: str,
    checks: tuple[McpReadinessCheck, ...],
    tool_snapshot_sha256: str | None,
    tool_count: int | None,
    write_tool_count: int | None,
    high_risk_tool_count: int | None,
    local_policy_sha256: str | None,
    observed_at: datetime,
) -> McpConnectionReadinessObservation:
    checks = tuple(sorted(checks, key=lambda item: item.check_id.value))
    observed_at = _require_aware(observed_at)
    return McpConnectionReadinessObservation(
        observation_id=observation_id,
        request=request,
        capability_profile_sha256=capability_profile_sha256,
        reconciliation_profile_sha256=reconciliation_profile_sha256,
        checks=checks,
        tool_snapshot_sha256=tool_snapshot_sha256,
        tool_count=tool_count,
        write_tool_count=write_tool_count,
        high_risk_tool_count=high_risk_tool_count,
        local_policy_sha256=local_policy_sha256,
        observed_at=observed_at,
        observation_sha256=compute_mcp_readiness_observation_sha256(
            observation_id=observation_id,
            request=request,
            capability_profile_sha256=capability_profile_sha256,
            reconciliation_profile_sha256=reconciliation_profile_sha256,
            checks=checks,
            tool_snapshot_sha256=tool_snapshot_sha256,
            tool_count=tool_count,
            write_tool_count=write_tool_count,
            high_risk_tool_count=high_risk_tool_count,
            local_policy_sha256=local_policy_sha256,
            observed_at=observed_at,
        ),
    )
