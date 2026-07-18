from __future__ import annotations

from datetime import datetime, timezone

from .chatgpt_mcp_readiness import (
    evaluate_chatgpt_mcp_connection_readiness,
    verify_chatgpt_mcp_evidence_reconciliation_profile,
)
from .mcp_deployment_models import ChatGptMcpCapabilityProfile
from .mcp_operator_evidence_models import (
    McpOperatorEvidenceBundle,
    McpOperatorEvidenceCompilation,
    McpOperatorEvidenceEvaluation,
    commit_mcp_operator_evidence_compilation,
    commit_mcp_operator_evidence_evaluation,
)
from .mcp_readiness_models import (
    ChatGptMcpEvidenceReconciliationProfile,
    McpConnectionReadinessObservation,
    McpReadinessCheckId,
    McpReadinessCheckState,
    commit_mcp_connection_readiness_observation,
    commit_mcp_readiness_check,
)
from .chatgpt_mcp_deployment import verify_chatgpt_mcp_capability_profile


def _require_aware(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")
    return value.astimezone(timezone.utc)


def verify_mcp_operator_evidence_bundle(
    bundle: McpOperatorEvidenceBundle,
) -> McpOperatorEvidenceBundle:
    return McpOperatorEvidenceBundle.model_validate(bundle.model_dump(mode="python"))


def compile_chatgpt_mcp_operator_evidence_bundle(
    *,
    capability_profile: ChatGptMcpCapabilityProfile,
    reconciliation_profile: ChatGptMcpEvidenceReconciliationProfile,
    bundle: McpOperatorEvidenceBundle,
    observation_id: str,
    compilation_id: str,
    compiled_at: datetime,
) -> McpOperatorEvidenceCompilation:
    capability_profile = verify_chatgpt_mcp_capability_profile(capability_profile)
    reconciliation_profile = verify_chatgpt_mcp_evidence_reconciliation_profile(
        reconciliation_profile
    )
    bundle = verify_mcp_operator_evidence_bundle(bundle)
    compiled_at = _require_aware(compiled_at, field_name="compiled_at")

    if bundle.capability_profile_sha256 != capability_profile.profile_sha256:
        raise ValueError("operator evidence bundle capability profile digest mismatch")
    if bundle.reconciliation_profile_sha256 != reconciliation_profile.profile_sha256:
        raise ValueError("operator evidence bundle reconciliation profile digest mismatch")
    if compiled_at < bundle.collected_at:
        raise ValueError("compiled_at cannot predate bundle collected_at")
    if compiled_at > bundle.expires_at:
        raise ValueError("cannot compile an expired operator evidence bundle")

    checks = tuple(
        commit_mcp_readiness_check(
            check_id=record.check_id,
            state=record.state,
            checked_at=record.observed_at,
            evidence_sha256=record.evidence_sha256,
            detail_code=(
                record.failure_code.value
                if record.state is McpReadinessCheckState.FAILED
                else None
            ),
        )
        for record in bundle.records
    )

    tool_verified = next(
        record
        for record in bundle.records
        if record.check_id is McpReadinessCheckId.TOOL_SNAPSHOT
    ).state is McpReadinessCheckState.VERIFIED

    tool_snapshot_sha256 = None
    tool_count = None
    write_tool_count = None
    high_risk_tool_count = None
    if tool_verified:
        if bundle.tool_review_summary is None:
            raise ValueError("verified tool evidence is missing its summary")
        tool_snapshot_sha256 = bundle.tool_review_summary.tool_snapshot_sha256
        tool_count = bundle.tool_review_summary.tool_count
        write_tool_count = bundle.tool_review_summary.write_tool_count
        high_risk_tool_count = bundle.tool_review_summary.high_risk_tool_count

    local_policy_verified = next(
        record
        for record in bundle.records
        if record.check_id is McpReadinessCheckId.LOCAL_POLICY
    ).state is McpReadinessCheckState.VERIFIED

    observation: McpConnectionReadinessObservation = (
        commit_mcp_connection_readiness_observation(
            observation_id=observation_id,
            request=bundle.request,
            capability_profile_sha256=bundle.capability_profile_sha256,
            reconciliation_profile_sha256=bundle.reconciliation_profile_sha256,
            checks=checks,
            tool_snapshot_sha256=tool_snapshot_sha256,
            tool_count=tool_count,
            write_tool_count=write_tool_count,
            high_risk_tool_count=high_risk_tool_count,
            local_policy_sha256=(
                bundle.local_policy_sha256 if local_policy_verified else None
            ),
            observed_at=bundle.collected_at,
        )
    )

    return commit_mcp_operator_evidence_compilation(
        compilation_id=compilation_id,
        bundle_id=bundle.bundle_id,
        bundle_sha256=bundle.bundle_sha256,
        bundle_expires_at=bundle.expires_at,
        observation=observation,
        compiled_at=compiled_at,
    )


def verify_chatgpt_mcp_operator_evidence_compilation(
    *,
    capability_profile: ChatGptMcpCapabilityProfile,
    reconciliation_profile: ChatGptMcpEvidenceReconciliationProfile,
    bundle: McpOperatorEvidenceBundle,
    compilation: McpOperatorEvidenceCompilation,
) -> McpOperatorEvidenceCompilation:
    compilation = McpOperatorEvidenceCompilation.model_validate(
        compilation.model_dump(mode="python")
    )
    expected = compile_chatgpt_mcp_operator_evidence_bundle(
        capability_profile=capability_profile,
        reconciliation_profile=reconciliation_profile,
        bundle=bundle,
        observation_id=compilation.observation.observation_id,
        compilation_id=compilation.compilation_id,
        compiled_at=compilation.compiled_at,
    )
    if compilation != expected:
        raise ValueError("ChatGPT MCP operator evidence compilation mismatch")
    return compilation


def evaluate_chatgpt_mcp_operator_evidence_bundle(
    *,
    capability_profile: ChatGptMcpCapabilityProfile,
    reconciliation_profile: ChatGptMcpEvidenceReconciliationProfile,
    bundle: McpOperatorEvidenceBundle,
    observation_id: str,
    compilation_id: str,
    evaluation_id: str,
    compiled_at: datetime,
    evaluated_at: datetime,
) -> McpOperatorEvidenceEvaluation:
    evaluated_at = _require_aware(evaluated_at, field_name="evaluated_at")
    compilation = compile_chatgpt_mcp_operator_evidence_bundle(
        capability_profile=capability_profile,
        reconciliation_profile=reconciliation_profile,
        bundle=bundle,
        observation_id=observation_id,
        compilation_id=compilation_id,
        compiled_at=compiled_at,
    )
    if evaluated_at < compilation.compiled_at:
        raise ValueError("evaluated_at cannot predate compiled_at")
    if evaluated_at > bundle.expires_at:
        raise ValueError("cannot evaluate an expired operator evidence bundle")

    decision = evaluate_chatgpt_mcp_connection_readiness(
        capability_profile=capability_profile,
        reconciliation_profile=reconciliation_profile,
        observation=compilation.observation,
        evaluated_at=evaluated_at,
    )
    return commit_mcp_operator_evidence_evaluation(
        evaluation_id=evaluation_id,
        compilation=compilation,
        decision=decision,
        evaluated_at=evaluated_at,
    )


def verify_chatgpt_mcp_operator_evidence_evaluation(
    *,
    capability_profile: ChatGptMcpCapabilityProfile,
    reconciliation_profile: ChatGptMcpEvidenceReconciliationProfile,
    bundle: McpOperatorEvidenceBundle,
    evaluation: McpOperatorEvidenceEvaluation,
) -> McpOperatorEvidenceEvaluation:
    evaluation = McpOperatorEvidenceEvaluation.model_validate(
        evaluation.model_dump(mode="python")
    )
    expected = evaluate_chatgpt_mcp_operator_evidence_bundle(
        capability_profile=capability_profile,
        reconciliation_profile=reconciliation_profile,
        bundle=bundle,
        observation_id=evaluation.compilation.observation.observation_id,
        compilation_id=evaluation.compilation.compilation_id,
        evaluation_id=evaluation.evaluation_id,
        compiled_at=evaluation.compilation.compiled_at,
        evaluated_at=evaluation.evaluated_at,
    )
    if evaluation != expected:
        raise ValueError("ChatGPT MCP operator evidence evaluation mismatch")
    return evaluation
