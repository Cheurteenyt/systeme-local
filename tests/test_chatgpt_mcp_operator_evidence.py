from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from systeme_local_gateway.providers.chatgpt_mcp_deployment import (
    build_current_chatgpt_mcp_capability_profile,
)
from systeme_local_gateway.providers.chatgpt_mcp_operator_evidence import (
    compile_chatgpt_mcp_operator_evidence_bundle,
    evaluate_chatgpt_mcp_operator_evidence_bundle,
    verify_chatgpt_mcp_operator_evidence_compilation,
    verify_chatgpt_mcp_operator_evidence_evaluation,
    verify_mcp_operator_evidence_bundle,
)
from systeme_local_gateway.providers.chatgpt_mcp_readiness import (
    build_current_chatgpt_mcp_evidence_reconciliation_profile,
)
from systeme_local_gateway.providers.mcp_deployment_models import (
    ChatGptClientSurface,
    ChatGptPlan,
    ChatGptWorkspaceRole,
    McpAccessMode,
    McpAuthenticationKind,
    McpDeploymentPhase,
    McpDeploymentRequest,
    McpServerLocation,
    McpTransportKind,
    RefreshTokenCapability,
)
from systeme_local_gateway.providers.mcp_operator_evidence_models import (
    McpOperatorEvidenceFailureCode,
    McpOperatorEvidenceSource,
    commit_mcp_authentication_evidence_summary,
    commit_mcp_operator_evidence_bundle,
    commit_mcp_operator_evidence_record,
    commit_mcp_tool_review_evidence_summary,
    commit_mcp_transport_evidence_summary,
)
from systeme_local_gateway.providers.mcp_readiness_models import (
    McpReadinessCheckId,
    McpReadinessCheckState,
    McpReadinessReason,
    McpReadinessStage,
)

NOW = datetime(2026, 7, 18, 18, 0, tzinfo=timezone.utc)
DIGESTS = tuple(f"{index:x}" * 64 for index in range(1, 10))

SOURCE_BY_CHECK = {
    McpReadinessCheckId.ACTION_REVIEW: McpOperatorEvidenceSource.ACTION_REVIEW_SNAPSHOT,
    McpReadinessCheckId.APP_CONFIGURATION: McpOperatorEvidenceSource.OPERATOR_ATTESTATION,
    McpReadinessCheckId.AUTHENTICATION_METADATA: (
        McpOperatorEvidenceSource.SANITIZED_METADATA_DIGEST
    ),
    McpReadinessCheckId.DEVELOPER_MODE: McpOperatorEvidenceSource.OPERATOR_ATTESTATION,
    McpReadinessCheckId.LOCAL_POLICY: McpOperatorEvidenceSource.LOCAL_POLICY_SNAPSHOT,
    McpReadinessCheckId.PLAN_ROLE_OBSERVATION: (
        McpOperatorEvidenceSource.OPERATOR_ATTESTATION
    ),
    McpReadinessCheckId.REFRESH_TOKEN: (
        McpOperatorEvidenceSource.SANITIZED_METADATA_DIGEST
    ),
    McpReadinessCheckId.TOOL_SNAPSHOT: McpOperatorEvidenceSource.TOOL_SCAN_SNAPSHOT,
    McpReadinessCheckId.TRANSPORT: McpOperatorEvidenceSource.SECURE_TUNNEL_ATTESTATION,
    McpReadinessCheckId.WEB_CLIENT: McpOperatorEvidenceSource.OPERATOR_ATTESTATION,
    McpReadinessCheckId.WORKSPACE_ACCESS: (
        McpOperatorEvidenceSource.WORKSPACE_ADMIN_ATTESTATION
    ),
}

FAILURE_BY_CHECK = {
    McpReadinessCheckId.ACTION_REVIEW: (
        McpOperatorEvidenceFailureCode.ACTION_REVIEW_INCOMPLETE
    ),
    McpReadinessCheckId.APP_CONFIGURATION: McpOperatorEvidenceFailureCode.APP_NOT_CONFIGURED,
    McpReadinessCheckId.AUTHENTICATION_METADATA: (
        McpOperatorEvidenceFailureCode.AUTHENTICATION_METADATA_INVALID
    ),
    McpReadinessCheckId.DEVELOPER_MODE: (
        McpOperatorEvidenceFailureCode.DEVELOPER_MODE_DISABLED
    ),
    McpReadinessCheckId.LOCAL_POLICY: (
        McpOperatorEvidenceFailureCode.LOCAL_POLICY_DIGEST_MISMATCH
    ),
    McpReadinessCheckId.PLAN_ROLE_OBSERVATION: (
        McpOperatorEvidenceFailureCode.PLAN_ROLE_NOT_CONFIRMED
    ),
    McpReadinessCheckId.REFRESH_TOKEN: (
        McpOperatorEvidenceFailureCode.REFRESH_TOKEN_CAPABILITY_MISSING
    ),
    McpReadinessCheckId.TOOL_SNAPSHOT: (
        McpOperatorEvidenceFailureCode.TOOL_SNAPSHOT_NOT_REVIEWED
    ),
    McpReadinessCheckId.TRANSPORT: (
        McpOperatorEvidenceFailureCode.TRANSPORT_ATTESTATION_FAILED
    ),
    McpReadinessCheckId.WEB_CLIENT: (
        McpOperatorEvidenceFailureCode.WEB_CLIENT_UNAVAILABLE
    ),
    McpReadinessCheckId.WORKSPACE_ACCESS: (
        McpOperatorEvidenceFailureCode.WORKSPACE_ACCESS_NOT_GRANTED
    ),
}


def request(**updates: object) -> McpDeploymentRequest:
    data: dict[str, object] = {
        "request_id": "req_operator",
        "plan": ChatGptPlan.PRO,
        "role": ChatGptWorkspaceRole.MEMBER,
        "client": ChatGptClientSurface.WEB,
        "phase": McpDeploymentPhase.TEST,
        "access_mode": McpAccessMode.READ_FETCH,
        "server_location": McpServerLocation.DEVELOPER_MACHINE,
        "authentication": McpAuthenticationKind.OAUTH,
        "persistent_connectivity_required": True,
        "refresh_token_capability": RefreshTokenCapability.ISSUED,
        "developer_mode_enabled": True,
        "app_configured": False,
        "workspace_app_access_granted": False,
        "requested_at": NOW,
    }
    data.update(updates)
    return McpDeploymentRequest(**data)


def base_states() -> dict[McpReadinessCheckId, McpReadinessCheckState]:
    return {
        McpReadinessCheckId.AUTHENTICATION_METADATA: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.DEVELOPER_MODE: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.LOCAL_POLICY: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.PLAN_ROLE_OBSERVATION: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.REFRESH_TOKEN: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.TRANSPORT: McpReadinessCheckState.VERIFIED,
        McpReadinessCheckId.WEB_CLIENT: McpReadinessCheckState.VERIFIED,
    }


def summaries(*, deployment_request: McpDeploymentRequest, tools=None):
    selected_transport = (
        McpTransportKind.REMOTE_DIRECT
        if deployment_request.server_location is McpServerLocation.PUBLIC_REMOTE
        else McpTransportKind.SECURE_MCP_TUNNEL
    )
    transport = commit_mcp_transport_evidence_summary(
        summary_id="transport_summary",
        server_location=deployment_request.server_location,
        selected_transport=selected_transport,
        endpoint_origin_sha256=DIGESTS[0],
        tls_profile_sha256=DIGESTS[1],
        secure_tunnel_receipt_sha256=(
            DIGESTS[2] if selected_transport is McpTransportKind.SECURE_MCP_TUNNEL else None
        ),
        public_endpoint_receipt_sha256=(
            DIGESTS[2] if selected_transport is McpTransportKind.REMOTE_DIRECT else None
        ),
        observed_at=NOW,
        valid_until=NOW + timedelta(minutes=10),
    )
    auth = None
    if deployment_request.authentication in (
        McpAuthenticationKind.OAUTH,
        McpAuthenticationKind.OPENID_CONNECT,
    ):
        auth = commit_mcp_authentication_evidence_summary(
            summary_id="auth_summary",
            authentication=deployment_request.authentication,
            issuer_sha256=DIGESTS[0],
            discovery_metadata_sha256=DIGESTS[1],
            authorization_endpoint_sha256=DIGESTS[2],
            token_endpoint_sha256=DIGESTS[3],
            scopes_supported_sha256=DIGESTS[4],
            refresh_capability_advertised=True,
            refresh_tokens_issued=(
                deployment_request.refresh_token_capability
                is RefreshTokenCapability.ISSUED
            ),
            observed_at=NOW,
            valid_until=NOW + timedelta(minutes=30),
        )
    return transport, auth, tools


def make_bundle(
    *,
    deployment_request: McpDeploymentRequest | None = None,
    states: dict[McpReadinessCheckId, McpReadinessCheckState] | None = None,
    tool_count: int | None = None,
    write_tool_count: int | None = None,
    high_risk_tool_count: int | None = None,
    collected_at: datetime = NOW,
    expires_at: datetime | None = None,
):
    deployment_request = deployment_request or request()
    states = states or base_states()
    tool_review = None
    if states.get(McpReadinessCheckId.TOOL_SNAPSHOT) is McpReadinessCheckState.VERIFIED:
        tool_review = commit_mcp_tool_review_evidence_summary(
            summary_id="tool_summary",
            tool_snapshot_sha256=DIGESTS[0],
            tool_count=tool_count if tool_count is not None else 4,
            write_tool_count=write_tool_count if write_tool_count is not None else 0,
            high_risk_tool_count=(
                high_risk_tool_count if high_risk_tool_count is not None else 0
            ),
            action_review_sha256=DIGESTS[1],
            observed_at=NOW,
            valid_until=NOW + timedelta(minutes=20),
        )
    transport, auth, tool_review = summaries(
        deployment_request=deployment_request,
        tools=tool_review,
    )
    records = []
    for index, check_id in enumerate(McpReadinessCheckId):
        state = states.get(check_id, McpReadinessCheckState.UNKNOWN)
        source = (
            SOURCE_BY_CHECK[check_id]
            if state in (McpReadinessCheckState.VERIFIED, McpReadinessCheckState.FAILED)
            else McpOperatorEvidenceSource.NONE
        )
        if (
            check_id is McpReadinessCheckId.TRANSPORT
            and deployment_request.server_location is McpServerLocation.PUBLIC_REMOTE
            and state in (McpReadinessCheckState.VERIFIED, McpReadinessCheckState.FAILED)
        ):
            source = McpOperatorEvidenceSource.PUBLIC_ENDPOINT_ATTESTATION
        evidence = None
        if state in (McpReadinessCheckState.VERIFIED, McpReadinessCheckState.FAILED):
            evidence = DIGESTS[index % len(DIGESTS)]
            if check_id is McpReadinessCheckId.TRANSPORT:
                evidence = transport.summary_sha256
            elif check_id in (
                McpReadinessCheckId.AUTHENTICATION_METADATA,
                McpReadinessCheckId.REFRESH_TOKEN,
            ):
                assert auth is not None
                evidence = auth.summary_sha256
            elif check_id is McpReadinessCheckId.TOOL_SNAPSHOT:
                assert tool_review is not None
                evidence = tool_review.summary_sha256
            elif check_id is McpReadinessCheckId.ACTION_REVIEW:
                assert tool_review is not None
                evidence = tool_review.action_review_sha256
            elif check_id is McpReadinessCheckId.LOCAL_POLICY:
                evidence = DIGESTS[5]
        records.append(
            commit_mcp_operator_evidence_record(
                record_id=f"record_{check_id.value}",
                check_id=check_id,
                state=state,
                source=source,
                evidence_sha256=evidence,
                failure_code=(
                    FAILURE_BY_CHECK[check_id]
                    if state is McpReadinessCheckState.FAILED
                    else None
                ),
                collector_id="operator_primary",
                collection_session_id="collection_primary",
                observed_at=NOW,
                valid_until=NOW + timedelta(minutes=10),
            )
        )
    capability = build_current_chatgpt_mcp_capability_profile()
    reconciliation = build_current_chatgpt_mcp_evidence_reconciliation_profile()
    return commit_mcp_operator_evidence_bundle(
        bundle_id="bundle_primary",
        request=deployment_request,
        capability_profile_sha256=capability.profile_sha256,
        reconciliation_profile_sha256=reconciliation.profile_sha256,
        records=tuple(records),
        transport_summary=(
            transport
            if states.get(McpReadinessCheckId.TRANSPORT)
            is McpReadinessCheckState.VERIFIED
            else None
        ),
        authentication_summary=(
            auth
            if states.get(McpReadinessCheckId.AUTHENTICATION_METADATA)
            is McpReadinessCheckState.VERIFIED
            else None
        ),
        tool_review_summary=tool_review,
        local_policy_sha256=(
            DIGESTS[5]
            if states.get(McpReadinessCheckId.LOCAL_POLICY)
            is McpReadinessCheckState.VERIFIED
            else None
        ),
        collected_at=collected_at,
        expires_at=expires_at or collected_at + timedelta(minutes=10),
    )


def compile_bundle(item, *, compiled_at=NOW + timedelta(minutes=1)):
    return compile_chatgpt_mcp_operator_evidence_bundle(
        capability_profile=build_current_chatgpt_mcp_capability_profile(),
        reconciliation_profile=build_current_chatgpt_mcp_evidence_reconciliation_profile(),
        bundle=item,
        observation_id="observation_operator",
        compilation_id="compilation_operator",
        compiled_at=compiled_at,
    )


def evaluate_bundle(item, *, evaluated_at=NOW + timedelta(minutes=2)):
    return evaluate_chatgpt_mcp_operator_evidence_bundle(
        capability_profile=build_current_chatgpt_mcp_capability_profile(),
        reconciliation_profile=build_current_chatgpt_mcp_evidence_reconciliation_profile(),
        bundle=item,
        observation_id="observation_operator",
        compilation_id="compilation_operator",
        evaluation_id="evaluation_operator",
        compiled_at=NOW + timedelta(minutes=1),
        evaluated_at=evaluated_at,
    )


def test_bundle_verifier_round_trips() -> None:
    item = make_bundle()
    assert verify_mcp_operator_evidence_bundle(item) == item


def test_compile_maps_all_eleven_records_to_readiness_checks() -> None:
    compilation = compile_bundle(make_bundle())
    assert len(compilation.observation.checks) == 11
    assert compilation.observation.real_connection_requested is False
    assert compilation.real_connection_established is False
    assert compilation.secrets_stored is False


def test_compile_binds_tool_and_policy_summaries() -> None:
    states = base_states()
    states.update(
        {
            McpReadinessCheckId.ACTION_REVIEW: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.APP_CONFIGURATION: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED,
        }
    )
    compilation = compile_bundle(
        make_bundle(
            deployment_request=request(app_configured=True),
            states=states,
            tool_count=5,
            write_tool_count=0,
            high_risk_tool_count=0,
        )
    )
    assert compilation.observation.tool_count == 5
    assert compilation.observation.local_policy_sha256 == DIGESTS[5]


def test_compile_rejects_profile_digest_mismatch() -> None:
    item = make_bundle()
    changed = commit_mcp_operator_evidence_bundle(
        bundle_id=item.bundle_id,
        request=item.request,
        capability_profile_sha256=DIGESTS[8],
        reconciliation_profile_sha256=item.reconciliation_profile_sha256,
        records=item.records,
        transport_summary=item.transport_summary,
        authentication_summary=item.authentication_summary,
        tool_review_summary=item.tool_review_summary,
        local_policy_sha256=item.local_policy_sha256,
        collected_at=item.collected_at,
        expires_at=item.expires_at,
    )
    with pytest.raises(ValueError, match="capability profile digest"):
        compile_bundle(changed)


def test_compile_rejects_time_inversion_and_expiry() -> None:
    item = make_bundle()
    with pytest.raises(ValueError, match="predate"):
        compile_bundle(item, compiled_at=NOW - timedelta(seconds=1))
    with pytest.raises(ValueError, match="expired"):
        compile_bundle(item, compiled_at=NOW + timedelta(minutes=11))


def test_compilation_verifier_rejects_tampering() -> None:
    item = make_bundle()
    compilation = compile_bundle(item)
    assert (
        verify_chatgpt_mcp_operator_evidence_compilation(
            capability_profile=build_current_chatgpt_mcp_capability_profile(),
            reconciliation_profile=(
                build_current_chatgpt_mcp_evidence_reconciliation_profile()
            ),
            bundle=item,
            compilation=compilation,
        )
        == compilation
    )
    tampered = compilation.model_copy(update={"bundle_sha256": DIGESTS[8]})
    with pytest.raises(ValidationError, match="digest mismatch"):
        verify_chatgpt_mcp_operator_evidence_compilation(
            capability_profile=build_current_chatgpt_mcp_capability_profile(),
            reconciliation_profile=(
                build_current_chatgpt_mcp_evidence_reconciliation_profile()
            ),
            bundle=item,
            compilation=tampered,
        )


def test_pro_read_fetch_bundle_reaches_configure_draft_review() -> None:
    evaluation = evaluate_bundle(make_bundle())
    assert evaluation.decision.ready is True
    assert evaluation.decision.stage is McpReadinessStage.READY_TO_CONFIGURE_DRAFT
    assert evaluation.decision.selected_transport is McpTransportKind.SECURE_MCP_TUNNEL
    assert evaluation.real_connection_established is False
    assert evaluation.secrets_stored is False


def test_configured_bundle_with_tool_review_reaches_test_draft_review() -> None:
    states = base_states()
    states.update(
        {
            McpReadinessCheckId.ACTION_REVIEW: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.APP_CONFIGURATION: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED,
        }
    )
    evaluation = evaluate_bundle(
        make_bundle(
            deployment_request=request(app_configured=True),
            states=states,
        )
    )
    assert evaluation.decision.ready is True
    assert evaluation.decision.stage is McpReadinessStage.READY_TO_TEST_DRAFT


@pytest.mark.parametrize(
    ("write_tool_count", "high_risk_tool_count", "reason"),
    [
        (
            1,
            0,
            McpReadinessReason.READ_FETCH_SNAPSHOT_CONTAINS_WRITE_TOOLS,
        ),
        (
            0,
            1,
            McpReadinessReason.HIGH_RISK_TOOLS_REQUIRE_SEPARATE_REVIEW,
        ),
    ],
)
def test_tool_risk_blocks_evaluation(write_tool_count, high_risk_tool_count, reason) -> None:
    states = base_states()
    states.update(
        {
            McpReadinessCheckId.ACTION_REVIEW: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.APP_CONFIGURATION: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED,
        }
    )
    evaluation = evaluate_bundle(
        make_bundle(
            deployment_request=request(app_configured=True),
            states=states,
            write_tool_count=write_tool_count,
            high_risk_tool_count=high_risk_tool_count,
        )
    )
    assert evaluation.decision.ready is False
    assert reason in evaluation.decision.reasons


@pytest.mark.parametrize(
    ("check_id", "state", "reason"),
    [
        (
            McpReadinessCheckId.LOCAL_POLICY,
            McpReadinessCheckState.UNKNOWN,
            McpReadinessReason.REQUIRED_CHECK_UNKNOWN,
        ),
        (
            McpReadinessCheckId.DEVELOPER_MODE,
            McpReadinessCheckState.FAILED,
            McpReadinessReason.REQUIRED_CHECK_FAILED,
        ),
    ],
)
def test_failed_or_unknown_required_evidence_blocks(check_id, state, reason) -> None:
    states = base_states()
    states[check_id] = state
    deployment_request = request(
        developer_mode_enabled=False
        if check_id is McpReadinessCheckId.DEVELOPER_MODE
        and state is McpReadinessCheckState.FAILED
        else True
    )
    evaluation = evaluate_bundle(
        make_bundle(deployment_request=deployment_request, states=states)
    )
    assert evaluation.decision.ready is False
    assert reason in evaluation.decision.reasons


def test_plus_bundle_fails_closed() -> None:
    evaluation = evaluate_bundle(
        make_bundle(deployment_request=request(plan=ChatGptPlan.PLUS))
    )
    assert evaluation.decision.ready is False
    assert McpReadinessReason.PLUS_PLAN_SCOPE_AMBIGUOUS in evaluation.decision.reasons


def test_public_remote_bundle_selects_remote_direct() -> None:
    evaluation = evaluate_bundle(
        make_bundle(
            deployment_request=request(server_location=McpServerLocation.PUBLIC_REMOTE)
        )
    )
    assert evaluation.decision.ready is True
    assert evaluation.decision.selected_transport is McpTransportKind.REMOTE_DIRECT


def test_business_publish_bundle_reaches_publish_review() -> None:
    states = base_states()
    states.update(
        {
            McpReadinessCheckId.ACTION_REVIEW: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.APP_CONFIGURATION: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED,
        }
    )
    evaluation = evaluate_bundle(
        make_bundle(
            deployment_request=request(
                plan=ChatGptPlan.BUSINESS,
                role=ChatGptWorkspaceRole.ADMIN,
                phase=McpDeploymentPhase.PUBLISH,
                access_mode=McpAccessMode.WRITE_MODIFY,
                app_configured=True,
            ),
            states=states,
            tool_count=4,
            write_tool_count=2,
        )
    )
    assert evaluation.decision.ready is True
    assert evaluation.decision.stage is McpReadinessStage.READY_FOR_PUBLISH_REVIEW


def test_enterprise_use_bundle_requires_and_accepts_workspace_access() -> None:
    states = base_states()
    states.pop(McpReadinessCheckId.DEVELOPER_MODE)
    states.update(
        {
            McpReadinessCheckId.ACTION_REVIEW: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.APP_CONFIGURATION: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.TOOL_SNAPSHOT: McpReadinessCheckState.VERIFIED,
            McpReadinessCheckId.WORKSPACE_ACCESS: McpReadinessCheckState.VERIFIED,
        }
    )
    evaluation = evaluate_bundle(
        make_bundle(
            deployment_request=request(
                plan=ChatGptPlan.ENTERPRISE,
                role=ChatGptWorkspaceRole.MEMBER,
                phase=McpDeploymentPhase.USE,
                app_configured=True,
                workspace_app_access_granted=True,
            ),
            states=states,
        )
    )
    assert evaluation.decision.ready is True
    assert evaluation.decision.stage is McpReadinessStage.READY_FOR_USE_REVIEW


def test_no_auth_bundle_compiles_not_applicable_auth_checks() -> None:
    states = base_states()
    states[McpReadinessCheckId.AUTHENTICATION_METADATA] = (
        McpReadinessCheckState.NOT_APPLICABLE
    )
    states[McpReadinessCheckId.REFRESH_TOKEN] = McpReadinessCheckState.NOT_APPLICABLE
    item = make_bundle(
        deployment_request=request(
            authentication=McpAuthenticationKind.NONE,
            refresh_token_capability=RefreshTokenCapability.NOT_APPLICABLE,
            persistent_connectivity_required=False,
        ),
        states=states,
    )
    compilation = compile_bundle(item)
    by_id = {check.check_id: check for check in compilation.observation.checks}
    assert (
        by_id[McpReadinessCheckId.AUTHENTICATION_METADATA].state
        is McpReadinessCheckState.NOT_APPLICABLE
    )


def test_evaluation_rejects_expired_bundle() -> None:
    item = make_bundle(expires_at=NOW + timedelta(minutes=2))
    with pytest.raises(ValueError, match="expired"):
        evaluate_bundle(item, evaluated_at=NOW + timedelta(minutes=3))


def test_evaluation_verifier_round_trips_and_rejects_tampering() -> None:
    item = make_bundle()
    evaluation = evaluate_bundle(item)
    assert (
        verify_chatgpt_mcp_operator_evidence_evaluation(
            capability_profile=build_current_chatgpt_mcp_capability_profile(),
            reconciliation_profile=(
                build_current_chatgpt_mcp_evidence_reconciliation_profile()
            ),
            bundle=item,
            evaluation=evaluation,
        )
        == evaluation
    )
    tampered = evaluation.model_copy(update={"evaluation_id": "evaluation_changed"})
    with pytest.raises(ValidationError, match="digest mismatch"):
        verify_chatgpt_mcp_operator_evidence_evaluation(
            capability_profile=build_current_chatgpt_mcp_capability_profile(),
            reconciliation_profile=(
                build_current_chatgpt_mcp_evidence_reconciliation_profile()
            ),
            bundle=item,
            evaluation=tampered,
        )


def test_runtime_modules_have_no_network_or_browser_imports() -> None:
    provider_root = Path(__file__).parents[1] / "src/systeme_local_gateway/providers"
    forbidden = {
        "httpx",
        "requests",
        "socket",
        "subprocess",
        "playwright",
        "selenium",
    }
    for filename in (
        "mcp_operator_evidence_models.py",
        "chatgpt_mcp_operator_evidence.py",
    ):
        tree = ast.parse((provider_root / filename).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        assert imported.isdisjoint(forbidden)
