from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

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
    McpAuthenticationEvidenceSummary,
    McpOperatorEvidenceAssertion,
    McpOperatorEvidenceBundle,
    McpOperatorEvidenceFailureCode,
    McpOperatorEvidenceSource,
    McpReadinessCheckId,
    McpReadinessCheckState,
    commit_mcp_authentication_evidence_summary,
    commit_mcp_operator_evidence_bundle,
    commit_mcp_operator_evidence_record,
    commit_mcp_tool_review_evidence_summary,
    commit_mcp_transport_evidence_summary,
)

NOW = datetime(2026, 7, 18, 18, 0, tzinfo=timezone.utc)
DIGESTS = tuple(f"{index:x}" * 64 for index in range(1, 10))


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


def auth_summary(**updates: object):
    data: dict[str, object] = {
        "summary_id": "auth_summary",
        "authentication": McpAuthenticationKind.OAUTH,
        "issuer_sha256": DIGESTS[0],
        "discovery_metadata_sha256": DIGESTS[1],
        "authorization_endpoint_sha256": DIGESTS[2],
        "token_endpoint_sha256": DIGESTS[3],
        "scopes_supported_sha256": DIGESTS[4],
        "refresh_capability_advertised": True,
        "refresh_tokens_issued": True,
        "observed_at": NOW,
        "valid_until": NOW + timedelta(minutes=30),
    }
    data.update(updates)
    return commit_mcp_authentication_evidence_summary(**data)


def transport_summary(**updates: object):
    data: dict[str, object] = {
        "summary_id": "transport_summary",
        "server_location": McpServerLocation.DEVELOPER_MACHINE,
        "selected_transport": McpTransportKind.SECURE_MCP_TUNNEL,
        "endpoint_origin_sha256": DIGESTS[0],
        "tls_profile_sha256": DIGESTS[1],
        "secure_tunnel_receipt_sha256": DIGESTS[2],
        "observed_at": NOW,
        "valid_until": NOW + timedelta(minutes=10),
    }
    data.update(updates)
    return commit_mcp_transport_evidence_summary(**data)


def tool_summary(**updates: object):
    data: dict[str, object] = {
        "summary_id": "tool_summary",
        "tool_snapshot_sha256": DIGESTS[0],
        "tool_count": 4,
        "write_tool_count": 0,
        "high_risk_tool_count": 0,
        "action_review_sha256": DIGESTS[1],
        "observed_at": NOW,
        "valid_until": NOW + timedelta(minutes=20),
    }
    data.update(updates)
    return commit_mcp_tool_review_evidence_summary(**data)


def records(
    *,
    states: dict[McpReadinessCheckId, McpReadinessCheckState] | None = None,
    auth=None,
    transport=None,
    tools=None,
    local_policy_sha256: str = DIGESTS[5],
):
    states = states or {}
    auth = auth or auth_summary()
    transport = transport or transport_summary()
    result = []
    for index, check_id in enumerate(McpReadinessCheckId):
        state = states.get(check_id, McpReadinessCheckState.UNKNOWN)
        source = (
            SOURCE_BY_CHECK[check_id]
            if state in (McpReadinessCheckState.VERIFIED, McpReadinessCheckState.FAILED)
            else McpOperatorEvidenceSource.NONE
        )
        evidence = None
        if state in (McpReadinessCheckState.VERIFIED, McpReadinessCheckState.FAILED):
            evidence = DIGESTS[index % len(DIGESTS)]
            if check_id is McpReadinessCheckId.TRANSPORT:
                evidence = transport.summary_sha256
            elif check_id in (
                McpReadinessCheckId.AUTHENTICATION_METADATA,
                McpReadinessCheckId.REFRESH_TOKEN,
            ):
                evidence = auth.summary_sha256
            elif check_id is McpReadinessCheckId.TOOL_SNAPSHOT and tools is not None:
                evidence = tools.summary_sha256
            elif check_id is McpReadinessCheckId.ACTION_REVIEW and tools is not None:
                evidence = tools.action_review_sha256
            elif check_id is McpReadinessCheckId.LOCAL_POLICY:
                evidence = local_policy_sha256
        result.append(
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
    return tuple(result)


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


def bundle(**updates: object):
    auth = updates.pop("authentication_summary", auth_summary())
    transport = updates.pop("transport_summary", transport_summary())
    tools = updates.pop("tool_review_summary", None)
    states = updates.pop("states", base_states())
    local_policy = updates.pop("local_policy_sha256", DIGESTS[5])
    data: dict[str, object] = {
        "bundle_id": "bundle_primary",
        "request": request(),
        "capability_profile_sha256": DIGESTS[6],
        "reconciliation_profile_sha256": DIGESTS[7],
        "records": records(
            states=states,
            auth=auth,
            transport=transport,
            tools=tools,
            local_policy_sha256=local_policy,
        ),
        "transport_summary": transport,
        "authentication_summary": auth,
        "tool_review_summary": tools,
        "local_policy_sha256": local_policy,
        "collected_at": NOW,
        "expires_at": NOW + timedelta(minutes=10),
    }
    data.update(updates)
    return commit_mcp_operator_evidence_bundle(**data)


def test_operator_record_is_frozen_strict_and_digest_bound() -> None:
    record = records(states=base_states())[0]
    with pytest.raises(ValidationError):
        record.model_validate({**record.model_dump(), "extra": True})
    with pytest.raises(ValidationError, match="digest mismatch"):
        record.model_validate({**record.model_dump(), "collector_id": "operator_changed"})
    with pytest.raises(ValidationError):
        record.record_id = "changed"  # type: ignore[misc]


@pytest.mark.parametrize("check_id", tuple(McpReadinessCheckId))
def test_commit_assigns_exact_assertion_for_every_check(check_id: McpReadinessCheckId) -> None:
    record = commit_mcp_operator_evidence_record(
        record_id=f"record_{check_id.value}",
        check_id=check_id,
        state=McpReadinessCheckState.UNKNOWN,
        source=McpOperatorEvidenceSource.NONE,
        collector_id="operator_primary",
        collection_session_id="collection_primary",
        observed_at=NOW,
        valid_until=NOW + timedelta(minutes=10),
    )
    assert isinstance(record.assertion, McpOperatorEvidenceAssertion)


def test_record_rejects_assertion_tampering() -> None:
    record = records(states=base_states())[0]
    with pytest.raises(ValidationError, match="assertion"):
        record.model_validate(
            {
                **record.model_dump(),
                "assertion": McpOperatorEvidenceAssertion.WEB_CLIENT_CONFIRMED,
            }
        )


@pytest.mark.parametrize(
    "state",
    [McpReadinessCheckState.UNKNOWN, McpReadinessCheckState.NOT_APPLICABLE],
)
def test_unknown_and_not_applicable_records_reject_evidence(state) -> None:
    with pytest.raises(ValidationError, match="source=none"):
        commit_mcp_operator_evidence_record(
            record_id="record_unknown",
            check_id=McpReadinessCheckId.WEB_CLIENT,
            state=state,
            source=McpOperatorEvidenceSource.OPERATOR_ATTESTATION,
            evidence_sha256=DIGESTS[0],
            collector_id="operator_primary",
            collection_session_id="collection_primary",
            observed_at=NOW,
            valid_until=NOW + timedelta(minutes=10),
        )


@pytest.mark.parametrize("check_id", tuple(McpReadinessCheckId))
def test_failed_records_require_exact_failure_code(check_id: McpReadinessCheckId) -> None:
    wrong = next(
        code
        for code in McpOperatorEvidenceFailureCode
        if code is not FAILURE_BY_CHECK[check_id]
    )
    with pytest.raises(ValidationError, match="exact typed failure"):
        commit_mcp_operator_evidence_record(
            record_id=f"record_{check_id.value}",
            check_id=check_id,
            state=McpReadinessCheckState.FAILED,
            source=SOURCE_BY_CHECK[check_id],
            evidence_sha256=DIGESTS[0],
            failure_code=wrong,
            collector_id="operator_primary",
            collection_session_id="collection_primary",
            observed_at=NOW,
            valid_until=NOW + timedelta(minutes=10),
        )


def test_record_rejects_incompatible_source() -> None:
    with pytest.raises(ValidationError, match="incompatible"):
        commit_mcp_operator_evidence_record(
            record_id="record_transport",
            check_id=McpReadinessCheckId.TRANSPORT,
            state=McpReadinessCheckState.VERIFIED,
            source=McpOperatorEvidenceSource.OPERATOR_ATTESTATION,
            evidence_sha256=DIGESTS[0],
            collector_id="operator_primary",
            collection_session_id="collection_primary",
            observed_at=NOW,
            valid_until=NOW + timedelta(minutes=10),
        )


def test_record_freshness_is_check_specific() -> None:
    with pytest.raises(ValidationError, match="freshness window"):
        commit_mcp_operator_evidence_record(
            record_id="record_transport",
            check_id=McpReadinessCheckId.TRANSPORT,
            state=McpReadinessCheckState.UNKNOWN,
            source=McpOperatorEvidenceSource.NONE,
            collector_id="operator_primary",
            collection_session_id="collection_primary",
            observed_at=NOW,
            valid_until=NOW + timedelta(minutes=16),
        )


def test_transport_summary_requires_tunnel_for_developer_machine() -> None:
    with pytest.raises(ValidationError, match="secure_mcp_tunnel"):
        transport_summary(selected_transport=McpTransportKind.REMOTE_DIRECT)


def test_public_transport_requires_public_receipt_and_no_tunnel_receipt() -> None:
    summary = transport_summary(
        server_location=McpServerLocation.PUBLIC_REMOTE,
        selected_transport=McpTransportKind.REMOTE_DIRECT,
        secure_tunnel_receipt_sha256=None,
        public_endpoint_receipt_sha256=DIGESTS[3],
    )
    assert summary.selected_transport is McpTransportKind.REMOTE_DIRECT
    with pytest.raises(ValidationError, match="public endpoint receipt"):
        transport_summary(
            server_location=McpServerLocation.PUBLIC_REMOTE,
            selected_transport=McpTransportKind.REMOTE_DIRECT,
            secure_tunnel_receipt_sha256=None,
        )


def test_transport_summary_rejects_raw_fields() -> None:
    summary = transport_summary()
    with pytest.raises(ValidationError):
        summary.model_validate({**summary.model_dump(), "endpoint_url": "https://example.com"})


def test_auth_summary_requires_oauth_or_oidc() -> None:
    with pytest.raises(ValidationError, match="OAuth or OpenID Connect"):
        auth_summary(authentication=McpAuthenticationKind.NONE)


def test_auth_summary_rejects_refresh_without_advertised_capability() -> None:
    with pytest.raises(ValidationError, match="advertised"):
        auth_summary(refresh_capability_advertised=False, refresh_tokens_issued=True)


def test_auth_summary_rejects_secret_fields() -> None:
    summary = auth_summary()
    with pytest.raises(ValidationError):
        summary.model_validate({**summary.model_dump(), "client_secret": "secret"})


def test_tool_summary_rejects_incoherent_counts() -> None:
    with pytest.raises(ValidationError, match="write_tool_count"):
        tool_summary(tool_count=1, write_tool_count=2)
    with pytest.raises(ValidationError, match="high_risk_tool_count"):
        tool_summary(tool_count=1, high_risk_tool_count=2)


def test_tool_summary_rejects_raw_tool_definitions() -> None:
    summary = tool_summary()
    with pytest.raises(ValidationError):
        summary.model_validate({**summary.model_dump(), "tool_definitions": []})


def test_bundle_is_complete_sorted_strict_and_digest_bound() -> None:
    item = bundle()
    assert tuple(record.check_id.value for record in item.records) == tuple(
        sorted(check_id.value for check_id in McpReadinessCheckId)
    )
    with pytest.raises(ValidationError, match="every check exactly once"):
        commit_mcp_operator_evidence_bundle(
            bundle_id="bundle_missing",
            request=item.request,
            capability_profile_sha256=item.capability_profile_sha256,
            reconciliation_profile_sha256=item.reconciliation_profile_sha256,
            records=item.records[:-1],
            transport_summary=item.transport_summary,
            authentication_summary=item.authentication_summary,
            local_policy_sha256=item.local_policy_sha256,
            collected_at=item.collected_at,
            expires_at=item.expires_at,
        )
    with pytest.raises(ValidationError, match="digest mismatch"):
        item.model_validate({**item.model_dump(), "bundle_id": "bundle_changed"})


def test_bundle_expires_within_fifteen_minutes() -> None:
    with pytest.raises(ValidationError, match="fifteen minutes"):
        bundle(expires_at=NOW + timedelta(minutes=16))


def test_bundle_rejects_record_that_expires_too_early() -> None:
    item = bundle()
    original = item.records[0]
    changed = commit_mcp_operator_evidence_record(
        record_id=original.record_id,
        check_id=original.check_id,
        state=original.state,
        source=original.source,
        evidence_sha256=original.evidence_sha256,
        failure_code=original.failure_code,
        collector_id=original.collector_id,
        collection_session_id=original.collection_session_id,
        observed_at=original.observed_at,
        valid_until=NOW + timedelta(minutes=5),
    )
    with pytest.raises(ValidationError, match="record validity"):
        item.model_validate(
            {
                **item.model_dump(),
                "records": (changed, *item.records[1:]),
            }
        )


def test_verified_plan_role_rejects_unknown_values() -> None:
    with pytest.raises(ValidationError, match="unknown values"):
        bundle(request=request(plan=ChatGptPlan.UNKNOWN))


def test_verified_web_client_requires_web() -> None:
    with pytest.raises(ValidationError, match="client=web"):
        bundle(request=request(client=ChatGptClientSurface.DESKTOP))


def test_verified_runtime_gates_must_match_request() -> None:
    with pytest.raises(ValidationError, match="developer-mode"):
        bundle(request=request(developer_mode_enabled=False))


def test_transport_record_must_bind_summary() -> None:
    item = bundle()
    changed_records = list(item.records)
    index = next(
        index
        for index, record in enumerate(changed_records)
        if record.check_id is McpReadinessCheckId.TRANSPORT
    )
    original = changed_records[index]
    changed_records[index] = commit_mcp_operator_evidence_record(
        record_id=original.record_id,
        check_id=original.check_id,
        state=original.state,
        source=original.source,
        evidence_sha256=DIGESTS[8],
        collector_id=original.collector_id,
        collection_session_id=original.collection_session_id,
        observed_at=original.observed_at,
        valid_until=original.valid_until,
    )
    with pytest.raises(ValidationError, match="transport record"):
        item.model_validate({**item.model_dump(), "records": tuple(changed_records)})


def test_non_oauth_request_requires_auth_checks_not_applicable() -> None:
    states = base_states()
    states[McpReadinessCheckId.AUTHENTICATION_METADATA] = McpReadinessCheckState.NOT_APPLICABLE
    states[McpReadinessCheckId.REFRESH_TOKEN] = McpReadinessCheckState.NOT_APPLICABLE
    item = bundle(
        request=request(
            authentication=McpAuthenticationKind.NONE,
            refresh_token_capability=RefreshTokenCapability.NOT_APPLICABLE,
        ),
        states=states,
        authentication_summary=None,
    )
    assert item.authentication_summary is None


def test_nonpersistent_request_requires_refresh_not_applicable() -> None:
    states = base_states()
    states[McpReadinessCheckId.REFRESH_TOKEN] = McpReadinessCheckState.NOT_APPLICABLE
    item = bundle(
        request=request(
            persistent_connectivity_required=False,
            refresh_token_capability=RefreshTokenCapability.NOT_ISSUED,
        ),
        states=states,
    )
    assert next(
        record
        for record in item.records
        if record.check_id is McpReadinessCheckId.REFRESH_TOKEN
    ).state is McpReadinessCheckState.NOT_APPLICABLE


def test_verified_refresh_requires_issued_request_and_summary() -> None:
    with pytest.raises(ValidationError, match="request capability=issued"):
        bundle(request=request(refresh_token_capability=RefreshTokenCapability.NOT_ISSUED))
    with pytest.raises(ValidationError, match="issued refresh tokens"):
        bundle(authentication_summary=auth_summary(refresh_tokens_issued=False))


def test_verified_tool_and_action_records_bind_summary() -> None:
    states = base_states()
    states[McpReadinessCheckId.TOOL_SNAPSHOT] = McpReadinessCheckState.VERIFIED
    states[McpReadinessCheckId.ACTION_REVIEW] = McpReadinessCheckState.VERIFIED
    summary = tool_summary()
    item = bundle(states=states, tool_review_summary=summary)
    assert item.tool_review_summary == summary


def test_unverified_tool_records_reject_summary() -> None:
    with pytest.raises(ValidationError, match="unverified tool"):
        bundle(tool_review_summary=tool_summary())


def test_verified_local_policy_binds_exact_digest() -> None:
    item = bundle()
    assert next(
        record
        for record in item.records
        if record.check_id is McpReadinessCheckId.LOCAL_POLICY
    ).evidence_sha256 == item.local_policy_sha256


def test_bundle_public_schema_has_no_secret_or_raw_value_fields() -> None:
    fields = set(McpOperatorEvidenceBundle.model_fields)
    forbidden = {
        "password",
        "cookie",
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
        "endpoint_url",
        "metadata_document",
        "tool_definitions",
    }
    assert fields.isdisjoint(forbidden)
    assert McpAuthenticationEvidenceSummary.model_fields.keys().isdisjoint(forbidden)


def test_bundle_normalizes_timezone_offsets() -> None:
    item = bundle()
    offset = NOW.astimezone(timezone(timedelta(hours=2)))
    rebuilt = bundle(collected_at=offset, expires_at=offset + timedelta(minutes=10))
    assert item.bundle_sha256 == rebuilt.bundle_sha256
