from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from systeme_local_gateway.c3_evidence import (
    C3GateStatus,
    C3ProtectedAction,
    EvidenceLifecycleState,
    EvidenceReviewerState,
    build_current_c3_official_capability_profile,
    build_current_c3_registry,
)
from systeme_local_gateway.c6_revalidation import (
    C6_DOCS_MCP_ENDPOINT,
    C6_MAX_MCP_ENVELOPE_BYTES,
    C6AcquisitionError,
    C6FailureCode,
    C6PolicyLifecycle,
    C6ReportState,
    C6RevalidationPolicy,
    C6RevalidationReport,
    C6SourcePolicy,
    C6SourceState,
    OpenAIDocsMcpClient,
    _assert_no_sensitive_process_environment,
    _document_from_json_rpc,
    _parse_sse_json,
    _safe_state_output,
    build_current_c6_policy,
    canonical_sha256,
    commit_c6_policy,
    evaluate_c6_sources,
    main,
    normalize_official_markdown,
    semantic_markdown_text,
    verify_c6_policy,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "governance/c6-revalidation-policy.json"
C3_REGISTRY_PATH = ROOT / "governance/c3-capability-registry.json"
NOW = datetime(2026, 8, 7, 15, 0, tzinfo=UTC)


def _synthetic_policy() -> tuple[C6RevalidationPolicy, dict[str, str]]:
    reviewed = build_current_c6_policy()
    documents: dict[str, str] = {}
    sources: list[C6SourcePolicy] = []
    for source in reviewed.sources:
        marker = f"reviewed marker {source.source_id}"
        document = f"## Synthetic {source.source_id}\n\n{marker}\n"
        normalized = normalize_official_markdown(document)
        documents[source.source_id] = document
        sources.append(
            C6SourcePolicy(
                source_id=source.source_id,
                title=source.title,
                url=source.url,
                anchor=source.anchor,
                reviewed_normalized_bytes=len(normalized.encode("utf-8")),
                reviewed_content_sha256=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
                required_markers=(marker,),
            )
        )
    profile = build_current_c3_official_capability_profile()
    registry = build_current_c3_registry()
    return (
        commit_c6_policy(
            profile=profile,
            registry=registry,
            sources=tuple(sources),
            reviewed_at=NOW - timedelta(minutes=5),
            revalidate_after=NOW + timedelta(days=14) - timedelta(minutes=5),
        ),
        documents,
    )


def _sse_response(*, request_id: str, text: str) -> bytes:
    envelope = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": text,
                }
            ]
        },
    }
    return f"event: message\ndata: {json.dumps(envelope)}\n\n".encode()


def test_committed_policy_matches_reviewed_builder_and_denies_every_action() -> None:
    committed = C6RevalidationPolicy.model_validate(
        json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    )
    expected = build_current_c6_policy()
    assert committed == expected
    assert (
        committed.policy_sha256
        == "f0710c24b3dc2941d0c09c1bf5e360637af176a3d1eaf31dd6f208c09641597f"
    )
    assert len(committed.sources) == 4
    assert committed.fetched_content_can_change_gate is False
    assert committed.automatic_promotion_supported is False

    status = verify_c6_policy(
        root=ROOT,
        policy_path=POLICY_PATH,
        c3_registry_path=C3_REGISTRY_PATH,
        evaluated_at=NOW,
    )
    assert status.policy_lifecycle is C6PolicyLifecycle.CURRENT
    assert status.c3_lifecycle is EvidenceLifecycleState.CURRENT
    assert status.c3_final_status is C3GateStatus.NO_OFFICIAL_CHAT_TOOL_INTERFACE
    assert status.live_actions_allowed is False
    assert set(status.action_decisions) == set(C3ProtectedAction)
    assert not any(status.action_decisions.values())


def test_unchanged_sources_generate_only_a_candidate_and_never_promote() -> None:
    policy, documents = _synthetic_policy()
    result = evaluate_c6_sources(
        policy=policy,
        active_profile=build_current_c3_official_capability_profile(),
        registry=build_current_c3_registry(),
        acquired_at=NOW,
        fetch_markdown=lambda source: documents[source.source_id],
    )
    assert result.report.report_state is C6ReportState.UNCHANGED
    assert all(item.state is C6SourceState.UNCHANGED for item in result.report.observations)
    assert result.candidate is not None
    assert result.candidate.reviewer_state is EvidenceReviewerState.CANDIDATE
    assert result.report.candidate_profile_sha256 == result.candidate.profile_sha256
    assert result.report.candidate_can_change_gate is False
    assert result.report.promotion_allowed is False
    assert result.report.requires_independent_review is True
    assert result.report.live_actions_allowed is False
    assert not any(result.report.action_decisions.values())
    assert result.report.raw_content_persisted is False


@pytest.mark.parametrize("mutation", ["content", "marker"])
def test_source_drift_never_generates_a_candidate(mutation: str) -> None:
    policy, documents = _synthetic_policy()
    target = policy.sources[0]
    changed = dict(documents)
    if mutation == "content":
        changed[target.source_id] += "\nUnexpected change.\n"
    else:
        payload = policy.model_dump(mode="json", exclude={"policy_sha256"})
        payload["sources"][0]["required_markers"] = ["marker that is absent"]
        policy = C6RevalidationPolicy(
            **payload,
            policy_sha256=canonical_sha256(payload),
        )

    result = evaluate_c6_sources(
        policy=policy,
        active_profile=build_current_c3_official_capability_profile(),
        registry=build_current_c3_registry(),
        acquired_at=NOW,
        fetch_markdown=lambda source: changed[source.source_id],
    )
    assert result.report.report_state is C6ReportState.SOURCE_DRIFT
    assert result.report.drift_source_ids == (target.source_id,)
    assert result.candidate is None
    assert result.report.candidate_generated is False
    assert result.report.candidate_profile_sha256 is None
    assert result.report.promotion_allowed is False
    assert not any(result.report.action_decisions.values())


def test_policy_rejects_digest_tampering_unknown_fields_and_unapproved_hosts() -> None:
    payload = build_current_c6_policy().model_dump(mode="json")
    payload["policy_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="digest"):
        C6RevalidationPolicy.model_validate(payload)

    payload = build_current_c6_policy().model_dump(mode="json")
    payload["unknown"] = True
    with pytest.raises(ValidationError):
        C6RevalidationPolicy.model_validate(payload)

    payload = build_current_c6_policy().model_dump(mode="json", exclude={"policy_sha256"})
    payload["sources"][0]["url"] = "https://example.com/docs"
    with pytest.raises(ValidationError, match="host"):
        C6RevalidationPolicy(
            **payload,
            policy_sha256=canonical_sha256(payload),
        )


def test_policy_rejects_duplicate_routes_and_overlong_review_window() -> None:
    payload = build_current_c6_policy().model_dump(mode="json", exclude={"policy_sha256"})
    payload["sources"][1]["url"] = payload["sources"][0]["url"]
    payload["sources"][1]["anchor"] = payload["sources"][0]["anchor"]
    with pytest.raises(ValidationError, match="routes"):
        C6RevalidationPolicy(
            **payload,
            policy_sha256=canonical_sha256(payload),
        )

    payload = build_current_c6_policy().model_dump(mode="json", exclude={"policy_sha256"})
    payload["revalidate_after"] = "2026-08-22T14:42:00Z"
    with pytest.raises(ValidationError, match="14 days"):
        C6RevalidationPolicy(
            **payload,
            policy_sha256=canonical_sha256(payload),
        )


def test_report_rejects_inconsistent_drift_and_digest() -> None:
    policy, documents = _synthetic_policy()
    report = evaluate_c6_sources(
        policy=policy,
        active_profile=build_current_c3_official_capability_profile(),
        registry=build_current_c3_registry(),
        acquired_at=NOW,
        fetch_markdown=lambda source: documents[source.source_id],
    ).report
    payload = report.model_dump(mode="json")
    payload["drift_source_ids"] = [policy.sources[0].source_id]
    with pytest.raises(ValidationError, match="drift"):
        C6RevalidationReport.model_validate(payload)

    payload = report.model_dump(mode="json")
    payload["report_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="digest"):
        C6RevalidationReport.model_validate(payload)


def test_markdown_normalization_is_stable_and_semantic_text_is_bounded() -> None:
    raw = "  \r\n## Caf\u0065\u0301  \r\n\r\n\r\nGo to [ChatGPT Plugins](https://chatgpt.com/plugins).  \r\n"
    normalized = normalize_official_markdown(raw)
    assert normalized == "## Café\n\nGo to [ChatGPT Plugins](https://chatgpt.com/plugins).\n"
    assert semantic_markdown_text(normalized) == "## Café Go to ChatGPT Plugins."
    with pytest.raises(ValueError, match="NUL"):
        normalize_official_markdown("bad\x00content")


def test_sse_parser_accepts_one_exact_message_and_rejects_ambiguity() -> None:
    value = _sse_response(request_id="c6-source", text="reviewed")
    envelope = _parse_sse_json(value, expected_id="c6-source")
    assert _document_from_json_rpc(envelope) == "reviewed"

    with pytest.raises(C6AcquisitionError) as multiple:
        _parse_sse_json(value + value, expected_id="c6-source")
    assert multiple.value.code is C6FailureCode.SSE_INVALID

    with pytest.raises(C6AcquisitionError) as wrong_id:
        _parse_sse_json(value, expected_id="c6-other")
    assert wrong_id.value.code is C6FailureCode.JSON_RPC_INVALID


@pytest.mark.parametrize(
    ("envelope", "expected"),
    [
        ({"jsonrpc": "2.0", "id": "x", "error": {"code": -1}}, C6FailureCode.MCP_TOOL_FAILED),
        (
            {"jsonrpc": "2.0", "id": "x", "result": {"content": []}},
            C6FailureCode.JSON_RPC_INVALID,
        ),
        (
            {
                "jsonrpc": "2.0",
                "id": "x",
                "result": {
                    "content": [
                        {"type": "text", "text": "one"},
                        {"type": "text", "text": "two"},
                    ]
                },
            },
            C6FailureCode.JSON_RPC_INVALID,
        ),
    ],
)
def test_json_rpc_document_contract_rejects_errors_and_multiple_blocks(
    envelope: dict[str, object],
    expected: C6FailureCode,
) -> None:
    with pytest.raises(C6AcquisitionError) as error:
        _document_from_json_rpc(envelope)
    assert error.value.code is expected


def test_json_rpc_document_contract_rejects_unknown_and_duplicate_fields() -> None:
    unknown = {
        "jsonrpc": "2.0",
        "id": "x",
        "result": {"content": [{"type": "text", "text": "one"}]},
        "unexpected": True,
    }
    with pytest.raises(C6AcquisitionError) as extra:
        _document_from_json_rpc(unknown)
    assert extra.value.code is C6FailureCode.JSON_RPC_INVALID

    duplicate = (
        b'event: message\ndata: {"jsonrpc":"2.0","id":"c6-source",'
        b'"id":"substituted","result":{"content":[{"type":"text","text":"one"}]}}\n\n'
    )
    with pytest.raises(C6AcquisitionError) as repeated:
        _parse_sse_json(duplicate, expected_id="c6-source")
    assert repeated.value.code is C6FailureCode.JSON_RPC_INVALID


def test_docs_mcp_client_is_read_only_bounded_and_rejects_redirects() -> None:
    source = build_current_c6_policy().sources[0]

    def success(request: httpx.Request) -> httpx.Response:
        assert request.url == C6_DOCS_MCP_ENDPOINT
        assert request.headers.get("authorization") is None
        payload = json.loads(request.content)
        assert payload["method"] == "tools/call"
        assert payload["params"]["name"] == "fetch_openai_doc"
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=_sse_response(
                request_id=f"c6-{source.source_id}",
                text="bounded markdown",
            ),
        )

    client = OpenAIDocsMcpClient(
        endpoint=C6_DOCS_MCP_ENDPOINT,
        transport=httpx.MockTransport(success),
    )
    assert client.fetch(source) == "bounded markdown"

    redirecting = OpenAIDocsMcpClient(
        endpoint=C6_DOCS_MCP_ENDPOINT,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(302, headers={"location": "https://example.com"})
        ),
    )
    with pytest.raises(C6AcquisitionError) as redirect:
        redirecting.fetch(source)
    assert redirect.value.code is C6FailureCode.HTTP_FAILED


def test_docs_mcp_client_rejects_oversized_and_wrong_content_type() -> None:
    source = build_current_c6_policy().sources[0]
    oversized = OpenAIDocsMcpClient(
        endpoint=C6_DOCS_MCP_ENDPOINT,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=b"x" * (C6_MAX_MCP_ENVELOPE_BYTES + 1),
            )
        ),
    )
    with pytest.raises(C6AcquisitionError) as large:
        oversized.fetch(source)
    assert large.value.code is C6FailureCode.RESPONSE_TOO_LARGE

    wrong_type = OpenAIDocsMcpClient(
        endpoint=C6_DOCS_MCP_ENDPOINT,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=b"<html></html>",
            )
        ),
    )
    with pytest.raises(C6AcquisitionError) as content_type:
        wrong_type.fetch(source)
    assert content_type.value.code is C6FailureCode.CONTENT_TYPE_INVALID


def test_output_paths_are_local_and_sensitive_environment_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _safe_state_output(
        root=tmp_path,
        value=Path(".systeme-local/c6/receipt.json"),
    )
    assert output == tmp_path / ".systeme-local" / "c6" / "receipt.json"
    with pytest.raises(ValueError, match="must stay"):
        _safe_state_output(root=tmp_path, value=Path("governance/receipt.json"))

    monkeypatch.setenv("CONTROL_PLANE_API_KEY", "not-a-real-key")
    with pytest.raises(ValueError, match="secrets"):
        _assert_no_sensitive_process_environment()


def test_cli_policy_and_verify_are_deterministic(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["official-policy"]) == 0
    policy_output = json.loads(capsys.readouterr().out)
    assert policy_output["policy_sha256"] == build_current_c6_policy().policy_sha256

    assert (
        main(
            [
                "verify",
                "--root",
                str(ROOT),
                "--policy",
                str(POLICY_PATH),
                "--c3-registry",
                str(C3_REGISTRY_PATH),
                "--as-of",
                NOW.isoformat(),
                "--expect-all-denied",
            ]
        )
        == 0
    )
    status = json.loads(capsys.readouterr().out)
    assert status["live_actions_allowed"] is False
    assert set(status["action_decisions"].values()) == {False}
