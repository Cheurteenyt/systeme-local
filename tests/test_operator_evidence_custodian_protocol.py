from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import ValidationError

import systeme_local_gateway.providers as providers
from systeme_local_gateway.providers._operator_evidence import (
    ContractErrorResponse,
    ContractRequest,
    ContractSuccessResponse,
    CustodianExecutionError,
    ProcessResult,
    ProtocolErrorCode,
    ProtocolValidationError,
    build_contract_success_response,
    encode_contract_request,
    parse_contract_request_text,
    parse_contract_response_text,
    run_contract_probe,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "operator_evidence_custodian"
VALID_REQUEST = FIXTURES / "valid_request.ndjson"
VALID_RESPONSE = FIXTURES / "valid_response.ndjson"
INVALID_CASES = FIXTURES / "invalid_cases.json"


@dataclass
class RecordingExecutor:
    result: ProcessResult
    executable: Path | None = None
    stdin: str | None = None
    timeout_seconds: float | None = None

    def run(
        self,
        *,
        executable: Path,
        stdin: str,
        timeout_seconds: float,
    ) -> ProcessResult:
        self.executable = executable
        self.stdin = stdin
        self.timeout_seconds = timeout_seconds
        return self.result


def test_valid_request_and_response_fixtures_are_deterministic() -> None:
    request_text = VALID_REQUEST.read_text(encoding="utf-8")
    response_text = VALID_RESPONSE.read_text(encoding="utf-8")

    request = parse_contract_request_text(request_text)
    response = parse_contract_response_text(response_text)

    assert request == ContractRequest(
        request_id="contract_probe_001",
        challenge_sha256="3e5318cc2a895a2db4d7cb083f095ae9d33c929cfe5aefd3d0d9798fd25e4f39",
    )
    assert encode_contract_request(request) == request_text
    assert isinstance(response, ContractSuccessResponse)
    assert response == build_contract_success_response(request)
    assert (
        response.contract_sha256
        == "ac0b52c54d52e4733dd965b973f08e47e8d1a7435541052262061ad51f51f823"
    )


def test_invalid_conformance_cases_fail_with_exact_codes() -> None:
    cases = json.loads(INVALID_CASES.read_text(encoding="utf-8"))

    for case in cases:
        with pytest.raises(ProtocolValidationError) as captured:
            parse_contract_request_text(case["input"])

        assert captured.value.code.value == case["error_code"], case["name"]


def test_response_models_reject_unknown_fields_and_bad_commitments() -> None:
    payload = json.loads(VALID_RESPONSE.read_text(encoding="utf-8"))
    payload["source_path"] = "C:/operator/secret.txt"

    with pytest.raises(ValidationError):
        ContractSuccessResponse.model_validate(payload)

    payload.pop("source_path")
    payload["contract_sha256"] = "0" * 64

    with pytest.raises(ProtocolValidationError) as captured:
        parse_contract_response_text(json.dumps(payload, separators=(",", ":")) + "\n")

    assert captured.value.code is ProtocolErrorCode.INVALID_DIGEST


def test_runner_uses_only_stdin_and_validates_the_exact_response() -> None:
    request = parse_contract_request_text(VALID_REQUEST.read_text(encoding="utf-8"))
    response_text = VALID_RESPONSE.read_text(encoding="utf-8")
    executor = RecordingExecutor(ProcessResult(returncode=0, stdout=response_text, stderr=""))
    executable = Path("custodian-synthetic-binary")

    response = run_contract_probe(
        executable=executable,
        request=request,
        executor=executor,
    )

    assert response == build_contract_success_response(request)
    assert executor.executable == executable
    assert executor.stdin == encode_contract_request(request)
    assert executor.timeout_seconds == 5.0


@pytest.mark.parametrize(
    ("result", "message", "code"),
    [
        (
            ProcessResult(
                returncode=0,
                stdout=VALID_RESPONSE.read_text(encoding="utf-8"),
                stderr="noise",
            ),
            "emitted stderr",
            None,
        ),
        (
            ProcessResult(
                returncode=0,
                stdout=VALID_RESPONSE.read_text() + "{}\n",
                stderr="",
            ),
            "malformed protocol response",
            ProtocolErrorCode.MULTIPLE_MESSAGES,
        ),
        (
            ProcessResult(
                returncode=2,
                stdout=(
                    '{"protocol_version":1,"request_id":"contract_probe_001",'
                    '"status":"error","error_code":"unknown_field"}\n'
                ),
                stderr="",
            ),
            "rejected the request",
            ProtocolErrorCode.UNKNOWN_FIELD,
        ),
    ],
)
def test_runner_fails_closed(
    result: ProcessResult,
    message: str,
    code: ProtocolErrorCode | None,
) -> None:
    request = parse_contract_request_text(VALID_REQUEST.read_text(encoding="utf-8"))
    executor = RecordingExecutor(result)

    with pytest.raises(CustodianExecutionError) as captured:
        run_contract_probe(
            executable=Path("custodian-synthetic-binary"),
            request=request,
            executor=executor,
        )

    assert message in str(captured.value)
    assert captured.value.code is code


def test_error_response_is_typed_and_path_free() -> None:
    response = parse_contract_response_text(
        ('{"protocol_version":1,"request_id":null,"status":"error","error_code":"unknown_field"}\n')
    )

    assert isinstance(response, ContractErrorResponse)
    serialized = response.model_dump_json()
    for forbidden in (
        "source_path",
        "raw_evidence",
        "credential",
        "secret",
        "token",
        "endpoint",
    ):
        assert forbidden not in serialized


def test_private_package_does_not_change_provider_exports() -> None:
    assert len(providers.__all__) == 179
    assert not any(
        name.startswith("Contract") or name.startswith("Custodian") for name in providers.__all__
    )
