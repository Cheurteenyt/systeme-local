from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_INPUT_BYTES = 8_192
CONTRACT_DOMAIN = b"systeme-local:operator-evidence-custodian-contract:v1\x00"
REQUEST_FIELDS = frozenset(
    {
        "protocol_version",
        "request_id",
        "operation",
        "challenge_sha256",
    }
)
_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ContractOperation(StrEnum):
    DESCRIBE_CONTRACT = "describe_contract"


class ContractStatus(StrEnum):
    OK = "ok"
    ERROR = "error"


class ProtocolErrorCode(StrEnum):
    INPUT_TOO_LARGE = "input_too_large"
    MULTIPLE_MESSAGES = "multiple_messages"
    INVALID_JSON = "invalid_json"
    INVALID_SHAPE = "invalid_shape"
    UNKNOWN_FIELD = "unknown_field"
    MISSING_FIELD = "missing_field"
    UNSUPPORTED_PROTOCOL_VERSION = "unsupported_protocol_version"
    INVALID_REQUEST_ID = "invalid_request_id"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    INVALID_DIGEST = "invalid_digest"
    SERIALIZATION_FAILURE = "serialization_failure"


class ContractRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal[1] = 1
    request_id: str = Field(pattern=_IDENTIFIER_PATTERN.pattern)
    operation: Literal[ContractOperation.DESCRIBE_CONTRACT] = ContractOperation.DESCRIBE_CONTRACT
    challenge_sha256: str = Field(pattern=_SHA256_PATTERN.pattern)


class ContractDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    synthetic_only: Literal[True] = True
    real_evidence_ingestion: Literal[False] = False
    filesystem_access: Literal[False] = False
    network_access: Literal[False] = False
    sanitizer_execution: Literal[False] = False
    public_provider_model_authority: Literal[False] = False


class ContractSuccessResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal[1] = 1
    request_id: str = Field(pattern=_IDENTIFIER_PATTERN.pattern)
    status: Literal[ContractStatus.OK] = ContractStatus.OK
    operation: Literal[ContractOperation.DESCRIBE_CONTRACT] = ContractOperation.DESCRIBE_CONTRACT
    challenge_sha256: str = Field(pattern=_SHA256_PATTERN.pattern)
    contract_sha256: str = Field(pattern=_SHA256_PATTERN.pattern)
    contract: ContractDescriptor


class ContractErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal[1] = 1
    request_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN.pattern)
    status: Literal[ContractStatus.ERROR] = ContractStatus.ERROR
    error_code: ProtocolErrorCode


class ProtocolValidationError(ValueError):
    def __init__(
        self,
        code: ProtocolErrorCode,
        *,
        request_id: str | None = None,
    ) -> None:
        super().__init__(code.value)
        self.code = code
        self.request_id = request_id


def parse_contract_request_text(value: str) -> ContractRequest:
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_INPUT_BYTES:
        raise ProtocolValidationError(ProtocolErrorCode.INPUT_TOO_LARGE)

    line = _single_line(value)
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as error:
        raise ProtocolValidationError(ProtocolErrorCode.INVALID_JSON) from error

    if not isinstance(payload, dict):
        raise ProtocolValidationError(ProtocolErrorCode.INVALID_SHAPE)

    request_id = _safe_request_id(payload.get("request_id"))
    actual_fields = frozenset(payload)
    if actual_fields - REQUEST_FIELDS:
        raise ProtocolValidationError(
            ProtocolErrorCode.UNKNOWN_FIELD,
            request_id=request_id,
        )
    if REQUEST_FIELDS - actual_fields:
        raise ProtocolValidationError(
            ProtocolErrorCode.MISSING_FIELD,
            request_id=request_id,
        )

    protocol_version = payload.get("protocol_version")
    if (
        not isinstance(protocol_version, int)
        or isinstance(protocol_version, bool)
        or protocol_version != 1
    ):
        raise ProtocolValidationError(
            ProtocolErrorCode.UNSUPPORTED_PROTOCOL_VERSION,
            request_id=request_id,
        )

    raw_request_id = payload.get("request_id")
    if not isinstance(raw_request_id, str) or _IDENTIFIER_PATTERN.fullmatch(raw_request_id) is None:
        raise ProtocolValidationError(ProtocolErrorCode.INVALID_REQUEST_ID)

    if payload.get("operation") != ContractOperation.DESCRIBE_CONTRACT.value:
        raise ProtocolValidationError(
            ProtocolErrorCode.UNSUPPORTED_OPERATION,
            request_id=raw_request_id,
        )

    challenge = payload.get("challenge_sha256")
    if not isinstance(challenge, str) or _SHA256_PATTERN.fullmatch(challenge) is None:
        raise ProtocolValidationError(
            ProtocolErrorCode.INVALID_DIGEST,
            request_id=raw_request_id,
        )

    return ContractRequest.model_validate(payload)


def compute_contract_sha256(request: ContractRequest) -> str:
    digest = hashlib.sha256()
    digest.update(CONTRACT_DOMAIN)
    for field in (
        str(request.protocol_version),
        request.request_id,
        request.operation.value,
        request.challenge_sha256,
    ):
        encoded = field.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def build_contract_success_response(
    request: ContractRequest,
) -> ContractSuccessResponse:
    return ContractSuccessResponse(
        request_id=request.request_id,
        challenge_sha256=request.challenge_sha256,
        contract_sha256=compute_contract_sha256(request),
        contract=ContractDescriptor(),
    )


def parse_contract_response_text(
    value: str,
) -> ContractSuccessResponse | ContractErrorResponse:
    line = _single_line(value)
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as error:
        raise ProtocolValidationError(ProtocolErrorCode.INVALID_JSON) from error

    if not isinstance(payload, dict):
        raise ProtocolValidationError(ProtocolErrorCode.INVALID_SHAPE)

    if payload.get("status") == ContractStatus.OK.value:
        response = ContractSuccessResponse.model_validate(payload)
        expected_request = ContractRequest(
            request_id=response.request_id,
            challenge_sha256=response.challenge_sha256,
        )
        expected = build_contract_success_response(expected_request)
        if response != expected:
            raise ProtocolValidationError(ProtocolErrorCode.INVALID_DIGEST)
        return response

    if payload.get("status") == ContractStatus.ERROR.value:
        return ContractErrorResponse.model_validate(payload)

    raise ProtocolValidationError(ProtocolErrorCode.INVALID_SHAPE)


def encode_contract_request(request: ContractRequest) -> str:
    return request.model_dump_json() + "\n"


def _single_line(value: str) -> str:
    if value.endswith("\r\n"):
        line = value[:-2]
    elif value.endswith("\n"):
        line = value[:-1]
    else:
        line = value

    if "\r" in line or "\n" in line:
        raise ProtocolValidationError(ProtocolErrorCode.MULTIPLE_MESSAGES)
    if not line:
        raise ProtocolValidationError(ProtocolErrorCode.INVALID_JSON)
    return line


def _safe_request_id(value: object) -> str | None:
    if isinstance(value, str) and _IDENTIFIER_PATTERN.fullmatch(value) is not None:
        return value
    return None
