from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .models import (
    ContractErrorResponse,
    ContractRequest,
    ContractSuccessResponse,
    ProtocolErrorCode,
    ProtocolValidationError,
    encode_contract_request,
    parse_contract_response_text,
)

MAX_STDERR_BYTES = 4_096


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str


class ProcessExecutor(Protocol):
    def run(
        self,
        *,
        executable: Path,
        stdin: str,
        timeout_seconds: float,
    ) -> ProcessResult: ...


@dataclass(frozen=True, slots=True)
class SubprocessExecutor:
    def run(
        self,
        *,
        executable: Path,
        stdin: str,
        timeout_seconds: float,
    ) -> ProcessResult:
        try:
            completed = subprocess.run(
                [str(executable)],
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                shell=False,
                env={"NO_COLOR": "1"},
            )
        except subprocess.TimeoutExpired as error:
            raise CustodianExecutionError(
                "operator-evidence custodian timed out",
            ) from error

        return ProcessResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


class CustodianExecutionError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        code: ProtocolErrorCode | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code


def run_contract_probe(
    *,
    executable: Path,
    request: ContractRequest,
    timeout_seconds: float = 5.0,
    executor: ProcessExecutor | None = None,
) -> ContractSuccessResponse:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    selected_executor = executor if executor is not None else SubprocessExecutor()
    result = selected_executor.run(
        executable=executable,
        stdin=encode_contract_request(request),
        timeout_seconds=timeout_seconds,
    )

    if len(result.stderr.encode("utf-8")) > MAX_STDERR_BYTES:
        raise CustodianExecutionError("operator-evidence custodian stderr exceeded limit")
    if result.returncode == 0 and result.stderr:
        raise CustodianExecutionError(
            "operator-evidence custodian emitted stderr on success",
        )

    try:
        response = parse_contract_response_text(result.stdout)
    except ProtocolValidationError as error:
        raise CustodianExecutionError(
            "operator-evidence custodian returned a malformed protocol response",
            code=error.code,
        ) from error
    if result.returncode != 0:
        if isinstance(response, ContractErrorResponse):
            raise CustodianExecutionError(
                "operator-evidence custodian rejected the request",
                code=response.error_code,
            )
        raise CustodianExecutionError(
            "operator-evidence custodian failed without a typed error",
        )

    if not isinstance(response, ContractSuccessResponse):
        raise CustodianExecutionError(
            "operator-evidence custodian returned an error with exit code zero",
        )
    if response.request_id != request.request_id:
        raise CustodianExecutionError(
            "operator-evidence custodian request identifier mismatch",
        )
    if response.challenge_sha256 != request.challenge_sha256:
        raise CustodianExecutionError(
            "operator-evidence custodian challenge mismatch",
        )
    return response
