from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import make_png
from pydantic import ValidationError

from systeme_local_gateway import c9_local_ai
from systeme_local_gateway.c9_local_ai import (
    C9_LOCAL_AI_MAX_DOCUMENT_BYTES,
    C9_LOCAL_AI_MAX_IMAGE_BYTES,
    C9LocalAICapabilities,
    C9LocalAIConfig,
    C9LocalAIError,
    C9LocalAIErrorCode,
    C9LocalAIInference,
    C9LocalAIProviderKind,
    c9_local_ai_runtime_observation_sha256,
    capture_c9_local_ai_runtime_continuity,
    commit_c9_local_ai_runtime_observation,
    run_c9_local_ai_inference,
    validate_c9_local_ai_endpoint,
    verify_c9_local_ai_runtime_observation,
)

IMAGE_NONCE = "c9_image_nonce_0123456789"
DOCUMENT_NONCE = "c9_document_nonce_012345"
DOCUMENT_BYTES = b"synthetic document nonce: c9_document_nonce_012345\n"
IMAGE_NONCE_SHA256 = hashlib.sha256(IMAGE_NONCE.encode()).hexdigest()
DOCUMENT_NONCE_SHA256 = hashlib.sha256(DOCUMENT_NONCE.encode()).hexdigest()
RUNTIME_OBSERVATION_SHA256 = hashlib.sha256(b"runtime-observation").hexdigest()
AUDIT_KEY = "c9-local-ai-test-audit-key-" + ("a" * 32)


def _completion(
    *,
    image_nonce: str = IMAGE_NONCE,
    document_nonce: str = DOCUMENT_NONCE,
) -> bytes:
    content = json.dumps(
        {
            "version": "1",
            "image_nonce": image_nonce,
            "document_nonce": document_nonce,
        },
        separators=(",", ":"),
    )
    return json.dumps(
        {"choices": [{"message": {"content": content}}]},
        separators=(",", ":"),
    ).encode()


class _ServerState:
    def __init__(
        self,
        *,
        body: bytes,
        status: int = 200,
        content_type: str = "application/json",
        delay_seconds: float = 0.0,
        declared_length: str | None = None,
        omit_content_length: bool = False,
    ) -> None:
        self.body = body
        self.status = status
        self.content_type = content_type
        self.delay_seconds = delay_seconds
        self.declared_length = declared_length
        self.omit_content_length = omit_content_length
        self.requests: list[dict[str, object]] = []


@contextmanager
def _loopback_server(
    *,
    body: bytes | None = None,
    status: int = 200,
    content_type: str = "application/json",
    delay_seconds: float = 0.0,
    declared_length: str | None = None,
    omit_content_length: bool = False,
) -> Iterator[tuple[str, _ServerState]]:
    state = _ServerState(
        body=_completion() if body is None else body,
        status=status,
        content_type=content_type,
        delay_seconds=delay_seconds,
        declared_length=declared_length,
        omit_content_length=omit_content_length,
    )

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            request_body = self.rfile.read(length)
            state.requests.append(
                {
                    "path": self.path,
                    "headers": {key.lower(): value for key, value in self.headers.items()},
                    "body": request_body,
                }
            )
            if state.delay_seconds:
                time.sleep(state.delay_seconds)
            self.send_response(state.status)
            self.send_header("Content-Type", state.content_type)
            if state.omit_content_length:
                self.send_header("Connection", "close")
                self.close_connection = True
            else:
                self.send_header(
                    "Content-Length",
                    state.declared_length
                    if state.declared_length is not None
                    else str(len(state.body)),
                )
            self.end_headers()
            try:
                self.wfile.write(state.body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, _format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}/v1/chat/completions", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _config(endpoint: str, **changes: object) -> C9LocalAIConfig:
    values: dict[str, object] = {
        "endpoint": endpoint,
        "visible_model_label": "local-vision-model",
        "runtime_observation_sha256": RUNTIME_OBSERVATION_SHA256,
        "capabilities": C9LocalAICapabilities(
            image_input=True,
            utf8_document_input=True,
            structured_json_output=True,
        ),
    }
    values.update(changes)
    return C9LocalAIConfig(**values)


def _run(
    endpoint: str,
    *,
    expected_image_nonce_sha256: str = IMAGE_NONCE_SHA256,
    expected_document_nonce_sha256: str = DOCUMENT_NONCE_SHA256,
    **config_changes: object,
) -> C9LocalAIInference:
    return run_c9_local_ai_inference(
        config=_config(endpoint, **config_changes),
        image_bytes=make_png(8, 8),
        image_media_type="image/png",
        document_bytes=DOCUMENT_BYTES,
        expected_image_nonce_sha256=expected_image_nonce_sha256,
        expected_document_nonce_sha256=expected_document_nonce_sha256,
    )


def _runtime_observation(
    tmp_path: Path,
    *,
    observed_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> c9_local_ai.C9LocalAIRuntimeObservation:
    at = observed_at or datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
    executable = tmp_path / "ollama.exe"
    executable.write_bytes(b"reviewed native ollama executable")
    return commit_c9_local_ai_runtime_observation(
        cycle_id="c9_cycle_" + ("1" * 32),
        provider_kind=C9LocalAIProviderKind.OLLAMA,
        product_name="Ollama",
        product_version="0.11.0",
        listening_pid=4242,
        executable_path=executable,
        endpoint="http://127.0.0.1:11434/v1/chat/completions",
        visible_model_label="qwen2.5-vl:7b",
        runtime_request_logging_disabled=True,
        runtime_request_persistence_disabled=True,
        operator_confirmed_native_runtime=True,
        operator_confirmed_runtime_privacy_settings=True,
        observed_at=at,
        expires_at=expires_at or at + timedelta(minutes=10),
        audit_key=AUDIT_KEY,
    )


def test_unversioned_runtime_label_must_bind_the_executable(
    tmp_path: Path,
) -> None:
    observation = _runtime_observation(tmp_path)
    payload = observation.model_dump(mode="python")
    prefix = "unversioned-binary-sha256:"
    payload["product_version"] = prefix + observation.executable_sha256

    accepted = c9_local_ai.C9LocalAIRuntimeObservation.model_validate(payload)

    assert accepted.product_version == prefix + accepted.executable_sha256
    payload["product_version"] = prefix + ("0" * 64)
    with pytest.raises(ValueError, match="does not bind the executable"):
        c9_local_ai.C9LocalAIRuntimeObservation.model_validate(payload)


class _FakeNativeRuntimeProcess:
    def __init__(
        self,
        *,
        executable_path: Path,
        create_times: tuple[float, ...] = (123.0,),
    ) -> None:
        self._executable_path = executable_path
        self._create_times = list(create_times)

    def create_time(self) -> float:
        if len(self._create_times) > 1:
            return self._create_times.pop(0)
        return self._create_times[0]

    def exe(self) -> str:
        return str(self._executable_path)

    def is_running(self) -> bool:
        return True

    def status(self) -> str:
        return "running"


def _patch_native_runtime_identity(
    monkeypatch: pytest.MonkeyPatch,
    *,
    executable_path: Path,
    listener_pids: tuple[int, ...] = (4242,),
    create_times: tuple[float, ...] = (123.0,),
) -> None:
    listener_sequence = list(listener_pids)
    process = _FakeNativeRuntimeProcess(
        executable_path=executable_path,
        create_times=create_times,
    )

    def net_connections(*, kind: str) -> list[SimpleNamespace]:
        assert kind == "tcp4"
        listener_pid = (
            listener_sequence.pop(0) if len(listener_sequence) > 1 else listener_sequence[0]
        )
        return [
            SimpleNamespace(
                status=c9_local_ai.psutil.CONN_LISTEN,
                laddr=("127.0.0.1", 11434),
                pid=listener_pid,
            )
        ]

    def process_for_pid(pid: int) -> _FakeNativeRuntimeProcess:
        assert pid == 4242
        return process

    monkeypatch.setattr(c9_local_ai.psutil, "net_connections", net_connections)
    monkeypatch.setattr(c9_local_ai.psutil, "Process", process_for_pid)


def test_runtime_observation_is_hmac_bound_exact_and_fresh(tmp_path: Path) -> None:
    observation = _runtime_observation(tmp_path)
    verified = verify_c9_local_ai_runtime_observation(
        observation,
        endpoint="http://127.0.0.1:11434/v1/chat/completions",
        visible_model_label="qwen2.5-vl:7b",
        audit_key=AUDIT_KEY,
        evaluated_at=observation.observed_at,
    )

    assert verified.simulated is False
    assert verified.provider_kind is C9LocalAIProviderKind.OLLAMA
    assert verified.executable_basename == "ollama.exe"
    assert verified.runtime_request_logging_disabled is True
    assert verified.runtime_request_persistence_disabled is True
    assert (
        verified.privacy_settings_observation == "operator_confirmed_not_programmatically_detected"
    )
    assert len(c9_local_ai_runtime_observation_sha256(verified)) == 64


def test_runtime_observation_accepts_lm_studio_llmster_listener(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "llmster.exe"
    executable.write_bytes(b"reviewed native LM Studio llmster executable")
    observed_at = datetime(2026, 7, 28, 8, 0, tzinfo=UTC)
    observation = commit_c9_local_ai_runtime_observation(
        cycle_id="c9_cycle_" + ("3" * 32),
        provider_kind=C9LocalAIProviderKind.LM_STUDIO,
        product_name="LM Studio",
        product_version="0.4.0",
        listening_pid=4242,
        executable_path=executable,
        endpoint="http://127.0.0.1:1234/v1/chat/completions",
        visible_model_label="qwen/qwen3.5-4b",
        runtime_request_logging_disabled=True,
        runtime_request_persistence_disabled=True,
        operator_confirmed_native_runtime=True,
        operator_confirmed_runtime_privacy_settings=True,
        observed_at=observed_at,
        expires_at=observed_at + timedelta(minutes=10),
        audit_key=AUDIT_KEY,
    )

    assert observation.provider_kind is C9LocalAIProviderKind.LM_STUDIO
    assert observation.executable_basename == "llmster.exe"


def test_runtime_continuity_matches_listener_pid_and_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observation = _runtime_observation(tmp_path)
    executable = tmp_path / "ollama.exe"
    _patch_native_runtime_identity(
        monkeypatch,
        executable_path=executable,
    )

    snapshot = capture_c9_local_ai_runtime_continuity(
        observation,
        endpoint="http://127.0.0.1:11434/v1/chat/completions",
    )

    assert snapshot.listening_pid == 4242
    assert snapshot.process_create_time == 123.0
    assert snapshot.executable_basename == "ollama.exe"
    assert snapshot.executable_sha256 == observation.executable_sha256
    assert snapshot.endpoint_sha256 == observation.endpoint_sha256


def test_runtime_continuity_rejects_listener_pid_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observation = _runtime_observation(tmp_path)
    _patch_native_runtime_identity(
        monkeypatch,
        executable_path=tmp_path / "ollama.exe",
        listener_pids=(5252,),
    )

    with pytest.raises(C9LocalAIError) as error:
        capture_c9_local_ai_runtime_continuity(
            observation,
            endpoint="http://127.0.0.1:11434/v1/chat/completions",
        )

    assert error.value.code is C9LocalAIErrorCode.RUNTIME_CONTINUITY_FAILED
    assert str(error.value) == "local AI runtime continuity verification failed"


@pytest.mark.parametrize("mismatch", ["basename", "sha256"])
def test_runtime_continuity_rejects_executable_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    observation = _runtime_observation(tmp_path)
    replacement_directory = tmp_path / "replacement"
    replacement_directory.mkdir()
    replacement = replacement_directory / (
        "other-runtime.exe" if mismatch == "basename" else "ollama.exe"
    )
    replacement.write_bytes(
        b"reviewed native ollama executable"
        if mismatch == "basename"
        else b"runtime executable with another digest"
    )
    _patch_native_runtime_identity(
        monkeypatch,
        executable_path=replacement,
    )

    with pytest.raises(C9LocalAIError) as error:
        capture_c9_local_ai_runtime_continuity(
            observation,
            endpoint="http://127.0.0.1:11434/v1/chat/completions",
        )

    assert error.value.code is C9LocalAIErrorCode.RUNTIME_CONTINUITY_FAILED
    assert str(error.value) == "local AI runtime continuity verification failed"
    assert str(replacement) not in str(error.value)


def test_runtime_continuity_rejects_listener_takeover_during_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observation = _runtime_observation(tmp_path)
    _patch_native_runtime_identity(
        monkeypatch,
        executable_path=tmp_path / "ollama.exe",
        listener_pids=(4242, 5252),
    )

    with pytest.raises(C9LocalAIError) as error:
        capture_c9_local_ai_runtime_continuity(
            observation,
            endpoint="http://127.0.0.1:11434/v1/chat/completions",
        )

    assert error.value.code is C9LocalAIErrorCode.RUNTIME_CONTINUITY_FAILED


def test_runtime_observation_rejects_tamper_wrong_binding_and_expiry(
    tmp_path: Path,
) -> None:
    observation = _runtime_observation(tmp_path)
    tampered_payload = observation.model_dump()
    tampered_payload["product_version"] = "tampered"
    tampered = type(observation).model_validate(tampered_payload)
    with pytest.raises(ValueError):
        verify_c9_local_ai_runtime_observation(
            tampered,
            endpoint="http://127.0.0.1:11434/v1/chat/completions",
            visible_model_label="qwen2.5-vl:7b",
            audit_key=AUDIT_KEY,
            evaluated_at=observation.observed_at,
        )
    with pytest.raises(ValueError):
        verify_c9_local_ai_runtime_observation(
            observation,
            endpoint="http://127.0.0.1:11435/v1/chat/completions",
            visible_model_label="qwen2.5-vl:7b",
            audit_key=AUDIT_KEY,
            evaluated_at=observation.observed_at,
        )
    with pytest.raises(ValueError):
        verify_c9_local_ai_runtime_observation(
            observation,
            endpoint="http://127.0.0.1:11434/v1/chat/completions",
            visible_model_label="qwen2.5-vl:7b",
            audit_key=AUDIT_KEY,
            evaluated_at=observation.expires_at,
        )


def test_runtime_observation_cli_uses_audit_key_and_emits_metadata_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    executable = tmp_path / "ollama.exe"
    executable.write_bytes(b"reviewed native executable")
    monkeypatch.setenv("SLG_AUDIT_KEY", AUDIT_KEY)
    result = c9_local_ai.main(
        [
            "commit-runtime-observation",
            "--cycle-id",
            "c9_cycle_" + ("1" * 32),
            "--provider-kind",
            "ollama",
            "--product-name",
            "Ollama",
            "--product-version",
            "0.11.0",
            "--listening-pid",
            "4242",
            "--executable-path",
            str(executable),
            "--endpoint",
            "http://127.0.0.1:11434/v1/chat/completions",
            "--visible-model-label",
            "qwen2.5-vl:7b",
            "--observed-at",
            "2026-07-28T12:00:00Z",
            "--expires-at",
            "2026-07-28T12:10:00Z",
            "--confirmed-native-runtime",
            "--confirmed-runtime-request-logging-disabled",
            "--confirmed-runtime-request-persistence-disabled",
            "--confirmed-runtime-privacy-settings",
        ]
    )
    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["provider_kind"] == "ollama"
    assert payload["executable_basename"] == "ollama.exe"
    assert payload["process_identity_observation"] == (
        "operator_attested_not_programmatically_verified"
    )
    assert str(executable) not in captured.out


def test_runtime_executable_hash_rejects_a_hard_link(tmp_path: Path) -> None:
    executable = tmp_path / "ollama.exe"
    alias = tmp_path / "ollama-hardlink.exe"
    executable.write_bytes(b"reviewed runtime executable")
    try:
        os.link(executable, alias)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")

    with pytest.raises(ValueError, match="singly-linked"):
        c9_local_ai._inspect_runtime_executable(executable)


def test_runtime_executable_hash_rejects_replacement_before_final_revalidation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable = tmp_path / "ollama.exe"
    replacement = tmp_path / "replacement.exe"
    executable.write_bytes(b"reviewed runtime executable")
    replacement.write_bytes(b"unreviewed replacement executable")
    original_close = c9_local_ai.os.close
    replaced = False

    def close_then_replace(descriptor: int) -> None:
        nonlocal replaced
        original_close(descriptor)
        if not replaced:
            replaced = True
            os.replace(replacement, executable)

    monkeypatch.setattr(c9_local_ai.os, "close", close_then_replace)

    with pytest.raises(ValueError, match="changed after hashing"):
        c9_local_ai._inspect_runtime_executable(executable)
    assert replaced is True


def test_fake_http_transport_does_not_emit_native_runtime_observation() -> None:
    with _loopback_server() as (endpoint, _state):
        inference = _run(endpoint)

    assert set(inference.model_dump()) == {"receipt"}
    assert "runtime_observation" not in inference.model_dump()
    assert inference.receipt.runtime_observation_sha256 == RUNTIME_OBSERVATION_SHA256


def test_real_loopback_inference_is_bounded_structured_and_metadata_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://203.0.113.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://203.0.113.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://203.0.113.1:9")
    monkeypatch.setenv("NO_PROXY", "")

    with _loopback_server() as (endpoint, state):
        inference = _run(endpoint)

    internal_output = inference._verified_output_for_internal_use()
    assert internal_output.image_nonce == IMAGE_NONCE
    assert internal_output.document_nonce == DOCUMENT_NONCE
    assert inference.receipt.transport == "openai_compatible_chat_completions_loopback"
    assert inference.receipt.authentication == "none"
    assert inference.receipt.proxy_environment_used is False
    assert inference.receipt.adapter_persistent_storage_used is False
    assert inference.receipt.runtime_observation_sha256 == RUNTIME_OBSERVATION_SHA256
    assert inference.receipt.image_byte_count == len(make_png(8, 8))
    assert inference.receipt.document_byte_count == len(DOCUMENT_BYTES)
    assert inference.receipt.request_byte_count > len(DOCUMENT_BYTES)
    assert inference.receipt.response_byte_count == len(_completion())
    assert inference.receipt.expected_image_nonce_sha256 == IMAGE_NONCE_SHA256
    assert inference.receipt.expected_document_nonce_sha256 == DOCUMENT_NONCE_SHA256
    assert inference.receipt.nonce_hashes_verified is True
    assert inference.receipt.completed_at >= inference.receipt.started_at
    assert len(inference.receipt.receipt_sha256) == 64

    [request] = state.requests
    assert request["path"] == "/v1/chat/completions"
    headers = request["headers"]
    assert isinstance(headers, dict)
    assert "authorization" not in headers
    assert "cookie" not in headers
    payload = json.loads(request["body"])
    assert payload["model"] == "local-vision-model"
    assert payload["response_format"] == {"type": "json_object"}
    assert payload["stream"] is False
    user_parts = payload["messages"][1]["content"]
    assert DOCUMENT_BYTES.decode().strip() in user_parts[0]["text"]
    assert user_parts[1]["image_url"]["url"].startswith("data:image/png;base64,")

    public_representations = (
        repr(inference),
        str(inference),
        inference.model_dump_json(),
        json.dumps(inference.model_dump(), default=str),
        repr(inference.receipt),
        inference.receipt.model_dump_json(),
    )
    for serialized in public_representations:
        assert IMAGE_NONCE not in serialized
        assert DOCUMENT_NONCE not in serialized
        assert DOCUMENT_BYTES.decode().strip() not in serialized
        assert "data:image/" not in serialized
        assert "UNTRUSTED_SYNTHETIC" not in serialized
        assert endpoint not in serialized
        assert "local-vision-model" not in serialized
    assert set(inference.model_dump()) == {"receipt"}


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:8000/v1/chat/completions",
        "http://localhost:8000/v1/chat/completions",
        "http://user@127.0.0.1:8000/v1/chat/completions",
        "http://127.0.0.1/v1/chat/completions",
        "http://127.0.0.1:0/v1/chat/completions",
        "http://192.0.2.1:8000/v1/chat/completions",
        "http://127.0.0.1:8000/",
        "http://127.0.0.1:8000/v1/chat/completions?",
        "http://127.0.0.1:8000/v1/chat/completions#",
        "http://127.0.0.1:8000/v1/chat/completions?token=do-not-disclose",
        "http://127.0.0.1:8000/v1/chat/completions#fragment",
        "http://127.0.0.1:99999/v1/chat/completions",
        " http://127.0.0.1:8000/v1/chat/completions",
        "http://127.0.0.1:8000\\v1\\chat\\completions",
        "http://127.0.0.2:8000/v1/chat/completions",
        "http://[::1]:8000/v1/chat/completions",
        "http://[::1%25loopback]:8000/v1/chat/completions",
    ],
)
def test_endpoint_rejects_ambiguous_or_non_loopback_targets(endpoint: str) -> None:
    with pytest.raises(ValueError):
        validate_c9_local_ai_endpoint(endpoint)


def test_endpoint_accepts_only_literal_ipv4_127_0_0_1() -> None:
    assert (
        validate_c9_local_ai_endpoint("http://127.0.0.1:8000/v1/chat/completions")
        == "http://127.0.0.1:8000/v1/chat/completions"
    )


def test_config_errors_hide_endpoint_input_and_forbid_auth_fields() -> None:
    secret = "do-not-disclose"
    with pytest.raises(ValidationError) as error:
        C9LocalAIConfig(
            endpoint=f"http://127.0.0.1:8000/v1/chat/completions?token={secret}",
            visible_model_label="local-model",
            runtime_observation_sha256=RUNTIME_OBSERVATION_SHA256,
            capabilities=C9LocalAICapabilities(
                image_input=True,
                utf8_document_input=True,
                structured_json_output=True,
            ),
            api_key=secret,
        )
    assert secret not in str(error.value)


def test_inference_revalidates_constructed_config_before_network() -> None:
    secret = "do-not-disclose"
    unsafe = C9LocalAIConfig.model_construct(
        version="1",
        endpoint=f"http://192.0.2.1:8000/v1/chat/completions?token={secret}",
        visible_model_label="local-model",
        runtime_observation_sha256=RUNTIME_OBSERVATION_SHA256,
        capabilities=C9LocalAICapabilities(
            image_input=True,
            utf8_document_input=True,
            structured_json_output=True,
        ),
        authentication="none",
        connect_timeout_seconds=0.05,
        read_timeout_seconds=0.05,
        total_timeout_seconds=0.1,
        max_response_bytes=1_024,
    )
    with pytest.raises(C9LocalAIError) as error:
        run_c9_local_ai_inference(
            config=unsafe,
            image_bytes=make_png(),
            image_media_type="image/png",
            document_bytes=DOCUMENT_BYTES,
            expected_image_nonce_sha256=IMAGE_NONCE_SHA256,
            expected_document_nonce_sha256=DOCUMENT_NONCE_SHA256,
        )
    assert error.value.code is C9LocalAIErrorCode.CONFIG_INVALID
    assert secret not in str(error.value)


@pytest.mark.parametrize(
    ("image", "image_type", "document", "document_type", "code"),
    [
        (b"", "image/png", DOCUMENT_BYTES, "text/plain", C9LocalAIErrorCode.INPUT_INVALID),
        (
            b"not-a-png",
            "image/png",
            DOCUMENT_BYTES,
            "text/plain",
            C9LocalAIErrorCode.INPUT_INVALID,
        ),
        (
            make_png(),
            "image/gif",
            DOCUMENT_BYTES,
            "text/plain",
            C9LocalAIErrorCode.INPUT_INVALID,
        ),
        (
            make_png(20_000, 2),
            "image/png",
            DOCUMENT_BYTES,
            "text/plain",
            C9LocalAIErrorCode.INPUT_INVALID,
        ),
        (
            make_png(),
            "image/png",
            b"\xff",
            "text/plain",
            C9LocalAIErrorCode.INPUT_INVALID,
        ),
        (
            make_png(),
            "image/png",
            DOCUMENT_BYTES,
            "application/pdf",
            C9LocalAIErrorCode.INPUT_INVALID,
        ),
        (
            b"x" * (C9_LOCAL_AI_MAX_IMAGE_BYTES + 1),
            "image/png",
            DOCUMENT_BYTES,
            "text/plain",
            C9LocalAIErrorCode.INPUT_TOO_LARGE,
        ),
        (
            make_png(),
            "image/png",
            b"x" * (C9_LOCAL_AI_MAX_DOCUMENT_BYTES + 1),
            "text/plain",
            C9LocalAIErrorCode.INPUT_TOO_LARGE,
        ),
    ],
    ids=[
        "empty-image",
        "invalid-png",
        "unsupported-image-type",
        "oversized-image-dimension",
        "invalid-document-utf8",
        "unsupported-document-type",
        "oversized-image",
        "oversized-document",
    ],
)
def test_invalid_inputs_fail_before_network(
    image: bytes,
    image_type: str,
    document: bytes,
    document_type: str,
    code: C9LocalAIErrorCode,
) -> None:
    endpoint = "http://127.0.0.1:9/v1/chat/completions"
    with pytest.raises(C9LocalAIError) as error:
        run_c9_local_ai_inference(
            config=_config(endpoint),
            image_bytes=image,
            image_media_type=image_type,  # type: ignore[arg-type]
            document_bytes=document,
            document_media_type=document_type,  # type: ignore[arg-type]
            expected_image_nonce_sha256=IMAGE_NONCE_SHA256,
            expected_document_nonce_sha256=DOCUMENT_NONCE_SHA256,
        )
    assert error.value.code is code


@pytest.mark.parametrize(
    ("body", "status", "content_type", "declared_length", "code"),
    [
        (
            b'{"error":"sensitive response must not escape"}',
            500,
            "application/json",
            None,
            C9LocalAIErrorCode.HTTP_FAILED,
        ),
        (
            _completion(),
            200,
            "text/plain",
            None,
            C9LocalAIErrorCode.RESPONSE_INVALID,
        ),
        (
            b"not-json",
            200,
            "application/json",
            None,
            C9LocalAIErrorCode.RESPONSE_INVALID,
        ),
        (
            _completion(),
            200,
            "application/json",
            "999999",
            C9LocalAIErrorCode.RESPONSE_TOO_LARGE,
        ),
    ],
)
def test_http_and_envelope_failures_are_static_and_redacted(
    body: bytes,
    status: int,
    content_type: str,
    declared_length: str | None,
    code: C9LocalAIErrorCode,
) -> None:
    with (
        _loopback_server(
            body=body,
            status=status,
            content_type=content_type,
            declared_length=declared_length,
        ) as (endpoint, _state),
        pytest.raises(C9LocalAIError) as error,
    ):
        _run(endpoint)
    assert error.value.code is code
    assert "sensitive" not in str(error.value)
    assert endpoint not in str(error.value)


def test_streamed_response_without_content_length_is_still_bounded() -> None:
    with (
        _loopback_server(
            body=b"x" * 2_048,
            omit_content_length=True,
        ) as (endpoint, _state),
        pytest.raises(C9LocalAIError) as error,
    ):
        _run(endpoint, max_response_bytes=1_024)
    assert error.value.code is C9LocalAIErrorCode.RESPONSE_TOO_LARGE


@pytest.mark.parametrize(
    "content",
    [
        (
            '{"version":"1","image_nonce":"c9_image_nonce_0123456789",'
            '"image_nonce":"c9_image_nonce_other_1234",'
            '"document_nonce":"c9_document_nonce_012345"}'
        ),
        '{"version":"1","image_nonce":"too-short","document_nonce":"c9_document_nonce_012345"}',
        (
            '{"version":"1","image_nonce":"c9_same_nonce_0123456789",'
            '"document_nonce":"c9_same_nonce_0123456789"}'
        ),
        (
            '{"version":"1","image_nonce":"c9_image_nonce_0123456789",'
            '"document_nonce":"c9_document_nonce_012345","unexpected":true}'
        ),
    ],
)
def test_structured_output_rejects_duplicates_invalid_nonces_and_unknown_fields(
    content: str,
) -> None:
    body = json.dumps(
        {"choices": [{"message": {"content": content}}]},
        separators=(",", ":"),
    ).encode()
    with _loopback_server(body=body) as (endpoint, _state):
        with pytest.raises(C9LocalAIError) as error:
            _run(endpoint)
    assert error.value.code in {
        C9LocalAIErrorCode.RESPONSE_INVALID,
        C9LocalAIErrorCode.OUTPUT_INVALID,
    }
    assert content not in str(error.value)


@pytest.mark.parametrize(
    ("server_image_nonce", "server_document_nonce"),
    [
        ("c9_wrong_image_nonce_012345", DOCUMENT_NONCE),
        (IMAGE_NONCE, "c9_wrong_document_nonce_0123"),
        ("c9_wrong_image_nonce_012345", "c9_wrong_document_nonce_0123"),
    ],
)
def test_valid_but_mismatched_nonce_output_is_rejected_without_disclosure(
    server_image_nonce: str,
    server_document_nonce: str,
) -> None:
    body = _completion(
        image_nonce=server_image_nonce,
        document_nonce=server_document_nonce,
    )
    with _loopback_server(body=body) as (endpoint, _state):
        with pytest.raises(C9LocalAIError) as error:
            _run(endpoint)
    assert error.value.code is C9LocalAIErrorCode.NONCE_MISMATCH
    assert server_image_nonce not in str(error.value)
    assert server_document_nonce not in str(error.value)
    assert server_image_nonce not in repr(error.value)
    assert server_document_nonce not in repr(error.value)


@pytest.mark.parametrize(
    ("image_hash", "document_hash"),
    [
        ("not-a-sha256", DOCUMENT_NONCE_SHA256),
        (IMAGE_NONCE_SHA256.upper(), DOCUMENT_NONCE_SHA256),
        (IMAGE_NONCE_SHA256, IMAGE_NONCE_SHA256),
    ],
)
def test_expected_nonce_hashes_are_strict_and_distinct_before_network(
    image_hash: str,
    document_hash: str,
) -> None:
    with pytest.raises(C9LocalAIError) as error:
        _run(
            "http://127.0.0.1:9/v1/chat/completions",
            expected_image_nonce_sha256=image_hash,
            expected_document_nonce_sha256=document_hash,
        )
    assert error.value.code is C9LocalAIErrorCode.INPUT_INVALID
    assert image_hash not in str(error.value)
    assert document_hash not in str(error.value)


def test_read_timeout_is_bounded_and_metadata_free() -> None:
    with _loopback_server(delay_seconds=0.2) as (endpoint, _state):
        with pytest.raises(C9LocalAIError) as error:
            _run(
                endpoint,
                connect_timeout_seconds=0.05,
                read_timeout_seconds=0.05,
            )
    assert error.value.code is C9LocalAIErrorCode.TIMEOUT
    assert endpoint not in str(error.value)


def test_total_timeout_bounds_a_slow_but_individually_timely_response() -> None:
    with _loopback_server(delay_seconds=0.5) as (endpoint, _state):
        with pytest.raises(C9LocalAIError) as error:
            _run(
                endpoint,
                connect_timeout_seconds=1.0,
                read_timeout_seconds=1.0,
                total_timeout_seconds=0.1,
            )
    assert error.value.code is C9LocalAIErrorCode.TIMEOUT


def test_each_http_timeout_is_capped_by_the_total_timeout() -> None:
    timeout = c9_local_ai._bounded_http_timeout(
        _config(
            "http://127.0.0.1:8000/v1/chat/completions",
            connect_timeout_seconds=5.0,
            read_timeout_seconds=7.0,
            total_timeout_seconds=0.25,
        )
    )
    assert timeout.connect == 0.25
    assert timeout.read == 0.25
    assert timeout.write == 0.25
    assert timeout.pool == 0.25


def test_receipt_and_output_digest_tampering_is_rejected() -> None:
    with _loopback_server() as (endpoint, _state):
        inference = _run(endpoint)

    receipt_payload = inference.receipt.model_dump()
    receipt_payload["image_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        type(inference.receipt).model_validate(receipt_payload)

    receipt_payload = inference.receipt.model_dump()
    receipt_payload["expected_image_nonce_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        type(inference.receipt).model_validate(receipt_payload)
