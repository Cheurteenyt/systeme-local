import hmac
import os
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .c9_private_state import (
    C9PrivateStateError,
    lexical_c9_path,
    reject_c9_reparse_prefix,
)


def _normalized_path(path: Path) -> str:
    return os.path.normcase(os.fspath(path.resolve(strict=False)))


def _lock_path(path: Path) -> Path:
    return path.parent / f"{path.name}.lock"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SLG_",
        extra="ignore",
        hide_input_in_errors=True,
    )

    shared_secret: str = Field(min_length=32)
    audit_key: str = Field(min_length=32)
    workspace: Path = Path("./workspace")
    policy_file: Path = Path("./policy.yaml")
    audit_log: Path = Path("./audit.jsonl")
    audit_anchor_log: Path | None = None
    audit_anchor_key: str | None = Field(default=None, min_length=32)
    replay_db: Path = Path("./.systeme-local/replay.sqlite3")
    replay_max_entries: int = Field(default=10_000, ge=1, le=1_000_000)
    approval_db: Path = Path("./.systeme-local/approvals.sqlite3")
    approval_max_entries: int = Field(default=1_000, ge=1, le=100_000)
    approval_ttl_seconds: int = Field(default=900, ge=30, le=3_600)
    sandbox_root: Path = Path("./.systeme-local/sandboxes")
    docker_image: str = "python:3.12-slim"
    mcp_enabled: bool = False
    mcp_token: str | None = Field(default=None, min_length=32, max_length=512)
    c0_enabled: bool = False
    c0_server_build_commit: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{40}$",
    )
    provider_runtime_mode: (
        Literal[
            "chatgpt_chat_c4",
            "chatgpt_work_c8",
            "chatgpt_web_c9",
        ]
        | None
    ) = None
    provider_runtime_root: Path | None = None
    c8_live_cycle_file: Path | None = None
    c9_control_token: str | None = Field(default=None, min_length=32, max_length=512)
    c9_server_build_commit: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{40}$",
    )
    c9_state_directory: Path | None = None
    c9_admission_file: Path | None = None
    c9_local_ai_runtime_observation_file: Path | None = None
    c9_local_ai_endpoint: str | None = None
    c9_local_ai_model: str | None = Field(default=None, min_length=1, max_length=128)
    mcp_max_request_bytes: int = Field(
        default=1_048_576,
        ge=1_024,
        le=10_485_760,
    )
    mcp_requests_per_minute: int = Field(default=120, ge=1, le=10_000)
    mcp_max_concurrency: int = Field(default=4, ge=1, le=64)
    mcp_max_rendered_response_bytes: int = Field(
        default=16 * 1024 * 1024,
        ge=1_024,
        le=64 * 1024 * 1024,
    )

    @field_validator(
        "shared_secret",
        "audit_key",
        "audit_anchor_key",
        "mcp_token",
        "c9_control_token",
    )
    @classmethod
    def reject_insecure_secret(
        cls,
        value: str | None,
        info: ValidationInfo,
    ) -> str | None:
        if value is None:
            return None
        insecure_values = {
            "replace-with-at-least-32-random-characters",
            "replace-with-different-at-least-32-random-characters",
            "replace-with-third-independent-at-least-32-random-characters",
            "replace-with-fourth-independent-at-least-32-random-characters",
            "change-me-change-me-change-me-change-me",
        }
        if value in insecure_values:
            field_name = info.field_name or "secret"
            variable = f"SLG_{field_name.upper()}"
            raise ValueError(f"{variable} must be replaced with a random secret")
        return value

    @field_validator("c9_local_ai_endpoint")
    @classmethod
    def validate_c9_local_ai_endpoint_setting(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from .c9_local_ai import validate_c9_local_ai_endpoint

        return validate_c9_local_ai_endpoint(value)

    @field_validator("c9_local_ai_model")
    @classmethod
    def validate_c9_local_ai_model_setting(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("SLG_C9_LOCAL_AI_MODEL contains invalid whitespace")
        return value

    @model_validator(mode="after")
    def require_consistent_security_configuration(self) -> "Settings":
        if hmac.compare_digest(self.shared_secret, self.audit_key):
            raise ValueError("SLG_AUDIT_KEY must be different from SLG_SHARED_SECRET")

        anchor_path_configured = self.audit_anchor_log is not None
        anchor_key_configured = self.audit_anchor_key is not None
        if anchor_path_configured != anchor_key_configured:
            raise ValueError(
                "SLG_AUDIT_ANCHOR_LOG and SLG_AUDIT_ANCHOR_KEY must be configured together"
            )

        if self.audit_anchor_key is not None:
            if hmac.compare_digest(
                self.audit_anchor_key,
                self.shared_secret,
            ):
                raise ValueError("SLG_AUDIT_ANCHOR_KEY must be different from SLG_SHARED_SECRET")
            if hmac.compare_digest(
                self.audit_anchor_key,
                self.audit_key,
            ):
                raise ValueError("SLG_AUDIT_ANCHOR_KEY must be different from SLG_AUDIT_KEY")

        if self.mcp_enabled and self.mcp_token is None:
            raise ValueError("SLG_MCP_TOKEN must be configured when SLG_MCP_ENABLED is true")

        if self.c0_enabled:
            if not self.mcp_enabled:
                raise ValueError("SLG_MCP_ENABLED must be true when SLG_C0_ENABLED is true")
            if self.c0_server_build_commit is None:
                raise ValueError(
                    "SLG_C0_SERVER_BUILD_COMMIT is required when SLG_C0_ENABLED is true"
                )

        provider_mode_configured = self.provider_runtime_mode is not None
        provider_root_configured = self.provider_runtime_root is not None
        if provider_mode_configured != provider_root_configured:
            raise ValueError(
                "SLG_PROVIDER_RUNTIME_MODE and SLG_PROVIDER_RUNTIME_ROOT "
                "must be configured together"
            )
        if provider_mode_configured:
            if not self.mcp_enabled:
                raise ValueError("provider runtime requires SLG_MCP_ENABLED")
            if self.provider_runtime_mode == "chatgpt_web_c9":
                if self.c0_enabled:
                    raise ValueError("C9 Web runtime must not enable the C0 probe surface")
            elif not self.c0_enabled:
                raise ValueError("provider runtime requires SLG_C0_ENABLED")
            assert self.provider_runtime_root is not None
            if not self.provider_runtime_root.is_absolute():
                raise ValueError("SLG_PROVIDER_RUNTIME_ROOT must be an absolute path")
        if self.provider_runtime_mode == "chatgpt_work_c8":
            if self.c8_live_cycle_file is None:
                raise ValueError("SLG_C8_LIVE_CYCLE_FILE is required for the C8 Work runtime")
            if not self.c8_live_cycle_file.is_absolute():
                raise ValueError("SLG_C8_LIVE_CYCLE_FILE must be an absolute path")
            assert self.provider_runtime_root is not None
            expected_root = _normalized_path(self.provider_runtime_root / ".systeme-local" / "c8")
            cycle_path = _normalized_path(self.c8_live_cycle_file)
            if cycle_path != expected_root and not cycle_path.startswith(expected_root + os.sep):
                raise ValueError("SLG_C8_LIVE_CYCLE_FILE must remain inside .systeme-local/c8")
        elif self.c8_live_cycle_file is not None:
            raise ValueError("SLG_C8_LIVE_CYCLE_FILE is only valid with chatgpt_work_c8")

        c9_fields = (
            self.c9_control_token,
            self.c9_server_build_commit,
            self.c9_state_directory,
            self.c9_admission_file,
            self.c9_local_ai_runtime_observation_file,
            self.c9_local_ai_endpoint,
            self.c9_local_ai_model,
        )
        if self.provider_runtime_mode == "chatgpt_web_c9":
            if any(value is None for value in c9_fields):
                raise ValueError(
                    "SLG_C9_CONTROL_TOKEN, SLG_C9_SERVER_BUILD_COMMIT, and "
                    "SLG_C9_STATE_DIRECTORY, SLG_C9_ADMISSION_FILE, "
                    "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE, "
                    "SLG_C9_LOCAL_AI_ENDPOINT, and SLG_C9_LOCAL_AI_MODEL are required "
                    "for the C9 Web runtime"
                )
            assert self.provider_runtime_root is not None
            assert self.c9_state_directory is not None
            assert self.c9_admission_file is not None
            assert self.c9_local_ai_runtime_observation_file is not None
            if not self.c9_state_directory.is_absolute():
                raise ValueError("SLG_C9_STATE_DIRECTORY must be an absolute path")
            expected_path = lexical_c9_path(self.provider_runtime_root / ".systeme-local" / "c9")
            state = lexical_c9_path(self.c9_state_directory)
            admission = lexical_c9_path(self.c9_admission_file)
            runtime_observation = lexical_c9_path(self.c9_local_ai_runtime_observation_file)
            expected_root = os.path.normcase(os.fspath(expected_path))
            state_path = os.path.normcase(os.fspath(state))
            if state_path != expected_root and not state_path.startswith(expected_root + os.sep):
                raise ValueError("SLG_C9_STATE_DIRECTORY must remain inside .systeme-local/c9")
            admission_path = os.path.normcase(os.fspath(admission))
            if os.path.normcase(os.fspath(admission.parent)) != state_path:
                raise ValueError(
                    "SLG_C9_ADMISSION_FILE must be a direct child of SLG_C9_STATE_DIRECTORY"
                )
            observation_path = os.path.normcase(os.fspath(runtime_observation))
            if os.path.normcase(os.fspath(runtime_observation.parent)) != state_path:
                raise ValueError(
                    "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE must be a direct child of "
                    "SLG_C9_STATE_DIRECTORY"
                )
            if observation_path == admission_path:
                raise ValueError("C9 admission and local-AI runtime observation files must differ")
            try:
                reject_c9_reparse_prefix(expected_path, allow_missing_tail=True)
                reject_c9_reparse_prefix(state, allow_missing_tail=True)
                reject_c9_reparse_prefix(admission, allow_missing_tail=True)
                reject_c9_reparse_prefix(
                    runtime_observation,
                    allow_missing_tail=True,
                )
            except C9PrivateStateError as exc:
                raise ValueError(
                    "C9 private state rejects symlink, junction, or reparse traversal"
                ) from exc
        elif any(value is not None for value in c9_fields):
            raise ValueError("C9 runtime settings are only valid with chatgpt_web_c9")

        if self.mcp_token is not None:
            secrets_to_compare = {
                "SLG_SHARED_SECRET": self.shared_secret,
                "SLG_AUDIT_KEY": self.audit_key,
            }
            if self.audit_anchor_key is not None:
                secrets_to_compare["SLG_AUDIT_ANCHOR_KEY"] = self.audit_anchor_key
            if self.c9_control_token is not None:
                secrets_to_compare["SLG_C9_CONTROL_TOKEN"] = self.c9_control_token
            for variable, secret in secrets_to_compare.items():
                if hmac.compare_digest(self.mcp_token, secret):
                    raise ValueError(f"SLG_MCP_TOKEN must be different from {variable}")

        if self.c9_control_token is not None:
            c9_secrets_to_compare = {
                "SLG_SHARED_SECRET": self.shared_secret,
                "SLG_AUDIT_KEY": self.audit_key,
            }
            if self.audit_anchor_key is not None:
                c9_secrets_to_compare["SLG_AUDIT_ANCHOR_KEY"] = self.audit_anchor_key
            for variable, secret in c9_secrets_to_compare.items():
                if hmac.compare_digest(self.c9_control_token, secret):
                    raise ValueError(f"SLG_C9_CONTROL_TOKEN must be different from {variable}")

        if self.audit_anchor_log is not None:
            audit_paths = {
                _normalized_path(self.audit_log),
                _normalized_path(_lock_path(self.audit_log)),
            }
            anchor_paths = {
                _normalized_path(self.audit_anchor_log),
                _normalized_path(_lock_path(self.audit_anchor_log)),
            }
            if audit_paths & anchor_paths:
                raise ValueError("audit log, audit anchor, and their lock paths must not overlap")

        return self


settings = Settings()
