import hmac
import os
from pathlib import Path

from pydantic import Field, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    @field_validator("shared_secret", "audit_key", "audit_anchor_key")
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
            "change-me-change-me-change-me-change-me",
        }
        if value in insecure_values:
            variable = f"SLG_{info.field_name.upper()}"
            raise ValueError(f"{variable} must be replaced with a random secret")
        return value

    @model_validator(mode="after")
    def require_consistent_security_configuration(self) -> "Settings":
        if hmac.compare_digest(self.shared_secret, self.audit_key):
            raise ValueError(
                "SLG_AUDIT_KEY must be different from SLG_SHARED_SECRET"
            )

        anchor_path_configured = self.audit_anchor_log is not None
        anchor_key_configured = self.audit_anchor_key is not None
        if anchor_path_configured != anchor_key_configured:
            raise ValueError(
                "SLG_AUDIT_ANCHOR_LOG and SLG_AUDIT_ANCHOR_KEY "
                "must be configured together"
            )

        if self.audit_anchor_key is not None:
            if hmac.compare_digest(
                self.audit_anchor_key,
                self.shared_secret,
            ):
                raise ValueError(
                    "SLG_AUDIT_ANCHOR_KEY must be different from "
                    "SLG_SHARED_SECRET"
                )
            if hmac.compare_digest(
                self.audit_anchor_key,
                self.audit_key,
            ):
                raise ValueError(
                    "SLG_AUDIT_ANCHOR_KEY must be different from "
                    "SLG_AUDIT_KEY"
                )

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
                raise ValueError(
                    "audit log, audit anchor, and their lock paths "
                    "must not overlap"
                )

        return self


settings = Settings()
