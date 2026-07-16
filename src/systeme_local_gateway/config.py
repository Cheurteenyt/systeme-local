import hmac
from pathlib import Path

from pydantic import Field, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SLG_", extra="ignore")

    shared_secret: str = Field(min_length=32)
    audit_key: str = Field(min_length=32)
    workspace: Path = Path("./workspace")
    policy_file: Path = Path("./policy.yaml")
    audit_log: Path = Path("./audit.jsonl")
    replay_db: Path = Path("./.systeme-local/replay.sqlite3")
    replay_max_entries: int = Field(default=10_000, ge=1, le=1_000_000)
    approval_db: Path = Path("./.systeme-local/approvals.sqlite3")
    approval_max_entries: int = Field(default=1_000, ge=1, le=100_000)
    approval_ttl_seconds: int = Field(default=900, ge=30, le=3_600)
    sandbox_root: Path = Path("./.systeme-local/sandboxes")
    docker_image: str = "python:3.12-slim"

    @field_validator("shared_secret", "audit_key")
    @classmethod
    def reject_insecure_secret(cls, value: str, info: ValidationInfo) -> str:
        insecure_values = {
            "replace-with-at-least-32-random-characters",
            "replace-with-different-at-least-32-random-characters",
            "change-me-change-me-change-me-change-me",
        }
        if value in insecure_values:
            variable = f"SLG_{info.field_name.upper()}"
            raise ValueError(f"{variable} must be replaced with a random secret")
        return value

    @model_validator(mode="after")
    def require_distinct_secrets(self) -> "Settings":
        if hmac.compare_digest(self.shared_secret, self.audit_key):
            raise ValueError("SLG_AUDIT_KEY must be different from SLG_SHARED_SECRET")
        return self


settings = Settings()
