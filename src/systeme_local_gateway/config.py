from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SLG_", extra="ignore")

    shared_secret: str = Field(min_length=32)
    workspace: Path = Path("./workspace")
    policy_file: Path = Path("./policy.yaml")
    audit_log: Path = Path("./audit.jsonl")
    docker_image: str = "python:3.12-slim"

    @field_validator("shared_secret")
    @classmethod
    def reject_insecure_shared_secret(cls, value: str) -> str:
        insecure_values = {
            "replace-with-at-least-32-random-characters",
            "change-me-change-me-change-me-change-me",
        }
        if value in insecure_values:
            raise ValueError("SLG_SHARED_SECRET must be replaced with a random secret")
        return value


settings = Settings()
