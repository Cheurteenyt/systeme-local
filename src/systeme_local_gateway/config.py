from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SLG_", extra="ignore")

    shared_secret: str = Field(min_length=32)
    workspace: Path = Path("./workspace")
    policy_file: Path = Path("./policy.yaml")
    audit_log: Path = Path("./audit.jsonl")
    docker_image: str = "python:3.12-slim"


settings = Settings()
