from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AgentIdentity(StrictModel):
    provider: str = Field(min_length=1, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)


class TaskEnvelope(StrictModel):
    version: Literal["1"] = "1"
    task_id: str = Field(min_length=8, max_length=128)
    issued_at: datetime
    expires_at: datetime
    agent: AgentIdentity
    capability: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,80}$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = Field(
        default=None,
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    nonce: str = Field(min_length=16, max_length=128)
    signature: str = Field(min_length=43, max_length=128)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_time_window(self) -> "TaskEnvelope":
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self


class TaskResult(StrictModel):
    task_id: str
    status: Literal["completed", "denied", "approval_required", "failed"]
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    audit_id: str
