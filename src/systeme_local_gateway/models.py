from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class AgentIdentity(BaseModel):
    provider: str = Field(min_length=1, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)


class TaskEnvelope(BaseModel):
    version: Literal["1"] = "1"
    task_id: str = Field(min_length=8, max_length=128)
    issued_at: datetime
    expires_at: datetime
    agent: AgentIdentity
    capability: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,80}$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    nonce: str = Field(min_length=16, max_length=128)
    signature: str = Field(min_length=43, max_length=128)


class TaskResult(BaseModel):
    task_id: str
    status: Literal["completed", "denied", "approval_required", "failed"]
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    audit_id: str
