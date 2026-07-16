from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class BrainTransport(StrEnum):
    """How a remote intelligence participates in a task.

    MCP_CLIENT
        The web agent owns the conversation and calls our MCP server. The local
        node cannot invoke this provider by itself.
    OFFICIAL_API
        The local node can submit a request programmatically through a supported
        provider API.
    INTERACTIVE_HANDOFF
        A human or approved browser companion transfers a signed task capsule.
    """

    MCP_CLIENT = "mcp_client"
    OFFICIAL_API = "official_api"
    INTERACTIVE_HANDOFF = "interactive_handoff"


class Availability(StrEnum):
    AVAILABLE = "available"
    DEGRADED = "degraded"
    TEMPORARY_CAPACITY = "temporary_capacity"
    RATE_LIMITED = "rate_limited"
    QUOTA_EXHAUSTED = "quota_exhausted"
    USER_ACTION_REQUIRED = "user_action_required"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class BrainCapability(StrEnum):
    GENERAL_REASONING = "general_reasoning"
    CODING = "coding"
    ARCHITECTURE = "architecture"
    DEBUGGING = "debugging"
    SECURITY_REVIEW = "security_review"
    LONG_CONTEXT = "long_context"
    STRUCTURED_OUTPUT = "structured_output"
    TOOL_USE = "tool_use"


class BrainProfile(BaseModel):
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,80}$")
    display_name: str = Field(min_length=1, max_length=128)
    transport: BrainTransport
    capabilities: set[BrainCapability] = Field(default_factory=set)
    priority: int = Field(default=0, ge=-10_000, le=10_000)
    enabled: bool = True
    availability: Availability = Availability.UNKNOWN
    max_parallel_tasks: int = Field(default=1, ge=1, le=128)
    active_tasks: int = Field(default=0, ge=0)
    allowed_data_classes: set[Literal["public", "internal", "confidential"]] = Field(
        default_factory=lambda: {"public"}
    )
    exact_quota_visibility: bool = False

    @model_validator(mode="after")
    def validate_parallelism(self) -> "BrainProfile":
        if self.active_tasks > self.max_parallel_tasks:
            raise ValueError("active_tasks cannot exceed max_parallel_tasks")
        return self

    @property
    def has_capacity(self) -> bool:
        return self.active_tasks < self.max_parallel_tasks

    @property
    def autonomously_invokable(self) -> bool:
        return self.transport is BrainTransport.OFFICIAL_API


class BrainRequest(BaseModel):
    task_id: str = Field(min_length=8, max_length=128)
    capability: BrainCapability
    data_class: Literal["public", "internal", "confidential"] = "internal"
    preferred_provider_id: str | None = None
    allow_fallback: bool = True


class RouteDecision(BaseModel):
    provider_id: str
    transport: BrainTransport
    mode: Literal["autonomous_outbound", "inbound_claim", "interactive_handoff"]
    reason: str


class Checkpoint(BaseModel):
    """Provider-neutral state used to resume a task with another brain."""

    task_id: str = Field(min_length=8, max_length=128)
    checkpoint_id: str = Field(min_length=8, max_length=128)
    objective: str = Field(min_length=1, max_length=20_000)
    completed_steps: list[str] = Field(default_factory=list, max_length=1_000)
    observations: list[str] = Field(default_factory=list, max_length=5_000)
    artifact_refs: list[str] = Field(default_factory=list, max_length=5_000)
    pending_question: str | None = Field(default=None, max_length=20_000)
    state_digest: str = Field(pattern=r"^(sha256|blake3):[0-9a-f]{32,128}$")
    created_at: datetime


class TaskClaim(BaseModel):
    """Short lease granted to an inbound MCP client for one task step."""

    task_id: str = Field(min_length=8, max_length=128)
    step_id: str = Field(min_length=4, max_length=128)
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,80}$")
    checkpoint_id: str = Field(min_length=8, max_length=128)
    lease_id: str = Field(min_length=16, max_length=128)
    leased_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_lease_window(self) -> "TaskClaim":
        if self.expires_at <= self.leased_at:
            raise ValueError("claim expiry must be after lease start")
        return self
