import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

Decision = Literal["allow", "deny", "require_approval"]
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,80}$")


class LimitsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_task_seconds: int = Field(default=120, ge=1, le=3_600)
    max_output_bytes: int = Field(default=200_000, ge=1, le=10_000_000)
    max_read_bytes: int = Field(default=1_000_000, ge=1, le=100_000_000)
    max_write_bytes: int = Field(default=1_000_000, ge=1, le=100_000_000)
    cpu_count: float = Field(default=1, gt=0, le=64)
    memory_mb: int = Field(default=1_024, ge=64, le=262_144)
    max_snapshot_files: int = Field(default=50_000, ge=1, le=1_000_000)
    max_snapshot_bytes: int = Field(default=536_870_912, ge=1, le=10_737_418_240)
    max_change_entries: int = Field(default=1_000, ge=1, le=100_000)


class CapabilityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Decision
    allowed_commands: list[list[str]] = Field(default_factory=list, max_length=256)

    @field_validator("allowed_commands")
    @classmethod
    def validate_commands(cls, commands: list[list[str]]) -> list[list[str]]:
        for command in commands:
            if not command or not all(isinstance(part, str) and part for part in command):
                raise ValueError("allowed_commands must contain non-empty argv arrays")
        return commands


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    default: Literal["deny"] = "deny"
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    capabilities: dict[str, CapabilityConfig] = Field(default_factory=dict)

    @field_validator("capabilities")
    @classmethod
    def validate_capability_names(
        cls, capabilities: dict[str, CapabilityConfig]
    ) -> dict[str, CapabilityConfig]:
        invalid = [name for name in capabilities if not _CAPABILITY_RE.fullmatch(name)]
        if invalid:
            raise ValueError(f"invalid capability names: {', '.join(sorted(invalid))}")
        return capabilities


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: str
    config: dict[str, Any]


class PolicyEngine:
    def __init__(self, policy_path: Path):
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
        document = PolicyDocument.model_validate(raw)
        self._default: Decision = document.default
        self.limits: dict[str, Any] = document.limits.model_dump(mode="json")
        self._capabilities = document.capabilities

    def evaluate(self, capability: str) -> PolicyDecision:
        config = self._capabilities.get(capability)
        if config is None:
            return PolicyDecision(self._default, "capability not declared", {})
        return PolicyDecision(
            config.decision,
            f"policy decision: {config.decision}",
            config.model_dump(mode="json"),
        )
