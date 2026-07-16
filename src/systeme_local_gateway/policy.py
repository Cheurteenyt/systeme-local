from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

Decision = Literal["allow", "deny", "require_approval"]


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: str
    config: dict[str, Any]


class PolicyEngine:
    def __init__(self, policy_path: Path):
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
        self._default: Decision = raw.get("default", "deny")
        self.limits: dict[str, Any] = raw.get("limits", {})
        self._capabilities: dict[str, dict[str, Any]] = raw.get("capabilities", {})

    def evaluate(self, capability: str) -> PolicyDecision:
        config = self._capabilities.get(capability)
        if not config:
            return PolicyDecision(self._default, "capability not declared", {})
        decision: Decision = config.get("decision", self._default)
        return PolicyDecision(decision, f"policy decision: {decision}", config)
