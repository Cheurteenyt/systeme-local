"""Remote-brain connectivity and routing primitives.

The control plane deliberately separates inbound MCP clients from outbound API
providers. A web agent connected through MCP initiates calls and is therefore
never treated as an API provider that the local node can invoke autonomously.
"""

from .models import (
    Availability,
    BrainCapability,
    BrainProfile,
    BrainRequest,
    BrainTransport,
    Checkpoint,
    RouteDecision,
    TaskClaim,
)
from .router import BrainRouter, NoEligibleBrain

__all__ = [
    "Availability",
    "BrainCapability",
    "BrainProfile",
    "BrainRequest",
    "BrainRouter",
    "BrainTransport",
    "Checkpoint",
    "NoEligibleBrain",
    "RouteDecision",
    "TaskClaim",
]
