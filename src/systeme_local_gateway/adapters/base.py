from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from ..models import TaskEnvelope, TaskResult


class AgentTransport(ABC):
    """A transport never executes actions; it only moves signed task envelopes."""

    @abstractmethod
    async def receive(self) -> AsyncIterator[TaskEnvelope]:
        raise NotImplementedError

    @abstractmethod
    async def send_result(self, result: TaskResult) -> None:
        raise NotImplementedError
