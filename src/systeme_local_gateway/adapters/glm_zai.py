"""GLM/z.ai adapter boundary.

The core gateway deliberately does not depend on undocumented provider behavior.
Implement either:
- an MCP/tool definition that produces TaskEnvelope objects; or
- an HTTPS relay adapter using the provider's supported outbound environment.

Provider-specific authentication must stay outside the local executor.
"""

from .base import AgentTransport


class GlmZaiTransport(AgentTransport):
    async def receive(self):
        raise NotImplementedError("Implement after validating the current z.ai tool/API contract")

    async def send_result(self, result):
        raise NotImplementedError("Implement after validating the current z.ai tool/API contract")
