import pytest

from systeme_local_gateway.c0_tunnel_smoke import (
    _validated_local_tunnel_endpoint,
)
from systeme_local_gateway.mcp_smoke import McpSmokeInputError

VALID_ENDPOINT = "http://127.0.0.1:43123/v1/mcp/tunnel_0123456789abcdef0123456789abcdef"


def test_local_tunnel_endpoint_is_literal_loopback_and_exactly_scoped() -> None:
    assert _validated_local_tunnel_endpoint(VALID_ENDPOINT) == VALID_ENDPOINT


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:43123/v1/mcp/tunnel_0123456789abcdef0123456789abcdef",
        "http://localhost:43123/v1/mcp/tunnel_0123456789abcdef0123456789abcdef",
        "http://192.0.2.1:43123/v1/mcp/tunnel_0123456789abcdef0123456789abcdef",
        "http://user@127.0.0.1:43123/v1/mcp/tunnel_0123456789abcdef0123456789abcdef",
        "http://127.0.0.1/v1/mcp/tunnel_0123456789abcdef0123456789abcdef",
        "http://127.0.0.1:43123/mcp",
        "http://127.0.0.1:43123/v1/mcp/tunnel_0123456789ABCDEF0123456789ABCDEF",
        ("http://127.0.0.1:43123/v1/mcp/tunnel_0123456789abcdef0123456789abcdef?debug=true"),
    ],
)
def test_local_tunnel_endpoint_rejects_widening(endpoint: str) -> None:
    with pytest.raises(McpSmokeInputError):
        _validated_local_tunnel_endpoint(endpoint)
