import pytest

from systeme_local_gateway.brains import (
    Availability,
    BrainCapability,
    BrainProfile,
    BrainRequest,
    BrainRouter,
    BrainTransport,
    NoEligibleBrain,
)


def profile(
    provider_id: str,
    transport: BrainTransport,
    *,
    priority: int = 0,
    availability: Availability = Availability.AVAILABLE,
) -> BrainProfile:
    return BrainProfile(
        provider_id=provider_id,
        display_name=provider_id,
        transport=transport,
        capabilities={BrainCapability.CODING},
        priority=priority,
        availability=availability,
        allowed_data_classes={"public", "internal"},
    )


def request(**overrides: object) -> BrainRequest:
    data: dict[str, object] = {
        "task_id": "task-12345678",
        "capability": BrainCapability.CODING,
        "data_class": "internal",
    }
    data.update(overrides)
    return BrainRequest(**data)


def test_outbound_router_never_treats_mcp_client_as_api() -> None:
    router = BrainRouter()
    profiles = [
        profile("glm-web", BrainTransport.MCP_CLIENT, priority=100),
        profile("glm-api", BrainTransport.OFFICIAL_API, priority=10),
    ]

    decision = router.select_outbound(request(), profiles)

    assert decision.provider_id == "glm-api"
    assert decision.mode == "autonomous_outbound"


def test_inbound_claim_selects_connected_mcp_brain() -> None:
    router = BrainRouter()
    profiles = [
        profile("glm-web", BrainTransport.MCP_CLIENT, priority=100),
        profile("other-web", BrainTransport.MCP_CLIENT, priority=10),
    ]

    decision = router.select_inbound_claimant(request(), profiles)

    assert decision.provider_id == "glm-web"
    assert decision.mode == "inbound_claim"


def test_preferred_provider_can_fallback() -> None:
    router = BrainRouter()
    profiles = [profile("fallback-api", BrainTransport.OFFICIAL_API)]

    decision = router.select_outbound(
        request(preferred_provider_id="unavailable-api", allow_fallback=True),
        profiles,
    )

    assert decision.provider_id == "fallback-api"


def test_preferred_provider_without_fallback_is_strict() -> None:
    router = BrainRouter()
    profiles = [profile("fallback-api", BrainTransport.OFFICIAL_API)]

    with pytest.raises(NoEligibleBrain, match="preferred provider"):
        router.select_outbound(
            request(preferred_provider_id="unavailable-api", allow_fallback=False),
            profiles,
        )


def test_confidential_data_is_not_sent_without_explicit_permission() -> None:
    router = BrainRouter()
    profiles = [profile("public-api", BrainTransport.OFFICIAL_API)]

    with pytest.raises(NoEligibleBrain, match="data class confidential"):
        router.select_outbound(request(data_class="confidential"), profiles)


def test_rate_limited_api_is_not_selected_for_outbound_call() -> None:
    router = BrainRouter()
    profiles = [
        profile(
            "limited-api",
            BrainTransport.OFFICIAL_API,
            availability=Availability.RATE_LIMITED,
        )
    ]

    with pytest.raises(NoEligibleBrain):
        router.select_outbound(request(), profiles)
