from collections.abc import Iterable

from .models import (
    Availability,
    BrainProfile,
    BrainRequest,
    BrainTransport,
    RouteDecision,
)


class NoEligibleBrain(RuntimeError):
    pass


class BrainRouter:
    """Deterministic routing for remote reasoning providers.

    This router never pretends that a web UI is an API. Only OFFICIAL_API
    profiles can be selected for autonomous outbound calls. MCP clients claim
    provider-neutral checkpoints when they connect, while interactive providers
    require an explicit handoff.
    """

    _OUTBOUND_STATES = {Availability.AVAILABLE, Availability.DEGRADED}
    _CLAIM_STATES = {
        Availability.AVAILABLE,
        Availability.DEGRADED,
        Availability.UNKNOWN,
    }

    def select_outbound(
        self,
        request: BrainRequest,
        profiles: Iterable[BrainProfile],
    ) -> RouteDecision:
        eligible = [
            profile
            for profile in profiles
            if self._common_eligibility(request, profile)
            and profile.transport is BrainTransport.OFFICIAL_API
            and profile.availability in self._OUTBOUND_STATES
        ]
        selected = self._select(request, eligible)
        return RouteDecision(
            provider_id=selected.provider_id,
            transport=selected.transport,
            mode="autonomous_outbound",
            reason=self._reason(request, selected),
        )

    def select_inbound_claimant(
        self,
        request: BrainRequest,
        profiles: Iterable[BrainProfile],
    ) -> RouteDecision:
        eligible = [
            profile
            for profile in profiles
            if self._common_eligibility(request, profile)
            and profile.transport is BrainTransport.MCP_CLIENT
            and profile.availability in self._CLAIM_STATES
        ]
        selected = self._select(request, eligible)
        return RouteDecision(
            provider_id=selected.provider_id,
            transport=selected.transport,
            mode="inbound_claim",
            reason=self._reason(request, selected),
        )

    def select_interactive_handoff(
        self,
        request: BrainRequest,
        profiles: Iterable[BrainProfile],
    ) -> RouteDecision:
        eligible = [
            profile
            for profile in profiles
            if self._common_eligibility(request, profile)
            and profile.transport is BrainTransport.INTERACTIVE_HANDOFF
            and profile.availability
            not in {Availability.OFFLINE, Availability.QUOTA_EXHAUSTED}
        ]
        selected = self._select(request, eligible)
        return RouteDecision(
            provider_id=selected.provider_id,
            transport=selected.transport,
            mode="interactive_handoff",
            reason=self._reason(request, selected),
        )

    @staticmethod
    def _common_eligibility(request: BrainRequest, profile: BrainProfile) -> bool:
        return (
            profile.enabled
            and profile.has_capacity
            and request.capability in profile.capabilities
            and request.data_class in profile.allowed_data_classes
        )

    @staticmethod
    def _select(request: BrainRequest, profiles: list[BrainProfile]) -> BrainProfile:
        if not profiles:
            raise NoEligibleBrain(
                f"no eligible brain for {request.capability.value} "
                f"with data class {request.data_class}"
            )

        by_id = {profile.provider_id: profile for profile in profiles}
        if request.preferred_provider_id:
            preferred = by_id.get(request.preferred_provider_id)
            if preferred:
                return preferred
            if not request.allow_fallback:
                raise NoEligibleBrain(
                    f"preferred provider {request.preferred_provider_id!r} is not eligible"
                )

        # Stable deterministic ordering prevents routing changes caused by list order.
        return sorted(profiles, key=lambda p: (-p.priority, p.provider_id))[0]

    @staticmethod
    def _reason(request: BrainRequest, profile: BrainProfile) -> str:
        preference = (
            "preferred provider"
            if request.preferred_provider_id == profile.provider_id
            else "highest eligible priority"
        )
        return (
            f"selected as {preference}; capability={request.capability.value}; "
            f"availability={profile.availability.value}; transport={profile.transport.value}"
        )
