from pathlib import Path

from systeme_local_gateway.policy import PolicyEngine


def test_unknown_capability_is_denied() -> None:
    engine = PolicyEngine(Path("policy.yaml"))
    assert engine.evaluate("host.shell").decision == "deny"


def test_write_requires_approval() -> None:
    engine = PolicyEngine(Path("policy.yaml"))
    assert engine.evaluate("workspace.write_text").decision == "require_approval"
