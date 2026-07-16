from pathlib import Path

import pytest

from systeme_local_gateway.policy import PolicyEngine


def test_unknown_capability_is_denied() -> None:
    engine = PolicyEngine(Path("policy.yaml"))
    assert engine.evaluate("host.shell").decision == "deny"


def test_write_requires_approval() -> None:
    engine = PolicyEngine(Path("policy.yaml"))
    assert engine.evaluate("workspace.write_text").decision == "require_approval"


def test_unknown_decision_fails_closed(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """version: 1
default: deny
capabilities:
  workspace.write_text:
    decision: alloww
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="decision"):
        PolicyEngine(policy)


def test_default_cannot_be_changed_to_allow(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\ndefault: allow\n", encoding="utf-8")
    with pytest.raises(ValueError, match="default"):
        PolicyEngine(policy)


def test_invalid_command_allowlist_is_rejected(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """version: 1
default: deny
capabilities:
  sandbox.run_tests:
    decision: allow
    allowed_commands:
      - []
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="allowed_commands"):
        PolicyEngine(policy)
