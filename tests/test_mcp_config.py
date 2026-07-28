import importlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

with patch.dict(
    os.environ,
    {
        "SLG_SHARED_SECRET": "s" * 48,
        "SLG_AUDIT_KEY": "a" * 48,
    },
):
    Settings = importlib.import_module("systeme_local_gateway.config").Settings


def _settings(**overrides):
    values = {
        "shared_secret": "s" * 48,
        "audit_key": "a" * 48,
        "_env_file": None,
    }
    values.update(overrides)
    return Settings(**values)


def test_mcp_is_disabled_by_default_without_a_token() -> None:
    settings = _settings()

    assert settings.mcp_enabled is False
    assert settings.mcp_token is None
    assert settings.c0_enabled is False
    assert settings.c0_server_build_commit is None


def test_enabled_mcp_requires_a_token() -> None:
    with pytest.raises(ValidationError, match="SLG_MCP_TOKEN"):
        _settings(mcp_enabled=True)


@pytest.mark.parametrize(
    ("variable", "overrides"),
    [
        (
            "SLG_SHARED_SECRET",
            {"mcp_token": "s" * 48},
        ),
        (
            "SLG_AUDIT_KEY",
            {"mcp_token": "a" * 48},
        ),
        (
            "SLG_AUDIT_ANCHOR_KEY",
            {
                "mcp_token": "n" * 48,
                "audit_anchor_log": "anchor.jsonl",
                "audit_anchor_key": "n" * 48,
            },
        ),
    ],
)
def test_mcp_token_must_be_independent(
    variable: str,
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match=variable):
        _settings(mcp_enabled=True, **overrides)


def test_placeholder_mcp_token_is_rejected() -> None:
    with pytest.raises(ValidationError, match="SLG_MCP_TOKEN"):
        _settings(
            mcp_enabled=True,
            mcp_token=("replace-with-fourth-independent-at-least-32-random-characters"),
        )


def test_c0_requires_mcp_and_full_build_commit() -> None:
    with pytest.raises(ValidationError, match="SLG_MCP_ENABLED"):
        _settings(c0_enabled=True, c0_server_build_commit="a" * 40)

    with pytest.raises(ValidationError, match="SLG_C0_SERVER_BUILD_COMMIT"):
        _settings(mcp_enabled=True, mcp_token="t" * 48, c0_enabled=True)


def test_c0_security_configuration_can_be_enabled_explicitly() -> None:
    settings = _settings(
        mcp_enabled=True,
        mcp_token="t" * 48,
        c0_enabled=True,
        c0_server_build_commit="a" * 40,
    )

    assert settings.c0_enabled is True
    assert settings.c0_server_build_commit == "a" * 40


def test_provider_runtime_configuration_is_paired_bounded_and_absolute() -> None:
    absolute_root = Path.cwd().resolve() / "reviewed"
    base = {
        "mcp_enabled": True,
        "mcp_token": "t" * 48,
        "c0_enabled": True,
        "c0_server_build_commit": "a" * 40,
    }
    with pytest.raises(ValidationError, match="configured together"):
        _settings(**base, provider_runtime_mode="chatgpt_chat_c4")
    with pytest.raises(ValidationError, match="absolute path"):
        _settings(
            **base,
            provider_runtime_mode="chatgpt_chat_c4",
            provider_runtime_root="relative",
        )
    with pytest.raises(ValidationError, match="SLG_MCP_ENABLED"):
        _settings(
            provider_runtime_mode="chatgpt_chat_c4",
            provider_runtime_root=absolute_root,
        )

    settings = _settings(
        **base,
        provider_runtime_mode="chatgpt_chat_c4",
        provider_runtime_root=absolute_root,
    )
    assert settings.provider_runtime_mode == "chatgpt_chat_c4"
    assert settings.provider_runtime_root is not None
    assert settings.provider_runtime_root.is_absolute()


def test_c8_runtime_requires_a_cycle_file_inside_ignored_c8_state() -> None:
    absolute_root = Path.cwd().resolve() / "reviewed"
    base = {
        "mcp_enabled": True,
        "mcp_token": "t" * 48,
        "c0_enabled": True,
        "c0_server_build_commit": "a" * 40,
        "provider_runtime_mode": "chatgpt_work_c8",
        "provider_runtime_root": absolute_root,
    }
    with pytest.raises(ValidationError, match="SLG_C8_LIVE_CYCLE_FILE"):
        _settings(**base)
    with pytest.raises(ValidationError, match="inside .systeme-local/c8"):
        _settings(
            **base,
            c8_live_cycle_file=absolute_root / "outside.json",
        )

    cycle_file = absolute_root / ".systeme-local" / "c8" / "live-cycle.json"
    settings = _settings(**base, c8_live_cycle_file=cycle_file)
    assert settings.provider_runtime_mode == "chatgpt_work_c8"
    assert settings.c8_live_cycle_file == cycle_file


def test_c8_cycle_file_is_rejected_without_c8_runtime_mode() -> None:
    absolute_root = Path.cwd().resolve() / "reviewed"
    with pytest.raises(ValidationError, match="only valid"):
        _settings(c8_live_cycle_file=(absolute_root / ".systeme-local" / "c8" / "live-cycle.json"))


def test_c9_runtime_is_mcp_only_and_confines_private_state() -> None:
    absolute_root = Path.cwd().resolve() / "reviewed"
    state = absolute_root / ".systeme-local" / "c9" / "cycle-a"
    base = {
        "mcp_enabled": True,
        "mcp_token": "t" * 48,
        "provider_runtime_mode": "chatgpt_web_c9",
        "provider_runtime_root": absolute_root,
        "c9_control_token": "c" * 48,
        "c9_server_build_commit": "9" * 40,
        "c9_admission_file": state / "admission.json",
        "c9_local_ai_runtime_observation_file": (state / "local-ai-runtime-observation.json"),
        "c9_local_ai_endpoint": "http://127.0.0.1:1234/v1/chat/completions",
        "c9_local_ai_model": "local-vision-model",
    }

    with pytest.raises(ValidationError, match="SLG_C9_STATE_DIRECTORY"):
        _settings(**base)
    with pytest.raises(ValidationError, match="inside .systeme-local/c9"):
        _settings(**base, c9_state_directory=absolute_root / "outside")
    with pytest.raises(
        ValidationError,
        match="SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE",
    ):
        _settings(
            **(
                base
                | {
                    "c9_state_directory": state,
                    "c9_local_ai_runtime_observation_file": absolute_root / "outside.json",
                }
            ),
        )
    with pytest.raises(ValidationError, match="files must differ"):
        _settings(
            **(
                base
                | {
                    "c9_state_directory": state,
                    "c9_local_ai_runtime_observation_file": state / "admission.json",
                }
            ),
        )
    with pytest.raises(ValidationError, match="must not enable the C0 probe"):
        _settings(
            **base,
            c9_state_directory=state,
            c0_enabled=True,
            c0_server_build_commit="a" * 40,
        )

    settings = _settings(**base, c9_state_directory=state)

    assert settings.provider_runtime_mode == "chatgpt_web_c9"
    assert settings.c0_enabled is False
    assert settings.c9_state_directory == state
    assert settings.c9_admission_file == state / "admission.json"
    assert settings.c9_local_ai_runtime_observation_file == (
        state / "local-ai-runtime-observation.json"
    )


def test_c9_runtime_secrets_are_required_independent_and_mode_scoped() -> None:
    absolute_root = Path.cwd().resolve() / "reviewed"
    state = absolute_root / ".systeme-local" / "c9"
    base = {
        "mcp_enabled": True,
        "mcp_token": "t" * 48,
        "provider_runtime_mode": "chatgpt_web_c9",
        "provider_runtime_root": absolute_root,
        "c9_server_build_commit": "9" * 40,
        "c9_state_directory": state,
        "c9_admission_file": state / "admission.json",
        "c9_local_ai_runtime_observation_file": (state / "local-ai-runtime-observation.json"),
        "c9_local_ai_endpoint": "http://127.0.0.1:1234/v1/chat/completions",
        "c9_local_ai_model": "local-vision-model",
    }

    with pytest.raises(ValidationError, match="SLG_C9_CONTROL_TOKEN"):
        _settings(**base)
    with pytest.raises(ValidationError, match="different from SLG_SHARED_SECRET"):
        _settings(**base, c9_control_token="s" * 48)
    with pytest.raises(ValidationError, match="different from SLG_C9_CONTROL_TOKEN"):
        _settings(
            **base,
            c9_control_token="t" * 48,
        )
    with pytest.raises(ValidationError, match="only valid"):
        _settings(
            c9_control_token="c" * 48,
            c9_server_build_commit="9" * 40,
            c9_state_directory=state,
        )


def test_c9_local_ai_must_use_an_exact_literal_loopback_endpoint() -> None:
    absolute_root = Path.cwd().resolve() / "reviewed"
    state = absolute_root / ".systeme-local" / "c9"
    base = {
        "mcp_enabled": True,
        "mcp_token": "t" * 48,
        "provider_runtime_mode": "chatgpt_web_c9",
        "provider_runtime_root": absolute_root,
        "c9_control_token": "c" * 48,
        "c9_server_build_commit": "9" * 40,
        "c9_state_directory": state,
        "c9_admission_file": state / "admission.json",
        "c9_local_ai_runtime_observation_file": (state / "local-ai-runtime-observation.json"),
        "c9_local_ai_model": "local-vision-model",
    }

    with pytest.raises(ValidationError, match="literal loopback"):
        _settings(
            **base,
            c9_local_ai_endpoint="http://localhost:1234/v1/chat/completions",
        )
    with pytest.raises(ValidationError, match="exact chat-completions"):
        _settings(
            **base,
            c9_local_ai_endpoint="http://127.0.0.1:1234/v1/models",
        )
