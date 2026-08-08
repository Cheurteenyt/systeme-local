from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from systeme_local_gateway.c9_local_ai import (
    C9LocalAIProviderKind,
    commit_c9_local_ai_runtime_observation,
    rendered_json,
)

ROOT = Path(__file__).resolve().parents[1]


def _trusted_git_executable() -> Path:
    discovered = shutil.which("git")
    assert discovered is not None
    candidate = Path(discovered).resolve()
    if os.name == "nt" and candidate.parent.name.casefold() == "cmd":
        candidate = candidate.parent.parent / "bin" / "git.exe"
    return candidate.resolve(strict=True)


def _head() -> str:
    return subprocess.run(
        ("git", "-C", str(ROOT), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout.strip()


@contextmanager
def _isolated_runtime_state() -> Iterator[Path]:
    private_root = ROOT / ".systeme-local" / "c9"
    private_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=private_root) as temporary:
        provider_root = Path(temporary)
        state = provider_root / ".systeme-local" / "c9" / "cycle"
        state.mkdir(parents=True)
        yield state


def _environment(state: Path, *, commit: str | None = None) -> dict[str, str]:
    provider_root = state.parents[2]
    endpoint = "http://127.0.0.1:11434/v1/chat/completions"
    model = "local-multimodal-test"
    observed_at = datetime.now(timezone.utc)
    observation = commit_c9_local_ai_runtime_observation(
        cycle_id="c9_cycle_" + "1" * 32,
        provider_kind=C9LocalAIProviderKind.OTHER_REVIEWED_NATIVE,
        product_name="C9 reviewed test runtime",
        product_version="1.0",
        listening_pid=os.getpid(),
        executable_path=Path(sys.executable).resolve(),
        endpoint=endpoint,
        visible_model_label=model,
        runtime_request_logging_disabled=True,
        runtime_request_persistence_disabled=True,
        operator_confirmed_native_runtime=True,
        operator_confirmed_runtime_privacy_settings=True,
        observed_at=observed_at,
        expires_at=observed_at + timedelta(minutes=10),
        audit_key="a" * 48,
    )
    observation_file = state / "local-ai-runtime-observation.json"
    observation_file.write_text(rendered_json(observation), encoding="utf-8")
    environment = os.environ.copy()
    for name in ("SLG_AUDIT_ANCHOR_LOG", "SLG_AUDIT_ANCHOR_KEY"):
        environment.pop(name, None)
    environment.update(
        {
            "SLG_SHARED_SECRET": "s" * 48,
            "SLG_AUDIT_KEY": "a" * 48,
            "SLG_MCP_TOKEN": "m" * 48,
            "SLG_C9_CONTROL_TOKEN": "c" * 48,
            "SLG_WORKSPACE": str(ROOT),
            "SLG_POLICY_FILE": str(ROOT / "policy.c9.yaml"),
            "SLG_AUDIT_LOG": str(state / "audit.jsonl"),
            "SLG_REPLAY_DB": str(state / "replay.sqlite3"),
            "SLG_APPROVAL_DB": str(state / "approvals.sqlite3"),
            "SLG_SANDBOX_ROOT": str(state / "sandboxes"),
            "SLG_MCP_ENABLED": "true",
            "SLG_C0_ENABLED": "false",
            "SLG_PROVIDER_RUNTIME_MODE": "chatgpt_web_c9",
            "SLG_PROVIDER_RUNTIME_ROOT": str(provider_root),
            "SLG_C9_SERVER_BUILD_COMMIT": commit or _head(),
            "SLG_C9_STATE_DIRECTORY": str(state),
            "SLG_C9_ADMISSION_FILE": str(state / "admission.json"),
            "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE": str(observation_file),
            "SLG_C9_LOCAL_AI_ENDPOINT": endpoint,
            "SLG_C9_LOCAL_AI_MODEL": model,
            "SLG_C9_GIT_EXECUTABLE": str(_trusted_git_executable()),
        }
    )
    environment.pop("SLG_C0_SERVER_BUILD_COMMIT", None)
    return environment


def _run(state: Path, code: str, *, environment: dict[str, str] | None = None):
    return subprocess.run(
        (sys.executable, "-c", code),
        cwd=state,
        env=environment or _environment(state),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_c9_main_starts_unadmitted_with_zero_tools_and_private_routes() -> None:
    with _isolated_runtime_state() as state:
        completed = _run(
            state,
            (
                "import json; import systeme_local_gateway.main as m;"
                "print(json.dumps({"
                "'tools':[t.name for t in m.mcp_registry.list_tools()],"
                "'routes':sorted(r.path for r in m.c9_control_router.routes),"
                "'c0':m.c0_probe is not None"
                "}))"
            ),
        )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result == {
        "tools": [],
        "routes": [
            "/_local/c9/approve",
            "/_local/c9/chat/claim",
            "/_local/c9/chat/confirm",
            "/_local/c9/chat/export",
            "/_local/c9/close",
            "/_local/c9/stage",
            "/_local/c9/status",
            "/_local/c9/work/confirm",
        ],
        "c0": False,
    }


def test_c9_main_rejects_a_build_commit_different_from_head() -> None:
    with _isolated_runtime_state() as state:
        completed = _run(
            state,
            "import systeme_local_gateway.main",
            environment=_environment(state, commit="0" * 40),
        )

    assert completed.returncode != 0
    assert "configured build commit does not match repository HEAD" in completed.stderr


def test_c9_main_requires_the_exact_trusted_git_executable() -> None:
    with _isolated_runtime_state() as state:
        environment = _environment(state)
        environment.pop("SLG_C9_GIT_EXECUTABLE")
        completed = _run(
            state,
            "import systeme_local_gateway.main",
            environment=environment,
        )

    assert completed.returncode != 0
    assert "SLG_C9_GIT_EXECUTABLE" in completed.stderr


def test_c9_main_refuses_a_policy_without_the_exact_handoff_capability() -> None:
    with _isolated_runtime_state() as state:
        environment = _environment(state)
        environment["SLG_POLICY_FILE"] = str(ROOT / "policy.c0.yaml")
        completed = _run(
            state,
            "import systeme_local_gateway.main",
            environment=environment,
        )

    assert completed.returncode != 0
    assert "policy must admit exactly the attachment handoff tool" in completed.stderr


def test_c9_main_removes_stale_runtime_admission_before_registry_construction() -> None:
    with _isolated_runtime_state() as state:
        admission = state / "admission.json"
        admission.write_text('{"stale":true}', encoding="utf-8")
        completed = _run(
            state,
            (
                "from pathlib import Path;"
                "import systeme_local_gateway.main as m;"
                "print(Path(m.settings.c9_admission_file).exists())"
            ),
        )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "False"


def test_c9_main_refuses_to_unlink_a_hardlinked_stale_admission() -> None:
    with _isolated_runtime_state() as state:
        outside = state.parent / f"{state.name}-outside-admission.json"
        outside.write_text('{"outside":true}', encoding="utf-8")
        admission = state / "admission.json"
        try:
            os.link(outside, admission)
        except OSError:
            outside.unlink(missing_ok=True)
            return
        try:
            completed = _run(
                state,
                "import systeme_local_gateway.main",
            )

            assert completed.returncode != 0
            assert "multiply-linked" in completed.stderr
            assert outside.read_text(encoding="utf-8") == '{"outside":true}'
            assert admission.exists()
        finally:
            admission.unlink(missing_ok=True)
            outside.unlink(missing_ok=True)


def test_c9_main_refuses_a_missing_runtime_observation() -> None:
    with _isolated_runtime_state() as state:
        environment = _environment(state)
        Path(environment["SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE"]).unlink()

        completed = _run(
            state,
            "import systeme_local_gateway.main",
            environment=environment,
        )

    assert completed.returncode != 0
    assert "C9 local-AI runtime observation is invalid" in completed.stderr


def test_c9_main_refuses_an_oversized_runtime_observation() -> None:
    with _isolated_runtime_state() as state:
        environment = _environment(state)
        observation = Path(environment["SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE"])
        observation.write_bytes(b"x" * (64 * 1024 + 1))

        completed = _run(
            state,
            "import systeme_local_gateway.main",
            environment=environment,
        )

    assert completed.returncode != 0
    assert "C9 local-AI runtime observation is invalid" in completed.stderr


def test_c9_main_refuses_a_hardlinked_runtime_observation() -> None:
    with _isolated_runtime_state() as state:
        environment = _environment(state)
        observation = Path(environment["SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE"])
        content = observation.read_bytes()
        observation.unlink()
        outside = state.parent / f"{state.name}-outside-observation.json"
        outside.write_bytes(content)
        try:
            try:
                os.link(outside, observation)
            except OSError:
                return

            completed = _run(
                state,
                "import systeme_local_gateway.main",
                environment=environment,
            )

            assert completed.returncode != 0
            assert "multiply-linked" in completed.stderr
            assert outside.read_bytes() == content
        finally:
            observation.unlink(missing_ok=True)
            outside.unlink(missing_ok=True)
