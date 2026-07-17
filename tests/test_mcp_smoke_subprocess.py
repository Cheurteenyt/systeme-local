from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MCP_TOKEN = "mcp-smoke-token-" + ("t" * 64)
SHARED_SECRET = "mcp-smoke-shared-" + ("s" * 64)
AUDIT_KEY = "mcp-smoke-audit-" + ("a" * 64)


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _environment(tmp_path: Path) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("SLG_")
    }
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["PYTHONUNBUFFERED"] = "1"
    environment["SLG_SHARED_SECRET"] = SHARED_SECRET
    environment["SLG_AUDIT_KEY"] = AUDIT_KEY
    environment["SLG_MCP_ENABLED"] = "true"
    environment["SLG_MCP_TOKEN"] = MCP_TOKEN
    environment["SLG_WORKSPACE"] = str(tmp_path / "workspace")
    environment["SLG_POLICY_FILE"] = str(tmp_path / "policy.yaml")
    environment["SLG_AUDIT_LOG"] = str(tmp_path / "audit.jsonl")
    environment["SLG_REPLAY_DB"] = str(tmp_path / "replay.sqlite3")
    environment["SLG_APPROVAL_DB"] = str(tmp_path / "approvals.sqlite3")
    environment["SLG_SANDBOX_ROOT"] = str(tmp_path / "sandboxes")
    return environment


def _wait_until_healthy(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=2)
            raise AssertionError(
                "gateway exited before becoming healthy\n"
                f"stdout:\n{stdout}\n"
                f"stderr:\n{stderr}"
            )
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            body = response.read()
            if response.status == 200 and json.loads(body) == {"status": "ok"}:
                return
        except (ConnectionError, OSError, TimeoutError, json.JSONDecodeError):
            pass
        finally:
            connection.close()
        time.sleep(0.1)
    raise AssertionError("gateway did not become healthy before the timeout")


def _run_client(
    environment: dict[str, str],
    endpoint: str,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "systeme_local_gateway.mcp_smoke",
            "--url",
            endpoint,
            *arguments,
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def test_official_client_smoke_against_real_loopback_server(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "sample.txt").write_text("local smoke test\n", encoding="utf-8")
    (tmp_path / "policy.yaml").write_text(
        """version: 1
default: deny
capabilities:
  workspace.list:
    decision: allow
  workspace.read_text:
    decision: allow
  workspace.write_text:
    decision: require_approval
""",
        encoding="utf-8",
    )
    environment = _environment(tmp_path)
    port = _free_loopback_port()
    endpoint = f"http://127.0.0.1:{port}/mcp"
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "systeme_local_gateway.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=tmp_path,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_until_healthy(process, port)

        success = _run_client(
            environment,
            endpoint,
            "--call-tool",
            "workspace.list",
            "--arguments-json",
            '{"path":"."}',
        )
        assert success.returncode == 0, success.stderr
        payload = json.loads(success.stdout)
        assert payload["status"] == "ok"
        assert payload["tools"] == ["workspace.list", "workspace.read_text"]
        assert payload["call"] == {
            "tool": "workspace.list",
            "structured_content": {
                "path": ".",
                "entries": [{"name": "sample.txt", "type": "file"}],
            },
        }
        assert MCP_TOKEN not in success.stdout
        assert MCP_TOKEN not in success.stderr

        wrong_environment = dict(environment)
        wrong_token = "mcp-smoke-wrong-" + ("x" * 64)
        wrong_environment["SLG_MCP_TOKEN"] = wrong_token
        rejected = _run_client(wrong_environment, endpoint)
        assert rejected.returncode == 1
        assert rejected.stdout == ""
        assert json.loads(rejected.stderr) == {
            "status": "error",
            "error": "MCP smoke check failed",
        }
        assert MCP_TOKEN not in rejected.stderr
        assert wrong_token not in rejected.stderr
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        process.communicate(timeout=2)
