import subprocess
from pathlib import Path
from typing import Any

from .paths import resolve_inside


class CapabilityExecutor:
    def __init__(self, workspace: Path, docker_image: str, limits: dict[str, Any]):
        self.workspace = workspace.resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.docker_image = docker_image
        self.limits = limits

    def execute(self, capability: str, arguments: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        handlers = {
            "workspace.list": self._list,
            "workspace.read_text": self._read_text,
            "workspace.write_text": self._write_text,
            "sandbox.run_tests": self._run_sandbox_command,
            "git.diff": self._run_sandbox_command,
        }
        handler = handlers.get(capability)
        if handler is None:
            raise ValueError("capability has no executor")
        return handler(arguments, config)

    def _list(self, arguments: dict[str, Any], _config: dict[str, Any]) -> dict[str, Any]:
        target = resolve_inside(self.workspace, str(arguments.get("path", ".")))
        if not target.is_dir():
            raise ValueError("path is not a directory")
        entries = []
        for child in sorted(target.iterdir(), key=lambda p: p.name.lower()):
            entries.append({"name": child.name, "type": "directory" if child.is_dir() else "file"})
        return {"path": str(target.relative_to(self.workspace)), "entries": entries[:1000]}

    def _read_text(self, arguments: dict[str, Any], _config: dict[str, Any]) -> dict[str, Any]:
        target = resolve_inside(self.workspace, str(arguments["path"]))
        max_bytes = int(self.limits.get("max_read_bytes", 1_000_000))
        data = target.read_bytes()
        if len(data) > max_bytes:
            raise ValueError("file exceeds read limit")
        return {"path": str(target.relative_to(self.workspace)), "content": data.decode("utf-8")}

    def _write_text(self, arguments: dict[str, Any], _config: dict[str, Any]) -> dict[str, Any]:
        target = resolve_inside(self.workspace, str(arguments["path"]))
        content = str(arguments.get("content", ""))
        encoded = content.encode("utf-8")
        max_bytes = int(self.limits.get("max_write_bytes", 1_000_000))
        if len(encoded) > max_bytes:
            raise ValueError("content exceeds write limit")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(encoded)
        return {"path": str(target.relative_to(self.workspace)), "bytes_written": len(encoded)}

    def _run_sandbox_command(self, arguments: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        command = arguments.get("command")
        allowed = config.get("allowed_commands", [])
        if command not in allowed:
            raise ValueError("command is not allowlisted")
        if not isinstance(command, list) or not all(isinstance(x, str) for x in command):
            raise ValueError("command must be an argv array")

        timeout = int(self.limits.get("max_task_seconds", 120))
        memory_mb = int(self.limits.get("memory_mb", 1024))
        cpu_count = float(self.limits.get("cpu_count", 1))
        max_output = int(self.limits.get("max_output_bytes", 200_000))

        docker_command = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256",
            "--cpus", str(cpu_count),
            "--memory", f"{memory_mb}m",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
            "-v", f"{self.workspace}:/workspace:rw",
            "-w", "/workspace",
            self.docker_image,
            *command,
        ]
        completed = subprocess.run(
            docker_command,
            shell=False,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        stdout = completed.stdout[:max_output].decode("utf-8", errors="replace")
        stderr = completed.stderr[:max_output].decode("utf-8", errors="replace")
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": len(completed.stdout) > max_output or len(completed.stderr) > max_output,
        }
