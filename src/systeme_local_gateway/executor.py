from pathlib import Path
from typing import Any, Protocol

from .paths import resolve_inside
from .sandbox import DockerSandboxRunner


class SandboxRunner(Protocol):
    def run(
        self,
        workspace: Path,
        command: list[str],
        *,
        include_git: bool,
    ) -> dict[str, object]: ...


class CapabilityExecutor:
    def __init__(
        self,
        workspace: Path,
        docker_image: str,
        limits: dict[str, Any],
        sandbox_root: Path | None = None,
        sandbox_runner: SandboxRunner | None = None,
    ):
        self.workspace = workspace.resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.docker_image = docker_image
        self.limits = limits
        resolved_sandbox_root = (
            sandbox_root.resolve()
            if sandbox_root is not None
            else (self.workspace.parent / ".systeme-local" / "sandboxes").resolve()
        )
        self.sandbox_runner = sandbox_runner or DockerSandboxRunner(
            docker_image,
            resolved_sandbox_root,
            limits,
        )

    def execute(
        self,
        capability: str,
        arguments: dict[str, Any],
        config: dict[str, Any],
    ) -> dict[str, Any]:
        handlers = {
            "workspace.list": self._list,
            "workspace.read_text": self._read_text,
            "workspace.write_text": self._write_text,
            "sandbox.run_tests": self._run_tests,
            "git.diff": self._run_git_command,
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

    def _run_tests(self, arguments: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        command = self._validated_command(arguments, config)
        return self.sandbox_runner.run(self.workspace, command, include_git=False)

    def _run_git_command(self, arguments: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        command = self._validated_command(arguments, config)
        return self.sandbox_runner.run(self.workspace, command, include_git=True)

    @staticmethod
    def _validated_command(arguments: dict[str, Any], config: dict[str, Any]) -> list[str]:
        command = arguments.get("command")
        if not isinstance(command, list) or not command or not all(
            isinstance(item, str) and item for item in command
        ):
            raise ValueError("command must be a non-empty argv array")
        allowed = config.get("allowed_commands", [])
        if command not in allowed:
            raise ValueError("command is not allowlisted")
        return command
