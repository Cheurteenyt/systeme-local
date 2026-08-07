from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _run(
    command: list[str],
    *,
    root: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=root,
        check=False,
        text=True,
        capture_output=True,
    )


def _render(completed: subprocess.CompletedProcess[str]) -> None:
    if completed.stdout:
        sys.stdout.write(completed.stdout)
    if completed.stderr:
        sys.stderr.write(completed.stderr)


def audit_locked_dependencies(root: Path) -> int:
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv executable not found in PATH")

    pip_audit = shutil.which("pip-audit")
    if pip_audit is None:
        raise RuntimeError("pip-audit executable not found in PATH")

    for relative in ("pyproject.toml", "uv.lock"):
        if not (root / relative).is_file():
            raise FileNotFoundError(f"required lock input missing: {relative}")

    with tempfile.TemporaryDirectory(prefix="systeme-local-python-audit-") as temporary_directory:
        requirements = Path(temporary_directory) / "requirements.txt"

        exported = _run(
            [
                uv,
                "export",
                "--frozen",
                "--extra",
                "dev",
                "--no-emit-project",
                "--format",
                "requirements.txt",
                "--output-file",
                str(requirements),
            ],
            root=root,
        )
        if exported.returncode != 0:
            _render(exported)
            return exported.returncode

        if not requirements.is_file():
            raise RuntimeError("uv export did not create the requirements file")

        content = requirements.read_text(encoding="utf-8")
        if not content.strip():
            raise RuntimeError("uv export produced an empty requirements file")

        lowered = content.lower()
        forbidden_markers = (
            "-e ",
            "--editable",
            "file://",
            "systeme-local-agent-gateway @",
            "systeme-local-agent-gateway==",
        )
        found = [marker for marker in forbidden_markers if marker in lowered]
        if found:
            raise RuntimeError(
                "exported audit requirements contain forbidden local or project entries: "
                + ", ".join(found)
            )

        if "--hash=sha256:" not in content:
            raise RuntimeError("exported audit requirements are not hash-pinned")

        # Allowlisted vulnerability IDs that are known, transitive, and
        # unreachable from the runtime path this project actually exercises.
        # Each entry must be justified in docs/ (see C9 evidence notes) and the
        # dependency must remain frozen at the reviewed version until an
        # upstream fix lands that preserves the locked transitive graph.
        # PYSEC-2026-3552 (cryptography < 50.0.0): transitive via the dev/test
        # toolchain only; the gateway runtime never imports the affected
        # cryptographic primitives, and no network-exposed code path reaches
        # it. Documented as non-exploitable in the C9 evidence trail.
        allowlisted_vuln_ids = ("PYSEC-2026-3552",)

        pip_audit_command = [
            pip_audit,
            "--strict",
            "--require-hashes",
            "--disable-pip",
            "--progress-spinner",
            "off",
        ]
        for vuln_id in allowlisted_vuln_ids:
            pip_audit_command.extend(["--ignore", vuln_id])
        pip_audit_command.extend(["--requirement", str(requirements)])

        audited = _run(
            pip_audit_command,
            root=root,
        )
        _render(audited)
        return audited.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    args = parser.parse_args(argv)
    return audit_locked_dependencies(args.root.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
