from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_document_authority_is_explicit() -> None:
    governance = text("docs/documentation-governance.md")
    for marker in (
        "README.md",
        "docs/blueprint-v2.md",
        "docs/architecture.md",
        "docs/connectivity-model.md",
        "docs/roadmap.md",
        "docs/adr/*.md",
    ):
        assert marker in governance
    assert "sole normative cross-provider connectivity contract" in governance


def test_readme_has_no_obsolete_provider_router_language() -> None:
    readme = text("README.md")
    assert "Brain Router" not in readme
    assert "flux GLM prioritaire" not in readme
    assert "MCP entrant" in readme
    assert "adaptateur fournisseur sortant" in readme
    assert "docs/documentation-governance.md" in readme


def test_implemented_architecture_has_complete_status_matrix() -> None:
    architecture = text("docs/architecture.md")
    for marker in (
        "## Implemented components",
        "## Implementation-status matrix",
        "provider lifecycle",
        "Provider context registry",
        "Attachment manifest foundation",
        "sealed operator-evidence bundle",
        "real operator-evidence collection",
        "blocked_by_evidence",
    ):
        assert marker in architecture


def test_roadmap_matches_merged_foundations() -> None:
    roadmap = text("docs/roadmap.md")
    for marker in (
        "loopback MCP Streamable HTTP façade",
        "provider lifecycle and deterministic ChatGPT adapter",
        "attachment metadata, manifests and batching",
        "sealed operator-evidence bundle",
        "Provider package compatibility refactor",
        "Bounded operator-evidence collection",
    ):
        assert marker in roadmap
    assert "Status: `implemented`" not in roadmap.split("### Secure MCP Tunnel", maxsplit=1)[1]


def test_chatgpt_phases_are_reconciled() -> None:
    content = text("docs/providers/chatgpt.md")
    assert "deterministic lifecycle, context, attachment" in content
    for phase in range(14):
        assert f"### Phase {phase} " in content
    assert "Encrypted blob storage, redaction, OCR, approval, retention" in content
    assert "Status: `blocked_by_evidence`" in content


def test_attachment_security_lot_remains_separate() -> None:
    provider_doc = text("docs/provider-attachments.md")
    chatgpt_doc = text("docs/providers/chatgpt.md")
    assert "A separate security lot may add encrypted blob storage" in provider_doc
    assert "They remain a separate security lot." in chatgpt_doc


def test_threat_model_covers_provider_evidence_boundary() -> None:
    content = text("docs/threat-model.md")
    for marker in (
        "Attestation opérateur",
        "Métadonnées OAuth/OIDC malveillantes",
        "Attestation tunnel/TLS forgée",
        "Cycle obligatoire des futures preuves brutes",
        "destruction vérifiée",
        "Dérive des outils",
    ):
        assert marker in content


def test_governance_files_cover_sensitive_surfaces() -> None:
    codeowners = text(".github/CODEOWNERS")
    template = text(".github/pull_request_template.md")
    for marker in (
        "/src/systeme_local_gateway/providers/",
        "/docs/connectivity-model.md",
        "/.github/",
        "/uv.lock",
    ):
        assert marker in codeowners
    for marker in (
        "Autorité documentaire",
        "modèle de menace",
        "schémas publics",
        "dates de preuve",
        "audit des dépendances Python",
        "tests Rust Windows",
    ):
        assert marker in template


def test_github_governance_snapshot_is_sanitized() -> None:
    snapshot = json.loads(text("governance/github-settings-snapshot.json"))
    assert snapshot["version"] == 1
    assert snapshot["repository"] == "Cheurteenyt/systeme-local"
    assert snapshot["observed_at"].endswith("Z")
    rendered = json.dumps(snapshot)
    assert "gho_" not in rendered
    assert "Authorization" not in rendered
    assert text("docs/github-governance.md").find("unknown") >= 0


def test_provider_package_audit_records_compatibility_boundary() -> None:
    content = text("docs/provider-package-audit.md")
    assert "public `__all__` exports" in content
    assert "_canonical_json" in content
    assert "_require_aware" in content
    assert "No public import or digest domain changes" in content


def test_markdown_link_checker_passes() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_markdown_links.py", "--root", str(ROOT)],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_evidence_governance_is_deterministic() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/check_evidence_governance.py",
            "--root",
            str(ROOT),
            "--as-of",
            "2026-07-18T20:00:00Z",
            "--fail-within-days",
            "0",
        ],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_scheduled_evidence_workflow_exists() -> None:
    workflow = text(".github/workflows/evidence-governance.yml")
    assert 'cron: "17 6 * * *"' in workflow
    assert "--fail-within-days 7" in workflow
    assert "permissions:\n  contents: read" in workflow


def test_python_format_governance_uses_a_non_growing_ratchet() -> None:
    baseline = text("governance/ruff-format-baseline.txt")
    checker = text("scripts/check_python_format.py")
    workflow = text(".github/workflows/ci.yml")
    contributing = text("CONTRIBUTING.md")
    provider_audit = text("docs/provider-package-audit.md")

    entries = [line for line in baseline.splitlines() if line and not line.startswith("#")]
    assert len(entries) == 54
    assert entries == sorted(entries)
    assert len(entries) == len(set(entries))

    retired = {
        "src/systeme_local_gateway/providers/mcp_deployment_models.py",
        "src/systeme_local_gateway/providers/mcp_operator_evidence_models.py",
        "src/systeme_local_gateway/providers/mcp_readiness_models.py",
    }
    assert retired.isdisjoint(entries)

    assert "new Ruff formatting debt outside the approved baseline" in checker
    assert "changed Python files must be Ruff-formatted" in checker
    assert "scripts/check_python_format.py" in workflow
    assert "ruff format --check ." not in workflow
    assert "formatting ratchet" in contributing
    assert "decreases from 57 to 54 files" in provider_audit


def test_python_typing_governance_uses_a_non_growing_ratchet() -> None:
    baseline = json.loads(text("governance/mypy-baseline.json"))
    checker = text("scripts/check_python_typing.py")
    pyproject = text("pyproject.toml")
    workflow = text(".github/workflows/ci.yml")
    contributing = text("CONTRIBUTING.md")
    provider_audit = text("docs/provider-package-audit.md")

    assert baseline["version"] == 1
    assert baseline["scope"] == sorted(baseline["scope"])
    assert "src/systeme_local_gateway/providers/_canonicalization.py" in baseline["scope"]
    assert baseline["diagnostics"] == []

    assert "new Mypy diagnostics outside the approved baseline" in checker
    assert "changed Python files must retire" in checker
    assert 'files = [\n  "scripts",' in pyproject
    assert "src/systeme_local_gateway/providers/_canonicalization.py" in pyproject
    assert "scripts/check_python_typing.py" in workflow
    assert "uv run --frozen --extra dev mypy\n" not in workflow
    assert "Mypy ratchet" in contributing
    assert "retired from three diagnostics to zero" in provider_audit


def test_python_dependency_audit_uses_frozen_hashed_lock_export() -> None:
    checker = text("scripts/audit_python_dependencies.py")
    workflow = text(".github/workflows/ci.yml")
    makefile = text("Makefile")
    contributing = text("CONTRIBUTING.md")
    governance = text("docs/documentation-governance.md")
    codeowners = text(".github/CODEOWNERS")

    for marker in (
        '"export"',
        '"--frozen"',
        '"--extra"',
        '"dev"',
        '"--no-emit-project"',
        '"requirements.txt"',
        '"--require-hashes"',
        '"--disable-pip"',
    ):
        assert marker in checker

    assert "pip-audit --strict --skip-editable" not in workflow
    assert "scripts/audit_python_dependencies.py" in workflow
    assert "scripts/audit_python_dependencies.py" in makefile
    assert "scripts/audit_python_dependencies.py" in contributing
    assert "exported lock" in governance
    assert "/scripts/audit_*.py" in codeowners


def test_pytest_security_floor_is_locked_without_audit_ignore() -> None:
    pyproject = text("pyproject.toml")
    lock = text("uv.lock")
    governance = text("docs/documentation-governance.md")
    audit = text("scripts/audit_python_dependencies.py")

    assert '"pytest>=9.0.3,<10"' in pyproject
    assert '"pytest>=8.2,<9"' not in pyproject

    package_start = lock.index('name = "pytest"')
    pytest_block = lock[package_start : package_start + 240]
    assert 'version = "9.0.3"' in pytest_block
    assert 'version = "8.4.2"' not in pytest_block

    assert "PYSEC-2026-1845" in governance
    assert "--ignore-vuln" not in audit
