from __future__ import annotations

import json
import posixpath
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def section(content: str, heading: str) -> str:
    start = content.index(heading)
    boundaries = [
        index
        for marker in ("\n### ", "\n## ")
        if (index := content.find(marker, start + len(heading))) >= 0
    ]
    return content[start : min(boundaries, default=len(content))]


def normalized_prose(value: str) -> str:
    return " ".join(value.split())


def test_document_authority_is_explicit() -> None:
    governance = text("docs/documentation-governance.md")
    for marker in (
        "README.md",
        "docs/blueprint-v2.md",
        "docs/architecture.md",
        "docs/connectivity-model.md",
        "docs/operator-evidence-session-lifecycle.md",
        "docs/operator-evidence-staging.md",
        "docs/roadmap.md",
        "docs/adr/*.md",
        "[`docs/github-governance.md`](github-governance.md)",
    ):
        assert marker in governance
    assert "sole normative cross-provider connectivity contract" in governance


def test_documentation_index_is_complete_and_non_normative() -> None:
    readme = text("README.md")
    index = text("docs/index.md")
    governance = text("docs/documentation-governance.md")

    assert "[`index documentaire`](docs/index.md)" in readme
    assert "[`docs/index.md`](index.md)" in governance
    assert "descriptive navigation only" in index
    assert "does not own normative facts" in index
    assert "linked document remains authoritative" in index

    tracked = subprocess.run(
        ["git", "ls-files", "--", "*.md"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.splitlines()
    expected_targets = {
        posixpath.relpath(path, "docs") for path in tracked if path != "docs/index.md"
    }
    observed_targets = set(re.findall(r"\]\(([^)#]+)(?:#[^)]+)?\)", index))

    assert expected_targets <= observed_targets


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
    assert "through pull request #42" in roadmap
    assert "1c84538369eb662b61cc4f56a79131569b9ca200" in roadmap

    architecture = section(roadmap, "### Architecture and evidence governance")
    canonicalization = section(
        roadmap,
        "### Provider canonicalization compatibility refactor",
    )
    operator_evidence = section(roadmap, "### Bounded operator-evidence collection")
    tunnel = section(roadmap, "### Secure MCP Tunnel")
    oauth = section(roadmap, "### OAuth/OIDC and app configuration")
    outbound = section(roadmap, "### One supported outbound provider transport")
    public_reorganization = section(roadmap, "### Public provider package reorganization")

    architecture_prose = normalized_prose(architecture)
    canonicalization_prose = normalized_prose(canonicalization)
    operator_evidence_prose = normalized_prose(operator_evidence)
    public_reorganization_prose = normalized_prose(public_reorganization)

    assert "Status: `implemented`" in architecture
    assert "pull request #40" in architecture_prose.lower()
    assert "c720f4ae9d295e3e2af6993b40a0b03bfd14c2b9" in architecture_prose

    assert "Status: `implemented`" in canonicalization
    for marker in (
        "179 ordered public provider exports",
        "18 affected Pydantic contracts",
        "22 enums",
        "13 digest domains",
        "three diagnostics to zero",
        "57 to 54 files",
        "did not split the public façade",
    ):
        assert marker in canonicalization_prose

    assert "Status: `planned`" in operator_evidence
    for marker in (
        "next product implementation lot",
        "exactly the eleven required observations",
        "No tunnel, OAuth client, app configuration or provider call",
    ):
        assert marker in operator_evidence_prose

    assert "Status: `planned`" in public_reorganization
    for marker in (
        "separate issue",
        "explicit compatibility and versioning decision",
        "does not grant implicit permission",
    ):
        assert marker in public_reorganization_prose

    assert roadmap.index("### Bounded operator-evidence collection") < roadmap.index(
        "### Secure MCP Tunnel"
    )
    assert roadmap.index("### Secure MCP Tunnel") < roadmap.index(
        "### OAuth/OIDC and app configuration"
    )
    assert roadmap.index("### OAuth/OIDC and app configuration") < roadmap.index(
        "### One supported outbound provider transport"
    )

    for future_section in (tunnel, oauth, outbound, public_reorganization):
        assert "Status: `implemented`" not in future_section


def test_chatgpt_phases_are_reconciled() -> None:
    content = text("docs/providers/chatgpt.md")
    assert "deterministic lifecycle, context, attachment" in content
    for phase in range(17):
        assert f"### Phase {phase} " in content

    phase_7 = section(
        content,
        "### Phase 7 — architecture and provider-package reconciliation",
    )
    phase_8 = section(
        content,
        "### Phase 8 — private provider canonicalization compatibility refactor",
    )
    phase_9 = section(
        content,
        "### Phase 9 — bounded local operator-evidence collection",
    )
    phase_12 = section(content, "### Phase 12 — ChatGPT custom MCP app connection")

    phase_7_prose = normalized_prose(phase_7)
    phase_8_prose = normalized_prose(phase_8)
    phase_9_prose = normalized_prose(phase_9)

    assert "Status: `implemented`" in phase_7
    for marker in (
        "pull request #40",
        "added no capability",
        "performed no provider connection",
    ):
        assert marker in phase_7_prose.lower()

    assert "Status: `implemented`" in phase_8
    for marker in (
        "179 ordered public exports",
        "18 affected Pydantic contracts",
        "22 enums",
        "13 digest domains",
        "Mypy baseline is zero diagnostics",
        "Ruff formatting baseline is 54 files",
        "did not split the public façade",
        "separate planned compatibility and versioning decision",
    ):
        assert marker in phase_8_prose

    assert "Status: `planned`" in phase_9
    for marker in (
        "next product implementation phase",
        "exactly the eleven required observations",
        "no tunnel installation, OAuth registration, app configuration or provider",
    ):
        assert marker in phase_9_prose

    assert "Status: `planned`" in phase_12
    assert content.index("### Phase 9 ") < content.index("### Phase 12 ")
    assert "Encrypted blob storage, redaction, OCR, approval, retention" in content
    assert "Status: `blocked_by_evidence`" in content


def test_provider_reconciliation_metrics_match_governance_contracts() -> None:
    roadmap = text("docs/roadmap.md")
    chatgpt = text("docs/providers/chatgpt.md")
    provider_audit = text("docs/provider-package-audit.md")
    mypy_baseline = json.loads(text("governance/mypy-baseline.json"))
    ruff_entries = [
        line
        for line in text("governance/ruff-format-baseline.txt").splitlines()
        if line and not line.startswith("#")
    ]

    assert mypy_baseline["diagnostics"] == []
    assert len(ruff_entries) == 42

    for content in (roadmap, chatgpt, provider_audit):
        assert "179" in content
        assert "zero" in content
        assert "42" in content

    assert "18 affected Pydantic" in roadmap
    assert "18 affected Pydantic" in chatgpt
    assert "18 affected public Pydantic" in provider_audit
    assert "22 enums" in roadmap
    assert "22 enums" in chatgpt
    assert "22 affected public enum" in provider_audit
    assert "13 digest domains" in roadmap
    assert "13 digest domains" in chatgpt
    assert "13 domain-separated SHA-256" in provider_audit


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


def test_operator_evidence_session_lifecycle_is_reconciled() -> None:
    lifecycle = text("docs/operator-evidence-session-lifecycle.md")
    protocol = text("docs/operator-evidence-custodian-protocol.md")
    architecture = text("docs/architecture.md")
    threat_model = text("docs/threat-model.md")

    for marker in (
        "Status: normative private Rust lifecycle contract through B1.6",
        "disposed -> <none>",
        "revision + 1",
        r"systeme-local:operator-evidence-session-transition:v1\x00",
        "The receipt is not a disposition receipt",
        "filesystem or network I/O;",
    ):
        assert marker in lifecycle

    assert "does not add a protocol operation" in protocol
    assert "operator-evidence session lifecycle | implemented" in architecture
    assert "Controls implemented in B1.1" in threat_model
    assert "Controls implemented in B1.2" in threat_model


def test_operator_evidence_staging_is_reconciled() -> None:
    staging = text("docs/operator-evidence-staging.md")
    protocol = text("docs/operator-evidence-custodian-protocol.md")
    architecture = text("docs/architecture.md")
    lifecycle = text("docs/operator-evidence-session-lifecycle.md")
    governance = text("docs/documentation-governance.md")

    for marker in (
        "Status: normative private Rust staging contract through B1.6",
        "src_[0-9a-f]{32}.raw",
        "cap-std = 4.0.2",
        "cap-fs-ext = 4.0.2",
        "session.state == collecting",
        "1 ..= 8 MiB",
        "16 KiB",
        "The public Rust surface exposes only",
        "not a disposition receipt",
        "No real evidence may be handled",
    ):
        assert marker in staging

    assert "B1.2 internal staging reader" in protocol
    assert "not reachable through protocol v1" in protocol
    assert "operator-evidence bounded staging | implemented" in architecture
    assert "B1.2 staging relationship" in lifecycle
    assert "docs/operator-evidence-staging.md" in governance


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
            "2026-07-26T20:00:00Z",
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
    assert len(entries) == 42
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
    assert "decreases from 54 to 42 files" in provider_audit


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
    assert 'version = "9.1.1"' in pytest_block
    assert 'version = "8.4.2"' not in pytest_block

    assert "PYSEC-2026-1845" in governance
    assert "--ignore-vuln" not in audit


def test_operator_evidence_controlled_staging_is_reconciled() -> None:
    staging = text("docs/operator-evidence-staging.md")
    lifecycle = text("docs/operator-evidence-session-lifecycle.md")
    protocol = text("docs/operator-evidence-custodian-protocol.md")
    architecture = text("docs/architecture.md")
    threat_model = text("docs/threat-model.md")
    adr = text("docs/adr/0005-python-rust-operator-evidence-custody.md")

    for marker in (
        "stg_[0-9a-f]{32}",
        "0700",
        "0600",
        "protected DACL",
        "create_new",
        "same live lease identity",
    ):
        assert marker in staging

    assert "B1.3 controlled staging relationship" in lifecycle
    assert "B1.3 controlled staging boundary" in protocol
    assert "operator-evidence controlled staging | implemented" in architecture
    assert "Controls implemented in B1.3" in threat_model
    assert "B1.3 implementation record" in adr
    assert "source commitment | planned" in architecture
    assert "real evidence ingestion | not implemented" in architecture


def test_operator_evidence_retention_disposition_is_reconciled() -> None:
    contract = text("docs/operator-evidence-retention-disposition.md")
    lifecycle = text("docs/operator-evidence-session-lifecycle.md")
    staging = text("docs/operator-evidence-staging.md")
    protocol = text("docs/operator-evidence-custodian-protocol.md")
    architecture = text("docs/architecture.md")
    roadmap = text("docs/roadmap.md")
    threat_model = text("docs/threat-model.md")
    governance = text("docs/documentation-governance.md")
    index = text("docs/index.md")
    adr = text("docs/adr/0005-python-rust-operator-evidence-custody.md")

    for marker in (
        "dispose_immediately",
        "retain_until",
        "1 <= dispose_by_unix_seconds - decided_at_unix_seconds <= 900",
        r"systeme-local:operator-evidence-retention-decision:v1\x00",
        r"systeme-local:operator-evidence-logical-disposition:v1\x00",
        "logical namespace disposition",
        "not a physical-erasure",
    ):
        assert marker in contract

    assert "B1.6 retention and disposition behavior" in lifecycle
    assert "B1.6 capability-relative logical cleanup" in staging
    assert "B1.6 remains outside protocol v1" in protocol
    assert "B1.6 private retention and logical disposition" in architecture
    assert "B1.6 bounded retention and logical disposition foundation" in roadmap
    assert "B1.6 retention and logical-disposition threats and controls" in threat_model
    assert "docs/operator-evidence-retention-disposition.md" in governance
    assert "operator-evidence-retention-disposition.md" in index
    assert "B1.6 retention and logical-disposition record" in adr


def test_b2_0_operator_evidence_orchestration_contract_is_closed() -> None:
    contract = text("docs/operator-evidence-orchestration.md")
    manifest = json.loads(text("docs/operator-evidence-protocol-v2-design.json"))
    protocol = text("docs/operator-evidence-custodian-protocol.md")
    architecture = text("docs/architecture.md")
    roadmap = text("docs/roadmap.md")
    threat_model = text("docs/threat-model.md")
    governance = text("docs/documentation-governance.md")
    index = text("docs/index.md")
    adr_5 = text("docs/adr/0005-python-rust-operator-evidence-custody.md")
    adr_6 = text("docs/adr/0006-inherited-handles-for-operator-evidence.md")
    chatgpt = text("docs/providers/chatgpt.md")

    for marker in (
        "no protocol-v2 runtime capability is implemented",
        "process_evidence",
        "recover_evidence",
        "dispose_immediately",
        "retain_until",
        "readiness_ui_snapshot_v1",
        "authentication_summary_v1",
        "tool_review_snapshot_v1",
        "transport_attestation_summary_v1",
        "success_evidence_emitted = false",
        "Python does not read raw evidence bytes",
    ):
        assert marker in contract

    assert manifest["schema"] == "systeme-local.operator-evidence-protocol-v2-design.v1"
    assert manifest["status"] == "contract_only"
    assert manifest["runtime_reachable"] is False
    assert manifest["real_evidence_collection_enabled"] is False
    assert manifest["protocol_v1"] == {
        "version": 1,
        "operations": ["describe_contract"],
        "fixtures_byte_for_byte_unchanged": True,
    }

    protocol_v2 = manifest["protocol_v2"]
    assert protocol_v2["operations"] == [
        "describe_contract",
        "process_evidence",
        "recover_evidence",
    ]
    assert protocol_v2["wire_retention_modes"] == ["dispose_immediately"]
    assert protocol_v2["library_only_retention_modes"] == ["retain_until"]
    assert protocol_v2["path_in_request"] is False
    assert protocol_v2["raw_bytes_in_python"] is False
    assert protocol_v2["network_access"] is False
    assert protocol_v2["shell_invocation"] is False
    assert protocol_v2["limits"] == {
        "absolute_source_bytes": 8_388_608,
        "projection_bytes": 8_192,
        "recovery_journal_bytes": 4_096,
        "stderr_bytes": 8_192,
        "stdin_bytes": 16_384,
        "stdout_bytes": 65_536,
    }

    expected_check_order = [
        "plan_role_observation",
        "web_client",
        "transport",
        "authentication_metadata",
        "refresh_token",
        "developer_mode",
        "app_configuration",
        "workspace_access",
        "tool_snapshot",
        "action_review",
        "local_policy",
    ]
    expected_validity = [
        86_400,
        14_400,
        900,
        3_600,
        3_600,
        3_600,
        3_600,
        3_600,
        1_800,
        1_800,
        86_400,
    ]
    assert [entry["check_id"] for entry in manifest["checks"]] == expected_check_order
    assert [entry["max_validity_seconds"] for entry in manifest["checks"]] == expected_validity
    assert [entry["order"] for entry in manifest["checks"]] == list(range(1, 12))

    by_check = {entry["check_id"]: entry for entry in manifest["checks"]}
    assert by_check["local_policy"]["exact_b1_profile"] == "local_policy_snapshot_v1"
    assert by_check["local_policy"]["mapping_status"] == "exact"
    assert by_check["action_review"]["exact_b1_profile"] == "action_review_snapshot_v1"
    assert by_check["action_review"]["mapping_status"] == "partial"
    assert by_check["transport"]["mapping_status"] == "external_dependency"
    assert by_check["tool_snapshot"]["gap_id"] == "tool_review_snapshot_v1"
    assert by_check["authentication_metadata"]["gap_id"] == "authentication_summary_v1"
    assert by_check["refresh_token"]["source_reuse"] == (
        "authentication_metadata_same_summary_only"
    )

    assert "B2.0 protocol-v2 design remains non-reachable" in protocol
    assert "B2.0 contract-only orchestration design" in architecture
    assert "B2.0 operator-evidence protocol and orchestration contract" in roadmap
    assert "B2.0 protocol and orchestration design threats" in threat_model
    assert "docs/operator-evidence-orchestration.md" in governance
    assert "operator-evidence-orchestration.md" in index
    assert "0006-inherited-handles-for-operator-evidence.md" in index
    assert "B2.0 successor decision" in adr_5
    assert "Use inherited read-only handles" in adr_6
    assert "B2.0 contract boundary" in chatgpt

    fixtures = sorted((ROOT / "tests/fixtures/operator_evidence_v2").glob("*.ndjson"))
    assert [path.name for path in fixtures] == [
        "error.response.ndjson",
        "process_evidence.request.ndjson",
        "process_evidence.response.ndjson",
        "recover_evidence.request.ndjson",
        "recover_evidence.response.ndjson",
    ]
    for fixture in fixtures:
        raw = fixture.read_bytes()
        assert raw.endswith(b"\n")
        assert b"\r" not in raw
        parsed = json.loads(raw)
        assert parsed["protocol_version"] == 2
        rendered = raw.decode("utf-8")
        for forbidden in (
            "C:\\\\",
            "/home/",
            "https://",
            "gho_",
            "Bearer ",
            "client_secret",
            "refresh_token_value",
            '"path"',
        ):
            assert forbidden not in rendered

    process_request = json.loads(
        text("tests/fixtures/operator_evidence_v2/process_evidence.request.ndjson")
    )
    assert process_request["operation"] == "process_evidence"
    assert process_request["retention_mode"] == "dispose_immediately"
    assert set(process_request) == set(protocol_v2["request_fields"]["process_evidence"])

    recover_response = json.loads(
        text("tests/fixtures/operator_evidence_v2/recover_evidence.response.ndjson")
    )
    assert recover_response["operation"] == "recover_evidence"
    assert recover_response["success_evidence_emitted"] is False


def test_b2_0_independent_review_findings_are_closed() -> None:
    from hashlib import sha256

    design = json.loads(text("docs/operator-evidence-protocol-v2-design.json"))
    protocol = design["protocol_v2"]

    assert design["contract_revision"] == 2
    assert sorted(design["review_finding_closures"]) == [
        "B20-REV-001",
        "B20-REV-002",
        "B20-REV-003",
        "B20-REV-004",
        "B20-REV-005",
    ]
    for key in (
        "request_schemas",
        "response_schemas",
        "error_response_schemas",
        "field_schemas",
        "canonical_field_order",
        "commitment_domains",
        "commitment_framing",
        "projection_schemas",
        "projection_verification",
        "recovery_journal_schema",
        "recovery_progress_states",
        "recovery_journal_permissions",
        "recovery_journal_integrity",
        "recovery_atomic_replace_contract",
        "recovery_validation_precedence",
    ):
        assert key in protocol

    assert sorted(protocol["synthetic_error_examples"]) == sorted(protocol["error_codes"])
    assert len(protocol["validation_precedence_edges"]) == (
        len(protocol["validation_precedence"]) - 1
    )
    assert sorted(design["attestation_digest_domains"]) == [
        "app_configuration",
        "developer_mode",
        "plan_role_observation",
        "web_client",
        "workspace_access",
    ]
    assert design["attestation_schemas"]["workspace_access"]["fields"]["authority"]["enum"] == [
        "workspace_admin"
    ]

    handles = protocol["inherited_handles"]
    assert handles["identifier_contract"]["bit_width"] == 63
    assert handles["identifier_contract"]["supported_process_pointer_width_bits"] == [64]
    assert handles["windows"]["spawn"]["close_fds"] is True
    assert handles["unix"]["spawn"]["close_fds"] is True

    journal = protocol["recovery_journal_schema"]
    assert journal["field_order"][-1] == "journal_sha256"
    assert protocol["recovery_progress_states"][0] == "prepared"
    assert protocol["recovery_progress_states"][-1] == "complete"
    assert len(protocol["recovery_progress_states"]) == 13

    time_contract = design["timestamp_ownership"]
    assert time_contract["maximum_future_skew_seconds"] == 0
    assert time_contract["maximum_process_duration_seconds"] == 60
    assert time_contract["maximum_recovery_duration_seconds"] == 30

    def domain_bytes(value: str) -> bytes:
        assert value.endswith("\\x00")
        return value[:-4].encode() + b"\x00"

    def canonical(value: dict[str, object]) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()

    def committed(domain: str, value: dict[str, object]) -> str:
        payload = canonical(value)
        return sha256(domain_bytes(domain) + len(payload).to_bytes(8, "big") + payload).hexdigest()

    domains = protocol["commitment_domains"]
    request = json.loads(
        text("tests/fixtures/operator_evidence_v2/process_evidence.request.ndjson")
    )
    request_order = protocol["request_schemas"]["process_evidence"]["field_order"]
    assert list(request) == request_order
    request_payload = {key: request[key] for key in request_order if key != "request_sha256"}
    assert request["request_sha256"] == committed(
        domains["request"],
        request_payload,
    )

    response = json.loads(
        text("tests/fixtures/operator_evidence_v2/process_evidence.response.ndjson")
    )
    response_order = protocol["response_schemas"]["process_evidence"]["field_order"]
    assert list(response) == response_order
    response_payload = {key: response[key] for key in response_order if key != "response_sha256"}
    assert response["response_sha256"] == committed(
        domains["success_response"],
        response_payload,
    )

    error = json.loads(text("tests/fixtures/operator_evidence_v2/error.response.ndjson"))
    error_order = protocol["error_response_schemas"]["typed_error"]["field_order"]
    assert list(error) == error_order
    error_payload = {key: error[key] for key in error_order if key != "error_sha256"}
    assert error["error_sha256"] == committed(
        domains["error_response"],
        error_payload,
    )

    assert design["runtime_reachable"] is False
    assert design["real_evidence_collection_enabled"] is False
