from __future__ import annotations

import ast
from pathlib import Path

import systeme_local_gateway.providers as providers

ROOT = Path(__file__).resolve().parents[1]


def test_attachment_contract_documents_security_boundaries():
    text = (ROOT / "docs/provider-attachments.md").read_text(encoding="utf-8")
    for marker in (
        "Raw bytes are not placed in Pydantic models",
        "There is intentionally no generic `application/octet-stream` commitment",
        "already be NFC-normalized",
        "duplicate raw content digests",
        "## Deterministic all-or-nothing batching",
        "JSON-grammar whitespace only",
        "domain-separated digest of the complete quota snapshot",
        "A simulated receipt cannot predate its plan",
        "Ambiguous acceptance never authorizes an automatic retry",
        "stores no local path",
        "encrypted blob storage",
    ):
        assert marker in text


def test_connectivity_links_attachment_contract():
    text = (ROOT / "docs/connectivity-model.md").read_text(encoding="utf-8")
    assert "## Committed attachments and deterministic batching" in text
    assert "[`provider-attachments.md`](provider-attachments.md)" in text
    assert "No real provider upload capability is inferred" in text


def test_context_registry_points_to_separate_attachment_contract():
    text = (ROOT / "docs/provider-context-registry.md").read_text(encoding="utf-8")
    assert "## Attachment foundation" in text
    assert "[`provider-attachments.md`](provider-attachments.md)" in text
    assert "still stores no attachment bytes or screenshots" in text


def test_chatgpt_keeps_real_upload_capability_unknown():
    text = (ROOT / "docs/providers/chatgpt.md").read_text(encoding="utf-8")
    assert (
        "Real ChatGPT upload capability for an outbound local-agent "
        "surface remains `unknown`."
        in text
    )
    assert (
        "No local format validator or fake receipt proves a supported "
        "ChatGPT transport."
        in text
    )


def test_public_attachment_exports_are_complete():
    expected = {
        "AttachmentBatch",
        "AttachmentBatchPlan",
        "AttachmentBatchReceipt",
        "AttachmentCapabilityProfile",
        "AttachmentIdempotencyConflictError",
        "AttachmentInspection",
        "AttachmentInspectionError",
        "AttachmentInspectionReason",
        "AttachmentManifest",
        "AttachmentMediaFamily",
        "AttachmentMediaType",
        "AttachmentPlanningError",
        "AttachmentPlanningReason",
        "AttachmentQuotaRequirement",
        "AttachmentRetryDirective",
        "AttachmentRole",
        "AttachmentSource",
        "AttachmentTransferStatus",
        "AttachmentVerificationError",
        "AttachmentVerificationReason",
        "CommittedAttachment",
        "attachment_quota_snapshot_sha256",
        "DeterministicFakeAttachmentProvider",
        "FakeAttachmentScenario",
        "commit_attachment",
        "commit_attachment_capability_profile",
        "commit_attachment_manifest",
        "inspect_attachment_bytes",
        "plan_attachment_batches",
        "verify_attachment_batch_plan",
        "verify_attachment_batch_receipt",
        "verify_attachment_bytes",
        "verify_attachment_manifest",
    }
    assert expected <= set(providers.__all__)
    for name in expected:
        assert getattr(providers, name) is not None


def test_new_attachment_modules_have_no_transport_or_process_imports():
    forbidden = {
        "aiohttp",
        "http",
        "httpx",
        "openai",
        "requests",
        "socket",
        "subprocess",
        "urllib",
        "webbrowser",
    }
    paths = [
        ROOT / "src/systeme_local_gateway/providers/attachment_models.py",
        ROOT / "src/systeme_local_gateway/providers/attachment_commit.py",
        ROOT / "src/systeme_local_gateway/providers/attachment_policy.py",
        ROOT / "src/systeme_local_gateway/providers/fake_attachment_provider.py",
    ]
    observed: set[str] = set()
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                observed.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                observed.add(node.module.split(".", 1)[0])
    assert observed.isdisjoint(forbidden)


def test_attachment_models_do_not_contain_raw_bytes_fields():
    source = (ROOT / "src/systeme_local_gateway/providers/attachment_models.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign):
            annotation = ast.unparse(node.annotation)
            assert annotation not in {"bytes", "bytearray", "memoryview"}
