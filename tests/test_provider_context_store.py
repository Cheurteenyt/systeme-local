from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from systeme_local_gateway.providers.context_models import (
    AvailabilityState,
    BindingState,
    ConversationPersistence,
    DiscoverySource,
    ExperienceKind,
    PlanKind,
    ProjectMemoryScope,
    ProviderAccountProfile,
    ProviderContextCapabilities,
    ProviderConversationBinding,
    ProviderProjectBinding,
    ProviderQuotaSnapshot,
    QuotaDimension,
    QuotaState,
    SyncScope,
)
from systeme_local_gateway.providers.context_store import (
    ContextStoreConflictError,
    ContextStoreCorruptError,
    ContextStoreError,
    ContextWriteResult,
    ProviderContextStore,
    UnsupportedContextSchemaVersion,
)
from systeme_local_gateway.providers.models import (
    CapabilityClaim,
    CapabilityEvidence,
    CapabilitySupport,
)

NOW = datetime(2026, 7, 18, 10, 0, tzinfo=timezone.utc)


def context_fingerprint(payload: str) -> str:
    digest = sha256(b"systeme-local:provider-context:v1\x00")
    encoded = payload.encode("utf-8")
    digest.update(len(encoded).to_bytes(8, byteorder="big", signed=False))
    digest.update(encoded)
    return digest.hexdigest()


def unknown_context_capabilities() -> ProviderContextCapabilities:
    unknown = CapabilityClaim(
        state=CapabilitySupport.UNKNOWN,
        evidence=CapabilityEvidence.NONE,
    )
    return ProviderContextCapabilities(
        can_create_projects=unknown,
        can_enumerate_projects=unknown,
        exposes_project_id=unknown,
        can_create_conversations=unknown,
        can_enumerate_conversations=unknown,
        exposes_conversation_id=unknown,
    )


def account(**updates: object) -> ProviderAccountProfile:
    data: dict[str, object] = {
        "account_id": "acct_main",
        "provider": "chatgpt",
        "surface": "visible_account",
        "provider_account_id": "provider-account-1",
        "plan_kind": PlanKind.PAID,
        "plan_code": "plus",
        "availability": AvailabilityState.AVAILABLE,
        "profile_evidence": CapabilityEvidence.OBSERVED,
        "work_capability": CapabilityClaim(
            state=CapabilitySupport.SUPPORTED,
            evidence=CapabilityEvidence.DOCUMENTED,
        ),
        "context_capabilities": unknown_context_capabilities(),
        "revision": 1,
        "created_at": NOW,
        "updated_at": NOW,
    }
    data.update(updates)
    return ProviderAccountProfile(**data)


def project(**updates: object) -> ProviderProjectBinding:
    data: dict[str, object] = {
        "project_id": "proj_main",
        "account_id": "acct_main",
        "provider": "chatgpt",
        "surface": "visible_account",
        "provider_project_id": "provider-project-1",
        "display_name": "Système Local",
        "memory_scope": ProjectMemoryScope.PROJECT_ONLY,
        "state": BindingState.ACTIVE,
        "discovery_source": DiscoverySource.OPERATOR_CONFIRMED,
        "revision": 1,
        "created_at": NOW,
        "updated_at": NOW,
    }
    data.update(updates)
    return ProviderProjectBinding(**data)


def conversation(**updates: object) -> ProviderConversationBinding:
    data: dict[str, object] = {
        "conversation_id": "conv_architecture",
        "account_id": "acct_main",
        "project_id": "proj_main",
        "provider": "chatgpt",
        "surface": "visible_account",
        "provider_conversation_id": "provider-chat-1",
        "display_name": "Architecture générale",
        "experience": ExperienceKind.CHAT,
        "persistence": ConversationPersistence.PERSISTENT,
        "sync_scope": SyncScope.CLOUD,
        "state": BindingState.ACTIVE,
        "discovery_source": DiscoverySource.OPERATOR_CONFIRMED,
        "revision": 1,
        "created_at": NOW,
        "updated_at": NOW,
    }
    data.update(updates)
    return ProviderConversationBinding(**data)


def quota(**updates: object) -> ProviderQuotaSnapshot:
    data: dict[str, object] = {
        "snapshot_id": "quota_first",
        "account_id": "acct_main",
        "dimension": QuotaDimension.WORK_AGENTIC,
        "state": QuotaState.AVAILABLE,
        "evidence": CapabilityEvidence.OBSERVED,
        "observed_at": NOW,
    }
    data.update(updates)
    return ProviderQuotaSnapshot(**data)


def test_register_and_load_account_is_idempotent(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    assert store.register_account(account()) is ContextWriteResult.WRITTEN
    assert store.register_account(account()) is ContextWriteResult.DUPLICATE
    assert store.load_account("acct_main") == account()


def test_conflicting_account_and_provider_mapping_fail_closed(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    store.register_account(account())
    with pytest.raises(ContextStoreConflictError, match="already registered"):
        store.register_account(account(plan_code="pro"))
    other = account(
        account_id="acct_other",
        provider_account_id="provider-account-1",
    )
    with pytest.raises(ContextStoreConflictError, match="mapping"):
        store.register_account(other)


def test_account_compare_and_swap_rejects_stale_revisions(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    first = ProviderContextStore(path)
    second = ProviderContextStore(path)
    first.register_account(account())
    updated = account(
        revision=2,
        plan_code="pro",
        updated_at=NOW + timedelta(minutes=1),
    )
    assert first.replace_account(updated, expected_revision=1) is ContextWriteResult.WRITTEN
    with pytest.raises(ContextStoreConflictError, match="stale"):
        second.replace_account(
            account(
                revision=2,
                plan_code="business",
                updated_at=NOW + timedelta(minutes=1),
            ),
            expected_revision=1,
        )


def test_replacement_requires_sequential_revision_and_immutable_identity(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    store.register_account(account())
    with pytest.raises(ContextStoreConflictError, match="advance by one"):
        store.replace_account(
            account(revision=3, updated_at=NOW + timedelta(minutes=1)),
            expected_revision=1,
        )
    with pytest.raises(ContextStoreConflictError, match="identity"):
        store.replace_account(
            account(
                revision=2,
                provider="other",
                updated_at=NOW + timedelta(minutes=1),
            ),
            expected_revision=1,
        )




def test_replacement_rejects_mapping_changes_and_timestamp_regression(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    store.register_account(account())
    with pytest.raises(ContextStoreConflictError, match="mapping"):
        store.replace_account(
            account(
                revision=2,
                provider_account_id="provider-account-2",
                updated_at=NOW + timedelta(minutes=1),
            ),
            expected_revision=1,
        )
    second = ProviderContextStore(tmp_path / "timestamp.sqlite3")
    second.register_account(account(updated_at=NOW + timedelta(minutes=1)))
    with pytest.raises(ContextStoreConflictError, match="updated_at"):
        second.replace_account(
            account(
                revision=2,
                updated_at=NOW,
            ),
            expected_revision=1,
        )


def test_unknown_provider_mapping_can_be_enriched_once(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    store.register_account(account(provider_account_id=None))
    enriched = account(
        provider_account_id="provider-account-1",
        revision=2,
        updated_at=NOW + timedelta(minutes=1),
    )
    assert store.replace_account(enriched, expected_revision=1) is ContextWriteResult.WRITTEN
    assert store.load_account("acct_main") == enriched


def test_quota_history_is_append_only_and_idempotent(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    store.register_account(account())
    first = quota()
    second = quota(
        snapshot_id="quota_second",
        state=QuotaState.EXHAUSTED,
        observed_at=NOW + timedelta(minutes=1),
    )
    assert store.append_quota(first) is ContextWriteResult.WRITTEN
    assert store.append_quota(first) is ContextWriteResult.DUPLICATE
    assert store.append_quota(second) is ContextWriteResult.WRITTEN
    assert store.list_quota_history("acct_main") == [first, second]
    assert (
        store.load_latest_quota(
            "acct_main",
            dimension=QuotaDimension.WORK_AGENTIC,
        )
        == second
    )


def test_quota_conflicts_and_missing_account_fail_closed(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    with pytest.raises(ContextStoreError, match="registered account"):
        store.append_quota(quota())
    store.register_account(account())
    store.append_quota(quota())
    with pytest.raises(ContextStoreConflictError, match="snapshot_id"):
        store.append_quota(quota(state=QuotaState.EXHAUSTED))
    with pytest.raises(ContextStoreConflictError, match="timestamp"):
        store.append_quota(quota(snapshot_id="quota_same_time", state=QuotaState.EXHAUSTED))


def test_project_registration_and_revision_are_transactional(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    store.register_account(account())
    assert store.register_project(project()) is ContextWriteResult.WRITTEN
    assert store.register_project(project()) is ContextWriteResult.DUPLICATE
    revised = project(
        revision=2,
        display_name="Système Local — principal",
        updated_at=NOW + timedelta(minutes=1),
    )
    assert store.replace_project(revised, expected_revision=1) is ContextWriteResult.WRITTEN
    assert store.load_project("proj_main") == revised
    with pytest.raises(ContextStoreConflictError, match="stale"):
        store.replace_project(
            project(
                revision=2,
                display_name="stale",
                updated_at=NOW + timedelta(minutes=1),
            ),
            expected_revision=1,
        )


def test_project_requires_matching_registered_account(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    with pytest.raises(ContextStoreError, match="registered account"):
        store.register_project(project())
    store.register_account(account())
    with pytest.raises(ContextStoreError, match="account surface"):
        store.register_project(project(project_id="proj_other", surface="other_surface"))


def test_project_provider_mapping_is_unique(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    store.register_account(account())
    store.register_project(project())
    with pytest.raises(ContextStoreConflictError, match="mapping"):
        store.register_project(
            project(project_id="proj_other", display_name="Other")
        )


def test_conversation_requires_project_and_matching_surface(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    store.register_account(account())
    with pytest.raises(ContextStoreError, match="registered project"):
        store.register_conversation(conversation())
    store.register_project(project())
    with pytest.raises(ContextStoreError, match="account surface"):
        store.register_conversation(
            conversation(conversation_id="conv_other", surface="other_surface")
        )


def test_conversation_registration_and_revision(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    store.register_account(account())
    store.register_project(project())
    assert store.register_conversation(conversation()) is ContextWriteResult.WRITTEN
    revised = conversation(
        revision=2,
        state=BindingState.ARCHIVED,
        updated_at=NOW + timedelta(minutes=1),
    )
    assert (
        store.replace_conversation(revised, expected_revision=1)
        is ContextWriteResult.WRITTEN
    )
    assert store.load_conversation("conv_architecture") == revised


def test_existing_conversation_can_move_into_a_newer_project(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    store.register_account(account())
    store.register_conversation(conversation(project_id=None))
    later_project = project(
        created_at=NOW + timedelta(minutes=1),
        updated_at=NOW + timedelta(minutes=1),
    )
    store.register_project(later_project)
    moved = conversation(
        revision=2,
        project_id=later_project.project_id,
        updated_at=NOW + timedelta(minutes=2),
    )
    assert (
        store.replace_conversation(moved, expected_revision=1)
        is ContextWriteResult.WRITTEN
    )
    assert store.load_conversation(moved.conversation_id) == moved


def test_conversation_provider_mapping_is_unique(tmp_path: Path) -> None:
    store = ProviderContextStore(tmp_path / "context.sqlite3")
    store.register_account(account())
    store.register_project(project())
    store.register_conversation(conversation())
    with pytest.raises(ContextStoreConflictError, match="mapping"):
        store.register_conversation(
            conversation(
                conversation_id="conv_other",
                display_name="Other",
            )
        )


def test_store_detects_fingerprint_and_column_corruption(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    store = ProviderContextStore(path)
    store.register_account(account())
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE accounts SET fingerprint = ? WHERE account_id = ?",
            ("0" * 64, "acct_main"),
        )
    with pytest.raises(ContextStoreCorruptError, match="fingerprint"):
        store.load_account("acct_main")

    path2 = tmp_path / "columns.sqlite3"
    store2 = ProviderContextStore(path2)
    store2.register_account(account())
    with sqlite3.connect(path2) as connection:
        connection.execute(
            "UPDATE accounts SET provider = ? WHERE account_id = ?",
            ("other", "acct_main"),
        )
    with pytest.raises(ContextStoreCorruptError, match="columns"):
        store2.load_account("acct_main")




def test_store_rejects_history_head_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    store = ProviderContextStore(path)
    store.register_account(account())
    with sqlite3.connect(path) as connection:
        connection.execute(
            "DELETE FROM account_versions WHERE account_id = ? AND revision = 1",
            ("acct_main",),
        )
    with pytest.raises(ContextStoreCorruptError, match="version history"):
        ProviderContextStore(path)


def test_store_rejects_hidden_future_history_revision(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    store = ProviderContextStore(path)
    store.register_account(account())
    future = account(
        revision=2,
        updated_at=NOW + timedelta(minutes=1),
    )
    payload = future.model_dump_json(exclude_none=False)
    fingerprint = context_fingerprint(payload)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO account_versions(
                account_id, revision, provider, surface, provider_account_id,
                fingerprint, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                future.account_id,
                future.revision,
                future.provider,
                future.surface,
                future.provider_account_id,
                fingerprint,
                payload,
            ),
        )
    with pytest.raises(ContextStoreCorruptError, match="latest recorded revision"):
        ProviderContextStore(path)


def test_store_rejects_orphaned_conversation_project_mapping(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    store = ProviderContextStore(path)
    store.register_account(account())
    store.register_project(project())
    store.register_conversation(conversation())

    orphaned = conversation(project_id="proj_missing")
    payload = orphaned.model_dump_json(exclude_none=False)
    fingerprint = context_fingerprint(payload)
    with sqlite3.connect(path) as connection:
        for table in ("conversations", "conversation_versions"):
            connection.execute(
                f"""
                UPDATE {table}
                SET fingerprint = ?, payload_json = ?
                WHERE conversation_id = ?
                """,
                (fingerprint, payload, orphaned.conversation_id),
            )

    with pytest.raises(ContextStoreCorruptError, match="unknown project"):
        ProviderContextStore(path)


def test_store_rejects_cross_surface_project_history(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    store = ProviderContextStore(path)
    store.register_account(account())
    store.register_project(project())

    corrupted = project(surface="other_surface")
    payload = corrupted.model_dump_json(exclude_none=False)
    fingerprint = context_fingerprint(payload)
    with sqlite3.connect(path) as connection:
        for table in ("projects", "project_versions"):
            connection.execute(
                f"""
                UPDATE {table}
                SET surface = ?, fingerprint = ?, payload_json = ?
                WHERE project_id = ?
                """,
                (
                    corrupted.surface,
                    fingerprint,
                    payload,
                    corrupted.project_id,
                ),
            )

    with pytest.raises(ContextStoreCorruptError, match="account surface"):
        ProviderContextStore(path)


def test_store_rejects_unsupported_schema_version(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    ProviderContextStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE metadata SET value = '999' WHERE key = 'schema_version'"
        )
    with pytest.raises(UnsupportedContextSchemaVersion):
        ProviderContextStore(path)


def test_store_rejects_schema_drift(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    ProviderContextStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute("ALTER TABLE accounts ADD COLUMN unexpected TEXT")
    with pytest.raises(ContextStoreCorruptError, match="schema"):
        ProviderContextStore(path)


def test_store_rejects_non_regular_path(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"")
    link = tmp_path / "link.sqlite3"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ContextStoreError, match="regular file"):
        ProviderContextStore(link)


def test_store_rejects_noncontiguous_history(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    store = ProviderContextStore(path)
    store.register_account(account())
    store.replace_account(
        account(revision=2, updated_at=NOW + timedelta(minutes=1)),
        expected_revision=1,
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "DELETE FROM account_versions WHERE account_id = ? AND revision = 1",
            ("acct_main",),
        )
    with pytest.raises(ContextStoreCorruptError, match="not contiguous"):
        ProviderContextStore(path)


def test_store_rejects_extra_application_table(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    ProviderContextStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE unexpected_table(value TEXT)")
    with pytest.raises(ContextStoreCorruptError, match="table set"):
        ProviderContextStore(path)


def test_store_rejects_missing_security_index(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    ProviderContextStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP INDEX accounts_provider_mapping_unique")
    with pytest.raises(ContextStoreCorruptError, match="index"):
        ProviderContextStore(path)


def test_store_rejects_wrong_security_index_predicate(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    ProviderContextStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP INDEX accounts_provider_mapping_unique")
        connection.execute(
            """
            CREATE UNIQUE INDEX accounts_provider_mapping_unique
            ON accounts(provider, surface, provider_account_id)
            WHERE provider_account_id IS NULL
            """
        )
    with pytest.raises(ContextStoreCorruptError, match="predicate"):
        ProviderContextStore(path)


def test_store_rejects_extra_metadata_rows(tmp_path: Path) -> None:
    path = tmp_path / "context.sqlite3"
    ProviderContextStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES ('unexpected', 'value')"
        )
    with pytest.raises(ContextStoreCorruptError, match="only schema_version"):
        ProviderContextStore(path)
