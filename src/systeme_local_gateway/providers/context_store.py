from __future__ import annotations

import sqlite3
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, TypeVar

from .context_models import (
    ProviderAccountProfile,
    ProviderConversationBinding,
    ProviderProjectBinding,
    ProviderQuotaSnapshot,
    QuotaDimension,
)

_SCHEMA_VERSION = "1"
_ModelT = TypeVar("_ModelT")


class ContextStoreError(RuntimeError):
    pass


class ContextStoreConflictError(ContextStoreError):
    pass


class ContextStoreCorruptError(ContextStoreError):
    pass


class UnsupportedContextSchemaVersion(ContextStoreError):
    pass


class ContextWriteResult(StrEnum):
    WRITTEN = "written"
    DUPLICATE = "duplicate"


class ProviderContextStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.exists() and (self.path.is_symlink() or not self.path.is_file()):
            raise ContextStoreError("context store path must be a regular file")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def register_account(self, profile: ProviderAccountProfile) -> ContextWriteResult:
        if profile.revision != 1:
            raise ContextStoreConflictError("new accounts must start at revision 1")
        with self._connect() as connection:
            self._begin(connection)
            try:
                existing = self._select_account(connection, profile.account_id)
                if existing is not None:
                    stored = self._account_from_row(existing)
                    if stored == profile:
                        connection.execute("COMMIT")
                        return ContextWriteResult.DUPLICATE
                    raise ContextStoreConflictError("account_id is already registered")
                self._ensure_account_mapping_available(connection, profile)
                payload, fingerprint = _serialized(profile)
                self._insert_account_history(connection, profile, payload, fingerprint)
                connection.execute(
                    """
                    INSERT INTO accounts(
                        account_id, revision, provider, surface, provider_account_id,
                        fingerprint, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        profile.account_id,
                        profile.revision,
                        profile.provider,
                        profile.surface,
                        profile.provider_account_id,
                        fingerprint,
                        payload,
                    ),
                )
                connection.execute("COMMIT")
                return ContextWriteResult.WRITTEN
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def replace_account(
        self,
        profile: ProviderAccountProfile,
        *,
        expected_revision: int,
    ) -> ContextWriteResult:
        with self._connect() as connection:
            self._begin(connection)
            try:
                row = self._select_account(connection, profile.account_id)
                if row is None:
                    raise KeyError(profile.account_id)
                current = self._account_from_row(row)
                if current == profile:
                    connection.execute("COMMIT")
                    return ContextWriteResult.DUPLICATE
                self._validate_replacement(
                    current_revision=current.revision,
                    expected_revision=expected_revision,
                    new_revision=profile.revision,
                    created_at_matches=current.created_at == profile.created_at,
                    identity_matches=(
                        current.provider == profile.provider
                        and current.surface == profile.surface
                    ),
                    updated_at_not_backwards=profile.updated_at >= current.updated_at,
                    provider_mapping_compatible=(
                        current.provider_account_id is None
                        or current.provider_account_id == profile.provider_account_id
                    ),
                    model_name="account",
                )
                self._ensure_account_mapping_available(connection, profile)
                payload, fingerprint = _serialized(profile)
                self._insert_account_history(connection, profile, payload, fingerprint)
                cursor = connection.execute(
                    """
                    UPDATE accounts
                    SET revision = ?, provider = ?, surface = ?, provider_account_id = ?,
                        fingerprint = ?, payload_json = ?
                    WHERE account_id = ? AND revision = ?
                    """,
                    (
                        profile.revision,
                        profile.provider,
                        profile.surface,
                        profile.provider_account_id,
                        fingerprint,
                        payload,
                        profile.account_id,
                        expected_revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ContextStoreConflictError("stale account revision")
                connection.execute("COMMIT")
                return ContextWriteResult.WRITTEN
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def append_quota(self, snapshot: ProviderQuotaSnapshot) -> ContextWriteResult:
        payload, fingerprint = _serialized(snapshot)
        with self._connect() as connection:
            self._begin(connection)
            try:
                account_row = self._select_account(connection, snapshot.account_id)
                if account_row is None:
                    raise ContextStoreError("quota snapshot requires a registered account")
                account = self._account_from_row(account_row)
                if snapshot.observed_at < account.created_at:
                    raise ContextStoreError("quota snapshot cannot precede the account")
                existing = connection.execute(
                    """
                    SELECT snapshot_id, account_id, dimension, observed_at,
                           fingerprint, payload_json
                    FROM quota_snapshots
                    WHERE snapshot_id = ?
                    """,
                    (snapshot.snapshot_id,),
                ).fetchone()
                if existing is not None:
                    stored = self._quota_from_row(existing)
                    if stored == snapshot:
                        connection.execute("COMMIT")
                        return ContextWriteResult.DUPLICATE
                    raise ContextStoreConflictError("snapshot_id is already registered")
                same_observation = connection.execute(
                    """
                    SELECT snapshot_id
                    FROM quota_snapshots
                    WHERE account_id = ? AND dimension = ? AND observed_at = ?
                    """,
                    (
                        snapshot.account_id,
                        snapshot.dimension.value,
                        snapshot.observed_at.isoformat(),
                    ),
                ).fetchone()
                if same_observation is not None:
                    raise ContextStoreConflictError(
                        "quota dimension already has an observation at this timestamp"
                    )
                connection.execute(
                    """
                    INSERT INTO quota_snapshots(
                        snapshot_id, account_id, dimension, observed_at,
                        fingerprint, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot.snapshot_id,
                        snapshot.account_id,
                        snapshot.dimension.value,
                        snapshot.observed_at.isoformat(),
                        fingerprint,
                        payload,
                    ),
                )
                connection.execute("COMMIT")
                return ContextWriteResult.WRITTEN
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def register_project(self, binding: ProviderProjectBinding) -> ContextWriteResult:
        if binding.revision != 1:
            raise ContextStoreConflictError("new projects must start at revision 1")
        return self._register_binding(
            binding=binding,
            table="projects",
            history_table="project_versions",
            id_column="project_id",
            provider_id_column="provider_project_id",
            select=self._select_project,
            parse=self._project_from_row,
        )

    def replace_project(
        self,
        binding: ProviderProjectBinding,
        *,
        expected_revision: int,
    ) -> ContextWriteResult:
        return self._replace_binding(
            binding=binding,
            expected_revision=expected_revision,
            table="projects",
            history_table="project_versions",
            id_column="project_id",
            provider_id_column="provider_project_id",
            select=self._select_project,
            parse=self._project_from_row,
            model_name="project",
        )

    def register_conversation(
        self,
        binding: ProviderConversationBinding,
    ) -> ContextWriteResult:
        if binding.revision != 1:
            raise ContextStoreConflictError("new conversations must start at revision 1")
        return self._register_binding(
            binding=binding,
            table="conversations",
            history_table="conversation_versions",
            id_column="conversation_id",
            provider_id_column="provider_conversation_id",
            select=self._select_conversation,
            parse=self._conversation_from_row,
        )

    def replace_conversation(
        self,
        binding: ProviderConversationBinding,
        *,
        expected_revision: int,
    ) -> ContextWriteResult:
        return self._replace_binding(
            binding=binding,
            expected_revision=expected_revision,
            table="conversations",
            history_table="conversation_versions",
            id_column="conversation_id",
            provider_id_column="provider_conversation_id",
            select=self._select_conversation,
            parse=self._conversation_from_row,
            model_name="conversation",
        )

    def load_account(self, account_id: str) -> ProviderAccountProfile:
        with self._connect() as connection:
            row = self._select_account(connection, account_id)
        if row is None:
            raise KeyError(account_id)
        return self._account_from_row(row)

    def load_project(self, project_id: str) -> ProviderProjectBinding:
        with self._connect() as connection:
            row = self._select_project(connection, project_id)
        if row is None:
            raise KeyError(project_id)
        return self._project_from_row(row)

    def load_conversation(self, conversation_id: str) -> ProviderConversationBinding:
        with self._connect() as connection:
            row = self._select_conversation(connection, conversation_id)
        if row is None:
            raise KeyError(conversation_id)
        return self._conversation_from_row(row)

    def load_latest_quota(
        self,
        account_id: str,
        *,
        dimension: QuotaDimension,
    ) -> ProviderQuotaSnapshot:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT snapshot_id, account_id, dimension, observed_at,
                       fingerprint, payload_json
                FROM quota_snapshots
                WHERE account_id = ? AND dimension = ?
                ORDER BY observed_at DESC, snapshot_id DESC
                LIMIT 1
                """,
                (account_id, dimension.value),
            ).fetchone()
        if row is None:
            raise KeyError((account_id, dimension))
        return self._quota_from_row(row)

    def list_quota_history(
        self,
        account_id: str,
        *,
        dimension: QuotaDimension | None = None,
    ) -> list[ProviderQuotaSnapshot]:
        with self._connect() as connection:
            if dimension is None:
                rows = connection.execute(
                    """
                    SELECT snapshot_id, account_id, dimension, observed_at,
                           fingerprint, payload_json
                    FROM quota_snapshots
                    WHERE account_id = ?
                    ORDER BY observed_at, snapshot_id
                    """,
                    (account_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT snapshot_id, account_id, dimension, observed_at,
                           fingerprint, payload_json
                    FROM quota_snapshots
                    WHERE account_id = ? AND dimension = ?
                    ORDER BY observed_at, snapshot_id
                    """,
                    (account_id, dimension.value),
                ).fetchall()
        return [self._quota_from_row(row) for row in rows]

    def _register_binding(
        self,
        *,
        binding: ProviderProjectBinding | ProviderConversationBinding,
        table: str,
        history_table: str,
        id_column: str,
        provider_id_column: str,
        select: Callable[[sqlite3.Connection, str], sqlite3.Row | None],
        parse: Callable[[sqlite3.Row], Any],
    ) -> ContextWriteResult:
        binding_id = str(getattr(binding, id_column))
        with self._connect() as connection:
            self._begin(connection)
            try:
                self._validate_binding_dependencies(connection, binding)
                existing = select(connection, binding_id)
                if existing is not None:
                    stored = parse(existing)
                    if stored == binding:
                        connection.execute("COMMIT")
                        return ContextWriteResult.DUPLICATE
                    raise ContextStoreConflictError(f"{id_column} is already registered")
                self._ensure_binding_mapping_available(
                    connection,
                    table=table,
                    id_column=id_column,
                    provider_id_column=provider_id_column,
                    binding=binding,
                )
                payload, fingerprint = _serialized(binding)
                self._insert_binding_history(
                    connection,
                    history_table=history_table,
                    id_column=id_column,
                    binding=binding,
                    payload=payload,
                    fingerprint=fingerprint,
                )
                connection.execute(
                    f"""
                    INSERT INTO {table}(
                        {id_column}, revision, account_id, provider, surface,
                        {provider_id_column}, fingerprint, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,  # noqa: S608 - table and column names are internal constants
                    (
                        binding_id,
                        binding.revision,
                        binding.account_id,
                        binding.provider,
                        binding.surface,
                        getattr(binding, provider_id_column),
                        fingerprint,
                        payload,
                    ),
                )
                connection.execute("COMMIT")
                return ContextWriteResult.WRITTEN
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def _replace_binding(
        self,
        *,
        binding: ProviderProjectBinding | ProviderConversationBinding,
        expected_revision: int,
        table: str,
        history_table: str,
        id_column: str,
        provider_id_column: str,
        select: Callable[[sqlite3.Connection, str], sqlite3.Row | None],
        parse: Callable[[sqlite3.Row], Any],
        model_name: str,
    ) -> ContextWriteResult:
        binding_id = str(getattr(binding, id_column))
        with self._connect() as connection:
            self._begin(connection)
            try:
                self._validate_binding_dependencies(connection, binding)
                row = select(connection, binding_id)
                if row is None:
                    raise KeyError(binding_id)
                current = parse(row)
                if current == binding:
                    connection.execute("COMMIT")
                    return ContextWriteResult.DUPLICATE
                self._validate_replacement(
                    current_revision=current.revision,
                    expected_revision=expected_revision,
                    new_revision=binding.revision,
                    created_at_matches=current.created_at == binding.created_at,
                    identity_matches=(
                        current.account_id == binding.account_id
                        and current.provider == binding.provider
                        and current.surface == binding.surface
                    ),
                    updated_at_not_backwards=binding.updated_at >= current.updated_at,
                    provider_mapping_compatible=(
                        getattr(current, provider_id_column) is None
                        or getattr(current, provider_id_column)
                        == getattr(binding, provider_id_column)
                    ),
                    model_name=model_name,
                )
                self._ensure_binding_mapping_available(
                    connection,
                    table=table,
                    id_column=id_column,
                    provider_id_column=provider_id_column,
                    binding=binding,
                )
                payload, fingerprint = _serialized(binding)
                self._insert_binding_history(
                    connection,
                    history_table=history_table,
                    id_column=id_column,
                    binding=binding,
                    payload=payload,
                    fingerprint=fingerprint,
                )
                cursor = connection.execute(
                    f"""
                    UPDATE {table}
                    SET revision = ?, account_id = ?, provider = ?, surface = ?,
                        {provider_id_column} = ?, fingerprint = ?, payload_json = ?
                    WHERE {id_column} = ? AND revision = ?
                    """,  # noqa: S608 - table and column names are internal constants
                    (
                        binding.revision,
                        binding.account_id,
                        binding.provider,
                        binding.surface,
                        getattr(binding, provider_id_column),
                        fingerprint,
                        payload,
                        binding_id,
                        expected_revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ContextStoreConflictError(f"stale {model_name} revision")
                connection.execute("COMMIT")
                return ContextWriteResult.WRITTEN
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def _validate_binding_dependencies(
        self,
        connection: sqlite3.Connection,
        binding: ProviderProjectBinding | ProviderConversationBinding,
    ) -> None:
        account_row = self._select_account(connection, binding.account_id)
        if account_row is None:
            raise ContextStoreError("binding requires a registered account")
        account = self._account_from_row(account_row)
        if account.provider != binding.provider or account.surface != binding.surface:
            raise ContextStoreError("binding does not match its account surface")
        if isinstance(binding, ProviderConversationBinding) and binding.project_id is not None:
            project_row = self._select_project(connection, binding.project_id)
            if project_row is None:
                raise ContextStoreError("conversation requires a registered project")
            project = self._project_from_row(project_row)
            if (
                project.account_id != binding.account_id
                or project.provider != binding.provider
                or project.surface != binding.surface
            ):
                raise ContextStoreError("conversation does not match its project")
        if binding.created_at < account.created_at:
            raise ContextStoreError("binding cannot precede its account")

    @staticmethod
    def _validate_replacement(
        *,
        current_revision: int,
        expected_revision: int,
        new_revision: int,
        created_at_matches: bool,
        identity_matches: bool,
        updated_at_not_backwards: bool,
        provider_mapping_compatible: bool,
        model_name: str,
    ) -> None:
        if current_revision != expected_revision:
            raise ContextStoreConflictError(f"stale {model_name} revision")
        if new_revision != expected_revision + 1:
            raise ContextStoreConflictError(f"{model_name} revision must advance by one")
        if not created_at_matches:
            raise ContextStoreConflictError(f"{model_name} created_at is immutable")
        if not identity_matches:
            raise ContextStoreConflictError(f"{model_name} identity is immutable")
        if not updated_at_not_backwards:
            raise ContextStoreConflictError(f"{model_name} updated_at cannot move backwards")
        if not provider_mapping_compatible:
            raise ContextStoreConflictError(
                f"{model_name} provider mapping cannot be replaced or cleared"
            )

    @staticmethod
    def _ensure_account_mapping_available(
        connection: sqlite3.Connection,
        profile: ProviderAccountProfile,
    ) -> None:
        if profile.provider_account_id is None:
            return
        row = connection.execute(
            """
            SELECT account_id
            FROM accounts
            WHERE provider = ? AND surface = ? AND provider_account_id = ?
              AND account_id <> ?
            """,
            (
                profile.provider,
                profile.surface,
                profile.provider_account_id,
                profile.account_id,
            ),
        ).fetchone()
        if row is not None:
            raise ContextStoreConflictError("provider account mapping is already registered")

    @staticmethod
    def _ensure_binding_mapping_available(
        connection: sqlite3.Connection,
        *,
        table: str,
        id_column: str,
        provider_id_column: str,
        binding: ProviderProjectBinding | ProviderConversationBinding,
    ) -> None:
        provider_id = getattr(binding, provider_id_column)
        if provider_id is None:
            return
        binding_id = getattr(binding, id_column)
        row = connection.execute(
            f"""
            SELECT {id_column}
            FROM {table}
            WHERE provider = ? AND surface = ? AND {provider_id_column} = ?
              AND {id_column} <> ?
            """,  # noqa: S608 - table and column names are internal constants
            (binding.provider, binding.surface, provider_id, binding_id),
        ).fetchone()
        if row is not None:
            raise ContextStoreConflictError("provider binding mapping is already registered")

    @staticmethod
    def _insert_account_history(
        connection: sqlite3.Connection,
        profile: ProviderAccountProfile,
        payload: str,
        fingerprint: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO account_versions(
                account_id, revision, provider, surface, provider_account_id,
                fingerprint, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                profile.account_id,
                profile.revision,
                profile.provider,
                profile.surface,
                profile.provider_account_id,
                fingerprint,
                payload,
            ),
        )

    @staticmethod
    def _insert_binding_history(
        connection: sqlite3.Connection,
        *,
        history_table: str,
        id_column: str,
        binding: ProviderProjectBinding | ProviderConversationBinding,
        payload: str,
        fingerprint: str,
    ) -> None:
        provider_id_column = (
            "provider_project_id"
            if isinstance(binding, ProviderProjectBinding)
            else "provider_conversation_id"
        )
        connection.execute(
            f"""
            INSERT INTO {history_table}(
                {id_column}, revision, account_id, provider, surface,
                {provider_id_column}, fingerprint, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,  # noqa: S608 - table and column names are internal constants
            (
                getattr(binding, id_column),
                binding.revision,
                binding.account_id,
                binding.provider,
                binding.surface,
                getattr(binding, provider_id_column),
                fingerprint,
                payload,
            ),
        )

    @staticmethod
    def _select_account(
        connection: sqlite3.Connection,
        account_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT account_id, revision, provider, surface, provider_account_id,
                   fingerprint, payload_json
            FROM accounts
            WHERE account_id = ?
            """,
            (account_id,),
        ).fetchone()

    @staticmethod
    def _select_project(
        connection: sqlite3.Connection,
        project_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT project_id, revision, account_id, provider, surface,
                   provider_project_id, fingerprint, payload_json
            FROM projects
            WHERE project_id = ?
            """,
            (project_id,),
        ).fetchone()

    @staticmethod
    def _select_conversation(
        connection: sqlite3.Connection,
        conversation_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT conversation_id, revision, account_id, provider, surface,
                   provider_conversation_id, fingerprint, payload_json
            FROM conversations
            WHERE conversation_id = ?
            """,
            (conversation_id,),
        ).fetchone()

    @staticmethod
    def _account_from_row(row: sqlite3.Row) -> ProviderAccountProfile:
        model = _validated_payload(
            row=row,
            model_name="account",
            validator=ProviderAccountProfile.model_validate_json,
        )
        if (
            model.account_id != row["account_id"]
            or model.revision != row["revision"]
            or model.provider != row["provider"]
            or model.surface != row["surface"]
            or model.provider_account_id != row["provider_account_id"]
        ):
            raise ContextStoreCorruptError("account columns do not match its payload")
        return model

    @staticmethod
    def _quota_from_row(row: sqlite3.Row) -> ProviderQuotaSnapshot:
        model = _validated_payload(
            row=row,
            model_name="quota snapshot",
            validator=ProviderQuotaSnapshot.model_validate_json,
        )
        if (
            model.snapshot_id != row["snapshot_id"]
            or model.account_id != row["account_id"]
            or model.dimension.value != row["dimension"]
            or model.observed_at.isoformat() != row["observed_at"]
        ):
            raise ContextStoreCorruptError("quota columns do not match its payload")
        return model

    @staticmethod
    def _project_from_row(row: sqlite3.Row) -> ProviderProjectBinding:
        model = _validated_payload(
            row=row,
            model_name="project",
            validator=ProviderProjectBinding.model_validate_json,
        )
        if (
            model.project_id != row["project_id"]
            or model.revision != row["revision"]
            or model.account_id != row["account_id"]
            or model.provider != row["provider"]
            or model.surface != row["surface"]
            or model.provider_project_id != row["provider_project_id"]
        ):
            raise ContextStoreCorruptError("project columns do not match its payload")
        return model

    @staticmethod
    def _conversation_from_row(row: sqlite3.Row) -> ProviderConversationBinding:
        model = _validated_payload(
            row=row,
            model_name="conversation",
            validator=ProviderConversationBinding.model_validate_json,
        )
        if (
            model.conversation_id != row["conversation_id"]
            or model.revision != row["revision"]
            or model.account_id != row["account_id"]
            or model.provider != row["provider"]
            or model.surface != row["surface"]
            or model.provider_conversation_id != row["provider_conversation_id"]
        ):
            raise ContextStoreCorruptError("conversation columns do not match its payload")
        return model

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                result = connection.execute("PRAGMA quick_check").fetchone()
                if result is None or result[0] != "ok":
                    raise ContextStoreCorruptError("SQLite quick_check failed")
                self._begin(connection)
                try:
                    existing_tables = self._application_tables(connection)
                    if existing_tables:
                        if "metadata" not in existing_tables:
                            raise ContextStoreCorruptError(
                                "existing context store has no metadata table"
                            )
                        metadata_columns = {
                            str(row["name"])
                            for row in connection.execute(
                                "PRAGMA table_info(metadata)"
                            ).fetchall()
                        }
                        if metadata_columns != {"key", "value"}:
                            raise ContextStoreCorruptError(
                                "unexpected provider context schema for metadata"
                            )
                        schema_version = self._read_schema_version(connection)
                        if schema_version != _SCHEMA_VERSION:
                            raise UnsupportedContextSchemaVersion(
                                "unsupported provider context schema version: "
                                f"{schema_version}"
                            )
                    else:
                        connection.execute(
                            "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                        )
                        connection.execute(
                            "INSERT INTO metadata(key, value) VALUES ('schema_version', ?)",
                            (_SCHEMA_VERSION,),
                        )
                        self._create_schema(connection)

                    self._verify_schema(connection)
                    self._verify_indexes(connection)
                    self._verify_semantic_integrity(connection)
                    foreign_key_problem = connection.execute(
                        "PRAGMA foreign_key_check"
                    ).fetchone()
                    if foreign_key_problem is not None:
                        raise ContextStoreCorruptError("SQLite foreign key check failed")
                    connection.execute("COMMIT")
                except Exception:
                    connection.execute("ROLLBACK")
                    raise
        except (UnsupportedContextSchemaVersion, ContextStoreCorruptError):
            raise
        except sqlite3.DatabaseError as exc:
            raise ContextStoreCorruptError("invalid or corrupt provider context store") from exc

    @staticmethod
    def _application_tables(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
        return {str(row["name"]) for row in rows}

    @staticmethod
    def _read_schema_version(connection: sqlite3.Connection) -> str:
        rows = connection.execute(
            "SELECT key, value FROM metadata ORDER BY key"
        ).fetchall()
        if len(rows) != 1 or rows[0]["key"] != "schema_version":
            raise ContextStoreCorruptError(
                "provider context metadata must contain only schema_version"
            )
        return str(rows[0]["value"])

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        statements = (
            """
            CREATE TABLE IF NOT EXISTS accounts(
                account_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL CHECK(revision >= 1),
                provider TEXT NOT NULL,
                surface TEXT NOT NULL,
                provider_account_id TEXT,
                fingerprint TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS accounts_provider_mapping_unique
            ON accounts(provider, surface, provider_account_id)
            WHERE provider_account_id IS NOT NULL
            """,
            """
            CREATE TABLE IF NOT EXISTS account_versions(
                account_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision >= 1),
                provider TEXT NOT NULL,
                surface TEXT NOT NULL,
                provider_account_id TEXT,
                fingerprint TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY(account_id, revision)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS quota_snapshots(
                snapshot_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                dimension TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                UNIQUE(account_id, dimension, observed_at),
                FOREIGN KEY(account_id) REFERENCES accounts(account_id) ON DELETE RESTRICT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS projects(
                project_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL CHECK(revision >= 1),
                account_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                surface TEXT NOT NULL,
                provider_project_id TEXT,
                fingerprint TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                FOREIGN KEY(account_id) REFERENCES accounts(account_id) ON DELETE RESTRICT
            )
            """,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS projects_provider_mapping_unique
            ON projects(provider, surface, provider_project_id)
            WHERE provider_project_id IS NOT NULL
            """,
            """
            CREATE TABLE IF NOT EXISTS project_versions(
                project_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision >= 1),
                account_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                surface TEXT NOT NULL,
                provider_project_id TEXT,
                fingerprint TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY(project_id, revision),
                FOREIGN KEY(account_id) REFERENCES accounts(account_id) ON DELETE RESTRICT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS conversations(
                conversation_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL CHECK(revision >= 1),
                account_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                surface TEXT NOT NULL,
                provider_conversation_id TEXT,
                fingerprint TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                FOREIGN KEY(account_id) REFERENCES accounts(account_id) ON DELETE RESTRICT
            )
            """,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS conversations_provider_mapping_unique
            ON conversations(provider, surface, provider_conversation_id)
            WHERE provider_conversation_id IS NOT NULL
            """,
            """
            CREATE TABLE IF NOT EXISTS conversation_versions(
                conversation_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision >= 1),
                account_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                surface TEXT NOT NULL,
                provider_conversation_id TEXT,
                fingerprint TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY(conversation_id, revision),
                FOREIGN KEY(account_id) REFERENCES accounts(account_id) ON DELETE RESTRICT
            )
            """,
        )
        for statement in statements:
            connection.execute(statement)

    @classmethod
    def _verify_semantic_integrity(cls, connection: sqlite3.Connection) -> None:
        account_history_rows = connection.execute(
            """
            SELECT account_id, revision, provider, surface, provider_account_id,
                   fingerprint, payload_json
            FROM account_versions
            ORDER BY account_id, revision
            """
        ).fetchall()
        project_history_rows = connection.execute(
            """
            SELECT project_id, revision, account_id, provider, surface,
                   provider_project_id, fingerprint, payload_json
            FROM project_versions
            ORDER BY project_id, revision
            """
        ).fetchall()
        conversation_history_rows = connection.execute(
            """
            SELECT conversation_id, revision, account_id, provider, surface,
                   provider_conversation_id, fingerprint, payload_json
            FROM conversation_versions
            ORDER BY conversation_id, revision
            """
        ).fetchall()

        account_history = cls._verify_history_rows(
            account_history_rows,
            id_column="account_id",
            model_name="account",
            parse=cls._account_from_row,
        )
        project_history = cls._verify_history_rows(
            project_history_rows,
            id_column="project_id",
            model_name="project",
            parse=cls._project_from_row,
        )
        conversation_history = cls._verify_history_rows(
            conversation_history_rows,
            id_column="conversation_id",
            model_name="conversation",
            parse=cls._conversation_from_row,
        )

        accounts: dict[str, ProviderAccountProfile] = {}
        account_rows = connection.execute(
            """
            SELECT account_id, revision, provider, surface, provider_account_id,
                   fingerprint, payload_json
            FROM accounts
            """
        ).fetchall()
        for row in account_rows:
            current = cls._account_from_row(row)
            accounts[current.account_id] = current
            if account_history.get(current.account_id) != current.revision:
                raise ContextStoreCorruptError(
                    "account head is not the latest recorded revision in version history"
                )
            history = connection.execute(
                """
                SELECT account_id, revision, provider, surface, provider_account_id,
                       fingerprint, payload_json
                FROM account_versions
                WHERE account_id = ? AND revision = ?
                """,
                (current.account_id, current.revision),
            ).fetchone()
            if history is None or cls._account_from_row(history) != current:
                raise ContextStoreCorruptError(
                    "account head does not match its version history"
                )
        if set(account_history) != set(accounts):
            raise ContextStoreCorruptError("account history has no matching current head")

        projects: dict[str, ProviderProjectBinding] = {}
        project_rows = connection.execute(
            """
            SELECT project_id, revision, account_id, provider, surface,
                   provider_project_id, fingerprint, payload_json
            FROM projects
            """
        ).fetchall()
        for row in project_rows:
            current = cls._project_from_row(row)
            projects[current.project_id] = current
            if project_history.get(current.project_id) != current.revision:
                raise ContextStoreCorruptError(
                    "project head is not the latest recorded revision in version history"
                )
            history = connection.execute(
                """
                SELECT project_id, revision, account_id, provider, surface,
                       provider_project_id, fingerprint, payload_json
                FROM project_versions
                WHERE project_id = ? AND revision = ?
                """,
                (current.project_id, current.revision),
            ).fetchone()
            if history is None or cls._project_from_row(history) != current:
                raise ContextStoreCorruptError(
                    "project head does not match its version history"
                )
        if set(project_history) != set(projects):
            raise ContextStoreCorruptError("project history has no matching current head")

        current_conversation_ids: set[str] = set()
        conversation_rows = connection.execute(
            """
            SELECT conversation_id, revision, account_id, provider, surface,
                   provider_conversation_id, fingerprint, payload_json
            FROM conversations
            """
        ).fetchall()
        for row in conversation_rows:
            current = cls._conversation_from_row(row)
            current_conversation_ids.add(current.conversation_id)
            if conversation_history.get(current.conversation_id) != current.revision:
                raise ContextStoreCorruptError(
                    "conversation head is not the latest recorded revision in version history"
                )
            history = connection.execute(
                """
                SELECT conversation_id, revision, account_id, provider, surface,
                       provider_conversation_id, fingerprint, payload_json
                FROM conversation_versions
                WHERE conversation_id = ? AND revision = ?
                """,
                (current.conversation_id, current.revision),
            ).fetchone()
            if history is None or cls._conversation_from_row(history) != current:
                raise ContextStoreCorruptError(
                    "conversation head does not match its version history"
                )
        if set(conversation_history) != current_conversation_ids:
            raise ContextStoreCorruptError(
                "conversation history has no matching current head"
            )

        for row in project_history_rows:
            cls._validate_project_semantics(
                cls._project_from_row(row),
                accounts=accounts,
            )

        for row in conversation_history_rows:
            cls._validate_conversation_semantics(
                cls._conversation_from_row(row),
                accounts=accounts,
                projects=projects,
            )

        quota_rows = connection.execute(
            """
            SELECT snapshot_id, account_id, dimension, observed_at,
                   fingerprint, payload_json
            FROM quota_snapshots
            """
        ).fetchall()
        for row in quota_rows:
            cls._validate_quota_semantics(
                cls._quota_from_row(row),
                accounts=accounts,
            )

    @staticmethod
    def _validate_project_semantics(
        project: ProviderProjectBinding,
        *,
        accounts: dict[str, ProviderAccountProfile],
    ) -> None:
        account = accounts.get(project.account_id)
        if account is None:
            raise ContextStoreCorruptError(
                "project references an unknown account"
            )
        if (
            project.provider != account.provider
            or project.surface != account.surface
        ):
            raise ContextStoreCorruptError(
                "project does not match its account surface"
            )
        if project.created_at < account.created_at:
            raise ContextStoreCorruptError(
                "project predates its account"
            )

    @staticmethod
    def _validate_conversation_semantics(
        conversation: ProviderConversationBinding,
        *,
        accounts: dict[str, ProviderAccountProfile],
        projects: dict[str, ProviderProjectBinding],
    ) -> None:
        account = accounts.get(conversation.account_id)
        if account is None:
            raise ContextStoreCorruptError(
                "conversation references an unknown account"
            )
        if (
            conversation.provider != account.provider
            or conversation.surface != account.surface
        ):
            raise ContextStoreCorruptError(
                "conversation does not match its account surface"
            )
        if conversation.created_at < account.created_at:
            raise ContextStoreCorruptError(
                "conversation predates its account"
            )
        if conversation.project_id is None:
            return
        project = projects.get(conversation.project_id)
        if project is None:
            raise ContextStoreCorruptError(
                "conversation references an unknown project"
            )
        if (
            project.account_id != conversation.account_id
            or project.provider != conversation.provider
            or project.surface != conversation.surface
        ):
            raise ContextStoreCorruptError(
                "conversation does not match its project"
            )

    @staticmethod
    def _validate_quota_semantics(
        snapshot: ProviderQuotaSnapshot,
        *,
        accounts: dict[str, ProviderAccountProfile],
    ) -> None:
        account = accounts.get(snapshot.account_id)
        if account is None:
            raise ContextStoreCorruptError(
                "quota snapshot references an unknown account"
            )
        if snapshot.observed_at < account.created_at:
            raise ContextStoreCorruptError(
                "quota snapshot predates its account"
            )

    @staticmethod
    def _verify_history_rows(
        rows: list[sqlite3.Row],
        *,
        id_column: str,
        model_name: str,
        parse: Callable[[sqlite3.Row], Any],
    ) -> dict[str, int]:
        latest: dict[str, int] = {}
        for row in rows:
            model = parse(row)
            model_id = str(row[id_column])
            revision = int(row["revision"])
            if getattr(model, id_column) != model_id or model.revision != revision:
                raise ContextStoreCorruptError(
                    f"{model_name} history columns do not match its payload"
                )
            expected_revision = latest.get(model_id, 0) + 1
            if revision != expected_revision:
                raise ContextStoreCorruptError(
                    f"{model_name} version history is not contiguous"
                )
            latest[model_id] = revision
        return latest

    @staticmethod
    def _expected_schema() -> dict[str, set[str]]:
        return {
            "metadata": {"key", "value"},
            "accounts": {
                "account_id",
                "revision",
                "provider",
                "surface",
                "provider_account_id",
                "fingerprint",
                "payload_json",
            },
            "account_versions": {
                "account_id",
                "revision",
                "provider",
                "surface",
                "provider_account_id",
                "fingerprint",
                "payload_json",
            },
            "quota_snapshots": {
                "snapshot_id",
                "account_id",
                "dimension",
                "observed_at",
                "fingerprint",
                "payload_json",
            },
            "projects": {
                "project_id",
                "revision",
                "account_id",
                "provider",
                "surface",
                "provider_project_id",
                "fingerprint",
                "payload_json",
            },
            "project_versions": {
                "project_id",
                "revision",
                "account_id",
                "provider",
                "surface",
                "provider_project_id",
                "fingerprint",
                "payload_json",
            },
            "conversations": {
                "conversation_id",
                "revision",
                "account_id",
                "provider",
                "surface",
                "provider_conversation_id",
                "fingerprint",
                "payload_json",
            },
            "conversation_versions": {
                "conversation_id",
                "revision",
                "account_id",
                "provider",
                "surface",
                "provider_conversation_id",
                "fingerprint",
                "payload_json",
            },
        }

    @classmethod
    def _verify_schema(cls, connection: sqlite3.Connection) -> None:
        expected = cls._expected_schema()
        actual_tables = cls._application_tables(connection)
        if actual_tables != set(expected):
            raise ContextStoreCorruptError(
                "unexpected provider context table set"
            )
        for table, columns in expected.items():
            rows = connection.execute(
                f"PRAGMA table_info({table})"  # noqa: S608 - internal table names
            ).fetchall()
            actual = {str(row["name"]) for row in rows}
            if actual != columns:
                raise ContextStoreCorruptError(
                    f"unexpected provider context schema for {table}"
                )
        if cls._read_schema_version(connection) != _SCHEMA_VERSION:
            raise UnsupportedContextSchemaVersion(
                "unsupported provider context schema version"
            )

    @staticmethod
    def _verify_indexes(connection: sqlite3.Connection) -> None:
        expected_named = {
            "accounts_provider_mapping_unique": (
                "accounts",
                ("provider", "surface", "provider_account_id"),
                "where provider_account_id is not null",
            ),
            "projects_provider_mapping_unique": (
                "projects",
                ("provider", "surface", "provider_project_id"),
                "where provider_project_id is not null",
            ),
            "conversations_provider_mapping_unique": (
                "conversations",
                ("provider", "surface", "provider_conversation_id"),
                "where provider_conversation_id is not null",
            ),
        }
        for index_name, (table, columns, expected_predicate) in expected_named.items():
            rows = connection.execute(
                f"PRAGMA index_list({table})"  # noqa: S608 - internal table names
            ).fetchall()
            match = next((row for row in rows if row["name"] == index_name), None)
            if (
                match is None
                or int(match["unique"]) != 1
                or not bool(match["partial"])
            ):
                raise ContextStoreCorruptError(
                    f"missing or invalid provider context index {index_name}"
                )
            index_columns = tuple(
                str(row["name"])
                for row in connection.execute(
                    f"PRAGMA index_info({index_name})"  # noqa: S608
                ).fetchall()
            )
            if index_columns != columns:
                raise ContextStoreCorruptError(
                    f"unexpected provider context index columns for {index_name}"
                )
            index_sql_row = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'index' AND name = ?
                """,
                (index_name,),
            ).fetchone()
            if index_sql_row is None or index_sql_row["sql"] is None:
                raise ContextStoreCorruptError(
                    f"missing provider context index SQL for {index_name}"
                )
            normalized_sql = " ".join(
                str(index_sql_row["sql"]).lower().split()
            )
            if not normalized_sql.endswith(expected_predicate):
                raise ContextStoreCorruptError(
                    f"unexpected provider context index predicate for {index_name}"
                )

        quota_indexes = connection.execute(
            "PRAGMA index_list(quota_snapshots)"
        ).fetchall()
        quota_unique_found = False
        for row in quota_indexes:
            if int(row["unique"]) != 1 or bool(row["partial"]):
                continue
            columns = tuple(
                str(item["name"])
                for item in connection.execute(
                    f"PRAGMA index_info({row['name']})"  # noqa: S608
                ).fetchall()
            )
            if columns == ("account_id", "dimension", "observed_at"):
                quota_unique_found = True
                break
        if not quota_unique_found:
            raise ContextStoreCorruptError(
                "quota observation uniqueness index is missing"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")


def _serialized(model: Any) -> tuple[str, str]:
    payload = model.model_dump_json(exclude_none=False)
    return payload, _fingerprint(payload)


def _validated_payload(
    *,
    row: sqlite3.Row,
    model_name: str,
    validator: Callable[[str], _ModelT],
) -> _ModelT:
    payload = str(row["payload_json"])
    fingerprint = str(row["fingerprint"])
    if _fingerprint(payload) != fingerprint:
        raise ContextStoreCorruptError(f"{model_name} fingerprint mismatch")
    try:
        model = validator(payload)
    except (TypeError, ValueError) as exc:
        raise ContextStoreCorruptError(f"invalid {model_name} payload") from exc
    normalized = model.model_dump_json(exclude_none=False)
    if _fingerprint(normalized) != fingerprint:
        raise ContextStoreCorruptError(f"{model_name} payload is not canonical")
    return model


def _fingerprint(payload: str) -> str:
    digest = sha256(b"systeme-local:provider-context:v1\x00")
    encoded = payload.encode("utf-8")
    digest.update(len(encoded).to_bytes(8, byteorder="big", signed=False))
    digest.update(encoded)
    return digest.hexdigest()
