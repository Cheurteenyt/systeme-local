from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from .audit import AuditLog


class AuditRuntimeSettings(Protocol):
    shared_secret: str
    audit_key: str
    audit_log: Path
    audit_anchor_log: Path | None
    audit_anchor_key: str | None


def _normalized_path(path: Path) -> str:
    return os.path.normcase(os.fspath(path.resolve(strict=False)))


def _lock_path(path: Path) -> Path:
    return path.parent / f"{path.name}.lock"


def create_configured_audit_log(
    settings: AuditRuntimeSettings,
) -> AuditLog:
    from .audit import AuditLog

    anchor_path_configured = settings.audit_anchor_log is not None
    anchor_key_configured = settings.audit_anchor_key is not None
    if anchor_path_configured != anchor_key_configured:
        raise ValueError(
            "audit anchor path and key must be configured together"
        )

    anchor = None
    if settings.audit_anchor_log is not None:
        from .audit_anchor import FileAuditAnchor, derive_audit_log_id

        assert settings.audit_anchor_key is not None
        if hmac.compare_digest(
            settings.audit_anchor_key,
            settings.shared_secret,
        ) or hmac.compare_digest(
            settings.audit_anchor_key,
            settings.audit_key,
        ):
            raise ValueError(
                "audit anchor key must be independent from runtime secrets"
            )

        audit_paths = {
            _normalized_path(settings.audit_log),
            _normalized_path(_lock_path(settings.audit_log)),
        }
        anchor_paths = {
            _normalized_path(settings.audit_anchor_log),
            _normalized_path(_lock_path(settings.audit_anchor_log)),
        }
        if audit_paths & anchor_paths:
            raise ValueError(
                "audit log, audit anchor, and lock paths must not overlap"
            )

        anchor = FileAuditAnchor(
            settings.audit_anchor_log,
            settings.audit_anchor_key,
            derive_audit_log_id(settings.audit_key),
        )

    return AuditLog(
        settings.audit_log,
        settings.audit_key,
        anchor=anchor,
    )
