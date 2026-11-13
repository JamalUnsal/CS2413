"""Storage package.

OWNER: Shalom Olorunfemi.

Use :func:`create_storage` so the rest of the system never imports a concrete
backend directly.
"""

from __future__ import annotations

from auth_system.audit import AuditLog
from auth_system.config import Settings
from auth_system.storage.base import IntegrityReport, StorageBackend
from auth_system.storage.json_backend import JsonStorage, inspect_json_storage
from auth_system.storage.sqlite_backend import SqliteStorage

__all__ = [
    "IntegrityReport",
    "StorageBackend",
    "JsonStorage",
    "SqliteStorage",
    "create_storage",
    "inspect_json_storage",
]


def create_storage(
    backend: str,
    settings: Settings,
    *,
    audit: AuditLog | None = None,
) -> StorageBackend:
    """Build the requested backend (``"json"`` or ``"sqlite"``)."""
    kind = backend.strip().lower()
    if kind == "json":
        return JsonStorage(settings.users_path, settings.integrity_key_path, audit=audit)
    if kind == "sqlite":
        return SqliteStorage(settings.sqlite_path, settings.integrity_key_path, audit=audit)
    raise ValueError(f"unknown storage backend: {backend!r} (expected 'json' or 'sqlite')")
