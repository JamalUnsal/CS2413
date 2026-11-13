"""JSON file storage backend with HMAC integrity protection.

OWNER: Shalom Olorunfemi.

File layout::

    {
      "schema_version": 1,
      "users": { "<username>": { ...UserRecord... } },
      "integrity": {"algorithm": "HMAC-SHA256", "digest": "<hex>"}
    }

The digest covers the canonical encoding of ``schema_version`` + ``users``
only.  Writes are atomic (temp file + ``os.replace``) and serialised by an
in-process lock.  A failed integrity check makes the backend refuse to expose
or modify data - it never "repairs" silently.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from auth_system.audit import AuditEvent, AuditLog
from auth_system.errors import IntegrityError, StorageError
from auth_system.models import SCHEMA_VERSION, UserRecord
from auth_system.storage.base import IntegrityReport, StorageBackend
from auth_system.storage.integrity import IntegritySigner, canonical_json


class JsonStorage(StorageBackend):
    backend_name = "json"

    def __init__(
        self,
        path: str | Path,
        key_path: str | Path,
        *,
        audit: AuditLog | None = None,
        clock: Callable[[], float] = time.time,
        create_if_missing: bool = True,
    ) -> None:
        self.path = Path(path)
        self.key_path = Path(key_path)
        self._audit = audit
        self._clock = clock
        self._lock = threading.RLock()
        self._users: dict[str, UserRecord] = {}
        self._create_if_missing = create_if_missing
        self._signer = IntegritySigner.load_or_create(self.key_path, create=create_if_missing)
        self._load()

    # ------------------------------------------------------------------
    # StorageBackend API
    # ------------------------------------------------------------------
    def get_user(self, username: str) -> UserRecord | None:
        with self._lock:
            user = self._users.get(username)
            return user.copy() if user is not None else None

    def save_user(self, user: UserRecord) -> None:
        if not isinstance(user, UserRecord):
            raise TypeError("save_user expects a UserRecord")
        if not user.username:
            raise StorageError("cannot save a user without a username")
        with self._lock:
            self._users[user.username] = user.copy()
            self._persist_locked()

    def list_users(self) -> list[UserRecord]:
        with self._lock:
            return [user.copy() for user in self._users.values()]

    def delete_user(self, username: str) -> bool:
        with self._lock:
            if username not in self._users:
                return False
            del self._users[username]
            self._persist_locked()
            return True

    def verify_integrity(self) -> IntegrityReport:
        with self._lock:
            return _verify_file(self.path, self._signer)

    def close(self) -> None:
        # Nothing to release: the file is opened per operation.
        return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _load(self) -> None:
        with self._lock:
            if not self.path.exists():
                if not self._create_if_missing:
                    raise StorageError(f"credential file not found: {self.path}")
                self._users = {}
                self._persist_locked()
                return

            try:
                document = self._read_document()
                users_raw = document["users"]
                if not isinstance(users_raw, dict):
                    raise ValueError("'users' must be a JSON object")
                payload = {
                    "schema_version": document.get("schema_version", SCHEMA_VERSION),
                    "users": users_raw,
                }
                digest = (document.get("integrity") or {}).get("digest")
                if not self._signer.verify(canonical_json(payload), digest):
                    self._fail_integrity("HMAC digest mismatch")
                records = {
                    name: UserRecord.from_dict(record)
                    for name, record in users_raw.items()
                }
            except IntegrityError:
                raise
            except (OSError, ValueError, KeyError, TypeError) as exc:
                self._fail_integrity(f"malformed or unreadable credential file: {exc}")

            self._users = records

    def _read_document(self) -> dict[str, Any]:
        raw = self.path.read_text(encoding="utf-8")
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise ValueError("credential file must contain a JSON object")
        if not isinstance(document.get("users"), dict):
            raise ValueError("credential file is missing the 'users' object")
        return document

    def _persist_locked(self) -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "users": {
                name: user.to_dict()
                for name, user in sorted(self._users.items())
            },
        }
        document = {
            **payload,
            "integrity": {
                "algorithm": "HMAC-SHA256",
                "digest": self._signer.sign(canonical_json(payload)),
            },
        }

        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_name(self.path.name + ".tmp")
        try:
            temp_path.write_text(
                json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            os.replace(temp_path, self.path)
        except OSError as exc:
            raise StorageError(f"could not write credential file: {exc}") from exc
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass

    def _fail_integrity(self, reason: str) -> None:
        if self._audit is not None:
            self._audit.record(
                AuditEvent.INTEGRITY_FAILURE,
                username=None,
                details={
                    "backend": self.backend_name,
                    "path": str(self.path),
                    "reason": reason,
                    "detected_at": self._clock(),
                },
            )
        raise IntegrityError(
            f"stored credential data failed the integrity check ({reason}); "
            "refusing to trust it"
        )


def inspect_json_storage(path: str | Path, key_path: str | Path) -> IntegrityReport:
    """Verify a JSON credential file *without* trusting or loading it.

    Safe to call from diagnostics/experiments after the backend refused to
    initialise.  Never raises.
    """
    try:
        signer = IntegritySigner.load_or_create(key_path, create=False)
    except IntegrityError as exc:
        return IntegrityReport(
            backend="json",
            ok=False,
            checked_records=0,
            problems=(str(exc),),
        )
    return _verify_file(Path(path), signer)


def _verify_file(path: Path, signer: IntegritySigner) -> IntegrityReport:
    try:
        raw = path.read_text(encoding="utf-8")
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise ValueError("credential file must contain a JSON object")
        users = document.get("users")
        if not isinstance(users, dict):
            raise ValueError("credential file is missing the 'users' object")
        payload = {
            "schema_version": document.get("schema_version", SCHEMA_VERSION),
            "users": users,
        }
        digest = (document.get("integrity") or {}).get("digest")
        ok = signer.verify(canonical_json(payload), digest)
        return IntegrityReport(
            backend="json",
            ok=ok,
            checked_records=len(users),
            problems=() if ok else ("HMAC digest mismatch",),
        )
    except FileNotFoundError:
        return IntegrityReport(
            backend="json",
            ok=False,
            checked_records=0,
            problems=(f"credential file not found: {path}",),
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return IntegrityReport(
            backend="json",
            ok=False,
            checked_records=0,
            problems=(f"unreadable credential file: {exc}",),
        )
