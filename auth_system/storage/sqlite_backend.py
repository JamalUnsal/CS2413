"""SQLite storage backend behind the same interface as the JSON backend.

OWNER: Shalom Olorunfemi (Experiment 10).

Integrity design:
  * each row stores the canonical JSON record plus its own HMAC-SHA256
    signature (same key file as the JSON backend);
  * a table-level *manifest* HMAC covers the ordered list of
    ``(username, signature)`` pairs, so deleting or inserting a row outside the
    storage API is detected too - a per-row signature alone cannot catch that;
  * reads verify the row signature and that the record's username matches the
    row key;
  * opening a database re-verifies the manifest before trusting it.

The backend adds what the JSON prototype lacks: transactional writes, row-level
locking and safe concurrent access from multiple threads/processes.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable

from auth_system.audit import AuditEvent, AuditLog
from auth_system.errors import IntegrityError, StorageError
from auth_system.models import SCHEMA_VERSION, UserRecord
from auth_system.storage.base import IntegrityReport, StorageBackend
from auth_system.storage.integrity import IntegritySigner, canonical_json

MANIFEST_KEY = "manifest"


class SqliteStorage(StorageBackend):
    backend_name = "sqlite"

    def __init__(
        self,
        path: str | Path,
        key_path: str | Path,
        *,
        audit: AuditLog | None = None,
        clock: Callable[[], float] = time.time,
        timeout: float = 10.0,
    ) -> None:
        self.path = Path(path)
        self.key_path = Path(key_path)
        self._audit = audit
        self._clock = clock
        self._lock = threading.RLock()
        self._signer = IntegritySigner.load_or_create(self.key_path)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.path),
            timeout=timeout,
            check_same_thread=False,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        try:
            self._create_schema()
            self._require_manifest_ok()
        except Exception:
            self._conn.close()
            raise

    # ------------------------------------------------------------------
    # StorageBackend API
    # ------------------------------------------------------------------
    def get_user(self, username: str) -> UserRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT record, signature FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                return None
            return self._verify_row(username, *row)

    def save_user(self, user: UserRecord) -> None:
        if not isinstance(user, UserRecord):
            raise TypeError("save_user expects a UserRecord")
        if not user.username:
            raise StorageError("cannot save a user without a username")

        record_json, signature = self._encode_record(user)
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO users (username, record, signature, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    record = excluded.record,
                    signature = excluded.signature,
                    updated_at = excluded.updated_at
                """,
                (user.username, record_json, signature, self._clock()),
            )
            self._write_manifest_locked()

    def list_users(self) -> list[UserRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT username, record, signature FROM users ORDER BY username"
            ).fetchall()
            users: list[UserRecord] = []
            problems: list[str] = []
            for username, record_json, signature in rows:
                try:
                    users.append(self._verify_row(username, record_json, signature))
                except IntegrityError as exc:
                    problems.append(str(exc))
            if problems:
                self._record_failure("; ".join(problems))
                raise IntegrityError(
                    "stored credential data failed the integrity check; "
                    "refusing to trust it: " + "; ".join(problems)
                )
            return users

    def delete_user(self, username: str) -> bool:
        with self._lock, self._conn:
            cursor = self._conn.execute("DELETE FROM users WHERE username = ?", (username,))
            deleted = cursor.rowcount > 0
            if deleted:
                self._write_manifest_locked()
            return deleted

    def verify_integrity(self) -> IntegrityReport:
        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT username, record, signature FROM users ORDER BY username"
                ).fetchall()
            except sqlite3.Error as exc:
                return IntegrityReport(
                    backend=self.backend_name,
                    ok=False,
                    checked_records=0,
                    problems=(f"database unreadable: {exc}",),
                )

            problems: list[str] = []
            for username, record_json, signature in rows:
                try:
                    self._verify_row(username, record_json, signature)
                except IntegrityError:
                    problems.append(f"record for {username!r} failed verification")

            stored_manifest = self._stored_manifest_locked()
            manifest_ok = (
                stored_manifest is not None
                and self._signer.verify(
                    canonical_json(self._manifest_payload_locked()), stored_manifest
                )
            )
            if not manifest_ok:
                problems.append("table manifest mismatch (row inserted or deleted)")

            return IntegrityReport(
                backend=self.backend_name,
                ok=not problems,
                checked_records=len(rows),
                problems=tuple(problems),
            )

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    # ------------------------------------------------------------------
    # Schema / manifest
    # ------------------------------------------------------------------
    def _create_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    record TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            if self._stored_manifest_locked() is None:
                count = self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                if count:
                    # An existing database without a manifest has lost its
                    # integrity metadata; do not silently re-bless the data.
                    raise IntegrityError(
                        "users table has data but the integrity manifest is missing"
                    )
                self._write_manifest_locked()

    def _manifest_payload_locked(self) -> dict:
        rows = self._conn.execute(
            "SELECT username, signature FROM users ORDER BY username"
        ).fetchall()
        return {
            "schema_version": SCHEMA_VERSION,
            "rows": [
                {"username": username, "signature": signature}
                for username, signature in rows
            ],
        }

    def _stored_manifest_locked(self) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (MANIFEST_KEY,)
        ).fetchone()
        return row[0] if row is not None else None

    def _write_manifest_locked(self) -> None:
        digest = self._signer.sign(canonical_json(self._manifest_payload_locked()))
        self._conn.execute(
            """
            INSERT INTO meta (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (MANIFEST_KEY, digest),
        )

    def _require_manifest_ok(self) -> None:
        with self._lock:
            stored = self._stored_manifest_locked()
            if stored is None or not self._signer.verify(
                canonical_json(self._manifest_payload_locked()), stored
            ):
                message = "table manifest mismatch (row inserted or deleted)"
                self._record_failure(message)
                raise IntegrityError(
                    "stored credential data failed the integrity check; refusing to trust it"
                )

    # ------------------------------------------------------------------
    # Row handling
    # ------------------------------------------------------------------
    def _encode_record(self, user: UserRecord) -> tuple[str, str]:
        record_json = json.dumps(
            user.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        signature = self._signer.sign(record_json.encode("utf-8"))
        return record_json, signature

    def _verify_row(self, username: str, record_json: str, signature: str) -> UserRecord:
        if not self._signer.verify(record_json.encode("utf-8"), signature):
            self._record_failure(f"HMAC digest mismatch for user {username!r}")
            raise IntegrityError(f"integrity check failed for user {username!r}")

        try:
            user = UserRecord.from_dict(json.loads(record_json))
        except (ValueError, TypeError) as exc:
            self._record_failure(f"malformed record for user {username!r}: {exc}")
            raise IntegrityError(f"stored record for {username!r} is malformed") from exc

        if user.username != username:
            self._record_failure(f"username mismatch for row {username!r}")
            raise IntegrityError(f"row {username!r} contains a different username")
        return user

    def _record_failure(self, reason: str) -> None:
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
