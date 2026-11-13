"""Unit tests for storage backends and HMAC integrity (owner: Shalom Olorunfemi)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from auth_system import devtools
from auth_system.audit import AuditEvent
from auth_system.errors import IntegrityError
from auth_system.models import UserRecord
from auth_system.storage import (
    JsonStorage,
    create_storage,
    inspect_json_storage,
)

PASSWORD = "Correct-Horse-Battery-9!"


def make_user(username: str, password_hash: str = "hash", **overrides) -> UserRecord:
    data = {
        "username": username,
        "password_hash": password_hash,
        "created_at": 1.0,
        "updated_at": 2.0,
        "password_changed_at": 1.0,
    }
    data.update(overrides)
    return UserRecord(**data)


def tamper_json(path: Path, mutate) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document["users"])
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ----------------------------------------------------------------------
# JSON backend
# ----------------------------------------------------------------------
def test_json_roundtrip_and_persistence(settings):
    storage = JsonStorage(settings.users_path, settings.integrity_key_path)
    try:
        assert storage.get_user("alice") is None
        storage.save_user(make_user("alice", failed_attempts=2))
        assert storage.get_user("alice").failed_attempts == 2
        assert [user.username for user in storage.list_users()] == ["alice"]
        assert storage.user_exists("alice") is True
    finally:
        storage.close()

    reopened = JsonStorage(settings.users_path, settings.integrity_key_path)
    try:
        user = reopened.get_user("alice")
        assert user is not None and user.failed_attempts == 2
        assert reopened.delete_user("alice") is True
        assert reopened.delete_user("alice") is False
    finally:
        reopened.close()

    final = JsonStorage(settings.users_path, settings.integrity_key_path)
    try:
        assert final.list_users() == []
    finally:
        final.close()


def test_returned_records_are_detached_copies(settings):
    storage = JsonStorage(settings.users_path, settings.integrity_key_path)
    try:
        storage.save_user(make_user("alice"))
        copy = storage.get_user("alice")
        copy.failed_attempts = 99
        copy.password_hash = "changed-in-memory"

        stored = storage.get_user("alice")
        assert stored.failed_attempts == 0
        assert stored.password_hash == "hash"
    finally:
        storage.close()


def test_json_integrity_is_valid_after_writes(settings):
    storage = JsonStorage(settings.users_path, settings.integrity_key_path)
    try:
        storage.save_user(make_user("alice"))
        report = storage.verify_integrity()
        assert report.ok is True
        assert report.checked_records == 1
    finally:
        storage.close()


def test_json_stores_no_plaintext_password(settings):
    storage = JsonStorage(settings.users_path, settings.integrity_key_path)
    try:
        devtools.seed_user(storage, "alice", PASSWORD, rounds=4)
    finally:
        storage.close()

    raw = settings.users_path.read_text(encoding="utf-8")
    assert PASSWORD not in raw
    assert "password_hash" in raw


def test_hmac_key_lives_outside_the_credential_file(settings):
    storage = JsonStorage(settings.users_path, settings.integrity_key_path)
    try:
        storage.save_user(make_user("alice"))
    finally:
        storage.close()

    key_hex = settings.integrity_key_path.read_text(encoding="utf-8").strip()
    assert len(bytes.fromhex(key_hex)) == 32
    assert key_hex not in settings.users_path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("changed hash", lambda users: users["alice"].__setitem__("password_hash", "tampered")),
        ("reset failed attempts", lambda users: users["alice"].__setitem__("failed_attempts", 0)),
        ("removed lockout", lambda users: users["alice"].__setitem__("lockout_until", None)),
        ("deleted user", lambda users: users.pop("bob")),
    ],
)
def test_json_tampering_is_detected(settings, audit, label, mutate):
    storage = JsonStorage(settings.users_path, settings.integrity_key_path, audit=audit)
    try:
        storage.save_user(make_user("alice", failed_attempts=5, lockout_until=999.0))
        storage.save_user(make_user("bob"))
    finally:
        storage.close()

    tamper_json(settings.users_path, mutate)
    inspection = inspect_json_storage(settings.users_path, settings.integrity_key_path)
    assert inspection.ok is False, label

    with pytest.raises(IntegrityError):
        JsonStorage(settings.users_path, settings.integrity_key_path, audit=audit)

    assert len(audit.events_for(AuditEvent.INTEGRITY_FAILURE)) == 1


def test_wrong_key_is_rejected(settings, tmp_path):
    storage = JsonStorage(settings.users_path, settings.integrity_key_path)
    try:
        storage.save_user(make_user("alice"))
    finally:
        storage.close()

    wrong_key = tmp_path / "attacker.key"
    wrong_key.write_text("11" * 32 + "\n", encoding="utf-8")

    with pytest.raises(IntegrityError):
        JsonStorage(settings.users_path, wrong_key)


def test_malformed_file_is_rejected(settings):
    settings.users_path.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(IntegrityError):
        JsonStorage(settings.users_path, settings.integrity_key_path)


# ----------------------------------------------------------------------
# SQLite backend
# ----------------------------------------------------------------------
def _sqlite_tamper(settings) -> None:
    connection = sqlite3.connect(str(settings.sqlite_path))
    try:
        connection.execute(
            "UPDATE users SET record = replace(record, ?, ?) WHERE username = ?",
            ('"password_hash":"hash"', '"password_hash":"tampered"', "alice"),
        )
        connection.commit()
    finally:
        connection.close()


def test_sqlite_roundtrip_and_persistence(settings):
    storage = create_storage("sqlite", settings)
    try:
        storage.save_user(make_user("alice", failed_attempts=3))
        assert storage.get_user("alice").failed_attempts == 3
        assert storage.get_user("alice").password_hash == "hash"
        assert [user.username for user in storage.list_users()] == ["alice"]
        assert storage.verify_integrity().ok is True
    finally:
        storage.close()

    reopened = create_storage("sqlite", settings)
    try:
        assert reopened.get_user("alice").failed_attempts == 3
        assert reopened.delete_user("alice") is True
        assert reopened.delete_user("alice") is False
    finally:
        reopened.close()


def test_sqlite_tampering_is_detected_on_read(settings, audit):
    storage = create_storage("sqlite", settings, audit=audit)
    try:
        storage.save_user(make_user("alice"))
        _sqlite_tamper(settings)

        report = storage.verify_integrity()
        assert report.ok is False
        assert any("alice" in problem for problem in report.problems)

        with pytest.raises(IntegrityError):
            storage.get_user("alice")
        assert len(audit.events_for(AuditEvent.INTEGRITY_FAILURE)) >= 1
    finally:
        storage.close()


def test_sqlite_delete_tampering_is_detected(settings):
    storage = create_storage("sqlite", settings)
    try:
        storage.save_user(make_user("alice"))

        connection = sqlite3.connect(str(settings.sqlite_path))
        try:
            connection.execute("DELETE FROM users WHERE username = ?", ("alice",))
            connection.commit()
        finally:
            connection.close()

        # The table-level manifest detects deleted rows, which per-row
        # signatures alone could not prove.
        report = storage.verify_integrity()
        assert report.ok is False
        assert any("manifest" in problem for problem in report.problems)
        assert storage.get_user("alice") is None
    finally:
        storage.close()


# ----------------------------------------------------------------------
# Interface parity
# ----------------------------------------------------------------------
@pytest.mark.parametrize("backend", ["json", "sqlite"])
def test_storage_contract_is_backend_independent(backend, settings, audit):
    storage = create_storage(backend, settings, audit=audit)
    try:
        assert storage.get_user("alice") is None
        assert storage.list_users() == []

        storage.save_user(make_user("alice"))
        storage.save_user(make_user("bob"))
        assert storage.get_user("alice") is not None
        assert {user.username for user in storage.list_users()} == {"alice", "bob"}

        copy = storage.get_user("alice")
        copy.failed_attempts = 9
        assert storage.get_user("alice").failed_attempts == 0

        assert storage.delete_user("alice") is True
        assert storage.delete_user("alice") is False
        assert storage.get_user("alice") is None
        assert storage.verify_integrity().ok is True
    finally:
        storage.close()
