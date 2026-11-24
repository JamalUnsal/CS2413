"""Unit tests for session handling """

from __future__ import annotations

from auth_system.sessions import SessionManager
from tests.support import FakeClock


def make_manager(clock: FakeClock, ttl: int = 60) -> SessionManager:
    return SessionManager(ttl_seconds=ttl, clock=clock)


def test_tokens_are_unique_and_long(clock: FakeClock):
    manager = make_manager(clock)
    tokens = [manager.create_session("alice")[0] for _ in range(100)]

    assert len(set(tokens)) == 100
    assert min(len(token) for token in tokens) >= 32


def test_validate_returns_session(clock: FakeClock):
    manager = make_manager(clock)
    token, session = manager.create_session("alice")

    validated = manager.validate(token)
    assert validated is not None
    assert validated.username == "alice"
    assert validated.expires_at == session.expires_at


def test_session_expires(clock: FakeClock):
    manager = make_manager(clock)
    token, _ = manager.create_session("alice")

    clock.advance(59)
    assert manager.validate(token) is not None

    clock.advance(2)
    assert manager.validate(token) is None


def test_logout_invalidates_token(clock: FakeClock):
    manager = make_manager(clock)
    token, _ = manager.create_session("alice")

    assert manager.invalidate(token) is True
    assert manager.validate(token) is None
    assert manager.invalidate(token) is False


def test_invalidate_all_only_clears_account(clock: FakeClock):
    manager = make_manager(clock)
    alice_tokens = [manager.create_session("alice")[0] for _ in range(3)]
    bob_token, _ = manager.create_session("bob")

    assert manager.invalidate_all("alice") == 3
    assert all(manager.validate(token) is None for token in alice_tokens)
    assert manager.validate(bob_token) is not None


def test_raw_tokens_are_not_stored(clock: FakeClock):
    manager = make_manager(clock)
    tokens = [manager.create_session("alice")[0] for _ in range(10)]
    fingerprints = {session.fingerprint for session in manager.active_sessions()}

    assert all(token not in fingerprints for token in tokens)
    assert len(fingerprints) == 10


def test_invalid_tokens_are_rejected(clock: FakeClock):
    manager = make_manager(clock)
    token, _ = manager.create_session("alice")

    assert manager.validate(None) is None
    assert manager.validate("") is None
    assert manager.validate("not-a-real-token") is None
    assert manager.validate(token + "x") is None


def test_expired_sessions_are_purged(clock: FakeClock):
    manager = make_manager(clock, ttl=10)
    manager.create_session("alice")
    manager.create_session("bob")
    assert len(manager) == 2

    clock.advance(11)
    assert manager.active_sessions() == []
    assert len(manager) == 0
