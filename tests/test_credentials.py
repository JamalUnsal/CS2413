"""Unit tests for password change and reset (owner: Shalom Olorunfemi)."""

from __future__ import annotations

from auth_system.audit import AuditEvent
from auth_system.credentials import (
    INCORRECT_CURRENT_PASSWORD_MESSAGE,
    INVALID_RESET_TOKEN_MESSAGE,
    SESSION_INVALID_MESSAGE,
    CredentialManager,
)
from auth_system.sessions import SessionManager
from tests.support import FakePolicy, make_credentials, seed

OLD_PASSWORD = "Old-Password-9!"
NEW_PASSWORD = "New-Password-8!"
THIRD_PASSWORD = "Third-Password-7!"


# ----------------------------------------------------------------------
# Change password
# ----------------------------------------------------------------------
def test_change_password_updates_the_hash(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)

    result = credentials.change_password("alice", OLD_PASSWORD, NEW_PASSWORD)

    assert result.success is True
    assert runtime.auth.login("alice", NEW_PASSWORD).success is True
    assert runtime.auth.login("alice", OLD_PASSWORD).success is False


def test_change_password_requires_the_current_password(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)

    result = credentials.change_password("alice", "Not-The-Password-1!", NEW_PASSWORD)

    assert result.success is False
    assert result.message == INCORRECT_CURRENT_PASSWORD_MESSAGE
    assert result.reason == "bad_old_password"
    assert runtime.auth.login("alice", OLD_PASSWORD).success is True


def test_change_password_for_unknown_user_uses_the_same_message(runtime):
    credentials = make_credentials(runtime)

    result = credentials.change_password("ghost", "whatever", NEW_PASSWORD)

    assert result.success is False
    assert result.message == INCORRECT_CURRENT_PASSWORD_MESSAGE


def test_change_password_rejects_reuse(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)

    result = credentials.change_password("alice", OLD_PASSWORD, OLD_PASSWORD)

    assert result.success is False
    assert result.reason == "password_reuse"


def test_change_password_enforces_policy(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    policy = FakePolicy()
    credentials = make_credentials(runtime, policy)

    result = credentials.change_password("alice", OLD_PASSWORD, "short")

    assert result.success is False
    assert result.reason == "policy_rejected"
    assert "at least 8 characters" in result.message
    assert policy.calls == [("alice", "short")]
    assert runtime.auth.login("alice", OLD_PASSWORD).success is True


def test_change_password_invalidates_all_sessions(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    first = runtime.auth.login("alice", OLD_PASSWORD).session_token
    second = runtime.sessions.create_session("alice")[0]
    credentials = make_credentials(runtime)

    result = credentials.change_password("alice", OLD_PASSWORD, NEW_PASSWORD)

    assert result.success is True
    assert runtime.auth.current_session(first) is None
    assert runtime.sessions.validate(second) is None


def test_change_password_rejects_a_foreign_session(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    seed(runtime, "bob", THIRD_PASSWORD)
    bob_token = runtime.auth.login("bob", THIRD_PASSWORD).session_token
    credentials = make_credentials(runtime)

    result = credentials.change_password(
        "alice", OLD_PASSWORD, NEW_PASSWORD, session_token=bob_token
    )

    assert result.success is False
    assert result.message == SESSION_INVALID_MESSAGE


def test_change_password_rejects_an_invalid_session(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)

    result = credentials.change_password(
        "alice", OLD_PASSWORD, NEW_PASSWORD, session_token="forged-token"
    )

    assert result.success is False
    assert result.message == SESSION_INVALID_MESSAGE
    assert runtime.auth.login("alice", OLD_PASSWORD).success is True


def test_change_password_is_audited_without_secrets(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)

    credentials.change_password("alice", OLD_PASSWORD, NEW_PASSWORD)

    events = runtime.audit.events_for(AuditEvent.PASSWORD_CHANGE)
    assert any(event.details.get("result") == "success" for event in events)
    serialized = " ".join(str(event.details) for event in runtime.audit.events)
    assert OLD_PASSWORD not in serialized
    assert NEW_PASSWORD not in serialized


# ----------------------------------------------------------------------
# Reset flow
# ----------------------------------------------------------------------
def test_reset_request_returns_a_token_and_stores_only_its_hash(runtime, settings):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)

    request = credentials.request_password_reset("alice")

    assert request.token is not None
    raw_store = settings.users_path.read_text(encoding="utf-8")
    assert request.token not in raw_store
    user = runtime.storage.get_user("alice")
    assert user.reset_token_hash is not None
    assert user.reset_token_expires_at == runtime.clock() + settings.reset_token_ttl_seconds


def test_reset_request_is_identical_for_unknown_users(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)

    known = credentials.request_password_reset("alice")
    unknown = credentials.request_password_reset("ghost")

    assert known.message == unknown.message
    assert unknown.token is None


def test_reset_password_with_valid_token(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)
    request = credentials.request_password_reset("alice")

    result = credentials.reset_password("alice", request.token, NEW_PASSWORD)

    assert result.success is True
    assert runtime.auth.login("alice", NEW_PASSWORD).success is True
    assert runtime.auth.login("alice", OLD_PASSWORD).success is False


def test_reset_token_is_single_use(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)
    request = credentials.request_password_reset("alice")

    assert credentials.reset_password("alice", request.token, NEW_PASSWORD).success is True

    reuse = credentials.reset_password("alice", request.token, THIRD_PASSWORD)
    assert reuse.success is False
    assert reuse.message == INVALID_RESET_TOKEN_MESSAGE
    assert runtime.auth.login("alice", NEW_PASSWORD).success is True


def test_expired_reset_token_is_rejected(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)
    request = credentials.request_password_reset("alice")

    runtime.clock.advance(runtime.settings.reset_token_ttl_seconds + 1)

    result = credentials.reset_password("alice", request.token, NEW_PASSWORD)
    assert result.success is False
    assert result.message == INVALID_RESET_TOKEN_MESSAGE
    assert runtime.auth.login("alice", OLD_PASSWORD).success is True


def test_reset_token_for_another_user_is_rejected(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    seed(runtime, "bob", THIRD_PASSWORD)
    credentials = make_credentials(runtime)
    request = credentials.request_password_reset("alice")

    result = credentials.reset_password("bob", request.token, NEW_PASSWORD)

    assert result.success is False
    assert runtime.auth.login("bob", THIRD_PASSWORD).success is True


def test_policy_failure_does_not_consume_the_reset_token(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)
    request = credentials.request_password_reset("alice")

    rejected = credentials.reset_password("alice", request.token, "short")
    assert rejected.success is False
    assert rejected.reason == "policy_rejected"
    assert runtime.auth.login("alice", OLD_PASSWORD).success is True

    retried = credentials.reset_password("alice", request.token, NEW_PASSWORD)
    assert retried.success is True


def test_requesting_a_new_token_invalidates_the_old_one(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)

    first = credentials.request_password_reset("alice")
    second = credentials.request_password_reset("alice")

    assert first.token != second.token
    assert credentials.reset_password("alice", first.token, NEW_PASSWORD).success is False
    assert credentials.reset_password("alice", second.token, NEW_PASSWORD).success is True


def test_reset_password_rejects_reuse(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    credentials = make_credentials(runtime)
    request = credentials.request_password_reset("alice")

    result = credentials.reset_password("alice", request.token, OLD_PASSWORD)

    assert result.success is False
    assert result.reason == "password_reuse"


def test_reset_invalidates_sessions_and_is_audited(runtime):
    seed(runtime, "alice", OLD_PASSWORD)
    token = runtime.auth.login("alice", OLD_PASSWORD).session_token
    credentials = make_credentials(runtime)
    request = credentials.request_password_reset("alice")

    assert credentials.reset_password("alice", request.token, NEW_PASSWORD).success is True

    assert runtime.auth.current_session(token) is None
    reset_events = runtime.audit.events_for(AuditEvent.PASSWORD_RESET)
    assert any(event.details.get("result") == "success" for event in reset_events)
    assert len(runtime.audit.events_for(AuditEvent.PASSWORD_RESET_REQUEST)) == 1


def test_credentials_manager_accepts_injected_dependencies(settings, clock, audit):
    manager = CredentialManager(
        storage=_FakeStorage(),
        sessions=SessionManager(ttl_seconds=60, clock=clock),
        audit=audit,
        settings=settings,
        policy=FakePolicy(),
        hasher=lambda password: "fake-hash",
        clock=clock,
    )
    assert manager.settings is settings


class _FakeStorage:
    """Tiny stub used only to assert constructor injection."""

    def get_user(self, username):  # pragma: no cover - not called
        return None
