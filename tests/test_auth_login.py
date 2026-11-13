"""Unit tests for login, MFA enforcement and sessions (owner: Sandeep Singh)."""

from __future__ import annotations

from auth_system.auth import AuthService
from auth_system.mfa import INVALID_MFA_MESSAGE
from auth_system.verification import INVALID_CREDENTIALS_MESSAGE
from tests.support import seed

PASSWORD = "Correct-Horse-Battery-9!"
WRONG_PASSWORD = "Definitely-Wrong-1!"


def enable_mfa(runtime, username: str = "alice"):
    login = runtime.auth.login(username, PASSWORD)
    enrollment = runtime.auth.begin_mfa_enrollment(login.session_token)
    assert enrollment.success and enrollment.enrollment is not None
    code = runtime.mfa.generate_code(enrollment.enrollment.secret)
    confirmation = runtime.auth.confirm_mfa_enrollment(login.session_token, code)
    assert confirmation.success
    return enrollment.enrollment.secret, login.session_token


# ----------------------------------------------------------------------
# Password verification and enumeration resistance
# ----------------------------------------------------------------------
def test_successful_login_issues_a_session(runtime):
    seed(runtime, "alice", PASSWORD)

    result = runtime.auth.login("alice", PASSWORD)

    assert result.success is True
    assert result.session_token
    session = runtime.auth.current_session(result.session_token)
    assert session is not None
    assert session.username == "alice"
    assert result.session_expires_at == runtime.clock() + runtime.settings.session_ttl_seconds


def test_username_is_trimmed(runtime):
    seed(runtime, "alice", PASSWORD)

    assert runtime.auth.login("  alice  ", PASSWORD).success is True


def test_wrong_password_and_unknown_user_are_indistinguishable(runtime):
    seed(runtime, "alice", PASSWORD)

    wrong_password = runtime.auth.login("alice", WRONG_PASSWORD)
    unknown_user = runtime.auth.login("ghost", WRONG_PASSWORD)

    assert wrong_password.success is False
    assert unknown_user.success is False
    assert wrong_password.session_token is None
    assert unknown_user.session_token is None
    assert wrong_password.message == unknown_user.message == INVALID_CREDENTIALS_MESSAGE
    # Different internal reasons for audit/experiments, never for the user.
    assert wrong_password.reason == "bad_password"
    assert unknown_user.reason == "unknown_user"


def test_empty_credentials_are_rejected_generically(runtime):
    seed(runtime, "alice", PASSWORD)

    for username, password in (("", ""), ("alice", ""), ("", PASSWORD)):
        result = runtime.auth.login(username, password)
        assert result.success is False
        assert result.session_token is None
        assert result.message == INVALID_CREDENTIALS_MESSAGE


def test_very_long_password_is_rejected_without_error(runtime):
    seed(runtime, "alice", PASSWORD)

    result = runtime.auth.login("alice", "A" * 5000)

    assert result.success is False
    assert result.message == INVALID_CREDENTIALS_MESSAGE


def test_successful_login_resets_failure_counters(runtime):
    seed(runtime, "alice", PASSWORD, failed_attempts=2, lockout_until=runtime.clock() + 50)

    result = runtime.auth.login("alice", PASSWORD)

    assert result.success is True
    user = runtime.storage.get_user("alice")
    assert user.failed_attempts == 0
    assert user.lockout_until is None


def test_logout_invalidates_the_session(runtime):
    seed(runtime, "alice", PASSWORD)
    token = runtime.auth.login("alice", PASSWORD).session_token
    assert runtime.auth.current_session(token) is not None

    assert runtime.auth.logout(token) is True
    assert runtime.auth.current_session(token) is None
    assert runtime.auth.logout(token) is False


# ----------------------------------------------------------------------
# MFA
# ----------------------------------------------------------------------
def test_mfa_enrollment_requires_a_valid_session(runtime):
    assert runtime.auth.begin_mfa_enrollment(None).success is False
    assert runtime.auth.begin_mfa_enrollment("bogus-token").success is False


def test_mfa_is_not_enabled_until_a_code_is_confirmed(runtime):
    seed(runtime, "alice", PASSWORD)
    login = runtime.auth.login("alice", PASSWORD)
    enrollment = runtime.auth.begin_mfa_enrollment(login.session_token)

    assert enrollment.success is True
    assert runtime.storage.get_user("alice").mfa_enabled is False

    # A password-only login still works while enrollment is pending.
    assert runtime.auth.login("alice", PASSWORD).success is True


def test_mfa_login_requires_a_code(runtime):
    seed(runtime, "alice", PASSWORD)
    secret, _ = enable_mfa(runtime)

    result = runtime.auth.login("alice", PASSWORD)

    assert result.success is False
    assert result.session_token is None
    assert result.reason == "mfa_required"
    assert result.message == INVALID_MFA_MESSAGE


def test_wrong_mfa_code_is_rejected(runtime):
    seed(runtime, "alice", PASSWORD)
    secret, _ = enable_mfa(runtime)
    wrong_code = runtime.mfa.generate_code(secret, at=runtime.clock() + 120)

    result = runtime.auth.login("alice", PASSWORD, wrong_code)

    assert result.success is False
    assert result.reason == "mfa_failed"
    assert result.message == INVALID_MFA_MESSAGE
    assert runtime.storage.get_user("alice").mfa_failed_attempts == 1


def test_expired_mfa_code_is_rejected(runtime):
    seed(runtime, "alice", PASSWORD)
    secret, _ = enable_mfa(runtime)
    expired_code = runtime.mfa.generate_code(secret, at=runtime.clock() - 120)

    result = runtime.auth.login("alice", PASSWORD, expired_code)

    assert result.success is False
    assert result.reason == "mfa_failed"


def test_valid_mfa_code_completes_login(runtime):
    seed(runtime, "alice", PASSWORD)
    secret, _ = enable_mfa(runtime)

    result = runtime.auth.login("alice", PASSWORD, runtime.mfa.generate_code(secret))

    assert result.success is True
    assert result.mfa_used is True
    assert result.session_token is not None
    user = runtime.storage.get_user("alice")
    assert user.mfa_failed_attempts == 0
    assert user.mfa_locked_until is None


def test_mfa_guessing_is_rate_limited_and_recovers_after_cooldown(runtime):
    seed(runtime, "alice", PASSWORD)
    secret, _ = enable_mfa(runtime)
    max_attempts = runtime.settings.mfa_max_attempts

    for index in range(max_attempts):
        wrong_code = runtime.mfa.generate_code(secret, at=runtime.clock() + 30 * (index + 1))
        result = runtime.auth.login("alice", PASSWORD, wrong_code)
        assert result.success is False
        assert result.session_token is None

    # Even the correct code is refused while the limiter is active.
    blocked = runtime.auth.login("alice", PASSWORD, runtime.mfa.generate_code(secret))
    assert blocked.success is False
    assert blocked.reason == "mfa_locked"
    assert blocked.retry_after is not None

    runtime.clock.advance(runtime.settings.mfa_cooldown_seconds + 1)
    recovered = runtime.auth.login("alice", PASSWORD, runtime.mfa.generate_code(secret))
    assert recovered.success is True


def test_reenrolling_mfa_is_rejected(runtime):
    seed(runtime, "alice", PASSWORD)
    _, token = enable_mfa(runtime)

    result = runtime.auth.begin_mfa_enrollment(token)

    assert result.success is False
    assert "already enabled" in result.message.lower()


def test_mfa_confirmation_rejects_a_bad_code(runtime):
    seed(runtime, "alice", PASSWORD)
    login = runtime.auth.login("alice", PASSWORD)
    enrollment = runtime.auth.begin_mfa_enrollment(login.session_token)
    wrong_code = runtime.mfa.generate_code(enrollment.enrollment.secret, at=runtime.clock() + 120)

    result = runtime.auth.confirm_mfa_enrollment(login.session_token, wrong_code)

    assert result.success is False
    assert runtime.storage.get_user("alice").mfa_enabled is False


# ----------------------------------------------------------------------
# Audit integration (Jamal will implement the writer; wiring is tested here)
# ----------------------------------------------------------------------
def test_audit_events_are_recorded_without_secrets(runtime):
    seed(runtime, "alice", PASSWORD)
    runtime.auth.login("alice", WRONG_PASSWORD)
    runtime.auth.login("alice", PASSWORD)

    events = runtime.audit.events
    assert any(entry.event == "login_failure" for entry in events)
    assert any(entry.event == "login_success" for entry in events)
    serialized = " ".join(str(entry.details) for entry in events)
    assert PASSWORD not in serialized
    assert WRONG_PASSWORD not in serialized


def test_auth_service_is_constructed_with_dependencies(settings, clock, audit):
    from auth_system.runtime import build_runtime

    instance = build_runtime(settings, audit=audit, clock=clock)
    try:
        assert isinstance(instance.auth, AuthService)
    finally:
        instance.close()
