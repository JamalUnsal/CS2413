"""Login orchestration: verification, generic errors, MFA and sessions.

OWNER: Sandeep Singh (Experiments 3, 7 and 9).

Flow:
  1. Reject empty input with the same generic message as any other failure.
  2. Unknown username -> run the dummy bcrypt check (equal cost) + generic error.
  3. Lockout policy check (Jamal's module; ``NoLockoutPolicy`` until ready).
  4. bcrypt verification -> on failure record the attempt and return the generic
     message, regardless of whether the username exists.
  5. If MFA is enabled, require a valid TOTP code and limit code attempts.
  6. On success reset failure state, create a session token and return it.

The public ``message`` on every failure is either ``INVALID_CREDENTIALS_MESSAGE``
or ``INVALID_MFA_MESSAGE``; the machine-readable ``reason`` is for the audit log
and experiments only and must never be shown to end users.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from auth_system.audit import AuditEvent, AuditLog
from auth_system.config import Settings
from auth_system.lockout import LockoutPolicy
from auth_system.mfa import INVALID_MFA_MESSAGE, MfaEnrollment, MfaService
from auth_system.models import UserRecord
from auth_system.results import OperationResult
from auth_system.sessions import Session, SessionManager
from auth_system.storage.base import StorageBackend
from auth_system.verification import INVALID_CREDENTIALS_MESSAGE, dummy_verify, verify_password


@dataclass(frozen=True)
class LoginResult:
    success: bool
    message: str
    reason: str | None = None
    session_token: str | None = None
    session_expires_at: float | None = None
    mfa_used: bool = False
    retry_after: float | None = None


@dataclass(frozen=True)
class MfaEnrollmentResult:
    success: bool
    message: str
    enrollment: MfaEnrollment | None = None


class AuthService:
    def __init__(
        self,
        storage: StorageBackend,
        sessions: SessionManager,
        mfa: MfaService,
        lockout: LockoutPolicy,
        audit: AuditLog,
        settings: Settings,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.storage = storage
        self.sessions = sessions
        self.mfa = mfa
        self.lockout = lockout
        self.audit = audit
        self.settings = settings
        self._clock = clock

    # ------------------------------------------------------------------
    # Login / logout
    # ------------------------------------------------------------------
    def login(self, username: str, password: str, totp_code: str | None = None) -> LoginResult:
        normalized = (username or "").strip() if isinstance(username, str) else ""

        if not normalized or not isinstance(password, str) or password == "":
            # Keep the cost identical to a real attempt.
            dummy_verify(
                password if isinstance(password, str) else "",
                self.settings.bcrypt_rounds,
            )
            self._audit_failure(normalized or None, reason="empty_input")
            return self._credential_failure("empty_input")

        now = self._clock()
        user = self.storage.get_user(normalized)

        if user is None:
            dummy_verify(password, self.settings.bcrypt_rounds)
            self._audit_failure(normalized, reason="unknown_user")
            return self._credential_failure("unknown_user")

        decision = self.lockout.check(user, now)
        if not decision.allowed:
            self.audit.record(
                AuditEvent.LOCKOUT_BLOCKED,
                normalized,
                {"retry_after": decision.retry_after},
            )
            return LoginResult(
                success=False,
                message=INVALID_CREDENTIALS_MESSAGE,
                reason="locked_out",
                retry_after=decision.retry_after,
            )

        if not verify_password(user.password_hash, password):
            decision = self.lockout.register_failure(user, now)
            user.updated_at = now
            self.storage.save_user(user)
            if decision.locked:
                self.audit.record(
                    AuditEvent.LOCKOUT_TRIGGERED,
                    normalized,
                    {"failed_attempts": user.failed_attempts},
                )
            self._audit_failure(normalized, reason="bad_password")
            return LoginResult(
                success=False,
                message=INVALID_CREDENTIALS_MESSAGE,
                reason="bad_password",
                retry_after=decision.retry_after,
            )

        if user.mfa_enabled:
            mfa_failure = self._enforce_mfa(user, totp_code, now)
            if mfa_failure is not None:
                return mfa_failure

        # --- success ---------------------------------------------------
        self.lockout.reset(user, now)
        user.failed_attempts = 0
        user.lockout_until = None
        user.updated_at = now
        token, session = self.sessions.create_session(user.username)
        self.storage.save_user(user)
        self.audit.record(
            AuditEvent.SESSION_CREATED,
            user.username,
            {"expires_at": session.expires_at},
        )
        self.audit.record(
            AuditEvent.LOGIN_SUCCESS,
            user.username,
            {"mfa": user.mfa_enabled},
        )
        return LoginResult(
            success=True,
            message="Login successful.",
            session_token=token,
            session_expires_at=session.expires_at,
            mfa_used=user.mfa_enabled,
        )

    def logout(self, token: str | None) -> bool:
        session = self.sessions.validate(token)
        invalidated = self.sessions.invalidate(token)
        if invalidated and session is not None:
            self.audit.record(AuditEvent.LOGOUT, session.username)
        return invalidated

    def current_session(self, token: str | None) -> Session | None:
        session = self.sessions.validate(token)
        if session is None and token:
            self.audit.record(AuditEvent.SESSION_REJECTED, None, {"reason": "invalid_or_expired"})
        return session

    # ------------------------------------------------------------------
    # MFA enrollment
    # ------------------------------------------------------------------
    def begin_mfa_enrollment(self, token: str | None) -> MfaEnrollmentResult:
        session = self.current_session(token)
        if session is None:
            return MfaEnrollmentResult(False, "Your session is invalid or has expired. Please log in again.")

        user = self.storage.get_user(session.username)
        if user is None:
            return MfaEnrollmentResult(False, "Account not found.")

        if user.mfa_enabled:
            return MfaEnrollmentResult(
                False,
                "Multi-factor authentication is already enabled for this account.",
            )

        enrollment = self.mfa.enrollment_for(user.username)
        user.totp_secret = enrollment.secret
        user.mfa_enabled = False
        user.updated_at = self._clock()
        self.storage.save_user(user)
        self.audit.record(AuditEvent.MFA_ENROLLMENT_STARTED, user.username)
        return MfaEnrollmentResult(
            True,
            "Scan the provisioning URI with an authenticator app, then confirm a code.",
            enrollment=enrollment,
        )

    def confirm_mfa_enrollment(self, token: str | None, code: str | None) -> OperationResult:
        session = self.current_session(token)
        if session is None:
            return OperationResult(False, "Your session is invalid or has expired. Please log in again.")

        user = self.storage.get_user(session.username)
        if user is None:
            return OperationResult(False, "Account not found.")
        if user.mfa_enabled:
            return OperationResult(False, "Multi-factor authentication is already enabled.")
        if not user.totp_secret:
            return OperationResult(False, "Start MFA enrollment first.")

        if not self.mfa.verify_code(user.totp_secret, code):
            self.audit.record(AuditEvent.MFA_FAILURE, user.username, {"phase": "enrollment"})
            return OperationResult(False, "That code is not valid. Check the time on your device and try again.", "mfa_failed")

        user.mfa_enabled = True
        user.mfa_failed_attempts = 0
        user.mfa_locked_until = None
        user.updated_at = self._clock()
        self.storage.save_user(user)
        self.audit.record(AuditEvent.MFA_ENROLLMENT_CONFIRMED, user.username)
        return OperationResult(True, "Multi-factor authentication is now enabled.")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _enforce_mfa(
        self,
        user: UserRecord,
        totp_code: str | None,
        now: float,
    ) -> LoginResult | None:
        """Return a failure result, or ``None`` when the second factor passes."""
        if user.is_mfa_locked_out(now):
            self.audit.record(AuditEvent.MFA_FAILURE, user.username, {"reason": "mfa_locked"})
            return LoginResult(
                success=False,
                message=INVALID_MFA_MESSAGE,
                reason="mfa_locked",
                retry_after=max(0.0, (user.mfa_locked_until or now) - now),
            )

        if totp_code is None or (isinstance(totp_code, str) and not totp_code.strip()):
            # A missing code is not a wrong guess; do not consume an attempt.
            self.audit.record(AuditEvent.MFA_FAILURE, user.username, {"reason": "missing_code"})
            return LoginResult(
                success=False,
                message=INVALID_MFA_MESSAGE,
                reason="mfa_required",
            )

        if not self.mfa.verify_code(user.totp_secret or "", totp_code, at=now):
            user.mfa_failed_attempts += 1
            locked = user.mfa_failed_attempts >= self.settings.mfa_max_attempts
            if locked:
                user.mfa_locked_until = now + self.settings.mfa_cooldown_seconds
                self.audit.record(
                    AuditEvent.MFA_LOCKED,
                    user.username,
                    {"attempts": user.mfa_failed_attempts},
                )
            user.updated_at = now
            self.storage.save_user(user)
            self.audit.record(AuditEvent.MFA_FAILURE, user.username, {"reason": "bad_code"})
            return LoginResult(
                success=False,
                message=INVALID_MFA_MESSAGE,
                reason="mfa_locked" if locked else "mfa_failed",
                retry_after=self.settings.mfa_cooldown_seconds if locked else None,
            )

        user.mfa_failed_attempts = 0
        user.mfa_locked_until = None
        self.audit.record(AuditEvent.MFA_SUCCESS, user.username)
        return None

    def _credential_failure(self, reason: str) -> LoginResult:
        return LoginResult(
            success=False,
            message=INVALID_CREDENTIALS_MESSAGE,
            reason=reason,
        )

    def _audit_failure(self, username: str | None, *, reason: str) -> None:
        self.audit.record(AuditEvent.LOGIN_FAILURE, username, {"reason": reason})
